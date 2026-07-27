use mesh_tun::control::{
    BwrapInfoServerConfig, EgressRedirectConfig, run_bwrap_info_server, run_control_server,
};
use mesh_tun::flow::MeshPassthrough;
use mesh_tun::policy::AllowAllPolicy;
use mesh_tun::uds::{UdsServerConfig, UdsStyle, run_uds_server};
use mesh_tun::vhost_user::{VhostUserNetConfig, spawn_vhost_user_net};
use mesh_tun::{MeshTun, MeshTunConfig};
use std::env;
use std::net::Ipv4Addr;
use std::os::fd::AsRawFd;
use std::os::unix::io::FromRawFd;
use std::os::unix::process::ExitStatusExt;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;
use tokio::net::UnixListener;

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), anyhow::Error> {
    let args: Vec<String> = env::args().collect();
    if args.len() > 1 && args[1] == "bwrap" {
        return run_bwrap_command(&args[2..]);
    }

    let (log_buffer, _trace_guard) = mesh::local_trace::init("mesh-tun");

    // Bind the UDS trace socket (with optional FD activation via
    // MESH_TUN_TRACE_FD). The path comes from `default_trace_socket_path`,
    // which is governed by TRACE_SOCKET_DIR / HOME — if neither is set, the
    // trace surface is off and we skip the bind entirely.
    if let Some(trace_socket) = mesh::local_trace::default_trace_socket_path("mesh-tun") {
        let trace_socket_str = trace_socket.to_string_lossy().to_string();
        match resolve_and_bind_uds("mesh-tun", &trace_socket_str, "MESH_TUN_TRACE_FD", None) {
            Ok(trace_listener) => {
                tokio::spawn(async move {
                    if let Err(error) = mesh::local_trace::start_uds_listener_from_listener(
                        trace_listener,
                        log_buffer,
                    )
                    .await
                    {
                        tracing::error!(%error, "UDS trace listener stopped");
                    }
                });
            }
            Err(error) => {
                tracing::error!(%error, "Failed to bind UDS trace listener");
            }
        }
    } else {
        tracing::debug!("TRACE_SOCKET_DIR/HOME not set; not binding UDS trace listener");
    }

    let mode = env::var("MESH_TUN_MODE").unwrap_or_else(|_| {
        if env_truthy("MESH_TUN_REAL_TUN") {
            "tun".to_string()
        } else {
            "uds".to_string()
        }
    });

    let config = mesh_tun_config_from_env()?;
    let passthrough = Arc::new(MeshPassthrough::new(config.vm_id.clone()));

    match mode.as_str() {
        "tun" | "real-tun" => run_real_tun(config, passthrough).await,
        "uds" | "unix" | "unix-socket" => run_capture_sockets(config, passthrough).await,
        other => anyhow::bail!("unsupported MESH_TUN_MODE={other}; expected uds or tun"),
    }
}

fn run_bwrap_command(args: &[String]) -> Result<(), anyhow::Error> {
    let Some(command_separator) = args.iter().position(|arg| arg == "--") else {
        anyhow::bail!("usage: mesh-tun bwrap [bwrap-args...] -- [command...]");
    };

    let bwrap_socket =
        env::var("MESH_TUN_BWRAP_SOCKET").unwrap_or_else(|_| "/tmp/mesh-tun-bwrap.sock".into());
    let stream = std::os::unix::net::UnixStream::connect(&bwrap_socket)
        .map_err(|error| anyhow::anyhow!("connect {bwrap_socket}: {error}"))?;
    let info_fd = dup_fd(stream.as_raw_fd())?;
    let block_fd = dup_fd(stream.as_raw_fd())?;
    drop(stream);

    let mut bwrap_args = args[..command_separator].to_vec();
    let command = if command_separator + 1 == args.len() {
        vec![env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string())]
    } else {
        args[command_separator + 1..].to_vec()
    };

    bwrap_args.extend([
        "--info-fd".to_string(),
        info_fd.to_string(),
        "--block-fd".to_string(),
        block_fd.to_string(),
        "--".to_string(),
    ]);
    bwrap_args.extend(command);

    let status = Command::new("bwrap").args(&bwrap_args).status();
    close_fd(info_fd);
    close_fd(block_fd);

    let status = status?;
    if let Some(code) = status.code() {
        std::process::exit(code);
    }
    if let Some(signal) = status.signal() {
        anyhow::bail!("bwrap terminated by signal {signal}");
    }
    anyhow::bail!("bwrap terminated without an exit code")
}

/// Duplicate a file descriptor for passing to `bwrap`.
///
/// The returned fd must be inheritable by the immediate `bwrap` process because
/// it is passed as `--info-fd` or `--block-fd`. `bwrap` owns closing or
/// forwarding those descriptors according to its own sandbox setup.
fn dup_fd(fd: i32) -> Result<i32, anyhow::Error> {
    // SAFETY: `fd` is a valid open file descriptor owned by the caller.
    let duplicated = unsafe { libc::fcntl(fd, libc::F_DUPFD, 3) };
    if duplicated < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(duplicated)
}

fn close_fd(fd: i32) {
    // SAFETY: fd is a valid open file descriptor owned by the caller.
    unsafe {
        libc::close(fd);
    }
}

/// Set `FD_CLOEXEC` on an existing file descriptor.
///
/// Best-effort: logs a warning on failure. This prevents the FD from being
/// inherited by child processes spawned via `execve()` (e.g. bwrap workloads).
fn set_fd_cloexec(fd: i32) {
    // SAFETY: fd is a valid open file descriptor. F_GETFD/F_SETFD do not
    // have undefined behavior on valid fds.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        tracing::warn!("fcntl(F_GETFD) failed on fd {}", fd);
        return;
    }
    if flags & libc::FD_CLOEXEC != 0 {
        return; // already set
    }
    let rc = unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) };
    if rc < 0 {
        tracing::warn!("fcntl(F_SETFD FD_CLOEXEC) failed on fd {}", fd);
    }
}

async fn run_real_tun(
    config: MeshTunConfig,
    passthrough: Arc<MeshPassthrough>,
) -> Result<(), anyhow::Error> {
    let tun = MeshTun::new(config)?;
    let injector = tun
        .run_with_policy(
            Arc::new(AllowAllPolicy),
            passthrough.clone(),
            passthrough.clone(),
        )
        .await?;
    passthrough.set_injector(injector);
    std::future::pending::<()>().await;
    Ok(())
}

async fn run_capture_sockets(
    config: MeshTunConfig,
    passthrough: Arc<MeshPassthrough>,
) -> Result<(), anyhow::Error> {
    let run_dir = get_run_dir();
    let socket_path_str = env::var("MESH_TUN_SOCKET").unwrap_or_else(|_| "qemu.sock".to_string());

    let resolved_socket_path = if socket_path_str.starts_with('/') {
        PathBuf::from(&socket_path_str)
    } else if socket_path_str.starts_with('_') {
        PathBuf::from(&socket_path_str)
    } else {
        run_dir.join(&socket_path_str)
    };

    let capture_listener = resolve_and_bind_uds(
        "mesh-tun",
        &socket_path_str,
        "MESH_TUN_CAPTURE_FD",
        Some("LISTEN_FD"),
    )?;

    let style = UdsStyle::from_env_value(
        &env::var("MESH_TUN_UDS_STYLE").unwrap_or_else(|_| "qemu".to_string()),
    )?;

    let control_socket_str =
        env::var("MESH_TUN_CONTROL_SOCKET").unwrap_or_else(|_| "control.sock".to_string());

    let control_listener =
        resolve_and_bind_uds("mesh-tun", &control_socket_str, "MESH_TUN_CONTROL_FD", None)?;
    let bwrap_socket_str =
        env::var("MESH_TUN_BWRAP_SOCKET").unwrap_or_else(|_| "bwrap.sock".to_string());
    let bwrap_listener =
        resolve_and_bind_uds("mesh-tun", &bwrap_socket_str, "MESH_TUN_BWRAP_FD", None)?;

    let vhost_socket = env::var("MESH_TUN_VHOST_SOCKET")
        .ok()
        .map(PathBuf::from)
        .or_else(|| env_truthy("MESH_TUN_ENABLE_VHOST").then(|| run_dir.join("vhost.sock")));
    let packet_queue_capacity = config.packet_queue_capacity;
    let tun = MeshTun::new(config)?;
    let (injector, tun_tx, mut stack_rx) = tun
        .run_with_channels_and_policy(
            Arc::new(AllowAllPolicy),
            passthrough.clone(),
            passthrough.clone(),
        )
        .await?;
    passthrough.set_injector(injector);

    let (fallback_tx, fallback_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(packet_queue_capacity);
    tokio::spawn(async move {
        while let Some(packet) = stack_rx.recv().await {
            if !mesh_tun::control::route_outgoing_packet(&packet) {
                if fallback_tx.try_send(packet).is_err() {
                    mesh_tun::stats::stats()
                        .fallback_queue_full
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
            }
        }
    });

    let control_tx = tun_tx.clone();
    tokio::spawn(async move {
        if let Err(error) = run_control_server(control_listener, control_tx).await {
            tracing::error!(%error, "mesh-tun control socket stopped");
        }
    });

    let bwrap_tx = tun_tx.clone();
    let pool = env::var("MESH_TUN_BWRAP_POOL").unwrap_or_else(|_| "10.5.0.0/24".to_string());
    let (network, prefix_len) = parse_ipv4_cidr(&pool)?;
    let bwrap_config = BwrapInfoServerConfig {
        if_name: env::var("MESH_TUN_BWRAP_IF").unwrap_or_else(|_| "tap0".to_string()),
        network,
        prefix_len,
        first_host: env::var("MESH_TUN_BWRAP_FIRST_HOST")
            .ok()
            .map(|value| value.parse())
            .transpose()?
            .unwrap_or(2),
        gateway: env::var("MESH_TUN_BWRAP_GW").unwrap_or_else(|_| "10.5.0.1".to_string()),
        vm_id: env::var("MESH_TUN_BWRAP_VM_ID").unwrap_or_else(|_| "bwrap".to_string()),
        egress_redirect: egress_redirect_config_from_env()?,
    };
    tokio::spawn(async move {
        if let Err(error) = run_bwrap_info_server(bwrap_listener, bwrap_config, bwrap_tx).await {
            tracing::error!(%error, "mesh-tun bwrap info socket stopped");
        }
    });

    if let Some(socket_path) = vhost_socket {
        let mut vhost_config =
            VhostUserNetConfig::new(socket_path, passthrough.vm_id().to_string());
        if let Ok(mtu) = env::var("MESH_TUN_MTU") {
            vhost_config.mtu = mtu.parse()?;
        }
        spawn_vhost_user_net(vhost_config)?;
    }

    run_uds_server(
        capture_listener,
        UdsServerConfig::new(resolved_socket_path, style),
        tun_tx,
        fallback_rx,
    )
    .await
}

fn egress_redirect_config_from_env() -> Result<Option<EgressRedirectConfig>, anyhow::Error> {
    let Some(port) = env::var("MESH_TUN_EGRESS_REDIRECT_PORT").ok() else {
        return Ok(None);
    };
    if port.is_empty() {
        return Ok(None);
    }
    let proxy_uid = env::var("MESH_TUN_EGRESS_PROXY_UID")
        .ok()
        .filter(|value| !value.is_empty())
        .map(|value| value.parse())
        .transpose()?;
    Ok(Some(EgressRedirectConfig {
        listen_port: port.parse()?,
        proxy_uid,
    }))
}

fn mesh_tun_config_from_env() -> Result<MeshTunConfig, anyhow::Error> {
    let mut config = MeshTunConfig::default();
    if let Ok(name) = env::var("MESH_TUN_NAME") {
        if !name.is_empty() {
            config.name = Some(name);
        }
    }
    if let Ok(address) = env::var("MESH_TUN_ADDRESS") {
        config.address = address.parse()?;
    }
    if let Ok(prefix_len) = env::var("MESH_TUN_PREFIX_LEN") {
        config.prefix_len = prefix_len.parse()?;
    }
    if let Ok(mtu) = env::var("MESH_TUN_MTU") {
        config.mtu = mtu.parse()?;
    }
    if let Ok(capacity) = env::var("MESH_TUN_PACKET_QUEUE") {
        config.packet_queue_capacity = capacity.parse()?;
    }
    if let Ok(max_flows) = env::var("MESH_TUN_TCP_MAX_FLOWS") {
        config.tcp_proxy_config.max_flows = max_flows.parse()?;
    }
    if let Ok(capacity) = env::var("MESH_TUN_TCP_PER_FLOW_QUEUE") {
        config.tcp_proxy_config.per_flow_queue_capacity = capacity.parse()?;
    }
    if let Ok(timeout_ms) = env::var("MESH_TUN_TCP_HANDSHAKE_TIMEOUT_MS") {
        config.tcp_proxy_config.handshake_timeout =
            std::time::Duration::from_millis(timeout_ms.parse()?);
    }
    if let Ok(timeout_ms) = env::var("MESH_TUN_TCP_CONNECT_TIMEOUT_MS") {
        config.tcp_proxy_config.connect_timeout =
            std::time::Duration::from_millis(timeout_ms.parse()?);
    }
    if let Ok(vm_id) = env::var("MESH_TUN_VM_ID") {
        if !vm_id.is_empty() {
            config.vm_id = vm_id;
        }
    }
    Ok(config)
}

fn parse_ipv4_cidr(value: &str) -> Result<(Ipv4Addr, u8), anyhow::Error> {
    let Some((addr, prefix_len)) = value.split_once('/') else {
        anyhow::bail!("expected IPv4 CIDR, got {value}");
    };
    let prefix_len = prefix_len.parse::<u8>()?;
    if prefix_len > 32 {
        anyhow::bail!("invalid IPv4 prefix length {prefix_len}");
    }
    Ok((addr.parse()?, prefix_len))
}

fn env_truthy(name: &str) -> bool {
    env::var(name)
        .map(|value| env_value_truthy(&value))
        .unwrap_or(false)
}

fn env_value_truthy(value: &str) -> bool {
    matches!(value, "1" | "true" | "yes" | "on")
}

fn get_run_dir() -> PathBuf {
    if let Ok(dir) = env::var("MESH_TUN_RUN") {
        PathBuf::from(dir)
    } else {
        let home = env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        PathBuf::from(format!("{}/.run/mesh-tun", home))
    }
}

fn resolve_and_bind_uds(
    app_name: &str,
    path_str: &str,
    specific_fd_var: &str,
    fallback_fd_var: Option<&str>,
) -> Result<UnixListener, anyhow::Error> {
    let fd_str = env::var(specific_fd_var)
        .ok()
        .or_else(|| fallback_fd_var.and_then(|var| env::var(var).ok()));

    if let Some(fd_str) = fd_str {
        if let Ok(fd) = fd_str.parse::<i32>() {
            tracing::info!("Using activated listener FD {} for {}", fd, path_str);
            // SAFETY: the FD was passed by the parent (systemd-style
            // activation) and is a valid, owned UnixListener fd.
            let std_listener = unsafe { std::os::unix::net::UnixListener::from_raw_fd(fd) };
            std_listener.set_nonblocking(true)?;
            // Ensure the listener is closed on exec so it does not leak into
            // spawned bwrap workloads or other child processes.
            use std::os::fd::AsRawFd;
            set_fd_cloexec(std_listener.as_raw_fd());
            let listener = UnixListener::from_std(std_listener)?;
            return Ok(listener);
        }
    }

    let actual_path = if path_str.starts_with('_') {
        path_str.replacen('_', "\0", 1)
    } else if path_str.starts_with('/') {
        path_str.to_string()
    } else {
        let home = env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        let dir = format!("{}/.run/{}", home, app_name);
        let _ = std::fs::create_dir_all(&dir);
        format!("{}/{}", dir, path_str)
    };

    if !actual_path.starts_with('\0') {
        let path = std::path::Path::new(&actual_path);
        if path.exists() {
            let _ = std::fs::remove_file(path);
        }
    }
    let listener = UnixListener::bind(&actual_path)?;
    tracing::info!("Listening on UDS {:?}", actual_path);

    if !actual_path.starts_with('\0') {
        // Set permissions to 0660
        let mut perms = std::fs::metadata(&actual_path)?.permissions();
        use std::os::unix::fs::PermissionsExt;
        perms.set_mode(0o660);
        std::fs::set_permissions(&actual_path, perms)?;
    }

    Ok(listener)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    #[test]
    fn duplicated_bwrap_fd_is_inheritable() {
        let mut fds = [0i32; 2];
        let rc = unsafe { libc::pipe(fds.as_mut_ptr()) };
        assert_eq!(rc, 0);
        let read_fd = unsafe { OwnedFd::from_raw_fd(fds[0]) };
        let write_fd = unsafe { OwnedFd::from_raw_fd(fds[1]) };

        let dup = dup_fd(read_fd.as_raw_fd()).expect("duplicate fd");
        assert!(dup >= 3);
        let flags = unsafe { libc::fcntl(dup, libc::F_GETFD) };
        assert!(flags >= 0);
        assert_eq!(flags & libc::FD_CLOEXEC, 0);

        close_fd(dup);
        drop(read_fd);
        drop(write_fd);
    }
}
