//! Socket activation for mesh-init services.
//!
//! Handles listening on TCP ports, UDP ports, and Unix sockets on behalf of services.
//! Supports three activation models:
//!
//! - **Systemd socket activation** — mesh-init receives pre-bound file
//!   descriptors from systemd via `LISTEN_PID`/`LISTEN_FDS`. Uses them
//!   directly instead of binding new sockets.
//! - **Listener activation (Accept=false)** - passes listening file descriptors
//!   to the child service using systemd fd 3.. + `LISTEN_FDS=N`.
//! - **Inetd-style (Accept=true)** - accepts the connection in mesh-init
//!   and passes the connected client socket as stdin/stdout/stderr.
//! - **Hybrid activation (service activation_mode=hybrid)** - accepts the
//!   connection in mesh-init and forwards the accepted fd to a service JSONL
//!   Unix socket using SCM_RIGHTS.

use std::collections::{HashMap, VecDeque};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd};
use std::os::unix::net::UnixStream as StdUnixStream;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::OnceLock;

use parking_lot::Mutex;
use tokio::io::unix::AsyncFd;
use tokio::sync::Semaphore;
use tracing::{debug, error, info, warn};

use crate::config::{AppConfig, ServiceActivationMode};
use crate::daemon::{Daemon, apply_activation_context_env};
use crate::process::{ActivationFd, ActivationListenFd};
use crate::protocol::ServiceState;

// ============================================================================
// Concurrency limits
// ============================================================================

/// Default maximum number of concurrent inetd-style activation
/// children. Prevents a connection flood from exhausting PIDs/memory/FDs.
/// Override via the `MESH_INIT_MAX_ACTIVATION_CHILDREN` env var.
const DEFAULT_MAX_ACTIVATION_CHILDREN: usize = 64;

fn max_activation_children() -> usize {
    std::env::var("MESH_INIT_MAX_ACTIVATION_CHILDREN")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|&n: &usize| n > 0)
        .unwrap_or(DEFAULT_MAX_ACTIVATION_CHILDREN)
}

/// Global semaphore capping concurrent inetd-style activation spawns.
static ACTIVATION_SEMAPHORE: OnceLock<Arc<Semaphore>> = OnceLock::new();
static SERVICE_LISTENER_FDS: OnceLock<
    Mutex<HashMap<String, Vec<(usize, OwnedFd, Option<String>)>>>,
> = OnceLock::new();
static ACTIVE_INETD_PERMITS: OnceLock<Mutex<HashMap<u32, tokio::sync::OwnedSemaphorePermit>>> =
    OnceLock::new();

pub fn register_inetd_permit(pid: u32, permit: tokio::sync::OwnedSemaphorePermit) {
    let registry = ACTIVE_INETD_PERMITS.get_or_init(|| Mutex::new(HashMap::new()));
    registry.lock().insert(pid, permit);
}

pub fn reclaim_inetd_permit(pid: u32) {
    if let Some(registry) = ACTIVE_INETD_PERMITS.get() {
        if registry.lock().remove(&pid).is_some() {
            debug!(pid, "inetd_permit_reclaimed");
        }
    }
}

fn activation_semaphore() -> Arc<Semaphore> {
    ACTIVATION_SEMAPHORE
        .get_or_init(|| Arc::new(Semaphore::new(max_activation_children())))
        .clone()
}

/// Register one listener for a service in the daemon-held registry.
///
/// Listeners arrive from activations and from FDSTORE notifications; both
/// feed warm restarts and the LISTEN_FDS hand-off.
pub(crate) fn register_service_listener_fd(
    service_name: &str,
    order: usize,
    fd: &OwnedFd,
    fd_name: Option<String>,
) {
    let Ok(fd_clone) = fd.try_clone() else {
        warn!(service = %service_name, "clone_activation_listener_fd_failed");
        return;
    };
    let registry = SERVICE_LISTENER_FDS.get_or_init(|| Mutex::new(HashMap::new()));
    let mut registry = registry.lock();
    let listeners = registry.entry(service_name.to_string()).or_default();
    if let Some((_, existing, existing_name)) =
        listeners.iter_mut().find(|(idx, _, _)| *idx == order)
    {
        *existing = fd_clone;
        *existing_name = fd_name;
    } else {
        listeners.push((order, fd_clone, fd_name));
        listeners.sort_by_key(|(idx, _, _)| *idx);
    }
}

pub(crate) fn service_listener_fds(service_name: &str) -> Vec<ActivationListenFd> {
    let Some(registry) = SERVICE_LISTENER_FDS.get() else {
        return Vec::new();
    };
    registry
        .lock()
        .get(service_name)
        .map(|listeners| {
            listeners
                .iter()
                .filter_map(|(_, fd, name)| {
                    fd.try_clone().ok().map(|fd| ActivationListenFd {
                        fd,
                        name: name.clone(),
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Edge-free readability check for a listener socket.
///
/// Tokio's `AsyncFd` is edge-triggered, so a connection that was already
/// queued before a freeze produced no fresh readiness event. After each
/// freeze, run one `poll(fd, 0)` pass over the listeners; any connection
/// already pending thaws the service at once.
pub(crate) fn has_pending_connection(fd: i32) -> bool {
    let mut pollfd = [libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    }];
    // Non-blocking read check: timeout 0 returns immediately.
    let rc = unsafe { libc::poll(pollfd.as_mut_ptr(), 1, 0) };
    if rc <= 0 {
        return false;
    }
    let revents = pollfd[0].revents;
    revents & (libc::POLLIN | libc::POLLRDNORM | libc::POLLRDHUP) != 0
}

// ============================================================================
// Systemd socket activation — FD identification
// ============================================================================

/// The kind of a systemd socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SocketKind {
    Stream,
    Datagram,
}

/// Identity of a systemd socket activation file descriptor.
#[derive(Debug, Clone, PartialEq)]
enum FdIdentity {
    Tcp(u16, SocketKind),
    Unix(PathBuf, SocketKind),
    Unknown,
}

/// Global pool of file descriptors received from systemd socket activation.
/// Populated once by [`collect_systemd_fds`] before any listener starts.
static SYSTEMD_FDS: OnceLock<Mutex<VecDeque<(OwnedFd, FdIdentity, Option<String>)>>> =
    OnceLock::new();

/// Collect file descriptors from systemd socket activation.
///
/// Checks `LISTEN_PID` and `LISTEN_FDS` environment variables. If the PID
/// matches the current process and `LISTEN_FDS > 0`, takes ownership of the
/// file descriptors starting from FD 3 and populates the global [`SYSTEMD_FDS`]
/// pool. Clears both environment variables so they are not inherited by child
/// processes.
///
/// Must be called early in startup, before any activation listeners are started.
/// Idempotent — only the first call has effect.
pub fn collect_systemd_fds() {
    if SYSTEMD_FDS.get().is_some() {
        return;
    }

    let listen_pid = match std::env::var("LISTEN_PID") {
        Ok(pid_str) => match pid_str.parse::<u32>() {
            Ok(pid) if pid == std::process::id() => pid,
            _ => return,
        },
        Err(_) => return,
    };

    let listen_fds: usize = match std::env::var("LISTEN_FDS") {
        Ok(fds_str) => match fds_str.parse() {
            Ok(n) if n > 0 => n,
            _ => return,
        },
        Err(_) => return,
    };
    let listen_fd_names: Vec<Option<String>> = std::env::var("LISTEN_FDNAMES")
        .ok()
        .map(|names| {
            names
                .split(|c: char| c == ':' || c.is_ascii_whitespace())
                .filter(|name| !name.is_empty())
                .map(|name| {
                    if name.is_empty() {
                        None
                    } else {
                        Some(name.to_string())
                    }
                })
                .collect()
        })
        .unwrap_or_default();

    // Clear env vars so children don't misinterpret them as their own activation
    // SAFETY: removing these env vars is safe — they were set by systemd and
    // are only meaningful for the process that matches LISTEN_PID (us).
    unsafe {
        std::env::remove_var("LISTEN_PID");
        std::env::remove_var("LISTEN_FDS");
        std::env::remove_var("LISTEN_FDNAMES");
    }

    info!(listen_pid, listen_fds, "systemd_socket_activation_detected");

    const SD_LISTEN_FDS_START: i32 = 3;
    let pool = SYSTEMD_FDS.get_or_init(|| Mutex::new(VecDeque::new()));
    let mut pool = pool.lock();

    for i in 0..listen_fds {
        let raw_fd = SD_LISTEN_FDS_START + i as i32;
        // SAFETY: systemd guarantees these FDs are open and their ownership
        // is transferred to us when `LISTEN_PID` matches our PID.
        let owned = unsafe { OwnedFd::from_raw_fd(raw_fd) };
        let identity = identify_fd(&owned);
        let fd_name = listen_fd_names.get(i).cloned().flatten();
        debug!(
            index = i,
            raw_fd,
            identity = ?identity,
            name = ?fd_name,
            "systemd_activation_fd_processed"
        );
        pool.push_back((owned, identity, fd_name));
    }

    info!(count = listen_fds, "systemd_fds_collected");
}

/// Identify the type, address, and socket kind of a file descriptor.
fn identify_fd(fd: &OwnedFd) -> FdIdentity {
    let raw_fd = fd.as_raw_fd();

    // Determine socket type (SOCK_STREAM vs SOCK_DGRAM)
    let sock_kind = get_sock_type(raw_fd);

    // Try UDS first
    let mut sockaddr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t;
    let ret = unsafe {
        libc::getsockname(
            raw_fd,
            &mut sockaddr as *mut _ as *mut libc::sockaddr,
            &mut len,
        )
    };
    if ret == 0 && sockaddr.sun_family == libc::AF_UNIX as libc::sa_family_t {
        use std::os::unix::ffi::OsStrExt;
        let path_bytes: &[i8] = &sockaddr.sun_path;
        let path_len = path_bytes
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(path_bytes.len());
        if path_len > 0 && path_bytes[0] != 0 {
            // SAFETY: casting i8 sun_path to u8 for OsStrExt::from_bytes.
            // The path bytes are valid ASCII/UTF-8 filesystem paths.
            let bytes: &[u8] =
                unsafe { std::slice::from_raw_parts(path_bytes.as_ptr() as *const u8, path_len) };
            let path = PathBuf::from(<std::ffi::OsStr as OsStrExt>::from_bytes(bytes));
            return FdIdentity::Unix(path, sock_kind);
        }
        // Abstract namespace or empty — treat as Unknown
        return FdIdentity::Unknown;
    }

    // Try TCP (IPv4)
    let mut sockaddr_in: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
    let ret = unsafe {
        libc::getsockname(
            raw_fd,
            &mut sockaddr_in as *mut _ as *mut libc::sockaddr,
            &mut len,
        )
    };
    if ret == 0 && sockaddr_in.sin_family == libc::AF_INET as libc::sa_family_t {
        let port = u16::from_be(sockaddr_in.sin_port);
        return FdIdentity::Tcp(port, sock_kind);
    }

    // Try TCP (IPv6)
    let mut sockaddr_in6: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;
    let ret = unsafe {
        libc::getsockname(
            raw_fd,
            &mut sockaddr_in6 as *mut _ as *mut libc::sockaddr,
            &mut len,
        )
    };
    if ret == 0 && sockaddr_in6.sin6_family == libc::AF_INET6 as libc::sa_family_t {
        let port = u16::from_be(sockaddr_in6.sin6_port);
        return FdIdentity::Tcp(port, sock_kind);
    }

    FdIdentity::Unknown
}

/// Determine the socket type (SOCK_STREAM or SOCK_DGRAM) via `getsockopt(SO_TYPE)`.
fn get_sock_type(raw_fd: i32) -> SocketKind {
    let mut sock_type: i32 = 0;
    let mut len = std::mem::size_of::<i32>() as libc::socklen_t;
    let ret = unsafe {
        libc::getsockopt(
            raw_fd,
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            &mut sock_type as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if ret == 0 && sock_type == libc::SOCK_DGRAM {
        SocketKind::Datagram
    } else {
        SocketKind::Stream
    }
}

/// Try to take a matching systemd-provided TCP listener FD by port and kind.
fn take_systemd_tcp_fd(port: u16, datagram: bool) -> Option<ActivationListenFd> {
    let kind = if datagram {
        SocketKind::Datagram
    } else {
        SocketKind::Stream
    };
    let pool = SYSTEMD_FDS.get()?;
    let mut pool = pool.lock();
    let idx = pool.iter().position(
        |(_, identity, _)| matches!(identity, FdIdentity::Tcp(p, k) if *p == port && *k == kind),
    );
    idx.map(|i| {
        let (fd, _, name) = pool.remove(i).unwrap();
        ActivationListenFd { fd, name }
    })
}

/// Try to take a matching systemd-provided UDS listener FD by path and kind.
fn take_systemd_uds_fd(path: &str, datagram: bool) -> Option<ActivationListenFd> {
    let kind = if datagram {
        SocketKind::Datagram
    } else {
        SocketKind::Stream
    };
    let pool = SYSTEMD_FDS.get()?;
    let mut pool = pool.lock();
    let idx = pool.iter().position(|(_, identity, _)| {
        if let FdIdentity::Unix(p, k) = identity {
            p.as_os_str() == path && *k == kind
        } else {
            false
        }
    });
    idx.map(|i| {
        let (fd, _, name) = pool.remove(i).unwrap();
        ActivationListenFd { fd, name }
    })
}

// ============================================================================
// Peer credential helper
// ============================================================================

/// Get peer UID from a raw file descriptor using SO_PEERCRED.
fn get_peer_uid(fd: i32) -> Option<u32> {
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if ret == 0 {
        Some(cred.uid)
    } else {
        warn!(fd, "get_peer_credentials_failed");
        None
    }
}

/// Resolve a username to a UID via the reentrant libc lookup.
///
/// Returns `None` on missing user, NUL byte in the name, or lookup error.
/// Uses `getpwnam_r` so concurrent calls from async tasks don't race on
/// libc's static passwd buffer.
fn lookup_uid_by_name(name: &str) -> Option<u32> {
    let c_name = std::ffi::CString::new(name).ok()?;
    let mut entry: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    let mut buffer = vec![0u8; 16 * 1024];
    let rc = unsafe {
        libc::getpwnam_r(
            c_name.as_ptr(),
            &mut entry,
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut result,
        )
    };
    if rc != 0 || result.is_null() {
        return None;
    }
    Some(entry.pw_uid)
}

/// Resolve a group name to a GID via the reentrant libc lookup.
fn lookup_gid_by_name(name: &str) -> Option<u32> {
    let c_name = std::ffi::CString::new(name).ok()?;
    let mut entry: libc::group = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::group = std::ptr::null_mut();
    let mut buffer = vec![0u8; 16 * 1024];
    let rc = unsafe {
        libc::getgrnam_r(
            c_name.as_ptr(),
            &mut entry,
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut result,
        )
    };
    if rc != 0 || result.is_null() {
        return None;
    }
    Some(entry.gr_gid)
}

async fn forward_accepted_fd(
    service_name: &str,
    activation_socket: &str,
    client_fd: OwnedFd,
    stream_cache: &mut Option<StdUnixStream>,
    daemon: Arc<Daemon>,
) -> anyhow::Result<()> {
    let message = serde_json::json!({
        "method": "accepted_fd",
        "service": service_name,
        "activation_socket": activation_socket,
        "peer_uid": get_peer_uid(client_fd.as_raw_fd()),
    });

    if stream_cache.is_none() {
        *stream_cache = Some(
            connect_or_start_activation_socket(service_name, activation_socket, daemon.clone())
                .await?,
        );
    }

    if let Some(stream) = stream_cache.as_mut() {
        if mesh::jsonl::send_json_with_fd(stream, &message, &client_fd).is_ok() {
            return Ok(());
        }
    }

    debug!(
        socket = %activation_socket,
        service = %service_name,
        "activation_fd_send_failed_reconnecting"
    );
    *stream_cache = None;
    let mut stream =
        connect_or_start_activation_socket(service_name, activation_socket, daemon).await?;
    mesh::jsonl::send_json_with_fd(&mut stream, &message, &client_fd)?;
    *stream_cache = Some(stream);
    Ok(())
}

async fn connect_or_start_activation_socket(
    service_name: &str,
    activation_socket: &str,
    daemon: Arc<Daemon>,
) -> anyhow::Result<StdUnixStream> {
    match StdUnixStream::connect(activation_socket) {
        Ok(stream) => Ok(stream),
        Err(first_error) => {
            debug!(
                socket = %activation_socket,
                service = %service_name,
                error = %first_error,
                "activation_socket_not_ready_starting_target"
            );
            start_activation_socket_target(service_name, activation_socket, daemon)?;
            connect_activation_socket(activation_socket).await
        }
    }
}

fn start_activation_socket_target(
    service_name: &str,
    activation_socket: &str,
    daemon: Arc<Daemon>,
) -> anyhow::Result<()> {
    let already_running = {
        let services = daemon.services.lock();
        services.get(service_name).is_some_and(|p| {
            matches!(
                p.protocol_state(),
                ServiceState::Running | ServiceState::Starting
            )
        })
    };

    if already_running {
        return Ok(());
    }

    let mut config = daemon
        .configs
        .lock()
        .get(service_name)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("missing service config for {}", service_name))?;

    let context = daemon.take_activation_context(service_name);
    apply_activation_context_env(&mut config, context);

    let listener = bind_activation_socket(activation_socket)?;
    daemon
        .start_service_with_config(
            config,
            Some(ActivationFd::Listen(vec![ActivationListenFd {
                fd: listener,
                name: Some("activation".to_string()),
            }])),
        )
        .map(|_| ())
        .map_err(|e| anyhow::anyhow!("failed to start forward target {}: {}", service_name, e))
}

fn bind_activation_socket(path: &str) -> anyhow::Result<OwnedFd> {
    let path_ref = std::path::Path::new(path);
    if let Some(parent) = path_ref.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let _ = std::fs::remove_file(path_ref);

    let listener = std::os::unix::net::UnixListener::bind(path_ref)?;
    listener.set_nonblocking(true)?;

    if let Ok(metadata) = std::fs::metadata(path_ref) {
        let mut perms = metadata.permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o660);
        let _ = std::fs::set_permissions(path_ref, perms);
    }

    Ok(listener.into())
}

fn activation_socket_for_service(config: &AppConfig, service_name: &str) -> String {
    config
        .activation_socket
        .clone()
        .unwrap_or_else(|| default_activation_socket(service_name))
}

fn default_activation_socket(service_name: &str) -> String {
    mesh::paths::AppPaths::for_app(service_name)
        .control_socket(service_name)
        .to_string_lossy()
        .into_owned()
}

async fn connect_activation_socket(path: &str) -> anyhow::Result<StdUnixStream> {
    let mut last_error = None;
    for _ in 0..40 {
        match StdUnixStream::connect(path) {
            Ok(stream) => return Ok(stream),
            Err(e) => {
                last_error = Some(e);
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        }
    }

    Err(last_error
        .map(anyhow::Error::from)
        .unwrap_or_else(|| anyhow::anyhow!("failed to connect to {}", path)))
}

// ============================================================================
// Start listeners
// ============================================================================

/// Start activation listeners for a given service.
pub fn start_listeners(daemon: Arc<Daemon>, config: &AppConfig) {
    for (order, act) in config.activation.iter().enumerate() {
        if let Some(port) = act.port {
            // Check for pre-bound systemd socket activation FD
            if let Some(fd) = take_systemd_tcp_fd(port, act.datagram) {
                info!(
                    service = %config.name,
                    port,
                    datagram = act.datagram,
                    "using_systemd_tcp_activation_fd"
                );
                let daemon_clone = daemon.clone();
                let name = config.name.clone();
                let wait = act.wait;
                if wait {
                    register_service_listener_fd(&name, order, &fd.fd, fd.name.clone());
                }
                tokio::spawn(async move {
                    handle_listener(fd.fd, name, wait, daemon_clone).await;
                });
                continue;
            }
            let daemon_clone = daemon.clone();
            let name = config.name.clone();
            let wait = act.wait;
            let bind = act.bind.clone();
            let fd_name = act.fd_name.clone();
            let datagram = act.datagram;
            tokio::spawn(async move {
                run_inet_listener(
                    port,
                    bind,
                    fd_name,
                    datagram,
                    name,
                    wait,
                    order,
                    daemon_clone,
                )
                .await;
            });
        }
        if let Some(ref path) = act.socket {
            // Check for pre-bound systemd socket activation FD
            if let Some(fd) = take_systemd_uds_fd(path, act.datagram) {
                info!(service = %config.name, path = %path, "using_systemd_uds_activation_fd");
                let daemon_clone = daemon.clone();
                let name = config.name.clone();
                let wait = act.wait;
                if wait {
                    register_service_listener_fd(&name, order, &fd.fd, fd.name.clone());
                }
                tokio::spawn(async move {
                    handle_listener(fd.fd, name, wait, daemon_clone).await;
                });
                continue;
            }
            let daemon_clone = daemon.clone();
            let name = config.name.clone();
            let path_clone = path.clone();
            let wait = act.wait;
            let fd_name = act.fd_name.clone();
            let socket_mode = act.socket_mode;
            let socket_user = act.socket_user.clone();
            let socket_group = act.socket_group.clone();
            let datagram = act.datagram;
            tokio::spawn(async move {
                run_uds_listener(
                    path_clone,
                    name,
                    wait,
                    order,
                    datagram,
                    socket_mode,
                    socket_user,
                    socket_group,
                    fd_name,
                    daemon_clone,
                )
                .await;
            });
        }
        if let Some(vsock_port) = act.vsock_port {
            if act.datagram {
                error!(
                    service = %config.name,
                    port = vsock_port,
                    "vsock_datagram_activation_not_supported"
                );
                continue;
            }
            let daemon_clone = daemon.clone();
            let name = config.name.clone();
            let wait = act.wait;
            let cid = act.vsock_cid;
            let fd_name = act.fd_name.clone();
            tokio::spawn(async move {
                run_vsock_listener(cid, vsock_port, fd_name, name, wait, order, daemon_clone).await;
            });
        }
    }
}

// ============================================================================
// Internet listeners
// ============================================================================

async fn run_inet_listener(
    port: u16,
    bind: Option<String>,
    fd_name: Option<String>,
    datagram: bool,
    service_name: String,
    wait: bool,
    order: usize,
    daemon: Arc<Daemon>,
) {
    let bind_addr = bind
        .filter(|b| !b.is_empty())
        .unwrap_or_else(|| "[::]".to_string());
    let addr = format!("{}:{}", bind_addr, port);

    info!(
        proto = if datagram { "UDP" } else { "TCP" },
        service = %service_name,
        address = %addr,
        wait,
        "starting_inet_listener"
    );

    if datagram && !wait {
        error!(service = %service_name, "udp_datagram_activation_accept_true_not_supported");
        return;
    }

    if wait {
        let has_auth = daemon
            .configs
            .lock()
            .get(&service_name)
            .is_some_and(|c| c.auth.is_some());
        if has_auth {
            error!(service = %service_name, "listener_activation_auth_conflict");
            return;
        }
    }

    let fd = match bind_inet_socket(&bind_addr, port, datagram) {
        Ok(fd) => fd,
        Err(e) => {
            error!(
                proto = if datagram { "UDP" } else { "TCP" },
                port,
                service = %service_name,
                error = %e,
                "bind_inet_socket_failed"
            );
            return;
        }
    };
    if wait {
        register_service_listener_fd(&service_name, order, &fd, fd_name);
    }
    handle_listener(fd, service_name, wait, daemon).await;
}

fn bind_inet_socket(bind_addr: &str, port: u16, datagram: bool) -> std::io::Result<OwnedFd> {
    if datagram {
        let socket = bind_udp_socket(bind_addr, port)?;
        return Ok(unsafe { OwnedFd::from_raw_fd(socket.into_raw_fd()) });
    }

    let listener = bind_tcp_listener(bind_addr, port)?;
    listener.set_nonblocking(true)?;
    Ok(listener.into())
}

fn bind_tcp_listener(bind_addr: &str, port: u16) -> std::io::Result<std::net::TcpListener> {
    let host = bind_addr
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(bind_addr);

    if host.contains(':')
        && let Ok(ip) = host
            .split_once('%')
            .map(|(addr, _)| addr)
            .unwrap_or(host)
            .parse::<std::net::Ipv6Addr>()
    {
        return bind_ipv6_dual_stack(ip, port);
    }

    std::net::TcpListener::bind(format!("{}:{}", bind_addr, port))
}

fn bind_udp_socket(bind_addr: &str, port: u16) -> std::io::Result<std::net::UdpSocket> {
    let host = bind_addr
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(bind_addr);
    let bind_target = if host.contains(':') && !bind_addr.starts_with('[') {
        format!("[{}]:{}", host, port)
    } else {
        format!("{}:{}", bind_addr, port)
    };
    let socket = std::net::UdpSocket::bind(bind_target)?;
    socket.set_nonblocking(true)?;
    Ok(socket)
}

fn bind_ipv6_dual_stack(
    ip: std::net::Ipv6Addr,
    port: u16,
) -> std::io::Result<std::net::TcpListener> {
    use std::os::fd::FromRawFd;

    // SAFETY: libc::socket returns a new fd or -1.
    let fd = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }

    let close_fd = |fd| {
        // SAFETY: fd is owned by this function until converted with from_raw_fd.
        let _ = unsafe { libc::close(fd) };
    };

    let reuse: libc::c_int = 1;
    // SAFETY: setsockopt reads `reuse` for the specified size.
    if unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            (&reuse as *const libc::c_int).cast(),
            std::mem::size_of_val(&reuse) as libc::socklen_t,
        )
    } != 0
    {
        let err = std::io::Error::last_os_error();
        close_fd(fd);
        return Err(err);
    }

    let v6only: libc::c_int = 0;
    // SAFETY: setsockopt reads `v6only` for the specified size.
    if unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IPV6,
            libc::IPV6_V6ONLY,
            (&v6only as *const libc::c_int).cast(),
            std::mem::size_of_val(&v6only) as libc::socklen_t,
        )
    } != 0
    {
        let err = std::io::Error::last_os_error();
        close_fd(fd);
        return Err(err);
    }

    let octets = ip.octets();
    let addr = libc::sockaddr_in6 {
        sin6_family: libc::AF_INET6 as libc::sa_family_t,
        sin6_port: port.to_be(),
        sin6_flowinfo: 0,
        sin6_addr: libc::in6_addr { s6_addr: octets },
        sin6_scope_id: 0,
    };
    // SAFETY: addr points to a valid sockaddr_in6 for the specified length.
    if unsafe {
        libc::bind(
            fd,
            (&addr as *const libc::sockaddr_in6).cast(),
            std::mem::size_of_val(&addr) as libc::socklen_t,
        )
    } != 0
    {
        let err = std::io::Error::last_os_error();
        close_fd(fd);
        return Err(err);
    }
    // SAFETY: fd is a valid socket fd.
    if unsafe { libc::listen(fd, 128) } != 0 {
        let err = std::io::Error::last_os_error();
        close_fd(fd);
        return Err(err);
    }

    // SAFETY: fd is uniquely owned and is now transferred to TcpListener.
    Ok(unsafe { std::net::TcpListener::from_raw_fd(fd) })
}

// ============================================================================
// AF_VSOCK listener
// ============================================================================

async fn run_vsock_listener(
    cid: Option<u32>,
    port: u32,
    fd_name: Option<String>,
    service_name: String,
    wait: bool,
    order: usize,
    daemon: Arc<Daemon>,
) {
    let cid = cid.unwrap_or(VMADDR_CID_ANY);
    info!(
        service = %service_name,
        cid,
        port,
        wait,
        "starting_vsock_listener"
    );

    if wait {
        let has_auth = daemon
            .configs
            .lock()
            .get(&service_name)
            .is_some_and(|c| c.auth.is_some());
        if has_auth {
            error!(service = %service_name, "listener_activation_auth_conflict");
            return;
        }
    }

    let fd = match bind_vsock_listener(cid, port) {
        Ok(fd) => fd,
        Err(e) => {
            error!(
                cid,
                port,
                service = %service_name,
                error = %e,
                "bind_vsock_listener_failed"
            );
            return;
        }
    };
    if wait {
        register_service_listener_fd(&service_name, order, &fd, fd_name);
    }
    handle_listener(fd, service_name, wait, daemon).await;
}

#[cfg(target_os = "linux")]
const VMADDR_CID_ANY: u32 = 0xffff_ffff;

#[cfg(not(target_os = "linux"))]
const VMADDR_CID_ANY: u32 = 0xffff_ffff;

#[cfg(target_os = "linux")]
fn bind_vsock_listener(cid: u32, port: u32) -> std::io::Result<OwnedFd> {
    let fd = unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    set_fd_nonblocking(fd.as_raw_fd())?;

    let addr = libc::sockaddr_vm {
        svm_family: libc::AF_VSOCK as libc::sa_family_t,
        svm_reserved1: 0,
        svm_port: port,
        svm_cid: cid,
        svm_zero: [0; 4],
    };
    let rc = unsafe {
        libc::bind(
            fd.as_raw_fd(),
            &addr as *const libc::sockaddr_vm as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_vm>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let rc = unsafe { libc::listen(fd.as_raw_fd(), 128) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(fd)
}

#[cfg(not(target_os = "linux"))]
fn bind_vsock_listener(_cid: u32, _port: u32) -> std::io::Result<OwnedFd> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "AF_VSOCK is only supported on Linux",
    ))
}

fn set_fd_nonblocking(fd: i32) -> std::io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let rc = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    if rc < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

// ============================================================================
// UDS listener
// ============================================================================

async fn run_uds_listener(
    path: String,
    service_name: String,
    wait: bool,
    order: usize,
    datagram: bool,
    socket_mode: Option<u32>,
    socket_user: Option<String>,
    socket_group: Option<String>,
    fd_name: Option<String>,
    daemon: Arc<Daemon>,
) {
    info!(
        proto = if datagram { "UDS datagram" } else { "UDS stream" },
        service = %service_name,
        path = %path,
        "starting_uds_listener"
    );
    if datagram && !wait {
        error!(service = %service_name, "uds_datagram_activation_accept_true_not_supported");
        return;
    }
    if let Some(parent) = std::path::Path::new(&path).parent()
        && let Err(e) = std::fs::create_dir_all(parent)
    {
        error!(
            directory = %parent.display(),
            service = %service_name,
            error = %e,
            "create_uds_directory_failed"
        );
        return;
    }
    let _ = std::fs::remove_file(&path);

    let fd = match bind_unix_socket(&path, datagram) {
        Ok(fd) => fd,
        Err(e) => {
            error!(
                path = %path,
                service = %service_name,
                error = %e,
                "bind_unix_socket_failed"
            );
            return;
        }
    };

    // Apply socket permissions from config, or default to public local IPC.
    // Apps authenticate requests at the protocol layer.
    if let Ok(metadata) = std::fs::metadata(&path) {
        let mode = socket_mode.unwrap_or(0o666);
        let mut perms = metadata.permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut perms, mode);
        let _ = std::fs::set_permissions(&path, perms);
    }

    // Apply socket ownership from config
    if let Some(user) = socket_user {
        if unsafe { libc::getuid() } == 0 {
            let uid = match user.parse::<u32>() {
                Ok(n) => n,
                Err(_) => match lookup_uid_by_name(&user) {
                    Some(n) => n,
                    None => {
                        // Don't fall back to UID 0 (root) — that would
                        // chown the socket to root. Leave ownership unchanged.
                        warn!(
                            user = %user,
                            service = %service_name,
                            "resolve_socket_user_failed"
                        );
                        u32::MAX
                    }
                },
            };
            let c_path = std::ffi::CString::new(path.as_str()).unwrap_or_default();
            let gid = socket_group
                .as_ref()
                .and_then(|g| {
                    if g.is_empty() {
                        None
                    } else {
                        Some(match g.parse::<u32>() {
                            Ok(n) => n,
                            Err(_) => match lookup_gid_by_name(g) {
                                Some(n) => n,
                                None => {
                                    warn!(
                                        group = %g,
                                        service = %service_name,
                                        "resolve_socket_group_failed"
                                    );
                                    u32::MAX
                                }
                            },
                        })
                    }
                })
                .unwrap_or(u32::MAX);
            unsafe {
                libc::chown(c_path.as_ptr() as *const _, uid, gid);
            }
        } else {
            warn!(path = %path, "cannot_chown_non_root");
        }
    } else if let Some(group) = socket_group
        && unsafe { libc::getuid() } == 0
    {
        let gid = match group.parse::<u32>() {
            Ok(n) => n,
            Err(_) => match lookup_gid_by_name(&group) {
                Some(n) => n,
                None => {
                    warn!(
                        group = %group,
                        service = %service_name,
                        "resolve_socket_group_failed"
                    );
                    u32::MAX
                }
            },
        };
        let c_path = std::ffi::CString::new(path.as_str()).unwrap_or_default();
        unsafe {
            libc::chown(c_path.as_ptr() as *const _, u32::MAX, gid);
        }
    }

    if wait {
        register_service_listener_fd(&service_name, order, &fd, fd_name);
    }
    handle_listener(fd, service_name, wait, daemon).await;
}

fn bind_unix_socket(path: &str, datagram: bool) -> std::io::Result<OwnedFd> {
    if datagram {
        let socket = std::os::unix::net::UnixDatagram::bind(path)?;
        socket.set_nonblocking(true)?;
        return Ok(socket.into());
    }

    let listener = std::os::unix::net::UnixListener::bind(path)?;
    listener.set_nonblocking(true)?;
    Ok(listener.into())
}

// ============================================================================
// Core listener loop
// ============================================================================

async fn handle_listener(
    listener_fd: OwnedFd,
    service_name: String,
    wait: bool,
    daemon: Arc<Daemon>,
) {
    let async_fd = match AsyncFd::new(listener_fd) {
        Ok(afd) => afd,
        Err(e) => {
            error!(error = %e, "register_listener_fd_failed");
            return;
        }
    };
    let mut activation_stream: Option<StdUnixStream> = None;

    loop {
        let mut guard = match async_fd.readable().await {
            Ok(g) => g,
            Err(e) => {
                error!(service = %service_name, error = %e, "listener_wait_error");
                break;
            }
        };

        debug!(service = %service_name, "activation_connection_ready");

        if wait {
            // Accept=false: pass the listening FD to the child using systemd-style activation.
            // Phase 1: a Frozen or Freezing service is woken, not started a second time.
            let state_probe = {
                let services = daemon.services.lock();
                services.get(&service_name).map(|p| p.state)
            };
            if let Some(state) = state_probe {
                match state {
                    crate::states::ServiceState::Frozen { .. }
                    | crate::states::ServiceState::Freezing { .. } => {
                        // One poll(fd, 0) sweep first: an already-queued
                        // connection must thaw the service right away.
                        let has_queued = has_pending_connection(async_fd.get_ref().as_raw_fd());
                        info!(
                            service = %service_name,
                            queued = has_queued,
                            "activation_wake_thaw_service"
                        );
                        if let Err(error) = daemon.ensure_running(&service_name, None, None).await {
                            error!(service = %service_name, error = %error, "wake_service_failed");
                        }
                        guard.clear_ready();
                        continue;
                    }
                    // Starting/Running/Stopping: already tracked by the daemon.
                    _ => {
                        guard.clear_ready();
                        continue;
                    }
                }
            }

            let already_running = {
                let services = daemon.services.lock();
                services.get(&service_name).is_some_and(|p| {
                    matches!(
                        p.protocol_state(),
                        ServiceState::Running | ServiceState::Starting
                    )
                })
            };
            if already_running {
                guard.clear_ready();
                continue;
            }

            let config_opt = daemon.configs.lock().get(&service_name).cloned();
            if let Some(mut config) = config_opt {
                if config.auth.is_some() {
                    warn!(service = %service_name, "auth_ignored_for_listener_activation");
                }

                let context = daemon.take_activation_context(&service_name);
                apply_activation_context_env(&mut config, context);

                let mut fds = service_listener_fds(&service_name);
                if fds.is_empty()
                    && let Ok(fd) = async_fd.get_ref().try_clone()
                {
                    fds.push(ActivationListenFd { fd, name: None });
                }
                let passed_fd = Some(ActivationFd::Listen(fds));
                if let Err(e) = daemon
                    .ensure_running(&service_name, Some(config), passed_fd)
                    .await
                {
                    error!(service = %service_name, error = %e, "activate_service_failed");
                }
            }

            guard.clear_ready();
        } else {
            // Accept=true: accept and pass the client fd in inetd style.
            let raw_fd = async_fd.get_ref().as_raw_fd();
            let client_fd =
                unsafe { libc::accept(raw_fd, std::ptr::null_mut(), std::ptr::null_mut()) };

            if client_fd < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::WouldBlock {
                    guard.clear_ready();
                    continue;
                }
                error!(service = %service_name, error = %err, "accept_failed");
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                continue;
            }

            guard.retain_ready();
            let client_owned = unsafe { OwnedFd::from_raw_fd(client_fd) };

            let config_opt = daemon.configs.lock().get(&service_name).cloned();
            if let Some(mut config) = config_opt {
                let context = daemon.take_activation_context(&service_name);
                apply_activation_context_env(&mut config, context);

                // UDS peer auth check
                if let Some(ref auth) = config.auth {
                    let peer_uid = get_peer_uid(client_owned.as_raw_fd());
                    let current_uid = unsafe { libc::getuid() };

                    if let Some(peer_uid) = peer_uid {
                        if !auth.is_uid_authorized(peer_uid, current_uid) {
                            error!(
                                service = %service_name,
                                peer_uid,
                                "activation_rejected_unauthorized_uid"
                            );
                            drop(client_owned);
                            continue;
                        }

                        if let Some(_pattern) = auth.get_delegate(peer_uid) {
                            config
                                .env
                                .insert("X_PEER_DELEGATE_UID".to_string(), peer_uid.to_string());
                        } else {
                            config
                                .env
                                .insert("X_PEER_UID".to_string(), peer_uid.to_string());
                        }
                    } else {
                        error!(
                            service = %service_name,
                            "activation_rejected_peer_uid_unavailable"
                        );
                        drop(client_owned);
                        continue;
                    }
                }

                if config.activation_mode == ServiceActivationMode::Hybrid {
                    let activation_socket = activation_socket_for_service(&config, &service_name);
                    if let Err(e) = forward_accepted_fd(
                        &service_name,
                        &activation_socket,
                        client_owned,
                        &mut activation_stream,
                        daemon.clone(),
                    )
                    .await
                    {
                        error!(
                            service = %service_name,
                            socket = %activation_socket,
                            error = %e,
                            "forward_activated_fd_failed"
                        );
                    }
                    continue;
                }

                let cg = crate::cgroup::create_cgroup(&service_name)
                    .unwrap_or_else(|_| "/sys/fs/cgroup".to_string());

                let permit = match activation_semaphore().acquire_owned().await {
                    Ok(p) => p,
                    Err(e) => {
                        error!(service = %service_name, error = %e, "activation_semaphore_closed");
                        drop(client_owned);
                        continue;
                    }
                };

                match crate::process::spawn_process(
                    &config,
                    &cg,
                    Some(ActivationFd::Stdio(client_owned)),
                ) {
                    Ok((pid, _)) => {
                        debug!(pid, "spawned_activated_instance");
                        if let Some(ref tracked) = *daemon.tracked_child_pids.lock() {
                            tracked.lock().insert(pid);
                        }
                        register_inetd_permit(pid, permit);
                    }
                    Err(e) => {
                        error!(
                            service = %service_name,
                            error = %e,
                            "spawn_activated_instance_failed"
                        );
                        drop(permit);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bind_udp_socket_returns_datagram_fd() {
        let fd = bind_inet_socket("127.0.0.1", 0, true).unwrap();
        assert_eq!(get_sock_type(fd.as_raw_fd()), SocketKind::Datagram);
    }

    #[test]
    fn bind_unix_datagram_socket_returns_datagram_fd() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("svc.sock");
        let fd = bind_unix_socket(path.to_str().unwrap(), true).unwrap();
        assert_eq!(get_sock_type(fd.as_raw_fd()), SocketKind::Datagram);
        assert!(path.exists());
    }
}
