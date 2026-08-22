//! Common mesh node handle and operations shared by the JNI wrapper.
//!
//! The JNI wrapper (`mesh_jni.rs`) delegates to these functions for the actual
//! mesh logic. JNI-specific marshalling stays in the wrapper module.

use dmesh_store::StoreService;
use ssh_mesh::sshc::SshClientManager;
use ssh_mesh::{MeshNode, MeshNodeConfig, run_ssh_server};
#[cfg(target_os = "android")]
use std::collections::BTreeSet;
#[cfg(target_os = "android")]
use std::ffi::CStr;
#[cfg(target_os = "android")]
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::runtime::Runtime;

/// Opaque handle for a running mesh node instance.
///
/// Owns the tokio runtime, the `MeshNode`, the SSH client manager,
/// and join handles for the SSH, HTTP, and shared UDP service tasks.
pub struct MeshHandle {
    pub node: Arc<MeshNode>,
    pub client_manager: Arc<SshClientManager>,
    pub runtime: Runtime,
    pub ssh_server_handle: Option<tokio::task::JoinHandle<()>>,
    pub http_server_handle: Option<tokio::task::JoinHandle<()>>,
    pub udp_server_handle: Option<tokio::task::JoinHandle<()>>,
    pub announce_server_handle: Option<tokio::task::JoinHandle<()>>,
}

/// Opaque handle for a bidirectional stream (channel).
pub struct MeshStreamHandle {
    pub stream: DuplexStream,
    pub runtime_handle: tokio::runtime::Handle,
}

/// Create and start a mesh node.
///
/// Initialises the node from `base_dir`, spawns SSH server (and optionally
/// HTTP server), and returns a handle that can be used for subsequent
/// operations.
pub fn start_mesh(
    base_dir: &str,
    ssh_port: i32,
    http_port: i32,
) -> Result<MeshHandle, anyhow::Error> {
    let base_path = PathBuf::from(base_dir);
    let _ = std::fs::create_dir_all(&base_path);

    let runtime = Runtime::new()?;

    let mut cfg = MeshNodeConfig::default();
    cfg.base_dir = Some(base_path.clone());
    cfg.ssh_port = if ssh_port > 0 {
        Some(ssh_port as u16)
    } else {
        Some(0)
    };
    cfg.http_port = if http_port > 0 {
        Some(http_port as u16)
    } else {
        None
    };

    let node = Arc::new(MeshNode::new(Some(base_path.clone()), Some(cfg)));

    let client_manager = Arc::new(SshClientManager::new(
        node.private_key().clone(),
        (*node.ca_keys).clone(),
        Some(base_path.join("config")),
        None,
    ));

    // Initialize dmesh-store service
    let db_path = base_path.join("dmesh-store.db");
    runtime.block_on(async {
        match StoreService::new(db_path.to_str().unwrap()).await {
            Ok(svc) => {
                let sender = svc.sender();
                crate::mesh_jni::init_store_sender(sender);
                tokio::spawn(async move {
                    svc.run().await;
                });
            }
            Err(e) => {
                log::warn!("Failed to initialize dmesh-store: {}", e);
            }
        }
    });

    // Spawn SSH server
    let node_clone = node.clone();
    let ssh_server_handle = runtime.spawn(async move {
        let config = node_clone.get_config();
        let port = node_clone.ssh_port();
        if let Err(e) = run_ssh_server(port, config, (*node_clone).clone()).await {
            log::error!("SSH server failed: {}", e);
        }
    });

    // Spawn HTTP server if port configured
    let mut http_server_handle = None;
    if let Some(h_port) = node.http_port() {
        let app_state = ssh_mesh::AppState {
            ssh_server: node.clone(),
            target_http_address: None,
            ssh_client_manager: client_manager.clone(),
        };
        let app = ssh_mesh::handlers::app(app_state);
        http_server_handle = Some(runtime.spawn(async move {
            let addr = format!("0.0.0.0:{}", h_port);
            match tokio::net::TcpListener::bind(&addr).await {
                Ok(listener) => {
                    if let Err(e) = axum::serve(listener, app.into_make_service()).await {
                        log::error!("HTTP server failed: {}", e);
                    }
                }
                Err(e) => log::error!("Failed to bind HTTP server to {}: {}", addr, e),
            }
        }));
    }

    // Android participates in the same bearer-neutral service surface as
    // lmesh-wifi and firmware. Bind IPv6 explicitly: link-local and NAN
    // data-path tests use scoped IPv6 addresses, while the shared registry
    // supplies status/handlers/iperf without an Android-only replacement.
    // Keep this Android-only: host MeshNode users must not unexpectedly claim
    // the stable Wi-Fi UDP port merely by constructing a node.
    #[cfg(target_os = "android")]
    let udp_server_handle = {
        let udp_config = dmesh_server::udp::UdpConfig {
            bind: SocketAddr::from((
                Ipv6Addr::UNSPECIFIED,
                dmesh_server::udp::STABLE_WIFI_UDP_PORT,
            )),
            artifact_root: base_path.clone(),
            ..dmesh_server::udp::UdpConfig::default()
        };
        Some(runtime.spawn(async move {
            if let Err(error) = dmesh_server::udp::run(udp_config).await {
                log::error!("Android UDP service failed: {error}");
            }
        }))
    };
    #[cfg(not(target_os = "android"))]
    let udp_server_handle = None;

    #[cfg(target_os = "android")]
    let announce_server_handle = {
        let public_key = node
            .private_key()
            .public_key()
            .to_openssh()
            .unwrap_or_default();
        Some(runtime.spawn(android_announce_loop(public_key)))
    };
    #[cfg(not(target_os = "android"))]
    let announce_server_handle = None;

    Ok(MeshHandle {
        node,
        client_manager,
        runtime,
        ssh_server_handle: Some(ssh_server_handle),
        http_server_handle,
        udp_server_handle,
        announce_server_handle,
    })
}

/// Stop a mesh node, aborting all server tasks and shutting down the runtime.
pub fn stop_mesh(handle: MeshHandle) {
    if let Some(h) = handle.ssh_server_handle {
        h.abort();
    }
    if let Some(h) = handle.http_server_handle {
        h.abort();
    }
    if let Some(h) = handle.udp_server_handle {
        h.abort();
    }
    if let Some(h) = handle.announce_server_handle {
        h.abort();
    }
    handle.runtime.shutdown_background();
}

/// Android's local-link presence socket is intentionally distinct from the
/// QUIC-lite port. It uses the established lmesh group and shared CBOR record,
/// while the QUIC UDP listener remains unicast-only.
#[cfg(target_os = "android")]
async fn android_announce_loop(public_key: String) {
    const PORT: u16 = 5227;
    let group = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x5227);
    let socket = match tokio::net::UdpSocket::bind((Ipv6Addr::UNSPECIFIED, PORT)).await {
        Ok(socket) => socket,
        Err(error) => {
            log::error!("Android announce UDP bind failed: {error}");
            return;
        }
    };
    let mut id = [0; 16];
    let key_bytes = public_key.as_bytes();
    let take = key_bytes.len().min(id.len());
    id[..take].copy_from_slice(&key_bytes[..take]);
    let started = tokio::time::Instant::now();
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(15 * 60));
    let mut receive = [0u8; 256];
    let mut boot_pending = true;
    let mut joined_interfaces = BTreeSet::new();
    loop {
        tokio::select! {
            _ = interval.tick() => {
                let kind = if boot_pending {
                    dmesh_server::announce::ANNOUNCE_BOOT
                } else {
                    dmesh_server::announce::ANNOUNCE_DISCOVERY
                };
                let announce = if kind == dmesh_server::announce::ANNOUNCE_BOOT {
                    dmesh_server::announce::Announce::boot(id, take as u8, 0)
                } else {
                    dmesh_server::announce::Announce::discovery(
                        id,
                        take as u8,
                        u32::try_from(started.elapsed().as_secs()).unwrap_or(u32::MAX),
                        0,
                        0,
                    )
                };
                let mut wire = [0u8; 96];
                if let Some(used) = dmesh_server::announce::encode(announce, &mut wire) {
                    let interfaces = multicast_interface_indices();
                    for interface_index in &interfaces {
                        if joined_interfaces.insert(*interface_index) {
                            if let Err(error) = socket.join_multicast_v6(&group, *interface_index) {
                                log::warn!("Android announce multicast join failed on interface {interface_index}: {error}");
                            }
                        }
                    }
                    let mut sent = false;
                    for interface_index in interfaces {
                        let destination = SocketAddr::V6(SocketAddrV6::new(group, PORT, 0, interface_index));
                        match socket.send_to(&wire[..used], destination).await {
                            Ok(_) => sent = true,
                            Err(error) => log::warn!("Android announce multicast send failed on interface {interface_index}: {error}"),
                        }
                    }
                    // Do not silently lose the boot event when the service starts before
                    // Wi-Fi/NAN has an IPv6 interface. The first successful emission is boot.
                    if sent {
                        boot_pending = false;
                    }
                }
            }
            received = socket.recv_from(&mut receive) => match received {
                Ok((len, sender)) => {
                    if let Some(announce) = dmesh_server::announce::decode_announce(&receive[..len]) {
                        crate::mesh_jni::observe_announce(
                            announce,
                            sender.to_string(),
                            "udp_multicast",
                        );
                    }
                }
                Err(error) => {
                    log::warn!("Android announce UDP receive failed: {error}");
                }
            },
        }
    }
}

/// Return each enabled, non-loopback IPv6 interface index. Android's
/// link-local multicast routes require this scope; `0` is not enough to select
/// Wi-Fi and would make a service-start boot announce disappear before a
/// network becomes available.
#[cfg(target_os = "android")]
fn multicast_interface_indices() -> Vec<u32> {
    let mut interfaces = BTreeSet::new();
    unsafe {
        let mut head = std::ptr::null_mut();
        if libc::getifaddrs(&mut head) != 0 {
            log::warn!(
                "Android announce could not enumerate interfaces: {}",
                std::io::Error::last_os_error()
            );
            return Vec::new();
        }
        let mut current = head;
        while !current.is_null() {
            let entry = &*current;
            let enabled = entry.ifa_flags & (libc::IFF_UP as u32) != 0;
            let loopback = entry.ifa_flags & (libc::IFF_LOOPBACK as u32) != 0;
            if enabled
                && !loopback
                && !entry.ifa_addr.is_null()
                && (*entry.ifa_addr).sa_family as i32 == libc::AF_INET6
            {
                let index = libc::if_nametoindex(CStr::from_ptr(entry.ifa_name).as_ptr());
                if index != 0 {
                    interfaces.insert(index);
                }
            }
            current = entry.ifa_next;
        }
        libc::freeifaddrs(head);
    }
    interfaces.into_iter().collect()
}

/// Connect to a remote SSH server.
pub fn mesh_connect(
    handle: &MeshHandle,
    host: &str,
    port: u16,
    user: &str,
    server_key: &str,
) -> Result<u64, anyhow::Error> {
    handle.runtime.block_on(async {
        handle
            .client_manager
            .connect(host, port, user, server_key)
            .await
    })
}

/// Execute a command on an existing SSH connection.
pub fn mesh_exec(
    handle: &MeshHandle,
    conn_id: u64,
    command: &str,
) -> Result<String, anyhow::Error> {
    let res = handle
        .runtime
        .block_on(async { handle.client_manager.exec(conn_id, command).await })?;
    Ok(res.stdout)
}

/// Open a bidirectional stream to a remote host through an SSH connection.
pub fn mesh_open_stream(
    handle: &MeshHandle,
    conn_id: u64,
    host: &str,
    port: u16,
) -> Result<MeshStreamHandle, anyhow::Error> {
    let stream = handle
        .runtime
        .block_on(async { handle.client_manager.open_stream(conn_id, host, port).await })?;
    Ok(MeshStreamHandle {
        stream,
        runtime_handle: handle.runtime.handle().clone(),
    })
}

/// Get the node's public key in OpenSSH format.
pub fn mesh_get_public_key(handle: &MeshHandle) -> String {
    handle
        .node
        .private_key()
        .public_key()
        .to_openssh()
        .unwrap_or_default()
}

/// Add a local port forward on an SSH connection.
pub fn mesh_add_local_forward(
    handle: &MeshHandle,
    conn_id: u64,
    local_port: u16,
    remote_host: &str,
    remote_port: u16,
) -> Result<(), anyhow::Error> {
    handle.runtime.block_on(async {
        handle
            .client_manager
            .add_local_forward(conn_id, local_port, remote_host, remote_port)
            .await
    })?;
    Ok(())
}

/// Add a remote port forward on an SSH connection.
pub fn mesh_add_remote_forward(
    handle: &MeshHandle,
    conn_id: u64,
    remote_port: u16,
    local_host: &str,
    local_port: u16,
) -> Result<u32, anyhow::Error> {
    handle.runtime.block_on(async {
        handle
            .client_manager
            .add_remote_forward(conn_id, remote_port, local_host, local_port)
            .await
    })
}

/// Read from a stream into a buffer. Returns the number of bytes read.
pub fn stream_read(handle: &mut MeshStreamHandle, buf: &mut [u8]) -> Result<usize, anyhow::Error> {
    let n = handle
        .runtime_handle
        .block_on(async { handle.stream.read(buf).await })?;
    Ok(n)
}

/// Write data to a stream.
pub fn stream_write(handle: &mut MeshStreamHandle, data: &[u8]) -> Result<(), anyhow::Error> {
    handle
        .runtime_handle
        .block_on(async { handle.stream.write_all(data).await })?;
    Ok(())
}

/// Shutdown and close a stream.
pub fn stream_close(handle: &mut MeshStreamHandle) -> Result<(), anyhow::Error> {
    handle.runtime_handle.block_on(async {
        let _ = handle.stream.shutdown().await;
    });
    Ok(())
}
