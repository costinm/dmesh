//! Common mesh node handle and operations shared by the JNI wrapper.
//!
//! The JNI wrapper (`mesh_jni.rs`) delegates to these functions for the actual
//! mesh logic. JNI-specific marshalling stays in the wrapper module.

use dmesh_store::StoreService;
use ssh_mesh::sshc::SshClientManager;
use ssh_mesh::{MeshNode, MeshNodeConfig, run_ssh_server};
#[cfg(target_os = "android")]
use std::net::Ipv6Addr;
#[cfg(target_os = "android")]
use std::os::fd::FromRawFd;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::runtime::Runtime;

/// Opaque handle for a running mesh node instance.
///
/// Owns the tokio runtime, the `MeshNode`, the SSH client manager,
/// and join handles for the SSH, HTTP, and discovery tasks. The Android UDP
/// socket is retained until the shared QUIC node registers it as a bearer.
pub struct MeshHandle {
    pub node: Arc<MeshNode>,
    pub client_manager: Arc<SshClientManager>,
    pub runtime: Runtime,
    pub ssh_server_handle: Option<tokio::task::JoinHandle<()>>,
    pub http_server_handle: Option<tokio::task::JoinHandle<()>>,
    #[cfg(target_os = "android")]
    pub android_udp_socket: std::sync::Mutex<Option<std::net::UdpSocket>>,
    pub announce_server_handle: Option<tokio::task::JoinHandle<()>>,
    /// Platform network transitions request an immediate announce without
    /// changing the fifteen-minute periodic cadence.
    pub announce_trigger: Option<tokio::sync::mpsc::UnboundedSender<bool>>,
    pub mesh_services: ssh_mesh::mesh_rest::MeshServiceRegistry,
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
    #[cfg_attr(not(target_os = "android"), allow(unused_variables))] android_udp_fd: Option<i32>,
    #[cfg_attr(not(target_os = "android"), allow(unused_variables))] android_discovery_fd: Option<
        i32,
    >,
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

    let mesh_services = ssh_mesh::mesh_rest::MeshServiceRegistry::default();
    #[cfg(target_os = "android")]
    crate::mesh_jni::android_note_started();
    #[cfg(target_os = "android")]
    crate::mesh_jni::register_android_methods();
    #[cfg(target_os = "android")]
    crate::mesh_jni::register_ble_service(&mesh_services);
    #[cfg(target_os = "android")]
    crate::mesh_jni::register_companion_service(&mesh_services);
    #[cfg(target_os = "android")]
    crate::mesh_jni::register_usb_service(&mesh_services);
    #[cfg(target_os = "android")]
    crate::mesh_jni::register_wifi_service(&mesh_services);
    #[cfg(target_os = "android")]
    crate::mesh_jni::register_transport_service(&mesh_services);
    #[cfg(target_os = "android")]
    crate::mesh_jni::register_history_service(&mesh_services);
    #[cfg(target_os = "android")]
    crate::mesh_jni::register_status_service(&mesh_services);
    #[cfg(target_os = "android")]
    crate::mesh_jni::register_probe_service(&mesh_services);
    #[cfg(target_os = "android")]
    crate::mesh_jni::register_telemetry_services(&mesh_services);

    // Spawn HTTP server if port configured
    let mut http_server_handle = None;
    if let Some(h_port) = node.http_port() {
        let app_state = ssh_mesh::AppState {
            ssh_server: node.clone(),
            target_http_address: None,
            ssh_client_manager: client_manager.clone(),
            mesh_services: mesh_services.clone(),
            web_root: Some(base_path.join("web")),
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
    let android_udp_socket = {
        // Java opens this descriptor on Android's selected Network.  Adopt it
        // here so the single Rust QUIC-lite listener retains that route mark;
        // a second bind would silently lose it.
        let socket = match android_udp_fd {
            Some(fd) => unsafe { std::net::UdpSocket::from_raw_fd(fd) },
            None => std::net::UdpSocket::bind((
                Ipv6Addr::UNSPECIFIED,
                dmesh_server::firmware_profile::DEFAULT_EVENT_PORT,
            ))?,
        };
        socket.set_nonblocking(true)?;
        std::sync::Mutex::new(Some(socket))
    };
    #[cfg(target_os = "android")]
    let (announce_server_handle, announce_trigger) = {
        let public_key = node
            .private_key()
            .public_key()
            .to_openssh()
            .unwrap_or_default();
        let (trigger, receiver) = tokio::sync::mpsc::unbounded_channel();
        // A restarted service replaces nothing here: the first trigger stays
        // valid only while its worker runs, so a send error means "not running".
        let _ = SOLICIT.set(trigger.clone());
        let engine = crate::mesh_jni::install_discovery_engine(&public_key);
        (
            Some(runtime.spawn(android_discovery_task(
                engine,
                receiver,
                android_discovery_fd,
            ))),
            Some(trigger),
        )
    };
    #[cfg(not(target_os = "android"))]
    let (announce_server_handle, announce_trigger) = (None, None);

    Ok(MeshHandle {
        node,
        client_manager,
        runtime,
        ssh_server_handle: Some(ssh_server_handle),
        http_server_handle,
        #[cfg(target_os = "android")]
        android_udp_socket,
        announce_server_handle,
        announce_trigger,
        mesh_services,
    })
}

/// Ask the Android announce worker to join/send on a newly available local
/// link, such as a P2P group. The message contains no radio policy or payload.
pub fn trigger_announce(handle: &MeshHandle) -> bool {
    handle
        .announce_trigger
        .as_ref()
        .is_some_and(|trigger| trigger.send(false).is_ok())
}

/// The running announce worker's trigger, for `discovery.active`, which has no
/// access to the mesh handle. `true` also multicasts a discovery request.
static SOLICIT: std::sync::OnceLock<tokio::sync::mpsc::UnboundedSender<bool>> =
    std::sync::OnceLock::new();

/// Announce now and multicast a discovery request on every IPv6 interface, so
/// each listener (lmesh, ESP, other Android) answers with a directed announce.
/// False when the announce worker is not running.
pub fn solicit_discovery() -> bool {
    SOLICIT.get().is_some_and(|trigger| trigger.send(true).is_ok())
}

/// Stop a mesh node, aborting all server tasks and shutting down the runtime.
pub fn stop_mesh(handle: MeshHandle) {
    if let Some(h) = handle.ssh_server_handle {
        h.abort();
    }
    if let Some(h) = handle.http_server_handle {
        h.abort();
    }
    if let Some(h) = handle.announce_server_handle {
        h.abort();
    }
    handle.runtime.shutdown_background();
}

/// Android's local-link presence: the shared `dmesh-discovery` UDP6 transport
/// over the route-marked descriptor Java opened (distinct from the QUIC-lite
/// port, which stays unicast-only). The engine builds and signs nothing here
/// that the other platforms do not: it announces every 15 minutes, on a
/// platform trigger (a P2P group appearing), and when `discovery.active` asks.
#[cfg(target_os = "android")]
async fn android_discovery_task(
    engine: Arc<dmesh_discovery::Engine>,
    mut trigger: tokio::sync::mpsc::UnboundedReceiver<bool>,
    android_discovery_fd: Option<i32>,
) {
    use dmesh_discovery::udp::{Destinations, UdpDiscovery};
    let destinations = Destinations::Multicast { ipv4: false };
    let discovery = match android_discovery_fd {
        // Java used `Network.bindSocket`, the only platform API that applies
        // the selected Wi-Fi route mark; without it a Rust-created 5227
        // socket did not answer a live LAN multicast probe.
        Some(fd) => UdpDiscovery::from_fd(engine, fd, destinations),
        None => UdpDiscovery::bind_multicast(engine).await,
    };
    let discovery = match discovery {
        Ok(discovery) => discovery,
        Err(error) => {
            log::error!("Android discovery socket unavailable: {error}");
            return;
        }
    };
    let _receivers = discovery.spawn();
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(15 * 60));
    loop {
        tokio::select! {
            _ = interval.tick() => {
                let _ = discovery.announce().await;
            }
            Some(solicit) = trigger.recv() => {
                // A P2P group may appear long after boot: announce on it now.
                let _ = discovery.announce().await;
                if solicit {
                    discovery.solicit().await;
                }
            }
        }
    }
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
