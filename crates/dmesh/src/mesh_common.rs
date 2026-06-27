//! Common mesh node handle and operations shared by the JNI wrapper.
//!
//! The JNI wrapper (`mesh_jni.rs`) delegates to these functions for the actual
//! mesh logic. JNI-specific marshalling stays in the wrapper module.
//!
//! The Rust binary (`main.rs`) and Java/Android wrapper start a single node
//! using the same feature set. Keep them in sync when adding new capabilities.

use ssh_mesh::sshc::SshClientManager;
use ssh_mesh::{run_ssh_server, MeshNode, MeshNodeConfig};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::runtime::Runtime;

/// Opaque handle for a running mesh node instance.
///
/// Owns the tokio runtime, the `MeshNode`, the SSH client manager,
/// and join handles for the SSH and HTTP server tasks.
pub struct MeshHandle {
    pub node: Arc<MeshNode>,
    pub client_manager: Arc<SshClientManager>,
    pub runtime: Runtime,
    pub ssh_server_handle: Option<tokio::task::JoinHandle<()>>,
    pub http_server_handle: Option<tokio::task::JoinHandle<()>>,
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

    Ok(MeshHandle {
        node,
        client_manager,
        runtime,
        ssh_server_handle: Some(ssh_server_handle),
        http_server_handle,
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
    handle.runtime.shutdown_background();
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
