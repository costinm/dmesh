//! Shared host HTTP adapter for the upstream ssh-mesh admin router.
//!
//! Linux and Android supply different private backends, but listener setup,
//! request normalization, omitted-ID allocation, and routing all use this one
//! Rust integration. The HTTP layer never dispatches a bearer-specific DMesh
//! command itself.

use std::{net::SocketAddr, path::PathBuf, sync::Arc};

/// One backend exposed through the shared ssh-mesh HTTP/UI router.
pub struct HttpService {
    pub name: String,
    pub backend: ssh_mesh::mesh_rest::MeshServiceBackend,
    pub catalog: Option<serde_json::Value>,
}

/// Everything needed to serve one host's admin endpoint.
pub struct HttpConfig {
    pub bind: SocketAddr,
    pub node: Arc<ssh_mesh::MeshNode>,
    pub client_manager: Arc<ssh_mesh::sshc::SshClientManager>,
    pub service: HttpService,
    pub web_root: Option<PathBuf>,
}

/// Serve the common admin router until the listener stops.
pub async fn serve(config: HttpConfig) -> anyhow::Result<()> {
    let services = ssh_mesh::mesh_rest::MeshServiceRegistry::default();
    services.register(
        config.service.name,
        ssh_mesh::mesh_rest::MeshService {
            backend: config.service.backend,
            catalog: config.service.catalog,
        },
    );
    let app = ssh_mesh::handlers::app(ssh_mesh::AppState {
        ssh_server: config.node,
        target_http_address: None,
        ssh_client_manager: config.client_manager,
        mesh_services: services,
        web_root: config.web_root,
    });
    let listener = tokio::net::TcpListener::bind(config.bind).await?;
    axum::serve(listener, app.into_make_service()).await?;
    Ok(())
}
