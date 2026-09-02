use anyhow::Result;

/// Stable launcher for the shared lmesh-wifi mesh core.
#[tokio::main]
async fn main() -> Result<()> {
    lmesh_wifi::mesh_runtime::run_mesh_service(lmesh_wifi::mesh_runtime::LMESH_WIFI_DEFAULTS).await
}
