use anyhow::Result;

/// BLE-enabled launcher for the shared lmesh-wifi mesh core.
#[tokio::main]
async fn main() -> Result<()> {
    lmesh_wifi::mesh_runtime::run_mesh_service(lmesh_wifi::mesh_runtime::LMESH_DEFAULTS).await
}
