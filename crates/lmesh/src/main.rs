use anyhow::Result;

/// Linux mesh daemon with radio and BLE adapters.
#[tokio::main]
async fn main() -> Result<()> {
    lmesh_wifi::mesh_runtime::run_mesh_service(lmesh_wifi::mesh_runtime::LMESH_DEFAULTS).await
}
