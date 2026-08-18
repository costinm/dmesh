//! Retired compatibility entry point. Use the standalone `dmesh-cli` binary.

fn main() -> anyhow::Result<()> {
    lmesh_uart::client::run_dmesh_cli().map_err(anyhow::Error::msg)
}
