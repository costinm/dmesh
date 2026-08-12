//! Stable UART forwarding JSONL service.

use anyhow::Result;
use lmesh_uart::{UartService, handle_request};
use serde_json::json;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

#[tokio::main]
async fn main() -> Result<()> {
    let uart = Arc::new(UartService::from_environment());
    let (trace, _guard) = mesh::local_trace::init("lmesh-uart");
    mesh::local_trace::serve("lmesh-uart", trace);
    // mesh-init provides the service HOME and creates /run/mesh/lmesh-uart.
    // Keep the socket default fixed so HOME is the only service-specific
    // setting needed for configuration and logs.
    let path = std::env::var("LMESH_CONTROL_SOCKET")
        .unwrap_or_else(|_| "/run/mesh/lmesh-uart/mesh.sock".to_string());
    let mut listener = mesh::server::MeshListener::new("lmesh-uart", Some(&path))
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    while let Some(stream) = listener
        .accept()
        .await
        .map_err(|error| anyhow::anyhow!(error.to_string()))?
    {
        let uart = uart.clone();
        tokio::spawn(async move {
            let (reader, mut writer) = tokio::io::split(stream);
            let mut reader = BufReader::new(reader);
            let mut line = String::new();
            loop {
                line.clear();
                if reader
                    .read_line(&mut line)
                    .await
                    .ok()
                    .filter(|count| *count > 0)
                    .is_none()
                {
                    break;
                }
                let request = serde_json::from_str(line.trim()).unwrap_or_else(|_| json!({}));
                let response = handle_request(&uart, request);
                if writer
                    .write_all(response.to_string().as_bytes())
                    .await
                    .is_err()
                {
                    break;
                }
                if writer.write_all(b"\n").await.is_err() {
                    break;
                }
                let _ = writer.flush().await;
            }
        });
    }
    Ok(())
}
