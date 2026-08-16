use anyhow::Result;
use lmesh_wifi::{
    WifiService,
    dispatch::{handle_request, subscription_config},
};
use serde_json::json;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

#[tokio::main]
async fn main() -> Result<()> {
    let service = Arc::new(WifiService::from_environment());
    let netd = Arc::new(service.netd().clone());
    let radio = Arc::new(service.radio().clone());
    let (trace, _guard) = mesh::local_trace::init("lmesh-wifi");
    mesh::local_trace::serve("lmesh-wifi", trace.clone());
    if service.start_object_store() {
        tracing::info!("object_store_startup");
    }
    for result in service.start_stable() {
        tracing::info!(
            ok = result
                .get("ok")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false),
            iface = result
                .get("iface")
                .and_then(serde_json::Value::as_str)
                .unwrap_or(""),
            profile = result
                .get("profile")
                .and_then(serde_json::Value::as_str)
                .unwrap_or(""),
            error = result
                .get("error")
                .and_then(serde_json::Value::as_str)
                .unwrap_or(""),
            "wifi_startup_rate_profile"
        );
    }

    if netd.owned_interfaces().names().is_empty() {
        tracing::warn!("LMESH_INTERFACES is empty; Wi-Fi AP was not started");
    }

    // The Recovery Wi-Fi flashing path is part of the service's normal
    // bearer set. Keep it alive with lmesh-wifi so flash-device.py only has
    // to configure the device; an explicit wifi.object.udp.start request is
    // retained as an idempotent diagnostic/control surface.
    let object_udp = radio.object_udp_start(None, None, None);
    tracing::info!(
        ok = object_udp
            .get("ok")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false),
        port = object_udp
            .get("port")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(3336),
        error = object_udp
            .get("error")
            .and_then(serde_json::Value::as_str)
            .unwrap_or(""),
        "object_udp_startup",
    );
    let path = std::env::var("LMESH_CONTROL_SOCKET")
        .unwrap_or_else(|_| "/run/mesh/lmesh-wifi/mesh.sock".to_string());
    let mut listener = mesh::server::MeshListener::new("lmesh-wifi", Some(&path))
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    while let Some(stream) = listener
        .accept()
        .await
        .map_err(|error| anyhow::anyhow!(error.to_string()))?
    {
        let netd = netd.clone();
        let radio = radio.clone();
        let trace = trace.clone();
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
                    .filter(|n| *n > 0)
                    .is_none()
                {
                    break;
                }
                let request = serde_json::from_str(line.trim()).unwrap_or_else(|_| json!({}));
                if let Some(config) = subscription_config(&request) {
                    let rawnan_subscription = radio.rawnan_subscription_start(&config);
                    let ack = json!({
                        "success": true,
                        "data": {"subscribed": true, "service": "lmesh-wifi", "targets": config.targets.clone()}
                    });
                    if writer.write_all(ack.to_string().as_bytes()).await.is_err()
                        || writer.write_all(b"\n").await.is_err()
                        || writer.flush().await.is_err()
                    {
                        if let Some(iface) = rawnan_subscription {
                            radio.rawnan_subscription_stop(&iface);
                        }
                        break;
                    }
                    for entry in trace.get_all() {
                        if config.matches(&entry) {
                            if writer
                                .write_all(
                                    serde_json::to_string(&entry).unwrap_or_default().as_bytes(),
                                )
                                .await
                                .is_err()
                                || writer.write_all(b"\n").await.is_err()
                            {
                                break;
                            }
                        }
                    }
                    let mut events = trace.subscribe();
                    while let Ok(entry) = events.recv().await {
                        if config.matches(&entry)
                            && (writer
                                .write_all(
                                    serde_json::to_string(&entry).unwrap_or_default().as_bytes(),
                                )
                                .await
                                .is_err()
                                || writer.write_all(b"\n").await.is_err()
                                || writer.flush().await.is_err())
                        {
                            break;
                        }
                    }
                    if let Some(iface) = rawnan_subscription {
                        radio.rawnan_subscription_stop(&iface);
                    }
                    break;
                }
                let response = handle_request(&netd, &radio, request);
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
