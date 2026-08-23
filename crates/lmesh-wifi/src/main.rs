use anyhow::Result;
use lmesh_wifi::{
    WifiService,
    dispatch::{
        handle_request, handle_reviewed_request, normalize_json_rpc_request, subscription_config,
    },
    reviewed::ReviewedWifiRequest,
};
use serde_json::json;
use std::sync::{Arc, LazyLock};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

static CONTROL_CATALOG: LazyLock<mesh::tagged::TaggedCatalog> = LazyLock::new(|| {
    mesh::tagged::TaggedCatalog::from_tools_json(
        &serde_json::from_str(include_str!("../resources/tools.json"))
            .expect("lmesh-wifi tools.json must be valid JSON"),
    )
    .expect("lmesh-wifi tools.json must be a valid tagged catalog")
});

struct WifiCborHandler {
    netd: Arc<lmesh_wifi::WifiNetd>,
    radio: Arc<lmesh_wifi::RadioService>,
}

#[async_trait::async_trait]
impl mesh::wire::TaggedRecordHandler for WifiCborHandler {
    async fn handle_record(
        &self,
        record: mesh::tagged::TaggedRecord,
    ) -> anyhow::Result<Option<mesh::tagged::TaggedRecord>> {
        let id = record
            .id
            .clone()
            .ok_or_else(|| anyhow::anyhow!("tagged-CBOR request missing id"))?;
        let request = match decode_wifi_tagged_request(&record) {
            Ok(request) => request,
            Err(error) => {
                return Ok(Some(mesh::wire::response_error(
                    id,
                    json!({"error": error.to_string()}),
                )));
            }
        };
        let response = handle_reviewed_request(&self.netd, &self.radio, request);
        Ok(Some(mesh::wire::response_ok(id, response)))
    }
}

fn decode_wifi_tagged_request(
    record: &mesh::tagged::TaggedRecord,
) -> anyhow::Result<ReviewedWifiRequest> {
    let Some(method) = CONTROL_CATALOG.method_name(record) else {
        anyhow::bail!("tagged-CBOR method is outside the reviewed wifi catalog");
    };
    let value = CONTROL_CATALOG.to_jsonl(record);
    match method {
        "wifi.ap.status" => serde_json::from_value(value).map(ReviewedWifiRequest::ApStatus),
        "wifi.sta.status" => serde_json::from_value(value).map(ReviewedWifiRequest::StaStatus),
        "wifi.rawnan.status" => {
            serde_json::from_value(value).map(ReviewedWifiRequest::RawNanStatus)
        }
        "wifi.probe.plan" => serde_json::from_value(value).map(ReviewedWifiRequest::ProbePlan),
        "wifi.interface.status" => {
            serde_json::from_value(value).map(ReviewedWifiRequest::InterfaceStatus)
        }
        "wifi.ap.stations" => serde_json::from_value(value).map(ReviewedWifiRequest::ApStations),
        "wifi.raw.metrics" => serde_json::from_value(value).map(ReviewedWifiRequest::RawMetrics),
        "wifi.raw.stop" => serde_json::from_value(value).map(ReviewedWifiRequest::RawStop),
        "wifi.raw.listen" => serde_json::from_value(value).map(ReviewedWifiRequest::RawListen),
        "wifi.raw.check" => serde_json::from_value(value).map(ReviewedWifiRequest::RawCheck),
        "wifi.raw.iperf" => serde_json::from_value(value).map(ReviewedWifiRequest::RawIperf),
        "wifi.raw.send" => serde_json::from_value(value).map(ReviewedWifiRequest::RawSend),
        "wifi.rawnan.ping" => serde_json::from_value(value).map(ReviewedWifiRequest::RawNanPing),
        "wifi.rawnan.listen" => {
            serde_json::from_value(value).map(ReviewedWifiRequest::RawNanListen)
        }
        _ => unreachable!("the reviewed wifi catalog contains only typed read-only methods"),
    }
    .map_err(Into::into)
}

#[tokio::main]
async fn main() -> Result<()> {
    let service = Arc::new(WifiService::from_environment());
    let netd = Arc::new(service.netd().clone());
    let radio = Arc::new(service.radio().clone());
    let (trace, _guard) = mesh::local_trace::init("lmesh-wifi");
    mesh::local_trace::serve("lmesh-wifi", trace.clone());
    // wlan0 is the stable infrastructure fixture: start its AP at service
    // launch. lmesh owns the independent AP-off NAN+NOW/STA+NOW radio.
    for result in service.start_stable() {
        let phase = if result.get("ssid").is_some() {
            "ap_start"
        } else if result.get("monitor_iface").is_some() {
            "raw_monitor"
        } else if result.get("profile").is_some() {
            "rate_profile"
        } else {
            "startup"
        };
        tracing::info!(
            phase,
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
            result = ?result,
            "wifi_startup_result"
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
            let mut stream = stream;
            let mut first = [0_u8; 1];
            let Ok(bytes_read) = stream.read(&mut first).await else {
                return;
            };
            if bytes_read == 0 {
                return;
            }
            let mut stream = mesh::wire::PrefixedStream::new(first[0], stream);
            if first[0] == 0 {
                let _ =
                    mesh::wire::serve_cbor_session(&mut stream, &WifiCborHandler { netd, radio })
                        .await;
                return;
            }
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
                let request = normalize_json_rpc_request(
                    serde_json::from_str(line.trim()).unwrap_or_else(|_| json!({})),
                );
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reviewed_wifi_status_decodes_numeric_tags() {
        let request = decode_wifi_tagged_request(&mesh::tagged::TaggedRecord {
            component: mesh::tagged::NameOrTag::Tag(5),
            method: mesh::tagged::NameOrTag::Tag(1),
            id: Some(json!(11)),
            env: [(mesh::tagged::NameOrTag::Tag(1), json!("wlan0"))]
                .into_iter()
                .collect(),
            ..Default::default()
        })
        .unwrap();
        assert!(
            matches!(request, ReviewedWifiRequest::ApStatus(request) if request.iface.as_deref() == Some("wlan0"))
        );
    }

    #[test]
    fn reviewed_wifi_metrics_decode_numeric_tags() {
        let request = decode_wifi_tagged_request(&mesh::tagged::TaggedRecord {
            component: mesh::tagged::NameOrTag::Tag(5),
            method: mesh::tagged::NameOrTag::Tag(6),
            id: Some(json!(12)),
            env: [(mesh::tagged::NameOrTag::Tag(1), json!("wlan0"))]
                .into_iter()
                .collect(),
            ..Default::default()
        })
        .unwrap();
        assert!(
            matches!(request, ReviewedWifiRequest::RawMetrics(request) if request.iface.as_deref() == Some("wlan0"))
        );
    }

    #[test]
    fn reviewed_pair_probe_plan_decodes_numeric_tags() {
        let request = decode_wifi_tagged_request(&mesh::tagged::TaggedRecord {
            component: mesh::tagged::NameOrTag::Tag(5),
            method: mesh::tagged::NameOrTag::Tag(16),
            id: Some(json!(13)),
            env: [
                (mesh::tagged::NameOrTag::Tag(1), json!("wlan0")),
                (mesh::tagged::NameOrTag::Tag(2), json!("111111111111")),
                (mesh::tagged::NameOrTag::Tag(3), json!("222222222222")),
            ]
            .into_iter()
            .collect(),
            ..Default::default()
        })
        .unwrap();
        assert!(matches!(
            request,
            ReviewedWifiRequest::ProbePlan(request)
                if request.iface.as_deref() == Some("wlan0")
                    && request.source_id == "111111111111"
                    && request.target_id == "222222222222"
        ));
    }

    #[test]
    fn unreviewed_wifi_method_is_not_named_cbor() {
        assert!(
            decode_wifi_tagged_request(&mesh::tagged::TaggedRecord {
                component: mesh::tagged::NameOrTag::Name("wifi".to_owned()),
                method: mesh::tagged::NameOrTag::Name("ap.stop".to_owned()),
                id: Some(json!(11)),
                ..Default::default()
            })
            .is_err()
        );
    }
}
