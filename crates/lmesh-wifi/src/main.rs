use anyhow::Result;
use lmesh_wifi::{Operation, RadioService, WifiNetd};
use serde_json::{Value, json};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

fn string_arg(request: &Value, name: &str) -> Option<String> {
    request.get(name).and_then(Value::as_str).map(str::to_owned)
}

fn iface_arg(request: &Value) -> Option<String> {
    string_arg(request, "iface").or_else(lmesh_wifi::default_interface)
}

fn authorize(netd: &WifiNetd, request: &Value, operation: Operation) -> Result<String> {
    let iface = iface_arg(request)
        .ok_or_else(|| anyhow::anyhow!("LMESH_INTERFACES must name an owned Wi-Fi interface"))?;
    netd.authorize(operation, &iface)?;
    Ok(iface)
}

fn configure_ap_address(radio: &RadioService, iface: &str) {
    let cidr = std::env::var("LMESH_AP_ADDRESS")
        .unwrap_or_else(|_| "10.78.0.1/16".to_owned());
    let (address, prefix) = cidr.split_once('/').unwrap_or((&cidr, "16"));
    let prefix = match prefix.parse::<u8>() {
        Ok(prefix) => prefix,
        Err(error) => {
            tracing::error!(%error, address = %cidr, "wifi_ap_address_invalid");
            return;
        }
    };
    let result = radio.wifi_sta_configure_ipv4(Some(iface.to_owned()), address.to_owned(), Some(prefix));
    let ok = result.get("ok").and_then(serde_json::Value::as_bool).unwrap_or(false);
    let backend = result.get("backend").and_then(serde_json::Value::as_str).unwrap_or("");
    tracing::info!(
        address = %cidr,
        ok,
        backend,
        "wifi_service_ap_address"
    );
}

fn log_ap_start(result: &Value, iface: &str) {
    let steps = result.get("steps").and_then(Value::as_array);
    let step_count = steps.map(Vec::len).unwrap_or(0);
    let failed_steps = steps
        .map(|items| {
            items
                .iter()
                .filter(|item| item.get("ok").and_then(Value::as_bool) == Some(false))
                .count()
        })
        .unwrap_or(0);
    let ok = result.get("ok").and_then(serde_json::Value::as_bool).unwrap_or(false);
    let ssid = result.get("ssid").and_then(serde_json::Value::as_str).unwrap_or("");
    let bssid = result.get("bssid").and_then(serde_json::Value::as_str).unwrap_or("");
    let channel = result.get("channel").and_then(serde_json::Value::as_u64).unwrap_or(0);
    let profile = result.get("selected_profile").and_then(serde_json::Value::as_str).unwrap_or("");
    let error = result.get("error").and_then(serde_json::Value::as_str).unwrap_or("");
    tracing::info!(
        iface = %iface,
        ok,
        ssid,
        bssid,
        channel,
        profile,
        step_count,
        failed_steps,
        error,
        "wifi_service_ap_start"
    );
}

fn log_rawnan_start(result: &Value, iface: &str) {
    tracing::info!(
        iface = %iface,
        ok = result.get("ok").and_then(serde_json::Value::as_bool).unwrap_or(false),
        backend = result.get("backend").and_then(serde_json::Value::as_str).unwrap_or(""),
        monitor_iface = result.get("monitor_iface").and_then(serde_json::Value::as_str).unwrap_or(""),
        channel = result.get("channel").and_then(serde_json::Value::as_u64).unwrap_or(0),
        rx_variant = result.get("rx_variant").and_then(serde_json::Value::as_str).unwrap_or(""),
        error = result.get("error").and_then(serde_json::Value::as_str).unwrap_or(""),
        "wifi_service_rawnan_start"
    );
}

fn subscription_config(request: &Value) -> Option<mesh::local_trace::TraceConfig> {
    let method = request.get("method").and_then(Value::as_str)?;
    if !(matches!(method, "subscribe" | "trace.subscribe" | "events.subscribe")
        || method.ends_with(".subscribe"))
    {
        return None;
    }
    let mut config = request
        .get("params")
        .cloned()
        .unwrap_or_else(|| request.clone());
    if let Some(object) = config.as_object_mut() {
        object.remove("method");
        object.remove("jsonrpc");
        object.remove("id");
        if let Some(Value::Array(params)) = object.remove("params") {
            for param in params {
                if let Some(param) = param.as_str()
                    && let Some((key, value)) = param.split_once('=')
                {
                    object.insert(key.to_owned(), Value::String(value.to_owned()));
                }
            }
        }
        // The text mesh CLI represents repeated values as a comma-separated
        // scalar; accept that form as well as the raw JSON array.
        if let Some(Value::String(targets)) = object.get("targets").cloned() {
            object.insert(
                "targets".to_owned(),
                Value::Array(
                    targets
                        .split(',')
                        .filter(|target| !target.is_empty())
                        .map(|target| Value::String(target.to_owned()))
                        .collect(),
                ),
            );
        }
    }
    serde_json::from_value(config).ok()
}

fn handle_request(netd: &WifiNetd, radio: &RadioService, request: Value) -> Value {
    let method = request.get("method").and_then(Value::as_str).unwrap_or("");
    let result = (|| -> Result<Value> {
        match method {
            "wifi.ap.start_open" => {
                let iface = authorize(netd, &request, Operation::Ap)?;
                Ok(radio.wifi_ap_start_open(Some(iface), string_arg(&request, "ssid")))
            }
            "wifi.ap.stop" => {
                let iface = authorize(netd, &request, Operation::Ap)?;
                Ok(radio.wifi_ap_stop(Some(iface)))
            }
            "wifi.ap.status" => {
                let iface = authorize(netd, &request, Operation::Ap)?;
                Ok(radio.wifi_ap_status(Some(iface)))
            }
            "wifi.ap.configure_ipv4" => {
                let iface = authorize(netd, &request, Operation::Ap)?;
                let address = string_arg(&request, "address")
                    .ok_or_else(|| anyhow::anyhow!("address is required"))?;
                Ok(radio.wifi_sta_configure_ipv4(
                    Some(iface),
                    address,
                    request.get("prefix").and_then(Value::as_u64).map(|value| value.min(32) as u8),
                ))
            }
            "wifi.ap.stations" => {
                let iface = authorize(netd, &request, Operation::Ap)?;
                Ok(radio.wifi_ap_stations(Some(iface)))
            }
            "wifi.ap.station.remove" => {
                let iface = authorize(netd, &request, Operation::Ap)?;
                let mac = string_arg(&request, "mac")
                    .ok_or_else(|| anyhow::anyhow!("mac is required"))?;
                Ok(radio.wifi_ap_station_remove(Some(iface), mac))
            }
            "wifi.ap.station.remove_all" => {
                let iface = authorize(netd, &request, Operation::Ap)?;
                Ok(radio.wifi_ap_station_remove_all(Some(iface)))
            }
            "wifi.scan" => {
                let iface = authorize(netd, &request, Operation::Sta)?;
                Ok(radio.wifi_scan(Some(iface), string_arg(&request, "ssid")))
            }
            "wifi.sta.status" => {
                let iface = authorize(netd, &request, Operation::Sta)?;
                Ok(radio.wifi_sta_status(Some(iface)))
            }
            "wifi.nan.start" => {
                let iface = authorize(netd, &request, Operation::Nan)?;
                Ok(radio.nan_start(Some(iface), string_arg(&request, "ctrl_dir")))
            }
            "wifi.nan.status" => {
                let iface = authorize(netd, &request, Operation::Nan)?;
                Ok(radio.nan_status(
                    Some(iface),
                    string_arg(&request, "ctrl_dir"),
                    request.get("events_ms").and_then(Value::as_u64),
                ))
            }
            "wifi.nan.default" => {
                let iface = authorize(netd, &request, Operation::Nan)?;
                Ok(radio.nan_default(
                    Some(iface),
                    string_arg(&request, "ctrl_dir"),
                    string_arg(&request, "service_name"),
                    request.get("ttl").and_then(Value::as_u64).map(|v| v as u32),
                ))
            }
            "wifi.nan.ping" => {
                let iface = authorize(netd, &request, Operation::Nan)?;
                Ok(radio.nan_ping(
                    Some(iface),
                    string_arg(&request, "ctrl_dir"),
                    string_arg(&request, "peer"),
                    string_arg(&request, "payload"),
                )?)
            }
            "wifi.nan.native.start" => {
                let iface = authorize(netd, &request, Operation::Nan)?;
                Ok(radio.nan_native_start(
                    Some(iface),
                    string_arg(&request, "service_name"),
                    request.get("subscribe").and_then(Value::as_bool).unwrap_or(false),
                ))
            }
            "wifi.nan.usd.start" => {
                let iface = authorize(netd, &request, Operation::Nan)?;
                Ok(radio.nan_usd_start(
                    Some(iface),
                    string_arg(&request, "service_name"),
                    request.get("subscribe").and_then(Value::as_bool).unwrap_or(false),
                    request.get("infra").and_then(Value::as_bool).unwrap_or(false),
                ))
            }
            "wifi.nan.native.status" => {
                let iface = authorize(netd, &request, Operation::Nan)?;
                Ok(radio.nan_native_status(Some(iface)))
            }
            "wifi.nan.native.transmit" => {
                let iface = authorize(netd, &request, Operation::Nan)?;
                let destination = string_arg(&request, "destination")
                    .ok_or_else(|| anyhow::anyhow!("destination is required"))?;
                let payload = string_arg(&request, "payload").unwrap_or_default();
                Ok(radio.nan_native_transmit(
                    Some(iface),
                    destination,
                    request.get("instance_id").and_then(Value::as_u64).unwrap_or(1) as u8,
                    request.get("requestor_id").and_then(Value::as_u64).unwrap_or(1) as u8,
                    payload,
                ))
            }
            "wifi.nan.native.stop" => {
                let iface = authorize(netd, &request, Operation::Nan)?;
                Ok(radio.nan_native_stop(Some(iface)))
            }
            "wifi.rawnan.listen" => {
                let iface = authorize(netd, &request, Operation::Nan)?;
                if string_arg(&request, "rx_variant").as_deref() == Some("native") {
                    return Ok(radio.nan_native_start(
                        Some(iface),
                        string_arg(&request, "service_name"),
                        request.get("subscribe").and_then(Value::as_bool).unwrap_or(false),
                    ));
                }
                Ok(radio.wifi_raw_listen(
                    Some(iface),
                    None,
                    request.get("channel").and_then(Value::as_u64).map(|v| v.min(13) as u8),
                    request.get("listen_sec").and_then(Value::as_u64),
                    Some("monitor".to_owned()),
                ))
            }
            "wifi.rawnan.status" => {
                let iface = authorize(netd, &request, Operation::Nan)?;
                Ok(radio.rawnan_status(Some(iface)))
            }
            "wifi.interface.status" => {
                let iface = authorize(netd, &request, Operation::Nan)?;
                Ok(radio.wifi_interface_status(Some(iface)))
            }
            "wifi.interface.up" => {
                let iface = authorize(netd, &request, Operation::Nan)?;
                Ok(radio.wifi_interface_up(Some(iface)))
            }
            "wifi.interface.channel" => {
                let iface = authorize(netd, &request, Operation::Nan)?;
                let channel = request
                    .get("channel")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| anyhow::anyhow!("channel is required"))?;
                Ok(radio.wifi_interface_set_channel(Some(iface), channel.min(13) as u8))
            }
            "wifi.raw.stop" => {
                let iface = authorize(netd, &request, Operation::Nan)?;
                Ok(radio.wifi_raw_stop(Some(iface)))
            }
            "wifi.rawnan.ping" => {
                let iface = authorize(netd, &request, Operation::Nan)?;
                Ok(radio.rawnan_ping(
                    Some(iface),
                    request.get("channel").and_then(Value::as_u64).map(|v| v.min(13) as u8),
                    string_arg(&request, "destination"),
                    string_arg(&request, "bssid"),
                    string_arg(&request, "payload").unwrap_or_else(|| "ping".to_owned()),
                    request.get("wait_ms").and_then(Value::as_u64),
                ))
            }
            "wifi.raw.send" => {
                let iface = authorize(netd, &request, Operation::Nan)?;
                if let Some(frame_hex) = string_arg(&request, "frame_hex") {
                    return Ok(radio.wifi_raw_send_frame(
                        Some(iface),
                        request.get("channel").and_then(Value::as_u64).map(|v| v.min(13) as u8),
                        string_arg(&request, "tx_variant"),
                    frame_hex,
                ));
                }
                Ok(radio.wifi_raw_send(
                    Some(iface),
                    string_arg(&request, "ctrl_dir"),
                    request.get("channel").and_then(Value::as_u64).map(|v| v.min(13) as u8),
                    request.get("listen_sec").and_then(Value::as_u64),
                    string_arg(&request, "destination"),
                    string_arg(&request, "source"),
                    string_arg(&request, "tx_variant"),
                    request.get("tx_duration_ms").and_then(Value::as_u64).map(|v| v as u32),
                    string_arg(&request, "bssid"),
                    string_arg(&request, "llc"),
                    string_arg(&request, "payload").unwrap_or_default(),
                ))
            }
            "wifi.raw.bench_send" => {
                let iface = authorize(netd, &request, Operation::Nan)?;
                let destination = string_arg(&request, "destination")
                    .ok_or_else(|| anyhow::anyhow!("destination is required"))?;
                let bytes = request
                    .get("bytes")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| anyhow::anyhow!("bytes is required"))?;
                Ok(radio.wifi_raw_bench_send(
                    Some(iface),
                    request.get("channel").and_then(Value::as_u64).map(|v| v.min(13) as u8),
                    destination,
                    string_arg(&request, "bssid"),
                    bytes as usize,
                    request.get("chunk_bytes").and_then(Value::as_u64).map(|v| v as usize),
                    string_arg(&request, "tx_variant"),
                    string_arg(&request, "llc"),
                    request.get("multicast").and_then(Value::as_bool).unwrap_or(false),
                ))
            }
            "messages.history" => Ok(radio.history(
                string_arg(&request, "keys"),
                request.get("limit").and_then(Value::as_u64).map(|v| v as usize),
            )),
            "esp.serial.command" => Ok(radio.esp_remote_command(
                string_arg(&request, "gateway").unwrap_or_default(),
                string_arg(&request, "target"),
                string_arg(&request, "command").unwrap_or_default(),
                request.get("timeout_sec").and_then(Value::as_f64),
                request
                    .get("active_ms")
                    .and_then(Value::as_u64)
                    .map(|v| v as u32),
            )),
            "status" => Ok(json!({
                "service": "lmesh-wifi",
                "interfaces": netd.owned_interfaces().names(),
                "radio": radio.status(),
            })),
            _ => Err(anyhow::anyhow!("unsupported lmesh-wifi method {method:?}")),
        }
    })();
    match result {
        Ok(data) => json!({"success": true, "data": data}),
        Err(error) => json!({"success": false, "error": error.to_string()}),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let netd = Arc::new(WifiNetd::from_environment());
    let radio = Arc::new(RadioService::from_environment_without_uart());
    let (trace, _guard) = mesh::local_trace::init("lmesh-wifi");
    mesh::local_trace::serve("lmesh-wifi", trace.clone());

    // lmesh-wifi is the stable recovery/AP service.  Its first owned
    // interface is the AP by default; lmesh itself only starts AP operation
    // when explicitly requested through its API.
    if let Some(iface) = lmesh_wifi::default_interface() {
        netd.authorize(Operation::Ap, &iface)?;
        let result = radio.wifi_ap_start_open(Some(iface.clone()), None);
        log_ap_start(&result, &iface);
        configure_ap_address(&radio, &iface);
        let rawnan = radio.wifi_raw_listen(
            Some(iface.clone()),
            None,
            Some(6),
            Some(86_400),
            Some("monitor".to_owned()),
        );
        log_rawnan_start(&rawnan, &iface);
    } else {
        tracing::warn!("LMESH_INTERFACES is empty; Wi-Fi AP was not started");
    }

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
                    let ack = json!({
                        "success": true,
                        "data": {"subscribed": true, "service": "lmesh-wifi", "targets": config.targets.clone()}
                    });
                    if writer.write_all(ack.to_string().as_bytes()).await.is_err()
                        || writer.write_all(b"\n").await.is_err()
                        || writer.flush().await.is_err()
                    {
                        break;
                    }
                    let _ = mesh::local_trace::stream_logs_filtered(
                        &trace,
                        &mesh::jsonl::ProtocolFormat::FlatJson { id: None },
                        &mut writer,
                        "lmesh-wifi",
                        &config,
                    )
                    .await;
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
