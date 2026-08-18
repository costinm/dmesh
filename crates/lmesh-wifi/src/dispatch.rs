//! JSONL request dispatch shared by the lmesh-wifi launcher and embedders.

use crate::{Operation, RadioService, WifiNetd};
use anyhow::Result;
use serde_json::{Value, json};

fn string_arg(request: &Value, name: &str) -> Option<String> {
    request.get(name).and_then(Value::as_str).map(str::to_owned)
}

/// The text mesh CLI transmits `key=value` arguments as strings, while JSON
/// clients use numbers. Keep control requests equivalent across both forms.
fn u8_arg(request: &Value, name: &str) -> Option<u8> {
    request.get(name).and_then(|value| match value {
        Value::Number(value) => value.as_u64().and_then(|value| u8::try_from(value).ok()),
        Value::String(value) => value.parse::<u8>().ok(),
        _ => None,
    })
}

fn u64_arg(request: &Value, name: &str) -> Option<u64> {
    request.get(name).and_then(|value| match value {
        Value::Number(value) => value.as_u64(),
        Value::String(value) => value.parse::<u64>().ok(),
        _ => None,
    })
}

/// The mesh CLI deliberately parses bare numeric values as JSON numbers.
/// Rate profiles use human-readable values ("12", "24", "auto"), so accept
/// those numeric CLI forms instead of silently falling back to `auto`.
fn rate_profile_arg(request: &Value) -> Option<String> {
    request.get("profile").and_then(|value| match value {
        Value::String(value) => Some(value.clone()),
        Value::Number(value) => value.as_u64().map(|value| value.to_string()),
        _ => None,
    })
}

fn iface_arg(request: &Value) -> Option<String> {
    string_arg(request, "iface").or_else(crate::default_interface)
}

fn authorize(netd: &WifiNetd, request: &Value, operation: Operation) -> Result<String> {
    let iface = iface_arg(request)
        .ok_or_else(|| anyhow::anyhow!("LMESH_INTERFACES must name an owned Wi-Fi interface"))?;
    netd.authorize(operation, &iface)?;
    Ok(iface)
}

pub fn subscription_config(request: &Value) -> Option<mesh::local_trace::TraceConfig> {
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

pub fn handle_request(netd: &WifiNetd, radio: &RadioService, request: Value) -> Value {
    let method = request.get("method").and_then(Value::as_str).unwrap_or("");
    let result = (|| -> Result<Value> {
        match method {
            "wifi.ap.start_open" => {
                let iface = authorize(netd, &request, Operation::Ap)?;
                let channel = u8_arg(&request, "channel");
                Ok(radio.wifi_ap_start_open_on_channel(
                    Some(iface),
                    string_arg(&request, "ssid"),
                    channel,
                ))
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
                    request
                        .get("prefix")
                        .and_then(Value::as_u64)
                        .map(|value| value.min(32) as u8),
                ))
            }
            "wifi.ap.stations" => {
                let iface = authorize(netd, &request, Operation::Ap)?;
                Ok(radio.wifi_ap_stations(Some(iface)))
            }
            "wifi.udp6.ndp.capture" => {
                let iface = authorize(netd, &request, Operation::Ap)?;
                Ok(crate::ndp::capture_neighbor_advertisements(
                    &iface,
                    u64_arg(&request, "wait_ms").unwrap_or(2_000),
                ))
            }
            "wifi.udp6.ndp.monitor" => {
                let iface = authorize(netd, &request, Operation::Ap)?;
                Ok(crate::ndp::capture_monitor_neighbor_advertisements(
                    &iface,
                    u64_arg(&request, "wait_ms").unwrap_or(2_000),
                ))
            }
            "wifi.udp6.ndp.reset" => {
                let iface = authorize(netd, &request, Operation::Ap)?;
                let address = string_arg(&request, "address")
                    .ok_or_else(|| anyhow::anyhow!("address is required"))?;
                Ok(crate::ndp::clear_neighbor(&iface, &address))
            }
            "wifi.udp6.neigh.set" => {
                let iface = authorize(netd, &request, Operation::Ap)?;
                let address = string_arg(&request, "address")
                    .ok_or_else(|| anyhow::anyhow!("address is required"))?;
                let mac = string_arg(&request, "mac")
                    .ok_or_else(|| anyhow::anyhow!("mac is required"))?;
                Ok(crate::ndp::set_static_neighbor(&iface, &address, &mac))
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
            "wifi.ap.station.profile" => {
                let _iface = authorize(netd, &request, Operation::Ap)?;
                let mac = string_arg(&request, "mac")
                    .ok_or_else(|| anyhow::anyhow!("mac is required"))?;
                let ht = request
                    .get("ht")
                    .and_then(Value::as_bool)
                    .ok_or_else(|| anyhow::anyhow!("ht is required"))?;
                Ok(radio.wifi_ap_station_profile(mac, ht))
            }
            "wifi.scan" => {
                let iface = authorize(netd, &request, Operation::Sta)?;
                Ok(radio.wifi_scan(Some(iface), string_arg(&request, "ssid")))
            }
            "wifi.sta.status" => {
                let iface = authorize(netd, &request, Operation::Sta)?;
                Ok(radio.wifi_sta_status(Some(iface)))
            }
            "wifi.rawnan.listen" => {
                let iface = authorize(netd, &request, Operation::Nan)?;
                Ok(radio.wifi_raw_listen(
                    Some(iface),
                    request
                        .get("channel")
                        .and_then(Value::as_u64)
                        .map(|v| v.min(13) as u8),
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
                    request
                        .get("channel")
                        .and_then(Value::as_u64)
                        .map(|v| v.min(13) as u8),
                    string_arg(&request, "destination"),
                    string_arg(&request, "bssid"),
                    string_arg(&request, "payload").unwrap_or_else(|| "ping".to_owned()),
                    request.get("wait_ms").and_then(Value::as_u64),
                ))
            }
            "wifi.raw.iperf" => {
                let iface = authorize(netd, &request, Operation::Nan)?;
                let destination = string_arg(&request, "destination")
                    .ok_or_else(|| anyhow::anyhow!("destination is required"))?;
                Ok(radio.raw_espnow_iperf(
                    Some(iface),
                    request
                        .get("channel")
                        .and_then(Value::as_u64)
                        .map(|v| v.min(13) as u8),
                    destination,
                    u64_arg(&request, "bytes").unwrap_or(8 * 1024),
                    u64_arg(&request, "timeout_ms"),
                ))
            }
            "wifi.rate.profile" => {
                let iface = authorize(netd, &request, Operation::Nan)?;
                Ok(radio.wifi_rate_profile(
                    Some(iface),
                    rate_profile_arg(&request).unwrap_or_else(|| "auto".to_owned()),
                    request
                        .get("disable_80211b")
                        .and_then(Value::as_bool)
                        .unwrap_or(false),
                ))
            }
            "wifi.power_save" => {
                let iface = authorize(netd, &request, Operation::Ap)?;
                let enabled = request
                    .get("enabled")
                    .and_then(Value::as_bool)
                    .ok_or_else(|| anyhow::anyhow!("enabled is required"))?;
                Ok(radio.wifi_power_save(Some(iface), enabled))
            }
            "wifi.raw.send" => {
                let iface = authorize(netd, &request, Operation::Nan)?;
                if let Some(frame_hex) = string_arg(&request, "frame_hex") {
                    return Ok(radio.wifi_raw_send_frame(
                        Some(iface),
                        request
                            .get("channel")
                            .and_then(Value::as_u64)
                            .map(|v| v.min(13) as u8),
                        string_arg(&request, "tx_variant"),
                        frame_hex,
                    ));
                }
                Ok(radio.wifi_raw_send(
                    Some(iface),
                    request
                        .get("channel")
                        .and_then(Value::as_u64)
                        .map(|v| v.min(13) as u8),
                    request.get("listen_sec").and_then(Value::as_u64),
                    string_arg(&request, "destination"),
                    string_arg(&request, "source"),
                    string_arg(&request, "tx_variant"),
                    request
                        .get("tx_duration_ms")
                        .and_then(Value::as_u64)
                        .map(|v| v as u32),
                    string_arg(&request, "bssid"),
                    string_arg(&request, "llc"),
                    string_arg(&request, "payload").unwrap_or_default(),
                    request
                        .get("tx_rate_mbps")
                        .and_then(Value::as_u64)
                        .map(|v| v.min(54) as u8),
                ))
            }
            "wifi.object.udp.start" => {
                let _iface = authorize(netd, &request, Operation::Sta)?;
                Ok(radio.object_udp_start(
                    string_arg(&request, "bind"),
                    request
                        .get("port")
                        .and_then(Value::as_u64)
                        .map(|value| value.min(u16::MAX as u64) as u16),
                    string_arg(&request, "root"),
                ))
            }
            "wifi.object.udp.status" => Ok(radio.object_udp_status()),
            "transport.client.iperf" => {
                let _iface = authorize(netd, &request, Operation::Sta)?;
                let serial = string_arg(&request, "serial")
                    .ok_or_else(|| anyhow::anyhow!("serial is required"))?;
                let bootstrap = string_arg(&request, "bootstrap")
                    .ok_or_else(|| anyhow::anyhow!("bootstrap is required"))?;
                let backend = string_arg(&request, "backend")
                    .ok_or_else(|| anyhow::anyhow!("backend is required"))?;
                let bytes = request
                    .get("bytes")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| anyhow::anyhow!("bytes is required"))?
                    .min(u32::MAX as u64) as u32;
                Ok(radio.transport_client_iperf(
                    serial,
                    bootstrap,
                    backend,
                    bytes,
                    string_arg(&request, "bearer"),
                ))
            }
            "transport.client.service" => {
                let _iface = authorize(netd, &request, Operation::Sta)?;
                let target = string_arg(&request, "target")
                    .ok_or_else(|| anyhow::anyhow!("target is required (udp://HOST:PORT)"))?;
                Ok(radio.transport_client_service(
                    target,
                    string_arg(&request, "service").unwrap_or_else(|| "status".to_owned()),
                    string_arg(&request, "body_hex"),
                    request
                        .get("log_records")
                        .and_then(Value::as_u64)
                        .map(|value| value.min(u8::MAX as u64) as u8),
                ))
            }
            "messages.history" => Ok(radio.history(
                string_arg(&request, "keys"),
                request
                    .get("limit")
                    .and_then(Value::as_u64)
                    .map(|v| v as usize),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_profile_accepts_cli_numeric_values() {
        assert_eq!(
            rate_profile_arg(&json!({"profile": 24})).as_deref(),
            Some("24")
        );
        assert_eq!(
            rate_profile_arg(&json!({"profile": "auto"})).as_deref(),
            Some("auto")
        );
        assert_eq!(rate_profile_arg(&json!({"profile": true})), None);
    }

    #[test]
    fn channel_accepts_cli_and_json_numbers() {
        assert_eq!(u8_arg(&json!({"channel": "11"}), "channel"), Some(11));
        assert_eq!(u8_arg(&json!({"channel": 1}), "channel"), Some(1));
        assert_eq!(u8_arg(&json!({"channel": true}), "channel"), None);
    }
}
