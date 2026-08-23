//! JSONL request dispatch shared by the lmesh-wifi launcher and embedders.

use crate::{Operation, RadioService, WifiNetd, reviewed::ReviewedWifiRequest};
use anyhow::Result;
use serde_json::{Value, json};

/// Resolve the live discovery inventory into the portable pair-probe
/// descriptors.  This is a planning operation only: `wlan0` is read for
/// inventory evidence and is never brought down, retuned, or associated by a
/// probe request.  The executor receives the returned rows and configures
/// only the two selected endpoints.
pub fn discovery_pair_plan(
    radio: &RadioService,
    iface: &str,
    source_id: &str,
    target_id: &str,
    short_bytes: u32,
    long_bytes: u32,
) -> Result<Value> {
    if source_id == target_id {
        anyhow::bail!("source_id and target_id must identify different devices");
    }
    let inventory = radio.rawnan_status(Some(iface.to_owned()));
    let devices = inventory
        .get("discovered_devices")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow::anyhow!("raw-NAN inventory is unavailable"))?;
    // Return the complete portable fleet view with the plan.  Callers use it
    // to choose two ESPs, two Androids, or two Hosts without hard-coding lab
    // names.  This is inventory only: a Host may be selected as an endpoint,
    // but the executor still must not change the control-plane host's mode.
    let discovered = devices
        .iter()
        .filter_map(|device| {
            let id = device.get("id").and_then(Value::as_str)?;
            let announce = device.get("announce")?;
            let class = announce.get("device_class").and_then(Value::as_u64)?;
            let capabilities = announce.get("probe_capabilities").and_then(Value::as_u64)?;
            let kind = match class as u8 {
                dmesh_server::announce::DEVICE_CLASS_ESP => "esp",
                dmesh_server::announce::DEVICE_CLASS_HOST => "host",
                dmesh_server::announce::DEVICE_CLASS_ANDROID => "android",
                _ => return None,
            };
            Some(json!({
                "id": id,
                "kind": kind,
                "capabilities": capabilities,
            }))
        })
        .collect::<Vec<_>>();
    let descriptor = |id: &str| -> Result<dmesh_server::probe::ProbeDeviceDescriptor> {
        let device = devices
            .iter()
            .find(|device| device.get("id").and_then(Value::as_str) == Some(id))
            .ok_or_else(|| anyhow::anyhow!("discovery inventory has no device {id:?}"))?;
        let announce = device
            .get("announce")
            .ok_or_else(|| anyhow::anyhow!("discovered device {id:?} has no announce"))?;
        let class = announce
            .get("device_class")
            .and_then(Value::as_u64)
            .and_then(|value| u8::try_from(value).ok())
            .unwrap_or(dmesh_server::announce::DEVICE_CLASS_UNKNOWN);
        let kind = match class {
            dmesh_server::announce::DEVICE_CLASS_ESP => {
                dmesh_server::probe::ProbeEndpointKind::Esp
            }
            dmesh_server::announce::DEVICE_CLASS_HOST => {
                dmesh_server::probe::ProbeEndpointKind::Host
            }
            dmesh_server::announce::DEVICE_CLASS_ANDROID => {
                dmesh_server::probe::ProbeEndpointKind::Android
            }
            _ => anyhow::bail!("discovered device {id:?} has no supported device_class"),
        };
        let capabilities = announce
            .get("probe_capabilities")
            .and_then(Value::as_u64)
            .and_then(|value| u16::try_from(value).ok())
            .filter(|value| *value != 0)
            .ok_or_else(|| anyhow::anyhow!("discovered device {id:?} has no probe capabilities"))?;
        let bytes = decode_hex(id, "device id")?;
        if bytes.len() < 6 {
            anyhow::bail!("discovered device {id:?} cannot supply a six-byte radio identity");
        }
        let mut node = [0; 6];
        node.copy_from_slice(&bytes[..6]);
        Ok(dmesh_server::probe::ProbeDeviceDescriptor {
            endpoint: dmesh_server::probe::ProbeEndpoint {
                kind,
                node,
                mode: dmesh_server::probe::ProbeMode::NAN_NOW,
                bssid: None,
            },
            capabilities,
        })
    };
    let source = descriptor(source_id)?;
    let target = descriptor(target_id)?;
    let rows = dmesh_server::probe::full_pair_probe_requests(
        0x4D_50_2000,
        source,
        target,
        short_bytes,
        long_bytes,
    );
    if rows.is_empty() {
        anyhow::bail!("selected devices share no NAN-capable pair-probe row");
    }
    Ok(json!({
        "ok": true,
        "control_plane_iface": iface,
        "control_plane_mode_changed": false,
        "discovered": discovered,
        "source": source,
        "target": target,
        "rows": rows,
    }))
}

fn string_arg(request: &Value, name: &str) -> Option<String> {
    request.get(name).and_then(Value::as_str).map(str::to_owned)
}

/// Decode a bounded tagged-CBOR record supplied by a local sibling service.
/// This is intentionally kept at the control boundary: the registry receives
/// the same semantic `Announce` type as NAN, never another process's buffer.
fn decode_announce_hex(value: &str) -> Result<dmesh_server::announce::Announce> {
    let wire = decode_hex(value, "announce_hex")?;
    dmesh_server::announce::decode_announce(&wire)
        .ok_or_else(|| anyhow::anyhow!("announce_hex is not a common tagged-CBOR announce"))
}

fn decode_hex(value: &str, field: &str) -> Result<Vec<u8>> {
    let value = value.trim().strip_prefix("hex:").unwrap_or(value.trim());
    if value.is_empty() || value.len() % 2 != 0 {
        anyhow::bail!("{field} must contain complete hexadecimal bytes");
    }
    (0..value.len())
        .step_by(2)
        .map(|offset| u8::from_str_radix(&value[offset..offset + 2], 16).map_err(Into::into))
        .collect()
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

/// The text mesh CLI transmits `key=value` arguments as strings, while JSON
/// clients use booleans. Keep AP bandwidth selection equivalent across both.
fn bool_arg(request: &Value, name: &str) -> Option<bool> {
    request.get(name).and_then(|value| match value {
        Value::Bool(value) => Some(*value),
        Value::String(value) => match value.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => Some(true),
            "0" | "false" | "no" | "off" => Some(false),
            _ => None,
        },
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

fn i16_arg(request: &Value, name: &str) -> Option<i16> {
    request.get(name).and_then(|value| match value {
        Value::Number(value) => value.as_i64().and_then(|value| i16::try_from(value).ok()),
        Value::String(value) => value.parse::<i16>().ok(),
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

fn authorize_iface(netd: &WifiNetd, iface: Option<&str>, operation: Operation) -> Result<String> {
    let iface = iface
        .map(str::to_owned)
        .or_else(crate::default_interface)
        .ok_or_else(|| anyhow::anyhow!("LMESH_INTERFACES must name an owned Wi-Fi interface"))?;
    netd.authorize(operation, &iface)?;
    Ok(iface)
}

/// Dispatch the reviewed numeric-CBOR Wi-Fi request set without translating it
/// into the old flat JSON handler request. Keep state-changing and unreviewed
/// methods on the JSON-RPC compatibility path until they have a documented
/// typed request and stable catalog ID.
pub fn handle_reviewed_request(
    netd: &WifiNetd,
    radio: &RadioService,
    request: ReviewedWifiRequest,
) -> Value {
    let result = (|| -> Result<Value> {
        match request {
            ReviewedWifiRequest::ApStatus(request) => {
                let iface = authorize_iface(netd, request.iface.as_deref(), Operation::Ap)?;
                Ok(radio.wifi_ap_status(Some(iface)))
            }
            ReviewedWifiRequest::StaStatus(request) => {
                let iface = authorize_iface(netd, request.iface.as_deref(), Operation::Sta)?;
                Ok(radio.wifi_sta_status(Some(iface)))
            }
            ReviewedWifiRequest::RawNanStatus(request) => {
                let iface = authorize_iface(netd, request.iface.as_deref(), Operation::Nan)?;
                Ok(radio.rawnan_status(Some(iface)))
            }
            ReviewedWifiRequest::ProbePlan(request) => {
                let iface = authorize_iface(netd, request.iface.as_deref(), Operation::Nan)?;
                discovery_pair_plan(
                    radio,
                    &iface,
                    &request.source_id,
                    &request.target_id,
                    request.short_bytes.unwrap_or(4 * 1024),
                    request.long_bytes.unwrap_or(64 * 1024),
                )
            }
            ReviewedWifiRequest::InterfaceStatus(request) => {
                let iface = authorize_iface(netd, request.iface.as_deref(), Operation::Nan)?;
                Ok(radio.wifi_interface_status(Some(iface)))
            }
            ReviewedWifiRequest::ApStations(request) => {
                let iface = authorize_iface(netd, request.iface.as_deref(), Operation::Ap)?;
                Ok(radio.wifi_ap_stations(Some(iface)))
            }
            ReviewedWifiRequest::RawMetrics(request) => {
                let iface = authorize_iface(netd, request.iface.as_deref(), Operation::Nan)?;
                Ok(radio.wifi_raw_metrics(Some(iface)))
            }
            ReviewedWifiRequest::RawStop(request) => {
                let iface = authorize_iface(netd, request.iface.as_deref(), Operation::Nan)?;
                Ok(radio.wifi_raw_stop(Some(iface)))
            }
            ReviewedWifiRequest::RawListen(request) => {
                let iface = authorize_iface(netd, request.iface.as_deref(), Operation::Nan)?;
                Ok(radio.wifi_raw_listen(
                    Some(iface),
                    request.channel,
                    request.listen_sec,
                    request.rx_variant.or(Some("monitor".to_owned())),
                ))
            }
            ReviewedWifiRequest::RawCheck(request) => {
                let iface = authorize_iface(netd, request.iface.as_deref(), Operation::Nan)?;
                Ok(radio.raw_espnow_check(
                    Some(iface),
                    request.channel,
                    request.destination,
                    request.nonce.unwrap_or(0),
                    request.timeout_ms,
                    request.tx_rate_mbps.map(u64::from),
                    request.tx_variant,
                    request.rx_variant,
                    request.expected_peer,
                ))
            }
            ReviewedWifiRequest::RawIperf(request) => {
                let iface = authorize_iface(netd, request.iface.as_deref(), Operation::Nan)?;
                Ok(radio.raw_espnow_iperf(
                    Some(iface),
                    request.channel,
                    request.destination,
                    request.bytes.unwrap_or(8 * 1024),
                    request.packet_size.map(u64::from),
                    request.timeout_ms,
                    request.tx_rate_mbps.map(u64::from),
                    request.tx_variant,
                    request.rx_variant,
                    request.expected_peer,
                ))
            }
            ReviewedWifiRequest::RawSend(request) => {
                let iface = authorize_iface(netd, request.iface.as_deref(), Operation::Nan)?;
                let frame_hex = request.frame_hex.ok_or_else(|| {
                    anyhow::anyhow!("frame_hex is required for reviewed wifi.raw.send")
                })?;
                Ok(radio.wifi_raw_send_frame(
                    Some(iface),
                    request.channel,
                    request.tx_variant,
                    frame_hex,
                    request.tx_rate_mbps,
                ))
            }
            ReviewedWifiRequest::RawNanPing(request) => {
                let iface = authorize_iface(netd, request.iface.as_deref(), Operation::Nan)?;
                Ok(radio.rawnan_ping(
                    Some(iface),
                    request.channel,
                    request.destination,
                    request.bssid,
                    request.payload.unwrap_or_else(|| "ping".to_owned()),
                    request.wait_ms,
                ))
            }
            ReviewedWifiRequest::RawNanListen(request) => {
                let iface = authorize_iface(netd, request.iface.as_deref(), Operation::Nan)?;
                Ok(radio.wifi_raw_listen(
                    Some(iface),
                    request.channel,
                    request.listen_sec,
                    Some("monitor".to_owned()),
                ))
            }
        }
    })();
    match result {
        Ok(data) => json!({"success": true, "data": data}),
        Err(error) => json!({"success": false, "error": error.to_string()}),
    }
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

/// Convert the standard JSON-RPC gateway envelope into the long-standing flat
/// handler shape. Tagged CBOR never reaches this adapter; it is only the
/// schema-less compatibility path used when no reviewed numeric catalog exists.
pub fn normalize_json_rpc_request(request: Value) -> Value {
    if request.get("jsonrpc").is_none() {
        return request;
    }
    let Some(method) = request.get("method").cloned() else {
        return request;
    };
    let mut normalized = request
        .get("params")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    normalized.insert("method".to_owned(), method);
    if let Some(id) = request.get("id") {
        normalized.insert("id".to_owned(), id.clone());
    }
    Value::Object(normalized)
}

pub fn handle_request(netd: &WifiNetd, radio: &RadioService, request: Value) -> Value {
    let method = request.get("method").and_then(Value::as_str).unwrap_or("");
    let result = (|| -> Result<Value> {
        match method {
            "wifi.ap.start_open" => {
                let iface = authorize(netd, &request, Operation::Ap)?;
                let channel = u8_arg(&request, "channel");
                Ok(radio.wifi_ap_start_open_on_channel_with_interval(
                    Some(iface),
                    string_arg(&request, "ssid"),
                    channel,
                    bool_arg(&request, "ht40"),
                    request
                        .get("beacon_interval_tu")
                        .and_then(Value::as_u64)
                        .unwrap_or(100)
                        .min(u16::MAX as u64) as u16,
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
                Ok(radio.wifi_scan(
                    Some(iface),
                    string_arg(&request, "ssid"),
                    u8_arg(&request, "channel"),
                    bool_arg(&request, "passive").unwrap_or(false),
                ))
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
            "wifi.raw.listen" => {
                let iface = authorize(netd, &request, Operation::Nan)?;
                Ok(radio.wifi_raw_listen(
                    Some(iface),
                    request
                        .get("channel")
                        .and_then(Value::as_u64)
                        .map(|v| v.min(13) as u8),
                    request.get("listen_sec").and_then(Value::as_u64),
                    string_arg(&request, "rx_variant"),
                ))
            }
            "wifi.rawnan.status" => {
                let iface = authorize(netd, &request, Operation::Nan)?;
                Ok(radio.rawnan_status(Some(iface)))
            }
            "wifi.rawnan.active_publish" => {
                let _iface = authorize(netd, &request, Operation::Nan)?;
                let enabled = bool_arg(&request, "enabled")
                    .ok_or_else(|| anyhow::anyhow!("enabled is required"))?;
                let service_info = match string_arg(&request, "service_info_hex") {
                    Some(value) => decode_hex(&value, "service_info_hex")?,
                    None if !enabled => Vec::new(),
                    None => anyhow::bail!("service_info_hex is required when enabled"),
                };
                radio.rawnan_active_publish_configure(enabled, &service_info)
            }
            // A sibling host service forwards only a locally validated
            // announce here. This operation cannot retune or otherwise
            // mutate Wi-Fi; it is the control-plane ingress for a semantic
            // cross-bearer inventory update.
            "wifi.discovery.observe" => {
                let source = string_arg(&request, "source")
                    .ok_or_else(|| anyhow::anyhow!("source is required"))?;
                let peer = string_arg(&request, "peer")
                    .ok_or_else(|| anyhow::anyhow!("peer is required"))?;
                let announce_hex = string_arg(&request, "announce_hex")
                    .ok_or_else(|| anyhow::anyhow!("announce_hex is required"))?;
                let announce = decode_announce_hex(&announce_hex)?;
                let device_id = announce.device_id().to_vec();
                let accepted = radio.observe_discovered_announce(
                    &source,
                    peer,
                    string_arg(&request, "bssid"),
                    announce,
                );
                Ok(json!({"ok": accepted, "device_id": hex_bytes(&device_id)}))
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
            "wifi.raw.metrics" => {
                let iface = authorize(netd, &request, Operation::Nan)?;
                Ok(radio.wifi_raw_metrics(Some(iface)))
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
            "wifi.raw.check" => {
                let iface = authorize(netd, &request, Operation::Nan)?;
                let destination = string_arg(&request, "destination")
                    .ok_or_else(|| anyhow::anyhow!("destination is required"))?;
                Ok(radio.raw_espnow_check(
                    Some(iface),
                    request
                        .get("channel")
                        .and_then(Value::as_u64)
                        .map(|v| v.min(13) as u8),
                    destination,
                    // The client CID is generated by the shared raw-check
                    // client. A caller-provided nonce makes repeated probes
                    // correlate cleanly; zero remains a valid default.
                    u64_arg(&request, "nonce").unwrap_or(0),
                    u64_arg(&request, "timeout_ms"),
                    request.get("tx_rate_mbps").and_then(Value::as_u64),
                    string_arg(&request, "tx_variant"),
                    string_arg(&request, "rx_variant"),
                    string_arg(&request, "expected_peer"),
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
                    request.get("packet_size").and_then(Value::as_u64),
                    u64_arg(&request, "timeout_ms"),
                    request.get("tx_rate_mbps").and_then(Value::as_u64),
                    string_arg(&request, "tx_variant"),
                    string_arg(&request, "rx_variant"),
                    string_arg(&request, "expected_peer"),
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
            "wifi.tx_power" => {
                let iface = authorize(netd, &request, Operation::Ap)?;
                Ok(radio.wifi_tx_power(Some(iface), i16_arg(&request, "dbm")))
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
                        request
                            .get("tx_rate_mbps")
                            .and_then(Value::as_u64)
                            .map(|v| v.min(54) as u8),
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
            "messages.history" => Ok(radio.history(
                string_arg(&request, "keys"),
                request
                    .get("limit")
                    .and_then(Value::as_u64)
                    .map(|v| v as usize),
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

fn hex_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        text.push(HEX[(byte >> 4) as usize] as char);
        text.push(HEX[(byte & 0x0f) as usize] as char);
    }
    text
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

    #[test]
    fn json_rpc_gateway_flattens_params_for_existing_handlers() {
        assert_eq!(
            normalize_json_rpc_request(json!({
                "jsonrpc": "2.0",
                "id": 7,
                "method": "wifi.ap.stop",
                "params": {"iface": "wlan0"}
            })),
            json!({"id": 7, "method": "wifi.ap.stop", "iface": "wlan0"})
        );
    }

    #[test]
    fn local_observe_ingress_accepts_the_common_announce_wire() {
        let announce = dmesh_server::announce::Announce::discovery([0x4D; 16], 16, 7, 0, 3);
        let mut wire = [0_u8; 96];
        let used = dmesh_server::announce::encode(announce, &mut wire).unwrap();
        assert_eq!(
            decode_announce_hex(&hex_bytes(&wire[..used])).unwrap(),
            announce,
        );
        assert!(decode_announce_hex("not hex").is_err());
    }

    #[test]
    fn local_observe_ingress_updates_the_shared_device_inventory() {
        let log = tempfile::NamedTempFile::new().unwrap();
        let radio = RadioService::from_environment_with_discovery_log(log.path());
        let announce = dmesh_server::announce::Announce::discovery([0x54; 16], 16, 8, 1, 5);
        let mut wire = [0_u8; 96];
        let used = dmesh_server::announce::encode(announce, &mut wire).unwrap();
        let response = handle_request(
            &WifiNetd::from_environment(),
            &radio,
            json!({
                "method": "wifi.discovery.observe",
                "source": "udp_multicast",
                "peer": "[fe80::54]:5227",
                "announce_hex": hex_bytes(&wire[..used]),
            }),
        );
        assert_eq!(response["success"], true);
        let status = radio.rawnan_status(None);
        assert_eq!(
            status["discovered_devices"][0]["id"],
            "54545454545454545454545454545454"
        );
        assert_eq!(status["discovered_devices"][0]["source"], "udp_multicast");
        assert_eq!(status["discovered_devices"][0]["nan"]["observed"], false);
        assert_eq!(status["discovered_devices"][0]["active_transport"]["state"], "sta");
    }

    #[test]
    fn discovery_inventory_retains_nan_and_udp6_observations_for_one_device() {
        let log = tempfile::NamedTempFile::new().unwrap();
        let radio = RadioService::from_environment_with_discovery_log(log.path());
        let mut announce = dmesh_server::announce::Announce::discovery([0x55; 16], 16, 8, 0, 5);
        announce.set_probe_descriptor(
            dmesh_server::announce::DEVICE_CLASS_ANDROID,
            dmesh_server::probe::PROBE_CAP_NAN | dmesh_server::probe::PROBE_CAP_UDP6,
        );
        assert!(radio.observe_discovered_announce(
            "udp_multicast",
            "[fe80::55]:5227".to_owned(),
            None,
            announce,
        ));
        assert!(radio.observe_discovered_announce(
            "nan",
            "02:00:00:00:00:55".to_owned(),
            Some("50:6f:9a:01:54:6c".to_owned()),
            announce,
        ));
        let status = radio.rawnan_status(None);
        let device = &status["discovered_devices"][0];
        assert_eq!(device["nan"]["observed"], true);
        assert!(device["observations"].get("nan").is_some());
        assert!(device["observations"].get("udp_multicast").is_some());
        assert_eq!(device["active_transport"]["state"], "nan_now");
    }

    #[test]
    fn probe_plan_uses_live_inventory_without_touching_control_plane_state() {
        let log = tempfile::NamedTempFile::new().unwrap();
        let radio = RadioService::from_environment_with_discovery_log(log.path());
        for (id, peer) in [([0x11; 6], "esp-a"), ([0x22; 6], "esp-b")] {
            let mut full_id = [0; 16];
            full_id[..6].copy_from_slice(&id);
            let mut announce = dmesh_server::announce::Announce::discovery(full_id, 6, 1, 0, 0);
            announce.set_probe_descriptor(
                dmesh_server::announce::DEVICE_CLASS_ESP,
                dmesh_server::probe::PROBE_CAP_NAN
                    | dmesh_server::probe::PROBE_CAP_NOW
                    | dmesh_server::probe::PROBE_CAP_STA
                    | dmesh_server::probe::PROBE_CAP_AP
                    | dmesh_server::probe::PROBE_CAP_UDP6,
            );
            assert!(radio.observe_discovered_announce("nan", peer.to_owned(), None, announce));
        }
        let plan = discovery_pair_plan(&radio, "wlan0", "111111111111", "222222222222", 100, 1000)
            .unwrap();
        assert_eq!(plan["control_plane_iface"], "wlan0");
        assert_eq!(plan["control_plane_mode_changed"], false);
        assert_eq!(plan["rows"].as_array().unwrap().len(), 4);
        assert!(plan["rows"]
            .as_array()
            .unwrap()
            .iter()
            .all(|row| row["request"]["test_nan"] == true));
    }
}
