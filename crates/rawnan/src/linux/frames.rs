//! Frame parsing/building and the raw action transmitter, moved from `radio.rs`.
use super::*;
use crate::{Action as RawNanAction, NanState, RxFrame as RawNanRxFrame};

pub fn parse_dmesh_vendor_action(frame: &[u8], iface: &str) -> Option<Value> {
    parse_dmesh_wifi_frame(frame, iface, "linux_nl80211")
}

pub fn parse_dmesh_wifi_frame(frame: &[u8], iface: &str, backend: &str) -> Option<Value> {
    // The raw NOW bearer is a standard 802.11 public/vendor action whose
    // payload is owned by `rawnan::espnow`. Parse it before the legacy DMesh
    // vendor-marker path so host monitor events expose the exact complete
    // QUIC-lite datagram that firmware receives.
    // The older DMesh marker has a deliberate fixed header.  Check it first:
    // its bytes can otherwise be interpreted as a permissive ESP-NOW IE by
    // the generic parser, losing the marker and destination metadata.
    let has_legacy_dmesh_marker = frame
        .get(IEEE80211_BODY..)
        .and_then(parse_dmesh_vendor_action_header)
        .is_some();
    if !has_legacy_dmesh_marker
        && let Some((source, payload)) = crate::espnow::parse_action_frame(frame)
    {
        let destination = mac_at(frame, IEEE80211_ADDR1)?;
        let bssid = mac_at(frame, IEEE80211_ADDR3)?;
        return Some(json!({
            "protocol": "dmesh_wifi_raw",
            "layout": "espnow_action",
            "backend": backend,
            "encapsulation": "espnow_v2_vendor_ie",
            "iface": iface,
            "frame_type": frame_type(frame),
            "frame_subtype": frame_subtype(frame),
            "source": colon_mac(&source),
            "destination": colon_mac(&destination),
            "bssid": colon_mac(&bssid),
            "payload_len": payload.len(),
            "payload": hex_bytes(payload),
        }));
    }
    if frame.len() <= IEEE80211_BODY + DMESH_LEGACY_VENDOR_ACTION.len() {
        return None;
    }
    let mut body = &frame[IEEE80211_BODY..];
    let encapsulation = if body.starts_with(&IEEE80211_LLC_SNAP_IPV6) {
        return parse_nan_ipv6_udp_frame(frame, iface, backend);
    } else if body.starts_with(&IEEE80211_LLC_SNAP_DMESH) {
        body = &body[IEEE80211_LLC_SNAP_LEN..];
        "llc_snap"
    } else if body.len() >= IEEE80211_LLC_SNAP_LEN && body[..3] == [0xaa, 0xaa, 0x03] {
        // Experimental NAN data uses an LLC/SNAP prefix. Do not treat every
        // unknown action body as LLC: the ESP-NOW-compatible vendor action
        // header starts with 7f and must continue to the marker parser below.
        let llc = &body[..IEEE80211_LLC_SNAP_LEN];
        body = &body[IEEE80211_LLC_SNAP_LEN..];
        let source = mac_at(frame, IEEE80211_ADDR2)?;
        let destination = mac_at(frame, IEEE80211_ADDR1)?;
        let bssid = mac_at(frame, IEEE80211_ADDR3)?;
        return Some(json!({
            "protocol": "dmesh_wifi_raw",
            "layout": "nan_raw_data",
            "backend": backend,
            "encapsulation": "llc_experimental",
            "iface": iface,
            "frame_type": frame_type(frame),
            "frame_subtype": frame_subtype(frame),
            "source": colon_mac(&source),
            "destination": colon_mac(&destination),
            "bssid": colon_mac(&bssid),
            "llc": hex_bytes(llc),
            "payload_len": body.len(),
            "payload": hex_bytes(body),
            "payload_text": String::from_utf8_lossy(body).trim(),
        }));
    } else {
        "vendor_action"
    };
    let header = parse_dmesh_vendor_action_header(body)?;
    let payload = &body[header.header_len..];
    let source = mac_at(frame, IEEE80211_ADDR2)?;
    let destination = mac_at(frame, IEEE80211_ADDR1)?;
    let bssid = mac_at(frame, IEEE80211_ADDR3)?;
    let layout = if frame_type(frame) == 2 {
        "multicast_data"
    } else {
        "vendor_action"
    };
    Some(json!({
        "protocol": "dmesh_wifi_raw",
        "layout": layout,
        "backend": backend,
        "encapsulation": encapsulation,
        "iface": iface,
        "frame_type": frame_type(frame),
        "frame_subtype": frame_subtype(frame),
        "source": colon_mac(&source),
        "destination": colon_mac(&destination),
        "bssid": colon_mac(&bssid),
        "vendor_marker": header.marker,
        "mesh_dst4": hex_bytes(&header.mesh_dst4),
        "payload_len": payload.len(),
        "payload": hex_bytes(payload),
        "payload_text": String::from_utf8_lossy(payload).trim(),
    }))
}

pub fn parse_nan_ipv6_udp_frame(frame: &[u8], iface: &str, backend: &str) -> Option<Value> {
    let body = frame.get(IEEE80211_BODY + IEEE80211_LLC_SNAP_LEN..)?;
    if body.len() < 48 || body[0] >> 4 != 6 || body[6] != 17 {
        return None;
    }
    let payload_len = u16::from_be_bytes([body[4], body[5]]) as usize;
    if payload_len < 8 || body.len() < 40 + payload_len {
        return None;
    }
    let udp = &body[40..40 + payload_len];
    let source = mac_at(frame, IEEE80211_ADDR2)?;
    let destination = mac_at(frame, IEEE80211_ADDR1)?;
    let bssid = mac_at(frame, IEEE80211_ADDR3)?;
    let payload = &udp[8..];
    Some(json!({
        "protocol": "dmesh_wifi_raw",
        "layout": "nan_ipv6_udp",
        "backend": backend,
        "encapsulation": "llc_snap_ipv6",
        "iface": iface,
        "frame_type": frame_type(frame),
        "frame_subtype": frame_subtype(frame),
        "source": colon_mac(&source),
        "destination": colon_mac(&destination),
        "bssid": colon_mac(&bssid),
        "ipv6_source": format_ipv6(&body[8..24]),
        "ipv6_destination": format_ipv6(&body[24..40]),
        "udp_source": u16::from_be_bytes([udp[0], udp[1]]),
        "udp_destination": u16::from_be_bytes([udp[2], udp[3]]),
        "payload_len": payload.len(),
        "payload": hex_bytes(payload),
        "payload_text": String::from_utf8_lossy(payload).trim(),
    }))
}

pub fn format_ipv6(bytes: &[u8]) -> String {
    bytes
        .chunks_exact(2)
        .map(|part| format!("{:x}", u16::from_be_bytes([part[0], part[1]])))
        .collect::<Vec<_>>()
        .join(":")
}

pub struct DmeshWifiHeader {
    pub header_len: usize,
    pub marker: &'static str,
    pub mesh_dst4: [u8; 4],
}

pub fn parse_dmesh_vendor_action_header(body: &[u8]) -> Option<DmeshWifiHeader> {
    if body.len() >= DMESH_VENDOR_ACTION_LEN
        && body[..DMESH_ESPNOW_PREFIX.len()] == DMESH_ESPNOW_PREFIX
    {
        // Native action frames continue with one ESP-NOW vendor IE.  The
        // Ethernet/LLC diagnostic encapsulation uses the same eight-byte
        // marker directly, so only skip the IE when it is actually present.
        let header_len = if body.len() >= DMESH_VENDOR_ACTION_LEN + DMESH_VENDOR_IE_LEN
            && body[DMESH_VENDOR_ACTION_LEN] == 0xdd
            && body[DMESH_VENDOR_ACTION_LEN + 2..DMESH_VENDOR_ACTION_LEN + 5]
                == DMESH_ESPNOW_PREFIX[1..]
            && body[DMESH_VENDOR_ACTION_LEN + 5] == 0x04
        {
            DMESH_VENDOR_ACTION_LEN + DMESH_VENDOR_IE_LEN
        } else {
            DMESH_VENDOR_ACTION_LEN
        };
        return Some(DmeshWifiHeader {
            header_len,
            marker: "espnow_dmesh",
            mesh_dst4: [body[4], body[5], body[6], body[7]],
        });
    }
    if body.starts_with(&DMESH_LEGACY_VENDOR_ACTION) {
        return Some(DmeshWifiHeader {
            header_len: DMESH_LEGACY_VENDOR_ACTION.len(),
            marker: "legacy_dmesh",
            mesh_dst4: [0xff; 4],
        });
    }
    None
}

pub fn parse_management_frame(frame: &[u8], iface: &str, backend: &str) -> Value {
    let subtype = frame_subtype(frame);
    let kind = match subtype {
        0 => "assoc_req",
        1 => "assoc_resp",
        2 => "reassoc_req",
        3 => "reassoc_resp",
        4 => "probe_req",
        5 => "probe_resp",
        8 => "beacon",
        10 => "disassoc",
        11 => "auth",
        12 => "deauth",
        13 => "action",
        _ => "mgmt",
    };
    let destination = mac_at(frame, IEEE80211_ADDR1).unwrap_or([0; 6]);
    let source = mac_at(frame, IEEE80211_ADDR2).unwrap_or([0; 6]);
    let bssid = mac_at(frame, IEEE80211_ADDR3).unwrap_or([0; 6]);
    let mut fixed = serde_json::Map::new();
    let ies_start = match subtype {
        0 => {
            insert_u16_at(&mut fixed, "capability", frame, IEEE80211_BODY);
            insert_u16_at(&mut fixed, "listen_interval", frame, IEEE80211_BODY + 2);
            IEEE80211_BODY + 4
        }
        1 | 3 => {
            insert_u16_at(&mut fixed, "capability", frame, IEEE80211_BODY);
            insert_u16_at(&mut fixed, "status_code", frame, IEEE80211_BODY + 2);
            insert_u16_at(&mut fixed, "aid", frame, IEEE80211_BODY + 4);
            IEEE80211_BODY + 6
        }
        2 => {
            insert_u16_at(&mut fixed, "capability", frame, IEEE80211_BODY);
            insert_u16_at(&mut fixed, "listen_interval", frame, IEEE80211_BODY + 2);
            if let Some(current_ap) = mac_at(frame, IEEE80211_BODY + 4) {
                fixed.insert("current_ap".to_string(), json!(colon_mac(&current_ap)));
            }
            IEEE80211_BODY + 10
        }
        4 => IEEE80211_BODY,
        5 | 8 => {
            if let Some(timestamp) = read_u64_at(frame, IEEE80211_BODY) {
                fixed.insert("timestamp".to_string(), json!(timestamp));
            }
            insert_u16_at(&mut fixed, "beacon_interval", frame, IEEE80211_BODY + 8);
            insert_u16_at(&mut fixed, "capability", frame, IEEE80211_BODY + 10);
            IEEE80211_BODY + 12
        }
        10 | 12 => {
            insert_u16_at(&mut fixed, "reason_code", frame, IEEE80211_BODY);
            IEEE80211_BODY + 2
        }
        11 => {
            insert_u16_at(&mut fixed, "auth_algorithm", frame, IEEE80211_BODY);
            insert_u16_at(&mut fixed, "auth_transaction", frame, IEEE80211_BODY + 2);
            insert_u16_at(&mut fixed, "status_code", frame, IEEE80211_BODY + 4);
            IEEE80211_BODY + 6
        }
        13 => {
            if let Some(category) = frame.get(IEEE80211_BODY) {
                fixed.insert("category".to_string(), json!(*category));
            }
            frame.len()
        }
        _ => frame.len(),
    };
    let ies = if ies_start <= frame.len() {
        parse_wifi_ies(&frame[ies_start..])
    } else {
        Vec::new()
    };
    let ssid = ies
        .iter()
        .find(|ie| ie.get("id").and_then(Value::as_u64) == Some(0))
        .and_then(|ie| ie.get("text"))
        .cloned()
        .unwrap_or(Value::Null);
    let channel = ies
        .iter()
        .find(|ie| ie.get("id").and_then(Value::as_u64) == Some(3))
        .and_then(|ie| ie.get("bytes").and_then(Value::as_array))
        .and_then(|bytes| bytes.first().and_then(Value::as_u64));
    json!({
        "kind": kind,
        "backend": backend,
        "iface": iface,
        "frame_type": frame_type(frame),
        "frame_subtype": subtype,
        "destination": colon_mac(&destination),
        "source": colon_mac(&source),
        "bssid": colon_mac(&bssid),
        "fixed": fixed,
        "ssid": ssid,
        "channel": channel,
        "len": frame.len(),
        "frame": hex_bytes(frame),
        "ies": ies,
    })
}

pub fn is_nan_data_frame(frame: &[u8]) -> bool {
    if frame.len() < IEEE80211_BODY + IEEE80211_LLC_SNAP_LEN
        || frame_type(frame) != 2
        || mac_at(frame, IEEE80211_ADDR3).map(|bssid| bssid[..3] == [0x50, 0x6f, 0x9a])
            != Some(true)
    {
        return false;
    }
    true
}

pub fn raw_wifi_receive_addresses(iface: &str) -> Vec<[u8; 6]> {
    match iface_mac(iface) {
        Ok(mac) => vec![mac, raw_receive_mac(mac), RAW_WIFI_MULTICAST],
        Err(_) => vec![RAW_WIFI_MULTICAST],
    }
}

pub fn raw_wifi_receive_address_allowed(frame: &[u8], addresses: &[[u8; 6]]) -> bool {
    let Some(destination) = mac_at(frame, IEEE80211_ADDR1) else {
        return false;
    };
    addresses.iter().any(|address| *address == destination)
}

pub fn build_dmesh_multicast_data_frame(
    destination: [u8; 6],
    source: [u8; 6],
    payload: &[u8],
) -> Vec<u8> {
    let body_len = payload.len().min(1400);
    let mut frame = Vec::with_capacity(IEEE80211_BODY + DMESH_VENDOR_ACTION_LEN + body_len);
    frame.extend_from_slice(&[0x08, 0x00, 0x00, 0x00]);
    frame.extend_from_slice(&destination);
    frame.extend_from_slice(&source);
    frame.extend_from_slice(&destination);
    frame.extend_from_slice(&[0x00, 0x00]);
    frame.extend_from_slice(&dmesh_vendor_action_header(destination));
    frame.extend_from_slice(&payload[..body_len]);
    frame
}

pub fn build_dmesh_sta_multicast_llc_frame(bssid: [u8; 6], source: [u8; 6], payload: &[u8]) -> Vec<u8> {
    let body_len = payload.len().min(1400);
    let mut frame = Vec::with_capacity(
        IEEE80211_BODY + IEEE80211_LLC_SNAP_LEN + DMESH_VENDOR_ACTION_LEN + body_len,
    );
    frame.extend_from_slice(&[0x08, 0x01, 0x00, 0x00]);
    frame.extend_from_slice(&bssid);
    frame.extend_from_slice(&source);
    frame.extend_from_slice(&RAW_WIFI_MULTICAST);
    frame.extend_from_slice(&[0x00, 0x00]);
    frame.extend_from_slice(&IEEE80211_LLC_SNAP_DMESH);
    frame.extend_from_slice(&dmesh_vendor_action_header(RAW_WIFI_MULTICAST));
    frame.extend_from_slice(&payload[..body_len]);
    frame
}

pub fn build_dmesh_sta_direct_llc_frame(
    destination: [u8; 6],
    source: [u8; 6],
    payload: &[u8],
) -> Vec<u8> {
    let body_len = payload.len().min(1400);
    let mut frame = Vec::with_capacity(
        IEEE80211_BODY + IEEE80211_LLC_SNAP_LEN + DMESH_VENDOR_ACTION_LEN + body_len,
    );
    frame.extend_from_slice(&[0x08, 0x00, 0x00, 0x00]);
    frame.extend_from_slice(&destination);
    frame.extend_from_slice(&source);
    frame.extend_from_slice(&destination);
    frame.extend_from_slice(&[0x00, 0x00]);
    frame.extend_from_slice(&IEEE80211_LLC_SNAP_DMESH);
    frame.extend_from_slice(&dmesh_vendor_action_header(destination));
    frame.extend_from_slice(&payload[..body_len]);
    frame
}

/// Build an unassociated NAN-cluster data frame. Address3 is the selected
/// cluster BSSID; no IP/UDP/AP association is involved. The LLC/SNAP marker is
/// intentionally the same one used by the existing raw data parser so this
/// can be compared with the action-frame path.
pub fn build_dmesh_nan_data_frame(
    bssid: [u8; 6],
    destination: [u8; 6],
    source: [u8; 6],
    payload: &[u8],
) -> Vec<u8> {
    crate::build_nan_ipv6_udp_frame(bssid, destination, source, payload)
}

pub fn build_dmesh_nan_raw_data_frame(
    bssid: [u8; 6],
    destination: [u8; 6],
    source: [u8; 6],
    llc: &[u8; IEEE80211_LLC_SNAP_LEN],
    payload: &[u8],
) -> Vec<u8> {
    crate::build_nan_raw_data_frame(bssid, destination, source, *llc, payload)
}

pub fn parse_experimental_llc(value: Option<&str>) -> Option<[u8; IEEE80211_LLC_SNAP_LEN]> {
    let value = value?;
    let value = value.strip_prefix("hex:").unwrap_or(value);
    let compact = value.replace([':', '-', ' ', '_'], "");
    if compact.len() != IEEE80211_LLC_SNAP_LEN * 2 {
        return None;
    }
    let mut out = [0u8; IEEE80211_LLC_SNAP_LEN];
    for (index, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&compact[index * 2..index * 2 + 2], 16).ok()?;
    }
    Some(out)
}

/// Consume management beacons for the shared raw-NAN synchronization state.
/// USD action frames are intentionally not treated as a timing source: sleepy
/// peers need the cluster/AP beacon TSF and interval to schedule their wake
/// window and follow-up transmission.
pub fn handle_beacon_frame(
    frame: &[u8],
    iface: &str,
    rx_signal_dbm: Option<i32>,
    rawnan_state: &Arc<Mutex<NanState>>,
) -> Option<Value> {
    if frame_type(frame) != 0 || frame_subtype(frame) != 8 {
        return None;
    }
    let rx = RawNanRxFrame {
        bytes: frame,
        rssi_dbm: rx_signal_dbm
            .unwrap_or(0)
            .clamp(i8::MIN as i32, i8::MAX as i32) as i8,
        timestamp_us: now_micros_u64(),
    };
    let action = if crate::is_nan_beacon(frame) {
        rawnan_state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .observe(rx)
    } else {
        rawnan_state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .observe_ap_beacon(rx);
        RawNanAction::None
    };
    let bssid = mac_at(frame, IEEE80211_ADDR3).map(|mac| colon_mac(&mac));
    let nan = crate::is_nan_beacon(frame);
    let parsed = parse_management_frame(frame, iface, "passive_monitor");
    Some(json!({
        "ok": true,
        "backend": "rawnan_host",
        "iface": iface,
        "source": mac_at(frame, IEEE80211_ADDR2).map(|mac| colon_mac(&mac)),
        "bssid": bssid,
        "ssid": parsed.get("ssid").cloned().unwrap_or(Value::Null),
        "channel": parsed.get("channel").cloned().unwrap_or(Value::Null),
        "sync_source": if nan { "nan_cluster" } else { "ap_anchor" },
        "nan_beacon": nan,
        "tsf_us": crate::beacon_tsf_us(frame),
        "beacon_interval_tu": crate::beacon_interval_tu(frame),
        "rx_signal_dbm": rx_signal_dbm,
        "nan_action": match action {
            RawNanAction::None => "none",
            RawNanAction::ArmA3(_) => "arm_a3",
            RawNanAction::DropForeign => "drop_foreign",
            RawNanAction::Rediscover => "rediscover",
        },
    }))
}

/// Hand a validated NOW synchronization record to the NAN timing owner: it plays the part
/// of a beacon in the one `NanState`, which stays the sole scheduler of the discovery
/// windows. `local` is this device's own MAC (a record that names it is ignored).
pub fn handle_now_sync_as_nan(
    local: [u8; 6],
    peer: [u8; 6],
    sync: &crate::NowSyncFrame<'_>,
    received_at_us: u64,
    rawnan_state: &Arc<Mutex<NanState>>,
) {
    if peer == local {
        return;
    }
    rawnan_state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .observe_now_sync(
            crate::MacAddr(local),
            sync.cluster_id,
            sync.tsf_us,
            sync.interval_tu,
            sync.is_nan_aligned(),
            received_at_us,
        );
}

/// Classify every received 802.11 action frame in one place. AP management
/// responses remain handled by `handle_open_ap_sme_frame`; this function is
/// deliberately receive-only and covers NAN public/vendor actions and the
/// DMesh/ESP-NOW action marker without creating a second read loop.
pub fn handle_action_frame(
    frame: &[u8],
    iface: &str,
    rx_signal_dbm: Option<i32>,
    rawnan_state: &Arc<Mutex<NanState>>,
) -> Option<Value> {
    if frame_type(frame) != 0 || frame_subtype(frame) != 13 {
        return None;
    }
    let nan_kind = crate::classify(frame);
    let nan_action = rawnan_state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .observe(RawNanRxFrame {
            bytes: frame,
            rssi_dbm: rx_signal_dbm
                .unwrap_or(0)
                .clamp(i8::MIN as i32, i8::MAX as i32) as i8,
            timestamp_us: now_micros_u64(),
        });
    let source = mac_at(frame, IEEE80211_ADDR2).map(|mac| colon_mac(&mac));
    let destination = mac_at(frame, IEEE80211_ADDR1).map(|mac| colon_mac(&mac));
    let bssid = mac_at(frame, IEEE80211_ADDR3).map(|mac| colon_mac(&mac));
    let mut result = json!({
        "ok": true,
        "protocol": "80211_action",
        "iface": iface,
        "source": source,
        "destination": destination,
        "bssid": bssid,
        "frame_len": frame.len(),
        "category": frame.get(IEEE80211_BODY).copied(),
        "nan_kind": match nan_kind {
            crate::FrameKind::Beacon => "beacon",
            crate::FrameKind::Sdf => "service_discovery",
            crate::FrameKind::Followup => "followup",
            crate::FrameKind::P2p => "p2p",
            crate::FrameKind::Gas => "gas",
            crate::FrameKind::Other => "other",
        },
        "nan_filter_action": match nan_action {
            RawNanAction::None => "none",
            RawNanAction::ArmA3(_) => "arm_a3",
            RawNanAction::DropForeign => "drop_foreign",
            RawNanAction::Rediscover => "rediscover",
        },
        "p2p_gas_initial_request": crate::is_gas_initial_request(frame),
    });
    if let Some(signal) = rx_signal_dbm
        && let Some(object) = result.as_object_mut()
    {
        object.insert("rx_signal_dbm".to_string(), json!(signal));
    }
    if let Some(vendor) = parse_dmesh_wifi_frame(frame, iface, "linux_nl80211_ap_sme")
        && let Some(object) = result.as_object_mut()
    {
        object.insert("dmesh".to_string(), vendor);
    }
    Some(result)
}

/// A user-space AP must retire its nl80211 station entry when a peer leaves.
/// Auth/association are handled separately by `handle_open_ap_sme_frame`.
pub fn ap_sme_station_departed(subtype: u8) -> bool {
    matches!(subtype, 10 | 12)
}

pub fn handle_open_ap_sme_frame(
    socket: &Nl80211Socket,
    iface: &str,
    ifindex: u32,
    ap_mac: [u8; 6],
    frame: &[u8],
    ap_no_ht_stations: &Arc<Mutex<HashSet<[u8; 6]>>>,
    channel: u8,
    ht40: bool,
) -> Option<Value> {
    if frame_type(frame) != 0 {
        return None;
    }
    let sta_mac = mac_at(frame, IEEE80211_ADDR2)?;
    let subtype = frame_subtype(frame);
    let response = match subtype {
        4 if crate::is_p2p_probe_request(frame) => {
            // P2P peer discovery uses a management Probe Request, not an
            // action frame. Respond on the AP's already-registered nl80211
            // management socket with device/channel discovery attributes.
            // This does not form a group or answer the later GAS SD request.
            let response = build_p2p_probe_response(ap_mac, sta_mac, channel)
                .expect("bounded P2P probe response");
            let tx = send_open_ap_mgmt_response(socket, iface, ifindex, channel, &response);
            json!({
                "kind": "p2p_probe_response",
                "destination": colon_mac(&sta_mac),
                "channel": channel,
                "frame_len": response.len(),
                "tx": tx,
            })
        }
        11 => {
            if read_u16_at(frame, IEEE80211_BODY) != Some(NL80211_AUTHTYPE_OPEN_SYSTEM as u16) {
                return None;
            }
            let response = build_open_auth_response(ap_mac, sta_mac);
            let tx = send_open_ap_mgmt_response(socket, iface, ifindex, channel, &response);
            json!({
                "kind": "auth_resp",
                "association_attempt": true,
                "destination": colon_mac(&sta_mac),
                "frame_len": response.len(),
                "tx": tx,
            })
        }
        0 | 2 => {
            let aid = 1_u16;
            let allow_ht = !ap_no_ht_stations
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .contains(&sta_mac);
            let add_station = Nl80211Socket::open()
                .and_then(|socket| {
                    // A station entry can survive an ESP reset or a prior
                    // monitor-fallback association. Replace it before
                    // applying the new association parameters; otherwise
                    // mt76x2u accepts the response but sends reason-8
                    // disassociation about a second later.
                    let _ = socket.remove_station(ifindex, sta_mac);
                    socket.add_station_from_assoc(ifindex, sta_mac, frame, allow_ht)
                })
                .map(|_| json!({ "ok": true }))
                .unwrap_or_else(|error| json!({ "ok": false, "error": format!("{error:#}") }));
            let response = build_open_assoc_response(ap_mac, sta_mac, aid, allow_ht, channel, ht40);
            let tx = send_open_ap_mgmt_response(socket, iface, ifindex, channel, &response);
            json!({
                "kind": "assoc_resp",
                "association_attempt": true,
                "destination": colon_mac(&sta_mac),
                "aid": aid,
                "ht": allow_ht,
                "add_station": add_station,
                "frame_len": response.len(),
                "tx": tx,
            })
        }
        _ => return None,
    };
    Some(response)
}

/// Build a directed P2P discovery Probe Response for one received P2P Probe
/// Request. The common codec owns the vendor IE; this Linux adapter only owns
/// the management header and on-channel transmission.
pub fn build_p2p_probe_response(source: [u8; 6], destination: [u8; 6], channel: u8) -> Result<Vec<u8>> {
    let mut frame = mgmt_frame_header(5, destination, source, source);
    frame.extend_from_slice(&[0; 8]);
    frame.extend_from_slice(&100_u16.to_le_bytes());
    frame.extend_from_slice(&0x0421_u16.to_le_bytes());
    frame.extend_from_slice(&[0, 7]);
    frame.extend_from_slice(b"DIRECT-");
    frame.extend_from_slice(&[1, OPEN_AP_OFDM_BASIC_RATES.len() as u8]);
    frame.extend_from_slice(&OPEN_AP_OFDM_BASIC_RATES);
    frame.extend_from_slice(&[3, 1, channel]);
    let mut p2p = [0u8; 64];
    let used = crate::p2p::encode_discovery_advertisement(&mut p2p, source, channel)
        .map_err(|error| anyhow::anyhow!("P2P probe-response IE: {error:?}"))?;
    frame.extend_from_slice(&p2p[..used]);
    Ok(frame)
}

/// Build a successful `dmesh._dmesh._tcp` DNS-SD response for a received P2P
/// SD request. The portable codec validates and echoes the query key and
/// transaction; this Linux adapter supplies only the management header.
pub fn build_dmesh_p2p_sd_response(source: [u8; 6], request: &[u8]) -> Option<Vec<u8>> {
    let destination = mac_at(request, IEEE80211_ADDR2)?;
    let mut frame = mgmt_frame_header(13, destination, source, source);
    let mut presence = [0u8; 18];
    let presence_len =
        crate::p2p::encode_dmesh_service_presence_txt(&mut presence, &source).ok()?;
    let mut body = [0u8; 192];
    let used = crate::p2p::encode_dmesh_dns_sd_gas_initial_response(
        &mut body,
        request,
        &presence[..presence_len],
    )
    .ok()?;
    frame.extend_from_slice(&body[..used]);
    Some(frame)
}

pub fn send_open_ap_mgmt_response(
    socket: &Nl80211Socket,
    iface: &str,
    ifindex: u32,
    channel: u8,
    frame: &[u8],
) -> Value {
    match socket.send_mgmt_frame(ifindex, frame, None) {
        Ok(()) => json!({ "ok": true, "backend": "linux_nl80211" }),
        Err(error) => {
            // Some mac80211 drivers reject the minimal CMD_FRAME form while
            // an AP SME is active, but accept the fully-qualified on-channel
            // form used by the normal raw TX path. Try that before falling
            // back to monitor injection (which may be looped back rather than
            // emitted when the managed AP owns the parent interface).
            let options = RawWifiTxOptions {
                variant: "ap_sme".to_owned(),
                include_freq: true,
                duration_ms: Some(100),
                offchannel_tx_ok: false,
                dont_wait_for_ack: true,
                tx_no_cck_rate: false,
            };
            // mt76x2u can reject NL80211_CMD_FRAME with ENOMEM while its
            // management-TX context is busy.  The same physical radio can
            // still inject a short on-channel control frame through a
            // monitor VIF, which is also the NAN raw-frame path. Keep this a
            // narrow fallback for AP SME responses rather than changing the
            // normal NAN TX policy.
            match send_monitor_frame(iface, channel, frame, None) {
                Ok(monitor) => json!({
                    "ok": true,
                    "backend": "linux_monitor_ap_sme_fallback",
                    "nl80211_error": format!("{error:#}"),
                    "monitor": monitor,
                }),
                Err(monitor_error) => {
                    if socket
                        .send_frame(ifindex, channel_to_freq(channel), &options, frame, None)
                        .is_ok()
                    {
                        json!({
                            "ok": true,
                            "backend": "linux_nl80211_ap_sme_explicit_channel",
                            "nl80211_error": format!("{error:#}"),
                            "monitor_error": format!("{monitor_error:#}"),
                        })
                    } else {
                        json!({
                            "ok": false,
                            "backend": "linux_nl80211",
                            "error": format!("{error:#}"),
                            "monitor_fallback_error": format!("{monitor_error:#}"),
                        })
                    }
                }
            }
        }
    }
}

/// Return stations that should use legacy (non-HT) association parameters.
///
/// The AP advertises HT20 globally, but a manually managed nl80211 AP can
/// still have a particular station/driver with unreliable aggregation or
/// Block-ACK behavior. Keep the normal HT20 path as the default and allow a
/// targeted workaround without lowering the rate for every station.
/// `LMESH_WIFI_AP_NO_HT_STATIONS` is a comma-separated list of MAC addresses.
pub fn ap_no_ht_stations() -> HashSet<[u8; 6]> {
    std::env::var("LMESH_WIFI_AP_NO_HT_STATIONS")
        .ok()
        .into_iter()
        .flat_map(|value| value.split(',').map(str::to_string).collect::<Vec<_>>())
        .filter_map(|value| parse_mac(Some(value.trim())))
        .collect()
}

/// Encode and send one bearer-neutral QUIC datagram as an ESP-NOW-like
/// action. Keeping this in one helper makes immediate responses and timer
/// retransmissions use identical address/rate/framing behavior.
/// Persistent transmit path for the ESP-NOW QUIC bearer. Creating an AF_PACKET
/// socket for every datagram can race driver context changes and lose packets;
/// retain the bound monitor socket between submissions. A failed submission
/// retires the socket so the next QUIC retry can reopen it after radio/VIF
/// recreation.
pub struct RawActionTransmitter {
    pub iface: String,
    pub socket: Option<MonitorTxSocket>,
}

impl RawActionTransmitter {
    pub fn new(iface: String) -> Self {
        Self {
            iface,
            socket: None,
        }
    }

    pub fn send(
        &mut self,
        peer: [u8; 6],
        payload: &[u8],
        tx_rate_mbps: u8,
    ) -> std::result::Result<(), RawActionSubmitError> {
        if self.socket.is_none() {
            let monitor_iface = monitor_iface_name(&self.iface);
            self.socket = Some(
                MonitorTxSocket::open(&monitor_iface).map_err(RawActionSubmitError::Failed)?,
            );
        }
        let result = send_raw_action_datagram_on_socket(
            &self.iface,
            self.socket.as_ref().expect("socket opened above"),
            peer,
            payload,
            tx_rate_mbps,
        );
        match result {
            Ok(()) => Ok(()),
            Err(error) if raw_action_error_is_would_block(&error) => {
                Err(RawActionSubmitError::WouldBlock)
            }
            Err(error) => {
                self.socket.take();
                Err(RawActionSubmitError::Failed(error))
            }
        }
    }
}

pub enum RawActionSubmitError {
    WouldBlock,
    Failed(anyhow::Error),
}

pub fn raw_action_error_is_would_block(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<std::io::Error>()
        .is_some_and(|error| error.kind() == std::io::ErrorKind::WouldBlock)
}

/// Send using a caller-owned AF_PACKET socket.  The receive loop sends both
/// immediate QUIC responses and PTO retransmissions; keeping one bound socket
/// for that loop avoids repeated socket/bind setup and, more importantly,
/// avoids dropping packets while the driver is switching between short-lived
/// transmit contexts.
/// NOW transmissions this process attempted, completed and failed (every path ends in
/// [`send_raw_action_datagram_on_socket`]); reported as `telemetry.now`.
pub static NOW_TX_ATTEMPTED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
pub static NOW_TX_ACCEPTED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
pub static NOW_TX_FAILED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

pub fn send_raw_action_datagram_on_socket(
    iface: &str,
    socket: &MonitorTxSocket,
    peer: [u8; 6],
    payload: &[u8],
    tx_rate_mbps: u8,
) -> Result<()> {
    use std::sync::atomic::Ordering::Relaxed;
    NOW_TX_ATTEMPTED.fetch_add(1, Relaxed);
    let result = send_raw_action_datagram_inner(iface, socket, peer, payload, tx_rate_mbps);
    match &result {
        Ok(()) => NOW_TX_ACCEPTED.fetch_add(1, Relaxed),
        Err(_) => NOW_TX_FAILED.fetch_add(1, Relaxed),
    };
    result
}

fn send_raw_action_datagram_inner(
    iface: &str,
    socket: &MonitorTxSocket,
    peer: [u8; 6],
    payload: &[u8],
    tx_rate_mbps: u8,
) -> Result<()> {
    let local = iface_mac(iface).with_context(|| format!("missing local MAC for {iface}"))?;
    let mut action = [0_u8; quic_lite::DEFAULT_MAX_PACKET_SIZE + 64];
    let destination = raw_action_response_address(peer);
    let action_len = crate::espnow::encode_action_frame(
        &mut action,
        destination,
        local,
        [0xff; 6],
        payload,
    )
    .map_err(|error| anyhow::anyhow!("raw NOW response frame: {error:?}"))?;
    let packet = build_radiotap_packet_at_rate_with_ack(
        &action[..action_len],
        Some(tx_rate_mbps),
        // Replies use the same DMesh NOW no-MAC-ACK policy as requests.
        false,
    )?;
    for repetition in 0..raw_action_response_repetitions() {
        if repetition != 0 {
            // A duplicate sent back-to-back can be discarded by the
            // monitor/driver queue as one write.  A short gap makes this a
            // real independent on-air attempt while retaining one shared
            // QUIC packet buffer.
            std::thread::sleep(Duration::from_millis(raw_action_burst_gap_ms()));
        }
        let written = socket.send(&packet)?;
        if written != packet.len() {
            bail!(
                "short raw NOW response write: wrote {written}, expected {}",
                packet.len()
            );
        }
    }
    Ok(())
}

/// Address-1 used for a host-originated NOW QUIC packet. QUIC is directed
/// unicast; the receive alias is reserved for the separate discovery probe
/// and remains available only as an explicit diagnostic override.
pub fn raw_action_response_address(peer: [u8; 6]) -> [u8; 6] {
    raw_action_response_address_with_alias_override(
        peer,
        std::env::var("DMESH_RAW_ACTION_RESPONSE_A1").as_deref() == Ok("receive_alias"),
    )
}

pub fn raw_action_response_address_with_alias_override(
    peer: [u8; 6],
    use_receive_alias: bool,
) -> [u8; 6] {
    if use_receive_alias {
        raw_receive_mac(peer)
    } else {
        directed_now_destination(peer)
    }
}

pub fn raw_action_burst_gap_ms() -> u64 {
    std::env::var("DMESH_RAW_ACTION_BURST_GAP_MS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(2)
        .min(100)
}

pub fn raw_action_response_repetitions() -> usize {
    std::env::var("DMESH_RAW_ACTION_RESPONSE_REPETITIONS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(RAW_ACTION_RESPONSE_REPETITIONS)
        .clamp(1, 8)
}

pub fn raw_wifi_destination(value: Option<&str>, variant: &str) -> [u8; 6] {
    if let Some(value) = value {
        if let Some(mac) = value
            .strip_prefix("rx:")
            .or_else(|| value.strip_prefix("raw:"))
            .and_then(|mac| parse_mac(Some(mac)))
        {
            // NAN data frames use ordinary 802.11 address semantics. The
            // raw-receive-MAC XOR convention is only for the ESP-NOW/action
            // probe path.
            if variant != "nan_data" && variant != "nan_data_active" {
                return raw_receive_mac(mac);
            }
            return mac;
        }
        if let Some(mac) = parse_mac(Some(value)) {
            return mac;
        }
    }
    if variant == "multicast_data" || variant == "multicast_data_active" {
        RAW_WIFI_MULTICAST
    } else {
        RAW_WIFI_BROADCAST
    }
}

pub fn raw_wifi_destination_mode(value: Option<&str>, variant: &str) -> &'static str {
    if let Some(value) = value {
        if (value.starts_with("rx:") || value.starts_with("raw:"))
            && variant != "nan_data"
            && variant != "nan_data_active"
        {
            return "peer_raw_receive_mac";
        }
        if parse_mac(Some(value)).is_some() {
            return "explicit_mac";
        }
    }
    if variant == "multicast_data" || variant == "multicast_data_active" {
        "ipv6_multicast_ff02_5227"
    } else {
        "broadcast"
    }
}

pub fn raw_wifi_source(value: Option<&str>, iface: &str) -> Result<[u8; 6]> {
    if let Some(value) = value {
        if let Some(mac) = parse_mac(Some(value)) {
            return Ok(mac);
        }
        bail!("invalid source MAC {value:?}");
    }
    iface_mac(iface)
}

/// Directed NOW QUIC traffic uses the selected peer address unchanged in
/// 802.11 address 1.  `raw_receive_mac` is retained only for legacy monitor
/// filtering and discovery experiments; applying it to a directed sender
/// turns a unicast address into a group address.
pub fn directed_now_destination(peer: [u8; 6]) -> [u8; 6] {
    peer
}

pub fn json_scalar_string(value: &Value) -> String {
    value
        .as_str()
        .map(str::to_string)
        .unwrap_or_else(|| value.to_string())
}
