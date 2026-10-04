//! Frame constants and small address/IE helpers shared by the Linux backend.
use super::*;

pub const DEFAULT_RAW_WIFI_CHANNEL: u8 = 6;

pub const ETH_P_ALL: u16 = 0x0003;

pub const ETH_P_DMESH: u16 = 0x88b5;

pub const IEEE80211_LLC_SNAP_LEN: usize = 8;

pub const IEEE80211_ADDR1: usize = 4;

pub const IEEE80211_ADDR2: usize = 10;

pub const IEEE80211_ADDR3: usize = 16;

pub const IEEE80211_BODY: usize = 24;

pub const IEEE80211_ACTION_FRAME_TYPE: u16 = 0x00d0;

pub const RAW_WIFI_BROADCAST: [u8; 6] = [0xff; 6];

pub const RAW_WIFI_MULTICAST: [u8; 6] = [0x33, 0x33, 0x00, 0x00, 0x52, 0x27];

pub const DMESH_ESPNOW_PREFIX: [u8; 4] = [0x7f, 0x18, 0xfe, 0x34];

// rawnan owns the ESP-NOW-compatible action prefix.  Its current envelope is
// category/OUI plus four random bytes; the vendor type lives in the first IE,
// not after this prefix.
pub const DMESH_VENDOR_ACTION_LEN: usize = 8;

pub const DMESH_VENDOR_IE_LEN: usize = 7;

pub const DMESH_LEGACY_VENDOR_ACTION: [u8; 5] = [0x7f, 0x50, 0x6f, 0x9a, 0x42];

pub const IEEE80211_LLC_SNAP_DMESH: [u8; IEEE80211_LLC_SNAP_LEN] = [
    0xaa,
    0xaa,
    0x03,
    0x00,
    0x00,
    0x00,
    (ETH_P_DMESH >> 8) as u8,
    ETH_P_DMESH as u8,
];

pub const IEEE80211_LLC_SNAP_IPV6: [u8; IEEE80211_LLC_SNAP_LEN] =
    [0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x86, 0xdd];

// Private experimental marker for raw NAN data tests.  The payload after
// this eight-byte LLC value is quic-lite directly, not IPv6/UDP.
pub const RAWNAN_LLC_DEFAULT: [u8; IEEE80211_LLC_SNAP_LEN] =
    [0xaa, 0xaa, 0x03, 0xd0, 0x4d, 0x45, 0x53, 0x48];

pub fn management_ie_bytes(mut bytes: &[u8], wanted_id: u8) -> Option<&[u8]> {
    while bytes.len() >= 2 {
        let id = bytes[0];
        let length = bytes[1] as usize;
        bytes = &bytes[2..];
        if bytes.len() < length {
            return None;
        }
        let value = &bytes[..length];
        if id == wanted_id {
            return Some(value);
        }
        bytes = &bytes[length..];
    }
    None
}

pub fn hex_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn dmesh_vendor_action_header(destination: [u8; 6]) -> [u8; DMESH_VENDOR_ACTION_LEN] {
    let _ = destination;
    crate::espnow_action_header()
}

pub fn frame_type(frame: &[u8]) -> u8 {
    (frame.first().copied().unwrap_or(0) & 0x0c) >> 2
}

pub fn frame_subtype(frame: &[u8]) -> u8 {
    frame.first().copied().unwrap_or(0) >> 4
}

pub fn colon_mac(bytes: &[u8; 6]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

pub fn raw_receive_mac(mut mac: [u8; 6]) -> [u8; 6] {
    mac[0] ^= 0x01;
    mac
}

pub fn monitor_iface_name(iface: &str) -> String {
    if iface.ends_with("mon") {
        iface.to_string()
    } else {
        format!("{iface}mon")
    }
}

pub fn mac_at(frame: &[u8], offset: usize) -> Option<[u8; 6]> {
    let mut out = [0_u8; 6];
    out.copy_from_slice(frame.get(offset..offset + 6)?);
    Some(out)
}

#[derive(Clone)]
pub struct RawWifiTxOptions {
    pub variant: String,
    pub include_freq: bool,
    pub duration_ms: Option<u32>,
    pub offchannel_tx_ok: bool,
    pub dont_wait_for_ack: bool,
    pub tx_no_cck_rate: bool,
}

impl RawWifiTxOptions {
    pub fn from_variant(
        variant: Option<&str>,
        listen_sec: u64,
        tx_duration_ms: Option<u32>,
    ) -> Result<Self> {
        // Host raw NOW/NAN has no association requirement.  The monitor
        // injector is therefore the default: nl80211 management-frame TX is
        // retained as an explicit driver experiment, but returns ENOTCONN on
        // an unassociated adapter and must not be the production host path.
        let variant = variant.unwrap_or("monitor").trim();
        let duration_ms = tx_duration_ms
            .unwrap_or_else(|| listen_sec.saturating_mul(1000).min(u32::MAX as u64) as u32);
        let options = match variant {
            "" | "standard" => Self {
                variant: "standard".to_string(),
                include_freq: true,
                duration_ms: Some(duration_ms),
                offchannel_tx_ok: true,
                dont_wait_for_ack: false,
                tx_no_cck_rate: false,
            },
            "zero_duration" => Self {
                variant: variant.to_string(),
                include_freq: true,
                duration_ms: Some(0),
                offchannel_tx_ok: true,
                dont_wait_for_ack: false,
                tx_no_cck_rate: false,
            },
            "no_duration" => Self {
                variant: variant.to_string(),
                include_freq: true,
                duration_ms: None,
                offchannel_tx_ok: true,
                dont_wait_for_ack: false,
                tx_no_cck_rate: false,
            },
            "no_offchannel" => Self {
                variant: variant.to_string(),
                include_freq: true,
                duration_ms: Some(duration_ms),
                offchannel_tx_ok: false,
                dont_wait_for_ack: false,
                tx_no_cck_rate: false,
            },
            "minimal" => Self {
                variant: variant.to_string(),
                include_freq: true,
                duration_ms: None,
                offchannel_tx_ok: false,
                dont_wait_for_ack: false,
                tx_no_cck_rate: false,
            },
            "dont_wait_ack" => Self {
                variant: variant.to_string(),
                include_freq: true,
                duration_ms: Some(duration_ms),
                offchannel_tx_ok: true,
                dont_wait_for_ack: true,
                tx_no_cck_rate: false,
            },
            "dont_wait_no_duration" => Self {
                variant: variant.to_string(),
                include_freq: true,
                duration_ms: None,
                offchannel_tx_ok: true,
                dont_wait_for_ack: true,
                tx_no_cck_rate: false,
            },
            "dont_wait_minimal" => Self {
                variant: variant.to_string(),
                include_freq: true,
                duration_ms: None,
                offchannel_tx_ok: false,
                dont_wait_for_ack: true,
                tx_no_cck_rate: false,
            },
            "onchannel" => Self {
                variant: variant.to_string(),
                include_freq: false,
                duration_ms: None,
                offchannel_tx_ok: false,
                dont_wait_for_ack: false,
                tx_no_cck_rate: false,
            },
            "onchannel_noack" | "noack_onchannel" => Self {
                variant: variant.to_string(),
                include_freq: false,
                duration_ms: None,
                offchannel_tx_ok: false,
                dont_wait_for_ack: true,
                tx_no_cck_rate: false,
            },
            "dont_wait_no_cck" => Self {
                variant: variant.to_string(),
                include_freq: true,
                duration_ms: None,
                offchannel_tx_ok: true,
                dont_wait_for_ack: true,
                tx_no_cck_rate: true,
            },
            "no_cck" => Self {
                variant: variant.to_string(),
                include_freq: true,
                duration_ms: Some(duration_ms),
                offchannel_tx_ok: true,
                dont_wait_for_ack: false,
                tx_no_cck_rate: true,
            },
            "no_freq" => Self {
                variant: variant.to_string(),
                include_freq: false,
                duration_ms: Some(duration_ms),
                offchannel_tx_ok: true,
                dont_wait_for_ack: false,
                tx_no_cck_rate: false,
            },
            "monitor" => Self {
                variant: variant.to_string(),
                include_freq: false,
                duration_ms: None,
                offchannel_tx_ok: false,
                dont_wait_for_ack: true,
                tx_no_cck_rate: false,
            },
            "monitor_active" => Self {
                variant: variant.to_string(),
                include_freq: false,
                duration_ms: None,
                offchannel_tx_ok: false,
                dont_wait_for_ack: true,
                tx_no_cck_rate: false,
            },
            "action" | "send_action" => Self {
                variant: variant.to_string(),
                include_freq: false,
                duration_ms: None,
                offchannel_tx_ok: false,
                dont_wait_for_ack: false,
                tx_no_cck_rate: false,
            },
            "multicast_data" => Self {
                variant: variant.to_string(),
                include_freq: false,
                duration_ms: None,
                offchannel_tx_ok: false,
                dont_wait_for_ack: true,
                tx_no_cck_rate: false,
            },
            "multicast_data_active" => Self {
                variant: variant.to_string(),
                include_freq: false,
                duration_ms: None,
                offchannel_tx_ok: false,
                dont_wait_for_ack: true,
                tx_no_cck_rate: false,
            },
            "sta_multicast_llc" => Self {
                variant: variant.to_string(),
                include_freq: false,
                duration_ms: None,
                offchannel_tx_ok: false,
                dont_wait_for_ack: true,
                tx_no_cck_rate: false,
            },
            "sta_multicast_llc_active" => Self {
                variant: variant.to_string(),
                include_freq: false,
                duration_ms: None,
                offchannel_tx_ok: false,
                dont_wait_for_ack: true,
                tx_no_cck_rate: false,
            },
            "sta_direct_llc" => Self {
                variant: variant.to_string(),
                include_freq: false,
                duration_ms: None,
                offchannel_tx_ok: false,
                dont_wait_for_ack: true,
                tx_no_cck_rate: false,
            },
            "sta_direct_llc_active" => Self {
                variant: variant.to_string(),
                include_freq: false,
                duration_ms: None,
                offchannel_tx_ok: false,
                dont_wait_for_ack: true,
                tx_no_cck_rate: false,
            },
            "nan_data" => Self {
                variant: variant.to_string(),
                include_freq: false,
                duration_ms: None,
                offchannel_tx_ok: false,
                dont_wait_for_ack: true,
                tx_no_cck_rate: false,
            },
            "nan_data_active" => Self {
                variant: variant.to_string(),
                include_freq: false,
                duration_ms: None,
                offchannel_tx_ok: false,
                dont_wait_for_ack: true,
                tx_no_cck_rate: false,
            },
            "nan_data_raw"
            | "nan_data_raw_active"
            | "nan_data_multicast"
            | "nan_data_multicast_active" => Self {
                variant: variant.to_string(),
                include_freq: false,
                duration_ms: None,
                offchannel_tx_ok: false,
                dont_wait_for_ack: true,
                tx_no_cck_rate: false,
            },
            "roc" => Self {
                variant: variant.to_string(),
                include_freq: true,
                duration_ms: Some(tx_duration_ms.unwrap_or(10)),
                offchannel_tx_ok: true,
                dont_wait_for_ack: true,
                tx_no_cck_rate: false,
            },
            "pyroute2" => Self {
                variant: variant.to_string(),
                include_freq: true,
                duration_ms: Some(duration_ms),
                offchannel_tx_ok: false,
                dont_wait_for_ack: false,
                tx_no_cck_rate: false,
            },
            other => bail!(
                "unknown tx_variant {other:?}; expected standard, zero_duration, no_duration, no_offchannel, minimal, dont_wait_ack, dont_wait_no_duration, dont_wait_minimal, onchannel, onchannel_noack, action, send_action, dont_wait_no_cck, no_cck, no_freq, monitor, monitor_active, multicast_data, multicast_data_active, sta_multicast_llc, sta_multicast_llc_active, sta_direct_llc, sta_direct_llc_active, nan_data, nan_data_active, nan_data_raw, nan_data_raw_active, nan_data_multicast, nan_data_multicast_active, roc, or pyroute2"
            ),
        };
        Ok(options)
    }

    pub fn as_json(&self) -> Value {
        json!({
            "include_freq": self.include_freq,
            "duration_ms": self.duration_ms,
            "offchannel_tx_ok": self.offchannel_tx_ok,
            "dont_wait_for_ack": self.dont_wait_for_ack,
            "tx_no_cck_rate": self.tx_no_cck_rate,
        })
    }
}

pub fn build_dmesh_vendor_action_frame_with_bssid(
    destination: [u8; 6],
    source: [u8; 6],
    bssid: [u8; 6],
    payload: &[u8],
) -> Result<Vec<u8>> {
    crate::build_espnow_action_frame(destination, source, bssid, payload)
}

pub fn parse_wifi_ies(mut bytes: &[u8]) -> Vec<Value> {
    let mut ies = Vec::new();
    while bytes.len() >= 2 {
        let id = bytes[0];
        let len = bytes[1] as usize;
        bytes = &bytes[2..];
        if bytes.len() < len {
            ies.push(json!({
                "id": id,
                "name": wifi_ie_name(id),
                "truncated": true,
                "want_len": len,
                "remaining": bytes.len(),
            }));
            break;
        }
        let data = &bytes[..len];
        let mut value = json!({
            "id": id,
            "name": wifi_ie_name(id),
            "len": len,
            "hex": hex_bytes(data),
            "bytes": data.iter().map(|byte| json!(*byte)).collect::<Vec<_>>(),
        });
        if id == 0 {
            value["text"] = json!(String::from_utf8_lossy(data));
        }
        if id == 1 || id == 50 {
            value["rates_mbps"] = json!(
                data.iter()
                    .map(|rate| ((*rate & 0x7f) as f32) / 2.0)
                    .collect::<Vec<_>>()
            );
        }
        ies.push(value);
        bytes = &bytes[len..];
    }
    ies
}

pub fn wifi_ie_name(id: u8) -> &'static str {
    match id {
        0 => "ssid",
        1 => "supported_rates",
        3 => "ds_parameter_set",
        5 => "tim",
        42 => "erp",
        45 => "ht_capabilities",
        48 => "rsn",
        50 => "extended_supported_rates",
        61 => "ht_operation",
        127 => "extended_capabilities",
        221 => "vendor_specific",
        _ => "unknown",
    }
}

pub fn ieee80211_frame(packet: &[u8]) -> Option<&[u8]> {
    if packet.len() < IEEE80211_BODY {
        return None;
    }
    if let Some(radiotap_len) = radiotap_len(packet) {
        let frame = packet.get(radiotap_len..)?;
        return is_plausible_80211_frame(frame).then_some(strip_valid_fcs(frame));
    }
    if is_plausible_80211_frame(packet) {
        return Some(strip_valid_fcs(packet));
    }
    None
}

pub fn radiotap_len(packet: &[u8]) -> Option<usize> {
    if packet.len() < 8 || packet[0] != 0 {
        return None;
    }
    let len = u16::from_le_bytes([packet[2], packet[3]]) as usize;
    (len >= 8 && len < packet.len()).then_some(len)
}

pub fn is_plausible_80211_frame(frame: &[u8]) -> bool {
    if frame.len() < IEEE80211_BODY {
        return false;
    }
    matches!(frame_type(frame), 0..=2)
}

/// Monitor-mode captures commonly include the four-byte 802.11 FCS while
/// nl80211 action-frame events do not.  Keep the frame boundary consistent
/// before handing a vendor payload to the CBOR dispatcher.  Verify the CRC
/// instead of blindly dropping four bytes: injected frames and drivers that
/// suppress FCS must remain usable, and arbitrary payloads may legitimately
/// end in four bytes.
pub fn strip_valid_fcs(frame: &[u8]) -> &[u8] {
    if frame.len() <= IEEE80211_BODY + 4 {
        return frame;
    }
    let split = frame.len() - 4;
    let expected = u32::from_le_bytes([
        frame[split],
        frame[split + 1],
        frame[split + 2],
        frame[split + 3],
    ]);
    (crc32_ieee(&frame[..split]) == expected)
        .then_some(&frame[..split])
        .unwrap_or(frame)
}

pub fn crc32_ieee(bytes: &[u8]) -> u32 {
    let mut crc = 0xffff_ffff;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xedb8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

/// Return true for NAN beacons and NAN public action frames.  NAN uses the
/// Wi-Fi Alliance OUI in address3 (the cluster BSSID); ordinary AP beacons and
/// unrelated public actions must retain the caller/driver rate policy.
pub fn is_nan_control_frame(frame: &[u8]) -> bool {
    frame.len() >= 24
        && frame_type(frame) == 0
        && matches!(frame_subtype(frame), 8 | 13)
        && frame[16..19] == [0x50, 0x6f, 0x9a]
}

pub fn now_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

pub fn now_millis_u64() -> u64 {
    now_millis().min(u64::MAX as u128) as u64
}

pub fn now_micros_u64() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros()
        .min(u128::from(u64::MAX)) as u64
}

pub const RAW_ACTION_RESPONSE_REPETITIONS: usize = 1;

pub fn peer_availability_name(availability: crate::PeerAvailability) -> &'static str {
    match availability {
        crate::PeerAvailability::Infra => "infra",
        crate::PeerAvailability::Dw0Dw8 => "dw0_dw8",
    }
}
