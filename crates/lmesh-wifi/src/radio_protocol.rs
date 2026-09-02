//! Host-only protocol compatibility layer.
//!
//! NAN service-info/follow-up parsing is shared with host callers, while the
//! BLE service-data functions below are legacy Android/ESP compatibility
//! helpers. BLE is deliberately kept out of the firmware build by the
//! crate's `host` feature; it is not a dependency of the NAN radio core.

use anyhow::{Result, bail};
use dmesh_rawnan as rawnan;
use serde_json::{Value, json};
use std::collections::{HashMap, VecDeque};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

/// Temporary discovery identity: Bluetooth Internet Protocol Support Service.
/// This is intentionally an adopted-service interoperability experiment, not
/// a DMesh-assigned UUID; replace it once DMesh has a SIG allocation.
pub const DMESH_BLE_SERVICE_UUID16: u16 = 0x1820;
pub const DMESH_BLE_OPERATIONAL_UUID: [u8; 16] = [
    0x02, 0x00, 0x68, 0x73, 0x65, 0x4d, 0x42, 0x8c, 0x6f, 0x4a, 0x2a, 0x4f, 0x80, 0x6f, 0x6b, 0x5f,
];
const DMESH_MAGIC: [u8; 2] = *b"DM";
const DMESH_VERSION: u8 = 1;
const BLE_MAX_PREFIX: usize = 17;
const BLE_DEDUPE_TTL: Duration = Duration::from_secs(10);
const NAN_DEDUPE_TTL: Duration = Duration::from_secs(30);

const BLE_EVENT_GENERIC: u8 = 0;
const BLE_EVENT_LORA_RX: u8 = 1;
const BLE_EVENT_IDLE_HELLO: u8 = 2;
const BLE_EVENT_WAKE_REQUEST: u8 = 3;
const BLE_EVENT_PAYLOAD_PENDING: u8 = 4;
/// High bit in the ESP32 service-data pending byte.  Older firmware used the
/// whole byte as a queue count; v2 reserves the low seven bits for that count
/// and appends the explicit event byte after battery.
const BLE_ESP32_V2: u8 = 0x80;

const NAN_ROLE_FIRMWARE_PUBLISHER: u8 = 1;
const NAN_ROLE_ANDROID_PUBLISHER: u8 = 2;

const NAN_MSG_HELLO: u8 = 1;
const NAN_MSG_WAKE_REQUEST: u8 = 2;
const NAN_MSG_PACKET_HINT: u8 = 3;
const NAN_MSG_PACKET_CHUNK: u8 = 4;
const NAN_MSG_ACK: u8 = 5;
const NAN_MSG_COMMAND_TEXT: u8 = 6;
/// A complete framed tagged-CBOR control record.  Unlike `command_text`, its
/// payload is binary and must not be passed through a JSON/base64 gateway.
const NAN_MSG_COMMAND_CBOR: u8 = 7;

static BLE_DEDUPE: OnceLock<Mutex<Dedupe>> = OnceLock::new();
static NAN_DEDUPE: OnceLock<Mutex<Dedupe>> = OnceLock::new();
static NAN_SEQ: OnceLock<Mutex<u16>> = OnceLock::new();

#[derive(Default)]
struct Dedupe {
    order: VecDeque<(String, Instant)>,
    seen: HashMap<String, Instant>,
}

impl Dedupe {
    fn check(&mut self, key: String, ttl: Duration) -> bool {
        let now = Instant::now();
        while let Some((old_key, old_seen)) = self.order.front() {
            if now.duration_since(*old_seen) <= ttl {
                break;
            }
            let old_key = old_key.clone();
            self.order.pop_front();
            if self
                .seen
                .get(&old_key)
                .map(|seen| now.duration_since(*seen) > ttl)
                .unwrap_or(false)
            {
                self.seen.remove(&old_key);
            }
        }
        let duplicate = self
            .seen
            .get(&key)
            .map(|seen| now.duration_since(*seen) <= ttl)
            .unwrap_or(false);
        self.seen.insert(key.clone(), now);
        self.order.push_back((key, now));
        duplicate
    }
}

#[derive(Clone, Copy)]
pub enum BleEvent {
    Generic,
    LoraRx,
    IdleHello,
    WakeRequest,
    PayloadPending,
}

impl BleEvent {
    pub fn parse(value: &str) -> Self {
        match value {
            "lora" | "lora_rx" => Self::LoraRx,
            "idle" | "idle_hello" => Self::IdleHello,
            "wake" | "wake_request" => Self::WakeRequest,
            "pending" | "payload_pending" => Self::PayloadPending,
            _ => Self::Generic,
        }
    }

    fn from_code(code: u8) -> Self {
        match code {
            BLE_EVENT_LORA_RX => Self::LoraRx,
            BLE_EVENT_IDLE_HELLO => Self::IdleHello,
            BLE_EVENT_WAKE_REQUEST => Self::WakeRequest,
            BLE_EVENT_PAYLOAD_PENDING => Self::PayloadPending,
            _ => Self::Generic,
        }
    }

    fn code(self) -> u8 {
        match self {
            Self::Generic => BLE_EVENT_GENERIC,
            Self::LoraRx => BLE_EVENT_LORA_RX,
            Self::IdleHello => BLE_EVENT_IDLE_HELLO,
            Self::WakeRequest => BLE_EVENT_WAKE_REQUEST,
            Self::PayloadPending => BLE_EVENT_PAYLOAD_PENDING,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Generic => "generic",
            Self::LoraRx => "lora_rx",
            Self::IdleHello => "idle_hello",
            Self::WakeRequest => "wake_request",
            Self::PayloadPending => "payload_pending",
        }
    }
}

pub fn build_ble_service_data(
    event: BleEvent,
    device_id: &[u8],
    payload: &[u8],
    rssi: i32,
    snr_q4: i32,
) -> Result<Vec<u8>> {
    let device_id = checked_device_id(device_id)?;
    let source = u32::from_le_bytes([device_id[0], device_id[1], device_id[2], device_id[3]]);
    // The ESP32 layout historically overloaded `pending` with the event code.
    // Keep the queue count separate and put the event in its v2 extension.
    let pending = if matches!(event, BleEvent::PayloadPending | BleEvent::LoraRx) {
        1
    } else {
        0
    };
    let battery = if snr_q4 > 0 {
        snr_q4.clamp(0, u8::MAX as i32) as u8
    } else {
        rssi.clamp(0, u8::MAX as i32) as u8
    };
    build_ble_esp32_service_data_event(source, fnv1a32(payload), pending, battery, event, payload)
}

/// Build the current ESP32 DMesh BLE service-data layout.
pub fn build_ble_esp32_service_data(
    source: u32,
    packet_id: u32,
    pending: u8,
    battery: u8,
    packet: &[u8],
) -> Result<Vec<u8>> {
    let prefix_len = packet.len().min(BLE_MAX_PREFIX);
    let mut out = Vec::with_capacity(12 + prefix_len);
    out.extend_from_slice(&DMESH_BLE_SERVICE_UUID16.to_le_bytes());
    out.extend_from_slice(&source.to_le_bytes());
    out.extend_from_slice(&packet_id.to_le_bytes());
    out.push(pending);
    out.push(battery);
    out.extend_from_slice(&packet[..prefix_len]);
    Ok(out)
}

/// Build the v2 ESP32 service-data layout with an explicit rendezvous event.
/// The marker preserves parsing compatibility with pre-v2 advertisements.
pub fn build_ble_esp32_service_data_event(
    source: u32,
    packet_id: u32,
    pending: u8,
    battery: u8,
    event: BleEvent,
    packet: &[u8],
) -> Result<Vec<u8>> {
    let prefix_len = packet.len().min(BLE_MAX_PREFIX.saturating_sub(1));
    let mut out = Vec::with_capacity(13 + prefix_len);
    out.extend_from_slice(&DMESH_BLE_SERVICE_UUID16.to_le_bytes());
    out.extend_from_slice(&source.to_le_bytes());
    out.extend_from_slice(&packet_id.to_le_bytes());
    out.push(BLE_ESP32_V2 | pending.min(0x7f));
    out.push(battery);
    out.push(event.code());
    out.extend_from_slice(&packet[..prefix_len]);
    Ok(out)
}

pub fn parse_ble_service_data(data: &[u8], scan_rssi: i32, address: &str) -> Result<Value> {
    let (data, service_uuid) =
        if data.len() >= 12 && u16::from_le_bytes([data[0], data[1]]) == DMESH_BLE_SERVICE_UUID16 {
            (&data[2..], "1820")
        } else if data.len() >= 26 && data[..16] == DMESH_BLE_OPERATIONAL_UUID {
            (&data[16..], "5f6b6f80-4f2a-4a6f-8c42-4d6573680002")
        } else {
            (data, "unknown")
        };
    if data.len() >= 19 && data[0..2] == DMESH_MAGIC && data[2] == DMESH_VERSION {
        return parse_legacy_ble_service_data(data, scan_rssi, address);
    }
    if data.len() < 10 {
        bail!("DMesh BLE service data too short: {}", data.len());
    }
    let source = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let packet_id = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
    let encoded_pending = data[8];
    let v2 = encoded_pending & BLE_ESP32_V2 != 0 && data.len() >= 11;
    let pending = encoded_pending & !BLE_ESP32_V2;
    let battery = data[9];
    let prefix = if v2 { &data[11..] } else { &data[10..] };
    let event = if v2 {
        BleEvent::from_code(data[10])
    } else if pending > 0 {
        BleEvent::PayloadPending
    } else {
        BleEvent::IdleHello
    };
    let key = format!("{source:08x}:{packet_id:08x}");
    let duplicate = BLE_DEDUPE
        .get_or_init(|| Mutex::new(Dedupe::default()))
        .lock()
        .map(|mut dedupe| dedupe.check(key, BLE_DEDUPE_TTL))
        .unwrap_or(false);
    Ok(json!({
        "protocol": "dmesh_ble",
        "layout": "esp32_service_data",
        "service_uuid": service_uuid,
        "service_uuid16": format!("0x{:04x}", DMESH_BLE_SERVICE_UUID16),
        "mode": "operational",
        "event": event.name(),
        "event_code": event.code(),
        "src": source,
        "src_hex": format!("0x{source:08x}"),
        "packet_id": packet_id,
        "packet_id_hex": format!("0x{packet_id:08x}"),
        "pending": pending,
        "battery": battery,
        "prefix": hex_bytes(prefix),
        "scan_rssi": scan_rssi,
        "address": address,
        "duplicate": duplicate,
        "connectable_response": matches!(event, BleEvent::WakeRequest | BleEvent::PayloadPending | BleEvent::LoraRx),
    }))
}

fn parse_legacy_ble_service_data(data: &[u8], scan_rssi: i32, address: &str) -> Result<Value> {
    let event = BleEvent::from_code(data[4]);
    let mut device_id = [0_u8; 6];
    device_id.copy_from_slice(&data[5..11]);
    let payload_len = u16::from_le_bytes([data[11], data[12]]);
    let payload_hash = u32::from_le_bytes([data[13], data[14], data[15], data[16]]);
    let lora_rssi = data[17] as i8;
    let snr_q4 = data[18] as i8;
    let prefix = &data[19..];
    let key = format!(
        "{}:{}:{}:{}",
        hex_bytes(&device_id),
        event.code(),
        payload_len,
        payload_hash
    );
    let duplicate = BLE_DEDUPE
        .get_or_init(|| Mutex::new(Dedupe::default()))
        .lock()
        .map(|mut dedupe| dedupe.check(key, BLE_DEDUPE_TTL))
        .unwrap_or(false);
    Ok(json!({
        "protocol": "dmesh_ble",
        "layout": "legacy_dm_v1",
        "version": DMESH_VERSION,
        "event": event.name(),
        "event_code": event.code(),
        "device_id": hex_bytes(&device_id),
        "payload_len": payload_len,
        "payload_hash": format!("0x{payload_hash:08x}"),
        "payload_hash_u32": payload_hash,
        "rssi": lora_rssi,
        "snr_q4": snr_q4,
        "snr": (snr_q4 as f32) / 4.0,
        "prefix": hex_bytes(prefix),
        "scan_rssi": scan_rssi,
        "address": address,
        "duplicate": duplicate,
        "connectable_response": matches!(event, BleEvent::WakeRequest | BleEvent::PayloadPending),
    }))
}

pub fn build_nan_service_info(role: &str, device_id: &[u8], wake_count: u32) -> Result<Vec<u8>> {
    let device_id: [u8; 6] = checked_device_id(device_id)?
        .try_into()
        .expect("checked id");
    let role = match role {
        "firmware" | "firmware_publisher" => NAN_ROLE_FIRMWARE_PUBLISHER,
        _ => NAN_ROLE_ANDROID_PUBLISHER,
    };
    let mut info = rawnan::build_dmesh_service_info(device_id, role, None).to_vec();
    info[11..15].copy_from_slice(&wake_count.to_le_bytes());
    Ok(info)
}

pub fn parse_nan_service_info(data: &[u8]) -> Result<Value> {
    let info = rawnan::parse_dmesh_service_info(data)
        .ok_or_else(|| anyhow::anyhow!("not a DMesh NAN service info payload"))?;
    Ok(
        json!({"protocol":"dmesh_nan_service","role":nan_role_name(info.role),"role_code":info.role,"flags":info.flags,"device_id":hex_bytes(&info.device_id),"wake_count":info.wake_target,"last_len":info.wake_duration_ms}),
    )
}

pub fn build_nan_followup(
    msg_type: &str,
    device_id: &[u8],
    target_id: &[u8],
    payload: &[u8],
) -> Result<Vec<u8>> {
    let source: [u8; 6] = checked_device_id(device_id)?
        .try_into()
        .expect("checked id");
    let target: [u8; 6] = checked_device_id(target_id)?
        .try_into()
        .expect("checked id");
    rawnan::build_dmesh_followup_payload(
        nan_msg_type(msg_type),
        next_nan_seq(),
        source,
        target,
        &payload[..payload.len().min(231)],
    )
}

pub fn parse_nan_followup(data: &[u8]) -> Result<Value> {
    let followup = rawnan::parse_dmesh_nan_followup(data)
        .ok_or_else(|| anyhow::anyhow!("not a DMesh NAN follow-up payload"))?;
    Ok(
        json!({"protocol":"dmesh_nan_followup","msg_type":nan_msg_name(followup.msg_type),"msg_type_code":followup.msg_type,"seq":followup.seq,"device_id":hex_bytes(&followup.device_id),"target_id":hex_bytes(&followup.target_id),"payload_len":followup.payload.len(),"payload":hex_bytes(followup.payload),"payload_text":String::from_utf8_lossy(followup.payload)}),
    )
}

fn checked_device_id(value: &[u8]) -> Result<&[u8]> {
    if value.len() != 6 {
        bail!("device_id must be exactly 6 bytes, got {}", value.len());
    }
    Ok(value)
}

fn next_nan_seq() -> u16 {
    let mut seq = NAN_SEQ
        .get_or_init(|| Mutex::new(1))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let out = *seq;
    *seq = seq.wrapping_add(1).max(1);
    out
}

fn nan_role_name(role: u8) -> &'static str {
    match role {
        NAN_ROLE_FIRMWARE_PUBLISHER => "firmware_publisher",
        NAN_ROLE_ANDROID_PUBLISHER => "android_publisher",
        _ => "unknown",
    }
}

fn nan_msg_type(value: &str) -> u8 {
    match value {
        "hello" => NAN_MSG_HELLO,
        "wake" | "wake_request" => NAN_MSG_WAKE_REQUEST,
        "hint" | "packet_hint" => NAN_MSG_PACKET_HINT,
        "chunk" | "packet_chunk" => NAN_MSG_PACKET_CHUNK,
        "ack" => NAN_MSG_ACK,
        "command" | "command_text" => NAN_MSG_COMMAND_TEXT,
        "command_cbor" => NAN_MSG_COMMAND_CBOR,
        _ => NAN_MSG_HELLO,
    }
}

fn nan_msg_name(msg_type: u8) -> &'static str {
    match msg_type {
        NAN_MSG_HELLO => "hello",
        NAN_MSG_WAKE_REQUEST => "wake_request",
        NAN_MSG_PACKET_HINT => "packet_hint",
        NAN_MSG_PACKET_CHUNK => "packet_chunk",
        NAN_MSG_ACK => "ack",
        NAN_MSG_COMMAND_TEXT => "command_text",
        NAN_MSG_COMMAND_CBOR => "command_cbor",
        _ => "unknown",
    }
}

fn fnv1a32(bytes: &[u8]) -> u32 {
    bytes.iter().fold(0x811c_9dc5_u32, |acc, byte| {
        acc.wrapping_mul(16777619) ^ *byte as u32
    })
}

fn hex_bytes(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join("")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ble_service_data_round_trips() {
        let data = build_ble_esp32_service_data(0x11223344, 0xaabbccdd, 2, 91, b"abcdef").unwrap();
        assert_eq!(
            u16::from_le_bytes([data[0], data[1]]),
            DMESH_BLE_SERVICE_UUID16
        );
        assert_eq!(data.len(), 18);
        let parsed = parse_ble_service_data(&data, -62, "aa:bb").unwrap();
        assert_eq!(parsed["layout"], "esp32_service_data");
        assert_eq!(parsed["src"], 0x11223344_u32);
        assert_eq!(parsed["packet_id"], 0xaabbccdd_u32);
        assert_eq!(parsed["pending"], 2);
        assert_eq!(parsed["battery"], 91);
        assert_eq!(parsed["prefix"], "616263646566");
    }

    #[test]
    fn nan_service_info_round_trips() {
        let id = [9, 8, 7, 6, 5, 4];
        let data = build_nan_service_info("android", &id, 42).unwrap();
        let parsed = parse_nan_service_info(&data).unwrap();
        assert_eq!(parsed["role"], "android_publisher");
        assert_eq!(parsed["device_id"], "090807060504");
        assert_eq!(parsed["wake_count"], 42);
    }

    #[test]
    fn nan_followup_round_trips() {
        let id = [1, 1, 1, 1, 1, 1];
        let target = [2, 2, 2, 2, 2, 2];
        let data = build_nan_followup("command_text", &id, &target, b"ble stats=true").unwrap();
        let parsed = parse_nan_followup(&data).unwrap();
        assert_eq!(parsed["msg_type"], "command_text");
        assert_eq!(parsed["device_id"], "010101010101");
        assert_eq!(parsed["target_id"], "020202020202");
        assert_eq!(parsed["payload_text"], "ble stats=true");
    }

    #[test]
    fn nan_followup_preserves_tagged_cbor_bytes() {
        let source = [1, 1, 1, 1, 1, 1];
        let target = [2, 2, 2, 2, 2, 2];
        let tagged = [
            0xa4, 1, 4, 2, 8, 9, 0x46, 2, 2, 2, 2, 2, 2, 10, 0x42, 0, 0xff,
        ];
        let data = build_nan_followup("command_cbor", &source, &target, &tagged).unwrap();
        let parsed = parse_nan_followup(&data).unwrap();
        assert_eq!(parsed["msg_type"], "command_cbor");
        assert_eq!(parsed["payload"], "a40104020809460202020202020a4200ff");
    }
}
