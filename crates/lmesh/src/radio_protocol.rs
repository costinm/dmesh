use anyhow::{Result, bail};
use serde_json::{Value, json};
use std::collections::{HashMap, VecDeque};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

pub const DMESH_BLE_SERVICE_UUID16: u16 = 0xfd5d;
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

const NAN_ROLE_FIRMWARE_PUBLISHER: u8 = 1;
const NAN_ROLE_ANDROID_PUBLISHER: u8 = 2;

const NAN_MSG_HELLO: u8 = 1;
const NAN_MSG_WAKE_REQUEST: u8 = 2;
const NAN_MSG_PACKET_HINT: u8 = 3;
const NAN_MSG_PACKET_CHUNK: u8 = 4;
const NAN_MSG_ACK: u8 = 5;
const NAN_MSG_COMMAND_TEXT: u8 = 6;

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
    let pending = event.code();
    let battery = if snr_q4 > 0 {
        snr_q4.clamp(0, u8::MAX as i32) as u8
    } else {
        rssi.clamp(0, u8::MAX as i32) as u8
    };
    build_ble_esp32_service_data(source, fnv1a32(payload), pending, battery, payload)
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

pub fn parse_ble_service_data(data: &[u8], scan_rssi: i32, address: &str) -> Result<Value> {
    let (data, service_uuid) =
        if data.len() >= 12 && u16::from_le_bytes([data[0], data[1]]) == DMESH_BLE_SERVICE_UUID16 {
            (&data[2..], "fd5d")
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
    let pending = data[8];
    let battery = data[9];
    let prefix = &data[10..];
    let event = if pending > 0 {
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
        "connectable_response": pending > 0,
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
    let device_id = checked_device_id(device_id)?;
    let role = match role {
        "android" | "android_publisher" => NAN_ROLE_ANDROID_PUBLISHER,
        "firmware" | "firmware_publisher" => NAN_ROLE_FIRMWARE_PUBLISHER,
        _ => NAN_ROLE_ANDROID_PUBLISHER,
    };
    let mut out = Vec::with_capacity(21);
    out.extend_from_slice(&DMESH_MAGIC);
    out.push(DMESH_VERSION);
    out.push(role);
    out.push(0);
    out.extend_from_slice(device_id);
    out.extend_from_slice(&wake_count.to_le_bytes());
    out.extend_from_slice(&0_u16.to_le_bytes());
    out.extend_from_slice(&0_u32.to_le_bytes());
    Ok(out)
}

pub fn parse_nan_service_info(data: &[u8]) -> Result<Value> {
    if data.len() < 21 {
        bail!("DMesh NAN service info too short: {}", data.len());
    }
    if data[0..2] != DMESH_MAGIC || data[2] != DMESH_VERSION {
        bail!("not a DMesh NAN v1 service info payload");
    }
    let mut device_id = [0_u8; 6];
    device_id.copy_from_slice(&data[5..11]);
    let wake_count = u32::from_le_bytes([data[11], data[12], data[13], data[14]]);
    let last_len = u16::from_le_bytes([data[15], data[16]]);
    let last_hash = u32::from_le_bytes([data[17], data[18], data[19], data[20]]);
    Ok(json!({
        "protocol": "dmesh_nan_service",
        "version": DMESH_VERSION,
        "role": nan_role_name(data[3]),
        "role_code": data[3],
        "flags": data[4],
        "device_id": hex_bytes(&device_id),
        "wake_count": wake_count,
        "last_len": last_len,
        "last_hash": format!("0x{last_hash:08x}"),
        "last_hash_u32": last_hash,
    }))
}

pub fn build_nan_followup(
    msg_type: &str,
    device_id: &[u8],
    target_id: &[u8],
    payload: &[u8],
) -> Result<Vec<u8>> {
    let device_id = checked_device_id(device_id)?;
    let target_id = checked_device_id(target_id)?;
    let msg_type = nan_msg_type(msg_type);
    let payload_len = payload.len().min(231);
    let seq = next_nan_seq();
    let hash = fnv1a32(&payload[..payload_len]);
    let mut out = Vec::with_capacity(24 + payload_len);
    out.extend_from_slice(&DMESH_MAGIC);
    out.push(DMESH_VERSION);
    out.push(msg_type);
    out.extend_from_slice(&seq.to_le_bytes());
    out.extend_from_slice(device_id);
    out.extend_from_slice(target_id);
    out.extend_from_slice(&(payload_len as u16).to_le_bytes());
    out.extend_from_slice(&hash.to_le_bytes());
    out.extend_from_slice(&payload[..payload_len]);
    Ok(out)
}

pub fn parse_nan_followup(data: &[u8]) -> Result<Value> {
    if data.len() < 24 {
        bail!("DMesh NAN follow-up too short: {}", data.len());
    }
    if data[0..2] != DMESH_MAGIC || data[2] != DMESH_VERSION {
        bail!("not a DMesh NAN v1 follow-up payload");
    }
    let msg_type = data[3];
    let seq = u16::from_le_bytes([data[4], data[5]]);
    let mut device_id = [0_u8; 6];
    device_id.copy_from_slice(&data[6..12]);
    let mut target_id = [0_u8; 6];
    target_id.copy_from_slice(&data[12..18]);
    let payload_len = u16::from_le_bytes([data[18], data[19]]) as usize;
    let payload_hash = u32::from_le_bytes([data[20], data[21], data[22], data[23]]);
    let payload_end = 24 + payload_len.min(data.len().saturating_sub(24));
    let payload = &data[24..payload_end];
    let key = format!(
        "{}:{}:{}:{}",
        hex_bytes(&device_id),
        seq,
        msg_type,
        payload_hash
    );
    let duplicate = NAN_DEDUPE
        .get_or_init(|| Mutex::new(Dedupe::default()))
        .lock()
        .map(|mut dedupe| dedupe.check(key, NAN_DEDUPE_TTL))
        .unwrap_or(false);
    Ok(json!({
        "protocol": "dmesh_nan_followup",
        "version": DMESH_VERSION,
        "msg_type": nan_msg_name(msg_type),
        "msg_type_code": msg_type,
        "seq": seq,
        "device_id": hex_bytes(&device_id),
        "target_id": hex_bytes(&target_id),
        "payload_len": payload_len,
        "payload_hash": format!("0x{payload_hash:08x}"),
        "payload_hash_u32": payload_hash,
        "payload": hex_bytes(payload),
        "payload_text": String::from_utf8_lossy(payload),
        "duplicate": duplicate,
    }))
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
}
