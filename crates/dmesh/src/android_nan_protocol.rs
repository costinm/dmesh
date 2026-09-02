//! Android JSON/JNI projection of the shared `dmesh-rawnan` wire codec.
//!
//! This module contains no Linux radio ownership or lifecycle code. Android
//! uses the same raw NAN bytes as ESP and Linux, then projects decoded fields
//! to JSON only at its JNI boundary.

use anyhow::Result;
use serde_json::{Value, json};
use std::sync::atomic::{AtomicU16, Ordering};

const NAN_ROLE_FIRMWARE_PUBLISHER: u8 = 1;
const NAN_ROLE_ANDROID_PUBLISHER: u8 = 2;

const NAN_MSG_HELLO: u8 = 1;
const NAN_MSG_WAKE_REQUEST: u8 = 2;
const NAN_MSG_PACKET_HINT: u8 = 3;
const NAN_MSG_PACKET_CHUNK: u8 = 4;
const NAN_MSG_ACK: u8 = 5;
const NAN_MSG_COMMAND_TEXT: u8 = 6;
const NAN_MSG_COMMAND_CBOR: u8 = 7;

static NAN_SEQUENCE: AtomicU16 = AtomicU16::new(1);

pub fn build_nan_service_info(role: &str, device_id: &[u8], wake_count: u32) -> Result<Vec<u8>> {
    let device_id = checked_device_id(device_id)?;
    let role = match role {
        "firmware" | "firmware_publisher" => NAN_ROLE_FIRMWARE_PUBLISHER,
        _ => NAN_ROLE_ANDROID_PUBLISHER,
    };
    let mut info = dmesh_rawnan::build_dmesh_service_info(device_id, role, None).to_vec();
    info[11..15].copy_from_slice(&wake_count.to_le_bytes());
    Ok(info)
}

pub fn parse_nan_service_info(data: &[u8]) -> Result<Value> {
    let info = dmesh_rawnan::parse_dmesh_service_info(data)
        .ok_or_else(|| anyhow::anyhow!("not a DMesh NAN service info payload"))?;
    Ok(json!({
        "protocol": "dmesh_nan_service",
        "role": nan_role_name(info.role),
        "role_code": info.role,
        "flags": info.flags,
        "device_id": hex_bytes(&info.device_id),
        "wake_count": info.wake_target,
        "last_len": info.wake_duration_ms,
    }))
}

pub fn build_nan_followup(
    msg_type: &str,
    device_id: &[u8],
    target_id: &[u8],
    payload: &[u8],
) -> Result<Vec<u8>> {
    let sequence = NAN_SEQUENCE.fetch_add(1, Ordering::Relaxed).max(1);
    dmesh_rawnan::build_dmesh_followup_payload(
        nan_msg_type(msg_type),
        sequence,
        checked_device_id(device_id)?,
        checked_device_id(target_id)?,
        &payload[..payload.len().min(dmesh_rawnan::NAN_COMMAND_MAX_LEN)],
    )
    .map_err(anyhow::Error::msg)
}

pub fn parse_nan_followup(data: &[u8]) -> Result<Value> {
    let followup = dmesh_rawnan::parse_dmesh_nan_followup(data)
        .ok_or_else(|| anyhow::anyhow!("not a DMesh NAN follow-up payload"))?;
    Ok(json!({
        "protocol": "dmesh_nan_followup",
        "msg_type": nan_msg_name(followup.msg_type),
        "msg_type_code": followup.msg_type,
        "seq": followup.seq,
        "device_id": hex_bytes(&followup.device_id),
        "target_id": hex_bytes(&followup.target_id),
        "payload_len": followup.payload.len(),
        "payload": hex_bytes(followup.payload),
        "payload_text": String::from_utf8_lossy(followup.payload),
    }))
}

fn checked_device_id(value: &[u8]) -> Result<[u8; 6]> {
    value
        .try_into()
        .map_err(|_| anyhow::anyhow!("device_id must be exactly 6 bytes, got {}", value.len()))
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

fn hex_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
