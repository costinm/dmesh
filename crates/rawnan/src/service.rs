//! Generic NAN service state and the DMesh service contract shared by firmware,
//! Linux, Android JNI, recovery, and other adapters.
//!
//! This module has no radio-driver or transport dependencies. It contains the
//! bounded receipt records used by debug services and higher-level dispatch;
//! adapters decide how to queue, render, or act on them. CBOR command payloads
//! remain opaque here; this module only carries them through NAN SDF/follow-up
//! frames and exposes bounded service receipts.

use crate::{
    fnv1a32, DMESH_MAGIC, DMESH_NAN_FOLLOWUP_HEADER_LEN, DMESH_VERSION, NAN_COMMAND_MAX_LEN,
    NAN_SDEA_SERVICE_UPDATE_CONTROL, NAN_SERVICE_FLAG_ACTIVE_ACK, NAN_SERVICE_FLAG_BLE_WAKE,
    NAN_SERVICE_FLAG_UART_WAKE, NAN_SERVICE_INFO_LEN,
};
use alloc::{collections::VecDeque, vec::Vec};
use anyhow::{bail, Result};

/// Build the USD active-subscribe/publish service-discovery frame. Service
/// information is opaque and may contain a CBOR command envelope.
pub fn build_nan_usd_sdf(
    destination: [u8; 6],
    source: [u8; 6],
    service_id: [u8; 6],
    instance_id: u8,
    control: u8,
    service_info: &[u8],
) -> Vec<u8> {
    let info_len = service_info.len().min(231);
    let mut frame = Vec::with_capacity(24 + 6 + 3 + 9 + 3 + 9 + info_len);
    frame.extend_from_slice(&[0xd0, 0x00, 0x00, 0x00]);
    frame.extend_from_slice(&destination);
    frame.extend_from_slice(&source);
    frame.extend_from_slice(&[0xff; 6]);
    frame.extend_from_slice(&[0x00, 0x00, 0x04, 0x09, 0x50, 0x6f, 0x9a, 0x13]);
    frame.push(0x03);
    frame.extend_from_slice(&9_u16.to_le_bytes());
    frame.extend_from_slice(&service_id);
    frame.extend_from_slice(&[instance_id, 0, control]);
    frame.push(0x0e);
    frame.extend_from_slice(&((9 + info_len) as u16).to_le_bytes());
    frame.extend_from_slice(&[instance_id, 0, 0, 0, 4]);
    frame.extend_from_slice(&((4 + info_len) as u16).to_le_bytes());
    frame.extend_from_slice(&[0x50, 0x6f, 0x9a, 0x00]);
    frame.extend_from_slice(&service_info[..info_len]);
    frame
}

pub fn build_nan_publish_sdf(
    destination: [u8; 6],
    source: [u8; 6],
    cluster_bssid: [u8; 6],
    service_id: [u8; 6],
    instance_id: u8,
    service_info: &[u8],
) -> Vec<u8> {
    build_nan_publish_sdf_with_sdea(
        destination,
        source,
        cluster_bssid,
        service_id,
        instance_id,
        service_info,
        None,
    )
}

pub fn build_nan_publish_sdf_with_sdea(
    destination: [u8; 6],
    source: [u8; 6],
    cluster_bssid: [u8; 6],
    service_id: [u8; 6],
    instance_id: u8,
    service_info: &[u8],
    sdea_update: Option<u8>,
) -> Vec<u8> {
    let info_len = service_info.len().min(255);
    let sdea_len = usize::from(sdea_update.is_some()) * 7;
    let descriptor_len = 6 + 4 + info_len + sdea_len;
    let mut frame = Vec::with_capacity(30 + 3 + descriptor_len);
    frame.extend_from_slice(&[0xd0, 0x00, 0x00, 0x00]);
    frame.extend_from_slice(&destination);
    frame.extend_from_slice(&source);
    frame.extend_from_slice(&cluster_bssid);
    frame.extend_from_slice(&[0x00, 0x00, 0x04, 0x09, 0x50, 0x6f, 0x9a, 0x13]);
    frame.push(0x03);
    frame.extend_from_slice(&(descriptor_len as u16).to_le_bytes());
    frame.extend_from_slice(&service_id);
    frame.extend_from_slice(&[instance_id, 0, 0x10, info_len as u8]);
    frame.extend_from_slice(&service_info[..info_len]);
    if let Some(update) = sdea_update {
        frame.extend_from_slice(&[
            0x0e,
            0x04,
            0x00,
            instance_id,
            NAN_SDEA_SERVICE_UPDATE_CONTROL[0],
            NAN_SDEA_SERVICE_UPDATE_CONTROL[1],
            update,
        ]);
    }
    frame
}

pub fn build_nan_service_extension(service_update: u8) -> [u8; 7] {
    [
        0x0e,
        0x04,
        0x00,
        1,
        NAN_SDEA_SERVICE_UPDATE_CONTROL[0],
        NAN_SDEA_SERVICE_UPDATE_CONTROL[1],
        service_update,
    ]
}

pub fn build_dmesh_service_info(
    device_id: [u8; 6],
    role: u8,
    wake: Option<(u32, u16, u8)>,
) -> [u8; NAN_SERVICE_INFO_LEN] {
    let mut info = [0; NAN_SERVICE_INFO_LEN];
    info[..2].copy_from_slice(&DMESH_MAGIC);
    info[2] = DMESH_VERSION;
    info[3] = role;
    info[5..11].copy_from_slice(&device_id);
    if let Some((target, duration_ms, flags)) = wake {
        info[4] = flags
            & (NAN_SERVICE_FLAG_UART_WAKE
                | NAN_SERVICE_FLAG_BLE_WAKE
                | NAN_SERVICE_FLAG_ACTIVE_ACK);
        info[11..15].copy_from_slice(&target.to_le_bytes());
        info[15..17].copy_from_slice(&duration_ms.to_le_bytes());
    }
    info
}

pub fn build_dmesh_followup_payload(
    msg_type: u8,
    seq: u16,
    device_id: [u8; 6],
    target_id: [u8; 6],
    payload: &[u8],
) -> Result<Vec<u8>> {
    if payload.len() > NAN_COMMAND_MAX_LEN {
        bail!("DMesh NAN payload exceeds {NAN_COMMAND_MAX_LEN} bytes");
    }
    let mut out = Vec::with_capacity(DMESH_NAN_FOLLOWUP_HEADER_LEN + payload.len());
    out.extend_from_slice(&DMESH_MAGIC);
    out.extend_from_slice(&[DMESH_VERSION, msg_type]);
    out.extend_from_slice(&seq.to_le_bytes());
    out.extend_from_slice(&device_id);
    out.extend_from_slice(&target_id);
    out.extend_from_slice(&(payload.len() as u16).to_le_bytes());
    out.extend_from_slice(&fnv1a32(payload).to_le_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

pub fn build_nan_followup_sdf(
    destination: [u8; 6],
    source: [u8; 6],
    cluster_bssid: [u8; 6],
    service_id: [u8; 6],
    instance_id: u8,
    payload: &[u8],
) -> Vec<u8> {
    let len = payload.len().min(255);
    let mut frame = Vec::with_capacity(30 + 3 + 10 + len);
    frame.extend_from_slice(&[0xd0, 0x00, 0x00, 0x00]);
    frame.extend_from_slice(&destination);
    frame.extend_from_slice(&source);
    frame.extend_from_slice(&cluster_bssid);
    frame.extend_from_slice(&[0x00, 0x00, 0x04, 0x09, 0x50, 0x6f, 0x9a, 0x13]);
    frame.push(0x03);
    frame.extend_from_slice(&((10 + len) as u16).to_le_bytes());
    frame.extend_from_slice(&service_id);
    frame.extend_from_slice(&[instance_id, 0, 0x12, len as u8]);
    frame.extend_from_slice(&payload[..len]);
    frame
}

pub fn parse_dmesh_nan_followup(data: &[u8]) -> Option<DmeshNanFollowup<'_>> {
    if data.len() < DMESH_NAN_FOLLOWUP_HEADER_LEN
        || data[..2] != DMESH_MAGIC
        || data[2] != DMESH_VERSION
    {
        return None;
    }
    let mut device_id = [0; 6];
    device_id.copy_from_slice(&data[6..12]);
    let mut target_id = [0; 6];
    target_id.copy_from_slice(&data[12..18]);
    let len = u16::from_le_bytes([data[18], data[19]]) as usize;
    let end = DMESH_NAN_FOLLOWUP_HEADER_LEN.checked_add(len)?;
    Some(DmeshNanFollowup {
        msg_type: data[3],
        seq: u16::from_le_bytes([data[4], data[5]]),
        device_id,
        target_id,
        payload: data.get(DMESH_NAN_FOLLOWUP_HEADER_LEN..end)?,
    })
}

pub fn is_dmesh_service_info(data: &[u8]) -> bool {
    data.len() == NAN_SERVICE_INFO_LEN && data[..2] == DMESH_MAGIC && data[2] == DMESH_VERSION
}
pub fn wake_request_for_service(data: &[u8]) -> Option<(u32, u8)> {
    if !is_dmesh_service_info(data)
        || data[4] & (NAN_SERVICE_FLAG_UART_WAKE | NAN_SERVICE_FLAG_BLE_WAKE) == 0
    {
        return None;
    }
    Some((
        (u16::from_le_bytes(data[15..17].try_into().ok()?) as u32).clamp(1_000, 300_000),
        data[4],
    ))
}
pub fn active_ack_for_service(data: &[u8]) -> Option<(u32, u16)> {
    if !is_dmesh_service_info(data) || data[4] & NAN_SERVICE_FLAG_ACTIVE_ACK == 0 {
        return None;
    }
    Some((
        u32::from_be_bytes(data[5..9].try_into().ok()?),
        u16::from_le_bytes(data[15..17].try_into().ok()?),
    ))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceReceipt {
    pub local_us: u64,
    pub source: [u8; 6],
    pub device_id: [u8; 6],
    pub instance: u8,
    pub kind: u8,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FollowupReceipt {
    pub local_us: u64,
    pub tsf_us: u64,
    pub msg_type: u8,
    pub seq: u16,
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResponseReceipt {
    pub local_us: u64,
    pub source: [u8; 6],
    pub payload: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DmeshNanFollowup<'a> {
    pub msg_type: u8,
    pub seq: u16,
    pub device_id: [u8; 6],
    pub target_id: [u8; 6],
    pub payload: &'a [u8],
}

/// Fixed DMesh service advertisement. Follow-up payloads carry CBOR service
/// commands and responses, including active-window, object-store, AP, SSID,
/// and IP information without coupling this crate to a particular transport.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DmeshServiceInfo {
    pub role: u8,
    pub flags: u8,
    pub device_id: [u8; 6],
    pub wake_target: u32,
    pub wake_duration_ms: u16,
}

pub fn parse_dmesh_service_info(data: &[u8]) -> Option<DmeshServiceInfo> {
    if !is_dmesh_service_info(data) {
        return None;
    }
    let mut device_id = [0; 6];
    device_id.copy_from_slice(&data[5..11]);
    Some(DmeshServiceInfo {
        role: data[3],
        flags: data[4],
        device_id,
        wake_target: u32::from_le_bytes(data[11..15].try_into().ok()?),
        wake_duration_ms: u16::from_le_bytes(data[15..17].try_into().ok()?),
    })
}

/// Bounded duplicate filter for DMesh follow-ups. The key is protocol-level,
/// not transport-level, so monitor, native NAN, and ESP adapters can apply the
/// same rule before dispatching a service callback.
#[derive(Debug)]
pub struct FollowupDedup {
    capacity: usize,
    order: VecDeque<([u8; 6], u16, u8, u32)>,
}

impl FollowupDedup {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            order: VecDeque::new(),
        }
    }

    pub fn is_duplicate(
        &mut self,
        device_id: [u8; 6],
        seq: u16,
        msg_type: u8,
        payload: &[u8],
    ) -> bool {
        let key = (device_id, seq, msg_type, crate::fnv1a32(payload));
        if self.order.contains(&key) {
            return true;
        }
        self.order.push_back(key);
        while self.order.len() > self.capacity {
            self.order.pop_front();
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dmesh_service_info_round_trips_and_preserves_wake_contract() {
        let info = build_dmesh_service_info(
            [1, 2, 3, 4, 5, 6],
            2,
            Some((0x1122_3344, 4_000, NAN_SERVICE_FLAG_ACTIVE_ACK)),
        );
        let parsed = parse_dmesh_service_info(&info).unwrap();
        assert_eq!(parsed.device_id, [1, 2, 3, 4, 5, 6]);
        assert_eq!(parsed.role, 2);
        assert_eq!(parsed.wake_target, 0x1122_3344);
        assert_eq!(parsed.wake_duration_ms, 4_000);
        assert_eq!(active_ack_for_service(&info), Some((0x0102_0304, 4_000)));
    }
}
