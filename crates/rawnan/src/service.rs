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

/// Maximum Service Info carried by a NAN Publish service descriptor.
pub const NAN_ACTIVE_PUBLISH_MAX_LEN: usize = 255;
/// Presence should refresh slowly; a new configuration is sent at the next
/// confirmed DW, while steady state uses this cadence.
pub const NAN_ACTIVE_PUBLISH_INTERVAL_MS: u64 = 15 * 60 * 1_000;

/// Driver-independent state for an active NAN Publish descriptor.
///
/// Adapters retain only this bounded CBOR Service Info and ask [`due`] from a
/// confirmed discovery window. They build the 802.11 frame with their current
/// MAC/BSSID immediately before transmission, so a stale radio context is
/// never preserved across an association or cluster change.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NanActivePublish {
    enabled: bool,
    instance: u8,
    service_info: Vec<u8>,
    pending: bool,
    last_sent_ms: Option<u64>,
}

impl Default for NanActivePublish {
    fn default() -> Self {
        Self::new(1)
    }
}

impl NanActivePublish {
    pub const fn new(instance: u8) -> Self {
        Self {
            enabled: false,
            instance,
            service_info: Vec::new(),
            pending: false,
            last_sent_ms: None,
        }
    }

    /// Replace the entire publish configuration. An enabled update is due in
    /// the next DW even if the ordinary refresh interval has not elapsed.
    pub fn configure(&mut self, enabled: bool, service_info: &[u8]) -> Result<()> {
        if service_info.len() > NAN_ACTIVE_PUBLISH_MAX_LEN {
            bail!("NAN active Publish Service Info exceeds {NAN_ACTIVE_PUBLISH_MAX_LEN} bytes");
        }
        if enabled && service_info.is_empty() {
            bail!("enabled NAN active Publish requires Service Info");
        }
        self.enabled = enabled;
        self.service_info.clear();
        self.service_info.extend_from_slice(service_info);
        self.pending = enabled;
        if !enabled {
            self.last_sent_ms = None;
        }
        Ok(())
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }
    pub fn instance(&self) -> u8 {
        self.instance
    }
    pub fn service_info(&self) -> &[u8] {
        &self.service_info
    }
    pub fn pending(&self) -> bool {
        self.pending
    }
    pub fn last_sent_ms(&self) -> Option<u64> {
        self.last_sent_ms
    }

    /// Return the current payload only when a caller has confirmed an open DW.
    pub fn due(&self, now_ms: u64) -> Option<&[u8]> {
        (self.enabled
            && !self.service_info.is_empty()
            && (self.pending
                || self.last_sent_ms.is_none_or(|last| {
                    now_ms.saturating_sub(last) >= NAN_ACTIVE_PUBLISH_INTERVAL_MS
                })))
        .then_some(self.service_info())
    }

    pub fn mark_sent(&mut self, now_ms: u64) {
        self.pending = false;
        self.last_sent_ms = Some(now_ms);
    }
}

/// A copied NAN follow-up transmission intent.
///
/// This is deliberately not an 802.11 frame: policy can safely retain it
/// until a confirmed discovery window, and each radio adapter builds the
/// frame immediately before submission using its current local MAC/BSSID.
/// The type is shared by host control code and embedded adapters; it never
/// borrows a driver buffer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NanFollowupIntent {
    pub destination: [u8; 6],
    pub instance: u8,
    pub payload: Vec<u8>,
    pub queued_at_us: u64,
}

/// Result of adding an intent to a bounded NAN follow-up queue.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NanFollowupEnqueue {
    Queued,
    ReplacedOldest,
    Duplicate,
}

/// Portable bounded intent policy for DW-gated NAN follow-ups.
///
/// Callers enqueue outside a confirmed DW and take a small batch after their
/// own beacon/timing adapter confirms the window is open. Keeping this policy
/// here prevents host and firmware from developing incompatible retry or
/// deduplication behavior; driver callbacks and radio submission remain in
/// their respective adapters.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NanFollowupQueue {
    capacity: usize,
    intents: VecDeque<NanFollowupIntent>,
}

impl Default for NanFollowupQueue {
    fn default() -> Self {
        // The default is deliberately small and matches the host radio
        // service. Production adapters may choose a tighter bound explicitly.
        Self::new(32)
    }
}

impl NanFollowupQueue {
    /// A zero-capacity queue would silently discard a valid control response,
    /// so callers must select a small positive bound explicitly.
    pub fn new(capacity: usize) -> Self {
        assert!(
            capacity != 0,
            "NAN follow-up queue capacity must be nonzero"
        );
        Self {
            capacity,
            intents: VecDeque::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.intents.len()
    }

    pub fn is_empty(&self) -> bool {
        self.intents.is_empty()
    }

    /// Deduplicate an identical target/instance/payload. When full, replace
    /// the oldest intent: callers get bounded memory and their higher layer
    /// can observe the replacement rather than waiting forever.
    pub fn enqueue(&mut self, intent: NanFollowupIntent) -> NanFollowupEnqueue {
        if self.intents.iter().any(|item| {
            item.destination == intent.destination
                && item.instance == intent.instance
                && item.payload == intent.payload
        }) {
            return NanFollowupEnqueue::Duplicate;
        }
        let replaced = self.intents.len() == self.capacity;
        if replaced {
            self.intents.pop_front();
        }
        self.intents.push_back(intent);
        if replaced {
            NanFollowupEnqueue::ReplacedOldest
        } else {
            NanFollowupEnqueue::Queued
        }
    }

    /// Take at most `limit` intents for a currently confirmed DW. The caller
    /// owns the DW check and attempts transmission; failed submissions are
    /// intentionally observable at that adapter boundary rather than being
    /// silently requeued with stale radio context.
    pub fn take_up_to(&mut self, limit: usize) -> Vec<NanFollowupIntent> {
        let count = limit.min(self.intents.len());
        self.intents.drain(..count).collect()
    }
}

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
    let mut frame = Vec::with_capacity(24 + 6 + 3 + 9 + 3 + 11 + info_len);
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
    // SDEA body: instance/requestor/control (5), service-info length (2),
    // WFA OUI/type (4), then the opaque Service Info.
    frame.extend_from_slice(&((11 + info_len) as u16).to_le_bytes());
    frame.extend_from_slice(&[instance_id, 0, 0, 0, 4]);
    frame.extend_from_slice(&((4 + info_len) as u16).to_le_bytes());
    frame.extend_from_slice(&[0x50, 0x6f, 0x9a, 0x00]);
    frame.extend_from_slice(&service_info[..info_len]);
    frame
}

/// A complete active-Subscribe Service Info record recovered from the
/// Subscribe SDA plus its following SDEA. NAN puts Subscribe SSI in SDEA,
/// not in the SDA payload, so generic descriptor inspection intentionally
/// reports an empty payload for this form.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActiveSubscribeServiceInfo<'a> {
    pub instance: u8,
    pub requestor_instance: u8,
    pub service_info: &'a [u8],
}

/// Recover the bounded custom Service Info from an active Subscribe SDF.
///
/// The parser accepts only a matching service ID, control `0x11`, and a SDEA
/// with the same instance. Malformed or unrelated attributes are ignored.
pub fn active_subscribe_service_info<'a>(
    frame: &'a [u8],
    service_id: [u8; 6],
) -> Option<ActiveSubscribeServiceInfo<'a>> {
    if !crate::is_nan_sdf(frame) {
        return None;
    }
    let mut subscribe = None;
    let mut offset = crate::NAN_ACTION_START;
    while offset + 3 <= frame.len() {
        let attr_id = frame[offset];
        let len = u16::from_le_bytes([frame[offset + 1], frame[offset + 2]]) as usize;
        let body_start = offset + 3;
        let body_end = body_start.checked_add(len)?;
        let body = frame.get(body_start..body_end)?;
        if attr_id == 0x03 && body.len() == 9 && body[..6] == service_id && body[8] == 0x11 {
            subscribe = Some((body[6], body[7]));
        } else if attr_id == 0x0e {
            if let Some((instance, requestor_instance)) = subscribe {
                // Attribute body emitted by `build_nan_usd_sdf`:
                // instance, requestor, control(3), info_len(2), OUI/type(4), SI.
                if body.len() >= 11 && body[0] == instance && body[1] == requestor_instance {
                    // The SDEA Service Info length includes its four-byte
                    // WFA OUI/type prefix; the returned SSI excludes it.
                    let info_len =
                        (u16::from_le_bytes([body[5], body[6]]) as usize).checked_sub(4)?;
                    let info_start = 11usize;
                    let info_end = info_start.checked_add(info_len)?;
                    if body.get(7..11) == Some(&[0x50, 0x6f, 0x9a, 0x00]) {
                        return Some(ActiveSubscribeServiceInfo {
                            instance,
                            requestor_instance,
                            service_info: body.get(info_start..info_end)?,
                        });
                    }
                }
            }
        }
        offset = body_end;
    }
    None
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
    use alloc::vec;

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

    #[test]
    fn active_subscribe_recovers_custom_sdea_service_info() {
        let service_id = [7, 8, 9, 10, 11, 12];
        let custom = [0xa1, 0x01, 0x01];
        let frame = build_nan_usd_sdf(
            crate::NAN_DISCOVERY_MAC,
            [1, 2, 3, 4, 5, 6],
            service_id,
            9,
            0x11,
            &custom,
        );
        let descriptor = crate::service_descriptor(&frame, service_id).unwrap();
        assert_eq!(descriptor.control, 0x11);
        assert!(descriptor.payload.is_empty());
        assert_eq!(
            active_subscribe_service_info(&frame, service_id),
            Some(ActiveSubscribeServiceInfo {
                instance: 9,
                requestor_instance: 0,
                service_info: &custom,
            })
        );
    }

    #[test]
    fn followup_queue_deduplicates_and_replaces_oldest_at_its_bound() {
        let mut queue = NanFollowupQueue::new(2);
        let first = NanFollowupIntent {
            destination: [1; 6],
            instance: 1,
            payload: vec![1],
            queued_at_us: 10,
        };
        assert_eq!(queue.enqueue(first.clone()), NanFollowupEnqueue::Queued);
        assert_eq!(queue.enqueue(first), NanFollowupEnqueue::Duplicate);
        assert_eq!(
            queue.enqueue(NanFollowupIntent {
                destination: [2; 6],
                instance: 1,
                payload: vec![2],
                queued_at_us: 20,
            }),
            NanFollowupEnqueue::Queued
        );
        assert_eq!(
            queue.enqueue(NanFollowupIntent {
                destination: [3; 6],
                instance: 1,
                payload: vec![3],
                queued_at_us: 30,
            }),
            NanFollowupEnqueue::ReplacedOldest
        );
        let taken = queue.take_up_to(4);
        assert_eq!(taken.len(), 2);
        assert_eq!(taken[0].destination, [2; 6]);
        assert_eq!(taken[1].destination, [3; 6]);
        assert!(queue.is_empty());
    }

    #[test]
    fn active_publish_is_due_on_update_then_at_the_bounded_refresh_cadence() {
        let mut publish = NanActivePublish::default();
        publish.configure(true, &[0xa1, 1, 1]).unwrap();
        assert_eq!(publish.due(10), Some(&[0xa1, 1, 1][..]));
        publish.mark_sent(10);
        assert_eq!(publish.due(10 + NAN_ACTIVE_PUBLISH_INTERVAL_MS - 1), None);
        assert_eq!(
            publish.due(10 + NAN_ACTIVE_PUBLISH_INTERVAL_MS),
            Some(&[0xa1, 1, 1][..])
        );
        publish.configure(false, &[]).unwrap();
        assert_eq!(publish.due(u64::MAX), None);
    }
}
