//! Wire-level NAN definitions copied from Main's tested raw-NAN path.
//! Keep offsets and vendor identifiers synchronized with
//! `fw/esp32/rust/src/components/nan.rs`.

use anyhow::{Result, anyhow, bail};

/// Shared DMesh NAN/BLE service-data and follow-up wire protocol.
pub mod protocol;

pub const FRAME_DST: usize = 4;
pub const FRAME_SRC: usize = 10;
pub const FRAME_BSSID: usize = 16;
pub const FRAME_DATA: usize = 24;
pub const NAN_ACTION_START: usize = 30;
pub const NAN_BSSID_OUI: [u8; 3] = [0x50, 0x6f, 0x9a];
pub const NAN_DISCOVERY_MAC: [u8; 6] = [0x51, 0x6f, 0x9a, 0x01, 0x00, 0x00];
pub const NAN_CLUSTER_RESELECT_AFTER_US: u64 = 3 * 512 * 1024;
pub const NAN_DISCOVERY_PERIOD_US: u64 = 512 * 1024;
pub const DMESH_SERVICE_ID: [u8; 6] = [0x75, 0x94, 0x31, 0x93, 0xea, 0xc9];
pub const DMESH_MAGIC: [u8; 2] = *b"DM";
pub const DMESH_VERSION: u8 = 1;
pub const DMESH_NAN_FOLLOWUP_HEADER_LEN: usize = 24;
pub const NAN_SERVICE_INFO_LEN: usize = 21;
pub const NAN_SERVICE_FLAG_UART_WAKE: u8 = 0x80;
pub const NAN_SERVICE_FLAG_BLE_WAKE: u8 = 0x40;
pub const NAN_SERVICE_FLAG_ACTIVE_ACK: u8 = 0x20;

const NAN_AVAILABILITY_ATTR_ID: u8 = 0x12;
const NAN_TU_US: u32 = 1024;
const NAN_AVAILABILITY_BITMAP_TU: u32 = 16;

/// Encode the shared NAN Availability attribute for a 2.4-GHz duty schedule.
/// Adapter code supplies timing policy; this function owns the wire layout.
pub fn build_nan_availability_attribute(
    dw_tu: u32,
    offset_tu: u32,
    stride: u32,
    active_ms: u32,
    map_id: u8,
) -> Result<Vec<u8>> {
    if map_id > 15 { bail!("NAN Availability Map ID must be in 0..=15; got {map_id}"); }
    let period_tu = dw_tu.checked_mul(stride).ok_or_else(|| anyhow!("NAN availability period overflow"))?;
    let period_code = match period_tu {
        128 => 1, 256 => 2, 512 => 3, 1_024 => 4,
        2_048 => 5, 4_096 => 6, 8_192 => 7,
        _ => bail!("NAN availability period must be 128..=8192 TU power-of-two; got {period_tu}"),
    };
    if offset_tu % NAN_AVAILABILITY_BITMAP_TU != 0 || offset_tu >= period_tu {
        bail!("NAN availability offset must be a 16-TU multiple below the period; got {offset_tu}");
    }
    let active_tu = active_ms.saturating_mul(1_000).saturating_add(NAN_TU_US - 1) / NAN_TU_US;
    let active_slots = active_tu.saturating_add(NAN_AVAILABILITY_BITMAP_TU - 1) / NAN_AVAILABILITY_BITMAP_TU;
    let start_slot = offset_tu / NAN_AVAILABILITY_BITMAP_TU;
    let max_slots = period_tu / NAN_AVAILABILITY_BITMAP_TU;
    if active_slots == 0 || start_slot.saturating_add(active_slots) > max_slots {
        bail!("NAN active interval does not fit the availability period");
    }
    let bitmap_len = ((start_slot + active_slots).saturating_add(7) / 8) as usize;
    let mut bitmap = vec![0_u8; bitmap_len];
    for bit in start_slot..start_slot + active_slots {
        bitmap[(bit / 8) as usize] |= 1 << (bit % 8);
    }
    let entry_len = 2 + 2 + 1 + bitmap.len() + 2;
    let attr_len = 1 + 2 + 2 + entry_len;
    let mut attr = Vec::with_capacity(3 + attr_len);
    attr.push(NAN_AVAILABILITY_ATTR_ID);
    attr.extend_from_slice(&(attr_len as u16).to_le_bytes());
    attr.push(1);
    attr.extend_from_slice(&u16::from(map_id).to_le_bytes());
    attr.extend_from_slice(&(entry_len as u16).to_le_bytes());
    attr.extend_from_slice(&0x1101_u16.to_le_bytes());
    let bitmap_control: u16 = ((period_code << 3) | ((offset_tu / NAN_AVAILABILITY_BITMAP_TU) << 6)) as u16;
    attr.extend_from_slice(&bitmap_control.to_le_bytes());
    attr.push(bitmap.len() as u8);
    attr.extend_from_slice(&bitmap);
    attr.extend_from_slice(&[0x10, 0x02]);
    Ok(attr)
}

/// Encode the shared 2.4-GHz ESP/Android Device Capability attribute.
pub fn build_nan_device_capability_attribute(stride: u32) -> Result<Vec<u8>> {
    let dw_code = match stride { 1 => 1, 2 => 2, 4 => 3, 8 => 4, 16 => 5,
        _ => bail!("NAN committed DW stride must be 1, 2, 4, 8, or 16; got {stride}"), };
    Ok(vec![0x0f, 0x09, 0x00, 0x00, dw_code, 0x00, 0x04, 0x00, 0x11, 0x00, 0x00, 0x00])
}

/// Build the Wi-Fi Aware unsynchronized service-discovery action frame used
/// by wpa_supplicant's CONFIG_NAN_USD implementation.  The returned bytes
/// include the 802.11 management header and can be passed to nl80211 FRAME.
/// DMesh/ESP-NOW vendor actions remain a separate wire format.
pub fn build_nan_usd_sdf(
    destination: [u8; 6],
    source: [u8; 6],
    service_id: [u8; 6],
    instance_id: u8,
    control: u8,
    service_info: &[u8],
) -> Vec<u8> {
    let service_info_len = service_info.len().min(231);
    let sdea_len = 9 + service_info_len;
    let mut frame = Vec::with_capacity(24 + 6 + 3 + 9 + 3 + sdea_len);
    frame.extend_from_slice(&[0xd0, 0x00, 0x00, 0x00]);
    frame.extend_from_slice(&destination);
    frame.extend_from_slice(&source);
    frame.extend_from_slice(&[0xff; 6]);
    frame.extend_from_slice(&[0x00, 0x00]);
    frame.extend_from_slice(&[0x04, 0x09, 0x50, 0x6f, 0x9a, 0x13]);
    frame.push(0x03);
    frame.extend_from_slice(&9_u16.to_le_bytes());
    frame.extend_from_slice(&service_id);
    frame.push(instance_id);
    frame.push(0);
    frame.push(control);
    frame.push(0x0e);
    frame.extend_from_slice(&(sdea_len as u16).to_le_bytes());
    frame.push(instance_id);
    frame.extend_from_slice(&0_u16.to_le_bytes());
    frame.extend_from_slice(&((4 + service_info_len) as u16).to_le_bytes());
    frame.extend_from_slice(&[0x50, 0x6f, 0x9a, 0x00]);
    frame.extend_from_slice(&service_info[..service_info_len]);
    frame
}

/// Build a synchronized DMesh NAN publish SDF. Unlike USD, this frame uses
/// the selected NAN cluster BSSID in A3 and carries the DMesh service-info
/// length/control layout consumed by ESP/Android raw-NAN peers.
pub fn build_nan_publish_sdf(
    destination: [u8; 6],
    source: [u8; 6],
    cluster_bssid: [u8; 6],
    service_id: [u8; 6],
    instance_id: u8,
    service_info: &[u8],
) -> Vec<u8> {
    let info_len = service_info.len().min(255);
    let descriptor_len = 6 + 4 + info_len;
    let mut frame = Vec::with_capacity(30 + 3 + descriptor_len);
    frame.extend_from_slice(&[0xd0, 0x00, 0x00, 0x00]);
    frame.extend_from_slice(&destination);
    frame.extend_from_slice(&source);
    frame.extend_from_slice(&cluster_bssid);
    frame.extend_from_slice(&[0x00, 0x00]);
    frame.extend_from_slice(&[0x04, 0x09, 0x50, 0x6f, 0x9a, 0x13]);
    frame.push(0x03);
    frame.extend_from_slice(&(descriptor_len as u16).to_le_bytes());
    frame.extend_from_slice(&service_id);
    frame.push(instance_id);
    frame.push(0);
    frame.push(0x10);
    frame.push(info_len as u8);
    frame.extend_from_slice(&service_info[..info_len]);
    frame
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nan_usd_sdf_matches_wpa_action_prefix_and_attributes() {
        let frame = build_nan_usd_sdf(
            NAN_DISCOVERY_MAC,
            [1, 2, 3, 4, 5, 6],
            [7, 8, 9, 10, 11, 12],
            1,
            0,
            b"ssi",
        );
        assert_eq!(&frame[..24], &[0xd0, 0, 0, 0, 0x51, 0x6f, 0x9a, 1, 0, 0,
            1, 2, 3, 4, 5, 6, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0]);
        assert_eq!(&frame[24..30], &[0x04, 0x09, 0x50, 0x6f, 0x9a, 0x13]);
        assert_eq!(frame[30], 0x03);
        assert_eq!(u16::from_le_bytes([frame[31], frame[32]]), 9);
        assert_eq!(&frame[33..39], &[7, 8, 9, 10, 11, 12]);
        assert_eq!(frame[39], 1);
        assert_eq!(frame[41], 0);
        assert_eq!(classify(&frame), FrameKind::Sdf);
        let descriptor = service_descriptor(&frame, [7, 8, 9, 10, 11, 12]).expect("USD SDA");
        assert_eq!(descriptor.control, 0);
        assert_eq!(peer_availability(&frame), PeerAvailability::Dw0Dw8);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServiceDescriptor<'a> {
    pub instance: u8,
    pub requestor_instance: u8,
    pub control: u8,
    pub payload: &'a [u8],
}

/// Coarse peer availability used for follow-up scheduling.  We deliberately
/// do not expose the complete NAN availability bitmap here: validation only
/// needs to distinguish continuously powered infrastructure from the common
/// DW0/DW8 sleepy cadence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerAvailability {
    Infra,
    Dw0Dw8,
}

pub fn peer_availability(frame: &[u8]) -> PeerAvailability {
    let mut offset = NAN_ACTION_START;
    while offset + 3 <= frame.len() {
        let attr_id = frame[offset];
        let len = u16::from_le_bytes([frame[offset + 1], frame[offset + 2]]) as usize;
        let start = offset + 3;
        let Some(end) = start.checked_add(len) else { break };
        let Some(body) = frame.get(start..end) else { break };
        // Device Capability: map id, committed DW cadence, bands, ...
        if attr_id == 0x0f && body.len() >= 2 {
            return if body[1] == 1 {
                PeerAvailability::Infra
            } else {
                PeerAvailability::Dw0Dw8
            };
        }
        offset = end;
    }
    PeerAvailability::Dw0Dw8
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DmeshNanFollowup<'a> {
    pub msg_type: u8,
    pub seq: u16,
    pub device_id: [u8; 6],
    pub target_id: [u8; 6],
    pub payload: &'a [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameKind {
    Other,
    Beacon,
    Sdf,
    Followup,
}

pub fn bssid(frame: &[u8]) -> Option<[u8; 6]> {
    frame.get(FRAME_BSSID..FRAME_BSSID + 6)?.try_into().ok()
}

pub fn source(frame: &[u8]) -> Option<[u8; 6]> {
    frame.get(FRAME_SRC..FRAME_SRC + 6)?.try_into().ok()
}

pub fn is_nan_bssid(frame: &[u8]) -> bool {
    bssid(frame)
        .map(|b| b[..3] == NAN_BSSID_OUI)
        .unwrap_or(false)
}

pub fn is_beacon(frame: &[u8]) -> bool {
    frame.first() == Some(&0x80)
}

pub fn is_nan_beacon(frame: &[u8]) -> bool {
    is_beacon(frame) && is_nan_bssid(frame)
}

pub fn beacon_tsf_us(frame: &[u8]) -> Option<u64> {
    Some(u64::from_le_bytes(
        frame.get(FRAME_DATA..FRAME_DATA + 8)?.try_into().ok()?,
    ))
}

pub fn beacon_interval_tu(frame: &[u8]) -> Option<u32> {
    let value = u16::from_le_bytes(
        frame
            .get(FRAME_DATA + 8..FRAME_DATA + 10)?
            .try_into()
            .ok()?,
    ) as u32;
    (value != 0).then_some(value)
}

pub fn is_nan_sdf(frame: &[u8]) -> bool {
    // USD has no synchronized NAN cluster and therefore uses wildcard A3;
    // do not require the cluster OUI here. Cluster/raw-NAN filtering remains
    // the responsibility of NanState and the caller's filter mode.
    frame.len() > NAN_ACTION_START
        && frame.get(FRAME_DATA..FRAME_DATA + 6) == Some(&[0x04, 0x09, 0x50, 0x6f, 0x9a, 0x13])
}

pub fn classify(frame: &[u8]) -> FrameKind {
    if is_nan_beacon(frame) {
        FrameKind::Beacon
    } else if is_nan_followup(frame) {
        FrameKind::Followup
    } else if is_nan_sdf(frame) {
        FrameKind::Sdf
    } else {
        FrameKind::Other
    }
}

pub fn is_nan_followup(frame: &[u8]) -> bool {
    service_descriptor(frame, DMESH_SERVICE_ID)
        .map(|descriptor| matches!(descriptor.control, 0x02 | 0x12))
        .unwrap_or(false)
}

pub fn parse_dmesh_nan_followup(data: &[u8]) -> Option<DmeshNanFollowup<'_>> {
    if data.len() < DMESH_NAN_FOLLOWUP_HEADER_LEN
        || data[..2] != DMESH_MAGIC
        || data[2] != DMESH_VERSION
    {
        return None;
    }
    let mut device_id = [0u8; 6];
    device_id.copy_from_slice(&data[6..12]);
    let mut target_id = [0u8; 6];
    target_id.copy_from_slice(&data[12..18]);
    let payload_len = u16::from_le_bytes([data[18], data[19]]) as usize;
    let end = DMESH_NAN_FOLLOWUP_HEADER_LEN.checked_add(payload_len)?;
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
    let duration = u16::from_le_bytes(data[15..17].try_into().ok()?) as u32;
    Some((duration.clamp(1_000, 300_000), data[4]))
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

pub fn fnv1a32(data: &[u8]) -> u32 {
    data.iter().fold(0x811c9dc5u32, |hash, byte| {
        (hash ^ u32::from(*byte)).wrapping_mul(0x01000193)
    })
}

pub fn service_descriptor_payload<'a>(frame: &'a [u8], service_id: [u8; 6]) -> Option<&'a [u8]> {
    service_descriptor(frame, service_id).map(|descriptor| descriptor.payload)
}

pub fn service_descriptor<'a>(
    frame: &'a [u8],
    service_id: [u8; 6],
) -> Option<ServiceDescriptor<'a>> {
    if !is_nan_sdf(frame) {
        return None;
    }
    let mut offset = NAN_ACTION_START;
    while offset + 3 <= frame.len() {
        let attr_id = frame[offset];
        let len = u16::from_le_bytes([frame[offset + 1], frame[offset + 2]]) as usize;
        let start = offset + 3;
        let end = start.checked_add(len)?;
        let body = frame.get(start..end)?;
        if attr_id == 0x03 {
            if let Some(descriptor) = service_descriptor_body(body, service_id) {
                return Some(descriptor);
            }
        }
        offset = end;
    }
    None
}

pub fn service_descriptor_body<'a>(
    body: &'a [u8],
    service_id: [u8; 6],
) -> Option<ServiceDescriptor<'a>> {
    if body.len() < 9 || body[..6] != service_id {
        return None;
    }
    if matches!(body[8], 0x10..=0x12) {
        let payload_len = *body.get(9)? as usize;
        return Some(ServiceDescriptor {
            instance: body[6],
            requestor_instance: body[7],
            control: body[8],
            payload: body.get(10..10 + payload_len)?,
        });
    }
    // wpa_supplicant/NAN USD puts service information in SDEA, so SDA is the
    // nine-byte descriptor without the DMesh payload-length byte.
    if matches!(body[8], 0..=2) {
        return Some(ServiceDescriptor {
            instance: body[6],
            requestor_instance: body[7],
            control: body[8],
            payload: &[],
        });
    }
    None
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MacAddr(pub [u8; 6]);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RxFrame<'a> {
    pub bytes: &'a [u8],
    pub rssi_dbm: i8,
    pub timestamp_us: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FilterMode {
    Discovery,
    Cluster,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Action {
    None,
    ArmA3(MacAddr),
    DropForeign,
    Rediscover,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NanState {
    mode: FilterMode,
    cluster: Option<MacAddr>,
    sync_bssid: Option<MacAddr>,
    last_beacon_tsf_us: u64,
    beacon_interval_tu: u32,
    last_beacon_us: u64,
    stale_after_us: u64,
}

impl NanState {
    pub const fn new(stale_after_us: u64) -> Self {
        Self {
            mode: FilterMode::Discovery,
            cluster: None,
            sync_bssid: None,
            last_beacon_tsf_us: 0,
            beacon_interval_tu: 0,
            last_beacon_us: 0,
            stale_after_us,
        }
    }
    pub const fn mode(&self) -> FilterMode {
        self.mode
    }
    pub const fn cluster(&self) -> Option<MacAddr> {
        self.cluster
    }
    pub const fn sync_bssid(&self) -> Option<MacAddr> { self.sync_bssid }
    pub const fn last_beacon_tsf_us(&self) -> u64 { self.last_beacon_tsf_us }
    pub const fn beacon_interval_tu(&self) -> u32 { self.beacon_interval_tu }
    /// Latest selected NAN beacon timing: local receive time, beacon TSF,
    /// and the expected NAN interval in microseconds.
    pub fn nan_sync_timing(&self) -> Option<(u64, u64, u64)> {
        match (self.cluster, self.last_beacon_us, self.last_beacon_tsf_us) {
            (Some(_), local_us, tsf_us) if local_us != 0 && tsf_us != 0 => {
                Some((local_us, tsf_us, NAN_DISCOVERY_PERIOD_US))
            }
            _ => None,
        }
    }

    /// Record a normal AP beacon as a timing fallback.  A selected NAN
    /// cluster remains preferred; the AP beacon is only an anchor when no NAN
    /// cluster beacon has been seen.
    pub fn observe_ap_beacon(&mut self, frame: RxFrame<'_>) {
        if !is_beacon(frame.bytes) || self.cluster.is_some() { return; }
        if let Some(a3) = bssid(frame.bytes) {
            self.sync_bssid = Some(MacAddr(a3));
            self.last_beacon_tsf_us = beacon_tsf_us(frame.bytes).unwrap_or(0);
            self.beacon_interval_tu = beacon_interval_tu(frame.bytes).unwrap_or(0);
            self.last_beacon_us = frame.timestamp_us;
        }
    }

    pub fn observe(&mut self, frame: RxFrame<'_>) -> Action {
        let Some(a3) = bssid(frame.bytes) else {
            return Action::None;
        };
        let a3 = MacAddr(a3);
        if is_nan_beacon(frame.bytes) {
            if self.cluster.is_none() {
                self.cluster = Some(a3);
                self.sync_bssid = Some(a3);
                self.last_beacon_tsf_us = beacon_tsf_us(frame.bytes).unwrap_or(0);
                self.beacon_interval_tu = beacon_interval_tu(frame.bytes).unwrap_or(0);
                self.mode = FilterMode::Cluster;
                self.last_beacon_us = frame.timestamp_us;
                self.sync_bssid = Some(a3);
                self.last_beacon_tsf_us = beacon_tsf_us(frame.bytes).unwrap_or(0);
                self.beacon_interval_tu = beacon_interval_tu(frame.bytes).unwrap_or(0);
                return Action::ArmA3(a3);
            }
            if self.cluster == Some(a3) {
                self.last_beacon_us = frame.timestamp_us;
                return Action::None;
            }
            if frame.timestamp_us.saturating_sub(self.last_beacon_us)
                >= NAN_CLUSTER_RESELECT_AFTER_US
            {
                self.cluster = Some(a3);
                self.sync_bssid = Some(a3);
                self.last_beacon_tsf_us = beacon_tsf_us(frame.bytes).unwrap_or(0);
                self.beacon_interval_tu = beacon_interval_tu(frame.bytes).unwrap_or(0);
                self.last_beacon_us = frame.timestamp_us;
                return Action::ArmA3(a3);
            }
            return Action::DropForeign;
        }
        if self.mode == FilterMode::Cluster && self.cluster != Some(a3) {
            return Action::DropForeign;
        }
        Action::None
    }

    pub fn tick(&mut self, now_us: u64) -> Action {
        if self.mode == FilterMode::Cluster
            && now_us.saturating_sub(self.last_beacon_us) >= self.stale_after_us
        {
            self.mode = FilterMode::Discovery;
            self.cluster = None;
            self.sync_bssid = None;
            self.last_beacon_tsf_us = 0;
            self.beacon_interval_tu = 0;
            return Action::Rediscover;
        }
        Action::None
    }
}

impl Default for NanState {
    fn default() -> Self {
        Self::new(5_000_000)
    }
}
