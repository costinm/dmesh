//! Wire-level NAN definitions copied from Main's tested raw-NAN path.
//! Keep offsets and vendor identifiers synchronized with
//! `fw/esp32/rust/src/components/nan.rs`.

pub const FRAME_DST: usize = 4;
pub const FRAME_SRC: usize = 10;
pub const FRAME_BSSID: usize = 16;
pub const FRAME_DATA: usize = 24;
pub const NAN_ACTION_START: usize = 30;
pub const NAN_BSSID_OUI: [u8; 3] = [0x50, 0x6f, 0x9a];
pub const NAN_DISCOVERY_MAC: [u8; 6] = [0x51, 0x6f, 0x9a, 0x01, 0x00, 0x00];
pub const NAN_CLUSTER_RESELECT_AFTER_US: u64 = 3 * 512 * 1024;
pub const DMESH_SERVICE_ID: [u8; 6] = [0x75, 0x94, 0x31, 0x93, 0xea, 0xc9];
pub const DMESH_MAGIC: [u8; 2] = *b"DM";
pub const DMESH_VERSION: u8 = 1;
pub const DMESH_NAN_FOLLOWUP_HEADER_LEN: usize = 24;
pub const NAN_SERVICE_INFO_LEN: usize = 21;
pub const NAN_SERVICE_FLAG_UART_WAKE: u8 = 0x80;
pub const NAN_SERVICE_FLAG_BLE_WAKE: u8 = 0x40;
pub const NAN_SERVICE_FLAG_ACTIVE_ACK: u8 = 0x20;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServiceDescriptor<'a> {
    pub instance: u8,
    pub requestor_instance: u8,
    pub control: u8,
    pub payload: &'a [u8],
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
    frame.len() > NAN_ACTION_START
        && is_nan_bssid(frame)
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
        .map(|descriptor| descriptor.control == 0x12)
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
    if body.len() < 10 || body[..6] != service_id || !matches!(body[8], 0x10..=0x12) {
        return None;
    }
    let payload_len = body[9] as usize;
    Some(ServiceDescriptor {
        instance: body[6],
        requestor_instance: body[7],
        control: body[8],
        payload: body.get(10..10 + payload_len)?,
    })
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
pub enum FilterMode { Discovery, Cluster }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Action { None, ArmA3(MacAddr), DropForeign, Rediscover }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NanState {
    mode: FilterMode,
    cluster: Option<MacAddr>,
    last_beacon_us: u64,
    stale_after_us: u64,
}

impl NanState {
    pub const fn new(stale_after_us: u64) -> Self {
        Self { mode: FilterMode::Discovery, cluster: None, last_beacon_us: 0, stale_after_us }
    }
    pub const fn mode(&self) -> FilterMode { self.mode }
    pub const fn cluster(&self) -> Option<MacAddr> { self.cluster }

    pub fn observe(&mut self, frame: RxFrame<'_>) -> Action {
        let Some(a3) = bssid(frame.bytes) else { return Action::None };
        let a3 = MacAddr(a3);
        if is_nan_beacon(frame.bytes) {
            if self.cluster.is_none() {
                self.cluster = Some(a3);
                self.mode = FilterMode::Cluster;
                self.last_beacon_us = frame.timestamp_us;
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
            return Action::Rediscover;
        }
        Action::None
    }
}

impl Default for NanState { fn default() -> Self { Self::new(5_000_000) } }
