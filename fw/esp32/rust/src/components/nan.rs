use std::collections::VecDeque;
use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, AtomicPtr, AtomicU32, AtomicU8, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use anyhow::{anyhow, bail, Result};
use esp_idf_sys as sys;

use crate::commands::{CommandHandler, CommandRegistry, CommandRequest, CommandResponse};

use super::l3dmesh::{Frame, Transport};
use super::settings::{parse_bool, parse_i32, SharedSettings};
use super::telemetry::{self, Direction};

const NAN_ID: u8 = 1;
const FRAME_DST: usize = 4;
const FRAME_SRC: usize = 10;
const FRAME_BSSID: usize = 16;
const FRAME_DATA: usize = 24;
const NAN_ACTION_START: usize = 30;
const SVC_ID: [u8; 6] = [0x75, 0x94, 0x31, 0x93, 0xea, 0xc9];
const NAN_BSSID: [u8; 6] = [0x50, 0x6f, 0x9a, 0x01, 0x05, 0x01];
// Public Wi-Fi Aware action frames use the NAN discovery MAC for broadcast
// discovery/follow-up traffic, not the Ethernet broadcast address.
const NAN_DISCOVERY_MAC: [u8; 6] = [0x51, 0x6f, 0x9a, 0x01, 0x00, 0x00];
const DEFAULT_SERVICE: &str = "dmesh";
const DEFAULT_CHANNEL: u8 = 6;
const NAN_COMMAND_QUEUE_MAX: usize = 8;
const NAN_OUTGOING_QUEUE_MAX: usize = 8;
const NAN_FOLLOWUP_HISTORY_LEN: usize = 32;
const NAN_COMMAND_MAX_LEN: usize = 231;
const NAN_RX_QUEUE_LEN: u32 = 8;
// NAN beacons, SDFs, and the DMesh action payload all fit below this bound.
// Drop unusual large management frames in the Wi-Fi callback rather than
// parsing or allocating in the driver task.
const NAN_RX_FRAME_MAX: usize = 512;
const NAN_TX_DWELL_US: u64 = 32_000;

static NAN_RUNNING: AtomicBool = AtomicBool::new(false);
static NAN_RX_MGMT: AtomicU32 = AtomicU32::new(0);
static NAN_RX_ACTION: AtomicU32 = AtomicU32::new(0);
static NAN_RX_BEACON: AtomicU32 = AtomicU32::new(0);
static NAN_RX_SDF: AtomicU32 = AtomicU32::new(0);
static NAN_RX_OTHER: AtomicU32 = AtomicU32::new(0);
static NAN_RX_BYTES: AtomicU32 = AtomicU32::new(0);
static NAN_RX_MATCHED: AtomicU32 = AtomicU32::new(0);
static NAN_RAW_COMMAND_RX: AtomicU32 = AtomicU32::new(0);
static NAN_RAW_RESPONSE_RX: AtomicU32 = AtomicU32::new(0);
static NAN_RAW_RESPONSE_TX: AtomicU32 = AtomicU32::new(0);
static NAN_DMESH_SERVICE_RX: AtomicU32 = AtomicU32::new(0);
static NAN_DMESH_FOLLOWUP_RX: AtomicU32 = AtomicU32::new(0);
static NAN_DMESH_FOLLOWUP_TX: AtomicU32 = AtomicU32::new(0);
static NAN_SYNC_BEACON_TX: AtomicU32 = AtomicU32::new(0);
static NAN_LAST_PUBLISH_BEACON: AtomicU32 = AtomicU32::new(0);
// Bounded timing evidence for the last Android DMesh service descriptor and
// follow-up. A powered observer uses these fields to place Android traffic on
// the NAN 512-TU timeline without retaining packet history.
static NAN_LAST_SERVICE_LOCAL_LO: AtomicU32 = AtomicU32::new(0);
static NAN_LAST_SERVICE_LOCAL_HI: AtomicU32 = AtomicU32::new(0);
static NAN_LAST_ACTION_LOCAL_LO: AtomicU32 = AtomicU32::new(0);
static NAN_LAST_ACTION_LOCAL_HI: AtomicU32 = AtomicU32::new(0);
static NAN_RX_QUEUE: AtomicPtr<sys::QueueDefinition> = AtomicPtr::new(core::ptr::null_mut());
static NAN_RX_QUEUE_DROPS: AtomicU32 = AtomicU32::new(0);
static NAN_RX_PREFILTER_DROPS: AtomicU32 = AtomicU32::new(0);
static NAN_RX_OVERSIZE_DROPS: AtomicU32 = AtomicU32::new(0);
static NAN_LAST_BEACON_LOCAL_LO: AtomicU32 = AtomicU32::new(0);
static NAN_LAST_BEACON_LOCAL_HI: AtomicU32 = AtomicU32::new(0);
static NAN_LAST_BEACON_TSF_LO: AtomicU32 = AtomicU32::new(0);
static NAN_LAST_BEACON_TSF_HI: AtomicU32 = AtomicU32::new(0);
// The NAN cluster ID is learned from the synchronized beacon.  It is not a
// fixed value: Android rotates the final bytes as it forms or joins a cluster.
static NAN_CLUSTER_BSSID: [AtomicU8; 6] = [
    AtomicU8::new(NAN_BSSID[0]),
    AtomicU8::new(NAN_BSSID[1]),
    AtomicU8::new(NAN_BSSID[2]),
    AtomicU8::new(NAN_BSSID[3]),
    AtomicU8::new(NAN_BSSID[4]),
    AtomicU8::new(NAN_BSSID[5]),
];
static AP_LAST_BEACON_LOCAL_LO: AtomicU32 = AtomicU32::new(0);
static AP_LAST_BEACON_LOCAL_HI: AtomicU32 = AtomicU32::new(0);
static AP_LAST_BEACON_TSF_LO: AtomicU32 = AtomicU32::new(0);
static AP_LAST_BEACON_TSF_HI: AtomicU32 = AtomicU32::new(0);
static AP_LAST_BEACON_INTERVAL_TU: AtomicU32 = AtomicU32::new(0);
static AP_LAST_BEACON_RSSI: AtomicU32 = AtomicU32::new(0);
static AP_LAST_BEACON_BSSID: [AtomicU8; 6] = [
    AtomicU8::new(0),
    AtomicU8::new(0),
    AtomicU8::new(0),
    AtomicU8::new(0),
    AtomicU8::new(0),
    AtomicU8::new(0),
];
static AP_LAST_BEACON_DIRECT: AtomicBool = AtomicBool::new(false);
static AP_RX_BEACON: AtomicU32 = AtomicU32::new(0);
static NAN_FILTER_MODE: AtomicU32 = AtomicU32::new(FILTER_NAN);
static NAN_FILTER_BSSID_ENABLED: AtomicBool = AtomicBool::new(false);
static NAN_FILTER_BSSID: [AtomicU8; 6] = [
    AtomicU8::new(0),
    AtomicU8::new(0),
    AtomicU8::new(0),
    AtomicU8::new(0),
    AtomicU8::new(0),
    AtomicU8::new(0),
];

const FILTER_ALL_MGMT: u32 = 0;
const FILTER_NAN: u32 = 1;
const FILTER_ACTION: u32 = 2;
const FILTER_BEACON: u32 = 3;
const FILTER_SDF: u32 = 4;
const FILTER_SYNC: u32 = 5;

#[derive(Clone, Copy, Debug)]
pub struct SyncBeacon {
    pub local_us: u64,
    pub tsf_us: u64,
    pub interval_tu: u32,
    pub bssid: [u8; 6],
    pub direct: bool,
}

static NAN_HEADER: [u8; 30] = [
    0xd0, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x50, 0x6f, 0x9a, 0x01, 0x05, 0x01, 0x00, 0x00, 0x04, 0x09, 0x50, 0x6f, 0x9a, 0x13,
];

static NAN_DEVICE_CAPABILITIES: [u8; 12] = [
    0x0f, 0x09, 0x00, 0x00, 0x01, 0x00, 0x04, 0x01, 0x00, 0x00, 0x14, 0x00,
];

const NAN_AVAILABILITY_ATTR_ID: u8 = 0x12;
const NAN_TU_US: u32 = 1024;
const NAN_AVAILABILITY_BITMAP_TU: u32 = 16;

static NAN_SERVICE_EXTENSION: [u8; 7] = [0x0e, 0x04, 0x00, NAN_ID, 0x00, 0x02, 0x02];

const NAN_SERVICE_INFO_LEN: usize = 21;
// Service Control bits 0..=1 identify the descriptor type: 00 = publish,
// 01 = subscribe, 10 = follow-up.  Bit 4 says that service-specific
// information follows.  This is an ESP publisher, not a subscriber.
const NAN_SERVICE_CONTROL_PUBLISH_WITH_INFO: u8 = 0x10;
const DMESH_MAGIC: [u8; 2] = *b"DM";
const DMESH_VERSION: u8 = 1;
const DMESH_NAN_FOLLOWUP_HEADER_LEN: usize = 24;
const DMESH_NAN_ACK: u8 = 5;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NanBackend {
    Raw,
}

impl NanBackend {
    fn parse(value: &str) -> Result<Self> {
        match value {
            "raw" | "frame" | "promisc" => Ok(Self::Raw),
            _ => bail!("unsupported NAN backend; firmware supports raw only"),
        }
    }

    fn name(self) -> &'static str {
        "raw"
    }
}

static NAN_COMMAND_QUEUE: OnceLock<Mutex<VecDeque<NanIncomingCommand>>> = OnceLock::new();
static NAN_OUTGOING_QUEUE: OnceLock<Mutex<VecDeque<RawNanOutgoing>>> = OnceLock::new();
static NAN_PUBLISH_QUEUE: OnceLock<Mutex<VecDeque<Vec<u8>>>> = OnceLock::new();
// Captured in the worker path (never the promiscuous callback) for bounded
// raw-NAN interoperability diagnostics. This provides a live Android sync
// beacon template without treating an inferred beacon layout as authoritative.
static NAN_LAST_SYNC_BEACON_FRAME: OnceLock<Mutex<Vec<u8>>> = OnceLock::new();
// Same bounded diagnostic capture for a valid Android DMesh service descriptor.
// It lets the raw publisher be compared byte-for-byte with an on-air peer
// without retaining frames in the Wi-Fi callback.
static NAN_LAST_DMESH_SERVICE_FRAME: OnceLock<Mutex<Vec<u8>>> = OnceLock::new();
// Android runs both publish and active subscribe sessions. Keep the latter
// separately: it carries the subscriber instance and NAN MAC required for a
// solicited ESP publish response.
static NAN_LAST_DMESH_SUBSCRIBE_FRAME: OnceLock<Mutex<Vec<u8>>> = OnceLock::new();
static NAN_LAST_ACTION_FRAME: OnceLock<Mutex<Vec<u8>>> = OnceLock::new();
// Last SDF handed to the raw transmitter. This is bounded diagnostic evidence
// for Android discovery failures; it is populated in task context, not in the
// Wi-Fi callback.
static NAN_LAST_PUBLISH_FRAME: OnceLock<Mutex<Vec<u8>>> = OnceLock::new();
// Bounded evidence for scheduled Android follow-up probes.  This is filled by
// the worker after DMesh parsing, never by the Wi-Fi callback.
static NAN_FOLLOWUP_HISTORY: OnceLock<Mutex<VecDeque<NanFollowupReceipt>>> = OnceLock::new();

#[derive(Clone, Debug)]
enum NanCommandPeer {
    Raw { mac: [u8; 6], instance: u8 },
}

pub struct NanIncomingCommand {
    peer: NanCommandPeer,
    pub payload: Vec<u8>,
}

struct RawNanOutgoing {
    dst: [u8; 6],
    instance: u8,
    payload: Vec<u8>,
    response: bool,
}

#[derive(Clone, Debug)]
struct NanFollowupReceipt {
    local_us: u64,
    tsf_us: u64,
    msg_type: u8,
    seq: u16,
    payload: Vec<u8>,
}

#[repr(C)]
struct RawNanRxFrame {
    len: u16,
    rssi: i8,
    _reserved: u8,
    data: [u8; NAN_RX_FRAME_MAX],
}

fn nan_command_queue() -> &'static Mutex<VecDeque<NanIncomingCommand>> {
    NAN_COMMAND_QUEUE.get_or_init(|| Mutex::new(VecDeque::with_capacity(NAN_COMMAND_QUEUE_MAX)))
}

fn nan_outgoing_queue() -> &'static Mutex<VecDeque<RawNanOutgoing>> {
    NAN_OUTGOING_QUEUE.get_or_init(|| Mutex::new(VecDeque::with_capacity(NAN_OUTGOING_QUEUE_MAX)))
}

fn nan_publish_queue() -> &'static Mutex<VecDeque<Vec<u8>>> {
    NAN_PUBLISH_QUEUE.get_or_init(|| Mutex::new(VecDeque::with_capacity(NAN_OUTGOING_QUEUE_MAX)));
    NAN_PUBLISH_QUEUE.get().expect("publish queue initialized")
}

fn last_sync_beacon_frame() -> &'static Mutex<Vec<u8>> {
    NAN_LAST_SYNC_BEACON_FRAME.get_or_init(|| Mutex::new(Vec::new()))
}

fn last_dmesh_service_frame() -> &'static Mutex<Vec<u8>> {
    NAN_LAST_DMESH_SERVICE_FRAME.get_or_init(|| Mutex::new(Vec::new()))
}

fn last_dmesh_subscribe_frame() -> &'static Mutex<Vec<u8>> {
    NAN_LAST_DMESH_SUBSCRIBE_FRAME.get_or_init(|| Mutex::new(Vec::new()))
}

fn last_action_frame() -> &'static Mutex<Vec<u8>> {
    NAN_LAST_ACTION_FRAME.get_or_init(|| Mutex::new(Vec::new()))
}

fn last_publish_frame() -> &'static Mutex<Vec<u8>> {
    NAN_LAST_PUBLISH_FRAME.get_or_init(|| Mutex::new(Vec::new()))
}

fn followup_history() -> &'static Mutex<VecDeque<NanFollowupReceipt>> {
    NAN_FOLLOWUP_HISTORY
        .get_or_init(|| Mutex::new(VecDeque::with_capacity(NAN_FOLLOWUP_HISTORY_LEN)))
}

fn record_followup_receipt(msg_type: u8, seq: u16, payload: &[u8]) {
    let local_us = now_us();
    let receipt = NanFollowupReceipt {
        local_us,
        tsf_us: estimated_tsf_us(local_us),
        msg_type,
        seq,
        payload: payload[..payload.len().min(NAN_COMMAND_MAX_LEN)].to_vec(),
    };
    if let Ok(mut history) = followup_history().lock() {
        if history.len() == NAN_FOLLOWUP_HISTORY_LEN {
            history.pop_front();
        }
        history.push_back(receipt);
    }
}

fn render_followup_history() -> Result<String> {
    let history = followup_history()
        .lock()
        .map_err(|_| anyhow!("NAN follow-up history lock poisoned"))?;
    if history.is_empty() {
        return Ok("nan action_history=empty".to_string());
    }
    const DW512_US: u64 = 512 * 1024;
    let entries = history
        .iter()
        .map(|entry| {
            let (index, phase) = if entry.tsf_us == 0 {
                ("none".to_string(), "none".to_string())
            } else {
                (
                    (entry.tsf_us / DW512_US).to_string(),
                    (entry.tsf_us % DW512_US).to_string(),
                )
            };
            format!(
                "seq:{}:type:{}:local_us:{}:dw512_index:{}:dw512_phase_us:{}:payload_hex:{}",
                entry.seq,
                entry.msg_type,
                entry.local_us,
                index,
                phase,
                encode_hex(&entry.payload),
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    Ok(format!(
        "nan action_history count={} entries={}",
        history.len(),
        entries
    ))
}

pub fn take_command() -> Option<NanIncomingCommand> {
    nan_command_queue().lock().ok()?.pop_front()
}

/// Drain management frames copied by the Wi-Fi callback.
///
/// The Wi-Fi promiscuous callback runs in a driver task. It must not allocate,
/// lock telemetry, parse payloads, or dispatch commands, otherwise action
/// traffic can starve the Wi-Fi interrupt path and trigger an interrupt WDT.
pub fn poll_rx() {
    let queue = NAN_RX_QUEUE.load(Ordering::Acquire);
    if queue.is_null() {
        return;
    }
    loop {
        let mut received = core::mem::MaybeUninit::<RawNanRxFrame>::uninit();
        let ok = unsafe { sys::xQueueReceive(queue, received.as_mut_ptr().cast::<c_void>(), 0) };
        if ok != 1 {
            return;
        }
        let received = unsafe { received.assume_init() };
        let len = usize::from(received.len).min(NAN_RX_FRAME_MAX);
        observe_promiscuous_frame(&received.data[..len], received.rssi as i32);
    }
}

pub fn register_commands(registry: &mut CommandRegistry, settings: SharedSettings) {
    registry.register(NanCommand::new(settings));
}

pub fn transport() -> NanTransport {
    NanTransport::default()
}

pub fn forward_packet(packet: &[u8]) -> Result<()> {
    if NAN_RUNNING.load(Ordering::Relaxed) {
        let frame = nan_followup_frame(&[0xff; 6], NAN_ID, packet)?;
        raw_tx(&frame, true)?;
        if packet.starts_with(b"dmesh.pong ")
            || packet
                .windows(b"reply=true".len())
                .any(|part| part == b"reply=true")
        {
            NAN_RAW_RESPONSE_TX.fetch_add(1, Ordering::Relaxed);
        }
        telemetry::record_log(format!(
            "event type=nan.forward backend=raw dst=ff:ff:ff:ff:ff:ff bytes={}",
            packet.len()
        ));
        return Ok(());
    }
    bail!("NAN is not running")
}

/// Send a raw-NAN packet now, or queue it for the next duty-cycle window.
///
/// Control-plane discovery must not depend on a console command landing in the
/// short active window. The queue makes the normal raw-NAN cadence a first
/// class transport instead of treating an inactive Wi-Fi modem as a send
/// failure.
pub fn forward_or_queue_packet(packet: &[u8]) -> Result<bool> {
    if NAN_RUNNING.load(Ordering::Relaxed) {
        forward_packet(packet)?;
        return Ok(false);
    }
    queue_raw_broadcast(packet)?;
    telemetry::record_log(format!(
        "event type=nan.forward queued=true dst=ff:ff:ff:ff:ff:ff bytes={}",
        packet.len()
    ));
    Ok(true)
}

pub fn raw_followup_frame(dst: &[u8; 6], data: &[u8]) -> Result<Vec<u8>> {
    nan_followup_frame(dst, NAN_ID, data)
}

pub fn start_raw_window(channel: u8, filter: &str) -> Result<()> {
    NAN_FILTER_MODE.store(parse_filter_mode(filter)?, Ordering::Relaxed);
    start_raw_sniffer(channel.max(1))
}

/// The most recent NAN synchronization beacon, if one has been received.
pub fn last_nan_sync_beacon() -> Option<SyncBeacon> {
    let local_us = last_beacon_local_us();
    let tsf_us = last_beacon_tsf_us();
    (local_us != 0 && tsf_us != 0).then_some(SyncBeacon {
        local_us,
        tsf_us,
        interval_tu: 512,
        bssid: nan_cluster_bssid(),
        direct: false,
    })
}

/// The latest non-NAN channel beacon. Direct DMesh APs are marked so callers
/// can prefer them without requiring an allow list yet.
pub fn last_ap_sync_beacon() -> Option<SyncBeacon> {
    let local_us = load_u64(&AP_LAST_BEACON_LOCAL_LO, &AP_LAST_BEACON_LOCAL_HI);
    let tsf_us = load_u64(&AP_LAST_BEACON_TSF_LO, &AP_LAST_BEACON_TSF_HI);
    let interval_tu = AP_LAST_BEACON_INTERVAL_TU.load(Ordering::Relaxed);
    if local_us == 0 || tsf_us == 0 || interval_tu == 0 {
        return None;
    }
    let mut bssid = [0_u8; 6];
    for (index, byte) in bssid.iter_mut().enumerate() {
        *byte = AP_LAST_BEACON_BSSID[index].load(Ordering::Relaxed);
    }
    Some(SyncBeacon {
        local_us,
        tsf_us,
        interval_tu,
        bssid,
        direct: AP_LAST_BEACON_DIRECT.load(Ordering::Relaxed),
    })
}

pub fn nan_beacon_age_ms() -> Option<u32> {
    beacon_age_ms(last_beacon_local_us())
}

pub fn ap_beacon_age_ms() -> Option<u32> {
    beacon_age_ms(load_u64(&AP_LAST_BEACON_LOCAL_LO, &AP_LAST_BEACON_LOCAL_HI))
}

pub fn raw_payload(frame: &[u8]) -> Option<&[u8]> {
    raw_command_info(frame).map(|info| info.payload)
}

struct RawNanCommandInfo<'a> {
    source: [u8; 6],
    instance: u8,
    requestor_instance: u8,
    payload: &'a [u8],
}

#[derive(Clone, Copy, Debug)]
struct DmeshNanFollowup<'a> {
    msg_type: u8,
    seq: u16,
    device_id: [u8; 6],
    target_id: [u8; 6],
    payload: &'a [u8],
}

fn raw_command_info(frame: &[u8]) -> Option<RawNanCommandInfo<'_>> {
    if !is_nan_sdf(frame) || frame.len() <= NAN_ACTION_START {
        return None;
    }
    let source = frame.get(FRAME_SRC..FRAME_SRC + 6)?.try_into().ok()?;
    let mut offset = NAN_ACTION_START;
    while offset + 3 <= frame.len() {
        let attr_id = frame[offset];
        let attr_len = u16::from_le_bytes([frame[offset + 1], frame[offset + 2]]) as usize;
        let body_start = offset + 3;
        let body_end = body_start.checked_add(attr_len)?;
        if body_end > frame.len() {
            return None;
        }
        let body = &frame[body_start..body_end];
        if attr_id == 0x03 {
            if let Some((instance, requestor_instance, payload)) =
                raw_service_descriptor_payload(body)
            {
                return Some(RawNanCommandInfo {
                    source,
                    instance,
                    requestor_instance,
                    payload,
                });
            }
        }
        offset = body_end;
    }
    None
}

/// Return the publish/subscribe/follow-up kind of the first DMesh SDA.
fn dmesh_service_descriptor_kind(frame: &[u8]) -> Option<u8> {
    if !is_nan_sdf(frame) {
        return None;
    }
    let mut offset = NAN_ACTION_START;
    while offset + 3 <= frame.len() {
        let attr_id = frame[offset];
        let len = u16::from_le_bytes([frame[offset + 1], frame[offset + 2]]) as usize;
        let body_start = offset + 3;
        let body_end = body_start.checked_add(len)?;
        let body = frame.get(body_start..body_end)?;
        if attr_id == 0x03
            && body.len() >= 10
            && body[..SVC_ID.len()] == SVC_ID
            && is_dmesh_nan_service_info(&body[10..])
        {
            return Some(body[8] & 0x03);
        }
        offset = body_end;
    }
    None
}

fn is_nan_followup(frame: &[u8]) -> bool {
    if !is_nan_sdf(frame) {
        return false;
    }
    let mut offset = NAN_ACTION_START;
    while offset + 3 <= frame.len() {
        let attr_id = frame[offset];
        let len = u16::from_le_bytes([frame[offset + 1], frame[offset + 2]]) as usize;
        let body_start = offset + 3;
        let Some(body_end) = body_start.checked_add(len) else {
            return false;
        };
        if body_end > frame.len() {
            return false;
        }
        let body = &frame[body_start..body_end];
        if attr_id == 0x03 && body.len() >= 9 && body[..SVC_ID.len()] == SVC_ID {
            return body[8] == 0x12;
        }
        offset = body_end;
    }
    false
}

fn raw_service_descriptor_payload(body: &[u8]) -> Option<(u8, u8, &[u8])> {
    if body.len() < 10 || body[..SVC_ID.len()] != SVC_ID {
        return None;
    }
    // Service descriptor body:
    //   service_id[6], instance_id, requestor_instance_id,
    //   service_control, ssi_len, service_specific_info...
    // Android Wi-Fi Aware uses the standard publish/subscribe controls (0x10
    // and 0x11) for discovery and 0x12 for follow-ups.  The old raw parser
    // accepted only 0x12, which made the ESP invisible to Android service
    // advertisements and discarded otherwise conforming descriptors.
    if !matches!(body[8], 0x10..=0x12) {
        return None;
    }
    let instance = body[6];
    let requestor_instance = body[7];
    let len = body[9] as usize;
    let payload_start = 10_usize;
    let payload_end = payload_start.checked_add(len)?;
    if payload_end > body.len() {
        return None;
    }
    Some((
        instance,
        requestor_instance,
        &body[payload_start..payload_end],
    ))
}

/// Parse the shared DMesh v1 NAN follow-up envelope.  It is deliberately
/// separate from compact-CBOR firmware commands: Android service discovery
/// uses this envelope for hello/ack and packet hints, whereas control traffic
/// remains compact CBOR.
fn parse_dmesh_nan_followup(data: &[u8]) -> Option<DmeshNanFollowup<'_>> {
    if data.len() < DMESH_NAN_FOLLOWUP_HEADER_LEN
        || data[..2] != DMESH_MAGIC
        || data[2] != DMESH_VERSION
    {
        return None;
    }
    let mut device_id = [0_u8; 6];
    device_id.copy_from_slice(&data[6..12]);
    let mut target_id = [0_u8; 6];
    target_id.copy_from_slice(&data[12..18]);
    let payload_len = u16::from_le_bytes([data[18], data[19]]) as usize;
    let payload_end = DMESH_NAN_FOLLOWUP_HEADER_LEN.checked_add(payload_len)?;
    if payload_end > data.len() {
        return None;
    }
    Some(DmeshNanFollowup {
        msg_type: data[3],
        seq: u16::from_le_bytes([data[4], data[5]]),
        device_id,
        target_id,
        payload: &data[DMESH_NAN_FOLLOWUP_HEADER_LEN..payload_end],
    })
}

fn is_dmesh_nan_service_info(data: &[u8]) -> bool {
    data.len() == NAN_SERVICE_INFO_LEN && data[..2] == DMESH_MAGIC && data[2] == DMESH_VERSION
}

fn dmesh_nan_followup_frame(
    msg_type: u8,
    seq: u16,
    device_id: &[u8; 6],
    target_id: &[u8; 6],
    payload: &[u8],
) -> Result<Vec<u8>> {
    if payload.len() > NAN_COMMAND_MAX_LEN {
        bail!("DMesh NAN payload exceeds {NAN_COMMAND_MAX_LEN} bytes");
    }
    let mut out = Vec::with_capacity(DMESH_NAN_FOLLOWUP_HEADER_LEN + payload.len());
    out.extend_from_slice(&DMESH_MAGIC);
    out.push(DMESH_VERSION);
    out.push(msg_type);
    out.extend_from_slice(&seq.to_le_bytes());
    out.extend_from_slice(device_id);
    out.extend_from_slice(target_id);
    out.extend_from_slice(&(payload.len() as u16).to_le_bytes());
    out.extend_from_slice(&fnv1a32(payload).to_le_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

fn fnv1a32(data: &[u8]) -> u32 {
    data.iter().fold(0x811c9dc5_u32, |hash, byte| {
        (hash ^ u32::from(*byte)).wrapping_mul(0x01000193)
    })
}

/// Queue a response for a raw-NAN peer.
///
/// In duty-cycle mode, the scheduler drains this queue during the next radio
/// window. In continuously active raw mode, drain it now so interactive
/// diagnostics retain their request/response behavior.
pub fn queue_response_payload_to(command: &NanIncomingCommand, payload: &[u8]) -> Result<usize> {
    // A raw-NAN SDF carries at most 255 bytes. Never truncate compact CBOR:
    // an incomplete response is decoded as a request by the peer and corrupts
    // response accounting. Preserve the method ID where possible and return a
    // small, valid CBOR error instead.
    let bounded = if payload.len() <= NAN_COMMAND_MAX_LEN {
        payload.to_vec()
    } else {
        let method = crate::commands::protocol::decode_binary(payload)
            .map(|response| response.method)
            .unwrap_or(0);
        let mut response = CommandRequest::new_binary(method);
        response.args.insert(
            crate::commands::protocol::CBOR_ERROR,
            format!("raw NAN response exceeds {NAN_COMMAND_MAX_LEN} bytes"),
        );
        crate::commands::protocol::encode_binary(&response)
    };
    match &command.peer {
        NanCommandPeer::Raw { mac, instance } => {
            let queued = enqueue_outgoing_raw(*mac, *instance, &bounded, true)?;
            if !super::mode::raw_nan_duty_enabled() && NAN_RUNNING.load(Ordering::Relaxed) {
                drain_outgoing_raw();
            }
            Ok(queued)
        }
    }
}

pub fn queue_raw_broadcast(payload: &[u8]) -> Result<usize> {
    enqueue_outgoing_raw([0xff; 6], NAN_ID, payload, false)
}

/// Whether an unsent follow-up/discovery frame needs an immediate DW retry.
pub fn raw_queue_pending() -> bool {
    nan_outgoing_queue()
        .lock()
        .map(|queue| !queue.is_empty())
        .unwrap_or(false)
}

pub fn drain_raw_queue() -> usize {
    drain_outgoing_raw()
}

/// Emit one queued service descriptor only immediately after a newly observed
/// NAN cluster beacon. Called by the mode task, never the Wi-Fi callback.
pub fn drain_publish_on_discovery_window() -> usize {
    // The current main-loop wake-to-poll latency is about 34 ms on ESP32.
    // Keep a bounded 64-ms post-beacon transmit guard while measuring the
    // real Android channel-6 dwell; this remains DW-anchored rather than a
    // free-running radio-on interval.
    const DWELL_US: u64 = 64_000;
    if !NAN_RUNNING.load(Ordering::Relaxed) {
        return 0;
    }
    let beacon = NAN_RX_BEACON.load(Ordering::Relaxed);
    if beacon == 0 || beacon == NAN_LAST_PUBLISH_BEACON.load(Ordering::Relaxed) {
        return 0;
    }
    if now_us().saturating_sub(last_beacon_local_us()) > DWELL_US {
        return 0;
    }
    let frame = nan_publish_queue()
        .lock()
        .ok()
        .and_then(|mut queue| queue.pop_front());
    let Some(frame) = frame else {
        return 0;
    };
    if let Ok(mut captured) = last_publish_frame().lock() {
        captured.clear();
        captured.extend_from_slice(&frame);
    }
    match raw_tx(&frame, true) {
        Ok(()) => {
            NAN_LAST_PUBLISH_BEACON.store(beacon, Ordering::Relaxed);
            telemetry::record_log(format!(
                "event type=nan.publish_dw ok=true beacon={}",
                beacon
            ));
            1
        }
        Err(error) => {
            telemetry::record_log(format!(
                "event type=nan.publish_dw ok=false message={}",
                crate::commands::protocol::escape_value(&error.to_string())
            ));
            0
        }
    }
}

pub fn raw_response_rx_count() -> u32 {
    NAN_RAW_RESPONSE_RX.load(Ordering::Relaxed)
}

pub fn raw_tx_active() -> bool {
    NAN_RUNNING.load(Ordering::Relaxed)
}

pub fn sync_to_next_discovery_window(timeout_ms: u64, dw_tu: u64, offset_tu: u64) -> u64 {
    let start_us = now_us();
    let _ = wait_for_discovery_beacon_at_phase(
        timeout_ms,
        dw_tu.saturating_mul(1024),
        offset_tu.saturating_mul(1024),
    );
    now_us().saturating_sub(start_us)
}

/// Wait for a real matching NAN beacon before a data-plane transmission.
/// Unlike the sleep-planning helper above, this fails closed: the caller must
/// not send merely because its local TSF estimate reached the expected phase.
pub fn sync_to_observed_discovery_window(
    timeout_ms: u64,
    dw_tu: u64,
    offset_tu: u64,
) -> Option<u64> {
    let start_us = now_us();
    wait_for_discovery_beacon_at_phase(
        timeout_ms,
        dw_tu.saturating_mul(1024),
        offset_tu.saturating_mul(1024),
    )
    .then(|| now_us().saturating_sub(start_us))
}

struct NanCommand {
    settings: SharedSettings,
    dump: bool,
    channel: u8,
    backend: NanBackend,
    service: String,
}

impl NanCommand {
    fn new(settings: SharedSettings) -> Self {
        Self {
            settings,
            dump: false,
            channel: DEFAULT_CHANNEL,
            backend: NanBackend::Raw,
            service: DEFAULT_SERVICE.to_string(),
        }
    }

    fn apply_settings(&mut self, request: &CommandRequest) -> Result<()> {
        if let Some(backend) = request.arg("backend") {
            self.backend = NanBackend::parse(backend)?;
        } else if let Some(backend) = self.settings.borrow().get_str("nan.backend")? {
            self.backend = NanBackend::parse(&backend)?;
        }
        if let Some(service) = request.arg("service") {
            self.service = checked_service_name(service)?;
        } else if let Some(service) = self.settings.borrow().get_str("nan.service")? {
            self.service = checked_service_name(&service)?;
        }
        if let Some(channel) = request.arg("channel").map(parse_i32).transpose()? {
            self.channel = channel.clamp(1, 13) as u8;
        } else {
            self.channel = self
                .settings
                .borrow()
                .get_i32("nan.channel", DEFAULT_CHANNEL as i32)?
                .clamp(1, 13) as u8;
        }
        Ok(())
    }

    fn maybe_save_settings(&self, request: &CommandRequest, enabled: bool) -> Result<()> {
        if request
            .arg("save")
            .map(parse_bool)
            .transpose()?
            .unwrap_or(false)
        {
            let mut settings = self.settings.borrow_mut();
            settings.set_bool("nan.enabled", enabled)?;
            settings.set_str("nan.backend", self.backend.name())?;
            settings.set_str("nan.service", &self.service)?;
            settings.set_i32("nan.channel", self.channel as i32)?;
        }
        Ok(())
    }
}

impl CommandHandler for NanCommand {
    fn name(&self) -> &'static str {
        "nan"
    }

    fn handle(&mut self, request: &CommandRequest) -> Result<CommandResponse> {
        if let Some(dump) = request.arg("dump") {
            self.dump = parse_bool(dump)?;
        }
        self.apply_settings(request)?;
        if let Some(filter) = request.arg("filter") {
            NAN_FILTER_MODE.store(parse_filter_mode(filter)?, Ordering::Relaxed);
        }
        if let Some(bssid) = request.arg("bssid") {
            if bssid == "none" || bssid == "false" {
                NAN_FILTER_BSSID_ENABLED.store(false, Ordering::Relaxed);
            } else {
                let bssid = parse_mac(bssid)?;
                for (idx, byte) in bssid.iter().enumerate() {
                    NAN_FILTER_BSSID[idx].store(*byte, Ordering::Relaxed);
                }
                NAN_FILTER_BSSID_ENABLED.store(true, Ordering::Relaxed);
            }
        }
        if request.arg("cycle").is_some() {
            return self.raw_cycle_test(request);
        }
        if request.arg("stop").is_some() {
            super::mode::stop_raw_nan_duty();
            stop_nan()?;
            super::wifi::stop_raw_monitor()?;
            self.maybe_save_settings(request, false)?;
            return Ok(CommandResponse::ok("nan stopped"));
        }
        if request.arg("stats").is_some() {
            return Ok(CommandResponse::ok(stats()));
        }
        if request.arg("beacon_dump").is_some() {
            let beacon = last_sync_beacon_frame()
                .lock()
                .map_err(|_| anyhow!("NAN sync beacon capture lock poisoned"))?;
            if beacon.is_empty() {
                return Ok(CommandResponse::ok("nan beacon_dump=empty"));
            }
            return Ok(CommandResponse::ok(format!(
                "nan beacon_dump bytes={} hex={}",
                beacon.len(),
                encode_hex(&beacon)
            )));
        }
        if request.arg("service_dump").is_some() {
            let frame = last_dmesh_service_frame()
                .lock()
                .map_err(|_| anyhow!("NAN service descriptor capture lock poisoned"))?;
            if frame.is_empty() {
                return Ok(CommandResponse::ok("nan service_dump=empty"));
            }
            return Ok(CommandResponse::ok(format!(
                "nan service_dump {} bytes={} hex={}",
                rx_timing_fields(load_u64(
                    &NAN_LAST_SERVICE_LOCAL_LO,
                    &NAN_LAST_SERVICE_LOCAL_HI,
                )),
                frame.len(),
                encode_hex(&frame)
            )));
        }
        if request.arg("action_dump").is_some() {
            let frame = last_action_frame()
                .lock()
                .map_err(|_| anyhow!("NAN action capture lock poisoned"))?;
            if frame.is_empty() {
                return Ok(CommandResponse::ok("nan action_dump=empty"));
            }
            return Ok(CommandResponse::ok(format!(
                "nan action_dump {} bytes={} hex={}",
                rx_timing_fields(load_u64(
                    &NAN_LAST_ACTION_LOCAL_LO,
                    &NAN_LAST_ACTION_LOCAL_HI,
                )),
                frame.len(),
                encode_hex(&frame)
            )));
        }
        if request.arg("publish_dump").is_some() {
            let frame = last_publish_frame()
                .lock()
                .map_err(|_| anyhow!("NAN publish capture lock poisoned"))?;
            if frame.is_empty() {
                return Ok(CommandResponse::ok("nan publish_dump=empty"));
            }
            return Ok(CommandResponse::ok(format!(
                "nan publish_dump bytes={} hex={}",
                frame.len(),
                encode_hex(&frame)
            )));
        }
        if let Some(action_history) = request.arg("action_history") {
            if action_history == "clear" {
                let mut history = followup_history()
                    .lock()
                    .map_err(|_| anyhow!("NAN follow-up history lock poisoned"))?;
                history.clear();
                return Ok(CommandResponse::ok("nan action_history=cleared"));
            }
            return Ok(CommandResponse::ok(render_followup_history()?));
        }
        if request.arg("sync_beacon").is_some() {
            self.ensure_raw_started()?;
            let count = request.arg_i32("count")?.unwrap_or(1).clamp(1, 20) as usize;
            let interval_ms = request
                .arg_i32("interval_ms")?
                .unwrap_or(100)
                .clamp(20, 1_000) as u64;
            let mut frame_len = 0;
            for index in 0..count {
                let frame = nan_sync_beacon_frame()?;
                frame_len = frame.len();
                raw_tx(&frame, true)?;
                NAN_SYNC_BEACON_TX.fetch_add(1, Ordering::Relaxed);
                if index + 1 < count {
                    task_delay(Duration::from_millis(interval_ms));
                }
            }
            return Ok(CommandResponse::ok(format!(
                "nan sync_beacon count={} interval_ms={} bssid={} bytes={}",
                count,
                interval_ms,
                format_mac(&nan_cluster_bssid()),
                frame_len
            )));
        }
        // A gateway sends an already-encoded addressed command as binary
        // payload. Do not accept text here: raw-NAN, BLE, and UART all use the
        // same compact-CBOR command bytes. The duty scheduler drains this
        // queue during lora1's next active NAN window.
        if !request.payload.is_empty() {
            if request.payload.len() > NAN_COMMAND_MAX_LEN {
                bail!("nan payload exceeds {NAN_COMMAND_MAX_LEN} bytes");
            }
            let queued = queue_raw_broadcast(&request.payload)?;
            // Duty-cycled nodes transmit from their next scheduled window.
            // An explicitly active raw-NAN session is used for host debugging
            // and transfers, so deliver the queued compact-CBOR command now.
            if !super::mode::raw_nan_duty_enabled() && NAN_RUNNING.load(Ordering::Relaxed) {
                drain_outgoing_raw();
            }
            return Ok(CommandResponse::ok(format!(
                "nan queued=true bytes={} queue_len={}",
                request.payload.len(),
                queued
            )));
        }
        if request.arg("start").is_some()
            || request
                .arg("enable")
                .map(parse_bool)
                .transpose()?
                .unwrap_or(false)
        {
            self.start_selected()?;
            self.maybe_save_settings(request, true)?;
            return Ok(CommandResponse::ok(format!(
                "nan started backend={} service={} channel={} dump={} filter={}",
                self.backend.name(),
                self.service,
                self.channel.max(1),
                self.dump,
                filter_name()
            )));
        }
        if let Some(raw) = request.arg("raw") {
            let bytes = parse_bytes(raw)?;
            self.ensure_raw_started()?;
            raw_tx(&bytes, true)?;
            return Ok(CommandResponse::ok(format!(
                "nan raw sent bytes={}",
                bytes.len()
            )));
        }
        if request.arg("publish").is_some() {
            self.ensure_raw_started()?;
            let count = request.arg_i32("count")?.unwrap_or(1).clamp(1, 20) as u32;
            let sync = request
                .arg("sync")
                .map(parse_bool)
                .transpose()?
                .unwrap_or(false);
            if !sync {
                bail!("nan publish requires sync=true; raw NAN data is DW-gated");
            }
            let _ = request.arg_i32("sync_timeout_ms")?;
            let availability = nan_availability_from_settings(&self.settings)?;
            let mut frame_len = 0_usize;
            let mut destination = NAN_DISCOVERY_MAC;
            let mut queue = nan_publish_queue()
                .lock()
                .map_err(|_| anyhow!("nan publish queue lock failed"))?;
            for _ in 0..count {
                let frame = nan_publish_frame(&availability)?;
                frame_len = frame.len();
                destination.copy_from_slice(&frame[FRAME_DST..FRAME_DST + 6]);
                if queue.len() >= NAN_OUTGOING_QUEUE_MAX {
                    queue.pop_front();
                }
                queue.push_back(frame);
            }
            return Ok(CommandResponse::ok(format!(
                "nan publish queued=true backend={} service={} count={} dst={} bssid={} bytes={}",
                self.backend.name(),
                self.service,
                count,
                format_mac(&destination),
                format_mac(&nan_cluster_bssid()),
                frame_len
            )));
        }
        if let Some(data) = request.arg("queue").or_else(|| request.arg("enqueue")) {
            let _ = data;
            return Err(anyhow!("nan queue requires a binary transport payload"));
        }
        if let Some(data) = request.arg("send") {
            let _ = data;
            return Err(anyhow!("nan send requires a binary transport payload"));
        }
        Ok(CommandResponse::ok(stats()))
    }
}

impl NanCommand {
    fn raw_cycle_test(&mut self, request: &CommandRequest) -> Result<CommandResponse> {
        self.backend = NanBackend::Raw;
        let channel = self.channel.max(1);
        let period_ms = request
            .arg_i32("wake_ms")?
            .unwrap_or(2_000)
            .clamp(100, 60_000) as u64;
        let active_ms = request
            .arg_i32("active_ms")?
            .unwrap_or(500)
            .clamp(50, 60_000) as u64;
        let count = request.arg_i32("count")?.unwrap_or(10).clamp(1, 100) as u32;
        // Match the duty scheduler: TSF synchronization needs NAN beacons in
        // addition to DMesh SDF follow-ups.
        let filter = request.arg("filter").unwrap_or("nan");
        let sync = request
            .arg("sync")
            .map(parse_bool)
            .transpose()?
            .unwrap_or(false);
        let dw_tu = request.arg_i32("dw_tu")?.unwrap_or(512).clamp(1, 65_535) as u64;
        let offset_tu = request.arg_i32("offset_tu")?.unwrap_or(0).max(0) as u64;
        let sync_timeout_ms = request
            .arg_i32("sync_ms")?
            .unwrap_or(1_000)
            .clamp(10, 10_000) as u64;
        let extend_on_rx = request
            .arg("extend_on_rx")
            .map(parse_bool)
            .transpose()?
            .unwrap_or(true);
        let extend_ms = request
            .arg_i32("extend_ms")?
            .unwrap_or(500)
            .clamp(0, 60_000) as u64;
        let idle_ms = period_ms.saturating_sub(active_ms);

        telemetry::record_log(format!(
            "event type=nan.cycle start=true channel={} period_ms={} active_ms={} idle_ms={} count={} filter={} sync={} dw_tu={} offset_tu={} sync_ms={} extend_on_rx={} extend_ms={}",
            channel, period_ms, active_ms, idle_ms, count, filter, sync, dw_tu, offset_tu, sync_timeout_ms, extend_on_rx, extend_ms
        ));
        for idx in 0..count {
            stop_nan()?;
            let _ = super::wifi::stop_raw_monitor();
            let idle_start_us = now_us();
            telemetry::record_log(format!(
                "event type=nan.cycle phase=idle index={} local_us={} idle_ms={}",
                idx, idle_start_us, idle_ms
            ));
            if idle_ms > 0 {
                task_delay(Duration::from_millis(idle_ms));
            }

            let start_beacons = NAN_RX_BEACON.load(Ordering::Relaxed);
            let start_sdf = NAN_RX_SDF.load(Ordering::Relaxed);
            let start_action = NAN_RX_ACTION.load(Ordering::Relaxed);
            let radio_start_begin_us = now_us();
            start_raw_window(channel, filter)?;
            let radio_start_end_us = now_us();
            let radio_start_us = radio_start_end_us.saturating_sub(radio_start_begin_us);
            if sync {
                let sync_start_us = now_us();
                let before_beacon = NAN_RX_BEACON.load(Ordering::Relaxed);
                wait_for_beacon_or_timeout(before_beacon, sync_timeout_ms);
                let wait_us = wait_us_until_tsf_phase(dw_tu * 1024, offset_tu * 1024);
                telemetry::record_log(format!(
                    "event type=nan.cycle phase=sync index={} local_us={} sync_wait_ms={} phase_wait_us={} last_beacon_local_us={} last_beacon_tsf_us={} beacon_delta={}",
                    idx,
                    now_us(),
                    now_us().saturating_sub(sync_start_us) / 1000,
                    wait_us,
                    last_beacon_local_us(),
                    last_beacon_tsf_us(),
                    NAN_RX_BEACON.load(Ordering::Relaxed).saturating_sub(before_beacon)
                ));
                if wait_us > 0 {
                    task_delay(Duration::from_micros(wait_us));
                }
            }
            let start_local_us = now_us();
            telemetry::record_log(format!(
                "event type=nan.cycle phase=active_start index={} local_us={} radio_start_us={} est_tsf_us={} est_tsf_phase_us={} last_beacon_local_us={} last_beacon_tsf_us={} raw_beacon={} raw_sdf={} raw_action={}",
                idx,
                start_local_us,
                radio_start_us,
                estimated_tsf_us(start_local_us),
                estimated_tsf_us(start_local_us) % (dw_tu * 1024),
                last_beacon_local_us(),
                last_beacon_tsf_us(),
                start_beacons,
                start_sdf,
                start_action
            ));
            let queued_sent = drain_outgoing_raw();
            if queued_sent > 0 {
                telemetry::record_log(format!(
                    "event type=nan.cycle phase=active_tx index={} queued_sent={}",
                    idx, queued_sent
                ));
            }
            let mut deadline_us = start_local_us.saturating_add(active_ms.saturating_mul(1000));
            let mut last_sdf = NAN_RX_SDF.load(Ordering::Relaxed);
            let mut extended = 0_u32;
            while now_us() < deadline_us {
                task_delay(Duration::from_millis(20));
                let current_sdf = NAN_RX_SDF.load(Ordering::Relaxed);
                if extend_on_rx && extend_ms > 0 && current_sdf != last_sdf {
                    let extended_deadline = now_us().saturating_add(extend_ms.saturating_mul(1000));
                    if extended_deadline > deadline_us {
                        deadline_us = extended_deadline;
                        extended = extended.saturating_add(1);
                        telemetry::record_log(format!(
                            "event type=nan.cycle phase=extend index={} local_us={} sdf_delta={} new_deadline_us={}",
                            idx,
                            now_us(),
                            current_sdf.saturating_sub(start_sdf),
                            deadline_us
                        ));
                    }
                    last_sdf = current_sdf;
                }
            }

            let end_local_us = now_us();
            telemetry::record_log(format!(
                "event type=nan.cycle phase=active_stop index={} local_us={} elapsed_ms={} extended={} est_tsf_us={} est_tsf_phase_us={} beacon_delta={} sdf_delta={} action_delta={} last_beacon_local_us={} last_beacon_tsf_us={}",
                idx,
                end_local_us,
                end_local_us.saturating_sub(start_local_us) / 1000,
                extended,
                estimated_tsf_us(end_local_us),
                estimated_tsf_us(end_local_us) % (dw_tu * 1024),
                NAN_RX_BEACON.load(Ordering::Relaxed).saturating_sub(start_beacons),
                NAN_RX_SDF.load(Ordering::Relaxed).saturating_sub(start_sdf),
                NAN_RX_ACTION.load(Ordering::Relaxed).saturating_sub(start_action),
                last_beacon_local_us(),
                last_beacon_tsf_us()
            ));
        }
        stop_nan()?;
        let _ = super::wifi::stop_raw_monitor();
        Ok(CommandResponse::ok(format!(
            "nan cycle done channel={} period_ms={} active_ms={} count={} {}",
            channel,
            period_ms,
            active_ms,
            count,
            stats()
        )))
    }

    fn start_selected(&mut self) -> Result<()> {
        if NAN_RUNNING.load(Ordering::Relaxed) {
            stop_nan()?;
        }
        self.start_raw()
    }

    fn start_raw(&mut self) -> Result<()> {
        start_raw_sniffer(self.channel.max(1))?;
        if self.dump {
            log::info!(
                "nan raw monitor started channel={} filter={}",
                self.channel.max(1),
                filter_name()
            );
        }
        Ok(())
    }

    fn ensure_raw_started(&mut self) -> Result<()> {
        if !NAN_RUNNING.load(Ordering::Relaxed) {
            self.start_raw()?;
        }
        Ok(())
    }
}

fn wait_for_beacon_or_timeout(start_count: u32, timeout_ms: u64) {
    let deadline_us = now_us().saturating_add(timeout_ms.saturating_mul(1000));
    while now_us() < deadline_us {
        if NAN_RX_BEACON.load(Ordering::Relaxed) != start_count {
            return;
        }
        task_delay(Duration::from_millis(10));
    }
}

/// Wait for an actual on-air NAN beacon in the requested cadence. The current
/// cluster beacon establishes DW0; NAN clusters are not required to align
/// their DW phase to a global TSF modulus of zero.
fn wait_for_discovery_beacon_at_phase(timeout_ms: u64, period_us: u64, _offset_us: u64) -> bool {
    if period_us == 0 {
        return false;
    }
    let deadline_us = now_us().saturating_add(timeout_ms.saturating_mul(1000));
    let mut count = NAN_RX_BEACON.load(Ordering::Relaxed);
    let anchor_tsf_us = last_beacon_tsf_us();
    while now_us() < deadline_us {
        let observed = NAN_RX_BEACON.load(Ordering::Relaxed);
        if observed != count {
            count = observed;
            // At the 512-TU test cadence every received cluster beacon is
            // the next selected DW.  Its observed arrival, not an assumed
            // TSF phase, is the only safe authority for a channel-6 TX.
            if period_us <= 512 * 1024 {
                return true;
            }
            let tsf_us = last_beacon_tsf_us();
            let phase_us = tsf_us.abs_diff(anchor_tsf_us) % period_us;
            if phase_us <= NAN_TX_DWELL_US || period_us.saturating_sub(phase_us) <= NAN_TX_DWELL_US
            {
                return true;
            }
        }
        task_delay(Duration::from_millis(2));
    }
    false
}

fn wait_us_until_tsf_phase(period_us: u64, offset_us: u64) -> u64 {
    if period_us == 0 {
        return 0;
    }
    let now = now_us();
    let tsf = estimated_tsf_us(now);
    if tsf == 0 {
        return 0;
    }
    let phase = tsf % period_us;
    let target = offset_us % period_us;
    if phase <= target {
        target - phase
    } else {
        period_us - (phase - target)
    }
}

fn estimated_tsf_us(local_us: u64) -> u64 {
    let beacon_local = last_beacon_local_us();
    let beacon_tsf = last_beacon_tsf_us();
    if beacon_local == 0 || beacon_tsf == 0 {
        return 0;
    }
    beacon_tsf.saturating_add(local_us.saturating_sub(beacon_local))
}

/// Render the last receive point against the NAN DW0 cadence. NAN uses a
/// 512-TU (524288 us) period here; `dw512_index` is monotonic and
/// `dw512_phase_us=0` is the configured DW0 boundary.
fn rx_timing_fields(local_us: u64) -> String {
    if local_us == 0 {
        return "local_us=none est_tsf_us=none dw512_index=none dw512_phase_us=none".to_string();
    }
    let tsf_us = estimated_tsf_us(local_us);
    if tsf_us == 0 {
        return format!(
            "local_us={} est_tsf_us=none dw512_index=none dw512_phase_us=none",
            local_us
        );
    }
    const DW512_US: u64 = 512 * 1024;
    format!(
        "local_us={} est_tsf_us={} dw512_index={} dw512_phase_us={}",
        local_us,
        tsf_us,
        tsf_us / DW512_US,
        tsf_us % DW512_US
    )
}

fn start_raw_sniffer(channel: u8) -> Result<()> {
    ensure_rx_queue()?;
    super::wifi::ensure_raw_wifi_started(channel)?;
    unsafe {
        let mut filter = sys::wifi_promiscuous_filter_t {
            filter_mask: sys::WIFI_PROMIS_FILTER_MASK_MGMT,
        };
        esp_ok(sys::esp_wifi_set_promiscuous(false))?;
        esp_ok(sys::esp_wifi_set_promiscuous_rx_cb(Some(sniffer_cb)))?;
        esp_ok(sys::esp_wifi_set_promiscuous_filter(&mut filter))?;
        esp_ok(sys::esp_wifi_set_channel(
            channel,
            sys::wifi_second_chan_t_WIFI_SECOND_CHAN_NONE,
        ))?;
        esp_ok(sys::esp_wifi_set_promiscuous(true))?;
    }
    NAN_RUNNING.store(true, Ordering::Relaxed);
    Ok(())
}

fn ensure_rx_queue() -> Result<()> {
    if !NAN_RX_QUEUE.load(Ordering::Acquire).is_null() {
        return Ok(());
    }
    let queue = unsafe {
        sys::xQueueGenericCreate(
            NAN_RX_QUEUE_LEN,
            core::mem::size_of::<RawNanRxFrame>() as u32,
            0,
        )
    };
    if queue.is_null() {
        bail!("raw NAN receive queue allocation failed");
    }
    if NAN_RX_QUEUE
        .compare_exchange(
            core::ptr::null_mut(),
            queue,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_err()
    {
        unsafe { sys::vQueueDelete(queue) };
    }
    Ok(())
}

#[derive(Default)]
pub struct NanTransport {
    #[allow(dead_code)]
    sent_frames: u32,
}

impl Transport for NanTransport {
    fn name(&self) -> &'static str {
        "nan"
    }

    fn send(&mut self, frame: &Frame<'_>, from_interface: i32) -> Result<()> {
        self.sent_frames = self.sent_frames.saturating_add(1);
        telemetry::record_packet(
            "wifi",
            Direction::Tx,
            frame.payload(),
            format!("source=nan_l3mesh from={from_interface}"),
        );
        log::info!(
            "nan send: from={} len={} total={}",
            from_interface,
            frame.payload().len(),
            self.sent_frames
        );
        Ok(())
    }
}

fn task_delay(timeout: Duration) {
    unsafe {
        sys::vTaskDelay(duration_to_ticks(timeout).max(1));
    }
}

fn duration_to_ticks(timeout: Duration) -> sys::TickType_t {
    let hz = sys::configTICK_RATE_HZ as u128;
    let ticks = timeout.as_millis().saturating_mul(hz).div_ceil(1000);
    ticks.min(sys::TickType_t::MAX as u128) as sys::TickType_t
}

fn now_us() -> u64 {
    unsafe { sys::esp_timer_get_time().max(0) as u64 }
}

fn load_u64(low: &AtomicU32, high: &AtomicU32) -> u64 {
    ((high.load(Ordering::Relaxed) as u64) << 32) | low.load(Ordering::Relaxed) as u64
}

fn store_u64(low: &AtomicU32, high: &AtomicU32, value: u64) {
    low.store(value as u32, Ordering::Relaxed);
    high.store((value >> 32) as u32, Ordering::Relaxed);
}

fn beacon_age_ms(local_us: u64) -> Option<u32> {
    (local_us != 0)
        .then(|| (now_us().saturating_sub(local_us) / 1_000).min(u64::from(u32::MAX)) as u32)
}

fn store_last_beacon_local_us(value: u64) {
    NAN_LAST_BEACON_LOCAL_LO.store(value as u32, Ordering::Relaxed);
    NAN_LAST_BEACON_LOCAL_HI.store((value >> 32) as u32, Ordering::Relaxed);
}

fn store_last_beacon_tsf_us(value: u64) {
    NAN_LAST_BEACON_TSF_LO.store(value as u32, Ordering::Relaxed);
    NAN_LAST_BEACON_TSF_HI.store((value >> 32) as u32, Ordering::Relaxed);
}

fn last_beacon_local_us() -> u64 {
    load_u64(&NAN_LAST_BEACON_LOCAL_LO, &NAN_LAST_BEACON_LOCAL_HI)
}

fn last_beacon_tsf_us() -> u64 {
    load_u64(&NAN_LAST_BEACON_TSF_LO, &NAN_LAST_BEACON_TSF_HI)
}

fn enqueue_raw_command(source: [u8; 6], instance: u8, payload: &[u8]) -> bool {
    if payload.len() > NAN_COMMAND_MAX_LEN {
        telemetry::record_log("event type=nan.reject reason=len".to_string());
        return false;
    }
    let req = match crate::commands::protocol::decode_binary(payload) {
        Ok(req) => req,
        Err(err) => {
            telemetry::record_log(format!("event type=nan.reject reason=decode err={}", err));
            return false;
        }
    };
    if !command_targets_this_device_cbor(&req) {
        telemetry::record_log("event type=nan.reject reason=target".to_string());
        return false;
    }
    if station_mac().map(|mac| mac == source).unwrap_or(false) {
        telemetry::record_log("event type=nan.reject reason=self".to_string());
        return false;
    }
    let Ok(mut queue) = nan_command_queue().lock() else {
        return false;
    };
    if queue.len() >= NAN_COMMAND_QUEUE_MAX {
        queue.pop_front();
    }
    queue.push_back(NanIncomingCommand {
        peer: NanCommandPeer::Raw {
            mac: source,
            instance,
        },
        payload: payload.to_vec(),
    });
    NAN_RAW_COMMAND_RX.fetch_add(1, Ordering::Relaxed);
    super::wake::notify();
    true
}

fn command_targets_this_device_cbor(request: &CommandRequest) -> bool {
    let Some(to) = request.args.get(&331) else {
        telemetry::record_log("event type=nan.target_check to=none".to_string());
        return true;
    };
    if is_broadcast_target(to) {
        telemetry::record_log("event type=nan.target_check to=broadcast".to_string());
        return true;
    }
    let Ok(mac) = station_mac() else {
        telemetry::record_log("event type=nan.target_check err=no_mac".to_string());
        return false;
    };
    let suffix = mac_suffix4_hex(&mac);
    let matched = to.eq_ignore_ascii_case(&suffix);
    telemetry::record_log(format!(
        "event type=nan.target_check to={} suffix={} matched={}",
        to, suffix, matched
    ));
    matched
}

fn enqueue_outgoing_raw(
    dst: [u8; 6],
    instance: u8,
    payload: &[u8],
    response: bool,
) -> Result<usize> {
    if payload.len() > NAN_COMMAND_MAX_LEN {
        bail!("raw NAN payload exceeds {NAN_COMMAND_MAX_LEN} bytes");
    }
    let queued = {
        let Ok(mut queue) = nan_outgoing_queue().lock() else {
            bail!("nan outgoing queue lock failed")
        };
        if queue.len() >= NAN_OUTGOING_QUEUE_MAX {
            queue.pop_front();
        }
        queue.push_back(RawNanOutgoing {
            dst,
            instance,
            payload: payload.to_vec(),
            response,
        });
        queue.len()
    };
    // The mode poller drains this queue while a beacon-opened DW permit is
    // valid. Never call Wi-Fi TX from the promiscuous receive callback.
    Ok(queued)
}

fn drain_outgoing_raw() -> usize {
    // A duty-cycled ESP may have Wi-Fi powered for beacon acquisition before
    // the peer's actual DW.  Do not turn that wider receive interval into a
    // transmit opportunity: Android departs channel 6 rapidly after DW.
    if !super::mode::raw_nan_data_dw_open() {
        return 0;
    }
    let mut sent = 0_usize;
    loop {
        let item = {
            let Ok(mut queue) = nan_outgoing_queue().lock() else {
                return sent;
            };
            queue.pop_front()
        };
        let Some(item) = item else {
            return sent;
        };
        match nan_followup_frame(&item.dst, item.instance, &item.payload)
            .and_then(|frame| raw_tx(&frame, true))
        {
            Ok(()) => {
                sent += 1;
                if item.response {
                    NAN_RAW_RESPONSE_TX.fetch_add(1, Ordering::Relaxed);
                }
                telemetry::record_log(format!(
                    "event type=nan.queue_tx ok=true dst={} len={} sent={}",
                    format_mac(&item.dst),
                    item.payload.len(),
                    sent
                ));
            }
            Err(err) => {
                telemetry::record_log(format!(
                    "event type=nan.queue_tx ok=false dst={} len={} message={}",
                    format_mac(&item.dst),
                    item.payload.len(),
                    crate::commands::protocol::escape_value(&err.to_string())
                ));
                let _ = enqueue_outgoing_raw(item.dst, item.instance, &item.payload, item.response);
                return sent;
            }
        }
    }
}

fn checked_service_name(value: &str) -> Result<String> {
    if value.is_empty() || value.len() >= 256 || value.as_bytes().contains(&0) {
        bail!("NAN service name must be 1..255 non-NUL bytes");
    }
    Ok(value.to_string())
}

pub fn stop_nan() -> Result<()> {
    unsafe {
        let _ = sys::esp_wifi_set_promiscuous(false);
    }
    NAN_RUNNING.store(false, Ordering::Relaxed);
    Ok(())
}

fn raw_tx(bytes: &[u8], en_sys_seq: bool) -> Result<()> {
    if bytes.len() < 24 || bytes.len() > 1500 {
        bail!(
            "raw 802.11 frame length must be 24..=1500, got {}",
            bytes.len()
        );
    }
    unsafe {
        esp_ok(sys::esp_wifi_80211_tx(
            super::wifi::raw_tx_interface(),
            bytes.as_ptr() as *const _,
            bytes.len() as i32,
            en_sys_seq,
        ))?;
    }
    telemetry::record_packet("wifi", Direction::Tx, bytes, "source=nan_raw");
    // TX samples are normally suppressed globally to avoid retaining traffic
    // indefinitely.  Raw NAN is a bounded control-plane experiment, and the
    // exact emitted action bytes are essential to compare against Android's
    // public Wi-Fi Aware captures.
    telemetry::record_packet_sample("wifi", Direction::Tx, bytes, "source=nan_raw");
    Ok(())
}

/// Re-emit a captured Android NAN synchronization beacon as a bounded raw
/// interoperability probe. The NAN vendor IE and its cluster/master
/// attributes are preserved byte-for-byte: they are live on-air state, not a
/// layout guessed by this firmware. Only the 802.11 transmitter address,
/// cluster BSSID, and advancing local TSF are changed for this ESP station.
fn nan_sync_beacon_frame() -> Result<Vec<u8>> {
    let template = last_sync_beacon_frame()
        .lock()
        .map_err(|_| anyhow!("NAN sync beacon capture lock poisoned"))?
        .clone();
    let local_us = last_beacon_local_us();
    let observed_tsf_us = last_beacon_tsf_us();
    if template.is_empty() || local_us == 0 || observed_tsf_us == 0 {
        bail!("no captured NAN synchronization beacon yet");
    }
    let tsf_us = observed_tsf_us.saturating_add(now_us().saturating_sub(local_us));
    nan_sync_beacon_frame_for(&template, &station_mac()?, &nan_cluster_bssid(), tsf_us)
}

fn nan_sync_beacon_frame_for(
    template: &[u8],
    mac: &[u8; 6],
    cluster_bssid: &[u8; 6],
    tsf_us: u64,
) -> Result<Vec<u8>> {
    if template.len() < FRAME_DATA + 12 || template.len() > NAN_RX_FRAME_MAX {
        bail!(
            "invalid NAN synchronization beacon template length={}",
            template.len()
        );
    }
    if template[0] != 0x80 || !is_nan_bssid(template) {
        bail!("captured frame is not a NAN synchronization beacon");
    }
    let mut frame = template.to_vec();
    frame[FRAME_SRC..FRAME_SRC + 6].copy_from_slice(mac);
    frame[FRAME_BSSID..FRAME_BSSID + 6].copy_from_slice(cluster_bssid);
    frame[FRAME_DATA..FRAME_DATA + 8].copy_from_slice(&tsf_us.to_le_bytes());
    Ok(frame)
}

/// Encode one committed 2.4-GHz availability entry from the raw-NAN duty
/// settings.  Each bitmap bit represents 16 TU; bits outside the bounded
/// radio-on interval are deliberately zero, because uncovered NAN slots are
/// unavailable by definition.
///
/// Wi-Fi Aware v3.2 Tables 85--91 define this layout.  The raw duty profile
/// supports a 128/256/512-TU DW base and a power-of-two stride such that the
/// repeat period is one of the standard 128..8192-TU values.
//
// Keep this in step with Android's `awake_dw_interval` / discovery-window
// interval when that vendor/framework setting is enabled. On 2.4 GHz Android
// accepts values 1..=5, meaning every 1, 2, 4, 8, or 16 DWs respectively; an
// ESP `nan.dw_stride=8` therefore corresponds to Android value 4. The normal
// public app API leaves it unset and lets the framework choose, so changing
// `nan.dw_tu` or `nan.dw_stride` requires a fresh Android capability/config
// check before treating both sides as power-synchronized.
fn nan_availability_attribute(
    dw_tu: u32,
    offset_tu: u32,
    stride: u32,
    active_ms: u32,
) -> Result<Vec<u8>> {
    let period_tu = dw_tu
        .checked_mul(stride)
        .ok_or_else(|| anyhow!("NAN availability period overflow"))?;
    let period_code = match period_tu {
        128 => 1,
        256 => 2,
        512 => 3,
        1_024 => 4,
        2_048 => 5,
        4_096 => 6,
        8_192 => 7,
        _ => bail!(
            "nan.dw_tu * nan.dw_stride must be 128, 256, 512, 1024, 2048, 4096, or 8192 TU; got {period_tu}"
        ),
    };
    if offset_tu % NAN_AVAILABILITY_BITMAP_TU != 0 || offset_tu >= period_tu {
        bail!(
            "nan.dw_off_tu must be a multiple of 16 below the {}-TU availability period; got {}",
            period_tu,
            offset_tu
        );
    }
    let active_tu = active_ms
        .saturating_mul(1_000)
        .saturating_add(NAN_TU_US - 1)
        / NAN_TU_US;
    let active_slots =
        active_tu.saturating_add(NAN_AVAILABILITY_BITMAP_TU - 1) / NAN_AVAILABILITY_BITMAP_TU;
    let start_slot = offset_tu / NAN_AVAILABILITY_BITMAP_TU;
    let max_slots = period_tu / NAN_AVAILABILITY_BITMAP_TU;
    if active_slots == 0 || start_slot.saturating_add(active_slots) > max_slots {
        bail!(
            "nan.active_ms={} does not fit the {}-TU availability period at offset {} TU",
            active_ms,
            period_tu,
            offset_tu
        );
    }
    let bitmap_len = ((start_slot + active_slots).saturating_add(7) / 8) as usize;
    let mut bitmap = vec![0_u8; bitmap_len];
    for bit in start_slot..start_slot + active_slots {
        bitmap[(bit / 8) as usize] |= 1 << (bit % 8);
    }

    // Attribute control: map 1, no change flags. Entry control: committed,
    // one receive spatial stream, and Time Bitmap Present. The one-entry
    // band list explicitly constrains this schedule to 2.4 GHz.
    let entry_len = 2 + 2 + 1 + bitmap.len() + 2;
    let attr_len = 1 + 2 + 2 + entry_len;
    let mut attr = Vec::with_capacity(3 + attr_len);
    attr.push(NAN_AVAILABILITY_ATTR_ID);
    attr.extend_from_slice(&(attr_len as u16).to_le_bytes());
    attr.push(1); // sequence ID for the initial stable schedule
    attr.extend_from_slice(&0x0001_u16.to_le_bytes()); // Map ID 1
    attr.extend_from_slice(&(entry_len as u16).to_le_bytes());
    attr.extend_from_slice(&0x1101_u16.to_le_bytes()); // committed + bitmap + RX NSS=1
    let bitmap_control = (period_code << 3) | ((offset_tu / NAN_AVAILABILITY_BITMAP_TU) << 6);
    attr.extend_from_slice(&bitmap_control.to_le_bytes()); // 16-TU bit duration
    attr.push(bitmap.len() as u8);
    attr.extend_from_slice(&bitmap);
    attr.extend_from_slice(&[0x10, 0x02]); // one band entry: 2.4 GHz
    Ok(attr)
}

fn nan_availability_from_settings(settings: &SharedSettings) -> Result<Vec<u8>> {
    let settings = settings.borrow();
    let dw_tu = settings.get_i32("nan.dw_tu", 512)?.clamp(128, 8_192) as u32;
    let offset_tu = settings.get_i32("nan.dw_off_tu", 0)?.max(0) as u32;
    let stride = settings.get_i32("nan.dw_stride", 4)?.clamp(1, 64) as u32;
    let active_ms = settings.get_i32("nan.active_ms", 250)?.clamp(16, 8_000) as u32;
    nan_availability_attribute(dw_tu, offset_tu, stride, active_ms)
}

fn nan_publish_frame(availability: &[u8]) -> Result<Vec<u8>> {
    let device_mac = station_mac()?;
    let tx_mac = super::wifi::raw_tx_source_mac()?;
    let cluster_bssid = nan_cluster_bssid();
    let subscribe_template = last_dmesh_subscribe_frame()
        .lock()
        .map_err(|_| anyhow!("NAN service descriptor capture lock poisoned"))?
        .clone();
    let template = if subscribe_template.is_empty() {
        last_dmesh_service_frame()
            .lock()
            .map_err(|_| anyhow!("NAN service descriptor capture lock poisoned"))?
            .clone()
    } else {
        subscribe_template
    };
    if !template.is_empty() {
        return nan_publish_frame_from_template(
            &template,
            &tx_mac,
            &device_mac,
            &cluster_bssid,
            availability,
        );
    }
    Ok(nan_publish_frame_for(
        &tx_mac,
        &device_mac,
        &cluster_bssid,
        availability,
    ))
}

/// Reuse a captured Android SDF for its interoperable NAN envelope while
/// replacing its service identity and Availability attribute with this ESP's
/// configured duty schedule.
fn nan_publish_frame_from_template(
    template: &[u8],
    tx_mac: &[u8; 6],
    device_mac: &[u8; 6],
    cluster_bssid: &[u8; 6],
    availability: &[u8],
) -> Result<Vec<u8>> {
    if template.len() < NAN_ACTION_START + 3 || template.len() > NAN_RX_FRAME_MAX {
        bail!(
            "invalid NAN service descriptor template length={}",
            template.len()
        );
    }
    if !is_nan_sdf(template) {
        bail!("captured frame is not a NAN service discovery frame");
    }
    let mut frame = template.to_vec();
    frame[FRAME_DST..FRAME_DST + 6].copy_from_slice(&NAN_DISCOVERY_MAC);
    frame[FRAME_SRC..FRAME_SRC + 6].copy_from_slice(tx_mac);
    frame[FRAME_BSSID..FRAME_BSSID + 6].copy_from_slice(cluster_bssid);

    let mut found_descriptor = false;
    let mut availability_range = None;
    let mut offset = NAN_ACTION_START;
    while offset + 3 <= frame.len() {
        let attr_id = frame[offset];
        let len = u16::from_le_bytes([frame[offset + 1], frame[offset + 2]]) as usize;
        let body_start = offset + 3;
        let body_end = body_start
            .checked_add(len)
            .ok_or_else(|| anyhow!("NAN attribute length overflow"))?;
        if body_end > frame.len() {
            // Promiscuous captures can retain a short trailing FCS/padding
            // fragment after otherwise complete Android attributes. Once the
            // DMesh SDA was rewritten, retain all preceding valid attributes
            // (including SDEA) rather than discarding the entire publish.
            if found_descriptor {
                break;
            }
            bail!("truncated NAN service descriptor attribute");
        }
        let body = &mut frame[body_start..body_end];
        if attr_id == 0x03 && body.len() >= 10 && body[..SVC_ID.len()] == SVC_ID {
            let info_len = body[9] as usize;
            if info_len != NAN_SERVICE_INFO_LEN || body.len() != 10 + info_len {
                bail!("unexpected DMesh service descriptor length={}", body.len());
            }
            // NAN service discovery frames stay on the NAN discovery multicast
            // address, including a solicited response to an active subscribe.
            // The Requestor Instance ID, not a unicast 802.11 destination,
            // binds this publish descriptor to the Android subscriber.
            let peer_instance = body[6];
            let peer_is_subscribe = body[8] & 0x03 == 0x01;
            body[6] = NAN_ID;
            body[7] = if peer_is_subscribe { peer_instance } else { 0 };
            body[8] = NAN_SERVICE_CONTROL_PUBLISH_WITH_INFO;
            body[10..10 + NAN_SERVICE_INFO_LEN].copy_from_slice(&nan_service_info(device_mac));
            found_descriptor = true;
        } else if attr_id == 0x0e && !body.is_empty() {
            // The Service Descriptor Extension is bound to the SDA by its
            // first instance-ID byte. A captured Android subscribe template
            // commonly has `2` here; leaving it after the SDA becomes our
            // publisher instance `1` makes the pair internally inconsistent.
            body[0] = NAN_ID;
        } else if attr_id == NAN_AVAILABILITY_ATTR_ID {
            availability_range = Some(offset..body_end);
        }
        offset = body_end;
    }
    if found_descriptor {
        if let Some(range) = availability_range {
            frame.splice(range, availability.iter().copied());
        } else {
            // A publish SDF requires Availability after the SDEA and Device
            // Capability attributes. Captured Android descriptors normally
            // have it; append only for a malformed/minimal capture.
            frame.extend_from_slice(availability);
        }
        Ok(frame)
    } else {
        bail!("captured NAN SDF has no DMesh service descriptor")
    }
}

/// Build the public Wi-Fi Aware publish SDF without reading hardware state.
/// Keeping this deterministic makes the wire ordering regression-testable.
fn nan_publish_frame_for(
    tx_mac: &[u8; 6],
    device_mac: &[u8; 6],
    cluster_bssid: &[u8; 6],
    availability: &[u8],
) -> Vec<u8> {
    let mut frame = NAN_HEADER.to_vec();
    frame[FRAME_DST..FRAME_DST + 6].copy_from_slice(&NAN_DISCOVERY_MAC);
    frame[FRAME_SRC..FRAME_SRC + 6].copy_from_slice(tx_mac);
    frame[FRAME_BSSID..FRAME_BSSID + 6].copy_from_slice(cluster_bssid);
    let service_info = nan_service_info(device_mac);
    let descriptor_len = SVC_ID.len() + 4 + service_info.len();
    // NAN v3.2 table 25 requires the publish SDA first, followed by the SDA
    // extension, device capability, and NAN availability. Android's NAN
    // implementation drops a descriptor that is syntactically valid but
    // violates this required ordering.
    frame.push(0x03);
    frame.extend_from_slice(&(descriptor_len as u16).to_le_bytes());
    frame.extend_from_slice(&SVC_ID);
    frame.push(NAN_ID);
    // No matching peer triggered this first-contact publish, so NAN requires
    // a zero requestor instance ID.
    frame.push(0);
    frame.push(NAN_SERVICE_CONTROL_PUBLISH_WITH_INFO);
    frame.push(service_info.len() as u8);
    frame.extend_from_slice(&service_info);
    frame.extend_from_slice(&NAN_SERVICE_EXTENSION);
    frame.extend_from_slice(&NAN_DEVICE_CAPABILITIES);
    frame.extend_from_slice(availability);
    frame
}

/// DMesh NAN service-specific information shared with the Android JNI and
/// lmesh radio protocol.  Keeping this wire shape identical lets Android
/// accept a raw ESP NAN publish as a normal `dmesh` service discovery event.
fn nan_service_info(mac: &[u8; 6]) -> [u8; NAN_SERVICE_INFO_LEN] {
    let mut info = [0_u8; NAN_SERVICE_INFO_LEN];
    info[0..2].copy_from_slice(b"DM");
    info[2] = 1;
    info[3] = 1; // firmware_publisher
    info[4] = 0;
    info[5..11].copy_from_slice(mac);
    // wake_count, last_len, and last_hash deliberately remain zero until the
    // raw-NAN scheduler owns per-advertisement payload metadata.
    info
}

fn nan_followup_frame(dst: &[u8; 6], instance: u8, data: &[u8]) -> Result<Vec<u8>> {
    let len = data.len().min(255);
    let mut frame = NAN_HEADER.to_vec();
    let mac = super::wifi::raw_tx_source_mac()?;
    let destination = if *dst == [0xff; 6] {
        &NAN_DISCOVERY_MAC
    } else {
        dst
    };
    frame[FRAME_DST..FRAME_DST + 6].copy_from_slice(destination);
    frame[FRAME_SRC..FRAME_SRC + 6].copy_from_slice(&mac);
    frame[FRAME_BSSID..FRAME_BSSID + 6].copy_from_slice(&nan_cluster_bssid());
    let sz = len + 6 + 4;
    frame.push(0x03);
    frame.push((sz & 0xff) as u8);
    frame.push((sz >> 8) as u8);
    frame.extend_from_slice(&SVC_ID);
    frame.push(NAN_ID);
    frame.push(instance);
    frame.push(0x12);
    frame.push(len as u8);
    frame.extend_from_slice(&data[..len]);
    Ok(frame)
}

fn station_mac() -> Result<[u8; 6]> {
    let mut mac = [0_u8; 6];
    unsafe {
        esp_ok(sys::esp_read_mac(
            mac.as_mut_ptr(),
            sys::esp_mac_type_t_ESP_MAC_WIFI_STA,
        ))?;
    }
    Ok(mac)
}

fn is_broadcast_target(value: &str) -> bool {
    let value = value.strip_prefix("0x").unwrap_or(value);
    value.eq_ignore_ascii_case("ffffffff")
        || value.eq_ignore_ascii_case("ff:ff:ff:ff")
        || value.eq_ignore_ascii_case("broadcast")
        || value.eq_ignore_ascii_case("all")
}

fn mac_suffix4_hex(mac: &[u8; 6]) -> String {
    format!("{:02x}{:02x}{:02x}{:02x}", mac[2], mac[3], mac[4], mac[5])
}

unsafe extern "C" fn sniffer_cb(
    buf: *mut core::ffi::c_void,
    type_: sys::wifi_promiscuous_pkt_type_t,
) {
    if type_ != sys::wifi_promiscuous_pkt_type_t_WIFI_PKT_MGMT || buf.is_null() {
        NAN_RX_OTHER.fetch_add(1, Ordering::Relaxed);
        return;
    }
    let pkt = unsafe { &*(buf as *const sys::wifi_promiscuous_pkt_t) };
    let len = pkt.rx_ctrl.sig_len() as usize;
    let payload = pkt.payload.as_ptr();
    if payload.is_null() || len < FRAME_DATA {
        NAN_RX_OTHER.fetch_add(1, Ordering::Relaxed);
        return;
    }
    if len > NAN_RX_FRAME_MAX {
        NAN_RX_OVERSIZE_DROPS.fetch_add(1, Ordering::Relaxed);
        return;
    }
    // This callback runs in the Wi-Fi driver task. Do the fixed-offset filter
    // before copying a complete management frame into the FreeRTOS queue.
    // Otherwise unrelated SDF/action traffic fills the queue before the main
    // task can reach a directed raw-NAN command.
    let frame = unsafe { core::slice::from_raw_parts(payload, len) };
    if !matches_filter(frame) && super::wifi::custom_raw_action_payload(frame).is_none() {
        NAN_RX_PREFILTER_DROPS.fetch_add(1, Ordering::Relaxed);
        return;
    }
    let queue = NAN_RX_QUEUE.load(Ordering::Acquire);
    if queue.is_null() {
        NAN_RX_QUEUE_DROPS.fetch_add(1, Ordering::Relaxed);
        return;
    }
    let mut received = RawNanRxFrame {
        len: len as u16,
        rssi: pkt.rx_ctrl.rssi() as i8,
        _reserved: 0,
        data: [0; NAN_RX_FRAME_MAX],
    };
    unsafe {
        core::ptr::copy_nonoverlapping(payload, received.data.as_mut_ptr(), len);
    }
    let sent = unsafe {
        sys::xQueueGenericSend(
            queue,
            (&received as *const RawNanRxFrame).cast::<c_void>(),
            0,
            0,
        )
    };
    if sent == 1 {
        super::wake::notify();
    } else {
        NAN_RX_QUEUE_DROPS.fetch_add(1, Ordering::Relaxed);
    }
}

pub fn observe_promiscuous_frame(frame: &[u8], _rssi: i32) {
    if !NAN_RUNNING.load(Ordering::Relaxed) {
        return;
    }
    NAN_RX_MGMT.fetch_add(1, Ordering::Relaxed);
    NAN_RX_BYTES.fetch_add(frame.len() as u32, Ordering::Relaxed);
    super::wifi::observe_promiscuous_frame(frame, _rssi);
    if frame.first() == Some(&0x80) {
        observe_sync_beacon(frame, _rssi);
    }
    let custom_raw_action = super::wifi::custom_raw_action_payload(frame);
    if custom_raw_action.is_none() && !matches_filter(frame) {
        return;
    }
    NAN_RX_MATCHED.fetch_add(1, Ordering::Relaxed);
    // AP recovery scans may observe many unrelated beacons. Keep their timing
    // state but do not retain every full beacon in bounded telemetry.
    if frame.first() != Some(&0x80) || is_nan_bssid(frame) || is_direct_dmesh_ssid(frame) {
        telemetry::record_packet(
            "wifi",
            Direction::Rx,
            frame,
            format!("source=nan subtype=0x{:02x}", frame[0]),
        );
    }
    match frame[0] {
        0x80 => {
            if is_nan_bssid(frame) {
                NAN_RX_BEACON.fetch_add(1, Ordering::Relaxed);
            }
        }
        0xd0 => {
            NAN_RX_ACTION.fetch_add(1, Ordering::Relaxed);
            let source = frame
                .get(FRAME_SRC..FRAME_SRC + 6)
                .and_then(|bytes| <&[u8] as TryInto<&[u8; 6]>>::try_into(bytes).ok())
                .copied();
            let foreign = source
                .and_then(|source| station_mac().ok().map(|mac| mac != source))
                .unwrap_or(false);
            if foreign && is_nan_followup(frame) {
                if let Ok(mut captured) = last_action_frame().lock() {
                    captured.clear();
                    captured.extend_from_slice(&frame[..frame.len().min(NAN_RX_FRAME_MAX)]);
                }
                store_u64(
                    &NAN_LAST_ACTION_LOCAL_LO,
                    &NAN_LAST_ACTION_LOCAL_HI,
                    now_us(),
                );
            }
            if let Some((source, payload)) = custom_raw_action {
                telemetry::record_log(format!(
                    "event type=wifi.raw_action_rx peer={} len={}",
                    format_mac(&source),
                    payload.len()
                ));
                telemetry::record_packet("wifi", Direction::Rx, payload, "source=raw_action");
            } else if is_nan_sdf(frame) {
                NAN_RX_SDF.fetch_add(1, Ordering::Relaxed);
                if let Some(info) = raw_command_info(frame) {
                    super::mode::observe_ping("nan_raw", info.payload);
                    if is_dmesh_nan_service_info(info.payload) {
                        if let Ok(mut captured) = last_dmesh_service_frame().lock() {
                            captured.clear();
                            captured.extend_from_slice(&frame[..frame.len().min(NAN_RX_FRAME_MAX)]);
                        }
                        if dmesh_service_descriptor_kind(frame) == Some(0x01) {
                            if let Ok(mut captured) = last_dmesh_subscribe_frame().lock() {
                                captured.clear();
                                captured
                                    .extend_from_slice(&frame[..frame.len().min(NAN_RX_FRAME_MAX)]);
                            }
                        }
                        store_u64(
                            &NAN_LAST_SERVICE_LOCAL_LO,
                            &NAN_LAST_SERVICE_LOCAL_HI,
                            now_us(),
                        );
                        NAN_DMESH_SERVICE_RX.fetch_add(1, Ordering::Relaxed);
                        telemetry::record_log(format!(
                            "event type=nan.dmesh_service_rx peer={} instance={} role={} device={}",
                            format_mac(&info.source),
                            info.instance,
                            info.payload[3],
                            format_mac(&info.payload[5..11].try_into().unwrap_or([0; 6]))
                        ));
                        return;
                    }
                    if let Some(dmesh) = parse_dmesh_nan_followup(info.payload) {
                        NAN_DMESH_FOLLOWUP_RX.fetch_add(1, Ordering::Relaxed);
                        record_followup_receipt(dmesh.msg_type, dmesh.seq, dmesh.payload);
                        let targets_this_device = station_mac()
                            .map(|mac| mac == dmesh.target_id)
                            .unwrap_or(false);
                        telemetry::record_log(format!(
                            "event type=nan.dmesh_followup_rx peer={} instance={} requestor_instance={} type={} seq={} device={} target={} len={} targeted={}",
                            format_mac(&info.source),
                            info.instance,
                            info.requestor_instance,
                            dmesh.msg_type,
                            dmesh.seq,
                            format_mac(&dmesh.device_id),
                            format_mac(&dmesh.target_id),
                            dmesh.payload.len(),
                            targets_this_device
                        ));
                        // Acknowledge every directed DMesh follow-up except an
                        // ACK itself. This covers Android hello, wake, and
                        // command-text probes without creating an ACK loop.
                        if targets_this_device && dmesh.msg_type != DMESH_NAN_ACK {
                            match station_mac()
                                .and_then(|local| {
                                    dmesh_nan_followup_frame(
                                        DMESH_NAN_ACK,
                                        dmesh.seq,
                                        &local,
                                        &dmesh.device_id,
                                        &[],
                                    )
                                })
                                .and_then(|payload| {
                                    enqueue_outgoing_raw(
                                        info.source,
                                        info.requestor_instance,
                                        &payload,
                                        true,
                                    )
                                })
                            {
                                Ok(queued) => {
                                    telemetry::record_log(format!(
                                        "event type=nan.dmesh_followup_ack queued={} peer={} seq={}",
                                        queued,
                                        format_mac(&info.source),
                                        dmesh.seq
                                    ));
                                }
                                Err(error) => telemetry::record_log(format!(
                                    "event type=nan.dmesh_followup_ack_error peer={} seq={} message={}",
                                    format_mac(&info.source),
                                    dmesh.seq,
                                    crate::commands::protocol::escape_value(&error.to_string())
                                )),
                            }
                        }
                        return;
                    }
                    telemetry::record_log(format!(
                        "event type=nan.raw_followup_rx peer={} instance={} len={}",
                        format_mac(&info.source),
                        info.instance,
                        info.payload.len()
                    ));
                    let decoded = crate::commands::protocol::decode_binary(info.payload);
                    let is_resp = decoded
                        .as_ref()
                        .map(|req| req.args.contains_key(&4) || req.args.contains_key(&5))
                        .unwrap_or(false);
                    telemetry::record_log(format!(
                        "event type=nan.raw_followup_rx.cbor_decode ok={} is_resp={}",
                        decoded.is_ok(),
                        is_resp
                    ));
                    if !station_mac().map(|mac| mac == info.source).unwrap_or(false) && is_resp {
                        telemetry::record_log(format!(
                            "event type=nan.raw_response_rx source={}",
                            format_mac(&info.source)
                        ));
                        NAN_RAW_RESPONSE_RX.fetch_add(1, Ordering::Relaxed);
                    } else {
                        enqueue_raw_command(info.source, info.instance, info.payload);
                    }
                }
            }
        }
        _ => {
            NAN_RX_OTHER.fetch_add(1, Ordering::Relaxed);
        }
    }
}

fn observe_sync_beacon(frame: &[u8], rssi: i32) {
    let Some(tsf_us) = beacon_tsf_us(frame) else {
        return;
    };
    let local_us = now_us();
    if is_nan_bssid(frame) {
        if let Ok(mut captured) = last_sync_beacon_frame().lock() {
            captured.clear();
            captured.extend_from_slice(&frame[..frame.len().min(NAN_RX_FRAME_MAX)]);
        }
        store_nan_cluster_bssid(frame);
        store_last_beacon_local_us(local_us);
        store_last_beacon_tsf_us(tsf_us);
        super::wifi::observe_beacon(frame);
        // Receive callbacks only capture the authoritative DW timestamp.
        // Queue draining/permit decisions belong to the normal mode task.
        super::wake::notify();
        return;
    }

    let Some(interval_tu) = beacon_interval_tu(frame) else {
        return;
    };
    let Some(bssid) = frame.get(FRAME_BSSID..FRAME_BSSID + 6) else {
        return;
    };
    AP_RX_BEACON.fetch_add(1, Ordering::Relaxed);
    store_u64(&AP_LAST_BEACON_LOCAL_LO, &AP_LAST_BEACON_LOCAL_HI, local_us);
    store_u64(&AP_LAST_BEACON_TSF_LO, &AP_LAST_BEACON_TSF_HI, tsf_us);
    AP_LAST_BEACON_INTERVAL_TU.store(interval_tu, Ordering::Relaxed);
    AP_LAST_BEACON_RSSI.store(rssi as u32, Ordering::Relaxed);
    for (index, byte) in bssid.iter().enumerate() {
        AP_LAST_BEACON_BSSID[index].store(*byte, Ordering::Relaxed);
    }
    AP_LAST_BEACON_DIRECT.store(is_direct_dmesh_ssid(frame), Ordering::Relaxed);
}

fn store_nan_cluster_bssid(frame: &[u8]) {
    let Some(bssid) = frame.get(FRAME_BSSID..FRAME_BSSID + 6) else {
        return;
    };
    for (index, byte) in bssid.iter().enumerate() {
        NAN_CLUSTER_BSSID[index].store(*byte, Ordering::Relaxed);
    }
}

fn nan_cluster_bssid() -> [u8; 6] {
    let mut bssid = [0_u8; 6];
    for (index, byte) in bssid.iter_mut().enumerate() {
        *byte = NAN_CLUSTER_BSSID[index].load(Ordering::Relaxed);
    }
    bssid
}

fn is_nan_bssid(frame: &[u8]) -> bool {
    frame.len() > FRAME_BSSID + 3
        && frame[FRAME_BSSID] == 0x50
        && frame[FRAME_BSSID + 1] == 0x6f
        && frame[FRAME_BSSID + 2] == 0x9a
}

fn beacon_tsf_us(frame: &[u8]) -> Option<u64> {
    let tsf = frame.get(FRAME_DATA..FRAME_DATA + 8)?;
    Some(u64::from_le_bytes(tsf.try_into().ok()?))
}

fn beacon_interval_tu(frame: &[u8]) -> Option<u32> {
    let bytes = frame.get(FRAME_DATA + 8..FRAME_DATA + 10)?;
    let interval = u16::from_le_bytes(bytes.try_into().ok()?) as u32;
    (interval >= 1).then_some(interval)
}

fn is_direct_dmesh_ssid(frame: &[u8]) -> bool {
    let mut offset = FRAME_DATA + 12;
    while offset + 2 <= frame.len() {
        let id = frame[offset];
        let len = frame[offset + 1] as usize;
        let start = offset + 2;
        let Some(end) = start.checked_add(len) else {
            return false;
        };
        if end > frame.len() {
            return false;
        }
        if id == 0 && frame[start..end].starts_with(b"DIRECT-DMESH-") {
            return true;
        }
        offset = end;
    }
    false
}

fn is_nan_sdf(frame: &[u8]) -> bool {
    frame.len() > NAN_ACTION_START
        && is_nan_bssid(frame)
        && frame[FRAME_DATA] == 0x04
        && frame[FRAME_DATA + 1] == 0x09
        && frame[FRAME_DATA + 2] == 0x50
        && frame[FRAME_DATA + 3] == 0x6f
        && frame[FRAME_DATA + 4] == 0x9a
        && frame[FRAME_DATA + 5] == 0x13
}

fn matches_filter(frame: &[u8]) -> bool {
    if NAN_FILTER_BSSID_ENABLED.load(Ordering::Relaxed) {
        if frame.len() < FRAME_BSSID + 6 {
            return false;
        }
        for idx in 0..6 {
            if frame[FRAME_BSSID + idx] != NAN_FILTER_BSSID[idx].load(Ordering::Relaxed) {
                return false;
            }
        }
    }
    match NAN_FILTER_MODE.load(Ordering::Relaxed) {
        FILTER_ALL_MGMT => true,
        FILTER_NAN => is_nan_bssid(frame),
        FILTER_ACTION => frame.first() == Some(&0xd0),
        FILTER_BEACON => frame.first() == Some(&0x80),
        FILTER_SDF => is_nan_sdf(frame),
        FILTER_SYNC => frame.first() == Some(&0x80) || is_nan_bssid(frame),
        _ => is_nan_bssid(frame),
    }
}

fn stats() -> String {
    let last_beacon_local_us = last_beacon_local_us();
    let last_beacon_tsf_us = last_beacon_tsf_us();
    let beacon_age_ms = if last_beacon_local_us == 0 {
        u64::MAX
    } else {
        now_us().saturating_sub(last_beacon_local_us) / 1000
    };
    let queue_len = nan_outgoing_queue()
        .lock()
        .map(|queue| queue.len())
        .unwrap_or(0);
    let publish_queue_len = nan_publish_queue()
        .lock()
        .map(|queue| queue.len())
        .unwrap_or(0);
    let ap = last_ap_sync_beacon();
    let ap_age_ms = ap_beacon_age_ms()
        .map(|value| value.to_string())
        .unwrap_or_else(|| "none".to_string());
    let ap_bssid = ap
        .map(|value| format_mac(&value.bssid))
        .unwrap_or_else(|| "none".to_string());
    let cluster_bssid = format_mac(&nan_cluster_bssid());
    format!(
        "nan support=raw running={} filter={} bssid_filter={} cluster_bssid={} raw_mgmt={} raw_matched={} raw_action={} raw_beacon={} sync_beacon_tx={} ap_beacon={} ap_bssid={} ap_direct={} ap_interval_tu={} ap_rssi={} ap_age_ms={} raw_sdf={} raw_other={} raw_bytes={} raw_cmd_rx={} raw_resp_rx={} raw_resp_tx={} dmesh_service_rx={} dmesh_followup_rx={} dmesh_followup_tx={} rx_prefilter_drop={} rx_queue_drop={} rx_oversize_drop={} last_beacon_local_us={} last_beacon_tsf_us={} beacon_age_ms={} queue_len={} publish_queue_len={} publish_last_beacon={}",
        NAN_RUNNING.load(Ordering::Relaxed),
        filter_name(),
        NAN_FILTER_BSSID_ENABLED.load(Ordering::Relaxed),
        cluster_bssid,
        NAN_RX_MGMT.load(Ordering::Relaxed),
        NAN_RX_MATCHED.load(Ordering::Relaxed),
        NAN_RX_ACTION.load(Ordering::Relaxed),
        NAN_RX_BEACON.load(Ordering::Relaxed),
        NAN_SYNC_BEACON_TX.load(Ordering::Relaxed),
        AP_RX_BEACON.load(Ordering::Relaxed),
        ap_bssid,
        ap.map(|value| value.direct).unwrap_or(false),
        ap.map(|value| value.interval_tu).unwrap_or(0),
        AP_LAST_BEACON_RSSI.load(Ordering::Relaxed) as i32,
        ap_age_ms,
        NAN_RX_SDF.load(Ordering::Relaxed),
        NAN_RX_OTHER.load(Ordering::Relaxed),
        NAN_RX_BYTES.load(Ordering::Relaxed),
        NAN_RAW_COMMAND_RX.load(Ordering::Relaxed),
        NAN_RAW_RESPONSE_RX.load(Ordering::Relaxed),
        NAN_RAW_RESPONSE_TX.load(Ordering::Relaxed),
        NAN_DMESH_SERVICE_RX.load(Ordering::Relaxed),
        NAN_DMESH_FOLLOWUP_RX.load(Ordering::Relaxed),
        NAN_DMESH_FOLLOWUP_TX.load(Ordering::Relaxed),
        NAN_RX_PREFILTER_DROPS.load(Ordering::Relaxed),
        NAN_RX_QUEUE_DROPS.load(Ordering::Relaxed),
        NAN_RX_OVERSIZE_DROPS.load(Ordering::Relaxed),
        last_beacon_local_us,
        last_beacon_tsf_us,
        beacon_age_ms,
        queue_len,
        publish_queue_len,
        NAN_LAST_PUBLISH_BEACON.load(Ordering::Relaxed)
    )
}

fn parse_filter_mode(value: &str) -> Result<u32> {
    match value {
        "mgmt" | "all" | "all_mgmt" => Ok(FILTER_ALL_MGMT),
        "nan" => Ok(FILTER_NAN),
        "action" => Ok(FILTER_ACTION),
        "beacon" => Ok(FILTER_BEACON),
        "sdf" => Ok(FILTER_SDF),
        "sync" => Ok(FILTER_SYNC),
        _ => bail!("unknown nan filter {value}"),
    }
}

fn filter_name() -> &'static str {
    match NAN_FILTER_MODE.load(Ordering::Relaxed) {
        FILTER_ALL_MGMT => "mgmt",
        FILTER_NAN => "nan",
        FILTER_ACTION => "action",
        FILTER_BEACON => "beacon",
        FILTER_SDF => "sdf",
        FILTER_SYNC => "sync",
        _ => "nan",
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn parse_bytes(value: &str) -> Result<Vec<u8>> {
    let value = value.strip_prefix("hex:").unwrap_or(value);
    if value.contains(',') {
        return value
            .split(',')
            .map(|v| Ok(parse_i32(v.trim())? as u8))
            .collect();
    }
    if value.len() % 2 != 0 {
        bail!("hex byte string must have even length");
    }
    (0..value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&value[i..i + 2], 16).map_err(Into::into))
        .collect()
}

fn parse_mac(value: &str) -> Result<[u8; 6]> {
    let parts = value.split(':').collect::<Vec<_>>();
    if parts.len() != 6 {
        bail!("MAC must have 6 colon-separated bytes");
    }
    let mut mac = [0_u8; 6];
    for (idx, part) in parts.iter().enumerate() {
        mac[idx] = u8::from_str_radix(part, 16).map_err(|err| anyhow!("invalid MAC: {err}"))?;
    }
    Ok(mac)
}

fn format_mac(mac: &[u8; 6]) -> String {
    mac.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn esp_ok(ret: sys::esp_err_t) -> Result<()> {
    if ret == sys::ESP_OK {
        Ok(())
    } else {
        bail!("esp_err=0x{ret:x}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_nan_publish_is_a_publish_with_required_attribute_order() {
        let tx_mac = [0xd8, 0xa0, 0x1d, 0x4c, 0x5e, 0x1d];
        let device_mac = [0xd8, 0xa0, 0x1d, 0x4c, 0x5e, 0x1c];
        let bssid = [0x50, 0x6f, 0x9a, 0x01, 0x55, 0x46];
        let availability = nan_availability_attribute(512, 0, 8, 250).unwrap();
        let frame = nan_publish_frame_for(&tx_mac, &device_mac, &bssid, &availability);

        assert_eq!(&frame[FRAME_DST..FRAME_DST + 6], NAN_DISCOVERY_MAC);
        assert_eq!(&frame[FRAME_SRC..FRAME_SRC + 6], tx_mac);
        assert_eq!(&frame[FRAME_BSSID..FRAME_BSSID + 6], bssid);

        let mut offset = NAN_ACTION_START;
        let mut attributes = Vec::new();
        while offset + 3 <= frame.len() {
            let id = frame[offset];
            let length = u16::from_le_bytes([frame[offset + 1], frame[offset + 2]]) as usize;
            let body_start = offset + 3;
            let body_end = body_start + length;
            assert!(body_end <= frame.len());
            attributes.push((id, &frame[body_start..body_end]));
            offset = body_end;
        }
        assert_eq!(
            attributes.iter().map(|(id, _)| *id).collect::<Vec<_>>(),
            [0x03, 0x0e, 0x0f, 0x12]
        );
        assert_eq!(attributes[0].1[7], 0);
        assert_eq!(attributes[0].1[8], NAN_SERVICE_CONTROL_PUBLISH_WITH_INFO);
        assert_eq!(&attributes[0].1[10..12], b"DM");
        assert_eq!(&attributes[0].1[15..21], device_mac);
        assert_eq!(attributes[3].1, &availability[3..]);
    }

    #[test]
    fn dmesh_nan_followup_round_trips_without_cbor() {
        let device = [0x30; 6];
        let target = [0xd8, 0xa0, 0x1d, 0x4c, 0x5e, 0x1c];
        let frame = dmesh_nan_followup_frame(1, 17, &device, &target, b"ping").unwrap();
        let parsed = parse_dmesh_nan_followup(&frame).unwrap();
        assert_eq!(parsed.msg_type, 1);
        assert_eq!(parsed.seq, 17);
        assert_eq!(parsed.device_id, device);
        assert_eq!(parsed.target_id, target);
        assert_eq!(parsed.payload, b"ping");
    }

    #[test]
    fn captured_sync_beacon_preserves_nan_attributes_and_updates_header() {
        let mac = [0xd8, 0xa0, 0x1d, 0x4c, 0x5e, 0x1c];
        let bssid = [0x50, 0x6f, 0x9a, 0x01, 0x55, 0x46];
        let mut template = vec![0; FRAME_DATA + 18];
        template[0] = 0x80;
        template[FRAME_BSSID..FRAME_BSSID + 6]
            .copy_from_slice(&[0x50, 0x6f, 0x9a, 0x01, 0x01, 0x02]);
        template[FRAME_DATA + 12..].copy_from_slice(b"nan-ie");

        let frame = nan_sync_beacon_frame_for(&template, &mac, &bssid, 42).unwrap();
        assert_eq!(&frame[FRAME_SRC..FRAME_SRC + 6], mac);
        assert_eq!(&frame[FRAME_BSSID..FRAME_BSSID + 6], bssid);
        assert_eq!(beacon_tsf_us(&frame), Some(42));
        assert_eq!(&frame[FRAME_DATA + 12..], b"nan-ie");
    }

    #[test]
    fn captured_service_descriptor_keeps_live_attributes_and_replaces_identity() {
        let old_mac = [0xc2, 0x17, 0x1e, 0x09, 0x88, 0x38];
        let tx_mac = [0xd8, 0xa0, 0x1d, 0x4c, 0x5e, 0x1d];
        let device_mac = [0xd8, 0xa0, 0x1d, 0x4c, 0x5e, 0x1c];
        let bssid = [0x50, 0x6f, 0x9a, 0x01, 0x55, 0x46];
        let old_availability = nan_availability_attribute(512, 0, 4, 250).unwrap();
        let availability = nan_availability_attribute(512, 0, 8, 250).unwrap();
        let mut template = nan_publish_frame_for(&old_mac, &old_mac, &bssid, &old_availability);
        // Model the Android subscribe SDF that is commonly the most recent
        // captured descriptor when both app sessions are active.
        let descriptor_start = NAN_ACTION_START + 3;
        template[descriptor_start + 6] = 2;
        template[descriptor_start + 7] = 0;
        template[descriptor_start + 8] = 0x11;
        template.extend_from_slice(&[0x0b, 0x02, 0x00, 0xaa, 0xbb]);

        let frame =
            nan_publish_frame_from_template(&template, &tx_mac, &device_mac, &bssid, &availability)
                .unwrap();
        assert_eq!(&frame[FRAME_SRC..FRAME_SRC + 6], tx_mac);
        assert_eq!(&frame[FRAME_DST..FRAME_DST + 6], NAN_DISCOVERY_MAC);
        assert_eq!(&frame[FRAME_BSSID..FRAME_BSSID + 6], bssid);
        assert_eq!(&frame[frame.len() - 5..], &[0x0b, 0x02, 0x00, 0xaa, 0xbb]);
        let descriptor = &frame[descriptor_start..descriptor_start + 31];
        assert_eq!(descriptor[6], NAN_ID);
        assert_eq!(descriptor[7], 2);
        assert_eq!(descriptor[8], NAN_SERVICE_CONTROL_PUBLISH_WITH_INFO);
        assert!(frame
            .windows(NAN_SERVICE_INFO_LEN)
            .any(|part| part == nan_service_info(&device_mac)));
        assert!(frame
            .windows(availability.len())
            .any(|part| part == availability));
    }

    #[test]
    fn availability_bitmap_matches_eight_512_tu_slot_schedule() {
        let availability = nan_availability_attribute(512, 0, 8, 250).unwrap();
        assert_eq!(availability[0], NAN_AVAILABILITY_ATTR_ID);
        // 250 ms rounds up to sixteen 16-TU bits, repeated every 4096 TU.
        assert_eq!(availability[3..6], [1, 1, 0]);
        let entry_start = 6;
        assert_eq!(
            u16::from_le_bytes([availability[entry_start], availability[entry_start + 1]]),
            9
        );
        assert_eq!(
            u16::from_le_bytes([availability[entry_start + 4], availability[entry_start + 5]]),
            0x0030
        );
        assert_eq!(availability[entry_start + 6], 2);
        assert_eq!(
            &availability[entry_start + 7..entry_start + 9],
            &[0xff, 0xff]
        );
        assert_eq!(
            &availability[entry_start + 9..entry_start + 11],
            &[0x10, 0x02]
        );
    }
}
