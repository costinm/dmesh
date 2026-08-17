use std::collections::VecDeque;
use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, AtomicPtr, AtomicU32, AtomicU8, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use esp_idf_sys as sys;

use crate::commands::{CommandHandler, CommandRegistry, CommandRequest, CommandResponse};
use dmesh_rawnan as shared_nan;
use shared_nan::metrics::*;
use shared_nan::{
    NAN_CLUSTER_BSSID_DEFAULT as NAN_BSSID, NAN_COMMAND_MAX_LEN, NAN_COMMAND_TIMEOUT_KEY,
    NAN_DEFAULT_CHANNEL as DEFAULT_CHANNEL, NAN_DW_CONTROL_KEY, NAN_DW_DONE, NAN_DW_MORE,
    NAN_DW_UNITS_SHIFT, NAN_REQUEST_ID_KEY, NAN_RX_FRAME_MAX,
};

use super::object_store::NanObjectService;
use super::settings::{parse_bool, parse_i32, SharedSettings};
use super::telemetry::{self, Direction};

const NAN_ID: u8 = 1;
// These offsets are shared wire constants.  Keep hardware-specific code
// (callbacks, TSF sampling, queues, and TX scheduling) below this boundary;
// changing an offset here would change the Android/Linux/ESP on-air ABI.
const FRAME_DST: usize = shared_nan::FRAME_DST;
const FRAME_SRC: usize = shared_nan::FRAME_SRC;
const FRAME_BSSID: usize = shared_nan::FRAME_BSSID;
const FRAME_DATA: usize = shared_nan::FRAME_DATA;
const OBJECT_LLC_SNAP: [u8; 8] = [0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x88, 0xb5];
const OBJECT_DMESH_MARKER: [u8; 4] = [0x7f, 0x18, 0xfe, 0x34];
const OBJECT_DMESH_MARKER_TYPE: u8 = 0x04;
const NAN_ACTION_START: usize = shared_nan::NAN_ACTION_START;
const SVC_ID: [u8; 6] = shared_nan::DMESH_SERVICE_ID;
// Public Wi-Fi Aware action frames use the NAN discovery MAC for broadcast
// discovery/follow-up traffic, not the Ethernet broadcast address.
const NAN_DISCOVERY_MAC: [u8; 6] = shared_nan::NAN_DISCOVERY_MAC;
const DEFAULT_SERVICE: &str = "dmesh";
const NAN_COMMAND_QUEUE_MAX: usize = 8;
const NAN_OUTGOING_QUEUE_MAX: usize = 10;
// Do not retain responses beyond two 512-TU NAN intervals. A missing sync
// source should cause a bounded retry, not unbounded buffer growth.
const NAN_OUTGOING_MAX_AGE_MS: u64 = 9_000;
const NAN_FOLLOWUP_HISTORY_LEN: usize = 32;
// Keep a short source-indexed history because an observer can hear several
// phones at once.  A single "last service descriptor" cannot prove which
// publisher produced a later test burst.
const NAN_SERVICE_HISTORY_LEN: usize = 32;
// A sleepy receiver can hear several cluster beacons during one active
// window. Keep their bounded TSF history so the scheduler can prove that the
// selected DW was received even when a later beacon becomes the "last" one.
const NAN_BEACON_HISTORY_LEN: usize = 64;
// Optional command argument carried inside the compact-CBOR args map.  The
// low two bits are DW continuation state (MORE/DONE); bits 2..7 request that
// many additional 512-TU units of awake time.  The gateway adds this byte at
// enqueue time, so older callers do not need to know about the hint.
// The regular command `timeout` argument (tag 41) is also a wire-level
// response deadline.  Keep a separate named constant here so the raw-NAN
// scheduler documents that it is intentionally used to hold a sleepy target
// awake while the command is executed and its response is queued.
// Per-command correlation token. The gateway copies this into the response
// so delayed status/active records cannot satisfy a later request.
const NAN_RX_QUEUE_LEN: u32 = 8;
// A synchronized 512-TU NAN cluster beacon is normally visible at least once
// per raw-NAN wake.  Do not replace the chosen cluster merely because another
// nearby NAN cluster happens to transmit in the same receive window.  After
// this bounded absence the next valid cluster can become the new authority.
const NAN_CLUSTER_RESELECT_AFTER_US: u64 = 3 * 512 * 1024;
// NAN beacons, SDFs, and the DMesh action payload all fit below this bound.
// Drop unusual large management frames in the Wi-Fi callback rather than
// parsing or allocating in the driver task.
// Raw action frames carry up to the 1200-byte DMesh payload plus the
// 802.11/vendor header. Keep enough room for the complete frame so the NAN
// queue does not discard bulk transport packets as oversize.
const NAN_TX_DWELL_US: u64 = shared_nan::NAN_TX_DWELL_US;

static NAN_RUNNING: AtomicBool = AtomicBool::new(false);
static NAN_OBJECT_SERVICE: OnceLock<Mutex<NanObjectService>> = OnceLock::new();
// Raw-NAN work queues are deliberately bounded.  Keep explicit drop counters
// so a saturated node is observable and the higher-level sender can retry;
// never grow these queues with unbounded radio input.
// Service descriptors are released only from the post-beacon DW drain. Keep
// bounded counters so a hardware test can prove that invariant from runtime
// evidence, not merely from the command's `sync=true` acknowledgement.
// Infrastructure peers advertise periodically even when no console command
// has primed the publish queue.  This makes the lmesh-wifi discovery test and
// sleepy-peer rendezvous self-starting while retaining the DW retransmission
// path for devices that were asleep during the immediate transmission.
// Bounded timing evidence for the last Android DMesh service descriptor and
// follow-up. A powered observer uses these fields to place Android traffic on
// the NAN 512-TU timeline without retaining packet history.
static NAN_RX_QUEUE: AtomicPtr<sys::QueueDefinition> = AtomicPtr::new(core::ptr::null_mut());
static NAN_HW_FILTER_ENABLED: AtomicBool = AtomicBool::new(true);
static NAN_IPV6_UDP_RX: AtomicU32 = AtomicU32::new(0);
static NAN_IPV6_UDP_BYTES: AtomicU32 = AtomicU32::new(0);
// The NAN cluster ID is learned from the first synchronized beacon. It stays
// sticky while that cluster remains fresh: nearby clusters have independent
// TSF timelines and must not replace the timing authority mid-window.
static NAN_CLUSTER_BSSID: [AtomicU8; 6] = [
    AtomicU8::new(NAN_BSSID[0]),
    AtomicU8::new(NAN_BSSID[1]),
    AtomicU8::new(NAN_BSSID[2]),
    AtomicU8::new(NAN_BSSID[3]),
    AtomicU8::new(NAN_BSSID[4]),
    AtomicU8::new(NAN_BSSID[5]),
];
// Source-aware beacon timing evidence. These counters are deliberately
// separate from raw management/action/SDF counters: only accepted beacon
// subtype frames update them.
const BEACON_STATS_NONE: u32 = 0;
const BEACON_STATS_NAN: u32 = 1;
const BEACON_STATS_AP: u32 = 2;
const BEACON_STATS_RAW: u32 = 3;
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

// The hardware filter is deliberately a small state machine rather than a
// permanent setting.  Discovery starts unfiltered, then the first accepted
// cluster beacon arms the exact BSSID comparator.  If that beacon goes stale,
// the comparator is released again so a replacement cluster can be learned.
const NAN_HW_FILTER_DISCOVERY: u8 = 0;
const NAN_HW_FILTER_ARMED: u8 = 1;
static NAN_HW_FILTER_STATE: AtomicU8 = AtomicU8::new(NAN_HW_FILTER_DISCOVERY);
static NAN_HW_FILTER_ARMS: AtomicU32 = AtomicU32::new(0);
static NAN_HW_FILTER_REPROBES: AtomicU32 = AtomicU32::new(0);
static NAN_HW_FILTER_ERRORS: AtomicU32 = AtomicU32::new(0);

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

const NAN_AVAILABILITY_ATTR_ID: u8 = 0x12;
const NAN_TU_US: u32 = shared_nan::NAN_TU_US;
const NAN_AVAILABILITY_BITMAP_TU: u32 = shared_nan::NAN_AVAILABILITY_BITMAP_TU;

const NAN_SERVICE_INFO_LEN: usize = 21;
const NAN_SERVICE_FLAG_UART_WAKE: u8 = 0x80;
const NAN_SERVICE_FLAG_BLE_WAKE: u8 = 0x40;
const NAN_SERVICE_FLAG_ACTIVE_ACK: u8 = 0x20;
// TODO: reserve another service-info flag for a stronger "I really want to
// talk" advertisement that also asks the target to enable STA and associate
// with the infrastructure AP. Keep the current control radio-only until that
// association path has explicit power and security tests.
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
// The raw worker receives Subscribe SDFs in task context.  Cache only the
// standards-generated optional attributes needed to form its bounded
// solicited Publish response; never retain or rewrite a peer's frame.
static NAN_SOLICITED_PUBLISH_ATTRIBUTES: OnceLock<Mutex<Option<NanPublishAttributes>>> =
    OnceLock::new();
// Bounded evidence for scheduled Android follow-up probes.  This is filled by
// the worker after DMesh parsing, never by the Wi-Fi callback.
static NAN_FOLLOWUP_HISTORY: OnceLock<Mutex<VecDeque<NanFollowupReceipt>>> = OnceLock::new();
static NAN_SERVICE_HISTORY: OnceLock<Mutex<VecDeque<NanServiceReceipt>>> = OnceLock::new();
static NAN_RAW_RESPONSE_HISTORY: OnceLock<Mutex<VecDeque<RawResponseReceipt>>> = OnceLock::new();
static NAN_FOLLOWUP_DEDUP: OnceLock<Mutex<shared_nan::service::FollowupDedup>> = OnceLock::new();

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
    enqueued_ms: u64,
}

type NanFollowupReceipt = shared_nan::service::FollowupReceipt;
type NanServiceReceipt = shared_nan::service::ServiceReceipt;
type RawResponseReceipt = shared_nan::service::ResponseReceipt;

#[derive(Clone, Debug)]
struct NanPublishAttributes {
    availability: Vec<u8>,
    device_capabilities: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NanDiscoveryRole {
    Publisher,
    PublisherSolicited,
    Subscriber,
    Both,
}

impl NanDiscoveryRole {
    fn parse(value: &str) -> Result<Self> {
        match value {
            "publish" | "publisher" => Ok(Self::Publisher),
            "publisher_solicited" => Ok(Self::PublisherSolicited),
            "subscribe" | "subscriber" => Ok(Self::Subscriber),
            "both" => Ok(Self::Both),
            _ => bail!("nan role must be publisher, publisher_solicited, subscriber, or both"),
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Publisher => "publisher",
            Self::PublisherSolicited => "publisher_solicited",
            Self::Subscriber => "subscriber",
            Self::Both => "both",
        }
    }

    fn responds_to_subscribe(self) -> bool {
        matches!(self, Self::PublisherSolicited | Self::Both)
    }

    fn code(self) -> u8 {
        match self {
            Self::Publisher => 0,
            Self::PublisherSolicited => 1,
            Self::Subscriber => 2,
            Self::Both => 3,
        }
    }

    fn from_code(code: u8) -> Self {
        match code {
            1 => Self::PublisherSolicited,
            2 => Self::Subscriber,
            3 => Self::Both,
            _ => Self::Publisher,
        }
    }
}

fn configured_discovery_role() -> Result<NanDiscoveryRole> {
    Ok(NanDiscoveryRole::from_code(
        NAN_DISCOVERY_ROLE.load(Ordering::Relaxed),
    ))
}

#[repr(C)]
struct RawNanRxFrame {
    len: u16,
    rssi: i8,
    _reserved: u8,
    // Captured in the Wi-Fi callback before bounded worker-queue delay.
    local_us: u64,
    data: [u8; NAN_RX_FRAME_MAX],
}

// The promiscuous callback runs on the Wi-Fi task. Keep the large frame
// scratch buffer out of that task's stack; xQueueGenericSend copies it before
// the callback returns.
static mut NAN_RX_SCRATCH: RawNanRxFrame = RawNanRxFrame {
    len: 0,
    rssi: 0,
    _reserved: 0,
    local_us: 0,
    data: [0; NAN_RX_FRAME_MAX],
};

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

/// Drop queued wire transmissions when their discovery-session context ends.
///
/// A solicited Publish binds a particular received Subscribe instance.  It
/// must never be sent after changing role or stopping NAN, even if the next
/// command happens to be an otherwise valid unsolicited Publish.
fn clear_pending_nan_transmissions() {
    if let Ok(mut queue) = nan_publish_queue().lock() {
        queue.clear();
    }
    if let Ok(mut queue) = nan_outgoing_queue().lock() {
        queue.clear();
    }
}

fn set_discovery_role(role: NanDiscoveryRole) {
    let previous = NAN_DISCOVERY_ROLE.swap(role.code(), Ordering::Relaxed);
    if previous != role.code() {
        clear_pending_nan_transmissions();
    }
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

fn solicited_publish_attributes() -> &'static Mutex<Option<NanPublishAttributes>> {
    NAN_SOLICITED_PUBLISH_ATTRIBUTES.get_or_init(|| Mutex::new(None))
}

fn set_solicited_publish_attributes(settings: &SharedSettings) -> Result<()> {
    let (availability, device_capabilities) = nan_publish_attributes(settings, 1)?;
    let mut attributes = solicited_publish_attributes()
        .lock()
        .map_err(|_| anyhow!("NAN solicited publish attributes lock poisoned"))?;
    *attributes = Some(NanPublishAttributes {
        availability,
        device_capabilities,
    });
    Ok(())
}

fn queue_solicited_publish(requestor_instance: u8) -> Result<usize> {
    if requestor_instance == 0 {
        bail!("solicited publish requires a nonzero subscriber instance ID");
    }
    let attributes = solicited_publish_attributes()
        .lock()
        .map_err(|_| anyhow!("NAN solicited publish attributes lock poisoned"))?
        .clone()
        .ok_or_else(|| anyhow!("NAN solicited publish attributes are not configured"))?;
    let frame = nan_publish_frame_with_requestor(
        &attributes.availability,
        &attributes.device_capabilities,
        true,
        2,
        requestor_instance,
    )?;
    let mut queue = nan_publish_queue()
        .lock()
        .map_err(|_| anyhow!("nan publish queue lock failed"))?;
    if queue.len() >= NAN_OUTGOING_QUEUE_MAX {
        queue.pop_front();
    }
    queue.push_back(frame);
    Ok(queue.len())
}

fn followup_history() -> &'static Mutex<VecDeque<NanFollowupReceipt>> {
    NAN_FOLLOWUP_HISTORY
        .get_or_init(|| Mutex::new(VecDeque::with_capacity(NAN_FOLLOWUP_HISTORY_LEN)))
}

fn service_history() -> &'static Mutex<VecDeque<NanServiceReceipt>> {
    NAN_SERVICE_HISTORY.get_or_init(|| Mutex::new(VecDeque::with_capacity(NAN_SERVICE_HISTORY_LEN)))
}

fn record_service_receipt(info: &RawNanCommandInfo<'_>, kind: u8, local_us: u64) {
    let Some(device_id) = info
        .payload
        .get(5..11)
        .and_then(|bytes| bytes.try_into().ok())
    else {
        return;
    };
    let receipt = NanServiceReceipt {
        local_us,
        source: info.source,
        device_id,
        instance: info.instance,
        kind,
    };
    if let Ok(mut history) = service_history().lock() {
        if history.len() == NAN_SERVICE_HISTORY_LEN {
            history.pop_front();
        }
        history.push_back(receipt);
    }
}

fn render_service_history() -> Result<String> {
    let history = service_history()
        .lock()
        .map_err(|_| anyhow!("NAN service history lock poisoned"))?;
    if history.is_empty() {
        return Ok("nan service_history=empty".to_string());
    }
    let entries = history
        .iter()
        .map(|entry| {
            let kind = match entry.kind {
                0 => "publish",
                1 => "subscribe",
                2 => "followup",
                _ => "reserved",
            };
            format!(
                "local_us:{}:source:{}:device:{}:instance:{}:kind:{}",
                entry.local_us,
                format_mac(&entry.source),
                format_mac(&entry.device_id),
                entry.instance,
                kind,
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    Ok(format!(
        "nan service_history count={} entries={}",
        history.len(),
        entries
    ))
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

fn raw_response_history() -> &'static Mutex<VecDeque<RawResponseReceipt>> {
    NAN_RAW_RESPONSE_HISTORY.get_or_init(|| Mutex::new(VecDeque::with_capacity(16)))
}

fn record_raw_response(source: [u8; 6], payload: &[u8]) {
    if let Ok(mut history) = raw_response_history().lock() {
        if history.len() >= 16 {
            history.pop_front();
        }
        history.push_back(RawResponseReceipt {
            local_us: now_us(),
            source,
            payload: payload[..payload.len().min(NAN_COMMAND_MAX_LEN)].to_vec(),
        });
    }
}

fn render_raw_response_history() -> Result<String> {
    const MAX_ENTRIES: usize = 6;
    const MAX_TEXT: usize = 3_200;
    let history = raw_response_history()
        .lock()
        .map_err(|_| anyhow!("NAN raw response history lock poisoned"))?;
    if history.is_empty() {
        return Ok("nan response_history=empty".to_string());
    }
    // This is queried over the same bounded UART record as normal commands.
    // Keep the response below the firmware CBOR/PPP budget and retain the
    // newest receipts, which are the only ones useful for command matching.
    let mut selected = history.iter().rev().take(MAX_ENTRIES).collect::<Vec<_>>();
    selected.reverse();
    let mut entries = String::new();
    for entry in selected {
        let item = format!(
            "local_us:{}:source:{}:payload_hex:{}",
            entry.local_us,
            format_mac(&entry.source),
            encode_hex(&entry.payload)
        );
        if entries.len().saturating_add(item.len()).saturating_add(1) > MAX_TEXT {
            break;
        }
        if !entries.is_empty() {
            entries.push(',');
        }
        entries.push_str(&item);
    }
    Ok(format!(
        "nan response_history count={} entries={}",
        history.len(),
        entries
    ))
}

pub fn take_command() -> Option<NanIncomingCommand> {
    let command = nan_command_queue().lock().ok()?.pop_front();
    if command.is_some() {
        NAN_RAW_COMMAND_PENDING.fetch_sub(1, Ordering::Relaxed);
    }
    command
}

/// Drain management frames copied by the Wi-Fi callback.
///
/// The Wi-Fi promiscuous callback runs in a driver task. It must not allocate,
/// lock telemetry, parse payloads, or dispatch commands, otherwise action
/// traffic can starve the Wi-Fi interrupt path and trigger an interrupt WDT.
pub fn poll_rx() {
    let queue = NAN_RX_QUEUE.load(Ordering::Acquire);
    if queue.is_null() {
        reconcile_hardware_bssid_filter();
        return;
    }
    loop {
        let mut received = core::mem::MaybeUninit::<RawNanRxFrame>::uninit();
        let ok = unsafe { sys::xQueueReceive(queue, received.as_mut_ptr().cast::<c_void>(), 0) };
        if ok != 1 {
            reconcile_hardware_bssid_filter();
            return;
        }
        let received = unsafe { received.assume_init() };
        let len = usize::from(received.len).min(NAN_RX_FRAME_MAX);
        // Object transfer uses the selected NAN cluster as address3 and is
        // parsed outside the Wi-Fi callback. Data and action frames share the
        // same bounded envelope; management frames continue through NAN's
        // discovery parser below.
        if len >= FRAME_DATA && (received.data[0] & 0x0c) == 0x08 {
            if let Ok(mut service) = NAN_OBJECT_SERVICE
                .get_or_init(|| Mutex::new(NanObjectService::new()))
                .lock()
            {
                // Only dispatch frames carrying the explicit DMesh object
                // wrapper. Other NAN/AP data traffic must not inflate the
                // object rejection counter or enter the object protocol.
                let wrapped = &received.data[FRAME_DATA..len];
                if wrapped.starts_with(&OBJECT_LLC_SNAP)
                    && wrapped.len() >= OBJECT_LLC_SNAP.len() + 9
                    && wrapped[OBJECT_LLC_SNAP.len()..].starts_with(&OBJECT_DMESH_MARKER)
                {
                    let payload = &wrapped[OBJECT_LLC_SNAP.len() + 9..];
                    let _ = service.observe(payload);
                }
                if wrapped.len() >= 8 + 40 + 8
                    && wrapped[..6] == [0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00]
                    && wrapped[6..8] == [0x86, 0xdd]
                    && wrapped[8] >> 4 == 6
                    && wrapped[14] == 17
                {
                    let udp_payload_len = u16::from_be_bytes([wrapped[12], wrapped[13]]) as usize;
                    if udp_payload_len >= 8 && 8 + 40 + udp_payload_len <= wrapped.len() {
                        NAN_IPV6_UDP_RX.fetch_add(1, Ordering::Relaxed);
                        NAN_IPV6_UDP_BYTES.fetch_add(
                            (udp_payload_len - 8).min(u32::MAX as usize) as u32,
                            Ordering::Relaxed,
                        );
                    }
                }
            }
        }
        observe_promiscuous_frame_at(
            &received.data[..len],
            received.rssi as i32,
            received.local_us,
        );
    }
}

pub fn object_service_start() {
    NAN_OBJECT_SERVICE
        .get_or_init(|| Mutex::new(NanObjectService::new()))
        .lock()
        .ok()
        .map(|mut s| s.start());
}

pub fn object_service_stop() {
    if let Some(service) = NAN_OBJECT_SERVICE.get() {
        service.lock().ok().map(|mut s| s.stop());
    }
}

fn object_service_active() -> bool {
    NAN_OBJECT_SERVICE
        .get()
        .and_then(|service| service.lock().ok().map(|s| s.active()))
        .unwrap_or(false)
}

pub fn object_service_stats() -> super::object_store::Stats {
    NAN_OBJECT_SERVICE
        .get_or_init(|| Mutex::new(NanObjectService::new()))
        .lock()
        .map(|s| s.stats())
        .unwrap_or_default()
}

/// Feed an object-store envelope received on the action-frame bearer into the
/// same bounded receiver used by NAN data frames.  The action parser runs in
/// the deferred radio task, never from the Wi-Fi callback.
pub fn object_service_observe_action(frame: &[u8]) -> bool {
    let accepted = NAN_OBJECT_SERVICE
        .get_or_init(|| Mutex::new(NanObjectService::new()))
        .lock()
        .ok()
        .and_then(|mut service| service.observe(frame))
        .is_some();
    if accepted {
        NAN_OBJECT_ACTION_ACCEPTED.fetch_add(1, Ordering::Relaxed);
    }
    accepted
}

pub fn register_commands(registry: &mut CommandRegistry, settings: SharedSettings) {
    registry.register(NanCommand::new(settings));
}

pub fn forward_packet(packet: &[u8]) -> Result<()> {
    if NAN_RUNNING.load(Ordering::Relaxed) {
        let frame = nan_followup_frame(&[0xff; 6], NAN_ID, packet)?;
        nan_control_rate()?;
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
    super::wifi::reset_raw_first_frame();
    start_raw_sniffer(channel.max(1))?;
    // A direct Wi-Fi mode transition also starts NAN, bypassing NanCommand's
    // settings-bearing path. Prime several infrastructure publishes here so
    // the first lmesh-wifi USD interval is self-starting; DW draining repeats
    // the retained frames even if the immediate TX is missed.
    if super::mode::infra_mode() {
        prime_infra_publish();
    }
    Ok(())
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

/// Return the selected NAN-cluster timing snapshot for the sleepy scheduler.
/// This excludes unrelated AP beacons that may be visible in the same active
/// window; AP fallback timing is exposed separately by `last_ap_sync_beacon`.
pub fn nan_beacon_snapshot() -> super::wifi::BeaconSnapshot {
    super::wifi::BeaconSnapshot {
        count: NAN_RX_BEACON.load(Ordering::Relaxed),
        local_us: last_beacon_local_us(),
        tsf_us: last_beacon_tsf_us(),
    }
}

pub fn nan_cluster_reselects() -> u32 {
    NAN_CLUSTER_RESELECTS.load(Ordering::Relaxed)
}

/// Render the bounded TSF/local history used by the sleepy scheduler. This is
/// intentionally compact so an always-on observer can be compared with a
/// sleepy node without retaining full beacon frames.
fn render_beacon_history() -> String {
    let newest = NAN_RX_BEACON.load(Ordering::Relaxed);
    let mut entries = Vec::new();
    for offset in 0..NAN_BEACON_HISTORY_LEN {
        let sequence = newest.saturating_sub(offset as u32);
        if sequence == 0 {
            break;
        }
        let index = (sequence as usize) % NAN_BEACON_HISTORY_LEN;
        if NAN_BEACON_HISTORY_SEQ[index].load(Ordering::Acquire) != sequence {
            continue;
        }
        let tsf_us = load_u64(
            &NAN_BEACON_HISTORY_TSF_LO[index],
            &NAN_BEACON_HISTORY_TSF_HI[index],
        );
        let local_us = load_u64(
            &NAN_BEACON_HISTORY_LOCAL_LO[index],
            &NAN_BEACON_HISTORY_LOCAL_HI[index],
        );
        let mut source = [0_u8; 6];
        for (byte, value) in source.iter_mut().enumerate() {
            *value = NAN_BEACON_HISTORY_SOURCE[index][byte].load(Ordering::Relaxed);
        }
        entries.push(format!(
            "{}:{}:{}:{}",
            sequence,
            tsf_us,
            local_us,
            format_mac(&source)
        ));
    }
    format!(
        "nan beacon_history count={} entries={}",
        entries.len(),
        entries.join(",")
    )
}

fn beacon_stats_source_name(source: u32) -> &'static str {
    match source {
        BEACON_STATS_NAN => "nan",
        BEACON_STATS_AP => "ap",
        BEACON_STATS_RAW => "raw",
        _ => "none",
    }
}

fn beacon_stats_bssid() -> [u8; 6] {
    let mut bssid = [0_u8; 6];
    for (index, byte) in bssid.iter_mut().enumerate() {
        *byte = BEACON_STATS_BSSID[index].load(Ordering::Relaxed);
    }
    bssid
}

fn store_beacon_stats_bssid(bssid: [u8; 6]) {
    for (index, byte) in bssid.iter().enumerate() {
        BEACON_STATS_BSSID[index].store(*byte, Ordering::Relaxed);
    }
}

/// Clear the bounded accepted-beacon timing reference.
#[cfg(test)]
fn legacy_reset_beacon_stats() {
    BEACON_STATS_SOURCE.store(BEACON_STATS_NONE, Ordering::Relaxed);
    store_beacon_stats_bssid([0; 6]);
    BEACON_STATS_INTERVAL_TU.store(512, Ordering::Relaxed);
    BEACON_STATS_STRIDE.store(8, Ordering::Relaxed);
    for cell in [
        &BEACON_STATS_FIRST_TSF_LO,
        &BEACON_STATS_FIRST_TSF_HI,
        &BEACON_STATS_LAST_TSF_LO,
        &BEACON_STATS_LAST_TSF_HI,
        &BEACON_STATS_LAST_LOCAL_LO,
        &BEACON_STATS_LAST_LOCAL_HI,
        &BEACON_STATS_LAST_SLOT_LO,
        &BEACON_STATS_LAST_SLOT_HI,
        &BEACON_STATS_LAST_SELECTED_SLOT_LO,
        &BEACON_STATS_LAST_SELECTED_SLOT_HI,
    ] {
        cell.store(0, Ordering::Relaxed);
    }
    BEACON_STATS_LAST_PHASE.store(0, Ordering::Relaxed);
    BEACON_STATS_ACCEPTED.store(0, Ordering::Relaxed);
    BEACON_STATS_SELECTED_SEEN.store(0, Ordering::Relaxed);
    BEACON_STATS_SELECTED_MISSED.store(0, Ordering::Relaxed);
    BEACON_STATS_DUPLICATES.store(0, Ordering::Relaxed);
    BEACON_STATS_TSF_REGRESSIONS.store(0, Ordering::Relaxed);
    BEACON_STATS_PHASE_MIN.store(u32::MAX, Ordering::Relaxed);
    BEACON_STATS_PHASE_MAX.store(0, Ordering::Relaxed);
    BEACON_STATS_LOCAL_DELTA_MIN.store(u32::MAX, Ordering::Relaxed);
    BEACON_STATS_LOCAL_DELTA_MAX.store(0, Ordering::Relaxed);
    BEACON_STATS_TSF_DELTA_MIN.store(u32::MAX, Ordering::Relaxed);
    BEACON_STATS_TSF_DELTA_MAX.store(0, Ordering::Relaxed);
}

#[cfg(test)]
fn legacy_record_beacon_stats(
    source: u32,
    bssid: [u8; 6],
    tsf_us: u64,
    local_us: u64,
    interval_tu: u32,
    stride: u32,
) {
    let current_source = BEACON_STATS_SOURCE.load(Ordering::Acquire);
    if current_source != source || beacon_stats_bssid() != bssid {
        legacy_reset_beacon_stats();
        BEACON_STATS_SOURCE.store(source, Ordering::Release);
        store_beacon_stats_bssid(bssid);
    }
    let interval_tu = interval_tu.max(1);
    let stride = stride.max(1);
    BEACON_STATS_INTERVAL_TU.store(interval_tu, Ordering::Relaxed);
    BEACON_STATS_STRIDE.store(stride, Ordering::Relaxed);
    let period_us = u64::from(interval_tu).saturating_mul(1024);
    let slot = tsf_us / period_us;
    let phase = (tsf_us % period_us).min(u64::from(u32::MAX)) as u32;
    let last_tsf = load_u64(&BEACON_STATS_LAST_TSF_LO, &BEACON_STATS_LAST_TSF_HI);
    let last_local = load_u64(&BEACON_STATS_LAST_LOCAL_LO, &BEACON_STATS_LAST_LOCAL_HI);
    if last_tsf != 0 {
        if tsf_us < last_tsf {
            BEACON_STATS_TSF_REGRESSIONS.fetch_add(1, Ordering::Relaxed);
        } else {
            let delta = tsf_us.saturating_sub(last_tsf).min(u64::from(u32::MAX)) as u32;
            BEACON_STATS_TSF_DELTA_MIN.fetch_min(delta, Ordering::Relaxed);
            BEACON_STATS_TSF_DELTA_MAX.fetch_max(delta, Ordering::Relaxed);
        }
    } else {
        store_u64(
            &BEACON_STATS_FIRST_TSF_LO,
            &BEACON_STATS_FIRST_TSF_HI,
            tsf_us,
        );
    }
    if last_local != 0 {
        let delta = local_us.saturating_sub(last_local).min(u64::from(u32::MAX)) as u32;
        BEACON_STATS_LOCAL_DELTA_MIN.fetch_min(delta, Ordering::Relaxed);
        BEACON_STATS_LOCAL_DELTA_MAX.fetch_max(delta, Ordering::Relaxed);
    }
    BEACON_STATS_PHASE_MIN.fetch_min(phase, Ordering::Relaxed);
    BEACON_STATS_PHASE_MAX.fetch_max(phase, Ordering::Relaxed);
    BEACON_STATS_ACCEPTED.fetch_add(1, Ordering::Relaxed);
    let selected = slot % u64::from(stride) == 0;
    if selected {
        let last_selected = load_u64(
            &BEACON_STATS_LAST_SELECTED_SLOT_LO,
            &BEACON_STATS_LAST_SELECTED_SLOT_HI,
        );
        if last_selected == slot {
            BEACON_STATS_DUPLICATES.fetch_add(1, Ordering::Relaxed);
        } else {
            if last_selected != 0 && slot > last_selected + 1 {
                let selected_gap = (slot - last_selected) / u64::from(stride);
                BEACON_STATS_SELECTED_MISSED.fetch_add(
                    selected_gap.saturating_sub(1).min(u64::from(u32::MAX)) as u32,
                    Ordering::Relaxed,
                );
            }
            BEACON_STATS_SELECTED_SEEN.fetch_add(1, Ordering::Relaxed);
            store_u64(
                &BEACON_STATS_LAST_SELECTED_SLOT_LO,
                &BEACON_STATS_LAST_SELECTED_SLOT_HI,
                slot,
            );
        }
    }
    store_u64(&BEACON_STATS_LAST_TSF_LO, &BEACON_STATS_LAST_TSF_HI, tsf_us);
    store_u64(
        &BEACON_STATS_LAST_LOCAL_LO,
        &BEACON_STATS_LAST_LOCAL_HI,
        local_us,
    );
    store_u64(&BEACON_STATS_LAST_SLOT_LO, &BEACON_STATS_LAST_SLOT_HI, slot);
    BEACON_STATS_LAST_PHASE.store(phase, Ordering::Relaxed);
}

pub fn reset_beacon_stats() {
    shared_nan::metrics::reset_beacon_stats();
}

fn record_beacon_stats(
    source: u32,
    bssid: [u8; 6],
    tsf_us: u64,
    local_us: u64,
    interval_tu: u32,
    stride: u32,
) {
    shared_nan::metrics::record_beacon_stats(source, bssid, tsf_us, local_us, interval_tu, stride);
}

fn beacon_stats() -> String {
    shared_nan::metrics::format_beacon_stats(&shared_nan::metrics::beacon_stats_snapshot())
}

/// Find a selected-slot beacon received after `baseline`.
///
/// The latest-beacon snapshot is insufficient when a receiver hears several
/// cluster beacons in one active window: a later beacon can make an otherwise
/// valid DW0/DW8 rendezvous look late. The bounded history is only timing
/// metadata and is overwritten continuously.
pub fn nan_beacon_matching_since(
    baseline: u32,
    expected_tsf_us: u64,
    period_us: u64,
    tolerance_us: u64,
) -> Option<super::wifi::BeaconSnapshot> {
    if expected_tsf_us == 0 || period_us == 0 {
        return None;
    }
    let current = NAN_RX_BEACON.load(Ordering::Acquire);
    let expected_slot = expected_tsf_us / period_us;
    let expected_phase = expected_tsf_us % period_us;
    for index in 0..NAN_BEACON_HISTORY_LEN {
        let sequence = NAN_BEACON_HISTORY_SEQ[index].load(Ordering::Acquire);
        if sequence <= baseline || sequence > current {
            continue;
        }
        let tsf_us = (u64::from(NAN_BEACON_HISTORY_TSF_HI[index].load(Ordering::Relaxed)) << 32)
            | u64::from(NAN_BEACON_HISTORY_TSF_LO[index].load(Ordering::Relaxed));
        let phase_delta_us = (tsf_us % period_us).abs_diff(expected_phase);
        if tsf_us / period_us != expected_slot || phase_delta_us > tolerance_us {
            continue;
        }
        let local_us = (u64::from(NAN_BEACON_HISTORY_LOCAL_HI[index].load(Ordering::Relaxed))
            << 32)
            | u64::from(NAN_BEACON_HISTORY_LOCAL_LO[index].load(Ordering::Relaxed));
        return Some(super::wifi::BeaconSnapshot {
            count: sequence,
            local_us,
            tsf_us,
        });
    }
    None
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
    shared_nan::service_descriptor(frame, shared_nan::DMESH_SERVICE_ID)
        .filter(|descriptor| shared_nan::is_dmesh_service_info(descriptor.payload))
        .map(|descriptor| descriptor.control & 0x03)
}

fn is_nan_followup(frame: &[u8]) -> bool {
    shared_nan::is_nan_followup(frame)
}

fn raw_service_descriptor_payload(body: &[u8]) -> Option<(u8, u8, &[u8])> {
    let descriptor = shared_nan::service_descriptor_body(body, shared_nan::DMESH_SERVICE_ID)?;
    Some((
        descriptor.instance,
        descriptor.requestor_instance,
        descriptor.payload,
    ))
}

/// Parse the shared DMesh v1 NAN follow-up envelope.  It is deliberately
/// separate from compact-CBOR firmware commands: Android service discovery
/// uses this envelope for hello/ack and packet hints, whereas control traffic
/// remains compact CBOR.
fn parse_dmesh_nan_followup(data: &[u8]) -> Option<DmeshNanFollowup<'_>> {
    let followup = shared_nan::parse_dmesh_nan_followup(data)?;
    Some(DmeshNanFollowup {
        msg_type: followup.msg_type,
        seq: followup.seq,
        device_id: followup.device_id,
        target_id: followup.target_id,
        payload: followup.payload,
    })
}

fn is_dmesh_nan_service_info(data: &[u8]) -> bool {
    shared_nan::is_dmesh_service_info(data)
}

fn wake_request_for_service(data: &[u8]) -> Option<(u32, u8)> {
    if !is_dmesh_nan_service_info(data)
        || data[4] & (NAN_SERVICE_FLAG_UART_WAKE | NAN_SERVICE_FLAG_BLE_WAKE) == 0
    {
        return None;
    }
    let target = u32::from_le_bytes(data[11..15].try_into().ok()?);
    if target != u32::MAX && !target_matches_local(target) {
        return None;
    }
    let duration = u16::from_le_bytes(data[15..17].try_into().ok()?) as u32;
    Some((duration.clamp(1_000, 300_000), data[4]))
}

fn active_ack_for_service(data: &[u8]) -> Option<(u32, u16)> {
    if !is_dmesh_nan_service_info(data) || data[4] & NAN_SERVICE_FLAG_ACTIVE_ACK == 0 {
        return None;
    }
    let target = u32::from_le_bytes(data[11..15].try_into().ok()?);
    if target != u32::MAX && !target_matches_local(target) {
        return None;
    }
    let peer_suffix = u32::from_be_bytes(data[5..9].try_into().ok()?);
    let duration = u16::from_le_bytes(data[15..17].try_into().ok()?);
    Some((peer_suffix, duration))
}

fn dmesh_nan_followup_frame(
    msg_type: u8,
    seq: u16,
    device_id: &[u8; 6],
    target_id: &[u8; 6],
    payload: &[u8],
) -> Result<Vec<u8>> {
    shared_nan::build_dmesh_followup_payload(msg_type, seq, *device_id, *target_id, payload)
}

fn fnv1a32(data: &[u8]) -> u32 {
    shared_nan::fnv1a32(data)
}

/// Queue a response for a raw-NAN peer.
///
/// In duty-cycle mode, the scheduler drains this queue during the next radio
/// window. In continuously active raw mode, drain it now so interactive
/// diagnostics retain their request/response behavior.
pub fn queue_response_payload_to(command: &NanIncomingCommand, payload: &[u8]) -> Result<usize> {
    let request_id = crate::commands::protocol::decode_binary(&command.payload)
        .ok()
        .and_then(|request| request.args.get(&NAN_REQUEST_ID_KEY).cloned());
    // A raw-NAN SDF carries at most 255 bytes. Never truncate compact CBOR:
    // an incomplete response is decoded as a request by the peer and corrupts
    // response accounting. Preserve the method ID where possible and return a
    // small, valid response. A status response is intentionally marked as
    // truncated rather than converted to an error: `status` and `ping` carry
    // verbose UART text, but the addressed command still completed and the
    // gateway must be able to observe that completion over NAN.
    let bounded = if payload.len() <= NAN_COMMAND_MAX_LEN {
        payload.to_vec()
    } else {
        let decoded = crate::commands::protocol::decode_binary(payload).ok();
        let method = decoded
            .as_ref()
            .map(|response| response.method)
            .unwrap_or(0);
        let mut compact = CommandRequest::new_binary(method);
        if decoded.as_ref().is_some_and(|response| {
            response
                .args
                .contains_key(&crate::commands::protocol::CBOR_ERROR)
        }) {
            compact.args.insert(
                crate::commands::protocol::CBOR_ERROR,
                "raw NAN response exceeds 231 bytes".to_string(),
            );
        } else {
            compact.args.insert(
                crate::commands::protocol::CBOR_STATUS,
                "partial".to_string(),
            );
            if let Some(message) = decoded.as_ref().and_then(|response| response.args.get(&32)) {
                let prefix = message.chars().take(150).collect::<String>();
                compact.args.insert(32, format!("{prefix} [truncated]"));
            }
        }
        crate::commands::protocol::encode_binary(&compact)
    };
    let bounded = if let Some(request_id) = request_id {
        if let Ok(mut response) = crate::commands::protocol::decode_binary(&bounded) {
            response.args.insert(NAN_REQUEST_ID_KEY, request_id);
            let encoded = crate::commands::protocol::encode_binary(&response);
            if encoded.len() <= NAN_COMMAND_MAX_LEN {
                encoded
            } else {
                bounded
            }
        } else {
            bounded
        }
    } else {
        bounded
    };
    match &command.peer {
        NanCommandPeer::Raw { mac, instance } => {
            // Keep the response on the NAN discovery multicast destination.
            // ESP STA/AP MAC filtering is inconsistent across IDF modes, while
            // the request already carries the logical target in CBOR. The
            // gateway filters by source/sequence in response history.
            let _ = mac;
            let queued = enqueue_outgoing_raw([0xff; 6], *instance, &bounded, true)?;
            NAN_RAW_RESPONSE_PENDING.fetch_add(1, Ordering::Relaxed);
            if (!super::mode::raw_nan_duty_enabled() || super::mode::raw_nan_interactive_active())
                && NAN_RUNNING.load(Ordering::Relaxed)
            {
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

/// True while addressed work is queued, being dispatched, or awaiting its
/// response transmission. The mode scheduler uses this to keep a sleepy node
/// awake across the command/response exchange.
pub fn raw_work_pending() -> bool {
    NAN_RAW_COMMAND_PENDING.load(Ordering::Relaxed) != 0
        || NAN_RAW_RESPONSE_PENDING.load(Ordering::Relaxed) != 0
        || raw_queue_pending()
}

pub fn raw_command_pending_count() -> u32 {
    NAN_RAW_COMMAND_PENDING.load(Ordering::Relaxed)
}

pub fn raw_response_pending_count() -> u32 {
    NAN_RAW_RESPONSE_PENDING.load(Ordering::Relaxed)
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
    // Do not turn idle beacon traffic into a skipped-slot counter. The counter
    // is evidence about queued SDFs that were deliberately held for their
    // advertised rendezvous slot.
    let has_publish = nan_publish_queue()
        .lock()
        .map(|queue| !queue.is_empty())
        .unwrap_or(false);
    if !has_publish {
        return 0;
    }
    let beacon_tsf_us = last_beacon_tsf_us();
    let Some(slot) = super::mode::raw_nan_publish_dw_slot(beacon_tsf_us) else {
        NAN_PUBLISH_DW_SKIPPED_SLOT.fetch_add(1, Ordering::Relaxed);
        return 0;
    };
    if slot == NAN_LAST_PUBLISH_SLOT.load(Ordering::Relaxed) {
        return 0;
    }
    let local_us = now_us();
    let min_spacing_us = super::mode::raw_nan_publish_min_spacing_us();
    let last_publish_local_us = load_u64(&NAN_LAST_PUBLISH_LOCAL_LO, &NAN_LAST_PUBLISH_LOCAL_HI);
    if min_spacing_us != 0
        && last_publish_local_us != 0
        && local_us.saturating_sub(last_publish_local_us) < min_spacing_us
    {
        NAN_PUBLISH_DW_LOCAL_GUARD_DROPS.fetch_add(1, Ordering::Relaxed);
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
    // Unassociated APSTA SoftAP injection must let IDF allocate the sequence
    // number; forcing station system sequencing is accepted but suppressed
    // by the driver. Associated STA/data paths retain `true` elsewhere.
    match raw_tx_publish(&frame, super::wifi::raw_tx_sys_seq()) {
        Ok(()) => {
            let offset_us = now_us().saturating_sub(last_beacon_local_us());
            NAN_LAST_PUBLISH_BEACON.store(beacon, Ordering::Relaxed);
            NAN_LAST_PUBLISH_SLOT.store(slot, Ordering::Relaxed);
            store_u64(
                &NAN_LAST_PUBLISH_LOCAL_LO,
                &NAN_LAST_PUBLISH_LOCAL_HI,
                local_us,
            );
            NAN_PUBLISH_DW_TX.fetch_add(1, Ordering::Relaxed);
            NAN_PUBLISH_DW_LAST_OFFSET_US
                .store(offset_us.min(u32::MAX as u64) as u32, Ordering::Relaxed);
            telemetry::record_log(format!(
                "event type=nan.publish_dw ok=true beacon={} slot={} tsf_us={} offset_us={}",
                beacon, slot, beacon_tsf_us, offset_us
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

/// Send one queued publication immediately for an infrastructure node.
///
/// Infrastructure radios are continuously powered and are explicitly allowed
/// to advertise outside a sleepy peer's DW.  Keep the existing synchronized
/// path for sleepy nodes; this helper is only called after the command path
/// has established `mode=infra`.
pub fn drain_publish_infra_immediate() -> usize {
    if !super::mode::infra_mode() || !NAN_RUNNING.load(Ordering::Relaxed) {
        return 0;
    }
    // Keep the queued copy: the immediate broadcast is only an early hint.
    // The same publication must be retransmitted in the next synchronized
    // DW0/DW4 so sleepy peers that missed the active send can receive it.
    let frame = nan_publish_queue()
        .lock()
        .ok()
        .and_then(|queue| queue.front().cloned());
    let Some(frame) = frame else {
        return 0;
    };
    if let Ok(mut captured) = last_publish_frame().lock() {
        captured.clear();
        captured.extend_from_slice(&frame);
    }
    match raw_tx_publish(&frame, super::wifi::raw_tx_sys_seq()) {
        Ok(()) => {
            NAN_PUBLISH_DW_TX.fetch_add(1, Ordering::Relaxed);
            telemetry::record_log(format!(
                "event type=nan.publish_infra ok=true bytes={}",
                frame.len()
            ));
            1
        }
        Err(error) => {
            telemetry::record_log(format!(
                "event type=nan.publish_infra ok=false message={}",
                crate::commands::protocol::escape_value(&error.to_string())
            ));
            0
        }
    }
}

/// Keep an infrastructure ESP discoverable without a one-shot UART command.
/// The queued frame is sent immediately and remains available for the next
/// synchronized discovery window, matching the active-plus-DW policy.
pub fn ensure_infra_publish(settings: &SharedSettings) {
    if !super::mode::infra_mode() || !NAN_RUNNING.load(Ordering::Relaxed) {
        return;
    }
    const PERIOD_US: u64 = 4_000_000;
    let now = now_us();
    let last = load_u64(
        &NAN_LAST_INFRA_AUTO_PUBLISH_LO,
        &NAN_LAST_INFRA_AUTO_PUBLISH_HI,
    );
    if last != 0 && now.saturating_sub(last) < PERIOD_US {
        return;
    }
    let queued = nan_publish_queue()
        .lock()
        .ok()
        .and_then(|queue| queue.front().cloned());
    if let Some(frame) = queued {
        store_u64(
            &NAN_LAST_INFRA_AUTO_PUBLISH_LO,
            &NAN_LAST_INFRA_AUTO_PUBLISH_HI,
            now,
        );
        let _ = raw_tx_publish(&frame, super::wifi::raw_tx_sys_seq());
        return;
    }
    let Ok((availability, device_capabilities)) = nan_publish_attributes(settings, 1) else {
        return;
    };
    let Ok(frame) = nan_publish_frame(&availability, &device_capabilities, true, 2) else {
        return;
    };
    if let Ok(mut queue) = nan_publish_queue().lock() {
        queue.push_back(frame);
    } else {
        return;
    }
    store_u64(
        &NAN_LAST_INFRA_AUTO_PUBLISH_LO,
        &NAN_LAST_INFRA_AUTO_PUBLISH_HI,
        now,
    );
    let _ = drain_publish_infra_immediate();
}

fn prime_infra_publish() {
    if !NAN_RUNNING.load(Ordering::Relaxed) {
        return;
    }
    let Ok(availability) = dmesh_rawnan::build_nan_availability_attribute(512, 0, 1, 64, 1) else {
        return;
    };
    let Ok(device_capabilities) = dmesh_rawnan::build_nan_device_capability_attribute(1) else {
        return;
    };
    let Ok(frame) = nan_publish_frame(&availability, &device_capabilities, true, 2) else {
        return;
    };
    if let Ok(mut queue) = nan_publish_queue().lock() {
        if !queue.is_empty() {
            return;
        }
        for _ in 0..4 {
            queue.push_back(frame.clone());
        }
    } else {
        return;
    }
    let now = now_us();
    store_u64(
        &NAN_LAST_INFRA_AUTO_PUBLISH_LO,
        &NAN_LAST_INFRA_AUTO_PUBLISH_HI,
        now,
    );
    let _ = drain_publish_infra_immediate();
    // A freshly-created APSTA context can drop the first management TX while
    // its beacon scheduler settles. Repeat a bounded burst; keep one queued
    // copy for the next synchronized DW instead of free-running forever.
    for _ in 0..3 {
        task_delay(Duration::from_millis(120));
        let frame = nan_publish_queue()
            .lock()
            .ok()
            .and_then(|mut queue| queue.pop_front());
        let Some(frame) = frame else {
            break;
        };
        let _ = raw_tx_publish(&frame, super::wifi::raw_tx_sys_seq());
    }
}

/// Prime an infrastructure publisher when Wi-Fi mode setup, rather than the
/// `nan` command, owns startup. Hardware setup supplies only the channel;
/// frame policy and encoding remain in this module/shared `dmesh-rawnan`.
pub fn prime_infra_publish_for_wifi(channel: u8) -> Result<()> {
    if !NAN_RUNNING.load(Ordering::Relaxed) {
        start_raw_sniffer(channel.max(1))?;
    }
    if super::mode::infra_mode() {
        // IDF reports APSTA started before the SoftAP injection context is
        // actually ready. Give the hardware task a bounded settle interval;
        // this is deliberately adapter timing, not NAN wire policy.
        task_delay(Duration::from_millis(500));
        prime_infra_publish();
    }
    Ok(())
}

pub fn raw_response_rx_count() -> u32 {
    NAN_RAW_RESPONSE_RX.load(Ordering::Relaxed)
}

/// Bounded raw command/response counters exposed in the compact mode status.
pub fn raw_command_rx_count() -> u32 {
    NAN_RAW_COMMAND_RX.load(Ordering::Relaxed)
}

pub fn raw_response_tx_count() -> u32 {
    NAN_RAW_RESPONSE_TX.load(Ordering::Relaxed)
}

pub fn raw_queue_len() -> usize {
    nan_outgoing_queue()
        .lock()
        .map(|queue| queue.len())
        .unwrap_or(0)
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
    role: NanDiscoveryRole,
    role_loaded: bool,
}

impl NanCommand {
    fn new(settings: SharedSettings) -> Self {
        Self {
            settings,
            dump: false,
            channel: DEFAULT_CHANNEL,
            backend: NanBackend::Raw,
            service: DEFAULT_SERVICE.to_string(),
            role: NanDiscoveryRole::Publisher,
            role_loaded: false,
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
        // NVS supplies the initial role after boot.  Subsequent commands in
        // this firmware session retain an explicit runtime role until the
        // caller changes it again; otherwise `nan publish` could silently
        // revert a non-persistent `nan start role=publisher` to an old
        // persisted solicited role and emit the wrong SDF form.
        if let Some(role) = request.arg("role") {
            self.role = NanDiscoveryRole::parse(role)?;
            self.role_loaded = true;
        } else if !self.role_loaded {
            self.role = if let Some(role) = self.settings.borrow().get_str("nan.role")? {
                NanDiscoveryRole::parse(&role)?
            } else {
                NanDiscoveryRole::Publisher
            };
            self.role_loaded = true;
        }
        set_discovery_role(self.role);
        set_solicited_publish_attributes(&self.settings)?;
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
            settings.set_str("nan.role", self.role.name())?;
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
        if let Some(enabled) = request.arg("hw_filter") {
            NAN_HW_FILTER_ENABLED.store(parse_bool(enabled)?, Ordering::Relaxed);
            reconcile_hardware_bssid_filter();
        }
        if request.arg("cycle").is_some() {
            return self.raw_cycle_test(request);
        }
        if request.arg("stop").is_some() {
            clear_pending_nan_transmissions();
            super::mode::stop_raw_nan_duty();
            stop_nan()?;
            super::wifi::stop_raw_monitor()?;
            self.maybe_save_settings(request, false)?;
            return Ok(CommandResponse::ok("nan stopped"));
        }
        if request.arg("transport").is_some() {
            bail!("NAN is discovery-only; use an L2 bearer for QUIC-lite streams")
        }
        if request.arg("stats") == Some("object") {
            let object_stats = object_service_stats();
            return Ok(CommandResponse::ok(format!(
                "nan object_stats frames={} bytes={} rejected={} action_dispatch={} action_accepted={}",
                object_stats.frames,
                object_stats.bytes,
                object_stats.rejected,
                NAN_OBJECT_ACTION_DISPATCH.load(Ordering::Relaxed),
                NAN_OBJECT_ACTION_ACCEPTED.load(Ordering::Relaxed),
            )));
        }
        if request.arg("stats").is_some() {
            return Ok(CommandResponse::ok(stats()));
        }
        if let Some(value) = request.arg("beacon_stats") {
            if matches!(value, "reset" | "clear" | "false") {
                reset_beacon_stats();
                return Ok(CommandResponse::ok("beacon_stats reset=true"));
            }
            return Ok(CommandResponse::ok(beacon_stats()));
        }
        if request.arg("timing").is_some() {
            return Ok(CommandResponse::ok(super::mode::raw_nan_timing_fields()));
        }
        if request.arg("beacon_history").is_some() {
            return Ok(CommandResponse::ok(render_beacon_history()));
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
        if let Some(service_dump) = request.arg("service_dump") {
            let mut frame = last_dmesh_service_frame()
                .lock()
                .map_err(|_| anyhow!("NAN service descriptor capture lock poisoned"))?;
            if service_dump == "clear" {
                frame.clear();
                return Ok(CommandResponse::ok("nan service_dump=cleared"));
            }
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
        if let Some(service_history_request) = request.arg("service_history") {
            if service_history_request == "clear" {
                service_history()
                    .lock()
                    .map_err(|_| anyhow!("NAN service history lock poisoned"))?
                    .clear();
                return Ok(CommandResponse::ok("nan service_history=cleared"));
            }
            return Ok(CommandResponse::ok(render_service_history()?));
        }
        if request.arg("subscribe_dump").is_some() {
            let frame = last_dmesh_subscribe_frame()
                .lock()
                .map_err(|_| anyhow!("NAN subscribe descriptor capture lock poisoned"))?;
            if frame.is_empty() {
                return Ok(CommandResponse::ok("nan subscribe_dump=empty"));
            }
            return Ok(CommandResponse::ok(format!(
                "nan subscribe_dump bytes={} hex={}",
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
        if request.arg("response_history").is_some() {
            return Ok(CommandResponse::ok(render_raw_response_history()?));
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
                nan_control_rate()?;
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
        let frame_data = request.arg("frame").or_else(|| request.arg("data"));
        if let Some(data) = frame_data {
            let payload = parse_bytes(data)?;
            if payload.len() > NAN_COMMAND_MAX_LEN {
                bail!("nan data exceeds {NAN_COMMAND_MAX_LEN} bytes");
            }
            self.ensure_raw_started()?;
            let destination = request
                .arg("destination")
                .or_else(|| request.arg("dst"))
                .map(parse_mac)
                .transpose()?
                .unwrap_or(NAN_DISCOVERY_MAC);
            let source = station_mac()?;
            let bssid = nan_cluster_bssid();
            let frame = super::udp::build_nan_udp_frame(destination, source, bssid, &payload);
            nan_control_rate()?;
            raw_tx(&frame, true)?;
            return Ok(CommandResponse::ok(format!(
                "nan data sent=true bytes={} dst={} bssid={}",
                payload.len(),
                format_mac(&destination),
                format_mac(&bssid)
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
                "nan started backend={} role={} service={} channel={} dump={} filter={}",
                self.backend.name(),
                self.role.name(),
                self.service,
                self.channel.max(1),
                self.dump,
                filter_name()
            )));
        }
        if let Some(raw) = request.arg("raw") {
            let bytes = parse_bytes(raw)?;
            self.ensure_raw_started()?;
            if let Some(rate) = request.arg("tx_rate") {
                super::wifi::configure_fixed_tx_rate(
                    rate,
                    super::wifi::raw_tx_interface(),
                    request
                        .arg("disable_11b")
                        .map(parse_bool)
                        .transpose()?
                        .unwrap_or(true),
                )?;
            }
            let en_sys_seq = request
                .arg("sys_seq")
                .map(parse_bool)
                .transpose()?
                .unwrap_or(true);
            raw_tx(&bytes, en_sys_seq)?;
            return Ok(CommandResponse::ok(format!(
                "nan raw sent bytes={} sys_seq={}",
                bytes.len(),
                en_sys_seq
            )));
        }
        if let Some(target) = request
            .arg("uart_wake")
            .or_else(|| request.arg("wake_uart"))
        {
            self.ensure_raw_started()?;
            let sync = request
                .arg("sync")
                .map(parse_bool)
                .transpose()?
                .unwrap_or(false);
            if !sync {
                bail!("nan uart_wake requires sync=true; raw NAN data is DW-gated");
            }
            let target = parse_uart_wake_target(target)?;
            let duration_ms = request
                .arg_i32("duration_ms")?
                .or(request.arg_i32("ms")?)
                .unwrap_or(2_000)
                .clamp(1_000, 300_000) as u16;
            let availability_map = request.arg_i32("availability_map")?.unwrap_or(1);
            if !(0..=15).contains(&availability_map) {
                bail!("availability_map must be in 0..=15; got {availability_map}");
            }
            let (availability, device_capabilities) =
                nan_publish_attributes(&self.settings, availability_map as u8)?;
            let frame = nan_publish_frame_with_wake(
                &availability,
                &device_capabilities,
                true,
                2,
                0,
                Some(target),
                duration_ms,
                NAN_SERVICE_FLAG_UART_WAKE,
            )?;
            let frame_len = frame.len();
            let mut queue = nan_publish_queue()
                .lock()
                .map_err(|_| anyhow!("nan publish queue lock failed"))?;
            if queue.len() >= NAN_OUTGOING_QUEUE_MAX {
                queue.pop_front();
            }
            queue.push_back(frame);
            return Ok(CommandResponse::ok(format!(
                "nan uart_wake queued=true target={} duration_ms={} bytes={}",
                if target == u32::MAX {
                    "*".to_string()
                } else {
                    format!("{target:08x}")
                },
                duration_ms,
                frame_len
            )));
        }
        if let Some(target) = request.arg("ble_wake").or_else(|| request.arg("wake_ble")) {
            self.ensure_raw_started()?;
            let sync = request
                .arg("sync")
                .map(parse_bool)
                .transpose()?
                .unwrap_or(false);
            if !sync {
                bail!("nan ble_wake requires sync=true; raw NAN data is DW-gated");
            }
            let target = parse_uart_wake_target(target)?;
            let duration_ms = request
                .arg_i32("duration_ms")?
                .or(request.arg_i32("ms")?)
                .unwrap_or(2_000)
                .clamp(1_000, 300_000) as u16;
            let availability_map = request.arg_i32("availability_map")?.unwrap_or(1);
            if !(0..=15).contains(&availability_map) {
                bail!("availability_map must be in 0..=15; got {availability_map}");
            }
            let (availability, device_capabilities) =
                nan_publish_attributes(&self.settings, availability_map as u8)?;
            let frame = nan_publish_frame_with_wake(
                &availability,
                &device_capabilities,
                true,
                2,
                0,
                Some(target),
                duration_ms,
                NAN_SERVICE_FLAG_BLE_WAKE,
            )?;
            let frame_len = frame.len();
            let mut queue = nan_publish_queue()
                .lock()
                .map_err(|_| anyhow!("nan publish queue lock failed"))?;
            if queue.len() >= NAN_OUTGOING_QUEUE_MAX {
                queue.pop_front();
            }
            queue.push_back(frame);
            return Ok(CommandResponse::ok(format!(
                "nan ble_wake queued=true target={} duration_ms={} bytes={}",
                if target == u32::MAX {
                    "*".to_string()
                } else {
                    format!("{target:08x}")
                },
                duration_ms,
                frame_len
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
            let availability_map = request.arg_i32("availability_map")?.unwrap_or(1);
            if !(0..=15).contains(&availability_map) {
                bail!("availability_map must be in 0..=15; got {availability_map}");
            }
            let availability_map = availability_map as u8;
            let (availability, device_capabilities) =
                nan_publish_attributes(&self.settings, availability_map)?;
            // Table 25 permits a bare unsolicited Publish SDF without SDEA.
            // Keep SDEA enabled by default, but expose this narrow wire-level
            // experiment for implementations that reject the optional Service
            // Update Indicator before creating a peer.
            let include_sdea = request
                .arg("sdea")
                .map(parse_bool)
                .transpose()?
                .unwrap_or(true);
            let sdea_update = request.arg_i32("sdea_update")?.unwrap_or(2);
            if !(0..=u8::MAX as i32).contains(&sdea_update) {
                bail!("sdea_update must be in 0..=255; got {sdea_update}");
            }
            let sdea_update = sdea_update as u8;
            let mut frame_len = 0_usize;
            let mut destination = NAN_DISCOVERY_MAC;
            let mut queue = nan_publish_queue()
                .lock()
                .map_err(|_| anyhow!("nan publish queue lock failed"))?;
            for _ in 0..count {
                let frame = nan_publish_frame(
                    &availability,
                    &device_capabilities,
                    include_sdea,
                    sdea_update,
                )?;
                frame_len = frame.len();
                destination.copy_from_slice(&frame[FRAME_DST..FRAME_DST + 6]);
                if queue.len() >= NAN_OUTGOING_QUEUE_MAX {
                    queue.pop_front();
                }
                queue.push_back(frame);
            }
            // A powered infrastructure node may advertise immediately; a
            // sleepy node leaves the queue for the synchronized DW poller.
            let immediate = if super::mode::infra_mode() {
                drop(queue);
                drain_publish_infra_immediate()
            } else {
                0
            };
            return Ok(CommandResponse::ok(format!(
                "nan publish queued=true immediate={} backend={} service={} count={} sdea={} sdea_update={} availability_map={} dst={} bssid={} bytes={}",
                immediate,
                self.backend.name(),
                self.service,
                count,
                include_sdea,
                sdea_update,
                availability_map,
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
                let remaining_us = deadline_us.saturating_sub(now_us());
                // The Wi-Fi callback notifies this task after queueing every
                // frame. Sleep until either input arrives or the active
                // window expires; do not sample SDF state with a fixed poll.
                super::wake::wait(Duration::from_micros(remaining_us.max(1)));
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
        if super::mode::infra_mode() {
            prime_infra_publish();
        }
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
        if shared_nan::beacon_seen_since(start_count, NAN_RX_BEACON.load(Ordering::Relaxed)) {
            return;
        }
        let remaining_us = deadline_us.saturating_sub(now_us());
        // Beacon reception and all raw-frame enqueue paths notify the main
        // task. Block on that event instead of polling every 10 ms; unrelated
        // wakeups are harmless because the counter predicate is rechecked.
        super::wake::wait(Duration::from_micros(remaining_us.max(1)));
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
        if shared_nan::beacon_seen_since(count, observed) {
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
        let remaining_us = deadline_us.saturating_sub(now_us());
        // This is an event wait, not a timing source: only an observed beacon
        // can satisfy the predicate. The timeout bounds a missing-cluster
        // case without burning CPU in a short sleep loop.
        super::wake::wait(Duration::from_micros(remaining_us.max(1)));
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
    ensure_rx_queue().context("nan rx queue")?;
    super::wifi::ensure_raw_wifi_started(channel).context("nan wifi start")?;
    // Discovery starts without a comparator. Once a beacon has been accepted,
    // reconcile_hardware_bssid_filter() arms the exact cluster comparator;
    // stale timing releases it before the next discovery interval.
    reconcile_hardware_bssid_filter();
    unsafe {
        // Include data frames for the first-frame timing marker.  NAN still
        // queues/parses management frames only; a data frame merely proves
        // that the RX path was alive before the selected beacon.
        let mut filter = sys::wifi_promiscuous_filter_t {
            filter_mask: sys::WIFI_PROMIS_FILTER_MASK_MGMT | sys::WIFI_PROMIS_FILTER_MASK_DATA,
        };
        esp_ok(sys::esp_wifi_set_promiscuous(false)).context("nan promiscuous disable")?;
        esp_ok(sys::esp_wifi_set_promiscuous_rx_cb(Some(sniffer_cb)))
            .context("nan promiscuous callback")?;
        esp_ok(sys::esp_wifi_set_promiscuous_filter(&mut filter))
            .context("nan promiscuous filter")?;
        // Keep an established STA/AP on its beacon channel. NAN and the
        // infrastructure profile share this radio; retuning here breaks the
        // host-STA contract. Unassociated raw mode is retuned by the helper.
        super::wifi::prepare_nan_channel(channel).context("nan channel")?;
        esp_ok(sys::esp_wifi_set_promiscuous(true)).context("nan promiscuous enable")?;
    }
    NAN_RUNNING.store(true, Ordering::Relaxed);
    object_service_start();
    Ok(())
}

fn configured_hardware_filter_bssid() -> Option<[u8; 6]> {
    if !NAN_FILTER_BSSID_ENABLED.load(Ordering::Relaxed) {
        return None;
    }
    Some(configured_filter_bssid())
}

/// Keep the MAC prefilter aligned with the cluster-selection state machine.
/// This runs from the normal Main task (never the Wi-Fi callback), so changing
/// the internal driver comparator cannot block the RX interrupt path.
fn reconcile_hardware_bssid_filter() {
    if !NAN_RUNNING.load(Ordering::Relaxed) {
        return;
    }
    let manual = configured_hardware_filter_bssid();
    let desired = if let Some(bssid) = manual {
        Some(bssid)
    } else if !NAN_HW_FILTER_ENABLED.load(Ordering::Relaxed) {
        None
    } else {
        let last = last_beacon_local_us();
        let fresh = last != 0 && now_us().saturating_sub(last) < NAN_CLUSTER_RESELECT_AFTER_US;
        if fresh && NAN_CLUSTER_LOCKED.load(Ordering::Acquire) {
            Some(nan_cluster_bssid())
        } else {
            None
        }
    };
    let currently_armed = NAN_HW_FILTER_STATE.load(Ordering::Acquire) == NAN_HW_FILTER_ARMED;
    let current_bssid = nan_cluster_bssid();
    let needs_change = match desired {
        Some(bssid) => !currently_armed || current_bssid != bssid,
        None => currently_armed,
    };
    if !needs_change {
        return;
    }
    let result = match desired {
        Some(bssid) => {
            let result = super::wifi::set_hardware_bssid_filter(bssid, true);
            if result.is_ok() {
                NAN_HW_FILTER_STATE.store(NAN_HW_FILTER_ARMED, Ordering::Release);
                NAN_HW_FILTER_ARMS.fetch_add(1, Ordering::Relaxed);
            }
            result
        }
        None => {
            let result = super::wifi::set_hardware_bssid_filter([0; 6], false);
            if result.is_ok() {
                NAN_HW_FILTER_STATE.store(NAN_HW_FILTER_DISCOVERY, Ordering::Release);
                NAN_HW_FILTER_REPROBES.fetch_add(1, Ordering::Relaxed);
                if last_beacon_local_us() != 0
                    && now_us().saturating_sub(last_beacon_local_us())
                        >= NAN_CLUSTER_RESELECT_AFTER_US
                {
                    NAN_CLUSTER_LOCKED.store(false, Ordering::Release);
                }
            }
            result
        }
    };
    if let Err(err) = result {
        NAN_HW_FILTER_ERRORS.fetch_add(1, Ordering::Relaxed);
        telemetry::record_log(format!(
            "event type=nan.hw_bssid_filter ok=false state={} error={}",
            if desired.is_some() {
                "armed"
            } else {
                "discovery"
            },
            crate::commands::protocol::escape_value(&err.to_string())
        ));
    } else {
        telemetry::record_log(format!(
            "event type=nan.hw_bssid_filter ok=true state={} bssid={}",
            if desired.is_some() {
                "armed"
            } else {
                "discovery"
            },
            desired
                .map(|bssid| format_mac(&bssid))
                .unwrap_or_else(|| "none".to_string())
        ));
    }
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
    apply_dw_control(&req);
    if station_mac().map(|mac| mac == source).unwrap_or(false) {
        telemetry::record_log("event type=nan.reject reason=self".to_string());
        return false;
    }
    let Ok(mut queue) = nan_command_queue().lock() else {
        return false;
    };
    if queue.len() >= NAN_COMMAND_QUEUE_MAX {
        queue.pop_front();
        NAN_RAW_COMMAND_DROPS.fetch_add(1, Ordering::Relaxed);
        telemetry::record_log(format!(
            "event type=nan.queue_drop kind=command limit={NAN_COMMAND_QUEUE_MAX}"
        ));
    }
    queue.push_back(NanIncomingCommand {
        peer: NanCommandPeer::Raw {
            mac: source,
            instance,
        },
        payload: payload.to_vec(),
    });
    NAN_RAW_COMMAND_PENDING.fetch_add(1, Ordering::Relaxed);
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
    let matched = local_target_suffixes()
        .iter()
        .any(|suffix| to.eq_ignore_ascii_case(suffix));
    telemetry::record_log(format!(
        "event type=nan.target_check to={} suffixes={} matched={}",
        to,
        local_target_suffixes().join(","),
        matched
    ));
    matched
}

fn enqueue_outgoing_raw(
    dst: [u8; 6],
    instance: u8,
    payload: &[u8],
    response: bool,
) -> Result<usize> {
    enqueue_outgoing_raw_at(dst, instance, payload, response, now_us() / 1_000)
}

fn enqueue_outgoing_raw_at(
    dst: [u8; 6],
    instance: u8,
    payload: &[u8],
    response: bool,
    enqueued_ms: u64,
) -> Result<usize> {
    if payload.len() > NAN_COMMAND_MAX_LEN {
        bail!("raw NAN payload exceeds {NAN_COMMAND_MAX_LEN} bytes");
    }
    let queued = {
        let Ok(mut queue) = nan_outgoing_queue().lock() else {
            bail!("nan outgoing queue lock failed")
        };
        let now_ms = now_us() / 1_000;
        expire_outgoing_queue_locked(&mut queue, now_ms);
        while queue.len() >= NAN_OUTGOING_QUEUE_MAX {
            let dropped = queue.pop_front();
            NAN_RAW_OUTGOING_DROPS.fetch_add(1, Ordering::Relaxed);
            if dropped.as_ref().is_some_and(|item| item.response)
                && NAN_RAW_RESPONSE_PENDING.load(Ordering::Relaxed) != 0
            {
                NAN_RAW_RESPONSE_PENDING.fetch_sub(1, Ordering::Relaxed);
            }
            telemetry::record_log(format!(
                "event type=nan.queue_drop kind=outgoing reason=limit limit={NAN_OUTGOING_QUEUE_MAX}"
            ));
        }
        // Add continuation metadata to command records at the gateway.  It
        // is deliberately derived from the bounded queue, not from a caller
        // supplied duration: a peer stays awake only while this gateway has
        // more work to flush.  Responses are left untouched.
        let wire_payload = if response {
            payload.to_vec()
        } else {
            let queued_after = queue.len().saturating_add(1);
            let mut control = if queued_after > 1 {
                NAN_DW_MORE
            } else {
                NAN_DW_DONE
            };
            let units = queued_after.min(8) as u8;
            control |= units << NAN_DW_UNITS_SHIFT;
            add_dw_control(payload, control)
        };
        queue.push_back(RawNanOutgoing {
            dst,
            instance,
            payload: wire_payload,
            response,
            enqueued_ms,
        });
        queue.len()
    };
    // The mode poller drains this queue while a beacon-opened DW permit is
    // valid. Never call Wi-Fi TX from the promiscuous receive callback.
    Ok(queued)
}

fn expire_outgoing_queue_locked(queue: &mut VecDeque<RawNanOutgoing>, now_ms: u64) {
    let mut expired = 0usize;
    while queue
        .front()
        .is_some_and(|item| now_ms.saturating_sub(item.enqueued_ms) >= NAN_OUTGOING_MAX_AGE_MS)
    {
        if let Some(dropped) = queue.pop_front() {
            expired += 1;
            NAN_RAW_OUTGOING_DROPS.fetch_add(1, Ordering::Relaxed);
            if dropped.response && NAN_RAW_RESPONSE_PENDING.load(Ordering::Relaxed) != 0 {
                NAN_RAW_RESPONSE_PENDING.fetch_sub(1, Ordering::Relaxed);
            }
        }
    }
    if expired != 0 {
        telemetry::record_log(format!(
            "event type=nan.queue_drop kind=outgoing reason=age count={expired} age_ms={NAN_OUTGOING_MAX_AGE_MS}"
        ));
    }
}

/// Expire unsent raw frames even when no new frame is being queued. This is
/// called by the mode poller so an unavailable NAN cluster cannot retain old
/// responses until an unrelated future command arrives.
pub fn expire_raw_queue() {
    if let Ok(mut queue) = nan_outgoing_queue().lock() {
        expire_outgoing_queue_locked(&mut queue, now_us() / 1_000);
    }
}

fn add_dw_control(payload: &[u8], control: u8) -> Vec<u8> {
    let Ok(mut request) = crate::commands::protocol::decode_binary(payload) else {
        return payload.to_vec();
    };
    request.args.insert(NAN_DW_CONTROL_KEY, control.to_string());
    let encoded = crate::commands::protocol::encode_binary(&request);
    if encoded.len() <= NAN_COMMAND_MAX_LEN {
        encoded
    } else {
        payload.to_vec()
    }
}

fn apply_dw_control(request: &CommandRequest) {
    let (more, done, units) = match request.args.get(&NAN_DW_CONTROL_KEY) {
        None => (false, false, 0),
        Some(raw) => match raw.parse::<u8>() {
            Ok(control) => {
                let more = control & NAN_DW_MORE != 0;
                let done = control & NAN_DW_DONE != 0;
                let units = control >> NAN_DW_UNITS_SHIFT;
                if more || units != 0 {
                    // One unit is one 512-TU cadence. Clamp through the mode
                    // helper so a malformed hint cannot pin a node awake.
                    let duration_ms = u32::from(units.max(1)).saturating_mul(512);
                    super::mode::request_targeted_wake(duration_ms);
                }
                (more, done, units)
            }
            Err(_) => {
                telemetry::record_log("event type=nan.dw_control invalid=true".to_string());
                (false, false, 0)
            }
        },
    };
    // Commands that explicitly carry `timeout=<ms>` expect an immediate
    // response.  Treat that value as a bounded post-DW awake deadline too;
    // this lets the target execute the command and flush its response over
    // the interactive burst transport without requiring another wake hint.
    if let Some(raw_timeout) = request.args.get(&NAN_COMMAND_TIMEOUT_KEY) {
        match raw_timeout.parse::<i32>() {
            Ok(timeout_ms) if timeout_ms > 0 => {
                super::mode::request_targeted_wake(timeout_ms as u32);
                telemetry::record_log(format!(
                    "event type=nan.response_deadline timeout_ms={}",
                    timeout_ms
                ));
            }
            Ok(_) => {}
            Err(_) => {
                telemetry::record_log("event type=nan.response_deadline invalid=true".to_string())
            }
        }
    }
    if request.args.contains_key(&NAN_DW_CONTROL_KEY) {
        telemetry::record_log(format!(
            "event type=nan.dw_control more={} done={} units={}",
            more, done, units
        ));
    }
}

fn drain_outgoing_raw() -> usize {
    // A duty-cycled ESP may have Wi-Fi powered for beacon acquisition before
    // the peer's actual DW.  Do not turn that wider receive interval into a
    // transmit opportunity: Android departs channel 6 rapidly after DW.
    let infra_dw_open = super::mode::ap_owner_running()
        && last_beacon_local_us() != 0
        && now_us().saturating_sub(last_beacon_local_us()) <= 64_000
        && super::mode::infra_target_dw_open(last_beacon_tsf_us());
    if !super::mode::raw_nan_data_dw_open()
        && !super::mode::raw_nan_interactive_active()
        && !infra_dw_open
    {
        return 0;
    }
    // A sleepy peer has only a short receive dwell after the selected beacon.
    // The DW protocol intentionally exchanges exactly one frame per selected
    // window. That frame may carry the continuation hint (MORE/DONE); a MORE
    // request keeps the peer awake for the following burst, where the
    // session-oriented bearer takes over. Never turn a retry backlog into a
    // same-DW burst.
    let max_per_window = 1;
    let mut sent = 0_usize;
    loop {
        if sent >= max_per_window {
            return sent;
        }
        let item = {
            let Ok(mut queue) = nan_outgoing_queue().lock() else {
                return sent;
            };
            queue.pop_front()
        };
        let Some(item) = item else {
            return sent;
        };
        match nan_followup_frame(&item.dst, item.instance, &item.payload).and_then(|frame| {
            nan_control_rate()?;
            raw_tx(&frame, true)
        }) {
            Ok(()) => {
                sent += 1;
                NAN_LAST_RAW_TX_OFFSET_US.store(
                    now_us()
                        .saturating_sub(last_beacon_local_us())
                        .min(u64::from(u32::MAX)) as u32,
                    Ordering::Relaxed,
                );
                let tx_slot = last_beacon_tsf_us() / 524_288;
                NAN_LAST_RAW_TX_SLOT_LO.store(tx_slot as u32, Ordering::Relaxed);
                NAN_LAST_RAW_TX_SLOT_HI.store((tx_slot >> 32) as u32, Ordering::Relaxed);
                if item.response {
                    NAN_RAW_RESPONSE_TX.fetch_add(1, Ordering::Relaxed);
                    NAN_RAW_RESPONSE_PENDING.fetch_sub(1, Ordering::Relaxed);
                } else {
                    NAN_RAW_COMMAND_TX.fetch_add(1, Ordering::Relaxed);
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
                let _ = enqueue_outgoing_raw_at(
                    item.dst,
                    item.instance,
                    &item.payload,
                    item.response,
                    item.enqueued_ms,
                );
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
    NAN_HW_FILTER_STATE.store(NAN_HW_FILTER_DISCOVERY, Ordering::Release);
    NAN_RUNNING.store(false, Ordering::Relaxed);
    object_service_stop();
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

/// NAN beacons are fixed at 6 Mbps by Wi-Fi Aware; NAN public action/SDF
/// frames use the mandatory OFDM family. Apply this immediately before the
/// ESP raw injection so a targeted high-rate experiment cannot affect the
/// next synchronization or discovery transmission.
fn nan_control_rate() -> Result<()> {
    super::wifi::configure_fixed_tx_rate("6", super::wifi::raw_tx_interface(), true)
}

/// Inject an autonomous NAN publication with the address of the interface
/// that is live at the instant of TX. APSTA may associate after the publish
/// frame was built; keeping a SoftAP address in addr2 while injecting through
/// STA is silently discarded by IDF/firmware on some targets.
fn raw_tx_publish(bytes: &[u8], en_sys_seq: bool) -> Result<()> {
    if bytes.len() < 16 {
        return raw_tx(bytes, en_sys_seq);
    }
    let mut frame = bytes.to_vec();
    frame[10..16].copy_from_slice(&super::wifi::raw_tx_source_mac()?);
    nan_control_rate()?;
    raw_tx(&frame, en_sys_seq)
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
    map_id: u8,
) -> Result<Vec<u8>> {
    shared_nan::build_nan_availability_attribute(dw_tu, offset_tu, stride, active_ms, map_id)
}

fn nan_publish_attributes(
    settings: &SharedSettings,
    availability_map: u8,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let settings = settings.borrow();
    let dw_tu = settings.get_i32("nan.dw_tu", 512)?.clamp(128, 8_192) as u32;
    let offset_tu = settings.get_i32("nan.dw_off_tu", 0)?.max(0) as u32;
    let configured_stride = settings.get_i32("nan.dw_stride", 8)?.clamp(1, 64) as u32;
    // Infrastructure nodes are continuously powered and advertise every DW;
    // sleepy nodes retain their configured sparse cadence.  This is a NAN
    // role decision, not an AP-owner policy knob.
    let stride = if super::mode::infra_mode() {
        1
    } else {
        configured_stride
    };
    let active_ms = settings.get_i32("nan.active_ms", 64)?.clamp(16, 8_000) as u32;
    Ok((
        dmesh_rawnan::build_nan_availability_attribute(
            dw_tu,
            offset_tu,
            stride,
            active_ms,
            availability_map,
        )?,
        dmesh_rawnan::build_nan_device_capability_attribute(stride)?,
    ))
}

/// Encode the Device Capability attribute tied to the 2.4-GHz duty schedule.
///
/// Classic ESP32 is HT-only with one TX/RX chain. Do not advertise VHT, a
/// 5-GHz DW, or an invented channel-switch bound. The Committed DW value is
/// relative to DW0: 1, 2, 4, 8, or 16 means wake every 1, 2, 4, 8, or 16 DWs.
fn nan_device_capability_attribute(stride: u32) -> Result<Vec<u8>> {
    shared_nan::build_nan_device_capability_attribute(stride)
}

fn nan_publish_frame(
    availability: &[u8],
    device_capabilities: &[u8],
    include_sdea: bool,
    sdea_update: u8,
) -> Result<Vec<u8>> {
    nan_publish_frame_with_requestor(
        availability,
        device_capabilities,
        include_sdea,
        sdea_update,
        0,
    )
}

fn nan_publish_frame_with_requestor(
    availability: &[u8],
    device_capabilities: &[u8],
    include_sdea: bool,
    sdea_update: u8,
    requestor_instance: u8,
) -> Result<Vec<u8>> {
    nan_publish_frame_with_wake(
        availability,
        device_capabilities,
        include_sdea,
        sdea_update,
        requestor_instance,
        None,
        0,
        0,
    )
}

fn nan_publish_frame_with_wake(
    availability: &[u8],
    device_capabilities: &[u8],
    include_sdea: bool,
    sdea_update: u8,
    requestor_instance: u8,
    uart_wake_target: Option<u32>,
    uart_wake_duration_ms: u16,
    wake_flags: u8,
) -> Result<Vec<u8>> {
    let device_mac = station_mac()?;
    let tx_mac = super::wifi::raw_tx_source_mac()?;
    let cluster_bssid = nan_cluster_bssid();
    // First-contact unsolicited publish is standards-generated, not
    // capture-derived. Its Requestor Instance ID is zero because no received
    // discovery frame triggered it. Captured SDFs remain diagnostic evidence
    // only, so peer identifiers and optional attributes cannot leak into this
    // broadcast.
    Ok(nan_publish_frame_for_requestor_with_wake(
        &tx_mac,
        &device_mac,
        &cluster_bssid,
        availability,
        device_capabilities,
        include_sdea,
        sdea_update,
        requestor_instance,
        uart_wake_target,
        uart_wake_duration_ms,
        wake_flags,
    ))
}

/// Build the public Wi-Fi Aware publish SDF without reading hardware state.
/// Keeping this deterministic makes the wire ordering regression-testable.
fn nan_publish_frame_for(
    tx_mac: &[u8; 6],
    device_mac: &[u8; 6],
    cluster_bssid: &[u8; 6],
    availability: &[u8],
    device_capabilities: &[u8],
    include_sdea: bool,
    sdea_update: u8,
) -> Vec<u8> {
    nan_publish_frame_for_requestor(
        tx_mac,
        device_mac,
        cluster_bssid,
        availability,
        device_capabilities,
        include_sdea,
        sdea_update,
        0,
    )
}

fn nan_publish_frame_for_requestor(
    tx_mac: &[u8; 6],
    device_mac: &[u8; 6],
    cluster_bssid: &[u8; 6],
    availability: &[u8],
    device_capabilities: &[u8],
    include_sdea: bool,
    sdea_update: u8,
    requestor_instance: u8,
) -> Vec<u8> {
    nan_publish_frame_for_requestor_with_wake(
        tx_mac,
        device_mac,
        cluster_bssid,
        availability,
        device_capabilities,
        include_sdea,
        sdea_update,
        requestor_instance,
        None,
        0,
        0,
    )
}

fn nan_publish_frame_for_requestor_with_wake(
    tx_mac: &[u8; 6],
    device_mac: &[u8; 6],
    cluster_bssid: &[u8; 6],
    availability: &[u8],
    device_capabilities: &[u8],
    include_sdea: bool,
    sdea_update: u8,
    requestor_instance: u8,
    uart_wake_target: Option<u32>,
    uart_wake_duration_ms: u16,
    wake_flags: u8,
) -> Vec<u8> {
    let service_info = nan_service_info_with_wake(
        device_mac,
        uart_wake_target,
        uart_wake_duration_ms,
        wake_flags,
    );
    let mut frame = shared_nan::build_nan_publish_sdf_with_sdea(
        NAN_DISCOVERY_MAC,
        *tx_mac,
        *cluster_bssid,
        SVC_ID,
        NAN_ID,
        &service_info,
        include_sdea.then_some(sdea_update),
    );
    // The shared builder emits the SDA first. NAN Availability and Device
    // Capability are adapter-selected attributes, so append them here after
    // the service descriptor has been built.
    frame.extend_from_slice(device_capabilities);
    frame.extend_from_slice(availability);
    frame
}

/// DMesh NAN service-specific information shared with the Android JNI and
/// lmesh radio protocol.  Keeping this wire shape identical lets Android
/// accept a raw ESP NAN publish as a normal `dmesh` service discovery event.
fn nan_service_info(mac: &[u8; 6]) -> [u8; NAN_SERVICE_INFO_LEN] {
    nan_service_info_with_wake(mac, None, 0, 0)
}

fn nan_service_info_with_wake(
    mac: &[u8; 6],
    uart_wake_target: Option<u32>,
    uart_wake_duration_ms: u16,
    wake_flags: u8,
) -> [u8; NAN_SERVICE_INFO_LEN] {
    shared_nan::build_dmesh_service_info(
        *mac,
        1, // firmware_publisher
        uart_wake_target.map(|target| (target, uart_wake_duration_ms, wake_flags)),
    )
}

fn nan_followup_frame(dst: &[u8; 6], instance: u8, data: &[u8]) -> Result<Vec<u8>> {
    let mac = super::wifi::raw_tx_source_mac()?;
    let destination = if *dst == [0xff; 6] {
        &NAN_DISCOVERY_MAC
    } else {
        dst
    };
    Ok(shared_nan::build_nan_followup_sdf(
        *destination,
        mac,
        nan_cluster_bssid(),
        SVC_ID,
        instance,
        data,
    ))
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

/// Return the suffixes that may identify this node on raw NAN.  ESP-IDF uses
/// the STA MAC for station identity, while raw management/action frames sent
/// through the AP interface carry the adjacent SoftAP MAC.  The gateway maps
/// targets from the on-air NAN source, so filtering only the STA suffix drops
/// every addressed command by one in the final octet.
fn local_target_suffixes() -> Vec<String> {
    let mut suffixes = Vec::with_capacity(2);
    if let Ok(mac) = station_mac() {
        suffixes.push(mac_suffix4_hex(&mac));
    }
    if let Ok(mac) = super::wifi::raw_tx_source_mac() {
        let suffix = mac_suffix4_hex(&mac);
        if !suffixes.iter().any(|known| known == &suffix) {
            suffixes.push(suffix);
        }
    }
    suffixes
}

fn target_matches_local(target: u32) -> bool {
    let wanted = format!("{target:08x}");
    local_target_suffixes()
        .iter()
        .any(|suffix| suffix.eq_ignore_ascii_case(&wanted))
}

fn local_mac_matches(target: [u8; 6]) -> bool {
    station_mac().map(|mac| mac == target).unwrap_or(false)
        || super::wifi::raw_tx_source_mac()
            .map(|mac| mac == target)
            .unwrap_or(false)
}

fn is_broadcast_target(value: &str) -> bool {
    let value = value.strip_prefix("0x").unwrap_or(value);
    value.eq_ignore_ascii_case("ffffffff")
        || value.eq_ignore_ascii_case("ff:ff:ff:ff")
        || value.eq_ignore_ascii_case("broadcast")
        || value.eq_ignore_ascii_case("all")
}

fn parse_uart_wake_target(value: &str) -> Result<u32> {
    if is_broadcast_target(value) || value == "*" {
        return Ok(u32::MAX);
    }
    let value = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value);
    if value.len() != 8 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("uart wake target must be * or an 8-digit device suffix");
    }
    u32::from_str_radix(value, 16).map_err(|_| anyhow!("invalid uart wake target"))
}

fn mac_suffix4_hex(mac: &[u8; 6]) -> String {
    format!("{:02x}{:02x}{:02x}{:02x}", mac[2], mac[3], mac[4], mac[5])
}

unsafe extern "C" fn sniffer_cb(
    buf: *mut core::ffi::c_void,
    type_: sys::wifi_promiscuous_pkt_type_t,
) {
    if !buf.is_null() {
        super::wifi::mark_raw_first_frame(unsafe { sys::esp_timer_get_time().max(0) as u64 });
    }
    if buf.is_null()
        || (type_ != sys::wifi_promiscuous_pkt_type_t_WIFI_PKT_MGMT
            && type_ != sys::wifi_promiscuous_pkt_type_t_WIFI_PKT_DATA)
    {
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
    if frame.first().map(|value| value & 0x0c) == Some(0x08) {
        NAN_RX_DATA.fetch_add(1, Ordering::Relaxed);
    }
    // Keep NAN beacons long enough for the worker to make the bounded
    // cluster-reselection decision.  Filtering a foreign beacon here would
    // prevent recovery after the selected cluster disappears.
    let is_nan_beacon = frame.first() == Some(&0x80) && is_nan_bssid(frame);
    if !is_nan_beacon
        && !matches_filter(frame)
        && dmesh_rawnan::parse_espnow_action_frame(frame).is_none()
    {
        NAN_RX_PREFILTER_DROPS.fetch_add(1, Ordering::Relaxed);
        return;
    }
    let queue = NAN_RX_QUEUE.load(Ordering::Acquire);
    if queue.is_null() {
        NAN_RX_QUEUE_DROPS.fetch_add(1, Ordering::Relaxed);
        return;
    }
    unsafe {
        let received = core::ptr::addr_of_mut!(NAN_RX_SCRATCH);
        (*received).len = len as u16;
        (*received).rssi = pkt.rx_ctrl.rssi() as i8;
        (*received)._reserved = 0;
        (*received).local_us = now_us();
        core::ptr::copy_nonoverlapping(payload, (*received).data.as_mut_ptr(), len);
        let sent = sys::xQueueGenericSend(queue, received.cast::<c_void>(), 0, 0);
        if sent == 1 {
            super::wake::notify();
        } else {
            NAN_RX_QUEUE_DROPS.fetch_add(1, Ordering::Relaxed);
        }
    }
}

pub fn observe_promiscuous_frame(frame: &[u8], rssi: i32) {
    observe_promiscuous_frame_at(frame, rssi, now_us());
}

// Called from the ESP-IDF promiscuous RX callback. The parser/classifier and
// cluster policy are shareable, but queue ownership, atomics, telemetry,
// wake-notification, and timestamp sampling are firmware concerns. A host
// implementation should feed the equivalent raw frame plus its receive time
// into its own adapter callback rather than reuse this function directly.
fn observe_promiscuous_frame_at(frame: &[u8], rssi: i32, received_local_us: u64) {
    if !NAN_RUNNING.load(Ordering::Relaxed) {
        return;
    }
    NAN_RX_MGMT.fetch_add(1, Ordering::Relaxed);
    NAN_RX_BYTES.fetch_add(frame.len() as u32, Ordering::Relaxed);
    super::wifi::observe_promiscuous_frame(frame, rssi);
    if frame.first() == Some(&0x80) {
        observe_sync_beacon(frame, rssi);
    }
    let espnow_action = dmesh_rawnan::parse_espnow_action_frame(frame);
    if espnow_action.is_none() && !matches_filter(frame) {
        return;
    }
    NAN_RX_MATCHED.fetch_add(1, Ordering::Relaxed);
    // AP recovery scans may observe many unrelated beacons. Keep their timing
    // state but do not retain every full beacon in bounded telemetry.
    if frame.first() != Some(&0x80)
        || is_nan_bssid(frame)
        || shared_nan::is_direct_dmesh_ssid(frame)
    {
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
                let sequence = NAN_RX_BEACON.fetch_add(1, Ordering::AcqRel).wrapping_add(1);
                let index = (sequence as usize) % NAN_BEACON_HISTORY_LEN;
                if let Some(tsf_us) = beacon_tsf_us(frame) {
                    store_u64(
                        &NAN_BEACON_HISTORY_TSF_LO[index],
                        &NAN_BEACON_HISTORY_TSF_HI[index],
                        tsf_us,
                    );
                    store_u64(
                        &NAN_BEACON_HISTORY_LOCAL_LO[index],
                        &NAN_BEACON_HISTORY_LOCAL_HI[index],
                        received_local_us,
                    );
                    if let Some(source) = frame
                        .get(FRAME_SRC..FRAME_SRC + 6)
                        .and_then(|bytes| <&[u8] as TryInto<&[u8; 6]>>::try_into(bytes).ok())
                    {
                        for (byte, value) in source.iter().enumerate() {
                            NAN_BEACON_HISTORY_SOURCE[index][byte].store(*value, Ordering::Relaxed);
                        }
                    }
                    // Publish the sequence last so readers never accept a
                    // partially written history entry.
                    NAN_BEACON_HISTORY_SEQ[index].store(sequence, Ordering::Release);
                }
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
            if let Some((source, payload)) = espnow_action {
                // This is an ESP-NOW-compatible data bearer carried by raw
                // injection, not a NAN action protocol. NAN frames below
                // remain discovery/time-sync/activation control only.
                NAN_OBJECT_ACTION_DISPATCH.fetch_add(1, Ordering::Relaxed);
                telemetry::record_packet("wifi", Direction::Rx, payload, "source=espnow_raw");
                let _ = rssi;
                let _ = super::action_stream::receive_espnow(source, payload);
            } else if is_nan_sdf(frame) {
                NAN_RX_SDF.fetch_add(1, Ordering::Relaxed);
                if let Some(info) = raw_command_info(frame) {
                    super::mode::observe_ping("nan_raw", info.payload);
                    if is_dmesh_nan_service_info(info.payload) {
                        let kind = dmesh_service_descriptor_kind(frame).unwrap_or(3);
                        record_service_receipt(&info, kind, received_local_us);
                        if let Ok(mut captured) = last_dmesh_service_frame().lock() {
                            captured.clear();
                            captured.extend_from_slice(&frame[..frame.len().min(NAN_RX_FRAME_MAX)]);
                        }
                        if let Some((peer_suffix, duration_ms)) =
                            active_ack_for_service(info.payload)
                        {
                            telemetry::record_log(format!(
                                "event type=nan.active_ack peer={:08x} duration_ms={}",
                                peer_suffix, duration_ms
                            ));
                        }
                        if let Some((duration_ms, wake_flags)) =
                            wake_request_for_service(info.payload)
                        {
                            if wake_flags & NAN_SERVICE_FLAG_UART_WAKE != 0 {
                                super::mode::request_targeted_wake(duration_ms);
                                // NAN service discovery is the sleepy
                                // control plane. It may request the bounded
                                // STA/stream session, whereas ordinary NAN
                                // receive windows never start IP transport.
                                super::transport_runtime::request_active_session("nan_service");
                                // A sleepy node acknowledges the negotiated
                                // active interval in the same DW protocol.
                                // The ACK is queued here and released by the
                                // normal selected-DW transmitter, preserving
                                // the one-frame rendezvous rule.
                                if let Ok(availability) =
                                    nan_availability_attribute(512, 0, 8, 64, 1)
                                {
                                    if let Ok(capabilities) = nan_device_capability_attribute(8) {
                                        let peer_suffix = u32::from_be_bytes(
                                            info.source[2..6].try_into().unwrap_or([0; 4]),
                                        );
                                        if let Ok(ack) = nan_publish_frame_with_wake(
                                            &availability,
                                            &capabilities,
                                            true,
                                            2,
                                            0,
                                            Some(peer_suffix),
                                            duration_ms as u16,
                                            NAN_SERVICE_FLAG_ACTIVE_ACK,
                                        ) {
                                            if let Ok(mut queue) = nan_publish_queue().lock() {
                                                if queue.len() >= NAN_OUTGOING_QUEUE_MAX {
                                                    queue.pop_front();
                                                }
                                                queue.push_back(ack);
                                            }
                                        }
                                    }
                                }
                                telemetry::record_log(format!(
                                    "event type=nan.wake_request target=matched duration_ms={} peer={}",
                                    duration_ms,
                                    format_mac(&info.source)
                                ));
                            }
                        }
                        if kind == 0x01 {
                            if let Ok(mut captured) = last_dmesh_subscribe_frame().lock() {
                                captured.clear();
                                captured
                                    .extend_from_slice(&frame[..frame.len().min(NAN_RX_FRAME_MAX)]);
                            }
                            // A solicited Publisher responds on the next
                            // observed DW.  The response is still an SDF
                            // Publish, but its Requestor Instance ID is the
                            // instance carried by the matching Subscribe.
                            // Do not borrow source, optional attributes, or
                            // requestor state from a peer capture.
                            if let Ok(role) = configured_discovery_role() {
                                if role.responds_to_subscribe() {
                                    match queue_solicited_publish(info.instance) {
                                        Ok(queued) => telemetry::record_log(format!(
                                            "event type=nan.solicited_publish_queued peer={} requestor_instance={} queue_len={}",
                                            format_mac(&info.source), info.instance, queued
                                        )),
                                        Err(error) => telemetry::record_log(format!(
                                            "event type=nan.solicited_publish_queued ok=false peer={} requestor_instance={} message={}",
                                            format_mac(&info.source), info.instance,
                                            crate::commands::protocol::escape_value(&error.to_string())
                                        )),
                                    }
                                }
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
                        let duplicate = NAN_FOLLOWUP_DEDUP
                            .get_or_init(|| {
                                Mutex::new(shared_nan::service::FollowupDedup::new(256))
                            })
                            .lock()
                            .map(|mut dedup| {
                                dedup.is_duplicate(
                                    dmesh.device_id,
                                    dmesh.seq,
                                    dmesh.msg_type,
                                    dmesh.payload,
                                )
                            })
                            .unwrap_or(false);
                        if duplicate {
                            telemetry::record_log(format!(
                                "event type=nan.dmesh_followup_duplicate peer={} seq={} type={}",
                                format_mac(&info.source),
                                dmesh.seq,
                                dmesh.msg_type
                            ));
                            return;
                        }
                        record_followup_receipt(dmesh.msg_type, dmesh.seq, dmesh.payload);
                        let targets_this_device = local_mac_matches(dmesh.target_id);
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
                        record_raw_response(info.source, info.payload);
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
        if !accept_nan_cluster(frame, local_us) {
            return;
        }
        let bssid = frame
            .get(FRAME_BSSID..FRAME_BSSID + 6)
            .and_then(|bytes| <&[u8] as TryInto<&[u8; 6]>>::try_into(bytes).ok())
            .copied()
            .unwrap_or_else(nan_cluster_bssid);
        record_beacon_stats(
            BEACON_STATS_NAN,
            bssid,
            tsf_us,
            local_us,
            512,
            super::mode::raw_nan_data_stride(),
        );
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
    AP_LAST_BEACON_DIRECT.store(shared_nan::is_direct_dmesh_ssid(frame), Ordering::Relaxed);
    // Do not let nearby AP traffic overwrite an active NAN reference. AP
    // timing becomes the source only after the NAN source has gone stale.
    if last_beacon_local_us() == 0
        || local_us.saturating_sub(last_beacon_local_us()) >= NAN_CLUSTER_RESELECT_AFTER_US
    {
        record_beacon_stats(
            BEACON_STATS_AP,
            <&[u8] as TryInto<&[u8; 6]>>::try_into(bssid)
                .copied()
                .unwrap_or([0; 6]),
            tsf_us,
            local_us,
            interval_tu,
            1,
        );
    }
}

fn store_nan_cluster_bssid(frame: &[u8]) {
    let Some(bssid) = frame.get(FRAME_BSSID..FRAME_BSSID + 6) else {
        return;
    };
    let Ok(bssid) = <&[u8] as TryInto<&[u8; 6]>>::try_into(bssid) else {
        return;
    };
    store_nan_cluster_bssid_bytes(*bssid);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ClusterBeaconDecision {
    Initial,
    Current,
    Reselect,
    Foreign,
}

fn cluster_beacon_decision(
    locked: bool,
    current: [u8; 6],
    candidate: [u8; 6],
    last_local_us: u64,
    local_us: u64,
) -> ClusterBeaconDecision {
    if !locked {
        return ClusterBeaconDecision::Initial;
    }
    if current == candidate {
        return ClusterBeaconDecision::Current;
    }
    if local_us.saturating_sub(last_local_us) >= NAN_CLUSTER_RESELECT_AFTER_US {
        ClusterBeaconDecision::Reselect
    } else {
        ClusterBeaconDecision::Foreign
    }
}

/// Adopt one NAN cluster as the raw-duty timing authority.  Manual BSSID
/// filtering is a diagnostic override; otherwise a fresh selected cluster is
/// sticky and a foreign cluster can replace it only after bounded absence.
fn accept_nan_cluster(frame: &[u8], local_us: u64) -> bool {
    // The byte-level candidate extraction and freshness decision are protocol
    // logic; this wrapper additionally commits the selected BSSID to ESP32
    // atomics and updates firmware counters. Keep the pure decision in
    // rawnan when adding another adapter.
    let Some(candidate) = frame
        .get(FRAME_BSSID..FRAME_BSSID + 6)
        .and_then(|bytes| <&[u8] as TryInto<&[u8; 6]>>::try_into(bytes).ok())
        .copied()
    else {
        return false;
    };
    if NAN_FILTER_BSSID_ENABLED.load(Ordering::Relaxed) {
        let expected = configured_filter_bssid();
        if candidate != expected {
            NAN_CLUSTER_FOREIGN_DROPS.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        let changed =
            !NAN_CLUSTER_LOCKED.load(Ordering::Relaxed) || nan_cluster_bssid() != candidate;
        store_nan_cluster_bssid_bytes(candidate);
        NAN_CLUSTER_LOCKED.store(true, Ordering::Relaxed);
        if changed {
            NAN_CLUSTER_RESELECTS.fetch_add(1, Ordering::Relaxed);
        }
        return true;
    }
    match cluster_beacon_decision(
        NAN_CLUSTER_LOCKED.load(Ordering::Relaxed),
        nan_cluster_bssid(),
        candidate,
        last_beacon_local_us(),
        local_us,
    ) {
        ClusterBeaconDecision::Initial | ClusterBeaconDecision::Current => {
            store_nan_cluster_bssid_bytes(candidate);
            NAN_CLUSTER_LOCKED.store(true, Ordering::Relaxed);
            true
        }
        ClusterBeaconDecision::Reselect => {
            store_nan_cluster_bssid_bytes(candidate);
            NAN_CLUSTER_RESELECTS.fetch_add(1, Ordering::Relaxed);
            true
        }
        ClusterBeaconDecision::Foreign => {
            NAN_CLUSTER_FOREIGN_DROPS.fetch_add(1, Ordering::Relaxed);
            false
        }
    }
}

fn store_nan_cluster_bssid_bytes(bssid: [u8; 6]) {
    for (index, byte) in bssid.iter().enumerate() {
        NAN_CLUSTER_BSSID[index].store(*byte, Ordering::Relaxed);
    }
}

fn configured_filter_bssid() -> [u8; 6] {
    let mut bssid = [0_u8; 6];
    for (index, byte) in bssid.iter_mut().enumerate() {
        *byte = NAN_FILTER_BSSID[index].load(Ordering::Relaxed);
    }
    bssid
}

fn nan_cluster_bssid() -> [u8; 6] {
    let mut bssid = [0_u8; 6];
    for (index, byte) in bssid.iter_mut().enumerate() {
        *byte = NAN_CLUSTER_BSSID[index].load(Ordering::Relaxed);
    }
    bssid
}

/// Return the current NAN cluster BSSID for out-of-band data frames. The
/// value is only exposed while the selected cluster is fresh; callers should
/// fall back to their normal destination/BSSID when this returns `None`.
pub(crate) fn selected_cluster_bssid() -> Option<[u8; 6]> {
    if NAN_CLUSTER_LOCKED.load(Ordering::Acquire)
        && last_beacon_local_us() != 0
        && now_us().saturating_sub(last_beacon_local_us()) < NAN_CLUSTER_RESELECT_AFTER_US
    {
        Some(nan_cluster_bssid())
    } else {
        None
    }
}

fn is_nan_bssid(frame: &[u8]) -> bool {
    shared_nan::is_nan_bssid(frame)
}

fn beacon_tsf_us(frame: &[u8]) -> Option<u64> {
    shared_nan::beacon_tsf_us(frame)
}

fn beacon_interval_tu(frame: &[u8]) -> Option<u32> {
    shared_nan::beacon_interval_tu(frame)
}

fn is_nan_sdf(frame: &[u8]) -> bool {
    shared_nan::is_nan_sdf(frame)
}

fn matches_filter(frame: &[u8]) -> bool {
    if NAN_FILTER_BSSID_ENABLED.load(Ordering::Relaxed) {
        if frame.len() < FRAME_BSSID + 6 {
            return false;
        }
        if frame[FRAME_BSSID..FRAME_BSSID + 6] != configured_filter_bssid() {
            return false;
        }
    } else if is_nan_bssid(frame)
        && NAN_CLUSTER_LOCKED.load(Ordering::Relaxed)
        && frame.len() >= FRAME_BSSID + 6
        && frame[FRAME_BSSID..FRAME_BSSID + 6] != nan_cluster_bssid()
    {
        // `observe_sync_beacon()` has already decided whether a stale cluster
        // may be replaced.  Do not deliver service descriptors or actions
        // from a foreign cluster while the selected one remains fresh.
        return false;
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
    let last_raw_tx_slot = load_u64(&NAN_LAST_RAW_TX_SLOT_LO, &NAN_LAST_RAW_TX_SLOT_HI);
    let object_stats = object_service_stats();
    let common_metrics = shared_nan::metrics::format_nan_metrics(&nan_metrics_snapshot());
    format!(
        "{} nan dispatch={} accepted={} support=raw running={} filter={} bssid_filter={} hw_bssid_state={} hw_bssid_arms={} hw_bssid_reprobes={} hw_bssid_errors={} cluster_bssid={} cluster_locked={} cluster_foreign_drop={} cluster_reselects={} raw_mgmt={} raw_data={} raw_matched={} raw_action={} raw_beacon={} sync_beacon_tx={} ap_beacon={} ap_bssid={} ap_direct={} ap_interval_tu={} ap_rssi={} ap_age_ms={} raw_sdf={} raw_other={} raw_bytes={} raw_cmd_rx={} raw_cmd_tx={} raw_cmd_drop={} raw_resp_rx={} raw_resp_tx={} raw_outgoing_drop={} raw_last_tx_offset_us={} raw_last_tx_slot={} dmesh_service_rx={} dmesh_followup_rx={} dmesh_followup_tx={} rx_prefilter_drop={} rx_queue_drop={} rx_oversize_drop={} ipv6_udp_rx={} ipv6_udp_bytes={} object_active={} object_frames={} object_bytes={} object_rejected={} last_beacon_local_us={} last_beacon_tsf_us={} beacon_age_ms={} queue_len={} publish_queue_len={} publish_last_beacon={} publish_dw_tx={} publish_dw_skipped_slot={} publish_dw_guard_drops={} publish_dw_last_slot={} publish_dw_last_offset_us={}",
        common_metrics,
        NAN_OBJECT_ACTION_DISPATCH.load(Ordering::Relaxed),
        NAN_OBJECT_ACTION_ACCEPTED.load(Ordering::Relaxed),
        NAN_RUNNING.load(Ordering::Relaxed),
        filter_name(),
        NAN_FILTER_BSSID_ENABLED.load(Ordering::Relaxed),
        if NAN_HW_FILTER_STATE.load(Ordering::Relaxed) == NAN_HW_FILTER_ARMED {
            "armed"
        } else {
            "discovery"
        },
        NAN_HW_FILTER_ARMS.load(Ordering::Relaxed),
        NAN_HW_FILTER_REPROBES.load(Ordering::Relaxed),
        NAN_HW_FILTER_ERRORS.load(Ordering::Relaxed),
        cluster_bssid,
        NAN_CLUSTER_LOCKED.load(Ordering::Relaxed),
        NAN_CLUSTER_FOREIGN_DROPS.load(Ordering::Relaxed),
        NAN_CLUSTER_RESELECTS.load(Ordering::Relaxed),
        NAN_RX_MGMT.load(Ordering::Relaxed),
        NAN_RX_DATA.load(Ordering::Relaxed),
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
        NAN_RAW_COMMAND_TX.load(Ordering::Relaxed),
        NAN_RAW_COMMAND_DROPS.load(Ordering::Relaxed),
        NAN_RAW_RESPONSE_RX.load(Ordering::Relaxed),
        NAN_RAW_RESPONSE_TX.load(Ordering::Relaxed),
        NAN_RAW_OUTGOING_DROPS.load(Ordering::Relaxed),
        NAN_LAST_RAW_TX_OFFSET_US.load(Ordering::Relaxed),
        last_raw_tx_slot,
        NAN_DMESH_SERVICE_RX.load(Ordering::Relaxed),
        NAN_DMESH_FOLLOWUP_RX.load(Ordering::Relaxed),
        NAN_DMESH_FOLLOWUP_TX.load(Ordering::Relaxed),
        NAN_RX_PREFILTER_DROPS.load(Ordering::Relaxed),
        NAN_RX_QUEUE_DROPS.load(Ordering::Relaxed),
        NAN_RX_OVERSIZE_DROPS.load(Ordering::Relaxed),
        NAN_IPV6_UDP_RX.load(Ordering::Relaxed),
        NAN_IPV6_UDP_BYTES.load(Ordering::Relaxed),
        object_service_active(),
        object_stats.frames,
        object_stats.bytes,
        object_stats.rejected,
        last_beacon_local_us,
        last_beacon_tsf_us,
        beacon_age_ms,
        queue_len,
        publish_queue_len,
        NAN_LAST_PUBLISH_BEACON.load(Ordering::Relaxed),
        NAN_PUBLISH_DW_TX.load(Ordering::Relaxed),
        NAN_PUBLISH_DW_SKIPPED_SLOT.load(Ordering::Relaxed),
        NAN_PUBLISH_DW_LOCAL_GUARD_DROPS.load(Ordering::Relaxed),
        NAN_LAST_PUBLISH_SLOT.load(Ordering::Relaxed),
        NAN_PUBLISH_DW_LAST_OFFSET_US.load(Ordering::Relaxed)
    )
}

/// Populate the common raw-NAN metrics contract from ESP32 adapter state.
/// Hardware-only queue handles and object-store details stay out of this
/// snapshot; Linux and recovery can expose the same fields directly.
pub fn nan_metrics_snapshot() -> shared_nan::metrics::NanMetricsSnapshot {
    let queue_len = nan_outgoing_queue().lock().map(|q| q.len()).unwrap_or(0);
    let publish_queue_len = nan_publish_queue().lock().map(|q| q.len()).unwrap_or(0);
    shared_nan::metrics::NanMetricsSnapshot {
        dispatch: NAN_OBJECT_ACTION_DISPATCH.load(Ordering::Relaxed) as u64,
        accepted: NAN_OBJECT_ACTION_ACCEPTED.load(Ordering::Relaxed) as u64,
        rx_mgmt: NAN_RX_MGMT.load(Ordering::Relaxed) as u64,
        rx_data: NAN_RX_DATA.load(Ordering::Relaxed) as u64,
        rx_matched: NAN_RX_MATCHED.load(Ordering::Relaxed) as u64,
        rx_action: NAN_RX_ACTION.load(Ordering::Relaxed) as u64,
        rx_beacon: NAN_RX_BEACON.load(Ordering::Relaxed) as u64,
        rx_sdf: NAN_RX_SDF.load(Ordering::Relaxed) as u64,
        rx_other: NAN_RX_OTHER.load(Ordering::Relaxed) as u64,
        rx_bytes: NAN_RX_BYTES.load(Ordering::Relaxed) as u64,
        sync_beacon_tx: NAN_SYNC_BEACON_TX.load(Ordering::Relaxed) as u64,
        ap_beacon: AP_RX_BEACON.load(Ordering::Relaxed) as u64,
        command_rx: NAN_RAW_COMMAND_RX.load(Ordering::Relaxed) as u64,
        command_tx: NAN_RAW_COMMAND_TX.load(Ordering::Relaxed) as u64,
        command_drops: NAN_RAW_COMMAND_DROPS.load(Ordering::Relaxed) as u64,
        response_rx: NAN_RAW_RESPONSE_RX.load(Ordering::Relaxed) as u64,
        response_tx: NAN_RAW_RESPONSE_TX.load(Ordering::Relaxed) as u64,
        outgoing_drops: NAN_RAW_OUTGOING_DROPS.load(Ordering::Relaxed) as u64,
        service_rx: NAN_DMESH_SERVICE_RX.load(Ordering::Relaxed) as u64,
        followup_rx: NAN_DMESH_FOLLOWUP_RX.load(Ordering::Relaxed) as u64,
        followup_tx: NAN_DMESH_FOLLOWUP_TX.load(Ordering::Relaxed) as u64,
        prefilter_drops: NAN_RX_PREFILTER_DROPS.load(Ordering::Relaxed) as u64,
        queue_drops: NAN_RX_QUEUE_DROPS.load(Ordering::Relaxed) as u64,
        oversize_drops: NAN_RX_OVERSIZE_DROPS.load(Ordering::Relaxed) as u64,
        ipv6_udp_rx: NAN_IPV6_UDP_RX.load(Ordering::Relaxed) as u64,
        ipv6_udp_bytes: NAN_IPV6_UDP_BYTES.load(Ordering::Relaxed) as u64,
        cluster_foreign_drops: NAN_CLUSTER_FOREIGN_DROPS.load(Ordering::Relaxed) as u64,
        cluster_reselects: NAN_CLUSTER_RESELECTS.load(Ordering::Relaxed) as u64,
        hw_filter_arms: NAN_HW_FILTER_ARMS.load(Ordering::Relaxed) as u64,
        hw_filter_reprobes: NAN_HW_FILTER_REPROBES.load(Ordering::Relaxed) as u64,
        hw_filter_errors: NAN_HW_FILTER_ERRORS.load(Ordering::Relaxed) as u64,
        publish_dw_tx: NAN_PUBLISH_DW_TX.load(Ordering::Relaxed) as u64,
        publish_dw_skipped: NAN_PUBLISH_DW_SKIPPED_SLOT.load(Ordering::Relaxed) as u64,
        publish_guard_drops: NAN_PUBLISH_DW_LOCAL_GUARD_DROPS.load(Ordering::Relaxed) as u64,
        queue_len: queue_len as u64,
        publish_queue_len: publish_queue_len as u64,
        last_beacon_local_us: last_beacon_local_us(),
        last_beacon_tsf_us: last_beacon_tsf_us(),
        last_raw_tx_offset_us: NAN_LAST_RAW_TX_OFFSET_US.load(Ordering::Relaxed) as u64,
        last_raw_tx_slot: load_u64(&NAN_LAST_RAW_TX_SLOT_LO, &NAN_LAST_RAW_TX_SLOT_HI),
        last_publish_beacon: NAN_LAST_PUBLISH_BEACON.load(Ordering::Relaxed) as u64,
        last_publish_slot: NAN_LAST_PUBLISH_SLOT.load(Ordering::Relaxed) as u64,
        last_publish_offset_us: NAN_PUBLISH_DW_LAST_OFFSET_US.load(Ordering::Relaxed) as u64,
    }
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
    fn transport_fragments_use_scheduler_queue_without_mutating_payload() {
        clear_pending_nan_transmissions();
        let peer = [0x84, 0x0d, 0x8e, 0x07, 0x42, 0xc5];
        let envelope = [0x7f, 0x18, 0xfe, 0x34, 0x40, 0x01, 0x00, 0x08];
        enqueue_outgoing_raw(peer, NAN_ID, &envelope, true).unwrap();
        let queue = nan_outgoing_queue().lock().unwrap();
        let item = queue.back().unwrap();
        assert_eq!(item.dst, peer);
        assert_eq!(item.instance, NAN_ID);
        assert_eq!(item.payload, envelope);
        assert!(item.response);
        drop(queue);
        clear_pending_nan_transmissions();
    }

    #[test]
    fn cluster_selection_is_sticky_until_the_current_cluster_is_stale() {
        let first = [0x50, 0x6f, 0x9a, 0x01, 0x11, 0x11];
        let foreign = [0x50, 0x6f, 0x9a, 0x01, 0x22, 0x22];
        assert_eq!(
            cluster_beacon_decision(false, NAN_BSSID, first, 0, 10),
            ClusterBeaconDecision::Initial
        );
        assert_eq!(
            cluster_beacon_decision(true, first, first, 1_000, 1_500),
            ClusterBeaconDecision::Current
        );
        assert_eq!(
            cluster_beacon_decision(
                true,
                first,
                foreign,
                1_000,
                1_000 + NAN_CLUSTER_RESELECT_AFTER_US - 1
            ),
            ClusterBeaconDecision::Foreign
        );
        assert_eq!(
            cluster_beacon_decision(
                true,
                first,
                foreign,
                1_000,
                1_000 + NAN_CLUSTER_RESELECT_AFTER_US
            ),
            ClusterBeaconDecision::Reselect
        );
    }

    #[test]
    fn raw_nan_publish_is_a_publish_with_required_attribute_order() {
        let tx_mac = [0xd8, 0xa0, 0x1d, 0x4c, 0x5e, 0x1d];
        let device_mac = [0xd8, 0xa0, 0x1d, 0x4c, 0x5e, 0x1c];
        let bssid = [0x50, 0x6f, 0x9a, 0x01, 0x55, 0x46];
        let availability = nan_availability_attribute(512, 0, 8, 250, 1).unwrap();
        let capabilities = nan_device_capability_attribute(8).unwrap();
        let frame = nan_publish_frame_for(
            &tx_mac,
            &device_mac,
            &bssid,
            &availability,
            &capabilities,
            true,
            2,
        );

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
        assert_eq!(attributes[2].1, &capabilities[3..]);
        assert_eq!(attributes[3].1, &availability[3..]);
        assert_eq!(offset, frame.len(), "no bytes may trail the NAN attributes");
    }

    #[test]
    fn raw_nan_bare_publish_can_omit_optional_sdea() {
        let tx_mac = [0xd8, 0xa0, 0x1d, 0x4c, 0x5e, 0x1d];
        let device_mac = [0xd8, 0xa0, 0x1d, 0x4c, 0x5e, 0x1c];
        let bssid = [0x50, 0x6f, 0x9a, 0x01, 0x55, 0x46];
        let availability = nan_availability_attribute(512, 0, 8, 250, 1).unwrap();
        let capabilities = nan_device_capability_attribute(8).unwrap();
        let frame = nan_publish_frame_for(
            &tx_mac,
            &device_mac,
            &bssid,
            &availability,
            &capabilities,
            false,
            2,
        );
        let mut ids = Vec::new();
        let mut offset = NAN_ACTION_START;
        while offset + 3 <= frame.len() {
            let size = u16::from_le_bytes([frame[offset + 1], frame[offset + 2]]) as usize;
            ids.push(frame[offset]);
            offset += 3 + size;
        }
        assert_eq!(ids, [0x03, 0x0f, 0x12]);
    }

    #[test]
    fn solicited_publish_binds_the_subscriber_instance_only() {
        let tx_mac = [0xd8, 0xa0, 0x1d, 0x4c, 0x5e, 0x1d];
        let device_mac = [0xd8, 0xa0, 0x1d, 0x4c, 0x5e, 0x1c];
        let bssid = [0x50, 0x6f, 0x9a, 0x01, 0x55, 0x46];
        let availability = nan_availability_attribute(512, 0, 8, 250, 1).unwrap();
        let capabilities = nan_device_capability_attribute(8).unwrap();
        let frame = nan_publish_frame_for_requestor(
            &tx_mac,
            &device_mac,
            &bssid,
            &availability,
            &capabilities,
            true,
            2,
            7,
        );
        let descriptor = &frame[NAN_ACTION_START + 3..];
        assert_eq!(descriptor[6], NAN_ID);
        assert_eq!(descriptor[7], 7);
        assert_eq!(descriptor[8], NAN_SERVICE_CONTROL_PUBLISH_WITH_INFO);
        assert_eq!(&frame[FRAME_DST..FRAME_DST + 6], NAN_DISCOVERY_MAC);
    }

    #[test]
    fn role_change_discards_pending_solicited_publish() {
        let mut queue = nan_publish_queue().lock().unwrap();
        queue.clear();
        queue.push_back(vec![0x03, 0x01, 0x10]);
        drop(queue);

        NAN_DISCOVERY_ROLE.store(
            NanDiscoveryRole::PublisherSolicited.code(),
            Ordering::Relaxed,
        );
        set_discovery_role(NanDiscoveryRole::Publisher);

        assert!(nan_publish_queue().lock().unwrap().is_empty());
    }

    #[test]
    fn sdea_update_value_only_changes_the_indicator() {
        let update_two = shared_nan::build_nan_service_extension(2);
        let update_four = shared_nan::build_nan_service_extension(4);
        assert_eq!(&update_two[..6], &[0x0e, 0x04, 0x00, NAN_ID, 0x00, 0x02]);
        assert_eq!(update_two[6], 2);
        assert_eq!(update_four[6], 4);
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
    fn availability_bitmap_matches_eight_512_tu_slot_schedule() {
        let availability = nan_availability_attribute(512, 0, 8, 250, 1).unwrap();
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
