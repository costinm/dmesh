//! Bounded promiscuous NAN discovery-window capture for always-on firmware.
//!
//! This adapter is intentionally small: Main owns its sleepy/TSF-aware power
//! policy, while Recovery is an always-on infra receiver and needs a regular
//! 512-TU capture cadence to establish NAN beacon timing and receive SDF or
//! follow-up frames. ESP-NOW-compatible actions seen inside this bounded
//! window are handed to the same shared action ingress as the private driver
//! hook; outside the window there is no promiscuous capture.

use core::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, AtomicU8, AtomicUsize, Ordering};

const NAN_DW_PERIOD_MS: u32 = 512 * 1_024 / 1_000;
const NAN_DW_CAPTURE_MS: u32 = 64;
/// Infra startup needs enough uninterrupted time to see a NAN beacon and
/// establish a cluster/TSF before switching to the low-duty DW cadence.
const NAN_INITIAL_ACQUIRE_MS: u32 = 1_500;
/// Temporary paired-C6 laboratory override.  It bypasses beacon acquisition
/// only so the private Address-3 comparator can be tested with promiscuous
/// mode completely disabled.  Normal cluster discovery remains the default
/// when this is `None`; do not turn this into association policy.
// A fixed cluster is no longer compiled into an image.  The registered radio
// control handler can select one at runtime, which is essential for a
// repeatable A3-comparator matrix without a flash per cluster.
const LAB_FIXED_CLUSTER_BSSID: Option<[u8; 6]> = None;

/// `0=normal`, `1=disabled`, `2=manual`.  Normal is the only policy which
/// lets `poll()` schedule acquisition/DW capture.  Disabled/manual both keep
/// promiscuous RX off until an explicit future manual-capture operation.
static LAB_DW_POLICY: AtomicU8 = AtomicU8::new(0);
/// Requested cadence in 512 ms discovery windows. This is separate from the
/// lab override: mode configuration selects `0`, `1`, `8`, or `16`; the lab
/// control can still temporarily suppress a configured capture schedule.
static DW_INTERVAL: AtomicU8 = AtomicU8::new(0);

static STARTED: AtomicBool = AtomicBool::new(false);
static CAPTURING: AtomicBool = AtomicBool::new(false);
static UNTIL_MS: AtomicU32 = AtomicU32::new(0);
static NEXT_MS: AtomicU32 = AtomicU32::new(0);
static ACQUIRING: AtomicBool = AtomicBool::new(false);
// A runtime control request may restore normal DW policy while a bounded ROC
// lease is still owned by ESP-IDF.  Record the requested initial acquisition
// here and begin it from the worker only after ROC's completion callback.
static ACQUIRE_PENDING: AtomicBool = AtomicBool::new(false);
static FRAMES: AtomicU32 = AtomicU32::new(0);
static BYTES: AtomicU32 = AtomicU32::new(0);
static BEACONS: AtomicU32 = AtomicU32::new(0);
static SDFS: AtomicU32 = AtomicU32::new(0);
static FOLLOWUPS: AtomicU32 = AtomicU32::new(0);
static FOLLOWUP_SEQUENCE: AtomicU16 = AtomicU16::new(1);
/// Shared Recovery/Main receipt history. It stores copied, bounded follow-up
/// data only after the Wi-Fi callback has classified the frame; it never
/// retains a driver buffer or adds an ingress queue.
pub const FOLLOWUP_HISTORY_CAPACITY: usize = 10;
/// Active Subscribe control handling runs on the copied ingress worker and
/// can finish just after the narrow receive capture closes. Retain a few
/// response *intents* until the next captured DW; never retain ESP-IDF frame
/// buffers or send NAN management traffic outside that window.
const PENDING_FOLLOWUP_CAPACITY: usize = 4;
/// Publish uses the same bounded Service-Info limit as the portable NAN
/// contract. Only copied CBOR bytes live here; Wi-Fi builds the action frame
/// at the point of DW-gated transmission.
const ACTIVE_PUBLISH_MAX_LEN: usize = dmesh_rawnan::NAN_ACTIVE_PUBLISH_MAX_LEN;
const ACTIVE_PUBLISH_REFRESH_MS: u32 = dmesh_rawnan::NAN_ACTIVE_PUBLISH_INTERVAL_MS as u32;
const PENDING_EMPTY: u8 = 0;
const PENDING_WRITING: u8 = 1;
const PENDING_READY: u8 = 2;

struct FollowupSlot {
    source: [AtomicU8; 6],
    target: [AtomicU8; 6],
    msg_type: AtomicU8,
    seq: AtomicU16,
    payload_len: AtomicU16,
    payload: [AtomicU8; dmesh_rawnan::NAN_COMMAND_MAX_LEN],
    last_seen_ms: AtomicU32,
}

impl FollowupSlot {
    const fn new() -> Self {
        Self {
            source: [const { AtomicU8::new(0) }; 6],
            target: [const { AtomicU8::new(0) }; 6],
            msg_type: AtomicU8::new(0),
            seq: AtomicU16::new(0),
            payload_len: AtomicU16::new(0),
            payload: [const { AtomicU8::new(0) }; dmesh_rawnan::NAN_COMMAND_MAX_LEN],
            last_seen_ms: AtomicU32::new(0),
        }
    }
}

/// A copied, bounded follow-up receipt suitable for a control response.
#[derive(Clone, Copy)]
pub struct FollowupSnapshot {
    pub source: [u8; 6],
    pub target: [u8; 6],
    pub msg_type: u8,
    pub seq: u16,
    pub payload: [u8; dmesh_rawnan::NAN_COMMAND_MAX_LEN],
    pub payload_len: u16,
    pub payload_hash: u32,
    pub last_seen_ms: u32,
}

static FOLLOWUP_HISTORY: [FollowupSlot; FOLLOWUP_HISTORY_CAPACITY] =
    [const { FollowupSlot::new() }; FOLLOWUP_HISTORY_CAPACITY];
static FOLLOWUP_HISTORY_NEXT: AtomicUsize = AtomicUsize::new(0);
static PENDING_FOLLOWUP_NEXT: AtomicUsize = AtomicUsize::new(0);
static PENDING_FOLLOWUP_QUEUED: AtomicU32 = AtomicU32::new(0);
static PENDING_FOLLOWUP_SENT: AtomicU32 = AtomicU32::new(0);
static PENDING_FOLLOWUP_DROPPED: AtomicU32 = AtomicU32::new(0);
static ACTIVE_PUBLISH_ENABLED: AtomicBool = AtomicBool::new(false);
static ACTIVE_PUBLISH_PENDING: AtomicBool = AtomicBool::new(false);
static ACTIVE_PUBLISH_LEN: AtomicU16 = AtomicU16::new(0);
static ACTIVE_PUBLISH_LAST_SENT_MS: AtomicU32 = AtomicU32::new(0);
static ACTIVE_PUBLISH_INFO: [AtomicU8; ACTIVE_PUBLISH_MAX_LEN] =
    [const { AtomicU8::new(0) }; ACTIVE_PUBLISH_MAX_LEN];

struct PendingFollowup {
    state: AtomicU8,
    peer: [AtomicU8; 6],
    payload_len: AtomicU16,
    payload: [AtomicU8; dmesh_rawnan::NAN_COMMAND_MAX_LEN],
    queued_ms: AtomicU32,
}

impl PendingFollowup {
    const fn new() -> Self {
        Self {
            state: AtomicU8::new(PENDING_EMPTY),
            peer: [const { AtomicU8::new(0) }; 6],
            payload_len: AtomicU16::new(0),
            payload: [const { AtomicU8::new(0) }; dmesh_rawnan::NAN_COMMAND_MAX_LEN],
            queued_ms: AtomicU32::new(0),
        }
    }
}

static PENDING_FOLLOWUPS: [PendingFollowup; PENDING_FOLLOWUP_CAPACITY] =
    [const { PendingFollowup::new() }; PENDING_FOLLOWUP_CAPACITY];
static ACTIVE_SUBSCRIBE_PENDING: AtomicBool = AtomicBool::new(false);
static ACTIVE_SUBSCRIBE_PEER: [AtomicU8; 6] = [
    AtomicU8::new(0), AtomicU8::new(0), AtomicU8::new(0),
    AtomicU8::new(0), AtomicU8::new(0), AtomicU8::new(0),
];
/// Application-owned CBOR dispatcher. Wi-Fi owns the callback and packet copy;
/// Recovery/Main only receives a copied Service Info payload on the common
/// ingress worker.
pub type NanServiceInfoHandler = fn([u8; 6], &[u8]);
static SERVICE_INFO_HANDLER: AtomicUsize = AtomicUsize::new(0);
static FILTER_PENDING: AtomicBool = AtomicBool::new(false);
static FILTER_ARMED: AtomicBool = AtomicBool::new(false);
static FILTER_ARMS: AtomicU32 = AtomicU32::new(0);
static FILTER_ERRORS: AtomicU32 = AtomicU32::new(0);
static SYNC_ANCHOR_PENDING: AtomicBool = AtomicBool::new(false);
static SYNC_ANCHOR_LO: AtomicU32 = AtomicU32::new(0);
static SYNC_ANCHOR_HI: AtomicU32 = AtomicU32::new(0);
static FILTER_BSSID: [AtomicU8; 6] = [
    AtomicU8::new(0),
    AtomicU8::new(0),
    AtomicU8::new(0),
    AtomicU8::new(0),
    AtomicU8::new(0),
    AtomicU8::new(0),
];

fn selected_bssid() -> [u8; 6] {
    let mut bssid = [0u8; 6];
    for (index, byte) in bssid.iter_mut().enumerate() {
        *byte = FILTER_BSSID[index].load(Ordering::Relaxed);
    }
    bssid
}

fn bssid_is_unset(bssid: [u8; 6]) -> bool {
    bssid == [0; 6]
}

fn record_followup(followup: dmesh_rawnan::DmeshNanFollowup<'_>) {
    let index = FOLLOWUP_HISTORY_NEXT.fetch_add(1, Ordering::Relaxed) % FOLLOWUP_HISTORY_CAPACITY;
    let slot = &FOLLOWUP_HISTORY[index];
    let payload = &followup.payload[..followup.payload.len().min(dmesh_rawnan::NAN_COMMAND_MAX_LEN)];
    for (index, byte) in followup.device_id.iter().enumerate() {
        slot.source[index].store(*byte, Ordering::Relaxed);
    }
    for (index, byte) in followup.target_id.iter().enumerate() {
        slot.target[index].store(*byte, Ordering::Relaxed);
    }
    for (index, byte) in payload.iter().enumerate() {
        slot.payload[index].store(*byte, Ordering::Relaxed);
    }
    slot.msg_type.store(followup.msg_type, Ordering::Relaxed);
    slot.seq.store(followup.seq, Ordering::Relaxed);
    slot.payload_len.store(payload.len() as u16, Ordering::Relaxed);
    // Publish last so readers see either the previous complete entry or this
    // complete copied entry. The bounded cache is advisory diagnostics only.
    slot.last_seen_ms.store(now_ms(), Ordering::Release);
}

/// Return the fixed-size newest/oldest independent receipt cache. Unused
/// entries are `None`; callers can choose their presentation order.
pub fn followup_history(
    out: &mut [Option<FollowupSnapshot>; FOLLOWUP_HISTORY_CAPACITY],
) {
    for (index, slot) in FOLLOWUP_HISTORY.iter().enumerate() {
        let last_seen_ms = slot.last_seen_ms.load(Ordering::Acquire);
        if last_seen_ms == 0 {
            out[index] = None;
            continue;
        }
        let mut source = [0; 6];
        let mut target = [0; 6];
        let mut payload = [0; dmesh_rawnan::NAN_COMMAND_MAX_LEN];
        for (index, byte) in source.iter_mut().enumerate() {
            *byte = slot.source[index].load(Ordering::Relaxed);
        }
        for (index, byte) in target.iter_mut().enumerate() {
            *byte = slot.target[index].load(Ordering::Relaxed);
        }
        let payload_len = usize::from(slot.payload_len.load(Ordering::Relaxed))
            .min(dmesh_rawnan::NAN_COMMAND_MAX_LEN);
        for (index, byte) in payload[..payload_len].iter_mut().enumerate() {
            *byte = slot.payload[index].load(Ordering::Relaxed);
        }
        out[index] = Some(FollowupSnapshot {
            source,
            target,
            msg_type: slot.msg_type.load(Ordering::Relaxed),
            seq: slot.seq.load(Ordering::Relaxed),
            payload,
            payload_len: payload_len as u16,
            payload_hash: payload[..payload_len]
                .iter()
                .fold(0x811c_9dc5u32, |hash, byte| {
                    (hash ^ u32::from(*byte)).wrapping_mul(0x0100_0193)
                }),
            last_seen_ms,
        });
    }
}

/// Queue accounting for DW-gated control responses. `pending` is sampled
/// advisory state; the monotonic counters are suitable for an E2E snapshot.
pub fn pending_followup_stats() -> (u32, u32, u32, u8) {
    let pending = PENDING_FOLLOWUPS
        .iter()
        .filter(|slot| slot.state.load(Ordering::Acquire) == PENDING_READY)
        .count() as u8;
    (
        PENDING_FOLLOWUP_QUEUED.load(Ordering::Relaxed),
        PENDING_FOLLOWUP_SENT.load(Ordering::Relaxed),
        PENDING_FOLLOWUP_DROPPED.load(Ordering::Relaxed),
        pending,
    )
}

fn mark_active_subscribe(peer: [u8; 6]) {
    for (index, value) in peer.iter().enumerate() {
        ACTIVE_SUBSCRIBE_PEER[index].store(*value, Ordering::Relaxed);
    }
    ACTIVE_SUBSCRIBE_PENDING.store(true, Ordering::Release);
}

/// Consume the active-subscribe marker associated with a copied Service Info
/// record. The common ingress worker is single-consumer, so this ties a
/// response to the current request without passing Wi-Fi driver buffers or
/// callback state outside this owner.
pub fn take_active_subscribe(peer: [u8; 6]) -> bool {
    if !ACTIVE_SUBSCRIBE_PENDING.load(Ordering::Acquire) {
        return false;
    }
    let matches = ACTIVE_SUBSCRIBE_PEER.iter().enumerate().all(|(index, value)| {
        value.load(Ordering::Relaxed) == peer[index]
    });
    if matches {
        ACTIVE_SUBSCRIBE_PENDING.store(false, Ordering::Release);
    }
    matches
}

fn queue_followup_response(peer: [u8; 6], response: &[u8]) -> bool {
    if response.len() > dmesh_rawnan::NAN_COMMAND_MAX_LEN {
        return false;
    }
    let now = now_ms();
    let mut oldest_ready: Option<(&PendingFollowup, u32)> = None;
    for _ in 0..PENDING_FOLLOWUP_CAPACITY {
        let index = PENDING_FOLLOWUP_NEXT.fetch_add(1, Ordering::Relaxed)
            % PENDING_FOLLOWUP_CAPACITY;
        let slot = &PENDING_FOLLOWUPS[index];
        if slot
            .state
            .compare_exchange(
                PENDING_EMPTY,
                PENDING_WRITING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            if slot.state.load(Ordering::Acquire) == PENDING_READY {
                let payload_len = usize::from(slot.payload_len.load(Ordering::Relaxed))
                    .min(dmesh_rawnan::NAN_COMMAND_MAX_LEN);
                let identical = payload_len == response.len()
                    && slot
                        .peer
                        .iter()
                        .enumerate()
                        .all(|(index, byte)| byte.load(Ordering::Relaxed) == peer[index])
                    && slot.payload[..payload_len]
                        .iter()
                        .enumerate()
                        .all(|(index, byte)| byte.load(Ordering::Relaxed) == response[index]);
                if identical {
                    // Match `NanFollowupQueue`: duplicate work is already
                    // retained, so report success without consuming a slot.
                    return true;
                }
                let age = now.wrapping_sub(slot.queued_ms.load(Ordering::Relaxed));
                if oldest_ready.is_none_or(|(_, oldest_age)| age > oldest_age) {
                    oldest_ready = Some((slot, age));
                }
            }
            continue;
        }
        for (index, byte) in peer.iter().enumerate() {
            slot.peer[index].store(*byte, Ordering::Relaxed);
        }
        for (index, byte) in response.iter().enumerate() {
            slot.payload[index].store(*byte, Ordering::Relaxed);
        }
        slot.payload_len.store(response.len() as u16, Ordering::Relaxed);
        slot.queued_ms.store(now, Ordering::Relaxed);
        slot.state.store(PENDING_READY, Ordering::Release);
        PENDING_FOLLOWUP_QUEUED.fetch_add(1, Ordering::Relaxed);
        return true;
    }
    if let Some((slot, _)) = oldest_ready {
        if slot
            .state
            .compare_exchange(
                PENDING_READY,
                PENDING_WRITING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
        {
            // The portable queue replaces its oldest intent at capacity. Keep
            // the same behavior here while counting the evicted response as a
            // bounded drop for diagnostics.
            for (index, byte) in peer.iter().enumerate() {
                slot.peer[index].store(*byte, Ordering::Relaxed);
            }
            for (index, byte) in response.iter().enumerate() {
                slot.payload[index].store(*byte, Ordering::Relaxed);
            }
            slot.payload_len.store(response.len() as u16, Ordering::Relaxed);
            slot.queued_ms.store(now, Ordering::Relaxed);
            slot.state.store(PENDING_READY, Ordering::Release);
            PENDING_FOLLOWUP_QUEUED.fetch_add(1, Ordering::Relaxed);
            PENDING_FOLLOWUP_DROPPED.fetch_add(1, Ordering::Relaxed);
            return true;
        }
    }
    PENDING_FOLLOWUP_DROPPED.fetch_add(1, Ordering::Relaxed);
    false
}

fn transmit_followup_response(peer: [u8; 6], response: &[u8]) -> bool {
    if response.len() > dmesh_rawnan::NAN_COMMAND_MAX_LEN {
        return false;
    }
    let interface = if crate::wifi_esp::sta_associated() || !crate::wifi_esp::lab_open_ap_active() {
        crate::wifi_esp::RadioInterface::Sta
    } else {
        crate::wifi_esp::RadioInterface::Ap
    };
    let Some(local) = crate::wifi_esp::interface_mac(interface) else {
        return false;
    };
    let bssid = selected_bssid();
    if bssid_is_unset(bssid) {
        return false;
    }
    let sequence = FOLLOWUP_SEQUENCE.fetch_add(1, Ordering::Relaxed).max(1);
    let Ok(payload) = dmesh_rawnan::build_dmesh_followup_payload(
        7, // command_cbor
        sequence,
        local,
        peer,
        response,
    ) else {
        return false;
    };
    let frame = dmesh_rawnan::build_nan_followup_sdf(
        peer,
        local,
        bssid,
        dmesh_rawnan::DMESH_SERVICE_ID,
        1,
        &payload,
    );
    crate::wifi_espnow_esp::transmit_public_action_on_interface(
        interface,
        peer,
        bssid,
        &frame[24..],
    )
}

fn drain_pending_followup_responses() {
    if !CAPTURING.load(Ordering::Acquire) {
        return;
    }
    for slot in &PENDING_FOLLOWUPS {
        if slot
            .state
            .compare_exchange(
                PENDING_READY,
                PENDING_WRITING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            continue;
        }
        let mut peer = [0u8; 6];
        let mut payload = [0u8; dmesh_rawnan::NAN_COMMAND_MAX_LEN];
        for (index, byte) in peer.iter_mut().enumerate() {
            *byte = slot.peer[index].load(Ordering::Relaxed);
        }
        let payload_len = usize::from(slot.payload_len.load(Ordering::Acquire))
            .min(dmesh_rawnan::NAN_COMMAND_MAX_LEN);
        for (index, byte) in payload[..payload_len].iter_mut().enumerate() {
            *byte = slot.payload[index].load(Ordering::Relaxed);
        }
        slot.state.store(PENDING_EMPTY, Ordering::Release);
        if transmit_followup_response(peer, &payload[..payload_len]) {
            PENDING_FOLLOWUP_SENT.fetch_add(1, Ordering::Relaxed);
        } else {
            PENDING_FOLLOWUP_DROPPED.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Send the current active Publish exactly from the worker while a bounded DW
/// capture is open. This is deliberately adjacent to the follow-up drain: it
/// shares the selected BSSID/interface policy but remains an independent
/// broadcast descriptor rather than a reply to a peer command.
fn drain_active_publish() {
    if !CAPTURING.load(Ordering::Acquire) || !ACTIVE_PUBLISH_ENABLED.load(Ordering::Acquire) {
        return;
    }
    let now = now_ms();
    let pending = ACTIVE_PUBLISH_PENDING.load(Ordering::Acquire);
    let last_sent = ACTIVE_PUBLISH_LAST_SENT_MS.load(Ordering::Acquire);
    if !pending && now.wrapping_sub(last_sent) < ACTIVE_PUBLISH_REFRESH_MS {
        return;
    }
    let len = usize::from(ACTIVE_PUBLISH_LEN.load(Ordering::Acquire)).min(ACTIVE_PUBLISH_MAX_LEN);
    if len == 0 {
        return;
    }
    let interface = if crate::wifi_esp::sta_associated() || !crate::wifi_esp::lab_open_ap_active() {
        crate::wifi_esp::RadioInterface::Sta
    } else {
        crate::wifi_esp::RadioInterface::Ap
    };
    let Some(local) = crate::wifi_esp::interface_mac(interface) else {
        return;
    };
    let bssid = selected_bssid();
    if bssid_is_unset(bssid) {
        return;
    }
    let mut service_info = [0u8; ACTIVE_PUBLISH_MAX_LEN];
    for (index, byte) in service_info[..len].iter_mut().enumerate() {
        *byte = ACTIVE_PUBLISH_INFO[index].load(Ordering::Relaxed);
    }
    let frame = dmesh_rawnan::build_nan_publish_sdf(
        dmesh_rawnan::NAN_DISCOVERY_MAC,
        local,
        bssid,
        dmesh_rawnan::DMESH_SERVICE_ID,
        1,
        &service_info[..len],
    );
    if crate::wifi_espnow_esp::transmit_public_action_on_interface(
        interface,
        dmesh_rawnan::NAN_DISCOVERY_MAC,
        bssid,
        &frame[24..],
    ) {
        ACTIVE_PUBLISH_LAST_SENT_MS.store(now, Ordering::Release);
        ACTIVE_PUBLISH_PENDING.store(false, Ordering::Release);
    }
}

/// Send one bounded DMesh NAN Follow-up response during the currently open
/// discovery capture window. The copied control worker may complete after
/// that window, in which case this queues the response for the next DW.
/// This module owns scheduling/context; `wifi_espnow_esp` remains the sole
/// ESP-IDF public-action submitter.
pub fn send_followup_response(peer: [u8; 6], response: &[u8]) -> bool {
    if CAPTURING.load(Ordering::Acquire) {
        transmit_followup_response(peer, response)
    } else {
        queue_followup_response(peer, response)
    }
}

/// Send a caller-built NAN Follow-up only while this adapter owns an open DW.
/// The raw-radio handler uses this for explicit E2E probes; it deliberately
/// rejects outside-DW calls instead of letting a generic action transmitter
/// turn the probe into an always-on management-frame path.
pub fn send_followup_frame(frame: &[u8]) -> Result<usize, &'static str> {
    if !CAPTURING.load(Ordering::Acquire) {
        return Err("NAN follow-up outside discovery window");
    }
    if !dmesh_rawnan::is_nan_followup(frame) || frame.len() < 24 {
        return Err("NAN follow-up frame required");
    }
    let destination: [u8; 6] = frame[4..10].try_into().map_err(|_| "NAN destination")?;
    let bssid: [u8; 6] = frame[16..22].try_into().map_err(|_| "NAN BSSID")?;
    if bssid != selected_bssid() {
        return Err("NAN follow-up BSSID mismatch");
    }
    let interface = if crate::wifi_esp::sta_associated() || !crate::wifi_esp::lab_open_ap_active() {
        crate::wifi_esp::RadioInterface::Sta
    } else {
        crate::wifi_esp::RadioInterface::Ap
    };
    crate::wifi_espnow_esp::transmit_public_action_on_interface(
        interface,
        destination,
        bssid,
        &frame[24..],
    )
    .then_some(frame.len())
    .ok_or("NAN follow-up driver rejected")
}

fn now_ms() -> u32 {
    (unsafe { esp_idf_sys::esp_timer_get_time().max(0) as u64 } / 1_000) as u32
}

fn now_us() -> u64 {
    unsafe { esp_idf_sys::esp_timer_get_time().max(0) as u64 }
}

fn store_sync_anchor_us(value: u64) {
    SYNC_ANCHOR_LO.store(value as u32, Ordering::Relaxed);
    SYNC_ANCHOR_HI.store((value >> 32) as u32, Ordering::Release);
}

fn take_sync_anchor_us() -> Option<u64> {
    if !SYNC_ANCHOR_PENDING.swap(false, Ordering::AcqRel) {
        return None;
    }
    let high = SYNC_ANCHOR_HI.load(Ordering::Acquire);
    let low = SYNC_ANCHOR_LO.load(Ordering::Relaxed);
    Some((u64::from(high) << 32) | u64::from(low))
}

/// Selected NAN cluster and the last local beacon receive anchor. Exposed for
/// paired-device diagnosis; it does not retain frames or change radio policy.
pub fn sync_diagnostics() -> ([u8; 6], u64, bool) {
    let high = SYNC_ANCHOR_HI.load(Ordering::Acquire);
    let low = SYNC_ANCHOR_LO.load(Ordering::Relaxed);
    (
        selected_bssid(),
        (u64::from(high) << 32) | u64::from(low),
        capturing(),
    )
}

fn due(now: u32, deadline: u32) -> bool {
    now.wrapping_sub(deadline) < (1 << 31)
}

/// `(all_management_frames, bytes, NAN_beacons, NAN_SDFs, NAN_followups)`.
pub fn stats() -> (u32, u32, u32, u32, u32) {
    (
        FRAMES.load(Ordering::Relaxed),
        BYTES.load(Ordering::Relaxed),
        BEACONS.load(Ordering::Relaxed),
        SDFS.load(Ordering::Relaxed),
        FOLLOWUPS.load(Ordering::Relaxed),
    )
}

/// Replace the active NAN Publish Service Info. The bytes are normally the
/// common tagged-CBOR boot/discovery announce, so UART, UDP6, NOW, and NAN SD
/// all expose one semantic record. This only changes portable state; the
/// next confirmed DW performs the actual radio transmission.
pub fn configure_active_publish(enabled: bool, service_info: &[u8]) -> bool {
    if service_info.len() > ACTIVE_PUBLISH_MAX_LEN || (enabled && service_info.is_empty()) {
        return false;
    }
    ACTIVE_PUBLISH_ENABLED.store(false, Ordering::Release);
    for (index, byte) in service_info.iter().enumerate() {
        ACTIVE_PUBLISH_INFO[index].store(*byte, Ordering::Relaxed);
    }
    ACTIVE_PUBLISH_LEN.store(service_info.len() as u16, Ordering::Release);
    ACTIVE_PUBLISH_LAST_SENT_MS.store(0, Ordering::Release);
    ACTIVE_PUBLISH_PENDING.store(enabled, Ordering::Release);
    ACTIVE_PUBLISH_ENABLED.store(enabled, Ordering::Release);
    true
}

/// `(enabled, pending, service_info_len, last_sent_ms)` for a bounded control
/// status response. The record itself is intentionally not returned.
pub fn active_publish_status() -> (bool, bool, u16, u32) {
    (
        ACTIVE_PUBLISH_ENABLED.load(Ordering::Acquire),
        ACTIVE_PUBLISH_PENDING.load(Ordering::Acquire),
        ACTIVE_PUBLISH_LEN.load(Ordering::Acquire),
        ACTIVE_PUBLISH_LAST_SENT_MS.load(Ordering::Acquire),
    )
}

/// Select the non-radio owner of active-subscribe Service Info. This must be
/// installed before a NAN DW interval is enabled.
pub fn set_service_info_handler(handler: Option<NanServiceInfoHandler>) {
    SERVICE_INFO_HANDLER.store(
        handler.map_or(0, |handler| handler as usize),
        Ordering::Release,
    );
}

fn dispatch_service_info(item: crate::shared_ingress_esp::IngressPacket, payload: &[u8]) {
    let handler = SERVICE_INFO_HANDLER.load(Ordering::Acquire);
    if handler != 0 {
        let handler: NanServiceInfoHandler = unsafe { core::mem::transmute(handler) };
        handler(item.source(), payload);
    }
}

/// `(armed, successful_arms, errors)` for the private A3/BSSID comparator.
pub fn filter_stats() -> (bool, u32, u32) {
    (
        FILTER_ARMED.load(Ordering::Acquire),
        FILTER_ARMS.load(Ordering::Relaxed),
        FILTER_ERRORS.load(Ordering::Relaxed),
    )
}

/// Current lab DW policy.  This is an applied runtime property, not an NVS
/// setting or a Main sleepy policy.
pub fn lab_dw_policy() -> u8 {
    LAB_DW_POLICY.load(Ordering::Acquire)
}

/// Change the bounded infra capture policy from the normal worker context.
/// Disabling capture immediately turns promiscuous receive off, so a later
/// raw NOW/NAN action result can prove it was not delivered by a stale DW.
pub fn set_lab_dw_policy(policy: u8) -> bool {
    if policy > 2 {
        return false;
    }
    LAB_DW_POLICY.store(policy, Ordering::Release);
    if policy != 0 {
        let _ = crate::wifi_esp::set_promiscuous(false);
        CAPTURING.store(false, Ordering::Release);
        ACQUIRING.store(false, Ordering::Release);
        ACQUIRE_PENDING.store(false, Ordering::Release);
        return true;
    }
    // Restoring normal policy begins a fresh bounded acquisition interval;
    // it does not resurrect an arbitrary pre-disable TSF anchor.
    if STARTED.load(Ordering::Acquire) {
        if crate::wifi_nonpromisc_probe_esp::roc_in_flight() {
            // `esp_wifi_remain_on_channel` retains its request and owns the
            // receive transition until its done callback. Do not toggle
            // promiscuous mode from this direct handler in the meantime.
            CAPTURING.store(false, Ordering::Release);
            ACQUIRING.store(true, Ordering::Release);
            ACQUIRE_PENDING.store(true, Ordering::Release);
            return true;
        }
        let now = now_ms();
        if crate::wifi_esp::set_promiscuous(true) {
            CAPTURING.store(true, Ordering::Release);
            ACQUIRING.store(true, Ordering::Release);
            ACQUIRE_PENDING.store(false, Ordering::Release);
            UNTIL_MS.store(now.wrapping_add(NAN_INITIAL_ACQUIRE_MS), Ordering::Release);
            NEXT_MS.store(now.wrapping_add(NAN_INITIAL_ACQUIRE_MS), Ordering::Release);
            return true;
        }
        return false;
    }
    true
}

/// The private A3 comparator experiment was removed: C6 has no separate NAN
/// receive lane, and the normal policy deliberately leaves STA/AP BSSID
/// checks off. Preserve the control result so callers can report that an arm
/// request is unavailable rather than silently changing receive policy.
pub fn set_lab_comparator(bssid: Option<[u8; 6]>, enabled: bool) -> bool {
    if !enabled {
        FILTER_ARMED.store(false, Ordering::Release);
        return true;
    }
    let _ = bssid;
    FILTER_ERRORS.fetch_add(1, Ordering::Relaxed);
    false
}

/// Reset only monotonic capture accounting for a test-matrix epoch.  The
/// selected cluster and actual radio policy remain unchanged.
pub fn reset_stats() {
    FRAMES.store(0, Ordering::Release);
    BYTES.store(0, Ordering::Release);
    BEACONS.store(0, Ordering::Release);
    SDFS.store(0, Ordering::Release);
    FOLLOWUPS.store(0, Ordering::Release);
    FILTER_ARMS.store(0, Ordering::Release);
    FILTER_ERRORS.store(0, Ordering::Release);
}

/// Whether the bounded discovery-window receiver is currently enabled.
/// Normal UDP6 and NOW-like traffic continues outside this interval; callers
/// use this only for diagnostics and NAN capture accounting.
pub fn capturing() -> bool {
    CAPTURING.load(Ordering::Acquire)
}

/// Whether starting a ROC lease with `duration_ms` would overlap a normal NAN
/// permissive window.  The caller supplies the ROC duration plus its driver
/// completion guard. This is the shared scheduling boundary between the two
/// ESP-only receive mechanisms; it allocates nothing and has no side effect.
pub fn roc_conflicts(duration_ms: u32) -> bool {
    if !STARTED.load(Ordering::Acquire) || lab_dw_policy() != 0 {
        return false;
    }
    if CAPTURING.load(Ordering::Acquire) || ACQUIRE_PENDING.load(Ordering::Acquire) {
        return true;
    }
    let now = now_ms();
    let next = NEXT_MS.load(Ordering::Acquire);
    due(now, next) || next.wrapping_sub(now) <= duration_ms
}

/// Install the management callback and begin the bounded infra acquisition
/// interval.  After 1.5 seconds [`poll`] reduces capture to 64 ms per 512 TU;
/// Recovery never remains a continuous promiscuous monitor.
pub fn start(interval: u8) -> bool {
    if !matches!(interval, 1 | 8 | 16) {
        return false;
    }
    DW_INTERVAL.store(interval, Ordering::Release);
    if STARTED.swap(true, Ordering::AcqRel) {
        return true;
    }
    if !crate::shared_ingress_esp::start(
        crate::shared_ingress_esp::IngressKind::NanServiceInfo,
        dispatch_service_info,
    ) {
        STARTED.store(false, Ordering::Release);
        return false;
    }
    let mut filter = esp_idf_sys::wifi_promiscuous_filter_t {
        filter_mask: esp_idf_sys::WIFI_PROMIS_FILTER_MASK_MGMT,
    };
    let result = crate::wifi_esp::configure_promiscuous_rx(Some(callback), &mut filter);
    if !result {
        crate::shared_ingress_esp::stop(crate::shared_ingress_esp::IngressKind::NanServiceInfo);
        STARTED.store(false, Ordering::Release);
        return false;
    }
    let now = now_ms();
    if !crate::wifi_esp::set_promiscuous(true) {
        crate::shared_ingress_esp::stop(crate::shared_ingress_esp::IngressKind::NanServiceInfo);
        STARTED.store(false, Ordering::Release);
        return false;
    }
    CAPTURING.store(true, Ordering::Release);
    ACQUIRING.store(true, Ordering::Release);
    ACQUIRE_PENDING.store(false, Ordering::Release);
    UNTIL_MS.store(now.wrapping_add(NAN_INITIAL_ACQUIRE_MS), Ordering::Release);
    NEXT_MS.store(now.wrapping_add(NAN_INITIAL_ACQUIRE_MS), Ordering::Release);
    drain_pending_followup_responses();
    drain_active_publish();
    true
}

/// Change an active mode's DW cadence. Zero stops the NAN capture layer;
/// nonzero values are measured in 512 ms DWs. The Wi-Fi owner invokes this
/// from its normal worker path, never from a driver callback.
pub fn set_interval(interval: u8) -> bool {
    if interval == 0 {
        stop();
        return true;
    }
    if !matches!(interval, 1 | 8 | 16) {
        return false;
    }
    if !STARTED.load(Ordering::Acquire) {
        return start(interval);
    }
    DW_INTERVAL.store(interval, Ordering::Release);
    true
}

/// Quiesce the bounded NAN capture before another radio personality changes
/// callbacks, channel, or Wi-Fi driver state.  The callback registration is
/// cleared while promiscuous mode is off, so no NAN receive path remains live.
pub fn stop() {
    if !STARTED.swap(false, Ordering::AcqRel) {
        return;
    }
    let _ = crate::wifi_esp::set_promiscuous(false);
    let mut filter = esp_idf_sys::wifi_promiscuous_filter_t { filter_mask: 0 };
    let _ = crate::wifi_esp::configure_promiscuous_rx(None, &mut filter);
    crate::shared_ingress_esp::stop(crate::shared_ingress_esp::IngressKind::NanServiceInfo);
    CAPTURING.store(false, Ordering::Release);
    ACQUIRING.store(false, Ordering::Release);
    ACQUIRE_PENDING.store(false, Ordering::Release);
    UNTIL_MS.store(0, Ordering::Release);
    NEXT_MS.store(0, Ordering::Release);
    DW_INTERVAL.store(0, Ordering::Release);
}

/// Advance the fixed Recovery discovery cadence. Call from the normal worker;
/// all radio state changes occur outside the Wi-Fi driver callback.
pub fn poll() {
    if !STARTED.load(Ordering::Acquire) {
        return;
    }
    if lab_dw_policy() != 0 {
        return;
    }
    let now = now_ms();
    if ACQUIRE_PENDING.load(Ordering::Acquire) {
        if crate::wifi_nonpromisc_probe_esp::roc_in_flight() {
            return;
        }
        if !crate::wifi_esp::set_promiscuous(true) {
            return;
        }
        ACQUIRE_PENDING.store(false, Ordering::Release);
        ACQUIRING.store(true, Ordering::Release);
        CAPTURING.store(true, Ordering::Release);
        UNTIL_MS.store(now.wrapping_add(NAN_INITIAL_ACQUIRE_MS), Ordering::Release);
        NEXT_MS.store(now.wrapping_add(NAN_INITIAL_ACQUIRE_MS), Ordering::Release);
        drain_pending_followup_responses();
        drain_active_publish();
        return;
    }
    // A direct one-shot ROC request may have been made between periodic
    // worker polls. Keep the DW state intact until the driver's done callback
    // releases the static request, instead of changing promiscuous mode from
    // underneath ROC.
    if crate::wifi_nonpromisc_probe_esp::roc_in_flight() {
        return;
    }
    // A beacon observed during acquisition or a DW defines the next DW in
    // local time. This aligns independent devices to the same cluster beacon
    // instead of preserving their arbitrary boot-time phase.
    if let Some(anchor_us) = take_sync_anchor_us() {
        let next_us = dmesh_rawnan::next_nan_dw_start_us(anchor_us, now_us());
        NEXT_MS.store(
            (next_us / 1_000).min(u64::from(u32::MAX)) as u32,
            Ordering::Release,
        );
    }
    // A callback may record a selected cluster, but it must not change the
    // STA/AP hardware BSSID policy. Clear the pending bit outside callback
    // context and continue with the ordinary bounded DW schedule.
    if !CAPTURING.load(Ordering::Acquire) && FILTER_PENDING.swap(false, Ordering::AcqRel) {
        FILTER_ARMED.store(false, Ordering::Release);
    }
    if CAPTURING.load(Ordering::Acquire) {
        drain_pending_followup_responses();
        drain_active_publish();
        if due(now, UNTIL_MS.load(Ordering::Relaxed)) {
            let _ = crate::wifi_esp::set_promiscuous(false);
            CAPTURING.store(false, Ordering::Release);
            if ACQUIRING.swap(false, Ordering::AcqRel) {
                NEXT_MS.store(now.wrapping_add(dw_period_ms()), Ordering::Release);
            }
        }
        return;
    }
    if !due(now, NEXT_MS.load(Ordering::Relaxed)) {
        return;
    }
    if crate::wifi_esp::set_promiscuous(true) {
        CAPTURING.store(true, Ordering::Release);
        UNTIL_MS.store(now.wrapping_add(NAN_DW_CAPTURE_MS), Ordering::Relaxed);
        NEXT_MS.store(now.wrapping_add(dw_period_ms()), Ordering::Relaxed);
        drain_pending_followup_responses();
        drain_active_publish();
    }
}

fn dw_period_ms() -> u32 {
    NAN_DW_PERIOD_MS.saturating_mul(u32::from(DW_INTERVAL.load(Ordering::Acquire).max(1)))
}

unsafe extern "C" fn callback(
    buffer: *mut core::ffi::c_void,
    kind: esp_idf_sys::wifi_promiscuous_pkt_type_t,
) {
    if buffer.is_null() || kind != esp_idf_sys::wifi_promiscuous_pkt_type_t_WIFI_PKT_MGMT {
        return;
    }
    let packet = unsafe { &*(buffer as *const esp_idf_sys::wifi_promiscuous_pkt_t) };
    let len = packet.rx_ctrl.sig_len() as usize;
    if len < dmesh_rawnan::FRAME_DATA || len > dmesh_rawnan::NAN_RX_FRAME_MAX {
        return;
    }
    let frame = unsafe { core::slice::from_raw_parts(packet.payload.as_ptr(), len) };
    receive_management_frame(frame);
}

fn receive_management_frame(frame: &[u8]) {
    FRAMES.fetch_add(1, Ordering::Relaxed);
    BYTES.fetch_add(frame.len().min(u32::MAX as usize) as u32, Ordering::Relaxed);
    // The private action dispatcher is useful when the driver admits a frame,
    // but C6 does not continuously accept unsolicited peer actions through
    // it. DW capture is the reliable, explicitly bounded fallback.
    crate::wifi_espnow_esp::receive_promiscuous_action(frame);
    match dmesh_rawnan::classify(frame) {
        dmesh_rawnan::FrameKind::Beacon if dmesh_rawnan::is_nan_beacon(frame) => {
            BEACONS.fetch_add(1, Ordering::Relaxed);
            if let Some(bssid) = frame.get(dmesh_rawnan::FRAME_BSSID..dmesh_rawnan::FRAME_BSSID + 6)
            {
                let selected = selected_bssid();
                // Acquisition selects one cluster and keeps it until the
                // state machine explicitly rediscovers. Re-anchoring from
                // every visible cluster gave peers different DW phases.
                if bssid_is_unset(selected) {
                    for (index, byte) in bssid.iter().enumerate() {
                        FILTER_BSSID[index].store(*byte, Ordering::Relaxed);
                    }
                }
                if bssid_is_unset(selected) || bssid == selected {
                    // Store the local receive point, not the beacon TSF. TSF
                    // is cluster-wide but local receive time schedules this
                    // adapter's radio window for the selected cluster.
                    store_sync_anchor_us(now_us());
                    SYNC_ANCHOR_PENDING.store(true, Ordering::Release);
                    FILTER_PENDING.store(true, Ordering::Release);
                }
            }
        }
        dmesh_rawnan::FrameKind::Sdf => {
            SDFS.fetch_add(1, Ordering::Relaxed);
            let Some(source) = frame.get(10..16).and_then(|source| source.try_into().ok()) else {
                return;
            };
            // Active Subscribe puts its custom CBOR Service Info in SDEA;
            // active Publish puts it directly in the SDA. Both are delivered
            // through the same copied ingress record as UART/SD control.
            let active_subscribe = dmesh_rawnan::active_subscribe_service_info(
                frame,
                dmesh_rawnan::DMESH_SERVICE_ID,
            );
            let payload = active_subscribe.map(|item| item.service_info).or_else(|| {
                dmesh_rawnan::service_descriptor_payload(frame, dmesh_rawnan::DMESH_SERVICE_ID)
            });
            if let Some(payload) = payload {
                if active_subscribe.is_some() {
                    mark_active_subscribe(source);
                }
                let _ = crate::shared_ingress_esp::enqueue(
                    crate::shared_ingress_esp::IngressKind::NanServiceInfo,
                    source,
                    payload,
                );
            }
        }
        dmesh_rawnan::FrameKind::Followup => {
            FOLLOWUPS.fetch_add(1, Ordering::Relaxed);
            if let Some(payload) = dmesh_rawnan::service_descriptor_payload(
                frame,
                dmesh_rawnan::DMESH_SERVICE_ID,
            ) {
                if let Some(followup) = dmesh_rawnan::parse_dmesh_nan_followup(payload) {
                    record_followup(followup);
                }
            }
        }
        _ => {}
    }
}
