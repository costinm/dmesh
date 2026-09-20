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
/// Open a little before the selected cluster's beacon. The ESP timestamp is
/// local receive time, so this absorbs bounded callback/worker jitter without
/// changing the common DW phase.
const NAN_DW_PRE_BEACON_US: u64 = 8_000;
/// A NAN DW is 16 TU (16.384 ms). Begin 8 ms before its selected beacon so
/// callback/timer jitter cannot lose the synchronization frame; the capture
/// itself therefore lasts 24 ms at the current millisecond timer resolution.
const NAN_DW_DURATION_MS: u32 = 16;
const NAN_DW_CAPTURE_MS: u32 = 24;
/// ESP-NOW gets the immediately adjacent 16-TU window. It must not overlap
/// NAN transmission contention in the preceding NAN DW.
const NOW_DW_CAPTURE_MS: u32 = NAN_DW_DURATION_MS;
/// Sleepy peers receive one NAN window followed immediately by one NOW
/// window. This retains the radio only for the paired discovery opportunity,
/// rather than waiting another 512-TU period for the NOW receiver.
const SLEEPY_DW_PAIR_TAIL_MS: u32 = 4;
/// Infra startup must keep receiving until it has a realistic chance to see
/// an Android/host NAN beacon and establish a cluster/TSF.  A 1.5-second
/// acquisition raced Android's active-publish setup; after that it sampled a
/// 64 ms window on an arbitrary phase and could miss every peer DW forever.
/// This bounded 15-second cost is paid only after a radio-mode replacement;
/// normal operation still reduces to the configured low-duty cadence.
const NAN_INITIAL_ACQUIRE_MS: u32 = 15_000;
/// A selected cluster is useful only while its timing beacon remains live.
/// Use the shared NAN stale bound (rather than the shorter foreign-cluster
/// reselect guard): at that point retain neither the BSSID nor its old local
/// phase and return to bounded acquisition. Otherwise a moved or stopped
/// cluster can pin a sleepy device to a phase which no peer uses.
const NAN_CLUSTER_MISSED_BEACON_US: u64 = dmesh_rawnan::NAN_CLUSTER_STALE_AFTER_US;

/// Temporary paired-C6 laboratory override.  It bypasses beacon acquisition
/// only so the private Address-3 comparator can be tested with promiscuous
/// mode completely disabled.  Normal cluster discovery remains the default
/// when this is `None`; do not turn this into association policy.
// A fixed cluster is no longer compiled into an image.  The registered radio
// control handler can select one at runtime, which is essential for a
// repeatable A3-comparator matrix without a flash per cluster.
const LAB_FIXED_CLUSTER_BSSID: Option<[u8; 6]> = None;

/// `0=normal`, `1=disabled`, `2=manual`.  Normal is the only policy which
/// lets `service_deadline()` schedule acquisition/DW capture. Disabled/manual both keep
/// promiscuous RX off until an explicit future manual-capture operation.
static LAB_DW_POLICY: AtomicU8 = AtomicU8::new(0);
/// Requested cadence in 512 ms discovery windows. This is separate from the
/// lab override: mode configuration selects `0`, `1`, `8`, or `16`; the lab
/// control can still temporarily suppress a configured capture schedule.
static DW_INTERVAL: AtomicU8 = AtomicU8::new(0);

static STARTED: AtomicBool = AtomicBool::new(false);
/// Set only by Main immediately before an explicit DW8 sleep.  A generic
/// profile replacement must reacquire, even though its previous cluster
/// observation remains available for diagnostics.
static RESUME_SAVED_SYNC: AtomicBool = AtomicBool::new(false);
static CAPTURING: AtomicBool = AtomicBool::new(false);
/// A bounded raw-NOW client needs continuous management receive after its
/// OPEN succeeds. The private C6 action dispatcher can receive the bootstrap
/// but is not reliable for the peer's unsolicited stream flight once the
/// ordinary 64 ms NAN DW closes. This flag is set only for the lifetime of
/// one explicit client; it is not a background monitor or a timer-driven
/// service tick.
///
/// The NAN capture owner is also the only code that changes promiscuous mode,
/// so NOW extends that owner's lease instead of creating a competing receive
/// callback or a bearer-private queue.  `end_now_receive_lease` restores the
/// normal low-duty DW cadence after the client finishes or times out.
static NOW_CLIENT_RECEIVE_LEASE: AtomicBool = AtomicBool::new(false);
/// Active non-sleepy NOW is a standing control plane.  Unlike the bounded
/// client/responder leases below, it is selected only when Main commits an
/// active DW1 profile and lets an idle peer hear the very first broadcast
/// action.  DW8 sleepy mode never enables this flag.
static NOW_ACTIVE_RECEIVE: AtomicBool = AtomicBool::new(false);
/// A responder needs the same receive coverage while its accepted association
/// waits for the client's request or ACK. Unlike the client lease this is
/// explicitly time-bounded and rearmed only by an accepted NOW datagram. The
/// Main task includes this deadline in its blocking wait, so expiry does not
/// add a service tick or keep an idle device in promiscuous mode.
static NOW_SERVICE_RECEIVE_UNTIL_MS: AtomicU32 = AtomicU32::new(0);
/// C6 action replies commonly arrive several seconds after the peer's driver
/// accepted the first action. Eight seconds covers that observed one-flight
/// delay while bounding a stalled responder much more tightly than a client
/// operation deadline.
const NOW_SERVICE_RECEIVE_LEASE_MS: u32 = 8_000;
static UNTIL_MS: AtomicU32 = AtomicU32::new(0);
static NEXT_MS: AtomicU32 = AtomicU32::new(0);
static ACQUIRING: AtomicBool = AtomicBool::new(false);
/// Main selects paired NAN+NOW capture only for a sleepy DW8 epoch. It is
/// state, not a timer: `service_deadline` owns both window boundaries.
static SLEEPY_DW_PAIR: AtomicBool = AtomicBool::new(false);
static SLEEPY_DW_PAIR_SECOND: AtomicBool = AtomicBool::new(false);
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
/// Device observations are semantic receive facts, separate from the small
/// directed follow-up history. This is the ESP projection of the common
/// `radio.devices` contract: fixed-capacity, no allocations, and no retained
/// driver frame. A peer without a decoded DMesh announce remains provisional
/// by its NAN MAC address.
pub const NAN_DEVICE_OBSERVATION_CAPACITY: usize = 10;
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
/// A fresh announce must cross independently phased NAN discovery windows.
/// Eight 512-TU windows reaches the next DW0/DW8 boundary without creating a
/// polling path or reacting to every repeated active-Subscribe packet.
const ACTIVE_PUBLISH_BURST_WINDOWS: u8 = 8;
/// A targeted wake must overlap a peer that listens only once per DW8. Ten
/// 512-TU attempts span about 4.72 seconds from first to last submission,
/// exceeding the 4.194-second DW8 period with one base-window of margin.
/// Eight attempts span only seven gaps (about 3.67 seconds) and can fit
/// entirely between two peer receive windows.
const NAN_WAKE_BURST_WINDOWS: u8 = 10;
/// Externally requested active-Subscribe SDFs wait for a local NAN discovery
/// window. Each accepted control request owns one semantic intent slot and is
/// either transmitted for its requested number of windows or explicitly
/// rejected when fixed capacity is exhausted. No accepted frame is replaced.
const PENDING_SDF_MAX_LEN: usize = 384;
const PENDING_SDF_CAPACITY: usize = 4;
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

const OBSERVATION_EMPTY: u8 = 0;
const OBSERVATION_WRITING: u8 = 1;
const OBSERVATION_READY: u8 = 2;
pub const NAN_OBSERVATION_OTHER: u8 = 0;
pub const NAN_OBSERVATION_ACTIVE_PUBLISH: u8 = 1;
pub const NAN_OBSERVATION_ACTIVE_SUBSCRIBE: u8 = 2;
pub const NAN_OBSERVATION_FOLLOWUP: u8 = 3;

struct NanDeviceObservationSlot {
    state: AtomicU8,
    peer: [AtomicU8; 6],
    bssid: [AtomicU8; 6],
    first_seen_ms: AtomicU32,
    last_seen_ms: AtomicU32,
    packets: AtomicU32,
    active_publish_rx: AtomicU32,
    active_subscribe_rx: AtomicU32,
    followup_rx: AtomicU32,
    last_kind: AtomicU8,
    last_channel: AtomicU8,
    last_payload_len: AtomicU16,
    last_payload_hash: AtomicU32,
}

impl NanDeviceObservationSlot {
    const fn new() -> Self {
        Self {
            state: AtomicU8::new(OBSERVATION_EMPTY),
            peer: [const { AtomicU8::new(0) }; 6],
            bssid: [const { AtomicU8::new(0) }; 6],
            first_seen_ms: AtomicU32::new(0),
            last_seen_ms: AtomicU32::new(0),
            packets: AtomicU32::new(0),
            active_publish_rx: AtomicU32::new(0),
            active_subscribe_rx: AtomicU32::new(0),
            followup_rx: AtomicU32::new(0),
            last_kind: AtomicU8::new(NAN_OBSERVATION_OTHER),
            last_channel: AtomicU8::new(0),
            last_payload_len: AtomicU16::new(0),
            last_payload_hash: AtomicU32::new(0),
        }
    }
}

/// Copied device-list facts for a single observed NAN peer.
#[derive(Clone, Copy)]
pub struct NanDeviceObservationSnapshot {
    pub peer: [u8; 6],
    pub bssid: [u8; 6],
    pub first_seen_ms: u32,
    pub last_seen_ms: u32,
    pub packets: u32,
    pub active_publish_rx: u32,
    pub active_subscribe_rx: u32,
    pub followup_rx: u32,
    pub last_kind: u8,
    /// Receiver radio channel at capture time, or zero when the owner had no
    /// selected channel fact. This is not a channel advertised by the peer.
    pub last_channel: u8,
    pub last_payload_len: u16,
    pub last_payload_hash: u32,
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
static NAN_DEVICE_OBSERVATIONS: [NanDeviceObservationSlot; NAN_DEVICE_OBSERVATION_CAPACITY] =
    [const { NanDeviceObservationSlot::new() }; NAN_DEVICE_OBSERVATION_CAPACITY];
static PENDING_FOLLOWUP_NEXT: AtomicUsize = AtomicUsize::new(0);
static PENDING_FOLLOWUP_QUEUED: AtomicU32 = AtomicU32::new(0);
static PENDING_FOLLOWUP_SENT: AtomicU32 = AtomicU32::new(0);
static PENDING_FOLLOWUP_DROPPED: AtomicU32 = AtomicU32::new(0);
static ACTIVE_PUBLISH_ENABLED: AtomicBool = AtomicBool::new(false);
static ACTIVE_PUBLISH_PENDING: AtomicBool = AtomicBool::new(false);
static ACTIVE_PUBLISH_LEN: AtomicU16 = AtomicU16::new(0);
static ACTIVE_PUBLISH_LAST_SENT_MS: AtomicU32 = AtomicU32::new(0);
static ACTIVE_PUBLISH_REMAINING: AtomicU8 = AtomicU8::new(0);
static ACTIVE_PUBLISH_ATTEMPTED: AtomicU32 = AtomicU32::new(0);
static ACTIVE_PUBLISH_SENT: AtomicU32 = AtomicU32::new(0);
static ACTIVE_PUBLISH_DROPPED: AtomicU32 = AtomicU32::new(0);
/// A temporary Main-owned policy gate for an exclusive durable operation.
/// It suppresses outbound NAN public actions, which all share ESP-IDF's
/// scarce off-channel action-TX request pool. NAN capture, NOW ingress, and
/// raw STA UDP6 remain live; a caller may retry any directed NAN request once
/// the exclusive operation completes.
static NAN_ACTION_TX_SUPPRESSED: AtomicBool = AtomicBool::new(false);
/// An exclusive transfer temporarily owns the shared callback packet pool.
/// NAN management capture is useful background work, but it can otherwise
/// fill that pool while a host sends the first UDP object flight.  This gate
/// affects only the promiscuous NAN/DW receiver: the associated STA Ethernet
/// callback used by raw UDP6 remains registered and live.
static NAN_CAPTURE_SUSPENDED: AtomicBool = AtomicBool::new(false);
static ACTIVE_PUBLISH_INFO: [AtomicU8; ACTIVE_PUBLISH_MAX_LEN] =
    [const { AtomicU8::new(0) }; ACTIVE_PUBLISH_MAX_LEN];
struct PendingSdf {
    state: AtomicU8,
    len: AtomicU16,
    frame: [AtomicU8; PENDING_SDF_MAX_LEN],
    count_active_discovery: AtomicBool,
    remaining: AtomicU8,
    next_send_ms: AtomicU32,
}

impl PendingSdf {
    const fn new() -> Self {
        Self {
            state: AtomicU8::new(PENDING_EMPTY),
            len: AtomicU16::new(0),
            frame: [const { AtomicU8::new(0) }; PENDING_SDF_MAX_LEN],
            count_active_discovery: AtomicBool::new(false),
            remaining: AtomicU8::new(0),
            next_send_ms: AtomicU32::new(0),
        }
    }
}

static PENDING_SDFS: [PendingSdf; PENDING_SDF_CAPACITY] =
    [const { PendingSdf::new() }; PENDING_SDF_CAPACITY];
static PENDING_SDF_NEXT: AtomicUsize = AtomicUsize::new(0);
static PENDING_SDF_QUEUED: AtomicU32 = AtomicU32::new(0);
static PENDING_SDF_REJECTED: AtomicU32 = AtomicU32::new(0);
static PENDING_SDF_TX_ATTEMPTED: AtomicU32 = AtomicU32::new(0);
static PENDING_SDF_TX_ACCEPTED: AtomicU32 = AtomicU32::new(0);
static PENDING_SDF_COMPLETED: AtomicU32 = AtomicU32::new(0);
static ACTIVE_DISCOVERY_QUEUED: AtomicU32 = AtomicU32::new(0);
static ACTIVE_DISCOVERY_SENT: AtomicU32 = AtomicU32::new(0);
static ACTIVE_DISCOVERY_DROPPED: AtomicU32 = AtomicU32::new(0);

struct PendingFollowup {
    state: AtomicU8,
    peer: [AtomicU8; 6],
    /// The receiver's Subscribe transaction identifiers.  A NAN Follow-up
    /// must target that instance, not this device's Publish instance.
    instance: AtomicU8,
    requestor_instance: AtomicU8,
    payload_len: AtomicU16,
    payload: [AtomicU8; dmesh_rawnan::NAN_COMMAND_MAX_LEN],
    queued_ms: AtomicU32,
}

impl PendingFollowup {
    const fn new() -> Self {
        Self {
            state: AtomicU8::new(PENDING_EMPTY),
            peer: [const { AtomicU8::new(0) }; 6],
            instance: AtomicU8::new(0),
            requestor_instance: AtomicU8::new(0),
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
    AtomicU8::new(0),
    AtomicU8::new(0),
    AtomicU8::new(0),
    AtomicU8::new(0),
    AtomicU8::new(0),
    AtomicU8::new(0),
];
static ACTIVE_SUBSCRIBE_INSTANCE: AtomicU8 = AtomicU8::new(0);
static ACTIVE_SUBSCRIBE_REQUESTOR_INSTANCE: AtomicU8 = AtomicU8::new(0);
/// Application-owned CBOR dispatcher. Wi-Fi owns the callback and packet copy;
/// Recovery/Main only receives a copied Service Info payload on the common
/// ingress worker.
pub type NanServiceInfoHandler = fn([u8; 6], &[u8]);
static SERVICE_INFO_HANDLER: AtomicUsize = AtomicUsize::new(0);
// These counters distinguish "the radio saw an SDF" from "the SDF contained
// our Service Info and was safely handed to the common worker".  They are
// intentionally scalar diagnostics: neither the Wi-Fi callback nor the
// snapshot retains a driver-owned frame or CBOR payload.
static SERVICE_INFO_MATCHED: AtomicU32 = AtomicU32::new(0);
/// DMesh SDA records that advertise an active-Subscribe control value. This
/// proves the radio saw a request independently of whether its SDEA layout
/// exposes a bounded Service Info record to the common parser.
static ACTIVE_SUBSCRIBE_DESCRIPTORS: AtomicU32 = AtomicU32::new(0);
/// Active DMesh Subscribe SDAs for which the following SDEA could not be
/// associated and decoded. No driver frame or payload is retained.
static ACTIVE_SUBSCRIBE_SDEA_MISSES: AtomicU32 = AtomicU32::new(0);
// Structural diagnostics for the most recent active-Subscribe SDEA. These
// retain no Service Info: header packs body[0..3], and declared length is the
// fixed u16 at body[5..7] when present.
static ACTIVE_SUBSCRIBE_SDEA_HEADER: AtomicU32 = AtomicU32::new(0);
static ACTIVE_SUBSCRIBE_SDEA_INFO_LEN: AtomicU32 = AtomicU32::new(0);
/// Address-3 from the latest DMesh active-Subscribe SDF. It permits a
/// bounded request/response cluster comparison without retaining a frame.
static ACTIVE_SUBSCRIBE_BSSID: [AtomicU8; 6] = [const { AtomicU8::new(0) }; 6];
static LAST_SDF_SOURCE: [AtomicU8; 6] = [const { AtomicU8::new(0) }; 6];
static LAST_SDF_SERVICE_ID: [AtomicU8; 6] = [const { AtomicU8::new(0) }; 6];
static LAST_SDF_FRAME_BYTES: AtomicU32 = AtomicU32::new(0);
static SMALL_SDF_MAX_BYTES: AtomicU32 = AtomicU32::new(0);
static SMALL_SDF_MAX_SOURCE: [AtomicU8; 6] = [const { AtomicU8::new(0) }; 6];
/// One semantic discovery request may be received in several management
/// frames while Android keeps an active Subscribe open.  We still parse and
/// account for every frame; this cache only suppresses construction of the
/// same signed Follow-up response repeatedly within one sleepy cadence.
static LAST_DISCOVERY_REPLY_PEER: [AtomicU8; 6] = [const { AtomicU8::new(0) }; 6];
// ESP32-C6 lacks native atomics wider than one word. Request IDs are only a
// four-second reply-dedup discriminator, so their low word is sufficient;
// peer MAC and the short expiry are also part of the key.
static LAST_DISCOVERY_REPLY_ID: AtomicU32 = AtomicU32::new(0);
static LAST_DISCOVERY_REPLY_MS: AtomicU32 = AtomicU32::new(0);
static DISCOVERY_REPLY_DUPLICATES_SUPPRESSED: AtomicU32 = AtomicU32::new(0);
/// Local elapsed time from the most recent selected NAN beacon to the last
/// SDF. It records timing only, never service information or frame bytes.
static LAST_SDF_AFTER_BEACON_US: AtomicU32 = AtomicU32::new(0);
// Low 32-bit local timestamps are sufficient for one bounded wake window.
// Main resets the deltas on every physical wake; the callback only performs
// wrapping subtraction and atomic first-observation recording.
static SLEEP_WAKE_US: AtomicU32 = AtomicU32::new(0);
static FIRST_FRAME_AFTER_WAKE_US: AtomicU32 = AtomicU32::new(0);
static FIRST_BEACON_AFTER_WAKE_US: AtomicU32 = AtomicU32::new(0);
static CAPTURE_STARTED_US: AtomicU32 = AtomicU32::new(0);
static CAPTURE_START_FRAMES: AtomicU32 = AtomicU32::new(0);
static CAPTURE_START_BEACONS: AtomicU32 = AtomicU32::new(0);
static ACTIVE_SUBSCRIBES: AtomicU32 = AtomicU32::new(0);
static SERVICE_INFO_ENQUEUED: AtomicU32 = AtomicU32::new(0);
static SERVICE_INFO_DROPPED: AtomicU32 = AtomicU32::new(0);
// The shared worker has actually invoked the Main/Recovery handler.  This is
// deliberately separate from `SERVICE_INFO_ENQUEUED`: a copied frame proves
// callback admission, whereas this proves that normal runtime control saw it.
static SERVICE_INFO_DISPATCHED: AtomicU32 = AtomicU32::new(0);
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

/// Change the NAN cluster used for DW synchronization and transmitted A3.
/// This is receive-side state only: it must never alter the STA/AP BSSID.
fn select_cluster_bssid(bssid: &[u8]) {
    if bssid.len() != 6 {
        return;
    }
    for (index, byte) in bssid.iter().enumerate() {
        FILTER_BSSID[index].store(*byte, Ordering::Relaxed);
    }
}

/// Drop a stale selected cluster and its timing anchor.  This only changes
/// receive-side NAN state; it never changes the associated STA/AP BSSID.
fn clear_cluster_selection() {
    select_cluster_bssid(&[0; 6]);
    store_sync_anchor_us(0);
    SYNC_ANCHOR_PENDING.store(false, Ordering::Release);
    FILTER_PENDING.store(true, Ordering::Release);
}

fn bssid_is_unset(bssid: [u8; 6]) -> bool {
    bssid == [0; 6]
}

fn observation_peer_matches(slot: &NanDeviceObservationSlot, peer: [u8; 6]) -> bool {
    slot.state.load(Ordering::Acquire) == OBSERVATION_READY
        && slot
            .peer
            .iter()
            .enumerate()
            .all(|(index, byte)| byte.load(Ordering::Relaxed) == peer[index])
}

fn record_nan_device_observation(peer: [u8; 6], bssid: [u8; 6], kind: u8, payload: &[u8]) {
    let now = now_ms();
    let slot = NAN_DEVICE_OBSERVATIONS
        .iter()
        .find(|slot| observation_peer_matches(slot, peer))
        .or_else(|| {
            NAN_DEVICE_OBSERVATIONS.iter().find(|slot| {
                slot.state
                    .compare_exchange(
                        OBSERVATION_EMPTY,
                        OBSERVATION_WRITING,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    )
                    .is_ok()
            })
        })
        .or_else(|| {
            NAN_DEVICE_OBSERVATIONS
                .iter()
                .filter(|slot| slot.state.load(Ordering::Acquire) == OBSERVATION_READY)
                .min_by_key(|slot| slot.last_seen_ms.load(Ordering::Relaxed))
                .filter(|slot| {
                    slot.state
                        .compare_exchange(
                            OBSERVATION_READY,
                            OBSERVATION_WRITING,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_ok()
                })
        });
    let Some(slot) = slot else {
        return;
    };
    let replacing = slot.state.load(Ordering::Acquire) == OBSERVATION_WRITING;
    if replacing {
        for (index, byte) in peer.iter().enumerate() {
            slot.peer[index].store(*byte, Ordering::Relaxed);
        }
        slot.first_seen_ms.store(now, Ordering::Relaxed);
        slot.packets.store(0, Ordering::Relaxed);
        slot.active_publish_rx.store(0, Ordering::Relaxed);
        slot.active_subscribe_rx.store(0, Ordering::Relaxed);
        slot.followup_rx.store(0, Ordering::Relaxed);
    }
    for (index, byte) in bssid.iter().enumerate() {
        slot.bssid[index].store(*byte, Ordering::Relaxed);
    }
    slot.last_seen_ms.store(now, Ordering::Relaxed);
    slot.packets.fetch_add(1, Ordering::Relaxed);
    match kind {
        NAN_OBSERVATION_ACTIVE_PUBLISH => {
            slot.active_publish_rx.fetch_add(1, Ordering::Relaxed);
        }
        NAN_OBSERVATION_ACTIVE_SUBSCRIBE => {
            slot.active_subscribe_rx.fetch_add(1, Ordering::Relaxed);
        }
        NAN_OBSERVATION_FOLLOWUP => {
            slot.followup_rx.fetch_add(1, Ordering::Relaxed);
        }
        _ => {}
    }
    slot.last_kind.store(kind, Ordering::Relaxed);
    // This callback cannot query ESP-IDF. The Wi-Fi owner records its last
    // successfully applied channel atomically, which is the channel on which
    // this management frame was captured.
    slot.last_channel.store(
        crate::wifi_esp::selected_channel().unwrap_or(0),
        Ordering::Relaxed,
    );
    slot.last_payload_len.store(
        payload.len().min(u16::MAX as usize) as u16,
        Ordering::Relaxed,
    );
    slot.last_payload_hash.store(
        dmesh_server::discovery::payload_hash(payload),
        Ordering::Relaxed,
    );
    slot.state.store(OBSERVATION_READY, Ordering::Release);
}

/// Copy the bounded NAN device observations for the shared device-list
/// projection. ESP has no public RSSI fact on this receive path. The channel
/// is the Wi-Fi owner's receiver channel captured with the frame, not a peer
///-advertised channel.
pub fn nan_device_observations(
    out: &mut [Option<NanDeviceObservationSnapshot>; NAN_DEVICE_OBSERVATION_CAPACITY],
) {
    for (index, slot) in NAN_DEVICE_OBSERVATIONS.iter().enumerate() {
        if slot.state.load(Ordering::Acquire) != OBSERVATION_READY {
            out[index] = None;
            continue;
        }
        let mut peer = [0; 6];
        let mut bssid = [0; 6];
        for (index, byte) in peer.iter_mut().enumerate() {
            *byte = slot.peer[index].load(Ordering::Relaxed);
        }
        for (index, byte) in bssid.iter_mut().enumerate() {
            *byte = slot.bssid[index].load(Ordering::Relaxed);
        }
        out[index] = Some(NanDeviceObservationSnapshot {
            peer,
            bssid,
            first_seen_ms: slot.first_seen_ms.load(Ordering::Relaxed),
            last_seen_ms: slot.last_seen_ms.load(Ordering::Relaxed),
            packets: slot.packets.load(Ordering::Relaxed),
            active_publish_rx: slot.active_publish_rx.load(Ordering::Relaxed),
            active_subscribe_rx: slot.active_subscribe_rx.load(Ordering::Relaxed),
            followup_rx: slot.followup_rx.load(Ordering::Relaxed),
            last_kind: slot.last_kind.load(Ordering::Relaxed),
            last_channel: slot.last_channel.load(Ordering::Relaxed),
            last_payload_len: slot.last_payload_len.load(Ordering::Relaxed),
            last_payload_hash: slot.last_payload_hash.load(Ordering::Relaxed),
        });
    }
}

/// Compact passive-discovery facts for an unsolicited or directed UDP
/// discovery announce. `services` is monotonic receipt evidence; `nodes` is
/// the current bounded peer inventory. Both are local observations, not a
/// claim about mesh-wide reachability.
pub fn discovery_facts() -> ([u8; 6], u16, u16) {
    let mut snapshots = [None; NAN_DEVICE_OBSERVATION_CAPACITY];
    nan_device_observations(&mut snapshots);
    let nodes = snapshots.iter().flatten().count().min(u16::MAX as usize) as u16;
    (
        selected_bssid(),
        SERVICE_INFO_MATCHED
            .load(Ordering::Relaxed)
            .min(u32::from(u16::MAX)) as u16,
        nodes,
    )
}

fn record_followup(followup: dmesh_rawnan::DmeshNanFollowup<'_>) {
    let index = FOLLOWUP_HISTORY_NEXT.fetch_add(1, Ordering::Relaxed) % FOLLOWUP_HISTORY_CAPACITY;
    let slot = &FOLLOWUP_HISTORY[index];
    let payload = &followup.payload[..followup
        .payload
        .len()
        .min(dmesh_rawnan::NAN_COMMAND_MAX_LEN)];
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
    slot.payload_len
        .store(payload.len() as u16, Ordering::Relaxed);
    // Publish last so readers see either the previous complete entry or this
    // complete copied entry. The bounded cache is advisory diagnostics only.
    slot.last_seen_ms.store(now_ms(), Ordering::Release);
}

/// Return the fixed-size newest/oldest independent receipt cache. Unused
/// entries are `None`; callers can choose their presentation order.
pub fn followup_history(out: &mut [Option<FollowupSnapshot>; FOLLOWUP_HISTORY_CAPACITY]) {
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

fn mark_active_subscribe(peer: [u8; 6], instance: u8, requestor_instance: u8) {
    for (index, value) in peer.iter().enumerate() {
        ACTIVE_SUBSCRIBE_PEER[index].store(*value, Ordering::Relaxed);
    }
    ACTIVE_SUBSCRIBE_INSTANCE.store(instance, Ordering::Relaxed);
    ACTIVE_SUBSCRIBE_REQUESTOR_INSTANCE.store(requestor_instance, Ordering::Relaxed);
    ACTIVE_SUBSCRIBE_PENDING.store(true, Ordering::Release);
}

/// Consume the active-subscribe marker associated with a copied Service Info
/// record. The common ingress worker is single-consumer, so this ties a
/// response to the current request without passing Wi-Fi driver buffers or
/// callback state outside this owner.
pub fn take_active_subscribe(peer: [u8; 6]) -> Option<(u8, u8)> {
    if !ACTIVE_SUBSCRIBE_PENDING.load(Ordering::Acquire) {
        return None;
    }
    let matches = ACTIVE_SUBSCRIBE_PEER
        .iter()
        .enumerate()
        .all(|(index, value)| value.load(Ordering::Relaxed) == peer[index]);
    if matches {
        let instance = ACTIVE_SUBSCRIBE_INSTANCE.load(Ordering::Relaxed);
        let requestor_instance = ACTIVE_SUBSCRIBE_REQUESTOR_INSTANCE.load(Ordering::Relaxed);
        ACTIVE_SUBSCRIBE_PENDING.store(false, Ordering::Release);
        Some((instance, requestor_instance))
    } else {
        None
    }
}

fn queue_followup_response(
    peer: [u8; 6],
    instance: u8,
    requestor_instance: u8,
    response: &[u8],
) -> bool {
    if response.len() > dmesh_rawnan::NAN_COMMAND_MAX_LEN {
        return false;
    }
    let now = now_ms();
    let mut oldest_ready: Option<(&PendingFollowup, u32)> = None;
    for _ in 0..PENDING_FOLLOWUP_CAPACITY {
        let index =
            PENDING_FOLLOWUP_NEXT.fetch_add(1, Ordering::Relaxed) % PENDING_FOLLOWUP_CAPACITY;
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
                    && slot.instance.load(Ordering::Relaxed) == instance
                    && slot.requestor_instance.load(Ordering::Relaxed) == requestor_instance
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
        slot.instance.store(instance, Ordering::Relaxed);
        slot.requestor_instance
            .store(requestor_instance, Ordering::Relaxed);
        for (index, byte) in response.iter().enumerate() {
            slot.payload[index].store(*byte, Ordering::Relaxed);
        }
        slot.payload_len
            .store(response.len() as u16, Ordering::Relaxed);
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
            slot.instance.store(instance, Ordering::Relaxed);
            slot.requestor_instance
                .store(requestor_instance, Ordering::Relaxed);
            for (index, byte) in response.iter().enumerate() {
                slot.payload[index].store(*byte, Ordering::Relaxed);
            }
            slot.payload_len
                .store(response.len() as u16, Ordering::Relaxed);
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

fn transmit_followup_response(
    peer: [u8; 6],
    subscriber_instance: u8,
    _subscribe_requestor_instance: u8,
    response: &[u8],
) -> bool {
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
        sequence, local, peer, response,
    ) else {
        return false;
    };
    // A follow-up is emitted by our Publish instance (1).  The matching
    // Android Subscribe supplied its own instance in the received SDA; that
    // value becomes the requestor instance ID in the response.  Reversing
    // these fields makes the framework silently discard an otherwise valid
    // unicast NAN action.
    let frame = dmesh_rawnan::build_nan_followup_sdf_for_requestor(
        peer,
        local,
        bssid,
        dmesh_rawnan::DMESH_SERVICE_ID,
        1,
        subscriber_instance,
        &payload,
    );
    transmit_public_action_from_dw(interface, peer, bssid, &frame[24..])
}

/// Submit one NAN public action inside a DW without leaving ESP-IDF in
/// promiscuous receive mode for the transmit call.  This is called only by
/// the one-shot NAN deadline while `CAPTURING` is true: ESP-IDF rejects an
/// off-channel public-action request while promiscuous capture owns the radio.
/// We therefore yield only the source's capture for the short driver submit,
/// immediately restore it, and leave the peer's independently scheduled DW
/// receiver untouched.  It is not a polling path and it creates no task.
fn transmit_public_action_from_dw(
    interface: crate::wifi_esp::RadioInterface,
    destination: [u8; 6],
    bssid: [u8; 6],
    body: &[u8],
) -> bool {
    if NAN_ACTION_TX_SUPPRESSED.load(Ordering::Acquire) {
        return false;
    }
    yield_capture_for_action_tx(|| {
        crate::wifi_espnow_esp::transmit_public_action_on_interface(
            interface,
            destination,
            bssid,
            body,
        )
    })
}

/// Yield the capture owner for one ESP-IDF action submission, then restore it.
///
/// Called only from the shared radio worker/deadline owner. ESP-IDF cannot
/// reliably submit an off-channel action while promiscuous capture owns the
/// radio; this provides the same short, explicit handoff for NAN and NOW.
/// It is not a receive loop and never retains a packet.
pub(crate) fn yield_capture_for_action_tx(send: impl FnOnce() -> bool) -> bool {
    yield_capture_for_action_tx_result(|| {
        if send() {
            esp_idf_sys::ESP_OK
        } else {
            esp_idf_sys::ESP_FAIL
        }
    }) == esp_idf_sys::ESP_OK
}

/// Integer-result counterpart for raw action TX, which preserves the ESP-IDF
/// error code in radio diagnostics.
pub(crate) fn yield_capture_for_action_tx_result(send: impl FnOnce() -> i32) -> i32 {
    let was_capturing = CAPTURING.load(Ordering::Acquire);
    if was_capturing && !crate::wifi_esp::set_promiscuous(false) {
        return esp_idf_sys::ESP_FAIL;
    }
    let sent = send();
    if was_capturing && !crate::wifi_esp::set_promiscuous(true) {
        // Do not report a capture that the driver could not restore. The next
        // deadline will attempt a normal capture transition from this state.
        CAPTURING.store(false, Ordering::Release);
    }
    sent
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
        let instance = slot.instance.load(Ordering::Relaxed);
        let requestor_instance = slot.requestor_instance.load(Ordering::Relaxed);
        let payload_len = usize::from(slot.payload_len.load(Ordering::Acquire))
            .min(dmesh_rawnan::NAN_COMMAND_MAX_LEN);
        for (index, byte) in payload[..payload_len].iter_mut().enumerate() {
            *byte = slot.payload[index].load(Ordering::Relaxed);
        }
        slot.state.store(PENDING_EMPTY, Ordering::Release);
        if transmit_followup_response(peer, instance, requestor_instance, &payload[..payload_len]) {
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
    if !CAPTURING.load(Ordering::Acquire)
        || !ACTIVE_PUBLISH_ENABLED.load(Ordering::Acquire)
        || NAN_ACTION_TX_SUPPRESSED.load(Ordering::Acquire)
    {
        return;
    }
    let now = now_ms();
    let pending = ACTIVE_PUBLISH_PENDING.load(Ordering::Acquire);
    let burst_remaining = ACTIVE_PUBLISH_REMAINING.load(Ordering::Acquire);
    let last_sent = ACTIVE_PUBLISH_LAST_SENT_MS.load(Ordering::Acquire);
    if burst_remaining != 0 && last_sent != 0 && now.wrapping_sub(last_sent) < dw_period_ms() {
        return;
    }
    if !pending && burst_remaining == 0 && now.wrapping_sub(last_sent) < ACTIVE_PUBLISH_REFRESH_MS {
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
    ACTIVE_PUBLISH_ATTEMPTED.fetch_add(1, Ordering::Relaxed);
    if transmit_public_action_from_dw(
        interface,
        dmesh_rawnan::NAN_DISCOVERY_MAC,
        bssid,
        &frame[24..],
    ) {
        ACTIVE_PUBLISH_SENT.fetch_add(1, Ordering::Relaxed);
        ACTIVE_PUBLISH_LAST_SENT_MS.store(now, Ordering::Release);
        let remaining = ACTIVE_PUBLISH_REMAINING
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                value.checked_sub(1)
            })
            .map(|value| value - 1)
            .unwrap_or(0);
        ACTIVE_PUBLISH_PENDING.store(remaining != 0, Ordering::Release);
    } else {
        ACTIVE_PUBLISH_DROPPED.fetch_add(1, Ordering::Relaxed);
    }
}

/// Submit every due raw SDF while the source's selected NAN DW is open. The
/// existing one-shot NAN deadline calls this on capture entry; it adds neither
/// a busy service tick nor callback-side Wi-Fi transmission.
fn drain_pending_sdfs() {
    if !CAPTURING.load(Ordering::Acquire) {
        return;
    }
    let now = now_ms();
    for slot in &PENDING_SDFS {
        if slot.state.load(Ordering::Acquire) != PENDING_READY
            || !due(now, slot.next_send_ms.load(Ordering::Acquire))
            || slot
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
        let len = usize::from(slot.len.load(Ordering::Relaxed)).min(PENDING_SDF_MAX_LEN);
        let mut frame = [0u8; PENDING_SDF_MAX_LEN];
        for (index, byte) in frame[..len].iter_mut().enumerate() {
            *byte = slot.frame[index].load(Ordering::Relaxed);
        }
        let destination = frame.get(4..10).and_then(|bytes| bytes.try_into().ok());
        let bssid = frame
            .get(dmesh_rawnan::FRAME_BSSID..dmesh_rawnan::FRAME_BSSID + 6)
            .and_then(|bytes| bytes.try_into().ok());
        let valid = len >= dmesh_rawnan::FRAME_DATA && destination.is_some() && bssid.is_some();
        if valid {
            PENDING_SDF_TX_ATTEMPTED.fetch_add(1, Ordering::Relaxed);
        }
        let sent = if valid {
            let interface =
                if crate::wifi_esp::sta_associated() || !crate::wifi_esp::lab_open_ap_active() {
                    crate::wifi_esp::RadioInterface::Sta
                } else {
                    crate::wifi_esp::RadioInterface::Ap
                };
            transmit_public_action_from_dw(
                interface,
                destination.unwrap(),
                bssid.unwrap(),
                &frame[dmesh_rawnan::FRAME_DATA..len],
            )
        } else {
            false
        };
        if sent {
            PENDING_SDF_TX_ACCEPTED.fetch_add(1, Ordering::Relaxed);
        }
        let remaining = slot.remaining.load(Ordering::Relaxed);
        if remaining <= 1 || slot.next_send_ms.load(Ordering::Relaxed) == 0 {
            crate::commands::send_stats(&[
                (b"nan SDF tx frame_bytes", len as u64),
                (b"nan SDF tx remaining", u64::from(remaining)),
                (b"nan SDF tx accepted", u64::from(sent)),
            ]);
        }
        if slot.count_active_discovery.load(Ordering::Relaxed) {
            if sent {
                ACTIVE_DISCOVERY_SENT.fetch_add(1, Ordering::Relaxed);
            } else {
                ACTIVE_DISCOVERY_DROPPED.fetch_add(1, Ordering::Relaxed);
            }
        }
        if !valid || remaining <= 1 {
            slot.remaining.store(0, Ordering::Relaxed);
            slot.state.store(PENDING_EMPTY, Ordering::Release);
            PENDING_SDF_COMPLETED.fetch_add(1, Ordering::Relaxed);
        } else {
            slot.remaining.store(remaining - 1, Ordering::Relaxed);
            slot.next_send_ms
                .store(now.wrapping_add(NAN_DW_PERIOD_MS), Ordering::Relaxed);
            slot.state.store(PENDING_READY, Ordering::Release);
        }
    }
}

/// Send one bounded DMesh NAN Follow-up response during the currently open
/// discovery capture window. The copied control worker may complete after
/// that window, in which case this queues the response for the next DW.
/// This module owns scheduling/context; `wifi_espnow_esp` remains the sole
/// ESP-IDF public-action submitter.
pub fn send_followup_response(
    peer: [u8; 6],
    instance: u8,
    requestor_instance: u8,
    response: &[u8],
) -> bool {
    // Do this before queueing or constructing a NAN Follow-up. The exclusive
    // flash path deliberately has no use for an outbound NAN response, and a
    // failed Vec allocation here used to abort the whole firmware.
    if nan_action_tx_suppressed() {
        PENDING_FOLLOWUP_DROPPED.fetch_add(1, Ordering::Relaxed);
        return false;
    }
    if CAPTURING.load(Ordering::Acquire) {
        let sent = transmit_followup_response(peer, instance, requestor_instance, response);
        if sent {
            PENDING_FOLLOWUP_SENT.fetch_add(1, Ordering::Relaxed);
        } else {
            PENDING_FOLLOWUP_DROPPED.fetch_add(1, Ordering::Relaxed);
        }
        sent
    } else {
        queue_followup_response(peer, instance, requestor_instance, response)
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
    transmit_public_action_from_dw(interface, destination, bssid, &frame[24..])
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

/// Arm per-window receive readiness measurements immediately after the CPU
/// returns from explicit light sleep and before Wi-Fi reconstruction begins.
pub fn mark_sleep_wake(woke_us: u64) {
    SLEEP_WAKE_US.store(woke_us as u32, Ordering::Release);
    FIRST_FRAME_AFTER_WAKE_US.store(0, Ordering::Release);
    FIRST_BEACON_AFTER_WAKE_US.store(0, Ordering::Release);
}

/// `(first management frame after wake, first NAN beacon after wake)` in us.
pub fn sleep_wake_receive_diagnostics() -> (u32, u32) {
    (
        FIRST_FRAME_AFTER_WAKE_US.load(Ordering::Acquire),
        FIRST_BEACON_AFTER_WAKE_US.load(Ordering::Acquire),
    )
}

/// Scheduler state sampled by Main immediately after a sleepy radio resume.
/// This is diagnostic only and does not advance or re-arm the capture owner.
pub fn sleep_wake_scheduler_diagnostics() -> (bool, bool, bool, bool, u32, u32) {
    (
        STARTED.load(Ordering::Acquire),
        NAN_CAPTURE_SUSPENDED.load(Ordering::Acquire),
        CAPTURING.load(Ordering::Acquire),
        NOW_ACTIVE_RECEIVE.load(Ordering::Acquire),
        NEXT_MS.load(Ordering::Acquire),
        next_service_delay_ms().unwrap_or(u32::MAX),
    )
}

fn due(now: u32, deadline: u32) -> bool {
    now.wrapping_sub(deadline) < (1 << 31)
}

/// `(all_management_frames, bytes, NAN_beacons, NAN_SDFs, NAN_followups,
/// DMesh_Service_Info_matches, active_Subscribe_SDAs, active_SDEA_misses,
/// last_SDEA_header, last_SDEA_declared_info_len, decoded_active_Subscribes,
/// copied_to_ingress, ingress_copy_failures, worker_handler_invocations)`.
pub fn stats() -> (
    u32,
    u32,
    u32,
    u32,
    u32,
    u32,
    u32,
    u32,
    u32,
    u32,
    [u8; 6],
    [u8; 6],
    [u8; 6],
    u32,
    u32,
    u32,
    u32,
    u32,
) {
    let mut active_subscribe_bssid = [0u8; 6];
    for (index, byte) in active_subscribe_bssid.iter_mut().enumerate() {
        *byte = ACTIVE_SUBSCRIBE_BSSID[index].load(Ordering::Relaxed);
    }
    let mut last_sdf_source = [0u8; 6];
    let mut last_sdf_service_id = [0u8; 6];
    for index in 0..6 {
        last_sdf_source[index] = LAST_SDF_SOURCE[index].load(Ordering::Relaxed);
        last_sdf_service_id[index] = LAST_SDF_SERVICE_ID[index].load(Ordering::Relaxed);
    }
    (
        FRAMES.load(Ordering::Relaxed),
        BYTES.load(Ordering::Relaxed),
        BEACONS.load(Ordering::Relaxed),
        SDFS.load(Ordering::Relaxed),
        FOLLOWUPS.load(Ordering::Relaxed),
        SERVICE_INFO_MATCHED.load(Ordering::Relaxed),
        ACTIVE_SUBSCRIBE_DESCRIPTORS.load(Ordering::Relaxed),
        ACTIVE_SUBSCRIBE_SDEA_MISSES.load(Ordering::Relaxed),
        ACTIVE_SUBSCRIBE_SDEA_HEADER.load(Ordering::Relaxed),
        ACTIVE_SUBSCRIBE_SDEA_INFO_LEN.load(Ordering::Relaxed),
        active_subscribe_bssid,
        last_sdf_source,
        last_sdf_service_id,
        ACTIVE_SUBSCRIBES.load(Ordering::Relaxed),
        SERVICE_INFO_ENQUEUED.load(Ordering::Relaxed),
        SERVICE_INFO_DROPPED.load(Ordering::Relaxed),
        SERVICE_INFO_DISPATCHED.load(Ordering::Relaxed),
        LAST_SDF_AFTER_BEACON_US.load(Ordering::Relaxed),
    )
}

/// Callback-safe raw SDF ingress evidence. This intentionally reports the
/// frame before Service Info parsing so malformed/unsupported NAN encoding is
/// distinguishable from an RF miss.
pub fn last_sdf_ingress() -> (u32, u64, u32, u64) {
    let mut source = [0u8; 8];
    let mut small_source = [0u8; 8];
    for (index, byte) in source[..6].iter_mut().enumerate() {
        *byte = LAST_SDF_SOURCE[index].load(Ordering::Relaxed);
        small_source[index] = SMALL_SDF_MAX_SOURCE[index].load(Ordering::Relaxed);
    }
    (
        LAST_SDF_FRAME_BYTES.load(Ordering::Relaxed),
        u64::from_le_bytes(source),
        SMALL_SDF_MAX_BYTES.load(Ordering::Relaxed),
        u64::from_le_bytes(small_source),
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
    ACTIVE_PUBLISH_REMAINING.store(
        if enabled {
            ACTIVE_PUBLISH_BURST_WINDOWS
        } else {
            0
        },
        Ordering::Release,
    );
    ACTIVE_PUBLISH_ENABLED.store(enabled, Ordering::Release);
    // This can be called by the copied NAN ingress worker after Main has
    // already armed its current wait. Wake that existing owner once so it
    // recomputes the next DW deadline; it remains a one-shot deadline, not a
    // publish timer or an additional worker.
    crate::main_runtime::request_deadline_recheck();
    true
}

/// Gate optional NAN action transmission while retaining configured records
/// and pending work. Clearing the gate resumes ordinary NAN policy on a later
/// discovery window; it does not manipulate Wi-Fi callbacks, promiscuous
/// state, or any transport bearer.
pub(crate) fn set_nan_action_tx_suppressed(suppressed: bool) {
    NAN_ACTION_TX_SUPPRESSED.store(suppressed, Ordering::Release);
}

/// Suspend or resume optional NAN capture for an exclusive operation.
///
/// The gate suppresses NAN's management-frame work at the callback boundary;
/// it must not toggle ESP-IDF promiscuous mode.  On the classic STA driver the
/// raw Ethernet callback is registered separately, but disabling promiscuous
/// mode during a live packet handoff can still suppress its next unicast
/// frame.  Keeping the driver mode unchanged preserves raw UDP6 while the
/// callback immediately returns every optional NAN management frame.
pub(crate) fn set_nan_capture_suspended(suspended: bool) {
    if NAN_CAPTURE_SUSPENDED.swap(suspended, Ordering::AcqRel) == suspended {
        return;
    }
    if suspended {
        CAPTURING.store(false, Ordering::Release);
    } else {
        // Start the next ordinary capture from a fresh deadline; do not turn
        // promiscuous receive back on synchronously in a flash completion
        // path where an ESP-NOW/ROC owner might be releasing the radio.
        NEXT_MS.store(now_ms(), Ordering::Release);
        crate::main_runtime::request_deadline_recheck();
    }
}

/// Whether an exclusive operation has temporarily deferred NAN responses.
/// Receive-side callers use this before constructing a response, so the gate
/// also avoids a transient allocation when the board is under memory pressure.
pub(crate) fn nan_action_tx_suppressed() -> bool {
    NAN_ACTION_TX_SUPPRESSED.load(Ordering::Acquire)
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

/// True only while the NAN DW receiver is active on NAN's fixed channel 6.
/// Associated STA on another channel keeps NOW and UDP6 but must not publish
/// NAN Service Info as if it were reachable there.
pub fn active_on_nan_channel() -> bool {
    STARTED.load(Ordering::Acquire) && crate::wifi_esp::selected_channel() == Some(6)
}

/// Monotonic local active-Publish TX evidence. `sent` means the ESP action
/// submitter accepted it; a peer-side NAN observation is still required to
/// prove RF delivery.
pub fn active_publish_stats() -> (u32, u32, u32) {
    (
        ACTIVE_PUBLISH_ATTEMPTED.load(Ordering::Relaxed),
        ACTIVE_PUBLISH_SENT.load(Ordering::Relaxed),
        ACTIVE_PUBLISH_DROPPED.load(Ordering::Relaxed),
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

/// Queue one active-Subscribe SDF for the next local discovery window.
///
/// This is called by the raw-radio control adapter from normal worker
/// context. The frame must name the cluster already selected by this radio.
/// Each accepted request retains its own bounded intent; capacity exhaustion
/// is reported to the caller and never replaces already accepted work.
pub fn queue_sdf_frame(frame: &[u8]) -> bool {
    queue_sdf_frame_kind(frame, false, 1)
}

fn queue_sdf_frame_kind(frame: &[u8], active_discovery: bool, attempts: u8) -> bool {
    if !dmesh_rawnan::is_nan_sdf(frame)
        || frame.len() > PENDING_SDF_MAX_LEN
        || frame.len() < dmesh_rawnan::FRAME_BSSID + 6
        || bssid_is_unset(selected_bssid())
        || frame[dmesh_rawnan::FRAME_BSSID..dmesh_rawnan::FRAME_BSSID + 6] != selected_bssid()
    {
        return false;
    }
    let mut selected = None;
    for _ in 0..PENDING_SDF_CAPACITY {
        let index = PENDING_SDF_NEXT.fetch_add(1, Ordering::Relaxed) % PENDING_SDF_CAPACITY;
        let slot = &PENDING_SDFS[index];
        if slot
            .state
            .compare_exchange(
                PENDING_EMPTY,
                PENDING_WRITING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
        {
            selected = Some(slot);
            break;
        }
    }
    let Some(slot) = selected else {
        PENDING_SDF_REJECTED.fetch_add(1, Ordering::Relaxed);
        return false;
    };
    for (index, byte) in frame.iter().enumerate() {
        slot.frame[index].store(*byte, Ordering::Relaxed);
    }
    slot.len.store(frame.len() as u16, Ordering::Relaxed);
    slot.count_active_discovery
        .store(active_discovery, Ordering::Relaxed);
    slot.remaining.store(attempts.max(1), Ordering::Relaxed);
    slot.next_send_ms.store(0, Ordering::Relaxed);
    slot.state.store(PENDING_READY, Ordering::Release);
    PENDING_SDF_QUEUED.fetch_add(1, Ordering::Relaxed);
    // This direct control request runs on Main's normal worker, never a Wi-Fi
    // callback.  If the selected DW is already open, submit it now through
    // the same capture-yield helper used by the deadline.  Otherwise the
    // pending flag is consumed at the next one-shot DW timer; no periodic
    // poll is introduced merely to service a newly queued SDF.
    if CAPTURING.load(Ordering::Acquire) {
        drain_pending_sdfs();
    }
    // A continuously active NAN/NOW owner otherwise has no periodic service
    // deadline.  Re-arm Main after queueing (and after an immediate first
    // send) so the remaining bounded repetitions are driven by their actual
    // SDF deadline instead of depending on unrelated radio activity.
    crate::main_runtime::request_deadline_recheck();
    true
}

/// Queue the common directed-discovery request in an active NAN Subscribe.
///
/// Unlike an active Publish, a Subscribe asks an otherwise sleepy DMesh peer
/// to answer with its current signed announce.  The caller is Main's event
/// owner; this function prepares one independently retained SDF intent for a
/// future DW and never scans, opens a radio task, or transmits off-window.
pub fn queue_active_discovery() -> bool {
    if !active_on_nan_channel() {
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
    let mut request = [0u8; 96];
    let request_id = now_us();
    let Some(used) = dmesh_server::announce::encode_discovery_request(request_id, &mut request)
    else {
        return false;
    };
    let frame = dmesh_rawnan::build_nan_usd_sdf_with_bssid(
        dmesh_rawnan::NAN_DISCOVERY_MAC,
        local,
        bssid,
        dmesh_rawnan::DMESH_SERVICE_ID,
        1,
        0x11,
        &request[..used],
    );
    let queued = queue_sdf_frame_kind(&frame, true, 1);
    if queued {
        ACTIVE_DISCOVERY_QUEUED.fetch_add(1, Ordering::Relaxed);
    }
    queued
}

/// Queue one directed sleepy-peer activation at the next local NAN DW.  The
/// public action is `nan.wakeup`; the SDEA deliberately carries the existing
/// target-checked `transport.set { mode: sta, wake_target }` record so the
/// receiver has no NAN-only profile parser.
pub fn queue_nan_wakeup(target: [u8; 6]) -> bool {
    if !active_on_nan_channel() {
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
    let request = dmesh_server::control::Request::TransportSet {
        kind: dmesh_server::control::TransportKind::Sta,
        config: dmesh_server::control::TransportConfig {
            wake_target: Some(target),
            ..dmesh_server::control::TransportConfig::default()
        },
    };
    let mut record = [0u8; 96];
    let Some(used) = dmesh_server::control::encode_request(request, None, &mut record) else {
        return false;
    };
    let frame = dmesh_rawnan::build_nan_usd_sdf_with_bssid(
        dmesh_rawnan::NAN_DISCOVERY_MAC,
        local,
        bssid,
        dmesh_rawnan::DMESH_SERVICE_ID,
        2,
        0x11,
        &record[..used],
    );
    // Cover more than one complete DW8 cadence while retaining one bounded
    // *semantic intent*. Each received frame remains independently parsed;
    // this fixed management-action burst is never an idle poll.
    queue_sdf_frame_kind(&frame, false, NAN_WAKE_BURST_WINDOWS)
}

/// `(queued, sent, dropped)` active-discovery Subscribe evidence.  `sent`
/// means only that ESP-IDF accepted the SDF action submission; peer-side
/// observation remains necessary to establish RF delivery and a response.
pub fn active_discovery_stats() -> (u32, u32, u32) {
    (
        ACTIVE_DISCOVERY_QUEUED.load(Ordering::Relaxed),
        ACTIVE_DISCOVERY_SENT.load(Ordering::Relaxed),
        ACTIVE_DISCOVERY_DROPPED.load(Ordering::Relaxed),
    )
}

/// Admit at most one directed-discovery Follow-up for the same peer and
/// request ID during one full DW8 interval. This does not suppress frame
/// receive, parsing, observation, or direct-request validation: callers run
/// it only after the complete SDF has reached Main and a return Follow-up is
/// otherwise ready to submit.
pub fn admit_discovery_reply(peer: [u8; 6], request_id: u64) -> bool {
    let now = now_ms();
    let request_id = request_id as u32;
    let same_peer = LAST_DISCOVERY_REPLY_PEER
        .iter()
        .enumerate()
        .all(|(index, value)| value.load(Ordering::Acquire) == peer[index]);
    let last_ms = LAST_DISCOVERY_REPLY_MS.load(Ordering::Acquire);
    let still_fresh = now.wrapping_sub(last_ms) < NAN_DW_PERIOD_MS.saturating_mul(8);
    if same_peer && LAST_DISCOVERY_REPLY_ID.load(Ordering::Acquire) == request_id && still_fresh {
        DISCOVERY_REPLY_DUPLICATES_SUPPRESSED.fetch_add(1, Ordering::Relaxed);
        return false;
    }
    for (index, byte) in peer.iter().enumerate() {
        LAST_DISCOVERY_REPLY_PEER[index].store(*byte, Ordering::Release);
    }
    LAST_DISCOVERY_REPLY_ID.store(request_id, Ordering::Release);
    LAST_DISCOVERY_REPLY_MS.store(now, Ordering::Release);
    true
}

/// Number of parsed direct-discovery frames whose already-cached Follow-up
/// response was intentionally not transmitted again.
pub fn duplicate_discovery_replies_suppressed() -> u32 {
    DISCOVERY_REPLY_DUPLICATES_SUPPRESSED.load(Ordering::Relaxed)
}

/// `(queued, rejected, tx_attempted, tx_accepted, completed, pending)` for
/// independently retained NAN SDF intents. A request is rejected only before
/// admission when every fixed semantic-intent slot is busy; accepted work is
/// never replaced by later discovery or wake requests.
pub fn pending_sdf_stats() -> (u32, u32, u32, u32, u32, u8) {
    let pending = PENDING_SDFS
        .iter()
        .filter(|slot| slot.state.load(Ordering::Acquire) == PENDING_READY)
        .count() as u8;
    (
        PENDING_SDF_QUEUED.load(Ordering::Relaxed),
        PENDING_SDF_REJECTED.load(Ordering::Relaxed),
        PENDING_SDF_TX_ATTEMPTED.load(Ordering::Relaxed),
        PENDING_SDF_TX_ACCEPTED.load(Ordering::Relaxed),
        PENDING_SDF_COMPLETED.load(Ordering::Relaxed),
        pending,
    )
}

fn dispatch_service_info(item: crate::shared_ingress_esp::IngressPacket, payload: &[u8]) {
    // This is intentionally separate from SDF parsing and control admission:
    // it proves the raw callback copied a matching Service Info payload and
    // the deferred worker is about to hand it to Main.  The downstream log
    // then identifies a target mismatch or direct-record rejection.
    let peer = item.source();
    crate::commands::send_stats(&[
        (
            b"nan SD received peer_le",
            u64::from_le_bytes([peer[0], peer[1], peer[2], peer[3], peer[4], peer[5], 0, 0]),
        ),
        (b"nan SD received bytes", payload.len() as u64),
    ]);
    let handler = SERVICE_INFO_HANDLER.load(Ordering::Acquire);
    if handler != 0 {
        SERVICE_INFO_DISPATCHED.fetch_add(1, Ordering::Relaxed);
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
    SERVICE_INFO_MATCHED.store(0, Ordering::Release);
    ACTIVE_SUBSCRIBE_DESCRIPTORS.store(0, Ordering::Release);
    ACTIVE_SUBSCRIBE_SDEA_MISSES.store(0, Ordering::Release);
    ACTIVE_SUBSCRIBE_SDEA_HEADER.store(0, Ordering::Release);
    ACTIVE_SUBSCRIBE_SDEA_INFO_LEN.store(0, Ordering::Release);
    ACTIVE_SUBSCRIBES.store(0, Ordering::Release);
    LAST_SDF_AFTER_BEACON_US.store(0, Ordering::Release);
    SERVICE_INFO_ENQUEUED.store(0, Ordering::Release);
    SERVICE_INFO_DROPPED.store(0, Ordering::Release);
    SERVICE_INFO_DISPATCHED.store(0, Ordering::Release);
    ACTIVE_PUBLISH_ATTEMPTED.store(0, Ordering::Release);
    ACTIVE_PUBLISH_SENT.store(0, Ordering::Release);
    ACTIVE_PUBLISH_DROPPED.store(0, Ordering::Release);
    FILTER_ARMS.store(0, Ordering::Release);
    FILTER_ERRORS.store(0, Ordering::Release);
}

/// Whether management promiscuous receive is currently enabled.  This is
/// normally one bounded NAN discovery window; while an explicit NOW client is
/// active it can instead be the client's bounded receive lease.  Normal UDP6
/// traffic never requires this mode.
pub fn capturing() -> bool {
    CAPTURING.load(Ordering::Acquire)
}

/// Configured discovery-window cadence. Unlike [`capturing`], this is stable
/// between the bounded 64 ms receive windows and is therefore suitable for
/// control-plane/radio-profile verification.
pub fn interval() -> u8 {
    DW_INTERVAL.load(Ordering::Acquire)
}

/// Select the paired NAN/NOW receive span for a sleepy profile. Active and
/// STA profiles keep their existing capture/lease policies.
pub fn set_sleepy_dw_pair(enabled: bool) {
    SLEEPY_DW_PAIR.store(enabled, Ordering::Release);
    if !enabled {
        SLEEPY_DW_PAIR_SECOND.store(false, Ordering::Release);
    }
}

/// First bounded capture point at or after `not_before_us`, derived from the
/// current local receive-time beacon anchor. This is deliberately an anchor
/// calculation rather than a fixed DW8 duration: radio restart time shifts
/// the preceding sleep boundary, while the cluster beacon does not.
pub fn next_capture_start_us(not_before_us: u64) -> Option<u64> {
    let (bssid, anchor_us, _) = sync_diagnostics();
    (!bssid_is_unset(bssid) && anchor_us != 0).then(|| {
        dmesh_rawnan::next_nan_dw_start_us(
            anchor_us,
            not_before_us.saturating_add(NAN_DW_PRE_BEACON_US),
        )
        .saturating_sub(NAN_DW_PRE_BEACON_US)
    })
}

/// The next selected sleepy capture after the just-completed DW pair. A DW8
/// peer intentionally skips seven 512-TU base windows; using
/// `next_capture_start_us` directly here would wake it for the very next
/// base DW (often a few hundred milliseconds later) and destroy the intended
/// duty cycle.
pub fn next_sleepy_capture_start_us(after_us: u64, interval: u8) -> Option<u64> {
    next_capture_start_us(after_us).map(|first| {
        let skipped_windows = u64::from(interval.max(1) - 1);
        first.saturating_add(skipped_windows * 512 * 1_024)
    })
}

/// Length retained after the first scheduled capture starts: NAN DW, NOW DW,
/// and a small post-window tail before Main may enter the next timer sleep.
pub const fn sleepy_dw_pair_hold_us() -> u64 {
    ((NAN_DW_CAPTURE_MS + NOW_DW_CAPTURE_MS + SLEEPY_DW_PAIR_TAIL_MS) as u64) * 1_000
}

/// Open receive immediately after a sleepy radio reconstruction and retain it
/// through the selected NAN+NOW pair. The wake lead is already paid active
/// time; listening during it lets a drifting local anchor observe the real
/// beacon instead of idling until a potentially stale narrow deadline.
pub fn begin_sleepy_resume_capture(until_us: u64) -> bool {
    if !STARTED.load(Ordering::Acquire) || NAN_CAPTURE_SUSPENDED.load(Ordering::Acquire) {
        return false;
    }
    let _ = crate::wifi_esp::set_nan_dw_power_save(false);
    if !CAPTURING.load(Ordering::Acquire) && !crate::wifi_esp::set_promiscuous(true) {
        let _ = crate::wifi_esp::set_nan_dw_power_save(true);
        return false;
    }
    let started_us = now_us();
    CAPTURE_STARTED_US.store(started_us as u32, Ordering::Release);
    CAPTURE_START_FRAMES.store(FRAMES.load(Ordering::Acquire), Ordering::Release);
    CAPTURE_START_BEACONS.store(BEACONS.load(Ordering::Acquire), Ordering::Release);
    CAPTURING.store(true, Ordering::Release);
    // This one lease already spans both adjacent windows; its terminal
    // deadline must close receive rather than adding another NOW interval.
    SLEEPY_DW_PAIR_SECOND.store(true, Ordering::Release);
    UNTIL_MS.store(
        (until_us / 1_000).min(u64::from(u32::MAX)) as u32,
        Ordering::Release,
    );
    crate::commands::send_stats(&[
        (
            b"nan resume capture_us",
            until_us.saturating_sub(started_us),
        ),
        (b"nan resume capture_until_us", until_us),
    ]);
    true
}

/// The current explicit sleepy-resume capture lease, if one is active. Main
/// uses this as the physical-sleep boundary after a selected beacon shortens
/// the conservative predicted phase below. Normal DW capture never exposes a
/// lease here, so it cannot change the ordinary scheduler's cadence.
pub fn sleepy_resume_capture_until_ms() -> Option<u64> {
    (CAPTURING.load(Ordering::Acquire)
        && SLEEPY_DW_PAIR_SECOND.load(Ordering::Acquire))
    .then(|| u64::from(UNTIL_MS.load(Ordering::Acquire)))
}

fn shorten_sleepy_resume_capture_after_beacon(received_us: u64) {
    if !CAPTURING.load(Ordering::Acquire)
        || !SLEEPY_DW_PAIR_SECOND.load(Ordering::Acquire)
    {
        return;
    }
    // The lease already spans the NAN DW, adjacent NOW DW, and its tail. A
    // selected beacon proves that pair has started earlier than the predicted
    // phase, so retaining the old predicted deadline only burns power. Round
    // upward to the millisecond timer so this never shortens the pair early.
    let after_pair_ms = received_us
        .saturating_add(sleepy_dw_pair_hold_us())
        .saturating_add(999)
        / 1_000;
    let current = u64::from(UNTIL_MS.load(Ordering::Acquire));
    if after_pair_ms >= current {
        return;
    }
    UNTIL_MS.store(after_pair_ms as u32, Ordering::Release);
    // The Main owner may be blocked on the former prediction. Recompute its
    // one-shot deadline; this is a coalesced event wake, never a callback
    // transition or polling loop.
    crate::main_runtime::request_deadline_recheck();
}

/// Extend the existing NAN management receive window for one explicit
/// channel-6 observation request. This is deliberately bounded to 600 ms so
/// it can see a 500-TU infrastructure beacon without becoming continuous
/// promiscuous receive. The Wi-Fi owner invokes it from its normal worker,
/// never from the ESP-IDF callback.
pub fn request_permissive_capture(duration_ms: u16) -> bool {
    if !STARTED.load(Ordering::Acquire)
        || lab_dw_policy() != 0
        || !(100..=600).contains(&duration_ms)
        || crate::wifi_nonpromisc_probe_esp::roc_in_flight()
    {
        return false;
    }
    let now = now_ms();
    let requested_until = now.wrapping_add(u32::from(duration_ms));
    if !CAPTURING.load(Ordering::Acquire) {
        if !crate::wifi_esp::set_promiscuous(true) {
            return false;
        }
        CAPTURING.store(true, Ordering::Release);
    }
    let current_until = UNTIL_MS.load(Ordering::Acquire);
    if due(requested_until, current_until) {
        UNTIL_MS.store(requested_until, Ordering::Release);
    }
    // Resume ordinary DW scheduling only after this bounded observation
    // closes; do not alter the configured cadence.
    NEXT_MS.store(
        requested_until.wrapping_add(dw_period_ms()),
        Ordering::Release,
    );
    true
}

/// Start the receive lease for one explicit raw-NOW client association.
///
/// Called synchronously from the normal shared-ingress worker immediately
/// before that worker transmits the client's OPEN.  It is never called from a
/// Wi-Fi callback, allocates no packet storage, and does not create a task.
/// The client has its own one-shot retry/PTO deadlines; this lease merely
/// keeps the existing management callback capable of receiving the peer's
/// stream packets between ordinary NAN DWs.  A caller must pair success with
/// [`end_now_receive_lease`] on every terminal client path.
pub fn begin_now_receive_lease() -> bool {
    if !STARTED.load(Ordering::Acquire)
        || lab_dw_policy() != 0
        || crate::wifi_nonpromisc_probe_esp::roc_in_flight()
    {
        return false;
    }
    if NOW_CLIENT_RECEIVE_LEASE.swap(true, Ordering::AcqRel) {
        return true;
    }
    if CAPTURING.load(Ordering::Acquire) || crate::wifi_esp::set_promiscuous(true) {
        CAPTURING.store(true, Ordering::Release);
        return true;
    }
    NOW_CLIENT_RECEIVE_LEASE.store(false, Ordering::Release);
    false
}

/// Keep the responder receive-capable for one active NOW association.
///
/// Called by the shared packet worker only after the raw dispatcher has
/// accepted a packet for its current NOW path. Each accepted packet extends
/// the one explicit deadline; unrelated action frames cannot hold the radio
/// awake. This complements, rather than replaces, the initiator lease above:
/// either side may temporarily be both a client and a responder.
pub fn begin_now_service_receive_lease() -> bool {
    if !STARTED.load(Ordering::Acquire)
        || lab_dw_policy() != 0
        || crate::wifi_nonpromisc_probe_esp::roc_in_flight()
    {
        return false;
    }
    let now = now_ms();
    NOW_SERVICE_RECEIVE_UNTIL_MS.store(
        now.wrapping_add(NOW_SERVICE_RECEIVE_LEASE_MS),
        Ordering::Release,
    );
    if CAPTURING.load(Ordering::Acquire) || crate::wifi_esp::set_promiscuous(true) {
        CAPTURING.store(true, Ordering::Release);
        true
    } else {
        NOW_SERVICE_RECEIVE_UNTIL_MS.store(0, Ordering::Release);
        false
    }
}

/// Release responder coverage once its raw association is explicitly retired.
///
/// Profile replacement and a clean QUIC CLOSE call this immediately. An
/// unclean peer is covered by the deadline above; no periodic cleanup task is
/// needed. A simultaneous local client continues to own the radio lease.
pub fn end_now_service_receive_lease() {
    NOW_SERVICE_RECEIVE_UNTIL_MS.store(0, Ordering::Release);
    if NOW_CLIENT_RECEIVE_LEASE.load(Ordering::Acquire)
        || NOW_ACTIVE_RECEIVE.load(Ordering::Acquire)
        || !STARTED.load(Ordering::Acquire)
    {
        return;
    }
    if crate::wifi_nonpromisc_probe_esp::roc_in_flight() {
        return;
    }
    let now = now_ms();
    let _ = crate::wifi_esp::set_promiscuous(false);
    CAPTURING.store(false, Ordering::Release);
    ACQUIRING.store(false, Ordering::Release);
    NEXT_MS.store(now.wrapping_add(dw_period_ms()), Ordering::Release);
}

/// Return from an active raw-NOW client to the normal NAN DW receive policy.
///
/// Called only from a raw client's completion, timeout, start-failure, or
/// radio-teardown path.  It performs no packet parsing and does not wait for a
/// timer: after disabling the temporary receive lease, the next ordinary DW
/// begins after one configured period.  This avoids an immediate close/open
/// bounce that would otherwise keep an idle active device in promiscuous mode.
pub fn end_now_receive_lease() {
    if !NOW_CLIENT_RECEIVE_LEASE.swap(false, Ordering::AcqRel) || !STARTED.load(Ordering::Acquire) {
        return;
    }
    if NOW_SERVICE_RECEIVE_UNTIL_MS.load(Ordering::Acquire) != 0
        || NOW_ACTIVE_RECEIVE.load(Ordering::Acquire)
    {
        return;
    }
    if crate::wifi_nonpromisc_probe_esp::roc_in_flight() {
        // ROC owns the driver receive transition.  Its completion event will
        // re-enter the normal deadline service, which observes that the NOW
        // lease is gone and resumes DW scheduling without a conflicting call.
        return;
    }
    let now = now_ms();
    let _ = crate::wifi_esp::set_promiscuous(false);
    CAPTURING.store(false, Ordering::Release);
    ACQUIRING.store(false, Ordering::Release);
    NEXT_MS.store(now.wrapping_add(dw_period_ms()), Ordering::Release);
    // Lease release originates on the shared ingress worker, whereas the
    // normal DW deadline is armed by Main's blocking event owner.  Notify it
    // once for this state transition so it recomputes the next timer; without
    // that notification a completed NOW session could leave NAN idle until
    // some unrelated control event happened to wake Main.
    crate::main_runtime::request_deadline_recheck();
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
    let (bssid, anchor_us, _) = sync_diagnostics();
    // Light sleep retains these atomics, while `stop()` deliberately clears
    // only the ESP-IDF callback/runtime state.  Reacquiring for 15 seconds
    // after every DW8 wake kept the radio awake almost continuously.  Reuse
    // a live cluster anchor to arm the next ordinary bounded DW instead.
    if RESUME_SAVED_SYNC.swap(false, Ordering::AcqRel) && !bssid_is_unset(bssid) && anchor_us != 0 {
        let next_us = dmesh_rawnan::next_nan_dw_start_us(
            anchor_us,
            now_us().saturating_add(NAN_DW_PRE_BEACON_US),
        )
        .saturating_sub(NAN_DW_PRE_BEACON_US);
        CAPTURING.store(false, Ordering::Release);
        ACQUIRING.store(false, Ordering::Release);
        ACQUIRE_PENDING.store(false, Ordering::Release);
        UNTIL_MS.store(0, Ordering::Release);
        NEXT_MS.store(
            (next_us / 1_000).min(u64::from(u32::MAX)) as u32,
            Ordering::Release,
        );
        return true;
    }
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

/// Preserve a current cluster timing anchor across one intentional physical
/// DW8 sleep. This is not a general profile-transition shortcut.
pub fn prepare_light_sleep_resume() {
    let (bssid, anchor_us, _) = sync_diagnostics();
    RESUME_SAVED_SYNC.store(!bssid_is_unset(bssid) && anchor_us != 0, Ordering::Release);
}

/// Select whether an active NOW epoch listens continuously for initial
/// actions.
///
/// Main calls this once while applying a committed radio profile, never from
/// an ESP-IDF callback or a timer tick.  An unassociated active device cannot
/// otherwise know which peer will initiate the next action, so limiting it to
/// a 64 ms NAN capture window makes NOW bootstrap probabilistic.  Sleepy DW8
/// profiles pass `false` and retain their normal bounded discovery windows.
pub fn set_active_now_receive(enabled: bool) -> bool {
    let was_enabled = NOW_ACTIVE_RECEIVE.swap(enabled, Ordering::AcqRel);
    // Applying an already-disabled NOW policy after `start()` must not replace
    // the phase-locked NAN deadline which start restored from the retained
    // cluster anchor.  Only a real enabled -> disabled transition owns the
    // receive teardown and its fallback cadence.
    if !enabled && !was_enabled {
        return true;
    }
    if !STARTED.load(Ordering::Acquire) || crate::wifi_nonpromisc_probe_esp::roc_in_flight() {
        return !enabled;
    }
    let now = now_ms();
    if enabled {
        if CAPTURING.load(Ordering::Acquire) || crate::wifi_esp::set_promiscuous(true) {
            CAPTURING.store(true, Ordering::Release);
            ACQUIRING.store(false, Ordering::Release);
            return true;
        }
        NOW_ACTIVE_RECEIVE.store(false, Ordering::Release);
        return false;
    }
    if NOW_CLIENT_RECEIVE_LEASE.load(Ordering::Acquire)
        || NOW_SERVICE_RECEIVE_UNTIL_MS.load(Ordering::Acquire) != 0
    {
        return true;
    }
    let _ = crate::wifi_esp::set_promiscuous(false);
    CAPTURING.store(false, Ordering::Release);
    ACQUIRING.store(false, Ordering::Release);
    NEXT_MS.store(now.wrapping_add(dw_period_ms()), Ordering::Release);
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
    NOW_CLIENT_RECEIVE_LEASE.store(false, Ordering::Release);
    NOW_ACTIVE_RECEIVE.store(false, Ordering::Release);
    NOW_SERVICE_RECEIVE_UNTIL_MS.store(0, Ordering::Release);
    ACQUIRING.store(false, Ordering::Release);
    ACQUIRE_PENDING.store(false, Ordering::Release);
    UNTIL_MS.store(0, Ordering::Release);
    NEXT_MS.store(0, Ordering::Release);
    DW_INTERVAL.store(0, Ordering::Release);
}

/// Advance the fixed discovery-window cadence. Call from the normal worker;
/// all radio state changes occur outside the Wi-Fi driver callback. Frame
/// callbacks copy bounded Service Info into `shared_ingress_esp` (which wakes
/// its deferred task); this function remains necessary only to service the
/// independent acquisition/DW deadlines and to perform the driver calls that
/// callbacks are not allowed to make.
///
/// Main calls this exactly once after the adapter's nearest acquisition, DW,
/// publish-refresh, or bounded ROC deadline. It does not inspect packets and
/// it has no idle cadence: [`next_service_delay_ms`] returns `None` when NAN
/// capture is stopped, leaving the Main task blocked on its event queue.
pub fn service_deadline() {
    if !STARTED.load(Ordering::Acquire) {
        return;
    }
    if NAN_CAPTURE_SUSPENDED.load(Ordering::Acquire) {
        // The callback gate drops every NAN management frame before parsing
        // or queueing it.  Do not alter promiscuous mode here: that hardware
        // transition can suppress the independently registered raw UDP6 RX
        // callback on classic associated STA.
        CAPTURING.store(false, Ordering::Release);
        return;
    }
    if lab_dw_policy() != 0 {
        return;
    }
    let now = now_ms();
    // Cluster selection is synchronization.  Do not continue to advertise
    // or schedule from a phase whose beacon has disappeared: a stale anchor
    // makes DW8 wake at the wrong time and prevents convergence on the live
    // NAN cluster. The normal acquisition window below is intentionally the
    // only recovery path; this does not add a polling task.
    let (selected, anchor_us, _) = sync_diagnostics();
    if !bssid_is_unset(selected)
        && anchor_us != 0
        && now_us().saturating_sub(anchor_us) >= NAN_CLUSTER_MISSED_BEACON_US
    {
        clear_cluster_selection();
        if !CAPTURING.load(Ordering::Acquire) && crate::wifi_esp::set_promiscuous(true) {
            CAPTURING.store(true, Ordering::Release);
            ACQUIRING.store(true, Ordering::Release);
            UNTIL_MS.store(now.wrapping_add(NAN_INITIAL_ACQUIRE_MS), Ordering::Release);
            NEXT_MS.store(now.wrapping_add(NAN_INITIAL_ACQUIRE_MS), Ordering::Release);
        }
        return;
    }
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
        drain_pending_sdfs();
        return;
    }
    // A direct one-shot ROC request may have been made between periodic
    // worker polls. Keep the DW state intact until the driver's done callback
    // releases the static request, instead of changing promiscuous mode from
    // underneath ROC.
    if crate::wifi_nonpromisc_probe_esp::roc_in_flight() {
        return;
    }
    if NOW_ACTIVE_RECEIVE.load(Ordering::Acquire) {
        // This is not a service cadence: Main does not arm NAN deadlines in
        // this state.  A queued control/radio event can enter here to restore
        // promiscuous receive after ROC, then the task blocks again.
        if !CAPTURING.load(Ordering::Acquire) && crate::wifi_esp::set_promiscuous(true) {
            CAPTURING.store(true, Ordering::Release);
        }
        drain_pending_followup_responses();
        drain_active_publish();
        drain_pending_sdfs();
        return;
    }
    // An explicit raw-NOW association temporarily extends the same receive
    // owner used by NAN.  Its client task is driven by exact PTO/deadline
    // events, not by this function; while the lease is held there is no NAN
    // capture deadline to wake for and no service-loop work to perform.
    if NOW_CLIENT_RECEIVE_LEASE.load(Ordering::Acquire) {
        if !CAPTURING.load(Ordering::Acquire) && crate::wifi_esp::set_promiscuous(true) {
            CAPTURING.store(true, Ordering::Release);
        }
        drain_pending_followup_responses();
        drain_active_publish();
        drain_pending_sdfs();
        return;
    }
    let service_until = NOW_SERVICE_RECEIVE_UNTIL_MS.load(Ordering::Acquire);
    if service_until != 0 {
        if !due(now, service_until) {
            if !CAPTURING.load(Ordering::Acquire) && crate::wifi_esp::set_promiscuous(true) {
                CAPTURING.store(true, Ordering::Release);
            }
            drain_pending_followup_responses();
            drain_active_publish();
            drain_pending_sdfs();
            return;
        }
        // The responder received no traffic before its explicit lease
        // deadline. Return to normal DW scheduling; the peer's QUIC PTO will
        // initiate another bounded action if the association is still alive.
        NOW_SERVICE_RECEIVE_UNTIL_MS.store(0, Ordering::Release);
        let _ = crate::wifi_esp::set_promiscuous(false);
        CAPTURING.store(false, Ordering::Release);
        ACQUIRING.store(false, Ordering::Release);
        NEXT_MS.store(now.wrapping_add(dw_period_ms()), Ordering::Release);
    }
    // A beacon observed during acquisition or a DW defines the next DW in
    // local time. This aligns independent devices to the same cluster beacon
    // instead of preserving their arbitrary boot-time phase.
    if let Some(anchor_us) = take_sync_anchor_us() {
        let next_us = dmesh_rawnan::next_nan_dw_start_us(
            anchor_us,
            now_us().saturating_add(NAN_DW_PRE_BEACON_US),
        )
        .saturating_sub(NAN_DW_PRE_BEACON_US);
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
        drain_pending_sdfs();
        if due(now, UNTIL_MS.load(Ordering::Relaxed)) {
            if SLEEPY_DW_PAIR.load(Ordering::Acquire)
                && !SLEEPY_DW_PAIR_SECOND.swap(true, Ordering::AcqRel)
            {
                // Do not toggle promiscuous RX between the paired windows:
                // the NOW window begins exactly as the NAN DW ends.
                UNTIL_MS.store(now.wrapping_add(NOW_DW_CAPTURE_MS), Ordering::Release);
                crate::commands::send_response(b"now DW start: paired capture retained");
                return;
            }
            let _ = crate::wifi_esp::set_promiscuous(false);
            // The paired receive span is complete. Return the unassociated
            // NAN driver to modem power-save while Main waits for the next
            // phase-locked deadline.
            let _ = crate::wifi_esp::set_nan_dw_power_save(true);
            CAPTURING.store(false, Ordering::Release);
            let capture_started_us = CAPTURE_STARTED_US.swap(0, Ordering::AcqRel);
            crate::commands::send_stats(&[
                (
                    b"nan DW end elapsed_us",
                    u64::from((now_us() as u32).wrapping_sub(capture_started_us)),
                ),
                (
                    b"nan DW end frames",
                    u64::from(
                        FRAMES
                            .load(Ordering::Acquire)
                            .wrapping_sub(CAPTURE_START_FRAMES.load(Ordering::Acquire)),
                    ),
                ),
                (
                    b"nan DW end beacons",
                    u64::from(
                        BEACONS
                            .load(Ordering::Acquire)
                            .wrapping_sub(CAPTURE_START_BEACONS.load(Ordering::Acquire)),
                    ),
                ),
            ]);
            if ACQUIRING.swap(false, Ordering::AcqRel) {
                NEXT_MS.store(now.wrapping_add(dw_period_ms()), Ordering::Release);
            }
        }
        return;
    }
    if !due(now, NEXT_MS.load(Ordering::Relaxed)) {
        return;
    }
    // Promiscuous NAN/NOW receive must not be deferred by modem power save.
    // This owner-side change is paired with the restore after the DW pair.
    let _ = crate::wifi_esp::set_nan_dw_power_save(false);
    if crate::wifi_esp::set_promiscuous(true) {
        CAPTURE_STARTED_US.store(now_us() as u32, Ordering::Release);
        CAPTURE_START_FRAMES.store(FRAMES.load(Ordering::Acquire), Ordering::Release);
        CAPTURE_START_BEACONS.store(BEACONS.load(Ordering::Acquire), Ordering::Release);
        CAPTURING.store(true, Ordering::Release);
        SLEEPY_DW_PAIR_SECOND.store(false, Ordering::Release);
        UNTIL_MS.store(now.wrapping_add(NAN_DW_CAPTURE_MS), Ordering::Relaxed);
        NEXT_MS.store(now.wrapping_add(dw_period_ms()), Ordering::Relaxed);
        drain_pending_followup_responses();
        drain_active_publish();
        drain_pending_sdfs();
        let cluster = selected_bssid();
        crate::commands::send_stats(&[
            (b"nan DW start interval", u64::from(interval())),
            (
                b"nan DW start cluster_le",
                u64::from_le_bytes([
                    cluster[0], cluster[1], cluster[2], cluster[3], cluster[4], cluster[5], 0, 0,
                ]),
            ),
        ]);
    } else {
        let _ = crate::wifi_esp::set_nan_dw_power_save(true);
    }
}

/// Return the next NAN acquisition/DW deadline in milliseconds. The Main
/// owner combines this with task notifications so the runtime sleeps until a
/// real radio timer expires or a control transition wakes it.
pub fn next_service_delay_ms() -> Option<u32> {
    if !STARTED.load(Ordering::Acquire) {
        return None;
    }
    if NAN_CAPTURE_SUSPENDED.load(Ordering::Acquire) {
        return None;
    }
    // ROC owns the Wi-Fi request slot and `service_deadline` cannot legally
    // change promiscuous state until ESP-IDF's done callback releases it.
    // Returning an already-expired DW deadline here used to rearm Main's
    // one-shot timer at 1 ms, creating a pointless wake loop. The ROC adapter
    // now enqueues a NAN completion event after release, so Main blocks until
    // that real state transition instead of polling the lease.
    if crate::wifi_nonpromisc_probe_esp::roc_in_flight() {
        return None;
    }
    let now = now_ms();
    // The active NOW receive owner is normally event-driven. Fresh NAN
    // announces and explicitly queued SDFs are bounded exceptions. In
    // particular, a targeted wake is repeated across discovery windows and
    // must not rely on an unrelated event to service attempts after the
    // immediate first transmission.
    if NOW_ACTIVE_RECEIVE.load(Ordering::Acquire) {
        let publish =
            (ACTIVE_PUBLISH_REMAINING.load(Ordering::Acquire) != 0).then_some(dw_period_ms());
        let pending_sdf = pending_sdf_delay_ms(now);
        return match (publish, pending_sdf) {
            (Some(left), Some(right)) => Some(left.min(right)),
            (Some(delay), None) | (None, Some(delay)) => Some(delay),
            (None, None) => None,
        };
    }
    // The active NOW client owns its own exact retry/PTO deadline in Main.
    // Returning `None` here prevents a second synthetic timer wake while the
    // receive lease is intentionally held open for real stream traffic.
    if NOW_CLIENT_RECEIVE_LEASE.load(Ordering::Acquire) {
        return None;
    }
    let service_until = NOW_SERVICE_RECEIVE_UNTIL_MS.load(Ordering::Acquire);
    if service_until != 0 {
        let remaining = service_until.wrapping_sub(now);
        return Some(if remaining > 0x8000_0000 {
            1
        } else {
            remaining.max(1)
        });
    }
    let deadline = if CAPTURING.load(Ordering::Acquire) {
        UNTIL_MS.load(Ordering::Acquire)
    } else {
        NEXT_MS.load(Ordering::Acquire)
    };
    let remaining = deadline.wrapping_sub(now);
    Some(if remaining > 0x8000_0000 {
        0
    } else {
        remaining.max(1)
    })
}

fn pending_sdf_delay_ms(now: u32) -> Option<u32> {
    PENDING_SDFS
        .iter()
        .filter(|slot| slot.state.load(Ordering::Acquire) == PENDING_READY)
        .map(|slot| {
            let deadline = slot.next_send_ms.load(Ordering::Acquire);
            if deadline == 0 {
                1
            } else {
                let remaining = deadline.wrapping_sub(now);
                if remaining > 0x8000_0000 {
                    1
                } else {
                    remaining.max(1)
                }
            }
        })
        .min()
}

fn dw_period_ms() -> u32 {
    NAN_DW_PERIOD_MS.saturating_mul(u32::from(DW_INTERVAL.load(Ordering::Acquire).max(1)))
}

unsafe extern "C" fn callback(
    buffer: *mut core::ffi::c_void,
    kind: esp_idf_sys::wifi_promiscuous_pkt_type_t,
) {
    if NAN_CAPTURE_SUSPENDED.load(Ordering::Acquire)
        || buffer.is_null()
        || kind != esp_idf_sys::wifi_promiscuous_pkt_type_t_WIFI_PKT_MGMT
    {
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
    let received_us = now_us() as u32;
    let woke_us = SLEEP_WAKE_US.load(Ordering::Acquire);
    if woke_us != 0 {
        let delta = received_us.wrapping_sub(woke_us).max(1);
        let _ = FIRST_FRAME_AFTER_WAKE_US.compare_exchange(
            0,
            delta,
            Ordering::AcqRel,
            Ordering::Relaxed,
        );
    }
    FRAMES.fetch_add(1, Ordering::Relaxed);
    BYTES.fetch_add(frame.len().min(u32::MAX as usize) as u32, Ordering::Relaxed);
    // Promiscuous capture is enabled only for the scheduled NAN DW and its
    // time-sync beacon. Keep the existing bounded NOW fallback on this same
    // ingress: C6's private `(127, 0)` callback is the continuous fast path,
    // but its split header/payload ABI has not completed every unassociated
    // exchange while a DW capture is active. Both paths enter the one NOW
    // parser/pool, which handles the duplicate safely. Do not admit P2P here.
    if dmesh_rawnan::is_action_frame(frame) {
        crate::wifi_espnow_esp::receive_action_frame(frame);
    }
    if dmesh_rawnan::is_nan_beacon(frame) {
        BEACONS.fetch_add(1, Ordering::Relaxed);
        if woke_us != 0 {
            let delta = received_us.wrapping_sub(woke_us).max(1);
            let _ = FIRST_BEACON_AFTER_WAKE_US.compare_exchange(
                0,
                delta,
                Ordering::AcqRel,
                Ordering::Relaxed,
            );
        }
        if let Some(bssid) = frame.get(dmesh_rawnan::FRAME_BSSID..dmesh_rawnan::FRAME_BSSID + 6) {
            let selected = selected_bssid();
            let received_us = now_us();
            let last_selected_us = {
                let high = SYNC_ANCHOR_HI.load(Ordering::Acquire);
                let low = SYNC_ANCHOR_LO.load(Ordering::Relaxed);
                (u64::from(high) << 32) | u64::from(low)
            };
            // Keep one live cluster so peers retain a common DW phase. If it
            // disappears, a foreign NAN beacon may replace it after the same
            // three-DW guard as rawnan::NanState. This avoids a permanently
            // stale first-acquired BSSID while avoiding per-beacon flapping.
            // TODO(NAN cluster convergence): ESP cannot transmit NAN sync
            // beacons, so it cannot take part in normal cluster merging. If
            // two isolated clusters later become visible through an ESP in
            // the middle, select the stronger beacon; when their RSSI values
            // are too close to distinguish, choose the lexicographically
            // smallest BSSID. Keep the stale-only handover for now: that
            // split-cluster case is uncommon and needs measured RSSI/hysteresis
            // before it can safely replace a live common DW phase.
            let replace_stale_cluster = !bssid_is_unset(selected)
                && bssid != selected
                && received_us.saturating_sub(last_selected_us)
                    >= dmesh_rawnan::NAN_CLUSTER_RESELECT_AFTER_US;
            if bssid_is_unset(selected) || replace_stale_cluster {
                select_cluster_bssid(bssid);
            }
            if bssid_is_unset(selected) || bssid == selected || replace_stale_cluster {
                // Store the local receive point. The selected beacon is the
                // local-clock anchor for subsequent fixed-interval DWs.
                store_sync_anchor_us(received_us);
                SYNC_ANCHOR_PENDING.store(true, Ordering::Release);
                FILTER_PENDING.store(true, Ordering::Release);
                shorten_sleepy_resume_capture_after_beacon(received_us);
            }
        }
    }
    if matches!(
        dmesh_rawnan::classify(frame),
        dmesh_rawnan::FrameKind::Sdf | dmesh_rawnan::FrameKind::Followup
    ) {
        receive_nan_action(frame);
    }
}

fn receive_nan_action(frame: &[u8]) {
    match dmesh_rawnan::classify(frame) {
        dmesh_rawnan::FrameKind::Sdf => {
            SDFS.fetch_add(1, Ordering::Relaxed);
            // Some ESP-IDF radio modes deliver NAN public actions through
            // the registered action path but do not surface NAN beacons to
            // the management promiscuous callback after a Main reboot.  A
            // matching DMesh SDF still proves a peer in this cluster is live
            // in the current discovery window. Use it only to seed an empty
            // cluster; ordinary beacon reception remains the authoritative
            // refresh/reselection path above.
            let dmesh_sdf = dmesh_rawnan::service_descriptors(frame)
                .into_iter()
                .any(|item| item.service_id == dmesh_rawnan::DMESH_SERVICE_ID);
            if dmesh_sdf {
                if let Some(bssid) =
                    frame.get(dmesh_rawnan::FRAME_BSSID..dmesh_rawnan::FRAME_BSSID + 6)
                {
                    let selected = selected_bssid();
                    // An SDF proves the cluster is visible, but contention
                    // gives it an arbitrary offset inside the DW. Never move
                    // the beacon-derived local clock anchor to an SDF arrival;
                    // doing so can shift the next 24 ms receive window past
                    // the actual beacon.
                    if bssid_is_unset(selected) {
                        select_cluster_bssid(bssid);
                        FILTER_PENDING.store(true, Ordering::Release);
                        crate::main_runtime::request_deadline_recheck();
                    }
                }
            }
            let last_beacon_us = {
                let high = SYNC_ANCHOR_HI.load(Ordering::Acquire);
                let low = SYNC_ANCHOR_LO.load(Ordering::Relaxed);
                (u64::from(high) << 32) | u64::from(low)
            };
            let after_beacon_us = now_us().saturating_sub(last_beacon_us);
            LAST_SDF_AFTER_BEACON_US.store(
                after_beacon_us.min(u64::from(u32::MAX)) as u32,
                Ordering::Relaxed,
            );
            let Some(source): Option<[u8; 6]> =
                frame.get(10..16).and_then(|source| source.try_into().ok())
            else {
                return;
            };
            LAST_SDF_FRAME_BYTES
                .store(frame.len().min(u32::MAX as usize) as u32, Ordering::Relaxed);
            let frame_len = frame.len().min(u32::MAX as usize) as u32;
            if frame_len <= 128
                && SMALL_SDF_MAX_BYTES
                    .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                        (frame_len > current).then_some(frame_len)
                    })
                    .is_ok()
            {
                for (index, byte) in source.iter().enumerate() {
                    SMALL_SDF_MAX_SOURCE[index].store(*byte, Ordering::Release);
                }
            }
            let bssid: [u8; 6] = frame
                .get(16..22)
                .and_then(|value| value.try_into().ok())
                .unwrap_or([0; 6]);
            for (index, byte) in source.iter().enumerate() {
                LAST_SDF_SOURCE[index].store(*byte, Ordering::Relaxed);
            }
            if frame.get(30) == Some(&0x03) {
                if let Some(service_id) = frame.get(33..39) {
                    for (index, byte) in service_id.iter().enumerate() {
                        LAST_SDF_SERVICE_ID[index].store(*byte, Ordering::Relaxed);
                    }
                }
            }
            // Active Subscribe puts its custom CBOR Service Info in SDEA;
            // active Publish puts it directly in the SDA. Both are delivered
            // through the same copied ingress record as UART/SD control.
            let active_descriptor =
                dmesh_rawnan::service_descriptors(frame)
                    .into_iter()
                    .any(|item| {
                        item.service_id == dmesh_rawnan::DMESH_SERVICE_ID
                            && matches!(item.descriptor.control, 0x10..=0x12)
                    });
            // A single public-action frame may contain several DMesh Service
            // Descriptors.  They are independent records: do not collapse the
            // receive path to the final descriptor merely because the common
            // worker is bounded.  `enqueue` copies each accepted payload and
            // reports a real pool-full drop, so Main can validate/handle every
            // on-air control record in its normal order.
            let mut descriptor_payload_seen = false;
            for descriptor in dmesh_rawnan::service_descriptors(frame) {
                if descriptor.service_id != dmesh_rawnan::DMESH_SERVICE_ID {
                    continue;
                }
                let descriptor_payload = descriptor.descriptor.payload;
                let kind = match descriptor.descriptor.control & 0x03 {
                    0 => NAN_OBSERVATION_ACTIVE_PUBLISH,
                    1 => NAN_OBSERVATION_ACTIVE_SUBSCRIBE,
                    2 => NAN_OBSERVATION_FOLLOWUP,
                    _ => NAN_OBSERVATION_OTHER,
                };
                record_nan_device_observation(source, bssid, kind, descriptor_payload);
                if !descriptor_payload.is_empty() {
                    descriptor_payload_seen = true;
                    SERVICE_INFO_MATCHED.fetch_add(1, Ordering::Relaxed);
                    // Some Android/driver combinations expose a Follow-up's
                    // DMesh service payload through the generic descriptor
                    // iterator rather than `FrameKind::Followup`. Unwrap it
                    // before shared direct dispatch. The inner payload is the
                    // same target-checked tagged-CBOR record received through
                    // the dedicated Follow-up branch below; forwarding the
                    // wrapper itself only produces a misleading reject.
                    let payload = dmesh_rawnan::parse_dmesh_nan_followup(descriptor_payload)
                        .map(|followup| followup.payload)
                        .unwrap_or(descriptor_payload);
                    if crate::shared_ingress_esp::enqueue(
                        crate::shared_ingress_esp::IngressKind::NanServiceInfo,
                        source,
                        payload,
                    ) {
                        SERVICE_INFO_ENQUEUED.fetch_add(1, Ordering::Relaxed);
                    } else {
                        SERVICE_INFO_DROPPED.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
            let active_subscribe =
                dmesh_rawnan::active_subscribe_service_info(frame, dmesh_rawnan::DMESH_SERVICE_ID);
            if active_descriptor {
                if let Some(bssid) = frame.get(16..22) {
                    for (index, byte) in bssid.iter().enumerate() {
                        ACTIVE_SUBSCRIBE_BSSID[index].store(*byte, Ordering::Relaxed);
                    }
                }
                ACTIVE_SUBSCRIBE_DESCRIPTORS.fetch_add(1, Ordering::Relaxed);
                let (header, info_len) = active_subscribe_sdea_layout(frame);
                ACTIVE_SUBSCRIBE_SDEA_HEADER.store(header, Ordering::Relaxed);
                ACTIVE_SUBSCRIBE_SDEA_INFO_LEN.store(info_len, Ordering::Relaxed);
                if active_subscribe.is_none() {
                    ACTIVE_SUBSCRIBE_SDEA_MISSES.fetch_add(1, Ordering::Relaxed);
                }
            }
            // Active-Subscribe Service Info lives in the matching SDEA, not
            // necessarily in the descriptor payload. It is another received
            // control record and therefore gets its own ingress submission.
            // Keep it distinct from descriptor payloads rather than selecting
            // a single "preferred" frame field.
            let active_service_info = active_subscribe
                .map(|item| item.service_info)
                .filter(|payload| !payload.is_empty());
            // Android's public Wi-Fi Aware API cannot put our arbitrary
            // control CBOR in an active-Subscribe SDEA reliably. It first
            // sends an empty Subscribe to obtain a framework PeerHandle, then
            // sends the target-checked wake record as a Follow-up. Answer the
            // empty DMesh Subscribe with the same bounded directed-discovery
            // request used by every other bearer so Main returns its signed
            // announce through the existing NAN Follow-up path. This is not a
            // new control grammar and does not promote the ESP by itself.
            if active_descriptor && !descriptor_payload_seen && active_service_info.is_none() {
                let (instance, requestor_instance) = active_subscribe
                    .map(|item| (item.instance, item.requestor_instance))
                    .unwrap_or((1, 0));
                ACTIVE_SUBSCRIBES.fetch_add(1, Ordering::Relaxed);
                mark_active_subscribe(source, instance, requestor_instance);
                let mut request = [0u8; 96];
                let queued = dmesh_server::announce::encode_discovery_request(0, &mut request)
                    .is_some_and(|used| {
                        crate::shared_ingress_esp::enqueue(
                            crate::shared_ingress_esp::IngressKind::NanServiceInfo,
                            source,
                            &request[..used],
                        )
                    });
                if queued {
                    SERVICE_INFO_ENQUEUED.fetch_add(1, Ordering::Relaxed);
                } else {
                    SERVICE_INFO_DROPPED.fetch_add(1, Ordering::Relaxed);
                }
                return;
            }
            if let Some(payload) = active_service_info {
                SERVICE_INFO_MATCHED.fetch_add(1, Ordering::Relaxed);
                // Preserve only NAN transaction metadata here. Shared direct
                // policy decides whether this payload is discovery,
                // transport configuration, or rejected input.
                if active_descriptor {
                    ACTIVE_SUBSCRIBES.fetch_add(1, Ordering::Relaxed);
                    let (instance, requestor_instance) = active_subscribe
                        .map(|item| (item.instance, item.requestor_instance))
                        // A descriptor without a decoded SDEA has no richer
                        // transaction facts; retain only its framing defaults.
                        .unwrap_or((1, 0));
                    mark_active_subscribe(source, instance, requestor_instance);
                }
                if crate::shared_ingress_esp::enqueue(
                    crate::shared_ingress_esp::IngressKind::NanServiceInfo,
                    source,
                    payload,
                ) {
                    SERVICE_INFO_ENQUEUED.fetch_add(1, Ordering::Relaxed);
                } else {
                    SERVICE_INFO_DROPPED.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        dmesh_rawnan::FrameKind::Followup => {
            FOLLOWUPS.fetch_add(1, Ordering::Relaxed);
            let source: Option<[u8; 6]> = frame.get(10..16).and_then(|value| value.try_into().ok());
            let bssid: [u8; 6] = frame
                .get(16..22)
                .and_then(|value| value.try_into().ok())
                .unwrap_or([0; 6]);
            if let Some(payload) =
                dmesh_rawnan::followup_service_info(frame, dmesh_rawnan::DMESH_SERVICE_ID)
            {
                if let Some(source) = source {
                    record_nan_device_observation(source, bssid, NAN_OBSERVATION_FOLLOWUP, payload);
                }
                if let Some(followup) = dmesh_rawnan::parse_dmesh_nan_followup(payload) {
                    // Directed discovery returns the signed announce inside
                    // the DMesh Follow-up envelope. It has a correlation
                    // `to` field, so the presence-only `decode_announce`
                    // helper intentionally rejects it. Retain only the
                    // compact identity/MAC correlation in the bounded cache;
                    // this lets a VIP-selected sleepy target be addressed by
                    // a controller's active Subscribe.
                    if let Some(source) = source {
                        if let Some(announce) = dmesh_server::tagged::decode(followup.payload)
                            .and_then(dmesh_server::announce::decode_record)
                        {
                            crate::wifi_raw_udp6_esp::record_connectionless_announce(
                                announce, source,
                            );
                        }
                    }
                    // A targeted Android `nan.wakeup` carries the common
                    // direct `transport.set` record in this Follow-up.  The
                    // former path retained it only for observation, which
                    // meant the target could see a valid Follow-up but could
                    // never execute the requested STA activation. Copy every
                    // valid DMesh Follow-up payload into the same bounded
                    // Main dispatcher used by SDF Service Info. Main still
                    // classifies the tagged record and the wake target before
                    // changing a profile; reception alone has no side effect.
                    if let Some(source) = source {
                        if crate::shared_ingress_esp::enqueue(
                            crate::shared_ingress_esp::IngressKind::NanServiceInfo,
                            source,
                            followup.payload,
                        ) {
                            SERVICE_INFO_ENQUEUED.fetch_add(1, Ordering::Relaxed);
                        } else {
                            SERVICE_INFO_DROPPED.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    record_followup(followup);
                }
            }
        }
        _ => {}
    }
}

/// Read only the fixed SDEA structural prefix after an active DMesh SDA. It
/// is a diagnostic of parser interoperability, never an application payload
/// capture.
fn active_subscribe_sdea_layout(frame: &[u8]) -> (u32, u32) {
    let mut active = None;
    let mut offset = dmesh_rawnan::NAN_ACTION_START;
    while offset + 3 <= frame.len() {
        let attribute = frame[offset];
        let len = u16::from_le_bytes([frame[offset + 1], frame[offset + 2]]) as usize;
        let body_start = offset + 3;
        let Some(body_end) = body_start.checked_add(len) else {
            return (0, 0);
        };
        let Some(body) = frame.get(body_start..body_end) else {
            return (0, 0);
        };
        if attribute == 0x03
            && body.len() >= 9
            && body[..6] == dmesh_rawnan::DMESH_SERVICE_ID
            && matches!(body[8], 0x10..=0x12)
        {
            active = Some((body[6], body[7]));
        } else if attribute == 0x0e
            && active.is_some_and(|(instance, requestor)| {
                body.len() >= 2 && body[0] == instance && body[1] == requestor
            })
        {
            let header = body
                .get(..4)
                .map(|bytes| u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
                .unwrap_or(0);
            let info_len = body
                .get(5..7)
                .map(|bytes| u32::from(u16::from_le_bytes([bytes[0], bytes[1]])))
                .unwrap_or(0);
            return (header, info_len);
        }
        offset = body_end;
    }
    (0, 0)
}
