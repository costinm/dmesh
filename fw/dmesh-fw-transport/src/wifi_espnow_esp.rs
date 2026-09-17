//! ESP adapter for the shared ESP-NOW-compatible action-frame bearer.
//!
//! `dmesh_rawnan::espnow` owns portable framing and tests. This module owns
//! raw 802.11 injection and continuous filtered action receive.
//!
//! ESP-NOW is connectionless and its action-frame address 3 is broadcast;
//! see <https://docs.espressif.com/projects/esp-idf/en/stable/esp32/api-reference/network/esp_now.html>.
//! Do not use an associated AP BSSID here. Receive is supplied by the private
//! non-promiscuous vendor-action dispatcher; it is deliberately independent
//! of NAN discovery-window/ROC policy. Main's hardware BSSID filter remains
//! an optional lower-level prefilter experiment.

// TODO: as fallback for NAN, we can use periodic (4s) NOW sync with similar master election.
// That works on host/esp32 - if Androids are present they can start a NAN cluster.
// Using only NOW action frames is simplest - no deps on the beacon/management frames in NAN.

use alloc::alloc::{alloc_zeroed, dealloc, Layout};
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicPtr, AtomicU32, AtomicUsize, Ordering};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EspNowPeer {
    pub mac: [u8; 6],
}

pub type EspNowHandler =
    fn(EspNowPeer, &[u8], &mut [u8; quic_lite::DEFAULT_MAX_DATAGRAM_SIZE]) -> Option<usize>;
/// Connection-owned egress poller. It is the same packet-at-a-time contract
/// used by raw UDP6: the action adapter has no egress queue of its own.
pub type EspNowPollHandler =
    fn(EspNowPeer, &mut [u8; quic_lite::DEFAULT_MAX_DATAGRAM_SIZE]) -> Option<usize>;

const FRAME_CAPACITY: usize = quic_lite::DEFAULT_MAX_DATAGRAM_SIZE + 96;
/// STA, AP, and the action bearer are deliberately co-channel (6) in this
/// design. A 400-ms off-channel dwell serialized each NOW packet and capped
/// even a successful transfer at a few kbit/s.  The C6 private receive path
/// reliably delivers the immediate action response through this transaction's
/// callback, but may not surface the following stream frames through its
/// continuous dispatcher.  Keep the transaction open for one bounded server
/// burst (ACK/control plus up to four action frames), rather than creating a
/// polling receive task or a bearer-private queue.  This latency/power cost is
/// paid only for an explicit NOW datagram; idle NAN discovery remains asleep.
// A response is produced by the shared ingress worker after the receiving
// driver callback returns. Ten milliseconds admits the bootstrap reply but
// is too short for the next server frame after the client sends its ACK: C6
// then drops that directed frame before the continuous dispatcher observes
// it. A connection *client* therefore keeps its initiating action request
// open long enough for the server's first reply and the following handoff.
//
// In principle only the client needs this window. Current C6 action receive,
// however, drops a directed server response when that server submission uses
// the short dwell, so every packet in the current single-worker implementation
// must retain it. This is deliberately a temporary compatibility constraint:
// moving radio submission to the common egress consumer will let server
// submission wait without blocking ingress/ACK handling.
// A full packet-at-a-time turn includes: TX callback -> shared ingress
// -> peer action dispatcher -> peer shared ingress -> peer reply. On C6 the
// measured 80 ms dwell covers the first reply but not this second directed
// turn, so retain the receiver for a bounded half second. QUIC-lite still
// supplies the eventual PTO; this only preserves the driver's in-band reply
// delivery while an explicit NOW transfer is active.
const NOW_ACTION_TX_SERVER_WAIT_MS: u32 = 1_000;
/// Public NAN Service Discovery actions use the same ESP-IDF submission API,
/// but they are control-plane advertisements rather than a NOW reply window.
/// Preserve their short original dwell so passive/active discovery does not
/// inherit the bulk-bearer latency or energy cost.
const PUBLIC_ACTION_TX_WAIT_MS: u32 = 10;
static HANDLER: AtomicUsize = AtomicUsize::new(0);
static POLL_HANDLER: AtomicUsize = AtomicUsize::new(0);
// Direct NOW frames are unicast by default, so let the Wi-Fi hardware retry a
// missed hop before QUIC-lite's end-to-end PTO is needed.  Broadcast records
// override this below: 802.11 does not acknowledge group-addressed frames.
static MAC_ACK_ENABLED: AtomicBool = AtomicBool::new(true);
static STARTED: AtomicBool = AtomicBool::new(false);
static RX_ACTIONS: AtomicU32 = AtomicU32::new(0);
static RX_DROPS: AtomicU32 = AtomicU32::new(0);
static RX_MANAGEMENT: AtomicU32 = AtomicU32::new(0);
static RX_BEACONS: AtomicU32 = AtomicU32::new(0);
static RX_NAN_BEACONS: AtomicU32 = AtomicU32::new(0);
static RX_ACTION_FRAMES: AtomicU32 = AtomicU32::new(0);
static RX_DISPATCHER: AtomicU32 = AtomicU32::new(0);
static RX_TX_RESPONSE_HOOK: AtomicU32 = AtomicU32::new(0);
static RX_PARSE_DROPS: AtomicU32 = AtomicU32::new(0);
static RX_INVALID_DROPS: AtomicU32 = AtomicU32::new(0);
static RX_BUSY_DROPS: AtomicU32 = AtomicU32::new(0);
static RX_SHARED_INGRESS_DROPS: AtomicU32 = AtomicU32::new(0);
static LAST_REGISTERED_BODY_PREFIX: AtomicU32 = AtomicU32::new(0);
static LAST_REGISTERED_BODY_LEN: AtomicU32 = AtomicU32::new(0);
static LAST_ROC_BODY_PREFIX: AtomicU32 = AtomicU32::new(0);
static LAST_ROC_BODY_LEN: AtomicU32 = AtomicU32::new(0);
static RX_SELF_ECHOES: AtomicU32 = AtomicU32::new(0);
/// The private vendor-action hook and bounded NAN promiscuous capture can
/// report the same physical action a few microseconds apart. Keep only this
/// scalar fingerprint/time pair, never a packet copy or bearer queue, so the
/// shared ingress pool does not spend two slots on one on-air frame.
static LAST_ACTION_FINGERPRINT: AtomicU32 = AtomicU32::new(0);
static LAST_ACTION_MS: AtomicU32 = AtomicU32::new(0);
static RX_DUPLICATE_ACTIONS: AtomicU32 = AtomicU32::new(0);
/// The three ESP-IDF receive callbacks below can preempt one another while
/// they use the bounded parser scratch.  They must never overwrite a frame
/// between header reconstruction and the shared-ingress copy: a corrupted
/// datagram is worse than one intentional loss because it can poison the
/// one-association QUIC-lite state.  Contention is therefore counted as a
/// normal bounded drop; the endpoint PTO retransmits through the common
/// egress path and no callback allocates or waits on a lock.
static ACTION_PARSE_BUSY: AtomicBool = AtomicBool::new(false);
const DUPLICATE_ACTION_WINDOW_MS: u32 = 20;
static TX_ACTIONS: AtomicU32 = AtomicU32::new(0);
static TX_FAILURES: AtomicU32 = AtomicU32::new(0);
static TX_LAST_ERROR: AtomicI32 = AtomicI32::new(0);
static TX_DURATION_TOTAL_US: AtomicU32 = AtomicU32::new(0);
static TX_DURATION_MAX_US: AtomicU32 = AtomicU32::new(0);
static TX_DURATION_LE_250US: AtomicU32 = AtomicU32::new(0);
static TX_DURATION_LE_750US: AtomicU32 = AtomicU32::new(0);
static TX_DURATION_LE_2MS: AtomicU32 = AtomicU32::new(0);
static TX_DURATION_GT_2MS: AtomicU32 = AtomicU32::new(0);
static mut LOCAL_MAC: [u8; 6] = [0; 6];
/// C flexible-array request storage for `esp_wifi_action_tx_req`. The SDK
/// copies this request before returning (as its own off-channel tests do),
/// and the heap-owned radio scratch avoids a per-packet allocator path.
#[repr(C)]
struct ActionTxRequest {
    request: esp_idf_sys::wifi_action_tx_req_t,
    data: [u8; FRAME_CAPACITY - 24],
}

/// NAN/NOW scratch is needed only while the action bearer is installed. Keep
/// its four MTU-sized buffers out of firmware BSS so reduced images which link
/// shared flash code do not permanently reserve them. The allocation is made
/// once before callbacks are registered and retained across radio restarts;
/// callbacks and packet turns never allocate.
#[repr(C)]
struct ActionBuffers {
    response: [u8; quic_lite::DEFAULT_MAX_DATAGRAM_SIZE],
    tx_frame: [u8; FRAME_CAPACITY],
    rx_payload: [u8; quic_lite::DEFAULT_MAX_DATAGRAM_SIZE],
    action_tx_request: ActionTxRequest,
}

static ACTION_BUFFERS: AtomicPtr<ActionBuffers> = AtomicPtr::new(core::ptr::null_mut());

fn ensure_action_buffers() -> bool {
    if !ACTION_BUFFERS.load(Ordering::Acquire).is_null() {
        return true;
    }
    let layout = Layout::new::<ActionBuffers>();
    let allocated = unsafe { alloc_zeroed(layout).cast::<ActionBuffers>() };
    if allocated.is_null() {
        return false;
    }
    if ACTION_BUFFERS
        .compare_exchange(
            core::ptr::null_mut(),
            allocated,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_err()
    {
        // A concurrent radio-start won the one-time installation. No callback
        // can see this un-published allocation, so releasing only the loser is
        // safe; the published scratch remains stable for the firmware lifetime.
        unsafe { dealloc(allocated.cast(), layout) };
    }
    true
}

fn action_buffers() -> Option<*mut ActionBuffers> {
    let buffers = ACTION_BUFFERS.load(Ordering::Acquire);
    (!buffers.is_null()).then_some(buffers)
}
pub fn stats() -> (u32, u32, u32, u32) {
    (
        RX_ACTIONS.load(Ordering::Relaxed),
        RX_DROPS.load(Ordering::Relaxed),
        TX_ACTIONS.load(Ordering::Relaxed),
        TX_FAILURES.load(Ordering::Relaxed),
    )
}

/// Bounded framing evidence for the ROC action callback.  It deliberately
/// exposes only a four-byte prefix and length, never an application record.
pub fn last_roc_action_body() -> (u32, u32) {
    (
        LAST_ROC_BODY_PREFIX.load(Ordering::Relaxed),
        LAST_ROC_BODY_LEN.load(Ordering::Relaxed),
    )
}

/// Per-driver-lane receive evidence: private dispatcher, transmit-response
/// hook, parser rejects, and locally echoed transmissions.  This does not
/// retain frames and is shared by Main and Recovery for radio diagnosis.
pub fn receive_diagnostics() -> (u32, u32, u32, u32) {
    (
        RX_DISPATCHER.load(Ordering::Relaxed),
        RX_TX_RESPONSE_HOOK.load(Ordering::Relaxed),
        RX_PARSE_DROPS.load(Ordering::Relaxed),
        RX_SELF_ECHOES.load(Ordering::Relaxed),
    )
}

/// Compact reason and shape evidence for action admission failures. The body
/// prefix is framing-only (four bytes), never retained application data.
pub fn receive_drop_diagnostics() -> (u32, u32, u32, u32, u32) {
    (
        RX_INVALID_DROPS.load(Ordering::Relaxed),
        RX_BUSY_DROPS.load(Ordering::Relaxed),
        RX_SHARED_INGRESS_DROPS.load(Ordering::Relaxed),
        LAST_REGISTERED_BODY_PREFIX.load(Ordering::Relaxed),
        LAST_REGISTERED_BODY_LEN.load(Ordering::Relaxed),
    )
}

/// Reset the scalar action-bearer accounting at a radio-lab epoch boundary.
/// This deliberately retains registered callbacks, peers, and packet-pool
/// state: `radio.reset_counters` must not disrupt a transfer or create a new
/// queue just to obtain before/after matrix evidence.
pub fn reset_stats() {
    RX_ACTIONS.store(0, Ordering::Release);
    RX_DROPS.store(0, Ordering::Release);
    RX_MANAGEMENT.store(0, Ordering::Release);
    RX_BEACONS.store(0, Ordering::Release);
    RX_NAN_BEACONS.store(0, Ordering::Release);
    RX_ACTION_FRAMES.store(0, Ordering::Release);
    RX_DISPATCHER.store(0, Ordering::Release);
    RX_TX_RESPONSE_HOOK.store(0, Ordering::Release);
    RX_PARSE_DROPS.store(0, Ordering::Release);
    RX_INVALID_DROPS.store(0, Ordering::Release);
    RX_BUSY_DROPS.store(0, Ordering::Release);
    RX_SHARED_INGRESS_DROPS.store(0, Ordering::Release);
    LAST_REGISTERED_BODY_PREFIX.store(0, Ordering::Release);
    LAST_REGISTERED_BODY_LEN.store(0, Ordering::Release);
    RX_SELF_ECHOES.store(0, Ordering::Release);
    TX_ACTIONS.store(0, Ordering::Release);
    TX_FAILURES.store(0, Ordering::Release);
    TX_LAST_ERROR.store(0, Ordering::Release);
    TX_DURATION_TOTAL_US.store(0, Ordering::Release);
    TX_DURATION_MAX_US.store(0, Ordering::Release);
    TX_DURATION_LE_250US.store(0, Ordering::Release);
    TX_DURATION_LE_750US.store(0, Ordering::Release);
    TX_DURATION_LE_2MS.store(0, Ordering::Release);
    TX_DURATION_GT_2MS.store(0, Ordering::Release);
}

/// Runtime action-TX acknowledgement policy for paired radio experiments.
/// This changes only ESP-IDF's immediate action request; QUIC credits and
/// retransmission remain connection-owned.
pub fn set_mac_ack_enabled(enabled: bool) {
    MAC_ACK_ENABLED.store(enabled, Ordering::Release);
}

pub fn mac_ack_enabled() -> bool {
    MAC_ACK_ENABLED.load(Ordering::Acquire)
}

/// `(total_us, max_us, <=250us, <=750us, <=2ms, >2ms)` measured around the
/// synchronous ESP-IDF transmit request. The buckets expose retry/contention
/// tails without retaining per-packet samples or allocating telemetry RAM.
pub fn tx_timing() -> (u32, u32, u32, u32, u32, u32) {
    (
        TX_DURATION_TOTAL_US.load(Ordering::Relaxed),
        TX_DURATION_MAX_US.load(Ordering::Relaxed),
        TX_DURATION_LE_250US.load(Ordering::Relaxed),
        TX_DURATION_LE_750US.load(Ordering::Relaxed),
        TX_DURATION_LE_2MS.load(Ordering::Relaxed),
        TX_DURATION_GT_2MS.load(Ordering::Relaxed),
    )
}

fn record_tx_duration_us(duration_us: u32) {
    TX_DURATION_TOTAL_US.fetch_add(duration_us, Ordering::Relaxed);
    let mut previous = TX_DURATION_MAX_US.load(Ordering::Relaxed);
    while duration_us > previous {
        match TX_DURATION_MAX_US.compare_exchange_weak(
            previous,
            duration_us,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => break,
            Err(observed) => previous = observed,
        }
    }
    match duration_us {
        0..=250 => {
            TX_DURATION_LE_250US.fetch_add(1, Ordering::Relaxed);
        }
        251..=750 => {
            TX_DURATION_LE_750US.fetch_add(1, Ordering::Relaxed);
        }
        751..=2_000 => {
            TX_DURATION_LE_2MS.fetch_add(1, Ordering::Relaxed);
        }
        _ => {
            TX_DURATION_GT_2MS.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Last raw action-TX driver result, retained as a scalar for lab diagnosis.
/// `ESP_OK` is zero; this adds no packet storage or queue.
pub fn last_tx_error() -> i32 {
    TX_LAST_ERROR.load(Ordering::Relaxed)
}

/// Install the connection-owned poller used after an accepted ingress packet.
/// It retains neither peer data nor a packet; the caller supplies the next
/// datagram directly into the shared scratch buffer.
pub fn set_poll_handler(handler: Option<EspNowPollHandler>) {
    POLL_HANDLER.store(
        handler.map_or(0, |handler| handler as usize),
        Ordering::Release,
    );
}

/// Bound one action-bearer egress burst by the association's packet history.
/// Capture evidence for the raw radio input. These counters deliberately do
/// not implement NAN synchronization or power decisions, which remain Main
/// policy, but make filter experiments observable in either firmware image.
pub fn management_stats() -> (u32, u32, u32, u32) {
    (
        RX_MANAGEMENT.load(Ordering::Relaxed),
        RX_BEACONS.load(Ordering::Relaxed),
        RX_NAN_BEACONS.load(Ordering::Relaxed),
        RX_ACTION_FRAMES.load(Ordering::Relaxed),
    )
}

/// Bind decoded public-vendor actions to the common QUIC-lite action handler.
/// Wi-Fi owns callback registration and starts/stops the shared packet pool;
/// this function never changes a driver callback or buffer lifecycle.
pub fn install_action_ingress(local_mac: [u8; 6], handler: EspNowHandler) -> bool {
    if !ensure_action_buffers() {
        return false;
    }
    HANDLER.store(handler as usize, Ordering::Release);
    // All NOW ingress and egress share one worker.  Main's one-shot client
    // timer and the packet worker can both produce actions; queuing egress
    // here prevents them from concurrently rewriting ACTION_TX_REQUEST while
    // retaining the same bounded packet-pool backpressure as UDP6 and UART.
    if !crate::shared_ingress_esp::start(
        crate::shared_ingress_esp::IngressKind::EspNowTx,
        dispatch_egress,
    ) {
        return false;
    }
    unsafe {
        LOCAL_MAC = local_mac;
    }
    STARTED.store(true, Ordering::Release);
    true
}

/// Make NOW framing/dispatch inert. ESP-IDF callback registration and shared
/// ingress-pool stop remain with `wifi_esp`, the sole Wi-Fi owner.
pub fn stop_action_ingress() {
    HANDLER.store(0, Ordering::Release);
    // The matching radio epoch owns the egress submitter too. A queued
    // datagram can still be released by the common worker, but it must not
    // call ESP-IDF after NOW has been stopped.
    crate::shared_ingress_esp::stop(crate::shared_ingress_esp::IngressKind::EspNowTx);
    STARTED.store(false, Ordering::Release);
}

/// Feed the C6 private vendor-action callback into the common NOW ingress.
///
/// `ieee80211_recv_action_register(127, 0, ...)` has the callback ABI
/// The private C6 action dispatcher has two call forms. Its vendor-reassembled
/// path uses `(context, length, payload)`. Generic STA/AP action ingress uses
/// `(interface, ieee80211_header, body_start, body_end)`. Both forms have
/// already checked category/OUI/vendor IEs and supplied the complete NOW body,
/// so this is deliberately an ABI adaptation, not a raw 802.11 frame parser.
/// Copy only the source MAC and bounded body into common ingress; none of the
/// private input pointers outlive this callback.
pub(crate) fn receive_registered_action_payload(
    peer_context: *mut core::ffi::c_void,
    second: usize,
    third: *mut u8,
    fourth: *mut u8,
) {
    RX_DISPATCHER.fetch_add(1, Ordering::Relaxed);
    if peer_context.is_null() || third.is_null() {
        RX_INVALID_DROPS.fetch_add(1, Ordering::Relaxed);
        RX_DROPS.fetch_add(1, Ordering::Relaxed);
        return;
    }
    let mut source = [0u8; 6];
    let (payload, len, vendor_reassembled) = if second <= crate::TRANSPORT_MTU {
        // `ieee80211_recv_action_vendor_esp_now`: its first context word is
        // the source-MAC pointer and `second` is the reassembled body length.
        let source_ptr = unsafe { core::ptr::read_unaligned(peer_context.cast::<*const u8>()) };
        if source_ptr.is_null() {
            RX_INVALID_DROPS.fetch_add(1, Ordering::Relaxed);
            RX_DROPS.fetch_add(1, Ordering::Relaxed);
            return;
        }
        unsafe { source.copy_from_slice(core::slice::from_raw_parts(source_ptr, 6)) };
        (third, second, true)
    } else {
        // Generic STA/AP action ingress. `second` is the 802.11 header
        // address, while third/fourth delimit the action body. Compare raw
        // addresses before creating either slice so a malformed native call
        // cannot underflow or retain a driver buffer.
        let header = second as *const u8;
        let start = third as usize;
        let end = fourth as usize;
        let Some(len) = end
            .checked_sub(start)
            .filter(|len| *len <= crate::TRANSPORT_MTU)
        else {
            LAST_REGISTERED_BODY_LEN.store(second.min(u32::MAX as usize) as u32, Ordering::Relaxed);
            RX_INVALID_DROPS.fetch_add(1, Ordering::Relaxed);
            RX_DROPS.fetch_add(1, Ordering::Relaxed);
            return;
        };
        if header.is_null() {
            RX_INVALID_DROPS.fetch_add(1, Ordering::Relaxed);
            RX_DROPS.fetch_add(1, Ordering::Relaxed);
            return;
        }
        unsafe { source.copy_from_slice(core::slice::from_raw_parts(header.add(10), 6)) };
        (third, len, false)
    };
    LAST_REGISTERED_BODY_LEN.store(len as u32, Ordering::Relaxed);
    let body = unsafe { core::slice::from_raw_parts(payload, len) };
    let prefix = body
        .iter()
        .take(4)
        .fold(0u32, |value, byte| (value << 8) | u32::from(*byte));
    LAST_REGISTERED_BODY_PREFIX.store(prefix, Ordering::Relaxed);
    if vendor_reassembled {
        // The vendor helper already concatenated the bodies into the complete
        // QUIC-lite datagram. Do not parse radio framing a second time.
        admit_now_payload(source, body);
        return;
    }
    // Generic STA/AP action ingress still includes the normal vendor action
    // prefix and IEs. Strip only that radio framing before handing the
    // complete opaque QUIC-lite datagram to the common dispatcher.
    let Some(buffers) = action_buffers() else {
        RX_DROPS.fetch_add(1, Ordering::Relaxed);
        return;
    };
    let output = unsafe { &mut (*buffers).rx_payload };
    match dmesh_rawnan::espnow::parse_action_body_into(body, output) {
        Some(used) => admit_now_payload(source, &output[..used]),
        None => {
            RX_PARSE_DROPS.fetch_add(1, Ordering::Relaxed);
            RX_DROPS.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// ESP-IDF's action-transmit request may receive a co-channel response during
/// its normal response interval. This is not remain-on-channel: it is the
/// request's own in-band reply hook, and it shares the exact parser/pool path
/// with the continuous private action dispatcher above.
unsafe extern "C" fn action_tx_rx_callback(
    header: *mut u8,
    payload: *mut u8,
    len: usize,
    _channel: u8,
) -> i32 {
    RX_TX_RESPONSE_HOOK.fetch_add(1, Ordering::Relaxed);
    receive_action_parts(header, payload, len);
    0
}

fn receive_action_parts(header: *mut u8, payload: *mut u8, len: usize) {
    // ROC supplies a normal 802.11 header and a separate action body.  Do
    // not synthesize a frame merely to parse it again; the portable parser
    // accepts this exact body shape.
    if header.is_null() || payload.is_null() || len > FRAME_CAPACITY - 24 {
        RX_DROPS.fetch_add(1, Ordering::Relaxed);
        return;
    }
    if ACTION_PARSE_BUSY.swap(true, Ordering::AcqRel) {
        RX_BUSY_DROPS.fetch_add(1, Ordering::Relaxed);
        RX_DROPS.fetch_add(1, Ordering::Relaxed);
        return;
    }
    let header = unsafe { core::slice::from_raw_parts(header, 24) };
    let payload = unsafe { core::slice::from_raw_parts(payload, len) };
    let prefix = payload
        .iter()
        .take(4)
        .fold(0u32, |value, byte| (value << 8) | u32::from(*byte));
    LAST_ROC_BODY_PREFIX.store(prefix, Ordering::Relaxed);
    LAST_ROC_BODY_LEN.store(len.min(u32::MAX as usize) as u32, Ordering::Relaxed);
    let Ok(source) = <[u8; 6]>::try_from(&header[10..16]) else {
        RX_PARSE_DROPS.fetch_add(1, Ordering::Relaxed);
        ACTION_PARSE_BUSY.store(false, Ordering::Release);
        return;
    };
    let Some(buffers) = action_buffers() else {
        RX_DROPS.fetch_add(1, Ordering::Relaxed);
        ACTION_PARSE_BUSY.store(false, Ordering::Release);
        return;
    };
    let output = unsafe { &mut (*buffers).rx_payload };
    RX_MANAGEMENT.fetch_add(1, Ordering::Relaxed);
    RX_ACTION_FRAMES.fetch_add(1, Ordering::Relaxed);
    match dmesh_rawnan::espnow::parse_action_body_into(payload, output) {
        Some(used) => admit_now_payload(source, &output[..used]),
        None if payload.starts_with(&dmesh_rawnan::espnow::ACTION_PREFIX) && payload.len() > 8 => {
            // The C6 ROC callback may validate and remove the vendor IEs
            // before invoking its response hook, while retaining the eight
            // byte action header.  In that ABI variant the suffix is already
            // the complete bounded QUIC datagram.  The connection/direct
            // dispatcher still validates it; this branch only removes the
            // native framing that the driver has already consumed.
            admit_now_payload(source, &payload[8..]);
        }
        None => {
            RX_PARSE_DROPS.fetch_add(1, Ordering::Relaxed);
        }
    }
    ACTION_PARSE_BUSY.store(false, Ordering::Release);
}

/// Feed an action supplied by ESP-IDF's bounded ROC receiver into the exact
/// parser and shared ingress queue used by the private `(127,0)` hook. ROC
/// owns only a receive lease; it is not a second bearer or packet queue.
pub(crate) fn receive_roc_action_parts(header: *mut u8, payload: *mut u8, len: usize) {
    receive_action_parts(header, payload, len);
}

/// Feed one complete action frame into the shared NOW parser and bounded
/// ingress pool. The continuous private dispatcher normally supplies spans,
/// while the existing NAN DW capture supplies a complete management frame as
/// the bounded fallback on C6.
pub fn receive_action_frame(frame: &[u8]) {
    if !dmesh_rawnan::is_action_frame(frame) {
        return;
    }
    RX_DISPATCHER.fetch_add(1, Ordering::Relaxed);
    if ACTION_PARSE_BUSY.swap(true, Ordering::AcqRel) {
        RX_BUSY_DROPS.fetch_add(1, Ordering::Relaxed);
        RX_DROPS.fetch_add(1, Ordering::Relaxed);
        return;
    }
    RX_MANAGEMENT.fetch_add(1, Ordering::Relaxed);
    RX_ACTION_FRAMES.fetch_add(1, Ordering::Relaxed);
    receive_action_frame_unlocked(frame);
    ACTION_PARSE_BUSY.store(false, Ordering::Release);
}

/// Parse one action while [`ACTION_PARSE_BUSY`] owns the shared scratch.
/// Callers above are the only callback adapters and release the guard after
/// the parser has copied the accepted payload into `shared_ingress_esp`.
fn receive_action_frame_unlocked(frame: &[u8]) {
    let Some(buffers) = action_buffers() else {
        RX_DROPS.fetch_add(1, Ordering::Relaxed);
        return;
    };
    let output = unsafe { &mut (*buffers).rx_payload };
    let Some((source, used)) = dmesh_rawnan::espnow::parse_action_frame_into(frame, output) else {
        RX_PARSE_DROPS.fetch_add(1, Ordering::Relaxed);
        return;
    };
    admit_now_payload(source, &output[..used]);
}

/// Apply the common post-framing admission policy.  Every callback variant
/// has supplied one complete bounded QUIC datagram and its immutable source
/// path fact by this point.
fn admit_now_payload(source: [u8; 6], payload: &[u8]) {
    // ESP-IDF exposes a locally transmitted action to private receive paths.
    // It is not ingress and must not consume a device-wide packet slot.
    if crate::wifi_radio_control_esp::is_local_action_source(source) {
        RX_SELF_ECHOES.fetch_add(1, Ordering::Relaxed);
        return;
    }
    if recently_seen_action(source, payload) {
        RX_DUPLICATE_ACTIONS.fetch_add(1, Ordering::Relaxed);
        return;
    }
    if !crate::wifi_esp::enqueue_now_payload(source, payload) {
        RX_SHARED_INGRESS_DROPS.fetch_add(1, Ordering::Relaxed);
        RX_DROPS.fetch_add(1, Ordering::Relaxed);
    } else {
        RX_ACTIONS.fetch_add(1, Ordering::Relaxed);
    }
}

/// Suppress only a near-simultaneous duplicate from the two C6 receive
/// callbacks. A QUIC-lite retransmission is separated by its PTO (hundreds
/// of milliseconds) and therefore remains visible to normal transport
/// recovery. This deliberately uses no allocation or retained payload.
fn recently_seen_action(source: [u8; 6], payload: &[u8]) -> bool {
    let mut hash = 0x811c_9dc5u32;
    for byte in source.iter().chain(payload.iter()) {
        hash ^= u32::from(*byte);
        hash = hash.wrapping_mul(0x0100_0193);
    }
    // Zero is reserved as the uninitialized value; preserve the comparison
    // contract even for the astronomically unlikely zero FNV result.
    let hash = hash.max(1);
    let now_ms = ((unsafe { esp_idf_sys::esp_timer_get_time() }.max(0) as u64) / 1_000) as u32;
    let previous_hash = LAST_ACTION_FINGERPRINT.load(Ordering::Acquire);
    let previous_ms = LAST_ACTION_MS.load(Ordering::Acquire);
    let duplicate =
        previous_hash == hash && now_ms.wrapping_sub(previous_ms) <= DUPLICATE_ACTION_WINDOW_MS;
    LAST_ACTION_FINGERPRINT.store(hash, Ordering::Release);
    LAST_ACTION_MS.store(now_ms, Ordering::Release);
    duplicate
}

pub(crate) fn dispatch_ingress(item: crate::shared_ingress_esp::IngressPacket, payload: &[u8]) {
    let handler = HANDLER.load(Ordering::Acquire);
    if handler == 0 {
        return;
    }
    let handler: EspNowHandler = unsafe { core::mem::transmute(handler) };
    let Some(buffers) = action_buffers() else {
        RX_DROPS.fetch_add(1, Ordering::Relaxed);
        return;
    };
    let response = unsafe { &mut (*buffers).response };
    // A valid QUIC-lite ACK normally has no immediate reply.  It can still
    // release a queued stream packet, so always reach the connection-owned
    // poller after handling ingress. Returning here used to stall the service
    // after its first ACK on packet-at-a-time bearers.
    let peer = EspNowPeer { mac: item.source() };
    let immediate = handler(peer, payload, response);
    let poll = POLL_HANDLER.load(Ordering::Acquire);
    let poll: Option<EspNowPollHandler> =
        (poll != 0).then(|| unsafe { core::mem::transmute(poll) });
    let used = immediate.or_else(|| poll.and_then(|poll| poll(peer, response)));
    if let Some(used) = used {
        if used > response.len() {
            TX_FAILURES.fetch_add(1, Ordering::Relaxed);
        } else {
            let packet = &response[..used];
            if !transmit_from_worker(peer, packet) {
                TX_FAILURES.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

/// Submit one queued NOW datagram from the sole common packet worker.
///
/// This is called once per [`IngressKind::EspNowTx`] queue item, not from a
/// periodic service tick.  The sender owns no packet history: QUIC-lite keeps
/// retransmission state and re-enqueues only a due complete datagram.
pub(crate) fn dispatch_egress(item: crate::shared_ingress_esp::IngressPacket, payload: &[u8]) {
    // A packet-at-a-time raw association sends one stream frame, then waits
    // for the peer's ACK before the next frame may leave the QUIC-lite
    // ledger.  Keep the existing NAN capture owner available for that reply
    // flight.  This is an egress-triggered, bounded 600 ms lease renewal—not
    // a periodic poll—and it is a no-op when NAN capture is not the active
    // radio personality.
    let _ = crate::wifi_nan_dw_capture_esp::request_permissive_capture(600);
    if !transmit_submitted(
        EspNowPeer { mac: item.source() },
        payload,
        NOW_ACTION_TX_SERVER_WAIT_MS,
    ) {
        TX_FAILURES.fetch_add(1, Ordering::Relaxed);
    }
}

/// Send one complete QUIC-lite datagram through the same driver action lane
/// used by the shared Recovery/Main bearer. Main-local raw 802.11 injection
/// remains available for explicit radio experiments, but must not be used by
/// the bearer: it bypasses this driver's action receive/reply integration.
pub fn transmit(peer: EspNowPeer, payload: &[u8]) -> bool {
    // Do not call the ESP-IDF action API from the Main timer owner or an RX
    // reply path directly.  Both producers share one static flexible-array
    // request below; the shared worker is the single submit owner and uses
    // the same bounded pool as UART and UDP6.
    crate::shared_ingress_esp::enqueue_espnow_tx(peer.mac, payload)
}

/// Submit a NOW datagram from the already serialized packet worker.
///
/// RX dispatch, client deadlines, server timers, and connection replies all
/// run on that one worker, so submitting here retains the single radio owner
/// while avoiding an extra queue turn inside the short C6 action reply window.
/// Callers outside that worker must use [`transmit`].
pub(crate) fn transmit_from_worker(peer: EspNowPeer, payload: &[u8]) -> bool {
    transmit_submitted(peer, payload, NOW_ACTION_TX_SERVER_WAIT_MS)
}

/// Perform the actual ESP-IDF action submission after common egress
/// serialization.  Only [`dispatch_egress`] calls this method, so the static
/// action request is never concurrently initialized by a client deadline and
/// a server response.
fn transmit_submitted(peer: EspNowPeer, payload: &[u8], wait_time_ms: u32) -> bool {
    // Normal NOW-like traffic is deliberately independent of NAN discovery
    // windows.  The common NAN policy enables promiscuous *receive* only for
    // the bounded DW capture; constraining data TX to that window both
    // destroys throughput and makes it depend on two devices' observation
    // phase.  A long transfer therefore runs with promiscuous disabled apart
    // from the 64 ms capture in each 512-TU DW, which is exactly the intended
    // coexistence test.
    let peer_is_broadcast = peer.mac == [0xff; 6];
    let lab_forces_broadcast = crate::wifi_radio_control_esp::action_destination_broadcast();
    let destination = if peer_is_broadcast || lab_forces_broadcast {
        [0xff; 6]
    } else {
        peer.mac
    };
    let Some(buffers) = action_buffers() else {
        TX_FAILURES.fetch_add(1, Ordering::Relaxed);
        return false;
    };
    let frame = unsafe { &mut (*buffers).tx_frame };
    // Auto normally means the STA identity, but an AP-only epoch has no
    // associated STA peer to which a reply could be addressed.  In that
    // topology the incoming action was received through the AP identity and
    // a client has bound its connection to that AP MAC.  Replying from the
    // factory STA MAC makes the packet reach the radio yet fail the client's
    // selected-peer check.  Keep explicit radio-control selections intact;
    // only resolve Auto to AP for this unambiguous AP-only personality.
    let configured_interface = crate::wifi_radio_control_esp::action_tx_interface();
    let interface = match configured_interface {
        dmesh_server::raw_wifi::RawWifiInterface::Auto
            if crate::wifi_esp::lab_open_ap_active() && !crate::wifi_esp::sta_associated() =>
        {
            crate::wifi_esp::RadioInterface::Ap
        }
        dmesh_server::raw_wifi::RawWifiInterface::Auto
        | dmesh_server::raw_wifi::RawWifiInterface::Sta => crate::wifi_esp::RadioInterface::Sta,
        dmesh_server::raw_wifi::RawWifiInterface::Ap => crate::wifi_esp::RadioInterface::Ap,
        // C6 has no usable public NAN interface.  Do not silently select a
        // phantom interface for an operational bearer; raw NAN discovery is
        // handled by its scheduled capture path instead.
        dmesh_server::raw_wifi::RawWifiInterface::Nan => {
            TX_FAILURES.fetch_add(1, Ordering::Relaxed);
            return false;
        }
    };
    let local = crate::wifi_esp::interface_mac(interface).unwrap_or_else(|| unsafe { LOCAL_MAC });
    // ESP-NOW-compatible actions use broadcast A3 even when the station is
    // associated. The cluster-BSSID experiment did not admit unsolicited
    // vendor actions through C6's private receiver.
    let Ok(frame_len) =
        dmesh_rawnan::espnow::encode_action_frame(frame, destination, local, [0xff; 6], payload)
    else {
        return false;
    };
    let action = &frame[24..frame_len];
    // The bearer has no independent egress queue, but it does have a local
    // link identity.  The shared radio handler controls this at runtime so
    // an APSTA relay can send action traffic from its AP MAC when requested;
    // Auto remains the STA behaviour used by normal infrastructure traffic.
    let sent = unsafe {
        let request = &mut (*buffers).action_tx_request;
        core::ptr::write_bytes(request as *mut ActionTxRequest, 0, 1);
        request.request.ifx = crate::wifi_esp::radio_interface_id(interface);
        request.request.dest_mac = destination;
        request.request.type_ = esp_idf_sys::wifi_action_tx_t_WIFI_OFFCHAN_TX_REQ;
        let Some((channel, secondary)) = crate::wifi_esp::current_channel() else {
            TX_FAILURES.fetch_add(1, Ordering::Relaxed);
            return false;
        };
        request.request.channel = channel;
        request.request.sec_channel = secondary;
        request.request.wait_time_ms = wait_time_ms;
        // A direct NOW packet has one concrete receiver, so use normal 802.11
        // ACK/retry when enabled.  Group-addressed discovery/announce records
        // cannot be ACKed; forcing no-ACK there avoids an invalid driver
        // request while preserving their one-to-many semantics.
        request.request.no_ack = peer_is_broadcast || lab_forces_broadcast || !mac_ack_enabled();
        request.request.rx_cb = Some(action_tx_rx_callback);
        request.request.bssid = [0xff; 6];
        request.request.data_len = action.len() as u32;
        request.data[..action.len()].copy_from_slice(action);
        let started_us = esp_idf_sys::esp_timer_get_time();
        let result = crate::wifi_esp::submit_action_tx(&mut request.request);
        record_tx_duration_us((esp_idf_sys::esp_timer_get_time() - started_us).max(0) as u32);
        result
    };
    if sent == esp_idf_sys::ESP_OK {
        TX_LAST_ERROR.store(0, Ordering::Relaxed);
        TX_ACTIONS.fetch_add(1, Ordering::Relaxed);
        true
    } else {
        TX_LAST_ERROR.store(sent, Ordering::Relaxed);
        TX_FAILURES.fetch_add(1, Ordering::Relaxed);
        false
    }
}

/// Emit a bounded unsolicited control/event record on the active NOW radio.
/// Direct records are QUIC-lite custom long-header packets even though they
/// are connectionless.  This matches UART and UDP6 and prevents a legacy CID sentinel or
/// a bare tagged-CBOR shape from becoming a bearer-specific protocol.
pub fn broadcast_record(record: &[u8]) -> bool {
    let mut packet = [0u8; crate::TRANSPORT_MTU];
    let Some(used) = crate::core_runtime::encode_connectionless_message(record, &mut packet) else {
        return false;
    };
    transmit(EspNowPeer { mac: [0xff; 6] }, &packet[..used])
}

/// Send a pre-built public action body through the same ESP-IDF action-TX
/// request lane as the NOW-like bearer. This is an explicit NAN diagnostic
/// primitive: `body` starts with public category/action/OUI (`04 09 50 6f
/// 9a 13`) and is not parsed as ESP-NOW data. Keeping it here avoids the
/// legacy `esp_wifi_80211_tx` restriction on associated stations.
pub fn transmit_public_action(destination: [u8; 6], bssid: [u8; 6], body: &[u8]) -> bool {
    transmit_public_action_on_interface(
        crate::wifi_esp::RadioInterface::Sta,
        destination,
        bssid,
        body,
    )
}

/// Send a complete public-action body on an explicitly selected driver lane.
/// This is used by the common raw-frame handler after it has retained A1, A3,
/// and the action body from a caller-supplied 802.11 frame.  Unlike
/// `esp_wifi_80211_tx`, the action request has an interface field; lab callers
/// may therefore ask the driver to attempt STA, AP, or NAN and receive its
/// actual result instead of a hidden STA fallback.
pub fn transmit_public_action_on_interface(
    interface: crate::wifi_esp::RadioInterface,
    destination: [u8; 6],
    bssid: [u8; 6],
    body: &[u8],
) -> bool {
    if body.len() > FRAME_CAPACITY - 24 {
        TX_FAILURES.fetch_add(1, Ordering::Relaxed);
        return false;
    }
    let Some(buffers) = action_buffers() else {
        TX_FAILURES.fetch_add(1, Ordering::Relaxed);
        return false;
    };
    let sent = unsafe {
        let request = &mut (*buffers).action_tx_request;
        core::ptr::write_bytes(request as *mut ActionTxRequest, 0, 1);
        request.request.ifx = crate::wifi_esp::radio_interface_id(interface);
        request.request.dest_mac = destination;
        request.request.type_ = esp_idf_sys::wifi_action_tx_t_WIFI_OFFCHAN_TX_REQ;
        let Some((channel, secondary)) = crate::wifi_esp::current_channel() else {
            TX_FAILURES.fetch_add(1, Ordering::Relaxed);
            return false;
        };
        request.request.channel = channel;
        request.request.sec_channel = secondary;
        request.request.wait_time_ms = PUBLIC_ACTION_TX_WAIT_MS;
        // Match ESP-IDF's own `esp_nan_de_tx`: NAN public actions use the
        // normal acknowledged action-request path even when A1 is the NAN
        // discovery-group address. Setting `no_ack` for that multicast MAC
        // makes `esp_wifi_action_tx_req` return success without producing a
        // peer-visible SDF on current ESP32/C6 drivers.
        request.request.no_ack = false;
        request.request.rx_cb = Some(action_tx_rx_callback);
        request.request.bssid = bssid;
        request.request.data_len = body.len() as u32;
        request.data[..body.len()].copy_from_slice(body);
        let started_us = esp_idf_sys::esp_timer_get_time();
        let result = crate::wifi_esp::submit_action_tx(&mut request.request);
        record_tx_duration_us((esp_idf_sys::esp_timer_get_time() - started_us).max(0) as u32);
        result
    };
    if sent == esp_idf_sys::ESP_OK {
        TX_LAST_ERROR.store(0, Ordering::Relaxed);
        TX_ACTIONS.fetch_add(1, Ordering::Relaxed);
        true
    } else {
        TX_LAST_ERROR.store(sent, Ordering::Relaxed);
        TX_FAILURES.fetch_add(1, Ordering::Relaxed);
        false
    }
}
