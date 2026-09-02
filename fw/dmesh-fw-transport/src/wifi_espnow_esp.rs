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

use alloc::boxed::Box;
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicUsize, Ordering};
use core::{alloc::Layout, mem::MaybeUninit};

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
// it. A raw-service *client* therefore keeps its initiating action request
// open long enough for the server's first reply and the following handoff.
//
// In principle only the client needs this window. Current C6 action receive,
// however, drops a directed server response when that server submission uses
// the short dwell, so every packet in the current single-worker implementation
// must retain it. This is deliberately a temporary compatibility constraint:
// moving radio submission to the common egress consumer will let server
// submission wait without blocking ingress/ACK handling.
// A full packet-at-a-time turn includes: client TX callback -> shared ingress
// -> peer action dispatcher -> peer shared ingress -> peer reply. On C6 the
// measured 80 ms dwell covers the first reply but not this second directed
// turn, so retain the receiver for a bounded half second. QUIC-lite still
// supplies the eventual PTO; this only preserves the driver's in-band reply
// delivery while an explicit NOW transfer is active.
const NOW_ACTION_TX_CLIENT_WAIT_MS: u32 = 1_000;
/// See [`NOW_ACTION_TX_CLIENT_WAIT_MS`]. This is intentionally equal until
/// the action submitter no longer runs on the ingress worker.
const NOW_ACTION_TX_SERVER_WAIT_MS: u32 = NOW_ACTION_TX_CLIENT_WAIT_MS;
/// Public NAN Service Discovery actions use the same ESP-IDF submission API,
/// but they are control-plane advertisements rather than a NOW reply window.
/// Preserve their short original dwell so passive/active discovery does not
/// inherit the bulk-bearer latency or energy cost.
const PUBLIC_ACTION_TX_WAIT_MS: u32 = 10;
static HANDLER: AtomicUsize = AtomicUsize::new(0);
static POLL_HANDLER: AtomicUsize = AtomicUsize::new(0);
/// Endpoint-owned egress credit for NOW. This is the pre-refactor proven
/// value: the raw service may emit its ACK/control follow-up without waiting
/// for an unrelated driver callback. It remains bounded by the association
/// history and changes only NOW action egress, never UDP6 or UART.
static TX_BURST_PACKETS: AtomicUsize = AtomicUsize::new(4);
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
// Attribute a received action after it leaves the driver.  These counters make
// a raw-service bootstrap failure distinguishable from a driver/filter failure
// without retaining any extra packet data.
static CLIENT_PEER_MISMATCHES: AtomicU32 = AtomicU32::new(0);
static CLIENT_RECEIVE_OK: AtomicU32 = AtomicU32::new(0);
static CLIENT_RECEIVE_ERRORS: AtomicU32 = AtomicU32::new(0);
static CLIENT_LAST_ERROR: AtomicU32 = AtomicU32::new(0);
static CLIENT_BOOTSTRAP_ACKS: AtomicU32 = AtomicU32::new(0);
static CLIENT_STREAM_PACKETS: AtomicU32 = AtomicU32::new(0);
static CLIENT_OTHER_PACKETS: AtomicU32 = AtomicU32::new(0);
// Keep only the low 32 bits of connection identifiers, never a payload, for
// the next bounded radio snapshot. C6 has no lock-free 64-bit atomics; this
// discriminator still identifies the delayed association that conflicts with
// a new bootstrap without a diagnostic queue or critical section.
static CLIENT_EXPECTED_SERVER_CID: AtomicU32 = AtomicU32::new(0);
static CLIENT_LAST_OTHER_DCID: AtomicU32 = AtomicU32::new(0);
/// Low 24 bits of the most recent peer that did not match the selected NOW
/// client. This completes the bounded stale-frame evidence on targets that
/// have only 32-bit lock-free atomics.
static CLIENT_LAST_OTHER_PEER_SUFFIX: AtomicU32 = AtomicU32::new(0);
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
static mut RESPONSE: [u8; quic_lite::DEFAULT_MAX_DATAGRAM_SIZE] =
    [0; quic_lite::DEFAULT_MAX_DATAGRAM_SIZE];
static mut TX_FRAME: [u8; FRAME_CAPACITY] = [0; FRAME_CAPACITY];
static mut RX_PAYLOAD: [u8; quic_lite::DEFAULT_MAX_DATAGRAM_SIZE] =
    [0; quic_lite::DEFAULT_MAX_DATAGRAM_SIZE];
static mut ROC_FRAME: [u8; FRAME_CAPACITY] = [0; FRAME_CAPACITY];
/// C flexible-array request storage for `esp_wifi_action_tx_req`. The SDK
/// copies this request before returning (as its own off-channel tests do),
/// but static storage also avoids a per-packet allocator path.
#[repr(C)]
struct ActionTxRequest {
    request: esp_idf_sys::wifi_action_tx_req_t,
    data: [u8; FRAME_CAPACITY - 24],
}
static mut ACTION_TX_REQUEST: core::mem::MaybeUninit<ActionTxRequest> =
    core::mem::MaybeUninit::uninit();
enum RawServiceClient {
    Check(dmesh_server::raw_transport::RawCheckClient<4, { quic_lite::DEFAULT_MAX_DATAGRAM_SIZE }>),
    /// Same one-client ownership as Check, but drives the bounded shared
    /// IPERF stream.  It adds no bearer queue or task: normal ingress and the
    /// existing poll callback supply every packet.
    // An IPERF client owns several ordered stream receivers in addition to
    // the QUIC-lite ledger.  Keep that bounded allocation off the shared
    // ingress worker stack: it is allocated only for an explicit command and
    // is released when the one-shot association completes or is replaced.
    // UART, UDP6, and NOW still submit packet bytes through the same pool;
    // this is connection state, not a bearer-private packet queue.
    Iperf(Box<dmesh_server::raw_transport::RawClient<4, { quic_lite::DEFAULT_MAX_DATAGRAM_SIZE }>>),
}
struct RawClientState {
    peer: EspNowPeer,
    client: RawServiceClient,
    started_at_us: i64,
    next_bootstrap_retry_us: i64,
    deadline_us: i64,
    // A one-shot raw client remains allocated briefly after FIN so a lossy
    // action bearer gets several terminal CLOSE transmissions.  Without this
    // drain the peer can retain its old one-association ledger and inject
    // stale packets into the next explicit check or IPERF session.
    close_drain_until_us: i64,
    next_close_retry_us: i64,
}

/// Terminal CLOSE is small and has no application payload. Four bounded
/// retries over this window are enough to retire the peer without turning a
/// completed association into an idle polling task or a persistent wake cost.
const RAW_CLIENT_CLOSE_DRAIN_US: i64 = 750_000;
const RAW_CLIENT_CLOSE_RETRY_US: i64 = 150_000;

/// Allocate a connection ID unique to this physical radio and association.
///
/// Both test peers begin their local generation at one after boot.  A
/// generation-only client CID therefore aliases e6's first client with e7's
/// first client, which is unsafe when both endpoints have recently served a
/// request and delayed action frames remain in flight.  The factory STA MAC is
/// stable before Wi-Fi is initialized and makes the client namespace local to
/// a board; the generation still separates successive client associations on
/// that board.  This is identity construction only--it neither polls nor
/// changes the radio state.
fn raw_client_connection_id(generation: u32) -> quic_lite::ConnectionId {
    let mac_value = crate::wifi_esp::factory_sta_mac()
        .map(|mac| {
            mac.into_iter()
                .fold(0u64, |value, byte| (value << 8) | u64::from(byte))
        })
        .unwrap_or(1);
    let mut value = 0x4553_0000_0000u64 | mac_value;
    value ^= u64::from(generation.max(1)).wrapping_mul(0x9e37_79b9);
    quic_lite::ConnectionId::new(value.max(1)).expect("nonzero NOW client CID")
}

impl RawServiceClient {
    fn server_cid(&self) -> Option<quic_lite::ConnectionId> {
        match self {
            Self::Check(client) => client.server_cid(),
            Self::Iperf(client) => client.server_cid(),
        }
    }
    fn retry_bootstrap(
        &self,
        out: &mut [u8; quic_lite::DEFAULT_MAX_DATAGRAM_SIZE],
    ) -> Result<usize, quic_lite::Error> {
        match self {
            Self::Check(client) => client.retry_bootstrap(out),
            Self::Iperf(client) => client.retry_bootstrap(out),
        }
    }
    fn receive(
        &mut self,
        packet: &[u8],
        now_ms: u64,
        out: &mut [u8; quic_lite::DEFAULT_MAX_DATAGRAM_SIZE],
    ) -> Result<Option<usize>, quic_lite::Error> {
        match self {
            Self::Check(client) => client.receive_at(packet, now_ms, out),
            Self::Iperf(client) => client.receive_at(packet, now_ms, out),
        }
    }
    fn accepts(&self, packet: &[u8]) -> bool {
        match self {
            Self::Check(client) => client.accepts(packet),
            Self::Iperf(client) => client.accepts(packet),
        }
    }
    fn poll(
        &mut self,
        now_ms: u64,
        _now_us: u64,
        out: &mut [u8; quic_lite::DEFAULT_MAX_DATAGRAM_SIZE],
    ) -> Result<Option<usize>, quic_lite::Error> {
        match self {
            Self::Check(client) => {
                match client.poll_transmit_at(now_ms, out) {
                    Ok(Some(packet)) => Ok(Some(packet)),
                    // `RawCheckClient` records endpoint time in the
                    // millisecond clock supplied by its receive path. Keep
                    // PTO in that same unit: comparing it to microseconds
                    // makes every 25 ms owner wake look hundreds of seconds
                    // overdue and floods the action bearer with duplicates.
                    Ok(None) => client.poll_retransmit(now_ms, 600, out),
                    Err(error) => Err(error),
                }
            }
            Self::Iperf(client) => match client.poll_transmit_at(now_ms, out) {
                Ok(Some(packet)) => Ok(Some(packet)),
                // `RawIperfClient::receive_at` likewise stamps sent packets
                // with `now_ms`, so its loss clock must stay in milliseconds.
                Ok(None) => client.poll_retransmit(now_ms, 600, out),
                Err(error) => Err(error),
            },
        }
    }
    /// Return the next genuine QUIC ACK/PTO deadline for this association.
    /// Main uses it to block on one timer event; it replaces the former 25 ms
    /// service tick and creates no packet queue or private bearer task.
    fn next_service_deadline_ms(&self, pto_ms: u64) -> Option<u64> {
        match self {
            Self::Check(client) => client.next_service_deadline_ms(pto_ms),
            Self::Iperf(client) => client.next_service_deadline_ms(pto_ms),
        }
    }
    /// Produce only the already-recorded terminal CLOSE during the adapter's
    /// short post-completion drain. It cannot encode a new request or stream
    /// frame, so it is safe to call from a one-shot deadline event.
    fn poll_close(
        &mut self,
        out: &mut [u8; quic_lite::DEFAULT_MAX_DATAGRAM_SIZE],
    ) -> Result<Option<usize>, quic_lite::Error> {
        match self {
            Self::Check(client) => client.poll_close(out),
            Self::Iperf(client) => client.poll_close(out),
        }
    }
    fn counters(&self) -> dmesh_server::raw_transport::RawServiceCounters {
        match self {
            Self::Check(client) => client.counters(),
            Self::Iperf(client) => client.counters(),
        }
    }
    fn is_complete(&self) -> bool {
        match self {
            Self::Check(client) => client.is_complete(),
            Self::Iperf(client) => client.is_complete(),
        }
    }
    fn bytes(&self) -> u64 {
        match self {
            Self::Check(client) => client.bytes(),
            Self::Iperf(client) => client.bytes(),
        }
    }
    fn errors(&self) -> u64 {
        match self {
            Self::Check(_) => 0,
            Self::Iperf(client) => client.callback_errors().into_iter().sum(),
        }
    }
}
static RAW_CLIENT_ACTIVE: AtomicBool = AtomicBool::new(false);
// `RAW_CLIENT_ACTIVE` reserves the one association before construction so two
// concurrent control records cannot both start it.  Construction can still
// fail before `RAW_CLIENT` has been written, therefore teardown needs this
// separate ownership bit before it may run `drop_in_place` on the static.
static RAW_CLIENT_INITIALIZED: AtomicBool = AtomicBool::new(false);
/// Monotonic generation for bounded status-check associations.
static RAW_CLIENT_GENERATION: AtomicU32 = AtomicU32::new(0);
static RAW_CLIENT_BYTES: AtomicU32 = AtomicU32::new(0);
static RAW_CLIENT_ERRORS: AtomicU32 = AtomicU32::new(0);
static RAW_CLIENT_ELAPSED_US: AtomicU32 = AtomicU32::new(0);
/// Published by the shared ingress owner after every client state change.
/// Main reads this scalar only to arm its one-shot timer; it never borrows
/// `RAW_CLIENT`, whose ledger and response scratch belong to that worker.
static RAW_CLIENT_NEXT_DUE_MS: AtomicU32 = AtomicU32::new(0);
static mut RAW_CLIENT: MaybeUninit<RawClientState> = MaybeUninit::uninit();

/// Allocate the one bounded IPERF client without Rust's infallible `Box::new`
/// abort path.  Classic ESP boards can have sufficient total heap but no
/// contiguous block after a radio epoch replacement; admission must then fail
/// visibly instead of rebooting the board.  The allocation is reclaimed by
/// [`finish_raw_client`] and never forms a packet queue.
fn try_allocate_iperf_client_storage() -> Option<
    Box<
        MaybeUninit<
            dmesh_server::raw_transport::RawClient<4, { quic_lite::DEFAULT_MAX_DATAGRAM_SIZE }>,
        >,
    >,
> {
    let layout = Layout::new::<
        MaybeUninit<
            dmesh_server::raw_transport::RawClient<4, { quic_lite::DEFAULT_MAX_DATAGRAM_SIZE }>,
        >,
    >();
    let storage = unsafe { alloc::alloc::alloc(layout) };
    (!storage.is_null()).then(|| unsafe { Box::from_raw(storage.cast()) })
}

/// Retire the one raw-NOW association and release its receive coverage.
///
/// Every terminal path shares this helper so a failed first OPEN, timeout,
/// normal CLOSE drain, and radio-mode replacement cannot leave the NAN owner
/// in continuous promiscuous receive.  This does not free or queue packets:
/// packet ingress remains the common UART/UDP6/NOW pool.  It *does* drop the
/// one boxed IPERF ledger when the association is finished; overwriting a
/// `MaybeUninit` static without that drop leaked several KiB on every NOW
/// run and eventually reset small classic-ESP boards during a later request.
fn finish_raw_client() {
    RAW_CLIENT_NEXT_DUE_MS.store(0, Ordering::Release);
    let was_active = RAW_CLIENT_ACTIVE.swap(false, Ordering::AcqRel);
    if was_active && RAW_CLIENT_INITIALIZED.swap(false, Ordering::AcqRel) {
        // All start paths publish INITIALIZED only after writing every field.
        // The raw-service owner is the single ingress worker, so no callback
        // can retain a state reference once it observes ACTIVE=false.
        unsafe {
            core::ptr::drop_in_place(core::ptr::addr_of_mut!(RAW_CLIENT).cast::<RawClientState>());
        }
    }
    crate::wifi_nan_dw_capture_esp::end_now_receive_lease();
}

pub fn stats() -> (u32, u32, u32, u32) {
    (
        RX_ACTIONS.load(Ordering::Relaxed),
        RX_DROPS.load(Ordering::Relaxed),
        TX_ACTIONS.load(Ordering::Relaxed),
        TX_FAILURES.load(Ordering::Relaxed),
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
    CLIENT_PEER_MISMATCHES.store(0, Ordering::Release);
    CLIENT_RECEIVE_OK.store(0, Ordering::Release);
    CLIENT_RECEIVE_ERRORS.store(0, Ordering::Release);
    CLIENT_LAST_ERROR.store(0, Ordering::Release);
    CLIENT_BOOTSTRAP_ACKS.store(0, Ordering::Release);
    CLIENT_STREAM_PACKETS.store(0, Ordering::Release);
    CLIENT_OTHER_PACKETS.store(0, Ordering::Release);
    {
        RAW_CLIENT_BYTES.store(0, Ordering::Release);
        RAW_CLIENT_ERRORS.store(0, Ordering::Release);
        RAW_CLIENT_ELAPSED_US.store(0, Ordering::Release);
    }
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

/// Client-side disposition of parseable ingress while a raw-service bootstrap
/// is active: wrong source MAC, accepted by the host-tested state machine, or
/// rejected by that state machine. These remain scalars so they do not change
/// the device-wide packet budget.
pub fn client_diagnostics() -> (u32, u32, u32, u32, u32, u32, u32) {
    (
        CLIENT_PEER_MISMATCHES.load(Ordering::Relaxed),
        CLIENT_RECEIVE_OK.load(Ordering::Relaxed),
        CLIENT_RECEIVE_ERRORS.load(Ordering::Relaxed),
        CLIENT_LAST_ERROR.load(Ordering::Relaxed),
        CLIENT_BOOTSTRAP_ACKS.load(Ordering::Relaxed),
        CLIENT_STREAM_PACKETS.load(Ordering::Relaxed),
        CLIENT_OTHER_PACKETS.load(Ordering::Relaxed),
    )
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
pub fn set_tx_burst_packets(packets: usize) {
    TX_BURST_PACKETS.store(
        packets.clamp(1, crate::RAW_SERVICE_HISTORY_CAPACITY),
        Ordering::Release,
    );
}

/// True only while the single bounded raw-action service check owns a client
/// association. Main uses this to tighten its normal housekeeping cadence
/// for delayed ACKs without turning it into a permanent wake/power cost.
pub fn raw_client_active() -> bool {
    RAW_CLIENT_ACTIVE.load(Ordering::Acquire)
}

/// Return the next bounded NOW-client service deadline for Main's one-shot
/// timer. Called only while arming that timer, after a queued event; it does
/// not transmit or poll a driver. Bootstrap retries use their exact 400 ms
/// due time, while an established QUIC-lite client is serviced at a short
/// delayed-ACK/PTO cadence until its own completion or deadline.
pub fn next_raw_client_delay_ms() -> Option<u32> {
    if !RAW_CLIENT_ACTIVE.load(Ordering::Acquire) {
        return None;
    }
    let due_ms = RAW_CLIENT_NEXT_DUE_MS.load(Ordering::Acquire);
    if due_ms == 0 {
        return None;
    }
    let now_ms = (unsafe { esp_idf_sys::esp_timer_get_time() }.max(0) as u64 / 1_000) as u32;
    let remaining = due_ms.wrapping_sub(now_ms);
    Some(if remaining > 0x8000_0000 {
        1
    } else {
        remaining.clamp(1, 1_000)
    })
}

/// Recompute Main's next one-shot wake after a shared-worker client change.
/// This function is never called from a Wi-Fi callback and only publishes a
/// scalar deadline; it deliberately does not schedule or transmit anything.
fn publish_raw_client_deadline(state: &RawClientState) {
    let now_us = unsafe { esp_idf_sys::esp_timer_get_time() };
    let due_us = if state.client.is_complete() {
        state.next_close_retry_us.min(state.close_drain_until_us)
    } else if state.client.server_cid().is_some() {
        // QUIC-lite already knows whether an ACK is due and when its earliest
        // retained packet reaches PTO.  Do not turn a live association into a
        // 25 ms firmware tick: arm only that exact endpoint deadline.
        state
            .client
            .next_service_deadline_ms(600)
            .map(|deadline_ms| (deadline_ms.saturating_mul(1_000)) as i64)
            .unwrap_or(state.deadline_us)
    } else {
        state.next_bootstrap_retry_us.min(state.deadline_us)
    };
    RAW_CLIENT_NEXT_DUE_MS.store((due_us.max(0) as u64 / 1_000) as u32, Ordering::Release);
}

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

pub fn raw_client_result() -> (u32, u32, u32) {
    (
        RAW_CLIENT_BYTES.load(Ordering::Acquire),
        RAW_CLIENT_ERRORS.load(Ordering::Acquire),
        RAW_CLIENT_ELAPSED_US.load(Ordering::Acquire),
    )
}

/// Return the connection IDs behind the last NOW-client demultiplex decision.
/// The ordinary radio snapshot reads these scalars; neither field retains a
/// frame or creates another task, queue, or buffer pool.
pub fn raw_client_cid_diagnostics() -> (Option<u32>, Option<u32>, Option<u32>) {
    let expected = CLIENT_EXPECTED_SERVER_CID.load(Ordering::Acquire);
    let other = CLIENT_LAST_OTHER_DCID.load(Ordering::Acquire);
    let peer = CLIENT_LAST_OTHER_PEER_SUFFIX.load(Ordering::Acquire);
    (
        (expected != 0).then_some(expected),
        (other != 0).then_some(other),
        (peer != 0).then_some(peer),
    )
}

/// Bind decoded public-vendor actions to the common QUIC-lite action handler.
/// Wi-Fi owns callback registration and starts/stops the shared packet pool;
/// this function never changes a driver callback or buffer lifecycle.
pub fn install_action_ingress(local_mac: [u8; 6], handler: EspNowHandler) -> bool {
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

/// Notify Main that an active client has an exact retry/PTO wake. Main owns
/// the single blocking deadline queue shared with other transports; this
/// adapter neither creates a task nor polls while idle.
pub fn schedule_raw_client_service() {
    publish_current_raw_client_deadline();
    // Packet ingress or a new client has changed the earliest deadline while
    // Main may be blocked indefinitely. Wake it once to recalculate. A due
    // timer turn uses only `publish_current_raw_client_deadline` below: waking
    // Main from that path would turn a 25-ms ACK deadline into a hot loop.
    crate::main_runtime::request_transport_service();
}

fn publish_current_raw_client_deadline() {
    if !RAW_CLIENT_ACTIVE.load(Ordering::Acquire) {
        return;
    }
    // This helper runs only on the shared ingress worker. Main reads the
    // resulting atomic scalar but never dereferences RAW_CLIENT.
    unsafe {
        let state = &*core::ptr::addr_of!(RAW_CLIENT).cast::<RawClientState>();
        publish_raw_client_deadline(state);
    }
}

/// Make NOW framing/dispatch inert. ESP-IDF callback registration and shared
/// ingress-pool stop remain with `wifi_esp`, the sole Wi-Fi owner.
pub fn stop_action_ingress() {
    // `transport.start` replaces a complete Wi-Fi epoch. A bounded NOW
    // client from the previous epoch cannot remain eligible for polling or
    // prevent the next epoch from starting its own check client. The state
    // occupies only static storage; clearing this ownership bit is sufficient
    // and avoids carrying a packet or driver buffer across the replacement.
    finish_raw_client();
    HANDLER.store(0, Ordering::Release);
    // The matching radio epoch owns the egress submitter too. A queued
    // datagram can still be released by the common worker, but it must not
    // call ESP-IDF after NOW has been stopped.
    crate::shared_ingress_esp::stop(crate::shared_ingress_esp::IngressKind::EspNowTx);
    STARTED.store(false, Ordering::Release);
}

/// Start one bounded `SERVICE_ECHO` check over the NOW-like bearer. This
/// shares the same packet slot, timeout, receive callback, and counters as
/// a normal stream service; only the `dmesh-server` client differs.
pub fn start_check_client(peer: EspNowPeer, nonce: u64, timeout_ms: u32) -> bool {
    // NAN+NOW keeps the private action callback registered even while the
    // endpoint is unassociated.  Do not acquire a blocking ROC lease here:
    // ROC is a diagnostic receive mode and would hold the client before its
    // first OPEN transmission, making the normal NAN+NOW bearer appear dead.
    // The dedicated ROC tests configure that mode explicitly through the raw
    // radio control handler instead.
    if RAW_CLIENT_ACTIVE.swap(true, Ordering::AcqRel) {
        return false;
    }
    if !crate::wifi_nan_dw_capture_esp::begin_now_receive_lease() {
        finish_raw_client();
        return false;
    }
    let generation = RAW_CLIENT_GENERATION
        .fetch_add(1, Ordering::AcqRel)
        .wrapping_add(1);
    CLIENT_EXPECTED_SERVER_CID.store(0, Ordering::Release);
    CLIENT_LAST_OTHER_DCID.store(0, Ordering::Release);
    CLIENT_LAST_OTHER_PEER_SUFFIX.store(0, Ordering::Release);
    let cid = raw_client_connection_id(generation);
    let mut client = dmesh_server::raw_transport::RawCheckClient::new(cid, nonce);
    let used = unsafe {
        let response = &mut *core::ptr::addr_of_mut!(RESPONSE);
        match client.start(response) {
            Ok(used) => used,
            Err(_) => {
                finish_raw_client();
                return false;
            }
        }
    };
    unsafe {
        core::ptr::addr_of_mut!(RAW_CLIENT).write(MaybeUninit::new(RawClientState {
            peer,
            client: RawServiceClient::Check(client),
            started_at_us: esp_idf_sys::esp_timer_get_time(),
            next_bootstrap_retry_us: esp_idf_sys::esp_timer_get_time() + 400_000,
            deadline_us: esp_idf_sys::esp_timer_get_time()
                + i64::from(timeout_ms.clamp(
                    1_000,
                    dmesh_server::raw_iperf::RAW_ACTION_IPERF_MAX_TIMEOUT_MS,
                )) * 1_000,
            close_drain_until_us: 0,
            next_close_retry_us: 0,
        }));
        RAW_CLIENT_INITIALIZED.store(true, Ordering::Release);
        let response = &*core::ptr::addr_of!(RESPONSE);
        // A radio check is commonly initiated by a UART control record, not
        // by the shared ingress worker.  The action request scratch and its
        // in-band RX callback have one owner, so enqueue this first OPEN
        // exactly like the timer-driven retransmits instead of writing that
        // scratch from the UART service context.
        if !transmit(peer, &response[..used]) {
            finish_raw_client();
            return false;
        }
    }
    // The opening flight has left the adapter, so Main must now block until
    // this association's exact retry/deadline even if the first OPEN_ACK is
    // lost.  Receiving an ACK also rearms this service, but cannot be its
    // only source or a silent first-frame loss strands the client forever.
    schedule_raw_client_service();
    true
}

/// Start one bounded device-to-device NOW IPERF run.  The control record may
/// arrive through NAN Service Discovery, a QUIC stream, or UART; all paths
/// enter this one client and therefore get identical packet, timeout, and
/// completion accounting.
pub fn start_iperf_client(peer: EspNowPeer, bytes: u64, packet_size: u16, timeout_ms: u32) -> bool {
    if RAW_CLIENT_ACTIVE.swap(true, Ordering::AcqRel) {
        return false;
    }
    if !crate::wifi_nan_dw_capture_esp::begin_now_receive_lease() {
        finish_raw_client();
        return false;
    }
    let generation = RAW_CLIENT_GENERATION
        .fetch_add(1, Ordering::AcqRel)
        .wrapping_add(1);
    CLIENT_EXPECTED_SERVER_CID.store(0, Ordering::Release);
    CLIENT_LAST_OTHER_DCID.store(0, Ordering::Release);
    CLIENT_LAST_OTHER_PEER_SUFFIX.store(0, Ordering::Release);
    // Check and IPERF share the board-specific client namespace.  The action
    // bearer is service-opaque; the CID exists solely for QUIC-lite routing.
    let cid = raw_client_connection_id(generation);
    // Construct directly in heap storage.  Returning RawClient by value
    // would first materialize its complete fixed ledger on this command/
    // ingress worker stack; a burst of control messages then risks corrupting
    // the same worker that owns all UART, UDP6, and NOW parsing.  The client
    // lifetime is exactly RAW_CLIENT_ACTIVE, so replacing or completing the
    // association drops this allocation without retaining a packet buffer.
    let mut client_storage = match try_allocate_iperf_client_storage() {
        Some(storage) => storage,
        None => {
            RAW_CLIENT_ERRORS.fetch_add(1, Ordering::Relaxed);
            crate::commands::send_response(b"espnow IPERF client allocation unavailable");
            finish_raw_client();
            return false;
        }
    };
    let mut client: Box<
        dmesh_server::raw_transport::RawClient<4, { quic_lite::DEFAULT_MAX_DATAGRAM_SIZE }>,
    > = match dmesh_server::raw_transport::RawClient::new_in_place(
        &mut client_storage,
        cid,
        bytes,
        packet_size,
    ) {
        Ok(_) => {
            // new_in_place initialized every field, so reinterpret the same
            // allocation as its final type without a stack-sized move.
            unsafe { Box::from_raw(Box::into_raw(client_storage).cast()) }
        }
        Err(_) => {
            finish_raw_client();
            return false;
        }
    };
    let used = unsafe {
        let response = &mut *core::ptr::addr_of_mut!(RESPONSE);
        match client.start(response) {
            Ok(used) => used,
            Err(_) => {
                finish_raw_client();
                return false;
            }
        }
    };
    unsafe {
        core::ptr::addr_of_mut!(RAW_CLIENT).write(MaybeUninit::new(RawClientState {
            peer,
            client: RawServiceClient::Iperf(client),
            started_at_us: esp_idf_sys::esp_timer_get_time(),
            next_bootstrap_retry_us: esp_idf_sys::esp_timer_get_time() + 400_000,
            deadline_us: esp_idf_sys::esp_timer_get_time()
                + i64::from(timeout_ms.clamp(
                    1_000,
                    dmesh_server::raw_iperf::RAW_ACTION_IPERF_MAX_TIMEOUT_MS,
                )) * 1_000,
            close_drain_until_us: 0,
            next_close_retry_us: 0,
        }));
        RAW_CLIENT_INITIALIZED.store(true, Ordering::Release);
        let response = &*core::ptr::addr_of!(RESPONSE);
        // See the check-client OPEN above: this control-path start can run
        // from UART, while the action request itself is owned by the common
        // egress worker.
        if !transmit(peer, &response[..used]) {
            finish_raw_client();
            return false;
        }
    }
    // See the Check client above: this installs a durable owner-side timer,
    // not a bearer polling task or a private NOW queue.
    schedule_raw_client_service();
    true
}

/// Feed the original ESP-IDF private-dispatcher spans into the proven NOW
/// adapter. `wifi_esp` owns registration and classification; this module owns
/// only ESP-NOW framing and bounded ingress.
pub(crate) fn receive_registered_action_parts(header: *mut u8, payload: *mut u8, len: usize) {
    RX_DISPATCHER.fetch_add(1, Ordering::Relaxed);
    receive_action_parts(header, payload, len);
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
    if header.is_null() || payload.is_null() || len > FRAME_CAPACITY - 24 {
        RX_DROPS.fetch_add(1, Ordering::Relaxed);
        return;
    }
    if ACTION_PARSE_BUSY.swap(true, Ordering::AcqRel) {
        RX_DROPS.fetch_add(1, Ordering::Relaxed);
        return;
    }
    let frame = unsafe { &mut *core::ptr::addr_of_mut!(ROC_FRAME) };
    let header = unsafe { core::slice::from_raw_parts(header, 24) };
    let payload = unsafe { core::slice::from_raw_parts(payload, len) };
    frame[..24].copy_from_slice(header);
    frame[24..24 + len].copy_from_slice(payload);
    RX_MANAGEMENT.fetch_add(1, Ordering::Relaxed);
    RX_ACTION_FRAMES.fetch_add(1, Ordering::Relaxed);
    receive_action_frame_unlocked(&frame[..24 + len]);
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
    let output = unsafe { &mut *core::ptr::addr_of_mut!(RX_PAYLOAD) };
    let Some((source, used)) = dmesh_rawnan::espnow::parse_action_frame_into(frame, output) else {
        RX_PARSE_DROPS.fetch_add(1, Ordering::Relaxed);
        return;
    };
    // ESP-IDF exposes a locally transmitted action to the private receive
    // dispatcher on C6. It is not ingress and must not consume one of the
    // device-wide packet slots or be confused with the peer's reply.
    if crate::wifi_radio_control_esp::is_local_action_source(source) {
        RX_SELF_ECHOES.fetch_add(1, Ordering::Relaxed);
        return;
    }
    if recently_seen_action(source, &output[..used]) {
        RX_DUPLICATE_ACTIONS.fetch_add(1, Ordering::Relaxed);
        return;
    }
    if !crate::wifi_esp::enqueue_now_payload(source, &output[..used]) {
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

/// Drive the bounded discovery retry for the one active raw-service client.
/// This owns no transport queue: it regenerates the fixed bootstrap OPEN in
/// the shared response scratch buffer until the first server acknowledgement.
/// Queue the due client turn on the shared worker. Main calls this only after
/// its one-shot deadline fires; it never services a bearer or accesses client
/// memory itself.
pub fn schedule_raw_client_timer() {
    let _ = crate::shared_ingress_esp::schedule_espnow_client_timer(poll_raw_client);
}

/// Run one due NOW-client turn from the shared ingress worker. RX handling,
/// client-state mutation, response encoding, and enqueueing action egress all
/// therefore have one owner; no timer callback or Main task races `RESPONSE`.
fn poll_raw_client() {
    if !RAW_CLIENT_ACTIVE.load(Ordering::Acquire) {
        return;
    }
    unsafe {
        let state = &mut *core::ptr::addr_of_mut!(RAW_CLIENT).cast::<RawClientState>();
        let now = esp_idf_sys::esp_timer_get_time();
        if state.client.is_complete() {
            // This path is reached only by Main's one-shot deadline event
            // after the final application response. It deliberately emits
            // CLOSE only: no retransmit, bootstrap, or new stream data can
            // run after completion.
            if state.close_drain_until_us == 0 || now >= state.close_drain_until_us {
                finish_raw_client();
                return;
            }
            if now >= state.next_close_retry_us {
                let response = &mut *core::ptr::addr_of_mut!(RESPONSE);
                if let Ok(Some(used)) = state.client.poll_close(response) {
                    if !transmit_client_from_worker(state.peer, &response[..used]) {
                        TX_FAILURES.fetch_add(1, Ordering::Relaxed);
                    }
                }
                state.next_close_retry_us = now.saturating_add(RAW_CLIENT_CLOSE_RETRY_US);
            }
            publish_current_raw_client_deadline();
            return;
        }
        if now >= state.deadline_us {
            RAW_CLIENT_ERRORS.fetch_add(1, Ordering::Relaxed);
            crate::commands::send_stat(
                b"espnow client timeout_us=",
                ((state.deadline_us - state.started_at_us).max(0)) as u64,
            );
            finish_raw_client();
            return;
        }
        if state.client.server_cid().is_some() {
            let response = &mut *core::ptr::addr_of_mut!(RESPONSE);
            // This is the normal delayed-ACK/control poll. It must run before
            // PTO so the peer receives timely QUIC-lite ACK ranges and credit
            // updates; the association, not this bearer, decides flight size.
            if let Ok(Some(used)) =
                state
                    .client
                    .poll((now.max(0) as u64) / 1_000, now as u64, response)
            {
                let _ = transmit_client_from_worker(state.peer, &response[..used]);
                publish_current_raw_client_deadline();
                return;
            }
            publish_current_raw_client_deadline();
            return;
        }
        if now < state.next_bootstrap_retry_us {
            publish_current_raw_client_deadline();
            return;
        }
        let response = &mut *core::ptr::addr_of_mut!(RESPONSE);
        match state.client.retry_bootstrap(response) {
            Ok(used) if transmit_client_from_worker(state.peer, &response[..used]) => {
                state.next_bootstrap_retry_us = now + 400_000;
            }
            Ok(_) => {
                state.next_bootstrap_retry_us = now + 400_000;
            }
            Err(_) => {}
        }
    }
    // All nonterminal paths have either sent an endpoint-controlled packet or
    // observed that no ACK/PTO is due yet. Re-arm Main from the worker-owned
    // state so it can block until the next exact client deadline.
    publish_current_raw_client_deadline();
}

pub(crate) fn dispatch_ingress(item: crate::shared_ingress_esp::IngressPacket, payload: &[u8]) {
    unsafe {
        if RAW_CLIENT_ACTIVE.load(Ordering::Acquire) {
            let state = &mut *core::ptr::addr_of_mut!(RAW_CLIENT).cast::<RawClientState>();
            if state.peer.mac == item.source() && state.client.accepts(payload) {
                let response = &mut *core::ptr::addr_of_mut!(RESPONSE);
                let outbound = match state.client.receive(
                    payload,
                    (esp_idf_sys::esp_timer_get_time().max(0) as u64) / 1_000,
                    response,
                ) {
                    Ok(Some(used)) if used <= response.len() => {
                        CLIENT_RECEIVE_OK.fetch_add(1, Ordering::Relaxed);
                        Some(used)
                    }
                    Ok(_) => {
                        CLIENT_RECEIVE_OK.fetch_add(1, Ordering::Relaxed);
                        None
                    }
                    Err(error) => {
                        CLIENT_LAST_ERROR.store(
                            u32::from(dmesh_server::raw_transport::receive_error_code(error)),
                            Ordering::Relaxed,
                        );
                        CLIENT_RECEIVE_ERRORS.fetch_add(1, Ordering::Relaxed);
                        TX_FAILURES.fetch_add(1, Ordering::Relaxed);
                        None
                    }
                };
                let counters = state.client.counters();
                CLIENT_BOOTSTRAP_ACKS.store(counters.bootstrap_acks, Ordering::Relaxed);
                CLIENT_STREAM_PACKETS.store(counters.stream_packets, Ordering::Relaxed);
                CLIENT_OTHER_PACKETS.store(counters.other_packets, Ordering::Relaxed);
                // Keep a live progress value as well as the final result.
                // Sparse action receive can take longer than a diagnostic
                // deadline; reporting only on FIN made a transfer with real
                // stream progress indistinguishable from a zero-byte one.
                RAW_CLIENT_BYTES.store(
                    state.client.bytes().min(u64::from(u32::MAX)) as u32,
                    Ordering::Release,
                );
                if state.client.is_complete() {
                    let bytes = state.client.bytes();
                    let errors = state.client.errors();
                    let elapsed_us =
                        (esp_idf_sys::esp_timer_get_time() - state.started_at_us).max(1) as u64;
                    RAW_CLIENT_BYTES
                        .store(bytes.min(u64::from(u32::MAX)) as u32, Ordering::Release);
                    RAW_CLIENT_ERRORS
                        .store(errors.min(u64::from(u32::MAX)) as u32, Ordering::Release);
                    RAW_CLIENT_ELAPSED_US.store(
                        elapsed_us.min(u64::from(u32::MAX)) as u32,
                        Ordering::Release,
                    );
                    crate::commands::send_stat(
                        b"espnow client bps=",
                        bytes.saturating_mul(8_000_000) / elapsed_us,
                    );
                    crate::commands::send_stat(b"espnow client elapsed_us=", elapsed_us);
                    crate::commands::send_stat(b"espnow client bytes=", bytes);
                    crate::commands::send_stat(b"espnow client errors=", errors);
                    // Keep only a CLOSE-only drain after the final ACK. The
                    // common ingress worker may see an old server packet
                    // during this bounded window, but the completed client
                    // accepts it solely to re-emit CLOSE; it cannot restart
                    // the service or consume a new packet allocation.
                    let now = esp_idf_sys::esp_timer_get_time();
                    state.close_drain_until_us = now.saturating_add(RAW_CLIENT_CLOSE_DRAIN_US);
                    state.next_close_retry_us = now.saturating_add(RAW_CLIENT_CLOSE_RETRY_US);
                }
                if let Some(used) = outbound {
                    // OPEN is safe to repeat because the server replies with
                    // the same stateless acknowledgement.  A service request
                    // is not: each duplicate reaches the live IPERF sender
                    // and can advance its one-packet response window before
                    // the client has received the first packet.  Send it once
                    // here; the endpoint-owned PTO below retransmits the
                    // exact request if the action is lost.
                    if !transmit_client_from_worker(state.peer, &response[..used]) {
                        TX_FAILURES.fetch_add(1, Ordering::Relaxed);
                    }
                }
                if let Some(server_cid) = state.client.server_cid() {
                    CLIENT_EXPECTED_SERVER_CID.store(server_cid.value() as u32, Ordering::Release);
                }
                if RAW_CLIENT_ACTIVE.load(Ordering::Acquire) {
                    schedule_raw_client_service();
                }
                return;
            }
            if state.peer.mac == item.source() {
                // The same physical peer can concurrently address this
                // board's shared server while our older one-shot client is
                // still draining CLOSE. Route a packet for that server CID
                // through the normal common dispatcher; source-MAC-only
                // filtering here previously dropped the server's ACK and
                // left a multi-frame stream retransmitting its first frame.
                if crate::core_runtime::raw_service_owns_espnow_packet(
                    EspNowPeer { mac: item.source() },
                    payload,
                ) {
                    // Fall through to the normal handler/poller below. It
                    // remains the only owner of shared service state and the
                    // common packet pool.
                } else {
                    // This is deliberately scalar USB-visible evidence rather
                    // than a retained packet trace. A peer action reached this
                    // client while it was active, but its QUIC-lite receive CID
                    // did not select the client or shared server.
                    if let Ok((header, _)) = quic_lite::ShortHeader::decode(payload) {
                        CLIENT_OTHER_PACKETS.fetch_add(1, Ordering::Relaxed);
                        CLIENT_LAST_OTHER_DCID.store(header.dcid.value() as u32, Ordering::Release);
                        crate::commands::send_stat(b"espnow unexpected_dcid=", header.dcid.value());
                    }
                    // It is a delayed association or unrelated service. The
                    // one-entry shared dispatcher must not let it disturb the
                    // active client or server state.
                    return;
                }
            }
            if state.peer.mac != item.source() {
                CLIENT_PEER_MISMATCHES.fetch_add(1, Ordering::Relaxed);
                let source = item.source();
                CLIENT_LAST_OTHER_PEER_SUFFIX.store(
                    (u32::from(source[3]) << 16)
                        | (u32::from(source[4]) << 8)
                        | u32::from(source[5]),
                    Ordering::Release,
                );
                // Surface an unexpected sender through the same bounded
                // snapshot bucket as an unexpected DCID. A client accepts
                // only its explicitly selected peer; forwarding this packet
                // to the generic raw server would let unrelated broadcast
                // traffic steal the live association.
                CLIENT_OTHER_PACKETS.fetch_add(1, Ordering::Relaxed);
                // Presence records return before the client branch. A
                // foreign QUIC packet cannot advance this active client and
                // must not replace the selected peer in the current
                // one-association dispatcher. A future connection table can
                // route it independently by DCID.
                return;
            }
        }
    }
    let handler = HANDLER.load(Ordering::Acquire);
    if handler == 0 {
        return;
    }
    let handler: EspNowHandler = unsafe { core::mem::transmute(handler) };
    let response = unsafe { &mut *core::ptr::addr_of_mut!(RESPONSE) };
    // A valid QUIC-lite ACK normally has no immediate reply.  It can still
    // release a queued stream packet, so always reach the connection-owned
    // poller after handling ingress. Returning here used to stall the service
    // after its first ACK on packet-at-a-time bearers.
    let peer = EspNowPeer { mac: item.source() };
    let immediate = handler(peer, payload, response);
    let poll = POLL_HANDLER.load(Ordering::Acquire);
    let poll: Option<EspNowPollHandler> =
        (poll != 0).then(|| unsafe { core::mem::transmute(poll) });
    let result = dmesh_server::raw_transport::pump_egress(
        response,
        TX_BURST_PACKETS.load(Ordering::Acquire),
        immediate,
        |response| poll.and_then(|poll| poll(peer, response)),
        |packet| transmit_from_worker(peer, packet),
    );
    if result.invalid_length || result.submit_failed {
        TX_FAILURES.fetch_add(1, Ordering::Relaxed);
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
/// RX dispatch, client deadlines, server timers, and raw-service replies all
/// run on that one worker, so submitting here retains the single radio owner
/// while avoiding an extra queue turn inside the short C6 action reply window.
/// Callers outside that worker must use [`transmit`].
pub(crate) fn transmit_from_worker(peer: EspNowPeer, payload: &[u8]) -> bool {
    transmit_submitted(peer, payload, NOW_ACTION_TX_SERVER_WAIT_MS)
}

/// Submit a packet produced by the currently active raw-service client.
///
/// Only the client uses the longer response window because its initiating
/// action is the one C6 uses to surface the server reply through the in-band
/// callback. This still runs on the shared worker and uses the shared packet
/// pool; it is a bounded driver transaction, not a client-specific queue.
fn transmit_client_from_worker(peer: EspNowPeer, payload: &[u8]) -> bool {
    transmit_submitted(peer, payload, NOW_ACTION_TX_CLIENT_WAIT_MS)
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
    let frame = unsafe { &mut *core::ptr::addr_of_mut!(TX_FRAME) };
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
        let request = &mut *core::ptr::addr_of_mut!(ACTION_TX_REQUEST).cast::<ActionTxRequest>();
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
/// This is the action-bearer counterpart of the direct UART boot record: it
/// deliberately carries the same CBOR bytes and does not create a QUIC-lite
/// client or retain a peer-specific egress queue.
pub fn broadcast_record(record: &[u8]) -> bool {
    transmit(EspNowPeer { mac: [0xff; 6] }, record)
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
    let sent = unsafe {
        let request = &mut *core::ptr::addr_of_mut!(ACTION_TX_REQUEST).cast::<ActionTxRequest>();
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
        // Public actions include both directed NAN requests and multicast
        // announcements.  Only the former can use a MAC acknowledgement.
        request.request.no_ack = destination == [0xff; 6] || !mac_ack_enabled();
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
