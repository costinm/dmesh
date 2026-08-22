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

use core::mem::MaybeUninit;
use core::{
    ffi::c_void,
    sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicUsize, Ordering},
};

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
/// even a successful transfer at a few kbit/s; retain a short driver request
/// window solely for the action transaction itself.
const ACTION_TX_WAIT_MS: u32 = 10;
static HANDLER: AtomicUsize = AtomicUsize::new(0);
static POLL_HANDLER: AtomicUsize = AtomicUsize::new(0);
static TX_BURST_PACKETS: AtomicUsize = AtomicUsize::new(4);
static MAC_ACK_ENABLED: AtomicBool = AtomicBool::new(false);
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
}
struct RawClientState {
    peer: EspNowPeer,
    client: RawServiceClient,
    started_at_us: i64,
    next_bootstrap_retry_us: i64,
    deadline_us: i64,
}

impl RawServiceClient {
    fn server_cid(&self) -> Option<quic_lite::ConnectionId> {
        let Self::Check(client) = self;
        client.server_cid()
    }
    fn retry_bootstrap(
        &self,
        out: &mut [u8; quic_lite::DEFAULT_MAX_DATAGRAM_SIZE],
    ) -> Result<usize, quic_lite::Error> {
        let Self::Check(client) = self;
        client.retry_bootstrap(out)
    }
    fn receive(
        &mut self,
        packet: &[u8],
        now_ms: u64,
        out: &mut [u8; quic_lite::DEFAULT_MAX_DATAGRAM_SIZE],
    ) -> Result<Option<usize>, quic_lite::Error> {
        let Self::Check(client) = self;
        let _ = now_ms;
        client.receive(packet, out)
    }
    fn accepts(&self, packet: &[u8]) -> bool {
        let Self::Check(client) = self;
        client.accepts(packet)
    }
    fn poll(
        &mut self,
        now_ms: u64,
        now_us: u64,
        out: &mut [u8; quic_lite::DEFAULT_MAX_DATAGRAM_SIZE],
    ) -> Result<Option<usize>, quic_lite::Error> {
        let Self::Check(client) = self;
        let _ = now_ms;
        match client.poll_transmit(out) {
            Ok(Some(packet)) => Ok(Some(packet)),
            Ok(None) => client.poll_retransmit(now_us, 600_000, out),
            Err(error) => Err(error),
        }
    }
    fn counters(&self) -> dmesh_server::raw_transport::RawServiceCounters {
        let Self::Check(client) = self;
        client.counters()
    }
    fn is_complete(&self) -> bool {
        let Self::Check(client) = self;
        client.is_complete()
    }
    fn bytes(&self) -> u64 {
        let Self::Check(client) = self;
        client.bytes()
    }
    fn errors(&self) -> u64 {
        0
    }
}
static RAW_CLIENT_ACTIVE: AtomicBool = AtomicBool::new(false);
/// Monotonic generation for bounded status-check associations.
static RAW_CLIENT_GENERATION: AtomicU32 = AtomicU32::new(0);
static RAW_CLIENT_BYTES: AtomicU32 = AtomicU32::new(0);
static RAW_CLIENT_ERRORS: AtomicU32 = AtomicU32::new(0);
static RAW_CLIENT_ELAPSED_US: AtomicU32 = AtomicU32::new(0);
static mut RAW_CLIENT: MaybeUninit<RawClientState> = MaybeUninit::uninit();

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

/// Bind decoded public-vendor actions to the common QUIC-lite action handler.
/// Wi-Fi owns callback registration and starts/stops the shared packet pool;
/// this function never changes a driver callback or buffer lifecycle.
pub fn install_action_ingress(local_mac: [u8; 6], handler: EspNowHandler) -> bool {
    HANDLER.store(handler as usize, Ordering::Release);
    unsafe {
        LOCAL_MAC = local_mac;
    }
    STARTED.store(true, Ordering::Release);
    true
}

/// Make NOW framing/dispatch inert. ESP-IDF callback registration and shared
/// ingress-pool stop remain with `wifi_esp`, the sole Wi-Fi owner.
pub fn stop_action_ingress() {
    // `transport.start` replaces a complete Wi-Fi epoch. A bounded NOW
    // client from the previous epoch cannot remain eligible for polling or
    // prevent the next epoch from starting its own check client. The state
    // occupies only static storage; clearing this ownership bit is sufficient
    // and avoids carrying a packet or driver buffer across the replacement.
    RAW_CLIENT_ACTIVE.store(false, Ordering::Release);
    HANDLER.store(0, Ordering::Release);
    STARTED.store(false, Ordering::Release);
}

/// Start one bounded `SERVICE_ECHO` check over the NOW-like bearer. This
/// shares the same packet slot, timeout, receive callback, and counters as
/// a normal stream service; only the `dmesh-server` client differs.
pub fn start_check_client(peer: EspNowPeer, nonce: u64, timeout_ms: u32) -> bool {
    // An unassociated STA has no infrastructure BSSID context for the
    // private action dispatcher. Request a bounded same-channel ROC receive
    // lease with `allow_broadcast`; it does not enable promiscuous mode or
    // retune the radio because this lab keeps all peers on channel six.
    // Associated and APSTA checks use the continuous callback alone.
    if crate::wifi_esp::lab_force_unassociated()
        && !crate::wifi_nonpromisc_probe_esp::listen_on_current_channel(timeout_ms)
    {
        return false;
    }
    if RAW_CLIENT_ACTIVE.swap(true, Ordering::AcqRel) {
        return false;
    }
    let generation = RAW_CLIENT_GENERATION
        .fetch_add(1, Ordering::AcqRel)
        .wrapping_add(1);
    let cid = quic_lite::ConnectionId::new(0x4553_0000 | u64::from(generation.max(1)))
        .expect("nonzero NOW CID");
    let mut client = dmesh_server::raw_transport::RawCheckClient::new(cid, nonce);
    let used = unsafe {
        let response = &mut *core::ptr::addr_of_mut!(RESPONSE);
        match client.start(response) {
            Ok(used) => used,
            Err(_) => {
                RAW_CLIENT_ACTIVE.store(false, Ordering::Release);
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
                + i64::from(timeout_ms.clamp(1_000, 60_000)) * 1_000,
        }));
        let response = &*core::ptr::addr_of!(RESPONSE);
        if !transmit(peer, &response[..used]) {
            RAW_CLIENT_ACTIVE.store(false, Ordering::Release);
            return false;
        }
    }
    true
}

/// Receive one action from the private non-promiscuous driver dispatcher.
/// The callback supplies a 24-byte 802.11 header separately from the action
/// body. Reconstitute only enough frame storage for the host-tested rawnan
/// parser, then make the single shared-ingress copy. No allocation,
/// promiscuous mode, or remain-on-channel operation is involved.
pub(crate) unsafe extern "C" fn action_rx_callback(
    _driver_context: *mut c_void,
    header: *mut u8,
    payload: *mut u8,
    payload_end: *mut u8,
) -> i32 {
    if !crate::wifi_esp::now_dispatcher_enabled() {
        return 0;
    }
    RX_DISPATCHER.fetch_add(1, Ordering::Relaxed);
    let Some(len) = (payload_end as usize).checked_sub(payload as usize) else {
        RX_DROPS.fetch_add(1, Ordering::Relaxed);
        return 0;
    };
    receive_action_parts(header, payload, len);
    0
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
    let frame = unsafe { &mut *core::ptr::addr_of_mut!(ROC_FRAME) };
    let header = unsafe { core::slice::from_raw_parts(header, 24) };
    let payload = unsafe { core::slice::from_raw_parts(payload, len) };
    frame[..24].copy_from_slice(header);
    frame[24..24 + len].copy_from_slice(payload);
    RX_MANAGEMENT.fetch_add(1, Ordering::Relaxed);
    RX_ACTION_FRAMES.fetch_add(1, Ordering::Relaxed);
    receive_action_frame(&frame[..24 + len]);
}

/// Feed an action supplied by ESP-IDF's bounded ROC receiver into the exact
/// parser and shared ingress queue used by the private `(127,0)` hook. ROC
/// owns only a receive lease; it is not a second bearer or packet queue.
pub(crate) fn receive_roc_action_parts(header: *mut u8, payload: *mut u8, len: usize) {
    receive_action_parts(header, payload, len);
}

/// Feed a complete management frame seen during a bounded NAN discovery
/// capture. The caller controls promiscuous lifetime; this helper only admits
/// an ESP-NOW-compatible action into the same shared packet pool as the
/// private dispatcher. It is deliberately not a continuous monitor path.
pub fn receive_promiscuous_action(frame: &[u8]) {
    if !dmesh_rawnan::is_action_frame(frame) {
        return;
    }
    RX_MANAGEMENT.fetch_add(1, Ordering::Relaxed);
    RX_ACTION_FRAMES.fetch_add(1, Ordering::Relaxed);
    receive_action_frame(frame);
}

fn receive_action_frame(frame: &[u8]) {
    let output = unsafe { &mut *core::ptr::addr_of_mut!(RX_PAYLOAD) };
    let Some((source, used)) = dmesh_rawnan::espnow::parse_action_frame_into(frame, output) else {
        RX_PARSE_DROPS.fetch_add(1, Ordering::Relaxed);
        return;
    };
    // ESP-IDF exposes a locally transmitted action to the private receive
    // dispatcher on C6. It is not ingress and must not consume one of the
    // device-wide packet slots or be confused with the peer's reply.
    if crate::wifi_radio_lab_esp::is_local_action_source(source) {
        RX_SELF_ECHOES.fetch_add(1, Ordering::Relaxed);
        return;
    }
    if !crate::wifi_esp::enqueue_now_payload(source, &output[..used]) {
        RX_DROPS.fetch_add(1, Ordering::Relaxed);
    } else {
        RX_ACTIONS.fetch_add(1, Ordering::Relaxed);
    }
}

/// Drive the bounded discovery retry for the one active raw-service client.
/// This owns no transport queue: it regenerates the fixed bootstrap OPEN in
/// the shared response scratch buffer until the first server acknowledgement.
pub fn poll_raw_client() {
    if !RAW_CLIENT_ACTIVE.load(Ordering::Acquire) {
        return;
    }
    unsafe {
        let state = &mut *core::ptr::addr_of_mut!(RAW_CLIENT).cast::<RawClientState>();
        let now = esp_idf_sys::esp_timer_get_time();
        if now >= state.deadline_us {
            RAW_CLIENT_ERRORS.fetch_add(1, Ordering::Relaxed);
            crate::commands::send_stat(
                b"espnow client timeout_us=",
                ((state.deadline_us - state.started_at_us).max(0)) as u64,
            );
            RAW_CLIENT_ACTIVE.store(false, Ordering::Release);
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
                let _ = transmit(state.peer, &response[..used]);
                return;
            }
            return;
        }
        if now < state.next_bootstrap_retry_us {
            return;
        }
        let response = &mut *core::ptr::addr_of_mut!(RESPONSE);
        match state.client.retry_bootstrap(response) {
            Ok(used) if transmit(state.peer, &response[..used]) => {
                state.next_bootstrap_retry_us = now + 400_000;
            }
            Ok(_) => {
                state.next_bootstrap_retry_us = now + 400_000;
            }
            Err(_) => {}
        }
    }
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
                    // `esp_wifi_action_tx_req` may synchronously invoke the
                    // receive callback. Retire this client before sending its
                    // final ACK, so a reentrant server control/retransmission
                    // cannot be decoded by an already-complete client.
                    RAW_CLIENT_ACTIVE.store(false, Ordering::Release);
                }
                if let Some(used) = outbound {
                    if !transmit(state.peer, &response[..used]) {
                        TX_FAILURES.fetch_add(1, Ordering::Relaxed);
                    }
                }
                return;
            }
            if state.peer.mac != item.source() {
                CLIENT_PEER_MISMATCHES.fetch_add(1, Ordering::Relaxed);
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
        |packet| transmit(peer, packet),
    );
    if result.invalid_length || result.submit_failed {
        TX_FAILURES.fetch_add(1, Ordering::Relaxed);
    }
}

/// Send one complete QUIC-lite datagram through the same driver action lane
/// used by the shared Recovery/Main bearer. Main-local raw 802.11 injection
/// remains available for explicit radio experiments, but must not be used by
/// the bearer: it bypasses this driver's action receive/reply integration.
pub fn transmit(peer: EspNowPeer, payload: &[u8]) -> bool {
    // Normal NOW-like traffic is deliberately independent of NAN discovery
    // windows.  The common NAN policy enables promiscuous *receive* only for
    // the bounded DW capture; constraining data TX to that window both
    // destroys throughput and makes it depend on two devices' observation
    // phase.  A long transfer therefore runs with promiscuous disabled apart
    // from the 64 ms capture in each 512-TU DW, which is exactly the intended
    // coexistence test.
    let local = crate::wifi_radio_lab_esp::action_tx_mac().unwrap_or_else(|| unsafe { LOCAL_MAC });
    let destination = if crate::wifi_radio_lab_esp::action_destination_broadcast() {
        [0xff; 6]
    } else {
        peer.mac
    };
    let frame = unsafe { &mut *core::ptr::addr_of_mut!(TX_FRAME) };
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
    let interface = match crate::wifi_radio_lab_esp::action_tx_interface() {
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
        request.request.wait_time_ms = ACTION_TX_WAIT_MS;
        // Keep connectionless action TX independent of link-layer ACK/retry
        // pacing. QUIC-lite owns the larger end-to-end window, loss recovery,
        // and congestion policy; ESP-IDF exposes no useful ACK telemetry here.
        request.request.no_ack = !mac_ack_enabled();
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
        request.request.wait_time_ms = ACTION_TX_WAIT_MS;
        request.request.no_ack = !mac_ack_enabled();
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
