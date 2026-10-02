//! Firmware QUIC owner and ESP packet-bearer registration.
//!
//! UART receives its pool and ingress handle only through `BearerContext`.
//! QUIC output returns through the registered `PacketEgress` implementation;
//! neither direction calls private node packet APIs.

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use quic_lite::{
    BearerContext, BearerInfo, BearerName, EgressSubmission, OwnedPacket, PacketBearer,
    PacketEgress, PacketMeta, PacketPool as _, PacketSendOutcome, PacketSubmitError, PacketWriter,
    PeerL2Address, QuicAssociation, QuicNodeEgressError, QuicStream,
    nostd::NoStdRuntime,
    packet_pool::{PacketPool, PoolBufferLease},
};

const PACKETS: usize = 8;
const SLOT_SIZE: usize = quic_lite::DEFAULT_PACKET_POOL_SLOT_SIZE;

pub(crate) type FirmwarePool = PacketPool<PACKETS, SLOT_SIZE>;
pub(crate) type FirmwarePacket = OwnedPacket<PoolBufferLease<'static, PACKETS, SLOT_SIZE>>;
// Every local association owns one receive CID in the node's shared DCID
// registry. Firmware does not currently reserve additional entries for relay
// forwarding, but a zero-entry registry would reject the first association.
type FirmwareRuntime = NoStdRuntime<FirmwarePool>;

static POOL: FirmwarePool = FirmwarePool::new();
static UART_READY: AtomicBool = AtomicBool::new(false);
static UDP6_READY: AtomicBool = AtomicBool::new(false);
static NOW_READY: AtomicBool = AtomicBool::new(false);
static INGRESS_ERROR_REPORTED: AtomicBool = AtomicBool::new(false);
static UDP6_INGRESS_REPORTED: AtomicUsize = AtomicUsize::new(0);
static UDP6_EGRESS_REPORTED: AtomicUsize = AtomicUsize::new(0);
static mut UART_CONTEXT: core::mem::MaybeUninit<BearerContext<FirmwarePool>> =
    core::mem::MaybeUninit::uninit();
static mut UDP6_CONTEXT: core::mem::MaybeUninit<BearerContext<FirmwarePool>> =
    core::mem::MaybeUninit::uninit();
static mut NOW_CONTEXT: core::mem::MaybeUninit<BearerContext<FirmwarePool>> =
    core::mem::MaybeUninit::uninit();
static READY: AtomicBool = AtomicBool::new(false);
// The node contains association and stream state. Keeping it in a static
// `MaybeUninit` reserves the complete value in `.bss`, which does not fit
// classic ESP32 internal DRAM. Allocate it once after ESP-IDF has
// initialized the heap; the leaked box remains the device-wide owner.
static mut RUNTIME: *mut FirmwareRuntime = core::ptr::null_mut();
// A device-originated probe (`probe.start`): this node is the QUIC client of a
// peer's `probe.handler` handler. The job is owned by Main's single QUIC owner.
struct PendingPeerProbe {
    id: u64,
    request: dmesh_server::probe::ProbeServiceRequest,
    started_at_us: u64,
    /// The job's time limit: the caller's `timeout`, else a size-based default.
    timeout_us: u64,
    association: Option<QuicAssociation>,
    stream: Option<QuicStream>,
    request_wire: [u8; dmesh_server::probe::PROBE_REQUEST_MAX],
    request_len: usize,
    request_offset: usize,
    reader: dmesh_server::probe::ProbeResponseReader,
}
static mut PENDING_PEER_PROBE: Option<PendingPeerProbe> = None;
// The finished job's `probe.start` response header, taken by the deferred
// response of the registered handler.
static mut PEER_PROBE_RESULT: Option<Vec<u8>> = None;
const WRITE_CHUNK: usize = quic_lite::DEFAULT_MAX_STREAM_PAYLOAD;
/// Inbound handler streams held at once (each holds a request header buffer
/// and, for a body method, its sink).
const MAX_HANDLER_STREAMS: usize = 4;
/// A handler stream with no application progress for this long is abandoned.
const HANDLER_STREAM_IDLE_MS: u64 = 15_000;

/// Connectionless responses retain node-pool leases while crossing from the
/// Wi-Fi callback to Main's event owner. The generic QUIC-owned queue stores
/// only metadata and packet handles, not a second payload buffer.
static PENDING_NOW_CONTROL_TX: quic_lite::packet_pool::PacketLeaseQueue<
    [u8; 6],
    PoolBufferLease<'static, PACKETS, SLOT_SIZE>,
    PACKETS,
> = quic_lite::packet_pool::PacketLeaseQueue::new();

pub(crate) enum NowReceiveError {
    NotReady,
    PoolFull,
    InvalidFrame,
    InvalidPeer,
    CommitFailed,
}

/// Copy one generated non-QUIC response into the shared node pool and defer
/// radio submission to Main's serialized owner. It never enters QUIC parsing.
pub(crate) fn queue_now_control_response(
    peer: crate::wifi_espnow_esp::EspNowPeer,
    payload: &[u8],
) -> bool {
    if !NOW_READY.load(Ordering::Acquire) || payload.is_empty() {
        return false;
    }
    let context = unsafe {
        (&*core::ptr::addr_of!(NOW_CONTEXT).cast::<BearerContext<FirmwarePool>>()).clone()
    };
    let Some(mut writer) = context.pool().acquire_writer(0, 0) else {
        return false;
    };
    if payload.len() > writer.payload_mut().len() {
        return false;
    }
    writer.payload_mut()[..payload.len()].copy_from_slice(payload);
    let Some(packet) = writer.commit(payload.len()) else {
        return false;
    };
    if let Err((_peer, packet)) = PENDING_NOW_CONTROL_TX.try_push(peer.mac, packet) {
        drop(packet);
        return false;
    }
    if crate::wifi_espnow_esp::now_tx_retry_delay_ms().is_none() {
        crate::main_runtime::request_quic_ingress();
    }
    true
}

pub(crate) fn take_pending_now_control_response()
-> Option<(crate::wifi_espnow_esp::EspNowPeer, FirmwarePacket)> {
    PENDING_NOW_CONTROL_TX
        .try_pop()
        .map(|(peer, packet)| (crate::wifi_espnow_esp::EspNowPeer { mac: peer }, packet))
}

/// Return an unsubmitted control/discovery packet to the same shared pool
/// lease queue after transient ESP-IDF send pressure.
pub(crate) fn requeue_pending_now_control_response(
    peer: crate::wifi_espnow_esp::EspNowPeer,
    packet: FirmwarePacket,
) -> bool {
    if let Err((_peer, packet)) = PENDING_NOW_CONTROL_TX.try_push(peer.mac, packet) {
        drop(packet);
        return false;
    }
    true
}

pub(crate) fn now_control_response_pending() -> Option<bool> {
    PENDING_NOW_CONTROL_TX.try_is_empty().map(|empty| !empty)
}

struct UartBearer;

impl PacketEgress<<FirmwarePool as quic_lite::PacketPool>::Buffer> for UartBearer {
    fn submit(
        &mut self,
        peer: PeerL2Address,
        submission: EgressSubmission<<FirmwarePool as quic_lite::PacketPool>::Buffer>,
    ) -> Result<(), PacketSubmitError<<FirmwarePool as quic_lite::PacketPool>::Buffer>> {
        // The physical bearer retains this pool lease until every framed byte
        // has been accepted by the UART driver. Do not copy into the legacy
        // raw-packet queue or report completion at queue admission: completion
        // is the edge that returns the node-owned packet to its pool and lets
        // QUIC submit the next pending packet.
        crate::uart_esp::EspUartBearer.submit(peer, submission)
    }
}

impl PacketBearer<FirmwarePool> for UartBearer {
    type AttachError = ();

    fn info(&self) -> BearerInfo {
        BearerInfo {
            name: BearerName::new("uart0").expect("static bearer name is valid"),
            max_packet_size: quic_lite::DEFAULT_MAX_PACKET_SIZE,
            prefix_required: quic_lite::PACKET_PREFIX_RESERVE,
            suffix_required: quic_lite::PACKET_SUFFIX_RESERVE,
            requires_packet_encryption: false,
            secure_link: true,
            nominal_bitrate_bps: 115_200,
            local_mac: None,
        }
    }

    fn attach(&mut self, context: BearerContext<FirmwarePool>) -> Result<(), Self::AttachError> {
        unsafe {
            core::ptr::addr_of_mut!(UART_CONTEXT).write(core::mem::MaybeUninit::new(context));
        }
        UART_READY.store(true, Ordering::Release);
        Ok(())
    }
}

struct Udp6Bearer;

impl PacketEgress<<FirmwarePool as quic_lite::PacketPool>::Buffer> for Udp6Bearer {
    fn submit(
        &mut self,
        peer: PeerL2Address,
        submission: EgressSubmission<<FirmwarePool as quic_lite::PacketPool>::Buffer>,
    ) -> Result<(), PacketSubmitError<<FirmwarePool as quic_lite::PacketPool>::Buffer>> {
        let sent = crate::wifi_raw_udp6_esp::peer_for_path(peer).is_some_and(|endpoint| {
            crate::wifi_raw_udp6_esp::transmit_udp6(
                endpoint.link,
                endpoint,
                crate::wifi_raw_udp6_esp::RAW_UDP6_PORT,
                submission.packet().bytes(),
            )
        });
        if UDP6_EGRESS_REPORTED.fetch_add(1, Ordering::AcqRel) < 4 {
            let _ = crate::uart_esp::send_debug_text(if sent {
                b"DMESH udp6 QUIC egress sent=true"
            } else {
                b"DMESH udp6 QUIC egress sent=false"
            });
        }
        submission.complete(
            if sent {
                PacketSendOutcome::Sent
            } else {
                PacketSendOutcome::Failed
            },
            0,
        );
        crate::main_runtime::request_quic_ingress();
        Ok(())
    }
}

impl PacketBearer<FirmwarePool> for Udp6Bearer {
    type AttachError = ();

    fn info(&self) -> BearerInfo {
        BearerInfo {
            name: BearerName::new("udp6").expect("static bearer name is valid"),
            max_packet_size: quic_lite::DEFAULT_MAX_PACKET_SIZE,
            prefix_required: 0,
            suffix_required: 0,
            requires_packet_encryption: false,
            secure_link: false,
            nominal_bitrate_bps: 1_000_000,
            local_mac: None,
        }
    }

    fn attach(&mut self, context: BearerContext<FirmwarePool>) -> Result<(), Self::AttachError> {
        unsafe {
            core::ptr::addr_of_mut!(UDP6_CONTEXT).write(core::mem::MaybeUninit::new(context));
        }
        UDP6_READY.store(true, Ordering::Release);
        Ok(())
    }
}

struct NowBearer;

impl PacketEgress<<FirmwarePool as quic_lite::PacketPool>::Buffer> for NowBearer {
    fn submit(
        &mut self,
        peer: PeerL2Address,
        submission: EgressSubmission<<FirmwarePool as quic_lite::PacketPool>::Buffer>,
    ) -> Result<(), PacketSubmitError<<FirmwarePool as quic_lite::PacketPool>::Buffer>> {
        let result = crate::wifi_espnow_esp::try_transmit_from_worker(
            crate::wifi_espnow_esp::EspNowPeer {
                mac: peer.value().to_be_bytes()[2..]
                    .try_into()
                    .expect("NOW peer handle contains six MAC bytes"),
            },
            submission.packet().bytes(),
        );
        match result {
            crate::wifi_espnow_esp::NowTransmitResult::Accepted => {
                submission.complete(PacketSendOutcome::Sent, 0);
                crate::main_runtime::request_quic_ingress();
                Ok(())
            }
            crate::wifi_espnow_esp::NowTransmitResult::Busy => {
                Err(PacketSubmitError::WouldBlock(submission))
            }
            crate::wifi_espnow_esp::NowTransmitResult::Failed => {
                submission.complete(PacketSendOutcome::Failed, 0);
                crate::main_runtime::request_quic_ingress();
                Ok(())
            }
        }
    }
}

impl PacketBearer<FirmwarePool> for NowBearer {
    type AttachError = ();

    fn info(&self) -> BearerInfo {
        BearerInfo {
            name: BearerName::new("espnow").expect("static bearer name is valid"),
            max_packet_size: quic_lite::DEFAULT_MAX_PACKET_SIZE,
            prefix_required: 0,
            suffix_required: 0,
            requires_packet_encryption: true,
            secure_link: false,
            nominal_bitrate_bps: 1_000_000,
            local_mac: None,
        }
    }

    fn attach(&mut self, context: BearerContext<FirmwarePool>) -> Result<(), Self::AttachError> {
        unsafe {
            core::ptr::addr_of_mut!(NOW_CONTEXT).write(core::mem::MaybeUninit::new(context));
        }
        NOW_READY.store(true, Ordering::Release);
        Ok(())
    }
}

unsafe fn runtime() -> &'static mut FirmwareRuntime {
    if !READY.load(Ordering::Acquire) {
        let embedded = quic_lite::AssociationLimits::embedded();
        let mut value = FirmwareRuntime::try_new_boxed(&POOL, embedded.connection)
            .expect("firmware QUIC runtime allocation succeeds");
        value
            .set_limits(quic_lite::NodeLimits::embedded())
            .expect("firmware QUIC node limits are valid");
        value
            .set_default_association_limits(embedded)
            .expect("firmware QUIC association limits are valid");
        value
            .add_bearer(UartBearer)
            .expect("static UART bearer registration succeeds");
        value
            .add_bearer(Udp6Bearer)
            .expect("static UDP6 bearer registration succeeds");
        value
            .add_bearer(NowBearer)
            .expect("static ESP-NOW bearer registration succeeds");
        core::ptr::addr_of_mut!(RUNTIME).write(Box::into_raw(value));
        READY.store(true, Ordering::Release);
    }
    &mut **core::ptr::addr_of_mut!(RUNTIME)
}

pub(crate) fn connection_delay_ms() -> Option<u32> {
    if !READY.load(Ordering::Acquire) {
        return None;
    }
    let now_us = unsafe { esp_idf_sys::esp_timer_get_time().max(0) as u64 };
    let runtime = unsafe { runtime() };
    let now_ms = now_us / 1_000;
    let transport_delay = runtime.next_deadline().map(|deadline| {
        deadline
            .saturating_sub(now_us)
            .div_ceil(1_000)
            .min(u64::from(u32::MAX)) as u32
    });
    let flash_delay = crate::flash::next_report_delay_ms(now_ms);
    let body_delay = body_poll_pending().then_some(BODY_POLL_MS);
    let delay_ms = transport_delay
        .into_iter()
        .chain(flash_delay)
        .chain(body_delay)
        .min()?;
    Some(delay_ms.max(1))
}

pub(crate) fn node_telemetry() -> quic_lite::NodeTelemetry {
    if !READY.load(Ordering::Acquire) {
        return quic_lite::NodeTelemetry::default();
    }
    unsafe { runtime() }.telemetry()
}

fn report_flash_progress(runtime: &FirmwareRuntime, now_ms: u64) {
    crate::flash::report_progress(now_ms, |association| {
        runtime.association_telemetry(association)
    });
}

pub(crate) fn schedule_connection_timer() {
    if !READY.load(Ordering::Acquire) {
        return;
    }
    let now_us = unsafe { esp_idf_sys::esp_timer_get_time().max(0) as u64 };
    let runtime = unsafe { runtime() };
    if runtime.advance_time(now_us).unwrap_or(false) {
        crate::main_runtime::request_quic_ingress();
    }
    sweep_handler_streams(now_us / 1_000);
    if body_poll_pending() {
        // Ask the ingress loop to poll the streaming bodies again.
        crate::main_runtime::request_quic_ingress();
    }
    report_flash_progress(runtime, now_us / 1_000);
    crate::main_runtime::request_connection_deadline_recheck();
}

/// Pool assigned to UART by its registered bearer context.
pub(crate) fn uart_pool() -> &'static FirmwarePool {
    unsafe {
        let _ = runtime();
    }
    assert!(UART_READY.load(Ordering::Acquire));
    unsafe { (&*core::ptr::addr_of!(UART_CONTEXT).cast::<BearerContext<FirmwarePool>>()).pool() }
}

/// Packet-pool capacity and currently free slots shared by all QUIC bearers.
/// Keep this read-only snapshot at the owner boundary so diagnostics observe
/// the actual QUIC pool rather than the retired callback-ingress shim.
pub(crate) fn packet_pool_snapshot() -> (u32, u32) {
    (
        u32::try_from(PACKETS).unwrap_or(u32::MAX),
        u32::try_from(POOL.available()).unwrap_or(u32::MAX),
    )
}

/// Transfer one UART-decoded packet through its bearer context.
///
/// The physical UART task stops here. QUIC parsing and application dispatch
/// run on the firmware owner task after the bearer's wake callback fires, so
/// neither the node nor handler working set is placed on the UART task stack.
pub(crate) fn receive_uart(packet: FirmwarePacket) {
    let context = {
        unsafe {
            let _ = runtime();
        }
        assert!(UART_READY.load(Ordering::Acquire));
        unsafe {
            (&*core::ptr::addr_of!(UART_CONTEXT).cast::<BearerContext<FirmwarePool>>()).clone()
        }
    };
    let meta = PacketMeta {
        bearer: context.bearer(),
        peer_l2_address: PeerL2Address::new(1).expect("UART peer handle is nonzero"),
        received_at_us: unsafe { esp_idf_sys::esp_timer_get_time().max(0) as u64 },
    };

    context.enqueue_packet(meta, packet);
}

/// Copy one complete raw UDP6 datagram into the node-owned packet pool and
/// enqueue it through the registered UDP6 bearer. Discovery remains on its
/// separate connectionless path.
pub(crate) fn receive_udp6(path: PeerL2Address, bytes: &[u8]) {
    if UDP6_INGRESS_REPORTED.fetch_add(1, Ordering::AcqRel) < 4 {
        let mut line = [0u8; 48];
        let prefix = b"DMESH udp6 QUIC ingress bytes=";
        line[..prefix.len()].copy_from_slice(prefix);
        let mut len = prefix.len();
        let mut digits = [0u8; 10];
        let mut used = 0;
        let mut value = bytes.len();
        loop {
            digits[used] = b'0' + (value % 10) as u8;
            used += 1;
            value /= 10;
            if value == 0 {
                break;
            }
        }
        for digit in digits[..used].iter().rev() {
            line[len] = *digit;
            len += 1;
        }
        let _ = crate::uart_esp::send_debug_text(&line[..len]);
    }
    let context = {
        unsafe {
            let _ = runtime();
        }
        assert!(UDP6_READY.load(Ordering::Acquire));
        unsafe {
            (&*core::ptr::addr_of!(UDP6_CONTEXT).cast::<BearerContext<FirmwarePool>>()).clone()
        }
    };
    let Some(mut writer) = context.pool().acquire_writer(0, 0) else {
        return;
    };
    let target = writer.payload_mut();
    if bytes.len() > target.len() {
        return;
    }
    target[..bytes.len()].copy_from_slice(bytes);
    let Some(packet) = writer.commit(bytes.len()) else {
        return;
    };
    let meta = PacketMeta {
        bearer: context.bearer(),
        peer_l2_address: path,
        received_at_us: unsafe { esp_idf_sys::esp_timer_get_time().max(0) as u64 },
    };
    context.enqueue_packet(meta, packet);
    crate::main_runtime::request_quic_ingress();
}

/// Admit one already-decoded NOW QUIC datagram through the registered bearer
/// context. The native action-frame path uses `receive_now_with` to parse
/// directly into this same pool; this entry point serves ingress adapters that
/// have already separated the action envelope from its payload.
pub(crate) fn receive_now_packet(peer: crate::wifi_espnow_esp::EspNowPeer, bytes: &[u8]) -> bool {
    if !NOW_READY.load(Ordering::Acquire) || bytes.is_empty() {
        return false;
    }
    let context = unsafe {
        (&*core::ptr::addr_of!(NOW_CONTEXT).cast::<BearerContext<FirmwarePool>>()).clone()
    };
    let Some(mut writer) = context.pool().acquire_writer(0, 0) else {
        return false;
    };
    let target = writer.payload_mut();
    if bytes.len() > target.len() {
        return false;
    }
    target[..bytes.len()].copy_from_slice(bytes);
    let Some(packet) = writer.commit(bytes.len()) else {
        return false;
    };
    let value = peer
        .mac
        .into_iter()
        .fold(0_u64, |value, octet| (value << 8) | u64::from(octet));
    let Some(peer_l2_address) = PeerL2Address::new(value.max(1)) else {
        return false;
    };
    context.enqueue_packet(
        PacketMeta {
            bearer: context.bearer(),
            peer_l2_address,
            received_at_us: unsafe { esp_idf_sys::esp_timer_get_time().max(0) as u64 },
        },
        packet,
    );
    crate::main_runtime::request_quic_ingress();
    true
}

/// Parse a NOW frame directly into the shared QUIC packet pool. The admission
/// callback may consume sync/discovery records from that same buffer; only an
/// opaque QUIC datagram is committed and enqueued to the node.
pub(crate) fn receive_now_with<F, A>(parse: F, admit: A) -> Result<bool, NowReceiveError>
where
    F: FnOnce(&mut [u8]) -> Option<([u8; 6], usize)>,
    A: FnOnce(crate::wifi_espnow_esp::EspNowPeer, &[u8]) -> bool,
{
    if !NOW_READY.load(Ordering::Acquire) {
        return Err(NowReceiveError::NotReady);
    }
    let context = unsafe {
        (&*core::ptr::addr_of!(NOW_CONTEXT).cast::<BearerContext<FirmwarePool>>()).clone()
    };
    let Some(mut writer) = context.pool().acquire_writer(0, 0) else {
        return Err(NowReceiveError::PoolFull);
    };
    let Some((mac, len)) = parse(writer.payload_mut()) else {
        return Err(NowReceiveError::InvalidFrame);
    };
    if len > writer.payload_mut().len() {
        return Err(NowReceiveError::InvalidFrame);
    }
    let peer = crate::wifi_espnow_esp::EspNowPeer { mac };
    if !admit(peer, &writer.payload_mut()[..len]) {
        return Ok(false);
    }
    let value = mac
        .into_iter()
        .fold(0_u64, |value, octet| (value << 8) | u64::from(octet));
    let Some(peer_l2_address) = PeerL2Address::new(value.max(1)) else {
        return Err(NowReceiveError::InvalidPeer);
    };
    let Some(packet) = writer.commit(len) else {
        return Err(NowReceiveError::CommitFailed);
    };
    context.enqueue_packet(
        PacketMeta {
            bearer: context.bearer(),
            peer_l2_address,
            received_at_us: unsafe { esp_idf_sys::esp_timer_get_time().max(0) as u64 },
        },
        packet,
    );
    crate::main_runtime::request_quic_ingress();
    Ok(true)
}

/// Advance queued bearer ingress and dispatch complete request streams.
///
/// Main calls this only from its single event owner. It is intentionally not
/// public API: physical bearers enqueue through `BearerContext` and merely
/// wake that owner.
pub(crate) fn progress() {
    let runtime = unsafe { runtime() };
    let now_ms = (unsafe { esp_idf_sys::esp_timer_get_time().max(0) as u64 }) / 1_000;
    sweep_handler_streams(now_ms);
    report_flash_progress(runtime, now_ms);
    progress_directed_probe(runtime);
    if runtime.take_ingress_drops() != 0 {
        let _ = crate::uart_esp::send_debug_text(b"DMESH QUIC ingress queue packet dropped");
    }
    service_handler_streams(runtime, now_ms);
    loop {
        let processed = match runtime.progress_with_stream(|stream, offset, fin, bytes| {
            // Data on a stream this node opened (the response of a probe it
            // runs as a client) is not a request.
            if let Some(result) = peer_probe_chunk(&stream, fin, bytes) {
                return result;
            }
            Ok(ingest_handler_chunk(stream, offset, fin, bytes, now_ms))
        }) {
            Ok(true) => true,
            Ok(false) => false,
            Err(error) => {
                if !INGRESS_ERROR_REPORTED.swap(true, Ordering::AcqRel) {
                    let detail = match error {
                        QuicNodeEgressError::Association(_) => b"association".as_slice(),
                        QuicNodeEgressError::Transport(quic_lite::Error::BufferTooSmall) => {
                            b"buffer-too-small"
                        }
                        QuicNodeEgressError::Transport(quic_lite::Error::Truncated) => b"truncated",
                        QuicNodeEgressError::Transport(quic_lite::Error::Invalid) => b"invalid",
                        QuicNodeEgressError::Transport(quic_lite::Error::Blocked) => b"blocked",
                        QuicNodeEgressError::Transport(quic_lite::Error::InvalidVarint) => {
                            b"invalid-varint"
                        }
                        QuicNodeEgressError::Transport(quic_lite::Error::FlowControl) => {
                            b"flow-control"
                        }
                        QuicNodeEgressError::Transport(quic_lite::Error::StreamLimit) => {
                            b"stream-limit"
                        }
                        QuicNodeEgressError::Transport(quic_lite::Error::PathLimit) => {
                            b"path-limit"
                        }
                        QuicNodeEgressError::Transport(quic_lite::Error::PacketNumberExhausted) => {
                            b"packet-number-exhausted"
                        }
                        QuicNodeEgressError::Transport(quic_lite::Error::WrongConnectionId) => {
                            b"wrong-connection-id"
                        }
                        QuicNodeEgressError::Transport(quic_lite::Error::PeerRestarted) => {
                            b"peer-restarted"
                        }
                        QuicNodeEgressError::Transport(quic_lite::Error::BootstrapInvalid) => {
                            b"bootstrap-invalid"
                        }
                        QuicNodeEgressError::Transport(quic_lite::Error::HistoryFull) => {
                            b"history-full"
                        }
                        QuicNodeEgressError::Transport(
                            quic_lite::Error::RetransmissionTooLarge,
                        ) => b"retransmission-too-large",
                        QuicNodeEgressError::PoolUnavailable => b"pool-unavailable",
                        QuicNodeEgressError::InvalidPoolLayout => b"invalid-pool-layout",
                        QuicNodeEgressError::MissingEgressAddress => b"missing-egress-address",
                        QuicNodeEgressError::MissingBearer => b"missing-bearer",
                        QuicNodeEgressError::BearerBusy => b"bearer-busy",
                        QuicNodeEgressError::StreamEventsFull => b"stream-events-full",
                        QuicNodeEgressError::AssociationTimedOut => b"association-timeout",
                        QuicNodeEgressError::CircuitBusy => b"circuit-busy",
                        QuicNodeEgressError::PathSetupAttemptsExhausted => {
                            b"path-attempts-exhausted"
                        }
                        QuicNodeEgressError::SetupRejected(_) => b"setup-rejected",
                    };
                    let _ = crate::uart_esp::send_debug_text(detail);
                }
                false
            }
        };
        while let Some(chunk) = runtime.next_stream_chunk() {
            queue_handler_chunk(chunk.stream, chunk.offset, chunk.fin, &chunk.bytes, now_ms);
        }
        service_handler_streams(runtime, now_ms);
        if !processed {
            break;
        }
    }
    crate::main_runtime::request_connection_deadline_recheck();
}

/// Report NOW driver capacity after a prior zero-byte WouldBlock. Main calls
/// this from its one-shot retry deadline before advancing the QUIC owner.
pub(crate) fn now_send_ready() {
    if !NOW_READY.load(Ordering::Acquire) {
        return;
    }
    let context = unsafe {
        (&*core::ptr::addr_of!(NOW_CONTEXT).cast::<BearerContext<FirmwarePool>>()).clone()
    };
    context.send_ready();
}

/// Release a UART bearer packet retained after `WouldBlock`. The physical
/// writer calls this only after it has drained the one active pool-backed
/// submission and can accept another packet.
pub(crate) fn uart_send_ready() {
    if !UART_READY.load(Ordering::Acquire) || !crate::uart_esp::take_send_blocked() {
        return;
    }
    let context = unsafe {
        (&*core::ptr::addr_of!(UART_CONTEXT).cast::<BearerContext<FirmwarePool>>()).clone()
    };
    context.send_ready();
}


// ---------------------------------------------------------------------------
// Handler streams
//
// Every inbound stream is served by the one registry: a header, then an
// optional raw body, FIN after the body (see ssh-mesh `PROTOCOLS.md`). This
// file only moves bytes between the node's stream callbacks and
// `dmesh_server::stream::ServerStream`; it dispatches no method itself.
// ---------------------------------------------------------------------------

/// The response of one stream being written: its header, then its body.
struct ResponseWriter {
    reader: dmesh_server::stream::ResponseReader,
    /// Bytes read from the reader that the node has not accepted yet.
    carry: Vec<u8>,
    /// The reader reported its last byte; FIN goes with the last write.
    last_read: bool,
    done: bool,
    /// A streaming body had nothing to send yet (`log.watch`): nobody is told
    /// when it has, so the owner polls it on a timer while this is set.
    waiting_body: bool,
}

struct HandlerStream {
    stream: QuicStream,
    request: dmesh_server::stream::ServerStream,
    writer: Option<ResponseWriter>,
    /// The peer's FIN was accepted.
    request_finished: bool,
    last_ms: u64,
    /// Request bytes the handler withheld from a queued chunk.
    leftover: Vec<u8>,
    leftover_offset: u64,
    leftover_fin: bool,
}

static mut HANDLER_STREAMS: Vec<HandlerStream> = Vec::new();

fn handler_streams() -> &'static mut Vec<HandlerStream> {
    // Main's single QUIC owner is the only caller.
    unsafe { &mut *core::ptr::addr_of_mut!(HANDLER_STREAMS) }
}

impl HandlerStream {
    fn start_response(&mut self, response: dmesh_server::stream::Response) {
        self.writer = Some(ResponseWriter {
            reader: response.into_reader(),
            carry: Vec::new(),
            last_read: false,
            done: false,
            waiting_body: false,
        });
        crate::main_runtime::request_quic_ingress();
    }
}

/// Offer request bytes to a stream's handler; returns how many were taken.
fn ingest(entry: &mut HandlerStream, offset: u64, fin: bool, bytes: &[u8]) -> usize {
    let pushed = dmesh_server::stream::track_progress(
        &mut entry.last_ms,
        handler_clock_ms,
        || {
            let pushed = entry
                .request
                .push(&dmesh_server::registry::REGISTRY, offset, fin, bytes);
            let progressed = pushed.accepted != 0 || (fin && bytes.is_empty());
            (pushed, progressed)
        },
    );
    if let Some(response) = pushed.response {
        entry.start_response(response);
    }
    if fin && pushed.accepted == bytes.len() {
        entry.request_finished = true;
    }
    pushed.accepted
}

fn handler_clock_ms() -> u64 {
    (unsafe { esp_idf_sys::esp_timer_get_time().max(0) as u64 }) / 1_000
}

fn find_or_open(stream: QuicStream, now_ms: u64) -> Option<&'static mut HandlerStream> {
    let streams = handler_streams();
    if let Some(index) = streams
        .iter()
        .position(|entry| entry.stream.same_stream(&stream))
    {
        return Some(&mut streams[index]);
    }
    if streams.len() >= MAX_HANDLER_STREAMS {
        return None;
    }
    let context = dmesh_server::registry::CallContext {
        association: stream.association_id(),
        stream_id: Some(stream.id()),
        ..Default::default()
    };
    streams.push(HandlerStream {
        stream,
        request: dmesh_server::stream::ServerStream::new(context),
        writer: None,
        request_finished: false,
        last_ms: now_ms,
        leftover: Vec::new(),
        leftover_offset: 0,
        leftover_fin: false,
    });
    streams.last_mut()
}

/// Stream callback: hand request bytes to the stream's handler.
fn ingest_handler_chunk(
    stream: QuicStream,
    offset: u64,
    fin: bool,
    bytes: &[u8],
    now_ms: u64,
) -> usize {
    match find_or_open(stream, now_ms) {
        Some(entry) => ingest(entry, offset, fin, bytes),
        // No room for another stream: refuse the bytes, so the transport
        // keeps them and offers them again.
        None => 0,
    }
}

/// A chunk the node queued instead of delivering to the callback. Bytes the
/// handler withholds are kept and offered again from `service_handler_streams`.
fn queue_handler_chunk(stream: QuicStream, offset: u64, fin: bool, bytes: &[u8], now_ms: u64) {
    let Some(entry) = find_or_open(stream, now_ms) else {
        let _ = crate::uart_esp::send_debug_text(b"DMESH handler streams full; chunk dropped");
        return;
    };
    let accepted = ingest(entry, offset, fin, bytes);
    if accepted < bytes.len() {
        entry.leftover = bytes[accepted..].to_vec();
        entry.leftover_offset = offset + accepted as u64;
        entry.leftover_fin = fin;
    }
}

enum WriteState {
    /// Nothing could be written now (flow control, pool, bearer, empty body).
    Blocked,
    /// Wrote some bytes; more remain.
    More,
    Done,
    Failed,
}

fn write_some(
    runtime: &mut FirmwareRuntime,
    stream: &mut QuicStream,
    writer: &mut ResponseWriter,
) -> WriteState {
    if writer.carry.is_empty() && !writer.last_read {
        let window = match runtime.stream_send_window(stream) {
            Ok(window) => window,
            Err(error) if error.is_retryable() => return WriteState::Blocked,
            Err(_) => return WriteState::Failed,
        };
        let capacity = window.min(WRITE_CHUNK as u64) as usize;
        if capacity == 0 {
            return WriteState::Blocked;
        }
        let mut chunk = [0u8; WRITE_CHUNK];
        let (count, done) = writer.reader.read(&mut chunk[..capacity]);
        writer.waiting_body = count == 0 && !done;
        if count == 0 && !done {
            return WriteState::Blocked;
        }
        writer.carry.extend_from_slice(&chunk[..count]);
        writer.last_read = done;
    }
    let result = if writer.last_read {
        runtime.write_stream_and_finish(stream, &writer.carry)
    } else {
        runtime.write_stream(stream, &writer.carry)
    };
    match result {
        Ok(accepted) => {
            writer.carry.drain(..accepted);
            if !writer.carry.is_empty() {
                WriteState::More
            } else if writer.last_read {
                WriteState::Done
            } else {
                WriteState::More
            }
        }
        Err(error) if error.is_retryable() => WriteState::Blocked,
        Err(_) => WriteState::Failed,
    }
}

/// Advance every handler stream: withheld request bytes, deferred work, and
/// response writing. Called from the QUIC owner's progress loop.
fn service_handler_streams(runtime: &mut FirmwareRuntime, now_ms: u64) {
    let streams = handler_streams();
    let mut more = false;
    let mut index = 0;
    while index < streams.len() {
        let entry = &mut streams[index];
        if !entry.leftover.is_empty() {
            let leftover = core::mem::take(&mut entry.leftover);
            let (offset, fin) = (entry.leftover_offset, entry.leftover_fin);
            let accepted = ingest(entry, offset, fin, &leftover);
            entry.leftover_offset = offset + accepted as u64;
            entry.leftover = leftover[accepted..].to_vec();
        }
        if let Some(response) = dmesh_server::stream::track_progress(
            &mut entry.last_ms,
            handler_clock_ms,
            || {
                let response = entry.request.poll();
                let progressed = response.is_some();
                (response, progressed)
            },
        ) {
            entry.start_response(response);
        }
        if let Some(writer) = entry.writer.as_mut() {
            let state = dmesh_server::stream::track_progress(
                &mut entry.last_ms,
                handler_clock_ms,
                || {
                    let state = write_some(runtime, &mut entry.stream, writer);
                    let progressed = matches!(state, WriteState::More | WriteState::Done);
                    (state, progressed)
                },
            );
            match state {
                WriteState::Blocked => {}
                WriteState::More => {
                    more = true;
                }
                WriteState::Done => writer.done = true,
                WriteState::Failed => {
                    let _ = crate::uart_esp::send_debug_text(b"DMESH QUIC response write failed");
                    writer.done = true;
                }
            }
        }
        let answered_and_sent = entry.writer.as_ref().is_some_and(|writer| writer.done);
        if answered_and_sent && entry.request_finished {
            streams.swap_remove(index);
        } else {
            index += 1;
        }
    }
    if more {
        // A response is application-owned work outside the stream callback.
        // Keep the owner moving after each accepted chunk; bearer readiness
        // can arrive before the peer's next packet and must not be the only
        // edge that resumes a pending producer.
        crate::main_runtime::request_quic_ingress();
    }
}

/// Whether a response body is waiting for data it will not announce.
fn body_poll_pending() -> bool {
    handler_streams().iter().any(|entry| {
        entry
            .writer
            .as_ref()
            .is_some_and(|writer| writer.waiting_body && !writer.done)
    })
}

/// How often a waiting streaming body is polled.
const BODY_POLL_MS: u32 = 100;

/// Abandon streams with no application progress, releasing their handlers
/// (a flash transfer, for example, stops owning the object writer).
fn sweep_handler_streams(now_ms: u64) {
    let streams = handler_streams();
    // A finished probe result that no stream waits for (its stream ended
    // first) must not block later probes.
    if !streams.iter().any(|entry| entry.request.is_waiting())
        && unsafe { (&*core::ptr::addr_of!(PEER_PROBE_RESULT)).is_some() }
    {
        unsafe { *core::ptr::addr_of_mut!(PEER_PROBE_RESULT) = None };
    }
    let mut index = 0;
    while index < streams.len() {
        // A stream waiting on deferred work (a probe job, which has its own
        // time limit) shows no stream activity until the job ends; sweeping it
        // would orphan the job's result.
        if !streams[index].request.is_waiting()
            && now_ms.saturating_sub(streams[index].last_ms) >= HANDLER_STREAM_IDLE_MS
        {
            let entry = streams.swap_remove(index);
            entry.request.abort();
        } else {
            index += 1;
        }
    }
}

// ---------------------------------------------------------------------------
// Probe
//
// `probe.handler` is the shared handler (`dmesh_server::probe`): header, then
// the probe payload as the response body. `probe.start` asks this node to be the
// client of a peer's `probe.handler`; its response header, sent when the job
// ends, is the outcome. The job runs on the NOW bearer from Main's owner.
// ---------------------------------------------------------------------------

/// Register `probe` (run) and `probe.handler` in the process-wide registry.
pub(crate) fn register_probe_handlers() {
    use dmesh_server::registry::{self, methods};
    let _ = registry::register_stream(methods::PROBE_START, ProbeStartHandler);
    let _ = registry::register_stream(methods::PROBE_HANDLER, dmesh_server::probe::ProbeHandler);
}

struct ProbeStartHandler;

/// Waits for the one active probe job to finish.
struct ProbeStartWait;

impl dmesh_server::stream::Deferred for ProbeStartWait {
    fn poll(&mut self) -> Option<dmesh_server::stream::Response> {
        unsafe { (&mut *core::ptr::addr_of_mut!(PEER_PROBE_RESULT)).take() }
            .map(dmesh_server::stream::Response::header)
    }
}

impl dmesh_server::stream::StreamHandler for ProbeStartHandler {
    fn open<'a>(
        &'a self,
        request: dmesh_server::stream::Request<'a>,
    ) -> dmesh_server::stream::OpenFuture<'a> {
        use dmesh_server::stream::{Outcome, Response};
        let outcome = (|| {
            let (id, probe) = dmesh_server::probe::decode_probe_start_record(request.record)?;
            let peer = probe.peer?;
            let failed = || {
                let mut response = alloc::vec![0u8; 256];
                let len = dmesh_server::probe::encode_probe_result_response(
                    id,
                    probe,
                    false,
                    0,
                    0,
                    &mut response,
                )
                .unwrap_or(0);
                response.truncate(len);
                Some(Outcome::Respond(Response::header(response)))
            };
            let busy = unsafe {
                (&*core::ptr::addr_of!(PENDING_PEER_PROBE)).is_some()
                    || (&*core::ptr::addr_of!(PEER_PROBE_RESULT)).is_some()
            };
            if busy || !NOW_READY.load(Ordering::Acquire) || peer.espnow_mac().is_none() {
                return failed();
            }
            let outbound = dmesh_server::probe::ProbeServiceRequest::new(probe.bytes, probe.packet_size);
            let mut request_wire = [0; dmesh_server::probe::PROBE_REQUEST_MAX];
            let Some(request_len) =
                dmesh_server::probe::encode_probe_handler_request(outbound, id, &mut request_wire)
            else {
                return failed();
            };
            unsafe {
                *core::ptr::addr_of_mut!(PENDING_PEER_PROBE) = Some(PendingPeerProbe {
                    id,
                    request: probe,
                    started_at_us: esp_idf_sys::esp_timer_get_time().max(0) as u64,
                    timeout_us: dmesh_server::probe::probe_timeout_ms(
                        request.context.timeout_ms,
                        probe.bytes,
                    )
                    .saturating_mul(1000),
                    association: None,
                    stream: None,
                    request_wire,
                    request_len,
                    request_offset: 0,
                    reader: dmesh_server::probe::ProbeResponseReader::new(probe.bytes),
                });
            }
            let _ = crate::uart_esp::send_debug_text(b"DMESH directed probe queued");
            crate::main_runtime::request_quic_ingress();
            crate::main_runtime::request_connection_deadline_recheck();
            Some(Outcome::Defer(alloc::boxed::Box::new(ProbeStartWait)))
        })();
        alloc::boxed::Box::pin(core::future::ready(outcome))
    }
}

/// Data on the stream of the running probe job: the peer's response header,
/// then the probe payload. `None` when the stream is not the job's.
fn peer_probe_chunk(
    stream: &QuicStream,
    fin: bool,
    bytes: &[u8],
) -> Option<Result<usize, quic_lite::Error>> {
    let pending = unsafe { (&mut *core::ptr::addr_of_mut!(PENDING_PEER_PROBE)).as_mut()? };
    let outbound = pending.stream.as_ref()?;
    if !outbound.same_stream(stream) {
        return None;
    }
    match pending.reader.push(bytes) {
        Ok(()) => {
            if pending.reader.is_complete() {
                let _ = crate::uart_esp::send_debug_text(b"DMESH directed probe RX complete");
                finish_peer_probe(true);
            } else if fin {
                let _ = crate::uart_esp::send_debug_text(b"DMESH directed probe RX ended early");
                finish_peer_probe(false);
            }
        }
        Err(error) => {
            report_probe_value(
                b"DMESH directed probe RX rejected bytes=",
                pending.reader.bytes(),
            );
            let _ = crate::uart_esp::send_debug_text(match error {
                dmesh_server::probe::ProbeClientError::Header => b"DMESH directed probe RX bad header",
                dmesh_server::probe::ProbeClientError::Rejected => {
                    b"DMESH directed probe peer rejected"
                }
                dmesh_server::probe::ProbeClientError::Payload => {
                    b"DMESH directed probe RX data rejected"
                }
            });
            finish_peer_probe(false);
        }
    }
    Some(Ok(bytes.len()))
}

/// Run one device-originated NOW probe from Main's single QUIC owner.
fn progress_directed_probe(runtime: &mut FirmwareRuntime) {
    let Some(pending) = (unsafe { (&mut *core::ptr::addr_of_mut!(PENDING_PEER_PROBE)).as_mut() })
    else {
        return;
    };
    let now_us = unsafe { esp_idf_sys::esp_timer_get_time().max(0) as u64 };
    if now_us.saturating_sub(pending.started_at_us) > pending.timeout_us {
        crate::uart_esp::send_debug_text(b"DMESH directed probe timed out");
        finish_peer_probe(false);
        return;
    }
    if pending.association.is_none() {
        let context = unsafe {
            (&*core::ptr::addr_of!(NOW_CONTEXT).cast::<BearerContext<FirmwarePool>>()).clone()
        };
        let Some(peer) = pending
            .request
            .peer
            .and_then(|destination| destination.espnow_mac())
        else {
            crate::uart_esp::send_debug_text(b"DMESH directed probe peer invalid");
            finish_peer_probe(false);
            return;
        };
        let peer_value = peer
            .into_iter()
            .fold(0_u64, |value, octet| (value << 8) | u64::from(octet));
        let Some(peer_l2_address) = PeerL2Address::new(peer_value) else {
            crate::uart_esp::send_debug_text(b"DMESH directed probe peer address invalid");
            finish_peer_probe(false);
            return;
        };
        let meta = PacketMeta {
            bearer: context.bearer(),
            peer_l2_address,
            received_at_us: now_us,
        };
        match runtime.associate(meta, now_us) {
            Ok(association) => {
                pending.association = Some(association);
                let _ =
                    crate::uart_esp::send_debug_text(b"DMESH NOW peer probe association started");
                crate::main_runtime::request_connection_deadline_recheck();
            }
            Err(_) => {
                crate::uart_esp::send_debug_text(b"DMESH directed probe association rejected");
                finish_peer_probe(false)
            }
        }
        return;
    }
    let association = pending.association.expect("association checked above");
    if !runtime.association_is_established(association) {
        return;
    }
    if pending.stream.is_none() {
        match runtime.open_stream(association) {
            Ok(stream) => pending.stream = Some(stream),
            Err(_) => {
                crate::uart_esp::send_debug_text(b"DMESH directed probe stream open failed");
                finish_peer_probe(false);
                return;
            }
        }
    }
    let stream = pending.stream.as_mut().expect("stream initialized above");
    // The request is a header and no body: FIN follows the header.
    let result = if pending.request_offset < pending.request_len {
        runtime.write_stream_and_finish(
            stream,
            &pending.request_wire[pending.request_offset..pending.request_len],
        )
    } else {
        return;
    };
    match result {
        Ok(written) => {
            pending.request_offset += written;
            if pending.request_offset < pending.request_len {
                crate::main_runtime::request_quic_ingress();
            } else {
                let _ = crate::uart_esp::send_debug_text(b"DMESH directed probe request sent");
            }
        }
        Err(error) if error.is_retryable() => {}
        Err(_) => {
            crate::uart_esp::send_debug_text(b"DMESH directed probe request write failed");
            finish_peer_probe(false);
        }
    }
}

fn finish_peer_probe(ok: bool) {
    let Some(pending) = (unsafe { (&mut *core::ptr::addr_of_mut!(PENDING_PEER_PROBE)).take() })
    else {
        return;
    };
    let received = pending.reader.bytes();
    let _ = crate::uart_esp::send_debug_text(if ok {
        b"DMESH directed probe finish ok"
    } else {
        b"DMESH directed probe finish error"
    });
    let elapsed = (unsafe { esp_idf_sys::esp_timer_get_time().max(0) as u64 })
        .saturating_sub(pending.started_at_us);
    let mut response = alloc::vec![0u8; 256];
    let len = dmesh_server::probe::encode_probe_result_response(
        pending.id,
        pending.request,
        ok && pending.reader.is_complete() && received == pending.request.bytes,
        received,
        elapsed,
        &mut response,
    )
    .unwrap_or(0);
    response.truncate(len);
    unsafe { *core::ptr::addr_of_mut!(PEER_PROBE_RESULT) = Some(response) };
    crate::main_runtime::request_quic_ingress();
    crate::main_runtime::request_connection_deadline_recheck();
}

fn report_probe_value(prefix: &[u8], value: u64) {
    let mut line = [0u8; 80];
    if prefix.len() + 20 > line.len() {
        return;
    }
    line[..prefix.len()].copy_from_slice(prefix);
    let len = prefix.len() + append_decimal(&mut line[prefix.len()..], value);
    let _ = crate::uart_esp::send_debug_text(&line[..len]);
}

fn append_decimal(target: &mut [u8], mut value: u64) -> usize {
    let mut digits = [0u8; 20];
    let mut used = 0;
    loop {
        digits[used] = b'0' + (value % 10) as u8;
        used += 1;
        value /= 10;
        if value == 0 {
            break;
        }
    }
    for (index, digit) in digits[..used].iter().rev().enumerate() {
        target[index] = *digit;
    }
    used
}
