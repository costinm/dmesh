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
    PeerL2Address, QuicNodeEgressError, QuicStream,
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
static INGRESS_PROGRESS_REPORTED: AtomicBool = AtomicBool::new(false);
static INGRESS_ERROR_REPORTED: AtomicBool = AtomicBool::new(false);
static UDP6_INGRESS_REPORTED: AtomicUsize = AtomicUsize::new(0);
static UDP6_EGRESS_REPORTED: AtomicUsize = AtomicUsize::new(0);
static SERVICE_STREAM_REPORTED: AtomicUsize = AtomicUsize::new(0);
static SERVICE_CHUNK_REPORTED: AtomicUsize = AtomicUsize::new(0);
static RESPONSE_WRITE_DIAGNOSTICS: AtomicUsize = AtomicUsize::new(0);
static RESPONSE_WRITE_ACCEPTS_REPORTED: AtomicUsize = AtomicUsize::new(0);
static PROBE_PROGRESS_REPORTED: AtomicUsize = AtomicUsize::new(0);
static PROBE_WINDOW_BLOCK_REPORTED: AtomicBool = AtomicBool::new(false);
static PROBE_POOL_BLOCK_REPORTED: AtomicBool = AtomicBool::new(false);
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
// The stream position is unchanged when the UART bearer retains an ACK or
// another packet. Keep the application response until send completion wakes
// the node owner, then retry the same bytes without a second packet copy.
static mut PENDING_RESPONSE: Option<(QuicStream, Vec<u8>, usize)> = None;
struct PendingProbeResponse {
    stream: QuicStream,
    sender: dmesh_server::probe::ProbeSender,
    chunk_size: usize,
}
static mut PENDING_PROBE_RESPONSE: Option<PendingProbeResponse> = None;
const PROBE_CHUNK_SIZE: usize = quic_lite::DEFAULT_MAX_STREAM_PAYLOAD;
static mut INCOMING_REQUESTS: dmesh_server::services::OrderedRecordAssembler<QuicStream> =
    dmesh_server::services::OrderedRecordAssembler::new();

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
    crate::main_runtime::request_quic_ingress();
    true
}

pub(crate) fn take_pending_now_control_response(
) -> Option<(crate::wifi_espnow_esp::EspNowPeer, FirmwarePacket)> {
    PENDING_NOW_CONTROL_TX
        .try_pop()
        .map(|(peer, packet)| (crate::wifi_espnow_esp::EspNowPeer { mac: peer }, packet))
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
        let sent = crate::wifi_espnow_esp::transmit_from_worker(
            crate::wifi_espnow_esp::EspNowPeer {
                mac: peer.value().to_be_bytes()[2..]
                    .try_into()
                    .expect("NOW peer handle contains six MAC bytes"),
            },
            submission.packet().bytes(),
        );
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
        let mut value = FirmwareRuntime::try_new_boxed(
            crate::main_runtime::stateless_reset_key(),
            &POOL,
            embedded.connection,
        )
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

/// Pool assigned to UART by its registered bearer context.
pub(crate) fn uart_pool() -> &'static FirmwarePool {
    unsafe {
        let _ = runtime();
    }
    assert!(UART_READY.load(Ordering::Acquire));
    unsafe { (&*core::ptr::addr_of!(UART_CONTEXT).cast::<BearerContext<FirmwarePool>>()).pool() }
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
    if runtime.take_ingress_drops() != 0 {
        let _ = crate::uart_esp::send_debug_text(b"DMESH QUIC ingress queue packet dropped");
    }
    if let Some((mut stream, response, offset)) = unsafe { PENDING_RESPONSE.take() } {
        match write_response(runtime, &mut stream, &response, offset) {
            Ok(next) if next < response.len() => {
                unsafe { PENDING_RESPONSE = Some((stream, response, next)) };
                return;
            }
            Err(error) if error.is_retryable() => {
                unsafe { PENDING_RESPONSE = Some((stream, response, offset)) };
                return;
            }
            _ => {}
        }
    }
    progress_probe_response(runtime);
    let request_limit = runtime
        .default_association_limits()
        .max_buffered_stream_bytes;
    let aggregate_request_limit = runtime
        .limits()
        .max_associations
        .saturating_mul(request_limit);
    loop {
        let mut received_response = None;
        let processed = match runtime.progress_with_stream(|stream, offset, fin, bytes| {
            let (accepted, complete) = unsafe {
                INCOMING_REQUESTS.push(
                    stream,
                    offset,
                    fin,
                    bytes,
                    request_limit,
                    aggregate_request_limit,
                )
            };
            report_service_chunk(offset, fin, bytes.len());
            if let Some((stream, request)) = complete {
                if SERVICE_STREAM_REPORTED.fetch_add(1, Ordering::AcqRel) < 4 {
                    let _ = crate::uart_esp::send_debug_text(b"DMESH QUIC service stream complete");
                }
                if let Some(response) = dispatch_complete_request(stream, &request) {
                    received_response = Some(response);
                }
            }
            Ok(accepted)
        }) {
            Ok(true) => {
                if !INGRESS_PROGRESS_REPORTED.swap(true, Ordering::AcqRel) {
                    let _ = crate::uart_esp::send_debug_text(b"DMESH uart: quic ingress processed");
                }
                true
            }
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
                        QuicNodeEgressError::RelayUnavailable => b"relay-unavailable",
                    };
                    let _ = crate::uart_esp::send_debug_text(detail);
                }
                false
            }
        };
        if let Some((mut stream, response)) = received_response {
            match write_response(runtime, &mut stream, &response, 0) {
                Ok(next) if next < response.len() => {
                    unsafe { PENDING_RESPONSE = Some((stream, response, next)) };
                    return;
                }
                Err(error) if error.is_retryable() => {
                    unsafe { PENDING_RESPONSE = Some((stream, response, 0)) };
                    return;
                }
                _ => {}
            }
        }
        while let Some(chunk) = runtime.next_stream_chunk() {
            report_service_chunk(chunk.offset, chunk.fin, chunk.bytes.len());
            let (accepted, complete) = unsafe {
                INCOMING_REQUESTS.push(
                    chunk.stream,
                    chunk.offset,
                    chunk.fin,
                    &chunk.bytes,
                    request_limit,
                    aggregate_request_limit,
                )
            };
            debug_assert_eq!(accepted, chunk.bytes.len());
            if let Some((stream, request)) = complete {
                if let Some((mut stream, response)) = dispatch_complete_request(stream, &request) {
                    match write_response(runtime, &mut stream, &response, 0) {
                        Ok(next) if next < response.len() => {
                            unsafe { PENDING_RESPONSE = Some((stream, response, next)) };
                            return;
                        }
                        Err(error) if error.is_retryable() => {
                            unsafe { PENDING_RESPONSE = Some((stream, response, 0)) };
                            return;
                        }
                        _ => {}
                    }
                }
            }
        }
        if !processed {
            break;
        }
        progress_probe_response(runtime);
    }
}

fn dispatch_complete_request(stream: QuicStream, request: &[u8]) -> Option<(QuicStream, Vec<u8>)> {
    if let Some(record) = dmesh_server::tagged::decode(request) {
        if let Some((_, probe_request)) = dmesh_server::probe::decode_probe_run_record(record) {
            if unsafe { PENDING_PROBE_RESPONSE.is_none() } {
                if let Some((sender, chunk_size)) = pending_probe(stream.id(), probe_request) {
                    PROBE_PROGRESS_REPORTED.store(0, Ordering::Release);
                    PROBE_WINDOW_BLOCK_REPORTED.store(false, Ordering::Release);
                    PROBE_POOL_BLOCK_REPORTED.store(false, Ordering::Release);
                    unsafe {
                        PENDING_PROBE_RESPONSE = Some(PendingProbeResponse {
                            stream,
                            sender,
                            chunk_size,
                        })
                    };
                    let _ = crate::uart_esp::send_debug_text(b"DMESH QUIC probe response started");
                    crate::main_runtime::request_quic_ingress();
                    return None;
                }
            }
        }
    }

    let response = dmesh_server::services::dispatch_tagged_stream(request);
    if response.is_some() {
        let _ = crate::uart_esp::send_debug_text(b"DMESH QUIC service dispatch matched");
    } else {
        let _ = crate::uart_esp::send_debug_text(b"DMESH QUIC service dispatch unmatched");
    }
    response.map(|response| (stream, response))
}

fn pending_probe(
    stream_id: u64,
    request: dmesh_server::probe::ProbeServiceRequest,
) -> Option<(dmesh_server::probe::ProbeSender, usize)> {
    if request.bytes == 0
        || request.bytes > dmesh_server::probe::PROBE_MAX_BYTES
        || usize::try_from(request.bytes).is_err()
        || request.parallel_streams.is_some_and(|streams| streams != 1)
        || request.high_priority_bytes.is_some_and(|bytes| bytes != 0)
        || request.low_priority_bytes.is_some_and(|bytes| bytes != 0)
        || request.ack_frequency.is_some()
        || request.ack_delay_ms.is_some()
    {
        return None;
    }
    let plan = dmesh_server::probe::ProbeServicePlan::from_request(
        request,
        quic_lite::DEFAULT_MAX_STREAM_PAYLOAD,
    );
    Some((
        dmesh_server::probe::ProbeSender::new(
            stream_id,
            usize::try_from(request.bytes).ok()?,
            plan.packet_size,
        )?,
        plan.packet_size,
    ))
}

fn progress_probe_response(runtime: &mut FirmwareRuntime) {
    let Some(mut pending) = (unsafe { PENDING_PROBE_RESPONSE.take() }) else {
        return;
    };
    let mut bytes = [0u8; PROBE_CHUNK_SIZE];
    let Ok(window) = runtime.stream_send_window(&pending.stream) else {
        unsafe { PENDING_PROBE_RESPONSE = Some(pending) };
        return;
    };
    let Some(chunk) = pending
        .sender
        .prepare(window, &mut bytes[..pending.chunk_size])
    else {
        if !pending.sender.is_complete()
            && !PROBE_WINDOW_BLOCK_REPORTED.swap(true, Ordering::AcqRel)
        {
            report_probe_value(
                b"DMESH QUIC probe window blocked bytes=",
                pending.sender.bytes_sent(),
            );
        }
        unsafe { PENDING_PROBE_RESPONSE = Some(pending) };
        return;
    };
    let written = if chunk.fin {
        runtime.write_stream_and_finish(&mut pending.stream, &bytes[..chunk.len])
    } else {
        runtime.write_stream(&mut pending.stream, &bytes[..chunk.len])
    };
    match written {
        Ok(accepted) if accepted == chunk.len => {
            if pending.sender.commit(chunk).is_err() {
                let _ = crate::uart_esp::send_debug_text(b"DMESH QUIC probe commit failed");
                return;
            }
            if pending.sender.is_complete() {
                let _ = crate::uart_esp::send_debug_text(b"DMESH QUIC probe response complete");
            } else {
                let sent = pending.sender.bytes_sent();
                let progress_mark = usize::try_from(sent / 16_384).unwrap_or(usize::MAX);
                let reported = PROBE_PROGRESS_REPORTED.load(Ordering::Acquire);
                if progress_mark > reported
                    && PROBE_PROGRESS_REPORTED
                        .compare_exchange(
                            reported,
                            progress_mark,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_ok()
                {
                    report_probe_value(b"DMESH QUIC probe bytes sent=", sent);
                }
                unsafe { PENDING_PROBE_RESPONSE = Some(pending) };
            }
        }
        Ok(_) => {
            let _ = crate::uart_esp::send_debug_text(b"DMESH QUIC probe response partial");
            unsafe { PENDING_PROBE_RESPONSE = Some(pending) };
        }
        Err(error) if error.is_retryable() => {
            if matches!(error, QuicNodeEgressError::PoolUnavailable)
                && !PROBE_POOL_BLOCK_REPORTED.swap(true, Ordering::AcqRel)
            {
                report_probe_value(
                    b"DMESH QUIC probe pool blocked bytes=",
                    pending.sender.bytes_sent(),
                );
            }
            unsafe { PENDING_PROBE_RESPONSE = Some(pending) };
        }
        Err(_) => {
            let _ = crate::uart_esp::send_debug_text(b"DMESH QUIC probe response failed");
        }
    }
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

fn report_service_chunk(offset: u64, fin: bool, bytes: usize) {
    if SERVICE_CHUNK_REPORTED.fetch_add(1, Ordering::AcqRel) >= 12 {
        return;
    }
    let mut line = [0u8; 96];
    let prefix = b"DMESH QUIC stream chunk offset=";
    line[..prefix.len()].copy_from_slice(prefix);
    let mut len = prefix.len();
    len += append_decimal(&mut line[len..], offset);
    let middle = b" bytes=";
    line[len..len + middle.len()].copy_from_slice(middle);
    len += middle.len();
    len += append_decimal(&mut line[len..], bytes as u64);
    let fin_text = if fin {
        b" fin=true".as_slice()
    } else {
        b" fin=false".as_slice()
    };
    line[len..len + fin_text.len()].copy_from_slice(fin_text);
    len += fin_text.len();
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

fn write_response(
    runtime: &mut FirmwareRuntime,
    stream: &mut QuicStream,
    response: &[u8],
    offset: usize,
) -> Result<usize, QuicNodeEgressError> {
    let accepted = match runtime.write_stream_and_finish(stream, &response[offset..]) {
        Ok(accepted) => accepted,
        Err(error) => {
            if RESPONSE_WRITE_DIAGNOSTICS.fetch_add(1, Ordering::Relaxed) < 8 {
                let reason = match error {
                    QuicNodeEgressError::Association(_) => b"association".as_slice(),
                    QuicNodeEgressError::Transport(quic_lite::Error::Blocked) => b"blocked",
                    QuicNodeEgressError::Transport(quic_lite::Error::FlowControl) => {
                        b"flow-control"
                    }
                    QuicNodeEgressError::Transport(quic_lite::Error::HistoryFull) => {
                        b"history-full"
                    }
                    QuicNodeEgressError::PoolUnavailable => b"pool-unavailable",
                    QuicNodeEgressError::InvalidPoolLayout => b"pool-layout",
                    QuicNodeEgressError::MissingEgressAddress => b"missing-address",
                    QuicNodeEgressError::MissingBearer => b"missing-bearer",
                    QuicNodeEgressError::BearerBusy => b"bearer-busy",
                    QuicNodeEgressError::StreamEventsFull => b"stream-events-full",
                    QuicNodeEgressError::AssociationTimedOut => b"association-timeout",
                    QuicNodeEgressError::RelayUnavailable => b"relay-unavailable",
                    QuicNodeEgressError::Transport(_) => b"transport",
                };
                let _ = crate::uart_esp::send_debug_text(b"DMESH QUIC response write failed");
                let _ = crate::uart_esp::send_debug_text(reason);
            }
            return Err(error);
        }
    };
    if RESPONSE_WRITE_ACCEPTS_REPORTED.fetch_add(1, Ordering::Relaxed) < 12 {
        let _ = crate::uart_esp::send_debug_text(b"DMESH QUIC response accepted by node");
    }
    if accepted < response.len().saturating_sub(offset)
        && RESPONSE_WRITE_DIAGNOSTICS.fetch_add(1, Ordering::Relaxed) < 8
    {
        let _ = crate::uart_esp::send_debug_text(b"DMESH QUIC response write partial");
    }
    Ok(offset.saturating_add(accepted))
}
