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
    heap_packet_pool::{HeapPacketAllocator, HeapPacketLease, HeapPacketPool},
    nostd::NoStdRuntime,
};

// Table ceiling only: packet storage is allocated/reclaimed at runtime.
pub(crate) const PACKETS: usize = 128;
const MIN_PACKETS: usize = 8;
const CONTROL_QUEUE_CAPACITY: usize = 8;
const HEAP_RESERVE: usize = 48 * 1024;
const SLOT_SIZE: usize = quic_lite::DEFAULT_PACKET_POOL_SLOT_SIZE;

pub(crate) type FirmwarePool = HeapPacketPool<PACKETS, SLOT_SIZE>;
pub(crate) type FirmwarePacket = OwnedPacket<HeapPacketLease<'static, PACKETS, SLOT_SIZE>>;
// Every local association owns one receive CID in the node's shared DCID
// registry. Firmware does not currently reserve additional entries for relay
// forwarding, but a zero-entry registry would reject the first association.
type FirmwareRuntime = NoStdRuntime<FirmwarePool>;

fn allocate_packet(bytes: usize) -> *mut u8 {
    unsafe {
        esp_idf_sys::heap_caps_malloc(
            bytes,
            esp_idf_sys::MALLOC_CAP_INTERNAL | esp_idf_sys::MALLOC_CAP_8BIT,
        )
        .cast()
    }
}
unsafe fn free_packet(pointer: *mut u8, _bytes: usize) {
    esp_idf_sys::heap_caps_free(pointer.cast());
}
static POOL: FirmwarePool =
    FirmwarePool::new_with_allocator(HeapPacketAllocator::new(allocate_packet, free_packet));
static mut POOL_POLICY: dmesh_server::packet_pool_policy::PacketPoolPolicy =
    dmesh_server::packet_pool_policy::PacketPoolPolicy::new(MIN_PACKETS, PACKETS, 8, 2_000);
static POOL_LIMIT: AtomicUsize = AtomicUsize::new(PACKETS);
static POOL_PRESSURE: AtomicBool = AtomicBool::new(false);

pub(crate) fn note_packet_pool_pressure() {
    POOL_PRESSURE.store(true, Ordering::Release);
    crate::main_runtime::request_quic_ingress();
}

fn acquire_packet_writer(
    headroom: usize,
) -> Option<<FirmwarePool as quic_lite::PacketPool>::Writer> {
    let writer = POOL.acquire_writer(headroom, 0);
    if writer.is_none() {
        note_packet_pool_pressure();
    }
    writer
}

/// Acquire a retained-log packet from the same dynamic pool as QUIC traffic.
/// QUIC prefix space is left available so a completed history packet can be
/// transferred to a stream writer without first shifting its CBOR bytes.
pub(crate) fn acquire_log_writer() -> Option<<FirmwarePool as quic_lite::PacketPool>::Writer> {
    acquire_packet_writer(quic_lite::PACKET_PREFIX_RESERVE)
}

/// Acquire a transient UART framing chunk from the shared dynamic pool. This
/// replaces a permanently reserved UART TX scratch array; an idle UART holds
/// no dedicated encoder buffer.
pub(crate) fn acquire_uart_tx_writer() -> Option<<FirmwarePool as quic_lite::PacketPool>::Writer> {
    acquire_packet_writer(0)
}

/// Acquire a receive packet directly from the node pool with relay headroom.
pub(crate) fn acquire_udp_receive_writer() -> Option<<FirmwarePool as quic_lite::PacketPool>::Writer>
{
    acquire_packet_writer(quic_lite::PACKET_PREFIX_RESERVE)
}

pub(crate) fn set_packet_capacity_limit(slots: usize) {
    POOL_LIMIT.store(slots.clamp(MIN_PACKETS, PACKETS), Ordering::Release);
    crate::main_runtime::request_quic_ingress();
}

/// Serialized owner only. Callbacks acquire existing leases and never allocate.
fn maintain_packet_pool(now_ms: u64) {
    let target = unsafe {
        let policy = &mut *core::ptr::addr_of_mut!(POOL_POLICY);
        policy.maximum = POOL_LIMIT.load(Ordering::Acquire);
        if POOL_PRESSURE.swap(false, Ordering::AcqRel) {
            policy.note_pressure(POOL.capacity());
        }
        policy.target(now_ms, POOL.capacity(), POOL.in_use())
    };
    let capacity = POOL.capacity();
    // Heap free-list walks are needed only for resizing, not for every
    // packet/owner wake when the policy leaves capacity unchanged.
    if target == capacity && POOL.allocated() == capacity {
        return;
    }
    let caps = esp_idf_sys::MALLOC_CAP_INTERNAL | esp_idf_sys::MALLOC_CAP_8BIT;
    let free = unsafe { esp_idf_sys::heap_caps_get_free_size(caps) };
    let largest = unsafe { esp_idf_sys::heap_caps_get_largest_free_block(caps) };
    if largest >= SLOT_SIZE || target <= capacity {
        let _ = POOL.resize_with_budget(target, free, HEAP_RESERVE);
    }
}
#[derive(Clone, Copy)]
pub(crate) enum ControlPeer {
    Udp(crate::wifi_raw_udp6_esp::RawUdp6Peer),
    UdpQuic(crate::wifi_raw_udp6_esp::RawUdp6Peer),
    Now(crate::wifi_espnow_esp::EspNowPeer),
}

// Wi-Fi callbacks only retain a pool lease. CBOR dispatch/signing and radio
// replies run on the firmware owner, not the small ESP-IDF Wi-Fi task stack.
static PENDING_CONTROL_RX: quic_lite::packet_pool::PacketLeaseQueue<
    ControlPeer,
    HeapPacketLease<'static, PACKETS, SLOT_SIZE>,
    CONTROL_QUEUE_CAPACITY,
> = quic_lite::packet_pool::PacketLeaseQueue::new();

pub(crate) fn defer_control_request(peer: ControlPeer, payload: &[u8]) -> bool {
    let Some(mut writer) = acquire_packet_writer(0) else {
        return false;
    };
    if payload.is_empty() || payload.len() > writer.payload_mut().len() {
        return false;
    }
    writer.payload_mut()[..payload.len()].copy_from_slice(payload);
    let Some(packet) = writer.commit(payload.len()) else {
        return false;
    };
    if PENDING_CONTROL_RX.try_push(peer, packet).is_err() {
        return false;
    }
    crate::main_runtime::request_quic_ingress();
    true
}

/// Defer a connectionless datagram that has already been received in the
/// shared packet pool, preserving its lease through owner-side dispatch.
pub(crate) fn defer_control_packet(peer: ControlPeer, packet: FirmwarePacket) -> bool {
    if PENDING_CONTROL_RX.try_push(peer, packet).is_err() {
        return false;
    }
    crate::main_runtime::request_quic_ingress();
    true
}

/// Queue a pool-backed UDP receive lease for owner-side path binding and QUIC
/// admission. The socket task transfers the original packet; it does not copy
/// the payload into another slot.
pub(crate) fn defer_udp_packet(
    peer: crate::wifi_raw_udp6_esp::RawUdp6Peer,
    packet: FirmwarePacket,
) -> bool {
    if PENDING_CONTROL_RX
        .try_push(ControlPeer::UdpQuic(peer), packet)
        .is_err()
    {
        return false;
    }
    crate::main_runtime::request_quic_ingress();
    true
}

fn dispatch_control_requests() {
    // Limit each owner turn even if callbacks refill the queue concurrently.
    for _ in 0..CONTROL_QUEUE_CAPACITY {
        let Some((peer, packet)) = PENDING_CONTROL_RX.try_pop() else {
            break;
        };
        if let ControlPeer::UdpQuic(peer) = peer {
            if let Some(path) = crate::wifi_raw_udp6_esp::bind_udp_peer_for_socket(peer) {
                receive_udp6_packet(path, packet);
            }
            continue;
        }
        let _ = crate::main_runtime::receive_connectionless_request(packet.bytes(), |response| {
            match peer {
                ControlPeer::Udp(peer) => {
                    let _ = crate::wifi_raw_udp6_esp::transmit_udp6(
                        peer.link,
                        peer,
                        crate::wifi_raw_udp6_esp::RAW_UDP6_PORT,
                        response,
                    );
                }
                ControlPeer::Now(peer) => {
                    let _ = crate::wifi_espnow_esp::transmit(peer, response);
                }
                ControlPeer::UdpQuic(_) => unreachable!("UDP QUIC packet handled above"),
            }
        });
    }
}
static UART_READY: AtomicBool = AtomicBool::new(false);
static BLE_READY: AtomicBool = AtomicBool::new(false);
/// Set while the BLE link refused a packet; cleared when it reports it can take another.
static BLE_SEND_BLOCKED: AtomicBool = AtomicBool::new(false);
/// The BLE link, supplied by the BLE adapter (`fw/ble`): `(connected, send)`. `send` returns
/// 0 when the SDU was accepted, 1 when the link is busy (retry on the ready edge), else failure.
static BLE_CONNECTED: AtomicUsize = AtomicUsize::new(0);
static BLE_SEND: AtomicUsize = AtomicUsize::new(0);
static mut BLE_CONTEXT: core::mem::MaybeUninit<BearerContext<FirmwarePool>> =
    core::mem::MaybeUninit::uninit();
static UDP6_READY: AtomicBool = AtomicBool::new(false);
static UDP6_TX_WAITING: AtomicBool = AtomicBool::new(false);
static UDP6_TX_READY_HINT: AtomicBool = AtomicBool::new(false);
// Serialized owner state, not a packet queue. The node retains the busy lease.
static mut UDP6_RETRY_AT_US: Option<u64> = None;

/// Wi-Fi task callback: coalesce a readiness hint only for a blocked attempt.
/// The owner alone touches the context, retry deadline, and retained packet.
pub(crate) fn notify_udp6_tx_done() {
    if UDP6_TX_WAITING.load(Ordering::Acquire) && !UDP6_TX_READY_HINT.swap(true, Ordering::AcqRel) {
        crate::main_runtime::request_quic_ingress();
    }
}

fn service_udp6_tx_ready_hint() {
    if !UDP6_TX_READY_HINT.swap(false, Ordering::AcqRel)
        || !UDP6_TX_WAITING.swap(false, Ordering::AcqRel)
    {
        return;
    }
    unsafe {
        UDP6_RETRY_AT_US = None;
    }
    let context = unsafe {
        (&*core::ptr::addr_of!(UDP6_CONTEXT).cast::<BearerContext<FirmwarePool>>()).clone()
    };
    context.send_ready();
}
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
    upload: Option<quic_lite::probe::ProbePayload>,
    upload_chunk: [u8; quic_lite::DEFAULT_MAX_STREAM_PAYLOAD],
    upload_len: usize,
    upload_offset: usize,
    reader: dmesh_server::probe::ProbeResponseReader,
    completed: bool,
    download: Option<PeerProbeDownload>,
}

struct PeerProbeDownload {
    stream: Option<QuicStream>,
    request_wire: [u8; dmesh_server::probe::PROBE_REQUEST_MAX],
    request_len: usize,
    request_offset: usize,
    reader: dmesh_server::probe::ProbeResponseReader,
    completed: bool,
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
    HeapPacketLease<'static, PACKETS, SLOT_SIZE>,
    CONTROL_QUEUE_CAPACITY,
> = quic_lite::packet_pool::PacketLeaseQueue::new();

pub(crate) enum NowReceiveError {
    NotReady,
    PoolFull,
    InvalidFrame,
    InvalidPeer,
    CommitFailed,
}

pub(crate) enum NowPayloadAdmission {
    Consumed,
    Control,
    Quic,
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
    let Some(mut writer) = acquire_packet_writer(0) else {
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
        #[cfg(feature = "rtos-stats")]
        let _submit_timer = BearerSubmitTimer::start();
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

/// The BLE L2CAP channel as a QUIC bearer, like the UART: one peer, one SDU per packet. The
/// link is encrypted by BLE itself (the pairing handler requires it), so the bearer adds no
/// cryptography of its own.
struct BleBearer;

impl PacketEgress<<FirmwarePool as quic_lite::PacketPool>::Buffer> for BleBearer {
    fn submit(
        &mut self,
        _peer: PeerL2Address,
        submission: EgressSubmission<<FirmwarePool as quic_lite::PacketPool>::Buffer>,
    ) -> Result<(), PacketSubmitError<<FirmwarePool as quic_lite::PacketPool>::Buffer>> {
        let connected = BLE_CONNECTED.load(Ordering::Acquire);
        let send = BLE_SEND.load(Ordering::Acquire);
        let link_up = connected != 0 && {
            let connected: fn() -> bool = unsafe { core::mem::transmute(connected) };
            connected()
        };
        if send == 0 || !link_up {
            submission.complete(PacketSendOutcome::Failed, 0);
            crate::main_runtime::request_quic_ingress();
            return Ok(());
        }
        let send: fn(&[u8]) -> u8 = unsafe { core::mem::transmute(send) };
        match send(submission.packet().bytes()) {
            0 => {
                submission.complete(PacketSendOutcome::Sent, 0);
                crate::main_runtime::request_quic_ingress();
                Ok(())
            }
            1 => {
                BLE_SEND_BLOCKED.store(true, Ordering::Release);
                Err(PacketSubmitError::WouldBlock(submission))
            }
            _ => {
                submission.complete(PacketSendOutcome::Failed, 0);
                crate::main_runtime::request_quic_ingress();
                Ok(())
            }
        }
    }
}

impl PacketBearer<FirmwarePool> for BleBearer {
    type AttachError = ();

    fn info(&self) -> BearerInfo {
        BearerInfo {
            name: BearerName::new("ble").expect("static bearer name is valid"),
            max_packet_size: quic_lite::DEFAULT_MAX_PACKET_SIZE,
            prefix_required: 0,
            suffix_required: 0,
            requires_packet_encryption: false,
            secure_link: true,
            nominal_bitrate_bps: 100_000,
            local_mac: None,
        }
    }

    fn attach(&mut self, context: BearerContext<FirmwarePool>) -> Result<(), Self::AttachError> {
        unsafe {
            core::ptr::addr_of_mut!(BLE_CONTEXT).write(core::mem::MaybeUninit::new(context));
        }
        BLE_READY.store(true, Ordering::Release);
        Ok(())
    }
}

/// Give the BLE bearer its link: `connected` reports the L2CAP channel is open and `send`
/// submits one SDU (0 accepted, 1 busy, other failure).
pub(crate) fn install_ble_coc_io(connected: fn() -> bool, send: fn(&[u8]) -> u8) {
    BLE_CONNECTED.store(connected as usize, Ordering::Release);
    BLE_SEND.store(send as usize, Ordering::Release);
}

/// Admit one SDU received on the BLE channel through the bearer's context.
pub(crate) fn receive_ble_coc(bytes: &[u8]) -> bool {
    if !BLE_READY.load(Ordering::Acquire) || bytes.is_empty() {
        return false;
    }
    let context = unsafe {
        (&*core::ptr::addr_of!(BLE_CONTEXT).cast::<BearerContext<FirmwarePool>>()).clone()
    };
    let Some(mut writer) = acquire_packet_writer(0) else {
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
    context.enqueue_packet(
        PacketMeta {
            bearer: context.bearer(),
            peer_l2_address: PeerL2Address::new(1).expect("BLE peer handle is nonzero"),
            received_at_us: unsafe { esp_idf_sys::esp_timer_get_time().max(0) as u64 },
        },
        packet,
    );
    crate::main_runtime::request_quic_ingress();
    true
}

/// The BLE link can take another SDU: release a packet retained after it was busy.
pub(crate) fn ble_coc_send_ready() {
    if !BLE_READY.load(Ordering::Acquire) || !BLE_SEND_BLOCKED.swap(false, Ordering::AcqRel) {
        return;
    }
    let context = unsafe {
        (&*core::ptr::addr_of!(BLE_CONTEXT).cast::<BearerContext<FirmwarePool>>()).clone()
    };
    context.send_ready();
}

struct Udp6Bearer;

// Private diagnostic mailbox, not a packet queue. The callback never waits:
// 0=free, 1=publishing, 2=ready, 3=owner reading. Busy samples are skipped.
#[cfg(feature = "rtos-stats")]
static UDP_TIMING_RX_STATE: AtomicUsize = AtomicUsize::new(0);
#[cfg(feature = "rtos-stats")]
static UDP_TIMING_RX: [AtomicUsize; 6] = [const { AtomicUsize::new(0) }; 6];
#[cfg(feature = "rtos-stats")]
static UDP_TIMING_RX_COUNT: AtomicUsize = AtomicUsize::new(0);
#[cfg(feature = "rtos-stats")]
static UDP_TIMING_TX_COUNT: AtomicUsize = AtomicUsize::new(0);

#[cfg(feature = "rtos-stats")]
fn packet_timing_fingerprint(bytes: &[u8]) -> u32 {
    bytes.iter().take(32).fold(2_166_136_261u32, |hash, byte| {
        (hash ^ u32::from(*byte)).wrapping_mul(16_777_619)
    })
}

#[cfg(feature = "rtos-stats")]
fn packet_sample_clock() -> Option<(u64, usize, usize)> {
    #[cfg(target_arch = "riscv32")]
    if esp_idf_sys::CONFIG_IDF_TARGET.as_slice() == b"esp32c6\0" {
        // Read the OS's latest UNIT1 latch without updating registers shared
        // with the tick ISR. This has tick resolution, not microsecond
        // accuracy, but is independent of UNIT0 rollback/repair.
        let reg = |offset: usize| unsafe {
            core::ptr::read_volatile((0x6000_a000usize + offset) as *const u32)
        };
        for _ in 0..3 {
            let lo = reg(0x4c);
            let hi = reg(0x48);
            if lo == reg(0x4c) {
                let us = ((u64::from(hi) << 32) | u64::from(lo)) / 16;
                return Some((
                    us,
                    2,
                    1_000_000usize.div_ceil(esp_idf_sys::configTICK_RATE_HZ as usize),
                ));
            }
        }
        return None;
    }
    Some((
        unsafe { esp_idf_sys::esp_timer_get_time().max(0) as u64 },
        1,
        0,
    ))
}

#[cfg(feature = "rtos-stats")]
fn sample_udp_receive(bytes: &[u8]) {
    if UDP_TIMING_RX_COUNT.fetch_add(1, Ordering::Relaxed) % 64 != 0
        || UDP_TIMING_RX_STATE
            .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
    {
        return;
    }
    let Some((received_at_us, source, resolution)) = packet_sample_clock() else {
        UDP_TIMING_RX_STATE.store(0, Ordering::Release);
        return;
    };
    let values = [
        received_at_us as u32 as usize,
        (received_at_us >> 32) as usize,
        packet_timing_fingerprint(bytes) as usize,
        bytes.len(),
        source,
        resolution,
    ];
    for (slot, value) in UDP_TIMING_RX.iter().zip(values) {
        slot.store(value, Ordering::Relaxed);
    }
    UDP_TIMING_RX_STATE.store(2, Ordering::Release);
}

#[cfg(feature = "rtos-stats")]
#[cold]
#[inline(never)]
fn report_udp_receive_sample() {
    if UDP_TIMING_RX_STATE
        .compare_exchange(2, 3, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        return;
    }
    let values = UDP_TIMING_RX
        .each_ref()
        .map(|slot| slot.load(Ordering::Relaxed));
    UDP_TIMING_RX_STATE.store(0, Ordering::Release);
    use dmesh_server::cbor::FieldValue::Unsigned as U;
    crate::wifi_esp::sta_diagnostic(
        "quic.packet_rx_sample",
        &[
            (1, U(values[0] as u64 | ((values[1] as u64) << 32))),
            (2, U(values[2] as u64)),
            (3, U(values[3] as u64)),
            (5, U(values[4] as u64)),
            (6, U(values[5] as u64)),
        ],
    );
}

impl PacketEgress<<FirmwarePool as quic_lite::PacketPool>::Buffer> for Udp6Bearer {
    fn submit(
        &mut self,
        peer: PeerL2Address,
        submission: EgressSubmission<<FirmwarePool as quic_lite::PacketPool>::Buffer>,
    ) -> Result<(), PacketSubmitError<<FirmwarePool as quic_lite::PacketPool>::Buffer>> {
        use crate::wifi_raw_udp6_esp::UdpTransmitResult;
        #[cfg(feature = "rtos-stats")]
        let _submit_timer = BearerSubmitTimer::start();
        let (packet, completion) = submission.into_parts();
        #[cfg(feature = "rtos-stats")]
        let timing_sample = (UDP_TIMING_TX_COUNT.fetch_add(1, Ordering::Relaxed) % 64 == 0)
            .then(packet_sample_clock)
            .flatten()
            .map(|(stamp, source, resolution)| {
                (
                    stamp,
                    source,
                    resolution,
                    packet_timing_fingerprint(packet.bytes()),
                    packet.bytes().len(),
                )
            });
        // Arm before submission so a concurrent completion cannot be lost
        // between a Busy result and publishing the wait state.
        UDP6_TX_WAITING.store(true, Ordering::Release);
        let (packet, sent) = if let Some(endpoint) = crate::wifi_raw_udp6_esp::peer_for_path(peer) {
            crate::wifi_raw_udp6_esp::transmit_udp6_owned(
                endpoint,
                crate::wifi_raw_udp6_esp::RAW_UDP6_PORT,
                packet,
            )
        } else {
            (packet, UdpTransmitResult::Failed)
        };
        #[cfg(feature = "rtos-stats")]
        if let Some((started_us, source, resolution, fingerprint, length)) = timing_sample {
            use dmesh_server::cbor::FieldValue::Unsigned as U;
            crate::wifi_esp::sta_diagnostic(
                "quic.packet_tx_sample",
                &[
                    (1, U(started_us)),
                    (2, U(u64::from(fingerprint))),
                    (3, U(length as u64)),
                    (
                        4,
                        U(match sent {
                            UdpTransmitResult::Accepted => 1,
                            UdpTransmitResult::Busy => 2,
                            UdpTransmitResult::Failed => 3,
                        }),
                    ),
                    (5, U(source as u64)),
                    (6, U(resolution as u64)),
                ],
            );
        }
        if sent == UdpTransmitResult::Busy {
            // Completion normally wakes us sooner. A blocked-only fallback
            // covers lost/racing callbacks and unrelated heap pressure; it
            // is not a periodic cadence for accepted packets or ingress.
            unsafe {
                UDP6_RETRY_AT_US =
                    Some((esp_idf_sys::esp_timer_get_time().max(0) as u64).saturating_add(10_000));
            }
            crate::main_runtime::request_connection_deadline_recheck();
            return Err(PacketSubmitError::WouldBlock(EgressSubmission::from_parts(
                packet, completion,
            )));
        }
        UDP6_TX_WAITING.store(false, Ordering::Release);
        UDP6_TX_READY_HINT.store(false, Ordering::Release);
        unsafe {
            UDP6_RETRY_AT_US = None;
        }
        if UDP6_EGRESS_REPORTED.fetch_add(1, Ordering::AcqRel) < 4 {
            let _ = crate::log_history::push_event(
                dmesh_server::log_watch::LEVEL_INFO,
                "udp6",
                "quic_egress",
                &[(
                    1,
                    dmesh_server::cbor::FieldValue::Bool(sent == UdpTransmitResult::Accepted),
                )],
            );
        }
        completion.complete(
            packet,
            if sent == UdpTransmitResult::Accepted {
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
            prefix_required: quic_lite::PACKET_PREFIX_RESERVE,
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
        initialize_runtime();
    }
    &mut **core::ptr::addr_of_mut!(RUNTIME)
}

// Keep the initialization frame off the steady-state owner/adapter stack.
// With size optimization this otherwise reserves about 2.5 KiB even when READY
// is true, leaving very little interrupt headroom in a small receive task.
#[cold]
#[inline(never)]
unsafe fn initialize_runtime() {
    if !READY.load(Ordering::Acquire) {
        POOL.resize(MIN_PACKETS)
            .expect("minimum firmware packet pool allocation succeeds");
        let mut embedded = quic_lite::AssociationLimits::embedded();
        // Outstanding reliable payload, not diagnostic history. Heap slots
        // grow on demand; these limits reserve no packet bytes at admission.
        #[cfg(target_arch = "riscv32")]
        {
            // Keep reliable send retention below Main's shared heap budget.
            // 32 payload records exhausted heap/driver RX headroom during
            // simultaneous upload/download; TCP uses 16 KiB here as well.
            embedded.history_packets = 16;
            embedded.transmission_records = 32;
            embedded.connection.max_stream_data = 16 * 1024;
        }
        let mut value = FirmwareRuntime::try_new_boxed(&POOL, embedded.connection)
            .expect("firmware QUIC runtime allocation succeeds");
        value
            .set_limits(quic_lite::NodeLimits::embedded())
            .expect("firmware QUIC node limits are valid");
        value
            .set_default_association_limits(embedded)
            .expect("firmware QUIC association limits are valid");
        #[cfg(feature = "uart-transport")]
        value
            .add_bearer(UartBearer)
            .expect("static UART bearer registration succeeds");
        let udp_bearer = value
            .add_bearer(Udp6Bearer)
            .expect("static UDP6 bearer registration succeeds");
        value.set_path_open_resolver(move |kind, address| {
            if kind != dmesh_server::transport_path::TransportId::UDP6.0 {
                return None;
            }
            crate::wifi_raw_udp6_esp::path_for_udp_address(address).map(|peer_l2_address| {
                quic_lite::CircuitNextHop {
                    bearer: udp_bearer,
                    peer_l2_address,
                }
            })
        });
        value
            .add_bearer(BleBearer)
            .expect("static BLE bearer registration succeeds");
        #[cfg(feature = "espnow-transport")]
        value
            .add_bearer(NowBearer)
            .expect("static ESP-NOW bearer registration succeeds");
        core::ptr::addr_of_mut!(RUNTIME).write(Box::into_raw(value));
        READY.store(true, Ordering::Release);
    }
}

/// Initialize the owner before radio callbacks can enqueue packets. Main's
/// UART pool startup also does this; Recovery has no UART input startup.
pub(crate) fn initialize() {
    unsafe {
        let _ = runtime();
    }
}

pub(crate) fn connection_delay_ms() -> Option<u32> {
    connection_delay_us().map(|delay| delay.div_ceil(1_000).min(u64::from(u32::MAX)) as u32)
}

/// Preserve sub-tick pacing deadlines for the serialized owner's one-shot
/// timer. Recovery's millisecond compatibility path remains unchanged.
pub(crate) fn connection_delay_us() -> Option<u64> {
    if !READY.load(Ordering::Acquire) {
        return None;
    }
    let now_us = unsafe { esp_idf_sys::esp_timer_get_time().max(0) as u64 };
    #[cfg(all(feature = "rtos-stats", target_arch = "riscv32"))]
    let now_us = observe_platform_clock(now_us);
    let runtime = unsafe { runtime() };
    let now_ms = now_us / 1_000;
    report_uart_receive_progress(runtime, now_ms);
    let transport_delay = runtime.next_deadline().map(|deadline| {
        deadline
            .saturating_sub(now_us)
            .min(u64::from(u32::MAX).saturating_mul(1_000))
    });
    let flash_delay = crate::flash::next_report_delay_ms(now_ms);
    let body_delay = body_poll_pending().then_some(BODY_POLL_MS);
    let pool_delay = unsafe { (&*core::ptr::addr_of!(POOL_POLICY)).shrink_deadline() }
        .map(|deadline| deadline.saturating_sub(now_ms).min(u64::from(u32::MAX)) as u32);
    let delay_ms = transport_delay
        .into_iter()
        .chain(unsafe { UDP6_RETRY_AT_US }.map(|deadline| deadline.saturating_sub(now_us)))
        .chain(flash_delay.map(|delay| u64::from(delay) * 1_000))
        .chain(body_delay.map(|delay| u64::from(delay) * 1_000))
        .chain(pool_delay.map(|delay| u64::from(delay) * 1_000))
        .min();
    if delay_ms.is_none_or(|delay| delay >= 1_000_000) {
        report_writer_wait(runtime, now_ms, delay_ms);
    }
    delay_ms
}

/// Existing owner checkpoint; the stats-only canary repairs proven awake C6
/// backsteps through the SDK, not by changing the transport's clock policy.
#[cfg(all(feature = "rtos-stats", target_arch = "riscv32"))]
fn observe_platform_clock(mut now_us: u64) -> u64 {
    if esp_idf_sys::CONFIG_IDF_TARGET.as_slice() != b"esp32c6\0" {
        return now_us;
    }
    static mut PREVIOUS: Option<(u64, u32)> = None;
    let ticks = unsafe { esp_idf_sys::xTaskGetTickCount() } as u32;
    let previous = unsafe {
        let slot = core::ptr::addr_of_mut!(PREVIOUS);
        let previous = slot.read();
        previous
    };
    if let Some((previous_us, previous_ticks)) = previous {
        if now_us < previous_us {
            now_us = report_platform_clock_rollback(previous_us, previous_ticks, now_us, ticks);
        }
    }
    unsafe {
        core::ptr::addr_of_mut!(PREVIOUS).write(Some((now_us, ticks)));
    }
    now_us
}

#[cfg(all(feature = "rtos-stats", target_arch = "riscv32"))]
#[cold]
#[inline(never)]
fn report_platform_clock_rollback(
    previous_us: u64,
    previous_ticks: u32,
    now_us: u64,
    ticks: u32,
) -> u64 {
    // Sticky load registers may become nonzero after our first SDK repair.
    // Reject a different load value (an unaccounted-for counter write).
    static mut EXPECTED_LOAD: (u32, u32) = (0, 0);
    // C6's raw systimer is 16 MHz. Read through the SDK snapshot routine,
    // not direct MMIO; FreeRTOS ticks are a separate accumulated observation.
    unsafe extern "C" {
        fn esp_timer_impl_get_counter_reg() -> u64;
    }
    let raw = unsafe { esp_timer_impl_get_counter_reg() };
    let after_us = unsafe { esp_idf_sys::esp_timer_get_time().max(0) as u64 };
    // C6 offsets from SDK soc/systimer_reg.h. Read only: do not request a
    // UNIT1 snapshot or interfere with the OS tick ISR. Its latest snapshot
    // can lag a tick. LO/HI/LO detects an ISR refresh during reading.
    let reg = |offset: usize| unsafe {
        core::ptr::read_volatile((0x6000_a000usize + offset) as *const u32)
    };
    let conf = reg(0);
    let load_hi = reg(0x0c);
    let load_lo = reg(0x10);
    let mut os_counter = 0u64;
    let mut os_consistent = false;
    for _ in 0..3 {
        let lo = reg(0x4c);
        let hi = reg(0x48);
        if lo == reg(0x4c) {
            os_counter = (u64::from(hi) << 32) | u64::from(lo);
            os_consistent = true;
            break;
        }
    }
    let power = crate::power_esp::status();
    let (sleep_exits, sleep_us, _, _) = crate::power_esp::automatic_sleep_metrics();
    use dmesh_server::cbor::FieldValue::Unsigned as U;
    crate::wifi_esp::sta_diagnostic(
        "quic.clock_rollback",
        &[
            (1, U(previous_us)),
            (2, U(u64::from(previous_ticks))),
            (3, U(now_us)),
            (4, U(u64::from(ticks))),
            (5, U(raw)),
            (6, U(after_us)),
            (7, U(u64::from(esp_idf_sys::configTICK_RATE_HZ))),
            (8, U(u64::from(power.cpu_mhz))),
            (9, U(u64::from(power.automatic_light_sleep))),
            (10, U(u64::from(power.light_sleep_entries))),
            (11, U(u64::from(sleep_exits))),
            (12, U(u64::from(sleep_us))),
            (13, U(u64::from(conf))),
            (14, U(u64::from(load_hi))),
            (15, U(u64::from(load_lo))),
            (16, U(os_counter)),
            (17, U(u64::from(os_consistent))),
        ],
    );
    let tick_hz = esp_idf_sys::configTICK_RATE_HZ as u32;
    let os_us = os_counter / 16;
    let tick_us = u64::from(ticks) * 1_000_000 / u64::from(tick_hz.max(1));
    let independent_matches =
        os_consistent && os_us.abs_diff(tick_us) <= 2_000_000 / u64::from(tick_hz.max(1));
    let expected_load = unsafe { core::ptr::addr_of!(EXPECTED_LOAD).read() };
    let awake = !power.automatic_light_sleep
        && power.light_sleep_entries == 0
        && sleep_exits == 0
        && (load_hi, load_lo) == expected_load
        && conf & (3 << 29) == (3 << 29)
        && independent_matches;
    if let Some(advance) = dmesh_server::clock_guard::rollback_advance_us(
        previous_us,
        now_us,
        previous_ticks,
        ticks,
        tick_hz,
        awake,
    ) {
        // Use the SDK's locked counter update. Never write the counter MMIO
        // ourselves; keep existing alarms and every native-clock consumer on
        // the same timeline. This experiment is limited to never-slept C6.
        unsafe extern "C" {
            fn esp_timer_private_advance(time_diff_us: i64);
        }
        unsafe {
            esp_timer_private_advance(advance as i64);
        }
        unsafe {
            core::ptr::addr_of_mut!(EXPECTED_LOAD).write((reg(0x0c), reg(0x10)));
        }
        let repaired_us = unsafe { esp_idf_sys::esp_timer_get_time().max(0) as u64 };
        crate::wifi_esp::sta_diagnostic(
            "clock.repaired",
            &[
                (1, U(now_us)),
                (2, U(advance)),
                (3, U(repaired_us)),
                (4, U(u64::from(ticks))),
            ],
        );
        return repaired_us;
    }
    after_us
}

/// Record long connection-timer waits without introducing a polling wake.
/// Radio deadlines may wake Main earlier; this is not actual slept time.
#[cold]
#[inline(never)]
fn report_writer_wait(runtime: &FirmwareRuntime, now_ms: u64, delay_us: Option<u64>) {
    static mut REPORT_AT_MS: u64 = 0;
    if now_ms < unsafe { REPORT_AT_MS } {
        return;
    }
    let streams = handler_streams();
    if !streams
        .iter()
        .any(|entry| entry.writer.as_ref().is_some_and(|writer| !writer.done))
    {
        return;
    }
    unsafe {
        REPORT_AT_MS = now_ms.saturating_add(5_000);
    }
    use dmesh_server::cbor::FieldValue::Unsigned as U;
    for entry in streams.iter() {
        let Some(writer) = entry.writer.as_ref().filter(|writer| !writer.done) else {
            continue;
        };
        let window = runtime.stream_send_window(&entry.stream);
        let snapshot = entry
            .stream
            .association_id()
            .and_then(|association| runtime.association_telemetry(association))
            .unwrap_or_default();
        crate::wifi_esp::sta_diagnostic(
            "quic.writer_wait",
            &[
                (1, U(entry.diagnostic_id)),
                (2, U(entry.stream.id())),
                (3, U(delay_us.unwrap_or(u64::MAX))),
                (4, U(u64::from(writer.blocked_reason))),
                (5, U(writer.generated_bytes)),
                (6, U(writer.accepted_bytes)),
                (7, U(window.as_ref().copied().unwrap_or(0))),
                (8, U(u64::from(window.is_err()))),
                (9, U(snapshot.bytes_in_flight)),
                (10, U(writer.carry.len() as u64)),
                (11, U(now_ms.saturating_sub(entry.last_ms))),
            ],
        );
    }
}

pub(crate) fn node_telemetry() -> quic_lite::NodeTelemetry {
    if !READY.load(Ordering::Acquire) {
        return quic_lite::NodeTelemetry::default();
    }
    unsafe { runtime() }.telemetry()
}

fn report_flash_progress(runtime: &FirmwareRuntime, now_ms: u64) {
    if crate::flash::report_progress(now_ms, |association| {
        runtime.association_telemetry(association)
    }) {
        let deadline_ms = runtime.next_deadline().map(|deadline| {
            deadline
                .saturating_sub(now_ms.saturating_mul(1000))
                .div_ceil(1000)
        });
        crate::flash::report_owner_progress(now_ms, deadline_ms, POOL.available());
    }
}

pub(crate) fn schedule_connection_timer() {
    if !READY.load(Ordering::Acquire) {
        return;
    }
    let now_us = unsafe { esp_idf_sys::esp_timer_get_time().max(0) as u64 };
    maintain_packet_pool(now_us / 1_000);
    let runtime = unsafe { runtime() };
    if unsafe { UDP6_RETRY_AT_US }.is_some_and(|deadline| deadline <= now_us) {
        unsafe {
            UDP6_RETRY_AT_US = None;
        }
        UDP6_TX_WAITING.store(false, Ordering::Release);
        UDP6_TX_READY_HINT.store(false, Ordering::Release);
        let context = unsafe {
            (&*core::ptr::addr_of!(UDP6_CONTEXT).cast::<BearerContext<FirmwarePool>>()).clone()
        };
        context.send_ready();
    }
    let _ = runtime.advance_time(now_us);
    // A pacing deadline may produce no control/retransmission packet while
    // making an application write eligible. Like the Tokio driver, always
    // resume pending stream producers after a timer turn; the runtime's bool
    // reports generated transport work, not application write readiness.
    crate::main_runtime::request_quic_ingress();
    drain_runtime_notifications(runtime);
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
        u32::try_from(POOL.capacity()).unwrap_or(u32::MAX),
        u32::try_from(POOL.available()).unwrap_or(u32::MAX),
    )
}

/// Transfer one UART-decoded packet through its bearer context.
///
/// The physical UART task stops here. QUIC parsing and application dispatch
/// run on the firmware owner task after the bearer's wake callback fires, so
/// neither the node nor handler working set is placed on the UART task stack.
pub(crate) fn receive_uart(packet: FirmwarePacket) {
    note_ingress_queued();
    let context = {
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
    #[cfg(feature = "rtos-stats")]
    sample_udp_receive(bytes);
    note_ingress_queued();
    if UDP6_INGRESS_REPORTED.fetch_add(1, Ordering::AcqRel) < 4 {
        let _ = crate::log_history::push_event(
            dmesh_server::log_watch::LEVEL_INFO,
            "udp6",
            "quic_ingress",
            &[(
                1,
                dmesh_server::cbor::FieldValue::Unsigned(bytes.len() as u64),
            )],
        );
    }
    let context = {
        assert!(UDP6_READY.load(Ordering::Acquire));
        unsafe {
            (&*core::ptr::addr_of!(UDP6_CONTEXT).cast::<BearerContext<FirmwarePool>>()).clone()
        }
    };
    let Some(mut writer) = acquire_packet_writer(0) else {
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

/// Enqueue a UDP datagram already received into a node-pool lease. Socket
/// adapters use this path so the payload is not copied into a second packet.
pub(crate) fn receive_udp6_packet(path: PeerL2Address, packet: FirmwarePacket) {
    #[cfg(feature = "rtos-stats")]
    sample_udp_receive(packet.bytes());
    note_ingress_queued();
    let context = {
        // Registration initializes the owner before UDP6_READY is published.
        // An RX task only uses the immutable ingress context; it must neither
        // initialize nor borrow the owner's mutable runtime.
        assert!(UDP6_READY.load(Ordering::Acquire));
        unsafe {
            (&*core::ptr::addr_of!(UDP6_CONTEXT).cast::<BearerContext<FirmwarePool>>()).clone()
        }
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
    let Some(mut writer) = acquire_packet_writer(0) else {
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
    A: FnOnce(crate::wifi_espnow_esp::EspNowPeer, &[u8]) -> NowPayloadAdmission,
{
    if !NOW_READY.load(Ordering::Acquire) {
        return Err(NowReceiveError::NotReady);
    }
    let context = unsafe {
        (&*core::ptr::addr_of!(NOW_CONTEXT).cast::<BearerContext<FirmwarePool>>()).clone()
    };
    let Some(mut writer) = acquire_packet_writer(0) else {
        return Err(NowReceiveError::PoolFull);
    };
    let Some((mac, len)) = parse(writer.payload_mut()) else {
        return Err(NowReceiveError::InvalidFrame);
    };
    if len > writer.payload_mut().len() {
        return Err(NowReceiveError::InvalidFrame);
    }
    let peer = crate::wifi_espnow_esp::EspNowPeer { mac };
    let admission = admit(peer, &writer.payload_mut()[..len]);
    if matches!(admission, NowPayloadAdmission::Consumed) {
        return Ok(false);
    }
    if matches!(admission, NowPayloadAdmission::Control) {
        let packet = writer.commit(len).ok_or(NowReceiveError::CommitFailed)?;
        PENDING_CONTROL_RX
            .try_push(ControlPeer::Now(peer), packet)
            .map_err(|_| NowReceiveError::PoolFull)?;
        crate::main_runtime::request_quic_ingress();
        return Ok(true);
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

/// This owner dispatches streams directly, rather than accepting associations
/// through a separate application task. Consume both notification queues so
/// short-lived command connections cannot retain lifecycle history forever.
fn drain_runtime_notifications(runtime: &mut FirmwareRuntime) {
    while runtime.next_association().is_some() {}
    while runtime.next_event().is_some() {}
}

/// Advance queued bearer ingress and dispatch complete request streams.
///
/// Main calls this only from its single event owner. It is intentionally not
/// public API: physical bearers enqueue through `BearerContext` and merely
/// wake that owner.
// Diagnostic placement experiment: reduce the C6 owner instruction-cache
// footprint. This remains task code and calls flash-resident functions; it
// is not safe to invoke while the flash cache is disabled.
#[cfg_attr(target_arch = "riscv32", link_section = ".iram1.text")]
pub(crate) fn progress() {
    #[cfg(feature = "tcp-stream")]
    crate::tcp_stream_esp::progress();
    let started_us = unsafe { esp_idf_sys::esp_timer_get_time().max(0) as u64 };
    maintain_packet_pool(unsafe { esp_idf_sys::esp_timer_get_time().max(0) as u64 } / 1_000);
    dispatch_control_requests();
    service_udp6_tx_ready_hint();
    let runtime = unsafe { runtime() };
    drain_runtime_notifications(runtime);
    let now_ms = (unsafe { esp_idf_sys::esp_timer_get_time().max(0) as u64 }) / 1_000;
    report_uart_receive_progress(runtime, now_ms);
    sweep_handler_streams(now_ms);
    report_flash_progress(runtime, now_ms);
    #[cfg(feature = "probe")]
    progress_directed_probe(runtime);
    INGRESS_DROPS_TOTAL.fetch_add(runtime.take_ingress_drops(), Ordering::Relaxed);
    // Keep the receive path resident for a short burst instead of pulling
    // every handler and the association deadline scan into cache per packet.
    // A finite burst preserves response service during continuous ingress.
    let mut ingress_batch = 0usize;
    loop {
        // Sample every ingress-service attempt, not merely the outer turn:
        // a long drain can already consume the callback's packet before the
        // next outer turn begins.
        let queued_us = INGRESS_QUEUED_US.swap(0, Ordering::AcqRel);
        if queued_us != 0 {
            let now = unsafe { esp_idf_sys::esp_timer_get_time().max(0) as usize };
            // A wrapping 32-bit timestamp is comparable only within half
            // its range. Do not promote a clock discontinuity to a 71-minute
            // queue delay; retain a separate diagnostic for that sample.
            let delay = now.wrapping_sub(queued_us);
            unsafe {
                if delay <= usize::MAX / 2 {
                    OWNER_MAX_QUEUE_US = OWNER_MAX_QUEUE_US.max(delay as u64);
                } else {
                    OWNER_CLOCK_DISCONTINUITIES += 1;
                }
            }
        }
        let ingress_started_us = unsafe { esp_idf_sys::esp_timer_get_time().max(0) as u64 };
        let processed = match runtime.progress_with_stream(|stream, offset, fin, bytes| {
            // Data on a stream this node opened (the response of a probe it
            // runs as a client) is not a request.
            #[cfg(feature = "probe")]
            if let Some(result) = peer_probe_chunk(&stream, fin, bytes) {
                return result;
            }
            Ok(ingest_handler_chunk(stream, offset, fin, bytes, now_ms))
        }) {
            Ok(true) => true,
            Ok(false) => false,
            Err(error) => {
                report_ingress_error(error);
                false
            }
        };
        let ingress_elapsed_us = (unsafe { esp_idf_sys::esp_timer_get_time().max(0) as u64 })
            .saturating_sub(ingress_started_us);
        unsafe {
            OWNER_INGRESS_TOTAL_US += ingress_elapsed_us;
            OWNER_INGRESS_MAX_US = OWNER_INGRESS_MAX_US.max(ingress_elapsed_us);
        }
        while let Some(chunk) = runtime.next_stream_chunk() {
            queue_handler_chunk(chunk.stream, chunk.offset, chunk.fin, &chunk.bytes, now_ms);
        }
        ingress_batch += usize::from(processed);
        // Batch ingress without delaying an already-due QUIC timer. A
        // separate work ceiling lets radio/profile services run even under
        // continuous ingress; it is not a periodic packet-processing tick.
        let now_us = unsafe { esp_idf_sys::esp_timer_get_time().max(0) as u64 };
        let owner_budget_expired = now_us.saturating_sub(started_us) >= 20_000;
        if processed && ingress_batch < 4 && !owner_budget_expired {
            continue;
        }
        ingress_batch = 0;
        drain_runtime_notifications(runtime);
        service_handler_streams(runtime, now_us / 1_000);
        if !processed {
            break;
        }
        if runtime
            .next_deadline()
            .is_some_and(|deadline| deadline <= now_us)
            || owner_budget_expired
        {
            crate::main_runtime::request_quic_ingress();
            break;
        }
    }
    maintain_packet_pool(unsafe { esp_idf_sys::esp_timer_get_time().max(0) as u64 } / 1_000);
    let elapsed_us =
        (unsafe { esp_idf_sys::esp_timer_get_time().max(0) as u64 }).saturating_sub(started_us);
    unsafe {
        OWNER_TURNS = OWNER_TURNS.saturating_add(1);
        OWNER_TOTAL_US = OWNER_TOTAL_US.saturating_add(elapsed_us);
        OWNER_MAX_TURN_US = OWNER_MAX_TURN_US.max(elapsed_us);
    }
    report_transport_progress(runtime, handler_clock_ms());
    #[cfg(feature = "rtos-stats")]
    report_udp_receive_sample();
    crate::main_runtime::request_connection_deadline_recheck();
}

/// Keep diagnostic decoding and UART output off the steady-state owner path.
#[cold]
#[inline(never)]
fn report_uart_receive_progress(runtime: &FirmwareRuntime, now_ms: u64) {
    static mut REPORT_AT_MS: u64 = 0;
    static mut LAST_RX_BYTES: u32 = 0;
    let uart = crate::uart_esp::receive_diagnostics();
    if now_ms < unsafe { REPORT_AT_MS } || uart[0] == unsafe { LAST_RX_BYTES } {
        return;
    }
    unsafe {
        REPORT_AT_MS = now_ms.saturating_add(5_000);
        LAST_RX_BYTES = uart[0];
    }
    use dmesh_server::cbor::FieldValue::Unsigned as U;
    crate::wifi_esp::sta_diagnostic(
        "uart.rx_progress",
        &[
            (1, U(u64::from(uart[0]))),
            (2, U(u64::from(uart[1]))),
            (3, U(u64::from(uart[2]))),
            (4, U(u64::from(uart[3]))),
            (5, U(u64::from(uart[4]))),
            (6, U(u64::from(uart[5]))),
            (7, U(u64::from(uart[6]))),
            (8, U(runtime.telemetry().live_associations)),
            (9, U(POOL.available() as u64)),
            (10, U(INGRESS_DROPS_TOTAL.load(Ordering::Relaxed) as u64)),
        ],
    );
}

fn report_ingress_error(error: QuicNodeEgressError) {
    if !INGRESS_ERROR_REPORTED.swap(true, Ordering::AcqRel) {
        let detail = match error {
            QuicNodeEgressError::Association(_) => b"association".as_slice(),
            QuicNodeEgressError::Transport(quic_lite::Error::BufferTooSmall) => b"buffer-too-small",
            QuicNodeEgressError::Transport(quic_lite::Error::Truncated) => b"truncated",
            QuicNodeEgressError::Transport(quic_lite::Error::Invalid) => b"invalid",
            QuicNodeEgressError::Transport(quic_lite::Error::Blocked) => b"blocked",
            QuicNodeEgressError::Transport(quic_lite::Error::DatagramUnsupported) => {
                b"datagram-unsupported"
            }
            QuicNodeEgressError::Transport(quic_lite::Error::DatagramTooLarge) => {
                b"datagram-too-large"
            }
            QuicNodeEgressError::Transport(quic_lite::Error::InvalidVarint) => b"invalid-varint",
            QuicNodeEgressError::Transport(quic_lite::Error::FlowControl) => b"flow-control",
            QuicNodeEgressError::Transport(quic_lite::Error::StreamLimit) => b"stream-limit",
            QuicNodeEgressError::Transport(quic_lite::Error::PathLimit) => b"path-limit",
            QuicNodeEgressError::Transport(quic_lite::Error::PacketNumberExhausted) => {
                b"packet-number-exhausted"
            }
            QuicNodeEgressError::Transport(quic_lite::Error::WrongConnectionId) => {
                b"wrong-connection-id"
            }
            QuicNodeEgressError::Transport(quic_lite::Error::PeerRestarted) => b"peer-restarted",
            QuicNodeEgressError::Transport(quic_lite::Error::BootstrapInvalid) => {
                b"bootstrap-invalid"
            }
            QuicNodeEgressError::Transport(quic_lite::Error::HistoryFull) => b"history-full",
            QuicNodeEgressError::Transport(quic_lite::Error::RetransmissionTooLarge) => {
                b"retransmission-too-large"
            }
            QuicNodeEgressError::PoolUnavailable => b"pool-unavailable",
            QuicNodeEgressError::InvalidPoolLayout => b"invalid-pool-layout",
            QuicNodeEgressError::MissingEgressAddress => b"missing-egress-address",
            QuicNodeEgressError::MissingBearer => b"missing-bearer",
            QuicNodeEgressError::BearerBusy => b"bearer-busy",
            QuicNodeEgressError::StreamEventsFull => b"stream-events-full",
            QuicNodeEgressError::AssociationTimedOut => b"association-timeout",
            QuicNodeEgressError::CircuitBusy => b"circuit-busy",
            QuicNodeEgressError::PathSetupAttemptsExhausted => b"path-attempts-exhausted",
            QuicNodeEgressError::SetupRejected(_) => b"setup-rejected",
        };
        let detail = core::str::from_utf8(detail).unwrap_or("unknown");
        let _ = crate::log_history::push_event(
            dmesh_server::log_watch::LEVEL_ERROR,
            "quic",
            "egress_error",
            &[(1, dmesh_server::cbor::FieldValue::Text(detail))],
        );
    }
}

static INGRESS_DROPS_TOTAL: AtomicUsize = AtomicUsize::new(0);
static mut TRANSPORT_REPORT_AT_MS: u64 = 0;
static INGRESS_QUEUED_US: AtomicUsize = AtomicUsize::new(0);
// Only the serialized owner accesses these cumulative diagnostic scalars.
static mut OWNER_TURNS: u64 = 0;
static mut OWNER_TOTAL_US: u64 = 0;
static mut OWNER_MAX_TURN_US: u64 = 0;
static mut OWNER_MAX_QUEUE_US: u64 = 0;
static mut OWNER_CLOCK_DISCONTINUITIES: u64 = 0;
static mut OWNER_INGRESS_TOTAL_US: u64 = 0;
static mut OWNER_INGRESS_MAX_US: u64 = 0;
static mut OWNER_HANDLER_TOTAL_US: u64 = 0;
static mut OWNER_HANDLER_MAX_US: u64 = 0;
// Serialized-owner diagnostics, cumulative since boot. Elapsed durations
// include preemption; compare with RTOS runtime rather than calling them CPU.
static mut RESPONSE_ATTEMPTS: u64 = 0;
static mut RESPONSE_BLOCKED: u64 = 0;
static mut RESPONSE_READ_CALLS: u64 = 0;
static mut RESPONSE_READ_US: u64 = 0;
static mut RESPONSE_WRITE_CALLS: u64 = 0;
static mut RESPONSE_WRITE_US: u64 = 0;
static mut RESPONSE_WRITE_MAX_US: u64 = 0;
static mut RESPONSE_ACCEPTED_BYTES: u64 = 0;
static mut RESPONSE_WRITE_BLOCKED: u64 = 0;
static mut RESPONSE_WINDOW_US: u64 = 0;
static mut RESPONSE_BEARER_US: u64 = 0;
static mut RESPONSE_BLOCKED_REASONS: [u64; 8] = [0; 8];

// Diagnostic builds only. This measures synchronous adapter submission,
// including framing/completion callbacks and preemption, not radio delivery
// or CPU time. The serialized owner submits UART/UDP responses here.
#[cfg(feature = "rtos-stats")]
static mut BEARER_SUBMIT_US: u64 = 0;
#[cfg(feature = "rtos-stats")]
struct BearerSubmitTimer(u64);
#[cfg(feature = "rtos-stats")]
impl BearerSubmitTimer {
    fn start() -> Self {
        Self(unsafe { esp_idf_sys::esp_timer_get_time().max(0) as u64 })
    }
}
#[cfg(feature = "rtos-stats")]
impl Drop for BearerSubmitTimer {
    fn drop(&mut self) {
        let elapsed =
            (unsafe { esp_idf_sys::esp_timer_get_time().max(0) as u64 }).saturating_sub(self.0);
        unsafe {
            BEARER_SUBMIT_US = BEARER_SUBMIT_US.saturating_add(elapsed);
        }
    }
}

// Temporary CPU-share diagnosis for the core running the serialized owner.
// The existing RTOS tick supplies samples; no task, timer, allocation or
// formatting is added. These are sampled task shares, not cycle accounting
// (interrupt execution and sub-tick scheduling can bias them).
static OWNER_SAMPLE_TASK: AtomicUsize = AtomicUsize::new(0);
static OWNER_SAMPLE_IDLE_TASK: AtomicUsize = AtomicUsize::new(0);
static OWNER_SAMPLE_ACTIVE: AtomicBool = AtomicBool::new(false);
static OWNER_SAMPLE_HOOK_STATUS: AtomicUsize = AtomicUsize::new(usize::MAX);
static OWNER_CPU_SAMPLES: AtomicUsize = AtomicUsize::new(0);
static IDLE_CPU_SAMPLES: AtomicUsize = AtomicUsize::new(0);
static OTHER_CPU_SAMPLES: AtomicUsize = AtomicUsize::new(0);
static CACHE_OFF_CPU_SAMPLES: AtomicUsize = AtomicUsize::new(0);
#[cfg(target_arch = "riscv32")]
static OWNER_PC_SAMPLES: [AtomicUsize; 64] = [const { AtomicUsize::new(0) }; 64];

unsafe extern "C" {
    // ESP-IDF esp_private/cache_utils.h; this helper is IRAM-resident.
    fn spi_flash_cache_enabled() -> bool;
}

#[link_section = ".iram1.text"]
unsafe extern "C" fn sample_owner_cpu_tick() {
    if !OWNER_SAMPLE_ACTIVE.load(Ordering::Acquire) {
        return;
    }
    // Some SDK task lookup functions are flash-resident even though the
    // RTOS tick and this callback are in IRAM. Skip cache-off erase/write
    // intervals instead of calling through an unavailable flash cache.
    if !spi_flash_cache_enabled() {
        CACHE_OFF_CPU_SAMPLES.fetch_add(1, Ordering::Relaxed);
        return;
    }
    let task = esp_idf_sys::xTaskGetCurrentTaskHandle() as usize;
    let counter = if task == OWNER_SAMPLE_TASK.load(Ordering::Relaxed) {
        &OWNER_CPU_SAMPLES
    } else if task == OWNER_SAMPLE_IDLE_TASK.load(Ordering::Relaxed) {
        &IDLE_CPU_SAMPLES
    } else {
        &OTHER_CPU_SAMPLES
    };
    let sequence = counter.fetch_add(1, Ordering::Relaxed);
    #[cfg(not(target_arch = "riscv32"))]
    let _ = sequence;
    #[cfg(target_arch = "riscv32")]
    if task == OWNER_SAMPLE_TASK.load(Ordering::Relaxed) {
        // RISC-V trap entry preserves the interrupted PC in mepc until trap
        // return. Keep a rolling sample, with no allocation or ISR logging.
        let pc: usize;
        core::arch::asm!("csrr {}, mepc", out(reg) pc, options(nomem, nostack));
        OWNER_PC_SAMPLES[sequence % OWNER_PC_SAMPLES.len()].store(pc, Ordering::Relaxed);
    }
}

#[cfg(target_arch = "riscv32")]
fn report_owner_pc_samples() {
    use dmesh_server::cbor::FieldValue::Unsigned as U;
    let active = OWNER_SAMPLE_ACTIVE.swap(false, Ordering::AcqRel);
    let sequence = OWNER_CPU_SAMPLES.load(Ordering::Relaxed);
    let samples = core::array::from_fn::<_, 64, _>(|i| OWNER_PC_SAMPLES[i].load(Ordering::Relaxed));
    OWNER_SAMPLE_ACTIVE.store(active, Ordering::Release);
    for (batch, pcs) in samples.chunks(16).enumerate() {
        let mut fields = [(0, U(0)); 18];
        fields[0] = (1, U(sequence as u64));
        fields[1] = (2, U(batch as u64));
        for (index, pc) in pcs.iter().enumerate() {
            fields[index + 2] = (index as u64 + 3, U(*pc as u64));
        }
        crate::wifi_esp::sta_diagnostic("quic.owner_pc", &fields);
    }
}

fn sample_owner_cpu_while_active(active: bool) {
    if active && OWNER_SAMPLE_HOOK_STATUS.load(Ordering::Relaxed) == usize::MAX {
        unsafe {
            OWNER_SAMPLE_TASK.store(
                esp_idf_sys::xTaskGetCurrentTaskHandle() as usize,
                Ordering::Relaxed,
            );
            OWNER_SAMPLE_IDLE_TASK.store(
                esp_idf_sys::xTaskGetIdleTaskHandle() as usize,
                Ordering::Relaxed,
            );
            // Only the calling core is sampled on dual-core ESPs.
            let result = esp_idf_sys::esp_register_freertos_tick_hook(Some(sample_owner_cpu_tick));
            OWNER_SAMPLE_HOOK_STATUS.store(result as u32 as usize, Ordering::Relaxed);
        }
    }
    OWNER_SAMPLE_ACTIVE.store(
        active && OWNER_SAMPLE_HOOK_STATUS.load(Ordering::Relaxed) == 0,
        Ordering::Release,
    );
}

fn note_ingress_queued() {
    let now = unsafe { esp_idf_sys::esp_timer_get_time().max(0) as usize }.max(1);
    let _ = INGRESS_QUEUED_US.compare_exchange(0, now, Ordering::AcqRel, Ordering::Relaxed);
}

/// Private cache-bus diagnostics, sampled only from the serialized owner.
#[cfg(target_arch = "riscv32")]
fn report_cache_accesses() {
    // IDF's chip cfg is not propagated to this dependency crate. Use the
    // generated target constant, so another RISC-V ESP never reads C6 MMIO.
    if esp_idf_sys::CONFIG_IDF_TARGET.as_slice() != b"esp32c6\0" {
        return;
    }
    // SDK soc/esp32c6/register/soc/extmem_reg.h. These cache bus counters
    // are separate from the CPU cycle counter used by SDK timekeeping.
    // Enable only statistics: do not reset counters, change cache geometry,
    // disable either bus, or enable an interrupt. Counts are wrapping u32
    // totals for all CPU activity, not just this task.
    let base = esp_idf_sys::DR_REG_EXTMEM_BASE as usize;
    let control = (base + 0x178) as *mut u32;
    let enabled = (1 << 4) | (1 << 5);
    unsafe {
        let previous = core::ptr::read_volatile(control);
        if previous & enabled != enabled {
            // Never echo the write-trigger counter-clear bits.
            core::ptr::write_volatile(control, (previous & !((1 << 20) | (1 << 21))) | enabled);
        }
    }
    use dmesh_server::cbor::FieldValue::Unsigned as U;
    let read = |offset| unsafe {
        U(u64::from(core::ptr::read_volatile(
            (base + offset) as *const u32,
        )))
    };
    crate::wifi_esp::sta_diagnostic(
        "quic.cache_progress",
        &[
            (1, read(0x178)),
            (2, read(0x1bc)),
            (3, read(0x1c0)),
            (4, read(0x1c4)),
            (5, read(0x1c8)),
            (6, read(0x1cc)),
            (7, read(0x1d0)),
            (8, read(0x1d4)),
            (9, read(0x1d8)),
        ],
    );
    // Read-only configuration evidence, not values inferred from build flags.
    // SDK C6 ROM cache.h and soc/{spi_mem,pcr}_reg.h. Keep raw clock-source
    // and divider registers so host analysis can reject unsupported sources.
    unsafe extern "C" {
        fn Cache_Get_ICache_Line_Size() -> u32;
    }
    let read_register =
        |address: usize| unsafe { U(u64::from(core::ptr::read_volatile(address as *const u32))) };
    let spi = esp_idf_sys::DR_REG_SPI0_BASE as usize;
    let pcr = esp_idf_sys::DR_REG_PCR_BASE as usize;
    // Read RDID only once on the serialized owner, not once per packet or
    // every report. Capacity alone cannot establish quad-mode support.
    // ESP-IDF's ID packs manufacturer in bits 23:16 and chip ID in 15:0.
    static mut FLASH_ID: Option<(u32, i32)> = None;
    // This diagnostic is only called by the serialized QUIC owner.
    let (flash_id, flash_id_status) = unsafe {
        match FLASH_ID {
            Some(value) => value,
            None => {
                let mut id = 0;
                let status = esp_idf_sys::esp_flash_read_id(core::ptr::null_mut(), &mut id);
                FLASH_ID = Some((id, status));
                (id, status)
            }
        }
    };
    crate::wifi_esp::sta_diagnostic(
        "quic.cache_config",
        &[
            (1, U(u64::from(unsafe { Cache_Get_ICache_Line_Size() }))),
            (2, read_register(spi + 0x14)),
            (3, read_register(spi + 0x08)),
            (4, read_register(pcr + 0x1c)),
            (5, read_register(pcr + 0x110)),
            (6, U(u64::from(flash_id))),
            (
                7,
                dmesh_server::cbor::FieldValue::Signed(i64::from(flash_id_status)),
            ),
        ],
    );
}

/// Private debugging event, emitted from existing owner progress, not a new
/// telemetry API or periodic task. Use the existing generic circuit snapshot;
/// there is no adapter-owned RTT/congestion ledger. One row per association.
#[cfg(feature = "rtos-stats")]
fn report_rtos_tasks() {
    use dmesh_server::cbor::FieldValue::{Text as T, Unsigned as U};
    // vTaskSuspendAll is core-local on ESP-IDF's non-SMP dual-core port.
    // Until names can be copied under its shared task-list lock, only report
    // on single-core targets; another core could otherwise delete a task.
    if esp_idf_sys::CONFIG_FREERTOS_NUMBER_OF_CORES != 1 {
        return;
    }
    // Owner-only scratch. No heap allocation or logging while the scheduler
    // is suspended. Copy names before resuming: task-name pointers become
    // invalid when a task is deleted. Zero returned rows means insufficient
    // capacity, not zero CPU usage. Snapshot cost is reported separately.
    const CAPACITY: usize = 32;
    #[derive(Clone, Copy)]
    struct Row {
        name: [u8; 16],
        number: u64,
        runtime: u64,
        priority: u64,
        state: u64,
        stack_free: u64,
    }
    static mut STATUS: [esp_idf_sys::TaskStatus_t; CAPACITY] =
        [const { unsafe { core::mem::zeroed() } }; CAPACITY];
    static mut ROWS: [Row; CAPACITY] = [Row {
        name: [0; 16],
        number: 0,
        runtime: 0,
        priority: 0,
        state: 0,
        stack_free: 0,
    }; CAPACITY];
    unsafe {
        let started = esp_idf_sys::esp_timer_get_time();
        let mut total = 0;
        esp_idf_sys::vTaskSuspendAll();
        let count = esp_idf_sys::uxTaskGetSystemState(
            core::ptr::addr_of_mut!(STATUS).cast(),
            CAPACITY as _,
            &mut total,
        ) as usize;
        let status = core::ptr::addr_of!(STATUS).cast::<esp_idf_sys::TaskStatus_t>();
        let rows = core::ptr::addr_of_mut!(ROWS).cast::<Row>();
        for index in 0..count.min(CAPACITY) {
            let task = &*status.add(index);
            let row = &mut *rows.add(index);
            row.name = [0; 16];
            if !task.pcTaskName.is_null() {
                for offset in 0..15 {
                    let byte = *task.pcTaskName.add(offset) as u8;
                    if byte == 0 {
                        break;
                    }
                    row.name[offset] = byte;
                }
            }
            row.number = task.xTaskNumber as u64;
            row.runtime = task.ulRunTimeCounter as u64;
            row.priority = task.uxCurrentPriority as u64;
            row.state = task.eCurrentState as u64;
            row.stack_free = task.usStackHighWaterMark as u64;
        }
        esp_idf_sys::xTaskResumeAll();
        let elapsed = esp_idf_sys::esp_timer_get_time().saturating_sub(started) as u64;
        crate::wifi_esp::sta_diagnostic(
            "quic.rtos_snapshot",
            &[
                (1, U(total as u64)),
                (2, U(count as u64)),
                (3, U(elapsed)),
                (4, U(CAPACITY as u64)),
            ],
        );
        for index in 0..count.min(CAPACITY) {
            let row = &*rows.add(index);
            let length = row.name.iter().position(|byte| *byte == 0).unwrap_or(16);
            let name = core::str::from_utf8(&row.name[..length]).unwrap_or("?");
            crate::wifi_esp::sta_diagnostic(
                "quic.rtos_task",
                &[
                    (1, U(total as u64)),
                    (2, U(row.number)),
                    (3, T(name)),
                    (4, U(row.runtime)),
                    (5, U(row.priority)),
                    (6, U(row.state)),
                    (7, U(row.stack_free)),
                ],
            );
        }
    }
}

fn report_transport_progress(runtime: &FirmwareRuntime, now_ms: u64) {
    let streams = handler_streams();
    sample_owner_cpu_while_active(!streams.is_empty());
    if streams.is_empty() || now_ms < unsafe { TRANSPORT_REPORT_AT_MS } {
        return;
    }
    unsafe {
        TRANSPORT_REPORT_AT_MS = now_ms.saturating_add(5_000);
    }
    // Sample once per report, not per packet or association. These are the
    // same observations exposed by telemetry.memory; post-transfer free heap
    // alone hides transient exhaustion while reliable payload is retained.
    let memory = crate::shared_ingress_esp::memory_stats();
    #[cfg(feature = "rtos-stats")]
    report_rtos_tasks();
    #[cfg(target_arch = "riscv32")]
    report_cache_accesses();
    #[cfg(target_arch = "riscv32")]
    report_owner_pc_samples();
    use dmesh_server::cbor::FieldValue::Unsigned as U;
    // Keep the node-wide heap sample separate: adding fields to the large
    // owner event can exceed the fixed 256-byte structured-log encoder.
    crate::wifi_esp::sta_diagnostic(
        "quic.memory",
        &[
            (1, U(u64::from(memory.free_internal_bytes))),
            (2, U(u64::from(memory.min_free_internal_bytes))),
            (3, U(u64::from(memory.largest_internal_block_bytes))),
        ],
    );
    let tx_done = crate::wifi_raw_udp6_esp::ethernet_tx_done_diagnostics();
    crate::wifi_esp::sta_diagnostic(
        "quic.tx_done",
        &[
            (1, U(u64::from(tx_done[0]))),
            (2, U(u64::from(tx_done[1]))),
            (3, U(u64::from(tx_done[2]))),
            (4, U(u64::from(tx_done[3]))),
        ],
    );
    crate::wifi_esp::sta_diagnostic(
        "quic.response_progress",
        &[
            (1, U(unsafe { RESPONSE_ATTEMPTS })),
            (2, U(unsafe { RESPONSE_BLOCKED })),
            (3, U(unsafe { RESPONSE_READ_CALLS })),
            (4, U(unsafe { RESPONSE_READ_US })),
            (5, U(unsafe { RESPONSE_WRITE_CALLS })),
            (6, U(unsafe { RESPONSE_WRITE_US })),
            (7, U(unsafe { RESPONSE_WRITE_MAX_US })),
            (8, U(unsafe { RESPONSE_ACCEPTED_BYTES })),
            (9, U(unsafe { RESPONSE_WRITE_BLOCKED })),
            (10, U(unsafe { RESPONSE_BEARER_US })),
            (11, U(unsafe { RESPONSE_WINDOW_US })),
        ],
    );
    crate::wifi_esp::sta_diagnostic(
        "quic.write_pressure",
        &[
            (1, U(unsafe { RESPONSE_BLOCKED_REASONS[0] })),
            (2, U(unsafe { RESPONSE_BLOCKED_REASONS[1] })),
            (3, U(unsafe { RESPONSE_BLOCKED_REASONS[2] })),
            (4, U(unsafe { RESPONSE_BLOCKED_REASONS[3] })),
            (5, U(unsafe { RESPONSE_BLOCKED_REASONS[4] })),
            (6, U(unsafe { RESPONSE_BLOCKED_REASONS[5] })),
            (7, U(unsafe { RESPONSE_BLOCKED_REASONS[6] })),
            (8, U(unsafe { RESPONSE_BLOCKED_REASONS[7] })),
        ],
    );
    for (index, entry) in streams.iter().enumerate() {
        report_handler_state("quic.handler_progress", entry, now_ms);
        let Some(association) = entry.stream.association_id() else {
            continue;
        };
        if streams[..index]
            .iter()
            .any(|other| other.stream.association_id() == Some(association))
        {
            continue;
        }
        let mut circuits = [quic_lite::CircuitInfo::default(); 1];
        if runtime.circuits(association, &mut circuits) == 0 {
            continue;
        }
        let circuit = circuits[0];
        let (tx_calls, tx_total_us, tx_max_us) = crate::wifi_raw_udp6_esp::tx_submit_timing();
        let (native_tx_failures, native_tx_error, native_tx_error_ms) =
            crate::wifi_raw_udp6_esp::tx_submit_failure_details();
        // Keep native-driver diagnostics separate: the owner report is already
        // close to the shared 256-byte log encoder's capacity.
        crate::wifi_esp::sta_diagnostic(
            "quic.tx_submit",
            &[
                (1, U(u64::from(native_tx_failures))),
                (2, U(u64::from(native_tx_error))),
                (3, U(u64::from(native_tx_error_ms))),
            ],
        );
        {
            let memory = crate::wifi_raw_udp6_esp::tx_failure_memory();
            crate::wifi_esp::sta_diagnostic(
                "quic.tx_memory",
                &[
                    (1, U(u64::from(memory[0]))),
                    (2, U(u64::from(memory[1]))),
                    (3, U(u64::from(memory[2]))),
                    (4, U(u64::from(memory[3]))),
                ],
            );
        }
        let power = crate::power_esp::status();
        let snapshot = runtime
            .association_telemetry(association)
            .unwrap_or_default();
        let transport = snapshot.transport;
        // Private stall diagnostic. The deadline is node-wide, not a promise
        // that this stream's next packet is writable; no formatting or new
        // per-packet timing calls are added.
        let window = runtime.stream_send_window(&entry.stream);
        crate::wifi_esp::sta_diagnostic(
            "quic.recovery_progress",
            &[
                (1, U(entry.stream.id())),
                (2, U(window.as_ref().copied().unwrap_or(0))),
                (3, U(u64::from(window.is_err()))),
                (4, U(runtime.next_deadline().unwrap_or(u64::MAX))),
                (5, U(now_ms.saturating_mul(1_000))),
                (6, U(snapshot.peer_sent_data)),
                (7, U(snapshot.peer_max_data)),
                (8, U(snapshot.bytes_in_flight)),
                (
                    9,
                    U(u64::from(
                        snapshot.largest_acked_by_peer.unwrap_or(u32::MAX),
                    )),
                ),
            ],
        );
        crate::wifi_esp::sta_diagnostic(
            "quic.owner_progress",
            &[
                (1, U(entry.stream.id())),
                (2, U(circuit.srtt_us as u64)),
                (3, U(circuit.min_rtt_us as u64)),
                (4, U(circuit.cwnd_bytes as u64)),
                (5, U(circuit.bytes_in_flight as u64)),
                (6, U(circuit.packets_lost)),
                (7, U(circuit.spurious_losses)),
                (8, U(circuit.retransmitted_packets)),
                (9, U(POOL.capacity() as u64)),
                (10, U(POOL.available() as u64)),
                (11, U(INGRESS_DROPS_TOTAL.load(Ordering::Relaxed) as u64)),
                (12, U(unsafe { OWNER_TURNS })),
                (13, U(unsafe { OWNER_TOTAL_US })),
                (14, U(unsafe { OWNER_MAX_TURN_US })),
                (15, U(unsafe { OWNER_MAX_QUEUE_US })),
                (16, U(crate::shared_ingress_esp::drops() as u64)),
                (17, U(unsafe { OWNER_INGRESS_TOTAL_US })),
                (18, U(unsafe { OWNER_INGRESS_MAX_US })),
                (19, U(unsafe { OWNER_HANDLER_TOTAL_US })),
                (20, U(unsafe { OWNER_HANDLER_MAX_US })),
                (21, U(tx_calls as u64)),
                (22, U(tx_total_us as u64)),
                (23, U(tx_max_us as u64)),
                (24, U(unsafe { OWNER_CLOCK_DISCONTINUITIES })),
                (
                    25,
                    U(crate::wifi_esp::modem_power_save_mode().unwrap_or(u32::MAX) as u64),
                ),
                (26, U(OWNER_CPU_SAMPLES.load(Ordering::Relaxed) as u64)),
                (27, U(IDLE_CPU_SAMPLES.load(Ordering::Relaxed) as u64)),
                (28, U(OTHER_CPU_SAMPLES.load(Ordering::Relaxed) as u64)),
                (
                    29,
                    U(OWNER_SAMPLE_HOOK_STATUS.load(Ordering::Relaxed) as u64),
                ),
                (30, U(CACHE_OFF_CPU_SAMPLES.load(Ordering::Relaxed) as u64)),
                (31, U(u64::from(power.cpu_mhz))),
                (32, U(u64::from(power.min_mhz))),
                (33, U(u64::from(power.max_mhz))),
                (34, U(transport.loss_packet_threshold_packets)),
                (35, U(transport.loss_time_threshold_packets)),
                (36, U(transport.pto_retransmitted_packets)),
                (37, U(transport.submission_failures)),
            ],
        );
    }
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
    /// Private diagnostic, not a wire API: latest write readiness result.
    blocked_reason: u8,
    /// Response envelope/body bytes generated and admitted, not peer delivery.
    generated_bytes: u64,
    accepted_bytes: u64,
    /// Private failure snapshot; set only on a terminal readiness/write error.
    failure: Option<(u8, QuicNodeEgressError)>,
}

struct HandlerStream {
    /// Private instance identity: stream IDs repeat across associations.
    diagnostic_id: u64,
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

/// Main-owner-only power-policy view; no bearer lock or transport policy.
pub(crate) fn has_active_handlers() -> bool {
    unsafe { !(&*core::ptr::addr_of!(HANDLER_STREAMS)).is_empty() }
}
static mut HANDLER_DIAGNOSTIC_SEQUENCE: u64 = 0;

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
            blocked_reason: 0,
            generated_bytes: 0,
            accepted_bytes: 0,
            failure: None,
        });
        crate::main_runtime::request_quic_ingress();
    }
}

/// Offer request bytes to a stream's handler; returns how many were taken.
fn ingest(entry: &mut HandlerStream, offset: u64, fin: bool, bytes: &[u8]) -> usize {
    let pushed = dmesh_server::stream::track_progress(&mut entry.last_ms, handler_clock_ms, || {
        let pushed = entry
            .request
            .push(&dmesh_server::registry::REGISTRY, offset, fin, bytes);
        let progressed = pushed.accepted != 0 || (fin && bytes.is_empty());
        (pushed, progressed)
    });
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
    let association = stream.association_id();
    let context = dmesh_server::registry::CallContext {
        association,
        stream_id: Some(stream.id()),
        // The node's own record of where this association runs.
        bearer: association.and_then(|id| unsafe { runtime() }.association_bearer_name(id)),
        ..Default::default()
    };
    let diagnostic_id = unsafe {
        HANDLER_DIAGNOSTIC_SEQUENCE = HANDLER_DIAGNOSTIC_SEQUENCE.saturating_add(1);
        HANDLER_DIAGNOSTIC_SEQUENCE
    };
    streams.push(HandlerStream {
        diagnostic_id,
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

struct QuicBodyWriter<'a> {
    runtime: &'a mut FirmwareRuntime,
    stream: &'a mut QuicStream,
    error: Option<QuicNodeEgressError>,
}

impl dmesh_server::stream::BodyChunkWriter for QuicBodyWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> Result<usize, dmesh_server::stream::BodyChunkWriteError> {
        match self.runtime.write_stream(self.stream, bytes) {
            Ok(count) => Ok(count),
            Err(error) if error.is_retryable() => {
                self.error = Some(error);
                Err(dmesh_server::stream::BodyChunkWriteError::Retryable)
            }
            Err(error) => {
                self.error = Some(error);
                Err(dmesh_server::stream::BodyChunkWriteError::Failed)
            }
        }
    }

    fn write_owned(
        &mut self,
        packet: OwnedPacket<quic_lite::ErasedPacketBuffer>,
    ) -> dmesh_server::stream::OwnedBodyChunkProgress {
        use dmesh_server::stream::OwnedBodyChunkProgress as Progress;

        match self
            .runtime
            .write_stream_owned_packet(self.stream, packet, false)
        {
            Ok(count) => Progress::Accepted(count),
            Err((error, packet)) if error.is_retryable() => {
                // If the whole pool lease does not fit current stream credit,
                // send a prefix through the ordinary byte API. The original
                // log-history lease remains retained until its full CBOR run
                // has entered QUIC's reliable stream history.
                match self.runtime.write_stream(self.stream, packet.bytes()) {
                    Ok(count) if count != 0 => Progress::Accepted(count),
                    Ok(_) => {
                        self.error = Some(error);
                        Progress::Retryable
                    }
                    Err(retryable) if retryable.is_retryable() => {
                        self.error = Some(retryable);
                        Progress::Retryable
                    }
                    Err(failed) => {
                        self.error = Some(failed);
                        Progress::Failed
                    }
                }
            }
            Err((error, _packet)) => {
                self.error = Some(error);
                Progress::Failed
            }
        }
    }
}

fn write_some(
    runtime: &mut FirmwareRuntime,
    stream: &mut QuicStream,
    writer: &mut ResponseWriter,
) -> WriteState {
    let state = write_some_inner(runtime, stream, writer);
    unsafe {
        RESPONSE_ATTEMPTS += 1;
        RESPONSE_BLOCKED += u64::from(matches!(state, WriteState::Blocked));
        if matches!(state, WriteState::Blocked) {
            let index = usize::from(writer.blocked_reason.saturating_sub(1)).min(7);
            RESPONSE_BLOCKED_REASONS[index] += 1;
        }
    }
    state
}

fn write_some_inner(
    runtime: &mut FirmwareRuntime,
    stream: &mut QuicStream,
    writer: &mut ResponseWriter,
) -> WriteState {
    writer.blocked_reason = 0;
    writer.waiting_body = false;
    if writer.carry.is_empty() && !writer.last_read {
        let window_started = unsafe { esp_idf_sys::esp_timer_get_time().max(0) as u64 };
        let window_result = runtime.stream_send_window(stream);
        unsafe {
            RESPONSE_WINDOW_US +=
                (esp_idf_sys::esp_timer_get_time().max(0) as u64).saturating_sub(window_started);
        }
        let window = match window_result {
            Ok(window) => window,
            Err(error) if error.is_retryable() => {
                writer.blocked_reason = write_blocked_reason(error);
                return WriteState::Blocked;
            }
            Err(error) => {
                writer.failure = Some((1, error));
                return WriteState::Failed;
            }
        };
        let capacity = window.min(WRITE_CHUNK as u64) as usize;
        if capacity == 0 {
            writer.blocked_reason = 6;
            return WriteState::Blocked;
        }
        let mut chunk_writer = QuicBodyWriter {
            runtime,
            stream,
            error: None,
        };
        let direct_started = unsafe { esp_idf_sys::esp_timer_get_time().max(0) as u64 };
        let direct = writer.reader.write_direct(&mut chunk_writer);
        let direct_elapsed = (unsafe { esp_idf_sys::esp_timer_get_time().max(0) as u64 })
            .saturating_sub(direct_started);
        if let Some(progress) = direct {
            use dmesh_server::stream::BodyChunkProgress as Progress;
            unsafe {
                RESPONSE_WRITE_CALLS += 1;
                RESPONSE_WRITE_US += direct_elapsed;
                RESPONSE_WRITE_MAX_US = RESPONSE_WRITE_MAX_US.max(direct_elapsed);
            }
            match progress {
                Progress::Accepted(accepted) if accepted != 0 => {
                    writer.generated_bytes = writer.generated_bytes.saturating_add(accepted as u64);
                    writer.accepted_bytes = writer.accepted_bytes.saturating_add(accepted as u64);
                    unsafe {
                        RESPONSE_ACCEPTED_BYTES += accepted as u64;
                    }
                    return WriteState::More;
                }
                Progress::Accepted(_) | Progress::Waiting => {
                    writer.waiting_body = true;
                    writer.blocked_reason = 7;
                    return WriteState::Blocked;
                }
                Progress::Retryable => {
                    let error = chunk_writer
                        .error
                        .unwrap_or(QuicNodeEgressError::BearerBusy);
                    writer.blocked_reason = write_blocked_reason(error);
                    unsafe {
                        RESPONSE_WRITE_BLOCKED += 1;
                    }
                    return WriteState::Blocked;
                }
                Progress::Failed => {
                    writer.failure = Some((
                        2,
                        chunk_writer
                            .error
                            .unwrap_or(QuicNodeEgressError::Transport(quic_lite::Error::Invalid)),
                    ));
                    return WriteState::Failed;
                }
                Progress::Done => {
                    writer.last_read = true;
                    match runtime.finish_stream(stream) {
                        Ok(()) => return WriteState::Done,
                        Err(error) if error.is_retryable() => {
                            writer.blocked_reason = write_blocked_reason(error);
                            return WriteState::Blocked;
                        }
                        Err(error) => {
                            writer.failure = Some((2, error));
                            return WriteState::Failed;
                        }
                    }
                }
            }
        }
        let mut chunk = [0u8; WRITE_CHUNK];
        let read_started = unsafe { esp_idf_sys::esp_timer_get_time().max(0) as u64 };
        let (count, done) = writer.reader.read(&mut chunk[..capacity]);
        let read_elapsed = (unsafe { esp_idf_sys::esp_timer_get_time().max(0) as u64 })
            .saturating_sub(read_started);
        unsafe {
            RESPONSE_READ_CALLS += 1;
            RESPONSE_READ_US += read_elapsed;
        }
        writer.waiting_body = count == 0 && !done;
        if count == 0 && !done {
            writer.blocked_reason = 7;
            return WriteState::Blocked;
        }
        writer.carry.extend_from_slice(&chunk[..count]);
        writer.generated_bytes = writer.generated_bytes.saturating_add(count as u64);
        writer.last_read = done;
    }
    let write_started = unsafe { esp_idf_sys::esp_timer_get_time().max(0) as u64 };
    #[cfg(feature = "rtos-stats")]
    let bearer_before = unsafe { BEARER_SUBMIT_US };
    let result = if writer.last_read {
        runtime.write_stream_and_finish(stream, &writer.carry)
    } else {
        runtime.write_stream(stream, &writer.carry)
    };
    let write_elapsed =
        (unsafe { esp_idf_sys::esp_timer_get_time().max(0) as u64 }).saturating_sub(write_started);
    unsafe {
        RESPONSE_WRITE_CALLS += 1;
        RESPONSE_WRITE_US += write_elapsed;
        #[cfg(feature = "rtos-stats")]
        {
            RESPONSE_BEARER_US += BEARER_SUBMIT_US.saturating_sub(bearer_before);
        }
        RESPONSE_WRITE_MAX_US = RESPONSE_WRITE_MAX_US.max(write_elapsed);
        if let Ok(accepted) = &result {
            RESPONSE_ACCEPTED_BYTES += *accepted as u64;
        } else if result
            .as_ref()
            .err()
            .is_some_and(|error| error.is_retryable())
        {
            RESPONSE_WRITE_BLOCKED += 1;
        }
    }
    match result {
        Ok(accepted) => {
            writer.accepted_bytes = writer.accepted_bytes.saturating_add(accepted as u64);
            writer.carry.drain(..accepted);
            if !writer.carry.is_empty() {
                WriteState::More
            } else if writer.last_read {
                WriteState::Done
            } else {
                WriteState::More
            }
        }
        Err(error) if error.is_retryable() => {
            writer.blocked_reason = write_blocked_reason(error);
            WriteState::Blocked
        }
        Err(error) => {
            writer.failure = Some((2, error));
            WriteState::Failed
        }
    }
}

fn write_blocked_reason(error: QuicNodeEgressError) -> u8 {
    match error {
        QuicNodeEgressError::BearerBusy => 1,
        QuicNodeEgressError::PoolUnavailable => 2,
        QuicNodeEgressError::Transport(quic_lite::Error::Blocked) => 3,
        QuicNodeEgressError::Transport(quic_lite::Error::FlowControl) => 4,
        QuicNodeEgressError::Transport(quic_lite::Error::HistoryFull) => 5,
        _ => 8,
    }
}

/// Advance every handler stream: withheld request bytes, deferred work, and
/// response writing. Called from the QUIC owner's progress loop.
fn service_handler_streams(runtime: &mut FirmwareRuntime, now_ms: u64) {
    let started_us = unsafe { esp_idf_sys::esp_timer_get_time().max(0) as u64 };
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
        if let Some(response) =
            dmesh_server::stream::track_progress(&mut entry.last_ms, handler_clock_ms, || {
                let response = entry.request.poll();
                let progressed = response.is_some();
                (response, progressed)
            })
        {
            entry.start_response(response);
        }
        if let Some(writer) = entry.writer.as_mut() {
            let state =
                dmesh_server::stream::track_progress(&mut entry.last_ms, handler_clock_ms, || {
                    let state = write_some(runtime, &mut entry.stream, writer);
                    let progressed = matches!(state, WriteState::More | WriteState::Done);
                    (state, progressed)
                });
            match state {
                WriteState::Blocked => {}
                WriteState::More => {
                    more = true;
                }
                WriteState::Done => writer.done = true,
                WriteState::Failed => {
                    report_response_failure(entry, now_ms);
                    // A failed response must not invoke its after-finish
                    // action (for example, rebooting into another image).
                    streams.swap_remove(index);
                    continue;
                }
            }
        }
        let answered_and_sent = entry.writer.as_ref().is_some_and(|writer| writer.done);
        if answered_and_sent && entry.request_finished {
            // Local admission including FIN, not evidence of peer delivery.
            report_handler_state("quic.response_admitted", entry, now_ms);
            entry.writer.as_mut().unwrap().reader.finish_response();
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
    let elapsed_us =
        (unsafe { esp_idf_sys::esp_timer_get_time().max(0) as u64 }).saturating_sub(started_us);
    unsafe {
        OWNER_HANDLER_TOTAL_US += elapsed_us;
        OWNER_HANDLER_MAX_US = OWNER_HANDLER_MAX_US.max(elapsed_us);
    }
}

/// Cold-path CBOR evidence for a response producer being removed. Enum
/// detail ordinals are private build-specific diagnostics, not a wire API.
#[cold]
#[inline(never)]
fn report_response_failure(entry: &HandlerStream, now_ms: u64) {
    use dmesh_server::cbor::FieldValue::{Text as T, Unsigned as U};
    let Some(writer) = entry.writer.as_ref() else {
        return;
    };
    let Some((phase, error)) = writer.failure else {
        return;
    };
    let (class, detail) = match error {
        QuicNodeEgressError::Association(error) => ("association", error as u64),
        QuicNodeEgressError::Transport(error) => ("transport", error as u64),
        QuicNodeEgressError::PoolUnavailable => ("pool-unavailable", 0),
        QuicNodeEgressError::InvalidPoolLayout => ("invalid-pool-layout", 0),
        QuicNodeEgressError::MissingEgressAddress => ("missing-egress-address", 0),
        QuicNodeEgressError::MissingBearer => ("missing-bearer", 0),
        QuicNodeEgressError::BearerBusy => ("bearer-busy", 0),
        QuicNodeEgressError::CircuitBusy => ("circuit-busy", 0),
        QuicNodeEgressError::StreamEventsFull => ("stream-events-full", 0),
        QuicNodeEgressError::AssociationTimedOut => ("association-timeout", 0),
        QuicNodeEgressError::PathSetupAttemptsExhausted => ("path-attempts-exhausted", 0),
        QuicNodeEgressError::SetupRejected(code) => ("setup-rejected", code),
    };
    crate::wifi_esp::sta_diagnostic(
        "quic.response_failed",
        &[
            (1, U(entry.diagnostic_id)),
            (2, U(entry.stream.id())),
            (3, U(u64::from(phase))),
            (4, T(class)),
            (5, U(detail)),
            (6, U(writer.generated_bytes)),
            (7, U(writer.accepted_bytes)),
            (8, U(writer.carry.len() as u64)),
            (9, U(writer.last_read as u64)),
            (10, U(now_ms.saturating_sub(entry.last_ms))),
            (11, U(POOL.available() as u64)),
            (12, U(POOL.capacity() as u64)),
        ],
    );
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

/// Private diagnostics: distinguish producer/transport stalls from idle expiry.
/// Report each stream, not only the first stream on a duplex association.
fn report_handler_state(event: &str, entry: &HandlerStream, now_ms: u64) {
    use dmesh_server::cbor::FieldValue::Unsigned as U;
    let writer = entry.writer.as_ref();
    crate::wifi_esp::sta_diagnostic(
        event,
        &[
            (1, U(entry.stream.id())),
            (2, U(now_ms.saturating_sub(entry.last_ms))),
            (3, U(entry.request_finished as u64)),
            (4, U(entry.request.is_waiting() as u64)),
            (5, U(writer.is_some() as u64)),
            (6, U(writer.is_some_and(|writer| writer.done) as u64)),
            (
                7,
                U(writer.is_some_and(|writer| writer.waiting_body) as u64),
            ),
            (8, U(writer.map_or(0, |writer| writer.carry.len()) as u64)),
            (9, U(writer.is_some_and(|writer| writer.last_read) as u64)),
            (10, U(entry.leftover.len() as u64)),
            (
                11,
                U(writer.map_or(0, |writer| writer.blocked_reason) as u64),
            ),
            (12, U(POOL.available() as u64)),
            (13, U(entry.diagnostic_id)),
            (14, U(writer.map_or(0, |writer| writer.generated_bytes))),
            (15, U(writer.map_or(0, |writer| writer.accepted_bytes))),
        ],
    );
}

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
        if dmesh_server::stream::handler_idle_expired(
            now_ms,
            streams[index].last_ms,
            HANDLER_STREAM_IDLE_MS,
            streams[index].request.is_waiting(),
            streams[index]
                .writer
                .as_ref()
                .is_some_and(|writer| !writer.done),
        ) {
            let entry = streams.swap_remove(index);
            report_handler_state("quic.handler_expired", &entry, now_ms);
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
            let mut outbound = probe;
            outbound.peer = None;
            let download = if probe.direction == dmesh_server::probe::ProbeDirection::Both {
                outbound.direction = dmesh_server::probe::ProbeDirection::Upload;
                let mut down = outbound;
                down.direction = dmesh_server::probe::ProbeDirection::Download;
                let mut wire = [0; dmesh_server::probe::PROBE_REQUEST_MAX];
                let Some(len) = dmesh_server::probe::encode_probe_handler_request(
                    down,
                    id.wrapping_add(1),
                    &mut wire,
                ) else {
                    return failed();
                };
                Some(PeerProbeDownload {
                    stream: None,
                    request_wire: wire,
                    request_len: len,
                    request_offset: 0,
                    reader: dmesh_server::probe::ProbeResponseReader::for_request(down),
                    completed: false,
                })
            } else {
                None
            };
            let plan = dmesh_server::probe::ProbeServicePlan::from_request(
                outbound.workload(),
                quic_lite::DEFAULT_MAX_STREAM_PAYLOAD,
            );
            let upload = if outbound.upload_bytes() == 0 {
                None
            } else {
                let Some(source) =
                    quic_lite::probe::ProbePayload::new(outbound.upload_bytes(), plan.packet_size)
                else {
                    return failed();
                };
                Some(source)
            };
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
                        probe.total_bytes(),
                    )
                    .saturating_mul(1000),
                    association: None,
                    stream: None,
                    request_wire,
                    request_len,
                    request_offset: 0,
                    upload,
                    upload_chunk: [0; quic_lite::DEFAULT_MAX_STREAM_PAYLOAD],
                    upload_len: 0,
                    upload_offset: 0,
                    reader: dmesh_server::probe::ProbeResponseReader::for_request(outbound),
                    completed: false,
                    download,
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
    let primary = pending
        .stream
        .as_ref()
        .is_some_and(|outbound| outbound.same_stream(stream));
    let (reader, completed) = if primary {
        (&mut pending.reader, &mut pending.completed)
    } else {
        let download = pending.download.as_mut()?;
        if !download
            .stream
            .as_ref()
            .is_some_and(|outbound| outbound.same_stream(stream))
        {
            return None;
        }
        (&mut download.reader, &mut download.completed)
    };
    match reader.push(bytes) {
        Ok(()) => {
            if fin && !reader.is_complete() {
                let _ = crate::uart_esp::send_debug_text(b"DMESH directed probe RX ended early");
                finish_peer_probe(false);
            } else if fin {
                *completed = true;
                if pending.completed
                    && pending
                        .download
                        .as_ref()
                        .is_none_or(|download| download.completed)
                {
                    finish_peer_probe(true);
                }
            }
        }
        Err(error) => {
            let reason = match error {
                dmesh_server::probe::ProbeClientError::Header => "bad_header",
                dmesh_server::probe::ProbeClientError::Rejected => "peer_rejected",
                dmesh_server::probe::ProbeClientError::Payload => "data_rejected",
            };
            let _ = crate::log_history::push_event(
                dmesh_server::log_watch::LEVEL_WARN,
                "probe",
                "receive_rejected",
                &[
                    (1, dmesh_server::cbor::FieldValue::Unsigned(reader.bytes())),
                    (2, dmesh_server::cbor::FieldValue::Text(reason)),
                ],
            );
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
    if let Some(download) = pending.download.as_mut() {
        if download.stream.is_none() {
            match runtime.open_stream(association) {
                Ok(stream) => download.stream = Some(stream),
                Err(error) if error.is_retryable() => return,
                Err(_) => {
                    finish_peer_probe(false);
                    return;
                }
            }
        }
        if download.request_offset < download.request_len {
            let stream = download
                .stream
                .as_mut()
                .expect("download stream initialized");
            match runtime.write_stream_and_finish(
                stream,
                &download.request_wire[download.request_offset..download.request_len],
            ) {
                Ok(written) => {
                    download.request_offset += written;
                    if written != 0 {
                        crate::main_runtime::request_quic_ingress();
                    }
                }
                Err(error) if error.is_retryable() => {}
                Err(_) => {
                    finish_peer_probe(false);
                    return;
                }
            }
        }
    }
    if pending.completed {
        return;
    }
    let stream = pending.stream.as_mut().expect("stream initialized above");
    // Retain the current workload chunk across partial stream writes.
    let result = if pending.request_offset < pending.request_len {
        let bytes = &pending.request_wire[pending.request_offset..pending.request_len];
        if pending.upload.is_none() {
            runtime.write_stream_and_finish(stream, bytes)
        } else {
            runtime.write_stream(stream, bytes)
        }
    } else {
        let Some(source) = pending.upload.as_mut() else {
            return;
        };
        if pending.upload_offset == pending.upload_len {
            if source.is_complete() {
                return;
            }
            pending.upload_len = source.fill(&mut pending.upload_chunk);
            pending.upload_offset = 0;
        }
        let bytes = &pending.upload_chunk[pending.upload_offset..pending.upload_len];
        if source.is_complete() {
            runtime.write_stream_and_finish(stream, bytes)
        } else {
            runtime.write_stream(stream, bytes)
        }
    };
    match result {
        Ok(written) => {
            if pending.request_offset < pending.request_len {
                pending.request_offset += written;
            } else {
                pending.upload_offset += written;
            }
            if written != 0 {
                crate::main_runtime::request_quic_ingress();
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
    let received = pending.reader.bytes()
        + pending.reader.uploaded_bytes()
        + pending
            .download
            .as_ref()
            .map_or(0, |download| download.reader.bytes());
    let elapsed = (unsafe { esp_idf_sys::esp_timer_get_time().max(0) as u64 })
        .saturating_sub(pending.started_at_us);
    let succeeded = ok
        && pending.completed
        && pending
            .download
            .as_ref()
            .is_none_or(|download| download.completed)
        && received == pending.request.total_bytes();
    let _ = crate::log_history::push_event(
        if succeeded {
            dmesh_server::log_watch::LEVEL_INFO
        } else {
            dmesh_server::log_watch::LEVEL_WARN
        },
        "probe",
        "completed",
        &[
            (1, dmesh_server::cbor::FieldValue::Unsigned(pending.id)),
            (2, dmesh_server::cbor::FieldValue::Bool(succeeded)),
            (3, dmesh_server::cbor::FieldValue::Unsigned(received)),
            (4, dmesh_server::cbor::FieldValue::Unsigned(elapsed / 1_000)),
        ],
    );
    let mut response = alloc::vec![0u8; 256];
    let len = dmesh_server::probe::encode_probe_result_response(
        pending.id,
        pending.request,
        succeeded,
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
