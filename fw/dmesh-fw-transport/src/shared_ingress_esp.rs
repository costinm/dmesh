//! One bounded packet pool and one worker for every ESP packet bearer.
//!
//! The Wi-Fi driver owns its RX allocation only during its callback, so the
//! callback copies once into a device-wide slot and queues only metadata.
//! Raw UDP6 and ESP-NOW never retain separate MTU queues or worker stacks.
//! Bearer parsing and transmission stay in their own adapters; this module is
//! only the ESP/FreeRTOS ownership boundary.

use core::{
    ffi::c_void,
    sync::atomic::{AtomicBool, AtomicPtr, AtomicU32, AtomicU8, AtomicUsize, Ordering},
};

use quic_lite::packet_pool::{PacketPool, PacketSlot};

/// Ethernet plus the common QUIC-lite datagram, sufficient for raw IPv6.
pub const FRAME_CAPACITY: usize = crate::TRANSPORT_MTU + 96;
/// This is the device-wide count, not a per-bearer multiplier.
pub const PACKET_SLOTS: usize = 8;
/// A received frame may be dropped under pressure, but a response that has
/// already been admitted by the QUIC-lite endpoint must still have room to
/// leave the device.  Reserve two of the single, shared packet slots for
/// egress rather than creating a NOW-only queue.  The same reservation will
/// serve UDP6, UART, FSK, and relay output as their adapters move to the
/// common sender.
const EGRESS_RESERVED_SLOTS: usize = 2;
/// FreeRTOS `xQueueGenericSend` copy-position value for the queue head.
/// ESP-IDF exposes the generic call but not this macro through every bindgen
/// configuration.  Egress uses it only after a packet has been admitted: a
/// reply has a live QUIC-lite credit/deadline, whereas fresh radio ingress can
/// be retried by the peer.  It remains one queue and one worker, not a
/// NOW-private fast path.
const QUEUE_SEND_TO_FRONT: i32 = 1;
/// One active ingress worker owns the shared service-dispatch call chain for
/// UART, NOW, UDP6, and NAN Service Info.  It does not own packet buffers:
/// those are in [`PACKETS`].  The former 48 KiB value was an unmeasured
/// construction peak and prevented classic ESP32 UART ingress after Wi-Fi
/// initialization.  32 KiB is the previously measured safe floor for a
/// single classic-IPERF service turn; `memory_stats` records its actual
/// high-water mark so this can be reduced from device evidence later.
const TASK_STACK_BYTES: u32 = 32 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum IngressKind {
    RawUdp6 = 1,
    EspNow = 2,
    /// PPP-decoded QUIC-lite payload from the physical UART/USB L2 bearer.
    /// It shares these slots with radio ingress; UART never owns a packet
    /// queue of its own.
    Uart = 3,
    /// Complete PPP record intentionally not marked as QUIC-lite. This is a
    /// bounded raw CBOR/log/control lane, never a second UART queue.
    UartRaw = 4,
    Work = 5,
    /// NAN active-subscribe/publish Service Info. The Wi-Fi callback copies
    /// only the bounded CBOR payload, then this common worker applies it.
    NanServiceInfo = 6,
    /// A connection-owned raw-service deadline. This is queue metadata only:
    /// it owns no packet slot and wakes the same worker that owns raw service
    /// state, so a lost NOW server response can be retransmitted safely.
    RawServiceTimer = 7,
    /// One complete NOW datagram awaiting radio submission.  It uses the same
    /// device-wide packet pool and FreeRTOS worker as RX, rather than a
    /// bearer-private egress buffer or a second Wi-Fi task.  This serializes
    /// ESP-IDF action-TX request ownership across Main deadline work and
    /// packet-worker replies; those two producers may otherwise overwrite
    /// the driver's static request while a previous action is in flight.
    EspNowTx = 8,
    /// A due NOW client retry, ACK, PTO, or close-drain turn.  It carries no
    /// packet data: it makes the shared worker the sole owner of the client's
    /// QUIC-lite state and response scratch, rather than letting Main's timer
    /// race an RX callback.  UDP6 and UART will use the same shape when their
    /// active client state moves into the common connection scheduler.
    EspNowClientTimer = 9,
    /// The physical UART writer has released one bounded egress record. It
    /// carries no data and only wakes the existing worker so the shared raw
    /// service can produce the next packet within the real UART queue's
    /// capacity. This is the UART equivalent of a writable-socket event, not
    /// a periodic transmit poll or a bearer-private packet queue.
    UartEgressReady = 10,
    /// A due raw-UDP6 client bootstrap, delayed-ACK, PTO, or timeout turn.
    /// Like the NOW client timer, it contains no frame and makes the shared
    /// ingress worker the sole mutable owner of the QUIC-lite client ledger.
    RawUdp6ClientTimer = 11,
}

/// Link context preserved across the one required driver-buffer copy.
///
/// The shared worker is deliberately bearer-neutral, but raw Ethernet has two
/// distinct ESP data interfaces.  Keeping this byte with the packet prevents
/// an AP-received request from accidentally being returned as a STA To-DS
/// frame after it leaves the Wi-Fi callback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum IngressLink {
    None = 0,
    WifiSta = 1,
    WifiAp = 2,
}

/// Slot metadata that can cross the FreeRTOS queue without copying a packet.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct IngressPacket {
    pub kind: IngressKind,
    pub link: IngressLink,
    pub source: [u8; 6],
    pub len: u16,
    slot: PacketSlot,
}

impl IngressPacket {
    pub const fn source(self) -> [u8; 6] {
        self.source
    }

    pub const fn link(self) -> IngressLink {
        self.link
    }
}

pub type IngressHandler = fn(IngressPacket, &[u8]);

struct QueueStorage<const N: usize>([u8; N]);

static PACKETS: PacketPool<PACKET_SLOTS, FRAME_CAPACITY> = PacketPool::new();
static QUEUE: AtomicPtr<c_void> = AtomicPtr::new(core::ptr::null_mut());
static STARTED: AtomicBool = AtomicBool::new(false);
static RAW_HANDLER: AtomicUsize = AtomicUsize::new(0);
static ESPNOW_HANDLER: AtomicUsize = AtomicUsize::new(0);
static ESPNOW_TX_HANDLER: AtomicUsize = AtomicUsize::new(0);
static UART_HANDLER: AtomicUsize = AtomicUsize::new(0);
static UART_RAW_HANDLER: AtomicUsize = AtomicUsize::new(0);
static WORK_HANDLER: AtomicUsize = AtomicUsize::new(0);
static NAN_SERVICE_INFO_HANDLER: AtomicUsize = AtomicUsize::new(0);
static RAW_SERVICE_TIMER_HANDLER: AtomicUsize = AtomicUsize::new(0);
static RAW_SERVICE_TIMER_PENDING: AtomicBool = AtomicBool::new(false);
static ESPNOW_CLIENT_TIMER_HANDLER: AtomicUsize = AtomicUsize::new(0);
static ESPNOW_CLIENT_TIMER_PENDING: AtomicBool = AtomicBool::new(false);
static RAW_UDP6_CLIENT_TIMER_HANDLER: AtomicUsize = AtomicUsize::new(0);
static RAW_UDP6_CLIENT_TIMER_PENDING: AtomicBool = AtomicBool::new(false);
static UART_EGRESS_READY_HANDLER: AtomicUsize = AtomicUsize::new(0);
static UART_EGRESS_READY_PENDING: AtomicBool = AtomicBool::new(false);
static DROPS: AtomicU32 = AtomicU32::new(0);
// This worker is created lazily on the first accepted packet, then blocks on
// the shared queue for the active firmware lifetime. It must not retire after
// a short quiet interval: 20 ticks caused repeated internal-heap allocation
// and packet loss between normal UART/NOW/UDP bursts. A later explicit
// all-bearers-stopped lifecycle may reclaim it; UART-only stop must never
// delete a worker while a radio bearer can still enqueue packets.
const WORKER_IDLE: u8 = 0;
const WORKER_STARTING: u8 = 1;
const WORKER_RUNNING: u8 = 2;
static WORKER_STATE: AtomicU8 = AtomicU8::new(WORKER_IDLE);
static WORKER_HANDLE: AtomicPtr<c_void> = AtomicPtr::new(core::ptr::null_mut());
static WORKER_STARTS: AtomicU32 = AtomicU32::new(0);
static WORKER_CREATE_FAILURES: AtomicU32 = AtomicU32::new(0);
static WORKER_STACK_MIN_FREE_WORDS: AtomicU32 = AtomicU32::new(u32::MAX);
static WORKER_FREE_INTERNAL_BYTES: AtomicU32 = AtomicU32::new(0);
static WORKER_MIN_FREE_INTERNAL_BYTES: AtomicU32 = AtomicU32::new(u32::MAX);
static WORKER_LARGEST_INTERNAL_BLOCK_BYTES: AtomicU32 = AtomicU32::new(0);

static mut QUEUE_CONTROL: core::mem::MaybeUninit<esp_idf_sys::StaticQueue_t> =
    core::mem::MaybeUninit::uninit();
static mut QUEUE_STORAGE: QueueStorage<{ PACKET_SLOTS * core::mem::size_of::<IngressPacket>() }> =
    QueueStorage([0; PACKET_SLOTS * core::mem::size_of::<IngressPacket>()]);
static mut TASK_PACKET: core::mem::MaybeUninit<IngressPacket> = core::mem::MaybeUninit::uninit();

/// Memory evidence for sizing the shared event-driven dispatcher. These
/// counters do not alter admission: a full pool or failed task creation still
/// drops the packet immediately, but the next reachable status request can
/// distinguish heap exhaustion from malformed bearer traffic.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct IngressMemoryStats {
    pub worker_stack_bytes: u32,
    pub worker_running: bool,
    pub worker_starts: u32,
    pub worker_create_failures: u32,
    pub worker_stack_min_free_words: u32,
    pub free_internal_bytes: u32,
    pub min_free_internal_bytes: u32,
    pub largest_internal_block_bytes: u32,
}

/// Return the latest allocator and stack headroom observed by the shared
/// worker. Stack high water is FreeRTOS words remaining, not bytes used.
pub fn memory_stats() -> IngressMemoryStats {
    IngressMemoryStats {
        worker_stack_bytes: TASK_STACK_BYTES,
        worker_running: !WORKER_HANDLE.load(Ordering::Relaxed).is_null(),
        worker_starts: WORKER_STARTS.load(Ordering::Relaxed),
        worker_create_failures: WORKER_CREATE_FAILURES.load(Ordering::Relaxed),
        worker_stack_min_free_words: zero_if_unset(
            WORKER_STACK_MIN_FREE_WORDS.load(Ordering::Relaxed),
        ),
        free_internal_bytes: WORKER_FREE_INTERNAL_BYTES.load(Ordering::Relaxed),
        min_free_internal_bytes: zero_if_unset(
            WORKER_MIN_FREE_INTERNAL_BYTES.load(Ordering::Relaxed),
        ),
        largest_internal_block_bytes: WORKER_LARGEST_INTERNAL_BLOCK_BYTES.load(Ordering::Relaxed),
    }
}

fn zero_if_unset(value: u32) -> u32 {
    if value == u32::MAX { 0 } else { value }
}

fn record_lowest(slot: &AtomicU32, value: u32) {
    let mut current = slot.load(Ordering::Relaxed);
    while value < current {
        match slot.compare_exchange_weak(current, value, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return,
            Err(observed) => current = observed,
        }
    }
}

fn record_memory_headroom() {
    // The task requires internal 8-bit memory, so record that exact heap
    // capability rather than only the aggregate heap visible to unrelated
    // PSRAM-capable allocations.
    let capabilities = esp_idf_sys::MALLOC_CAP_INTERNAL | esp_idf_sys::MALLOC_CAP_8BIT;
    let free = unsafe { esp_idf_sys::heap_caps_get_free_size(capabilities) as u32 };
    WORKER_FREE_INTERNAL_BYTES.store(free, Ordering::Relaxed);
    record_lowest(&WORKER_MIN_FREE_INTERNAL_BYTES, free);
    WORKER_LARGEST_INTERNAL_BLOCK_BYTES.store(
        unsafe { esp_idf_sys::heap_caps_get_largest_free_block(capabilities) as u32 },
        Ordering::Relaxed,
    );
}

pub fn start(kind: IngressKind, handler: IngressHandler) -> bool {
    handler_slot(kind).store(handler as usize, Ordering::Release);
    if STARTED.load(Ordering::Acquire) {
        return true;
    }
    if STARTED.swap(true, Ordering::AcqRel) {
        return true;
    }
    let queue = unsafe {
        esp_idf_sys::xQueueGenericCreateStatic(
            PACKET_SLOTS as _,
            core::mem::size_of::<IngressPacket>() as _,
            core::ptr::addr_of_mut!(QUEUE_STORAGE.0).cast(),
            core::ptr::addr_of_mut!(QUEUE_CONTROL).cast(),
            0,
        )
    };
    if queue.is_null() {
        STARTED.store(false, Ordering::Release);
        return false;
    }
    QUEUE.store(queue.cast(), Ordering::Release);
    true
}

/// Remove an ingress bearer after its hardware callback has been quiesced.
///
/// No worker is retained by this operation. Its stack is released after the
/// short idle drain interval; the queue/pool remain valid for other bearers.
pub fn stop(kind: IngressKind) {
    handler_slot(kind).store(0, Ordering::Release);
}

/// Make one bounded ingress copy.  A full pool is backpressure: adapters must
/// release their Wi-Fi driver RX buffer and count a drop, never allocate.
pub fn enqueue(kind: IngressKind, source: [u8; 6], bytes: &[u8]) -> bool {
    enqueue_on_link(kind, IngressLink::None, source, bytes)
}

/// Submit one NOW datagram through the common packet worker.
///
/// Called for every complete action-bearer datagram, whether it originated
/// from a client timer, a server reply, or a future relay policy.  It is an
/// immediate bounded copy into the shared pool; the worker later invokes the
/// registered action submitter once, in its normal queue order.  A full pool
/// is explicit backpressure, never an allocation or an unbounded sender
/// queue.  `peer` is carried in the existing source field because egress has
/// no RX-source semantics.
pub fn enqueue_espnow_tx(peer: [u8; 6], bytes: &[u8]) -> bool {
    enqueue(IngressKind::EspNowTx, peer, bytes)
}

/// Make one bounded ingress copy and retain the data-link interface that
/// supplied it. UART and action-frame callers use [`enqueue`]; raw Ethernet
/// uses this form so AP and STA replies cannot cross interfaces.
pub fn enqueue_on_link(
    kind: IngressKind,
    link: IngressLink,
    source: [u8; 6],
    bytes: &[u8],
) -> bool {
    if bytes.len() > FRAME_CAPACITY {
        DROPS.fetch_add(1, Ordering::Relaxed);
        return false;
    }
    // RX callbacks are producers, not guaranteed delivery.  Do not let a
    // burst of NAN/action capture consume the last shared packet slots and
    // prevent the worker from submitting an already-admitted response.  This
    // is one pool and one queue: only admission priority differs.  Egress is
    // bounded by the same eight slots and remains subject to normal failure
    // accounting when both reserved slots are occupied.
    if kind != IngressKind::EspNowTx && PACKETS.available() <= EGRESS_RESERVED_SLOTS {
        DROPS.fetch_add(1, Ordering::Relaxed);
        return false;
    }
    let queue = QUEUE.load(Ordering::Acquire);
    let Some(slot) = PACKETS.acquire() else {
        DROPS.fetch_add(1, Ordering::Relaxed);
        return false;
    };
    if queue.is_null() || !PACKETS.write(slot, bytes) {
        let _ = PACKETS.release(slot);
        DROPS.fetch_add(1, Ordering::Relaxed);
        return false;
    }
    // Task creation happens in caller task context (never an ISR), only when
    // a frame arrives after an idle interval. Do this before publishing the
    // slot so a low-memory failure can release it without touching the queue.
    if !wake_worker() {
        let _ = PACKETS.release(slot);
        DROPS.fetch_add(1, Ordering::Relaxed);
        return false;
    }
    let item = IngressPacket {
        kind,
        link,
        source,
        len: bytes.len() as u16,
        slot,
    };
    // A received request may have opened a short action-TX reply window on
    // the peer. Place its admitted egress at the head so it is the next
    // operation after this worker turn; normal UART/UDP/NAN ingress remains
    // FIFO behind it and still uses the exact same packet pool and worker.
    let copy_position = if kind == IngressKind::EspNowTx {
        QUEUE_SEND_TO_FRONT
    } else {
        0
    };
    let queued = unsafe {
        esp_idf_sys::xQueueGenericSend(
            queue.cast(),
            (&item as *const IngressPacket).cast(),
            0,
            copy_position,
        ) == 1
    };
    if !queued {
        let _ = PACKETS.release(slot);
        DROPS.fetch_add(1, Ordering::Relaxed);
    } else {
        // A worker can observe an empty queue and begin retirement between
        // the first wake and this send. Recheck so this item always has a
        // consumer.
        let _ = wake_worker();
    }
    queued
}

/// Schedule one bounded control action on the already-reserved ingress task.
/// It carries no packet slot and is rejected while a previous action remains
/// queued. This is deliberately not a generic task facility: it is used for
/// actions whose stack must not be charged to a bearer callback or STA task.
pub fn schedule_work(work: fn()) -> bool {
    if WORK_HANDLER
        .compare_exchange(0, work as usize, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return false;
    }
    let queue = QUEUE.load(Ordering::Acquire);
    if queue.is_null() || !wake_worker() {
        WORK_HANDLER.store(0, Ordering::Release);
        return false;
    }
    let item = IngressPacket {
        kind: IngressKind::Work,
        link: IngressLink::None,
        source: [0; 6],
        len: 0,
        slot: PacketSlot::sentinel(),
    };
    let queued = unsafe {
        esp_idf_sys::xQueueGenericSend(queue.cast(), (&item as *const IngressPacket).cast(), 0, 0)
            == 1
    };
    if !queued {
        WORK_HANDLER.store(0, Ordering::Release);
    } else {
        let _ = wake_worker();
    }
    queued
}

/// Queue one connection-owned raw-service deadline on the shared ingress
/// worker. Unlike [`schedule_work`], this has a dedicated typed queue item:
/// unrelated deferred work cannot replace an outstanding retransmission.
/// The event contains no bearer queue or payload; the raw-service ledger owns
/// both the path and retransmittable packet history.
pub fn schedule_raw_service_timer(handler: fn()) -> bool {
    RAW_SERVICE_TIMER_HANDLER.store(handler as usize, Ordering::Release);
    if RAW_SERVICE_TIMER_PENDING.swap(true, Ordering::AcqRel) {
        return true;
    }
    let queue = QUEUE.load(Ordering::Acquire);
    if queue.is_null() || !wake_worker() {
        RAW_SERVICE_TIMER_PENDING.store(false, Ordering::Release);
        return false;
    }
    let item = IngressPacket {
        kind: IngressKind::RawServiceTimer,
        link: IngressLink::None,
        source: [0; 6],
        len: 0,
        slot: PacketSlot::sentinel(),
    };
    let queued = unsafe {
        esp_idf_sys::xQueueGenericSend(queue.cast(), (&item as *const IngressPacket).cast(), 0, 0)
            == 1
    };
    if !queued {
        RAW_SERVICE_TIMER_PENDING.store(false, Ordering::Release);
        DROPS.fetch_add(1, Ordering::Relaxed);
    }
    queued
}

/// Queue one due NOW-client transition on the same worker as NOW ingress and
/// egress.  Main's ESP timer only tells this owner that a deadline arrived;
/// it must not touch the client ledger or its response scratch itself.
pub fn schedule_espnow_client_timer(handler: fn()) -> bool {
    ESPNOW_CLIENT_TIMER_HANDLER.store(handler as usize, Ordering::Release);
    if ESPNOW_CLIENT_TIMER_PENDING.swap(true, Ordering::AcqRel) {
        return true;
    }
    let queue = QUEUE.load(Ordering::Acquire);
    if queue.is_null() || !wake_worker() {
        ESPNOW_CLIENT_TIMER_PENDING.store(false, Ordering::Release);
        return false;
    }
    let item = IngressPacket {
        kind: IngressKind::EspNowClientTimer,
        link: IngressLink::None,
        source: [0; 6],
        len: 0,
        slot: PacketSlot::sentinel(),
    };
    let queued = unsafe {
        esp_idf_sys::xQueueGenericSend(queue.cast(), (&item as *const IngressPacket).cast(), 0, 0)
            == 1
    };
    if !queued {
        ESPNOW_CLIENT_TIMER_PENDING.store(false, Ordering::Release);
        DROPS.fetch_add(1, Ordering::Relaxed);
    }
    queued
}

/// Queue one due raw-UDP6 client transition on the same worker that owns raw
/// Ethernet receive and response scratch. Main's one-shot deadline merely
/// requests this turn; it never races the RX callback by touching client state.
pub fn schedule_raw_udp6_client_timer(handler: fn()) -> bool {
    RAW_UDP6_CLIENT_TIMER_HANDLER.store(handler as usize, Ordering::Release);
    if RAW_UDP6_CLIENT_TIMER_PENDING.swap(true, Ordering::AcqRel) {
        return true;
    }
    let queue = QUEUE.load(Ordering::Acquire);
    if queue.is_null() || !wake_worker() {
        RAW_UDP6_CLIENT_TIMER_PENDING.store(false, Ordering::Release);
        return false;
    }
    let item = IngressPacket {
        kind: IngressKind::RawUdp6ClientTimer,
        link: IngressLink::None,
        source: [0; 6],
        len: 0,
        slot: PacketSlot::sentinel(),
    };
    let queued = unsafe {
        esp_idf_sys::xQueueGenericSend(queue.cast(), (&item as *const IngressPacket).cast(), 0, 0)
            == 1
    };
    if !queued {
        RAW_UDP6_CLIENT_TIMER_PENDING.store(false, Ordering::Release);
        DROPS.fetch_add(1, Ordering::Relaxed);
    }
    queued
}

/// Queue one UART-writable transition on the shared ingress worker.
///
/// The UART writer calls this after it dequeues a complete PPP record, so the
/// worker may ask the common QUIC-lite service for exactly the next packet.
/// Coalescing is intentional: a writer can free several records before the
/// worker runs, but one event observes the current queue capacity and drains
/// no more than that capacity permits.
pub fn schedule_uart_egress_ready(handler: fn()) -> bool {
    UART_EGRESS_READY_HANDLER.store(handler as usize, Ordering::Release);
    if UART_EGRESS_READY_PENDING.swap(true, Ordering::AcqRel) {
        return true;
    }
    let queue = QUEUE.load(Ordering::Acquire);
    if queue.is_null() || !wake_worker() {
        UART_EGRESS_READY_PENDING.store(false, Ordering::Release);
        return false;
    }
    let item = IngressPacket {
        kind: IngressKind::UartEgressReady,
        link: IngressLink::None,
        source: [0; 6],
        len: 0,
        slot: PacketSlot::sentinel(),
    };
    let queued = unsafe {
        esp_idf_sys::xQueueGenericSend(queue.cast(), (&item as *const IngressPacket).cast(), 0, 0)
            == 1
    };
    if !queued {
        UART_EGRESS_READY_PENDING.store(false, Ordering::Release);
        DROPS.fetch_add(1, Ordering::Relaxed);
    }
    queued
}

pub fn available() -> usize {
    PACKETS.available()
}
pub fn drops() -> u32 {
    DROPS.load(Ordering::Relaxed)
}

fn handler_slot(kind: IngressKind) -> &'static AtomicUsize {
    match kind {
        IngressKind::RawUdp6 => &RAW_HANDLER,
        IngressKind::EspNow => &ESPNOW_HANDLER,
        IngressKind::Uart => &UART_HANDLER,
        IngressKind::UartRaw => &UART_RAW_HANDLER,
        IngressKind::Work => &WORK_HANDLER,
        IngressKind::NanServiceInfo => &NAN_SERVICE_INFO_HANDLER,
        IngressKind::RawServiceTimer => &RAW_SERVICE_TIMER_HANDLER,
        IngressKind::EspNowTx => &ESPNOW_TX_HANDLER,
        IngressKind::EspNowClientTimer => &ESPNOW_CLIENT_TIMER_HANDLER,
        IngressKind::UartEgressReady => &UART_EGRESS_READY_HANDLER,
        IngressKind::RawUdp6ClientTimer => &RAW_UDP6_CLIENT_TIMER_HANDLER,
    }
}

unsafe extern "C" fn task_entry(_argument: *mut c_void) {
    let queue = QUEUE.load(Ordering::Acquire);
    if queue.is_null() {
        return;
    }
    loop {
        if unsafe {
            esp_idf_sys::xQueueReceive(
                queue.cast(),
                core::ptr::addr_of_mut!(TASK_PACKET).cast(),
                esp_idf_sys::TickType_t::MAX,
            )
        } != 1 { continue; }
        let item = unsafe { *core::ptr::addr_of!(TASK_PACKET).cast::<IngressPacket>() };
        if item.kind == IngressKind::Work {
            let work = WORK_HANDLER.swap(0, Ordering::AcqRel);
            if work != 0 {
                let work: fn() = unsafe { core::mem::transmute(work) };
                work();
            }
            continue;
        }
        if item.kind == IngressKind::RawServiceTimer {
            RAW_SERVICE_TIMER_PENDING.store(false, Ordering::Release);
            let handler = RAW_SERVICE_TIMER_HANDLER.load(Ordering::Acquire);
            if handler != 0 {
                let handler: fn() = unsafe { core::mem::transmute(handler) };
                handler();
            }
            continue;
        }
        if item.kind == IngressKind::EspNowClientTimer {
            ESPNOW_CLIENT_TIMER_PENDING.store(false, Ordering::Release);
            let handler = ESPNOW_CLIENT_TIMER_HANDLER.load(Ordering::Acquire);
            if handler != 0 {
                let handler: fn() = unsafe { core::mem::transmute(handler) };
                handler();
            }
            continue;
        }
        if item.kind == IngressKind::RawUdp6ClientTimer {
            RAW_UDP6_CLIENT_TIMER_PENDING.store(false, Ordering::Release);
            let handler = RAW_UDP6_CLIENT_TIMER_HANDLER.load(Ordering::Acquire);
            if handler != 0 {
                let handler: fn() = unsafe { core::mem::transmute(handler) };
                handler();
            }
            continue;
        }
        if item.kind == IngressKind::UartEgressReady {
            UART_EGRESS_READY_PENDING.store(false, Ordering::Release);
            let handler = UART_EGRESS_READY_HANDLER.load(Ordering::Acquire);
            if handler != 0 {
                let handler: fn() = unsafe { core::mem::transmute(handler) };
                handler();
            }
            continue;
        }
        let handler = handler_slot(item.kind).load(Ordering::Acquire);
        if handler != 0 {
            if let Some(packet) = PACKETS.packet(item.slot, item.len as usize) {
                let handler: IngressHandler = unsafe { core::mem::transmute(handler) };
                handler(item, packet);
            }
        }
        let _ = PACKETS.release(item.slot);
        // This is the worker's own task context, so FreeRTOS can report the
        // real remaining-stack watermark without synchronizing with a caller.
        record_lowest(
            &WORKER_STACK_MIN_FREE_WORDS,
            unsafe { esp_idf_sys::uxTaskGetStackHighWaterMark(core::ptr::null_mut()) as u32 },
        );
    }
}

/// Start the deferred worker only while a packet/control item needs draining.
/// This runs in normal FreeRTOS task context, including the ESP Wi-Fi RX
/// callback; it must never be called from an ISR.
fn wake_worker() -> bool {
    loop {
        match WORKER_STATE.load(Ordering::Acquire) {
            WORKER_RUNNING => return true,
            WORKER_STARTING => core::hint::spin_loop(),
            WORKER_IDLE => {
                if WORKER_STATE
                    .compare_exchange(
                        WORKER_IDLE,
                        WORKER_STARTING,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    )
                    .is_err()
                {
                    continue;
                }
                // The new task can run before the create call returns, so it
                // must never observe STARTING as its own state.
                WORKER_STATE.store(WORKER_RUNNING, Ordering::Release);
                let mut task = core::ptr::null_mut();
                let created = unsafe {
                    esp_idf_sys::xTaskCreatePinnedToCoreWithCaps(
                        Some(task_entry),
                        b"packet_ingress\0".as_ptr().cast(),
                        TASK_STACK_BYTES,
                        core::ptr::null_mut(),
                        5,
                        &mut task,
                        0,
                        esp_idf_sys::MALLOC_CAP_INTERNAL | esp_idf_sys::MALLOC_CAP_8BIT,
                    )
                };
                if created != 1 || task.is_null() {
                    WORKER_CREATE_FAILURES.fetch_add(1, Ordering::Relaxed);
                    record_memory_headroom();
                    WORKER_STATE.store(WORKER_IDLE, Ordering::Release);
                    return false;
                }
                WORKER_HANDLE.store(task.cast(), Ordering::Release);
                WORKER_STARTS.fetch_add(1, Ordering::Relaxed);
                record_memory_headroom();
                return true;
            }
            _ => return false,
        }
    }
}
