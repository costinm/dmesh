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
/// One active ingress worker needs parser and dispatch call depth only: packet
/// frames and QUIC response buffers are static/pool-backed rather than task
/// locals. Keep this allocation bounded and internal, but do not reserve it
/// in every firmware mode while no raw bearer is active.
const TASK_STACK_BYTES: u32 = 48 * 1024;

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
static UART_HANDLER: AtomicUsize = AtomicUsize::new(0);
static UART_RAW_HANDLER: AtomicUsize = AtomicUsize::new(0);
static WORK_HANDLER: AtomicUsize = AtomicUsize::new(0);
static NAN_SERVICE_INFO_HANDLER: AtomicUsize = AtomicUsize::new(0);
static DROPS: AtomicU32 = AtomicU32::new(0);
// The bearer callback itself remains registered while a radio/UART is active,
// but no ingress task exists while it is idle. The first queued item creates a
// short-lived drain task; RETIRING closes the race between an empty receive
// poll and a producer enqueueing a new slot.
//
// One tick was short enough for the worker to retire between consecutive UDP
// packets. The next Wi-Fi RX callback then had to allocate a 48 KiB task
// stack before it could publish its packet, producing avoidable receive gaps
// and AP retries. Keep the heap-backed stack only for a short quiet interval
// after real traffic, then release it exactly as before.
const WORKER_IDLE_DRAIN_TICKS: esp_idf_sys::TickType_t = 20;
const WORKER_IDLE: u8 = 0;
const WORKER_STARTING: u8 = 1;
const WORKER_RUNNING: u8 = 2;
const WORKER_RETIRING: u8 = 3;
static WORKER_STATE: AtomicU8 = AtomicU8::new(WORKER_IDLE);

static mut QUEUE_CONTROL: core::mem::MaybeUninit<esp_idf_sys::StaticQueue_t> =
    core::mem::MaybeUninit::uninit();
static mut QUEUE_STORAGE: QueueStorage<{ PACKET_SLOTS * core::mem::size_of::<IngressPacket>() }> =
    QueueStorage([0; PACKET_SLOTS * core::mem::size_of::<IngressPacket>()]);
static mut TASK_PACKET: core::mem::MaybeUninit<IngressPacket> = core::mem::MaybeUninit::uninit();

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
    let queued = unsafe {
        esp_idf_sys::xQueueGenericSend(queue.cast(), (&item as *const IngressPacket).cast(), 0, 0)
            == 1
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
                WORKER_IDLE_DRAIN_TICKS,
            )
        } != 1
        {
            // Transition before the final queue check. Producers that see
            // RETIRING retry until IDLE, while a producer that had already
            // seen RUNNING is caught by this check.
            WORKER_STATE.store(WORKER_RETIRING, Ordering::Release);
            if unsafe { esp_idf_sys::uxQueueMessagesWaiting(queue.cast()) } != 0 {
                WORKER_STATE.store(WORKER_RUNNING, Ordering::Release);
                continue;
            }
            WORKER_STATE.store(WORKER_IDLE, Ordering::Release);
            unsafe { esp_idf_sys::vTaskDeleteWithCaps(core::ptr::null_mut()) };
            return;
        }
        let item = unsafe { *core::ptr::addr_of!(TASK_PACKET).cast::<IngressPacket>() };
        if item.kind == IngressKind::Work {
            let work = WORK_HANDLER.swap(0, Ordering::AcqRel);
            if work != 0 {
                let work: fn() = unsafe { core::mem::transmute(work) };
                work();
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
    }
}

/// Start the deferred worker only while a packet/control item needs draining.
/// This runs in normal FreeRTOS task context, including the ESP Wi-Fi RX
/// callback; it must never be called from an ISR.
fn wake_worker() -> bool {
    loop {
        match WORKER_STATE.load(Ordering::Acquire) {
            WORKER_RUNNING => return true,
            WORKER_RETIRING | WORKER_STARTING => core::hint::spin_loop(),
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
                    WORKER_STATE.store(WORKER_IDLE, Ordering::Release);
                    return false;
                }
                return true;
            }
            _ => return false,
        }
    }
}
