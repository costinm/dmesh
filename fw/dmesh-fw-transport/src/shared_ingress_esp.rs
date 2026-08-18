//! One bounded packet pool and one worker for every ESP packet bearer.
//!
//! The Wi-Fi driver owns its RX allocation only during its callback, so the
//! callback copies once into a device-wide slot and queues only metadata.
//! Raw UDP6 and ESP-NOW never retain separate MTU queues or worker stacks.
//! Bearer parsing and transmission stay in their own adapters; this module is
//! only the ESP/FreeRTOS ownership boundary.

use core::{
    ffi::c_void,
    sync::atomic::{AtomicBool, AtomicPtr, AtomicU32, AtomicUsize, Ordering},
};

use quic_lite::packet_pool::{PacketPool, PacketSlot};

/// Ethernet plus the common QUIC-lite datagram, sufficient for raw IPv6.
pub const FRAME_CAPACITY: usize = crate::TRANSPORT_MTU + 96;
/// This is the device-wide count, not a per-bearer multiplier.
pub const PACKET_SLOTS: usize = 8;
// E6 diagnostic: establish the actual construction peak for the shared
// eight-history association.  This is reverted to a named device budget once
// the on-device result is known.
const TASK_STACK_BYTES: u32 = 48 * 1024;
const TASK_STACK_WORDS: usize =
    TASK_STACK_BYTES as usize / core::mem::size_of::<esp_idf_sys::StackType_t>();

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
}

/// Slot metadata that can cross the FreeRTOS queue without copying a packet.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct IngressPacket {
    pub kind: IngressKind,
    pub source: [u8; 6],
    pub len: u16,
    slot: PacketSlot,
}

impl IngressPacket {
    pub const fn source(self) -> [u8; 6] {
        self.source
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
static DROPS: AtomicU32 = AtomicU32::new(0);

static mut QUEUE_CONTROL: core::mem::MaybeUninit<esp_idf_sys::StaticQueue_t> =
    core::mem::MaybeUninit::uninit();
static mut QUEUE_STORAGE: QueueStorage<{ PACKET_SLOTS * core::mem::size_of::<IngressPacket>() }> =
    QueueStorage([0; PACKET_SLOTS * core::mem::size_of::<IngressPacket>()]);
static mut TASK_PACKET: core::mem::MaybeUninit<IngressPacket> = core::mem::MaybeUninit::uninit();
static mut TASK_CONTROL: core::mem::MaybeUninit<esp_idf_sys::StaticTask_t> =
    core::mem::MaybeUninit::uninit();
static mut TASK_STACK: [esp_idf_sys::StackType_t; TASK_STACK_WORDS] = [0; TASK_STACK_WORDS];

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
    let task = unsafe {
        esp_idf_sys::xTaskCreateStaticPinnedToCore(
            Some(task_entry),
            b"packet_ingress\0".as_ptr().cast(),
            TASK_STACK_BYTES,
            core::ptr::null_mut(),
            5,
            core::ptr::addr_of_mut!(TASK_STACK).cast(),
            core::ptr::addr_of_mut!(TASK_CONTROL).cast(),
            0,
        )
    };
    if task.is_null() {
        QUEUE.store(core::ptr::null_mut(), Ordering::Release);
        STARTED.store(false, Ordering::Release);
        return false;
    }
    true
}

/// Make one bounded ingress copy.  A full pool is backpressure: adapters must
/// release their Wi-Fi driver RX buffer and count a drop, never allocate.
pub fn enqueue(kind: IngressKind, source: [u8; 6], bytes: &[u8]) -> bool {
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
    let item = IngressPacket {
        kind,
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
    let item = IngressPacket {
        kind: IngressKind::Work,
        source: [0; 6],
        len: 0,
        slot: PacketSlot::sentinel(),
    };
    let queued = !queue.is_null()
        && unsafe {
            esp_idf_sys::xQueueGenericSend(
                queue.cast(),
                (&item as *const IngressPacket).cast(),
                0,
                0,
            ) == 1
        };
    if !queued {
        WORK_HANDLER.store(0, Ordering::Release);
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
                10,
            )
        } != 1
        {
            continue;
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
