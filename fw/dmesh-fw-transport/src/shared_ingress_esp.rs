//! Temporary metadata scheduler for ESP callbacks.
//!
//! Packet storage was removed: QUIC packet buffers come from the registered
//! bearer context. The remaining functions only preserve callback scheduling
//! call sites while each radio is converted to `PacketBearer`.

use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use quic_lite::{packet_pool::PoolBufferLease, OwnedPacket};

pub const FRAME_CAPACITY: usize = crate::TRANSPORT_MTU + 96;
pub const ESP_CALLBACK_PACKET_SLOTS: usize = 8;
pub const ESP_MAX_PACKET_SLOTS: usize = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum IngressKind {
    RawUdp6 = 1,
    EspNow = 2,
    Uart = 3,
    Work = 5,
    NanServiceInfo = 6,
    ConnectionTimer = 7,
    UartEgressReady = 10,
    BleCoc = 11,
    BleCocEgressReady = 12,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum IngressLink {
    None = 0,
    WifiSta = 1,
    WifiAp = 2,
}

#[derive(Clone, Copy)]
pub struct IngressPacket {
    pub kind: IngressKind,
    pub link: IngressLink,
    pub source: [u8; 6],
    pub len: u16,
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
pub type SharedPacketLease =
    PoolBufferLease<'static, 8, { quic_lite::DEFAULT_PACKET_POOL_SLOT_SIZE }>;
pub type OwnedIngressPacket = OwnedPacket<SharedPacketLease>;

static RAW_UDP6: AtomicUsize = AtomicUsize::new(0);
static ESP_NOW: AtomicUsize = AtomicUsize::new(0);
static NAN_INFO: AtomicUsize = AtomicUsize::new(0);
static BLE_COC: AtomicUsize = AtomicUsize::new(0);
static DROPS: AtomicU32 = AtomicU32::new(0);

fn slot(kind: IngressKind) -> Option<&'static AtomicUsize> {
    match kind {
        IngressKind::RawUdp6 => Some(&RAW_UDP6),
        IngressKind::EspNow => Some(&ESP_NOW),
        IngressKind::NanServiceInfo => Some(&NAN_INFO),
        IngressKind::BleCoc => Some(&BLE_COC),
        _ => None,
    }
}

pub fn start(kind: IngressKind, handler: IngressHandler) -> bool {
    let Some(slot) = slot(kind) else { return true };
    slot.store(handler as usize, Ordering::Release);
    true
}

pub fn stop(kind: IngressKind) {
    if let Some(slot) = slot(kind) {
        slot.store(0, Ordering::Release);
    }
}

pub fn enqueue(kind: IngressKind, source: [u8; 6], bytes: &[u8]) -> bool {
    enqueue_on_link(kind, IngressLink::None, source, bytes)
}

pub fn enqueue_on_link(
    kind: IngressKind,
    link: IngressLink,
    source: [u8; 6],
    bytes: &[u8],
) -> bool {
    let raw = slot(kind).map(|s| s.load(Ordering::Acquire)).unwrap_or(0);
    if raw == 0 || bytes.len() > u16::MAX as usize {
        DROPS.fetch_add(1, Ordering::Relaxed);
        return false;
    }
    let handler: IngressHandler = unsafe { core::mem::transmute(raw) };
    handler(
        IngressPacket {
            kind,
            link,
            source,
            len: bytes.len() as u16,
        },
        bytes,
    );
    true
}

pub fn schedule_work(work: fn()) -> bool {
    work();
    true
}
pub fn schedule_connection_timer(handler: fn()) -> bool {
    handler();
    true
}
pub fn schedule_uart_egress_ready(handler: fn()) -> bool {
    handler();
    true
}
pub fn schedule_ble_coc_egress_ready(handler: fn()) -> bool {
    handler();
    true
}
pub fn active_pairing_bearer() -> Option<IngressKind> {
    None
}
pub fn set_packet_capacity_limit(_slots: usize) {}
pub fn available() -> usize {
    0
}
pub fn drops() -> u32 {
    DROPS.load(Ordering::Relaxed)
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct IngressMemoryStats {
    pub packet_slots: u32,
    pub packet_slots_available: u32,
    pub packet_drops: u32,
    pub worker_stack_bytes: u32,
    pub worker_running: bool,
    pub worker_starts: u32,
    pub worker_create_failures: u32,
    pub worker_stack_min_free_words: u32,
    pub free_internal_bytes: u32,
    pub min_free_internal_bytes: u32,
    pub largest_internal_block_bytes: u32,
}

pub fn memory_stats() -> IngressMemoryStats {
    IngressMemoryStats {
        packet_drops: drops(),
        ..IngressMemoryStats::default()
    }
}
