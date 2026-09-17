//! ESP Wi-Fi glue for the common raw Ethernet / IPv6 / UDP bearer.
//!
//! Packet parsing, checksum logic, and address derivation live in
//! `quic_lite::raw_udp6` so they are host-tested. This module owns only the
//! ESP callback, fixed queue, task, and raw station TX call.

use core::{
    ffi::c_void,
    sync::atomic::{AtomicBool, AtomicU32, AtomicU8, AtomicUsize, Ordering},
};

use quic_lite::raw_udp6::{
    encode_neighbor_advertisement, encode_station_ipv6_data_frame, encode_station_udp6_data_frame,
    encode_udp6, link_local_from_mac, parse_neighbor_solicitation, parse_udp6,
    parse_udp6_for_destination, Error,
};

pub const RAW_UDP6_PORT: u16 = 3339;
/// Shared local-link announce group used by lmesh discovery.
pub const ANNOUNCE_UDP6_PORT: u16 = 5227;
const ANNOUNCE_IPV6: [u8; 16] = [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x52, 0x27];
const ANNOUNCE_MAC: [u8; 6] = [0x33, 0x33, 0, 0, 0x52, 0x27];
const FRAME_CAPACITY: usize = quic_lite::DEFAULT_MAX_DATAGRAM_SIZE + 96;
// Temporary e6 MAC-ACK probe. When enabled, the registered STA RX callback
// releases the driver buffer and returns immediately, without touching the
// shared pool or parser. It is intentionally false in normal firmware; a
// one-off hardware build can prove whether callback cost affects ACK timing.
const RX_DROP_FOR_MAC_ACK_PROBE: bool = false;
// Temporary STA-only A/B: use the identical Ethernet-II handoff registered by
// ESP-IDF's `esp_netif` for lwIP (`esp_wifi_internal_tx`). Raw action/NOW
// remains on `esp_wifi_80211_tx`; AP already uses its normal Ethernet handoff.
// The normal associated-STA path is ESP-IDF Ethernet submission. Raw 802.11
// injection remains a live diagnostic opt-out.  This is deliberately atomic,
// not a build-time A/B: UART/Recovery control can switch the next egress
// packet without rebooting the radio.
static STA_DRIVER_TX_ENABLED: AtomicBool = AtomicBool::new(true);

pub fn set_sta_driver_tx(enabled: bool) {
    STA_DRIVER_TX_ENABLED.store(enabled, Ordering::Release);
}

pub fn sta_driver_tx_enabled() -> bool {
    STA_DRIVER_TX_ENABLED.load(Ordering::Acquire)
}

/// Peer identity supplied to a bearer-neutral QUIC-lite handler.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RawUdp6Peer {
    pub link: crate::shared_ingress_esp::IngressLink,
    pub mac: [u8; 6],
    pub ip: [u8; 16],
    pub port: u16,
}

/// The handler owns QUIC-lite/DCID/service state. It receives one complete
/// UDP payload and writes at most one response payload into `response`.
pub type RawUdp6Handler = fn(
    quic_lite::PathId,
    RawUdp6Peer,
    &[u8],
    &mut [u8; quic_lite::DEFAULT_MAX_DATAGRAM_SIZE],
) -> Option<usize>;
/// Consume one complete connectionless UDP payload with immutable source
/// metadata. The adapter selects this callback by UDP destination only; it
/// does not decode direct envelopes or application records.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectionlessUdp6Outcome {
    Rejected,
    Handled,
    Response(usize),
}

pub type ConnectionlessUdp6Handler = fn(
    RawUdp6Peer,
    &[u8],
    &mut [u8; quic_lite::DEFAULT_MAX_DATAGRAM_SIZE],
) -> ConnectionlessUdp6Outcome;
/// Produce a further already-authorized connection packet. This is not a
/// bearer queue: the connection retains the packet ledger and the adapter
/// immediately transmits each returned datagram.
pub type RawUdp6PollHandler =
    fn(quic_lite::PathId, &mut [u8; quic_lite::DEFAULT_MAX_DATAGRAM_SIZE]) -> Option<usize>;

static HANDLER: AtomicUsize = AtomicUsize::new(0);
static CONNECTIONLESS_HANDLER: AtomicUsize = AtomicUsize::new(0);
static POLL_HANDLER: AtomicUsize = AtomicUsize::new(0);
static STARTED: AtomicBool = AtomicBool::new(false);

/// Whether raw UDP6 currently owns the STA Ethernet RX callback. `false`
/// leaves receive delivery to the default ESP-IDF esp-netif/lwIP glue.
pub fn started() -> bool {
    STARTED.load(Ordering::Acquire)
}
// ESP-IDF keeps raw Ethernet RX callbacks per data interface.  STA is
// installed at raw-bearer startup; AP is installed only after APSTA is live,
// because registering WIFI_IF_AP while the driver is STA-only is not a
// portable success condition across the C6 SDK revisions we use.
static AP_RX_CALLBACK_REGISTERED: AtomicBool = AtomicBool::new(false);
static LOCAL_MAC_LOW: AtomicU32 = AtomicU32::new(0);
static LOCAL_MAC_HIGH: AtomicU32 = AtomicU32::new(0);
static AP_MAC_LOW: AtomicU32 = AtomicU32::new(0);
static AP_MAC_HIGH: AtomicU32 = AtomicU32::new(0);
static AP_BSSID_LOW: AtomicU32 = AtomicU32::new(0);
static AP_BSSID_HIGH: AtomicU32 = AtomicU32::new(0);
static RX_FRAMES: AtomicU32 = AtomicU32::new(0);
static RX_QUEUE_DROPS: AtomicU32 = AtomicU32::new(0);
static RX_INVALID: AtomicU32 = AtomicU32::new(0);
static UDP_DELIVERED: AtomicU32 = AtomicU32::new(0);
static UDP_PARSED: AtomicU32 = AtomicU32::new(0);
static NDP_ADVERTISEMENTS: AtomicU32 = AtomicU32::new(0);
static NDP_INVALID: AtomicU32 = AtomicU32::new(0);
static TX_FRAMES: AtomicU32 = AtomicU32::new(0);
static TX_FAILURES: AtomicU32 = AtomicU32::new(0);
static LAST_TX_RESULT: AtomicU32 = AtomicU32::new(0);
static RAW_TX_COMPLETIONS: AtomicU32 = AtomicU32::new(0);
static RAW_TX_COMPLETION_FAILURES: AtomicU32 = AtomicU32::new(0);
static RAW_TX_COMPLETION_RATE: AtomicU32 = AtomicU32::new(0);
static TX_SUBMIT_CALLS: AtomicU32 = AtomicU32::new(0);
static TX_SUBMIT_US_TOTAL: AtomicU32 = AtomicU32::new(0);
static TX_SUBMIT_US_MAX: AtomicU32 = AtomicU32::new(0);
// A one-packet raw burst must not wait indefinitely for a peer packet before
// it can make its next sender-owned packet eligible.  The continuation uses
// the existing shared ingress worker (and its already-accounted stack), not
// a per-bearer task or queue.  It is armed only for the explicit burst-one
// pacing mode, where yielding the CPU also gives the STA an RX/ACK window.
type UdpPathBindings =
    dmesh_server::transport_path::PathBindingTable<RawUdp6Peer, { crate::MAX_QUIC_ASSOCIATIONS }>;
// Access is serialized by the one shared packet worker. Unlike the previous
// global last-peer atomics, every opaque path retains its exact link/MAC/IP/
// port return tuple, matching the host UDP association owner.
static mut UDP_PATH_BINDINGS: UdpPathBindings =
    UdpPathBindings::new(((dmesh_server::transport_path::TransportId::UDP6.0 as u64) << 48) | 1);
/// 0=not attempted, 1=started, 2=shared worker unavailable, 3=RX callback
/// registration failed. This is deliberately a small status value rather
/// than a boot-only log: a host can inspect it after association has settled.
static START_STATUS: AtomicU32 = AtomicU32::new(0);
pub const ANNOUNCE_PEER_CAPACITY: usize = 10;

/// A bounded, lock-free observation record. The shared ingress worker is the
/// only writer; snapshots may see an older complete record but never retain a
/// Wi-Fi driver buffer or allocate while receiving a multicast announce.
struct AnnouncePeerSlot {
    device_id: [AtomicU32; 4],
    device_id_len: AtomicU8,
    source_ip: [AtomicU32; 4],
    source_mac_low: AtomicU32,
    source_mac_high: AtomicU32,
    uptime_secs: AtomicU32,
    kind: AtomicU32,
    last_seen_ms: AtomicU32,
}

impl AnnouncePeerSlot {
    const fn new() -> Self {
        Self {
            device_id: [
                AtomicU32::new(0),
                AtomicU32::new(0),
                AtomicU32::new(0),
                AtomicU32::new(0),
            ],
            device_id_len: AtomicU8::new(0),
            source_ip: [
                AtomicU32::new(0),
                AtomicU32::new(0),
                AtomicU32::new(0),
                AtomicU32::new(0),
            ],
            source_mac_low: AtomicU32::new(0),
            source_mac_high: AtomicU32::new(0),
            uptime_secs: AtomicU32::new(0),
            kind: AtomicU32::new(0),
            last_seen_ms: AtomicU32::new(0),
        }
    }
}

static ANNOUNCE_PEERS: [AnnouncePeerSlot; ANNOUNCE_PEER_CAPACITY] =
    [const { AnnouncePeerSlot::new() }; ANNOUNCE_PEER_CAPACITY];
static ANNOUNCE_NEXT: AtomicUsize = AtomicUsize::new(0);
static ANNOUNCE_RECEIVED: AtomicU32 = AtomicU32::new(0);
static ANNOUNCE_INVALID: AtomicU32 = AtomicU32::new(0);

/// A copied presence observation exposed to status adapters. `last_seen_ms`
/// uses the ESP monotonic millisecond counter and is zero for an unused slot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AnnouncePeerSnapshot {
    pub device_id: [u8; 16],
    pub device_id_len: u8,
    pub source_ip: [u8; 16],
    pub source_mac: [u8; 6],
    pub uptime_secs: u32,
    pub kind: u8,
    pub last_seen_ms: u32,
}

/// Return the fixed ten-entry ESP discovery cache. Entries are advisory,
/// unsigned, and replaced round-robin when full.
pub fn announce_peers(out: &mut [Option<AnnouncePeerSnapshot>; ANNOUNCE_PEER_CAPACITY]) {
    for (index, slot) in ANNOUNCE_PEERS.iter().enumerate() {
        let last_seen_ms = slot.last_seen_ms.load(Ordering::Acquire);
        if last_seen_ms == 0 {
            out[index] = None;
            continue;
        }
        let mut device_id = [0; 16];
        let mut source_ip = [0; 16];
        for (index, word) in slot.device_id.iter().enumerate() {
            device_id[index * 4..index * 4 + 4]
                .copy_from_slice(&word.load(Ordering::Relaxed).to_be_bytes());
        }
        for (index, word) in slot.source_ip.iter().enumerate() {
            source_ip[index * 4..index * 4 + 4]
                .copy_from_slice(&word.load(Ordering::Relaxed).to_be_bytes());
        }
        let low = slot.source_mac_low.load(Ordering::Relaxed).to_le_bytes();
        let high = slot.source_mac_high.load(Ordering::Relaxed).to_le_bytes();
        out[index] = Some(AnnouncePeerSnapshot {
            device_id,
            device_id_len: slot.device_id_len.load(Ordering::Relaxed),
            source_ip,
            source_mac: [low[0], low[1], low[2], low[3], high[0], high[1]],
            uptime_secs: slot.uptime_secs.load(Ordering::Relaxed),
            kind: slot.kind.load(Ordering::Relaxed) as u8,
            last_seen_ms,
        });
    }
}
// Only the single shared-ingress consumer calls `dispatch_ingress`, therefore
// these scratch frames are never accessed concurrently. They are temporary
// until the common packet-pool conversion lands; no callback retains them.
static mut TX_FRAME: [u8; FRAME_CAPACITY] = [0; FRAME_CAPACITY];
static mut IEEE80211_TX_FRAME: [u8; FRAME_CAPACITY] = [0; FRAME_CAPACITY];
static mut RESPONSE_BUFFER: [u8; quic_lite::DEFAULT_MAX_DATAGRAM_SIZE] =
    [0; quic_lite::DEFAULT_MAX_DATAGRAM_SIZE];
// One common writable-edge slot preserves an encoded QUIC datagram when the
// nonblocking ESP Wi-Fi submit queue is full. It is not a UDP retransmission
// queue; quic-lite owns packet history and this driver retries the exact
// physically-unsubmitted bytes before polling for anything new.
static mut EGRESS_DRIVER: quic_lite::connection::DatagramEgressDriver<
    quic_lite::PathId,
    { quic_lite::DEFAULT_MAX_DATAGRAM_SIZE },
> = quic_lite::connection::DatagramEgressDriver::new();
/// Snapshot counters for status/log adapters.  The counters are deliberately
/// separate from the packet ingress path and remain meaningful across bearers.
pub fn stats() -> (u32, u32, u32, u32, u32, u32) {
    (
        RX_FRAMES.load(Ordering::Relaxed),
        RX_QUEUE_DROPS.load(Ordering::Relaxed),
        RX_INVALID.load(Ordering::Relaxed),
        UDP_DELIVERED.load(Ordering::Relaxed),
        TX_FRAMES.load(Ordering::Relaxed),
        TX_FAILURES.load(Ordering::Relaxed),
    )
}

pub fn start_status() -> u32 {
    START_STATUS.load(Ordering::Relaxed)
}

/// Number of validated Neighbor Solicitations answered by this bearer.
pub fn ndp_advertisements() -> u32 {
    NDP_ADVERTISEMENTS.load(Ordering::Relaxed)
}

/// Monotonic raw-UDP6 egress/NDP counters for the common radio snapshot.
/// They are observations only: the shared transport owns retries and no
/// extra packet state is retained here.
pub fn diagnostics() -> (u32, u32, u32, u32, u32, u32) {
    (
        NDP_ADVERTISEMENTS.load(Ordering::Relaxed),
        TX_FAILURES.load(Ordering::Relaxed),
        LAST_TX_RESULT.load(Ordering::Relaxed),
        RAW_TX_COMPLETIONS.load(Ordering::Relaxed),
        RAW_TX_COMPLETION_FAILURES.load(Ordering::Relaxed),
        RAW_TX_COMPLETION_RATE.load(Ordering::Relaxed),
    )
}

pub fn reset_diagnostics() {
    RX_FRAMES.store(0, Ordering::Relaxed);
    RX_QUEUE_DROPS.store(0, Ordering::Relaxed);
    RX_INVALID.store(0, Ordering::Relaxed);
    UDP_DELIVERED.store(0, Ordering::Relaxed);
    UDP_PARSED.store(0, Ordering::Relaxed);
    NDP_ADVERTISEMENTS.store(0, Ordering::Relaxed);
    NDP_INVALID.store(0, Ordering::Relaxed);
    TX_FRAMES.store(0, Ordering::Relaxed);
    TX_FAILURES.store(0, Ordering::Relaxed);
    LAST_TX_RESULT.store(0, Ordering::Relaxed);
    RAW_TX_COMPLETIONS.store(0, Ordering::Relaxed);
    RAW_TX_COMPLETION_FAILURES.store(0, Ordering::Relaxed);
    RAW_TX_COMPLETION_RATE.store(0, Ordering::Relaxed);
    TX_SUBMIT_CALLS.store(0, Ordering::Relaxed);
    TX_SUBMIT_US_TOTAL.store(0, Ordering::Relaxed);
    TX_SUBMIT_US_MAX.store(0, Ordering::Relaxed);
}

unsafe extern "C" fn raw_tx_done(info: *const esp_idf_sys::esp_80211_tx_info_t) {
    if info.is_null() {
        return;
    }
    let info = unsafe { &*info };
    RAW_TX_COMPLETIONS.fetch_add(1, Ordering::Relaxed);
    RAW_TX_COMPLETION_RATE.store(info.rate as u32, Ordering::Relaxed);
    if info.tx_status != esp_idf_sys::wifi_tx_status_t_WIFI_SEND_SUCCESS {
        RAW_TX_COMPLETION_FAILURES.fetch_add(1, Ordering::Relaxed);
    }
}

/// Register the raw STA RX callback with the device-wide packet worker.
///
/// `WIFI_IF_AP` is a distinct raw Ethernet ingress and is registered later by
/// [`ensure_ap_rx_callback`] once an APSTA owner has actually started.  The
/// action-frame receivers do *not* use this API: ESP's private action
/// dispatcher is global (category/action/callback only), and therefore has
/// no per-interface registration to duplicate.
pub fn start(
    local_mac: [u8; 6],
    ap_bssid: [u8; 6],
    handler: RawUdp6Handler,
    connectionless_handler: ConnectionlessUdp6Handler,
) -> bool {
    HANDLER.store(handler as usize, Ordering::Release);
    CONNECTIONLESS_HANDLER.store(connectionless_handler as usize, Ordering::Release);
    store_local_mac(local_mac);
    store_ap_bssid(ap_bssid);
    if STARTED.swap(true, Ordering::AcqRel) {
        START_STATUS.store(1, Ordering::Release);
        return true;
    }
    if !crate::shared_ingress_esp::start(
        crate::shared_ingress_esp::IngressKind::RawUdp6,
        dispatch_ingress,
    ) {
        crate::commands::send_response(b"raw udp6 queue failed");
        STARTED.store(false, Ordering::Release);
        START_STATUS.store(2, Ordering::Release);
        return false;
    }
    let register_result = crate::wifi_esp::register_ethernet_rx_callback(
        crate::wifi_esp::RadioInterface::Sta,
        Some(rx_callback_sta),
    );
    let registered = register_result == esp_idf_sys::ESP_OK;
    if !registered {
        crate::commands::send_stat(b"raw udp6 rxcb result=", register_result as u32 as u64);
        STARTED.store(false, Ordering::Release);
        START_STATUS.store(3, Ordering::Release);
        return false;
    }
    let tx_callback = crate::wifi_esp::register_raw_tx_done_callback(Some(raw_tx_done));
    if tx_callback != esp_idf_sys::ESP_OK {
        crate::commands::send_stat(b"raw udp6 txcb result=", tx_callback as u32 as u64);
    }
    START_STATUS.store(1, Ordering::Release);
    true
}

/// Start the same raw UDP6 bearer on an open AP when no STA association
/// exists.  AP mode has a distinct ESP-IDF Ethernet RX registration; it must
/// not be gated on `esp_wifi_sta_get_ap_info()`.  The packet worker, handler,
/// and response path remain shared with the STA bearer.
pub fn start_ap(
    handler: RawUdp6Handler,
    connectionless_handler: ConnectionlessUdp6Handler,
) -> bool {
    let Some(ap_mac) = crate::wifi_esp::interface_mac(crate::wifi_esp::RadioInterface::Ap) else {
        crate::commands::send_response(b"raw udp6 AP mac failed");
        return false;
    };
    HANDLER.store(handler as usize, Ordering::Release);
    CONNECTIONLESS_HANDLER.store(connectionless_handler as usize, Ordering::Release);
    store_local_mac(ap_mac);
    store_ap_bssid(ap_mac);
    if !STARTED.swap(true, Ordering::AcqRel)
        && !crate::shared_ingress_esp::start(
            crate::shared_ingress_esp::IngressKind::RawUdp6,
            dispatch_ingress,
        )
    {
        crate::commands::send_response(b"raw udp6 queue failed");
        STARTED.store(false, Ordering::Release);
        START_STATUS.store(2, Ordering::Release);
        return false;
    }
    if !ensure_ap_rx_callback() {
        STARTED.store(false, Ordering::Release);
        START_STATUS.store(3, Ordering::Release);
        return false;
    }
    let tx_callback = crate::wifi_esp::register_raw_tx_done_callback(Some(raw_tx_done));
    if tx_callback != esp_idf_sys::ESP_OK {
        crate::commands::send_stat(b"raw udp6 txcb result=", tx_callback as u32 as u64);
    }
    START_STATUS.store(1, Ordering::Release);
    true
}

/// Remove raw Ethernet ingress before STA teardown or a personality change.
/// The shared packet pool remains available to another bearer; only this
/// driver's callback and dispatch handler are disabled.
pub fn stop() {
    if !STARTED.swap(false, Ordering::AcqRel) {
        return;
    }
    let _ =
        crate::wifi_esp::register_ethernet_rx_callback(crate::wifi_esp::RadioInterface::Sta, None);
    if AP_RX_CALLBACK_REGISTERED.swap(false, Ordering::AcqRel) {
        let _ = crate::wifi_esp::register_ethernet_rx_callback(
            crate::wifi_esp::RadioInterface::Ap,
            None,
        );
    }
    HANDLER.store(0, Ordering::Release);
    crate::shared_ingress_esp::stop(crate::shared_ingress_esp::IngressKind::RawUdp6);
    START_STATUS.store(0, Ordering::Release);
}

/// Re-register driver-owned callbacks after a controlled Wi-Fi stop/start.
///
/// A lab APSTA transition owns the ESP-IDF lifecycle but not this bearer.  A
/// Rust-side `STARTED` flag alone is insufficient after `esp_wifi_stop()`:
/// ESP-IDF has discarded the Ethernet RX and raw-TX completion callbacks.
/// Keep the shared ingress worker and handler intact, but bind them again to
/// the newly started STA driver epoch.
pub fn rebind_sta_after_wifi_restart() -> bool {
    if !STARTED.load(Ordering::Acquire) {
        return true;
    }
    // ESP-IDF discarded both interface callbacks with the driver.  The AP
    // owner calls `ensure_ap_rx_callback` after this STA baseline rebind.
    AP_RX_CALLBACK_REGISTERED.store(false, Ordering::Release);
    let rx = crate::wifi_esp::register_ethernet_rx_callback(
        crate::wifi_esp::RadioInterface::Sta,
        Some(rx_callback_sta),
    );
    if rx != esp_idf_sys::ESP_OK {
        START_STATUS.store(3, Ordering::Release);
        crate::commands::send_stat(b"raw udp6 rebind rxcb result=", rx as u32 as u64);
        return false;
    }
    let tx = crate::wifi_esp::register_raw_tx_done_callback(Some(raw_tx_done));
    if tx != esp_idf_sys::ESP_OK {
        crate::commands::send_stat(b"raw udp6 rebind txcb result=", tx as u32 as u64);
    }
    START_STATUS.store(1, Ordering::Release);
    true
}

/// Register the AP raw-Ethernet callback after an APSTA transition.
///
/// This is deliberately idempotent and does not create a second queue: AP
/// and STA frames share the device-wide ingress pool and parser.  A false
/// result means the AP raw *data* plane is unavailable; it does not alter the
/// separately-global NOW action dispatcher. NAN action receive is DW-only.
pub fn ensure_ap_rx_callback() -> bool {
    if !STARTED.load(Ordering::Acquire) || AP_RX_CALLBACK_REGISTERED.load(Ordering::Acquire) {
        return true;
    }
    let result = crate::wifi_esp::register_ethernet_rx_callback(
        crate::wifi_esp::RadioInterface::Ap,
        Some(rx_callback_ap),
    );
    if result != esp_idf_sys::ESP_OK {
        crate::commands::send_stat(b"raw udp6 AP rxcb result=", result as u32 as u64);
        return false;
    }
    let Some(ap_mac) = crate::wifi_esp::interface_mac(crate::wifi_esp::RadioInterface::Ap) else {
        crate::commands::send_response(b"raw udp6 AP mac failed");
        return false;
    };
    store_ap_mac(ap_mac);
    AP_RX_CALLBACK_REGISTERED.store(true, Ordering::Release);
    true
}

/// Refresh the associated AP identity after the shared STA controller has
/// reselected a beacon.  The raw bearer owns no association policy, but its
/// To-DS frames must use the newly selected BSSID immediately; otherwise a
/// successful fallback association would still transmit to the old AP.
pub fn update_ap_bssid(ap_bssid: [u8; 6]) {
    if STARTED.load(Ordering::Acquire) {
        store_ap_bssid(ap_bssid);
    }
}

/// Install the connection-owned raw transmit poller. Recovery uses this for
/// a bounded in-flight window; Main may leave it unset while it uses its own
/// connection scheduler.
pub fn set_poll_handler(handler: Option<RawUdp6PollHandler>) {
    POLL_HANDLER.store(
        handler.map_or(0, |handler| handler as usize),
        Ordering::Release,
    );
}

pub fn tx_submit_timing() -> (u32, u32, u32) {
    (
        TX_SUBMIT_CALLS.load(Ordering::Relaxed),
        TX_SUBMIT_US_TOTAL.load(Ordering::Relaxed),
        TX_SUBMIT_US_MAX.load(Ordering::Relaxed),
    )
}

fn record_tx_submit(elapsed_us: u32) {
    TX_SUBMIT_CALLS.fetch_add(1, Ordering::Relaxed);
    TX_SUBMIT_US_TOTAL.fetch_add(elapsed_us, Ordering::Relaxed);
    let mut observed = TX_SUBMIT_US_MAX.load(Ordering::Relaxed);
    while elapsed_us > observed {
        match TX_SUBMIT_US_MAX.compare_exchange_weak(
            observed,
            elapsed_us,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => break,
            Err(current) => observed = current,
        }
    }
}

pub fn last_tx_result() -> u32 {
    LAST_TX_RESULT.load(Ordering::Relaxed)
}

unsafe extern "C" fn rx_callback_sta(buffer: *mut c_void, len: u16, eb: *mut c_void) -> i32 {
    unsafe {
        rx_callback(
            crate::shared_ingress_esp::IngressLink::WifiSta,
            buffer,
            len,
            eb,
        )
    }
}

unsafe extern "C" fn rx_callback_ap(buffer: *mut c_void, len: u16, eb: *mut c_void) -> i32 {
    unsafe {
        rx_callback(
            crate::shared_ingress_esp::IngressLink::WifiAp,
            buffer,
            len,
            eb,
        )
    }
}

unsafe fn rx_callback(
    link: crate::shared_ingress_esp::IngressLink,
    buffer: *mut c_void,
    len: u16,
    eb: *mut c_void,
) -> i32 {
    if buffer.is_null() || len as usize > FRAME_CAPACITY {
        if !eb.is_null() {
            crate::wifi_esp::release_ethernet_rx_buffer(eb);
        }
        RX_QUEUE_DROPS.fetch_add(1, Ordering::Relaxed);
        return esp_idf_sys::ESP_FAIL;
    }
    if RX_DROP_FOR_MAC_ACK_PROBE {
        if !eb.is_null() {
            crate::wifi_esp::release_ethernet_rx_buffer(eb);
        }
        RX_FRAMES.fetch_add(1, Ordering::Relaxed);
        return esp_idf_sys::ESP_OK;
    }
    unsafe {
        let frame = core::slice::from_raw_parts(buffer.cast::<u8>(), len as usize);
        // ESP-IDF delivers the whole associated Ethernet feed to this raw
        // callback.  The shared eight-slot packet pool is for the UDP6
        // bearer, not a general STA sniffer: copying ARP, IPv4, and unrelated
        // L2 traffic can otherwise evict the IPv6 Neighbor Solicitation that
        // establishes the return path for an incoming QUIC-lite association.
        // Keep the callback's decision to the common raw-UDP6 frame classes;
        // detailed NDP and UDP validation remains in the worker below.
        if !quic_lite::raw_udp6::is_icmpv6_frame(frame)
            && !quic_lite::raw_udp6::is_udp6_frame(frame)
        {
            if !eb.is_null() {
                crate::wifi_esp::release_ethernet_rx_buffer(eb);
            }
            return esp_idf_sys::ESP_OK;
        }
        let queued = crate::shared_ingress_esp::enqueue_on_link(
            crate::shared_ingress_esp::IngressKind::RawUdp6,
            link,
            [0; 6],
            frame,
        );
        // `buffer` is owned by the Wi-Fi driver. This adapter has copied it
        // into its static queue, so it must return the opaque RX allocation
        // immediately; retaining it would exhaust the driver's RX pool.
        if !eb.is_null() {
            crate::wifi_esp::release_ethernet_rx_buffer(eb);
        }
        if !queued {
            RX_QUEUE_DROPS.fetch_add(1, Ordering::Relaxed);
            return esp_idf_sys::ESP_FAIL;
        }
    }
    RX_FRAMES.fetch_add(1, Ordering::Relaxed);
    esp_idf_sys::ESP_OK
}

fn dispatch_ingress(item: crate::shared_ingress_esp::IngressPacket, frame: &[u8]) {
    let local_mac = local_mac_for(item.link());
    let local_ip = link_local_from_mac(local_mac);
    // Linux resolves a link-local IPv6 destination with NDP; it does not
    // infer the Ethernet MAC from a modified-EUI-64 IID. Answer the bounded
    // NS/NA exchange before the UDP-only parser sees ICMPv6.
    if quic_lite::raw_udp6::is_icmpv6_frame(frame) {
        match parse_neighbor_solicitation(frame, local_ip) {
            Ok(solicitation) => {
                crate::commands::send_stat(b"raw udp6 ndp accepted=", 1);
                let advertisement = unsafe { &mut *core::ptr::addr_of_mut!(TX_FRAME) };
                if let Ok(frame_len) = encode_neighbor_advertisement(
                    advertisement,
                    solicitation.source_mac,
                    local_mac,
                    solicitation.source_ip,
                    local_ip,
                ) {
                    // AP and STA own distinct Ethernet egress.  An AP-side
                    // Neighbor Advertisement must follow the received AP
                    // link; sending it through the STA raw injector can
                    // reset an unassociated APSTA epoch.
                    if transmit_ipv6(
                        item.link(),
                        solicitation.source_mac,
                        local_mac,
                        &advertisement[..frame_len],
                    ) {
                        NDP_ADVERTISEMENTS.fetch_add(1, Ordering::Relaxed);
                        TX_FRAMES.fetch_add(1, Ordering::Relaxed);
                        crate::commands::send_stat(
                            b"raw udp6 ndp tx result=",
                            LAST_TX_RESULT.load(Ordering::Relaxed) as u64,
                        );
                    } else {
                        TX_FAILURES.fetch_add(1, Ordering::Relaxed);
                        crate::commands::send_stat(
                            b"raw udp6 ndp tx result=",
                            LAST_TX_RESULT.load(Ordering::Relaxed) as u64,
                        );
                    }
                } else {
                    crate::commands::send_response(b"raw udp6 ndp encode failed");
                }
            }
            Err(_) => {
                // Router solicitations/advertisements and NDP for another
                // local address are routine L2 traffic.  They are neither a
                // DMesh packet failure nor UART diagnostics.  Retain only a
                // scalar count for malformed NS traffic aimed at this raw
                // bearer; explicit debug can expose that counter later.
                if quic_lite::raw_udp6::icmpv6_frame_info(frame).is_some_and(|info| {
                    info.icmp_type == quic_lite::raw_udp6::ICMPV6_NEIGHBOR_SOLICITATION
                }) {
                    NDP_INVALID.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        return;
    }
    // The raw adapter receives all normal Ethernet traffic from the STA
    // driver.  Only IPv6 UDP can be a DMesh UDP6 bearer packet; do not count
    // unrelated L2/control traffic as a rejected DMesh datagram.
    if !quic_lite::raw_udp6::is_udp6_frame(frame) {
        return;
    }
    // Connectionless records have a distinct multicast UDP destination. The
    // adapter passes the complete payload and source facts to shared policy;
    // it does not inspect the direct envelope or tagged application record.
    if let Ok(packet) = parse_udp6_for_destination(frame, ANNOUNCE_IPV6, ANNOUNCE_UDP6_PORT) {
        let handler = CONNECTIONLESS_HANDLER.load(Ordering::Acquire);
        let peer = RawUdp6Peer {
            link: item.link(),
            mac: packet.source_mac,
            ip: packet.source_ip,
            port: packet.source_port,
        };
        if handler == 0 {
            ANNOUNCE_INVALID.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let handler = unsafe { core::mem::transmute::<usize, ConnectionlessUdp6Handler>(handler) };
        let response = unsafe { &mut *core::ptr::addr_of_mut!(RESPONSE_BUFFER) };
        match handler(peer, packet.payload, response) {
            ConnectionlessUdp6Outcome::Rejected => {
                ANNOUNCE_INVALID.fetch_add(1, Ordering::Relaxed);
            }
            ConnectionlessUdp6Outcome::Handled => {}
            ConnectionlessUdp6Outcome::Response(used) if used <= response.len() => {
                if !transmit_udp6(item.link(), peer, RAW_UDP6_PORT, &response[..used]) {
                    TX_FAILURES.fetch_add(1, Ordering::Relaxed);
                }
            }
            ConnectionlessUdp6Outcome::Response(_) => {
                TX_FAILURES.fetch_add(1, Ordering::Relaxed);
            }
        }
        return;
    }
    let packet = match parse_udp6(frame, local_ip, RAW_UDP6_PORT) {
        Ok(packet) => packet,
        // The Ethernet callback receives every normal UDP datagram delivered
        // to the STA.  A packet for another IPv6 address or UDP service is
        // not a malformed DMesh frame and must not poison the UDP6 health
        // counter or its first-error diagnostic.
        Err(Error::Destination | Error::Port) => return,
        Err(error) => {
            if RX_INVALID.fetch_add(1, Ordering::Relaxed) == 0 {
                crate::commands::send_stat(
                    b"raw udp6 parse error=",
                    quic_lite::raw_udp6::error_code(error) as u64,
                );
            }
            return;
        }
    };
    let parsed = UDP_PARSED.fetch_add(1, Ordering::Relaxed) + 1;
    if parsed <= 2 {
        crate::commands::send_stat(b"raw udp6 parsed payload=", packet.payload.len() as u64);
    }
    let handler = HANDLER.load(Ordering::Acquire);
    if handler == 0 {
        return;
    }
    let handler: RawUdp6Handler = unsafe { core::mem::transmute(handler) };
    let response = unsafe { &mut *core::ptr::addr_of_mut!(RESPONSE_BUFFER) };
    // An ACK may make transport progress without an immediate packet.  Do not
    // skip the bounded poller in that case: it owns the next queued stream
    // packet for raw UDP6 and raw action alike.
    let peer = RawUdp6Peer {
        link: item.link(),
        mac: packet.source_mac,
        ip: packet.source_ip,
        port: packet.source_port,
    };
    // Preserve the complete UDP return tuple behind a stable opaque path.
    // MAC alone is insufficient: independent host processes can use the same
    // L2 peer with different source ports and associations.
    let Some(path) = bind_udp_peer(peer) else {
        RX_QUEUE_DROPS.fetch_add(1, Ordering::Relaxed);
        return;
    };
    let immediate = handler(path, peer, packet.payload, response);
    let poll = POLL_HANDLER.load(Ordering::Acquire);
    let poll: Option<RawUdp6PollHandler> =
        (poll != 0).then(|| unsafe { core::mem::transmute(poll) });
    let mut attempted = false;
    let submitted = unsafe { &mut *core::ptr::addr_of_mut!(EGRESS_DRIVER) }
        .drain(
            path,
            response,
            crate::core_runtime::connection_tx_burst_packets(),
            immediate,
            |response| {
                Ok::<_, core::convert::Infallible>(poll.and_then(|poll| poll(path, response)))
            },
            |send_path, packet| {
                attempted = true;
                let Some(send_peer) =
                    (unsafe { (*core::ptr::addr_of!(UDP_PATH_BINDINGS)).get(send_path) })
                else {
                    return false;
                };
                let sent = transmit_udp6(send_peer.link, send_peer, RAW_UDP6_PORT, packet);
                if sent {
                    UDP_DELIVERED.fetch_add(1, Ordering::Relaxed);
                    TX_FRAMES.fetch_add(1, Ordering::Relaxed);
                } else {
                    TX_FAILURES.fetch_add(1, Ordering::Relaxed);
                }
                sent
            },
        )
        .unwrap_or(0);
    if submitted != 0 {
        // Keep a small physical-path breadcrumb for the host->STA direct
        // responder. A client timeout alone cannot distinguish a handler
        // that produced nothing from a Wi-Fi submit or AP-forwarding loss.
        if UDP_DELIVERED.load(Ordering::Relaxed) <= 2 {
            crate::commands::send_stat(b"raw udp6 egress sent=", 1);
            crate::commands::send_stat(
                b"raw udp6 egress tx result=",
                LAST_TX_RESULT.load(Ordering::Relaxed) as u64,
            );
        }
    }
    if attempted && submitted == 0 {
        crate::commands::send_stat(b"raw udp6 egress submit_failed=", 1);
    }
}

pub(crate) fn record_announce_peer(
    announce: dmesh_server::announce::Announce,
    source_mac: [u8; 6],
    source_ip: [u8; 16],
) {
    let mut selected = None;
    for (index, slot) in ANNOUNCE_PEERS.iter().enumerate() {
        let mut equal = slot.device_id_len.load(Ordering::Acquire) == announce.device_id_len;
        // Compare all sixteen bytes. Announce IDs may be shorter (ESP uses a
        // six-byte MAC) and comparing only complete chunks would otherwise
        // merge peers that differ in the final two MAC bytes.
        for (word, bytes) in slot
            .device_id
            .iter()
            .zip(announce.device_id.chunks_exact(4))
        {
            if word.load(Ordering::Acquire) != u32::from_be_bytes(bytes.try_into().unwrap()) {
                equal = false;
                break;
            }
        }
        if equal && slot.last_seen_ms.load(Ordering::Acquire) != 0 {
            selected = Some(index);
            break;
        }
    }
    let index = selected
        .unwrap_or_else(|| ANNOUNCE_NEXT.fetch_add(1, Ordering::Relaxed) % ANNOUNCE_PEER_CAPACITY);
    let slot = &ANNOUNCE_PEERS[index];
    for (word, bytes) in slot
        .device_id
        .iter()
        .zip(announce.device_id.chunks_exact(4))
    {
        word.store(
            u32::from_be_bytes(bytes.try_into().unwrap()),
            Ordering::Relaxed,
        );
    }
    slot.device_id_len
        .store(announce.device_id_len, Ordering::Relaxed);
    for (word, bytes) in slot.source_ip.iter().zip(source_ip.chunks_exact(4)) {
        word.store(
            u32::from_be_bytes(bytes.try_into().unwrap()),
            Ordering::Relaxed,
        );
    }
    slot.source_mac_low.store(
        u32::from_le_bytes([source_mac[0], source_mac[1], source_mac[2], source_mac[3]]),
        Ordering::Relaxed,
    );
    slot.source_mac_high.store(
        u32::from_le_bytes([source_mac[4], source_mac[5], 0, 0]),
        Ordering::Relaxed,
    );
    slot.uptime_secs
        .store(announce.uptime_secs, Ordering::Relaxed);
    slot.kind.store(announce.kind as u32, Ordering::Relaxed);
    let now_ms = (unsafe { esp_idf_sys::esp_timer_get_time() } / 1_000).max(1) as u32;
    slot.last_seen_ms.store(now_ms, Ordering::Release);
    ANNOUNCE_RECEIVED.fetch_add(1, Ordering::Relaxed);
}

/// Record an announce from a bearer without an IPv6 source tuple. NAN Service
/// Info, NOW action frames, and UART use this exact same bounded cache as
/// multicast UDP6; only the unavailable IPv6 provenance is represented by an
/// unspecified address. Presence semantics never depend on the bearer.
pub fn record_connectionless_announce(
    announce: dmesh_server::announce::Announce,
    source_mac: [u8; 6],
) {
    record_announce_peer(announce, source_mac, [0; 16]);
}

/// Execute one connection-owned delayed-ACK/PTO turn after Main's exact
/// QUIC-lite deadline. This adapter supplies only the last validated UDP
/// return tuple; it never decides ACK timing or retains packet data.
pub(crate) fn poll_connection_timer() {
    if !STARTED.load(Ordering::Acquire) {
        return;
    }
    let Some(path) = crate::core_runtime::connection_reply_path() else {
        return;
    };
    let Some(_) = (unsafe { (*core::ptr::addr_of!(UDP_PATH_BINDINGS)).get(path) }) else {
        return;
    };
    let poll = POLL_HANDLER.load(Ordering::Acquire);
    if poll == 0 {
        return;
    }
    let poll: RawUdp6PollHandler = unsafe { core::mem::transmute(poll) };
    let response = unsafe { &mut *core::ptr::addr_of_mut!(RESPONSE_BUFFER) };
    let first = poll(path, response);
    let submitted = unsafe { &mut *core::ptr::addr_of_mut!(EGRESS_DRIVER) }
        .drain(
            path,
            response,
            crate::core_runtime::connection_tx_burst_packets(),
            first,
            |response| Ok::<_, core::convert::Infallible>(poll(path, response)),
            |send_path, packet| {
                let Some(send_peer) =
                    (unsafe { (*core::ptr::addr_of!(UDP_PATH_BINDINGS)).get(send_path) })
                else {
                    return false;
                };
                let sent = transmit_udp6(send_peer.link, send_peer, RAW_UDP6_PORT, packet);
                if sent {
                    TX_FRAMES.fetch_add(1, Ordering::Relaxed);
                } else {
                    TX_FAILURES.fetch_add(1, Ordering::Relaxed);
                }
                sent
            },
        )
        .unwrap_or(0);
    let _ = submitted;
}

fn bind_udp_peer(peer: RawUdp6Peer) -> Option<quic_lite::PathId> {
    unsafe {
        let bindings = &mut *core::ptr::addr_of_mut!(UDP_PATH_BINDINGS);
        if let Some(path) = bindings.bind(peer) {
            return Some(path);
        }
        if !bindings.reclaim_one(|path| !crate::core_runtime::connection_has_path(path)) {
            return None;
        }
        bindings.bind(peer)
    }
}

pub(crate) fn transmit_udp6(
    link: crate::shared_ingress_esp::IngressLink,
    peer: RawUdp6Peer,
    source_port: u16,
    payload: &[u8],
) -> bool {
    let local_mac = local_mac_for(link);
    let local_ip = link_local_from_mac(local_mac);
    if link == crate::shared_ingress_esp::IngressLink::WifiSta && !sta_driver_tx_enabled() {
        let wifi_frame = unsafe { &mut *core::ptr::addr_of_mut!(IEEE80211_TX_FRAME) };
        let Ok(frame_len) = encode_station_udp6_data_frame(
            wifi_frame,
            load_ap_bssid(),
            local_mac,
            peer.mac,
            peer.ip,
            local_ip,
            peer.port,
            source_port,
            payload,
        ) else {
            return false;
        };
        return transmit_station_frame(wifi_frame, frame_len);
    }
    let ethernet = unsafe { &mut *core::ptr::addr_of_mut!(TX_FRAME) };
    let Ok(frame_len) = encode_udp6(
        ethernet,
        peer.mac,
        local_mac,
        peer.ip,
        local_ip,
        peer.port,
        source_port,
        payload,
    ) else {
        return false;
    };
    transmit_ipv6(link, peer.mac, local_mac, &ethernet[..frame_len])
}

/// Send one bounded unsigned presence record over every live UDP6 Wi-Fi link.
/// STA and AP have distinct ESP-IDF Ethernet egress, so APSTA must submit one
/// multicast datagram through each rather than silently favouring STA.  The
/// common payload may advertise both deterministic link-local endpoints;
/// each Ethernet frame uses the source MAC/IP of its own egress link.
/// This is intentionally outside the QUIC-lite listener port, but the payload
/// still uses the QUIC-lite private direct-message envelope. Multicast discovery must
/// not be misparsed as a connection datagram.
pub fn broadcast_announce(payload: &[u8]) -> bool {
    if payload.is_empty() || payload.len() > crate::TRANSPORT_MTU.saturating_sub(6) {
        return false;
    }
    let mut direct = [0u8; crate::TRANSPORT_MTU];
    let Some(used) = crate::core_runtime::encode_connectionless_message(payload, &mut direct)
    else {
        return false;
    };
    let mut sent = false;
    if crate::wifi_esp::sta_associated() {
        sent |= broadcast_announce_on_link(
            crate::shared_ingress_esp::IngressLink::WifiSta,
            &direct[..used],
        );
    }
    if crate::wifi_esp::lab_open_ap_active() {
        sent |= broadcast_announce_on_link(
            crate::shared_ingress_esp::IngressLink::WifiAp,
            &direct[..used],
        );
    }
    sent
}

fn broadcast_announce_on_link(
    link: crate::shared_ingress_esp::IngressLink,
    payload: &[u8],
) -> bool {
    let local_mac = local_mac_for(link);
    let local_ip = link_local_from_mac(local_mac);
    let ethernet = unsafe { &mut *core::ptr::addr_of_mut!(TX_FRAME) };
    let Ok(frame_len) = encode_udp6(
        ethernet,
        ANNOUNCE_MAC,
        local_mac,
        ANNOUNCE_IPV6,
        local_ip,
        ANNOUNCE_UDP6_PORT,
        RAW_UDP6_PORT,
        payload,
    ) else {
        return false;
    };
    transmit_ipv6(link, ANNOUNCE_MAC, local_mac, &ethernet[..frame_len])
}

fn transmit_ipv6(
    link: crate::shared_ingress_esp::IngressLink,
    destination_mac: [u8; 6],
    local_mac: [u8; 6],
    ethernet: &[u8],
) -> bool {
    match link {
        crate::shared_ingress_esp::IngressLink::WifiAp => {
            transmit_ethernet(crate::wifi_esp::RadioInterface::Ap, ethernet)
        }
        crate::shared_ingress_esp::IngressLink::WifiSta if sta_driver_tx_enabled() => {
            transmit_ethernet(crate::wifi_esp::RadioInterface::Sta, ethernet)
        }
        crate::shared_ingress_esp::IngressLink::WifiSta
        | crate::shared_ingress_esp::IngressLink::None => {
            transmit_station_ipv6(destination_mac, local_mac, ethernet)
        }
    }
}

/// This is exactly the ESP-IDF `esp_netif`/lwIP Wi-Fi handoff, including its
/// driver-owned copy and ordinary associated-STA rate/queue policy.
fn transmit_ethernet(interface: crate::wifi_esp::RadioInterface, ethernet: &[u8]) -> bool {
    let started = unsafe { esp_idf_sys::esp_timer_get_time() };
    let result = crate::wifi_esp::transmit_ethernet(interface, ethernet);
    let elapsed = (unsafe { esp_idf_sys::esp_timer_get_time() } - started).max(0) as u32;
    record_tx_submit(elapsed);
    LAST_TX_RESULT.store(result as u32, Ordering::Relaxed);
    result == esp_idf_sys::ESP_OK
}

/// Send an Ethernet-II IPv6 packet through the station's raw non-QoS data
/// path. It constructs the infrastructure To-DS frame directly, avoiding an
/// ESP private TX API and keeping the association BSSID explicit. This has
/// one caller (the raw UDP6 task), so its fixed backing buffer is never
/// concurrently reused.
fn transmit_station_ipv6(_destination_mac: [u8; 6], station_mac: [u8; 6], ethernet: &[u8]) -> bool {
    let wifi_frame = unsafe { &mut *core::ptr::addr_of_mut!(IEEE80211_TX_FRAME) };
    let Ok(wifi_len) =
        encode_station_ipv6_data_frame(wifi_frame, load_ap_bssid(), station_mac, ethernet)
    else {
        return false;
    };
    transmit_station_frame(wifi_frame, wifi_len)
}

fn transmit_station_frame(wifi_frame: &[u8], wifi_len: usize) -> bool {
    let result = crate::wifi_esp::transmit_raw_station(&wifi_frame[..wifi_len]);
    LAST_TX_RESULT.store(result as u32, Ordering::Relaxed);
    result == esp_idf_sys::ESP_OK
}

fn store_local_mac(mac: [u8; 6]) {
    LOCAL_MAC_LOW.store(
        u32::from_le_bytes([mac[0], mac[1], mac[2], mac[3]]),
        Ordering::Release,
    );
    LOCAL_MAC_HIGH.store(
        u32::from_le_bytes([mac[4], mac[5], 0, 0]),
        Ordering::Release,
    );
}

fn store_ap_mac(mac: [u8; 6]) {
    AP_MAC_LOW.store(
        u32::from_le_bytes([mac[0], mac[1], mac[2], mac[3]]),
        Ordering::Release,
    );
    AP_MAC_HIGH.store(
        u32::from_le_bytes([mac[4], mac[5], 0, 0]),
        Ordering::Release,
    );
}

fn store_ap_bssid(mac: [u8; 6]) {
    AP_BSSID_LOW.store(
        u32::from_le_bytes([mac[0], mac[1], mac[2], mac[3]]),
        Ordering::Release,
    );
    AP_BSSID_HIGH.store(
        u32::from_le_bytes([mac[4], mac[5], 0, 0]),
        Ordering::Release,
    );
}

fn load_local_mac() -> [u8; 6] {
    let low = LOCAL_MAC_LOW.load(Ordering::Acquire).to_le_bytes();
    let high = LOCAL_MAC_HIGH.load(Ordering::Acquire).to_le_bytes();
    [low[0], low[1], low[2], low[3], high[0], high[1]]
}

fn local_mac_for(link: crate::shared_ingress_esp::IngressLink) -> [u8; 6] {
    if link != crate::shared_ingress_esp::IngressLink::WifiAp {
        return load_local_mac();
    }
    let low = AP_MAC_LOW.load(Ordering::Acquire).to_le_bytes();
    let high = AP_MAC_HIGH.load(Ordering::Acquire).to_le_bytes();
    [low[0], low[1], low[2], low[3], high[0], high[1]]
}

fn load_ap_bssid() -> [u8; 6] {
    let low = AP_BSSID_LOW.load(Ordering::Acquire).to_le_bytes();
    let high = AP_BSSID_HIGH.load(Ordering::Acquire).to_le_bytes();
    [low[0], low[1], low[2], low[3], high[0], high[1]]
}
