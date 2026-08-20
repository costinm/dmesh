//! ESP Wi-Fi glue for the common raw Ethernet / IPv6 / UDP bearer.
//!
//! Packet parsing, checksum logic, and address derivation live in
//! `quic_lite::raw_udp6` so they are host-tested. This module owns only the
//! ESP callback, fixed queue, task, and raw station TX call.

use core::{
    ffi::c_void,
    sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering},
};

use quic_lite::raw_udp6::{
    encode_neighbor_advertisement, encode_station_ipv6_data_frame, encode_station_udp6_data_frame,
    encode_udp6, link_local_from_mac, parse_neighbor_solicitation, parse_udp6,
};

pub const RAW_UDP6_PORT: u16 = 3339;
const FRAME_CAPACITY: usize = quic_lite::DEFAULT_MAX_DATAGRAM_SIZE + 96;
// Temporary e6 MAC-ACK probe. When enabled, the registered STA RX callback
// releases the driver buffer and returns immediately, without touching the
// shared pool or parser. It is intentionally false in normal firmware; a
// one-off hardware build can prove whether callback cost affects ACK timing.
const RX_DROP_FOR_MAC_ACK_PROBE: bool = false;
// Temporary STA-only A/B: use the identical Ethernet-II handoff registered by
// ESP-IDF's `esp_netif` for lwIP (`esp_wifi_internal_tx`). Raw action/NOW
// remains on `esp_wifi_80211_tx`; AP already uses its normal Ethernet handoff.
// The safe starting point remains raw injection until a live command selects
// the driver's associated Ethernet handoff.  It is deliberately an atomic
// setting, not a build-time A/B: UART/Recovery control can switch the next
// egress packet without rebooting the radio.
static STA_DRIVER_TX_ENABLED: AtomicBool = AtomicBool::new(false);

pub fn set_sta_driver_tx(enabled: bool) {
    STA_DRIVER_TX_ENABLED.store(enabled, Ordering::Release);
}

pub fn sta_driver_tx_enabled() -> bool {
    STA_DRIVER_TX_ENABLED.load(Ordering::Acquire)
}

/// Peer identity supplied to a bearer-neutral QUIC-lite handler.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RawUdp6Peer {
    pub mac: [u8; 6],
    pub ip: [u8; 16],
    pub port: u16,
}

/// The handler owns QUIC-lite/DCID/service state. It receives one complete
/// UDP payload and writes at most one response payload into `response`.
pub type RawUdp6Handler =
    fn(RawUdp6Peer, &[u8], &mut [u8; quic_lite::DEFAULT_MAX_DATAGRAM_SIZE]) -> Option<usize>;
/// Produce a further already-authorized connection packet. This is not a
/// bearer queue: the connection retains the packet ledger and the adapter
/// immediately transmits each returned datagram.
pub type RawUdp6PollHandler =
    fn(RawUdp6Peer, &mut [u8; quic_lite::DEFAULT_MAX_DATAGRAM_SIZE]) -> Option<usize>;

static HANDLER: AtomicUsize = AtomicUsize::new(0);
static POLL_HANDLER: AtomicUsize = AtomicUsize::new(0);
static TX_BURST_PACKETS: AtomicUsize = AtomicUsize::new(8);
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
static UDP_HANDLER_NO_RESPONSE: AtomicU32 = AtomicU32::new(0);
static NDP_ADVERTISEMENTS: AtomicU32 = AtomicU32::new(0);
static NDP_INVALID: AtomicU32 = AtomicU32::new(0);
static TX_FRAMES: AtomicU32 = AtomicU32::new(0);
static TX_FAILURES: AtomicU32 = AtomicU32::new(0);
static LAST_TX_RESULT: AtomicU32 = AtomicU32::new(0);
static RAW_TX_COMPLETIONS: AtomicU32 = AtomicU32::new(0);
static RAW_TX_COMPLETION_FAILURES: AtomicU32 = AtomicU32::new(0);
static RAW_TX_COMPLETION_RATE: AtomicU32 = AtomicU32::new(0);
// A one-packet raw burst must not wait indefinitely for a peer packet before
// it can make its next sender-owned packet eligible.  The continuation uses
// the existing shared ingress worker (and its already-accounted stack), not
// a per-bearer task or queue.  It is armed only for the explicit burst-one
// pacing mode, where yielding the CPU also gives the STA an RX/ACK window.
static PACED_POLL_PENDING: AtomicBool = AtomicBool::new(false);
static PACED_LINK: AtomicUsize = AtomicUsize::new(0);
static PACED_PEER_MAC_LOW: AtomicU32 = AtomicU32::new(0);
static PACED_PEER_MAC_HIGH: AtomicU32 = AtomicU32::new(0);
static PACED_PEER_IP: [AtomicU32; 4] = [
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
];
static PACED_PEER_PORT: AtomicU32 = AtomicU32::new(0);
/// 0=not attempted, 1=started, 2=shared worker unavailable, 3=RX callback
/// registration failed. This is deliberately a small status value rather
/// than a boot-only log: a host can inspect it after association has settled.
static START_STATUS: AtomicU32 = AtomicU32::new(0);
// Startup breadcrumbs are atomics so the Wi-Fi RX callback never formats or
// allocates. The consumer emits at most one report after it owns the frame.
static FIRST_RX_LEN: AtomicU32 = AtomicU32::new(0);
static FIRST_RX_REPORTED: AtomicBool = AtomicBool::new(false);
static RX_CALLBACK_LOGGED: AtomicU32 = AtomicU32::new(0);
// Only the single shared-ingress consumer calls `dispatch_ingress`, therefore
// these scratch frames are never accessed concurrently. They are temporary
// until the common packet-pool conversion lands; no callback retains them.
static mut TX_FRAME: [u8; FRAME_CAPACITY] = [0; FRAME_CAPACITY];
static mut IEEE80211_TX_FRAME: [u8; FRAME_CAPACITY] = [0; FRAME_CAPACITY];
static mut RESPONSE_BUFFER: [u8; quic_lite::DEFAULT_MAX_DATAGRAM_SIZE] =
    [0; quic_lite::DEFAULT_MAX_DATAGRAM_SIZE];
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
    UDP_HANDLER_NO_RESPONSE.store(0, Ordering::Relaxed);
    NDP_ADVERTISEMENTS.store(0, Ordering::Relaxed);
    NDP_INVALID.store(0, Ordering::Relaxed);
    TX_FRAMES.store(0, Ordering::Relaxed);
    TX_FAILURES.store(0, Ordering::Relaxed);
    LAST_TX_RESULT.store(0, Ordering::Relaxed);
    RAW_TX_COMPLETIONS.store(0, Ordering::Relaxed);
    RAW_TX_COMPLETION_FAILURES.store(0, Ordering::Relaxed);
    RAW_TX_COMPLETION_RATE.store(0, Ordering::Relaxed);
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
pub fn start(local_mac: [u8; 6], ap_bssid: [u8; 6], handler: RawUdp6Handler) -> bool {
    HANDLER.store(handler as usize, Ordering::Release);
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

/// Remove raw Ethernet ingress before STA teardown or a personality change.
/// The shared packet pool remains available to another bearer; only this
/// driver's callback and dispatch handler are disabled.
pub fn stop() {
    if !STARTED.swap(false, Ordering::AcqRel) {
        return;
    }
    let _ = crate::wifi_esp::register_ethernet_rx_callback(
        crate::wifi_esp::RadioInterface::Sta,
        None,
    );
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
    let Some(ap_mac) = crate::wifi_esp::interface_mac(crate::wifi_esp::RadioInterface::Ap)
    else {
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

/// Applies to the next association; the raw adapter keeps no packet queue.
pub fn set_tx_burst_packets(packets: usize) {
    TX_BURST_PACKETS.store(
        packets.clamp(1, crate::RAW_SERVICE_HISTORY_CAPACITY),
        Ordering::Release,
    );
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
    // Keep the callback bounded: reporting happens in the consumer task.
    let _ = FIRST_RX_LEN.compare_exchange(0, len as u32, Ordering::Relaxed, Ordering::Relaxed);
    let received = RX_FRAMES.fetch_add(1, Ordering::Relaxed) + 1;
    if received <= 4 {
        RX_CALLBACK_LOGGED.store(len as u32, Ordering::Relaxed);
    }
    esp_idf_sys::ESP_OK
}

fn dispatch_ingress(item: crate::shared_ingress_esp::IngressPacket, frame: &[u8]) {
    // One bounded startup breadcrumb for hardware bring-up. This adapter
    // otherwise has no logging in the RX path, so a C6-specific frame-shape
    // mismatch is indistinguishable from AP delivery failure.
    let first_len = FIRST_RX_LEN.load(Ordering::Relaxed);
    if first_len != 0 && !FIRST_RX_REPORTED.swap(true, Ordering::Relaxed) {
        crate::commands::send_stat(b"raw udp6 rx first len=", first_len as u64);
    }
    let callback_len = RX_CALLBACK_LOGGED.swap(0, Ordering::Relaxed);
    if callback_len != 0 {
        crate::commands::send_stat(b"raw udp6 rx callback len=", callback_len as u64);
    }
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
                    // The normal STA Ethernet handoff accepts this tiny
                    // control frame but, on the C6/AP combination under
                    // test, can leave it undrained after an association
                    // transition.  Send only NDP replies through the proven
                    // associated-STA raw injector; bulk UDP still uses the
                    // driver's AMPDU-capable Ethernet path below.
                    if transmit_station_ipv6(
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
            Err(error) => {
                NDP_INVALID.fetch_add(1, Ordering::Relaxed);
                crate::commands::send_stat(
                    b"raw udp6 ndp parse error=",
                    quic_lite::raw_udp6::error_code(error) as u64,
                );
                // An ICMPv6 frame can be a Neighbor Solicitation, a
                // reachability probe, or unrelated control traffic.  Keep
                // enough wire shape to distinguish an ESP RX truncation from
                // an NDP parser rule without copying/logging the frame.
                crate::commands::send_stat(b"raw udp6 ndp rx len=", frame.len() as u64);
                if frame.len() >= quic_lite::raw_udp6::ETHERNET_HEADER_LEN + quic_lite::raw_udp6::IPV6_HEADER_LEN {
                    let ip = &frame[quic_lite::raw_udp6::ETHERNET_HEADER_LEN..];
                    crate::commands::send_stat(
                        b"raw udp6 ndp ip payload_len=",
                        u16::from_be_bytes([ip[4], ip[5]]) as u64,
                    );
                    crate::commands::send_stat(
                        b"raw udp6 ndp ip next_hop_type=",
                        ((ip[6] as u64) << 16)
                            | ((ip[7] as u64) << 8)
                            | ip.get(quic_lite::raw_udp6::IPV6_HEADER_LEN)
                                .copied()
                                .unwrap_or(0) as u64,
                    );
                }
            }
        }
        return;
    }
    let packet = match parse_udp6(frame, local_ip, RAW_UDP6_PORT) {
        Ok(packet) => packet,
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
        mac: packet.source_mac,
        ip: packet.source_ip,
        port: packet.source_port,
    };
    let immediate = handler(peer, packet.payload, response);
    if immediate.is_none() && UDP_HANDLER_NO_RESPONSE.fetch_add(1, Ordering::Relaxed) == 0 {
        // This is expected for an ACK-only transport packet; retain one
        // breadcrumb for non-service handlers without treating it as a drop.
        crate::commands::send_response(b"raw udp6 handler no immediate response");
    }
    let poll = POLL_HANDLER.load(Ordering::Acquire);
    let poll: Option<RawUdp6PollHandler> =
        (poll != 0).then(|| unsafe { core::mem::transmute(poll) });
    let result = dmesh_server::raw_transport::pump_egress(
        response,
        TX_BURST_PACKETS.load(Ordering::Acquire),
        immediate,
        |response| poll.and_then(|poll| poll(peer, response)),
        |payload| transmit_udp6(item.link(), peer, RAW_UDP6_PORT, payload),
    );
    if result.sent != 0 {
        UDP_DELIVERED.fetch_add(1, Ordering::Relaxed);
        TX_FRAMES.fetch_add(result.sent as u32, Ordering::Relaxed);
    }
    if result.invalid_length || result.submit_failed {
        TX_FAILURES.fetch_add(1, Ordering::Relaxed);
    }
    if result.sent != 0 {
        schedule_paced_poll(item.link(), peer);
    }
}

/// Continue an explicit one-packet burst after yielding the shared worker for
/// one RTOS tick.  This is deliberately a worker action, not a timer task:
/// it retains no driver buffer and disappears with normal ingress idleness.
fn paced_poll_work() {
    PACED_POLL_PENDING.store(false, Ordering::Release);
    if !STARTED.load(Ordering::Acquire) {
        return;
    }
    unsafe { esp_idf_sys::vTaskDelay(1) };
    if !STARTED.load(Ordering::Acquire) {
        return;
    }
    let link = match PACED_LINK.load(Ordering::Acquire) {
        1 => crate::shared_ingress_esp::IngressLink::WifiSta,
        2 => crate::shared_ingress_esp::IngressLink::WifiAp,
        _ => return,
    };
    let peer = load_paced_peer();
    let poll = POLL_HANDLER.load(Ordering::Acquire);
    if poll == 0 {
        return;
    }
    let poll: RawUdp6PollHandler = unsafe { core::mem::transmute(poll) };
    let response = unsafe { &mut *core::ptr::addr_of_mut!(RESPONSE_BUFFER) };
    let result = dmesh_server::raw_transport::pump_egress(
        response,
        1,
        None,
        |response| poll(peer, response),
        |payload| transmit_udp6(link, peer, RAW_UDP6_PORT, payload),
    );
    if result.sent != 0 {
        TX_FRAMES.fetch_add(result.sent as u32, Ordering::Relaxed);
        schedule_paced_poll(link, peer);
    }
    if result.invalid_length || result.submit_failed {
        TX_FAILURES.fetch_add(1, Ordering::Relaxed);
    }
}

fn schedule_paced_poll(link: crate::shared_ingress_esp::IngressLink, peer: RawUdp6Peer) {
    if !STARTED.load(Ordering::Acquire)
        || TX_BURST_PACKETS.load(Ordering::Acquire) != 1
        || PACED_POLL_PENDING
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
    {
        return;
    }
    store_paced_peer(link, peer);
    if !crate::shared_ingress_esp::schedule_work(paced_poll_work) {
        PACED_POLL_PENDING.store(false, Ordering::Release);
    }
}

fn store_paced_peer(link: crate::shared_ingress_esp::IngressLink, peer: RawUdp6Peer) {
    PACED_LINK.store(link as usize, Ordering::Release);
    PACED_PEER_MAC_LOW.store(
        u32::from_le_bytes([peer.mac[0], peer.mac[1], peer.mac[2], peer.mac[3]]),
        Ordering::Release,
    );
    PACED_PEER_MAC_HIGH.store(u32::from_le_bytes([peer.mac[4], peer.mac[5], 0, 0]), Ordering::Release);
    for (slot, bytes) in PACED_PEER_IP.iter().zip(peer.ip.chunks_exact(4)) {
        slot.store(u32::from_be_bytes(bytes.try_into().unwrap()), Ordering::Release);
    }
    PACED_PEER_PORT.store(u32::from(peer.port), Ordering::Release);
}

fn load_paced_peer() -> RawUdp6Peer {
    let low = PACED_PEER_MAC_LOW.load(Ordering::Acquire).to_le_bytes();
    let high = PACED_PEER_MAC_HIGH.load(Ordering::Acquire).to_le_bytes();
    let mut ip = [0; 16];
    for (index, slot) in PACED_PEER_IP.iter().enumerate() {
        ip[index * 4..index * 4 + 4].copy_from_slice(&slot.load(Ordering::Acquire).to_be_bytes());
    }
    RawUdp6Peer {
        mac: [low[0], low[1], low[2], low[3], high[0], high[1]],
        ip,
        port: PACED_PEER_PORT.load(Ordering::Acquire) as u16,
    }
}

fn transmit_udp6(
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

fn transmit_ipv6(
    link: crate::shared_ingress_esp::IngressLink,
    destination_mac: [u8; 6],
    local_mac: [u8; 6],
    ethernet: &[u8],
) -> bool {
    match link {
        crate::shared_ingress_esp::IngressLink::WifiAp => {
            transmit_ethernet(crate::wifi_esp::RadioInterface::Ap, ethernet)
        },
        crate::shared_ingress_esp::IngressLink::WifiSta if sta_driver_tx_enabled() => {
            transmit_ethernet(crate::wifi_esp::RadioInterface::Sta, ethernet)
        },
        crate::shared_ingress_esp::IngressLink::WifiSta
        | crate::shared_ingress_esp::IngressLink::None => {
            transmit_station_ipv6(destination_mac, local_mac, ethernet)
        }
    }
}

/// This is exactly the ESP-IDF `esp_netif`/lwIP Wi-Fi handoff, including its
/// driver-owned copy and ordinary associated-STA rate/queue policy.
fn transmit_ethernet(interface: crate::wifi_esp::RadioInterface, ethernet: &[u8]) -> bool {
    let result = crate::wifi_esp::transmit_ethernet(interface, ethernet);
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
