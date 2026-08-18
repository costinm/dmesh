//! ESP Wi-Fi glue for the common raw Ethernet / IPv6 / UDP bearer.
//!
//! Packet parsing, checksum logic, and address derivation live in
//! `quic_lite::raw_udp6` so they are host-tested. This module owns only the
//! ESP callback, fixed queue, task, and internal Ethernet TX call.

#[cfg(feature = "wifi-raw-udp6-client")]
use core::mem::MaybeUninit;
use core::{
    ffi::c_void,
    sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering},
};

use quic_lite::raw_udp6::{
    encode_neighbor_advertisement, encode_station_ipv6_data_frame, encode_udp6,
    link_local_from_mac, parse_neighbor_solicitation, parse_udp6,
};

pub const RAW_UDP6_PORT: u16 = 3339;
/// Dedicated local port for the one bounded raw-UDP6 diagnostic client.
/// Keeping this distinct from `RAW_UDP6_PORT` lets a server and client exist
/// on the same adapter without confusing the IPERF response direction.
pub const RAW_UDP6_CLIENT_PORT: u16 = 3340;
const FRAME_CAPACITY: usize = quic_lite::DEFAULT_MAX_DATAGRAM_SIZE + 96;

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
static LOCAL_MAC_LOW: AtomicU32 = AtomicU32::new(0);
static LOCAL_MAC_HIGH: AtomicU32 = AtomicU32::new(0);
static AP_BSSID_LOW: AtomicU32 = AtomicU32::new(0);
static AP_BSSID_HIGH: AtomicU32 = AtomicU32::new(0);
static RX_FRAMES: AtomicU32 = AtomicU32::new(0);
static RX_QUEUE_DROPS: AtomicU32 = AtomicU32::new(0);
static RX_INVALID: AtomicU32 = AtomicU32::new(0);
static UDP_DELIVERED: AtomicU32 = AtomicU32::new(0);
static NDP_ADVERTISEMENTS: AtomicU32 = AtomicU32::new(0);
static NDP_INVALID: AtomicU32 = AtomicU32::new(0);
static TX_FRAMES: AtomicU32 = AtomicU32::new(0);
static TX_FAILURES: AtomicU32 = AtomicU32::new(0);
static LAST_TX_RESULT: AtomicU32 = AtomicU32::new(0);
/// 0=not attempted, 1=started, 2=shared worker unavailable, 3=RX callback
/// registration failed. This is deliberately a small status value rather
/// than a boot-only log: a host can inspect it after association has settled.
static START_STATUS: AtomicU32 = AtomicU32::new(0);
#[cfg(feature = "wifi-raw-udp6-client")]
static IPERF_CLIENT_START_STATUS: AtomicU32 = AtomicU32::new(0);
#[cfg(feature = "wifi-raw-udp6-client")]
static IPERF_CLIENT_BYTES: AtomicU32 = AtomicU32::new(0);
#[cfg(feature = "wifi-raw-udp6-client")]
static IPERF_CLIENT_ERRORS: AtomicU32 = AtomicU32::new(0);
#[cfg(feature = "wifi-raw-udp6-client")]
static IPERF_CLIENT_ELAPSED_US: AtomicU32 = AtomicU32::new(0);
#[cfg(feature = "wifi-raw-udp6-client")]
static IPERF_CLIENT_RX_FRAMES: AtomicU32 = AtomicU32::new(0);
#[cfg(feature = "wifi-raw-udp6-client")]
static IPERF_CLIENT_MATCHED: AtomicU32 = AtomicU32::new(0);
#[cfg(feature = "wifi-raw-udp6-client")]
static IPERF_CLIENT_CALLBACK_ERRORS: AtomicU32 = AtomicU32::new(0);
static FIRST_RX_LEN: AtomicU32 = AtomicU32::new(0);
static FIRST_RX_REPORTED: AtomicBool = AtomicBool::new(false);
static mut RESPONSE_BUFFER: [u8; quic_lite::DEFAULT_MAX_DATAGRAM_SIZE] =
    [0; quic_lite::DEFAULT_MAX_DATAGRAM_SIZE];
static mut TX_FRAME: [u8; FRAME_CAPACITY] = [0; FRAME_CAPACITY];
static mut IEEE80211_TX_FRAME: [u8; FRAME_CAPACITY] = [0; FRAME_CAPACITY];
#[cfg(feature = "wifi-raw-udp6-client")]
struct IperfClientState {
    peer: RawUdp6Peer,
    client: dmesh_server::raw_iperf::RawIperfClient<4, { quic_lite::DEFAULT_MAX_DATAGRAM_SIZE }>,
    started_at_us: i64,
}
#[cfg(feature = "wifi-raw-udp6-client")]
// The lab client can be several KiB.  It is one explicitly enabled diagnostic
// connection, not an unbounded heap allocation that can make the Wi-Fi
// bearer fail after it has advertised capacity.  Production server builds do
// not include this feature; the future general connection budget owns this
// storage through the device-wide packet/connection allocator.
static IPERF_CLIENT_ACTIVE: AtomicBool = AtomicBool::new(false);
#[cfg(feature = "wifi-raw-udp6-client")]
static mut IPERF_CLIENT: MaybeUninit<IperfClientState> = MaybeUninit::uninit();

/// Snapshot counters for status/log adapters.  The counters are deliberately
/// separate from the lwIP bearer and remain meaningful when both features are
/// built for comparison.
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

/// Register the raw STA RX callback with the device-wide packet worker.
/// Call only after the STA has associated. Repeated calls update the handler
/// but never create a competing callback or task.
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
    let register_result = unsafe {
        esp_idf_sys::esp_wifi_internal_reg_rxcb(
            esp_idf_sys::wifi_interface_t_WIFI_IF_STA,
            Some(rx_callback),
        )
    };
    let registered = register_result == esp_idf_sys::ESP_OK;
    if !registered {
        crate::commands::send_stat(b"raw udp6 rxcb result=", register_result as u32 as u64);
        STARTED.store(false, Ordering::Release);
        START_STATUS.store(3, Ordering::Release);
        return false;
    }
    START_STATUS.store(1, Ordering::Release);
    true
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
        packets.clamp(1, crate::RAW_IPERF_HISTORY_CAPACITY),
        Ordering::Release,
    );
}

/// Start one device-to-device raw UDP6 IPERF client. QUIC-lite/IPERF state is
/// host-tested; this adapter only supplies Ethernet/802.11 framing and time.
#[cfg(feature = "wifi-raw-udp6-client")]
pub fn start_iperf_client(peer: RawUdp6Peer, bytes: u64) -> bool {
    IPERF_CLIENT_START_STATUS.store(0, Ordering::Release);
    IPERF_CLIENT_BYTES.store(0, Ordering::Release);
    IPERF_CLIENT_ERRORS.store(0, Ordering::Release);
    IPERF_CLIENT_ELAPSED_US.store(0, Ordering::Release);
    IPERF_CLIENT_RX_FRAMES.store(0, Ordering::Release);
    IPERF_CLIENT_MATCHED.store(0, Ordering::Release);
    IPERF_CLIENT_CALLBACK_ERRORS.store(0, Ordering::Release);
    if IPERF_CLIENT_ACTIVE.swap(true, Ordering::AcqRel) {
        IPERF_CLIENT_START_STATUS.store(1, Ordering::Release);
        return false;
    }
    let Ok(mut client) = dmesh_server::raw_iperf::RawIperfClient::new(
        quic_lite::ConnectionId::new(0x5544_5036).expect("nonzero raw UDP6 client CID"),
        bytes,
    ) else {
        IPERF_CLIENT_START_STATUS.store(2, Ordering::Release);
        IPERF_CLIENT_ACTIVE.store(false, Ordering::Release);
        return false;
    };
    let used = unsafe {
        let response = &mut *core::ptr::addr_of_mut!(RESPONSE_BUFFER);
        let Ok(used) = client.start(response) else {
            IPERF_CLIENT_START_STATUS.store(3, Ordering::Release);
            IPERF_CLIENT_ACTIVE.store(false, Ordering::Release);
            return false;
        };
        used
    };
    unsafe {
        core::ptr::addr_of_mut!(IPERF_CLIENT).write(MaybeUninit::new(IperfClientState {
            peer,
            client,
            started_at_us: unsafe { esp_idf_sys::esp_timer_get_time() },
        }));
    }
    unsafe {
        let response = &*core::ptr::addr_of!(RESPONSE_BUFFER);
        // Association can be reported before the Wi-Fi driver's first raw TX
        // buffer is available. This bounded start-only retry is outside RX
        // callbacks and steady-state transport never waits here.
        let mut sent = false;
        for _ in 0..8 {
            if transmit_udp6(peer, RAW_UDP6_CLIENT_PORT, &response[..used]) {
                sent = true;
                break;
            }
            esp_idf_sys::vTaskDelay(2);
        }
        if sent {
            true
        } else {
            IPERF_CLIENT_START_STATUS.store(4, Ordering::Release);
            IPERF_CLIENT_ACTIVE.store(false, Ordering::Release);
            false
        }
    }
}

/// 0=started; 1=active client; 2=client setup; 3=bootstrap; 4=first TX.
#[cfg(feature = "wifi-raw-udp6-client")]
pub fn iperf_client_start_status() -> u32 {
    IPERF_CLIENT_START_STATUS.load(Ordering::Acquire)
}

#[cfg(feature = "wifi-raw-udp6-client")]
pub fn iperf_client_result() -> (u32, u32, u32) {
    (
        IPERF_CLIENT_BYTES.load(Ordering::Acquire),
        IPERF_CLIENT_ERRORS.load(Ordering::Acquire),
        IPERF_CLIENT_ELAPSED_US.load(Ordering::Acquire),
    )
}

#[cfg(feature = "wifi-raw-udp6-client")]
pub fn iperf_client_progress() -> (u32, u32, u32) {
    (
        IPERF_CLIENT_RX_FRAMES.load(Ordering::Acquire),
        IPERF_CLIENT_MATCHED.load(Ordering::Acquire),
        IPERF_CLIENT_CALLBACK_ERRORS.load(Ordering::Acquire),
    )
}

pub fn last_tx_result() -> u32 {
    LAST_TX_RESULT.load(Ordering::Relaxed)
}

unsafe extern "C" fn rx_callback(buffer: *mut c_void, len: u16, eb: *mut c_void) -> i32 {
    if buffer.is_null() || len as usize > FRAME_CAPACITY {
        if !eb.is_null() {
            unsafe { esp_idf_sys::esp_wifi_internal_free_rx_buffer(eb) };
        }
        RX_QUEUE_DROPS.fetch_add(1, Ordering::Relaxed);
        return esp_idf_sys::ESP_FAIL;
    }
    unsafe {
        let frame = core::slice::from_raw_parts(buffer.cast::<u8>(), len as usize);
        let queued = crate::shared_ingress_esp::enqueue(
            crate::shared_ingress_esp::IngressKind::RawUdp6,
            [0; 6],
            frame,
        );
        // `buffer` is owned by the Wi-Fi driver. This adapter has copied it
        // into its static queue, so it must return the opaque RX allocation
        // immediately; retaining it would exhaust the driver's RX pool.
        if !eb.is_null() {
            esp_idf_sys::esp_wifi_internal_free_rx_buffer(eb);
        }
        if !queued {
            RX_QUEUE_DROPS.fetch_add(1, Ordering::Relaxed);
            return esp_idf_sys::ESP_FAIL;
        }
    }
    // Keep the callback bounded: reporting happens in the consumer task.
    let _ = FIRST_RX_LEN.compare_exchange(0, len as u32, Ordering::Relaxed, Ordering::Relaxed);
    RX_FRAMES.fetch_add(1, Ordering::Relaxed);
    esp_idf_sys::ESP_OK
}

fn dispatch_ingress(_item: crate::shared_ingress_esp::IngressPacket, frame: &[u8]) {
    // One bounded startup breadcrumb for hardware bring-up. This adapter
    // otherwise has no logging in the RX path, so a C6-specific frame-shape
    // mismatch is indistinguishable from AP delivery failure.
    let first_len = FIRST_RX_LEN.load(Ordering::Relaxed);
    if first_len != 0 && !FIRST_RX_REPORTED.swap(true, Ordering::Relaxed) {
        crate::commands::send_stat(b"raw udp6 rx first len=", first_len as u64);
    }
    let local_mac = load_local_mac();
    let local_ip = link_local_from_mac(local_mac);
    #[cfg(feature = "wifi-raw-udp6-client")]
    unsafe {
        if IPERF_CLIENT_ACTIVE.load(Ordering::Acquire) {
            IPERF_CLIENT_RX_FRAMES.fetch_add(1, Ordering::Relaxed);
            if let Ok(packet) = parse_udp6(frame, local_ip, RAW_UDP6_CLIENT_PORT) {
                let state = &mut *core::ptr::addr_of_mut!(IPERF_CLIENT).cast::<IperfClientState>();
                if state.peer.mac == packet.source_mac && state.peer.ip == packet.source_ip {
                    IPERF_CLIENT_MATCHED.fetch_add(1, Ordering::Relaxed);
                    let response = &mut *core::ptr::addr_of_mut!(RESPONSE_BUFFER);
                    match state.client.receive(packet.payload, response) {
                        Ok(Some(used)) if used <= response.len() => {
                            if !transmit_udp6(state.peer, RAW_UDP6_CLIENT_PORT, &response[..used]) {
                                TX_FAILURES.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                        Ok(_) => {}
                        Err(_) => {
                            IPERF_CLIENT_CALLBACK_ERRORS.fetch_add(1, Ordering::Relaxed);
                            TX_FAILURES.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    if state.client.is_complete() {
                        let bytes = state.client.bytes();
                        let errors: u64 = state.client.callback_errors().iter().sum();
                        let elapsed_us =
                            (esp_idf_sys::esp_timer_get_time() - state.started_at_us).max(1) as u64;
                        IPERF_CLIENT_BYTES
                            .store(bytes.min(u64::from(u32::MAX)) as u32, Ordering::Release);
                        IPERF_CLIENT_ERRORS
                            .store(errors.min(u64::from(u32::MAX)) as u32, Ordering::Release);
                        IPERF_CLIENT_ELAPSED_US.store(
                            elapsed_us.min(u64::from(u32::MAX)) as u32,
                            Ordering::Release,
                        );
                        crate::commands::send_stat(
                            b"raw udp6 client bps=",
                            bytes.saturating_mul(8_000_000) / elapsed_us,
                        );
                        crate::commands::send_stat(b"raw udp6 client elapsed_us=", elapsed_us);
                        crate::commands::send_stat(b"raw udp6 client bytes=", bytes);
                        crate::commands::send_stat(b"raw udp6 client errors=", errors);
                        IPERF_CLIENT_ACTIVE.store(false, Ordering::Release);
                    }
                    return;
                }
            }
        }
    }
    // Linux resolves a link-local IPv6 destination with NDP; it does not
    // infer the Ethernet MAC from a modified-EUI-64 IID. Answer the bounded
    // NS/NA exchange before the UDP-only parser sees ICMPv6.
    if quic_lite::raw_udp6::is_icmpv6_frame(frame) {
        match parse_neighbor_solicitation(frame, local_ip) {
            Ok(solicitation) => {
                let advertisement = unsafe { &mut *core::ptr::addr_of_mut!(TX_FRAME) };
                if let Ok(frame_len) = encode_neighbor_advertisement(
                    advertisement,
                    solicitation.source_mac,
                    local_mac,
                    solicitation.source_ip,
                    local_ip,
                ) {
                    if transmit_station_ipv6(
                        solicitation.source_mac,
                        local_mac,
                        &advertisement[..frame_len],
                    ) {
                        NDP_ADVERTISEMENTS.fetch_add(1, Ordering::Relaxed);
                        TX_FRAMES.fetch_add(1, Ordering::Relaxed);
                    } else {
                        TX_FAILURES.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
            Err(error) => {
                NDP_INVALID.fetch_add(1, Ordering::Relaxed);
                let _ = error;
            }
        }
        return;
    }
    let packet = match parse_udp6(frame, local_ip, RAW_UDP6_PORT) {
        Ok(packet) => packet,
        Err(error) => {
            if RX_INVALID.fetch_add(1, Ordering::Relaxed) == 0 {
                crate::commands::send_response(b"raw udp6 parse rejected");
            }
            let _ = error;
            return;
        }
    };
    let handler = HANDLER.load(Ordering::Acquire);
    if handler == 0 {
        return;
    }
    let handler: RawUdp6Handler = unsafe { core::mem::transmute(handler) };
    let response = unsafe { &mut *core::ptr::addr_of_mut!(RESPONSE_BUFFER) };
    let Some(used) = handler(
        RawUdp6Peer {
            mac: packet.source_mac,
            ip: packet.source_ip,
            port: packet.source_port,
        },
        packet.payload,
        response,
    ) else {
        return;
    };
    if used > response.len() {
        TX_FAILURES.fetch_add(1, Ordering::Relaxed);
        return;
    }
    UDP_DELIVERED.fetch_add(1, Ordering::Relaxed);
    if transmit_udp6(
        RawUdp6Peer {
            mac: packet.source_mac,
            ip: packet.source_ip,
            port: packet.source_port,
        },
        RAW_UDP6_PORT,
        &response[..used],
    ) {
        TX_FRAMES.fetch_add(1, Ordering::Relaxed);
    } else {
        TX_FAILURES.fetch_add(1, Ordering::Relaxed);
        return;
    }
    let poll = POLL_HANDLER.load(Ordering::Acquire);
    if poll == 0 {
        return;
    }
    let poll: RawUdp6PollHandler = unsafe { core::mem::transmute(poll) };
    for _ in 1..TX_BURST_PACKETS.load(Ordering::Acquire) {
        let Some(used) = poll(
            RawUdp6Peer {
                mac: packet.source_mac,
                ip: packet.source_ip,
                port: packet.source_port,
            },
            response,
        ) else {
            break;
        };
        if used > response.len()
            || !transmit_udp6(
                RawUdp6Peer {
                    mac: packet.source_mac,
                    ip: packet.source_ip,
                    port: packet.source_port,
                },
                RAW_UDP6_PORT,
                &response[..used],
            )
        {
            TX_FAILURES.fetch_add(1, Ordering::Relaxed);
            break;
        }
        TX_FRAMES.fetch_add(1, Ordering::Relaxed);
    }
}

fn transmit_udp6(peer: RawUdp6Peer, source_port: u16, payload: &[u8]) -> bool {
    let local_mac = load_local_mac();
    let local_ip = link_local_from_mac(local_mac);
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
    transmit_station_ipv6(peer.mac, local_mac, &ethernet[..frame_len])
}

/// Send an Ethernet-II IPv6 packet through the station's raw non-QoS data
/// path. This has one caller (the raw UDP6 task), so its fixed backing buffer
/// is never concurrently reused.
fn transmit_station_ipv6(_destination_mac: [u8; 6], station_mac: [u8; 6], ethernet: &[u8]) -> bool {
    let wifi_frame = unsafe { &mut *core::ptr::addr_of_mut!(IEEE80211_TX_FRAME) };
    let Ok(wifi_len) =
        encode_station_ipv6_data_frame(wifi_frame, load_ap_bssid(), station_mac, ethernet)
    else {
        return false;
    };
    unsafe {
        let result = esp_idf_sys::esp_wifi_80211_tx(
            esp_idf_sys::wifi_interface_t_WIFI_IF_STA,
            wifi_frame.as_ptr().cast(),
            wifi_len as i32,
            true,
        );
        LAST_TX_RESULT.store(result as u32, Ordering::Relaxed);
        result == esp_idf_sys::ESP_OK
    }
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

fn load_ap_bssid() -> [u8; 6] {
    let low = AP_BSSID_LOW.load(Ordering::Acquire).to_le_bytes();
    let high = AP_BSSID_HIGH.load(Ordering::Acquire).to_le_bytes();
    [low[0], low[1], low[2], low[3], high[0], high[1]]
}
