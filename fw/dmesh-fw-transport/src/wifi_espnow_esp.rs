//! ESP adapter for the shared ESP-NOW-compatible action-frame bearer.
//!
//! `dmesh_rawnan::espnow` owns portable framing and tests. This module owns
//! raw 802.11 injection and capture.
//!
//! ESP-NOW is connectionless and its action-frame address 3 is broadcast;
//! see <https://docs.espressif.com/projects/esp-idf/en/stable/esp32/api-reference/network/esp_now.html>.
//! Do not use an associated AP BSSID here. The raw RX path presently uses
//! promiscuous capture; Main's hardware BSSID filter is evaluated separately
//! so the common framing remains shared with Linux.

#[cfg(feature = "wifi-espnow-client")]
use core::mem::MaybeUninit;
use core::{
    ffi::c_void,
    sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EspNowPeer {
    pub mac: [u8; 6],
}

pub type EspNowHandler =
    fn(EspNowPeer, &[u8], &mut [u8; quic_lite::DEFAULT_MAX_DATAGRAM_SIZE]) -> Option<usize>;

const FRAME_CAPACITY: usize = quic_lite::DEFAULT_MAX_DATAGRAM_SIZE + 96;

static HANDLER: AtomicUsize = AtomicUsize::new(0);
static STARTED: AtomicBool = AtomicBool::new(false);
static RX_ACTIONS: AtomicU32 = AtomicU32::new(0);
static RX_DROPS: AtomicU32 = AtomicU32::new(0);
static RX_MANAGEMENT: AtomicU32 = AtomicU32::new(0);
static RX_BEACONS: AtomicU32 = AtomicU32::new(0);
static RX_NAN_BEACONS: AtomicU32 = AtomicU32::new(0);
static RX_ACTION_FRAMES: AtomicU32 = AtomicU32::new(0);
static TX_ACTIONS: AtomicU32 = AtomicU32::new(0);
static TX_FAILURES: AtomicU32 = AtomicU32::new(0);
static mut LOCAL_MAC: [u8; 6] = [0; 6];
static mut RESPONSE: [u8; quic_lite::DEFAULT_MAX_DATAGRAM_SIZE] =
    [0; quic_lite::DEFAULT_MAX_DATAGRAM_SIZE];
static mut TX_FRAME: [u8; FRAME_CAPACITY] = [0; FRAME_CAPACITY];
static mut RX_PAYLOAD: [u8; quic_lite::DEFAULT_MAX_DATAGRAM_SIZE] =
    [0; quic_lite::DEFAULT_MAX_DATAGRAM_SIZE];
#[cfg(feature = "wifi-espnow-client")]
struct IperfClientState {
    peer: EspNowPeer,
    client: dmesh_server::raw_iperf::RawIperfClient<4, { quic_lite::DEFAULT_MAX_DATAGRAM_SIZE }>,
    started_at_us: i64,
}
#[cfg(feature = "wifi-espnow-client")]
static IPERF_CLIENT_ACTIVE: AtomicBool = AtomicBool::new(false);
#[cfg(feature = "wifi-espnow-client")]
static IPERF_CLIENT_BYTES: AtomicU32 = AtomicU32::new(0);
#[cfg(feature = "wifi-espnow-client")]
static IPERF_CLIENT_ERRORS: AtomicU32 = AtomicU32::new(0);
#[cfg(feature = "wifi-espnow-client")]
static IPERF_CLIENT_ELAPSED_US: AtomicU32 = AtomicU32::new(0);
#[cfg(feature = "wifi-espnow-client")]
static mut IPERF_CLIENT: MaybeUninit<IperfClientState> = MaybeUninit::uninit();

pub fn stats() -> (u32, u32, u32, u32) {
    (
        RX_ACTIONS.load(Ordering::Relaxed),
        RX_DROPS.load(Ordering::Relaxed),
        TX_ACTIONS.load(Ordering::Relaxed),
        TX_FAILURES.load(Ordering::Relaxed),
    )
}

/// Capture evidence for the raw radio input. These counters deliberately do
/// not implement NAN synchronization or power decisions, which remain Main
/// policy, but make filter experiments observable in either firmware image.
pub fn management_stats() -> (u32, u32, u32, u32) {
    (
        RX_MANAGEMENT.load(Ordering::Relaxed),
        RX_BEACONS.load(Ordering::Relaxed),
        RX_NAN_BEACONS.load(Ordering::Relaxed),
        RX_ACTION_FRAMES.load(Ordering::Relaxed),
    )
}

#[cfg(feature = "wifi-espnow-client")]
pub fn iperf_client_result() -> (u32, u32, u32) {
    (
        IPERF_CLIENT_BYTES.load(Ordering::Acquire),
        IPERF_CLIENT_ERRORS.load(Ordering::Acquire),
        IPERF_CLIENT_ELAPSED_US.load(Ordering::Acquire),
    )
}

pub fn start(local_mac: [u8; 6], handler: EspNowHandler) -> bool {
    HANDLER.store(handler as usize, Ordering::Release);
    unsafe {
        LOCAL_MAC = local_mac;
    }
    if STARTED.swap(true, Ordering::AcqRel) {
        return true;
    }
    if !crate::shared_ingress_esp::start(
        crate::shared_ingress_esp::IngressKind::EspNow,
        dispatch_ingress,
    ) {
        STARTED.store(false, Ordering::Release);
        return false;
    }
    let registered = unsafe {
        let mut filter = esp_idf_sys::wifi_promiscuous_filter_t {
            filter_mask: esp_idf_sys::WIFI_PROMIS_FILTER_MASK_MGMT,
        };
        esp_idf_sys::esp_wifi_set_promiscuous(false) == esp_idf_sys::ESP_OK
            && esp_idf_sys::esp_wifi_set_promiscuous_rx_cb(Some(rx_callback)) == esp_idf_sys::ESP_OK
            && esp_idf_sys::esp_wifi_set_promiscuous_filter(&mut filter) == esp_idf_sys::ESP_OK
            && esp_idf_sys::esp_wifi_set_promiscuous(true) == esp_idf_sys::ESP_OK
    };
    if !registered {
        STARTED.store(false, Ordering::Release);
    }
    registered
}

/// Start one bounded ESP-NOW IPERF client. A second local request is rejected
/// instead of allocating another packet queue or response buffer.
#[cfg(feature = "wifi-espnow-client")]
pub fn start_iperf_client(peer: EspNowPeer, bytes: u64) -> bool {
    IPERF_CLIENT_BYTES.store(0, Ordering::Release);
    IPERF_CLIENT_ERRORS.store(0, Ordering::Release);
    IPERF_CLIENT_ELAPSED_US.store(0, Ordering::Release);
    if IPERF_CLIENT_ACTIVE.swap(true, Ordering::AcqRel) {
        return false;
    }
    let Ok(mut client) = dmesh_server::raw_iperf::RawIperfClient::new(
        quic_lite::ConnectionId::new(0x4553_5043).expect("nonzero ESP-NOW client CID"),
        bytes,
    ) else {
        IPERF_CLIENT_ACTIVE.store(false, Ordering::Release);
        return false;
    };
    let used = unsafe {
        let response = &mut *core::ptr::addr_of_mut!(RESPONSE);
        let Ok(used) = client.start(response) else {
            IPERF_CLIENT_ACTIVE.store(false, Ordering::Release);
            return false;
        };
        used
    };
    unsafe {
        core::ptr::addr_of_mut!(IPERF_CLIENT).write(MaybeUninit::new(IperfClientState {
            peer,
            client,
            // Timing is adapter-specific; the IPERF state machine itself stays
            // entirely host-testable in dmesh-server.
            started_at_us: unsafe { esp_idf_sys::esp_timer_get_time() },
        }));
    }
    unsafe {
        let response = &*core::ptr::addr_of!(RESPONSE);
        if transmit(peer, &response[..used]) {
            true
        } else {
            IPERF_CLIENT_ACTIVE.store(false, Ordering::Release);
            false
        }
    }
}

unsafe extern "C" fn rx_callback(
    buffer: *mut c_void,
    kind: esp_idf_sys::wifi_promiscuous_pkt_type_t,
) {
    if buffer.is_null() || kind != esp_idf_sys::wifi_promiscuous_pkt_type_t_WIFI_PKT_MGMT {
        return;
    }
    let packet = unsafe { &*(buffer as *const esp_idf_sys::wifi_promiscuous_pkt_t) };
    let len = packet.rx_ctrl.sig_len() as usize;
    if len > FRAME_CAPACITY {
        RX_DROPS.fetch_add(1, Ordering::Relaxed);
        return;
    }
    let frame = unsafe { core::slice::from_raw_parts(packet.payload.as_ptr(), len) };
    RX_MANAGEMENT.fetch_add(1, Ordering::Relaxed);
    if dmesh_rawnan::is_beacon(frame) {
        RX_BEACONS.fetch_add(1, Ordering::Relaxed);
        if dmesh_rawnan::is_nan_beacon(frame) {
            RX_NAN_BEACONS.fetch_add(1, Ordering::Relaxed);
        }
    }
    if dmesh_rawnan::is_action_frame(frame) {
        RX_ACTION_FRAMES.fetch_add(1, Ordering::Relaxed);
    }
    let output = unsafe { &mut *core::ptr::addr_of_mut!(RX_PAYLOAD) };
    let Some((source, used)) = dmesh_rawnan::espnow::parse_action_frame_into(frame, output) else {
        return;
    };
    if !crate::shared_ingress_esp::enqueue(
        crate::shared_ingress_esp::IngressKind::EspNow,
        source,
        &output[..used],
    ) {
        RX_DROPS.fetch_add(1, Ordering::Relaxed);
    } else {
        RX_ACTIONS.fetch_add(1, Ordering::Relaxed);
    }
}

fn dispatch_ingress(item: crate::shared_ingress_esp::IngressPacket, payload: &[u8]) {
    #[cfg(feature = "wifi-espnow-client")]
    unsafe {
        if IPERF_CLIENT_ACTIVE.load(Ordering::Acquire) {
            let state = &mut *core::ptr::addr_of_mut!(IPERF_CLIENT).cast::<IperfClientState>();
            if state.peer.mac == item.source() {
                let response = &mut *core::ptr::addr_of_mut!(RESPONSE);
                match state.client.receive(payload, response) {
                    Ok(Some(used)) if used <= response.len() => {
                        if !transmit(state.peer, &response[..used]) {
                            TX_FAILURES.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    Ok(_) => {}
                    Err(_) => {
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
                        b"espnow client bps=",
                        bytes.saturating_mul(8_000_000) / elapsed_us,
                    );
                    crate::commands::send_stat(b"espnow client elapsed_us=", elapsed_us);
                    crate::commands::send_stat(b"espnow client bytes=", bytes);
                    crate::commands::send_stat(b"espnow client errors=", errors);
                    IPERF_CLIENT_ACTIVE.store(false, Ordering::Release);
                }
                return;
            }
        }
    }
    let handler = HANDLER.load(Ordering::Acquire);
    if handler == 0 {
        return;
    }
    let handler: EspNowHandler = unsafe { core::mem::transmute(handler) };
    let response = unsafe { &mut *core::ptr::addr_of_mut!(RESPONSE) };
    let Some(used) = handler(EspNowPeer { mac: item.source() }, payload, response) else {
        return;
    };
    if used > response.len() {
        TX_FAILURES.fetch_add(1, Ordering::Relaxed);
        return;
    }
    if !transmit(EspNowPeer { mac: item.source() }, &response[..used]) {
        TX_FAILURES.fetch_add(1, Ordering::Relaxed);
    }
}

fn transmit(peer: EspNowPeer, payload: &[u8]) -> bool {
    let local = unsafe { LOCAL_MAC };
    let frame = unsafe { &mut *core::ptr::addr_of_mut!(TX_FRAME) };
    // ESP-NOW vendor action frames are connectionless: address 3 is the
    // broadcast BSSID, even when the station happens to be associated. See
    // https://docs.espressif.com/projects/esp-idf/en/stable/esp32/api-reference/network/esp_now.html
    let Ok(frame_len) =
        dmesh_rawnan::espnow::encode_action_frame(frame, peer.mac, local, [0xff; 6], payload)
    else {
        return false;
    };
    let sent = unsafe {
        esp_idf_sys::esp_wifi_80211_tx(
            esp_idf_sys::wifi_interface_t_WIFI_IF_STA,
            frame.as_ptr().cast(),
            frame_len as i32,
            true,
        )
    };
    if sent == esp_idf_sys::ESP_OK {
        TX_ACTIONS.fetch_add(1, Ordering::Relaxed);
        true
    } else {
        TX_FAILURES.fetch_add(1, Ordering::Relaxed);
        false
    }
}
