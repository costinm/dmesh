// IMPORTANT: This is shared no-std ESP firmware code. QUIC-lite and CBOR
// service mechanics remain in quic-lite/dmesh-server; this file owns ESP-IDF
// STA, UDP sockets, and FreeRTOS bearer scheduling for Recovery and Main.
//! Wi-Fi STA setup and UDP transport adapter.
//!
//! This module owns all bearer concerns: static STA configuration, sockets,
//! bootstrap, datagram receive/send, and quic-lite scheduling. The
//! flashing module sees only ordered application stream callbacks.

use crate::{
    commands as uart,
    flash::{FlashHandler, OBJECT_STREAM},
    uart_esp as l2, TransportProfile,
};
use core::{
    ffi::{c_int, c_void},
    sync::atomic::{AtomicBool, AtomicPtr, Ordering},
};
use dmesh_server::protocol::encode_get;
use quic_lite::iperf::IperfRun;
use quic_lite::{
    interpacket_gap_bucket, CommittedStreamDisposition, ConnectionId, DatagramTiming,
    RecoveryEndpoint, Role, INTERPACKET_GAP_BUCKETS,
};

const UDP_MTU: usize = quic_lite::DEFAULT_MAX_DATAGRAM_SIZE;
// The socket queue is part of the receiver budget, not merely an incidental
// lwIP tuning knob. A command may advertise the 64-packet diagnostic window;
// accepting that flight with only the former 40-datagram queue lets ordinary
// burst delivery drop packets before quic-lite can ACK or reorder them.
// The raw command endpoint remains registered while a transport transfer is
// active.  Two 64-packet lwIP queues plus the manifest and flash-slot pool
// exhaust C6 internal RAM, so retain one 32-packet radio burst here. Transport
// still supports a 64-packet peer-history budget; byte credit is the actual
// startup backpressure.
const UDP_RECEIVE_PACKETS: usize = 32;
const UDP_RECEIVE_BUFFER_BYTES: usize = UDP_RECEIVE_PACKETS * UDP_MTU;
// This is also the delayed-ACK timer tick. It must be shorter than the
// transport delayed-ACK deadline so a short final burst is acknowledged even
// when no more datagrams arrive.
const SOCKET_TIMEOUT_MS: u32 = 5;
// Bound one nonblocking lwIP drain so control/timer work cannot starve when
// the peer continuously refills the UDP receive queue.
const UDP_RECEIVE_DRAIN_LIMIT: usize = 32;
// Recovery's UDP worker runs above Idle on the single-core C6. A yield is a
// whole FreeRTOS tick on this board, so doing it after each burst turns the
// receive loop into an accidental sender pacer. Drain eight bounded bursts
// (at most 256 datagrams) before yielding: Idle and the flash worker still
// run regularly, while ACK/window progress remains genuinely batched.
const UDP_RECEIVE_YIELD_BURSTS: u64 = 8;
// A few immediate returns establish that this is a real spin rather than the
// normal tail after an ACK. The subsequent wall-clock budget, rather than a
// packet/poll count, determines when we must let Idle run for a whole tick.
const EMPTY_SOCKET_TICK_YIELD_SPINS: u64 = 8;
// FreeRTOS runs at 100 Hz here, so vTaskDelay(1) costs roughly 10 ms. Do not
// pay that cost once per handful of EWOULDBLOCK returns: it became most of a
// benchmark's wall time. A 100 ms bound still gives Idle and the flash worker
// a deterministic opportunity during a sustained empty spin.
const EMPTY_SOCKET_MAX_UNYIELDED_US: u64 = 100_000;
// LAN Recovery should not defer the tail of a burst for WAN-scale delays.
// Reordering still triggers an immediate ACK inside quic-lite.
// Recovery and the host object service use this LAN profile from bootstrap.
// ACK_FREQUENCY may refine it later, but a lost one-shot control frame must
// not silently fall back to ACK-every-two and collapse a 32-packet flight.
const DEFAULT_ACK_FREQUENCY: u8 = 8;
const RECOVERY_MAX_ACK_DELAY_MS: u64 = 5;
const BOOTSTRAP_RETRY_MS: u64 = 500;
/// Normal QUIC-lite PING interval used to refresh measurements on every live
/// bearer. This is not an empty PPP heartbeat.
const PATH_PROBE_INTERVAL_US: u64 = 1_000_000;
const RECOVERY_CONNECTION_CID_PREFIX: u64 = 1 << 32;
const SERVICE_OBJECT: u8 = quic_lite::SERVICE_OBJECT;
const REQUEST_STREAM: u64 = quic_lite::FIRST_CLIENT_BIDI_STREAM_ID;
const IPERF_STREAM: u64 = quic_lite::FIRST_SERVER_BIDI_STREAM_ID;
const IPERF_MAX_NORMAL_STREAMS: usize = 4;
/// Three normal IPERF streams plus high/low service streams fit in this
/// bounded Recovery endpoint.  This is transport stream-state capacity, not
/// a UART queue size; keep it independent of the selected bearer.
const RECOVERY_TRANSPORT_STREAMS: usize = IPERF_MAX_NORMAL_STREAMS + 2;
/// Second server-initiated stream used only by the priority-flow test. It is
/// a log-like low-priority service payload, not a UART/control record.
const INITIAL_MAX_STREAM_DATA: u64 = quic_lite::INITIAL_MAX_STREAM_DATA;
const TRANSPORT_UDP_PORT: u16 = 3339;
// Recovery-only PHY policy. It is deliberately not an NVS setting: normal
// images retain their default protocol set.  ESP-IDF does not support an
// 802.11n-only 2.4 GHz STA bitmap; the supported set is b/g/n.  Including n
// lets the association negotiate HT20 and use AMPDU for bulk UDP traffic.
const RECOVERY_STA_PROTOCOL: u8 = (esp_idf_sys::WIFI_PROTOCOL_11B
    | esp_idf_sys::WIFI_PROTOCOL_11G
    | esp_idf_sys::WIFI_PROTOCOL_11N) as u8;

unsafe extern "C" {
    fn __errno() -> *mut c_int;
    fn esp_wifi_config_11b_rate(interface: esp_idf_sys::wifi_interface_t, disable: bool) -> i32;
}

static STA_RECONNECT_TASK_STARTED: AtomicBool = AtomicBool::new(false);
// Main may keep NAN/raw Wi-Fi initialized while the STA association retries.
// The default STA netif is an ESP-IDF singleton: recreating it on a retry
// asserts in `esp_netif_create_default_wifi_sta`.  Retain this adapter-owned
// handle for the lifetime of the firmware and reuse it after `stop_sta()`.
static STA_NETIF: AtomicPtr<esp_idf_sys::esp_netif_t> = AtomicPtr::new(core::ptr::null_mut());
static STA_DRIVER_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// ESP-IDF supplies the monotonic clock; the transport owns the resulting
/// opaque timing accumulator so every bearer uses the same measurements.
fn record_control_success(timing: &mut DatagramTiming) {
    timing.record_at(unsafe { esp_idf_sys::esp_timer_get_time() as u64 });
}

pub(crate) use dmesh_server::net::parse_ipv4;

fn wifi_init_config_default() -> esp_idf_sys::wifi_init_config_t {
    esp_idf_sys::wifi_init_config_t {
        osi_funcs: core::ptr::addr_of_mut!(esp_idf_sys::g_wifi_osi_funcs),
        wpa_crypto_funcs: unsafe { esp_idf_sys::g_wifi_default_wpa_crypto_funcs },
        static_rx_buf_num: esp_idf_sys::CONFIG_ESP_WIFI_STATIC_RX_BUFFER_NUM as i32,
        dynamic_rx_buf_num: esp_idf_sys::CONFIG_ESP_WIFI_DYNAMIC_RX_BUFFER_NUM as i32,
        tx_buf_type: esp_idf_sys::CONFIG_ESP_WIFI_TX_BUFFER_TYPE as i32,
        static_tx_buf_num: esp_idf_sys::WIFI_STATIC_TX_BUFFER_NUM as i32,
        dynamic_tx_buf_num: esp_idf_sys::WIFI_DYNAMIC_TX_BUFFER_NUM as i32,
        rx_mgmt_buf_type: esp_idf_sys::CONFIG_ESP_WIFI_DYNAMIC_RX_MGMT_BUF as i32,
        rx_mgmt_buf_num: esp_idf_sys::WIFI_RX_MGMT_BUF_NUM_DEF as i32,
        cache_tx_buf_num: esp_idf_sys::WIFI_CACHE_TX_BUFFER_NUM as i32,
        csi_enable: esp_idf_sys::WIFI_CSI_ENABLED as i32,
        ampdu_rx_enable: esp_idf_sys::WIFI_AMPDU_RX_ENABLED as i32,
        ampdu_tx_enable: esp_idf_sys::WIFI_AMPDU_TX_ENABLED as i32,
        amsdu_tx_enable: esp_idf_sys::WIFI_AMSDU_TX_ENABLED as i32,
        nvs_enable: 0,
        nano_enable: esp_idf_sys::WIFI_NANO_FORMAT_ENABLED as i32,
        rx_ba_win: esp_idf_sys::WIFI_DEFAULT_RX_BA_WIN as i32,
        wifi_task_core_id: esp_idf_sys::WIFI_TASK_CORE_ID as i32,
        beacon_max_len: esp_idf_sys::WIFI_SOFTAP_BEACON_MAX_LEN as i32,
        mgmt_sbuf_num: esp_idf_sys::WIFI_MGMT_SBUF_NUM as i32,
        feature_caps: esp_idf_sys::WIFI_FEATURE_CAPS as u64,
        sta_disconnected_pm: esp_idf_sys::WIFI_STA_DISCONNECTED_PM_ENABLED != 0,
        espnow_max_encrypt_num: esp_idf_sys::CONFIG_ESP_WIFI_ESPNOW_MAX_ENCRYPT_NUM as i32,
        tx_hetb_queue_num: esp_idf_sys::WIFI_TX_HETB_QUEUE_NUM as i32,
        dump_hesigb_enable: esp_idf_sys::WIFI_DUMP_HESIGB_ENABLED != 0,
        magic: esp_idf_sys::WIFI_INIT_CONFIG_MAGIC as i32,
    }
}

unsafe fn report_radio_profile() {
    let mut phymode: esp_idf_sys::wifi_phy_mode_t = core::mem::zeroed();
    if esp_idf_sys::esp_wifi_sta_get_negotiated_phymode(&mut phymode) == esp_idf_sys::ESP_OK {
        uart::send_stat(b"radio negotiated_phymode_id=", phymode as u64);
    }
    let mut bandwidth: esp_idf_sys::wifi_bandwidth_t = core::mem::zeroed();
    if esp_idf_sys::esp_wifi_get_bandwidth(
        esp_idf_sys::wifi_interface_t_WIFI_IF_STA,
        &mut bandwidth,
    ) == esp_idf_sys::ESP_OK
    {
        uart::send_stat(b"radio bandwidth_id=", bandwidth as u64);
    }
    let mut protocol_bitmap = 0u8;
    if esp_idf_sys::esp_wifi_get_protocol(
        esp_idf_sys::wifi_interface_t_WIFI_IF_STA,
        &mut protocol_bitmap,
    ) == esp_idf_sys::ESP_OK
    {
        uart::send_stat(b"radio protocol_bitmap=", protocol_bitmap as u64);
    }
}

pub fn init_sta(params: &TransportProfile) {
    unsafe {
        if !params.has_flash_profile() {
            uart::send_response(b"recovery profile missing");
            return;
        }
        uart::send_response(b"wifi init begin");
        let _ = esp_idf_sys::esp_netif_init();
        let _ = esp_idf_sys::esp_event_loop_create_default();
        let mut netif = STA_NETIF.load(Ordering::Acquire);
        if netif.is_null() {
            let created = esp_idf_sys::esp_netif_create_default_wifi_sta();
            if created.is_null() {
                uart::send_response(b"wifi netif failed");
                return;
            }
            match STA_NETIF.compare_exchange(
                core::ptr::null_mut(),
                created,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => netif = created,
                Err(existing) => {
                    // The Main session owner serializes starts today, but
                    // keep this safe if another FreeRTOS task races startup.
                    netif = existing;
                }
            }
        }
        uart::send_response(b"wifi netif ready");
        if !STA_DRIVER_INITIALIZED.swap(true, Ordering::AcqRel) {
            let mut init = wifi_init_config_default();
            let result = esp_idf_sys::esp_wifi_init(&mut init);
            if result != esp_idf_sys::ESP_OK && result != esp_idf_sys::ESP_ERR_INVALID_STATE {
                STA_DRIVER_INITIALIZED.store(false, Ordering::Release);
                uart::send_response(b"wifi driver init failed");
                return;
            }
        }
        uart::send_response(b"wifi driver ready");
        let _ = esp_idf_sys::esp_wifi_set_storage(esp_idf_sys::wifi_storage_t_WIFI_STORAGE_RAM);
        let mut sta = esp_idf_sys::wifi_sta_config_t::default();
        let ssid = if params.ssid_len != 0 {
            &params.ssid[..params.ssid_len]
        } else {
            b"Direct-Recovery"
        };
        for (dst, src) in sta.ssid.iter_mut().zip(ssid.iter().copied()) {
            *dst = src;
        }
        sta.password = [0; 64];
        let mut config = esp_idf_sys::wifi_config_t { sta };
        let _ = esp_idf_sys::esp_wifi_set_mode(esp_idf_sys::wifi_mode_t_WIFI_MODE_STA);
        let _ = esp_idf_sys::esp_wifi_set_config(
            esp_idf_sys::wifi_interface_t_WIFI_IF_STA,
            &mut config,
        );
        let mut protocols = esp_idf_sys::wifi_protocols_t {
            ghz_2g: RECOVERY_STA_PROTOCOL as u16,
            ghz_5g: 0,
        };
        if esp_idf_sys::esp_wifi_set_protocols(
            esp_idf_sys::wifi_interface_t_WIFI_IF_STA,
            &mut protocols,
        ) != esp_idf_sys::ESP_OK
        {
            uart::send_response(b"wifi bgn set failed");
            return;
        }
        uart::send_response(b"wifi bgn configured");
        // ESP-IDF does not offer n-only for a 2.4 GHz STA; keep the required
        // b/g/n protocol bitmap for HT negotiation but prohibit CCK/11b data
        // rates before the association begins.
        if esp_wifi_config_11b_rate(esp_idf_sys::wifi_interface_t_WIFI_IF_STA, true)
            == esp_idf_sys::ESP_OK
        {
            uart::send_response(b"wifi 11b rates disabled");
        } else {
            uart::send_response(b"wifi 11b rate policy failed");
        }
        let server_host = params
            .server
            .get(..params.server_len)
            .and_then(|server| server.split(|byte| *byte == b':').next())
            .unwrap_or(&[]);
        let gateway_bytes = if params.gateway_len != 0 {
            &params.gateway[..params.gateway_len]
        } else {
            server_host
        };
        let mask_bytes: &[u8] = if params.mask_len != 0 {
            &params.mask[..params.mask_len]
        } else {
            b"255.255.0.0"
        };
        let (Some(ip), Some(mask), Some(gateway)) = (
            parse_ipv4(&params.local_ip[..params.local_ip_len]),
            parse_ipv4(mask_bytes),
            parse_ipv4(gateway_bytes),
        ) else {
            uart::send_response(b"wifi static profile invalid");
            return;
        };
        let dhcp = esp_idf_sys::esp_netif_dhcpc_stop(netif);
        if dhcp != esp_idf_sys::ESP_OK
            && dhcp != esp_idf_sys::ESP_ERR_ESP_NETIF_DHCP_ALREADY_STOPPED
        {
            uart::send_response(b"wifi DHCP stop failed");
            return;
        }
        let info = esp_idf_sys::esp_netif_ip_info_t {
            ip: esp_idf_sys::esp_ip4_addr { addr: ip },
            netmask: esp_idf_sys::esp_ip4_addr { addr: mask },
            gw: esp_idf_sys::esp_ip4_addr { addr: gateway },
        };
        if esp_idf_sys::esp_netif_set_ip_info(netif, &info) != esp_idf_sys::ESP_OK {
            uart::send_response(b"wifi static IP failed");
            return;
        }
        uart::send_response(b"wifi static IP configured");
        let start_result = esp_idf_sys::esp_wifi_start();
        if start_result != esp_idf_sys::ESP_OK && start_result != esp_idf_sys::ESP_ERR_INVALID_STATE
        {
            uart::send_response(b"wifi STA start failed");
            return;
        }
        uart::send_response(b"wifi start complete");
        let _ = esp_idf_sys::esp_wifi_set_ps(esp_idf_sys::wifi_ps_type_t_WIFI_PS_NONE);
        if esp_idf_sys::esp_wifi_connect() != esp_idf_sys::ESP_OK {
            uart::send_response(b"wifi STA connect failed");
            return;
        }
        start_sta_reconnect_task();
        uart::send_response(b"wifi connect issued");
        uart::send_response(b"wifi STA started");
        let mut associated = false;
        let mut ip_ready = false;
        for attempt in 0..50 {
            esp_idf_sys::vTaskDelay(100);
            if attempt != 0 && attempt % 10 == 0 && !associated {
                let _ = esp_idf_sys::esp_wifi_connect();
            }
            let _ = esp_idf_sys::esp_netif_dhcpc_stop(netif);
            let _ = esp_idf_sys::esp_netif_set_default_netif(netif);
            let _ = esp_idf_sys::esp_netif_set_ip_info(netif, &info);
            let mut ap = esp_idf_sys::wifi_ap_record_t::default();
            if esp_idf_sys::esp_wifi_sta_get_ap_info(&mut ap) == esp_idf_sys::ESP_OK {
                associated = true;
            }
            let mut current = esp_idf_sys::esp_netif_ip_info_t::default();
            ip_ready = esp_idf_sys::esp_netif_get_ip_info(netif, &mut current)
                == esp_idf_sys::ESP_OK
                && current.ip.addr != 0
                && esp_idf_sys::esp_netif_is_netif_up(netif);
            if associated && ip_ready {
                break;
            }
        }
        if !(associated && ip_ready) {
            uart::send_response(b"wifi readiness timeout");
        }
        uart::send_response(if associated {
            b"wifi STA associated"
        } else {
            b"wifi STA association failed"
        });
        uart::send_response(if ip_ready {
            b"wifi IP ready"
        } else {
            b"wifi IP not ready"
        });
        // esp-netif requires an active STA netif before it can install the
        // link-local address.  Asking immediately after esp_wifi_start()
        // returned ESP_ERR_ESP_NETIF_IF_NOT_READY on the C6.
        if associated && esp_idf_sys::esp_netif_create_ip6_linklocal(netif) == esp_idf_sys::ESP_OK {
            uart::send_response(b"wifi IPv6 link-local requested");
        } else {
            uart::send_response(b"wifi IPv6 link-local failed");
        }
        if associated {
            report_radio_profile();
        }
        uart::send_response(b"wifi static STA configured");
    }
}

/// End a bounded sleepy-node STA session.  The caller owns the session policy;
/// this adapter only releases the ESP-IDF STA bearer so the normal light-sleep
/// scheduler can resume. Infrastructure callers intentionally never use it.
pub fn stop_sta() {
    unsafe {
        let _ = esp_idf_sys::esp_wifi_disconnect();
        let _ = esp_idf_sys::esp_wifi_stop();
    }
}

/// Cheap association observation for Main's nonblocking session owner.
pub fn sta_associated() -> bool {
    unsafe {
        let mut ap = esp_idf_sys::wifi_ap_record_t::default();
        esp_idf_sys::esp_wifi_sta_get_ap_info(&mut ap) == esp_idf_sys::ESP_OK
    }
}

/// Keep the Recovery STA associated across a controlled AP restart/channel
/// move.  The transport owns reconnect/ACK state above this bearer; this task
/// only asks ESP-IDF to restore the existing STA association when its own
/// association query says it is absent.
fn start_sta_reconnect_task() {
    if STA_RECONNECT_TASK_STARTED.swap(true, Ordering::AcqRel) {
        return;
    }
    let mut task = core::ptr::null_mut();
    let result = unsafe {
        esp_idf_sys::xTaskCreatePinnedToCore(
            Some(sta_reconnect_task),
            b"wifi_recon\0".as_ptr().cast(),
            3072,
            core::ptr::null_mut(),
            3,
            &mut task,
            0,
        )
    };
    if result != 1 || task.is_null() {
        STA_RECONNECT_TASK_STARTED.store(false, Ordering::Release);
        uart::send_response(b"wifi reconnect task failed");
    }
}

unsafe extern "C" fn sta_reconnect_task(_argument: *mut c_void) {
    loop {
        esp_idf_sys::vTaskDelay(1000);
        let mut ap = esp_idf_sys::wifi_ap_record_t::default();
        if esp_idf_sys::esp_wifi_sta_get_ap_info(&mut ap) != esp_idf_sys::ESP_OK {
            let _ = esp_idf_sys::esp_wifi_connect();
        }
    }
}

fn sockaddr_len() -> esp_idf_sys::socklen_t {
    core::mem::size_of::<esp_idf_sys::sockaddr_in>() as _
}

fn send_packet(fd: c_int, peer: &esp_idf_sys::sockaddr_in, bytes: &[u8]) -> bool {
    unsafe {
        // lwIP recvfrom does not reliably populate BSD's sin_len field. Make
        // the outbound address canonical rather than feeding that partial
        // structure straight back into sendto.
        let mut destination = *peer;
        destination.sin_len = core::mem::size_of::<esp_idf_sys::sockaddr_in>() as u8;
        destination.sin_family = esp_idf_sys::AF_INET as u8;
        esp_idf_sys::lwip_sendto(
            fd,
            bytes.as_ptr().cast(),
            bytes.len(),
            0,
            (&destination as *const esp_idf_sys::sockaddr_in).cast(),
            sockaddr_len(),
        ) >= 0
    }
}

/// ESP32-specific egress selection for the shared connection. Path 0 is the
/// Recovery UDP socket and path 1 is PPP UART; `DcidRouter` owns availability
/// and fallback, not the application/flash callbacks.
fn send_transport_datagram(
    router: &mut quic_lite::DcidRouter<1, 2>,
    policy: quic_lite::PathPolicy,
    primary_full: bool,
    fd: c_int,
    peer: &esp_idf_sys::sockaddr_in,
    bytes: &[u8],
) -> bool {
    // UART egress is owned by its dedicated FreeRTOS task. Publish its
    // bounded queue before choosing a path so AirtimeFirst can spill rather
    // than turn a full USB/PPP queue into a transport failure.
    let (queued_packets, capacity_packets) = l2::transport_egress_capacity();
    let _ = router.set_path_capacity(
        1,
        quic_lite::PathCapacity::new(queued_packets, capacity_packets),
    );
    let selected = match router.select_with_policy(policy, primary_full) {
        Ok(path) => path,
        Err(_) => return false,
    };
    let started = unsafe { esp_idf_sys::esp_timer_get_time() as u64 };
    let sent = match selected {
        0 => send_packet(fd, peer, bytes),
        1 => l2::send_transport_packet(bytes),
        _ => false,
    };
    let elapsed = (unsafe { esp_idf_sys::esp_timer_get_time() as u64 }).saturating_sub(started);
    if sent {
        let _ = router.record_path_sample(selected, bytes.len(), elapsed);
        return true;
    }
    let _ = router.record_path_loss(selected);
    let _ = router.set_path_available(selected, false);
    // A failure is a bearer observation, not a stream failure. Try another
    // live path under the dynamic policy without rebuilding endpoint state.
    let fallback =
        match router.select_with_policy(quic_lite::PathPolicy::HighestMeasuredSpeed, true) {
            Ok(path) => path,
            Err(_) => return false,
        };
    let fallback_started = unsafe { esp_idf_sys::esp_timer_get_time() as u64 };
    let fallback_sent = match fallback {
        0 => send_packet(fd, peer, bytes),
        1 => l2::send_transport_packet(bytes),
        _ => false,
    };
    let fallback_elapsed =
        (unsafe { esp_idf_sys::esp_timer_get_time() as u64 }).saturating_sub(fallback_started);
    if fallback_sent {
        let _ = router.record_path_sample(fallback, bytes.len(), fallback_elapsed);
    } else {
        let _ = router.record_path_loss(fallback);
        let _ = router.set_path_available(fallback, false);
    }
    fallback_sent
}

fn send_errno() -> i32 {
    unsafe { *__errno() }
}

/// Run one shared Recovery/Main connection over its registered L2 bearers.
///
/// UDP supplies the STA socket adapter and UART supplies the dedicated PPP
/// queue adapter. Both ingress paths route through the same DCID router and
/// the same endpoint/stream/flash state below; neither bearer owns an ACK,
/// retransmission ledger, or service callback. Additional ESP bearers extend
/// this loop by feeding a complete MTU datagram plus a path ID.
pub fn run_transport(
    profile: &TransportProfile,
    // Recovery supplies its RTC/Stage2/reboot completion action. Main passes
    // a non-rebooting completion action for its own permitted flash targets.
    complete_main_flash: fn() -> bool,
) {
    // Keep the runtime entry point profile-shaped. Recovery and Main load the
    // same no-std profile, so adding a transport option cannot create a
    // second, positional argument contract in one firmware binary.
    let server = &profile.server[..profile.server_len];
    let port = profile.port;
    let benchmark = profile.benchmark;
    let timeout_ms = profile.timeout_ms;
    let ack_frequency = profile.ack_frequency;
    let ack_delay_ms = profile.ack_delay_ms;
    let path_policy = profile.path_policy;
    let transport_test = profile.transport_test;
    let iperf_packet_size = profile.iperf_packet_size;
    let iperf_bytes = profile.iperf_bytes;
    let iperf_parallel_streams = profile.iperf_parallel_streams;
    let iperf_high_priority_bytes = profile.iperf_high_priority_bytes;
    let iperf_low_priority_bytes = profile.iperf_low_priority_bytes;
    let iperf_validation = profile.iperf_validation;
    let iperf_pace_us = profile.iperf_pace_us;
    let iperf_burst_packets = profile.iperf_burst_packets;
    let iperf_burst_delay_us = profile.iperf_burst_delay_us;
    let iperf_window_packets = profile.iperf_window_packets;
    let benchmark_run_id = profile.benchmark_run_id;
    let Some(server_ip) = parse_ipv4(server) else {
        uart::send_response(b"udp server address invalid");
        return;
    };
    let fd = unsafe {
        esp_idf_sys::lwip_socket(
            esp_idf_sys::AF_INET as c_int,
            esp_idf_sys::SOCK_DGRAM as c_int,
            esp_idf_sys::IPPROTO_UDP as c_int,
        )
    };
    if fd < 0 {
        uart::send_response(b"udp socket failed");
        return;
    }
    uart::send_response(b"udp socket ready");
    let receive_buffer_bytes = UDP_RECEIVE_BUFFER_BYTES as c_int;
    let receive_buffer_result = unsafe {
        esp_idf_sys::lwip_setsockopt(
            fd,
            esp_idf_sys::SOL_SOCKET as c_int,
            esp_idf_sys::SO_RCVBUF as c_int,
            (&receive_buffer_bytes as *const c_int).cast(),
            core::mem::size_of_val(&receive_buffer_bytes) as _,
        )
    };
    if receive_buffer_result != 0 {
        uart::send_response(b"udp receive buffer failed");
    } else {
        uart::send_stat(b"udp receive buffer=", UDP_RECEIVE_BUFFER_BYTES as u64);
    }
    let timeout = esp_idf_sys::timeval {
        tv_sec: 0,
        tv_usec: SOCKET_TIMEOUT_MS as i32 * 1000,
    };
    unsafe {
        let _ = esp_idf_sys::lwip_setsockopt(
            fd,
            esp_idf_sys::SOL_SOCKET as c_int,
            esp_idf_sys::SO_RCVTIMEO as c_int,
            (&timeout as *const esp_idf_sys::timeval).cast(),
            core::mem::size_of_val(&timeout) as _,
        );
    }
    let local = esp_idf_sys::sockaddr_in {
        sin_len: core::mem::size_of::<esp_idf_sys::sockaddr_in>() as u8,
        sin_family: esp_idf_sys::AF_INET as u8,
        sin_port: TRANSPORT_UDP_PORT.to_be(),
        sin_addr: esp_idf_sys::in_addr { s_addr: 0 },
        sin_zero: [0; 8],
    };
    if unsafe {
        esp_idf_sys::lwip_bind(
            fd,
            (&local as *const esp_idf_sys::sockaddr_in).cast(),
            sockaddr_len(),
        )
    } < 0
    {
        unsafe {
            esp_idf_sys::lwip_close(fd);
        }
        return;
    }
    let recovery_limits =
        quic_lite::recovery_connection_limits(transport_test, iperf_window_packets);
    let mut endpoint = RecoveryEndpoint::<RECOVERY_TRANSPORT_STREAMS>::new(
        Role::Client,
        recovery_limits,
        UDP_MTU as u64,
    );
    // ACK coalescing is configured here, while ACK encoding and emission
    // remain entirely inside quic-lite.
    let effective_ack_delay_ms = if ack_delay_ms == 0 {
        RECOVERY_MAX_ACK_DELAY_MS
    } else {
        u64::from(ack_delay_ms.clamp(1, 25))
    };
    endpoint.set_ack_policy(
        if ack_frequency == 0 {
            DEFAULT_ACK_FREQUENCY
        } else {
            ack_frequency
        },
        effective_ack_delay_ms,
    );
    let server_peer = esp_idf_sys::sockaddr_in {
        sin_len: core::mem::size_of::<esp_idf_sys::sockaddr_in>() as u8,
        sin_family: esp_idf_sys::AF_INET as u8,
        sin_port: port.to_be(),
        sin_addr: esp_idf_sys::in_addr { s_addr: server_ip },
        sin_zero: [0; 8],
    };
    // A server retains a completed connection briefly so delayed packets can
    // be rejected safely.  Reusing CID=1 on the fixed Recovery UDP source
    // port therefore makes a later command-mode benchmark look like a stale
    // bootstrap and it never receives a bootstrap ACK.  A benchmark run ID is
    // host-generated per command; normal object runs use ESP's hardware RNG.
    // Packet numbers may restart only because this is a distinct connection.
    let Some(client_cid) =
        recovery_connection_id(benchmark_run_id, unsafe { esp_idf_sys::esp_random() })
    else {
        unsafe {
            esp_idf_sys::lwip_close(fd);
        }
        return;
    };
    let mut open_packet = [0u8; UDP_MTU];
    let mut bootstrap_packet_number = 0u32;
    let Some(mut open_len) = quic_lite::encode_bootstrap_open_packet_with_profile(
        client_cid,
        bootstrap_packet_number,
        recovery_limits,
        if iperf_window_packets == 0 {
            quic_lite::RECOVERY_MAX_IN_FLIGHT_PACKETS
        } else {
            u16::from(iperf_window_packets)
        },
        &mut open_packet,
    )
    .ok() else {
        unsafe {
            esp_idf_sys::lwip_close(fd);
        }
        return;
    };
    if !send_packet(fd, &server_peer, &open_packet[..open_len]) {
        uart::send_response(b"udp bootstrap send failed");
        unsafe {
            esp_idf_sys::lwip_close(fd);
        }
        return;
    }
    uart::send_response(b"udp bootstrap open sent");
    let deadline = unsafe { esp_idf_sys::esp_timer_get_time() as u64 / 1000 }
        .saturating_add(timeout_ms as u64);
    let mut server_cid = None;
    let mut last_open = unsafe { esp_idf_sys::esp_timer_get_time() as u64 / 1000 };
    let mut packet = [0u8; UDP_MTU];
    let mut peer = esp_idf_sys::sockaddr_in::default();
    let mut peer_len = sockaddr_len();
    while unsafe { esp_idf_sys::esp_timer_get_time() as u64 / 1000 } < deadline {
        let received = unsafe {
            esp_idf_sys::lwip_recvfrom(
                fd,
                packet.as_mut_ptr().cast(),
                packet.len(),
                0,
                (&mut peer as *mut esp_idf_sys::sockaddr_in).cast(),
                &mut peer_len,
            )
        };
        if received > 0 {
            if let Ok((header, ack)) = quic_lite::decode_bootstrap_open_ack_packet_with_limits(
                &packet[..received as usize],
                client_cid,
            ) {
                if endpoint
                    .set_initial_peer_budget(
                        ack.max_data,
                        ack.max_stream_data,
                        ack.max_in_flight_packets,
                    )
                    .is_err()
                {
                    break;
                }
                // Bootstrap retries can make the host emit several OPEN_ACKs
                // before this one arrives. Its sender packet number belongs
                // to the host's independent packet-number space; observing it
                // here makes the first established packet contiguous instead
                // of reporting those valid bootstrap ACKs as stream loss.
                endpoint.observe_packet(header.packet_number);
                server_cid = Some(ack.server_receive_cid);
                break;
            }
        }
        let now = unsafe { esp_idf_sys::esp_timer_get_time() as u64 / 1000 };
        if now.saturating_sub(last_open) >= BOOTSTRAP_RETRY_MS {
            bootstrap_packet_number = match bootstrap_packet_number.checked_add(1) {
                Some(value) => value,
                None => break,
            };
            let Some(next_open_len) = quic_lite::encode_bootstrap_open_packet_with_profile(
                client_cid,
                bootstrap_packet_number,
                recovery_limits,
                if iperf_window_packets == 0 {
                    quic_lite::RECOVERY_MAX_IN_FLIGHT_PACKETS
                } else {
                    u16::from(iperf_window_packets)
                },
                &mut open_packet,
            )
            .ok() else {
                break;
            };
            open_len = next_open_len;
            let _ = send_packet(fd, &server_peer, &open_packet[..open_len]);
            last_open = now;
        }
    }
    let Some(server_cid) = server_cid else {
        uart::send_response(b"udp bootstrap timeout");
        unsafe {
            esp_idf_sys::lwip_close(fd);
        }
        return;
    };
    uart::send_response(b"udp bootstrap established");
    if endpoint
        .install_connection_ids(client_cid, server_cid)
        .is_err()
    {
        unsafe {
            esp_idf_sys::lwip_close(fd);
        }
        return;
    }
    let Some(first_established_packet_number) = bootstrap_packet_number.checked_add(1) else {
        unsafe {
            esp_idf_sys::lwip_close(fd);
        }
        return;
    };
    if endpoint
        .continue_packet_numbers_from(first_established_packet_number)
        .is_err()
    {
        unsafe {
            esp_idf_sys::lwip_close(fd);
        }
        return;
    }
    // Every established bearer packet reaches this shared DCID router before
    // the connection. Recovery currently supplies only UDP path 0; UART and
    // future bearers register the same client CID without creating a second
    // endpoint or stream state.
    let mut ingress = quic_lite::DcidRouter::<1, 2>::new([
        quic_lite::PathState::new(), // UDP
        quic_lite::PathState::new(), // UART PPP
    ]);
    if ingress.register(client_cid).is_err() || ingress.set_path_available(0, true).is_err() {
        unsafe {
            esp_idf_sys::lwip_close(fd);
        }
        return;
    }
    // Normal operation migrates to the best measured bearer. A direct
    // command/control policy may later pin a benchmark path or request
    // airtime-first spillover without changing this connection instance.
    let path_policy = match path_policy {
        1 => quic_lite::PathPolicy::Explicit(0), // UDP comparison
        2 => quic_lite::PathPolicy::Explicit(1), // UART comparison
        3 => quic_lite::PathPolicy::AirtimeFirst { primary: 1 },
        _ => quic_lite::PathPolicy::HighestMeasuredSpeed,
    };
    let mut request_body = [0u8; 64];
    let request_body_len = if transport_test {
        // SERVICE_IPERF is a transport-only deterministic byte stream. This
        // deliberately isolates radio/lwIP/transport behavior from object
        // decoding, hashing, erase, and flash writes.
        request_body[0] = quic_lite::SERVICE_IPERF;
        request_body[1..9].copy_from_slice(&(iperf_bytes as u64).to_be_bytes());
        request_body[9..11].copy_from_slice(&iperf_packet_size.to_be_bytes());
        // Optional, request-scoped host sender controls. They make a pacing
        // matrix reproducible without restarting the standalone listener;
        // all-zero preserves the normal unlimited/unpaced transport path.
        request_body[11..15].copy_from_slice(&iperf_pace_us.to_be_bytes());
        request_body[15] = iperf_burst_packets;
        request_body[16..20].copy_from_slice(&iperf_burst_delay_us.to_be_bytes());
        // The server reflects this byte in ACK_FREQUENCY. Keeping it in the
        // benchmark request makes the selected device ACK policy visible and
        // negotiated instead of a local-only UART/UDP command setting.
        request_body[20] = if ack_frequency == 0 {
            DEFAULT_ACK_FREQUENCY
        } else {
            ack_frequency
        };
        // The server reflects this limit through ACK_FREQUENCY, so both
        // endpoints use the same request-scoped delayed-ACK policy.
        request_body[21] = effective_ack_delay_ms as u8;
        // A nonzero trailing low-priority byte count asks the host service to
        // send a separate log-like stream alongside the primary IPERF stream.
        // It remains a stream-level test; UART is only the selected L2.
        request_body[22..26].copy_from_slice(&iperf_low_priority_bytes.to_be_bytes());
        request_body[26..30].copy_from_slice(&iperf_high_priority_bytes.to_be_bytes());
        request_body[30] = iperf_parallel_streams.clamp(1, IPERF_MAX_NORMAL_STREAMS as u8);
        31
    } else {
        request_body[0] = SERVICE_OBJECT;
        // This one-byte transport-service envelope carries the negotiated
        // ACK ratio. The object-store payload starts at byte two and remains
        // its exact canonical CBOR GET map.
        request_body[1] = if ack_frequency == 0 {
            DEFAULT_ACK_FREQUENCY
        } else {
            ack_frequency
        };
        let Some(request_len_body) = encode_get(&mut request_body[2..], None, 13, 6) else {
            unsafe {
                esp_idf_sys::lwip_close(fd);
            }
            return;
        };
        request_len_body + 2
    };
    if endpoint
        .open_send_stream(REQUEST_STREAM, INITIAL_MAX_STREAM_DATA)
        .is_err()
    {
        unsafe {
            esp_idf_sys::lwip_close(fd);
        }
        return;
    }
    let mut request_packet = [0u8; UDP_MTU];
    let Some((mut request_len, mut request_packet_number)) = endpoint
        .encode_stream_packet(
            server_cid,
            REQUEST_STREAM,
            0,
            true,
            &request_body[..request_body_len],
            &mut request_packet,
        )
        .ok()
    else {
        unsafe {
            esp_idf_sys::lwip_close(fd);
        }
        return;
    };
    let _ = send_packet(fd, &server_peer, &request_packet[..request_len]);
    // Measure the object transfer itself, excluding bootstrap and request
    // setup. The counters come from quic-lite; Recovery only reports
    // the opaque snapshot and never interprets ACK or loss behavior.
    endpoint.reset_stats();
    uart::send_response(b"udp request sent");
    let mut last_request = unsafe { esp_idf_sys::esp_timer_get_time() as u64 / 1000 };
    let mut session_started = false;
    let mut flash = if transport_test {
        None
    } else {
        match FlashHandler::new(benchmark) {
            Some(value) => Some(value),
            None => {
                uart::send_response(b"udp main partition missing");
                unsafe {
                    esp_idf_sys::lwip_close(fd);
                }
                return;
            }
        }
    };
    let mut rx_datagrams = 0u64;
    let mut rejected_datagrams = 0u64;
    let mut stream_datagrams = 0u64;
    let mut control_datagrams = 0u64;
    let mut transport_datagrams = 0u64;
    let mut request_retries = 0u64;
    let mut duplicate_datagrams = 0u64;
    let mut last_rx_us = None;
    let mut interpacket_count = 0u64;
    let mut interpacket_total_us = 0u64;
    let mut interpacket_max_us = 0u64;
    let mut interpacket_gap_buckets = [0u64; INTERPACKET_GAP_BUCKETS];
    let iperf_parallel_streams = iperf_parallel_streams.clamp(1, IPERF_MAX_NORMAL_STREAMS as u8);
    // Stream placement, validation, completion and byte/error accounting are
    // host-testable QUIC-lite IPERF semantics. The ESP loop supplies only
    // committed stream frames and uses their consumed byte count for credit.
    let mut iperf = IperfRun::<IPERF_MAX_NORMAL_STREAMS>::new(
        iperf_validation,
        iperf_parallel_streams as usize,
        iperf_high_priority_bytes != 0,
        iperf_low_priority_bytes != 0,
    );
    let mut transfer_started_us = 0u64;
    let mut transfer_completed_us = 0u64;
    let mut transport_errors = [0u64; 11];
    let mut transport_send_failures = 0u64;
    let mut transport_last_send_errno = 0i32;
    let mut outbound_control_timing = DatagramTiming::default();
    // Separate genuine socket timeouts from immediate EWOULDBLOCK returns.
    // They have different scheduling meaning: the former already gave Wi-Fi
    // time to run, while the latter can spin this higher-priority task.
    let mut empty_socket_returns = 0u64;
    let mut empty_socket_spins = 0u64;
    let mut empty_socket_yields = 0u64;
    // Measured around the full RTOS-tick yield only.  This distinguishes the
    // intended cooperative handoff from an actual scheduler delay without
    // putting a clock read in the per-datagram receive path.
    let mut empty_socket_tick_yield_us = 0u64;
    let mut empty_socket_cooperative_yields = 0u64;
    let mut consecutive_empty_spins = 0u64;
    let mut last_full_tick_yield_us = unsafe { esp_idf_sys::esp_timer_get_time() as u64 };
    let mut receive_bursts = 0u64;
    let mut receive_burst_max = 0u64;
    let mut receive_bursts_since_yield = 0u64;
    let mut uart_packet = [0u8; l2::UART_MAX_PACKET];
    loop {
        let now = unsafe { esp_idf_sys::esp_timer_get_time() as u64 / 1000 };
        if now >= deadline {
            break;
        }
        endpoint.set_time(now);
        let probe_now_us = unsafe { esp_idf_sys::esp_timer_get_time() as u64 };
        if let Some(path) = ingress.select_probe(probe_now_us, PATH_PROBE_INTERVAL_US) {
            let mut probe = [0u8; UDP_MTU];
            if let Ok((used, _)) = endpoint.encode_probe_packet(server_cid, &mut probe) {
                let _ = send_transport_datagram(
                    &mut ingress,
                    quic_lite::PathPolicy::Explicit(path),
                    false,
                    fd,
                    &server_peer,
                    &probe[..used],
                );
            }
        }
        let receive_started_us = unsafe { esp_idf_sys::esp_timer_get_time() as u64 };
        let mut received_path = 0usize;
        let received = if let Some(used) = l2::dequeue_transport_packet(&mut uart_packet) {
            // The UART task has already stripped the PPP marker. Copy into
            // the common packet buffer so the same endpoint consumes this
            // packet exactly as it would a UDP datagram.
            packet[..used].copy_from_slice(&uart_packet[..used]);
            let _ = ingress.set_path_available(1, true);
            received_path = 1;
            used as i32
        } else {
            // Once a packetized serial bearer is live, never let an empty UDP
            // socket impose its 5 ms (one FreeRTOS tick in practice) timeout
            // between serial packets. The UART task is independently filling
            // its bounded ingress queue; use the existing cooperative empty
            // path below until either bearer has input. UDP-only transfers
            // retain their short blocking receive for efficient Wi-Fi idle.
            let socket_flags = if ingress.path(1).is_some_and(|path| path.available)
                || matches!(
                    path_policy,
                    quic_lite::PathPolicy::Explicit(1)
                        | quic_lite::PathPolicy::AirtimeFirst { primary: 1 }
                ) {
                esp_idf_sys::MSG_DONTWAIT as c_int
            } else {
                0
            };
            peer_len = sockaddr_len();
            unsafe {
                esp_idf_sys::lwip_recvfrom(
                    fd,
                    packet.as_mut_ptr().cast(),
                    packet.len(),
                    socket_flags,
                    (&mut peer as *mut esp_idf_sys::sockaddr_in).cast(),
                    &mut peer_len,
                ) as i32
            }
        };
        if received <= 0 {
            let receive_wait_us = (unsafe { esp_idf_sys::esp_timer_get_time() as u64 })
                .saturating_sub(receive_started_us);
            empty_socket_returns = empty_socket_returns.saturating_add(1);
            if receive_wait_us < 1_000 {
                empty_socket_spins = empty_socket_spins.saturating_add(1);
                consecutive_empty_spins = consecutive_empty_spins.saturating_add(1);
            } else {
                consecutive_empty_spins = 0;
            }
            // The bearer only reports its timer tick. Transport decides
            // whether a delayed ACK/window update is pending and encodes it;
            // Recovery must never manipulate ACKs or credit directly.
            endpoint.on_bearer_timeout();
            // A full initial stream window can leave the sender correctly
            // waiting for MAX_* while the flash worker finishes its queued
            // blocks.  Do not require a new inbound datagram to observe that
            // completion: drain the application-owned slots on every bearer
            // timeout, then give transport an opportunity to publish its own
            // credit/control frame.  Recovery neither inspects nor encodes
            // that frame.
            if let Some(flash) = flash.as_mut() {
                let released = match flash.flush_pending() {
                    Ok(value) => value,
                    Err(()) => {
                        uart::send_response(b"udp flash sink failed");
                        unsafe { esp_idf_sys::lwip_close(fd) };
                        return;
                    }
                };
                if released != 0
                    && endpoint
                        .stream_consumed_deferred(OBJECT_STREAM, released)
                        .is_err()
                {
                    uart::send_response(b"udp stream credit failed");
                    unsafe { esp_idf_sys::lwip_close(fd) };
                    return;
                }
            }
            let mut delayed_control = [0u8; UDP_MTU];
            let mut emitted_control = false;
            if let Ok(Some(used)) = endpoint.poll_transmit(&mut delayed_control) {
                if send_transport_datagram(
                    &mut ingress,
                    path_policy,
                    false,
                    fd,
                    &server_peer,
                    &delayed_control[..used],
                ) {
                    transport_datagrams = transport_datagrams.saturating_add(1);
                    record_control_success(&mut outbound_control_timing);
                    emitted_control = true;
                } else {
                    transport_send_failures = transport_send_failures.saturating_add(1);
                    transport_last_send_errno = send_errno();
                }
            }
            if let Some(flash) = flash.as_mut() {
                if flash.start_erase_after_bootstrap().is_err() {
                    uart::send_response(b"udp flash erase failed");
                    unsafe { esp_idf_sys::lwip_close(fd) };
                    return;
                }
            }
            if !session_started && now.saturating_sub(last_request) >= 500 {
                let mut retry = [0u8; UDP_MTU];
                if let Ok(Some((retry_len, replacement_packet_number))) =
                    endpoint.retransmit_stream_packet(request_packet_number, &mut retry)
                {
                    request_packet[..retry_len].copy_from_slice(&retry[..retry_len]);
                    request_len = retry_len;
                    request_packet_number = replacement_packet_number;
                    let _ = send_transport_datagram(
                        &mut ingress,
                        path_policy,
                        false,
                        fd,
                        &server_peer,
                        &request_packet[..request_len],
                    );
                    request_retries = request_retries.saturating_add(1);
                }
                last_request = now;
            }
            // lwIP can return EWOULDBLOCK immediately despite SO_RCVTIMEO.
            // In a real flash this commonly happens while the asynchronous
            // erase/write worker owns every record slot. Without a yield,
            // this higher-priority task spins, starves both Idle (task-WDT)
            // and the worker, and makes a healthy flow-control pause fatal.
            // A successfully emitted transport control packet is different:
            // return to the blocking receive immediately so its peer's
            // response is not delayed by one scheduler tick.
            if quic_lite::bearer_poll_should_yield(
                emitted_control,
                receive_wait_us,
                consecutive_empty_spins,
                (unsafe { esp_idf_sys::esp_timer_get_time() as u64 })
                    .saturating_sub(last_full_tick_yield_us),
                EMPTY_SOCKET_TICK_YIELD_SPINS,
                EMPTY_SOCKET_MAX_UNYIELDED_US,
            ) {
                empty_socket_yields = empty_socket_yields.saturating_add(1);
                consecutive_empty_spins = 0;
                let yield_started_us = unsafe { esp_idf_sys::esp_timer_get_time() as u64 };
                unsafe { esp_idf_sys::vTaskDelay(1) };
                empty_socket_tick_yield_us = empty_socket_tick_yield_us.saturating_add(
                    (unsafe { esp_idf_sys::esp_timer_get_time() as u64 })
                        .saturating_sub(yield_started_us),
                );
                last_full_tick_yield_us = unsafe { esp_idf_sys::esp_timer_get_time() as u64 };
            } else if !emitted_control && receive_wait_us < 1_000 {
                // Let Wi-Fi/lwIP work run without turning this recovery
                // turn into a fixed 10 ms sleep. The bounded full-tick path
                // above still guarantees Idle time during a true empty spin.
                empty_socket_cooperative_yields = empty_socket_cooperative_yields.saturating_add(1);
                unsafe { esp_idf_sys::vPortYield() };
            }
            continue;
        }
        consecutive_empty_spins = 0;
        let mut received = received as usize;
        let mut burst_datagrams = 0usize;
        let mut image_complete = false;
        'drain: loop {
            endpoint.set_time(unsafe { esp_idf_sys::esp_timer_get_time() as u64 / 1000 });
            rx_datagrams = rx_datagrams.saturating_add(1);
            burst_datagrams = burst_datagrams.saturating_add(1);
            let received_at_us = unsafe { esp_idf_sys::esp_timer_get_time() as u64 };
            if let Some(previous) = last_rx_us {
                let delta = received_at_us.saturating_sub(previous);
                let _ = ingress.record_path_sample(received_path, received, delta);
                interpacket_count = interpacket_count.saturating_add(1);
                interpacket_total_us = interpacket_total_us.saturating_add(delta);
                interpacket_max_us = interpacket_max_us.max(delta);
                let bucket = interpacket_gap_bucket(delta);
                interpacket_gap_buckets[bucket] = interpacket_gap_buckets[bucket].saturating_add(1);
            }
            last_rx_us = Some(received_at_us);
            if received_path == 0 {
                let _ = ingress.set_path_available(0, true);
            }
            if ingress.route(received_path, &packet[..received]).is_err() {
                rejected_datagrams = rejected_datagrams.saturating_add(1);
                if !benchmark {
                    uart::send_response(b"udp packet route rejected");
                }
                break 'drain;
            }
            let mut stream_error = false;
            // Recovery treats an image/parser failure as terminal for this
            // transfer.  Use the committed callback path so an ordinary in-order
            // packet does not heap-copy the complete transport endpoint and its
            // retransmission ledger merely to preserve retryable callback
            // backpressure that Recovery never uses.
            let receive_result = endpoint.receive_with_committed_callback_dispositions(
                &packet[..received],
                |stream| {
                    stream_datagrams = stream_datagrams.saturating_add(1);
                    if !session_started {
                        // Benchmark receives must not synchronously write UART:
                        // one record here stalled the next recvfrom for ~300 ms
                        // and manufactured two apparent Wi-Fi losses.
                        if !benchmark {
                            uart::send_response(b"udp stream received");
                        }
                        session_started = true;
                        transfer_started_us = received_at_us;
                    }
                    if transport_test {
                        let (complete, consumed) = match iperf.handle(IPERF_STREAM, stream) {
                            Ok(value) => value,
                            Err(()) => {
                                stream_error = true;
                                return Err(quic_lite::Error::Invalid);
                            }
                        };
                        image_complete = complete;
                        if image_complete {
                            transfer_completed_us =
                                unsafe { esp_idf_sys::esp_timer_get_time() as u64 };
                        }
                        Ok(CommittedStreamDisposition::Consumed(consumed))
                    } else {
                        match flash
                            .as_mut()
                            .expect("flash receiver")
                            .handle_stream(stream)
                        {
                            Ok((complete, consumed)) => {
                                image_complete = complete;
                                if image_complete {
                                    transfer_completed_us =
                                        unsafe { esp_idf_sys::esp_timer_get_time() as u64 };
                                }
                                Ok(if consumed == 0 {
                                    // CallbackStreams returns zero only for an
                                    // already delivered range. That is a real
                                    // reordering/retransmission exception.
                                    CommittedStreamDisposition::Reack
                                } else {
                                    // The bounded flash pool owns these bytes;
                                    // its post-ACK flush will return credit.
                                    CommittedStreamDisposition::Deferred
                                })
                            }
                            Err(()) => {
                                stream_error = true;
                                Err(quic_lite::Error::Invalid)
                            }
                        }
                    }
                },
            );
            let transport_info = match receive_result {
                Ok(value) => value,
                Err(error) => {
                    rejected_datagrams = rejected_datagrams.saturating_add(1);
                    let index = match error {
                        quic_lite::Error::BufferTooSmall => 0,
                        quic_lite::Error::Truncated => 1,
                        quic_lite::Error::Invalid => 2,
                        quic_lite::Error::InvalidVarint => 3,
                        quic_lite::Error::FlowControl => 4,
                        quic_lite::Error::StreamLimit => 5,
                        quic_lite::Error::PacketNumberExhausted => 6,
                        quic_lite::Error::WrongConnectionId => 7,
                        quic_lite::Error::BootstrapInvalid => 8,
                        quic_lite::Error::HistoryFull => 9,
                        quic_lite::Error::RetransmissionTooLarge => 10,
                    };
                    transport_errors[index] = transport_errors[index].saturating_add(1);
                    // Never log a packet-level error here. UART writes can block
                    // for roughly one scheduler tick and turn ordinary
                    // reordering into an artificial hundred-millisecond radio
                    // gap. The final numeric benchmark record reports this
                    // counter; non-benchmark transfers retain the concise error.
                    if !benchmark {
                        uart::send_response(if stream_error {
                            b"udp stream reassembly failed"
                        } else {
                            b"udp packet rejected"
                        });
                    }
                    break 'drain;
                }
            };
            if transport_info.duplicate {
                duplicate_datagrams = duplicate_datagrams.saturating_add(1);
            }
            if !transport_info.stream {
                control_datagrams = control_datagrams.saturating_add(1);
            }
            if image_complete || burst_datagrams >= UDP_RECEIVE_DRAIN_LIMIT {
                break 'drain;
            }
            peer_len = sockaddr_len();
            let next = unsafe {
                esp_idf_sys::lwip_recvfrom(
                    fd,
                    packet.as_mut_ptr().cast(),
                    packet.len(),
                    esp_idf_sys::MSG_DONTWAIT as i32,
                    (&mut peer as *mut esp_idf_sys::sockaddr_in).cast(),
                    &mut peer_len,
                )
            };
            if next <= 0 {
                break 'drain;
            }
            received = next as usize;
            received_path = 0;
        }
        receive_bursts = receive_bursts.saturating_add(1);
        receive_burst_max = receive_burst_max.max(burst_datagrams as u64);
        let mut transport_out = [0u8; UDP_MTU];
        if let Ok(Some(used)) = endpoint.poll_transmit(&mut transport_out) {
            if send_transport_datagram(
                &mut ingress,
                path_policy,
                false,
                fd,
                &server_peer,
                &transport_out[..used],
            ) {
                transport_datagrams = transport_datagrams.saturating_add(1);
                record_control_success(&mut outbound_control_timing);
            } else {
                transport_send_failures = transport_send_failures.saturating_add(1);
                transport_last_send_errno = send_errno();
            }
        }
        if let Some(flash) = flash.as_mut() {
            // Do not begin erase here.  A byte threshold reached at the end
            // of this drained burst does not prove the Wi-Fi/lwIP queues are
            // empty: later frames from the same host flight may already be
            // queued.  ESP flash erase pauses Wi-Fi, so starting it here
            // drops precisely those frames and strands the transfer before
            // it can return any storage credit.  The empty-socket branch
            // above is the application-safe boundary: transport has emitted
            // its ACK/control and the sender is flow-credit blocked.
            let released = match flash.flush_pending() {
                Ok(value) => value,
                Err(()) => {
                    uart::send_response(b"udp flash sink failed");
                    unsafe { esp_idf_sys::lwip_close(fd) };
                    return;
                }
            };
            if released != 0
                && endpoint
                    .stream_consumed_deferred(OBJECT_STREAM, released)
                    .is_err()
            {
                uart::send_response(b"udp stream credit failed");
                unsafe { esp_idf_sys::lwip_close(fd) };
                return;
            }
            if released != 0 {
                // The first poll ACKed the receive burst before SPI work.
                // Storage is now free, so give transport one immediate
                // scheduling opportunity to advertise its own MAX_* update;
                // Recovery neither encodes nor interprets that control data.
                let mut released_control = [0u8; UDP_MTU];
                if let Ok(Some(used)) = endpoint.poll_transmit(&mut released_control) {
                    if send_transport_datagram(
                        &mut ingress,
                        path_policy,
                        false,
                        fd,
                        &server_peer,
                        &released_control[..used],
                    ) {
                        transport_datagrams = transport_datagrams.saturating_add(1);
                        record_control_success(&mut outbound_control_timing);
                    } else {
                        transport_send_failures = transport_send_failures.saturating_add(1);
                        transport_last_send_errno = send_errno();
                    }
                }
            }
        }
        receive_bursts_since_yield = receive_bursts_since_yield.saturating_add(1);
        if receive_bursts_since_yield >= UDP_RECEIVE_YIELD_BURSTS {
            // One tick per drained burst is small compared with a per-packet
            // delay, while preventing a continuous full-rate stream from
            // starving the registered Idle task.
            unsafe { esp_idf_sys::vTaskDelay(1) };
            receive_bursts_since_yield = 0;
        }
        if image_complete {
            // The DONE record proves that every block has been checked, not
            // that the asynchronous flash worker has made those checked
            // bytes durable.  Keep Recovery alive until every retained slot
            // returns from the worker before handing Main to stage2.
            if !benchmark && !transport_test {
                let mut next_durable_log_us = unsafe { esp_idf_sys::esp_timer_get_time() as u64 };
                loop {
                    if flash
                        .as_mut()
                        .expect("flash receiver")
                        .start_erase_after_bootstrap()
                        .is_err()
                    {
                        uart::send_response(b"udp flash erase failed");
                        unsafe { esp_idf_sys::lwip_close(fd) };
                        return;
                    }
                    let released = match flash.as_mut().expect("flash receiver").flush_pending() {
                        Ok(value) => value,
                        Err(()) => {
                            uart::send_response(b"udp flash sink failed");
                            unsafe { esp_idf_sys::lwip_close(fd) };
                            return;
                        }
                    };
                    if released != 0 {
                        if endpoint
                            .stream_consumed_deferred(OBJECT_STREAM, released)
                            .is_err()
                        {
                            uart::send_response(b"udp stream credit failed");
                            unsafe { esp_idf_sys::lwip_close(fd) };
                            return;
                        }
                        let mut control = [0u8; UDP_MTU];
                        if let Ok(Some(used)) = endpoint.poll_transmit(&mut control) {
                            if send_transport_datagram(
                                &mut ingress,
                                path_policy,
                                false,
                                fd,
                                &server_peer,
                                &control[..used],
                            ) {
                                transport_datagrams = transport_datagrams.saturating_add(1);
                                record_control_success(&mut outbound_control_timing);
                            }
                        }
                    }
                    if flash.as_mut().expect("flash receiver").durable() {
                        break;
                    }
                    let now_us = unsafe { esp_idf_sys::esp_timer_get_time() as u64 };
                    if now_us >= next_durable_log_us {
                        // One compact counter per second is deliberately
                        // after the final stream frame. It diagnoses a stuck
                        // erase/write worker without perturbing radio or ACK
                        // scheduling during the transfer.
                        uart::send_stat(
                            b"udp durable jobs=",
                            flash.as_mut().expect("flash receiver").pending_flash_jobs(),
                        );
                        next_durable_log_us = now_us.saturating_add(1_000_000);
                    }
                    unsafe { esp_idf_sys::vTaskDelay(1) };
                }
            }
            uart::send_response(b"udp image complete");
            if benchmark {
                let (delivered_bytes, block_records) = if transport_test {
                    (iperf.bytes() as usize, 0)
                } else {
                    flash.as_ref().expect("flash receiver").benchmark_stats()
                };
                let elapsed_us = transfer_completed_us.saturating_sub(transfer_started_us);
                let bits_per_second = if elapsed_us == 0 {
                    0
                } else {
                    delivered_bytes as u64 * 8_000_000 / elapsed_us
                };
                let transport_stats = endpoint.stats();
                let iperf_errors = iperf.callback_errors();
                uart::send_benchmark_stats(&[
                    (0, rx_datagrams),
                    (1, rejected_datagrams),
                    (2, stream_datagrams),
                    (3, control_datagrams),
                    (4, transport_datagrams),
                    (5, request_retries),
                    (6, duplicate_datagrams),
                    (7, interpacket_count),
                    (8, interpacket_total_us),
                    (9, interpacket_max_us),
                    (10, delivered_bytes as u64),
                    (11, block_records as u64),
                    (12, transport_stats.received_datagrams),
                    (13, transport_stats.stream_datagrams),
                    (14, transport_stats.control_datagrams),
                    (15, transport_stats.duplicate_datagrams),
                    (16, transport_stats.out_of_order_datagrams),
                    (17, transport_stats.inferred_missing_packets),
                    (18, transport_stats.sent_datagrams),
                    (103, transport_stats.sent_stream_datagrams),
                    (104, transport_stats.sent_control_datagrams),
                    (19, transport_stats.retransmitted_datagrams),
                    (20, transport_stats.ack_datagrams),
                    (21, transport_stats.receive_interpacket_samples),
                    (22, transport_stats.receive_interpacket_total),
                    (23, transport_stats.receive_interpacket_min),
                    (24, transport_stats.ack_immediate_datagrams),
                    (25, transport_stats.ack_threshold_datagrams),
                    (26, transport_stats.ack_timer_datagrams),
                    // Transport-only result: 34 bytes, 35 elapsed us, 36
                    // bits/s. Host presentation must use kbps/Mbps.
                    (34, delivered_bytes as u64),
                    (35, elapsed_us),
                    (36, bits_per_second),
                    (39, iperf_validation as u64),
                    (40, iperf_errors[0]),
                    (41, iperf_errors[1]),
                    (42, iperf_errors[2]),
                    (43, iperf_errors[3]),
                    (44, iperf_errors[4]),
                    (45, iperf_errors[5]),
                    (46, transport_errors[0]),
                    (47, transport_errors[1]),
                    (48, transport_errors[2]),
                    (49, transport_errors[3]),
                    (50, transport_errors[4]),
                    (51, transport_errors[5]),
                    (52, transport_errors[6]),
                    (53, transport_errors[7]),
                    (54, transport_errors[8]),
                    (55, transport_errors[9]),
                    (56, transport_errors[10]),
                    (57, transport_send_failures),
                    (58, transport_last_send_errno as u64),
                    (59, benchmark_run_id as u64),
                    (107, iperf.normal_bytes()),
                    (108, iperf.high_bytes()),
                    (109, iperf.low_bytes()),
                    // Receiver credit snapshot: lets the host distinguish a
                    // sender congestion stall from a MAX_* update that was
                    // never emitted or accepted, without packet logging.
                    (60, endpoint.receive.connection.max_data),
                    (61, endpoint.receive.connection.consumed),
                    (
                        62,
                        endpoint.receive.stream_max_data(IPERF_STREAM).unwrap_or(0),
                    ),
                    (63, endpoint.receive.received_data),
                    (64, interpacket_gap_buckets[0]),
                    (65, interpacket_gap_buckets[1]),
                    (66, interpacket_gap_buckets[2]),
                    (67, interpacket_gap_buckets[3]),
                    (68, interpacket_gap_buckets[4]),
                    (69, interpacket_gap_buckets[5]),
                    (70, transport_stats.loss_packet_threshold_datagrams),
                    (71, transport_stats.loss_time_threshold_datagrams),
                    (72, transport_stats.loss_events),
                    (73, transport_stats.loss_retransmitted_datagrams),
                    (74, transport_stats.pto_retransmitted_datagrams),
                    (75, transport_stats.ack_frequency_received),
                    (76, transport_stats.ack_frequency_sent),
                    (77, endpoint.ack_frequency() as u64),
                    (78, endpoint.max_ack_delay_ms()),
                    (82, receive_bursts),
                    (83, receive_burst_max),
                    (88, outbound_control_timing.datagrams),
                    (89, outbound_control_timing.gaps),
                    (90, outbound_control_timing.total_gap_us),
                    (91, outbound_control_timing.max_gap_us),
                    (92, outbound_control_timing.gap_buckets[0]),
                    (93, outbound_control_timing.gap_buckets[1]),
                    (94, outbound_control_timing.gap_buckets[2]),
                    (95, outbound_control_timing.gap_buckets[3]),
                    (96, outbound_control_timing.gap_buckets[4]),
                    (97, outbound_control_timing.gap_buckets[5]),
                    // Empty-socket scheduling evidence: all empty returns,
                    // those which were immediate spins, and actual RTOS
                    // tick yields. These are bearer timing only; no ACK or
                    // packet detail leaks into Recovery's application path.
                    (98, empty_socket_returns),
                    (99, empty_socket_spins),
                    (100, empty_socket_yields),
                    (101, empty_socket_cooperative_yields),
                    // Actual wall time spent in the bounded full-tick path.
                    // This is deliberately aggregate-only telemetry.
                    (102, empty_socket_tick_yield_us),
                ]);
                uart::send_response(b"udp benchmark complete");
                // A benchmark worker owns one fresh transport association.
                // Tell the persistent host listener that this operation is
                // terminal before releasing the UDP socket; otherwise a
                // lost final ACK can leave PTO retransmissions running into
                // the next independent benchmark on the same AP.
                endpoint.close(0);
                let mut close = [0u8; UDP_MTU];
                if let Ok(Some(used)) = endpoint.poll_close(&mut close) {
                    let _ = send_transport_datagram(
                        &mut ingress,
                        path_policy,
                        false,
                        fd,
                        &server_peer,
                        &close[..used],
                    );
                }
                unsafe {
                    esp_idf_sys::lwip_close(fd);
                }
                return;
            } else {
                // Numeric timings let the host distinguish radio/transport
                // stalls from synchronous SPI flash work without adding a
                // packet-path UART log. Keys 84..86 are erase us, write us,
                // and successful write calls.
                let (erase_us, write_us, writes) =
                    flash.as_mut().expect("flash receiver").flash_stats();
                let (delivered_bytes, block_records) =
                    flash.as_ref().expect("flash receiver").benchmark_stats();
                // Production elapsed time runs through the final durable
                // flash completion, unlike dry mode which stops at the DONE
                // record.  This is the actual Recovery Wi-Fi flashing rate.
                let elapsed_us = (unsafe { esp_idf_sys::esp_timer_get_time() as u64 })
                    .saturating_sub(transfer_started_us);
                let bits_per_second = if elapsed_us == 0 {
                    0
                } else {
                    delivered_bytes as u64 * 8_000_000 / elapsed_us
                };
                let transport_stats = endpoint.stats();
                uart::send_benchmark_stats(&[
                    (7, interpacket_count),
                    (8, interpacket_total_us),
                    (9, interpacket_max_us),
                    (10, delivered_bytes as u64),
                    (11, block_records as u64),
                    (34, delivered_bytes as u64),
                    (35, elapsed_us),
                    (36, bits_per_second),
                    (12, transport_stats.received_datagrams),
                    (13, transport_stats.stream_datagrams),
                    (14, transport_stats.control_datagrams),
                    (15, transport_stats.duplicate_datagrams),
                    (16, transport_stats.out_of_order_datagrams),
                    (17, transport_stats.inferred_missing_packets),
                    (18, transport_stats.sent_datagrams),
                    (103, transport_stats.sent_stream_datagrams),
                    (104, transport_stats.sent_control_datagrams),
                    (19, transport_stats.retransmitted_datagrams),
                    (20, transport_stats.ack_datagrams),
                    (21, transport_stats.receive_interpacket_samples),
                    (22, transport_stats.receive_interpacket_total),
                    (23, transport_stats.receive_interpacket_min),
                    (24, transport_stats.ack_immediate_datagrams),
                    (25, transport_stats.ack_threshold_datagrams),
                    (26, transport_stats.ack_timer_datagrams),
                    (70, transport_stats.loss_packet_threshold_datagrams),
                    (71, transport_stats.loss_time_threshold_datagrams),
                    (72, transport_stats.loss_events),
                    (73, transport_stats.loss_retransmitted_datagrams),
                    (74, transport_stats.pto_retransmitted_datagrams),
                    (75, transport_stats.ack_frequency_received),
                    (76, transport_stats.ack_frequency_sent),
                    (77, endpoint.ack_frequency() as u64),
                    (78, endpoint.max_ack_delay_ms()),
                    (64, interpacket_gap_buckets[0]),
                    (65, interpacket_gap_buckets[1]),
                    (66, interpacket_gap_buckets[2]),
                    (67, interpacket_gap_buckets[3]),
                    (68, interpacket_gap_buckets[4]),
                    (69, interpacket_gap_buckets[5]),
                    (82, receive_bursts),
                    (83, receive_burst_max),
                    // Opaque outbound control timing, after successful
                    // sendto only. This is not ACK interpretation.
                    (88, outbound_control_timing.datagrams),
                    (89, outbound_control_timing.gaps),
                    (90, outbound_control_timing.total_gap_us),
                    (91, outbound_control_timing.max_gap_us),
                    (92, outbound_control_timing.gap_buckets[0]),
                    (93, outbound_control_timing.gap_buckets[1]),
                    (94, outbound_control_timing.gap_buckets[2]),
                    (95, outbound_control_timing.gap_buckets[3]),
                    (96, outbound_control_timing.gap_buckets[4]),
                    (97, outbound_control_timing.gap_buckets[5]),
                    // Retain the same credit snapshot on a production
                    // timeout as on a dry run. A partial real-write report
                    // must say whether the sender stopped on receiver
                    // credit, rather than forcing a UART packet trace.
                    (60, endpoint.receive.connection.max_data),
                    (61, endpoint.receive.connection.consumed),
                    (
                        62,
                        endpoint.receive.stream_max_data(OBJECT_STREAM).unwrap_or(0),
                    ),
                    (63, endpoint.receive.received_data),
                    (84, erase_us),
                    (85, write_us),
                    (86, writes),
                    // Explicitly distinguish this durable, verified image
                    // completion from the structurally similar timeout
                    // diagnostic emitted below.
                    (87, 1),
                ]);
                // Only dry/diagnostic runs are reusable. A real image is now
                // durable and every block has matched the authenticated
                // manifest, so hand Stage2 back to Main after its concise
                // completion telemetry has reached the UART/UDP log queues.
                if !complete_main_flash() {
                    // Do not reset into forced Recovery and falsely claim a
                    // Main handoff. The durable image remains available for
                    // a later retry of this final policy commit.
                    uart::send_response(b"udp main target failed");
                    unsafe { esp_idf_sys::lwip_close(fd) };
                    return;
                }
                // Recovery's callback restarts after committing its handoff.
                // A shared runtime cannot assume that policy for Main.
                uart::send_response(b"udp main completion requested");
            }
        }
        // recvfrom() is already blocking with a bounded timeout. Sleeping
        // here adds one RTOS tick after every datagram (about 10 ms on this
        // target), turning a windowed transfer into an accidental paced
        // sender. Let the next socket call provide the wait/yield instead.
    }
    // A production timeout is exactly when the transport counters matter
    // most.  It must expose the same compact, aggregate evidence as a dry
    // run: packet loss/reordering, ACK policy, receive bursts, and durable
    // flash work.  This runs only after the socket loop has ended, never on
    // the packet path, so it cannot manufacture the gap it reports.
    if !benchmark {
        let transport_stats = endpoint.stats();
        let (erase_us, write_us, writes) = flash
            .as_mut()
            .map(FlashHandler::flash_stats)
            .unwrap_or((0, 0, 0));
        uart::send_benchmark_stats(&[
            (0, rx_datagrams),
            (1, rejected_datagrams),
            (2, stream_datagrams),
            (3, control_datagrams),
            (4, transport_datagrams),
            (5, request_retries),
            (6, duplicate_datagrams),
            (7, interpacket_count),
            (8, interpacket_total_us),
            (9, interpacket_max_us),
            (12, transport_stats.received_datagrams),
            (13, transport_stats.stream_datagrams),
            (14, transport_stats.control_datagrams),
            (15, transport_stats.duplicate_datagrams),
            (16, transport_stats.out_of_order_datagrams),
            (17, transport_stats.inferred_missing_packets),
            (18, transport_stats.sent_datagrams),
            (103, transport_stats.sent_stream_datagrams),
            (104, transport_stats.sent_control_datagrams),
            (19, transport_stats.retransmitted_datagrams),
            (20, transport_stats.ack_datagrams),
            (24, transport_stats.ack_immediate_datagrams),
            (25, transport_stats.ack_threshold_datagrams),
            (26, transport_stats.ack_timer_datagrams),
            (64, interpacket_gap_buckets[0]),
            (65, interpacket_gap_buckets[1]),
            (66, interpacket_gap_buckets[2]),
            (67, interpacket_gap_buckets[3]),
            (68, interpacket_gap_buckets[4]),
            (69, interpacket_gap_buckets[5]),
            (70, transport_stats.loss_packet_threshold_datagrams),
            (71, transport_stats.loss_time_threshold_datagrams),
            (72, transport_stats.loss_events),
            (73, transport_stats.loss_retransmitted_datagrams),
            (74, transport_stats.pto_retransmitted_datagrams),
            (75, transport_stats.ack_frequency_received),
            (76, transport_stats.ack_frequency_sent),
            (77, endpoint.ack_frequency() as u64),
            (78, endpoint.max_ack_delay_ms()),
            (82, receive_bursts),
            (83, receive_burst_max),
            (88, outbound_control_timing.datagrams),
            (89, outbound_control_timing.gaps),
            (90, outbound_control_timing.total_gap_us),
            (91, outbound_control_timing.max_gap_us),
            (92, outbound_control_timing.gap_buckets[0]),
            (93, outbound_control_timing.gap_buckets[1]),
            (94, outbound_control_timing.gap_buckets[2]),
            (95, outbound_control_timing.gap_buckets[3]),
            (96, outbound_control_timing.gap_buckets[4]),
            (97, outbound_control_timing.gap_buckets[5]),
            (84, erase_us),
            (85, write_us),
            (86, writes),
        ]);
    }
    if benchmark {
        let (delivered_bytes, block_records) = if transport_test {
            (iperf.bytes() as usize, 0)
        } else {
            flash.as_ref().expect("flash receiver").benchmark_stats()
        };
        let elapsed_us = if transfer_started_us != 0 {
            (unsafe { esp_idf_sys::esp_timer_get_time() as u64 })
                .saturating_sub(transfer_started_us)
        } else {
            0
        };
        let bits_per_second = if elapsed_us == 0 {
            0
        } else {
            delivered_bytes as u64 * 8_000_000 / elapsed_us
        };
        let transport_stats = endpoint.stats();
        uart::send_benchmark_stats(&[
            (0, rx_datagrams),
            (1, rejected_datagrams),
            (2, stream_datagrams),
            (3, control_datagrams),
            (4, transport_datagrams),
            (5, request_retries),
            (6, duplicate_datagrams),
            (7, interpacket_count),
            (8, interpacket_total_us),
            (9, interpacket_max_us),
            (10, delivered_bytes as u64),
            (11, block_records as u64),
            (12, transport_stats.received_datagrams),
            (13, transport_stats.stream_datagrams),
            (14, transport_stats.control_datagrams),
            (15, transport_stats.duplicate_datagrams),
            (16, transport_stats.out_of_order_datagrams),
            (17, transport_stats.inferred_missing_packets),
            (18, transport_stats.sent_datagrams),
            (103, transport_stats.sent_stream_datagrams),
            (104, transport_stats.sent_control_datagrams),
            (19, transport_stats.retransmitted_datagrams),
            (20, transport_stats.ack_datagrams),
            (21, transport_stats.receive_interpacket_samples),
            (22, transport_stats.receive_interpacket_total),
            (23, transport_stats.receive_interpacket_min),
            (24, transport_stats.ack_immediate_datagrams),
            (25, transport_stats.ack_threshold_datagrams),
            (26, transport_stats.ack_timer_datagrams),
            (34, delivered_bytes as u64),
            (35, elapsed_us),
            (36, bits_per_second),
            (57, transport_send_failures),
            (58, transport_last_send_errno as u64),
            (59, benchmark_run_id as u64),
            (107, iperf.normal_bytes()),
            (108, iperf.high_bytes()),
            (109, iperf.low_bytes()),
            (60, endpoint.receive.connection.max_data),
            (61, endpoint.receive.connection.consumed),
            (
                62,
                endpoint.receive.stream_max_data(IPERF_STREAM).unwrap_or(0),
            ),
            (63, endpoint.receive.received_data),
            (64, interpacket_gap_buckets[0]),
            (65, interpacket_gap_buckets[1]),
            (66, interpacket_gap_buckets[2]),
            (67, interpacket_gap_buckets[3]),
            (68, interpacket_gap_buckets[4]),
            (69, interpacket_gap_buckets[5]),
            (70, transport_stats.loss_packet_threshold_datagrams),
            (71, transport_stats.loss_time_threshold_datagrams),
            (72, transport_stats.loss_events),
            (73, transport_stats.loss_retransmitted_datagrams),
            (74, transport_stats.pto_retransmitted_datagrams),
            (75, transport_stats.ack_frequency_received),
            (76, transport_stats.ack_frequency_sent),
            (77, endpoint.ack_frequency() as u64),
            (78, endpoint.max_ack_delay_ms()),
            (82, receive_bursts),
            (83, receive_burst_max),
            (88, outbound_control_timing.datagrams),
            (89, outbound_control_timing.gaps),
            (90, outbound_control_timing.total_gap_us),
            (91, outbound_control_timing.max_gap_us),
            (92, outbound_control_timing.gap_buckets[0]),
            (93, outbound_control_timing.gap_buckets[1]),
            (94, outbound_control_timing.gap_buckets[2]),
            (95, outbound_control_timing.gap_buckets[3]),
            (96, outbound_control_timing.gap_buckets[4]),
            (97, outbound_control_timing.gap_buckets[5]),
        ]);
    }
    uart::send_response(b"udp timeout");
    unsafe {
        esp_idf_sys::lwip_close(fd);
    }
}

fn recovery_connection_id(run_id: u32, random: u32) -> Option<ConnectionId> {
    let nonce = if run_id == 0 { random } else { run_id };
    ConnectionId::new(RECOVERY_CONNECTION_CID_PREFIX | u64::from(nonce))
}

#[cfg(test)]
mod tests {
    use super::{ConnectionId, RecoveryEndpoint, Role, StreamFrame, IPERF_STREAM};
    use quic_lite::{
        interpacket_gap_bucket, ConnectionLimits, DatagramTiming, Frame, ShortHeader, FLAG_FIXED,
    };

    #[test]
    fn interpacket_gap_buckets_cover_boundaries() {
        assert_eq!(interpacket_gap_bucket(0), 0);
        assert_eq!(interpacket_gap_bucket(999), 0);
        assert_eq!(interpacket_gap_bucket(1_000), 1);
        assert_eq!(interpacket_gap_bucket(4_999), 1);
        assert_eq!(interpacket_gap_bucket(5_000), 2);
        assert_eq!(interpacket_gap_bucket(10_000), 3);
        assert_eq!(interpacket_gap_bucket(25_000), 4);
        assert_eq!(interpacket_gap_bucket(50_000), 5);
    }

    #[test]
    fn immediate_empty_bearer_returns_only_need_a_bounded_tick_yield() {
        assert!(!quic_lite::bearer_poll_should_yield(
            true, 0, 8, 100_000, 8, 100_000
        ));
        assert!(!quic_lite::bearer_poll_should_yield(
            false, 0, 7, 100_000, 8, 100_000
        ));
        assert!(!quic_lite::bearer_poll_should_yield(
            false, 0, 8, 99_999, 8, 100_000
        ));
        assert!(quic_lite::bearer_poll_should_yield(
            false, 0, 8, 100_000, 8, 100_000
        ));
        assert!(!quic_lite::bearer_poll_should_yield(
            false, 1_000, 8, 100_000, 8, 100_000
        ));
    }

    #[test]
    fn outbound_control_timing_is_opaque_and_aggregate() {
        let mut timing = DatagramTiming::default();
        timing.record_at(1_000);
        timing.record_at(1_500);
        timing.record_at(11_500);
        assert_eq!(timing.datagrams, 3);
        assert_eq!(timing.gaps, 2);
        assert_eq!(timing.total_gap_us, 10_500);
        assert_eq!(timing.max_gap_us, 10_000);
        assert_eq!(timing.gap_buckets, [1, 0, 0, 1, 0, 0]);
    }

    #[test]
    fn transport_iperf_credit_uses_the_diagnostic_packet_budget_only() {
        let flash = quic_lite::recovery_connection_limits(false, 64);
        let iperf_default = quic_lite::recovery_connection_limits(true, 0);
        let iperf_24 = quic_lite::recovery_connection_limits(true, 24);
        let iperf_64 = quic_lite::recovery_connection_limits(true, 64);
        assert_eq!(flash.max_data, quic_lite::RECOVERY_INITIAL_MAX_DATA);
        assert_eq!(flash.max_stream_data, quic_lite::RECOVERY_INITIAL_MAX_DATA);
        assert_eq!(
            iperf_default.max_data,
            u64::from(quic_lite::RECOVERY_MAX_IN_FLIGHT_PACKETS) * 1200
        );
        assert_eq!(iperf_24.max_data, 24 * 1200);
        assert_eq!(iperf_64.max_stream_data, 64 * 1200);
        assert!(iperf_64.max_data > flash.max_data);
    }

    #[test]
    fn delayed_bootstrap_ack_sets_the_host_packet_number_frontier() {
        let client = ConnectionId::new(0x41).unwrap();
        let server = ConnectionId::new(0x42).unwrap();
        let limits = ConnectionLimits {
            max_data: 64 * 1200,
            max_stream_data: 64 * 1200,
            ..ConnectionLimits::default()
        };
        let mut bootstrap_ack = [0u8; 128];
        let ack_len = quic_lite::encode_bootstrap_open_ack_packet_with_limits(
            client,
            server,
            98,
            limits,
            &mut bootstrap_ack,
        )
        .unwrap();
        let (header, ack) = quic_lite::decode_bootstrap_open_ack_packet_with_limits(
            &bootstrap_ack[..ack_len],
            client,
        )
        .unwrap();
        assert_eq!(header.packet_number, 98);

        let mut endpoint = RecoveryEndpoint::<2>::new(Role::Client, limits, 1400);
        endpoint
            .set_initial_peer_budget(ack.max_data, ack.max_stream_data, ack.max_in_flight_packets)
            .unwrap();
        endpoint.observe_packet(header.packet_number);
        endpoint.install_connection_ids(client, server).unwrap();

        let mut stream_packet = [0u8; 128];
        let stream_header = ShortHeader {
            flags: FLAG_FIXED,
            dcid: client,
            packet_number: 99,
            packet_number_len: 1,
        }
        .encode(&mut stream_packet)
        .unwrap();
        let stream_len = Frame::Stream(StreamFrame {
            id: IPERF_STREAM,
            offset: 0,
            fin: false,
            data: b"ok",
        })
        .encode(&mut stream_packet[stream_header..])
        .unwrap();
        endpoint
            .receive_datagram(&stream_packet[..stream_header + stream_len])
            .unwrap();
        assert_eq!(endpoint.stats().inferred_missing_packets, 0);
    }
}
