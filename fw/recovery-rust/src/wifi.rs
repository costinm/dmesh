//! Recovery Wi-Fi STA setup and UDP transport adapter.
//!
//! This module owns all bearer concerns: static STA configuration, sockets,
//! bootstrap, datagram receive/send, and dmesh-transport scheduling. The
//! flashing module sees only ordered application stream callbacks.

use crate::{uart, udp_flash::{FlashHandler, OBJECT_STREAM}};
use alloc::{sync::Arc, vec::Vec};
use core::{
    ffi::{c_int, c_void},
    sync::atomic::{AtomicBool, AtomicI32, AtomicPtr, AtomicU32, Ordering},
};
use dmesh_object_store::protocol::encode_get;
use dmesh_transport::callback::{
    CallbackError, CallbackStreams, CopyingError, CopyingStreamEvents,
};
use dmesh_transport::{
    BootstrapOpen, BootstrapOpenAck, CommittedStreamDisposition, ConnectionId, ConnectionLimits, Frame, RecoveryEndpoint, Role,
    ShortHeader, StreamFrame, FLAG_FIXED,
};

const UDP_MTU: usize = 1400;
// The socket queue is part of the receiver budget, not merely an incidental
// lwIP tuning knob. A command may advertise the 64-packet diagnostic window;
// accepting that flight with only the former 40-datagram queue lets ordinary
// burst delivery drop packets before dmesh-transport can ACK or reorder them.
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
// Reordering still triggers an immediate ACK inside dmesh-transport.
// Recovery and the host object service use this LAN profile from bootstrap.
// ACK_FREQUENCY may refine it later, but a lost one-shot control frame must
// not silently fall back to ACK-every-two and collapse a 32-packet flight.
const DEFAULT_ACK_FREQUENCY: u8 = 8;
const RECOVERY_MAX_ACK_DELAY_MS: u64 = 5;
const BOOTSTRAP_RETRY_MS: u64 = 500;
const RECOVERY_CONNECTION_CID_PREFIX: u64 = 1 << 32;
const SERVICE_OBJECT: u8 = dmesh_transport::SERVICE_OBJECT;
const REQUEST_STREAM: u64 = dmesh_transport::FIRST_CLIENT_BIDI_STREAM_ID;
const IPERF_STREAM: u64 = dmesh_transport::FIRST_SERVER_BIDI_STREAM_ID;
const INITIAL_MAX_STREAM_DATA: u64 = dmesh_transport::INITIAL_MAX_STREAM_DATA;
/// Host-driven raw Wi-Fi/lwIP diagnostics. This intentionally differs from
/// the host listener and transport port, so it cannot consume object traffic.
const RAW_UDP_ENDPOINT_PORT: u16 = 3337;
const RAW_UDP_LOG_PORT: u16 = 3338;
const TRANSPORT_UDP_PORT: u16 = 3339;
const RAW_UDP_FLOOD_BYTES: usize = 2 * 1024 * 1024;
const RAW_UDP_FLOOD_PAYLOAD: usize = 1200;
const RAW_UDP_SEND_BURST: u32 = 16;
// A raw command acknowledgement can be lost, but an identical benchmark is
// also a valid later request.  Deduplicate only the retry window; retaining a
// command forever turned every subsequent identical request into a no-op.
const RAW_UDP_COMMAND_DEDUP_MS: u64 = 1_000;
const UDP_TELEMETRY_REPETITIONS: usize = 3;
// Command/start/final telemetry can briefly overlap while the raw endpoint
// is blocked in recvfrom. Twelve MTU-sized records (~17 KiB) preserves a
// complete benchmark result plus status wakes without creating an unbounded
// log buffer.
const UDP_LOG_QUEUE_DEPTH: usize = 12;
// Compact transport-benchmark receive-gap buckets, in microseconds. Keeping
// these numeric lets the host distinguish a steady radio cadence from a
// scheduler timeout without packet-level UART/UDP logging in the hot path.
const INTERPACKET_GAP_BUCKETS: usize = 6;
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

struct IperfSink<'a> {
    validation: u8,
    bytes: &'a mut u64,
    next_offset: &'a mut u64,
    next_packet_id: &'a mut u32,
    complete: &'a mut bool,
}

impl CopyingStreamEvents for IperfSink<'_> {
    type Error = ();

    fn stream_chunk(
        &mut self,
        _stream: u64,
        offset: u64,
        end: bool,
        bytes: &[u8],
    ) -> Result<(), ()> {
        if self.validation >= 1 {
            let packet_id = bytes
                .get(..4)
                .and_then(|id| id.try_into().ok())
                .map(u32::from_be_bytes);
            if offset != *self.next_offset || packet_id != Some(*self.next_packet_id) {
                return Err(());
            }
            if self.validation >= 2
                && bytes[4..]
                    .iter()
                    .enumerate()
                    .any(|(i, byte)| *byte != self.next_offset.wrapping_add(4 + i as u64) as u8)
            {
                return Err(());
            }
            *self.next_packet_id = self.next_packet_id.wrapping_add(1);
        }
        *self.next_offset = self.next_offset.saturating_add(bytes.len() as u64);
        *self.bytes = self.bytes.saturating_add(bytes.len() as u64);
        *self.complete = end;
        Ok(())
    }
}

struct IperfHandler {
    ordered: CallbackStreams<Arc<Vec<u8>>>,
    validation: u8,
    bytes: u64,
    next_offset: u64,
    next_packet_id: u32,
    callback_errors: [u64; 6],
}

impl IperfHandler {
    fn new(validation: u8) -> Self {
        Self {
            ordered: CallbackStreams::new(1, dmesh_transport::RECOVERY_REORDER_CAPACITY_BYTES),
            validation,
            bytes: 0,
            next_offset: 0,
            next_packet_id: 0,
            callback_errors: [0; 6],
        }
    }

    fn handle(&mut self, stream: StreamFrame<'_>) -> Result<(bool, usize), ()> {
        let mut complete = false;
        let before = self.bytes;
        let mut sink = IperfSink {
            validation: self.validation,
            bytes: &mut self.bytes,
            next_offset: &mut self.next_offset,
            next_packet_id: &mut self.next_packet_id,
            complete: &mut complete,
        };
        if let Err(error) = self.ordered.receive_copying_borrowed(
            stream.id,
            stream.data,
            stream.offset,
            stream.fin,
            || Arc::new(stream.data.to_vec()),
            &mut sink,
        ) {
            let index = match error {
                CopyingError::Transport(CallbackError::InvalidOverlap) => 0,
                CopyingError::Transport(CallbackError::InvalidFin) => 1,
                CopyingError::Transport(CallbackError::InvalidCompletion) => 2,
                CopyingError::Transport(CallbackError::Capacity) => 3,
                CopyingError::Transport(CallbackError::Reset) => 4,
                CopyingError::Callback(()) => 5,
            };
            self.callback_errors[index] = self.callback_errors[index].saturating_add(1);
            return Err(());
        }
        Ok((complete, self.bytes.saturating_sub(before) as usize))
    }
}
static RAW_UDP_ENDPOINT_STARTED: AtomicBool = AtomicBool::new(false);
static RAW_UDP_V6_ENDPOINT_STARTED: AtomicBool = AtomicBool::new(false);
static STA_RECONNECT_TASK_STARTED: AtomicBool = AtomicBool::new(false);
static UDP_LOG_FD: AtomicI32 = AtomicI32::new(-1);
static UDP_LOG_HOST: AtomicU32 = AtomicU32::new(0);
static UDP_LOG_QUEUE: AtomicPtr<c_void> = AtomicPtr::new(core::ptr::null_mut());
static UDP_LOG_QUEUED: AtomicU32 = AtomicU32::new(0);
static UDP_LOG_DROPPED: AtomicU32 = AtomicU32::new(0);
static UDP_LOG_SENT: AtomicU32 = AtomicU32::new(0);

#[repr(C)]
struct UdpLogRecord {
    len: u16,
    bytes: [u8; UDP_MTU - 1],
}

fn interpacket_gap_bucket(delta_us: u64) -> usize {
    match delta_us {
        0..=999 => 0,
        1_000..=4_999 => 1,
        5_000..=9_999 => 2,
        10_000..=24_999 => 3,
        25_000..=49_999 => 4,
        _ => 5,
    }
}

/// An empty bearer poll that produced transport-owned control must immediately
/// return to `recvfrom`. Sleeping here delays the peer's refill after a
/// delayed ACK/MAX update by a whole FreeRTOS tick. A real bounded socket
/// timeout has already yielded CPU to Wi-Fi and Idle; only an immediate
/// EWOULDBLOCK-style return needs the extra spin-prevention tick.
#[inline]
fn bearer_timeout_should_yield(
    emitted_control: bool,
    receive_wait_us: u64,
    consecutive_empty_spins: u64,
    since_full_yield_us: u64,
) -> bool {
    !emitted_control
        && receive_wait_us < 1_000
        && consecutive_empty_spins >= EMPTY_SOCKET_TICK_YIELD_SPINS
        && since_full_yield_us >= EMPTY_SOCKET_MAX_UNYIELDED_US
}

fn recovery_receive_limits(transport_test: bool, requested_packets: u8) -> ConnectionLimits {
    let max_data = if transport_test {
        // Transport IPERF has no object decoder or flash slots. Match its
        // byte credit to the request-scoped packet budget so a 24-packet
        // diagnostic does not secretly retain a 64-packet flight. Zero uses
        // Recovery's normal 32-packet profile; production flashing stays at
        // RECOVERY_INITIAL_MAX_DATA regardless of this test-only setting.
        let packets = if requested_packets == 0 {
            dmesh_transport::RECOVERY_MAX_IN_FLIGHT_PACKETS
        } else {
            u16::from(requested_packets)
                .min(dmesh_transport::RECOVERY_MAX_DIAGNOSTIC_IN_FLIGHT_PACKETS)
        };
        u64::from(packets) * 1200
    } else {
        dmesh_transport::RECOVERY_INITIAL_MAX_DATA
    };
    ConnectionLimits {
        max_data,
        max_stream_data: max_data,
        ..ConnectionLimits::default()
    }
}

/// Aggregate bearer-side control-send timing. The transport owns the encoded
/// control contents; Recovery records only successful opaque datagrams so a
/// benchmark can distinguish a late local send from a late peer refill.
#[derive(Default)]
struct OutboundControlTiming {
    datagrams: u64,
    gaps: u64,
    total_gap_us: u64,
    max_gap_us: u64,
    gap_buckets: [u64; INTERPACKET_GAP_BUCKETS],
    last_sent_us: Option<u64>,
}

impl OutboundControlTiming {
    fn record_success(&mut self) {
        self.record_at(unsafe { esp_idf_sys::esp_timer_get_time() as u64 });
    }

    fn record_at(&mut self, now: u64) {
        if let Some(previous) = self.last_sent_us {
            let gap = now.saturating_sub(previous);
            self.gaps = self.gaps.saturating_add(1);
            self.total_gap_us = self.total_gap_us.saturating_add(gap);
            self.max_gap_us = self.max_gap_us.max(gap);
            let bucket = interpacket_gap_bucket(gap);
            self.gap_buckets[bucket] = self.gap_buckets[bucket].saturating_add(1);
        }
        self.last_sent_us = Some(now);
        self.datagrams = self.datagrams.saturating_add(1);
    }
}

pub(crate) fn parse_ipv4(bytes: &[u8]) -> Option<u32> {
    let mut octets = [0u8; 4];
    let mut part = 0usize;
    let mut number = 0u16;
    for byte in bytes.iter().copied().chain(core::iter::once(b'.')) {
        if byte == b'.' {
            if part >= 4 || number > 255 {
                return None;
            }
            octets[part] = number as u8;
            part += 1;
            number = 0;
        } else if byte.is_ascii_digit() {
            number = number.checked_mul(10)?.checked_add((byte - b'0') as u16)?;
        } else {
            return None;
        }
    }
    (part == 4).then(|| u32::from_ne_bytes(octets))
}

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

pub(crate) fn init_sta(params: &uart::RecoveryParams) {
    unsafe {
        if !params.has_flash_profile() {
            uart::send_response(b"recovery profile missing");
            return;
        }
        uart::send_response(b"wifi init begin");
        let _ = esp_idf_sys::esp_netif_init();
        let _ = esp_idf_sys::esp_event_loop_create_default();
        let netif = esp_idf_sys::esp_netif_create_default_wifi_sta();
        if netif.is_null() {
            uart::send_response(b"wifi netif failed");
            return;
        }
        uart::send_response(b"wifi netif ready");
        let mut init = wifi_init_config_default();
        if esp_idf_sys::esp_wifi_init(&mut init) != esp_idf_sys::ESP_OK {
            uart::send_response(b"wifi driver init failed");
            return;
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
        if esp_idf_sys::esp_wifi_start() != esp_idf_sys::ESP_OK {
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

fn send_errno() -> i32 {
    unsafe { *__errno() }
}

/// Wi-Fi adapter for Recovery's common compact UART log record. The host
/// test server receives one-byte tag 0x71 followed by the unchanged CBOR.
fn udp_log_record(record: &[u8]) {
    let queue = UDP_LOG_QUEUE.load(Ordering::Acquire).cast::<esp_idf_sys::QueueDefinition>();
    if queue.is_null() || record.len() > UDP_MTU - 1 {
        UDP_LOG_DROPPED.fetch_add(1, Ordering::Relaxed);
        return;
    }
    let mut queued = UdpLogRecord { len: record.len() as u16, bytes: [0; UDP_MTU - 1] };
    queued.bytes[..record.len()].copy_from_slice(record);
    if unsafe { esp_idf_sys::xQueueGenericSend(queue, (&queued as *const UdpLogRecord).cast(), 0, 0) } == 1 {
        UDP_LOG_QUEUED.fetch_add(1, Ordering::Relaxed);
    } else {
        UDP_LOG_DROPPED.fetch_add(1, Ordering::Relaxed);
    }
}

fn udp_log_drain(fd: c_int) {
    let queue = UDP_LOG_QUEUE.load(Ordering::Acquire).cast::<esp_idf_sys::QueueDefinition>();
    let host = UDP_LOG_HOST.load(Ordering::Acquire);
    if queue.is_null() || host == 0 { return; }
    loop {
        let mut queued = UdpLogRecord { len: 0, bytes: [0; UDP_MTU - 1] };
        if unsafe { esp_idf_sys::xQueueReceive(queue, (&mut queued as *mut UdpLogRecord).cast(), 0) } != 1 { return; }
        let len = (queued.len as usize).min(queued.bytes.len());
        let peer = esp_idf_sys::sockaddr_in { sin_len: core::mem::size_of::<esp_idf_sys::sockaddr_in>() as u8, sin_family: esp_idf_sys::AF_INET as u8, sin_port: RAW_UDP_LOG_PORT.to_be(), sin_addr: esp_idf_sys::in_addr { s_addr: host }, sin_zero: [0; 8] };
        let mut packet = [0u8; UDP_MTU];
        packet[0] = 0x71;
        packet[1..1 + len].copy_from_slice(&queued.bytes[..len]);
        for _ in 0..UDP_TELEMETRY_REPETITIONS { let _ = send_packet(fd, &peer, &packet[..1 + len]); unsafe { esp_idf_sys::vTaskDelay(10) }; }
        UDP_LOG_SENT.fetch_add(1, Ordering::Relaxed);
    }
}

fn udp_boot_beacon() {
    let fd = UDP_LOG_FD.load(Ordering::Acquire);
    let host = UDP_LOG_HOST.load(Ordering::Acquire);
    if fd < 0 || host == 0 {
        return;
    }
    let peer = esp_idf_sys::sockaddr_in {
        sin_len: core::mem::size_of::<esp_idf_sys::sockaddr_in>() as u8,
        sin_family: esp_idf_sys::AF_INET as u8,
        sin_port: RAW_UDP_LOG_PORT.to_be(),
        sin_addr: esp_idf_sys::in_addr { s_addr: host },
        sin_zero: [0; 8],
    };
    for _ in 0..UDP_TELEMETRY_REPETITIONS {
        let _ = send_packet(fd, &peer, &[0x70, 1]);
        unsafe {
            esp_idf_sys::vTaskDelay(10);
        }
    }
}

/// Start the host-driven raw Wi-Fi endpoint once Recovery has associated.
/// It is a diagnostic server only: it has no object-store, flash, ACK, or
/// dmesh-transport state. Commands are single numeric bytes:
/// `1` status reply, `2` device-to-host flood, `3` begin host-to-device
/// flood, followed by `0x85` to return its counters.
pub(crate) fn start_raw_udp_endpoint(params: *mut uart::RecoveryParams) {
    if RAW_UDP_ENDPOINT_STARTED.swap(true, Ordering::AcqRel) {
        return;
    }
    let mut task = core::ptr::null_mut();
    let result = unsafe {
        esp_idf_sys::xTaskCreatePinnedToCore(
            // The task has a 1400-byte receive buffer and may synchronously
            // enter a 1205-byte flood generator.  Four KiB overflows once
            // normal lwIP/CBOR call frames are included.
            Some(raw_udp_endpoint_task),
            b"raw_udp\0".as_ptr().cast(),
            8192,
            params.cast::<c_void>(),
            // Match the command task's priority.  At priority four the raw
            // receiver could leave its lwIP queue full even with a modest
            // 5 ms host cadence, making this diagnostic measure scheduler
            // starvation rather than Wi-Fi. It remains below Wi-Fi internals
            // and performs no UART work in its packet path.
            5,
            &mut task,
            0,
        )
    };
    if result != 1 || task.is_null() {
        RAW_UDP_ENDPOINT_STARTED.store(false, Ordering::Release);
        uart::send_response(b"raw UDP endpoint failed");
    } else {
        uart::send_response(b"raw UDP endpoint started");
    }
    // Keep IPv6 deliberately small: it is an independent link-local status
    // probe for the AP/device path, not a second diagnostic or transport
    // protocol.  The normal raw IPERF endpoint remains IPv4-only.
    if !RAW_UDP_V6_ENDPOINT_STARTED.swap(true, Ordering::AcqRel) {
        let mut task = core::ptr::null_mut();
        let result = unsafe {
            esp_idf_sys::xTaskCreatePinnedToCore(
                Some(raw_udp_v6_status_task),
                b"raw_udp6\0".as_ptr().cast(),
                4096,
                core::ptr::null_mut(),
                4,
                &mut task,
                0,
            )
        };
        if result != 1 || task.is_null() {
            RAW_UDP_V6_ENDPOINT_STARTED.store(false, Ordering::Release);
            uart::send_response(b"raw UDP IPv6 endpoint failed");
        } else {
            uart::send_response(b"raw UDP IPv6 endpoint started");
        }
    }
}

unsafe extern "C" fn raw_udp_v6_status_task(_argument: *mut c_void) {
    let fd = esp_idf_sys::lwip_socket(
        esp_idf_sys::AF_INET6 as c_int,
        esp_idf_sys::SOCK_DGRAM as c_int,
        esp_idf_sys::IPPROTO_UDP as c_int,
    );
    if fd < 0 {
        uart::send_response(b"raw UDP IPv6 socket failed");
        RAW_UDP_V6_ENDPOINT_STARTED.store(false, Ordering::Release);
        esp_idf_sys::vTaskDelete(core::ptr::null_mut());
        return;
    }
    // Keep the same fixed port available in both families. Without this,
    // lwIP treats the IPv6 socket as dual-stack and rejects it because the
    // IPv4 :3337 endpoint already exists.
    let v6_only: c_int = 1;
    let _ = esp_idf_sys::lwip_setsockopt(
        fd,
        esp_idf_sys::IPPROTO_IPV6 as c_int,
        esp_idf_sys::IPV6_V6ONLY as c_int,
        (&v6_only as *const c_int).cast(),
        core::mem::size_of_val(&v6_only) as _,
    );
    let local = esp_idf_sys::sockaddr_in6 {
        sin6_len: core::mem::size_of::<esp_idf_sys::sockaddr_in6>() as u8,
        sin6_family: esp_idf_sys::AF_INET6 as u8,
        sin6_port: RAW_UDP_ENDPOINT_PORT.to_be(),
        sin6_flowinfo: 0,
        sin6_addr: esp_idf_sys::in6_addr::default(),
        sin6_scope_id: 0,
    };
    if esp_idf_sys::lwip_bind(
        fd,
        (&local as *const esp_idf_sys::sockaddr_in6).cast(),
        core::mem::size_of::<esp_idf_sys::sockaddr_in6>() as _,
    ) < 0
    {
        uart::send_response(b"raw UDP IPv6 bind failed");
        esp_idf_sys::lwip_close(fd);
        RAW_UDP_V6_ENDPOINT_STARTED.store(false, Ordering::Release);
        // A FreeRTOS task entry may not return: doing so jumps through a null
        // task-return address and rebooted e6 with an instruction-access
        // fault.  This is an error exit, not a normal task completion.
        esp_idf_sys::vTaskDelete(core::ptr::null_mut());
        return;
    }
    let timeout = esp_idf_sys::timeval {
        tv_sec: 1,
        tv_usec: 0,
    };
    let _ = esp_idf_sys::lwip_setsockopt(
        fd,
        esp_idf_sys::SOL_SOCKET as c_int,
        esp_idf_sys::SO_RCVTIMEO as c_int,
        (&timeout as *const esp_idf_sys::timeval).cast(),
        core::mem::size_of_val(&timeout) as _,
    );
    uart::send_response(b"raw UDP IPv6 ready");
    let mut packet = [0u8; 32];
    loop {
        let mut peer = esp_idf_sys::sockaddr_in6::default();
        let mut peer_len = core::mem::size_of::<esp_idf_sys::sockaddr_in6>() as _;
        let used = esp_idf_sys::lwip_recvfrom(
            fd,
            packet.as_mut_ptr().cast(),
            packet.len(),
            0,
            (&mut peer as *mut esp_idf_sys::sockaddr_in6).cast(),
            &mut peer_len,
        );
        if used <= 0 {
            esp_idf_sys::vTaskDelay(1);
            continue;
        }
        if packet[0] == 1 {
            peer.sin6_len = core::mem::size_of::<esp_idf_sys::sockaddr_in6>() as u8;
            peer.sin6_family = esp_idf_sys::AF_INET6 as u8;
            let _ = esp_idf_sys::lwip_sendto(
                fd,
                [0x81u8, 1].as_ptr().cast(),
                2,
                0,
                (&peer as *const esp_idf_sys::sockaddr_in6).cast(),
                peer_len,
            );
        }
    }
}

unsafe extern "C" fn raw_udp_endpoint_task(argument: *mut c_void) {
    if argument.is_null() {
        return;
    }
    let params = &mut *(argument as *mut uart::RecoveryParams);
    let fd = esp_idf_sys::lwip_socket(
        esp_idf_sys::AF_INET as c_int,
        esp_idf_sys::SOCK_DGRAM as c_int,
        esp_idf_sys::IPPROTO_UDP as c_int,
    );
    if fd < 0 {
        uart::send_response(b"raw UDP socket failed");
        return;
    }
    let Some(local_ip) = parse_ipv4(&params.local_ip[..params.local_ip_len]) else {
        uart::send_response(b"raw UDP local IP invalid");
        esp_idf_sys::lwip_close(fd);
        return;
    };
    let local = esp_idf_sys::sockaddr_in {
        sin_len: core::mem::size_of::<esp_idf_sys::sockaddr_in>() as u8,
        sin_family: esp_idf_sys::AF_INET as u8,
        sin_port: RAW_UDP_ENDPOINT_PORT.to_be(),
        // Recovery owns a configured static STA address.  Bind it explicitly:
        // current ESP lwIP accepts a wildcard UDP send but can emit a frame
        // which reaches the AP at L2 and is not delivered to the host UDP
        // socket.  This is also the source-address contract the transport
        // bearer must use; reassociation never changes this configured IP.
        sin_addr: esp_idf_sys::in_addr { s_addr: local_ip },
        sin_zero: [0; 8],
    };
    if esp_idf_sys::lwip_bind(
        fd,
        (&local as *const esp_idf_sys::sockaddr_in).cast(),
        sockaddr_len(),
    ) < 0
    {
        uart::send_response(b"raw UDP bind failed");
        esp_idf_sys::lwip_close(fd);
        return;
    }
    // Raw host-to-device IPERF is intentionally allowed to burst. Match the
    // transport socket's bounded queue so this baseline measures Wi-Fi/lwIP,
    // rather than an otherwise hidden per-socket default of a few datagrams.
    let receive_buffer_bytes = UDP_RECEIVE_BUFFER_BYTES as c_int;
    let _ = esp_idf_sys::lwip_setsockopt(
        fd,
        esp_idf_sys::SOL_SOCKET as c_int,
        esp_idf_sys::SO_RCVBUF as c_int,
        (&receive_buffer_bytes as *const c_int).cast(),
        core::mem::size_of_val(&receive_buffer_bytes) as _,
    );
    if let Some(host) = parse_ipv4(&params.server[..params.server_len]) {
        UDP_LOG_HOST.store(host, Ordering::Release);
        let queue = esp_idf_sys::xQueueCreateWithCaps(
            UDP_LOG_QUEUE_DEPTH as _,
            core::mem::size_of::<UdpLogRecord>() as _,
            esp_idf_sys::MALLOC_CAP_INTERNAL as _,
        );
        if !queue.is_null() {
            UDP_LOG_QUEUE.store(queue.cast(), Ordering::Release);
        }
        // Logs are command-rate and share :3337, avoiding a third device
        // socket and making the source port stable for host listeners.
        UDP_LOG_FD.store(fd, Ordering::Release);
        uart::set_udp_log_sink(udp_log_record);
        udp_boot_beacon();
    }
    let timeout = esp_idf_sys::timeval {
        tv_sec: 1,
        tv_usec: 0,
    };
    let _ = esp_idf_sys::lwip_setsockopt(
        fd,
        esp_idf_sys::SOL_SOCKET as c_int,
        esp_idf_sys::SO_RCVTIMEO as c_int,
        (&timeout as *const esp_idf_sys::timeval).cast(),
        core::mem::size_of_val(&timeout) as _,
    );
    uart::send_response(b"raw UDP ready");
    let mut packet = [0u8; UDP_MTU];
    let mut receiving = false;
    let mut received_packets = 0u32;
    let mut received_bytes = 0u64;
    let mut expected_packets = None;
    let mut expected_sequence = 0u32;
    let mut missing_packets = 0u32;
    let mut duplicate_packets = 0u32;
    // The raw control client may retry when its tiny acknowledgement is lost.
    // Keep the last accepted command so that retry cannot consume a second
    // mailbox slot or run the same benchmark twice.
    let mut last_command = [0u8; uart::UART_MAX_PACKET];
    let mut last_command_len = 0usize;
    let mut last_command_at_ms = 0u64;
    loop {
        let mut peer = esp_idf_sys::sockaddr_in::default();
        let mut peer_len = sockaddr_len();
        let used = esp_idf_sys::lwip_recvfrom(
            fd,
            packet.as_mut_ptr().cast(),
            packet.len(),
            0,
            (&mut peer as *mut esp_idf_sys::sockaddr_in).cast(),
            &mut peer_len,
        );
        if used <= 0 {
            udp_log_drain(fd);
            // lwIP may return EWOULDBLOCK immediately despite SO_RCVTIMEO.
            // This task runs above idle priority; always yield so an empty
            // diagnostic port cannot starve Wi-Fi work or trip the watchdog.
            esp_idf_sys::vTaskDelay(1);
            continue;
        }
        let used = used as usize;
        match packet[0] {
            1 => {
                // This must stay in the socket task. `send_response()` also
                // mirrors to UDP and can wait for USB UART space; doing that
                // per command made this endpoint stop servicing subsequent
                // probes. The binary status reply is the only acknowledgement.
                let sent = send_packet(fd, &peer, &[0x81, 1]);
                let mut local = esp_idf_sys::sockaddr_in::default();
                let mut local_len = sockaddr_len();
                let local_ok = esp_idf_sys::lwip_getsockname(
                    fd,
                    (&mut local as *mut esp_idf_sys::sockaddr_in).cast(),
                    &mut local_len,
                ) == 0;
                let mut tx_power_dbm_q4 = i8::MIN;
                let tx_power_ok = esp_idf_sys::esp_wifi_get_max_tx_power(&mut tx_power_dbm_q4)
                    == esp_idf_sys::ESP_OK;
                let mut power_save = esp_idf_sys::wifi_ps_type_t_WIFI_PS_NONE;
                let power_save_ok = esp_idf_sys::esp_wifi_get_ps(&mut power_save)
                    == esp_idf_sys::ESP_OK;
                let mut phymode: esp_idf_sys::wifi_phy_mode_t = core::mem::zeroed();
                let phymode_ok = esp_idf_sys::esp_wifi_sta_get_negotiated_phymode(&mut phymode)
                    == esp_idf_sys::ESP_OK;
                let mut bandwidth: esp_idf_sys::wifi_bandwidth_t = core::mem::zeroed();
                let bandwidth_ok = esp_idf_sys::esp_wifi_get_bandwidth(
                    esp_idf_sys::wifi_interface_t_WIFI_IF_STA,
                    &mut bandwidth,
                ) == esp_idf_sys::ESP_OK;
                let mut protocol = 0u8;
                let protocol_ok = esp_idf_sys::esp_wifi_get_protocol(
                    esp_idf_sys::wifi_interface_t_WIFI_IF_STA,
                    &mut protocol,
                ) == esp_idf_sys::ESP_OK;
                // Status is deliberately low-rate. These numeric fields are
                // mirrored through the normal UART/UDP log path so a lost
                // reply can be separated from an unreceived request without
                // adding logging to any benchmark packet loop.
                uart::send_benchmark_stats(&[
                    (70, 1),
                    (71, peer.sin_addr.s_addr as u64),
                    (72, u16::from_be(peer.sin_port) as u64),
                    (73, u64::from(sent)),
                    (74, if sent { 0 } else { send_errno() as u64 }),
                    // These are sampled only for the explicit status command,
                    // never on a packet-rate path.  They prove which local
                    // IPv4 tuple lwIP selected for the reply that the host
                    // observed at L2 but did not deliver to its UDP socket.
                    (
                        75,
                        if local_ok {
                            local.sin_addr.s_addr as u64
                        } else {
                            0
                        },
                    ),
                    (
                        76,
                        if local_ok {
                            u16::from_be(local.sin_port) as u64
                        } else {
                            0
                        },
                    ),
                    // These values distinguish a board-specific low TX-power
                    // limit or accidental modem sleep from a physical RF
                    // path problem. They are sampled only for status, never
                    // in a packet-rate benchmark loop.
                    (77, if tx_power_ok { tx_power_dbm_q4 as u8 as u64 } else { 0 }),
                    (
                        78,
                        u64::from(
                            power_save_ok
                                && power_save == esp_idf_sys::wifi_ps_type_t_WIFI_PS_NONE,
                        ),
                    ),
                    // The live negotiated PHY state makes a low MCS/rate
                    // report actionable without adding any telemetry to the
                    // data path. These are ESP-IDF enum/bitmap values.
                    (79, if phymode_ok { phymode as u64 } else { 0 }),
                    (80, if bandwidth_ok { bandwidth as u64 } else { 0 }),
                    (81, if protocol_ok { protocol as u64 } else { 0 }),
                    (90, u64::from(UDP_LOG_QUEUED.load(Ordering::Relaxed))),
                    (91, u64::from(UDP_LOG_DROPPED.load(Ordering::Relaxed))),
                    (92, u64::from(UDP_LOG_SENT.load(Ordering::Relaxed))),
                ]);
            }
            2 => {
                let (payload, bytes, pace_us) = if used == 11 {
                    let payload = u16::from_be_bytes([packet[1], packet[2]]) as usize;
                    let bytes = u32::from_be_bytes(packet[3..7].try_into().unwrap()) as usize;
                    let pace_us = u32::from_be_bytes(packet[7..11].try_into().unwrap());
                    (
                        payload.clamp(8, RAW_UDP_FLOOD_PAYLOAD),
                        bytes.clamp(8, RAW_UDP_FLOOD_BYTES),
                        pace_us,
                    )
                } else if used == 7 {
                    let payload = u16::from_be_bytes([packet[1], packet[2]]) as usize;
                    let bytes = u32::from_be_bytes(packet[3..7].try_into().unwrap()) as usize;
                    (
                        payload.clamp(8, RAW_UDP_FLOOD_PAYLOAD),
                        bytes.clamp(8, RAW_UDP_FLOOD_BYTES),
                        0,
                    )
                } else {
                    (RAW_UDP_FLOOD_PAYLOAD, RAW_UDP_FLOOD_BYTES, 0)
                };
                let (packets, bytes, failed, elapsed, terminal_sent, last_errno) =
                    raw_udp_send_flood(fd, &peer, bytes, payload, pace_us);
                // Raw diagnostics are intentionally quiet in the hot loop.
                // These final compact counters distinguish lwIP send failure
                // from Wi-Fi/host receive loss.
                uart::send_benchmark_stats(&[
                    (60, packets),
                    (61, bytes),
                    (62, failed),
                    (63, elapsed),
                    (64, u64::from(terminal_sent)),
                    (65, last_errno as u64),
                ]);
            }
            // Ask Recovery to repeat its UDP-only boot marker. This lets a
            // host test attach after boot without restarting the stable AP.
            4 => udp_boot_beacon(),
            3 => {
                receiving = true;
                received_packets = 0;
                received_bytes = 0;
                // New hosts attach the requested packet count to the
                // one-byte legacy command.  It lets this deliberately
                // unreliable raw diagnostic report tail loss even if the
                // final data packet was never received.
                expected_packets = (used == 5)
                    .then(|| u32::from_be_bytes(packet[1..5].try_into().unwrap()));
                expected_sequence = 0;
                missing_packets = 0;
                duplicate_packets = 0;
                let _ = send_packet(fd, &peer, &[0x84, 1]);
            }
            0x82 if receiving && used >= 5 => {
                let sequence = u32::from_be_bytes(packet[1..5].try_into().unwrap());
                if sequence < expected_sequence {
                    duplicate_packets = duplicate_packets.saturating_add(1);
                } else {
                    missing_packets = missing_packets
                        .saturating_add(sequence.saturating_sub(expected_sequence));
                    expected_sequence = sequence.wrapping_add(1);
                    received_packets = received_packets.saturating_add(1);
                    received_bytes = received_bytes.saturating_add((used - 5) as u64);
                }
            }
            0x85 if receiving => {
                if let Some(expected) = expected_packets {
                    missing_packets = missing_packets
                        .saturating_add(expected.saturating_sub(expected_sequence));
                }
                let mut result = [0u8; 21];
                result[0] = 0x86;
                result[1..5].copy_from_slice(&received_packets.to_be_bytes());
                result[5..13].copy_from_slice(&received_bytes.to_be_bytes());
                result[13..17].copy_from_slice(&missing_packets.to_be_bytes());
                result[17..21].copy_from_slice(&duplicate_packets.to_be_bytes());
                let _ = send_packet(fd, &peer, &result);
                receiving = false;
            }
            // A CBOR map begins with 0xa0..0xbf, so it cannot collide with
            // the one-byte raw diagnostics above. Reuse the exact command
            // decoder used by UART; UDP only returns a compact status byte.
            _ => {
                // Keep command ownership in main.rs. A direct mutation here
                // raced its volatile snapshot while a prior benchmark was
                // closing, so an acknowledged second command could vanish.
                let now_ms = unsafe { esp_idf_sys::esp_timer_get_time() as u64 / 1_000 };
                let duplicate = now_ms.saturating_sub(last_command_at_ms) <= RAW_UDP_COMMAND_DEDUP_MS
                    && used <= uart::UART_MAX_PACKET
                    && used == last_command_len
                    && last_command[..used] == packet[..used];
                let accepted = duplicate || uart::enqueue_udp_command(&packet[..used]);
                if accepted && !duplicate {
                    last_command[..used].copy_from_slice(&packet[..used]);
                    last_command_len = used;
                    last_command_at_ms = now_ms;
                }
                let _ = send_packet(fd, &peer, &[0x90, u8::from(accepted)]);
            }
        }
        udp_log_drain(fd);
    }
}

unsafe fn raw_udp_send_flood(
    fd: c_int,
    peer: &esp_idf_sys::sockaddr_in,
    byte_count: usize,
    payload_size: usize,
    pace_us: u32,
) -> (u64, u64, u64, u64, bool, i32) {
    let mut packet = [0u8; 5 + RAW_UDP_FLOOD_PAYLOAD];
    packet[0] = 0x82;
    let started = esp_idf_sys::esp_timer_get_time() as u64;
    let mut sent = 0usize;
    let mut sequence = 0u32;
    let mut failed = 0u64;
    let mut last_errno = 0i32;
    while sent < byte_count {
        let payload = (byte_count - sent).min(payload_size);
        packet[1..5].copy_from_slice(&sequence.to_be_bytes());
        if !send_packet(fd, peer, &packet[..5 + payload]) {
            failed = failed.saturating_add(1);
            last_errno = send_errno();
            // The lwIP UDP TX pool is small. This is queue backpressure, not
            // a lost benchmark packet: retry the identical sequence after
            // giving Wi-Fi one tick to drain it. The retry counter is emitted
            // with the final result so host tests can distinguish it from RF
            // loss. A bounded limit prevents a broken bearer from wedging the
            // command endpoint indefinitely.
            if failed >= 64 {
                break;
            }
            esp_idf_sys::vTaskDelay(1);
            continue;
        }
        sent += payload;
        sequence = sequence.saturating_add(1);
        if pace_us != 0 {
            // FreeRTOS scheduling granularity is one tick, so this is a
            // bounded diagnostic pacing knob rather than a sub-millisecond
            // rate shaper. It is intentionally outside the hot flood case.
            let ticks = ((pace_us as u64 + 999) / 1000).max(1) as u32;
            esp_idf_sys::vTaskDelay(ticks);
        } else if sequence % RAW_UDP_SEND_BURST == 0 {
            esp_idf_sys::vTaskDelay(1);
        }
    }
    let mut done = [0u8; 21];
    done[0] = 0x83;
    done[1..5].copy_from_slice(&sequence.to_be_bytes());
    done[5..13].copy_from_slice(&(sent as u64).to_be_bytes());
    done[13..21].copy_from_slice(
        &(esp_idf_sys::esp_timer_get_time() as u64)
            .saturating_sub(started)
            .to_be_bytes(),
    );
    let elapsed = (esp_idf_sys::esp_timer_get_time() as u64).saturating_sub(started);
    done[13..21].copy_from_slice(&elapsed.to_be_bytes());
    let terminal_sent = send_packet(fd, peer, &done);
    (
        sequence as u64,
        sent as u64,
        failed,
        elapsed,
        terminal_sent,
        last_errno,
    )
}

fn encode_bootstrap_open(
    cid: ConnectionId,
    packet_number: u32,
    limits: ConnectionLimits,
    max_in_flight_packets: u8,
    out: &mut [u8],
) -> Option<usize> {
    let mut body = [0u8; 32];
    let body_len = BootstrapOpen {
        client_receive_cid: cid,
        max_data: limits.max_data,
        max_stream_data: limits.max_stream_data,
        max_in_flight_packets: if max_in_flight_packets == 0 {
            dmesh_transport::RECOVERY_MAX_IN_FLIGHT_PACKETS
        } else {
            max_in_flight_packets as u16
        },
    }
    .encode(&mut body)
    .ok()?;
    let header_len = ShortHeader {
        flags: FLAG_FIXED,
        dcid: ConnectionId::new(0)?,
        packet_number,
        packet_number_len: 4,
    }
    .encode(out)
    .ok()?;
    let frame_len = Frame::Stream(StreamFrame {
        id: 0,
        offset: 0,
        fin: true,
        data: &body[..body_len],
    })
    .encode(&mut out[header_len..])
    .ok()?;
    Some(header_len + frame_len)
}

fn decode_bootstrap_ack(
    input: &[u8],
    expected: ConnectionId,
) -> Option<(ShortHeader, BootstrapOpenAck)> {
    dmesh_transport::decode_bootstrap_open_ack_packet_with_limits(input, expected).ok()
}

pub(crate) fn run_udp(
    server: &[u8],
    port: u16,
    benchmark: bool,
    timeout_ms: u32,
    ack_frequency: u8,
    ack_delay_ms: u8,
    transport_test: bool,
    iperf_packet_size: u16,
    iperf_bytes: u32,
    iperf_validation: u8,
    iperf_pace_us: u32,
    iperf_burst_packets: u8,
    iperf_burst_delay_us: u32,
    iperf_window_packets: u8,
    benchmark_run_id: u32,
) {
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
    let recovery_limits = recovery_receive_limits(transport_test, iperf_window_packets);
    let mut endpoint = RecoveryEndpoint::<2>::new(Role::Client, recovery_limits, UDP_MTU as u64);
    // ACK coalescing is configured here, while ACK encoding and emission
    // remain entirely inside dmesh-transport.
    let effective_ack_delay_ms = if ack_delay_ms == 0 {
        RECOVERY_MAX_ACK_DELAY_MS
    } else {
        u64::from(ack_delay_ms.clamp(1, 25))
    };
    endpoint.set_ack_policy(if ack_frequency == 0 {
        DEFAULT_ACK_FREQUENCY
    } else {
        ack_frequency
    }, effective_ack_delay_ms);
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
    let Some(mut open_len) = encode_bootstrap_open(
        client_cid,
        bootstrap_packet_number,
        recovery_limits,
        iperf_window_packets,
        &mut open_packet,
    ) else {
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
            if let Some((header, ack)) = decode_bootstrap_ack(&packet[..received as usize], client_cid) {
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
            let Some(next_open_len) = encode_bootstrap_open(
                client_cid,
                bootstrap_packet_number,
                recovery_limits,
                iperf_window_packets,
                &mut open_packet,
            ) else {
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
    let mut request_body = [0u8; 64];
    let request_body_len = if transport_test {
        // SERVICE_IPERF is a transport-only deterministic byte stream. This
        // deliberately isolates radio/lwIP/transport behavior from object
        // decoding, hashing, erase, and flash writes.
        request_body[0] = dmesh_transport::SERVICE_IPERF;
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
        22
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
    // setup. The counters come from dmesh-transport; Recovery only reports
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
    let mut iperf = IperfHandler::new(iperf_validation);
    let mut transfer_started_us = 0u64;
    let mut transfer_completed_us = 0u64;
    let mut transport_errors = [0u64; 11];
    let mut transport_send_failures = 0u64;
    let mut transport_last_send_errno = 0i32;
    let mut outbound_control_timing = OutboundControlTiming::default();
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
    loop {
        let now = unsafe { esp_idf_sys::esp_timer_get_time() as u64 / 1000 };
        if now >= deadline {
            break;
        }
        endpoint.set_time(now);
        peer_len = sockaddr_len();
        let receive_started_us = unsafe { esp_idf_sys::esp_timer_get_time() as u64 };
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
                if send_packet(fd, &server_peer, &delayed_control[..used]) {
                    transport_datagrams = transport_datagrams.saturating_add(1);
                    outbound_control_timing.record_success();
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
                    let _ = send_packet(fd, &server_peer, &request_packet[..request_len]);
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
            if bearer_timeout_should_yield(
                emitted_control,
                receive_wait_us,
                consecutive_empty_spins,
                (unsafe { esp_idf_sys::esp_timer_get_time() as u64 })
                    .saturating_sub(last_full_tick_yield_us),
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
            interpacket_count = interpacket_count.saturating_add(1);
            interpacket_total_us = interpacket_total_us.saturating_add(delta);
            interpacket_max_us = interpacket_max_us.max(delta);
            let bucket = interpacket_gap_bucket(delta);
            interpacket_gap_buckets[bucket] = interpacket_gap_buckets[bucket].saturating_add(1);
        }
        last_rx_us = Some(received_at_us);
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
                    let (complete, consumed) = match iperf.handle(stream) {
                        Ok(value) => value,
                        Err(()) => {
                            stream_error = true;
                            return Err(dmesh_transport::Error::Invalid);
                        }
                    };
                    image_complete = complete;
                    if image_complete {
                        transfer_completed_us = unsafe { esp_idf_sys::esp_timer_get_time() as u64 };
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
                                transfer_completed_us = unsafe { esp_idf_sys::esp_timer_get_time() as u64 };
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
                            Err(dmesh_transport::Error::Invalid)
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
                    dmesh_transport::Error::BufferTooSmall => 0,
                    dmesh_transport::Error::Truncated => 1,
                    dmesh_transport::Error::Invalid => 2,
                    dmesh_transport::Error::InvalidVarint => 3,
                    dmesh_transport::Error::FlowControl => 4,
                    dmesh_transport::Error::StreamLimit => 5,
                    dmesh_transport::Error::PacketNumberExhausted => 6,
                    dmesh_transport::Error::WrongConnectionId => 7,
                    dmesh_transport::Error::BootstrapInvalid => 8,
                    dmesh_transport::Error::HistoryFull => 9,
                    dmesh_transport::Error::RetransmissionTooLarge => 10,
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
        }
        receive_bursts = receive_bursts.saturating_add(1);
        receive_burst_max = receive_burst_max.max(burst_datagrams as u64);
        let mut transport_out = [0u8; UDP_MTU];
        if let Ok(Some(used)) = endpoint.poll_transmit(&mut transport_out) {
            if send_packet(fd, &server_peer, &transport_out[..used]) {
                transport_datagrams = transport_datagrams.saturating_add(1);
                outbound_control_timing.record_success();
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
            if released != 0 && endpoint.stream_consumed_deferred(OBJECT_STREAM, released).is_err() {
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
                    if send_packet(fd, &server_peer, &released_control[..used]) {
                        transport_datagrams = transport_datagrams.saturating_add(1);
                        outbound_control_timing.record_success();
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
                        if endpoint.stream_consumed_deferred(OBJECT_STREAM, released).is_err() {
                            uart::send_response(b"udp stream credit failed");
                            unsafe { esp_idf_sys::lwip_close(fd) };
                            return;
                        }
                        let mut control = [0u8; UDP_MTU];
                        if let Ok(Some(used)) = endpoint.poll_transmit(&mut control) {
                            if send_packet(fd, &server_peer, &control[..used]) {
                                transport_datagrams = transport_datagrams.saturating_add(1);
                                outbound_control_timing.record_success();
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
                    (iperf.bytes as usize, 0)
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
                    (40, iperf.callback_errors[0]),
                    (41, iperf.callback_errors[1]),
                    (42, iperf.callback_errors[2]),
                    (43, iperf.callback_errors[3]),
                    (44, iperf.callback_errors[4]),
                    (45, iperf.callback_errors[5]),
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
                    let _ = send_packet(fd, &server_peer, &close[..used]);
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
                // The raw-log task normally drains on its one-second socket
                // timeout, but a successful production transfer resets into
                // Main in 100 ms. Flush this one completion-only record now
                // so the host can separate erase/write time from radio time.
                // This is outside the receive hot path and remains a log
                // bearer action, not transport control.
                udp_log_drain(UDP_LOG_FD.load(Ordering::Acquire));
                // Only dry/diagnostic runs are reusable. A real image is now
                // durable and every block has matched the authenticated
                // manifest, so hand Stage2 back to Main after its concise
                // completion telemetry has reached the UART/UDP log queues.
                uart::send_stat(
                    b"udp handoff=",
                    crate::udp_flash::set_main_handoff() as u64,
                );
                if !uart::set_stg2_boot_target(1) {
                    // Do not reset into forced Recovery and falsely claim a
                    // Main handoff. The durable image remains available for
                    // a later retry of this final policy commit.
                    uart::send_response(b"udp main target failed");
                    unsafe { esp_idf_sys::lwip_close(fd) };
                    return;
                }
                uart::send_response(b"udp main target=1");
                unsafe {
                    esp_idf_sys::vTaskDelay(100);
                    esp_idf_sys::esp_restart();
                }
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
            (iperf.bytes as usize, 0)
        } else {
            flash.as_ref().expect("flash receiver").benchmark_stats()
        };
        let elapsed_us = if transfer_started_us != 0 {
            (unsafe { esp_idf_sys::esp_timer_get_time() as u64 }).saturating_sub(transfer_started_us)
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

/// Dedicated raw-UDP diagnostic. Its packets are not transport headers and
/// never enter object-store or stream decoding. The request is exactly one
/// byte: 2 asks the host for its fixed-size flood. Data packets are
/// `[0x82, sequence_be_u32, payload...]`; the terminal packet is
/// `[0x83, packets_be_u32, bytes_be_u64]`. This stays deliberately binary so
/// it measures Wi-Fi/lwIP rather than a text or object decoder.
pub(crate) fn run_raw_udp(server: &[u8], port: u16, timeout_ms: u32, packet_size: u16) {
    let Some(server_ip) = parse_ipv4(server) else {
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
        return;
    }
    // Keep the raw baseline's socket behavior equal to the transport bearer:
    // an explicit ephemeral bind and enough queued receive datagrams for a
    // host burst. Otherwise a valid reply can vanish before lwIP associates
    // it with this unbound socket or before Recovery returns to recvfrom.
    let receive_buffer_bytes = UDP_RECEIVE_BUFFER_BYTES as c_int;
    unsafe {
        let _ = esp_idf_sys::lwip_setsockopt(
            fd,
            esp_idf_sys::SOL_SOCKET as c_int,
            esp_idf_sys::SO_RCVBUF as c_int,
            (&receive_buffer_bytes as *const c_int).cast(),
            core::mem::size_of_val(&receive_buffer_bytes) as _,
        );
    }
    let local = esp_idf_sys::sockaddr_in {
        sin_len: core::mem::size_of::<esp_idf_sys::sockaddr_in>() as u8,
        sin_family: esp_idf_sys::AF_INET as u8,
        sin_port: 0u16.to_be(),
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
    let peer = esp_idf_sys::sockaddr_in {
        sin_len: core::mem::size_of::<esp_idf_sys::sockaddr_in>() as u8,
        sin_family: esp_idf_sys::AF_INET as u8,
        sin_port: port.to_be(),
        sin_addr: esp_idf_sys::in_addr { s_addr: server_ip },
        sin_zero: [0; 8],
    };
    let timeout = esp_idf_sys::timeval {
        tv_sec: (timeout_ms / 1000) as _,
        tv_usec: ((timeout_ms % 1000) * 1000) as _,
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
    let started = unsafe { esp_idf_sys::esp_timer_get_time() as u64 };
    // Raw IPERF uses the same requested application packet size and a
    // monotonic u32 packet ID as transport IPERF, making their loss and Mbps
    // figures directly comparable. The raw packet header itself is 5 bytes.
    let raw_request = if packet_size as usize == RAW_UDP_FLOOD_PAYLOAD {
        &[2][..]
    } else {
        &[2, (packet_size >> 8) as u8, packet_size as u8][..]
    };
    if !send_packet(fd, &peer, raw_request) {
        unsafe {
            esp_idf_sys::lwip_close(fd);
        }
        return;
    }
    let mut reply = [0u8; UDP_MTU];
    let mut packets = 0u64;
    let mut bytes = 0u64;
    let mut duplicates = 0u64;
    let mut missing = 0u64;
    let mut expected_sequence = 0u32;
    loop {
        let received = unsafe {
            esp_idf_sys::lwip_recvfrom(
                fd,
                reply.as_mut_ptr().cast(),
                reply.len(),
                0,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            )
        };
        if received <= 0 {
            break;
        }
        let received = received as usize;
        match reply[0] {
            0x82 if received >= 5 => {
                let sequence = u32::from_be_bytes(reply[1..5].try_into().unwrap());
                if sequence < expected_sequence {
                    duplicates += 1;
                    continue;
                }
                missing = missing.saturating_add(sequence.saturating_sub(expected_sequence) as u64);
                expected_sequence = sequence.wrapping_add(1);
                packets += 1;
                bytes += (received - 5) as u64;
            }
            0x83 if received == 13 => break,
            _ => {}
        }
    }
    let elapsed = unsafe { esp_idf_sys::esp_timer_get_time() as u64 }.saturating_sub(started);
    let bits_per_second = if elapsed == 0 {
        0
    } else {
        bytes * 8_000_000 / elapsed
    };
    uart::send_benchmark_stats(&[
        (30, bytes),
        (31, elapsed),
        (32, packets),
        (33, duplicates),
        (36, bits_per_second),
        (37, missing),
        (38, packet_size as u64),
    ]);
    unsafe {
        esp_idf_sys::lwip_close(fd);
    }
}

#[cfg(test)]
mod tests {
    use super::{
        bearer_timeout_should_yield, decode_bootstrap_ack, interpacket_gap_bucket,
        recovery_receive_limits, ConnectionId, ConnectionLimits, Frame, RecoveryEndpoint, Role,
        ShortHeader, StreamFrame, FLAG_FIXED, IPERF_STREAM, OutboundControlTiming,
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
        assert!(!bearer_timeout_should_yield(true, 0, 8, 100_000));
        assert!(!bearer_timeout_should_yield(false, 0, 7, 100_000));
        assert!(!bearer_timeout_should_yield(false, 0, 8, 99_999));
        assert!(bearer_timeout_should_yield(false, 0, 8, 100_000));
        assert!(!bearer_timeout_should_yield(false, 1_000, 8, 100_000));
    }

    #[test]
    fn outbound_control_timing_is_opaque_and_aggregate() {
        let mut timing = OutboundControlTiming::default();
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
        let flash = recovery_receive_limits(false, 64);
        let iperf_default = recovery_receive_limits(true, 0);
        let iperf_24 = recovery_receive_limits(true, 24);
        let iperf_64 = recovery_receive_limits(true, 64);
        assert_eq!(flash.max_data, dmesh_transport::RECOVERY_INITIAL_MAX_DATA);
        assert_eq!(flash.max_stream_data, dmesh_transport::RECOVERY_INITIAL_MAX_DATA);
        assert_eq!(
            iperf_default.max_data,
            u64::from(dmesh_transport::RECOVERY_MAX_IN_FLIGHT_PACKETS) * 1200
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
        let ack_len = dmesh_transport::encode_bootstrap_open_ack_packet_with_limits(
            client,
            server,
            98,
            limits,
            &mut bootstrap_ack,
        )
        .unwrap();
        let (header, ack) = decode_bootstrap_ack(&bootstrap_ack[..ack_len], client).unwrap();
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
