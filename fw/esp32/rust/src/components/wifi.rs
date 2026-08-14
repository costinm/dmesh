use std::collections::VecDeque;
use std::ffi::c_char;
use std::io::ErrorKind;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicU8, Ordering};
use std::sync::{Mutex, OnceLock};
use std::thread;
use std::time::Duration;

unsafe extern "C" {
    fn esp_wifi_internal_set_fix_rate(
        ifx: sys::wifi_interface_t,
        en: bool,
        rate: sys::wifi_phy_rate_t,
    ) -> sys::esp_err_t;
}

// Main creates the default STA netif before initializing the Wi-Fi driver,
// matching Recovery's C startup sequence. The normal ESP-IDF event handlers
// own link-up and route transitions after association.
extern "C" {
    fn dmesh_module_loader_ip_netif_flags(esp_netif: *mut sys::esp_netif_t) -> u8;
    fn dmesh_module_loader_ip_netif_default(esp_netif: *mut sys::esp_netif_t) -> u8;
    fn dmesh_module_loader_ip_netif_io_state(esp_netif: *mut sys::esp_netif_t) -> u8;
    fn dmesh_module_loader_ip_netif_addr(esp_netif: *mut sys::esp_netif_t, which: u8) -> u32;
}

use anyhow::{anyhow, bail, Context, Result};
use dmesh_transport::{decode_bench_stream, decode_frame, encode_bench_stream, ConnectionId, Frame, ShortHeader, StreamFrame, FLAG_FIXED};
use esp_idf_svc::espnow::{EspNow, PeerInfo, BROADCAST as ESPNOW_BROADCAST};
use esp_idf_sys as sys;

use crate::commands::{CommandHandler, CommandRegistry, CommandRequest, CommandResponse};

use super::bytes::{hex_bytes, parse_bytes};
use super::settings::{parse_bool, parse_i32, SharedSettings};
use super::telemetry::{self, Direction};

unsafe extern "C" {
    fn esp_wifi_connectionless_module_set_wake_interval(wake_interval: u16) -> sys::esp_err_t;
    fn dmesh_wifi_filter_set_bssid(interface_id: u8, bssid: *const u8, enabled: bool) -> i32;
    fn dmesh_wifi_filter_supported() -> bool;
}

const FRAME_ADDR1: usize = 4;
const FRAME_ADDR2: usize = 10;
const FRAME_ADDR3: usize = 16;
#[allow(dead_code)]
const ETH_ADDR_DST: usize = 0;
#[allow(dead_code)]
const ETH_ADDR_SRC: usize = 6;
#[allow(dead_code)]
const ETHERTYPE_IPV4: u16 = 0x0800;
const IEEE80211_LLC_SNAP_LEN: usize = 8;
const RAW_FILTER_ALL: u32 = 0;
const RAW_FILTER_MGMT: u32 = 1;
const RAW_FILTER_ACTION: u32 = 2;
const RAW_FILTER_BEACON: u32 = 3;
const RAW_FILTER_PROBE_REQ: u32 = 4;
const RAW_FILTER_PROBE_RESP: u32 = 5;
const RAW_FILTER_DATA: u32 = 6;
const RAW_FILTER_DMESH: u32 = 7;
const RAW_FILTER_DMESH_DATA: u32 = 8;
const RAW_COMMAND_QUEUE_MAX: usize = 8;
const RAW_COMMAND_MAX_LEN: usize = 512;
const RAW_BROADCAST: [u8; 6] = [0xff; 6];
// ESP-IDF does not expose esp-netif error constants through every generated
// esp-idf-sys binding set.  This is ESP_ERR_ESP_NETIF_BASE + 0x05 from
// esp_netif_types.h (0x5005): stopping DHCP when it is already stopped.
const ESP_ERR_DHCP_ALREADY_STOPPED: sys::esp_err_t = 0x5005;
// lmesh discovery uses ff02::5227, whose Ethernet/Wi-Fi multicast mapping is
// 33:33:00:00:52:27. Directed device traffic uses the peer MAC with the
// multicast bit set.
const LMESH_IPV6_DISCOVERY_MULTICAST: [u8; 6] = [0x33, 0x33, 0x00, 0x00, 0x52, 0x27];
const LMESH_IPV4_MULTICAST: [u8; 4] = [224, 0, 0, 250];
const DMESH_UDP_PORT: u16 = 15009;
const DMESH_DATA_MARKER_PREFIX: [u8; 4] = [0x7f, 0x18, 0xfe, 0x34];
const DMESH_DATA_MARKER_TYPE: u8 = 0x04;
const DMESH_DATA_MARKER_LEN: usize = 9;
/// Maximum DMesh payload in one custom raw 802.11 vendor action frame.
///
/// This is deliberately independent from ESP-NOW's 250-byte compatibility
/// limit. The complete 802.11 frame remains below the firmware's 1500-byte
/// raw transmit/receive bound.
pub const RAW_ACTION_MAX_PAYLOAD: usize = 1200;
const BENCH_STREAM_MAGIC: [u8; 4] = dmesh_transport::BENCH_MAGIC;
const BENCH_STREAM_DCID: u64 = dmesh_transport::BENCH_CONNECTION_ID;
const BENCH_STREAM_ID: u64 = dmesh_transport::BENCH_STREAM_ID;
// Minimum recognizable benchmark envelope: magic plus the encoded transport
// header. The actual short-header/frame size is variable.
// Leave room for the DMTB tag, QUIC-like short header, and stream-frame
// varints. The exact encoded size is checked before sending.
// Keep benchmark action frames comfortably below the monitor driver's large
// management-frame edge cases. The transport itself is independent of this
// chunk size and can be raised after the reliable path is established.
const BENCH_STREAM_DATA_MAX: usize = 512;
const DMESH_FIXED_MESH_DST4: [u8; 4] = [0xff; 4];
const IEEE80211_LLC_SNAP_IPV4: [u8; IEEE80211_LLC_SNAP_LEN] =
    [0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x08, 0x00];
const RAWNAN_LLC_DEFAULT: [u8; IEEE80211_LLC_SNAP_LEN] =
    [0xaa, 0xaa, 0x03, 0xd0, 0x4d, 0x45, 0x53, 0x48];

static RAW_MONITOR_RUNNING: AtomicBool = AtomicBool::new(false);
// Serialize all Wi-Fi driver stop/start transitions. The NAN duty loop and
// an explicit IP-STA command can otherwise interleave `esp_wifi_stop()` with
// a just-completed association, producing a station-originated reason-8
// disassociation.
static WIFI_DRIVER_TRANSITION: OnceLock<Mutex<()>> = OnceLock::new();

fn wifi_driver_transition() -> &'static Mutex<()> {
    WIFI_DRIVER_TRANSITION.get_or_init(|| Mutex::new(()))
}

static IP_STA_NETIF: OnceLock<usize> = OnceLock::new();
// Set only after the static STA has associated and has a non-zero address.
// `mode::stop_for_ip_transport()` is also called by a module that is already
// using this STA; it must not tear that working data plane down again.
static IP_STA_READY: AtomicBool = AtomicBool::new(false);
static IP_STA_STARTING: AtomicBool = AtomicBool::new(false);
// The ESP-IDF default netif handlers publish link state, but they do not
// reconnect a station after every disconnect on all supported IDF versions.
// Keep reconnect bounded and only active while Main has explicitly handed the
// radio to the IP transport.
static IP_STA_NEXT_RECONNECT_MS: AtomicU32 = AtomicU32::new(0);
static IP_STA_RECONNECTS: AtomicU32 = AtomicU32::new(0);
// 0=unknown, 1=associated+IP, 2=associated without usable netif,
// 3=not associated.  Only transitions are logged so a failed STA does not
// flood the serial stream while the bounded reconnect loop is running.
static IP_STA_LAST_STATE: AtomicU8 = AtomicU8::new(0);
static RAW_FILTER_MODE: AtomicU32 = AtomicU32::new(RAW_FILTER_MGMT);
static RAW_FILTER_BSSID_ENABLED: AtomicBool = AtomicBool::new(false);
static RAW_FILTER_BSSID: [AtomicU8; 6] = [
    AtomicU8::new(0),
    AtomicU8::new(0),
    AtomicU8::new(0),
    AtomicU8::new(0),
    AtomicU8::new(0),
    AtomicU8::new(0),
];
static RAW_RX_TOTAL: AtomicU32 = AtomicU32::new(0);
static RAW_RX_MATCHED: AtomicU32 = AtomicU32::new(0);
static RAW_RX_DROPPED: AtomicU32 = AtomicU32::new(0);
static RAW_RX_LAST_LEN: AtomicU32 = AtomicU32::new(0);
static RAW_RX_LAST_RSSI: AtomicI32 = AtomicI32::new(0);
static RAW_TX_TOTAL: AtomicU32 = AtomicU32::new(0);
static RAW_CMD_RX_TOTAL: AtomicU32 = AtomicU32::new(0);
static RAW_CMD_DROPPED: AtomicU32 = AtomicU32::new(0);
static RAW_OBJECT_ACTION_ATTEMPTS: AtomicU32 = AtomicU32::new(0);
static RAW_OBJECT_ACTION_ACCEPTED: AtomicU32 = AtomicU32::new(0);
static RAW_OBJECT_ACTION_LAST_LEN: AtomicU32 = AtomicU32::new(0);
static RAW_OBJECT_ACTION_LAST_PREFIX: AtomicU32 = AtomicU32::new(0);
// Receive-path diagnostics for custom DMesh action frames. These distinguish
// an action frame reaching Main from one carrying the expected marker and
// from one actually being accepted for command dispatch.
static RAW_ACTION_CANDIDATES: AtomicU32 = AtomicU32::new(0);
static RAW_ACTION_MARKER_MISSES: AtomicU32 = AtomicU32::new(0);
static RAW_ACTION_ACCEPTED: AtomicU32 = AtomicU32::new(0);
static WIFI_CONNECTIONLESS_WAKE_INTERVAL_MS: AtomicU32 = AtomicU32::new(0);
static RAW_WIFI_INIT: AtomicBool = AtomicBool::new(false);
static WIFI_NETIF_PROBE_RUNNING: AtomicBool = AtomicBool::new(false);
static WIFI_NETIF_RX_TOTAL: AtomicU32 = AtomicU32::new(0);
static WIFI_NETIF_RX_LAST_LEN: AtomicU32 = AtomicU32::new(0);
static RAW_LAST_COMMAND_PEER: [AtomicU8; 6] = [
    AtomicU8::new(0),
    AtomicU8::new(0),
    AtomicU8::new(0),
    AtomicU8::new(0),
    AtomicU8::new(0),
    AtomicU8::new(0),
];
static RAW_LAST_COMMAND_PEER_VALID: AtomicBool = AtomicBool::new(false);
static RAW_LAST_COMMAND_RESPONSE: AtomicU8 = AtomicU8::new(0);
static WIFI_NOTIFY_FORWARDING: AtomicBool = AtomicBool::new(false);
static ESPNOW_SERVICE: OnceLock<EspNow<'static>> = OnceLock::new();
static WIFI_BEACON_COUNT: AtomicU32 = AtomicU32::new(0);
static WIFI_BEACON_LOCAL_LO: AtomicU32 = AtomicU32::new(0);
static WIFI_BEACON_LOCAL_HI: AtomicU32 = AtomicU32::new(0);
static WIFI_BEACON_TSF_LO: AtomicU32 = AtomicU32::new(0);
static WIFI_BEACON_TSF_HI: AtomicU32 = AtomicU32::new(0);
static BENCH_RX_BYTES: AtomicU32 = AtomicU32::new(0);
static BENCH_RX_FRAMES: AtomicU32 = AtomicU32::new(0);
static BENCH_RX_LAST_SEQ: AtomicU32 = AtomicU32::new(0);
static BENCH_RX_EXPECTED_BYTES: AtomicU32 = AtomicU32::new(0);
static BENCH_RX_EXPECTED_FRAMES: AtomicU32 = AtomicU32::new(0);
static BENCH_RX_DELAY_US: AtomicU32 = AtomicU32::new(0);
static BENCH_RX_SEEN: AtomicU32 = AtomicU32::new(0);
static BENCH_RX_DECODE_ERRORS: AtomicU32 = AtomicU32::new(0);
static BENCH_RX_LENGTH_ERRORS: AtomicU32 = AtomicU32::new(0);
static mut BENCH_TX_ENCODED: [u8; RAW_ACTION_MAX_PAYLOAD] = [0; RAW_ACTION_MAX_PAYLOAD];
static mut BENCH_TX_DATA: [u8; BENCH_STREAM_DATA_MAX] = [0; BENCH_STREAM_DATA_MAX];
struct UdpHelloProbe {
    socket: UdpSocket,
    server: String,
    port: u16,
    target: u8,
    started_ms: u64,
    timeout_ms: u32,
    sent_bytes: usize,
    // Keep the large datagram buffer off Main's small task stack. The shared
    // encoder/parser remains no-std and allocation-free; this is only the
    // platform-owned socket adapter storage.
    response: Box<[u8; 2048]>,
}

// Small bidirectional UDP health exchange. This intentionally has no object
// or QUIC semantics: it answers one request with a fixed status record so a
// failed test can be attributed to socket send, host receive, device receive,
// or the return path.
const UDP_STATUS_MAGIC: [u8; 4] = *b"DMSU";
const UDP_STATUS_VERSION: u8 = 1;
const UDP_STATUS_REQUEST: u8 = 1;
const UDP_STATUS_RESPONSE: u8 = 2;
const UDP_STATUS_REQUEST_LEN: usize = 14;
const UDP_STATUS_RESPONSE_LEN: usize = 26;

struct UdpStatusProbe {
    socket: UdpSocket,
    peer: SocketAddr,
    server: String,
    port: u16,
    started_ms: u64,
    timeout_ms: u32,
    nonce: u64,
    sent_bytes: usize,
    response: Box<[u8; 128]>,
}

struct UdpStatusServer {
    socket: UdpSocket,
    port: u16,
    requests: u32,
    responses: u32,
    last_peer: Option<SocketAddr>,
    last_sent: usize,
}

fn udp_status_probe_state() -> &'static Mutex<Option<UdpStatusProbe>> {
    static STATE: OnceLock<Mutex<Option<UdpStatusProbe>>> = OnceLock::new();
    STATE.get_or_init(|| Mutex::new(None))
}

fn udp_status_probe_last() -> &'static Mutex<String> {
    static LAST: OnceLock<Mutex<String>> = OnceLock::new();
    LAST.get_or_init(|| Mutex::new("wifi udp_status_probe idle".to_owned()))
}

fn udp_status_server_state() -> &'static Mutex<Option<UdpStatusServer>> {
    static STATE: OnceLock<Mutex<Option<UdpStatusServer>>> = OnceLock::new();
    STATE.get_or_init(|| Mutex::new(None))
}

fn udp_status_server_last() -> &'static Mutex<String> {
    static LAST: OnceLock<Mutex<String>> = OnceLock::new();
    LAST.get_or_init(|| Mutex::new("wifi udp_status_server stopped".to_owned()))
}

fn udp_status_nonce() -> u64 {
    now_ms() ^ ((unsafe { sys::esp_random() }) as u64) << 32
}

fn encode_udp_status_request(nonce: u64, out: &mut [u8; UDP_STATUS_REQUEST_LEN]) {
    out[..4].copy_from_slice(&UDP_STATUS_MAGIC);
    out[4] = UDP_STATUS_VERSION;
    out[5] = UDP_STATUS_REQUEST;
    out[6..14].copy_from_slice(&nonce.to_be_bytes());
}

fn encode_udp_status_response(nonce: u64, out: &mut [u8; UDP_STATUS_RESPONSE_LEN]) {
    out[..4].copy_from_slice(&UDP_STATUS_MAGIC);
    out[4] = UDP_STATUS_VERSION;
    out[5] = UDP_STATUS_RESPONSE;
    out[6..14].copy_from_slice(&nonce.to_be_bytes());
    out[14..22].copy_from_slice(&now_ms().to_be_bytes());
    let ip = IP_STA_NETIF
        .get()
        .map(|value| unsafe { dmesh_module_loader_ip_netif_addr(*value as *mut sys::esp_netif_t, 0) })
        .unwrap_or(0);
    // esp_netif exposes the IPv4 address in the native u32 representation;
    // normalize the octets before putting them on the network wire.
    out[22..26].copy_from_slice(&ip.to_ne_bytes());
}

const DRS2_MAGIC: u32 = 0x4452_5332;
const DRS2_FRAME_HELLO: u16 = 1;
const DRS2_FRAME_MANIFEST: u16 = 6;
const DRS2_FRAME_MANIFEST_OK: u16 = 13;
const UDP_MANIFEST_STREAM: u64 = 3;
const UDP_HELLO_STREAM: u64 = 0;
const UDP_HELLO_LEN: usize = 90;

const UDP_RX_WINDOW_MAX: usize = 64;
// The object-store sender uses a 1200-byte UDP payload. Keep a little room
// for the transport header while making the reassembly storage fixed-size;
// allocating one Vec per datagram eventually fragments the small ESP heap.
const UDP_PACKET_MAX: usize = 1200;
struct UdpDryRun {
    socket: UdpSocket,
    peer: SocketAddr,
    hello: Box<[u8; 256]>,
    hello_len: usize,
    hello_sent: bool,
    hello_sent_ms: u64,
    hello_retransmits: u32,
    server: String,
    port: u16,
    target: u8,
    started_ms: u64,
    timeout_ms: u32,
    packet: Box<[u8; UDP_PACKET_MAX]>,
    phase: u8,
    acks_sent: u32,
    rx_window_packets: usize,
    write_flash: bool,
    receiver: crate::components::object_transfer::ObjectReceiver<crate::components::object_transfer::TransferSink>,
}

fn udp_dry_run_state() -> &'static Mutex<Option<UdpDryRun>> {
    static STATE: OnceLock<Mutex<Option<UdpDryRun>>> = OnceLock::new();
    STATE.get_or_init(|| Mutex::new(None))
}

fn udp_dry_run_last() -> &'static Mutex<String> {
    static LAST: OnceLock<Mutex<String>> = OnceLock::new();
    LAST.get_or_init(|| Mutex::new("wifi udp_dry_run idle".to_owned()))
}

fn udp_hello_probe_state() -> &'static Mutex<Option<UdpHelloProbe>> {
    static STATE: OnceLock<Mutex<Option<UdpHelloProbe>>> = OnceLock::new();
    STATE.get_or_init(|| Mutex::new(None))
}

fn udp_hello_probe_last() -> &'static Mutex<String> {
    static LAST: OnceLock<Mutex<String>> = OnceLock::new();
    LAST.get_or_init(|| Mutex::new("wifi udp_hello idle".to_owned()))
}
static RAW_FIRST_FRAME_LOCAL_LO: AtomicU32 = AtomicU32::new(0);
static RAW_FIRST_FRAME_LOCAL_HI: AtomicU32 = AtomicU32::new(0);
static mut RAW_RX_LAST: [u8; 256] = [0; 256];

/// Generic beacon-derived wake plan shared by NAN and AP-beacon schedulers.
#[derive(Clone, Copy, Debug)]
pub struct BeaconWakePlan {
    pub window_delay_ms: u32,
    pub light_sleep_ms: u32,
    pub beacon_age_ms: u32,
    pub expected_tsf_us: u64,
    pub period_us: u32,
}

/// Latest observed 802.11 beacon timing state.
#[derive(Clone, Copy, Debug)]
pub struct BeaconSnapshot {
    pub count: u32,
    pub local_us: u64,
    pub tsf_us: u64,
}

pub fn beacon_snapshot() -> BeaconSnapshot {
    BeaconSnapshot {
        count: WIFI_BEACON_COUNT.load(Ordering::Relaxed),
        local_us: load_u64(&WIFI_BEACON_LOCAL_LO, &WIFI_BEACON_LOCAL_HI),
        tsf_us: load_u64(&WIFI_BEACON_TSF_LO, &WIFI_BEACON_TSF_HI),
    }
}

/// Compute a beacon-aligned wake plan from a caller-selected timing source.
/// The raw NAN scheduler uses this to keep NAN and AP beacon clocks separate.
pub fn beacon_wake_plan_from(
    snapshot: BeaconSnapshot,
    min_delay_ms: u32,
    interval_tu: u32,
    offset_tu: u32,
    wake_early_ms: u32,
) -> Option<BeaconWakePlan> {
    let period_us = u64::from(interval_tu.max(1)).saturating_mul(1024);
    if snapshot.local_us == 0 || snapshot.tsf_us == 0 {
        return None;
    }
    let now_us = unsafe { sys::esp_timer_get_time().max(0) as u64 };
    let age_us = now_us.saturating_sub(snapshot.local_us);
    if age_us > period_us.saturating_mul(2) {
        return None;
    }
    let now_tsf_us = snapshot.tsf_us.saturating_add(age_us);
    // The captured beacon timestamp is the local authority for the cluster's
    // DW phase. Do not project every cluster onto absolute TSF zero: Android
    // and AP timing sources commonly run at a stable non-zero phase. The
    // configured offset is relative to that observed phase.
    let target_us = (snapshot.tsf_us % period_us)
        .saturating_add(u64::from(offset_tu).saturating_mul(1024))
        % period_us;
    let earliest_us = now_tsf_us.saturating_add(u64::from(min_delay_ms) * 1000);
    let phase_us = earliest_us % period_us;
    let until_us = if phase_us <= target_us {
        target_us - phase_us
    } else {
        period_us - (phase_us - target_us)
    };
    let delay_us = u64::from(min_delay_ms) * 1000 + until_us;
    Some(BeaconWakePlan {
        window_delay_ms: delay_us.div_ceil(1000).min(u64::from(u32::MAX)) as u32,
        light_sleep_ms: delay_us
            .saturating_sub(u64::from(wake_early_ms) * 1000)
            .saturating_div(1000)
            .min(u64::from(u32::MAX)) as u32,
        beacon_age_ms: (age_us / 1000).min(u64::from(u32::MAX)) as u32,
        expected_tsf_us: earliest_us.saturating_add(until_us),
        period_us: period_us.min(u64::from(u32::MAX)) as u32,
    })
}

/// Compute a wake plan for a numbered NAN discovery-window cadence.
///
/// `slot_stride` selects global DW indices rather than free-running elapsed
/// time: with a 512-TU DW period and stride eight, the default valid targets
/// are DW0, DW0+8, DW0+16, and so on. This is used by sleepy radios after they have a
/// fresh NAN TSF source. `min_delay_ms` protects against scheduling a target
/// that is already too close to wake reliably.
pub fn beacon_wake_plan_for_dw_stride(
    snapshot: BeaconSnapshot,
    min_delay_ms: u32,
    interval_tu: u32,
    offset_tu: u32,
    slot_stride: u32,
    wake_early_ms: u32,
) -> Option<BeaconWakePlan> {
    let period_us = u64::from(interval_tu.max(1)).saturating_mul(1024);
    if snapshot.local_us == 0 || snapshot.tsf_us == 0 {
        return None;
    }
    let now_us = unsafe { sys::esp_timer_get_time().max(0) as u64 };
    let age_us = now_us.saturating_sub(snapshot.local_us);
    // A sparse duty cadence can legitimately observe its timing beacon several
    // base DWs before the next selected slot. Keep the freshness bound tied to
    // the selected stride and the configured ~15 s NAN-loss recovery horizon;
    // rejecting everything older than two 512-TU periods makes stride=8 fall
    // back to an unsynchronized free-running wake loop after a few misses.
    let freshness_periods = u64::from(slot_stride.max(1)).saturating_mul(8);
    if age_us > period_us.saturating_mul(freshness_periods) {
        return None;
    }
    let now_tsf_us = snapshot.tsf_us.saturating_add(age_us);
    // NAN's TSF is the cluster clock.  A received beacon may be transmitted
    // at any point while the cluster is active, so its own phase is not the
    // Discovery Window boundary.  Chasing `snapshot.tsf_us % period_us`
    // made a sleepy node wake at the phase of whichever beacon happened to be
    // last, which is why the powered observer showed ~180-ms beacon spacing.
    // Anchor the rendezvous to the configured DW offset modulo the NAN period
    // instead (DW0 is zero; DW8 is selected by the stride).
    let target_phase_us = u64::from(offset_tu).saturating_mul(1024) % period_us;
    let stride = u64::from(slot_stride.max(1));
    let current_index = now_tsf_us / period_us;
    let mut target_index = current_index
        .saturating_div(stride)
        .saturating_add(1)
        .saturating_mul(stride);
    let min_target_us = now_tsf_us.saturating_add(u64::from(min_delay_ms) * 1000);
    let mut expected_tsf_us = target_index
        .saturating_mul(period_us)
        .saturating_add(target_phase_us);
    while expected_tsf_us < min_target_us {
        target_index = target_index.saturating_add(stride);
        expected_tsf_us = target_index
            .saturating_mul(period_us)
            .saturating_add(target_phase_us);
    }
    let delay_us = expected_tsf_us.saturating_sub(now_tsf_us);
    Some(BeaconWakePlan {
        window_delay_ms: delay_us.div_ceil(1000).min(u64::from(u32::MAX)) as u32,
        light_sleep_ms: delay_us
            .saturating_sub(u64::from(wake_early_ms) * 1000)
            .saturating_div(1000)
            .min(u64::from(u32::MAX)) as u32,
        beacon_age_ms: (age_us / 1000).min(u64::from(u32::MAX)) as u32,
        expected_tsf_us,
        period_us: period_us.min(u64::from(u32::MAX)) as u32,
    })
}

#[derive(Clone, Debug)]
pub struct RawWifiCommand {
    pub source: [u8; 6],
    pub payload: Vec<u8>,
    pub rssi: i32,
    pub response: WifiResponsePath,
}

#[derive(Clone, Copy, Debug)]
pub enum WifiResponsePath {
    Action,
    Data,
}

impl WifiResponsePath {
    fn as_u8(self) -> u8 {
        match self {
            Self::Action => 0,
            Self::Data => 1,
        }
    }

    fn from_u8(value: u8) -> Self {
        match value {
            1 => Self::Data,
            _ => Self::Action,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Action => "action",
            Self::Data => "data",
        }
    }
}

static RAW_COMMAND_QUEUE: OnceLock<Mutex<VecDeque<RawWifiCommand>>> = OnceLock::new();
const RAW_RESPONSE_HISTORY_MAX: usize = 4;

#[derive(Clone, Debug)]
struct RawWifiResponse {
    local_us: u64,
    source: [u8; 6],
    payload: Vec<u8>,
}

static RAW_RESPONSE_HISTORY: OnceLock<Mutex<VecDeque<RawWifiResponse>>> = OnceLock::new();

pub fn register_commands(registry: &mut CommandRegistry, settings: SharedSettings) {
    registry.register(WifiCommand::new(settings));
}

pub fn forward_management_packet(packet: &[u8]) -> Result<()> {
    if !super::nan::raw_tx_active() {
        ensure_raw_wifi_started(6)?;
    }
    let frame = nan_sdf_action_frame(RAW_BROADCAST, packet)?;
    raw_tx_frame(&frame, true)?;
    RAW_TX_TOTAL.fetch_add(1, Ordering::Relaxed);
    telemetry::record_packet("wifi", Direction::Tx, packet, "source=lora_forward");
    Ok(())
}

/// Initialize the real ESP-NOW service and its broadcast peer on the active
/// Wi-Fi interface. This is separate from the existing injected action-frame
/// path: receivers that use the ESP-NOW API can consume these packets without
/// knowing the DMesh raw-action framing.
fn ensure_espnow() -> Result<&'static EspNow<'static>> {
    if let Some(service) = ESPNOW_SERVICE.get() {
        return Ok(service);
    }
    let service = EspNow::take().map_err(|err| anyhow!("esp-now init failed: {err}"))?;
    let peer = espnow_peer_info();
    if let Err(err) = service.add_peer(peer) {
        return Err(anyhow!("esp-now broadcast peer failed: {err}"));
    }
    ESPNOW_SERVICE
        .set(service)
        .map_err(|_| anyhow!("esp-now service initialized concurrently"))?;
    ESPNOW_SERVICE
        .get()
        .ok_or_else(|| anyhow!("esp-now service unavailable after init"))
}

fn espnow_peer_info() -> PeerInfo {
    let mut peer = PeerInfo::default();
    peer.peer_addr = ESPNOW_BROADCAST;
    peer.channel = 0; // use the active Wi-Fi channel
    peer.ifidx = raw_tx_interface();
    peer.encrypt = false;
    peer
}

/// Send a broadcast ESP-NOW payload. The caller supplies the complete binary
/// envelope; ESP-NOW v2 supports the full 1470-byte IDF limit.
pub fn send_espnow_broadcast(payload: &[u8]) -> Result<()> {
    const ESPNOW_MAX_DATA_LEN_V2: usize = 1470;
    if payload.is_empty() || payload.len() > ESPNOW_MAX_DATA_LEN_V2 {
        bail!("ESP-NOW payload length must be 1..={ESPNOW_MAX_DATA_LEN_V2}");
    }
    prepare_raw_tx(6)?;
    let service = ensure_espnow()?;
    if let Err(first) = service.send(ESPNOW_BROADCAST, payload) {
        // Main can change between STA/AP/NAN ownership while the service is
        // alive. ESP-NOW peers retain the interface selected at add time, so
        // refresh the broadcast peer once before reporting a real send error.
        service
            .mod_peer(espnow_peer_info())
            .map_err(|err| anyhow!("esp-now peer refresh failed after {first}: {err}"))?;
        service
            .send(ESPNOW_BROADCAST, payload)
            .map_err(|err| anyhow!("esp-now send failed after peer refresh: {err}"))?;
    }
    RAW_TX_TOTAL.fetch_add(1, Ordering::Relaxed);
    telemetry::record_packet("wifi", Direction::Tx, payload, "source=espnow_broadcast");
    Ok(())
}

pub fn send_raw_action_payload_to(destination: [u8; 6], payload: &[u8]) -> Result<()> {
    send_raw_action_payload_to_with_options(destination, payload, true, None)
}

fn send_raw_action_payload_to_with_options(
    destination: [u8; 6],
    payload: &[u8],
    en_sys_seq: bool,
    tx_if: Option<sys::wifi_interface_t>,
) -> Result<()> {
    // NAN already initialized and owns the raw monitor/channel. Re-running
    // esp_wifi_set_channel from every transport packet returns ESP_ERR_INVALID_STATE
    // on IDF 6.x and aborts the stream. Only initialize the bearer when NAN is
    // not active (standalone raw-NAN diagnostic mode).
    if !super::nan::raw_tx_active() {
        ensure_raw_wifi_started(6)?;
    }
    let frame = custom_raw_action_frame_with_bssid_for(
        destination,
        super::nan::selected_cluster_bssid().unwrap_or(destination),
        payload,
        tx_if,
    )?;
    raw_tx_frame_on(&frame, en_sys_seq, tx_if)?;
    RAW_TX_TOTAL.fetch_add(1, Ordering::Relaxed);
    telemetry::record_packet(
        "wifi",
        Direction::Tx,
        payload,
        format!(
            "source=raw_command_response dst={}",
            format_mac(destination)
        ),
    );
    Ok(())
}

pub fn send_data_payload_to(destination: [u8; 6], payload: &[u8]) -> Result<()> {
    prepare_raw_tx(6)?;
    let frame = dmesh_data_frame(destination, None, payload)?;
    raw_tx_frame(&frame, true)?;
    RAW_TX_TOTAL.fetch_add(1, Ordering::Relaxed);
    telemetry::record_packet(
        "wifi",
        Direction::Tx,
        payload,
        format!(
            "source=data_command_response dst={}",
            format_mac(destination)
        ),
    );
    Ok(())
}

pub fn send_response_payload_to(
    response: WifiResponsePath,
    destination: [u8; 6],
    payload: &[u8],
) -> Result<()> {
    match response {
        WifiResponsePath::Action => send_raw_action_payload_to(destination, payload),
        WifiResponsePath::Data => send_data_payload_to(destination, payload),
    }
}

pub fn forward_console_notification(line: &str) {
    if WIFI_NOTIFY_FORWARDING.swap(true, Ordering::Acquire) {
        return;
    }
    let result = (|| -> Result<()> {
        let peer = last_command_peer().context("no wifi command peer known")?;
        let response = last_response_path();
        let payload = crate::transports::encode_log_packet(line);
        send_response_payload_to(response, peer, &payload)
    })();
    if result.is_err() {
        RAW_CMD_DROPPED.fetch_add(1, Ordering::Relaxed);
    }
    WIFI_NOTIFY_FORWARDING.store(false, Ordering::Release);
}

#[allow(dead_code)]
pub fn send_to_last_command_peer(payload: &[u8]) -> Result<()> {
    let peer = last_command_peer().context("no raw wifi command peer known")?;
    send_raw_action_payload_to(peer, payload)
}

pub fn take_raw_command() -> Option<RawWifiCommand> {
    raw_command_queue().lock().ok()?.pop_front()
}

/// Receive an ESP-NOW-style custom action payload. Terminal CBOR records are
/// retained for the lora1 session gateway; all other records are dispatched by
/// Main and answered unicast on the same action bearer.
pub fn observe_raw_action_payload(source: [u8; 6], payload: &[u8], rssi: i32) {
    telemetry::record_log(format!(
        "event type=wifi.raw_action_rx peer={} len={}",
        format_mac(source),
        payload.len()
    ));
    telemetry::record_packet("wifi", Direction::Rx, payload, "source=raw_action");
    // Object-store envelopes use the same bearer-independent format on NAN
    // action and data frames.  Dispatch them before the command/diagnostic
    // paths so a DRS2 transport packet is not mistaken for a text command.
    RAW_OBJECT_ACTION_ATTEMPTS.fetch_add(1, Ordering::Relaxed);
    let mut prefix = 0u32;
    for byte in payload.iter().take(4) {
        prefix = (prefix << 8) | u32::from(*byte);
    }
    RAW_OBJECT_ACTION_LAST_LEN.store(payload.len() as u32, Ordering::Relaxed);
    RAW_OBJECT_ACTION_LAST_PREFIX.store(prefix, Ordering::Relaxed);
    if super::nan::object_service_observe_action(payload) {
        RAW_OBJECT_ACTION_ACCEPTED.fetch_add(1, Ordering::Relaxed);
        telemetry::record_log(format!(
            "event type=wifi.object_action_rx peer={} len={}",
            format_mac(source),
            payload.len()
        ));
        return;
    }
    if observe_bench_stream(payload) {
        return;
    }
    if is_wifi_terminal_payload(payload) {
        let response = RawWifiResponse {
            local_us: unsafe { sys::esp_timer_get_time().max(0) as u64 },
            source,
            payload: payload.to_vec(),
        };
        if let Ok(mut history) = raw_response_history().lock() {
            if history.len() >= RAW_RESPONSE_HISTORY_MAX {
                history.pop_front();
            }
            history.push_back(response);
        }
        return;
    }
    // The NAN exchange only creates this serverless session. Each subsequent
    // ESP-NOW-style command refreshes a short idle lease, so a burst of work
    // stays awake but an idle target naturally returns to its duty schedule.
    super::mode::request_targeted_wake(5_000);
    enqueue_command(source, payload, rssi, WifiResponsePath::Action);
}

/// Consume the bounded diagnostic stream used for transport throughput tests.
/// This deliberately lives below the command/object-store layers: each action
/// frame is self-describing and the receiver only accounts for bytes.
fn observe_bench_stream(payload: &[u8]) -> bool {
    if payload.len() < 8 || payload[..4] != BENCH_STREAM_MAGIC {
        return false;
    }
    BENCH_RX_SEEN.fetch_add(1, Ordering::Relaxed);
    let Ok((header, stream, used)) = decode_bench_stream(payload) else {
        BENCH_RX_DECODE_ERRORS.fetch_add(1, Ordering::Relaxed);
        return true;
    };
    let end = stream.offset.saturating_add(stream.data.len() as u64);
    let encoded_len = used;
    // Some ESP-IDF receive paths retain the 802.11 FCS after the vendor
    // payload. `custom_raw_action_payload` strips it when the CRC is
    // verifiable, but accept the four-byte form as well for chips/drivers
    // that expose an unchecked monitor trailer.
    if payload.len() != encoded_len && payload.len() != encoded_len + 4 {
        BENCH_RX_LENGTH_ERRORS.fetch_add(1, Ordering::Relaxed);
        return true;
    }
    if stream.fin {
        BENCH_RX_EXPECTED_BYTES.store(end as u32, Ordering::Relaxed);
        BENCH_RX_EXPECTED_FRAMES.store(
            header.packet_number.saturating_add(1),
            Ordering::Relaxed,
        );
    }
    let frames = BENCH_RX_FRAMES.fetch_add(1, Ordering::Relaxed).saturating_add(1);
    let before = BENCH_RX_BYTES.fetch_max(end as u32, Ordering::Relaxed);
    BENCH_RX_LAST_SEQ.store(header.packet_number, Ordering::Relaxed);
    let delay_us = BENCH_RX_DELAY_US.load(Ordering::Relaxed);
    if delay_us != 0 && (before / 4096) != ((end as u32) / 4096) {
        task_delay(Duration::from_micros(u64::from(delay_us)));
    }
    let total = BENCH_RX_EXPECTED_BYTES.load(Ordering::Relaxed);
    telemetry::record_log(format!(
        "event type=bench.transport_rx pn={} bytes={} frames={} total={}",
        header.packet_number,
        end,
        frames,
        total
    ));
    true
}

fn bench_stats() -> String {
    format!(
        "bench_obj attempts={} accepted={} bench_rx bytes={} frames={} expected_bytes={} expected_frames={} last_seq={} delay_us={} seen={} decode_errors={} length_errors={}",
        RAW_OBJECT_ACTION_ATTEMPTS.load(Ordering::Relaxed),
        RAW_OBJECT_ACTION_ACCEPTED.load(Ordering::Relaxed),
        BENCH_RX_BYTES.load(Ordering::Relaxed),
        BENCH_RX_FRAMES.load(Ordering::Relaxed),
        BENCH_RX_EXPECTED_BYTES.load(Ordering::Relaxed),
        BENCH_RX_EXPECTED_FRAMES.load(Ordering::Relaxed),
        BENCH_RX_LAST_SEQ.load(Ordering::Relaxed),
        BENCH_RX_DELAY_US.load(Ordering::Relaxed),
        BENCH_RX_SEEN.load(Ordering::Relaxed),
        BENCH_RX_DECODE_ERRORS.load(Ordering::Relaxed),
        BENCH_RX_LENGTH_ERRORS.load(Ordering::Relaxed),
    )
}

fn bench_reset(delay_us: u32) {
    BENCH_RX_BYTES.store(0, Ordering::Relaxed);
    BENCH_RX_FRAMES.store(0, Ordering::Relaxed);
    BENCH_RX_LAST_SEQ.store(0, Ordering::Relaxed);
    BENCH_RX_EXPECTED_BYTES.store(0, Ordering::Relaxed);
    BENCH_RX_EXPECTED_FRAMES.store(0, Ordering::Relaxed);
    BENCH_RX_DELAY_US.store(delay_us, Ordering::Relaxed);
    BENCH_RX_SEEN.store(0, Ordering::Relaxed);
    BENCH_RX_DECODE_ERRORS.store(0, Ordering::Relaxed);
    BENCH_RX_LENGTH_ERRORS.store(0, Ordering::Relaxed);
}

fn bench_stream_send(
    destination: [u8; 6],
    total_bytes: usize,
    delay_us: u32,
    en_sys_seq: bool,
    tx_if: Option<sys::wifi_interface_t>,
) -> Result<String> {
    if total_bytes == 0 || total_bytes > 16 * 1024 * 1024 {
        bail!("bench bytes must be in 1..=16777216");
    }
    if !super::nan::raw_tx_active() {
        ensure_raw_wifi_started(6)?;
    }
    let started = unsafe { sys::esp_timer_get_time().max(0) as u64 };
    let frame_count = total_bytes.div_ceil(BENCH_STREAM_DATA_MAX);
    for seq in 0..frame_count {
        let offset = seq * BENCH_STREAM_DATA_MAX;
        let data_len = (total_bytes - offset).min(BENCH_STREAM_DATA_MAX);
        let encoded_ptr = core::ptr::addr_of_mut!(BENCH_TX_ENCODED);
        let data_ptr = core::ptr::addr_of_mut!(BENCH_TX_DATA);
        let (encoded, data) = unsafe {
            (
                core::slice::from_raw_parts_mut(encoded_ptr.cast::<u8>(), RAW_ACTION_MAX_PAYLOAD),
                core::slice::from_raw_parts_mut(data_ptr.cast::<u8>(), BENCH_STREAM_DATA_MAX),
            )
        };
        for index in 0..data_len {
            data[index] = ((offset + index) & 0xff) as u8;
        }
        let n = encode_bench_stream(
            seq as u32,
            offset as u64,
            seq + 1 == frame_count,
            &data[..data_len],
            encoded,
        )
        .map_err(|error| anyhow!("benchmark stream encode: {error:?}"))?;
        let mut sent = false;
        let mut last_error = None;
        for _attempt in 0..20 {
            match send_raw_action_payload_to_with_options(
                destination,
                &encoded[..n],
                en_sys_seq,
                tx_if,
            ) {
                Ok(()) => {
                    sent = true;
                    break;
                }
                Err(err) => {
                    last_error = Some(err);
                    task_delay(Duration::from_millis(5));
                }
            }
        }
        if !sent {
            return Err(last_error.unwrap_or_else(|| anyhow!("benchmark transmit failed")));
        }
        // esp_wifi_80211_tx is asynchronous and its bounded TX queue can
        // return ESP_ERR_INVALID_ARG/STATE when a long burst is submitted
        // without yielding. One RTOS tick keeps NAN ownership intact while
        // avoiding an unbounded busy loop in the benchmark.
        task_delay(Duration::from_millis(1));
        if delay_us != 0 {
            task_delay(Duration::from_micros(u64::from(delay_us)));
        }
    }
    let elapsed_ms = (unsafe { sys::esp_timer_get_time().max(0) as u64 } - started) / 1000;
    Ok(format!(
        "bench_stream sent_bytes={} frames={} elapsed_ms={} delay_us={} dst={}",
        total_bytes, frame_count, elapsed_ms, delay_us, format_mac(destination)
    ))
}

fn now_ms() -> u64 {
    unsafe { sys::esp_timer_get_time().max(0) as u64 / 1_000 }
}

fn start_udp_status_probe(server: &str, port: u16, timeout_ms: u32) -> Result<String> {
    let address = server
        .parse::<Ipv4Addr>()
        .map_err(|error| anyhow!("UDP status server must be IPv4: {error}"))?;
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.set_nonblocking(true)?;
    let peer = SocketAddrV4::new(address, port);
    let nonce = udp_status_nonce();
    let mut request = [0u8; UDP_STATUS_REQUEST_LEN];
    encode_udp_status_request(nonce, &mut request);
    let sent_bytes = socket.send_to(&request, peer)?;
    let mut state = udp_status_probe_state()
        .lock()
        .map_err(|_| anyhow!("UDP status probe state lock poisoned"))?;
    if state.is_some() {
        bail!("UDP status probe already active");
    }
    *state = Some(UdpStatusProbe {
        socket,
        peer: SocketAddr::V4(peer),
        server: server.to_owned(),
        port,
        started_ms: now_ms(),
        timeout_ms,
        nonce,
        sent_bytes,
        response: Box::new([0u8; 128]),
    });
    Ok(format!(
        "wifi udp_status_probe started=true server={} port={} nonce={} sent_bytes={} timeout_ms={}",
        server, port, nonce, sent_bytes, timeout_ms
    ))
}

pub fn poll_udp_status_probe() {
    let mut probe = match udp_status_probe_state().lock() {
        Ok(mut state) => state.take(),
        Err(_) => return,
    };
    let Some(mut probe_value) = probe.take() else { return };
    let result = match probe_value.socket.recv_from(&mut probe_value.response[..]) {
        Ok((received, peer)) if peer == probe_value.peer && received == UDP_STATUS_RESPONSE_LEN
            && probe_value.response[..4] == UDP_STATUS_MAGIC
            && probe_value.response[4] == UDP_STATUS_VERSION
            && probe_value.response[5] == UDP_STATUS_RESPONSE
            && u64::from_be_bytes(probe_value.response[6..14].try_into().unwrap()) == probe_value.nonce =>
        {
            let elapsed = now_ms().saturating_sub(probe_value.started_ms);
            let server_uptime = u64::from_be_bytes(probe_value.response[14..22].try_into().unwrap());
            Some(format!(
                "wifi udp_status_probe ok=true server={} port={} nonce={} sent_bytes={} received_bytes={} server_uptime_ms={} elapsed_ms={}",
                probe_value.server, probe_value.port, probe_value.nonce, probe_value.sent_bytes,
                received, server_uptime, elapsed
            ))
        }
        Ok((received, peer)) => Some(format!(
            "wifi udp_status_probe ok=false server={} port={} nonce={} peer={} received_bytes={} error=invalid_response",
            probe_value.server, probe_value.port, probe_value.nonce, peer, received
        )),
        Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::Interrupted) => {
            if now_ms().saturating_sub(probe_value.started_ms) >= u64::from(probe_value.timeout_ms) {
                Some(format!(
                    "wifi udp_status_probe ok=false server={} port={} nonce={} sent_bytes={} error=timeout elapsed_ms={}",
                    probe_value.server, probe_value.port, probe_value.nonce, probe_value.sent_bytes,
                    now_ms().saturating_sub(probe_value.started_ms)
                ))
            } else {
                None
            }
        }
        Err(error) => Some(format!(
            "wifi udp_status_probe ok=false server={} port={} nonce={} error=recv:{}",
            probe_value.server, probe_value.port, probe_value.nonce, error
        )),
    };
    if let Some(result) = result {
        if let Ok(mut last) = udp_status_probe_last().lock() { *last = result.clone(); }
        telemetry::record_log(format!("event type=wifi.udp_status_probe {result}"));
    } else if let Ok(mut state) = udp_status_probe_state().lock() {
        *state = Some(probe_value);
    }
}

fn start_udp_status_server(port: u16) -> Result<String> {
    let socket = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port))?;
    socket.set_nonblocking(true)?;
    let mut state = udp_status_server_state()
        .lock()
        .map_err(|_| anyhow!("UDP status server state lock poisoned"))?;
    if state.is_some() { bail!("UDP status server already active"); }
    *state = Some(UdpStatusServer {
        socket,
        port,
        requests: 0,
        responses: 0,
        last_peer: None,
        last_sent: 0,
    });
    let result = format!("wifi udp_status_server started=true port={port}");
    if let Ok(mut last) = udp_status_server_last().lock() { *last = result.clone(); }
    Ok(result)
}

pub fn poll_udp_status_server() {
    let mut server = match udp_status_server_state().lock() {
        Ok(mut state) => state.take(),
        Err(_) => return,
    };
    let Some(mut server_value) = server.take() else { return };
    let mut request = [0u8; 128];
    match server_value.socket.recv_from(&mut request) {
        Ok((received, peer)) => {
            if received == UDP_STATUS_REQUEST_LEN
                && request[..4] == UDP_STATUS_MAGIC
                && request[4] == UDP_STATUS_VERSION
                && request[5] == UDP_STATUS_REQUEST
            {
                let nonce = u64::from_be_bytes(request[6..14].try_into().unwrap());
                let mut response = [0u8; UDP_STATUS_RESPONSE_LEN];
                encode_udp_status_response(nonce, &mut response);
                server_value.requests = server_value.requests.saturating_add(1);
                server_value.last_peer = Some(peer);
                telemetry::record_log(format!(
                    "event type=wifi.udp_status_server request=true peer={} bytes={received}",
                    peer,
                ));
                match server_value.socket.send_to(&response, peer) {
                    Ok(sent) => {
                        server_value.responses = server_value.responses.saturating_add(1);
                        server_value.last_sent = sent;
                        telemetry::record_log(format!(
                            "event type=wifi.udp_status_server response=true peer={} bytes={sent}",
                            peer,
                        ));
                    }
                    Err(error) => telemetry::record_log(format!(
                        "event type=wifi.udp_status_server send_error peer={} error={}", peer, error
                    )),
                }
            } else {
                telemetry::record_log(format!(
                    "event type=wifi.udp_status_server invalid_request peer={} bytes={}", peer, received
                ));
            }
        }
        Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::Interrupted) => {}
        Err(error) => telemetry::record_log(format!(
            "event type=wifi.udp_status_server recv_error error={}", error
        )),
    }
    if let Ok(mut state) = udp_status_server_state().lock() { *state = Some(server_value); }
}

fn udp_status_probe_status() -> String {
    let active = udp_status_probe_state().lock().map(|state| state.is_some()).unwrap_or(false);
    let last = udp_status_probe_last().lock().map(|value| value.clone()).unwrap_or_else(|_| "state_lock_poisoned".to_owned());
    format!("active={active} last={last}")
}

fn udp_status_server_status() -> String {
    let state = udp_status_server_state().lock().ok();
    match state.as_deref().and_then(|value| value.as_ref()) {
        Some(server) => format!(
            "active=true port={} requests={} responses={} last_peer={} last_sent={}",
            server.port,
            server.requests,
            server.responses,
            server.last_peer.map(|peer| peer.to_string()).unwrap_or_else(|| "none".to_owned()),
            server.last_sent,
        ),
        None => udp_status_server_last().lock().map(|value| value.clone()).unwrap_or_else(|_| "state_lock_poisoned".to_owned()),
    }
}

/// Start a non-blocking, read-only UDP HELLO probe. The socket is polled from
/// Main's normal loop; this command never waits for the network or performs
/// any flash/object operation.
fn encode_udp_hello(model: u8, target: u8, dry_run: bool, out: &mut [u8]) -> Result<usize> {
    let mut hello = [0u8; UDP_HELLO_LEN];
    hello[0] = model;
    hello[71] = target;
    hello[89] = 0x07 | if dry_run { 0x08 } else { 0 };
    let mut drs = [0u8; 8 + UDP_HELLO_LEN];
    drs[..4].copy_from_slice(&DRS2_MAGIC.to_be_bytes());
    drs[4..6].copy_from_slice(&DRS2_FRAME_HELLO.to_be_bytes());
    drs[6..8].copy_from_slice(&(UDP_HELLO_LEN as u16).to_be_bytes());
    drs[8..].copy_from_slice(&hello);
    let header = ShortHeader {
        flags: FLAG_FIXED,
        dcid: ConnectionId::new(1).unwrap(),
        packet_number: 0,
        packet_number_len: 2,
    };
    let header_len = header.encode(out).map_err(|error| anyhow!("HELLO header: {error:?}"))?;
    let frame_len = Frame::Stream(StreamFrame { id: UDP_HELLO_STREAM, offset: 0, fin: true, data: &drs })
        .encode(&mut out[header_len..])
        .map_err(|error| anyhow!("HELLO frame: {error:?}"))?;
    Ok(header_len + frame_len)
}

struct UdpManifestProbe<'a> { dcid: ConnectionId, payload: &'a [u8] }

fn decode_udp_manifest(input: &[u8]) -> Result<UdpManifestProbe<'_>> {
    let (header, header_len) = ShortHeader::decode(input).map_err(|error| anyhow!("header: {error:?}"))?;
    let (frame, _) = decode_frame(&input[header_len..]).map_err(|error| anyhow!("frame: {error:?}"))?;
    let Frame::Stream(stream) = frame else { bail!("manifest response was not a stream") };
    if stream.id != UDP_MANIFEST_STREAM || stream.offset != 0 || stream.data.len() < 8 {
        bail!("invalid manifest stream");
    }
    if u32::from_be_bytes(stream.data[..4].try_into()?) != DRS2_MAGIC
        || u16::from_be_bytes(stream.data[4..6].try_into()?) != DRS2_FRAME_MANIFEST
    { bail!("invalid manifest frame"); }
    let length = u16::from_be_bytes(stream.data[6..8].try_into()?) as usize;
    if stream.data.len() > 8 + length { bail!("manifest response overran declared length"); }
    Ok(UdpManifestProbe { dcid: header.dcid, payload: &stream.data[8..] })
}

fn start_udp_hello_probe(server: &str, port: u16, timeout_ms: u32, target: u8) -> Result<String> {
    let address = server
        .parse::<Ipv4Addr>()
        .map_err(|error| anyhow!("UDP server must be an IPv4 address: {error}"))?;
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.set_nonblocking(true)?;
    let mut packet = [0u8; 256];
    let packet_len = encode_udp_hello(1, target, false, &mut packet)
        .map_err(|error| anyhow!("UDP HELLO encode failed: {error:?}"))?;
    let peer = SocketAddrV4::new(address, port);
    let sent_bytes = socket.send_to(&packet[..packet_len], peer)?;
    socket.connect(peer)?;
    let mut state = udp_hello_probe_state()
        .lock()
        .map_err(|_| anyhow!("UDP HELLO state lock poisoned"))?;
    if state.is_some() {
        bail!("UDP HELLO probe already active");
    }
    *state = Some(UdpHelloProbe {
        socket,
        server: server.to_owned(),
        port,
        target,
        started_ms: now_ms(),
        timeout_ms,
        sent_bytes,
        response: Box::new([0u8; 2048]),
    });
    Ok(format!(
        "wifi udp_hello started=true server={} port={} target={} sent_bytes={} timeout_ms={}",
        server, port, target, sent_bytes, timeout_ms
    ))
}

/// Poll the non-blocking UDP HELLO probe. This is deliberately separate from
/// command dispatch so a slow or unreachable server cannot block UART/Main.
pub fn poll_udp_hello() {
    let mut probe = match udp_hello_probe_state().lock() {
        Ok(mut state) => state.take(),
        Err(_) => return,
    };
    let Some(mut probe_value) = probe.take() else { return };
    let result = match probe_value.socket.recv(&mut probe_value.response[..]) {
        Ok(received) => match decode_udp_manifest(&probe_value.response[..received]) {
            Ok(manifest) => Some(format!(
                "wifi udp_hello ok=true server={} port={} target={} sent_bytes={} received_bytes={} response_dcid={} manifest_bytes={} elapsed_ms={}",
                probe_value.server,
                probe_value.port,
                probe_value.target,
                probe_value.sent_bytes,
                received,
                manifest.dcid.value(),
                manifest.payload.len(),
                now_ms().saturating_sub(probe_value.started_ms)
            )),
            Err(error) => Some(format!(
                "wifi udp_hello ok=false server={} port={} error=manifest_decode:{error:?}",
                probe_value.server, probe_value.port
            )),
        },
        Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::Interrupted) => {
            if now_ms().saturating_sub(probe_value.started_ms) >= u64::from(probe_value.timeout_ms) {
                Some(format!(
                    "wifi udp_hello ok=false server={} port={} error=timeout elapsed_ms={}",
                    probe_value.server,
                    probe_value.port,
                    now_ms().saturating_sub(probe_value.started_ms)
                ))
            } else {
                None
            }
        }
        Err(error) => Some(format!(
            "wifi udp_hello ok=false server={} port={} error=recv:{error}",
            probe_value.server, probe_value.port
        )),
    };
    if let Some(result) = result {
        if let Ok(mut last) = udp_hello_probe_last().lock() {
            *last = result.clone();
        }
        telemetry::record_log(format!("event type=wifi.udp_hello {}", result));
    } else if let Ok(mut state) = udp_hello_probe_state().lock() {
        *state = Some(probe_value);
    }
}

fn encode_udp_manifest_ok(header: ShortHeader, out: &mut [u8; 256]) -> Result<usize> {
    let mut body = [0u8; 8];
    body[..4].copy_from_slice(&DRS2_MAGIC.to_be_bytes());
    body[4..6].copy_from_slice(&DRS2_FRAME_MANIFEST_OK.to_be_bytes());
    let mut p = header.encode(out).map_err(|error| anyhow!("UDP manifest header: {error:?}"))?;
    p += Frame::Stream(StreamFrame { id: 0, offset: 0, fin: true, data: &body })
        .encode(&mut out[p..])
        .map_err(|error| anyhow!("UDP manifest response: {error:?}"))?;
    Ok(p)
}

/*
fn parse_dry_run_manifest(bytes: &[u8], retain_hashes: bool) -> Result<(u64, Vec<[u8; 4]>)> {
    // DRS2 manifest wire layout is documented in dmesh-object-store. Only the
    // size and block count are needed by a receive-only benchmark.
    if bytes.len() < 149 || u32::from_be_bytes(bytes[0..4].try_into()?) != DRS2_MAGIC
        || u16::from_be_bytes(bytes[4..6].try_into()?) != DRS2_FRAME_MANIFEST {
        bail!("invalid DRS2 manifest");
    }
    let body = &bytes[8..];
    if body.len() < 20 { bail!("truncated DRS2 manifest"); }
    let block_count = u32::from_be_bytes(body[12..16].try_into()?);
    let image_size = u32::from_be_bytes(body[16..20].try_into()?) as u64;
    if block_count == 0 || image_size == 0 { bail!("empty DRS2 manifest"); }
    // The manifest body has 149 bytes before the 4-byte block-hash prefixes:
    // fixed header (20), table digest (32), image SHA-256 (32), and the
    // 65-byte signing slot.  Include the eight-byte DRS2 frame header here.
    // Starting at 145 would read the final four bytes of the signature slot
    // and make every verified transfer fail at block zero.
    let hashes_start = 8 + 149;
    let hashes_len = (block_count as usize).checked_mul(4).ok_or_else(|| anyhow!("block hash table overflow"))?;
    if bytes.len() < hashes_start + hashes_len {
        bail!("truncated DRS2 block hash table");
    }
    if !retain_hashes {
        return Ok((image_size, Vec::new()));
    }
    let mut hashes = Vec::with_capacity(block_count as usize);
    for chunk in bytes[hashes_start..hashes_start + hashes_len].chunks_exact(4) {
        hashes.push([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }
    Ok((image_size, hashes))
}
*/

fn start_udp_dry_run(
    server: &str,
    port: u16,
    timeout_ms: u32,
    target: u8,
    verify_sha: bool,
    rx_window_packets: usize,
    write_flash: bool,
    settings: &crate::components::settings::SharedSettings,
) -> Result<String> {
    if !ip_sta_ready() {
        bail!("UDP dry-run requires STA to be ready (wait for wifi.sta state=ready and ip_up=true)");
    }
    let address = server.parse::<Ipv4Addr>()
        .map_err(|error| anyhow!("UDP server must be an IPv4 address: {error}"))?;
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.set_nonblocking(true)?;
    let mut hello = [0u8; 256];
    if write_flash && target == 7 {
        crate::components::module::prepare_udp_flash(settings)?;
    }
    let hello_len = encode_udp_hello(1, target, !write_flash, &mut hello)
        .map_err(|error| anyhow!("UDP HELLO encode failed: {error:?}"))?;
    let peer = SocketAddrV4::new(address, port);
    let mut state = udp_dry_run_state().lock().map_err(|_| anyhow!("UDP dry-run state lock poisoned"))?;
    if state.is_some() { bail!("UDP dry-run already active"); }
    let rx_window_packets = rx_window_packets.clamp(1, UDP_RX_WINDOW_MAX);
    *state = Some(UdpDryRun {
        socket, peer: SocketAddr::V4(peer), hello: Box::new(hello), hello_len, hello_sent: false,
        hello_sent_ms: 0, hello_retransmits: 0,
        server: server.to_owned(), port, target, started_ms: now_ms(), timeout_ms,
        packet: Box::new([0u8; UDP_PACKET_MAX]),
        phase: 1, acks_sent: 0, rx_window_packets, write_flash,
        receiver: crate::components::object_transfer::ObjectReceiver::new_with_sink(
            verify_sha,
            UDP_PACKET_MAX as u64,
            if write_flash && target == 6 {
                crate::components::object_transfer::TransferSink::Main(
                    crate::components::object_transfer::MainFlashSink::new(),
                )
            } else if write_flash {
                crate::components::object_transfer::TransferSink::Module(
                    crate::components::object_transfer::ModuleFlashSink::new(),
                )
            } else {
                crate::components::object_transfer::TransferSink::Null(
                    crate::components::object_transfer::NullSink,
                )
            },
        ),
    });
    Ok(format!("wifi udp_transfer started=true write_flash={} server={} port={} target={} verify_sha={} rx_window_packets={} hello_bytes={} timeout_ms={}", write_flash, server, port, target, verify_sha, rx_window_packets, hello_len, timeout_ms))
}

fn udp_dry_send(run: &UdpDryRun, packet: &[u8]) -> Result<()> {
    // lwIP can briefly run out of pbufs while the receive task is draining a
    // sustained stream.  Treat that as transient, but keep the retry bounded
    // so a genuinely broken socket still terminates the dry run.
    for attempt in 0..32 {
        match run.socket.send_to(packet, run.peer) {
            Ok(_) => return Ok(()),
            Err(error)
                if attempt < 31
                    && (error.kind() == ErrorKind::WouldBlock
                        || error.kind() == ErrorKind::Interrupted
                        || error.raw_os_error() == Some(12)
                        // lwIP reports an unresolved first-hop ARP lookup as
                        // EHOSTUNREACH.  The status-probe path normally
                        // primes this cache, but a fresh STA association can
                        // race the first QUIC hello; retry while ARP resolves.
                        || error.raw_os_error() == Some(118)) =>
            {
                // ESP-IDF's UDP send path can need several scheduler turns
                // to recycle pbufs while the receive loop is committing a
                // sustained QUIC-like stream. A 1 ms retry was too short and
                // made otherwise healthy 1 MiB STA transfers fail with
                // ENOMEM.
                task_delay(Duration::from_millis(5));
            }
            Err(error) => return Err(anyhow!("udp_send: {error}")),
        }
    }
    bail!("udp_send: retry limit exceeded")
}

/*
fn udp_dry_ack(run: &mut UdpDryRun, header: ShortHeader, stream_id: u64) -> Result<()> {
    let mut ack = [0u8; 256];
    let largest = run.endpoint.largest_received().ok_or_else(|| anyhow!("ACK range is empty"))?;
    let mut p = header.encode(&mut ack).map_err(|error| anyhow!("UDP ACK header: {error:?}"))?;
    p += Frame::AckRanges { largest, delay: 0, ranges: run.endpoint.received_packets }
        .encode(&mut ack[p..]).map_err(|error| anyhow!("UDP ACK frame: {error:?}"))?;
    p += Frame::MaxData(run.endpoint.receive.connection.max_data)
        .encode(&mut ack[p..]).map_err(|error| anyhow!("UDP MAX_DATA frame: {error:?}"))?;
    if let Some(max_data) = run.endpoint.receive.stream_max_data(stream_id) {
        p += Frame::MaxStreamData { id: stream_id, max: max_data }
            .encode(&mut ack[p..]).map_err(|error| anyhow!("UDP MAX_STREAM_DATA frame: {error:?}"))?;
    }
    let ack_len = p;
    udp_dry_send(run, &ack[..ack_len])?;
    run.acks_sent = run.acks_sent.saturating_add(1);
    Ok(())
}
*/

fn udp_dry_run_result(run: &UdpDryRun, ok: bool, error: &str) -> String {
    let stats = run.receiver.stats();
    let elapsed = now_ms().saturating_sub(run.started_ms).max(1);
    let bps = stats.image_bytes.saturating_mul(8_000) / elapsed;
    format!("wifi udp_transfer ok={} write_flash={} server={} port={} target={} verify_sha={} image_bytes={} image_size={} packets={} blocks={} sha_blocks={} duplicate_packets={} acks_sent={} hello_retransmits={} rx_window_packets={} elapsed_ms={} bitrate_kbps={} error={}", ok, run.write_flash, run.server, run.port, run.target, run.receiver.verify_sha(), stats.image_bytes, stats.image_size, stats.packets, stats.block_count, stats.sha_blocks, stats.duplicate_packets, run.acks_sent, run.hello_retransmits, run.rx_window_packets, elapsed, bps / 1000, error)
}

/*
fn consume_udp_dry_run_stream(run: &mut UdpDryRun) -> Result<bool> {
    loop {
        if run.stream_len < 8 { return Ok(false); }
        let magic = u32::from_be_bytes(run.stream[0..4].try_into()?);
        let kind = u16::from_be_bytes(run.stream[4..6].try_into()?);
        let length = u16::from_be_bytes(run.stream[6..8].try_into()?) as usize;
        let frame_len = 8 + length;
        if magic != DRS2_MAGIC || run.stream_len < frame_len { return Ok(false); }
        match kind {
            DRS2_FRAME_BLOCK => {
                if frame_len < 20 { bail!("truncated DRS2 block"); }
                let block_bytes = u32::from_be_bytes(run.stream[16..20].try_into()?) as usize;
                if block_bytes > frame_len - 20 { bail!("invalid DRS2 block length"); }
                if run.verify_sha {
                    let index = u32::from_be_bytes(run.stream[12..16].try_into()?) as usize;
                    let expected = run.block_hashes.get(index).ok_or_else(|| anyhow!("block hash index out of range index={index}"))?;
                    let digest = Sha256::digest(&run.stream[20..20 + block_bytes]);
                    if digest[..4] != expected[..] {
                        bail!("block SHA prefix mismatch index={index}");
                    }
                    run.sha_blocks = run.sha_blocks.saturating_add(1);
                }
                run.image_bytes = run.image_bytes.saturating_add(block_bytes as u64);
            }
            DRS2_FRAME_DONE => return Ok(true),
            _ => bail!("unexpected DRS2 stream frame kind={kind}"),
        }
        let remaining = run.stream_len - frame_len;
        run.stream.copy_within(frame_len..run.stream_len, 0);
        run.stream_len = remaining;
    }
}

fn append_udp_stream(run: &mut UdpDryRun, data: &[u8]) -> Result<()> {
    if data.len() > UDP_STREAM_BUFFER_MAX - run.stream_len {
        bail!("UDP stream buffer full capacity={} used={} append={}", UDP_STREAM_BUFFER_MAX, run.stream_len, data.len());
    }
    let end = run.stream_len + data.len();
    run.stream[run.stream_len..end].copy_from_slice(data);
    run.stream_len = end;
    Ok(())
}

fn append_udp_scratch(run: &mut UdpDryRun, len: usize) -> Result<()> {
    if len > UDP_PACKET_MAX { bail!("UDP scratch length too large bytes={len}"); }
    if len > UDP_STREAM_BUFFER_MAX - run.stream_len {
        bail!("UDP stream buffer full capacity={} used={} append={}", UDP_STREAM_BUFFER_MAX, run.stream_len, len);
    }
    let end = run.stream_len + len;
    run.stream[run.stream_len..end].copy_from_slice(&run.scratch[..len]);
    run.stream_len = end;
    Ok(())
}
*/

pub fn poll_udp_dry_run() {
    let mut run = match udp_dry_run_state().lock() { Ok(mut state) => state.take(), Err(_) => return };
    let Some(mut run_value) = run.take() else { return };
    let result: Result<Option<String>> = (|| {
        if !run_value.hello_sent {
            match run_value.socket.send_to(&run_value.hello[..run_value.hello_len], run_value.peer) {
                Ok(_) => {
                    run_value.hello_sent = true;
                    run_value.hello_sent_ms = now_ms();
                },
                Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::Interrupted) => return Ok(None),
                Err(error) => return Ok(Some(udp_dry_run_result(&run_value, false, &format!("hello_send:{error}")))),
            }
        }
        match run_value.socket.recv_from(&mut run_value.packet[..]) {
        Ok((received, peer)) if peer == run_value.peer => {
            let event = run_value.receiver.receive(&run_value.packet[..received])?;
            let mut ack = [0u8; 256];
            let ack_len = run_value.receiver.encode_ack(&mut ack, event)?;
            // Let lwIP recycle the RX/TX pbufs from the just-consumed
            // datagram before allocating the ACK. Without this yield, a
            // sustained object stream can exhaust the ESP-IDF UDP pool even
            // though the stop-and-wait peer has only one packet in flight.
            task_delay(Duration::from_millis(5));
            udp_dry_send(&run_value, &ack[..ack_len])?;
            run_value.acks_sent = run_value.acks_sent.saturating_add(1);
            if event.manifest_complete {
                let mut ok = [0u8; 256];
                let ok_len = encode_udp_manifest_ok(event.header, &mut ok)?;
                udp_dry_send(&run_value, &ok[..ok_len])?;
                run_value.phase = 2;
            }
            if event.complete {
                return Ok(Some(udp_dry_run_result(&run_value, true, "")));
            }
            Ok(None)
        }
        Ok((_received, peer)) => Err(anyhow!("UDP packet from unexpected peer={peer}")),
        Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::Interrupted) => {
            if run_value.phase == 1
                && run_value.receiver.stats().packets == 0
                && run_value.hello_retransmits < 3
                && now_ms().saturating_sub(run_value.hello_sent_ms) >= 100
            {
                if run_value.socket.send_to(&run_value.hello[..run_value.hello_len], run_value.peer).is_ok() {
                    run_value.hello_retransmits = run_value.hello_retransmits.saturating_add(1);
                    run_value.hello_sent_ms = now_ms();
                }
            }
            if now_ms().saturating_sub(run_value.started_ms) >= u64::from(run_value.timeout_ms) {
                Ok(Some(udp_dry_run_result(&run_value, false, "timeout")))
            } else { Ok(None) }
        }
        Err(error) => Ok(Some(udp_dry_run_result(&run_value, false, &format!("recv:{error}")))),
        }
    })();
    match result {
        Ok(Some(result)) => {
            if let Ok(mut last) = udp_dry_run_last().lock() { *last = result.clone(); }
            telemetry::record_log(format!("event type=wifi.udp_dry_run {result}"));
        }
        Ok(None) => if let Ok(mut state) = udp_dry_run_state().lock() { *state = Some(run_value); },
        Err(error) => {
            let result = udp_dry_run_result(&run_value, false, &format!("protocol:{error}"));
            if let Ok(mut last) = udp_dry_run_last().lock() { *last = result.clone(); }
            telemetry::record_log(format!("event type=wifi.udp_dry_run {result}"));
        }
    }
}

fn udp_dry_run_status() -> String {
    if let Ok(state) = udp_dry_run_state().lock() {
        if let Some(run) = state.as_ref() {
            let stats = run.receiver.stats();
            return format!(
                "wifi udp_transfer active=true write_flash={} server={} port={} phase={} packets={} stream_received={} image_bytes={} image_size={} blocks={} sha_blocks={} duplicate_packets={} acks_sent={} hello_retransmits={} verify_sha={} rx_window_packets={} pending_segments={}",
                run.write_flash, run.server, run.port, run.phase, stats.packets, stats.stream_received,
                stats.image_bytes, stats.image_size, stats.block_count, stats.sha_blocks,
                stats.duplicate_packets, run.acks_sent, run.hello_retransmits, run.receiver.verify_sha(),
                run.rx_window_packets, stats.pending_segments
            );
        }
    }
    udp_dry_run_last().lock().map(|last| last.clone()).unwrap_or_else(|_| "wifi udp_dry_run state lock poisoned".to_owned())
}

/// Keep the explicit IP STA lease alive after an AP-side or RF disconnect.
/// This is deliberately a small, nonblocking poll: the Wi-Fi task performs
/// association asynchronously and Main remains available for UART/control
/// traffic while it retries.
pub fn poll_ip_sta() {
    if IP_STA_STARTING.load(Ordering::Acquire)
        || !IP_STA_READY.load(Ordering::Acquire)
        || !super::mode::ip_transport_active()
    {
        return;
    }
    let now = now_ms();
    let now32 = now as u32;
    let next = IP_STA_NEXT_RECONNECT_MS.load(Ordering::Acquire);
    if next != 0 && (now32.wrapping_sub(next) as i32) < 0 {
        return;
    }
    IP_STA_NEXT_RECONNECT_MS.store(now32.wrapping_add(1_000), Ordering::Release);

    let netif = IP_STA_NETIF
        .get()
        .copied()
        .map(|value| value as *mut sys::esp_netif_t);
    let Some(netif) = netif else { return; };
    let associated = unsafe {
        let mut ap = sys::wifi_ap_record_t::default();
        sys::esp_wifi_sta_get_ap_info(&mut ap) == sys::ESP_OK
    };
    let netif_up = unsafe { sys::esp_netif_is_netif_up(netif) };
    let state = if associated && netif_up { 1 } else if associated { 2 } else { 3 };
    if IP_STA_LAST_STATE.swap(state, Ordering::AcqRel) != state {
        let mut ap = sys::wifi_ap_record_t::default();
        let mut info = sys::esp_netif_ip_info_t::default();
        let (bssid, rssi) = if associated && unsafe { sys::esp_wifi_sta_get_ap_info(&mut ap) == sys::ESP_OK } {
            (format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", ap.bssid[0], ap.bssid[1], ap.bssid[2], ap.bssid[3], ap.bssid[4], ap.bssid[5]), ap.rssi)
        } else { ("none".to_owned(), 0) };
        let ip = unsafe { sys::esp_netif_get_ip_info(netif, &mut info) };
        telemetry::record_log(format!(
            "event type=wifi.sta state={} associated={} ip_up={} ip={} bssid={} rssi={}",
            if state == 1 { "connected" } else if state == 2 { "associated" } else { "disconnected" },
            associated, netif_up, if ip == sys::ESP_OK { format_ipv4_u32(info.ip.addr) } else { "none".to_owned() }, bssid, rssi
        ));
    }
    if associated && netif_up {
        return;
    }

    IP_STA_READY.store(false, Ordering::Release);
    let mut mode = sys::wifi_mode_t_WIFI_MODE_NULL;
    unsafe {
        let _ = sys::esp_wifi_get_mode(&mut mode);
        if mode == sys::wifi_mode_t_WIFI_MODE_NULL {
            let _ = sys::esp_wifi_set_mode(sys::wifi_mode_t_WIFI_MODE_STA);
        }
        let _ = sys::esp_wifi_start();
        let _ = sys::esp_netif_set_default_netif(netif);
        let _ = sys::esp_wifi_set_ps(sys::wifi_ps_type_t_WIFI_PS_NONE);
        let result = sys::esp_wifi_connect();
        if result != sys::ESP_OK && result != sys::ESP_ERR_WIFI_CONN {
            telemetry::record_log(format!(
                "event type=wifi.sta_reconnect ok=false result=0x{result:x} associated={} netif_up={}",
                associated, netif_up
            ));
        } else {
            let count = IP_STA_RECONNECTS.fetch_add(1, Ordering::Relaxed) + 1;
            telemetry::record_log(format!(
                "event type=wifi.sta_reconnect ok=true count={} associated={} netif_up={}",
                count, associated, netif_up
            ));
        }
    }
}

fn udp_hello_status() -> String {
    let active = udp_hello_probe_state()
        .lock()
        .map(|state| state.is_some())
        .unwrap_or(false);
    let last = udp_hello_probe_last()
        .lock()
        .map(|value| value.clone())
        .unwrap_or_else(|_| "wifi udp_hello state lock poisoned".to_owned());
    format!("active={} last={}", active, last)
}


pub fn start_raw_monitor_mode(channel: u8, filter: &str) -> Result<()> {
    start_raw_only(channel, filter)
}

/// Apply the Wi-Fi MAC's internal BSSID comparator. This is a hardware
/// prefilter, unlike `RAW_FILTER_BSSID`, which discards a frame in software
/// after the promiscuous callback has already run.
pub(crate) fn set_hardware_bssid_filter(bssid: [u8; 6], enabled: bool) -> Result<()> {
    if !unsafe { dmesh_wifi_filter_supported() } {
        bail!("hardware Wi-Fi BSSID filter is unavailable")
    }
    // Raw-NAN owns the NAN receive policy, not the public STA/AP profiles.
    // Using the STA comparator here can leave NAN action frames outside the
    // intended hardware-filter path on targets that expose a separate NAN
    // interface slot (notably ESP32-C6).
    let rc = unsafe { dmesh_wifi_filter_set_bssid(2, bssid.as_ptr(), enabled) };
    if rc != 0 {
        bail!("hardware Wi-Fi BSSID filter failed result={rc}")
    }
    Ok(())
}

pub fn start_light_sleep_test_mode(mode: &str, channel: u8) -> Result<()> {
    let channel = channel.clamp(1, 13);
    match mode {
        "raw" | "mgmt" | "prom" | "prom_mgmt" => start_raw_only(channel, "dmesh"),
        "raw_data" | "data" | "prom_data" => start_raw_only(channel, "dmesh_data"),
        "sta" | "unconnected_sta" | "idle_sta" => {
            ensure_raw_wifi_started(channel)?;
            unsafe {
                esp_ok(sys::esp_wifi_set_promiscuous(false))?;
            }
            Ok(())
        }
        "ap" | "softap" | "open_ap" => start_light_sleep_test_ap(channel, 2_000),
        _ => bail!("unsupported wifi light sleep test mode={mode}"),
    }
}

pub fn start_light_sleep_test_ap(channel: u8, beacon_ms: u32) -> Result<()> {
    let ssid = default_direct_ssid()?;
    let beacon_tu = beacon_ms_to_tu(beacon_ms);
    low_level_start_ap_with_beacon_tu(&ssid, "", channel, beacon_tu)
}

fn start_raw_only(channel: u8, filter: &str) -> Result<()> {
    let filter_mode = parse_raw_filter(filter)?;
    RAW_FILTER_MODE.store(filter_mode, Ordering::Relaxed);
    ensure_raw_wifi_started(channel.clamp(1, 13))?;
    start_raw_after_wifi(channel, filter)
}

fn start_raw_after_wifi(channel: u8, filter: &str) -> Result<()> {
    let filter_mode = parse_raw_filter(filter)?;
    RAW_FILTER_MODE.store(filter_mode, Ordering::Relaxed);
    unsafe {
        let mut promisc_filter = sys::wifi_promiscuous_filter_t {
            filter_mask: promiscuous_filter_mask(filter_mode),
        };
        // Never retune an established STA/APSTA link here. The single ESP
        // radio must stay on the AP/NAN channel (channel 6 in the lab); an
        // unassociated APSTA profile is retuned by prepare_nan_channel below.
        esp_ok(sys::esp_wifi_set_promiscuous(false))?;
        esp_ok(sys::esp_wifi_set_promiscuous_rx_cb(Some(raw_wifi_cb)))?;
        esp_ok(sys::esp_wifi_set_promiscuous_filter(&mut promisc_filter))?;
        // ESP-IDF's control filter only selects 802.11 control subtypes; it
        // cannot match the DMesh body key. Keep control frames disabled and
        // apply the DMesh mesh-dst4 filter in the RX parser below.
        let ctrl_filter = sys::wifi_promiscuous_filter_t { filter_mask: 0 };
        esp_ok(sys::esp_wifi_set_promiscuous_ctrl_filter(&ctrl_filter))?;
        esp_ok(sys::esp_wifi_set_promiscuous(true))?;
    }
    prepare_nan_channel(channel.clamp(1, 13))?;
    RAW_MONITOR_RUNNING.store(true, Ordering::Relaxed);
    // A direct wifi mode transition bypasses NanCommand; let the NAN adapter
    // install its callback and prime the shared infrastructure SDF publisher.
    if super::mode::infra_mode() {
        super::nan::prime_infra_publish_for_wifi(channel)?;
    }
    Ok(())
}

pub fn set_power_save(mode: &str) -> Result<()> {
    let ps = match mode {
        "none" | "off" => sys::wifi_ps_type_t_WIFI_PS_NONE,
        "min" | "min_modem" => sys::wifi_ps_type_t_WIFI_PS_MIN_MODEM,
        "max" | "max_modem" => sys::wifi_ps_type_t_WIFI_PS_MAX_MODEM,
        _ => bail!("unsupported wifi ps={mode}"),
    };
    unsafe { esp_ok(sys::esp_wifi_set_ps(ps)) }
}

pub fn power_save_name() -> &'static str {
    let mut ps = sys::wifi_ps_type_t_WIFI_PS_NONE;
    let ret = unsafe { sys::esp_wifi_get_ps(&mut ps) };
    if ret != sys::ESP_OK {
        return "unknown";
    }
    match ps {
        x if x == sys::wifi_ps_type_t_WIFI_PS_NONE => "none",
        x if x == sys::wifi_ps_type_t_WIFI_PS_MIN_MODEM => "min",
        x if x == sys::wifi_ps_type_t_WIFI_PS_MAX_MODEM => "max",
        _ => "unknown",
    }
}

pub fn set_connectionless_wake_interval(interval_ms: u16) -> Result<()> {
    ensure_low_level_wifi()?;
    unsafe {
        let _ = sys::esp_wifi_set_promiscuous(false);
        let _ = sys::esp_wifi_stop();
        esp_ok(esp_wifi_connectionless_module_set_wake_interval(
            interval_ms,
        ))?;
    }
    WIFI_CONNECTIONLESS_WAKE_INTERVAL_MS.store(interval_ms as u32, Ordering::Relaxed);
    RAW_MONITOR_RUNNING.store(false, Ordering::Relaxed);
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum WifiMode {
    Off,
    StaIdle,
    ApIdle,
    IpSta,
    Raw,
    RawData,
    RawSta,
    RawStaData,
    RawAp,
    RawApData,
    RawApSta,
    RawApStaData,
}

impl Default for WifiMode {
    fn default() -> Self {
        Self::Off
    }
}

struct WifiCommand {
    mode: WifiMode,
    ssid: Option<String>,
    psk: Option<String>,
    timeout_ms: u32,
    settings: SharedSettings,
}

impl WifiCommand {
    fn new(settings: SharedSettings) -> Self {
        Self { mode: WifiMode::default(), ssid: None, psk: None, timeout_ms: 0, settings }
    }
}

impl CommandHandler for WifiCommand {
    fn name(&self) -> &'static str {
        "wifi"
    }

    fn handle(&mut self, request: &CommandRequest) -> Result<CommandResponse> {
        self.configure_raw_filter(request)?;
        if let Some(interval) = request
            .arg("wake_interval_ms")
            .or_else(|| request.arg("conn_wake_ms"))
        {
            let interval = parse_i32(interval)?.clamp(0, u16::MAX as i32) as u16;
            set_connectionless_wake_interval(interval)?;
            return Ok(CommandResponse::ok(format!(
                "wifi connectionless_wake_interval_ms={} {}",
                interval,
                raw_stats()
            )));
        }
        if request.arg("raw_stop").is_some() {
            stop_raw_monitor()?;
            return Ok(CommandResponse::ok("wifi raw monitor stopped"));
        }
        if request.arg("raw_response_history").is_some() {
            return Ok(CommandResponse::ok(raw_response_history_text()));
        }
        if request.arg("raw_stats").is_some() {
            return Ok(CommandResponse::ok(raw_stats()));
        }
        if request.arg("object_action_stats").is_some() {
            return Ok(CommandResponse::ok(format!(
                "wifi object_action attempts={} accepted={} last_len={} last_prefix={:08x}",
                RAW_OBJECT_ACTION_ATTEMPTS.load(Ordering::Relaxed),
                RAW_OBJECT_ACTION_ACCEPTED.load(Ordering::Relaxed),
                RAW_OBJECT_ACTION_LAST_LEN.load(Ordering::Relaxed),
                RAW_OBJECT_ACTION_LAST_PREFIX.load(Ordering::Relaxed),
            )));
        }
        if request.arg("bench_stats").is_some() {
            if request
                .arg("reset")
                .or_else(|| request.arg("bench_reset"))
                .map(parse_bool)
                .transpose()?
                .unwrap_or(false)
            {
                let delay_us = request
                    .arg_i32("delay_us")?
                    .unwrap_or(0)
                    .clamp(0, 1_000_000) as u32;
                bench_reset(delay_us);
            }
            return Ok(CommandResponse::ok(bench_stats()));
        }
        if request.arg("udp_hello_status").is_some() {
            return Ok(CommandResponse::ok(format!("wifi udp_hello {}", udp_hello_status())));
        }
        if request.arg("udp_dry_run_status").is_some() {
            return Ok(CommandResponse::ok(udp_dry_run_status()));
        }
        if request.arg("udp_status_probe_status").is_some() {
            return Ok(CommandResponse::ok(format!("wifi udp_status_probe {}", udp_status_probe_status())));
        }
        if request.arg("udp_status_server_status").is_some() {
            return Ok(CommandResponse::ok(format!("wifi udp_status_server {}", udp_status_server_status())));
        }
        if request
            .arg("udp_status_server")
            .map(parse_bool)
            .transpose()?
            .unwrap_or(false)
        {
            let port = request.arg_i32("port")?.unwrap_or(3338).clamp(1, u16::MAX as i32) as u16;
            return Ok(CommandResponse::ok(start_udp_status_server(port)?));
        }
        if request
            .arg("udp_status_probe")
            .map(parse_bool)
            .transpose()?
            .unwrap_or(false)
        {
            let server = request.arg("server").unwrap_or("10.78.0.1");
            let port = request.arg_i32("port")?.unwrap_or(3338).clamp(1, u16::MAX as i32) as u16;
            let timeout_ms = request.arg_i32("timeout_ms")?.or(request.arg_i32("timeout")?).unwrap_or(3_000).clamp(1, 60_000) as u32;
            return Ok(CommandResponse::ok(start_udp_status_probe(server, port, timeout_ms)?));
        }
        if request
            .arg("udp_dry_run")
            .map(parse_bool)
            .transpose()?
            .unwrap_or(false)
        {
            let server = request.arg("server").unwrap_or("10.78.0.1");
            let port = request.arg_i32("port")?.unwrap_or(3337).clamp(1, u16::MAX as i32) as u16;
            let timeout_ms = request.arg_i32("timeout_ms")?.or(request.arg_i32("timeout")?).unwrap_or(60_000).clamp(1, 300_000) as u32;
            let verify_sha = request.arg("verify_sha").map(parse_bool).transpose()?.unwrap_or(false);
            let rx_window_packets = self
                .settings
                .borrow()
                // A one-packet window is useful for bring-up but causes
                // stop-and-wait behavior and excessive retransmits on an
                // otherwise healthy STA link. Keep the protocol bounded,
                // while defaulting to a small multi-packet flight.
                .get_i32("udp.win", 8)?
                .clamp(1, UDP_RX_WINDOW_MAX as i32) as usize;
            let target = match request.arg("target").unwrap_or("main") {
                "main" => 6,
                "module" => 7,
                value => value.parse::<u8>().map_err(|error| anyhow!("invalid UDP target={value}: {error}"))?,
            };
            let write_flash = request.arg("write_flash").map(parse_bool).transpose()?.unwrap_or(false);
            return Ok(CommandResponse::ok(start_udp_dry_run(server, port, timeout_ms, target, verify_sha, rx_window_packets, write_flash, &self.settings)?));
        }
        if request.arg("udp_flash").map(parse_bool).transpose()?.unwrap_or(false) {
            let server = request.arg("server").unwrap_or("10.78.0.1");
            let port = request.arg_i32("port")?.unwrap_or(3337).clamp(1, u16::MAX as i32) as u16;
            let timeout_ms = request.arg_i32("timeout_ms")?.or(request.arg_i32("timeout")?).unwrap_or(300_000).clamp(1, 600_000) as u32;
            let verify_sha = request.arg("verify_sha").map(parse_bool).transpose()?.unwrap_or(true);
            let rx_window_packets = self.settings.borrow().get_i32("udp.win", 8)?.clamp(1, UDP_RX_WINDOW_MAX as i32) as usize;
            return Ok(CommandResponse::ok(start_udp_dry_run(server, port, timeout_ms, 7, verify_sha, rx_window_packets, true, &self.settings)?));
        }
        if request
            .arg("udp_hello")
            .map(parse_bool)
            .transpose()?
            .unwrap_or(false)
        {
            let server = request.arg("server").unwrap_or("10.78.0.1");
            let port = request
                .arg_i32("port")?
                .unwrap_or(3337)
                .clamp(1, u16::MAX as i32) as u16;
            let timeout_ms = request
                .arg_i32("timeout_ms")?
                .or(request.arg_i32("timeout")?)
                .unwrap_or(3_000)
                .clamp(1, 60_000) as u32;
            let target = match request.arg("target").unwrap_or("main") {
                "main" => 6,
                "module" => 7,
                value => value
                    .parse::<u8>()
                    .map_err(|error| anyhow!("invalid UDP target={value}: {error}"))?,
            };
            return Ok(CommandResponse::ok(start_udp_hello_probe(
                server,
                port,
                timeout_ms,
                target,
            )?));
        }
        if request
            .arg("bench_stream_send")
            .or_else(|| request.arg("bench_send"))
            .map(parse_bool)
            .transpose()?
            .unwrap_or(false)
        {
            let total_bytes = request
                .arg_i32("bytes")?
                .unwrap_or(2 * 1024 * 1024)
                .max(1) as usize;
            let delay_us = request
                .arg_i32("delay_us")?
                .unwrap_or(0)
                .clamp(0, 1_000_000) as u32;
            let destination = request
                .arg("dst")
                .or_else(|| request.arg("destination"))
                .map(parse_mac)
                .transpose()?
                .ok_or_else(|| anyhow!("bench_stream_send requires dst=<mac>"))?;
            let en_sys_seq = request
                .arg("sys_seq")
                .map(parse_bool)
                .transpose()?
                .unwrap_or(true);
            let tx_if = parse_raw_tx_interface(request.arg("tx_if").or_else(|| request.arg("wifi_if")))?;
            return Ok(CommandResponse::ok(bench_stream_send(
                destination,
                total_bytes,
                delay_us,
                en_sys_seq,
                tx_if,
            )?));
        }
        if request.arg("netif_stats").is_some() {
            return Ok(CommandResponse::ok(netif_probe_stats()));
        }
        if request
            .arg("netif_probe")
            .map(parse_bool)
            .transpose()?
            .unwrap_or(false)
        {
            let iface = request
                .arg("iface")
                .or_else(|| request.arg("if"))
                .unwrap_or("sta");
            start_netif_probe(iface)?;
            return Ok(CommandResponse::ok(format!(
                "wifi netif_probe started {}",
                netif_probe_stats()
            )));
        }
        if request
            .arg("raw_monitor")
            .or_else(|| request.arg("monitor"))
            .map(parse_bool)
            .transpose()?
            .unwrap_or(false)
        {
            self.start_raw_monitor(request)?;
            return Ok(CommandResponse::ok(format!(
                "wifi raw monitor started {}",
                raw_stats()
            )));
        }
        if let Some(raw) = request.arg("raw").or_else(|| request.arg("raw_tx")) {
            let channel = request
                .arg("channel")
                .map(parse_i32)
                .transpose()?
                .unwrap_or(6)
                .clamp(1, 13) as u8;
            prepare_raw_tx(channel)?;
            let bytes = parse_bytes(raw)?;
            raw_tx(&bytes, request)?;
            return Ok(CommandResponse::ok(format!(
                "wifi raw sent bytes={} {}",
                bytes.len(),
                raw_stats()
            )));
        }
        if let Some(payload) = request.arg("raw_data") {
            let channel = request
                .arg("channel")
                .map(parse_i32)
                .transpose()?
                .unwrap_or(6)
                .clamp(1, 13) as u8;
            let destination = request
                .arg("dst")
                .or_else(|| request.arg("destination"))
                .map(parse_mac)
                .transpose()?
                .unwrap_or(LMESH_IPV6_DISCOVERY_MULTICAST);
            let source = request
                .arg("src")
                .or_else(|| request.arg("source_mac"))
                .map(parse_mac)
                .transpose()?;
            let bssid = request
                .arg("bssid")
                .or_else(|| request.arg("ap_bssid"))
                .map(parse_mac)
                .transpose()?;
            let to_ap = request
                .arg("to_ap")
                .or_else(|| request.arg("tods"))
                .map(parse_bool)
                .transpose()?
                .unwrap_or(false);
            let ds = request.arg("ds").or_else(|| request.arg("data_ds"));
            prepare_raw_tx(channel)?;
            let frame = match (bssid, ds) {
                (Some(bssid), Some("none" | "nods" | "ibss")) => {
                    dmesh_data_frame_with_bssid(destination, source, bssid, payload.as_bytes())?
                }
                (Some(bssid), Some("to_ap" | "tods" | "sta_to_ap")) => {
                    dmesh_sta_to_ap_data_frame(destination, source, bssid, payload.as_bytes())?
                }
                (Some(bssid), Some("from_ap" | "fromds" | "ap_to_sta")) => {
                    dmesh_ap_to_sta_data_frame(destination, bssid, payload.as_bytes())?
                }
                (Some(_), Some(other)) => bail!("unsupported raw_data ds={other}"),
                (Some(bssid), None) if to_ap => {
                    dmesh_sta_to_ap_data_frame(destination, source, bssid, payload.as_bytes())?
                }
                (Some(bssid), None) => {
                    dmesh_data_frame_with_bssid(destination, source, bssid, payload.as_bytes())?
                }
                (None, _) => dmesh_data_frame(destination, source, payload.as_bytes())?,
            };
            let en_sys_seq = request.arg("sys_seq").map(parse_bool).transpose()?.unwrap_or(true);
            let tx_if = parse_raw_tx_interface(request.arg("tx_if").or_else(|| request.arg("wifi_if")))?;
            raw_tx_frame_on(&frame, en_sys_seq, tx_if)?;
            RAW_TX_TOTAL.fetch_add(1, Ordering::Relaxed);
            telemetry::record_packet("wifi", Direction::Tx, payload.as_bytes(), "raw_data=true");
            return Ok(CommandResponse::ok(format!(
                "wifi raw_data sent bytes={} {}",
                frame.len(),
                raw_stats()
            )));
        }
        if let Some(payload) = request
            .arg("raw_action_hex")
            .or_else(|| request.arg("raw_payload_hex"))
        {
            let channel = request
                .arg("channel")
                .map(parse_i32)
                .transpose()?
                .unwrap_or(6)
                .clamp(1, 13) as u8;
            let destination = request
                .arg("dst")
                .or_else(|| request.arg("destination"))
                .map(parse_mac)
                .transpose()?
                .unwrap_or(RAW_BROADCAST);
            prepare_raw_tx(channel)?;
            let payload = parse_bytes(payload)?;
            let en_sys_seq = request.arg("sys_seq").map(parse_bool).transpose()?.unwrap_or(true);
            let tx_if = parse_raw_tx_interface(request.arg("tx_if").or_else(|| request.arg("wifi_if")))?;
            let frame = custom_raw_action_frame_with_bssid_for(destination, destination, &payload, tx_if)?;
            raw_tx_frame_on(&frame, en_sys_seq, tx_if)?;
            RAW_TX_TOTAL.fetch_add(1, Ordering::Relaxed);
            telemetry::record_packet(
                "wifi",
                Direction::Tx,
                &payload,
                "raw_action=true binary=true",
            );
            return Ok(CommandResponse::ok(format!(
                "wifi raw_action sent bytes={} payload_bytes={} payload_max={} binary=true {}",
                frame.len(),
                payload.len(),
                RAW_ACTION_MAX_PAYLOAD,
                raw_stats()
            )));
        }
        if let Some(payload) = request
            .arg("raw_action")
            .or_else(|| request.arg("raw_payload"))
        {
            let channel = request
                .arg("channel")
                .map(parse_i32)
                .transpose()?
                .unwrap_or(6)
                .clamp(1, 13) as u8;
            let destination = request
                .arg("dst")
                .or_else(|| request.arg("destination"))
                .map(parse_mac)
                .transpose()?
                .unwrap_or(RAW_BROADCAST);
            prepare_raw_tx(channel)?;
            let en_sys_seq = request.arg("sys_seq").map(parse_bool).transpose()?.unwrap_or(true);
            let tx_if = parse_raw_tx_interface(request.arg("tx_if").or_else(|| request.arg("wifi_if")))?;
            let frame = custom_raw_action_frame_with_bssid_for(destination, destination, payload.as_bytes(), tx_if)?;
            raw_tx_frame_on(&frame, en_sys_seq, tx_if)?;
            RAW_TX_TOTAL.fetch_add(1, Ordering::Relaxed);
            telemetry::record_packet("wifi", Direction::Tx, payload.as_bytes(), "raw_action=true");
            return Ok(CommandResponse::ok(format!(
                "wifi raw_action sent bytes={} payload_max={} {}",
                frame.len(),
                RAW_ACTION_MAX_PAYLOAD,
                raw_stats()
            )));
        }
        if request.arg("stop").is_some() {
            self.stop()?;
            return Ok(CommandResponse::ok("wifi stopped"));
        }
        if request.arg("time").is_some() {
            bail!("wifi time/SNTP is not compiled; firmware does not start IP services");
        }
        if request.arg("scan").is_some() {
            return self.scan();
        }
        if let Some(mode) = request.arg("mode") {
            return self.start_mode(request, mode);
        }

        if let Some(timeout) = request.arg_i32("timeout")? {
            self.timeout_ms = timeout.max(0) as u32;
        }
        if request
            .arg("ap")
            .map(parse_bool)
            .transpose()?
            .unwrap_or(false)
        {
            self.start_ap(request)
        } else if request.arg("ssid").is_some() {
            self.start_sta(request)
        } else {
            Ok(CommandResponse::ok(format!(
                "wifi mode={:?} ssid={} timeout_ms={} {}",
                self.mode,
                self.ssid.as_deref().unwrap_or(""),
                self.timeout_ms,
                wifi_net_status()
            )))
        }
    }
}

impl WifiCommand {
    fn start_mode(&mut self, request: &CommandRequest, mode: &str) -> Result<CommandResponse> {
        let channel = command_channel(request, 6)?;
        match mode {
            "off" | "stop" | "stopped" => {
                self.stop()?;
                Ok(CommandResponse::ok("wifi mode=Off"))
            }
            "raw" => {
                start_raw_only(channel, mode_filter_name(request, "dmesh"))?;
                self.mode = WifiMode::Raw;
                Ok(CommandResponse::ok(format!(
                    "wifi mode=Raw channel={} {} {}",
                    channel,
                    wifi_net_status(),
                    raw_stats()
                )))
            }
            "raw_data" | "data_raw" => {
                start_raw_only(channel, mode_filter_name(request, "dmesh_data"))?;
                self.mode = WifiMode::RawData;
                Ok(CommandResponse::ok(format!(
                    "wifi mode=RawData sta=unassociated channel={} {} {}",
                    channel,
                    wifi_net_status(),
                    raw_stats()
                )))
            }
            "sta_idle" | "idle_sta" | "sta_only" | "station_idle" => {
                let ssid = request.arg("ssid").unwrap_or("DMesh-Idle");
                validate_wifi_string("ssid", ssid, 32)?;
                if let Some(bssid) = request
                    .arg("bssid")
                    .or_else(|| request.arg("ap_bssid"))
                    .map(parse_mac)
                    .transpose()?
                {
                    low_level_start_fake_sta(ssid, "", bssid, channel)?;
                } else {
                    low_level_start_sta_idle(ssid, channel)?;
                }
                reject_netif_probe_if_requested(request)?;
                self.mode = WifiMode::StaIdle;
                self.ssid = Some(ssid.to_string());
                self.psk = None;
                Ok(CommandResponse::ok(format!(
                    "wifi mode=StaIdle ssid={} channel={} connect=false {} {}",
                    ssid,
                    channel,
                    wifi_net_status(),
                    raw_stats()
                )))
            }
            "ap_idle" | "idle_ap" | "ap_only" | "softap_idle" => {
                let (ssid, psk) = self.ap_identity(request)?;
                let beacon_tu = command_beacon_tu(request)?;
                low_level_start_ap_with_beacon_tu(&ssid, &psk, channel, beacon_tu)?;
                reject_netif_probe_if_requested(request)?;
                self.mode = WifiMode::ApIdle;
                self.ssid = Some(ssid.clone());
                self.psk = Some(psk.clone());
                Ok(CommandResponse::ok(format!(
                    "wifi mode=ApIdle ssid={} channel={} beacon_tu={} auth={} {} {}",
                    ssid,
                    channel,
                    beacon_tu,
                    if psk.is_empty() { "open" } else { "wpa2" },
                    wifi_net_status(),
                    raw_stats()
                )))
            }
            "raw_sta" | "sta_raw" => {
                let ssid = request
                    .arg("ssid")
                    .context("wifi raw_sta requires ssid=...")?;
                let psk = request.arg("psk").unwrap_or("");
                let timeout_ms = self.command_timeout(request)?;
                validate_wifi_string("ssid", ssid, 32)?;
                validate_wifi_string("psk", psk, 64)?;
                low_level_start_sta(ssid, psk, channel)?;
                start_raw_after_wifi(channel, mode_filter_name(request, "dmesh"))?;
                if timeout_ms > 0 {
                    task_delay(Duration::from_millis(timeout_ms as u64));
                    disable_mesh_ip_services();
                }
                self.mode = WifiMode::RawSta;
                self.ssid = Some(ssid.to_string());
                self.psk = Some(psk.to_string());
                Ok(CommandResponse::ok(format!(
                    "wifi mode=RawSta ssid={} channel={} timeout_ms={} {} {}",
                    ssid,
                    channel,
                    timeout_ms,
                    wifi_net_status(),
                    raw_stats()
                )))
            }
            "raw_sta_data" | "sta_raw_data" | "raw_data_sta" | "data_raw_sta" => {
                if let Some(ssid) = request.arg("ssid") {
                    let psk = request.arg("psk").unwrap_or("");
                    let timeout_ms = self.command_timeout(request)?;
                    validate_wifi_string("ssid", ssid, 32)?;
                    validate_wifi_string("psk", psk, 64)?;
                    low_level_start_sta(ssid, psk, channel)?;
                    start_raw_after_wifi(channel, mode_filter_name(request, "dmesh_data"))?;
                    if timeout_ms > 0 {
                        task_delay(Duration::from_millis(timeout_ms as u64));
                        disable_mesh_ip_services();
                    }
                    self.mode = WifiMode::RawStaData;
                    self.ssid = Some(ssid.to_string());
                    self.psk = Some(psk.to_string());
                    Ok(CommandResponse::ok(format!(
                        "wifi mode=RawStaData ssid={} channel={} timeout_ms={} {} {}",
                        ssid,
                        channel,
                        timeout_ms,
                        wifi_net_status(),
                        raw_stats()
                    )))
                } else {
                    start_raw_only(channel, mode_filter_name(request, "dmesh_data"))?;
                    self.mode = WifiMode::RawStaData;
                    Ok(CommandResponse::ok(format!(
                        "wifi mode=RawStaData sta=unassociated channel={} {} {}",
                        channel,
                        wifi_net_status(),
                        raw_stats()
                    )))
                }
            }
            "fake_sta" | "sta_fake" | "raw_fake_sta" | "fake_sta_raw" => {
                let bssid = request
                    .arg("bssid")
                    .or_else(|| request.arg("ap_bssid"))
                    .map(parse_mac)
                    .transpose()?
                    .context("wifi fake_sta requires bssid=xx:xx:xx:xx:xx:xx")?;
                let ssid = request.arg("ssid").unwrap_or("DMesh-Fake");
                let psk = request.arg("psk").unwrap_or("");
                validate_wifi_string("ssid", ssid, 32)?;
                validate_wifi_string("psk", psk, 64)?;
                low_level_start_fake_sta(ssid, psk, bssid, channel)?;
                start_raw_after_wifi(channel, mode_filter_name(request, "dmesh"))?;
                self.mode = WifiMode::RawSta;
                self.ssid = Some(ssid.to_string());
                self.psk = Some(psk.to_string());
                Ok(CommandResponse::ok(format!(
                    "wifi mode=FakeSta ssid={} bssid={} channel={} connect=false {} {}",
                    ssid,
                    format_mac(bssid),
                    channel,
                    wifi_net_status(),
                    raw_stats()
                )))
            }
            "raw_ap" | "ap_raw" => {
                let (ssid, psk) = self.ap_identity(request)?;
                let beacon_tu = command_beacon_tu(request)?;
                low_level_start_ap_with_beacon_tu(&ssid, &psk, channel, beacon_tu)?;
                start_raw_after_wifi(channel, mode_filter_name(request, "dmesh"))?;
                self.mode = WifiMode::RawAp;
                self.ssid = Some(ssid.clone());
                self.psk = Some(psk.clone());
                Ok(CommandResponse::ok(format!(
                    "wifi mode=RawAp ssid={} channel={} beacon_tu={} auth={} {} {}",
                    ssid,
                    channel,
                    beacon_tu,
                    if psk.is_empty() { "open" } else { "wpa2" },
                    wifi_net_status(),
                    raw_stats()
                )))
            }
            "raw_ap_data" | "ap_raw_data" | "raw_data_ap" | "data_raw_ap" => {
                let (ssid, psk) = self.ap_identity(request)?;
                let beacon_tu = command_beacon_tu(request)?;
                low_level_start_ap_with_beacon_tu(&ssid, &psk, channel, beacon_tu)?;
                start_raw_after_wifi(channel, mode_filter_name(request, "dmesh_data"))?;
                self.mode = WifiMode::RawApData;
                self.ssid = Some(ssid.clone());
                self.psk = Some(psk.clone());
                Ok(CommandResponse::ok(format!(
                    "wifi mode=RawApData ssid={} channel={} beacon_tu={} auth={} {} {}",
                    ssid,
                    channel,
                    beacon_tu,
                    if psk.is_empty() { "open" } else { "wpa2" },
                    wifi_net_status(),
                    raw_stats()
                )))
            }
            "raw_ap_sta" | "raw_sta_ap" | "ap_sta_raw" | "sta_ap_raw" => {
                let (ap_ssid, ap_psk) = self.ap_identity(request)?;
                let sta_ssid = request
                    .arg("sta_ssid")
                    .or_else(|| request.arg("join_ssid"))
                    .or_else(|| request.arg("ssid"))
                    .context("wifi raw_ap_sta requires ssid=... or sta_ssid=...")?;
                let sta_psk = request
                    .arg("sta_psk")
                    .or_else(|| request.arg("join_psk"))
                    .or_else(|| request.arg("psk"))
                    .unwrap_or("");
                let timeout_ms = self.command_timeout(request)?;
                validate_wifi_string("ssid", sta_ssid, 32)?;
                validate_wifi_string("psk", sta_psk, 64)?;
                low_level_start_ap_sta(&ap_ssid, &ap_psk, sta_ssid, sta_psk, channel)?;
                start_raw_after_wifi(channel, mode_filter_name(request, "dmesh"))?;
                if timeout_ms > 0 {
                    task_delay(Duration::from_millis(timeout_ms as u64));
                    disable_mesh_ip_services();
                }
                self.mode = WifiMode::RawApSta;
                self.ssid = Some(ap_ssid.clone());
                self.psk = Some(ap_psk.clone());
                Ok(CommandResponse::ok(format!(
                    "wifi mode=RawApSta ap_ssid={} sta_ssid={} channel={} timeout_ms={} {} {}",
                    ap_ssid,
                    sta_ssid,
                    channel,
                    timeout_ms,
                    wifi_net_status(),
                    raw_stats()
                )))
            }
            "raw_ap_sta_data" | "raw_sta_ap_data" | "ap_sta_raw_data" | "sta_ap_raw_data" => {
                let (ap_ssid, ap_psk) = self.ap_identity(request)?;
                let sta_ssid = request
                    .arg("sta_ssid")
                    .or_else(|| request.arg("join_ssid"))
                    .or_else(|| request.arg("ssid"))
                    .context("wifi raw_ap_sta_data requires ssid=... or sta_ssid=...")?;
                let sta_psk = request
                    .arg("sta_psk")
                    .or_else(|| request.arg("join_psk"))
                    .or_else(|| request.arg("psk"))
                    .unwrap_or("");
                let timeout_ms = self.command_timeout(request)?;
                validate_wifi_string("ssid", sta_ssid, 32)?;
                validate_wifi_string("psk", sta_psk, 64)?;
                low_level_start_ap_sta(&ap_ssid, &ap_psk, sta_ssid, sta_psk, channel)?;
                start_raw_after_wifi(channel, mode_filter_name(request, "dmesh_data"))?;
                if timeout_ms > 0 {
                    task_delay(Duration::from_millis(timeout_ms as u64));
                    disable_mesh_ip_services();
                }
                self.mode = WifiMode::RawApStaData;
                self.ssid = Some(ap_ssid.clone());
                self.psk = Some(ap_psk.clone());
                Ok(CommandResponse::ok(format!(
                    "wifi mode=RawApStaData ap_ssid={} sta_ssid={} channel={} timeout_ms={} {} {}",
                    ap_ssid,
                    sta_ssid,
                    channel,
                    timeout_ms,
                    wifi_net_status(),
                    raw_stats()
                )))
            }
            "sta" => self.start_sta(request),
            "ap" => self.start_ap(request),
            _ => bail!("unsupported wifi mode={mode}"),
        }
    }

fn start_sta(&mut self, request: &CommandRequest) -> Result<CommandResponse> {
        let ssid = request.arg("ssid").context("wifi sta requires ssid=...")?;
        let psk = request.arg("psk").unwrap_or("");
        let channel = command_channel(request, 6)?;
        validate_wifi_string("ssid", ssid, 32)?;
        validate_wifi_string("psk", psk, 64)?;
        self.ssid = Some(ssid.to_string());
        self.psk = Some(psk.to_string());

        let timeout_ms = self.command_timeout(request)?;
        let ip_mode = request
            .arg("ip")
            .or_else(|| request.arg("local_ip"))
            .is_some()
            || request.arg_bytes("ip").is_some()
            || request.arg_bytes("local_ip").is_some();
        if ip_mode {
            // Keep the bounded association sequence in the command context.
            // A detached worker could be starved behind the raw-NAN scheduler,
            // leaving only a static address with no STA attempt or failure.
            start_ip_sta_sync(request, ssid, psk, channel)?;
        } else {
            low_level_start_sta(ssid, psk, channel)?;
        }
        // IP STA is the recovery/update data plane. Starting the raw monitor
        // after it would replace the normal Wi-Fi receive path and make TCP
        // listeners unreachable. Raw STA remains the default when no IP was
        // requested.
        if !ip_mode {
            start_raw_after_wifi(channel, raw_filter_name())?;
        }
        if timeout_ms > 0 && !ip_mode {
            task_delay(Duration::from_millis(timeout_ms as u64));
            disable_mesh_ip_services();
        }
        self.mode = if ip_mode { WifiMode::IpSta } else { WifiMode::RawSta };
        Ok(CommandResponse::ok(format!(
            "wifi mode={} ssid={} channel={} timeout_ms={}{} {}",
            if ip_mode { "IpSta" } else { "RawSta" },
            self.ssid.as_deref().unwrap_or(""),
            channel,
            timeout_ms,
            if ip_mode { " ready=true" } else { "" },
            wifi_net_status()
    )))
}

    fn start_ap(&mut self, request: &CommandRequest) -> Result<CommandResponse> {
        let (ssid, psk) = self.ap_identity(request)?;
        let channel = command_channel(request, 6)?;
        self.ssid = Some(ssid.clone());
        self.psk = Some(psk.clone());

        let beacon_tu = command_beacon_tu(request)?;
        low_level_start_ap_with_beacon_tu(&ssid, &psk, channel, beacon_tu)?;
        start_raw_after_wifi(channel, raw_filter_name())?;
        self.mode = WifiMode::RawAp;
        Ok(CommandResponse::ok(format!(
            "wifi mode=RawAp ssid={} channel={} beacon_tu={} auth={} {}",
            self.ssid.as_deref().unwrap_or(""),
            channel,
            beacon_tu,
            if psk.is_empty() { "open" } else { "wpa2" },
            wifi_net_status()
        )))
    }

    fn scan(&mut self) -> Result<CommandResponse> {
        let aps = low_level_scan()?;
        let summary = aps
            .iter()
            .take(16)
            .map(|ap| format!("{}:{}:ch{}:auth{}", ap.ssid, ap.rssi, ap.channel, ap.auth))
            .collect::<Vec<_>>()
            .join(",");
        Ok(CommandResponse::ok(format!(
            "wifi scan count={} {}",
            aps.len(),
            summary
        )))
    }

    fn start_raw_monitor(&mut self, request: &CommandRequest) -> Result<()> {
        let channel = command_channel(request, 6)?;
        start_raw_only(channel, mode_filter_name(request, "dmesh"))?;
        self.mode = WifiMode::Raw;
        Ok(())
    }

    fn configure_raw_filter(&mut self, request: &CommandRequest) -> Result<()> {
        if let Some(filter) = request.arg("filter").or_else(|| request.arg("raw_filter")) {
            RAW_FILTER_MODE.store(parse_raw_filter(filter)?, Ordering::Relaxed);
        }
        if let Some(bssid) = request
            .arg("raw_bssid")
            .or_else(|| request.arg("bssid_filter"))
        {
            if bssid == "none" || bssid == "false" {
                RAW_FILTER_BSSID_ENABLED.store(false, Ordering::Relaxed);
            } else {
                let bssid = parse_mac(bssid)?;
                for (idx, byte) in bssid.iter().enumerate() {
                    RAW_FILTER_BSSID[idx].store(*byte, Ordering::Relaxed);
                }
                RAW_FILTER_BSSID_ENABLED.store(true, Ordering::Relaxed);
            }
        }
        Ok(())
    }

    fn stop(&mut self) -> Result<()> {
        low_level_stop_wifi()?;
        self.mode = WifiMode::Off;
        Ok(())
    }

    fn command_timeout(&mut self, request: &CommandRequest) -> Result<u32> {
        if let Some(timeout) = request.arg_i32("timeout")? {
            self.timeout_ms = timeout.max(0) as u32;
        }
        Ok(self.timeout_ms)
    }

    fn ap_identity(&self, request: &CommandRequest) -> Result<(String, String)> {
        let ssid = if let Some(ssid) = request.arg("ap_ssid").or_else(|| request.arg("ssid")) {
            ssid.to_string()
        } else {
            default_direct_ssid()?
        };
        let psk = request
            .arg("ap_psk")
            .or_else(|| request.arg("psk"))
            .unwrap_or("")
            .to_string();
        validate_wifi_string("ssid", &ssid, 32)?;
        validate_wifi_string("psk", &psk, 64)?;
        if !psk.is_empty() && psk.len() < 8 {
            bail!("AP psk must be empty or at least 8 bytes");
        }
        Ok((ssid, psk))
    }
}

/// Temporarily move Main from raw NAN to the IP STA data plane. This is used
/// only by the control-plane flasher; callers must later resume NAN through
/// mode::resume_from_ip_transport().
pub fn start_flash_sta(
    ssid: &str,
    psk: &str,
    ip: &str,
    gateway: &str,
    netmask: &str,
) -> Result<()> {
    let ip_bytes = parse_ipv4_bytes(ip, "local")?;
    let gateway_bytes = parse_ipv4_bytes(gateway, "gateway")?;
    let netmask_bytes = parse_ipv4_bytes(netmask, "netmask")?;
    let request = CommandRequest::new("wifi")
        .arg_pair("ssid", ssid)
        .arg_pair("psk", psk)
        .arg_bytes_pair("ip", &ip_bytes)
        .arg_bytes_pair("gw", &gateway_bytes)
        .arg_bytes_pair("mask", &netmask_bytes)
        .arg_pair("timeout", "0");
    start_ip_sta_sync(&request, ssid, psk, 0)
}

pub fn stop_flash_sta() {
    if let Ok(mut state) = udp_dry_run_state().lock() {
        if let Some(run) = state.take() {
            let result = udp_dry_run_result(&run, false, "cancelled: STA stopped");
            if let Ok(mut last) = udp_dry_run_last().lock() {
                *last = result;
            }
        }
    }
    IP_STA_READY.store(false, Ordering::Release);
    IP_STA_STARTING.store(false, Ordering::Release);
    IP_STA_NEXT_RECONNECT_MS.store(0, Ordering::Release);
    unsafe {
        let _ = sys::esp_wifi_disconnect();
        // Do not synchronously stop the driver from the UART command
        // dispatcher.  ESP-IDF can wait for the lwIP RX/TX task here while a
        // just-failed UDP hello is still unwinding, which strands the
        // dispatcher and prevents the public `mode raw_nan=true` recovery
        // command from returning.  The next raw-NAN start owns the normal
        // driver transition; disconnecting first is sufficient to release
        // the STA association without deadlocking control traffic.
    }
}

pub fn ip_sta_ready() -> bool {
    if IP_STA_READY.load(Ordering::Acquire) {
        return true;
    }

    // The association and static address can become valid through the IDF
    // event path before the STA worker gets its final scheduling turn.  Do a
    // non-blocking read of the same invariants used by the worker and latch
    // readiness so a UDP/TCP transfer is not rejected after the network is
    // already demonstrably usable.
    let Some(value) = IP_STA_NETIF.get().copied() else {
        return false;
    };
    let netif = value as *mut sys::esp_netif_t;
    let associated = unsafe {
        let mut ap = sys::wifi_ap_record_t::default();
        sys::esp_wifi_sta_get_ap_info(&mut ap) == sys::ESP_OK
    };
    let mut info = sys::esp_netif_ip_info_t::default();
    let ready = associated
        && unsafe { sys::esp_netif_get_ip_info(netif, &mut info) == sys::ESP_OK }
        && info.ip.addr != 0
        && unsafe { sys::esp_netif_is_netif_up(netif) };
    if ready {
        IP_STA_READY.store(true, Ordering::Release);
    }
    ready
}

fn command_channel(request: &CommandRequest, default: u8) -> Result<u8> {
    Ok(request
        .arg("channel")
        .map(parse_i32)
        .transpose()?
        .unwrap_or(default as i32)
        .clamp(1, 13) as u8)
}

fn mode_filter_name<'a>(request: &'a CommandRequest, default: &'a str) -> &'a str {
    request
        .arg("filter")
        .or_else(|| request.arg("raw_filter"))
        .unwrap_or(default)
}

#[derive(Debug)]
struct ScanAp {
    ssid: String,
    rssi: i8,
    channel: u8,
    auth: &'static str,
}

pub fn ensure_raw_wifi_started(channel: u8) -> Result<()> {
    ensure_low_level_wifi()?;
    unsafe {
        let mut mode = sys::wifi_mode_t_WIFI_MODE_NULL;
        let _ = sys::esp_wifi_get_mode(&mut mode);
        // A powered fallback owner runs SoftAP plus raw management/action
        // receive.  Do not turn that AP into STA merely to arm the sniffer.
        if mode == sys::wifi_mode_t_WIFI_MODE_NULL {
            esp_ok_allow_invalid_state(sys::esp_wifi_set_mode(sys::wifi_mode_t_WIFI_MODE_STA))?;
        }
        esp_ok_allow_invalid_state(sys::esp_wifi_start())?;
        // Channel selection is applied by start_raw_after_wifi after the
        // historical APSTA profile has been created.
        let _ = channel;
    }
    Ok(())
}

/// Prepare the raw NAN callback without disrupting an existing STA/AP link.
/// NAN shares the radio with the infrastructure profile; retuning a connected
/// STA here silently drops its association on several ESP-IDF targets.
pub fn prepare_nan_channel(channel: u8) -> Result<()> {
    unsafe {
        let mut mode = sys::wifi_mode_t_WIFI_MODE_NULL;
        let _ = sys::esp_wifi_get_mode(&mut mode);
        let associated = {
            let mut ap = sys::wifi_ap_record_t::default();
            sys::esp_wifi_sta_get_ap_info(&mut ap) == sys::ESP_OK
        };
        // Channel 6 is the 2.4 GHz social channel used by the NAN lab and is
        // the only channel assumed by the Linux/ESP cluster. These radios do
        // not switch quickly enough for useful per-frame channel hopping, and
        // hopping would defeat sleepy-device timing and waste power. A
        // SoftAP-only profile already owns its configured channel. An
        // unassociated APSTA profile can have been retuned by the STA scan,
        // so restore the requested channel before NAN injection; an
        // associated STA must remain on its AP channel.
        let unassociated_apsta = mode == sys::wifi_mode_t_WIFI_MODE_APSTA && !associated;
        if unassociated_apsta || (!associated && mode != sys::wifi_mode_t_WIFI_MODE_AP) {
            let mut current = 0_u8;
            let mut second = sys::wifi_second_chan_t_WIFI_SECOND_CHAN_NONE;
            let current_ok = sys::esp_wifi_get_channel(&mut current, &mut second) == sys::ESP_OK;
            if !current_ok || current != channel.clamp(1, 13) {
                esp_ok_allow_invalid_state(sys::esp_wifi_set_channel(
                    channel.clamp(1, 13),
                    sys::wifi_second_chan_t_WIFI_SECOND_CHAN_NONE,
                ))?;
            }
        }
    }
    Ok(())
}

/// Start the powered DMesh timing AP. It intentionally has no IP/netif
/// services; its beacons and raw action frames are the only mesh interface.
pub fn start_direct_ap_beacon_source(channel: u8, beacon_tu: u16) -> Result<String> {
    let ssid = default_direct_ssid()?;
    low_level_start_ap_with_beacon_tu(&ssid, "", channel, beacon_tu)?;
    Ok(ssid)
}

/// Stop the DMesh timing AP before returning to raw-NAN duty cycling.
pub fn stop_direct_ap_beacon_source() -> Result<()> {
    low_level_stop_wifi()
}

fn ensure_low_level_wifi() -> Result<()> {
    unsafe {
        // Keep lwIP/socket initialization independent from whether the
        // current radio profile is raw NAN or IP STA.  Flash TCP may be
        // requested after either profile has been running.
        esp_ok_allow_invalid_state(sys::esp_netif_init())?;
        // esp_netif_init() must precede the default event loop.  Reversing
        // these calls can leave lwIP's tcpip mailbox uninitialized; the first
        // socket operation then aborts with "tcpip_send_msg_wait_sem: Invalid
        // mbox".
        esp_ok_allow_invalid_state(sys::esp_event_loop_create_default())?;
        if !RAW_WIFI_INIT.swap(true, Ordering::SeqCst) {
            let mut cfg = wifi_init_config_default();
            let ret = sys::esp_wifi_init(&mut cfg);
            if ret != sys::ESP_OK && ret != sys::ESP_ERR_INVALID_STATE {
                RAW_WIFI_INIT.store(false, Ordering::SeqCst);
                esp_ok(ret)?;
            }
            let _ = sys::esp_wifi_set_storage(sys::wifi_storage_t_WIFI_STORAGE_RAM);
        }
    }
    Ok(())
}

/// Initialize the IDF IP stack even when Main normally runs raw NAN only.
///
/// This is deliberately separate from creating a Wi-Fi netif: it makes the
/// lwIP tcpip mailbox available before a later STA/recovery command starts a
/// BSD socket.  Delaying this until after a raw-radio transition can leave
/// the mailbox invalid on some IDF builds.
pub fn init_ip_stack() -> Result<()> {
    unsafe {
        esp_ok_allow_invalid_state(sys::esp_netif_init())?;
        esp_ok_allow_invalid_state(sys::esp_event_loop_create_default())?;
    }
    Ok(())
}

fn ensure_ip_sta_netif() -> Result<*mut sys::esp_netif_t> {
    if let Some(value) = IP_STA_NETIF.get() {
        return Ok(*value as *mut sys::esp_netif_t);
    }
    // The default helper creates and attaches the Wi-Fi netif driver. Ensure
    // esp_wifi_init has completed before creating it; otherwise the object
    // can expose valid IP bookkeeping while its TX attachment is inert.
    ensure_low_level_wifi()?;
    let value = unsafe {
        esp_ok_allow_invalid_state(sys::esp_netif_init())?;
        let netif = sys::esp_netif_create_default_wifi_sta();
        if netif.is_null() {
            return Err(anyhow!("failed to create STA IP netif"));
        }
        esp_ok(sys::esp_netif_set_default_netif(netif))?;
        netif as usize
    };
    let _ = IP_STA_NETIF.set(value);
    Ok(*IP_STA_NETIF.get().unwrap_or(&value) as *mut sys::esp_netif_t)
}

/// Prepare the default STA netif after the Wi-Fi driver is initialized, so
/// ESP-IDF can attach the actual station data driver at creation time.
pub fn prepare_ip_sta_netif() -> Result<()> {
    let _ = ensure_ip_sta_netif()?;
    Ok(())
}

fn parse_ipv4(value: &str, name: &str) -> Result<u32> {
    let address = value
        .parse::<Ipv4Addr>()
        .map_err(|error| anyhow!("invalid {name} address {value}: {error}"))?;
    // esp_netif_ip_info_t uses the lwIP/IDF htonl representation in its
    // u32 field (the same representation used by ESP_IP4TOADDR).
    Ok(u32::from_ne_bytes(address.octets()))
}

fn parse_ipv4_bytes(value: &str, name: &str) -> Result<[u8; 4]> {
    value
        .parse::<Ipv4Addr>()
        .map(|address| address.octets())
        .map_err(|error| anyhow!("invalid {name} address {value}: {error}"))
}

fn request_ipv4(request: &CommandRequest, key: &str, default: &str) -> Result<u32> {
    if let Some(bytes) = request.arg_bytes(key) {
        if bytes.len() != 4 {
            bail!("{key} must be a 4-byte IPv4 CBOR byte string, got {} bytes", bytes.len());
        }
        // The CBOR representation is network order.  esp_netif's u32 field
        // is the lwIP/IDF native representation, so preserve those octets.
        return Ok(u32::from_ne_bytes(bytes.try_into().unwrap()));
    }
    parse_ipv4(request.arg(key).unwrap_or(default), key)
}

fn start_ip_sta_async(
    request: CommandRequest,
    ssid: String,
    psk: String,
    channel: u8,
) -> Result<()> {
    if IP_STA_STARTING.swap(true, Ordering::AcqRel) {
        bail!("IP STA start already in progress");
    }
    thread::Builder::new()
        .name("wifi-sta-start".to_owned())
        .spawn(move || {
            let result = start_ip_sta_sync(&request, &ssid, &psk, channel);
            IP_STA_STARTING.store(false, Ordering::Release);
            match result {
                Ok(()) => {
                    let mut ap = sys::wifi_ap_record_t::default();
                    let mut info = sys::esp_netif_ip_info_t::default();
                    let (associated, ip_up) = IP_STA_NETIF
                        .get()
                        .copied()
                        .map(|value| unsafe {
                            let netif = value as *mut sys::esp_netif_t;
                            (
                                sys::esp_wifi_sta_get_ap_info(&mut ap) == sys::ESP_OK,
                                sys::esp_netif_get_ip_info(netif, &mut info) == sys::ESP_OK
                                    && sys::esp_netif_is_netif_up(netif),
                            )
                        })
                        .unwrap_or((false, false));
                    telemetry::record_log(format!(
                        "event type=wifi.sta state=connected associated={} ip_up={} ip={} gw={} mask={} bssid={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} rssi={}",
                        associated,
                        ip_up,
                        format_ipv4_u32(info.ip.addr),
                        format_ipv4_u32(info.gw.addr),
                        format_ipv4_u32(info.netmask.addr),
                        ap.bssid[0], ap.bssid[1], ap.bssid[2], ap.bssid[3], ap.bssid[4], ap.bssid[5],
                        ap.rssi,
                    ));
                }
                Err(error) => telemetry::record_log(format!(
                    "event type=wifi.sta state=failed associated=false ip_up=false message={}",
                    crate::commands::protocol::escape_value(&error.to_string())
                )),
            }
        })
        .map(|_| ())
        .map_err(|error| {
            IP_STA_STARTING.store(false, Ordering::Release);
            anyhow!("spawn STA worker: {error}")
        })
}

fn start_ip_sta_sync(request: &CommandRequest, ssid: &str, psk: &str, channel: u8) -> Result<()> {
    IP_STA_LAST_STATE.store(0, Ordering::Release);
    telemetry::record_log(format!("event type=wifi.sta phase=begin ssid={} channel={}", crate::commands::protocol::escape_value(ssid), channel));
    // Keep the Recovery ordering explicit at the handoff too.  The boot path
    // normally initializes these objects, but raw-NAN builds can be entered
    // before that path has completed on a warm reset; IDF treats repeated
    // init calls as INVALID_STATE and leaves the existing mailbox intact.
    init_ip_stack()?;
    // The lwIP/event loop and STA netif are created once during Main boot,
    // before raw NAN starts. Re-running esp_netif_init/event-loop creation
    // from this worker can block the IDF tcpip task while NAN is active.
    let netif = ensure_ip_sta_netif()?;
    // Raw-NAN mode may have changed the active/default netif since Main
    // created the STA object at boot.  `ip_up` can still be true while lwIP
    // has no default route for sockets, which surfaces as EHOSTUNREACH from
    // connect(). Publish the STA as the default again before configuring the
    // static address and opening the TCP data plane.
    esp_ok(unsafe { sys::esp_netif_set_default_netif(netif) })?;
    // Recovery creates the default STA netif before initializing the Wi-Fi
    // driver. Preserve that IDF ordering in Main: creating it after the raw
    // radio has already initialized can produce an associated STA with no
    // usable lwIP link, so ARP never reaches the AP.
    // Main normally owns a sleepy raw-NAN scheduler. IP STA is a dedicated
    // bulk-transfer mode, so stop that scheduler after the IP stack exists.
    super::mode::stop_for_ip_transport();
    // Let the STA scan for the AP.  Recovery uses channel 0 here as well;
    // forcing the raw-radio channel can prevent association when the host AP
    // was started on a different channel.
    // Let IDF scan for the named AP. The lab AP is fixed to channel 6, but
    // channel 0 is the proven Recovery/STA sequence and avoids leaving the
    // station in a raw-NAN channel state during the handoff.
    let _ = channel;
    configure_sta(ssid, psk, 0, None)?;

    if request.arg("ip").is_none() && request.arg_bytes("ip").is_none()
        && request.arg("local_ip").is_none()
    {
        bail!("wifi STA IP mode requires ip=... or a 4-byte ip CBOR value");
    }
    let mut info = sys::esp_netif_ip_info_t::default();
    info.ip.addr = request_ipv4(request, "ip", "0.0.0.0")?;
    info.gw.addr = request_ipv4(request, "gw", "10.78.0.1")?;
    // The DMesh local AP uses the shared 10.78.0.0/16 network.  Keep this
    // default in firmware so every STA command does not need to repeat a
    // transport detail; an explicit mask remains supported for diagnostics.
    info.netmask.addr = request_ipv4(request, "mask", "255.255.0.0")?;
    // Match Recovery's working C sequence: stop DHCP and install the static
    // address before esp_wifi_start(), then let the normal IDF Wi-Fi event
    // handler bring the netif up on association. This preserves the route and
    // ARP setup instead of reconstructing it after the link is already up.
    unsafe {
        esp_ok_allow_dhcp_already_stopped(sys::esp_netif_dhcpc_stop(netif))?;
        esp_ok(sys::esp_netif_set_ip_info(netif, &info))?;
        esp_ok(sys::esp_wifi_start())?;
        // A module dry-run is a bulk TCP session, just like Recovery. Do not
        // let modem power-save create multi-second gaps or collapse the TCP
        // congestion window while the module is receiving blocks.
        esp_ok(sys::esp_wifi_set_ps(sys::wifi_ps_type_t_WIFI_PS_NONE))?;
        let connect_ret = sys::esp_wifi_connect();
        telemetry::record_log(format!(
            "event type=wifi.sta attempt ssid={} channel={} bssid=auto connect_ret=0x{:x}",
            crate::commands::protocol::escape_value(ssid),
            0,
            connect_ret
        ));
        esp_ok(connect_ret)?;
    }
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    loop {
        let mut ap = sys::wifi_ap_record_t::default();
        let mut current = sys::esp_netif_ip_info_t::default();
        let associated = unsafe { sys::esp_wifi_sta_get_ap_info(&mut ap) == sys::ESP_OK };
        if associated {
            telemetry::record_log(format!(
                "event type=wifi.sta associated=true bssid={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} rssi={}",
                ap.bssid[0], ap.bssid[1], ap.bssid[2], ap.bssid[3], ap.bssid[4], ap.bssid[5], ap.rssi
            ));
        }
        if associated {
            // The default STA netif is created before esp_wifi_init(), just as
            // in Recovery. Reassert the default and static address after the
            // link-up event as well: on this IDF path the pre-start static
            // address is visible through esp_netif_get_ip_info(), but the
            // connected route is not published until the address is applied
            // to an already-up netif. Without this, BSD connect() returns
            // EHOSTUNREACH even though the STA is associated.
            esp_ok(unsafe { sys::esp_netif_set_default_netif(netif) })?;
            esp_ok(unsafe { sys::esp_netif_set_ip_info(netif, &info) })?;
            std::thread::sleep(Duration::from_millis(20));
            let stable = unsafe {
                sys::esp_netif_get_ip_info(netif, &mut current) == sys::ESP_OK
                    && current.ip.addr == info.ip.addr
                    && current.gw.addr == info.gw.addr
                    && current.netmask.addr == info.netmask.addr
                    && sys::esp_netif_is_netif_up(netif)
            };
            if !stable {
                continue;
            }
            esp_ok(unsafe { sys::esp_wifi_set_ps(sys::wifi_ps_type_t_WIFI_PS_NONE) })?;
            // Raw NAN discovery/action TX fixes this interface at its control
            // rate.  Restore normal rate control only after the STA is fully
            // started and associated; doing it before esp_wifi_start() is
            // rejected by IDF and leaves the data path at the raw-NAN rate.
            IP_STA_READY.store(true, Ordering::Release);
            // The IDF Wi-Fi event path can briefly report the old link state
            // immediately after the static address is installed.  Do not let
            // the first Main-loop poll call esp_wifi_connect() again and
            // tear down a freshly completed association; give the link a
            // bounded settling window before recovery is allowed to run.
            IP_STA_NEXT_RECONNECT_MS.store(
                now_ms().saturating_add(5_000) as u32,
                Ordering::Release,
            );
            break;
        }
        if std::time::Instant::now() >= deadline {
            bail!("STA association/IP timeout for ssid={ssid}");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    RAW_MONITOR_RUNNING.store(false, Ordering::Relaxed);
    WIFI_NETIF_PROBE_RUNNING.store(false, Ordering::Relaxed);
    Ok(())
}

fn disable_mesh_ip_services() {
    // No-op by design: this firmware profile does not create esp_netif objects
    // for raw mesh modes, so there is no DHCP or IP state to stop.
}

#[allow(dead_code)]
fn low_level_start_ap(ssid: &str, psk: &str, channel: u8) -> Result<()> {
    low_level_start_ap_with_beacon_tu(ssid, psk, channel, 100)
}

fn low_level_start_ap_with_beacon_tu(
    ssid: &str,
    psk: &str,
    channel: u8,
    beacon_tu: u16,
) -> Result<()> {
    unsafe {
        let _ = sys::esp_wifi_stop();
        let _ = sys::esp_wifi_set_promiscuous(false);
        // Keep the STA interface started alongside the SoftAP. The AP supplies
        // the 512-TU timing beacon, while raw NAN SDF/action injection uses
        // STA. In AP-only mode `esp_wifi_80211_tx(WIFI_IF_AP, ...)` accepts
        // the call but the injected NAN management frame is not observable by
        // another ESP receiver. AP+STA keeps both on the same configured
        // channel without creating an IP/association data path.
        esp_ok(sys::esp_wifi_set_mode(sys::wifi_mode_t_WIFI_MODE_APSTA))?;
        let mut ap = sys::wifi_ap_config_t::default();
        copy_cstr_bytes(&mut ap.ssid, ssid.as_bytes());
        copy_cstr_bytes(&mut ap.password, psk.as_bytes());
        ap.ssid_len = ssid.len().min(ap.ssid.len()) as u8;
        ap.channel = channel;
        ap.authmode = if psk.is_empty() {
            sys::wifi_auth_mode_t_WIFI_AUTH_OPEN
        } else {
            sys::wifi_auth_mode_t_WIFI_AUTH_WPA2_PSK
        };
        ap.max_connection = 4;
        ap.beacon_interval = beacon_tu;
        let mut conf = sys::wifi_config_t { ap };
        esp_ok(sys::esp_wifi_set_config(
            sys::wifi_interface_t_WIFI_IF_AP,
            &mut conf,
        ))?;
        esp_ok(sys::esp_wifi_start())?;
        disable_mesh_ip_services();
    }
    RAW_MONITOR_RUNNING.store(false, Ordering::Relaxed);
    WIFI_NETIF_PROBE_RUNNING.store(false, Ordering::Relaxed);
    Ok(())
}

fn beacon_ms_to_tu(beacon_ms: u32) -> u16 {
    // ESP-IDF stores SoftAP beacon_interval in 1024 us time units. Keep the
    // test helper in the common documented range while allowing a 2 s beacon.
    let tu = ((beacon_ms as u64 * 1000) / 1024).clamp(100, 60_000);
    tu as u16
}

fn command_beacon_tu(request: &CommandRequest) -> Result<u16> {
    let beacon_ms = request
        .arg("beacon_ms")
        .or_else(|| request.arg("beacon"))
        .map(parse_i32)
        .transpose()?
        .unwrap_or(102);
    Ok(beacon_ms_to_tu(beacon_ms.max(1) as u32))
}

fn configure_sta(ssid: &str, psk: &str, channel: u8, bssid: Option<[u8; 6]>) -> Result<()> {
    let _transition = wifi_driver_transition()
        .lock()
        .map_err(|_| anyhow!("Wi-Fi driver transition lock poisoned"))?;
    ensure_low_level_wifi()?;
    unsafe {
        let _ = sys::esp_wifi_disconnect();
        let _ = sys::esp_wifi_set_promiscuous(false);
        // Always perform the full stop/set-mode transition. Raw NAN uses the
        // same STA hardware profile but leaves monitor callbacks and channel
        // state behind; preserving a nominal STA mode here can associate
        // successfully while the normal lwIP TX path remains detached.
        let _ = sys::esp_wifi_stop();
        esp_ok(sys::esp_wifi_set_mode(sys::wifi_mode_t_WIFI_MODE_STA))?;
        let mut sta = sys::wifi_sta_config_t::default();
        copy_cstr_bytes(&mut sta.ssid, ssid.as_bytes());
        copy_cstr_bytes(&mut sta.password, psk.as_bytes());
        sta.channel = channel;
        if let Some(bssid) = bssid {
            sta.bssid_set = true;
            sta.bssid.copy_from_slice(&bssid);
        }
        sta.threshold.authmode = if psk.is_empty() {
            sys::wifi_auth_mode_t_WIFI_AUTH_OPEN
        } else {
            sys::wifi_auth_mode_t_WIFI_AUTH_WPA2_PSK
        };
        let mut conf = sys::wifi_config_t { sta };
        esp_ok(sys::esp_wifi_set_config(
            sys::wifi_interface_t_WIFI_IF_STA,
            &mut conf,
        ))?;
    }
    Ok(())
}

fn low_level_start_sta(ssid: &str, psk: &str, channel: u8) -> Result<()> {
    configure_sta(ssid, psk, channel, None)?;
    unsafe {
        esp_ok_allow_invalid_state(sys::esp_wifi_start())?;
        esp_ok(sys::esp_wifi_connect())?;
        disable_mesh_ip_services();
    }
    // Let the association complete before arming promiscuous/raw reception.
    // Starting the monitor immediately after esp_wifi_connect() can win the
    // channel-control race and leave the STA unassociated on ESP-IDF.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        let associated = unsafe {
            let mut ap = sys::wifi_ap_record_t::default();
            sys::esp_wifi_sta_get_ap_info(&mut ap) == sys::ESP_OK
        };
        if associated || std::time::Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    RAW_MONITOR_RUNNING.store(false, Ordering::Relaxed);
    WIFI_NETIF_PROBE_RUNNING.store(false, Ordering::Relaxed);
    Ok(())
}

fn low_level_start_sta_idle(ssid: &str, channel: u8) -> Result<()> {
    ensure_low_level_wifi()?;
    unsafe {
        let _ = sys::esp_wifi_disconnect();
        let _ = sys::esp_wifi_set_promiscuous(false);
        let _ = sys::esp_wifi_stop();
        esp_ok(sys::esp_wifi_set_mode(sys::wifi_mode_t_WIFI_MODE_STA))?;
        let mut sta = sys::wifi_sta_config_t::default();
        copy_cstr_bytes(&mut sta.ssid, ssid.as_bytes());
        sta.channel = channel;
        sta.threshold.authmode = sys::wifi_auth_mode_t_WIFI_AUTH_OPEN;
        let mut conf = sys::wifi_config_t { sta };
        esp_ok(sys::esp_wifi_set_config(
            sys::wifi_interface_t_WIFI_IF_STA,
            &mut conf,
        ))?;
        esp_ok(sys::esp_wifi_start())?;
        esp_ok_allow_invalid_state(sys::esp_wifi_set_channel(
            channel.clamp(1, 13),
            sys::wifi_second_chan_t_WIFI_SECOND_CHAN_NONE,
        ))?;
        disable_mesh_ip_services();
    }
    RAW_MONITOR_RUNNING.store(false, Ordering::Relaxed);
    WIFI_NETIF_PROBE_RUNNING.store(false, Ordering::Relaxed);
    Ok(())
}

fn low_level_start_fake_sta(ssid: &str, psk: &str, bssid: [u8; 6], channel: u8) -> Result<()> {
    ensure_low_level_wifi()?;
    unsafe {
        let _ = sys::esp_wifi_disconnect();
        let _ = sys::esp_wifi_stop();
        esp_ok(sys::esp_wifi_set_mode(sys::wifi_mode_t_WIFI_MODE_STA))?;
        let mut sta = sys::wifi_sta_config_t::default();
        copy_cstr_bytes(&mut sta.ssid, ssid.as_bytes());
        copy_cstr_bytes(&mut sta.password, psk.as_bytes());
        sta.bssid_set = true;
        sta.bssid.copy_from_slice(&bssid);
        sta.channel = channel;
        sta.threshold.authmode = if psk.is_empty() {
            sys::wifi_auth_mode_t_WIFI_AUTH_OPEN
        } else {
            sys::wifi_auth_mode_t_WIFI_AUTH_WPA2_PSK
        };
        let mut conf = sys::wifi_config_t { sta };
        esp_ok(sys::esp_wifi_set_config(
            sys::wifi_interface_t_WIFI_IF_STA,
            &mut conf,
        ))?;
        esp_ok(sys::esp_wifi_start())?;
        esp_ok_allow_invalid_state(sys::esp_wifi_set_channel(
            channel.clamp(1, 13),
            sys::wifi_second_chan_t_WIFI_SECOND_CHAN_NONE,
        ))?;
        disable_mesh_ip_services();
    }
    Ok(())
}

fn low_level_start_ap_sta(
    ap_ssid: &str,
    ap_psk: &str,
    sta_ssid: &str,
    sta_psk: &str,
    channel: u8,
) -> Result<()> {
    ensure_low_level_wifi()?;
    unsafe {
        let _ = sys::esp_wifi_disconnect();
        let _ = sys::esp_wifi_stop();
        esp_ok(sys::esp_wifi_set_mode(sys::wifi_mode_t_WIFI_MODE_APSTA))?;

        let mut ap = sys::wifi_ap_config_t::default();
        copy_cstr_bytes(&mut ap.ssid, ap_ssid.as_bytes());
        copy_cstr_bytes(&mut ap.password, ap_psk.as_bytes());
        ap.ssid_len = ap_ssid.len().min(ap.ssid.len()) as u8;
        ap.channel = channel;
        ap.authmode = if ap_psk.is_empty() {
            sys::wifi_auth_mode_t_WIFI_AUTH_OPEN
        } else {
            sys::wifi_auth_mode_t_WIFI_AUTH_WPA2_PSK
        };
        ap.max_connection = 4;
        ap.beacon_interval = 100;
        let mut ap_conf = sys::wifi_config_t { ap };
        esp_ok(sys::esp_wifi_set_config(
            sys::wifi_interface_t_WIFI_IF_AP,
            &mut ap_conf,
        ))?;

        let mut sta = sys::wifi_sta_config_t::default();
        copy_cstr_bytes(&mut sta.ssid, sta_ssid.as_bytes());
        copy_cstr_bytes(&mut sta.password, sta_psk.as_bytes());
        sta.channel = channel;
        sta.threshold.authmode = if sta_psk.is_empty() {
            sys::wifi_auth_mode_t_WIFI_AUTH_OPEN
        } else {
            sys::wifi_auth_mode_t_WIFI_AUTH_WPA2_PSK
        };
        let mut sta_conf = sys::wifi_config_t { sta };
        esp_ok(sys::esp_wifi_set_config(
            sys::wifi_interface_t_WIFI_IF_STA,
            &mut sta_conf,
        ))?;

        esp_ok(sys::esp_wifi_start())?;
        esp_ok(sys::esp_wifi_connect())?;
        disable_mesh_ip_services();
    }
    Ok(())
}

fn low_level_scan() -> Result<Vec<ScanAp>> {
    ensure_low_level_wifi()?;
    unsafe {
        let _ = sys::esp_wifi_stop();
        esp_ok(sys::esp_wifi_set_mode(sys::wifi_mode_t_WIFI_MODE_STA))?;
        esp_ok(sys::esp_wifi_start())?;
        esp_ok(sys::esp_wifi_scan_start(std::ptr::null(), true))?;
        let mut total = 0_u16;
        esp_ok(sys::esp_wifi_scan_get_ap_num(&mut total))?;
        let mut records = vec![sys::wifi_ap_record_t::default(); total.min(32) as usize];
        let mut count = records.len() as u16;
        if count > 0 {
            esp_ok(sys::esp_wifi_scan_get_ap_records(
                &mut count,
                records.as_mut_ptr(),
            ))?;
        }
        records.truncate(count as usize);
        Ok(records
            .iter()
            .map(|record| ScanAp {
                ssid: ssid_from_bytes(&record.ssid),
                rssi: record.rssi,
                channel: record.primary,
                auth: auth_name(record.authmode),
            })
            .collect())
    }
}

fn low_level_stop_wifi() -> Result<()> {
    let _ = set_hardware_bssid_filter([0; 6], false);
    unsafe {
        let _ = sys::esp_wifi_disconnect();
        let _ = sys::esp_wifi_set_promiscuous(false);
        let _ = sys::esp_wifi_internal_reg_rxcb(sys::wifi_interface_t_WIFI_IF_STA, None);
        let stopped = sys::esp_wifi_stop();
        if stopped != sys::ESP_OK && stopped != sys::ESP_ERR_WIFI_NOT_INIT {
            bail!("esp_wifi_stop failed err=0x{stopped:x}");
        }
        let deinitialized = sys::esp_wifi_deinit();
        if deinitialized != sys::ESP_OK && deinitialized != sys::ESP_ERR_WIFI_NOT_INIT {
            bail!("esp_wifi_deinit failed err=0x{deinitialized:x}");
        }
    }
    RAW_WIFI_INIT.store(false, Ordering::SeqCst);
    RAW_MONITOR_RUNNING.store(false, Ordering::Relaxed);
    WIFI_NETIF_PROBE_RUNNING.store(false, Ordering::Relaxed);
    Ok(())
}

fn prepare_raw_tx(channel: u8) -> Result<()> {
    let mut mode = sys::wifi_mode_t_WIFI_MODE_NULL;
    let ret = unsafe { sys::esp_wifi_get_mode(&mut mode) };
    if ret != sys::ESP_OK || mode == sys::wifi_mode_t_WIFI_MODE_NULL {
        ensure_raw_wifi_started(channel)?;
    }
    Ok(())
}

fn wifi_init_config_default() -> sys::wifi_init_config_t {
    sys::wifi_init_config_t {
        osi_funcs: std::ptr::addr_of_mut!(sys::g_wifi_osi_funcs),
        wpa_crypto_funcs: unsafe { sys::g_wifi_default_wpa_crypto_funcs },
        static_rx_buf_num: sys::CONFIG_ESP_WIFI_STATIC_RX_BUFFER_NUM as i32,
        dynamic_rx_buf_num: sys::CONFIG_ESP_WIFI_DYNAMIC_RX_BUFFER_NUM as i32,
        tx_buf_type: sys::CONFIG_ESP_WIFI_TX_BUFFER_TYPE as i32,
        static_tx_buf_num: sys::WIFI_STATIC_TX_BUFFER_NUM as i32,
        dynamic_tx_buf_num: sys::WIFI_DYNAMIC_TX_BUFFER_NUM as i32,
        rx_mgmt_buf_type: sys::CONFIG_ESP_WIFI_DYNAMIC_RX_MGMT_BUF as i32,
        rx_mgmt_buf_num: sys::WIFI_RX_MGMT_BUF_NUM_DEF as i32,
        cache_tx_buf_num: sys::WIFI_CACHE_TX_BUFFER_NUM as i32,
        csi_enable: sys::WIFI_CSI_ENABLED as i32,
        ampdu_rx_enable: sys::WIFI_AMPDU_RX_ENABLED as i32,
        // Keep management/NAN operation independent of AMPDU aggregation.
        // The ESP32-C6 driver has a known failure mode where an associated
        // STA receives frames but its first non-aggregated UDP response never
        // leaves the TX queue when AMPDU TX is enabled.
        ampdu_tx_enable: 0,
        amsdu_tx_enable: sys::WIFI_AMSDU_TX_ENABLED as i32,
        nvs_enable: sys::WIFI_NVS_ENABLED as i32,
        nano_enable: sys::WIFI_NANO_FORMAT_ENABLED as i32,
        rx_ba_win: sys::WIFI_DEFAULT_RX_BA_WIN as i32,
        wifi_task_core_id: sys::WIFI_TASK_CORE_ID as i32,
        beacon_max_len: sys::WIFI_SOFTAP_BEACON_MAX_LEN as i32,
        mgmt_sbuf_num: sys::WIFI_MGMT_SBUF_NUM as i32,
        feature_caps: sys::WIFI_FEATURE_CAPS as u64,
        sta_disconnected_pm: sys::WIFI_STA_DISCONNECTED_PM_ENABLED != 0,
        espnow_max_encrypt_num: sys::CONFIG_ESP_WIFI_ESPNOW_MAX_ENCRYPT_NUM as i32,
        tx_hetb_queue_num: sys::WIFI_TX_HETB_QUEUE_NUM as i32,
        dump_hesigb_enable: sys::WIFI_DUMP_HESIGB_ENABLED != 0,
        magic: sys::WIFI_INIT_CONFIG_MAGIC as i32,
    }
}

pub fn stop_raw_monitor() -> Result<()> {
    // Clear the comparator while the driver is still initialized.
    let _ = set_hardware_bssid_filter([0; 6], false);
    unsafe {
        let _ = sys::esp_wifi_set_promiscuous(false);
        let stopped = sys::esp_wifi_stop();
        if stopped != sys::ESP_OK
            && stopped != sys::ESP_ERR_INVALID_STATE
            && stopped != sys::ESP_ERR_WIFI_NOT_INIT
            && stopped != sys::ESP_ERR_WIFI_NOT_STARTED
        {
            bail!("esp_wifi_stop failed err=0x{stopped:x}");
        }
    }
    RAW_MONITOR_RUNNING.store(false, Ordering::Relaxed);
    Ok(())
}

/// Disable raw-NAN capture without stopping an already-running STA driver.
/// The esp-netif Wi-Fi attachment is stateful on ESP-IDF; preserving it is
/// required when switching an active raw-NAN STA into the IP data plane.
pub fn stop_raw_capture() -> Result<()> {
    let _ = set_hardware_bssid_filter([0; 6], false);
    unsafe { esp_ok(sys::esp_wifi_set_promiscuous(false))?; }
    RAW_MONITOR_RUNNING.store(false, Ordering::Relaxed);
    Ok(())
}

/// Stop raw Wi-Fi for a bounded raw-NAN sleep interval.
///
/// Stop raw Wi-Fi for an explicit light-sleep interval.
///
/// The classic ESP32 must fully tear down the driver before
/// `esp_light_sleep_start()`: retaining it leaves a Wi-Fi/interrupt watchdog
/// path active in the RTC sleep transition.  ESP32-S3 keeps the initialized
/// driver because repeatedly recreating it there has previously left UART0
/// unusable; the target-specific split is intentional.
pub fn stop_raw_wifi_for_sleep() -> Result<()> {
    let _transition = wifi_driver_transition()
        .lock()
        .map_err(|_| anyhow!("Wi-Fi driver transition lock poisoned"))?;
    // IP transport may claim ownership while the duty loop is waiting for
    // this transition lock. Do not stop the driver after that handoff.
    if super::mode::ip_transport_active() {
        return Ok(());
    }
    #[cfg(target_feature = "esp32s3ops")]
    {
        let _ = set_hardware_bssid_filter([0; 6], false);
        unsafe {
            let _ = sys::esp_wifi_disconnect();
            let _ = sys::esp_wifi_set_promiscuous(false);
            let _ = sys::esp_wifi_internal_reg_rxcb(sys::wifi_interface_t_WIFI_IF_STA, None);
            let stopped = sys::esp_wifi_stop();
            if stopped != sys::ESP_OK
                && stopped != sys::ESP_ERR_INVALID_STATE
                && stopped != sys::ESP_ERR_WIFI_NOT_INIT
                && stopped != sys::ESP_ERR_WIFI_NOT_STARTED
            {
                bail!("esp_wifi_stop failed err=0x{stopped:x}");
            }
        }
        RAW_MONITOR_RUNNING.store(false, Ordering::Relaxed);
        WIFI_NETIF_PROBE_RUNNING.store(false, Ordering::Relaxed);
        telemetry::record_log("event type=wifi.raw_sleep off=true driver_retained=true");
        return Ok(());
    }

    #[cfg(not(target_feature = "esp32s3ops"))]
    {
        low_level_stop_wifi()?;
        telemetry::record_log("event type=wifi.raw_sleep off=true driver_retained=false");
        Ok(())
    }
}

fn raw_tx(bytes: &[u8], request: &CommandRequest) -> Result<()> {
    if bytes.len() < 24 || bytes.len() > 1500 {
        bail!(
            "raw 802.11 frame length must be 24..=1500, got {}",
            bytes.len()
        );
    }
    let en_sys_seq = request
        .arg("sys_seq")
        .map(parse_bool)
        .transpose()?
        .unwrap_or(true);
    let tx_if = parse_raw_tx_interface(request.arg("tx_if").or_else(|| request.arg("wifi_if")))?;
    if let Some(rate) = request.arg("tx_rate") {
        configure_fixed_tx_rate(rate, tx_if.unwrap_or_else(raw_tx_interface), request.arg("disable_11b").map(parse_bool).transpose()?.unwrap_or(true))?;
    }
    raw_tx_frame_on(bytes, en_sys_seq, tx_if)?;
    RAW_TX_TOTAL.fetch_add(1, Ordering::Relaxed);
    telemetry::record_packet(
        "wifi",
        Direction::Tx,
        bytes,
        format!(
            "raw=true sys_seq={} subtype={}",
            en_sys_seq,
            frame_subtype(bytes)
        ),
    );
    Ok(())
}

pub(crate) fn configure_fixed_tx_rate(name: &str, iface: sys::wifi_interface_t, disable_11b: bool) -> Result<()> {
    let rate = match name.to_ascii_lowercase().as_str() {
        "6" | "6m" => sys::wifi_phy_rate_t_WIFI_PHY_RATE_6M,
        "9" | "9m" => sys::wifi_phy_rate_t_WIFI_PHY_RATE_9M,
        "12" | "12m" => sys::wifi_phy_rate_t_WIFI_PHY_RATE_12M,
        "18" | "18m" => sys::wifi_phy_rate_t_WIFI_PHY_RATE_18M,
        "24" | "24m" => sys::wifi_phy_rate_t_WIFI_PHY_RATE_24M,
        "36" | "36m" => sys::wifi_phy_rate_t_WIFI_PHY_RATE_36M,
        "48" | "48m" => sys::wifi_phy_rate_t_WIFI_PHY_RATE_48M,
        "54" | "54m" => sys::wifi_phy_rate_t_WIFI_PHY_RATE_54M,
        "auto" | "default" | "reset" => {
            unsafe {
                esp_ok(esp_wifi_internal_set_fix_rate(iface, false, sys::wifi_phy_rate_t_WIFI_PHY_RATE_12M))?;
                esp_ok(sys::esp_wifi_config_11b_rate(iface, false))?;
            }
            return Ok(());
        }
        other => bail!("unsupported tx_rate={other}; expected auto, 6, 9, 12, 18, 24, 36, 48, or 54"),
    };
    unsafe {
        esp_ok(esp_wifi_internal_set_fix_rate(iface, true, rate))?;
        esp_ok(sys::esp_wifi_config_11b_rate(iface, disable_11b))?;
    }
    Ok(())
}

fn raw_tx_frame(bytes: &[u8], en_sys_seq: bool) -> Result<()> {
    raw_tx_frame_on(bytes, en_sys_seq, None)
}

fn raw_tx_frame_on(
    bytes: &[u8],
    en_sys_seq: bool,
    requested: Option<sys::wifi_interface_t>,
) -> Result<()> {
    let iface = requested.unwrap_or_else(raw_tx_interface);
    unsafe {
        esp_ok(sys::esp_wifi_80211_tx(
            iface,
            bytes.as_ptr() as *const _,
            bytes.len() as i32,
            en_sys_seq,
        ))
    }
}

/// Select the active Wi-Fi interface for injected management/action frames.
///
/// AP-owner mode runs the driver as `WIFI_MODE_AP`, whereas the normal raw-NAN
/// window runs as STA. Callers must not hard-code STA or AP-owner NAN TX fails
/// with `ESP_ERR_WIFI_IF`.
pub(crate) fn raw_tx_interface() -> sys::wifi_interface_t {
    let mut mode = sys::wifi_mode_t_WIFI_MODE_NULL;
    let _ = unsafe { sys::esp_wifi_get_mode(&mut mode) };
    select_raw_tx_interface(mode)
}

fn select_raw_tx_interface(mode: sys::wifi_mode_t) -> sys::wifi_interface_t {
    if mode == sys::wifi_mode_t_WIFI_MODE_AP
        || mode == sys::wifi_mode_t_WIFI_MODE_APSTA
    {
        sys::wifi_interface_t_WIFI_IF_AP
    } else {
        sys::wifi_interface_t_WIFI_IF_STA
    }
}

/// APSTA's SoftAP injection path uses the driver's sequence allocator. This
/// is the default for autonomous NAN publications in the APSTA lab profile.
pub(crate) fn raw_tx_sys_seq() -> bool {
    true
}

fn parse_raw_tx_interface(value: Option<&str>) -> Result<Option<sys::wifi_interface_t>> {
    let Some(value) = value else { return Ok(None); };
    match value {
        "sta" | "STA" => Ok(Some(sys::wifi_interface_t_WIFI_IF_STA)),
        "ap" | "AP" | "softap" => Ok(Some(sys::wifi_interface_t_WIFI_IF_AP)),
        other => bail!("invalid tx_if={other}; expected sta or ap"),
    }
}

/// Return the MAC address belonging to the interface selected for injected
/// management/action frames. The 802.11 source address must match the active
/// interface: a SoftAP raw transmitter cannot advertise a STA source address.
pub(crate) fn raw_tx_source_mac() -> Result<[u8; 6]> {
    raw_tx_source_mac_for(None)
}

fn raw_tx_source_mac_for(iface: Option<sys::wifi_interface_t>) -> Result<[u8; 6]> {
    let mac_type = if iface.unwrap_or_else(raw_tx_interface) == sys::wifi_interface_t_WIFI_IF_AP {
        sys::esp_mac_type_t_ESP_MAC_WIFI_SOFTAP
    } else {
        sys::esp_mac_type_t_ESP_MAC_WIFI_STA
    };
    let mut mac = [0_u8; 6];
    unsafe {
        esp_ok(sys::esp_read_mac(mac.as_mut_ptr(), mac_type))?;
    }
    Ok(mac)
}

fn start_netif_probe(iface: &str) -> Result<()> {
    bail!("netif_probe iface={iface} is not compiled; firmware does not create esp_netif objects")
}

/// Build the DMesh custom vendor-action frame shared with host lmesh.
pub fn custom_raw_action_frame(destination: [u8; 6], payload: &[u8]) -> Result<Vec<u8>> {
    custom_raw_action_frame_with_bssid_for(destination, destination, payload, None)
}

fn custom_raw_action_frame_with_bssid(
    destination: [u8; 6], bssid: [u8; 6], payload: &[u8]
) -> Result<Vec<u8>> {
    custom_raw_action_frame_with_bssid_for(destination, bssid, payload, None)
}

fn custom_raw_action_frame_with_bssid_for(
    destination: [u8; 6],
    bssid: [u8; 6],
    payload: &[u8],
    tx_if: Option<sys::wifi_interface_t>,
) -> Result<Vec<u8>> {
    if payload.len() > RAW_ACTION_MAX_PAYLOAD {
        bail!(
            "raw action payload exceeds {} bytes: {}",
            RAW_ACTION_MAX_PAYLOAD,
            payload.len()
        );
    }
    let source = raw_tx_source_mac_for(tx_if)?;
    let mut frame = Vec::with_capacity(24 + DMESH_DATA_MARKER_LEN + payload.len());
    frame.extend_from_slice(&[0xd0, 0x00, 0x00, 0x00]);
    frame.extend_from_slice(&destination);
    frame.extend_from_slice(&source);
    frame.extend_from_slice(&bssid);
    frame.extend_from_slice(&[0x00, 0x00]);
    frame.extend_from_slice(&dmesh_data_marker(destination));
    frame.extend_from_slice(payload);
    Ok(frame)
}

fn nan_sdf_action_frame(destination: [u8; 6], payload: &[u8]) -> Result<Vec<u8>> {
    super::nan::raw_followup_frame(&destination, payload)
}

/// Return the source and binary payload of a DMesh custom vendor-action frame.
pub fn custom_raw_action_payload(frame: &[u8]) -> Option<([u8; 6], &[u8])> {
    const IEEE80211_HEADER_LEN: usize = 24;
    if frame.first() == Some(&0xd0) {
        RAW_ACTION_CANDIDATES.fetch_add(1, Ordering::Relaxed);
    }
    if frame.first() != Some(&0xd0) {
        return None;
    }
    let source = frame_address(frame, FRAME_ADDR2)?;
    let body = frame.get(IEEE80211_HEADER_LEN..)?;
    let Some(header) = dmesh_data_header(body) else {
        RAW_ACTION_MARKER_MISSES.fetch_add(1, Ordering::Relaxed);
        return None;
    };
    RAW_ACTION_ACCEPTED.fetch_add(1, Ordering::Relaxed);
    Some((source, strip_valid_fcs(frame, &body[header.len..])))
}

/// Some monitor transmitters (including Linux nl80211) let the radio append
/// an 802.11 FCS. ESP raw management RX may expose that FCS as part of the
/// action body, so remove it only when the CRC verifies. This keeps the CBOR
/// command boundary intact without truncating payloads on drivers that omit
/// FCS.
fn strip_valid_fcs<'a>(frame: &[u8], payload: &'a [u8]) -> &'a [u8] {
    if payload.len() <= 4 {
        return payload;
    }
    let split = payload.len() - 4;
    let expected = u32::from_le_bytes([
        payload[split],
        payload[split + 1],
        payload[split + 2],
        payload[split + 3],
    ]);
    // The IEEE 802.11 FCS covers the complete MAC frame, not just the
    // vendor body.  `frame` is the received frame without any radiotap
    // prefix; append-free frames remain unchanged when the driver omits FCS.
    let frame_split = frame.len().saturating_sub(4);
    if frame_split >= 24
        && frame.len() >= 4
        && crc32_ieee(&frame[..frame_split]) == expected
    {
        return &payload[..split];
    }
    // Some ESP-IDF raw-management paths report sig_len without the FCS while
    // still leaving the FCS bytes in the copied action body. In that case the
    // frame-wide CRC check cannot succeed. Prefer the shorter candidate only
    // when it is a valid DMesh CBOR command and the full body is not; this
    // preserves support for drivers that omit FCS entirely.
    if crate::commands::protocol::decode_binary(payload).is_err()
        && crate::commands::protocol::decode_binary(&payload[..split]).is_ok()
    {
        return &payload[..split];
    }
    payload
}

fn crc32_ieee(bytes: &[u8]) -> u32 {
    let mut crc = 0xffff_ffff;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xedb8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

fn dmesh_data_frame(
    destination: [u8; 6],
    source: Option<[u8; 6]>,
    payload: &[u8],
) -> Result<Vec<u8>> {
    let mac = source.map(Ok).unwrap_or_else(station_mac)?;
    let body = dmesh_ipv4_udp_body(destination, mac, payload);
    dmesh_data_frame_nods(destination, mac, destination, body)
}

fn dmesh_data_frame_with_bssid(
    destination: [u8; 6],
    source: Option<[u8; 6]>,
    bssid: [u8; 6],
    payload: &[u8],
) -> Result<Vec<u8>> {
    let mac = source.map(Ok).unwrap_or_else(station_mac)?;
    let body = dmesh_ipv4_udp_body(destination, mac, payload);
    dmesh_data_frame_nods(destination, mac, bssid, body)
}

fn dmesh_data_frame_nods(
    destination: [u8; 6],
    source: [u8; 6],
    bssid: [u8; 6],
    body: Vec<u8>,
) -> Result<Vec<u8>> {
    let mut frame = Vec::with_capacity(24 + body.len());
    frame.extend_from_slice(&[0x08, 0x00, 0x00, 0x00]);
    frame.extend_from_slice(&destination);
    frame.extend_from_slice(&source);
    frame.extend_from_slice(&bssid);
    frame.extend_from_slice(&[0x00, 0x00]);
    frame.extend_from_slice(&body);
    Ok(frame)
}

fn dmesh_sta_to_ap_data_frame(
    destination: [u8; 6],
    source: Option<[u8; 6]>,
    bssid: [u8; 6],
    payload: &[u8],
) -> Result<Vec<u8>> {
    let source = source.map(Ok).unwrap_or_else(station_mac)?;
    let body = dmesh_ipv4_udp_body(destination, source, payload);
    let mut frame = Vec::with_capacity(24 + body.len());
    frame.extend_from_slice(&[0x08, 0x01, 0x00, 0x00]);
    frame.extend_from_slice(&bssid);
    frame.extend_from_slice(&source);
    frame.extend_from_slice(&destination);
    frame.extend_from_slice(&[0x00, 0x00]);
    frame.extend_from_slice(&body);
    Ok(frame)
}

fn dmesh_ap_to_sta_data_frame(
    destination: [u8; 6],
    bssid: [u8; 6],
    payload: &[u8],
) -> Result<Vec<u8>> {
    let body = dmesh_ipv4_udp_body(destination, bssid, payload);
    let mut frame = Vec::with_capacity(24 + body.len());
    frame.extend_from_slice(&[0x08, 0x02, 0x00, 0x00]);
    frame.extend_from_slice(&destination);
    frame.extend_from_slice(&bssid);
    frame.extend_from_slice(&bssid);
    frame.extend_from_slice(&[0x00, 0x00]);
    frame.extend_from_slice(&body);
    Ok(frame)
}

fn dmesh_ipv4_udp_body(destination: [u8; 6], source: [u8; 6], payload: &[u8]) -> Vec<u8> {
    let body_len = payload.len().min(1380);
    let udp_len = (8 + DMESH_DATA_MARKER_LEN + body_len) as u16;
    let ip_len = 20_u16 + udp_len;
    let mut body = Vec::with_capacity(IEEE80211_LLC_SNAP_LEN + ip_len as usize);
    body.extend_from_slice(&IEEE80211_LLC_SNAP_IPV4);

    let mut ip = [0_u8; 20];
    ip[0] = 0x45;
    ip[1] = 0;
    ip[2..4].copy_from_slice(&ip_len.to_be_bytes());
    ip[4..6].copy_from_slice(&0_u16.to_be_bytes());
    ip[6..8].copy_from_slice(&0x4000_u16.to_be_bytes());
    ip[8] = 1;
    ip[9] = 17;
    ip[12..16].copy_from_slice(&[10, source[3], source[4], source[5]]);
    ip[16..20].copy_from_slice(&LMESH_IPV4_MULTICAST);
    let csum = ipv4_checksum(&ip);
    ip[10..12].copy_from_slice(&csum.to_be_bytes());
    body.extend_from_slice(&ip);

    body.extend_from_slice(&DMESH_UDP_PORT.to_be_bytes());
    body.extend_from_slice(&DMESH_UDP_PORT.to_be_bytes());
    body.extend_from_slice(&udp_len.to_be_bytes());
    body.extend_from_slice(&0_u16.to_be_bytes());
    body.extend_from_slice(&dmesh_data_marker(destination));
    body.extend_from_slice(&payload[..body_len]);
    body
}

fn ipv4_checksum(header: &[u8; 20]) -> u16 {
    let mut sum = 0_u32;
    for chunk in header.chunks_exact(2) {
        sum = sum.wrapping_add(u16::from_be_bytes([chunk[0], chunk[1]]) as u32);
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn dmesh_data_marker(destination: [u8; 6]) -> [u8; DMESH_DATA_MARKER_LEN] {
    let mut marker = [0_u8; DMESH_DATA_MARKER_LEN];
    marker[..DMESH_DATA_MARKER_PREFIX.len()].copy_from_slice(&DMESH_DATA_MARKER_PREFIX);
    marker[4..8].copy_from_slice(&destination[2..6]);
    marker[8] = DMESH_DATA_MARKER_TYPE;
    marker
}

fn device_multicast_mac() -> Result<[u8; 6]> {
    let mut mac = station_mac()?;
    mac[0] |= 0x01;
    mac[0] &= !0x02;
    Ok(mac)
}

fn station_mac() -> Result<[u8; 6]> {
    let mut mac = [0_u8; 6];
    unsafe {
        esp_ok(sys::esp_read_mac(
            mac.as_mut_ptr(),
            sys::esp_mac_type_t_ESP_MAC_WIFI_STA,
        ))?;
    }
    Ok(mac)
}

fn ap_mac() -> Result<[u8; 6]> {
    let mut mac = [0_u8; 6];
    unsafe {
        esp_ok(sys::esp_read_mac(
            mac.as_mut_ptr(),
            sys::esp_mac_type_t_ESP_MAC_WIFI_SOFTAP,
        ))?;
    }
    Ok(mac)
}

fn load_u64(low: &AtomicU32, high: &AtomicU32) -> u64 {
    ((high.load(Ordering::Relaxed) as u64) << 32) | low.load(Ordering::Relaxed) as u64
}

fn store_u64(low: &AtomicU32, high: &AtomicU32, value: u64) {
    low.store(value as u32, Ordering::Relaxed);
    high.store((value >> 32) as u32, Ordering::Relaxed);
}

unsafe extern "C" fn raw_wifi_cb(
    buf: *mut core::ffi::c_void,
    type_: sys::wifi_promiscuous_pkt_type_t,
) {
    if buf.is_null()
        || (type_ != sys::wifi_promiscuous_pkt_type_t_WIFI_PKT_MGMT
            && type_ != sys::wifi_promiscuous_pkt_type_t_WIFI_PKT_DATA)
    {
        RAW_RX_DROPPED.fetch_add(1, Ordering::Relaxed);
        return;
    }
    let pkt = unsafe { &*(buf as *const sys::wifi_promiscuous_pkt_t) };
    let len = pkt.rx_ctrl.sig_len().min(1500) as usize;
    let payload = pkt.payload.as_ptr();
    if payload.is_null() || len < 24 {
        RAW_RX_DROPPED.fetch_add(1, Ordering::Relaxed);
        return;
    }
    let frame = unsafe { core::slice::from_raw_parts(payload, len) };
    mark_raw_first_frame(unsafe { sys::esp_timer_get_time().max(0) as u64 });
    observe_beacon(frame);
    super::nan::observe_promiscuous_frame(frame, pkt.rx_ctrl.rssi() as i32);
    observe_promiscuous_frame(frame, pkt.rx_ctrl.rssi() as i32);
}

/// Record a beacon TSF as a shared timing source for raw-NAN and AP schedules.
/// Raw-NAN owns its own promiscuous callback, so it calls this directly rather
/// than relying on the generic raw-monitor callback.
pub fn observe_beacon(frame: &[u8]) {
    // Beacon management frames carry the AP/NAN TSF timestamp immediately
    // after the 24-byte 802.11 header. This shared snapshot is the raw-NAN
    // clock, so accept only NAN cluster BSSIDs (50:6f:9a vendor OUI). Generic
    // nearby AP beacons use `nan::last_ap_sync_beacon` instead; mixing them
    // here can move a sleepy node several DWs away from its selected cluster.
    if frame.first() != Some(&0x80)
        || frame.len() < 32
        || frame.get(FRAME_ADDR3..FRAME_ADDR3 + 3) != Some(&[0x50, 0x6f, 0x9a])
    {
        return;
    }
    let tsf_us = u64::from_le_bytes(frame[24..32].try_into().unwrap_or([0; 8]));
    if tsf_us == 0 {
        return;
    }
    let local_us = unsafe { sys::esp_timer_get_time().max(0) as u64 };
    store_u64(&WIFI_BEACON_LOCAL_LO, &WIFI_BEACON_LOCAL_HI, local_us);
    store_u64(&WIFI_BEACON_TSF_LO, &WIFI_BEACON_TSF_HI, tsf_us);
    WIFI_BEACON_COUNT.fetch_add(1, Ordering::Relaxed);
}

/// Reset the first-frame marker before arming a raw-NAN receive window.
pub fn reset_raw_first_frame() {
    RAW_FIRST_FRAME_LOCAL_LO.store(0, Ordering::Relaxed);
    RAW_FIRST_FRAME_LOCAL_HI.store(0, Ordering::Relaxed);
}

/// Return the local timestamp of the first accepted Wi-Fi frame in the window.
pub fn raw_first_frame_local_us() -> u64 {
    load_u64(&RAW_FIRST_FRAME_LOCAL_LO, &RAW_FIRST_FRAME_LOCAL_HI)
}

pub fn mark_raw_first_frame(local_us: u64) {
    if RAW_FIRST_FRAME_LOCAL_LO.load(Ordering::Acquire) == 0 {
        store_u64(
            &RAW_FIRST_FRAME_LOCAL_LO,
            &RAW_FIRST_FRAME_LOCAL_HI,
            local_us,
        );
    }
}

pub fn observe_promiscuous_frame(frame: &[u8], rssi: i32) {
    if !RAW_MONITOR_RUNNING.load(Ordering::Relaxed) {
        return;
    }
    RAW_RX_TOTAL.fetch_add(1, Ordering::Relaxed);
    if !matches_raw_filter(frame) {
        return;
    }
    let dmesh_payload = dmesh_raw_payload(frame);
    if matches!(
        RAW_FILTER_MODE.load(Ordering::Relaxed),
        RAW_FILTER_ALL
            | RAW_FILTER_ACTION
            | RAW_FILTER_DATA
            | RAW_FILTER_DMESH
            | RAW_FILTER_DMESH_DATA
    ) && dmesh_payload.is_none()
    {
        RAW_RX_DROPPED.fetch_add(1, Ordering::Relaxed);
        return;
    }
    RAW_RX_MATCHED.fetch_add(1, Ordering::Relaxed);
    telemetry::record_packet(
        "wifi",
        Direction::Rx,
        frame,
        format!("raw=true subtype={} rssi={}", frame_subtype(frame), rssi),
    );
    RAW_RX_LAST_RSSI.store(rssi, Ordering::Relaxed);
    let copy_len = frame.len().min(256);
    unsafe {
        core::ptr::copy_nonoverlapping(
            frame.as_ptr(),
            core::ptr::addr_of_mut!(RAW_RX_LAST) as *mut u8,
            copy_len,
        );
    }
    RAW_RX_LAST_LEN.store(copy_len as u32, Ordering::Relaxed);
    if let Some(payload) = dmesh_payload {
        telemetry::record_companion_packet("wifi", payload);
        super::mode::observe_ping("wifi_raw", payload);
        if is_wifi_terminal_payload(payload) {
            let line = format!(
                "event type=wifi.notify source=raw src={} len={} payload_b64={}",
                frame_address(frame, FRAME_ADDR2)
                    .map(format_mac)
                    .unwrap_or_else(|| "none".to_string()),
                payload.len(),
                base64_standard(payload)
            );
            telemetry::record_log(line);
            return;
        }
        let response = if frame_type(frame) == 2 {
            WifiResponsePath::Data
        } else {
            WifiResponsePath::Action
        };
        enqueue_raw_command(frame, payload, rssi, response);
        let dst = frame_address(frame, FRAME_ADDR1)
            .map(format_mac)
            .unwrap_or_else(|| "none".to_string());
        let src = frame_address(frame, FRAME_ADDR2)
            .map(format_mac)
            .unwrap_or_else(|| "none".to_string());
        let destination = raw_destination_name(frame);
        let payload_b64 = base64_standard(payload);
        let line = format!(
            "event type=wifi.raw_frame source=dmesh_nan destination={} src={} dst={} len={} rssi={} payload_b64={}",
            destination,
            src,
            dst,
            payload.len(),
            rssi,
            payload_b64
        );
        telemetry::emit_console(&line);
        telemetry::record_log(line);
    }
}

fn matches_raw_filter(frame: &[u8]) -> bool {
    if RAW_FILTER_BSSID_ENABLED.load(Ordering::Relaxed) && !frame_has_bssid(frame) {
        return false;
    }
    match RAW_FILTER_MODE.load(Ordering::Relaxed) {
        RAW_FILTER_ALL => true,
        RAW_FILTER_MGMT => frame_type(frame) == 0,
        RAW_FILTER_ACTION => frame_subtype(frame) == 13,
        RAW_FILTER_BEACON => frame_subtype(frame) == 8,
        RAW_FILTER_PROBE_REQ => frame_subtype(frame) == 4,
        RAW_FILTER_PROBE_RESP => frame_subtype(frame) == 5,
        RAW_FILTER_DATA => frame_type(frame) == 2,
        RAW_FILTER_DMESH => frame_type(frame) == 0 && frame_subtype(frame) == 13,
        RAW_FILTER_DMESH_DATA => {
            frame_type(frame) == 2 || (frame_type(frame) == 0 && frame_subtype(frame) == 13)
        }
        _ => true,
    }
}

fn frame_type(frame: &[u8]) -> u8 {
    (frame.first().copied().unwrap_or(0) & 0x0c) >> 2
}

fn frame_subtype(frame: &[u8]) -> u8 {
    frame.first().copied().unwrap_or(0) >> 4
}

fn frame_has_bssid(frame: &[u8]) -> bool {
    if frame.len() < FRAME_ADDR3 + 6 {
        return false;
    }
    for base in [FRAME_ADDR1, FRAME_ADDR2, FRAME_ADDR3] {
        let mut matched = true;
        for idx in 0..6 {
            if frame[base + idx] != RAW_FILTER_BSSID[idx].load(Ordering::Relaxed) {
                matched = false;
                break;
            }
        }
        if matched {
            return true;
        }
    }
    false
}

fn dmesh_raw_payload(frame: &[u8]) -> Option<&[u8]> {
    if frame.len() <= 24 {
        return None;
    }
    if frame_type(frame) == 2 {
        if !frame_matches_nan_data_destination(frame) {
            return None;
        }
        if let Some(payload) = raw_nan_data_payload(&frame[24..]) {
            return Some(payload);
        }
        let (header, payload) = dmesh_payload_from_body(&frame[24..])?;
        if !mesh_dst4_allowed(header.mesh_dst4) {
            return None;
        }
        return Some(payload);
    } else if frame_subtype(frame) != 13 {
        return None;
    }
    super::nan::raw_payload(frame)
}

fn raw_nan_data_payload(body: &[u8]) -> Option<&[u8]> {
    body.starts_with(&RAWNAN_LLC_DEFAULT)
        .then_some(&body[IEEE80211_LLC_SNAP_LEN..])
}

fn dmesh_payload_from_body(body: &[u8]) -> Option<(DmeshDataHeader, &[u8])> {
    if let Some(header) = dmesh_data_header(body) {
        return Some((header, &body[header.len..]));
    }
    dmesh_payload_from_ipv4_udp_body(body)
}

fn dmesh_payload_from_ipv4_udp_body(body: &[u8]) -> Option<(DmeshDataHeader, &[u8])> {
    let body = if body.starts_with(&IEEE80211_LLC_SNAP_IPV4) {
        &body[IEEE80211_LLC_SNAP_LEN..]
    } else {
        body
    };
    if body.len() < 28 || body.first()? >> 4 != 4 || body[9] != 17 {
        return None;
    }
    let ihl = ((body[0] & 0x0f) as usize) * 4;
    if ihl < 20 || body.len() < ihl + 8 {
        return None;
    }
    let total_len = u16::from_be_bytes([body[2], body[3]]) as usize;
    if total_len < ihl + 8 || body.len() < total_len {
        return None;
    }
    if body[16..20] != LMESH_IPV4_MULTICAST {
        return None;
    }
    let udp = &body[ihl..total_len];
    let src_port = u16::from_be_bytes([udp[0], udp[1]]);
    let dst_port = u16::from_be_bytes([udp[2], udp[3]]);
    let udp_len = u16::from_be_bytes([udp[4], udp[5]]) as usize;
    if src_port != DMESH_UDP_PORT || dst_port != DMESH_UDP_PORT || udp_len < 8 {
        return None;
    }
    if udp.len() < udp_len {
        return None;
    }
    let dmesh = &udp[8..udp_len];
    let header = dmesh_data_header(dmesh)?;
    Some((header, &dmesh[header.len..]))
}

#[allow(dead_code)]
fn dmesh_netif_payload(frame: &[u8]) -> Option<([u8; 6], &[u8])> {
    if frame.len() >= 14 {
        let destination = frame_address(frame, ETH_ADDR_DST)?;
        if !ethernet_destination_allowed(destination) {
            return None;
        }
        let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
        if ethertype == ETHERTYPE_IPV4 {
            let (header, payload) = dmesh_payload_from_ipv4_udp_body(&frame[14..])?;
            if mesh_dst4_allowed(header.mesh_dst4) {
                return Some((frame_address(frame, ETH_ADDR_SRC)?, payload));
            }
        }
    }
    let (header, payload) = dmesh_payload_from_ipv4_udp_body(frame)?;
    if mesh_dst4_allowed(header.mesh_dst4) {
        let source = station_mac().unwrap_or([0; 6]);
        return Some((source, payload));
    }
    None
}

#[allow(dead_code)]
fn ethernet_destination_allowed(destination: [u8; 6]) -> bool {
    if destination == LMESH_IPV6_DISCOVERY_MULTICAST {
        return true;
    }
    if station_mac().map(|mac| destination == mac).unwrap_or(false) {
        return true;
    }
    if ap_mac().map(|mac| destination == mac).unwrap_or(false) {
        return true;
    }
    device_multicast_mac()
        .map(|mac| destination == mac)
        .unwrap_or(false)
}

#[derive(Clone, Copy)]
struct DmeshDataHeader {
    len: usize,
    mesh_dst4: [u8; 4],
}

fn dmesh_data_header(body: &[u8]) -> Option<DmeshDataHeader> {
    if body.len() >= DMESH_DATA_MARKER_LEN
        && body[..DMESH_DATA_MARKER_PREFIX.len()] == DMESH_DATA_MARKER_PREFIX
        && body[8] == DMESH_DATA_MARKER_TYPE
    {
        return Some(DmeshDataHeader {
            len: DMESH_DATA_MARKER_LEN,
            mesh_dst4: [body[4], body[5], body[6], body[7]],
        });
    }
    None
}

fn mesh_dst4_allowed(key: [u8; 4]) -> bool {
    if key == DMESH_FIXED_MESH_DST4 || key == mesh_dst4(LMESH_IPV6_DISCOVERY_MULTICAST) {
        return true;
    }
    if station_mac()
        .map(|mac| key == mesh_dst4(mac))
        .unwrap_or(false)
    {
        return true;
    }
    ap_mac().map(|mac| key == mesh_dst4(mac)).unwrap_or(false)
}

fn mesh_dst4(destination: [u8; 6]) -> [u8; 4] {
    [
        destination[2],
        destination[3],
        destination[4],
        destination[5],
    ]
}

fn frame_matches_dmesh_data_destination(frame: &[u8]) -> bool {
    let Some(destination) = frame_address(frame, FRAME_ADDR1) else {
        return false;
    };
    if destination == LMESH_IPV6_DISCOVERY_MULTICAST {
        return true;
    }
    if station_mac().map(|mac| destination == mac).unwrap_or(false) {
        return true;
    }
    if ap_mac().map(|mac| destination == mac).unwrap_or(false) {
        return true;
    }
    device_multicast_mac()
        .map(|mac| destination == mac)
        .unwrap_or(false)
}

fn frame_matches_nan_data_destination(frame: &[u8]) -> bool {
    let Some(destination) = frame_address(frame, FRAME_ADDR1) else {
        return false;
    };
    // Experimental raw NAN accepts unicast to this device and any IEEE
    // multicast destination.  The cluster-BSSID filter remains the primary
    // admission boundary, so multicast is never enabled globally.
    destination[0] & 1 != 0 || frame_matches_dmesh_data_destination(frame)
}

fn raw_destination_name(frame: &[u8]) -> &'static str {
    let Some(destination) = frame_address(frame, FRAME_ADDR1) else {
        return "unknown";
    };
    if destination == LMESH_IPV6_DISCOVERY_MULTICAST {
        return "ff02_5227";
    }
    if station_mac().map(|mac| destination == mac).unwrap_or(false) {
        return "device_unicast";
    }
    if ap_mac().map(|mac| destination == mac).unwrap_or(false) {
        return "ap_unicast";
    }
    if device_multicast_mac()
        .map(|mac| destination == mac)
        .unwrap_or(false)
    {
        return "device_multicast";
    }
    "other"
}

fn base64_standard(data: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    let mut chunks = data.chunks_exact(3);
    for chunk in &mut chunks {
        let word = ((chunk[0] as u32) << 16) | ((chunk[1] as u32) << 8) | chunk[2] as u32;
        out.push(TABLE[((word >> 18) & 0x3f) as usize] as char);
        out.push(TABLE[((word >> 12) & 0x3f) as usize] as char);
        out.push(TABLE[((word >> 6) & 0x3f) as usize] as char);
        out.push(TABLE[(word & 0x3f) as usize] as char);
    }
    let rem = chunks.remainder();
    if rem.len() == 1 {
        let word = (rem[0] as u32) << 16;
        out.push(TABLE[((word >> 18) & 0x3f) as usize] as char);
        out.push(TABLE[((word >> 12) & 0x3f) as usize] as char);
        out.push('=');
        out.push('=');
    } else if rem.len() == 2 {
        let word = ((rem[0] as u32) << 16) | ((rem[1] as u32) << 8);
        out.push(TABLE[((word >> 18) & 0x3f) as usize] as char);
        out.push(TABLE[((word >> 12) & 0x3f) as usize] as char);
        out.push(TABLE[((word >> 6) & 0x3f) as usize] as char);
        out.push('=');
    }
    out
}

fn enqueue_raw_command(frame: &[u8], payload: &[u8], rssi: i32, response: WifiResponsePath) {
    let Some(source) = frame_address(frame, FRAME_ADDR2) else {
        RAW_CMD_DROPPED.fetch_add(1, Ordering::Relaxed);
        return;
    };
    enqueue_command(source, payload, rssi, response);
}

fn enqueue_command(source: [u8; 6], payload: &[u8], rssi: i32, response: WifiResponsePath) {
    if payload.len() > RAW_COMMAND_MAX_LEN {
        RAW_CMD_DROPPED.fetch_add(1, Ordering::Relaxed);
        return;
    }
    set_last_command_peer(source, response);
    let Ok(mut queue) = raw_command_queue().lock() else {
        RAW_CMD_DROPPED.fetch_add(1, Ordering::Relaxed);
        return;
    };
    if queue.len() >= RAW_COMMAND_QUEUE_MAX {
        queue.pop_front();
        RAW_CMD_DROPPED.fetch_add(1, Ordering::Relaxed);
    }
    queue.push_back(RawWifiCommand {
        source,
        payload: payload.to_vec(),
        rssi,
        response,
    });
    RAW_CMD_RX_TOTAL.fetch_add(1, Ordering::Relaxed);
    super::wake::notify();
}

fn is_wifi_terminal_payload(payload: &[u8]) -> bool {
    crate::commands::protocol::decode_binary(payload)
        .map(|req| req.args.contains_key(&4) || req.args.contains_key(&5))
        .unwrap_or(false)
}

fn raw_command_queue() -> &'static Mutex<VecDeque<RawWifiCommand>> {
    RAW_COMMAND_QUEUE.get_or_init(|| Mutex::new(VecDeque::with_capacity(RAW_COMMAND_QUEUE_MAX)))
}

fn raw_response_history() -> &'static Mutex<VecDeque<RawWifiResponse>> {
    RAW_RESPONSE_HISTORY
        .get_or_init(|| Mutex::new(VecDeque::with_capacity(RAW_RESPONSE_HISTORY_MAX)))
}

fn raw_response_history_text() -> String {
    let Ok(history) = raw_response_history().lock() else {
        return "raw_response_history unavailable".to_string();
    };
    let entries = history
        .iter()
        .map(|item| {
            format!(
                "local_us:{}:source={}:payload_hex:{}",
                item.local_us,
                format_mac(item.source),
                hex_bytes(&item.payload)
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "raw_response_history count={} entries={}",
        history.len(),
        entries
    )
}

fn frame_address(frame: &[u8], offset: usize) -> Option<[u8; 6]> {
    frame.get(offset..offset + 6)?.try_into().ok()
}

fn set_last_command_peer(peer: [u8; 6], response: WifiResponsePath) {
    for (idx, byte) in peer.iter().enumerate() {
        RAW_LAST_COMMAND_PEER[idx].store(*byte, Ordering::Relaxed);
    }
    RAW_LAST_COMMAND_RESPONSE.store(response.as_u8(), Ordering::Relaxed);
    RAW_LAST_COMMAND_PEER_VALID.store(true, Ordering::Release);
}

fn last_command_peer() -> Option<[u8; 6]> {
    if !RAW_LAST_COMMAND_PEER_VALID.load(Ordering::Acquire) {
        return None;
    }
    let mut peer = [0_u8; 6];
    for (idx, byte) in peer.iter_mut().enumerate() {
        *byte = RAW_LAST_COMMAND_PEER[idx].load(Ordering::Relaxed);
    }
    Some(peer)
}

fn last_response_path() -> WifiResponsePath {
    WifiResponsePath::from_u8(RAW_LAST_COMMAND_RESPONSE.load(Ordering::Relaxed))
}

fn format_mac(mac: [u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

fn raw_stats() -> String {
    let last_len = RAW_RX_LAST_LEN.load(Ordering::Relaxed) as usize;
    let last = unsafe { &RAW_RX_LAST[..last_len.min(256)] };
    let peer = last_command_peer()
        .map(format_mac)
        .unwrap_or_else(|| "none".to_string());
    let (channel, second) = wifi_channel_status();
    format!(
        "raw_monitor={} filter={} bssid_filter={} ch={} second={} conn_wake_ms={} rx={} matched={} dropped={} tx={} cmd_rx={} cmd_dropped={} action_candidates={} action_marker_misses={} action_accepted={} object_attempts={} object_accepted={} last_peer={} last_response={} last_len={} last_rssi={} last={}",
        RAW_MONITOR_RUNNING.load(Ordering::Relaxed),
        raw_filter_name(),
        RAW_FILTER_BSSID_ENABLED.load(Ordering::Relaxed),
        channel,
        second,
        WIFI_CONNECTIONLESS_WAKE_INTERVAL_MS.load(Ordering::Relaxed),
        RAW_RX_TOTAL.load(Ordering::Relaxed),
        RAW_RX_MATCHED.load(Ordering::Relaxed),
        RAW_RX_DROPPED.load(Ordering::Relaxed),
        RAW_TX_TOTAL.load(Ordering::Relaxed),
        RAW_CMD_RX_TOTAL.load(Ordering::Relaxed),
        RAW_CMD_DROPPED.load(Ordering::Relaxed),
        RAW_ACTION_CANDIDATES.load(Ordering::Relaxed),
        RAW_ACTION_MARKER_MISSES.load(Ordering::Relaxed),
        RAW_ACTION_ACCEPTED.load(Ordering::Relaxed),
        RAW_OBJECT_ACTION_ATTEMPTS.load(Ordering::Relaxed),
        RAW_OBJECT_ACTION_ACCEPTED.load(Ordering::Relaxed),
        peer,
        last_response_path().name(),
        last_len,
        RAW_RX_LAST_RSSI.load(Ordering::Relaxed),
        hex_bytes(last)
    )
}

fn netif_probe_stats() -> String {
    format!(
        "netif_probe={} netif_rx={} netif_last_len={} netif_last=disabled",
        WIFI_NETIF_PROBE_RUNNING.load(Ordering::Relaxed),
        WIFI_NETIF_RX_TOTAL.load(Ordering::Relaxed),
        WIFI_NETIF_RX_LAST_LEN.load(Ordering::Relaxed)
    )
}

fn reject_netif_probe_if_requested(request: &CommandRequest) -> Result<()> {
    if request
        .arg("netif_probe")
        .or_else(|| request.arg("probe"))
        .map(parse_bool)
        .transpose()?
        .unwrap_or(false)
    {
        bail!("netif_probe is not compiled; firmware does not create esp_netif objects");
    }
    Ok(())
}

fn parse_raw_filter(value: &str) -> Result<u32> {
    match value {
        "all" => Ok(RAW_FILTER_ALL),
        "mgmt" | "management" => Ok(RAW_FILTER_MGMT),
        "action" => Ok(RAW_FILTER_ACTION),
        "data" => Ok(RAW_FILTER_DATA),
        "dmesh" | "mesh" => Ok(RAW_FILTER_DMESH),
        "dmesh_data" | "mesh_data" | "dmesh+data" | "mesh+data" => Ok(RAW_FILTER_DMESH_DATA),
        "beacon" => Ok(RAW_FILTER_BEACON),
        "probe_req" | "probe-request" => Ok(RAW_FILTER_PROBE_REQ),
        "probe_resp" | "probe-response" => Ok(RAW_FILTER_PROBE_RESP),
        _ => bail!("unsupported raw wifi filter {value}"),
    }
}

fn raw_filter_name() -> &'static str {
    match RAW_FILTER_MODE.load(Ordering::Relaxed) {
        RAW_FILTER_ALL => "all",
        RAW_FILTER_MGMT => "mgmt",
        RAW_FILTER_ACTION => "action",
        RAW_FILTER_DATA => "data",
        RAW_FILTER_DMESH => "dmesh",
        RAW_FILTER_DMESH_DATA => "dmesh_data",
        RAW_FILTER_BEACON => "beacon",
        RAW_FILTER_PROBE_REQ => "probe_req",
        RAW_FILTER_PROBE_RESP => "probe_resp",
        _ => "unknown",
    }
}

fn promiscuous_filter_mask(filter_mode: u32) -> u32 {
    match filter_mode {
        RAW_FILTER_ALL | RAW_FILTER_DMESH_DATA => {
            sys::WIFI_PROMIS_FILTER_MASK_MGMT | sys::WIFI_PROMIS_FILTER_MASK_DATA
        }
        RAW_FILTER_DMESH => sys::WIFI_PROMIS_FILTER_MASK_MGMT,
        RAW_FILTER_DATA => sys::WIFI_PROMIS_FILTER_MASK_DATA,
        _ => sys::WIFI_PROMIS_FILTER_MASK_MGMT,
    }
}

fn parse_mac(value: &str) -> Result<[u8; 6]> {
    let parts = value.split(':').collect::<Vec<_>>();
    if parts.len() != 6 {
        bail!("MAC must have 6 colon-separated bytes");
    }
    let mut mac = [0_u8; 6];
    for (idx, part) in parts.iter().enumerate() {
        mac[idx] = u8::from_str_radix(part, 16).map_err(|err| anyhow!("invalid MAC: {err}"))?;
    }
    Ok(mac)
}

fn default_direct_ssid() -> Result<String> {
    let mac = station_mac()?;
    Ok(format!(
        "DIRECT-DMESH-{:02X}{:02X}{:02X}{:02X}",
        mac[2], mac[3], mac[4], mac[5]
    ))
}

fn copy_cstr_bytes<const N: usize>(dst: &mut [u8; N], src: &[u8]) {
    dst.fill(0);
    let len = src.len().min(N);
    dst[..len].copy_from_slice(&src[..len]);
}

fn ssid_from_bytes(bytes: &[u8]) -> String {
    let len = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..len]).into_owned()
}

fn auth_name(auth: sys::wifi_auth_mode_t) -> &'static str {
    match auth {
        x if x == sys::wifi_auth_mode_t_WIFI_AUTH_OPEN => "open",
        x if x == sys::wifi_auth_mode_t_WIFI_AUTH_WPA2_PSK => "wpa2",
        x if x == sys::wifi_auth_mode_t_WIFI_AUTH_WPA_WPA2_PSK => "wpa_wpa2",
        x if x == sys::wifi_auth_mode_t_WIFI_AUTH_WPA3_PSK => "wpa3",
        x if x == sys::wifi_auth_mode_t_WIFI_AUTH_WPA2_WPA3_PSK => "wpa2_wpa3",
        _ => "other",
    }
}

fn wifi_net_status() -> String {
    let (channel, second) = wifi_channel_status();
    let (ip, ip_up, netif_flags, lwip_flags, lwip_default, lwip_io, lwip_ip, lwip_mask, lwip_gw) = IP_STA_NETIF
        .get()
        .and_then(|value| unsafe {
            let mut info = sys::esp_netif_ip_info_t::default();
            let netif = *value as *mut sys::esp_netif_t;
            let result = sys::esp_netif_get_ip_info(netif, &mut info);
            if result == sys::ESP_OK && info.ip.addr != 0 {
                let ip = format!(
                    "{}.{}.{}.{}",
                    info.ip.addr.to_ne_bytes()[0],
                    info.ip.addr.to_ne_bytes()[1],
                    info.ip.addr.to_ne_bytes()[2],
                    info.ip.addr.to_ne_bytes()[3]
                );
                Some((
                    ip,
                    sys::esp_netif_is_netif_up(netif),
                    sys::esp_netif_get_flags(netif),
                    dmesh_module_loader_ip_netif_flags(netif),
                    dmesh_module_loader_ip_netif_default(netif),
                    dmesh_module_loader_ip_netif_io_state(netif),
                    dmesh_module_loader_ip_netif_addr(netif, 0),
                    dmesh_module_loader_ip_netif_addr(netif, 1),
                    dmesh_module_loader_ip_netif_addr(netif, 2),
                ))
            } else {
                None
            }
        })
        .unwrap_or_else(|| ("disabled".to_string(), false, 0, 0, 0, 0, 0, 0, 0));
    let (ap_bssid, ap_rssi) = unsafe {
        let mut ap = sys::wifi_ap_record_t::default();
        if sys::esp_wifi_sta_get_ap_info(&mut ap) == sys::ESP_OK {
            (format_mac(ap.bssid), ap.rssi.to_string())
        } else {
            ("none".to_string(), "0".to_string())
        }
    };
    format!(
        "sta_mac={} ap_mac={} ch={} second={} country={} ip={} ip_up={} netif_flags={} lwip_flags={} lwip_default={} lwip_io={} lwip_ip={} lwip_mask={} lwip_gw={} ap_bssid={} ap_rssi={} ap_stations={}",
        station_mac()
            .map(format_mac)
            .unwrap_or_else(|_| "unknown".to_string()),
        ap_mac()
            .map(format_mac)
            .unwrap_or_else(|_| "unknown".to_string()),
        channel,
        second,
        wifi_country_code(),
        ip,
        ip_up,
        netif_flags,
        lwip_flags,
        lwip_default,
        lwip_io,
        format_ipv4_u32(lwip_ip),
        format_ipv4_u32(lwip_mask),
        format_ipv4_u32(lwip_gw),
        ap_bssid,
        ap_rssi,
        ap_station_count()
    )
}

fn format_ipv4_u32(value: u32) -> String {
    let octets = value.to_ne_bytes();
    format!("{}.{}.{}.{}", octets[0], octets[1], octets[2], octets[3])
}

/// Read the ESP-IDF effective two-character regulatory country code.
///
/// `01` is ESP-IDF's world-safe default and must not be emitted as a NAN
/// Country Code attribute. The raw-NAN publisher uses this status value only
/// as the authoritative source for a later optional-attribute experiment.
fn wifi_country_code() -> String {
    let mut country = [0 as c_char; 3];
    let ret = unsafe { sys::esp_wifi_get_country_code(country.as_mut_ptr()) };
    if ret != sys::ESP_OK {
        return "unknown".to_string();
    }
    let bytes = [country[0] as u8, country[1] as u8];
    if bytes
        .iter()
        .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
    {
        String::from_utf8_lossy(&bytes).into_owned()
    } else {
        "unknown".to_string()
    }
}

fn wifi_channel_status() -> (i32, &'static str) {
    let mut primary = 0_u8;
    let mut second = sys::wifi_second_chan_t_WIFI_SECOND_CHAN_NONE;
    let ret = unsafe { sys::esp_wifi_get_channel(&mut primary, &mut second) };
    if ret != sys::ESP_OK {
        return (-1, "unknown");
    }
    let second = match second {
        x if x == sys::wifi_second_chan_t_WIFI_SECOND_CHAN_NONE => "none",
        x if x == sys::wifi_second_chan_t_WIFI_SECOND_CHAN_ABOVE => "above",
        x if x == sys::wifi_second_chan_t_WIFI_SECOND_CHAN_BELOW => "below",
        _ => "other",
    };
    (primary as i32, second)
}

fn ap_station_count() -> i32 {
    let mut list = sys::wifi_sta_list_t::default();
    let ret = unsafe { sys::esp_wifi_ap_get_sta_list(&mut list) };
    if ret == sys::ESP_OK {
        list.num
    } else {
        -1
    }
}

fn validate_wifi_string(name: &str, value: &str, max: usize) -> Result<()> {
    if value.len() > max {
        bail!("{name} must be at most {max} bytes");
    }
    Ok(())
}

fn task_delay(timeout: Duration) {
    unsafe {
        sys::vTaskDelay(duration_to_ticks(timeout).max(1));
    }
}

fn duration_to_ticks(timeout: Duration) -> sys::TickType_t {
    let hz = sys::configTICK_RATE_HZ as u128;
    let ticks = timeout.as_millis().saturating_mul(hz).div_ceil(1000);
    ticks.min(sys::TickType_t::MAX as u128) as sys::TickType_t
}

fn esp_ok(ret: sys::esp_err_t) -> Result<()> {
    if ret == sys::ESP_OK {
        Ok(())
    } else {
        bail!("esp_err=0x{ret:x}")
    }
}

fn esp_ok_allow_invalid_state(ret: sys::esp_err_t) -> Result<()> {
    if ret == sys::ESP_OK || ret == sys::ESP_ERR_INVALID_STATE {
        Ok(())
    } else {
        bail!("esp_err=0x{ret:x}")
    }
}

fn esp_ok_allow_dhcp_already_stopped(ret: sys::esp_err_t) -> Result<()> {
    if ret == ESP_ERR_DHCP_ALREADY_STOPPED {
        Ok(())
    } else {
        esp_ok_allow_invalid_state(ret)
    }
}
