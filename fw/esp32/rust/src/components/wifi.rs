use std::collections::VecDeque;
use std::ffi::c_char;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicU8, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use esp_idf_sys as sys;

use crate::commands::{CommandHandler, CommandRegistry, CommandRequest, CommandResponse};

use super::frames::{hex_bytes, parse_bytes};
use super::settings::{parse_bool, parse_i32};
use super::telemetry::{self, Direction};

unsafe extern "C" {
    fn esp_wifi_connectionless_module_set_wake_interval(wake_interval: u16) -> sys::esp_err_t;
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
const DMESH_FIXED_MESH_DST4: [u8; 4] = [0xff; 4];
const IEEE80211_LLC_SNAP_IPV4: [u8; IEEE80211_LLC_SNAP_LEN] =
    [0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x08, 0x00];

static RAW_MONITOR_RUNNING: AtomicBool = AtomicBool::new(false);
static IP_STA_NETIF: OnceLock<usize> = OnceLock::new();
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
static WIFI_BEACON_COUNT: AtomicU32 = AtomicU32::new(0);
static WIFI_BEACON_LOCAL_LO: AtomicU32 = AtomicU32::new(0);
static WIFI_BEACON_LOCAL_HI: AtomicU32 = AtomicU32::new(0);
static WIFI_BEACON_TSF_LO: AtomicU32 = AtomicU32::new(0);
static WIFI_BEACON_TSF_HI: AtomicU32 = AtomicU32::new(0);
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

pub fn register_commands(registry: &mut CommandRegistry) {
    registry.register(WifiCommand::default());
}

pub fn forward_management_packet(packet: &[u8]) -> Result<()> {
    ensure_raw_wifi_started(6)?;
    let frame = nan_sdf_action_frame(RAW_BROADCAST, packet)?;
    raw_tx_frame(&frame, true)?;
    RAW_TX_TOTAL.fetch_add(1, Ordering::Relaxed);
    telemetry::record_packet("wifi", Direction::Tx, packet, "source=lora_forward");
    Ok(())
}

pub fn send_raw_action_payload_to(destination: [u8; 6], payload: &[u8]) -> Result<()> {
    ensure_raw_wifi_started(6)?;
    let frame = custom_raw_action_frame(destination, payload)?;
    raw_tx_frame(&frame, true)?;
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

pub fn start_raw_monitor_mode(channel: u8, filter: &str) -> Result<()> {
    start_raw_only(channel, filter)
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
        let _ = sys::esp_wifi_set_channel(
            channel.clamp(1, 13),
            sys::wifi_second_chan_t_WIFI_SECOND_CHAN_NONE,
        );
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
    RAW_MONITOR_RUNNING.store(true, Ordering::Relaxed);
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

#[derive(Default)]
struct WifiCommand {
    mode: WifiMode,
    ssid: Option<String>,
    psk: Option<String>,
    timeout_ms: u32,
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
        if request.arg("raw_stats").is_some() {
            return Ok(CommandResponse::ok(raw_stats()));
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
            raw_tx_frame(&frame, true)?;
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
            let frame = custom_raw_action_frame(destination, &payload)?;
            raw_tx_frame(&frame, true)?;
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
            let frame = custom_raw_action_frame(destination, payload.as_bytes())?;
            raw_tx_frame(&frame, true)?;
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
            .is_some();
        if ip_mode {
            start_ip_sta(request, ssid, psk, channel)?;
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
        if timeout_ms > 0 {
            task_delay(Duration::from_millis(timeout_ms as u64));
            disable_mesh_ip_services();
        }
        self.mode = WifiMode::RawSta;
        Ok(CommandResponse::ok(format!(
            "wifi mode=RawSta ssid={} channel={} timeout_ms={} {}",
            self.ssid.as_deref().unwrap_or(""),
            channel,
            timeout_ms,
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
        esp_ok(sys::esp_wifi_set_channel(
            channel.max(1),
            sys::wifi_second_chan_t_WIFI_SECOND_CHAN_NONE,
        ))?;
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

fn parse_ipv4(value: &str, name: &str) -> Result<u32> {
    let address = value
        .parse::<Ipv4Addr>()
        .map_err(|error| anyhow!("invalid {name} address {value}: {error}"))?;
    Ok(u32::from_ne_bytes(address.octets()))
}

fn start_ip_sta(request: &CommandRequest, ssid: &str, psk: &str, _channel: u8) -> Result<()> {
    // Establish the lwIP/tcpip stack and its default netif before handing the
    // radio away from raw NAN. This matches Recovery's initialization order;
    // stopping the raw driver first can leave a later BSD socket with an
    // invalid tcpip mailbox on ESP32.
    init_ip_stack()?;
    ensure_low_level_wifi()?;
    let netif = ensure_ip_sta_netif()?;
    // Main normally owns a sleepy raw-NAN scheduler. IP STA is a dedicated
    // bulk-transfer mode, so stop that scheduler after the IP stack exists.
    super::mode::stop_for_ip_transport();
    // Let the STA scan for the AP.  Recovery uses channel 0 here as well;
    // forcing the raw-radio channel can prevent association when the host AP
    // was started on a different channel.
    configure_sta(ssid, psk, 0)?;

    let local_ip = request
        .arg("ip")
        .or_else(|| request.arg("local_ip"))
        .context("wifi STA IP mode requires ip=...")?;
    let gateway = request.arg("gw").unwrap_or("10.78.0.1");
    let netmask = request.arg("mask").unwrap_or("255.255.255.0");
    let mut info = sys::esp_netif_ip_info_t::default();
    info.ip.addr = parse_ipv4(local_ip, "local")?;
    info.gw.addr = parse_ipv4(gateway, "gateway")?;
    info.netmask.addr = parse_ipv4(netmask, "netmask")?;
    unsafe {
        esp_ok_allow_invalid_state(sys::esp_netif_dhcpc_stop(netif))?;
        esp_ok(sys::esp_netif_set_ip_info(netif, &info))?;
    }
    // Configure the static address before starting the station. This is the
    // same ordering used by Recovery and prevents the DHCP/netif event path
    // from replacing the address while the association is coming up.
    unsafe {
        esp_ok(sys::esp_wifi_start())?;
        esp_ok(sys::esp_wifi_connect())?;
    }
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    loop {
        let mut ap = sys::wifi_ap_record_t::default();
        let mut current = sys::esp_netif_ip_info_t::default();
        let associated = unsafe { sys::esp_wifi_sta_get_ap_info(&mut ap) == sys::ESP_OK };
        let has_ip = unsafe {
            sys::esp_netif_get_ip_info(netif, &mut current) == sys::ESP_OK && current.ip.addr != 0
        };
        if associated && has_ip {
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
    ensure_low_level_wifi()?;
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

fn configure_sta(ssid: &str, psk: &str, channel: u8) -> Result<()> {
    ensure_low_level_wifi()?;
    unsafe {
        let _ = sys::esp_wifi_disconnect();
        let _ = sys::esp_wifi_set_promiscuous(false);
        let _ = sys::esp_wifi_stop();
        esp_ok(sys::esp_wifi_set_mode(sys::wifi_mode_t_WIFI_MODE_STA))?;
        let mut sta = sys::wifi_sta_config_t::default();
        copy_cstr_bytes(&mut sta.ssid, ssid.as_bytes());
        copy_cstr_bytes(&mut sta.password, psk.as_bytes());
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
    }
    Ok(())
}

fn low_level_start_sta(ssid: &str, psk: &str, channel: u8) -> Result<()> {
    configure_sta(ssid, psk, channel)?;
    unsafe {
        esp_ok(sys::esp_wifi_start())?;
        esp_ok(sys::esp_wifi_connect())?;
        disable_mesh_ip_services();
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
        ampdu_tx_enable: sys::WIFI_AMPDU_TX_ENABLED as i32,
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
    #[cfg(target_feature = "esp32s3ops")]
    {
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
    raw_tx_frame(bytes, en_sys_seq)?;
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

fn raw_tx_frame(bytes: &[u8], en_sys_seq: bool) -> Result<()> {
    let iface = raw_tx_interface();
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
    let ret = unsafe { sys::esp_wifi_get_mode(&mut mode) };
    if ret == sys::ESP_OK && mode == sys::wifi_mode_t_WIFI_MODE_AP {
        sys::wifi_interface_t_WIFI_IF_AP
    } else {
        sys::wifi_interface_t_WIFI_IF_STA
    }
}

/// Return the MAC address belonging to the interface selected for injected
/// management/action frames. The 802.11 source address must match the active
/// interface: a SoftAP raw transmitter cannot advertise a STA source address.
pub(crate) fn raw_tx_source_mac() -> Result<[u8; 6]> {
    let mac_type = if raw_tx_interface() == sys::wifi_interface_t_WIFI_IF_AP {
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
    if payload.len() > RAW_ACTION_MAX_PAYLOAD {
        bail!(
            "raw action payload exceeds {} bytes: {}",
            RAW_ACTION_MAX_PAYLOAD,
            payload.len()
        );
    }
    let source = station_mac()?;
    let mut frame = Vec::with_capacity(24 + DMESH_DATA_MARKER_LEN + payload.len());
    frame.extend_from_slice(&[0xd0, 0x00, 0x00, 0x00]);
    frame.extend_from_slice(&destination);
    frame.extend_from_slice(&source);
    frame.extend_from_slice(&destination);
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
    if frame.first() != Some(&0xd0) {
        return None;
    }
    let source = frame_address(frame, FRAME_ADDR2)?;
    let body = frame.get(IEEE80211_HEADER_LEN..)?;
    let header = dmesh_data_header(body)?;
    Some((source, &body[header.len..]))
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
        if !frame_matches_dmesh_data_destination(frame) {
            return None;
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
        "raw_monitor={} filter={} bssid_filter={} ch={} second={} conn_wake_ms={} rx={} matched={} dropped={} tx={} cmd_rx={} cmd_dropped={} last_peer={} last_response={} last_len={} last_rssi={} last={}",
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
    let ip = IP_STA_NETIF
        .get()
        .and_then(|value| unsafe {
            let mut info = sys::esp_netif_ip_info_t::default();
            if sys::esp_netif_get_ip_info(*value as *mut sys::esp_netif_t, &mut info) == sys::ESP_OK
                && info.ip.addr != 0
            {
                Some(format!(
                    "{}.{}.{}.{}",
                    info.ip.addr.to_ne_bytes()[0],
                    info.ip.addr.to_ne_bytes()[1],
                    info.ip.addr.to_ne_bytes()[2],
                    info.ip.addr.to_ne_bytes()[3]
                ))
            } else {
                None
            }
        })
        .unwrap_or_else(|| "disabled".to_string());
    format!(
        "sta_mac={} ap_mac={} ch={} second={} country={} ip={} ap_stations={}",
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
        ap_station_count()
    )
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
