use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicU8, Ordering};

use anyhow::{bail, Result};
use esp_idf_sys as sys;

use crate::commands::{CommandHandler, CommandRegistry, CommandRequest, CommandResponse};

use super::settings::{parse_bool, SharedSettings};
use super::telemetry;

const MODE_COMPANION: u8 = 0;
const MODE_INFRA: u8 = 1;
const DEFAULT_ADV_MS: u32 = 1_000;
const DEFAULT_PENDING_ADV_MS: u32 = 1_500;
const DEFAULT_WINDOW_MS: u32 = 10_000;
const DEFAULT_ACTIVE_MS: u32 = 5_000;
const DEFAULT_PENDING_WINDOW_MS: u32 = 30_000;
const DEFAULT_WAKE_MS: u32 = 30_000;
const DEFAULT_NAN_DUTY_MS: u32 = 4_000;
const DEFAULT_NAN_ACTIVE_MS: u32 = 250;
const DEFAULT_NAN_WAKE_EARLY_MS: u32 = 5;
const DEFAULT_NAN_DW_TU: u32 = 512;
const DEFAULT_NAN_DW_OFFSET_TU: u32 = 0;
const DEFAULT_AP_LOSS_MS: u32 = 5_000;
const DEFAULT_AP_RECOVERY_MS: u32 = 32_000;
const DEFAULT_AP_RECOVERY_LISTEN_MS: u32 = 1_200;
const DEFAULT_AP_SLOT_TU: u32 = 4_000;
const DEFAULT_AP_BEACON_TU: u16 = 500;
const RAW_NAN_DW_HISTORY_LEN: usize = 8;
const RAW_NAN_DW_FLAG_DW0: u32 = 1 << 0;
const RAW_NAN_DW_FLAG_SYNC: u32 = 1 << 1;
const RAW_NAN_DW_FLAG_BEACON: u32 = 1 << 2;
const RAW_NAN_DW_FLAG_LATE: u32 = 1 << 3;
const RAW_NAN_DW_FLAG_NEXT: u32 = 1 << 4;
const RAW_NAN_DW_FLAG_DRIFT: u32 = 1 << 5;
const RAW_NAN_DW_FLAG_LIGHT: u32 = 1 << 6;
const PING_PREFIX: &[u8] = b"dmesh.ping";

static PRODUCT_MODE: AtomicU8 = AtomicU8::new(MODE_INFRA);
static COMPANION_ADVERTISING: AtomicBool = AtomicBool::new(false);
static COMPANION_DEADLINE_MS: AtomicU32 = AtomicU32::new(0);
static COMPANION_PENDING_ADVERTISING: AtomicBool = AtomicBool::new(false);
static RAW_NAN_DUTY_ENABLED: AtomicBool = AtomicBool::new(false);
static RAW_NAN_DUTY_ACTIVE: AtomicBool = AtomicBool::new(false);
static RAW_NAN_DUTY_NEXT_MS: AtomicU32 = AtomicU32::new(0);
static RAW_NAN_SYNC_SOURCE: AtomicU8 = AtomicU8::new(SYNC_SOURCE_NONE);
static RAW_NAN_RECOVERY_NEXT_MS: AtomicU32 = AtomicU32::new(0);
static RAW_NAN_RECOVERY_RUNS: AtomicU32 = AtomicU32::new(0);
static RAW_NAN_RECOVERY_ACTIVE: AtomicBool = AtomicBool::new(false);
static AP_OWNER_RUNNING: AtomicBool = AtomicBool::new(false);
static AP_OWNER_AP_ACTIVE: AtomicBool = AtomicBool::new(false);
static AP_OWNER_STARTED_MS: AtomicU32 = AtomicU32::new(0);
static AP_OWNER_UART_NEXT_MS: AtomicU32 = AtomicU32::new(0);
static AP_OWNER_STARTS: AtomicU32 = AtomicU32::new(0);
static AP_OWNER_STOPS: AtomicU32 = AtomicU32::new(0);
// Infra active mode is a runtime-only override for a powered gateway or a
// bounded bulk transfer. It deliberately does not persist in NVS: reset must
// always return a battery node to its configured raw-NAN duty cycle.
static INFRA_ACTIVE_PERSISTENT: AtomicBool = AtomicBool::new(false);
static INFRA_ACTIVE_DEADLINE_MS: AtomicU32 = AtomicU32::new(0);
static INFRA_ACTIVE_STARTS: AtomicU32 = AtomicU32::new(0);
static INFRA_ACTIVE_STOPS: AtomicU32 = AtomicU32::new(0);
static INFRA_ACTIVE_EXPIRES: AtomicU32 = AtomicU32::new(0);
static INFRA_ACTIVE_UART_EXTENDS: AtomicU32 = AtomicU32::new(0);
static RAW_NAN_BEACON_BASELINE: AtomicU32 = AtomicU32::new(0);
static RAW_NAN_EXPECT_TSF_LO: AtomicU32 = AtomicU32::new(0);
static RAW_NAN_EXPECT_TSF_HI: AtomicU32 = AtomicU32::new(0);
static RAW_NAN_EXPECT_PERIOD_US: AtomicU32 = AtomicU32::new(0);
static RAW_NAN_MISS_BACKOFF_MS: AtomicU32 = AtomicU32::new(0);
static RAW_NAN_BEACON_SEEN: AtomicU32 = AtomicU32::new(0);
static RAW_NAN_BEACON_MISSED: AtomicU32 = AtomicU32::new(0);
static RAW_NAN_BEACON_LATE: AtomicU32 = AtomicU32::new(0);
static RAW_NAN_BEACON_LATE_NEXT_DW: AtomicU32 = AtomicU32::new(0);
static RAW_NAN_BEACON_DRIFT: AtomicU32 = AtomicU32::new(0);
static RAW_NAN_DW_TOTAL: AtomicU32 = AtomicU32::new(0);
static RAW_NAN_DW0_TOTAL: AtomicU32 = AtomicU32::new(0);
static RAW_NAN_DW_SYNC_TOTAL: AtomicU32 = AtomicU32::new(0);
static RAW_NAN_DW_EARLY_WAKE_TOTAL: AtomicU32 = AtomicU32::new(0);
static RAW_NAN_DW_ACTIVE_SEQ: AtomicU32 = AtomicU32::new(0);
static RAW_NAN_DW_HISTORY_SEQ: [AtomicU32; RAW_NAN_DW_HISTORY_LEN] =
    [const { AtomicU32::new(0) }; RAW_NAN_DW_HISTORY_LEN];
static RAW_NAN_DW_HISTORY_START_MS: [AtomicU32; RAW_NAN_DW_HISTORY_LEN] =
    [const { AtomicU32::new(0) }; RAW_NAN_DW_HISTORY_LEN];
static RAW_NAN_DW_HISTORY_BEACONS: [AtomicU32; RAW_NAN_DW_HISTORY_LEN] =
    [const { AtomicU32::new(0) }; RAW_NAN_DW_HISTORY_LEN];
static RAW_NAN_DW_HISTORY_FLAGS: [AtomicU32; RAW_NAN_DW_HISTORY_LEN] =
    [const { AtomicU32::new(0) }; RAW_NAN_DW_HISTORY_LEN];
static PING_RESPONSE_PENDING: AtomicBool = AtomicBool::new(false);
static PING_RESPONSE_NOT_BEFORE_MS: AtomicU32 = AtomicU32::new(0);
static PING_LAST_REQUEST_HASH: AtomicU32 = AtomicU32::new(0);
static PING_LAST_REQUEST_MS: AtomicU32 = AtomicU32::new(0);
static PING_RX: AtomicU32 = AtomicU32::new(0);
static PING_TX: AtomicU32 = AtomicU32::new(0);
static PING_LAST_RX_RSSI_DBM: AtomicI32 = AtomicI32::new(0);
static PING_LAST_RX_RSSI_VALID: AtomicBool = AtomicBool::new(false);

const SYNC_SOURCE_NONE: u8 = 0;
const SYNC_SOURCE_NAN: u8 = 1;
const SYNC_SOURCE_DIRECT_AP: u8 = 2;
const SYNC_SOURCE_AP: u8 = 3;

#[derive(Clone, Copy, Eq, PartialEq)]
enum SyncPolicy {
    Auto,
    NanOnly,
    ApOnly,
}

pub fn register_commands(registry: &mut CommandRegistry, settings: SharedSettings) {
    registry.register(ModeCommand { settings });
}

pub fn init(settings: &SharedSettings) {
    PRODUCT_MODE.store(MODE_INFRA, Ordering::Relaxed);
    if let Err(err) = start_infra_radios(settings, "boot") {
        telemetry::record_log(format!(
            "event type=mode.infra_start ok=false reason=boot msg={}",
            crate::commands::protocol::escape_value(&err.to_string())
        ));
    }
}

#[allow(dead_code)]
pub fn configured_companion(settings: &SharedSettings) -> bool {
    configured_mode(settings) == MODE_COMPANION
}

/// True only while the runtime owns the nearby-phone companion workflow.
/// Infrastructure nodes must not initialize BLE merely because they receive a
/// LoRa frame; their radio forwarding path is LoRa plus raw-NAN/Wi-Fi.
pub fn is_companion_mode() -> bool {
    PRODUCT_MODE.load(Ordering::Relaxed) == MODE_COMPANION
}

pub fn init_after_boot_window(settings: &SharedSettings, button_wake: bool) {
    let reason = if button_wake {
        "button_wake"
    } else {
        "boot_window_done"
    };
    PRODUCT_MODE.store(MODE_INFRA, Ordering::Relaxed);
    if let Err(err) = start_infra_radios(settings, reason) {
        telemetry::record_log(format!(
            "event type=mode.infra_start ok=false reason={} msg={}",
            reason,
            crate::commands::protocol::escape_value(&err.to_string())
        ));
    }
}

pub fn set_infra(settings: &SharedSettings, save: bool, reason: &'static str) -> Result<()> {
    PRODUCT_MODE.store(MODE_INFRA, Ordering::Relaxed);
    COMPANION_ADVERTISING.store(false, Ordering::Relaxed);
    COMPANION_PENDING_ADVERTISING.store(false, Ordering::Relaxed);
    COMPANION_DEADLINE_MS.store(0, Ordering::Relaxed);
    if save {
        settings.borrow_mut().set_str("mode", "infra")?;
    }
    start_infra_radios(settings, reason)?;
    telemetry::record_log(format!("event type=mode active=infra reason={}", reason));
    Ok(())
}

pub fn enter_pairing_recovery(settings: &SharedSettings, window_ms: u32) {
    PRODUCT_MODE.store(MODE_COMPANION, Ordering::Relaxed);
    stop_infra_active_session();
    COMPANION_ADVERTISING.store(true, Ordering::Relaxed);
    COMPANION_PENDING_ADVERTISING.store(false, Ordering::Relaxed);
    COMPANION_DEADLINE_MS.store(now_ms().wrapping_add(window_ms), Ordering::Relaxed);
    stop_ap_owner().ok();
    stop_raw_nan_duty();
    super::nan::stop_nan().ok();
    super::wifi::stop_raw_monitor().ok();
    super::lora::sleep_radio(settings).ok();
    telemetry::record_log(format!(
        "event type=mode active=companion state=pairing_recovery window_ms={}",
        window_ms
    ));
}

pub fn poll(settings: &SharedSettings) {
    poll_infra_active_session();
    if AP_OWNER_RUNNING.load(Ordering::Relaxed) {
        poll_ap_owner(settings);
    } else {
        poll_raw_nan_duty(settings);
    }

    let response_due = PING_RESPONSE_NOT_BEFORE_MS.load(Ordering::Relaxed);
    if PING_RESPONSE_PENDING.load(Ordering::Relaxed)
        && (response_due == 0 || now_ms().wrapping_sub(response_due) < i32::MAX as u32)
    {
        PING_RESPONSE_PENDING.store(false, Ordering::Relaxed);
        PING_RESPONSE_NOT_BEFORE_MS.store(0, Ordering::Relaxed);
        if let Err(err) = send_status_ping(settings, "rx") {
            telemetry::record_log(format!(
                "event type=mode.ping_response ok=false msg={}",
                crate::commands::protocol::escape_value(&err.to_string())
            ));
        }
    }
}

pub fn send_button_sync(settings: &SharedSettings) {
    if let Err(err) = send_status_ping(settings, "button") {
        telemetry::record_log(format!(
            "event type=mode.button action=sync ok=false msg={}",
            crate::commands::protocol::escape_value(&err.to_string())
        ));
    }
}

pub fn mark_companion_active(settings: &SharedSettings, window_ms: u32) {
    if is_companion_mode() {
        return;
    }
    extend_infra_active_session(settings, window_ms, "uart");
}

fn deadline_is_due(deadline: u32, now: u32) -> bool {
    deadline != 0 && now.wrapping_sub(deadline) < u32::MAX / 2
}

fn infra_active_session_enabled() -> bool {
    if INFRA_ACTIVE_PERSISTENT.load(Ordering::Relaxed) {
        return true;
    }
    let deadline = INFRA_ACTIVE_DEADLINE_MS.load(Ordering::Relaxed);
    deadline != 0 && !deadline_is_due(deadline, now_ms())
}

fn poll_infra_active_session() {
    if INFRA_ACTIVE_PERSISTENT.load(Ordering::Relaxed) {
        return;
    }
    let deadline = INFRA_ACTIVE_DEADLINE_MS.load(Ordering::Relaxed);
    if !deadline_is_due(deadline, now_ms()) {
        return;
    }
    if INFRA_ACTIVE_DEADLINE_MS
        .compare_exchange(deadline, 0, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
    {
        INFRA_ACTIVE_EXPIRES.fetch_add(1, Ordering::Relaxed);
        telemetry::record_log("event type=mode.infra_active state=expired");
    }
}

fn infra_radio_hold_active() -> bool {
    infra_active_session_enabled() || super::serial::is_active()
}

fn extend_infra_active_session(settings: &SharedSettings, window_ms: u32, reason: &'static str) {
    let window_ms = window_ms.max(1_000).min(300_000);
    if INFRA_ACTIVE_PERSISTENT.load(Ordering::Relaxed) {
        return;
    }
    let deadline = now_ms().wrapping_add(window_ms);
    let previous = INFRA_ACTIVE_DEADLINE_MS.load(Ordering::Relaxed);
    if previous == 0 || deadline_is_due(previous, deadline) {
        INFRA_ACTIVE_DEADLINE_MS.store(deadline, Ordering::Relaxed);
    }
    INFRA_ACTIVE_UART_EXTENDS.fetch_add(1, Ordering::Relaxed);
    if let Err(err) = ensure_infra_active_radios(settings, reason) {
        telemetry::record_log(format!(
            "event type=mode.infra_active state=uart_extend ok=false msg={}",
            crate::commands::protocol::escape_value(&err.to_string())
        ));
    }
}

fn start_infra_active_session(
    settings: &SharedSettings,
    active_ms: Option<u32>,
    reason: &'static str,
) -> Result<()> {
    if is_companion_mode() {
        bail!("mode active requires infra mode; run mode infra=true first");
    }
    match active_ms {
        Some(ms) => {
            let ms = ms.clamp(1_000, 300_000);
            INFRA_ACTIVE_PERSISTENT.store(false, Ordering::Relaxed);
            INFRA_ACTIVE_DEADLINE_MS.store(now_ms().wrapping_add(ms), Ordering::Relaxed);
        }
        None => {
            INFRA_ACTIVE_DEADLINE_MS.store(0, Ordering::Relaxed);
            INFRA_ACTIVE_PERSISTENT.store(true, Ordering::Relaxed);
        }
    }
    INFRA_ACTIVE_STARTS.fetch_add(1, Ordering::Relaxed);
    ensure_infra_active_radios(settings, reason)?;
    // A remote `active` request is also the supported way to recover the
    // physical debug/modem UART on a sleepy board. Keep the radio override
    // independent and persistent, but bound UART/APB activity to its normal
    // debug window so unattended battery nodes still return to low power.
    super::serial::set_debug_enabled(true);
    super::serial::activate_window();
    let persistent = INFRA_ACTIVE_PERSISTENT.load(Ordering::Relaxed);
    telemetry::record_log(format!(
        "event type=mode.infra_active state=start persistent={} active_ms={}",
        persistent,
        active_ms.unwrap_or(0)
    ));
    Ok(())
}

fn stop_infra_active_session() {
    let was_active = INFRA_ACTIVE_PERSISTENT.swap(false, Ordering::AcqRel)
        || INFRA_ACTIVE_DEADLINE_MS.swap(0, Ordering::AcqRel) != 0;
    if was_active {
        INFRA_ACTIVE_STOPS.fetch_add(1, Ordering::Relaxed);
        // Let the next mode poll close the current window and compute a fresh
        // beacon-aligned duty sleep interval.
        RAW_NAN_DUTY_NEXT_MS.store(now_ms(), Ordering::Relaxed);
        telemetry::record_log("event type=mode.infra_active state=stopped");
    }
}

/// Observe a ping from a transport that expects the standard infra response.
/// The request is de-duplicated across LoRa, raw action, and raw-NAN copies.
pub fn observe_ping(transport: &'static str, payload: &[u8]) {
    observe_ping_inner(transport, payload, true, None);
}

/// Record a LoRa ping and preserve its receive level for the corresponding
/// broadcast pong. Wi-Fi action frames currently do not expose a comparable
/// stable signal value on every target.
pub fn observe_lora_ping(transport: &'static str, payload: &[u8], rssi_dbm: i32) {
    observe_ping_inner(transport, payload, true, Some(rssi_dbm));
}

fn observe_ping_inner(
    transport: &'static str,
    payload: &[u8],
    auto_response: bool,
    rssi_dbm: Option<i32>,
) {
    let mut is_ping = false;
    let mut is_reply = false;
    if let Ok(req) = crate::commands::protocol::decode_binary(payload) {
        if req.method == 33 {
            is_ping = true;
            is_reply = req.args.contains_key(&4) || req.args.contains_key(&5);
        }
    } else if payload.starts_with(PING_PREFIX) {
        is_ping = true;
        is_reply = payload
            .windows(b"reply=true".len())
            .any(|w| w == b"reply=true");
    }

    if !is_ping {
        return;
    }
    PING_RX.fetch_add(1, Ordering::Relaxed);
    if let Some(rssi_dbm) = rssi_dbm {
        PING_LAST_RX_RSSI_DBM.store(rssi_dbm, Ordering::Relaxed);
        PING_LAST_RX_RSSI_VALID.store(true, Ordering::Relaxed);
    }
    telemetry::record_log(format!(
        "event type=mode.ping_rx transport={} len={} rssi_dbm={}",
        transport,
        payload.len(),
        rssi_dbm.unwrap_or(0)
    ));
    if auto_response && PRODUCT_MODE.load(Ordering::Relaxed) == MODE_INFRA && !is_reply {
        let hash = ping_hash(payload);
        let now = now_ms();
        let previous_hash = PING_LAST_REQUEST_HASH.load(Ordering::Relaxed);
        let previous_ms = PING_LAST_REQUEST_MS.load(Ordering::Relaxed);
        if hash == previous_hash && now.wrapping_sub(previous_ms) < 2_000 {
            telemetry::record_log(format!(
                "event type=mode.ping_response queued=false reason=duplicate transport={}",
                transport
            ));
            return;
        }
        PING_LAST_REQUEST_HASH.store(hash, Ordering::Relaxed);
        PING_LAST_REQUEST_MS.store(now, Ordering::Relaxed);
        // A discovery ping is broadcast. Peers must not all answer in the
        // same LoRa airtime slot or the origin will miss every pong while it
        // returns from TX to RX. Four deterministic slots keep discovery
        // bounded below the normal 8-second raw-NAN wake cycle.
        let slot = local_suffix4_hex()
            .ok()
            .and_then(|suffix| u32::from_str_radix(&suffix, 16).ok())
            .map(|value| {
                let folded = value ^ (value >> 8) ^ (value >> 16) ^ (value >> 24);
                folded & 0x07
            })
            .unwrap_or(0);
        let delay_ms = 350 + slot * 700;
        PING_RESPONSE_NOT_BEFORE_MS.store(now_ms().wrapping_add(delay_ms), Ordering::Relaxed);
        PING_RESPONSE_PENDING.store(true, Ordering::Relaxed);
        telemetry::record_log(format!(
            "event type=mode.ping_response queued=true delay_ms={} slot={}",
            delay_ms, slot
        ));
    }
}

fn ping_hash(payload: &[u8]) -> u32 {
    payload.iter().fold(0x811c_9dc5_u32, |hash, byte| {
        hash.wrapping_mul(0x0100_0193) ^ u32::from(*byte)
    })
}

fn enter_companion_advertising(
    settings: &SharedSettings,
    window_ms: u32,
    adv_ms: u32,
    reason: &'static str,
) -> Result<()> {
    PRODUCT_MODE.store(MODE_COMPANION, Ordering::Relaxed);
    stop_infra_active_session();
    if reason != "pending" {
        COMPANION_PENDING_ADVERTISING.store(false, Ordering::Relaxed);
    }
    stop_ap_owner().ok();
    stop_raw_nan_duty();
    super::nan::stop_nan().ok();
    super::wifi::stop_raw_monitor().ok();
    super::lora::sleep_radio(settings).ok();
    super::ble_bt::set_advertising_interval_ms(adv_ms, adv_ms);
    if let Err(err) = super::sleep::enable_companion_idle_pm(settings) {
        telemetry::record_log(format!(
            "event type=mode.companion_pm ok=false msg={}",
            crate::commands::protocol::escape_value(&err.to_string())
        ));
    }
    if let Err(err) = super::ble_bt::enable_controller_sleep() {
        telemetry::record_log(format!(
            "event type=mode.companion_ble_sleep ok=false msg={}",
            crate::commands::protocol::escape_value(&err.to_string())
        ));
    }
    super::ble_bt::start_connectable_advertising()?;
    super::ble_bt::open_companion_active_window(window_ms);
    COMPANION_ADVERTISING.store(true, Ordering::Relaxed);
    COMPANION_DEADLINE_MS.store(now_ms().wrapping_add(window_ms), Ordering::Relaxed);
    telemetry::record_log(format!(
        "event type=mode active=companion state=ble_advertising reason={} window_ms={} adv_ms={}",
        reason, window_ms, adv_ms
    ));
    Ok(())
}

fn enter_companion_sleep(settings: &SharedSettings) -> Result<()> {
    PRODUCT_MODE.store(MODE_COMPANION, Ordering::Relaxed);
    let lora_listen = get_bool(settings, "cm.lora", false);
    let pending = telemetry::pending_message_count();
    if pending > 0 && !COMPANION_PENDING_ADVERTISING.swap(true, Ordering::Relaxed) {
        let window_ms = get_u32(settings, "cm.pending_ms", DEFAULT_PENDING_WINDOW_MS);
        let adv_ms = get_u32(settings, "cm.pending_adv_ms", DEFAULT_PENDING_ADV_MS);
        telemetry::record_log(format!(
            "event type=mode active=companion state=pending_advertising pending={} window_ms={} adv_ms={}",
            pending, window_ms, adv_ms
        ));
        return enter_companion_advertising(settings, window_ms, adv_ms, "pending");
    }

    stop_ap_owner().ok();
    stop_raw_nan_duty();
    super::nan::stop_nan().ok();
    super::wifi::stop_raw_monitor().ok();
    super::ble_bt::stop_radio_activity();
    COMPANION_ADVERTISING.store(false, Ordering::Relaxed);
    COMPANION_PENDING_ADVERTISING.store(false, Ordering::Relaxed);
    COMPANION_DEADLINE_MS.store(0, Ordering::Relaxed);
    let wake_ms = get_u32(settings, "cm.wake_ms", DEFAULT_WAKE_MS);
    let active_ms = if lora_listen {
        get_u32(settings, "cm.active_ms", DEFAULT_ACTIVE_MS)
    } else {
        0
    };
    telemetry::record_log(format!(
        "event type=mode active=companion state=deep_sleep lora_listen={} wake_ms={} active_ms={} pending={}",
        lora_listen, wake_ms, active_ms, pending
    ));
    super::sleep::enter_companion_deep_sleep(settings, lora_listen, wake_ms, active_ms)
}

fn start_infra_radios(settings: &SharedSettings, reason: &'static str) -> Result<()> {
    boot_print("dm-rs mode step=infra_start");
    let channel =
        get_u32(settings, "nan.channel", get_u32(settings, "raw.ch", 6)).clamp(1, 13) as u8;
    if get_bool(settings, "wifi.enabled", true) {
        if get_bool(settings, "nan.ap_owner", false) {
            start_ap_owner(settings, reason, channel)?;
        } else {
            stop_ap_owner().ok();
            start_raw_nan_duty(settings, reason, channel)?;
        }
        telemetry::record_log(format!(
            "event type=mode.infra_radio medium=wifi profile=discovery_window channel={} reason={}",
            channel, reason
        ));
    } else {
        stop_ap_owner().ok();
        stop_raw_nan_duty();
        super::nan::stop_nan().ok();
        super::wifi::stop_raw_monitor().ok();
        telemetry::record_log(format!(
            "event type=mode.infra_radio medium=wifi status=disabled channel={} reason={}",
            channel, reason
        ));
    }
    start_infra_lora(settings, reason)
}
fn start_infra_lora(settings: &SharedSettings, reason: &'static str) -> Result<()> {
    boot_print("dm-rs mode step=lora_start");
    if !lora_boot_enabled(settings) {
        telemetry::record_log(format!(
            "event type=mode.infra_radio medium=lora rx=false reason={} status=not_configured",
            reason
        ));
        boot_print("dm-rs mode step=lora_skipped");
        return Ok(());
    }
    boot_print("dm-rs mode step=lora_status");
    telemetry::record_log(format!(
        "event type=mode.infra_radio medium=lora reason={} {}",
        reason,
        super::lora::status_text(settings)
    ));
    if !get_bool(settings, "lora.enabled", true) {
        let _ = super::lora::sleep_radio(settings);
        telemetry::record_log(format!(
            "event type=mode.infra_radio medium=lora rx=false reason={} status=disabled",
            reason
        ));
        boot_print("dm-rs mode step=lora_disabled");
        return Ok(());
    }
    boot_print("dm-rs mode step=lora_rx");
    match super::lora::start_background_rx(settings.clone()) {
        Ok(Some(_)) => telemetry::record_log(format!(
            "event type=mode.infra_radio medium=lora rx=true reason={}",
            reason
        )),
        Ok(None) => telemetry::record_log(format!(
            "event type=mode.infra_radio medium=lora rx=false reason={} status=unavailable_or_running",
            reason
        )),
        Err(err) => telemetry::record_log(format!(
            "event type=mode.infra_radio medium=lora rx=false reason={} msg={}",
            reason,
            crate::commands::protocol::escape_value(&err.to_string())
        )),
    }
    boot_print("dm-rs mode step=lora_done");
    Ok(())
}

fn lora_boot_enabled(settings: &SharedSettings) -> bool {
    let settings = settings.borrow();
    let configured = [
        "lora.spi_host",
        "lora.sck",
        "lora.miso",
        "lora.mosi",
        "lora.cs",
        "lora.rst",
        "lora.dio0",
        "lora.busy",
    ]
    .iter()
    .any(|key| matches!(settings.get_str(key), Ok(Some(_))));
    if !configured {
        return false;
    }
    match settings.get_str("lora.enabled") {
        Ok(Some(value)) => parse_bool(&value).unwrap_or(false),
        _ => true,
    }
}

fn sync_policy(settings: &SharedSettings) -> SyncPolicy {
    match settings
        .borrow()
        .get_str("nan.sync_source")
        .ok()
        .flatten()
        .as_deref()
    {
        Some("nan_only") | Some("nan") => SyncPolicy::NanOnly,
        Some("ap_only") | Some("ap") => SyncPolicy::ApOnly,
        _ => SyncPolicy::Auto,
    }
}

fn start_ap_owner(settings: &SharedSettings, reason: &'static str, channel: u8) -> Result<()> {
    if AP_OWNER_RUNNING.load(Ordering::Relaxed) {
        stop_ap_owner()?;
    }
    stop_raw_nan_duty();
    AP_OWNER_RUNNING.store(true, Ordering::Relaxed);
    AP_OWNER_STARTED_MS.store(now_ms(), Ordering::Relaxed);
    AP_OWNER_UART_NEXT_MS.store(0, Ordering::Relaxed);
    AP_OWNER_AP_ACTIVE.store(false, Ordering::Relaxed);
    RAW_NAN_SYNC_SOURCE.store(SYNC_SOURCE_NONE, Ordering::Relaxed);
    AP_OWNER_UART_NEXT_MS.store(0, Ordering::Relaxed);
    super::nan::start_raw_window(channel, "nan")?;
    telemetry::record_log(format!(
        "event type=mode.ap_owner state=watching channel={} reason={} sync_policy={}",
        channel,
        reason,
        sync_policy_name(sync_policy(settings))
    ));
    if sync_policy(settings) == SyncPolicy::ApOnly {
        start_ap_owner_fallback(settings, channel)?;
    }
    Ok(())
}

fn stop_ap_owner() -> Result<()> {
    if !AP_OWNER_RUNNING.swap(false, Ordering::AcqRel) {
        return Ok(());
    }
    if AP_OWNER_AP_ACTIVE.swap(false, Ordering::AcqRel) {
        super::nan::stop_nan().ok();
        super::wifi::stop_direct_ap_beacon_source()?;
        AP_OWNER_STOPS.fetch_add(1, Ordering::Relaxed);
    }
    RAW_NAN_SYNC_SOURCE.store(SYNC_SOURCE_NONE, Ordering::Relaxed);
    Ok(())
}

fn start_ap_owner_fallback(settings: &SharedSettings, channel: u8) -> Result<()> {
    if AP_OWNER_AP_ACTIVE.load(Ordering::Relaxed) {
        return Ok(());
    }
    super::nan::stop_nan().ok();
    let beacon_tu = get_u32(settings, "nan.ap_beacon_tu", DEFAULT_AP_BEACON_TU as u32)
        .clamp(100, 60_000) as u16;
    let ssid = super::wifi::start_direct_ap_beacon_source(channel, beacon_tu)?;
    // Re-arm the management callback without changing AP mode.
    super::nan::start_raw_window(channel, "nan")?;
    AP_OWNER_AP_ACTIVE.store(true, Ordering::Relaxed);
    AP_OWNER_STARTS.fetch_add(1, Ordering::Relaxed);
    RAW_NAN_SYNC_SOURCE.store(SYNC_SOURCE_DIRECT_AP, Ordering::Relaxed);
    telemetry::record_log(format!(
        "event type=mode.ap_owner state=ap_started ssid={} channel={} beacon_tu={} sleep_inhibited=ap",
        ssid, channel, beacon_tu
    ));
    Ok(())
}

fn poll_ap_owner(settings: &SharedSettings) {
    // An AP owner keeps Wi-Fi powered rather than entering raw-NAN duty sleep,
    // so it has no regular duty callback to emit the UART heartbeat. Keep the
    // host modem contract identical to battery nodes: one bounded UART window
    // per configured wake cadence, without extending it from UART output.
    let now = now_ms();
    let next_uart = AP_OWNER_UART_NEXT_MS.load(Ordering::Relaxed);
    if next_uart == 0 || now.wrapping_sub(next_uart) < i32::MAX as u32 {
        let active_ms = get_u32(settings, "nan.active_ms", DEFAULT_NAN_ACTIVE_MS).clamp(100, 5_000);
        let wake_ms =
            get_u32(settings, "nan.wake_ms", DEFAULT_NAN_DUTY_MS).clamp(active_ms, 60_000);
        let _ = super::serial::on_raw_nan_wake(active_ms);
        AP_OWNER_UART_NEXT_MS.store(now.wrapping_add(wake_ms), Ordering::Relaxed);
    }
    let channel = get_u32(settings, "nan.channel", 6).clamp(1, 13) as u8;
    let policy = sync_policy(settings);
    let nan_fresh = super::nan::nan_beacon_age_ms()
        .is_some_and(|age| age <= get_u32(settings, "nan.ap_loss_ms", DEFAULT_AP_LOSS_MS));
    let owner_age_ms = now_ms().wrapping_sub(AP_OWNER_STARTED_MS.load(Ordering::Relaxed));
    let loss_ms = get_u32(settings, "nan.ap_loss_ms", DEFAULT_AP_LOSS_MS);
    let should_run_ap = policy == SyncPolicy::ApOnly
        || (policy == SyncPolicy::Auto && !nan_fresh && owner_age_ms >= loss_ms);

    if should_run_ap {
        if let Err(err) = start_ap_owner_fallback(settings, channel) {
            telemetry::record_log(format!(
                "event type=mode.ap_owner state=ap_start_failed msg={}",
                crate::commands::protocol::escape_value(&err.to_string())
            ));
        }
        return;
    }

    RAW_NAN_SYNC_SOURCE.store(SYNC_SOURCE_NAN, Ordering::Relaxed);
    if AP_OWNER_AP_ACTIVE.swap(false, Ordering::AcqRel) {
        super::nan::stop_nan().ok();
        if let Err(err) = super::wifi::stop_direct_ap_beacon_source() {
            telemetry::record_log(format!(
                "event type=mode.ap_owner state=ap_stop_failed msg={}",
                crate::commands::protocol::escape_value(&err.to_string())
            ));
            return;
        }
        AP_OWNER_STOPS.fetch_add(1, Ordering::Relaxed);
        if let Err(err) = super::nan::start_raw_window(channel, "mgmt") {
            telemetry::record_log(format!(
                "event type=mode.ap_owner state=nan_watch_failed msg={}",
                crate::commands::protocol::escape_value(&err.to_string())
            ));
        } else {
            telemetry::record_log("event type=mode.ap_owner state=nan_detected ap_stopped=true");
        }
    }
}

fn start_raw_nan_duty(
    settings: &SharedSettings,
    reason: &'static str,
    default_channel: u8,
) -> Result<()> {
    if get_bool(settings, "nan.ap_owner", false) {
        return start_ap_owner(settings, reason, default_channel);
    }
    #[cfg(target_feature = "esp32s3ops")]
    {
        if matches!(reason, "boot" | "boot_window_done") && !get_bool(settings, "nan.boot", false) {
            stop_raw_nan_duty();
            telemetry::record_log(format!(
                "event type=mode.infra_radio medium=nan status=deferred target=s3 reason={} set=nan.boot=true",
                reason
            ));
            return Ok(());
        }
    }
    super::wifi::stop_raw_monitor().ok();
    let channel = get_u32(settings, "nan.channel", default_channel as u32).clamp(1, 13) as u8;
    let active_ms = get_u32(settings, "nan.active_ms", DEFAULT_NAN_ACTIVE_MS).clamp(50, 60_000);
    let duty_ms = get_u32(settings, "nan.wake_ms", DEFAULT_NAN_DUTY_MS)
        .max(active_ms)
        .clamp(100, 60_000);
    let light_sleep = get_bool(settings, "nan.light_sleep", true);
    let wake_early_ms = get_u32(settings, "nan.early_ms", DEFAULT_NAN_WAKE_EARLY_MS)
        .min(duty_ms.saturating_sub(active_ms));
    let dw_tu = get_u32(settings, "nan.dw_tu", DEFAULT_NAN_DW_TU).clamp(1, 65_535);
    let dw_offset_tu = get_u32(settings, "nan.dw_off_tu", DEFAULT_NAN_DW_OFFSET_TU);
    arm_raw_nan_beacon_window(None);
    // The production duty window must accept NAN sync beacons as well as DMesh
    // SDF follow-ups.  SDF-only filtering prevents TSF capture, so the next
    // window can never be aligned to the powered Android/Linux NAN cluster.
    let initial_recovery = sync_policy(settings) == SyncPolicy::ApOnly;
    super::nan::start_raw_window(channel, sync_window_filter(settings, initial_recovery))?;
    record_raw_nan_dw_start(dw_offset_tu, false, light_sleep);
    RAW_NAN_DUTY_ENABLED.store(true, Ordering::Relaxed);
    RAW_NAN_DUTY_ACTIVE.store(true, Ordering::Relaxed);
    let initial_window_ms = if initial_recovery {
        RAW_NAN_RECOVERY_RUNS.fetch_add(1, Ordering::Relaxed);
        get_u32(
            settings,
            "nan.ap_recovery_listen_ms",
            DEFAULT_AP_RECOVERY_LISTEN_MS,
        )
        .max(active_ms)
    } else {
        active_ms
    };
    RAW_NAN_RECOVERY_ACTIVE.store(initial_recovery, Ordering::Relaxed);
    RAW_NAN_DUTY_NEXT_MS.store(now_ms().wrapping_add(initial_window_ms), Ordering::Relaxed);
    if matches!(reason, "boot" | "boot_window_done") {
        let _ = queue_boot_discovery(settings, reason);
    }
    let queued_sent = super::nan::drain_raw_queue();
    telemetry::record_log(format!(
        "event type=mode.infra_radio medium=nan status=raw_duty channel={} reason={} duty_ms={} active_ms={} light_sleep={} wake_early_ms={} dw_tu={} dw_offset_tu={} sync_policy={} queued_sent={}",
        channel,
        reason,
        duty_ms,
        active_ms,
        light_sleep,
        wake_early_ms,
        dw_tu,
        dw_offset_tu,
        sync_policy_name(sync_policy(settings)),
        queued_sent
    ));
    Ok(())
}

/// Ensure the configured infra radios are ready for a powered or bounded
/// transfer without replacing the raw-NAN duty-cycle configuration.
fn ensure_infra_active_radios(settings: &SharedSettings, reason: &'static str) -> Result<()> {
    if !get_bool(settings, "wifi.enabled", true) {
        bail!("wifi is disabled; set wifi.enabled=true before mode active");
    }
    let channel =
        get_u32(settings, "nan.channel", get_u32(settings, "raw.ch", 6)).clamp(1, 13) as u8;
    if !RAW_NAN_DUTY_ENABLED.load(Ordering::Relaxed) {
        start_raw_nan_duty(settings, reason, channel)?;
    } else if !RAW_NAN_DUTY_ACTIVE.load(Ordering::Relaxed) {
        arm_raw_nan_beacon_window(None);
        super::nan::start_raw_window(channel, sync_window_filter(settings, false))?;
        let active_ms = get_u32(settings, "nan.active_ms", DEFAULT_NAN_ACTIVE_MS).clamp(50, 60_000);
        let queued_sent = super::nan::drain_raw_queue();
        record_raw_nan_dw_start(
            get_u32(settings, "nan.dw_off_tu", DEFAULT_NAN_DW_OFFSET_TU),
            false,
            false,
        );
        RAW_NAN_DUTY_ACTIVE.store(true, Ordering::Relaxed);
        RAW_NAN_DUTY_NEXT_MS.store(now_ms().wrapping_add(active_ms), Ordering::Relaxed);
        telemetry::record_log(format!(
            "event type=mode.infra_active wifi=started channel={} reason={} queued_sent={}",
            channel, reason, queued_sent
        ));
    }
    start_infra_lora(settings, reason)
}

pub fn stop_raw_nan_duty() {
    RAW_NAN_DUTY_ENABLED.store(false, Ordering::Relaxed);
    RAW_NAN_DUTY_ACTIVE.store(false, Ordering::Relaxed);
    RAW_NAN_DUTY_NEXT_MS.store(0, Ordering::Relaxed);
    RAW_NAN_MISS_BACKOFF_MS.store(0, Ordering::Relaxed);
    RAW_NAN_SYNC_SOURCE.store(SYNC_SOURCE_NONE, Ordering::Relaxed);
}

pub fn raw_nan_duty_enabled() -> bool {
    RAW_NAN_DUTY_ENABLED.load(Ordering::Relaxed)
}

fn selected_sync_beacon(settings: &SharedSettings) -> Option<(u8, super::nan::SyncBeacon)> {
    let policy = sync_policy(settings);
    let nan_loss_ms = get_u32(settings, "nan.ap_loss_ms", DEFAULT_AP_LOSS_MS);
    if policy != SyncPolicy::ApOnly {
        if let Some(beacon) = super::nan::last_nan_sync_beacon() {
            if super::nan::nan_beacon_age_ms().is_some_and(|age| age <= nan_loss_ms) {
                return Some((SYNC_SOURCE_NAN, beacon));
            }
        }
    }
    if policy != SyncPolicy::NanOnly {
        if let Some(beacon) = super::nan::last_ap_sync_beacon() {
            let max_age = get_u32(settings, "nan.ap_recovery_ms", DEFAULT_AP_RECOVERY_MS)
                .saturating_add(get_u32(
                    settings,
                    "nan.ap_recovery_listen_ms",
                    DEFAULT_AP_RECOVERY_LISTEN_MS,
                ));
            if super::nan::ap_beacon_age_ms().is_some_and(|age| age <= max_age) {
                return Some((
                    if beacon.direct {
                        SYNC_SOURCE_DIRECT_AP
                    } else {
                        SYNC_SOURCE_AP
                    },
                    beacon,
                ));
            }
        }
    }
    None
}

fn sync_window_filter(settings: &SharedSettings, recovery: bool) -> &'static str {
    if recovery || sync_policy(settings) == SyncPolicy::ApOnly {
        "sync"
    } else {
        "nan"
    }
}

fn sync_policy_name(policy: SyncPolicy) -> &'static str {
    match policy {
        SyncPolicy::Auto => "auto",
        SyncPolicy::NanOnly => "nan_only",
        SyncPolicy::ApOnly => "ap_only",
    }
}

fn sync_source_name(source: u8) -> &'static str {
    match source {
        SYNC_SOURCE_NAN => "nan",
        SYNC_SOURCE_DIRECT_AP => "direct_ap",
        SYNC_SOURCE_AP => "ap",
        _ => "none",
    }
}

fn sync_wake_plan(
    settings: &SharedSettings,
    idle_ms: u32,
    wake_early_ms: u32,
    nan_dw_tu: u32,
    nan_dw_offset_tu: u32,
) -> Option<(u8, super::wifi::BeaconWakePlan)> {
    let (source, beacon) = selected_sync_beacon(settings)?;
    let (period_tu, offset_tu) = if source == SYNC_SOURCE_NAN {
        (nan_dw_tu, nan_dw_offset_tu)
    } else {
        (get_u32(settings, "nan.ap_slot_tu", DEFAULT_AP_SLOT_TU), 0)
    };
    let snapshot = super::wifi::BeaconSnapshot {
        count: 0,
        local_us: beacon.local_us,
        tsf_us: beacon.tsf_us,
    };
    super::wifi::beacon_wake_plan_from(snapshot, idle_ms, period_tu, offset_tu, wake_early_ms)
        .map(|plan| (source, plan))
}

fn deadline_due(now: u32, deadline: u32) -> bool {
    deadline == 0 || now.wrapping_sub(deadline) < u32::MAX / 2
}

fn poll_raw_nan_duty(settings: &SharedSettings) {
    if !RAW_NAN_DUTY_ENABLED.load(Ordering::Relaxed) {
        return;
    }
    let now = now_ms();
    let deadline = RAW_NAN_DUTY_NEXT_MS.load(Ordering::Relaxed);
    if deadline != 0 && now.wrapping_sub(deadline) >= u32::MAX / 2 {
        return;
    }
    let channel = get_u32(settings, "nan.channel", 6).clamp(1, 13) as u8;
    let active_ms = get_u32(settings, "nan.active_ms", DEFAULT_NAN_ACTIVE_MS).clamp(50, 60_000);
    let duty_ms = get_u32(settings, "nan.wake_ms", DEFAULT_NAN_DUTY_MS)
        .max(active_ms)
        .clamp(100, 60_000);
    let light_sleep = get_bool(settings, "nan.light_sleep", true);
    let wake_early_ms = get_u32(settings, "nan.early_ms", DEFAULT_NAN_WAKE_EARLY_MS)
        .min(duty_ms.saturating_sub(active_ms));
    let dw_tu = get_u32(settings, "nan.dw_tu", DEFAULT_NAN_DW_TU).clamp(1, 65_535);
    let dw_offset_tu = get_u32(settings, "nan.dw_off_tu", DEFAULT_NAN_DW_OFFSET_TU);
    let hold_active = infra_radio_hold_active();
    let source_before_window = selected_sync_beacon(settings).map(|(source, _)| source);
    let recovery_due = source_before_window.is_none()
        && sync_policy(settings) != SyncPolicy::NanOnly
        && deadline_due(now, RAW_NAN_RECOVERY_NEXT_MS.load(Ordering::Relaxed));
    let window_active_ms = if recovery_due {
        get_u32(
            settings,
            "nan.ap_recovery_listen_ms",
            DEFAULT_AP_RECOVERY_LISTEN_MS,
        )
        .max(active_ms)
    } else {
        active_ms
    };

    // A powered gateway, bounded transfer, or locally woken console owns the
    // radio. If duty sleep had already stopped Wi-Fi, bring it up immediately;
    // otherwise retain the current receiver without churn.
    if hold_active && !RAW_NAN_DUTY_ACTIVE.load(Ordering::Relaxed) {
        if let Err(err) = ensure_infra_active_radios(settings, "active_session") {
            telemetry::record_log(format!(
                "event type=mode.infra_active wifi=started ok=false msg={}",
                crate::commands::protocol::escape_value(&err.to_string())
            ));
            RAW_NAN_DUTY_NEXT_MS.store(now.wrapping_add(1_000), Ordering::Relaxed);
        }
        return;
    }

    if RAW_NAN_DUTY_ACTIVE.load(Ordering::Relaxed) {
        // A GPIO0/DTR or UART wake deliberately owns a short debug window.
        // Keep the existing raw Wi-Fi instance up for that window instead of
        // tearing it down and rebuilding it every `nan.active_ms`. Apart from
        // wasting power, that restart loop races UART TX and leaves forwarded
        // console clients with a result but no prompt. Once the console window
        // expires the next poll follows the normal modem-off sleep path.
        if hold_active {
            // A powered gateway keeps raw Wi-Fi up specifically so it can
            // deliver queued addressed commands without waiting for its next
            // duty transition. Leaving this queue undrained made remote
            // `active` requests remain pending forever.
            super::nan::drain_raw_queue();
            RAW_NAN_DUTY_NEXT_MS.store(now.wrapping_add(active_ms), Ordering::Relaxed);
            return;
        }
        let recovery_window = RAW_NAN_RECOVERY_ACTIVE.swap(false, Ordering::AcqRel);
        if RAW_NAN_SYNC_SOURCE.load(Ordering::Relaxed) == SYNC_SOURCE_NAN {
            finish_raw_nan_beacon_window();
        }
        let queued_sent = super::nan::drain_raw_queue();
        super::nan::stop_nan().ok();
        if let Err(err) = super::wifi::stop_raw_wifi_for_sleep() {
            telemetry::record_log(format!(
                "event type=wifi.raw_sleep off=false msg={}",
                crate::commands::protocol::escape_value(&err.to_string())
            ));
        }
        RAW_NAN_DUTY_ACTIVE.store(false, Ordering::Relaxed);
        let backoff_ms = RAW_NAN_MISS_BACKOFF_MS.swap(0, Ordering::Relaxed);
        let idle_ms = duty_ms.saturating_sub(active_ms).saturating_add(backoff_ms);
        let selected_plan = sync_wake_plan(settings, idle_ms, wake_early_ms, dw_tu, dw_offset_tu);
        let sync_plan = selected_plan.map(|(_, plan)| plan);
        let selected_source = selected_plan
            .map(|(source, _)| source)
            .unwrap_or(SYNC_SOURCE_NONE);
        RAW_NAN_SYNC_SOURCE.store(selected_source, Ordering::Relaxed);
        if recovery_window {
            RAW_NAN_RECOVERY_NEXT_MS.store(
                now_ms().wrapping_add(get_u32(
                    settings,
                    "nan.ap_recovery_ms",
                    DEFAULT_AP_RECOVERY_MS,
                )),
                Ordering::Relaxed,
            );
        }
        let window_delay_ms = sync_plan
            .map(|plan| plan.window_delay_ms)
            .unwrap_or(idle_ms);
        let light_sleep_ms = sync_plan
            .map(|plan| plan.light_sleep_ms)
            .unwrap_or_else(|| idle_ms.saturating_sub(wake_early_ms));
        let beacon_age_ms = sync_plan.map(|plan| plan.beacon_age_ms);
        telemetry::record_log(format!(
            "event type=nan.duty phase=idle channel={} idle_ms={} miss_backoff_ms={} window_delay_ms={} light_sleep={} light_sleep_ms={} wake_early_ms={} sync={} sync_source={} recovery={} beacon_age_ms={} dw_tu={} dw_offset_tu={} queued_sent={}",
            channel,
            idle_ms,
            backoff_ms,
            window_delay_ms,
            light_sleep,
            light_sleep_ms,
            wake_early_ms,
            sync_plan.is_some(),
            sync_source_name(selected_source),
            recovery_window,
            beacon_age_ms
                .map(|value| value.to_string())
                .unwrap_or_else(|| "none".to_string()),
            dw_tu,
            dw_offset_tu,
            queued_sent
        ));
        if light_sleep {
            let sleep_started_ms = now_ms();
            loop {
                let elapsed_ms = now_ms().wrapping_sub(sleep_started_ms);
                if elapsed_ms >= light_sleep_ms || super::serial::is_active() {
                    break;
                }
                let remaining_ms = light_sleep_ms.saturating_sub(elapsed_ms);
                if let Err(err) = super::sleep::idle_light_sleep(settings, remaining_ms) {
                    telemetry::record_log(format!(
                        "event type=nan.duty phase=light_sleep ok=false msg={}",
                        crate::commands::protocol::escape_value(&err.to_string())
                    ));
                    arm_raw_nan_beacon_window(None);
                    RAW_NAN_DUTY_NEXT_MS
                        .store(now.wrapping_add(window_delay_ms), Ordering::Relaxed);
                    return;
                }
                if now_ms().wrapping_sub(sleep_started_ms) < light_sleep_ms
                    && !super::serial::is_active()
                {
                    RAW_NAN_DW_EARLY_WAKE_TOTAL.fetch_add(1, Ordering::Relaxed);
                }
            }
            arm_raw_nan_beacon_window(sync_plan);
            match super::nan::start_raw_window(channel, sync_window_filter(settings, recovery_due))
            {
                Ok(()) => {
                    let queued_sent = super::nan::drain_raw_queue();
                    record_raw_nan_dw_start(dw_offset_tu, sync_plan.is_some(), true);
                    let uart_heartbeat = super::serial::on_raw_nan_wake(active_ms);
                    RAW_NAN_DUTY_ACTIVE.store(true, Ordering::Relaxed);
                    RAW_NAN_RECOVERY_ACTIVE.store(recovery_due, Ordering::Relaxed);
                    if recovery_due {
                        RAW_NAN_RECOVERY_RUNS.fetch_add(1, Ordering::Relaxed);
                    }
                    RAW_NAN_DUTY_NEXT_MS
                        .store(now_ms().wrapping_add(window_active_ms), Ordering::Relaxed);
                    telemetry::record_log(format!(
                        "event type=nan.duty phase=active channel={} active_ms={} wake=light recovery={} queued_sent={} uart_heartbeat={}",
                        channel, window_active_ms, recovery_due, queued_sent, uart_heartbeat
                    ));
                }
                Err(err) => {
                    RAW_NAN_DUTY_NEXT_MS.store(now_ms().wrapping_add(1_000), Ordering::Relaxed);
                    telemetry::record_log(format!(
                        "event type=nan.duty phase=active wake=light ok=false msg={}",
                        crate::commands::protocol::escape_value(&err.to_string())
                    ));
                }
            }
        } else {
            arm_raw_nan_beacon_window(sync_plan);
            RAW_NAN_DUTY_NEXT_MS.store(now.wrapping_add(window_delay_ms), Ordering::Relaxed);
        }
        return;
    }

    // The non-light-sleep diagnostic path arms its beacon baseline when it
    // schedules the window above. Keep it intact until this delayed start.
    match super::nan::start_raw_window(channel, sync_window_filter(settings, recovery_due)) {
        Ok(()) => {
            let queued_sent = super::nan::drain_raw_queue();
            // The non-light-sleep diagnostic path does not retain its prior
            // wake plan across polls, so only mark it synchronized when the
            // active window itself was entered from the light-sleep path.
            record_raw_nan_dw_start(dw_offset_tu, false, false);
            let uart_heartbeat = super::serial::on_raw_nan_wake(active_ms);
            RAW_NAN_DUTY_ACTIVE.store(true, Ordering::Relaxed);
            RAW_NAN_RECOVERY_ACTIVE.store(recovery_due, Ordering::Relaxed);
            if recovery_due {
                RAW_NAN_RECOVERY_RUNS.fetch_add(1, Ordering::Relaxed);
            }
            RAW_NAN_DUTY_NEXT_MS.store(now.wrapping_add(window_active_ms), Ordering::Relaxed);
            telemetry::record_log(format!(
                "event type=nan.duty phase=active channel={} active_ms={} recovery={} queued_sent={} uart_heartbeat={}",
                channel, window_active_ms, recovery_due, queued_sent, uart_heartbeat
            ));
        }
        Err(err) => {
            RAW_NAN_DUTY_NEXT_MS.store(now.wrapping_add(1_000), Ordering::Relaxed);
            telemetry::record_log(format!(
                "event type=nan.duty phase=active ok=false msg={}",
                crate::commands::protocol::escape_value(&err.to_string())
            ));
        }
    }
}

fn arm_raw_nan_beacon_window(plan: Option<super::wifi::BeaconWakePlan>) {
    let snapshot = super::wifi::beacon_snapshot();
    RAW_NAN_BEACON_BASELINE.store(snapshot.count, Ordering::Relaxed);
    let (expected_tsf_us, period_us) = plan
        .map(|plan| (plan.expected_tsf_us, plan.period_us))
        .unwrap_or((0, 0));
    RAW_NAN_EXPECT_TSF_LO.store(expected_tsf_us as u32, Ordering::Relaxed);
    RAW_NAN_EXPECT_TSF_HI.store((expected_tsf_us >> 32) as u32, Ordering::Relaxed);
    RAW_NAN_EXPECT_PERIOD_US.store(period_us, Ordering::Relaxed);
}

fn finish_raw_nan_beacon_window() {
    const LATE_TOLERANCE_US: u64 = 80_000;
    const MISS_BACKOFF_MS: u32 = 1_000;

    let snapshot = super::wifi::beacon_snapshot();
    let baseline = RAW_NAN_BEACON_BASELINE.load(Ordering::Relaxed);
    let received = snapshot.count.saturating_sub(baseline);
    if received == 0 {
        RAW_NAN_BEACON_MISSED.fetch_add(1, Ordering::Relaxed);
        record_raw_nan_dw_finish(0, 0);
        RAW_NAN_MISS_BACKOFF_MS.store(MISS_BACKOFF_MS, Ordering::Relaxed);
        telemetry::record_log(format!(
            "event type=nan.duty beacon=missed active_ms_backoff={} baseline={} current={}",
            MISS_BACKOFF_MS, baseline, snapshot.count
        ));
        return;
    }

    RAW_NAN_BEACON_SEEN.fetch_add(received, Ordering::Relaxed);
    record_raw_nan_dw_finish(received, RAW_NAN_DW_FLAG_BEACON);
    let expected_tsf_us = (u64::from(RAW_NAN_EXPECT_TSF_HI.load(Ordering::Relaxed)) << 32)
        | u64::from(RAW_NAN_EXPECT_TSF_LO.load(Ordering::Relaxed));
    let period_us = u64::from(RAW_NAN_EXPECT_PERIOD_US.load(Ordering::Relaxed));
    if expected_tsf_us == 0 || period_us == 0 || snapshot.tsf_us == 0 {
        return;
    }

    let delta_us = snapshot.tsf_us.abs_diff(expected_tsf_us);
    if delta_us <= LATE_TOLERANCE_US {
        return;
    }
    RAW_NAN_BEACON_LATE.fetch_add(1, Ordering::Relaxed);
    raw_nan_dw_add_flags(RAW_NAN_DW_FLAG_LATE);
    let next_dw =
        snapshot.tsf_us >= expected_tsf_us && delta_us.abs_diff(period_us) <= LATE_TOLERANCE_US;
    if next_dw {
        RAW_NAN_BEACON_LATE_NEXT_DW.fetch_add(1, Ordering::Relaxed);
        raw_nan_dw_add_flags(RAW_NAN_DW_FLAG_NEXT);
    } else {
        RAW_NAN_BEACON_DRIFT.fetch_add(1, Ordering::Relaxed);
        raw_nan_dw_add_flags(RAW_NAN_DW_FLAG_DRIFT);
    }
    telemetry::record_log(format!(
        "event type=nan.duty beacon=late class={} delta_us={} expected_tsf_us={} actual_tsf_us={} local_us={} period_us={}",
        if next_dw { "next_dw" } else { "drift" },
        delta_us,
        expected_tsf_us,
        snapshot.tsf_us,
        snapshot.local_us,
        period_us
    ));
}

fn record_raw_nan_dw_start(dw_offset_tu: u32, synced: bool, light_sleep: bool) {
    let seq = RAW_NAN_DW_TOTAL
        .fetch_add(1, Ordering::Relaxed)
        .wrapping_add(1);
    let index = (seq as usize) % RAW_NAN_DW_HISTORY_LEN;
    let mut flags = 0;
    if dw_offset_tu == 0 {
        RAW_NAN_DW0_TOTAL.fetch_add(1, Ordering::Relaxed);
        flags |= RAW_NAN_DW_FLAG_DW0;
    }
    if synced {
        RAW_NAN_DW_SYNC_TOTAL.fetch_add(1, Ordering::Relaxed);
        flags |= RAW_NAN_DW_FLAG_SYNC;
    }
    if light_sleep {
        flags |= RAW_NAN_DW_FLAG_LIGHT;
    }
    RAW_NAN_DW_HISTORY_START_MS[index].store(now_ms(), Ordering::Relaxed);
    RAW_NAN_DW_HISTORY_BEACONS[index].store(0, Ordering::Relaxed);
    RAW_NAN_DW_HISTORY_FLAGS[index].store(flags, Ordering::Relaxed);
    RAW_NAN_DW_HISTORY_SEQ[index].store(seq, Ordering::Release);
    RAW_NAN_DW_ACTIVE_SEQ.store(seq, Ordering::Release);
}

fn raw_nan_dw_add_flags(flags: u32) {
    let seq = RAW_NAN_DW_ACTIVE_SEQ.load(Ordering::Acquire);
    if seq == 0 {
        return;
    }
    let index = (seq as usize) % RAW_NAN_DW_HISTORY_LEN;
    if RAW_NAN_DW_HISTORY_SEQ[index].load(Ordering::Acquire) == seq {
        RAW_NAN_DW_HISTORY_FLAGS[index].fetch_or(flags, Ordering::Relaxed);
    }
}

fn record_raw_nan_dw_finish(beacons: u32, flags: u32) {
    let seq = RAW_NAN_DW_ACTIVE_SEQ.load(Ordering::Acquire);
    if seq == 0 {
        return;
    }
    let index = (seq as usize) % RAW_NAN_DW_HISTORY_LEN;
    if RAW_NAN_DW_HISTORY_SEQ[index].load(Ordering::Acquire) == seq {
        RAW_NAN_DW_HISTORY_BEACONS[index].store(beacons, Ordering::Relaxed);
        RAW_NAN_DW_HISTORY_FLAGS[index].fetch_or(flags, Ordering::Relaxed);
    }
}

fn raw_nan_dw_recent_fields() -> String {
    let newest = RAW_NAN_DW_TOTAL.load(Ordering::Relaxed);
    let mut records = Vec::with_capacity(RAW_NAN_DW_HISTORY_LEN);
    for offset in 0..RAW_NAN_DW_HISTORY_LEN {
        let seq = newest.saturating_sub(offset as u32);
        if seq == 0 {
            break;
        }
        let index = (seq as usize) % RAW_NAN_DW_HISTORY_LEN;
        if RAW_NAN_DW_HISTORY_SEQ[index].load(Ordering::Acquire) != seq {
            continue;
        }
        records.push(format!(
            "{}:{}:{}:{}",
            seq,
            RAW_NAN_DW_HISTORY_START_MS[index].load(Ordering::Relaxed),
            RAW_NAN_DW_HISTORY_BEACONS[index].load(Ordering::Relaxed),
            RAW_NAN_DW_HISTORY_FLAGS[index].load(Ordering::Relaxed),
        ));
    }
    records.join(",")
}

pub fn raw_nan_status_fields() -> String {
    format!(
        "nan_dw_total={} nan_dw0_total={} nan_dw_sync_total={} nan_dw_early_wake_total={} nan_dw_recent=seq:start_ms:beacons:flags:{} nan_beacon_seen={} nan_beacon_missed={} nan_beacon_late={} nan_beacon_late_next_dw={} nan_beacon_drift={} nan_miss_backoff_ms={} sync_source={} ap_owner={} ap_active={} sleep_inhibited={} ap_owner_start={} ap_owner_stop={} ap_recovery_runs={} ap_recovery_next_ms={}",
        RAW_NAN_DW_TOTAL.load(Ordering::Relaxed),
        RAW_NAN_DW0_TOTAL.load(Ordering::Relaxed),
        RAW_NAN_DW_SYNC_TOTAL.load(Ordering::Relaxed),
        RAW_NAN_DW_EARLY_WAKE_TOTAL.load(Ordering::Relaxed),
        raw_nan_dw_recent_fields(),
        RAW_NAN_BEACON_SEEN.load(Ordering::Relaxed),
        RAW_NAN_BEACON_MISSED.load(Ordering::Relaxed),
        RAW_NAN_BEACON_LATE.load(Ordering::Relaxed),
        RAW_NAN_BEACON_LATE_NEXT_DW.load(Ordering::Relaxed),
        RAW_NAN_BEACON_DRIFT.load(Ordering::Relaxed),
        RAW_NAN_MISS_BACKOFF_MS.load(Ordering::Relaxed),
        sync_source_name(RAW_NAN_SYNC_SOURCE.load(Ordering::Relaxed)),
        AP_OWNER_RUNNING.load(Ordering::Relaxed),
        AP_OWNER_AP_ACTIVE.load(Ordering::Relaxed),
        if AP_OWNER_AP_ACTIVE.load(Ordering::Relaxed) { "ap" } else { "none" },
        AP_OWNER_STARTS.load(Ordering::Relaxed),
        AP_OWNER_STOPS.load(Ordering::Relaxed),
        RAW_NAN_RECOVERY_RUNS.load(Ordering::Relaxed),
        RAW_NAN_RECOVERY_NEXT_MS.load(Ordering::Relaxed),
    )
}

fn queue_boot_discovery(_settings: &SharedSettings, _source: &'static str) -> Result<()> {
    let payload = ping_packet(false);
    super::nan::queue_raw_broadcast(&payload)?;
    telemetry::record_log(format!(
        "event type=mode.discovery queued=true medium=nan from={} len={}",
        local_suffix4_hex()?,
        payload.len()
    ));
    Ok(())
}

fn local_suffix4_hex() -> Result<String> {
    let mut mac = [0_u8; 6];
    unsafe {
        let ret = sys::esp_read_mac(mac.as_mut_ptr(), sys::esp_mac_type_t_ESP_MAC_WIFI_STA);
        if ret != sys::ESP_OK {
            bail!("esp_read_mac failed err=0x{ret:x}");
        }
    }
    Ok(format!(
        "{:02x}{:02x}{:02x}{:02x}",
        mac[2], mac[3], mac[4], mac[5]
    ))
}

fn send_status_ping(settings: &SharedSettings, source: &'static str) -> Result<()> {
    if PRODUCT_MODE.load(Ordering::Relaxed) == MODE_COMPANION {
        bail!("companion firmware does not send ping");
    }
    let bytes = ping_packet(source == "rx");
    let lora = super::lora::send_raw(settings, &bytes).is_ok();
    let wifi = super::wifi::forward_management_packet(&bytes).is_ok();
    let nan = super::nan::forward_or_queue_packet(&bytes).is_ok();
    PING_TX.fetch_add(1, Ordering::Relaxed);
    telemetry::record_log(format!(
        "event type=mode.ping_tx source={} len={} lora={} wifi_raw={} nan={}",
        source,
        bytes.len(),
        lora,
        wifi,
        nan
    ));
    Ok(())
}

/// Build the shared raw-radio ping envelope. Method 33 is the stable ping
/// method; status marks a pong so receiving infra nodes do not answer it.
fn ping_packet(reply: bool) -> Vec<u8> {
    let mut request = CommandRequest::new_binary(33);
    if reply {
        request
            .args
            .insert(crate::commands::protocol::CBOR_STATUS, "pong".to_string());
    }
    crate::commands::protocol::encode_binary(&request)
}

fn configured_mode(settings: &SharedSettings) -> u8 {
    let from_mode = settings.borrow().get_str("mode").ok().flatten();
    if matches!(from_mode.as_deref(), Some("companion")) {
        telemetry::record_log("event type=mode.startup saved=companion action=ignore start=infra");
    }
    MODE_INFRA
}

fn get_u32(settings: &SharedSettings, key: &str, default: u32) -> u32 {
    settings
        .borrow()
        .get_i32(key, default as i32)
        .unwrap_or(default as i32)
        .max(0) as u32
}

fn get_bool(settings: &SharedSettings, key: &str, default: bool) -> bool {
    settings.borrow().get_bool(key, default).unwrap_or(default)
}

fn now_ms() -> u32 {
    (unsafe { sys::esp_timer_get_time() } / 1000) as u32
}

fn boot_print(line: &str) {
    // Retain startup progress for diagnostics without writing UART0 while the
    // radio stack starts. A burst of small UART writes at this point can wedge
    // the classic ESP32 driver's TX ISR.
    telemetry::record_log(line);
}

fn mode_name() -> &'static str {
    match PRODUCT_MODE.load(Ordering::Relaxed) {
        MODE_INFRA => "infra",
        _ => "companion",
    }
}

struct ModeCommand {
    settings: SharedSettings,
}

impl CommandHandler for ModeCommand {
    fn name(&self) -> &'static str {
        "mode"
    }

    fn handle(&mut self, request: &CommandRequest) -> Result<CommandResponse> {
        // `active` and `idle` are compact-CBOR command aliases for the
        // runtime-only radio override. Keep the implementation in `mode` so
        // both direct UART and addressed raw-NAN commands have identical
        // semantics.
        if request.name == "active" {
            if is_companion_mode() {
                bail!("active requires infra mode; run mode infra=true first");
            }
            start_infra_active_session(&self.settings, None, "command_alias")?;
            return Ok(CommandResponse::ok(status_text()));
        }
        if request.name == "idle" {
            if is_companion_mode() {
                bail!("idle requires infra mode; run mode infra=true first");
            }
            stop_infra_active_session();
            return Ok(CommandResponse::ok(status_text()));
        }
        if request
            .arg("infra")
            .map(parse_bool)
            .transpose()?
            .unwrap_or(false)
        {
            if save_requested(request) {
                let mut settings = self.settings.borrow_mut();
                settings.set_str("mode", "infra")?;
                settings.set_bool("ble.comp", false)?;
                drop(settings);
                set_infra(&self.settings, false, "command")?;
            } else {
                set_infra(&self.settings, false, "command")?;
            }
            return Ok(CommandResponse::ok(status_text()));
        }
        if request
            .arg("companion")
            .map(parse_bool)
            .transpose()?
            .unwrap_or(false)
        {
            PRODUCT_MODE.store(MODE_COMPANION, Ordering::Relaxed);
            if save_requested(request) {
                self.settings.borrow_mut().set_str("mode", "companion")?;
            }
            enter_companion_advertising(
                &self.settings,
                get_u32(&self.settings, "cm.win_ms", DEFAULT_WINDOW_MS),
                get_u32(&self.settings, "cm.adv_ms", DEFAULT_ADV_MS),
                "command",
            )?;
            return Ok(CommandResponse::ok(status_text()));
        }
        if let Some(enabled) = request
            .arg("lora_sleep_listen")
            .or_else(|| request.arg("lora_listen"))
        {
            let enabled = parse_bool(enabled)?;
            if save_requested(request) {
                self.settings.borrow_mut().set_bool("cm.lora", enabled)?;
            }
            return Ok(CommandResponse::ok(status_text()));
        }
        if let Some(raw_nan) = request.arg("raw_nan").map(parse_bool).transpose()? {
            if raw_nan {
                PRODUCT_MODE.store(MODE_INFRA, Ordering::Relaxed);
                let channel = request.arg_i32("channel")?.unwrap_or(6).clamp(1, 13) as u8;
                start_raw_nan_duty(&self.settings, "command", channel)?;
                if request
                    .arg("lora")
                    .map(parse_bool)
                    .transpose()?
                    .is_some_and(|enabled| !enabled)
                {
                    super::lora::sleep_radio(&self.settings)?;
                }
            } else {
                stop_ap_owner().ok();
                stop_raw_nan_duty();
                super::nan::stop_nan().ok();
                super::wifi::stop_raw_monitor().ok();
            }
            return Ok(CommandResponse::ok(status_text()));
        }
        if request
            .arg("raw_wifi")
            .or_else(|| request.arg("raw"))
            .map(parse_bool)
            .transpose()?
            .unwrap_or(false)
        {
            let channel = request.arg_i32("channel")?.unwrap_or(6).clamp(1, 13) as u8;
            super::wifi::start_raw_monitor_mode(channel, "dmesh")?;
            return Ok(CommandResponse::ok(format!(
                "mode raw_wifi=true channel={} {}",
                channel,
                status_text()
            )));
        }
        if request
            .arg("raw_wifi")
            .or_else(|| request.arg("raw"))
            .map(parse_bool)
            .transpose()?
            .is_some_and(|enabled| !enabled)
        {
            super::wifi::stop_raw_monitor()?;
            return Ok(CommandResponse::ok(format!(
                "mode raw_wifi=false {}",
                status_text()
            )));
        }
        if request
            .arg("ping")
            .map(parse_bool)
            .transpose()?
            .unwrap_or(false)
        {
            send_status_ping(&self.settings, "command")?;
            return Ok(CommandResponse::ok(status_text()));
        }
        if request.arg("active").is_some() || request.arg("active_ms").is_some() {
            let enabled = request
                .arg("active")
                .map(parse_bool)
                .transpose()?
                .unwrap_or(true);
            if is_companion_mode() {
                if enabled {
                    let window_ms = request
                        .arg_i32("active_ms")?
                        .or(request.arg_i32("ms")?)
                        .or(request.arg_i32("window_ms")?)
                        .unwrap_or(DEFAULT_ACTIVE_MS as i32)
                        .max(1_000) as u32;
                    enter_companion_advertising(
                        &self.settings,
                        window_ms,
                        get_u32(&self.settings, "cm.adv_ms", DEFAULT_ADV_MS),
                        "command",
                    )?;
                } else {
                    enter_companion_sleep(&self.settings)?;
                }
                return Ok(CommandResponse::ok(status_text()));
            }
            if enabled {
                let active_ms = request
                    .arg_i32("active_ms")?
                    .or(request.arg_i32("ms")?)
                    .or(request.arg_i32("window_ms")?)
                    .map(|value| value.clamp(1_000, 300_000) as u32);
                start_infra_active_session(&self.settings, active_ms, "command")?;
            } else {
                stop_infra_active_session();
            }
            return Ok(CommandResponse::ok(status_text()));
        }
        if request
            .arg("advertise")
            .or_else(|| request.arg("adv"))
            .map(parse_bool)
            .transpose()?
            .unwrap_or(false)
        {
            let window_ms = request
                .arg_i32("window_ms")?
                .or(request.arg_i32("ms")?)
                .unwrap_or(DEFAULT_WINDOW_MS as i32)
                .max(1_000) as u32;
            let adv_ms = request
                .arg_i32("adv_ms")?
                .unwrap_or(DEFAULT_ADV_MS as i32)
                .clamp(100, 10_000) as u32;
            enter_companion_advertising(&self.settings, window_ms, adv_ms, "command")?;
            return Ok(CommandResponse::ok(status_text()));
        }
        if request
            .arg("sleep")
            .map(parse_bool)
            .transpose()?
            .unwrap_or(false)
        {
            enter_companion_sleep(&self.settings)?;
            return Ok(CommandResponse::ok("mode sleep rejected"));
        }
        Ok(CommandResponse::ok(status_text()))
    }
}

fn save_requested(request: &CommandRequest) -> bool {
    request
        .arg("save")
        .map(parse_bool)
        .transpose()
        .unwrap_or(None)
        .unwrap_or(false)
}

fn status_text() -> String {
    format!(
        "mode active={} infra_active={} infra_active_persistent={} infra_active_deadline_ms={} infra_active_start={} infra_active_stop={} infra_active_expire={} infra_active_uart_extend={} companion_advertising={} companion_pending_advertising={} pending={} deadline_ms={} ping_rx={} ping_tx={} {}",
        mode_name(),
        infra_active_session_enabled(),
        INFRA_ACTIVE_PERSISTENT.load(Ordering::Relaxed),
        INFRA_ACTIVE_DEADLINE_MS.load(Ordering::Relaxed),
        INFRA_ACTIVE_STARTS.load(Ordering::Relaxed),
        INFRA_ACTIVE_STOPS.load(Ordering::Relaxed),
        INFRA_ACTIVE_EXPIRES.load(Ordering::Relaxed),
        INFRA_ACTIVE_UART_EXTENDS.load(Ordering::Relaxed),
        COMPANION_ADVERTISING.load(Ordering::Relaxed),
        COMPANION_PENDING_ADVERTISING.load(Ordering::Relaxed),
        telemetry::pending_message_count(),
        COMPANION_DEADLINE_MS.load(Ordering::Relaxed),
        PING_RX.load(Ordering::Relaxed),
        PING_TX.load(Ordering::Relaxed),
        raw_nan_status_fields()
    )
}

#[cfg(test)]
mod tests {
    use super::ping_packet;
    use crate::commands::protocol::{decode_binary, CBOR_STATUS};

    #[test]
    fn radio_ping_packets_are_compact_cbor_status_requests() {
        let ping = decode_binary(&ping_packet(false)).expect("ping packet must decode as CBOR");
        assert_eq!(ping.method, 33);
        assert!(ping.args.is_empty());

        let pong = decode_binary(&ping_packet(true)).expect("pong packet must decode as CBOR");
        assert_eq!(pong.method, 33);
        assert_eq!(
            pong.args.get(&CBOR_STATUS).map(String::as_str),
            Some("pong")
        );
    }
}
