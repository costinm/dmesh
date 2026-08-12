use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicU8, Ordering};

use anyhow::{anyhow, bail, Result};
use esp_idf_sys as sys;

use crate::commands::{CommandHandler, CommandRegistry, CommandRequest, CommandResponse};

use super::settings::{parse_bool, SharedSettings};
use super::telemetry;

const MODE_COMPANION: u8 = 0;
const MODE_INFRA: u8 = 1;
const MODE_SLEEPY: u8 = 2;
const DEFAULT_ADV_MS: u32 = 1_000;
const DEFAULT_PENDING_ADV_MS: u32 = 1_500;
const DEFAULT_WINDOW_MS: u32 = 10_000;
const DEFAULT_ACTIVE_MS: u32 = 5_000;
const DEFAULT_PENDING_WINDOW_MS: u32 = 30_000;
const DEFAULT_WAKE_MS: u32 = 30_000;
const DEFAULT_NAN_DUTY_MS: u32 = 4_000;
// The active interval is the NAN receive/data dwell, not the radio resume
// margin. The scheduler adds the measured pre-wake margin separately.
const DEFAULT_NAN_ACTIVE_MS: u32 = 64;
// Fixed pre-wake guard. Packet loss is intentionally diagnostic only; it must
// not retune the schedule because a missed 802.11 frame is not evidence that
// the local clock or radio-start latency changed.
const NAN_WAKE_MARGIN_MIN_MS: u32 = 1;
// Keep the bounds explicit for diagnostics and future controlled experiments.
// The current production profile does not adapt this value at runtime: a
// missed frame can be caused by the NAN publisher or channel occupancy, not by
// local startup latency, so changing the schedule automatically would hide
// the failure mode.
const NAN_WAKE_MARGIN_MAX_MS: u32 = 2_000;
const DEFAULT_NAN_WAKE_EARLY_MS: u32 = 40;
const DEFAULT_NAN_DW_TU: u32 = 512;
const DEFAULT_NAN_DW_OFFSET_TU: u32 = 0;
// Keep the last NAN TSF usable across the normal 4 s duty interval and a
// delayed UART/active window, while still forcing recovery when the cluster
// has been absent for a bounded period.
// In sleepy mode three normal 4 s duty intervals without a beacon are enough
// to declare the cluster unavailable.  Recovery first listens for the AP (or
// another NAN sync source), then repeats a short scan every 16 s.
const DEFAULT_AP_LOSS_MS: u32 = 12_000;
const DEFAULT_AP_RECOVERY_MS: u32 = 16_000;
const DEFAULT_AP_RECOVERY_LISTEN_MS: u32 = 600;
// ESP-IDF requires SoftAP beacon intervals to be multiples of 100 TU. The AP
// timestamp still samples the same TSF clock used to select the separate
// 512-TU NAN DW grid below.
const DEFAULT_AP_BEACON_TU: u16 = 500;
const RAW_NAN_DW_HISTORY_LEN: usize = 8;
const RAW_NAN_TIMING_HISTORY_LEN: usize = 32;
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
/// Set while Main has handed the radio to the IP/TCP flash transport.  The
/// normal mode poller must not restart raw-NAN windows or light-sleep while a
/// socket listener owns the Wi-Fi driver.
static IP_TRANSPORT_ACTIVE: AtomicBool = AtomicBool::new(false);
static RAW_NAN_DUTY_ACTIVE: AtomicBool = AtomicBool::new(false);
static RAW_NAN_DUTY_NEXT_MS: AtomicU32 = AtomicU32::new(0);
static RAW_NAN_TARGET_WAKE_UNTIL_MS: AtomicU32 = AtomicU32::new(0);
static RAW_NAN_TARGET_WAKE_SESSION_END_SENT: AtomicBool = AtomicBool::new(false);
static RAW_NAN_SYNC_SOURCE: AtomicU8 = AtomicU8::new(SYNC_SOURCE_NONE);
static RAW_NAN_RECOVERY_NEXT_MS: AtomicU32 = AtomicU32::new(0);
static RAW_NAN_RECOVERY_RUNS: AtomicU32 = AtomicU32::new(0);
static RAW_NAN_RECOVERY_ACTIVE: AtomicBool = AtomicBool::new(false);
static AP_OWNER_RUNNING: AtomicBool = AtomicBool::new(false);
static AP_OWNER_AP_ACTIVE: AtomicBool = AtomicBool::new(false);
static AP_OWNER_STARTED_MS: AtomicU32 = AtomicU32::new(0);
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
static RAW_NAN_EXPECT_EXTENDS: AtomicU32 = AtomicU32::new(0);
static RAW_NAN_MISS_PROBES: AtomicU32 = AtomicU32::new(0);
static RAW_NAN_MISS_PROBE_ACTIVE: AtomicBool = AtomicBool::new(false);
static RAW_NAN_EXPECT_TSF_LO: AtomicU32 = AtomicU32::new(0);
static RAW_NAN_EXPECT_TSF_HI: AtomicU32 = AtomicU32::new(0);
static RAW_NAN_EXPECT_PERIOD_US: AtomicU32 = AtomicU32::new(0);
static RAW_NAN_WINDOW_START_US_LO: AtomicU32 = AtomicU32::new(0);
static RAW_NAN_WINDOW_START_US_HI: AtomicU32 = AtomicU32::new(0);
static RAW_NAN_LAST_WAKE_TO_BEACON_US: AtomicU32 = AtomicU32::new(0);
static RAW_NAN_LAST_BEACON_TO_SLEEP_US: AtomicU32 = AtomicU32::new(0);
static RAW_NAN_LAST_WAKE_TO_FIRST_FRAME_US: AtomicU32 = AtomicU32::new(0);
static RAW_NAN_LAST_MISS_WAKE_TO_FIRST_FRAME_US: AtomicU32 = AtomicU32::new(0);
static RAW_NAN_LAST_BEACON_TSF_LO: AtomicU32 = AtomicU32::new(0);
static RAW_NAN_LAST_BEACON_TSF_HI: AtomicU32 = AtomicU32::new(0);
static RAW_NAN_LAST_MISS_EXPECT_TSF_LO: AtomicU32 = AtomicU32::new(0);
static RAW_NAN_LAST_MISS_EXPECT_TSF_HI: AtomicU32 = AtomicU32::new(0);
static RAW_NAN_LAST_MISS_TSF_LO: AtomicU32 = AtomicU32::new(0);
static RAW_NAN_LAST_MISS_TSF_HI: AtomicU32 = AtomicU32::new(0);
static RAW_NAN_LAST_MISS_LOCAL_LO: AtomicU32 = AtomicU32::new(0);
static RAW_NAN_LAST_MISS_LOCAL_HI: AtomicU32 = AtomicU32::new(0);
static RAW_NAN_LAST_MISS_NOW_LO: AtomicU32 = AtomicU32::new(0);
static RAW_NAN_LAST_MISS_NOW_HI: AtomicU32 = AtomicU32::new(0);
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
// Runtime copy of the configured nan.early_ms guard. It changes only on boot
// or an explicit `mode nan_early_ms=...` experiment; no feedback loop adapts
// it from individual beacon outcomes.
static RAW_NAN_WAKE_EARLY_MS: AtomicU32 = AtomicU32::new(DEFAULT_NAN_WAKE_EARLY_MS);
static RAW_NAN_DW_ACTIVE_SEQ: AtomicU32 = AtomicU32::new(0);
// The data plane is permitted only for the short interval immediately after a
// selected NAN discovery window beacon.  Keeping this separate from the
// broader radio-on interval prevents an action/follow-up from being emitted
// after Android has already left channel 6.
static RAW_NAN_DATA_DW_DEADLINE_LO: AtomicU32 = AtomicU32::new(0);
static RAW_NAN_DATA_DW_DEADLINE_HI: AtomicU32 = AtomicU32::new(0);
static RAW_NAN_DATA_DW_PERIOD_US: AtomicU32 = AtomicU32::new(0);
static RAW_NAN_DATA_DW_STRIDE: AtomicU32 = AtomicU32::new(8);
const RAW_NAN_DATA_DW_DWELL_US: u64 = 32_000;
// The duty deadline must include the adaptive pre-wake margin.  Otherwise a
// margin larger than `nan.active_ms` turns a deliberately early wake into a
// missed beacon because Wi-Fi is stopped before the target DW arrives.
const RAW_NAN_DATA_DW_DWELL_MS: u32 = 32;
// The callback may arrive well after the nominal wake margin while the
// ESP32 radio/driver resumes. Keep a bounded receive floor so the first
// preceding beacon can extend the window to the selected sparse DW.
// Keep a small lower bound for driver polling and the 32 ms NAN data dwell;
// synchronized windows otherwise use wake_margin + dwell. Recovery windows
// have their own longer configured listen interval.
const RAW_NAN_BEACON_LISTEN_FLOOR_MS: u32 = 64;
// A 512-TU discovery window is 524,288 us. The beacon's phase within that
// window can move substantially when the source is an Android/host NAN
// publisher. The rendezvous contract is the selected DW0/DW8 slot, not a
// particular phase inside it, so accept any phase in the same slot. The slot
// index check below still rejects a beacon from DW0/DW8's neighbour.
const RAW_NAN_BEACON_LATE_TOLERANCE_US: u64 = 512 * 1024 - 1;
static RAW_NAN_DW_HISTORY_SEQ: [AtomicU32; RAW_NAN_DW_HISTORY_LEN] =
    [const { AtomicU32::new(0) }; RAW_NAN_DW_HISTORY_LEN];
static RAW_NAN_DW_HISTORY_START_MS: [AtomicU32; RAW_NAN_DW_HISTORY_LEN] =
    [const { AtomicU32::new(0) }; RAW_NAN_DW_HISTORY_LEN];
static RAW_NAN_DW_HISTORY_BEACONS: [AtomicU32; RAW_NAN_DW_HISTORY_LEN] =
    [const { AtomicU32::new(0) }; RAW_NAN_DW_HISTORY_LEN];
static RAW_NAN_DW_HISTORY_FLAGS: [AtomicU32; RAW_NAN_DW_HISTORY_LEN] =
    [const { AtomicU32::new(0) }; RAW_NAN_DW_HISTORY_LEN];
static RAW_NAN_TIMING_SEQ: [AtomicU32; RAW_NAN_TIMING_HISTORY_LEN] =
    [const { AtomicU32::new(0) }; RAW_NAN_TIMING_HISTORY_LEN];
static RAW_NAN_TIMING_FIRST_FRAME_US: [AtomicU32; RAW_NAN_TIMING_HISTORY_LEN] =
    [const { AtomicU32::new(0) }; RAW_NAN_TIMING_HISTORY_LEN];
static RAW_NAN_TIMING_BEACON_US: [AtomicU32; RAW_NAN_TIMING_HISTORY_LEN] =
    [const { AtomicU32::new(0) }; RAW_NAN_TIMING_HISTORY_LEN];
static RAW_NAN_TIMING_POST_BEACON_US: [AtomicU32; RAW_NAN_TIMING_HISTORY_LEN] =
    [const { AtomicU32::new(0) }; RAW_NAN_TIMING_HISTORY_LEN];
static RAW_NAN_TIMING_FLAGS: [AtomicU32; RAW_NAN_TIMING_HISTORY_LEN] =
    [const { AtomicU32::new(0) }; RAW_NAN_TIMING_HISTORY_LEN];
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
    let mode = configured_mode(settings);
    PRODUCT_MODE.store(mode, Ordering::Relaxed);
    let result = if mode == MODE_SLEEPY {
        start_raw_nan_duty(settings, "boot", get_u32(settings, "nan.channel", 6) as u8)
    } else {
        start_infra_radios(settings, "boot")
    };
    if let Err(err) = result {
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

pub fn init_after_boot_window(
    settings: &SharedSettings,
    button_wake: bool,
    rebooted: bool,
) {
    let reason = if button_wake {
        "button_wake"
    } else {
        "boot_window_done"
    };
    let mode = configured_mode(settings);
    PRODUCT_MODE.store(mode, Ordering::Relaxed);
    let result = if mode == MODE_SLEEPY {
        start_raw_nan_duty(settings, reason, get_u32(settings, "nan.channel", 6) as u8)
    } else {
        start_infra_radios(settings, reason)
    };
    if let Err(err) = result {
        telemetry::record_log(format!(
            "event type=mode.infra_start ok=false reason={} msg={}",
            reason,
            crate::commands::protocol::escape_value(&err.to_string())
        ));
    }
    // This is the first compact framed state packet after the startup hold.
    // lmesh uses it to classify the forward without waiting for a host probe;
    // `active` is intentionally present so older lmesh versions can consume
    // it using the existing mode parser.
    telemetry::emit_console(&format!(
        "event type=boot.state rebooted={} mode={} active={} infra_active={}",
        rebooted,
        mode_name(),
        mode_name(),
        infra_active_session_enabled()
    ));
    emit_mode_state();
}

/// Host-visible state transition used by managed UART forwards.  This is an
/// event, not a command response, so lmesh can update its write policy when a
/// board enters or leaves a bounded active window without polling repeatedly.
fn emit_mode_state() {
    telemetry::emit_console(&format!(
        "event type=mode.state active={} infra_active={}",
        mode_name(),
        infra_active_session_enabled()
    ));
}

pub fn set_infra(settings: &SharedSettings, save: bool, reason: &'static str) -> Result<()> {
    // Infrastructure mode is a persistent powered role.  Reissuing the mode
    // command from the managed UART must not tear down and recreate the AP/
    // raw-NAN callbacks while the command task is servicing that same UART;
    // doing so can deadlock the Wi-Fi driver and leave the gateway silent.
    if PRODUCT_MODE.load(Ordering::Relaxed) == MODE_INFRA {
        super::serial::set_always_on(true);
        if save {
            settings.borrow_mut().set_str("mode", "infra")?;
        }
        telemetry::record_log(format!(
            "event type=mode active=infra reason={} already_running={} ap_owner_running={}",
            reason,
            true,
            AP_OWNER_RUNNING.load(Ordering::Relaxed)
        ));
        emit_mode_state();
        return Ok(());
    }
    PRODUCT_MODE.store(MODE_INFRA, Ordering::Relaxed);
    COMPANION_ADVERTISING.store(false, Ordering::Relaxed);
    COMPANION_PENDING_ADVERTISING.store(false, Ordering::Relaxed);
    COMPANION_DEADLINE_MS.store(0, Ordering::Relaxed);
    if save {
        settings.borrow_mut().set_str("mode", "infra")?;
    }
    start_infra_radios(settings, reason)?;
    telemetry::record_log(format!("event type=mode active=infra reason={}", reason));
    emit_mode_state();
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
    emit_mode_state();
}

pub fn poll(settings: &SharedSettings) {
    // NAN remains a control-plane service even when the IP transport owns the
    // main poll path. Infrastructure ESPs must keep advertising in that case.
    if infra_mode() {
        super::nan::ensure_infra_publish(settings);
    }
    if IP_TRANSPORT_ACTIVE.load(Ordering::Acquire) {
        return;
    }
    poll_infra_active_session();
    poll_targeted_wake_session_end();
    // Infrastructure mode is continuously powered even while AP ownership is
    // being (re)established. Never let the generic housekeeping path turn
    // this node into a battery heartbeat/light-sleep participant.
    if PRODUCT_MODE.load(Ordering::Relaxed) == MODE_INFRA {
        super::serial::set_always_on(true);
    }
    // Raw AP/APSTA infrastructure profiles may not use the normal AP-owner
    // state machine, but they still need the periodic NAN advertisement.
    if infra_mode() {
        super::nan::ensure_infra_publish(settings);
    }
    if AP_OWNER_RUNNING.load(Ordering::Relaxed) {
        poll_ap_owner(settings);
        // Keep an infrastructure ESP discoverable without requiring a
        // one-shot UART `nan publish` command. The helper sends immediately
        // and retains the frame for the next synchronized DW retransmission.
        super::nan::ensure_infra_publish(settings);
        // The powered AP owner does not run the sleepy raw-NAN duty loop, but
        // it still observes the same Android NAN beacons. Release one queued
        // raw NAN publish in the common post-beacon dwell guard so its ESP
        // advertisements are not stranded behind the duty-only scheduler.
        let _ = super::nan::drain_publish_on_discovery_window();
        // The raw command queue uses the same selected-DW gate as service
        // publishes. Poll it continuously while infra is awake so a command
        // queued between beacons is released at the next DW, never free-run
        // transmitted merely because the gateway has power.
        let _ = super::nan::drain_raw_queue();
    } else if PRODUCT_MODE.load(Ordering::Relaxed) == MODE_SLEEPY {
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

/// Request a bounded active session after a LoRa packet wakes the receiver.
/// This only updates atomics; the normal mode poll performs any Wi-Fi/NAN
/// transition, so the module callback never blocks on radio setup.
pub fn request_lora_packet_active(window_ms: u32) {
    if is_companion_mode() || INFRA_ACTIVE_PERSISTENT.load(Ordering::Relaxed) {
        return;
    }
    let deadline = now_ms().wrapping_add(window_ms.clamp(1_000, 300_000));
    let previous = INFRA_ACTIVE_DEADLINE_MS.load(Ordering::Acquire);
    if previous == 0 || deadline_is_due(previous, deadline) {
        INFRA_ACTIVE_DEADLINE_MS.store(deadline, Ordering::Release);
    }
    INFRA_ACTIVE_UART_EXTENDS.fetch_add(1, Ordering::Relaxed);
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
        emit_mode_state();
    }
}

fn infra_radio_hold_active() -> bool {
    infra_active_session_enabled()
        || targeted_wake_active()
        || super::serial::is_active()
        // A queued response is retried from the next bounded recovery/DW
        // window. It must not keep an unsynchronised sleepy node awake
        // indefinitely (lora4's old pending-response deadlock).
        || (PRODUCT_MODE.load(Ordering::Relaxed) != MODE_SLEEPY
            && super::nan::raw_work_pending())
}

/// An explicit "I want to talk" window permits immediate raw command/response
/// traffic after the wake handshake. Sleepy nodes still use DW gating when no
/// bounded active session is in force.
pub fn raw_nan_interactive_active() -> bool {
    // The infrastructure gateway receives its queue over a local UART, but
    // that UART activity is not permission to transmit over NAN immediately.
    // lora1 must remain DW-gated; otherwise the frame is emitted hundreds of
    // milliseconds after the beacon and a sleepy peer has already powered its
    // radio down.  Only non-infrastructure targets may use the bounded active
    // session/console exemption.
    if ap_owner_running() {
        return false;
    }
    // Infrastructure nodes keep the radio and UART awake continuously, but
    // that does not make every queued packet an arbitrary-time transmission.
    // A target-specific wake request or an explicit bounded `mode active`
    // session does, however: the receiver has acknowledged the DW control
    // frame and is now in the post-DW burst interval for CoC/ESP-NOW-style
    // traffic. A serial/interactive console remains the local fallback.
    targeted_wake_active() || infra_active_session_enabled() || super::serial::interactive_active()
}

fn targeted_wake_active() -> bool {
    let deadline = RAW_NAN_TARGET_WAKE_UNTIL_MS.load(Ordering::Acquire);
    deadline != 0 && !deadline_is_due(deadline, now_ms())
}

/// Notify the gateway immediately before a serverless wake lease expires.
/// The notification is best effort; lmesh also expires the lease locally.
fn poll_targeted_wake_session_end() {
    let deadline = RAW_NAN_TARGET_WAKE_UNTIL_MS.load(Ordering::Acquire);
    if deadline == 0
        || deadline_is_due(deadline, now_ms())
        || RAW_NAN_TARGET_WAKE_SESSION_END_SENT.load(Ordering::Acquire)
        || deadline.wrapping_sub(now_ms()) > 250
    {
        return;
    }
    RAW_NAN_TARGET_WAKE_SESSION_END_SENT.store(true, Ordering::Release);
    let mut notice = crate::commands::CommandRequest::new_binary(33);
    notice.args.insert(
        crate::commands::protocol::CBOR_STATUS,
        "session_end".to_string(),
    );
    let payload = crate::commands::protocol::encode_binary(&notice);
    if let Err(error) = super::wifi::send_to_last_command_peer(&payload) {
        telemetry::record_log(format!(
            "event type=session.end notify=false msg={}",
            crate::commands::protocol::escape_value(&error.to_string())
        ));
    } else {
        telemetry::record_log("event type=session.end notify=true");
    }
}

/// Keep raw Wi-Fi active after a matching NAN service advertisement.
pub fn request_targeted_wake(duration_ms: u32) {
    let deadline = now_ms().wrapping_add(duration_ms.clamp(1_000, 300_000));
    let current = RAW_NAN_TARGET_WAKE_UNTIL_MS.load(Ordering::Acquire);
    if current == 0 || deadline_is_due(current, deadline) {
        RAW_NAN_TARGET_WAKE_UNTIL_MS.store(deadline, Ordering::Release);
    }
    RAW_NAN_TARGET_WAKE_SESSION_END_SENT.store(false, Ordering::Release);
    telemetry::record_log(format!(
        "event type=nan.target_wake requested_ms={} deadline_ms={}",
        duration_ms, deadline
    ));
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
    emit_mode_state();
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
        emit_mode_state();
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
    // Keep CPU power management off during the initial Android GATT
    // validation.  Companion sleep is a separate follow-up once the ATT path
    // has been proven under an always-awake controller and host.
    // Keep the classic ESP32 controller awake while validating the GATT
    // transport.  The low-power companion policy is separate and must not
    // mask ATT/GATT failures during bring-up.
    if let Err(err) = super::ble_bt::disable_controller_sleep() {
        telemetry::record_log(format!(
            "event type=mode.companion_ble_sleep enabled=false ok=false msg={}",
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
        // `mode=infra` is the powered/infrastructure role. It must remain
        // reachable continuously; battery-node raw-NAN duty cycling is an
        // explicit non-infrastructure path. `nan.sync_source=ap_only` can
        // still force the timing-source AP immediately.
        start_ap_owner(settings, reason, channel)?;
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
    super::serial::set_always_on(true);
    AP_OWNER_STARTED_MS.store(now_ms(), Ordering::Relaxed);
    AP_OWNER_AP_ACTIVE.store(false, Ordering::Relaxed);
    // Infra/AP owners remain awake, but the preferred common clock is still
    // the shared NAN cluster.  Only an explicit AP-only policy starts with
    // no NAN source; Auto/NAN modes must be able to receive and DW-gate
    // follow-ups immediately after observing the cluster.
    let initial_source = match sync_policy(settings) {
        SyncPolicy::ApOnly => SYNC_SOURCE_NONE,
        _ => SYNC_SOURCE_NAN,
    };
    RAW_NAN_SYNC_SOURCE.store(initial_source, Ordering::Relaxed);
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
    super::serial::set_always_on(false);
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
    // Infrastructure/AP owners are deliberately always reachable. Keep the
    // UART powered for the lifetime of AP ownership. There is no heartbeat
    // cadence or battery wake window in infrastructure mode; sleepy-node duty
    // scheduling does not apply while infrastructure mode is selected.
    super::serial::set_always_on(true);
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
    // Infrastructure nodes stay awake, but they still need the shared NAN
    // TSF/512-TU grid as their transmit reference.  The sleepy scheduler
    // normally arms this state before each wake; AP owners bypass that loop,
    // so refresh the base timing directly from the selected NAN beacon.
    if RAW_NAN_EXPECT_PERIOD_US.load(Ordering::Relaxed) == 0 {
        let snapshot = super::nan::nan_beacon_snapshot();
        if let Some(plan) = super::wifi::beacon_wake_plan_for_dw_stride(snapshot, 0, 512, 0, 1, 0) {
            arm_raw_nan_beacon_window(Some(plan));
        }
    }
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
    let active_ms = get_u32(settings, "nan.active_ms", DEFAULT_NAN_ACTIVE_MS).clamp(32, 60_000);
    let duty_ms = get_u32(settings, "nan.wake_ms", DEFAULT_NAN_DUTY_MS)
        .max(active_ms)
        .clamp(100, 60_000);
    let light_sleep = get_bool(settings, "nan.light_sleep", true);
    // The default is conservative, but an explicit margin experiment may be
    // selected with `mode nan_early_ms=<n> save=true`. Clamp persisted values
    // so a stale or malformed profile cannot disable the startup guard.
    let configured_wake_early_ms = get_u32(settings, "nan.early_ms", DEFAULT_NAN_WAKE_EARLY_MS)
        .clamp(
            NAN_WAKE_MARGIN_MIN_MS,
            duty_ms
                .saturating_sub(active_ms)
                .max(NAN_WAKE_MARGIN_MIN_MS)
                .min(NAN_WAKE_MARGIN_MAX_MS),
        );
    RAW_NAN_WAKE_EARLY_MS.store(configured_wake_early_ms, Ordering::Relaxed);
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
        configured_wake_early_ms,
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
        let active_ms = get_u32(settings, "nan.active_ms", DEFAULT_NAN_ACTIVE_MS).clamp(32, 60_000);
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
    RAW_NAN_TARGET_WAKE_UNTIL_MS.store(0, Ordering::Release);
}

/// Hand the Wi-Fi driver to an IP data-plane user such as the recovery/TCP
/// flasher.  The normal firmware scheduler is allowed to stop raw Wi-Fi and
/// enter light sleep; that is correct for NAN but would make an established
/// TCP listener intermittently unreachable.  This is runtime-only state and
/// is intentionally not persisted in NVS.
pub fn stop_for_ip_transport() {
    IP_TRANSPORT_ACTIVE.store(true, Ordering::Release);
    // Main remains the control-plane owner while the STA/TCP worker is
    // active. Keep its managed UART available for status, handoff errors,
    // and an emergency firmware reset for the entire transfer; the normal
    // bounded UART window must not expire halfway through a flash session.
    super::serial::set_always_on(true);
    // Keep the tcpip task scheduled while the update data plane is active;
    // raw-NAN normally enables automatic light sleep between discovery
    // windows, which is not compatible with starting a BSD listener.
    super::power::configure_for_light_sleep(false).ok();
    // This must happen even when the STA is already configured.  Keeping the
    // association avoids a needless reconnect, but leaving the NAN duty
    // scheduler armed lets the board enter a sleepy window while the TCP
    // module is opening its socket.
    stop_raw_nan_duty();
    // A preceding `wifi ... ip=...` command may already have established the
    // STA for a module-owned TCP session. In that case the NAN teardown below
    // would stop the same Wi-Fi driver and make the module's connect() time
    // out. Only tear down the radio owner when IP STA is not already ready.
    if !super::wifi::ip_sta_ready() {
        stop_ap_owner().ok();
        super::nan::stop_nan().ok();
        super::wifi::stop_raw_monitor().ok();
    }
    telemetry::record_log("event type=mode.ip_transport scheduler=stopped");
}

pub fn ip_transport_active() -> bool {
    IP_TRANSPORT_ACTIVE.load(Ordering::Acquire)
}

/// Return Main to its normal raw-NAN duty cycle after a control-plane TCP
/// session, including failed sessions. This state is runtime-only and is not
/// persisted in NVS.
pub fn resume_from_ip_transport(settings: &SharedSettings) -> Result<()> {
    if !IP_TRANSPORT_ACTIVE.swap(false, Ordering::AcqRel) {
        return Ok(());
    }
    super::ip_command::stop();
    super::wifi::stop_flash_sta();
    super::serial::set_always_on(false);
    super::power::configure_for_light_sleep(true).ok();
    let channel = get_u32(settings, "nan.channel", 6).clamp(1, 13) as u8;
    start_raw_nan_duty(settings, "flash_complete", channel)
}

pub fn raw_nan_duty_enabled() -> bool {
    RAW_NAN_DUTY_ENABLED.load(Ordering::Relaxed)
}

/// True while the raw-NAN receiver is in its bounded awake window. The main
/// loop uses this to poll housekeeping more frequently only while the radio is
/// already awake; the long timeout remains in force during light sleep.
pub fn raw_nan_duty_active() -> bool {
    RAW_NAN_DUTY_ACTIVE.load(Ordering::Relaxed)
}

/// Whether this node is the continuously powered infrastructure gateway.
/// Infrastructure still schedules addressed traffic to sleepy peers in the
/// observed discovery window; it does not use the battery-node duty state.
pub fn ap_owner_running() -> bool {
    AP_OWNER_RUNNING.load(Ordering::Relaxed)
}

/// Infrastructure nodes have a continuously powered radio and may emit
/// discovery/publication frames outside a sleepy peer's selected DW.  Sleepy
/// nodes must continue to use the synchronized DW scheduler.
pub fn infra_mode() -> bool {
    PRODUCT_MODE.load(Ordering::Relaxed) == MODE_INFRA
}

/// Infrastructure-to-sleepy traffic uses the default advertised stride even
/// though the infrastructure radio itself never sleeps. This keeps addressed
/// follow-ups on DW0/DW8 instead of transmitting on every nearby beacon.
pub fn infra_target_dw_open(tsf_us: u64) -> bool {
    let base_period_us = u64::from(RAW_NAN_EXPECT_PERIOD_US.load(Ordering::Relaxed));
    if base_period_us == 0 {
        return false;
    }
    let stride = u64::from(RAW_NAN_DATA_DW_STRIDE.load(Ordering::Relaxed).max(1));
    (tsf_us / base_period_us) % stride == 0
}

/// Whether a just-observed NAN beacon is in this node's advertised publish
/// cadence.
///
/// The raw-NAN duty scheduler chooses DW0, DW0 + stride, ... from the same
/// TSF/512-TU timeline.  SDF transmission must use that selection too: sending
/// after every nearby cluster beacon while advertising a sparse `dw_stride`
/// makes the
/// Availability Attribute untrue on air.  The AP owner is intentionally the
/// exception because its descriptor advertises every DW and it is powered
/// continuously.
pub fn raw_nan_publish_dw_slot(tsf_us: u64) -> Option<u32> {
    if AP_OWNER_RUNNING.load(Ordering::Relaxed) {
        // The AP owner publishes every DW. Its slot is still returned so the
        // caller can keep one SDF per observed discovery window.
        let period_us = u64::from(RAW_NAN_EXPECT_PERIOD_US.load(Ordering::Relaxed));
        return (period_us != 0).then(|| (tsf_us / period_us).min(u64::from(u32::MAX)) as u32);
    }
    if !RAW_NAN_DUTY_ENABLED.load(Ordering::Relaxed)
        || RAW_NAN_SYNC_SOURCE.load(Ordering::Relaxed) != SYNC_SOURCE_NAN
    {
        return None;
    }
    let base_period_us = u64::from(RAW_NAN_EXPECT_PERIOD_US.load(Ordering::Relaxed));
    if base_period_us == 0 {
        return None;
    }
    let stride = u64::from(RAW_NAN_DATA_DW_STRIDE.load(Ordering::Relaxed).max(1));
    let slot = tsf_us / base_period_us;
    (slot % stride == 0).then(|| slot.min(u64::from(u32::MAX)) as u32)
}

/// Smallest local interval between two queued service descriptors.  Beacon
/// TSF is the primary DW authority, but a raw receiver can observe two
/// transmitters that claim the same cluster BSSID with incompatible TSFs.  A
/// local guard prevents the second claim from releasing another descriptor in
/// the same physical radio window while retaining enough jitter for observed
/// ESP/Android DW scheduling.
pub fn raw_nan_publish_min_spacing_us() -> u64 {
    let base_period_us = u64::from(RAW_NAN_EXPECT_PERIOD_US.load(Ordering::Relaxed));
    if base_period_us == 0 {
        return 0;
    }
    let stride = if AP_OWNER_RUNNING.load(Ordering::Relaxed) {
        1
    } else {
        u64::from(RAW_NAN_DATA_DW_STRIDE.load(Ordering::Relaxed).max(1))
    };
    // Permit up to one quarter of a selected interval for real beacon jitter;
    // this still makes a second SDF milliseconds later impossible.
    base_period_us.saturating_mul(stride).saturating_mul(3) / 4
}

/// Open the data plane only for the selected DW0/DW-stride rendezvous slot
/// (DW0/DW8 in the default 512-TU, four-second profile).
///
/// `tsf_us` is sampled from the NAN beacon that arrived on channel 6. The
/// scheduler selected this radio-on interval; the observed cluster beacon,
/// rather than an arbitrary global TSF phase of zero, is the DW authority.
pub fn open_raw_nan_data_dw(tsf_us: u64, local_us: u64) -> bool {
    if !RAW_NAN_DUTY_ENABLED.load(Ordering::Relaxed)
        || !RAW_NAN_DUTY_ACTIVE.load(Ordering::Relaxed)
        || RAW_NAN_SYNC_SOURCE.load(Ordering::Relaxed) != SYNC_SOURCE_NAN
    {
        return false;
    }
    let base_period_us = u64::from(RAW_NAN_EXPECT_PERIOD_US.load(Ordering::Relaxed));
    let stride = u64::from(RAW_NAN_DATA_DW_STRIDE.load(Ordering::Relaxed).max(1));
    let period_us = base_period_us.saturating_mul(stride);
    if period_us == 0 {
        return false;
    }
    let deadline = local_us.saturating_add(RAW_NAN_DATA_DW_DWELL_US);
    RAW_NAN_DATA_DW_PERIOD_US.store(period_us.min(u64::from(u32::MAX)) as u32, Ordering::Relaxed);
    RAW_NAN_DATA_DW_DEADLINE_LO.store(deadline as u32, Ordering::Relaxed);
    RAW_NAN_DATA_DW_DEADLINE_HI.store((deadline >> 32) as u32, Ordering::Relaxed);
    telemetry::record_log(format!(
        "event type=nan.data_dw open=true tsf_us={} phase_us={} period_us={} stride={} dwell_us={}",
        tsf_us,
        tsf_us % base_period_us.max(1),
        period_us,
        stride,
        RAW_NAN_DATA_DW_DWELL_US
    ));
    true
}

/// Whether a queued NAN data-plane packet may be transmitted right now.
pub fn raw_nan_data_dw_open() -> bool {
    if AP_OWNER_RUNNING.load(Ordering::Relaxed) {
        let Some(beacon) = super::nan::last_nan_sync_beacon() else {
            return false;
        };
        let period_us = u64::from(RAW_NAN_EXPECT_PERIOD_US.load(Ordering::Relaxed));
        let stride = u64::from(RAW_NAN_DATA_DW_STRIDE.load(Ordering::Relaxed).max(1));
        if period_us == 0 || (beacon.tsf_us / period_us) % stride != 0 {
            return false;
        }
        // Infra nodes receive continuously, but the shared NAN action/SDF
        // contract permits transmission only in the short post-beacon DW
        // dwell. Sending later in the 512-TU interval is unreliable for
        // sleepy peers, which have already powered the radio back down.
        return now_us().saturating_sub(beacon.local_us) <= RAW_NAN_DATA_DW_DWELL_US;
    }
    if !RAW_NAN_DUTY_ENABLED.load(Ordering::Relaxed) {
        return true;
    }
    let deadline = (u64::from(RAW_NAN_DATA_DW_DEADLINE_HI.load(Ordering::Relaxed)) << 32)
        | u64::from(RAW_NAN_DATA_DW_DEADLINE_LO.load(Ordering::Relaxed));
    deadline != 0 && now_us() <= deadline
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
    min_delay_ms: u32,
    wake_early_ms: u32,
    nan_dw_tu: u32,
    nan_dw_offset_tu: u32,
) -> Option<(u8, super::wifi::BeaconWakePlan)> {
    let (source, beacon) = selected_sync_beacon(settings)?;
    // Both NAN and the local timing AP provide a beacon TSF. The AP interval
    // is restricted by ESP-IDF to multiples of 100 TU (normally 500), so its
    // fallback DW0 is `TSF / ap_beacon_interval % stride == 0`. This is a
    // modulo of the AP's own beacon cadence, not an accidental test of the
    // trailing digits of TSF and not a projection onto NAN's 512-TU grid.
    // Once a fresh NAN beacon exists, `selected_sync_beacon` chooses NAN
    // above and restores its configured 512-TU DW timeline. The received
    // beacon's transmission phase is not reused: a beacon can arrive anywhere
    // in a discovery window, while DW0/DW8 are defined by the TSF period.
    let (period_tu, offset_tu) = if source == SYNC_SOURCE_NAN {
        (nan_dw_tu, nan_dw_offset_tu)
    } else {
        (beacon.interval_tu.max(1), 0)
    };
    let snapshot = super::wifi::BeaconSnapshot {
        count: 0,
        local_us: beacon.local_us,
        tsf_us: beacon.tsf_us,
    };
    let configured_stride = get_u32(settings, "nan.dw_stride", 8).clamp(1, 64);
    // The configured stride is the device's selected power contract. A
    // pending frame must wait for that rendezvous; silently changing to every
    // 512-TU DW defeats sleep. The raw SDF Availability attribute is encoded
    // separately and must not be inferred from this scheduler setting.
    RAW_NAN_DATA_DW_STRIDE.store(configured_stride, Ordering::Relaxed);
    super::wifi::beacon_wake_plan_for_dw_stride(
        snapshot,
        min_delay_ms,
        period_tu,
        offset_tu,
        configured_stride,
        wake_early_ms,
    )
    .map(|plan| (source, plan))
}

fn deadline_due(now: u32, deadline: u32) -> bool {
    deadline == 0 || now.wrapping_sub(deadline) < u32::MAX / 2
}

fn deadline_not_due(now: u32, deadline: u32) -> bool {
    deadline != 0 && now.wrapping_sub(deadline) >= u32::MAX / 2
}

/// Return the selected sparse-slot beacon received after `baseline`.
///
/// Prefer the bounded NAN beacon history over the latest snapshot. A raw-NAN
/// window can contain several beacons; using only the last one can hide a
/// valid DW0/DW8 beacon behind a later frame and incorrectly increase the
/// wake margin.
fn raw_nan_expected_beacon(
    snapshot: super::wifi::BeaconSnapshot,
    baseline: u32,
) -> Option<super::wifi::BeaconSnapshot> {
    let expected_tsf_us = (u64::from(RAW_NAN_EXPECT_TSF_HI.load(Ordering::Relaxed)) << 32)
        | u64::from(RAW_NAN_EXPECT_TSF_LO.load(Ordering::Relaxed));
    let period_us = u64::from(RAW_NAN_EXPECT_PERIOD_US.load(Ordering::Relaxed));
    if expected_tsf_us == 0 || period_us == 0 {
        return None;
    }
    if let Some(matched) = super::nan::nan_beacon_matching_since(
        baseline,
        expected_tsf_us,
        period_us,
        RAW_NAN_BEACON_LATE_TOLERANCE_US,
    ) {
        return Some(matched);
    }
    if snapshot.count <= baseline || snapshot.tsf_us == 0 {
        return None;
    }
    let phase_delta_us = (snapshot.tsf_us % period_us).abs_diff(expected_tsf_us % period_us);
    (snapshot.tsf_us / period_us == expected_tsf_us / period_us
        && phase_delta_us <= RAW_NAN_BEACON_LATE_TOLERANCE_US)
        .then_some(snapshot)
}

/// If the receiver first reports the immediately preceding sparse DW, keep
/// Wi-Fi on until the selected target can actually arrive. This is a bounded
/// recovery for TSF/local-clock skew: it lets the next pass measure the real
/// radio-on interval instead of stopping after the stale beacon and learning
/// nothing useful from every cycle.
fn pending_expected_remaining_ms(
    snapshot: super::wifi::BeaconSnapshot,
    baseline: u32,
) -> Option<u32> {
    if snapshot.count <= baseline || snapshot.tsf_us == 0 {
        return None;
    }
    let expected_tsf_us = (u64::from(RAW_NAN_EXPECT_TSF_HI.load(Ordering::Relaxed)) << 32)
        | u64::from(RAW_NAN_EXPECT_TSF_LO.load(Ordering::Relaxed));
    let period_us = u64::from(RAW_NAN_EXPECT_PERIOD_US.load(Ordering::Relaxed));
    if expected_tsf_us == 0 || period_us == 0 || snapshot.tsf_us >= expected_tsf_us {
        return None;
    }
    if snapshot.tsf_us / period_us >= expected_tsf_us / period_us {
        return None;
    }
    let elapsed_us = now_us().saturating_sub(snapshot.local_us);
    // If the target passed while the radio was down, this is no longer a
    // pending expected slot. Returning `None` lets the normal window finish
    // and recompute the next stride instead of reopening the same stale slot
    // once per second.
    if expected_tsf_us <= snapshot.tsf_us.saturating_add(elapsed_us) {
        return None;
    }
    let remaining_us = expected_tsf_us
        .saturating_sub(snapshot.tsf_us)
        .saturating_sub(elapsed_us);
    let extension_ms = remaining_us
        .div_ceil(1_000)
        .saturating_add(u64::from(RAW_NAN_DATA_DW_DWELL_MS))
        .saturating_add(2)
        .min(u64::from(u32::MAX)) as u32;
    Some(extension_ms)
}

fn poll_raw_nan_duty(settings: &SharedSettings) {
    // Keep the response queue bounded even while the cluster is unavailable;
    // stale entries must not survive until an unrelated future command.
    super::nan::expire_raw_queue();
    if !RAW_NAN_DUTY_ENABLED.load(Ordering::Relaxed) {
        return;
    }
    // Check every normal duty poll. The publish helper itself requires both an
    // active raw NAN radio and a fresh observed cluster beacon.
    let _ = super::nan::drain_publish_on_discovery_window();
    let now = now_ms();
    let mut deadline = RAW_NAN_DUTY_NEXT_MS.load(Ordering::Relaxed);
    let post_beacon_due = if RAW_NAN_DUTY_ACTIVE.load(Ordering::Relaxed)
        && !infra_radio_hold_active()
        && RAW_NAN_SYNC_SOURCE.load(Ordering::Relaxed) == SYNC_SOURCE_NAN
    {
        let snapshot = super::nan::nan_beacon_snapshot();
        let baseline = RAW_NAN_BEACON_BASELINE.load(Ordering::Relaxed);
        raw_nan_expected_beacon(snapshot, baseline)
            .map(|beacon| now_us().saturating_sub(beacon.local_us) >= RAW_NAN_DATA_DW_DWELL_US)
            .unwrap_or(false)
    } else {
        false
    };
    if RAW_NAN_DUTY_ACTIVE.load(Ordering::Relaxed)
        && !post_beacon_due
        && RAW_NAN_SYNC_SOURCE.load(Ordering::Relaxed) == SYNC_SOURCE_NAN
    {
        let snapshot = super::nan::nan_beacon_snapshot();
        let baseline = RAW_NAN_BEACON_BASELINE.load(Ordering::Relaxed);
        if let Some(remaining_ms) = pending_expected_remaining_ms(snapshot, baseline) {
            // A beacon from the immediately preceding sparse slot proves the
            // receiver is synchronized, but it is not the target slot. Keep
            // this already-open radio window alive only until the target plus
            // the minimum data dwell. Stopping here and restarting through
            // the inactive path loses the pending plan and can classify the
            // same stale slot as a multi-DW drift.
            // The scheduler polls while the radio is open. Count and log the
            // reschedule once, when the current deadline is first observed;
            // otherwise a single preceding beacon inflates the counter by
            // hundreds of poll iterations and floods the bounded log ring.
            let first_reschedule = deadline_due(now, deadline);
            if first_reschedule {
                RAW_NAN_EXPECT_EXTENDS.fetch_add(1, Ordering::Relaxed);
            }
            let expected_tsf_us = (u64::from(RAW_NAN_EXPECT_TSF_HI.load(Ordering::Relaxed)) << 32)
                | u64::from(RAW_NAN_EXPECT_TSF_LO.load(Ordering::Relaxed));
            if first_reschedule {
                telemetry::record_log(format!(
                    "event type=nan.duty stale_beacon_reschedule=true remaining_ms={} expected_tsf_us={} actual_tsf_us={}",
                    remaining_ms, expected_tsf_us, snapshot.tsf_us
                ));
            }
            RAW_NAN_DUTY_NEXT_MS.store(now.wrapping_add(remaining_ms), Ordering::Relaxed);
            return;
        }
        deadline = RAW_NAN_DUTY_NEXT_MS.load(Ordering::Relaxed);
    }
    // If the selected DW produced no accepted beacon at all, keep the already
    // running receiver through the immediately following 512-TU slot. A
    // beacon there proves the selected frame was lost at RX; no beacon in the
    // probe indicates TSF/local-clock drift or a source that disappeared.
    if RAW_NAN_DUTY_ACTIVE.load(Ordering::Relaxed)
        && deadline_due(now, deadline)
        && !post_beacon_due
        && RAW_NAN_SYNC_SOURCE.load(Ordering::Relaxed) == SYNC_SOURCE_NAN
        && !RAW_NAN_MISS_PROBE_ACTIVE.swap(true, Ordering::AcqRel)
    {
        let snapshot = super::nan::nan_beacon_snapshot();
        let baseline = RAW_NAN_BEACON_BASELINE.load(Ordering::Relaxed);
        if snapshot.count <= baseline {
            const NAN_MISS_PROBE_MS: u32 = 600;
            RAW_NAN_MISS_PROBES.fetch_add(1, Ordering::Relaxed);
            RAW_NAN_DUTY_NEXT_MS.store(now.wrapping_add(NAN_MISS_PROBE_MS), Ordering::Relaxed);
            telemetry::record_log(format!(
                "event type=nan.duty miss_probe=true duration_ms={} expected_tsf_us={} baseline={} current={}",
                NAN_MISS_PROBE_MS,
                (u64::from(RAW_NAN_EXPECT_TSF_HI.load(Ordering::Relaxed)) << 32)
                    | u64::from(RAW_NAN_EXPECT_TSF_LO.load(Ordering::Relaxed)),
                baseline,
                snapshot.count
            ));
            return;
        }
    }
    // `wrapping_sub(deadline) >= HALF` means the deadline is still in the
    // future. Keep servicing the active window in that case, unless the
    // expected beacon has already arrived and the short post-beacon dwell has
    // elapsed; that path must fall through to the shutdown code below.
    if deadline_not_due(now, deadline) && !post_beacon_due {
        // Raw-NAN publish frames are queued by the command task and released
        // here, in task context, only within the beacon-defined DW.
        let _ = super::nan::drain_publish_on_discovery_window();
        // The Wi-Fi callback only opens the short DW permit.  TX is performed
        // here in normal task context, avoiding driver re-entry from a
        // promiscuous callback while still staying inside the dwell.
        if RAW_NAN_DUTY_ACTIVE.load(Ordering::Relaxed) && raw_nan_data_dw_open() {
            let queued_sent = super::nan::drain_raw_queue();
            if queued_sent > 0 {
                telemetry::record_log(format!(
                    "event type=nan.data_dw queue_tx={} context=mode_poll",
                    queued_sent
                ));
            }
        }
        return;
    }
    let channel = get_u32(settings, "nan.channel", 6).clamp(1, 13) as u8;
    let active_ms = get_u32(settings, "nan.active_ms", DEFAULT_NAN_ACTIVE_MS).clamp(32, 60_000);
    let duty_ms = get_u32(settings, "nan.wake_ms", DEFAULT_NAN_DUTY_MS)
        .max(active_ms)
        .clamp(100, 60_000);
    let light_sleep = get_bool(settings, "nan.light_sleep", true);
    let wake_early_ms = RAW_NAN_WAKE_EARLY_MS.load(Ordering::Relaxed).clamp(
        NAN_WAKE_MARGIN_MIN_MS,
        duty_ms
            .saturating_sub(active_ms)
            .max(NAN_WAKE_MARGIN_MIN_MS)
            .min(NAN_WAKE_MARGIN_MAX_MS),
    );
    let dw_tu = get_u32(settings, "nan.dw_tu", DEFAULT_NAN_DW_TU).clamp(1, 65_535);
    let dw_offset_tu = get_u32(settings, "nan.dw_off_tu", DEFAULT_NAN_DW_OFFSET_TU);
    let hold_active = infra_radio_hold_active();
    let source_before_window = selected_sync_beacon(settings).map(|(source, _)| source);
    let recovery_due = source_before_window.is_none()
        && sync_policy(settings) != SyncPolicy::NanOnly
        && deadline_due(now, RAW_NAN_RECOVERY_NEXT_MS.load(Ordering::Relaxed));
    let requested_active_ms = if recovery_due {
        get_u32(
            settings,
            "nan.ap_recovery_listen_ms",
            DEFAULT_AP_RECOVERY_LISTEN_MS,
        )
        .max(active_ms)
    } else {
        active_ms
    };
    // Keep Wi-Fi through the expected beacon and the minimum NAN data dwell.
    // `wake_early_ms` is measured from the expected beacon, not from the
    // beginning of this active window, so it must be part of the deadline.
    let window_active_ms = requested_active_ms
        .max(
            wake_early_ms
                .saturating_add(RAW_NAN_DATA_DW_DWELL_MS)
                .saturating_add(2),
        )
        .max(RAW_NAN_BEACON_LISTEN_FLOOR_MS);

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
        // A UART/radio wake deliberately owns a short debug window.
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
            let queued_sent = super::nan::drain_raw_queue();
            // SDFs (including UART/BLE wake advertisements) use the separate
            // publish queue. Infrastructure nodes do not pass through the
            // sleepy DW loop, so drain that queue here as well; the helper
            // still requires a fresh beacon and the configured DW slot.
            let publish_sent = super::nan::drain_publish_on_discovery_window();
            if queued_sent > 0 || publish_sent > 0 {
                telemetry::record_log(format!(
                    "event type=nan.infra_queue_tx raw={} publish={}",
                    queued_sent, publish_sent
                ));
            }
            RAW_NAN_DUTY_NEXT_MS.store(now.wrapping_add(active_ms), Ordering::Relaxed);
            return;
        }
        // Once the selected NAN beacon has arrived, retain the radio only for
        // the bounded data-plane dwell. The full active_ms remains the miss
        // timeout, so a late/missing beacon still gets a recovery window.
        if RAW_NAN_SYNC_SOURCE.load(Ordering::Relaxed) == SYNC_SOURCE_NAN {
            let snapshot = super::nan::nan_beacon_snapshot();
            let baseline = RAW_NAN_BEACON_BASELINE.load(Ordering::Relaxed);
            if let Some(beacon) = raw_nan_expected_beacon(snapshot, baseline) {
                let since_beacon_us = now_us().saturating_sub(beacon.local_us);
                if since_beacon_us >= RAW_NAN_DATA_DW_DWELL_US {
                    telemetry::record_log(format!(
                        "event type=nan.duty phase=post_beacon_stop since_beacon_us={} dwell_us={}",
                        since_beacon_us, RAW_NAN_DATA_DW_DWELL_US
                    ));
                    RAW_NAN_DUTY_NEXT_MS.store(now, Ordering::Relaxed);
                }
            }
        }
        let recovery_window = RAW_NAN_RECOVERY_ACTIVE.swap(false, Ordering::AcqRel);
        // Notify the managed UART forward before handing the radio and CPU
        // back to the duty-cycle sleep path.  This is deliberately a state
        // notification, not a response to a command; lmesh uses it to mark
        // the device unreachable while retaining queued commands.
        telemetry::emit_console(&format!(
            "event type=mode.state active={} infra_active=false phase=enter_sleep",
            mode_name()
        ));
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
        // A fresh NAN TSF selects the next DW0/DW-stride cadence slot. The
        // four-second duty interval is only the fallback when no beacon is
        // available; it must not create a free-running synchronized schedule.
        let selected_plan =
            sync_wake_plan(settings, wake_early_ms, wake_early_ms, dw_tu, dw_offset_tu);
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
            // Start timing before Wi-Fi/monitor bring-up. This measures the
            // real radio-on-to-beacon interval, not just the time after the
            // promiscuous callback has already been installed.
            let radio_on_start_us = now_us();
            match super::nan::start_raw_window(channel, sync_window_filter(settings, recovery_due))
            {
                Ok(()) => {
                    let queued_sent = super::nan::drain_raw_queue();
                    record_raw_nan_dw_start(dw_offset_tu, sync_plan.is_some(), true);
                    set_raw_nan_window_start_us(radio_on_start_us);
                    let uart_heartbeat = if sync_plan.is_none() && source_before_window.is_none() {
                        super::serial::on_uart_recovery_wake(active_ms)
                    } else {
                        super::serial::on_raw_nan_wake(active_ms)
                    };
                    RAW_NAN_DUTY_ACTIVE.store(true, Ordering::Relaxed);
                    RAW_NAN_MISS_PROBE_ACTIVE.store(false, Ordering::Release);
                    RAW_NAN_RECOVERY_ACTIVE.store(recovery_due, Ordering::Relaxed);
                    if recovery_due {
                        RAW_NAN_RECOVERY_RUNS.fetch_add(1, Ordering::Relaxed);
                    }
                    RAW_NAN_DUTY_NEXT_MS
                        .store(now_ms().wrapping_add(window_active_ms), Ordering::Relaxed);
                    telemetry::record_log(format!(
                        "event type=nan.duty phase=active channel={} active_ms={} listen_floor_ms={} wake=light recovery={} queued_sent={} uart_heartbeat={}",
                        channel,
                        window_active_ms,
                        RAW_NAN_BEACON_LISTEN_FLOOR_MS,
                        recovery_due,
                        queued_sent,
                        uart_heartbeat
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
    let radio_on_start_us = now_us();
    match super::nan::start_raw_window(channel, sync_window_filter(settings, recovery_due)) {
        Ok(()) => {
            let queued_sent = super::nan::drain_raw_queue();
            // The non-light-sleep diagnostic path does not retain its prior
            // wake plan across polls, so only mark it synchronized when the
            // active window itself was entered from the light-sleep path.
            record_raw_nan_dw_start(dw_offset_tu, false, false);
            set_raw_nan_window_start_us(radio_on_start_us);
            let uart_heartbeat = if source_before_window.is_none() {
                super::serial::on_uart_recovery_wake(active_ms)
            } else {
                super::serial::on_raw_nan_wake(active_ms)
            };
            RAW_NAN_DUTY_ACTIVE.store(true, Ordering::Relaxed);
            RAW_NAN_MISS_PROBE_ACTIVE.store(false, Ordering::Release);
            RAW_NAN_RECOVERY_ACTIVE.store(recovery_due, Ordering::Relaxed);
            if recovery_due {
                RAW_NAN_RECOVERY_RUNS.fetch_add(1, Ordering::Relaxed);
            }
            RAW_NAN_DUTY_NEXT_MS.store(now.wrapping_add(window_active_ms), Ordering::Relaxed);
            telemetry::record_log(format!(
                "event type=nan.duty phase=active channel={} active_ms={} listen_floor_ms={} recovery={} queued_sent={} uart_heartbeat={}",
                channel,
                window_active_ms,
                RAW_NAN_BEACON_LISTEN_FLOOR_MS,
                recovery_due,
                queued_sent,
                uart_heartbeat
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
    let snapshot = super::nan::nan_beacon_snapshot();
    RAW_NAN_BEACON_BASELINE.store(snapshot.count, Ordering::Relaxed);
    let (expected_tsf_us, period_us) = plan
        .map(|plan| (plan.expected_tsf_us, plan.period_us))
        .unwrap_or((0, 0));
    RAW_NAN_EXPECT_TSF_LO.store(expected_tsf_us as u32, Ordering::Relaxed);
    RAW_NAN_EXPECT_TSF_HI.store((expected_tsf_us >> 32) as u32, Ordering::Relaxed);
    RAW_NAN_EXPECT_PERIOD_US.store(period_us, Ordering::Relaxed);
}

fn finish_raw_nan_beacon_window() {
    // Loss classification must not perturb the next synchronized wake. The
    // one-slot probe above is the only extra listen interval.
    const MISS_BACKOFF_MS: u32 = 0;
    let snapshot = super::nan::nan_beacon_snapshot();
    let baseline = RAW_NAN_BEACON_BASELINE.load(Ordering::Relaxed);
    let received = snapshot.count.saturating_sub(baseline);
    let window_start_us = (u64::from(RAW_NAN_WINDOW_START_US_HI.load(Ordering::Relaxed)) << 32)
        | u64::from(RAW_NAN_WINDOW_START_US_LO.load(Ordering::Relaxed));
    // Preserve this measurement even when no NAN beacon was accepted. It is
    // the key discriminator between a late/absent beacon and a radio/RX
    // startup failure.
    let first_frame_local_us = super::wifi::raw_first_frame_local_us();
    let wake_to_first_frame_us = first_frame_local_us
        .saturating_sub(window_start_us)
        .min(u64::from(u32::MAX));
    RAW_NAN_LAST_WAKE_TO_FIRST_FRAME_US.store(wake_to_first_frame_us as u32, Ordering::Relaxed);
    if received == 0 {
        let expected_tsf_us = (u64::from(RAW_NAN_EXPECT_TSF_HI.load(Ordering::Relaxed)) << 32)
            | u64::from(RAW_NAN_EXPECT_TSF_LO.load(Ordering::Relaxed));
        let now_us_value = now_us();
        RAW_NAN_LAST_MISS_EXPECT_TSF_LO.store(expected_tsf_us as u32, Ordering::Relaxed);
        RAW_NAN_LAST_MISS_EXPECT_TSF_HI.store((expected_tsf_us >> 32) as u32, Ordering::Relaxed);
        RAW_NAN_LAST_MISS_TSF_LO.store(snapshot.tsf_us as u32, Ordering::Relaxed);
        RAW_NAN_LAST_MISS_TSF_HI.store((snapshot.tsf_us >> 32) as u32, Ordering::Relaxed);
        RAW_NAN_LAST_MISS_LOCAL_LO.store(snapshot.local_us as u32, Ordering::Relaxed);
        RAW_NAN_LAST_MISS_LOCAL_HI.store((snapshot.local_us >> 32) as u32, Ordering::Relaxed);
        RAW_NAN_LAST_MISS_NOW_LO.store(now_us_value as u32, Ordering::Relaxed);
        RAW_NAN_LAST_MISS_NOW_HI.store((now_us_value >> 32) as u32, Ordering::Relaxed);
        RAW_NAN_LAST_MISS_WAKE_TO_FIRST_FRAME_US
            .store(wake_to_first_frame_us as u32, Ordering::Relaxed);
        RAW_NAN_BEACON_MISSED.fetch_add(1, Ordering::Relaxed);
        record_raw_nan_dw_finish(0, 0);
        RAW_NAN_MISS_BACKOFF_MS.store(MISS_BACKOFF_MS, Ordering::Relaxed);
        telemetry::record_log(format!(
            "event type=nan.duty beacon=missed active_ms_backoff={} wake_margin_ms={} wake_to_first_frame_us={} baseline={} current={} expected_tsf_us={} expected_period_us={} last_tsf_us={} last_local_us={} now_us={}",
            MISS_BACKOFF_MS,
            RAW_NAN_WAKE_EARLY_MS.load(Ordering::Relaxed),
            wake_to_first_frame_us,
            baseline,
            snapshot.count,
            expected_tsf_us,
            RAW_NAN_EXPECT_PERIOD_US.load(Ordering::Relaxed),
            snapshot.tsf_us,
            snapshot.local_us,
            now_us_value,
        ));
        record_raw_nan_timing(wake_to_first_frame_us, 0, 0, 0);
        return;
    }

    RAW_NAN_BEACON_SEEN.fetch_add(received, Ordering::Relaxed);
    // The latest snapshot is useful for diagnostics, but the bounded history
    // selects the actual expected DW when several beacons arrived in one
    // window. This keeps timing measurements tied to the rendezvous that
    // justified the sleep decision rather than to a later beacon.
    let expected_tsf_us = (u64::from(RAW_NAN_EXPECT_TSF_HI.load(Ordering::Relaxed)) << 32)
        | u64::from(RAW_NAN_EXPECT_TSF_LO.load(Ordering::Relaxed));
    let period_us = u64::from(RAW_NAN_EXPECT_PERIOD_US.load(Ordering::Relaxed));
    if expected_tsf_us == 0 || period_us == 0 || snapshot.tsf_us == 0 {
        return;
    }
    let matched_beacon = raw_nan_expected_beacon(snapshot, baseline);
    let timing_snapshot = matched_beacon.unwrap_or(snapshot);
    let wake_to_beacon_us = timing_snapshot.local_us.saturating_sub(window_start_us);
    let beacon_to_sleep_us = now_us().saturating_sub(timing_snapshot.local_us);
    RAW_NAN_LAST_BEACON_TSF_LO.store(snapshot.tsf_us as u32, Ordering::Relaxed);
    RAW_NAN_LAST_BEACON_TSF_HI.store((snapshot.tsf_us >> 32) as u32, Ordering::Relaxed);
    record_raw_nan_dw_finish(received, RAW_NAN_DW_FLAG_BEACON);

    // Beacon TSF values include the global base-DW index. The selected sparse
    // stride is already reflected in `expected_tsf_us`; requiring the expected
    // index prevents a stale beacon from a previous DW from looking successful
    // merely because its phase happens to match.
    let expected_phase_us = expected_tsf_us % period_us;
    let actual_phase_us = timing_snapshot.tsf_us % period_us;
    let phase_delta_us = expected_phase_us.abs_diff(actual_phase_us);
    let expected_slot_index = expected_tsf_us / period_us;
    let actual_slot_index = timing_snapshot.tsf_us / period_us;
    let expected_beacon = matched_beacon.is_some()
        || (actual_slot_index == expected_slot_index
            && phase_delta_us <= RAW_NAN_BEACON_LATE_TOLERANCE_US);
    if expected_beacon {
        RAW_NAN_LAST_WAKE_TO_BEACON_US.store(
            wake_to_beacon_us.min(u64::from(u32::MAX)) as u32,
            Ordering::Relaxed,
        );
        RAW_NAN_LAST_WAKE_TO_FIRST_FRAME_US.store(wake_to_first_frame_us as u32, Ordering::Relaxed);
        RAW_NAN_LAST_BEACON_TO_SLEEP_US.store(
            beacon_to_sleep_us.min(u64::from(u32::MAX)) as u32,
            Ordering::Relaxed,
        );
        RAW_NAN_MISS_BACKOFF_MS.store(0, Ordering::Relaxed);
        telemetry::record_log(format!(
            "event type=nan.duty beacon=expected slot_index={} wake_to_first_frame_us={} wake_to_beacon_us={} beacon_to_sleep_us={} wake_margin_ms={}",
            actual_slot_index,
            wake_to_first_frame_us,
            wake_to_beacon_us,
            beacon_to_sleep_us,
            RAW_NAN_WAKE_EARLY_MS.load(Ordering::Relaxed)
        ));
        record_raw_nan_timing(
            wake_to_first_frame_us,
            wake_to_beacon_us.min(u64::from(u32::MAX)) as u32,
            beacon_to_sleep_us.min(u64::from(u32::MAX)) as u32,
            RAW_NAN_DW_FLAG_BEACON,
        );
        return;
    }
    let now_us_value = now_us();
    RAW_NAN_LAST_MISS_EXPECT_TSF_LO.store(expected_tsf_us as u32, Ordering::Relaxed);
    RAW_NAN_LAST_MISS_EXPECT_TSF_HI.store((expected_tsf_us >> 32) as u32, Ordering::Relaxed);
    RAW_NAN_LAST_MISS_TSF_LO.store(snapshot.tsf_us as u32, Ordering::Relaxed);
    RAW_NAN_LAST_MISS_TSF_HI.store((snapshot.tsf_us >> 32) as u32, Ordering::Relaxed);
    RAW_NAN_LAST_MISS_LOCAL_LO.store(snapshot.local_us as u32, Ordering::Relaxed);
    RAW_NAN_LAST_MISS_LOCAL_HI.store((snapshot.local_us >> 32) as u32, Ordering::Relaxed);
    RAW_NAN_LAST_MISS_NOW_LO.store(now_us_value as u32, Ordering::Relaxed);
    RAW_NAN_LAST_MISS_NOW_HI.store((now_us_value >> 32) as u32, Ordering::Relaxed);
    RAW_NAN_LAST_MISS_WAKE_TO_FIRST_FRAME_US
        .store(wake_to_first_frame_us as u32, Ordering::Relaxed);
    // A beacon outside the expected slot is diagnostic only. Do not retune
    // the fixed guard based on a single lost or filtered 802.11 frame.
    RAW_NAN_MISS_BACKOFF_MS.store(MISS_BACKOFF_MS, Ordering::Relaxed);
    RAW_NAN_BEACON_LATE.fetch_add(1, Ordering::Relaxed);
    raw_nan_dw_add_flags(RAW_NAN_DW_FLAG_LATE);
    let next_dw = actual_slot_index == expected_slot_index.saturating_add(1)
        && phase_delta_us <= RAW_NAN_BEACON_LATE_TOLERANCE_US;
    RAW_NAN_BEACON_MISSED.fetch_add(1, Ordering::Relaxed);
    if next_dw {
        RAW_NAN_BEACON_LATE_NEXT_DW.fetch_add(1, Ordering::Relaxed);
        raw_nan_dw_add_flags(RAW_NAN_DW_FLAG_NEXT);
    } else {
        RAW_NAN_BEACON_DRIFT.fetch_add(1, Ordering::Relaxed);
        raw_nan_dw_add_flags(RAW_NAN_DW_FLAG_DRIFT);
    }
    telemetry::record_log(format!(
        "event type=nan.duty beacon=late class={} expected_slot_index={} actual_slot_index={} phase_delta_us={} wake_to_first_frame_us={} expected_tsf_us={} actual_tsf_us={} local_us={} period_us={} wake_margin_ms={}",
        if next_dw { "next_dw" } else { "drift" },
        expected_slot_index,
        actual_slot_index,
        phase_delta_us,
        wake_to_first_frame_us,
        expected_tsf_us,
        snapshot.tsf_us,
        snapshot.local_us,
        period_us,
        RAW_NAN_WAKE_EARLY_MS.load(Ordering::Relaxed)
    ));
    record_raw_nan_timing(
        wake_to_first_frame_us,
        wake_to_beacon_us.min(u64::from(u32::MAX)) as u32,
        beacon_to_sleep_us.min(u64::from(u32::MAX)) as u32,
        RAW_NAN_DW_FLAG_LATE,
    );
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
    let start_us = now_us();
    set_raw_nan_window_start_us(start_us);
    RAW_NAN_DW_HISTORY_START_MS[index].store((start_us / 1000) as u32, Ordering::Relaxed);
    RAW_NAN_DW_HISTORY_BEACONS[index].store(0, Ordering::Relaxed);
    RAW_NAN_DW_HISTORY_FLAGS[index].store(flags, Ordering::Relaxed);
    RAW_NAN_DW_HISTORY_SEQ[index].store(seq, Ordering::Release);
    RAW_NAN_DW_ACTIVE_SEQ.store(seq, Ordering::Release);
}

fn set_raw_nan_window_start_us(start_us: u64) {
    RAW_NAN_WINDOW_START_US_LO.store(start_us as u32, Ordering::Relaxed);
    RAW_NAN_WINDOW_START_US_HI.store((start_us >> 32) as u32, Ordering::Relaxed);
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

fn record_raw_nan_timing(first_frame_us: u64, beacon_us: u32, post_beacon_us: u32, flags: u32) {
    let seq = RAW_NAN_DW_TOTAL.load(Ordering::Acquire);
    if seq == 0 {
        return;
    }
    let index = (seq as usize) % RAW_NAN_TIMING_HISTORY_LEN;
    RAW_NAN_TIMING_FIRST_FRAME_US[index].store(
        first_frame_us.min(u64::from(u32::MAX)) as u32,
        Ordering::Relaxed,
    );
    RAW_NAN_TIMING_BEACON_US[index].store(beacon_us, Ordering::Relaxed);
    RAW_NAN_TIMING_POST_BEACON_US[index].store(post_beacon_us, Ordering::Relaxed);
    RAW_NAN_TIMING_FLAGS[index].store(flags, Ordering::Relaxed);
    RAW_NAN_TIMING_SEQ[index].store(seq, Ordering::Release);
}

fn raw_nan_timing_history_fields() -> String {
    let newest = RAW_NAN_DW_TOTAL.load(Ordering::Acquire);
    let mut records = Vec::with_capacity(RAW_NAN_TIMING_HISTORY_LEN);
    for offset in 0..RAW_NAN_TIMING_HISTORY_LEN {
        let seq = newest.saturating_sub(offset as u32);
        if seq == 0 {
            break;
        }
        let index = (seq as usize) % RAW_NAN_TIMING_HISTORY_LEN;
        if RAW_NAN_TIMING_SEQ[index].load(Ordering::Acquire) != seq {
            continue;
        }
        records.push(format!(
            "{}:{}:{}:{}:{}",
            seq,
            RAW_NAN_TIMING_FIRST_FRAME_US[index].load(Ordering::Relaxed),
            RAW_NAN_TIMING_BEACON_US[index].load(Ordering::Relaxed),
            RAW_NAN_TIMING_POST_BEACON_US[index].load(Ordering::Relaxed),
            RAW_NAN_TIMING_FLAGS[index].load(Ordering::Relaxed),
        ));
    }
    records.join(",")
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
    let expected_tsf_us = (u64::from(RAW_NAN_EXPECT_TSF_HI.load(Ordering::Relaxed)) << 32)
        | u64::from(RAW_NAN_EXPECT_TSF_LO.load(Ordering::Relaxed));
    let expected_period_us = u64::from(RAW_NAN_EXPECT_PERIOD_US.load(Ordering::Relaxed));
    let (expected_dw_index, expected_dw_phase_us) = if expected_period_us == 0 {
        ("none".to_string(), "none".to_string())
    } else {
        (
            (expected_tsf_us / expected_period_us).to_string(),
            (expected_tsf_us % expected_period_us).to_string(),
        )
    };
    let last_beacon_tsf_us = (u64::from(RAW_NAN_LAST_BEACON_TSF_HI.load(Ordering::Relaxed)) << 32)
        | u64::from(RAW_NAN_LAST_BEACON_TSF_LO.load(Ordering::Relaxed));
    let (last_beacon_dw_index, last_beacon_dw_phase_us) = if expected_period_us == 0 {
        ("none".to_string(), "none".to_string())
    } else {
        (
            (last_beacon_tsf_us / expected_period_us).to_string(),
            (last_beacon_tsf_us % expected_period_us).to_string(),
        )
    };
    let last_miss_expected_tsf_us =
        (u64::from(RAW_NAN_LAST_MISS_EXPECT_TSF_HI.load(Ordering::Relaxed)) << 32)
            | u64::from(RAW_NAN_LAST_MISS_EXPECT_TSF_LO.load(Ordering::Relaxed));
    let last_miss_tsf_us = (u64::from(RAW_NAN_LAST_MISS_TSF_HI.load(Ordering::Relaxed)) << 32)
        | u64::from(RAW_NAN_LAST_MISS_TSF_LO.load(Ordering::Relaxed));
    let last_miss_local_us = (u64::from(RAW_NAN_LAST_MISS_LOCAL_HI.load(Ordering::Relaxed)) << 32)
        | u64::from(RAW_NAN_LAST_MISS_LOCAL_LO.load(Ordering::Relaxed));
    let last_miss_now_us = (u64::from(RAW_NAN_LAST_MISS_NOW_HI.load(Ordering::Relaxed)) << 32)
        | u64::from(RAW_NAN_LAST_MISS_NOW_LO.load(Ordering::Relaxed));
    format!(
        "nan_dw_total={} nan_dw0_total={} nan_dw_sync_total={} nan_dw_early_wake_total={} nan_wake_early_ms={} nan_miss_probes={} nan_raw_cmd_rx={} nan_raw_resp_tx={} nan_raw_queue_len={} nan_raw_cmd_pending={} nan_raw_resp_pending={} nan_dw_recent=seq:start_ms:beacons:flags:{} nan_expected_tsf_us={} nan_expected_period_us={} nan_selected_stride={} nan_expected_slot_index={} nan_expected_slot_phase_us={} nan_last_beacon_tsf_us={} nan_last_beacon_slot_index={} nan_last_beacon_slot_phase_us={} nan_last_wake_to_first_frame_us={} nan_last_wake_to_beacon_us={} nan_last_beacon_to_sleep_us={} nan_last_miss_wake_to_first_frame_us={} nan_last_miss_expected_tsf_us={} nan_last_miss_tsf_us={} nan_last_miss_local_us={} nan_last_miss_now_us={} nan_beacon_seen={} nan_beacon_missed={} nan_beacon_late={} nan_beacon_late_next_dw={} nan_beacon_drift={} nan_miss_backoff_ms={} sync_source={} ap_owner={} ap_active={} sleep_inhibited={} ap_owner_start={} ap_owner_stop={} ap_recovery_runs={} ap_recovery_next_ms={}",
        RAW_NAN_DW_TOTAL.load(Ordering::Relaxed),
        RAW_NAN_DW0_TOTAL.load(Ordering::Relaxed),
        RAW_NAN_DW_SYNC_TOTAL.load(Ordering::Relaxed),
        RAW_NAN_DW_EARLY_WAKE_TOTAL.load(Ordering::Relaxed),
        RAW_NAN_WAKE_EARLY_MS.load(Ordering::Relaxed),
        RAW_NAN_MISS_PROBES.load(Ordering::Relaxed),
        super::nan::raw_command_rx_count(),
        super::nan::raw_response_tx_count(),
        super::nan::raw_queue_len(),
        super::nan::raw_command_pending_count(),
        super::nan::raw_response_pending_count(),
        raw_nan_dw_recent_fields(),
        expected_tsf_us,
        expected_period_us,
        RAW_NAN_DATA_DW_STRIDE.load(Ordering::Relaxed),
        expected_dw_index,
        expected_dw_phase_us,
        last_beacon_tsf_us,
        last_beacon_dw_index,
        last_beacon_dw_phase_us,
        RAW_NAN_LAST_WAKE_TO_FIRST_FRAME_US.load(Ordering::Relaxed),
        RAW_NAN_LAST_WAKE_TO_BEACON_US.load(Ordering::Relaxed),
        RAW_NAN_LAST_BEACON_TO_SLEEP_US.load(Ordering::Relaxed),
        RAW_NAN_LAST_MISS_WAKE_TO_FIRST_FRAME_US.load(Ordering::Relaxed),
        last_miss_expected_tsf_us,
        last_miss_tsf_us,
        last_miss_local_us,
        last_miss_now_us,
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

/// Small subset of NAN counters suitable for an event-triggered LoRa wake
/// report. The full mode status remains available on demand.
pub fn raw_nan_wake_summary() -> String {
    format!(
        "nan_miss_probes={} nan_beacon_seen={} nan_beacon_missed={} sync_source={}",
        RAW_NAN_MISS_PROBES.load(Ordering::Relaxed),
        RAW_NAN_BEACON_SEEN.load(Ordering::Relaxed),
        RAW_NAN_BEACON_MISSED.load(Ordering::Relaxed),
        sync_source_name(RAW_NAN_SYNC_SOURCE.load(Ordering::Relaxed)),
    )
}

/// Return the bounded timing counters used by the no-command sleep soak.
/// Unlike the full mode status this excludes queue, AP, and companion state,
/// so a host can sample it without turning the diagnostic itself into a large
/// UART wake.
pub fn raw_nan_timing_fields() -> String {
    format!(
        "nan_timing wake_margin_ms={} dw_stride={} dw_total={} dw_sync={} dw_missed={} dw_late={} dw_next_dw={} dw_drift={} early_wakes={} wake_to_first_frame_us={} wake_to_beacon_us={} beacon_to_sleep_us={} miss_wake_to_first_frame_us={} expected_tsf_us={} last_tsf_us={} history=seq:first_frame_us:beacon_us:post_beacon_us:flags:{}",
        RAW_NAN_WAKE_EARLY_MS.load(Ordering::Relaxed),
        RAW_NAN_DATA_DW_STRIDE.load(Ordering::Relaxed),
        RAW_NAN_DW_TOTAL.load(Ordering::Relaxed),
        RAW_NAN_DW_SYNC_TOTAL.load(Ordering::Relaxed),
        RAW_NAN_BEACON_MISSED.load(Ordering::Relaxed),
        RAW_NAN_BEACON_LATE.load(Ordering::Relaxed),
        RAW_NAN_BEACON_LATE_NEXT_DW.load(Ordering::Relaxed),
        RAW_NAN_BEACON_DRIFT.load(Ordering::Relaxed),
        RAW_NAN_DW_EARLY_WAKE_TOTAL.load(Ordering::Relaxed),
        RAW_NAN_LAST_WAKE_TO_FIRST_FRAME_US.load(Ordering::Relaxed),
        RAW_NAN_LAST_WAKE_TO_BEACON_US.load(Ordering::Relaxed),
        RAW_NAN_LAST_BEACON_TO_SLEEP_US.load(Ordering::Relaxed),
        RAW_NAN_LAST_MISS_WAKE_TO_FIRST_FRAME_US.load(Ordering::Relaxed),
        (u64::from(RAW_NAN_EXPECT_TSF_HI.load(Ordering::Relaxed)) << 32)
            | u64::from(RAW_NAN_EXPECT_TSF_LO.load(Ordering::Relaxed)),
        (u64::from(RAW_NAN_LAST_BEACON_TSF_HI.load(Ordering::Relaxed)) << 32)
            | u64::from(RAW_NAN_LAST_BEACON_TSF_LO.load(Ordering::Relaxed)),
        raw_nan_timing_history_fields(),
    )
}

/// Return the configured NAN slot stride for source-side beacon accounting.
pub fn raw_nan_data_stride() -> u32 {
    RAW_NAN_DATA_DW_STRIDE.load(Ordering::Relaxed).max(1)
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
    match from_mode.as_deref() {
        Some("sleepy") | Some("battery") | Some("nan_sleep") => MODE_SLEEPY,
        Some("companion") => {
            telemetry::record_log(
                "event type=mode.startup saved=companion action=ignore start=infra",
            );
            MODE_INFRA
        }
        _ => MODE_INFRA,
    }
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
    (now_us() / 1000) as u32
}

fn now_us() -> u64 {
    unsafe { sys::esp_timer_get_time().max(0) as u64 }
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
        MODE_SLEEPY => "sleepy",
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
            return Ok(CommandResponse::ok(active_status_text()));
        }
        if request.name == "idle" {
            if is_companion_mode() {
                bail!("idle requires infra mode; run mode infra=true first");
            }
            stop_infra_active_session();
            return Ok(CommandResponse::ok(active_status_text()));
        }
        if let Some(value) = request
            .arg("nan_early_ms")
            .or_else(|| request.arg("wake_early_ms"))
        {
            let margin = value
                .parse::<u32>()
                .map_err(|err| anyhow!("invalid nan_early_ms={value}: {err}"))?
                .clamp(NAN_WAKE_MARGIN_MIN_MS, NAN_WAKE_MARGIN_MAX_MS);
            RAW_NAN_WAKE_EARLY_MS.store(margin, Ordering::Release);
            if save_requested(request) {
                self.settings
                    .borrow_mut()
                    .set_i32("nan.early_ms", margin as i32)?;
            }
            telemetry::record_log(format!(
                "event type=nan.duty wake_margin_update_ms={} saved={}",
                margin,
                save_requested(request)
            ));
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
            .arg("sleepy")
            .or_else(|| request.arg("battery"))
            .map(parse_bool)
            .transpose()?
            .unwrap_or(false)
        {
            // A sleepy transition must terminate an earlier explicit
            // `mode active` session.  Without this, the persistent active
            // flag keeps the raw-WiFi and UART no-light-sleep locks held even
            // though PRODUCT_MODE is changed to sleepy, leaving a battery
            // node at the infrastructure power level indefinitely.
            stop_infra_active_session();
            super::serial::set_always_on(false);
            PRODUCT_MODE.store(MODE_SLEEPY, Ordering::Relaxed);
            if save_requested(request) {
                self.settings.borrow_mut().set_str("mode", "sleepy")?;
            }
            stop_ap_owner().ok();
            stop_raw_nan_duty();
            let channel = get_u32(&self.settings, "nan.channel", 6).clamp(1, 13) as u8;
            start_raw_nan_duty(&self.settings, "command", channel)?;
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
                PRODUCT_MODE.store(MODE_SLEEPY, Ordering::Relaxed);
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
                return Ok(CommandResponse::ok(active_status_text()));
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
            return Ok(CommandResponse::ok(active_status_text()));
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
        "mode active={} infra_active={} infra_active_persistent={} infra_active_deadline_ms={} infra_active_start={} infra_active_stop={} infra_active_expire={} infra_active_uart_extend={} nan_expected_extends={} targeted_wake={} targeted_wake_deadline_ms={} companion_advertising={} companion_pending_advertising={} pending={} deadline_ms={} ping_rx={} ping_tx={} {}",
        mode_name(),
        infra_active_session_enabled(),
        INFRA_ACTIVE_PERSISTENT.load(Ordering::Relaxed),
        INFRA_ACTIVE_DEADLINE_MS.load(Ordering::Relaxed),
        INFRA_ACTIVE_STARTS.load(Ordering::Relaxed),
        INFRA_ACTIVE_STOPS.load(Ordering::Relaxed),
        INFRA_ACTIVE_EXPIRES.load(Ordering::Relaxed),
        INFRA_ACTIVE_UART_EXTENDS.load(Ordering::Relaxed),
        RAW_NAN_EXPECT_EXTENDS.load(Ordering::Relaxed),
        targeted_wake_active(),
        RAW_NAN_TARGET_WAKE_UNTIL_MS.load(Ordering::Relaxed),
        COMPANION_ADVERTISING.load(Ordering::Relaxed),
        COMPANION_PENDING_ADVERTISING.load(Ordering::Relaxed),
        telemetry::pending_message_count(),
        COMPANION_DEADLINE_MS.load(Ordering::Relaxed),
        PING_RX.load(Ordering::Relaxed),
        PING_TX.load(Ordering::Relaxed),
        raw_nan_status_fields()
    )
}

// Keep the response to the runtime active/idle control command below the
// 4 KiB UART record limit. The full status includes the raw-NAN diagnostic
// counters and can be several kilobytes long; returning it here makes lmesh
// reject the otherwise successful command as an oversized framed record.
fn active_status_text() -> String {
    format!(
        "mode active={} infra_active={} infra_active_persistent={} infra_active_deadline_ms={} pending={} deadline_ms={}",
        mode_name(),
        infra_active_session_enabled(),
        INFRA_ACTIVE_PERSISTENT.load(Ordering::Relaxed),
        INFRA_ACTIVE_DEADLINE_MS.load(Ordering::Relaxed),
        telemetry::pending_message_count(),
        COMPANION_DEADLINE_MS.load(Ordering::Relaxed),
    )
}

#[cfg(test)]
mod tests {
    use super::{deadline_due, deadline_not_due, ping_packet};
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

    #[test]
    fn duty_deadline_wrap_logic_keeps_future_window_open() {
        assert!(deadline_not_due(100, 1_000));
        assert!(!deadline_due(100, 1_000));
        assert!(deadline_due(1_001, 1_000));
        assert!(!deadline_not_due(1_001, 1_000));
        // Timer wrap must preserve the same ordering semantics.
        assert!(deadline_not_due(u32::MAX - 10, 5));
        assert!(deadline_due(5, u32::MAX - 10));
    }
}
