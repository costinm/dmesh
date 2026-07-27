use std::mem::size_of;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU8, Ordering};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Result};
use esp_idf_sys as sys;

use crate::commands::{CommandHandler, CommandRegistry, CommandRequest, CommandResponse};

use super::lora::{self, LoraChip, LoraConfig};
use super::settings::{parse_bool, SharedSettings};
use super::telemetry;

const RTC_MAGIC: u32 = 0x4453_4c50;
const RTC_VERSION: u16 = 5;
const FLAG_WIFI: u32 = 1 << 0;
const FLAG_SERIAL: u32 = 1 << 1;
const FLAG_BLE: u32 = 1 << 2;
const FLAG_LORA: u32 = 1 << 3;
const FLAG_NAN_RAW: u32 = 1 << 4;
const DEFAULT_WAKE_MS: u32 = 5_000;
const DEFAULT_FORWARD_MS: u32 = 1_000;
const LIGHT_PS_NONE: u8 = 0;
const LIGHT_PS_MIN: u8 = 1;
const LIGHT_PS_MAX: u8 = 2;

static LIGHT_SLEEP_ENABLED: AtomicBool = AtomicBool::new(false);
static LIGHT_WIFI: AtomicBool = AtomicBool::new(false);
static LIGHT_BLE: AtomicBool = AtomicBool::new(false);
static LIGHT_BLE_SCAN: AtomicBool = AtomicBool::new(false);
static LIGHT_RAW: AtomicBool = AtomicBool::new(false);
static LIGHT_NAN: AtomicBool = AtomicBool::new(false);
static LIGHT_SERIAL: AtomicBool = AtomicBool::new(false);
static LIGHT_CHANNEL: AtomicU8 = AtomicU8::new(6);
static LIGHT_WAKE_MS: AtomicU32 = AtomicU32::new(0);
static LIGHT_PS: AtomicU8 = AtomicU8::new(LIGHT_PS_MIN);
static LIGHT_TEST_RUNS: AtomicU32 = AtomicU32::new(0);
static LIGHT_TEST_PREPARE_OK: AtomicU32 = AtomicU32::new(0);
static LIGHT_TEST_PREPARE_FAIL: AtomicU32 = AtomicU32::new(0);
static LIGHT_TEST_WAKE_OK: AtomicU32 = AtomicU32::new(0);
static LIGHT_TEST_WAKE_FAIL: AtomicU32 = AtomicU32::new(0);
static LIGHT_TEST_RESTORE_OK: AtomicU32 = AtomicU32::new(0);
static LIGHT_TEST_RESTORE_FAIL: AtomicU32 = AtomicU32::new(0);
static LIGHT_TEST_WIFI_WAKE_OK: AtomicU32 = AtomicU32::new(0);
static LIGHT_TEST_WIFI_WAKE_UNSUPPORTED: AtomicU32 = AtomicU32::new(0);
static LIGHT_TEST_WIFI_BEACON_WAKE_OK: AtomicU32 = AtomicU32::new(0);
static LIGHT_TEST_WIFI_BEACON_WAKE_UNSUPPORTED: AtomicU32 = AtomicU32::new(0);
static LIGHT_TEST_BT_WAKE_OK: AtomicU32 = AtomicU32::new(0);
static LIGHT_TEST_BT_WAKE_UNSUPPORTED: AtomicU32 = AtomicU32::new(0);
static LIGHT_TEST_LAST_ELAPSED_MS: AtomicU32 = AtomicU32::new(0);
static LIGHT_TEST_LAST_CAUSE: AtomicU32 = AtomicU32::new(0);
static LIGHT_TEST_LAST_CAUSES: AtomicU32 = AtomicU32::new(0);
static LIGHT_TEST_LAST_RET: AtomicU32 = AtomicU32::new(0);
static LIGHT_TEST_LAST_PHASE: AtomicU8 = AtomicU8::new(0);
static LIGHT_TEST_LAST_ERR: AtomicU32 = AtomicU32::new(0);
static RAW_NAN_LIGHT_RUNS: AtomicU32 = AtomicU32::new(0);
static RAW_NAN_LIGHT_WAKE_OK: AtomicU32 = AtomicU32::new(0);
static RAW_NAN_LIGHT_WAKE_FAIL: AtomicU32 = AtomicU32::new(0);
static RAW_NAN_LIGHT_LAST_MS: AtomicU32 = AtomicU32::new(0);
static RAW_NAN_LIGHT_LAST_CAUSE: AtomicU32 = AtomicU32::new(0);
static RAW_NAN_LIGHT_LAST_RET: AtomicU32 = AtomicU32::new(0);

/// Sleep for a bounded idle interval with the radio-independent wake sources armed.
///
/// Timer, button, UART, and LoRa DIO0 wake sources are armed through the same
/// helper as the interactive light-sleep profile. Transport schedulers decide
/// their own deadlines and resume their radios after this returns.
pub fn idle_light_sleep(settings: &SharedSettings, sleep_ms: u32) -> Result<()> {
    if sleep_ms == 0 {
        return Ok(());
    }

    // A DTR/PRG wake owns the next active window. Do not let the NAN duty
    // scheduler suspend UART again while the operator is still using the
    // console or while a command response is being emitted.
    if super::serial::is_active() {
        telemetry::record_log("event type=uart.sleep skipped=true reason=active_window");
        return Ok(());
    }

    #[cfg(target_feature = "esp32s3ops")]
    {
        // Do not rely on automatic PM here. The S3 has long-lived Wi-Fi and
        // system tasks, so a FreeRTOS notification wait can remain runnable
        // while tickless idle never calls into light sleep. GPIO0 is shared by
        // physical PRG and the CP210x DTR line and is the explicit console
        // wake source; leave UART RX out of the sleep mask because its level
        // detector can remain asserted by the bridge and reject the request.
        configure_light_wake_sources(settings, sleep_ms, false, false, true)?;
        super::serial::suspend_for_light_sleep();
        RAW_NAN_LIGHT_RUNS.fetch_add(1, Ordering::Relaxed);
        let before_us = now_us();
        let ret = start_raw_nan_light_sleep();
        let elapsed_ms = now_us()
            .saturating_sub(before_us)
            .saturating_div(1000)
            .min(u32::MAX as u64) as u32;
        RAW_NAN_LIGHT_LAST_MS.store(elapsed_ms, Ordering::Relaxed);
        let cause = unsafe { sys::esp_sleep_get_wakeup_cause() };
        RAW_NAN_LIGHT_LAST_CAUSE.store(cause as u32, Ordering::Relaxed);
        RAW_NAN_LIGHT_LAST_RET.store(ret as u32, Ordering::Relaxed);
        // GPIO0 is both PRG and the CP210x DTR line. DTR is a pulse, so the
        // level may already be released when esp_light_sleep_start returns.
        // It is the only GPIO source armed for this S3 raw-NAN interval;
        // LoRa DIO is intentionally not registered here.
        if cause == sys::esp_sleep_source_t_ESP_SLEEP_WAKEUP_GPIO {
            super::serial::rearm_after_wake();
            telemetry::record_log("event type=uart.wake source=gpio phase=light_sleep_return");
        }
        if ret == sys::ESP_OK {
            RAW_NAN_LIGHT_WAKE_OK.fetch_add(1, Ordering::Relaxed);
            return Ok(());
        }
        RAW_NAN_LIGHT_WAKE_FAIL.fetch_add(1, Ordering::Relaxed);
        return esp_ok(ret);
    }

    #[cfg(not(target_feature = "esp32s3ops"))]
    {
        // Classic ESP32 keeps UART RX wake armed in idle. ESP32-S3 uses GPIO0/DTR
        // instead: its UART wake detector can be left asserted by the USB-UART
        // bridge and rejects the sleep request before the timer can run.
        // Raw-NAN has already stopped Wi-Fi before this interval. Its scheduler
        // resumes the modem from its timer deadline, so do not register Wi-Fi,
        // beacon, or BT wake sources here. On ESP32-S3 those inactive sources make
        // esp_light_sleep_start() reject the sleep configuration with 0x103.
        configure_light_wake_sources(
            settings,
            sleep_ms,
            super::serial::RAW_NAN_UART_WAKE,
            false,
            super::serial::RAW_NAN_BUTTON_WAKE,
        )?;
        super::serial::suspend_for_light_sleep();
        RAW_NAN_LIGHT_RUNS.fetch_add(1, Ordering::Relaxed);
        let before_us = now_us();
        let ret = start_raw_nan_light_sleep();
        let elapsed_ms = now_us()
            .saturating_sub(before_us)
            .saturating_div(1000)
            .min(u32::MAX as u64) as u32;
        let cause = unsafe { sys::esp_sleep_get_wakeup_cause() };
        RAW_NAN_LIGHT_LAST_MS.store(elapsed_ms, Ordering::Relaxed);
        RAW_NAN_LIGHT_LAST_CAUSE.store(cause as u32, Ordering::Relaxed);
        RAW_NAN_LIGHT_LAST_RET.store(ret as u32, Ordering::Relaxed);
        let button_wake =
            cause == sys::esp_sleep_source_t_ESP_SLEEP_WAKEUP_GPIO && super::button::is_pressed();
        if cause == sys::esp_sleep_source_t_ESP_SLEEP_WAKEUP_UART || button_wake {
            // A real UART edge or asserted GPIO0/PRG wake owns the console
            // window. LoRa DIO can also wake light sleep through GPIO; it must
            // not make every CAD/RX interrupt look like a console request.
            super::serial::rearm_after_wake();
            telemetry::record_log(format!(
                "event type=uart.wake source={} phase=light_sleep_return",
                wake_cause_name(cause)
            ));
        } else if cause == sys::esp_sleep_source_t_ESP_SLEEP_WAKEUP_GPIO {
            telemetry::record_log("event type=sleep.light_wake source=gpio non_console=true");
        }
        if ret == sys::ESP_OK {
            RAW_NAN_LIGHT_WAKE_OK.fetch_add(1, Ordering::Relaxed);
            Ok(())
        } else {
            RAW_NAN_LIGHT_WAKE_FAIL.fetch_add(1, Ordering::Relaxed);
            esp_ok(ret)
        }
    }
}

/// Enter raw-NAN light sleep after Wi-Fi has been stopped.
///
/// ESP-IDF occasionally reports `ESP_ERR_INVALID_STATE` in the few
/// milliseconds while the Wi-Fi/PM teardown completes. Retrying once is
/// bounded and avoids losing an entire raw-NAN duty interval to that
/// transition race. Other errors remain observable to the caller.
fn start_raw_nan_light_sleep() -> sys::esp_err_t {
    let ret = unsafe { sys::esp_light_sleep_start() };
    if ret != sys::ESP_ERR_INVALID_STATE {
        return ret;
    }
    telemetry::record_log("event type=nan.duty phase=light_sleep retry=true err=0x103");
    unsafe {
        sys::vTaskDelay((10 * sys::configTICK_RATE_HZ / 1_000).max(1));
        sys::esp_light_sleep_start()
    }
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct RtcLoraConfig {
    chip: i32,
    frequency_hz: u32,
    bandwidth_hz: u32,
    spi_host: i32,
    sck: i32,
    miso: i32,
    mosi: i32,
    cs: i32,
    rst: i32,
    dio0: i32,
    busy: i32,
    board_power_pin: i32,
    board_power_level: i32,
    sx1262_tcxo_mv: i32,
    sx1262_pa_duty: i32,
    sx1262_pa_hp: i32,
    sx1262_pa_device: i32,
    sx1262_pa_lut: i32,
    sx1262_rx_timeout_ms: i32,
    sx1262_sync_word: i32,
    sf: i32,
    cr: i32,
    sync_word: i32,
    crc: u8,
    beacon: u8,
    sx1262_dio2_rf_switch: u8,
    _pad0: u8,
    preamble: i32,
    tx_power: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RtcSleepState {
    magic: u32,
    version: u16,
    len: u16,
    checksum: u32,
    flags: u32,
    wake_ms: u32,
    forward_ms: u32,
    boot_count: u32,
    wake_count: u32,
    last_cause: u32,
    last_ext1_mask: u64,
    last_packet_len: u16,
    wifi_channel: u8,
    _pad0: u8,
    last_packet_hash: u32,
    lora: RtcLoraConfig,
}

impl RtcSleepState {
    const fn empty() -> Self {
        Self {
            magic: 0,
            version: 0,
            len: 0,
            checksum: 0,
            flags: 0,
            wake_ms: 0,
            forward_ms: 0,
            boot_count: 0,
            wake_count: 0,
            last_cause: 0,
            last_ext1_mask: 0,
            last_packet_len: 0,
            wifi_channel: 6,
            _pad0: 0,
            last_packet_hash: 0,
            lora: RtcLoraConfig {
                chip: 0,
                frequency_hz: 0,
                bandwidth_hz: 0,
                spi_host: 0,
                sck: 0,
                miso: 0,
                mosi: 0,
                cs: 0,
                rst: 0,
                dio0: 0,
                busy: -1,
                board_power_pin: -1,
                board_power_level: 1,
                sx1262_tcxo_mv: 0,
                sx1262_pa_duty: 0,
                sx1262_pa_hp: 0,
                sx1262_pa_device: 0,
                sx1262_pa_lut: 0,
                sx1262_rx_timeout_ms: 0,
                sx1262_sync_word: -1,
                sf: 0,
                cr: 0,
                sync_word: 0,
                crc: 0,
                beacon: 0,
                sx1262_dio2_rf_switch: 0,
                _pad0: 0,
                preamble: 0,
                tx_power: 0,
            },
        }
    }
}

#[link_section = ".rtc_noinit"]
static mut RTC_SLEEP_STATE: RtcSleepState = RtcSleepState::empty();

pub fn register_commands(registry: &mut CommandRegistry, settings: SharedSettings) {
    registry.register(SleepCommand { settings });
}

pub fn handle_deep_sleep_wake() -> Result<()> {
    let cause = unsafe { sys::esp_sleep_get_wakeup_cause() };
    let ext1_mask = unsafe { sys::esp_sleep_get_ext1_wakeup_status() };
    let mut state = read_state();
    if valid_state(&state) {
        state.boot_count = state.boot_count.saturating_add(1);
        if cause != sys::esp_sleep_source_t_ESP_SLEEP_WAKEUP_UNDEFINED {
            state.last_cause = cause;
            state.last_ext1_mask = ext1_mask;
        }
        state = update_checksum(state);
        write_state(state);
    }

    telemetry::record_log(format!(
        "event type=sleep.wakeup cause={} ext1_mask=0x{:x} rtc_valid={}",
        wake_cause_name(cause),
        ext1_mask,
        valid_state(&state)
    ));

    if !valid_state(&state) {
        return Ok(());
    }

    let lora_wake = state.flags & FLAG_LORA != 0
        && cause == sys::esp_sleep_source_t_ESP_SLEEP_WAKEUP_EXT1
        && ext1_mask & (1_u64 << state.lora.dio0) != 0;
    let timer_wake = cause == sys::esp_sleep_source_t_ESP_SLEEP_WAKEUP_TIMER;
    if !lora_wake && !timer_wake {
        return Ok(());
    }

    if lora_wake {
        let config = state.lora.to_config();
        match lora::read_wake_packet_no_reset(&config) {
            Ok(Some(packet)) => {
                state.wake_count = state.wake_count.saturating_add(1);
                state.last_packet_len = packet.data.len().min(u16::MAX as usize) as u16;
                state.last_packet_hash = fnv1a32(&packet.data);
                write_state(update_checksum(state));
                if state.flags & FLAG_SERIAL != 0 {
                    telemetry::record_log(format!(
                        "event type=lora.wake_rx len={} rssi={} snr={}",
                        packet.data.len(),
                        packet.rssi,
                        packet.snr
                    ));
                } else {
                    telemetry::record_log(format!(
                        "event type=lora.wake_rx len={} rssi={} snr={}",
                        packet.data.len(),
                        packet.rssi,
                        packet.snr
                    ));
                }
                forward_packet(&state, &packet.data, Some((packet.rssi, packet.snr)));
            }
            Ok(None) => {
                telemetry::record_log("event type=lora.wake_rx len=0 message=no-pending-packet");
            }
            Err(err) => {
                telemetry::record_log(format!(
                    "event type=lora.wake_rx error={}",
                    crate::commands::protocol::escape_value(&err.to_string())
                ));
            }
        }
    }

    if active_window(&state)? {
        return Ok(());
    }
    enter_deep_sleep_with_state(state)
}

struct SleepCommand {
    settings: SharedSettings,
}

impl CommandHandler for SleepCommand {
    fn name(&self) -> &'static str {
        "sleep"
    }

    fn handle(&mut self, request: &CommandRequest) -> Result<CommandResponse> {
        if let Some(profile) = request.arg("profile") {
            return apply_profile(&self.settings, request, profile);
        }
        if let Some(test) = request.arg("test") {
            let result = run_light_sleep_test(&self.settings, request, test)?;
            return Ok(CommandResponse::ok(result));
        }
        if request.arg("status").is_some()
            || (request.arg("start").is_none() && request.arg("stop").is_none())
        {
            return Ok(CommandResponse::ok(status_text()));
        }

        let mode = request.arg("mode").unwrap_or("deep");
        if mode == "light" {
            if request
                .arg("stop")
                .map(parse_bool)
                .transpose()?
                .unwrap_or(false)
            {
                stop_light_sleep()?;
                return Ok(CommandResponse::ok(status_text()));
            }
            start_light_sleep(&self.settings, request)?;
            return Ok(CommandResponse::ok(status_text()));
        }
        if mode != "deep" && mode != "nan_raw" && mode != "raw_nan" {
            bail!("only mode=deep is implemented for RTC LoRa wake loop");
        }
        let config = lora::load_config(&self.settings)?;
        let default_wake_ms =
            if (mode == "nan_raw" || mode == "raw_nan") && super::test::has_active_send_test() {
                super::test::wake_ms()
            } else {
                DEFAULT_WAKE_MS
            };
        let default_forward_ms =
            if (mode == "nan_raw" || mode == "raw_nan") && super::test::has_active_send_test() {
                super::test::active_ms()
            } else {
                DEFAULT_FORWARD_MS
            };
        let wake_ms = parse_u32_arg(request, "wake_ms", default_wake_ms)?
            .or(parse_u32_arg(request, "ms", default_wake_ms)?)
            .unwrap_or(default_wake_ms);
        let forward_ms = parse_u32_arg(request, "active_ms", default_forward_ms)?
            .or(parse_u32_arg(request, "forward_ms", default_forward_ms)?)
            .unwrap_or(default_forward_ms);
        let channel = request
            .arg("channel")
            .map(|value| {
                value
                    .parse::<u8>()
                    .map_err(|err| anyhow!("invalid channel={value}: {err}"))
            })
            .transpose()?
            .unwrap_or(6)
            .clamp(1, 13);
        let mut flags = 0_u32;
        if mode == "nan_raw" || mode == "raw_nan" {
            flags |= FLAG_NAN_RAW | FLAG_WIFI;
        }
        if request
            .arg("lora")
            .or_else(|| request.arg("lora_listen"))
            .map(parse_bool)
            .transpose()?
            .unwrap_or(false)
        {
            flags |= FLAG_LORA;
        }
        if request
            .arg("wifi")
            .map(parse_bool)
            .transpose()?
            .unwrap_or(mode != "nan_raw" && mode != "raw_nan")
        {
            flags |= FLAG_WIFI;
        }
        if request
            .arg("ble")
            .map(parse_bool)
            .transpose()?
            .unwrap_or(true)
        {
            flags |= FLAG_BLE;
        }
        if request
            .arg("serial")
            .map(parse_bool)
            .transpose()?
            .unwrap_or(true)
        {
            flags |= FLAG_SERIAL;
        }
        let mut state = new_state(config, wake_ms, forward_ms, flags, channel);
        if flags & FLAG_LORA != 0 {
            lora::prepare_deep_sleep_rx(&config)?;
        }
        state = update_checksum(state);
        write_state(state);
        enter_deep_sleep_with_state(state)?;
        Ok(CommandResponse::ok("sleep rejected"))
    }
}

fn apply_profile(
    settings: &SharedSettings,
    request: &CommandRequest,
    profile: &str,
) -> Result<CommandResponse> {
    match profile {
        "ble_adv" | "ble-advertise" | "ble_connectable" => {
            if request
                .arg("lora_sleep")
                .map(parse_bool)
                .transpose()?
                .unwrap_or(true)
            {
                lora::sleep_radio(settings)?;
            }
            start_light_sleep_profile(
                settings,
                LightSleepProfile {
                    ble: true,
                    ble_scan: false,
                    wifi: false,
                    raw: false,
                    nan: false,
                    serial: false,
                    channel: 6,
                    wake_ms: DEFAULT_WAKE_MS,
                    ps: "max",
                },
            )?;
            super::ble_bt::set_advertising_interval_ms(1000, 1200);
            super::ble_bt::start_connectable_advertising()?;
            Ok(CommandResponse::ok(format!(
                "{} {}",
                "sleep profile=ble_adv lora_sleep=true",
                status_text()
            )))
        }
        "active" | "awake" | "play" => {
            stop_light_sleep()?;
            super::ble_bt::disable_controller_sleep()?;
            super::ble_bt::start_listen_mode()?;
            Ok(CommandResponse::ok(format!(
                "sleep profile=active {}",
                status_text()
            )))
        }
        _ => bail!("unsupported sleep profile {profile}"),
    }
}

pub fn enter_companion_deep_sleep(
    settings: &SharedSettings,
    lora_listen: bool,
    wake_ms: u32,
    active_ms: u32,
) -> Result<()> {
    let mut flags = 0;
    if lora_listen {
        flags |= FLAG_LORA | FLAG_BLE;
    }
    let config = lora::load_config(settings)?;
    let mut state = new_state(config, wake_ms, active_ms, flags, 6);
    if lora_listen {
        lora::prepare_deep_sleep_rx(&state.lora.to_config())?;
    } else {
        let _ = lora::sleep_radio(settings);
    }
    state = update_checksum(state);
    write_state(state);
    enter_deep_sleep_with_state(state)
}

pub fn enable_companion_idle_pm(settings: &SharedSettings) -> Result<()> {
    configure_pm(true)?;
    configure_light_wake_sources(settings, DEFAULT_WAKE_MS, true, true, true)?;
    telemetry::record_log("ev=sleep.pm companion_idle=true light=true serial=true");
    Ok(())
}

struct LightSleepProfile {
    ble: bool,
    ble_scan: bool,
    wifi: bool,
    raw: bool,
    nan: bool,
    serial: bool,
    channel: u8,
    wake_ms: u32,
    ps: &'static str,
}

fn start_light_sleep_profile(settings: &SharedSettings, profile: LightSleepProfile) -> Result<()> {
    let ps_code = parse_ps(profile.ps)?;

    if profile.ble {
        if profile.ble_scan {
            super::ble_bt::start_listen_mode()?;
        } else {
            super::ble_bt::start_connectable_advertising()?;
        }
        if let Err(err) = super::ble_bt::enable_controller_sleep() {
            telemetry::record_log(format!(
                "ev=sleep.err mode=light target=ble_sleep err={}",
                crate::commands::protocol::escape_value(&err.to_string())
            ));
        }
    } else {
        super::ble_bt::stop_radio_activity();
    }
    if profile.wifi || profile.raw {
        if profile.raw {
            super::wifi::start_raw_monitor_mode(profile.channel, "dmesh")?;
        } else {
            super::wifi::ensure_raw_wifi_started(profile.channel)?;
        }
        super::wifi::set_power_save(profile.ps)?;
    } else if !profile.nan {
        let _ = super::wifi::stop_raw_monitor();
    }
    if profile.nan {
        super::wifi::stop_raw_monitor().ok();
        super::nan::start_raw_window(profile.channel, "dmesh")?;
        super::wifi::set_power_save(profile.ps)?;
    }
    configure_pm(true)?;
    configure_light_wake_sources(
        settings,
        profile.wake_ms,
        profile.serial,
        profile.wifi || profile.raw || profile.nan || profile.ble,
        true,
    )?;

    LIGHT_SLEEP_ENABLED.store(true, Ordering::Relaxed);
    LIGHT_WIFI.store(profile.wifi, Ordering::Relaxed);
    LIGHT_BLE.store(profile.ble, Ordering::Relaxed);
    LIGHT_BLE_SCAN.store(profile.ble_scan, Ordering::Relaxed);
    LIGHT_RAW.store(profile.raw, Ordering::Relaxed);
    LIGHT_NAN.store(profile.nan, Ordering::Relaxed);
    LIGHT_SERIAL.store(profile.serial, Ordering::Relaxed);
    LIGHT_CHANNEL.store(profile.channel, Ordering::Relaxed);
    LIGHT_WAKE_MS.store(profile.wake_ms, Ordering::Relaxed);
    LIGHT_PS.store(ps_code, Ordering::Relaxed);
    telemetry::record_log(format!(
        "ev=sleep.light on=true wifi={} ble={} ble_scan={} raw={} nan={} ps={} ch={} wake_ms={} serial={}",
        profile.wifi,
        profile.ble,
        profile.ble_scan,
        profile.raw,
        profile.nan,
        profile.ps,
        profile.channel,
        profile.wake_ms,
        profile.serial
    ));
    Ok(())
}

fn start_light_sleep(settings: &SharedSettings, request: &CommandRequest) -> Result<()> {
    let channel = request
        .arg("channel")
        .map(|value| {
            value
                .parse::<u8>()
                .map_err(|err| anyhow!("invalid channel={value}: {err}"))
        })
        .transpose()?
        .unwrap_or(6)
        .clamp(1, 13);
    let wake_ms = parse_u32_arg(request, "wake_ms", DEFAULT_WAKE_MS)?
        .or(parse_u32_arg(request, "ms", DEFAULT_WAKE_MS)?)
        .unwrap_or(DEFAULT_WAKE_MS)
        .max(1);
    let wifi = request
        .arg("wifi")
        .map(parse_bool)
        .transpose()?
        .unwrap_or(true);
    let ble = request
        .arg("ble")
        .map(parse_bool)
        .transpose()?
        .unwrap_or(true);
    let ble_scan = request
        .arg("ble_scan")
        .map(parse_bool)
        .transpose()?
        .unwrap_or(false);
    let raw = request
        .arg("raw")
        .map(parse_bool)
        .transpose()?
        .unwrap_or(true);
    let nan = request
        .arg("nan")
        .map(parse_bool)
        .transpose()?
        .unwrap_or(false);
    let serial = request
        .arg("serial")
        .map(parse_bool)
        .transpose()?
        .unwrap_or(true);
    let radio_wake = request
        .arg("radio_wake")
        .or_else(|| request.arg("wifi_wake"))
        .map(parse_bool)
        .transpose()?
        .unwrap_or(false);
    let ps = request.arg("ps").unwrap_or("min");
    let ps_code = parse_ps(ps)?;

    telemetry::record_log(format!(
        "event type=sleep.light phase=radio wifi={} raw={} ble={} ble_scan={} serial={} radio_wake={} wake_ms={} ps={} ch={}",
        wifi, raw, ble, ble_scan, serial, radio_wake, wake_ms, ps, channel
    ));
    if ble {
        if ble_scan {
            super::ble_bt::start_listen_mode()?;
        } else {
            super::ble_bt::start_connectable_advertising()?;
        }
        if let Err(err) = super::ble_bt::enable_controller_sleep() {
            telemetry::record_log(format!(
                "ev=sleep.err mode=light target=ble_sleep err={}",
                crate::commands::protocol::escape_value(&err.to_string())
            ));
        }
    } else {
        super::ble_bt::stop_radio_activity();
    }
    if wifi || raw {
        if raw {
            super::wifi::start_raw_monitor_mode(channel, "dmesh")?;
        } else {
            super::wifi::ensure_raw_wifi_started(channel)?;
        }
        super::wifi::set_power_save(ps)?;
    } else if !nan {
        let _ = super::wifi::stop_raw_monitor();
    }
    if nan {
        super::wifi::stop_raw_monitor().ok();
        super::nan::start_raw_window(channel, "dmesh")?;
        super::wifi::set_power_save(ps)?;
    }
    telemetry::record_log("event type=sleep.light phase=pm");
    configure_pm(true)?;
    telemetry::record_log("event type=sleep.light phase=wake_sources");
    configure_light_test_wake_sources(
        settings,
        wake_ms,
        serial,
        radio_wake && wifi,
        radio_wake && ble,
    )?;

    LIGHT_SLEEP_ENABLED.store(true, Ordering::Relaxed);
    LIGHT_WIFI.store(wifi, Ordering::Relaxed);
    LIGHT_BLE.store(ble, Ordering::Relaxed);
    LIGHT_BLE_SCAN.store(ble_scan, Ordering::Relaxed);
    LIGHT_RAW.store(raw, Ordering::Relaxed);
    LIGHT_NAN.store(nan, Ordering::Relaxed);
    LIGHT_SERIAL.store(serial, Ordering::Relaxed);
    LIGHT_CHANNEL.store(channel, Ordering::Relaxed);
    LIGHT_WAKE_MS.store(wake_ms, Ordering::Relaxed);
    LIGHT_PS.store(ps_code, Ordering::Relaxed);
    telemetry::record_log(format!(
        "ev=sleep.light on=true wifi={} ble={} ble_scan={} raw={} nan={} ps={} ch={} wake_ms={} serial={}",
        wifi, ble, ble_scan, raw, nan, ps, channel, wake_ms, serial
    ));
    Ok(())
}

fn run_light_sleep_test(
    settings: &SharedSettings,
    request: &CommandRequest,
    test: &str,
) -> Result<String> {
    let channel = request
        .arg("channel")
        .map(|value| {
            value
                .parse::<u8>()
                .map_err(|err| anyhow!("invalid channel={value}: {err}"))
        })
        .transpose()?
        .unwrap_or(6)
        .clamp(1, 13);
    let wake_ms = parse_u32_arg(request, "wake_ms", 5_000)?
        .or(parse_u32_arg(request, "ms", 5_000)?)
        .unwrap_or(5_000)
        .max(1);
    let ps = request.arg("ps").unwrap_or("max");
    let restore = request
        .arg("restore")
        .map(parse_bool)
        .transpose()?
        .unwrap_or(true);
    let serial = request
        .arg("serial")
        .map(parse_bool)
        .transpose()?
        .unwrap_or(false);
    let radio_wake = request
        .arg("radio_wake")
        .or_else(|| request.arg("wifi_wake"))
        .map(parse_bool)
        .transpose()?
        .unwrap_or(true);

    telemetry::record_log(format!(
        "event type=sleep.light_test phase=prepare test={} wake_ms={} channel={} ps={} restore={} serial={} radio_wake={}",
        test, wake_ms, channel, ps, restore, serial, radio_wake
    ));
    LIGHT_TEST_RUNS.fetch_add(1, Ordering::Relaxed);
    LIGHT_TEST_LAST_PHASE.store(light_test_phase_code("prepare"), Ordering::Relaxed);
    LIGHT_TEST_LAST_ERR.store(0, Ordering::Relaxed);
    if let Err(err) = prepare_light_sleep_test_radio(settings, request, test, channel, ps) {
        LIGHT_TEST_PREPARE_FAIL.fetch_add(1, Ordering::Relaxed);
        LIGHT_TEST_LAST_ERR.store(0xffff_ffff, Ordering::Relaxed);
        telemetry::record_log(format!(
            "event type=sleep.light_test phase=prepare ok=false test={} err={}",
            test,
            crate::commands::protocol::escape_value(&err.to_string())
        ));
        return Err(err);
    }
    LIGHT_TEST_PREPARE_OK.fetch_add(1, Ordering::Relaxed);
    LIGHT_TEST_LAST_PHASE.store(light_test_phase_code("pm"), Ordering::Relaxed);
    if let Err(err) = configure_pm(true) {
        LIGHT_TEST_PREPARE_FAIL.fetch_add(1, Ordering::Relaxed);
        LIGHT_TEST_LAST_ERR.store(0xffff_fffe, Ordering::Relaxed);
        telemetry::record_log(format!(
            "event type=sleep.light_test phase=pm ok=false test={} err={}",
            test,
            crate::commands::protocol::escape_value(&err.to_string())
        ));
        return Err(err);
    }
    LIGHT_TEST_LAST_PHASE.store(light_test_phase_code("wake_sources"), Ordering::Relaxed);
    configure_light_test_wake_sources(
        settings,
        wake_ms,
        serial,
        radio_wake && light_test_uses_wifi(test),
        radio_wake && light_test_uses_ble(test),
    )?;

    LIGHT_SLEEP_ENABLED.store(true, Ordering::Relaxed);
    LIGHT_WAKE_MS.store(wake_ms, Ordering::Relaxed);
    LIGHT_CHANNEL.store(channel, Ordering::Relaxed);
    LIGHT_PS.store(parse_ps(ps)?, Ordering::Relaxed);

    LIGHT_TEST_LAST_PHASE.store(light_test_phase_code("sleep"), Ordering::Relaxed);
    let before_us = now_us();
    let ret = unsafe { sys::esp_light_sleep_start() };
    let after_us = now_us();
    let elapsed_ms = after_us.saturating_sub(before_us).saturating_div(1000);
    let cause = unsafe { sys::esp_sleep_get_wakeup_cause() };
    let causes = unsafe { sys::esp_sleep_get_wakeup_causes() };
    LIGHT_TEST_LAST_ELAPSED_MS.store(elapsed_ms.min(u32::MAX as u64) as u32, Ordering::Relaxed);
    LIGHT_TEST_LAST_CAUSE.store(cause as u32, Ordering::Relaxed);
    LIGHT_TEST_LAST_CAUSES.store(causes, Ordering::Relaxed);
    LIGHT_TEST_LAST_RET.store(ret as u32, Ordering::Relaxed);
    LIGHT_TEST_LAST_PHASE.store(light_test_phase_code("wake"), Ordering::Relaxed);

    let ok = ret == sys::ESP_OK;
    if ok {
        LIGHT_TEST_WAKE_OK.fetch_add(1, Ordering::Relaxed);
    } else {
        LIGHT_TEST_WAKE_FAIL.fetch_add(1, Ordering::Relaxed);
        LIGHT_TEST_LAST_ERR.store(ret as u32, Ordering::Relaxed);
    }
    telemetry::record_log(format!(
        "event type=sleep.light_test phase=wake test={} ok={} ret=0x{:x} elapsed_ms={} cause={} causes=0x{:x}",
        test,
        ok,
        ret,
        elapsed_ms,
        wake_cause_name(cause),
        causes
    ));

    if restore {
        let _ = super::ble_bt::disable_controller_sleep();
        super::ble_bt::stop_radio_activity();
        LIGHT_TEST_LAST_PHASE.store(light_test_phase_code("restore"), Ordering::Relaxed);
        if let Err(err) = super::mode::set_infra(settings, false, "light_sleep_test_restore") {
            LIGHT_TEST_RESTORE_FAIL.fetch_add(1, Ordering::Relaxed);
            LIGHT_TEST_LAST_ERR.store(0xffff_fffd, Ordering::Relaxed);
            return Err(err);
        }
        LIGHT_TEST_RESTORE_OK.fetch_add(1, Ordering::Relaxed);
    }

    if !ok {
        esp_ok(ret)?;
    }
    LIGHT_TEST_LAST_PHASE.store(light_test_phase_code("done"), Ordering::Relaxed);
    Ok(format!(
        "sleep light_test test={} ok=true elapsed_ms={} requested_ms={} cause={} causes=0x{:x} restored={} {}",
        test,
        elapsed_ms,
        wake_ms,
        wake_cause_name(cause),
        causes,
        restore,
        status_text()
    ))
}

fn prepare_light_sleep_test_radio(
    settings: &SharedSettings,
    request: &CommandRequest,
    test: &str,
    channel: u8,
    ps: &str,
) -> Result<()> {
    let _ = super::lora::sleep_radio(settings);
    match test {
        "ble" | "ble_adv" | "ble_advertise" => {
            let _ = super::wifi::stop_raw_monitor();
            super::ble_bt::set_advertising_interval_ms(1000, 1200);
            super::ble_bt::start_connectable_advertising()?;
            if let Err(err) = super::ble_bt::enable_controller_sleep() {
                telemetry::record_log(format!(
                    "ev=sleep.err mode=light_test target=ble_sleep err={}",
                    crate::commands::protocol::escape_value(&err.to_string())
                ));
            }
            LIGHT_BLE.store(true, Ordering::Relaxed);
            LIGHT_BLE_SCAN.store(false, Ordering::Relaxed);
            LIGHT_WIFI.store(false, Ordering::Relaxed);
            LIGHT_RAW.store(false, Ordering::Relaxed);
        }
        "raw" | "mgmt" | "prom" | "prom_mgmt" => {
            super::ble_bt::stop_radio_activity();
            super::wifi::start_light_sleep_test_mode("raw", channel)?;
            super::wifi::set_power_save(ps)?;
            LIGHT_BLE.store(false, Ordering::Relaxed);
            LIGHT_BLE_SCAN.store(false, Ordering::Relaxed);
            LIGHT_WIFI.store(true, Ordering::Relaxed);
            LIGHT_RAW.store(true, Ordering::Relaxed);
        }
        "raw_data" | "data" | "prom_data" => {
            super::ble_bt::stop_radio_activity();
            super::wifi::start_light_sleep_test_mode("raw_data", channel)?;
            super::wifi::set_power_save(ps)?;
            LIGHT_BLE.store(false, Ordering::Relaxed);
            LIGHT_BLE_SCAN.store(false, Ordering::Relaxed);
            LIGHT_WIFI.store(true, Ordering::Relaxed);
            LIGHT_RAW.store(true, Ordering::Relaxed);
        }
        "sta" | "unconnected_sta" | "idle_sta" => {
            super::ble_bt::stop_radio_activity();
            super::wifi::start_light_sleep_test_mode("sta", channel)?;
            super::wifi::set_power_save(ps)?;
            LIGHT_BLE.store(false, Ordering::Relaxed);
            LIGHT_BLE_SCAN.store(false, Ordering::Relaxed);
            LIGHT_WIFI.store(true, Ordering::Relaxed);
            LIGHT_RAW.store(false, Ordering::Relaxed);
        }
        "ap" | "softap" | "open_ap" => {
            super::ble_bt::stop_radio_activity();
            let beacon_ms = parse_u32_arg(request, "beacon_ms", 2_000)?.unwrap_or(2_000);
            super::wifi::start_light_sleep_test_ap(channel, beacon_ms)?;
            super::wifi::set_power_save(ps)?;
            LIGHT_BLE.store(false, Ordering::Relaxed);
            LIGHT_BLE_SCAN.store(false, Ordering::Relaxed);
            LIGHT_WIFI.store(true, Ordering::Relaxed);
            LIGHT_RAW.store(false, Ordering::Relaxed);
        }
        _ => bail!("unsupported light sleep test={test}"),
    }
    LIGHT_NAN.store(false, Ordering::Relaxed);
    LIGHT_SERIAL.store(false, Ordering::Relaxed);
    Ok(())
}

fn light_test_phase_code(phase: &str) -> u8 {
    match phase {
        "prepare" => 1,
        "pm" => 2,
        "wake_sources" => 3,
        "sleep" => 4,
        "wake" => 5,
        "restore" => 6,
        "done" => 7,
        _ => 0,
    }
}

fn light_test_phase_name(code: u8) -> &'static str {
    match code {
        1 => "prepare",
        2 => "pm",
        3 => "wake_sources",
        4 => "sleep",
        5 => "wake",
        6 => "restore",
        7 => "done",
        _ => "none",
    }
}

fn light_test_uses_ble(test: &str) -> bool {
    matches!(test, "ble" | "ble_adv" | "ble_advertise")
}

fn light_test_uses_wifi(test: &str) -> bool {
    matches!(
        test,
        "raw"
            | "mgmt"
            | "prom"
            | "prom_mgmt"
            | "raw_data"
            | "data"
            | "prom_data"
            | "sta"
            | "unconnected_sta"
            | "idle_sta"
            | "ap"
            | "softap"
            | "open_ap"
    )
}

fn configure_light_test_wake_sources(
    settings: &SharedSettings,
    wake_ms: u32,
    serial: bool,
    wifi: bool,
    ble: bool,
) -> Result<()> {
    unsafe {
        let _ = sys::esp_sleep_disable_wakeup_source(sys::esp_sleep_source_t_ESP_SLEEP_WAKEUP_ALL);
        if wake_ms > 0 {
            esp_ok(sys::esp_sleep_enable_timer_wakeup(wake_ms as u64 * 1000))?;
        }
        if serial {
            esp_ok_allow_invalid_state(sys::uart_set_wakeup_threshold(
                sys::uart_port_t_UART_NUM_0,
                3,
            ))?;
            esp_ok_allow_invalid_state(sys::esp_sleep_enable_uart_wakeup(
                sys::uart_port_t_UART_NUM_0 as i32,
            ))?;
        }
        if wifi {
            log_optional_wake_source("wifi", sys::esp_sleep_enable_wifi_wakeup())?;
            log_optional_wake_source("wifi_beacon", sys::esp_sleep_enable_wifi_beacon_wakeup())?;
        }
        if ble {
            log_optional_wake_source("bt", sys::esp_sleep_enable_bt_wakeup())?;
        }
    }
    if let Ok(Some(pin)) = super::button::configure_light_wake(settings) {
        telemetry::record_log(format!(
            "ev=sleep.light_test_wake source=button gpio={}",
            pin
        ));
    }
    Ok(())
}

fn log_optional_wake_source(source: &str, ret: sys::esp_err_t) -> Result<()> {
    if ret == sys::ESP_OK {
        increment_light_test_wake_source(source, true);
        telemetry::record_log(format!(
            "ev=sleep.light_test_wake source={} status=enabled",
            source
        ));
        return Ok(());
    }
    if ret == sys::ESP_ERR_INVALID_STATE
        || ret == sys::ESP_ERR_NOT_SUPPORTED
        || ret == sys::ESP_ERR_NOT_ALLOWED
    {
        increment_light_test_wake_source(source, false);
        telemetry::record_log(format!(
            "ev=sleep.light_test_wake source={} status=unsupported err=0x{:x}",
            source, ret
        ));
        return Ok(());
    }
    esp_ok(ret)
}

fn increment_light_test_wake_source(source: &str, ok: bool) {
    match (source, ok) {
        ("wifi", true) => {
            LIGHT_TEST_WIFI_WAKE_OK.fetch_add(1, Ordering::Relaxed);
        }
        ("wifi", false) => {
            LIGHT_TEST_WIFI_WAKE_UNSUPPORTED.fetch_add(1, Ordering::Relaxed);
        }
        ("wifi_beacon", true) => {
            LIGHT_TEST_WIFI_BEACON_WAKE_OK.fetch_add(1, Ordering::Relaxed);
        }
        ("wifi_beacon", false) => {
            LIGHT_TEST_WIFI_BEACON_WAKE_UNSUPPORTED.fetch_add(1, Ordering::Relaxed);
        }
        ("bt", true) => {
            LIGHT_TEST_BT_WAKE_OK.fetch_add(1, Ordering::Relaxed);
        }
        ("bt", false) => {
            LIGHT_TEST_BT_WAKE_UNSUPPORTED.fetch_add(1, Ordering::Relaxed);
        }
        _ => {}
    }
}

fn stop_light_sleep() -> Result<()> {
    super::power::configure_for_light_sleep(false)?;
    unsafe {
        let _ = sys::esp_sleep_disable_wakeup_source(sys::esp_sleep_source_t_ESP_SLEEP_WAKEUP_ALL);
        let _ = sys::esp_wifi_set_ps(sys::wifi_ps_type_t_WIFI_PS_NONE);
    }
    let _ = super::ble_bt::disable_controller_sleep();
    LIGHT_SLEEP_ENABLED.store(false, Ordering::Relaxed);
    LIGHT_WIFI.store(false, Ordering::Relaxed);
    LIGHT_BLE.store(false, Ordering::Relaxed);
    LIGHT_BLE_SCAN.store(false, Ordering::Relaxed);
    LIGHT_RAW.store(false, Ordering::Relaxed);
    LIGHT_NAN.store(false, Ordering::Relaxed);
    LIGHT_SERIAL.store(false, Ordering::Relaxed);
    LIGHT_WAKE_MS.store(0, Ordering::Relaxed);
    telemetry::record_log("ev=sleep.light on=false");
    Ok(())
}

fn configure_pm(light_sleep_enable: bool) -> Result<()> {
    super::power::configure_for_light_sleep(light_sleep_enable)
}

fn configure_light_wake_sources(
    settings: &SharedSettings,
    wake_ms: u32,
    serial: bool,
    radio_wake: bool,
    button_wake: bool,
) -> Result<()> {
    unsafe {
        let _ = sys::esp_sleep_disable_wakeup_source(sys::esp_sleep_source_t_ESP_SLEEP_WAKEUP_ALL);
        if wake_ms > 0 {
            esp_ok(sys::esp_sleep_enable_timer_wakeup(wake_ms as u64 * 1000))?;
        }
        if serial {
            esp_ok_allow_invalid_state(sys::uart_set_wakeup_threshold(
                sys::uart_port_t_UART_NUM_0,
                3,
            ))?;
            esp_ok_allow_invalid_state(sys::esp_sleep_enable_uart_wakeup(
                sys::uart_port_t_UART_NUM_0 as i32,
            ))?;
        }
        if radio_wake {
            let _ = sys::esp_sleep_enable_wifi_wakeup();
            let _ = sys::esp_sleep_enable_wifi_beacon_wakeup();
            let _ = sys::esp_sleep_enable_bt_wakeup();
        }
    }

    let mut button_gpio = None;
    if button_wake {
        if let Ok(Some(pin)) = super::button::configure_light_wake(settings) {
            button_gpio = Some(pin);
        }
    }

    if lora::background_rx_running() {
        let config = lora::load_config(settings)?;
        if config.dio0 >= 0 {
            unsafe {
                let ret = sys::gpio_wakeup_enable(
                    config.dio0 as sys::gpio_num_t,
                    sys::gpio_int_type_t_GPIO_INTR_HIGH_LEVEL,
                );
                if ret == sys::ESP_OK {
                    esp_ok(sys::esp_sleep_enable_gpio_wakeup())?;
                } else {
                    telemetry::record_log(format!(
                        "ev=sleep.err mode=light target=lora_gpio gpio={} err=0x{:x}",
                        config.dio0, ret
                    ));
                }
            }
        }
    }
    if let Some(pin) = button_gpio {
        telemetry::record_log(format!("ev=sleep.light_wake source=button gpio={}", pin));
    }
    Ok(())
}

fn status_text() -> String {
    let state = read_state();
    let valid = valid_state(&state);
    let cause = unsafe { sys::esp_sleep_get_wakeup_cause() };
    let ext1_mask = unsafe { sys::esp_sleep_get_ext1_wakeup_status() };
    let mut pm = sys::esp_pm_config_t::default();
    let pm_ok =
        unsafe { sys::esp_pm_get_configuration((&mut pm as *mut sys::esp_pm_config_t).cast()) }
            == sys::ESP_OK;
    format!(
        "sleep rtc_valid={} cause={} rtc_cause={} ext1_mask=0x{:x} rtc_ext1_mask=0x{:x} rtc_bytes={} flags=0x{:x} wake_ms={} forward_ms={} boot_count={} wake_count={} last_len={} last_hash=0x{:08x} rtc_ch={} light={} pm={} max={} min={} wifi={} ble={} ble_scan={} raw={} nan={} serial={} ch={} ps={} wifi_ps={} light_wake_ms={} light_tests={} light_prepare_ok={} light_prepare_fail={} light_wake_ok={} light_wake_fail={} light_restore_ok={} light_restore_fail={} light_wifi_wake_ok={} light_wifi_wake_unsupported={} light_wifi_beacon_wake_ok={} light_wifi_beacon_wake_unsupported={} light_bt_wake_ok={} light_bt_wake_unsupported={} light_last_ms={} light_last_ret=0x{:x} light_last_phase={} light_last_err=0x{:x} light_last_cause={} light_last_causes=0x{:x} raw_nan_light_runs={} raw_nan_light_ok={} raw_nan_light_fail={} raw_nan_light_last_ms={} raw_nan_light_cause={} raw_nan_light_ret=0x{:x}",
        valid,
        wake_cause_name(cause),
        if valid {
            wake_cause_name(state.last_cause as sys::esp_sleep_wakeup_cause_t)
        } else {
            "undefined"
        },
        ext1_mask,
        if valid { state.last_ext1_mask } else { 0 },
        size_of::<RtcSleepState>(),
        if valid { state.flags } else { 0 },
        if valid { state.wake_ms } else { 0 },
        if valid { state.forward_ms } else { 0 },
        if valid { state.boot_count } else { 0 },
        if valid { state.wake_count } else { 0 },
        if valid { state.last_packet_len } else { 0 },
        if valid { state.last_packet_hash } else { 0 },
        if valid { state.wifi_channel } else { 0 },
        LIGHT_SLEEP_ENABLED.load(Ordering::Relaxed),
        pm_ok && pm.light_sleep_enable,
        if pm_ok { pm.max_freq_mhz } else { 0 },
        if pm_ok { pm.min_freq_mhz } else { 0 },
        LIGHT_WIFI.load(Ordering::Relaxed),
        LIGHT_BLE.load(Ordering::Relaxed),
        LIGHT_BLE_SCAN.load(Ordering::Relaxed),
        LIGHT_RAW.load(Ordering::Relaxed),
        LIGHT_NAN.load(Ordering::Relaxed),
        LIGHT_SERIAL.load(Ordering::Relaxed),
        LIGHT_CHANNEL.load(Ordering::Relaxed),
        ps_name(LIGHT_PS.load(Ordering::Relaxed)),
        super::wifi::power_save_name(),
        LIGHT_WAKE_MS.load(Ordering::Relaxed),
        LIGHT_TEST_RUNS.load(Ordering::Relaxed),
        LIGHT_TEST_PREPARE_OK.load(Ordering::Relaxed),
        LIGHT_TEST_PREPARE_FAIL.load(Ordering::Relaxed),
        LIGHT_TEST_WAKE_OK.load(Ordering::Relaxed),
        LIGHT_TEST_WAKE_FAIL.load(Ordering::Relaxed),
        LIGHT_TEST_RESTORE_OK.load(Ordering::Relaxed),
        LIGHT_TEST_RESTORE_FAIL.load(Ordering::Relaxed),
        LIGHT_TEST_WIFI_WAKE_OK.load(Ordering::Relaxed),
        LIGHT_TEST_WIFI_WAKE_UNSUPPORTED.load(Ordering::Relaxed),
        LIGHT_TEST_WIFI_BEACON_WAKE_OK.load(Ordering::Relaxed),
        LIGHT_TEST_WIFI_BEACON_WAKE_UNSUPPORTED.load(Ordering::Relaxed),
        LIGHT_TEST_BT_WAKE_OK.load(Ordering::Relaxed),
        LIGHT_TEST_BT_WAKE_UNSUPPORTED.load(Ordering::Relaxed),
        LIGHT_TEST_LAST_ELAPSED_MS.load(Ordering::Relaxed),
        LIGHT_TEST_LAST_RET.load(Ordering::Relaxed),
        light_test_phase_name(LIGHT_TEST_LAST_PHASE.load(Ordering::Relaxed)),
        LIGHT_TEST_LAST_ERR.load(Ordering::Relaxed),
        wake_cause_name(LIGHT_TEST_LAST_CAUSE.load(Ordering::Relaxed) as sys::esp_sleep_source_t),
        LIGHT_TEST_LAST_CAUSES.load(Ordering::Relaxed),
        RAW_NAN_LIGHT_RUNS.load(Ordering::Relaxed),
        RAW_NAN_LIGHT_WAKE_OK.load(Ordering::Relaxed),
        RAW_NAN_LIGHT_WAKE_FAIL.load(Ordering::Relaxed),
        RAW_NAN_LIGHT_LAST_MS.load(Ordering::Relaxed),
        wake_cause_name(RAW_NAN_LIGHT_LAST_CAUSE.load(Ordering::Relaxed) as sys::esp_sleep_source_t),
        RAW_NAN_LIGHT_LAST_RET.load(Ordering::Relaxed)
    )
}

pub fn status_summary_fields() -> String {
    let mut pm = sys::esp_pm_config_t::default();
    let pm_ok =
        unsafe { sys::esp_pm_get_configuration((&mut pm as *mut sys::esp_pm_config_t).cast()) }
            == sys::ESP_OK;
    format!(
        "sleep_light={} sleep_pm={} sleep_max={} sleep_min={} sleep_wifi={} sleep_ble={} sleep_raw={} sleep_nan={} sleep_serial={} sleep_wake_ms={} sleep_tests={} sleep_wake_ok={} sleep_wake_fail={} sleep_last_ms={} sleep_last_cause={} raw_nan_light_runs={} raw_nan_light_ok={} raw_nan_light_fail={} raw_nan_light_last_ms={} raw_nan_light_cause={}",
        LIGHT_SLEEP_ENABLED.load(Ordering::Relaxed),
        pm_ok && pm.light_sleep_enable,
        if pm_ok { pm.max_freq_mhz } else { 0 },
        if pm_ok { pm.min_freq_mhz } else { 0 },
        LIGHT_WIFI.load(Ordering::Relaxed),
        LIGHT_BLE.load(Ordering::Relaxed),
        LIGHT_RAW.load(Ordering::Relaxed),
        LIGHT_NAN.load(Ordering::Relaxed),
        LIGHT_SERIAL.load(Ordering::Relaxed),
        LIGHT_WAKE_MS.load(Ordering::Relaxed),
        LIGHT_TEST_RUNS.load(Ordering::Relaxed),
        LIGHT_TEST_WAKE_OK.load(Ordering::Relaxed),
        LIGHT_TEST_WAKE_FAIL.load(Ordering::Relaxed),
        LIGHT_TEST_LAST_ELAPSED_MS.load(Ordering::Relaxed),
        wake_cause_name(
            LIGHT_TEST_LAST_CAUSE.load(Ordering::Relaxed) as sys::esp_sleep_wakeup_cause_t
        ),
        RAW_NAN_LIGHT_RUNS.load(Ordering::Relaxed),
        RAW_NAN_LIGHT_WAKE_OK.load(Ordering::Relaxed),
        RAW_NAN_LIGHT_WAKE_FAIL.load(Ordering::Relaxed),
        RAW_NAN_LIGHT_LAST_MS.load(Ordering::Relaxed),
        wake_cause_name(
            RAW_NAN_LIGHT_LAST_CAUSE.load(Ordering::Relaxed) as sys::esp_sleep_wakeup_cause_t
        )
    )
}

fn enter_deep_sleep_with_state(state: RtcSleepState) -> Result<()> {
    let config = state.lora.to_config();
    if state.flags & FLAG_LORA != 0 {
        lora::prepare_deep_sleep_rx(&config)?;
    }
    configure_wake_sources(&state)?;
    telemetry::record_log(format!(
        "event type=sleep.enter mode=deep wake_ms={} active_ms={} flags=0x{:x} dio0={}",
        state.wake_ms, state.forward_ms, state.flags, state.lora.dio0
    ));
    unsafe {
        sys::esp_deep_sleep_start();
    }
}

fn configure_wake_sources(state: &RtcSleepState) -> Result<()> {
    unsafe {
        let _ = sys::esp_sleep_disable_wakeup_source(sys::esp_sleep_source_t_ESP_SLEEP_WAKEUP_ALL);
        if state.wake_ms > 0 {
            esp_ok(sys::esp_sleep_enable_timer_wakeup(
                state.wake_ms as u64 * 1000,
            ))?;
        }
        if let Some(pin) = super::button::configured_gpio() {
            if sys::rtc_gpio_is_valid_gpio(pin) {
                esp_ok(sys::esp_sleep_enable_ext0_wakeup(pin as sys::gpio_num_t, 0))?;
            } else {
                telemetry::record_log(format!(
                    "event type=sleep.wake_source source=button gpio={} status=invalid_rtc",
                    pin
                ));
            }
        }
        esp_ok(sys::esp_sleep_pd_config(
            sys::esp_sleep_pd_domain_t_ESP_PD_DOMAIN_RTC_PERIPH,
            sys::esp_sleep_pd_option_t_ESP_PD_OPTION_ON,
        ))?;
        if state.flags & FLAG_LORA != 0 {
            if !sys::rtc_gpio_is_valid_gpio(state.lora.dio0) {
                bail!("lora.dio0={} is not RTC-capable", state.lora.dio0);
            }
            esp_ok(sys::esp_sleep_enable_ext1_wakeup(
                1_u64 << state.lora.dio0,
                sys::esp_sleep_ext1_wakeup_mode_t_ESP_EXT1_WAKEUP_ANY_HIGH,
            ))?;
        }
        let _ = sys::rtc_gpio_isolate(sys::gpio_num_t_GPIO_NUM_12);
    }
    Ok(())
}

fn forward_packet(state: &RtcSleepState, packet: &[u8], metrics: Option<(i32, f32)>) {
    let start = Instant::now();
    let ble_sent = if state.flags & FLAG_BLE != 0 {
        match metrics {
            Some((rssi, snr)) => super::ble_bt::announce_lora_packet(packet, rssi, snr).is_ok(),
            None => super::ble_bt::forward_packet_for_window(packet, 0).unwrap_or(false),
        }
    } else {
        false
    };
    let wifi_sent = if state.flags & FLAG_WIFI != 0 {
        super::wifi::forward_management_packet(packet).is_ok()
    } else {
        false
    };
    if state.flags & FLAG_SERIAL != 0 {
        telemetry::record_log(format!(
            "event type=sleep.forward ble_sent={} wifi_sent={} elapsed_ms={}",
            ble_sent,
            wifi_sent,
            start.elapsed().as_millis()
        ));
    }
    let elapsed = start.elapsed();
    let target = Duration::from_millis(state.forward_ms as u64);
    if elapsed < target {
        task_delay(target - elapsed);
    }
}

fn active_window(state: &RtcSleepState) -> Result<bool> {
    let deadline = Instant::now() + Duration::from_millis(state.forward_ms as u64);
    if state.flags & FLAG_NAN_RAW != 0 {
        match super::nan::start_raw_window(state.wifi_channel.max(1), "sdf") {
            Ok(()) => telemetry::record_log(format!(
                "event type=sleep.active transport=nan_raw status=started channel={}",
                state.wifi_channel
            )),
            Err(err) => telemetry::record_log(format!(
                "event type=sleep.active transport=nan_raw status=error message={}",
                crate::commands::protocol::escape_value(&err.to_string())
            )),
        }
        let sync_us = super::nan::sync_to_next_discovery_window(350, 512, 0);
        telemetry::record_log(format!(
            "event type=sleep.active transport=nan_raw sync_us={}",
            sync_us
        ));
        super::test::poll_nan_active_window();
    }
    if state.flags & FLAG_BLE != 0 {
        let marker = state.wake_count.to_le_bytes();
        if let Err(err) =
            super::ble_bt::announce_packet(super::ble_bt::DmeshBleEvent::Generic, &marker, None)
        {
            telemetry::record_log(format!(
                "event type=sleep.active transport=ble status=error message={}",
                crate::commands::protocol::escape_value(&err.to_string())
            ));
        }
    }
    while Instant::now() < deadline {
        if state.flags & FLAG_SERIAL != 0 && super::serial::has_pending_frame() {
            telemetry::record_log("event type=sleep.active source=serial action=promote");
            if state.flags & FLAG_NAN_RAW != 0 {
                let _ = super::nan::stop_nan();
                let _ = super::wifi::stop_raw_monitor();
                telemetry::record_log("event type=sleep.active transport=nan_raw status=stopped");
            }
            return Ok(true);
        }
        task_delay(Duration::from_millis(50));
    }
    telemetry::record_log(format!(
        "event type=sleep.active source=timer action=sleep active_ms={}",
        state.forward_ms
    ));
    if state.flags & FLAG_NAN_RAW != 0 {
        let _ = super::nan::stop_nan();
        let _ = super::wifi::stop_raw_monitor();
        telemetry::record_log("event type=sleep.active transport=nan_raw status=stopped");
    }
    Ok(false)
}

fn now_us() -> u64 {
    unsafe { sys::esp_timer_get_time().max(0) as u64 }
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

fn new_state(
    config: LoraConfig,
    wake_ms: u32,
    forward_ms: u32,
    flags: u32,
    wifi_channel: u8,
) -> RtcSleepState {
    let old = read_state();
    let old_valid = valid_state(&old);
    let mut state = RtcSleepState {
        magic: RTC_MAGIC,
        version: RTC_VERSION,
        len: size_of::<RtcSleepState>() as u16,
        checksum: 0,
        flags,
        wake_ms,
        forward_ms,
        boot_count: if old_valid { old.boot_count } else { 0 },
        wake_count: if old_valid { old.wake_count } else { 0 },
        last_cause: if old_valid { old.last_cause } else { 0 },
        last_ext1_mask: if old_valid { old.last_ext1_mask } else { 0 },
        last_packet_len: if old_valid { old.last_packet_len } else { 0 },
        wifi_channel: wifi_channel.clamp(1, 13),
        _pad0: 0,
        last_packet_hash: if old_valid { old.last_packet_hash } else { 0 },
        lora: RtcLoraConfig::from_config(config),
    };
    state = update_checksum(state);
    state
}

impl RtcLoraConfig {
    fn from_config(config: LoraConfig) -> Self {
        Self {
            frequency_hz: config.frequency_hz,
            chip: match config.chip {
                LoraChip::Sx127x => 0,
                LoraChip::Sx1262 => 1,
            },
            bandwidth_hz: config.bandwidth_hz,
            spi_host: config.spi_host,
            sck: config.sck,
            miso: config.miso,
            mosi: config.mosi,
            cs: config.cs,
            rst: config.rst,
            dio0: config.dio0,
            busy: config.busy,
            board_power_pin: config.board_power_pin,
            board_power_level: config.board_power_level,
            sx1262_tcxo_mv: config.sx1262_tcxo_mv,
            sx1262_pa_duty: config.sx1262_pa_duty,
            sx1262_pa_hp: config.sx1262_pa_hp,
            sx1262_pa_device: config.sx1262_pa_device,
            sx1262_pa_lut: config.sx1262_pa_lut,
            sx1262_rx_timeout_ms: config.sx1262_rx_timeout_ms,
            sx1262_sync_word: config.sx1262_sync_word,
            sf: config.sf,
            cr: config.cr,
            sync_word: config.sync_word,
            crc: if config.crc { 1 } else { 0 },
            beacon: if config.beacon { 1 } else { 0 },
            sx1262_dio2_rf_switch: if config.sx1262_dio2_rf_switch { 1 } else { 0 },
            _pad0: 0,
            preamble: config.preamble,
            tx_power: config.tx_power,
        }
    }

    fn to_config(self) -> LoraConfig {
        LoraConfig {
            chip: if self.chip == 1 {
                LoraChip::Sx1262
            } else {
                LoraChip::Sx127x
            },
            frequency_hz: self.frequency_hz,
            bandwidth_hz: self.bandwidth_hz,
            beacon: self.beacon != 0,
            spi_host: self.spi_host,
            sck: self.sck,
            miso: self.miso,
            mosi: self.mosi,
            cs: self.cs,
            rst: self.rst,
            dio0: self.dio0,
            busy: self.busy,
            board_power_pin: self.board_power_pin,
            board_power_level: self.board_power_level,
            sx1262_dio2_rf_switch: self.sx1262_dio2_rf_switch != 0,
            sx1262_tcxo_mv: self.sx1262_tcxo_mv,
            sx1262_pa_duty: self.sx1262_pa_duty,
            sx1262_pa_hp: self.sx1262_pa_hp,
            sx1262_pa_device: self.sx1262_pa_device,
            sx1262_pa_lut: self.sx1262_pa_lut,
            sx1262_rx_timeout_ms: self.sx1262_rx_timeout_ms,
            sx1262_sync_word: self.sx1262_sync_word,
            sf: self.sf,
            cr: self.cr,
            sync_word: self.sync_word,
            crc: self.crc != 0,
            preamble: self.preamble,
            tx_power: self.tx_power,
        }
    }
}

fn read_state() -> RtcSleepState {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(RTC_SLEEP_STATE)) }
}

fn write_state(state: RtcSleepState) {
    unsafe {
        core::ptr::write_volatile(core::ptr::addr_of_mut!(RTC_SLEEP_STATE), state);
    }
}

fn valid_state(state: &RtcSleepState) -> bool {
    state.magic == RTC_MAGIC
        && state.version == RTC_VERSION
        && state.len as usize == size_of::<RtcSleepState>()
        && checksum_for_validation(state) == state.checksum
}

fn update_checksum(mut state: RtcSleepState) -> RtcSleepState {
    state.checksum = 0;
    state.checksum = checksum(&state);
    state
}

fn checksum(state: &RtcSleepState) -> u32 {
    let mut hash = 0x811c_9dc5_u32;
    hash = hash_u32(hash, state.magic);
    hash = hash_u16(hash, state.version);
    hash = hash_u16(hash, state.len);
    hash = hash_u32(hash, state.flags);
    hash = hash_u32(hash, state.wake_ms);
    hash = hash_u32(hash, state.forward_ms);
    hash = hash_u32(hash, state.boot_count);
    hash = hash_u32(hash, state.wake_count);
    hash = hash_u32(hash, state.last_cause);
    hash = hash_u64(hash, state.last_ext1_mask);
    hash = hash_u16(hash, state.last_packet_len);
    hash = hash_u8(hash, state.wifi_channel);
    hash = hash_u32(hash, state.last_packet_hash);

    let lora = &state.lora;
    hash = hash_i32(hash, lora.chip);
    hash = hash_u32(hash, lora.frequency_hz);
    hash = hash_u32(hash, lora.bandwidth_hz);
    hash = hash_i32(hash, lora.spi_host);
    hash = hash_i32(hash, lora.sck);
    hash = hash_i32(hash, lora.miso);
    hash = hash_i32(hash, lora.mosi);
    hash = hash_i32(hash, lora.cs);
    hash = hash_i32(hash, lora.rst);
    hash = hash_i32(hash, lora.dio0);
    hash = hash_i32(hash, lora.busy);
    hash = hash_i32(hash, lora.board_power_pin);
    hash = hash_i32(hash, lora.board_power_level);
    hash = hash_i32(hash, lora.sx1262_tcxo_mv);
    hash = hash_i32(hash, lora.sx1262_pa_duty);
    hash = hash_i32(hash, lora.sx1262_pa_hp);
    hash = hash_i32(hash, lora.sx1262_pa_device);
    hash = hash_i32(hash, lora.sx1262_pa_lut);
    hash = hash_i32(hash, lora.sx1262_rx_timeout_ms);
    hash = hash_i32(hash, lora.sx1262_sync_word);
    hash = hash_i32(hash, lora.sf);
    hash = hash_i32(hash, lora.cr);
    hash = hash_i32(hash, lora.sync_word);
    hash = hash_u8(hash, lora.crc);
    hash = hash_u8(hash, lora.beacon);
    hash = hash_u8(hash, lora.sx1262_dio2_rf_switch);
    hash = hash_i32(hash, lora.preamble);
    hash = hash_i32(hash, lora.tx_power);
    hash
}

fn checksum_for_validation(state: &RtcSleepState) -> u32 {
    checksum(state)
}

fn hash_u8(hash: u32, value: u8) -> u32 {
    hash_byte(hash, value)
}

fn hash_u16(mut hash: u32, value: u16) -> u32 {
    for byte in value.to_le_bytes() {
        hash = hash_byte(hash, byte);
    }
    hash
}

fn hash_u32(mut hash: u32, value: u32) -> u32 {
    for byte in value.to_le_bytes() {
        hash = hash_byte(hash, byte);
    }
    hash
}

fn hash_u64(mut hash: u32, value: u64) -> u32 {
    for byte in value.to_le_bytes() {
        hash = hash_byte(hash, byte);
    }
    hash
}

fn hash_i32(hash: u32, value: i32) -> u32 {
    hash_u32(hash, value as u32)
}

fn hash_byte(hash: u32, byte: u8) -> u32 {
    hash.wrapping_mul(16777619) ^ byte as u32
}

fn fnv1a32(bytes: &[u8]) -> u32 {
    bytes.iter().fold(0x811c_9dc5_u32, |acc, byte| {
        acc.wrapping_mul(16777619) ^ *byte as u32
    })
}

fn parse_u32_arg(request: &CommandRequest, key: &str, _default: u32) -> Result<Option<u32>> {
    request
        .arg(key)
        .map(|value| {
            value
                .parse::<u32>()
                .map_err(|err| anyhow!("invalid {key}={value}: {err}"))
        })
        .transpose()
}

fn parse_ps(value: &str) -> Result<u8> {
    match value {
        "none" | "off" => Ok(LIGHT_PS_NONE),
        "min" | "min_modem" => Ok(LIGHT_PS_MIN),
        "max" | "max_modem" => Ok(LIGHT_PS_MAX),
        _ => bail!("unsupported ps={value}"),
    }
}

fn ps_name(value: u8) -> &'static str {
    match value {
        LIGHT_PS_NONE => "none",
        LIGHT_PS_MIN => "min",
        LIGHT_PS_MAX => "max",
        _ => "unknown",
    }
}

fn wake_cause_name(cause: sys::esp_sleep_wakeup_cause_t) -> &'static str {
    match cause {
        x if x == sys::esp_sleep_source_t_ESP_SLEEP_WAKEUP_UNDEFINED => "undefined",
        x if x == sys::esp_sleep_source_t_ESP_SLEEP_WAKEUP_EXT0 => "ext0",
        x if x == sys::esp_sleep_source_t_ESP_SLEEP_WAKEUP_EXT1 => "ext1",
        x if x == sys::esp_sleep_source_t_ESP_SLEEP_WAKEUP_TIMER => "timer",
        x if x == sys::esp_sleep_source_t_ESP_SLEEP_WAKEUP_TOUCHPAD => "touchpad",
        x if x == sys::esp_sleep_source_t_ESP_SLEEP_WAKEUP_ULP => "ulp",
        x if x == sys::esp_sleep_source_t_ESP_SLEEP_WAKEUP_GPIO => "gpio",
        x if x == sys::esp_sleep_source_t_ESP_SLEEP_WAKEUP_UART => "uart",
        x if x == sys::esp_sleep_source_t_ESP_SLEEP_WAKEUP_WIFI => "wifi",
        _ => "other",
    }
}

fn esp_ok_allow_invalid_state(ret: sys::esp_err_t) -> Result<()> {
    if ret == sys::ESP_OK || ret == sys::ESP_ERR_INVALID_STATE {
        Ok(())
    } else {
        bail!("esp_err=0x{ret:x}")
    }
}

fn esp_ok(ret: sys::esp_err_t) -> Result<()> {
    if ret == sys::ESP_OK {
        Ok(())
    } else {
        bail!("esp_err=0x{ret:x}")
    }
}
