use std::time::Duration;

use anyhow::{anyhow, bail, Result};
use esp_idf_sys as sys;

use crate::commands::{CommandHandler, CommandRegistry, CommandRequest, CommandResponse};

use super::settings::{parse_bool, SharedSettings};

const DEFAULT_BATTERY_PIN: i32 = 35;
const DEFAULT_DIVIDER: f32 = 2.2;
const DEFAULT_REF_MV: u32 = 3300;
const DEFAULT_EMPTY_MV: u32 = 3300;
const DEFAULT_FULL_MV: u32 = 4200;
const UNKNOWN_LEVEL: u8 = 255;
const ADC_MAX_RAW: f32 = 4095.0;

pub fn register_commands(registry: &mut CommandRegistry, settings: SharedSettings) {
    registry.register(BatteryCommand {
        settings: settings.clone(),
    });
    registry.register(AdcProbeCommand { settings });
}

pub fn battery_level_default() -> u8 {
    read_battery_with_config(BatteryConfig::default())
        .map(|reading| reading.percent)
        .unwrap_or(UNKNOWN_LEVEL)
}

pub fn stats_fields(settings: &SharedSettings) -> String {
    match BatteryConfig::load(settings).and_then(read_battery_with_config) {
        Ok(reading) => format!(
            "battery_level={} battery_raw={} battery_adc_mv={} battery_mv={}",
            reading.percent, reading.raw, reading.adc_mv, reading.battery_mv
        ),
        Err(_) => "battery_level=255 battery_raw=-1 battery_adc_mv=0 battery_mv=0".to_string(),
    }
}

struct BatteryCommand {
    settings: SharedSettings,
}

struct AdcProbeCommand {
    settings: SharedSettings,
}

impl CommandHandler for BatteryCommand {
    fn name(&self) -> &'static str {
        "battery"
    }

    fn handle(&mut self, request: &CommandRequest) -> Result<CommandResponse> {
        if request
            .arg("save")
            .map(parse_bool)
            .transpose()?
            .unwrap_or(false)
        {
            let mut settings = self.settings.borrow_mut();
            if let Some(enabled) = request.arg("enabled").or_else(|| request.arg("enable")) {
                settings.set_bool("battery.enabled", parse_bool(enabled)?)?;
            }
            if let Some(pin) = request.arg_i32("pin")? {
                settings.set_i32("battery.pin", pin)?;
            }
            if let Some(divider) = request
                .arg("divider")
                .or_else(|| request.arg("mult"))
                .or_else(|| request.arg("multiplier"))
            {
                settings.set_str("battery.divider", divider)?;
            }
            if let Some(ctrl_pin) = request
                .arg_i32("ctrl_pin")?
                .or(request.arg_i32("ctrl")?)
                .or(request.arg_i32("enable_pin")?)
            {
                settings.set_i32("battery.ctrl", ctrl_pin)?;
            }
            if let Some(ctrl_level) = request
                .arg_i32("ctrl_level")?
                .or(request.arg_i32("enable_level")?)
            {
                settings.set_i32("battery.ctl_lvl", if ctrl_level == 0 { 0 } else { 1 })?;
            }
            if let Some(ref_mv) = request.arg_i32("ref_mv")? {
                settings.set_i32("battery.ref_mv", ref_mv)?;
            }
            if let Some(min_mv) = request.arg_i32("min_mv")? {
                settings.set_i32("battery.min_mv", min_mv)?;
            }
            if let Some(max_mv) = request.arg_i32("max_mv")? {
                settings.set_i32("battery.max_mv", max_mv)?;
            }
        }

        let config = BatteryConfig::load(&self.settings)?;
        if !config.enabled {
            return Ok(CommandResponse::ok(format!(
                "battery enabled=false pin={} level=255",
                config.pin
            )));
        }
        let reading = read_battery_with_config(config)?;
        Ok(CommandResponse::ok(format!(
            "battery enabled=true pin={} divider={} ctrl_pin={} ctrl_level={} ref_mv={} unit={} channel={} raw={} adc_mv={} mv={} level={}",
            config.pin,
            config.divider,
            config.ctrl_pin,
            config.ctrl_level,
            config.ref_mv,
            reading.unit + 1,
            reading.channel,
            reading.raw,
            reading.adc_mv,
            reading.battery_mv,
            reading.percent
        )))
    }
}

impl CommandHandler for AdcProbeCommand {
    fn name(&self) -> &'static str {
        "adcprobe"
    }

    fn handle(&mut self, request: &CommandRequest) -> Result<CommandResponse> {
        let pins = parse_pins(request.arg("pins").unwrap_or("34,35,36,39"))?;
        let interval_ms = request
            .arg_i32("interval_ms")?
            .or(request.arg_i32("ms")?)
            .unwrap_or(1000)
            .clamp(10, 60_000) as u64;
        let count = request
            .arg_i32("count")?
            .or(request.arg_i32("repeat")?)
            .unwrap_or(1)
            .max(0) as u32;
        let ref_mv = request
            .arg_i32("ref_mv")?
            .unwrap_or(
                self.settings
                    .borrow()
                    .get_i32("battery.ref_mv", DEFAULT_REF_MV as i32)?,
            )
            .clamp(1, 5000) as u32;

        if count == 0 {
            let mut sample = 0_u32;
            loop {
                sample = sample.saturating_add(1);
                let line = adc_sample_line(sample, &pins, ref_mv);
                super::telemetry::emit_console(&line);
                if wait_for_key_or_timeout(interval_ms) {
                    return Ok(CommandResponse::ok(format!(
                        "adcprobe stopped=true samples={sample}"
                    )));
                }
            }
        }

        let mut out = String::new();
        for sample in 1..=count {
            if sample > 1 {
                task_delay(Duration::from_millis(interval_ms));
            }
            out.push_str(&adc_sample_line(sample, &pins, ref_mv));
            if sample < count {
                out.push('\n');
            }
        }
        Ok(CommandResponse::ok(out))
    }
}

#[derive(Clone, Copy)]
struct BatteryConfig {
    enabled: bool,
    pin: i32,
    divider: f32,
    ctrl_pin: i32,
    ctrl_level: i32,
    ref_mv: u32,
    empty_mv: u32,
    full_mv: u32,
}

impl BatteryConfig {
    fn load(settings: &SharedSettings) -> Result<Self> {
        let settings = settings.borrow();
        let divider = settings
            .get_str("battery.divider")?
            .or(settings.get_str("battery.mult")?)
            .map(|value| parse_f32(&value))
            .transpose()?
            .unwrap_or(DEFAULT_DIVIDER);
        Ok(Self {
            enabled: settings.get_bool("battery.enabled", true)?,
            pin: settings.get_i32("battery.pin", DEFAULT_BATTERY_PIN)?,
            divider,
            ctrl_pin: settings.get_i32("battery.ctrl", -1)?,
            ctrl_level: settings.get_i32("battery.ctl_lvl", 1)?.clamp(0, 1),
            ref_mv: settings.get_i32("battery.ref_mv", DEFAULT_REF_MV as i32)? as u32,
            empty_mv: settings.get_i32("battery.min_mv", DEFAULT_EMPTY_MV as i32)? as u32,
            full_mv: settings.get_i32("battery.max_mv", DEFAULT_FULL_MV as i32)? as u32,
        })
    }
}

impl Default for BatteryConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            pin: DEFAULT_BATTERY_PIN,
            divider: DEFAULT_DIVIDER,
            ctrl_pin: -1,
            ctrl_level: 1,
            ref_mv: DEFAULT_REF_MV,
            empty_mv: DEFAULT_EMPTY_MV,
            full_mv: DEFAULT_FULL_MV,
        }
    }
}

pub struct BatteryReading {
    unit: sys::adc_unit_t,
    channel: sys::adc_channel_t,
    raw: i32,
    adc_mv: u32,
    battery_mv: u32,
    percent: u8,
}

fn read_battery_with_config(config: BatteryConfig) -> Result<BatteryReading> {
    if config.pin < 0 {
        bail!("battery pin disabled");
    }
    if config.full_mv <= config.empty_mv {
        bail!("battery max_mv must be greater than min_mv");
    }
    battery_adc_enable(config)?;
    let result = read_adc_pin(config.pin, config.ref_mv)
        .map_err(|err| anyhow!("battery ADC GPIO{}: {err}", config.pin));
    let _ = battery_adc_disable(config);
    let (unit, channel, raw, adc_mv) = result?;
    let battery_mv = (adc_mv as f32 * config.divider).round() as u32;
    let percent = battery_percent(battery_mv, config.empty_mv, config.full_mv);
    Ok(BatteryReading {
        unit,
        channel,
        raw,
        adc_mv,
        battery_mv,
        percent,
    })
}

fn battery_adc_enable(config: BatteryConfig) -> Result<()> {
    if config.ctrl_pin < 0 {
        return Ok(());
    }
    set_output_level(config.ctrl_pin, config.ctrl_level)?;
    task_delay(Duration::from_millis(10));
    Ok(())
}

fn battery_adc_disable(config: BatteryConfig) -> Result<()> {
    if config.ctrl_pin < 0 {
        return Ok(());
    }
    set_output_level(config.ctrl_pin, if config.ctrl_level == 0 { 1 } else { 0 })
}

fn set_output_level(pin: i32, level: i32) -> Result<()> {
    unsafe {
        let gpio = pin as sys::gpio_num_t;
        esp_ok(sys::gpio_reset_pin(gpio))?;
        esp_ok(sys::gpio_set_direction(
            gpio,
            sys::gpio_mode_t_GPIO_MODE_OUTPUT,
        ))?;
        esp_ok(sys::gpio_set_level(gpio, if level == 0 { 0 } else { 1 }))?;
    }
    Ok(())
}

fn read_adc_pin(pin: i32, ref_mv: u32) -> Result<(sys::adc_unit_t, sys::adc_channel_t, i32, u32)> {
    let mut unit = sys::adc_unit_t_ADC_UNIT_1;
    let mut channel = sys::adc_channel_t_ADC_CHANNEL_0;
    unsafe {
        esp_ok(sys::adc_oneshot_io_to_channel(pin, &mut unit, &mut channel))?;
    }
    if unit != sys::adc_unit_t_ADC_UNIT_1 {
        bail!("GPIO{pin} maps to ADC2; ADC2 conflicts with Wi-Fi on ESP32");
    }

    let mut handle = std::ptr::null_mut();
    unsafe {
        let init = sys::adc_oneshot_unit_init_cfg_t {
            unit_id: unit,
            clk_src: 0,
            ulp_mode: sys::adc_ulp_mode_t_ADC_ULP_MODE_DISABLE,
        };
        esp_ok(sys::adc_oneshot_new_unit(&init, &mut handle))?;
        let chan_config = sys::adc_oneshot_chan_cfg_t {
            atten: sys::adc_atten_t_ADC_ATTEN_DB_12,
            bitwidth: sys::adc_bitwidth_t_ADC_BITWIDTH_12,
        };
        let result: Result<i32> = (|| {
            esp_ok(sys::adc_oneshot_config_channel(
                handle,
                channel,
                &chan_config,
            ))?;
            let mut raw = 0;
            esp_ok(sys::adc_oneshot_read(handle, channel, &mut raw))?;
            Ok(raw)
        })();
        let _ = sys::adc_oneshot_del_unit(handle);
        let raw = result?;
        Ok((unit, channel, raw, raw_to_mv(raw, ref_mv)))
    }
}

fn adc_sample_line(sample: u32, pins: &[i32], ref_mv: u32) -> String {
    let mut out = format!("adcprobe sample={sample} ref_mv={ref_mv}");
    for pin in pins {
        match read_adc_pin(*pin, ref_mv) {
            Ok((unit, channel, raw, mv)) => {
                out.push_str(&format!(
                    " gpio{pin}_unit={} gpio{pin}_channel={} gpio{pin}_raw={raw} gpio{pin}_mv={mv}",
                    unit + 1,
                    channel
                ));
            }
            Err(err) => {
                out.push_str(&format!(
                    " gpio{pin}_error={}",
                    crate::commands::protocol::quote_text_value(&err.to_string())
                ));
            }
        }
    }
    out
}

fn raw_to_mv(raw: i32, ref_mv: u32) -> u32 {
    ((raw.max(0) as f32 / ADC_MAX_RAW) * ref_mv as f32).round() as u32
}

fn battery_percent(mv: u32, empty_mv: u32, full_mv: u32) -> u8 {
    if mv < empty_mv.saturating_sub(200) {
        return UNKNOWN_LEVEL;
    }
    let span = full_mv - empty_mv;
    let pct = mv.saturating_sub(empty_mv).saturating_mul(100) / span;
    pct.min(100) as u8
}

fn parse_f32(value: &str) -> Result<f32> {
    value
        .parse::<f32>()
        .map_err(|err| anyhow!("invalid float {value}: {err}"))
}

fn parse_pins(value: &str) -> Result<Vec<i32>> {
    let mut pins = Vec::new();
    for part in value.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let pin = part
            .parse::<i32>()
            .map_err(|err| anyhow!("invalid GPIO pin {part}: {err}"))?;
        pins.push(pin);
    }
    if pins.is_empty() {
        bail!("adcprobe requires at least one pin");
    }
    Ok(pins)
}

fn wait_for_key_or_timeout(interval_ms: u64) -> bool {
    let mut waited = 0_u64;
    while waited < interval_ms {
        if super::serial::has_pending_frame() {
            return true;
        }
        let step = (interval_ms - waited).min(50);
        task_delay(Duration::from_millis(step));
        waited += step;
    }
    false
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
