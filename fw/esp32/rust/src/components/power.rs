use std::sync::atomic::{AtomicU8, Ordering};

use anyhow::{anyhow, bail, Result};
use esp_idf_sys as sys;

use crate::commands::{CommandHandler, CommandRegistry, CommandRequest, CommandResponse};

use super::settings::{parse_bool, SharedSettings};

#[repr(C)]
#[derive(Default)]
struct SleepMetrics {
    attempts: u32,
    entries: u32,
    skipped: u32,
    expected_us: u64,
    slept_us: u64,
    max_us: u32,
    tracked_us: u64,
}

unsafe extern "C" {
    fn dmesh_pm_metrics_init() -> i32;
    fn dmesh_pm_metrics_reset();
    fn dmesh_pm_metrics_snapshot(out: *mut SleepMetrics);
    fn dmesh_pm_dump_locks(out: *mut u8, out_len: usize) -> i32;
}

const PROFILE_PERF: u8 = 0;
const PROFILE_DFS: u8 = 1;
const PROFILE_LOW: u8 = 2;
const PROFILE_AUTO: u8 = 3;

static ACTIVE_PROFILE: AtomicU8 = AtomicU8::new(PROFILE_DFS);

unsafe extern "C" {
    fn esp_clk_cpu_freq() -> u32;
    fn esp_clk_xtal_freq() -> u32;
}

pub fn register_commands(registry: &mut CommandRegistry, settings: SharedSettings) {
    registry.register(PowerCommand { settings });
}

pub fn apply_default(settings: &SharedSettings) -> Result<()> {
    let metrics_ret = unsafe { dmesh_pm_metrics_init() };
    if metrics_ret != sys::ESP_OK && metrics_ret != sys::ESP_ERR_NOT_SUPPORTED {
        return Err(anyhow!(
            "light-sleep metrics init failed err=0x{metrics_ret:x}"
        ));
    }
    let profile = settings
        .borrow()
        .get_str("power.profile")?
        .unwrap_or_else(|| "dfs".to_string());
    apply_profile(settings, PowerProfile::parse(&profile)?, false)
}

pub fn configure_for_light_sleep(light_sleep_enable: bool) -> Result<()> {
    if light_sleep_enable {
        configure_pm(default_max_mhz(), default_min_mhz(), true)?;
        ACTIVE_PROFILE.store(PROFILE_AUTO, Ordering::Relaxed);
    } else {
        configure_pm(default_max_mhz(), default_min_mhz(), false)?;
        ACTIVE_PROFILE.store(PROFILE_DFS, Ordering::Relaxed);
    }
    Ok(())
}

pub fn compact_status_fields() -> String {
    let mut pm = sys::esp_pm_config_t::default();
    let pm_ok =
        unsafe { sys::esp_pm_get_configuration((&mut pm as *mut sys::esp_pm_config_t).cast()) }
            == sys::ESP_OK;
    format!(
        "power={} cpu_mhz={} xtal_mhz={} pm={} pm_min={} pm_max={} light={} tick={}",
        active_profile_name(),
        cpu_freq_mhz(),
        xtal_freq_mhz(),
        pm_ok,
        if pm_ok { pm.min_freq_mhz } else { 0 },
        if pm_ok { pm.max_freq_mhz } else { 0 },
        pm_ok && pm.light_sleep_enable,
        unsafe { sys::xTaskGetTickCount() },
    )
}

pub fn resource_status_fields() -> String {
    format!(
        "heap={} heap_min={} heap_int={} psram={} psram_free={} psram_min={} psram_largest={} tasks={}",
        unsafe { sys::esp_get_free_heap_size() },
        unsafe { sys::esp_get_minimum_free_heap_size() },
        unsafe { sys::esp_get_free_internal_heap_size() },
        unsafe { sys::heap_caps_get_total_size(sys::MALLOC_CAP_SPIRAM) },
        unsafe { sys::heap_caps_get_free_size(sys::MALLOC_CAP_SPIRAM) },
        unsafe { sys::heap_caps_get_minimum_free_size(sys::MALLOC_CAP_SPIRAM) },
        unsafe { sys::heap_caps_get_largest_free_block(sys::MALLOC_CAP_SPIRAM) },
        unsafe { sys::uxTaskGetNumberOfTasks() },
    )
}

pub fn status_text() -> String {
    format!(
        "power {} {}",
        compact_status_fields(),
        sleep_metrics_fields()
    )
}

pub fn reset_sleep_metrics() {
    unsafe { dmesh_pm_metrics_reset() };
}

pub fn sleep_metrics_fields() -> String {
    let mut metrics = SleepMetrics::default();
    unsafe { dmesh_pm_metrics_snapshot(&mut metrics) };
    let slept_us = metrics.slept_us.min(metrics.tracked_us);
    let awake_us = metrics.tracked_us.saturating_sub(slept_us);
    let sleep_pct_x100 = if metrics.tracked_us == 0 {
        0
    } else {
        slept_us.saturating_mul(10_000) / metrics.tracked_us
    };
    format!(
        "ls_attempts={} ls_entries={} ls_skipped={} ls_expected_us={} ls_us={} ls_max_us={} ls_tracked_us={} ls_awake_us={} ls_pct={}.{:02}",
        metrics.attempts,
        metrics.entries,
        metrics.skipped,
        metrics.expected_us,
        slept_us,
        metrics.max_us,
        metrics.tracked_us,
        awake_us,
        sleep_pct_x100 / 100,
        sleep_pct_x100 % 100,
    )
}

struct PowerCommand {
    settings: SharedSettings,
}

impl CommandHandler for PowerCommand {
    fn name(&self) -> &'static str {
        "power"
    }

    fn handle(&mut self, request: &CommandRequest) -> Result<CommandResponse> {
        if request
            .arg("uart_probe_reset")
            .map(parse_bool)
            .transpose()?
            .unwrap_or(false)
        {
            super::serial::reset_output_probe();
            return Ok(CommandResponse::ok("power uart_probe_reset=true"));
        }
        if let Some(delay_ms) = request.arg_i32("uart_probe_ms")? {
            let delay_ms = delay_ms.clamp(1, 60_000) as u32;
            let deadline_ms = super::serial::schedule_output_probe(delay_ms);
            return Ok(CommandResponse::ok(format!(
                "power uart_probe=true delay_ms={} deadline_ms={}",
                delay_ms, deadline_ms
            )));
        }
        if request
            .arg("uart_status")
            .map(parse_bool)
            .transpose()?
            .unwrap_or(false)
        {
            return Ok(CommandResponse::ok(
                super::serial::measurement_status_fields(),
            ));
        }
        if request
            .arg("uart_uninstall")
            .map(parse_bool)
            .transpose()?
            .unwrap_or(false)
        {
            super::serial::request_uninstall_for_measurement();
            return Ok(CommandResponse::ok(
                "power uart_uninstall=true pending=true reset_required_for_restore",
            ));
        }
        if request
            .arg("quiet")
            .or_else(|| request.arg("uart_off"))
            .map(parse_bool)
            .transpose()?
            .unwrap_or(false)
        {
            super::serial::request_suspend_until_dtr();
            return Ok(CommandResponse::ok("power quiet=true pending=dtr"));
        }
        if request
            .arg("locks")
            .map(parse_bool)
            .transpose()?
            .unwrap_or(false)
        {
            let mut dump = [0_u8; 2048];
            let ret = unsafe { dmesh_pm_dump_locks(dump.as_mut_ptr(), dump.len()) };
            if ret < 0 {
                bail!("esp_pm_dump_locks failed err=0x{ret:x}");
            }
            if let Ok(text) = core::str::from_utf8(&dump[..ret as usize]) {
                super::telemetry::record_log(format!("event type=power.locks dump={text:?}"));
            }
        }
        if request
            .arg("reset")
            .map(parse_bool)
            .transpose()?
            .unwrap_or(false)
        {
            reset_sleep_metrics();
        }
        if request.arg("status").is_some() {
            return Ok(CommandResponse::ok(status_text()));
        }

        let profile = request
            .arg("profile")
            .map(PowerProfile::parse)
            .transpose()?
            .unwrap_or_else(|| {
                PowerProfile::parse(active_profile_name()).unwrap_or(PowerProfile::DFS)
            });
        apply_profile_from_request(&self.settings, profile, request)?;
        Ok(CommandResponse::ok(status_text()))
    }
}

fn apply_profile_from_request(
    settings: &SharedSettings,
    mut profile: PowerProfile,
    request: &CommandRequest,
) -> Result<()> {
    if let Some(light) = request.arg("light").map(parse_bool).transpose()? {
        profile.light_sleep = light;
    }
    if let Some(min) = request.arg_i32("min_mhz")? {
        profile.min_mhz = Some(min.max(1) as u32);
    }
    if let Some(max) = request.arg_i32("max_mhz")? {
        profile.max_mhz = Some(max.max(1) as u32);
    }

    let save = request
        .arg("save")
        .map(parse_bool)
        .transpose()?
        .unwrap_or(false);
    apply_profile(settings, profile, save)
}

fn apply_profile(settings: &SharedSettings, profile: PowerProfile, save: bool) -> Result<()> {
    let max_mhz = profile.max_mhz.unwrap_or_else(default_max_mhz);
    let min_mhz = profile.min_mhz.unwrap_or_else(default_min_mhz);
    configure_pm(max_mhz, min_mhz, profile.light_sleep)?;
    ACTIVE_PROFILE.store(profile.code(), Ordering::Relaxed);
    if save {
        settings
            .borrow_mut()
            .set_str("power.profile", profile.name())?;
    }
    super::telemetry::record_log(format!(
        "ev=power.profile profile={} min_mhz={} max_mhz={} light={}",
        profile.name(),
        min_mhz.clamp(1, max_mhz),
        max_mhz,
        profile.light_sleep
    ));
    Ok(())
}

fn configure_pm(max_mhz: u32, min_mhz: u32, light_sleep_enable: bool) -> Result<()> {
    let max_mhz = max_mhz.max(80);
    let min_mhz = min_mhz.clamp(1, max_mhz);
    let config = sys::esp_pm_config_t {
        max_freq_mhz: max_mhz as i32,
        min_freq_mhz: min_mhz as i32,
        light_sleep_enable,
    };
    let ret = unsafe { sys::esp_pm_configure((&config as *const sys::esp_pm_config_t).cast()) };
    if ret == sys::ESP_OK {
        Ok(())
    } else {
        bail!("esp_pm_configure failed err=0x{ret:x} min_mhz={min_mhz} max_mhz={max_mhz} light={light_sleep_enable}")
    }
}

#[derive(Clone, Copy)]
struct PowerProfile {
    code: u8,
    min_mhz: Option<u32>,
    max_mhz: Option<u32>,
    light_sleep: bool,
}

impl PowerProfile {
    const PERF: Self = Self {
        code: PROFILE_PERF,
        min_mhz: None,
        max_mhz: None,
        light_sleep: false,
    };
    const DFS: Self = Self {
        code: PROFILE_DFS,
        min_mhz: None,
        max_mhz: None,
        light_sleep: false,
    };
    const LOW: Self = Self {
        code: PROFILE_LOW,
        min_mhz: None,
        max_mhz: Some(80),
        light_sleep: false,
    };
    const AUTO: Self = Self {
        code: PROFILE_AUTO,
        min_mhz: None,
        max_mhz: None,
        light_sleep: true,
    };

    fn parse(value: &str) -> Result<Self> {
        match value {
            "perf" | "performance" => Ok(Self::PERF.with_min_max_equal()),
            "dfs" | "default" => Ok(Self::DFS),
            "low" | "80" | "80mhz" => Ok(Self::LOW),
            "auto" | "light" | "light_sleep" => Ok(Self::AUTO),
            other => Err(anyhow!("invalid power profile: {other}")),
        }
    }

    fn with_min_max_equal(mut self) -> Self {
        let max = default_max_mhz();
        self.min_mhz = Some(max);
        self.max_mhz = Some(max);
        self
    }

    fn code(self) -> u8 {
        self.code
    }

    fn name(self) -> &'static str {
        profile_name(self.code)
    }
}

fn active_profile_name() -> &'static str {
    profile_name(ACTIVE_PROFILE.load(Ordering::Relaxed))
}

fn profile_name(code: u8) -> &'static str {
    match code {
        PROFILE_PERF => "perf",
        PROFILE_LOW => "low",
        PROFILE_AUTO => "auto",
        _ => "dfs",
    }
}

fn cpu_freq_mhz() -> u32 {
    unsafe { esp_clk_cpu_freq() / 1_000_000 }
}

fn xtal_freq_mhz() -> u32 {
    unsafe { esp_clk_xtal_freq() / 1_000_000 }
}

fn default_max_mhz() -> u32 {
    sys::CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ.max(80)
}

fn default_min_mhz() -> u32 {
    #[cfg(target_feature = "esp32s3ops")]
    {
        80
    }
    #[cfg(not(target_feature = "esp32s3ops"))]
    {
        xtal_freq_mhz()
    }
}
