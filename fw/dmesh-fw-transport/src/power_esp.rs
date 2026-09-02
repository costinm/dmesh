//! Main-owned ESP power-management adapter.
//!
//! This module deliberately has no worker, callback, or periodic tick.  The
//! Main coordinator calls it only after an explicit active/sleepy policy
//! transition.  ESP-IDF then performs DFS/automatic idle sleep itself when it
//! has no PM locks; the synchronized DW8 physical sleep remains an explicit
//! Main effect in `main_runtime`.

use core::sync::atomic::{AtomicU32, Ordering};

/// Small, credential-free PM projection for Main diagnostics.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PowerStatus {
    pub cpu_mhz: u16,
    pub min_mhz: u16,
    pub max_mhz: u16,
    pub automatic_light_sleep: bool,
    pub configured: bool,
    pub light_sleep_attempts: u32,
    pub light_sleep_entries: u32,
    pub light_sleep_skipped: u32,
    pub last_sleep_requested_us: u32,
    pub last_sleep_duration_us: u32,
}

extern "C" {
    fn esp_clk_cpu_freq() -> u32;
}

const ACTIVE_MIN_MHZ: i32 = 80;
const ACTIVE_MAX_MHZ: i32 = 160;

// These are owner-task diagnostics, not an asynchronous sleep controller.
// Their values are copied into the runtime snapshot after a physical Main
// sleep boundary, so a host can distinguish policy/configuration from a real
// entered-and-returned light sleep.
static LIGHT_SLEEP_ATTEMPTS: AtomicU32 = AtomicU32::new(0);
static LIGHT_SLEEP_ENTRIES: AtomicU32 = AtomicU32::new(0);
static LIGHT_SLEEP_SKIPPED: AtomicU32 = AtomicU32::new(0);
static LAST_SLEEP_REQUESTED_US: AtomicU32 = AtomicU32::new(0);
static LAST_SLEEP_DURATION_US: AtomicU32 = AtomicU32::new(0);

/// Apply Main's active or sleepy PM policy after a boot/profile transition.
/// It is never called by packet ingress or a radio callback.  USB-JTAG and
/// the explicit DW8 sleep effect remain separate from this CPU-idle policy.
pub fn configure(sleepy: bool) -> bool {
    let config = esp_idf_sys::esp_pm_config_t {
        max_freq_mhz: ACTIVE_MAX_MHZ,
        min_freq_mhz: ACTIVE_MIN_MHZ,
        light_sleep_enable: sleepy,
    };
    unsafe {
        esp_idf_sys::esp_pm_configure((&config as *const esp_idf_sys::esp_pm_config_t).cast())
            == esp_idf_sys::ESP_OK
    }
}

/// Read ESP-IDF's current PM configuration. Called only by the Main snapshot
/// publisher or an explicit diagnostic request; it never allocates or waits.
pub fn status() -> PowerStatus {
    let mut config = esp_idf_sys::esp_pm_config_t::default();
    let configured = unsafe {
        esp_idf_sys::esp_pm_get_configuration(
            (&mut config as *mut esp_idf_sys::esp_pm_config_t).cast(),
        ) == esp_idf_sys::ESP_OK
    };
    PowerStatus {
        cpu_mhz: (unsafe { esp_clk_cpu_freq() } / 1_000_000).min(u32::from(u16::MAX)) as u16,
        min_mhz: configured
            .then_some(config.min_freq_mhz.max(0) as u16)
            .unwrap_or(0),
        max_mhz: configured
            .then_some(config.max_freq_mhz.max(0) as u16)
            .unwrap_or(0),
        automatic_light_sleep: configured && config.light_sleep_enable,
        configured,
        light_sleep_attempts: LIGHT_SLEEP_ATTEMPTS.load(Ordering::Relaxed),
        light_sleep_entries: LIGHT_SLEEP_ENTRIES.load(Ordering::Relaxed),
        light_sleep_skipped: LIGHT_SLEEP_SKIPPED.load(Ordering::Relaxed),
        last_sleep_requested_us: LAST_SLEEP_REQUESTED_US.load(Ordering::Relaxed),
        last_sleep_duration_us: LAST_SLEEP_DURATION_US.load(Ordering::Relaxed),
    }
}

/// Enter one explicit timer-bounded light sleep on behalf of the Main owner.
/// Called only after the reducer admits a sleepy radio boundary; it is never
/// invoked from a timer or Wi-Fi callback. The metrics cover actual entry and
/// return, not merely successful policy configuration.
pub(crate) fn enter_timer_light_sleep(duration_us: u64) -> bool {
    let requested = duration_us.min(u64::from(u32::MAX)) as u32;
    LIGHT_SLEEP_ATTEMPTS.fetch_add(1, Ordering::Relaxed);
    LAST_SLEEP_REQUESTED_US.store(requested, Ordering::Relaxed);
    if unsafe { esp_idf_sys::esp_sleep_enable_timer_wakeup(duration_us) } != esp_idf_sys::ESP_OK {
        LIGHT_SLEEP_SKIPPED.fetch_add(1, Ordering::Relaxed);
        return false;
    }
    let before = unsafe { esp_idf_sys::esp_timer_get_time() }.max(0) as u64;
    let result = unsafe { esp_idf_sys::esp_light_sleep_start() };
    let after = unsafe { esp_idf_sys::esp_timer_get_time() }.max(0) as u64;
    LAST_SLEEP_DURATION_US.store(
        after.saturating_sub(before).min(u64::from(u32::MAX)) as u32,
        Ordering::Relaxed,
    );
    if result == esp_idf_sys::ESP_OK {
        LIGHT_SLEEP_ENTRIES.fetch_add(1, Ordering::Relaxed);
        true
    } else {
        LIGHT_SLEEP_SKIPPED.fetch_add(1, Ordering::Relaxed);
        false
    }
}
