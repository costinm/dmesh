use std::ffi::CString;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicPtr, AtomicU32, Ordering};
use std::time::{Duration, Instant};

use anyhow::{bail, Result};
use esp_idf_sys as sys;

use crate::commands::{CommandHandler, CommandRegistry, CommandRequest, CommandResponse};

use super::settings::{parse_bool, SharedSettings};
use super::telemetry;

const DEFAULT_BUTTON_GPIO: i32 = 0;
const BUTTON_LONG_PRESS_MS: u32 = 2_500;
const BUTTON_DOUBLE_CLICK_MS: u32 = 500;
const BUTTON_ACTIVE_POLL_MS: u32 = 25;
const BUTTON_SNIFF_MAX_SLOTS: usize = 128;
#[allow(dead_code)]
const BOOT_SAMPLE_MS: u64 = 100;

static BUTTON_ENABLED: AtomicBool = AtomicBool::new(false);
static BUTTON_GPIO: AtomicI32 = AtomicI32::new(DEFAULT_BUTTON_GPIO);
static BUTTON_PRESSES: AtomicU32 = AtomicU32::new(0);
static BUTTON_SYNC_PENDING: AtomicU32 = AtomicU32::new(0);
static BUTTON_LEVEL_HELD: AtomicBool = AtomicBool::new(false);
static BUTTON_LEVEL_LONG_REPORTED: AtomicBool = AtomicBool::new(false);
static BUTTON_LEVEL_START_MS: AtomicU32 = AtomicU32::new(0);
static BUTTON_LONG_PENDING: AtomicU32 = AtomicU32::new(0);
static BUTTON_CONSOLE_PENDING: AtomicU32 = AtomicU32::new(0);
static BUTTON_TASK: AtomicPtr<sys::tskTaskControlBlock> = AtomicPtr::new(std::ptr::null_mut());
static GPIO_ISR_SERVICE_READY: AtomicBool = AtomicBool::new(false);

// This is deliberately independent from BUTTON_GPIO. GPIO0 is commonly wired
// to the USB-UART DTR/PRG debug button; a protocol capture must never alter
// that pin's interrupt, pull configuration, or wake behavior.
static SNIFF_ENABLED: AtomicBool = AtomicBool::new(false);
static SNIFF_PIN: AtomicI32 = AtomicI32::new(-1);
static SNIFF_SLOTS: AtomicU32 = AtomicU32::new(0);
static SNIFF_MIN_US: AtomicU32 = AtomicU32::new(0);
static SNIFF_LAST_US: AtomicU32 = AtomicU32::new(0);
static SNIFF_SEQUENCE: AtomicU32 = AtomicU32::new(0);
static SNIFF_EVENTS: AtomicU32 = AtomicU32::new(0);
static SNIFF_DROPS: AtomicU32 = AtomicU32::new(0);
static SNIFF_DATA: [AtomicU32; BUTTON_SNIFF_MAX_SLOTS] =
    [const { AtomicU32::new(0) }; BUTTON_SNIFF_MAX_SLOTS];

unsafe extern "C" {
    fn dmesh_button_irq_set_task(task: *mut sys::tskTaskControlBlock);
    fn dmesh_button_irq_rearm();
    fn dmesh_button_gpio_isr(arg: *mut core::ffi::c_void);
}

pub fn register_commands(registry: &mut CommandRegistry, settings: SharedSettings) {
    registry.register(ButtonCommand { settings });
}

/// Initialize GPIO0 and its task in a dedicated boot phase. Command registry
/// construction must remain side-effect free so a button-driver failure cannot
/// leave startup half-complete before the console becomes usable.
pub fn initialize(settings: &SharedSettings) -> Result<()> {
    init_from_settings(settings)
}

/// Install the runtime edge interrupt only after the boot console and long
/// press probe are available. GPIO input configuration is intentionally kept
/// separate because ISR service installation has previously stalled startup on
/// boards where GPIO0 is also driven by the USB-UART DTR line.
pub fn start_runtime_interrupts() -> Result<()> {
    if !BUTTON_ENABLED.load(Ordering::Relaxed) {
        return Ok(());
    }
    configure_button_interrupts(BUTTON_GPIO.load(Ordering::Relaxed))
}

pub fn configure_light_wake(settings: &SharedSettings) -> Result<Option<i32>> {
    let pin = settings
        .borrow()
        .get_i32("button.gpio", DEFAULT_BUTTON_GPIO)?
        .clamp(0, 39);
    // GPIO wake is level-triggered.  Entering sleep while DTR/PRG is already
    // asserted causes ESP_ERR_SLEEP_REJECT immediately, so leave it disabled
    // for this interval and let the timer retry after the line is released.
    let level = unsafe { sys::gpio_get_level(pin as sys::gpio_num_t) };
    if level == 0 {
        telemetry::record_log(format!(
            "event type=sleep.light_wake source=button skipped=true reason=asserted gpio={} level={}",
            pin, level
        ));
        return Ok(None);
    }
    unsafe {
        esp_ok(sys::gpio_wakeup_enable(
            pin as sys::gpio_num_t,
            sys::gpio_int_type_t_GPIO_INTR_LOW_LEVEL,
        ))?;
        esp_ok(sys::esp_sleep_enable_gpio_wakeup())?;
    }
    Ok(Some(pin))
}

pub fn take_sync_requests() -> u32 {
    BUTTON_SYNC_PENDING.swap(0, Ordering::Relaxed)
}

pub fn take_long_presses() -> u32 {
    BUTTON_LONG_PENDING.swap(0, Ordering::Relaxed)
}

/// Consume physical PRG/DTR wake events. The GPIO task deliberately does not
/// manipulate UART state; the control task opens the console window.
pub fn take_console_wakes() -> u32 {
    BUTTON_CONSOLE_PENDING.swap(0, Ordering::Relaxed)
}

pub fn configured_gpio() -> Option<i32> {
    if BUTTON_ENABLED.load(Ordering::Relaxed) {
        Some(BUTTON_GPIO.load(Ordering::Relaxed))
    } else {
        None
    }
}

pub fn is_pressed() -> bool {
    if !BUTTON_ENABLED.load(Ordering::Relaxed) {
        return false;
    }
    let pin = BUTTON_GPIO.load(Ordering::Relaxed);
    unsafe { sys::gpio_get_level(pin as sys::gpio_num_t) == 0 }
}

pub fn suppress_until_release() {
    BUTTON_LEVEL_HELD.store(true, Ordering::Relaxed);
    BUTTON_LEVEL_LONG_REPORTED.store(true, Ordering::Relaxed);
    BUTTON_LEVEL_START_MS.store(now_ms(), Ordering::Relaxed);
}

#[allow(dead_code)]
pub fn detect_boot_long_press(window_ms: u32, hold_ms: u32) -> bool {
    if !BUTTON_ENABLED.load(Ordering::Relaxed) {
        return false;
    }
    let pin = BUTTON_GPIO.load(Ordering::Relaxed);
    let deadline = Instant::now() + Duration::from_millis(window_ms as u64);
    let mut pressed_since: Option<Instant> = None;
    while Instant::now() < deadline {
        let pressed = unsafe { sys::gpio_get_level(pin as sys::gpio_num_t) == 0 };
        if pressed {
            let start = *pressed_since.get_or_insert_with(Instant::now);
            if start.elapsed() >= Duration::from_millis(hold_ms as u64) {
                telemetry::record_log(format!(
                    "ev=button.boot_long gpio={} hold_ms={}",
                    pin, hold_ms
                ));
                return true;
            }
        } else {
            pressed_since = None;
        }
        task_delay(Duration::from_millis(BOOT_SAMPLE_MS));
    }
    false
}

#[allow(dead_code)]
fn task_delay(timeout: Duration) {
    unsafe {
        sys::vTaskDelay(duration_to_ticks(timeout).max(1));
    }
}

#[allow(dead_code)]
fn duration_to_ticks(timeout: Duration) -> sys::TickType_t {
    let hz = sys::configTICK_RATE_HZ as u128;
    let ticks = timeout.as_millis().saturating_mul(hz).div_ceil(1000);
    ticks.min(sys::TickType_t::MAX as u128) as sys::TickType_t
}

#[allow(dead_code)]
pub fn poll_level_press() {
    if !BUTTON_ENABLED.load(Ordering::Relaxed) {
        return;
    }
    let pin = BUTTON_GPIO.load(Ordering::Relaxed);
    let pressed = unsafe { sys::gpio_get_level(pin as sys::gpio_num_t) == 0 };
    let now = now_ms();
    if pressed {
        if !BUTTON_LEVEL_HELD.swap(true, Ordering::Relaxed) {
            BUTTON_LEVEL_START_MS.store(now, Ordering::Relaxed);
            BUTTON_LEVEL_LONG_REPORTED.store(false, Ordering::Relaxed);
            super::ble_bt::open_companion_active_window(10_000);
            telemetry::record_log(format!("ev=button.down gpio={} source=level", pin));
            record_button_press("short", false);
        } else {
            let start = BUTTON_LEVEL_START_MS.load(Ordering::Relaxed);
            let elapsed = now.wrapping_sub(start);
            if elapsed >= BUTTON_LONG_PRESS_MS
                && !BUTTON_LEVEL_LONG_REPORTED.swap(true, Ordering::Relaxed)
            {
                record_button_press("long", true);
            }
        }
    } else {
        BUTTON_LEVEL_HELD.swap(false, Ordering::Relaxed);
        BUTTON_LEVEL_HELD.store(false, Ordering::Relaxed);
        BUTTON_LEVEL_LONG_REPORTED.store(false, Ordering::Relaxed);
    }
}

fn init_from_settings(settings: &SharedSettings) -> Result<()> {
    let settings = settings.borrow();
    let enabled = settings.get_bool("button.enabled", true)?;
    let pin = settings
        .get_i32("button.gpio", DEFAULT_BUTTON_GPIO)?
        .clamp(0, 39);
    drop(settings);
    if enabled {
        configure_button_input(pin)?;
    }
    BUTTON_ENABLED.store(enabled, Ordering::Relaxed);
    BUTTON_GPIO.store(pin, Ordering::Relaxed);
    Ok(())
}

fn configure_button_input(pin: i32) -> Result<()> {
    unsafe {
        let config = sys::gpio_config_t {
            pin_bit_mask: 1_u64 << pin,
            mode: sys::gpio_mode_t_GPIO_MODE_INPUT,
            pull_up_en: sys::gpio_pullup_t_GPIO_PULLUP_ENABLE,
            pull_down_en: sys::gpio_pulldown_t_GPIO_PULLDOWN_DISABLE,
            // GPIO0 is connected to CP210x DTR on lab boards. A falling edge
            // is the press/wake event; using both edges here caused an ISR
            // storm on DTR release. The button task samples only while a
            // press is active to classify release, double, and long presses.
            intr_type: sys::gpio_int_type_t_GPIO_INTR_NEGEDGE,
        };
        esp_ok(sys::gpio_config(&config))?;
        esp_ok(sys::gpio_wakeup_enable(
            pin as sys::gpio_num_t,
            sys::gpio_int_type_t_GPIO_INTR_LOW_LEVEL,
        ))?;
        esp_ok(sys::esp_sleep_enable_gpio_wakeup())?;
    }
    Ok(())
}

fn configure_button_interrupts(pin: i32) -> Result<()> {
    unsafe {
        let _ = sys::gpio_isr_handler_remove(pin);
        let _ = sys::gpio_intr_disable(pin as sys::gpio_num_t);
    }
    ensure_gpio_isr_service()?;
    start_button_task()?;
    unsafe {
        esp_ok(sys::gpio_isr_handler_add(
            pin as sys::gpio_num_t,
            Some(dmesh_button_gpio_isr),
            std::ptr::null_mut(),
        ))?;
        esp_ok(sys::gpio_intr_enable(pin as sys::gpio_num_t))?;
    }
    Ok(())
}

fn ensure_gpio_isr_service() -> Result<()> {
    if GPIO_ISR_SERVICE_READY.load(Ordering::SeqCst) {
        return Ok(());
    }
    unsafe {
        let ret = sys::gpio_install_isr_service(sys::ESP_INTR_FLAG_IRAM as i32);
        if ret == sys::ESP_OK || ret == sys::ESP_ERR_INVALID_STATE {
            GPIO_ISR_SERVICE_READY.store(true, Ordering::SeqCst);
            Ok(())
        } else {
            esp_ok(ret)
        }
    }
}

fn configure_sniffer(pin: i32, slots: u32, min_us: u32) -> Result<()> {
    if !(0..=39).contains(&pin) {
        bail!("invalid sniff pin {pin}");
    }
    if pin == BUTTON_GPIO.load(Ordering::Relaxed) {
        bail!("sniff pin {pin} is the debug/PRG button; choose a separate GPIO");
    }
    let old_pin = SNIFF_PIN.load(Ordering::Relaxed);
    unsafe {
        if old_pin >= 0 {
            let _ = sys::gpio_intr_disable(old_pin as sys::gpio_num_t);
            let _ = sys::gpio_isr_handler_remove(old_pin as sys::gpio_num_t);
        }
        let config = sys::gpio_config_t {
            pin_bit_mask: 1_u64 << pin,
            mode: sys::gpio_mode_t_GPIO_MODE_INPUT,
            pull_up_en: sys::gpio_pullup_t_GPIO_PULLUP_DISABLE,
            pull_down_en: sys::gpio_pulldown_t_GPIO_PULLDOWN_DISABLE,
            intr_type: sys::gpio_int_type_t_GPIO_INTR_ANYEDGE,
        };
        esp_ok(sys::gpio_config(&config))?;
    }
    ensure_gpio_isr_service()?;
    reset_sniffer();
    SNIFF_PIN.store(pin, Ordering::Relaxed);
    SNIFF_SLOTS.store(
        slots.clamp(1, BUTTON_SNIFF_MAX_SLOTS as u32),
        Ordering::Relaxed,
    );
    SNIFF_MIN_US.store(min_us, Ordering::Relaxed);
    SNIFF_ENABLED.store(true, Ordering::Release);
    unsafe {
        esp_ok(sys::gpio_isr_handler_add(
            pin as sys::gpio_num_t,
            Some(sniffer_isr),
            std::ptr::null_mut(),
        ))?;
        esp_ok(sys::gpio_intr_enable(pin as sys::gpio_num_t))?;
    }
    Ok(())
}

fn stop_sniffer() {
    SNIFF_ENABLED.store(false, Ordering::Release);
    let pin = SNIFF_PIN.swap(-1, Ordering::Relaxed);
    if pin >= 0 {
        unsafe {
            let _ = sys::gpio_intr_disable(pin as sys::gpio_num_t);
            let _ = sys::gpio_isr_handler_remove(pin as sys::gpio_num_t);
        }
    }
    reset_sniffer();
}

fn reset_sniffer() {
    SNIFF_LAST_US.store(0, Ordering::Relaxed);
    SNIFF_SEQUENCE.store(0, Ordering::Relaxed);
    SNIFF_EVENTS.store(0, Ordering::Relaxed);
    SNIFF_DROPS.store(0, Ordering::Relaxed);
    for sample in &SNIFF_DATA {
        sample.store(0, Ordering::Relaxed);
    }
}

fn take_sniffer_samples() -> String {
    let slots = SNIFF_SLOTS
        .load(Ordering::Acquire)
        .clamp(1, BUTTON_SNIFF_MAX_SLOTS as u32);
    let sequence = SNIFF_SEQUENCE.load(Ordering::Acquire);
    let count = sequence.min(slots) as usize;
    let first = sequence.saturating_sub(count as u32);
    let mut samples = String::new();
    for offset in 0..count {
        let index = ((first + offset as u32) % slots) as usize;
        let encoded = SNIFF_DATA[index].load(Ordering::Acquire);
        let level = if encoded & 0x8000_0000 == 0 {
            "low"
        } else {
            "high"
        };
        if !samples.is_empty() {
            samples.push(',');
        }
        samples.push_str(level);
        samples.push(':');
        samples.push_str(&(encoded & 0x7fff_ffff).to_string());
    }
    let events = SNIFF_EVENTS.load(Ordering::Relaxed);
    let drops = SNIFF_DROPS.load(Ordering::Relaxed);
    let pin = SNIFF_PIN.load(Ordering::Relaxed);
    let min_us = SNIFF_MIN_US.load(Ordering::Relaxed);
    reset_sniffer();
    format!(
        "button sniff pin={} slots={} min_us={} events={} drops={} samples={}",
        pin, slots, min_us, events, drops, samples
    )
}

fn start_button_task() -> Result<()> {
    if !BUTTON_TASK.load(Ordering::SeqCst).is_null() {
        return Ok(());
    }
    let name = CString::new("button")?;
    let mut task = std::ptr::null_mut();
    let ret = unsafe {
        sys::xTaskCreatePinnedToCore(
            Some(button_task),
            name.as_ptr(),
            3072,
            std::ptr::null_mut(),
            5,
            &mut task,
            0,
        )
    };
    if ret != 1 || task.is_null() {
        bail!("button task create failed ret={ret}");
    }
    BUTTON_TASK.store(task, Ordering::SeqCst);
    unsafe { dmesh_button_irq_set_task(task) };
    Ok(())
}

unsafe extern "C" fn sniffer_isr(_arg: *mut core::ffi::c_void) {
    if !SNIFF_ENABLED.load(Ordering::Acquire) {
        return;
    }
    let now_us = unsafe { sys::esp_timer_get_time() as u32 };
    let previous_us = SNIFF_LAST_US.swap(now_us, Ordering::Relaxed);
    if previous_us == 0 {
        return;
    }
    let delta_us = now_us.wrapping_sub(previous_us);
    if delta_us < SNIFF_MIN_US.load(Ordering::Relaxed) {
        SNIFF_DROPS.fetch_add(1, Ordering::Relaxed);
        return;
    }
    let pin = SNIFF_PIN.load(Ordering::Relaxed);
    let level = unsafe { sys::gpio_get_level(pin as sys::gpio_num_t) != 0 };
    let slots = SNIFF_SLOTS.load(Ordering::Relaxed);
    if slots == 0 {
        return;
    }
    let sequence = SNIFF_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let encoded = (u32::from(level) << 31) | delta_us.min(0x7fff_ffff);
    SNIFF_DATA[(sequence % slots) as usize].store(encoded, Ordering::Release);
    SNIFF_EVENTS.fetch_add(1, Ordering::Relaxed);
}

unsafe extern "C" fn button_task(_arg: *mut core::ffi::c_void) {
    let mut pressed_at: Option<Instant> = None;
    let mut long_reported = false;
    let mut clicks = 0_u32;
    let mut click_deadline: Option<Instant> = None;
    loop {
        let now = Instant::now();
        let deadline = if let Some(start) = pressed_at {
            (start + Duration::from_millis(BUTTON_LONG_PRESS_MS as u64))
                .min(now + Duration::from_millis(BUTTON_ACTIVE_POLL_MS as u64))
        } else if let Some(deadline) = click_deadline {
            deadline
        } else {
            now + Duration::from_secs(86_400)
        };
        let timeout = deadline.saturating_duration_since(now);
        // Re-arm before blocking. The IRAM ISR coalesces edges while a task
        // notification is pending, which bounds GPIO0/DTR interrupt work.
        unsafe { dmesh_button_irq_rearm() };
        let count =
            unsafe { sys::ulTaskGenericNotifyTake(0, 1, duration_to_ticks(timeout).max(1)) };
        let now = Instant::now();
        let pressed = is_pressed();
        if count > 0 && pressed && pressed_at.is_none() {
            pressed_at = Some(now);
            long_reported = false;
            BUTTON_CONSOLE_PENDING.fetch_add(1, Ordering::Relaxed);
            telemetry::record_log("ev=button.edge source=isr state=down".to_string());
            super::wake::notify();
        }
        if !pressed {
            if let Some(start) = pressed_at.take() {
                let held = now.saturating_duration_since(start);
                if long_reported || held >= Duration::from_millis(BUTTON_LONG_PRESS_MS as u64) {
                    if !long_reported {
                        record_button_press("long", true);
                    }
                    long_reported = false;
                    clicks = 0;
                    click_deadline = None;
                } else {
                    clicks = clicks.saturating_add(1);
                    if clicks >= 2 {
                        record_button_double();
                        clicks = 0;
                        click_deadline = None;
                    } else {
                        click_deadline =
                            Some(now + Duration::from_millis(BUTTON_DOUBLE_CLICK_MS as u64));
                    }
                }
            }
        }
        if let Some(start) = pressed_at {
            if !long_reported
                && pressed
                && now.saturating_duration_since(start)
                    >= Duration::from_millis(BUTTON_LONG_PRESS_MS as u64)
            {
                record_button_press("long", true);
                long_reported = true;
                clicks = 0;
                click_deadline = None;
            }
        } else if clicks == 1 && click_deadline.is_some_and(|deadline| now >= deadline) {
            record_button_press("short", false);
            clicks = 0;
            click_deadline = None;
        }
    }
}

fn record_button_press(source: &str, long_press: bool) {
    let total = BUTTON_PRESSES.fetch_add(1, Ordering::Relaxed) + 1;
    let pin = BUTTON_GPIO.load(Ordering::Relaxed);
    let line = format!("ev=button.press gpio={} n={} source={}", pin, total, source);
    telemetry::record_log(line.clone());
    super::ble_bt::open_companion_active_window(10_000);
    if long_press {
        BUTTON_LONG_PENDING.fetch_add(1, Ordering::Relaxed);
        BUTTON_SYNC_PENDING.fetch_add(1, Ordering::Relaxed);
        let line = "ev=button.long action=sync".to_string();
        telemetry::record_log(line.clone());
    } else {
        // A short PRG press is the physical equivalent of a console/DTR wake.
        // Keep it side-effect free so it is safe as a recovery action.
        let line = "ev=button.short action=console".to_string();
        telemetry::record_log(line.clone());
    }
    super::wake::notify();
}

fn record_button_double() {
    let total = BUTTON_PRESSES.fetch_add(1, Ordering::Relaxed) + 1;
    let pin = BUTTON_GPIO.load(Ordering::Relaxed);
    let line = format!("ev=button.press gpio={} n={} source=double", pin, total);
    telemetry::record_log(line.clone());
    super::ble_bt::open_companion_active_window(10_000);
    BUTTON_SYNC_PENDING.fetch_add(1, Ordering::Relaxed);
    let line = "ev=button.double action=sync".to_string();
    telemetry::record_log(line.clone());
    super::wake::notify();
}

fn now_ms() -> u32 {
    (unsafe { sys::esp_timer_get_time() } / 1000) as u32
}

struct ButtonCommand {
    settings: SharedSettings,
}

impl CommandHandler for ButtonCommand {
    fn name(&self) -> &'static str {
        "button"
    }

    fn handle(&mut self, request: &CommandRequest) -> Result<CommandResponse> {
        if request.arg("get").is_some() || request.positional(0) == Some("get") {
            return Ok(CommandResponse::ok(take_sniffer_samples()));
        }
        if request.arg("stop").is_some() || request.positional(0) == Some("stop") {
            stop_sniffer();
            return Ok(CommandResponse::ok("button sniff stopped"));
        }
        let sniff_pin = request.arg_i32("pin")?;
        let sniff_slots = request.arg_i32("slots")?;
        if sniff_pin.is_some() || sniff_slots.is_some() || request.arg("sniff").is_some() {
            let pin = sniff_pin.ok_or_else(|| anyhow::anyhow!("button sniff requires pin=N"))?;
            let slots = sniff_slots
                .ok_or_else(|| anyhow::anyhow!("button sniff requires slots=N"))?
                .clamp(1, BUTTON_SNIFF_MAX_SLOTS as i32) as u32;
            let min_us = if let Some(value) = request.arg_i32("min_us")? {
                value.max(0) as u32
            } else {
                (request.arg_i32("min_ms")?.unwrap_or(0).max(0) as u32).saturating_mul(1_000)
            };
            configure_sniffer(pin, slots, min_us)?;
            return Ok(CommandResponse::ok(format!(
                "button sniff enabled=true pin={} slots={} min_us={}",
                pin, slots, min_us
            )));
        }
        if let Some(enabled) = request.arg("enabled").or_else(|| request.arg("enable")) {
            BUTTON_ENABLED.store(parse_bool(enabled)?, Ordering::Relaxed);
        }
        if let Some(gpio) = request.arg_i32("gpio")? {
            let gpio = gpio.clamp(0, 39);
            if SNIFF_ENABLED.load(Ordering::Acquire) && gpio == SNIFF_PIN.load(Ordering::Relaxed) {
                bail!("debug/PRG gpio {gpio} is in use by the interval sniffer; stop it first");
            }
            BUTTON_GPIO.store(gpio, Ordering::Relaxed);
        }
        let enabled = BUTTON_ENABLED.load(Ordering::Relaxed);
        let pin = BUTTON_GPIO.load(Ordering::Relaxed);
        if request
            .arg("save")
            .map(parse_bool)
            .transpose()?
            .unwrap_or(false)
        {
            let mut settings = self.settings.borrow_mut();
            settings.set_bool("button.enabled", enabled)?;
            settings.set_i32("button.gpio", pin)?;
        }
        if enabled {
            configure_button_input(pin)?;
            configure_button_interrupts(pin)?;
        }
        Ok(CommandResponse::ok(format!(
            "button enabled={} gpio={} presses={}",
            enabled,
            pin,
            BUTTON_PRESSES.load(Ordering::Relaxed)
        )))
    }
}

fn esp_ok(ret: sys::esp_err_t) -> Result<()> {
    if ret == sys::ESP_OK {
        Ok(())
    } else {
        bail!("esp_err=0x{ret:x}")
    }
}
