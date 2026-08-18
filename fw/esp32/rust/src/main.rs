use anyhow::Result;
use std::ffi::{c_char, c_int};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::Duration;

mod commands;
mod components;

const BOOT_ACTIVE_WINDOW_MS: u32 = 10_000;
const MAIN_HOUSEKEEPING_POLL_MS: u64 = 1_000;
// A console wake keeps Main's non-BLE companion policy active, but it must
// not initialize the BLE controller or read BLE settings at boot.
const COMPANION_ACTIVE_MS: u32 = 5_000;

// UART0 has exactly one owner after init_console_uart(). Raw ROM breadcrumbs
// are useful before that point; afterwards raw ASCII diagnostics are injected
// as complete records into the shared UART writer, never emitted directly by
// a Main, Wi-Fi, or transport task.
static FRAMED_UART_READY: AtomicBool = AtomicBool::new(false);
// Heap APIs do not allocate. Capture the true entry state before flash, NVS,
// or console initialization; emit it only after the console writer is ready.
static HEAP_ENTRY_FREE: AtomicU32 = AtomicU32::new(0);
static HEAP_ENTRY_LARGEST: AtomicU32 = AtomicU32::new(0);
static HEAP_ENTRY_MINIMUM: AtomicU32 = AtomicU32::new(0);
// A host can attach just after the initial reset identity. Retransmit it once
// from the normal cooperative loop so boot proof does not depend on opening
// the physical UART during the reset edge.
static BOOT_IDENTITY_RETRY_AT_MS: AtomicU32 = AtomicU32::new(0);

fn main() {
    let _ = run();
}

#[no_mangle]
pub extern "C" fn app_main() {
    let _ = run();
}

fn run() -> Result<()> {
    capture_entry_heap();
    rom_breadcrumb(b"dm-rs boot step=link_patches\0");
    esp_idf_sys::link_patches();
    rom_breadcrumb(b"dm-rs boot step=link_patches_done\0");
    rom_breadcrumb(b"dm-rs boot step=flash_size_begin\0");
    if let Err(err) = components::recovery::configure_flash_size_from_hardware() {
        rom_breadcrumb(b"dm-rs flash size override failed\0");
        eprintln!("flash size override failed: {err}");
    }
    rom_breadcrumb(b"dm-rs boot step=flash_size_done\0");
    components::recovery::mark_main_boot_start();
    components::wake::register_main_task();
    dmesh_fw_transport::uart_esp::set_ingress_notify(Some(components::wake::notify));
    let before_console = heap_snapshot();
    rom_breadcrumb(b"dm-rs uart setup begin\0");
    init_console_uart();
    rom_breadcrumb(b"dm-rs uart setup done\0");
    report_entry_and_console_heap(before_console);
    // `std::sync::Mutex` is backed by an ESP-IDF queue.  On classic ESP32,
    // defer its first construction until NVS/settings has initialized its own
    // allocator and lock state; the UART driver itself remains available for
    // raw boot diagnostics in the meantime.
    #[cfg(any(target_arch = "riscv32", target_feature = "esp32s3ops"))]
    {
        components::telemetry::initialize_log_stream();
        rom_breadcrumb(b"dm-rs log queue done\0");
    }
    // ESP-IDF 6's classic-ESP32 log-level path lazily creates a global log
    // mutex without inter-core initialization. Boot logging may already have
    // raced that setup, and `esp_log_level_set` then asserts on a non-mutex
    // queue handle. Suppressing optional log levels is not required for the
    // UART L2; retain raw diagnostic text and leave C6/S3 unchanged.
    #[cfg(any(target_arch = "riscv32", target_feature = "esp32s3ops"))]
    quiet_runtime_logs();
    // `dmesh-fw-transport::wifi_esp` owns the ESP-IDF network stack and the
    // default STA netif.  Creating either here races the shared STA adapter
    // and makes ESP-IDF abort on a duplicate default netif.

    rom_breadcrumb(b"dm-rs wake cause begin\0");
    let wake_cause = unsafe { esp_idf_sys::esp_sleep_get_wakeup_cause() };
    rom_breadcrumb(b"dm-rs wake cause done\0");
    // This isolates NVS/settings-store cost from the entry and console
    // baselines reported immediately after the console writer became ready.
    report_heap_phase(
        b"heap pre_settings free=",
        b"heap pre_settings largest=",
        b"heap pre_settings min=",
    );
    rom_breadcrumb(b"dm-rs settings begin\0");
    let settings = components::settings::open_shared();
    rom_breadcrumb(b"dm-rs settings done\0");
    report_heap_phase(
        b"heap settings free=",
        b"heap settings largest=",
        b"heap settings min=",
    );
    // Reserve the shared raw STA driver's allocations before optional power,
    // BLE, and boot-window work. Recovery reaches Wi-Fi at this point; doing
    // it later in Main can leave ESP-IDF without the contiguous heap it needs
    // even though total free memory appears sufficient.
    let infra_at_boot = components::mode::configured_infra_mode(&settings);
    components::transport_runtime::initialize(&settings, infra_at_boot);
    report_heap_phase(
        b"heap transport free=",
        b"heap transport largest=",
        b"heap transport min=",
    );
    #[cfg(all(not(target_arch = "riscv32"), not(target_feature = "esp32s3ops")))]
    {
        components::telemetry::initialize_log_stream();
        rom_breadcrumb(b"dm-rs log queue done\0");
    }
    #[cfg(all(not(target_arch = "riscv32"), not(target_feature = "esp32s3ops")))]
    start_deferred_classic_uart_l2();
    boot_print("dm-rs boot step=power\n");
    if let Err(err) = components::power::apply_default(&settings) {
        components::telemetry::record_log(format!(
            "event type=power.default ok=false msg={}",
            commands::protocol::escape_value(&err.to_string())
        ));
    }
    // Keep the boot/control path awake until the first stable main loop. This
    // also prevents an invalid retained power profile from entering light
    // sleep while peripherals are still being initialized.
    let _ = components::power::configure_for_light_sleep(false);
    boot_print("dm-rs boot step=wake\n");
    if let Err(err) = components::sleep::handle_deep_sleep_wake() {
        components::telemetry::record_log(format!(
            "event type=sleep.error phase=wake message={}",
            commands::protocol::escape_value(&err.to_string())
        ));
    }

    boot_print("dm-rs boot step=button\n");
    if let Err(err) = components::peripherals::initialize_button(&settings) {
        components::telemetry::record_log(format!(
            "ev=button.err op=init err={}",
            commands::protocol::escape_value(&err.to_string())
        ));
    }

    // Main no longer exposes the old command registry. New operations are
    // registered as dmesh-server stream handlers on the shared QUIC-lite
    // connection; direct CBOR remains only for the narrow wake/bootstrap
    // exception handled below. Keep the parser module compiling while shared
    // component helpers are migrated, but never instantiate or dispatch it.
    boot_print("dm-rs boot step=legacy_commands_disabled\n");
    // Optional modules are deliberately not touched during boot. A stale or
    // incompatible module must not prevent Main from reaching its console;
    // explicit `module`/`lora` commands initialize the loader instead.
    boot_print("dm-rs boot step=module_deferred\n");

    boot_print("dm-rs boot step=ble_config\n");
    // BLE has no boot-time role in the Wi-Fi transport profile.  In
    // particular, do not construct its command queue/controller allocations
    // merely to read companion defaults: a hardware or pairing stream request
    // owns `ensure_ble()` and pays that memory cost on demand.
    report_heap_phase(
        b"heap ble_deferred free=",
        b"heap ble_deferred largest=",
        b"heap ble_deferred min=",
    );
    boot_print("dm-rs boot step=boot_window\n");
    let boot_window = run_boot_active_window(wake_cause);
    // UART remains available through its dedicated manager task, but it is
    // configured after the startup hold is armed and never decides its
    // duration or whether Main may continue booting.
    components::serial::configure_active_window(&settings);
    boot_print("dm-rs boot step=mode\n");
    if boot_window.pairing_recovery {
        components::telemetry::record_log(
            "event type=boot_window pairing_recovery=true ble=deferred",
        );
        components::mode::enter_pairing_recovery(
            &settings,
            components::ble_bt::PAIRING_RECOVERY_WINDOW_MS,
        );
    } else if is_real_boot(wake_cause) || is_button_wake(wake_cause) {
        components::mode::init_after_boot_window(
            &settings,
            is_button_wake(wake_cause),
            is_real_boot(wake_cause),
        );
    } else {
        components::mode::init(&settings);
    }

    let ready = "event type=system.ready app=dmesh-rs";
    components::telemetry::record_log(ready);
    components::recovery::mark_main_boot_healthy();
    // Direct boot identity is the bounded pre-stream proof that Stage2 chose
    // Main and this application reached its healthy point.  It is not a log
    // or command response; normal diagnostics remain stream services.
    let identity = dmesh_server::recovery::boot_identity_payload(1, 1);
    let _ = components::serial::write_direct_record(&identity);
    let identity_retry_at =
        unsafe { (esp_idf_sys::esp_timer_get_time().max(0) as u64 / 1_000) as u32 }
            .wrapping_add(1_000);
    BOOT_IDENTITY_RETRY_AT_MS.store(identity_retry_at, Ordering::Release);
    boot_print("dm-rs boot step=console\n");
    // Stage2 owns boot-time recovery selection. Do not install the GPIO0 ISR
    // during Main startup: on some ESP32 boards the physical PRG line can
    // generate an interrupt storm before the scheduler is fully settled,
    // starving CPU0 and tripping the interrupt watchdog. Button GPIO setup
    // remains available for sleep configuration and explicit future repair.
    components::telemetry::record_log(
        "event type=button.runtime_interrupt enabled=false reason=stage2_owns_recovery",
    );
    boot_print("dm-rs boot step=runtime_interrupts_skipped");
    let mut first_loop_trace = true;
    loop {
        let identity_retry_at = BOOT_IDENTITY_RETRY_AT_MS.load(Ordering::Acquire);
        let now_ms = unsafe { (esp_idf_sys::esp_timer_get_time().max(0) as u64 / 1_000) as u32 };
        if identity_retry_at != 0
            && !quic_lite::before_deadline_u32(now_ms, identity_retry_at)
            && BOOT_IDENTITY_RETRY_AT_MS
                .compare_exchange(identity_retry_at, 0, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
        {
            let identity = dmesh_server::recovery::boot_identity_payload(1, 1);
            let _ = components::serial::write_direct_record(&identity);
        }
        components::telemetry::record_main_loop();
        // GPIO0/PRG must be handled before the raw-NAN scheduler. Otherwise
        // the scheduler can try to enter light sleep while the PRG level
        // is still asserted, and ESP-IDF rejects that sleep request.
        if components::peripherals::take_console_wakes() > 0 {
            components::serial::rearm_after_wake();
            // GPIO0/PRG is the explicit console wake source. Rearming RX on
            // its own is insufficient: command responses remain TX-gated
            // unless this also restores the bounded UART active window.
            components::serial::activate_window();
            components::mode::mark_companion_active(&settings, COMPANION_ACTIVE_MS);
            components::telemetry::record_log("event type=uart.wake source=button");
            components::telemetry::emit_console("event type=uart.wake source=button");
        }
        if components::peripherals::take_long_presses() > 0 {
            components::serial::set_debug_enabled(true);
            components::serial::activate_window();
            components::mode::mark_companion_active(&settings, COMPANION_ACTIVE_MS);
        }
        for _ in 0..components::peripherals::take_sync_requests() {
            components::mode::send_button_sync(&settings);
        }
        if first_loop_trace {
            boot_print("dm-rs loop before_mode");
        }
        components::mode::poll(&settings);
        components::transport_runtime::poll();
        if first_loop_trace {
            boot_print("dm-rs loop after_mode");
        }
        components::wifi::poll_ip_sta();
        poll_nan_commands();
        components::module::poll_callbacks(&settings);
        components::module::poll_stream_services(&settings);
        // A beacon can arrive near the end of a sparse DW. Poll quickly only
        // while the raw-NAN window is already awake so post-beacon shutdown is
        // bounded by the NAN dwell without adding periodic wakeups during
        // light sleep.
        let housekeeping_ms = if components::mode::raw_nan_duty_active() {
            // The NAN-required post-beacon dwell is only 32 ms. Polling at
            // 10 ms keeps shutdown close to that dwell without adding any
            // periodic wakeups while the radio is light-sleeping.
            10
        } else {
            MAIN_HOUSEKEEPING_POLL_MS
        };
        match wait_for_firmware_activity(Duration::from_millis(housekeeping_ms)) {
            UartWait::Data => {}
            UartWait::Timeout => {
                components::telemetry::record_uart_timeout();
            }
        }
        components::serial::poll_active_window();
        components::serial::poll_output_probe();
        if first_loop_trace {
            boot_print("dm-rs loop complete");
            first_loop_trace = false;
        }
    }
}

/// Fixed-cost boot diagnostics: free heap alone hides fragmentation, whereas
/// the largest 8-bit-capable block directly explains a failed Rust allocation.
/// This does not enable heap tracing or allocate memory.
fn capture_entry_heap() {
    let (free, largest, minimum) = heap_snapshot();
    HEAP_ENTRY_FREE.store(free, Ordering::Relaxed);
    HEAP_ENTRY_LARGEST.store(largest, Ordering::Relaxed);
    HEAP_ENTRY_MINIMUM.store(minimum, Ordering::Relaxed);
}

fn heap_snapshot() -> (u32, u32, u32) {
    unsafe {
        (
            esp_idf_sys::esp_get_free_heap_size(),
            esp_idf_sys::heap_caps_get_largest_free_block(esp_idf_sys::MALLOC_CAP_8BIT as _) as u32,
            esp_idf_sys::esp_get_minimum_free_heap_size(),
        )
    }
}

fn report_entry_and_console_heap(before_console: (u32, u32, u32)) {
    dmesh_fw_transport::commands::send_stat(
        b"heap entry free=",
        HEAP_ENTRY_FREE.load(Ordering::Relaxed) as u64,
    );
    dmesh_fw_transport::commands::send_stat(
        b"heap entry largest=",
        HEAP_ENTRY_LARGEST.load(Ordering::Relaxed) as u64,
    );
    dmesh_fw_transport::commands::send_stat(
        b"heap entry min=",
        HEAP_ENTRY_MINIMUM.load(Ordering::Relaxed) as u64,
    );
    dmesh_fw_transport::commands::send_stat(b"heap pre_console free=", before_console.0 as u64);
    dmesh_fw_transport::commands::send_stat(b"heap pre_console largest=", before_console.1 as u64);
    dmesh_fw_transport::commands::send_stat(b"heap pre_console min=", before_console.2 as u64);
    report_heap_phase(
        b"heap console free=",
        b"heap console largest=",
        b"heap console min=",
    );
}

fn report_heap_phase(free: &[u8], largest: &[u8], minimum: &[u8]) {
    unsafe {
        dmesh_fw_transport::commands::send_stat(free, esp_idf_sys::esp_get_free_heap_size() as u64);
        dmesh_fw_transport::commands::send_stat(
            largest,
            esp_idf_sys::heap_caps_get_largest_free_block(esp_idf_sys::MALLOC_CAP_8BIT as _) as u64,
        );
        dmesh_fw_transport::commands::send_stat(
            minimum,
            esp_idf_sys::esp_get_minimum_free_heap_size() as u64,
        );
    }
}

enum UartWait {
    Data,
    Timeout,
}

struct BootWindowResult {
    pairing_recovery: bool,
}

fn run_boot_active_window(wake_cause: esp_idf_sys::esp_sleep_source_t) -> BootWindowResult {
    if !is_real_boot(wake_cause) {
        return BootWindowResult {
            pairing_recovery: false,
        };
    }

    components::telemetry::record_log("event type=boot_window barrier=true action=startup_hold");
    components::telemetry::record_log(format!(
        "event type=boot_window start=true cause={} window_ms={}",
        wake_cause_name(wake_cause),
        boot_active_window_ms()
    ));

    // Do not delay the Main task here. The sleep scheduler will skip light
    // sleep until this deadline, while all normal tasks (including UART) keep
    // running.
    components::sleep::begin_startup_hold(boot_active_window_ms());
    components::telemetry::record_log(format!(
        "event type=boot_window done=true pairing_recovery={}",
        false
    ));
    BootWindowResult {
        pairing_recovery: false,
    }
}

fn boot_active_window_ms() -> u32 {
    BOOT_ACTIVE_WINDOW_MS
}

fn is_real_boot(cause: esp_idf_sys::esp_sleep_source_t) -> bool {
    cause == esp_idf_sys::esp_sleep_source_t_ESP_SLEEP_WAKEUP_UNDEFINED
}

fn is_button_wake(cause: esp_idf_sys::esp_sleep_source_t) -> bool {
    cause == esp_idf_sys::esp_sleep_source_t_ESP_SLEEP_WAKEUP_EXT0
}

fn wake_cause_name(cause: esp_idf_sys::esp_sleep_source_t) -> &'static str {
    match cause {
        x if x == esp_idf_sys::esp_sleep_source_t_ESP_SLEEP_WAKEUP_UNDEFINED => "undefined",
        x if x == esp_idf_sys::esp_sleep_source_t_ESP_SLEEP_WAKEUP_EXT0 => "ext0",
        x if x == esp_idf_sys::esp_sleep_source_t_ESP_SLEEP_WAKEUP_EXT1 => "ext1",
        x if x == esp_idf_sys::esp_sleep_source_t_ESP_SLEEP_WAKEUP_TIMER => "timer",
        x if x == esp_idf_sys::esp_sleep_source_t_ESP_SLEEP_WAKEUP_GPIO => "gpio",
        x if x == esp_idf_sys::esp_sleep_source_t_ESP_SLEEP_WAKEUP_UART => "uart",
        _ => "other",
    }
}

fn poll_nan_commands() {
    components::nan::poll_rx();
}

/// Boot progress is retained in telemetry only. UART output is demand-driven:
/// emitting boot logs before a console client wakes it can leave UART0's IDF
/// ISR active through the radio startup transition.
fn boot_print(message: &str) {
    if FRAMED_UART_READY.load(Ordering::Acquire) {
        // Raw text is solely a UART/QUIC-lite troubleshooting breadcrumb. The
        // shared writer serializes this complete line with PPP records, while
        // normal firmware logs remain available through `log-watch`.
        #[cfg(any(target_arch = "riscv32", target_feature = "esp32s3ops"))]
        components::telemetry::record_log(message.trim());
        let _ = dmesh_fw_transport::uart_esp::send_debug_text(message.trim().as_bytes());
    } else {
        // Keep the pre-L2 path allocation-free. `boot_print` accepts dynamic
        // text, so it cannot safely pass an arbitrary Rust `&str` to ROM
        // printf without building a NUL-terminated buffer. Boot-critical
        // progress uses the static `rom_breadcrumb` calls above instead.
    }
}

unsafe extern "C" {
    fn esp_rom_printf(format: *const c_char, ...);
}

/// Heap-free static boot breadcrumb for diagnosing the narrow period before
/// Main's UART L2 can own the console. Unlike `boot_print`, this may be used
/// around driver/queue setup without allocating or taking a logger mutex.
fn rom_breadcrumb(message: &'static [u8]) {
    unsafe {
        esp_rom_printf(
            b"%s\r\n\0".as_ptr() as *const c_char,
            message.as_ptr() as *const c_char,
        );
    }
}

fn init_console_uart() {
    unsafe {
        if !dmesh_fw_transport::uart_esp::install_l2_driver() {
            components::telemetry::record_log(format!("event type=uart.driver state=failed"));
            return;
        }
        // On classic ESP32, defer shared queue/task creation until after NVS
        // settings has performed the application's first heap allocations.
        // Its console driver is ready now; only L2 ownership is delayed.
        #[cfg(all(not(target_arch = "riscv32"), not(target_feature = "esp32s3ops")))]
        return;

        #[cfg(any(target_arch = "riscv32", target_feature = "esp32s3ops"))]
        if dmesh_fw_transport::uart_esp::start_shared_l2(
            components::action_stream::dispatch_uart_ingress,
            components::action_stream::dispatch_uart_raw_ingress,
        ) {
            components::serial::activate_window();
            FRAMED_UART_READY.store(true, Ordering::Release);
            components::telemetry::record_log(
                "event type=uart state=ready baud=115200 tx_isr=false shared_l2=true pool=shared",
            );
        } else {
            components::telemetry::record_log("event type=uart state=failed reason=shared_l2");
        }
    }
}

#[cfg(all(not(target_arch = "riscv32"), not(target_feature = "esp32s3ops")))]
fn start_deferred_classic_uart_l2() {
    rom_breadcrumb(b"dm-rs uart l2 start begin\0");
    let task = unsafe {
        dmesh_fw_transport::uart_esp::start_shared_l2(
            components::action_stream::dispatch_uart_ingress,
            components::action_stream::dispatch_uart_raw_ingress,
        )
    };
    rom_breadcrumb(b"dm-rs uart l2 start done\0");
    if task {
        components::serial::activate_window();
        FRAMED_UART_READY.store(true, Ordering::Release);
        components::telemetry::record_log(
            "event type=uart state=ready baud=115200 tx_isr=false shared_l2=true pool=shared",
        );
    } else {
        // Keep the raw ROM/console diagnostic path alive; do not crash Main
        // merely because the optional framed L2 could not obtain its bounds.
        rom_breadcrumb(b"dm-rs uart l2 deferred start failed\0");
    }
}

fn wait_for_firmware_activity(timeout: Duration) -> UartWait {
    if components::wake::wait(timeout) {
        UartWait::Data
    } else {
        UartWait::Timeout
    }
}

fn quiet_runtime_logs() {
    log::set_max_level(log::LevelFilter::Off);
    unsafe {
        let _ = esp_idf_sys::esp_log_set_vprintf(Some(discard_log_vprintf));
        set_esp_log_level(b"*\0", esp_idf_sys::esp_log_level_t_ESP_LOG_WARN);
        set_esp_log_level(b"BT_APPL\0", esp_idf_sys::esp_log_level_t_ESP_LOG_NONE);
        set_esp_log_level(b"BT_BTM\0", esp_idf_sys::esp_log_level_t_ESP_LOG_NONE);
        set_esp_log_level(b"BT_HCI\0", esp_idf_sys::esp_log_level_t_ESP_LOG_NONE);
        set_esp_log_level(b"gpio\0", esp_idf_sys::esp_log_level_t_ESP_LOG_NONE);
        set_esp_log_level(b"nan_app\0", esp_idf_sys::esp_log_level_t_ESP_LOG_NONE);
        set_esp_log_level(b"wifi\0", esp_idf_sys::esp_log_level_t_ESP_LOG_NONE);
    }
}

unsafe extern "C" fn discard_log_vprintf(
    _format: *const c_char,
    _args: esp_idf_sys::va_list,
) -> c_int {
    0
}

unsafe fn set_esp_log_level(tag: &'static [u8], level: esp_idf_sys::esp_log_level_t) {
    unsafe {
        esp_idf_sys::esp_log_level_set(tag.as_ptr() as *const c_char, level);
    }
}
