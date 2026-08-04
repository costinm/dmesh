use anyhow::Result;
use std::ffi::{c_char, c_int};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

mod commands;
mod components;
mod transports;

use commands::CommandRegistry;
use components::l3dmesh::L3Mesh;

const BOOT_ACTIVE_WINDOW_MS: u32 = 10_000;
const MAIN_HOUSEKEEPING_POLL_MS: u64 = 1_000;

// UART0 has exactly one framed owner after init_console_uart().  Raw ROM
// breadcrumbs are useful before that point, but writing them afterwards can
// split a CBOR/PPP record and make lmesh lose the boot/mode notification.
static FRAMED_UART_READY: AtomicBool = AtomicBool::new(false);

fn main() {
    let _ = run();
}

#[no_mangle]
pub extern "C" fn app_main() {
    let _ = run();
}

fn run() -> Result<()> {
    boot_print("dm-rs boot step=link_patches");
    esp_idf_sys::link_patches();
    if let Err(err) = components::recovery::configure_flash_size_from_hardware() {
        boot_print("dm-rs flash size override failed");
        eprintln!("flash size override failed: {err}");
    }
    components::recovery::mark_main_boot_start();
    components::wake::register_main_task();
    init_console_uart();
    quiet_runtime_logs();
    if let Err(err) = components::wifi::init_ip_stack() {
        components::telemetry::record_log(format!(
            "event type=wifi.ip_stack_init ok=false message={}",
            commands::protocol::escape_value(&err.to_string())
        ));
    }

    let wake_cause = unsafe { esp_idf_sys::esp_sleep_get_wakeup_cause() };
    boot_print("dm-rs boot step=settings\n");
    let settings = components::settings::open_shared();
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
    if let Err(err) = components::button::initialize(&settings) {
        components::telemetry::record_log(format!(
            "ev=button.err op=init err={}",
            commands::protocol::escape_value(&err.to_string())
        ));
    }

    boot_print("dm-rs boot step=registry\n");
    let mut registry = CommandRegistry::new();
    components::register_commands(&mut registry, settings.clone());
    // Optional modules are deliberately not touched during boot. A stale or
    // incompatible module must not prevent Main from reaching its console;
    // explicit `module`/`lora` commands initialize the loader instead.
    boot_print("dm-rs boot step=module_deferred\n");

    boot_print("dm-rs boot step=ble_config\n");
    let companion_setting = settings.borrow().get_bool("ble.comp", true);
    if let Err(err) = &companion_setting {
        let line = format!(
            "event type=ble.companion_error source=startup message={}",
            commands::protocol::escape_value(&err.to_string())
        );
        components::telemetry::record_log(line);
    }
    let companion_active_ms = settings
        .borrow()
        .get_i32("cm.active_ms", 5_000)
        .unwrap_or(5_000)
        .max(0) as u32;
    components::ble_bt::configure_companion_advertising(30_000, 5_000);
    components::ble_bt::configure_companion_active_window(companion_active_ms);
    boot_print("dm-rs boot step=boot_window\n");
    let boot_window = run_boot_active_window(wake_cause);
    // UART remains available through its dedicated manager task, but it is
    // configured after the startup hold is armed and never decides its
    // duration or whether Main may continue booting.
    components::serial::configure_active_window(&settings);
    boot_print("dm-rs boot step=mode\n");
    if boot_window.pairing_recovery {
        match components::ble_bt::start_pairing_recovery(&settings) {
            Ok(removed) => {
                components::telemetry::record_log(format!(
                    "event type=boot_window pairing_recovery=true bonds_removed={}",
                    removed
                ));
            }
            Err(err) => {
                components::telemetry::record_log(format!(
                    "event type=boot_window pairing_recovery=false msg={}",
                    commands::protocol::escape_value(&err.to_string())
                ));
            }
        }
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

    if boot_window.pairing_recovery {
        boot_print("dm-rs boot step=mesh_skip_pairing\n");
        components::telemetry::record_log(
            "event type=mesh.start skipped=true reason=pairing_recovery",
        );
    } else {
        boot_print("dm-rs boot step=mesh\n");
        let mut mesh = L3Mesh::new();
        boot_print("dm-rs boot step=mesh_ble_local_only\n");
        boot_print("dm-rs boot step=mesh_lora\n");
        if components::module::lora_enabled() {
            boot_print("dm-rs lora backend=module");
        }
        // Keep the transport registration stable. The module owns the radio
        // task; this transport remains the Main-side forwarding surface and
        // legacy fallback path.
        mesh.add_transport(components::lora::transport(settings.clone()));
        boot_print("dm-rs boot step=mesh_nan\n");
        mesh.add_transport(components::nan::transport());
    }

    let ready = "event type=system.ready app=dmesh-rs";
    components::telemetry::record_log(ready);
    components::recovery::mark_main_boot_healthy();
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
        components::telemetry::record_main_loop();
        // GPIO0/PRG must be handled before the raw-NAN scheduler. Otherwise
        // the scheduler can try to enter light sleep while the PRG level
        // is still asserted, and ESP-IDF rejects that sleep request.
        if components::button::take_console_wakes() > 0 {
            components::serial::rearm_after_wake();
            // GPIO0/PRG is the explicit console wake source. Rearming RX on
            // its own is insufficient: command responses remain TX-gated
            // unless this also restores the bounded UART active window.
            components::serial::activate_window();
            components::mode::mark_companion_active(&settings, companion_active_ms);
            components::telemetry::record_log("event type=uart.wake source=button");
            components::telemetry::emit_console("event type=uart.wake source=button");
        }
        if components::button::take_long_presses() > 0 {
            components::serial::set_debug_enabled(true);
            components::serial::activate_window();
            components::mode::mark_companion_active(&settings, companion_active_ms);
        }
        for _ in 0..components::button::take_sync_requests() {
            components::mode::send_button_sync(&settings);
        }
        if first_loop_trace {
            boot_print("dm-rs loop before_mode");
        }
        components::mode::poll(&settings);
        if first_loop_trace {
            boot_print("dm-rs loop after_mode");
        }
        components::ble_bt::poll_text_commands(&mut registry);
        poll_raw_wifi_commands(&mut registry, &settings);
        poll_nan_commands(&mut registry, &settings);
        components::ip_command::poll(&mut registry);
        components::module::poll_main(&mut registry, &settings);
        components::test::poll_main();
        drain_uart_console(&mut registry, &settings, companion_active_ms);
        // The CBOR recovery command only arms the raw TCP session. The worker
        // owns the outbound socket and flash operations; keep this call as a
        // compatibility no-op for the stable Main command loop.
        components::recovery::poll_flash_tcp(&settings);
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

fn drain_uart_console(
    registry: &mut CommandRegistry,
    settings: &components::settings::SharedSettings,
    companion_active_ms: u32,
) {
    while let Some(frame) = components::serial::take_frame() {
        // `0x7e 0x7e` is the scheduled empty UART heartbeat. It only grants
        // lmesh permission to flush a queued command and must not extend the
        // radio/infra session; otherwise a heartbeat every Nth NAN wake keeps
        // a sleepy node powered indefinitely and contaminates timing tests.
        if frame.data.is_empty() {
            continue;
        }
        components::mode::mark_companion_active(settings, companion_active_ms);
        let response = transports::dispatch_uart_packet(registry, &frame.data);
        components::serial::write_packet(&response);
        // The manager owns driver deletion. It observes this notification only
        // after the acknowledgement above has been accepted by UART TX.
        let _ = components::serial::finish_pending_uninstall();
        let _ = components::serial::finish_pending_suspend();
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

    components::telemetry::record_log(
        "event type=boot_window barrier=true action=startup_hold",
    );
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

fn poll_raw_wifi_commands(
    registry: &mut CommandRegistry,
    _settings: &components::settings::SharedSettings,
) {
    components::telemetry::record_raw_poll();
    while let Some(command) = components::wifi::take_raw_command() {
        components::telemetry::record_raw_command();
        components::telemetry::record_log(format!(
            "event type=wifi.raw_command source={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} len={} rssi={}",
            command.source[0],
            command.source[1],
            command.source[2],
            command.source[3],
            command.source[4],
            command.source[5],
            command.payload.len(),
            command.rssi
        ));
        let response_payload = transports::dispatch_binary_packet(registry, &command.payload);
        if let Err(err) = components::wifi::send_response_payload_to(
            command.response,
            command.source,
            &response_payload,
        ) {
            components::telemetry::record_log(format!(
                "event type=wifi.raw_response ok=false msg={}",
                commands::protocol::escape_value(&err.to_string())
            ));
        }
    }
}

fn poll_nan_commands(
    registry: &mut CommandRegistry,
    _settings: &components::settings::SharedSettings,
) {
    components::nan::poll_rx();
    while let Some(command) = components::nan::take_command() {
        components::telemetry::record_log(format!(
            "event type=nan.command len={}",
            command.payload.len()
        ));
        let response_payload = transports::dispatch_binary_packet(registry, &command.payload);
        if let Err(err) = components::nan::queue_response_payload_to(&command, &response_payload) {
            components::telemetry::record_log(format!(
                "event type=nan.response ok=false msg={}",
                commands::protocol::escape_value(&err.to_string())
            ));
        }
    }
}

/// Boot progress is retained in telemetry only. UART output is demand-driven:
/// emitting boot logs before a console client wakes it can leave UART0's IDF
/// ISR active through the radio startup transition.
fn boot_print(message: &str) {
    components::telemetry::record_log(message.trim());
    // Keep raw output strictly before the framed UART owner starts. Once the
    // driver is ready, telemetry is the only output path; otherwise a ROM
    // breadcrumb can be inserted in the middle of a framed response/event.
    if !FRAMED_UART_READY.load(Ordering::Acquire) {
        if let Ok(message) = std::ffi::CString::new(message.trim()) {
            unsafe {
                esp_rom_printf(b"%s\r\n\0".as_ptr() as *const c_char, message.as_ptr());
            }
        }
    }
}

unsafe extern "C" {
    fn esp_rom_printf(format: *const c_char, ...);
}

fn init_console_uart() {
    const UART0: esp_idf_sys::uart_port_t = esp_idf_sys::uart_port_t_UART_NUM_0;
    unsafe {
        // RX uses ESP-IDF's proven interrupt/event queue. TX has no driver
        // buffer or TX-empty interrupt; serial.rs owns it with direct FIFO
        // writes, avoiding the classic ESP32 UART TX ISR watchdog failure.
        let mut config = esp_idf_sys::uart_config_t::default();
        config.baud_rate = 115_200;
        config.data_bits = esp_idf_sys::uart_word_length_t_UART_DATA_8_BITS;
        config.parity = esp_idf_sys::uart_parity_t_UART_PARITY_DISABLE;
        config.stop_bits = esp_idf_sys::uart_stop_bits_t_UART_STOP_BITS_1;
        config.flow_ctrl = esp_idf_sys::uart_hw_flowcontrol_t_UART_HW_FLOWCTRL_DISABLE;
        config.__bindgen_anon_1.source_clk = uart_source_clk();
        let _ = esp_idf_sys::uart_param_config(UART0, &config);
        preserve_uart0_pins_in_light_sleep();

        // Use ESP-IDF's RX event queue. The driver owns RX interrupts and
        // reports complete data/overflow events to serial.rs; no application
        // task blocks directly on UART0. TX has no driver buffer and remains
        // direct FIFO writes from serial.rs, avoiding TX-empty ISR loops.
        let mut queue: esp_idf_sys::QueueHandle_t = core::ptr::null_mut();
        let mut install = esp_idf_sys::uart_driver_install(UART0, 2_048, 0, 16, &mut queue, 0);
        if install == esp_idf_sys::ESP_ERR_INVALID_STATE {
            let _ = esp_idf_sys::uart_driver_delete(UART0);
            install = esp_idf_sys::uart_driver_install(UART0, 2_048, 0, 16, &mut queue, 0);
        }
        if install != esp_idf_sys::ESP_OK || queue.is_null() {
            components::telemetry::record_log(format!(
                "event type=uart.rx_queue state=failed err={install}"
            ));
            return;
        }
        let (tx_pin, rx_pin) = uart0_pins();
        // A replaced early-console driver does not retain a portable pin
        // attachment. UART0 is GPIO1/3 on classic ESP32 and GPIO43/44 on the
        // S3 external bridge used by the Heltec V3 test board.
        // ESP-IDF 6 exposes the variadic C macro as its concrete 7-argument
        // implementation in bindgen. Older SDKs expose the 5-argument symbol.
        #[cfg(esp_idf_version_at_least_6_0_0)]
        let _ = esp_idf_sys::_uart_set_pin6(UART0, tx_pin, rx_pin, -1, -1, -1, -1);
        #[cfg(not(esp_idf_version_at_least_6_0_0))]
        let _ = esp_idf_sys::uart_set_pin(UART0, tx_pin, rx_pin, -1, -1);
        let _ = esp_idf_sys::uart_disable_tx_intr(UART0);
        // Let the hardware report a complete short command or the RX timeout.
        // On ESP32-S3, a one-byte threshold can leave the IDF event path
        // disabled after the driver is installed; the timeout still handles
        // the short framed commands without requiring a second UART reader.
        let _ = esp_idf_sys::uart_set_rx_full_threshold(UART0, 64);
        let _ = esp_idf_sys::uart_set_rx_timeout(UART0, 10);
        esp_idf_sys::uart_set_always_rx_timeout(UART0, true);
        let _ = esp_idf_sys::uart_enable_rx_intr(UART0);
        let _ = esp_idf_sys::uart_set_wakeup_threshold(UART0, 3);
        let _ = esp_idf_sys::esp_sleep_enable_uart_wakeup(UART0 as i32);
        match components::serial::start_ingress_task(queue) {
            Ok(()) => {
                components::serial::activate_window();
                FRAMED_UART_READY.store(true, Ordering::Release);
                components::telemetry::record_log(
                    "event type=uart.rx_queue state=ready baud=115200 tx_isr=false",
                );
            }
            Err(err) => {
                components::telemetry::record_log(&format!("event type=uart.rx_queue err={err}"));
            }
        }
    }
}

#[cfg(target_feature = "esp32s3ops")]
fn uart0_pins() -> (i32, i32) {
    (43, 44)
}

#[cfg(not(target_feature = "esp32s3ops"))]
fn uart0_pins() -> (i32, i32) {
    (1, 3)
}

#[cfg(target_feature = "esp32s3ops")]
fn preserve_uart0_pins_in_light_sleep() {
    unsafe {
        // ESP32-S3 UART0 is fixed to TX=GPIO43/RX=GPIO44. IDF otherwise
        // switches those pins to its automatic GPIO sleep configuration,
        // preventing a stale PRG/UART wake from reopening the console while raw-NAN is
        // between Wi-Fi windows.
        let _ = esp_idf_sys::gpio_sleep_sel_dis(43);
        let _ = esp_idf_sys::gpio_sleep_sel_dis(44);
    }
}

#[cfg(not(target_feature = "esp32s3ops"))]
fn preserve_uart0_pins_in_light_sleep() {}

#[cfg(target_feature = "esp32s3ops")]
fn uart_source_clk() -> esp_idf_sys::uart_sclk_t {
    esp_idf_sys::soc_periph_uart_clk_src_legacy_t_UART_SCLK_XTAL
}

#[cfg(not(target_feature = "esp32s3ops"))]
fn uart_source_clk() -> esp_idf_sys::uart_sclk_t {
    esp_idf_sys::soc_periph_uart_clk_src_legacy_t_UART_SCLK_APB
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
