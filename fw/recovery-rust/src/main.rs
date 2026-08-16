//! Standalone Recovery shell for the bearer-neutral object transfer.
//!
//! The reusable pieces are split by bearer: `uart` handles the command/control
//! channel, `wifi` owns STA setup and the UDP transport adapter, and
//! `udp_flash` consumes ordered application stream bytes.
#![no_std]
#![no_main]

extern crate alloc;

use core::ffi::c_void;

mod uart;
mod udp_flash;
mod wifi;

static mut RECOVERY_PARAMS: uart::RecoveryParams = uart::RecoveryParams::new();

fn run() {
    esp_idf_sys::link_patches();
    uart::send_response(b"recovery boot");
    uart::install_console();
    uart::send_boot_identity();
    let params = unsafe { &mut RECOVERY_PARAMS };
    unsafe {
        params.load_from_nvs();
    }
    // A one-shot Stage2 selection reaches Recovery while normal boot remains
    // Main.  With a complete persisted STA profile, start that requested
    // recovery transfer immediately.  `boot_target=2` is deliberately
    // different: it is an operator-selected command shell, so it keeps the
    // profile inert until an explicit command arrives.
    if !params.command_mode && params.has_flash_profile() {
        params.run_requested = true;
    }
    let mut task = core::ptr::null_mut();
    let task_result = unsafe {
        esp_idf_sys::xTaskCreatePinnedToCore(
            Some(uart::task_entry),
            b"recovery_uart\0".as_ptr().cast(),
            4096,
            params as *mut uart::RecoveryParams as *mut c_void,
            5,
            &mut task,
            0,
        )
    };
    if task_result != 1 || task.is_null() {
        uart::send_response(b"recovery UART task failed");
    }
    if !unsafe { uart::init_udp_command_queue() } {
        uart::send_response(b"recovery UDP command queue failed");
    }
    // Wait briefly for the explicit STA profile. Recovery must not start a
    // partially configured client while the managed UART handoff is arriving.
    for _ in 0..uart::COMMAND_GRACE_TICKS {
        if unsafe { RECOVERY_PARAMS.server_len != 0 } {
            break;
        }
        unsafe {
            esp_idf_sys::vTaskDelay(1);
        }
    }
    let mut wifi_started = false;
    loop {
        // Raw UDP has a separate socket task, but command parsing and the
        // mutable Recovery image have one owner here. This removes the
        // cross-task static mutation that lost back-to-back benchmarks.
        let mut udp_command = [0u8; uart::UART_MAX_PACKET];
        while let Some(used) = uart::dequeue_udp_command(&mut udp_command) {
            let params = unsafe { &mut *core::ptr::addr_of_mut!(RECOVERY_PARAMS) };
            if uart::accept_packet(&udp_command[..used], params).is_none() {
                uart::send_response(b"protocol rejected");
            }
        }
        // UART and the raw-UDP command task update this small command image
        // asynchronously.  A plain read of `static mut` is undefined and
        // can be cached across the idle loop, leaving an accepted UDP command
        // with no worker.  The command generation provides release ordering;
        // this volatile snapshot makes the payload visible to this owner.
        let snapshot = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(RECOVERY_PARAMS)) };
        if (snapshot.command_mode || snapshot.run_requested)
            && snapshot.has_flash_profile()
            && !wifi_started
        {
            wifi::init_sta(&snapshot);
            wifi::start_raw_udp_endpoint(core::ptr::addr_of_mut!(RECOVERY_PARAMS));
            wifi_started = true;
        }
        if snapshot.run_requested && snapshot.has_flash_profile() {
            // Capture this before entering the synchronous worker. A command
            // received while its final telemetry is being emitted advances
            // the generation; sampling only after return loses that command
            // and makes back-to-back host benchmarks appear to hang.
            let generation = uart::command_generation();
            uart::send_response(b"udp worker begin");
            if snapshot.raw_udp {
                wifi::run_raw_udp(
                    &snapshot.server[..snapshot.server_len],
                    snapshot.port,
                    snapshot.timeout_ms,
                    snapshot.iperf_packet_size,
                );
            } else {
                wifi::run_udp(
                    &snapshot.server[..snapshot.server_len],
                    snapshot.port,
                    snapshot.benchmark,
                    snapshot.timeout_ms,
                    snapshot.ack_frequency,
                    snapshot.ack_delay_ms,
                    snapshot.transport_test,
                    snapshot.iperf_packet_size,
                    snapshot.iperf_bytes,
                    snapshot.iperf_validation,
                    snapshot.iperf_pace_us,
                    snapshot.iperf_burst_packets,
                    snapshot.iperf_burst_delay_us,
                    snapshot.iperf_window_packets,
                    snapshot.benchmark_run_id,
                );
            }
            uart::send_response(b"udp worker returned");
            if !snapshot.benchmark {
                break;
            }
            // Benchmark mode is deliberately reusable: the next UART
            // Recovery command can select another server/port/profile without
            // rebooting or reinitializing the STA.
            while !uart::command_generation_changed(generation) {
                unsafe { esp_idf_sys::vTaskDelay(10) };
            }
        } else {
            // The device-wide NVS profile only supplies STA settings. It is
            // inert for flashing until a UART Recovery command requests a
            // run. Its raw UDP endpoint is available to host-driven tests.
            unsafe { esp_idf_sys::vTaskDelay(10) };
        }
    }
    loop {
        unsafe {
            esp_idf_sys::vTaskDelay(1000);
        }
    }
}

#[no_mangle]
pub extern "C" fn app_main() {
    run();
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {
        unsafe {
            esp_idf_sys::vTaskDelay(1000);
        }
    }
}
