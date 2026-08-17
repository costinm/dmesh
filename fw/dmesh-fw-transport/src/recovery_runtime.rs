// IMPORTANT: This is shared no-std ESP firmware code. Host-neutral protocol
// behavior remains in quic-lite/dmesh-server; this worker composes ESP UART,
// NVS, STA/UDP, and flash adapters for Recovery and later Main reuse.
//! Shared no-std Recovery/Main transport worker.
//!
//! The reusable pieces are split by bearer: `uart` handles the command/control
//! channel, `wifi` owns STA setup and the UDP transport adapter, and
//! `udp_flash` consumes ordered application stream bytes.
use core::ffi::c_void;

static mut TRANSPORT_PROFILE: crate::TransportProfile = crate::TransportProfile::new();

/// Run the shared Recovery-style multi-bearer transport service loop.
///
/// The only Recovery-specific operation is supplied as `complete_main_flash`:
/// it selects Main and reboots only after a verified Main image is durable.
/// Main supplies a different completion policy for its allowed targets.
pub fn run(complete_main_flash: fn() -> bool) {
    esp_idf_sys::link_patches();
    crate::uart_esp::install_console();
    // The direct-record helpers now enqueue onto the dedicated UART task.
    // Create the queue before the first boot record; otherwise early status
    // would be silently dropped and a failed setup could recurse through the
    // error reporter.
    if !unsafe { crate::uart_esp::init_uart_egress_queue() } {
        return;
    }
    crate::commands::send_response(b"recovery boot");
    send_boot_identity(2, 2);
    // The UART command task receives this raw pointer after initialization;
    // do not create a long-lived `&mut` to a shared `static mut` here.
    let params = core::ptr::addr_of_mut!(TRANSPORT_PROFILE);
    unsafe {
        crate::esp_nvs::load_from_nvs(&mut *params);
    }
    // A one-shot Stage2 selection reaches Recovery while normal boot remains
    // Main.  With a complete persisted STA profile, start that requested
    // recovery transfer immediately.  `boot_target=2` is deliberately
    // different: it is an operator-selected command shell, so it keeps the
    // profile inert until an explicit command arrives.
    if unsafe { !(*params).command_mode && (*params).has_flash_profile() } {
        unsafe {
            (*params).run_requested = true;
        }
    }
    if !unsafe { crate::uart_esp::init_transport_ingress_queue() } {
        crate::commands::send_response(b"recovery transport ingress queue failed");
    }
    let mut task = core::ptr::null_mut();
    let task_result = unsafe {
        esp_idf_sys::xTaskCreatePinnedToCore(
            Some(crate::uart_esp::task_entry),
            b"recovery_uart\0".as_ptr().cast(),
            // The task owns one maximum escaped PPP record while handling a
            // partial nonblocking USB write. Keep that record off the main
            // transport worker without squeezing it into a 4 KiB task stack.
            8192,
            params.cast::<c_void>(),
            5,
            &mut task,
            0,
        )
    };
    if task_result != 1 || task.is_null() {
        crate::commands::send_response(b"recovery UART task failed");
    }
    if !unsafe { crate::command_esp::init_direct_record_queue() } {
        crate::commands::send_response(b"recovery direct record queue failed");
    }
    // Wait briefly for the explicit STA profile. Recovery must not start a
    // partially configured client while the managed UART handoff is arriving.
    for _ in 0..crate::uart_esp::COMMAND_GRACE_TICKS {
        if unsafe { TRANSPORT_PROFILE.server_len != 0 } {
            break;
        }
        unsafe {
            esp_idf_sys::vTaskDelay(1);
        }
    }
    let mut wifi_started = false;
    loop {
        // Command parsing and the mutable Recovery image have one owner
        // here. Bearers feed QUIC-lite; no raw UDP command/socket task is
        // started beside this worker.
        let mut direct_record = [0u8; crate::uart_esp::UART_MAX_PACKET];
        while let Some(used) = crate::command_esp::dequeue_direct_record(&mut direct_record) {
            let params = unsafe { &mut *core::ptr::addr_of_mut!(TRANSPORT_PROFILE) };
            if crate::commands::accept_packet(&direct_record[..used], params).is_none() {
                crate::commands::send_response(b"protocol rejected");
            }
        }
        // Direct bootstrap records update this small command image
        // asynchronously. A plain read of `static mut` is undefined and can
        // be cached across the idle loop; the command generation provides
        // release ordering and this volatile snapshot makes it visible here.
        let snapshot = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(TRANSPORT_PROFILE)) };
        if (snapshot.command_mode || snapshot.run_requested)
            && snapshot.has_flash_profile()
            && !wifi_started
        {
            crate::wifi_esp::init_sta(&snapshot);
            wifi_started = true;
        }
        if snapshot.run_requested && snapshot.has_flash_profile() {
            // Capture this before entering the synchronous worker. A command
            // received while its final telemetry is being emitted advances
            // the generation; sampling only after return loses that command
            // and makes back-to-back host benchmarks appear to hang.
            let generation = crate::state::command_generation();
            crate::commands::send_response(b"transport worker begin");
            crate::wifi_esp::run_transport(&snapshot, complete_main_flash);
            crate::commands::send_response(b"transport worker returned");
            if !snapshot.benchmark {
                break;
            }
            // Benchmark mode is deliberately reusable: the next UART
            // Recovery command can select another server/port/profile without
            // rebooting or reinitializing the STA.
            while !crate::state::command_generation_changed(generation) {
                unsafe { esp_idf_sys::vTaskDelay(10) };
            }
        } else {
            // The device-wide NVS profile only supplies STA settings. It is
            // inert until a direct bootstrap record requests a QUIC-lite
            // transfer run.
            unsafe { esp_idf_sys::vTaskDelay(10) };
        }
    }
    loop {
        unsafe {
            esp_idf_sys::vTaskDelay(1000);
        }
    }
}

/// Bounded boot identity exception record. It is a shared firmware bootstrap
/// event, not a Recovery command or UART-owned schema.
pub const fn boot_identity_payload(role: u8, partition: u8) -> [u8; 11] {
    // Bounded direct boot identity is one of the explicit exceptions to
    // stream-only application traffic.  Keep the role/partition pair small
    // and bearer-neutral so Stage2, Recovery, and Main can be distinguished
    // before a QUIC-lite connection exists.
    [
        0xbf, 0x07, 0x19, 0xea, 0x60, 0x06, 0x9f, role, partition, 0xff, 0xff,
    ]
}

pub fn send_boot_identity(role: u8, partition: u8) {
    let payload = boot_identity_payload(role, partition);
    let _ = crate::uart_esp::send_direct_record(&payload);
}
