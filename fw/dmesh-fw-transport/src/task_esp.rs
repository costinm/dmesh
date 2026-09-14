//! ESP-IDF/FreeRTOS scheduling primitives shared by Main and Recovery.
//!
//! IMPORTANT: this module is deliberately ESP-specific.  Scheduling policy,
//! transport state, handlers, and packet processing that can run on a host do
//! not belong here: put them in `quic-lite` or `dmesh-server` instead.  The
//! helpers below only bridge a small firmware action to an explicit FreeRTOS
//! task; they never create a host-thread wrapper.

use core::sync::atomic::{AtomicBool, Ordering};

static RESTART_PENDING: AtomicBool = AtomicBool::new(false);
// `esp_wifi_disconnect`/stop tears down driver-owned callbacks and cannot run
// on the old 2 KiB delayed-restart stack. This is platform execution space,
// not a QUIC or flash buffer; keep it separate from packet-pool sizing.
const RESTART_TASK_STACK_BYTES: u32 = 8 * 1024;

/// Schedule a single restart after `delay_ms` without blocking the caller.
///
/// `vTaskDelay` yields the FreeRTOS task; it does not busy-wait or block the
/// UART/transport task.  Duplicate requests intentionally coalesce because a
/// restart is terminal for the running image.
pub fn schedule_restart_ms(delay_ms: u32) -> bool {
    if RESTART_PENDING.swap(true, Ordering::AcqRel) {
        return true;
    }
    let mut task = core::ptr::null_mut();
    let result = unsafe {
        esp_idf_sys::xTaskCreatePinnedToCore(
            Some(restart_task),
            b"dmesh_restart\0".as_ptr().cast(),
            RESTART_TASK_STACK_BYTES,
            delay_ms as usize as *mut core::ffi::c_void,
            4,
            &mut task,
            0,
        )
    };
    if result == 1 && !task.is_null() {
        true
    } else {
        RESTART_PENDING.store(false, Ordering::Release);
        false
    }
}

unsafe extern "C" fn restart_task(argument: *mut core::ffi::c_void) {
    let delay_ms = argument as usize as u32;
    let ticks = (u64::from(delay_ms) * u64::from(esp_idf_sys::configTICK_RATE_HZ)).div_ceil(1_000)
        as esp_idf_sys::TickType_t;
    unsafe {
        // This task is separate from the QUIC ingress worker. Stopping the
        // STA tears down raw UDP callbacks, so the terminal response must be
        // delivered before this leave runs. A visible 802.11 leave prevents
        // the AP retaining a stale station through ROM reset.
        crate::wifi_esp::stop_sta_for_reset();
        esp_idf_sys::vTaskDelay(ticks.max(1));
        esp_idf_sys::esp_restart();
    }
}
