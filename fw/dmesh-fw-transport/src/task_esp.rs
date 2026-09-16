//! ESP-IDF/FreeRTOS scheduling primitives shared by Main and Recovery.
//!
//! IMPORTANT: this module is deliberately ESP-specific.  Scheduling policy,
//! transport state, handlers, and packet processing that can run on a host do
//! not belong here: put them in `quic-lite` or `dmesh-server` instead.  The
//! helpers below only bridge a small firmware action to an explicit FreeRTOS
//! task; they never create a host-thread wrapper.

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

static RESTART_PENDING: AtomicBool = AtomicBool::new(false);
static RESTART_DELAY_MS: AtomicU32 = AtomicU32::new(0);

/// Schedule a single restart after `delay_ms` without blocking the caller.
///
/// `vTaskDelay` yields the already-running shared ingress task; it does not
/// busy-wait or allocate a second rare-event task stack. Duplicate requests
/// intentionally coalesce because a restart is terminal for the running
/// image.
pub fn schedule_restart_ms(delay_ms: u32) -> bool {
    if RESTART_PENDING.swap(true, Ordering::AcqRel) {
        return true;
    }
    RESTART_DELAY_MS.store(delay_ms, Ordering::Release);
    if crate::shared_ingress_esp::schedule_work(restart_work) {
        true
    } else {
        RESTART_PENDING.store(false, Ordering::Release);
        false
    }
}

fn restart_work() {
    let delay_ms = RESTART_DELAY_MS.load(Ordering::Acquire);
    let ticks = (u64::from(delay_ms) * u64::from(esp_idf_sys::configTICK_RATE_HZ)).div_ceil(1_000)
        as esp_idf_sys::TickType_t;
    unsafe {
        // Stopping the STA tears down raw UDP callbacks, so the terminal
        // response must be delivered before this leave runs. A visible 802.11
        // leave prevents the AP retaining a stale station through ROM reset.
        // The shared worker has already drained that response and has enough
        // stack for the IDF Wi-Fi teardown; allocating another 8 KiB task at
        // this point fails on a constrained classic ESP exactly when recovery
        // needs to be reliable.
        crate::wifi_esp::stop_sta_for_reset();
        esp_idf_sys::vTaskDelay(ticks.max(1));
        esp_idf_sys::esp_restart();
    }
}
