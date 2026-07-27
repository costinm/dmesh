use std::sync::atomic::{AtomicPtr, AtomicU32, Ordering};
use std::time::Duration;

use esp_idf_sys as sys;

static MAIN_TASK: AtomicPtr<sys::tskTaskControlBlock> = AtomicPtr::new(std::ptr::null_mut());
static WAKE_NOTIFY_TOTAL: AtomicU32 = AtomicU32::new(0);
static WAKE_TIMEOUT_TOTAL: AtomicU32 = AtomicU32::new(0);

pub fn register_main_task() {
    let task = unsafe { sys::xTaskGetCurrentTaskHandle() };
    MAIN_TASK.store(task, Ordering::SeqCst);
}

pub fn notify() {
    let task = MAIN_TASK.load(Ordering::SeqCst);
    if task.is_null() {
        return;
    }
    unsafe {
        let _ = sys::xTaskGenericNotify(
            task,
            0,
            1,
            sys::eNotifyAction_eIncrement,
            core::ptr::null_mut(),
        );
    }
    WAKE_NOTIFY_TOTAL.fetch_add(1, Ordering::Relaxed);
}

#[allow(dead_code)]
pub fn notify_from_isr() {
    let task = MAIN_TASK.load(Ordering::SeqCst);
    if task.is_null() {
        return;
    }
    let mut woken = 0;
    unsafe {
        let _ = sys::xTaskGenericNotifyFromISR(
            task,
            0,
            1,
            sys::eNotifyAction_eIncrement,
            core::ptr::null_mut(),
            &mut woken,
        );
    }
    WAKE_NOTIFY_TOTAL.fetch_add(1, Ordering::Relaxed);
}

pub fn wait(timeout: Duration) -> bool {
    let count = unsafe { sys::ulTaskGenericNotifyTake(0, 1, duration_to_ticks(timeout)) };
    if count == 0 {
        WAKE_TIMEOUT_TOTAL.fetch_add(1, Ordering::Relaxed);
        false
    } else {
        true
    }
}

pub fn stats_fields() -> String {
    format!(
        "wake_notify={} wake_timeouts={}",
        WAKE_NOTIFY_TOTAL.load(Ordering::Relaxed),
        WAKE_TIMEOUT_TOTAL.load(Ordering::Relaxed)
    )
}

pub fn reset_stats() {
    WAKE_NOTIFY_TOTAL.store(0, Ordering::Relaxed);
    WAKE_TIMEOUT_TOTAL.store(0, Ordering::Relaxed);
}

fn duration_to_ticks(timeout: Duration) -> sys::TickType_t {
    if timeout.is_zero() {
        return 0;
    }
    let hz = sys::configTICK_RATE_HZ as u128;
    let ticks = timeout.as_millis().saturating_mul(hz).div_ceil(1000);
    ticks.max(1).min(sys::TickType_t::MAX as u128) as sys::TickType_t
}
