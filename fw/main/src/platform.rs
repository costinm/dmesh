const RTC_HANDOFF_OFFSET: usize = 12 + 5;
const RTC_HEALTH_EVENT_OFFSET: usize = 12 + 4;
#[cfg(target_arch = "riscv32")]
const RTC_RETAIN_BASE: usize = 0x5000_4000 - 56;
// Classic ESP32 retains this block at the RTC DRAM low address. ESP32-S3 does
// not have `ESP_ROM_HAS_LP_ROM`, so Stage2's C contract places it at
// `SOC_RTC_DRAM_HIGH - 56`, not at the S3 RTC DRAM low boundary. Do not fold
// these targets together: writing the wrong S3 address faults before Main
// can reach its healthy marker.
#[cfg(all(not(target_arch = "riscv32"), target_feature = "esp32s3ops"))]
const RTC_RETAIN_BASE: usize = 0x6010_0000 - 56;
#[cfg(all(not(target_arch = "riscv32"), not(target_feature = "esp32s3ops")))]
const RTC_RETAIN_BASE: usize = 0x3ff8_0000;

unsafe fn rtc_write(offset: usize, value: u8) {
    core::ptr::write_volatile((RTC_RETAIN_BASE + offset) as *mut u8, value);
}

pub fn mark_main_boot_start() {
    unsafe { rtc_write(RTC_HEALTH_EVENT_OFFSET, 1) };
}

pub fn mark_main_boot_healthy() {
    unsafe {
        rtc_write(RTC_HEALTH_EVENT_OFFSET, 2);
        rtc_write(RTC_HANDOFF_OFFSET, 0);
    }
}

/// Select Recovery for the next Stage2 decision, then reboot only after the
/// correlated QUIC response has had time to leave the active association.
pub fn schedule_recovery_boot() -> bool {
    // Do not leave a Recovery handoff armed if task creation failed.  The
    // restart task cannot run before this call returns, so a successful
    // schedule can be followed safely by the retained-state write.
    if !dmesh_fw_transport::task_esp::schedule_restart_ms(250) {
        return false;
    }
    unsafe { rtc_write(RTC_HANDOFF_OFFSET, 1) };
    true
}
