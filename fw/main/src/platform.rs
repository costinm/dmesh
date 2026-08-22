const RTC_HANDOFF_OFFSET: usize = 12 + 5;
const RTC_HEALTH_EVENT_OFFSET: usize = 12 + 4;
#[cfg(target_arch = "riscv32")]
const RTC_RETAIN_BASE: usize = 0x5000_4000 - 56;
#[cfg(not(target_arch = "riscv32"))]
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
