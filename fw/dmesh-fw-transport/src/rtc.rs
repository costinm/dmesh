//! Shared ESP Stage2 retained-state contract.
//!
//! Main writes the health markers and requests Recovery; Recovery overwrites
//! that request with a one-shot Main handoff after durable flashing. Stage2
//! is the reader. Keep the C Stage2 header synchronized with this small
//! hardware-only module; no QUIC, bearer, or application handler participates
//! in these operations.

const RTC_CUSTOM_OFFSET: usize = 12;
const RTC_HEALTH_EVENT_OFFSET: usize = RTC_CUSTOM_OFFSET + 4;
const RTC_HANDOFF_OFFSET: usize = RTC_CUSTOM_OFFSET + 5;
// `rtc_retain_mem_t`: twelve fixed bytes, 32 custom bytes, CRC, rounded to
// the bootloader's eight-byte alignment.
const RTC_RETAIN_SIZE: usize = 48;

pub const HANDOFF_NORMAL: u8 = 0;
pub const HANDOFF_RECOVERY: u8 = 1;
pub const HANDOFF_MAIN: u8 = 2;

#[cfg(target_arch = "riscv32")]
// C6 application code cannot write RTC DRAM low. Keep this high-end block
// outside the application RTC heap and make Stage2 use the same address.
const RTC_RETAIN_BASE: usize = 0x5000_4000 - RTC_RETAIN_SIZE;
#[cfg(all(not(target_arch = "riscv32"), target_feature = "esp32s3ops"))]
const RTC_RETAIN_BASE: usize = 0x6010_0000 - RTC_RETAIN_SIZE;
#[cfg(all(not(target_arch = "riscv32"), not(target_feature = "esp32s3ops")))]
// `boot_health_rtc.h` uses `SOC_RTC_DRAM_HIGH - DMESH_RTC_RETAIN_RAW_SIZE`
// on classic ESP32. ESP-IDF defines that high boundary as 0x3ff8_2000; using
// the low boundary (0x3ff8_0000) gives Main and Stage2 different retained
// blocks, so an acknowledged `boot.recovery` restarts Main instead.
const RTC_RETAIN_BASE: usize = 0x3ff8_2000 - RTC_RETAIN_SIZE;

#[inline]
unsafe fn write(offset: usize, value: u8) {
    core::ptr::write_volatile((RTC_RETAIN_BASE + offset) as *mut u8, value);
}

#[inline]
unsafe fn read(offset: usize) -> u8 {
    core::ptr::read_volatile((RTC_RETAIN_BASE + offset) as *const u8)
}

/// Stage2's current one-shot boot selection request.
pub fn handoff() -> u8 {
    unsafe { read(RTC_HANDOFF_OFFSET) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classic_rtc_layout_matches_stage2_header_contract() {
        #[cfg(all(not(target_arch = "riscv32"), not(target_feature = "esp32s3ops")))]
        assert_eq!(RTC_RETAIN_BASE, 0x3ff8_2000 - RTC_RETAIN_SIZE);
        assert_eq!(RTC_HANDOFF_OFFSET, 17);
    }

    #[test]
    fn c6_rtc_layout_matches_stage2_header_contract() {
        #[cfg(target_arch = "riscv32")]
        assert_eq!(RTC_RETAIN_BASE, 0x5000_4000 - RTC_RETAIN_SIZE);
        assert_eq!(RTC_RETAIN_SIZE, 48);
        assert_eq!(RTC_HANDOFF_OFFSET, 17);
    }
}

/// Replace any stale Recovery selection with a one-shot Main selection.
/// Stage2 consumes and clears this value before applying failure policy.
pub fn arm_main() -> bool {
    unsafe { write(RTC_HANDOFF_OFFSET, HANDOFF_MAIN) };
    handoff() == HANDOFF_MAIN
}

/// Select Recovery for the next Stage2 decision.
pub fn arm_recovery() {
    unsafe { write(RTC_HANDOFF_OFFSET, HANDOFF_RECOVERY) };
}

/// Mark Main as entered; Stage2 accounts this before the healthy marker.
pub fn mark_main_start() {
    unsafe { write(RTC_HEALTH_EVENT_OFFSET, 1) };
}

/// Mark Main healthy and clear only Recovery's consumed Main handoff.
///
/// A pending Main-to-Recovery request is armed after the terminal response
/// has been acknowledged but before the delayed reset runs. Main's normal
/// health callback can still execute in that small interval, so it must not
/// turn `HANDOFF_RECOVERY` back into normal boot.
pub fn mark_main_healthy() {
    unsafe {
        write(RTC_HEALTH_EVENT_OFFSET, 2);
        if read(RTC_HANDOFF_OFFSET) == HANDOFF_MAIN {
            write(RTC_HANDOFF_OFFSET, HANDOFF_NORMAL);
        }
    }
}

/// Record a Recovery request without racing its QUIC response.
pub fn request_recovery_boot() -> bool {
    // Re-enable only after the new stream API exposes terminal delivery. A
    // request must never arm Recovery merely because its response was queued.
    false
}
