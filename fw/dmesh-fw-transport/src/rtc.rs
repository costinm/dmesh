//! Shared ESP Stage2 retained-state contract.
//!
//! Main writes the health markers and requests Recovery; Recovery overwrites
//! that request with a one-shot Main handoff after durable flashing. Stage2
//! is the reader. Keep the C Stage2 header synchronized with this small
//! hardware-only module; no QUIC, bearer, or application handler participates
//! in these operations.

use core::sync::atomic::{AtomicU32, AtomicU8, Ordering};

const RTC_CUSTOM_OFFSET: usize = 12;
const RTC_HEALTH_EVENT_OFFSET: usize = RTC_CUSTOM_OFFSET + 4;
const RTC_HANDOFF_OFFSET: usize = RTC_CUSTOM_OFFSET + 5;
// `rtc_retain_mem_t`: twelve fixed bytes, 32 custom bytes, CRC, rounded to
// the bootloader's eight-byte alignment.
const RTC_RETAIN_SIZE: usize = 48;

pub const HANDOFF_NORMAL: u8 = 0;
pub const HANDOFF_RECOVERY: u8 = 1;
pub const HANDOFF_MAIN: u8 = 2;

static RECOVERY_BOOT_STATE: AtomicU8 = AtomicU8::new(0);
static RECOVERY_BOOT_CID_LOW: AtomicU32 = AtomicU32::new(0);
static RECOVERY_BOOT_CID_HIGH: AtomicU32 = AtomicU32::new(0);

#[cfg(target_arch = "riscv32")]
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

/// Mark Main healthy and clear a consumed handoff.
pub fn mark_main_healthy() {
    unsafe {
        write(RTC_HEALTH_EVENT_OFFSET, 2);
        write(RTC_HANDOFF_OFFSET, HANDOFF_NORMAL);
    }
}

/// Record a Recovery request without racing its QUIC response.
pub fn request_recovery_boot() -> bool {
    RECOVERY_BOOT_STATE.store(1, Ordering::Release);
    true
}

/// Bind the handler request to the association whose terminal response was
/// actually encoded after packet admission selected the current CID.
pub(crate) fn bind_recovery_response(cid: quic_lite::ConnectionId) {
    if RECOVERY_BOOT_STATE.load(Ordering::Acquire) != 1 {
        return;
    }
    let value = cid.value();
    RECOVERY_BOOT_CID_LOW.store(value as u32, Ordering::Relaxed);
    RECOVERY_BOOT_CID_HIGH.store((value >> 32) as u32, Ordering::Relaxed);
    RECOVERY_BOOT_STATE.store(2, Ordering::Release);
}

/// Arm Stage2 and schedule restart only after QUIC-lite reports that the peer
/// acknowledged the terminal stream response. ACK details remain private to
/// the transport; this is only the generic application delivery edge.
pub(crate) fn response_delivered(cid: quic_lite::ConnectionId) {
    if RECOVERY_BOOT_STATE.load(Ordering::Acquire) != 2 {
        return;
    }
    let expected = u64::from(RECOVERY_BOOT_CID_LOW.load(Ordering::Relaxed))
        | (u64::from(RECOVERY_BOOT_CID_HIGH.load(Ordering::Relaxed)) << 32);
    if cid.value() != expected
        || RECOVERY_BOOT_STATE
            .compare_exchange(2, 0, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
    {
        return;
    }
    if crate::task_esp::schedule_restart_ms(250) {
        arm_recovery();
    } else {
        RECOVERY_BOOT_STATE.store(2, Ordering::Release);
    }
}
