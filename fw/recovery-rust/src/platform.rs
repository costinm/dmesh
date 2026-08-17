//! Recovery-only ESP platform hooks.
//!
//! Keep RTC/NVS/partition details here so stream decoding and verification can
//! move toward shared host-testable code without importing ESP register state.

const RTC_HANDOFF_MAIN: u8 = 2;
const RTC_HANDOFF_OFFSET: usize = 12 + 5;
#[cfg(target_arch = "riscv32")]
const RTC_RETAIN_BASE: usize = 0x5000_4000 - 56;
#[cfg(not(target_arch = "riscv32"))]
const RTC_RETAIN_BASE: usize = 0x3ff8_0000;

fn set_main_handoff() -> u8 {
    unsafe {
        core::ptr::write_volatile(
            (RTC_RETAIN_BASE + RTC_HANDOFF_OFFSET) as *mut u8,
            RTC_HANDOFF_MAIN,
        );
        core::ptr::read_volatile((RTC_RETAIN_BASE + RTC_HANDOFF_OFFSET) as *const u8)
    }
}

extern "C" {
    fn nvs_flash_init() -> i32;
    fn nvs_open(namespace: *const i8, mode: i32, handle: *mut u32) -> i32;
    fn nvs_set_u32(handle: u32, key: *const i8, value: u32) -> i32;
    fn nvs_commit(handle: u32) -> i32;
    fn nvs_close(handle: u32);
}

/// Commit the next Stage2 boot target only after a complete image is durable.
fn set_stg2_boot_target(target: u32) -> bool {
    unsafe {
        if nvs_flash_init() != 0 {
            return false;
        }
        let mut handle = 0u32;
        if nvs_open(b"stg2\0".as_ptr().cast(), 1, &mut handle) != 0 {
            return false;
        }
        let ok = nvs_set_u32(handle, b"boot_target\0".as_ptr().cast(), target) == 0
            && nvs_commit(handle) == 0;
        nvs_close(handle);
        ok
    }
}

/// The one Recovery-only post-successful-Main-image action.  All stream,
/// flash, STA, and transport work has already completed in the shared
/// runtime before this runs.
#[allow(unreachable_code)]
pub(crate) fn complete_main_flash() -> bool {
    let handoff = set_main_handoff();
    if !set_stg2_boot_target(1) {
        return false;
    }
    let _ = handoff;
    unsafe {
        esp_idf_sys::vTaskDelay(100);
        esp_idf_sys::esp_restart();
    }
    true
}
