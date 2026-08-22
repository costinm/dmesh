//! Stage2 boot-health policy retained by Main.
//!
//! This module deliberately contains no transport or Wi-Fi operation. The
//! shared Recovery/Main runtime invokes these two hooks around its validated
//! UART/NVS/STA lifecycle.

extern "C" {
    fn dmesh_boot_health_set(event: u8);
    fn dmesh_boot_handoff_set(handoff: u8);
}

/// Mark a new Main boot attempt before entering the shared runtime.
pub fn mark_main_boot_start() {
    unsafe { dmesh_boot_health_set(1) };
}

/// Mark Main healthy only after the shared runtime has initialized its
/// command/transport surface.
pub fn mark_main_boot_healthy() {
    unsafe {
        dmesh_boot_health_set(2);
        dmesh_boot_handoff_set(0);
    }
}
