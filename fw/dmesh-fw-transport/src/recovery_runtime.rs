//! Frozen Recovery policy entry point over the shared transport engine.
//!
//! Recovery is deliberately kept as a separate binary-facing module even
//! while the first refactor still shares the old service loop. This is the
//! seam where the future open-STA UDP6-only Recovery implementation will be
//! installed without adding Recovery branches to Main.

// TODO: strip it down to:
// - flash main
// - UDP6 + STA (open) + QUIC-lite client
// - no NAN, SD, etc.
// - BSSID/IPv6 passed via RTC temp area - no commands.
// - UART for logs, no commands.

// Keep the old prototype's raw-service adapter imports compiling while it is
// being retired. NAN, NOW, and tagged `transport.start` are intentionally not
// part of this Recovery entry point.
pub use crate::core_runtime::{espnow_association, poll_raw_service, receive_raw_service};

/// Start the Recovery runtime with its platform-owned flash completion hook.
pub fn run(complete_main_flash: fn() -> bool) {
    run_with_boot_identity(complete_main_flash);
}

/// Minimal Recovery runtime: associate as a raw UDP6 STA and service the
/// flash/object protocol. Recovery deliberately has no NAN/NOW startup, no
/// tagged command registry, and no `transport.start` state machine; its future
/// profile source is the RTC/open-AP record owned by the platform adapter.
fn run_with_boot_identity(_complete_main_flash: fn() -> bool) {
    esp_idf_sys::link_patches();

    // The profile is a placeholder until the platform supplies the persisted
    // open-AP SSID/BSSID from RTC. Marking it as STA keeps this loop explicit
    // and prevents accidentally reviving the Main command personality.
    let mut profile = crate::TransportProfile::new();
    profile.requested_transport = Some(dmesh_server::control::TransportKind::Sta);
    // No synthetic SSID is installed here: until the RTC handoff reader is
    // connected, `init_sta` reports the missing profile instead of probing an
    // arbitrary network. This keeps the reduced Recovery image safe to flash.
    crate::wifi_esp::init_sta(&profile);

    let mut raw_started = false;
    loop {
        crate::wifi_nonpromisc_probe_esp::poll();
        if !raw_started && crate::wifi_esp::start_raw_udp6(crate::core_runtime::receive_raw_udp6) {
            crate::wifi_raw_udp6_esp::set_poll_handler(Some(crate::core_runtime::poll_raw_udp6));
            raw_started = true;
            crate::commands::send_response(b"recovery raw udp6 STA bearer started");
        }
        unsafe { esp_idf_sys::vTaskDelay(10) };
    }
}
