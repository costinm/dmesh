extern crate alloc;

mod platform;

fn receive_boot_control(record: dmesh_server::tagged::Record<'_>) -> Option<alloc::vec::Vec<u8>> {
    use dmesh_server::{services, tagged::Name};
    if record.to.is_some()
        || record.component != Some(Name::Tag(services::BOOT_COMPONENT))
        || record.method != Some(Name::Tag(services::BOOT_RECOVERY_METHOD))
        || record.params.is_some()
        || record.data.is_some()
        || record.fields.is_some()
        || record.result.is_some()
        || record.error.is_some()
    {
        return None;
    }
    if platform::schedule_recovery_boot() {
        Some(alloc::vec::Vec::from(&b"recovery scheduled"[..]))
    } else {
        None
    }
}

fn main() {
    app_main();
}

#[no_mangle]
pub extern "C" fn app_main() {
    // Kept adjacent to the Stage2 handoff write while lora4 early boot is
    // diagnosed: this distinguishes a failed Main entry from a bad RTC write
    // before the runtime can emit its own ROM markers.
    unsafe { esp_idf_sys::esp_rom_printf(b"DMESH main: entry\n\0".as_ptr().cast()) };
    platform::mark_main_boot_start();
    assert!(dmesh_server::services::register_tagged_component(
        dmesh_server::services::BOOT_COMPONENT,
        receive_boot_control,
    ));
    unsafe { esp_idf_sys::esp_rom_printf(b"DMESH main: health-start\n\0".as_ptr().cast()) };
    #[cfg(feature = "modules")]
    dmesh_fw_modules::register_tagged_handlers();
    // BLE is linked as a Main bearer. Its CoC byte-stream adapter will feed
    // this same runtime; it never revives the retired command/GATT payload
    // dispatcher.
    let _ = dmesh_ble::link_snapshot();
    // Route ESP-IDF logs through the UART writer queue. Direct console writes
    // would splice text into PPP-framed tagged responses.
    unsafe {
        esp_idf_sys::esp_log_set_vprintf(Some(dmesh_uart_log_vprintf));
    }
    dmesh_fw_transport::main_runtime::run(platform::mark_main_boot_healthy);
}

extern "C" {
    fn dmesh_uart_log_vprintf(format: *const core::ffi::c_char, args: esp_idf_sys::va_list) -> i32;
}

/// Module-to-transport bridge for a completed radio receive.  This is invoked
/// only by an active module task; it neither starts a module nor retains the
/// packet after the current bearer fan-out returns.
#[no_mangle]
pub unsafe extern "C" fn dmesh_module_lora_receive(
    payload: *const u8,
    payload_len: usize,
    rssi: i16,
    snr: i8,
) -> i32 {
    if payload.is_null() || payload_len == 0 {
        return -1;
    }
    let payload = core::slice::from_raw_parts(payload, payload_len);
    i32::from(dmesh_fw_transport::main_runtime::forward_lora_packet(
        payload, rssi, snr,
    ))
}
