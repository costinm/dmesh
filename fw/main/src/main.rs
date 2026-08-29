mod platform;

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
    unsafe { esp_idf_sys::esp_rom_printf(b"DMESH main: health-start\n\0".as_ptr().cast()) };
    #[cfg(feature = "modules")]
    dmesh_fw_modules::register_tagged_handlers();
    // Route ESP-IDF logs through the UART writer queue. Direct console writes
    // would splice text into PPP-framed tagged responses.
    unsafe {
        esp_idf_sys::esp_log_set_vprintf(Some(dmesh_uart_log_vprintf));
    }
    dmesh_fw_transport::main_runtime::run(platform::mark_main_boot_healthy);
}

extern "C" {
    fn dmesh_uart_log_vprintf(
        format: *const core::ffi::c_char,
        args: esp_idf_sys::va_list,
    ) -> i32;
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
    i32::from(dmesh_fw_transport::main_runtime::forward_lora_packet(payload, rssi, snr))
}
