extern crate alloc;

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
    // A stream handler always returns a correlated tagged record.  Returning
    // bare text here left the caller without the normal response contract and
    // prevented the RTC handoff from being tied to delivery of that response.
    let id = record.id?;
    let mut response = [0u8; 64];
    let used = dmesh_server::tagged::encode_numeric_data_response(
        services::BOOT_COMPONENT,
        services::BOOT_RECOVERY_METHOD,
        id,
        b"recovery scheduled",
        true,
        &mut response,
    )?;
    // This remains one transition log per accepted command; Recovery's UART
    // console is deliberately output-only, so it is also the bounded fallback
    // evidence when a remote client loses the terminal stream response.
    unsafe { esp_idf_sys::esp_rom_printf(b"DMESH main: recovery requested\n\0".as_ptr().cast()) };
    dmesh_fw_transport::rtc::request_recovery_boot().then(|| {
        unsafe {
            esp_idf_sys::esp_rom_printf(b"DMESH main: recovery response queued\n\0".as_ptr().cast())
        };
        alloc::vec::Vec::from(&response[..used])
    })
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
    let handoff = dmesh_fw_transport::rtc::handoff();
    unsafe {
        esp_idf_sys::esp_rom_printf(
            if handoff == 1 {
                b"DMESH main: entry handoff=recovery\n\0".as_ptr()
            } else if handoff == 2 {
                b"DMESH main: entry handoff=main\n\0".as_ptr()
            } else {
                b"DMESH main: entry handoff=normal\n\0".as_ptr()
            }
            .cast(),
        )
    };
    dmesh_fw_transport::rtc::mark_main_start();
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
    dmesh_fw_transport::main_runtime::run(dmesh_fw_transport::rtc::mark_main_healthy);
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
