//! Recovery binary shell. Shared transport, flash, STA, UART, NVS, and ESP
//! SHA code live in `dmesh-fw-transport`.
#![no_std]
#![no_main]

#[no_mangle]
pub extern "C" fn app_main() {
    // Console-only identity: Recovery deliberately installs no framed UART
    // transport, so a remote-update diagnosis can still distinguish Stage2
    // selection from a fallback to Main.
    unsafe { esp_idf_sys::esp_rom_printf(b"DMESH recovery: entry\n\0".as_ptr().cast()) };
    // Recovery can expose the identical optional module control surface as
    // Main. The loader's weak platform hooks keep hardware-only calls
    // unsupported here rather than introducing a Recovery-specific dispatcher.
    #[cfg(feature = "modules")]
    dmesh_fw_modules::register_tagged_handlers();
    dmesh_fw_transport::recovery_runtime::run();
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {
        unsafe { esp_idf_sys::vTaskDelay(1000) }
    }
}
