//! Recovery binary shell. Shared transport, flash, STA, UART, NVS, and ESP
//! SHA code live in `dmesh-fw-transport`; only the final Recovery-to-Main
//! Stage2/RTC/reboot policy stays here.
#![no_std]
#![no_main]

mod platform;

#[no_mangle]
pub extern "C" fn app_main() {
    // Recovery can expose the identical optional module control surface as
    // Main. The loader's weak platform hooks keep hardware-only calls
    // unsupported here rather than introducing a Recovery-specific dispatcher.
    #[cfg(feature = "modules")]
    dmesh_fw_modules::register_tagged_handlers();
    dmesh_fw_transport::firmware_runtime::run(
        platform::complete_main_flash,
    );
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {
        unsafe { esp_idf_sys::vTaskDelay(1000) }
    }
}
