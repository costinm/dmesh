//! Recovery binary shell. Shared transport, flash, STA, UART, NVS, and ESP
//! SHA code live in `dmesh-fw-transport`; only the final Recovery-to-Main
//! Stage2/RTC/reboot policy stays here.
#![no_std]
#![no_main]

mod platform;

#[no_mangle]
pub extern "C" fn app_main() {
    dmesh_fw_transport::recovery_runtime::run(
        platform::complete_main_flash,
    );
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {
        unsafe { esp_idf_sys::vTaskDelay(1000) }
    }
}
