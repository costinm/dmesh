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
    dmesh_fw_transport::main_runtime::run(platform::mark_main_boot_healthy);
}
