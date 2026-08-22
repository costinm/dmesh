mod platform;

fn main() {
    app_main();
}

#[no_mangle]
pub extern "C" fn app_main() {
    platform::mark_main_boot_start();
    #[cfg(feature = "modules")]
    dmesh_fw_modules::register_tagged_handlers();
    dmesh_fw_transport::firmware_runtime::FirmwareRuntime::main(
        platform::mark_main_boot_healthy,
    )
    .run();
}
