//! Main is the Recovery-core transport image plus a Stage2 health shim.
//!
//! Do not add Wi-Fi initialization, ESP-IDF Wi-Fi calls, a second transport
//! loop, or Main-specific radio callbacks here. `dmesh-fw-transport` owns the
//! validated UART/NVS/STA/raw-UDP6 lifecycle shared with Recovery; Main only
//! supplies its boot-health transition. Optional product modules will be
//! registered as explicit shared-service handlers when they are reintroduced.

mod components;

fn main() {
    app_main();
}

#[no_mangle]
pub extern "C" fn app_main() {
    components::recovery::mark_main_boot_start();
    // Module components are an application extension of the shared tagged
    // control handler. This registers no Wi-Fi callback and does not start a
    // module; the shared Recovery runtime remains the only radio owner.
    dmesh_fw_modules::register_tagged_handlers();
    dmesh_fw_transport::recovery_runtime::run_main(
        components::recovery::mark_main_boot_healthy,
    );
}
