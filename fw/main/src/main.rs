extern crate alloc;

#[cfg(feature = "ble-stack")]
mod ble;
mod loader_flash;
mod pairing;

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
    // Return the normal CBOR response envelope on the request stream.
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
    Some(alloc::vec::Vec::from(&response[..used]))
}

struct BootRecoveryHandler;

impl dmesh_server::stream::StreamHandler for BootRecoveryHandler {
    fn open<'a>(
        &'a self,
        request: dmesh_server::stream::Request<'a>,
    ) -> dmesh_server::stream::OpenFuture<'a> {
        use dmesh_server::stream::{Outcome, Response};
        let response = match receive_boot_control(request.record) {
            Some(header) => Response::header(header).after_finish(|| {
                unsafe {
                    esp_idf_sys::esp_rom_printf(
                        b"DMESH main: recovery response finished\n\0"
                            .as_ptr()
                            .cast(),
                    )
                };
                let _ = dmesh_fw_transport::rtc::request_recovery_boot();
            }),
            None => Response::header(dmesh_server::stream::error_header(
                request.record.id,
                b"invalid boot.recovery request",
            )),
        };
        alloc::boxed::Box::pin(core::future::ready(Some(Outcome::Respond(response))))
    }
}

fn main() {
    app_main();
}

/// BLE is a Main sidecar, not a prerequisite for the infrastructure STA.
/// Starting it after the radio-ready edge prevents the classic ESP32
/// coexistence allocator from racing the first WPA authentication while still
/// restoring BLE automatically for both associated and NAN/NOW boots.
#[cfg(feature = "ble-stack")]
fn start_ble_after_radio_ready() {
    if !dmesh_ble::boot_enabled() {
        return;
    }
    match dmesh_ble::start_dmesh_service(dmesh_fw_transport::main_runtime::shared_secret_exists()) {
        Ok(()) => unsafe {
            esp_idf_sys::esp_rom_printf(b"DMESH main: BLE auto start\n\0".as_ptr().cast());
        },
        Err(_) => unsafe {
            esp_idf_sys::esp_rom_printf(b"DMESH main: BLE auto start failed\n\0".as_ptr().cast());
        },
    }
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
    let _ = esp_idf_sys::link_patches();
    assert!(dmesh_server::registry::register_stream(
        dmesh_server::registry::methods::BOOT_RECOVERY,
        BootRecoveryHandler,
    ));
    #[cfg(feature = "ble-stack")]
    ble::register();
    pairing::register();
    loader_flash::start();
    unsafe { esp_idf_sys::esp_rom_printf(b"DMESH main: health-start\n\0".as_ptr().cast()) };
    #[cfg(feature = "modules")]
    dmesh_fw_modules::register_tagged_handlers();
    // Capture formatted ESP-IDF output as CBOR LogRecord entries in Main's
    // shared packet-pool history. Do not write routine logs onto framed UART.
    unsafe {
        esp_idf_sys::esp_log_set_vprintf(Some(dmesh_uart_log_vprintf));
    }
    #[cfg(feature = "ble-stack")]
    {
        let ble_auto = dmesh_fw_transport::main_runtime::boot_ble_auto();
        dmesh_ble::configure_boot(ble_auto);
        ble::install();
        if !ble_auto {
            unsafe {
                esp_idf_sys::esp_rom_printf(b"DMESH main: BLE auto disabled\n\0".as_ptr().cast())
            };
        }
        if ble_auto {
            dmesh_fw_transport::main_runtime::run_with_boot_radio_ready(
                dmesh_fw_transport::rtc::mark_main_healthy,
                start_ble_after_radio_ready,
            );
        } else {
            dmesh_fw_transport::main_runtime::run(dmesh_fw_transport::rtc::mark_main_healthy);
        }
    }
    #[cfg(not(feature = "ble-stack"))]
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
