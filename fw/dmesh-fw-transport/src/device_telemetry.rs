//! Static hardware/software telemetry shared by Main and Recovery.

pub(crate) fn receive(record: dmesh_server::tagged::Record<'_>) -> Option<alloc::vec::Vec<u8>> {
    let mut flash = 0u32;
    let flash_bytes = (unsafe { esp_idf_sys::esp_flash_get_size(core::ptr::null_mut(), &mut flash) }
        == esp_idf_sys::ESP_OK).then_some(u64::from(flash));
    #[cfg(target_arch = "riscv32")]
    let cpu_type = "esp32c6";
    #[cfg(all(not(target_arch = "riscv32"), target_feature = "esp32s3ops"))]
    let cpu_type = "esp32s3";
    #[cfg(all(not(target_arch = "riscv32"), not(target_feature = "esp32s3ops")))]
    let cpu_type = "esp32";
    // C6/S3 have a unified main SRAM address range. Classic ESP32's separate
    // instruction/data aliases do not describe physical capacity this way.
    let total_ram_bytes = if cpu_type == "esp32" { None } else {
        Some(u64::from(esp_idf_sys::SOC_DRAM_HIGH - esp_idf_sys::SOC_DRAM_LOW))
    };
    let app = unsafe { esp_idf_sys::esp_app_get_description().as_ref()? };
    let version_bytes = unsafe { core::slice::from_raw_parts(app.version.as_ptr().cast::<u8>(), app.version.len()) };
    let end = version_bytes.iter().position(|byte| *byte == 0).unwrap_or(version_bytes.len());
    let version = core::str::from_utf8(&version_bytes[..end]).ok()?;
    dmesh_server::telemetry::device_response(record, dmesh_server::telemetry::TelemetryDeviceResponse {
        version, cpu_type, total_ram_bytes, flash_bytes,
        role: if crate::recovery_runtime::active() { "recovery" } else { "main" },
    })
}
