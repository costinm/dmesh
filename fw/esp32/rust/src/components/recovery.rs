use anyhow::{Result, anyhow};
use esp_idf_sys as sys;

use crate::commands::{CommandHandler, CommandRegistry, CommandRequest, CommandResponse};

extern "C" {
    static mut esp_flash_default_chip: *mut sys::esp_flash_t;
    fn dmesh_boot_health_set(event: u8);
    fn dmesh_boot_handoff_set(handoff: u8);
    fn dmesh_boot_dry_run_set(dry_run: bool);
}

// Flash policy is target-specific: Main never writes its active Main
// partition, while Recovery never writes its active Recovery partition.
// Both images use the shared transport/protocol path as it is extracted.

pub fn register_commands(registry: &mut CommandRegistry) {
    registry.register(RecoveryCommand);
}

/// Tell the second-stage bootloader that Main has started a new attempt.
/// Main calls this before the rest of product initialization; if it crashes,
/// the marker remains `main_start` and the RTC failure counter is retained.
pub fn mark_main_boot_start() {
    unsafe { dmesh_boot_health_set(1) };
}

/// Tell the second-stage bootloader that Main reached its healthy runtime.
pub fn mark_main_boot_healthy() {
    unsafe { dmesh_boot_health_set(2) };
    unsafe { dmesh_boot_handoff_set(0) };
}

pub fn request_recovery_boot(dry_run: bool) {
    unsafe { dmesh_boot_handoff_set(1) };
    unsafe { dmesh_boot_dry_run_set(dry_run) };
}

/// Replace the ESP-IDF image-header flash limit with the size detected from
/// the physical chip. The image header is needed by the boot ROM/bootloader,
/// but it should not permanently limit an application from using additional
/// flash that the hardware actually provides.
pub fn configure_flash_size_from_hardware() -> Result<(usize, usize)> {
    let mut physical_size = 0_u32;
    let mut configured_size = 0_u32;
    let chip = unsafe { esp_flash_default_chip };
    if chip.is_null() {
        return Err(anyhow!("default flash chip is not initialized"));
    }
    let ret = unsafe { sys::esp_flash_get_size(chip, &mut configured_size) };
    if ret != sys::ESP_OK {
        return Err(anyhow!("configured flash-size query failed err=0x{ret:x}"));
    }
    let ret = unsafe { sys::esp_flash_get_physical_size(chip, &mut physical_size) };
    if ret != sys::ESP_OK {
        return Err(anyhow!("physical flash-size query failed err=0x{ret:x}"));
    }
    let configured_size = configured_size as usize;
    let physical_size = physical_size as usize;
    if physical_size < configured_size {
        return Err(anyhow!(
            "physical flash size 0x{physical_size:x} is below configured size 0x{configured_size:x}"
        ));
    }
    // ESP-IDF 6 makes esp_flash_t opaque, so its image-header `size` member
    // cannot be modified from Rust. Raw high-flash operations use the
    // physical-size API and explicit bounds instead.
    Ok((configured_size, physical_size))
}

struct RecoveryCommand;

impl CommandHandler for RecoveryCommand {
    fn name(&self) -> &'static str {
        "recovery"
    }

    fn handle(&mut self, request: &CommandRequest) -> Result<CommandResponse> {
        if request.arg("status").is_some() {
            return Ok(CommandResponse::ok("recovery request command available"));
        }
        if !parse_bool(request.arg("request").unwrap_or("true"))? {
            return Ok(CommandResponse::ok("recovery handoff not requested"));
        }
        let dry_run = parse_bool(request.arg("dry_run").unwrap_or("false"))?;
        request_recovery_boot(dry_run);
        let reboot = parse_bool(request.arg("reboot").unwrap_or("true"))?;
        if reboot {
            if !dmesh_fw_transport::task_esp::schedule_restart_ms(250) {
                return Err(anyhow!("recovery restart scheduler unavailable"));
            }
        }
        Ok(CommandResponse::ok(format!(
            "recovery RTC handoff armed; Recovery will scan Direct-* with device dry_run={dry_run} reboot={reboot}"
        )))
    }
}

fn parse_bool(value: &str) -> Result<bool> {
    match value {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        other => Err(anyhow!("invalid boolean {other}")),
    }
}
