use std::thread;
use std::time::Duration;

use anyhow::{anyhow, Result};
use esp_idf_svc::partition::EspPartition;
use esp_idf_sys as sys;

use crate::commands::{CommandHandler, CommandRegistry, CommandRequest, CommandResponse};
use crate::components::settings::SharedSettings;

extern "C" {
    static mut esp_flash_default_chip: *mut sys::esp_flash_t;
    fn dmesh_boot_health_set(event: u8);
    fn dmesh_boot_handoff_set(handoff: u8);
    fn dmesh_boot_dry_run_set(dry_run: bool);
    fn dmesh_module_loader_prepare_flash(timeout_ms: u32) -> bool;
}

// Flash policy is target-specific: Main never writes its active Main
// partition, while Recovery never writes its active Recovery partition.
// Both images use the shared transport/protocol path as it is extracted.

pub fn register_commands(registry: &mut CommandRegistry, settings: SharedSettings) {
    registry.register(RecoveryCommand { settings });
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

/// Flash writes disable the instruction/data cache on ESP32. A module task
/// executes from the data-region instruction mapping, so starting one while
/// DRS2 is erasing or writing would fault with `Cache disabled but cached
/// memory region accessed`. With the C flash worker retired, the only IP
/// transport Main can still hold is a module dry-run STA. Modules may run
/// while the IP transport is otherwise idle.
pub fn command_transport_ready() -> bool {
    true
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

struct RecoveryCommand {
    settings: SharedSettings,
}

impl RecoveryCommand {
    fn persist_transport_profile(&self, request: &CommandRequest) -> Result<()> {
        let mut settings = self.settings.borrow_mut();
        let mut profile = dmesh_fw_transport::TransportProfile::new();
        dmesh_fw_transport::load_profile(&mut *settings, &mut profile);
        apply_profile_text(
            request.arg("ssid"),
            &mut profile.ssid,
            &mut profile.ssid_len,
        )?;
        apply_profile_text(
            request.arg("server"),
            &mut profile.server,
            &mut profile.server_len,
        )?;
        apply_profile_text(
            request.arg("ip"),
            &mut profile.local_ip,
            &mut profile.local_ip_len,
        )?;
        apply_profile_text(
            request.arg("gateway").or_else(|| request.arg("gw")),
            &mut profile.gateway,
            &mut profile.gateway_len,
        )?;
        apply_profile_text(
            request.arg("mask"),
            &mut profile.mask,
            &mut profile.mask_len,
        )?;
        if let Some(port) = request.arg("port") {
            profile.port = port
                .parse()
                .map_err(|_| anyhow!("invalid transport port"))?;
        }
        dmesh_fw_transport::persist_profile(&mut *settings, &profile)
            .then_some(())
            .ok_or_else(|| anyhow!("shared transport profile persistence failed"))
    }
}

fn apply_profile_text(value: Option<&str>, output: &mut [u8], length: &mut usize) -> Result<()> {
    let Some(value) = value else {
        return Ok(());
    };
    let bytes = value.as_bytes();
    if bytes.len() > output.len() {
        return Err(anyhow!("transport profile value too long"));
    }
    output[..bytes.len()].copy_from_slice(bytes);
    *length = bytes.len();
    Ok(())
}

impl CommandHandler for RecoveryCommand {
    fn name(&self) -> &'static str {
        "recovery"
    }

    fn handle(&mut self, request: &CommandRequest) -> Result<CommandResponse> {
        if let Some(op) = request.arg("op") {
            return handle_flash_operation(request, op);
        }
        if request.arg("status").is_some() {
            return Ok(CommandResponse::ok("recovery request command available"));
        }
        if !parse_bool(request.arg("request").unwrap_or("true"))? {
            return Ok(CommandResponse::ok("recovery handoff not requested"));
        }
        let dry_run = parse_bool(request.arg("dry_run").unwrap_or("false"))?;
        self.persist_transport_profile(request)?;
        request_recovery_boot(dry_run);
        let reboot = parse_bool(request.arg("reboot").unwrap_or("true"))?;
        if reboot {
            thread::spawn(|| {
                thread::sleep(Duration::from_millis(250));
                unsafe { sys::esp_restart() };
            });
        }
        Ok(CommandResponse::ok(format!(
            "recovery RTC handoff armed; Recovery will scan Direct-* with device dry_run={dry_run} reboot={reboot}"
        )))
    }
}

const RAW_BOOT_LIMIT: usize = 0x7000;
const RAW_PARTITION_TABLE: usize = 0x1000;
const FLASH_ERASE_BLOCK: usize = 0x1000;
const HIGH_FLASH_BASE: usize = 0x400000;
const HIGH_FLASH_TEST_SIZE: usize = 0x1000;

fn handle_flash_operation(request: &CommandRequest, op: &str) -> Result<CommandResponse> {
    if op == "hw-test" {
        return run_high_flash_test();
    }
    if request.arg("target") == Some("main") {
        return Err(anyhow!(
            "Main cannot safely rewrite its running partition; use Recovery for target=main"
        ));
    }
    match op {
        "status" => Ok(CommandResponse::ok(
            "flash control plane migrated to Rust Recovery; request boot handoff instead",
        )),
        "serve" | "connect" | "accept" => Err(anyhow!(
            "legacy flash transport removed; arm the Recovery boot handoff via `recovery request=true`"
        )),
        "info" => {
            let target = required(request, "target")?;
            let (address, size) = target_range(target)?;
            Ok(CommandResponse::ok(format!(
                "recovery flash target={target} address=0x{address:x} size=0x{size:x}"
            )))
        }
        "erase" => {
            let target = required(request, "target")?;
            let (_, size) = target_range(target)?;
            let offset = parse_offset(request.arg("offset").unwrap_or("0"))?;
            let length = request
                .arg("length")
                .map(parse_offset)
                .transpose()?
                .unwrap_or(size.saturating_sub(offset));
            validate_range(target, offset, length)?;
            erase_target(target, offset, length)?;
            Ok(CommandResponse::ok(format!(
                "recovery flash erased target={target} offset=0x{offset:x} length=0x{length:x}"
            )))
        }
        "write" => {
            let target = required(request, "target")?;
            if request.payload.is_empty() {
                return Err(anyhow!("recovery flash write requires binary payload"));
            }
            let offset = parse_offset(request.arg("offset").unwrap_or("0"))?;
            validate_range(target, offset, request.payload.len())?;
            write_target(target, offset, &request.payload)?;
            Ok(CommandResponse::ok(format!(
                "recovery flash wrote target={target} offset=0x{offset:x} length={} verified=true",
                request.payload.len()
            )))
        }
        "reboot" => {
            thread::spawn(|| {
                thread::sleep(Duration::from_millis(250));
                unsafe { sys::esp_restart() };
            });
            Ok(CommandResponse::ok("recovery flash reboot scheduled"))
        }
        other => Err(anyhow!("unknown recovery operation {other}")),
    }
}

fn hardware_flash_size() -> Result<usize> {
    let mut size = 0_u32;
    // esp_flash_get_size() reports the size encoded in the image header. The
    // 4 MiB-header experiment needs the physical chip size instead.
    let ret = unsafe { sys::esp_flash_get_physical_size(std::ptr::null_mut(), &mut size) };
    if ret != sys::ESP_OK {
        return Err(anyhow!("hardware flash-size query failed err=0x{ret:x}"));
    }
    Ok(size as usize)
}

fn configured_flash_size() -> Result<usize> {
    let mut size = 0_u32;
    let ret = unsafe { sys::esp_flash_get_size(std::ptr::null_mut(), &mut size) };
    if ret != sys::ESP_OK {
        return Err(anyhow!("configured flash-size query failed err=0x{ret:x}"));
    }
    Ok(size as usize)
}

fn run_high_flash_test() -> Result<CommandResponse> {
    let flash_size = hardware_flash_size()?;
    let configured_size = configured_flash_size()?;
    if flash_size <= HIGH_FLASH_BASE + HIGH_FLASH_TEST_SIZE {
        return Err(anyhow!(
            "hardware flash is only 0x{flash_size:x}; no sector above 4 MiB"
        ));
    }
    let address = flash_size - HIGH_FLASH_TEST_SIZE;
    let mut original = vec![0_u8; HIGH_FLASH_TEST_SIZE];
    read_raw_flash(address, &mut original).map_err(|error| {
        anyhow!(
            "high-flash read rejected hardware=0x{flash_size:x} configured=0x{configured_size:x} address=0x{address:x}: {error}"
        )
    })?;

    let mut pattern = vec![0_u8; HIGH_FLASH_TEST_SIZE];
    for (index, byte) in pattern.iter_mut().enumerate() {
        *byte = (index as u8).wrapping_mul(37).wrapping_add(0xa5);
    }

    raw_flash_erase(address, HIGH_FLASH_TEST_SIZE)?;
    raw_flash_write(address, &pattern)?;
    let mut readback = vec![0_u8; HIGH_FLASH_TEST_SIZE];
    read_raw_flash(address, &mut readback)?;
    if readback != pattern {
        return Err(anyhow!(
            "high-flash pattern readback mismatch at 0x{address:x}"
        ));
    }

    raw_flash_erase(address, HIGH_FLASH_TEST_SIZE)?;
    if original.iter().any(|byte| *byte != 0xff) {
        raw_flash_write(address, &original)?;
    }
    let mut restored = vec![0_u8; HIGH_FLASH_TEST_SIZE];
    read_raw_flash(address, &mut restored)?;
    if restored != original {
        return Err(anyhow!(
            "high-flash sector restore mismatch at 0x{address:x}"
        ));
    }

    Ok(CommandResponse::ok(format!(
        "hardware_flash=0x{flash_size:x} configured_flash=0x{configured_size:x} test_address=0x{address:x} length=0x{HIGH_FLASH_TEST_SIZE:x} read_write_restore=ok"
    )))
}

fn parse_offset(value: &str) -> Result<usize> {
    let value = value.trim();
    let parsed = if let Some(hex) = value.strip_prefix("0x") {
        usize::from_str_radix(hex, 16)?
    } else {
        value.parse()?
    };
    Ok(parsed)
}

fn target_range(target: &str) -> Result<(usize, usize)> {
    match target {
        "boot" | "stage2" => Ok((0, RAW_BOOT_LIMIT)),
        "partition" | "partition-table" => Ok((0x8000, RAW_PARTITION_TABLE)),
        label => {
            let partition = find_partition(label)?;
            Ok((partition.address(), partition.size()))
        }
    }
}

fn find_partition(target: &str) -> Result<EspPartition> {
    let labels: &[&str] = match target {
        "main" => &["main", "factory"],
        "recovery" => &["recovery_app", "recovery"],
        "data" | "module" => &["dmesh_store", "data"],
        "nvs" => &["nvs"],
        other => &[other],
    };
    for label in labels {
        // The partition table is static for the running image; retaining one
        // wrapper for the selected label is safe for the duration of a command.
        if let Some(partition) = unsafe { EspPartition::new(label)? } {
            return Ok(partition);
        }
    }
    Err(anyhow!("flash target partition not found: {target}"))
}

fn validate_range(target: &str, offset: usize, length: usize) -> Result<()> {
    let (_, size) = target_range(target)?;
    if offset > size || length > size - offset {
        return Err(anyhow!(
            "flash range outside target={target} offset=0x{offset:x} length=0x{length:x} size=0x{size:x}"
        ));
    }
    if length == 0 {
        return Err(anyhow!("flash range must not be empty"));
    }
    Ok(())
}

fn erase_target(target: &str, offset: usize, length: usize) -> Result<()> {
    match target {
        "boot" | "stage2" => {
            if offset % FLASH_ERASE_BLOCK != 0 || length % FLASH_ERASE_BLOCK != 0 {
                return Err(anyhow!("raw flash erase range must be 0x1000 aligned"));
            }
            raw_flash_erase(offset, length)
        }
        "partition" | "partition-table" => {
            if offset % FLASH_ERASE_BLOCK != 0 || length % FLASH_ERASE_BLOCK != 0 {
                return Err(anyhow!("raw flash erase range must be 0x1000 aligned"));
            }
            raw_flash_erase(0x8000 + offset, length)
        }
        _ => {
            let mut partition = find_partition(target)?;
            partition.erase(offset, length)?;
            Ok(())
        }
    }
}

fn write_target(target: &str, offset: usize, data: &[u8]) -> Result<()> {
    match target {
        "boot" | "stage2" => raw_flash_write(offset, data),
        "partition" | "partition-table" => raw_flash_write(0x8000 + offset, data),
        _ => {
            let mut partition = find_partition(target)?;
            partition.write_raw(offset, data)?;
            let mut verify = vec![0_u8; data.len()];
            partition.read_raw(offset, &mut verify)?;
            if verify != data {
                return Err(anyhow!(
                    "flash readback mismatch target={target} offset=0x{offset:x}"
                ));
            }
            Ok(())
        }
    }
}

fn raw_flash_erase(address: usize, length: usize) -> Result<()> {
    let ret =
        unsafe { sys::esp_flash_erase_region(std::ptr::null_mut(), address as u32, length as u32) };
    if ret != sys::ESP_OK {
        return Err(anyhow!(
            "raw flash erase failed address=0x{address:x} err=0x{ret:x}"
        ));
    }
    Ok(())
}

fn raw_flash_write(address: usize, data: &[u8]) -> Result<()> {
    let ret = unsafe {
        sys::esp_flash_write(
            std::ptr::null_mut(),
            data.as_ptr() as *const _,
            address as u32,
            data.len() as u32,
        )
    };
    if ret != sys::ESP_OK {
        return Err(anyhow!(
            "raw flash write failed address=0x{address:x} err=0x{ret:x}"
        ));
    }
    let mut verify = vec![0_u8; data.len()];
    read_raw_flash(address, &mut verify)?;
    if verify != data {
        return Err(anyhow!("raw flash readback mismatch address=0x{address:x}"));
    }
    Ok(())
}

fn read_raw_flash(address: usize, data: &mut [u8]) -> Result<()> {
    let ret = unsafe {
        sys::esp_flash_read(
            std::ptr::null_mut(),
            data.as_mut_ptr() as *mut _,
            address as u32,
            data.len() as u32,
        )
    };
    if ret != sys::ESP_OK {
        return Err(anyhow!(
            "raw flash read failed address=0x{address:x} err=0x{ret:x}"
        ));
    }
    Ok(())
}

fn required<'a>(request: &'a CommandRequest, key: &str) -> Result<&'a str> {
    request
        .arg(key)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow!("recovery requires {key}=..."))
}

fn parse_bool(value: &str) -> Result<bool> {
    match value {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        other => Err(anyhow!("invalid boolean {other}")),
    }
}
