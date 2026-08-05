use std::ffi::CString;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};
use std::thread;
use std::time::Duration;

use anyhow::{anyhow, Result};
use esp_idf_svc::partition::EspPartition;
use esp_idf_sys as sys;

use crate::commands::{CommandHandler, CommandRegistry, CommandRequest, CommandResponse};
use crate::components::settings::SharedSettings;

const REQUEST_MAGIC: &str = "0x52455131"; // REQ1
const RECOVERY_NAMESPACE: &str = "recovery";
const DEFAULT_RECOVERY_SERVER: &str = "10.78.0.1";
const DEFAULT_RECOVERY_PORT: u16 = 3336;
extern "C" {
    static mut esp_flash_default_chip: *mut sys::esp_flash_t;
    fn dmesh_boot_health_set(event: u8);
    fn dmesh_flash_tcp_start_target(
        port: u16,
        remote_ip: *const i8,
        target: *const i8,
        module: *const i8,
    ) -> bool;
    fn dmesh_flash_tcp_prepare() -> bool;
    fn dmesh_flash_tcp_poll();
    fn dmesh_flash_tcp_accept() -> bool;
    fn dmesh_flash_tcp_finished() -> bool;
    fn dmesh_module_loader_prepare_flash(timeout_ms: u32) -> bool;
}

struct PendingFlash {
    port: u16,
    server: String,
    ssid: String,
    psk: String,
    ip: String,
    gateway: String,
    netmask: String,
    target: String,
    module: String,
}

static PENDING_FLASH: OnceLock<Mutex<Option<PendingFlash>>> = OnceLock::new();
static FLASH_STARTING: AtomicBool = AtomicBool::new(false);
static FLASH_START_FAILED: AtomicBool = AtomicBool::new(false);
static FLASH_FINISHED_REPORTED: AtomicBool = AtomicBool::new(false);
static CONTROL_STATUS: OnceLock<Mutex<String>> = OnceLock::new();

fn pending_flash() -> &'static Mutex<Option<PendingFlash>> {
    PENDING_FLASH.get_or_init(|| Mutex::new(None))
}

fn set_control_status(status: impl Into<String>) {
    *CONTROL_STATUS.get_or_init(|| Mutex::new(String::new())).lock().unwrap() = status.into();
}

fn control_status() -> String {
    CONTROL_STATUS
        .get_or_init(|| Mutex::new("idle".to_owned()))
        .lock()
        .map(|status| status.clone())
        .unwrap_or_else(|_| "status lock poisoned".to_owned())
}

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
}

/// Advance the armed raw TCP flash session from Main's normal task context.
/// The potentially slow STA association is handed to a worker; the polling
/// function itself remains bounded and runtime-only and does not touch NVS.
pub fn poll_flash_tcp(settings: &SharedSettings) {
    unsafe { dmesh_flash_tcp_poll() };
    if FLASH_START_FAILED.swap(false, Ordering::AcqRel) {
        let _ = crate::components::mode::resume_from_ip_transport(settings);
        // The previous session may still have left flash_done set. Do not
        // interpret that stale completion as the result of this failed start.
        return;
    }
    if FLASH_STARTING.load(Ordering::Acquire) {
        // The STA association and TCP worker are started asynchronously. The
        // C transport still contains the previous session's completion bit
        // until the worker resets it, so skip completion polling while start
        // is in progress.
        return;
    }
    if let Some(pending) = pending_flash().lock().unwrap().take() {
        if FLASH_STARTING.swap(true, Ordering::AcqRel) {
            set_control_status("flash start already in progress");
            return;
        }
        set_control_status(format!("starting STA server={} port={}", pending.server, pending.port));
        FLASH_FINISHED_REPORTED.store(false, Ordering::Release);
        // Association and static-IP setup can take up to 15 seconds. Keep it
        // out of Main's primary loop so UART responses, NAN bookkeeping, and
        // an emergency managed reset remain serviceable while the control
        // plane is connecting.
        let spawn_result = thread::Builder::new()
            .name("flash-sta-start".to_owned())
            .spawn(move || {
                let result = crate::components::wifi::start_flash_sta(
                    &pending.ssid,
                    &pending.psk,
                    &pending.ip,
                    &pending.gateway,
                    &pending.netmask,
                ).and_then(|()| {
                    let remote_ip = CString::new(pending.server.as_str())
                        .map_err(|err| anyhow!("invalid flash server address: {err}"))?;
                    let target = CString::new(pending.target.as_str())
                        .map_err(|err| anyhow!("invalid flash target: {err}"))?;
                    let module = CString::new(pending.module.as_str())
                        .map_err(|err| anyhow!("invalid flash module: {err}"))?;
                    if unsafe {
                        dmesh_flash_tcp_start_target(
                            pending.port,
                            remote_ip.as_ptr().cast(),
                            target.as_ptr().cast(),
                            module.as_ptr().cast(),
                        )
                    } {
                        crate::components::ip_command::start(
                            &pending.server,
                            pending.port.saturating_add(1),
                        )?;
                        set_control_status(format!(
                            "active STA server={} data_port={} reverse_command_port={}",
                            pending.server,
                            pending.port,
                            pending.port.saturating_add(1)
                        ));
                        Ok(())
                    } else {
                        Err(anyhow!("flash TCP task could not start"))
                    }
                });
                FLASH_STARTING.store(false, Ordering::Release);
                if let Err(err) = result {
                    set_control_status(format!("start failed: {err}"));
                    crate::components::telemetry::record_log(format!(
                        "event type=flash.control_plane start=false message={}",
                        crate::commands::protocol::escape_value(&err.to_string())
                    ));
                    FLASH_START_FAILED.store(true, Ordering::Release);
                }
            });
        if let Err(err) = spawn_result {
            FLASH_STARTING.store(false, Ordering::Release);
            set_control_status(format!("start failed: {err}"));
            FLASH_START_FAILED.store(true, Ordering::Release);
        }
        return;
    }
    if unsafe { dmesh_flash_tcp_finished() } {
        let succeeded = unsafe { dmesh_flash_tcp_accept() };
        if FLASH_FINISHED_REPORTED.swap(true, Ordering::AcqRel) {
            return;
        }
        if !succeeded {
            set_control_status("transfer failed");
            crate::components::telemetry::record_log(
                "event type=flash.control_plane transfer=failed",
            );
            let _ = crate::components::mode::resume_from_ip_transport(settings);
        } else {
            // DONE is the end of the data-plane session.  Do not retain the
            // IP transport state after it: doing so left Main looking alive
            // over UART while its normal NAN/command scheduler remained
            // suspended, and a later command could time out indefinitely.
            crate::components::telemetry::record_log(
                "event type=flash.control_plane transfer=complete resume=immediate",
            );
            set_control_status("transfer complete; resuming normal transport");
            let _ = crate::components::mode::resume_from_ip_transport(settings);
            set_control_status("idle");
        }
    }
}

/// Flash writes disable the instruction/data cache on ESP32. A module task
/// executes from the data-region instruction mapping, so starting one while
/// DRS2 is erasing or writing would fault with `Cache disabled but cached
/// memory region accessed`. Callers may dispatch modules only once the active
/// transfer has reported completion.
pub fn command_transport_ready() -> bool {
    if !crate::components::mode::ip_transport_active() {
        return true;
    }
    unsafe { dmesh_flash_tcp_finished() }
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
        if let Some(op) = request.arg("op") {
            return handle_flash_operation(request, op);
        }
        if request.arg("status").is_some() {
            return Ok(CommandResponse::ok("recovery request command available"));
        }
        if parse_bool(request.arg("clear").unwrap_or("false"))? {
            clear_request_marker()?;
            return Ok(CommandResponse::ok("recovery request marker cleared"));
        }
        if !parse_bool(request.arg("request").unwrap_or("true"))? {
            return Ok(CommandResponse::ok("recovery request not written"));
        }

        // Empty SSID selects the open Direct-*-Dmesh scan path in Recovery.
        // Empty IP selects the deterministic MAC-derived 10.78 address.
        let ssid = request.arg("ssid").unwrap_or("");
        let server = request
            .arg("server")
            .filter(|value| !value.is_empty())
            .unwrap_or(DEFAULT_RECOVERY_SERVER);
        let local_ip = request.arg("ip").unwrap_or("");
        let port: u16 = request
            .arg("port")
            .filter(|value| !value.is_empty())
            .map(str::parse)
            .transpose()
            .map_err(|err| anyhow!("invalid recovery port: {err}"))?
            .unwrap_or(DEFAULT_RECOVERY_PORT);
        if port == 0 {
            return Err(anyhow!("recovery port must be nonzero"));
        }
        let password = request.arg("password").unwrap_or("");
        let update_url = request
            .arg("url")
            .unwrap_or("tcp://configured-recovery-server");
        let flags = request.arg("flags").unwrap_or("0");

        write_request(ssid, password, server, local_ip, port, update_url, flags)?;
        let reboot = parse_bool(request.arg("reboot").unwrap_or("true"))?;
        if reboot {
            thread::spawn(|| {
                thread::sleep(Duration::from_millis(250));
                unsafe { sys::esp_restart() };
            });
        }
        Ok(CommandResponse::ok(format!(
            "recovery request written server={server} port={port} ssid_scan={} mac_ip={} reboot={reboot}",
            ssid.is_empty(), local_ip.is_empty()
        )))
    }
}

const RAW_BOOT_LIMIT: usize = 0x7000;
const RAW_PARTITION_TABLE: usize = 0x1000;
const TCP_TARGET_BOOT: u8 = 1;
const TCP_TARGET_PARTITION: u8 = 2;
const TCP_TARGET_RECOVERY: u8 = 3;
const TCP_TARGET_NVS: u8 = 4;
const TCP_TARGET_DATA: u8 = 5;
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
        "status" => Ok(CommandResponse::ok(format!("flash control plane {}", control_status()))),
        "serve" => {
            let target = required(request, "target")?.to_owned();
            let port: u16 = required(request, "port")?
                .parse()
                .map_err(|err| anyhow!("invalid flash port: {err}"))?;
            // Do not resolve an EspPartition in the command task after IP STA
            // has taken the flash/network locks.  The TCP worker validates the
            // target and resolves the partition after receiving the header.
            if !matches!(
                target.as_str(),
                "boot" | "stage2" | "partition" | "partition-table" | "recovery" | "nvs" | "data" | "module"
            ) {
                return Err(anyhow!("unsupported TCP flash target={target}"));
            }
            let remote_ip = CString::new("")?;
            let target_c = CString::new(target.as_str())?;
            let module_c = CString::new(request.arg("module").unwrap_or(""))?;
            // This C entry point creates the FreeRTOS worker and returns; the
            // worker owns the socket, erase, write, and TCP wait. Keep the
            // control-plane handler synchronous only for startup so its CBOR
            // response is sent before the data-plane handoff.
            let started = unsafe {
                dmesh_flash_tcp_start_target(
                    port,
                    remote_ip.as_ptr().cast(),
                    target_c.as_ptr().cast(),
                    module_c.as_ptr().cast(),
                )
            };
            if !started {
                return Err(anyhow!("flash TCP task could not start"));
            }
            Ok(CommandResponse::ok(format!(
                "flash TCP server port={port} negotiated"
            )))
        }
        "connect" => {
            if FLASH_STARTING.load(Ordering::Acquire) {
                return Err(anyhow!("flash control plane start already in progress"));
            }
            let target = required(request, "target")?.to_owned();
            let port: u16 = required(request, "port")?
                .parse()
                .map_err(|err| anyhow!("invalid flash port: {err}"))?;
            let server = required(request, "server")?;
            let ssid = required(request, "ssid")?;
            let local_ip = required(request, "ip")?;
            let gateway = request
                .arg("gateway")
                .or_else(|| request.arg("server"))
                .unwrap_or("10.78.0.1");
            let netmask = request.arg("mask").unwrap_or("255.255.0.0");
            if !matches!(
                target.as_str(),
                "boot" | "stage2" | "partition" | "partition-table" | "recovery" | "nvs" | "data" | "module"
            ) {
                return Err(anyhow!("unsupported TCP flash target={target}"));
            }
            if target == "module" && !unsafe { dmesh_module_loader_prepare_flash(2000) } {
                return Err(anyhow!("module task did not quiesce before flash"));
            }
            let mut slot = pending_flash().lock().unwrap();
            if slot.is_some() || crate::components::mode::ip_transport_active() {
                return Err(anyhow!("flash control plane already active"));
            }
            *slot = Some(PendingFlash {
                port,
                server: server.to_owned(),
                ssid: ssid.to_owned(),
                psk: request.arg("psk").unwrap_or("").to_owned(),
                ip: local_ip.to_owned(),
                gateway: gateway.to_owned(),
                netmask: netmask.to_owned(),
                target: target.clone(),
                module: request.arg("module").unwrap_or("").to_owned(),
            });
            if !unsafe { dmesh_flash_tcp_prepare() } {
                slot.take();
                return Err(anyhow!("flash control plane already active"));
            }
            set_control_status(format!("pending server={server} port={port}"));
            Ok(CommandResponse::ok(format!(
                "flash control plane pending server={server} port={port}; NAN remains active until acknowledged"
            )))
        }
        "accept" => {
            let completed = unsafe { dmesh_flash_tcp_accept() };
            if !completed {
                return Err(anyhow!("flash TCP session failed"));
            }
            Ok(CommandResponse::ok("flash TCP complete"))
        }
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

fn write_request(
    ssid: &str,
    password: &str,
    server: &str,
    local_ip: &str,
    port: u16,
    update_url: &str,
    flags: &str,
) -> Result<()> {
    let namespace = CString::new(RECOVERY_NAMESPACE)?;
    let mut handle = 0;
    let ret = unsafe {
        sys::nvs_open(
            namespace.as_ptr(),
            sys::nvs_open_mode_t_NVS_READWRITE,
            &mut handle,
        )
    };
    if ret != sys::ESP_OK {
        return Err(anyhow!("nvs_open(recovery) failed err=0x{ret:x}"));
    }

    let result = (|| {
        set_str(handle, "request_magic", REQUEST_MAGIC)?;
        set_str(handle, "request_version", "1")?;
        set_str(handle, "ssid", ssid)?;
        set_str(handle, "password", password)?;
        set_str(handle, "server", server)?;
        set_str(handle, "ip", local_ip)?;
        set_str(handle, "update_url", update_url)?;
        let flags = parse_u32(flags)?;
        let ret = unsafe { sys::nvs_set_u32(handle, c_string("flags")?.as_ptr(), flags) };
        if ret != sys::ESP_OK {
            return Err(anyhow!("nvs_set_u32(flags) failed err=0x{ret:x}"));
        }
        let ret = unsafe { sys::nvs_set_u16(handle, c_string("port")?.as_ptr(), port) };
        if ret != sys::ESP_OK {
            return Err(anyhow!("nvs_set_u16(port) failed err=0x{ret:x}"));
        }
        let ret = unsafe { sys::nvs_commit(handle) };
        if ret != sys::ESP_OK {
            return Err(anyhow!("nvs_commit(recovery) failed err=0x{ret:x}"));
        }
        Ok(())
    })();
    unsafe { sys::nvs_close(handle) };
    result
}

fn set_str(handle: sys::nvs_handle_t, key: &str, value: &str) -> Result<()> {
    let key = c_string(key)?;
    let value = CString::new(value)?;
    let ret = unsafe { sys::nvs_set_str(handle, key.as_ptr(), value.as_ptr()) };
    if ret != sys::ESP_OK {
        return Err(anyhow!("nvs_set_str({key:?}) failed err=0x{ret:x}"));
    }
    Ok(())
}

fn clear_request_marker() -> Result<()> {
    let namespace = CString::new(RECOVERY_NAMESPACE)?;
    let mut handle = 0;
    let ret = unsafe {
        sys::nvs_open(
            namespace.as_ptr(),
            sys::nvs_open_mode_t_NVS_READWRITE,
            &mut handle,
        )
    };
    if ret != sys::ESP_OK {
        return Err(anyhow!("nvs_open(recovery) failed err=0x{ret:x}"));
    }
    let result = (|| {
        for key in ["request_magic", "request_version", "flags"] {
            let key = c_string(key)?;
            let ret = unsafe { sys::nvs_erase_key(handle, key.as_ptr()) };
            if ret != sys::ESP_OK && ret != sys::ESP_ERR_NVS_NOT_FOUND {
                return Err(anyhow!("nvs_erase_key failed err=0x{ret:x}"));
            }
        }
        let ret = unsafe { sys::nvs_commit(handle) };
        if ret != sys::ESP_OK {
            return Err(anyhow!("nvs_commit(recovery) failed err=0x{ret:x}"));
        }
        Ok(())
    })();
    unsafe { sys::nvs_close(handle) };
    result
}

fn c_string(value: &str) -> Result<CString> {
    Ok(CString::new(value)?)
}

fn parse_u32(value: &str) -> Result<u32> {
    let value = value.trim();
    if let Some(hex) = value.strip_prefix("0x") {
        Ok(u32::from_str_radix(hex, 16)?)
    } else {
        Ok(value.parse()?)
    }
}
