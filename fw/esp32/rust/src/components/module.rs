//! Flash-mapped dynamic modules. Module tasks have no direct access to the
//! command registry: service calls are copied here and dispatched by Main.

use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};

use anyhow::{anyhow, Result};
use minicbor::Encoder;

use crate::commands::{CommandHandler, CommandRegistry, CommandRequest, CommandResponse};
use crate::components::telemetry;

const MODULE_ALIGN: u32 = 0x10000;
const MODULE_HW_SLOT: u32 = 1;
const MAX_SERVICE_CALLS: usize = 8;
const MAX_SERVICE_BYTES: usize = 4096;

static MODULE_INITIALIZED: AtomicBool = AtomicBool::new(false);
static MODULE_INIT_ONCE: OnceLock<()> = OnceLock::new();
// TCP flash temporarily owns the IP STA and must quiesce NAN. Other
// transports (FSK/NAN/future QUIC-like links) retain their radio owner.
static FLASH_TCP_TRANSPORT_ACTIVE: AtomicBool = AtomicBool::new(false);

fn setting_snapshot() -> &'static Mutex<BTreeMap<String, String>> {
    static SNAPSHOT: OnceLock<Mutex<BTreeMap<String, String>>> = OnceLock::new();
    SNAPSHOT.get_or_init(|| Mutex::new(BTreeMap::new()))
}

#[repr(C)]
struct ModuleLoraConfig {
    abi_version: u32,
    size: u32,
    chip: u32,
    frequency_hz: u32,
    bandwidth_hz: u32,
    spreading_factor: u32,
    spi_host: i32,
    sync_word: u8,
    tx_power: u8,
    reset_pin: i8,
    cs_pin: i8,
    irq_pin: i8,
    busy_pin: i8,
    sck_pin: i8,
    miso_pin: i8,
    mosi_pin: i8,
    board_power_pin: i32,
    board_power_level: i32,
    sx1262_dio2_rf_switch: i32,
    sx1262_tcxo_mv: i32,
    sx1262_pa_duty: i32,
    sx1262_pa_hp: i32,
    sx1262_pa_device: i32,
    sx1262_pa_lut: i32,
    sx1262_sync_word: i32,
    sx1262_rx_timeout_ms: i32,
    coding_rate: i32,
    preamble: i32,
    crc: i32,
    cad_rx: i32,
    cad_interval_ms: u32,
    cad_rx_ms: u32,
}

const _: () = assert!(std::mem::size_of::<ModuleLoraConfig>() == 104);

extern "C" {
    fn dmesh_module_loader_init();
    fn dmesh_module_loader_refresh_header() -> bool;
    fn dmesh_module_loader_prepare_flash(timeout_ms: u32) -> bool;
    fn dmesh_module_flash_supported() -> bool;
    fn dmesh_module_psram_exec_supported() -> bool;
    fn dmesh_module_psram_exec_reason() -> *const u8;
    fn dmesh_module_loader_header_valid() -> bool;
    fn dmesh_module_loader_is_lora() -> bool;
    fn dmesh_module_loader_offset() -> u32;
    fn dmesh_module_loader_image_size() -> u32;
    fn dmesh_module_loader_required_stack_words() -> u32;
    fn dmesh_module_lora_configure(config: *const ModuleLoraConfig) -> i32;
    fn dmesh_module_lora_update_config(config: *const ModuleLoraConfig) -> i32;
    fn dmesh_module_lora_command(args: *const u8, args_len: usize,
                                 payload: *const u8, payload_len: usize) -> i32;
    fn dmesh_module_loader_task_done() -> bool;
    fn dmesh_module_loader_last_result() -> i32;
    fn dmesh_module_loader_runtime_ms() -> u32;
    fn dmesh_module_loader_max_runtime_ms() -> u32;
    fn dmesh_module_loader_task_runs() -> u32;
    fn dmesh_module_loader_stack_high_water_words() -> u32;
    fn dmesh_module_loader_stage() -> u32;
    fn dmesh_module_loader_spi_calls() -> u32;
    fn dmesh_module_loader_spi_errors() -> u32;
    fn dmesh_module_loader_lora_poll_count() -> u32;
    fn dmesh_module_loader_lora_irq_wakes() -> u32;
    fn dmesh_module_loader_lora_irq_timeouts() -> u32;
    fn dmesh_module_loader_last_lora_payload_len() -> u32;
    fn dmesh_module_loader_last_lora_command_len() -> u32;
    fn dmesh_module_loader_module_event_calls() -> u32;
    fn dmesh_module_loader_last_module_event_id() -> u32;
    fn dmesh_module_loader_entry_args_len() -> u32;
    fn dmesh_module_loader_entry_args() -> *const u8;
    fn dmesh_module_loader_last_lora_command() -> *const u8;
    fn dmesh_module_loader_flash_connect_attempts() -> u32;
    fn dmesh_module_loader_flash_connect_errno() -> i32;
    fn dmesh_module_loader_flash_connect_port() -> u16;
    fn dmesh_module_loader_flash_connect_host() -> *const u8;
    fn dmesh_module_start_service(
        service_tag: u16,
        offset: u32,
        size: u32,
        payload: *const u8,
        payload_len: usize,
        args: *const u8,
        args_len: usize,
    ) -> i32;
}

/// Cache the module header once during Main startup. The general data region
/// may be reused by other stores; invocation never scans or reads it again.
/// Initialize the optional module exactly once, on an explicit module/LoRa
/// command. Main must remain bootable even when a module image is stale or
/// incompatible with the current firmware ABI.
pub fn ensure_initialized(settings: &crate::components::settings::SharedSettings) {
    MODULE_INIT_ONCE.get_or_init(|| {
        unsafe { dmesh_module_loader_init() };
        // Do not let boot-time capability checks call into the loader before
        // this point.  In particular, a bad module must not be able to break
        // Main before an explicit module/lora command requests it.
        MODULE_INITIALIZED.store(true, Ordering::Release);
        // Loading and host configuration are deliberately side-effect free.
        // In particular, do not initialize SPI or start the LoRa RX loop here:
        // `module op=status` and capability probes must remain bounded, and
        // the module must only own the radio after an explicit `lora`/`module
        // run` command asks it to do so.
    });
}

fn configure_lora(settings: &crate::components::settings::SharedSettings) -> Result<()> {
    if !unsafe { dmesh_module_loader_is_lora() } {
        return Ok(());
    }
    let config = lora_config_from_settings(settings);
    let rc = unsafe { dmesh_module_lora_configure(&config) };
    if rc != 0 {
        telemetry::record_log(format!(
            "event type=lora.module_host ok=false result={rc}"
        ));
        return Err(anyhow!("module LoRa host configuration failed result={rc}"));
    }
    Ok(())
}

/// Refresh the thread-safe view used by module callbacks. The module never
/// receives an NVS handle; Main remains responsible for validation and writes.
pub fn refresh_settings_snapshot(settings: &crate::components::settings::SharedSettings) {
    let values = {
        let settings = settings.borrow();
        settings
            .known_keys()
            .iter()
            .filter_map(|key| settings.get_str(key).ok().flatten().map(|value| ((*key).to_owned(), value)))
            .collect::<BTreeMap<_, _>>()
    };
    if let Ok(mut snapshot) = setting_snapshot().lock() {
        *snapshot = values;
    }
}

fn valid_callback_key(key: *const u8, key_len: usize) -> Option<&'static [u8]> {
    if key.is_null() || key_len == 0 || key_len > 64 {
        return None;
    }
    // The lifetime is only used inside the callback; the pointer is borrowed
    // from the caller for that duration.
    Some(unsafe { core::slice::from_raw_parts(key, key_len) })
}

#[derive(Debug)]
struct SettingWrite {
    key: String,
    value: String,
}

#[derive(Debug)]
struct ModuleEvent {
    event_id: u16,
    value_type: u8,
    flags: u8,
    payload: Vec<u8>,
}

fn setting_writes() -> &'static Mutex<VecDeque<SettingWrite>> {
    static WRITES: OnceLock<Mutex<VecDeque<SettingWrite>>> = OnceLock::new();
    WRITES.get_or_init(|| Mutex::new(VecDeque::new()))
}

fn encode_event_cbor(event: &ModuleEvent) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(event.payload.len().saturating_add(16));
    let mut encoder = Encoder::new(&mut encoded);
    let _ = encoder.array(4)
        .and_then(|encoder| encoder.u16(event.event_id))
        .and_then(|encoder| encoder.u8(event.value_type))
        .and_then(|encoder| encoder.u8(event.flags))
        .and_then(|encoder| match event.value_type {
            0 => encoder.null(),
            1 if event.payload.len() == 8 => {
                let mut bytes = [0u8; 8];
                bytes.copy_from_slice(&event.payload);
                encoder.u64(u64::from_le_bytes(bytes))
            }
            2 if event.payload.len() == 8 => {
                let mut bytes = [0u8; 8];
                bytes.copy_from_slice(&event.payload);
                encoder.i64(i64::from_le_bytes(bytes))
            }
            4 => match core::str::from_utf8(&event.payload) {
                Ok(value) => encoder.str(value),
                Err(_) => encoder.bytes(&event.payload),
            },
            _ => encoder.bytes(&event.payload),
        });
    encoded
}

fn module_events() -> &'static Mutex<VecDeque<ModuleEvent>> {
    static EVENTS: OnceLock<Mutex<VecDeque<ModuleEvent>>> = OnceLock::new();
    EVENTS.get_or_init(|| Mutex::new(VecDeque::new()))
}

#[no_mangle]
pub unsafe extern "C" fn dmesh_module_get_setting(
    key: *const u8,
    key_len: usize,
    value: *mut u8,
    value_capacity: usize,
    value_len: *mut usize,
) -> i32 {
    let Some(key) = valid_callback_key(key, key_len) else { return -1 };
    if value_len.is_null() || (value_capacity != 0 && value.is_null()) {
        return -1;
    }
    let Ok(key) = core::str::from_utf8(key) else { return -1 };
    let Ok(snapshot) = setting_snapshot().try_lock() else { return -1 };
    let Some(setting) = snapshot.get(key) else { return -2 };
    let bytes = setting.as_bytes();
    if bytes.len() > value_capacity { return -3; }
    if !bytes.is_empty() { core::ptr::copy_nonoverlapping(bytes.as_ptr(), value, bytes.len()); }
    *value_len = bytes.len();
    0
}

#[no_mangle]
pub unsafe extern "C" fn dmesh_module_set_setting(
    key: *const u8,
    key_len: usize,
    value: *const u8,
    value_len: usize,
) -> i32 {
    let Some(key) = valid_callback_key(key, key_len) else { return -1 };
    if value.is_null() || value_len > 128 { return -1; }
    let Ok(key) = core::str::from_utf8(key) else { return -1 };
    let value = core::slice::from_raw_parts(value, value_len);
    let Ok(value) = core::str::from_utf8(value) else { return -1 };
    let Ok(mut writes) = setting_writes().try_lock() else { return -1 };
    if writes.len() >= 16 { return -2; }
    writes.push_back(SettingWrite { key: key.to_owned(), value: value.to_owned() });
    0
}

#[no_mangle]
pub unsafe extern "C" fn dmesh_module_emit_event(
    event_id: u16,
    value_type: u8,
    flags: u8,
    payload: *const u8,
    payload_len: usize,
) -> i32 {
    if payload_len > MAX_SERVICE_BYTES || (payload_len != 0 && payload.is_null()) {
        return -1;
    }
    let payload = if payload_len == 0 {
        Vec::new()
    } else {
        core::slice::from_raw_parts(payload, payload_len).to_vec()
    };
    let Ok(mut events) = module_events().try_lock() else { return -1 };
    if events.len() >= MAX_SERVICE_CALLS { return -2; }
    if value_type == 1 || value_type == 2 {
        if payload_len != 8 { return -1; }
    } else if value_type > 5 {
        return -1;
    }
    events.push_back(ModuleEvent { event_id, value_type, flags, payload });
    0
}

fn lora_config_from_settings(settings: &crate::components::settings::SharedSettings) -> ModuleLoraConfig {
    let s = settings.borrow();
    let chip = s.get_str("lora.chip").ok().flatten();
    let sx126 = chip.as_deref().map(|v| v.contains("126")).unwrap_or(false);
    ModuleLoraConfig {
        abi_version: 2,
        size: std::mem::size_of::<ModuleLoraConfig>() as u32,
        chip: if sx126 { 2 } else { 1 },
        frequency_hz: s.get_i32("lora.freq", 913_125_000i32).unwrap_or(913_125_000) as u32,
        bandwidth_hz: s.get_i32("lora.bw", 250_000).unwrap_or(250_000) as u32,
        spreading_factor: s.get_i32("lora.sf", 10).unwrap_or(10) as u32,
        spi_host: s.get_i32("lora.spi_host", 2).unwrap_or(2),
        sync_word: s.get_i32("lora.sync_word", 0x2b).unwrap_or(0x2b) as u8,
        tx_power: s.get_i32("lora.tx_power", 17).unwrap_or(17) as u8,
        reset_pin: s.get_i32("lora.rst", if sx126 { 12 } else { 14 })
            .unwrap_or(if sx126 { 12 } else { 14 }) as i8,
        cs_pin: s.get_i32("lora.cs", if sx126 { 8 } else { 18 }).unwrap_or(if sx126 { 8 } else { 18 }) as i8,
        irq_pin: s.get_i32("lora.dio0", if sx126 { 14 } else { 26 }).unwrap_or(if sx126 { 14 } else { 26 }) as i8,
        busy_pin: s.get_i32("lora.busy", if sx126 { 13 } else { -1 })
            .unwrap_or(if sx126 { 13 } else { -1 }) as i8,
        sck_pin: s.get_i32("lora.sck", if sx126 { 9 } else { 5 }).unwrap_or(if sx126 { 9 } else { 5 }) as i8,
        miso_pin: s.get_i32("lora.miso", if sx126 { 11 } else { 19 }).unwrap_or(if sx126 { 11 } else { 19 }) as i8,
        mosi_pin: s.get_i32("lora.mosi", if sx126 { 10 } else { 27 }).unwrap_or(if sx126 { 10 } else { 27 }) as i8,
        board_power_pin: s.get_i32("lora.pwrpin", -1).unwrap_or(-1),
        board_power_level: s.get_i32("lora.pwrlvl", 1).unwrap_or(1),
        sx1262_dio2_rf_switch: if s.get_bool("lora.dio2rf", false).unwrap_or(false) { 1 } else { 0 },
        sx1262_tcxo_mv: s.get_i32("lora.tcxo_mv", 0).unwrap_or(0),
        sx1262_pa_duty: s.get_i32("lora.pa_duty", 4).unwrap_or(4),
        sx1262_pa_hp: s.get_i32("lora.pa_hp", 7).unwrap_or(7),
        sx1262_pa_device: s.get_i32("lora.pa_dev", 0).unwrap_or(0),
        sx1262_pa_lut: s.get_i32("lora.pa_lut", 1).unwrap_or(1),
        sx1262_sync_word: s.get_i32("lora.sx_sync", 0x24b4).unwrap_or(0x24b4),
        sx1262_rx_timeout_ms: s.get_i32("lora.rx_timeout", 0).unwrap_or(0),
        coding_rate: s.get_i32("lora.cr", 5).unwrap_or(5),
        preamble: s.get_i32("lora.preamble", 16).unwrap_or(16),
        crc: if s.get_bool("lora.crc", true).unwrap_or(true) { 1 } else { 0 },
        cad_rx: if s.get_bool("lora.cad_rx", false).unwrap_or(false) { 1 } else { 0 },
        cad_interval_ms: s.get_i32("lora.cad_int", 2000).unwrap_or(2000).max(1) as u32,
        cad_rx_ms: s.get_i32("lora.cad_rxms", 1000).unwrap_or(1000).max(1) as u32,
    }
}

/// Refresh the module's host-visible settings and ask its persistent task to
/// apply them. This deliberately leaves SPI ownership in the loader.
pub fn refresh_lora_config(settings: &crate::components::settings::SharedSettings) -> Result<()> {
    ensure_initialized(settings);
    if !unsafe { dmesh_module_loader_is_lora() }
        || unsafe { dmesh_module_loader_task_done() }
    {
        return Ok(());
    }
    let config = lora_config_from_settings(settings);
    let rc = unsafe { dmesh_module_lora_update_config(&config) };
    if rc != 0 { return Err(anyhow!("module lora config update failed result={rc}")); }
    Ok(())
}

/// A `lora` image is authoritative whenever it is present in the data region.
pub fn lora_enabled() -> bool {
    // A selected module is authoritative. There is intentionally no Main
    // radio fallback: a failed module remains observable through status/logs
    // and must be repaired by deploying a new module image.
    MODULE_INITIALIZED.load(Ordering::Acquire) && unsafe { dmesh_module_loader_is_lora() }
}

pub fn module_task_done() -> bool {
    unsafe { dmesh_module_loader_task_done() }
}

pub fn module_last_result() -> i32 {
    unsafe { dmesh_module_loader_last_result() }
}

pub fn poll_flash_transport(settings: &crate::components::settings::SharedSettings) {
    if !FLASH_TCP_TRANSPORT_ACTIVE.load(Ordering::Acquire)
        || !unsafe { dmesh_module_loader_task_done() }
    {
        return;
    }
    if !FLASH_TCP_TRANSPORT_ACTIVE.swap(false, Ordering::AcqRel) {
        return;
    }
    let result = unsafe { dmesh_module_loader_last_result() };
    telemetry::record_log(format!(
        "event type=module.flash.transport_complete transport=tcp result={} resume=true",
        result
    ));
    if let Err(error) = crate::components::mode::resume_from_ip_transport(settings) {
        telemetry::record_log(format!(
            "event type=module.flash.transport_resume ok=false message={}",
            crate::commands::protocol::escape_value(&error.to_string())
        ));
    }
}

#[derive(Debug)]
struct ServiceCall {
    service_tag: u16,
    payload: Vec<u8>,
}

fn service_calls() -> &'static Mutex<VecDeque<ServiceCall>> {
    static CALLS: OnceLock<Mutex<VecDeque<ServiceCall>>> = OnceLock::new();
    CALLS.get_or_init(|| Mutex::new(VecDeque::new()))
}

/// C ABI used by module task contexts. It only copies a bounded request into a
/// queue; `poll_main` dispatches it later on the single Main command loop.
#[no_mangle]
pub unsafe extern "C" fn dmesh_module_call_service(
    service_tag: u16,
    payload: *const u8,
    payload_len: usize,
    response: *mut u8,
    response_capacity: usize,
    response_len: *mut usize,
    timeout_ms: u32,
) -> i32 {
    if service_tag == 0 || payload_len > MAX_SERVICE_BYTES ||
        (payload_len != 0 && payload.is_null()) ||
        (response_capacity != 0 && response.is_null()) || timeout_ms == 0 {
        return -1;
    }
    if response_len.is_null() { return -1; }
    let payload = if payload_len == 0 {
        Vec::new()
    } else {
        core::slice::from_raw_parts(payload, payload_len).to_vec()
    };
    let Ok(mut calls) = service_calls().try_lock() else {
        // Module callbacks must never wait behind Main's command loop.
        return -3;
    };
    if calls.len() >= MAX_SERVICE_CALLS {
        return -2;
    }
    calls.push_back(ServiceCall { service_tag, payload });
    core::ptr::write(response_len, 0);
    0
}

/// Runs queued module service calls in Main's serialized command context.
pub fn poll_main(
    registry: &mut CommandRegistry,
    settings: &crate::components::settings::SharedSettings,
) {
    for _ in 0..2 {
        let write = setting_writes().lock().ok().and_then(|mut queue| queue.pop_front());
        let Some(write) = write else { break };
        let result = settings.borrow_mut().set_str(&write.key, &write.value);
        let ok = result.is_ok();
        let error = result
            .as_ref()
            .err()
            .map(|err| format!(" msg={err}"))
            .unwrap_or_default();
        telemetry::record_log(format!(
            "event type=module.setting_write key={} ok={}{}",
            write.key,
            ok,
            error
        ));
        if ok {
            refresh_settings_snapshot(settings);
        }
    }
    for _ in 0..2 {
        let event = module_events().lock().ok().and_then(|mut queue| queue.pop_front());
        let Some(event) = event else { break };
        let mut request = CommandRequest::new("module")
            .arg_pair("op", "event")
            .arg_pair("id", &event.event_id.to_string())
            .arg_pair("value_type", &event.value_type.to_string())
            .arg_pair("flags", &event.flags.to_string());
        request.payload = encode_event_cbor(&event);
        let response = registry.dispatch(&request);
        telemetry::record_log(format!(
            "event type=module.structured_event id={} value_type={} flags={} payload_len={} status={:?}",
            event.event_id, event.value_type, event.flags, request.payload.len(), response.status
        ));
    }
    for _ in 0..2 {
        let call = {
            service_calls()
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .pop_front()
        };
        let Some(call) = call else {
            return;
        };
        let name = match call.service_tag {
            101 => "module",
            43 => "lora",
            45 => "hw",
            46 => "hello",
            _ => {
                telemetry::record_log(format!(
                    "event type=module.service rejected=true tag={}", call.service_tag
                ));
                continue;
            }
        };
        let mut request = CommandRequest::new(name);
        if request.method == 0 {
            telemetry::record_log(format!(
                "event type=module.service rejected=true tag={}",
                call.service_tag
            ));
            continue;
        }
        request.payload = call.payload;
        let response = registry.dispatch(&request);
        telemetry::record_log(format!(
            "event type=module.service tag={} status={:?} message={}",
            call.service_tag, response.status, response.message
        ));
    }
}

pub fn register_commands(
    registry: &mut CommandRegistry,
    settings: crate::components::settings::SharedSettings,
) {
    registry.register(ModuleCommand {
        name: "module",
        fixed_name: None,
        settings: settings.clone(),
    });
    registry.register(ModuleCommand {
        name: "hello",
        fixed_name: Some("hello"),
        settings: settings.clone(),
    });
    registry.register(ModuleCommand {
        name: "hw",
        fixed_name: Some("hw"),
        settings,
    });
}

struct ModuleCommand {
    name: &'static str,
    fixed_name: Option<&'static str>,
    settings: crate::components::settings::SharedSettings,
}

impl CommandHandler for ModuleCommand {
    fn name(&self) -> &'static str {
        self.name
    }

    fn handle(&mut self, request: &CommandRequest) -> Result<CommandResponse> {
        if let Some(name) = self.fixed_name {
            ensure_initialized(&self.settings);
            return invoke(&self.settings, name, request);
        }
        match request.arg("op").unwrap_or("status") {
            "stop" => {
                ensure_initialized(&self.settings);
                if unsafe { dmesh_module_loader_prepare_flash(1500) } {
                    Ok(CommandResponse::ok("module stopped"))
                } else {
                    Err(anyhow!("module stop timed out"))
                }
            }
            "init" => {
                ensure_initialized(&self.settings);
                Ok(CommandResponse::ok("module initialized"))
            }
            "status" => {
                // Header inspection is read-only and does not map or execute
                // the module. Make status reflect the actual flash slot
                // instead of exposing the deferred-init sentinel values.
                ensure_initialized(&self.settings);
                unsafe { dmesh_module_loader_refresh_header(); }
                Ok(CommandResponse::ok(status_text()))
            }
            "psram" => Ok(CommandResponse::ok(psram_text())),
            "stats" => {
                ensure_initialized(&self.settings);
                let request = request.clone().arg_pair("args", "stats");
                invoke_module(&self.settings, "lora", &request)
            }
            "run" => {
                ensure_initialized(&self.settings);
                invoke(&self.settings, request.arg("name").unwrap_or("hello"), request)
            }
            "lora_rx" => crate::components::lora::handle_module_packet(
                &request.payload,
                request.arg("rssi").unwrap_or("0").parse().unwrap_or(0),
                request.arg("snr").unwrap_or("0").parse().unwrap_or(0.0),
            ),
            "lora_event" => {
                telemetry::record_log(format!(
                    "event type=lora.module name={} payload_len={}",
                    request.arg("name").unwrap_or("unknown"),
                    request.payload.len()
                ));
                Ok(CommandResponse::ok("module lora event recorded"))
            }
            "event" => Ok(CommandResponse::ok(format!(
                "module event id={} value_type={} payload_len={}",
                request.arg("id").unwrap_or("0"),
                request.arg("value_type").unwrap_or("0"),
                request.payload.len()
            ))),
            other => Err(anyhow!(
                "module op must be status, stats, event, run, or psram; got {other}"
            )),
        }
    }
}

fn status_text() -> String {
    let last_lora_command = unsafe {
        let ptr = dmesh_module_loader_last_lora_command();
        if ptr.is_null() {
            "".to_string()
        } else {
            std::ffi::CStr::from_ptr(ptr.cast())
                .to_string_lossy()
                .into_owned()
        }
    };
    let entry_args = unsafe {
        let ptr = dmesh_module_loader_entry_args();
        if ptr.is_null() { "".to_string() }
        else { std::ffi::CStr::from_ptr(ptr.cast()).to_string_lossy().into_owned() }
    };
    let flash_connect_host = unsafe {
        let ptr = dmesh_module_loader_flash_connect_host();
        if ptr.is_null() { "".to_string() }
        else { std::ffi::CStr::from_ptr(ptr.cast()).to_string_lossy().into_owned() }
    };
    format!(
        "module initialized={} flash_exec={} align=0x{MODULE_ALIGN:x} offset=0x{:x} hw_slot=0x{:x} target=module header_valid={} required_stack_words={} task_done={} last_result={} runtime_ms={} max_runtime_ms={} task_runs={} stack_high_water_words={} stage={} spi_calls={} spi_errors={} lora_polls={} lora_irq_wakes={} lora_irq_timeouts={} lora_last_command={} lora_last_command_len={} lora_last_payload_len={} module_events={} module_last_event_id={} entry_args_len={} entry_args={} flash_connect_attempts={} flash_connect_host={} flash_connect_port={} flash_connect_errno={} psram_exec={} psram_reason={}",
        MODULE_INITIALIZED.load(Ordering::Acquire),
        unsafe { dmesh_module_flash_supported() },
        unsafe { dmesh_module_loader_offset() },
        MODULE_HW_SLOT * MODULE_ALIGN,
        unsafe { dmesh_module_loader_header_valid() },
        unsafe { dmesh_module_loader_required_stack_words() },
        unsafe { dmesh_module_loader_task_done() },
        unsafe { dmesh_module_loader_last_result() },
        unsafe { dmesh_module_loader_runtime_ms() },
        unsafe { dmesh_module_loader_max_runtime_ms() },
        unsafe { dmesh_module_loader_task_runs() },
        unsafe { dmesh_module_loader_stack_high_water_words() },
        unsafe { dmesh_module_loader_stage() },
        unsafe { dmesh_module_loader_spi_calls() },
        unsafe { dmesh_module_loader_spi_errors() },
        unsafe { dmesh_module_loader_lora_poll_count() },
        unsafe { dmesh_module_loader_lora_irq_wakes() },
        unsafe { dmesh_module_loader_lora_irq_timeouts() },
        last_lora_command,
        unsafe { dmesh_module_loader_last_lora_command_len() },
        unsafe { dmesh_module_loader_last_lora_payload_len() },
        unsafe { dmesh_module_loader_module_event_calls() },
        unsafe { dmesh_module_loader_last_module_event_id() },
        unsafe { dmesh_module_loader_entry_args_len() },
        entry_args,
        unsafe { dmesh_module_loader_flash_connect_attempts() },
        flash_connect_host,
        unsafe { dmesh_module_loader_flash_connect_port() },
        unsafe { dmesh_module_loader_flash_connect_errno() },
        unsafe { dmesh_module_psram_exec_supported() },
        psram_reason()
    )
}
fn psram_text() -> String {
    format!(
        "module psram_exec={} reason={}",
        unsafe { dmesh_module_psram_exec_supported() },
        psram_reason()
    )
}
fn psram_reason() -> String {
    let reason = unsafe { dmesh_module_psram_exec_reason() };
    if reason.is_null() {
        return "unknown".to_string();
    }
    unsafe { std::ffi::CStr::from_ptr(reason) }
        .to_string_lossy()
        .into_owned()
}

pub fn invoke_module(
    settings: &crate::components::settings::SharedSettings,
    name: &str,
    request: &CommandRequest,
) -> Result<CommandResponse> {
    if !crate::components::recovery::command_transport_ready() {
        return Err(anyhow!("module unavailable while flash transfer is active"));
    }
    // A module transfer stops the old task before erasing its flash mapping,
    // but Main itself keeps running. Refresh the DMOD header before deciding
    // which ABI/service to invoke so a new image can be loaded immediately
    // without rebooting Main.
    unsafe { dmesh_module_loader_refresh_header(); }
    let service_tag = match name {
        "lora" => 43u16,
        /* Development-only flash protocol slot.  It is deliberately not in
         * the public module registry yet; tag 44 is used while lora is
         * quiesced and the Rust/lmesh replacement is developed. */
        "flash" => 44u16,
        "hw" => 45u16,
        "hello" => 46u16,
        _ => 0u16,
    };
    if service_tag == 0 || name.is_empty()
        || name.len() > 15
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return Err(anyhow!(
            "module name must be 1..15 ASCII alphanumeric or underscore bytes"
        ));
    }
    if name == "flash" {
        if !unsafe { dmesh_module_flash_supported() } {
            return Err(anyhow!("flash module host is unavailable"));
        }
        let transport = request.arg("transport").unwrap_or("tcp");
        if transport == "tcp" {
            // If the caller already prepared the IP STA, do not run another
            // radio/power transition immediately before the module opens its
            // socket. This is the normal scripted path: Main first stops NAN,
            // then configures the static STA, then starts mod_flash. A second
            // transition here can invalidate the lwIP/Wi-Fi data plane even
            // though the STA still reports an address.
            if !crate::components::wifi::ip_sta_ready() {
                crate::components::mode::stop_for_ip_transport();
            }
        }
        if !unsafe { dmesh_module_loader_prepare_flash(1500) } {
            if transport == "tcp" {
                let _ = crate::components::mode::resume_from_ip_transport(settings);
            }
            return Err(anyhow!("module did not quiesce before flash module start"));
        }
    }
    if name == "lora" && unsafe { dmesh_module_loader_is_lora() } {
        configure_lora(settings)?;
        let args = request.arg("args").unwrap_or("status").as_bytes();
        let result = unsafe {
            dmesh_module_lora_command(
                args.as_ptr(), args.len(), request.payload.as_ptr(), request.payload.len(),
            )
        };
        if result == 0 {
            return Ok(CommandResponse::ok(format!("module lora command queued args={}", String::from_utf8_lossy(args))));
        }
        if result != -21 {
            return Err(anyhow!("module lora command could not queue result={result}"));
        }
        /* -21 means the previous task has exited (normally after `stop`).
         * Starting a new module task is still the module path, not a Main
         * fallback; mod_lora has standalone tx/reconfigure handling for this
         * short-lived invocation. */
    }
    let offset = match (request.arg("slot"), request.arg("offset")) {
        (Some(_), Some(_)) => {
            return Err(anyhow!("module slot and offset are mutually exclusive"));
        }
        (Some(slot), None) => slot
            .parse::<u32>()
            .map_err(|err| anyhow!("invalid module slot: {err}"))?
            .checked_mul(MODULE_ALIGN)
            .ok_or_else(|| anyhow!("module slot is too large"))?,
        (None, Some(value)) => value
            .parse::<u32>()
            .map_err(|err| anyhow!("invalid module offset: {err}"))?,
        (None, None) => (service_tag - 43) as u32 * MODULE_ALIGN,
    };
    let size = request
        .arg("size")
        .unwrap_or("0")
        .parse::<u32>()
        .map_err(|err| anyhow!("invalid module size: {err}"))?;
    if offset % MODULE_ALIGN != 0 {
        return Err(anyhow!("module offset must be 0x{MODULE_ALIGN:x}-aligned"));
    }
    let flash_args = if name == "flash" {
        /* The command tokenizer exposes whitespace-separated `server`,
         * `port`, and `dry_run` fields as normal request arguments. Repack
         * them into the module's deliberately tiny ASCII argument ABI. */
        let mut value = request.arg("args").unwrap_or("").to_owned();
        for key in ["server", "port", "dry_run", "target"] {
            if let Some(item) = request.arg(key) {
                if !value.is_empty() { value.push(' '); }
                value.push_str(key); value.push('='); value.push_str(item);
            }
        }
        // TCP is the module's default and omitting it avoids duplicating the
        // common case in the tiny ASCII ABI. Preserve an explicit alternate
        // transport for future FSK/NAN/QUIC modules.
        if let Some(item) = request.arg("transport") {
            if item != "tcp" {
                if !value.is_empty() { value.push(' '); }
                value.push_str("transport="); value.push_str(item);
            }
        }
        Some(value)
    } else { None };
    let args = flash_args.as_deref().unwrap_or_else(|| request.arg("args").unwrap_or("")).as_bytes();
    let result = unsafe {
        dmesh_module_start_service(
            service_tag,
            offset,
            size,
            request.payload.as_ptr(),
            request.payload.len(),
            args.as_ptr(),
            args.len(),
        )
    };
    if result != 0 {
        if name == "flash" && request.arg("transport").unwrap_or("tcp") == "tcp" {
            let _ = crate::components::mode::resume_from_ip_transport(settings);
        }
        return Err(anyhow!("module task could not start result={result}"));
    }
    if name == "flash" && request.arg("transport").unwrap_or("tcp") == "tcp" {
        FLASH_TCP_TRANSPORT_ACTIVE.store(true, Ordering::Release);
    }
    Ok(CommandResponse::ok(format!(
        "module {name} task started offset=0x{offset:x} size=0x{size:x}; see serial log"
    )))
}

fn invoke(
    settings: &crate::components::settings::SharedSettings,
    name: &str,
    request: &CommandRequest,
) -> Result<CommandResponse> {
    invoke_module(settings, name, request)
}
