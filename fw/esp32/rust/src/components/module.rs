//! Flash-mapped dynamic modules. Module tasks have no direct access to the
//! command registry: service calls are copied here and dispatched by Main.

use std::collections::VecDeque;
use std::sync::{Mutex, OnceLock};

use anyhow::{anyhow, Result};

use crate::commands::{CommandHandler, CommandRegistry, CommandRequest, CommandResponse};
use crate::components::telemetry;

const MODULE_ALIGN: u32 = 0x10000;
const DEFAULT_MODULE_SIZE: u32 = MODULE_ALIGN;
const MAX_SERVICE_CALLS: usize = 8;
const MAX_SERVICE_BYTES: usize = 4096;

extern "C" {
    fn dmesh_module_loader_init();
    fn dmesh_module_flash_supported() -> bool;
    fn dmesh_module_psram_exec_supported() -> bool;
    fn dmesh_module_psram_exec_reason() -> *const u8;
    fn dmesh_module_loader_header_valid() -> bool;
    fn dmesh_module_loader_task_done() -> bool;
    fn dmesh_module_loader_last_result() -> i32;
    fn dmesh_module_start_task(
        name: *const u8,
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
pub fn init() {
    unsafe { dmesh_module_loader_init() };
}

#[derive(Debug)]
struct ServiceCall {
    name: String,
    payload: Vec<u8>,
    args: String,
}

fn service_calls() -> &'static Mutex<VecDeque<ServiceCall>> {
    static CALLS: OnceLock<Mutex<VecDeque<ServiceCall>>> = OnceLock::new();
    CALLS.get_or_init(|| Mutex::new(VecDeque::new()))
}

/// C ABI used by module task contexts. It only copies a bounded request into a
/// queue; `poll_main` dispatches it later on the single Main command loop.
#[no_mangle]
pub unsafe extern "C" fn dmesh_module_call_service(
    service: *const u8,
    service_len: usize,
    payload: *const u8,
    payload_len: usize,
    args: *const u8,
    args_len: usize,
) -> i32 {
    if service.is_null()
        || service_len == 0
        || service_len > 15
        || payload_len > MAX_SERVICE_BYTES
        || args_len > MAX_SERVICE_BYTES
        || (payload_len != 0 && payload.is_null())
        || (args_len != 0 && args.is_null())
    {
        return -1;
    }
    let service_bytes = core::slice::from_raw_parts(service, service_len);
    if !service_bytes
        .iter()
        .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
    {
        return -1;
    }
    let args_bytes = if args_len == 0 {
        &[]
    } else {
        core::slice::from_raw_parts(args, args_len)
    };
    let Ok(args) = core::str::from_utf8(args_bytes) else {
        return -1;
    };
    let payload = if payload_len == 0 {
        Vec::new()
    } else {
        core::slice::from_raw_parts(payload, payload_len).to_vec()
    };
    let mut calls = service_calls()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if calls.len() >= MAX_SERVICE_CALLS {
        return -2;
    }
    calls.push_back(ServiceCall {
        name: String::from_utf8_lossy(service_bytes).into_owned(),
        payload,
        args: args.to_owned(),
    });
    0
}

/// Runs queued module service calls in Main's serialized command context.
pub fn poll_main(registry: &mut CommandRegistry) {
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
        let mut request = CommandRequest::new(&call.name);
        if request.method == 0 {
            telemetry::record_log(format!(
                "event type=module.service rejected=true name={}",
                call.name
            ));
            continue;
        }
        request.payload = call.payload;
        for pair in call.args.split_whitespace() {
            if let Some((key, value)) = pair.split_once('=') {
                request = request.arg_pair(key, value);
            }
        }
        let response = registry.dispatch(&request);
        telemetry::record_log(format!(
            "event type=module.service name={} status={:?} message={}",
            call.name, response.status, response.message
        ));
    }
}

pub fn register_commands(registry: &mut CommandRegistry) {
    registry.register(ModuleCommand {
        name: "module",
        fixed_name: None,
    });
    registry.register(ModuleCommand {
        name: "hello",
        fixed_name: Some("hello"),
    });
}

struct ModuleCommand {
    name: &'static str,
    fixed_name: Option<&'static str>,
}

impl CommandHandler for ModuleCommand {
    fn name(&self) -> &'static str {
        self.name
    }

    fn handle(&mut self, request: &CommandRequest) -> Result<CommandResponse> {
        if let Some(name) = self.fixed_name {
            return invoke(name, request);
        }
        match request.arg("op").unwrap_or("status") {
            "status" => Ok(CommandResponse::ok(status_text())),
            "psram" => Ok(CommandResponse::ok(psram_text())),
            "run" => invoke(request.arg("name").unwrap_or("hello"), request),
            other => Err(anyhow!(
                "module op must be status, run, or psram; got {other}"
            )),
        }
    }
}

fn status_text() -> String {
    format!(
        "module flash_exec={} align=0x{MODULE_ALIGN:x} target=module header_valid={} task_done={} last_result={} psram_exec={} psram_reason={}",
        unsafe { dmesh_module_flash_supported() },
        unsafe { dmesh_module_loader_header_valid() },
        unsafe { dmesh_module_loader_task_done() },
        unsafe { dmesh_module_loader_last_result() },
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

fn invoke(name: &str, request: &CommandRequest) -> Result<CommandResponse> {
    if !crate::components::recovery::command_transport_ready() {
        return Err(anyhow!("module unavailable while flash transfer is active"));
    }
    if name.is_empty()
        || name.len() > 15
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return Err(anyhow!(
            "module name must be 1..15 ASCII alphanumeric or underscore bytes"
        ));
    }
    let offset = request
        .arg("offset")
        .unwrap_or("0")
        .parse::<u32>()
        .map_err(|err| anyhow!("invalid module offset: {err}"))?;
    let size = request
        .arg("size")
        .unwrap_or("65536")
        .parse::<u32>()
        .map_err(|err| anyhow!("invalid module size: {err}"))?;
    if offset % MODULE_ALIGN != 0 || size < DEFAULT_MODULE_SIZE {
        return Err(anyhow!("module offset must be 0x{MODULE_ALIGN:x}-aligned and size must be at least 0x{DEFAULT_MODULE_SIZE:x}"));
    }
    let args = request.arg("args").unwrap_or("").as_bytes();
    // C owns the task-copying ABI and expects a conventional NUL-terminated
    // name. `str::as_ptr()` is not terminated and made the C-side `strnlen`
    // validation read arbitrary bytes beyond a short module name.
    let c_name = std::ffi::CString::new(name)
        .map_err(|_| anyhow!("module name contains an interior NUL"))?;
    let result = unsafe {
        dmesh_module_start_task(
            c_name.as_ptr().cast(),
            offset,
            size,
            request.payload.as_ptr(),
            request.payload.len(),
            args.as_ptr(),
            args.len(),
        )
    };
    if result != 0 {
        return Err(anyhow!("module task could not start result={result}"));
    }
    Ok(CommandResponse::ok(format!(
        "module {name} task started offset=0x{offset:x} size=0x{size:x}; see serial log"
    )))
}
