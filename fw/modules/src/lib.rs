//! Optional ESP flash-module control, exposed as tagged-CBOR components.
//!
//! The schema/dispatch registration is transport-independent: a caller uses
//! a normal tagged-CBOR QUIC stream or a direct tagged record. Only this crate's
//! small C ABI bridge is ESP-specific. Images that do not link the native
//! module loader simply do not call [`register_tagged_handlers`].

#![no_std]

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
use dmesh_server::{
    cbor::Encoder,
    services,
    tagged::{self, Name, Record},
};

/// Module-loader control/status component.
pub const MODULE_COMPONENT: u64 = 1000;
/// Flash-mapped hello module service.
pub const HELLO_COMPONENT: u64 = 1001;
/// Flash-mapped LoRa module service.
pub const LORA_COMPONENT: u64 = 1002;
/// Flash-mapped hardware module service.
pub const HARDWARE_COMPONENT: u64 = 1003;

pub const MODULE_STATUS: u64 = 1;
pub const MODULE_INIT: u64 = 2;
pub const MODULE_STOP: u64 = 3;
pub const MODULE_RUN: u64 = 4;

extern "C" {
    fn dmesh_module_loader_init();
    fn dmesh_module_loader_refresh_header() -> bool;
    fn dmesh_module_loader_prepare_flash(timeout_ms: u32) -> bool;
    fn dmesh_module_loader_header_valid() -> bool;
    fn dmesh_module_loader_last_result() -> i32;
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

// The C loader calls these bearer-neutral callbacks from a module task.  The
// former Main implementation queued them through its legacy string-command
// registry.  That registry is intentionally no longer linked: tagged-CBOR
// handlers are the public surface.  Keep the ABI here, beside the loader
// handler, and fail unsupported asynchronous operations explicitly instead
// of silently routing them through a Main-only command path.  Settings and
// event delivery will be wired to their common dmesh-server counterparts when
// their tagged-CBOR request/response schema is added.
#[no_mangle]
pub unsafe extern "C" fn dmesh_module_get_setting(
    _key: *const u8,
    _key_len: usize,
    _value: *mut u8,
    _value_capacity: usize,
    value_len: *mut usize,
) -> i32 {
    if !value_len.is_null() {
        *value_len = 0;
    }
    -2 // absent
}

#[no_mangle]
pub unsafe extern "C" fn dmesh_module_set_setting(
    _key: *const u8,
    _key_len: usize,
    _value: *const u8,
    _value_len: usize,
) -> i32 {
    -2 // not yet supported by the common settings service
}

#[no_mangle]
pub unsafe extern "C" fn dmesh_module_emit_event(
    _event_id: u16,
    _value_type: u8,
    _flags: u8,
    _payload: *const u8,
    _payload_len: usize,
) -> i32 {
    -2 // not yet supported by the common events service
}

#[no_mangle]
pub unsafe extern "C" fn dmesh_module_call_service(
    _service_tag: u16,
    _payload: *const u8,
    _payload_len: usize,
    _response: *mut u8,
    _response_capacity: usize,
    response_len: *mut usize,
    _timeout_ms: u32,
) -> i32 {
    if !response_len.is_null() {
        *response_len = 0;
    }
    -2 // no legacy Main command dispatcher
}

/// Register the module components with `dmesh-server` before a connection is
/// accepted. This does not initialize, map, or execute a module.
pub fn register_tagged_handlers() {
    assert!(services::register_tagged_component(
        MODULE_COMPONENT,
        handle_module
    ));
    assert!(services::register_tagged_component(
        HELLO_COMPONENT,
        handle_hello
    ));
    assert!(services::register_tagged_component(
        LORA_COMPONENT,
        handle_lora
    ));
    assert!(services::register_tagged_component(
        HARDWARE_COMPONENT,
        handle_hardware
    ));
}

fn response(record: Record<'_>, ok: bool, value: i64) -> Option<Vec<u8>> {
    let mut result = [0u8; 24];
    let mut encoder = Encoder::new(&mut result);
    encoder.map(2)?;
    encoder.uint(1)?;
    encoder.boolean(ok)?;
    encoder.uint(2)?;
    // Native loader status is an `i32`; retain failures as their compact
    // absolute diagnostic code because this minimal shared CBOR encoder has
    // no signed-integer writer.
    encoder.uint(value.unsigned_abs() as u64)?;
    let used = encoder.len();
    drop(encoder);
    let mut response = vec![0; 64];
    let response_used = tagged::encode_numeric_response(
        match record.component? {
            Name::Tag(tag) => tag,
            _ => return None,
        },
        match record.method? {
            Name::Tag(tag) => tag,
            _ => return None,
        },
        record.id.unwrap_or(0),
        &result[..used],
        &mut response,
    )?;
    response.truncate(response_used);
    Some(response)
}

fn handle_module(record: Record<'_>) -> Option<Vec<u8>> {
    let component = match record.component? {
        Name::Tag(tag) if tag == MODULE_COMPONENT => tag,
        _ => return None,
    };
    let method = match record.method? {
        Name::Tag(tag) => tag,
        _ => return None,
    };
    let result = unsafe {
        match (component, method) {
            (MODULE_COMPONENT, MODULE_STATUS) => {
                dmesh_module_loader_refresh_header();
                return response(
                    record,
                    dmesh_module_loader_header_valid(),
                    dmesh_module_loader_last_result() as i64,
                );
            }
            (MODULE_COMPONENT, MODULE_INIT) => {
                dmesh_module_loader_init();
                0
            }
            (MODULE_COMPONENT, MODULE_STOP) => i32::from(!dmesh_module_loader_prepare_flash(1_500)),
            _ => return None,
        }
    };
    response(record, result == 0, result as i64)
}

fn handle_hello(record: Record<'_>) -> Option<Vec<u8>> {
    run_service(record, HELLO_COMPONENT, 46)
}
fn handle_lora(record: Record<'_>) -> Option<Vec<u8>> {
    run_service(record, LORA_COMPONENT, 43)
}
fn handle_hardware(record: Record<'_>) -> Option<Vec<u8>> {
    run_service(record, HARDWARE_COMPONENT, 45)
}

fn run_service(record: Record<'_>, component: u64, service_tag: u16) -> Option<Vec<u8>> {
    if !matches!(record.component, Some(Name::Tag(tag)) if tag == component)
        || !matches!(record.method, Some(Name::Tag(MODULE_RUN)))
    {
        return None;
    }
    let payload = record.data.unwrap_or_default();
    let offset = u32::from(service_tag - 43) * 0x10000;
    let result = unsafe {
        dmesh_module_start_service(
            service_tag,
            offset,
            0,
            payload.as_ptr(),
            payload.len(),
            core::ptr::null(),
            0,
        )
    };
    response(record, result == 0, i64::from(result))
}
