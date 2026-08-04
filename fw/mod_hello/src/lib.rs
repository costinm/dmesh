#![no_std]

//! Minimal dynamic-module ABI experiment.
//!
//! This crate deliberately has no allocation, statics, imported functions, or
//! target-specific dependencies.  The deployment wrapper supplies a context
//! containing the host callbacks and calls `dmesh_module_entry` directly.

use core::ffi::c_void;

pub const ABI_VERSION: u32 = 2;
const ERR_CONTEXT_ABI: i32 = -100;

pub type LogLine = unsafe extern "C" fn(*mut c_void, *const u8, usize) -> i32;
pub type CallService = unsafe extern "C" fn(
    *mut c_void,
    *const u8,
    usize,
    *const u8,
    usize,
    *const u8,
    usize,
) -> i32;
pub type GetSetting = unsafe extern "C" fn(
    *mut c_void, *const u8, usize, *mut u8, usize, *mut usize,
) -> i32;
pub type SetSetting = unsafe extern "C" fn(*mut c_void, *const u8, usize, *const u8, usize) -> i32;
#[repr(C)]
pub struct ModuleEvent {
    pub event_id: u16,
    pub value_type: u8,
    pub flags: u8,
    pub value: *const u8,
    pub value_len: usize,
}
#[cfg(target_pointer_width = "32")]
const _: () = assert!(core::mem::size_of::<ModuleEvent>() == 12);
pub type EmitEvent = unsafe extern "C" fn(*mut c_void, *const ModuleEvent) -> i32;

#[repr(C)]
pub struct ModuleContext {
    pub abi_version: u32,
    pub size: u32,
    pub user: *mut c_void,
    pub log_line: Option<LogLine>,
    pub call_service: Option<CallService>,
    pub get_setting: Option<GetSetting>,
    pub set_setting: Option<SetSetting>,
    pub emit_event: Option<EmitEvent>,
    pub lora_host: *const c_void,
    pub lora_config: *const c_void,
}

#[cfg(target_pointer_width = "32")]
const _: () = assert!(core::mem::size_of::<ModuleContext>() == 40);

/// Module implementation used by the flat-image entry stub.
///
/// `payload` and `args` are borrowed for the duration of this call.  The
/// module must not retain them or the context after returning.
pub unsafe fn entry(
    context: *const ModuleContext,
    payload: *const u8,
    payload_len: usize,
    args: *const u8,
    args_len: usize,
) -> i32 {
    if context.is_null() {
        return -1;
    }
    let context = &*context;
    if context.abi_version != ABI_VERSION || context.size < core::mem::size_of::<ModuleContext>() as u32 {
        return ERR_CONTEXT_ABI;
    }

    // Touch both borrowed buffers without retaining pointers. This proves the
    // intended ABI while keeping this module free of data/global state.
    let _ = (payload, payload_len, args, args_len);
    let message = [
        b'h', b'e', b'l', b'l', b'o', b' ', b'f', b'r', b'o', b'm', b' ',
        b'm', b'o', b'd', b'_', b'h', b'e', b'l', b'l', b'o',
    ];

    match context.log_line {
        Some(log_line) => log_line(context.user, message.as_ptr(), message.len()),
        None => -3,
    }
}
