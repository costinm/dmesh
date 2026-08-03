#![no_std]

//! Minimal dynamic-module ABI experiment.
//!
//! This crate deliberately has no allocation, statics, imported functions, or
//! target-specific dependencies.  The deployment wrapper supplies a context
//! containing the host callbacks and calls `dmesh_module_entry` directly.

use core::ffi::c_void;

pub const ABI_VERSION: u32 = 1;

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

#[repr(C)]
pub struct ModuleContext {
    pub abi_version: u32,
    pub size: u32,
    pub user: *mut c_void,
    pub log_line: Option<LogLine>,
    pub call_service: Option<CallService>,
    pub lora_host: *const c_void,
}

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
        return -2;
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
