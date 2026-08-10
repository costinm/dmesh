#![no_std]

use core::ffi::c_void;

mod adc;
mod cbor;
mod gpio;

const ABI_VERSION: u32 = 4;
const HW_ABI_VERSION: u32 = 1;
const ERR_CONTEXT: i32 = -100;

#[repr(C)]
pub struct HwHost {
    pub abi_version: u32,
    pub size: u32,
    pub features: u32,
    pub user: *mut c_void,
    pub gpio_config: Option<unsafe extern "C" fn(*mut c_void, i32, i32, i32, i32) -> i32>,
    pub gpio_read: Option<unsafe extern "C" fn(*mut c_void, i32) -> i32>,
    pub gpio_write: Option<unsafe extern "C" fn(*mut c_void, i32, i32) -> i32>,
    pub adc_read: Option<unsafe extern "C" fn(*mut c_void, i32, u32, *mut i32, *mut u32) -> i32>,
    pub i2c_transfer: Option<unsafe extern "C" fn(*mut c_void, i32, i32, i32, u32, u8, *const u8, usize, *mut u8, usize, u32) -> i32>,
    pub spi_transfer: Option<unsafe extern "C" fn(*mut c_void, *const u8, *mut u8, usize) -> i32>,
    pub rgbled_write: Option<unsafe extern "C" fn(*mut c_void, i32, u8, u8, u8) -> i32>,
    pub irq_register: Option<unsafe extern "C" fn(*mut c_void, i32, i32, u16) -> i32>,
    pub irq_unregister: Option<unsafe extern "C" fn(*mut c_void, i32) -> i32>,
    pub irq_enable: Option<unsafe extern "C" fn(*mut c_void, i32, i32) -> i32>,
    pub event_wait: Option<unsafe extern "C" fn(*mut c_void, u32, *mut u16, *mut i32) -> i32>,
    pub should_stop: Option<unsafe extern "C" fn(*mut c_void) -> i32>,
    pub sleep_ms: Option<unsafe extern "C" fn(*mut c_void, u32) -> i32>,
    pub now_ms: Option<unsafe extern "C" fn(*mut c_void) -> u64>,
    pub adc_read_ex: Option<unsafe extern "C" fn(*mut c_void, i32, u32, *mut i32, *mut u32, *mut i32, *mut i32) -> i32>,
}

#[repr(C)]
pub struct ModuleEvent {
    pub event_id: u16,
    pub value_type: u8,
    pub flags: u8,
    pub value: *const u8,
    pub value_len: usize,
}

#[repr(C)]
pub struct ModuleContext {
    pub abi_version: u32,
    pub size: u32,
    pub user: *mut c_void,
    pub log_line: Option<unsafe extern "C" fn(*mut c_void, *const u8, usize) -> i32>,
    pub call_service: Option<unsafe extern "C" fn(*mut c_void, u16, *const u8, usize, *mut u8, usize, *mut usize, u32) -> i32>,
    pub get_setting: Option<unsafe extern "C" fn(*mut c_void, *const u8, usize, *mut u8, usize, *mut usize) -> i32>,
    pub set_setting: Option<unsafe extern "C" fn(*mut c_void, *const u8, usize, *const u8, usize) -> i32>,
    pub emit_event: Option<unsafe extern "C" fn(*mut c_void, *const ModuleEvent) -> i32>,
    pub lora_host: *const c_void,
    pub lora_config: *const c_void,
    pub host: *const c_void,
}

unsafe fn host<'a>(ctx: &ModuleContext) -> Result<&'a HwHost, i32> {
    if ctx.host.is_null() { return Err(ERR_CONTEXT); }
    let common = ctx.host as *const CommonHost;
    if (*common).abi_version != ABI_VERSION || (*common).hw.is_null() { return Err(ERR_CONTEXT); }
    let hw = &*((*common).hw);
    if hw.abi_version != HW_ABI_VERSION || hw.size < core::mem::size_of::<HwHost>() as u32 {
        return Err(ERR_CONTEXT);
    }
    Ok(hw)
}

#[repr(C)]
struct CommonHost {
    abi_version: u32,
    size: u32,
    features: u32,
    user: *mut c_void,
    log_line: Option<unsafe extern "C" fn(*mut c_void, *const u8, usize) -> i32>,
    call_service: Option<unsafe extern "C" fn(*mut c_void, u16, *const u8, usize, *mut u8, usize, *mut usize, u32) -> i32>,
    get_setting: Option<unsafe extern "C" fn(*mut c_void, *const u8, usize, *mut u8, usize, *mut usize) -> i32>,
    set_setting: Option<unsafe extern "C" fn(*mut c_void, *const u8, usize, *const u8, usize) -> i32>,
    emit_event: Option<unsafe extern "C" fn(*mut c_void, *const ModuleEvent) -> i32>,
    hw: *const HwHost,
    alloc: Option<unsafe extern "C" fn(*mut c_void, usize, usize) -> *mut u8>,
}

#[cfg(target_pointer_width = "32")]
const _: () = assert!(core::mem::size_of::<CommonHost>() == 44);

/// Allocate transient memory from Main's task-scoped bump arena.
pub unsafe fn alloc(ctx: &ModuleContext, size: usize, align: usize) -> *mut u8 {
    if ctx.host.is_null() { return core::ptr::null_mut(); }
    let common = &*(ctx.host as *const CommonHost);
    common.alloc.map(|f| f(common.user, size, align)).unwrap_or(core::ptr::null_mut())
}

unsafe fn setting_i32(ctx: &ModuleContext, key: &[u8], default: i32) -> i32 {
    let Some(get) = ctx.get_setting else { return default };
    let mut buf = [0u8; 32];
    let mut len = 0usize;
    if get(ctx.user, key.as_ptr(), key.len(), buf.as_mut_ptr(), buf.len(), &mut len) != 0 { return default; }
    core::str::from_utf8(&buf[..len]).ok().and_then(|s| parse_i32(s)).unwrap_or(default)
}

pub unsafe fn get_setting_i32(ctx: &ModuleContext, key: &[u8], default: i32) -> i32 {
    setting_i32(ctx, key, default)
}

pub unsafe fn get_setting_scaled(ctx: &ModuleContext, key: &[u8], default: i32) -> i32 {
    let Some(get) = ctx.get_setting else { return default };
    let mut buf = [0u8; 32];
    let mut len = 0usize;
    if get(ctx.user, key.as_ptr(), key.len(), buf.as_mut_ptr(), buf.len(), &mut len) != 0 {
        return default;
    }
    let bytes = &buf[..len];
    let mut value = 0i32;
    let mut fraction = 0i32;
    let mut in_fraction = false;
    let mut digits = 0i32;
    for byte in bytes {
        if *byte == b'.' { if in_fraction { return default; } in_fraction = true; continue; }
        if *byte < b'0' || *byte > b'9' { return default; }
        if in_fraction {
            if fraction == 0 { fraction = (*byte - b'0') as i32 * 10; }
            digits += 1;
        } else {
            value = match value.checked_mul(10).and_then(|v| v.checked_add((*byte - b'0') as i32)) {
                Some(v) => v,
                None => return default,
            };
        }
    }
    if digits == 0 { value.checked_mul(100).unwrap_or(default) }
    else if digits == 1 { value.checked_mul(100).and_then(|v| v.checked_add(fraction)).unwrap_or(default) }
    else { value.checked_mul(100).and_then(|v| v.checked_add(fraction / 10)).unwrap_or(default) }
}

fn parse_i32(value: &str) -> Option<i32> {
    let bytes = value.as_bytes();
    if bytes.is_empty() { return None; }
    let mut sign = 1i32;
    let mut index = 0;
    if bytes[0] == b'-' { sign = -1; index = 1; }
    let mut out = 0i32;
    while index < bytes.len() {
        let digit = bytes[index].wrapping_sub(b'0');
        if digit > 9 { return None; }
        out = out.checked_mul(10)?.checked_add(digit as i32)?;
        index += 1;
    }
    Some(out * sign)
}

pub unsafe fn emit_cbor(ctx: &ModuleContext, event_id: u16, value: &[u8]) -> i32 {
    if let Some(emit) = ctx.emit_event {
        let event = ModuleEvent { event_id, value_type: 5, flags: 0, value: value.as_ptr(), value_len: value.len() };
        return emit(ctx.user, &event);
    }
    -1
}

pub unsafe fn entry(ctx_ptr: *const ModuleContext, payload: *const u8, payload_len: usize,
                    args: *const u8, args_len: usize) -> i32 {
    if ctx_ptr.is_null() { return -1; }
    let ctx = &*ctx_ptr;
    if ctx.abi_version != ABI_VERSION || ctx.size < core::mem::size_of::<ModuleContext>() as u32 { return ERR_CONTEXT; }
    let hw = match host(ctx) { Ok(value) => value, Err(err) => return err };
    let payload = if !payload.is_null() && payload_len != 0 {
        core::slice::from_raw_parts(payload, payload_len)
    } else { &[] };
    if !payload.is_empty() {
        let op = cbor::Reader::array(payload).and_then(|mut r| r.next_u64());
        return match op {
            Some(adc::OP_BATTERY) | Some(adc::OP_PROBE) => adc::run(ctx, hw, payload),
            Some(gpio::OP_BUTTON) => gpio::run(ctx, hw, payload),
            _ => -20,
        };
    }
    let args = if args.is_null() { &[] } else { core::slice::from_raw_parts(args, args_len) };
    if args.starts_with(b"button") {
        let request = [0x83, gpio::OP_BUTTON as u8, 0, 1];
        gpio::run(ctx, hw, &request)
    } else {
        let request = [0x81, adc::OP_BATTERY as u8];
        adc::run(ctx, hw, &request)
    }
}
