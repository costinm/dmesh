#![no_std]

use core::ffi::c_void;

#[repr(C)]
pub struct LoraHost {
    pub abi_version: u32,
    pub size: u32,
    pub features: u32,
    pub user: *mut c_void,
    pub spi_transfer: Option<unsafe extern "C" fn(*mut c_void, *const u8, *mut u8, usize) -> i32>,
    pub gpio_write: Option<unsafe extern "C" fn(*mut c_void, i32, i32) -> i32>,
    pub gpio_read: Option<unsafe extern "C" fn(*mut c_void, i32) -> i32>,
    pub irq_configure: Option<unsafe extern "C" fn(*mut c_void, i32, i32) -> i32>,
    pub irq_enable: Option<unsafe extern "C" fn(*mut c_void, i32, i32) -> i32>,
    pub wait_irq: Option<unsafe extern "C" fn(*mut c_void, u32) -> i32>,
    pub now_ms: Option<unsafe extern "C" fn(*mut c_void) -> u64>,
    pub log_line: Option<unsafe extern "C" fn(*mut c_void, *const u8, usize) -> i32>,
    pub emit_packet: Option<unsafe extern "C" fn(*mut c_void, *const u8, usize, i16, i8) -> i32>,
}

#[repr(C)]
pub struct ModuleContext {
    pub abi_version: u32,
    pub size: u32,
    pub user: *mut c_void,
    pub log_line: Option<unsafe extern "C" fn(*mut c_void, *const u8, usize) -> i32>,
    pub call_service: Option<unsafe extern "C" fn(*mut c_void, *const u8, usize, *const u8, usize, *const u8, usize) -> i32>,
    pub lora_host: *const LoraHost,
}

const ABI_VERSION: u32 = 1;
const LORA_ABI_VERSION: u32 = 1;
const SX127X_VERSION: u8 = 0x12;
const REG_VERSION: u8 = 0x42;
const SX126X_GET_STATUS: u8 = 0xC0;
const SX127X_REG_BITRATE_MSB: u8 = 0x02;
const SX127X_REG_BITRATE_LSB: u8 = 0x03;
const SX127X_REG_FDEV_MSB: u8 = 0x04;
const SX127X_REG_FDEV_LSB: u8 = 0x05;

unsafe fn log(ctx: &ModuleContext, text: &[u8]) {
    if let Some(f) = ctx.log_line { let _ = f(ctx.user, text.as_ptr(), text.len()); }
}

unsafe fn probe_sx127x(host: &LoraHost) -> i32 {
    let Some(spi) = host.spi_transfer else { return -2 };
    let tx = [REG_VERSION & 0x7f, 0];
    let mut rx = [0u8; 2];
    let rc = spi(host.user, tx.as_ptr(), rx.as_mut_ptr(), tx.len());
    if rc != 0 { return -3; }
    if rx[1] == SX127X_VERSION { 0 } else { -6 }
}

unsafe fn probe_sx126x(host: &LoraHost) -> i32 {
    let Some(spi) = host.spi_transfer else { return -2 };
    let tx = [SX126X_GET_STATUS, 0];
    let mut rx = [0u8; 2];
    let rc = spi(host.user, tx.as_ptr(), rx.as_mut_ptr(), tx.len());
    if rc == 0 && rx[1] != 0 { 0 } else if rc == 0 { -6 } else { -3 }
}

unsafe fn sx127x_fsk_setup(host: &LoraHost) -> i32 {
    let Some(spi) = host.spi_transfer else { return -2 };
    // The FSK mode shares the SX127x SPI register transport. Keep these
    // writes in the module so bitrate/deviation changes do not require a Main
    // image update; Main still owns the electrical SPI transaction.
    for (reg, value) in [
        (SX127X_REG_BITRATE_MSB, 0x1a), // 4.8 kbit/s
        (SX127X_REG_BITRATE_LSB, 0x0b),
        (SX127X_REG_FDEV_MSB, 0x00),
        (SX127X_REG_FDEV_LSB, 0x52),
    ] {
        let tx = [reg | 0x80, value];
        let mut rx = [0u8; 2];
        if spi(host.user, tx.as_ptr(), rx.as_mut_ptr(), tx.len()) != 0 { return -3; }
    }
    0
}

#[inline(always)]
/// Development entry point. `probe127`, `probe126`, and `fsk` exercise the
/// same host SPI path that the full RX/TX state machine will use.
pub unsafe fn entry(context: *const ModuleContext, _payload: *const u8, _payload_len: usize,
                    args: *const u8, args_len: usize) -> i32 {
    if context.is_null() { return -1; }
    let ctx = &*context;
    if ctx.abi_version != ABI_VERSION || ctx.size < core::mem::size_of::<ModuleContext>() as u32 || ctx.lora_host.is_null() { return -2; }
    let host = &*ctx.lora_host;
    if host.abi_version != LORA_ABI_VERSION || host.size < core::mem::size_of::<LoraHost>() as u32 { return -3; }
    let command = if !args.is_null() && args_len > 0 { core::str::from_utf8(core::slice::from_raw_parts(args, args_len)).unwrap_or("probe") } else { "probe" };
    if command == "probe127" { let rc = probe_sx127x(host); log(ctx, b"mod_lora sx127x probe"); return rc; }
    if command == "probe126" { let rc = probe_sx126x(host); log(ctx, b"mod_lora sx126x probe"); return rc; }
    if command == "fsk" {
        let rc = sx127x_fsk_setup(host);
        log(ctx, b"mod_lora FSK service selected");
        return rc;
    }
    log(ctx, b"mod_lora ready");
    0
}
