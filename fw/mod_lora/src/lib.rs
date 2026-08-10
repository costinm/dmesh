#![no_std]

#[cfg(test)]
extern crate std;

use core::ffi::c_void;

pub mod frames;

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
    pub poll_command: Option<unsafe extern "C" fn(*mut c_void, *mut u8, *mut usize, *mut u8, *mut usize) -> i32>,
}

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
    pub lora_host: *const LoraHost,
    pub lora_config: *const LoraConfig,
    pub host: *const c_void,
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
    hw: *const c_void,
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

#[repr(C)]
pub struct LoraConfig {
    pub abi_version: u32,
    pub size: u32,
    pub chip: u32,
    pub frequency_hz: u32,
    pub bandwidth_hz: u32,
    pub spreading_factor: u32,
    pub spi_host: i32,
    pub sync_word: u8,
    pub tx_power: u8,
    pub reset_pin: i8,
    pub cs_pin: i8,
    pub irq_pin: i8,
    pub busy_pin: i8,
    pub sck_pin: i8,
    pub miso_pin: i8,
    pub mosi_pin: i8,
    pub board_power_pin: i32,
    pub board_power_level: i32,
    pub sx1262_dio2_rf_switch: i32,
    pub sx1262_tcxo_mv: i32,
    pub sx1262_pa_duty: i32,
    pub sx1262_pa_hp: i32,
    pub sx1262_pa_device: i32,
    pub sx1262_pa_lut: i32,
    pub sx1262_sync_word: i32,
    pub sx1262_rx_timeout_ms: i32,
    pub coding_rate: i32,
    pub preamble: i32,
    pub crc: i32,
    pub cad_rx: i32,
    pub cad_interval_ms: u32,
    pub cad_rx_ms: u32,
}

#[cfg(target_pointer_width = "32")]
const _: () = assert!(core::mem::size_of::<LoraHost>() == 56);
#[cfg(target_pointer_width = "32")]
const _: () = assert!(core::mem::size_of::<ModuleContext>() == 44);
const _: () = assert!(core::mem::size_of::<LoraConfig>() == 104);

const ABI_VERSION: u32 = 4;
const LORA_ABI_VERSION: u32 = 2;
const ERR_CONTEXT_ABI: i32 = -100;
const ERR_HOST_ABI: i32 = -101;
const SX127X_VERSION: u8 = 0x12;
const REG_VERSION: u8 = 0x42;
const SX126X_GET_STATUS: u8 = 0xC0;
const SX127X_REG_BITRATE_MSB: u8 = 0x02;
const SX127X_REG_BITRATE_LSB: u8 = 0x03;
const SX127X_REG_FDEV_MSB: u8 = 0x04;
const SX127X_REG_FDEV_LSB: u8 = 0x05;
const SX127X_REG_PA_CONFIG: u8 = 0x09;
const SX127X_REG_PA_RAMP: u8 = 0x0a;
// SX127x FSK/OOK register bank. These overlap the LoRa bank and are valid
// only after LongRangeMode has been cleared while the chip is asleep.
const SX127X_FSK_REG_RX_CONFIG: u8 = 0x0d;
const SX127X_FSK_REG_RX_BW: u8 = 0x12;
const SX127X_FSK_REG_AFC_BW: u8 = 0x13;
const SX127X_FSK_REG_PREAMBLE_DETECT: u8 = 0x1f;
const SX127X_FSK_REG_PREAMBLE_MSB: u8 = 0x25;
const SX127X_FSK_REG_PREAMBLE_LSB: u8 = 0x26;
const SX127X_REG_SYNC_CONFIG: u8 = 0x27;
const SX127X_REG_SYNC_VALUE: u8 = 0x28;
const SX127X_REG_PACKET_CONFIG1: u8 = 0x30;
const SX127X_REG_PACKET_CONFIG2: u8 = 0x31;
const SX127X_FSK_REG_PAYLOAD_LENGTH: u8 = 0x32;
const SX127X_REG_FIFO_THRESH: u8 = 0x35;
const SX127X_REG_IRQ_FLAGS1: u8 = 0x3e;
const SX127X_REG_DIO_MAPPING1: u8 = 0x40;
const SX127X_REG_IRQ_FLAGS2: u8 = 0x3f;
const SX127X_REG_FIFO: u8 = 0x00;
const SX127X_REG_OP_MODE: u8 = 0x01;
const SX127X_REG_FRF_MSB: u8 = 0x06;
const SX127X_REG_FRF_MID: u8 = 0x07;
const SX127X_REG_FRF_LSB: u8 = 0x08;
const SX127X_REG_FIFO_RX_BASE: u8 = 0x0f;
const SX127X_REG_FIFO_RX_CURRENT: u8 = 0x10;
const SX127X_REG_IRQ_FLAGS: u8 = 0x12;
const SX127X_REG_RX_BYTES: u8 = 0x13;
const SX127X_REG_PKT_SNR: u8 = 0x19;
const SX127X_REG_PKT_RSSI: u8 = 0x1a;
// In FSK mode RSSI_VALUE is the instantaneous RSSI sample.  Unlike the
// LoRa packet RSSI register it is reported as a positive half-dB magnitude.
const SX127X_REG_FSK_RSSI_VALUE: u8 = 0x24;
const SX127X_REG_MODEM1: u8 = 0x1d;
const SX127X_REG_MODEM2: u8 = 0x1e;
const SX127X_REG_PREAMBLE_MSB: u8 = 0x20;
const SX127X_REG_PREAMBLE_LSB: u8 = 0x21;
const SX127X_REG_MODEM3: u8 = 0x26;
const SX127X_REG_SYNC: u8 = 0x39;
const SX127X_REG_DIO_MAPPING: u8 = 0x40;
const SX127X_LONG_RANGE: u8 = 0x80;
const SX127X_MODE_SLEEP: u8 = 0x00;
const SX127X_MODE_STDBY: u8 = 0x01;
const SX127X_MODE_TX: u8 = 0x03;
const SX127X_MODE_RX_CONTINUOUS: u8 = 0x05;
const SX127X_MODE_RX_SINGLE: u8 = 0x06;
const SX127X_MODE_CAD: u8 = 0x07;
const SX127X_IRQ_RX_DONE: u8 = 0x40;
const SX127X_IRQ_CRC_ERROR: u8 = 0x20;
const SX127X_IRQ_TX_DONE: u8 = 0x08;
const SX127X_IRQ_CAD_DONE: u8 = 0x04;
const SX127X_IRQ_CAD_DETECTED: u8 = 0x01;
const SX127X_FSK_IRQ2_PACKET_SENT: u8 = 0x08;
const SX127X_FSK_IRQ2_PAYLOAD_READY: u8 = 0x04;
const SX127X_FIFO_RX_BASE: u8 = 0;
const MAX_PACKET: usize = 255;
const SX126X_CMD_SET_STANDBY: u8 = 0x80;
const SX126X_CMD_SET_RX: u8 = 0x82;
const SX126X_CMD_SET_CAD: u8 = 0xc5;
const SX126X_CMD_SET_CAD_PARAMS: u8 = 0x88;
const SX126X_CMD_SET_TX: u8 = 0x83;
const SX126X_CMD_SET_FS: u8 = 0xc1;
const SX126X_CMD_SET_PACKET_TYPE: u8 = 0x8a;
const SX126X_CMD_SET_RF_FREQUENCY: u8 = 0x86;
const SX126X_CMD_SET_PA_CONFIG: u8 = 0x95;
const SX126X_CMD_SET_TX_PARAMS: u8 = 0x8e;
const SX126X_CMD_SET_BUFFER_BASE_ADDRESS: u8 = 0x8f;
const SX126X_CMD_SET_MODULATION_PARAMS: u8 = 0x8b;
const SX126X_CMD_SET_PACKET_PARAMS: u8 = 0x8c;
const SX126X_CMD_SET_DIO_IRQ_PARAMS: u8 = 0x08;
const SX126X_CMD_GET_IRQ_STATUS: u8 = 0x12;
const SX126X_CMD_GET_PACKET_TYPE: u8 = 0x11;
const SX126X_CMD_CLEAR_IRQ_STATUS: u8 = 0x02;
const SX126X_CMD_GET_RX_BUFFER_STATUS: u8 = 0x13;
const SX126X_CMD_GET_PACKET_STATUS: u8 = 0x14;
const SX126X_CMD_GET_DEVICE_ERRORS: u8 = 0x17;
const SX126X_CMD_CLEAR_DEVICE_ERRORS: u8 = 0x07;
const SX126X_CMD_WRITE_BUFFER: u8 = 0x0e;
const SX126X_CMD_READ_BUFFER: u8 = 0x1e;
const SX126X_CMD_WRITE_REGISTER: u8 = 0x0d;
const SX126X_CMD_READ_REGISTER: u8 = 0x1d;
const SX126X_CMD_SET_REGULATOR_MODE: u8 = 0x96;
const SX126X_CMD_CALIBRATE: u8 = 0x89;
const SX126X_CMD_CALIBRATE_IMAGE: u8 = 0x98;
const SX126X_CMD_SET_RX_TX_FALLBACK_MODE: u8 = 0x93;
const SX126X_CMD_SET_DIO2_AS_RF_SWITCH: u8 = 0x9d;
const SX126X_CMD_SET_DIO3_AS_TCXO_CTRL: u8 = 0x97;
const SX126X_PACKET_TYPE_GFSK: u8 = 0x00;
const SX126X_PACKET_TYPE_LORA: u8 = 0x01;
const SX126X_IRQ_TX_DONE: u16 = 0x0001;
const SX126X_IRQ_RX_DONE: u16 = 0x0002;
const SX126X_IRQ_CAD_DONE: u16 = 0x0004;
const SX126X_IRQ_CAD_DETECTED: u16 = 0x0008;
const SX126X_IRQ_CRC_ERR: u16 = 0x0040;
const SX126X_IRQ_TIMEOUT: u16 = 0x0200;
const SX126X_REG_SYNC_WORD: u16 = 0x0740;
const SX126X_REG_OCP: u16 = 0x08e7;
const SX126X_REG_RX_GAIN: u16 = 0x08ac;
const SX126X_REG_RX_SENSITIVITY: u16 = 0x08b5;
const SX126X_REG_TX_CLAMP_CONFIG: u16 = 0x08d8;

#[inline(always)] fn command_is(command: &str, bytes: &[u8]) -> bool {
    let actual = command.as_bytes();
    if actual.len() != bytes.len() { return false; }
    let mut i = 0;
    while i < bytes.len() {
        if actual[i] != bytes[i] { return false; }
        i += 1;
    }
    true
}
#[inline(always)] fn command_probe(command: &str) -> bool {
    let a = command.as_bytes(); a.len() == 5 && a[0] == 112 && a[1] == 114 && a[2] == 111 && a[3] == 98 && a[4] == 101
}
#[inline(always)] fn command_probe127(command: &str) -> bool {
    let a = command.as_bytes(); a.len() == 8 && a[0] == 112 && a[1] == 114 && a[2] == 111 && a[3] == 98 && a[4] == 101 && a[5] == 49 && a[6] == 50 && a[7] == 55
}
#[inline(always)] fn command_probe126(command: &str) -> bool {
    let a = command.as_bytes(); a.len() == 8 && a[0] == 112 && a[1] == 114 && a[2] == 111 && a[3] == 98 && a[4] == 101 && a[5] == 49 && a[6] == 50 && a[7] == 54
}
#[inline(always)] fn command_fsk(command: &str) -> bool {
    let a = command.as_bytes(); a.len() == 3 && a[0] == 102 && a[1] == 115 && a[2] == 107
}
#[inline(always)] fn command_tx(command: &str) -> bool {
    let a = command.as_bytes(); a.len() == 2 && a[0] == 116 && a[1] == 120
}
#[inline(always)] fn command_rx(command: &str) -> bool {
    let a = command.as_bytes(); a.len() == 2 && a[0] == 114 && a[1] == 120
}
#[inline(always)] fn command_stop(command: &str) -> bool {
    let a = command.as_bytes(); a.len() == 4 && a[0] == 115 && a[1] == 116 && a[2] == 111 && a[3] == 112
}

#[inline(always)] unsafe fn log(ctx: &ModuleContext, text: &[u8]) {
    if let Some(f) = ctx.log_line { let _ = f(ctx.user, text.as_ptr(), text.len()); }
}

#[inline(always)] unsafe fn event(ctx: &ModuleContext, event_id: u16, payload: &[u8]) {
    if let Some(emit) = ctx.emit_event {
        let event = ModuleEvent {
            event_id,
            value_type: if payload.is_empty() { 0 } else { 3 },
            flags: 0,
            value: payload.as_ptr(),
            value_len: payload.len(),
        };
        let _ = emit(ctx.user, &event);
    }
}

#[inline(always)] unsafe fn event_bytes(ctx: &ModuleContext, event_id: u16, bytes: &[u8]) {
    event(ctx, event_id, bytes);
}

#[inline(always)] unsafe fn event_i32(ctx: &ModuleContext, event_id: u16, value: i32) {
    event(ctx, event_id, &value.to_le_bytes());
}

#[inline(always)] unsafe fn power_down_radio(host: &LoraHost, config: &LoraConfig) {
    if config.board_power_pin >= 0 {
        if let Some(write) = host.gpio_write {
            let off = if config.board_power_level == 0 { 1 } else { 0 };
            let _ = write(host.user, config.board_power_pin, off);
        }
    }
}

#[inline(always)] unsafe fn probe_sx127x(host: &LoraHost) -> i32 {
    let Some(spi) = host.spi_transfer else { return -2 };
    let tx = [REG_VERSION & 0x7f, 0];
    let mut rx = [0u8; 2];
    let rc = spi(host.user, tx.as_ptr(), rx.as_mut_ptr(), tx.len());
    if rc != 0 { return -3; }
    if rx[1] == SX127X_VERSION { 0 } else { -6 }
}

#[inline(always)] unsafe fn probe_sx126x(host: &LoraHost) -> i32 {
    let Some(spi) = host.spi_transfer else { return -2 };
    let tx = [SX126X_GET_STATUS, 0];
    let mut rx = [0u8; 2];
    let rc = spi(host.user, tx.as_ptr(), rx.as_mut_ptr(), tx.len());
    if rc == 0 && rx[1] != 0 { 0 } else if rc == 0 { -6 } else { -3 }
}

#[inline(always)] unsafe fn sx127x_fsk_setup(host: &LoraHost, config: &LoraConfig) -> i32 {
    let Some(spi) = host.spi_transfer else { return -2 };
    // Main may have left the shared SX127x in LoRa RX or an incomplete
    // previous FSK state. A short module-owned reset makes the modem-bank
    // transition deterministic and uses the persisted board reset pin.
    if config.reset_pin >= 0 {
        if let Some(write) = host.gpio_write {
            let _ = write(host.user, config.reset_pin as i32, 0);
            if let Some(wait) = host.wait_irq { let _ = wait(host.user, 10); }
            let _ = write(host.user, config.reset_pin as i32, 1);
            if let Some(wait) = host.wait_irq { let _ = wait(host.user, 20); }
        }
    }
    // LongRangeMode can only be changed while asleep. A direct write of 0x00
    // while the LoRa state machine is active may be ignored, leaving all
    // overlapping registers in the LoRa bank. Follow the reference two-step
    // switch and verify the mode before touching FSK registers.
    if sx127x_write(host, SX127X_REG_OP_MODE, SX127X_LONG_RANGE | SX127X_MODE_SLEEP) != 0 { return -310; }
    if let Some(wait) = host.wait_irq { let _ = wait(host.user, 1); }
    if sx127x_write(host, SX127X_REG_OP_MODE, SX127X_MODE_SLEEP) != 0 { return -311; }
    if let Some(wait) = host.wait_irq { let _ = wait(host.user, 1); }
    if sx127x_read(host, SX127X_REG_OP_MODE).map(|value| value & SX127X_LONG_RANGE != 0).unwrap_or(true) { return -312; }
    let frf = ((config.frequency_hz as u64) << 19) / 32_000_000;
    for (index, (reg, value)) in [
        (SX127X_REG_FRF_MSB, (frf >> 16) as u8),
        (SX127X_REG_FRF_MID, (frf >> 8) as u8),
        (SX127X_REG_FRF_LSB, frf as u8),
        (SX127X_REG_BITRATE_MSB, 0x01), // 100 kbit/s
        (SX127X_REG_BITRATE_LSB, 0x40),
        (SX127X_REG_FDEV_MSB, 0x00),
        (SX127X_REG_FDEV_LSB, 0x52),
        (SX127X_FSK_REG_RX_BW, 0x01),
        (SX127X_FSK_REG_AFC_BW, 0x01),
        (SX127X_FSK_REG_PREAMBLE_MSB, 0x00),
        (SX127X_FSK_REG_PREAMBLE_LSB, 0x10),
        (SX127X_FSK_REG_PREAMBLE_DETECT, 0xaa),
        (SX127X_REG_SYNC_CONFIG, 0x11), // sync enabled, two sync bytes
        (SX127X_REG_SYNC_VALUE, 0xd3),
        (SX127X_REG_SYNC_VALUE + 1, 0xa5),
        // Variable packet profile: the FIFO begins with the payload length.
        (SX127X_REG_PACKET_CONFIG1, 0x90),
        // PacketConfig2 bit 6 selects the FIFO packet engine. The former
        // 0x00 selected continuous data mode and never framed RX packets.
        (SX127X_REG_PACKET_CONFIG2, 0x40),
        (SX127X_FSK_REG_PAYLOAD_LENGTH, 0xff),
        (SX127X_REG_FIFO_THRESH, 0x8f),
        (SX127X_FSK_REG_RX_CONFIG, 0x1e),
        (SX127X_REG_DIO_MAPPING1, 0x34), // DIO0=FSK ready, DIO1/2 unused
        (SX127X_REG_PA_RAMP, 0x29), // Gaussian BT=0.5, 40 us ramp
        (SX127X_REG_PA_CONFIG, 0x8f), // 17 dBm, same persisted LoRa power
    ].into_iter().enumerate() {
        let tx = [reg | 0x80, value];
        let mut rx = [0u8; 2];
        if spi(host.user, tx.as_ptr(), rx.as_mut_ptr(), tx.len()) != 0 { return -300 - index as i32; }
    }
    // Leave the radio in a valid FSK standby state.  Entering RX/TX directly
    // from Sleep is not accepted reliably by all SX127x revisions.
    if sx127x_write(host, SX127X_REG_OP_MODE, SX127X_MODE_STDBY) != 0 { return -313; }
    0
}

#[inline(always)] unsafe fn sx127x_fsk_send(host: &LoraHost, packet: &[u8]) -> i32 {
    if packet.is_empty() || packet.len() > MAX_PACKET { return -1; }
    let current_mode = sx127x_read(host, SX127X_REG_OP_MODE).unwrap_or(0);
    // Preserve the SX127x low-frequency oscillator bit, but explicitly clear
    // LongRangeMode and modulation-type bits before entering FSK TX.
    let fsk_base = current_mode & !0xe7;
    if sx127x_write(host, SX127X_REG_OP_MODE, fsk_base | SX127X_MODE_STDBY) != 0 { return -3; }
    // Use the reference byte-at-a-time FIFO sequence. It keeps each FIFO
    // write explicit across the ESP-IDF SPI wrapper and avoids relying on a
    // burst transaction's CS/FIFO auto-increment behavior in FSK mode.
    if sx127x_write(host, SX127X_FSK_REG_PAYLOAD_LENGTH, packet.len() as u8) != 0 { return -3; }
    // Variable-length FSK packets carry the payload length as the first FIFO
    // byte; SX127x removes it before exposing the received payload.
    if sx127x_write(host, SX127X_REG_FIFO, packet.len() as u8) != 0 { return -3; }
    for &byte in packet {
        if sx127x_write(host, SX127X_REG_FIFO, byte) != 0 { return -3; }
    }
    if sx127x_write(host, SX127X_REG_DIO_MAPPING1, 0x34) != 0 { return -3; }
    // IRQ_FLAGS2 status bits are read/clear; the reference FSK TX path leaves
    // them untouched before starting the packet engine.
    // Give the synthesizer an explicit FSTx phase before the packet engine
    // enters Tx; this avoids a stuck FIFO-empty state on some SX127x lots.
    if sx127x_write(host, SX127X_REG_OP_MODE, fsk_base | 0x02) != 0 { return -3; }
    if let Some(wait) = host.wait_irq { let _ = wait(host.user, 1); }
    if sx127x_write(host, SX127X_REG_OP_MODE, fsk_base | SX127X_MODE_TX) != 0 { return -3; }
    // The host tick is 10 ms; yield for a full tick while waiting for the
    // packet-sent flag so the radio task does not busy-loop.
    for _ in 0..100 {
        if let Ok(flags) = sx127x_read(host, SX127X_REG_IRQ_FLAGS2) {
            if flags & SX127X_FSK_IRQ2_PACKET_SENT != 0 {
                let _ = sx127x_write(host, SX127X_REG_OP_MODE, SX127X_MODE_STDBY);
                return 0;
            }
        }
        if let Some(wait) = host.wait_irq { let _ = wait(host.user, 10); }
    }
    -1000
}

#[inline(always)] unsafe fn sx127x_fsk_start_rx(host: &LoraHost, config: &LoraConfig) -> i32 {
    let setup = sx127x_fsk_setup(host, config);
    if setup != 0 { return setup; }
    if sx127x_write(host, SX127X_REG_DIO_MAPPING1, 0x00) != 0 { return -321; }
    if sx127x_write(host, SX127X_REG_IRQ_FLAGS2, 0xff) != 0 { return -322; }
    let current_mode = sx127x_read(host, SX127X_REG_OP_MODE).unwrap_or(0);
    if sx127x_write(host, SX127X_REG_OP_MODE, (current_mode & !0xe7) | SX127X_MODE_RX_CONTINUOUS) != 0 { return -320; }
    if let Some(configure) = host.irq_configure { let _ = configure(host.user, config.irq_pin as i32, 1); }
    if let Some(enable) = host.irq_enable { let _ = enable(host.user, config.irq_pin as i32, 1); }
    0
}

#[inline(always)] unsafe fn sx127x_fsk_emit_packet(host: &LoraHost) -> i32 {
    let flags = match sx127x_read(host, SX127X_REG_IRQ_FLAGS2) { Ok(v) => v, Err(e) => return e };
    if flags & SX127X_FSK_IRQ2_PAYLOAD_READY == 0 { return 1; }
    let len = 8;
    let mut packet = [0u8; MAX_PACKET];
    if sx127x_read_burst(host, SX127X_REG_FIFO, &mut packet[..len]) != 0 { return -3; }
    /* IRQ_FLAGS2 is write-one-to-clear on SX127x FSK.  Clear PayloadReady
     * after draining the FIFO; otherwise the polling loop emits the same
     * frame repeatedly and Main counts a storm of duplicate packets. */
    let _ = sx127x_write(host, SX127X_REG_IRQ_FLAGS2, 0xff);
    // FSK has no SNR measurement.  Preserve the measured RSSI in the common
    // callback so Main can put it in the ESP-NOW receive envelope instead of
    // silently reporting zero for every FSK frame.
    let rssi = sx127x_read(host, SX127X_REG_FSK_RSSI_VALUE)
        // SX127x FSK RSSI_VALUE has 0.5 dB units, unlike the LoRa
        // RegPktRssiValue register used by the LoRa path.
        .map(|raw| -((raw as i32) / 2))
        .unwrap_or(0);
    if let Some(emit) = host.emit_packet {
        emit(host.user, packet.as_ptr(), len, rssi.clamp(i16::MIN as i32, i16::MAX as i32) as i16, 0)
    } else { 0 }
}

#[inline(always)] unsafe fn event_sx127x_fsk_error(ctx: &ModuleContext, host: &LoraHost, rc: i32) {
    let op = sx127x_read(host, SX127X_REG_OP_MODE).unwrap_or(0xff) as u16;
    let irq = sx127x_read(host, SX127X_REG_IRQ_FLAGS2).unwrap_or(0xff) as u16;
    // Diagnostic event IDs reserve 0x40xx: the low two bytes are the
    // SX127x OpMode and IRQ_FLAGS2 values observed at failure. This keeps the
    // evidence visible through Main's bounded status surface even while the
    // event payload ABI is being migrated to typed CBOR values.
    event_i32(ctx, 0x4000 | (op << 8) | irq, rc);
}

#[inline(always)] unsafe fn sx127x_write(host: &LoraHost, reg: u8, value: u8) -> i32 {
    let Some(spi) = host.spi_transfer else { return -2 };
    let tx = [reg | 0x80, value];
    let mut rx = [0u8; 2];
    spi(host.user, tx.as_ptr(), rx.as_mut_ptr(), tx.len())
}

#[inline(always)] unsafe fn sx127x_read(host: &LoraHost, reg: u8) -> Result<u8, i32> {
    let Some(spi) = host.spi_transfer else { return Err(-2) };
    let tx = [reg & 0x7f, 0];
    let mut rx = [0u8; 2];
    let rc = spi(host.user, tx.as_ptr(), rx.as_mut_ptr(), tx.len());
    if rc == 0 { Ok(rx[1]) } else { Err(-3) }
}

#[inline(always)] unsafe fn sx127x_burst(host: &LoraHost, reg: u8, data: &[u8]) -> i32 {
    if data.len() > MAX_PACKET { return -1; }
    let Some(spi) = host.spi_transfer else { return -2 };
    let mut tx = [0u8; MAX_PACKET + 1];
    let mut rx = [0u8; MAX_PACKET + 1];
    tx[0] = reg | 0x80;
    tx[1..data.len() + 1].copy_from_slice(data);
    spi(host.user, tx.as_ptr(), rx.as_mut_ptr(), data.len() + 1)
}

#[inline(always)] unsafe fn sx127x_read_burst(host: &LoraHost, reg: u8, data: &mut [u8]) -> i32 {
    if data.len() > MAX_PACKET { return -1; }
    let Some(spi) = host.spi_transfer else { return -2 };
    let mut tx = [0u8; MAX_PACKET + 1];
    let mut rx = [0u8; MAX_PACKET + 1];
    tx[0] = reg & 0x7f;
    let rc = spi(host.user, tx.as_ptr(), rx.as_mut_ptr(), data.len() + 1);
    if rc == 0 { data.copy_from_slice(&rx[1..data.len() + 1]); }
    rc
}

#[inline(always)] unsafe fn sx127x_configure_rx(host: &LoraHost, config: &LoraConfig) -> i32 {
    if config.abi_version != LORA_ABI_VERSION || config.size < core::mem::size_of::<LoraConfig>() as u32 { return -2; }
    if config.chip != 1 { return -2; }
    if sx127x_write(host, SX127X_REG_OP_MODE, SX127X_LONG_RANGE | SX127X_MODE_SLEEP) != 0 { return -3; }
    let frf = ((config.frequency_hz as u64) << 19) / 32_000_000;
    let bw = if config.bandwidth_hz == 7_800 { 0 }
        else if config.bandwidth_hz == 10_400 { 1 }
        else if config.bandwidth_hz == 15_600 { 2 }
        else if config.bandwidth_hz == 20_800 { 3 }
        else if config.bandwidth_hz == 31_250 { 4 }
        else if config.bandwidth_hz == 41_700 { 5 }
        else if config.bandwidth_hz == 62_500 { 6 }
        else if config.bandwidth_hz == 125_000 { 7 }
        else if config.bandwidth_hz == 250_000 { 8 }
        else if config.bandwidth_hz == 500_000 { 9 }
        else { return -1 };
    let cr = config.coding_rate.clamp(4, 8).saturating_sub(4) as u8;
    let sf = config.spreading_factor.clamp(6, 12) as u8;
    let symbol_ms = ((1u64 << sf) * 1000 / config.bandwidth_hz.max(1) as u64) as u32;
    let modem1 = (bw << 4) | (cr << 1); // explicit header
    let modem2 = (sf << 4) | if config.crc != 0 { 0x04 } else { 0 };
    let modem3 = 0x04 | if symbol_ms >= 16 { 0x08 } else { 0 }; // AGC + optional LDRO
    let preamble = config.preamble.clamp(1, 65535) as u16;
    for (reg, value) in [
        (SX127X_REG_FRF_MSB, (frf >> 16) as u8),
        (SX127X_REG_FRF_MID, (frf >> 8) as u8),
        (SX127X_REG_FRF_LSB, frf as u8),
        (SX127X_REG_FIFO_RX_BASE, SX127X_FIFO_RX_BASE),
        (SX127X_REG_MODEM1, modem1),
        (SX127X_REG_MODEM2, modem2),
        (SX127X_REG_MODEM3, modem3),
        (SX127X_REG_PREAMBLE_MSB, (preamble >> 8) as u8),
        (SX127X_REG_PREAMBLE_LSB, preamble as u8),
        (SX127X_REG_SYNC, config.sync_word),
        (SX127X_REG_DIO_MAPPING, 0),
        (SX127X_REG_IRQ_FLAGS, 0xff),
    ] {
        if sx127x_write(host, reg, value) != 0 { return -3; }
    }
    sx127x_write(host, SX127X_REG_OP_MODE,
                 SX127X_LONG_RANGE | if config.cad_rx != 0 {
                     SX127X_MODE_STDBY
                 } else {
                     SX127X_MODE_RX_CONTINUOUS
                 })
}

#[inline(always)] unsafe fn sx127x_start_cad(host: &LoraHost) -> i32 {
    if sx127x_write(host, SX127X_REG_IRQ_FLAGS, 0xff) != 0 { return -3; }
    sx127x_write(host, SX127X_REG_OP_MODE, SX127X_LONG_RANGE | SX127X_MODE_CAD)
}

#[inline(always)] unsafe fn sx127x_cad_window(host: &LoraHost, config: &LoraConfig) -> i32 {
    if sx127x_start_cad(host) != 0 { return -3; }
    let cadence = if config.cad_interval_ms == 0 { 5 } else { config.cad_interval_ms };
    wait_for_irq(host, config.irq_pin, cadence);
    let irq = match sx127x_read(host, SX127X_REG_IRQ_FLAGS) {
        Ok(value) => value,
        Err(error) => return error,
    };
    if sx127x_write(host, SX127X_REG_IRQ_FLAGS, 0xff) != 0 { return -3; }
    if irq & SX127X_IRQ_CAD_DONE == 0 { return 1; }
    if irq & SX127X_IRQ_CAD_DETECTED == 0 { return 2; }
    if sx127x_write(host, SX127X_REG_OP_MODE, SX127X_LONG_RANGE | SX127X_MODE_RX_SINGLE) != 0 { return -3; }
    let receive_ms = if config.cad_rx_ms == 0 { 1000 } else { config.cad_rx_ms };
    wait_for_irq(host, config.irq_pin, receive_ms);
    if sx127x_emit_packet(host) == 0 { return 0; }
    let _ = sx127x_write(host, SX127X_REG_OP_MODE, SX127X_LONG_RANGE | SX127X_MODE_STDBY);
    1
}

#[inline(always)] unsafe fn sx127x_emit_packet(host: &LoraHost) -> i32 {
    let irq = match sx127x_read(host, SX127X_REG_IRQ_FLAGS) { Ok(v) => v, Err(e) => return e };
    if irq & SX127X_IRQ_RX_DONE == 0 { return 1; }
    if sx127x_write(host, SX127X_REG_IRQ_FLAGS, 0xff) != 0 { return -3; }
    if irq & SX127X_IRQ_CRC_ERROR != 0 { return 2; }
    let len = match sx127x_read(host, SX127X_REG_RX_BYTES) { Ok(v) => v as usize, Err(e) => return e };
    if len == 0 || len > MAX_PACKET { return -6; }
    let current = match sx127x_read(host, SX127X_REG_FIFO_RX_CURRENT) { Ok(v) => v, Err(e) => return e };
    if sx127x_write(host, SX127X_REG_FIFO_RX_BASE, current) != 0 { return -3; }
    let mut packet = [0u8; MAX_PACKET];
    if sx127x_read_burst(host, SX127X_REG_FIFO, &mut packet[..len]) != 0 { return -3; }
    let rssi = sx127x_read(host, SX127X_REG_PKT_RSSI).unwrap_or(0) as i16 - 157;
    let snr = sx127x_read(host, SX127X_REG_PKT_SNR).unwrap_or(0) as i8 / 4;
    if let Some(emit) = host.emit_packet {
        emit(host.user, packet.as_ptr(), len, rssi, snr)
    } else { 0 }
}

#[inline(always)] unsafe fn sx127x_send(host: &LoraHost, packet: &[u8]) -> i32 {
    if packet.is_empty() || packet.len() > MAX_PACKET { return -1; }
    if sx127x_write(host, SX127X_REG_OP_MODE, SX127X_LONG_RANGE | SX127X_MODE_STDBY) != 0 { return -3; }
    if sx127x_write(host, 0x0e, 0) != 0 || sx127x_write(host, 0x0d, 0) != 0 { return -3; }
    if sx127x_burst(host, SX127X_REG_FIFO, packet) != 0 { return -3; }
    if sx127x_write(host, 0x22, packet.len() as u8) != 0 || sx127x_write(host, SX127X_REG_IRQ_FLAGS, 0xff) != 0 { return -3; }
    if sx127x_write(host, SX127X_REG_OP_MODE, SX127X_LONG_RANGE | SX127X_MODE_TX) != 0 { return -3; }
    for _ in 0..200 {
        if sx127x_read(host, SX127X_REG_IRQ_FLAGS).unwrap_or(0) & SX127X_IRQ_TX_DONE != 0 {
            let _ = sx127x_write(host, SX127X_REG_IRQ_FLAGS, SX127X_IRQ_TX_DONE);
            return 0;
        }
        // SetDio3AsTcxoCtrl timeout is ~25 ms on this board; allow the
        // oscillator to settle before programming the packet engine.
        if let Some(wait) = host.wait_irq { let _ = wait(host.user, 30); }
    }
    -4
}

#[inline(always)] unsafe fn sx126x_command(host: &LoraHost, opcode: u8, data: &[u8]) -> i32 {
    if data.len() > 16 { return -1; }
    let Some(spi) = host.spi_transfer else { return -2 };
    let mut tx = [0u8; 18];
    let mut rx = [0u8; 18];
    tx[0] = opcode;
    tx[1..data.len() + 1].copy_from_slice(data);
    spi(host.user, tx.as_ptr(), rx.as_mut_ptr(), data.len() + 1)
}

#[inline(always)] unsafe fn sx126x_read(host: &LoraHost, opcode: u8, args: &[u8], out: &mut [u8]) -> i32 {
    if args.len() > 8 || out.len() > MAX_PACKET { return -1; }
    let Some(spi) = host.spi_transfer else { return -2 };
    let mut tx = [0u8; MAX_PACKET + 11];
    let mut rx = [0u8; MAX_PACKET + 11];
    tx[0] = opcode;
    tx[1..args.len() + 1].copy_from_slice(args);
    let total = args.len() + out.len() + 2;
    let rc = spi(host.user, tx.as_ptr(), rx.as_mut_ptr(), total);
    if rc == 0 {
        /* GetStatus returns its single status byte immediately after the
         * opcode; the other commands have a leading SPI status byte followed
         * by their response payload. */
        let response_offset = if opcode == SX126X_GET_STATUS { 1 } else { args.len() + 2 };
        out.copy_from_slice(&rx[response_offset..response_offset + out.len()]);
    }
    rc
}

#[inline(always)] unsafe fn sx126x_configure_rx(host: &LoraHost, config: &LoraConfig) -> i32 {
    if config.abi_version != LORA_ABI_VERSION || config.size < core::mem::size_of::<LoraConfig>() as u32 || config.chip != 2 { return -2; }
    if sx126x_command(host, SX126X_CMD_SET_STANDBY, &[0]) != 0 { return -3; }
    if sx126x_command(host, SX126X_CMD_SET_REGULATOR_MODE, &[1]) != 0 { return -3; }
    /* SX1262 reset leaves the analog image and PA path uncalibrated. The
     * production Main driver performs these steps before every radio session;
     * the module must do the same because it owns the complete radio setup. */
    if sx126x_command(host, SX126X_CMD_CALIBRATE, &[0x7f]) != 0 { return -3; }
    if sx126x_command(host, SX126X_CMD_CALIBRATE_IMAGE, &[0xe1, 0xe9]) != 0 { return -3; }
    if sx126x_command(host, SX126X_CMD_SET_RX_TX_FALLBACK_MODE, &[0x20]) != 0 { return -3; }
    let mut clamp = [0u8; 1];
    if sx126x_read(host, SX126X_CMD_READ_REGISTER,
                   &[(SX126X_REG_TX_CLAMP_CONFIG >> 8) as u8, SX126X_REG_TX_CLAMP_CONFIG as u8],
                   &mut clamp) != 0 { return -3; }
    if sx126x_write_register(host, SX126X_REG_TX_CLAMP_CONFIG, &[clamp[0] | 0x1e]) != 0 { return -3; }
    if sx126x_set_tcxo(host, config.sx1262_tcxo_mv) != 0 { return -1; }
    if config.sx1262_tcxo_mv > 0 {
        if let Some(wait) = host.wait_irq { let _ = wait(host.user, 5); }
    }
    // XOSC_START_ERR is latched at POR when a TCXO is used and is explicitly
    // documented as expected on the first wake. Clear the stale latch before
    // starting the packet engine so the post-TX diagnostic reflects a new
    // failure, not the boot-time condition.
    if sx126x_command(host, SX126X_CMD_CLEAR_DEVICE_ERRORS, &[0, 0]) != 0 { return -3; }
    if config.sx1262_dio2_rf_switch != 0 &&
        sx126x_command(host, SX126X_CMD_SET_DIO2_AS_RF_SWITCH, &[1]) != 0 { return -3; }
    if sx126x_command(host, SX126X_CMD_SET_PACKET_TYPE, &[SX126X_PACKET_TYPE_LORA]) != 0 { return -3; }
    let rf = ((config.frequency_hz as u64) << 25) / 32_000_000;
    if sx126x_command(host, SX126X_CMD_SET_RF_FREQUENCY, &[(rf >> 24) as u8, (rf >> 16) as u8, (rf >> 8) as u8, rf as u8]) != 0 { return -3; }
    let pa_duty = config.sx1262_pa_duty.clamp(0, 7) as u8;
    let pa_hp = config.sx1262_pa_hp.clamp(0, 7) as u8;
    let pa_device = config.sx1262_pa_device.clamp(0, 1) as u8;
    let pa_lut = config.sx1262_pa_lut.clamp(0, 1) as u8;
    if sx126x_command(host, SX126X_CMD_SET_PA_CONFIG, &[pa_duty, pa_hp, pa_device, pa_lut]) != 0 { return -3; }
    if sx126x_command(host, SX126X_CMD_SET_TX_PARAMS, &[((config.tx_power as i32).clamp(-9, 22) as i8) as u8, 4]) != 0 { return -3; }
    if sx126x_write_register(host, SX126X_REG_OCP, &[0x38]) != 0 { return -3; }
    let sync = config.sx1262_sync_word.clamp(0, 0xffff) as u16;
    if sx126x_write_register(host, SX126X_REG_SYNC_WORD, &[(sync >> 8) as u8, sync as u8]) != 0 { return -3; }
    if sx126x_write_register(host, SX126X_REG_RX_GAIN, &[0x96]) != 0 { return -3; }
    let mut sensitivity = [0u8; 1];
    if sx126x_read(host, SX126X_CMD_READ_REGISTER,
                   &[((SX126X_REG_RX_SENSITIVITY >> 8) & 0xff) as u8, SX126X_REG_RX_SENSITIVITY as u8],
                   &mut sensitivity) != 0 { return -3; }
    if sx126x_write_register(host, SX126X_REG_RX_SENSITIVITY, &[sensitivity[0] | 1]) != 0 { return -3; }
    if sx126x_command(host, SX126X_CMD_SET_BUFFER_BASE_ADDRESS, &[0, 0x80]) != 0 { return -3; }
    // Keep this as a branch chain. The flat Xtensa image is linked without
    // relocations; a large integer `match` becomes an absolute jump table in
    // .rodata, which is invalid after flash-MMU mapping at a different base.
    let bw = if config.bandwidth_hz == 7_800 { 0 }
        else if config.bandwidth_hz == 10_400 { 8 }
        else if config.bandwidth_hz == 15_600 { 1 }
        else if config.bandwidth_hz == 20_800 { 9 }
        else if config.bandwidth_hz == 31_250 { 2 }
        else if config.bandwidth_hz == 41_700 { 10 }
        else if config.bandwidth_hz == 62_500 { 3 }
        else if config.bandwidth_hz == 125_000 { 4 }
        else if config.bandwidth_hz == 250_000 { 5 }
        else if config.bandwidth_hz == 500_000 { 6 }
        else { return -1 };
    let sf = config.spreading_factor.clamp(5, 12) as u8;
    let cr = config.coding_rate.clamp(4, 8).saturating_sub(4) as u8;
    let symbol_ms = ((1u64 << sf) * 1000 / config.bandwidth_hz.max(1) as u64) as u32;
    let ldro = if symbol_ms >= 16 { 1 } else { 0 };
    if sx126x_command(host, SX126X_CMD_SET_MODULATION_PARAMS, &[sf, bw, cr, ldro]) != 0 { return -3; }
    let preamble = config.preamble.clamp(1, 65535) as u16;
    if sx126x_command(host, SX126X_CMD_SET_PACKET_PARAMS,
                      &[(preamble >> 8) as u8, preamble as u8, 0,
                        255, if config.crc != 0 { 1 } else { 0 }, 0]) != 0 { return -3; }
    let mut irq = SX126X_IRQ_TX_DONE | SX126X_IRQ_RX_DONE | SX126X_IRQ_CRC_ERR | SX126X_IRQ_TIMEOUT;
    if config.cad_rx != 0 { irq |= SX126X_IRQ_CAD_DONE | SX126X_IRQ_CAD_DETECTED; }
    if sx126x_command(host, SX126X_CMD_SET_DIO_IRQ_PARAMS, &[(irq >> 8) as u8, irq as u8, (irq >> 8) as u8, irq as u8, 0, 0, 0, 0]) != 0 { return -3; }
    if sx126x_command(host, SX126X_CMD_CLEAR_IRQ_STATUS, &[0xff, 0xff]) != 0 { return -3; }
    if config.cad_rx == 0 {
        sx126x_command(host, SX126X_CMD_SET_RX, &[0xff, 0xff, 0xff])
    } else {
        /* Use the modem's CAD state machine instead of SetRxDutyCycle. The
         * latter is not reliable on the deployed SX1262 board (it can leave
         * DIO1 idle even with a full receive window). CAD keeps the radio in
         * its low-power detector, and we explicitly enter a bounded RX window
         * only after a preamble is detected. */
        if sx126x_command(host, SX126X_CMD_SET_CAD_PARAMS,
                          /* 4-symbol CAD, then enter RX immediately when a
                           * preamble is detected. Returning to standby and
                           * issuing SetRx afterwards loses that preamble. */
                          &[0x02, 0x1a, 0x0a, 0x01, 0xff, 0xff, 0xff]) != 0 { return -3; }
        sx126x_command(host, SX126X_CMD_SET_CAD, &[])
    }
}

#[inline(always)] unsafe fn sx126x_cad_window(host: &LoraHost, config: &LoraConfig) -> i32 {
    if sx126x_command(host, SX126X_CMD_CLEAR_IRQ_STATUS, &[0xff, 0xff]) != 0 { return -3; }
    /* CAD exits to STDBY_RC on a quiet window. Re-enter standby explicitly
     * and publish the CAD parameters before every new operation so a timeout
     * or previous RX transition cannot leave the command rejected. */
    if sx126x_command(host, SX126X_CMD_SET_STANDBY, &[0]) != 0 { return -3; }
    if sx126x_command(host, SX126X_CMD_SET_CAD_PARAMS,
                      &[0x02, 0x1a, 0x0a, 0x01, 0xff, 0xff, 0xff]) != 0 { return -3; }
    if sx126x_command(host, SX126X_CMD_SET_CAD, &[]) != 0 { return -3; }
    /* Four CAD symbols at SF10/BW250 are short; the configured interval is a
     * bounded polling floor, not a packet preamble change. */
    wait_for_irq(host, config.irq_pin, config.cad_interval_ms.max(5).min(1000));
    let mut irq_bytes = [0u8; 2];
    if sx126x_read(host, SX126X_CMD_GET_IRQ_STATUS, &[], &mut irq_bytes) != 0 { return -3; }
    let irq = u16::from_be_bytes(irq_bytes);
    if irq & SX126X_IRQ_CAD_DONE == 0 {
        let _ = sx126x_command(host, SX126X_CMD_CLEAR_IRQ_STATUS, &[0xff, 0xff]);
        let mut status = [0u8; 1];
        if sx126x_read(host, SX126X_GET_STATUS, &[], &mut status) == 0 {
            return 0x100 | status[0] as i32;
        }
        return 11;
    }
    if irq & SX126X_IRQ_CAD_DETECTED == 0 {
        let _ = sx126x_command(host, SX126X_CMD_CLEAR_IRQ_STATUS, &[0xff, 0xff]);
        return 1;
    }
    /* CAD_RX has already switched the modem into RX. Clear only the CAD
     * completion bits so the subsequent RxDone remains observable. */
    let _ = sx126x_command(host, SX126X_CMD_CLEAR_IRQ_STATUS, &[0x00, (SX126X_IRQ_CAD_DONE | SX126X_IRQ_CAD_DETECTED) as u8]);
    let receive_ms = config.cad_rx_ms.max(1).min(4000);
    wait_for_irq(host, config.irq_pin, receive_ms);
    let result = sx126x_emit_packet(host);
    if result == 0 { return 0; }
    let _ = sx126x_command(host, SX126X_CMD_CLEAR_IRQ_STATUS, &[0xff, 0xff]);
    /* 2 means CAD detected activity but no valid packet completed; 1 is the
     * normal quiet-channel result. This distinction is surfaced as event 7
     * so the host can diagnose detector versus RX failures without a UART
     * parser. */
    if irq & SX126X_IRQ_CAD_DETECTED != 0 { 2 } else { 1 }
}

#[inline(always)] unsafe fn sx126x_emit_packet(host: &LoraHost) -> i32 {
    let mut irq_bytes = [0u8; 2];
    if sx126x_read(host, SX126X_CMD_GET_IRQ_STATUS, &[], &mut irq_bytes) != 0 { return -3; }
    let irq = u16::from_be_bytes(irq_bytes);
    if irq & SX126X_IRQ_RX_DONE == 0 { return 1; }
    let _ = sx126x_command(host, SX126X_CMD_CLEAR_IRQ_STATUS, &[0xff, 0xff]);
    if irq & SX126X_IRQ_CRC_ERR != 0 { return 2; }
    let mut status = [0u8; 2];
    if sx126x_read(host, SX126X_CMD_GET_RX_BUFFER_STATUS, &[], &mut status) != 0 { return -3; }
    let len = status[0] as usize;
    if len == 0 || len > MAX_PACKET { return -6; }
    let mut packet = [0u8; MAX_PACKET];
    if sx126x_read(host, SX126X_CMD_READ_BUFFER, &[status[1]], &mut packet[..len]) != 0 { return -3; }
    let mut stat = [0u8; 3];
    let _ = sx126x_read(host, SX126X_CMD_GET_PACKET_STATUS, &[], &mut stat);
    let rssi = -(stat[0] as i16) / 2;
    let snr = (stat[1] as i8) / 4;
    if let Some(emit) = host.emit_packet { emit(host.user, packet.as_ptr(), len, rssi, snr) } else { 0 }
}

#[inline(always)] unsafe fn sx126x_send(host: &LoraHost, config: &LoraConfig, packet: &[u8]) -> i32 {
    if packet.is_empty() || packet.len() > MAX_PACKET { return -1; }
    if sx126x_command(host, SX126X_CMD_SET_STANDBY, &[0]) != 0 { return -3; }
    let preamble = config.preamble.clamp(1, 65535) as u16;
    if sx126x_command(host, SX126X_CMD_SET_PACKET_PARAMS,
                      &[(preamble >> 8) as u8, preamble as u8, 0,
                        packet.len() as u8, if config.crc != 0 { 1 } else { 0 }, 0]) != 0 { return -3; }
    let mut tx = [0u8; MAX_PACKET + 2];
    let mut rx = [0u8; MAX_PACKET + 2];
    tx[0] = SX126X_CMD_WRITE_BUFFER;
    tx[1] = 0;
    tx[2..packet.len() + 2].copy_from_slice(packet);
    let Some(spi) = host.spi_transfer else { return -2 };
    if spi(host.user, tx.as_ptr(), rx.as_mut_ptr(), packet.len() + 2) != 0 { return -3; }
    let _ = sx126x_command(host, SX126X_CMD_CLEAR_IRQ_STATUS, &[0xff, 0xff]);
    // One second in SX1262 15.625-us timeout units. The bounded timeout
    // matches the validated host sender and avoids leaving a failed TX in an
    // effectively infinite modem state.
    if sx126x_command(host, SX126X_CMD_SET_FS, &[]) != 0 { return -3; }
    // SX126x timeout units are 15.625 us; use the device's maximum bounded
    // timeout so a failed LoRa TX cannot leave the modem in an unbounded state.
    if sx126x_command(host, SX126X_CMD_SET_TX, &[0xff, 0xff, 0xff]) != 0 { return -3; }
    let mut last_irq = 0u16;
    for _ in 0..200 {
        let mut bytes = [0u8; 2];
        if sx126x_read(host, SX126X_CMD_GET_IRQ_STATUS, &[], &mut bytes) == 0 {
            let irq = u16::from_be_bytes(bytes);
            last_irq = irq;
            if irq & SX126X_IRQ_TX_DONE != 0 { let _ = sx126x_command(host, SX126X_CMD_CLEAR_IRQ_STATUS, &[0xff, 0xff]); return 0; }
            if irq & 0x0200 != 0 {
                let _ = sx126x_command(host, SX126X_CMD_CLEAR_IRQ_STATUS, &[0xff, 0xff]);
                let _ = sx126x_command(host, SX126X_CMD_SET_STANDBY, &[0]);
                return -1000 - irq as i32;
            }
        }
        if let Some(wait) = host.wait_irq { let _ = wait(host.user, 5); }
    }
    /* Preserve the last modem IRQ bits in the diagnostic result. Main still
     * treats every negative value as a failed TX, while status makes it
     * possible to distinguish a radio timeout from a never-started TX. */
    // A failed SetTx can leave the SX1262 in TX with BUSY held. Always return
    // it to standby before the persistent task re-arms RX; otherwise one
    // transient TX error wedges module status and stop/upgrade commands.
    let _ = sx126x_command(host, SX126X_CMD_CLEAR_IRQ_STATUS, &[0xff, 0xff]);
    let _ = sx126x_command(host, SX126X_CMD_SET_STANDBY, &[0]);
    -1000 - last_irq as i32
}

#[inline(always)] unsafe fn sx126x_hard_reset(host: &LoraHost, config: &LoraConfig) {
    if config.reset_pin < 0 { return; }
    if let Some(write) = host.gpio_write {
        let _ = write(host.user, config.reset_pin as i32, 0);
        if let Some(wait) = host.wait_irq { let _ = wait(host.user, 30); }
        let _ = write(host.user, config.reset_pin as i32, 1);
        if let Some(wait) = host.wait_irq { let _ = wait(host.user, 20); }
    }
}

#[inline(always)] unsafe fn sx126x_write_register(host: &LoraHost, address: u16, value: &[u8]) -> i32 {
    if value.len() > 8 { return -1; }
    let Some(spi) = host.spi_transfer else { return -2 };
    let mut tx = [0u8; 11];
    let mut rx = [0u8; 11];
    tx[0] = SX126X_CMD_WRITE_REGISTER;
    tx[1] = (address >> 8) as u8;
    tx[2] = address as u8;
    tx[3..value.len() + 3].copy_from_slice(value);
    spi(host.user, tx.as_ptr(), rx.as_mut_ptr(), value.len() + 3)
}

#[inline(always)] unsafe fn sx126x_set_tcxo(host: &LoraHost, millivolts: i32) -> i32 {
    /* Keep this as a branch chain: the Xtensa flat-image lane must not gain a
     * literal jump table whose addresses depend on the mapping base. */
    let voltage = if millivolts == 0 { return 0 }
        // SX126x TCXO voltage codes use 1.5 V as code 0, then the table
        // advances through 1.6, 1.7, 1.8, 2.2, 2.4, 2.7, and 3.0 V.
        else if millivolts == 1500 { 0 }
        else if millivolts == 1600 { 1 }
        else if millivolts == 1700 { 2 }
        else if millivolts == 1800 { 3 }
        else if millivolts == 2200 { 4 }
        else if millivolts == 2400 { 5 }
        else if millivolts == 2700 { 6 }
        else if millivolts == 3000 { 7 }
        else { return -1 };
    sx126x_command(host, SX126X_CMD_SET_DIO3_AS_TCXO_CTRL,
                   &[voltage, 0x00, 0x03, 0x20])
}

#[inline(always)] unsafe fn sx126x_fsk_setup(host: &LoraHost, config: &LoraConfig) -> i32 {
    if config.chip != 2 { return sx127x_fsk_setup(host, config); }
    if sx126x_command(host, SX126X_CMD_SET_STANDBY, &[0]) != 0 { return -3; }
    if sx126x_command(host, SX126X_CMD_SET_REGULATOR_MODE, &[1]) != 0 { return -3; }
    // The TCXO must be running before calibration and packet-engine setup.
    // Leave the radio in its normal RC standby; the validated SX1262 FSK
    // sequence does not switch to XOSC standby between these commands.
    if sx126x_set_tcxo(host, config.sx1262_tcxo_mv) != 0 { return -1; }
    if config.sx1262_tcxo_mv > 0 {
        if let Some(wait) = host.wait_irq { let _ = wait(host.user, 5); }
    }
    if sx126x_command(host, SX126X_CMD_CALIBRATE, &[0x7f]) != 0 { return -3; }
    if sx126x_command(host, SX126X_CMD_CALIBRATE_IMAGE, &[0xe1, 0xe9]) != 0 { return -3; }
    if sx126x_command(host, SX126X_CMD_SET_RX_TX_FALLBACK_MODE, &[0x20]) != 0 { return -3; }
    if sx126x_command(host, SX126X_CMD_CLEAR_DEVICE_ERRORS, &[0, 0]) != 0 { return -3; }
    if config.sx1262_dio2_rf_switch != 0 &&
        sx126x_command(host, SX126X_CMD_SET_DIO2_AS_RF_SWITCH, &[1]) != 0 { return -3; }
    if sx126x_command(host, SX126X_CMD_SET_PACKET_TYPE, &[SX126X_PACKET_TYPE_GFSK]) != 0 { return -3; }
    let rf = ((config.frequency_hz as u64) << 25) / 32_000_000;
    if sx126x_command(host, SX126X_CMD_SET_RF_FREQUENCY,
                      &[(rf >> 24) as u8, (rf >> 16) as u8, (rf >> 8) as u8, rf as u8]) != 0 { return -3; }
    let pa_duty = config.sx1262_pa_duty.clamp(0, 7) as u8;
    let pa_hp = config.sx1262_pa_hp.clamp(0, 7) as u8;
    let pa_device = config.sx1262_pa_device.clamp(0, 1) as u8;
    let pa_lut = config.sx1262_pa_lut.clamp(0, 1) as u8;
    if sx126x_command(host, SX126X_CMD_SET_PA_CONFIG, &[pa_duty, pa_hp, pa_device, pa_lut]) != 0 { return -3; }
    if sx126x_command(host, SX126X_CMD_SET_TX_PARAMS,
                      &[((config.tx_power as i32).clamp(-9, 22) as i8) as u8, 4]) != 0 { return -3; }
    if sx126x_write_register(host, SX126X_REG_OCP, &[0x38]) != 0 { return -3; }
    if sx126x_write_register(host, SX126X_REG_RX_GAIN, &[0x96]) != 0 { return -3; }
    let mut sensitivity = [0u8; 1];
    if sx126x_read(host, SX126X_CMD_READ_REGISTER,
                   &[(SX126X_REG_RX_SENSITIVITY >> 8) as u8, SX126X_REG_RX_SENSITIVITY as u8],
                   &mut sensitivity) != 0 { return -3; }
    if sx126x_write_register(host, SX126X_REG_RX_SENSITIVITY, &[sensitivity[0] | 1]) != 0 { return -3; }
    if sx126x_command(host, SX126X_CMD_SET_BUFFER_BASE_ADDRESS, &[0, 0x80]) != 0 { return -3; }
    // Common 100 kbit/s FSK/GFSK profile, 5 kHz deviation, and a wide enough
    // receive filter for both SX127x and SX1262. SX126x encodes bitrate as
    // (32 * 32 MHz) / bitrate, so 100 kbit/s is 0x002800.
    if sx126x_command(host, SX126X_CMD_SET_MODULATION_PARAMS,
                      // No Gaussian shaping for the first interop profile;
                      // this is the same SX127x FSK setting and avoids a
                      // modem-side waveform mismatch while TX is validated.
                      &[0x00, 0x28, 0x00, 0x00, 0x0a, 0x00, 0x14, 0x7b]) != 0 { return -3; }
    // Match the SX127x FSK profile's two-byte sync word and standard
    // two-byte CCITT CRC. SX127x uses polynomial 0x1021, init 0x1d0f, with the
    // complemented output. Program these explicitly because SX1262 leaves
    // the GFSK CRC registers configurable across radio resets.
    if sx126x_write_register(host, 0x06c0, &[0xd3, 0xa5]) != 0 { return -3; }
    if sx126x_write_register(host, 0x06bc, &[0x1d, 0x0f]) != 0 { return -3; }
    if sx126x_write_register(host, 0x06be, &[0x10, 0x21]) != 0 { return -3; }
    // SX1262 encodes GFSK preamble length in bits. Match the SX127x 16-byte
    // preamble and leave the detector ungated for cross-chip interoperability.
    if sx126x_command(host, SX126X_CMD_SET_PACKET_PARAMS,
                      &[0, 128, 0x00, 16, 0, 1, 0xff, 6, 0]) != 0 { return -3; }
    let irq = SX126X_IRQ_TX_DONE | SX126X_IRQ_RX_DONE | SX126X_IRQ_CRC_ERR | SX126X_IRQ_TIMEOUT;
    sx126x_command(host, SX126X_CMD_SET_DIO_IRQ_PARAMS,
                   &[(irq >> 8) as u8, irq as u8, (irq >> 8) as u8, irq as u8, 0, 0, 0, 0])
}

#[inline(always)] unsafe fn sx126x_fsk_start_rx(host: &LoraHost, config: &LoraConfig) -> i32 {
    if sx126x_fsk_setup(host, config) != 0 { return -3; }
    // CRC_ERR is inspected from GET_IRQ_STATUS, but must not be a GPIO wake
    // source: at this low FSK rate a noisy CRC latch can hold DIO1 high and
    // starve the module command/control path. RX_DONE and timeout remain the
    // actual wake sources.
    let irq = SX126X_IRQ_RX_DONE | SX126X_IRQ_TIMEOUT;
    if sx126x_command(host, SX126X_CMD_SET_DIO_IRQ_PARAMS,
                      &[(irq >> 8) as u8, irq as u8, (irq >> 8) as u8, irq as u8, 0, 0, 0, 0]) != 0 { return -3; }
    if sx126x_command(host, SX126X_CMD_CLEAR_IRQ_STATUS, &[0xff, 0xff]) != 0 { return -3; }
    // Capture the cleared state before entering RX.  A nonzero value here
    // means the command did not reach the SX1262 (or the IRQ is being
    // regenerated by the packet engine), which must not be confused with a
    // packet received after SetRx.
    let mut cleared_irq = [0u8; 2];
    if sx126x_read(host, SX126X_CMD_GET_IRQ_STATUS, &[], &mut cleared_irq) == 0 {
        let value = u16::from_be_bytes(cleared_irq);
        if value != 0 { return -2000 - value as i32; }
    }
    if sx126x_command(host, SX126X_CMD_SET_RX, &[0xff, 0xff, 0xff]) != 0 { return -3; }
    if let Some(configure) = host.irq_configure { let _ = configure(host.user, config.irq_pin as i32, 1); }
    if let Some(enable) = host.irq_enable { let _ = enable(host.user, config.irq_pin as i32, 1); }
    0
}

/* After RX_DONE the SX1262 enters its configured fallback mode. Re-running
 * the complete setup sequence is unnecessarily fragile while the TCXO state
 * is transitioning. Packet parameters and DIO IRQ routing are unchanged, so
 * a persistent receiver only needs XOSC standby, IRQ clearing, and SetRx. */
#[inline(always)] unsafe fn sx126x_fsk_rearm_rx(host: &LoraHost) -> i32 {
    if sx126x_command(host, SX126X_CMD_SET_STANDBY, &[1]) != 0 { return -3; }
    // Restore the interoperable variable-length receive profile after TX.
    if sx126x_command(host, SX126X_CMD_SET_PACKET_PARAMS,
                      &[0, 128, 0x00, 16, 0, 1, 0xff, 6, 0]) != 0 { return -3; }
    if sx126x_command(host, SX126X_CMD_CLEAR_IRQ_STATUS, &[0xff, 0xff]) != 0 { return -3; }
    if sx126x_command(host, SX126X_CMD_SET_RX, &[0xff, 0xff, 0xff]) != 0 { return -3; }
    0
}

#[inline(always)] unsafe fn sx126x_fsk_send(host: &LoraHost, config: &LoraConfig, packet: &[u8]) -> i32 {
    if packet.is_empty() || packet.len() > MAX_PACKET { return -1; }
    if let Some(disable) = host.irq_enable {
        // The persistent RX task has DIO1 enabled. Mask it while reset and
        // TX are in progress so a reset edge cannot race the SPI command
        // sequence; the caller re-arms it when RX is restored.
        let _ = disable(host.user, config.irq_pin as i32, 0);
    }
    // The persistent task already configured the complete GFSK profile. Match
    // the old Main sender and only transition from RX to standby before
    // changing packet parameters and loading the FIFO.
    if sx126x_command(host, SX126X_CMD_SET_STANDBY, &[0]) != 0 { return -3; }
    let mut packet_type = [0u8; 1];
    if sx126x_read(host, SX126X_CMD_GET_PACKET_TYPE, &[], &mut packet_type) != 0 { return -4; }
    if packet_type[0] != SX126X_PACKET_TYPE_GFSK { return -400 - packet_type[0] as i32; }
    // SX1262 variable-length TX: the first FIFO byte is the payload length.
    if sx126x_command(host, SX126X_CMD_SET_PACKET_PARAMS,
                      &[0, 128, 0x00, 16, 0, 1, packet.len() as u8, 6, 0]) != 0 { return -3; }
    let mut tx = [0u8; MAX_PACKET + 2];
    let mut rx = [0u8; MAX_PACKET + 2];
    tx[0] = SX126X_CMD_WRITE_BUFFER;
    tx[1] = 0;
    tx[2] = packet.len() as u8;
    tx[3..packet.len() + 3].copy_from_slice(packet);
    let Some(spi) = host.spi_transfer else { return -2 };
    if spi(host.user, tx.as_ptr(), rx.as_mut_ptr(), packet.len() + 3) != 0 { return -3; }
    let tx_irq = SX126X_IRQ_TX_DONE | SX126X_IRQ_TIMEOUT;
    if sx126x_command(host, SX126X_CMD_SET_DIO_IRQ_PARAMS,
                      &[(tx_irq >> 8) as u8, tx_irq as u8,
                        (tx_irq >> 8) as u8, tx_irq as u8, 0, 0, 0, 0]) != 0 { return -3; }
    // Polling is authoritative; the old Main path did not re-route DIO1 for
    // a one-shot transmit.
    if sx126x_command(host, SX126X_CMD_CLEAR_IRQ_STATUS, &[0xff, 0xff]) != 0 { return -3; }
    // SetTx performs the synthesizer transition itself. Use the maximum
    // bounded timeout: SX126x units are 15.625 us and a maximum-size 100 kbit/s
    // frame can exceed a few milliseconds.
    if sx126x_command(host, SX126X_CMD_SET_TX, &[0xff, 0xff, 0xff]) != 0 { return -3; }
    let mut tx_status = [0u8; 1];
    let _ = sx126x_read(host, SX126X_GET_STATUS, &[], &mut tx_status);
    let mut device_errors = [0u8; 2];
    let _ = sx126x_read(host, SX126X_CMD_GET_DEVICE_ERRORS, &[], &mut device_errors);
    let mut packet_status = [0u8; 3];
    let _ = sx126x_read(host, SX126X_CMD_GET_PACKET_STATUS, &[], &mut packet_status);
    let mut last_irq = 0u16;
    for _ in 0..100 {
        let mut bytes = [0u8; 2];
        if sx126x_read(host, SX126X_CMD_GET_IRQ_STATUS, &[], &mut bytes) != 0 {
            let _ = sx126x_command(host, SX126X_CMD_SET_STANDBY, &[0]);
            return -5;
        }
        let irq = u16::from_be_bytes(bytes);
        last_irq = irq;
        if irq & SX126X_IRQ_TX_DONE != 0 {
            let _ = sx126x_command(host, SX126X_CMD_CLEAR_IRQ_STATUS, &[0xff, 0xff]);
            return 0;
        }
        if irq & SX126X_IRQ_TIMEOUT != 0 {
            let _ = sx126x_command(host, SX126X_CMD_CLEAR_IRQ_STATUS, &[0xff, 0xff]);
            let _ = sx126x_command(host, SX126X_CMD_SET_STANDBY, &[0]);
            return -1000 - irq as i32;
        }
        if let Some(wait) = host.wait_irq { let _ = wait(host.user, 5); }
    }
    // Keep the command status in the diagnostic result (the normal event
    // still reports tx_error=-1000 when no IRQ was observed).  This lets the
    // loader-only status surface distinguish STDBY, TX, and command-error
    // states without requiring a Main rebuild.
    // Fold the low device-error bits into the diagnostic return.  The
    // high-range event ID emitted by the task exposes these without a Main
    // ABI change (XOSC/PLL/PA errors are the important bits here).
    let _ = sx126x_command(host, SX126X_CMD_CLEAR_IRQ_STATUS, &[0xff, 0xff]);
    let _ = sx126x_command(host, SX126X_CMD_SET_STANDBY, &[0]);
    // Preserve the complete radio state in the one-shot result: status byte,
    // device-error word, packet-status bytes, and the last IRQ value. This is
    // only a diagnostic return; normal successful TX still returns zero.
    let diagnostic = ((tx_status[0] as u32) << 24)
        | ((u16::from_be_bytes(device_errors) as u32) << 8)
        | ((packet_status[0] as u32) << 4)
        | (last_irq as u32 & 0x0f);
    -1000 - diagnostic as i32
}

#[inline(always)] unsafe fn sx126x_fsk_emit_packet(host: &LoraHost) -> i32 {
    let mut irq_bytes = [0u8; 2];
    if sx126x_read(host, SX126X_CMD_GET_IRQ_STATUS, &[], &mut irq_bytes) != 0 { return -3; }
    let irq = u16::from_be_bytes(irq_bytes);
    if irq & SX126X_IRQ_RX_DONE == 0 { return 1; }
    let _ = sx126x_command(host, SX126X_CMD_CLEAR_IRQ_STATUS, &[0xff, 0xff]);
    let mut packet_status = [0u8; 3];
    let _ = sx126x_read(host, SX126X_CMD_GET_PACKET_STATUS, &[], &mut packet_status);
    if irq & SX126X_IRQ_CRC_ERR != 0 {
        // GFSK packet-status byte 0 distinguishes preamble, sync, address,
        // CRC, length, and abort failures. Preserve it for the task's
        // diagnostic event instead of collapsing every failure to `2`.
        return 0x1000 | packet_status[0] as i32;
    }
    let mut status = [0u8; 2];
    if sx126x_read(host, SX126X_CMD_GET_RX_BUFFER_STATUS, &[], &mut status) != 0 { return -3; }
    let len = status[0] as usize;
    if len == 0 || len > MAX_PACKET { return -6; }
    let mut packet = [0u8; MAX_PACKET];
    if sx126x_read(host, SX126X_CMD_READ_BUFFER, &[status[1]], &mut packet[..len]) != 0 { return -3; }
    // SX126x GFSK packet status reports RSSI in half-dB units.  There is no
    // FSK SNR value, so keep SNR at zero while carrying the real RSSI.
    let rssi = -((packet_status[2] as i32) / 2);
    if let Some(emit) = host.emit_packet {
        emit(host.user, packet.as_ptr(), len, rssi.clamp(i16::MIN as i32, i16::MAX as i32) as i16, 0)
    } else { 0 }
}

#[inline(always)] unsafe fn wait_for_irq(host: &LoraHost, irq_pin: i8, timeout_ms: u32) {
    if let Some(wait) = host.wait_irq { let _ = wait(host.user, timeout_ms); }
    /* The host ISR masks the GPIO edge before notifying the task. Re-enable
     * it after the radio status/FIFO has been sampled, including timeout
     * iterations, so a subsequent packet can wake the task. */
    if let Some(enable) = host.irq_enable { let _ = enable(host.user, irq_pin as i32, 1); }
}

#[inline(always)] unsafe fn run_sx127x_fsk_rx(ctx: &ModuleContext, host: &LoraHost, config: &LoraConfig) -> i32 {
    let start = sx127x_fsk_start_rx(host, config);
    if start != 0 {
        event_i32(ctx, 6, start);
        log(ctx, b"mod_lora sx127x fsk rx setup failed");
        return start;
    }
    log(ctx, b"mod_lora sx127x fsk rx started v2");
    event(ctx, 1, &[]);
    let mode = sx127x_read(host, SX127X_REG_OP_MODE).unwrap_or(0xff) as u16;
    event_i32(ctx, 0x5000 | mode, mode as i32);
    let mut args_buf = [0u8; 64];
    let mut payload_buf = [0u8; MAX_PACKET];
    loop {
        if let Some(poll) = host.poll_command {
            let mut args_len = args_buf.len();
            let mut payload_len = payload_buf.len();
            if poll(host.user, args_buf.as_mut_ptr(), &mut args_len,
                    payload_buf.as_mut_ptr(), &mut payload_len) == 0 {
                let command = core::str::from_utf8(&args_buf[..args_len])
                    .unwrap_or("").trim_matches(|byte| byte == '\0' || byte == ' ');
                if command_stop(command) {
                    if let Some(disable) = host.irq_enable { let _ = disable(host.user, config.irq_pin as i32, 0); }
                    if let Some(configure) = host.irq_configure { let _ = configure(host.user, config.irq_pin as i32, 0); }
                    power_down_radio(host, config);
                    event(ctx, 2, &[]);
                    return 0;
                }
                // Main's `radio` service uses `fsk` as the service selector;
                // when a persistent FSK task is already running, the same
                // queued request is its TX operation. Accept both spellings
                // so the service selector cannot silently drop a packet.
                if (command_tx(command) || command_fsk(command)) && payload_len > 0 {
                    event_i32(ctx, 20, payload_len as i32);
                    let rc = sx127x_fsk_send(host, &payload_buf[..payload_len]);
                    if rc != 0 { event_sx127x_fsk_error(ctx, host, rc); }
                    else { event_bytes(ctx, 3, &payload_buf[..payload_len]); }
                    let _ = sx127x_fsk_start_rx(host, config);
                } else if command_is(command, &[114,101,99,111,110,102,105,103,117,114,101]) {
                    let _ = sx127x_fsk_start_rx(host, config);
                }
            }
        }
        let irq_active = host.gpio_read.map(|read| read(host.user, config.irq_pin as i32) != 0).unwrap_or(true);
        if irq_active {
            let rc = sx127x_fsk_emit_packet(host);
            if rc == 0 { event(ctx, 22, &[]); }
            else if rc < 0 { event_i32(ctx, 23, rc); }
        }
        wait_for_irq(host, config.irq_pin, 25);
    }
}

#[inline(always)] unsafe fn run_sx126x_fsk_rx(ctx: &ModuleContext, host: &LoraHost, config: &LoraConfig) -> i32 {
    if sx126x_fsk_start_rx(host, config) != 0 { return -3; }
    log(ctx, b"mod_lora sx126x fsk rx started");
    event(ctx, 1, &[]);
    let mut initial_status = [0u8; 1];
    if sx126x_read(host, SX126X_GET_STATUS, &[], &mut initial_status) == 0 {
        // 0x51xx records the modem state immediately after SetRx; 0x82 is
        // the expected RX state and makes silent fallback observable.
        event_i32(ctx, 0x5100 | initial_status[0] as u16, initial_status[0] as i32);
    }
    let mut args_buf = [0u8; 64];
    let mut payload_buf = [0u8; MAX_PACKET];
    let mut last_irq_diag = 0xffffu16;
    loop {
        if let Some(poll) = host.poll_command {
            let mut args_len = args_buf.len();
            let mut payload_len = payload_buf.len();
            if poll(host.user, args_buf.as_mut_ptr(), &mut args_len,
                    payload_buf.as_mut_ptr(), &mut payload_len) == 0 {
                let command = core::str::from_utf8(&args_buf[..args_len])
                    .unwrap_or("").trim_matches(|byte| byte == '\0' || byte == ' ');
                if command_stop(command) {
                    if let Some(disable) = host.irq_enable { let _ = disable(host.user, config.irq_pin as i32, 0); }
                    if let Some(configure) = host.irq_configure { let _ = configure(host.user, config.irq_pin as i32, 0); }
                    power_down_radio(host, config);
                    event(ctx, 2, &[]);
                    return 0;
                }
                // See the SX127x loop above: `fsk` is also the queued-radio
                // selector used by Main for a persistent task.
                if (command_tx(command) || command_fsk(command)) && payload_len > 0 {
                    event_i32(ctx, 20, payload_len as i32);
                    let rc = sx126x_fsk_send(host, config, &payload_buf[..payload_len]);
                    if rc != 0 {
                        // Preserve the legacy tx_error event, while using a
                        // diagnostic high-range event ID during the SX1262
                        // bring-up so module status exposes the exact return
                        // code even though Main caches only the event ID.
                        event_i32(ctx, 6, rc);
                        event_i32(ctx, 0x6000 | ((-rc as u16) & 0x0fff), rc);
                    }
                    else { event_bytes(ctx, 3, &payload_buf[..payload_len]); }
                    let _ = sx126x_fsk_rearm_rx(host);
                } else if command_is(command, &[114,101,99,111,110,102,105,103,117,114,101]) {
                    let _ = sx126x_fsk_rearm_rx(host);
                }
            }
        }
        // Poll the modem status even when DIO1 is low. This is deliberately
        // conservative during bring-up: an incorrect persisted DIO pin or a
        // missed edge must not hide an RX_DONE/CRC diagnostic. Once the board
        // pin is proven, the GPIO wake gate can be restored for sleep power.
        {
            // Keep one structured diagnostic per IRQ value.  This makes the
            // SX1262 receive state visible through Main's bounded module
            // status surface without turning a stuck DIO line into an event
            // storm.  0x50xx is reserved for raw SX1262 IRQ snapshots.
            let mut irq_bytes = [0u8; 2];
            if sx126x_read(host, SX126X_CMD_GET_IRQ_STATUS, &[], &mut irq_bytes) == 0 {
                let irq = u16::from_be_bytes(irq_bytes);
                if irq != 0 && irq != last_irq_diag {
                    event_i32(ctx, 0x5000 | (irq & 0x0fff), irq as i32);
                    last_irq_diag = irq;
                }
            }
            let rc = sx126x_fsk_emit_packet(host);
            // Keep the event contract identical to SX127x: event 22 is a
            // decoded FSK packet, event 23 carries a negative receive error.
            // Without this marker a successful SX1262 receive was invisible
            // in module status even when the host packet callback ran.
            if rc == 0 {
                event(ctx, 22, &[]);
                // SetRx uses the configured fallback mode (STDBY_RC after a
                // packet). Re-arm the complete FSK RX path after each valid
                // frame so a persistent receiver can accept the next one.
                let _ = sx126x_fsk_rearm_rx(host);
            }
            else if rc >= 0x1000 {
                // 0x1000..0x10ff carries SX1262 GFSK packet-status byte 0.
                event_i32(ctx, 0x5200 | ((rc as u16) & 0xff), rc);
                let _ = sx126x_fsk_rearm_rx(host);
            }
            else if rc < 0 { event_i32(ctx, 23, rc); }
        }
        wait_for_irq(host, config.irq_pin, 25);
    }
}

#[inline(always)] unsafe fn run_sx127x_rx(ctx: &ModuleContext, host: &LoraHost, config: &LoraConfig) -> i32 {
    let rc = sx127x_configure_rx(host, config);
    if rc != 0 { return rc; }
    if let Some(configure) = host.irq_configure { let _ = configure(host.user, config.irq_pin as i32, 1); }
    if let Some(enable) = host.irq_enable { let _ = enable(host.user, config.irq_pin as i32, 1); }
    log(ctx, b"mod_lora sx127x rx started");
    event(ctx, 1, &[]);
    let mut args_buf = [0u8; 64];
    let mut payload_buf = [0u8; MAX_PACKET];
    let mut rx_packets = 0u32;
    let mut tx_packets = 0u32;
    loop {
        if let Some(poll) = host.poll_command {
            let mut args_len = args_buf.len();
            let mut payload_len = payload_buf.len();
            if poll(host.user, args_buf.as_mut_ptr(), &mut args_len,
                    payload_buf.as_mut_ptr(), &mut payload_len) == 0 {
                let command = core::str::from_utf8(&args_buf[..args_len])
                    .unwrap_or("").trim_matches(|byte| byte == '\0' || byte == ' ');
                if command_stop(command) {
                    if let Some(disable) = host.irq_enable { let _ = disable(host.user, config.irq_pin as i32, 0); }
                    if let Some(configure) = host.irq_configure { let _ = configure(host.user, config.irq_pin as i32, 0); }
                    power_down_radio(host, config);
                    log(ctx, b"mod_lora sx127x rx stopped"); event(ctx, 2, &[]); return 0;
                }
                if command_tx(command) {
                    let tx_rc = sx127x_send(host, &payload_buf[..payload_len]);
                    let _ = sx127x_configure_rx(host, config);
                    if tx_rc != 0 {
                        log(ctx, b"mod_lora sx127x tx failed");
                        event_i32(ctx, 6, tx_rc);
                    } else {
                        tx_packets = tx_packets.saturating_add(1);
                        event_bytes(ctx, 3, &payload_buf[..payload_len]);
                    }
                } else if command_is(command, &[114,101,99,111,110,102,105,103,117,114,101]) {
                    let rc = sx127x_configure_rx(host, config);
                    if rc != 0 { log(ctx, b"mod_lora sx127x reconfigure failed"); } else { event(ctx, 4, &[]); }
                } else if command_probe(command) {
                    let rc = probe_sx127x(host);
                    if rc != 0 { log(ctx, b"mod_lora sx127x probe failed"); }
                } else if command_fsk(command) {
                    if payload_len > 0 {
                        event_i32(ctx, 21, payload_len as i32);
                        let rc = sx127x_fsk_send(host, &payload_buf[..payload_len]);
                        if rc != 0 { event_i32(ctx, 6, rc); } else { event_bytes(ctx, 3, &payload_buf[..payload_len]); }
                        let _ = sx127x_configure_rx(host, config);
                    } else {
                        return run_sx127x_fsk_rx(ctx, host, config);
                    }
                } else if command_is(command, &[115,116,97,116,115]) {
                    let stats = [
                        rx_packets.to_le_bytes()[0], rx_packets.to_le_bytes()[1],
                        rx_packets.to_le_bytes()[2], rx_packets.to_le_bytes()[3],
                        tx_packets.to_le_bytes()[0], tx_packets.to_le_bytes()[1],
                        tx_packets.to_le_bytes()[2], tx_packets.to_le_bytes()[3],
                    ];
                    event(ctx, 5, &stats);
                }
            }
        }
        if config.cad_rx != 0 {
            let _ = sx127x_cad_window(host, config);
            continue;
        }
        /* Do not issue a SPI status transaction on every poll when the DIO
         * line is idle.  Apart from wasting bus time, a radio held BUSY can
         * otherwise delay command polling (including stop/tx) indefinitely. */
        let irq_active = host.gpio_read.map(|read| read(host.user, config.irq_pin as i32) != 0).unwrap_or(true);
        if irq_active && sx127x_emit_packet(host) == 0 { rx_packets = rx_packets.saturating_add(1); }
        wait_for_irq(host, config.irq_pin, 25);
    }
}

#[inline(always)] unsafe fn run_sx126x_rx(ctx: &ModuleContext, host: &LoraHost, config: &LoraConfig) -> i32 {
    let rc = sx126x_configure_rx(host, config);
    if rc != 0 { return rc; }
    if let Some(configure) = host.irq_configure { let _ = configure(host.user, config.irq_pin as i32, 1); }
    if let Some(enable) = host.irq_enable { let _ = enable(host.user, config.irq_pin as i32, 1); }
    log(ctx, b"mod_lora sx126x rx started");
    event(ctx, 1, &[]);
    let mut args_buf = [0u8; 64];
    let mut payload_buf = [0u8; MAX_PACKET];
    let mut rx_packets = 0u32;
    let tx_packets = 0u32;
    let mut cad_windows = 0u32;
    loop {
        if let Some(poll) = host.poll_command {
            let mut args_len = args_buf.len();
            let mut payload_len = payload_buf.len();
            if poll(host.user, args_buf.as_mut_ptr(), &mut args_len,
                    payload_buf.as_mut_ptr(), &mut payload_len) == 0 {
                let command = core::str::from_utf8(&args_buf[..args_len])
                    .unwrap_or("").trim_matches(|byte| byte == '\0' || byte == ' ');
                if command_stop(command) {
                    if let Some(disable) = host.irq_enable { let _ = disable(host.user, config.irq_pin as i32, 0); }
                    if let Some(configure) = host.irq_configure { let _ = configure(host.user, config.irq_pin as i32, 0); }
                    power_down_radio(host, config);
                    log(ctx, b"mod_lora sx126x rx stopped"); event(ctx, 2, &[]); return 0;
                }
                if command_tx(command) {
                    /* A persistent RX task may have observed an IRQ edge or
                     * a modem timeout since its last configuration.  Put the
                     * SX126x back through the complete session setup before
                     * switching it to TX; this also reapplies the calibrated
                     * PA/RF path rather than relying on RX state surviving a
                     * queued command. */
                    if let Some(disable) = host.irq_enable {
                        let _ = disable(host.user, config.irq_pin as i32, 0);
                    }
                    sx126x_hard_reset(host, config);
                    let setup_rc = sx126x_configure_rx(host, config);
                    if setup_rc != 0 {
                        log(ctx, b"mod_lora sx126x tx setup failed");
                        event_i32(ctx, 6, setup_rc);
                        if let Some(enable) = host.irq_enable {
                            let _ = enable(host.user, config.irq_pin as i32, 1);
                        }
                        continue;
                    }
                    let tx_rc = sx126x_send(host, config, &payload_buf[..payload_len]);
                    if tx_rc != 0 {
                        log(ctx, b"mod_lora sx126x tx failed");
                        event_i32(ctx, 6, tx_rc);
                        return tx_rc;
                    } else {
                        event_bytes(ctx, 3, &payload_buf[..payload_len]);
                        return 0;
                    }
                } else if command_is(command, &[114,101,99,111,110,102,105,103,117,114,101]) {
                    let rc = sx126x_configure_rx(host, config);
                    if rc != 0 { log(ctx, b"mod_lora sx126x reconfigure failed"); } else { event(ctx, 4, &[]); }
                } else if command_fsk(command) {
                    if payload_len > 0 {
                        let rc = sx126x_fsk_send(host, config, &payload_buf[..payload_len]);
                        if rc != 0 { event_i32(ctx, 6, rc); } else { event_bytes(ctx, 3, &payload_buf[..payload_len]); }
                        let _ = sx126x_configure_rx(host, config);
                    } else {
                        return run_sx126x_fsk_rx(ctx, host, config);
                    }
                } else if command_is(command, &[115,116,97,116,115]) {
                    let stats = [
                        rx_packets.to_le_bytes()[0], rx_packets.to_le_bytes()[1],
                        rx_packets.to_le_bytes()[2], rx_packets.to_le_bytes()[3],
                        tx_packets.to_le_bytes()[0], tx_packets.to_le_bytes()[1],
                        tx_packets.to_le_bytes()[2], tx_packets.to_le_bytes()[3],
                    ];
                    event(ctx, 5, &stats);
                }
            }
        }
        if config.cad_rx != 0 {
            let cad_result = sx126x_cad_window(host, config);
            cad_windows = cad_windows.saturating_add(1);
            if cad_result != 1 || cad_windows % 20 == 0 {
                /* 7=CAD completed quietly, 8=CAD detected but RX failed,
                 * 9=host/radio error, 10=packet delivered, 11=no CAD_DONE.
                 * Keep the result
                 * in the payload too; the event id is visible in Main logs. */
                let event_id = if cad_result == 1 { 7u16 }
                    else if cad_result == 2 { 8u16 }
                    else if cad_result == 0 { 10u16 }
                    else if cad_result == 11 { 11u16 }
                    else if cad_result >= 0x100 { 32 + (cad_result & 0xff) as u16 }
                    else { 9u16 };
                event_i32(ctx, event_id, cad_result);
            }
            continue;
        }
        let irq_active = host.gpio_read.map(|read| read(host.user, config.irq_pin as i32) != 0).unwrap_or(true);
        if irq_active && sx126x_emit_packet(host) == 0 { rx_packets = rx_packets.saturating_add(1); }
        wait_for_irq(host, config.irq_pin, 25);
    }
}

#[inline(always)]
/// Development entry point. `probe127`, `probe126`, and `fsk` exercise the
/// same host SPI path that the full RX/TX state machine will use.
pub unsafe fn entry(context: *const ModuleContext, payload: *const u8, payload_len: usize,
                    args: *const u8, args_len: usize) -> i32 {
    if context.is_null() { return -1; }
    let ctx = &*context;
    if ctx.abi_version != ABI_VERSION || ctx.size < core::mem::size_of::<ModuleContext>() as u32 || ctx.lora_host.is_null() || ctx.lora_config.is_null() { return ERR_CONTEXT_ABI; }
    let host = &*ctx.lora_host;
    let config = &*ctx.lora_config;
    if host.abi_version != LORA_ABI_VERSION || host.size < core::mem::size_of::<LoraHost>() as u32 { return ERR_HOST_ABI; }
    let command = if !args.is_null() && args_len > 0 { core::str::from_utf8(core::slice::from_raw_parts(args, args_len)).unwrap_or("probe") } else { "probe" };
    event_i32(ctx, 30, command.len() as i32);
    if command_probe(command) {
        event_i32(ctx, 31, config.chip as i32);
        return if config.chip == 2 {
            let rc = probe_sx126x(host); log(ctx, b"mod_lora sx126x probe"); rc
        } else {
            let rc = probe_sx127x(host); log(ctx, b"mod_lora sx127x probe"); rc
        };
    }
    if command_probe127(command) { let rc = probe_sx127x(host); log(ctx, b"mod_lora sx127x probe"); return rc; }
    if command_probe126(command) { let rc = probe_sx126x(host); log(ctx, b"mod_lora sx126x probe"); return rc; }
    if command_rx(command) {
        return if config.chip == 2 {
            run_sx126x_rx(ctx, host, config)
        } else {
            run_sx127x_rx(ctx, host, config)
        };
    }
    if command_tx(command) {
        if payload.is_null() || payload_len == 0 || payload_len > MAX_PACKET { return -1; }
        let packet = core::slice::from_raw_parts(payload, payload_len);
        /* A short-lived TX invocation may follow `stop`, so it cannot assume
         * that the persistent RX task already configured the radio. Reapply
         * the complete persisted configuration before touching the FIFO. */
        let setup_rc = if config.chip == 2 {
            sx126x_configure_rx(host, config)
        } else {
            sx127x_configure_rx(host, config)
        };
        if setup_rc != 0 { return setup_rc; }
        let rc = if config.chip == 2 { sx126x_send(host, config, packet) } else { sx127x_send(host, packet) };
        if rc == 0 { event_bytes(ctx, 3, packet); }
        return rc;
    }
    if command_stop(command) {
        power_down_radio(host, config);
        return 0;
    }
    if command_is(command, &[114, 101, 99, 111, 110, 102, 105, 103, 117, 114, 101]) {
        return if config.chip == 2 {
            sx126x_configure_rx(host, config)
        } else {
            sx127x_configure_rx(host, config)
        };
    }
    if command_fsk(command) {
        if !payload.is_null() && payload_len > 0 {
            let packet = core::slice::from_raw_parts(payload, payload_len);
            let rc = if config.chip == 2 {
                let setup = sx126x_fsk_setup(host, config);
                if setup == 0 { sx126x_fsk_send(host, config, packet) } else { setup }
            } else {
                let setup = sx127x_fsk_setup(host, config);
                if setup == 0 { sx127x_fsk_send(host, packet) } else { setup }
            };
            if rc == 0 { event_bytes(ctx, 3, packet); return 0; }
            event_i32(ctx, 6, rc);
            if config.chip == 1 {
                let op = sx127x_read(host, SX127X_REG_OP_MODE).unwrap_or(0xff) as i32;
                let irq1 = sx127x_read(host, SX127X_REG_IRQ_FLAGS1).unwrap_or(0xff) as i32;
                let irq = sx127x_read(host, SX127X_REG_IRQ_FLAGS2).unwrap_or(0xff) as i32;
                // Preserve the raw modem state in the bounded task result for
                // one-shot diagnostics: low byte is IRQ_FLAGS2, next byte is
                // RegOpMode. Persistent tasks expose the same data via the
                // diagnostic event ID.
                return -300_000 - ((irq1 << 16) | (op << 8) | irq);
            }
            return rc;
        }
        log(ctx, b"mod_lora FSK service selected");
        return if config.chip == 2 {
            run_sx126x_fsk_rx(ctx, host, config)
        } else {
            run_sx127x_fsk_rx(ctx, host, config)
        };
    }
    log(ctx, b"mod_lora ready");
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::vec::Vec;

    struct FakeSpi {
        transactions: Mutex<Vec<Vec<u8>>>,
    }

    struct TxSpi {
        transactions: Mutex<Vec<Vec<u8>>>,
    }

    unsafe extern "C" fn fake_spi(user: *mut c_void, tx: *const u8, _rx: *mut u8, len: usize) -> i32 {
        let fake = &*(user as *const FakeSpi);
        let bytes = core::slice::from_raw_parts(tx, len).to_vec();
        fake.transactions.lock().unwrap().push(bytes);
        0
    }

    unsafe extern "C" fn tx_spi(user: *mut c_void, tx: *const u8, rx: *mut u8, len: usize) -> i32 {
        let fake = &*(user as *const TxSpi);
        let bytes = core::slice::from_raw_parts(tx, len).to_vec();
        let opcode = bytes.first().copied().unwrap_or(0);
        fake.transactions.lock().unwrap().push(bytes);
        core::ptr::write_bytes(rx, 0, len);
        // SX127x IRQ_FLAGS reads report TX_DONE immediately.
        if len >= 2 && (opcode & 0x7f) == SX127X_REG_IRQ_FLAGS {
            *rx.add(1) = SX127X_IRQ_TX_DONE;
        }
        0
    }

    fn host(fake: &FakeSpi) -> LoraHost {
        LoraHost {
            abi_version: LORA_ABI_VERSION,
            size: core::mem::size_of::<LoraHost>() as u32,
            features: 0,
            user: fake as *const _ as *mut c_void,
            spi_transfer: Some(fake_spi),
            gpio_write: None,
            gpio_read: None,
            irq_configure: None,
            irq_enable: None,
            wait_irq: None,
            now_ms: None,
            log_line: None,
            emit_packet: None,
            poll_command: None,
        }
    }

    fn config(chip: u32) -> LoraConfig {
        LoraConfig {
            abi_version: LORA_ABI_VERSION,
            size: core::mem::size_of::<LoraConfig>() as u32,
            chip,
            frequency_hz: 913_125_000,
            bandwidth_hz: 250_000,
            spreading_factor: 10,
            spi_host: 3,
            sync_word: 0x2b,
            tx_power: 17,
            reset_pin: 14,
            cs_pin: 18,
            irq_pin: 26,
            busy_pin: -1,
            sck_pin: 5,
            miso_pin: 19,
            mosi_pin: 27,
            board_power_pin: -1,
            board_power_level: 1,
            sx1262_dio2_rf_switch: 0,
            sx1262_tcxo_mv: 0,
            sx1262_pa_duty: 4,
            sx1262_pa_hp: 7,
            sx1262_pa_device: 0,
            sx1262_pa_lut: 1,
            sx1262_sync_word: 0x24b4,
            sx1262_rx_timeout_ms: 0,
            coding_rate: 5,
            preamble: 16,
            crc: 1,
            cad_rx: 0,
            cad_interval_ms: 2000,
            cad_rx_ms: 1000,
        }
    }

    #[test]
    fn sx127x_configures_frequency_and_rx_registers() {
        let fake = FakeSpi { transactions: Mutex::new(Vec::new()) };
        let h = host(&fake);
        assert_eq!(unsafe { sx127x_configure_rx(&h, &config(1)) }, 0);
        let transactions = fake.transactions.lock().unwrap();
        assert!(transactions.iter().any(|tx| tx == &[SX127X_REG_OP_MODE | 0x80, SX127X_LONG_RANGE | SX127X_MODE_RX_CONTINUOUS]));
        assert!(transactions.iter().any(|tx| tx[0] == SX127X_REG_SYNC | 0x80 && tx[1] == 0x2b));
        assert!(transactions.iter().any(|tx| tx[0] == SX127X_REG_IRQ_FLAGS | 0x80 && tx[1] == 0xff));
    }

    #[test]
    fn sx127x_fsk_selects_fifo_packet_mode() {
        let fake = FakeSpi { transactions: Mutex::new(Vec::new()) };
        let h = host(&fake);
        assert_eq!(unsafe { sx127x_fsk_setup(&h, &config(1)) }, 0);
        let transactions = fake.transactions.lock().unwrap();
        assert!(transactions.iter().any(|tx| {
            tx == &[SX127X_REG_PACKET_CONFIG1 | 0x80, 0x90]
        }));
        assert!(transactions.iter().any(|tx| {
            tx == &[SX127X_REG_PACKET_CONFIG2 | 0x80, 0x40]
        }));
    }

    #[test]
    fn sx126x_configures_packet_type_frequency_and_irq() {
        let fake = FakeSpi { transactions: Mutex::new(Vec::new()) };
        let h = host(&fake);
        assert_eq!(unsafe { sx126x_configure_rx(&h, &config(2)) }, 0);
        let transactions = fake.transactions.lock().unwrap();
        assert!(transactions.iter().any(|tx| tx == &[SX126X_CMD_SET_PACKET_TYPE, SX126X_PACKET_TYPE_LORA]));
        assert!(transactions.iter().any(|tx| tx[0] == SX126X_CMD_SET_RF_FREQUENCY));
        assert!(transactions.iter().any(|tx| tx[0] == SX126X_CMD_SET_DIO_IRQ_PARAMS));
        assert!(transactions.iter().any(|tx| tx == &[SX126X_CMD_SET_RX, 0xff, 0xff, 0xff]));
    }

    #[test]
    fn sx126x_send_accepts_maximum_packet_buffer() {
        let fake = FakeSpi { transactions: Mutex::new(Vec::new()) };
        let h = host(&fake);
        let packet = [0x5au8; MAX_PACKET];
        // The fake never reports TX_DONE, so this exercises the complete
        // bounded write path and then reaches the normal timeout result.
        assert_eq!(unsafe { sx126x_send(&h, &config(2), &packet) }, -1000);
        let transactions = fake.transactions.lock().unwrap();
        assert!(transactions.iter().any(|tx| tx.len() == MAX_PACKET + 2));
    }

    #[test]
    fn standalone_tx_entry_completes_without_a_persistent_rx_task() {
        let fake = TxSpi { transactions: Mutex::new(Vec::new()) };
        let host = LoraHost {
            abi_version: LORA_ABI_VERSION,
            size: core::mem::size_of::<LoraHost>() as u32,
            features: 0,
            user: &fake as *const _ as *mut c_void,
            spi_transfer: Some(tx_spi),
            gpio_write: None,
            gpio_read: None,
            irq_configure: None,
            irq_enable: None,
            wait_irq: None,
            now_ms: None,
            log_line: None,
            emit_packet: None,
            poll_command: None,
        };
        let config = config(1);
        let context = ModuleContext {
            abi_version: ABI_VERSION,
            size: core::mem::size_of::<ModuleContext>() as u32,
            user: core::ptr::null_mut(),
            log_line: None,
            call_service: None,
            get_setting: None,
            set_setting: None,
            emit_event: None,
            lora_host: &host,
            lora_config: &config,
            host: core::ptr::null(),
        };
        let payload = [1u8, 2, 3];
        assert_eq!(unsafe {
            entry(
                &context,
                payload.as_ptr(),
                payload.len(),
                b"tx".as_ptr(),
                2,
            )
        }, 0);
    }

    #[test]
    fn entry_rejects_incompatible_context_and_host_without_calling_spi() {
        let fake = FakeSpi {
            transactions: Mutex::new(Vec::new()),
        };
        let mut host = host(&fake);
        let config = config(1);
        let mut context = ModuleContext {
            abi_version: ABI_VERSION,
            size: core::mem::size_of::<ModuleContext>() as u32,
            user: core::ptr::null_mut(),
            log_line: None,
            call_service: None,
            get_setting: None,
            set_setting: None,
            emit_event: None,
            lora_host: &host,
            lora_config: &config,
            host: core::ptr::null(),
        };
        context.abi_version = ABI_VERSION + 1;
        assert_eq!(unsafe { entry(&context, core::ptr::null(), 0, core::ptr::null(), 0) }, ERR_CONTEXT_ABI);

        context.abi_version = ABI_VERSION;
        host.abi_version = LORA_ABI_VERSION + 1;
        context.lora_host = &host;
        assert_eq!(unsafe { entry(&context, core::ptr::null(), 0, core::ptr::null(), 0) }, ERR_HOST_ABI);
        assert!(fake.transactions.lock().unwrap().is_empty());
    }
}
