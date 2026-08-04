#![no_std]

#[cfg(test)]
extern crate std;

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
    pub call_service: Option<unsafe extern "C" fn(*mut c_void, *const u8, usize, *const u8, usize, *const u8, usize) -> i32>,
    pub get_setting: Option<unsafe extern "C" fn(*mut c_void, *const u8, usize, *mut u8, usize, *mut usize) -> i32>,
    pub set_setting: Option<unsafe extern "C" fn(*mut c_void, *const u8, usize, *const u8, usize) -> i32>,
    pub emit_event: Option<unsafe extern "C" fn(*mut c_void, *const ModuleEvent) -> i32>,
    pub lora_host: *const LoraHost,
    pub lora_config: *const LoraConfig,
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
}

#[cfg(target_pointer_width = "32")]
const _: () = assert!(core::mem::size_of::<LoraHost>() == 56);
#[cfg(target_pointer_width = "32")]
const _: () = assert!(core::mem::size_of::<ModuleContext>() == 40);
const _: () = assert!(core::mem::size_of::<LoraConfig>() == 92);

const ABI_VERSION: u32 = 2;
const LORA_ABI_VERSION: u32 = 1;
const ERR_CONTEXT_ABI: i32 = -100;
const ERR_HOST_ABI: i32 = -101;
const SX127X_VERSION: u8 = 0x12;
const REG_VERSION: u8 = 0x42;
const SX126X_GET_STATUS: u8 = 0xC0;
const SX127X_REG_BITRATE_MSB: u8 = 0x02;
const SX127X_REG_BITRATE_LSB: u8 = 0x03;
const SX127X_REG_FDEV_MSB: u8 = 0x04;
const SX127X_REG_FDEV_LSB: u8 = 0x05;
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
const SX127X_IRQ_RX_DONE: u8 = 0x40;
const SX127X_IRQ_CRC_ERROR: u8 = 0x20;
const SX127X_IRQ_TX_DONE: u8 = 0x08;
const SX127X_FIFO_RX_BASE: u8 = 0;
const MAX_PACKET: usize = 255;
const SX126X_CMD_SET_STANDBY: u8 = 0x80;
const SX126X_CMD_SET_RX: u8 = 0x82;
const SX126X_CMD_SET_TX: u8 = 0x83;
const SX126X_CMD_SET_PACKET_TYPE: u8 = 0x8a;
const SX126X_CMD_SET_RF_FREQUENCY: u8 = 0x86;
const SX126X_CMD_SET_PA_CONFIG: u8 = 0x95;
const SX126X_CMD_SET_TX_PARAMS: u8 = 0x8e;
const SX126X_CMD_SET_BUFFER_BASE_ADDRESS: u8 = 0x8f;
const SX126X_CMD_SET_MODULATION_PARAMS: u8 = 0x8b;
const SX126X_CMD_SET_PACKET_PARAMS: u8 = 0x8c;
const SX126X_CMD_SET_DIO_IRQ_PARAMS: u8 = 0x08;
const SX126X_CMD_GET_IRQ_STATUS: u8 = 0x12;
const SX126X_CMD_CLEAR_IRQ_STATUS: u8 = 0x02;
const SX126X_CMD_GET_RX_BUFFER_STATUS: u8 = 0x13;
const SX126X_CMD_GET_PACKET_STATUS: u8 = 0x14;
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
const SX126X_IRQ_CRC_ERR: u16 = 0x0040;
const SX126X_REG_SYNC_WORD: u16 = 0x0740;
const SX126X_REG_OCP: u16 = 0x08e7;
const SX126X_REG_RX_GAIN: u16 = 0x08ac;
const SX126X_REG_RX_SENSITIVITY: u16 = 0x08b5;
const SX126X_REG_TX_CLAMP_CONFIG: u16 = 0x08d8;

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

#[inline(always)] unsafe fn sx127x_fsk_setup(host: &LoraHost) -> i32 {
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
    sx127x_write(host, SX127X_REG_OP_MODE, SX127X_LONG_RANGE | SX127X_MODE_RX_CONTINUOUS)
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
        if let Some(wait) = host.wait_irq { let _ = wait(host.user, 5); }
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
    if rc == 0 { out.copy_from_slice(&rx[args.len() + 2..total]); }
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
    let irq = SX126X_IRQ_TX_DONE | SX126X_IRQ_RX_DONE | SX126X_IRQ_CRC_ERR | 0x0200;
    if sx126x_command(host, SX126X_CMD_SET_DIO_IRQ_PARAMS, &[(irq >> 8) as u8, irq as u8, (irq >> 8) as u8, irq as u8, 0, 0, 0, 0]) != 0 { return -3; }
    if sx126x_command(host, SX126X_CMD_CLEAR_IRQ_STATUS, &[0xff, 0xff]) != 0 { return -3; }
    sx126x_command(host, SX126X_CMD_SET_RX, &[0xff, 0xff, 0xff])
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
                return -1000 - irq as i32;
            }
        }
        if let Some(wait) = host.wait_irq { let _ = wait(host.user, 5); }
    }
    /* Preserve the last modem IRQ bits in the diagnostic result. Main still
     * treats every negative value as a failed TX, while status makes it
     * possible to distinguish a radio timeout from a never-started TX. */
    -1000 - last_irq as i32
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
    if config.chip != 2 { return sx127x_fsk_setup(host); }
    if sx126x_command(host, SX126X_CMD_SET_STANDBY, &[0]) != 0 { return -3; }
    if sx126x_command(host, SX126X_CMD_SET_REGULATOR_MODE, &[1]) != 0 { return -3; }
    if sx126x_command(host, SX126X_CMD_SET_PACKET_TYPE, &[SX126X_PACKET_TYPE_GFSK]) != 0 { return -3; }
    if sx126x_command(host, SX126X_CMD_SET_BUFFER_BASE_ADDRESS, &[0, 0x80]) != 0 { return -3; }
    // 4.8 kbit/s, no shaping, 117.3 kHz RX bandwidth, modest deviation.
    if sx126x_command(host, SX126X_CMD_SET_MODULATION_PARAMS, &[0x01, 0x0a, 0x0b, 0, 0, 0x00, 0x00, 0x52]) != 0 { return -3; }
    if sx126x_write_register(host, 0x06c0, &[0xd3, 0xa5]) != 0 { return -3; }
    sx126x_command(host, SX126X_CMD_SET_PACKET_PARAMS, &[0, 128, 0, 1, 0, 0, 255, 6, 0])
}

#[inline(always)] unsafe fn wait_for_irq(host: &LoraHost, irq_pin: i8, timeout_ms: u32) {
    if let Some(wait) = host.wait_irq { let _ = wait(host.user, timeout_ms); }
    /* The host ISR masks the GPIO edge before notifying the task. Re-enable
     * it after the radio status/FIFO has been sampled, including timeout
     * iterations, so a subsequent packet can wake the task. */
    if let Some(enable) = host.irq_enable { let _ = enable(host.user, irq_pin as i32, 1); }
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
                let command = core::str::from_utf8(&args_buf[..args_len]).unwrap_or("");
                if command == "stop" {
                    if let Some(disable) = host.irq_enable { let _ = disable(host.user, config.irq_pin as i32, 0); }
                    power_down_radio(host, config);
                    log(ctx, b"mod_lora sx127x rx stopped"); event(ctx, 2, &[]); return 0;
                }
                if command == "tx" {
                    let tx_rc = sx127x_send(host, &payload_buf[..payload_len]);
                    let _ = sx127x_configure_rx(host, config);
                    if tx_rc != 0 { log(ctx, b"mod_lora sx127x tx failed"); } else { tx_packets = tx_packets.saturating_add(1); event_bytes(ctx, 3, &payload_buf[..payload_len]); }
                } else if command == "reconfigure" {
                    let rc = sx127x_configure_rx(host, config);
                    if rc != 0 { log(ctx, b"mod_lora sx127x reconfigure failed"); } else { event(ctx, 4, &[]); }
                } else if command == "probe127" {
                    let rc = probe_sx127x(host);
                    if rc != 0 { log(ctx, b"mod_lora sx127x probe failed"); }
                } else if command == "fsk" {
                    let rc = sx127x_fsk_setup(host);
                    if rc != 0 { log(ctx, b"mod_lora FSK setup failed"); }
                    let _ = sx127x_configure_rx(host, config);
                } else if command == "stats" {
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
    let mut tx_packets = 0u32;
    loop {
        if let Some(poll) = host.poll_command {
            let mut args_len = args_buf.len();
            let mut payload_len = payload_buf.len();
            if poll(host.user, args_buf.as_mut_ptr(), &mut args_len,
                    payload_buf.as_mut_ptr(), &mut payload_len) == 0 {
                let command = core::str::from_utf8(&args_buf[..args_len]).unwrap_or("");
                if command == "stop" {
                    if let Some(disable) = host.irq_enable { let _ = disable(host.user, config.irq_pin as i32, 0); }
                    power_down_radio(host, config);
                    log(ctx, b"mod_lora sx126x rx stopped"); event(ctx, 2, &[]); return 0;
                }
                if command == "tx" {
                    let tx_rc = sx126x_send(host, config, &payload_buf[..payload_len]);
                    let _ = sx126x_configure_rx(host, config);
                    if tx_rc != 0 { log(ctx, b"mod_lora sx126x tx failed"); } else { tx_packets = tx_packets.saturating_add(1); event_bytes(ctx, 3, &payload_buf[..payload_len]); }
                } else if command == "reconfigure" {
                    let rc = sx126x_configure_rx(host, config);
                    if rc != 0 { log(ctx, b"mod_lora sx126x reconfigure failed"); } else { event(ctx, 4, &[]); }
                } else if command == "fsk" {
                    let rc = sx126x_fsk_setup(host, config);
                    if rc != 0 { log(ctx, b"mod_lora SX126x FSK setup failed"); }
                    let _ = sx126x_configure_rx(host, config);
                } else if command == "stats" {
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
    if command == "probe" {
        return if config.chip == 2 {
            let rc = probe_sx126x(host); log(ctx, b"mod_lora sx126x probe"); rc
        } else {
            let rc = probe_sx127x(host); log(ctx, b"mod_lora sx127x probe"); rc
        };
    }
    if command == "probe127" { let rc = probe_sx127x(host); log(ctx, b"mod_lora sx127x probe"); return rc; }
    if command == "probe126" { let rc = probe_sx126x(host); log(ctx, b"mod_lora sx126x probe"); return rc; }
    if command == "rx" {
        return if config.chip == 2 {
            run_sx126x_rx(ctx, host, config)
        } else {
            run_sx127x_rx(ctx, host, config)
        };
    }
    if command == "tx" {
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
    if command == "stop" {
        power_down_radio(host, config);
        return 0;
    }
    if command == "reconfigure" {
        return if config.chip == 2 {
            sx126x_configure_rx(host, config)
        } else {
            sx127x_configure_rx(host, config)
        };
    }
    if command == "fsk" {
        let rc = if config.chip == 2 { sx126x_fsk_setup(host, config) } else { sx127x_fsk_setup(host) };
        log(ctx, b"mod_lora FSK service selected");
        return rc;
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
