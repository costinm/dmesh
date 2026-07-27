use std::sync::atomic::{AtomicBool, AtomicPtr, AtomicU32, Ordering};
use std::sync::{Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use esp_idf_sys as sys;

use crate::commands::{CommandHandler, CommandRegistry, CommandRequest, CommandResponse};

use super::frames::{
    address_metadata, decode_frame, encode_meshtastic_data, encode_meshtastic_frame,
    format_meshtastic_node, hex_bytes, parse_bytes, FrameKind, MESHTASTIC_DEFAULT_CHANNEL_HASH,
    MESHTASTIC_DEFAULT_HOP_LIMIT, MESHTASTIC_DEFAULT_PORTNUM,
};
use super::l3dmesh::{Frame, Transport};
use super::settings::{parse_bool, parse_i32, SharedSettings};
use super::telemetry::{self, Direction};

const DEFAULT_FREQUENCY_HZ: u32 = 913_125_000;
const DEFAULT_BANDWIDTH_HZ: u32 = 250_000;
const MESHCORE_FREQUENCY_HZ: u32 = 910_525_000;
const SX127X_VERSION: u8 = 0x12;

const REG_FIFO: u8 = 0x00;
const REG_OP_MODE: u8 = 0x01;
const REG_FRF_MSB: u8 = 0x06;
const REG_FRF_MID: u8 = 0x07;
const REG_FRF_LSB: u8 = 0x08;
const REG_PA_CONFIG: u8 = 0x09;
const REG_LNA: u8 = 0x0c;
const REG_FIFO_ADDR_PTR: u8 = 0x0d;
const REG_FIFO_TX_BASE_ADDR: u8 = 0x0e;
const REG_FIFO_RX_BASE_ADDR: u8 = 0x0f;
const REG_FIFO_RX_CURRENT_ADDR: u8 = 0x10;
const REG_IRQ_FLAGS: u8 = 0x12;
const REG_RX_NB_BYTES: u8 = 0x13;
const REG_PKT_SNR_VALUE: u8 = 0x19;
const REG_PKT_RSSI_VALUE: u8 = 0x1a;
const REG_MODEM_CONFIG_1: u8 = 0x1d;
const REG_MODEM_CONFIG_2: u8 = 0x1e;
const REG_PREAMBLE_MSB: u8 = 0x20;
const REG_PREAMBLE_LSB: u8 = 0x21;
const REG_PAYLOAD_LENGTH: u8 = 0x22;
const REG_MODEM_CONFIG_3: u8 = 0x26;
const REG_SYNC_WORD: u8 = 0x39;
const REG_DIO_MAPPING_1: u8 = 0x40;
const REG_VERSION: u8 = 0x42;

// SX127x FSK/OOK register bank. These addresses intentionally overlap the
// LoRa bank; they are only used after clearing MODE_LONG_RANGE.
const REG_FSK_BITRATE_MSB: u8 = 0x02;
const REG_FSK_BITRATE_LSB: u8 = 0x03;
const REG_FSK_FDEV_MSB: u8 = 0x04;
const REG_FSK_FDEV_LSB: u8 = 0x05;
const REG_FSK_RX_CONFIG: u8 = 0x0d;
const REG_FSK_RX_BW: u8 = 0x12;
const REG_FSK_AFC_BW: u8 = 0x13;
const REG_FSK_PREAMBLE_DETECT: u8 = 0x1f;
const REG_FSK_RSSI_VALUE: u8 = 0x24;
const REG_FSK_PREAMBLE_MSB: u8 = 0x25;
const REG_FSK_PREAMBLE_LSB: u8 = 0x26;
const REG_FSK_SYNC_CONFIG: u8 = 0x27;
const REG_FSK_SYNC_VALUE_1: u8 = 0x28;
const REG_FSK_PACKET_CONFIG_1: u8 = 0x30;
const REG_FSK_PACKET_CONFIG_2: u8 = 0x31;
const REG_FSK_PAYLOAD_LENGTH: u8 = 0x32;
const REG_FSK_FIFO_THRESH: u8 = 0x35;
const REG_FSK_IRQ_FLAGS_1: u8 = 0x3e;
const REG_FSK_IRQ_FLAGS_2: u8 = 0x3f;

const MODE_LONG_RANGE: u8 = 0x80;
const MODE_SLEEP: u8 = 0x00;
const MODE_STDBY: u8 = 0x01;
const MODE_TX: u8 = 0x03;
const MODE_RX_CONTINUOUS: u8 = 0x05;
const MODE_CAD: u8 = 0x07;

const IRQ_CAD_DETECTED: u8 = 0x01;
const IRQ_CAD_DONE: u8 = 0x04;
const IRQ_TX_DONE: u8 = 0x08;
const IRQ_PAYLOAD_CRC_ERROR: u8 = 0x20;
const IRQ_RX_DONE: u8 = 0x40;

const FSK_DEFAULT_NETWORK_ID: u16 = 0xd3a5;
const FSK_DEFAULT_SLOT_MS: u32 = 80;
const FSK_CHANNEL_COUNT: u8 = 50;
const FSK_PACKET_MAX: usize = 128;
const FSK_SYNC_MAGIC: &[u8; 4] = b"DMSF";

static BACKGROUND_RX_RUNNING: AtomicBool = AtomicBool::new(false);
static GPIO_ISR_SERVICE_READY: AtomicBool = AtomicBool::new(false);

unsafe extern "C" {
    fn dmesh_lora_irq_set_task(task: *mut sys::tskTaskControlBlock);
    fn dmesh_lora_irq_rearm();
    fn dmesh_lora_gpio_isr(arg: *mut core::ffi::c_void);
}
static LORA_PACKET_COUNTER: AtomicU32 = AtomicU32::new(1);
static LORA_RX_TASK: AtomicPtr<sys::tskTaskControlBlock> = AtomicPtr::new(std::ptr::null_mut());
static LORA_SPI_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

static LORA_CAD_RX_ENABLED: AtomicBool = AtomicBool::new(true);
static LORA_CAD_TX_ENABLED: AtomicBool = AtomicBool::new(true);
static LORA_CAD_INTERVAL_MS: AtomicU32 = AtomicU32::new(2_000);
static LORA_CAD_RX_WINDOW_MS: AtomicU32 = AtomicU32::new(1_000);
static LORA_CAD_TX_TRIES: AtomicU32 = AtomicU32::new(4);
static LORA_CAD_SAMPLES: AtomicU32 = AtomicU32::new(0);
static LORA_CAD_DETECTED: AtomicU32 = AtomicU32::new(0);
static LORA_IRQ_WAKES: AtomicU32 = AtomicU32::new(0);
const NVS_LORA_CAD_RX: &str = "lora.cad_rx";
const NVS_LORA_CAD_TX: &str = "lora.cad_tx";
const NVS_LORA_CAD_INT_MS: &str = "lora.cad_int";
const NVS_LORA_CAD_RX_MS: &str = "lora.cad_rx_ms";
const NVS_LORA_CAD_TX_N: &str = "lora.cad_tx_n";
const NVS_LORA_MODE: &str = "lora.mode";

pub fn register_commands(registry: &mut CommandRegistry, settings: SharedSettings) {
    load_cad_settings(&settings);
    registry.register(LoraCommand::new("lora", settings.clone()));
    registry.register(LoraCommand::new("loraprobe", settings.clone()));
    registry.register(LoraCommand::new("lorasend", settings.clone()));
    registry.register(LoraCommand::new("loralisten", settings.clone()));
    registry.register(LoraCommand::new("loradump", settings.clone()));
    registry.register(RadioCommand::new(settings));
}

/// Load CAD-related NVS settings into the module atomics. Settings that
/// are absent fall back to the current static defaults (`cad_rx=true`,
/// `cad_tx=true`, 2 s/1 s/RX intervals, 4 TX retries). Called once at
/// boot and again after the `lora cad_rx=...` command updates NVS.
pub fn load_cad_settings(settings: &SharedSettings) {
    let s = settings.borrow();
    LORA_CAD_RX_ENABLED.store(
        s.get_bool(NVS_LORA_CAD_RX, true).unwrap_or(true),
        Ordering::Relaxed,
    );
    LORA_CAD_TX_ENABLED.store(
        s.get_bool(NVS_LORA_CAD_TX, true).unwrap_or(true),
        Ordering::Relaxed,
    );
    LORA_CAD_INTERVAL_MS.store(
        s.get_i32(NVS_LORA_CAD_INT_MS, 2_000)
            .unwrap_or(2_000)
            .max(5) as u32,
        Ordering::Relaxed,
    );
    LORA_CAD_RX_WINDOW_MS.store(
        s.get_i32(NVS_LORA_CAD_RX_MS, 1_000)
            .unwrap_or(1_000)
            .max(50) as u32,
        Ordering::Relaxed,
    );
    LORA_CAD_TX_TRIES.store(
        s.get_i32(NVS_LORA_CAD_TX_N, 4).unwrap_or(4).clamp(0, 16) as u32,
        Ordering::Relaxed,
    );
}

pub fn sleep_radio(settings: &SharedSettings) -> Result<()> {
    BACKGROUND_RX_RUNNING.store(false, Ordering::Relaxed);
    notify_lora_rx_task();
    if !wait_for_background_rx_stopped(Duration::from_secs(2)) {
        bail!("LoRa background receiver did not stop before radio sleep");
    }
    let state = LoraState::load(settings)?;
    let _guard = lora_spi_lock().lock().unwrap();
    // A SX126x in hardware duty-cycle RX can hold BUSY high while the task is
    // being stopped. `Radio::open` enables Vext before it probes BUSY, so a
    // failed probe used to leave Heltec V3's radio rail powered indefinitely.
    // `rx=false` is an explicit request to turn the radio off: preserve a
    // successful SetSleep result when possible, but always cut a configured
    // board rail afterwards.
    let result = Radio::open(&state.config).and_then(|mut radio| radio.sleep());
    if state.config.board_power_pin >= 0 {
        power_down_board(&state.config)?;
        if let Err(err) = result {
            // The rail transition is the effective stop operation on boards
            // such as Heltec V3. Do not prevent a caller from entering its
            // low-power mode merely because a BUSY-stuck SX1262 could not
            // acknowledge SetSleep immediately before power was removed.
            telemetry::record_log(format!(
                "ev=lora.sleep fallback=board_power_off msg={}",
                crate::commands::protocol::escape_value(&err.to_string())
            ));
            return Ok(());
        }
    }
    result
}

/// Whether the background receiver currently owns the radio IRQ line.
/// Sleep setup must not arm a board's DIO line after the radio supply was
/// explicitly removed, because an unpowered input may read high and reject
/// light sleep immediately.
pub fn background_rx_running() -> bool {
    BACKGROUND_RX_RUNNING.load(Ordering::Relaxed)
}

#[allow(dead_code)]
pub fn send_text(settings: &SharedSettings, text: &str, hop_limit: u8) -> Result<String> {
    send_payload(
        settings,
        text.as_bytes(),
        FrameKind::Meshtastic,
        Some(hop_limit),
        None,
        2000,
    )
}

/// Send opaque modem-control bytes without imposing a text encoding.
///
/// Raw-NAN, raw Wi-Fi, and LoRa share compact-CBOR command packets. Keeping
/// this byte-oriented avoids accidentally putting a legacy text ping on one
/// radio while the others carry CBOR.
pub fn send_raw(settings: &SharedSettings, payload: &[u8]) -> Result<String> {
    send_payload(settings, payload, FrameKind::Raw, Some(0), None, 2000)
}

pub fn transport(settings: SharedSettings) -> LoraTransport {
    LoraTransport::new(settings)
}

pub fn start_background_rx(settings: SharedSettings) -> Result<Option<thread::JoinHandle<()>>> {
    let state = LoraState::load(&settings)?;
    let mut config = state.config;
    if BACKGROUND_RX_RUNNING.swap(true, Ordering::Relaxed) {
        return Ok(None);
    }
    if let Err(err) = probe_lora_ready(&config) {
        BACKGROUND_RX_RUNNING.store(false, Ordering::Relaxed);
        let line = format!(
            "ev=lora.probe ok=false sck={} miso={} mosi={} cs={} rst={} dio0={} msg={}",
            config.sck,
            config.miso,
            config.mosi,
            config.cs,
            config.rst,
            config.dio0,
            crate::commands::protocol::escape_value(&err.to_string())
        );
        telemetry::record_log(line);
        return Ok(None);
    }

    let mode = lora_mode(&settings);
    apply_preset(&mut config, mode);
    let line = format!(
        "ev=lora.probe ok=true preset={} rf={} sync=0x{:02x} sck={} miso={} mosi={} cs={} rst={} dio0={}",
        mode.as_str(),
        compact_rf(&config),
        config.sync_word,
        config.sck,
        config.miso,
        config.mosi,
        config.cs,
        config.rst,
        config.dio0
    );
    telemetry::record_log(line);

    let local_node = meshtastic_sender_node().ok();
    let handle = thread::Builder::new()
        .name("lora-rx".to_string())
        .stack_size(12 * 1024)
        .spawn(move || {
            if let Err(err) = run_background_rx(config, local_node) {
                BACKGROUND_RX_RUNNING.store(false, Ordering::Relaxed);
                let line = format!(
                    "ev=lora.err c=rx msg={}",
                    crate::commands::protocol::escape_value(&err.to_string())
                );
                telemetry::record_log(line);
            }
        })
        .map_err(|err| anyhow!("failed to start LoRa RX thread: {err}"))?;
    Ok(Some(handle))
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum LoraChip {
    Sx127x,
    Sx1262,
}

impl LoraChip {
    pub(crate) fn parse(value: &str) -> Result<Self> {
        match value.to_ascii_lowercase().as_str() {
            "sx127x" | "sx1276" | "sx1278" | "rf95" => Ok(Self::Sx127x),
            "sx1262" | "sx126x" => Ok(Self::Sx1262),
            _ => bail!("unsupported LoRa chip {value}"),
        }
    }

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Sx127x => "sx127x",
            Self::Sx1262 => "sx1262",
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct LoraConfig {
    pub(crate) chip: LoraChip,
    pub frequency_hz: u32,
    pub bandwidth_hz: u32,
    pub beacon: bool,
    pub spi_host: i32,
    pub sck: i32,
    pub miso: i32,
    pub mosi: i32,
    pub cs: i32,
    pub rst: i32,
    // Board GPIO connected to the radio interrupt output. The persisted key is
    // `lora.dio0` for compatibility: SX127x uses DIO0, while SX126x routes its
    // selected IRQs to DIO1 and uses this same board GPIO.
    pub dio0: i32,
    pub busy: i32,
    pub board_power_pin: i32,
    pub board_power_level: i32,
    pub sx1262_dio2_rf_switch: bool,
    pub sx1262_tcxo_mv: i32,
    pub sx1262_pa_duty: i32,
    pub sx1262_pa_hp: i32,
    pub sx1262_pa_device: i32,
    pub sx1262_pa_lut: i32,
    pub sx1262_rx_timeout_ms: i32,
    pub sx1262_sync_word: i32,
    pub sf: i32,
    pub cr: i32,
    pub sync_word: i32,
    pub crc: bool,
    pub preamble: i32,
    pub tx_power: i32,
}

impl Default for LoraConfig {
    fn default() -> Self {
        Self {
            chip: LoraChip::Sx127x,
            frequency_hz: DEFAULT_FREQUENCY_HZ,
            bandwidth_hz: DEFAULT_BANDWIDTH_HZ,
            beacon: true,
            spi_host: sys::spi_host_device_t_SPI3_HOST as i32,
            sck: 5,
            miso: 19,
            mosi: 27,
            cs: 18,
            rst: 14,
            dio0: 26,
            busy: -1,
            board_power_pin: -1,
            board_power_level: 1,
            sx1262_dio2_rf_switch: false,
            sx1262_tcxo_mv: 0,
            sx1262_pa_duty: 4,
            sx1262_pa_hp: 7,
            sx1262_pa_device: 0,
            sx1262_pa_lut: 1,
            sx1262_rx_timeout_ms: 0,
            sx1262_sync_word: -1,
            sf: 10,
            cr: 5,
            sync_word: 0x2b,
            crc: true,
            preamble: 16,
            tx_power: 17,
        }
    }
}

struct LoraCommand {
    name: &'static str,
    settings: SharedSettings,
}

/// Bounded FSK/GFSK operations. FSK is a host-activated discovery modem, not
/// a replacement for the background Meshtastic LoRa receiver.
struct RadioCommand {
    settings: SharedSettings,
}

impl RadioCommand {
    fn new(settings: SharedSettings) -> Self {
        Self { settings }
    }
}

#[derive(Clone, Copy, Debug)]
struct FskConfig {
    network_id: u16,
    hop_seed: u32,
    bitrate: u32,
    deviation: u32,
    rx_bw: u32,
    preamble: u16,
    slot_ms: u32,
}

impl FskConfig {
    fn load(settings: &SharedSettings) -> Result<Self> {
        let s = settings.borrow();
        Ok(Self {
            network_id: s
                .get_i32("fsk.network_id", FSK_DEFAULT_NETWORK_ID as i32)?
                .clamp(1, u16::MAX as i32) as u16,
            hop_seed: s.get_i32("fsk.hop_seed", 0)? as u32,
            bitrate: s.get_i32("fsk.bitrate", 100_000)?.clamp(4_800, 300_000) as u32,
            deviation: s.get_i32("fsk.deviation", 25_000)?.clamp(1_000, 200_000) as u32,
            rx_bw: s.get_i32("fsk.rx_bw", 250_000)?.clamp(10_000, 500_000) as u32,
            preamble: s.get_i32("fsk.preamble", 16)?.clamp(3, u16::MAX as i32) as u16,
            slot_ms: s
                .get_i32("fsk.slot_ms", FSK_DEFAULT_SLOT_MS as i32)?
                .clamp(20, 500) as u32,
        })
    }

    fn rendezvous_channel(self) -> u8 {
        ((self.network_id as u32 ^ self.hop_seed) % FSK_CHANNEL_COUNT as u32) as u8
    }
}

impl LoraCommand {
    fn new(name: &'static str, settings: SharedSettings) -> Self {
        Self { name, settings }
    }
}

#[derive(Clone, Debug)]
struct LoraState {
    config: LoraConfig,
}

impl LoraState {
    fn load(settings: &SharedSettings) -> Result<Self> {
        let defaults = LoraConfig::default();
        let settings_ref = settings.borrow();
        let mut config = LoraConfig {
            chip: settings_ref
                .get_str("lora.chip")?
                .as_deref()
                .map(LoraChip::parse)
                .transpose()?
                .unwrap_or(defaults.chip),
            frequency_hz: settings_ref.get_i32("lora.freq", defaults.frequency_hz as i32)? as u32,
            bandwidth_hz: settings_ref.get_i32("lora.bw", defaults.bandwidth_hz as i32)? as u32,
            beacon: settings_ref.get_bool("lora.beacon", defaults.beacon)?,
            spi_host: settings_ref.get_i32("lora.spi_host", defaults.spi_host)?,
            sck: settings_ref.get_i32("lora.sck", defaults.sck)?,
            miso: settings_ref.get_i32("lora.miso", defaults.miso)?,
            mosi: settings_ref.get_i32("lora.mosi", defaults.mosi)?,
            cs: settings_ref.get_i32("lora.cs", defaults.cs)?,
            rst: settings_ref.get_i32("lora.rst", defaults.rst)?,
            dio0: settings_ref.get_i32("lora.dio0", defaults.dio0)?,
            busy: settings_ref.get_i32("lora.busy", defaults.busy)?,
            board_power_pin: settings_ref.get_i32("lora.pwrpin", defaults.board_power_pin)?,
            board_power_level: settings_ref.get_i32("lora.pwrlvl", defaults.board_power_level)?,
            sx1262_dio2_rf_switch: settings_ref
                .get_bool("lora.dio2rf", defaults.sx1262_dio2_rf_switch)?,
            sx1262_tcxo_mv: settings_ref.get_i32("lora.tcxo_mv", defaults.sx1262_tcxo_mv)?,
            sx1262_pa_duty: settings_ref.get_i32("lora.pa_duty", defaults.sx1262_pa_duty)?,
            sx1262_pa_hp: settings_ref.get_i32("lora.pa_hp", defaults.sx1262_pa_hp)?,
            sx1262_pa_device: settings_ref.get_i32("lora.pa_dev", defaults.sx1262_pa_device)?,
            sx1262_pa_lut: settings_ref.get_i32("lora.pa_lut", defaults.sx1262_pa_lut)?,
            sx1262_rx_timeout_ms: settings_ref
                .get_i32("lora.rx_timeout", defaults.sx1262_rx_timeout_ms)?,
            sx1262_sync_word: settings_ref.get_i32("lora.sx_sync", defaults.sx1262_sync_word)?,
            sf: settings_ref.get_i32("lora.sf", defaults.sf)?,
            cr: settings_ref.get_i32("lora.cr", defaults.cr)?,
            sync_word: settings_ref.get_i32("lora.sync_word", defaults.sync_word)?,
            crc: settings_ref.get_bool("lora.crc", defaults.crc)?,
            preamble: settings_ref.get_i32("lora.preamble", defaults.preamble)?,
            tx_power: settings_ref.get_i32("lora.tx_power", defaults.tx_power)?,
        };
        let mode = settings_ref
            .get_str(NVS_LORA_MODE)
            .ok()
            .flatten()
            .and_then(|s| LoraMode::parse(&s).ok())
            .unwrap_or(LoraMode::Meshtastic);
        apply_preset(&mut config, mode);
        Ok(Self { config })
    }
}

pub fn load_config(settings: &SharedSettings) -> Result<LoraConfig> {
    Ok(LoraState::load(settings)?.config)
}

pub fn status_text(settings: &SharedSettings) -> String {
    lora_status_text(settings)
}

impl CommandHandler for LoraCommand {
    fn name(&self) -> &'static str {
        self.name
    }

    fn handle(&mut self, request: &CommandRequest) -> Result<CommandResponse> {
        match self.name {
            "lora" => self.configure(request),
            "loraprobe" => self.probe(request),
            "lorasend" => self.send_raw(request),
            "loralisten" => self.listen(request),
            "loradump" => self.dump(request),
            _ => Ok(CommandResponse::error("invalid lora command")),
        }
    }
}

impl CommandHandler for RadioCommand {
    fn name(&self) -> &'static str {
        "radio"
    }

    fn handle(&mut self, request: &CommandRequest) -> Result<CommandResponse> {
        if request
            .arg("status")
            .map(parse_bool)
            .transpose()?
            .unwrap_or(false)
        {
            return Ok(CommandResponse::ok(fsk_status_text(&self.settings)?));
        }
        for (arg, key, min, max) in [
            ("network_id", "fsk.network_id", 1, u16::MAX as i32),
            ("hop_seed", "fsk.hop_seed", 0, i32::MAX),
            ("bitrate", "fsk.bitrate", 4_800, 300_000),
            ("deviation", "fsk.deviation", 1_000, 200_000),
            ("rx_bw", "fsk.rx_bw", 10_000, 500_000),
            ("preamble", "fsk.preamble", 3, u16::MAX as i32),
            ("slot_ms", "fsk.slot_ms", 20, 500),
        ] {
            if let Some(value) = request.arg_i32(arg)? {
                self.settings
                    .borrow_mut()
                    .set_i32(key, value.clamp(min, max))?;
            }
        }
        let config = FskConfig::load(&self.settings)?;
        match request.arg("op").unwrap_or("status") {
            "status" => Ok(CommandResponse::ok(fsk_status_text(&self.settings)?)),
            "send" => {
                let payload = parse_payload(request)?;
                let channel = request
                    .arg_i32("channel")?
                    .unwrap_or(config.rendezvous_channel() as i32)
                    .clamp(0, (FSK_CHANNEL_COUNT - 1) as i32) as u8;
                run_fsk_session(&self.settings, config, |radio| {
                    radio.configure_fsk(config, fsk_channel_hz(channel))?;
                    radio.send_fsk(
                        &payload,
                        request.arg_i32("timeout")?.unwrap_or(500) as u32,
                        config.preamble,
                    )
                })?;
                Ok(CommandResponse::ok(format!(
                    "radio fsk=sent channel={} len={}",
                    channel,
                    payload.len()
                )))
            }
            "sweep" => {
                let target = request
                    .arg("target")
                    .or_else(|| request.arg("to"))
                    .map(parse_last4)
                    .transpose()?
                    .unwrap_or(u32::MAX);
                let sequence = request.arg_i32("sequence")?.unwrap_or(0) as u32;
                let frame = encode_fsk_sync(config, target, sequence);
                run_fsk_session(&self.settings, config, |radio| {
                    for channel in 0..FSK_CHANNEL_COUNT {
                        radio.configure_fsk(config, fsk_channel_hz(channel))?;
                        radio.send_fsk(&frame, 500, config.preamble)?;
                        task_delay(Duration::from_millis(config.slot_ms as u64));
                    }
                    Ok(())
                })?;
                Ok(CommandResponse::ok(format!(
                    "radio fsk=sweep channels={} slot_ms={} target={:08x} seq={}",
                    FSK_CHANNEL_COUNT, config.slot_ms, target, sequence
                )))
            }
            "listen" => {
                let channel = request
                    .arg_i32("channel")?
                    .unwrap_or(config.rendezvous_channel() as i32)
                    .clamp(0, (FSK_CHANNEL_COUNT - 1) as i32) as u8;
                let ms = request
                    .arg_i32("ms")?
                    .unwrap_or((FSK_CHANNEL_COUNT as u32 * config.slot_ms + 100) as i32)
                    .clamp(20, 10_000) as u32;
                let (packet, diagnostics) = run_fsk_session(&self.settings, config, |radio| {
                    radio.configure_fsk(config, fsk_channel_hz(channel))?;
                    radio.start_fsk_rx()?;
                    let deadline = Instant::now() + Duration::from_millis(ms as u64);
                    while Instant::now() < deadline {
                        if let Some(packet) = radio.poll_fsk_packet()? {
                            return Ok((Some(packet), radio.fsk_diagnostics()?));
                        }
                        task_delay(Duration::from_millis(2));
                    }
                    Ok((None, radio.fsk_diagnostics()?))
                })?;
                let detail = packet
                    .map(|p| {
                        format!(
                            "len={} rssi={} data={} {}",
                            p.data.len(),
                            p.rssi,
                            hex_bytes(&p.data),
                            diagnostics
                        )
                    })
                    .unwrap_or_else(|| format!("none=true {diagnostics}"));
                Ok(CommandResponse::ok(format!(
                    "radio fsk=listen channel={} ms={} {}",
                    channel, ms, detail
                )))
            }
            op => bail!("unsupported radio op {op}; use status, send, sweep, or listen"),
        }
    }
}

fn fsk_status_text(settings: &SharedSettings) -> Result<String> {
    let fsk = FskConfig::load(settings)?;
    Ok(format!(
        "radio modulation=gfsk profile=us915_fhss_100k network_id=0x{:04x} hop_seed={} bitrate={} deviation={} rx_bw={} preamble={} slot_ms={} channels={} rendezvous_channel={}",
        fsk.network_id, fsk.hop_seed, fsk.bitrate, fsk.deviation, fsk.rx_bw,
        fsk.preamble, fsk.slot_ms, FSK_CHANNEL_COUNT, fsk.rendezvous_channel()
    ))
}

fn parse_last4(value: &str) -> Result<u32> {
    let value = value.trim().trim_start_matches("0x").replace(':', "");
    u32::from_str_radix(&value, 16)
        .or_else(|_| value.parse())
        .map_err(Into::into)
}

fn fsk_channel_hz(channel: u8) -> u32 {
    // US915 test map: 22 + 4 + 24 channels, 500 kHz spacing. The selected
    // modulation is engineering-only until regional RF compliance is checked.
    match channel {
        0..=21 => 902_250_000 + channel as u32 * 500_000,
        22..=25 => 913_750_000 + (channel as u32 - 22) * 500_000,
        _ => 916_250_000 + (channel as u32 - 26) * 500_000,
    }
}

fn encode_fsk_sync(config: FskConfig, target: u32, sequence: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(16);
    out.extend_from_slice(FSK_SYNC_MAGIC);
    out.push(1);
    out.push(0); // FSK_SYNC
    out.extend_from_slice(&config.network_id.to_be_bytes());
    out.extend_from_slice(&sequence.to_be_bytes());
    out.extend_from_slice(&target.to_be_bytes());
    out
}

fn run_fsk_session<T>(
    settings: &SharedSettings,
    config: FskConfig,
    f: impl FnOnce(&mut Radio) -> Result<T>,
) -> Result<T> {
    let restart_rx = BACKGROUND_RX_RUNNING.swap(false, Ordering::Relaxed);
    if restart_rx {
        notify_lora_rx_task();
        if !wait_for_background_rx_stopped(Duration::from_secs(2)) {
            bail!("LoRa background receiver did not stop for FSK session");
        }
    }
    let state = LoraState::load(settings)?;
    let result = {
        let _guard = lora_spi_lock().lock().unwrap();
        let mut radio = Radio::open(&state.config)?;
        let result = f(&mut radio);
        let _ = radio.sleep();
        result
    };
    if restart_rx {
        let _ = start_background_rx(settings.clone());
    }
    // Keep the argument in this helper so operations cannot accidentally use
    // stale module globals when FSK configuration grows further.
    let _ = config;
    result
}

impl LoraCommand {
    fn configure(&mut self, request: &CommandRequest) -> Result<CommandResponse> {
        if request
            .arg("sleep")
            .map(parse_bool)
            .transpose()?
            .unwrap_or(false)
        {
            sleep_radio(&self.settings)?;
            return Ok(CommandResponse::ok("lora sleep=true"));
        }
        if request
            .arg("cad")
            .or_else(|| request.arg("channel_active"))
            .map(parse_bool)
            .transpose()?
            .unwrap_or(false)
        {
            let timeout_ms = request
                .arg_i32("cad_timeout")?
                .or(request.arg_i32("timeout")?)
                .unwrap_or(0)
                .max(0) as u32;
            return self.cad_probe(timeout_ms);
        }
        let rx_request = request.arg("rx").map(parse_bool).transpose()?;
        if let Some(false) = rx_request {
            sleep_radio(&self.settings)?;
            return Ok(CommandResponse::ok("lora rx=false"));
        }
        // CAD-related settings. Updates NVS and the runtime atomics in
        // one shot so a single `lora cad_rx=false` takes effect
        // immediately without needing an `apply`/restart cycle.
        let mut cad_dirty = false;
        if let Some(value) = request.arg("cad_rx") {
            let enabled = parse_bool(value)?;
            self.settings
                .borrow_mut()
                .set_bool(NVS_LORA_CAD_RX, enabled)?;
            LORA_CAD_RX_ENABLED.store(enabled, Ordering::Relaxed);
            cad_dirty = true;
        }
        if let Some(value) = request.arg("cad_tx") {
            let enabled = parse_bool(value)?;
            self.settings
                .borrow_mut()
                .set_bool(NVS_LORA_CAD_TX, enabled)?;
            LORA_CAD_TX_ENABLED.store(enabled, Ordering::Relaxed);
            cad_dirty = true;
        }
        if let Some(value) = request.arg_i32("cad_interval_ms")? {
            let v = value.max(5);
            self.settings.borrow_mut().set_i32(NVS_LORA_CAD_INT_MS, v)?;
            LORA_CAD_INTERVAL_MS.store(v as u32, Ordering::Relaxed);
            cad_dirty = true;
        }
        if let Some(value) = request.arg_i32("cad_rx_ms")? {
            let v = value.max(50);
            self.settings.borrow_mut().set_i32(NVS_LORA_CAD_RX_MS, v)?;
            LORA_CAD_RX_WINDOW_MS.store(v as u32, Ordering::Relaxed);
            cad_dirty = true;
        }
        if let Some(value) = request.arg_i32("cad_tx_tries")? {
            let v = value.clamp(0, 16);
            self.settings.borrow_mut().set_i32(NVS_LORA_CAD_TX_N, v)?;
            LORA_CAD_TX_TRIES.store(v as u32, Ordering::Relaxed);
            cad_dirty = true;
        }
        if cad_dirty {
            return Ok(CommandResponse::ok(cad_status_text()));
        }
        if let Some(mode) = request.arg("mode") {
            let mode = LoraMode::parse(mode)?;
            self.settings
                .borrow_mut()
                .set_str(NVS_LORA_MODE, mode.as_str())?;
        }
        if let Some(preset) = request.arg("preset") {
            let preset = LoraPreset::parse(preset)?;
            let mut settings = self.settings.borrow_mut();
            if let Some(freq) = preset.frequency_hz {
                settings.set_i32("lora.freq", freq as i32)?;
            }
            settings.set_i32("lora.bw", preset.bandwidth_hz as i32)?;
            settings.set_i32("lora.sf", preset.sf)?;
            settings.set_i32("lora.cr", preset.cr)?;
            settings.set_i32("lora.sync_word", preset.sync_word)?;
            settings.set_bool("lora.crc", true)?;
            settings.set_i32("lora.preamble", 16)?;
        }
        if let Some(board) = request.arg("board") {
            match board.to_ascii_lowercase().as_str() {
                "heltec_v3" | "heltec-v3" | "wb32laf" => {
                    let mut settings = self.settings.borrow_mut();
                    settings.set_str("lora.chip", LoraChip::Sx1262.as_str())?;
                    settings.set_i32("lora.spi_host", sys::spi_host_device_t_SPI2_HOST as i32)?;
                    settings.set_i32("lora.sck", 9)?;
                    settings.set_i32("lora.miso", 11)?;
                    settings.set_i32("lora.mosi", 10)?;
                    settings.set_i32("lora.cs", 8)?;
                    settings.set_i32("lora.rst", 12)?;
                    settings.set_i32("lora.dio0", 14)?;
                    settings.set_i32("lora.busy", 13)?;
                    settings.set_i32("lora.pwrpin", 36)?;
                    settings.set_i32("lora.pwrlvl", 0)?;
                    settings.set_bool("lora.dio2rf", true)?;
                    settings.set_i32("lora.tcxo_mv", 1800)?;
                    settings.set_i32("lora.pa_duty", 4)?;
                    settings.set_i32("lora.pa_hp", 7)?;
                    settings.set_i32("lora.pa_dev", 0)?;
                    settings.set_i32("lora.pa_lut", 1)?;
                    settings.set_i32("lora.rx_timeout", 0)?;
                    settings.set_i32("lora.tx_power", 17)?;
                }
                _ => bail!("unsupported LoRa board {board}"),
            }
        }
        if let Some(chip) = request.arg("chip") {
            self.settings
                .borrow_mut()
                .set_str("lora.chip", LoraChip::parse(chip)?.as_str())?;
        }
        if let Some(freq) = request.arg_i32("freq")? {
            self.settings
                .borrow_mut()
                .set_i32("lora.freq", freq.max(0))?;
        }
        if let Some(bw) = request.arg_i32("bw")? {
            validate_bandwidth(bw as u32)?;
            self.settings.borrow_mut().set_i32("lora.bw", bw)?;
        }
        if let Some(beacon) = request.arg("beacon") {
            self.settings
                .borrow_mut()
                .set_bool("lora.beacon", parse_bool(beacon)?)?;
        }
        if let Some(crc) = request.arg("crc") {
            self.settings
                .borrow_mut()
                .set_bool("lora.crc", parse_bool(crc)?)?;
        }
        for (arg, key) in [
            ("dio2rf", "lora.dio2rf"),
            ("rf_switch", "lora.dio2rf"),
            ("dio2_rf_switch", "lora.dio2rf"),
        ] {
            if let Some(value) = request.arg(arg) {
                self.settings
                    .borrow_mut()
                    .set_bool(key, parse_bool(value)?)?;
            }
        }
        for (arg, key) in [
            ("spi_host", "lora.spi_host"),
            ("sck", "lora.sck"),
            ("miso", "lora.miso"),
            ("mosi", "lora.mosi"),
            ("cs", "lora.cs"),
            ("rst", "lora.rst"),
            ("dio0", "lora.dio0"),
            ("busy", "lora.busy"),
            ("pwrpin", "lora.pwrpin"),
            ("power_pin", "lora.pwrpin"),
            ("pwrlvl", "lora.pwrlvl"),
            ("power_level", "lora.pwrlvl"),
            ("sf", "lora.sf"),
            ("cr", "lora.cr"),
            ("sync_word", "lora.sync_word"),
            ("preamble", "lora.preamble"),
            ("tx_power", "lora.tx_power"),
            ("tcxo_mv", "lora.tcxo_mv"),
            ("pa_duty", "lora.pa_duty"),
            ("pa_hp", "lora.pa_hp"),
            ("pa_dev", "lora.pa_dev"),
            ("pa_lut", "lora.pa_lut"),
            ("rx_timeout", "lora.rx_timeout"),
            ("sx_sync", "lora.sx_sync"),
            ("sx1262_sync", "lora.sx_sync"),
        ] {
            if let Some(value) = request.arg(arg) {
                let value = parse_i32(value)?;
                match arg {
                    "sck" | "miso" | "mosi" | "cs" | "rst" | "dio0" => validate_pin(value)?,
                    "busy" | "pwrpin" | "power_pin" => validate_optional_pin(value)?,
                    "pwrlvl" | "power_level" => validate_range("power_level", value, 0, 1)?,
                    "sf" => validate_sf(value)?,
                    "cr" => validate_cr(value)?,
                    "sync_word" => validate_u8(value)?,
                    "preamble" => validate_range("preamble", value, 6, 65535)?,
                    "tx_power" => validate_range("tx_power", value, 2, 20)?,
                    "tcxo_mv" => validate_range("tcxo_mv", value, 0, 3300)?,
                    "pa_duty" => validate_range("pa_duty", value, 0, 7)?,
                    "pa_hp" => validate_range("pa_hp", value, 0, 7)?,
                    "pa_dev" => validate_range("pa_dev", value, 0, 1)?,
                    "pa_lut" => validate_range("pa_lut", value, 0, 1)?,
                    "rx_timeout" => validate_range("rx_timeout", value, 0, 60_000)?,
                    "sx_sync" | "sx1262_sync" => validate_range("sx_sync", value, -1, 65535)?,
                    _ => {}
                }
                self.settings.borrow_mut().set_i32(key, value)?;
            }
        }

        let state = LoraState::load(&self.settings)?;
        let apply_requested = request
            .arg("apply")
            .map(parse_bool)
            .transpose()?
            .unwrap_or(false);
        let restart_rx_after_apply = apply_requested
            && BACKGROUND_RX_RUNNING.load(Ordering::Relaxed)
            && !matches!(rx_request, Some(false));
        if restart_rx_after_apply {
            BACKGROUND_RX_RUNNING.store(false, Ordering::Relaxed);
            notify_lora_rx_task();
            task_delay(Duration::from_millis(75));
        }
        if apply_requested {
            let _guard = lora_spi_lock().lock().unwrap();
            let mut radio = Radio::open(&state.config)?;
            radio.configure_radio()?;
        }
        if request
            .arg("status")
            .map(parse_bool)
            .transpose()?
            .unwrap_or(false)
        {
            return Ok(CommandResponse::ok(lora_status_text(&self.settings)));
        }
        if matches!(rx_request, Some(true)) || restart_rx_after_apply {
            let started = start_background_rx(self.settings.clone())?.is_some();
            let state = LoraState::load(&self.settings)?;
            return Ok(CommandResponse::ok(format!(
                "lora rx=true started={} chip={} freq={} bw={} sf={} cr={} sync_word=0x{:02x} sx_sync=0x{:04x}",
                started,
                state.config.chip.as_str(),
                state.config.frequency_hz,
                state.config.bandwidth_hz,
                state.config.sf,
                state.config.cr,
                state.config.sync_word,
                sx1262_sync_word(&state.config)
            )));
        }
        Ok(CommandResponse::ok(lora_status_text(&self.settings)))
    }

    fn probe(&mut self, request: &CommandRequest) -> Result<CommandResponse> {
        let state = LoraState::load(&self.settings)?;
        let host_candidates = parse_i32_list(request.arg("spi_host"), state.config.spi_host)?;
        let chip_candidates = parse_chip_list(request.arg("chip"), state.config.chip)?;
        let sck_candidates = parse_pin_list(request.arg("sck"), state.config.sck)?;
        let miso_candidates = parse_pin_list(request.arg("miso"), state.config.miso)?;
        let mosi_candidates = parse_pin_list(request.arg("mosi"), state.config.mosi)?;
        let cs_candidates = parse_pin_list(request.arg("cs"), state.config.cs)?;
        let rst_candidates = parse_pin_list(request.arg("rst"), state.config.rst)?;
        let dio0_candidates = parse_pin_list(request.arg("dio0"), state.config.dio0)?;
        let busy_candidates = parse_optional_pin_list(request.arg("busy"), state.config.busy)?;

        let save = request
            .arg("save")
            .map(parse_bool)
            .transpose()?
            .unwrap_or(false);
        let mut attempts = Vec::new();

        for chip in &chip_candidates {
            for host in &host_candidates {
                for sck in &sck_candidates {
                    for miso in &miso_candidates {
                        for mosi in &mosi_candidates {
                            for cs in &cs_candidates {
                                for rst in &rst_candidates {
                                    for dio0 in &dio0_candidates {
                                        for busy in &busy_candidates {
                                            if has_duplicate_pins(&[
                                                *sck, *miso, *mosi, *cs, *rst, *dio0, *busy,
                                            ]) {
                                                continue;
                                            }
                                            let mut config = state.config.clone();
                                            config.chip = *chip;
                                            config.spi_host = *host;
                                            config.sck = *sck;
                                            config.miso = *miso;
                                            config.mosi = *mosi;
                                            config.cs = *cs;
                                            config.rst = *rst;
                                            config.dio0 = *dio0;
                                            config.busy = *busy;
                                            let result = probe_lora(&config);
                                            attempts.push(format!(
                                        "chip={},host={host},sck={sck},miso={miso},mosi={mosi},cs={cs},rst={rst},dio0={dio0},busy={busy}:{result}",
                                        chip.as_str()
                                    ));
                                            if result.starts_with("ready") && save {
                                                let mut settings = self.settings.borrow_mut();
                                                settings.set_str("lora.chip", chip.as_str())?;
                                                settings.set_i32("lora.spi_host", *host)?;
                                                settings.set_i32("lora.sck", *sck)?;
                                                settings.set_i32("lora.miso", *miso)?;
                                                settings.set_i32("lora.mosi", *mosi)?;
                                                settings.set_i32("lora.cs", *cs)?;
                                                settings.set_i32("lora.rst", *rst)?;
                                                settings.set_i32("lora.dio0", *dio0)?;
                                                settings.set_i32("lora.busy", *busy)?;
                                                return Ok(CommandResponse::ok(format!(
                                            "loraprobe matched chip={} host={host} sck={sck} miso={miso} mosi={mosi} cs={cs} rst={rst} dio0={dio0} busy={busy} saved=true",
                                            chip.as_str()
                                        )));
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(CommandResponse::ok(format!(
            "loraprobe {}",
            attempts.join(" ")
        )))
    }

    fn send_raw(&mut self, request: &CommandRequest) -> Result<CommandResponse> {
        let payload = parse_payload(request)?;
        let kind = request
            .arg("format")
            .or_else(|| request.arg("kind"))
            .map(FrameKind::parse)
            .transpose()?
            .unwrap_or(FrameKind::Meshtastic);
        let portnum = request
            .arg_i32("portnum")?
            .or_else(|| {
                self.settings
                    .borrow()
                    .get_i32("lora.portnum", MESHTASTIC_DEFAULT_PORTNUM as i32)
                    .ok()
            })
            .unwrap_or(MESHTASTIC_DEFAULT_PORTNUM as i32);
        if !(0..=511).contains(&portnum) {
            bail!("Meshtastic portnum out of private/reserved range: {portnum}");
        }
        let timeout_ms = parse_arg_or(request, "timeout", 2000)? as u32;
        let hop_limit = request
            .arg_i32("hop_limit")?
            .or(request.arg_i32("hop")?)
            .or_else(|| {
                if request
                    .arg("forward")
                    .map(parse_bool)
                    .transpose()
                    .ok()
                    .flatten()
                    .unwrap_or(false)
                {
                    Some(1)
                } else {
                    None
                }
            })
            .map(|hop| hop.clamp(0, 7) as u8);
        let response = send_payload(
            &self.settings,
            &payload,
            kind,
            hop_limit,
            Some(portnum as u32),
            timeout_ms,
        )?;
        Ok(CommandResponse::ok(response))
    }

    fn cad_probe(&mut self, timeout_ms: u32) -> Result<CommandResponse> {
        let was_rx_running = BACKGROUND_RX_RUNNING.load(Ordering::Relaxed);
        if was_rx_running {
            BACKGROUND_RX_RUNNING.store(false, Ordering::Relaxed);
            notify_lora_rx_task();
            task_delay(Duration::from_millis(75));
        }

        let state = LoraState::load(&self.settings)?;
        let _guard = lora_spi_lock().lock().unwrap();
        let mut radio = Radio::open_no_reset(&state.config)?;
        radio.configure_radio()?;
        let timeout = if timeout_ms == 0 {
            sx127x_cad_timeout(&state.config)
        } else {
            Duration::from_millis(timeout_ms as u64)
        };
        let active = radio.is_channel_active(timeout)?;
        if was_rx_running {
            BACKGROUND_RX_RUNNING.store(true, Ordering::Relaxed);
            notify_lora_rx_task();
        }
        Ok(CommandResponse::ok(format!(
            "lora cad=true active={} timeout_ms={} chip={}",
            active,
            timeout.as_millis(),
            state.config.chip.as_str()
        )))
    }

    fn listen(&mut self, request: &CommandRequest) -> Result<CommandResponse> {
        let ms = parse_arg_or(request, "ms", 5000)?.max(1) as u32;
        let max_packets = parse_arg_or(request, "count", 4)?.clamp(1, 16) as usize;
        let local_only = request
            .arg("local_only")
            .or_else(|| request.arg("wake_only"))
            .map(parse_bool)
            .transpose()?
            .unwrap_or(false);
        let state = LoraState::load(&self.settings)?;
        let local_node = meshtastic_sender_node().ok();
        let _guard = lora_spi_lock().lock().unwrap();
        let mut radio = Radio::open(&state.config)?;
        radio.configure_radio()?;
        radio.start_rx()?;

        let deadline = Instant::now() + Duration::from_millis(ms as u64);
        let mut packets = Vec::new();
        while Instant::now() < deadline && packets.len() < max_packets {
            if let Some(packet) = radio.poll_packet()? {
                let decoded = decode_frame(&packet.data)?;
                let address = address_metadata(&packet.data, &self.settings)?;
                let mac_local_match = decoded
                    .meshtastic
                    .zip(local_node)
                    .map(|(header, node)| header.is_for(node))
                    .unwrap_or(false);
                let local_match = address.local_match || mac_local_match;
                if local_match {
                    telemetry::record_local_packet(
                        "lora",
                        Direction::Rx,
                        &packet.data,
                        compact_lora_detail(
                            decoded.meshtastic,
                            address.destination.as_deref(),
                            packet.rssi,
                            packet.snr,
                        ),
                    );
                }
                if local_only && !local_match && !address.broadcast {
                    continue;
                }
                telemetry::record_packet(
                    "lora",
                    Direction::Rx,
                    &packet.data,
                    compact_lora_detail(
                        decoded.meshtastic,
                        address.destination.as_deref(),
                        packet.rssi,
                        packet.snr,
                    ),
                );
                packets.push(format!(
                    "src={} dst={} n={} local={} bc={} hl={} hs={} len={} wire={} rssi={} snr={} data={}",
                    decoded
                        .meshtastic
                        .map(|h| format_meshtastic_node(h.from))
                        .unwrap_or_else(|| "-".to_string()),
                    address.destination.as_deref().unwrap_or(""),
                    decoded
                        .meshtastic
                        .map(|h| h.id.to_string())
                        .unwrap_or_else(|| "-".to_string()),
                    local_match,
                    address.broadcast,
                    decoded.meshtastic.map(|h| h.hop_limit()).unwrap_or(0),
                    decoded.meshtastic.map(|h| h.hop_start()).unwrap_or(0),
                    decoded.payload.len(),
                    packet.data.len(),
                    packet.rssi,
                    packet.snr,
                    hex_bytes(decoded.payload)
                ));
            }
            task_delay(Duration::from_millis(20));
        }
        Ok(CommandResponse::ok(format!(
            "loralisten n={} {}",
            packets.len(),
            packets.join(" | ")
        )))
    }

    fn dump(&mut self, _request: &CommandRequest) -> Result<CommandResponse> {
        let state = LoraState::load(&self.settings)?;
        let _guard = lora_spi_lock().lock().unwrap();
        let mut radio = Radio::open_no_reset(&state.config)?;
        Ok(CommandResponse::ok(format!("loradump {}", radio.dump()?)))
    }
}

pub struct LoraTransport {
    #[allow(dead_code)]
    sent_frames: u32,
    #[allow(dead_code)]
    settings: SharedSettings,
}

impl LoraTransport {
    fn new(settings: SharedSettings) -> Self {
        Self {
            sent_frames: 0,
            settings,
        }
    }
}

impl Transport for LoraTransport {
    fn name(&self) -> &'static str {
        "lora"
    }

    fn send(&mut self, frame: &Frame<'_>, from_interface: i32) -> Result<()> {
        self.sent_frames = self.sent_frames.saturating_add(1);
        let state = LoraState::load(&self.settings)?;
        telemetry::count_packet("lora", Direction::Tx, frame.payload().len());
        telemetry::record_log(format!(
            "ev=lora.tx t=lora src=l3 from={} n={} len={} rf={}",
            from_interface,
            self.sent_frames,
            frame.payload().len(),
            compact_rf(&state.config)
        ));
        log::info!(
            "lora transport queued: from={} len={} total={} freq={} cs={}",
            from_interface,
            frame.payload().len(),
            self.sent_frames,
            state.config.frequency_hz,
            state.config.cs
        );
        Ok(())
    }
}

fn run_background_rx(config: LoraConfig, local_node: Option<u32>) -> Result<()> {
    LORA_RX_TASK.store(
        unsafe { sys::xTaskGetCurrentTaskHandle() },
        Ordering::SeqCst,
    );
    unsafe { dmesh_lora_irq_set_task(LORA_RX_TASK.load(Ordering::SeqCst)) };
    // `lora rx=false` can arrive immediately after the thread is spawned but
    // before it begins radio setup. Do not let that late-starting task reopen
    // a radio that the stop path has already put to sleep.
    if !BACKGROUND_RX_RUNNING.load(Ordering::Relaxed) {
        LORA_RX_TASK.store(std::ptr::null_mut(), Ordering::SeqCst);
        unsafe { dmesh_lora_irq_set_task(std::ptr::null_mut()) };
        return Ok(());
    }
    let cad_rx = LORA_CAD_RX_ENABLED.load(Ordering::Relaxed);
    if cad_rx && matches!(config.chip, LoraChip::Sx1262) {
        let result = run_sx1262_duty_cycle_background_rx(&config, local_node);
        unsafe {
            let _ = sys::gpio_isr_handler_remove(config.dio0);
            let _ = set_lora_irq_enabled(config.dio0, false);
        }
        LORA_RX_TASK.store(std::ptr::null_mut(), Ordering::SeqCst);
        unsafe { dmesh_lora_irq_set_task(std::ptr::null_mut()) };
        return result;
    }
    if cad_rx {
        let result = run_cad_background_rx(&config, local_node);
        unsafe {
            let _ = sys::gpio_isr_handler_remove(config.dio0);
            let _ = set_lora_irq_enabled(config.dio0, false);
        }
        LORA_RX_TASK.store(std::ptr::null_mut(), Ordering::SeqCst);
        unsafe { dmesh_lora_irq_set_task(std::ptr::null_mut()) };
        return result;
    }
    let result = run_continuous_background_rx(&config, local_node);
    unsafe {
        let _ = sys::gpio_isr_handler_remove(config.dio0);
        let _ = set_lora_irq_enabled(config.dio0, false);
    }
    LORA_RX_TASK.store(std::ptr::null_mut(), Ordering::SeqCst);
    unsafe { dmesh_lora_irq_set_task(std::ptr::null_mut()) };
    result
}

/// Legacy receive loop: keep the radio in `RX_CONTINUOUS` and wait for
/// `IRQ_RX_DONE` via the DIO0 GPIO ISR. Highest current; only used when
/// `lora.cad_rx=false`.
fn run_continuous_background_rx(config: &LoraConfig, local_node: Option<u32>) -> Result<()> {
    {
        let _guard = lora_spi_lock().lock().unwrap();
        let mut radio = Radio::open(config)?;
        radio.configure_radio()?;
        radio.start_rx()?;
    }
    configure_lora_irq_interrupt(config.dio0)?;
    telemetry::record_log(format!(
        "ev=lora.rx_start mode=continuous rf={} sync=0x{:02x} cs={} rst={} dio0={}",
        compact_rf(config),
        config.sync_word,
        config.cs,
        config.rst,
        config.dio0
    ));

    while BACKGROUND_RX_RUNNING.load(Ordering::Relaxed) {
        let notified = wait_for_background_lora_irq(config.dio0, background_poll_interval(config));
        if !BACKGROUND_RX_RUNNING.load(Ordering::Relaxed) {
            break;
        }
        match notified {
            true => match poll_background_packet(config) {
                Ok(Some(packet)) => {
                    record_background_packet(&packet, "background", local_node);
                    forward_rx_packet(&packet);
                    rearm_background_rx(config)?;
                }
                Ok(None) => {}
                Err(err) => {
                    let line = format!(
                        "ev=lora.err c=rx msg={}",
                        crate::commands::protocol::escape_value(&err.to_string())
                    );
                    telemetry::record_log(line);
                    task_delay(Duration::from_millis(1000));
                }
            },
            false => {
                // A long timeout is a missed-IRQ recovery path, not the normal RX mechanism.
                if let Ok(Some(packet)) = poll_background_packet(config) {
                    record_background_packet(&packet, "background-timeout", local_node);
                    forward_rx_packet(&packet);
                    rearm_background_rx(config)?;
                }
            }
        }
    }
    Ok(())
}

/// SX126x hardware duty-cycle receive loop, matching Meshtastic's
/// `startReceiveDutyCycleAuto()` shape. The radio alternates RX and sleep
/// internally via `SetRxDutyCycle`; the ESP task only wakes for DIO IRQs,
/// stop requests, or a long missed-IRQ recovery timeout.
fn run_sx1262_duty_cycle_background_rx(config: &LoraConfig, local_node: Option<u32>) -> Result<()> {
    let duty = {
        let _guard = lora_spi_lock().lock().unwrap();
        let mut radio = Radio::open(config)?;
        radio.configure_radio()?;
        radio.start_background_rx_mode()?
    };
    configure_lora_irq_interrupt(config.dio0)?;
    telemetry::record_log(format!(
        "ev=lora.rx_start mode=sx126x_duty rf={} sync=0x{:02x} cs={} rst={} dio0={} rx_us={} sleep_us={} preamble={} min_symbols=8",
        compact_rf(config),
        config.sync_word,
        config.cs,
        config.rst,
        config.dio0,
        duty.rx_us,
        duty.sleep_us,
        config.preamble
    ));

    while BACKGROUND_RX_RUNNING.load(Ordering::Relaxed) {
        let notified = wait_for_background_lora_irq(config.dio0, Duration::from_secs(30));
        if !BACKGROUND_RX_RUNNING.load(Ordering::Relaxed) {
            break;
        }
        match poll_background_packet(config) {
            Ok(Some(packet)) => {
                record_background_packet(
                    &packet,
                    if notified {
                        "sx126x-duty"
                    } else {
                        "sx126x-duty-timeout"
                    },
                    local_node,
                );
                forward_rx_packet(&packet);
                rearm_background_rx(config)?;
            }
            Ok(None) => {
                if notified {
                    rearm_background_rx(config)?;
                }
            }
            Err(err) => {
                telemetry::record_log(format!(
                    "ev=lora.err c=sx126x_duty_rx msg={}",
                    crate::commands::protocol::escape_value(&err.to_string())
                ));
                task_delay(Duration::from_millis(1000));
                rearm_background_rx(config)?;
            }
        }
    }
    Ok(())
}

/// Battery-aware receive loop: channel-activity-detected duty cycling.
///
/// Between scans the SX127x is held in `STDBY`. On each cycle DIO0 is mapped
/// to `CAD_DONE` and the task blocks for the CAD interrupt. If preamble
/// activity is detected, DIO0 is remapped to `RX_DONE`, RX starts immediately,
/// and the task blocks for a packet. The ESP task then waits for
/// `lora.cad_interval_ms` before the next CAD operation.
///
/// The radio is the dominant ESP32 current source while awake
/// (SX127x `RX_CONTINUOUS` ~11 mA, SX1262 ~5-7 mA). CAD-RX keeps the
/// modem awake for only a fraction of each cycle: at SF9/250 kHz a
/// CAD scan takes ~8 ms, so a 2 s interval produces a typical duty
/// cycle well below 1 %.
fn run_cad_background_rx(config: &LoraConfig, local_node: Option<u32>) -> Result<()> {
    {
        let _guard = lora_spi_lock().lock().unwrap();
        let mut radio = Radio::open(config)?;
        radio.configure_radio()?;
        // Start in standby so the first and subsequent CAD transitions match.
        let _ = radio.standby();
    }
    configure_lora_irq_interrupt(config.dio0)?;
    let cad_timeout = sx127x_cad_timeout(config);
    let configured_cad_interval =
        Duration::from_millis(LORA_CAD_INTERVAL_MS.load(Ordering::Relaxed) as u64);
    let cad_interval = cad_receive_interval(config, configured_cad_interval);
    let cad_rx_window = Duration::from_millis(LORA_CAD_RX_WINDOW_MS.load(Ordering::Relaxed) as u64);
    telemetry::record_log(format!(
        "ev=lora.rx_start mode=cad rf={} sync=0x{:02x} cs={} rst={} dio0={} cad_interval_ms={} cad_configured_ms={} cad_rx_window_ms={}",
        compact_rf(config),
        config.sync_word,
        config.cs,
        config.rst,
        config.dio0,
        cad_interval.as_millis(),
        configured_cad_interval.as_millis(),
        cad_rx_window.as_millis()
    ));

    while BACKGROUND_RX_RUNNING.load(Ordering::Relaxed) {
        // --- CAD phase ---
        let active = {
            let _guard = lora_spi_lock().lock().unwrap();
            let mut radio = Radio::open_no_reset(config)?;
            LORA_CAD_SAMPLES.fetch_add(1, Ordering::Relaxed);
            match radio.is_channel_active(cad_timeout) {
                Ok(active) => active,
                Err(err) => {
                    if !is_cad_timeout_error(&err) {
                        telemetry::record_log(format!(
                            "ev=lora.cad c=rx err={}",
                            crate::commands::protocol::escape_value(&err.to_string())
                        ));
                    }
                    false
                }
            }
        };
        if !BACKGROUND_RX_RUNNING.load(Ordering::Relaxed) {
            break;
        }

        if active {
            LORA_CAD_DETECTED.fetch_add(1, Ordering::Relaxed);
            // --- RX window: arm RX and wait on the DIO0 ISR for RX_DONE ---
            {
                let _guard = lora_spi_lock().lock().unwrap();
                let mut radio = Radio::open_no_reset(config)?;
                if let Err(err) = radio.start_rx() {
                    telemetry::record_log(format!(
                        "ev=lora.cad c=start_rx err={}",
                        crate::commands::protocol::escape_value(&err.to_string())
                    ));
                    let _ = radio.standby();
                    continue;
                }
            }
            let rx_deadline = Instant::now() + cad_rx_window;
            while BACKGROUND_RX_RUNNING.load(Ordering::Relaxed) && Instant::now() < rx_deadline {
                let remaining = rx_deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() || !wait_for_background_lora_irq(config.dio0, remaining) {
                    break;
                }
                match poll_background_packet(config) {
                    Ok(Some(packet)) => {
                        record_background_packet(&packet, "cad", local_node);
                        forward_rx_packet(&packet);
                        break;
                    }
                    Ok(None) => {
                        let _ = rearm_background_rx(config);
                    }
                    Err(err) => {
                        telemetry::record_log(format!(
                            "ev=lora.err c=cad_rx msg={}",
                            crate::commands::protocol::escape_value(&err.to_string())
                        ));
                        let _ = rearm_background_rx(config);
                    }
                }
            }
            // `poll_background_packet` may have restarted RX. Force standby
            // before the interval so only the ESP automatic-light-sleep
            // behavior and SX127x standby current are measured.
            {
                let _guard = lora_spi_lock().lock().unwrap();
                let mut radio = Radio::open_no_reset(config)?;
                let _ = radio.standby();
            }
        }

        if !BACKGROUND_RX_RUNNING.load(Ordering::Relaxed) {
            break;
        }

        // --- Idle phase: keep radio in STDBY between CAD cycles ---
        // The wait doubles as a task delay; `wait_for_lora_irq` returns
        // early if any task notification arrives (e.g. a `sleep_radio`
        // request or an out-of-band `notify_lora_rx_task`).
        let _ = wait_for_background_lora_irq(config.dio0, cad_interval);
    }
    Ok(())
}

fn poll_background_packet(config: &LoraConfig) -> Result<Option<Packet>> {
    let _guard = lora_spi_lock().lock().unwrap();
    let mut radio = Radio::open_no_reset(config)?;
    radio.poll_packet()
}

fn rearm_background_rx(config: &LoraConfig) -> Result<()> {
    let _guard = lora_spi_lock().lock().unwrap();
    let mut radio = Radio::open_no_reset(config)?;
    radio.start_background_rx_mode()?;
    Ok(())
}

fn background_poll_interval(config: &LoraConfig) -> Duration {
    match config.chip {
        LoraChip::Sx1262 => Duration::from_millis(250),
        LoraChip::Sx127x => Duration::from_secs(30),
    }
}

/// Compact text summary of the current CAD parameters used by both
/// `lora cad_rx=true` and the periodic `lora status=true` output.
fn cad_status_text() -> String {
    format!(
        "lora cad_rx={} cad_tx={} cad_interval_ms={} cad_rx_window_ms={} cad_tx_tries={} cad_samples={} cad_detected={} irq_wakes={}",
        LORA_CAD_RX_ENABLED.load(Ordering::Relaxed),
        LORA_CAD_TX_ENABLED.load(Ordering::Relaxed),
        LORA_CAD_INTERVAL_MS.load(Ordering::Relaxed),
        LORA_CAD_RX_WINDOW_MS.load(Ordering::Relaxed),
        LORA_CAD_TX_TRIES.load(Ordering::Relaxed),
        LORA_CAD_SAMPLES.load(Ordering::Relaxed),
        LORA_CAD_DETECTED.load(Ordering::Relaxed),
        LORA_IRQ_WAKES.load(Ordering::Relaxed)
    )
}

fn wait_for_background_rx_stopped(timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while !LORA_RX_TASK.load(Ordering::Acquire).is_null() && Instant::now() < deadline {
        notify_lora_rx_task();
        task_delay(Duration::from_millis(10));
    }
    LORA_RX_TASK.load(Ordering::Acquire).is_null()
}

fn is_cad_timeout_error(err: &anyhow::Error) -> bool {
    err.to_string().contains("CAD timeout")
}

fn record_background_packet(packet: &Packet, source: &str, local_node: Option<u32>) {
    let decoded = decode_frame(&packet.data).ok();
    let (src, dst, packet_id, local_match, broadcast, hop_limit, hop_start) =
        if let Some(decoded) = decoded {
            if let Some(header) = decoded.meshtastic {
                (
                    format_meshtastic_node(header.from),
                    format_meshtastic_node(header.to),
                    header.id.to_string(),
                    local_node.map(|node| header.is_for(node)).unwrap_or(false),
                    header.is_broadcast(),
                    header.hop_limit(),
                    header.hop_start(),
                )
            } else {
                (
                    "-".to_string(),
                    "-".to_string(),
                    "-".to_string(),
                    false,
                    false,
                    0,
                    0,
                )
            }
        } else {
            (
                "-".to_string(),
                "-".to_string(),
                "-".to_string(),
                false,
                false,
                0,
                0,
            )
        };
    let detail = format!(
        "src={} dst={} n={} rssi={} snr={} hl={} hs={} source={}",
        src, dst, packet_id, packet.rssi, packet.snr, hop_limit, hop_start, source
    );
    telemetry::record_packet("lora", Direction::Rx, &packet.data, detail.clone());
    if local_match {
        telemetry::record_local_packet("lora", Direction::Rx, &packet.data, detail.clone());
    }
    let line = format!(
        "ev={} t=lora src={} dst={} n={} local={} bc={} hl={} hs={} len={} rssi={} snr={}",
        if local_match {
            "lora.rx_local"
        } else {
            "lora.rx"
        },
        src,
        dst,
        packet_id,
        local_match,
        broadcast,
        hop_limit,
        hop_start,
        packet.data.len(),
        packet.rssi,
        packet.snr
    );
    super::serial::on_radio_packet_received();
    telemetry::record_log(line.clone());
    telemetry::emit_console(&line);
    emit_dmesh_control_packet(packet, source);
}

/// Emit the small, stable subset of DMesh control text required by modem
/// supervisors. Raw frames remain opaque; only ping/pong metadata is mirrored
/// to the console so lmesh can attribute a response without scraping packet
/// bytes or Meshtastic headers.
fn emit_dmesh_control_packet(packet: &Packet, source: &str) {
    let Ok(text) = core::str::from_utf8(&packet.data) else {
        return;
    };
    let kind = if text.starts_with("dmesh.pong ") {
        "pong"
    } else if text.starts_with("dmesh.ping ") {
        "ping"
    } else {
        return;
    };
    let field = |name: &str| {
        text.split_ascii_whitespace()
            .find_map(|item| item.strip_prefix(name))
            .unwrap_or("-")
    };
    let line = format!(
        "event type=lora.dmesh_control kind={} source={} from={} to={} reply={} uptime_ms={} link_rssi_dbm={} snr={} nrun={} nmg={} nsdf={} nrx={} ntx={} ndrop={} nage={}",
        kind,
        source,
        field("from="),
        field("to="),
        field("reply="),
        field("uptime_ms="),
        packet.rssi,
        packet.snr,
        field("nrun="),
        field("nmg="),
        field("nsdf="),
        field("nrx="),
        field("ntx="),
        field("ndrop="),
        field("nage="),
    );
    telemetry::record_log(line.clone());
    telemetry::emit_console(&line);
}

fn lora_spi_lock() -> &'static Mutex<()> {
    LORA_SPI_LOCK.get_or_init(|| Mutex::new(()))
}

fn configure_lora_irq_interrupt(pin: i32) -> Result<()> {
    unsafe {
        if !GPIO_ISR_SERVICE_READY.load(Ordering::Relaxed) {
            let install = sys::gpio_install_isr_service(sys::ESP_INTR_FLAG_IRAM as i32);
            if install != sys::ESP_OK && install != sys::ESP_ERR_INVALID_STATE {
                esp_ok(install)?;
            }
            GPIO_ISR_SERVICE_READY.store(true, Ordering::Relaxed);
        }
        let _ = sys::gpio_isr_handler_remove(pin);
        esp_ok(sys::gpio_set_intr_type(
            pin,
            sys::gpio_int_type_t_GPIO_INTR_POSEDGE,
        ))?;
        esp_ok(sys::gpio_isr_handler_add(
            pin,
            Some(dmesh_lora_gpio_isr),
            pin as usize as *mut core::ffi::c_void,
        ))?;
    }
    Ok(())
}

fn set_lora_irq_enabled(pin: i32, enabled: bool) -> Result<()> {
    unsafe {
        if enabled {
            esp_ok(sys::gpio_set_intr_type(
                pin,
                sys::gpio_int_type_t_GPIO_INTR_POSEDGE,
            ))?;
            esp_ok(sys::gpio_intr_enable(pin as sys::gpio_num_t))?;
        } else {
            esp_ok(sys::gpio_intr_disable(pin as sys::gpio_num_t))?;
            esp_ok(sys::gpio_set_intr_type(
                pin,
                sys::gpio_int_type_t_GPIO_INTR_DISABLE,
            ))?;
        }
    }
    Ok(())
}

fn wait_for_lora_irq(pin: i32, timeout: Duration) -> bool {
    // A radio IRQ line can remain asserted or generate a burst around CAD/RX state
    // changes. Re-arm the IRAM ISR once per task wait so it cannot hold CPU0
    // in an interrupt storm before SPI has acknowledged the radio IRQ.
    // The ISR masks DIO0 on the first edge. Re-enable it only from task
    // context, after the previous radio operation has had a chance to clear
    // its IRQ source. This is shared by SX127x LoRa/FSK mappings and SX126x
    // LoRa duty-cycle mappings.
    unsafe { dmesh_lora_irq_rearm() };
    // Clear the software latch before unmasking the GPIO. Otherwise an edge
    // immediately after gpio_intr_enable could be erased by rearm().
    if set_lora_irq_enabled(pin, true).is_err() {
        return false;
    }
    let ticks = duration_to_ticks(timeout);
    let woke = unsafe { sys::ulTaskGenericNotifyTake(0, 1, ticks) != 0 };
    if woke {
        LORA_IRQ_WAKES.fetch_add(1, Ordering::Relaxed);
    }
    woke
}

/// Wait for a radio IRQ or a background-RX stop request without losing a stop
/// notification between the loop condition and the RTOS blocking call.
fn wait_for_background_lora_irq(pin: i32, timeout: Duration) -> bool {
    unsafe { dmesh_lora_irq_rearm() };
    // A stop may arrive while the task configures the radio, before it reaches
    // its next wait. Check after rearm so that notification cannot be erased
    // and turned into a 30-second SX126x wait.
    if !BACKGROUND_RX_RUNNING.load(Ordering::Relaxed) {
        return true;
    }
    if set_lora_irq_enabled(pin, true).is_err() {
        return false;
    }
    let ticks = duration_to_ticks(timeout);
    let woke = unsafe { sys::ulTaskGenericNotifyTake(0, 1, ticks) != 0 };
    if woke {
        LORA_IRQ_WAKES.fetch_add(1, Ordering::Relaxed);
    }
    woke
}

fn notify_lora_rx_task() {
    let task = LORA_RX_TASK.load(Ordering::SeqCst);
    if !task.is_null() {
        unsafe {
            sys::xTaskGenericNotify(
                task,
                0,
                1,
                sys::eNotifyAction_eIncrement,
                std::ptr::null_mut(),
            );
        }
    }
}

fn duration_to_ticks(timeout: Duration) -> sys::TickType_t {
    let hz = sys::configTICK_RATE_HZ as u128;
    let ticks = timeout.as_millis().saturating_mul(hz).div_ceil(1000);
    ticks.min(sys::TickType_t::MAX as u128) as sys::TickType_t
}

fn task_delay(timeout: Duration) {
    unsafe {
        sys::vTaskDelay(duration_to_ticks(timeout).max(1));
    }
}

fn forward_rx_packet(packet: &Packet) {
    super::mode::observe_lora_ping("lora", &packet.data, packet.rssi);
    if super::mode::is_companion_mode() {
        match super::ble_bt::announce_lora_packet(&packet.data, packet.rssi, packet.snr) {
            Ok(()) => {
                let line = format!("ev=lora.fwd t=ble len={} ok=true", packet.data.len());
                telemetry::record_log(line);
            }
            Err(err) => {
                let line = format!(
                    "ev=lora.fwd t=ble len={} ok=false msg={}",
                    packet.data.len(),
                    crate::commands::protocol::escape_value(&err.to_string())
                );
                telemetry::record_log(line);
            }
        }
    } else {
        telemetry::record_log(format!(
            "ev=lora.fwd t=ble skipped=true reason=infra len={}",
            packet.data.len()
        ));
    }
    match super::wifi::forward_management_packet(&packet.data) {
        Ok(()) => {
            let line = format!("ev=lora.fwd t=wifi_raw len={} ok=true", packet.data.len());
            telemetry::record_log(line);
        }
        Err(err) => {
            let line = format!(
                "ev=lora.fwd t=wifi_raw len={} ok=false msg={}",
                packet.data.len(),
                crate::commands::protocol::escape_value(&err.to_string())
            );
            telemetry::record_log(line);
        }
    }
    match super::nan::forward_packet(&packet.data) {
        Ok(()) => {
            let line = format!("ev=lora.fwd t=nan len={} ok=true", packet.data.len());
            telemetry::record_log(line);
        }
        Err(err) => {
            let line = format!(
                "ev=lora.fwd t=nan len={} ok=false msg={}",
                packet.data.len(),
                crate::commands::protocol::escape_value(&err.to_string())
            );
            telemetry::record_log(line);
        }
    }
}

struct Packet {
    data: Vec<u8>,
    rssi: i32,
    snr: f32,
}

struct LoraPreset {
    /// Override frequency, or `None` to keep the current setting.
    frequency_hz: Option<u32>,
    bandwidth_hz: u32,
    sf: i32,
    cr: i32,
    /// SX127x sync word byte. Meshtastic uses `0x2b`, MeshCore uses `0x34`
    /// (LoRa private network word).
    sync_word: i32,
}

impl LoraPreset {
    fn parse(value: &str) -> Result<Self> {
        match value.to_ascii_lowercase().as_str() {
            "medium_fast" | "mediumfast" | "mf" => Ok(Self {
                frequency_hz: None,
                bandwidth_hz: 250_000,
                sf: 9,
                cr: 5,
                sync_word: 0x2b,
            }),
            "medium_slow" | "mediumslow" | "ms" => Ok(Self {
                frequency_hz: None,
                bandwidth_hz: 250_000,
                sf: 10,
                cr: 5,
                sync_word: 0x2b,
            }),
            "meshcore" | "mesh_core" | "mc" => Ok(Self {
                frequency_hz: Some(MESHCORE_FREQUENCY_HZ),
                bandwidth_hz: 62_500,
                sf: 7,
                cr: 5,
                sync_word: 0x34,
            }),
            _ => bail!("unsupported LoRa preset {value}"),
        }
    }
}

/// LoRa operating mode: selects which preset is applied at background RX
/// startup. Persisted via `lora.mode` in NVS.
#[derive(Clone, Copy, Debug, PartialEq)]
enum LoraMode {
    /// Meshtastic MEDIUM_FAST: 913.125 MHz, BW 250 kHz, SF 9, CR 5,
    /// sync_word 0x2b.
    Meshtastic,
    /// MeshCore: 910.525 MHz, BW 62.5 kHz, SF 7, CR 5, sync_word 0x34.
    MeshCore,
}

impl LoraMode {
    fn parse(value: &str) -> Result<Self> {
        match value.to_ascii_lowercase().as_str() {
            "meshtastic" | "mt" | "medium_fast" => Ok(Self::Meshtastic),
            "meshcore" | "mesh_core" | "mc" => Ok(Self::MeshCore),
            _ => bail!("unsupported LoRa mode {value}"),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Meshtastic => "meshtastic",
            Self::MeshCore => "meshcore",
        }
    }
}

/// Read the persisted LoRa mode from NVS, defaulting to Meshtastic.
fn lora_mode(settings: &SharedSettings) -> LoraMode {
    settings
        .borrow()
        .get_str(NVS_LORA_MODE)
        .ok()
        .flatten()
        .and_then(|s| LoraMode::parse(&s).ok())
        .unwrap_or(LoraMode::Meshtastic)
}

/// Apply the modulation preset for the given mode to a radio config.
fn apply_preset(config: &mut LoraConfig, mode: LoraMode) {
    match mode {
        LoraMode::Meshtastic => {
            config.frequency_hz = DEFAULT_FREQUENCY_HZ;
            config.bandwidth_hz = 250_000;
            config.sf = 9;
            config.cr = 5;
            config.sync_word = 0x2b;
            config.crc = true;
            config.preamble = 16;
        }
        LoraMode::MeshCore => {
            config.frequency_hz = MESHCORE_FREQUENCY_HZ;
            config.bandwidth_hz = 62_500;
            config.sf = 7;
            config.cr = 5;
            config.sync_word = 0x34;
            config.crc = true;
            config.preamble = 16;
        }
    }
}

struct Sx127x {
    config: LoraConfig,
    host: sys::spi_host_device_t,
    handle: sys::spi_device_handle_t,
}

enum Radio {
    Sx127x(Sx127x),
    Sx1262(Sx1262),
}

impl Radio {
    fn open(config: &LoraConfig) -> Result<Self> {
        match config.chip {
            LoraChip::Sx127x => Ok(Self::Sx127x(Sx127x::open(config)?)),
            LoraChip::Sx1262 => Ok(Self::Sx1262(Sx1262::open(config)?)),
        }
    }

    fn open_no_reset(config: &LoraConfig) -> Result<Self> {
        match config.chip {
            LoraChip::Sx127x => Ok(Self::Sx127x(Sx127x::open_no_reset(config)?)),
            LoraChip::Sx1262 => Ok(Self::Sx1262(Sx1262::open_no_reset(config)?)),
        }
    }

    fn configure_radio(&mut self) -> Result<()> {
        match self {
            Self::Sx127x(radio) => radio.configure_radio(),
            Self::Sx1262(radio) => radio.configure_radio(),
        }
    }

    fn send_packet(&mut self, payload: &[u8], timeout_ms: u32) -> Result<()> {
        match self {
            Self::Sx127x(radio) => radio.send_packet(payload, timeout_ms),
            Self::Sx1262(radio) => radio.send_packet(payload, timeout_ms),
        }
    }

    fn start_rx(&mut self) -> Result<()> {
        match self {
            Self::Sx127x(radio) => radio.start_rx(),
            Self::Sx1262(radio) => radio.start_rx(),
        }
    }

    fn start_background_rx_mode(&mut self) -> Result<RxDutyCycle> {
        if LORA_CAD_RX_ENABLED.load(Ordering::Relaxed) {
            if let Self::Sx1262(radio) = self {
                return radio.start_rx_duty_cycle_auto();
            }
        }
        self.start_rx()?;
        Ok(RxDutyCycle {
            rx_us: 0,
            sleep_us: 0,
        })
    }

    fn is_channel_active(&mut self, timeout: Duration) -> Result<bool> {
        match self {
            Self::Sx127x(radio) => radio.is_channel_active(timeout),
            Self::Sx1262(radio) => radio.is_channel_active(timeout),
        }
    }

    /// Perform up to `max_tries` CAD scans with exponential backoff.
    /// Returns `Ok(())` once the channel reads clear (CAD detected no
    /// signal) or returns `Err` if all attempts report activity. CAD
    /// errors are logged and treated as "channel clear" so a transient
    /// radio issue does not block the caller's TX indefinitely.
    fn ensure_channel_clear(&mut self, timeout: Duration, max_tries: u32) -> Result<()> {
        if max_tries == 0 {
            return Ok(());
        }
        let mut backoff_ms: u64 = 10;
        for attempt in 0..max_tries {
            LORA_CAD_SAMPLES.fetch_add(1, Ordering::Relaxed);
            match self.is_channel_active(timeout) {
                Ok(false) => return Ok(()),
                Ok(true) => {
                    LORA_CAD_DETECTED.fetch_add(1, Ordering::Relaxed);
                    if attempt + 1 >= max_tries {
                        bail!("LoRa channel busy after {max_tries} CAD attempts");
                    }
                    task_delay(Duration::from_millis(backoff_ms));
                    backoff_ms = backoff_ms.saturating_mul(2).min(200);
                    continue;
                }
                Err(err) => {
                    telemetry::record_log(format!(
                        "ev=lora.cad c=tx err={}",
                        crate::commands::protocol::escape_value(&err.to_string())
                    ));
                    return Ok(());
                }
            }
        }
        Ok(())
    }

    fn sleep(&mut self) -> Result<()> {
        match self {
            Self::Sx127x(radio) => radio.sleep(),
            Self::Sx1262(radio) => radio.sleep(),
        }
    }

    fn standby(&mut self) -> Result<()> {
        match self {
            Self::Sx127x(radio) => radio.standby(),
            // The SX1262 receive path uses hardware duty-cycle RX and does not
            // call this helper; keep a low-power fallback for completeness.
            Self::Sx1262(radio) => radio.sleep(),
        }
    }

    fn poll_packet(&mut self) -> Result<Option<Packet>> {
        match self {
            Self::Sx127x(radio) => radio.poll_packet(),
            Self::Sx1262(radio) => radio.poll_packet(),
        }
    }

    fn dump(&mut self) -> Result<String> {
        match self {
            Self::Sx127x(radio) => radio.dump(),
            Self::Sx1262(radio) => radio.dump(),
        }
    }

    fn configure_fsk(&mut self, config: FskConfig, frequency_hz: u32) -> Result<()> {
        match self {
            Self::Sx127x(radio) => radio.configure_fsk(config, frequency_hz),
            Self::Sx1262(radio) => radio.configure_fsk(config, frequency_hz),
        }
    }

    fn send_fsk(&mut self, payload: &[u8], timeout_ms: u32, preamble: u16) -> Result<()> {
        match self {
            Self::Sx127x(radio) => radio.send_fsk(payload, timeout_ms),
            Self::Sx1262(radio) => radio.send_fsk(payload, timeout_ms, preamble),
        }
    }

    fn start_fsk_rx(&mut self) -> Result<()> {
        match self {
            Self::Sx127x(radio) => radio.start_fsk_rx(),
            Self::Sx1262(radio) => radio.start_fsk_rx(),
        }
    }

    fn poll_fsk_packet(&mut self) -> Result<Option<Packet>> {
        match self {
            Self::Sx127x(radio) => radio.poll_fsk_packet(),
            Self::Sx1262(radio) => radio.poll_fsk_packet(),
        }
    }

    fn fsk_diagnostics(&mut self) -> Result<String> {
        match self {
            Self::Sx127x(radio) => radio.fsk_diagnostics(),
            Self::Sx1262(radio) => radio.fsk_diagnostics(),
        }
    }
}

impl Sx127x {
    fn open(config: &LoraConfig) -> Result<Self> {
        Self::open_inner(config, true)
    }

    fn open_no_reset(config: &LoraConfig) -> Result<Self> {
        Self::open_inner(config, false)
    }

    fn open_inner(config: &LoraConfig, reset: bool) -> Result<Self> {
        validate_config(config)?;
        let host = spi_host(config.spi_host)?;
        unsafe {
            let _ = sys::spi_bus_free(host);
        }

        let mut bus = sys::spi_bus_config_t::default();
        bus.sclk_io_num = config.sck;
        bus.max_transfer_sz = 256;
        unsafe {
            bus.__bindgen_anon_1.mosi_io_num = config.mosi;
            bus.__bindgen_anon_2.miso_io_num = config.miso;
            bus.__bindgen_anon_3.quadwp_io_num = sys::gpio_num_t_GPIO_NUM_NC;
            bus.__bindgen_anon_4.quadhd_io_num = sys::gpio_num_t_GPIO_NUM_NC;
            esp_ok(sys::spi_bus_initialize(
                host,
                &bus,
                sys::spi_common_dma_t_SPI_DMA_CH_AUTO,
            ))?;
        }

        let mut dev = sys::spi_device_interface_config_t::default();
        dev.clock_speed_hz = 1_000_000;
        dev.mode = 0;
        dev.spics_io_num = sys::gpio_num_t_GPIO_NUM_NC;
        dev.queue_size = 1;

        let mut handle = std::ptr::null_mut();
        unsafe {
            esp_ok(sys::spi_bus_add_device(host, &dev, &mut handle))?;
            configure_board_power(config)?;
            esp_ok(sys::gpio_set_direction(
                config.cs,
                sys::gpio_mode_t_GPIO_MODE_OUTPUT,
            ))?;
            esp_ok(sys::gpio_set_level(config.cs, 1))?;
            esp_ok(sys::gpio_set_direction(
                config.rst,
                sys::gpio_mode_t_GPIO_MODE_OUTPUT,
            ))?;
            esp_ok(sys::gpio_set_direction(
                config.dio0,
                sys::gpio_mode_t_GPIO_MODE_INPUT,
            ))?;
        }

        let mut radio = Self {
            config: config.clone(),
            host,
            handle,
        };
        if reset {
            radio.reset()?;
        }
        let version = radio.read_reg(REG_VERSION)?;
        if version != SX127X_VERSION {
            bail!("unexpected SX127x version 0x{version:02x}");
        }
        Ok(radio)
    }

    fn reset(&mut self) -> Result<()> {
        unsafe {
            esp_ok(sys::gpio_set_level(self.config.rst, 0))?;
        }
        task_delay(Duration::from_millis(10));
        unsafe {
            esp_ok(sys::gpio_set_level(self.config.rst, 1))?;
        }
        task_delay(Duration::from_millis(10));
        Ok(())
    }

    fn configure_radio(&mut self) -> Result<()> {
        self.write_reg(REG_OP_MODE, MODE_LONG_RANGE | MODE_SLEEP)?;
        self.set_frequency(self.config.frequency_hz)?;
        self.write_reg(REG_FIFO_TX_BASE_ADDR, 0)?;
        self.write_reg(REG_FIFO_RX_BASE_ADDR, 0)?;
        let lna = self.read_reg(REG_LNA)? | 0x03;
        self.write_reg(REG_LNA, lna)?;
        self.set_bandwidth(self.config.bandwidth_hz)?;
        self.set_spreading_factor(self.config.sf)?;
        self.set_coding_rate(self.config.cr)?;
        self.set_crc(self.config.crc)?;
        self.set_preamble(self.config.preamble as u16)?;
        self.write_reg(REG_SYNC_WORD, self.config.sync_word as u8)?;
        self.set_tx_power(self.config.tx_power)?;
        self.write_reg(REG_MODEM_CONFIG_3, 0x04)?;
        self.write_reg(REG_IRQ_FLAGS, 0xff)?;
        self.write_reg(REG_OP_MODE, MODE_LONG_RANGE | MODE_STDBY)?;
        Ok(())
    }

    fn configure_fsk(&mut self, config: FskConfig, frequency_hz: u32) -> Result<()> {
        // LongRangeMode can only be changed while the SX127x is asleep. Enter
        // LoRa sleep first, then clear the mode bit in a second transaction.
        // A single write to 0x00 can be ignored while LoRa is running, leaving
        // the overlapping register bank in LoRa mode.
        self.write_reg(REG_OP_MODE, MODE_LONG_RANGE | MODE_SLEEP)?;
        task_delay(Duration::from_millis(1));
        self.write_reg(REG_OP_MODE, MODE_SLEEP)?;
        task_delay(Duration::from_millis(1));
        let op_mode = self.read_reg(REG_OP_MODE)?;
        if op_mode & MODE_LONG_RANGE != 0 {
            bail!("SX127x refused FSK mode switch op_mode=0x{op_mode:02x}");
        }
        self.set_frequency(frequency_hz)?;
        // Fxosc / bitrate and fdev / (Fxosc / 2^19), Fxosc=32 MHz.
        let bitrate = (32_000_000_u32 / config.bitrate.max(1)).clamp(1, u16::MAX as u32) as u16;
        let deviation =
            ((config.deviation as u64 * (1 << 19)) / 32_000_000).clamp(1, u16::MAX as u64) as u16;
        self.write_reg(REG_FSK_BITRATE_MSB, (bitrate >> 8) as u8)?;
        self.write_reg(REG_FSK_BITRATE_LSB, bitrate as u8)?;
        self.write_reg(REG_FSK_FDEV_MSB, (deviation >> 8) as u8)?;
        self.write_reg(REG_FSK_FDEV_LSB, deviation as u8)?;
        // 0x01 selects a 250 kHz-ish RX/AFC bandwidth (mantissa 16, exp 1).
        // The current profile keeps this fixed until the radio command exposes
        // the SX127x bandwidth code directly.
        let _ = config.rx_bw;
        self.write_reg(REG_FSK_RX_BW, 0x01)?;
        self.write_reg(REG_FSK_AFC_BW, 0x01)?;
        self.write_reg(REG_FSK_PREAMBLE_MSB, (config.preamble >> 8) as u8)?;
        self.write_reg(REG_FSK_PREAMBLE_LSB, config.preamble as u8)?;
        // Enable the FSK preamble detector with the SX127x reference
        // qualification: two preamble bytes and a tolerance of ten chips.
        // Reset leaves this gate disabled, which lets RSSI rise without ever
        // advancing an SX126x packet to sync/payload reception.
        self.write_reg(REG_FSK_PREAMBLE_DETECT, 0xaa)?;
        // Use the SX127x default 0xAA preamble. SX126x GFSK uses this
        // standard polarity as well; setting PreamblePolarity would make the
        // SX127x receiver wait for 0x55 and miss SX126x transmitters. Bit 4
        // enables sync and bits 2:0 encode SyncSize - 1 for the two-byte
        // network ID.
        self.write_reg(REG_FSK_SYNC_CONFIG, 0x10 | 0x01)?;
        self.write_reg(REG_FSK_SYNC_VALUE_1, (config.network_id >> 8) as u8)?;
        self.write_reg(REG_FSK_SYNC_VALUE_1 + 1, config.network_id as u8)?;
        // Variable length, CCITT CRC, no whitening. SX127x standard
        // whitening is not wire-compatible with the SX126x GFSK seed path;
        // discovery frames are short and retain the sync-word and CRC filters.
        // PacketConfig2 bit 6 selects packet mode; the first FIFO byte is the
        // packet length.
        self.write_reg(REG_FSK_PACKET_CONFIG_1, 0x90)?;
        self.write_reg(REG_FSK_PACKET_CONFIG_2, 0x40)?;
        self.write_reg(REG_FSK_PAYLOAD_LENGTH, FSK_PACKET_MAX as u8)?;
        // Do not inherit the packet-engine state from the prior LoRa session.
        // Bit 7 makes TX begin when the FIFO is non-empty, which is essential
        // for short packets below the FIFO-level threshold. RX starts from
        // preamble detection with AFC and AGC enabled, matching Semtech's FSK
        // reference sequence.
        self.write_reg(REG_FSK_FIFO_THRESH, 0x80 | 0x0f)?;
        self.write_reg(REG_FSK_RX_CONFIG, 0x1e)?;
        self.set_tx_power(self.config.tx_power)?;
        // DIO0=PacketSent and DIO1=FifoEmpty in FSK TX mapping. We poll the
        // packet-sent flag, but selecting the correct FifoEmpty mapping keeps
        // the hardware sequencer in the reference packet-engine state.
        self.write_reg(REG_DIO_MAPPING_1, 0x10)?;
        self.write_reg(REG_OP_MODE, MODE_STDBY)
    }

    fn send_fsk(&mut self, payload: &[u8], timeout_ms: u32) -> Result<()> {
        if payload.is_empty() || payload.len() > FSK_PACKET_MAX {
            bail!("FSK payload length must be 1..={FSK_PACKET_MAX}");
        }
        self.write_reg(REG_OP_MODE, MODE_STDBY)?;
        // RegFifoAddrPtr (0x0d) only exists in the LoRa register bank. In
        // FSK it aliases RegRxConfig; do not touch it while filling the common
        // FIFO at address zero or the packet-engine receive sequencer changes.
        self.write_reg(REG_FIFO, payload.len() as u8)?;
        for byte in payload {
            self.write_reg(REG_FIFO, *byte)?;
        }
        // DIO0=PacketSent and DIO1=FifoEmpty for FSK TX.
        self.write_reg(REG_DIO_MAPPING_1, 0x10)?;
        self.write_reg(REG_OP_MODE, MODE_TX)?;
        let deadline = Instant::now() + Duration::from_millis(timeout_ms as u64);
        while Instant::now() < deadline {
            if self.read_reg(REG_FSK_IRQ_FLAGS_2)? & 0x08 != 0 {
                self.write_reg(REG_OP_MODE, MODE_STDBY)?;
                return Ok(());
            }
            task_delay(Duration::from_millis(2));
        }
        self.write_reg(REG_OP_MODE, MODE_STDBY)?;
        bail!(
            "FSK TX timeout op_mode=0x{:02x} irq2=0x{:02x} packet1=0x{:02x} packet2=0x{:02x}",
            self.read_reg(REG_OP_MODE)?,
            self.read_reg(REG_FSK_IRQ_FLAGS_2)?,
            self.read_reg(REG_FSK_PACKET_CONFIG_1)?,
            self.read_reg(REG_FSK_PACKET_CONFIG_2)?,
        )
    }

    fn start_fsk_rx(&mut self) -> Result<()> {
        // FSK reads its common FIFO from the current packet-engine position;
        // 0x0d is RegRxConfig in this bank, not a FIFO pointer.
        // DIO0=PayloadReady and DIO1=FifoLevel for FSK RX.
        self.write_reg(REG_DIO_MAPPING_1, 0x00)?;
        self.write_reg(REG_FSK_RX_CONFIG, 0x1e)?;
        self.write_reg(REG_OP_MODE, MODE_RX_CONTINUOUS)
    }

    fn poll_fsk_packet(&mut self) -> Result<Option<Packet>> {
        let irq2 = self.read_reg(REG_FSK_IRQ_FLAGS_2)?;
        if irq2 & 0x04 == 0 {
            return Ok(None);
        }
        let len = self.read_reg(REG_FIFO)? as usize;
        if len == 0 || len > FSK_PACKET_MAX {
            return Ok(None);
        }
        let mut data = Vec::with_capacity(len);
        for _ in 0..len {
            data.push(self.read_reg(REG_FIFO)?);
        }
        let rssi = -(self.read_reg(REG_FSK_RSSI_VALUE)? as i32) / 2;
        let _ = self.read_reg(REG_FSK_IRQ_FLAGS_1)?;
        Ok(Some(Packet {
            data,
            rssi,
            snr: 0.0,
        }))
    }

    fn fsk_diagnostics(&mut self) -> Result<String> {
        Ok(format!(
            "irq1=0x{:02x} irq2=0x{:02x}",
            self.read_reg(REG_FSK_IRQ_FLAGS_1)?,
            self.read_reg(REG_FSK_IRQ_FLAGS_2)?,
        ))
    }

    fn set_frequency(&mut self, hz: u32) -> Result<()> {
        let frf = ((hz as u64) << 19) / 32_000_000_u64;
        self.write_reg(REG_FRF_MSB, (frf >> 16) as u8)?;
        self.write_reg(REG_FRF_MID, (frf >> 8) as u8)?;
        self.write_reg(REG_FRF_LSB, frf as u8)
    }

    fn set_bandwidth(&mut self, hz: u32) -> Result<()> {
        let bw = match hz {
            7_800 => 0,
            10_400 => 1,
            15_600 => 2,
            20_800 => 3,
            31_250 => 4,
            41_700 => 5,
            62_500 => 6,
            125_000 => 7,
            250_000 => 8,
            500_000 => 9,
            _ => bail!("unsupported LoRa bandwidth {hz}"),
        };
        let current = self.read_reg(REG_MODEM_CONFIG_1)? & 0x0f;
        self.write_reg(REG_MODEM_CONFIG_1, (bw << 4) | current)
    }

    fn set_spreading_factor(&mut self, sf: i32) -> Result<()> {
        validate_sf(sf)?;
        if sf == 6 {
            self.write_reg(0x31, 0xc5)?;
            self.write_reg(0x37, 0x0c)?;
        } else {
            self.write_reg(0x31, 0xc3)?;
            self.write_reg(0x37, 0x0a)?;
        }
        let current = self.read_reg(REG_MODEM_CONFIG_2)? & 0x0f;
        self.write_reg(REG_MODEM_CONFIG_2, ((sf as u8) << 4) | current)
    }

    fn set_coding_rate(&mut self, cr: i32) -> Result<()> {
        validate_cr(cr)?;
        let current = self.read_reg(REG_MODEM_CONFIG_1)? & 0xf1;
        self.write_reg(REG_MODEM_CONFIG_1, current | (((cr - 4) as u8) << 1))
    }

    fn set_crc(&mut self, enable: bool) -> Result<()> {
        let current = self.read_reg(REG_MODEM_CONFIG_2)?;
        let value = if enable {
            current | 0x04
        } else {
            current & !0x04
        };
        self.write_reg(REG_MODEM_CONFIG_2, value)
    }

    fn set_preamble(&mut self, preamble: u16) -> Result<()> {
        self.write_reg(REG_PREAMBLE_MSB, (preamble >> 8) as u8)?;
        self.write_reg(REG_PREAMBLE_LSB, preamble as u8)
    }

    fn set_tx_power(&mut self, dbm: i32) -> Result<()> {
        validate_range("tx_power", dbm, 2, 20)?;
        let output = dbm.clamp(2, 17);
        self.write_reg(REG_PA_CONFIG, 0x80 | ((output - 2) as u8))
    }

    fn send_packet(&mut self, payload: &[u8], timeout_ms: u32) -> Result<()> {
        self.write_reg(REG_OP_MODE, MODE_LONG_RANGE | MODE_STDBY)?;
        self.write_reg(REG_FIFO_ADDR_PTR, 0)?;
        for byte in payload {
            self.write_reg(REG_FIFO, *byte)?;
        }
        self.write_reg(REG_PAYLOAD_LENGTH, payload.len() as u8)?;
        self.write_reg(REG_IRQ_FLAGS, 0xff)?;
        self.write_reg(REG_DIO_MAPPING_1, 0x40)?;
        self.write_reg(REG_OP_MODE, MODE_LONG_RANGE | MODE_TX)?;

        let deadline = Instant::now() + Duration::from_millis(timeout_ms as u64);
        while Instant::now() < deadline {
            let irq = self.read_reg(REG_IRQ_FLAGS)?;
            if irq & IRQ_TX_DONE != 0 {
                self.write_reg(REG_IRQ_FLAGS, IRQ_TX_DONE)?;
                self.write_reg(REG_OP_MODE, MODE_LONG_RANGE | MODE_STDBY)?;
                return Ok(());
            }
            task_delay(Duration::from_millis(5));
        }
        bail!("LoRa TX timeout");
    }

    fn start_rx(&mut self) -> Result<()> {
        self.write_reg(REG_FIFO_ADDR_PTR, 0)?;
        self.write_reg(REG_IRQ_FLAGS, 0xff)?;
        self.write_reg(REG_DIO_MAPPING_1, 0x00)?;
        self.write_reg(REG_OP_MODE, MODE_LONG_RANGE | MODE_RX_CONTINUOUS)
    }

    fn is_channel_active(&mut self, timeout: Duration) -> Result<bool> {
        // Discard command/task notifications left from the previous cycle;
        // DIO0 will provide the next CAD completion notification.
        let _ = wait_for_lora_irq(self.config.dio0, Duration::ZERO);
        self.write_reg(REG_OP_MODE, MODE_LONG_RANGE | MODE_STDBY)?;
        self.write_reg(REG_IRQ_FLAGS, 0xff)?;
        // SX127x RegDioMapping1 bits 7:6 = 10 maps DIO0 to CadDone.
        self.write_reg(REG_DIO_MAPPING_1, 0x80)?;
        self.write_reg(REG_OP_MODE, MODE_LONG_RANGE | MODE_CAD)?;

        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() || !wait_for_lora_irq(self.config.dio0, remaining) {
                break;
            }
            let irq = self.read_reg(REG_IRQ_FLAGS)?;
            if irq & IRQ_CAD_DONE != 0 {
                self.write_reg(REG_IRQ_FLAGS, irq)?;
                self.write_reg(REG_OP_MODE, MODE_LONG_RANGE | MODE_STDBY)?;
                return Ok(irq & IRQ_CAD_DETECTED != 0);
            }
        }

        self.write_reg(REG_OP_MODE, MODE_LONG_RANGE | MODE_STDBY)?;
        bail!("SX127x CAD timeout after {} ms", timeout.as_millis())
    }

    fn sleep(&mut self) -> Result<()> {
        self.write_reg(REG_OP_MODE, MODE_LONG_RANGE | MODE_SLEEP)
    }

    fn standby(&mut self) -> Result<()> {
        self.write_reg(REG_OP_MODE, MODE_LONG_RANGE | MODE_STDBY)
    }

    fn poll_packet(&mut self) -> Result<Option<Packet>> {
        let irq = self.read_reg(REG_IRQ_FLAGS)?;
        if irq & IRQ_RX_DONE == 0 {
            return Ok(None);
        }
        self.write_reg(REG_IRQ_FLAGS, irq)?;
        if irq & IRQ_PAYLOAD_CRC_ERROR != 0 {
            return Ok(None);
        }
        let len = self.read_reg(REG_RX_NB_BYTES)? as usize;
        let current = self.read_reg(REG_FIFO_RX_CURRENT_ADDR)?;
        self.write_reg(REG_FIFO_ADDR_PTR, current)?;
        let mut data = Vec::with_capacity(len);
        for _ in 0..len {
            data.push(self.read_reg(REG_FIFO)?);
        }
        let snr = (self.read_reg(REG_PKT_SNR_VALUE)? as i8) as f32 / 4.0;
        let rssi = self.read_reg(REG_PKT_RSSI_VALUE)? as i32 - 164;
        Ok(Some(Packet { data, rssi, snr }))
    }

    fn dump(&mut self) -> Result<String> {
        let mut regs = Vec::new();
        let mut values = [0_u8; 0x50];
        for reg in 0x00_u8..=0x4f {
            let value = self.read_reg(reg)?;
            values[reg as usize] = value;
            regs.push(format!("{reg:02x}:{value:02x}"));
        }
        Ok(format!(
            "chip=sx127x {} regs={}",
            decode_registers(&values),
            regs.join(" ")
        ))
    }

    fn read_reg(&mut self, reg: u8) -> Result<u8> {
        let mut rx = [0_u8; 2];
        self.spi(&[reg & 0x7f, 0], &mut rx)?;
        Ok(rx[1])
    }

    fn write_reg(&mut self, reg: u8, value: u8) -> Result<()> {
        let mut rx = [0_u8; 2];
        self.spi(&[reg | 0x80, value], &mut rx)
    }

    fn spi(&mut self, tx: &[u8], rx: &mut [u8]) -> Result<()> {
        if tx.len() != rx.len() {
            bail!("spi tx/rx length mismatch");
        }
        let mut transaction = sys::spi_transaction_t::default();
        transaction.length = tx.len() * 8;
        unsafe {
            transaction.__bindgen_anon_1.tx_buffer = tx.as_ptr() as *const _;
            transaction.__bindgen_anon_2.rx_buffer = rx.as_mut_ptr() as *mut _;
            esp_ok(sys::gpio_set_level(self.config.cs, 0))?;
            let ret = sys::spi_device_transmit(self.handle, &mut transaction);
            let cs_ret = sys::gpio_set_level(self.config.cs, 1);
            esp_ok(ret)?;
            esp_ok(cs_ret)?;
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct WakePacket {
    pub data: Vec<u8>,
    pub rssi: i32,
    pub snr: f32,
}

pub fn prepare_deep_sleep_rx(config: &LoraConfig) -> Result<()> {
    let mut radio = Radio::open(config)?;
    radio.configure_radio()?;
    radio.start_rx()
}

pub fn read_wake_packet_no_reset(config: &LoraConfig) -> Result<Option<WakePacket>> {
    let mut radio = Radio::open_no_reset(config)?;
    Ok(radio.poll_packet()?.map(|packet| WakePacket {
        data: packet.data,
        rssi: packet.rssi,
        snr: packet.snr,
    }))
}

impl Drop for Sx127x {
    fn drop(&mut self) {
        unsafe {
            if !self.handle.is_null() {
                let _ = sys::spi_bus_remove_device(self.handle);
            }
            let _ = sys::spi_bus_free(self.host);
        }
    }
}

const SX126X_CMD_SET_SLEEP: u8 = 0x84;
const SX126X_CMD_SET_STANDBY: u8 = 0x80;
const SX126X_CMD_SET_TX: u8 = 0x83;
const SX126X_CMD_SET_RX: u8 = 0x82;
const SX126X_CMD_SET_RX_DUTY_CYCLE: u8 = 0x94;
const SX126X_CMD_SET_PACKET_TYPE: u8 = 0x8a;
const SX126X_CMD_GET_PACKET_TYPE: u8 = 0x11;
const SX126X_CMD_SET_RF_FREQUENCY: u8 = 0x86;
const SX126X_CMD_SET_PA_CONFIG: u8 = 0x95;
const SX126X_CMD_SET_TX_PARAMS: u8 = 0x8e;
const SX126X_CMD_SET_BUFFER_BASE_ADDRESS: u8 = 0x8f;
const SX126X_CMD_SET_MODULATION_PARAMS: u8 = 0x8b;
const SX126X_CMD_SET_PACKET_PARAMS: u8 = 0x8c;
const SX126X_CMD_SET_DIO_IRQ_PARAMS: u8 = 0x08;
const SX126X_CMD_GET_IRQ_STATUS: u8 = 0x12;
const SX126X_CMD_CLEAR_IRQ_STATUS: u8 = 0x02;
const SX126X_CMD_SET_DIO2_AS_RF_SWITCH: u8 = 0x9d;
const SX126X_CMD_SET_DIO3_AS_TCXO_CTRL: u8 = 0x97;
const SX126X_CMD_CALIBRATE: u8 = 0x89;
const SX126X_CMD_CALIBRATE_IMAGE: u8 = 0x98;
const SX126X_CMD_SET_RX_TX_FALLBACK_MODE: u8 = 0x93;
const SX126X_CMD_SET_REGULATOR_MODE: u8 = 0x96;
const SX126X_CMD_WRITE_REGISTER: u8 = 0x0d;
const SX126X_CMD_READ_REGISTER: u8 = 0x1d;
const SX126X_CMD_GET_STATUS: u8 = 0xc0;
const SX126X_CMD_GET_RX_BUFFER_STATUS: u8 = 0x13;
const SX126X_CMD_GET_PACKET_STATUS: u8 = 0x14;
const SX126X_CMD_WRITE_BUFFER: u8 = 0x0e;
const SX126X_CMD_READ_BUFFER: u8 = 0x1e;
const SX126X_CMD_SET_CAD_PARAMS: u8 = 0x88;
const SX126X_CMD_SET_CAD: u8 = 0xc5;

const SX126X_PACKET_TYPE_LORA: u8 = 0x01;
const SX126X_PACKET_TYPE_GFSK: u8 = 0x00;
const SX126X_STANDBY_RC: u8 = 0x00;
const SX126X_RAMP_200_US: u8 = 0x04;
const SX126X_IRQ_TX_DONE: u16 = 0x0001;
const SX126X_IRQ_RX_DONE: u16 = 0x0002;
const SX126X_IRQ_CRC_ERR: u16 = 0x0040;
const SX126X_IRQ_CAD_DONE: u16 = 0x0080;
const SX126X_IRQ_CAD_DETECTED: u16 = 0x0100;
const SX126X_IRQ_TIMEOUT: u16 = 0x0200;
const SX126X_REG_SYNC_WORD: u16 = 0x0740;
const SX126X_REG_GFSK_SYNC_WORD: u16 = 0x06c0;
const SX126X_REG_OCP: u16 = 0x08e7;
const SX126X_REG_TX_CLAMP_CONFIG: u16 = 0x08d8;
const SX126X_REG_RX_GAIN: u16 = 0x08ac;
const SX126X_REG_RX_SENSITIVITY: u16 = 0x08b5;

#[derive(Clone, Copy, Debug)]
struct RxDutyCycle {
    rx_us: u32,
    sleep_us: u32,
}

struct Sx1262 {
    config: LoraConfig,
    host: sys::spi_host_device_t,
    handle: sys::spi_device_handle_t,
}

impl Sx1262 {
    fn open(config: &LoraConfig) -> Result<Self> {
        Self::open_inner(config, true)
    }

    fn open_no_reset(config: &LoraConfig) -> Result<Self> {
        Self::open_inner(config, false)
    }

    fn open_inner(config: &LoraConfig, reset: bool) -> Result<Self> {
        validate_config(config)?;
        let host = spi_host(config.spi_host)?;
        unsafe {
            let _ = sys::spi_bus_free(host);
        }

        let mut bus = sys::spi_bus_config_t::default();
        bus.sclk_io_num = config.sck;
        bus.max_transfer_sz = 512;
        unsafe {
            bus.__bindgen_anon_1.mosi_io_num = config.mosi;
            bus.__bindgen_anon_2.miso_io_num = config.miso;
            bus.__bindgen_anon_3.quadwp_io_num = sys::gpio_num_t_GPIO_NUM_NC;
            bus.__bindgen_anon_4.quadhd_io_num = sys::gpio_num_t_GPIO_NUM_NC;
            esp_ok(sys::spi_bus_initialize(
                host,
                &bus,
                sys::spi_common_dma_t_SPI_DMA_CH_AUTO,
            ))?;
        }

        let mut dev = sys::spi_device_interface_config_t::default();
        dev.clock_speed_hz = 1_000_000;
        dev.mode = 0;
        dev.spics_io_num = sys::gpio_num_t_GPIO_NUM_NC;
        dev.queue_size = 1;

        let mut handle = std::ptr::null_mut();
        unsafe {
            esp_ok(sys::spi_bus_add_device(host, &dev, &mut handle))?;
            configure_board_power(config)?;
            esp_ok(sys::gpio_set_direction(
                config.cs,
                sys::gpio_mode_t_GPIO_MODE_OUTPUT,
            ))?;
            esp_ok(sys::gpio_set_level(config.cs, 1))?;
            esp_ok(sys::gpio_set_direction(
                config.rst,
                sys::gpio_mode_t_GPIO_MODE_OUTPUT,
            ))?;
            esp_ok(sys::gpio_set_direction(
                config.dio0,
                sys::gpio_mode_t_GPIO_MODE_INPUT,
            ))?;
            esp_ok(sys::gpio_set_direction(
                config.busy,
                sys::gpio_mode_t_GPIO_MODE_INPUT,
            ))?;
        }

        let mut radio = Self {
            config: *config,
            host,
            handle,
        };
        if reset {
            cycle_board_power(config)?;
            radio.reset()?;
            radio.set_standby()?;
        }
        let status = radio.status()?;
        if status == 0x00 || status == 0xff {
            bail!("unexpected SX1262 status 0x{status:02x}");
        }
        Ok(radio)
    }

    fn reset(&mut self) -> Result<()> {
        unsafe {
            esp_ok(sys::gpio_set_level(self.config.rst, 0))?;
        }
        task_delay(Duration::from_millis(10));
        unsafe {
            esp_ok(sys::gpio_set_level(self.config.rst, 1))?;
        }
        task_delay(Duration::from_millis(20));
        self.wait_while_busy(Duration::from_millis(500))
    }

    fn configure_radio(&mut self) -> Result<()> {
        self.set_standby()?;
        self.command(SX126X_CMD_SET_REGULATOR_MODE, &[0x01])?;
        if self.config.sx1262_tcxo_mv > 0 {
            self.set_tcxo(self.config.sx1262_tcxo_mv)?;
            task_delay(Duration::from_millis(5));
        }
        self.calibrate_902_928mhz()?;
        self.configure_common_fallback()?;
        if self.config.sx1262_dio2_rf_switch {
            self.command(SX126X_CMD_SET_DIO2_AS_RF_SWITCH, &[0x01])?;
        }
        self.command(SX126X_CMD_SET_PACKET_TYPE, &[SX126X_PACKET_TYPE_LORA])?;
        self.set_frequency(self.config.frequency_hz)?;
        self.command(
            SX126X_CMD_SET_PA_CONFIG,
            &[
                self.config.sx1262_pa_duty as u8,
                self.config.sx1262_pa_hp as u8,
                self.config.sx1262_pa_device as u8,
                self.config.sx1262_pa_lut as u8,
            ],
        )?;
        self.command(
            SX126X_CMD_SET_TX_PARAMS,
            &[
                self.config.tx_power.clamp(-9, 22) as i8 as u8,
                SX126X_RAMP_200_US,
            ],
        )?;
        self.set_current_limit_140ma()?;
        self.command(SX126X_CMD_SET_BUFFER_BASE_ADDRESS, &[0x00, 0x80])?;
        self.set_modulation_params()?;
        self.set_sync_word(sx1262_sync_word(&self.config))?;
        self.set_packet_params(255)?;
        self.set_rx_boosted_gain(true)?;
        self.apply_rx_sensitivity_patch()?;
        self.set_irq_mask(
            SX126X_IRQ_TX_DONE | SX126X_IRQ_RX_DONE | SX126X_IRQ_CRC_ERR | SX126X_IRQ_TIMEOUT,
        )?;
        self.clear_irq(0xffff)?;
        Ok(())
    }

    /// Configure the SX126x GFSK packet engine. This is intentionally kept
    /// separate from the LoRa helpers: packet type changes the meanings of
    /// SetModulationParams, SetPacketParams, packet status, and the sync-word
    /// register range.
    fn configure_fsk(&mut self, config: FskConfig, frequency_hz: u32) -> Result<()> {
        self.set_standby()?;
        self.command(SX126X_CMD_SET_REGULATOR_MODE, &[0x01])?;
        if self.config.sx1262_tcxo_mv > 0 {
            self.set_tcxo(self.config.sx1262_tcxo_mv)?;
            task_delay(Duration::from_millis(5));
        }
        self.calibrate_902_928mhz()?;
        self.configure_common_fallback()?;
        if self.config.sx1262_dio2_rf_switch {
            self.command(SX126X_CMD_SET_DIO2_AS_RF_SWITCH, &[0x01])?;
        }
        self.command(SX126X_CMD_SET_PACKET_TYPE, &[SX126X_PACKET_TYPE_GFSK])?;
        self.set_frequency(frequency_hz)?;
        self.command(
            SX126X_CMD_SET_PA_CONFIG,
            &[
                self.config.sx1262_pa_duty as u8,
                self.config.sx1262_pa_hp as u8,
                self.config.sx1262_pa_device as u8,
                self.config.sx1262_pa_lut as u8,
            ],
        )?;
        self.command(
            SX126X_CMD_SET_TX_PARAMS,
            &[
                self.config.tx_power.clamp(-9, 22) as i8 as u8,
                SX126X_RAMP_200_US,
            ],
        )?;
        // Keep GFSK TX power-stage setup identical to the normal LoRa path.
        // The reset OCP setting is not a valid production transmit default.
        self.set_current_limit_140ma()?;
        self.command(SX126X_CMD_SET_BUFFER_BASE_ADDRESS, &[0x00, 0x80])?;
        self.set_fsk_modulation_params(config)?;
        self.write_register(
            SX126X_REG_GFSK_SYNC_WORD,
            &[(config.network_id >> 8) as u8, config.network_id as u8],
        )?;
        // In variable packet mode the SX126x hardware length field must use
        // its full 255-byte maximum. Keep FSK_PACKET_MAX as the application
        // acceptance limit after a packet is read; using 128 here caused
        // valid SX127x variable packets to raise PacketLengthError.
        self.set_fsk_packet_params(u8::MAX, config.preamble)?;
        // GFSK receive uses the same analog front end as LoRa. Apply the
        // documented boosted-gain and sensitivity settings before a bounded
        // FSK listen session, matching the normal receive path.
        self.set_rx_boosted_gain(true)?;
        self.apply_rx_sensitivity_patch()?;
        self.set_irq_mask(
            SX126X_IRQ_TX_DONE | SX126X_IRQ_RX_DONE | SX126X_IRQ_CRC_ERR | SX126X_IRQ_TIMEOUT,
        )?;
        self.clear_irq(0xffff)
    }

    fn set_fsk_modulation_params(&mut self, config: FskConfig) -> Result<()> {
        // SetModulationParams(GFSK): bitrate(raw 24 bit), pulse shaping,
        // RX bandwidth, frequency deviation(raw 24 bit). Raw units are
        // 32 * 32 MHz / bitrate and frequency * 2^25 / 32 MHz respectively.
        // Unlike SX127x, SX126x encodes the requested bitrate with an extra
        // factor of 32. Omitting it changes the 100 kbps profile into 3.2 Mbps.
        let bitrate =
            ((32_u64 * 32_000_000) / config.bitrate.max(1) as u64).clamp(1, 0x00ff_ffff) as u32;
        let deviation =
            ((config.deviation as u64 * (1 << 25)) / 32_000_000).clamp(1, 0x00ff_ffff) as u32;
        // Semtech uses a non-linear GFSK Rx-bandwidth selector. Keep this
        // table explicit: these values are not the LoRa bandwidth selectors.
        let bandwidth = match config.rx_bw {
            0..=78_200 => 0x1b,        // 78.2 kHz
            78_201..=93_800 => 0x13,   // 93.8 kHz
            93_801..=117_300 => 0x0b,  // 117.3 kHz
            117_301..=156_200 => 0x1a, // 156.2 kHz
            156_201..=187_200 => 0x12, // 187.2 kHz
            187_201..=234_300 => 0x0a, // 234.3 kHz
            234_301..=312_000 => 0x19, // 312.0 kHz
            312_001..=373_600 => 0x11, // 373.6 kHz
            _ => 0x09,                 // 467.0 kHz
        };
        self.command(
            SX126X_CMD_SET_MODULATION_PARAMS,
            &[
                (bitrate >> 16) as u8,
                (bitrate >> 8) as u8,
                bitrate as u8,
                0x00, // no shaping; matches the SX127x FSK default
                bandwidth,
                (deviation >> 16) as u8,
                (deviation >> 8) as u8,
                deviation as u8,
            ],
        )
    }

    fn set_fsk_packet_params(&mut self, payload_len: u8, preamble_bytes: u16) -> Result<()> {
        // The shared FSK profile defines preamble in bytes, matching SX127x.
        // SX126x SetPacketParams instead takes its GFSK preamble length in
        // bits. Sending `16` directly emitted only a two-byte preamble: the
        // SX126x could receive the longer SX127x preamble with its detector
        // disabled, but SX127x never detected the SX126x transmission.
        let preamble_bits = preamble_bytes.saturating_mul(8);
        // Variable length, 16-bit sync word, CRC-CCITT, and no whitening.
        // Leave the SX126x preamble detector ungated for SX127x interop. The
        // SX127x preamble shape can otherwise enter SX126x packet recovery at
        // a different phase and produce a false CRC error; sync and CRC still
        // gate packet delivery.
        self.command(
            SX126X_CMD_SET_PACKET_PARAMS,
            &[
                (preamble_bits >> 8) as u8,
                preamble_bits as u8,
                0x00,
                16,
                0x00,
                0x01, // variable packet: hardware adds/consumes the length byte
                payload_len,
                0x06,
                0x00,
            ],
        )
    }

    fn set_standby(&mut self) -> Result<()> {
        self.command(SX126X_CMD_SET_STANDBY, &[SX126X_STANDBY_RC])
    }

    fn calibrate_902_928mhz(&mut self) -> Result<()> {
        // SX126x reset leaves analog blocks and image rejection uncalibrated.
        // Both the normal LoRa and GFSK paths operate in US915 for now.
        self.command(SX126X_CMD_CALIBRATE, &[0x7f])?;
        self.command(SX126X_CMD_CALIBRATE_IMAGE, &[0xe1, 0xe9])
    }

    fn configure_common_fallback(&mut self) -> Result<()> {
        self.command(SX126X_CMD_SET_RX_TX_FALLBACK_MODE, &[0x20])?;
        // SX1262 datasheet, known limitation 15.2: relax the PA clamp after
        // reset. Without it an otherwise-valid GFSK TX can remain in TX state
        // instead of completing.
        let clamp = self.read_register(SX126X_REG_TX_CLAMP_CONFIG, 1)?[0] | 0x1e;
        self.write_register(SX126X_REG_TX_CLAMP_CONFIG, &[clamp])
    }

    fn set_frequency(&mut self, hz: u32) -> Result<()> {
        let rf = ((hz as u64) << 25) / 32_000_000_u64;
        self.command(
            SX126X_CMD_SET_RF_FREQUENCY,
            &[
                (rf >> 24) as u8,
                (rf >> 16) as u8,
                (rf >> 8) as u8,
                rf as u8,
            ],
        )
    }

    fn set_tcxo(&mut self, millivolts: i32) -> Result<()> {
        let voltage = match millivolts {
            0 => return Ok(()),
            1500 => 0x00,
            1600 => 0x01,
            1700 => 0x02,
            1800 => 0x03,
            2200 => 0x04,
            2400 => 0x05,
            2700 => 0x06,
            3000 => 0x07,
            value => bail!("unsupported SX1262 TCXO voltage {value}mV"),
        };
        self.command(
            SX126X_CMD_SET_DIO3_AS_TCXO_CTRL,
            &[voltage, 0x00, 0x03, 0x20],
        )
    }

    fn set_sync_word(&mut self, sync_word: u16) -> Result<()> {
        self.write_register(
            SX126X_REG_SYNC_WORD,
            &[(sync_word >> 8) as u8, sync_word as u8],
        )
    }

    fn set_current_limit_140ma(&mut self) -> Result<()> {
        self.write_register(SX126X_REG_OCP, &[0x38])
    }

    fn set_rx_boosted_gain(&mut self, boosted: bool) -> Result<()> {
        self.write_register(SX126X_REG_RX_GAIN, &[if boosted { 0x96 } else { 0x94 }])
    }

    fn apply_rx_sensitivity_patch(&mut self) -> Result<()> {
        let value = self.read_register(SX126X_REG_RX_SENSITIVITY, 1)?[0] | 0x01;
        self.write_register(SX126X_REG_RX_SENSITIVITY, &[value])
    }

    fn set_modulation_params(&mut self) -> Result<()> {
        let bw = match self.config.bandwidth_hz {
            7_800 => 0x00,
            10_400 => 0x08,
            15_600 => 0x01,
            20_800 => 0x09,
            31_250 => 0x02,
            41_700 => 0x0a,
            62_500 => 0x03,
            125_000 => 0x04,
            250_000 => 0x05,
            500_000 => 0x06,
            hz => bail!("unsupported SX1262 LoRa bandwidth {hz}"),
        };
        let cr = (self.config.cr - 4).clamp(1, 4) as u8;
        let ldro = if symbol_time_ms(self.config.bandwidth_hz, self.config.sf) >= 16 {
            1
        } else {
            0
        };
        self.command(
            SX126X_CMD_SET_MODULATION_PARAMS,
            &[self.config.sf as u8, bw, cr, ldro],
        )
    }

    fn set_packet_params(&mut self, payload_len: u8) -> Result<()> {
        self.command(
            SX126X_CMD_SET_PACKET_PARAMS,
            &[
                (self.config.preamble >> 8) as u8,
                self.config.preamble as u8,
                0x00,
                payload_len,
                if self.config.crc { 0x01 } else { 0x00 },
                0x00,
            ],
        )
    }

    fn set_irq_mask(&mut self, mask: u16) -> Result<()> {
        // SX126x has a single board interrupt in this firmware: route every
        // enabled radio IRQ to DIO1. `LoraConfig::dio0` is the legacy setting
        // name for that board GPIO, shared with SX127x DIO0.
        let dio1 = mask;
        self.command(
            SX126X_CMD_SET_DIO_IRQ_PARAMS,
            &[
                (mask >> 8) as u8,
                mask as u8,
                (dio1 >> 8) as u8,
                dio1 as u8,
                0,
                0,
                0,
                0,
            ],
        )
    }

    fn send_packet(&mut self, payload: &[u8], timeout_ms: u32) -> Result<()> {
        if payload.len() > 255 {
            bail!("SX1262 payload too large: {}", payload.len());
        }
        self.set_standby()?;
        self.set_packet_params(payload.len() as u8)?;
        self.write_buffer(0, payload)?;
        self.clear_irq(0xffff)?;
        let timeout = sx126x_timeout(timeout_ms);
        self.command(
            SX126X_CMD_SET_TX,
            &[(timeout >> 16) as u8, (timeout >> 8) as u8, timeout as u8],
        )?;

        let deadline = Instant::now() + Duration::from_millis(timeout_ms as u64);
        while Instant::now() < deadline {
            let irq = self.irq_status()?;
            if irq & SX126X_IRQ_TX_DONE != 0 {
                self.clear_irq(irq)?;
                self.set_standby()?;
                return Ok(());
            }
            if irq & SX126X_IRQ_TIMEOUT != 0 {
                self.clear_irq(irq)?;
                bail!("SX1262 TX timeout");
            }
            task_delay(Duration::from_millis(5));
        }
        bail!("SX1262 TX timeout");
    }

    fn send_fsk(&mut self, payload: &[u8], timeout_ms: u32, preamble: u16) -> Result<()> {
        if payload.is_empty() || payload.len() > FSK_PACKET_MAX {
            bail!("FSK payload length must be 1..={FSK_PACKET_MAX}");
        }
        self.set_standby()?;
        // For SX126x GFSK the payload length in SetPacketParams is used by
        // the transmitter, including variable-length packets. Leaving the
        // receive-side maximum (255) here makes a short TX read past the
        // supplied FIFO payload and eventually time out.
        self.set_fsk_packet_params(payload.len() as u8, preamble)?;
        self.write_buffer(0, payload)?;
        self.clear_irq(0xffff)?;
        let timeout = sx126x_timeout(timeout_ms);
        self.command(
            SX126X_CMD_SET_TX,
            &[(timeout >> 16) as u8, (timeout >> 8) as u8, timeout as u8],
        )?;
        let deadline = Instant::now() + Duration::from_millis(timeout_ms as u64);
        let mut last_irq = 0_u16;
        while Instant::now() < deadline {
            let irq = self.irq_status()?;
            last_irq = irq;
            if irq & SX126X_IRQ_TX_DONE != 0 {
                self.clear_irq(irq)?;
                self.set_standby()?;
                return Ok(());
            }
            if irq & SX126X_IRQ_TIMEOUT != 0 {
                self.clear_irq(irq)?;
                bail!("SX1262 FSK TX timeout");
            }
            task_delay(Duration::from_millis(2));
        }
        bail!(
            "SX1262 FSK TX timeout irq=0x{last_irq:04x} status=0x{:02x} packet_type=0x{:02x}",
            self.status()?,
            self.read_u8(SX126X_CMD_GET_PACKET_TYPE)?,
        )
    }

    fn start_rx(&mut self) -> Result<()> {
        self.set_standby()?;
        self.set_packet_params(255)?;
        self.clear_irq(0xffff)?;
        let timeout = sx126x_rx_timeout(self.config.sx1262_rx_timeout_ms);
        self.command(
            SX126X_CMD_SET_RX,
            &[(timeout >> 16) as u8, (timeout >> 8) as u8, timeout as u8],
        )
    }

    fn start_fsk_rx(&mut self) -> Result<()> {
        self.set_standby()?;
        self.set_fsk_packet_params(u8::MAX, 16)?;
        self.clear_irq(0xffff)?;
        // 0xFFFFFF is the SX126x continuous-RX timeout.
        self.command(SX126X_CMD_SET_RX, &[0xff, 0xff, 0xff])
    }

    fn start_rx_duty_cycle_auto(&mut self) -> Result<RxDutyCycle> {
        const MIN_SYMBOLS: u32 = 8;
        let symbol_us = symbol_time_us(self.config.bandwidth_hz, self.config.sf);
        let preamble_symbols = self.config.preamble.max(MIN_SYMBOLS as i32 + 1) as u32;
        let rx_us = symbol_us
            .saturating_mul(MIN_SYMBOLS)
            .saturating_add(2_000)
            .max(1_000);
        let sleep_symbols = preamble_symbols.saturating_sub(MIN_SYMBOLS).max(1);
        let sleep_us = symbol_us
            .saturating_mul(sleep_symbols)
            .saturating_add(sx1262_transition_us(self.config.sx1262_tcxo_mv));
        if sleep_us < sx1262_transition_us(self.config.sx1262_tcxo_mv).saturating_add(1_016) {
            self.start_rx()?;
            return Ok(RxDutyCycle {
                rx_us: 0,
                sleep_us: 0,
            });
        }
        self.start_rx_duty_cycle(rx_us, sleep_us)?;
        Ok(RxDutyCycle { rx_us, sleep_us })
    }

    fn start_rx_duty_cycle(&mut self, rx_us: u32, sleep_us: u32) -> Result<()> {
        self.set_standby()?;
        self.set_packet_params(255)?;
        // Map packet completion/error to DIO1. Do not map RX timeout: in
        // duty-cycle mode timeout is an internal cadence event and would wake
        // the ESP task continuously.
        self.set_irq_mask(SX126X_IRQ_RX_DONE | SX126X_IRQ_CRC_ERR)?;
        self.clear_irq(0xffff)?;
        let transition_us = sx1262_transition_us(self.config.sx1262_tcxo_mv);
        let adjusted_sleep_us = sleep_us
            .checked_sub(transition_us)
            .context("SX1262 duty-cycle sleep period is shorter than transition time")?;
        let rx_raw = sx126x_duty_cycle_period(rx_us)?;
        let sleep_raw = sx126x_duty_cycle_period(adjusted_sleep_us)?;
        self.command(
            SX126X_CMD_SET_RX_DUTY_CYCLE,
            &[
                (rx_raw >> 16) as u8,
                (rx_raw >> 8) as u8,
                rx_raw as u8,
                (sleep_raw >> 16) as u8,
                (sleep_raw >> 8) as u8,
                sleep_raw as u8,
            ],
        )
    }

    fn sleep(&mut self) -> Result<()> {
        self.command(SX126X_CMD_SET_SLEEP, &[0x00])
    }

    /// Detect LoRa activity via a single Channel Activity Detection
    /// (CAD) cycle. The radio is placed in CAD-only mode (`CadExitMode = 0`),
    /// polls `IRQ_CAD_DONE`, and returns whether a preamble was seen.
    /// Radio is left in STDBY on return.
    fn is_channel_active(&mut self, timeout: Duration) -> Result<bool> {
        self.set_standby()?;
        self.set_cad_params()?;
        self.clear_irq(0xffff)?;
        self.command(SX126X_CMD_SET_CAD, &[])?;
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            let irq = self.irq_status()?;
            if irq & SX126X_IRQ_CAD_DONE != 0 {
                let detected = irq & SX126X_IRQ_CAD_DETECTED != 0;
                self.clear_irq(irq)?;
                self.set_standby()?;
                return Ok(detected);
            }
            task_delay(Duration::from_millis(1));
        }
        self.set_standby()?;
        bail!("SX1262 CAD timeout after {} ms", timeout.as_millis())
    }

    /// Configure `SetCadParams` based on the configured spreading factor.
    /// `CadDetPeak` follows the Semtech calibration table for SX126x:
    ///   SF6..SF8 -> 0x40, SF9 -> 0x44, SF10 -> 0x46, SF11/12 -> 0x50.
    /// `CadExitMode = 0` keeps the radio in STDBY after CAD so the caller
    /// can decide whether to enter RX.
    fn set_cad_params(&mut self) -> Result<()> {
        let peak = match self.config.sf {
            6 => 0x40_u8,
            7 => 0x40,
            8 => 0x40,
            9 => 0x44,
            10 => 0x46,
            11 => 0x50,
            12 => 0x50,
            _ => 0x44,
        };
        // CadDetMin, CadExitMode (0=CAD-only), CadTimeout (3 bytes, unused in CAD-only mode)
        self.command(
            SX126X_CMD_SET_CAD_PARAMS,
            &[peak, 0x10, 0x00, 0x00, 0x00, 0x00],
        )
    }

    fn poll_packet(&mut self) -> Result<Option<Packet>> {
        let irq = self.irq_status()?;
        if irq & SX126X_IRQ_RX_DONE == 0 {
            return Ok(None);
        }
        self.clear_irq(irq)?;
        if irq & SX126X_IRQ_CRC_ERR != 0 {
            return Ok(None);
        }
        let (len, offset) = self.rx_buffer_status()?;
        let data = self.read_buffer(offset, len)?;
        let (rssi, snr) = self.packet_status()?;
        Ok(Some(Packet { data, rssi, snr }))
    }

    fn poll_fsk_packet(&mut self) -> Result<Option<Packet>> {
        let irq = self.irq_status()?;
        if irq & SX126X_IRQ_RX_DONE == 0 {
            return Ok(None);
        }
        self.clear_irq(irq)?;
        if irq & SX126X_IRQ_CRC_ERR != 0 {
            return Ok(None);
        }
        let (len, offset) = self.rx_buffer_status()?;
        if len == 0 || len as usize > FSK_PACKET_MAX {
            return Ok(None);
        }
        let data = self.read_buffer(offset, len)?;
        // GFSK packet status has RSSI sync / RSSI average in the first two
        // bytes. RSSI is encoded as -value/2 dBm; no LoRa SNR exists.
        let (rssi, _) = self.packet_status()?;
        Ok(Some(Packet {
            data,
            rssi,
            snr: 0.0,
        }))
    }

    fn fsk_diagnostics(&mut self) -> Result<String> {
        const SX126X_CMD_GET_STATS: u8 = 0x10;
        let irq = self.irq_status()?;
        let stats = self.read(SX126X_CMD_GET_STATS, &[], 6)?;
        let received = u16::from_be_bytes([stats[0], stats[1]]);
        let crc_error = u16::from_be_bytes([stats[2], stats[3]]);
        let length_error = u16::from_be_bytes([stats[4], stats[5]]);
        Ok(format!(
            "irq=0x{irq:04x} packets={} crc_err={} len_err={}",
            received, crc_error, length_error
        ))
    }

    fn dump(&mut self) -> Result<String> {
        let status = self.status()?;
        let packet_type = self.read_u8(SX126X_CMD_GET_PACKET_TYPE)?;
        let irq = self.irq_status()?;
        let sync = self.read_register(SX126X_REG_SYNC_WORD, 2)?;
        let sync = ((sync[0] as u16) << 8) | sync[1] as u16;
        let ocp = self.read_register(SX126X_REG_OCP, 1)?[0];
        let rx_gain = self.read_register(SX126X_REG_RX_GAIN, 1)?[0];
        let rx_sensitivity = self.read_register(SX126X_REG_RX_SENSITIVITY, 1)?[0];
        let busy_level = unsafe { sys::gpio_get_level(self.config.busy) };
        let dio_level = unsafe { sys::gpio_get_level(self.config.dio0) };
        let pwr_level = if self.config.board_power_pin >= 0 {
            unsafe { sys::gpio_get_level(self.config.board_power_pin) }
        } else {
            -1
        };
        Ok(format!(
            "chip=sx1262 status=0x{status:02x} packet_type=0x{packet_type:02x} irq=0x{irq:04x} sync=0x{sync:04x} busy_gpio={} busy_level={} dio1_gpio={} dio1_level={} pwrpin={} pwrlvl={} dio2rf={} tcxo_mv={} pa={},{},{},{} rx_timeout={} ocp=0x{ocp:02x} rx_gain=0x{rx_gain:02x} rx_sens=0x{rx_sensitivity:02x}",
            self.config.busy,
            busy_level,
            self.config.dio0,
            dio_level,
            self.config.board_power_pin,
            pwr_level,
            self.config.sx1262_dio2_rf_switch,
            self.config.sx1262_tcxo_mv,
            self.config.sx1262_pa_duty,
            self.config.sx1262_pa_hp,
            self.config.sx1262_pa_device,
            self.config.sx1262_pa_lut,
            self.config.sx1262_rx_timeout_ms
        ))
    }

    fn status(&mut self) -> Result<u8> {
        self.read_u8(SX126X_CMD_GET_STATUS)
    }

    fn irq_status(&mut self) -> Result<u16> {
        let data = self.read(SX126X_CMD_GET_IRQ_STATUS, &[], 2)?;
        Ok(((data[0] as u16) << 8) | data[1] as u16)
    }

    fn clear_irq(&mut self, mask: u16) -> Result<()> {
        self.command(
            SX126X_CMD_CLEAR_IRQ_STATUS,
            &[(mask >> 8) as u8, mask as u8],
        )
    }

    fn rx_buffer_status(&mut self) -> Result<(usize, u8)> {
        let data = self.read(SX126X_CMD_GET_RX_BUFFER_STATUS, &[], 2)?;
        Ok((data[0] as usize, data[1]))
    }

    fn packet_status(&mut self) -> Result<(i32, f32)> {
        let data = self.read(SX126X_CMD_GET_PACKET_STATUS, &[], 3)?;
        let rssi = -(data[0] as i32) / 2;
        let snr = (data[1] as i8) as f32 / 4.0;
        Ok((rssi, snr))
    }

    fn write_buffer(&mut self, offset: u8, payload: &[u8]) -> Result<()> {
        let mut data = Vec::with_capacity(payload.len() + 1);
        data.push(offset);
        data.extend_from_slice(payload);
        self.command(SX126X_CMD_WRITE_BUFFER, &data)
    }

    fn read_buffer(&mut self, offset: u8, len: usize) -> Result<Vec<u8>> {
        self.read(SX126X_CMD_READ_BUFFER, &[offset], len)
    }

    fn write_register(&mut self, address: u16, data: &[u8]) -> Result<()> {
        let mut payload = Vec::with_capacity(data.len() + 2);
        payload.push((address >> 8) as u8);
        payload.push(address as u8);
        payload.extend_from_slice(data);
        self.command(SX126X_CMD_WRITE_REGISTER, &payload)
    }

    fn read_register(&mut self, address: u16, len: usize) -> Result<Vec<u8>> {
        self.read(
            SX126X_CMD_READ_REGISTER,
            &[(address >> 8) as u8, address as u8],
            len,
        )
    }

    fn read_u8(&mut self, opcode: u8) -> Result<u8> {
        Ok(self.read(opcode, &[], 1)?[0])
    }

    fn command(&mut self, opcode: u8, data: &[u8]) -> Result<()> {
        self.wait_while_busy(Duration::from_millis(500))?;
        let mut tx = Vec::with_capacity(data.len() + 1);
        tx.push(opcode);
        tx.extend_from_slice(data);
        let mut rx = vec![0_u8; tx.len()];
        self.spi(&tx, &mut rx)?;
        self.wait_while_busy(Duration::from_millis(500))
    }

    fn read(&mut self, opcode: u8, args: &[u8], len: usize) -> Result<Vec<u8>> {
        self.wait_while_busy(Duration::from_millis(500))?;
        let mut tx = Vec::with_capacity(args.len() + len + 2);
        tx.push(opcode);
        tx.extend_from_slice(args);
        tx.push(0);
        tx.resize(args.len() + len + 2, 0);
        let mut rx = vec![0_u8; tx.len()];
        self.spi(&tx, &mut rx)?;
        self.wait_while_busy(Duration::from_millis(500))?;
        Ok(rx[(args.len() + 2)..].to_vec())
    }

    fn wait_while_busy(&self, timeout: Duration) -> Result<()> {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            let level = unsafe { sys::gpio_get_level(self.config.busy) };
            if level == 0 {
                return Ok(());
            }
            task_delay(Duration::from_millis(1));
        }
        bail!("SX1262 busy timeout gpio={}", self.config.busy)
    }

    fn spi(&mut self, tx: &[u8], rx: &mut [u8]) -> Result<()> {
        if tx.len() != rx.len() {
            bail!("spi tx/rx length mismatch");
        }
        let mut transaction = sys::spi_transaction_t::default();
        transaction.length = tx.len() * 8;
        unsafe {
            transaction.__bindgen_anon_1.tx_buffer = tx.as_ptr() as *const _;
            transaction.__bindgen_anon_2.rx_buffer = rx.as_mut_ptr() as *mut _;
            esp_ok(sys::gpio_set_level(self.config.cs, 0))?;
            let ret = sys::spi_device_transmit(self.handle, &mut transaction);
            let cs_ret = sys::gpio_set_level(self.config.cs, 1);
            esp_ok(ret)?;
            esp_ok(cs_ret)?;
        }
        Ok(())
    }
}

impl Drop for Sx1262 {
    fn drop(&mut self) {
        unsafe {
            if !self.handle.is_null() {
                let _ = sys::spi_bus_remove_device(self.handle);
            }
            let _ = sys::spi_bus_free(self.host);
        }
    }
}

fn sx126x_timeout(timeout_ms: u32) -> u32 {
    let units = ((timeout_ms as u64) * 1000 / 15).clamp(1, 0x00ff_ffff);
    units as u32
}

fn sx126x_rx_timeout(timeout_ms: i32) -> u32 {
    if timeout_ms <= 0 {
        0x00ff_ffff
    } else {
        sx126x_timeout(timeout_ms as u32)
    }
}

fn sx126x_duty_cycle_period(period_us: u32) -> Result<u32> {
    let raw = ((period_us as u64) * 8 / 125) as u32;
    if raw == 0 || raw > 0x00ff_ffff {
        bail!("SX1262 duty-cycle period out of range: {period_us}us");
    }
    Ok(raw)
}

fn sx1262_transition_us(tcxo_mv: i32) -> u32 {
    let tcxo_delay_us = if tcxo_mv > 0 { 5_000 } else { 0 };
    tcxo_delay_us + 1_000
}

fn sx127x_cad_timeout(config: &LoraConfig) -> Duration {
    let symbol = symbol_time_ms(config.bandwidth_hz, config.sf).max(1);
    Duration::from_millis((symbol as u64).saturating_mul(4).saturating_add(10))
}

fn cad_receive_interval(config: &LoraConfig, configured: Duration) -> Duration {
    if !matches!(config.chip, LoraChip::Sx127x) {
        return configured;
    }
    // SX127x CAD has to overlap the transmit preamble and leave enough
    // symbols to switch into RX before the header. With the default
    // MEDIUM_FAST profile (SF9/250 kHz, preamble 16), the full LoRa
    // preamble is about 41 ms, so a 20 ms cadence is the practical upper
    // bound for reliable detection. Longer configured intervals are treated
    // as battery hints, but capped here when CAD-RX is actually enabled.
    let symbol_us = symbol_time_us(config.bandwidth_hz, config.sf).max(1);
    let preamble_symbols_x4 = (config.preamble.max(6) as u64)
        .saturating_mul(4)
        .saturating_add(17);
    let preamble_us = preamble_symbols_x4.saturating_mul(symbol_us as u64) / 4;
    let cap_ms = (preamble_us / 2_000).clamp(5, u64::MAX);
    configured.min(Duration::from_millis(cap_ms))
}

fn sx1262_sync_word(config: &LoraConfig) -> u16 {
    if config.sx1262_sync_word >= 0 {
        return config.sx1262_sync_word.clamp(0, 0xffff) as u16;
    }
    let sync_word = config.sync_word.clamp(0, 0xff) as u16;
    let control_bits = 0x44_u16;
    ((sync_word & 0xf0) << 8)
        | (((control_bits & 0xf0) >> 4) << 8)
        | ((sync_word & 0x0f) << 4)
        | (control_bits & 0x0f)
}

fn symbol_time_ms(bw: u32, sf: i32) -> u32 {
    (((1_u32 << sf.clamp(6, 12)) as u64) * 1000 / bw.max(1) as u64) as u32
}

fn symbol_time_us(bw: u32, sf: i32) -> u32 {
    (((1_u32 << sf.clamp(6, 12)) as u64) * 1_000_000 / bw.max(1) as u64) as u32
}

fn lora_status_text(settings: &SharedSettings) -> String {
    if !lora_pins_configured(settings) {
        return format!(
            "lora status=false configured=false rx_running={} {}",
            BACKGROUND_RX_RUNNING.load(Ordering::Relaxed),
            cad_status_text()
        );
    }
    let Ok(state) = LoraState::load(settings) else {
        return "lora status=false error=config".to_string();
    };
    let probe = probe_lora_no_reset(&state.config);
    let mode = lora_mode(settings);
    format!(
        "lora status=true mode={} chip={} rx_running={} probe={} freq={} bw={} sf={} cr={} sync_word=0x{:02x} sx_sync=0x{:04x} crc={} preamble={} tx_power={} spi_host={} sck={} miso={} mosi={} cs={} rst={} dio0={} busy={} pwrpin={} pwrlvl={} dio2rf={} tcxo_mv={} pa_duty={} pa_hp={} pa_dev={} pa_lut={} rx_timeout={}",
        mode.as_str(),
        state.config.chip.as_str(),
        BACKGROUND_RX_RUNNING.load(Ordering::Relaxed),
        crate::commands::protocol::quote_text_value(&probe),
        state.config.frequency_hz,
        state.config.bandwidth_hz,
        state.config.sf,
        state.config.cr,
        state.config.sync_word,
        sx1262_sync_word(&state.config),
        state.config.crc,
        state.config.preamble,
        state.config.tx_power,
        state.config.spi_host,
        state.config.sck,
        state.config.miso,
        state.config.mosi,
        state.config.cs,
        state.config.rst,
        state.config.dio0,
        state.config.busy,
        state.config.board_power_pin,
        state.config.board_power_level,
        state.config.sx1262_dio2_rf_switch,
        state.config.sx1262_tcxo_mv,
        state.config.sx1262_pa_duty,
        state.config.sx1262_pa_hp,
        state.config.sx1262_pa_device,
        state.config.sx1262_pa_lut,
        state.config.sx1262_rx_timeout_ms
    ) + " " + &cad_status_text()
}

fn lora_pins_configured(settings: &SharedSettings) -> bool {
    let settings = settings.borrow();
    [
        "lora.spi_host",
        "lora.sck",
        "lora.miso",
        "lora.mosi",
        "lora.cs",
        "lora.rst",
        "lora.dio0",
        "lora.busy",
    ]
    .iter()
    .any(|key| matches!(settings.get_str(key), Ok(Some(_))))
}

fn probe_lora(config: &LoraConfig) -> String {
    match probe_lora_ready(config) {
        Ok(value) => match config.chip {
            LoraChip::Sx127x => format!("ready(chip=sx127x,version=0x{value:02x})"),
            LoraChip::Sx1262 => format!("ready(chip=sx1262,status=0x{value:02x})"),
        },
        Err(err) => format!("err:{err}"),
    }
}

fn probe_lora_no_reset(config: &LoraConfig) -> String {
    let _guard = lora_spi_lock().lock().unwrap();
    let result = match Radio::open_no_reset(config) {
        Ok(Radio::Sx127x(mut radio)) => radio.read_reg(REG_VERSION),
        Ok(Radio::Sx1262(mut radio)) => radio.status(),
        Err(err) => return format!("err:{err}"),
    };
    match result {
        Ok(value) => match config.chip {
            LoraChip::Sx127x => format!("ready(chip=sx127x,version=0x{value:02x})"),
            LoraChip::Sx1262 => format!("ready(chip=sx1262,status=0x{value:02x})"),
        },
        Err(err) => format!("err:{err}"),
    }
}

fn configure_board_power(config: &LoraConfig) -> Result<()> {
    if config.board_power_pin < 0 {
        return Ok(());
    }
    validate_optional_pin(config.board_power_pin)?;
    validate_range("board_power_level", config.board_power_level, 0, 1)?;
    unsafe {
        esp_ok(sys::gpio_set_direction(
            config.board_power_pin,
            sys::gpio_mode_t_GPIO_MODE_OUTPUT,
        ))?;
        esp_ok(sys::gpio_set_level(
            config.board_power_pin,
            config.board_power_level as u32,
        ))?;
    }
    task_delay(Duration::from_millis(5));
    Ok(())
}

/// Turn off an optional board-level radio supply. This is intentionally only
/// used by explicit radio-stop paths; LoRa receive duty cycling must keep the
/// supply on so the SX126x can wake itself between RX windows.
fn power_down_board(config: &LoraConfig) -> Result<()> {
    if config.board_power_pin < 0 {
        return Ok(());
    }
    validate_optional_pin(config.board_power_pin)?;
    let off_level = 1_i32 - config.board_power_level;
    unsafe {
        esp_ok(sys::gpio_set_direction(
            config.board_power_pin,
            sys::gpio_mode_t_GPIO_MODE_OUTPUT,
        ))?;
        esp_ok(sys::gpio_set_level(
            config.board_power_pin,
            off_level as u32,
        ))?;
    }
    Ok(())
}

/// Recover SX126x boards whose hardware duty-cycle receiver leaves BUSY high
/// while a stop request is in flight. Heltec V3 exposes the radio supply as
/// active-low Vext, so reset must include a short power cycle before waiting
/// on BUSY again. Boards without a configured power rail are unaffected.
fn cycle_board_power(config: &LoraConfig) -> Result<()> {
    if config.board_power_pin < 0 {
        return Ok(());
    }
    validate_optional_pin(config.board_power_pin)?;
    power_down_board(config)?;
    task_delay(Duration::from_millis(10));
    configure_board_power(config)
}

fn probe_lora_ready(config: &LoraConfig) -> Result<u8> {
    let _guard = lora_spi_lock().lock().unwrap();
    match Radio::open(config)? {
        Radio::Sx127x(mut radio) => {
            let version = radio.read_reg(REG_VERSION)?;
            if version == SX127X_VERSION {
                Ok(version)
            } else {
                bail!("unexpected SX127x version 0x{version:02x}")
            }
        }
        Radio::Sx1262(mut radio) => radio.status(),
    }
}

fn decode_registers(regs: &[u8; 0x50]) -> String {
    let op_mode = regs[REG_OP_MODE as usize];
    let frf = ((regs[REG_FRF_MSB as usize] as u32) << 16)
        | ((regs[REG_FRF_MID as usize] as u32) << 8)
        | regs[REG_FRF_LSB as usize] as u32;
    let freq_hz = ((frf as u64) * 32_000_000_u64 / (1_u64 << 19)) as u32;
    let modem_config_1 = regs[REG_MODEM_CONFIG_1 as usize];
    let modem_config_2 = regs[REG_MODEM_CONFIG_2 as usize];
    let modem_config_3 = regs[REG_MODEM_CONFIG_3 as usize];
    let bw = decode_bandwidth((modem_config_1 >> 4) & 0x0f);
    let cr = 4 + ((modem_config_1 >> 1) & 0x07);
    let implicit_header = modem_config_1 & 0x01 != 0;
    let sf = modem_config_2 >> 4;
    let crc = modem_config_2 & 0x04 != 0;
    let preamble =
        ((regs[REG_PREAMBLE_MSB as usize] as u16) << 8) | regs[REG_PREAMBLE_LSB as usize] as u16;
    let mode = match op_mode & 0x07 {
        MODE_SLEEP => "sleep",
        MODE_STDBY => "standby",
        MODE_TX => "tx",
        MODE_RX_CONTINUOUS => "rx_continuous",
        _ => "other",
    };
    format!(
        "version=0x{:02x} mode={} lora={} freq={} bw={} sf={} cr={} header={} crc={} preamble={} sync_word=0x{:02x} irq=0x{:02x} dio=0x{:02x} lna=0x{:02x} modem3=0x{:02x}",
        regs[REG_VERSION as usize],
        mode,
        op_mode & MODE_LONG_RANGE != 0,
        freq_hz,
        bw.map(|value| value.to_string()).unwrap_or_else(|| "unknown".to_string()),
        sf,
        cr,
        if implicit_header { "implicit" } else { "explicit" },
        crc,
        preamble,
        regs[REG_SYNC_WORD as usize],
        regs[REG_IRQ_FLAGS as usize],
        regs[REG_DIO_MAPPING_1 as usize],
        regs[REG_LNA as usize],
        modem_config_3
    )
}

fn decode_bandwidth(code: u8) -> Option<u32> {
    match code {
        0 => Some(7_800),
        1 => Some(10_400),
        2 => Some(15_600),
        3 => Some(20_800),
        4 => Some(31_250),
        5 => Some(41_700),
        6 => Some(62_500),
        7 => Some(125_000),
        8 => Some(250_000),
        9 => Some(500_000),
        _ => None,
    }
}

fn parse_payload(request: &CommandRequest) -> Result<Vec<u8>> {
    if let Some(data) = request.arg("data").or_else(|| request.arg("payload")) {
        return parse_bytes(data);
    }
    if let Some(text) = request.arg("text") {
        return Ok(text.as_bytes().to_vec());
    }
    if !request.payload.is_empty() {
        return Ok(request.payload.clone());
    }
    bail!("lorasend requires data=hex:... or text=...");
}

fn send_payload(
    settings: &SharedSettings,
    payload: &[u8],
    kind: FrameKind,
    hop_limit: Option<u8>,
    portnum: Option<u32>,
    timeout_ms: u32,
) -> Result<String> {
    let sender = meshtastic_sender_node()?;
    let packet_id = LORA_PACKET_COUNTER.fetch_add(1, Ordering::Relaxed);
    let channel = settings
        .borrow()
        .get_i32("lora.channel_hash", MESHTASTIC_DEFAULT_CHANNEL_HASH as i32)?
        .clamp(0, u8::MAX as i32) as u8;
    let portnum = match portnum {
        Some(portnum) => portnum,
        None => settings
            .borrow()
            .get_i32("lora.portnum", MESHTASTIC_DEFAULT_PORTNUM as i32)?
            .clamp(0, 511) as u32,
    };
    let hop_limit = match hop_limit {
        Some(hop_limit) => hop_limit.clamp(0, 7),
        None => settings
            .borrow()
            .get_i32("lora.hop_limit", MESHTASTIC_DEFAULT_HOP_LIMIT as i32)?
            .clamp(0, 7) as u8,
    };
    let packet = match kind {
        FrameKind::Meshtastic => encode_meshtastic_frame(
            &encode_meshtastic_data(portnum, payload)?,
            sender,
            packet_id,
            channel,
            hop_limit,
        )?,
        FrameKind::Raw => payload.to_vec(),
    };
    if packet.len() > 255 {
        bail!("LoRa payload too large: {}", packet.len());
    }
    let state = LoraState::load(settings)?;
    let _guard = lora_spi_lock().lock().unwrap();
    let mut radio = Radio::open(&state.config)?;
    radio.configure_radio()?;
    let background_rx = BACKGROUND_RX_RUNNING.load(Ordering::Relaxed);
    if background_rx {
        set_lora_irq_enabled(state.config.dio0, false)?;
    }
    let cad_tx = LORA_CAD_TX_ENABLED.load(Ordering::Relaxed);
    let cad_tx_tries = LORA_CAD_TX_TRIES.load(Ordering::Relaxed);
    if cad_tx {
        let cad_timeout = sx127x_cad_timeout(&state.config);
        radio.ensure_channel_clear(cad_timeout, cad_tx_tries)?;
    }
    let send_result = radio.send_packet(&packet, timeout_ms);
    if background_rx {
        send_result?;
        if LORA_CAD_RX_ENABLED.load(Ordering::Relaxed)
            && matches!(state.config.chip, LoraChip::Sx1262)
        {
            radio.start_background_rx_mode()?;
        } else {
            radio.start_rx()?;
        }
        let irq_result = set_lora_irq_enabled(state.config.dio0, true);
        irq_result?;
    } else {
        send_result?;
    }
    telemetry::count_packet("lora", Direction::Tx, packet.len());
    telemetry::record_log(format!(
        "ev=lora.tx t=lora src={} dst={} n={} hop={} len={} data_len={} rf={}",
        format_meshtastic_node(sender),
        if kind == FrameKind::Meshtastic {
            format_meshtastic_node(super::frames::MESHTASTIC_BROADCAST)
        } else {
            "-".to_string()
        },
        packet_id,
        hop_limit,
        packet.len(),
        payload.len(),
        compact_rf(&state.config)
    ));
    Ok(format!(
        "lorasend src={} dst={} n={} hop={} len={} data_len={} rf={}{}",
        format_meshtastic_node(sender),
        if kind == FrameKind::Meshtastic {
            format_meshtastic_node(super::frames::MESHTASTIC_BROADCAST)
        } else {
            "-".to_string()
        },
        packet_id,
        hop_limit,
        packet.len(),
        payload.len(),
        compact_rf(&state.config),
        if kind == FrameKind::Raw { " f=raw" } else { "" }
    ))
}

fn compact_rf(config: &LoraConfig) -> String {
    format!(
        "{}/{}/{}/{}",
        compact_hz(config.frequency_hz, "M"),
        compact_hz(config.bandwidth_hz, "k"),
        config.sf,
        config.cr
    )
}

fn compact_hz(value: u32, suffix: &str) -> String {
    let divisor = if suffix == "M" { 1_000_000 } else { 1_000 };
    if value % divisor == 0 {
        format!("{}{}", value / divisor, suffix)
    } else {
        let scaled = value as f32 / divisor as f32;
        format!("{scaled:.3}{suffix}")
    }
}

fn compact_lora_detail(
    header: Option<super::frames::MeshtasticHeader>,
    dst: Option<&str>,
    rssi: i32,
    snr: f32,
) -> String {
    let (src, packet_id, hop_limit, hop_start) = header
        .map(|h| {
            (
                format_meshtastic_node(h.from),
                h.id.to_string(),
                h.hop_limit(),
                h.hop_start(),
            )
        })
        .unwrap_or_else(|| ("-".to_string(), "-".to_string(), 0, 0));
    format!(
        "src={} dst={} n={} rssi={} snr={} hl={} hs={}",
        src,
        dst.unwrap_or("-"),
        packet_id,
        rssi,
        snr,
        hop_limit,
        hop_start
    )
}

fn meshtastic_sender_node() -> Result<u32> {
    let mac = station_mac()?;
    Ok(u32::from_le_bytes([mac[2], mac[3], mac[4], mac[5]]))
}

fn station_mac() -> Result<[u8; 6]> {
    let mut mac = [0_u8; 6];
    unsafe {
        esp_ok(sys::esp_read_mac(
            mac.as_mut_ptr(),
            sys::esp_mac_type_t_ESP_MAC_WIFI_STA,
        ))?;
    }
    Ok(mac)
}

fn parse_pin_list(value: Option<&str>, default: i32) -> Result<Vec<i32>> {
    let values = parse_i32_list(value, default)?;
    for pin in &values {
        validate_pin(*pin)?;
    }
    Ok(values)
}

fn parse_optional_pin_list(value: Option<&str>, default: i32) -> Result<Vec<i32>> {
    let values = parse_i32_list(value, default)?;
    for pin in &values {
        validate_optional_pin(*pin)?;
    }
    Ok(values)
}

fn parse_chip_list(value: Option<&str>, default: LoraChip) -> Result<Vec<LoraChip>> {
    match value {
        Some(value) => value
            .split(',')
            .map(|item| LoraChip::parse(item.trim()))
            .collect(),
        None => Ok(vec![default]),
    }
}

fn parse_i32_list(value: Option<&str>, default: i32) -> Result<Vec<i32>> {
    match value {
        Some(value) => value
            .split(',')
            .map(|item| parse_i32(item.trim()))
            .collect(),
        None => Ok(vec![default]),
    }
}

fn parse_arg_or(request: &CommandRequest, key: &str, default: i32) -> Result<i32> {
    request
        .arg(key)
        .map(parse_i32)
        .transpose()
        .map(|v| v.unwrap_or(default))
}

fn has_duplicate_pins(pins: &[i32]) -> bool {
    for (idx, pin) in pins.iter().enumerate() {
        if *pin < 0 {
            continue;
        }
        if pins[idx + 1..].contains(pin) {
            return true;
        }
    }
    false
}

fn spi_host(host: i32) -> Result<sys::spi_host_device_t> {
    match host {
        1 => Ok(sys::spi_host_device_t_SPI2_HOST),
        2 => Ok(sys::spi_host_device_t_SPI3_HOST),
        _ => bail!("invalid SPI host {host}; use 1=SPI2/HSPI or 2=SPI3/VSPI"),
    }
}

fn validate_config(config: &LoraConfig) -> Result<()> {
    spi_host(config.spi_host)?;
    for pin in [
        config.sck,
        config.miso,
        config.mosi,
        config.cs,
        config.rst,
        config.dio0,
    ] {
        validate_pin(pin)?;
    }
    validate_optional_pin(config.busy)?;
    validate_optional_pin(config.board_power_pin)?;
    validate_range("board_power_level", config.board_power_level, 0, 1)?;
    if matches!(config.chip, LoraChip::Sx1262) && config.busy < 0 {
        bail!("SX1262 requires busy GPIO");
    }
    validate_sf(config.sf)?;
    validate_cr(config.cr)?;
    validate_bandwidth(config.bandwidth_hz)?;
    validate_u8(config.sync_word)?;
    validate_range("preamble", config.preamble, 6, 65535)?;
    validate_range("tx_power", config.tx_power, 2, 20)?;
    validate_range("tcxo_mv", config.sx1262_tcxo_mv, 0, 3300)?;
    validate_range("pa_duty", config.sx1262_pa_duty, 0, 7)?;
    validate_range("pa_hp", config.sx1262_pa_hp, 0, 7)?;
    validate_range("pa_dev", config.sx1262_pa_device, 0, 1)?;
    validate_range("pa_lut", config.sx1262_pa_lut, 0, 1)?;
    validate_range("rx_timeout", config.sx1262_rx_timeout_ms, 0, 60_000)?;
    validate_range("sx_sync", config.sx1262_sync_word, -1, 65_535)?;
    Ok(())
}

fn validate_pin(pin: i32) -> Result<()> {
    if !(0..=39).contains(&pin) {
        return Err(anyhow!("invalid ESP32 GPIO pin {pin}"));
    }
    Ok(())
}

fn validate_optional_pin(pin: i32) -> Result<()> {
    if pin == -1 {
        Ok(())
    } else {
        validate_pin(pin)
    }
}

fn validate_sf(sf: i32) -> Result<()> {
    validate_range("sf", sf, 6, 12)
}

fn validate_cr(cr: i32) -> Result<()> {
    validate_range("cr", cr, 5, 8)
}

fn validate_u8(value: i32) -> Result<()> {
    validate_range("u8", value, 0, 255)
}

fn validate_bandwidth(bw: u32) -> Result<()> {
    match bw {
        7_800 | 10_400 | 15_600 | 20_800 | 31_250 | 41_700 | 62_500 | 125_000 | 250_000
        | 500_000 => Ok(()),
        _ => bail!("unsupported LoRa bandwidth {bw}"),
    }
}

fn validate_range(name: &str, value: i32, min: i32, max: i32) -> Result<()> {
    if value < min || value > max {
        bail!("{name} must be in {min}..={max}, got {value}");
    }
    Ok(())
}

fn esp_ok(ret: sys::esp_err_t) -> Result<()> {
    if ret == sys::ESP_OK {
        Ok(())
    } else {
        bail!("esp_err=0x{ret:x}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fsk_channel_map_has_expected_edges() {
        assert_eq!(fsk_channel_hz(0), 902_250_000);
        assert_eq!(fsk_channel_hz(21), 912_750_000);
        assert_eq!(fsk_channel_hz(22), 913_750_000);
        assert_eq!(fsk_channel_hz(25), 915_250_000);
        assert_eq!(fsk_channel_hz(26), 916_250_000);
        assert_eq!(fsk_channel_hz(49), 927_750_000);
    }

    #[test]
    fn fsk_sync_is_network_order_and_contains_target() {
        let config = FskConfig {
            network_id: 0xd3a5,
            hop_seed: 0,
            bitrate: 100_000,
            deviation: 25_000,
            rx_bw: 250_000,
            preamble: 16,
            slot_ms: 80,
        };
        assert_eq!(
            encode_fsk_sync(config, 0x840d_8e07, 9),
            vec![b'D', b'M', b'S', b'F', 1, 0, 0xd3, 0xa5, 0, 0, 0, 9, 0x84, 0x0d, 0x8e, 0x07,]
        );
    }
}
