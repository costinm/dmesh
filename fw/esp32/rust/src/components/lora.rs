//! Main-side LoRa service adapter.
//!
//! Radio mechanics live in the flash-resident `mod_lora` image.  This file
//! deliberately contains only persisted configuration, the stable command
//! names, packet forwarding, and the mesh transport bridge.  It has no SPI,
//! GPIO, interrupt, or chip-driver implementation.

use anyhow::{Result, anyhow, bail};

use crate::commands::{CommandHandler, CommandRegistry, CommandRequest, CommandResponse};

use super::bytes::parse_bytes;
use super::settings::{SharedSettings, parse_bool, parse_i32};
use super::telemetry::{self, Direction};

const DEFAULT_FREQUENCY_HZ: u32 = 913_125_000;
const DEFAULT_BANDWIDTH_HZ: u32 = 250_000;
const DEFAULT_SYNC_WORD: i32 = 0x2b;
const DEFAULT_TX_POWER: i32 = 17;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LoraChip {
    Sx127x,
    Sx1262,
}

impl LoraChip {
    fn parse(value: &str) -> Result<Self> {
        match value.to_ascii_lowercase().as_str() {
            "sx127x" | "sx127" | "127" => Ok(Self::Sx127x),
            "sx1262" | "sx126x" | "126" => Ok(Self::Sx1262),
            other => bail!("unsupported LoRa chip {other}"),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Sx127x => "sx127x",
            Self::Sx1262 => "sx1262",
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct LoraConfig {
    pub(crate) chip: LoraChip,
    pub(crate) frequency_hz: u32,
    pub(crate) bandwidth_hz: u32,
    pub(crate) beacon: bool,
    pub(crate) spi_host: i32,
    pub(crate) sck: i32,
    pub(crate) miso: i32,
    pub(crate) mosi: i32,
    pub(crate) cs: i32,
    pub(crate) rst: i32,
    pub(crate) dio0: i32,
    pub(crate) busy: i32,
    pub(crate) board_power_pin: i32,
    pub(crate) board_power_level: i32,
    pub(crate) sx1262_dio2_rf_switch: bool,
    pub(crate) sx1262_tcxo_mv: i32,
    pub(crate) sx1262_pa_duty: i32,
    pub(crate) sx1262_pa_hp: i32,
    pub(crate) sx1262_pa_device: i32,
    pub(crate) sx1262_pa_lut: i32,
    pub(crate) sx1262_rx_timeout_ms: i32,
    pub(crate) sx1262_sync_word: i32,
    pub(crate) sf: i32,
    pub(crate) cr: i32,
    pub(crate) sync_word: i32,
    pub(crate) crc: bool,
    pub(crate) preamble: i32,
    pub(crate) tx_power: i32,
    pub(crate) cad_rx: bool,
    pub(crate) cad_interval_ms: i32,
    pub(crate) cad_rx_ms: i32,
}

impl Default for LoraConfig {
    fn default() -> Self {
        Self {
            chip: LoraChip::Sx127x,
            frequency_hz: DEFAULT_FREQUENCY_HZ,
            bandwidth_hz: DEFAULT_BANDWIDTH_HZ,
            beacon: false,
            spi_host: 3,
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
            sx1262_pa_duty: 0,
            sx1262_pa_hp: 0,
            sx1262_pa_device: 0,
            sx1262_pa_lut: 0,
            sx1262_rx_timeout_ms: 0,
            sx1262_sync_word: -1,
            sf: 10,
            cr: 5,
            sync_word: DEFAULT_SYNC_WORD,
            crc: true,
            preamble: 16,
            tx_power: DEFAULT_TX_POWER,
            cad_rx: false,
            cad_interval_ms: 2000,
            cad_rx_ms: 1000,
        }
    }
}

pub fn register_commands(registry: &mut CommandRegistry, settings: SharedSettings) {
    registry.register(LoraCommand {
        name: "lora",
        settings: settings.clone(),
    });
    registry.register(LoraCommand {
        name: "loraprobe",
        settings: settings.clone(),
    });
    registry.register(LoraCommand {
        name: "lorasend",
        settings: settings.clone(),
    });
    registry.register(LoraCommand {
        name: "loralisten",
        settings: settings.clone(),
    });
    registry.register(LoraCommand {
        name: "loradump",
        settings: settings.clone(),
    });
    registry.register(RadioCommand { settings });
}

pub fn load_cad_settings(_settings: &SharedSettings) {}

pub fn load_config(settings: &SharedSettings) -> Result<LoraConfig> {
    let s = settings.borrow();
    let mut config = LoraConfig::default();
    if let Some(chip) = s.get_str("lora.chip")? {
        config.chip = LoraChip::parse(&chip)?;
    }
    config.frequency_hz = s.get_i32("lora.freq", config.frequency_hz as i32)? as u32;
    config.bandwidth_hz = s.get_i32("lora.bw", config.bandwidth_hz as i32)? as u32;
    config.beacon = s.get_bool("lora.beacon", config.beacon)?;
    config.spi_host = s.get_i32("lora.spi_host", config.spi_host)?;
    for (key, field) in [
        ("sck", &mut config.sck),
        ("miso", &mut config.miso),
        ("mosi", &mut config.mosi),
        ("cs", &mut config.cs),
        ("rst", &mut config.rst),
        ("dio0", &mut config.dio0),
        ("busy", &mut config.busy),
        ("pwrpin", &mut config.board_power_pin),
        ("pwrlvl", &mut config.board_power_level),
        ("tcxo_mv", &mut config.sx1262_tcxo_mv),
        ("pa_duty", &mut config.sx1262_pa_duty),
        ("pa_hp", &mut config.sx1262_pa_hp),
        ("pa_dev", &mut config.sx1262_pa_device),
        ("pa_lut", &mut config.sx1262_pa_lut),
        ("rx_timeout", &mut config.sx1262_rx_timeout_ms),
        ("sx_sync", &mut config.sx1262_sync_word),
        ("sf", &mut config.sf),
        ("cr", &mut config.cr),
        ("sync_word", &mut config.sync_word),
        ("preamble", &mut config.preamble),
        ("tx_power", &mut config.tx_power),
    ] {
        *field = s.get_i32(&format!("lora.{key}"), *field)?;
    }
    config.crc = s.get_bool("lora.crc", config.crc)?;
    config.sx1262_dio2_rf_switch = s.get_bool("lora.dio2rf", config.sx1262_dio2_rf_switch)?;
    config.cad_rx = s.get_bool("lora.cad_rx", config.cad_rx)?;
    config.cad_interval_ms = s.get_i32("lora.cad_int", config.cad_interval_ms)?;
    config.cad_rx_ms = s.get_i32("lora.cad_rxms", config.cad_rx_ms)?;
    Ok(config)
}

pub fn status_text(settings: &SharedSettings) -> String {
    match load_config(settings) {
        Ok(config) => format!(
            "lora backend=module chip={} freq={} bw={} sf={} cr={} sync_word=0x{:02x} tx_power={} cad_rx={} cad_interval_ms={} cad_rx_ms={} module_authoritative=true",
            config.chip.as_str(),
            config.frequency_hz,
            config.bandwidth_hz,
            config.sf,
            config.cr,
            config.sync_word,
            config.tx_power,
            config.cad_rx,
            config.cad_interval_ms,
            config.cad_rx_ms
        ),
        Err(err) => format!("lora backend=module configured=false error={err}"),
    }
}

/// Whether the module currently owns a receive task that can wake the CPU.
/// The task is deliberately kept alive for CAD/duty-cycle receive during
/// light sleep; the radio's DIO line is then an asynchronous wake source.
pub fn background_rx_running() -> bool {
    super::module::lora_enabled() && !super::module::module_task_done()
}

/// CAD receivers remain configured across light-sleep intervals. Other radio
/// modes are stopped by the normal sleep/profile transitions.
pub fn keep_rx_in_light_sleep(settings: &SharedSettings) -> bool {
    if !background_rx_running() {
        return false;
    }
    load_config(settings)
        .map(|config| config.cad_rx)
        .unwrap_or(false)
}

pub fn start_background_rx(settings: SharedSettings) -> Result<()> {
    if !super::module::lora_enabled() {
        return Err(anyhow!("LoRa requires a deployed lora module"));
    }
    /* The module exits deliberately on `stop` so deep sleep does not retain a
     * polling task. Wake/infra transitions must create a fresh task. */
    if super::module::module_task_done() {
        let request = CommandRequest::new("lora").arg_pair("args", "rx");
        super::module::invoke_module(&settings, "lora", &request)?;
    }
    Ok(())
}

pub fn sleep_radio(settings: &SharedSettings) -> Result<()> {
    super::module::ensure_initialized(settings);
    let request = CommandRequest::new("lora").arg_pair("args", "stop");
    super::module::invoke_module(settings, "lora", &request).map(|_| ())
}

pub fn send_text(settings: &SharedSettings, text: &str, _hop_limit: u8) -> Result<String> {
    send_raw(settings, text.as_bytes())
}

pub fn send_raw(settings: &SharedSettings, payload: &[u8]) -> Result<String> {
    super::module::ensure_initialized(settings);
    let mut request = CommandRequest::new("lora").arg_pair("args", "tx");
    request.payload = payload.to_vec();
    super::module::invoke_module(settings, "lora", &request).map(|response| response.message)
}

struct LoraCommand {
    name: &'static str,
    settings: SharedSettings,
}

impl CommandHandler for LoraCommand {
    fn name(&self) -> &'static str {
        self.name
    }

    fn handle(&mut self, request: &CommandRequest) -> Result<CommandResponse> {
        super::module::ensure_initialized(&self.settings);
        /* Both spellings are common in the managed command surface.  Keep
         * status strictly observational: `lora op=status` must not configure
         * SPI, start a module task, or hand an unknown `status` command to a
         * stale image. */
        let status_requested = request.arg("op") == Some("status")
            || request
                .arg("status")
                .map(parse_bool)
                .transpose()?
                .unwrap_or(false);
        if self.name == "lora" && status_requested {
            return Ok(CommandResponse::ok(status_text(&self.settings)));
        }
        if self.name == "lora" {
            persist_settings(&self.settings, request)?;
            super::module::refresh_lora_config(&self.settings)?;
        }
        let mut module_request = request.clone();
        let op = match self.name {
            "lorasend" => {
                module_request.payload = parse_payload(request)?;
                "tx"
            }
            "loralisten" => "rx",
            "loraprobe" => "probe",
            _ if request
                .arg("rx")
                .or_else(|| request.arg("sleep"))
                .map(parse_bool)
                .transpose()?
                .is_some_and(|value| !value) =>
            {
                "stop"
            }
            _ => request.arg("op").unwrap_or("status"),
        };
        module_request = module_request.arg_pair("args", op);
        super::module::invoke_module(&self.settings, "lora", &module_request)
    }
}

struct RadioCommand {
    settings: SharedSettings,
}

impl CommandHandler for RadioCommand {
    fn name(&self) -> &'static str {
        "radio"
    }

    fn handle(&mut self, request: &CommandRequest) -> Result<CommandResponse> {
        super::module::ensure_initialized(&self.settings);
        if request
            .arg("status")
            .map(parse_bool)
            .transpose()?
            .unwrap_or(false)
        {
            return Ok(CommandResponse::ok("radio backend=module modulation=gfsk"));
        }
        let mut module_request = request.clone().arg_pair("args", "fsk");
        if request.arg("op") == Some("send") {
            module_request.payload = parse_payload(request)?;
        }
        super::module::invoke_module(&self.settings, "lora", &module_request)
    }
}

fn persist_settings(settings: &SharedSettings, request: &CommandRequest) -> Result<()> {
    if let Some(chip) = request.arg("chip") {
        settings
            .borrow_mut()
            .set_str("lora.chip", LoraChip::parse(chip)?.as_str())?;
    }
    for (arg, key) in [
        ("freq", "lora.freq"),
        ("bw", "lora.bw"),
        ("sf", "lora.sf"),
        ("cr", "lora.cr"),
        ("sync_word", "lora.sync_word"),
        ("preamble", "lora.preamble"),
        ("tx_power", "lora.tx_power"),
        ("spi_host", "lora.spi_host"),
        ("sck", "lora.sck"),
        ("miso", "lora.miso"),
        ("mosi", "lora.mosi"),
        ("cs", "lora.cs"),
        ("rst", "lora.rst"),
        ("dio0", "lora.dio0"),
        ("busy", "lora.busy"),
        ("cad_interval_ms", "lora.cad_int"),
        ("cad_rx_ms", "lora.cad_rxms"),
    ] {
        if let Some(value) = request.arg(arg) {
            settings.borrow_mut().set_i32(key, parse_i32(value)?)?;
        }
    }
    for (arg, key) in [
        ("crc", "lora.crc"),
        ("beacon", "lora.beacon"),
        ("dio2rf", "lora.dio2rf"),
        ("cad_rx", "lora.cad_rx"),
    ] {
        if let Some(value) = request.arg(arg) {
            settings.borrow_mut().set_bool(key, parse_bool(value)?)?;
        }
    }
    Ok(())
}

fn parse_payload(request: &CommandRequest) -> Result<Vec<u8>> {
    if !request.payload.is_empty() {
        return Ok(request.payload.clone());
    }
    let value = request
        .arg("data")
        .or_else(|| request.arg("payload"))
        .unwrap_or("");
    if value.is_empty() {
        bail!("payload is required")
    }
    parse_bytes(value)
}

#[derive(Clone, Debug)]
pub struct WakePacket {
    pub data: Vec<u8>,
    pub rssi: i32,
    pub snr: f32,
}

pub fn prepare_deep_sleep_rx(_config: &LoraConfig) -> Result<()> {
    Ok(())
}
pub fn read_wake_packet_no_reset(_config: &LoraConfig) -> Result<Option<WakePacket>> {
    Ok(None)
}

struct Packet {
    data: Vec<u8>,
    rssi: i32,
    snr: f32,
}

pub fn handle_module_packet(data: &[u8], rssi: i32, snr: f32) -> Result<CommandResponse> {
    if data.is_empty() || data.len() > 255 {
        bail!("module LoRa packet length invalid")
    }
    let packet = Packet {
        data: data.to_vec(),
        rssi,
        snr,
    };
    telemetry::record_packet(
        "lora",
        Direction::Rx,
        &packet.data,
        format!("source=module rssi={} snr={}", packet.rssi, packet.snr),
    );
    // A packet is an in-band radio wake trigger. Do not emit a second UART
    // heartbeat here: the scheduled NAN wake owns the single UART rendezvous
    // packet, and LoRa activity is included in its compact counters.
    super::mode::request_lora_packet_active(5_000);
    if telemetry::take_lora_wake_event_slot() {
        telemetry::record_log(format!(
            "event type=lora.packet_wake len={} rssi={} snr={} active_ms=5000",
            data.len(),
            rssi,
            snr
        ));
        let wake_stats = telemetry::lora_wake_stats_text();
        telemetry::record_log(wake_stats.clone());
        // Keep the automatic report small and structured. This is a
        // rate-limited notification, not a full status dump, and is queued
        // non-blockingly by the transport layer while the bounded UART
        // window is open. Packet counters remain lossless.
        telemetry::emit_console(&wake_stats);
    }
    forward_rx_packet(&packet);
    Ok(CommandResponse::ok(format!(
        "module lora rx len={} rssi={} snr={}",
        data.len(),
        rssi,
        snr
    )))
}

fn forward_rx_packet(packet: &Packet) {
    super::mode::observe_lora_ping("lora", &packet.data, packet.rssi);
    let Ok(espnow) =
        dmesh_rawnan::espnow::build_radio_packet(&packet.data, packet.rssi, packet.snr)
    else {
        telemetry::record_log(format!(
            "event type=lora.espnow_forward ok=false len={} rssi={} snr={} msg=payload-too-large",
            packet.data.len(),
            packet.rssi,
            packet.snr
        ));
        return;
    };
    if let Err(err) = super::wifi::send_espnow_broadcast(&espnow) {
        telemetry::record_log(format!(
            "event type=lora.espnow_forward ok=false len={} rssi={} snr={} msg={}",
            packet.data.len(),
            packet.rssi,
            packet.snr,
            err
        ));
    } else {
        telemetry::record_log(format!(
            "event type=lora.espnow_forward ok=true len={} rssi={} snr={} envelope_len={}",
            packet.data.len(),
            packet.rssi,
            packet.snr,
            espnow.len()
        ));
    }
    if super::mode::is_companion_mode() {
        let _ = super::ble_bt::announce_lora_packet(&packet.data, packet.rssi, packet.snr);
    }
    let _ = super::wifi::forward_management_packet(&packet.data);
    let _ = super::nan::forward_packet(&packet.data);
}
