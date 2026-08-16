//! Host UART forwarding backend.
//!
//! This module owns USB serial discovery, managed forwards, ESP console
//! exchange, modem control, and firmware framing. It has no Wi-Fi dependency.

use anyhow::{Context, Result, bail};
use mesh::message::MeshMessage;
use minicbor::{Decoder, Encoder, data::Type};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::{BTreeMap, VecDeque};
use std::ffi::CString;
use std::fs;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::fs::{FileTypeExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{
    Arc, Mutex, OnceLock,
    atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering},
};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::schema::FirmwareSchema;
use uart_codec::codec::{UART_ESCAPE, UART_FLAG};

const DEFAULT_ESP_NAN_GATEWAY: &str = "lora1";
const DEFAULT_ESP_COMMAND_TIMEOUT_MS: u64 = 3_000;
const SERVICE_CONFIG_RELATIVE_PATH: &str = "etc/lmesh-uart/lmesh.toml";
const REMOTE_REQUEST_ID_KEY: u16 = 333;
const RFC2217_IAC: u8 = 0xff;
const RFC2217_DONT: u8 = 0xfe;
const RFC2217_DO: u8 = 0xfd;
const RFC2217_WONT: u8 = 0xfc;
const RFC2217_WILL: u8 = 0xfb;
const RFC2217_SB: u8 = 0xfa;
const RFC2217_SE: u8 = 0xf0;
const RFC2217_SE_ALT: u8 = 0xef;
const RFC2217_BINARY: u8 = 0x00;
const RFC2217_COM_PORT_OPTION: u8 = 0x2c;
const RFC2217_SET_BAUDRATE: u8 = 1;
const RFC2217_SET_DATASIZE: u8 = 2;
const RFC2217_SET_PARITY: u8 = 3;
const RFC2217_SET_STOPSIZE: u8 = 4;
const RFC2217_SET_CONTROL: u8 = 5;
const RFC2217_PURGE_DATA: u8 = 12;
const SERIAL_FORWARD_MAX_PENDING: usize = 4 * 1024 * 1024;
const SERIAL_FORWARD_IO_BUFFER_BYTES: usize = 16 * 1024;
const SERIAL_LOG_FIELD_MAX: usize = 1800;
const SERIAL_LOG_MAX_BYTES: u64 = 16 * 1024 * 1024;
// Local UDS control prefix; it is consumed by lmesh and never sent to the
// firmware. It is retained for compatibility with older callers, but it must
// not bypass the sleepy-device queue: a direct host UART write cannot wake a
// NAN sleeper.
const SERIAL_FORWARD_FORCE_DIRECT_PREFIX: &[u8] = b"\0DMESH-DIRECT\n";
const SERIAL_RESET_NONE: u8 = 0;
// Firmware keeps its normal console receptive during the first ten seconds
// after a recovery reset.  The forward must use that documented window to
// deliver queued framed commands even if the retained duty profile has its
// periodic UART heartbeat disabled.
// The ROM and second-stage bootloader use a different baud rate.  Do not send
// a 460800 framed command until the application has taken over UART0.
// Physical PRG wakes firmware through a short button task before UART RX is
// re-armed. Keep incoming client bytes in the kernel socket buffer until that
// transition is complete.
// UART is an HDLC/PPP-style byte stream. Its payload is compact CBOR; the
// generic mesh stream envelope remains at the lmesh UDS boundary.
const FIRMWARE_UART_FLAG: u8 = UART_FLAG;
const FIRMWARE_UART_ESCAPE: u8 = UART_ESCAPE;

/// Host-side adapter from the no-std UART codec's raw payloads to the shared
/// mesh CBOR stream-frame representation used by the Linux service.
#[derive(Default)]
struct FirmwareUartDecoder {
    codec: uart_codec::codec::Decoder,
}

impl FirmwareUartDecoder {
    fn push(&mut self, bytes: &[u8]) -> Result<Vec<Vec<u8>>> {
        self.codec
            .push(bytes)
            .map_err(|error| anyhow::anyhow!(error.to_string()))?
            .into_iter()
            .map(|payload| mesh::cbor::encode_stream_frame(&payload))
            .collect()
    }

    fn take_frame_activity(&mut self) -> bool {
        self.codec.take_frame_activity()
    }
}
const NAN_SLEEPY_START_TAG: u8 = 6;
const DMESH_BOOT_METHOD_SELECT: u32 = 60010;
// Host-side decoder compatibility for already deployed stage2 records. New
// selectors and all new firmware images use the CBOR event above.
const DMESH_BOOT_MAGIC: &[u8; 4] = b"DMB1";
const DMESH_BOOT_VERSION: u8 = 1;
const DMESH_BOOT_ROLE_STAGE2: u8 = 3;
const DMESH_BOOT_PARTITION_BOOTLOADER: u8 = 0;
// Reset requests are sampled between events. 100 ms keeps them responsive
// without making every idle managed forward wake one hundred times per second.
const SERIAL_FORWARD_POLL_TIMEOUT_MS: i32 = 100;
/// Host-side UART service and its managed forward state.
#[derive(Clone)]
pub struct UartService {
    serial_forwards: Arc<Mutex<BTreeMap<String, SerialForwardRuntime>>>,
    esp_reverse_sessions: Arc<BTreeMap<String, ReverseMainRuntime>>,
    esp_gateway: String,
    esp_targets: Arc<BTreeMap<String, String>>,
}

struct SerialForwardRuntime {
    id: String,
    radio_id: String,
    port: String,
    socket_path: String,
    tcp_listen: Option<String>,
    log_path: Option<String>,
    baud: u32,
    multi: bool,
    reset_request: Arc<AtomicU8>,
    flush_request: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
    stats: Arc<SerialForwardStats>,
    firmware_state: Arc<Mutex<FirmwareState>>,
    handle: Option<std::thread::JoinHandle<()>>,
    started_ms: u64,
}

/// Last lifecycle notification observed on a managed firmware forward.
/// This is intentionally host RAM only: it is an observation of the current
/// UART session, not device configuration or durable device identity.
#[derive(Clone, Debug, Default)]
struct FirmwareState {
    role: Option<String>,
    partition: Option<String>,
    mode: Option<String>,
    infra_active: Option<bool>,
    phase: Option<String>,
    rebooted: Option<bool>,
    reset_reason: Option<u8>,
    mac: Option<String>,
    last_event_ms: u64,
}

impl FirmwareState {
    fn snapshot(&self) -> Value {
        json!({
            "role": self.role,
            "partition": self.partition,
            "mode": self.mode,
            "infra_active": self.infra_active,
            "phase": self.phase,
            "rebooted": self.rebooted,
            "reset_reason": self.reset_reason,
            "mac": self.mac,
            "last_event_ms": self.last_event_ms,
        })
    }
}

#[derive(Clone, Debug)]
struct ReverseMainRuntime {
    id: String,
    ip: Ipv4Addr,
    port: u16,
    socket_path: String,
    stream: Arc<Mutex<Option<TcpStream>>>,
}

#[derive(Default, Debug)]
struct SerialForwardStats {
    reset_requests: AtomicU64,
    reset_pulses: AtomicU64,
    reset_failures: AtomicU64,
    client_accepts: AtomicU64,
    client_drops: AtomicU64,
    client_to_serial_bytes: AtomicU64,
    serial_to_client_bytes: AtomicU64,
    serial_read_would_block: AtomicU64,
    serial_write_blocked: AtomicU64,
    client_read_would_block: AtomicU64,
    client_write_blocked: AtomicU64,
    serial_tx_queue_high_water: AtomicU64,
    serial_pending_queue_high_water: AtomicU64,
    uart_wake_frames: AtomicU64,
    uart_wake_flushes: AtomicU64,
    uart_wake_flush_bytes: AtomicU64,
    client_output_queue_high_water: AtomicU64,
    client_input_queue_high_water: AtomicU64,
    poll_calls: AtomicU64,
    poll_ready: AtomicU64,
    poll_timeouts: AtomicU64,
    log_records: AtomicU64,
    log_write_errors: AtomicU64,
    log_suppressed_records: AtomicU64,
    log_suppressed_bytes: AtomicU64,
}

impl SerialForwardStats {
    fn record_high_water(counter: &AtomicU64, value: usize) {
        counter.fetch_max(value as u64, Ordering::Relaxed);
    }

    fn snapshot(&self) -> Value {
        json!({
            "reset_requests": self.reset_requests.load(Ordering::Relaxed),
            "reset_pulses": self.reset_pulses.load(Ordering::Relaxed),
            "reset_failures": self.reset_failures.load(Ordering::Relaxed),
            "client_accepts": self.client_accepts.load(Ordering::Relaxed),
            "client_drops": self.client_drops.load(Ordering::Relaxed),
            "client_to_serial_bytes": self.client_to_serial_bytes.load(Ordering::Relaxed),
            "serial_to_client_bytes": self.serial_to_client_bytes.load(Ordering::Relaxed),
            "serial_read_would_block": self.serial_read_would_block.load(Ordering::Relaxed),
            "serial_write_blocked": self.serial_write_blocked.load(Ordering::Relaxed),
            "client_read_would_block": self.client_read_would_block.load(Ordering::Relaxed),
            "client_write_blocked": self.client_write_blocked.load(Ordering::Relaxed),
            "serial_tx_queue_high_water": self.serial_tx_queue_high_water.load(Ordering::Relaxed),
            "serial_pending_queue_high_water": self.serial_pending_queue_high_water.load(Ordering::Relaxed),
            "uart_wake_frames": self.uart_wake_frames.load(Ordering::Relaxed),
            "uart_wake_flushes": self.uart_wake_flushes.load(Ordering::Relaxed),
            "uart_wake_flush_bytes": self.uart_wake_flush_bytes.load(Ordering::Relaxed),
            "client_output_queue_high_water": self.client_output_queue_high_water.load(Ordering::Relaxed),
            "client_input_queue_high_water": self.client_input_queue_high_water.load(Ordering::Relaxed),
            "poll_calls": self.poll_calls.load(Ordering::Relaxed),
            "poll_ready": self.poll_ready.load(Ordering::Relaxed),
            "poll_timeouts": self.poll_timeouts.load(Ordering::Relaxed),
            "log_records": self.log_records.load(Ordering::Relaxed),
            "log_write_errors": self.log_write_errors.load(Ordering::Relaxed),
            "log_suppressed_records": self.log_suppressed_records.load(Ordering::Relaxed),
            "log_suppressed_bytes": self.log_suppressed_bytes.load(Ordering::Relaxed),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SerialForwardTcpMode {
    Framed,
    Rfc2217,
    Auto,
}

impl SerialForwardTcpMode {
    fn parse(value: &str) -> Result<Self> {
        match value {
            "framed" | "frame" | "text" | "plain" => Ok(Self::Framed),
            "rfc2217" | "telnet" | "flash" => Ok(Self::Rfc2217),
            "auto" | "" => Ok(Self::Auto),
            other => {
                bail!("unsupported serial TCP mode {other:?}; expected framed, rfc2217, or auto")
            }
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Framed => "framed",
            Self::Rfc2217 => "rfc2217",
            Self::Auto => "auto",
        }
    }
}

fn discover_usb_serial_devices() -> Vec<Value> {
    let mut paths = BTreeMap::<String, Value>::new();
    for prefix in ["/dev/ttyUSB", "/dev/ttyACM"] {
        for idx in 0..64 {
            let path = format!("{prefix}{idx}");
            if let Ok(metadata) = fs::metadata(&path) {
                if metadata.file_type().is_char_device() {
                    paths.insert(path.clone(), serial_device_json(&path, None));
                }
            }
        }
    }
    if let Ok(entries) = fs::read_dir("/dev/serial/by-id") {
        for entry in entries.flatten() {
            let symlink = entry.path();
            let Ok(target) = fs::canonicalize(&symlink) else {
                continue;
            };
            let Some(path) = target.to_str().map(str::to_string) else {
                continue;
            };
            let by_id = symlink.to_string_lossy().to_string();
            paths
                .entry(path.clone())
                .and_modify(|device| {
                    device["by_id"] = json!(by_id);
                })
                .or_insert_with(|| serial_device_json(&path, Some(by_id)));
        }
    }
    paths.into_values().collect()
}

fn serial_device_json(path: &str, by_id: Option<String>) -> Value {
    let metadata = fs::metadata(path).ok();
    let mode = metadata
        .as_ref()
        .map(|metadata| metadata.permissions().mode() & 0o7777);
    json!({
        "port": usb_port_id_from_path(path),
        "path": path,
        "by_id": by_id,
        "kind": if path.contains("ttyACM") { "cdc-acm" } else { "usb-serial" },
        "mode": mode.map(|mode| format!("{mode:04o}")),
    })
}

#[derive(Clone, Debug)]
struct UsbSerialTarget {
    id: String,
    path: String,
    socket_path: String,
    baud: u32,
}

fn resolve_usb_serial_target(port: Option<String>, baud: Option<u32>) -> Option<UsbSerialTarget> {
    let id = port
        .as_deref()
        .or(Some("USB0"))
        .and_then(canonical_usb_port_id)?;
    let path = usb_port_path(&id)?;
    let socket_dir = std::env::var("LMESH_SERIAL_SOCKET_DIR")
        .unwrap_or_else(|_| "/run/mesh/lmesh-uart".to_string());
    Some(UsbSerialTarget {
        socket_path: PathBuf::from(socket_dir)
            .join(format!("{id}.sock"))
            .to_string_lossy()
            .into_owned(),
        id,
        path,
        baud: baud.unwrap_or(460_800),
    })
}

fn canonical_usb_port_id(port: &str) -> Option<String> {
    let trimmed = port.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Some(name) = trimmed.strip_prefix("/dev/tty") {
        return canonical_usb_port_id(name);
    }
    let upper = trimmed.to_ascii_uppercase();
    if let Some(num) = upper.strip_prefix("USB") {
        return (!num.is_empty() && num.chars().all(|c| c.is_ascii_digit()))
            .then(|| format!("USB{num}"));
    }
    if let Some(num) = upper.strip_prefix("ACM") {
        return (!num.is_empty() && num.chars().all(|c| c.is_ascii_digit()))
            .then(|| format!("ACM{num}"));
    }
    // Configured lab/deployment roles use stable names instead of transient
    // tty numbering. Keep the accepted alphabet deliberately narrow because
    // the value is also used in the managed socket filename.
    (trimmed.len() <= 64
        && trimmed
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_')))
    .then(|| trimmed.to_string())
}

fn usb_port_path(id: &str) -> Option<String> {
    if let Some(path) = configured_serial_path(id) {
        return Some(path);
    }
    if let Some(num) = id.strip_prefix("USB") {
        return Some(format!("/dev/ttyUSB{num}"));
    }
    if let Some(num) = id.strip_prefix("ACM") {
        return Some(format!("/dev/ttyACM{num}"));
    }
    None
}

fn configured_serial_forward(id: &str) -> Option<SerialForwardConfig> {
    read_lmesh_config()?
        .serial_forwards
        .into_iter()
        .find(|forward| forward.port == id)
}

fn configured_serial_path(id: &str) -> Option<String> {
    configured_serial_forward(id)
        .and_then(|forward| forward.path)
        .filter(|path| !path.is_empty())
}

fn configured_serial_log_path_for_forward(id: &str) -> Option<String> {
    let config = read_lmesh_config()?;
    if config
        .serial_forwards
        .iter()
        .find(|forward| forward.port == id)
        .is_some_and(|forward| forward.log == Some(false))
    {
        return None;
    }
    let log_dir = std::env::var_os("HOME")
        .map(|home| PathBuf::from(home).join("logs"))
        .unwrap_or_else(|| PathBuf::from("logs"));
    Some(
        log_dir
            .join(format!("{id}.log"))
            .to_string_lossy()
            .into_owned(),
    )
}

fn usb_port_id_from_path(path: &str) -> Option<String> {
    let name = path.strip_prefix("/dev/tty").unwrap_or(path);
    canonical_usb_port_id(name)
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn serial_forward_loop(
    id: &str,
    port: &str,
    baud: u32,
    listener: UnixListener,
    tcp_listener: Option<TcpListener>,
    tcp_mode: SerialForwardTcpMode,
    multi: bool,
    raw_output: bool,
    reset_request: Arc<AtomicU8>,
    flush_request: Arc<AtomicBool>,
    initial_direct_write: bool,
    log_flash_quiet_until_ms: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
    stats: Arc<SerialForwardStats>,
    firmware_state: Arc<Mutex<FirmwareState>>,
    log_path: Option<String>,
    serial_log: Option<Arc<Mutex<SerialForwardLog>>>,
) -> Result<()> {
    let mut serial = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOCTTY | libc::O_NONBLOCK)
        .open(port)
        .with_context(|| format!("failed to open serial port {port}"))?;
    configure_serial(serial.as_raw_fd(), baud)
        .with_context(|| format!("failed to configure serial port {port}"))?;
    // Linux's tty open path may leave DTR and/or RTS asserted even though
    // lmesh did not request them. The CP210x board circuit combines both
    // lines into EN/GPIO0, so changing only one can select reset or ROM
    // bootloader. Normalize both together to the released/normal state; this
    // is not a pulse and explicit `usb.serial.reset` remains the only reset
    // operation exposed by lmesh.
    let state = modem_state(serial.as_raw_fd())?;
    let normal_state = state & !(libc::TIOCM_DTR | libc::TIOCM_RTS);
    if state != normal_state {
        set_modem_state(serial.as_raw_fd(), normal_state)
            .with_context(|| format!("failed to normalize modem lines for {port}"))?;
        tracing::debug!(forward_id = %id, port = %port, "serial_forward_normalized_modem_lines");
    }
    if log_path.is_some() && serial_log.is_none() {
        stats.log_write_errors.fetch_add(1, Ordering::Relaxed);
    }
    let mut clients: Vec<SerialForwardClient> = Vec::new();
    let mut firmware_uart_decoder = FirmwareUartDecoder::default();
    let mut serial_tx = VecDeque::new();
    // Probe twice without waiting.  This is deliberately a transport-level
    // probe: infra boards answer and release the client queue; sleepy boards
    // leave client records pending until a UART heartbeat/window arrives.
    let mut direct_write = initial_direct_write || raw_output;
    let mut mode_known = direct_write;
    let mut mode_probe_next_ms = now_millis_u64().saturating_add(500);
    let mut mode_probe_deadline = now_millis_u64().saturating_add(10_000);
    if !raw_output {
        for _ in 0..2 {
            let probe = firmware_command_cbor("mode status=true")
                .context("failed to encode serial-forward mode probe")?;
            queue_firmware_packet(&mut serial_tx, &probe)?;
        }
    }
    let mut serial_pending = VecDeque::new();
    // UART wake is proved by the firmware's framed heartbeat or an in-band
    // command window.  The forward never creates a wake by modem control.
    let mut serial_buf = [0_u8; SERIAL_FORWARD_IO_BUFFER_BYTES];
    while !stop.load(Ordering::Acquire) {
        let mut progressed = false;
        let mut uart_wake_seen = false;
        let mut nan_sleepy_start_seen = false;
        let reset_pending = reset_request
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |pending| {
                if pending != SERIAL_RESET_NONE {
                    Some(pending - 1)
                } else {
                    None
                }
            })
            .unwrap_or(SERIAL_RESET_NONE);
        if reset_pending != SERIAL_RESET_NONE {
            if let Err(error) = serial_run_reset(serial.as_raw_fd()) {
                stats.reset_failures.fetch_add(1, Ordering::Relaxed);
                tracing::warn!(forward_id = %id, port = %port, error = %error, "serial_reset_rejected");
            } else {
                stats.reset_pulses.fetch_add(1, Ordering::Relaxed);
                configure_serial(serial.as_raw_fd(), baud)
                    .with_context(|| format!("failed to restore serial baud for {port}"))?;
                if !raw_output {
                    // A reset is also the boot/recovery handoff boundary. The
                    // next client bytes may be a stage2 selector or Recovery
                    // command and must cross the same descriptor immediately;
                    // do not queue them behind the sleepy/Main mode probe.
                    // Main will publish its mode state after a normal boot and
                    // restore the usual sleepy/infra policy below.
                    mode_known = true;
                    direct_write = true;
                    mode_probe_next_ms = 0;
                    mode_probe_deadline = 0;
                }
            }
            progressed = true;
        }
        if flush_request.swap(false, Ordering::AcqRel) && !serial_pending.is_empty() {
            if serial_tx.len().saturating_add(serial_pending.len()) > SERIAL_FORWARD_MAX_PENDING {
                bail!(
                    "serial TX queue exceeded {} bytes while explicitly flushing UART queue",
                    SERIAL_FORWARD_MAX_PENDING
                );
            }
            serial_tx.append(&mut serial_pending);
            progressed = true;
        }
        if !raw_output
            && !mode_known
            && now_millis_u64() >= mode_probe_next_ms
            && now_millis_u64() < mode_probe_deadline
        {
            let probe = firmware_command_cbor("mode status=true")
                .context("failed to encode serial-forward mode retry")?;
            queue_firmware_packet(&mut serial_tx, &probe)?;
            mode_probe_next_ms = now_millis_u64().saturating_add(1_000);
            progressed = true;
        }
        match listener.accept() {
            Ok((stream, _)) => {
                stats.client_accepts.fetch_add(1, Ordering::Relaxed);
                tracing::info!(
                    forward_id = %id,
                    port = %port,
                    transport = "uds",
                    "serial_forward_client"
                );
                match add_serial_forward_unix_client(&mut clients, stream) {
                    Ok(()) => {}
                    Err(error) => {
                        tracing::warn!(
                            forward_id = %id,
                            port = %port,
                            error = %error,
                            "serial_forward_client_error"
                        );
                    }
                }
                progressed = true;
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(error).context("failed to accept serial forward client"),
        }
        if let Some(tcp_listener) = &tcp_listener {
            loop {
                match tcp_listener.accept() {
                    Ok((stream, addr)) => {
                        stats.client_accepts.fetch_add(1, Ordering::Relaxed);
                        tracing::info!(
                            forward_id = %id,
                            port = %port,
                            transport = "tcp",
                            client = %addr,
                            "serial_forward_client"
                        );
                        match add_serial_forward_tcp_client(&mut clients, stream, tcp_mode) {
                            Ok(()) => {}
                            Err(error) => {
                                tracing::warn!(
                                    forward_id = %id,
                                    port = %port,
                                    client = %addr,
                                    error = %error,
                                    "serial_forward_client_error"
                                );
                            }
                        }
                        progressed = true;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(error) => {
                        return Err(error).context("failed to accept TCP serial forward client");
                    }
                }
            }
        }
        let flash_log_quiet = log_flash_quiet_until_ms.load(Ordering::Acquire) > now_millis_u64();
        match serial.read(&mut serial_buf) {
            Ok(0) => {}
            Ok(n) => {
                stats
                    .serial_to_client_bytes
                    .fetch_add(n as u64, Ordering::Relaxed);
                let records = firmware_uart_decoder
                    .push(&serial_buf[..n])
                    .map_err(|error| anyhow::anyhow!(error.to_string()))?;
                record_serial_forward_rx_log(
                    serial_log.as_ref(),
                    &stats,
                    id,
                    &serial_buf[..n],
                    &records,
                    flash_log_quiet,
                );
                uart_wake_seen = firmware_uart_decoder.take_frame_activity();
                if uart_wake_seen {
                    stats.uart_wake_frames.fetch_add(1, Ordering::Relaxed);
                }
                broadcast_serial_output(
                    &mut clients,
                    &records,
                    &serial_buf[..n],
                    raw_output,
                    &stats,
                );
                if !raw_output {
                    for record in &records {
                        if nan_sleepy_start_event(
                            mesh::cbor::decode_stream_frame(record).unwrap_or(&[]),
                        )
                        .is_some()
                        {
                            nan_sleepy_start_seen = true;
                        }
                        if let Ok(payload) = mesh::cbor::decode_stream_frame(record) {
                            update_firmware_state_from_boot(&firmware_state, payload);
                        }
                        if let Some(text) = firmware_record_text(record) {
                            update_firmware_state_from_text(&firmware_state, &text);
                        }
                        if let Some(active) = firmware_record_direct_mode(record) {
                            direct_write = active;
                            mode_known = true;
                            mode_probe_deadline = 0;
                            tracing::debug!(
                                forward_id = %id,
                                device_direct_mode = active,
                                "serial_forward_device_mode"
                            );
                            if direct_write && !serial_pending.is_empty() {
                                serial_tx.append(&mut serial_pending);
                            }
                        }
                    }
                }
                progressed = true;
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                stats
                    .serial_read_would_block
                    .fetch_add(1, Ordering::Relaxed);
            }
            Err(error) => return Err(error).with_context(|| format!("failed to read {port}")),
        }
        if !mode_known && now_millis_u64() >= mode_probe_deadline {
            direct_write = false;
            // Make the timeout terminal for this forward's startup probe.
            // Leaving the old deadline in place caused this branch to log on
            // every poll iteration, flooding the managed log and making a
            // real sleepy/UART failure difficult to correlate. A later
            // firmware mode or heartbeat record still changes the policy.
            mode_probe_deadline = 0;
            tracing::debug!(forward_id = %id, "serial_forward_mode_probe_timeout");
        }
        let mut idx = 0;
        while idx < clients.len() {
            let may_write = multi || idx == 0;
            match clients[idx].pump_to_serial(
                serial.as_raw_fd(),
                &mut serial_tx,
                &mut serial_pending,
                may_write,
                // Direct-write forwards (normally continuously awake
                // infrastructure) deliver client bytes immediately; framed
                // sleepy forwards intentionally queue until the firmware
                // emits its UART wake delimiter.
                direct_write,
                &stats,
                id,
                serial_log.as_ref(),
                flash_log_quiet,
            ) {
                Ok((true, client_progressed, _control_event)) => {
                    progressed |= client_progressed;
                    idx += 1;
                }
                Ok((false, _, _)) => {
                    tracing::debug!(
                        forward_id = %id,
                        port = %port,
                        client_id = clients[idx].id,
                        "serial_forward_client_closed_input"
                    );
                    clients.remove(idx);
                    progressed = true;
                }
                Err(error) => {
                    tracing::warn!(
                        forward_id = %id,
                        port = %port,
                        client_id = clients[idx].id,
                        error = %error,
                        "serial_forward_client_error"
                    );
                    clients.remove(idx);
                    progressed = true;
                }
            }
        }
        if uart_wake_seen && !serial_pending.is_empty() {
            if serial_tx.len().saturating_add(serial_pending.len()) > SERIAL_FORWARD_MAX_PENDING {
                bail!(
                    "serial TX queue exceeded {} bytes while flushing UART wake queue",
                    SERIAL_FORWARD_MAX_PENDING
                );
            }
            if nan_sleepy_start_seen {
                // The tagged wake event proves that Main is inside its short
                // NAN/UART window. Put the internal one-second lease request
                // ahead of queued Main CBOR records so the rest of the queue
                // is handled as one active session. DMB1 and RFC2217 traffic
                // never enters serial_pending, so stage2/Recovery are not
                // affected by this automatic Main-only control packet.
                let active = firmware_command_cbor("mode active_ms=1000")
                    .context("failed to encode automatic sleepy active request")?;
                queue_firmware_packet(&mut serial_tx, &active)?;
            }
            let flushed = serial_pending.len();
            serial_tx.append(&mut serial_pending);
            stats.uart_wake_flushes.fetch_add(1, Ordering::Relaxed);
            stats
                .uart_wake_flush_bytes
                .fetch_add(flushed as u64, Ordering::Relaxed);
            progressed = true;
        }
        SerialForwardStats::record_high_water(&stats.serial_tx_queue_high_water, serial_tx.len());
        SerialForwardStats::record_high_water(
            &stats.serial_pending_queue_high_water,
            serial_pending.len(),
        );
        let serial_tx_before = serial_tx.len();
        if flush_queue_to_writer(&mut serial, &mut serial_tx)
            .with_context(|| format!("failed to write queued client data to {port}"))?
        {
            progressed = true;
        }
        stats.client_to_serial_bytes.fetch_add(
            serial_tx_before.saturating_sub(serial_tx.len()) as u64,
            Ordering::Relaxed,
        );
        if !serial_tx.is_empty() {
            stats.serial_write_blocked.fetch_add(1, Ordering::Relaxed);
        }
        let mut idx = 0;
        while idx < clients.len() {
            let output_pending = !clients[idx].output.is_empty();
            match clients[idx].flush_output() {
                Ok(true) => {
                    progressed = true;
                    idx += 1;
                }
                Ok(false) => {
                    if output_pending {
                        stats.client_write_blocked.fetch_add(1, Ordering::Relaxed);
                    }
                    idx += 1;
                }
                Err(error) => {
                    tracing::warn!(
                        forward_id = %id,
                        port = %port,
                        client_id = clients[idx].id,
                        error = %error,
                        "serial_forward_client_output_error"
                    );
                    clients.remove(idx);
                    progressed = true;
                }
            }
        }
        if !progressed {
            wait_for_serial_forward_io(
                &serial,
                &listener,
                tcp_listener.as_ref(),
                &clients,
                !serial_tx.is_empty(),
                &stats,
            )?;
        }
    }
    Ok(())
}

/// Wait for the next serial-forward event instead of polling every few milliseconds.
///
/// The timeout keeps a queued reset request responsive even when every endpoint is idle.
fn wait_for_serial_forward_io(
    serial: &fs::File,
    listener: &UnixListener,
    tcp_listener: Option<&TcpListener>,
    clients: &[SerialForwardClient],
    serial_writable: bool,
    stats: &SerialForwardStats,
) -> Result<()> {
    let mut fds = Vec::with_capacity(3 + clients.len());
    let mut serial_events = libc::POLLIN;
    if serial_writable {
        serial_events |= libc::POLLOUT;
    }
    fds.push(libc::pollfd {
        fd: serial.as_raw_fd(),
        events: serial_events,
        revents: 0,
    });
    fds.push(libc::pollfd {
        fd: listener.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    });
    if let Some(tcp_listener) = tcp_listener {
        fds.push(libc::pollfd {
            fd: tcp_listener.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        });
    }
    for client in clients {
        if let Some(fd) = client.stream.raw_fd() {
            let mut events = libc::POLLIN;
            if !client.output.is_empty() {
                events |= libc::POLLOUT;
            }
            fds.push(libc::pollfd {
                fd,
                events,
                revents: 0,
            });
        }
    }
    let rc = unsafe {
        libc::poll(
            fds.as_mut_ptr(),
            fds.len() as libc::nfds_t,
            SERIAL_FORWARD_POLL_TIMEOUT_MS,
        )
    };
    stats.poll_calls.fetch_add(1, Ordering::Relaxed);
    if rc > 0 {
        stats.poll_ready.fetch_add(1, Ordering::Relaxed);
    } else if rc == 0 {
        stats.poll_timeouts.fetch_add(1, Ordering::Relaxed);
    }
    if rc < 0 {
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(error).context("serial forward poll failed");
        }
    }
    Ok(())
}

fn configure_serial_forward_socket(socket_path: &str) -> Result<()> {
    let gid = group_gid("dialout").context("failed to resolve dialout group")?;
    let c_path = CString::new(socket_path).context("serial forward socket path contains NUL")?;
    let rc = unsafe { libc::chown(c_path.as_ptr(), u32::MAX, gid) };
    if rc < 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("failed to set dialout group on {socket_path}"));
    }
    fs::set_permissions(socket_path, fs::Permissions::from_mode(0o770))
        .with_context(|| format!("failed to chmod serial forward socket {socket_path} to 0770"))?;
    Ok(())
}

fn group_gid(name: &str) -> Result<libc::gid_t> {
    let c_name = CString::new(name).context("group name contains NUL")?;
    let group = unsafe { libc::getgrnam(c_name.as_ptr()) };
    if group.is_null() {
        bail!("group {name:?} not found");
    }
    Ok(unsafe { (*group).gr_gid })
}

fn add_serial_forward_unix_client(
    clients: &mut Vec<SerialForwardClient>,
    stream: UnixStream,
) -> Result<()> {
    stream
        .set_nonblocking(true)
        .context("failed to set UDS client nonblocking")?;
    add_serial_forward_client(clients, Box::new(stream), SerialForwardTcpMode::Framed);
    Ok(())
}

fn add_serial_forward_tcp_client(
    clients: &mut Vec<SerialForwardClient>,
    stream: TcpStream,
    tcp_mode: SerialForwardTcpMode,
) -> Result<()> {
    stream
        .set_nonblocking(true)
        .context("failed to set TCP client nonblocking")?;
    stream
        .set_nodelay(true)
        .context("failed to disable Nagle buffering for TCP serial forward")?;
    add_serial_forward_client(clients, Box::new(stream), tcp_mode);
    Ok(())
}

trait SerialForwardStream: Read + Write {
    fn raw_fd(&self) -> Option<RawFd> {
        None
    }
}

impl SerialForwardStream for UnixStream {
    fn raw_fd(&self) -> Option<RawFd> {
        Some(self.as_raw_fd())
    }
}

impl SerialForwardStream for TcpStream {
    fn raw_fd(&self) -> Option<RawFd> {
        Some(self.as_raw_fd())
    }
}

fn add_serial_forward_client(
    clients: &mut Vec<SerialForwardClient>,
    stream: Box<dyn SerialForwardStream>,
    tcp_mode: SerialForwardTcpMode,
) {
    let id = clients
        .last()
        .map(|client| client.id.saturating_add(1))
        .unwrap_or(1);
    clients.push(SerialForwardClient::new(id, stream, tcp_mode));
}

fn broadcast_serial_output(
    clients: &mut Vec<SerialForwardClient>,
    records: &[Vec<u8>],
    wire_bytes: &[u8],
    raw_output: bool,
    stats: &SerialForwardStats,
) {
    let mut idx = 0;
    while idx < clients.len() {
        let accepted = if raw_output || clients[idx].is_rfc2217() {
            clients[idx].queue_output(wire_bytes)
        } else if clients[idx].text_mode {
            records
                .iter()
                .all(|record| clients[idx].queue_text_record(record))
        } else {
            records
                .iter()
                .all(|record| clients[idx].queue_output(record))
        };
        if accepted {
            SerialForwardStats::record_high_water(
                &stats.client_output_queue_high_water,
                clients[idx].output.len(),
            );
            idx += 1;
        } else {
            clients.remove(idx);
            stats.client_drops.fetch_add(1, Ordering::Relaxed);
        }
    }
}

struct SerialForwardClient {
    id: u64,
    stream: Box<dyn SerialForwardStream>,
    input: Vec<u8>,
    output: VecDeque<u8>,
    tcp_mode: SerialForwardTcpMode,
    rfc2217_mode: bool,
    // UDS/TCP input is auto-detected per client. Text clients receive the
    // matching human-readable response representation; framed clients keep
    // the length-prefixed CBOR stream.
    text_mode: bool,
    force_direct: bool,
}

impl SerialForwardClient {
    fn new(id: u64, stream: Box<dyn SerialForwardStream>, tcp_mode: SerialForwardTcpMode) -> Self {
        Self {
            id,
            stream,
            input: Vec::new(),
            output: VecDeque::new(),
            tcp_mode,
            rfc2217_mode: tcp_mode == SerialForwardTcpMode::Rfc2217,
            text_mode: false,
            force_direct: false,
        }
    }

    fn queue_output(&mut self, bytes: &[u8]) -> bool {
        let escaped_len = if self.rfc2217_mode {
            bytes
                .iter()
                .filter(|byte| **byte == RFC2217_IAC)
                .count()
                .saturating_add(bytes.len())
        } else {
            bytes.len()
        };
        if self.output.len().saturating_add(escaped_len) > SERIAL_FORWARD_MAX_PENDING {
            return false;
        }
        if self.rfc2217_mode {
            for byte in bytes {
                self.output.push_back(*byte);
                if *byte == RFC2217_IAC {
                    self.output.push_back(RFC2217_IAC);
                }
            }
        } else {
            self.output.extend(bytes);
        }
        true
    }

    fn queue_text_record(&mut self, record: &[u8]) -> bool {
        let Some(text) = firmware_record_text(record) else {
            return true;
        };
        queue_client_bytes(&mut self.output, text.as_bytes()).is_ok()
    }

    fn is_rfc2217(&self) -> bool {
        self.rfc2217_mode || self.tcp_mode == SerialForwardTcpMode::Rfc2217
    }

    fn flush_output(&mut self) -> Result<bool> {
        flush_queue_to_writer(&mut *self.stream, &mut self.output)
    }

    fn pump_to_serial(
        &mut self,
        serial_fd: RawFd,
        serial_tx: &mut VecDeque<u8>,
        serial_pending: &mut VecDeque<u8>,
        may_write: bool,
        serial_direct: bool,
        stats: &SerialForwardStats,
        board: &str,
        serial_log: Option<&Arc<Mutex<SerialForwardLog>>>,
        flash_log_quiet: bool,
    ) -> Result<(bool, bool, bool)> {
        let mut buf = [0_u8; SERIAL_FORWARD_IO_BUFFER_BYTES];
        let mut progressed = false;
        let mut input_closed = false;
        loop {
            match self.stream.read(&mut buf) {
                // A short-lived client such as `printf ... | socat` can write a
                // complete newline record and close before this nonblocking
                // loop reaches EOF. Drain the buffered record before removing
                // the client, otherwise its final command is silently lost.
                Ok(0) => {
                    input_closed = true;
                    break;
                }
                Ok(n) => {
                    self.input.extend_from_slice(&buf[..n]);
                    SerialForwardStats::record_high_water(
                        &stats.client_input_queue_high_water,
                        self.input.len(),
                    );
                    progressed = true;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    stats
                        .client_read_would_block
                        .fetch_add(1, Ordering::Relaxed);
                    break;
                }
                Err(error) => return Err(error).context("failed to read UDS client"),
            }
        }
        if may_write {
            progressed |= self.flush_complete_records(
                serial_fd,
                serial_tx,
                serial_pending,
                serial_direct,
                serial_log,
                board,
                flash_log_quiet,
            )?;
        } else if !may_write {
            progressed |= !self.input.is_empty();
            self.input.clear();
        }
        Ok((!input_closed, progressed, false))
    }

    fn flush_complete_records(
        &mut self,
        serial_fd: RawFd,
        serial_tx: &mut VecDeque<u8>,
        serial_pending: &mut VecDeque<u8>,
        serial_direct: bool,
        serial_log: Option<&Arc<Mutex<SerialForwardLog>>>,
        board: &str,
        flash_log_quiet: bool,
    ) -> Result<bool> {
        let mut progressed = false;
        loop {
            if self.input.is_empty() {
                return Ok(progressed);
            }
            if !self.force_direct && self.input.starts_with(SERIAL_FORWARD_FORCE_DIRECT_PREFIX) {
                self.input.drain(..SERIAL_FORWARD_FORCE_DIRECT_PREFIX.len());
                self.force_direct = true;
                progressed = true;
                if self.input.is_empty() {
                    return Ok(progressed);
                }
            }
            // A request-specific direct prefix is used by stage2/Recovery
            // handoffs. It must override the forward-wide sleepy policy for
            // this client; merely recording `self.force_direct` is
            // insufficient because the packet would otherwise remain queued.
            let direct_for_client = serial_direct || self.force_direct;
            if (self.tcp_mode == SerialForwardTcpMode::Rfc2217
                || self.tcp_mode == SerialForwardTcpMode::Auto)
                && self.input[0] == RFC2217_IAC
            {
                self.rfc2217_mode = true;
                let Some(record_len) =
                    handle_rfc2217_input(&self.input, serial_fd, serial_tx, &mut self.output)?
                else {
                    return Ok(progressed);
                };
                self.input.drain(..record_len);
                progressed = true;
                continue;
            }
            if self.rfc2217_mode {
                let record_len = self
                    .input
                    .iter()
                    .position(|byte| *byte == RFC2217_IAC)
                    .unwrap_or(self.input.len());
                if record_len == 0 {
                    return Ok(progressed);
                }
                queue_serial_bytes(serial_tx, &self.input[..record_len])?;
                self.input.drain(..record_len);
                progressed = true;
                continue;
            }
            let record_len = if self.input[0] == 0 {
                if self.input.len() < 4 {
                    return Ok(progressed);
                }
                let len = u32::from_be_bytes(self.input[..4].try_into().unwrap()) as usize;
                let total = 4 + len;
                if self.input.len() < total {
                    return Ok(progressed);
                }
                total
            } else if let Some(pos) = self
                .input
                .iter()
                .position(|byte| matches!(*byte, b'\n' | b'\r'))
            {
                // readline-style clients commonly terminate with CRLF.
                // Consume the pair as one text record; otherwise the LF is
                // seen on the next pass as an empty firmware command.
                if self.input[pos] == b'\r' && self.input.get(pos + 1) == Some(&b'\n') {
                    pos + 2
                } else {
                    pos + 1
                }
            } else {
                return Ok(progressed);
            };
            if self.input[0] == 0 {
                let body = &self.input[4..record_len];
                let raw_boot =
                    (body.len() >= 6 && body[..4] == DMESH_BOOT_MAGIC[..]).then_some(body);
                if let Some(payload) = raw_boot.as_deref() {
                    // DMB1 is an explicit bootstrap command for stage2.  It
                    // must not wait for the normal active/direct policy: the
                    // bootloader has only a bounded selector window and the
                    // managed forward is the sole UART reader.
                    queue_firmware_payload(serial_tx, payload)?;
                } else if direct_for_client {
                    record_serial_forward_tx_log(
                        serial_log,
                        board,
                        &self.input[..record_len],
                        flash_log_quiet,
                    );
                    queue_firmware_packet(serial_tx, &self.input[..record_len])?;
                } else {
                    record_serial_forward_tx_log(
                        serial_log,
                        board,
                        &self.input[..record_len],
                        flash_log_quiet,
                    );
                    queue_firmware_packet(serial_pending, &self.input[..record_len])?;
                }
            } else {
                self.text_mode = true;
                let line = std::str::from_utf8(&self.input[..record_len])?.trim();
                // Empty lines are harmless interactive-console input. In
                // particular, tolerate a lone LF following a CR from a
                // client whose terminal emits mixed line endings.
                if !line.is_empty() {
                    match firmware_command_cbor(line) {
                        Ok(frame) => {
                            record_serial_forward_tx_log(
                                serial_log,
                                board,
                                &frame,
                                flash_log_quiet,
                            );
                            if direct_for_client {
                                queue_firmware_packet(serial_tx, &frame)?;
                            } else {
                                queue_firmware_packet(serial_pending, &frame)?;
                            }
                        }
                        Err(error) => {
                            queue_client_bytes(
                                &mut self.output,
                                format!("lmesh command error: {error}\n").as_bytes(),
                            )?;
                        }
                    }
                }
            }
            self.input.drain(..record_len);
            progressed = true;
        }
    }
}

/// Append a grep-friendly, lossless logfmt event to one device's capture log.
///
/// UART reads are arbitrary byte chunks rather than lines. `text` makes normal
/// firmware output searchable, while `hex` retains the exact bytes for boot ROM
/// or flashing traffic that is not valid UTF-8.
struct SerialForwardLog {
    file: fs::File,
    path: PathBuf,
    schema: FirmwareSchema,
    raw_text: BTreeMap<String, Vec<u8>>,
    ppp_active: BTreeMap<String, bool>,
    ppp_escaped: BTreeMap<String, bool>,
    ppp_payload: BTreeMap<String, bool>,
}

impl SerialForwardLog {
    fn open(path: &str) -> Result<Self> {
        let path = PathBuf::from(path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!("failed to create serial log directory {}", parent.display())
            })?;
        }
        let file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .with_context(|| format!("failed to open serial log {}", path.display()))?;
        Ok(Self {
            file,
            path,
            schema: FirmwareSchema::load(),
            raw_text: BTreeMap::new(),
            ppp_active: BTreeMap::new(),
            ppp_escaped: BTreeMap::new(),
            ppp_payload: BTreeMap::new(),
        })
    }

    fn rotate_if_needed(&mut self) -> Result<()> {
        if self.file.metadata()?.len() < SERIAL_LOG_MAX_BYTES {
            return Ok(());
        }
        let rotated = self.path.with_extension("log.1");
        fs::rename(&self.path, &rotated).with_context(|| {
            format!(
                "failed to rotate serial log {} to {}",
                self.path.display(),
                rotated.display()
            )
        })?;
        self.file = fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&self.path)
            .with_context(|| format!("failed to reopen serial log {}", self.path.display()))?;
        Ok(())
    }

    /// Log received UART bytes in protocol-aware form. ROM/stage2 output is
    /// not PPP and is reconstructed into complete text lines. PPP frames are
    /// represented by their decoded CBOR notification or boot identity; raw
    /// hex is retained only for an undecodable payload.
    fn append_rx(&mut self, host: &str, bytes: &[u8], records: &[Vec<u8>]) -> Result<usize> {
        self.rotate_if_needed()?;
        let mut raw_lines = Vec::new();
        let active = self.ppp_active.entry(host.to_owned()).or_default();
        let escaped = self.ppp_escaped.entry(host.to_owned()).or_default();
        let payload_seen = self.ppp_payload.entry(host.to_owned()).or_default();
        let raw = self.raw_text.entry(host.to_owned()).or_default();
        for byte in bytes {
            if *active {
                if *escaped {
                    *escaped = false;
                    *payload_seen = true;
                } else if *byte == FIRMWARE_UART_ESCAPE {
                    *escaped = true;
                } else if *byte == FIRMWARE_UART_FLAG {
                    *active = false;
                    *payload_seen = false;
                }
                continue;
            }
            // The first byte after a completed ROM line selects the parser:
            // 0x7e starts PPP, while any other byte belongs to the ROM/text
            // stream. Do not treat a stray '~' inside an ASCII boot line as a
            // PPP delimiter.
            if *byte == FIRMWARE_UART_FLAG && raw.is_empty() {
                *active = true;
                *escaped = false;
                *payload_seen = false;
                continue;
            }
            *payload_seen = true;
            raw.push(*byte);
            if *byte == b'\n' || raw.len() >= 4096 {
                raw_lines.push(std::mem::take(raw));
            }
        }
        let raw_line_count = raw_lines.len();
        for line in raw_lines {
            self.write_text_or_binary(host, &line)?;
        }

        let mut logged = 0;
        for record in records {
            let Some(payload) = mesh::cbor::decode_stream_frame(record).ok() else {
                writeln!(
                    self.file,
                    "ts_ms={} host={} dir=rx undecoded=true bytes={} hex={}",
                    now_millis_u64(),
                    host,
                    record.len(),
                    compact_serial_hex(record),
                )?;
                logged += 1;
                continue;
            };
            if let Some(event) = nan_sleepy_start_event(payload) {
                writeln!(
                    self.file,
                    "ts_ms={} host={} dir=rx event=nan.sleepy_start tag=6 flags={} lora_rx_delta={} nan_beacon_delta={} cluster_changed={}",
                    now_millis_u64(),
                    host,
                    event.flags,
                    event.lora_rx_delta,
                    event.nan_beacon_delta,
                    event.cluster_changed,
                )?;
                logged += 1;
                continue;
            }
            // The shared UART decoder is deliberately permissive while it
            // resynchronizes. A stale flag can therefore make a ROM/app
            // text burst look like one PPP payload. Never call that CBOR:
            // classify printable payloads as text and keep binary lossless.
            let is_boot_identity = is_boot_identity_payload(payload);
            let is_boot_event = is_boot_event_payload(payload);
            let is_boot_selector = is_boot_selector_payload(payload);
            if !is_boot_event
                && !is_boot_selector
                && !payload.is_empty()
                && payload.first().map(|byte| byte >> 5) != Some(5)
            {
                self.write_text_or_binary(host, payload)?;
                logged += 1;
                continue;
            }
            let fields = if is_boot_identity {
                format!("kind=boot identity={}", boot_identity_json(payload))
            } else if is_boot_event {
                format!("kind=boot event={}", boot_event_json(payload))
            } else if is_boot_selector {
                format!("kind=boot selector_hex={}", compact_serial_hex(payload))
            } else if let Ok(decoded) = self.schema.decode_packet(payload) {
                // decode_json represents schema/type failures as an error
                // object. Do not make malformed compact-CBOR look like a
                // valid firmware notification in the serial evidence.
                if let Some(error) = decoded.get("error").and_then(Value::as_str) {
                    format!(
                        "kind=cbor_error message={:?} {} payload_hex={}",
                        error,
                        cbor_first_byte_summary(payload),
                        compact_serial_hex(payload)
                    )
                } else {
                    cbor_log_fields(&decoded)
                }
            } else {
                format!(
                    "kind=cbor_error {} payload_hex={}",
                    cbor_first_byte_summary(payload),
                    compact_serial_hex(payload),
                )
            };
            let fields = truncate_serial_log_field(&fields);
            writeln!(
                self.file,
                "ts_ms={} host={} dir=rx bytes={} {}",
                now_millis_u64(),
                host,
                payload.len(),
                fields,
            )?;
            logged += 1;
        }
        self.file
            .flush()
            .context("failed to flush serial log record")?;
        Ok(logged + raw_line_count)
    }

    fn write_text_or_binary(&mut self, host: &str, bytes: &[u8]) -> Result<()> {
        if bytes.is_empty() {
            return Ok(());
        }
        if serial_bytes_are_text(bytes) {
            for line in bytes.split_inclusive(|byte| *byte == b'\n') {
                let text = serial_text_preview(line);
                if !text.is_empty() {
                    writeln!(
                        self.file,
                        "ts_ms={} host={} dir=rx kind=text bytes={} text={:?}",
                        now_millis_u64(),
                        host,
                        line.len(),
                        truncate_serial_log_field(&text),
                    )?;
                }
            }
        } else {
            writeln!(
                self.file,
                "ts_ms={} host={} dir=rx kind=raw_binary bytes={} hex={}",
                now_millis_u64(),
                host,
                bytes.len(),
                compact_serial_hex(bytes),
            )?;
        }
        Ok(())
    }
}

/// Stage2/Recovery boot identities are normal CBOR events.  They use an
/// indefinite map and tuple payload (`{7:60000,6:[...]}`), so they cannot be
/// passed through the regular method/payload-map JSON adapter.  Recognize the
/// registered event directly and keep it on the same packet log path as the
/// old fixed DMB1 compatibility record.
fn is_boot_identity_payload(payload: &[u8]) -> bool {
    (payload.len() >= DMESH_BOOT_HELLO_LEN && payload[..4] == DMESH_BOOT_MAGIC[..])
        || payload
            .windows(3)
            .any(|window| window == [0x19, 0xea, 0x60])
}

fn boot_event_id(payload: &[u8]) -> Option<u64> {
    payload.windows(3).find_map(|window| {
        if window[0] == 0x19 && window[1] == 0xea && (0x60..=0x63).contains(&window[2]) {
            Some(u64::from(window[2]) + 0xea00)
        } else {
            None
        }
    })
}

fn is_boot_event_payload(payload: &[u8]) -> bool {
    is_boot_identity_payload(payload) || boot_event_id(payload).is_some()
}

fn is_boot_selector_payload(payload: &[u8]) -> bool {
    payload.len() == 10
        && payload[..3] == [0xa2, 0x00, 0x1a]
        && payload[3..7] == DMESH_BOOT_METHOD_SELECT.to_be_bytes()
        && payload[7..9] == [0x06, 0x81]
        && matches!(payload[9], 0x01 | 0x02)
}

fn serial_bytes_are_text(bytes: &[u8]) -> bool {
    let printable = bytes
        .iter()
        .filter(|byte| matches!(**byte, b'\t' | b'\r' | b'\n' | 0x20..=0x7e))
        .count();
    printable * 100 >= bytes.len().saturating_mul(90)
}

fn serial_text_preview(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len());
    for byte in bytes {
        match *byte {
            b'\r' | b'\n' => {}
            b'\t' | 0x20..=0x7e => text.push(*byte as char),
            value => text.push_str(&format!("\\x{value:02x}")),
        }
    }
    text
}

/// Render the decoded compact-CBOR envelope as logfmt. The serial header is
/// already flat, so keeping the CBOR map nested as JSON makes common fields
/// such as `method` and `payload.message` hard to scan with standard tools.
/// `status=ok` is deliberately omitted: it is the normal firmware response
/// value, not a transport or delivery assertion.
fn cbor_log_fields(value: &Value) -> String {
    let mut fields = Vec::new();
    flatten_cbor_log_value(&mut fields, None, value, true);
    fields.join(" ")
}

fn flatten_cbor_log_value(
    fields: &mut Vec<String>,
    prefix: Option<&str>,
    value: &Value,
    top_level: bool,
) {
    match value {
        Value::Object(values) => {
            for (key, value) in values {
                if top_level && key == "status" && value.as_str() == Some("ok") {
                    continue;
                }
                let key = prefix
                    .map(|prefix| format!("{prefix}.{key}"))
                    .unwrap_or_else(|| key.clone());
                flatten_cbor_log_value(fields, Some(&key), value, false);
            }
        }
        Value::Array(_) => {
            if let Some(key) = prefix {
                fields.push(format!("{key}={}", logfmt_json_value(value)));
            }
        }
        _ => {
            if let Some(key) = prefix {
                fields.push(format!("{key}={}", logfmt_json_value(value)));
            }
        }
    }
}

fn logfmt_json_value(value: &Value) -> String {
    match value {
        Value::String(value)
            if !value.is_empty()
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_graphic() && !matches!(byte, b'=' | b'"')) =>
        {
            value.clone()
        }
        _ => value.to_string(),
    }
}

fn truncate_serial_log_field(value: &str) -> String {
    if value.len() <= SERIAL_LOG_FIELD_MAX {
        return value.to_owned();
    }
    let mut result = value
        .char_indices()
        .take_while(|(index, _)| *index < SERIAL_LOG_FIELD_MAX.saturating_sub(3))
        .map(|(_, character)| character)
        .collect::<String>();
    result.push_str("...");
    result
}

fn compact_serial_hex(bytes: &[u8]) -> String {
    let ff_count = bytes.iter().filter(|byte| **byte == 0xff).count();
    if bytes.len() >= 32 && ff_count * 100 >= bytes.len().saturating_mul(90) {
        return "ff...".to_owned();
    }
    truncate_serial_log_field(&hex_lower(bytes))
}

fn cbor_uint_at(payload: &[u8], offset: &mut usize) -> Option<u64> {
    let first = *payload.get(*offset)?;
    *offset += 1;
    if first >> 5 != 0 {
        return None;
    }
    let additional = first & 0x1f;
    if additional < 24 {
        return Some(additional as u64);
    }
    let width = match additional {
        24 => 1,
        25 => 2,
        26 => 4,
        27 => 8,
        _ => return None,
    };
    let end = offset.checked_add(width)?;
    let bytes = payload.get(*offset..end)?;
    *offset = end;
    Some(
        bytes
            .iter()
            .fold(0_u64, |value, byte| (value << 8) | u64::from(*byte)),
    )
}

fn cbor_argument_at(payload: &[u8], offset: &mut usize, first: u8) -> Option<u64> {
    let additional = first & 0x1f;
    if additional < 24 {
        return Some(additional as u64);
    }
    let width = match additional {
        24 => 1,
        25 => 2,
        26 => 4,
        27 => 8,
        _ => return None,
    };
    let end = offset.checked_add(width)?;
    let bytes = payload.get(*offset..end)?;
    *offset = end;
    Some(
        bytes
            .iter()
            .fold(0_u64, |value, byte| (value << 8) | u64::from(*byte)),
    )
}

fn cbor_tuple_value(payload: &[u8], offset: &mut usize) -> Option<Value> {
    let first = *payload.get(*offset)?;
    *offset += 1;
    match first >> 5 {
        0 => Some(Value::from(cbor_argument_at(payload, offset, first)?)),
        1 => {
            let argument = cbor_argument_at(payload, offset, first)?;
            let value = i64::try_from(argument)
                .ok()?
                .checked_add(1)?
                .checked_neg()?;
            Some(Value::from(value))
        }
        2 => {
            let length = usize::try_from(cbor_argument_at(payload, offset, first)?).ok()?;
            let end = offset.checked_add(length)?;
            let bytes = payload.get(*offset..end)?;
            *offset = end;
            Some(Value::String(hex_lower(bytes)))
        }
        _ => None,
    }
}

fn boot_identity_tuple(payload: &[u8]) -> Option<Vec<Value>> {
    let mut offset = 0;
    if *payload.get(offset)? != 0xbf {
        return None;
    }
    offset += 1;
    let mut tuple = None;
    while *payload.get(offset)? != 0xff {
        let key = cbor_uint_at(payload, &mut offset)?;
        if key == 7 {
            let _ = cbor_uint_at(payload, &mut offset)?;
        } else if key == 6 {
            if *payload.get(offset)? != 0x9f {
                return None;
            }
            offset += 1;
            let mut values = Vec::new();
            while *payload.get(offset)? != 0xff {
                values.push(cbor_tuple_value(payload, &mut offset)?);
            }
            offset += 1;
            tuple = Some(values);
        } else {
            return None;
        }
    }
    Some(tuple?)
}

fn cbor_major_type_name(byte: u8) -> &'static str {
    match byte >> 5 {
        0 => "unsigned",
        1 => "negative",
        2 => "bytes",
        3 => "text",
        4 => "array",
        5 => "map",
        6 => "tag",
        _ => "simple/float",
    }
}

fn cbor_first_byte_summary(payload: &[u8]) -> String {
    match payload.first().copied() {
        Some(byte) => format!(
            "first_byte=0x{byte:02x} major_type={}",
            cbor_major_type_name(byte),
        ),
        None => "first_byte=none major_type=empty".to_owned(),
    }
}

fn record_serial_forward_rx_log(
    log: Option<&Arc<Mutex<SerialForwardLog>>>,
    stats: &SerialForwardStats,
    board: &str,
    bytes: &[u8],
    records: &[Vec<u8>],
    suppressed: bool,
) {
    if suppressed {
        stats.log_suppressed_records.fetch_add(1, Ordering::Relaxed);
        stats
            .log_suppressed_bytes
            .fetch_add(bytes.len() as u64, Ordering::Relaxed);
        return;
    }
    let Some(log) = log else {
        return;
    };
    let mut sink = log.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Err(error) = sink.rotate_if_needed() {
        tracing::warn!(forward_id = %board, direction = "tx", error = %error, "serial_forward_log_rotation_failed");
        return;
    }
    match sink.append_rx(board, bytes, records) {
        Ok(count) => {
            stats
                .log_records
                .fetch_add(count.max(1) as u64, Ordering::Relaxed);
        }
        Err(error) => {
            stats.log_write_errors.fetch_add(1, Ordering::Relaxed);
            tracing::warn!(forward_id = %board, direction = "rx", error = %error, "serial_forward_log_write_failed");
        }
    }
}

/// Log the complete packet accepted from a managed client, after consuming
/// the UDS length/control envelope.  The old logger recorded that envelope
/// verbatim (`DMESH-DIRECT`), which made an internal lmesh marker look like a
/// physical UART protocol.  TX now uses the same CBOR classification as RX.
fn record_serial_forward_tx_log(
    log: Option<&Arc<Mutex<SerialForwardLog>>>,
    host: &str,
    stream_frame: &[u8],
    suppressed: bool,
) {
    if suppressed {
        return;
    }
    let Some(log) = log else {
        return;
    };
    let mut sink = log.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    // A boot/flash client may prepend the internal direct-delivery marker.
    // That marker is consumed by the forward and is not part of the UDS
    // stream envelope.  Strip it before decoding so TX logs describe the
    // actual CBOR packet instead of falling back to an unhelpful hex dump.
    let stream_frame = stream_frame
        .strip_prefix(SERIAL_FORWARD_FORCE_DIRECT_PREFIX)
        .unwrap_or(stream_frame);
    let payload = mesh::cbor::decode_stream_frame(stream_frame).unwrap_or(stream_frame);
    let fields = if is_boot_identity_payload(payload) {
        format!("kind=boot identity={}", boot_identity_json(payload))
    } else if is_boot_event_payload(payload) {
        format!("kind=boot event={}", boot_event_json(payload))
    } else if is_boot_selector_payload(payload) {
        format!("kind=boot selector_hex={}", compact_serial_hex(payload))
    } else if payload.first().map(|byte| byte >> 5) == Some(5)
        || payload.first().map(|byte| byte >> 5) == Some(4)
    {
        match sink.schema.decode_packet(payload) {
            Ok(decoded) => cbor_log_fields(&decoded),
            Err(error) => format!(
                "kind=cbor_error message={:?} {}",
                error,
                cbor_first_byte_summary(payload)
            ),
        }
    } else {
        format!("kind=raw hex={}", compact_serial_hex(payload))
    };
    let _ = writeln!(
        sink.file,
        "ts_ms={} host={} dir=tx bytes={} {}",
        now_millis_u64(),
        host,
        payload.len(),
        truncate_serial_log_field(&fields),
    );
    let _ = sink.file.flush();
}

fn queue_serial_bytes(queue: &mut VecDeque<u8>, bytes: &[u8]) -> Result<()> {
    if queue.len().saturating_add(bytes.len()) > SERIAL_FORWARD_MAX_PENDING {
        bail!(
            "serial TX queue exceeded {} bytes",
            SERIAL_FORWARD_MAX_PENDING
        );
    }
    queue.extend(bytes);
    Ok(())
}

#[derive(Default)]
struct NanSleepyStartEvent {
    flags: u16,
    lora_rx_delta: u32,
    nan_beacon_delta: u32,
    cluster_changed: bool,
}

fn nan_sleepy_start_event(payload: &[u8]) -> Option<NanSleepyStartEvent> {
    let mut decoder = Decoder::new(payload);
    if decoder.tag().ok()?.as_u64() != u64::from(NAN_SLEEPY_START_TAG) {
        return None;
    }
    let map_len = decoder.map().ok()?;
    let mut event = NanSleepyStartEvent::default();
    let mut remaining = map_len;
    loop {
        if remaining == Some(0) {
            break;
        }
        if remaining.is_none() && decoder.datatype().ok()? == Type::Break {
            decoder.skip().ok()?;
            break;
        }
        let key = decoder.u8().ok()?;
        match key {
            0 => event.flags = decoder.u16().ok()?,
            1 => event.lora_rx_delta = decoder.u32().ok()?,
            2 => event.nan_beacon_delta = decoder.u32().ok()?,
            _ => {
                decoder.skip().ok()?;
            }
        }
        if let Some(value) = remaining.as_mut() {
            *value = value.saturating_sub(1);
        }
    }
    event.cluster_changed = event.flags & (1 << 2) != 0;
    Some(event)
}

fn queue_firmware_packet(queue: &mut VecDeque<u8>, stream_frame: &[u8]) -> Result<()> {
    let payload = mesh::cbor::decode_stream_frame(stream_frame)?;
    queue_firmware_payload(queue, payload)
}

/// Queue one already-decoded physical UART payload.  Normal firmware records
/// are compact CBOR, but stage2 uses a fixed DMB1 payload so it can run without
/// a CBOR implementation.  Both payload kinds use the same PPP envelope.
fn queue_firmware_payload(queue: &mut VecDeque<u8>, payload: &[u8]) -> Result<()> {
    let wire = uart_codec::codec::encode_payload(payload, mesh::cbor::ESP_RECORD_MAX)
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    queue_serial_bytes(queue, &wire)
}

/// Decode one firmware response for a client that selected text input.
/// Framed clients receive the original stream record unchanged. The firmware
/// response text is carried in its private CBOR payload tag 32; retain the
/// generic message/error/status fallbacks for control-plane records.
fn firmware_record_text(record: &[u8]) -> Option<String> {
    let payload = mesh::cbor::decode_stream_frame(record).ok()?;
    if let Some(event) = nan_sleepy_start_event(payload) {
        return Some(format!(
            "event type=nan.sleepy_start flags={} lora_rx_delta={} nan_beacon_delta={} cluster_changed={}",
            event.flags, event.lora_rx_delta, event.nan_beacon_delta, event.cluster_changed,
        ));
    }
    let decoded = mesh::cbor::decode_json(payload, &mesh::cbor::Catalog::default()).ok()?;
    let message = decoded
        .get("payload")
        .and_then(Value::as_object)
        .and_then(|payload| payload.get("32"))
        .and_then(Value::as_str)
        .or_else(|| decoded.get("message").and_then(Value::as_str))
        .or_else(|| decoded.get("error").and_then(Value::as_str))
        .or_else(|| decoded.get("status").and_then(Value::as_str))?;
    let mut text = message.to_owned();
    if !text.ends_with('\n') {
        text.push('\n');
    }
    Some(text)
}

/// Return the current write policy advertised by a firmware status/event.
/// Infrastructure mode is continuously reachable; a sleepy device is only
/// directly writable while its bounded active session is reported true.
fn firmware_record_direct_mode(record: &[u8]) -> Option<bool> {
    let payload = mesh::cbor::decode_stream_frame(record).ok()?;
    if nan_sleepy_start_event(payload).is_some() {
        // NAN_SLEEPY_START proves that the device has just opened a short
        // UART receive window; it does not prove that a queued command may be
        // written immediately.  Keep the command in serial_pending so the
        // caller below can put `mode active_ms=1000` first and only then
        // release the command.  Returning Some(true) here used to promote
        // the forward to direct-write mode and bypass that ordering, which
        // lost status/flash commands on sleepy devices.
        return None;
    }
    let text = firmware_record_text(record)?;
    let active = text
        .split_whitespace()
        .find_map(|field| field.strip_prefix("active="))?;
    // `active=infra` is the continuously reachable gateway role. The
    // infra_active field describes only a bounded target/session lease and
    // must not make lora1's own UART queue sleepy.
    if active == "infra" {
        return Some(true);
    }
    if active != "companion" && active != "sleepy" {
        return None;
    }
    // A sleepy device can expose a bounded active window. In that case the
    // role remains `active=sleepy`, while `infra_active=true` is the actual
    // write-reachability signal.
    text.split_whitespace()
        .find_map(|field| field.strip_prefix("infra_active="))
        .and_then(|value| match value {
            "true" => Some(true),
            "false" => Some(false),
            _ => None,
        })
}

fn update_firmware_state_from_text(state: &Arc<Mutex<FirmwareState>>, text: &str) {
    let text = text.trim();
    let is_boot = text.starts_with("event type=boot.state");
    let is_mode = text.starts_with("event type=mode.state") || text.starts_with("mode active=");
    if !is_boot && !is_mode {
        return;
    }
    let mut state = state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    for field in text.split_whitespace() {
        if let Some(value) = field.strip_prefix("mode=") {
            state.mode = Some(value.to_string());
        } else if let Some(value) = field.strip_prefix("active=") {
            state.mode = Some(value.to_string());
        } else if let Some(value) = field.strip_prefix("infra_active=") {
            state.infra_active = match value {
                "true" => Some(true),
                "false" => Some(false),
                _ => state.infra_active,
            };
        } else if let Some(value) = field.strip_prefix("phase=") {
            state.phase = Some(value.to_string());
        } else if let Some(value) = field.strip_prefix("rebooted=") {
            state.rebooted = match value {
                "true" => Some(true),
                "false" => Some(false),
                _ => state.rebooted,
            };
        }
    }
    state.last_event_ms = now_millis_u64();
}

fn update_firmware_state_from_boot(state: &Arc<Mutex<FirmwareState>>, payload: &[u8]) {
    if payload.len() < DMESH_BOOT_HELLO_LEN
        || payload[..4] != DMESH_BOOT_MAGIC[..]
        || payload[4] != DMESH_BOOT_VERSION
        || payload[5] != 1
    {
        return;
    }
    let role = match payload[6] {
        1 => "main",
        2 => "recovery",
        3 => "stage2",
        _ => "unknown",
    };
    let partition = match payload[7] {
        0 => "bootloader",
        1 => "main",
        2 => "recovery",
        _ => "unknown",
    };
    let mut state = state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    state.role = Some(role.to_string());
    state.partition = Some(partition.to_string());
    state.reset_reason = Some(payload[8]);
    state.mac = Some(
        payload[12..18]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<Vec<_>>()
            .join(":"),
    );
    state.phase = Some("started".to_string());
    state.last_event_ms = now_millis_u64();
}

fn queue_client_bytes(queue: &mut VecDeque<u8>, bytes: &[u8]) -> Result<()> {
    if queue.len().saturating_add(bytes.len()) > SERIAL_FORWARD_MAX_PENDING {
        bail!(
            "serial forward client output queue exceeded {} bytes",
            SERIAL_FORWARD_MAX_PENDING
        );
    }
    queue.extend(bytes);
    Ok(())
}

fn flush_queue_to_writer(writer: &mut dyn Write, queue: &mut VecDeque<u8>) -> Result<bool> {
    let mut progressed = false;
    while !queue.is_empty() {
        let (front, _) = queue.as_slices();
        if front.is_empty() {
            break;
        }
        match writer.write(front) {
            Ok(0) => break,
            Ok(n) => {
                queue.drain(..n);
                progressed = true;
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error).context("failed to flush queued serial forward bytes"),
        }
    }
    Ok(progressed)
}

fn handle_rfc2217_input(
    input: &[u8],
    serial_fd: RawFd,
    serial_tx: &mut VecDeque<u8>,
    output: &mut VecDeque<u8>,
) -> Result<Option<usize>> {
    if input.len() < 2 {
        return Ok(None);
    }
    if input[1] == RFC2217_IAC {
        queue_serial_bytes(serial_tx, &[RFC2217_IAC])?;
        return Ok(Some(2));
    }
    if matches!(
        input[1],
        RFC2217_WILL | RFC2217_WONT | RFC2217_DO | RFC2217_DONT
    ) {
        if input.len() < 3 {
            return Ok(None);
        }
        respond_rfc2217_option(output, input[1], input[2])?;
        return Ok(Some(3));
    }
    if input[1] != RFC2217_SB {
        return Ok(Some(2));
    }
    let Some((end_idx, terminator_len)) = rfc2217_subnegotiation_end(input) else {
        return Ok(None);
    };
    if input.len() < 3 || input[2] != RFC2217_COM_PORT_OPTION {
        return Ok(Some(end_idx + terminator_len));
    }
    apply_rfc2217_com_port_option(serial_fd, output, &input[2..end_idx])?;
    Ok(Some(end_idx + terminator_len))
}

fn respond_rfc2217_option(output: &mut VecDeque<u8>, verb: u8, option: u8) -> Result<()> {
    let supported = matches!(option, RFC2217_BINARY | RFC2217_COM_PORT_OPTION);
    let response = match (verb, supported) {
        (RFC2217_DO, true) => [RFC2217_IAC, RFC2217_WILL, option],
        (RFC2217_WILL, true) => [RFC2217_IAC, RFC2217_DO, option],
        (RFC2217_DO, false) => [RFC2217_IAC, RFC2217_WONT, option],
        (RFC2217_WILL, false) => [RFC2217_IAC, RFC2217_DONT, option],
        (RFC2217_DONT, _) => [RFC2217_IAC, RFC2217_WONT, option],
        (RFC2217_WONT, _) => [RFC2217_IAC, RFC2217_DONT, option],
        _ => return Ok(()),
    };
    queue_client_bytes(output, &response)
}

fn rfc2217_subnegotiation_end(input: &[u8]) -> Option<(usize, usize)> {
    input
        .windows(2)
        .enumerate()
        .skip(2)
        .find_map(|(idx, window)| {
            (window[0] == RFC2217_IAC && (window[1] == RFC2217_SE || window[1] == RFC2217_SE_ALT))
                .then_some((idx, 2))
        })
}

fn apply_rfc2217_com_port_option(
    fd: RawFd,
    output: &mut VecDeque<u8>,
    payload: &[u8],
) -> Result<()> {
    if payload.len() < 2 || payload[0] != RFC2217_COM_PORT_OPTION {
        return Ok(());
    }
    let command = payload[1];
    let args = &payload[2..];
    match command {
        RFC2217_SET_BAUDRATE => {
            if args.len() < 4 {
                bail!("short RFC2217 SET-BAUDRATE command");
            }
            let baud = u32::from_be_bytes([args[0], args[1], args[2], args[3]]);
            tracing::debug!(baud, "rfc2217_set_baudrate");
            if baud != 0 {
                let _ = set_serial_baud(fd, baud);
            }
            ack_rfc2217_com_port_option(output, command, args)?;
        }
        RFC2217_SET_DATASIZE => {
            if let Some(bits) = args.first().copied()
                && bits != 0
            {
                tracing::debug!(bits, "rfc2217_set_datasize");
                let _ = set_serial_data_size(fd, bits);
            }
            ack_rfc2217_com_port_option(output, command, args)?;
        }
        RFC2217_SET_PARITY => {
            if let Some(parity) = args.first().copied()
                && parity != 0
            {
                tracing::debug!(parity, "rfc2217_set_parity");
                let _ = set_serial_parity(fd, parity);
            }
            ack_rfc2217_com_port_option(output, command, args)?;
        }
        RFC2217_SET_STOPSIZE => {
            if let Some(stop_bits) = args.first().copied()
                && stop_bits != 0
            {
                tracing::debug!(stop_bits, "rfc2217_set_stopsize");
                let _ = set_serial_stop_size(fd, stop_bits);
            }
            ack_rfc2217_com_port_option(output, command, args)?;
        }
        RFC2217_SET_CONTROL => {
            if let Some(control) = args.first().copied() {
                tracing::debug!(control, "rfc2217_set_control");
                let _ = set_serial_control(fd, control);
            }
            ack_rfc2217_com_port_option(output, command, args)?;
        }
        RFC2217_PURGE_DATA => {
            if let Some(purge) = args.first().copied() {
                let _ = purge_serial_data(fd, purge);
            }
            ack_rfc2217_com_port_option(output, command, args)?;
        }
        _ => {}
    }
    Ok(())
}

fn ack_rfc2217_com_port_option(output: &mut VecDeque<u8>, command: u8, args: &[u8]) -> Result<()> {
    let mut response = Vec::with_capacity(args.len() + 6);
    response.extend_from_slice(&[
        RFC2217_IAC,
        RFC2217_SB,
        RFC2217_COM_PORT_OPTION,
        command.saturating_add(100),
    ]);
    for byte in args {
        response.push(*byte);
        if *byte == RFC2217_IAC {
            response.push(RFC2217_IAC);
        }
    }
    response.extend_from_slice(&[RFC2217_IAC, RFC2217_SE]);
    queue_client_bytes(output, &response)
}

fn update_termios(fd: RawFd, update: impl FnOnce(&mut libc::termios) -> Result<()>) -> Result<()> {
    let mut termios = unsafe {
        let mut termios = std::mem::zeroed();
        if libc::tcgetattr(fd, &mut termios) != 0 {
            return Err(std::io::Error::last_os_error()).context("tcgetattr failed");
        }
        termios
    };
    update(&mut termios)?;
    if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &termios) } != 0 {
        return Err(std::io::Error::last_os_error()).context("tcsetattr failed");
    }
    Ok(())
}

fn set_serial_baud(fd: RawFd, baud: u32) -> Result<()> {
    let speed = baud_to_speed(baud)?;
    update_termios(fd, |termios| {
        if unsafe { libc::cfsetspeed(termios, speed) } != 0 {
            return Err(std::io::Error::last_os_error()).context("cfsetspeed failed");
        }
        Ok(())
    })
}

fn set_serial_data_size(fd: RawFd, bits: u8) -> Result<()> {
    update_termios(fd, |termios| {
        termios.c_cflag &= !libc::CSIZE;
        termios.c_cflag |= match bits {
            5 => libc::CS5,
            6 => libc::CS6,
            7 => libc::CS7,
            8 => libc::CS8,
            _ => bail!("unsupported RFC2217 data size {bits}"),
        };
        Ok(())
    })
}

fn set_serial_parity(fd: RawFd, parity: u8) -> Result<()> {
    update_termios(fd, |termios| {
        termios.c_cflag &= !(libc::PARENB | libc::PARODD);
        match parity {
            1 => {}
            2 => {
                termios.c_cflag |= libc::PARENB | libc::PARODD;
            }
            3 => {
                termios.c_cflag |= libc::PARENB;
            }
            _ => bail!("unsupported RFC2217 parity {parity}"),
        }
        Ok(())
    })
}

fn set_serial_stop_size(fd: RawFd, stop_bits: u8) -> Result<()> {
    update_termios(fd, |termios| {
        match stop_bits {
            1 => termios.c_cflag &= !libc::CSTOPB,
            2 => termios.c_cflag |= libc::CSTOPB,
            _ => bail!("unsupported RFC2217 stop size {stop_bits}"),
        }
        Ok(())
    })
}

fn set_serial_control(fd: RawFd, control: u8) -> Result<()> {
    match control {
        5 => {
            if unsafe { libc::ioctl(fd, libc::TIOCSBRK) } < 0 {
                return Err(std::io::Error::last_os_error()).context("TIOCSBRK failed");
            }
        }
        6 => {
            if unsafe { libc::ioctl(fd, libc::TIOCCBRK) } < 0 {
                return Err(std::io::Error::last_os_error()).context("TIOCCBRK failed");
            }
        }
        7 | 10 => {}
        // DTR/RTS are deliberately ignored.  CP210x modem transitions are
        // wired to ESP EN/GPIO0 and can reset or strap a board.  Bootloader
        // and recovery flashing owns modem control through direct esptool;
        // lmesh is a passive diagnostics forward only.
        8 | 9 | 11 | 12 => {}
        _ => {}
    }
    Ok(())
}

fn purge_serial_data(fd: RawFd, purge: u8) -> Result<()> {
    let queue = match purge {
        1 => libc::TCIFLUSH,
        2 => libc::TCOFLUSH,
        3 => libc::TCIOFLUSH,
        _ => return Ok(()),
    };
    if unsafe { libc::tcflush(fd, queue) } != 0 {
        return Err(std::io::Error::last_os_error()).context("tcflush failed");
    }
    Ok(())
}

/// Convert the lmesh debug command boundary to the firmware's compact-CBOR
/// wire format. Text never reaches the ESP UART: it is only accepted here so
/// existing JSONL/MCP tooling can keep a convenient command parameter.
fn firmware_command_cbor(command: &str) -> Result<Vec<u8>> {
    let mut words = command.split_ascii_whitespace();
    let method = words.next().context("empty firmware command")?;
    let mut fields: Vec<(String, Option<Vec<u8>>, String)> = Vec::new();
    for word in words {
        let (key, value) = word.split_once('=').unwrap_or((word, "true"));
        if key == "payload" {
            let hex = value.strip_prefix("hex:").unwrap_or(value);
            let payload = decode_firmware_hex(hex)?;
            fields.push(("data".to_owned(), Some(payload), String::new()));
        } else {
            fields.push((key.to_owned(), None, value.to_owned()));
        }
    }
    let mut cbor = Vec::with_capacity(64);
    let mut encoder = Encoder::new(&mut cbor);
    encoder.map(if fields.is_empty() { 1 } else { 2 })?;
    encoder.u16(0)?.str(method)?;
    if !fields.is_empty() {
        encoder.u16(6)?.map(fields.len() as u64)?;
        for (key, bytes, value) in fields {
            if let Some(tag) = firmware_arg_tag(&key) {
                encoder.u16(tag)?;
            } else {
                encoder.str(&key)?;
            }
            if let Some(bytes) = bytes {
                encoder.bytes(&bytes)?;
            } else {
                encoder.str(&value)?;
            }
        }
    }
    mesh::cbor::encode_stream_frame(&cbor)
}

/// Numeric firmware argument IDs for the compact command fields used by the
/// managed ESP path. Keep unknown/debug fields as text for compatibility, but
/// make module-flash requests match Main's native schema exactly.
fn firmware_arg_tag(name: &str) -> Option<u16> {
    Some(match name {
        "op" => 87,
        "name" => 409,
        "server" => 246,
        "port" => 191,
        "target" => 346,
        "object_action_stats" => 272,
        _ => return None,
    })
}

/// Accept one persistent reverse Main connection for every configured STA
/// address. Unknown peers are discarded rather than becoming an implicit
/// maintenance endpoint.
fn reverse_main_accept_loop(
    port: u16,
    sessions: Arc<BTreeMap<String, ReverseMainRuntime>>,
) -> Result<()> {
    let listener = TcpListener::bind((Ipv4Addr::UNSPECIFIED, port))
        .with_context(|| format!("failed to bind reverse Main listener on 0.0.0.0:{port}"))?;
    tracing::info!(port, "reverse_main_listener_started");
    for accepted in listener.incoming() {
        let stream = accepted.context("failed to accept reverse Main connection")?;
        let peer = stream
            .peer_addr()
            .context("failed to identify reverse Main peer")?;
        let Some((id, session)) = sessions
            .iter()
            .find(|(_, session)| peer.ip() == std::net::IpAddr::V4(session.ip))
        else {
            tracing::warn!(peer = %peer, port, "reverse_main_unknown_peer");
            continue;
        };
        stream.set_nodelay(true).ok();
        let mut current = session
            .stream
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *current = Some(stream);
        tracing::info!(id = %id, peer = %peer, socket = %session.socket_path, "reverse_main_connected");
    }
    Ok(())
}

/// Expose the accepted connection as the familiar per-device managed socket.
/// Each UDS client sends one `u32 length + CBOR` request and receives the
/// matching framed response. The shared reverse stream is serialized so one
/// device cannot have replies assigned to the wrong local caller.
fn reverse_main_uds_loop(session: ReverseMainRuntime) -> Result<()> {
    if let Some(parent) = PathBuf::from(&session.socket_path).parent() {
        fs::create_dir_all(parent)?;
    }
    let _ = fs::remove_file(&session.socket_path);
    let listener = UnixListener::bind(&session.socket_path)
        .with_context(|| format!("failed to bind reverse Main socket {}", session.socket_path))?;
    configure_serial_forward_socket(&session.socket_path)?;
    for accepted in listener.incoming() {
        let mut client = accepted.context("failed to accept reverse Main socket client")?;
        let session = session.clone();
        std::thread::spawn(move || {
            let result = (|| -> Result<()> {
                let mut length = [0_u8; 4];
                client.read_exact(&mut length)?;
                let length = u32::from_be_bytes(length) as usize;
                if length == 0 || length > 4096 {
                    bail!("invalid reverse Main request length {length}");
                }
                let mut payload = vec![0_u8; length];
                client.read_exact(&mut payload)?;
                let response = reverse_main_exchange_payload(&session, &payload, 30_000)?;
                client.write_all(&(response.len() as u32).to_be_bytes())?;
                client.write_all(&response)?;
                client.flush()?;
                Ok(())
            })();
            if let Err(error) = result {
                tracing::debug!(id = %session.id, error = %error, "reverse_main_socket_exchange_failed");
            }
        });
    }
    Ok(())
}

fn reverse_main_exchange(
    session: &ReverseMainRuntime,
    command: &str,
    timeout_ms: u64,
) -> Result<Value> {
    let stream_frame = firmware_command_cbor(command)?;
    let payload = mesh::cbor::decode_stream_frame(&stream_frame)?;
    let response = reverse_main_exchange_payload(session, &payload, timeout_ms)?;
    mesh::cbor::decode_json(&response, &mesh::cbor::Catalog::default())
        .context("Main reverse TCP response is not compact CBOR")
}

fn reverse_main_exchange_payload(
    session: &ReverseMainRuntime,
    payload: &[u8],
    timeout_ms: u64,
) -> Result<Vec<u8>> {
    let timeout = Duration::from_millis(timeout_ms);
    let mut guard = session
        .stream
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let stream = guard
        .as_mut()
        .ok_or_else(|| anyhow::anyhow!("Main reverse session {} is not connected", session.id))?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    let length = u32::try_from(payload.len()).context("firmware command is too large for TCP")?;
    if let Err(error) = stream
        .write_all(&length.to_be_bytes())
        .and_then(|_| stream.write_all(payload))
        .and_then(|_| stream.flush())
    {
        *guard = None;
        return Err(error).context("failed to write Main reverse command");
    }
    let mut length = [0_u8; 4];
    if let Err(error) = stream.read_exact(&mut length) {
        *guard = None;
        return Err(error).context("failed to read Main reverse response length");
    }
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > 4096 {
        bail!("invalid Main reverse response length {length}");
    }
    let mut response = vec![0_u8; length];
    if let Err(error) = stream.read_exact(&mut response) {
        *guard = None;
        return Err(error).context("failed to read Main reverse response");
    }
    Ok(response)
}

/// One request/response exchange with Main's STA maintenance command port.
/// The outer u32 is TCP framing only; its payload is the same compact CBOR
/// accepted by radio and UART command dispatch.
fn tcp_firmware_exchange(endpoint: &str, command: &str, timeout_ms: u64) -> Result<Value> {
    let address: SocketAddr = endpoint
        .parse()
        .with_context(|| format!("TCP endpoint must be numeric ip:port, got {endpoint:?}"))?;
    let timeout = Duration::from_millis(timeout_ms);
    let mut stream = TcpStream::connect_timeout(&address, timeout)
        .with_context(|| format!("failed to connect Main maintenance endpoint {endpoint}"))?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;

    let stream_frame = firmware_command_cbor(command)?;
    let payload = mesh::cbor::decode_stream_frame(&stream_frame)?;
    let length = u32::try_from(payload.len()).context("firmware command is too large for TCP")?;
    stream.write_all(&length.to_be_bytes())?;
    stream.write_all(payload)?;
    stream.flush()?;

    let mut length = [0_u8; 4];
    stream.read_exact(&mut length)?;
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > 4096 {
        bail!("invalid Main TCP response length {length}");
    }
    let mut payload = vec![0_u8; length];
    stream.read_exact(&mut payload)?;
    mesh::cbor::decode_json(&payload, &mesh::cbor::Catalog::default())
        .context("Main TCP response is not compact CBOR")
}

fn decode_firmware_hex(value: &str) -> Result<Vec<u8>> {
    if value.len() % 2 != 0 {
        bail!("firmware payload hex must have an even length");
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).expect("hex input is ASCII bytes");
            u8::from_str_radix(text, 16).context("firmware payload must be hex")
        })
        .collect()
}

fn boot_command_payload(command: &str) -> Result<Vec<u8>> {
    let partition = if command.eq_ignore_ascii_case("recovery") {
        2_u8
    } else if command.eq_ignore_ascii_case("main") {
        1_u8
    } else {
        bail!("unsupported boot command {command:?}");
    };
    // Keep the selector as a raw CBOR payload. queue_firmware_packet applies
    // the shared PPP/HDLC envelope exactly once before it reaches UART.
    Ok(vec![
        0xa2,
        0x00,
        0x1a,
        (DMESH_BOOT_METHOD_SELECT >> 24) as u8,
        (DMESH_BOOT_METHOD_SELECT >> 16) as u8,
        (DMESH_BOOT_METHOD_SELECT >> 8) as u8,
        DMESH_BOOT_METHOD_SELECT as u8,
        0x06,
        0x81,
        partition,
    ])
}

fn boot_identity_json(payload: &[u8]) -> Value {
    let hex = payload
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    if payload
        .windows(3)
        .any(|window| window == [0x19, 0xea, 0x60])
    {
        let tuple = boot_identity_tuple(payload);
        let stage2_version = tuple.as_ref().and_then(|values| values.get(8)).cloned();
        let boot_target_configured = tuple.as_ref().and_then(|values| values.get(9)).cloned();
        let boot_target = tuple.as_ref().and_then(|values| values.get(10)).cloned();
        let mut result = json!({
            "valid": true,
            "kind": "event",
            "event_id": 60000,
            "event_name": "boot.identity",
            "tuple": tuple,
        });
        if let Some(stage2_version) = stage2_version {
            result["stage2_version"] = stage2_version;
        }
        if let (Some(boot_target_configured), Some(boot_target)) =
            (boot_target_configured, boot_target)
        {
            result["boot_target_configured"] = boot_target_configured;
            result["boot_target"] = boot_target;
        }
        return result;
    }
    if payload.len() < 18 || payload[..4] != DMESH_BOOT_MAGIC[..] {
        return json!({"raw_hex": hex, "valid": false});
    }
    json!({
        "valid": payload[4] == DMESH_BOOT_VERSION && payload[5] == 1,
        "version": payload[4],
        "kind": payload[5],
        "role": payload[6],
        "partition": payload[7],
        "role_name": match payload[6] {
            1 => "main",
            2 => "recovery",
            3 => "stage2",
            _ => "unknown",
        },
        "partition_name": match payload[7] {
            0 => "bootloader",
            1 => "main",
            2 => "recovery",
            _ => "unknown",
        },
        "reset_reason": payload[8],
        "boot_count": payload[9],
        "timestamp": u16::from_be_bytes([payload[10], payload[11]]),
        "mac": payload[12..18].iter().map(|byte| format!("{byte:02x}")).collect::<Vec<_>>().join(":"),
        "raw_hex": hex,
    })
}

fn boot_event_json(payload: &[u8]) -> Value {
    let event_id = boot_event_id(payload).unwrap_or(0);
    let event_name = match event_id {
        60000 => "boot.identity",
        60001 => "flash.complete",
        60002 => "flash.error",
        60003 => "recovery.network_up",
        _ => "boot.event",
    };
    json!({
        "valid": event_id != 0,
        "kind": "event",
        "event_id": event_id,
        "event_name": event_name,
        "tuple": boot_identity_tuple(payload),
    })
}

const DMESH_BOOT_HELLO_LEN: usize = 18;

/// The managed UART forward preserves byte order but not physical UART read
/// boundaries. A DMB1 hello may therefore be split across several stream
/// records; reassemble it before validating the fixed fields.
fn find_stage2_identity(bytes: &[u8]) -> Option<Vec<u8>> {
    bytes
        .windows(DMESH_BOOT_HELLO_LEN)
        .find(|payload| {
            payload[..4] == DMESH_BOOT_MAGIC[..]
                && payload[4] == DMESH_BOOT_VERSION
                && payload[5] == 1
                && payload[6] == DMESH_BOOT_ROLE_STAGE2
                && payload[7] == DMESH_BOOT_PARTITION_BOOTLOADER
        })
        .map(|payload| payload.to_vec())
}

/// Reset an ESP bridge and send the fixed stage2 command on the same open
/// descriptor. Keeping reset, transmit, and receive in one operation avoids
/// losing stage2's short UART selector window. The managed serial forward is
/// deliberately left active so it continues to retain evidence.
fn set_modem_line(fd: RawFd, line: libc::c_int, enabled: bool) -> Result<()> {
    // Preserve the other modem line and submit the complete mask. Some
    // CP210x bridges do not reliably propagate a standalone TIOCMBIS/BIC
    // transition while the tty is shared with a long-lived forward; TIOCMSET
    // matches the control-line transaction used by the ESP reset tooling.
    let mut state = modem_state(fd)?;
    if enabled {
        state |= line;
    } else {
        state &= !line;
    }
    set_modem_state(fd, state)
}

fn set_modem_state(fd: RawFd, mut state: libc::c_int) -> Result<()> {
    if unsafe { libc::ioctl(fd, libc::TIOCMSET, &mut state) } < 0 {
        return Err(std::io::Error::last_os_error()).context("TIOCMSET failed");
    }
    Ok(())
}

fn modem_state(fd: RawFd) -> Result<libc::c_int> {
    let mut state: libc::c_int = 0;
    if unsafe { libc::ioctl(fd, libc::TIOCMGET, &mut state) } < 0 {
        return Err(std::io::Error::last_os_error()).context("TIOCMGET failed");
    }
    Ok(state)
}

/// Reset a running ESP through the descriptor owned by lmesh.
///
/// Some CP210x bridges leave DTR asserted after a previous client or open.
/// Refusing the reset in that state makes the recovery path unusable: the
/// request is accepted but no RTS pulse is performed. Release DTR on this same
/// descriptor first, then pulse RTS. Using the managed descriptor avoids the
/// second-open/close race that can restore modem lines and cancel the reset.
fn serial_run_reset(fd: RawFd) -> Result<()> {
    let state = modem_state(fd)?;
    if state & libc::TIOCM_DTR != 0 {
        set_modem_line(fd, libc::TIOCM_DTR, false)?;
        std::thread::sleep(Duration::from_millis(20));
    }
    // Establish the released level first.  A USB-UART bridge may already
    // report RTS asserted when it is opened; asserting an already-asserted
    // line produces no edge and therefore no ESP reset.
    set_modem_line(fd, libc::TIOCM_RTS, false)?;
    std::thread::sleep(Duration::from_millis(20));
    set_modem_line(fd, libc::TIOCM_RTS, true)?;
    std::thread::sleep(Duration::from_millis(120));
    set_modem_line(fd, libc::TIOCM_RTS, false)?;
    // Stage2's selector is sent by the same managed forward immediately
    // after this reset operation. Do not hold the descriptor for half a
    // second: that would consume a short boot-selector window before the
    // queued PPP packet reaches the UART.
    std::thread::sleep(Duration::from_millis(20));
    Ok(())
}

/// Send a PPP-CBOR boot selector through a managed UDS forward and wait for
/// the next structured boot identity record.
fn connect_uds_boot(socket_path: &str) -> Result<UnixStream> {
    UnixStream::connect(socket_path)
        .with_context(|| format!("failed to connect managed serial socket {socket_path}"))
}

fn uds_boot_exchange(socket_path: &str, command: &[u8], timeout_ms: u64) -> Result<Vec<u8>> {
    let stream = connect_uds_boot(socket_path)?;
    uds_boot_exchange_stream(stream, command, timeout_ms)
}

fn uds_boot_exchange_stream(
    mut stream: UnixStream,
    command: &[u8],
    timeout_ms: u64,
) -> Result<Vec<u8>> {
    let command_frame = mesh::cbor::encode_stream_frame(command)?;
    stream
        .set_read_timeout(Some(Duration::from_millis(100)))
        .context("failed to set managed serial read timeout")?;
    // ROM output precedes the custom bootloader. The selector must wait until
    // the PPP boot identity proves that stage2 has started polling UART.
    let deadline = std::time::Instant::now() + Duration::from_millis(timeout_ms);
    let mut output = Vec::new();
    let mut boot_bytes = Vec::new();
    let mut buf = [0_u8; 512];
    while std::time::Instant::now() < deadline {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(count) => output.extend_from_slice(&buf[..count]),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(error) => return Err(error).context("failed to read stage2 identity"),
        }
        while output.len() >= 4 {
            let body_len = u32::from_be_bytes(output[..4].try_into().unwrap()) as usize;
            if !(4..=mesh::cbor::ESP_RECORD_MAX + 4).contains(&body_len) {
                output.remove(0);
                continue;
            }
            let frame_len = 4 + body_len;
            if output.len() < frame_len {
                break;
            }
            let frame = output.drain(..frame_len).collect::<Vec<_>>();
            let payload = mesh::cbor::decode_stream_frame(&frame)
                .context("invalid managed stage2 stream envelope")?;
            boot_bytes.extend_from_slice(&payload);
            if boot_bytes.len() > DMESH_BOOT_HELLO_LEN * 4 {
                let keep = DMESH_BOOT_HELLO_LEN * 4;
                boot_bytes.drain(..boot_bytes.len() - keep);
            }
            if let Some(identity) = find_stage2_identity(&boot_bytes) {
                stream
                    .write_all(SERIAL_FORWARD_FORCE_DIRECT_PREFIX)
                    .context("failed to select direct delivery for stage2 command")?;
                stream
                    .write_all(&command_frame)
                    .context("failed to write fixed stage2 command")?;
                stream
                    .flush()
                    .context("failed to flush fixed stage2 command")?;
                return Ok(identity);
            }
            if boot_bytes
                .windows(3)
                .any(|window| window == [0x19, 0xea, 0x60])
            {
                stream
                    .write_all(SERIAL_FORWARD_FORCE_DIRECT_PREFIX)
                    .context("failed to select direct delivery for stage2 command")?;
                stream
                    .write_all(&command_frame)
                    .context("failed to write fixed stage2 command")?;
                stream
                    .flush()
                    .context("failed to flush fixed stage2 command")?;
                return Ok(boot_bytes.clone());
            }
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    bail!("timed out waiting for fixed stage2 identity")
}

/// Exchange one compact-CBOR payload through the managed framed forward.
/// The UDS and physical UART envelopes are applied here; callers never put
/// text commands directly on the firmware UART.
fn uds_cbor_exchange(socket_path: &str, payload: &[u8], timeout_ms: u64) -> Result<String> {
    static UDS_RAW_SERIALIZE: OnceLock<Mutex<()>> = OnceLock::new();
    let _exchange_guard = UDS_RAW_SERIALIZE
        .get_or_init(|| Mutex::new(()))
        .lock()
        .map_err(|_| anyhow::anyhow!("managed CBOR exchange lock poisoned"))?;
    let mut stream = UnixStream::connect(socket_path)
        .with_context(|| format!("failed to connect managed serial socket {socket_path}"))?;
    stream
        .set_read_timeout(Some(Duration::from_millis(5)))
        .context("failed to set stale-record timeout")?;
    let mut stale = [0_u8; 2048];
    loop {
        match stream.read(&mut stale) {
            Ok(0) => break,
            Ok(_) => continue,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                break;
            }
            Err(error) => return Err(error).context("failed to drain managed serial socket"),
        }
    }
    let command_frame = mesh::cbor::encode_stream_frame(payload)?;
    stream
        .set_read_timeout(Some(Duration::from_millis(100)))
        .context("failed to set managed raw read timeout")?;
    stream
        .write_all(SERIAL_FORWARD_FORCE_DIRECT_PREFIX)
        .context("failed to select direct delivery for CBOR command")?;
    stream
        .write_all(&command_frame)
        .context("failed to write managed CBOR serial command")?;
    stream
        .flush()
        .context("failed to flush managed CBOR serial command")?;

    let deadline = std::time::Instant::now() + Duration::from_millis(timeout_ms);
    let mut output = Vec::new();
    let mut raw = Vec::new();
    let mut buf = [0_u8; 512];
    while std::time::Instant::now() < deadline {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(count) => output.extend_from_slice(&buf[..count]),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(error) => return Err(error).context("failed to read managed raw response"),
        }
        while output.len() >= 4 {
            let body_len = u32::from_be_bytes(output[..4].try_into().unwrap()) as usize;
            if !(4..=mesh::cbor::ESP_RECORD_MAX + 4).contains(&body_len) {
                output.remove(0);
                continue;
            }
            let frame_len = 4 + body_len;
            if output.len() < frame_len {
                break;
            }
            let frame = output.drain(..frame_len).collect::<Vec<_>>();
            let body = mesh::cbor::decode_stream_frame(&frame)
                .context("invalid managed raw stream envelope")?;
            raw.extend_from_slice(&body);
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    Ok(String::from_utf8_lossy(&raw).to_string())
}

fn parse_raw_exchange_messages(raw: &str) -> Vec<MeshMessage> {
    raw.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .filter_map(|line| mesh::message::parse_firmware_message_line(line).ok())
        .collect()
}

/// Send one compact-CBOR console command through a managed forward.
#[allow(dead_code)]
fn uds_console_exchange(socket_path: &str, command: &str, timeout_ms: u64) -> Result<String> {
    uds_console_exchange_with_options(socket_path, command, timeout_ms, false)
}

fn uds_console_exchange_with_options(
    socket_path: &str,
    command: &str,
    timeout_ms: u64,
    force_direct: bool,
) -> Result<String> {
    uds_console_exchange_inner(socket_path, command, timeout_ms, force_direct)
}

fn uds_console_exchange_inner(
    socket_path: &str,
    command: &str,
    timeout_ms: u64,
    force_direct: bool,
) -> Result<String> {
    // A managed forward broadcasts every UART record to every connected UDS
    // client. Serialize request/reply exchanges and discard records already
    // queued when this client connects; otherwise a delayed response to a
    // previous `nan queued` request can be returned as the current command's
    // response (especially visible during DW retries).
    static UDS_CONSOLE_SERIALIZE: OnceLock<Mutex<()>> = OnceLock::new();
    let _exchange_guard = UDS_CONSOLE_SERIALIZE
        .get_or_init(|| Mutex::new(()))
        .lock()
        .map_err(|_| anyhow::anyhow!("managed console exchange lock poisoned"))?;
    let command_frame = firmware_command_cbor(command)?;
    let mut stream = UnixStream::connect(socket_path)
        .with_context(|| format!("failed to connect managed serial socket {socket_path}"))?;
    // Drain only data that was present before this command was written. The
    // short timeout keeps this bounded for a sleeping target.
    stream
        .set_read_timeout(Some(Duration::from_millis(5)))
        .with_context(|| format!("failed to set stale-record timeout on {socket_path}"))?;
    let mut stale = [0_u8; 2048];
    loop {
        match stream.read(&mut stale) {
            Ok(0) => break,
            Ok(_) => continue,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                break;
            }
            Err(error) => {
                return Err(error).with_context(|| format!("failed to drain {socket_path}"));
            }
        }
    }
    stream
        .set_read_timeout(Some(Duration::from_millis(250)))
        .with_context(|| format!("failed to set read timeout on {socket_path}"))?;
    // Battery nodes advertise a tagged UART wake event during their configured
    // raw-NAN window. The managed forward keeps this command pending until
    // that authoritative event arrives, then flushes it while
    // firmware UART RX is open. GPIO0/PRG is a recovery control and is not a
    // reliable product wake mechanism: using it here can consume the first
    // command on a board waking from light sleep.
    if force_direct {
        stream
            .write_all(SERIAL_FORWARD_FORCE_DIRECT_PREFIX)
            .with_context(|| format!("failed to select direct delivery on {socket_path}"))?;
    }
    stream
        .write_all(&command_frame)
        .with_context(|| format!("failed to write managed serial command to {socket_path}"))?;
    stream
        .flush()
        .with_context(|| format!("failed to flush {socket_path}"))?;
    let deadline = std::time::Instant::now() + Duration::from_millis(timeout_ms);
    let mut output = Vec::new();
    let mut records = String::new();
    let mut buf = [0_u8; 1024];
    while std::time::Instant::now() < deadline {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(count) => {
                output.extend_from_slice(&buf[..count]);
                while output.len() >= 4 {
                    let body_len = u32::from_be_bytes(output[..4].try_into().unwrap()) as usize;
                    let frame_len = body_len.saturating_add(4);
                    if !(4..=mesh::cbor::ESP_RECORD_MAX + 4).contains(&body_len) {
                        // Firmware logs can precede a valid record. Do not
                        // write a synthetic marker into UART: the previous
                        // 0xff recovery sequence was observable by the
                        // firmware and could monopolize a sleeping board's
                        // console. Discard one byte and keep scanning for the
                        // next authoritative stream-frame boundary.
                        let byte = output.remove(0);
                        records.push_str(&String::from_utf8_lossy(&[byte]));
                        continue;
                    }
                    if output.len() < frame_len {
                        break;
                    }
                    let frame = output.drain(..frame_len).collect::<Vec<_>>();
                    // The managed forward can contain a stale partial record
                    // after a board reset or wake.  It is not a command error:
                    // discard this candidate and continue looking for the next
                    // length-prefixed CBOR response on the same connection.
                    // In particular, do not let one bad record prevent a
                    // sleepy board's valid response from being observed.
                    let payload = match mesh::cbor::decode_stream_frame(&frame) {
                        Ok(payload) => payload,
                        Err(error) => {
                            tracing::debug!(%socket_path, %error, "ignored malformed UART stream frame");
                            continue;
                        }
                    };
                    let decoded = match mesh::cbor::decode_json(
                        payload,
                        &mesh::cbor::Catalog::default(),
                    ) {
                        Ok(decoded) => decoded,
                        Err(error) => {
                            tracing::debug!(%socket_path, %error, "ignored malformed UART CBOR payload");
                            continue;
                        }
                    };
                    // Firmware response text is compact-CBOR payload tag 32.
                    // The generic catalog intentionally does not assign this
                    // firmware-private tag a global field name.
                    let record_start = records.len();
                    if let Some(message) = decoded
                        .get("payload")
                        .and_then(Value::as_object)
                        .and_then(|payload| payload.get("32"))
                        .and_then(Value::as_str)
                    {
                        records.push_str(message);
                        records.push('\n');
                    } else if let Some(message) = decoded.get("message").and_then(Value::as_str) {
                        records.push_str(message);
                        records.push('\n');
                    } else if let Some(error) = decoded.get("error").and_then(Value::as_str) {
                        records.push_str("error message=");
                        records.push_str(error);
                        records.push('\n');
                    } else if let Some(status) = decoded.get("status").and_then(Value::as_str) {
                        records.push_str("status=");
                        records.push_str(status);
                        records.push('\n');
                    } else {
                        records.push_str(&decoded.to_string());
                        records.push('\n');
                    }
                    // Forward startup and wake classification records are
                    // broadcast to every UDS client. They are useful for
                    // lmesh's mode tracker but are not replies to an
                    // unrelated command (a `status` request must not be
                    // satisfied by `mode status=true`). Keep waiting for the
                    // command's own record on this same serialized client.
                    if is_unsolicited_console_record(command, &records[record_start..]) {
                        records.truncate(record_start);
                        continue;
                    }
                    // Firmware commands produce one authoritative CBOR
                    // response. Return immediately so this connection cannot
                    // receive and steal the response for a later command.
                    return Ok(records);
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(error) => {
                return Err(error).with_context(|| format!("failed to read {socket_path}"));
            }
        }
    }
    if !output.is_empty() {
        records.push_str(&String::from_utf8_lossy(&output));
    }
    bail!("timed out waiting for framed firmware response from {socket_path}")
}

fn is_unsolicited_console_record(command: &str, record: &str) -> bool {
    let command = command.trim_start();
    let record = record.trim_start();
    // State notifications are broadcast to all clients, including the client
    // that issued a mode command. They are never the command's authoritative
    // response, even for the compact `active`/`idle` aliases.
    // All event records are broadcast diagnostics, not the command reply.
    // This includes raw-NAN frame events, which can race a transport command
    // on a busy managed forward and otherwise make the caller observe a stale
    // event as its response.
    if record.starts_with("event type=") {
        return true;
    }
    // `active` and `idle` are compact aliases for the mode control command.
    // Their authoritative response is rendered as `mode active=...`, so it
    // must not be mistaken for the broadcast mode-state event.
    if command.starts_with("mode") || command.starts_with("active") || command.starts_with("idle") {
        return false;
    }
    record.starts_with("mode active=")
}

#[allow(dead_code)]
fn split_csv(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

#[allow(dead_code)]
fn normalize_mac_suffix(value: &str) -> Option<String> {
    let hex = value
        .bytes()
        .filter(u8::is_ascii_hexdigit)
        .map(char::from)
        .collect::<String>();
    match hex.len() {
        8 => Some(hex.to_ascii_lowercase()),
        12 => Some(hex[4..].to_ascii_lowercase()),
        _ => None,
    }
}

#[allow(dead_code)]
fn response_history_entries(value: &Value, target: Option<&str>) -> Vec<(String, String)> {
    let mut entries = Vec::new();
    let Some(messages) = value.get("messages").and_then(Value::as_array) else {
        return entries;
    };
    for message in messages {
        let Some(console) = message.get("console").and_then(Value::as_str) else {
            continue;
        };
        for line in console.lines() {
            let Some(raw_entries) = line.split_once("entries=").map(|(_, entries)| entries) else {
                continue;
            };
            for entry in raw_entries.split(",local_us:").map(|entry| {
                if entry.starts_with("local_us:") {
                    entry.to_owned()
                } else {
                    format!("local_us:{entry}")
                }
            }) {
                let Some((_, payload)) = entry.split_once("payload_hex:") else {
                    continue;
                };
                if let Some(target) = target {
                    let Some((_, source)) = entry.split_once("source:") else {
                        continue;
                    };
                    let source = source.split(':').take(6).collect::<String>();
                    let Some(source) = normalize_mac_suffix(&source) else {
                        continue;
                    };
                    if !mac_suffix_variants(target)
                        .iter()
                        .any(|suffix| suffix == &source)
                    {
                        continue;
                    }
                }
                entries.push((entry.trim().to_owned(), payload.trim().to_ascii_lowercase()));
            }
        }
    }
    entries
}

/// Parse lora1's bounded custom-action response history. The source spelling
/// may be the ESP SoftAP MAC (station + 1), just like NAN response history.
#[allow(dead_code)]
fn raw_response_history_entries(value: &Value, target: Option<&str>) -> Vec<(String, String)> {
    let mut entries = Vec::new();
    let Some(messages) = value.get("messages").and_then(Value::as_array) else {
        return entries;
    };
    for message in messages {
        let Some(console) = message.get("console").and_then(Value::as_str) else {
            continue;
        };
        let Some(raw_entries) = console.split_once("entries=").map(|(_, value)| value) else {
            continue;
        };
        for entry in raw_entries.split(",local_us:").map(|entry| {
            if entry.starts_with("local_us:") {
                entry.to_owned()
            } else {
                format!("local_us:{entry}")
            }
        }) {
            let Some((head, payload)) = entry.split_once(":payload_hex:") else {
                continue;
            };
            if let Some(target) = target {
                let Some(source) = head.split_once("source=").map(|(_, value)| value) else {
                    continue;
                };
                let Some(source) = normalize_mac_suffix(source) else {
                    continue;
                };
                if !mac_suffix_variants(target)
                    .iter()
                    .any(|candidate| candidate == &source)
                {
                    continue;
                }
            }
            entries.push((entry.trim().to_owned(), payload.trim().to_ascii_lowercase()));
        }
    }
    entries
}

/// Returns true when an older gateway has no dedicated action-frame history
/// command. Such gateways expose the same received replies through the NAN
/// response history during the compatibility rollout.
#[allow(dead_code)]
fn raw_history_unsupported(value: &Value) -> bool {
    value
        .get("messages")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|message| message.get("console").and_then(Value::as_str))
        .any(|console| console.contains("unknown payload key string: raw_response_history"))
}

#[allow(dead_code)]
fn is_session_end(payload_hex: &str) -> bool {
    decode_firmware_hex(payload_hex)
        .map(|payload| {
            payload
                .windows(b"session_end".len())
                .any(|part| part == b"session_end")
        })
        .unwrap_or(false)
}

#[allow(dead_code)]
fn response_request_id(payload_hex: &str) -> Option<u64> {
    let payload = decode_firmware_hex(payload_hex).ok()?;
    let decoded = mesh::cbor::decode_json(&payload, &mesh::cbor::Catalog::default()).ok()?;
    let request_id_key = REMOTE_REQUEST_ID_KEY.to_string();
    decoded
        .get("payload")
        .and_then(Value::as_object)
        .and_then(|payload| payload.get(&request_id_key))
        .and_then(Value::as_str)
        .and_then(|value| value.parse::<u64>().ok())
}

/// Return true for the compact firmware-level NAN ping response.  Ping
/// replies are transport observations and intentionally do not carry the
/// command request-id used by the command acknowledgement.
#[allow(dead_code)]
fn is_firmware_pong(payload_hex: &str) -> bool {
    decode_firmware_hex(payload_hex).is_ok_and(|payload| {
        payload.as_slice() == [0xa2, 0x00, 0x18, 0x21, 0x04, 0x64, b'p', b'o', b'n', b'g']
    })
}

/// ESP32 exposes the station MAC in some command paths and the AP MAC in raw
/// NAN frames. They differ only in the final byte (AP = STA + 1), so response
/// history matching must accept both forms for one addressed node.
#[allow(dead_code)]
fn mac_suffix_variants(value: &str) -> Vec<String> {
    let Some(normalized) = normalize_mac_suffix(value) else {
        return Vec::new();
    };
    let mut variants = vec![normalized.clone()];
    let Ok(last) = u8::from_str_radix(&normalized[6..], 16) else {
        return variants;
    };
    for adjacent in [last.wrapping_sub(1), last.wrapping_add(1)] {
        let candidate = format!("{}{:02x}", &normalized[..6], adjacent);
        if !variants.contains(&candidate) {
            variants.push(candidate);
        }
    }
    variants
}

/// Encode a raw-NAN command for one ESP target. The receiver applies the
/// normal `to=` filter before dispatching the method, so a broadcast follow-up
/// from the gateway cannot activate unrelated battery nodes.
#[allow(dead_code)]
fn firmware_targeted_command_cbor(command: &str, target: &str) -> Result<Vec<u8>> {
    firmware_targeted_command_cbor_with_metadata(command, target, None, None)
}

#[allow(dead_code)]
fn firmware_targeted_command_cbor_with_timeout(
    command: &str,
    target: &str,
    timeout_ms: Option<u32>,
) -> Result<Vec<u8>> {
    firmware_targeted_command_cbor_with_metadata(command, target, timeout_ms, None)
}

#[allow(dead_code)]
fn firmware_targeted_command_cbor_with_metadata(
    command: &str,
    target: &str,
    timeout_ms: Option<u32>,
    request_id: Option<u64>,
) -> Result<Vec<u8>> {
    // Keep the public remote-command shortcut aligned with the firmware ABI.
    // `ping` is a host convenience alias for `mode ping=true`; encoding the
    // literal method name would otherwise produce an unknown-command response
    // on the ESP and can be mistaken for a lost DW delivery.
    if command.trim().eq_ignore_ascii_case("ping") {
        let mut bytes = Vec::with_capacity(56);
        let mut encoder = Encoder::new(&mut bytes);
        let arg_count = 2 + usize::from(timeout_ms.is_some()) + usize::from(request_id.is_some());
        encoder.map(2)?;
        encoder.u16(0)?.u16(49)?;
        encoder.u16(6)?.map(arg_count as u64)?;
        encoder.u16(190)?.str("true")?;
        encoder.u16(331)?.str(target)?;
        if let Some(timeout_ms) = timeout_ms {
            encoder.u16(41)?.str(&timeout_ms.to_string())?;
        }
        if let Some(request_id) = request_id {
            encoder
                .u16(REMOTE_REQUEST_ID_KEY)?
                .str(&request_id.to_string())?;
        }
        return Ok(bytes);
    }
    let mut words = command.split_whitespace();
    let method = words
        .next()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow::anyhow!("remote firmware command is empty"))?;
    let mut command_args = Vec::new();
    for word in words {
        let (key, value) = word.split_once('=').unwrap_or((word, "true"));
        command_args.push((key.to_owned(), value.to_owned()));
    }
    let mut bytes = Vec::with_capacity(32);
    let mut encoder = Encoder::new(&mut bytes);
    let arg_count = command_args.len()
        + 1
        + usize::from(timeout_ms.is_some())
        + usize::from(request_id.is_some());
    encoder
        .map(2)
        .and_then(|encoder| encoder.u16(0))
        .and_then(|encoder| encoder.str(method))
        .and_then(|encoder| encoder.u16(6))
        .and_then(|encoder| encoder.map(arg_count as u64))
        .map_err(|error| anyhow::Error::msg(error.to_string()))?;
    for (key, value) in command_args {
        encoder
            .str(&key)
            .and_then(|encoder| encoder.str(&value))
            .map_err(|error| anyhow::Error::msg(error.to_string()))?;
    }
    encoder
        .u16(331)
        .and_then(|encoder| encoder.str(target))
        .and_then(|encoder| {
            if let Some(timeout_ms) = timeout_ms {
                encoder
                    .u16(41)
                    .and_then(|encoder| encoder.str(&timeout_ms.to_string()))
            } else {
                Ok(encoder)
            }
        })
        .and_then(|encoder| {
            if let Some(request_id) = request_id {
                encoder
                    .u16(REMOTE_REQUEST_ID_KEY)
                    .and_then(|encoder| encoder.str(&request_id.to_string()))
            } else {
                Ok(encoder)
            }
        })
        .map_err(|error| anyhow::Error::msg(error.to_string()))?;
    Ok(bytes)
}

/// Encode a bounded target wake. The target receives the regular `mode`
/// command with `active_ms`, entering command/transfer mode without requiring
/// a second UART or USB intervention.
#[allow(dead_code)]
fn firmware_targeted_active_window_cbor(target: &str, active_ms: u32) -> Result<Vec<u8>> {
    let mut bytes = Vec::with_capacity(48);
    let mut encoder = Encoder::new(&mut bytes);
    encoder
        .map(2)
        .and_then(|encoder| encoder.u16(0))
        .and_then(|encoder| encoder.str("mode"))
        .and_then(|encoder| encoder.u16(6))
        .and_then(|encoder| encoder.map(2))
        .and_then(|encoder| encoder.u16(80))
        .and_then(|encoder| encoder.str(&active_ms.clamp(1_000, 300_000).to_string()))
        .and_then(|encoder| encoder.u16(331))
        .and_then(|encoder| encoder.str(target))
        .map_err(|error| anyhow::Error::msg(error.to_string()))?;
    Ok(bytes)
}

/// Encode the firmware's `mode ping=true` command. The numeric tags are part
/// of the documented ESP firmware ABI: method 49 (`mode`) and argument 190
/// (`ping`). Keep host NAN command traffic binary even while UART debug text
/// remains supported.
#[allow(dead_code)]
fn firmware_mode_ping_cbor() -> Result<Vec<u8>> {
    let mut bytes = Vec::with_capacity(16);
    let mut encoder = Encoder::new(&mut bytes);
    encoder
        .map(2)
        .and_then(|encoder| encoder.u16(0))
        .and_then(|encoder| encoder.u16(49))
        .and_then(|encoder| encoder.u16(6))
        .and_then(|encoder| encoder.map(1))
        .and_then(|encoder| encoder.u16(190))
        .and_then(|encoder| encoder.str("true"))
        .map_err(|error| anyhow::Error::msg(error.to_string()))?;
    Ok(bytes)
}

#[allow(dead_code)]
fn parse_stability_pongs(output: &str) -> Vec<Value> {
    output
        .lines()
        .filter(|line| line.contains("type=lora.dmesh_control") && line.contains("kind=pong"))
        .filter_map(|line| {
            let mut fields = BTreeMap::new();
            for field in line.split_ascii_whitespace() {
                let Some((key, value)) = field.split_once('=') else {
                    continue;
                };
                fields.insert(key, value);
            }
            let from = fields.get("from")?;
            Some(json!({
                "from": from,
                "uptime_ms": fields.get("uptime_ms").copied().unwrap_or("-"),
                "link_rssi_dbm": fields.get("link_rssi_dbm").copied().unwrap_or("-"),
                "snr": fields.get("snr").copied().unwrap_or("-"),
                "nan": {
                    "running": fields.get("nrun").copied().unwrap_or("-"),
                    "mgmt_rx": fields.get("nmg").copied().unwrap_or("-"),
                    "sdf_rx": fields.get("nsdf").copied().unwrap_or("-"),
                    "response_rx": fields.get("nrx").copied().unwrap_or("-"),
                    "response_tx": fields.get("ntx").copied().unwrap_or("-"),
                    "prefilter_drop": fields.get("ndrop").copied().unwrap_or("-"),
                    "beacon_age_ms": fields.get("nage").copied().unwrap_or("-"),
                },
            }))
        })
        .collect()
}

/// Read the compact raw-NAN counters exposed by the firmware debug command.
/// The stability cycle takes a snapshot before and after its ping observation
/// window, making raw-NAN response delivery observable independently of the
/// LoRa console packet that carries the human-readable pong.
#[allow(dead_code)]
fn stability_nan_stats(socket: &str) -> Option<BTreeMap<String, u64>> {
    // A sleepy console may miss the first heartbeat at a duty-window boundary.
    // Retry once so the stability monitor does not turn that normal boundary
    // race into a missing raw-NAN health sample.
    for _ in 0..2 {
        let Ok(output) = uds_console_exchange(socket, "nan stats=true", 1_500) else {
            continue;
        };
        let Some(line) = output
            .lines()
            .find_map(|line| line.find("nan support=raw").map(|offset| &line[offset..]))
        else {
            continue;
        };
        let mut fields = BTreeMap::new();
        for field in line.split_ascii_whitespace() {
            let Some((key, value)) = field.split_once('=') else {
                continue;
            };
            if matches!(
                key,
                "raw_sdf" | "raw_resp_rx" | "raw_resp_tx" | "raw_beacon" | "rx_queue_drop"
            ) && let Ok(value) = value.parse::<u64>()
            {
                fields.insert(key.to_string(), value);
            }
        }
        return Some(fields);
    }
    None
}

#[allow(dead_code)]
fn stability_nan_cycle(
    before: Option<&BTreeMap<String, u64>>,
    after: Option<&BTreeMap<String, u64>>,
) -> Value {
    let delta = |key: &str| match (
        before.and_then(|values| values.get(key)),
        after.and_then(|values| values.get(key)),
    ) {
        (Some(before), Some(after)) => Some(after.saturating_sub(*before)),
        _ => None,
    };
    let response_rx_delta = delta("raw_resp_rx");
    json!({
        "before": before,
        "after": after,
        "sdf_rx_delta": delta("raw_sdf"),
        "response_rx_delta": response_rx_delta,
        "response_tx_delta": delta("raw_resp_tx"),
        "beacon_delta": delta("raw_beacon"),
        "queue_drop_delta": delta("rx_queue_drop"),
        "response_observed": response_rx_delta.is_some_and(|value| value > 0),
    })
}

fn configure_serial(fd: RawFd, baud: u32) -> Result<()> {
    let mut termios = unsafe {
        let mut termios = std::mem::zeroed();
        if libc::tcgetattr(fd, &mut termios) != 0 {
            return Err(std::io::Error::last_os_error()).context("tcgetattr failed");
        }
        termios
    };
    unsafe {
        libc::cfmakeraw(&mut termios);
    }
    let speed = baud_to_speed(baud)?;
    let rc = unsafe { libc::cfsetspeed(&mut termios, speed) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error()).context("cfsetspeed failed");
    }
    termios.c_cflag |= libc::CLOCAL | libc::CREAD;
    let rc = unsafe { libc::tcsetattr(fd, libc::TCSANOW, &termios) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error()).context("tcsetattr failed");
    }
    Ok(())
}

fn baud_to_speed(baud: u32) -> Result<libc::speed_t> {
    match baud {
        9_600 => Ok(libc::B9600),
        19_200 => Ok(libc::B19200),
        38_400 => Ok(libc::B38400),
        57_600 => Ok(libc::B57600),
        115_200 => Ok(libc::B115200),
        230_400 => Ok(libc::B230400),
        460_800 => Ok(libc::B460800),
        921_600 => Ok(libc::B921600),
        _ => bail!("unsupported serial baud {baud}"),
    }
}

#[derive(Debug, Deserialize)]
struct LmeshToml {
    #[serde(default)]
    serial_forwards: Vec<SerialForwardConfig>,
    #[serde(default)]
    esp_gateway: Option<String>,
    #[serde(default)]
    esp_targets: BTreeMap<String, String>,
    /// Main STA sessions originate at the ESP and are accepted by lmesh.
    #[serde(default)]
    esp_reverse_sessions: Vec<EspReverseSessionConfig>,
}

#[derive(Debug, Deserialize)]
struct EspReverseSessionConfig {
    id: String,
    ip: Ipv4Addr,
    #[serde(default = "default_reverse_main_port")]
    port: u16,
    socket: Option<String>,
}

fn default_reverse_main_port() -> u16 {
    3343
}

fn configured_esp_gateway() -> String {
    if let Ok(value) = std::env::var("LMESH_ESP_GATEWAY") {
        if !value.trim().is_empty() {
            return value;
        }
    }
    read_lmesh_config()
        .and_then(|config| config.esp_gateway)
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_ESP_NAN_GATEWAY.to_string())
}

fn configured_esp_targets() -> BTreeMap<String, String> {
    let mut targets = read_lmesh_config()
        .map(|config| config.esp_targets)
        .unwrap_or_default();
    if let Ok(value) = std::env::var("LMESH_ESP_TARGETS") {
        for entry in value
            .split(',')
            .map(str::trim)
            .filter(|entry| !entry.is_empty())
        {
            if let Some((role, target)) = entry.split_once('=') {
                if !role.trim().is_empty() && !target.trim().is_empty() {
                    targets.insert(role.trim().to_owned(), target.trim().to_owned());
                }
            }
        }
    }
    targets
}

fn configured_esp_reverse_sessions() -> BTreeMap<String, ReverseMainRuntime> {
    read_lmesh_config()
        .map(|config| config.esp_reverse_sessions)
        .unwrap_or_default()
        .into_iter()
        .map(|config| {
            let socket_path = config
                .socket
                .unwrap_or_else(|| format!("/run/mesh/lmesh-uart/{}-ip.sock", config.id));
            let runtime = ReverseMainRuntime {
                id: config.id.clone(),
                ip: config.ip,
                port: config.port,
                socket_path,
                stream: Arc::new(Mutex::new(None)),
            };
            (config.id, runtime)
        })
        .collect()
}

fn resolve_esp_route(
    gateway: &str,
    targets: &BTreeMap<String, String>,
    port: Option<&str>,
    adapter: Option<&str>,
) -> Option<(String, String)> {
    // An explicitly named adapter is the escape hatch for UART diagnostics.
    if adapter.is_some() {
        return None;
    }
    if gateway.trim().is_empty() {
        return None;
    }
    let target = targets.get(port?)?.clone();
    Some((gateway.to_owned(), target))
}

#[derive(Clone, Debug, Deserialize)]
struct SerialForwardConfig {
    port: String,
    path: Option<String>,
    baud: Option<u32>,
    tcp_port: Option<u16>,
    tcp_mode: Option<String>,
    multi: Option<bool>,
    log: Option<bool>,
    /// Forward unframed serial output verbatim. This is for external sources
    /// such as power meters, never ESP firmware UARTs.
    raw: Option<bool>,
    /// Write complete client command records immediately while retaining
    /// decoded framed output. Use for continuously awake infrastructure ESPs.
    direct: Option<bool>,
    enabled: Option<bool>,
}

fn read_lmesh_config() -> Option<LmeshToml> {
    let path = lmesh_config_path()?;
    let data = fs::read_to_string(path).ok()?;
    toml::from_str(&data).ok()
}

fn lmesh_config_path() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("LMESH_UART_CONFIG_FILE") {
        return Some(PathBuf::from(path));
    }

    // Each service gets an independent HOME. Keeping its configuration below
    // that HOME makes a target/... service instance self-contained and avoids
    // silently sharing forwards with the full lmesh process.
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .map(|service_home| service_home.join(SERVICE_CONFIG_RELATIVE_PATH))
}

fn now_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

fn now_millis_u64() -> u64 {
    now_millis().min(u64::MAX as u128) as u64
}

impl UartService {
    fn record_message<T>(&self, _key: &str, _id: &str, _value: T) {}

    pub fn status(&self) -> Value {
        json!({
            "service": "lmesh-uart",
            "uart_enabled": true,
            "forward_count": self.serial_forwards.lock().map(|forwards| forwards.len()).unwrap_or(0),
        })
    }

    fn esp_serial_target(
        &self,
        adapter: Option<String>,
        port: Option<String>,
    ) -> Option<(String, String, u32)> {
        self.generic_serial_target(adapter, port)
    }

    fn generic_serial_target(
        &self,
        adapter: Option<String>,
        port: Option<String>,
    ) -> Option<(String, String, u32)> {
        let requested = port.or(adapter)?;
        let path = configured_serial_path(&requested).unwrap_or_else(|| requested.clone());
        let forwards = self
            .serial_forwards
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let baud = forwards
            .values()
            .find(|forward| forward.id == requested || forward.port == path)
            .map(|forward| forward.baud)
            .unwrap_or(460_800);
        Some(("direct-port".to_string(), path, baud))
    }

    fn record(&self, _key: &str, _value: Value) {}

    pub fn from_environment() -> Self {
        Self::from_environment_with_uart(true)
    }

    /// Create a Wi-Fi-only backend without opening configured serial forwards.
    ///
    /// The full lmesh process and lmesh-uart use [`Self::from_environment`].
    /// The standalone Wi-Fi service uses this constructor so it can own AP,
    /// STA, and NAN interfaces without taking UART devices or serial sockets.
    pub fn from_environment_without_uart() -> Self {
        Self::from_environment_with_uart(false)
    }

    fn from_environment_with_uart(enable_uart: bool) -> Self {
        let reverse_sessions = configured_esp_reverse_sessions();
        let service = Self {
            serial_forwards: Arc::new(Mutex::new(BTreeMap::new())),
            esp_reverse_sessions: Arc::new(reverse_sessions),
            esp_gateway: configured_esp_gateway(),
            esp_targets: Arc::new(configured_esp_targets()),
        };
        if enable_uart {
            service.start_configured_serial_forwards();
            service.start_configured_esp_reverse_sessions();
        }
        service
    }

    /// Report whether this backend owns UART forwards and serial logging.
    pub fn default_esp_route(
        &self,
        port: Option<&str>,
        adapter: Option<&str>,
    ) -> Option<(String, String)> {
        resolve_esp_route(&self.esp_gateway, &self.esp_targets, port, adapter)
    }
    fn serial_forward_socket(&self, id: &str) -> Option<String> {
        self.serial_forwards
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(id)
            .map(|forward| forward.socket_path.clone())
    }

    fn start_configured_esp_reverse_sessions(&self) {
        if self.esp_reverse_sessions.is_empty() {
            return;
        }
        let sessions = self.esp_reverse_sessions.clone();
        for session in sessions.values() {
            let session = session.clone();
            let uds_session = session.clone();
            let sessions = sessions.clone();
            std::thread::spawn(move || {
                if let Err(error) = reverse_main_uds_loop(uds_session.clone()) {
                    tracing::warn!(id = %uds_session.id, error = %error, "reverse_main_uds_exited");
                }
            });
            // One listener is enough for all configured boards on a port.
            // The first matching session owns it; all peers are checked
            // against the configured STA address before being accepted.
            if !sessions
                .values()
                .any(|other| other.id < session.id && other.port == session.port)
            {
                std::thread::spawn(move || {
                    if let Err(error) = reverse_main_accept_loop(session.port, sessions) {
                        tracing::warn!(port = session.port, error = %error, "reverse_main_listener_exited");
                    }
                });
            }
        }
    }
    fn start_configured_serial_forwards(&self) {
        let config_path = lmesh_config_path();
        let Some(config) = read_lmesh_config() else {
            self.record(
                "usb.serial.forward.config",
                json!({
                    "path": config_path,
                    "loaded": false,
                    "forwards": 0,
                }),
            );
            return;
        };
        self.record(
            "usb.serial.forward.config",
            json!({
                "path": config_path,
                "loaded": true,
                "forwards": config.serial_forwards.len(),
            }),
        );
        for forward in config.serial_forwards {
            if forward.enabled == Some(false) {
                continue;
            }
            let tcp_mode = forward
                .tcp_mode
                .clone()
                .or_else(|| forward.tcp_port.map(|_| "rfc2217".to_string()))
                .unwrap_or_else(|| "framed".to_string());
            let result = self.serial_forward_start(
                Some(forward.port.clone()),
                forward.baud,
                forward.tcp_port,
                Some(tcp_mode),
                Some(false),
                forward.multi,
                forward.direct,
            );
            self.record(
                "usb.serial.forward.autostart",
                json!({
                    "port": forward.port,
                    "result": result,
                }),
            );
        }
    }
    pub fn usb_serial_list(&self, handshake: Option<bool>) -> Value {
        let handshake = handshake.unwrap_or(false);
        let mut devices = discover_usb_serial_devices();
        for device in &mut devices {
            if let Some(path) = device
                .get("path")
                .and_then(Value::as_str)
                .map(str::to_string)
            {
                let forwards = self
                    .serial_forwards
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .values()
                    .filter(|forward| forward.port == path)
                    .map(|forward| {
                        json!({
                            "id": forward.id,
                            "socket": forward.socket_path,
                            "tcp_listen": forward.tcp_listen,
                            "baud": forward.baud,
                            "firmware": forward
                                .firmware_state
                                .lock()
                                .unwrap_or_else(|poisoned| poisoned.into_inner())
                                .snapshot(),
                        })
                    })
                    .collect::<Vec<_>>();
                if !forwards.is_empty() {
                    device["forwards"] = Value::Array(forwards);
                }
                if handshake && let Some(port) = device.get("port").and_then(Value::as_str) {
                    device["handshake"] = self.usb_serial_handshake(
                        Some(port.to_string()),
                        Some("dmesh".to_string()),
                        None,
                        None,
                    );
                }
            }
        }
        json!({
            "ok": true,
            "devices": devices,
            "forwards": self.serial_forward_list().get("forwards").cloned().unwrap_or(Value::Array(Vec::new())),
        })
    }

    /// Run a generic or firmware-specific serial handshake without claiming the device permanently.
    pub fn usb_serial_handshake(
        &self,
        port: Option<String>,
        profile: Option<String>,
        timeout_sec: Option<f64>,
        baud: Option<u32>,
    ) -> Value {
        let profile = profile.unwrap_or_else(|| "generic".to_string());
        let timeout_ms = timeout_sec
            .map(|secs| (secs.max(0.05) * 1000.0).round() as u64)
            .unwrap_or(DEFAULT_ESP_COMMAND_TIMEOUT_MS)
            // Sleepy ESP nodes may expose UART only every Nth raw-NAN wake
            // (the lab default is every 16th four-second wake, about 64 s).
            // Keep the caller's bounded wait long enough to reach the next
            // authorized heartbeat instead of silently truncating it at the
            // old 30-second ceiling.
            .clamp(50, 300_000);
        let Some(target) = resolve_usb_serial_target(port.clone(), baud) else {
            return json!({
                "ok": false,
                "error": "missing USB serial target; pass port=USB0 or port=ACM0",
            });
        };
        let UsbSerialTarget {
            id,
            path,
            socket_path: _,
            baud,
        } = target;
        let commands = match profile.as_str() {
            "dmesh" | "esp" | "esp32" => vec![
                "wifi raw_stats=true".to_string(),
                "nan".to_string(),
                "ble".to_string(),
            ],
            "none" => Vec::new(),
            command if command.starts_with("cmd:") => vec![command[4..].to_string()],
            _ => vec!["help".to_string()],
        };
        // A configured managed forward is the only owner of the physical
        // UART. Opening `path` here creates a second reader and can also
        // disturb CP210x modem-line state while a boot log is in flight.
        let forward_socket = port
            .as_deref()
            .and_then(|id| self.serial_forward_socket(id))
            .or_else(|| {
                self.serial_forwards
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .values()
                    .find(|forward| forward.port == path && !forward.stop.load(Ordering::Acquire))
                    .map(|forward| forward.socket_path.clone())
            });
        let Some(forward_socket) = forward_socket else {
            return json!({
                "ok": false,
                "radio_id": id,
                "path": path,
                "baud": baud,
                "profile": profile,
                "error": "serial handshake requires an active managed serial forward",
            });
        };
        let mut exchanges = Vec::new();
        let mut ok = true;
        for command in commands {
            let payload = firmware_command_cbor(&command)
                .and_then(|frame| mesh::cbor::decode_stream_frame(&frame).map(Vec::from));
            match payload
                .and_then(|payload| uds_cbor_exchange(&forward_socket, &payload, timeout_ms))
            {
                Ok(raw) => {
                    let messages = parse_raw_exchange_messages(&raw);
                    for message in &messages {
                        self.record_message("usb.serial.handshake.rx", &id, message.clone());
                    }
                    exchanges.push(json!({
                        "command": command,
                        "raw": raw,
                        "messages": messages,
                    }));
                }
                Err(error) => {
                    ok = false;
                    exchanges.push(json!({
                        "command": command,
                        "error": error.to_string(),
                    }));
                }
            }
        }
        let result = json!({
            "ok": ok,
            "radio_id": id,
            "path": path,
            "baud": baud,
            "profile": profile,
            "exchanges": exchanges,
        });
        self.record("usb.serial.handshake", result.clone());
        result
    }

    /// Send the fixed stage2 boot command through the already-managed UART
    /// forward.  This is intentionally separate from `esp.serial.command`:
    /// stage2 has no CBOR decoder and is still running at the boot UART rate.
    pub fn usb_serial_boot(
        &self,
        port: Option<String>,
        command: Option<String>,
        timeout_sec: Option<f64>,
        reset: Option<bool>,
    ) -> Value {
        let timeout_ms = timeout_sec
            .map(|secs| (secs.max(0.05) * 1000.0).round() as u64)
            .unwrap_or(1_000)
            .clamp(50, 30_000);
        let command = command.unwrap_or_else(|| "recovery".to_owned());
        let Some(payload) = boot_command_payload(&command).ok() else {
            return json!({
                "ok": false,
                "error": format!("unsupported boot command {command:?}; expected recovery or main"),
            });
        };
        let Some(target) = resolve_usb_serial_target(port.clone(), None) else {
            return json!({
                "ok": false,
                "error": "missing USB serial target; pass port=e5 or configure LMESH_SERIAL_DEVICES/lmesh.toml",
            });
        };
        let UsbSerialTarget {
            id,
            path,
            socket_path: _,
            baud,
        } = target;
        if reset.unwrap_or(false) {
            // Keep the managed forward as the only UART reader.  Resetting
            // the bridge is a modem-line operation; the existing forward
            // then reads, logs, and broadcasts the stage2 identity and this
            // request/response client consumes the same managed stream.
            let forward_socket = self.serial_forward_socket(&id);
            let Some(forward_socket) = forward_socket else {
                return json!({
                    "ok": false,
                    "radio_id": id,
                    "path": path,
                    "error": "stage2 reset requires an active managed serial forward",
                });
            };
            let boot_baud = 115_200;
            // Keep reset and selector on the descriptor owned by the managed
            // forward.  Opening the tty a second time is unsafe with CP210x:
            // closing that temporary descriptor can restore RTS and cancel
            // the reset before stage2 observes the selector.
            let result = connect_uds_boot(&forward_socket).and_then(|stream| {
                let forwards = self
                    .serial_forwards
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                let Some(forward) = forwards.get(&id) else {
                    return Err(anyhow::anyhow!(
                        "managed serial forward {id} disappeared before stage2 reset"
                    ));
                };
                forward.stats.reset_requests.fetch_add(1, Ordering::Relaxed);
                forward
                    .reset_request
                    .fetch_update(Ordering::AcqRel, Ordering::Acquire, |pending| {
                        Some(pending.saturating_add(1))
                    })
                    .map_err(|_| anyhow::anyhow!("failed to queue managed stage2 reset"))?;
                drop(forwards);
                uds_boot_exchange_stream(stream, &payload, timeout_ms)
            });
            return match result {
                Ok(hello) => {
                    let result = json!({
                        "ok": true,
                        "radio_id": id,
                        "path": path,
                        "baud": boot_baud,
                        "command": command,
                        "reset": true,
                        "hello": boot_identity_json(&hello),
                        "via": "managed_forward_reset",
                    });
                    self.record("usb.serial.boot", result.clone());
                    result
                }
                Err(error) => json!({
                    "ok": false,
                    "radio_id": id,
                    "path": path,
                    "baud": boot_baud,
                    "command": command,
                    "reset": true,
                    "via": "managed_forward_reset",
                    "error": error.to_string(),
                }),
            };
        }
        // Prefer the configured role key.  Matching only the resolved device
        // path is fragile when a deployment changes a symlink or when a
        // serial forward is restarted between target resolution and lookup;
        // the managed role socket remains authoritative and avoids opening
        // the physical UART as a fallback.
        let forward_socket = port
            .as_deref()
            .and_then(|id| self.serial_forward_socket(id))
            .or_else(|| {
                self.serial_forwards
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .values()
                    .find(|forward| forward.port == path && !forward.stop.load(Ordering::Acquire))
                    .map(|forward| forward.socket_path.clone())
            });
        let Some(socket_path) = forward_socket else {
            return json!({
                "ok": false,
                "radio_id": id,
                "path": path,
                "error": "stage2 boot commands require an active managed serial forward",
            });
        };
        match uds_boot_exchange(&socket_path, &payload, timeout_ms) {
            Ok(hello) => {
                let result = json!({
                    "ok": true,
                    "radio_id": id,
                    "path": path,
                    "baud": baud,
                    "command": command,
                    "hello": boot_identity_json(&hello),
                    "via": "managed_forward",
                });
                self.record("usb.serial.boot", result.clone());
                result
            }
            Err(error) => json!({
                "ok": false,
                "radio_id": id,
                "path": path,
                "baud": baud,
                "command": command,
                "via": "managed_forward",
                "error": error.to_string(),
            }),
        }
    }

    /// Start a generic byte-forwarding UDS for one USB serial device.
    pub fn serial_forward_start(
        &self,
        port: Option<String>,
        mut baud: Option<u32>,
        mut tcp_port: Option<u16>,
        mut tcp_mode: Option<String>,
        handshake: Option<bool>,
        mut multi: Option<bool>,
        direct: Option<bool>,
    ) -> Value {
        let configured = port
            .as_deref()
            .and_then(canonical_usb_port_id)
            .and_then(|id| configured_serial_forward(&id));
        let raw_output = configured
            .as_ref()
            .and_then(|configured| configured.raw)
            .unwrap_or(false);
        if let Some(configured) = configured.as_ref() {
            baud = baud.or(configured.baud);
            tcp_port = tcp_port.or(configured.tcp_port);
            tcp_mode = tcp_mode.or_else(|| configured.tcp_mode.clone());
            multi = multi.or(configured.multi);
        }
        // Probe firmware forwards immediately.  Once the device reports
        // infrastructure/active mode, client records are written directly;
        // otherwise they wait for the device's UART heartbeat/window.  Raw
        // byte forwards may still opt into immediate delivery explicitly.
        let direct_write = raw_output || direct.unwrap_or(false);
        let multi = multi.unwrap_or(false);
        let tcp_mode = match SerialForwardTcpMode::parse(tcp_mode.as_deref().unwrap_or("auto")) {
            Ok(mode) => mode,
            Err(error) => {
                return json!({
                    "ok": false,
                    "error": error.to_string(),
                });
            }
        };
        let Some(target) = resolve_usb_serial_target(port, baud) else {
            return json!({
                "ok": false,
                "error": "missing USB serial target; pass port=USB0 or port=ACM0",
            });
        };
        let UsbSerialTarget {
            id,
            path,
            socket_path,
            baud,
        } = target;
        {
            let forwards = self
                .serial_forwards
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if forwards.contains_key(&id) {
                return json!({
                    "ok": false,
                    "id": id,
                    "error": "serial forward already exists",
                });
            }
        }
        if let Some(parent) = PathBuf::from(&socket_path).parent() {
            if let Err(error) = fs::create_dir_all(parent) {
                return json!({
                    "ok": false,
                    "id": id,
                    "socket": socket_path,
                    "error": format!("failed to create socket parent: {error}"),
                });
            }
        }
        let _ = fs::remove_file(&socket_path);
        let listener = match UnixListener::bind(&socket_path) {
            Ok(listener) => listener,
            Err(error) => {
                return json!({
                    "ok": false,
                    "id": id,
                    "socket": socket_path,
                    "error": format!("failed to bind serial forward socket: {error}"),
                });
            }
        };
        if let Err(error) = configure_serial_forward_socket(&socket_path) {
            let _ = fs::remove_file(&socket_path);
            return json!({
                "ok": false,
                "id": id,
                "socket": socket_path,
                "error": error.to_string(),
            });
        }
        if let Err(error) = listener.set_nonblocking(true) {
            let _ = fs::remove_file(&socket_path);
            return json!({
                "ok": false,
                "id": id,
                "socket": socket_path,
                "error": format!("failed to set serial forward listener nonblocking: {error}"),
            });
        }
        let (tcp_listener, tcp_listen) = match tcp_port {
            Some(port) => {
                let bind_addr = format!("127.0.0.1:{port}");
                match TcpListener::bind(&bind_addr) {
                    Ok(listener) => {
                        if let Err(error) = listener.set_nonblocking(true) {
                            let _ = fs::remove_file(&socket_path);
                            return json!({
                                "ok": false,
                                "id": id,
                                "tcp_listen": bind_addr,
                                "error": format!("failed to set TCP serial forward listener nonblocking: {error}"),
                            });
                        }
                        let listen = listener
                            .local_addr()
                            .map(|addr| addr.to_string())
                            .unwrap_or(bind_addr);
                        (Some(listener), Some(listen))
                    }
                    Err(error) => {
                        let _ = fs::remove_file(&socket_path);
                        return json!({
                            "ok": false,
                            "id": id,
                            "tcp_listen": bind_addr,
                            "error": format!("failed to bind TCP serial forward: {error}"),
                        });
                    }
                }
            }
            None => (None, None),
        };
        let stop = Arc::new(AtomicBool::new(false));
        let reset_request = Arc::new(AtomicU8::new(SERIAL_RESET_NONE));
        let flush_request = Arc::new(AtomicBool::new(false));
        let log_flash_quiet_until_ms = Arc::new(AtomicU64::new(0));
        let stats = Arc::new(SerialForwardStats::default());
        let firmware_state = Arc::new(Mutex::new(FirmwareState::default()));
        let log_path = configured_serial_log_path_for_forward(&id);
        let thread_stop = stop.clone();
        let thread_reset_request = reset_request.clone();
        let thread_flush_request = flush_request.clone();
        let thread_log_flash_quiet_until_ms = log_flash_quiet_until_ms.clone();
        let thread_stats = stats.clone();
        let thread_firmware_state = firmware_state.clone();
        let thread_id = id.clone();
        let thread_path = path.clone();
        let thread_socket_path = socket_path.clone();
        let thread_tcp_listen = tcp_listen.clone();
        let thread_log_path = log_path.clone();
        let thread_log = log_path.as_ref().and_then(|path| match SerialForwardLog::open(path) {
            Ok(log) => Some(Arc::new(Mutex::new(log))),
            Err(error) => {
                tracing::warn!(forward_id = %id, path = %path, error = %error, "serial_forward_log_disabled");
                None
            }
        });
        let thread_baud = baud;
        let handle = std::thread::spawn(move || {
            let mut serial_listener = listener;
            let mut serial_tcp_listener = tcp_listener;
            loop {
                if thread_stop.load(Ordering::Acquire) {
                    break;
                }
                let retry_listener = match serial_listener.try_clone() {
                    Ok(listener) => listener,
                    Err(error) => {
                        tracing::debug!(
                            forward_id = %thread_id,
                            error = %error,
                            "serial_forward_listener_clone_failed"
                        );
                        break;
                    }
                };
                let retry_tcp_listener = match serial_tcp_listener.as_ref() {
                    Some(listener) => match listener.try_clone() {
                        Ok(listener) => Some(listener),
                        Err(error) => {
                            tracing::debug!(
                                forward_id = %thread_id,
                                error = %error,
                                "serial_forward_tcp_listener_clone_failed"
                            );
                            break;
                        }
                    },
                    None => None,
                };
                let result = serial_forward_loop(
                    &thread_id,
                    &thread_path,
                    thread_baud,
                    serial_listener,
                    serial_tcp_listener,
                    tcp_mode,
                    multi,
                    raw_output,
                    thread_reset_request.clone(),
                    thread_flush_request.clone(),
                    direct_write,
                    thread_log_flash_quiet_until_ms.clone(),
                    thread_stop.clone(),
                    thread_stats.clone(),
                    thread_firmware_state.clone(),
                    thread_log_path.clone(),
                    thread_log.clone(),
                );
                match result {
                    Ok(()) => break,
                    Err(error) if !thread_stop.load(Ordering::Acquire) => {
                        tracing::debug!(
                            forward_id = %thread_id,
                            port = %thread_path,
                            socket = %thread_socket_path,
                            tcp = ?thread_tcp_listen,
                            error = %error,
                            "serial_forward_waiting_for_device"
                        );
                        serial_listener = retry_listener;
                        serial_tcp_listener = retry_tcp_listener;
                        std::thread::sleep(std::time::Duration::from_secs(1));
                    }
                    Err(_) => break,
                }
            }
        });
        let runtime = SerialForwardRuntime {
            id: id.clone(),
            radio_id: id.clone(),
            port: path.clone(),
            socket_path: socket_path.clone(),
            tcp_listen: tcp_listen.clone(),
            log_path: log_path.clone(),
            baud,
            multi,
            reset_request,
            flush_request,
            stop,
            stats,
            firmware_state,
            handle: Some(handle),
            started_ms: now_millis_u64(),
        };
        self.serial_forwards
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(id.clone(), runtime);
        let handshake_result = handshake.unwrap_or(false).then(|| {
            self.usb_serial_handshake(Some(id.clone()), Some("dmesh".to_string()), Some(1.5), None)
        });
        let result = json!({
            "ok": true,
            "id": id,
            "port": path,
            "baud": baud,
            "multi": multi,
            "raw": raw_output,
            "tcp_mode": tcp_mode.name(),
            "socket": socket_path,
            "tcp_listen": tcp_listen,
            "log_path": log_path,
            "handshake": handshake_result,
        });
        self.record("usb.serial.forward.start", result.clone());
        result
    }

    /// Stop one managed serial forward.
    pub fn serial_forward_stop(&self, port: Option<String>) -> Value {
        let Some(key) = port
            .as_deref()
            .or(Some("USB0"))
            .and_then(canonical_usb_port_id)
        else {
            return json!({ "ok": false, "error": "missing USB serial target; pass port=USB0 or port=ACM0" });
        };
        let Some(mut runtime) = self
            .serial_forwards
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&key)
        else {
            return json!({ "ok": false, "id": key, "error": "serial forward not found" });
        };
        runtime.stop.store(true, Ordering::Release);
        let _ = std::os::unix::net::UnixStream::connect(&runtime.socket_path);
        if let Some(tcp_listen) = &runtime.tcp_listen {
            let _ = TcpStream::connect(tcp_listen);
        }
        if let Some(handle) = runtime.handle.take() {
            let _ = handle.join();
        }
        let _ = fs::remove_file(&runtime.socket_path);
        let result = json!({
            "ok": true,
            "id": runtime.id,
            "port": runtime.port,
            "multi": runtime.multi,
            "socket": runtime.socket_path,
            "tcp_listen": runtime.tcp_listen,
        });
        self.record("usb.serial.forward.stop", result.clone());
        result
    }

    /// List managed serial forwards.
    pub fn serial_forward_list(&self) -> Value {
        let forwards = self
            .serial_forwards
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .values()
            .map(|forward| {
                json!({
                    "id": forward.id,
                    "radio_id": forward.radio_id,
                    "port": forward.port,
                    "socket": forward.socket_path,
                    "baud": forward.baud,
                    "multi": forward.multi,
                    "available": Path::new(&forward.port).exists(),
                    "tcp_listen": forward.tcp_listen,
                    "log_path": forward.log_path,
                    "started_ms": forward.started_ms,
                    "running": !forward.stop.load(Ordering::Acquire),
                    "firmware": forward
                        .firmware_state
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .snapshot(),
                    "stats": forward.stats.snapshot(),
                })
            })
            .collect::<Vec<_>>();
        json!({ "ok": true, "forwards": forwards })
    }

    /// Request a one-shot flush of bytes queued for a sleepy/unknown forward.
    /// This does not change mode policy or touch modem lines.
    pub fn serial_forward_flush(&self, port: Option<String>) -> Value {
        let Some(key) = port
            .as_deref()
            .or(Some("USB0"))
            .and_then(canonical_usb_port_id)
        else {
            return json!({"ok": false, "error": "missing USB serial target; pass port=e5 or configure lmesh"});
        };
        let forwards = self
            .serial_forwards
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(forward) = forwards.get(&key) else {
            return json!({"ok": false, "id": key, "error": "serial forward not found"});
        };
        forward.flush_request.store(true, Ordering::Release);
        json!({
            "ok": true,
            "id": forward.id,
            "socket": forward.socket_path,
            "queued": "flush_requested",
            "via": "managed_forward",
        })
    }

    /// Reset an explicitly requested ESP through the descriptor owned by its
    /// managed forward. This is important for CP210x devices: a second open
    /// can restore modem lines as soon as it closes, cancelling the reset.
    pub fn serial_modem_reset(&self, port: Option<String>) -> Value {
        let Some(id) = port.clone() else {
            return json!({"ok": false, "error": "missing USB serial target"});
        };
        let forwards = self
            .serial_forwards
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(forward) = forwards.get(&id) else {
            return json!({"ok": false, "id": id, "error": "RTS reset requires an active managed serial forward"});
        };
        forward.stats.reset_requests.fetch_add(1, Ordering::Relaxed);
        let _ =
            forward
                .reset_request
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |pending| {
                    Some(pending.saturating_add(1))
                });
        json!({
            "ok": true,
            "id": id,
            "path": forward.port,
            "line": "RTS",
            "asserted": false,
            "pulse_ms": 120,
            "via": "active_forward",
        })
    }

    /// Release DTR if an external tty opener left it asserted.
    /// Assertion and pulse operations are deliberately disabled.
    pub fn serial_modem_dtr(
        &self,
        port: Option<String>,
        asserted: Option<bool>,
        pulse_ms: Option<u64>,
    ) -> Value {
        if asserted != Some(false) {
            return json!({
                "ok": false,
                "error": "DTR assertion is disabled; only asserted=false release is permitted"
            });
        }
        self.serial_modem_line(port, libc::TIOCM_DTR, asserted, pulse_ms.unwrap_or(100))
    }

    fn serial_modem_line(
        &self,
        port: Option<String>,
        line: libc::c_int,
        asserted: Option<bool>,
        pulse_ms: u64,
    ) -> Value {
        let Some(id) = port.as_deref().and_then(canonical_usb_port_id) else {
            return json!({"ok": false, "error": "missing USB serial target"});
        };
        let Some(path) = usb_port_path(&id) else {
            return json!({"ok": false, "id": id, "error": "USB serial path not found"});
        };
        let result = (|| -> Result<Value> {
            let fd = fs::OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(libc::O_NOCTTY)
                .open(&path)?;
            let set = |value: bool| -> Result<()> {
                let mut mask = line;
                let request = if value {
                    libc::TIOCMBIS
                } else {
                    libc::TIOCMBIC
                };
                if unsafe { libc::ioctl(fd.as_raw_fd(), request, &mut mask) } < 0 {
                    return Err(std::io::Error::last_os_error().into());
                }
                Ok(())
            };
            if let Some(value) = asserted {
                set(value)?;
            } else {
                // USB-UART bridges used by ESP boards drive GPIO0 low when
                // DTR is asserted. Keep that level long enough for the
                // light-sleep GPIO wake detector to observe it.
                set(true)?;
                std::thread::sleep(std::time::Duration::from_millis(pulse_ms));
                set(false)?;
            }
            Ok(
                json!({"ok": true, "id": id, "path": path, "line": if line == libc::TIOCM_RTS {"RTS"} else {"DTR"}, "asserted": asserted.unwrap_or(true), "pulse_ms": pulse_ms}),
            )
        })();
        match result {
            Ok(value) => value,
            Err(error) => {
                json!({"ok": false, "id": id, "path": path, "error": format!("{error:#}")})
            }
        }
    }
    pub fn esp_serial_command(
        &self,
        adapter: Option<String>,
        port: Option<String>,
        command: String,
        timeout_sec: Option<f64>,
    ) -> Value {
        self.esp_serial_command_with_options(adapter, port, command, timeout_sec, false)
    }

    fn wait_for_firmware_role(&self, id: &str, role: &str, timeout: Duration) -> Result<()> {
        let deadline = Instant::now() + timeout;
        loop {
            let state = self
                .serial_forwards
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .get(id)
                .map(|forward| {
                    forward
                        .firmware_state
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .clone()
                });
            if state.as_ref().and_then(|value| value.role.as_deref()) == Some(role) {
                return Ok(());
            }
            if Instant::now() >= deadline {
                let observed = state.map(|value| value.snapshot()).unwrap_or(Value::Null);
                bail!("timed out waiting for {id} boot identity role={role}: {observed}");
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// Run one command against an ESP firmware serial adapter with an
    /// optional per-client direct-delivery override. The override is only for
    /// a caller that has independently established that the board is awake;
    /// it must not change the forward's default sleepy-node policy.
    pub fn esp_serial_command_with_options(
        &self,
        adapter: Option<String>,
        port: Option<String>,
        command: String,
        timeout_sec: Option<f64>,
        force_direct: bool,
    ) -> Value {
        let timeout_ms = timeout_sec
            .map(|secs| (secs.max(0.05) * 1000.0).round() as u64)
            .unwrap_or(DEFAULT_ESP_COMMAND_TIMEOUT_MS)
            // A battery node may open UART only every sixteenth 4-second
            // raw-NAN wake (~64 s). Do not silently truncate a caller's
            // bounded wait below that rendezvous interval.
            .clamp(50, 300_000);
        let target = self.esp_serial_target(adapter, port.clone());
        let Some((radio_id, path, baud)) = target else {
            return json!({
                "ok": false,
                "error": "missing ESP serial adapter; pass port or configure LMESH_SERIAL_DEVICES/lmesh.toml",
            });
        };
        let forward_id = port.as_deref().unwrap_or(&radio_id).to_owned();
        // A Recovery transport command is a handoff operation, not an
        // ordinary Main command. If Main is currently running, use the
        // managed Stage2 selector/reset path, wait for both boot identities
        // to be observed by this forward, and only then put the Recovery
        // packet on the UART. Callers use recovery commands; they do not
        // need force_direct or timing sleeps.
        let recovery_payload = command.starts_with("recovery ")
            && !command.contains("reboot=true")
            && !command.contains("op=main")
            && !command.contains("op=reboot_main");
        if recovery_payload {
            let role = self
                .serial_forwards
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .get(&forward_id)
                .and_then(|forward| {
                    forward
                        .firmware_state
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .role
                        .clone()
                });
            if role.as_deref() != Some("recovery") {
                let selector = self.usb_serial_boot(
                    Some(forward_id.clone()),
                    Some("recovery".to_owned()),
                    Some(3.0),
                    Some(true),
                );
                if selector.get("ok") != Some(&Value::Bool(true)) {
                    return json!({
                        "ok": false,
                        "radio_id": radio_id,
                        "path": path,
                        "baud": baud,
                        "command": command,
                        "error": "Recovery selector/reset failed",
                        "selector": selector,
                    });
                }
                if let Err(error) =
                    self.wait_for_firmware_role(&forward_id, "recovery", Duration::from_secs(8))
                {
                    return json!({
                        "ok": false,
                        "radio_id": radio_id,
                        "path": path,
                        "baud": baud,
                        "command": command,
                        "error": error.to_string(),
                        "selector": selector,
                    });
                }
            }
        }
        let forward_socket = port
            .as_deref()
            .and_then(|id| self.serial_forward_socket(id))
            .or_else(|| {
                self.serial_forwards
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .values()
                    .find(|forward| forward.port == path && !forward.stop.load(Ordering::Acquire))
                    .map(|forward| forward.socket_path.clone())
            });
        if let Some(socket_path) = forward_socket {
            return match uds_console_exchange_with_options(
                &socket_path,
                &command,
                timeout_ms,
                force_direct,
            ) {
                Ok(output) => {
                    let result = json!({
                        "ok": true,
                        "radio_id": radio_id,
                        "path": path,
                        "baud": baud,
                        "command": command,
                        "via": "managed_forward",
                        "messages": [{"console": output}],
                    });
                    self.record("esp.serial.command", result.clone());
                    result
                }
                Err(error) => json!({
                    "ok": false,
                    "radio_id": radio_id,
                    "path": path,
                    "baud": baud,
                    "command": command,
                    "via": "managed_forward",
                    "error": error.to_string(),
                }),
            };
        }
        json!({
            "ok": false,
            "radio_id": radio_id,
            "path": path,
            "baud": baud,
            "command": command,
            "error": "physical UART access is disabled; use an active managed serial forward",
        })
    }

    /// Send an existing compact-CBOR firmware command over Main's temporary
    /// STA maintenance listener.  This deliberately has no UART fallback:
    /// callers use NAN to activate the session, then specify the board's
    /// numeric `ip:port` endpoint for reliable command and block-image work.
    pub fn esp_tcp_command(
        &self,
        endpoint: String,
        command: String,
        timeout_sec: Option<f64>,
    ) -> Value {
        let timeout_ms = timeout_sec
            .map(|secs| (secs.max(0.05) * 1000.0).round() as u64)
            .unwrap_or(3_000)
            .clamp(50, 300_000);
        let result = match self
            .esp_reverse_sessions
            .get(&endpoint)
            .map(|session| reverse_main_exchange(session, &command, timeout_ms))
            .unwrap_or_else(|| tcp_firmware_exchange(&endpoint, &command, timeout_ms))
        {
            Ok(response) => json!({
                "ok": true,
                "endpoint": endpoint,
                "command": command,
                "via": "main_tcp_session",
                "response": response,
            }),
            Err(error) => json!({
                "ok": false,
                "endpoint": endpoint,
                "command": command,
                "via": "main_tcp_session",
                "error": error.to_string(),
            }),
        };
        self.record("esp.serial.command", result.clone());
        result
    }
}

#[cfg(test)]
mod log_fields_tests {
    use super::{boot_identity_json, cbor_log_fields};
    use serde_json::json;

    #[test]
    fn cbor_log_fields_flattens_and_omits_normal_status() {
        let fields = cbor_log_fields(&json!({
            "method": "event",
            "payload": {
                "message": "event type=mode.state active=infra",
                "data": {"infra_active": true}
            },
            "status": "ok"
        }));
        assert_eq!(
            fields,
            "method=event payload.data.infra_active=true payload.message=\"event type=mode.state active=infra\""
        );
    }

    #[test]
    fn cbor_log_fields_retains_non_default_status() {
        assert_eq!(
            cbor_log_fields(&json!({"method": "status", "status": "error"})),
            "method=status status=error"
        );
    }

    #[test]
    fn boot_identity_exposes_rtc_and_persisted_boot_target() {
        // {7: 60000, 6: [role, partition, reset, handoff, main_failures,
        // recovery_failures, recent_resets, rtc_tick, stage2_version,
        // boot_target_configured, boot_target, mac]}
        let payload = [
            0xbf, 0x07, 0x19, 0xea, 0x60, 0x06, 0x9f, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x1a, 0x12, 0x34, 0x56, 0x78, 0x18, 0x2a, 0x01, 0x02, 0x46,
            0x14, 0xc1, 0x9f, 0xe5, 0x98, 0x00, 0xff, 0xff,
        ];

        assert_eq!(
            boot_identity_json(&payload),
            json!({
                "valid": true,
                "kind": "event",
                "event_id": 60000,
                "event_name": "boot.identity",
                "tuple": [0, 0, 0, 0, 0, 0, 0, 0x12345678_u64, 42, 1, 2, "14c19fe59800"],
                "stage2_version": 42,
                "boot_target_configured": 1,
                "boot_target": 2,
            })
        );
    }
}
