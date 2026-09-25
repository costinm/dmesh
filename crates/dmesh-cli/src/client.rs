//! Direct serial L2 adapter for the standalone `dmesh-cli` host client.
//!
//! This belongs to `dmesh-cli`, not Recovery or firmware. It
//! opens an explicitly supplied serial port with no managed forward. The
//! optional initial record is opaque: commands/logs remain higher-level
//! transport services and this adapter never decodes them.

use crate::flash::{
    FlashTarget, flash_upload_object, flash_upload_success, object_upload_timeout,
    run_automated_flash,
};
use crate::uart::DeviceSession;
use crate::{
    device::{
        DeviceProfile, device_catalog_path, load_device, resolve_catalog_target, resolve_udp_peer,
    },
    schema::{
        encode_direct_command_with_id, encode_stream_argv_with_id, encode_stream_command_with_id,
        is_stream_command_name, load_tagged_schema, render_device_record,
    },
};
use dmesh_server::{
    announce,
    probe::{ProbeRun, ProbeServicePlan},
    uart::{UartIngress, classify_uart_payload, encode_uart_datagram},
    udp::{fresh_connection_id, fresh_request_id},
};
use quic_lite::{ClientAssociation, ConnectionLimits, LocalAddress, StreamFrame};
use std::{
    collections::BTreeMap,
    env,
    fs::{File, OpenOptions},
    io::{ErrorKind, Read, Write},
    net::{Ipv6Addr, SocketAddr, SocketAddrV6},
    os::fd::AsRawFd,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use uart_codec::codec::{Decoder, encode_payload};

pub(crate) fn is_fatal_diagnostic(line: &str) -> bool {
    let line = line.to_ascii_lowercase();
    [
        "panic",
        "guru meditation",
        "assert failed",
        "backtrace",
        "abort()",
        // A ROM reset after the initial session drain means the device
        // restarted during this suite even if it did not print a panic.
        "rst:",
    ]
    .iter()
    .any(|marker| line.contains(marker))
}

fn usage() -> ! {
    eprintln!(
        "usage: dmesh-cli SERIAL|DEVICE --reset\n       dmesh-cli SERIAL|DEVICE --watch [--reset] [--interactive] [--baud PHYSICAL_UART_BAUD] [--timeout-secs N]\n       dmesh-cli DEVICE METHOD [--field=value ...]\n       dmesh-cli devices check|backfill [--dry-run]\n       dmesh-cli discover\n       dmesh-cli flash TARGET [--target main|recovery|stage2|MODULE] [--file IMAGE]\n       dmesh-cli SERIAL|DEVICE [--msg TEXT | --direct-hex HEX] [--timeout-secs N]\n       dmesh-cli lmesh METHOD [--field=value ...]\n       dmesh-cli NODE check\n       dmesh-cli udp://HOST:PORT --socket PATH\n       dmesh-cli http://HOST:PORT SERVICE.METHOD [--field=value ...]"
    );
    std::process::exit(2)
}

fn hex(value: &str) -> Result<Vec<u8>, String> {
    if value.len() % 2 != 0 {
        return Err("hex length must be even".into());
    }
    (0..value.len())
        .step_by(2)
        .map(|offset| {
            u8::from_str_radix(&value[offset..offset + 2], 16).map_err(|error| error.to_string())
        })
        .collect()
}

pub(crate) fn hex_encode(value: &[u8]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Render a 6-byte radio MAC as a colon-separated lowercase hex string.
pub(crate) fn mac_encode(value: &[u8]) -> String {
    value
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn physical_baud(value: u32) -> Option<libc::speed_t> {
    match value {
        9_600 => Some(libc::B9600),
        19_200 => Some(libc::B19200),
        38_400 => Some(libc::B38400),
        57_600 => Some(libc::B57600),
        115_200 => Some(libc::B115200),
        230_400 => Some(libc::B230400),
        460_800 => Some(libc::B460800),
        921_600 => Some(libc::B921600),
        _ => None,
    }
}

/// Configure record framing without imposing a physical UART speed on a
/// packetized USB serial device. `--baud` is deliberately opt-in: it both
/// configures a real UART and enables matching 8N1 pacing in the L2 adapter.
pub(crate) fn configure_serial(file: &File, baud: Option<u32>) -> Result<(), String> {
    unsafe {
        let mut value: libc::termios = core::mem::zeroed();
        if libc::tcgetattr(file.as_raw_fd(), &mut value) != 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        let original = value;
        libc::cfmakeraw(&mut value);
        // A direct QUIC-lite session is a packet bearer, not a modem call.
        // Leave carrier local and suppress HUPCL so closing a short-lived
        // CLI request cannot drop DTR/RTS and reset an attached ESP board.
        // Modem-line experiments are explicit service operations elsewhere.
        value.c_cflag |= libc::CLOCAL;
        value.c_cflag &= !libc::HUPCL;
        if let Some(baud) = baud {
            let speed = physical_baud(baud).ok_or_else(|| {
                format!("unsupported physical UART baud {baud}; use 9600..921600 standard rates")
            })?;
            if libc::cfsetispeed(&mut value, speed) != 0
                || libc::cfsetospeed(&mut value, speed) != 0
            {
                return Err(std::io::Error::last_os_error().to_string());
            }
        }
        // Avoid a redundant TCSETS: a CP2102 may treat even an identical
        // termios update as a modem-state transition.  The common case is an
        // already-configured 115200 8N1 raw console, so leave it untouched.
        if libc::memcmp(
            (&original as *const libc::termios).cast(),
            (&value as *const libc::termios).cast(),
            core::mem::size_of::<libc::termios>(),
        ) != 0
            && libc::tcsetattr(file.as_raw_fd(), libc::TCSANOW, &value) != 0
        {
            return Err(std::io::Error::last_os_error().to_string());
        }
        let flags = libc::fcntl(file.as_raw_fd(), libc::F_GETFL);
        if flags < 0 || libc::fcntl(file.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) != 0
        {
            return Err(std::io::Error::last_os_error().to_string());
        }
    }
    Ok(())
}

/// Open a physical serial bearer without acquiring it as this process's
/// controlling terminal.  CP2102 bridges can change modem outputs when a
/// process opens the port as a controlling TTY, which resets ESP boards before
/// the first QUIC-lite packet.  Normal sessions never need DTR or RTS; reset
/// remains an explicit command path below.
pub(crate) fn open_serial(path: &str) -> Result<File, String> {
    OpenOptions::new()
        .read(true)
        .write(true)
        // Apply nonblocking at open time too.  Doing so only after `open(2)`
        // can let the USB serial driver assert its default modem state for
        // one transition on CP2102-backed ESP boards.
        .custom_flags(libc::O_NOCTTY | libc::O_NONBLOCK)
        .open(path)
        .map_err(|error| error.to_string())
}

pub(crate) fn send_ppp(serial: &mut File, payload: &[u8]) -> Result<(), String> {
    let wire = encode_payload(payload, quic_lite::DEFAULT_MAX_DATAGRAM_SIZE + 1)
        .map_err(|error| error.to_string())?;
    serial.write_all(&wire).map_err(|error| error.to_string())
}

/// Run the standalone DMesh client using process arguments.
pub fn run_dmesh_cli() -> Result<(), String> {
    run_dmesh_cli_args(env::args().skip(1))
}

/// Run the exact CLI client with supplied arguments. Managed callers use this
/// instead of spawning the executable, so tests, the CLI, and the Wi-Fi
/// gateway keep one L2/session implementation.
pub fn run_dmesh_cli_args(args: impl IntoIterator<Item = String>) -> Result<(), String> {
    let mut arguments: Vec<String> = args.into_iter().collect();
    if arguments
        .first()
        .is_some_and(|target| target.starts_with("http://"))
    {
        return crate::http::run(&arguments);
    }
    if arguments.as_slice() == ["devices", "check"] {
        return run_devices_check();
    }
    if matches!(arguments.as_slice(), [devices, backfill] if devices == "devices" && backfill == "backfill")
    {
        return run_devices_backfill(false);
    }
    if matches!(arguments.as_slice(), [devices, backfill, dry_run] if devices == "devices" && backfill == "backfill" && dry_run == "--dry-run")
    {
        return run_devices_backfill(true);
    }
    if arguments.as_slice() == ["discover"] {
        return run_hosts_discovery();
    }
    if arguments
        .first()
        .is_some_and(|argument| argument == "flash")
    {
        return run_automated_flash(&arguments[1..]);
    }
    if arguments.get(1).is_some_and(|argument| argument == "check") {
        return run_check_command(&arguments);
    }
    if arguments
        .first()
        .is_some_and(|target| lmesh_socket_target(target).is_some())
    {
        return run_lmesh_client(&arguments);
    }
    if arguments
        .get(1)
        .is_some_and(|argument| argument == "--reset")
    {
        if arguments.len() != 2 {
            return Err("--reset accepts exactly one serial target".into());
        }
        let target = arguments.first().cloned().unwrap_or_else(|| usage());
        if !target.starts_with('/') {
            let profile = load_device(&target)?;
            let serial = profile
                .serial_path()?
                .ok_or_else(|| format!("device {target:?} has no serial_id for --reset"))?;
            arguments[0] = serial.display().to_string();
        }
        return reset_serial(&arguments[0]);
    }
    // Watch is explicitly a physical UART operation. A device profile with
    // both serial and static-UDP paths must not silently choose UDP here.
    if arguments
        .get(1)
        .is_some_and(|argument| argument == "--watch")
    {
        let target = arguments.first().cloned().unwrap_or_else(|| usage());
        if !target.starts_with('/') {
            if target.contains(':') {
                return Err(
                    "--watch requires a serial path or device profile, not an IP target".into(),
                );
            }
            let profile = load_device(&target)?;
            let serial = profile
                .serial_path()?
                .ok_or_else(|| format!("device {target:?} has no serial_id for --watch"))?;
            arguments[0] = serial.display().to_string();
            append_catalog_uart_baud(&mut arguments, &profile);
        }
        return run_serial_watch(&arguments);
    }
    // Raw records are an intentional, bounded physical-bearer lane for
    // schema-defined bootstrap/control and diagnostics.  An explicit UDP URI
    // selects the companion's private direct-control lane; a named profile remains
    // serial-first so a routine local command cannot silently use the radio.
    if arguments
        .get(1)
        .is_some_and(|argument| matches!(argument.as_str(), "--direct-hex" | "--msg"))
    {
        let target = arguments.first().cloned().unwrap_or_else(|| usage());
        if target.starts_with("udp://") {
            return run_udp_direct_record(&arguments);
        }
        if !target.starts_with('/') {
            if target.contains(':') {
                return Err(
                    "--msg requires an explicit udp:// target, serial path, or device profile"
                        .into(),
                );
            }
            let profile = load_device(&target)?;
            let serial = profile
                .serial_path()?
                .ok_or_else(|| format!("device {target:?} has no serial_id for --msg"))?;
            arguments[0] = serial.display().to_string();
            append_catalog_uart_baud(&mut arguments, &profile);
        }
        return run_serial_direct_record(&arguments);
    }
    if let Some(target) = arguments
        .first()
        .cloned()
        .filter(|target| !target.starts_with("udp://"))
    {
        if let Some(profile) = resolve_catalog_target(&target)? {
            return run_catalog_target_service(&arguments, &profile);
        }
        match resolve_udp_peer(&target) {
            Ok(Some(peer)) => {
                arguments[0] = format!("udp://{peer}");
                return run_udp_service_client(&arguments);
            }
            Ok(None) => {}
            // A serial-only device profile is still a valid shell target.
            // Preserve the existing explicit UART backend arguments after
            // replacing its name with the resolved `/dev/serial/by-id` path.
            Err(_) if !target.starts_with('/') && !target.contains(':') => {
                let profile = load_device(&target)?;
                let serial = profile.serial_path()?.ok_or_else(|| {
                    format!("device {target:?} has neither static_ipv4 nor serial_id")
                })?;
                arguments[0] = serial.display().to_string();
                append_catalog_uart_baud(&mut arguments, &profile);
            }
            Err(error) => return Err(error),
        }
    }
    if arguments
        .first()
        .is_some_and(|target| target.starts_with("udp://"))
    {
        return run_udp_service_client(&arguments);
    }
    // A serial service probe is a direct QUIC-lite client. It is the smallest end-to-end check for
    // the shared firmware dispatcher and lets a failed UDP bearer be isolated
    // without reintroducing a command-specific UART protocol.
    if arguments
        .get(1)
        .is_some_and(|argument| is_stream_command_name(argument))
    {
        return run_serial_stream_command(&arguments);
    }
    Err("unsupported command form; select a UART path, UDP endpoint, named device, or lmesh service".into())
}

fn run_check_command(arguments: &[String]) -> Result<(), String> {
    let explicit_baud = match arguments {
        [_, _] => None,
        [_, _, flag, value] if flag == "--baud" => Some(
            value
                .parse::<u32>()
                .map_err(|error| format!("invalid check --baud: {error}"))?,
        ),
        _ => return Err("check accepts NODE [--baud PHYSICAL_UART_BAUD]".into()),
    };
    let target = arguments.first().cloned().unwrap_or_else(|| usage());
    if target.starts_with("udp://") {
        if explicit_baud.is_some() {
            return Err("--baud applies only to a UART check".into());
        }
        return run_udp_direct_discovery(parse_udp_peer(target.trim_start_matches("udp://"))?);
    }
    if !target.starts_with('/') {
        if let Ok(Some(peer)) = resolve_udp_peer(&target) {
            if explicit_baud.is_some() {
                return Err("--baud applies only to a UART check".into());
            }
            return run_udp_direct_discovery(peer);
        }
        let profile = load_device(&target)?;
        let serial = profile
            .serial_path()?
            .ok_or_else(|| format!("device {target:?} has no reachable check path"))?;
        return run_serial_direct_discovery(
            &serial.display().to_string(),
            explicit_baud.or(profile.uart_baud),
        );
    }
    run_serial_direct_discovery(&target, explicit_baud)
}

/// Resolve the supervised lmesh control socket.
fn lmesh_socket_target(target: &str) -> Option<&str> {
    match target {
        "lmesh" | "lmesh://lmesh" => Some("/run/mesh/lmesh/mesh.sock.cbor"),
        _ => target.strip_prefix("uds://"),
    }
}

/// Invoke a catalogued lmesh method over its tagged-CBOR control socket.
fn run_lmesh_client(arguments: &[String]) -> Result<(), String> {
    let target = arguments.first().ok_or("missing lmesh target")?;
    let socket = lmesh_socket_target(target).ok_or("invalid lmesh target")?;
    let method = arguments
        .get(1)
        .ok_or("lmesh requires METHOD [--field=value ...]")?;
    let catalog = mesh::tagged::load_service_catalog("lmesh")
        .transpose()
        .map_err(|error| error.to_string())?
        .ok_or("no installed lmesh tools.json; set MESH_SCHEMA_DIR")?;
    if catalog.method(method).is_none() {
        return Err(format!("unknown lmesh method {method}"));
    }
    let mut record = catalog
        .parse_argv(method, &arguments[2..])
        .map_err(|error| error.to_string())?;
    record.id = Some(serde_json::Value::from(fresh_request_id()));
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| error.to_string())?;
    let response = runtime
        .block_on(async {
            let socket = mesh::seqpacket::UnixSeqpacket::connect(socket).await?;
            socket.send_cbor_record(&record, &[]).await?;
            let (response, fds) =
                tokio::time::timeout(Duration::from_secs(10), socket.recv_cbor_record())
                    .await??
                    .ok_or_else(|| {
                        anyhow::anyhow!("lmesh CBOR socket closed without a response")
                    })?;
            anyhow::ensure!(
                fds.is_empty(),
                "unexpected file descriptors in lmesh response"
            );
            Ok::<_, anyhow::Error>(mesh::tagged::to_json(&response, Some(&catalog)))
        })
        .map_err(|error| error.to_string())?;
    println!(
        "dmesh_cli_lmesh_response endpoint={socket} method={method} {}",
        response
    );
    Ok(())
}

/// Direct physical reset for the client that owns the serial port.  This is
/// intentionally outside any retired forwarding service.
fn reset_serial(path: &str) -> Result<(), String> {
    let file = open_serial(path)?;
    pulse_serial_reset(&file)?;
    println!("dmesh_cli_reset target={path} line=RTS pulse_ms=120");
    Ok(())
}

/// Pulse RTS while the caller retains exclusive ownership of the serial port.
///
/// A boot diagnostic watch must use this instead of the standalone reset
/// command: closing and reopening a CP210x port after the pulse can lose the
/// ROM, Stage2, and early Main records that explain an otherwise silent UART
/// bootstrap failure.  It is intentionally available only to the direct
/// physical UART client, never to a routed transport operation.
fn pulse_serial_reset(file: &File) -> Result<(), String> {
    // CP210x LoRa boards wire RTS to EN and DTR to GPIO0.  RTS is therefore
    // the only reset line; DTR must be released before it, otherwise a reset
    // can enter the ROM serial downloader rather than Stage2/Main.  A prior
    // flasher owns these lines and may have closed while DTR was asserted, so
    // do not rely on the port driver's inherited modem state here.
    let mut released = libc::TIOCM_DTR | libc::TIOCM_RTS;
    unsafe {
        if libc::ioctl(file.as_raw_fd(), libc::TIOCMBIC, &mut released) < 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
    }
    let mut rts = libc::TIOCM_RTS;
    unsafe {
        if libc::ioctl(file.as_raw_fd(), libc::TIOCMBIS, &mut rts) < 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
    }
    thread::sleep(Duration::from_millis(120));
    unsafe {
        if libc::ioctl(file.as_raw_fd(), libc::TIOCMBIC, &mut rts) < 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
    }
    Ok(())
}

pub(crate) fn send_uart_transport(serial: &mut File, packet: &[u8]) -> Result<(), String> {
    let mut marked = [0u8; quic_lite::DEFAULT_MAX_DATAGRAM_SIZE + 1];
    let used = encode_uart_datagram(packet, &mut marked).ok_or("UART packet too large")?;
    send_ppp(serial, &marked[..used])
}

/// The UART session is the sole serial owner. Direct records are never used
/// as services, but retaining them here makes the narrowly permitted
/// UART-QUIC diagnostic line visible when transport setup itself fails.
fn report_uart_direct_record(path: &str, record: &[u8], filter: &mut WatchTextFilter) {
    match core::str::from_utf8(record) {
        Ok(text) if filter.retain(text) => eprintln!("dmesh_uart_diagnostic target={path} {text}"),
        Ok(_) => {}
        Err(_) => eprintln!(
            "dmesh_uart_diagnostic target={path} nontext_record_bytes={} hex={}",
            record.len(),
            hex_encode(record)
        ),
    }
}

/// Observe line-oriented ASCII emitted outside PPP framing. This is only the
/// UART/QUIC-lite troubleshooting channel used for boot, crash, and narrow
/// transport diagnostics; normal firmware logs are still read through the
/// flow-controlled `log-watch` service.
///
/// A PPP delimiter discards an unfinished text candidate. Consecutive PPP
/// frames may share a delimiter, but their binary payload cannot produce a
/// line because non-printable bytes discard the candidate. Keeping this tap
/// in the host shell avoids giving raw text any role in the L2 protocol.
#[derive(Default)]
pub(crate) struct RawTextTap {
    line: Vec<u8>,
}

/// The ESP-IDF sniffer teardown diagnostic may repeat at a fixed cadence while
/// the radio settles.  Keep the first line for diagnosis but avoid drowning a
/// bounded boot watch in identical text.
#[derive(Default)]
struct WatchTextFilter {
    seen_disable_sniffer: bool,
    suppressed_disable_sniffer: u64,
}

impl WatchTextFilter {
    fn retain(&mut self, line: &str) -> bool {
        if line.contains("ic_disable_sniffer") {
            if self.seen_disable_sniffer {
                self.suppressed_disable_sniffer = self.suppressed_disable_sniffer.saturating_add(1);
                return false;
            }
            self.seen_disable_sniffer = true;
        }
        true
    }
}

impl RawTextTap {
    const MAX_LINE: usize = 512;

    pub(crate) fn push(&mut self, bytes: &[u8]) -> Vec<String> {
        let mut lines = Vec::new();
        for byte in bytes {
            match *byte {
                0x7e => self.line.clear(),
                b'\r' => {}
                b'\n' if !self.line.is_empty() => {
                    if let Ok(line) = String::from_utf8(core::mem::take(&mut self.line)) {
                        lines.push(line);
                    }
                }
                b'\n' => {}
                byte if byte.is_ascii_graphic() || byte == b' ' || byte == b'\t' => {
                    if self.line.len() < Self::MAX_LINE {
                        self.line.push(byte);
                    } else {
                        self.line.clear();
                    }
                }
                _ => self.line.clear(),
            }
        }
        lines
    }
}

/// Directly list a device's registered stream handlers through its UART L2.
/// This intentionally shares the exact bootstrap and request packets used by
/// the UDP client; only PPP framing and file I/O differ.
fn run_serial_stream_command(arguments: &[String]) -> Result<(), String> {
    let mut service_arguments = Vec::new();
    let mut baud = None;
    let mut index = 1;
    while index < arguments.len() {
        if arguments[index] == "--baud" {
            index += 1;
            baud = Some(
                arguments
                    .get(index)
                    .ok_or("missing --baud value")?
                    .parse::<u32>()
                    .map_err(|error| error.to_string())?,
            );
        } else {
            service_arguments.push(arguments[index].clone());
        }
        index += 1;
    }
    let body = encode_stream_argv_with_id(&service_arguments, fresh_request_id())
        .map_err(|error| error.to_string())?;
    let path = arguments.first().ok_or("missing serial path")?;
    let tagged_probe = dmesh_server::tagged::decode(&body)
        .and_then(dmesh_server::probe::decode_probe_run_record)
        .map(|(_, request)| request);
    if let Some(request) = tagged_probe {
        let mut session = DeviceSession::open(path.clone(), baud)?;
        let mut client = dmesh_server::transport::ProbeClient::<
            16,
            { quic_lite::DEFAULT_MAX_DATAGRAM_SIZE },
        >::from_request(fresh_connection_id(), request)
        .map_err(|error| format!("probe client: {error:?}"))?;
        let stats = session.drive_client(&mut client, Duration::from_secs(45), "probe")?;
        let mut close = [0u8; quic_lite::DEFAULT_MAX_DATAGRAM_SIZE];
        if let Some(used) = client
            .poll_close(&mut close)
            .map_err(|error| format!("probe close: {error:?}"))?
        {
            session.send_quic_packet(&close[..used])?;
        }
        let bytes = client.bytes();
        let bps = bytes.saturating_mul(8_000_000) / stats.elapsed_us;
        println!(
            "dmesh_cli_probe_result bearer=uart bytes={} normal_bytes={} high_bytes={} low_bytes={} elapsed_us={} bps={} tx_packets={} rx_packets={} retransmits={}",
            bytes,
            client.normal_bytes(),
            client.high_bytes(),
            client.low_bytes(),
            stats.elapsed_us,
            bps,
            stats.tx_packets,
            stats.rx_packets,
            stats.retransmits,
        );
        return Ok(());
    }
    if dmesh_server::verified_object::decode_flash_handler_request(&body).is_some() {
        return Err(
            "object.flash is not supported over UART; use `dmesh-cli flash TARGET` for Wi-Fi flashing or scripts/flash-device.py for physical recovery"
                .into(),
        );
    }
    let mut serial = open_serial(path)?;
    configure_serial(&serial, baud)?;
    run_serial_service_request(&mut serial, path, &body).map(|_| ())
}

/// Preserve the catalog's physical-UART contract when a node name resolved to
/// a serial path. Explicit serial paths remain deliberately literal: callers
/// can supply `--baud` themselves, while a named CP210x device must not be
/// silently treated as packetized USB-JTAG.
fn append_catalog_uart_baud(arguments: &mut Vec<String>, profile: &DeviceProfile) {
    if profile.uart_baud.is_some() && !arguments.iter().any(|argument| argument == "--baud") {
        arguments.push("--baud".to_owned());
        arguments.push(profile.uart_baud.expect("checked above").to_string());
    }
}

fn run_serial_direct_discovery(path: &str, baud: Option<u32>) -> Result<(), String> {
    let started = Instant::now();
    let mut session = DeviceSession::open(path, baud)?;
    let id = fresh_request_id();
    let mut request = [0u8; 64];
    let used =
        announce::encode_discovery_request(id, &mut request).ok_or("encode discovery request")?;
    let mut client = dmesh_server::transport::TaggedClient::<
        8,
        { quic_lite::DEFAULT_MAX_DATAGRAM_SIZE },
    >::new(fresh_connection_id(), &request[..used])
    .map_err(|error| format!("check client: {error:?}"))?;
    session.drive_client(&mut client, Duration::from_secs(3), "check")?;
    let response = client.response().ok_or("check response missing")?;
    let record = dmesh_server::tagged::decode(response).ok_or("invalid check response")?;
    if record.id != Some(id) {
        return Err("check response ID mismatch".into());
    }
    let announce = announce::decode_record(record).ok_or("invalid discovery response")?;
    println!(
        "dmesh_direct_check target={} device={} elapsed_us={}",
        path,
        announce.device_name().unwrap_or("unknown"),
        started.elapsed().as_micros(),
    );
    Ok(())
}

/// Send exactly one unmarked PPP record and render any direct records returned
/// during a short bounded receive interval. This is the host counterpart of
/// `IngressKind::UartRaw`: it deliberately bypasses QUIC-lite while retaining
/// normal PPP framing, serial ownership, and schema rendering.
fn run_serial_direct_record(arguments: &[String]) -> Result<(), String> {
    let path = arguments.first().ok_or("missing serial path")?;
    let mut index = 1;
    let mut timeout = Duration::from_secs(2);
    let mut baud = None;
    let record = match arguments.get(index).map(String::as_str) {
        Some("--direct-hex") => {
            index += 1;
            hex(arguments.get(index).ok_or("missing --direct-hex value")?)?
        }
        Some("--msg") => {
            index += 1;
            let end = arguments[index..]
                .iter()
                .position(|argument| matches!(argument.as_str(), "--timeout-secs" | "--baud"))
                .map(|offset| index + offset)
                .unwrap_or(arguments.len());
            let command = arguments[index..end].join(" ");
            if command.is_empty() {
                return Err("missing --msg value".into());
            }
            index = end.saturating_sub(1);
            encode_direct_command_with_id(&command, fresh_request_id())
                .map_err(|error| error.to_string())?
        }
        _ => usage(),
    };
    index += 1;
    while index < arguments.len() {
        match arguments[index].as_str() {
            "--timeout-secs" => {
                index += 1;
                timeout = Duration::from_secs(
                    arguments
                        .get(index)
                        .ok_or("missing --timeout-secs value")?
                        .parse::<u64>()
                        .map_err(|error| error.to_string())?,
                );
            }
            "--baud" => {
                index += 1;
                baud = Some(
                    arguments
                        .get(index)
                        .ok_or("missing --baud value")?
                        .parse::<u32>()
                        .map_err(|error| error.to_string())?,
                );
            }
            argument => return Err(format!("raw record does not support {argument}")),
        }
        index += 1;
    }
    if record.is_empty() || record.len() > quic_lite::DEFAULT_MAX_DATAGRAM_SIZE - 6 {
        return Err("raw record is empty or exceeds the UART MTU".into());
    }
    let mut serial = open_serial(path)?;
    // CP210x boards expose a physical 8N1 UART while C6 USB-JTAG uses its
    // packetized driver cadence. Keep the former opt-in exactly as stream
    // requests do; direct schema-backed diagnostics must work on both.
    configure_serial(&serial, baud)?;
    // USB-JTAG retains diagnostic records across short-lived CLI owners. Do
    // not mistake that old backlog for the reply to the record below.
    let mut stale = [0u8; 256];
    loop {
        match serial.read(&mut stale) {
            Ok(used) if used != 0 => {}
            Ok(_) => break,
            Err(ref error) if error.kind() == ErrorKind::WouldBlock => break,
            Err(error) => return Err(error.to_string()),
        }
    }
    let mut packet = [0u8; quic_lite::DEFAULT_MAX_DATAGRAM_SIZE];
    let used = dmesh_server::direct::ConnectionlessMessage::encode(&record, &mut packet)
        .ok_or_else(|| "UART connectionless record exceeds the MTU".to_owned())?;
    send_ppp(&mut serial, &packet[..used])?;
    println!("dmesh_cli_raw_sent target={path} bytes={}", record.len());

    let schema = load_tagged_schema();
    let mut decoder = Decoder::with_max(quic_lite::DEFAULT_MAX_DATAGRAM_SIZE + 1);
    let mut buffer = [0u8; quic_lite::DEFAULT_MAX_DATAGRAM_SIZE + 1];
    let deadline = Instant::now() + timeout;
    let mut replies = 0u32;
    // Raw schema commands share the ESP console with stream requests. Keep
    // the repeated NAN sniffer teardown line from burying a bounded direct
    // response just as the service path does.
    let mut text_filter = WatchTextFilter::default();
    while Instant::now() < deadline {
        match serial.read(&mut buffer) {
            Ok(used) if used != 0 => {
                for frame in decoder
                    .push(&buffer[..used])
                    .map_err(|error| error.to_string())?
                {
                    if let Ok(UartIngress::Unmarked(packet)) = classify_uart_payload(&frame)
                        && let Some(record) =
                            dmesh_server::direct::ConnectionlessMessage::decode(packet)
                    {
                        let rendered = render_device_record(&schema, record);
                        if text_filter.retain(&rendered) {
                            println!("dmesh_cli_raw_reply bytes={} {rendered}", record.len());
                        }
                        replies = replies.saturating_add(1);
                    }
                }
            }
            Ok(_) => {
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) if error.kind() == ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(error.to_string()),
        }
    }
    if replies == 0 {
        Err("raw record response timeout".into())
    } else {
        if text_filter.suppressed_disable_sniffer != 0 {
            println!(
                "dmesh_cli_raw_suppressed text=ic_disable_sniffer count={}",
                text_filter.suppressed_disable_sniffer
            );
        }
        Ok(())
    }
}

/// Issue one bearer-neutral service request using an already-owned UART.
/// Interactive watch mode calls this so a tmux pane has exactly one serial
/// owner while it both renders diagnostics and accepts stream commands.
fn run_serial_service_request(serial: &mut File, path: &str, body: &[u8]) -> Result<(), String> {
    // Service requests can overlap normal ESP-IDF radio diagnostics. Apply
    // the same bounded sniffer-teardown filter as `--watch`, otherwise a
    // useful service response is buried under the identical idle line.
    let mut text_filter = WatchTextFilter::default();
    let cid = fresh_connection_id();
    let limits = ConnectionLimits::default();
    // UART is frame I/O only. Keep bootstrap/CID/packet state in the same
    // quic-lite association used by UDP and NOW adapters.
    let uart_path = LocalAddress::new(1).expect("static UART path ID is nonzero");
    let mut connection =
        ClientAssociation::<8, { quic_lite::DEFAULT_MAX_DATAGRAM_SIZE }>::with_limits(cid, limits);
    connection.select_path(uart_path);
    let mut open = [0u8; quic_lite::DEFAULT_MAX_DATAGRAM_SIZE];
    let (_, open_used) = connection
        .start(&mut open)
        .map_err(|error| format!("UART bootstrap OPEN: {error:?}"))?;
    send_uart_transport(serial, &open[..open_used])?;

    let mut decoder = Decoder::with_max(quic_lite::DEFAULT_MAX_DATAGRAM_SIZE + 1);
    let mut buffer = [0u8; quic_lite::DEFAULT_MAX_DATAGRAM_SIZE + 1];
    let bootstrap_deadline = Instant::now() + Duration::from_secs(3);
    'bootstrap: loop {
        if Instant::now() >= bootstrap_deadline {
            return Err("UART bootstrap timeout (no transport ACK)".into());
        }
        match serial.read(&mut buffer) {
            Ok(used) if used != 0 => {
                for record in decoder
                    .push(&buffer[..used])
                    .map_err(|error| error.to_string())?
                {
                    let packet = match classify_uart_payload(&record) {
                        Ok(UartIngress::Transport(packet)) => packet,
                        Ok(UartIngress::Unmarked(packet)) => {
                            if let Some(record) =
                                dmesh_server::direct::ConnectionlessMessage::decode(packet)
                            {
                                report_uart_direct_record(path, record, &mut text_filter);
                            }
                            continue;
                        }
                        Err(_) => continue,
                    };
                    // A stateless reset is intentionally not a valid short
                    // header. Recognize the issued token before filtering
                    // stale UART frames so a rebooted peer reports immediate
                    // association recovery instead of a bootstrap timeout.
                    if connection.is_peer_stateless_reset(packet) {
                        return Err("UART bootstrap: peer restarted".into());
                    }
                    if connection.receive_open_ack(uart_path, packet, 0).is_ok() {
                        break 'bootstrap;
                    }
                }
            }
            Ok(_) => thread::yield_now(),
            Err(error) if error.kind() == ErrorKind::WouldBlock => thread::yield_now(),
            Err(error) => return Err(error.to_string()),
        }
    }

    connection
        .continue_packet_numbers_from(1)
        .map_err(|error| format!("UART bootstrap packet numbers: {error:?}"))?;
    let stream_id = connection
        .allocate_client_bidi_stream()
        .map_err(|error| format!("UART service stream: {error:?}"))?;
    let mut packet = [0u8; quic_lite::DEFAULT_MAX_DATAGRAM_SIZE];
    let (_path, used) = connection
        .encode_stream_payload(stream_id, body, true, &mut packet)
        .map_err(|error| format!("UART service request: {error:?}"))?;
    send_uart_transport(serial, &packet[..used])?;

    let response_deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if Instant::now() >= response_deadline {
            return Err("UART services timeout (no stream response)".into());
        }
        match serial.read(&mut buffer) {
            Ok(used) if used != 0 => {
                for record in decoder
                    .push(&buffer[..used])
                    .map_err(|error| error.to_string())?
                {
                    let packet = match classify_uart_payload(&record) {
                        Ok(UartIngress::Transport(packet)) => packet,
                        Ok(UartIngress::Unmarked(packet)) => {
                            if let Some(record) =
                                dmesh_server::direct::ConnectionlessMessage::decode(packet)
                            {
                                report_uart_direct_record(path, record, &mut text_filter);
                            }
                            continue;
                        }
                        Err(_) => continue,
                    };
                    let received = connection
                        .receive_stream_payload(uart_path, packet)
                        .map_err(|error| format!("UART response packet: {error:?}"))?;
                    let Some((stream_id, _offset, fin, data)) = received else {
                        continue;
                    };
                    connection
                        .stream_consumed(stream_id, data.len(), false)
                        .map_err(|error| format!("UART response accounting: {error:?}"))?;
                    let mut ack = [0u8; quic_lite::DEFAULT_MAX_DATAGRAM_SIZE];
                    if let Some((_path, ack_len)) = connection
                        .poll_transmit(&mut ack)
                        .map_err(|error| format!("UART response ACK: {error:?}"))?
                    {
                        send_uart_transport(serial, &ack[..ack_len])?;
                    }
                    if stream_id == quic_lite::FIRST_SERVER_BIDI_STREAM_ID {
                        // A one-shot CLI service request must retire its
                        // association before closing the UART FD.  Keeping
                        // the close inside QUIC-lite prevents a serial
                        // command from consuming the firmware's bounded
                        // multi-peer association table.
                        if let Some((_close_path, close_used)) = connection
                            .poll_close(&mut ack)
                            .map_err(|error| format!("UART service close: {error:?}"))?
                        {
                            send_uart_transport(serial, &ack[..close_used])?;
                        }
                        println!(
                            "dmesh_cli_stream_command target={} stream={} fin={} bytes={} {}",
                            path,
                            stream_id,
                            fin,
                            data.len(),
                            render_device_record(&load_tagged_schema(), &data)
                        );
                        return Ok(());
                    }
                }
            }
            Ok(_) => thread::yield_now(),
            Err(error) if error.kind() == ErrorKind::WouldBlock => thread::yield_now(),
            Err(error) => return Err(error.to_string()),
        }
    }
}

/// Passively render direct UART records from boot/platform code. This does
/// not open a service stream and never substitutes for tagged `log-watch`:
/// firmware logs belong on that flow-controlled stream. Marked QUIC-lite
/// packets are reported only as transport observations, never decoded as
/// boot text or direct CBOR.
fn run_serial_watch(arguments: &[String]) -> Result<(), String> {
    let path = arguments.first().ok_or("missing serial path")?;
    if arguments
        .get(1)
        .is_none_or(|argument| argument != "--watch")
    {
        return Err("serial watch requires --watch immediately after the target".into());
    }
    let mut baud = None;
    let mut timeout = Duration::from_secs(90);
    let mut interactive = false;
    let mut reset_after_open = false;
    let mut index = 2;
    while index < arguments.len() {
        match arguments[index].as_str() {
            "--interactive" => interactive = true,
            // Keep the serial file open while resetting so the following
            // watch captures ROM, Stage2, and Main output. This is a
            // troubleshooting-only opt-in; a normal watch never toggles a
            // modem-control line.
            "--reset" => reset_after_open = true,
            "--baud" => {
                index += 1;
                baud = Some(
                    arguments
                        .get(index)
                        .ok_or("missing --baud value")?
                        .parse::<u32>()
                        .map_err(|error| error.to_string())?,
                );
            }
            "--timeout-secs" => {
                index += 1;
                timeout = Duration::from_secs(
                    arguments
                        .get(index)
                        .ok_or("missing --timeout-secs value")?
                        .parse::<u64>()
                        .map_err(|error| error.to_string())?,
                );
            }
            unknown => return Err(format!("unknown serial watch argument {unknown}")),
        }
        index += 1;
    }
    let mut serial = open_serial(path)?;
    configure_serial(&serial, baud)?;
    // Print the resolved physical contract before touching RTS.  A board name
    // has already been expanded to this exact `/dev/serial/by-id` path, and
    // an explicit baud makes a CP210x capture reproducible instead of relying
    // on whichever termios settings a prior owner left behind.  `None` is the
    // intentional packetized-native-USB case (for example C6 USB-JTAG).
    println!(
        "dmesh_uart_watch_open target={path} baud={}",
        baud.map_or("driver-default".to_owned(), |value| value.to_string())
    );
    if reset_after_open {
        pulse_serial_reset(&serial)?;
        println!("dmesh_uart_watch_reset target={path} line=RTS pulse_ms=120");
    }
    if interactive {
        unsafe {
            let flags = libc::fcntl(std::io::stdin().as_raw_fd(), libc::F_GETFL);
            if flags < 0
                || libc::fcntl(
                    std::io::stdin().as_raw_fd(),
                    libc::F_SETFL,
                    flags | libc::O_NONBLOCK,
                ) != 0
            {
                return Err(std::io::Error::last_os_error().to_string());
            }
        }
        eprintln!("dmesh_uart_interactive commands=SERVICE [field=value ...]|quit");
    }
    let schema = load_tagged_schema();
    let mut decoder = Decoder::with_max(quic_lite::DEFAULT_MAX_DATAGRAM_SIZE + 1);
    let mut raw_text = RawTextTap::default();
    let mut text_filter = WatchTextFilter::default();
    let mut buffer = [0u8; quic_lite::DEFAULT_MAX_DATAGRAM_SIZE + 1];
    let mut direct_records = 0u64;
    let mut transport_packets = 0u64;
    let mut received_bytes = 0u64;
    let mut stdin_buffer = String::new();
    let mut stdin_bytes = [0u8; 256];
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if interactive {
            match std::io::stdin().read(&mut stdin_bytes) {
                Ok(used) if used != 0 => {
                    stdin_buffer.push_str(&String::from_utf8_lossy(&stdin_bytes[..used]));
                    while let Some(newline) = stdin_buffer.find('\n') {
                        let line = stdin_buffer[..newline].trim().to_owned();
                        stdin_buffer.drain(..=newline);
                        if line.is_empty() {
                            continue;
                        }
                        if line == "quit" || line == "exit" {
                            println!("dmesh_uart_interactive exit");
                            return Ok(());
                        }
                        match parse_interactive_service_command(&line).and_then(|body| {
                            run_serial_service_request(&mut serial, path, &body).map(|_| ())
                        }) {
                            Ok(()) => {}
                            Err(error) => eprintln!("dmesh_uart_interactive error={error}"),
                        }
                    }
                }
                Ok(_) => {}
                Err(error) if error.kind() == ErrorKind::WouldBlock => {}
                Err(error) => return Err(error.to_string()),
            }
        }
        match serial.read(&mut buffer) {
            Ok(used) if used != 0 => {
                received_bytes = received_bytes.saturating_add(used as u64);
                for line in raw_text.push(&buffer[..used]) {
                    if text_filter.retain(&line) {
                        println!(
                            "dmesh_uart_watch_text {}",
                            serde_json::to_string(&line).unwrap()
                        );
                    }
                }
                for record in decoder
                    .push(&buffer[..used])
                    .map_err(|error| error.to_string())?
                {
                    match classify_uart_payload(&record) {
                        Ok(UartIngress::Unmarked(packet)) => {
                            if let Some(record) =
                                dmesh_server::direct::ConnectionlessMessage::decode(packet)
                            {
                                direct_records = direct_records.saturating_add(1);
                                println!(
                                    "dmesh_uart_watch_record bytes={} {}",
                                    record.len(),
                                    render_device_record(&schema, record)
                                );
                            }
                        }
                        Ok(UartIngress::Transport(packet)) => {
                            transport_packets = transport_packets.saturating_add(1);
                            // UART watch is a frame observer, not a second
                            // QUIC parser. CID/packet diagnostics come from
                            // the association owner through normal status.
                            println!("dmesh_uart_watch_transport bytes={}", packet.len());
                        }
                        Err(_) => {}
                    }
                }
            }
            Ok(_) => thread::sleep(Duration::from_millis(1)),
            Err(error) if error.kind() == ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(1))
            }
            Err(error) => return Err(error.to_string()),
        }
    }
    println!(
        "dmesh_uart_watch_timeout received_bytes={received_bytes} direct_records={direct_records} transport_packets={transport_packets}"
    );
    if text_filter.suppressed_disable_sniffer != 0 {
        println!(
            "dmesh_uart_watch_suppressed text=ic_disable_sniffer count={}",
            text_filter.suppressed_disable_sniffer
        );
    }
    // A passive watch may legitimately see nothing.  A watch that explicitly
    // performed the reset cannot: no byte at all means the ROM/Stage2/Main
    // serial path was not observed, so returning success would hide the exact
    // boot regression this diagnostic mode exists to expose.
    if reset_after_open && received_bytes == 0 {
        return Err(format!(
            "UART reset capture received no bytes target={path} baud={}; ROM, Stage2, or Main serial output was not observed",
            baud.map_or("driver-default".to_owned(), |value| value.to_string())
        ));
    }
    Ok(())
}

/// Line-oriented command vocabulary for a serial watch pane.  It intentionally
/// uses the same schema-driven tagged request as one-shot UART and UDP calls.
fn parse_interactive_service_command(line: &str) -> Result<Vec<u8>, String> {
    let command = line.split_whitespace().next().ok_or("empty command")?;
    if !is_stream_command_name(command) {
        return Err(format!("unknown schema service {command}"));
    }
    let record = encode_stream_command_with_id(line, fresh_request_id())
        .map_err(|error| error.to_string())?;
    Ok(record)
}

/// Execute one service operation directly over the UDP QUIC-lite bearer.
/// This is intentionally the same `UdpClient` used by the host transport
/// tests: a command client has no raw UDP fallback or UART-specific schema.
/// Long-lived log subscription delivery is not enabled yet; `log-watch` is a
/// bounded record poll until the server-side framed subscription is added.
pub(crate) fn run_udp_service_client(arguments: &[String]) -> Result<(), String> {
    let (arguments, object_file) = split_object_file_argument(arguments)?;
    let peer = arguments
        .first()
        .and_then(|target| target.strip_prefix("udp://"))
        .ok_or("UDP target must use udp://HOST:PORT")?;
    let peer = parse_udp_peer(peer)?;
    let mut session_socket = None;
    let mut relay_forward_dcid = None;
    let mut relay_reverse_dcid = None;
    let mut relay_next_mac = None;
    let mut relay_allocation = 1u64;
    let tagged_command = arguments
        .get(1)
        .filter(|command| is_stream_command_name(command))
        .map(|_| encode_stream_argv_with_id(&arguments[1..], fresh_request_id()))
        .transpose()
        .map_err(|error| error.to_string())?;
    let mut index = if tagged_command.is_some() {
        arguments.len()
    } else {
        1
    };
    while index < arguments.len() {
        match arguments[index].as_str() {
            "--socket" => {
                index += 1;
                session_socket = Some(
                    arguments
                        .get(index)
                        .ok_or("missing --socket value")?
                        .clone(),
                );
            }
            "--relay-forward-dcid" => {
                index += 1;
                relay_forward_dcid = Some(
                    arguments
                        .get(index)
                        .ok_or("missing --relay-forward-dcid value")?
                        .parse::<u64>()
                        .map_err(|error| error.to_string())?,
                );
            }
            "--relay-reverse-dcid" => {
                index += 1;
                relay_reverse_dcid = Some(
                    arguments
                        .get(index)
                        .ok_or("missing --relay-reverse-dcid value")?
                        .parse::<u64>()
                        .map_err(|error| error.to_string())?,
                );
            }
            "--relay-next-mac" => {
                index += 1;
                relay_next_mac = Some(
                    arguments
                        .get(index)
                        .ok_or("missing --relay-next-mac value")?
                        .clone(),
                );
            }
            "--relay-allocation" => {
                index += 1;
                relay_allocation = arguments
                    .get(index)
                    .ok_or("missing --relay-allocation value")?
                    .parse::<u64>()
                    .map_err(|error| error.to_string())?;
            }
            _ => return Err(format!("unknown UDP client argument {}", arguments[index])),
        }
        index += 1;
    }
    if let Some(socket_path) = session_socket {
        if tagged_command.is_some()
            || relay_forward_dcid.is_some()
            || relay_reverse_dcid.is_some()
            || relay_next_mac.is_some()
        {
            return Err("--socket cannot be combined with a one-shot or relay request".into());
        }
        return serve_udp_session_socket(peer, Path::new(&socket_path));
    }
    let request = tagged_command
        .ok_or("missing schema service; use dmesh-cli DEVICE METHOD [--field=value ...]")?;
    let tagged_probe = dmesh_server::tagged::decode(&request)
        .and_then(dmesh_server::probe::decode_probe_run_record)
        .map(|(_, request)| request);
    let probe_request = tagged_probe;
    // `object.flash` uses one client association with a command and an
    // ordered object-record stream. The CLI never starts a reverse UDP
    // server or a second association.
    let object_flash =
        dmesh_server::verified_object::decode_flash_handler_request(&request).is_some();
    let relay = match (relay_forward_dcid, relay_reverse_dcid, relay_next_mac) {
        (None, None, None) => None,
        (Some(forward), Some(reverse), Some(next_mac)) => Some((
            quic_lite::ConnectionId::new(forward).ok_or("invalid relay forward DCID")?,
            quic_lite::ConnectionId::new(reverse).ok_or("invalid relay reverse DCID")?,
            next_mac,
        )),
        _ => return Err("relay mode requires forward DCID, reverse DCID, and next MAC".into()),
    };
    if object_flash && relay.is_some() {
        return Err("object.flash cannot be combined with relay mode".into());
    }
    // This CID is owned by dmesh-cli and remains stable across relay alias
    // allocation. It is never a relay allocation.
    let cid = fresh_connection_id();
    let relay_pair = if let Some((forward, reverse, next_mac)) = relay.as_ref() {
        let revision = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| error.to_string())?
            .as_micros()
            .min(u128::from(u64::MAX - 1)) as u64;
        let reverse_allocation = relay_allocation
            .checked_add(1)
            .ok_or("relay reverse allocation overflow")?;
        let pair = format!(
            "relay.pair forward_allocation={relay_allocation} reverse_allocation={reverse_allocation} revision={revision} forward_dcid={} reverse_dcid={} client_dcid={} position=1 return_token={relay_allocation} next_mac={next_mac}",
            forward.value(),
            reverse.value(),
            cid.value(),
        );
        let request = encode_direct_command_with_id(&pair, fresh_request_id())
            .map_err(|error| error.to_string())?;
        let response = exchange_udp_stream_record(peer, &request)?;
        let response = dmesh_server::tagged::decode(&response)
            .ok_or("relay pair response is not tagged CBOR")?;
        if response.error.is_some() {
            return Err("relay pair returned an error".into());
        }
        let observed = dmesh_server::relay::decode_observed_pair(
            response.result.ok_or("relay pair response has no result")?,
        )
        .ok_or("relay pair response has invalid aliases")?;
        eprintln!(
            "dmesh_udp_relay_pair requested_forward={} requested_reverse={} forward_dcid={} reverse_dcid={} client_dcid={}",
            forward.value(),
            reverse.value(),
            observed.forward.local_dcid.unwrap().value(),
            observed.reverse.local_dcid.unwrap().value(),
            cid.value(),
        );
        Some((revision, observed))
    } else {
        None
    };
    let schema = load_tagged_schema();
    let runtime = tokio::runtime::Runtime::new().map_err(|error| error.to_string())?;
    runtime.block_on(async move {
        let mut client = if let Some((_, observed)) = relay_pair {
            dmesh_server::udp::UdpClient::connect_with_quic_lite_wire_dcid(
                udp_bind_for_peer(peer),
                peer,
                cid,
                observed.forward.local_dcid.unwrap(),
            )
            .await
        } else {
            dmesh_server::udp::UdpClient::connect(udp_bind_for_peer(peer), peer, cid).await
        }
        .map_err(|error| error.to_string())?;
        if let Some((pair_revision, observed)) = relay_pair {
            let (_, _, next_mac) = relay.as_ref().expect("relay pair has relay options");
            let forward = observed.forward.local_dcid.unwrap();
            let reverse = observed.reverse.local_dcid.unwrap();
            let server_cid = client
                .peer_connection_id()
                .ok_or("relayed bootstrap did not install server CID")?;
            eprintln!(
                "dmesh_udp_relay_bootstrap forward_dcid={} reverse_dcid={} server_dcid={}",
                forward.value(),
                reverse.value(),
                server_cid.value()
            );
            let revision = pair_revision
                .checked_add(1)
                .ok_or("missing relay pair revision")?;
            let update = encode_direct_command_with_id(
                &format!(
                    "relay.apply allocation={relay_allocation} revision={revision} inbound_dcid={} outbound_dcid={} position=1 next_mac={next_mac}",
                    forward.value(),
                    server_cid.value()
                ),
                fresh_request_id(),
            )
            .map_err(|error| error.to_string())?;
            let mut update_control = dmesh_server::udp::UdpClient::connect(
                udp_bind_for_peer(peer),
                peer,
                fresh_connection_id(),
            )
                .await
                .map_err(|error| error.to_string())?;
            let (_, update_response, update_fin) = update_control
                .request_stream(quic_lite::FIRST_CLIENT_BIDI_STREAM_ID, &update, true)
                .await
                .map_err(|error| error.to_string())?;
            if !update_fin {
                return Err("relay update stream did not finish".into());
            }
            let update_record = dmesh_server::tagged::decode(&update_response)
                .ok_or("relay update response is not tagged CBOR")?;
            if update_record.error.is_some() {
                return Err("relay update returned an error".into());
            }
            eprintln!(
                "dmesh_udp_relay_updated forward_dcid={} outbound_dcid={}",
                forward.value(),
                server_cid.value()
            );
        }
        if let Some(probe_request) = probe_request {
            client.set_deferred_receive_credit(true);
            let started = Instant::now();
            let mut frame = client
                .request_stream_frame(quic_lite::FIRST_CLIENT_BIDI_STREAM_ID, &request, true)
                .await
                .map_err(|error| error.to_string())?;
            // A priority scheduler may legitimately emit the high stream
            // before the first normal stream. The service stream map is
            // protocol-defined, so never infer its base from arrival order.
            let first_stream = quic_lite::FIRST_SERVER_BIDI_STREAM_ID;
            let plan = ProbeServicePlan::from_request(
                probe_request,
                quic_lite::DEFAULT_MAX_DATAGRAM_SIZE - 32,
            );
            let mut receiver = ProbeRun::<{ dmesh_server::probe::PROBE_MAX_NORMAL_STREAMS }>::new(
                2,
                plan.normal_streams,
                plan.high_priority_bytes != 0,
                plan.low_priority_bytes != 0,
            );
            loop {
                let stream = StreamFrame {
                    id: frame.id,
                    offset: frame.offset,
                    fin: frame.fin,
                    data: &frame.data,
                };
                let (complete, _) = receiver
                    .handle(first_stream, stream)
                    .map_err(|_| "UDP probe payload validation failed")?;
                if complete {
                    let elapsed = started.elapsed();
                    let bytes = receiver.bytes();
                    let transport = client.transport_stats();
                    let bps = if elapsed.is_zero() {
                        0
                    } else {
                        bytes.saturating_mul(8).saturating_mul(1_000_000)
                            / elapsed.as_micros().max(1) as u64
                    };
                    println!(
                        "dmesh_cli_probe_result bearer=udp target={peer} stream={first_stream} bytes={bytes} normal_bytes={} high_bytes={} low_bytes={} elapsed_us={} bps={bps} callback_errors={:?} received_datagrams={} duplicate_datagrams={} out_of_order_datagrams={} inferred_missing_packets={} retransmitted_datagrams={} loss_retransmits={} pto_retransmits={}",
                        receiver.normal_bytes(),
                        receiver.high_bytes(),
                        receiver.low_bytes(),
                        elapsed.as_micros(),
                        receiver.callback_errors(),
                        transport.received_datagrams,
                        transport.duplicate_datagrams,
                        transport.out_of_order_datagrams,
                        transport.inferred_missing_packets,
                        transport.retransmitted_datagrams,
                        transport.loss_retransmitted_datagrams,
                        transport.pto_retransmitted_datagrams,
                    );
                    // dmesh-cli owns this one-shot association.  Retire it
                    // explicitly before the process exits so an embedded
                    // peer with one active dispatcher can immediately admit
                    // lmesh's retained association on another path.
                    client.close(0).await.map_err(|error| error.to_string())?;
                    return Ok(());
                }
                frame = tokio::time::timeout(Duration::from_secs(30), client.recv_stream_frame())
                    .await
                    .map_err(|_| "UDP probe receive timeout")?
                    .map_err(|error| error.to_string())?;
            }
        }
        let flash_response = if object_flash {
            let (_, flash) = dmesh_server::verified_object::decode_flash_handler_request(&request)
                .ok_or("invalid object.flash request")?;
            let (manifest, image, artifact) =
                flash_upload_object(flash.object, object_file.as_deref())?;
            let mut object = dmesh_server::verified_object::ObjectBodyStream::from_object(
                manifest, image,
            );
            eprintln!(
                "dmesh_cli_object_upload bearer=udp association=single artifact={}",
                artifact.display()
            );

            let response = client
                .request_object_upload(
                    &request,
                    &mut object,
                    object_upload_timeout(),
                )
                .await
                .map_err(|error| error.to_string())?;
            eprintln!(
                "dmesh_cli_object_upload_complete records={} bytes={}",
                object.record_index(),
                object.sent_bytes()
            );
            flash_upload_success(&response.data)?;
            Ok((response.id, response.data, response.fin))
        } else {
            client
                .request_stream(quic_lite::FIRST_CLIENT_BIDI_STREAM_ID, &request, true)
                .await
        };
        let (stream, response, fin) = flash_response.map_err(|error| error.to_string())?;
        // A direct UDP CLI command is deliberately a one-shot client, unlike
        // lmesh's per-device association manager.  Send QUIC CLOSE while the
        // shared fixed-port socket is still alive; dropping it alone leaves a
        // firmware peer pinned to this transient CID until its idle timeout.
        client.close(0).await.map_err(|error| error.to_string())?;
        println!(
            "dmesh_cli_stream_command target={peer} stream={stream} fin={fin} bytes={} {}",
            response.len(),
            render_device_record(&schema, &response)
        );
        Ok(())
    })
}

/// Remove the CLI-only object source selector before schema encoding.  A
/// source path is host policy, not a firmware command field, so it must never
/// be sent to the device or become part of the signed object manifest.
fn split_object_file_argument(
    arguments: &[String],
) -> Result<(Vec<String>, Option<PathBuf>), String> {
    let mut retained = Vec::with_capacity(arguments.len());
    let mut object_file = None;
    let mut index = 0;
    while index < arguments.len() {
        if arguments[index] == "--file" {
            let value = arguments.get(index + 1).ok_or("missing --file path")?;
            if object_file.replace(PathBuf::from(value)).is_some() {
                return Err("object.flash accepts only one --file path".into());
            }
            index += 2;
        } else {
            retained.push(arguments[index].clone());
            index += 1;
        }
    }
    Ok((retained, object_file))
}

/// Select the wildcard address family from the peer. A raw IPv6 bearer must
/// not first fail in the host client by binding an IPv4 socket.
fn udp_bind_for_peer(peer: SocketAddr) -> SocketAddr {
    let port = env::var("DMESH_UDP_SOURCE_PORT")
        .ok()
        .and_then(|value| value.parse::<u16>().ok())
        // An operator may pin this for a capture/reproduction, but a normal
        // one-shot client must not share one port with every peer's multicast
        // announce stream. On a populated LAN that made an unrelated board's
        // packet look like the selected target's QUIC bootstrap response.
        .unwrap_or(0);
    match peer {
        // Keep the operator/client socket distinct from both managed host
        // listeners (wlan0:3336, wlan1:3337) and firmware raw UDP6 (3339).
        // The default is an ephemeral port. Set DMESH_UDP_SOURCE_PORT when a
        // reproducible fixed source is specifically required for a capture.
        SocketAddr::V4(_) => SocketAddr::from(([0, 0, 0, 0], port)),
        SocketAddr::V6(_) => SocketAddr::from(([0; 16], port)),
    }
}

/// Parse a UDP peer, including the scoped IPv6 link-local form required by
/// raw UDP6 tests: `[fe80::1%wlan0]` (the firmware default port is used) or
/// `[fe80::1%wlan0]:3339`. `SocketAddr` itself deliberately
/// does not parse interface names, so resolve the Linux interface index here
/// at the host CLI boundary rather than teaching firmware about host scopes.
fn parse_udp_peer(value: &str) -> Result<SocketAddr, String> {
    if let Ok(peer) = value.parse::<SocketAddr>() {
        return Ok(peer);
    }
    let scoped = value
        .strip_prefix('[')
        .and_then(|value| {
            value
                .rsplit_once("]:")
                .map(|(address_scope, port)| (address_scope, Some(port)))
                .or_else(|| {
                    value
                        .strip_suffix(']')
                        .map(|address_scope| (address_scope, None))
                })
        })
        .ok_or_else(|| format!("invalid UDP peer {value:?}"))?;
    let (address_scope, port) = scoped;
    let (address, scope) = address_scope
        .rsplit_once('%')
        .ok_or_else(|| format!("IPv6 link-local peer needs %INTERFACE: {value:?}"))?;
    let address = address
        .parse::<Ipv6Addr>()
        .map_err(|error| error.to_string())?;
    let port = port
        .map(str::parse::<u16>)
        .transpose()
        .map_err(|error| error.to_string())?
        .unwrap_or(dmesh_server::udp::RAW_UDP6_PORT);
    let scope_id = scope
        .parse::<u32>()
        .ok()
        .or_else(|| {
            std::fs::read_to_string(format!("/sys/class/net/{scope}/ifindex"))
                .ok()
                .and_then(|index| index.trim().parse::<u32>().ok())
        })
        .ok_or_else(|| format!("unknown IPv6 scope interface {scope:?}"))?;
    Ok(SocketAddr::V6(SocketAddrV6::new(
        address, port, 0, scope_id,
    )))
}

/// Verify a selected UDP neighbor through the supported directed-discovery
/// request/reply. The reply remains a signed `announce.discovery` record;
/// this deliberately replaces the old unrelated bearer probe.
fn run_udp_direct_discovery(peer: SocketAddr) -> Result<(), String> {
    let started = Instant::now();
    let (id, announce) = direct_discovery_announce(peer)?;
    println!(
        "dmesh_direct_check target={peer} request_id={id} device={} elapsed_us={}",
        announce.device_name().unwrap_or("unknown"),
        started.elapsed().as_micros()
    );
    Ok(())
}

pub(crate) fn direct_discovery_announce(
    peer: SocketAddr,
) -> Result<(u64, announce::Announce), String> {
    let id = fresh_request_id();
    let mut request = [0u8; 64];
    let used = announce::encode_discovery_request(id, &mut request)
        .ok_or("encode directed discovery request")?;
    let response = exchange_udp_direct_record(peer, &request[..used])?;
    let payload = dmesh_server::direct::ConnectionlessMessage::decode(&response)
        .ok_or_else(|| "direct discovery received a non-direct response".to_owned())?;
    let record = dmesh_server::tagged::decode(payload)
        .ok_or("direct discovery response is not tagged CBOR")?;
    if record.id != Some(id) {
        return Err("direct discovery response has the wrong request ID".into());
    }
    let announce = announce::decode_record(record)
        .filter(|announce| announce.kind == announce::ANNOUNCE_DISCOVERY)
        .ok_or("direct discovery response is not an announce.discovery record")?;
    Ok((id, announce))
}

/// A catalog VIP6/name is an identity selector, never a literal UDP route.
/// Prefer its explicitly scoped link-local bearer, then use the same signed
/// discovery and NAN wake sequence as flash when association is unavailable.
fn run_catalog_target_service(arguments: &[String], profile: &DeviceProfile) -> Result<(), String> {
    let name = profile.name.as_deref().unwrap_or("catalog-device");
    if let Some(peer) = catalog_udp6_peer(profile)? {
        match direct_discovery_announce(peer) {
            Ok((_, announce)) if catalog_profile_matches_announce(profile, &announce) => {
                println!("dmesh_catalog_udp6_association name={name} peer={peer} associated=true");
                let mut udp_arguments = arguments.to_vec();
                udp_arguments[0] = format!("udp://{peer}");
                return run_udp_service_client(&udp_arguments);
            }
            Ok((_, announce)) => println!(
                "dmesh_catalog_udp6_association name={name} peer={peer} associated=false reason=identity_mismatch node={}",
                hex_encode(announce.device_id())
            ),
            Err(error) => println!(
                "dmesh_catalog_udp6_association name={name} peer={peer} associated=false error={error}"
            ),
        }
    } else if profile.ipv6_link_local.is_some() {
        println!(
            "dmesh_catalog_udp6_association name={name} associated=false reason=missing_udp6_iface"
        );
    }

    let target = flash_target_from_catalog_profile(profile)?;
    let (peer, _) = discover_and_nan_activate(&target)?;
    println!("dmesh_catalog_fallback name={name} peer={peer} discovery=true nan_activation=true");
    let mut udp_arguments = arguments.to_vec();
    udp_arguments[0] = format!("udp://{peer}");
    run_udp_service_client(&udp_arguments)
}

pub(crate) fn catalog_udp6_peer(profile: &DeviceProfile) -> Result<Option<SocketAddr>, String> {
    let (Some(address), Some(iface)) = (profile.ipv6_link_local, profile.udp6_iface.as_deref())
    else {
        return Ok(None);
    };
    let scope_id = std::fs::read_to_string(format!("/sys/class/net/{iface}/ifindex"))
        .map_err(|error| format!("read catalog udp6_iface {iface:?}: {error}"))?
        .trim()
        .parse::<u32>()
        .map_err(|error| format!("parse catalog udp6_iface {iface:?}: {error}"))?;
    Ok(Some(SocketAddr::V6(SocketAddrV6::new(
        address,
        profile.udp_port,
        0,
        scope_id,
    ))))
}

fn catalog_profile_matches_announce(
    profile: &DeviceProfile,
    announce: &announce::Announce,
) -> bool {
    if let Some(vip6) = profile.vip6 {
        return announce::virtual_ip6_from_identity_hint(announce.device_id()).map(Ipv6Addr::from)
            == Some(vip6);
    }
    let address = announce
        .udp_link_local_v6()
        .or_else(|| announce.sta_link_local_v6())
        .map(Ipv6Addr::from);
    profile.ipv6_link_local == address
}

fn flash_target_from_catalog_profile(profile: &DeviceProfile) -> Result<FlashTarget, String> {
    let name = profile.name.as_deref().unwrap_or("catalog-device");
    let node = profile.vip6.map(|vip6| hex_encode(&vip6.octets()[8..]));
    if node.is_none() && profile.mac.is_none() {
        return Err(format!(
            "catalog device {name:?} has neither vip6 nor mac for discovery/NAN activation"
        ));
    }
    Ok(FlashTarget {
        description: profile
            .vip6
            .map(|vip6| format!("{name} ({vip6})"))
            .unwrap_or_else(|| name.to_owned()),
        node,
        mac: profile.mac,
        known_peer: catalog_udp6_peer(profile)?,
    })
}

/// Locate an already-active target or wake it through a passive-ready
/// observer. This is deliberately the same signed discovery/NAN sequence as
/// flash, without any flash-specific state change.
pub(crate) fn discover_and_nan_activate(
    target: &FlashTarget,
) -> Result<(SocketAddr, announce::Announce), String> {
    let target_mac = target.mac;
    let mut observed_node_id = target.node.clone();
    let mut peers = multicast_discover_peers()?;
    if let Some(peer) = peers.iter().find(|peer| flash_target_matches(peer, target)) {
        return Ok((peer.peer, peer.announce));
    }

    for peer in &peers {
        if peer.passive_ready {
            let request = encode_stream_command_with_id("discovery.active", fresh_request_id())
                .map_err(|error| error.to_string())?;
            let _ = exchange_udp_stream_record(peer.peer, &request);
        }
    }
    std::thread::sleep(Duration::from_secs(5));
    let mut observations = Vec::new();
    for peer in &peers {
        observations.push((peer.peer, peer.passive_ready, None, None));
        let request = encode_stream_command_with_id("discovery.nodes", fresh_request_id())
            .map_err(|error| error.to_string())?;
        let Ok(response) = exchange_udp_stream_record(peer.peer, &request) else {
            continue;
        };
        let Some(nodes) = observed_nodes(&response) else {
            continue;
        };
        for node in nodes {
            observations.push((
                peer.peer,
                peer.passive_ready,
                (!node.node.is_empty()).then_some(node.node),
                node.peer_mac,
            ));
        }
    }
    let plan = dmesh_server::wake::plan_nan_wake(
        target.node.as_deref(),
        target_mac,
        observations.iter().map(|(observer, ready, node, mac)| {
            dmesh_server::wake::NanObservation {
                observer: *observer,
                observer_ready: *ready,
                node: node.as_deref(),
                peer_mac: *mac,
            }
        }),
    );
    if let Some(node) = plan.observed_node {
        observed_node_id = Some(node);
    }
    if plan.attempts.is_empty() {
        return Err(format!(
            "target_not_visible target={}; no Main UDP announce or synced observer NAN entry was found",
            target.description
        ));
    }
    let mut accepted = false;
    for attempt in plan.attempts {
        let observer = attempt.observer;
        let mac = attempt.target_mac;
        let request = encode_nan_wake_stream_request(mac)?;
        match exchange_udp_stream_record(observer, &request)
            .and_then(|response| ensure_stream_success(response, "nan.wakeup"))
        {
            Ok(()) => {
                accepted = true;
                // Admission only proves this observer queued a bounded SDF;
                // it does not prove RF delivery to a DW-only peer. Submit to
                // every independently reachable observer so one controller's
                // stale cluster or RF blind spot cannot suppress another.
                println!(
                    "dmesh_catalog_nan_wake observer={observer} target_mac={} accepted=true",
                    mac_encode(&mac)
                );
            }
            Err(error) => println!(
                "dmesh_catalog_nan_wake observer={observer} target_mac={} accepted=false error={error}",
                mac_encode(&mac)
            ),
        }
    }
    if !accepted {
        return Err(format!(
            "target_wake_rejected target={}; no visible observer accepted nan.wakeup",
            target.description
        ));
    }
    let deadline = Instant::now() + Duration::from_secs(45);
    while Instant::now() < deadline {
        peers = multicast_discover_peers()?;
        if let Some(peer) = peers.iter().find(|peer| {
            observed_node_id
                .as_deref()
                .is_some_and(|node| peer.node.eq_ignore_ascii_case(node))
                || flash_target_matches(peer, target)
        }) {
            return Ok((peer.peer, peer.announce));
        }
    }
    Err(format!("target_wake_timeout target={}", target.description))
}

/// Ask every directly reachable NAN-capable controller to wake a known sleepy
/// radio MAC. A stream success is only local queue admission; callers must
/// separately wait for the target's UDP identity before treating it as awake.
pub(crate) fn submit_nan_wake_to_all(
    peers: &[DiscoveredPeer],
    target: &FlashTarget,
) -> Result<u32, String> {
    let target_mac = target.mac.ok_or_else(|| {
        format!(
            "target_wake_unavailable target={}; catalog has no radio MAC",
            target.description
        )
    })?;
    let plan = dmesh_server::wake::plan_nan_wake(
        target.node.as_deref(),
        Some(target_mac),
        peers.iter().map(|peer| dmesh_server::wake::NanObservation {
            observer: peer.peer,
            observer_ready: peer.passive_ready,
            node: None,
            peer_mac: None,
        }),
    );
    let mut accepted = 0u32;
    for attempt in plan.attempts {
        let request = encode_nan_wake_stream_request(attempt.target_mac)?;
        match exchange_udp_stream_record(attempt.observer, &request)
            .and_then(|response| ensure_stream_success(response, "nan.wakeup"))
        {
            Ok(()) => {
                accepted = accepted.saturating_add(1);
                println!(
                    "dmesh_flash_wake_attempt observer={} target_mac={} accepted=true",
                    attempt.observer,
                    mac_encode(&target_mac)
                );
            }
            Err(error) => println!(
                "dmesh_flash_wake_attempt observer={} target_mac={} accepted=false error={error}",
                attempt.observer,
                mac_encode(&target_mac)
            ),
        }
    }
    (accepted != 0)
        .then_some(accepted)
        .ok_or_else(|| format!("target_wake_rejected target={}", target.description))
}

/// A stable operator-facing device identity read from the shared catalog.
/// Its VIP6 low 64 bits are the signed announce identity hint. Names are only
/// lookup aliases and never participate in radio or flash target matching.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CatalogVip6 {
    pub(crate) name: String,
    pub(crate) vip6: Ipv6Addr,
    pub(crate) node: String,
    pub(crate) mac: Option<[u8; 6]>,
}

pub(crate) fn catalog_vip6_inventory() -> Result<Vec<CatalogVip6>, String> {
    let path = device_catalog_path();
    let catalog = crate::prober::E2eConfig::from_path(&path)?;
    let mut entries = Vec::new();
    for device in catalog.devices {
        let Some(value) = device.vip6 else {
            continue;
        };
        let vip6 = value.parse::<Ipv6Addr>().map_err(|error| {
            format!(
                "catalog device {:?} has invalid vip6 {value:?}: {error}",
                device.name
            )
        })?;
        if vip6.octets()[0] != 0xfc {
            return Err(format!(
                "catalog device {:?} has vip6 outside fc00::/8: {vip6}",
                device.name
            ));
        }
        entries.push(CatalogVip6 {
            name: device.name,
            vip6,
            node: hex_encode(&vip6.octets()[8..]),
            mac: device.mac.as_deref().and_then(parse_mac),
        });
    }
    if entries.is_empty() {
        return Err(format!(
            "device catalog {} has no vip6 entries (expected fc00::/8)",
            path.display()
        ));
    }
    Ok(entries)
}

/// Validate the checked-in node identity inventory against multicast
/// presence.  A VIP6 is an overlay identity, not a LAN route, so this must
/// not attempt a raw UDP packet to the VIP itself.
fn run_devices_check() -> Result<(), String> {
    let inventory = catalog_vip6_inventory()?;
    let peers = multicast_discover_peers()?;
    let mut visible = 0usize;
    for host in inventory {
        if let Some(peer) = peers.iter().find(|peer| peer.node == host.node) {
            println!(
                "dmesh_devices_check name={} vip6={} node={} reachable=true peer={}",
                host.name, host.vip6, host.node, peer.peer
            );
            visible += 1;
        } else {
            println!(
                "dmesh_devices_check name={} vip6={} node={} reachable=false",
                host.name, host.vip6, host.node
            );
        }
    }
    if visible == 0 {
        return Err("no catalogued VIP6 identity answered multicast discovery".into());
    }
    Ok(())
}

/// A signed identity correlated to a concrete Wi-Fi radio address.  The
/// catalog maps that address to an operator-owned device entry; the
/// announce display name is intentionally not used for this mapping.
#[derive(Clone, Debug, Eq, PartialEq)]
struct DiscoveryBinding {
    node: String,
    mac: [u8; 6],
}

fn mac_from_eui64(address: Ipv6Addr) -> Option<[u8; 6]> {
    let octets = address.octets();
    (octets[11] == 0xff && octets[12] == 0xfe).then(|| {
        [
            octets[8] ^ 0x02,
            octets[9],
            octets[10],
            octets[13],
            octets[14],
            octets[15],
        ]
    })
}

fn binding_from_direct_peer(peer: &DiscoveredPeer) -> Option<DiscoveryBinding> {
    if peer.node.len() != 16 {
        return None;
    }
    let address = peer
        .announce
        .sta_link_local_v6()
        .map(Ipv6Addr::from)
        .or_else(|| match peer.peer {
            SocketAddr::V6(address) => Some(*address.ip()),
            SocketAddr::V4(_) => None,
        })?;
    Some(DiscoveryBinding {
        node: peer.node.clone(),
        mac: mac_from_eui64(address)?,
    })
}

fn insert_binding(
    bindings: &mut BTreeMap<String, DiscoveryBinding>,
    binding: DiscoveryBinding,
) -> Result<(), String> {
    let key = mac_encode(&binding.mac);
    if let Some(existing) = bindings.get(&key) {
        if existing.node != binding.node {
            return Err(format!(
                "conflicting signed discovery identities for radio MAC {key}: {} and {}",
                existing.node, binding.node
            ));
        }
        return Ok(());
    }
    bindings.insert(key, binding);
    Ok(())
}

/// Update only one device's `vip6` field without reserializing the shared
/// operator-maintained catalog or exposing its protected fields.
fn upsert_catalog_vip6(path: &Path, name: &str, vip6: Ipv6Addr) -> Result<(), String> {
    let rendered = format!("\"{vip6}\"");
    let contents = std::fs::read_to_string(path)
        .map_err(|error| format!("read device catalog {}: {error}", path.display()))?;
    let mut lines = contents.lines().map(str::to_owned).collect::<Vec<_>>();
    let mut section = None;
    let mut end = lines.len();
    for (index, line) in lines.iter().enumerate() {
        if line.trim() == "[[devices]]" {
            if section.is_some() {
                end = index;
                break;
            }
            continue;
        }
        if line.split_once('=').is_some_and(|(key, value)| {
            key.trim() == "name" && value.trim() == format!("\"{name}\"")
        }) {
            section = (0..=index)
                .rev()
                .find(|&candidate| lines[candidate].trim() == "[[devices]]");
        }
    }
    let section = section.ok_or_else(|| {
        format!(
            "device catalog {} has no device named {name:?}",
            path.display()
        )
    })?;
    if end == lines.len() {
        end = lines[section + 1..]
            .iter()
            .position(|line| line.trim() == "[[devices]]")
            .map(|offset| section + 1 + offset)
            .unwrap_or(lines.len());
    }
    if let Some(index) = (section + 1..end).find(|&index| {
        lines[index]
            .split_once('=')
            .is_some_and(|(key, _)| key.trim() == "vip6")
    }) {
        lines[index] = format!("vip6 = {rendered}");
    } else {
        lines.insert(end, format!("vip6 = {rendered}"));
    }
    let updated = format!("{}\n", lines.join("\n"));
    let temporary = path.with_extension("toml.tmp");
    std::fs::write(&temporary, updated)
        .map_err(|error| format!("write {}: {error}", temporary.display()))?;
    std::fs::rename(&temporary, path)
        .map_err(|error| format!("replace {}: {error}", path.display()))
}

/// Back-fill catalogued VIP6 identities from live signed discovery. A write needs
/// both an announce identity and a radio MAC.  The common catalog is the only
/// MAC-to-name mapping, so a peer cannot create an arbitrary local node name.
fn run_devices_backfill(dry_run: bool) -> Result<(), String> {
    let reachable = multicast_discover_peers()?;
    let mut bindings = BTreeMap::<String, DiscoveryBinding>::new();
    for peer in &reachable {
        if let Some(binding) = binding_from_direct_peer(peer) {
            insert_binding(&mut bindings, binding)?;
        }
    }
    for peer in &reachable {
        if peer.passive_ready {
            let request = encode_stream_command_with_id("discovery.active", fresh_request_id())
                .map_err(|error| format!("encode discovery.active: {error}"))?;
            let _ = exchange_udp_stream_record(peer.peer, &request);
        }
    }
    std::thread::sleep(Duration::from_secs(5));
    for observer in &reachable {
        let request = encode_stream_command_with_id("discovery.nodes", fresh_request_id())
            .map_err(|error| format!("encode discovery.nodes: {error}"))?;
        let Ok(response) = exchange_udp_stream_record(observer.peer, &request) else {
            continue;
        };
        let Some(nodes) = observed_nodes(&response) else {
            continue;
        };
        for observed in nodes {
            if observed.node.len() == 16 {
                if let Some(mac) = observed.peer_mac {
                    insert_binding(
                        &mut bindings,
                        DiscoveryBinding {
                            node: observed.node,
                            mac,
                        },
                    )?;
                }
            }
        }
    }

    let catalog_path = device_catalog_path();
    let catalog = crate::prober::E2eConfig::from_path(&catalog_path)?;
    let mut changed = 0usize;
    for device in catalog.devices {
        let Some(mac) = device.mac.as_deref().and_then(parse_mac) else {
            continue;
        };
        let key = mac_encode(&mac);
        let Some(binding) = bindings.get(&key) else {
            continue;
        };
        let vip6 = announce::virtual_ip6_from_identity_hint(
            &hex(&binding.node)
                .map_err(|error| format!("decode node {}: {error}", binding.node))?,
        )
        .map(Ipv6Addr::from)
        .ok_or_else(|| format!("invalid identity hint {}", binding.node))?;
        println!(
            "dmesh_devices_backfill name={} mac={} vip6={} node={} write={}",
            device.name, key, vip6, binding.node, !dry_run
        );
        if !dry_run {
            upsert_catalog_vip6(&catalog_path, &device.name, vip6)?;
        }
        changed += 1;
    }
    if changed == 0 {
        return Err(
            "no catalogued radio MAC had a signed discovery identity; catalog unchanged".into(),
        );
    }
    Ok(())
}

/// Ask every directly reachable inventory node for a fresh discovery reply,
/// wait one DW8 interval plus margin, then collect each observer's local
/// `discovery.nodes` cache.  Every line describes one node; direct replies
/// are self reports without `visible_from`, observer cache rows carry the
/// single `visible_from` nodeID, and receiver-side facts keep one row per
/// (node, observer) pair because they differ per observer.
fn run_hosts_discovery() -> Result<(), String> {
    let reachable = multicast_discover_peers()?;
    if reachable.is_empty() {
        return Err("no peer answered UDP6 multicast discovery".into());
    }
    // Each observer owns different local media. Ask every reachable one to
    // run its common active pass (UDP, NAN, NOW where available), then allow
    // the sleepy-device DW and Android's temporary Aware Subscribe to report
    // before reading any observer cache.
    for discovered in &reachable {
        if !discovered.passive_ready {
            continue;
        }
        let request = encode_stream_command_with_id("discovery.active", fresh_request_id())
            .map_err(|error| format!("encode discovery.active: {error}"))?;
        let _ = exchange_udp_stream_record(discovered.peer, &request);
    }
    std::thread::sleep(Duration::from_secs(5));
    let mut rows = Vec::<(String, String, String)>::new();
    for discovered in &reachable {
        let peer = discovered.peer;
        let observer = discovered.node.clone();
        let request = encode_stream_command_with_id("discovery.nodes", fresh_request_id())
            .map_err(|error| format!("encode discovery.nodes: {error}"))?;
        match exchange_udp_stream_record(peer, &request) {
            Ok(response) => match observed_nodes(&response) {
                Some(nodes) => {
                    for entry in nodes {
                        rows.push((entry.node, observer.clone(), entry.fields));
                    }
                }
                None => println!("observer={observer} result=invalid_discovery_nodes"),
            },
            Err(error) => println!("observer={observer} error={error}"),
        }
    }
    rows.sort();
    for (node, observer, fields) in rows {
        let node_field = if node.is_empty() {
            String::new()
        } else {
            format!("node={node} ")
        };
        println!("{node_field}{fields} visible_from={observer}");
    }
    Ok(())
}

pub(crate) fn flash_target_matches(peer: &DiscoveredPeer, target: &FlashTarget) -> bool {
    flash_target_matches_announce(&peer.announce, target)
}

pub(crate) fn flash_target_matches_announce(
    announce: &announce::Announce,
    target: &FlashTarget,
) -> bool {
    target
        .node
        .as_deref()
        .is_some_and(|node| hex_encode(announce.device_id()).eq_ignore_ascii_case(node))
}

pub(crate) fn parse_mac(value: &str) -> Option<[u8; 6]> {
    let mut mac = [0u8; 6];
    let mut parts = value.split(':');
    for byte in &mut mac {
        *byte = u8::from_str_radix(parts.next()?, 16).ok()?;
    }
    parts.next().is_none().then_some(mac)
}

pub(crate) fn ensure_stream_success(response: Vec<u8>, action: &str) -> Result<(), String> {
    let record = dmesh_server::tagged::decode(&response)
        .ok_or_else(|| format!("{action} response is not tagged CBOR"))?;
    if record.error.is_some() || record.result.is_none() {
        return Err(format!("{action} rejected by peer"));
    }
    Ok(())
}

fn encode_nan_wake_stream_request(target: [u8; 6]) -> Result<Vec<u8>, String> {
    let mut request = [0u8; 96];
    let used = announce::encode_nan_wakeup_request(target, fresh_request_id(), &mut request)
        .ok_or("encode nan.wakeup request")?;
    Ok(request[..used].to_vec())
}

/// Return the exact running-image identity published by the common firmware
/// handler.  It is compared only for one endpoint across a requested reboot;
/// it is never used as a device identity or a substitute for the signed
/// announce identity.
pub(crate) fn firmware_identity(peer: SocketAddr) -> Result<String, String> {
    let request = encode_stream_command_with_id("firmware.identity", fresh_request_id())
        .map_err(|error| error.to_string())?;
    let response = exchange_udp_stream_record(peer, &request)?;
    let record = dmesh_server::tagged::decode(&response)
        .ok_or("firmware.identity response is not tagged CBOR")?;
    if record.error.is_some() {
        return Err("firmware.identity rejected by peer".into());
    }
    // The identity handler carries the hash as a CBOR text result. It is
    // still correlated by the enclosing record ID and is only compared across
    // this one requested Main -> Recovery -> Main handoff.
    let mut result = dmesh_server::cbor::Decoder::new(
        record
            .result
            .ok_or("firmware.identity response has no result")?,
    );
    let identity = result
        .text_ref()
        .and_then(|value| core::str::from_utf8(value).ok())
        .filter(|value| value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .ok_or("firmware.identity response is not a SHA-256 image hash")?;
    if !result.is_finished() {
        return Err("firmware.identity response has trailing fields".into());
    }
    Ok(identity.to_ascii_lowercase())
}

/// Send the common discovery request directly to every local IPv6 multicast
/// scope and return only peers that supplied the matching signed response.
pub(crate) struct DiscoveredPeer {
    pub(crate) peer: SocketAddr,
    /// Lowercase hex of the announce `device_id`, the stable nodeID for
    /// output; the peer address when the announce carries no device identity.
    pub(crate) node: String,
    /// The signed announce matched to this UDP6 endpoint.  The orchestrator
    /// uses its immutable device identity/class rather than inferring either
    /// from an address or a configured board nickname.
    pub(crate) announce: announce::Announce,
    /// A target relay must have receiver-side NAN evidence. A UDP multicast
    /// reply alone says nothing about whether it can see a sleepy device.
    pub(crate) passive_ready: bool,
}

/// Render the announce CBOR fields that are present, using the schema field
/// names. The virtual IPv6 identity replaces the raw public key/signature.
fn announce_log_fields(announce: &announce::Announce) -> Vec<String> {
    let mut fields = Vec::new();
    if announce.has_identity() {
        if let Some(vip) = announce::virtual_ip6(announce.public_key()) {
            fields.push(format!("vip6={}", Ipv6Addr::from(vip)));
        }
    }
    fields.push(format!("kind={}", announce.kind));
    fields.push(format!("uptime_secs={}", announce.uptime_secs));
    if announce.device_class != announce::DEVICE_CLASS_UNKNOWN {
        fields.push(format!("device_class={}", announce.device_class));
        fields.push(format!(
            "device_family={}",
            announce::device_class_name(announce.device_class)
        ));
        if let Some(cpu) = announce::flash_cpu_for_device_class(announce.device_class) {
            fields.push(format!("flash_cpu={cpu}"));
        }
    }
    if announce.probe_capabilities != 0 {
        fields.push(format!(
            "probe_capabilities={}",
            announce.probe_capabilities
        ));
    }
    if announce.recovery {
        fields.push("recovery=true".to_owned());
    }
    if let Some(name) = announce.device_name() {
        fields.push(format!("device_name={name}"));
    }
    if let Some(domain) = announce.device_domain() {
        fields.push(format!("device_domain={domain}"));
    }
    if let Some(name) = announce.network_name() {
        fields.push(format!("network_name={name}"));
    }
    if announce.wifi_channel != 0 {
        fields.push(format!("wifi_channel={}", announce.wifi_channel));
    }
    if let Some(addr) = announce.sta_link_local_v6() {
        fields.push(format!("sta_link_local_v6={}", Ipv6Addr::from(addr)));
    }
    if announce.udp_port != 0 {
        fields.push(format!("udp_port={}", announce.udp_port));
    }
    if let Some(addr) = announce.udp_link_local_v6() {
        fields.push(format!("udp_link_local_v6={}", Ipv6Addr::from(addr)));
    }
    fields
}

pub(crate) fn multicast_discover_peers() -> Result<Vec<DiscoveredPeer>, String> {
    dmesh_server::udp::discover_multicast_ipv6()
        .map_err(|error| error.to_string())
        .map(|discovered| {
            discovered
                .into_iter()
                .map(|entry| {
                    let passive_ready = entry.facts.is_some_and(|facts| {
                        facts.nan_service_observations != 0 || facts.nan_visible_nodes != 0
                    });
                    let node_id = hex_encode(entry.announce.device_id());
                    let node = if node_id.is_empty() {
                        entry.peer.to_string()
                    } else {
                        node_id.clone()
                    };
                    let mut line = vec![format!("peer={}", entry.peer)];
                    if !node_id.is_empty() {
                        line.insert(0, format!("node={node_id}"));
                    }
                    line.extend(announce_log_fields(&entry.announce));
                    if let Some(facts) = entry.facts {
                        if let Some(suffix) = facts.nan_cluster_suffix {
                            line.push(format!("nan_cluster_suffix={}", hex_encode(&suffix)));
                        }
                        line.push(format!(
                            "nan_service_observations={}",
                            facts.nan_service_observations
                        ));
                        line.push(format!("nan_visible_nodes={}", facts.nan_visible_nodes));
                    }
                    if !passive_ready {
                        line.push("passive_ready=false".to_owned());
                    }
                    println!("{}", line.join(" "));
                    DiscoveredPeer {
                        peer: entry.peer,
                        node,
                        announce: entry.announce,
                        passive_ready,
                    }
                })
                .collect()
        })
}

/// One decoded `discovery.nodes` observation. `node` is the hex of the
/// announce `device_id` (the truncated key used for the VIP6), empty for
/// provisional peers whose identity was never decoded; those rows are keyed
/// by the `peer` radio MAC inside `fields` instead. `fields` renders every
/// remaining observation fact with its CBOR schema name, in wire order.
struct ObservedNode {
    node: String,
    peer_mac: Option<[u8; 6]>,
    fields: String,
}

/// Decode the full bounded observation cache. The caller retains observer
/// provenance rather than pretending that a controller-local observation is
/// global mesh truth; receiver-side facts differ per observer and must not
/// be averaged together.
fn observed_nodes(response: &[u8]) -> Option<Vec<ObservedNode>> {
    dmesh_server::announce::decode_devices_observed_response(response).map(|devices| {
        devices
            .into_iter()
            .map(|device| {
                let mut fields = Vec::new();
                if let Some(peer) = device.peer {
                    fields.push(format!("peer={}", mac_encode(&peer)));
                }
                if let Some(bssid) = device.bssid {
                    fields.push(format!("bssid={}", mac_encode(&bssid)));
                }
                if let Some(channel) = device.channel {
                    fields.push(format!("channel={channel}"));
                }
                fields.push(format!("available_fields={}", device.available_fields));
                if device.first_seen_ms != 0 && device.first_seen_ms != u32::MAX {
                    fields.push(format!("first_seen_ms={}", device.first_seen_ms));
                }
                if device.last_seen_ms != 0 && device.last_seen_ms != u32::MAX {
                    fields.push(format!("last_seen_ms={}", device.last_seen_ms));
                }
                fields.push(format!("packets={}", device.packets));
                fields.push(format!("active_publish_rx={}", device.active_publish_rx));
                fields.push(format!(
                    "active_subscribe_rx={}",
                    device.active_subscribe_rx
                ));
                fields.push(format!("followup_rx={}", device.followup_rx));
                fields.push(format!("last_kind={}", device.last_kind));
                fields.push(format!("last_payload_len={}", device.last_payload_len));
                fields.push(format!("unavailable_fields={}", device.unavailable_fields));
                ObservedNode {
                    node: hex_encode(&device.device_id),
                    peer_mac: device.peer,
                    fields: fields.join(" "),
                }
            })
            .collect()
    })
}

/// Send one schema-backed private direct control record to an explicit UDP
/// companion.  This is deliberately separate from a QUIC-lite service stream:
/// it is used to request radio actions such as active discovery before a
/// relay/DCID route exists.
fn run_udp_direct_record(arguments: &[String]) -> Result<(), String> {
    let target = arguments.first().ok_or("missing UDP target")?;
    let peer = target
        .strip_prefix("udp://")
        .ok_or("UDP target must use udp://HOST:PORT")?;
    let peer = parse_udp_peer(peer)?;
    let mut index = 1;
    let record = match arguments.get(index).map(String::as_str) {
        Some("--direct-hex") => {
            index += 1;
            hex(arguments.get(index).ok_or("missing --direct-hex value")?)?
        }
        Some("--msg") => {
            index += 1;
            let end = arguments[index..]
                .iter()
                .position(|argument| matches!(argument.as_str(), "--timeout-secs" | "--baud"))
                .map(|offset| index + offset)
                .unwrap_or(arguments.len());
            let command = arguments[index..end].join(" ");
            if command.is_empty() {
                return Err("missing --msg value".into());
            }
            index = end.saturating_sub(1);
            encode_direct_command_with_id(&command, fresh_request_id())
                .map_err(|error| error.to_string())?
        }
        _ => usage(),
    };
    index += 1;
    let mut timeout = Duration::from_secs(2);
    while index < arguments.len() {
        match arguments[index].as_str() {
            "--timeout-secs" => {
                index += 1;
                timeout = Duration::from_secs(
                    arguments
                        .get(index)
                        .ok_or("missing --timeout-secs value")?
                        .parse::<u64>()
                        .map_err(|error| error.to_string())?,
                );
            }
            argument => return Err(format!("UDP direct record does not support {argument}")),
        }
        index += 1;
    }
    let response = exchange_udp_direct_record_with_timeout(peer, &record, timeout)?;
    let response_record = dmesh_server::direct::ConnectionlessMessage::decode(&response)
        .ok_or_else(|| "UDP direct record received a non-direct response".to_owned())?;
    let schema = load_tagged_schema();
    println!(
        "dmesh_udp_direct_reply target={peer} {}",
        render_device_record(&schema, response_record)
    );
    Ok(())
}

/// Exchange one direct record from the fixed dmesh-cli UDP source port.
/// Keeping this tuple stable is deliberate: relay.pair binds its reverse path
/// to it, while independent dmesh-cli invocations can reuse that binding.
fn exchange_udp_direct_record(peer: SocketAddr, record: &[u8]) -> Result<Vec<u8>, String> {
    exchange_udp_direct_record_with_timeout(peer, record, Duration::from_secs(2))
}

/// Execute a relay administration record on a normal QUIC stream. Relay
/// setup is never part of the direct-message allowlist.
pub(crate) fn exchange_udp_stream_record(
    peer: SocketAddr,
    record: &[u8],
) -> Result<Vec<u8>, String> {
    let runtime = tokio::runtime::Runtime::new().map_err(|error| error.to_string())?;
    runtime
        .block_on(dmesh_server::udp::exchange_stream_record(
            udp_bind_for_peer(peer),
            peer,
            record,
        ))
        .map_err(|error| error.to_string())
}

fn exchange_udp_direct_record_with_timeout(
    peer: SocketAddr,
    record: &[u8],
    timeout: Duration,
) -> Result<Vec<u8>, String> {
    let runtime = tokio::runtime::Runtime::new().map_err(|error| error.to_string())?;
    runtime
        .block_on(dmesh_server::udp::exchange_direct_record(
            udp_bind_for_peer(peer),
            peer,
            record,
            timeout,
        ))
        .map_err(|error| error.to_string())
}

/// Own one UDP QUIC-lite association and expose tagged-CBOR requests over a
/// mode-0600 seqpacket socket. Every local packet becomes one QUIC stream.
pub fn serve_udp_session_socket(peer: SocketAddr, socket_path: &Path) -> Result<(), String> {
    eprintln!(
        "dmesh_device_session target={peer} socket={}",
        socket_path.display()
    );
    let runtime = tokio::runtime::Runtime::new().map_err(|error| error.to_string())?;
    runtime
        .block_on(dmesh_server::udp::serve_session_socket(peer, socket_path))
        .map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::{
        RawTextTap, WatchTextFilter, is_fatal_diagnostic, lmesh_socket_target, observed_nodes,
        parse_udp_peer, run_serial_stream_command,
    };
    use crate::flash::{AutomatedFlashImage, parse_automated_flash_options};
    use dmesh_server::relay::{
        DesiredRule, PairRequest, RelayRoute, RelayState, Request, decode_pair_request,
        decode_request, encode_observed_pair, encode_observed_rule, encode_pair_request,
        encode_request, now_next_hop_handle, udp6_next_hop_handle,
    };
    use dmesh_server::udp::{
        RelayDatagramHandler, RelayDatagramOutcome, TaggedStreamContext, TaggedStreamHandler,
        UdpClient, UdpConfig,
    };
    use quic_lite::{ConnectionId, DcidDatagram, dispatch_datagram};
    use std::net::SocketAddr;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use tokio::net::UdpSocket;

    #[derive(Clone)]
    struct RelayHarness {
        state: Arc<Mutex<RelayState<SocketAddr, 2>>>,
        server_addr: SocketAddr,
        forward_count: Arc<AtomicUsize>,
        reverse_count: Arc<AtomicUsize>,
    }

    #[derive(Debug)]
    struct DirectRelayAdminSentinel(AtomicUsize);

    impl TaggedStreamHandler for DirectRelayAdminSentinel {
        fn handle<'a>(
            &'a self,
            _context: TaggedStreamContext,
            payload: Vec<u8>,
        ) -> Pin<Box<dyn std::future::Future<Output = Option<Vec<u8>>> + Send + 'a>> {
            Box::pin(async move {
                if decode_pair_request(&payload).is_some() || decode_request(&payload).is_some() {
                    self.0.fetch_add(1, Ordering::Relaxed);
                }
                None
            })
        }
    }

    impl TaggedStreamHandler for RelayHarness {
        fn handle<'a>(
            &'a self,
            context: TaggedStreamContext,
            request: Vec<u8>,
        ) -> Pin<Box<dyn std::future::Future<Output = Option<Vec<u8>>> + Send + 'a>> {
            Box::pin(async move {
                let record = dmesh_server::tagged::decode(&request)?;
                let id = record.id?;
                let mut response = [0u8; quic_lite::DEFAULT_MAX_DATAGRAM_SIZE];
                let used = if let Some(pair) = decode_pair_request(&request) {
                    let (forward, reverse) = self
                        .state
                        .lock()
                        .ok()?
                        .reconcile_pair(pair, |handle| {
                            if now_next_hop_handle([2, 0, 0, 0, 0, 1]) == Some(handle) {
                                Some(self.server_addr)
                            } else if udp6_next_hop_handle(1) == Some(handle) {
                                Some(context.peer)
                            } else {
                                None
                            }
                        })
                        .ok()?;
                    let mut fields = [0u8; 64];
                    let fields_len = encode_observed_pair(forward, reverse, &mut fields)?;
                    dmesh_server::tagged::encode_numeric_response(
                        dmesh_server::relay::RELAY_COMPONENT,
                        dmesh_server::relay::RELAY_APPLY_PAIR,
                        id,
                        &fields[..fields_len],
                        &mut response,
                    )?
                } else if let Some(request) = decode_request(&request) {
                    let observed = self
                        .state
                        .lock()
                        .ok()?
                        .reconcile(request, |handle| {
                            (now_next_hop_handle([2, 0, 0, 0, 0, 1]) == Some(handle))
                                .then_some(self.server_addr)
                        })
                        .ok()?;
                    let mut fields = [0u8; 64];
                    let fields_len = encode_observed_rule(observed, &mut fields)?;
                    dmesh_server::tagged::encode_numeric_response(
                        dmesh_server::relay::RELAY_COMPONENT,
                        dmesh_server::relay::RELAY_APPLY,
                        id,
                        &fields[..fields_len],
                        &mut response,
                    )?
                } else if record.component == Some(dmesh_server::tagged::Name::Tag(6))
                    && record.method == Some(dmesh_server::tagged::Name::Tag(9))
                {
                    // `curl -sS -X POST http://127.0.0.1:18981/_m/mesh \
                    //   -H 'content-type: application/json' \
                    //   --data '{"id":31,"method":"discovery.nodes"}'`
                    // exercises the same catalog method through HTTP.
                    dmesh_server::tagged::encode_numeric_response(
                        6,
                        9,
                        id,
                        &[0x81, 0x65, b'r', b'e', b'l', b'a', b'y'],
                        &mut response,
                    )?
                } else {
                    return None;
                };
                Some(response[..used].to_vec())
            })
        }
    }

    impl RelayDatagramHandler for RelayHarness {
        fn handle(
            &self,
            ingress: SocketAddr,
            packet: &[u8],
            out: &mut [u8],
        ) -> RelayDatagramOutcome {
            let Ok(state) = self.state.lock() else {
                return RelayDatagramOutcome::Drop;
            };
            let Ok(datagram) = dispatch_datagram(state.registry(), packet, out) else {
                return RelayDatagramOutcome::NotHandled;
            };
            let DcidDatagram::Forward {
                received_dcid,
                rule,
                used,
            } = datagram
            else {
                return RelayDatagramOutcome::NotHandled;
            };
            if ingress == self.server_addr {
                self.reverse_count.fetch_add(1, Ordering::Relaxed);
            } else {
                self.forward_count.fetch_add(1, Ordering::Relaxed);
            }
            let used = if matches!(rule.destination, quic_lite::ForwardDestination::Bootstrap)
                && ingress != self.server_addr
            {
                let Some(reverse) = state.relay_open_return_dcid(received_dcid) else {
                    return RelayDatagramOutcome::Drop;
                };
                let Ok(used) = quic_lite::rewrite_relay_open(packet, None, reverse, out) else {
                    return RelayDatagramOutcome::Drop;
                };
                used
            } else {
                used
            };
            RelayDatagramOutcome::Forward {
                peer: rule.next_hop,
                used,
            }
        }
    }

    /// CLIENT, RELAY, and SERVER share actual UDP listeners. Relay
    /// administration is sent on normal QUIC streams; only the current
    /// QUIC-lite relay-open bootstrap uses the custom-version Initial header.
    #[tokio::test]
    async fn udp_relay_pair_rewrites_bootstrap_and_status_both_directions() {
        let root = std::env::temp_dir().join(format!(
            "dmesh-cli-relay-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let server_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server_socket.local_addr().unwrap();
        drop(server_socket);
        let server_task = tokio::spawn(dmesh_server::udp::run(UdpConfig {
            bind: server_addr,
            artifact_root: root.clone(),
            ..UdpConfig::default()
        }));

        let relay_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = relay_socket.local_addr().unwrap();
        drop(relay_socket);
        let client_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let forward_count = Arc::new(AtomicUsize::new(0));
        let reverse_count = Arc::new(AtomicUsize::new(0));
        let relay = Arc::new(RelayHarness {
            state: Arc::new(Mutex::new(RelayState::new())),
            server_addr,
            forward_count: forward_count.clone(),
            reverse_count: reverse_count.clone(),
        });
        let direct_relay_admin = Arc::new(DirectRelayAdminSentinel(AtomicUsize::new(0)));
        let relay_task = tokio::spawn(dmesh_server::udp::run(UdpConfig {
            bind: relay_addr,
            artifact_root: root.clone(),
            tagged_handler: Some(relay.clone()),
            relay_handler: Some(relay),
            direct_handler: Some(direct_relay_admin.clone()),
            ..UdpConfig::default()
        }));

        // The first control connection uses the same stable client UDP tuple
        // that Step 2 will reuse for relay-open. `relay.pair` itself travels
        // on a normal tagged QUIC stream, never through the direct handler.
        let mut control = UdpClient::connect_with_socket(
            client_socket,
            relay_addr,
            ConnectionId::new(71).unwrap(),
        )
        .await
        .unwrap();
        let mut discovery = [0u8; 32];
        // HTTP-equivalent discovery request used by the dashboard before it
        // offers a relay-local neighbor:
        // curl -sS -X POST http://127.0.0.1:18982/_m/mesh/services/lmesh/call/discovery.nodes \
        //   -H 'content-type: application/json' --data '{"id":31}'
        let discovery_len =
            dmesh_server::tagged::encode_numeric_empty_request(6, 9, 31, &mut discovery).unwrap();
        let (_, discovery_response, discovery_fin) = control
            .request_stream(
                quic_lite::FIRST_CLIENT_BIDI_STREAM_ID,
                &discovery[..discovery_len],
                true,
            )
            .await
            .unwrap();
        assert!(discovery_fin);
        let discovery_response = dmesh_server::tagged::decode(&discovery_response).unwrap();
        assert_eq!(discovery_response.id, Some(31));
        assert_eq!(
            discovery_response.result,
            Some(&[0x81, 0x65, b'r', b'e', b'l', b'a', b'y'][..])
        );

        let pair = PairRequest {
            forward: Request {
                allocation: 1,
                revision: 1,
                rule: Some(DesiredRule {
                    proposed_dcid: Some(ConnectionId::new(8).unwrap()),
                    route: RelayRoute {
                        next_hop: now_next_hop_handle([2, 0, 0, 0, 0, 1]).unwrap(),
                        destination: quic_lite::ForwardDestination::Bootstrap,
                    },
                    position: 1,
                }),
            },
            reverse: Request {
                allocation: 2,
                revision: 1,
                rule: Some(DesiredRule {
                    proposed_dcid: Some(ConnectionId::new(12).unwrap()),
                    route: RelayRoute {
                        next_hop: udp6_next_hop_handle(1).unwrap(),
                        destination: quic_lite::ForwardDestination::Connection(
                            ConnectionId::new(77).unwrap(),
                        ),
                    },
                    position: 1,
                }),
            },
        };
        // Step-1 HTTP driver:
        // curl -sS -X POST http://127.0.0.1:18981/_m/mesh/services/lmesh/call/relay.connect \
        //   -H 'content-type: application/json' \
        //   --data '{"id":41,"relay_endpoint":"udp://[fe80::226e:f1ff:fe13:b170]:3339","next_hop_mac":"10:bd:a3:ac:5a:20"}'
        // performs this stream-side discovery + relay.pair sequence. Android
        // uses the same JSON at `/services/android/call/relay.connect`.
        let mut record = [0u8; 192];
        let record_len = encode_pair_request(pair, Some(41), &mut record).unwrap();
        let (_, response, response_fin) = control
            .request_stream(
                quic_lite::FIRST_CLIENT_BIDI_STREAM_ID + 4,
                &record[..record_len],
                true,
            )
            .await
            .unwrap();
        assert!(response_fin);
        let response_record = dmesh_server::tagged::decode(&response).unwrap();
        assert_eq!(
            response_record.method,
            Some(dmesh_server::tagged::Name::Tag(
                dmesh_server::relay::RELAY_APPLY_PAIR
            ))
        );
        assert!(response_record.error.is_none());
        let observed =
            dmesh_server::relay::decode_observed_pair(response_record.result.unwrap()).unwrap();
        assert_eq!(observed.forward.local_dcid.unwrap().value(), 8);
        assert_eq!(observed.reverse.local_dcid.unwrap().value(), 12);
        assert_eq!(
            direct_relay_admin.0.load(Ordering::Relaxed),
            0,
            "relay.pair must be administered through a normal QUIC stream"
        );
        let client_socket = control.into_socket().unwrap();

        let mut client = UdpClient::connect_with_socket_and_quic_lite_wire_dcid(
            client_socket,
            relay_addr,
            ConnectionId::new(77).unwrap(),
            ConnectionId::new(8).unwrap(),
        )
        .await
        .unwrap();
        let server_cid = client.peer_connection_id().unwrap();
        assert_ne!(server_cid.value(), 0);
        let update = Request {
            allocation: 1,
            revision: 2,
            rule: Some(DesiredRule {
                proposed_dcid: Some(ConnectionId::new(8).unwrap()),
                route: RelayRoute {
                    next_hop: now_next_hop_handle([2, 0, 0, 0, 0, 1]).unwrap(),
                    destination: quic_lite::ForwardDestination::Connection(server_cid),
                },
                position: 1,
            }),
        };
        let mut update_record = [0u8; 128];
        let update_record_len = encode_request(update, Some(42), &mut update_record).unwrap();
        // The current one-connection UDP helper gives its socket to the
        // relayed endpoint above. A later shared client-session mux will keep
        // this original control connection alive. Until then, verify that the
        // reconciliation is still a normal QUIC stream, not a direct packet.
        let mut update_control = UdpClient::connect(
            "127.0.0.1:0".parse().unwrap(),
            relay_addr,
            ConnectionId::new(72).unwrap(),
        )
        .await
        .unwrap();
        // `relay.apply` is an internal Step-2 reconciliation record, not a
        // public HTTP method. The future HTTP driver remains `relay.connect`;
        // it owns the retained session and performs this update after OPEN_ACK.
        let (_, update_response, update_fin) = update_control
            .request_stream(
                quic_lite::FIRST_CLIENT_BIDI_STREAM_ID,
                &update_record[..update_record_len],
                true,
            )
            .await
            .unwrap();
        assert!(update_fin);
        assert!(
            dmesh_server::tagged::decode(&update_response)
                .unwrap()
                .error
                .is_none()
        );

        let mut status_request = [0u8; 32];
        let status_request_len = dmesh_server::tagged::encode_numeric_empty_request(
            dmesh_server::services::DIAGNOSTIC_COMPONENT,
            dmesh_server::services::DIAGNOSTIC_STATUS_METHOD,
            43,
            &mut status_request,
        )
        .unwrap();
        let (_, status, fin) = client
            .request_stream(
                quic_lite::FIRST_CLIENT_BIDI_STREAM_ID,
                &status_request[..status_request_len],
                true,
            )
            .await
            .unwrap();
        let status_record = dmesh_server::tagged::decode(&status).unwrap();
        let mut status_result = dmesh_server::cbor::Decoder::new(status_record.result.unwrap());
        let status = String::from_utf8(status_result.text_ref().unwrap().to_vec()).unwrap();
        assert!(fin);
        assert!(
            status.contains("connection_dcid="),
            "status handler response: {status}"
        );
        assert!(
            forward_count.load(Ordering::Relaxed) >= 2,
            "bootstrap plus status must traverse forward route"
        );
        assert!(
            reverse_count.load(Ordering::Relaxed) >= 2,
            "bootstrap ACK plus status must traverse reverse route"
        );
        assert_eq!(
            direct_relay_admin.0.load(Ordering::Relaxed),
            0,
            "relay.apply must be administered through a normal QUIC stream"
        );
        eprintln!(
            "dmesh-cli relay-e2e server_dcid={} forward_packets={} reverse_packets={}",
            server_cid.value(),
            forward_count.load(Ordering::Relaxed),
            reverse_count.load(Ordering::Relaxed)
        );
        relay_task.abort();
        server_task.abort();
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn raw_text_tap_reports_complete_lines_and_ignores_ppp() {
        let mut tap = RawTextTap::default();
        assert!(tap.push(b"boot step=").is_empty());
        assert_eq!(tap.push(b"uart\r\n"), vec!["boot step=uart"]);
        assert!(tap.push(&[0x7e, b'a', 0, b'\n', 0x7e]).is_empty());
        assert_eq!(tap.push(b"panic=none\n"), vec!["panic=none"]);
    }

    #[test]
    fn lmesh_uses_a_positional_method_and_catalog_field_options() {
        assert_eq!(
            lmesh_socket_target("lmesh"),
            Some("/run/mesh/lmesh/mesh.sock.cbor")
        );
        assert_eq!(
            lmesh_socket_target("lmesh://lmesh"),
            Some("/run/mesh/lmesh/mesh.sock.cbor")
        );
        assert_eq!(
            lmesh_socket_target("uds:///tmp/lmesh.sock"),
            Some("/tmp/lmesh.sock")
        );
        let catalog = mesh::tagged::load_service_catalog("lmesh")
            .unwrap()
            .unwrap();
        let record = catalog
            .parse_argv(
                "wifi.interface.channel",
                &["--iface=wlan0".to_owned(), "--channel=6".to_owned()],
            )
            .unwrap();
        assert!(matches!(record.component, mesh::tagged::NameOrTag::Tag(5)));
        assert!(matches!(record.method, mesh::tagged::NameOrTag::Tag(32)));
        assert_eq!(record.env.len(), 2);
        assert!(catalog.method("wifi.rawnan.status").is_none());
    }

    #[test]
    fn watch_filter_keeps_first_sniffer_diagnostic() {
        let mut filter = WatchTextFilter::default();
        assert!(filter.retain("I (1) wifi:ic_disable_sniffer"));
        assert!(!filter.retain("I (2) wifi:ic_disable_sniffer"));
        assert!(filter.retain("DMESH main: radio ready"));
        assert_eq!(filter.suppressed_disable_sniffer, 1);
    }

    #[test]
    fn session_fatal_diagnostics_cover_panic_and_mid_suite_reset() {
        assert!(is_fatal_diagnostic("Guru Meditation Error"));
        assert!(is_fatal_diagnostic("rst:0x1 (POWERON_RESET)"));
        assert!(!is_fatal_diagnostic("transport status=ready"));
    }

    #[test]
    fn scoped_link_local_udp_peer_keeps_interface_index() {
        let peer = parse_udp_peer("[fe80::16c1:9fff:fee5:9800%9]:3339").unwrap();
        assert_eq!(peer.to_string(), "[fe80::16c1:9fff:fee5:9800%9]:3339");
    }

    #[test]
    fn scoped_link_local_udp_peer_uses_the_raw_firmware_default_port() {
        let peer = parse_udp_peer("[fe80::16c1:9fff:fee5:9800%9]").unwrap();
        assert_eq!(peer.to_string(), "[fe80::16c1:9fff:fee5:9800%9]:3339");
    }

    #[test]
    fn uart_rejects_firmware_upload_before_opening_the_device() {
        let error = run_serial_stream_command(&[
            "/definitely/not/a/serial/device".into(),
            "object.flash".into(),
            "cpu=13".into(),
            "target=6".into(),
        ])
        .unwrap_err();
        assert!(error.contains("not supported over UART"), "{error}");
    }

    #[test]
    fn observed_nodes_render_the_full_observation_facts() {
        let entries = [
            dmesh_server::announce::ObservedDevice {
                device_id: b"peer-a",
                peer: [1, 2, 3, 4, 5, 6],
                bssid: Some([0x50, 0x6f, 0x9a, 1, 2, 3]),
                channel: Some(6),
                available_fields: dmesh_server::discovery::OBSERVATION_ALL_FIELDS,
                first_seen_ms: 1,
                last_seen_ms: 2,
                packets: 3,
                active_publish_rx: 4,
                active_subscribe_rx: 5,
                followup_rx: 6,
                last_kind: 1,
                last_payload_len: 7,
                last_payload_hash: 8,
            },
            dmesh_server::announce::ObservedDevice {
                device_id: b"",
                peer: [7, 8, 9, 10, 11, 12],
                bssid: None,
                channel: None,
                available_fields: dmesh_server::discovery::OBSERVATION_PEER,
                first_seen_ms: 9,
                last_seen_ms: 10,
                packets: 11,
                active_publish_rx: 0,
                active_subscribe_rx: 0,
                followup_rx: 0,
                last_kind: 0,
                last_payload_len: 0,
                last_payload_hash: 0,
            },
            // Android-style row: a decoded identity but an opaque PeerHandle
            // (zero MAC) and wall-clock timestamps that degrade to u32::MAX.
            dmesh_server::announce::ObservedDevice {
                device_id: b"\x6c\x57\xff\x07\x63\x7d\x3b\x61\x7c\xab\x85\x77\x0b\x9c\xeb\xc4",
                peer: [0; 6],
                bssid: None,
                channel: None,
                available_fields: dmesh_server::discovery::OBSERVATION_PEER
                    | dmesh_server::discovery::OBSERVATION_PAYLOAD_FINGERPRINT,
                first_seen_ms: u32::MAX,
                last_seen_ms: u32::MAX,
                packets: 33,
                active_publish_rx: 33,
                active_subscribe_rx: 0,
                followup_rx: 0,
                last_kind: 0,
                last_payload_len: 96,
                last_payload_hash: 0,
            },
        ];
        let mut result = [0u8; 768];
        let result_len =
            dmesh_server::announce::encode_devices_observed_response(&entries, &mut result)
                .expect("encode discovery inventory");
        let fields = dmesh_server::tagged::decode(&result[..result_len])
            .and_then(|record| record.fields)
            .expect("extract discovery inventory fields");
        let mut response = [0u8; 960];
        let response_len =
            dmesh_server::tagged::encode_numeric_response(6, 9, 1, fields, &mut response)
                .expect("wrap discovery inventory");
        let nodes = observed_nodes(&response[..response_len]).expect("decode observations");
        assert_eq!(nodes.len(), 3);
        assert_eq!(nodes[0].node, "706565722d61");
        assert_eq!(
            nodes[0].fields,
            "peer=01:02:03:04:05:06 bssid=50:6f:9a:01:02:03 channel=6 \
              available_fields=31 first_seen_ms=1 last_seen_ms=2 packets=3 \
              active_publish_rx=4 active_subscribe_rx=5 followup_rx=6 \
              last_kind=1 last_payload_len=7 unavailable_fields=0"
        );
        // A provisional radio peer without a decoded identity has no nodeID;
        // its row is keyed by the peer MAC inside the facts.
        assert_eq!(nodes[1].node, "");
        assert_eq!(
            nodes[1].fields,
            "peer=07:08:09:0a:0b:0c available_fields=1 first_seen_ms=9 \
              last_seen_ms=10 packets=11 active_publish_rx=0 active_subscribe_rx=0 \
              followup_rx=0 last_kind=0 last_payload_len=0 unavailable_fields=30"
        );
        assert_eq!(nodes[2].node, "6c57ff07637d3b617cab85770b9cebc4");
        assert_eq!(nodes[2].peer_mac, None);
        // The zero PeerHandle MAC and u32::MAX timestamp sentinels are
        // placeholders, not facts, so they do not render.
        assert_eq!(
            nodes[2].fields,
            "available_fields=17 packets=33 active_publish_rx=33 active_subscribe_rx=0 \
              followup_rx=0 last_kind=0 last_payload_len=96 unavailable_fields=14"
        );
    }

    #[test]
    fn automated_flash_options_select_main_owned_targets_without_dry_run() {
        let recovery_args = ["e7".into(), "--target".into(), "recovery".into()];
        let recovery = parse_automated_flash_options(&recovery_args).unwrap();
        assert_eq!(recovery.image, AutomatedFlashImage::Recovery);
        assert_eq!(recovery.image.target(), 3);

        let stage2_args = [
            "e8".into(),
            "--target".into(),
            "stage2".into(),
            "--file".into(),
            "stage.bin".into(),
        ];
        let stage2 = parse_automated_flash_options(&stage2_args).unwrap();
        assert_eq!(stage2.image, AutomatedFlashImage::Stage2);
        assert_eq!(stage2.source, Some("stage.bin"));

        let module_args = ["lora1".into(), "--target".into(), "lora".into()];
        let module = parse_automated_flash_options(&module_args).unwrap();
        assert_eq!(module.image, AutomatedFlashImage::Module("lora".into()));
        assert_eq!(module.image.label(), "lora");
        assert_eq!(module.image.target(), 7);

        assert!(
            parse_automated_flash_options(&[
                "lora1".into(),
                "--target".into(),
                "lora".into(),
                "--module".into(),
                "legacy".into(),
            ])
            .is_err()
        );

        assert!(
            parse_automated_flash_options(&[
                "e7".into(),
                "--target".into(),
                "recovery".into(),
                "--dry-run".into(),
                "true".into(),
            ])
            .is_err()
        );
    }
}
