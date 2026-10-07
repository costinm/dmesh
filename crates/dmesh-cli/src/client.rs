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
use crate::uart::{DeviceSession, DeviceSessionEvent};
use crate::{
    device::{
        DeviceProfile, load_device, resolve_catalog_target, resolve_udp_peer,
    },
    schema::{
        encode_stream_argv_with_id, encode_stream_command_with_id,
        is_stream_command_name, load_tagged_schema, render_device_record,
    },
};
use dmesh_server::announce;
use std::{
    env,
    io::{ErrorKind, Read},
    net::{Ipv6Addr, SocketAddr, SocketAddrV6},
    os::fd::AsRawFd,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

static NEXT_REQUEST_ID: AtomicU64 = AtomicU64::new(1);

pub(crate) fn fresh_request_id() -> u64 {
    let time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_micros() as u64);
    time ^ NEXT_REQUEST_ID.fetch_add(1, Ordering::Relaxed)
}

pub(crate) fn is_fatal_diagnostic(line: &str) -> bool {
    let line = line.to_ascii_lowercase();
    [
        "panic",
        "guru meditation",
        "assert failed",
        "backtrace",
        "abort()",
    ]
    .iter()
    .any(|marker| line.contains(marker))
}

fn usage() -> ! {
    eprintln!(
        "usage: dmesh-cli SERIAL|DEVICE --reset\n       dmesh-cli SERIAL|DEVICE --wake [--baud PHYSICAL_UART_BAUD]\n       dmesh-cli SERIAL|DEVICE --watch [--reset] [--interactive] [--baud PHYSICAL_UART_BAUD] [--timeout-secs N]\n       dmesh-cli DEVICE METHOD [--field=value ...] [--bearer udp[,uart]]\n       dmesh-cli SERIAL METHOD [--baud PHYSICAL_UART_BAUD] [--timeout-secs N] [--linger-secs N] [--repeat-secs N] [--field=value ...]\n       dmesh-cli devices check|sync [--dry-run]\n       dmesh-cli discover\n       dmesh-cli flash TARGET [--target main|recovery|stage2|MODULE] [--file IMAGE]\n       dmesh-cli lmesh METHOD [--field=value ...]\n       dmesh-cli NODE check\n       dmesh-cli udp://HOST:PORT --socket PATH\n       dmesh-cli http://HOST:PORT SERVICE.METHOD [--field=value ...]"
    );
    std::process::exit(2)
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
    if matches!(arguments.as_slice(), [devices, sync] if devices == "devices" && (sync == "sync" || sync == "backfill"))
    {
        return run_devices_sync(false);
    }
    if matches!(arguments.as_slice(), [devices, sync, dry_run] if devices == "devices" && (sync == "sync" || sync == "backfill") && dry_run == "--dry-run")
    {
        return run_devices_sync(true);
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
    if arguments
        .get(1)
        .is_some_and(|argument| argument == "--wake")
    {
        let target = arguments.first().cloned().unwrap_or_else(|| usage());
        let mut baud = None;
        if !target.starts_with('/') {
            if target.contains(':') {
                return Err("--wake requires a serial path or device profile".into());
            }
            let profile = load_device(&target)?;
            let serial = profile
                .serial_path()?
                .ok_or_else(|| format!("device {target:?} has no serial_id for --wake"))?;
            arguments[0] = serial.display().to_string();
            baud = profile.uart_baud;
        }
        if arguments.len() > 2 {
            if arguments.len() == 4 && arguments[2] == "--baud" {
                baud = Some(
                    arguments[3]
                        .parse::<u32>()
                        .map_err(|error| error.to_string())?,
                );
            } else {
                return Err("--wake accepts only --baud PHYSICAL_UART_BAUD".into());
            }
        }
        let mut session = DeviceSession::open(&arguments[0], baud)?;
        session.send_wake()?;
        println!("dmesh_uart_wake_sent target={} bytes=1", arguments[0]);
        return Ok(());
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
        if let Some(profile) = resolve_catalog_target(&target)? {
            let selected = flash_target_from_catalog_profile(&profile)?;
            let (peer, _) = discover_and_nan_activate(&selected)?;
            return run_udp_direct_discovery(peer);
        }
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
    let session = DeviceSession::open(path, None)?;
    session.reset()?;
    println!("dmesh_cli_reset target={path} line=RTS pulse_ms=120");
    Ok(())
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

/// Directly invoke a stream handler through UART L2. The ordinary request and
/// probe paths share QUIC streams; probe payload validation stays incremental
/// on each bearer.
fn run_serial_stream_command(arguments: &[String]) -> Result<(), String> {
    let (service_arguments, baud, mut timeout, timeout_explicit, linger, repeat_interval) =
        parse_serial_stream_arguments(arguments.get(1..).unwrap_or_default())?;
    let body = encode_stream_argv_with_id(&service_arguments, fresh_request_id())
        .map_err(|error| error.to_string())?;
    let path = arguments.first().ok_or("missing serial path")?;
    if dmesh_server::object_transfer::decode_flash_command(&body).is_some() {
        return Err(
            "object.flash is not supported over UART; use `dmesh-cli flash TARGET` for Wi-Fi flashing or scripts/flash-device.py for physical recovery"
                .into(),
        );
    }
    let probe_request = dmesh_server::tagged::decode(&body)
        .and_then(dmesh_server::probe::decode_probe_start_record)
        .filter(|(_, request)| request.peer.is_none());
    let runtime = tokio::runtime::Runtime::new().map_err(|error| error.to_string())?;
    if let Some((id, probe_request)) = probe_request {
        if !timeout_explicit {
            timeout = probe_request_timeout(probe_request.total_bytes());
        }
        // Without a `peer` the CLI is the probe's client: it calls the probed
        // node's registered `probe.handler` handler and validates the payload.
        let mut source = [0u8; dmesh_server::probe::PROBE_REQUEST_MAX];
        let used = dmesh_server::probe::encode_probe_handler_request(probe_request, id, &mut source)
            .ok_or("probe request does not fit a probe.handler header")?;
        let result = runtime.block_on(crate::node_client::probe_uart(
            path,
            baud,
            &source[..used],
            probe_request,
            timeout,
        ))?;
        println!(
            "dmesh_cli_probe bearer=uart target={path} direction={} bytes={} elapsed_us={} mbps={:.3} callback_errors={:?}",
            probe_request.direction.as_str(),
            result.bytes,
            result.elapsed_us,
            result.bits_per_second() as f64 / 1_000_000.0,
            result.callback_errors,
        );
        return Ok(());
    }
    let repeat_arguments = service_arguments.clone();
    let schema = load_tagged_schema();
    let _last_response = runtime.block_on(crate::node_client::request_uart_monitor(
        path,
        baud,
        || {
            encode_stream_argv_with_id(&repeat_arguments, fresh_request_id())
                .map_err(|error| error.to_string())
        },
        timeout,
        repeat_interval,
        linger,
        |response| {
            println!(
                "dmesh_cli_stream_command target={} fin=true bytes={} {}",
                path,
                response.bytes.len(),
                render_device_record(&schema, &response.bytes),
            );
        },
    ))?;
    Ok(())
}

fn parse_serial_stream_arguments(
    arguments: &[String],
) -> Result<
    (
        Vec<String>,
        Option<u32>,
        Duration,
        bool,
        Duration,
        Option<Duration>,
    ),
    String,
> {
    let mut service_arguments = Vec::new();
    let mut baud = None;
    let mut timeout = Duration::from_secs(3);
    let mut timeout_explicit = false;
    let mut linger = Duration::ZERO;
    let mut repeat_interval = None;
    let mut index = 0;
    while index < arguments.len() {
        match arguments[index].as_str() {
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
                timeout_explicit = true;
                timeout = Duration::from_secs(
                    arguments
                        .get(index)
                        .ok_or("missing --timeout-secs value")?
                        .parse::<u64>()
                        .map_err(|error| error.to_string())?,
                );
            }
            "--linger-secs" => {
                index += 1;
                linger = Duration::from_secs(
                    arguments
                        .get(index)
                        .ok_or("missing --linger-secs value")?
                        .parse::<u64>()
                        .map_err(|error| error.to_string())?,
                );
            }
            "--repeat-secs" => {
                index += 1;
                let seconds = arguments
                    .get(index)
                    .ok_or("missing --repeat-secs value")?
                    .parse::<u64>()
                    .map_err(|error| error.to_string())?;
                if seconds == 0 {
                    return Err("--repeat-secs must be greater than zero".into());
                }
                repeat_interval = Some(Duration::from_secs(seconds));
            }
            _ => service_arguments.push(arguments[index].clone()),
        }
        index += 1;
    }
    if repeat_interval.is_some()
        && !matches!(
            service_arguments.first().map(String::as_str),
            Some("status" | "services")
        )
    {
        return Err(
            "--repeat-secs is limited to the read-only status and services commands".into(),
        );
    }
    Ok((
        service_arguments,
        baud,
        timeout,
        timeout_explicit,
        linger,
        repeat_interval,
    ))
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
    let id = fresh_request_id();
    let mut request = [0u8; 64];
    let used =
        announce::encode_discovery_request(id, &mut request).ok_or("encode discovery request")?;
    let runtime = tokio::runtime::Runtime::new().map_err(|error| error.to_string())?;
    let response = runtime
        .block_on(crate::node_client::request_uart(
            path,
            baud,
            &request[..used],
            Duration::from_secs(3),
        ))?
        .bytes;
    let record = dmesh_server::tagged::decode(&response).ok_or("invalid check response")?;
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
    let mut session = DeviceSession::open(path, baud)?;
    // Print the resolved physical contract before touching RTS.  A board name
    // has already been expanded to this exact `/dev/serial/by-id` path, and
    // an explicit baud makes a CP210x capture reproducible instead of relying
    // on whichever termios settings a prior owner left behind. `None` selects
    // the protocol default of 115200; native USB-JTAG ignores line coding.
    println!(
        "uart_watch event=open target={path} baud={}",
        baud.unwrap_or(uart_codec::host::DEFAULT_BAUD)
    );
    if reset_after_open {
        session.reset()?;
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
    let mut text_filter = WatchTextFilter::default();
    let mut transport_packets = 0u64;
    let mut observations = 0u64;
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
                        match parse_interactive_service_command(&line).and_then(|_| {
                            Err(
                                "interactive service requests require a one-shot UART session"
                                    .into(),
                            )
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
        session.poll_diagnostics(Duration::from_millis(2))?;
        for event in session.drain_events() {
            observations = observations.saturating_add(1);
            match event {
                DeviceSessionEvent::Diagnostic(line) => {
                    if text_filter.retain(&line) {
                            println!("{line}");
                    }
                }
                DeviceSessionEvent::Message(message) => {
                    println!("uart_watch event=message bytes={}", message.len());
                }
                DeviceSessionEvent::Datagram(packet) => {
                    transport_packets = transport_packets.saturating_add(1);
                    println!("uart_watch event=transport bytes={}", packet.len());
                }
            }
        }
        thread::sleep(Duration::from_millis(1));
    }
    println!(
        "uart_watch event=timeout observations={observations} transport_packets={transport_packets}"
    );
    if text_filter.suppressed_disable_sniffer != 0 {
        println!(
            "uart_watch event=suppressed text=ic_disable_sniffer count={}",
            text_filter.suppressed_disable_sniffer
        );
    }
    // A passive watch may legitimately see nothing.  A watch that explicitly
    // performed the reset cannot: no byte at all means the ROM/Stage2/Main
    // serial path was not observed, so returning success would hide the exact
    // boot regression this diagnostic mode exists to expose.
    if reset_after_open && observations == 0 {
        return Err(format!(
            "UART reset capture received no bytes target={path} baud={}; ROM, Stage2, or Main serial output was not observed",
            baud.map_or("driver-default".to_owned(), |value| value.to_string())
        ));
    }
    session.assert_healthy()
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
/// The node owns association setup, packet processing, and stream flow control;
/// the CLI only opens a byte stream and renders the returned tagged record.
pub(crate) fn run_udp_service_client(arguments: &[String]) -> Result<(), String> {
    let (arguments, object_file) = split_object_file_argument(arguments)?;
    let (arguments, uart_path, uart_baud) = split_uart_bearer_arguments(&arguments)?;
    let peer = arguments
        .first()
        .and_then(|target| target.strip_prefix("udp://"))
        .ok_or("UDP target must use udp://HOST:PORT")?;
    let peer = parse_udp_peer(peer)?;
    let command = arguments
        .get(1)
        .filter(|command| is_stream_command_name(command))
        .ok_or("missing schema service; use dmesh-cli DEVICE METHOD [--field=value ...]")?;
    let request = encode_stream_argv_with_id(&arguments[1..], fresh_request_id())
        .map_err(|error| error.to_string())?;
    let timeout = stream_request_timeout(&request)?;
    let probe_request = dmesh_server::probe::decode_probe_start_record(
        dmesh_server::tagged::decode(&request).ok_or("invalid tagged request")?,
    );
    let started = Instant::now();
    let runtime = tokio::runtime::Runtime::new().map_err(|error| error.to_string())?;
    let response = if command == "object.flash" {
        if uart_path.is_some() {
            return Err(
                "object.flash selects UDP for bulk image transfer; omit --uart-bearer".into(),
            );
        }
        let (_, flash) = dmesh_server::object_transfer::decode_flash_command(&request)
            .ok_or("invalid object.flash request")?;
        let (image, artifact) = flash_upload_object(flash.object, object_file.as_deref())?;
        eprintln!(
            "dmesh_cli_object_upload bearer=udp association=single stream=single artifact={}",
            artifact.display()
        );
        runtime
            .block_on(crate::node_client::flash_udp(
                udp_bind_for_peer(peer),
                peer,
                &request,
                &image,
                object_upload_timeout(),
            ))?
            .bytes
    } else {
        if let Some((id, probe_request)) =
            probe_request.filter(|(_, request)| request.peer.is_none())
        {
            // The CLI is the probe's client: it calls the probed node's
            // registered `probe.handler` handler and validates the payload.
            let mut source = [0u8; dmesh_server::probe::PROBE_REQUEST_MAX];
            let used =
                dmesh_server::probe::encode_probe_handler_request(probe_request, id, &mut source)
                    .ok_or("probe request does not fit a probe.handler header")?;
            let result = runtime.block_on(crate::node_client::probe_udp_with_uart(
                udp_bind_for_peer(peer),
                peer,
                uart_path.as_deref(),
                uart_baud,
                &source[..used],
                probe_request,
                timeout,
            ))?;
            println!(
                "dmesh_cli_probe bearer={} target={peer} direction={} bytes={} elapsed_us={} mbps={:.3} callback_errors={:?}",
                if uart_path.is_some() {
                    "udp+uart"
                } else {
                    "udp"
                },
                probe_request.direction.as_str(),
                result.bytes,
                result.elapsed_us,
                result.bits_per_second() as f64 / 1_000_000.0,
                result.callback_errors,
            );
            return Ok(());
        }
        runtime
            .block_on(crate::node_client::request_udp_with_uart(
                udp_bind_for_peer(peer),
                peer,
                uart_path.as_deref(),
                uart_baud,
                &request,
                timeout,
            ))?
            .bytes
    };
    if command == "object.flash" {
        flash_upload_success(&response)?;
    }
    println!(
        "dmesh_cli_stream_command target={peer} fin=true bytes={} elapsed_us={} {}",
        response.len(),
        started.elapsed().as_micros(),
        render_device_record(&load_tagged_schema(), &response),
    );
    Ok(())
}

fn split_uart_bearer_arguments(
    arguments: &[String],
) -> Result<(Vec<String>, Option<String>, Option<u32>), String> {
    let mut retained = Vec::with_capacity(arguments.len());
    let mut uart_path = None;
    let mut uart_baud = None;
    let mut index = 0;
    while index < arguments.len() {
        match arguments[index].as_str() {
            "--uart-bearer" => {
                let value = arguments
                    .get(index + 1)
                    .ok_or("missing --uart-bearer path")?;
                if uart_path.replace(value.clone()).is_some() {
                    return Err("only one --uart-bearer path may be selected".into());
                }
                index += 2;
            }
            "--uart-baud" => {
                let value = arguments
                    .get(index + 1)
                    .ok_or("missing --uart-baud value")?;
                uart_baud = Some(value.parse::<u32>().map_err(|error| error.to_string())?);
                index += 2;
            }
            "--bearer" => {
                let value = arguments.get(index + 1).ok_or("missing --bearer value")?;
                match value.as_str() {
                    "udp" => {}
                    "uart" => {
                        return Err(
                            "--bearer uart needs a device profile or --uart-bearer PATH".into()
                        );
                    }
                    "espnow" => {
                        return Err(
                            "ESP-NOW bearer selection requires the supervised lmesh node".into(),
                        );
                    }
                    other => return Err(format!("unknown bearer {other:?}")),
                }
                index += 2;
            }
            _ => {
                retained.push(arguments[index].clone());
                index += 1;
            }
        }
    }
    if uart_baud.is_some() && uart_path.is_none() {
        return Err("--uart-baud requires --uart-bearer PATH".into());
    }
    Ok((retained, uart_path, uart_baud))
}

fn stream_request_timeout(request: &[u8]) -> Result<Duration, String> {
    let record = dmesh_server::tagged::decode(request).ok_or("invalid tagged request")?;
    Ok(dmesh_server::probe::decode_probe_start_record(record)
        .map(|(_, request)| probe_request_timeout(request.total_bytes()))
        .unwrap_or_else(|| Duration::from_secs(3)))
}

/// Allow a full-rate UART probe at 115200 baud, with headroom for QUIC
/// framing, retransmission, and device scheduling. The caller can override
/// this per request with `--timeout-secs`.
fn probe_request_timeout(bytes: u64) -> Duration {
    Duration::from_secs(
        bytes
            .saturating_add(8 * 1024 - 1)
            .div_euclid(8 * 1024)
            .max(45),
    )
}

/// Remove the CLI-only object source selector before schema encoding.  A
/// source path is host policy, not a firmware command field, so it must never
/// be sent to the device or become part of the object manifest.
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
/// Source port of `dmesh-cli` itself (override with `DMESH_UDP_SOURCE_PORT`).
pub(crate) const DMESH_CLI_UDP_PORT: u16 = 3338;

fn udp_bind_for_peer(peer: SocketAddr) -> SocketAddr {
    let port = env::var("DMESH_UDP_SOURCE_PORT")
        .ok()
        .and_then(|value| value.parse::<u16>().ok())
        // The client's own fixed port: lmesh, Android and the firmware serve 3339, and this
        // is the one port the CLI uses, so a firewall or capture can name it.
        .unwrap_or(DMESH_CLI_UDP_PORT);
    // If another `dmesh-cli` holds it, an ephemeral port is used (see `bind_client_udp`).
    quic_lite::bearer_udp::wildcard_bind(peer, port)
}

/// Parse a UDP peer, including the scoped IPv6 link-local form required by
/// raw UDP6 tests: `[fe80::1%wlan0]` (the firmware default port is used) or
/// `[fe80::1%wlan0]:3339`. `SocketAddr` itself deliberately
/// does not parse interface names, so resolve the Linux interface index here
/// at the host CLI boundary rather than teaching firmware about host scopes.
fn parse_udp_peer(value: &str) -> Result<SocketAddr, String> {
    quic_lite::bearer_udp::parse_peer(value, 3339).map_err(|error| error.to_string())
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
    let announce = dmesh_server::discovery::discover_udp(peer, id, Duration::from_secs(3))?;
    Ok((id, announce))
}

/// A catalog VIP6/name is an identity selector, never a literal UDP route.
/// Prefer its explicitly scoped link-local bearer, then use the same signed
/// discovery and NAN wake sequence as flash when association is unavailable.
fn run_catalog_target_service(arguments: &[String], profile: &DeviceProfile) -> Result<(), String> {
    let name = profile.name.as_deref().unwrap_or("catalog-device");
    let (mut command_arguments, selected_bearers) = split_catalog_bearers(arguments)?;
    let uart_path = if selected_bearers
        .as_ref()
        .is_some_and(|bearers| bearers.iter().any(|bearer| bearer == "uart"))
    {
        Some(
            profile
                .serial_path()?
                .ok_or_else(|| format!("device {name:?} has no serial path for --bearer uart"))?,
        )
    } else {
        None
    };
    let use_udp = selected_bearers
        .as_ref()
        .is_none_or(|bearers| bearers.iter().any(|bearer| bearer == "udp"));
    if !use_udp {
        let path = uart_path
            .as_ref()
            .ok_or_else(|| format!("device {name:?} has no selected bearer"))?;
        command_arguments[0] = path.display().to_string();
        append_catalog_uart_baud(&mut command_arguments, profile);
        return run_serial_stream_command(&command_arguments);
    }
    if let Some(path) = &uart_path {
        command_arguments.push("--uart-bearer".into());
        command_arguments.push(path.display().to_string());
        if let Some(baud) = profile.uart_baud {
            command_arguments.push("--uart-baud".into());
            command_arguments.push(baud.to_string());
        }
    }
    if let Some(peer) = catalog_udp6_peer(profile)? {
        match direct_discovery_announce(peer) {
            Ok((_, announce)) if catalog_profile_matches_announce(profile, &announce) => {
                println!("dmesh_catalog_udp6_association name={name} peer={peer} associated=true");
                let mut udp_arguments = command_arguments;
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
    let mut udp_arguments = command_arguments;
    udp_arguments[0] = format!("udp://{peer}");
    run_udp_service_client(&udp_arguments)
}

fn split_catalog_bearers(
    arguments: &[String],
) -> Result<(Vec<String>, Option<Vec<String>>), String> {
    let mut retained = Vec::with_capacity(arguments.len());
    let mut selected = Vec::new();
    let mut index = 0;
    while index < arguments.len() {
        if arguments[index] == "--bearer" {
            let value = arguments.get(index + 1).ok_or("missing --bearer value")?;
            for bearer in value
                .split(',')
                .map(str::trim)
                .filter(|bearer| !bearer.is_empty())
            {
                if !matches!(bearer, "udp" | "uart" | "espnow") {
                    return Err(format!(
                        "unknown bearer {bearer:?}; expected udp, uart, or espnow"
                    ));
                }
                if selected.iter().any(|existing| existing == bearer) {
                    return Err(format!("duplicate --bearer {bearer}"));
                }
                selected.push(bearer.to_owned());
            }
            index += 2;
        } else {
            retained.push(arguments[index].clone());
            index += 1;
        }
    }
    if selected.contains(&"espnow".to_owned()) {
        return Err("ESP-NOW is owned by the supervised lmesh node; direct dmesh-cli bearer selection currently supports UDP and UART".into());
    }
    Ok((retained, (!selected.is_empty()).then_some(selected)))
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
        || profile
            .mac
            .is_some_and(|mac| address.is_some_and(|address| link_local_matches_mac(address, mac)))
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
        restore_sleepy: profile.sleepy,
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

/// A stable operator-facing node identity read from the node records.
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
    let mut entries = Vec::new();
    for node in crate::device::store().list()? {
        let name = node.name.clone().unwrap_or_else(|| node.device_id.clone());
        let Some(value) = node.vip6.as_deref() else {
            continue;
        };
        let vip6 = value
            .parse::<Ipv6Addr>()
            .map_err(|error| format!("node {name:?} has invalid vip6 {value:?}: {error}"))?;
        if vip6.octets()[0] != 0xfc {
            return Err(format!("node {name:?} has vip6 outside fc00::/8: {vip6}"));
        }
        entries.push(CatalogVip6 {
            name,
            vip6,
            node: hex_encode(&vip6.octets()[8..]),
            mac: node.mac,
        });
    }
    if entries.is_empty() {
        return Err(format!(
            "no node records with a vip6 in {} (expected fc00::/8); run `dmesh-cli devices sync`",
            crate::device::store()
                .directories()
                .iter()
                .map(|path| path.display().to_string())
                .collect::<Vec<_>>()
                .join(":")
        ));
    }
    Ok(entries)
}

/// Validate the node records against multicast presence. A VIP6 is an overlay
/// identity, not a LAN route, so this must not attempt a raw UDP packet to the
/// VIP itself.
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
        return Err("no node record answered multicast discovery".into());
    }
    Ok(())
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

/// The radio MAC behind a direct peer's link-local address (EUI-64), when it has one.
fn mac_of_direct_peer(peer: &DiscoveredPeer) -> Option<[u8; 6]> {
    let address = peer
        .announce
        .sta_link_local_v6()
        .map(Ipv6Addr::from)
        .or_else(|| match peer.peer {
            SocketAddr::V6(address) => Some(*address.ip()),
            SocketAddr::V4(_) => None,
        })?;
    mac_from_eui64(address)
}

/// Record every node that answers multicast discovery with a valid signed identity: the persisted
/// part of its announce (identity, name, domain, type, port) and its radio MAC, merged into the node
/// directory without touching a paired node's secret. Dynamic facts are not written.
fn run_devices_sync(dry_run: bool) -> Result<(), String> {
    let store = crate::device::store();
    let reachable = multicast_discover_peers()?;
    let mut changed = 0usize;
    for peer in &reachable {
        let Some(record) = dmesh_server::device_record::DeviceRecord::from_announce(
            &peer.announce,
            mac_of_direct_peer(peer),
        ) else {
            continue;
        };
        println!(
            "dmesh_devices_sync name={} vip6={} node={} write={}",
            record.name.as_deref().unwrap_or("-"),
            record.vip6.as_deref().unwrap_or("-"),
            peer.node,
            !dry_run
        );
        if !dry_run {
            store.observe(&record)?;
        }
        changed += 1;
    }
    if changed == 0 {
        return Err("no node answered with a signed discovery identity; nothing recorded".into());
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
    if let Some(node) = target.node.as_deref() {
        return hex_encode(announce.device_id()).eq_ignore_ascii_case(node);
    }
    target.mac.is_some_and(|mac| {
        announce
            .udp_link_local_v6()
            .or_else(|| announce.sta_link_local_v6())
            .is_some_and(|address| link_local_matches_mac(Ipv6Addr::from(address), mac))
    })
}

fn link_local_matches_mac(address: Ipv6Addr, mac: [u8; 6]) -> bool {
    let octets = address.octets();
    octets[..8] == [0xfe, 0x80, 0, 0, 0, 0, 0, 0]
        && octets[8] == (mac[0] ^ 0x02)
        && octets[9] == mac[1]
        && octets[10] == mac[2]
        && octets[11] == 0xff
        && octets[12] == 0xfe
        && octets[13] == mac[3]
        && octets[14] == mac[4]
        && octets[15] == mac[5]
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
    dmesh_server::discovery::discover_multicast_ipv6().map(|discovered| {
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

/// Exchange one direct record from the fixed dmesh-cli UDP source port.
/// Keeping this tuple stable is deliberate: relay.pair binds its reverse path
/// to it, while independent dmesh-cli invocations can reuse that binding.
/// Execute a relay administration record on a normal QUIC stream. Relay
/// setup is never part of the direct-message allowlist.
pub(crate) fn exchange_udp_stream_record(
    peer: SocketAddr,
    record: &[u8],
) -> Result<Vec<u8>, String> {
    let runtime = tokio::runtime::Runtime::new().map_err(|error| error.to_string())?;
    runtime
        .block_on(async {
            crate::node_client::request_udp(
                udp_bind_for_peer(peer),
                peer,
                record,
                Duration::from_secs(3),
            )
            .await
        })
        .map(|response| response.bytes)
}

#[cfg(test)]
mod tests {
    use super::{
        FlashTarget, flash_target_matches_announce, parse_serial_stream_arguments,
        probe_request_timeout, split_catalog_bearers,
    };
    use std::time::Duration;

    #[test]
    fn catalog_bearer_selection_accepts_udp_and_uart_together() {
        let args = [
            "status".to_owned(),
            "--bearer".to_owned(),
            "udp,uart".to_owned(),
            "verbose=true".to_owned(),
        ];
        assert_eq!(
            split_catalog_bearers(&args),
            Ok((
                vec!["status".to_owned(), "verbose=true".to_owned()],
                Some(vec!["udp".to_owned(), "uart".to_owned()]),
            ))
        );
    }

    #[test]
    fn serial_stream_timeout_and_baud_are_not_forwarded_as_service_fields() {
        let args = [
            "status".to_owned(),
            "verbose=true".to_owned(),
            "--timeout-secs".to_owned(),
            "10".to_owned(),
            "--baud".to_owned(),
            "115200".to_owned(),
        ];
        assert_eq!(
            parse_serial_stream_arguments(&args),
            Ok((
                vec!["status".to_owned(), "verbose=true".to_owned()],
                Some(115_200),
                Duration::from_secs(10),
                true,
                Duration::ZERO,
                None,
            ))
        );
    }

    #[test]
    fn serial_stream_linger_and_repeat_options_are_not_forwarded() {
        let args = [
            "status".to_owned(),
            "--linger-secs".to_owned(),
            "5".to_owned(),
            "--repeat-secs".to_owned(),
            "2".to_owned(),
        ];
        assert_eq!(
            parse_serial_stream_arguments(&args),
            Ok((
                vec!["status".to_owned()],
                None,
                Duration::from_secs(3),
                false,
                Duration::from_secs(5),
                Some(Duration::from_secs(2)),
            ))
        );
    }

    #[test]
    fn serial_stream_rejects_zero_repeat_interval() {
        let args = [
            "status".to_owned(),
            "--repeat-secs".to_owned(),
            "0".to_owned(),
        ];
        assert_eq!(
            parse_serial_stream_arguments(&args),
            Err("--repeat-secs must be greater than zero".to_owned())
        );
    }

    #[test]
    fn serial_stream_repeat_is_limited_to_read_only_commands() {
        let args = [
            "transport.set".to_owned(),
            "--repeat-secs".to_owned(),
            "1".to_owned(),
        ];
        assert_eq!(
            parse_serial_stream_arguments(&args),
            Err(
                "--repeat-secs is limited to the read-only status and services commands".to_owned()
            )
        );
    }

    #[test]
    fn probe_timeout_scales_for_large_uart_workloads() {
        assert_eq!(probe_request_timeout(64 * 1024), Duration::from_secs(45));
        assert_eq!(probe_request_timeout(1024 * 1024), Duration::from_secs(128));
        assert_eq!(
            probe_request_timeout(64 * 1024 * 1024),
            Duration::from_secs(8192)
        );
    }

    #[test]
    fn mac_only_catalog_target_matches_its_discovered_link_local_address() {
        let mac = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];
        let mut announce = dmesh_server::announce::Announce::discovery([1; 16], 16, 1);
        announce.set_sta_link_local_v6([
            0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x00, 0x11, 0x22, 0xff, 0xfe, 0x33, 0x44, 0x55,
        ]);
        let target = FlashTarget {
            restore_sleepy: false,
            description: "node-under-test".into(),
            node: None,
            mac: Some(mac),
            known_peer: None,
        };
        assert!(flash_target_matches_announce(&announce, &target));
        assert!(!flash_target_matches_announce(
            &announce,
            &FlashTarget {
                mac: Some([0x02, 0x11, 0x22, 0x33, 0x44, 0x56]),
                ..target
            }
        ));
    }
}
