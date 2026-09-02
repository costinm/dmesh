//! Direct serial L2 adapter for the standalone `dmesh-cli` host client.
//!
//! This belongs to `dmesh-cli`, not Recovery or firmware. It
//! opens an explicitly supplied serial port with no managed forward. The
//! optional initial record is opaque: commands/logs remain higher-level
//! transport services and this adapter never decodes them.

use crate::{
    device::{load_device, resolve_udp_peer},
    l2::UartEgressPacer,
    schema::{
        FirmwareSchema, encode_direct_command, encode_direct_command_with_id, render_device_record,
    },
};
use dmesh_server::{
    direct_iperf::{IperfRequest, decode_iperf_result, encode_iperf_request},
    iperf::{IperfServicePlan, decode_iperf_service_request},
    uart::{UartIngress, classify_uart_payload, encode_uart_datagram},
};
use quic_lite::{
    ConnectionLimits, EndpointState, Role, ShortHeader, StreamFrame, TransportPacket,
    iperf::IperfRun,
    path_bridge::{PathBridge, PathBridgeAction},
};
use serde::Deserialize;
use std::{
    collections::VecDeque,
    env,
    fs::{File, OpenOptions},
    io::{BufRead, BufReader, ErrorKind, Read, Write},
    net::{Ipv6Addr, SocketAddr, SocketAddrV6, UdpSocket},
    os::fd::AsRawFd,
    os::unix::{
        fs::{FileTypeExt, OpenOptionsExt},
        net::{UnixListener, UnixStream},
    },
    path::Path,
    sync::Arc,
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use uart_codec::codec::{Decoder, encode_payload};

/// A bounded observation made by a persistent physical-UART device session.
///
/// The serial bearer is shared by command/reply traffic, normal QUIC-lite
/// packets, and the small out-of-band boot/crash diagnostic channel.  Keeping
/// these observations together lets a hardware test retain the last useful
/// context when a later operation fails, without treating text as protocol.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DeviceSessionEvent {
    DirectRecord(Vec<u8>),
    TransportPacket(Vec<u8>),
    Diagnostic(String),
}

/// One explicitly owned UART connection to a firmware device.
///
/// A suite opens this once before its cases and closes it after all cases.
/// It deliberately does not implement an application protocol: callers send
/// a direct CBOR command or a QUIC-lite packet and inspect the bounded event
/// history through the same L2 owner.
pub struct DeviceSession {
    path: String,
    serial: File,
    decoder: Decoder,
    text_tap: RawTextTap,
    history: VecDeque<DeviceSessionEvent>,
    history_limit: usize,
    fatal_diagnostic: Option<String>,
}

impl DeviceSession {
    pub const DEFAULT_HISTORY_LIMIT: usize = 64;

    /// Open one non-controlling, nonblocking UART owner.  Startup backlog is
    /// discarded before the session starts so a previous CLI invocation cannot
    /// be mistaken for a callback from the current test case.
    pub fn open(path: impl Into<String>, baud: Option<u32>) -> Result<Self, String> {
        let path = path.into();
        let mut serial = open_serial(&path)?;
        configure_serial(&serial, baud)?;
        let mut stale = [0u8; 256];
        loop {
            match serial.read(&mut stale) {
                Ok(used) if used != 0 => {}
                Ok(_) => break,
                Err(ref error) if error.kind() == ErrorKind::WouldBlock => break,
                Err(error) => return Err(error.to_string()),
            }
        }
        Ok(Self {
            path,
            serial,
            decoder: Decoder::with_max(quic_lite::DEFAULT_MAX_DATAGRAM_SIZE + 1),
            text_tap: RawTextTap::default(),
            history: VecDeque::with_capacity(Self::DEFAULT_HISTORY_LIMIT),
            history_limit: Self::DEFAULT_HISTORY_LIMIT,
            fatal_diagnostic: None,
        })
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn set_history_limit(&mut self, limit: usize) {
        self.history_limit = limit.max(1);
        while self.history.len() > self.history_limit {
            self.history.pop_front();
        }
    }

    /// Discard delayed boot output before a caller starts its first operation.
    ///
    /// This is for a USB-pair fixture immediately after it obtains exclusive
    /// ownership of a CP210x port.  Some boards reset when the previous test
    /// process closes its last port owner; their ROM/ESP-IDF text can arrive
    /// after the next process has opened the same device.  Waiting and
    /// draining here keeps that *pre-test* reset from being attributed to the
    /// first radio operation.  It never runs during a probe: after the caller
    /// sends any record, [`poll_until`] retains diagnostics and treats a reset
    /// as a real failure.
    pub fn discard_startup_backlog(&mut self, settle: Duration) -> Result<(), String> {
        let deadline = Instant::now() + settle;
        let mut discarded = [0u8; quic_lite::DEFAULT_MAX_DATAGRAM_SIZE + 1];
        while Instant::now() < deadline {
            match self.serial.read(&mut discarded) {
                Ok(_) => {}
                Err(ref error) if error.kind() == ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(2));
                }
                Err(error) => return Err(error.to_string()),
            }
        }
        // A reset can split a PPP delimiter across the drain boundary.  Start
        // the actual test with no partial binary frame, diagnostic line, or
        // stale fatal marker from the preceding serial owner.
        self.decoder = Decoder::with_max(quic_lite::DEFAULT_MAX_DATAGRAM_SIZE + 1);
        self.text_tap = RawTextTap::default();
        self.history.clear();
        self.fatal_diagnostic = None;
        Ok(())
    }

    pub fn recent_events(&self) -> impl ExactSizeIterator<Item = &DeviceSessionEvent> {
        self.history.iter()
    }

    pub fn assert_healthy(&self) -> Result<(), String> {
        self.fatal_diagnostic.as_ref().map_or(Ok(()), |diagnostic| {
            // The first marker makes the session unhealthy, but its position
            // matters. ESP-IDF prints the panic/reset cause, register dump,
            // and backtrace footer as distinct UART lines. Keep the ordered
            // diagnostic window surrounding the *first* fatal line so a
            // long-running bearer test can distinguish a device reset from
            // an unrelated later boot banner. This is diagnostics only; the
            // serial session still stops at the first fatal condition.
            let diagnostics = self
                .history
                .iter()
                .filter_map(|event| match event {
                    DeviceSessionEvent::Diagnostic(line) => Some(line.as_str()),
                    _ => None,
                })
                .collect::<Vec<_>>();
            let first_fatal = diagnostics
                .iter()
                .position(|line| is_fatal_diagnostic(line))
                .unwrap_or(0);
            let context_start = first_fatal.saturating_sub(12);
            let context_end = (first_fatal + 33).min(diagnostics.len());
            let context = diagnostics[context_start..context_end].to_vec();
            Err(format!(
                "device {} reported fatal diagnostic={diagnostic:?}; ordered UART diagnostics around first fatal={context:?}",
                self.path,
            ))
        })
    }

    /// Send a PPP-framed DCID-zero direct record. The UART PPP layer remains
    /// physical framing only; control receives the same short header used by
    /// the UDP direct-record plane.
    pub fn send_direct_record(&mut self, record: &[u8]) -> Result<(), String> {
        if record.is_empty() || record.len() > quic_lite::DEFAULT_MAX_DATAGRAM_SIZE - 6 {
            return Err("direct record is empty or exceeds the UART MTU".into());
        }
        self.assert_healthy()?;
        let mut packet = [0u8; quic_lite::DEFAULT_MAX_DATAGRAM_SIZE];
        let used = quic_lite::encode_direct_packet(0, record, &mut packet)
            .map_err(|error| format!("UART direct record: {error:?}"))?;
        send_ppp(&mut self.serial, &packet[..used])
    }

    /// Poll the one UART owner and append all received observations to its
    /// bounded history. Returns the number of complete PPP records received.
    pub fn poll(&mut self, timeout: Duration) -> Result<usize, String> {
        self.poll_until(timeout, |_| false)
            .map(|(_, records)| records)
    }

    /// Poll until a caller-selected decoded event arrives or the bounded
    /// interval expires.  This lets an E2E suite retain one UART owner while
    /// correlating a real response instead of sleeping for every command.
    /// The callback sees the exact event retained in history, so no
    /// UART-specific response protocol is introduced here.
    pub fn poll_until<F>(
        &mut self,
        timeout: Duration,
        mut matched: F,
    ) -> Result<(bool, usize), String>
    where
        F: FnMut(&DeviceSessionEvent) -> bool,
    {
        let deadline = Instant::now() + timeout;
        let mut buffer = [0u8; quic_lite::DEFAULT_MAX_DATAGRAM_SIZE + 1];
        let mut records = 0;
        while Instant::now() < deadline {
            match self.serial.read(&mut buffer) {
                Ok(used) if used != 0 => {
                    for line in self.text_tap.push(&buffer[..used]) {
                        if is_fatal_diagnostic(&line) {
                            self.fatal_diagnostic.get_or_insert_with(|| line.clone());
                        }
                        self.push_event(DeviceSessionEvent::Diagnostic(line));
                    }
                    for frame in self
                        .decoder
                        .push(&buffer[..used])
                        .map_err(|error| error.to_string())?
                    {
                        records += 1;
                        match classify_uart_payload(&frame) {
                            Ok(UartIngress::DirectRecord(record)) => {
                                let event = DeviceSessionEvent::DirectRecord(record.to_vec());
                                let is_match = matched(&event);
                                self.push_event(event);
                                if is_match {
                                    self.assert_healthy()?;
                                    return Ok((true, records));
                                }
                            }
                            Ok(UartIngress::Transport(packet)) => {
                                let event = DeviceSessionEvent::TransportPacket(packet.to_vec());
                                let is_match = matched(&event);
                                self.push_event(event);
                                if is_match {
                                    self.assert_healthy()?;
                                    return Ok((true, records));
                                }
                            }
                            Err(_) => {}
                        }
                    }
                }
                Ok(_) => {
                    thread::sleep(Duration::from_millis(2));
                }
                Err(ref error) if error.kind() == ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(2));
                }
                Err(error) => return Err(error.to_string()),
            }
        }
        self.assert_healthy()?;
        Ok((false, records))
    }

    /// Send a direct record and retain callbacks for the requested interval.
    /// Callers select/correlate replies from `recent_events`; raw records do
    /// not have a universal response envelope to manufacture here.
    pub fn request_direct_record(
        &mut self,
        record: &[u8],
        timeout: Duration,
    ) -> Result<(), String> {
        self.send_direct_record(record)?;
        self.poll(timeout)?;
        Ok(())
    }

    /// Send one direct record and stop once its caller-defined response is
    /// observed.  The generic predicate keeps raw CBOR, stream packets, and
    /// future schema-defined diagnostics on the same UART L2 path.
    pub fn request_direct_record_until<F>(
        &mut self,
        record: &[u8],
        timeout: Duration,
        matched: F,
    ) -> Result<bool, String>
    where
        F: FnMut(&DeviceSessionEvent) -> bool,
    {
        self.send_direct_record(record)?;
        self.poll_until(timeout, matched)
            .map(|(matched, _)| matched)
    }

    fn push_event(&mut self, event: DeviceSessionEvent) {
        if self.history.len() == self.history_limit {
            self.history.pop_front();
        }
        self.history.push_back(event);
    }
}

fn is_fatal_diagnostic(line: &str) -> bool {
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

/// Bearer-neutral path policy accepted by the host CLI and the future
/// `lmesh-wifi` egress handler. The policy chooses among registered paths;
/// it never changes the command, IPERF, or log-watch stream protocol.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientPathPolicy {
    HighestMeasuredSpeed,
    Aggregate,
    Udp,
    Uart,
    UartSpillover,
}

impl ClientPathPolicy {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "aggregate" => Some(Self::Aggregate),
            "fastest" => Some(Self::HighestMeasuredSpeed),
            "udp" => Some(Self::Udp),
            "uart" => Some(Self::Uart),
            "spill" | "uart-spill-udp" => Some(Self::UartSpillover),
            _ => None,
        }
    }

    /// Compact policy value shared with the firmware transport profile.
    pub const fn wire(self) -> u8 {
        match self {
            Self::HighestMeasuredSpeed => 0,
            Self::Udp => 1,
            Self::Uart => 2,
            Self::UartSpillover => 3,
            Self::Aggregate => 4,
        }
    }
}

fn usage() -> ! {
    eprintln!(
        "usage: dmesh-cli SERIAL|DEVICE --reset\n       dmesh-cli SERIAL|DEVICE --watch [--reset] [--interactive] [--baud PHYSICAL_UART_BAUD] [--timeout-secs N]\n       dmesh-cli SERIAL|DEVICE [--command TEXT | --direct-hex HEX] [--timeout-secs N]\n       dmesh-cli SERIAL|DEVICE [--services | --service status|metrics|events|services|log-watch|control | --service-tag 0..255] [--body-hex HEX] [--log-records 1..64] [--iperf-bytes N]\n       dmesh-cli uds:///run/mesh/lmesh[-wifi]/mesh.sock|lmesh://lmesh[-wifi] --method METHOD [--data JSON] [--to NODE]\n       dmesh-cli SERIAL|DEVICE BOOTSTRAP_BIND BACKEND [--baud PHYSICAL_UART_BAUD] [--bearer uart|udp|aggregate|spill] [--command TEXT | --direct-hex HEX | --iperf-bytes N] [--parallel-streams 1..4] [--high-priority-bytes N] [--low-priority-bytes N] [--target-bps N] [--timeout-secs N]\n       dmesh-cli udp://HOST:PORT|IP|DEVICE --udp-probe\n       dmesh-cli udp://HOST:PORT|IP|DEVICE [--services | --service status|metrics|events|services|log-watch|control | --service-tag 0..255] [--body-hex HEX] [--log-records 1..64] [--iperf-bytes N] [--socket PATH]"
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

fn hex_encode(value: &[u8]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
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
fn configure_serial(file: &File, baud: Option<u32>) -> Result<(), String> {
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
fn open_serial(path: &str) -> Result<File, String> {
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

fn send_ppp(serial: &mut File, payload: &[u8]) -> Result<(), String> {
    let wire = encode_payload(payload, quic_lite::DEFAULT_MAX_DATAGRAM_SIZE + 1)
        .map_err(|error| error.to_string())?;
    serial.write_all(&wire).map_err(|error| error.to_string())
}

/// Run the standalone IPERF-compatible client using process arguments.
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
        .is_some_and(|target| proxy_socket_target(target).is_some())
    {
        return run_lmesh_proxy_client(&arguments);
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
        }
        return run_serial_watch(&arguments);
    }
    // Raw records are an intentional, bounded physical-bearer lane for
    // schema-defined bootstrap/control and diagnostics.  An explicit UDP URI
    // selects the companion's DCID-zero control lane; a named profile remains
    // serial-first so a routine local command cannot silently use the radio.
    if arguments
        .get(1)
        .is_some_and(|argument| matches!(argument.as_str(), "--direct-hex" | "--command"))
    {
        let target = arguments.first().cloned().unwrap_or_else(|| usage());
        if target.starts_with("udp://") {
            return run_udp_direct_record(&arguments);
        }
        if !target.starts_with('/') {
            if target.contains(':') {
                return Err(
                    "--command requires an explicit udp:// target, serial path, or device profile"
                        .into(),
                );
            }
            let profile = load_device(&target)?;
            let serial = profile
                .serial_path()?
                .ok_or_else(|| format!("device {target:?} has no serial_id for --command"))?;
            arguments[0] = serial.display().to_string();
        }
        return run_serial_direct_record(&arguments);
    }
    if let Some(target) = arguments
        .first()
        .cloned()
        .filter(|target| !target.starts_with("udp://"))
    {
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
    // A serial service probe is a direct QUIC-lite client, not the older
    // UART-to-UDP bridge mode below.  It is the smallest end-to-end check for
    // the shared firmware dispatcher and lets a failed UDP bearer be isolated
    // without reintroducing a command-specific UART protocol.
    if arguments.get(1).is_some_and(|argument| {
        matches!(
            argument.as_str(),
            "--services" | "--log-watch" | "--service" | "--service-tag" | "--iperf-bytes"
        )
    }) {
        return run_serial_service_probe(&arguments);
    }
    let mut args = arguments.into_iter();
    let path = args.next().unwrap_or_else(|| usage());
    let bootstrap = parse_udp_peer(&args.next().unwrap_or_else(|| usage()))?;
    let backend: SocketAddr = args
        .next()
        .unwrap_or_else(|| usage())
        .parse::<SocketAddr>()
        .map_err(|error| error.to_string())?;
    if backend.ip().is_unspecified() {
        return Err(
            "BACKEND must be a routable host address (for example 10.78.0.1:3340), not 0.0.0.0"
                .into(),
        );
    }
    let mut direct = None;
    let mut iperf_bytes = None;
    let mut parallel_streams = 1u8;
    let mut high_priority_bytes = 0u32;
    let mut target_bps = None;
    let mut low_priority_bytes = 0u32;
    let mut iperf_run_id = None;
    let mut iperf_expected_bytes = None;
    let mut server_control = None;
    let mut timeout = Duration::from_secs(90);
    // No `--baud` means packetized USB serial (the e6 USB-JTAG case), which
    // is governed by actual driver backpressure rather than a fake 115200
    // 8N1 link.  A physical UART must opt in with `--baud`.
    let mut baud = None;
    // Host egress policy. Recovery retains its normal dynamic return-path
    // policy and merely receives complete packets on whichever bearer wins.
    let mut host_policy = ClientPathPolicy::Uart;
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--direct-hex" => direct = Some(hex(&args.next().unwrap_or_else(|| usage()))?),
            "--command" => {
                if direct.is_some() {
                    return Err("choose one of --command and --direct-hex".into());
                }
                let command = args.next().unwrap_or_else(|| usage());
                direct = Some(encode_direct_command(&command).map_err(|error| error.to_string())?);
            }
            "--iperf-bytes" => {
                iperf_bytes = Some(
                    args.next()
                        .unwrap_or_else(|| usage())
                        .parse::<u32>()
                        .map_err(|error| error.to_string())?,
                )
            }
            "--low-priority-bytes" => {
                low_priority_bytes = args
                    .next()
                    .unwrap_or_else(|| usage())
                    .parse::<u32>()
                    .map_err(|error| error.to_string())?
            }
            "--high-priority-bytes" => {
                high_priority_bytes = args
                    .next()
                    .unwrap_or_else(|| usage())
                    .parse::<u32>()
                    .map_err(|error| error.to_string())?
            }
            "--parallel-streams" => {
                parallel_streams = args
                    .next()
                    .unwrap_or_else(|| usage())
                    .parse::<u8>()
                    .map_err(|error| error.to_string())?;
                if !(1..=4).contains(&parallel_streams) {
                    return Err("--parallel-streams must be in 1..=4".into());
                }
            }
            "--target-bps" => {
                target_bps = Some(
                    args.next()
                        .unwrap_or_else(|| usage())
                        .parse::<u64>()
                        .map_err(|error| error.to_string())?,
                );
            }
            "--timeout-secs" => {
                timeout = Duration::from_secs(
                    args.next()
                        .unwrap_or_else(|| usage())
                        .parse::<u64>()
                        .map_err(|error| error.to_string())?,
                )
            }
            "--baud" => {
                baud = Some(
                    args.next()
                        .unwrap_or_else(|| usage())
                        .parse::<u32>()
                        .map_err(|error| error.to_string())?,
                )
            }
            "--bearer" => {
                host_policy = ClientPathPolicy::parse(&args.next().unwrap_or_else(|| usage()))
                    .ok_or("bearer must be uart, udp, aggregate, fastest, or spill")?;
            }
            _ => usage(),
        }
    }
    if direct.is_some() && iperf_bytes.is_some() {
        return Err("choose --iperf-bytes or one direct command record".into());
    }
    // The hardware benchmark is self-contained: this CLI owns the temporary
    // host server as well as the direct UART L2 adapter.  Ordinary bridge use
    // remains opaque and does not pull service semantics into the library.
    let server_runtime = iperf_bytes
        .map(|bytes| {
            let port = if host_policy == ClientPathPolicy::Udp {
                backend.port()
            } else {
                bootstrap.port()
            };
            let run_id = fresh_request_id() as u32;
            let mut request = IperfRequest::uart(port, bytes, run_id);
            request.parallel_streams = parallel_streams;
            request.high_priority_bytes = high_priority_bytes;
            request.low_priority_bytes = low_priority_bytes;
            if let Some(target_bps) = target_bps {
                if target_bps == 0 {
                    return Err("--target-bps must be nonzero".into());
                }
                request.pace_us = ((u64::from(request.packet_size) * 8_000_000)
                    .saturating_add(target_bps - 1)
                    / target_bps)
                    .min(1_000_000) as u32;
            }
            // The Recovery client must know which L2 carries its initial
            // OPEN. This is the same sender-selected policy the host bridge
            // uses for established packets; encoding `0` unconditionally
            // made a UART comparison bootstrap over UDP instead.
            request.path_policy = host_policy.wire();
            let mut packet = [0u8; 128];
            let used = encode_iperf_request(request, &mut packet)
                .ok_or("CBOR IPERF request encoding failed")?;
            direct = Some(packet[..used].to_vec());
            iperf_run_id = Some(run_id);
            iperf_expected_bytes = Some(
                u64::from(bytes)
                    .saturating_add(u64::from(high_priority_bytes))
                    .saturating_add(u64::from(low_priority_bytes)),
            );
            let runtime = tokio::runtime::Runtime::new().map_err(|error| error.to_string())?;
            let control = Arc::new(dmesh_server::udp::TransportControl::default());
            server_control = Some(control.clone());
            runtime.spawn(dmesh_server::udp::run(dmesh_server::udp::UdpConfig {
                bind: backend,
                artifact_root: std::path::PathBuf::from("target/flash"),
                control: Some(control),
                ..dmesh_server::udp::UdpConfig::default()
            }));
            Ok::<_, String>(runtime)
        })
        .transpose()?;
    if server_runtime.is_some() {
        thread::sleep(Duration::from_millis(100));
    }
    let socket = UdpSocket::bind(bootstrap).map_err(|error| error.to_string())?;
    socket
        .set_nonblocking(true)
        .map_err(|error| error.to_string())?;
    let mut serial = open_serial(&path)?;
    configure_serial(&serial, None)?;
    if let Some(record) = direct {
        send_ppp(&mut serial, &record)?;
    }

    let schema = FirmwareSchema::load();
    let mut bridge = PathBridge::default();
    let mut decoder = Decoder::with_max(quic_lite::DEFAULT_MAX_DATAGRAM_SIZE + 1);
    // A USB driver accepting a burst is not evidence that the device has
    // consumed it. Keep the normal initial transport flight outstanding until
    // validated packets return on this L2 path; that is actual receiver
    // feedback rather than a made-up USB baud rate. A physical UART gains its
    // own wire pacing from `--baud` as well.
    let mut egress = baud.map_or_else(
        || UartEgressPacer::unpaced(8),
        |baud| UartEgressPacer::new(baud, 8),
    );
    let mut buffer = [0u8; quic_lite::DEFAULT_MAX_DATAGRAM_SIZE + 1];
    let mut bootstrap_peer = None;
    let mut established_backend_packets = 0u64;
    let mut primary_packets = 0u64;
    let mut secondary_packets = 0u64;
    let started = Instant::now();
    let deadline = started + timeout;
    while Instant::now() < deadline {
        // A UART is a slow, bounded datagram bearer. Do not drain a faster
        // backend into a full serial queue: leave data in the socket so
        // QUIC-lite ACK/credit applies pressure before local loss occurs.
        // Keep receiving backend packets when the UART queue is full.  For
        // `uart-spill-udp` that fullness is the signal to send the packet on
        // the bootstrap/UDP path; gating this recv behind UART capacity would
        // turn spillover into an artificial connection-wide stall.
        // Explicit UART is a comparison mode: retain socket backpressure
        // rather than changing the selected bearer. Only the spill policy is
        // allowed to keep receiving once UART reports a full local queue.
        if host_policy != ClientPathPolicy::Uart || egress.has_capacity() {
            match socket.recv_from(&mut buffer) {
                Ok((used, peer)) if peer == backend => {
                    let uart = match host_policy {
                        // Keep most traffic on the faster UDP bearer while
                        // periodically exercising the UART path as well.
                        ClientPathPolicy::HighestMeasuredSpeed => {
                            established_backend_packets =
                                established_backend_packets.saturating_add(1);
                            established_backend_packets % 32 == 0
                        }
                        // Fill a bounded UART egress queue; excess server
                        // traffic continues over UDP instead of stalling the
                        // shared connection behind UART wire time.
                        ClientPathPolicy::Aggregate | ClientPathPolicy::UartSpillover => {
                            quic_lite::PathCapacity::new(egress.occupied(), egress.capacity())
                                .has_capacity()
                        }
                        ClientPathPolicy::Udp => false,
                        ClientPathPolicy::Uart => true,
                    };
                    match bridge.on_backend_datagram_on_path(&buffer[..used], uart) {
                        PathBridgeAction::ToBootstrapPath(packet) => {
                            primary_packets = primary_packets.saturating_add(1);
                            if let Some(peer) = bootstrap_peer {
                                socket
                                    .send_to(packet, peer)
                                    .map_err(|error| error.to_string())?;
                            }
                        }
                        PathBridgeAction::ToSecondaryPath(packet) => {
                            secondary_packets = secondary_packets.saturating_add(1);
                            let mut payload = [0u8; quic_lite::DEFAULT_MAX_DATAGRAM_SIZE + 1];
                            let used = encode_uart_datagram(packet, &mut payload)
                                .ok_or("UART packet too large")?;
                            let wire = encode_payload(
                                &payload[..used],
                                quic_lite::DEFAULT_MAX_DATAGRAM_SIZE + 1,
                            )
                            .map_err(|error| error.to_string())?;
                            debug_assert!(egress.enqueue(wire));
                        }
                        _ => {}
                    }
                }
                Ok((used, peer)) => {
                    bootstrap_peer = Some(peer);
                    if let PathBridgeAction::ToBackend(packet) =
                        bridge.on_bootstrap_path(&buffer[..used])
                    {
                        socket
                            .send_to(packet, backend)
                            .map_err(|error| error.to_string())?;
                    }
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => {}
                Err(error) => return Err(error.to_string()),
            }
        }
        match serial.read(&mut buffer) {
            Ok(used) if used != 0 => {
                for record in decoder
                    .push(&buffer[..used])
                    .map_err(|error| error.to_string())?
                {
                    match classify_uart_payload(&record) {
                        Ok(UartIngress::Transport(packet)) => {
                            egress.on_path_feedback();
                            if let PathBridgeAction::ToBackend(packet) =
                                bridge.on_secondary_path(packet)
                            {
                                socket
                                    .send_to(packet, backend)
                                    .map_err(|error| error.to_string())?;
                            }
                        }
                        Ok(UartIngress::DirectRecord(record)) => {
                            eprintln!(
                                "dmesh_device_record bearer=uart bytes={} {}",
                                record.len(),
                                render_device_record(&schema, record)
                            );
                            if let Some(run_id) = iperf_run_id {
                                if let Some(result) = decode_iperf_result(record)
                                    .filter(|result| result.run_id == run_id)
                                {
                                    let expected = iperf_expected_bytes.unwrap_or(result.bytes);
                                    println!(
                                        "dmesh_cli_iperf_result bearer={} run_id={run_id} bytes={} normal_bytes={} high_bytes={} low_bytes={} elapsed_us={} bps={} primary_packets={} secondary_packets={}",
                                        bearer_name(host_policy),
                                        result.bytes,
                                        result.normal_priority_bytes,
                                        result.high_priority_bytes,
                                        result.low_priority_bytes,
                                        result.elapsed_us,
                                        result.bits_per_second(),
                                        primary_packets,
                                        secondary_packets,
                                    );
                                    if result.bytes != expected {
                                        return Err(format!(
                                            "IPERF incomplete: received {} of {expected} bytes",
                                            result.bytes
                                        ));
                                    }
                                    return Ok(());
                                }
                            }
                        }
                        Err(_) => {}
                    }
                }
            }
            Ok(_) => {}
            Err(error) if error.kind() == ErrorKind::WouldBlock => {}
            Err(error) => return Err(error.to_string()),
        }
        let now_us = Instant::now().duration_since(started).as_micros() as u64;
        if let Some(wire) = egress.take_ready(now_us) {
            match serial.write(&wire) {
                Ok(written) if written == wire.len() => egress.completed_write(wire.len(), now_us),
                Ok(written) if written != 0 => egress.retry_front(wire[written..].to_vec(), now_us),
                Ok(_) => egress.retry_front(wire, now_us),
                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                    egress.retry_front(wire, now_us)
                }
                Err(error) => return Err(error.to_string()),
            }
        }
        // Do not turn this packetized USB L2 into a millisecond-paced UART.
        // `egress.has_capacity()` is the actual bounded receiver feedback;
        // yield only to avoid monopolizing a host core while both descriptors
        // are empty.
        thread::yield_now();
    }
    if let (Some(run_id), Some(control)) = (iperf_run_id, server_control) {
        println!(
            "dmesh_cli_iperf_timeout bearer={} run_id={run_id} server_stats={:?}",
            bearer_name(host_policy),
            control.server_stats()
        );
    }
    Err("UART L2 bridge timed out".into())
}

/// Resolve a supervised host-radio control endpoint.  This is intentionally a
/// control-plane client, not a serial forwarder: `lmesh-wifi` or `lmesh` owns
/// NOW/NAN selection and returns its receiver-side counters in the response.
fn proxy_socket_target(target: &str) -> Option<&str> {
    match target {
        "lmesh://lmesh-wifi" => Some("/run/mesh/lmesh-wifi/mesh.sock"),
        "lmesh://lmesh" => Some("/run/mesh/lmesh/mesh.sock"),
        _ => target.strip_prefix("uds://"),
    }
}

fn proxy_request(
    method: &str,
    data: serde_json::Value,
    to: Option<String>,
) -> Result<serde_json::Value, String> {
    let mut data = data;
    if !data.is_object() {
        return Err("--data must be a JSON object".into());
    }
    let object = data.as_object_mut().expect("checked object");
    object.insert(
        "id".into(),
        serde_json::json!(format!("dmesh-cli-{}", fresh_request_id())),
    );
    object.insert(
        "method".into(),
        serde_json::Value::String(method.to_owned()),
    );
    if let Some(to) = to {
        object.insert("to".into(), serde_json::Value::String(to));
    }
    Ok(data)
}

/// Invoke one existing reviewed lmesh method over its JSONL UDS.  The CLI does
/// not interpret a successful host TX as peer success; it prints the service's
/// complete result, including NOW response/counter fields where applicable.
fn run_lmesh_proxy_client(arguments: &[String]) -> Result<(), String> {
    let target = arguments.first().ok_or("missing proxy target")?;
    let socket = proxy_socket_target(target).ok_or("invalid proxy target")?;
    let mut method = None;
    let mut to = None;
    let mut data = serde_json::json!({});
    let mut index = 1;
    while index < arguments.len() {
        match arguments[index].as_str() {
            "--method" => {
                index += 1;
                method = Some(
                    arguments
                        .get(index)
                        .ok_or("missing --method value")?
                        .clone(),
                );
            }
            "--data" => {
                index += 1;
                data = serde_json::from_str(arguments.get(index).ok_or("missing --data value")?)
                    .map_err(|error| format!("invalid --data JSON: {error}"))?;
            }
            "--to" => {
                index += 1;
                to = Some(arguments.get(index).ok_or("missing --to value")?.clone());
            }
            unknown => return Err(format!("unknown proxy argument {unknown}")),
        }
        index += 1;
    }
    let method = method.ok_or("proxy requests require --method METHOD")?;
    let request = proxy_request(&method, data, to)?;
    let mut stream =
        UnixStream::connect(socket).map_err(|error| format!("connect {socket}: {error}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|error| error.to_string())?;
    writeln!(stream, "{request}").map_err(|error| error.to_string())?;
    stream.flush().map_err(|error| error.to_string())?;
    let mut response = String::new();
    BufReader::new(stream)
        .read_line(&mut response)
        .map_err(|error| error.to_string())?;
    if response.trim().is_empty() {
        return Err(format!("proxy {socket} returned no response for {method}"));
    }
    println!(
        "dmesh_cli_proxy_response endpoint={socket} method={method} {}",
        response.trim()
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

fn send_uart_transport(serial: &mut File, packet: &[u8]) -> Result<(), String> {
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
struct RawTextTap {
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

    fn push(&mut self, bytes: &[u8]) -> Vec<String> {
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
fn run_serial_service_probe(arguments: &[String]) -> Result<(), String> {
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
    let (service, body) = parse_service_request(&service_arguments)?;
    let path = arguments.first().ok_or("missing serial path")?;
    let mut serial = open_serial(path)?;
    configure_serial(&serial, baud)?;
    run_serial_service_request(&mut serial, path, service, &body)
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
        Some("--command") => {
            index += 1;
            encode_direct_command_with_id(
                arguments.get(index).ok_or("missing --command value")?,
                fresh_request_id(),
            )
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
    let used = quic_lite::encode_direct_packet(0, &record, &mut packet)
        .map_err(|error| format!("UART direct record: {error:?}"))?;
    send_ppp(&mut serial, &packet[..used])?;
    println!("dmesh_cli_raw_sent target={path} bytes={}", record.len());

    let schema = FirmwareSchema::load();
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
                    if let Ok(UartIngress::DirectRecord(record)) = classify_uart_payload(&frame) {
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
fn run_serial_service_request(
    serial: &mut File,
    path: &str,
    service: u8,
    body: &[u8],
) -> Result<(), String> {
    // Service requests can overlap normal ESP-IDF radio diagnostics. Apply
    // the same bounded sniffer-teardown filter as `--watch`, otherwise a
    // useful service response is buried under the identical idle line.
    let mut text_filter = WatchTextFilter::default();
    let cid = fresh_connection_id()?;
    let limits = ConnectionLimits::default();
    let mut open = [0u8; quic_lite::DEFAULT_MAX_DATAGRAM_SIZE];
    let open_used = quic_lite::encode_bootstrap_open_packet_with_limits(cid, 0, limits, &mut open)
        .map_err(|error| format!("UART bootstrap OPEN: {error:?}"))?;
    send_uart_transport(serial, &open[..open_used])?;

    let mut decoder = Decoder::with_max(quic_lite::DEFAULT_MAX_DATAGRAM_SIZE + 1);
    let mut buffer = [0u8; quic_lite::DEFAULT_MAX_DATAGRAM_SIZE + 1];
    let bootstrap_deadline = Instant::now() + Duration::from_secs(3);
    let server_cid = 'bootstrap: loop {
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
                        Ok(UartIngress::DirectRecord(record)) => {
                            report_uart_direct_record(path, record, &mut text_filter);
                            continue;
                        }
                        Err(_) => continue,
                    };
                    if let Ok((header, ack)) =
                        quic_lite::decode_bootstrap_open_ack_packet_with_limits(packet, cid)
                    {
                        if header.dcid == cid && ack.server_receive_cid.value() != 0 {
                            break 'bootstrap ack.server_receive_cid;
                        }
                    }
                }
            }
            Ok(_) => thread::yield_now(),
            Err(error) if error.kind() == ErrorKind::WouldBlock => thread::yield_now(),
            Err(error) => return Err(error.to_string()),
        }
    };

    let mut endpoint = EndpointState::<8>::new(
        Role::Client,
        limits,
        quic_lite::DEFAULT_MAX_DATAGRAM_SIZE as u64,
    );
    endpoint
        .install_connection_ids(cid, server_cid)
        .map_err(|error| format!("UART bootstrap CIDs: {error:?}"))?;
    endpoint
        .set_initial_peer_credit(limits.max_data, limits.max_stream_data)
        .map_err(|error| format!("UART bootstrap credit: {error:?}"))?;
    endpoint
        .continue_packet_numbers_from(1)
        .map_err(|error| format!("UART bootstrap packet numbers: {error:?}"))?;
    endpoint
        .open_send_stream(
            quic_lite::FIRST_CLIENT_BIDI_STREAM_ID,
            quic_lite::INITIAL_MAX_STREAM_DATA,
        )
        .map_err(|error| format!("UART service stream: {error:?}"))?;
    let mut request = Vec::with_capacity(1 + body.len());
    request.push(service);
    request.extend_from_slice(&body);
    let mut packet = [0u8; quic_lite::DEFAULT_MAX_DATAGRAM_SIZE];
    let (used, _) = endpoint
        .encode_stream_packet(
            server_cid,
            quic_lite::FIRST_CLIENT_BIDI_STREAM_ID,
            0,
            true,
            &request,
            &mut packet,
        )
        .map_err(|error| format!("UART service request: {error:?}"))?;
    send_uart_transport(serial, &packet[..used])?;

    let response_deadline = Instant::now()
        + if service == quic_lite::SERVICE_IPERF {
            Duration::from_secs(45)
        } else {
            Duration::from_secs(3)
        };
    let iperf_plan = if service == quic_lite::SERVICE_IPERF {
        let plan = decode_iperf_service_request(&request).ok_or("UART IPERF request encoding")?;
        Some(IperfServicePlan::from_request(
            plan,
            quic_lite::DEFAULT_MAX_DATAGRAM_SIZE - 32,
        ))
    } else {
        None
    };
    let mut iperf_receiver = IperfRun::<{ dmesh_server::iperf::IPERF_MAX_NORMAL_STREAMS }>::new(
        2,
        iperf_plan.map_or(1, |plan| plan.normal_streams),
        iperf_plan.is_some_and(|plan| plan.high_priority_bytes != 0),
        iperf_plan.is_some_and(|plan| plan.low_priority_bytes != 0),
    );
    let iperf_started = Instant::now();
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
                        Ok(UartIngress::DirectRecord(record)) => {
                            report_uart_direct_record(path, record, &mut text_filter);
                            continue;
                        }
                        Err(_) => continue,
                    };
                    let TransportPacket::Stream { frame, .. } =
                        endpoint
                            .receive_datagram(packet)
                            .map_err(|error| format!("UART response packet: {error:?}"))?
                    else {
                        continue;
                    };
                    if service == quic_lite::SERVICE_IPERF {
                        let stream = StreamFrame {
                            id: frame.id,
                            offset: frame.offset,
                            fin: frame.fin,
                            data: frame.data,
                        };
                        let (complete, consumed) = iperf_receiver
                            .handle(quic_lite::FIRST_SERVER_BIDI_STREAM_ID, stream)
                            .map_err(|_| "UART IPERF payload validation failed")?;
                        endpoint
                            .stream_consumed(frame.id, consumed)
                            .map_err(|error| format!("UART IPERF credit: {error:?}"))?;
                        let mut ack = [0u8; quic_lite::DEFAULT_MAX_DATAGRAM_SIZE];
                        if let Some(used) = endpoint
                            .poll_transmit(&mut ack)
                            .map_err(|error| format!("UART IPERF ACK: {error:?}"))?
                        {
                            send_uart_transport(serial, &ack[..used])?;
                        }
                        if complete {
                            let elapsed = iperf_started.elapsed();
                            let bytes = iperf_receiver.bytes();
                            let bps = if elapsed.is_zero() {
                                0
                            } else {
                                bytes.saturating_mul(8).saturating_mul(1_000_000)
                                    / elapsed.as_micros().max(1) as u64
                            };
                            println!(
                                "dmesh_cli_iperf_result bearer=uart bytes={bytes} normal_bytes={} high_bytes={} low_bytes={} elapsed_us={} bps={bps} callback_errors={:?}",
                                iperf_receiver.normal_bytes(),
                                iperf_receiver.high_bytes(),
                                iperf_receiver.low_bytes(),
                                elapsed.as_micros(),
                                iperf_receiver.callback_errors()
                            );
                            return Ok(());
                        }
                        continue;
                    }
                    if frame.id == quic_lite::FIRST_SERVER_BIDI_STREAM_ID {
                        if service == quic_lite::SERVICE_HANDLERS {
                            println!(
                                "dmesh_client_services target={} stream={} fin={} {}",
                                path,
                                frame.id,
                                frame.fin,
                                render_handler_list(frame.data)
                            );
                        } else if service == quic_lite::SERVICE_EVENTS {
                            println!(
                                "dmesh_client_events target={} stream={} fin={} {}",
                                path,
                                frame.id,
                                frame.fin,
                                render_binary_events(frame.data)
                            );
                        } else {
                            println!(
                                "dmesh_client_response target={} service={} stream={} fin={} bytes={} {}",
                                path,
                                service,
                                frame.id,
                                frame.fin,
                                frame.data.len(),
                                render_device_record(&FirmwareSchema::load(), frame.data)
                            );
                        }
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
/// not open a service stream and never substitutes for `SERVICE_LOG_WATCH`:
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
        eprintln!(
            "dmesh_uart_interactive commands=status|metrics|events|services|log-watch [records]|control|iperf BYTES|quit"
        );
    }
    let schema = FirmwareSchema::load();
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
                        match parse_interactive_service_command(&line).and_then(
                            |(service, body)| {
                                run_serial_service_request(&mut serial, path, service, &body)
                            },
                        ) {
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
                        Ok(UartIngress::DirectRecord(record)) => {
                            direct_records = direct_records.saturating_add(1);
                            println!(
                                "dmesh_uart_watch_record bytes={} {}",
                                record.len(),
                                render_device_record(&schema, record)
                            );
                        }
                        Ok(UartIngress::Transport(packet)) => {
                            transport_packets = transport_packets.saturating_add(1);
                            match ShortHeader::decode(packet) {
                                Ok((header, _)) => println!(
                                    "dmesh_uart_watch_transport bytes={} dcid={:?} packet_number={}",
                                    packet.len(),
                                    header.dcid,
                                    header.packet_number
                                ),
                                Err(_) => println!(
                                    "dmesh_uart_watch_transport_invalid bytes={}",
                                    packet.len()
                                ),
                            }
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

/// Parse the bearer-neutral, one-shot stream request surface.  UART and UDP
/// deliberately use these exact service tags and bodies; only packet I/O and
/// the optional UDP session socket differ.
fn parse_service_request(arguments: &[String]) -> Result<(u8, Vec<u8>), String> {
    let mut service = quic_lite::SERVICE_STATUS;
    let mut body = Vec::new();
    let mut iperf_bytes = None;
    let mut parallel_streams = 1u8;
    let mut high_priority_bytes = 0u32;
    let mut low_priority_bytes = 0u32;
    let mut target_bps = None;
    let mut log_records = None;
    let mut index = 0;
    while index < arguments.len() {
        match arguments[index].as_str() {
            "--services" => service = quic_lite::SERVICE_HANDLERS,
            "--log-watch" => service = quic_lite::SERVICE_LOG_WATCH,
            "--service" => {
                index += 1;
                service = service_tag(arguments.get(index).ok_or("missing --service value")?)
                    .ok_or(
                        "service must be status, metrics, events, services, log-watch, or control",
                    )?;
            }
            "--service-tag" => {
                index += 1;
                service = arguments
                    .get(index)
                    .ok_or("missing --service-tag value")?
                    .parse::<u8>()
                    .map_err(|error| format!("invalid --service-tag: {error}"))?;
            }
            "--body-hex" => {
                index += 1;
                body = hex(arguments.get(index).ok_or("missing --body-hex value")?)?;
            }
            "--log-records" => {
                index += 1;
                log_records = Some(
                    arguments
                        .get(index)
                        .ok_or("missing --log-records value")?
                        .parse::<u8>()
                        .map_err(|error| error.to_string())?,
                );
            }
            "--iperf-bytes" => {
                index += 1;
                iperf_bytes = Some(
                    arguments
                        .get(index)
                        .ok_or("missing --iperf-bytes value")?
                        .parse::<u64>()
                        .map_err(|error| error.to_string())?,
                );
            }
            "--parallel-streams" => {
                index += 1;
                parallel_streams = arguments
                    .get(index)
                    .ok_or("missing --parallel-streams value")?
                    .parse::<u8>()
                    .map_err(|error| error.to_string())?;
                if !(1..=dmesh_server::iperf::IPERF_MAX_NORMAL_STREAMS as u8)
                    .contains(&parallel_streams)
                {
                    return Err("--parallel-streams must be in 1..=4".into());
                }
            }
            "--high-priority-bytes" => {
                index += 1;
                high_priority_bytes = arguments
                    .get(index)
                    .ok_or("missing --high-priority-bytes value")?
                    .parse::<u32>()
                    .map_err(|error| error.to_string())?;
            }
            "--low-priority-bytes" => {
                index += 1;
                low_priority_bytes = arguments
                    .get(index)
                    .ok_or("missing --low-priority-bytes value")?
                    .parse::<u32>()
                    .map_err(|error| error.to_string())?;
            }
            "--target-bps" => {
                index += 1;
                target_bps = Some(
                    arguments
                        .get(index)
                        .ok_or("missing --target-bps value")?
                        .parse::<u64>()
                        .map_err(|error| error.to_string())?,
                );
            }
            unknown => return Err(format!("unknown service request argument {unknown}")),
        }
        index += 1;
    }
    if let Some(records) = log_records {
        if service != quic_lite::SERVICE_LOG_WATCH || !(1..=64).contains(&records) {
            return Err("--log-records requires --service log-watch and a value in 1..=64".into());
        }
        body = vec![records];
    }
    if let Some(bytes) = iperf_bytes {
        if service != quic_lite::SERVICE_STATUS {
            return Err("--iperf-bytes cannot be combined with --service".into());
        }
        service = quic_lite::SERVICE_IPERF;
        body = encode_iperf_service_body(
            bytes,
            parallel_streams,
            high_priority_bytes,
            low_priority_bytes,
            target_bps,
        )?;
    }
    Ok((service, body))
}

/// Build the shared service body rather than a CLI-private IPERF envelope.
/// This stays outside UART/UDP I/O so both bearer clients issue byte-identical
/// handler requests and the plan is decoded again by the server.
fn encode_iperf_service_body(
    bytes: u64,
    parallel_streams: u8,
    high_priority_bytes: u32,
    low_priority_bytes: u32,
    target_bps: Option<u64>,
) -> Result<Vec<u8>, String> {
    let pace_us = match target_bps {
        Some(0) => return Err("--target-bps must be nonzero".into()),
        Some(rate) => Some(
            ((1200u64 * 8_000_000).saturating_add(rate - 1) / rate).min(u64::from(u32::MAX)) as u32,
        ),
        None => None,
    };
    let request = dmesh_server::iperf::IperfServiceRequest {
        bytes,
        packet_size: 1200,
        pace_us,
        burst_packets: None,
        burst_delay_us: None,
        // ACK cadence is negotiated by the connection association, not by
        // this diagnostic service request.
        ack_frequency: None,
        ack_delay_ms: None,
        low_priority_bytes: (low_priority_bytes != 0).then_some(low_priority_bytes),
        high_priority_bytes: (high_priority_bytes != 0).then_some(high_priority_bytes),
        parallel_streams: Some(parallel_streams),
    };
    let mut wire = [0u8; dmesh_server::iperf::IPERF_REQUEST_LEN];
    let used = dmesh_server::iperf::encode_iperf_service_request(request, &mut wire)
        .ok_or("IPERF request buffer")?;
    Ok(wire[1..used].to_vec())
}

/// Line-oriented command vocabulary for a serial watch pane.  It intentionally
/// maps to the same numeric service request parser used by one-shot UART and
/// UDP calls, rather than creating a UART command protocol.
fn parse_interactive_service_command(line: &str) -> Result<(u8, Vec<u8>), String> {
    let mut words = line.split_whitespace();
    let command = words.next().ok_or("empty command")?;
    let mut arguments = Vec::new();
    match command {
        "status" | "metrics" | "events" | "services" | "control" => {
            arguments.push("--service".to_owned());
            arguments.push(command.to_owned());
        }
        "log-watch" => {
            arguments.push("--service".to_owned());
            arguments.push(command.to_owned());
            if let Some(records) = words.next() {
                arguments.push("--log-records".to_owned());
                arguments.push(records.to_owned());
            }
        }
        "iperf" => {
            arguments.push("--iperf-bytes".to_owned());
            arguments.push(
                words
                    .next()
                    .ok_or("iperf requires a byte count")?
                    .to_owned(),
            );
        }
        _ => return Err(format!("unknown command {command}")),
    }
    if words.next().is_some() {
        return Err("too many command arguments".into());
    }
    parse_service_request(&arguments)
}

/// Execute one service operation directly over the UDP QUIC-lite bearer.
/// This is intentionally the same `UdpClient` used by the host transport
/// tests: a command client has no raw UDP fallback or UART-specific schema.
/// Long-lived log subscription delivery is not enabled yet; `log-watch` is a
/// bounded record poll until the server-side framed subscription is added.
fn run_udp_service_client(arguments: &[String]) -> Result<(), String> {
    let peer = arguments
        .first()
        .and_then(|target| target.strip_prefix("udp://"))
        .ok_or("UDP target must use udp://HOST:PORT")?;
    let peer = parse_udp_peer(peer)?;
    if arguments
        .get(1)
        .is_some_and(|argument| argument == "--udp-probe")
    {
        if arguments.len() != 2 {
            return Err("--udp-probe cannot be combined with a stream request".into());
        }
        return run_udp_bearer_probe(peer);
    }
    let mut service = quic_lite::SERVICE_STATUS;
    let mut body = Vec::new();
    let mut iperf_bytes = None;
    let mut parallel_streams = 1u8;
    let mut high_priority_bytes = 0u32;
    let mut low_priority_bytes = 0u32;
    let mut target_bps = None;
    let mut log_records = None;
    let mut session_socket = None;
    let mut relay_forward_dcid = None;
    let mut relay_reverse_dcid = None;
    let mut relay_next_mac = None;
    let mut relay_allocation = 1u64;
    let mut index = 1;
    while index < arguments.len() {
        match arguments[index].as_str() {
            "--services" => service = quic_lite::SERVICE_HANDLERS,
            "--log-watch" => service = quic_lite::SERVICE_LOG_WATCH,
            "--service" => {
                index += 1;
                let name = arguments.get(index).ok_or("missing --service value")?;
                service = match name.as_str() {
                    "status" => quic_lite::SERVICE_STATUS,
                    "metrics" => quic_lite::SERVICE_METRICS,
                    "events" => quic_lite::SERVICE_EVENTS,
                    "services" | "streams" => quic_lite::SERVICE_HANDLERS,
                    "log-watch" => quic_lite::SERVICE_LOG_WATCH,
                    "control" => quic_lite::SERVICE_CONTROL,
                    _ => {
                        return Err(
                            "service must be status, metrics, events, services, log-watch, or control"
                                .into(),
                        );
                    }
                };
            }
            "--service-tag" => {
                index += 1;
                service = arguments
                    .get(index)
                    .ok_or("missing --service-tag value")?
                    .parse::<u8>()
                    .map_err(|error| format!("invalid --service-tag: {error}"))?;
            }
            "--body-hex" => {
                index += 1;
                body = hex(arguments.get(index).ok_or("missing --body-hex value")?)?;
            }
            "--log-records" => {
                index += 1;
                log_records = Some(
                    arguments
                        .get(index)
                        .ok_or("missing --log-records value")?
                        .parse::<u8>()
                        .map_err(|error| error.to_string())?,
                );
            }
            "--iperf-bytes" => {
                index += 1;
                iperf_bytes = Some(
                    arguments
                        .get(index)
                        .ok_or("missing --iperf-bytes value")?
                        .parse::<u64>()
                        .map_err(|error| error.to_string())?,
                );
            }
            "--parallel-streams" => {
                index += 1;
                parallel_streams = arguments
                    .get(index)
                    .ok_or("missing --parallel-streams value")?
                    .parse::<u8>()
                    .map_err(|error| error.to_string())?;
                if !(1..=dmesh_server::iperf::IPERF_MAX_NORMAL_STREAMS as u8)
                    .contains(&parallel_streams)
                {
                    return Err("--parallel-streams must be in 1..=4".into());
                }
            }
            "--high-priority-bytes" => {
                index += 1;
                high_priority_bytes = arguments
                    .get(index)
                    .ok_or("missing --high-priority-bytes value")?
                    .parse::<u32>()
                    .map_err(|error| error.to_string())?;
            }
            "--low-priority-bytes" => {
                index += 1;
                low_priority_bytes = arguments
                    .get(index)
                    .ok_or("missing --low-priority-bytes value")?
                    .parse::<u32>()
                    .map_err(|error| error.to_string())?;
            }
            "--target-bps" => {
                index += 1;
                target_bps = Some(
                    arguments
                        .get(index)
                        .ok_or("missing --target-bps value")?
                        .parse::<u64>()
                        .map_err(|error| error.to_string())?,
                );
            }
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
    if let Some(records) = log_records {
        if service != quic_lite::SERVICE_LOG_WATCH || !(1..=64).contains(&records) {
            return Err("--log-records requires --service log-watch and a value in 1..=64".into());
        }
        body = vec![records];
    }
    if let Some(bytes) = iperf_bytes {
        if service != quic_lite::SERVICE_STATUS {
            return Err("--iperf-bytes cannot be combined with --service".into());
        }
        service = quic_lite::SERVICE_IPERF;
        body = encode_iperf_service_body(
            bytes,
            parallel_streams,
            high_priority_bytes,
            low_priority_bytes,
            target_bps,
        )?;
    }
    if let Some(socket_path) = session_socket {
        if service != quic_lite::SERVICE_STATUS || !body.is_empty() || iperf_bytes.is_some() {
            return Err(
                "--socket owns a device session; do not combine it with a one-shot request".into(),
            );
        }
        return serve_udp_session_socket(peer, Path::new(&socket_path));
    }
    let mut request = Vec::with_capacity(1 + body.len());
    request.push(service);
    request.extend_from_slice(&body);
    let relay = match (relay_forward_dcid, relay_reverse_dcid, relay_next_mac) {
        (None, None, None) => None,
        (Some(forward), Some(reverse), Some(next_mac)) => Some((
            quic_lite::ConnectionId::new(forward).ok_or("invalid relay forward DCID")?,
            quic_lite::ConnectionId::new(reverse).ok_or("invalid relay reverse DCID")?,
            next_mac,
        )),
        _ => return Err("relay mode requires forward DCID, reverse DCID, and next MAC".into()),
    };
    // This CID is owned by dmesh-cli and remains stable across relay alias
    // allocation. It is never a relay allocation.
    let cid = fresh_connection_id()?;
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
        let response = exchange_udp_direct_record(peer, &request)?;
        let (_, response) = quic_lite::decode_direct_packet(&response)
            .map_err(|error| format!("relay pair response packet: {error:?}"))?;
        let response = dmesh_server::tagged::decode(response)
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
    let schema = FirmwareSchema::load();
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
            let mut packet = [0u8; quic_lite::DEFAULT_MAX_DATAGRAM_SIZE];
            let used = quic_lite::encode_direct_packet(fresh_packet_number(), &update, &mut packet)
                .map_err(|error| format!("relay update packet: {error:?}"))?;
            let update_response = client
                .exchange_direct(&packet[..used])
                .await
                .map_err(|error| error.to_string())?;
            let update_record = dmesh_server::tagged::decode(
                quic_lite::decode_direct_packet(&update_response)
                    .map_err(|error| format!("relay update response packet: {error:?}"))?
                    .1,
            )
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
        if service == quic_lite::SERVICE_IPERF {
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
            let plan = decode_iperf_service_request(&request)
                .ok_or("UDP IPERF request encoding")?;
            let plan = IperfServicePlan::from_request(
                plan,
                quic_lite::DEFAULT_MAX_DATAGRAM_SIZE - 32,
            );
            let mut receiver = IperfRun::<{ dmesh_server::iperf::IPERF_MAX_NORMAL_STREAMS }>::new(
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
                    .map_err(|_| "UDP IPERF payload validation failed")?;
                if complete {
                    let elapsed = started.elapsed();
                    let bytes = receiver.bytes();
                    let bps = if elapsed.is_zero() {
                        0
                    } else {
                        bytes.saturating_mul(8).saturating_mul(1_000_000)
                            / elapsed.as_micros().max(1) as u64
                    };
                    println!(
                        "dmesh_cli_iperf_result bearer=udp target={peer} stream={first_stream} bytes={bytes} normal_bytes={} high_bytes={} low_bytes={} elapsed_us={} bps={bps} callback_errors={:?}",
                        receiver.normal_bytes(),
                        receiver.high_bytes(),
                        receiver.low_bytes(),
                        elapsed.as_micros(),
                        receiver.callback_errors()
                    );
                    return Ok(());
                }
                frame = tokio::time::timeout(Duration::from_secs(30), client.recv_stream_frame())
                    .await
                    .map_err(|_| "UDP IPERF receive timeout")?
                    .map_err(|error| error.to_string())?;
            }
        }
        let (stream, response, fin) = client
            .request_stream(quic_lite::FIRST_CLIENT_BIDI_STREAM_ID, &request, true)
            .await
            .map_err(|error| error.to_string())?;
        if service == quic_lite::SERVICE_HANDLERS {
            println!(
                "dmesh_client_services target={peer} stream={stream} fin={fin} {}",
                render_handler_list(&response)
            );
        } else if service == quic_lite::SERVICE_EVENTS {
            println!(
                "dmesh_client_events target={peer} stream={stream} fin={fin} {}",
                render_binary_events(&response)
            );
        } else {
            println!(
                "dmesh_client_response target={peer} service={service} stream={stream} fin={fin} bytes={} {}",
                response.len(),
                render_device_record(&schema, &response)
            );
        }
        Ok(())
    })
}

/// Select the wildcard address family from the peer. A raw IPv6 bearer must
/// not first fail in the host client by binding an IPv4 socket.
fn udp_bind_for_peer(peer: SocketAddr) -> SocketAddr {
    match peer {
        // Keep the operator/client socket distinct from both managed host
        // listeners (wlan0:3336, wlan1:3337) and firmware raw UDP6 (3339).
        // A fixed source port also makes link-local captures reproducible.
        SocketAddr::V4(_) => "0.0.0.0:3338".parse().expect("valid IPv4 UDP bind"),
        SocketAddr::V6(_) => "[::]:3338".parse().expect("valid IPv6 UDP bind"),
    }
}

/// Parse a UDP peer, including the scoped IPv6 link-local form required by
/// raw UDP6 tests: `[fe80::1%wlan0]:3339`. `SocketAddr` itself deliberately
/// does not parse interface names, so resolve the Linux interface index here
/// at the host CLI boundary rather than teaching firmware about host scopes.
fn parse_udp_peer(value: &str) -> Result<SocketAddr, String> {
    if let Ok(peer) = value.parse::<SocketAddr>() {
        return Ok(peer);
    }
    let scoped = value
        .strip_prefix('[')
        .and_then(|value| value.rsplit_once("]:"))
        .ok_or_else(|| format!("invalid UDP peer {value:?}"))?;
    let (address_scope, port) = scoped;
    let (address, scope) = address_scope
        .rsplit_once('%')
        .ok_or_else(|| format!("IPv6 link-local peer needs %INTERFACE: {value:?}"))?;
    let address = address
        .parse::<Ipv6Addr>()
        .map_err(|error| error.to_string())?;
    let port = port.parse::<u16>().map_err(|error| error.to_string())?;
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

/// Verify only UDP socket ingress and egress.  This intentionally bypasses
/// QUIC-lite/DCID dispatch and is not a command or a production keepalive.
fn run_udp_bearer_probe(peer: SocketAddr) -> Result<(), String> {
    // A scoped IPv6 link-local peer needs an IPv6 local socket.  Binding an
    // IPv4 wildcard first makes the diagnostic fail before it exercises the
    // bearer at all, even though the normal UDP client selects the family
    // from its peer through `udp_bind_for_peer`.
    let socket = UdpSocket::bind(udp_bind_for_peer(peer)).map_err(|error| error.to_string())?;
    socket.connect(peer).map_err(|error| error.to_string())?;
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(|error| error.to_string())?;
    let nonce = fresh_request_id();
    let packet_number = fresh_packet_number();
    let mut request = [0u8; 64];
    let request_len =
        quic_lite::bearer_probe::encode_udp_bearer_probe(packet_number, nonce, &mut request)
            .ok_or("encode UDP bearer probe")?;
    let started = Instant::now();
    loop {
        match socket.send(&request[..request_len]) {
            Ok(_) => break,
            Err(error)
                if error.kind() == ErrorKind::WouldBlock
                    && started.elapsed() < Duration::from_secs(2) =>
            {
                thread::sleep(Duration::from_millis(1));
            }
            Err(error) => return Err(error.to_string()),
        }
    }
    let mut response = [0u8; 64];
    let used = loop {
        match socket.recv(&mut response) {
            Ok(used) => break used,
            Err(error)
                if error.kind() == ErrorKind::WouldBlock
                    && started.elapsed() < Duration::from_secs(2) =>
            {
                thread::sleep(Duration::from_millis(1));
            }
            Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                return Err("UDP bearer probe timeout (no reply)".into());
            }
            Err(error) => return Err(error.to_string()),
        }
    };
    if !quic_lite::bearer_probe::decode_udp_bearer_probe_response(&response[..used], nonce) {
        return Err("UDP bearer probe received an invalid response".into());
    }
    println!(
        "dmesh_udp_probe target={peer} request_id={nonce} packet_number={packet_number} elapsed_us={}",
        started.elapsed().as_micros()
    );
    Ok(())
}

/// Send one schema-backed DCID-zero control record to an explicit UDP
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
        Some("--command") => {
            index += 1;
            encode_direct_command_with_id(
                arguments.get(index).ok_or("missing --command value")?,
                fresh_request_id(),
            )
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
    let (_, response_record) = quic_lite::decode_direct_packet(&response)
        .map_err(|_| "UDP direct record received a non-direct response".to_owned())?;
    let schema = FirmwareSchema::load();
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

fn exchange_udp_direct_record_with_timeout(
    peer: SocketAddr,
    record: &[u8],
    timeout: Duration,
) -> Result<Vec<u8>, String> {
    let mut packet = [0u8; quic_lite::DEFAULT_MAX_DATAGRAM_SIZE];
    let packet_number = fresh_packet_number();
    let used = quic_lite::encode_direct_packet(packet_number, record, &mut packet)
        .map_err(|error| format!("encode UDP direct packet: {error:?}"))?;
    let socket = UdpSocket::bind(udp_bind_for_peer(peer)).map_err(|error| error.to_string())?;
    socket.connect(peer).map_err(|error| error.to_string())?;
    socket
        .set_read_timeout(Some(timeout))
        .map_err(|error| error.to_string())?;
    socket
        .send(&packet[..used])
        .map_err(|error| error.to_string())?;
    let mut response = [0u8; quic_lite::DEFAULT_MAX_DATAGRAM_SIZE];
    let response_len = socket.recv(&mut response).map_err(|error| {
        if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) {
            "UDP direct record timeout (no reply)".to_owned()
        } else {
            error.to_string()
        }
    })?;
    Ok(response[..response_len].to_vec())
}

#[derive(Deserialize)]
struct LocalSessionRequest {
    /// Optional debug name for a registered service. Dispatch remains numeric.
    #[serde(default)]
    service: Option<String>,
    /// Numeric registered service tag. This takes precedence over `service`.
    #[serde(default)]
    service_tag: Option<u8>,
    /// Optional service payload. It is deliberately hex rather than a
    /// UART-specific framing language: this socket opens QUIC-lite streams.
    #[serde(default)]
    body_hex: Option<String>,
}

fn service_tag(name: &str) -> Option<u8> {
    Some(match name {
        "status" => quic_lite::SERVICE_STATUS,
        "metrics" => quic_lite::SERVICE_METRICS,
        "events" => quic_lite::SERVICE_EVENTS,
        "services" | "streams" => quic_lite::SERVICE_HANDLERS,
        "log-watch" => quic_lite::SERVICE_LOG_WATCH,
        "control" => quic_lite::SERVICE_CONTROL,
        _ => return None,
    })
}

/// Decode `SERVICE_HANDLERS`: canonical CBOR `[[tag, name], ...]`.
/// The handler list is deliberately its own tiny discovery schema; local
/// firmware schemas remain for direct CBOR records and handler responses.
fn render_handler_list(records: &[u8]) -> String {
    let mut index = 0;
    let Some(count) = decode_cbor_unsigned(records, &mut index, 4) else {
        return "invalid_handler_list".into();
    };
    let mut entries = Vec::new();
    for _ in 0..count {
        if decode_cbor_unsigned(records, &mut index, 4) != Some(2) {
            return "invalid_handler_list".into();
        }
        let Some(tag) = decode_cbor_unsigned(records, &mut index, 0) else {
            return "invalid_handler_list".into();
        };
        let Some(name_len) = decode_cbor_unsigned(records, &mut index, 3) else {
            return "invalid_handler_list".into();
        };
        let Ok(name_len) = usize::try_from(name_len) else {
            return "invalid_handler_list".into();
        };
        let Some(name) = records.get(index..index.saturating_add(name_len)) else {
            return "invalid_handler_list".into();
        };
        let Ok(name) = std::str::from_utf8(name) else {
            return "invalid_handler_list".into();
        };
        entries.push(format!("{tag}:{name}"));
        index += name_len;
    }
    if index != records.len() {
        return "invalid_handler_list".into();
    }
    format!("handlers={}", entries.join(","))
}

/// Decode Main module events: canonical CBOR
/// `[next_sequence, [[sequence,event_id,value_type,flags,payload], ...]]`.
/// Unknown event IDs remain numeric, while payload stays hex so module-owned
/// schemas are never guessed by the UART bearer client.
fn render_binary_events(records: &[u8]) -> String {
    let mut index = 0;
    if decode_cbor_unsigned(records, &mut index, 4) != Some(2) {
        // Recovery and older Android adapters expose the same event service
        // as the bounded textual snapshot used by the original server. Keep
        // that response visible instead of reporting a decoder failure; the
        // wire service was reached successfully and its payload is still
        // useful to the operator.
        return format!(
            "legacy_events={}",
            String::from_utf8_lossy(records).replace('\n', "\\n")
        );
    }
    let Some(next) = decode_cbor_unsigned(records, &mut index, 0) else {
        return "invalid_events".into();
    };
    let Some(count) = decode_cbor_unsigned(records, &mut index, 4) else {
        return "invalid_events".into();
    };
    let mut entries = Vec::new();
    for _ in 0..count {
        if decode_cbor_unsigned(records, &mut index, 4) != Some(5) {
            return "invalid_events".into();
        }
        let (Some(sequence), Some(event_id), Some(value_type), Some(flags)) = (
            decode_cbor_unsigned(records, &mut index, 0),
            decode_cbor_unsigned(records, &mut index, 0),
            decode_cbor_unsigned(records, &mut index, 0),
            decode_cbor_unsigned(records, &mut index, 0),
        ) else {
            return "invalid_events".into();
        };
        let Some(payload_len) = decode_cbor_unsigned(records, &mut index, 2) else {
            return "invalid_events".into();
        };
        let Ok(payload_len) = usize::try_from(payload_len) else {
            return "invalid_events".into();
        };
        let Some(payload) = records.get(index..index.saturating_add(payload_len)) else {
            return "invalid_events".into();
        };
        index += payload_len;
        entries.push(format!(
            "seq={sequence},id={event_id},type={value_type},flags={flags},payload_hex={}",
            hex_encode(payload)
        ));
    }
    if index != records.len() {
        return "invalid_events".into();
    }
    format!("events_next={next};events={}", entries.join("|"))
}

fn decode_cbor_unsigned(input: &[u8], index: &mut usize, expected_major: u8) -> Option<u64> {
    let head = *input.get(*index)?;
    *index += 1;
    if head >> 5 != expected_major {
        return None;
    }
    let additional = head & 0x1f;
    let bytes = match additional {
        value @ 0..=23 => return Some(u64::from(value)),
        24 => 1,
        25 => 2,
        26 => 4,
        27 => 8,
        _ => return None,
    };
    let end = index.checked_add(bytes)?;
    let value = input.get(*index..end)?;
    *index = end;
    Some(match bytes {
        1 => u64::from(value[0]),
        2 => u64::from(u16::from_be_bytes(value.try_into().ok()?)),
        4 => u64::from(u32::from_be_bytes(value.try_into().ok()?)),
        8 => u64::from_be_bytes(value.try_into().ok()?),
        _ => return None,
    })
}

/// Own a single UDP QUIC-lite connection and expose a deliberately small
/// local text socket. This replaces the retired byte-forwarding listener: a
/// local client supplies a JSON line such as
/// `{"service":"log-watch","body_hex":"04"}` or
/// `{"service_tag":45,"body_hex":"01"}` and receives one JSON
/// result. Requests use distinct QUIC stream IDs on this owned connection.
///
/// This is a session/shell helper, not a bearer proxy. It has no TCP path and
/// it never accepts arbitrary raw UART data. Long-lived log delivery will use
/// the same endpoint once the service handler publishes framed log records.
pub fn serve_udp_session_socket(peer: SocketAddr, socket_path: &Path) -> Result<(), String> {
    if socket_path.exists() {
        let metadata = std::fs::symlink_metadata(socket_path).map_err(|error| error.to_string())?;
        if !metadata.file_type().is_socket() {
            return Err(format!(
                "refusing to replace non-socket {}",
                socket_path.display()
            ));
        }
        std::fs::remove_file(socket_path).map_err(|error| error.to_string())?;
    }
    let listener = UnixListener::bind(socket_path).map_err(|error| error.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o600))
            .map_err(|error| error.to_string())?;
    }
    listener
        .set_nonblocking(true)
        .map_err(|error| error.to_string())?;
    let cid = fresh_connection_id()?;
    let runtime = tokio::runtime::Runtime::new().map_err(|error| error.to_string())?;
    let mut client = runtime
        .block_on(dmesh_server::udp::UdpClient::connect(
            "0.0.0.0:0".parse().expect("valid UDP bind"),
            peer,
            cid,
        ))
        .map_err(|error| error.to_string())?;
    let schema = FirmwareSchema::load();
    let mut next_stream = quic_lite::FIRST_CLIENT_BIDI_STREAM_ID;
    eprintln!(
        "dmesh_device_session target={peer} socket={}",
        socket_path.display()
    );
    loop {
        match listener.accept() {
            Ok((mut stream, _)) => {
                let mut line = String::new();
                BufReader::new(stream.try_clone().map_err(|error| error.to_string())?)
                    .read_line(&mut line)
                    .map_err(|error| error.to_string())?;
                let response = match serde_json::from_str::<LocalSessionRequest>(&line) {
                    Ok(request) => match request
                        .service_tag
                        .or_else(|| request.service.as_deref().and_then(service_tag))
                    {
                        None => serde_json::json!({"error": "unknown service"}),
                        Some(service) => {
                            let body = request.body_hex.as_deref().map(hex).transpose();
                            match body {
                                Ok(body) => {
                                    let mut packet =
                                        Vec::with_capacity(1 + body.as_ref().map_or(0, Vec::len));
                                    packet.push(service);
                                    if let Some(body) = body {
                                        packet.extend_from_slice(&body);
                                    }
                                    let stream_id = next_stream;
                                    next_stream = next_stream.saturating_add(4);
                                    match runtime
                                        .block_on(client.request_stream(stream_id, &packet, true))
                                    {
                                        Ok((stream_id, record, fin)) => serde_json::json!({
                                            "response": {
                                                "stream": stream_id, "fin": fin,
                                                "record": render_device_record(&schema, &record),
                                                "record_hex": hex_encode(&record),
                                            }
                                        }),
                                        Err(error) => {
                                            serde_json::json!({"error": error.to_string()})
                                        }
                                    }
                                }
                                Err(error) => serde_json::json!({"error": error}),
                            }
                        }
                    },
                    Err(error) => {
                        serde_json::json!({"error": format!("invalid JSON request: {error}")})
                    }
                };
                writeln!(stream, "{response}").map_err(|error| error.to_string())?;
            }
            Err(error) if error.kind() == ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(10))
            }
            Err(error) => return Err(error.to_string()),
        }
    }
}

fn bearer_name(path_policy: ClientPathPolicy) -> &'static str {
    match path_policy {
        ClientPathPolicy::Udp => "udp",
        ClientPathPolicy::Uart => "uart",
        ClientPathPolicy::UartSpillover => "uart-spill-udp",
        ClientPathPolicy::Aggregate => "uart+udp-aggregate",
        ClientPathPolicy::HighestMeasuredSpeed => "fastest",
    }
}

/// Fresh caller identity for correlation across independent CLI invocations.
///
/// Never derive this from process ID or a newly-created `Instant`: both made
/// consecutive dmesh-cli runs reuse the same connection ID and let a delayed
/// datagram be misattributed to the next request.
fn fresh_request_id() -> u64 {
    loop {
        let value = rand::random::<u64>();
        if value != 0 {
            return value;
        }
    }
}

fn fresh_connection_id() -> Result<quic_lite::ConnectionId, String> {
    let value = (fresh_request_id() & quic_lite::ConnectionId::MAX_VALUE).max(1);
    quic_lite::ConnectionId::new(value).ok_or("could not allocate random client CID".to_owned())
}

fn fresh_packet_number() -> u32 {
    // Keep below the full-width boundary so the bootstrap and its retries can
    // advance without wrapping, while still avoiding the fixed packet zero.
    (rand::random::<u32>() & 0x3fff_ffff).max(1)
}

#[cfg(test)]
mod tests {
    use super::{
        ClientPathPolicy, RawTextTap, WatchTextFilter, is_fatal_diagnostic, parse_udp_peer,
        proxy_request, proxy_socket_target, render_binary_events, render_handler_list,
    };
    use dmesh_server::relay::{
        DesiredRule, PairRequest, RelayRoute, RelayState, Request, decode_pair_request,
        decode_request, encode_observed_pair, encode_observed_rule, encode_pair_request,
        encode_request, now_next_hop_handle, udp6_next_hop_handle,
    };
    use dmesh_server::udp::{
        RelayDatagramHandler, RelayDatagramOutcome, TaggedStreamContext, TaggedStreamHandler,
        UdpClient, UdpConfig,
    };
    use quic_lite::{
        ConnectionId, DcidDatagram, dispatch_datagram,
    };
    use std::net::SocketAddr;
    use std::pin::Pin;
    use std::sync::{Arc, Mutex};
    use std::sync::atomic::{AtomicUsize, Ordering};
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

    impl dmesh_server::relay::DirectHandler for DirectRelayAdminSentinel {
        fn handle_direct(
            &self,
            _packet_number: u32,
            payload: &[u8],
            _out: &mut [u8],
        ) -> dmesh_server::relay::DirectOutcome {
            if decode_pair_request(payload).is_some() || decode_request(payload).is_some() {
                self.0.fetch_add(1, Ordering::Relaxed);
            }
            dmesh_server::relay::DirectOutcome::NotHandled
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
                    dmesh_server::tagged::encode_numeric_response(6, 9, id, &[0x81, 0x65, b'r', b'e', b'l', b'a', b'y'], &mut response)?
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
            let DcidDatagram::Forward { rule, used } = datagram else {
                return RelayDatagramOutcome::NotHandled;
            };
            if ingress == self.server_addr {
                self.reverse_count.fetch_add(1, Ordering::Relaxed);
            } else {
                self.forward_count.fetch_add(1, Ordering::Relaxed);
            }
            let used = if rule.outbound_dcid.value() == 0 && ingress != self.server_addr {
                let Ok((header, _)) = quic_lite::ShortHeader::decode(packet) else {
                    return RelayDatagramOutcome::Drop;
                };
                let Some(reverse) = state.relay_open_return_dcid(header.dcid) else {
                    return RelayDatagramOutcome::Drop;
                };
                let Ok(used) = quic_lite::rewrite_relay_open(
                    packet,
                    rule.outbound_dcid,
                    reverse,
                    out,
                ) else {
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
    /// QUIC-lite relay-open bootstrap uses DCID zero.
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
        let discovery_len = dmesh_server::tagged::encode_numeric_empty_request(
            6,
            9,
            31,
            &mut discovery,
        )
        .unwrap();
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
        assert_eq!(discovery_response.result, Some(&[0x81, 0x65, b'r', b'e', b'l', b'a', b'y'][..]));

        let pair = PairRequest {
            forward: Request {
                allocation: 1,
                revision: 1,
                rule: Some(DesiredRule {
                    proposed_dcid: Some(ConnectionId::new(8).unwrap()),
                    route: RelayRoute {
                        next_hop: now_next_hop_handle([2, 0, 0, 0, 0, 1]).unwrap(),
                        outbound_dcid: ConnectionId::new(0).unwrap(),
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
                        outbound_dcid: ConnectionId::new(77).unwrap(),
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
        let client_socket = control.into_socket();

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
                    outbound_dcid: server_cid,
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

        let (_, status, fin) = client
            .request_stream(
                quic_lite::FIRST_CLIENT_BIDI_STREAM_ID,
                &[quic_lite::SERVICE_STATUS],
                true,
            )
            .await
            .unwrap();
        let status = String::from_utf8(status).unwrap();
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
    fn path_policy_aliases_and_firmware_values_are_stable() {
        assert_eq!(
            ClientPathPolicy::parse("aggregate"),
            Some(ClientPathPolicy::Aggregate)
        );
        assert_eq!(
            ClientPathPolicy::parse("fastest"),
            Some(ClientPathPolicy::HighestMeasuredSpeed)
        );
        assert_eq!(ClientPathPolicy::parse("udp").unwrap().wire(), 1);
        assert_eq!(ClientPathPolicy::parse("uart").unwrap().wire(), 2);
        assert_eq!(ClientPathPolicy::parse("spill").unwrap().wire(), 3);
        assert_eq!(ClientPathPolicy::parse("aggregate").unwrap().wire(), 4);
        assert_eq!(ClientPathPolicy::parse("ESP-NOW"), None);
    }

    #[test]
    fn handler_list_uses_the_cbor_pair_schema() {
        assert_eq!(
            render_handler_list(&[
                0x81, 0x82, 4, 0x68, b'h', b'a', b'n', b'd', b'l', b'e', b'r', b's'
            ]),
            "handlers=4:handlers"
        );
        assert_eq!(render_handler_list(&[0x81, 4]), "invalid_handler_list");
    }

    #[test]
    fn binary_module_events_keep_numeric_fields_and_payload() {
        assert_eq!(
            render_binary_events(&[
                0x82, 7, 0x81, 0x85, 3, 0x18, 45, 5, 0, 0x43, b'a', b'b', b'c'
            ]),
            "events_next=7;events=seq=3,id=45,type=5,flags=0,payload_hex=616263"
        );
        assert_eq!(render_binary_events(&[0x82, 1]), "invalid_events");
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
    fn proxy_targets_and_requests_use_existing_jsonl_contract() {
        assert_eq!(
            proxy_socket_target("lmesh://lmesh-wifi"),
            Some("/run/mesh/lmesh-wifi/mesh.sock")
        );
        assert_eq!(
            proxy_socket_target("uds:///tmp/lmesh.sock"),
            Some("/tmp/lmesh.sock")
        );
        let request = proxy_request(
            "wifi.raw.check",
            serde_json::json!({"destination":"14:c1:9f:e4:5d:48"}),
            Some("14c19fe45d48".to_owned()),
        )
        .unwrap();
        assert_eq!(request["method"], "wifi.raw.check");
        assert_eq!(request["destination"], "14:c1:9f:e4:5d:48");
        assert_eq!(request["to"], "14c19fe45d48");
        assert!(request["id"].as_str().unwrap().starts_with("dmesh-cli-"));
        assert!(proxy_request("wifi.raw.check", serde_json::json!([]), None).is_err());
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
}
