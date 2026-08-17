//! Direct serial L2 adapter for QUIC-lite host tests.
//!
//! This is intentionally part of `lmesh-uart`, not Recovery or firmware. It
//! opens an explicitly supplied serial port with no managed forward. The
//! optional initial record is opaque: commands/logs remain higher-level
//! transport services and this adapter never decodes them.

use crate::l2::UartEgressPacer;
use dmesh_server::recovery::{IperfRequest, decode_iperf_result, encode_iperf_request};
use quic_lite::{
    path_bridge::{PathBridge, PathBridgeAction},
    uart::encode_uart_datagram,
};
use std::{
    env,
    fs::{File, OpenOptions},
    io::{ErrorKind, Read, Write},
    net::{SocketAddr, UdpSocket},
    os::fd::AsRawFd,
    sync::Arc,
    thread,
    time::{Duration, Instant},
};
use uart_codec::codec::{Decoder, encode_payload};

/// Bearer-neutral path policy accepted by the host CLI and the future
/// `lmesh-wifi` egress handler. The policy chooses among registered paths;
/// it never changes the command, IPERF, or log-watch stream protocol.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientPathPolicy {
    HighestMeasuredSpeed,
    Udp,
    Uart,
    UartSpillover,
}

impl ClientPathPolicy {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "aggregate" | "fastest" => Some(Self::HighestMeasuredSpeed),
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
        }
    }
}

fn usage() -> ! {
    eprintln!(
        "usage: dmesh-iperf SERIAL BOOTSTRAP_BIND BACKEND [--baud PHYSICAL_UART_BAUD] [--bearer uart|udp|aggregate|spill] [--iperf-bytes N] [--parallel-streams 1..4] [--high-priority-bytes N] [--low-priority-bytes N] [--target-bps N] [--timeout-secs N]\n       dmesh-iperf udp://HOST:PORT [--service status|metrics|streams|log-watch] [--body-hex HEX] [--log-records 1..64] [--iperf-bytes N]"
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
        libc::cfmakeraw(&mut value);
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
        if libc::tcsetattr(file.as_raw_fd(), libc::TCSANOW, &value) != 0 {
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

fn send_ppp(serial: &mut File, payload: &[u8]) -> Result<(), String> {
    let wire = encode_payload(payload, quic_lite::DEFAULT_MAX_DATAGRAM_SIZE + 1)
        .map_err(|error| error.to_string())?;
    serial.write_all(&wire).map_err(|error| error.to_string())
}

/// Run the standalone IPERF-compatible client using process arguments.
pub fn run_dmesh_iperf() -> Result<(), String> {
    run_dmesh_iperf_args(env::args().skip(1))
}

/// Run the exact CLI client with supplied arguments. Managed callers use this
/// instead of spawning the executable, so tests, the CLI, and the Wi-Fi
/// gateway keep one L2/session implementation.
pub fn run_dmesh_iperf_args(args: impl IntoIterator<Item = String>) -> Result<(), String> {
    let arguments: Vec<String> = args.into_iter().collect();
    if arguments
        .first()
        .is_some_and(|target| target.starts_with("udp://"))
    {
        return run_udp_service_client(&arguments);
    }
    let mut args = arguments.into_iter();
    let path = args.next().unwrap_or_else(|| usage());
    let bootstrap: SocketAddr = args
        .next()
        .unwrap_or_else(|| usage())
        .parse::<SocketAddr>()
        .map_err(|error| error.to_string())?;
    let backend: SocketAddr = args
        .next()
        .unwrap_or_else(|| usage())
        .parse::<SocketAddr>()
        .map_err(|error| error.to_string())?;
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
        return Err("choose --iperf-bytes or --direct-hex, not both".into());
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
            let run_id = run_id();
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
            request.path_policy = 0;
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
    let mut serial = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(|error| error.to_string())?;
    configure_serial(&serial, baud)?;
    if let Some(record) = direct {
        send_ppp(&mut serial, &record)?;
    }

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
                        ClientPathPolicy::UartSpillover => {
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
                    match quic_lite::uart::classify_uart_payload(&record) {
                        Ok(quic_lite::uart::UartIngress::Transport(packet)) => {
                            egress.on_path_feedback();
                            if let PathBridgeAction::ToBackend(packet) =
                                bridge.on_secondary_path(packet)
                            {
                                socket
                                    .send_to(packet, backend)
                                    .map_err(|error| error.to_string())?;
                            }
                        }
                        Ok(quic_lite::uart::UartIngress::DirectRecord(record)) => {
                            // Keep direct records opaque. A caller may attach a
                            // log/command service observer without making this
                            // UART L2 adapter depend on its schema.
                            eprintln!(
                                "uart_direct_record bytes={} hex={}",
                                record.len(),
                                hex_encode(record)
                            );
                            if let Some(run_id) = iperf_run_id {
                                if let Some(result) = decode_iperf_result(record)
                                    .filter(|result| result.run_id == run_id)
                                {
                                    let expected = iperf_expected_bytes.unwrap_or(result.bytes);
                                    println!(
                                        "dmesh_iperf_result bearer={} run_id={run_id} bytes={} normal_bytes={} high_bytes={} low_bytes={} elapsed_us={} bps={} primary_packets={} secondary_packets={}",
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
            "dmesh_iperf_timeout bearer={} run_id={run_id} server_stats={:?}",
            bearer_name(host_policy),
            control.server_stats()
        );
    }
    Err("UART L2 bridge timed out".into())
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
        .ok_or("UDP target must use udp://HOST:PORT")?
        .parse::<SocketAddr>()
        .map_err(|error| error.to_string())?;
    let mut service = quic_lite::SERVICE_STATUS;
    let mut body = Vec::new();
    let mut iperf_bytes = None;
    let mut log_records = None;
    let mut index = 1;
    while index < arguments.len() {
        match arguments[index].as_str() {
            "--service" => {
                index += 1;
                let name = arguments.get(index).ok_or("missing --service value")?;
                service = match name.as_str() {
                    "status" => quic_lite::SERVICE_STATUS,
                    "metrics" => quic_lite::SERVICE_METRICS,
                    "streams" => quic_lite::SERVICE_STREAM,
                    "log-watch" => quic_lite::SERVICE_LOG_WATCH,
                    "control" => quic_lite::SERVICE_CONTROL,
                    _ => {
                        return Err(
                            "service must be status, metrics, streams, log-watch, or control"
                                .into(),
                        );
                    }
                };
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
        body.extend_from_slice(&bytes.to_be_bytes());
        body.extend_from_slice(&1200u16.to_be_bytes());
    }
    let mut request = Vec::with_capacity(1 + body.len());
    request.push(service);
    request.extend_from_slice(&body);
    let cid = quic_lite::ConnectionId::new(u64::from(run_id()))
        .ok_or("could not allocate UDP client CID")?;
    let runtime = tokio::runtime::Runtime::new().map_err(|error| error.to_string())?;
    runtime.block_on(async move {
        let mut client = dmesh_server::udp::UdpClient::connect(
            "0.0.0.0:0".parse().expect("valid UDP bind"),
            peer,
            cid,
        )
        .await
        .map_err(|error| error.to_string())?;
        let (stream, response, fin) = client
            .request_stream(quic_lite::FIRST_CLIENT_BIDI_STREAM_ID, &request, true)
            .await
            .map_err(|error| error.to_string())?;
        println!(
            "dmesh_client_response target={peer} service={service} stream={stream} fin={fin} bytes={} hex={}",
            response.len(),
            hex_encode(&response)
        );
        Ok(())
    })
}

fn bearer_name(path_policy: ClientPathPolicy) -> &'static str {
    match path_policy {
        ClientPathPolicy::Udp => "udp",
        ClientPathPolicy::Uart => "uart",
        ClientPathPolicy::UartSpillover => "uart-spill-udp",
        ClientPathPolicy::HighestMeasuredSpeed => "uart+udp",
    }
}

fn run_id() -> u32 {
    let value = Instant::now().elapsed().as_nanos() as u32 ^ std::process::id();
    value.max(1)
}

#[cfg(test)]
mod tests {
    use super::ClientPathPolicy;

    #[test]
    fn path_policy_aliases_and_firmware_values_are_stable() {
        assert_eq!(
            ClientPathPolicy::parse("aggregate"),
            Some(ClientPathPolicy::HighestMeasuredSpeed)
        );
        assert_eq!(
            ClientPathPolicy::parse("fastest"),
            ClientPathPolicy::parse("aggregate")
        );
        assert_eq!(ClientPathPolicy::parse("udp").unwrap().wire(), 1);
        assert_eq!(ClientPathPolicy::parse("uart").unwrap().wire(), 2);
        assert_eq!(ClientPathPolicy::parse("spill").unwrap().wire(), 3);
        assert_eq!(ClientPathPolicy::parse("ESP-NOW"), None);
    }
}
