//! Feature-gated host UDP QUIC server and connection/mux harness.
//!
//! UDP is the datagram bearer. The first packet creates a connection keyed by
//! its opaque DCID; subsequent packets are routed to that connection. Stream
//! services run above the endpoint. The object store is the production service
//! currently installed here, while the same connection table is intended for
//! additional host-test services on other stream IDs.

use crate::services::{
    CONTROL_PATH_POLICY, CONTROL_RESPONSE, decode_path_policy, dispatch_tagged_stream,
    handle_stream_with_events,
};
pub use crate::services::{EventRing, StreamHandler, StreamRegistry};
use crate::{ObjectServer, ServerConfig};
use crate::{
    iperf::{IperfServicePlan, IperfServiceRequest, decode_iperf_service_request},
    protocol::ObjectRecordStream,
};
use anyhow::{Context, Result, bail};
use quic_lite::ledger::{
    LedgerCapacityController, LedgerMemoryPolicy, LedgerMemorySnapshot, select_capacity,
    system_memory_snapshot,
};
use quic_lite::mux::StreamMux;
use quic_lite::{ConnectionLimits, EndpointState, INITIAL_MAX_STREAM_DATA, PathPolicy, Role};
use std::boxed::Box;
use std::collections::{HashMap, VecDeque};
use std::eprintln;
use std::format;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::string::String;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::vec::Vec;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time::{Duration, Instant, timeout};

const MTU: usize = quic_lite::DEFAULT_MAX_DATAGRAM_SIZE;
/// Stable `lmesh-wifi`/wlan0 object and IPERF listener.
pub const STABLE_WIFI_UDP_PORT: u16 = 3336;
/// Development `lmesh`/wlan1 listener.  It must not collide with wlan0.
pub const DEVELOPMENT_WIFI_UDP_PORT: u16 = 3337;
/// Reserved local port for `dmesh-cli` session/driver endpoints.
pub const DMESH_CLI_UDP_PORT: u16 = 3338;
/// Raw IPv6 firmware bearer port (outside host UDP listener ownership).
pub const RAW_UDP6_PORT: u16 = 3339;
// Object records leave frame/control headroom inside the single shared bearer
// MTU. No UDP-only payload expansion is permitted while action frames remain
// capped at this bound.
const OBJECT_CHUNK: usize = MTU - 64;
const MAX_OBJECT_CHUNK: usize = MTU - 64;
const UDP_MIN_RETRANSMIT_PTO_MS: u64 = 250;
// The Linux default UDP receive queue is smaller than a normal host benchmark
// flight.  A host-side socket drop hides the ACK range that would trigger
// recovery and turns a loopback measurement into a scheduler artefact.  This
// is deliberately host-only: embedded receive budgets remain negotiated in
// the bootstrap/profile, not enlarged by a socket setting.
const HOST_UDP_SOCKET_BUFFER_BYTES: libc::c_int = 4 * 1024 * 1024;
// A sender that has just declared loss needs a small amount of temporal
// separation between subsequent new datagrams.  This is scheduler policy
// derived from transport feedback, not a bearer ACK/retry mechanism.  Keep
// it bounded: Wi-Fi needs microsecond-scale spacing, while a long fixed delay
// would recreate stop-and-wait on a clean link.
const ADAPTIVE_PACING_MIN: Duration = Duration::from_micros(125);
const ADAPTIVE_PACING_MAX: Duration = Duration::from_millis(2);
const ADAPTIVE_PACING_CLEAN_ACKS: u64 = 32;
// An object transfer must keep its connection scheduler responsive to a
// delayed ACK/window update. This is a wakeup bound, not sender pacing.
const ACTIVE_OBJECT_SCHEDULER_TICK: Duration = Duration::from_millis(1);
/// One ordered object-response stream: manifest, blobs, then done.
const OBJECT_STREAM: u64 = 3;
const ACK_TIMEOUT: Duration = Duration::from_millis(500);
const BOOTSTRAP_ATTEMPTS: u32 = 4;
const STREAM_ATTEMPTS: u32 = 4;
const MAX_ACTIVE_CONNECTIONS: usize = 64;
// A host IPERF receiver can acknowledge a full congestion window faster than
// the per-connection task observes it.  This remains bounded and is host-only
// routing state; tearing down the route on a transient full queue loses the
// ACK frontier and prevents PTO recovery entirely.
const CONNECTION_DATAGRAM_QUEUE_CAPACITY: usize = 1024;
/// Fixed bound shared with the no_std Recovery IPERF receiver.
const MAX_IPERF_STREAMS: usize = 4;
// Host UDP IPERF can refill a full host ledger in one scheduler pass. Device
// receivers still bound the effective burst through their advertised packet
// flight limit, so this does not enlarge Recovery/ESP receive memory.
const HOST_IPERF_NORMAL_REFILL_PACKETS: usize = 64;
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);
static NEXT_SERVER_CID: AtomicU64 = AtomicU64::new(0x100);

/// First byte on an application stream selects the connection service.
/// Remaining bytes belong to that service's schema.
pub use quic_lite::{
    SERVICE_CONTROL, SERVICE_ECHO, SERVICE_EVENTS, SERVICE_IPERF, SERVICE_METRICS, SERVICE_OBJECT,
    SERVICE_STATUS, SERVICE_STREAM,
};

const CONTROL_LOG: u8 = 0;
const CONTROL_POLL: u8 = 1;
/// Object streaming is the normal Recovery workload. ACK=8 keeps reverse
/// traffic sparse enough to preserve a useful forward burst, while the 5 ms
/// cap repairs a short/cwnd-limited burst promptly.
const RECOVERY_OBJECT_ACK_FREQUENCY: u8 = 8;
const RECOVERY_MAX_ACK_DELAY_US: u64 = 5_000;
const CONTROL_QUEUE_CAPACITY: usize = 64;

/// Decode the transport-service envelope for an object GET.  The CBOR bytes
/// themselves remain the canonical object-store request; the optional byte
/// before them is an association parameter selected for this connection.
/// Older `[SERVICE_OBJECT, CBOR-GET...]` clients remain valid.
fn object_request_envelope(request: &[u8]) -> Result<(u8, &[u8])> {
    let Some((&service, body)) = request.split_first() else {
        bail!("empty object request");
    };
    if service != SERVICE_OBJECT {
        bail!("not an object request");
    }
    match body.first().copied() {
        Some(1..=32) => Ok((body[0], &body[1..])),
        Some(_) => Ok((RECOVERY_OBJECT_ACK_FREQUENCY, body)),
        None => bail!("missing object GET"),
    }
}

/// Bounded command/log bridge for a transport test scaffold or a future
/// managed control service. Its contents are opaque compact CBOR records;
/// only Recovery's shared command parser interprets commands.
#[derive(Debug)]
pub struct TransportControl {
    commands: Mutex<VecDeque<Vec<u8>>>,
    logs: Mutex<VecDeque<QueuedLogRecord>>,
    log_dropped_full: AtomicU64,
    stats: Mutex<Option<ServerTransportStats>>,
    errors: Mutex<VecDeque<String>>,
    events: Mutex<VecDeque<String>>,
    path_policy: Mutex<PathPolicy>,
}

/// Opaque log retention state.  It is intentionally a service-level metric:
/// the QUIC-lite endpoint only sees stream bytes and credit, never log policy.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct LogQueueStats {
    pub queued_records: usize,
    pub dropped_full: u64,
    pub oldest_age_ms: u64,
}

#[derive(Debug)]
struct QueuedLogRecord {
    bytes: Vec<u8>,
    received_at: Instant,
}

/// Opaque sender-side snapshot for a bearer status surface.  It deliberately
/// exposes aggregates only: callers must not parse ACKs, packet numbers, or
/// transport frames to diagnose a live transfer.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ServerTransportStats {
    pub history_len: usize,
    pub history_capacity: usize,
    pub peer_max_in_flight_packets: usize,
    pub bytes_in_flight: u64,
    pub congestion_window: u64,
    pub largest_acked_by_peer: Option<u32>,
    pub transport: quic_lite::TransportStats,
}

impl TransportControl {
    /// The active policy is generic over UDP/UART/LoRa/action-frame paths.
    /// Authentication/authorization belongs to the future end-to-end layer,
    /// not to this untrusted bearer control codec.
    pub fn path_policy(&self) -> PathPolicy {
        *self.path_policy.lock().expect("path policy lock")
    }

    pub fn set_path_policy(&self, policy: PathPolicy) {
        *self.path_policy.lock().expect("path policy lock") = policy;
    }
    pub fn server_stats(&self) -> Option<ServerTransportStats> {
        *self.stats.lock().ok()?
    }
    fn record_server_stats<const H: usize>(&self, endpoint: &EndpointState<8, H>) {
        if let Ok(mut stats) = self.stats.lock() {
            *stats = Some(ServerTransportStats {
                history_len: endpoint.history_len(),
                history_capacity: endpoint.history_capacity(),
                peer_max_in_flight_packets: endpoint.peer_max_in_flight_packets(),
                bytes_in_flight: endpoint.bytes_in_flight(),
                congestion_window: endpoint.congestion.congestion_window,
                largest_acked_by_peer: endpoint.largest_acked_by_peer(),
                transport: endpoint.stats(),
            });
        }
    }
    fn record_error(&self, error: impl Into<String>) {
        let mut errors = self.errors.lock().expect("control errors lock");
        if errors.len() == CONTROL_QUEUE_CAPACITY {
            errors.pop_front();
        }
        errors.push_back(error.into());
    }
    pub fn take_errors(&self) -> Vec<String> {
        self.errors
            .lock()
            .expect("control errors lock")
            .drain(..)
            .collect()
    }
    fn record_event(&self, event: impl Into<String>) {
        let mut events = self.events.lock().expect("control events lock");
        if events.len() == CONTROL_QUEUE_CAPACITY {
            events.pop_front();
        }
        events.push_back(event.into());
    }
    pub fn take_events(&self) -> Vec<String> {
        self.events
            .lock()
            .expect("control events lock")
            .drain(..)
            .collect()
    }

    /// Non-destructive bounded diagnostics for a long-running listener.
    pub fn errors(&self) -> Vec<String> {
        self.errors
            .lock()
            .expect("control errors lock")
            .iter()
            .cloned()
            .collect()
    }

    /// Non-destructive bounded events for a long-running listener.
    pub fn events(&self) -> Vec<String> {
        self.events
            .lock()
            .expect("control events lock")
            .iter()
            .cloned()
            .collect()
    }
    pub fn queue_command(&self, record: Vec<u8>) {
        let mut commands = self.commands.lock().expect("control commands lock");
        if commands.len() == CONTROL_QUEUE_CAPACITY {
            commands.pop_front();
        }
        commands.push_back(record);
    }

    pub fn take_log(&self) -> Option<Vec<u8>> {
        self.logs
            .lock()
            .expect("control logs lock")
            .pop_front()
            .map(|record| record.bytes)
    }

    pub fn log_stats(&self) -> LogQueueStats {
        let logs = self.logs.lock().expect("control logs lock");
        LogQueueStats {
            queued_records: logs.len(),
            dropped_full: self.log_dropped_full.load(Ordering::Relaxed),
            oldest_age_ms: logs
                .front()
                .map(|record| record.received_at.elapsed().as_millis() as u64)
                .unwrap_or(0),
        }
    }

    fn receive_log(&self, record: &[u8]) {
        let mut logs = self.logs.lock().expect("control logs lock");
        if logs.len() == CONTROL_QUEUE_CAPACITY {
            logs.pop_front();
            self.log_dropped_full.fetch_add(1, Ordering::Relaxed);
        }
        logs.push_back(QueuedLogRecord {
            bytes: record.to_vec(),
            received_at: Instant::now(),
        });
    }

    fn next_response(&self) -> Vec<u8> {
        let command = self
            .commands
            .lock()
            .expect("control commands lock")
            .pop_front();
        let mut response = Vec::with_capacity(2 + command.as_ref().map_or(0, Vec::len));
        response.push(SERVICE_CONTROL);
        response.push(CONTROL_RESPONSE);
        if let Some(command) = command {
            response.extend_from_slice(&command);
        }
        response
    }
}

impl Default for TransportControl {
    fn default() -> Self {
        Self {
            commands: Mutex::new(VecDeque::new()),
            logs: Mutex::new(VecDeque::new()),
            log_dropped_full: AtomicU64::new(0),
            stats: Mutex::new(None),
            errors: Mutex::new(VecDeque::new()),
            events: Mutex::new(VecDeque::new()),
            path_policy: Mutex::new(PathPolicy::HighestMeasuredSpeed),
        }
    }
}

struct ConnectionDatagram {
    peer: SocketAddr,
    bytes: Vec<u8>,
}

/// Bootstrap shares the endpoint packet-number space until the first
/// established packet is processed. The listener owns OPEN_ACK retries, while
/// the persistent task raises its sender floor from this state before emitting
/// application traffic.
struct BootstrapPacketNumbers {
    next: AtomicU32,
    application_started: AtomicBool,
}

struct PendingObjectTransfer {
    stream: ObjectRecordStream,
    chunk_size: usize,
    pacer: AdaptivePacer,
    first_send: Option<Instant>,
    sent_datagrams: u64,
}

/// Transport-only response source for IPERF. It deliberately has no object
/// record header, manifest, store lookup, or flash semantics.
struct PendingByteTransfer {
    stream_id: u64,
    offset: u64,
    remaining: usize,
    chunk_size: usize,
    packet_id: u32,
    pace: Duration,
    burst_packets: usize,
    burst_delay: Duration,
    pacer: AdaptivePacer,
    /// Host-side scheduler evidence for one transport IPERF response.  This
    /// is deliberately aggregate-only: logging a datagram would itself
    /// perturb the Wi-Fi benchmark.
    first_send: Option<Instant>,
    last_send: Option<Instant>,
    sent_datagrams: u64,
    window_fills: u64,
    max_window_fill: u64,
    interpacket_gaps: [u64; 6],
}

/// Conservative feedback pacer shared by object and byte response streams.
/// It starts disabled. A transport-declared repair enables a bounded delay
/// based on the observed RTT and current congestion window; clean ACK
/// progress progressively removes it. The scheduler merely decides when to
/// call `send_to`; all ACK, loss, credit, and retransmission semantics remain
/// in `EndpointState`.
#[derive(Clone, Copy, Debug)]
struct AdaptivePacer {
    delay: Duration,
    next_send: Instant,
    seen_loss_repairs: u64,
    seen_control_datagrams: u64,
    clean_acks: u64,
    activations: u64,
}

impl AdaptivePacer {
    fn new() -> Self {
        Self {
            delay: Duration::ZERO,
            next_send: Instant::now(),
            seen_loss_repairs: 0,
            seen_control_datagrams: 0,
            clean_acks: 0,
            activations: 0,
        }
    }

    fn observe(
        &mut self,
        stats: quic_lite::TransportStats,
        smoothed_rtt_ms: Option<u64>,
        congestion_window: u64,
        max_datagram_size: u64,
    ) {
        let repairs = stats
            .loss_retransmitted_datagrams
            .saturating_add(stats.pto_retransmitted_datagrams);
        let new_repairs = repairs.saturating_sub(self.seen_loss_repairs);
        self.seen_loss_repairs = repairs;
        let controls = stats.control_datagrams;
        let new_controls = controls.saturating_sub(self.seen_control_datagrams);
        self.seen_control_datagrams = controls;
        if new_repairs != 0 {
            let packets = (congestion_window / max_datagram_size.max(1)).max(1);
            let target = Duration::from_micros(
                smoothed_rtt_ms
                    .unwrap_or(5)
                    .saturating_mul(1_000)
                    .saturating_div(packets),
            )
            .clamp(ADAPTIVE_PACING_MIN, ADAPTIVE_PACING_MAX);
            self.delay = self
                .delay
                .saturating_mul(2)
                .max(target)
                .min(ADAPTIVE_PACING_MAX);
            self.clean_acks = 0;
            self.activations = self.activations.saturating_add(1);
            return;
        }
        if self.delay.is_zero() || new_controls == 0 {
            return;
        }
        self.clean_acks = self.clean_acks.saturating_add(new_controls);
        while self.clean_acks >= ADAPTIVE_PACING_CLEAN_ACKS {
            self.clean_acks -= ADAPTIVE_PACING_CLEAN_ACKS;
            let relaxed = self.delay / 2;
            self.delay = if relaxed <= ADAPTIVE_PACING_MIN {
                Duration::ZERO
            } else {
                relaxed
            };
            if self.delay.is_zero() {
                self.clean_acks = 0;
                break;
            }
        }
    }

    fn ready(&self) -> bool {
        Instant::now() >= self.next_send
    }

    fn sent(&mut self, explicit_delay: Duration) {
        let delay = if explicit_delay.is_zero() {
            self.delay
        } else {
            explicit_delay
        };
        self.next_send = Instant::now() + delay;
    }

    fn next_delay(&self, explicit_delay: Duration) -> Option<Duration> {
        if explicit_delay.is_zero() && self.delay.is_zero() {
            return None;
        }
        Some(self.next_send.saturating_duration_since(Instant::now()))
    }
}

fn interpacket_gap_bucket(gap: Duration) -> usize {
    quic_lite::interpacket_gap_bucket(gap.as_micros().try_into().unwrap_or(u64::MAX))
}

/// Read optional, request-scoped IPERF scheduling controls.  The fixed first
/// 11 bytes remain the compatibility schema (`service`, byte count, packet
/// size); absent trailing fields deliberately inherit the listener defaults.
fn iperf_schedule(
    request: IperfServiceRequest,
    default_pace: Duration,
    default_burst_packets: usize,
    default_burst_delay: Duration,
) -> (Duration, usize, Duration, u8, u64) {
    let pace = request
        .pace_us
        .map(|pace| Duration::from_micros(u64::from(pace)))
        .unwrap_or(default_pace);
    let burst_packets = request
        .burst_packets
        .map(usize::from)
        .unwrap_or(default_burst_packets);
    let burst_delay = request
        .burst_delay_us
        .map(|delay| Duration::from_micros(u64::from(delay)))
        .unwrap_or(default_burst_delay);
    // ACK_FREQUENCY's wire threshold is one below the human-facing packet
    // ratio. Keep it request-scoped so a benchmark does not depend on a
    // local-only Recovery setting that the peer can silently overwrite.
    // ACK_FREQUENCY encodes the threshold as `frequency - 1`; the endpoint
    // can retain at most ACK_RANGE_CAPACITY ranges. Clamp at the same bound
    // as Recovery's command parser so a malformed request cannot start an
    // IPERF transfer while silently failing to install its advertised policy.
    let ack_frequency = request
        .ack_frequency
        .unwrap_or(2)
        .clamp(1, quic_lite::ACK_RANGE_CAPACITY as u8);
    let ack_delay_us = request
        .ack_delay_ms
        .map(|milliseconds| u64::from(milliseconds.clamp(1, 25)) * 1_000)
        .unwrap_or(RECOVERY_MAX_ACK_DELAY_US);
    (
        pace,
        burst_packets,
        burst_delay,
        ack_frequency,
        ack_delay_us,
    )
}

impl PendingByteTransfer {
    fn new(
        stream_id: u64,
        bytes: usize,
        chunk_size: usize,
        pace: Duration,
        burst_packets: usize,
        burst_delay: Duration,
    ) -> Self {
        Self {
            stream_id,
            offset: 0,
            remaining: bytes,
            chunk_size,
            packet_id: 0,
            pace,
            burst_packets,
            burst_delay,
            pacer: AdaptivePacer::new(),
            first_send: None,
            last_send: None,
            sent_datagrams: 0,
            window_fills: 0,
            max_window_fill: 0,
            interpacket_gaps: [0; 6],
        }
    }
}

fn report_byte_transfer<const H: usize>(
    transfer: &PendingByteTransfer,
    endpoint: &EndpointState<8, H>,
) {
    let stats = endpoint.stats();
    let elapsed_us = transfer
        .first_send
        .map(|first| first.elapsed().as_micros())
        .unwrap_or(0);
    eprintln!(
        "iperf_udp_send_summary stream={} datagrams={} endpoint_stream={} endpoint_control={} history={}/{} peer_flight={} cwnd={} inflight={} fills={} max_fill={} pace_us={} pace_activations={} elapsed_us={} \
         gaps=<1ms:{},1-5ms:{},5-10ms:{},10-25ms:{},25-50ms:{},>=50ms:{} \
         loss=gap:{} time:{} events:{} loss_retx:{} pto_retx:{}",
        transfer.stream_id,
        transfer.sent_datagrams,
        stats.sent_stream_datagrams,
        stats.sent_control_datagrams,
        endpoint.history_len(),
        endpoint.history_capacity(),
        endpoint.peer_max_in_flight_packets(),
        endpoint.congestion.congestion_window,
        endpoint.bytes_in_flight(),
        transfer.window_fills,
        transfer.max_window_fill,
        transfer.pacer.delay.as_micros(),
        transfer.pacer.activations,
        elapsed_us,
        transfer.interpacket_gaps[0],
        transfer.interpacket_gaps[1],
        transfer.interpacket_gaps[2],
        transfer.interpacket_gaps[3],
        transfer.interpacket_gaps[4],
        transfer.interpacket_gaps[5],
        stats.loss_packet_threshold_datagrams,
        stats.loss_time_threshold_datagrams,
        stats.loss_events,
        stats.loss_retransmitted_datagrams,
        stats.pto_retransmitted_datagrams,
    );
}

fn report_object_transfer(transfer: &PendingObjectTransfer, stats: quic_lite::TransportStats) {
    let elapsed_us = transfer
        .first_send
        .map(|first| first.elapsed().as_micros())
        .unwrap_or(0);
    eprintln!(
        "object_udp_send_summary bytes={} datagrams={} endpoint_stream={} endpoint_control={} pace_us={} pace_activations={} elapsed_us={} loss=gap:{} time:{} loss_retx:{} pto_retx:{}",
        transfer.stream.sent_bytes(),
        transfer.sent_datagrams,
        stats.sent_stream_datagrams,
        stats.sent_control_datagrams,
        transfer.pacer.delay.as_micros(),
        transfer.pacer.activations,
        elapsed_us,
        stats.loss_packet_threshold_datagrams,
        stats.loss_time_threshold_datagrams,
        stats.loss_retransmitted_datagrams,
        stats.pto_retransmitted_datagrams,
    );
}

impl PendingObjectTransfer {
    #[cfg(test)]
    fn new(records: Vec<(u8, Vec<u8>)>) -> Self {
        Self::with_chunk(records, OBJECT_CHUNK)
    }

    fn with_chunk(records: Vec<(u8, Vec<u8>)>, chunk_size: usize) -> Self {
        assert!((1..=MAX_OBJECT_CHUNK).contains(&chunk_size));
        Self {
            stream: ObjectRecordStream::new(records),
            chunk_size,
            pacer: AdaptivePacer::new(),
            first_send: None,
            sent_datagrams: 0,
        }
    }
}

#[derive(Clone, Debug)]
pub struct UdpConfig {
    pub bind: SocketAddr,
    pub artifact_root: PathBuf,
    /// Active retransmission slots per server-side endpoint. Zero selects a
    /// capacity from the host memory policy; non-zero is an explicit override.
    pub history_capacity: usize,
    /// Memory policy used when `history_capacity` is zero.
    pub ledger_memory_policy: LedgerMemoryPolicy,
    /// Optional deterministic memory snapshot for tests and operators. When
    /// absent, the adapter samples `/proc/meminfo` and falls back safely.
    pub ledger_memory: Option<LedgerMemorySnapshot>,
    /// Maximum number of simultaneously routed server-side connections.
    pub max_active_connections: usize,
    /// How long a routed connection may remain idle before its CID is evicted.
    pub idle_timeout: Duration,
    /// Receive-loop tick used to run idle cleanup even when no datagrams arrive.
    pub receive_timeout: Duration,
    /// Host ledger memory resampling interval. Zero disables runtime resizing.
    pub ledger_resize_interval: Duration,
    /// Application payload size for object datagrams. This is independent of
    /// the transport window: even small diagnostic records must still be sent
    /// in flight as a window, not as stop-and-wait packets.
    pub object_chunk: usize,
    /// Optional host-only interval between transport IPERF response packets.
    /// Zero preserves flood behavior. This is a diagnostic knob, not a
    /// transport reliability mechanism.
    pub iperf_pace: Duration,
    /// Test-only maximum IPERF datagrams in one sender pass. Zero preserves
    /// the normal unlimited congestion-window fill.
    pub iperf_burst_packets: usize,
    /// Test-only wait after an IPERF burst. Zero preserves unpaced sending.
    pub iperf_burst_delay: Duration,
    /// Optional IPv4 DSCP/TOS applied to this listener's outbound datagrams.
    /// It is a host-bearer diagnostic only; `None` preserves best-effort.
    pub ip_tos: Option<u8>,
    /// Optional opaque Recovery command/log mailbox. Normal object serving
    /// leaves it unset; host hardware tests can install it on a third port.
    pub control: Option<Arc<TransportControl>>,
}

impl Default for UdpConfig {
    fn default() -> Self {
        Self {
            bind: SocketAddr::from(([0, 0, 0, 0], STABLE_WIFI_UDP_PORT)),
            artifact_root: PathBuf::from("."),
            history_capacity: 0,
            ledger_memory_policy: LedgerMemoryPolicy::default(),
            ledger_memory: None,
            max_active_connections: MAX_ACTIVE_CONNECTIONS,
            idle_timeout: IDLE_TIMEOUT,
            receive_timeout: Duration::from_secs(1),
            ledger_resize_interval: Duration::from_secs(5),
            object_chunk: OBJECT_CHUNK,
            iperf_pace: Duration::ZERO,
            iperf_burst_packets: 0,
            iperf_burst_delay: Duration::ZERO,
            ip_tos: None,
            control: None,
        }
    }
}

#[cfg(unix)]
fn configure_ipv4_tos(socket: &UdpSocket, tos: u8) -> Result<()> {
    use std::os::fd::AsRawFd;

    let value = libc::c_int::from(tos);
    let result = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::IPPROTO_IP,
            libc::IP_TOS,
            (&value as *const libc::c_int).cast(),
            core::mem::size_of_val(&value) as libc::socklen_t,
        )
    };
    if result != 0 {
        bail!(
            "set IP_TOS=0x{tos:02x}: {}",
            std::io::Error::last_os_error()
        );
    }
    Ok(())
}

#[cfg(unix)]
fn configure_host_udp_buffers(socket: &UdpSocket) -> Result<()> {
    use std::os::fd::AsRawFd;

    for option in [libc::SO_RCVBUF, libc::SO_SNDBUF] {
        let result = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::SOL_SOCKET,
                option,
                (&HOST_UDP_SOCKET_BUFFER_BYTES as *const libc::c_int).cast(),
                core::mem::size_of_val(&HOST_UDP_SOCKET_BUFFER_BYTES) as libc::socklen_t,
            )
        };
        if result != 0 {
            bail!(
                "set UDP socket buffer option {option}: {}",
                std::io::Error::last_os_error()
            );
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn configure_host_udp_buffers(_socket: &UdpSocket) -> Result<()> {
    Ok(())
}

#[cfg(not(unix))]
fn configure_ipv4_tos(_socket: &UdpSocket, tos: u8) -> Result<()> {
    bail!("IP_TOS=0x{tos:02x} is unsupported on this host")
}

#[cfg(all(test, unix))]
fn socket_ipv4_tos(socket: &UdpSocket) -> Result<u8> {
    use std::os::fd::AsRawFd;

    let mut value = 0i32;
    let mut size = core::mem::size_of_val(&value) as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::IPPROTO_IP,
            libc::IP_TOS,
            (&mut value as *mut libc::c_int).cast(),
            &mut size,
        )
    };
    if result != 0 {
        bail!("get IP_TOS: {}", std::io::Error::last_os_error());
    }
    Ok(value as u8)
}

/// Minimal host client for the feature-gated UDP QUIC bearer. It owns one
/// transport connection and exposes only datagram/stream operations; service
/// schemas remain above this type.
pub struct UdpClient {
    socket: UdpSocket,
    peer: SocketAddr,
    endpoint: EndpointState<8, 512>,
    local_cid: quic_lite::ConnectionId,
    deferred_receive_credit: bool,
}

/// One committed server-initiated stream frame. This keeps offset and FIN
/// visible to diagnostic clients such as IPERF without exposing any socket or
/// bearer-specific framing above `UdpClient`.
#[derive(Debug)]
pub struct ReceivedStream {
    pub id: u64,
    pub offset: u64,
    pub fin: bool,
    pub data: Vec<u8>,
}

impl UdpClient {
    /// Snapshot endpoint-owned loss, retransmission, ACK, and ordering
    /// counters for a completed diagnostic transfer. The socket adapter does
    /// not infer these from packet timing; QUIC-lite remains the authority.
    pub const fn transport_stats(&self) -> quic_lite::TransportStats {
        self.endpoint.stats()
    }

    /// Explicitly retire this diagnostic association on its bearer.  Dropping
    /// a UDP socket does not notify a fixed-size embedded service dispatcher;
    /// callers that run repeated probes must send CLOSE so the peer can admit
    /// the next fresh connection without waiting for an idle timeout.
    pub async fn close(&mut self, code: u64) -> Result<()> {
        self.endpoint.close(code);
        let mut packet = [0u8; MTU];
        if let Some(used) = self
            .endpoint
            .poll_close(&mut packet)
            .map_err(|error| anyhow::anyhow!("UDP close: {error:?}"))?
        {
            self.socket.send_to(&packet[..used], self.peer).await?;
        }
        Ok(())
    }

    /// Allow a high-rate receiver to batch ACK/window control at the
    /// negotiated cadence. Generic request/object clients retain immediate
    /// credit because their application sinks may block between records.
    pub fn set_deferred_receive_credit(&mut self, enabled: bool) {
        self.deferred_receive_credit = enabled;
    }
    /// Set the local delayed-ACK packet threshold for a diagnostic client.
    /// The wire ACK logic remains in `EndpointState`.
    pub fn set_ack_frequency(&mut self, frequency: u8) {
        self.endpoint.set_ack_frequency(frequency);
    }

    /// Lower the active retransmission ledger for this side. The endpoint's
    /// static host profile remains the upper bound.
    pub fn set_history_capacity(&mut self, limit: usize) -> Result<()> {
        self.endpoint
            .set_history_capacity(limit)
            .map_err(|error| anyhow::anyhow!("UDP history capacity: {error:?}"))
    }

    /// Establish a directional-CID connection using the version-0 short
    /// header bootstrap on stream 0 and reserved `DCID=0`.
    pub async fn connect(
        bind: SocketAddr,
        peer: SocketAddr,
        local_cid: quic_lite::ConnectionId,
    ) -> Result<Self> {
        Self::connect_with_history_capacity(bind, peer, local_cid, 512).await
    }

    pub async fn connect_with_history_capacity(
        bind: SocketAddr,
        peer: SocketAddr,
        local_cid: quic_lite::ConnectionId,
        history_capacity: usize,
    ) -> Result<Self> {
        Self::connect_with_limits(
            bind,
            peer,
            local_cid,
            history_capacity,
            ConnectionLimits::default(),
        )
        .await
    }

    /// Connect with an explicit local receive window. This mirrors Recovery's
    /// bounded bootstrap profile in host regression tests.
    pub async fn connect_with_limits(
        bind: SocketAddr,
        peer: SocketAddr,
        local_cid: quic_lite::ConnectionId,
        history_capacity: usize,
        limits: ConnectionLimits,
    ) -> Result<Self> {
        if local_cid.value() == 0 {
            bail!("bootstrap local CID must be non-zero");
        }
        if !(1..=512).contains(&history_capacity) {
            bail!("UDP history capacity must be in 1..=512");
        }
        let socket = UdpSocket::bind(bind).await?;
        configure_host_udp_buffers(&socket)?;
        let mut client = Self {
            socket,
            peer,
            endpoint: EndpointState::new_with_history_capacity(
                Role::Client,
                limits,
                MTU as u64,
                history_capacity,
            ),
            local_cid: local_cid,
            deferred_receive_credit: false,
        };
        let mut response = [0u8; MTU];
        // A bootstrap timeout used to discard the only evidence of an L2
        // response.  Keep the client bearer-neutral but preserve a compact
        // diagnostic so an AP-relayed UDP test can distinguish no return
        // packet from a malformed or misrouted one.
        let mut last_observation = None;
        for packet_number in 0..BOOTSTRAP_ATTEMPTS {
            let mut open = [0u8; MTU];
            let used = quic_lite::encode_bootstrap_open_packet_with_limits(
                local_cid,
                packet_number,
                limits,
                &mut open,
            )
            .map_err(|error| anyhow::anyhow!("bootstrap OPEN: {error:?}"))?;
            client.socket.send_to(&open[..used], client.peer).await?;
            let received = timeout(ACK_TIMEOUT, client.socket.recv_from(&mut response)).await;
            let Ok(Ok((len, response_peer))) = received else {
                continue;
            };
            if response_peer != client.peer {
                last_observation = Some(format!(
                    "reply_peer={} expected_peer={} bytes={len}",
                    response_peer, client.peer
                ));
                continue;
            }
            let (header, ack) = match quic_lite::decode_bootstrap_open_ack_packet_with_limits(
                &response[..len],
                local_cid,
            ) {
                Ok(value) => value,
                Err(error) => {
                    last_observation = Some(format!("invalid_ack bytes={len} error={error:?}"));
                    continue;
                }
            };
            let server_cid = ack.server_receive_cid;
            if header.dcid != local_cid || server_cid.value() == 0 {
                last_observation = Some(format!(
                    "invalid_ack_route dcid={} server_cid={} expected_dcid={}",
                    header.dcid.value(),
                    server_cid.value(),
                    local_cid.value()
                ));
                continue;
            }
            client
                .endpoint
                .install_connection_ids(local_cid, server_cid)
                .map_err(|error| anyhow::anyhow!("install bootstrap CIDs: {error:?}"))?;
            client
                .endpoint
                .set_initial_peer_credit(ack.max_data, ack.max_stream_data)
                .map_err(|error| anyhow::anyhow!("bootstrap peer credit: {error:?}"))?;
            client
                .endpoint
                .continue_packet_numbers_from(packet_number.saturating_add(1))
                .map_err(|error| anyhow::anyhow!("continue bootstrap packet numbers: {error:?}"))?;
            return Ok(client);
        }
        if let Some(observation) = last_observation {
            bail!("UDP bootstrap timeout after {BOOTSTRAP_ATTEMPTS} attempts ({observation})")
        }
        bail!("UDP bootstrap timeout after {BOOTSTRAP_ATTEMPTS} attempts (no response)")
    }

    /// Send one complete application request stream and wait for its
    /// transport control response. The caller chooses the service tag/schema.
    pub async fn send_stream(&mut self, stream_id: u64, data: &[u8], fin: bool) -> Result<()> {
        self.endpoint
            .open_send_stream(stream_id, INITIAL_MAX_STREAM_DATA)
            .map_err(|error| anyhow::anyhow!("client stream: {error:?}"))?;
        let mut packet = [0u8; MTU];
        let (used, _) = self
            .endpoint
            .encode_stream_packet(
                self.endpoint.peer_connection_id().unwrap_or(self.local_cid),
                stream_id,
                0,
                fin,
                data,
                &mut packet,
            )
            .map_err(|error| anyhow::anyhow!("client packet: {error:?}"))?;
        self.socket.send_to(&packet[..used], self.peer).await?;
        let mut response = [0u8; MTU];
        let (len, peer) = timeout(ACK_TIMEOUT, self.socket.recv_from(&mut response))
            .await
            .context("UDP client ACK timeout")??;
        if peer != self.peer {
            bail!("UDP client peer changed");
        }
        match self
            .endpoint
            .receive_datagram(&response[..len])
            .map_err(|error| anyhow::anyhow!("client transport input: {error:?}"))?
        {
            quic_lite::TransportPacket::Control => Ok(()),
            quic_lite::TransportPacket::Stream { .. } => {
                bail!("unexpected stream while waiting for ACK")
            }
        }
    }

    /// Send a stream operation and wait for the first application response,
    /// while still acknowledging any transport control packets encountered.
    pub async fn request_stream(
        &mut self,
        stream_id: u64,
        data: &[u8],
        fin: bool,
    ) -> Result<(u64, Vec<u8>, bool)> {
        let frame = self.request_stream_frame(stream_id, data, fin).await?;
        Ok((frame.id, frame.data, frame.fin))
    }

    /// Send one request and wait for its first application response while
    /// retaining the stream offset for a multi-frame consumer.
    pub async fn request_stream_frame(
        &mut self,
        stream_id: u64,
        data: &[u8],
        fin: bool,
    ) -> Result<ReceivedStream> {
        self.endpoint
            .open_send_stream(stream_id, INITIAL_MAX_STREAM_DATA)
            .map_err(|error| anyhow::anyhow!("client stream: {error:?}"))?;
        let mut packet = [0u8; MTU];
        let (used, _) = self
            .endpoint
            .encode_stream_packet(
                self.endpoint.peer_connection_id().unwrap_or(self.local_cid),
                stream_id,
                0,
                fin,
                data,
                &mut packet,
            )
            .map_err(|error| anyhow::anyhow!("client packet: {error:?}"))?;
        self.socket.send_to(&packet[..used], self.peer).await?;
        let started = Instant::now();
        for attempt in 0..STREAM_ATTEMPTS {
            let deadline = Instant::now() + ACK_TIMEOUT;
            loop {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    break;
                }
                let mut incoming = [0u8; MTU];
                let received = timeout(remaining, self.socket.recv_from(&mut incoming)).await;
                let Ok(Ok((len, peer))) = received else {
                    break;
                };
                if peer != self.peer {
                    bail!("UDP client peer changed");
                }
                match self
                    .endpoint
                    .receive_datagram(&incoming[..len])
                    .map_err(|error| anyhow::anyhow!("client transport input: {error:?}"))?
                {
                    quic_lite::TransportPacket::Control => continue,
                    quic_lite::TransportPacket::Stream { frame, .. } => {
                        let response = ReceivedStream {
                            id: frame.id,
                            offset: frame.offset,
                            fin: frame.fin,
                            data: frame.data.to_vec(),
                        };
                        if self.deferred_receive_credit {
                            self.endpoint
                                .stream_consumed_deferred(response.id, response.data.len())
                        } else {
                            self.endpoint
                                .stream_consumed(response.id, response.data.len())
                        }
                        .map_err(|error| {
                            anyhow::anyhow!("client response accounting: {error:?}")
                        })?;
                        let mut ack = [0u8; MTU];
                        if let Some(ack_len) = self
                            .endpoint
                            .poll_transmit(&mut ack)
                            .map_err(|error| anyhow::anyhow!("client response ACK: {error:?}"))?
                        {
                            self.socket.send_to(&ack[..ack_len], self.peer).await?;
                        }
                        return Ok(response);
                    }
                }
            }
            if attempt + 1 == STREAM_ATTEMPTS {
                break;
            }
            let now = started.elapsed().as_millis() as u64;
            self.endpoint.set_time(now);
            let mut retry = [0u8; MTU];
            let pto = self.endpoint.pto_timeout();
            let retransmission = self
                .endpoint
                .retransmit_due(now, pto, &mut retry)
                .map_err(|error| anyhow::anyhow!("client stream retransmission: {error:?}"))?;
            let Some((retry_len, _packet_number)) = retransmission else {
                continue;
            };
            self.socket.send_to(&retry[..retry_len], self.peer).await?;
        }
        bail!("UDP stream request timeout after {STREAM_ATTEMPTS} attempts")
    }

    /// Receive one application stream packet and return its bytes. ACK and
    /// window generation remain inside the transport client.
    pub async fn recv_stream(&mut self) -> Result<(u64, Vec<u8>, bool)> {
        let frame = self.recv_stream_frame().await?;
        Ok((frame.id, frame.data, frame.fin))
    }

    /// Receive one application stream packet and retain its offset for a
    /// multi-frame consumer. ACK/window generation remains in this client.
    pub async fn recv_stream_frame(&mut self) -> Result<ReceivedStream> {
        loop {
            let mut packet = [0u8; MTU];
            let (len, peer) = self.socket.recv_from(&mut packet).await?;
            if peer != self.peer {
                bail!("UDP client peer changed");
            }
            let stream = match self
                .endpoint
                .receive_datagram(&packet[..len])
                .map_err(|error| anyhow::anyhow!("client transport input: {error:?}"))?
            {
                quic_lite::TransportPacket::Control => continue,
                quic_lite::TransportPacket::Stream { frame, .. } => frame,
            };
            if self.deferred_receive_credit {
                self.endpoint
                    .stream_consumed_deferred(stream.id, stream.data.len())
            } else {
                self.endpoint.stream_consumed(stream.id, stream.data.len())
            }
            .map_err(|error| anyhow::anyhow!("client stream accounting: {error:?}"))?;
            let mut control = [0u8; MTU];
            if let Some(used) = self
                .endpoint
                .poll_transmit(&mut control)
                .map_err(|error| anyhow::anyhow!("client ACK: {error:?}"))?
            {
                self.socket.send_to(&control[..used], self.peer).await?;
            }
            return Ok(ReceivedStream {
                id: stream.id,
                offset: stream.offset,
                fin: stream.fin,
                data: stream.data.to_vec(),
            });
        }
    }
}

/// Start the host-side UDP bearer used by Recovery and Main object transfers.
/// The returned task owns the socket; calling the lmesh-wifi command again is
/// rejected by the caller so the service can remain up while artifacts change.
pub async fn run(config: UdpConfig) -> Result<()> {
    if config.max_active_connections == 0 {
        bail!("UDP max active connections must be at least one");
    }
    if config.history_capacity > 512 {
        bail!("UDP history capacity must be at most 512");
    }
    if !(1..=MAX_OBJECT_CHUNK).contains(&config.object_chunk) {
        bail!("UDP object chunk must be between 1 and {MAX_OBJECT_CHUNK} bytes");
    }
    if config.ledger_memory_policy.min_packets > 512
        || config.ledger_memory_policy.max_packets > 512
    {
        bail!("UDP ledger memory policy must be bounded to 512 packets");
    }
    let memory = config
        .ledger_memory
        .or_else(system_memory_snapshot)
        .unwrap_or(LedgerMemorySnapshot {
            total_bytes: 512 * 1024 * 1024,
            available_bytes: 256 * 1024 * 1024,
        });
    let history_capacity = if config.history_capacity == 0 {
        select_capacity(
            memory,
            config.max_active_connections,
            MTU,
            config.ledger_memory_policy,
        )
    } else {
        config.history_capacity
    };
    // A non-zero history is an explicit bearer profile. Do not let the
    // memory-policy resizer silently widen it later; embedded receivers may
    // be sized for exactly that burst and cannot advertise a larger budget.
    let ledger_resize_interval = if config.history_capacity == 0 {
        config.ledger_resize_interval
    } else {
        Duration::ZERO
    };
    let socket = Arc::new(UdpSocket::bind(config.bind).await?);
    configure_host_udp_buffers(&socket)?;
    if let Some(tos) = config.ip_tos {
        configure_ipv4_tos(&socket, tos)?;
    }
    tracing::info!(bind = %config.bind, "object_udp_bound");
    let server = ObjectServer::new(ServerConfig {
        artifact_root: config.artifact_root,
        ..ServerConfig::default()
    });
    let registry = StreamRegistry::default();
    let mut datagram = [0u8; MTU];
    let mut connections: HashMap<u64, mpsc::Sender<ConnectionDatagram>> = HashMap::new();
    let mut connection_peers: HashMap<u64, SocketAddr> = HashMap::new();
    let mut pending_opens: HashMap<(SocketAddr, u64), u64> = HashMap::new();
    let mut pending_open_bytes: HashMap<(SocketAddr, u64), Vec<u8>> = HashMap::new();
    let mut bootstrap_packet_numbers: HashMap<(SocketAddr, u64), Arc<BootstrapPacketNumbers>> =
        HashMap::new();
    let mut last_activity: HashMap<u64, Instant> = HashMap::new();
    let closed_routes = Arc::new(std::sync::Mutex::new(Vec::<u64>::new()));
    loop {
        if let Ok(mut closed) = closed_routes.lock() {
            for cid in closed.drain(..) {
                connections.remove(&cid);
                connection_peers.remove(&cid);
                last_activity.remove(&cid);
            }
            pending_opens.retain(|_, cid| connections.contains_key(cid));
            pending_open_bytes.retain(|key, _| pending_opens.contains_key(key));
            bootstrap_packet_numbers.retain(|key, _| pending_opens.contains_key(key));
        }
        // Do this for every listener iteration, not only after an empty
        // recv timeout. A new benchmark can otherwise keep an old, stalled
        // route alive forever; its PTO retransmissions then contaminate the
        // otherwise independent next run on the same AP.
        let now = Instant::now();
        let expired: Vec<u64> = last_activity
            .iter()
            .filter(|(_, when)| now.duration_since(**when) >= config.idle_timeout)
            .map(|(cid, _)| *cid)
            .collect();
        for cid in expired {
            connections.remove(&cid);
            connection_peers.remove(&cid);
            last_activity.remove(&cid);
        }
        pending_opens.retain(|_, cid| connections.contains_key(cid));
        pending_open_bytes.retain(|key, _| pending_opens.contains_key(key));
        bootstrap_packet_numbers.retain(|key, _| pending_opens.contains_key(key));
        let (len, peer) =
            match timeout(config.receive_timeout, socket.recv_from(&mut datagram)).await {
                Ok(result) => result?,
                Err(_) => continue,
            };
        let packet = datagram[..len].to_vec();
        let (header, _) = match quic_lite::ShortHeader::decode(&packet) {
            Ok(value) => value,
            Err(error) => {
                tracing::warn!(%peer, error = ?error, "udp_transport_malformed_header");
                continue;
            }
        };
        if header.dcid.value() == 0 {
            let Ok((_, open)) = quic_lite::decode_bootstrap_open_packet_with_limits(&packet) else {
                tracing::warn!(%peer, "udp_transport_invalid_bootstrap");
                continue;
            };
            let client_cid = open.client_receive_cid;
            let key = (peer, client_cid.value());
            if let Some(previous) = pending_open_bytes.get(&key) {
                if decode_bootstrap_open_payload(&packet)
                    .map_or(true, |payload| previous.as_slice() != payload)
                {
                    tracing::warn!(%peer, cid = client_cid.value(), "udp_transport_conflicting_bootstrap");
                    continue;
                }
            }
            let server_cid = if let Some(existing) = pending_opens.get(&key).copied() {
                quic_lite::ConnectionId::new(existing)
                    .ok_or_else(|| anyhow::anyhow!("invalid pending CID"))?
            } else {
                if connections.len() >= config.max_active_connections {
                    tracing::warn!(%peer, "udp_transport_connection_capacity");
                    continue;
                }
                let allocated = allocate_server_cid(&connections, client_cid)?;
                pending_opens.insert(key, allocated.value());
                let open_payload = decode_bootstrap_open_payload(&packet)
                    .ok_or_else(|| anyhow::anyhow!("bootstrap payload disappeared"))?;
                pending_open_bytes.insert(key, open_payload.to_vec());
                let bootstrap_numbers = Arc::new(BootstrapPacketNumbers {
                    next: AtomicU32::new(0),
                    application_started: AtomicBool::new(false),
                });
                bootstrap_packet_numbers.insert(key, bootstrap_numbers.clone());
                let (sender, receiver) = mpsc::channel(CONNECTION_DATAGRAM_QUEUE_CAPACITY);
                connections.insert(allocated.value(), sender);
                connection_peers.insert(allocated.value(), peer);
                last_activity.insert(allocated.value(), Instant::now());
                let socket_for_connection = socket.clone();
                let registry_for_connection = registry.clone();
                let server_for_connection = server.clone();
                let control_for_connection = config.control.clone();
                let closed_routes_for_connection = closed_routes.clone();
                tokio::spawn(async move {
                    let result = serve_persistent_peer_with_ids(
                        socket_for_connection,
                        server_for_connection,
                        peer,
                        registry_for_connection,
                        receiver,
                        None,
                        allocated,
                        client_cid,
                        open.max_data,
                        open.max_stream_data,
                        open.max_in_flight_packets,
                        history_capacity,
                        bootstrap_numbers,
                        config.max_active_connections,
                        config.ledger_memory_policy,
                        config.ledger_memory,
                        ledger_resize_interval,
                        config.object_chunk,
                        config.iperf_pace,
                        config.iperf_burst_packets,
                        config.iperf_burst_delay,
                        control_for_connection,
                    )
                    .await;
                    if let Ok(mut closed) = closed_routes_for_connection.lock() {
                        closed.push(allocated.value());
                    }
                    if let Err(error) = result {
                        tracing::warn!(%peer, dcid = allocated.value(), error = %error, "object_udp_bootstrap_connection_failed");
                    }
                });
                allocated
            };
            tracing::info!(%peer, client_cid = client_cid.value(), server_cid = server_cid.value(),
                "object_udp_bootstrap_open");
            let Some(bootstrap_numbers) = bootstrap_packet_numbers.get(&key) else {
                continue;
            };
            if bootstrap_numbers
                .application_started
                .load(Ordering::Acquire)
            {
                // A delayed Initial/Open after application traffic started is
                // stale. Re-ACKing it would require a lower packet number and
                // violate the connection's monotonic sender space.
                tracing::debug!(%peer, client_cid = client_cid.value(), "udp_transport_stale_bootstrap");
                continue;
            }
            let packet_number = bootstrap_numbers
                .next
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                    current.checked_add(1)
                })
                .map_err(|_| anyhow::anyhow!("bootstrap packet number exhausted"))?;
            let mut ack = [0u8; MTU];
            let used = encode_bootstrap_ack(client_cid, packet_number, server_cid, &mut ack)?;
            socket.send_to(&ack[..used], peer).await?;
            tracing::info!(%peer, client_cid = client_cid.value(), server_cid = server_cid.value(),
                packet_number, "object_udp_bootstrap_ack");
            continue;
        }
        let key = header.dcid.value();
        if let Some(sender) = connections.get(&key) {
            if connection_peers.get(&key) != Some(&peer) {
                tracing::warn!(
                    %peer,
                    dcid = key,
                    expected_peer = ?connection_peers.get(&key),
                    "udp_transport_wrong_peer"
                );
                continue;
            }
            last_activity.insert(key, Instant::now());
            match sender.try_send(ConnectionDatagram {
                peer,
                bytes: packet.clone(),
            }) {
                Ok(()) => continue,
                Err(mpsc::error::TrySendError::Full(_)) => {
                    // Preserve the route. The connection task still owns a
                    // bounded ledger and its PTO path can recover a dropped
                    // control packet; removing the route makes that recovery
                    // impossible and turns a queue burst into a dead session.
                    tracing::warn!(%peer, dcid = key, "udp_transport_connection_queue_full");
                    continue;
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    connections.remove(&key);
                    connection_peers.remove(&key);
                }
            }
        }

        // Non-zero CIDs are routable only after bootstrap allocated them.
        // Unknown labels are dropped instead of creating an implicit
        // symmetric-CID connection.
        tracing::warn!(%peer, dcid = key, "udp_transport_unknown_cid");
    }
}

async fn serve_persistent_peer_with_ids(
    socket: Arc<UdpSocket>,
    server: ObjectServer,
    peer: SocketAddr,
    registry: StreamRegistry,
    mut receiver: mpsc::Receiver<ConnectionDatagram>,
    first_packet: Option<Vec<u8>>,
    local_cid: quic_lite::ConnectionId,
    peer_cid: quic_lite::ConnectionId,
    peer_max_data: u64,
    peer_max_stream_data: u64,
    peer_max_in_flight_packets: u16,
    history_capacity: usize,
    bootstrap_packet_numbers: Arc<BootstrapPacketNumbers>,
    max_active_connections: usize,
    ledger_memory_policy: LedgerMemoryPolicy,
    ledger_memory: Option<LedgerMemorySnapshot>,
    ledger_resize_interval: Duration,
    object_chunk: usize,
    iperf_pace: Duration,
    iperf_burst_packets: usize,
    iperf_burst_delay: Duration,
    control: Option<Arc<TransportControl>>,
) -> Result<()> {
    let mut mux = Box::new(StreamMux::<8, 512>::new_with_history_capacity(
        Role::Server,
        ConnectionLimits::default(),
        MTU as u64,
        64,
        8,
        256 * 1024,
        history_capacity,
    ));
    let mut events = EventRing::new(64);
    mux.install_connection_ids(local_cid, peer_cid)
        .map_err(|error| anyhow::anyhow!("persistent CIDs: {error:?}"))?;
    mux.endpoint
        .set_initial_peer_budget(
            peer_max_data,
            peer_max_stream_data,
            peer_max_in_flight_packets,
        )
        .map_err(|error| anyhow::anyhow!("bootstrap peer credit: {error:?}"))?;
    let mut response_stream = quic_lite::FIRST_SERVER_BIDI_STREAM_ID;
    let mut object_transfer = None;
    let mut byte_transfers: [Option<PendingByteTransfer>; MAX_IPERF_STREAMS] =
        core::array::from_fn(|_| None);
    let mut high_byte_transfer = None;
    let mut low_byte_transfer = None;
    let started = Instant::now();
    let mut ledger_controller = LedgerCapacityController::new(history_capacity, 2);
    let mut next_ledger_resize = Instant::now() + ledger_resize_interval;
    if let Some(first_packet) = first_packet {
        let next = bootstrap_packet_numbers.next.load(Ordering::Acquire);
        if next > mux.endpoint.next_packet_number {
            mux.endpoint
                .continue_packet_numbers_from(next)
                .map_err(|error| anyhow::anyhow!("continue bootstrap packet numbers: {error:?}"))?;
        }
        bootstrap_packet_numbers
            .application_started
            .store(true, Ordering::Release);
        process_persistent_packet(
            &socket,
            peer,
            &server,
            &first_packet,
            &mut mux,
            &registry,
            &mut events,
            &mut response_stream,
            &mut object_transfer,
            &mut byte_transfers,
            &mut high_byte_transfer,
            &mut low_byte_transfer,
            started,
            object_chunk,
            iperf_pace,
            iperf_burst_packets,
            iperf_burst_delay,
            control.as_deref(),
        )
        .await
        .context("initial persistent packet")?;
        if mux.is_closed() {
            return Ok(());
        }
    }
    loop {
        if let Some(control) = control.as_deref() {
            control.record_server_stats(&mux.endpoint);
        }
        let object_next_send = object_transfer
            .as_ref()
            .and_then(|transfer| transfer.pacer.next_delay(Duration::ZERO));
        // Each stream owns a pacer.  Use the earliest deadline, rather than
        // whichever transfer happens to be stored first, so a low-priority
        // stream cannot accidentally stall a ready higher-priority stream
        // (or vice versa) while both are active.
        let byte_next_send = byte_transfers
            .iter()
            .filter_map(|transfer| transfer.as_ref())
            .chain(high_byte_transfer.as_ref())
            .chain(low_byte_transfer.as_ref())
            .filter_map(|transfer| transfer.pacer.next_delay(transfer.pace))
            .min();
        let next_send = match (object_next_send, byte_next_send) {
            (Some(left), Some(right)) => Some(left.min(right)),
            (Some(value), None) | (None, Some(value)) => Some(value),
            (None, None) => None,
        };
        let receive_wait = connection_receive_wait(
            object_transfer.is_some(),
            byte_transfers.iter().any(Option::is_some)
                || high_byte_transfer.is_some()
                || low_byte_transfer.is_some(),
            next_send,
        );
        match timeout(receive_wait, receiver.recv()).await {
            Ok(Some(datagram)) if datagram.peer == peer => {
                let next = bootstrap_packet_numbers.next.load(Ordering::Acquire);
                if next > mux.endpoint.next_packet_number {
                    mux.endpoint
                        .continue_packet_numbers_from(next)
                        .map_err(|error| {
                            anyhow::anyhow!("continue bootstrap packet numbers: {error:?}")
                        })?;
                }
                bootstrap_packet_numbers
                    .application_started
                    .store(true, Ordering::Release);
                if let Err(error) = process_persistent_packet(
                    &socket,
                    peer,
                    &server,
                    &datagram.bytes,
                    &mut mux,
                    &registry,
                    &mut events,
                    &mut response_stream,
                    &mut object_transfer,
                    &mut byte_transfers,
                    &mut high_byte_transfer,
                    &mut low_byte_transfer,
                    started,
                    object_chunk,
                    iperf_pace,
                    iperf_burst_packets,
                    iperf_burst_delay,
                    control.as_deref(),
                )
                .await
                {
                    // A malformed or flow-rejected datagram belongs to this
                    // connection, not to the listener's task lifetime. Drop
                    // it and keep the route alive so hostile/late packets
                    // cannot terminate the persistent mux task.
                    tracing::warn!(
                        %peer,
                        dcid = local_cid.value(),
                        error = %error,
                        "udp_transport_connection_datagram_dropped"
                    );
                    if let Some(control) = control.as_deref() {
                        control.record_error(format!(
                            "peer={peer} dcid={} packet={error}",
                            local_cid.value()
                        ));
                    }
                }
                if !ledger_resize_interval.is_zero() {
                    maybe_resize_ledger(
                        &mut mux,
                        &mut ledger_controller,
                        &mut next_ledger_resize,
                        ledger_resize_interval,
                        max_active_connections,
                        ledger_memory_policy,
                        ledger_memory,
                    );
                }
                if mux.is_closed() {
                    break;
                }
            }
            Ok(Some(_)) => {}
            Ok(None) => break,
            Err(_) => {
                // Object production must also be driven by the connection
                // clock.  Waiting for an inbound datagram to call
                // `send_next_object_packet` couples application progress to
                // a peer ACK/control packet and can stall a Recovery sender
                // after the first record when that packet is delayed or
                // consumed by the bearer boundary. Fill any available window
                // slots; the normal bounded PTO path owns retransmission for
                // retained packets.
                if let Some(transfer) = object_transfer.as_mut() {
                    // Transport scheduling is independent of object records:
                    // ACK processing may mark a missing packet lost while
                    // the congestion window is full but the ledger is not.
                    // Repair that range before considering fresh bytes.
                    // A marked-loss repair consumes one slot but must not
                    // turn this scheduler pass into stop-and-wait. Refill
                    // every remaining congestion/history slot immediately.
                    let _ = retransmit_due_packet(&socket, peer, &mut mux, started).await?;
                    let mut packet = [0u8; MTU];
                    let filled =
                        fill_object_window(&socket, peer, &mut mux, transfer, &mut packet).await?;
                    let sent = filled && transfer.stream.is_complete();
                    if sent {
                        report_object_transfer(transfer, mux.endpoint.stats());
                        object_transfer = None;
                    }
                } else if byte_transfers.iter().any(Option::is_some)
                    || high_byte_transfer.is_some()
                    || low_byte_transfer.is_some()
                {
                    let mut packet = [0u8; MTU];
                    schedule_iperf_transfers(
                        &socket,
                        peer,
                        &mut mux,
                        &mut byte_transfers,
                        &mut high_byte_transfer,
                        &mut low_byte_transfer,
                        &mut packet,
                        started,
                    )
                    .await?;
                } else {
                    let _ = retransmit_due_packet(&socket, peer, &mut mux, started).await?;
                }
                if !ledger_resize_interval.is_zero() {
                    maybe_resize_ledger(
                        &mut mux,
                        &mut ledger_controller,
                        &mut next_ledger_resize,
                        ledger_resize_interval,
                        max_active_connections,
                        ledger_memory_policy,
                        ledger_memory,
                    );
                }
            }
        }
    }
    Ok(())
}

fn connection_receive_wait(
    object_active: bool,
    byte_active: bool,
    next_send: Option<Duration>,
) -> Duration {
    if object_active || byte_active {
        // An unpaced transfer has no next-send deadline. Keep the active
        // clock running so a briefly ACK/cwnd-limited sender never falls back
        // to the 50 ms idle wait; paced transfers wake at their bounded
        // scheduler deadline instead.
        next_send
            .map(|delay| delay.min(ACTIVE_OBJECT_SCHEDULER_TICK))
            .unwrap_or(ACTIVE_OBJECT_SCHEDULER_TICK)
    } else {
        Duration::from_millis(50)
    }
}

fn maybe_resize_ledger<const H: usize>(
    mux: &mut StreamMux<8, H>,
    controller: &mut LedgerCapacityController,
    next_resize: &mut Instant,
    interval: Duration,
    max_active_connections: usize,
    policy: LedgerMemoryPolicy,
    injected_memory: Option<LedgerMemorySnapshot>,
) {
    if interval == Duration::ZERO || Instant::now() < *next_resize {
        return;
    }
    let memory = injected_memory
        .or_else(system_memory_snapshot)
        .unwrap_or(LedgerMemorySnapshot {
            total_bytes: 512 * 1024 * 1024,
            available_bytes: 256 * 1024 * 1024,
        });
    if let Some(target) = controller.observe(
        memory,
        max_active_connections,
        MTU,
        policy,
        mux.endpoint.history_len(),
    ) {
        if mux.endpoint.set_history_capacity(target).is_err() {
            // A live entry may occupy a ring slot above the requested limit
            // even when the count fits. Keep the existing allocation and
            // retry after the next stable memory sample.
            *controller = LedgerCapacityController::new(mux.endpoint.history_capacity(), 2);
        }
    }
    *next_resize = Instant::now() + interval;
}

fn allocate_server_cid(
    connections: &HashMap<u64, mpsc::Sender<ConnectionDatagram>>,
    avoid: quic_lite::ConnectionId,
) -> Result<quic_lite::ConnectionId> {
    for _ in 0..1024 {
        let value = NEXT_SERVER_CID.fetch_add(1, Ordering::Relaxed) & ((1u64 << 62) - 1);
        if value != 0 && value != avoid.value() && !connections.contains_key(&value) {
            return quic_lite::ConnectionId::new(value)
                .ok_or_else(|| anyhow::anyhow!("CID allocation overflow"));
        }
    }
    bail!("CID allocation exhausted")
}

#[cfg(test)]
fn decode_bootstrap_open(packet: &[u8]) -> Option<quic_lite::ConnectionId> {
    quic_lite::decode_bootstrap_open_packet(packet)
        .ok()
        .map(|(_, client_cid)| client_cid)
}

fn decode_bootstrap_open_payload(packet: &[u8]) -> Option<&[u8]> {
    let (_, header_len) = quic_lite::ShortHeader::decode(packet).ok()?;
    let (frame, used) = quic_lite::decode_frame(&packet[header_len..]).ok()?;
    if used != packet.len().saturating_sub(header_len) {
        return None;
    }
    let quic_lite::Frame::Stream(stream) = frame else {
        return None;
    };
    (stream.id == quic_lite::CONTROL_STREAM_ID && stream.fin && stream.offset == 0)
        .then_some(stream.data)
}

#[cfg(test)]
fn encode_bootstrap_open(
    client_cid: quic_lite::ConnectionId,
    packet_number: u32,
    out: &mut [u8],
) -> Result<usize> {
    quic_lite::encode_bootstrap_open_packet(client_cid, packet_number, out)
        .map_err(|error| anyhow::anyhow!("bootstrap OPEN: {error:?}"))
}

#[cfg(test)]
fn decode_bootstrap_ack(
    packet: &[u8],
    expected_dcid: quic_lite::ConnectionId,
) -> Result<(quic_lite::ShortHeader, quic_lite::ConnectionId)> {
    quic_lite::decode_bootstrap_open_ack_packet(packet, expected_dcid)
        .map_err(|error| anyhow::anyhow!("bootstrap ACK: {error:?}"))
}

fn encode_bootstrap_ack(
    client_cid: quic_lite::ConnectionId,
    packet_number: u32,
    server_cid: quic_lite::ConnectionId,
    out: &mut [u8],
) -> Result<usize> {
    quic_lite::encode_bootstrap_open_ack_packet(client_cid, server_cid, packet_number, out)
        .map_err(|error| anyhow::anyhow!("bootstrap ACK: {error:?}"))
}

async fn process_persistent_packet<const H: usize>(
    socket: &UdpSocket,
    peer: SocketAddr,
    server: &ObjectServer,
    bytes: &[u8],
    mux: &mut StreamMux<8, H>,
    registry: &StreamRegistry,
    events: &mut EventRing,
    response_stream: &mut u64,
    object_transfer: &mut Option<PendingObjectTransfer>,
    byte_transfers: &mut [Option<PendingByteTransfer>; MAX_IPERF_STREAMS],
    high_byte_transfer: &mut Option<PendingByteTransfer>,
    low_byte_transfer: &mut Option<PendingByteTransfer>,
    started: Instant,
    object_chunk: usize,
    iperf_pace: Duration,
    iperf_burst_packets: usize,
    iperf_burst_delay: Duration,
    control: Option<&TransportControl>,
) -> Result<()> {
    mux.endpoint.set_time(started.elapsed().as_millis() as u64);
    let mut packet = [0u8; MTU];
    let request = mux
        .receive_request(bytes)
        .map_err(|error| anyhow::anyhow!("persistent input: {error:?}"))?;
    if let Some(request) = request {
        // Tagged-CBOR is the normal stream request envelope. It carries the
        // component/method itself, so no service byte is consumed from the
        // stream. The branches below are compatibility for legacy clients.
        if let Some(response) = dispatch_tagged_stream(&request.data) {
            mux.complete_request(request.stream_id, request.data.len())
                .map_err(|error| anyhow::anyhow!("tagged request accounting: {error:?}"))?;
            let (used, _) = mux
                .encode_response(*response_stream, &response, true, &mut packet)
                .map_err(|error| anyhow::anyhow!("tagged response: {error:?}"))?;
            socket.send_to(&packet[..used], peer).await?;
            *response_stream = response_stream.saturating_add(4);
            return Ok(());
        }
        if let Some(control) = control {
            control.record_event(format!(
                "request peer={peer} stream={} service={} bytes={}",
                request.stream_id,
                request.data.first().copied().unwrap_or_default(),
                request.data.len(),
            ));
        }
        if request.data.first() == Some(&SERVICE_CONTROL) {
            let record = request.data.get(2..).unwrap_or_default();
            match request.data.get(1).copied() {
                Some(CONTROL_LOG) => {
                    if let Some(control) = control {
                        control.receive_log(record);
                    }
                }
                Some(CONTROL_POLL) => {}
                Some(CONTROL_PATH_POLICY) => {
                    let policy = decode_path_policy(record)
                        .ok_or_else(|| anyhow::anyhow!("invalid path policy"))?;
                    if let Some(control) = control {
                        control.set_path_policy(policy);
                        control.record_event(format!("path_policy={policy:?}"));
                    }
                }
                _ => bail!("invalid control record"),
            }
            mux.complete_request(request.stream_id, request.data.len())
                .map_err(|error| anyhow::anyhow!("control request accounting: {error:?}"))?;
            let response = control.map_or_else(
                || Vec::from([SERVICE_CONTROL, CONTROL_RESPONSE]),
                TransportControl::next_response,
            );
            let (used, _) = mux
                .encode_response(*response_stream, &response, true, &mut packet)
                .map_err(|error| anyhow::anyhow!("control response: {error:?}"))?;
            socket.send_to(&packet[..used], peer).await?;
            *response_stream = response_stream.saturating_add(4);
            return Ok(());
        } else if request.data.first() == Some(&SERVICE_OBJECT) {
            if object_transfer.is_some() {
                bail!("object transfer already active");
            }
            let (ack_frequency, get_bytes) = object_request_envelope(&request.data)?;
            let get = crate::protocol::decode_get(get_bytes)
                .ok_or_else(|| anyhow::anyhow!("invalid bootstrapped object GET"))?;
            if get.target == 0 || get.name.as_ref().is_some_and(|name| name.len() > 128) {
                bail!("invalid bootstrapped object target");
            }
            let records = server.response_records(get)?;
            if let Some(control) = control {
                control.record_event(format!(
                    "object accepted peer={peer} records={}",
                    records.len()
                ));
            }
            tracing::info!(%peer, stream = request.stream_id, records = records.len(),
                "object_udp_get_accepted");
            *object_transfer = Some(PendingObjectTransfer::with_chunk(records, object_chunk));
            mux.complete_request(request.stream_id, request.data.len())
                .map_err(|error| anyhow::anyhow!("object request accounting: {error:?}"))?;
            // Object and IPERF use the same bearer. Make the object policy
            // explicit too; otherwise a Recovery client silently remains at
            // its local default and host/device diagnostics disagree.
            mux.endpoint
                .request_ack_frequency(
                    0,
                    u64::from(ack_frequency - 1),
                    RECOVERY_MAX_ACK_DELAY_US,
                    1,
                )
                .map_err(|error| anyhow::anyhow!("object ACK_FREQUENCY: {error:?}"))?;
            if let Some(used) = mux
                .endpoint
                .poll_transmit(&mut packet)
                .map_err(|error| anyhow::anyhow!("object ACK_FREQUENCY send: {error:?}"))?
            {
                socket.send_to(&packet[..used], peer).await?;
            }
        } else if request.data.first() == Some(&SERVICE_IPERF) {
            if byte_transfers.iter().any(Option::is_some)
                || high_byte_transfer.is_some()
                || low_byte_transfer.is_some()
            {
                bail!("iperf transfer already active");
            }
            let iperf_request = decode_iperf_service_request(&request.data)
                .ok_or_else(|| anyhow::anyhow!("invalid IPERF request"))?;
            // The no-std handler plan is also consumed by firmware. Keep
            // request clamping, stream expansion, and ACK policy identical
            // before this socket adapter adds host-only pacing.
            let iperf_plan = IperfServicePlan::from_request(iperf_request, MAX_OBJECT_CHUNK);
            // The optional fields are diagnostic-only, scoped to this
            // IPERF request. Normal object transfers keep UdpConfig's
            // default unpaced scheduling, and an older Recovery request
            // (11 bytes) still uses the listener defaults.
            let (request_pace, request_burst, request_burst_delay, _, _) = iperf_schedule(
                iperf_request,
                iperf_pace,
                iperf_burst_packets,
                iperf_burst_delay,
            );
            mux.complete_request(request.stream_id, request.data.len())
                .map_err(|error| anyhow::anyhow!("iperf request accounting: {error:?}"))?;
            // Default to RFC 9000's every-other-ack-eliciting-packet policy.
            // The selected ratio is carried in ACK_FREQUENCY, rather than
            // relying on a local Recovery setting the host cannot observe.
            mux.endpoint
                .request_ack_frequency(
                    0,
                    u64::from(iperf_plan.ack_frequency.saturating_sub(1)),
                    u64::from(iperf_plan.ack_delay_ms) * 1_000,
                    1,
                )
                .map_err(|error| anyhow::anyhow!("iperf ACK_FREQUENCY: {error:?}"))?;
            if let Some(used) = mux
                .endpoint
                .poll_transmit(&mut packet)
                .map_err(|error| anyhow::anyhow!("iperf ACK_FREQUENCY send: {error:?}"))?
            {
                socket.send_to(&packet[..used], peer).await?;
            }
            for (index, transfer) in byte_transfers
                .iter_mut()
                .take(iperf_plan.normal_streams)
                .enumerate()
            {
                let bytes = iperf_plan.normal_bytes[index];
                *transfer = Some(PendingByteTransfer::new(
                    *response_stream,
                    bytes,
                    iperf_plan.packet_size,
                    request_pace,
                    request_burst,
                    request_burst_delay,
                ));
                *response_stream = response_stream.saturating_add(4);
            }
            if iperf_plan.high_priority_bytes != 0 {
                *high_byte_transfer = Some(PendingByteTransfer::new(
                    *response_stream,
                    iperf_plan.high_priority_bytes,
                    iperf_plan.packet_size,
                    request_pace,
                    request_burst,
                    request_burst_delay,
                ));
                *response_stream = response_stream.saturating_add(4);
            }
            if iperf_plan.low_priority_bytes != 0 {
                *low_byte_transfer = Some(PendingByteTransfer::new(
                    *response_stream,
                    iperf_plan.low_priority_bytes,
                    iperf_plan.packet_size,
                    request_pace,
                    request_burst,
                    request_burst_delay,
                ));
                *response_stream = response_stream.saturating_add(4);
            }
        } else {
            let connection = mux
                .endpoint
                .local_connection_id()
                .or_else(|| mux.endpoint.peer_connection_id())
                .ok_or(quic_lite::Error::WrongConnectionId)
                .map_err(|error| anyhow::anyhow!("service CID: {error:?}"))?;
            let service = *request
                .data
                .first()
                .ok_or(quic_lite::Error::Invalid)
                .map_err(|error| anyhow::anyhow!("empty service: {error:?}"))?;
            let response = handle_stream_with_events(
                &mux.endpoint,
                Some(events),
                connection,
                request.stream_id,
                registry,
                service,
                &request.data[1..],
            )
            .map_err(|error| anyhow::anyhow!(error))?;
            mux.complete_request(request.stream_id, request.data.len())
                .map_err(|error| anyhow::anyhow!("service accounting: {error:?}"))?;
            let (used, _) = mux
                .encode_response(*response_stream, &response, true, &mut packet)
                .map_err(|error| anyhow::anyhow!("persistent response: {error:?}"))?;
            socket.send_to(&packet[..used], peer).await?;
            *response_stream = response_stream.saturating_add(4);
            return Ok(());
        }
    }
    if let Some(transfer) = object_transfer.as_mut() {
        // Fill the bounded transport window. Object chunk size is an
        // application choice; it must not turn the reliable transport into
        // stop-and-wait. ACK ranges let the receiver acknowledge gaps while
        // the retained history supplies selective retransmission.
        // An ACK can make a packet-threshold loss immediately eligible.  Do
        // not wait for a full history ledger or the next timeout tick before
        // retransmitting it.
        // A selective-ACK repair is ordered before new bytes, not instead of
        // them. This is the transport scheduler; object records do not form
        // an application pacing boundary.
        let _ = retransmit_due_packet(socket, peer, mux, started).await?;
        let filled = fill_object_window(socket, peer, mux, transfer, &mut packet).await?;
        if filled {
            if transfer.stream.is_complete() {
                report_object_transfer(transfer, mux.endpoint.stats());
                *object_transfer = None;
            }
        }
    } else if byte_transfers.iter().any(Option::is_some)
        || high_byte_transfer.is_some()
        || low_byte_transfer.is_some()
    {
        schedule_iperf_transfers(
            socket,
            peer,
            mux,
            byte_transfers,
            high_byte_transfer,
            low_byte_transfer,
            &mut packet,
            started,
        )
        .await?;
    } else if let Some(used) = mux
        .endpoint
        .poll_transmit(&mut packet)
        .map_err(|error| anyhow::anyhow!("persistent ACK: {error:?}"))?
    {
        socket.send_to(&packet[..used], peer).await?;
    }
    Ok(())
}

/// Priority scheduler for one connection. High-priority application records
/// consume up to four packet opportunities, normal IPERF streams share the
/// host refill quantum, and the log-like low stream receives one opportunity.
/// Every branch remains bounded by endpoint congestion and stream credit.
async fn schedule_iperf_transfers<const H: usize>(
    socket: &UdpSocket,
    peer: SocketAddr,
    mux: &mut StreamMux<8, H>,
    normal: &mut [Option<PendingByteTransfer>; MAX_IPERF_STREAMS],
    high: &mut Option<PendingByteTransfer>,
    low: &mut Option<PendingByteTransfer>,
    packet: &mut [u8; MTU],
    started: Instant,
) -> Result<()> {
    let _ = retransmit_due_packet(socket, peer, mux, started).await?;
    if let Some(transfer) = high.as_mut() {
        let filled = fill_byte_window(socket, peer, mux, transfer, packet, 4).await?;
        if filled && transfer.remaining == 0 {
            report_byte_transfer(transfer, &mux.endpoint);
            *high = None;
        }
    }
    let active = normal
        .iter()
        .filter(|transfer| transfer.is_some())
        .count()
        .max(1);
    let budget = if high.is_some() {
        HOST_IPERF_NORMAL_REFILL_PACKETS.saturating_sub(4)
    } else {
        HOST_IPERF_NORMAL_REFILL_PACKETS
    };
    for slot in normal.iter_mut() {
        let Some(transfer) = slot.as_mut() else {
            continue;
        };
        let filled = fill_byte_window(
            socket,
            peer,
            mux,
            transfer,
            packet,
            (budget / active).max(1),
        )
        .await?;
        if filled && transfer.remaining == 0 {
            report_byte_transfer(transfer, &mux.endpoint);
            *slot = None;
        }
    }
    if let Some(transfer) = low.as_mut() {
        let filled = fill_byte_window(socket, peer, mux, transfer, packet, 1).await?;
        if filled && transfer.remaining == 0 {
            report_byte_transfer(transfer, &mux.endpoint);
            *low = None;
        }
    }
    Ok(())
}

async fn fill_byte_window<const H: usize>(
    socket: &UdpSocket,
    peer: SocketAddr,
    mux: &mut StreamMux<8, H>,
    transfer: &mut PendingByteTransfer,
    packet: &mut [u8; MTU],
    packet_budget: usize,
) -> Result<bool> {
    transfer.pacer.observe(
        mux.endpoint.stats(),
        mux.endpoint.smoothed_rtt(),
        mux.endpoint.congestion.congestion_window,
        mux.endpoint.congestion.max_datagram_size,
    );
    let mut sent = false;
    let mut burst_sent = 0usize;
    while burst_sent < packet_budget
        && transfer.remaining != 0
        && transfer.pacer.ready()
        && mux.endpoint.history_len() < mux.endpoint.history_capacity()
    {
        mux.endpoint
            .open_send_stream(transfer.stream_id, INITIAL_MAX_STREAM_DATA)
            .ok();
        let length = transfer.remaining.min(transfer.chunk_size);
        let mut payload = [0u8; MAX_OBJECT_CHUNK];
        payload[..4].copy_from_slice(&transfer.packet_id.to_be_bytes());
        for (index, byte) in payload[4..length].iter_mut().enumerate() {
            *byte = transfer.offset.wrapping_add(4 + index as u64) as u8;
        }
        let fin = length == transfer.remaining;
        let encoded = mux.endpoint.encode_stream_packet(
            mux.endpoint
                .peer_connection_id()
                .ok_or(quic_lite::Error::WrongConnectionId)
                .map_err(|error| anyhow::anyhow!("iperf peer CID: {error:?}"))?,
            transfer.stream_id,
            transfer.offset,
            fin,
            &payload[..length],
            packet,
        );
        let (used, _) = match encoded {
            // Credit is a normal asynchronous send blocker.  Do not tear
            // down the persistent connection; the next MAX_* control frame
            // will re-enter this filler and resume the same stream offset.
            Err(quic_lite::Error::FlowControl) => break,
            // `encode_stream_packet` checks congestion using the actual
            // encoded packet length. Reserving MTU here made a 512-byte
            // benchmark consume 1200 bytes of cwnd per datagram and turned
            // a windowed sender into an unnecessarily tiny burst.
            Err(quic_lite::Error::Invalid) => break,
            Err(error) => return Err(anyhow::anyhow!("iperf response packet: {error:?}")),
            Ok(packet) => packet,
        };
        socket.send_to(&packet[..used], peer).await?;
        let sent_at = Instant::now();
        if let Some(previous) = transfer.last_send {
            let bucket = interpacket_gap_bucket(sent_at.saturating_duration_since(previous));
            transfer.interpacket_gaps[bucket] = transfer.interpacket_gaps[bucket].saturating_add(1);
        } else {
            transfer.first_send = Some(sent_at);
        }
        transfer.last_send = Some(sent_at);
        transfer.sent_datagrams = transfer.sent_datagrams.saturating_add(1);
        transfer.offset = transfer.offset.saturating_add(length as u64);
        transfer.remaining -= length;
        transfer.packet_id = transfer.packet_id.wrapping_add(1);
        sent = true;
        burst_sent = burst_sent.saturating_add(1);
        let adaptive_active = !transfer.pacer.delay.is_zero();
        transfer.pacer.sent(transfer.pace);
        if !transfer.pace.is_zero() {
            break;
        }
        if adaptive_active {
            break;
        }
        if transfer.burst_packets != 0 && burst_sent >= transfer.burst_packets {
            transfer.pacer.sent(transfer.burst_delay);
            break;
        }
    }
    if sent {
        transfer.window_fills = transfer.window_fills.saturating_add(1);
        transfer.max_window_fill = transfer.max_window_fill.max(burst_sent as u64);
    }
    Ok(sent)
}

async fn retransmit_due_packet<const H: usize>(
    socket: &UdpSocket,
    peer: SocketAddr,
    mux: &mut StreamMux<8, H>,
    started: Instant,
) -> Result<bool> {
    // Loss detection has already established these stream ranges are missing,
    // so repair a bounded flight before admitting fresh bytes. PTO is
    // deliberately different: with no declared loss, emit one probe only.
    const MAX_LOSS_REPAIRS_PER_PASS: usize = 8;
    let now = started.elapsed().as_millis() as u64;
    mux.endpoint.set_time(now);
    let mut packet = [0u8; MTU];
    let pto = mux.endpoint.pto_timeout().max(UDP_MIN_RETRANSMIT_PTO_MS);
    let mut sent = false;
    for _ in 0..MAX_LOSS_REPAIRS_PER_PASS {
        let Some((used, _packet_number)) = mux
            .endpoint
            .retransmit_marked_loss(&mut packet)
            .map_err(|error| anyhow::anyhow!("persistent loss retransmission: {error:?}"))?
        else {
            break;
        };
        socket.send_to(&packet[..used], peer).await?;
        sent = true;
    }
    if sent {
        return Ok(true);
    }
    if let Some((used, _packet_number)) =
        mux.endpoint
            .retransmit_pto_probe(now, pto, &mut packet)
            .map_err(|error| anyhow::anyhow!("persistent PTO retransmission: {error:?}"))?
    {
        socket.send_to(&packet[..used], peer).await?;
        return Ok(true);
    }
    Ok(false)
}

async fn send_next_object_packet<const H: usize>(
    socket: &UdpSocket,
    peer: SocketAddr,
    mux: &mut StreamMux<8, H>,
    transfer: &mut PendingObjectTransfer,
    packet: &mut [u8; MTU],
) -> Result<bool> {
    let stream_id = OBJECT_STREAM;
    mux.endpoint
        .open_send_stream(stream_id, INITIAL_MAX_STREAM_DATA)
        .ok();
    let mut object_bytes = [0u8; MAX_OBJECT_CHUNK];
    let Some(chunk) = transfer
        .stream
        .copy_next(&mut object_bytes[..transfer.chunk_size])
    else {
        return Ok(false);
    };
    let encoded = mux.endpoint.encode_stream_packet(
        mux.endpoint
            .peer_connection_id()
            .ok_or(quic_lite::Error::WrongConnectionId)
            .map_err(|error| anyhow::anyhow!("object peer CID: {error:?}"))?,
        stream_id,
        chunk.offset,
        chunk.fin,
        &object_bytes[..chunk.len],
        packet,
    );
    let (used, _) = match encoded {
        // Flow/congestion blockers are normal persistent-transfer states;
        // the next ACK/MAX_* control packet resumes this same offset.
        Err(quic_lite::Error::FlowControl | quic_lite::Error::Invalid) => return Ok(false),
        Err(error) => {
            return Err(anyhow::anyhow!(
                "object response packet: {error:?} history={} bytes_in_flight={} congestion_window={} stream_credit={:?} connection_credit={} stream_offset={} chunk={}",
                mux.endpoint.history_len(),
                mux.endpoint.bytes_in_flight(),
                mux.endpoint.congestion.congestion_window,
                mux.endpoint.send.stream_credit(stream_id),
                mux.endpoint.send.max_data,
                chunk.offset,
                chunk.len,
            ));
        }
        Ok(packet) => packet,
    };
    socket.send_to(&packet[..used], peer).await?;
    transfer.pacer.sent(Duration::ZERO);
    if transfer.first_send.is_none() {
        transfer.first_send = Some(Instant::now());
    }
    transfer.sent_datagrams = transfer.sent_datagrams.saturating_add(1);
    let previous_bytes = transfer.stream.sent_bytes();
    debug_assert!(transfer.stream.advance(chunk));
    let sent_bytes = transfer.stream.sent_bytes();
    if sent_bytes / (64 * 1024) != previous_bytes / (64 * 1024) {
        tracing::info!(%peer, stream = stream_id, record = chunk.record_index,
            sent_bytes, "object_udp_transfer_progress");
    }
    Ok(true)
}

async fn fill_object_window<const H: usize>(
    socket: &UdpSocket,
    peer: SocketAddr,
    mux: &mut StreamMux<8, H>,
    transfer: &mut PendingObjectTransfer,
    packet: &mut [u8; MTU],
) -> Result<bool> {
    transfer.pacer.observe(
        mux.endpoint.stats(),
        mux.endpoint.smoothed_rtt(),
        mux.endpoint.congestion.congestion_window,
        mux.endpoint.congestion.max_datagram_size,
    );
    if !transfer.pacer.ready() {
        return Ok(false);
    }
    let mut sent_any = false;
    let mut sent_packets = 0usize;
    while mux.endpoint.history_len() < mux.endpoint.history_capacity() {
        if !send_next_object_packet(socket, peer, mux, transfer, packet).await? {
            break;
        }
        sent_any = true;
        sent_packets += 1;
        if !transfer.pacer.delay.is_zero() {
            break;
        }
        // The manifest is on a separate stream and must be accepted before a
        // block can be verified. It is therefore a one-time application
        // barrier. Blocks are all on the same ordered stream and independent
        // once the manifest is accepted: stopping at every 4 KiB block would
        // force a Wi-Fi round trip per record and collapse throughput.
    }
    if sent_any {
        tracing::info!(
            %peer,
            sent_packets,
            history = mux.endpoint.history_len(),
            history_capacity = mux.endpoint.history_capacity(),
            bytes_in_flight = mux.endpoint.bytes_in_flight(),
            congestion_window = mux.endpoint.congestion.congestion_window,
            "object_udp_window_fill"
        );
    }
    Ok(sent_any)
}

#[cfg(test)]
mod tests {
    #[test]
    fn log_queue_drops_oldest_without_affecting_command_queue() {
        let control = TransportControl::default();
        control.queue_command(vec![0xa1]);
        for value in 0..=CONTROL_QUEUE_CAPACITY {
            control.receive_log(&[value as u8]);
        }
        let stats = control.log_stats();
        assert_eq!(stats.queued_records, CONTROL_QUEUE_CAPACITY);
        assert_eq!(stats.dropped_full, 1);
        assert_eq!(control.take_log(), Some(vec![1]));
        assert_eq!(
            control.next_response(),
            vec![SERVICE_CONTROL, CONTROL_RESPONSE, 0xa1]
        );
    }

    use std::collections::HashSet;
    use std::eprintln;

    use super::*;
    use quic_lite::CommittedStreamDisposition;

    #[test]
    fn active_object_scheduler_never_waits_the_idle_50ms_tick() {
        assert_eq!(
            connection_receive_wait(true, false, Some(Duration::from_secs(1))),
            ACTIVE_OBJECT_SCHEDULER_TICK,
        );
        assert_eq!(
            connection_receive_wait(false, false, None),
            Duration::from_millis(50),
        );
    }

    #[test]
    fn adaptive_pacer_uses_transport_loss_then_relaxes_after_clean_acks() {
        let mut pacer = AdaptivePacer::new();
        let mut stats = quic_lite::TransportStats::default();
        // Clean startup remains a full-window, unpaced sender.
        pacer.observe(stats, Some(5), 32 * 1200, 1200);
        assert!(pacer.delay.is_zero());

        // A declared retransmission enables RTT/cwnd-derived pacing. With a
        // 5 ms RTT and 32 packets in cwnd the target is 156 us, above the
        // 125 us lower bound.
        stats.loss_retransmitted_datagrams = 1;
        stats.control_datagrams = 1;
        pacer.observe(stats, Some(5), 32 * 1200, 1200);
        assert_eq!(pacer.delay, Duration::from_micros(156));
        assert_eq!(pacer.activations, 1);

        // Thirty-two clean peer control/ACK packets remove this small delay;
        // an adaptive policy must not permanently pace a recovered link.
        stats.control_datagrams = ADAPTIVE_PACING_CLEAN_ACKS + 1;
        pacer.observe(stats, Some(5), 32 * 1200, 1200);
        assert!(pacer.delay.is_zero());
    }

    #[test]
    fn active_scheduler_honors_sub_millisecond_pacing_deadline() {
        assert_eq!(
            connection_receive_wait(true, false, Some(Duration::from_micros(250))),
            Duration::from_micros(250),
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn udp_listener_tos_round_trips_for_wmm_diagnostics() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        configure_ipv4_tos(&socket, 0x88).unwrap();
        assert_eq!(socket_ipv4_tos(&socket).unwrap(), 0x88);
    }

    #[test]
    fn active_unpaced_iperf_never_falls_back_to_idle_50ms_tick() {
        // `None` is the normal unpaced state: `next_send` is already due.
        // It must not become the listener's 50 ms idle wait.
        assert_eq!(
            connection_receive_wait(false, true, None),
            ACTIVE_OBJECT_SCHEDULER_TICK,
        );
        assert_eq!(
            connection_receive_wait(false, true, Some(Duration::from_millis(20))),
            ACTIVE_OBJECT_SCHEDULER_TICK,
        );
    }

    #[test]
    fn iperf_request_schedule_is_scoped_and_backward_compatible() {
        let defaults = (Duration::from_micros(17), 3, Duration::from_micros(29));
        let legacy = [SERVICE_IPERF; 11];
        assert_eq!(
            iperf_schedule(
                decode_iperf_service_request(&legacy).unwrap(),
                defaults.0,
                defaults.1,
                defaults.2,
            ),
            (
                defaults.0,
                defaults.1,
                defaults.2,
                2,
                RECOVERY_MAX_ACK_DELAY_US
            )
        );

        let mut request = [0u8; 22];
        request[0] = SERVICE_IPERF;
        request[11..15].copy_from_slice(&250u32.to_be_bytes());
        request[15] = 4;
        request[16..20].copy_from_slice(&1_000u32.to_be_bytes());
        request[20] = 8;
        request[21] = 1;
        assert_eq!(
            iperf_schedule(
                decode_iperf_service_request(&request).unwrap(),
                defaults.0,
                defaults.1,
                defaults.2,
            ),
            (
                Duration::from_micros(250),
                4,
                Duration::from_micros(1_000),
                8,
                1_000
            )
        );
        request[20] = u8::MAX;
        assert_eq!(
            iperf_schedule(
                decode_iperf_service_request(&request).unwrap(),
                defaults.0,
                defaults.1,
                defaults.2,
            )
            .3,
            quic_lite::ACK_RANGE_CAPACITY as u8
        );
    }

    #[test]
    fn object_transfer_negotiates_lan_ack_policy() {
        let local = ConnectionId::new(0x31).unwrap();
        let peer = ConnectionId::new(0x32).unwrap();
        let mut endpoint =
            EndpointState::<4, 4>::new(Role::Server, ConnectionLimits::default(), MTU as u64);
        endpoint.install_connection_ids(local, peer).unwrap();
        endpoint
            .request_ack_frequency(
                0,
                u64::from(RECOVERY_OBJECT_ACK_FREQUENCY - 1),
                RECOVERY_MAX_ACK_DELAY_US,
                1,
            )
            .unwrap();
        let mut packet = [0u8; MTU];
        let used = endpoint.poll_transmit(&mut packet).unwrap().unwrap();
        let (_, header_len) = quic_lite::ShortHeader::decode(&packet[..used]).unwrap();
        assert_eq!(
            quic_lite::decode_frame(&packet[header_len..used])
                .unwrap()
                .0,
            quic_lite::Frame::AckFrequency {
                sequence: 0,
                packet_threshold: 7,
                max_ack_delay_us: RECOVERY_MAX_ACK_DELAY_US,
                reordering_threshold: 1,
            }
        );
    }

    #[test]
    fn iperf_send_gap_bins_have_the_compact_numeric_order() {
        assert_eq!(interpacket_gap_bucket(Duration::from_micros(999)), 0);
        assert_eq!(interpacket_gap_bucket(Duration::from_micros(1_000)), 1);
        assert_eq!(interpacket_gap_bucket(Duration::from_micros(5_000)), 2);
        assert_eq!(interpacket_gap_bucket(Duration::from_micros(10_000)), 3);
        assert_eq!(interpacket_gap_bucket(Duration::from_micros(25_000)), 4);
        assert_eq!(interpacket_gap_bucket(Duration::from_micros(50_000)), 5);
    }
    use crate::protocol::{
        BLOCK_SIZE, ImageEvent, ImageManifest, ImageReceiver, ImageSink, RECORD_BLOB, RECORD_DONE,
        RECORD_MANIFEST, RecordBuffer, encode_get,
    };
    use crate::services::handle_stream;
    use quic_lite::callback::{CallbackStreams, CopyingStreamEvents};
    use quic_lite::{
        ConnectionId, EndpointState, FIRST_CLIENT_BIDI_STREAM_ID, FLAG_FIXED, Frame,
        RECOVERY_MAX_HISTORY_PACKETS, RECOVERY_REORDER_CAPACITY_BYTES, RecoveryEndpoint,
        ShortHeader,
    };
    use std::format;
    use std::string::String;
    use std::sync::Arc;
    use std::vec;
    use tempfile::tempdir;

    struct FakeFlash {
        bytes: Vec<u8>,
    }

    #[test]
    fn two_connections_register_and_report_multiple_service_streams() {
        let registry = StreamRegistry::default();
        assert_eq!(registry.handlers().len(), 9);
        assert!(
            registry
                .handlers()
                .iter()
                .any(|handler| handler.tag == SERVICE_IPERF)
        );
        for (client_value, server_value) in [(11u64, 22u64), (33u64, 44u64)] {
            let client_cid = ConnectionId::new(client_value).unwrap();
            let server_cid = ConnectionId::new(server_value).unwrap();
            let mut client =
                EndpointState::<8, 8>::new(Role::Client, ConnectionLimits::default(), MTU as u64);
            let mut server =
                EndpointState::<8, 8>::new(Role::Server, ConnectionLimits::default(), MTU as u64);
            client
                .install_connection_ids(client_cid, server_cid)
                .unwrap();
            server
                .install_connection_ids(server_cid, client_cid)
                .unwrap();
            for (stream_id, service) in [
                (4u64, SERVICE_ECHO),
                (8, SERVICE_STATUS),
                (12, SERVICE_IPERF),
                (16, SERVICE_METRICS),
                (20, SERVICE_EVENTS),
            ] {
                client
                    .open_send_stream(stream_id, INITIAL_MAX_STREAM_DATA)
                    .unwrap();
                let mut packet = [0u8; MTU];
                let mut request = Vec::from([service]);
                if service == SERVICE_IPERF {
                    request.extend_from_slice(&128u64.to_be_bytes());
                    request.extend_from_slice(&[0xa5; 32]);
                } else if service == SERVICE_EVENTS {
                    request.extend_from_slice(b"since=0");
                } else {
                    request.extend_from_slice(b"probe");
                }
                let (used, _) = client
                    .encode_stream_packet(server_cid, stream_id, 0, true, &request, &mut packet)
                    .unwrap();
                let quic_lite::TransportPacket::Stream { frame, .. } =
                    server.receive_datagram(&packet[..used]).unwrap()
                else {
                    panic!("expected service stream");
                };
                let body = &frame.data[1..];
                let response = handle_stream(
                    &server,
                    server.local_connection_id().unwrap(),
                    stream_id,
                    &registry,
                    service,
                    body,
                )
                .unwrap();
                if service == SERVICE_IPERF {
                    assert_eq!(response.len(), 49);
                    assert_eq!(response[0], 1);
                    assert_eq!(u64::from_be_bytes(response[1..9].try_into().unwrap()), 128);
                    assert_eq!(u64::from_be_bytes(response[9..17].try_into().unwrap()), 32);
                    continue;
                }
                if service == SERVICE_ECHO {
                    // Echo is deliberately payload-only so direct action
                    // checks and a QUIC stream share one small response.
                    assert_eq!(response, b"probe");
                    continue;
                }
                let response_text = String::from_utf8(response).unwrap();
                assert!(response_text.contains(&format!("connection_dcid={server_value}")));
                assert!(response_text.contains(&format!("stream_id={stream_id}")));
                if service == SERVICE_METRICS {
                    assert!(response_text.contains("slow_start_threshold="));
                    assert!(response_text.contains("max_streams_bidi="));
                } else if service == SERVICE_EVENTS {
                    assert!(response_text.contains("event=transport_snapshot"));
                    assert!(response_text.contains("next_sequence="));
                } else {
                    assert!(response_text.contains("history="));
                }
            }
        }
    }

    #[test]
    fn bootstrap_helpers_are_canonical_and_reject_bad_records() {
        let client = ConnectionId::new(0x1234).unwrap();
        let server = ConnectionId::new(0x5678).unwrap();
        let mut packet = [0u8; MTU];
        let used = encode_bootstrap_open(client, 7, &mut packet).unwrap();
        assert_eq!(decode_bootstrap_open(&packet[..used]), Some(client));
        let mut ack = [0u8; MTU];
        let ack_used = encode_bootstrap_ack(client, 8, server, &mut ack).unwrap();
        let (header, decoded_server) = decode_bootstrap_ack(&ack[..ack_used], client).unwrap();
        assert_eq!(header.packet_number, 8);
        assert_eq!(decoded_server, server);
        assert!(decode_bootstrap_open(&packet[..used - 1]).is_none());
        assert!(decode_bootstrap_ack(&ack[..ack_used - 1], client).is_err());
        assert!(decode_bootstrap_ack(&ack[..ack_used], server).is_err());
        assert!(encode_bootstrap_open(ConnectionId::new(0).unwrap(), 0, &mut packet).is_err());
        assert!(encode_bootstrap_ack(client, 0, ConnectionId::new(0).unwrap(), &mut ack).is_err());
    }

    #[test]
    fn server_cid_allocator_skips_client_receive_cid() {
        let connections = HashMap::new();
        let next = NEXT_SERVER_CID.load(Ordering::Relaxed);
        let avoid = ConnectionId::new(next & ((1u64 << 62) - 1)).unwrap();
        let allocated = allocate_server_cid(&connections, avoid).unwrap();
        assert_ne!(allocated, avoid);
        assert_ne!(allocated.value(), 0);
    }

    #[tokio::test]
    async fn udp_connect_rejects_zero_and_invalid_bootstrap_responses() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();
        assert!(
            UdpClient::connect(
                "127.0.0.1:0".parse().unwrap(),
                server_addr,
                ConnectionId::new(0).unwrap(),
            )
            .await
            .is_err()
        );

        let task = tokio::spawn(async move {
            let mut input = [0u8; MTU];
            let (_, source) = server.recv_from(&mut input).await.unwrap();
            let mut output = [0u8; MTU];
            let used = encode_bootstrap_ack(
                ConnectionId::new(0xdead).unwrap(),
                0,
                ConnectionId::new(9).unwrap(),
                &mut output,
            )
            .unwrap();
            server.send_to(&output[..used], source).await.unwrap();
        });
        assert!(
            UdpClient::connect(
                "127.0.0.1:0".parse().unwrap(),
                server_addr,
                ConnectionId::new(7).unwrap(),
            )
            .await
            .is_err()
        );
        task.await.unwrap();
    }

    #[tokio::test]
    async fn udp_connect_retries_open_after_loss() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let mut input = [0u8; MTU];
            let (first_len, source) = server.recv_from(&mut input).await.unwrap();
            let (first_header, _) = ShortHeader::decode(&input[..first_len]).unwrap();
            assert_eq!(first_header.dcid.value(), 0);
            let (second_len, second_source) = server.recv_from(&mut input).await.unwrap();
            assert_eq!(second_source, source);
            let client_cid = decode_bootstrap_open(&input[..second_len]).unwrap();
            let mut output = [0u8; MTU];
            let used =
                encode_bootstrap_ack(client_cid, 1, ConnectionId::new(0xe3).unwrap(), &mut output)
                    .unwrap();
            server.send_to(&output[..used], source).await.unwrap();
        });
        let client = UdpClient::connect(
            "127.0.0.1:0".parse().unwrap(),
            server_addr,
            ConnectionId::new(0xe2).unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(
            client.endpoint.peer_connection_id(),
            Some(ConnectionId::new(0xe3).unwrap())
        );
        task.await.unwrap();
    }

    #[test]
    fn pending_object_transfer_keeps_record_offsets_until_transport_accepts() {
        let mut pending = PendingObjectTransfer::new(vec![
            (RECORD_MANIFEST, b"manifest".to_vec()),
            (RECORD_BLOB, b"blob".to_vec()),
        ]);
        let mut bytes = [0u8; 64];
        let manifest = pending.stream.copy_next(&mut bytes).unwrap();
        assert_eq!(manifest.offset, 0);
        assert_eq!(manifest.record_index, 0);
        assert_eq!(&bytes[5..manifest.len], b"manifest");
        // A rejected congestion/credit admission must not consume object
        // bytes. Retrying starts at the same stream offset.
        assert_eq!(pending.stream.copy_next(&mut bytes), Some(manifest));
        assert!(pending.stream.advance(manifest));
        let blob = pending.stream.copy_next(&mut bytes).unwrap();
        assert_eq!(blob.offset, manifest.len as u64);
        assert_eq!(blob.record_index, 1);
        assert_eq!(&bytes[5..blob.len], b"blob");
    }

    #[tokio::test]
    async fn udp_client_send_stream_accepts_transport_control() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();
        let local = ConnectionId::new(1).unwrap();
        let peer = ConnectionId::new(2).unwrap();
        let mut client = UdpClient {
            socket: UdpSocket::bind("127.0.0.1:0").await.unwrap(),
            peer: server_addr,
            endpoint: EndpointState::new(Role::Client, ConnectionLimits::default(), MTU as u64),
            local_cid: local,
            deferred_receive_credit: false,
        };
        client.endpoint.install_connection_ids(local, peer).unwrap();
        let task = tokio::spawn(async move {
            let mut input = [0u8; MTU];
            let (_, source) = server.recv_from(&mut input).await.unwrap();
            let mut output = [0u8; MTU];
            let header = ShortHeader {
                flags: FLAG_FIXED,
                dcid: local,
                packet_number: 0,
                packet_number_len: 4,
            }
            .encode(&mut output)
            .unwrap();
            let used = header + Frame::Ping.encode(&mut output[header..]).unwrap();
            server.send_to(&output[..used], source).await.unwrap();
        });
        client.send_stream(4, b"probe", true).await.unwrap();
        task.await.unwrap();
    }

    #[tokio::test]
    async fn udp_client_send_stream_rejects_application_stream_response() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();
        let local = ConnectionId::new(1).unwrap();
        let peer = ConnectionId::new(2).unwrap();
        let mut client = UdpClient {
            socket: UdpSocket::bind("127.0.0.1:0").await.unwrap(),
            peer: server_addr,
            endpoint: EndpointState::new(Role::Client, ConnectionLimits::default(), MTU as u64),
            local_cid: local,
            deferred_receive_credit: false,
        };
        client.endpoint.install_connection_ids(local, peer).unwrap();
        let task = tokio::spawn(async move {
            let mut input = [0u8; MTU];
            let (_, source) = server.recv_from(&mut input).await.unwrap();
            let mut endpoint =
                EndpointState::<4>::new(Role::Server, ConnectionLimits::default(), MTU as u64);
            endpoint.install_connection_ids(peer, local).unwrap();
            endpoint
                .open_send_stream(8, INITIAL_MAX_STREAM_DATA)
                .unwrap();
            let mut output = [0u8; MTU];
            let (used, _) = endpoint
                .encode_stream_packet(local, 8, 0, true, b"response", &mut output)
                .unwrap();
            server.send_to(&output[..used], source).await.unwrap();
        });
        assert!(client.send_stream(4, b"probe", true).await.is_err());
        task.await.unwrap();
    }

    impl ImageSink for FakeFlash {
        type Error = ();

        fn begin(&mut self, manifest: &ImageManifest) -> Result<(), Self::Error> {
            self.bytes.clear();
            self.bytes.reserve(manifest.image_size as usize);
            Ok(())
        }

        fn write_block(&mut self, _index: u32, data: &[u8]) -> Result<(), Self::Error> {
            // Simulate a bounded synchronous erase/write cost of Recovery's
            // flash sink while keeping this entirely on the host. The live
            // adapter is still covered separately because this does not model
            // ESP-IDF flash-cache stalls.
            std::thread::sleep(Duration::from_micros(500));
            self.bytes.extend_from_slice(data);
            Ok(())
        }

        fn finish(&mut self, _manifest: &ImageManifest) -> Result<(), Self::Error> {
            Ok(())
        }
        fn abort(&mut self) {}
    }

    async fn run_object_transfer(size: usize, object_chunk: usize) {
        let directory = tempdir().unwrap();
        let artifact_root = directory.path().join("flash");
        let artifact = artifact_root.join("esp32c6/main-app.bin");
        std::fs::create_dir_all(artifact.parent().unwrap()).unwrap();
        let expected = (0..size).map(|n| (n % 251) as u8).collect::<Vec<_>>();
        std::fs::write(&artifact, &expected).unwrap();

        let mut request_body = [0u8; 64];
        // Exercise the real Main-flash request path.
        let encoded_len = encode_get(&mut request_body[1..], None, 13, 6).unwrap();
        request_body[0] = SERVICE_OBJECT;
        let request_len = encoded_len + 1;
        let probe = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let bind = probe.local_addr().unwrap();
        drop(probe);
        let server_task = tokio::spawn(run(UdpConfig {
            bind,
            artifact_root,
            // Match the bounded Recovery-side ledger used by the managed
            // flash bearer. This keeps the regression sensitive to the
            // one-packet-in-flight and sliding-credit rules.
            history_capacity: 2,
            object_chunk,
            ..UdpConfig::default()
        }));
        tokio::time::sleep(Duration::from_millis(10)).await;
        let mut client = UdpClient::connect_with_history_capacity(
            "127.0.0.1:0".parse().unwrap(),
            bind,
            ConnectionId::new(0xa1).unwrap(),
            2,
        )
        .await
        .unwrap();
        let mut records = RecordBuffer::new();
        let mut receiver = ImageReceiver::new(FakeFlash { bytes: Vec::new() });
        let (stream_id, first, fin) = client
            .request_stream(
                quic_lite::FIRST_CLIENT_BIDI_STREAM_ID,
                &request_body[..request_len],
                true,
            )
            .await
            .unwrap();
        assert_eq!(stream_id, OBJECT_STREAM);
        assert!(!fin);
        let mut packets = vec![(stream_id, first, fin)];
        while let Some((id, data, finished)) = packets.pop() {
            assert_eq!(id, OBJECT_STREAM);
            records.push(&data);
            while let Some((kind, body)) = records.next() {
                match kind {
                    RECORD_MANIFEST => {
                        receiver.on_manifest(&body).unwrap();
                    }
                    RECORD_BLOB => {
                        receiver.on_block(&body).unwrap();
                    }
                    RECORD_DONE => {
                        assert_eq!(receiver.on_done().unwrap(), ImageEvent::Complete);
                    }
                    other => panic!("unexpected object record {other}"),
                }
            }
            if finished {
                break;
            }
            packets.push(client.recv_stream().await.unwrap());
        }
        server_task.abort();
        assert!(receiver.is_complete());
        assert_eq!(receiver.sink_mut().bytes, expected);
    }

    struct RecoveryMirrorSink<'a> {
        records: &'a mut RecordBuffer,
        bytes: usize,
    }

    impl CopyingStreamEvents for RecoveryMirrorSink<'_> {
        type Error = ();

        fn stream_chunk(
            &mut self,
            stream: u64,
            _offset: u64,
            _end: bool,
            bytes: &[u8],
        ) -> Result<(), Self::Error> {
            if stream != OBJECT_STREAM {
                return Err(());
            }
            self.records.push(bytes);
            self.bytes = self.bytes.saturating_add(bytes.len());
            Ok(())
        }
    }

    struct RecoveryMirror {
        endpoint: RecoveryEndpoint<2>,
        ordered: CallbackStreams<Arc<Vec<u8>>>,
        records: RecordBuffer,
        receiver: ImageReceiver<FakeFlash>,
        drop_outbound_control: usize,
        /// Production Recovery drains completed flash slots from its bounded
        /// socket-timeout path.  Keep accepted record credit pending until
        /// that path runs; otherwise a host test can hide the exact
        /// sender-waits-for-MAX_* deadlock that a full initial window exposes.
        pending_flash_credit: usize,
        /// Mirror the real-flash bootstrap erase barrier. Recovery must ACK
        /// the full advertised application window before flash erase pauses
        /// Wi-Fi; until then completed records retain their storage credit.
        hold_credit_until_bootstrap: bool,
        delivered_stream_bytes: usize,
        timer_credit_updates: usize,
        /// Bearer-only ACK/control latency. The stream callback and transport
        /// policy remain unchanged, so this models the measured Wi-Fi
        /// refill-cycle delay without inventing Recovery-side ACK logic.
        outbound_control_delay: Duration,
        /// Control waiting in the simulated bearer. Delaying a packet on the
        /// air must not suspend Recovery's receive loop.
        pending_outbound: Vec<(Instant, Vec<u8>)>,
    }

    impl RecoveryMirror {
        fn new() -> Self {
            Self {
                endpoint: RecoveryEndpoint::<2>::new(
                    Role::Client,
                    ConnectionLimits {
                        max_data: quic_lite::RECOVERY_INITIAL_MAX_DATA,
                        max_stream_data: quic_lite::RECOVERY_INITIAL_MAX_DATA,
                        ..ConnectionLimits::default()
                    },
                    MTU as u64,
                ),
                // Match fw/dmesh-fw-transport/src/flash.rs. This is deliberately
                // not UdpClient: the test must exercise Recovery's callback,
                // flow-credit, and two-stage ACK behavior.
                ordered: CallbackStreams::new(2, RECOVERY_REORDER_CAPACITY_BYTES),
                records: RecordBuffer::new(),
                receiver: ImageReceiver::new(FakeFlash { bytes: Vec::new() }),
                drop_outbound_control: 0,
                pending_flash_credit: 0,
                hold_credit_until_bootstrap: false,
                delivered_stream_bytes: 0,
                timer_credit_updates: 0,
                outbound_control_delay: Duration::ZERO,
                pending_outbound: Vec::new(),
            }
        }

        fn queue_outbound(&mut self, output: Vec<u8>) {
            if self.drop_outbound_control != 0 {
                self.drop_outbound_control -= 1;
                return;
            }
            self.pending_outbound
                .push((Instant::now() + self.outbound_control_delay, output));
        }

        async fn flush_outbound(&mut self, socket: &UdpSocket, peer: SocketAddr) -> Result<()> {
            let now = Instant::now();
            let mut index = 0;
            while index < self.pending_outbound.len() {
                if self.pending_outbound[index].0 > now {
                    index += 1;
                    continue;
                }
                let (_, output) = self.pending_outbound.swap_remove(index);
                socket.send_to(&output, peer).await?;
            }
            Ok(())
        }

        fn accept_recovery_records(
            stream: u64,
            records: &mut RecordBuffer,
            receiver: &mut ImageReceiver<FakeFlash>,
        ) -> usize {
            assert_eq!(stream, OBJECT_STREAM);
            let mut released = 0usize;
            while let Some((kind, body)) = records.next() {
                let event = match kind {
                    RECORD_MANIFEST => receiver.on_manifest(&body).unwrap(),
                    RECORD_BLOB => receiver.on_block(&body).unwrap(),
                    RECORD_DONE => receiver.on_done().unwrap(),
                    other => panic!("unexpected Recovery mirror record {other}"),
                };
                if kind == RECORD_DONE {
                    assert_eq!(event, ImageEvent::Complete);
                }
                // Match Recovery's fixed record sink: durable/reusable
                // storage returns exactly the framed record bytes, never an
                // arbitrary transport-packet size.
                released = released.saturating_add(5 + body.len());
            }
            released
        }

        async fn receive_one(
            &mut self,
            socket: &UdpSocket,
            peer: SocketAddr,
            packet: &[u8],
            now_ms: u64,
        ) -> Result<()> {
            self.flush_outbound(socket, peer).await?;
            // Match Recovery's receive loop: packet arrival advances the
            // transport clock before delayed ACK eligibility is evaluated.
            // Without this, a continuously nonempty host socket can leave a
            // mirror's ACK timer at its old value indefinitely.
            self.endpoint.set_time(now_ms);
            let mut transport_out = [0u8; MTU];
            let mut outputs: Vec<Vec<u8>> = Vec::new();
            let (endpoint, ordered, records, receiver) = (
                &mut self.endpoint,
                &mut self.ordered,
                &mut self.records,
                &mut self.receiver,
            );
            let mut released_credit = 0usize;
            let mut delivered_bytes = 0usize;
            endpoint
                .receive_with_committed_callback_dispositions(packet, |stream| {
                    let consumed = {
                        let mut sink = RecoveryMirrorSink { records, bytes: 0 };
                        ordered
                            .receive_copying(
                                stream.id,
                                Arc::new(stream.data.to_vec()),
                                stream.offset,
                                0..stream.data.len(),
                                stream.fin,
                                &mut sink,
                            )
                            .map_err(|_| quic_lite::Error::Invalid)?;
                        sink.bytes
                    };
                    if consumed != 0 {
                        delivered_bytes = delivered_bytes.saturating_add(consumed);
                        released_credit = released_credit.saturating_add(
                            Self::accept_recovery_records(stream.id, records, receiver),
                        );
                    }
                    Ok(if consumed == 0 {
                        CommittedStreamDisposition::Reack
                    } else {
                        // Recovery first ACKs the drained burst, then
                        // returns credit only after its record storage is
                        // reusable. This catches a benchmark path that
                        // accidentally retains bootstrap credit forever.
                        CommittedStreamDisposition::Deferred
                    })
                })
                .map_err(|error| anyhow::anyhow!("Recovery mirror input: {error:?}"))?;
            self.delivered_stream_bytes =
                self.delivered_stream_bytes.saturating_add(delivered_bytes);
            if let Some(used) = endpoint
                .poll_transmit(&mut transport_out)
                .map_err(|error| anyhow::anyhow!("Recovery mirror ACK: {error:?}"))?
            {
                outputs.push(transport_out[..used].to_vec());
            }
            if released_credit != 0 {
                self.pending_flash_credit =
                    self.pending_flash_credit.saturating_add(released_credit);
            }
            for output in outputs {
                self.queue_outbound(output);
            }
            self.flush_outbound(socket, peer).await?;
            Ok(())
        }

        /// Mirror Recovery's bounded `recvfrom` timeout.  Delayed ACKs and
        /// other transport control are clock-driven; they must not depend on
        /// another application datagram arriving.  This deliberately emits
        /// opaque transport output only, matching the shared ESP firmware runtime.
        async fn poll_timer(
            &mut self,
            socket: &UdpSocket,
            peer: SocketAddr,
            now_ms: u64,
        ) -> Result<()> {
            self.flush_outbound(socket, peer).await?;
            self.endpoint.set_time(now_ms);
            let released_credit = if self.hold_credit_until_bootstrap
                // Object transfer opens another record only when that whole
                // record fits. It can be credit-blocked just below the byte
                // limit; mirror the sink's bounded record reserve.
                && self.delivered_stream_bytes
                    < quic_lite::RECOVERY_INITIAL_MAX_DATA as usize - (5 + 12 + BLOCK_SIZE)
            {
                0
            } else {
                core::mem::take(&mut self.pending_flash_credit)
            };
            if released_credit != 0 {
                self.timer_credit_updates = self.timer_credit_updates.saturating_add(1);
                self.endpoint
                    .stream_consumed_deferred(OBJECT_STREAM, released_credit)
                    .map_err(|error| anyhow::anyhow!("Recovery mirror timer credit: {error:?}"))?;
            }
            let mut output = [0u8; MTU];
            if let Some(used) = self
                .endpoint
                .poll_transmit(&mut output)
                .map_err(|error| anyhow::anyhow!("Recovery mirror timer: {error:?}"))?
            {
                self.queue_outbound(output[..used].to_vec());
            }
            self.flush_outbound(socket, peer).await?;
            Ok(())
        }
    }

    #[derive(Debug, Default)]
    struct RecoveryMirrorResult {
        /// Stream datagrams intentionally withheld before Recovery's
        /// transport.  This is a bearer fault, not an application fault.
        dropped_streams: usize,
        /// A withheld stream offset later observed in a fresh-number packet.
        /// The sender has no other reason to emit the same stream range, so
        /// this is direct host-side proof of a transport retransmission.
        recovered_streams: usize,
        /// A repeated server stream offset in a fresh packet number that was
        /// not intentionally withheld. It is host-side evidence of a
        /// retransmission caused solely by ACK/refill timing.
        unexpected_retransmissions: usize,
        /// Completed record storage first became reusable while the socket
        /// was empty, so Recovery had to advertise MAX_* from its timer path.
        timer_credit_updates: usize,
    }

    async fn run_recovery_mirror(
        size: usize,
        object_chunk: usize,
        history_capacity: usize,
        ack_frequency: u8,
        drop_outbound_control: usize,
        drop_first_stream: bool,
        late_loss_burst: bool,
        drop_initial_alternate: bool,
        outbound_control_delay: Duration,
    ) -> RecoveryMirrorResult {
        run_recovery_mirror_with_bootstrap_erase(
            size,
            object_chunk,
            history_capacity,
            ack_frequency,
            drop_outbound_control,
            drop_first_stream,
            late_loss_burst,
            drop_initial_alternate,
            outbound_control_delay,
            false,
        )
        .await
    }

    async fn run_recovery_mirror_with_bootstrap_erase(
        size: usize,
        object_chunk: usize,
        history_capacity: usize,
        ack_frequency: u8,
        drop_outbound_control: usize,
        drop_first_stream: bool,
        late_loss_burst: bool,
        drop_initial_alternate: bool,
        outbound_control_delay: Duration,
        hold_credit_until_bootstrap: bool,
    ) -> RecoveryMirrorResult {
        let directory = tempdir().unwrap();
        let artifact_root = directory.path().join("flash");
        let artifact = artifact_root.join("esp32c6/main-app.bin");
        std::fs::create_dir_all(artifact.parent().unwrap()).unwrap();
        let expected = (0..size).map(|n| (n % 251) as u8).collect::<Vec<_>>();
        std::fs::write(&artifact, &expected).unwrap();

        let mut request_body = [0u8; 64];
        let encoded_len = encode_get(&mut request_body[2..], None, 13, 6).unwrap();
        request_body[0] = SERVICE_OBJECT;
        // Match Recovery's transport-service envelope. The host must not
        // silently select its listener default when this test requests a
        // specific delayed-ACK profile.
        request_body[1] = ack_frequency.clamp(1, quic_lite::ACK_RANGE_CAPACITY as u8);
        let request_len = encoded_len + 2;
        let probe = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let bind = probe.local_addr().unwrap();
        drop(probe);
        let server_task = tokio::spawn(run(UdpConfig {
            bind,
            artifact_root,
            history_capacity,
            object_chunk,
            // Exercise the explicit Recovery profile while the automatic
            // memory-policy tick is active. A regression must not widen the
            // four-packet service profile behind the test's back.
            ledger_resize_interval: Duration::from_millis(1),
            ledger_memory: Some(LedgerMemorySnapshot {
                total_bytes: 512 * 1024 * 1024,
                available_bytes: 512 * 1024 * 1024,
            }),
            ..UdpConfig::default()
        }));
        tokio::time::sleep(Duration::from_millis(10)).await;

        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_cid = ConnectionId::new(1).unwrap();
        let mut open = [0u8; MTU];
        let open_len = encode_bootstrap_open(client_cid, 0, &mut open).unwrap();
        socket.send_to(&open[..open_len], bind).await.unwrap();
        let mut input = [0u8; MTU];
        let server_cid = loop {
            let (len, peer) =
                tokio::time::timeout(Duration::from_secs(2), socket.recv_from(&mut input))
                    .await
                    .unwrap()
                    .unwrap();
            if peer == bind {
                if let Ok((_, cid)) = decode_bootstrap_ack(&input[..len], client_cid) {
                    break cid;
                }
            }
        };
        let mut mirror = RecoveryMirror::new();
        mirror.hold_credit_until_bootstrap = hold_credit_until_bootstrap;
        mirror
            .endpoint
            .install_connection_ids(client_cid, server_cid)
            .unwrap();
        mirror.endpoint.set_ack_frequency(ack_frequency);
        mirror.drop_outbound_control = drop_outbound_control;
        mirror.outbound_control_delay = outbound_control_delay;
        mirror
            .endpoint
            .open_send_stream(FIRST_CLIENT_BIDI_STREAM_ID, INITIAL_MAX_STREAM_DATA)
            .unwrap();
        let mut request = [0u8; MTU];
        let (request_used, _) = mirror
            .endpoint
            .encode_stream_packet(
                server_cid,
                FIRST_CLIENT_BIDI_STREAM_ID,
                0,
                true,
                &request_body[..request_len],
                &mut request,
            )
            .unwrap();
        socket
            .send_to(&request[..request_used], bind)
            .await
            .unwrap();

        let started = Instant::now();
        // The host suite runs several Recovery fault profiles concurrently.
        // Keep a generous absolute cap, but fail a real transport deadlock on
        // lack of delivered stream progress rather than scheduler contention.
        let deadline = started + Duration::from_secs(60);
        let mut last_delivery = started;
        let mut last_delivered_bytes = 0usize;
        let mut mirror_datagrams = 0usize;
        let mut drop_first_stream = drop_first_stream;
        let mut stream_datagrams = 0usize;
        let mut late_drops_remaining = if late_loss_burst { 3usize } else { 0 };
        let mut dropped_streams = Vec::new();
        let mut delivered_stream_offsets = HashMap::new();
        // The injected alternating-loss burst models loss of the first flight.
        // A retransmission carries the same stream offset in a fresh packet and
        // must be admitted; otherwise the test fault model can discard repairs
        // indefinitely instead of testing recovery.
        let mut initial_stream_offsets = HashSet::new();
        let mut result = RecoveryMirrorResult::default();
        while !mirror.receiver.is_complete() {
            if mirror.delivered_stream_bytes != last_delivered_bytes {
                last_delivered_bytes = mirror.delivered_stream_bytes;
                last_delivery = Instant::now();
            }
            assert!(
                last_delivery.elapsed() < Duration::from_secs(10),
                "Recovery mirror made no delivery progress for 10 seconds after {mirror_datagrams} datagrams; delivered={} pending_credit={}",
                mirror.delivered_stream_bytes,
                mirror.pending_flash_credit,
            );
            let remaining = deadline.saturating_duration_since(Instant::now());
            assert!(
                !remaining.is_zero(),
                "Recovery mirror transfer timed out after {mirror_datagrams} datagrams; delivered={} pending_credit={}",
                mirror.delivered_stream_bytes,
                mirror.pending_flash_credit,
            );
            match tokio::time::timeout(
                remaining.min(Duration::from_millis(10)),
                socket.recv_from(&mut input),
            )
            .await
            {
                Ok(Ok((len, peer))) => {
                    assert_eq!(peer, bind);
                    mirror_datagrams += 1;
                    let (header, header_len) = ShortHeader::decode(&input[..len]).unwrap();
                    let (frame, _) = quic_lite::decode_frame(&input[header_len..]).unwrap();
                    if let Frame::Stream(stream) = &frame {
                        if let Some(index) =
                            dropped_streams.iter().position(|(offset, packet_number)| {
                                *offset == stream.offset && *packet_number != header.packet_number
                            })
                        {
                            dropped_streams.swap_remove(index);
                            result.recovered_streams += 1;
                        }
                        stream_datagrams += 1;
                        let first_stream_drop = drop_first_stream;
                        let late_stream_drop = stream_datagrams >= 849 && late_drops_remaining != 0;
                        // A bounded alternating initial burst models the
                        // ESP/lwIP overflow seen live: the AP reports the
                        // frames transmitted, while Recovery observes only
                        // about half. This must recover through selective
                        // ACK/loss repair, not require another application
                        // record or a service restart.
                        let first_stream_offset = initial_stream_offsets.insert(stream.offset);
                        let initial_alternate_drop = drop_initial_alternate
                            && first_stream_offset
                            && initial_stream_offsets.len() <= 64
                            && initial_stream_offsets.len() % 2 == 0;
                        let drop_packet =
                            first_stream_drop || late_stream_drop || initial_alternate_drop;
                        if drop_packet {
                            drop_first_stream = false;
                            if late_stream_drop {
                                late_drops_remaining -= 1;
                            }
                            dropped_streams.push((stream.offset, header.packet_number));
                            result.dropped_streams += 1;
                            continue;
                        }
                        if let Some(previous_packet_number) =
                            delivered_stream_offsets.insert(stream.offset, header.packet_number)
                        {
                            if previous_packet_number != header.packet_number {
                                result.unexpected_retransmissions += 1;
                            }
                        }
                    }
                    match mirror
                        .receive_one(
                            &socket,
                            peer,
                            &input[..len],
                            started.elapsed().as_millis() as u64,
                        )
                        .await
                    {
                        Ok(()) => {}
                        // Recovery keeps its socket loop alive when the
                        // bounded callback credit rejects far-ahead data.
                        // Earlier selective ACKs make the sender repair the
                        // missing range; this is backpressure, not a session
                        // failure.
                        Err(error)
                            if error.to_string().contains("FlowControl")
                                || error.to_string().contains("Invalid") => {}
                        Err(error) => panic!("Recovery mirror input failed: {error}"),
                    }
                }
                Ok(Err(error)) => panic!("Recovery mirror receive failed: {error}"),
                Err(_) => mirror
                    .poll_timer(&socket, bind, started.elapsed().as_millis() as u64)
                    .await
                    .unwrap(),
            }
        }
        server_task.abort();
        assert_eq!(mirror.receiver.sink_mut().bytes, expected);
        assert!(
            dropped_streams.is_empty(),
            "host did not retransmit {} intentionally withheld stream ranges",
            dropped_streams.len()
        );
        result.timer_credit_updates = mirror.timer_credit_updates;
        result
    }

    #[tokio::test]
    async fn recovery_receive_loop_matrix_matches_device_profiles() {
        for history_capacity in [2, 4, 16, 32] {
            // Exercise both the 512-byte diagnostic profile and the normal
            // MTU-friendly production profile.
            for object_chunk in [512, OBJECT_CHUNK] {
                let result = run_recovery_mirror(
                    128 * 1024 + 123,
                    object_chunk,
                    history_capacity,
                    2,
                    0,
                    false,
                    false,
                    false,
                    Duration::ZERO,
                )
                .await;
                assert_eq!(result.dropped_streams, 0);
            }
        }
    }

    #[tokio::test]
    async fn recovery_profile_benchmark_matches_esp32_dry_run_size() {
        let size = 2_122_528;
        let started = Instant::now();
        let object_chunk = OBJECT_CHUNK;
        let result = run_recovery_mirror(
            size,
            object_chunk,
            32,
            8,
            0,
            false,
            false,
            false,
            Duration::ZERO,
        )
        .await;
        assert_eq!(result.dropped_streams, 0);
        assert!(
            result.timer_credit_updates != 0,
            "the full Recovery profile must exercise timer-driven flash credit",
        );
        let elapsed = started.elapsed();
        let mib_per_second = size as f64 / (1024.0 * 1024.0) / elapsed.as_secs_f64();
        eprintln!(
            "recovery host benchmark size={} chunk={} history=32 ack_frequency=8 elapsed_ms={} speed_mib_s={:.3}",
            size,
            object_chunk,
            elapsed.as_millis(),
            mib_per_second
        );
    }

    #[tokio::test]
    async fn recovery_profile_recovers_when_first_delayed_ack_is_lost() {
        // A 2 MiB image has a manifest larger than the initial congestion
        // window.  Drop the first timer-driven ACK exactly as Wi-Fi can; the
        // server must PTO a retained packet even though its history is not
        // yet full, then resume the same ordered response stream.
        let result = run_recovery_mirror(
            2_122_528,
            OBJECT_CHUNK,
            16,
            8,
            1,
            false,
            false,
            false,
            Duration::ZERO,
        )
        .await;
        assert_eq!(result.dropped_streams, 0);
    }

    #[tokio::test]
    async fn recovery_profile_recovers_from_late_three_packet_loss_burst() {
        // Matches the device stall boundary: do not let a late selective-ACK
        // gap turn an otherwise healthy 2 MiB Recovery transfer into silence.
        let result = run_recovery_mirror(
            2_122_528,
            OBJECT_CHUNK,
            32,
            8,
            0,
            false,
            true,
            false,
            Duration::ZERO,
        )
        .await;
        assert_eq!(result.dropped_streams, 3);
        assert_eq!(result.recovered_streams, 3);
    }

    #[tokio::test]
    async fn recovery_profile_reorders_one_stream_packet_with_bounded_credit() {
        // This mirrors the Wi-Fi fault that previously let the server send
        // roughly 256 KiB past a missing early range, overflowing Recovery's
        // callback buffer.  The receiver must advertise only its bounded
        // reorder budget and the sender must repair the gap.
        let result = run_recovery_mirror(
            2_122_528,
            OBJECT_CHUNK,
            16,
            8,
            0,
            true,
            false,
            false,
            Duration::ZERO,
        )
        .await;
        assert_eq!(result.dropped_streams, 1);
        assert_eq!(result.recovered_streams, 1);
    }

    #[tokio::test]
    async fn recovery_profile_delayed_ack_refills_without_spurious_retransmission() {
        // The live AP shows roughly one sender refill per ACK and recurrent
        // 10--25 ms gaps.  Model only that bearer delay: Recovery continues
        // to use its normal callback, flow credit, and transport-owned ACK
        // policy. A contiguous delayed ACK must refill the sender without a
        // replacement stream packet or congestion-loss episode.
        let result = run_recovery_mirror(
            128 * 1024,
            OBJECT_CHUNK,
            16,
            4,
            0,
            false,
            false,
            false,
            Duration::from_millis(18),
        )
        .await;
        assert_eq!(result.dropped_streams, 0);
        assert_eq!(result.unexpected_retransmissions, 0);
    }

    #[tokio::test]
    async fn recovery_real_flash_acks_bootstrap_before_erase_credit_barrier() {
        // Mirror MainSink's real-flash ordering: receive and ACK the whole
        // initial 76 KiB application window, withhold MAX_* while erase owns
        // the radio, then resume only through returned storage slots. This
        // must resume by the timer-driven MAX_* update rather than deadlock
        // below a partial record boundary.
        let result = run_recovery_mirror_with_bootstrap_erase(
            2_122_528,
            OBJECT_CHUNK,
            32,
            8,
            0,
            false,
            false,
            false,
            Duration::ZERO,
            true,
        )
        .await;
        assert_eq!(result.dropped_streams, 0);
        assert_eq!(result.recovered_streams, 0);
        assert!(result.timer_credit_updates > 0);
    }

    #[tokio::test]
    async fn recovery_profile_recovers_after_a_full_window_of_lost_acks() {
        // This is the exact host-side analogue of a live sender retaining a
        // full 32-packet flight while Recovery emits no usable ACKs. Once a
        // PTO probe reaches the receiver, duplicate re-ACK and normal window
        // refill must complete the stream; the connection may not wait for a
        // new application record or an external socket event.
        let result = run_recovery_mirror(
            128 * 1024,
            OBJECT_CHUNK,
            32,
            8,
            4,
            false,
            false,
            false,
            Duration::ZERO,
        )
        .await;
        assert_eq!(result.dropped_streams, 0);
    }

    #[tokio::test]
    async fn recovery_profile_recovers_from_initial_alternating_loss_burst() {
        // The fault is confined to the first 64 stream datagrams (32 drops).
        // 128 KiB leaves enough post-repair data to verify resumed progress
        // without making this host determinism gate compete with the larger
        // multi-megabyte Recovery benchmark tests.
        let result = run_recovery_mirror(
            128 * 1024,
            OBJECT_CHUNK,
            32,
            8,
            0,
            false,
            false,
            true,
            Duration::ZERO,
        )
        .await;
        assert_eq!(result.dropped_streams, 32);
        assert_eq!(result.recovered_streams, 32);
    }

    #[test]
    fn recovery_production_window_fits_callback_reorder_budget() {
        const RECEIVER_PACKET_BUDGET: usize =
            quic_lite::RECOVERY_MAX_DIAGNOSTIC_IN_FLIGHT_PACKETS as usize;
        const HOST_PAYLOAD_BYTES: usize = quic_lite::DEFAULT_MAX_DATAGRAM_SIZE;
        assert!(
            RECEIVER_PACKET_BUDGET * HOST_PAYLOAD_BYTES <= RECOVERY_REORDER_CAPACITY_BYTES,
            "Recovery callback reassembly must cover every outstanding host payload"
        );
        assert!(
            RECOVERY_MAX_HISTORY_PACKETS >= RECEIVER_PACKET_BUDGET,
            "host retransmission ledger must cover Recovery's packet budget"
        );
        // Packet history and byte credit are deliberately independent. The
        // C6 can retain/reorder a 64-packet sender history, while its fixed
        // application pool admits eight complete 4 KiB records before flash
        // releases credit.  Requiring both at startup would overcommit
        // internal RAM and turn a valid manifest into an allocator abort.
        assert!(
            quic_lite::RECOVERY_INITIAL_MAX_DATA as usize >= 8 * (5 + 12 + 4096),
            "initial byte credit must cover the fixed Recovery blob pool"
        );
    }

    #[tokio::test]
    async fn udp_bearer_streams_object_records_with_transport_ack() {
        run_object_transfer(512 * 1024 + 123, OBJECT_CHUNK).await;
    }

    #[tokio::test]
    async fn udp_object_transfer_size_matrix() {
        // Exercise the same bootstrapped persistent object path at the small
        // control/data boundaries and at a multi-megabyte transfer size. The
        // fake flash sink keeps this deterministic and bounded without
        // touching a real device.
        for object_chunk in [512, OBJECT_CHUNK] {
            for size in [4 * 1024, 64 * 1024, 512 * 1024, 2 * 1024 * 1024] {
                run_object_transfer(size, object_chunk).await;
            }
        }
    }

    #[tokio::test]
    async fn udp_bootstrap_assigns_directional_cids_and_persistent_metrics_stream() {
        let root = tempdir().unwrap();
        let probe = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let bind = probe.local_addr().unwrap();
        drop(probe);
        let server_task = tokio::spawn(run(UdpConfig {
            bind,
            artifact_root: root.path().to_path_buf(),
            history_capacity: 2,
            ..UdpConfig::default()
        }));
        tokio::time::sleep(Duration::from_millis(10)).await;
        let mut client = UdpClient::connect(
            "127.0.0.1:0".parse().unwrap(),
            bind,
            ConnectionId::new(0x55).unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(client.endpoint.local_connection_id().unwrap().value(), 0x55);
        assert_eq!(client.endpoint.next_packet_number, 1);
        let server_cid = client.endpoint.peer_connection_id().unwrap();
        assert_ne!(server_cid.value(), 0);
        assert_ne!(server_cid, client.endpoint.local_connection_id().unwrap());
        let (_response_stream, response, fin) = client
            .request_stream(
                quic_lite::FIRST_CLIENT_BIDI_STREAM_ID,
                &[SERVICE_METRICS],
                true,
            )
            .await
            .unwrap();
        assert!(fin);
        assert!(
            core::str::from_utf8(&response)
                .unwrap()
                .contains("metrics_version=1")
        );
        assert!(
            core::str::from_utf8(&response)
                .unwrap()
                .contains("history_capacity=2")
        );
        assert!(
            core::str::from_utf8(&response)
                .unwrap()
                .contains("next_packet_number=1")
        );
        server_task.abort();
    }

    #[tokio::test]
    async fn udp_auto_ledger_capacity_uses_injected_memory_policy() {
        let root = tempdir().unwrap();
        let probe = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let bind = probe.local_addr().unwrap();
        drop(probe);
        let server_task = tokio::spawn(run(UdpConfig {
            bind,
            artifact_root: root.path().to_path_buf(),
            history_capacity: 0,
            max_active_connections: 1,
            ledger_memory_policy: quic_lite::ledger::LedgerMemoryPolicy {
                min_packets: 4,
                max_packets: 16,
                reserve_bytes: 0,
                ..quic_lite::ledger::LedgerMemoryPolicy::default()
            },
            ledger_memory: Some(quic_lite::ledger::LedgerMemorySnapshot {
                total_bytes: 1024 * 1024,
                available_bytes: 1024 * 1024,
            }),
            ..UdpConfig::default()
        }));
        tokio::time::sleep(Duration::from_millis(10)).await;
        let mut client = UdpClient::connect(
            "127.0.0.1:0".parse().unwrap(),
            bind,
            ConnectionId::new(0x5a).unwrap(),
        )
        .await
        .unwrap();
        let (_, metrics, _) = client
            .request_stream(
                quic_lite::FIRST_CLIENT_BIDI_STREAM_ID,
                &[SERVICE_METRICS],
                true,
            )
            .await
            .unwrap();
        let metrics = core::str::from_utf8(&metrics).unwrap();
        assert!(metrics.contains("history_capacity=16"));
        assert!(metrics.contains("history_storage_slots=16"));
        server_task.abort();
    }

    #[tokio::test]
    async fn udp_runtime_ledger_resize_grows_after_stable_memory_samples() {
        let root = tempdir().unwrap();
        let probe = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let bind = probe.local_addr().unwrap();
        drop(probe);
        let server_task = tokio::spawn(run(UdpConfig {
            bind,
            artifact_root: root.path().to_path_buf(),
            // Zero selects the memory-aware policy; an explicit capacity is
            // intentionally fixed for embedded-compatible profiles.
            history_capacity: 0,
            max_active_connections: 1,
            ledger_memory_policy: quic_lite::ledger::LedgerMemoryPolicy {
                min_packets: 4,
                max_packets: 16,
                reserve_bytes: 0,
                ..quic_lite::ledger::LedgerMemoryPolicy::default()
            },
            ledger_memory: Some(quic_lite::ledger::LedgerMemorySnapshot {
                total_bytes: 1024 * 1024,
                available_bytes: 1024 * 1024,
            }),
            ledger_resize_interval: Duration::from_millis(10),
            ..UdpConfig::default()
        }));
        tokio::time::sleep(Duration::from_millis(10)).await;
        let mut client = UdpClient::connect(
            "127.0.0.1:0".parse().unwrap(),
            bind,
            ConnectionId::new(0x5b).unwrap(),
        )
        .await
        .unwrap();
        let mut final_metrics = String::new();
        for (index, stream_id) in [4_u64, 8, 12, 16].into_iter().enumerate() {
            tokio::time::sleep(Duration::from_millis(20)).await;
            let (_, metrics, _) = client
                .request_stream(stream_id, &[SERVICE_METRICS], true)
                .await
                .unwrap();
            if index == 3 {
                final_metrics = String::from_utf8(metrics).unwrap();
            }
        }
        assert!(final_metrics.contains("history_capacity=16"));
        assert!(final_metrics.contains("history_storage_slots=16"));
        server_task.abort();
    }

    #[tokio::test]
    async fn udp_bootstrap_supports_two_connections_and_multiple_operations() {
        let root = tempdir().unwrap();
        let probe = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let bind = probe.local_addr().unwrap();
        drop(probe);
        let server_task = tokio::spawn(run(UdpConfig {
            bind,
            artifact_root: root.path().to_path_buf(),
            // Exercise a bounded diagnostic burst. The default (exercised
            // by the Recovery profile tests) remains unpaced/unlimited.
            iperf_burst_packets: 2,
            iperf_burst_delay: Duration::from_micros(100),
            ..UdpConfig::default()
        }));
        tokio::time::sleep(Duration::from_millis(10)).await;
        let mut clients = Vec::new();
        for cid in [0x61, 0x71] {
            clients.push(
                UdpClient::connect(
                    "127.0.0.1:0".parse().unwrap(),
                    bind,
                    ConnectionId::new(cid).unwrap(),
                )
                .await
                .unwrap(),
            );
        }
        let mut server_cids = Vec::new();
        for (index, client) in clients.iter_mut().enumerate() {
            server_cids.push(client.endpoint.peer_connection_id().unwrap());
            let stream = quic_lite::FIRST_CLIENT_BIDI_STREAM_ID + index as u64 * 4;
            let (_, metrics, _) = client
                .request_stream(stream, &[SERVICE_METRICS], true)
                .await
                .unwrap();
            assert!(
                core::str::from_utf8(&metrics)
                    .unwrap()
                    .contains("metrics_version=1")
            );
            let event_stream = stream + 4;
            let (_, events, _) = client
                .request_stream(event_stream, &[SERVICE_EVENTS], true)
                .await
                .unwrap();
            assert!(
                core::str::from_utf8(&events)
                    .unwrap()
                    .contains("events_version=")
            );
            assert!(core::str::from_utf8(&events).unwrap().contains("events="));
            let echo_stream = event_stream + 4;
            let (_, echo, _) = client
                .request_stream(
                    echo_stream,
                    &[SERVICE_ECHO, b'p', b'r', b'o', b'b', b'e'],
                    true,
                )
                .await
                .unwrap();
            // Echo is a payload-preserving liveness primitive, not a
            // connection-status formatter. Status/metrics are separate
            // services and may be requested on adjacent streams.
            assert_eq!(echo, b"probe");
            let iperf_stream = echo_stream + 4;
            let mut iperf_request = Vec::from([SERVICE_IPERF]);
            iperf_request.extend_from_slice(&4096u64.to_be_bytes());
            iperf_request.extend_from_slice(&512u16.to_be_bytes());
            let (_, first, mut iperf_finished) = client
                .request_stream(iperf_stream, &iperf_request, true)
                .await
                .unwrap();
            let mut iperf = first;
            while !iperf_finished {
                let (_, bytes, finished) = client.recv_stream().await.unwrap();
                iperf.extend_from_slice(&bytes);
                iperf_finished = finished;
            }
            assert_eq!(iperf.len(), 4096);
            let mut offset = 0usize;
            let mut packet_id = 0u32;
            while offset < iperf.len() {
                let used = (iperf.len() - offset).min(512);
                assert_eq!(
                    u32::from_be_bytes(iperf[offset..offset + 4].try_into().unwrap()),
                    packet_id,
                );
                assert!(
                    iperf[offset + 4..offset + used]
                        .iter()
                        .enumerate()
                        .all(|(index, byte)| { *byte == (offset + 4 + index) as u8 })
                );
                offset += used;
                packet_id = packet_id.wrapping_add(1);
            }
            let registry_stream = iperf_stream + 4;
            let (_, registry, _) = client
                .request_stream(registry_stream, &[SERVICE_STREAM], true)
                .await
                .unwrap();
            // `handlers` is compact CBOR `[[tag, name], ...]`, not a text
            // command surface. The names remain discovery metadata only.
            assert_eq!(registry.first(), Some(&0x89));
            assert!(
                registry
                    .windows(b"metrics".len())
                    .any(|item| item == b"metrics")
            );
            assert!(
                registry
                    .windows(b"events".len())
                    .any(|item| item == b"events")
            );
        }
        assert_ne!(server_cids[0], server_cids[1]);
        server_task.abort();
    }

    #[tokio::test]
    async fn udp_recovery_command_mode_reconnects_on_same_tuple_with_fresh_cid() {
        // Recovery keeps its UDP source port stable.  A completed connection
        // remains routable for delayed packets, so a second command-mode run
        // must use a new client CID rather than trying to bootstrap over the
        // old connection's monotonic packet-number space.
        let root = tempdir().unwrap();
        let probe = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let bind = probe.local_addr().unwrap();
        drop(probe);
        let server_task = tokio::spawn(run(UdpConfig {
            bind,
            artifact_root: root.path().to_path_buf(),
            ..UdpConfig::default()
        }));
        tokio::time::sleep(Duration::from_millis(10)).await;

        // Reuse exactly one local UDP tuple, as Recovery does on hardware.
        let client_probe = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_bind = client_probe.local_addr().unwrap();
        drop(client_probe);
        let mut first =
            UdpClient::connect(client_bind, bind, ConnectionId::new(0x1_0000_0001).unwrap())
                .await
                .unwrap();
        let (_, first_metrics, _) = first
            .request_stream(FIRST_CLIENT_BIDI_STREAM_ID, &[SERVICE_METRICS], true)
            .await
            .unwrap();
        assert!(
            core::str::from_utf8(&first_metrics)
                .unwrap()
                .contains("metrics_version=1")
        );
        drop(first);

        // This is the old Recovery behavior: CID=1 on every command. The
        // listener correctly treats it as a stale bootstrap rather than
        // reusing a packet-number space after application traffic.
        assert!(
            UdpClient::connect(client_bind, bind, ConnectionId::new(0x1_0000_0001).unwrap(),)
                .await
                .is_err()
        );

        let mut second =
            UdpClient::connect(client_bind, bind, ConnectionId::new(0x1_0000_0002).unwrap())
                .await
                .unwrap();
        let (_, second_metrics, _) = second
            .request_stream(FIRST_CLIENT_BIDI_STREAM_ID, &[SERVICE_METRICS], true)
            .await
            .unwrap();
        assert!(
            core::str::from_utf8(&second_metrics)
                .unwrap()
                .contains("metrics_version=1")
        );
        server_task.abort();
    }

    #[tokio::test]
    async fn udp_iperf_honors_recovery_bootstrap_credit_before_first_ack() {
        let root = tempdir().unwrap();
        let probe = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let bind = probe.local_addr().unwrap();
        drop(probe);
        let server_task = tokio::spawn(run(UdpConfig {
            bind,
            artifact_root: root.path().to_path_buf(),
            ..UdpConfig::default()
        }));
        tokio::time::sleep(Duration::from_millis(10)).await;
        let limits = ConnectionLimits {
            max_data: quic_lite::RECOVERY_INITIAL_MAX_DATA,
            max_stream_data: quic_lite::RECOVERY_INITIAL_MAX_DATA,
            ..ConnectionLimits::default()
        };
        let mut client = UdpClient::connect_with_limits(
            "127.0.0.1:0".parse().unwrap(),
            bind,
            ConnectionId::new(0xb5).unwrap(),
            4,
            limits,
        )
        .await
        .unwrap();
        client.set_ack_frequency(4);
        let mut request = Vec::from([SERVICE_IPERF]);
        request.extend_from_slice(&120_000u64.to_be_bytes());
        request.extend_from_slice(&1200u16.to_be_bytes());
        let (_, first, mut finished) = client.request_stream(4, &request, true).await.unwrap();
        let mut received = first.len();
        while !finished {
            let (_, bytes, fin) = timeout(Duration::from_secs(2), client.recv_stream())
                .await
                .unwrap()
                .unwrap();
            received += bytes.len();
            finished = fin;
        }
        assert_eq!(received, 120_000);
        server_task.abort();
    }

    #[test]
    fn path_policy_control_is_bearer_neutral() {
        let control = TransportControl::default();
        assert_eq!(control.path_policy(), PathPolicy::HighestMeasuredSpeed);
        let policy = decode_path_policy(&[1, 3]).unwrap();
        control.set_path_policy(policy);
        assert_eq!(control.path_policy(), PathPolicy::Explicit(3));
        assert_eq!(
            decode_path_policy(&[2, 1]),
            Some(PathPolicy::AirtimeFirst { primary: 1 })
        );
        assert_eq!(decode_path_policy(&[9]), None);
    }

    #[tokio::test]
    async fn transport_control_carries_opaque_log_and_queued_command() {
        let root = tempdir().unwrap();
        let probe = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let bind = probe.local_addr().unwrap();
        drop(probe);
        let control = Arc::new(TransportControl::default());
        control.queue_command(vec![0xa1, 0x00, 0x18, 0x44]);
        let server_task = tokio::spawn(run(UdpConfig {
            bind,
            artifact_root: root.path().to_path_buf(),
            control: Some(control.clone()),
            ..UdpConfig::default()
        }));
        tokio::time::sleep(Duration::from_millis(10)).await;
        let mut client = UdpClient::connect(
            "127.0.0.1:0".parse().unwrap(),
            bind,
            ConnectionId::new(0x8c).unwrap(),
        )
        .await
        .unwrap();
        let log = [SERVICE_CONTROL, CONTROL_LOG, 0xa1, 0x04, 0x62, b'o', b'k'];
        let (_, response, finished) = client
            .request_stream(FIRST_CLIENT_BIDI_STREAM_ID, &log, true)
            .await
            .unwrap();
        assert!(finished);
        assert_eq!(
            response,
            [SERVICE_CONTROL, CONTROL_RESPONSE, 0xa1, 0x00, 0x18, 0x44]
        );
        assert_eq!(control.take_log().as_deref(), Some(&log[2..]));
        // The same opaque control handle used by a live Wi-Fi listener must
        // expose a current sender snapshot without requiring a packet trace.
        tokio::time::sleep(Duration::from_millis(2)).await;
        let stats = control.server_stats().expect("listener transport stats");
        assert!(stats.transport.received_datagrams >= 1);
        assert!(stats.transport.sent_datagrams >= 1);
        assert!(stats.transport.sent_stream_datagrams >= 1);
        server_task.abort();
    }

    #[tokio::test]
    async fn udp_wrong_peer_cannot_use_an_active_server_cid() {
        let root = tempdir().unwrap();
        let probe = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let bind = probe.local_addr().unwrap();
        drop(probe);
        let server_task = tokio::spawn(run(UdpConfig {
            bind,
            artifact_root: root.path().to_path_buf(),
            ..UdpConfig::default()
        }));
        tokio::time::sleep(Duration::from_millis(10)).await;
        let mut legitimate = UdpClient::connect(
            "127.0.0.1:0".parse().unwrap(),
            bind,
            ConnectionId::new(0xb1).unwrap(),
        )
        .await
        .unwrap();
        let server_cid = legitimate.endpoint.peer_connection_id().unwrap();

        let attacker = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut endpoint =
            EndpointState::<4>::new(Role::Client, ConnectionLimits::default(), MTU as u64);
        endpoint
            .install_connection_ids(ConnectionId::new(0xc1).unwrap(), server_cid)
            .unwrap();
        endpoint
            .open_send_stream(4, INITIAL_MAX_STREAM_DATA)
            .unwrap();
        let mut packet = [0u8; MTU];
        let (used, _) = endpoint
            .encode_stream_packet(server_cid, 4, 0, true, &[SERVICE_METRICS], &mut packet)
            .unwrap();
        attacker.send_to(&packet[..used], bind).await.unwrap();
        let mut response = [0u8; MTU];
        assert!(
            timeout(
                Duration::from_millis(100),
                attacker.recv_from(&mut response)
            )
            .await
            .is_err()
        );

        let (_, metrics, _) = legitimate
            .request_stream(
                quic_lite::FIRST_CLIENT_BIDI_STREAM_ID,
                &[SERVICE_METRICS],
                true,
            )
            .await
            .unwrap();
        assert!(
            core::str::from_utf8(&metrics)
                .unwrap()
                .contains("metrics_version=1")
        );
        server_task.abort();
    }

    #[tokio::test]
    async fn udp_malformed_established_datagram_does_not_kill_connection_task() {
        let root = tempdir().unwrap();
        let probe = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let bind = probe.local_addr().unwrap();
        drop(probe);
        let server_task = tokio::spawn(run(UdpConfig {
            bind,
            artifact_root: root.path().to_path_buf(),
            ..UdpConfig::default()
        }));
        tokio::time::sleep(Duration::from_millis(10)).await;
        let mut client = UdpClient::connect(
            "127.0.0.1:0".parse().unwrap(),
            bind,
            ConnectionId::new(0xd1).unwrap(),
        )
        .await
        .unwrap();
        let server_cid = client.endpoint.peer_connection_id().unwrap();
        let mut malformed = [0u8; MTU];
        let header_len = ShortHeader {
            flags: FLAG_FIXED,
            dcid: server_cid,
            packet_number: 90,
            packet_number_len: 4,
        }
        .encode(&mut malformed)
        .unwrap();
        malformed[header_len] = 0xff; // unknown frame type
        client
            .socket
            .send_to(&malformed[..header_len + 1], bind)
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;

        let (_, metrics, _) = client
            .request_stream(
                quic_lite::FIRST_CLIENT_BIDI_STREAM_ID,
                &[SERVICE_METRICS],
                true,
            )
            .await
            .unwrap();
        assert!(
            core::str::from_utf8(&metrics)
                .unwrap()
                .contains("metrics_version=1")
        );
        server_task.abort();
    }

    #[tokio::test]
    async fn udp_active_connection_capacity_rejects_new_open_boundedly() {
        let root = tempdir().unwrap();
        let probe = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let bind = probe.local_addr().unwrap();
        drop(probe);
        let server_task = tokio::spawn(run(UdpConfig {
            bind,
            artifact_root: root.path().to_path_buf(),
            max_active_connections: 1,
            ..UdpConfig::default()
        }));
        tokio::time::sleep(Duration::from_millis(10)).await;
        let mut first = UdpClient::connect(
            "127.0.0.1:0".parse().unwrap(),
            bind,
            ConnectionId::new(0xd1).unwrap(),
        )
        .await
        .unwrap();
        let second = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut open = [0u8; MTU];
        let used = encode_bootstrap_open(ConnectionId::new(0xd2).unwrap(), 0, &mut open).unwrap();
        second.send_to(&open[..used], bind).await.unwrap();
        let mut response = [0u8; MTU];
        assert!(
            timeout(Duration::from_millis(100), second.recv_from(&mut response))
                .await
                .is_err()
        );
        let (_, metrics, _) = first
            .request_stream(
                quic_lite::FIRST_CLIENT_BIDI_STREAM_ID,
                &[SERVICE_METRICS],
                true,
            )
            .await
            .unwrap();
        assert!(
            core::str::from_utf8(&metrics)
                .unwrap()
                .contains("metrics_version=1")
        );
        server_task.abort();
    }

    #[tokio::test]
    async fn udp_bootstrap_duplicate_replays_same_server_cid() {
        let root = tempdir().unwrap();
        let probe = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let bind = probe.local_addr().unwrap();
        drop(probe);
        let server_task = tokio::spawn(run(UdpConfig {
            bind,
            artifact_root: root.path().to_path_buf(),
            ..UdpConfig::default()
        }));
        tokio::time::sleep(Duration::from_millis(10)).await;
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let cid = ConnectionId::new(0x81).unwrap();
        let mut open = [0u8; MTU];
        let used = encode_bootstrap_open(cid, 0, &mut open).unwrap();
        client.send_to(&open[..used], bind).await.unwrap();
        let mut response = [0u8; MTU];
        let (first_len, _) = client.recv_from(&mut response).await.unwrap();
        let first_bytes = response[..first_len].to_vec();
        let (first_header, first_server) =
            decode_bootstrap_ack(&response[..first_len], cid).unwrap();
        let mut retry_open = [0u8; MTU];
        let retry_open_len = encode_bootstrap_open(cid, 1, &mut retry_open).unwrap();
        client
            .send_to(&retry_open[..retry_open_len], bind)
            .await
            .unwrap();
        let (second_len, _) = client.recv_from(&mut response).await.unwrap();
        let (second_header, second_server) =
            decode_bootstrap_ack(&response[..second_len], cid).unwrap();
        assert_eq!(first_server, second_server);
        assert_eq!(second_header.packet_number, first_header.packet_number + 1);
        assert_ne!(&response[..second_len], first_bytes.as_slice());

        // The pending key is the peer plus advertised client CID, not the
        // outer DCID or packet number. A retry with a new OPEN packet number
        // has the same stream-0 payload and must keep the server CID while
        // receiving a fresh, monotonic OPEN_ACK packet number.
        let mut conflicting = [0u8; MTU];
        let conflicting_len = encode_bootstrap_open(cid, 2, &mut conflicting).unwrap();
        client
            .send_to(&conflicting[..conflicting_len], bind)
            .await
            .unwrap();
        let (retry_len, _) = timeout(Duration::from_millis(100), client.recv_from(&mut response))
            .await
            .unwrap()
            .unwrap();
        let (retry_header, retry_server) =
            decode_bootstrap_ack(&response[..retry_len], cid).unwrap();
        assert_eq!(retry_server, first_server);
        assert_eq!(retry_header.packet_number, second_header.packet_number + 1);
        // Malformed and unknown non-zero-CID traffic must not terminate the
        // listener or poison another connection.
        client.send_to(&[0], bind).await.unwrap();
        let mut invalid_open = [0u8; 64];
        let invalid_header = ShortHeader {
            flags: FLAG_FIXED,
            dcid: ConnectionId::new(0).unwrap(),
            packet_number: 3,
            packet_number_len: 4,
        }
        .encode(&mut invalid_open)
        .unwrap();
        let invalid_frame = Frame::Ping
            .encode(&mut invalid_open[invalid_header..])
            .unwrap();
        client
            .send_to(&invalid_open[..invalid_header + invalid_frame], bind)
            .await
            .unwrap();
        let mut unknown = [0u8; 64];
        let unknown_header = ShortHeader {
            flags: FLAG_FIXED,
            dcid: ConnectionId::new(0xdead).unwrap(),
            packet_number: 0,
            packet_number_len: 4,
        }
        .encode(&mut unknown)
        .unwrap();
        let unknown_frame = Frame::Ping.encode(&mut unknown[unknown_header..]).unwrap();
        client
            .send_to(&unknown[..unknown_header + unknown_frame], bind)
            .await
            .unwrap();
        let mut surviving = UdpClient::connect(
            "127.0.0.1:0".parse().unwrap(),
            bind,
            ConnectionId::new(0x82).unwrap(),
        )
        .await
        .unwrap();
        let (_, metrics, _) = surviving
            .request_stream(
                quic_lite::FIRST_CLIENT_BIDI_STREAM_ID,
                &[SERVICE_METRICS],
                true,
            )
            .await
            .unwrap();
        assert!(
            core::str::from_utf8(&metrics)
                .unwrap()
                .contains("metrics_version=1")
        );
        server_task.abort();
    }

    #[tokio::test]
    async fn udp_configurable_idle_timeout_evicts_route_and_pending_alias() {
        let root = tempdir().unwrap();
        let probe = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let bind = probe.local_addr().unwrap();
        drop(probe);
        let server_task = tokio::spawn(run(UdpConfig {
            bind,
            artifact_root: root.path().to_path_buf(),
            idle_timeout: Duration::from_millis(2),
            // Keep the listener continuously busy below so expiry must not
            // depend on this timeout firing.
            receive_timeout: Duration::from_millis(20),
            ..UdpConfig::default()
        }));
        tokio::time::sleep(Duration::from_millis(10)).await;
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let cid = ConnectionId::new(0x98).unwrap();
        let mut open = [0u8; MTU];
        let used = encode_bootstrap_open(cid, 0, &mut open).unwrap();
        client.send_to(&open[..used], bind).await.unwrap();
        let mut response = [0u8; MTU];
        let (first_len, _) = timeout(Duration::from_millis(100), client.recv_from(&mut response))
            .await
            .unwrap()
            .unwrap();
        let (_, first_server) = decode_bootstrap_ack(&response[..first_len], cid).unwrap();
        let mut noise = [0u8; 64];
        let noise_header = ShortHeader {
            flags: FLAG_FIXED,
            dcid: ConnectionId::new(0xabcd).unwrap(),
            packet_number: 0,
            packet_number_len: 1,
        }
        .encode(&mut noise)
        .unwrap();
        let noise_len = noise_header + Frame::Ping.encode(&mut noise[noise_header..]).unwrap();
        // Before the fix the listener only swept idle routes following an
        // empty recv timeout. These valid but unknown packets prevent that
        // timeout while the old route ages past its configured limit.
        for _ in 0..8 {
            client.send_to(&noise[..noise_len], bind).await.unwrap();
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        client.send_to(&open[..used], bind).await.unwrap();
        let (second_len, _) = timeout(Duration::from_millis(100), client.recv_from(&mut response))
            .await
            .unwrap()
            .unwrap();
        let (_, second_server) = decode_bootstrap_ack(&response[..second_len], cid).unwrap();
        assert_ne!(first_server, second_server);
        server_task.abort();
    }

    #[tokio::test]
    async fn udp_peer_close_removes_route_without_waiting_for_idle_timeout() {
        let root = tempdir().unwrap();
        let probe = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let bind = probe.local_addr().unwrap();
        drop(probe);
        let server_task = tokio::spawn(run(UdpConfig {
            bind,
            artifact_root: root.path().to_path_buf(),
            idle_timeout: Duration::from_secs(30),
            receive_timeout: Duration::from_millis(1),
            ..UdpConfig::default()
        }));
        tokio::time::sleep(Duration::from_millis(10)).await;
        let mut client = UdpClient::connect(
            "127.0.0.1:0".parse().unwrap(),
            bind,
            ConnectionId::new(0xa8).unwrap(),
        )
        .await
        .unwrap();
        let server_cid = client.endpoint.peer_connection_id().unwrap();
        client.endpoint.close(0x77);
        let mut close = [0u8; MTU];
        let close_len = client.endpoint.poll_close(&mut close).unwrap().unwrap();
        client
            .socket
            .send_to(&close[..close_len], bind)
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;

        let mut ping = [0u8; MTU];
        let header_len = ShortHeader {
            flags: FLAG_FIXED,
            dcid: server_cid,
            packet_number: 1,
            packet_number_len: 4,
        }
        .encode(&mut ping)
        .unwrap();
        let ping_len = Frame::Ping.encode(&mut ping[header_len..]).unwrap();
        client
            .socket
            .send_to(&ping[..header_len + ping_len], bind)
            .await
            .unwrap();
        let mut response = [0u8; MTU];
        // Close/path-control is ACKed promptly, but the route still stays
        // closed: the following Ping must not revive an application session.
        let (response_len, _) = timeout(
            Duration::from_millis(50),
            client.socket.recv_from(&mut response),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(matches!(
            ShortHeader::decode(&response[..response_len]),
            Ok((_, _))
        ));
        server_task.abort();
    }

    #[tokio::test]
    async fn udp_invalid_dc0_bootstrap_is_dropped_without_killing_listener() {
        let root = tempdir().unwrap();
        let probe = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let bind = probe.local_addr().unwrap();
        drop(probe);
        let server_task = tokio::spawn(run(UdpConfig {
            bind,
            artifact_root: root.path().to_path_buf(),
            ..UdpConfig::default()
        }));
        tokio::time::sleep(Duration::from_millis(10)).await;
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut invalid = [0u8; 64];
        let header = ShortHeader {
            flags: FLAG_FIXED,
            dcid: ConnectionId::new(0).unwrap(),
            packet_number: 4,
            packet_number_len: 4,
        }
        .encode(&mut invalid)
        .unwrap();
        let frame = Frame::Ping.encode(&mut invalid[header..]).unwrap();
        client
            .send_to(&invalid[..header + frame], bind)
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(10)).await;
        let cid = ConnectionId::new(0x99).unwrap();
        let mut open = [0u8; MTU];
        let used = encode_bootstrap_open(cid, 0, &mut open).unwrap();
        client.send_to(&open[..used], bind).await.unwrap();
        let mut response = [0u8; MTU];
        let (len, _) = timeout(Duration::from_millis(100), client.recv_from(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            decode_bootstrap_ack(&response[..len], cid).unwrap().0.dcid,
            cid
        );
        server_task.abort();
    }

    #[tokio::test]
    async fn udp_bootstrapped_object_request_uses_persistent_transfer_state() {
        let root = tempdir().unwrap();
        let artifact = root.path().join("esp32c6/main-app.bin");
        std::fs::create_dir_all(artifact.parent().unwrap()).unwrap();
        std::fs::write(
            &artifact,
            (0..4096)
                .map(|value| (value % 251) as u8)
                .collect::<Vec<_>>(),
        )
        .unwrap();
        let probe = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let bind = probe.local_addr().unwrap();
        drop(probe);
        let server_task = tokio::spawn(run(UdpConfig {
            bind,
            artifact_root: root.path().to_path_buf(),
            ..UdpConfig::default()
        }));
        tokio::time::sleep(Duration::from_millis(10)).await;
        let mut client = UdpClient::connect(
            "127.0.0.1:0".parse().unwrap(),
            bind,
            ConnectionId::new(0x91).unwrap(),
        )
        .await
        .unwrap();
        let mut request = [0u8; 128];
        let get_len = encode_get(&mut request[1..], None, 13, 6).unwrap();
        request[0] = SERVICE_OBJECT;
        let (stream_id, first, fin) = client
            .request_stream(
                quic_lite::FIRST_CLIENT_BIDI_STREAM_ID,
                &request[..get_len + 1],
                true,
            )
            .await
            .unwrap();
        assert!(!fin);
        assert_eq!(stream_id, OBJECT_STREAM);
        assert_eq!(first[0], RECORD_MANIFEST);
        let mut records = RecordBuffer::new();
        records.push(&first);
        let mut saw_done = false;
        for _ in 0..16 {
            let (id, data, finished) = client.recv_stream().await.unwrap();
            assert_eq!(id, OBJECT_STREAM);
            records.push(&data);
            while let Some((kind, _)) = records.next() {
                if kind == RECORD_DONE {
                    saw_done = true;
                }
            }
            if saw_done || finished {
                break;
            }
        }
        assert!(saw_done);
        server_task.abort();
    }

    /// Repeatable host-to-host UDP IPERF measurement. It deliberately drives
    /// the production `run` listener and `UdpClient` through localhost, so it
    /// catches scheduler, ACK, flow-credit, and socket regressions without a
    /// shell-launched service or a Wi-Fi device. Keep it ignored: throughput
    /// is host-load dependent, while the printed conditions are the fast
    /// iteration signal. It never starts or restarts lmesh/lmesh-wifi.
    #[tokio::test]
    #[ignore = "explicit UDP IPERF throughput measurement"]
    async fn udp_iperf_loopback_measurement() {
        let bytes = std::env::var("DMESH_IPERF_BYTES")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(64 * 1024);
        let packet_size = std::env::var("DMESH_IPERF_PACKET_SIZE")
            .ok()
            .and_then(|value| value.parse::<u16>().ok())
            .unwrap_or(MAX_OBJECT_CHUNK as u16);
        let root = tempdir().unwrap();
        let control = Arc::new(TransportControl::default());
        let probe = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let bind = probe.local_addr().unwrap();
        drop(probe);
        let server_task = tokio::spawn(run(UdpConfig {
            bind,
            artifact_root: root.path().to_path_buf(),
            history_capacity: 512,
            control: Some(control.clone()),
            ..UdpConfig::default()
        }));
        tokio::time::sleep(Duration::from_millis(10)).await;
        let mut client = UdpClient::connect(
            "127.0.0.1:0".parse().unwrap(),
            bind,
            ConnectionId::new(0x1f3).unwrap(),
        )
        .await
        .unwrap();
        client.set_deferred_receive_credit(true);
        let mut request = [0u8; 11];
        request[0] = SERVICE_IPERF;
        request[1..9].copy_from_slice(&bytes.to_be_bytes());
        request[9..11].copy_from_slice(&packet_size.to_be_bytes());
        let started = Instant::now();
        let (_, first, mut fin) = client
            .request_stream(FIRST_CLIENT_BIDI_STREAM_ID, &request, true)
            .await
            .unwrap();
        let first_response_us = started.elapsed().as_micros();
        let mut received = first.len() as u64;
        while !fin {
            let received_frame = timeout(Duration::from_secs(5), client.recv_stream()).await;
            let Ok(Ok((_, frame, frame_fin))) = received_frame else {
                let stats = control.server_stats();
                let errors = control.take_errors();
                server_task.abort();
                panic!(
                    "UDP IPERF receive timeout bytes={received} server_stats={stats:?} errors={errors:?}"
                );
            };
            received = received.saturating_add(frame.len() as u64);
            fin = frame_fin;
        }
        let elapsed = started.elapsed();
        let bps = received.saturating_mul(8).saturating_mul(1_000_000)
            / elapsed.as_micros().max(1) as u64;
        let server_stats = control.server_stats();
        eprintln!(
            "host-host udp-iperf bytes={received} elapsed_us={} first_response_us={first_response_us} bps={bps} history=512 packet={packet_size} deferred_receive_credit=true server_stats={server_stats:?}",
            elapsed.as_micros(),
        );
        assert_eq!(received, bytes);
        server_task.abort();
    }

    #[test]
    fn object_request_envelope_keeps_get_bytes_and_negotiates_ack_ratio() {
        let legacy = [SERVICE_OBJECT, 0xa2, 0x01, 0x0d, 0x02, 0x06];
        let (legacy_ack, legacy_get) = object_request_envelope(&legacy).unwrap();
        assert_eq!(legacy_ack, RECOVERY_OBJECT_ACK_FREQUENCY);
        assert_eq!(legacy_get, &legacy[1..]);

        let configured = [SERVICE_OBJECT, 4, 0xa2, 0x01, 0x0d, 0x02, 0x06];
        let (ack, get) = object_request_envelope(&configured).unwrap();
        assert_eq!(ack, 4);
        assert_eq!(get, &configured[2..]);
        assert!(crate::protocol::decode_get(get).is_some());
    }
}
