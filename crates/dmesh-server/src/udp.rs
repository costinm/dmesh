//! Feature-gated host UDP QUIC server and connection/mux harness.
//!
//! UDP is the datagram bearer. The first packet creates a connection keyed by
//! its opaque DCID; subsequent packets are routed to that connection. Stream
//! services run above the endpoint. The object store is the production service
//! currently installed here, while the same connection table is intended for
//! additional host-test services on other stream IDs.

pub use crate::services::EventRing;
use crate::services::{dispatch_diagnostic_tagged_stream, dispatch_tagged_stream};
use crate::{ObjectServer, ServerConfig};
use crate::{
    probe::{ProbeServicePlan, ProbeServiceRequest},
    verified_object::{GetRequest, ObjectBodyStream, decode_get_request},
};
use anyhow::{Context, Result, bail};
#[cfg(test)]
use quic_lite::Role;
use quic_lite::ledger::{
    LedgerMemoryPolicy, LedgerMemorySnapshot, select_capacity, system_memory_snapshot,
};
use quic_lite::mux::StreamMux;
use quic_lite::{
    ConnectionLimits, ConnectionTable, EndpointState, INITIAL_MAX_STREAM_DATA, PathState,
    ServerStreamConfig, ServerStreamConnection,
};
use std::boxed::Box;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::eprintln;
use std::format;
use std::future::Future;
use std::hash::{Hash, Hasher};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::pin::Pin;
use std::string::String;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::vec::Vec;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};
use tokio::time::{Duration, Instant, timeout};

const MTU: usize = quic_lite::DEFAULT_MAX_DATAGRAM_SIZE;

/// Linux may omit the outgoing interface scope on an inbound IPv6 link-local
/// source.  Scope selects the local egress interface, not the remote UDP
/// peer, so association identity is address plus port.
fn same_udp_peer(received: SocketAddr, expected: SocketAddr) -> bool {
    match (received, expected) {
        (SocketAddr::V4(received), SocketAddr::V4(expected)) => {
            received.ip() == expected.ip() && received.port() == expected.port()
        }
        (SocketAddr::V6(received), SocketAddr::V6(expected)) => {
            received.ip() == expected.ip() && received.port() == expected.port()
        }
        _ => false,
    }
}

/// Adapter-local opaque handle for a UDP peer endpoint. The hash is never put
/// on the wire or used as a device identity; the connection's DCID remains
/// the peer-specific transport identity. IPv6 scope is deliberately excluded:
/// it selects our local egress interface, whereas the UDP bearer identifies
/// its peer by address and service port.
fn udp_path_id(peer: SocketAddr) -> quic_lite::PathId {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    match peer {
        SocketAddr::V4(peer) => {
            peer.ip().hash(&mut hasher);
            peer.port().hash(&mut hasher);
        }
        SocketAddr::V6(peer) => {
            peer.ip().hash(&mut hasher);
            peer.port().hash(&mut hasher);
        }
    }
    let value = hasher.finish() | (1_u64 << 63);
    quic_lite::PathId::new(value).expect("tagged UDP path ID is nonzero")
}
/// Stable `lmesh-wifi`/wlan0 object and PROBE listener.
pub const STABLE_WIFI_UDP_PORT: u16 = 3336;
/// Development `lmesh`/wlan1 listener.  It must not collide with wlan0.
pub const DEVELOPMENT_WIFI_UDP_PORT: u16 = 3337;

/// Application-owned tagged-CBOR dispatch for a normal QUIC stream.
///
/// This is intentionally distinct from the private direct-message hook:
/// callers receive a complete stream request only after the QUIC association
/// has been established. It lets host applications expose the same async
/// catalog handler over HTTP and every QUIC bearer without turning a bearer
/// address into a control API.
pub trait TaggedStreamHandler: Send + Sync {
    fn handle<'a>(
        &'a self,
        context: TaggedStreamContext,
        request: Vec<u8>,
    ) -> Pin<Box<dyn Future<Output = Option<Vec<u8>>> + Send + 'a>>;
}

/// Invoke the first registered handler that returns a correlated tagged
/// response.  The same composite is installed for normal streams and the
/// connectionless direct exception, so a direct operation cannot acquire a
/// second application implementation.
pub struct FallbackTaggedStreamHandler {
    primary: Arc<dyn TaggedStreamHandler>,
    fallback: Arc<dyn TaggedStreamHandler>,
}

impl FallbackTaggedStreamHandler {
    pub fn new(
        primary: Arc<dyn TaggedStreamHandler>,
        fallback: Arc<dyn TaggedStreamHandler>,
    ) -> Self {
        Self { primary, fallback }
    }
}

impl TaggedStreamHandler for FallbackTaggedStreamHandler {
    fn handle<'a>(
        &'a self,
        context: TaggedStreamContext,
        request: Vec<u8>,
    ) -> Pin<Box<dyn Future<Output = Option<Vec<u8>>> + Send + 'a>> {
        Box::pin(async move {
            if let Some(response) = self.primary.handle(context, request.clone()).await {
                return Some(response);
            }
            self.fallback.handle(context, request).await
        })
    }
}

/// Application callback behind the shared canonical tagged-stream boundary.
/// Implementations decode only their application schema; QUIC correlation
/// and envelope admission are handled by [`CanonicalTaggedStreamHandler`].
pub trait TaggedApplicationHandler: Send + Sync {
    fn handle_tagged<'a>(
        &'a self,
        context: TaggedStreamContext,
        request: Vec<u8>,
    ) -> Pin<Box<dyn Future<Output = Option<Vec<u8>>> + Send + 'a>>;
}

/// Shared QUIC tagged-CBOR adapter used by Linux and Android.
///
/// It rejects malformed or uncorrelated requests before application dispatch
/// and accepts only a terminal response carrying the same request ID. This
/// prevents each platform wrapper from growing subtly different QUIC-facing
/// decode, correlation, and response policy.
pub struct CanonicalTaggedStreamHandler {
    application: Arc<dyn TaggedApplicationHandler>,
}

impl CanonicalTaggedStreamHandler {
    pub fn new(application: Arc<dyn TaggedApplicationHandler>) -> Self {
        Self { application }
    }
}

impl TaggedStreamHandler for CanonicalTaggedStreamHandler {
    fn handle<'a>(
        &'a self,
        context: TaggedStreamContext,
        request: Vec<u8>,
    ) -> Pin<Box<dyn Future<Output = Option<Vec<u8>>> + Send + 'a>> {
        Box::pin(async move {
            let request_id = crate::tagged::decode(&request)?.id?;
            let response = self.application.handle_tagged(context, request).await?;
            let record = crate::tagged::decode(&response)?;
            if record.id != Some(request_id)
                || record.to.is_some()
                || (record.result.is_some() == record.error.is_some())
            {
                return None;
            }
            Some(response)
        })
    }
}

/// Transport facts for a normal tagged QUIC stream request.  The request
/// payload deliberately remains bearer-neutral, but a relay control handler
/// needs the authenticated adjacent peer when it binds a reverse route.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TaggedStreamContext {
    pub peer: SocketAddr,
}

/// Outcome of a relay-forwarding lookup on a UDP listener.  This shares one
/// socket with ordinary QUIC endpoints: a matching DCID is rewritten and sent
/// to the configured adjacent peer before endpoint-connection lookup.
pub enum RelayDatagramOutcome {
    NotHandled,
    Forward { peer: SocketAddr, used: usize },
    Drop,
}

/// Optional owner of relay forwarding state for a UDP listener.
///
/// The handler sees only bounded packets and an adjacent ingress tuple.  It
/// must not parse stream payloads; tagged relay administration is performed by
/// [`TaggedStreamHandler`] after QUIC termination.
pub trait RelayDatagramHandler: Send + Sync {
    fn handle(&self, ingress: SocketAddr, packet: &[u8], out: &mut [u8]) -> RelayDatagramOutcome;
}

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
// An object transfer must keep its connection scheduler responsive to a
// delayed ACK/window update. This is a wakeup bound, not sender pacing.
const ACTIVE_OBJECT_SCHEDULER_TICK: Duration = Duration::from_millis(1);
/// One ordered object-response stream: manifest, blobs, then done.
const OBJECT_STREAM: u64 = 3;
const ACK_TIMEOUT: Duration = Duration::from_millis(500);
const BOOTSTRAP_ATTEMPTS: u32 = 4;
const STREAM_ATTEMPTS: u32 = 4;
const MAX_ACTIVE_CONNECTIONS: usize = 64;
// A host PROBE receiver can acknowledge a full congestion window faster than
// the per-connection task observes it.  This remains bounded and is host-only
// routing state; tearing down the route on a transient full queue loses the
// ACK frontier and prevents PTO recovery entirely.
const CONNECTION_DATAGRAM_QUEUE_CAPACITY: usize = 1024;
/// Fixed bound shared with the no_std Recovery PROBE receiver.
const MAX_PROBE_STREAMS: usize = 4;
// Host UDP PROBE can refill a full host ledger in one scheduler pass. Device
// receivers still bound the effective burst through their advertised packet
// flight limit, so this does not enlarge Recovery/ESP receive memory.
const HOST_PROBE_NORMAL_REFILL_PACKETS: usize = 64;
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);
static NEXT_SERVER_CID: AtomicU64 = AtomicU64::new(0x100);

/// First byte on an application stream selects the connection service.
/// Remaining bytes belong to that service's schema.
/// Object streaming is the normal Recovery workload. ACK=8 keeps reverse
/// traffic sparse enough to preserve a useful forward burst, while the 5 ms
/// cap repairs a short/cwnd-limited burst promptly.
const RECOVERY_OBJECT_ACK_FREQUENCY: u8 = 8;
const RECOVERY_MAX_ACK_DELAY_US: u64 = 5_000;
const CONTROL_QUEUE_CAPACITY: usize = 64;

fn object_request(request: &[u8]) -> Result<GetRequest<'_>> {
    decode_get_request(request)
        .map(|(_, request)| request)
        .ok_or_else(|| anyhow::anyhow!("invalid tagged object GET"))
}

/// Local observability and path policy for a running UDP listener.
///
/// This object is not a wire command channel. Remote operations use tagged
/// QUIC handlers; callers such as lmesh read these bounded snapshots locally.
#[derive(Debug)]
pub struct TransportControl {
    stats: Mutex<Option<ServerTransportStats>>,
    errors: Mutex<VecDeque<String>>,
    events: Mutex<VecDeque<String>>,
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
    pub fn server_stats(&self) -> Option<ServerTransportStats> {
        *self.stats.lock().ok()?
    }
    fn record_server_stats<const N: usize, const H: usize>(&self, endpoint: &EndpointState<N, H>) {
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
}

impl Default for TransportControl {
    fn default() -> Self {
        Self {
            stats: Mutex::new(None),
            errors: Mutex::new(VecDeque::new()),
            events: Mutex::new(VecDeque::new()),
        }
    }
}

struct ConnectionDatagram {
    peer: SocketAddr,
    bytes: Vec<u8>,
}

struct UdpConnectionRoute {
    cid: quic_lite::ConnectionId,
    peer: SocketAddr,
    sender: mpsc::Sender<ConnectionDatagram>,
    last_activity: Instant,
}

/// Listener-local route for an outbound association.  The tuple is not a
/// QUIC identity; it is retained only so an opaque stateless reset can be
/// offered to the bounded set of associations that received it from that
/// adjacent peer.  Quic-lite performs the private reset-token comparison.
struct UdpClientIngressRoute {
    peer: SocketAddr,
    sender: mpsc::Sender<ConnectionDatagram>,
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
    stream: ObjectBodyStream,
    chunk_size: usize,
    first_send: Option<Instant>,
    sent_datagrams: u64,
}

/// Transport-only response source for PROBE. It deliberately has no object
/// record header, manifest, store lookup, or flash semantics.
struct PendingByteTransfer {
    stream_id: u64,
    offset: u64,
    remaining: usize,
    chunk_size: usize,
    packet_id: u32,
    /// Host-side scheduler evidence for one transport PROBE response.  This
    /// is deliberately aggregate-only: logging a datagram would itself
    /// perturb the Wi-Fi benchmark.
    first_send: Option<Instant>,
    last_send: Option<Instant>,
    sent_datagrams: u64,
    window_fills: u64,
    max_window_fill: u64,
    interpacket_gaps: [u64; 6],
}

/// One terminal tagged-CBOR response awaiting available QUIC packet-ledger
/// capacity.  This is connection state, not a bearer queue: UART/NOW/NAN and
/// UDP all resume the same response stream after an ACK or PTO edge.
struct PendingTaggedResponse {
    stream_id: u64,
    bytes: Vec<u8>,
    offset: usize,
}

fn interpacket_gap_bucket(gap: Duration) -> usize {
    quic_lite::interpacket_gap_bucket(gap.as_micros().try_into().unwrap_or(u64::MAX))
}

/// Read request-scoped ACK policy from the canonical tagged request.
fn probe_ack_policy(request: ProbeServiceRequest) -> (u8, u64) {
    // ACK_FREQUENCY's wire threshold is one below the human-facing packet
    // ratio. Keep it request-scoped so a benchmark does not depend on a
    // local-only Recovery setting that the peer can silently overwrite.
    // ACK_FREQUENCY encodes the threshold as `frequency - 1`; the endpoint
    // can retain at most ACK_RANGE_CAPACITY ranges. Clamp at the same bound
    // as Recovery's command parser so a malformed request cannot start an
    // PROBE transfer while silently failing to install its advertised policy.
    let ack_frequency = request
        .ack_frequency
        .unwrap_or(2)
        .clamp(1, quic_lite::ACK_RANGE_CAPACITY as u8);
    let ack_delay_us = request
        .ack_delay_ms
        .map(|milliseconds| u64::from(milliseconds.clamp(1, 25)) * 1_000)
        .unwrap_or(RECOVERY_MAX_ACK_DELAY_US);
    (ack_frequency, ack_delay_us)
}

impl PendingByteTransfer {
    fn new(stream_id: u64, bytes: usize, chunk_size: usize) -> Self {
        Self {
            stream_id,
            offset: 0,
            remaining: bytes,
            chunk_size,
            packet_id: 0,
            first_send: None,
            last_send: None,
            sent_datagrams: 0,
            window_fills: 0,
            max_window_fill: 0,
            interpacket_gaps: [0; 6],
        }
    }
}

fn report_byte_transfer<const N: usize, const H: usize>(
    transfer: &PendingByteTransfer,
    endpoint: &EndpointState<N, H>,
) {
    let stats = endpoint.stats();
    let elapsed_us = transfer
        .first_send
        .map(|first| first.elapsed().as_micros())
        .unwrap_or(0);
    eprintln!(
        "probe_udp_send_summary stream={} datagrams={} endpoint_stream={} endpoint_control={} history={}/{} peer_flight={} cwnd={} inflight={} rtt_ms={:?} pto_ms={} fills={} max_fill={} elapsed_us={} \
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
        endpoint.smoothed_rtt(),
        endpoint.pto_timeout(),
        transfer.window_fills,
        transfer.max_window_fill,
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
        "object_udp_send_summary bytes={} datagrams={} endpoint_stream={} endpoint_control={} elapsed_us={} loss=gap:{} time:{} events:{} loss_retx:{} pto_retx:{}",
        transfer.stream.sent_bytes(),
        transfer.sent_datagrams,
        stats.sent_stream_datagrams,
        stats.sent_control_datagrams,
        elapsed_us,
        stats.loss_packet_threshold_datagrams,
        stats.loss_time_threshold_datagrams,
        stats.loss_events,
        stats.loss_retransmitted_datagrams,
        stats.pto_retransmitted_datagrams,
    );
}

impl PendingObjectTransfer {
    fn from_object_with_chunk(manifest: Vec<u8>, body: Vec<u8>, chunk_size: usize) -> Self {
        assert!((1..=MAX_OBJECT_CHUNK).contains(&chunk_size));
        Self {
            stream: ObjectBodyStream::from_object(manifest, body),
            chunk_size,
            first_send: None,
            sent_datagrams: 0,
        }
    }

    #[cfg(test)]
    fn new(records: Vec<(u8, Vec<u8>)>) -> Self {
        Self::with_chunk(records, OBJECT_CHUNK)
    }

    #[cfg(test)]
    fn with_chunk(records: Vec<(u8, Vec<u8>)>, chunk_size: usize) -> Self {
        assert!((1..=MAX_OBJECT_CHUNK).contains(&chunk_size));
        Self {
            stream: ObjectBodyStream::new(records),
            chunk_size,
            first_send: None,
            sent_datagrams: 0,
        }
    }
}

#[derive(Clone)]
pub struct UdpConfig {
    pub bind: SocketAddr,
    /// A pre-bound process listener. When supplied, `run` adopts this socket
    /// instead of creating a second bind; discovery, client associations, and
    /// normal streams consequently share one local UDP port.
    pub socket: Option<Arc<UdpSocket>>,
    /// Process-owned ingress router for outbound associations using `socket`.
    /// The listener remains the only socket reader and dispatches packets by
    /// the association's local CID.  Transport adapters never compete with
    /// the listener through a second `recv_from` loop.
    pub client_ingress: Option<Arc<UdpClientIngress>>,
    /// Stable secret used by quic-lite to issue and later recognize
    /// stateless-reset tokens.  It must be device/service-local persistent
    /// material, not a boot-random value; leaving it unset retains PTO/idle
    /// recovery but cannot notify peers of a restart immediately.
    pub stateless_reset_key: Option<quic_lite::StatelessResetKey>,
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
    /// Application payload size for object datagrams. This is independent of
    /// the transport window: even small diagnostic records must still be sent
    /// in flight as a window, not as stop-and-wait packets.
    pub object_chunk: usize,
    /// Optional IPv4 DSCP/TOS applied to this listener's outbound datagrams.
    /// It is a host-bearer diagnostic only; `None` preserves best-effort.
    pub ip_tos: Option<u8>,
    /// Optional opaque Recovery command/log mailbox. Normal object serving
    /// leaves it unset; host hardware tests can install it on a third port.
    pub control: Option<Arc<TransportControl>>,
    /// Normal tagged handler also exposed through the custom-version direct
    /// long-header exception. QUIC-lite owns direct framing and only calls
    /// this established stream-handler boundary with the tagged payload.
    pub direct_handler: Option<Arc<dyn TaggedStreamHandler>>,
    /// Optional async tagged-CBOR handler for normal QUIC streams. When it
    /// declines a record, the bounded static component registry remains the
    /// fallback for firmware and compatibility services.
    pub tagged_handler: Option<Arc<dyn TaggedStreamHandler>>,
    /// Optional bounded DCID forwarding lookup sharing this listener with
    /// ordinary QUIC endpoints and normal tagged stream control.
    pub relay_handler: Option<Arc<dyn RelayDatagramHandler>>,
}

impl Default for UdpConfig {
    fn default() -> Self {
        Self {
            bind: SocketAddr::from(([0, 0, 0, 0], STABLE_WIFI_UDP_PORT)),
            socket: None,
            client_ingress: None,
            stateless_reset_key: None,
            artifact_root: PathBuf::from("."),
            history_capacity: 0,
            ledger_memory_policy: LedgerMemoryPolicy::default(),
            ledger_memory: None,
            max_active_connections: MAX_ACTIVE_CONNECTIONS,
            idle_timeout: IDLE_TIMEOUT,
            receive_timeout: Duration::from_secs(1),
            object_chunk: OBJECT_CHUNK,
            ip_tos: None,
            control: None,
            direct_handler: None,
            tagged_handler: None,
            relay_handler: None,
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

struct UdpClientIngressRegistration {
    cid: quic_lite::ConnectionId,
    peer: SocketAddr,
    sender: mpsc::Sender<ConnectionDatagram>,
    ready: oneshot::Sender<Result<()>>,
}

/// Listener-owned registration point for outgoing QUIC associations.
///
/// The UDP listener owns the port and is the only consumer of inbound frames.
/// A client association registers its non-zero local CID before transmitting
/// an Initial; the listener then forwards matching OPEN_ACK and normal QUIC
/// packets to that association.  This keeps one process port across incoming
/// services and outgoing streams while preserving the core association's CID
/// and path state.
pub struct UdpClientIngress {
    sender: mpsc::Sender<UdpClientIngressRegistration>,
    receiver: Mutex<Option<mpsc::Receiver<UdpClientIngressRegistration>>>,
}

impl UdpClientIngress {
    pub fn new() -> Arc<Self> {
        let (sender, receiver) = mpsc::channel(CONNECTION_DATAGRAM_QUEUE_CAPACITY);
        Arc::new(Self {
            sender,
            receiver: Mutex::new(Some(receiver)),
        })
    }

    fn take_receiver(&self) -> Option<mpsc::Receiver<UdpClientIngressRegistration>> {
        self.receiver.lock().ok()?.take()
    }

    async fn register(
        &self,
        cid: quic_lite::ConnectionId,
        peer: SocketAddr,
    ) -> Result<mpsc::Receiver<ConnectionDatagram>> {
        let (sender, receiver) = mpsc::channel(CONNECTION_DATAGRAM_QUEUE_CAPACITY);
        let (ready, accepted) = oneshot::channel();
        self.sender
            .send(UdpClientIngressRegistration {
                cid,
                peer,
                sender,
                ready,
            })
            .await
            .map_err(|_| anyhow::anyhow!("UDP listener ingress router stopped"))?;
        accepted
            .await
            .map_err(|_| anyhow::anyhow!("UDP listener ingress registration dropped"))??;
        Ok(receiver)
    }
}

/// Minimal host UDP frame adapter for one already-created QUIC association.
///
/// CID, endpoint, packet-number, and path state are all
/// [`quic_lite::ClientAssociation`] state. This adapter uses either a private
/// diagnostic socket or a listener-owned socket with CID ingress routing; it
/// never creates a second reader for a shared socket. The device-keyed
/// manager above it shares an association across concurrent streams and
/// UART/NOW/UDP paths. Service schemas remain above both layers.
pub struct UdpClient {
    socket: Arc<UdpSocket>,
    /// Present only when this association uses the process listener's shared
    /// socket. The listener has already selected packets by local CID.
    ingress: Option<mpsc::Receiver<ConnectionDatagram>>,
    peer: SocketAddr,
    /// The QUIC association is core state; this adapter holds only a socket
    /// reference, peer tuple, and opaque UDP path handle. A higher-level
    /// device manager may retain the same association while selecting another
    /// UART/NOW/UDP path for a later request.
    connection: quic_lite::ClientAssociation<512, MTU>,
    path: quic_lite::PathId,
    /// Optional adjacent-link wire label. QUIC-lite still creates packets for
    /// the authenticated end-to-end peer CID; the UDP path adapter replaces
    /// only the visible outer DCID before sending to `peer`.
    quic_lite_wire_dcid: Option<quic_lite::ConnectionId>,
    deferred_receive_credit: bool,
}

/// One committed server-initiated stream frame. This keeps offset and FIN
/// visible to diagnostic clients such as PROBE without exposing any socket or
/// bearer-specific framing above `UdpClient`.
#[derive(Debug)]
pub struct ReceivedStream {
    pub id: u64,
    pub offset: u64,
    pub fin: bool,
    pub data: Vec<u8>,
}

impl UdpClient {
    async fn recv_association_packet(&mut self, buffer: &mut [u8]) -> Result<(usize, SocketAddr)> {
        if let Some(ingress) = self.ingress.as_mut() {
            let datagram = ingress
                .recv()
                .await
                .ok_or_else(|| anyhow::anyhow!("UDP listener ingress router stopped"))?;
            if datagram.bytes.len() > buffer.len() {
                bail!("UDP listener ingress packet exceeds client buffer");
            }
            buffer[..datagram.bytes.len()].copy_from_slice(&datagram.bytes);
            return Ok((datagram.bytes.len(), datagram.peer));
        }
        Ok(self.socket.recv_from(buffer).await?)
    }

    fn endpoint(&self) -> &EndpointState<{ quic_lite::DEFAULT_STREAM_STATE_SLOTS }, 512> {
        self.connection
            .connection()
            .endpoint()
            .expect("UDP client methods require an established connection")
    }

    fn endpoint_mut(
        &mut self,
    ) -> &mut EndpointState<{ quic_lite::DEFAULT_STREAM_STATE_SLOTS }, 512> {
        self.connection
            .connection_mut()
            .endpoint_mut()
            .expect("UDP client methods require an established connection")
    }

    /// Publish the ACK for a terminal application response before a
    /// short-lived caller can send CLOSE or drop its socket.  Delayed ACK is
    /// still QUIC-lite policy; this adapter merely waits for the endpoint's
    /// advertised deadline and transmits the resulting complete datagram.
    ///
    /// This is shared by ordinary commands and object upload.  In particular,
    /// a `boot.recovery` response must not be followed immediately by CLOSE
    /// with no separately observable delivery edge on the device.
    async fn acknowledge_terminal_response(
        &mut self,
        started: Instant,
        packet: &mut [u8; MTU],
        context: &str,
    ) -> Result<()> {
        let now_ms = started.elapsed().as_millis() as u64;
        self.endpoint_mut().set_time(now_ms);
        let pto = self.endpoint().pto_timeout();
        if let Some(wake_at_ms) = self.endpoint().next_bearer_deadline(pto) {
            let current_ms = started.elapsed().as_millis() as u64;
            if wake_at_ms > current_ms {
                tokio::time::sleep(Duration::from_millis(wake_at_ms.saturating_sub(current_ms)))
                    .await;
            }
            self.endpoint_mut()
                .set_time(started.elapsed().as_millis() as u64);
        }
        if let Some((_path, ack_len)) = self
            .connection
            .poll_transmit(packet)
            .map_err(|error| anyhow::anyhow!("{context} terminal ACK: {error:?}"))?
        {
            self.send_endpoint_packet(&packet[..ack_len]).await?;
        }
        Ok(())
    }

    pub fn peer_connection_id(&self) -> Option<quic_lite::ConnectionId> {
        self.connection.connection().peer_cid()
    }

    /// Allocate the next stream from the shared QUIC association.  A UDP
    /// device manager must not retain a second stream-ID counter: when this
    /// association later gains a NOW or UART path, all paths share this one
    /// sequence.
    pub fn allocate_client_bidi_stream(&mut self) -> Result<u64> {
        self.connection
            .allocate_client_bidi_stream()
            .map_err(|error| anyhow::anyhow!("client stream ID: {error:?}"))
    }

    /// Select the UDP tuple used for the next datagram without replacing the
    /// QUIC association.  A caller must have already established that the
    /// tuple belongs to the same device identity: addresses are paths, not
    /// connection keys.  A valid response on the selected path is recorded
    /// by `ClientAssociation` alongside the previous paths.
    ///
    /// This deliberately does not open a socket or issue a new Initial.  The
    /// association keeps its CIDs, stream state, and (eventually) handshake
    /// material while a controller moves it between UDP paths.
    pub fn select_udp_path(&mut self, peer: SocketAddr) -> Result<()> {
        let local = self.socket.local_addr()?;
        if local.is_ipv4() != peer.is_ipv4() {
            bail!(
                "cannot move one UDP socket between IPv4 and IPv6 paths; retain the association through a dual-family path adapter"
            );
        }
        self.peer = peer;
        self.path = udp_path_id(peer);
        self.connection.select_path(self.path);
        Ok(())
    }

    /// Association-level stream counters, independent of the selected UDP
    /// path.  This is the same core diagnostic used by a future UART/NOW
    /// adapter, not a socket-local estimate.
    pub fn stream_stats(&self) -> quic_lite::ConnectionStreamStats {
        self.endpoint().stream_stats()
    }
    /// Snapshot endpoint-owned loss, retransmission, ACK, and ordering
    /// counters for a completed diagnostic transfer. The socket adapter does
    /// not infer these from packet timing; QUIC-lite remains the authority.
    pub fn transport_stats(&self) -> quic_lite::TransportStats {
        self.endpoint().stats()
    }

    /// Explicitly retire this diagnostic association on its bearer.  Dropping
    /// a UDP socket does not notify a fixed-size embedded service dispatcher;
    /// callers that run repeated probes must send CLOSE so the peer can admit
    /// the next fresh connection without waiting for an idle timeout.
    pub async fn close(&mut self, code: u64) -> Result<()> {
        self.endpoint_mut().close(code);
        let mut packet = [0u8; MTU];
        if let Some((_path, used)) = self
            .connection
            .poll_close(&mut packet)
            .map_err(|error| anyhow::anyhow!("UDP close: {error:?}"))?
        {
            self.send_endpoint_packet(&packet[..used]).await?;
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
        self.endpoint_mut().set_ack_frequency(frequency);
    }

    /// Lower the active retransmission ledger for this side. The endpoint's
    /// static host profile remains the upper bound.
    pub fn set_history_capacity(&mut self, limit: usize) -> Result<()> {
        self.endpoint_mut()
            .set_history_capacity(limit)
            .map_err(|error| anyhow::anyhow!("UDP history capacity: {error:?}"))
    }

    /// Establish a directional-CID connection using the custom-version QUIC
    /// Initial header and the standard DCID/SCID roles.
    pub async fn connect(
        bind: SocketAddr,
        peer: SocketAddr,
        local_cid: quic_lite::ConnectionId,
    ) -> Result<Self> {
        Self::connect_with_history_capacity(bind, peer, local_cid, 512).await
    }

    /// Establish a normal QUIC-lite connection on a caller-owned socket.
    ///
    /// A circuit session keeps one UDP source tuple stable while it first
    /// controls a relay and later opens adjacent relay legs. The session owner,
    /// rather than this single-connection helper, decides when the socket can
    /// be reused for another connection.
    pub async fn connect_with_socket(
        socket: UdpSocket,
        peer: SocketAddr,
        local_cid: quic_lite::ConnectionId,
    ) -> Result<Self> {
        configure_host_udp_buffers(&socket)?;
        Self::connect_with_socket_via(
            Arc::new(socket),
            peer,
            local_cid,
            512,
            ConnectionLimits::default(),
            None,
            None,
        )
        .await
    }

    /// Return the owned socket when this one-connection helper is no longer
    /// needed. The higher-level circuit session is responsible for preserving
    /// the socket's source tuple and for multiplexing retained connections.
    pub fn into_socket(self) -> Result<UdpSocket> {
        Arc::try_unwrap(self.socket)
            .map_err(|_| anyhow::anyhow!("UDP socket remains shared by a listener or association"))
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
        Self::connect_with_limits_via(bind, peer, local_cid, history_capacity, limits, None).await
    }

    /// Establish over an adjacent UDP link whose on-wire DCID differs from
    /// QUIC's end-to-end destination CID. This is path adaptation, not relay
    /// control: callers obtain `wire_dcid` from the bearer-neutral circuit
    /// builder, and this adapter never parses or installs relay rules.
    pub async fn connect_with_quic_lite_wire_dcid(
        bind: SocketAddr,
        peer: SocketAddr,
        local_cid: quic_lite::ConnectionId,
        wire_dcid: quic_lite::ConnectionId,
    ) -> Result<Self> {
        Self::connect_with_limits_via(
            bind,
            peer,
            local_cid,
            512,
            ConnectionLimits::default(),
            Some(wire_dcid),
        )
        .await
    }

    /// Continue on a caller-owned UDP socket with an adjacent-link wire CID.
    /// Circuit construction may have exchanged setup records on this same
    /// bearer first; UDP only preserves its peer/port and applies the returned
    /// wire label. The same circuit output can drive UART, NOW, FSK, or BLE-CoC
    /// adapters without involving this type.
    pub async fn connect_with_socket_and_quic_lite_wire_dcid(
        socket: UdpSocket,
        peer: SocketAddr,
        local_cid: quic_lite::ConnectionId,
        wire_dcid: quic_lite::ConnectionId,
    ) -> Result<Self> {
        configure_host_udp_buffers(&socket)?;
        Self::connect_with_socket_via(
            Arc::new(socket),
            peer,
            local_cid,
            512,
            ConnectionLimits::default(),
            Some(wire_dcid),
            None,
        )
        .await
    }

    async fn connect_with_limits_via(
        bind: SocketAddr,
        peer: SocketAddr,
        local_cid: quic_lite::ConnectionId,
        history_capacity: usize,
        limits: ConnectionLimits,
        quic_lite_wire_dcid: Option<quic_lite::ConnectionId>,
    ) -> Result<Self> {
        if local_cid.value() == 0 {
            bail!("bootstrap local CID must be non-zero");
        }
        if !(1..=512).contains(&history_capacity) {
            bail!("UDP history capacity must be in 1..=512");
        }
        let socket = Arc::new(UdpSocket::bind(bind).await?);
        configure_host_udp_buffers(&socket)?;
        Self::connect_with_socket_via(
            socket,
            peer,
            local_cid,
            history_capacity,
            limits,
            quic_lite_wire_dcid,
            None,
        )
        .await
    }

    /// Establish on the process listener's existing UDP socket. `ingress`
    /// ensures the listener, rather than this association, remains the sole
    /// reader of that socket and forwards only this CID's packets here.
    pub async fn connect_with_listener(
        socket: Arc<UdpSocket>,
        ingress: Arc<UdpClientIngress>,
        peer: SocketAddr,
        local_cid: quic_lite::ConnectionId,
    ) -> Result<Self> {
        let receiver = ingress.register(local_cid, peer).await?;
        Self::connect_with_socket_via(
            socket,
            peer,
            local_cid,
            512,
            ConnectionLimits::default(),
            None,
            Some(receiver),
        )
        .await
    }

    async fn connect_with_socket_via(
        socket: Arc<UdpSocket>,
        peer: SocketAddr,
        local_cid: quic_lite::ConnectionId,
        history_capacity: usize,
        limits: ConnectionLimits,
        quic_lite_wire_dcid: Option<quic_lite::ConnectionId>,
        ingress: Option<mpsc::Receiver<ConnectionDatagram>>,
    ) -> Result<Self> {
        let mut client = Self {
            socket,
            ingress,
            peer,
            connection: quic_lite::ClientAssociation::with_limits(local_cid, limits),
            path: udp_path_id(peer),
            quic_lite_wire_dcid,
            deferred_receive_credit: false,
        };
        client.connection.select_path(client.path);
        let mut response = [0u8; MTU];
        // A bootstrap timeout used to discard the only evidence of an L2
        // response.  Keep the client bearer-neutral but preserve a compact
        // diagnostic so an AP-relayed UDP test can distinguish no return
        // packet from a malformed or misrouted one.
        let mut last_observation = None;
        for packet_number in 0..BOOTSTRAP_ATTEMPTS {
            let mut open = [0u8; MTU];
            let (_path, used) = client
                .connection
                .encode_open_attempt(packet_number, &mut open)
                .map_err(|error| anyhow::anyhow!("bootstrap OPEN: {error:?}"))?;
            if let Some(wire_dcid) = quic_lite_wire_dcid {
                let mut relayed = [0u8; MTU];
                let relayed_used = quic_lite::rewrite_dcid(&open[..used], wire_dcid, &mut relayed)
                    .map_err(|error| anyhow::anyhow!("relay bootstrap DCID: {error:?}"))?;
                client
                    .socket
                    .send_to(&relayed[..relayed_used], client.peer)
                    .await?;
            } else {
                client.socket.send_to(&open[..used], client.peer).await?;
            }
            // Discovery and direct control use the same UDP listener as a
            // QUIC association. A connectionless record from the selected
            // peer must not consume this OPEN attempt: keep receiving until
            // the attempt deadline and admit only the matching long-header
            // OPEN_ACK. The socket/bearer never decodes its payload.
            let deadline = Instant::now() + ACK_TIMEOUT;
            loop {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    break;
                }
                let received =
                    timeout(remaining, client.recv_association_packet(&mut response)).await;
                let Ok(Ok((len, response_peer))) = received else {
                    break;
                };
                if !same_udp_peer(response_peer, client.peer) {
                    last_observation = Some(format!(
                        "reply_peer={} expected_peer={} bytes={len}",
                        response_peer, client.peer
                    ));
                    continue;
                }
                // The association owns long-header validation, CID matching,
                // reset recognition, and OPEN_ACK installation.  UDP merely
                // injects a complete datagram on its selected opaque path;
                // connectionless discovery and malformed traffic therefore
                // cannot become a second bootstrap parser here.
                let installed =
                    client
                        .connection
                        .receive_open_ack(client.path, &response[..len], 0);
                match installed {
                    Ok(_) => {}
                    Err(error) => {
                        last_observation =
                            Some(format!("rejected_bootstrap bytes={len} error={error:?}"));
                        continue;
                    }
                }
                client
                    .endpoint_mut()
                    .set_history_capacity(history_capacity)
                    .map_err(|error| anyhow::anyhow!("UDP history capacity: {error:?}"))?;
                return Ok(client);
            }
        }
        if let Some(observation) = last_observation {
            bail!("UDP bootstrap timeout after {BOOTSTRAP_ATTEMPTS} attempts ({observation})")
        }
        bail!("UDP bootstrap timeout after {BOOTSTRAP_ATTEMPTS} attempts (no response)")
    }

    async fn send_endpoint_packet(&self, packet: &[u8]) -> Result<()> {
        if let Some(wire_dcid) = self.quic_lite_wire_dcid {
            let mut relayed = [0u8; MTU];
            let used = quic_lite::rewrite_dcid(packet, wire_dcid, &mut relayed)
                .map_err(|error| anyhow::anyhow!("adjacent-link wire DCID: {error:?}"))?;
            self.socket.send_to(&relayed[..used], self.peer).await?;
        } else {
            self.socket.send_to(packet, self.peer).await?;
        }
        Ok(())
    }

    /// Exchange one private direct setup/update while retaining this client's
    /// stable UDP tuple. Non-direct connection traffic is ignored until the
    /// correlated direct response arrives.
    pub async fn exchange_direct(&self, packet: &[u8]) -> Result<Vec<u8>> {
        Self::exchange_direct_on_socket(&self.socket, self.peer, packet).await
    }

    /// Exchange one direct record on a socket that will subsequently become a
    /// relay client. This preserves the reverse-path UDP tuple across pair
    /// setup, relay-open, and later service traffic.
    pub async fn exchange_direct_on_socket(
        socket: &UdpSocket,
        peer: SocketAddr,
        packet: &[u8],
    ) -> Result<Vec<u8>> {
        socket.send_to(packet, peer).await?;
        let mut response = [0u8; MTU];
        for _ in 0..BOOTSTRAP_ATTEMPTS {
            let Ok(Ok((used, response_peer))) =
                timeout(ACK_TIMEOUT, socket.recv_from(&mut response)).await
            else {
                continue;
            };
            if !same_udp_peer(response_peer, peer)
                || quic_lite::decode_direct_message_response(&response[..used]).is_err()
            {
                continue;
            }
            return Ok(response[..used].to_vec());
        }
        bail!("UDP direct exchange timeout after {BOOTSTRAP_ATTEMPTS} attempts")
    }

    /// Send one stream fragment and wait for the peer's next transport
    /// packet.  A terminal application response is returned rather than
    /// discarded so an upload can finish on the packet carrying its last
    /// fragment.  Packet numbering, ACK processing, and retransmission stay
    /// entirely in `quic-lite`; callers only supply ordered stream bytes.
    pub async fn send_stream_with_response(
        &mut self,
        stream_id: u64,
        data: &[u8],
        fin: bool,
    ) -> Result<Option<ReceivedStream>> {
        let mut packet = [0u8; MTU];
        let (_path, used) = self
            .connection
            .encode_stream_payload(stream_id, data, fin, &mut packet)
            .map_err(|error| anyhow::anyhow!("client packet: {error:?}"))?;
        self.send_endpoint_packet(&packet[..used]).await?;
        let started = Instant::now();
        for attempt in 0..STREAM_ATTEMPTS {
            let mut response = [0u8; MTU];
            if let Ok(Ok((len, peer))) =
                timeout(ACK_TIMEOUT, self.recv_association_packet(&mut response)).await
            {
                if !same_udp_peer(peer, self.peer) {
                    // A shared UDP socket can receive a delayed packet from
                    // an earlier association. It is not a path migration.
                    continue;
                }
                let control = self
                    .connection
                    .receive_stream_payload(self.path, &response[..len])
                    .map_err(|error| anyhow::anyhow!("client transport input: {error:?}"))?;
                let Some((id, offset, response_fin, response_data)) = control else {
                    return Ok(None);
                };
                let stream = ReceivedStream {
                    id,
                    offset,
                    fin: response_fin,
                    data: response_data.to_vec(),
                };
                self.connection
                    .stream_consumed(stream.id, stream.data.len(), self.deferred_receive_credit)
                    .map_err(|error| anyhow::anyhow!("client stream accounting: {error:?}"))?;
                let mut ack = [0u8; MTU];
                if let Some((_path, used)) = self
                    .connection
                    .poll_transmit(&mut ack)
                    .map_err(|error| anyhow::anyhow!("client response ACK: {error:?}"))?
                {
                    self.send_endpoint_packet(&ack[..used]).await?;
                }
                if !self
                    .connection
                    .accept_server_response_stream(stream.id, stream.fin)
                    .map_err(|error| {
                        anyhow::anyhow!(
                            "UDP stream response id {} is not the association response: {error:?}",
                            stream.id
                        )
                    })?
                {
                    bail!("unexpected duplicate completed stream while waiting for ACK");
                }
                return Ok(Some(stream));
            }
            if attempt + 1 == STREAM_ATTEMPTS {
                break;
            }
            let now = started.elapsed().as_millis() as u64;
            self.endpoint_mut().set_time(now);
            let mut retry = [0u8; MTU];
            let pto = self.endpoint().pto_timeout();
            if let Some((retry_len, _)) =
                self.endpoint_mut()
                    .retransmit_due(now, pto, &mut retry)
                    .map_err(|error| anyhow::anyhow!("client stream retransmission: {error:?}"))?
            {
                self.send_endpoint_packet(&retry[..retry_len]).await?;
            }
        }
        bail!("UDP client ACK timeout after {STREAM_ATTEMPTS} transport attempts")
    }

    /// Queue one ordered stream fragment on this association without making
    /// an application-level assumption about when the peer will next poll and
    /// emit an ACK.  A following `send_stream_with_response` or
    /// `recv_stream_frame` performs the normal QUIC-lite receive/ACK pump.
    pub async fn send_stream_no_wait(
        &mut self,
        stream_id: u64,
        data: &[u8],
        fin: bool,
    ) -> Result<()> {
        let mut packet = [0u8; MTU];
        let (_path, used) = self
            .connection
            .encode_stream_payload(stream_id, data, fin, &mut packet)
            .map_err(|error| anyhow::anyhow!("client packet: {error:?}"))?;
        self.send_endpoint_packet(&packet[..used]).await
    }

    /// Attempt to admit one ordered fragment to QUIC-lite without waiting for
    /// a peer packet. `false` means the association's existing flow,
    /// congestion, or retained-packet limits require the caller to drain
    /// transport progress first; no application byte was accepted in that
    /// case.
    pub async fn try_send_stream_no_wait(
        &mut self,
        stream_id: u64,
        data: &[u8],
        fin: bool,
    ) -> Result<bool> {
        self.try_send_stream_no_wait_at(stream_id, 0, data, fin)
            .await
    }

    /// Attempt to admit one ordered range at `offset`.  This is the streaming
    /// counterpart to [`Self::try_send_stream_no_wait`]; it does not make the
    /// UDP adapter responsible for stream sequencing.
    pub async fn try_send_stream_no_wait_at(
        &mut self,
        stream_id: u64,
        offset: u64,
        data: &[u8],
        fin: bool,
    ) -> Result<bool> {
        let mut packet = [0u8; MTU];
        let (_path, used) = match self.connection.encode_stream_payload_at(
            stream_id,
            offset,
            data,
            fin,
            &mut packet,
        ) {
            Ok(encoded) => encoded,
            Err(
                quic_lite::Error::FlowControl
                | quic_lite::Error::HistoryFull
                | quic_lite::Error::Invalid,
            ) => return Ok(false),
            Err(error) => return Err(anyhow::anyhow!("client packet: {error:?}")),
        };
        self.send_endpoint_packet(&packet[..used]).await?;
        Ok(true)
    }

    /// Consume one incoming QUIC-lite packet without pretending that every
    /// ACK acknowledges the most recently submitted application fragment.
    /// Senders use this only after `try_send_stream_no_wait` reports blocked;
    /// endpoint state decides when stream/connection credit is available.
    pub async fn recv_transport_progress(
        &mut self,
        progress_timeout: Duration,
    ) -> Result<Option<ReceivedStream>> {
        if progress_timeout.is_zero() {
            bail!("UDP transport progress timeout must be non-zero");
        }
        let deadline = Instant::now() + progress_timeout;
        let mut packet = [0u8; MTU];
        let (len, _peer) = loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let (len, peer) = timeout(remaining, self.recv_association_packet(&mut packet))
                .await
                .context("UDP transport progress timeout")??;
            if same_udp_peer(peer, self.peer) {
                break (len, peer);
            }
        };
        let payload = self
            .connection
            .receive_stream_payload(self.path, &packet[..len])
            .map_err(|error| anyhow::anyhow!("client transport input: {error:?}"))?;
        let Some((id, offset, fin, data)) = payload else {
            return Ok(None);
        };
        let stream = ReceivedStream {
            id,
            offset,
            fin,
            data: data.to_vec(),
        };
        self.connection
            .stream_consumed(stream.id, stream.data.len(), self.deferred_receive_credit)
            .map_err(|error| anyhow::anyhow!("client stream accounting: {error:?}"))?;
        let mut ack = [0u8; MTU];
        if let Some((_path, used)) = self
            .connection
            .poll_transmit(&mut ack)
            .map_err(|error| anyhow::anyhow!("client response ACK: {error:?}"))?
        {
            self.send_endpoint_packet(&ack[..used]).await?;
        }
        if !self
            .connection
            .accept_server_response_stream(stream.id, stream.fin)
            .map_err(|error| {
                anyhow::anyhow!(
                    "UDP stream response id {} is not the association response: {error:?}",
                    stream.id
                )
            })?
        {
            bail!("unexpected duplicate completed stream while draining progress");
        }
        Ok(Some(stream))
    }

    /// Run the two-stream object upload shape on one established QUIC-lite
    /// association.  The caller supplies only the command bytes and an
    /// ordered record producer; ACKs, MAX_DATA, congestion history, and
    /// response-stream accounting remain private to this transport adapter.
    pub async fn request_object_upload(
        &mut self,
        command: &[u8],
        records: &mut ObjectBodyStream,
        scratch: &mut [u8],
        response_timeout: Duration,
    ) -> Result<ReceivedStream> {
        if scratch.is_empty() || response_timeout.is_zero() {
            bail!("object upload scratch and response timeout must be non-zero");
        }
        let started = Instant::now();
        let deadline = started + response_timeout;
        // QUIC-lite allocates the command and object stream IDs for this
        // association. Do not rely on adjacent UDP ordering to make the
        // command visible before object bytes: the
        // first ordinary transport packet after the command proves that the
        // peer's QUIC-lite endpoint has admitted it.  It also gives the
        // association its first RTT/ACK sample before the bulk stream fills
        // the bounded raw-UDP ingress window.
        let command_stream = self
            .connection
            .open_next_client_bidi_stream()
            .map_err(|error| anyhow::anyhow!("command stream allocation: {error:?}"))?;
        let object_stream = self
            .connection
            .open_next_client_bidi_stream()
            .map_err(|error| anyhow::anyhow!("object stream allocation: {error:?}"))?;
        self.send_stream_no_wait(command_stream, command, true)
            .await?;
        let mut command_admitted = false;
        let mut packet = [0u8; MTU];
        while Instant::now() < deadline {
            // Once the command is transport-admitted, fill only the credit
            // the common endpoint has made available. `ObjectBodyStream`
            // owns record ordering; packet history, congestion, ACKs and
            // retransmission remain entirely inside quic-lite.
            if command_admitted && !records.is_complete() {
                if let Some(next) = records.copy_next(scratch) {
                    let now_ms = started.elapsed().as_millis() as u64;
                    self.endpoint_mut().set_time(now_ms);
                    match self.connection.encode_stream_payload_at(
                        object_stream,
                        next.offset,
                        &scratch[..next.len],
                        next.fin,
                        &mut packet,
                    ) {
                        Ok((_path, used)) => {
                            self.send_endpoint_packet(&packet[..used]).await?;
                            if !records.advance(next) {
                                bail!("object record producer rejected admitted stream bytes");
                            }
                            // Return to the association receive/poll turn
                            // before offering another object range. The peer
                            // owns ACK and window production; a UDP adapter
                            // must not bypass those packets with an
                            // application-local burst loop.
                        }
                        Err(
                            quic_lite::Error::FlowControl
                            | quic_lite::Error::HistoryFull
                            | quic_lite::Error::Invalid,
                        ) => {}
                        Err(error) => {
                            return Err(anyhow::anyhow!("object upload packet: {error:?}"));
                        }
                    }
                }
            }

            // The bearer only waits for and injects a complete datagram.  A
            // short timeout is a normal QUIC-lite scheduling edge, not an
            // upload-level retry: after it, poll the association-owned PTO
            // ledger and delayed-control queue below.
            let remaining = deadline.saturating_duration_since(Instant::now());
            // A local mesh peer normally replies within one scheduler turn.
            // Keep that turn short: a longer idle wait per object fragment
            // turns a megabyte transfer into a receiver-timeout even though
            // both QUIC-lite endpoints remain healthy.
            let receive_wait = remaining.min(Duration::from_millis(1));
            match timeout(receive_wait, self.recv_association_packet(&mut packet)).await {
                Ok(Ok((len, peer))) => {
                    if !same_udp_peer(peer, self.peer) {
                        continue;
                    }
                    let now_ms = started.elapsed().as_millis() as u64;
                    let payload = self
                        .connection
                        .receive_stream_payload(self.path, &packet[..len])
                        .map_err(|error| {
                            anyhow::anyhow!("object upload transport input: {error:?}")
                        })?;
                    // Any established peer packet after the command means its
                    // endpoint accepted that request.  The application
                    // receiver is armed in that same ingress turn.
                    command_admitted = true;
                    if let Some((id, offset, fin, data)) = payload {
                        let stream = ReceivedStream {
                            id,
                            offset,
                            fin,
                            data: data.to_vec(),
                        };
                        self.connection
                            .stream_consumed(
                                stream.id,
                                stream.data.len(),
                                self.deferred_receive_credit,
                            )
                            .map_err(|error| {
                                anyhow::anyhow!("object upload stream accounting: {error:?}")
                            })?;
                        if !self
                            .connection
                            .accept_server_response_stream(stream.id, stream.fin)
                            .map_err(|error| {
                                anyhow::anyhow!(
                                    "object upload response stream {}: {error:?}",
                                    stream.id
                                )
                            })?
                        {
                            continue;
                        }
                        // A response stream may span more than one packet.
                        // It remains QUIC-lite's ordinary ordered response
                        // stream until FIN; only that terminal fragment can
                        // complete an upload operation.
                        if !stream.fin {
                            continue;
                        }
                        if !records.is_complete() {
                            bail!(
                                "object upload rejected before the object stream FIN: {:?}",
                                stream.data
                            );
                        }
                        // The terminal application record is still an
                        // ordinary incoming QUIC-lite stream fragment.  Drive
                        // QUIC-lite's delayed-ACK deadline before returning,
                        // rather than making Recovery or the flash handler
                        // infer ACK state.  Recovery waits for that generic
                        // delivery edge before handing Stage2 back to Main.
                        self.acknowledge_terminal_response(started, &mut packet, "object upload")
                            .await?;
                        return Ok(stream);
                    }
                    // Keep the association clock in the same domain used by
                    // every later PTO calculation, including control-only
                    // peer packets.
                    self.endpoint_mut().set_time(now_ms);
                }
                Ok(Err(error)) => return Err(error.into()),
                Err(_) => {}
            }

            let now_ms = started.elapsed().as_millis() as u64;
            self.endpoint_mut().set_time(now_ms);
            let pto = self.endpoint().pto_timeout();
            if let Some((_path, used)) =
                self.connection
                    .poll_retransmit(now_ms, pto, &mut packet)
                    .map_err(|error| anyhow::anyhow!("object upload retransmission: {error:?}"))?
            {
                self.send_endpoint_packet(&packet[..used]).await?;
                continue;
            }
            if let Some((_path, used)) = self
                .connection
                .poll_transmit(&mut packet)
                .map_err(|error| anyhow::anyhow!("object upload control: {error:?}"))?
            {
                self.send_endpoint_packet(&packet[..used]).await?;
            }
        }
        bail!("object upload response timeout after QUIC-lite transport progress")
    }

    /// Send one complete application request stream and require a transport
    /// control response. The caller chooses the service tag/schema.
    pub async fn send_stream(&mut self, stream_id: u64, data: &[u8], fin: bool) -> Result<()> {
        if self
            .send_stream_with_response(stream_id, data, fin)
            .await?
            .is_some()
        {
            bail!("unexpected stream while waiting for ACK")
        }
        Ok(())
    }

    /// Wait for a terminal application stream response after an upload has
    /// already sent its command and body on this same association.
    pub async fn wait_stream_response(
        &mut self,
        response_timeout: Duration,
    ) -> Result<ReceivedStream> {
        if response_timeout.is_zero() {
            bail!("UDP stream response timeout must be non-zero");
        }
        timeout(response_timeout, self.recv_stream_frame())
            .await
            .context("UDP client response timeout")?
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

    /// Send a request which may legitimately defer its terminal response.
    ///
    /// Object mutations use this for the original control stream: the peer
    /// first completes a separate object association and only then replies to
    /// the request. `attempts=1` is useful for a mutation whose receiver has
    /// already admitted the request, because replaying it while it is active
    /// is neither useful nor safe.
    pub async fn request_stream_with_response_timeout(
        &mut self,
        stream_id: u64,
        data: &[u8],
        fin: bool,
        response_timeout: Duration,
        attempts: u32,
    ) -> Result<(u64, Vec<u8>, bool)> {
        let frame = self
            .request_stream_frame_with_response_timeout(
                stream_id,
                data,
                fin,
                response_timeout,
                attempts,
            )
            .await?;
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
        self.request_stream_frame_with_response_timeout(
            stream_id,
            data,
            fin,
            ACK_TIMEOUT,
            STREAM_ATTEMPTS,
        )
        .await
    }

    async fn request_stream_frame_with_response_timeout(
        &mut self,
        stream_id: u64,
        data: &[u8],
        fin: bool,
        response_timeout: Duration,
        attempts: u32,
    ) -> Result<ReceivedStream> {
        if response_timeout.is_zero() || attempts == 0 {
            bail!("UDP stream response timeout and attempts must be non-zero");
        }
        if self.connection.has_active_server_response_stream() {
            bail!("previous UDP response stream has not reached FIN");
        }
        let mut packet = [0u8; MTU];
        let (_path, used) = self
            .connection
            .encode_stream_payload(stream_id, data, fin, &mut packet)
            .map_err(|error| anyhow::anyhow!("client packet: {error:?}"))?;
        self.send_endpoint_packet(&packet[..used]).await?;
        let started = Instant::now();
        for attempt in 0..attempts {
            let deadline = Instant::now() + response_timeout;
            loop {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    break;
                }
                let mut incoming = [0u8; MTU];
                let received =
                    timeout(remaining, self.recv_association_packet(&mut incoming)).await;
                let Ok(Ok((len, peer))) = received else {
                    break;
                };
                if !same_udp_peer(peer, self.peer) {
                    continue;
                }
                // The CLI intentionally uses one fixed diagnostic source
                // port. A delayed response from a retired association can
                // therefore arrive while a new request is active. Correlate
                // it by destination CID before asking EndpointState to parse
                // it; an unrelated packet is not a fatal
                // error for the current request.
                // A stateless reset is intentionally opaque, so it is not a
                // valid short header. Ask the shared association before the
                // normal delayed-packet filter; a peer restart then becomes
                // an immediate recovery event instead of three PTO waits.
                if self.connection.is_peer_stateless_reset(&incoming[..len]) {
                    return Err(anyhow::Error::new(quic_lite::Error::PeerRestarted));
                }
                let before_stats = self.connection.connection().endpoint().map(|e| e.stats());
                let received = match self.connection.receive_serial_response_payload(
                    self.path,
                    &incoming[..len],
                    self.deferred_receive_credit,
                ) {
                    Ok(packet) => packet,
                    Err(quic_lite::Error::Invalid | quic_lite::Error::WrongConnectionId) => {
                        continue;
                    }
                    Err(error) => bail!("client transport input: {error:?}"),
                };
                if std::env::var_os("DMESH_UDP_TRACE").is_some() {
                    match received {
                        Some(payload) => eprintln!(
                            "dmesh_udp_trace response stream={} offset={} bytes={} fin={}",
                            payload.stream_id,
                            payload.offset,
                            payload.data.len(),
                            payload.fin
                        ),
                        None => {
                            let after = self.connection.connection().endpoint().map(|e| e.stats());
                            eprintln!(
                                "dmesh_udp_trace non_response bytes={len} before={before_stats:?} after={after:?}"
                            )
                        }
                    }
                }
                match received {
                    None => continue,
                    Some(payload) => {
                        let response = ReceivedStream {
                            id: payload.stream_id,
                            offset: payload.offset,
                            fin: payload.fin,
                            data: payload.data.to_vec(),
                        };
                        let mut ack = [0u8; MTU];
                        self.acknowledge_terminal_response(started, &mut ack, "client response")
                            .await?;
                        return Ok(response);
                    }
                }
            }
            if attempt + 1 == attempts {
                break;
            }
            let now = started.elapsed().as_millis() as u64;
            self.endpoint_mut().set_time(now);
            let mut retry = [0u8; MTU];
            let pto = self.endpoint().pto_timeout();
            let retransmission = self
                .endpoint_mut()
                .retransmit_due(now, pto, &mut retry)
                .map_err(|error| anyhow::anyhow!("client stream retransmission: {error:?}"))?;
            let Some((retry_len, _packet_number)) = retransmission else {
                continue;
            };
            self.send_endpoint_packet(&retry[..retry_len]).await?;
        }
        Err(anyhow::Error::new(
            crate::transport::AssociationStreamTimeout { attempts },
        ))
    }

    /// Send one request and collect its complete ordered response stream.
    ///
    /// PROBE and object-like services may return many independently received
    /// frames.  Preserve offsets here so a bearer client does not mistake
    /// reordering or a retransmission for a successful byte-count transfer.
    /// `max_bytes` is an explicit caller-provided memory bound.
    pub async fn request_stream_all(
        &mut self,
        stream_id: u64,
        data: &[u8],
        fin: bool,
        max_bytes: usize,
    ) -> Result<Vec<u8>> {
        let first = self.request_stream_frame(stream_id, data, fin).await?;
        // A terminal may allocate the server-initiated response stream rather
        // than mirror the client request stream. Keep the first accepted
        // response stream ID as the correlation target for its fragments.
        let response_stream_id = first.id;
        let mut frames = BTreeMap::<u64, Vec<u8>>::new();
        let mut final_offset = None;
        let mut frame = first;
        loop {
            if frame.data.len() > max_bytes {
                bail!("UDP stream response frame exceeds bound");
            }
            let end = frame
                .offset
                .checked_add(u64::try_from(frame.data.len()).unwrap_or(u64::MAX))
                .ok_or_else(|| anyhow::anyhow!("UDP stream response offset overflow"))?;
            if end > u64::try_from(max_bytes).unwrap_or(u64::MAX) {
                bail!("UDP stream response exceeds bound");
            }
            if frame.fin {
                if let Some(previous) = final_offset
                    && previous != end
                {
                    bail!("UDP stream has conflicting final offsets");
                }
                final_offset = Some(end);
            }
            frames.entry(frame.offset).or_insert(frame.data);

            let mut assembled = Vec::new();
            let mut next = 0u64;
            for (offset, chunk) in &frames {
                if *offset > next {
                    break;
                }
                let chunk_end =
                    offset.saturating_add(u64::try_from(chunk.len()).unwrap_or(u64::MAX));
                if chunk_end <= next {
                    continue;
                }
                let start = usize::try_from(next - *offset)
                    .map_err(|_| anyhow::anyhow!("UDP stream overlap offset"))?;
                assembled.extend_from_slice(&chunk[start..]);
                next = chunk_end;
            }
            if final_offset == Some(next) {
                return Ok(assembled);
            }
            frame = self.recv_stream_frame().await?;
            if frame.id != response_stream_id {
                bail!(
                    "UDP stream response id {} expected {response_stream_id}",
                    frame.id
                );
            }
        }
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
            let (len, peer) = self.recv_association_packet(&mut packet).await?;
            if !same_udp_peer(peer, self.peer) {
                continue;
            }
            let stream = match self
                .connection
                .receive_stream_payload(self.path, &packet[..len])
                .map_err(|error| anyhow::anyhow!("client transport input: {error:?}"))?
            {
                None => continue,
                Some((id, offset, fin, data)) => ReceivedStream {
                    id,
                    offset,
                    fin,
                    data: data.to_vec(),
                },
            };
            self.connection
                .stream_consumed(stream.id, stream.data.len(), self.deferred_receive_credit)
                .map_err(|error| anyhow::anyhow!("client stream accounting: {error:?}"))?;
            let mut control = [0u8; MTU];
            if let Some((_path, used)) = self
                .connection
                .poll_transmit(&mut control)
                .map_err(|error| anyhow::anyhow!("client ACK: {error:?}"))?
            {
                self.send_endpoint_packet(&control[..used]).await?;
            }
            if self
                .connection
                .accept_server_response_stream(stream.id, stream.fin)
                .map_err(|error| {
                    anyhow::anyhow!(
                        "UDP stream response id {} is not the association response: {error:?}",
                        stream.id
                    )
                })?
            {
                return Ok(stream);
            }
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
    let socket = match config.socket.clone() {
        Some(socket) => socket,
        None => Arc::new(UdpSocket::bind(config.bind).await?),
    };
    let mut client_ingress = config
        .client_ingress
        .as_ref()
        .and_then(|ingress| ingress.take_receiver());
    if config.client_ingress.is_some() && client_ingress.is_none() {
        bail!("UDP client ingress router already has a listener");
    }
    configure_host_udp_buffers(&socket)?;
    if let Some(tos) = config.ip_tos {
        configure_ipv4_tos(&socket, tos)?;
    }
    tracing::info!(bind = %config.bind, "object_udp_bound");
    let server = ObjectServer::new(ServerConfig {
        artifact_root: config.artifact_root,
        ..ServerConfig::default()
    });
    let mut datagram = [0u8; MTU];
    let mut connections =
        ConnectionTable::<UdpConnectionRoute, MAX_ACTIVE_CONNECTIONS, 1>::new([PathState::new()]);
    connections
        .set_path_available(0, true)
        .map_err(|error| anyhow::anyhow!("UDP path registration: {error:?}"))?;
    let mut pending_opens: HashMap<(SocketAddr, u64), u64> = HashMap::new();
    let mut pending_open_bytes: HashMap<(SocketAddr, u64), Vec<u8>> = HashMap::new();
    let mut bootstrap_packet_numbers: HashMap<(SocketAddr, u64), Arc<BootstrapPacketNumbers>> =
        HashMap::new();
    let mut outbound_routes = HashMap::<u64, UdpClientIngressRoute>::new();
    let closed_routes = Arc::new(std::sync::Mutex::new(Vec::<u64>::new()));
    loop {
        if let Ok(mut closed) = closed_routes.lock() {
            for cid in closed.drain(..) {
                if let Some(cid) = quic_lite::ConnectionId::new(cid) {
                    let _ = connections.remove(cid);
                }
            }
            pending_opens.retain(|_, cid| {
                quic_lite::ConnectionId::new(*cid).is_some_and(|cid| connections.contains(cid))
            });
            pending_open_bytes.retain(|key, _| pending_opens.contains_key(key));
            bootstrap_packet_numbers.retain(|key, _| pending_opens.contains_key(key));
        }
        // Client receivers disappear when their association is closed or a
        // failed request is discarded. Retire their CID routing entry without
        // waiting for another packet on that stale association.
        outbound_routes.retain(|_, route| !route.sender.is_closed());
        // Do this for every listener iteration, not only after an empty
        // recv timeout. A new benchmark can otherwise keep an old, stalled
        // route alive forever; its PTO retransmissions then contaminate the
        // otherwise independent next run on the same AP.
        let now = Instant::now();
        let expired: Vec<quic_lite::ConnectionId> = connections
            .iter()
            .filter(|(_, route)| now.duration_since(route.last_activity) >= config.idle_timeout)
            .map(|(_, route)| route.cid)
            .collect();
        for cid in expired {
            let _ = connections.remove(cid);
        }
        pending_opens.retain(|_, cid| {
            quic_lite::ConnectionId::new(*cid).is_some_and(|cid| connections.contains(cid))
        });
        pending_open_bytes.retain(|key, _| pending_opens.contains_key(key));
        bootstrap_packet_numbers.retain(|key, _| pending_opens.contains_key(key));
        let received = if let Some(ingress) = client_ingress.as_mut() {
            tokio::select! {
                registration = ingress.recv() => {
                    if let Some(registration) = registration {
                        let cid = registration.cid.value();
                        if outbound_routes.contains_key(&cid) {
                            let _ = registration.ready.send(Err(anyhow::anyhow!(
                                "UDP client association CID is already registered"
                            )));
                        } else {
                            outbound_routes.insert(
                                cid,
                                UdpClientIngressRoute {
                                    peer: registration.peer,
                                    sender: registration.sender,
                                },
                            );
                            let _ = registration.ready.send(Ok(()));
                        }
                    }
                    continue;
                }
                result = timeout(config.receive_timeout, socket.recv_from(&mut datagram)) => result,
            }
        } else {
            timeout(config.receive_timeout, socket.recv_from(&mut datagram)).await
        };
        let (len, peer) = match received {
            Ok(result) => result?,
            Err(_) => continue,
        };
        let packet = datagram[..len].to_vec();
        let classified = match quic_lite::classify_server_datagram(&packet) {
            Ok(value) => value,
            Err(error) => {
                // A stateless reset intentionally has no parseable routing
                // header.  Offer it only to retained outbound associations
                // for this adjacent tuple; each association privately checks
                // its reset token, so no adapter derives a CID from it.
                let mut delivered = false;
                for route in outbound_routes.values() {
                    if !same_udp_peer(route.peer, peer) {
                        continue;
                    }
                    match route.sender.try_send(ConnectionDatagram {
                        peer,
                        bytes: packet.clone(),
                    }) {
                        Ok(()) => delivered = true,
                        Err(mpsc::error::TrySendError::Full(_)) => {
                            tracing::debug!(%peer, "udp_client_reset_ingress_queue_full");
                        }
                        Err(mpsc::error::TrySendError::Closed(_)) => {}
                    }
                }
                if !delivered {
                    tracing::warn!(%peer, error = ?error, "udp_transport_malformed_header");
                }
                continue;
            }
        };
        if matches!(classified, quic_lite::ServerDatagram::Direct) {
            if let Some(handler) = config.direct_handler.as_ref() {
                let request = match quic_lite::receive_direct_message_request(&packet) {
                    Ok(request) => request,
                    Err(_) => continue,
                };
                if crate::direct::classify(request.payload()).is_none() {
                    continue;
                }
                tracing::debug!(%peer, bytes = request.payload().len(), "udp_direct_request");
                if let Some(payload) = handler
                    .handle(TaggedStreamContext { peer }, request.payload().to_vec())
                    .await
                {
                    let mut response = [0u8; MTU];
                    match quic_lite::encode_direct_message_response(
                        request,
                        &payload,
                        &mut response,
                    ) {
                        Ok(used) => {
                            socket.send_to(&response[..used], peer).await?;
                            tracing::debug!(%peer, bytes = used, "udp_direct_response");
                        }
                        Err(_) => tracing::warn!(%peer, "udp_direct_handler_oversize_response"),
                    }
                }
                continue;
            }
            // Direct is a complete, explicitly typed long-header plane. It
            // is never reinterpreted as connection setup merely because a
            // handler declined its payload.
            continue;
        }
        if let quic_lite::ServerDatagram::Initial(open) = classified {
            let client_cid = open.client_receive_cid;
            if let Some(control) = config.control.as_ref() {
                control.record_event(format!(
                    "bootstrap initial peer={peer} client_cid={}",
                    client_cid.value()
                ));
            }
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
                connections
                    .insert(
                        allocated,
                        UdpConnectionRoute {
                            cid: allocated,
                            peer,
                            sender,
                            last_activity: Instant::now(),
                        },
                    )
                    .map_err(|error| anyhow::anyhow!("UDP connection route: {error:?}"))?;
                let socket_for_connection = socket.clone();
                let server_for_connection = server.clone();
                let control_for_connection = config.control.clone();
                let tagged_handler_for_connection = config.tagged_handler.clone();
                let closed_routes_for_connection = closed_routes.clone();
                tokio::spawn(async move {
                    let result = serve_persistent_peer_with_ids(
                        socket_for_connection,
                        server_for_connection,
                        peer,
                        receiver,
                        None,
                        allocated,
                        client_cid,
                        open.max_data,
                        open.max_stream_data,
                        open.max_in_flight_packets,
                        history_capacity,
                        bootstrap_numbers,
                        config.object_chunk,
                        control_for_connection,
                        tagged_handler_for_connection,
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
            let used = encode_bootstrap_ack_with_reset_token(
                client_cid,
                packet_number,
                server_cid,
                config
                    .stateless_reset_key
                    .map(|key| key.token_for(server_cid)),
                &mut ack,
            )?;
            socket.send_to(&ack[..used], peer).await?;
            if let Some(control) = config.control.as_ref() {
                control.record_event(format!(
                    "bootstrap ack peer={peer} client_cid={} server_cid={}",
                    client_cid.value(),
                    server_cid.value()
                ));
            }
            tracing::info!(%peer, client_cid = client_cid.value(), server_cid = server_cid.value(),
                packet_number, "object_udp_bootstrap_ack");
            continue;
        }
        let destination = match classified {
            quic_lite::ServerDatagram::Established { destination }
            | quic_lite::ServerDatagram::BootstrapAck { destination } => destination,
            // Direct and Initial each continue above. Keeping this exhaustive
            // match makes a new QUIC-lite ingress kind impossible to route by
            // accident in the socket adapter.
            quic_lite::ServerDatagram::Direct | quic_lite::ServerDatagram::Initial(_) => {
                continue;
            }
        };
        if let Some(route) = outbound_routes.get(&destination.value()) {
            match route.sender.try_send(ConnectionDatagram {
                peer,
                bytes: packet.clone(),
            }) {
                Ok(()) => continue,
                Err(mpsc::error::TrySendError::Full(_)) => {
                    tracing::warn!(%peer, dcid = destination.value(), "udp_client_ingress_queue_full");
                    continue;
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    outbound_routes.remove(&destination.value());
                    continue;
                }
            }
        }
        let key = destination.value();
        if let Some(handler) = config.relay_handler.as_deref() {
            let mut forwarded = [0u8; MTU];
            match handler.handle(peer, &packet, &mut forwarded) {
                RelayDatagramOutcome::NotHandled => {}
                RelayDatagramOutcome::Forward {
                    peer: next_hop,
                    used,
                } if used <= forwarded.len() => {
                    socket.send_to(&forwarded[..used], next_hop).await?;
                    continue;
                }
                RelayDatagramOutcome::Forward { .. } => {
                    tracing::warn!(%peer, "udp_relay_handler_oversize_forward");
                    continue;
                }
                RelayDatagramOutcome::Drop => continue,
            }
        }
        if let Ok(route) = connections.route_mut(0, &packet) {
            if !same_udp_peer(route.peer, peer) {
                tracing::warn!(
                    %peer,
                    dcid = key,
                    expected_peer = ?route.peer,
                    "udp_transport_wrong_peer"
                );
                continue;
            }
            route.last_activity = Instant::now();
            let route_closed = match route.sender.try_send(ConnectionDatagram {
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
                Err(mpsc::error::TrySendError::Closed(_)) => true,
            };
            if route_closed {
                let _ = connections.remove(destination);
            }
        }

        // Non-zero CIDs are routable only after bootstrap allocated them.
        // Unknown labels are dropped instead of creating an implicit
        // symmetric-CID connection.
        if let Some(reset_key) = config.stateless_reset_key {
            let mut reset = [0u8; MTU];
            match reset_key.encode_for_unknown_packet(&packet, &mut reset) {
                Ok(Some(used)) => {
                    socket.send_to(&reset[..used], peer).await?;
                    tracing::debug!(%peer, dcid = key, "udp_transport_stateless_reset");
                    continue;
                }
                Ok(None) => {}
                Err(error) => {
                    tracing::warn!(%peer, dcid = key, error = ?error, "udp_transport_stateless_reset_error")
                }
            }
        }
        tracing::warn!(%peer, dcid = key, "udp_transport_unknown_cid");
    }
}

async fn serve_persistent_peer_with_ids(
    socket: Arc<UdpSocket>,
    server: ObjectServer,
    peer: SocketAddr,
    mut receiver: mpsc::Receiver<ConnectionDatagram>,
    first_packet: Option<Vec<u8>>,
    local_cid: quic_lite::ConnectionId,
    peer_cid: quic_lite::ConnectionId,
    peer_max_data: u64,
    peer_max_stream_data: u64,
    peer_max_in_flight_packets: u16,
    history_capacity: usize,
    bootstrap_packet_numbers: Arc<BootstrapPacketNumbers>,
    object_chunk: usize,
    control: Option<Arc<TransportControl>>,
    tagged_handler: Option<Arc<dyn TaggedStreamHandler>>,
) -> Result<()> {
    let mut connection = Box::new(
        ServerStreamConnection::<8, 512>::established_with_config(
            local_cid,
            peer_cid,
            ConnectionLimits::default(),
            peer_max_data,
            peer_max_stream_data,
            peer_max_in_flight_packets,
            0,
            ServerStreamConfig {
                history_packets: history_capacity,
                max_pending_streams: 8,
                max_stream_bytes: 256 * 1024,
            },
        )
        .map_err(|error| anyhow::anyhow!("persistent connection: {error:?}"))?,
    );
    let mut events = EventRing::new(64);
    let mut object_transfer = None;
    let mut byte_transfers: [Option<PendingByteTransfer>; MAX_PROBE_STREAMS] =
        core::array::from_fn(|_| None);
    let mut high_byte_transfer = None;
    let mut low_byte_transfer = None;
    let mut tagged_response = None;
    let started = Instant::now();
    if let Some(first_packet) = first_packet {
        let next = bootstrap_packet_numbers.next.load(Ordering::Acquire);
        if next > connection.mux.endpoint.next_packet_number {
            connection
                .mux
                .endpoint
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
            &mut connection,
            &mut events,
            &mut object_transfer,
            &mut byte_transfers,
            &mut high_byte_transfer,
            &mut low_byte_transfer,
            &mut tagged_response,
            started,
            object_chunk,
            control.as_deref(),
            tagged_handler.as_deref(),
        )
        .await
        .context("initial persistent packet")?;
        if connection.mux.is_closed() {
            return Ok(());
        }
    }
    loop {
        if let Some(control) = control.as_deref() {
            control.record_server_stats(&connection.mux.endpoint);
        }
        let receive_wait = connection_receive_wait(
            object_transfer.is_some(),
            byte_transfers.iter().any(Option::is_some)
                || high_byte_transfer.is_some()
                || low_byte_transfer.is_some(),
            None,
        );
        match timeout(receive_wait, receiver.recv()).await {
            Ok(Some(datagram)) if datagram.peer == peer => {
                let next = bootstrap_packet_numbers.next.load(Ordering::Acquire);
                if next > connection.mux.endpoint.next_packet_number {
                    connection
                        .mux
                        .endpoint
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
                    &mut connection,
                    &mut events,
                    &mut object_transfer,
                    &mut byte_transfers,
                    &mut high_byte_transfer,
                    &mut low_byte_transfer,
                    &mut tagged_response,
                    started,
                    object_chunk,
                    control.as_deref(),
                    tagged_handler.as_deref(),
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
                if connection.mux.is_closed() {
                    break;
                }
                let mut packet = [0u8; MTU];
                let _ = send_next_tagged_response_fragment(
                    &socket,
                    peer,
                    &mut connection.mux,
                    &mut tagged_response,
                    &mut packet,
                )
                .await?;
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
                    let _ =
                        retransmit_due_packet(&socket, peer, &mut connection.mux, started).await?;
                    let mut packet = [0u8; MTU];
                    let filled = fill_object_window(
                        &socket,
                        peer,
                        &mut connection.mux,
                        transfer,
                        &mut packet,
                    )
                    .await?;
                    let sent = filled && transfer.stream.is_complete();
                    if sent {
                        report_object_transfer(transfer, connection.mux.endpoint.stats());
                        object_transfer = None;
                    }
                } else if byte_transfers.iter().any(Option::is_some)
                    || high_byte_transfer.is_some()
                    || low_byte_transfer.is_some()
                {
                    let mut packet = [0u8; MTU];
                    schedule_probe_transfers(
                        &socket,
                        peer,
                        &mut connection.mux,
                        &mut byte_transfers,
                        &mut high_byte_transfer,
                        &mut low_byte_transfer,
                        &mut packet,
                        started,
                    )
                    .await?;
                } else {
                    let _ =
                        retransmit_due_packet(&socket, peer, &mut connection.mux, started).await?;
                }
                let mut packet = [0u8; MTU];
                let _ = send_next_tagged_response_fragment(
                    &socket,
                    peer,
                    &mut connection.mux,
                    &mut tagged_response,
                    &mut packet,
                )
                .await?;
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

fn allocate_server_cid(
    connections: &ConnectionTable<UdpConnectionRoute, MAX_ACTIVE_CONNECTIONS, 1>,
    avoid: quic_lite::ConnectionId,
) -> Result<quic_lite::ConnectionId> {
    for _ in 0..1024 {
        let value =
            NEXT_SERVER_CID.fetch_add(1, Ordering::Relaxed) & quic_lite::ConnectionId::MAX_VALUE;
        if value != 0
            && value != avoid.value()
            && quic_lite::ConnectionId::new(value).is_some_and(|cid| !connections.contains(cid))
        {
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
    quic_lite::bootstrap_open_payload(packet).ok()
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

#[cfg(test)]
fn encode_bootstrap_ack(
    client_cid: quic_lite::ConnectionId,
    packet_number: u32,
    server_cid: quic_lite::ConnectionId,
    out: &mut [u8],
) -> Result<usize> {
    quic_lite::encode_bootstrap_open_ack_packet(client_cid, server_cid, packet_number, out)
        .map_err(|error| anyhow::anyhow!("bootstrap ACK: {error:?}"))
}

fn encode_bootstrap_ack_with_reset_token(
    client_cid: quic_lite::ConnectionId,
    packet_number: u32,
    server_cid: quic_lite::ConnectionId,
    stateless_reset_token: Option<quic_lite::StatelessResetToken>,
    out: &mut [u8],
) -> Result<usize> {
    quic_lite::encode_bootstrap_open_ack_packet_with_limits_and_reset_token(
        client_cid,
        server_cid,
        packet_number,
        ConnectionLimits::default(),
        stateless_reset_token,
        out,
    )
    .map_err(|error| anyhow::anyhow!("bootstrap ACK: {error:?}"))
}

async fn process_persistent_packet<const H: usize>(
    socket: &UdpSocket,
    peer: SocketAddr,
    server: &ObjectServer,
    bytes: &[u8],
    connection: &mut ServerStreamConnection<8, H>,
    events: &mut EventRing,
    object_transfer: &mut Option<PendingObjectTransfer>,
    byte_transfers: &mut [Option<PendingByteTransfer>; MAX_PROBE_STREAMS],
    high_byte_transfer: &mut Option<PendingByteTransfer>,
    low_byte_transfer: &mut Option<PendingByteTransfer>,
    tagged_response: &mut Option<PendingTaggedResponse>,
    started: Instant,
    object_chunk: usize,
    control: Option<&TransportControl>,
    tagged_handler: Option<&dyn TaggedStreamHandler>,
) -> Result<()> {
    connection
        .mux
        .endpoint
        .set_time(started.elapsed().as_millis() as u64);
    let mut packet = [0u8; MTU];
    let request = connection
        .mux
        .receive_request(bytes)
        .map_err(|error| anyhow::anyhow!("persistent input: {error:?}"))?;
    if let Some(request) = request {
        let tagged_probe = crate::tagged::decode(&request.data)
            .and_then(crate::probe::decode_probe_run_record)
            .map(|(_, request)| request);
        // Tagged-CBOR is the normal stream request envelope. It carries the
        // component/method itself, so no service byte is consumed from the
        // stream. The branches below are compatibility for legacy clients.
        if tagged_probe.is_none() {
            if let Some(response) = match tagged_handler {
                Some(handler) => {
                    handler
                        .handle(TaggedStreamContext { peer }, request.data.clone())
                        .await
                }
                None => None,
            }
            .or_else(|| {
                connection
                    .mux
                    .endpoint
                    .local_connection_id()
                    .or_else(|| connection.mux.endpoint.peer_connection_id())
                    .and_then(|connection_cid| {
                        dispatch_diagnostic_tagged_stream(
                            &connection.mux.endpoint,
                            Some(events),
                            connection_cid,
                            request.stream_id,
                            &request.data,
                        )
                    })
            })
            .or_else(|| dispatch_tagged_stream(&request.data))
            {
                connection
                    .mux
                    .complete_request(request.stream_id, request.data.len())
                    .map_err(|error| anyhow::anyhow!("tagged request accounting: {error:?}"))?;
                if tagged_response.is_some() {
                    bail!("tagged response already active");
                }
                *tagged_response = Some(PendingTaggedResponse {
                    stream_id: connection.reserve_response_stream(),
                    bytes: response,
                    offset: 0,
                });
                let _ = send_next_tagged_response_fragment(
                    socket,
                    peer,
                    &mut connection.mux,
                    tagged_response,
                    &mut packet,
                )
                .await?;
                return Ok(());
            }
        }
        if let Some(control) = control {
            control.record_event(format!(
                "request peer={peer} stream={} service={} bytes={}",
                request.stream_id,
                request.data.first().copied().unwrap_or_default(),
                request.data.len(),
            ));
        }
        if let Ok(get) = object_request(&request.data) {
            if object_transfer.is_some() {
                bail!("object transfer already active");
            }
            if get.target == 0 || get.name.as_ref().is_some_and(|name| name.len() > 128) {
                bail!("invalid bootstrapped object target");
            }
            let (manifest, body) = server.response_object(get)?;
            if let Some(control) = control {
                control.record_event(format!("object accepted peer={peer} bytes={}", body.len()));
            }
            tracing::info!(%peer, stream = request.stream_id, bytes = body.len(),
                "object_udp_get_accepted");
            *object_transfer = Some(PendingObjectTransfer::from_object_with_chunk(
                manifest,
                body,
                object_chunk,
            ));
            connection
                .mux
                .complete_request(request.stream_id, request.data.len())
                .map_err(|error| anyhow::anyhow!("object request accounting: {error:?}"))?;
            // Object and PROBE use the same bearer. Make the object policy
            // explicit too; otherwise a Recovery client silently remains at
            // its local default and host/device diagnostics disagree.
            connection
                .mux
                .endpoint
                .request_ack_frequency(
                    0,
                    u64::from(RECOVERY_OBJECT_ACK_FREQUENCY - 1),
                    RECOVERY_MAX_ACK_DELAY_US,
                    1,
                )
                .map_err(|error| anyhow::anyhow!("object ACK_FREQUENCY: {error:?}"))?;
            if let Some(used) = connection
                .mux
                .endpoint
                .poll_transmit(&mut packet)
                .map_err(|error| anyhow::anyhow!("object ACK_FREQUENCY send: {error:?}"))?
            {
                socket.send_to(&packet[..used], peer).await?;
            }
        } else if let Some(probe_request) = tagged_probe {
            if byte_transfers.iter().any(Option::is_some)
                || high_byte_transfer.is_some()
                || low_byte_transfer.is_some()
            {
                bail!("probe transfer already active");
            }
            // The no-std handler plan is also consumed by firmware. Keep
            // request clamping, stream expansion, and ACK policy identical
            // before this socket adapter adds host-only pacing.
            let probe_plan = ProbeServicePlan::from_request(probe_request, MAX_OBJECT_CHUNK);
            // The optional fields are diagnostic-only, scoped to this
            // PROBE request. Normal object transfers keep UdpConfig's
            // default unpaced scheduling, and an older Recovery request
            // (11 bytes) still uses the listener defaults.
            let (ack_frequency, ack_delay_us) = probe_ack_policy(probe_request);
            connection
                .mux
                .complete_request(request.stream_id, request.data.len())
                .map_err(|error| anyhow::anyhow!("probe request accounting: {error:?}"))?;
            // Default to RFC 9000's every-other-ack-eliciting-packet policy.
            // The selected ratio is carried in ACK_FREQUENCY, rather than
            // relying on a local Recovery setting the host cannot observe.
            connection
                .mux
                .endpoint
                .request_ack_frequency(
                    0,
                    u64::from(ack_frequency.saturating_sub(1)),
                    ack_delay_us,
                    1,
                )
                .map_err(|error| anyhow::anyhow!("probe ACK_FREQUENCY: {error:?}"))?;
            if let Some(used) = connection
                .mux
                .endpoint
                .poll_transmit(&mut packet)
                .map_err(|error| anyhow::anyhow!("probe ACK_FREQUENCY send: {error:?}"))?
            {
                socket.send_to(&packet[..used], peer).await?;
            }
            for (index, transfer) in byte_transfers
                .iter_mut()
                .take(probe_plan.normal_streams)
                .enumerate()
            {
                let bytes = probe_plan.normal_bytes[index];
                let response_stream = connection.reserve_response_stream();
                *transfer = Some(PendingByteTransfer::new(
                    response_stream,
                    bytes,
                    probe_plan.packet_size,
                ));
            }
            if probe_plan.high_priority_bytes != 0 {
                let response_stream = connection.reserve_response_stream();
                *high_byte_transfer = Some(PendingByteTransfer::new(
                    response_stream,
                    probe_plan.high_priority_bytes,
                    probe_plan.packet_size,
                ));
            }
            if probe_plan.low_priority_bytes != 0 {
                let response_stream = connection.reserve_response_stream();
                *low_byte_transfer = Some(PendingByteTransfer::new(
                    response_stream,
                    probe_plan.low_priority_bytes,
                    probe_plan.packet_size,
                ));
            }
        } else {
            anyhow::bail!("untagged diagnostic stream request rejected");
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
        let _ = retransmit_due_packet(socket, peer, &mut connection.mux, started).await?;
        let filled =
            fill_object_window(socket, peer, &mut connection.mux, transfer, &mut packet).await?;
        if filled {
            if transfer.stream.is_complete() {
                report_object_transfer(transfer, connection.mux.endpoint.stats());
                *object_transfer = None;
            }
        }
    } else if byte_transfers.iter().any(Option::is_some)
        || high_byte_transfer.is_some()
        || low_byte_transfer.is_some()
    {
        schedule_probe_transfers(
            socket,
            peer,
            &mut connection.mux,
            byte_transfers,
            high_byte_transfer,
            low_byte_transfer,
            &mut packet,
            started,
        )
        .await?;
    } else if let Some(used) = connection
        .mux
        .endpoint
        .poll_transmit(&mut packet)
        .map_err(|error| anyhow::anyhow!("persistent ACK: {error:?}"))?
    {
        socket.send_to(&packet[..used], peer).await?;
    }
    Ok(())
}

/// Advance one pending tagged response when its QUIC packet ledger has room.
/// A terminal result is fragmented only at the physical frame boundary, and
/// each next fragment is driven by the same ACK/PTO loop as every other QUIC
/// stream.  It is therefore not a UDP-only bulk path.
async fn send_next_tagged_response_fragment<const H: usize>(
    socket: &UdpSocket,
    peer: SocketAddr,
    mux: &mut StreamMux<8, H>,
    pending: &mut Option<PendingTaggedResponse>,
    packet: &mut [u8; MTU],
) -> Result<bool> {
    let Some(response) = pending.as_mut() else {
        return Ok(false);
    };
    if mux.endpoint.history_len() >= mux.endpoint.history_capacity() {
        return Ok(false);
    }
    if response.bytes.is_empty() {
        let (used, _) = mux
            .encode_response_at(response.stream_id, 0, &[], true, packet)
            .map_err(|error| anyhow::anyhow!("empty tagged response: {error:?}"))?;
        socket.send_to(&packet[..used], peer).await?;
        *pending = None;
        return Ok(true);
    }
    let offset = response.offset;
    let mut end = response.bytes.len().min(offset.saturating_add(MTU));
    let used = loop {
        let fin = end == response.bytes.len();
        match mux.encode_response_at(
            response.stream_id,
            offset as u64,
            &response.bytes[offset..end],
            fin,
            packet,
        ) {
            Ok((used, _)) => break used,
            Err(quic_lite::Error::BufferTooSmall) if end > offset + 1 => {
                end = offset + (end - offset) / 2;
            }
            Err(quic_lite::Error::HistoryFull) => return Ok(false),
            Err(error) => bail!("tagged response fragment: {error:?}"),
        }
    };
    socket.send_to(&packet[..used], peer).await?;
    response.offset = end;
    if response.offset == response.bytes.len() {
        *pending = None;
    }
    Ok(true)
}

/// Priority scheduler for one connection. High-priority application records
/// consume up to four packet opportunities, normal PROBE streams share the
/// host refill quantum, and the log-like low stream receives one opportunity.
/// Every branch remains bounded by endpoint congestion and stream credit.
async fn schedule_probe_transfers<const H: usize>(
    socket: &UdpSocket,
    peer: SocketAddr,
    mux: &mut StreamMux<8, H>,
    normal: &mut [Option<PendingByteTransfer>; MAX_PROBE_STREAMS],
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
        HOST_PROBE_NORMAL_REFILL_PACKETS.saturating_sub(4)
    } else {
        HOST_PROBE_NORMAL_REFILL_PACKETS
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
    let mut sent = false;
    let mut burst_sent = 0usize;
    while burst_sent < packet_budget
        && transfer.remaining != 0
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
                .map_err(|error| anyhow::anyhow!("probe peer CID: {error:?}"))?,
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
            Err(error) => return Err(anyhow::anyhow!("probe response packet: {error:?}")),
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
    if transfer.first_send.is_none() {
        mux.endpoint
            .open_send_stream(stream_id, INITIAL_MAX_STREAM_DATA)
            .map_err(|error| anyhow::anyhow!("object response stream open: {error:?}"))?;
    }
    let mut object_bytes = [0u8; MAX_OBJECT_CHUNK];
    let Some(chunk) = transfer
        .stream
        .copy_next(&mut object_bytes[..transfer.chunk_size])
    else {
        return Ok(false);
    };
    let encoded = mux.endpoint.encode_stream_packet_fitting(
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
    let (used, _, written) = match encoded {
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
    if transfer.first_send.is_none() {
        transfer.first_send = Some(Instant::now());
    }
    transfer.sent_datagrams = transfer.sent_datagrams.saturating_add(1);
    let previous_bytes = transfer.stream.sent_bytes();
    let sent_chunk = crate::verified_object::ObjectStreamChunk {
        offset: chunk.offset,
        len: written,
        fin: chunk.fin && written == chunk.len,
        record_index: chunk.record_index,
    };
    debug_assert!(transfer.stream.advance(sent_chunk));
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
    let mut sent_any = false;
    let mut sent_packets = 0usize;
    while mux.endpoint.history_len() < mux.endpoint.history_capacity() {
        if !send_next_object_packet(socket, peer, mux, transfer, packet).await? {
            break;
        }
        sent_any = true;
        sent_packets += 1;
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
    use std::collections::HashSet;
    use std::eprintln;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use quic_lite::CommittedStreamDisposition;

    fn established_client_connection(
        local: ConnectionId,
        peer: ConnectionId,
        path: quic_lite::PathId,
    ) -> quic_lite::ClientAssociation<512, MTU> {
        let mut connection = quic_lite::ClientAssociation::new(local);
        let mut packet = [0u8; MTU];
        connection.select_path(path);
        connection.start(&mut packet).unwrap();
        let used = quic_lite::encode_bootstrap_open_ack_packet_with_limits(
            local,
            peer,
            0,
            ConnectionLimits::default(),
            &mut packet,
        )
        .unwrap();
        connection
            .receive(path, &packet[..used], |client| {
                client.receive_open_ack(&packet[..used], 0)
            })
            .unwrap();
        connection
    }

    fn diagnostic_request(method: u64, id: u64) -> Vec<u8> {
        let mut request = [0u8; 48];
        let used = crate::tagged::encode_numeric_empty_request(
            crate::services::DIAGNOSTIC_COMPONENT,
            method,
            id,
            &mut request,
        )
        .unwrap();
        request[..used].to_vec()
    }

    fn diagnostic_text(response: &[u8]) -> String {
        let record = crate::tagged::decode(response).unwrap();
        let mut result = crate::cbor::Decoder::new(record.result.unwrap());
        let text = String::from_utf8(result.text_ref().unwrap().to_vec()).unwrap();
        assert!(result.is_finished());
        text
    }

    async fn request_diagnostic_text(
        client: &mut UdpClient,
        stream_id: u64,
        method: u64,
    ) -> String {
        let request = diagnostic_request(method, stream_id);
        let (_, response, finished) = client
            .request_stream(stream_id, &request, true)
            .await
            .unwrap();
        assert!(finished);
        diagnostic_text(&response)
    }

    #[derive(Debug)]
    struct EchoDirect;

    impl TaggedStreamHandler for EchoDirect {
        fn handle<'a>(
            &'a self,
            _context: TaggedStreamContext,
            payload: Vec<u8>,
        ) -> Pin<Box<dyn Future<Output = Option<Vec<u8>>> + Send + 'a>> {
            Box::pin(async move { crate::direct::classify(&payload).map(|_| payload) })
        }
    }

    /// Deliberately accepts every payload it is offered. The listener must
    /// still let a bootstrap OPEN through, because only tagged records are
    /// eligible for direct-control dispatch.
    #[derive(Debug)]
    struct GreedyDirect;

    impl TaggedStreamHandler for GreedyDirect {
        fn handle<'a>(
            &'a self,
            _context: TaggedStreamContext,
            _payload: Vec<u8>,
        ) -> Pin<Box<dyn Future<Output = Option<Vec<u8>>> + Send + 'a>> {
            Box::pin(async { None })
        }
    }

    #[derive(Debug, Default)]
    struct CountingDirect(AtomicUsize);

    impl TaggedStreamHandler for CountingDirect {
        fn handle<'a>(
            &'a self,
            _context: TaggedStreamContext,
            _payload: Vec<u8>,
        ) -> Pin<Box<dyn Future<Output = Option<Vec<u8>>> + Send + 'a>> {
            Box::pin(async move {
                self.0.fetch_add(1, Ordering::Relaxed);
                None
            })
        }
    }

    #[tokio::test]
    async fn udp_listener_dispatches_direct_message_before_quic_bootstrap() {
        let probe = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let bind = probe.local_addr().unwrap();
        drop(probe);
        let server = tokio::spawn(run(UdpConfig {
            bind,
            direct_handler: Some(Arc::new(EchoDirect)),
            ..UdpConfig::default()
        }));
        tokio::time::sleep(Duration::from_millis(10)).await;
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut request_payload = [0u8; 32];
        let request_payload_len =
            crate::announce::encode_discovery_request(7, &mut request_payload).unwrap();
        let mut request = [0u8; 32];
        let request_len = crate::direct::ConnectionlessMessage::encode(
            &request_payload[..request_payload_len],
            &mut request,
        )
        .unwrap();
        client.send_to(&request[..request_len], bind).await.unwrap();
        let mut response = [0u8; 32];
        let (response_len, peer) =
            timeout(Duration::from_millis(100), client.recv_from(&mut response))
                .await
                .unwrap()
                .unwrap();
        assert_eq!(peer, bind);
        let payload =
            crate::direct::ConnectionlessMessage::decode(&response[..response_len]).unwrap();
        assert_eq!(payload, &request_payload[..request_payload_len]);
        server.abort();
    }

    #[tokio::test]
    async fn udp_listener_returns_quic_lite_stateless_reset_for_unknown_short_cid() {
        let probe = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let bind = probe.local_addr().unwrap();
        drop(probe);
        let reset_key = quic_lite::StatelessResetKey::from_device_secret(&[0x71; 32]).unwrap();
        let server = tokio::spawn(run(UdpConfig {
            bind,
            stateless_reset_key: Some(reset_key),
            ..UdpConfig::default()
        }));
        tokio::time::sleep(Duration::from_millis(10)).await;
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let unknown = ConnectionId::new(0x1_2345).unwrap();
        let mut request = [0u8; 48];
        let header_len = quic_lite::ShortHeader {
            flags: quic_lite::FLAG_FIXED,
            dcid: unknown,
            packet_number: 1,
            packet_number_len: 1,
        }
        .encode(&mut request)
        .unwrap();
        request[header_len..].fill(0x44);
        client.send_to(&request, bind).await.unwrap();
        let mut response = [0u8; 64];
        let (used, peer) = timeout(Duration::from_millis(100), client.recv_from(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(peer, bind);
        assert_eq!(used, request.len());
        assert!(
            reset_key
                .token_for(unknown)
                .matches_packet(&response[..used])
        );
        server.abort();
    }

    #[tokio::test]
    async fn retained_client_recovers_peer_restart_without_waiting_for_pto() {
        let root = tempdir().unwrap();
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let bind = socket.local_addr().unwrap();
        let reset_key = quic_lite::StatelessResetKey::from_device_secret(&[0x92; 32]).unwrap();
        let config = || UdpConfig {
            bind,
            socket: Some(socket.clone()),
            artifact_root: root.path().to_path_buf(),
            stateless_reset_key: Some(reset_key),
            ..UdpConfig::default()
        };
        let first_server = tokio::spawn(run(config()));
        tokio::time::sleep(Duration::from_millis(10)).await;
        let mut client = UdpClient::connect(
            "127.0.0.1:0".parse().unwrap(),
            bind,
            ConnectionId::new(0x6a6).unwrap(),
        )
        .await
        .unwrap();
        // Keep the UDP port but discard the connection table, exactly as a
        // supervised peer restart does. The new listener derives the same
        // token for the old server CID and immediately resets the retained
        // client association.
        first_server.abort();
        let restarted_server = tokio::spawn(run(config()));
        tokio::time::sleep(Duration::from_millis(10)).await;
        let started = Instant::now();
        let error = client
            .request_stream(FIRST_CLIENT_BIDI_STREAM_ID, b"after-restart", true)
            .await
            .unwrap_err();
        assert!(started.elapsed() < ACK_TIMEOUT);
        assert!(crate::transport::is_peer_restarted_error(&error));
        restarted_server.abort();
    }

    #[tokio::test]
    async fn udp_bootstrap_bypasses_even_a_greedy_direct_handler() {
        let probe = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let bind = probe.local_addr().unwrap();
        drop(probe);
        let server = tokio::spawn(run(UdpConfig {
            bind,
            direct_handler: Some(Arc::new(GreedyDirect)),
            ..UdpConfig::default()
        }));
        tokio::time::sleep(Duration::from_millis(10)).await;
        let client = UdpClient::connect(
            "127.0.0.1:0".parse().unwrap(),
            bind,
            quic_lite::ConnectionId::new(17).unwrap(),
        )
        .await
        .expect("bootstrap must bypass direct handler");
        assert!(
            client
                .peer_connection_id()
                .is_some_and(|cid| cid.value() != 0)
        );
        server.abort();
    }

    #[tokio::test]
    async fn udp_bootstrap_keeps_waiting_after_connectionless_discovery() {
        let server_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer = server_socket.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let mut inbound = [0u8; MTU];
            let (received, client) = server_socket.recv_from(&mut inbound).await.unwrap();
            let (_, open) =
                quic_lite::decode_bootstrap_open_packet_with_limits(&inbound[..received]).unwrap();

            let mut direct = [0u8; MTU];
            let direct_len =
                crate::direct::ConnectionlessMessage::encode(b"discovery", &mut direct).unwrap();
            server_socket
                .send_to(&direct[..direct_len], client)
                .await
                .unwrap();

            let mut ack = [0u8; MTU];
            let ack_len = quic_lite::encode_bootstrap_open_ack_packet_with_limits(
                open.client_receive_cid,
                ConnectionId::new(0x7788).unwrap(),
                0,
                ConnectionLimits::default(),
                &mut ack,
            )
            .unwrap();
            server_socket
                .send_to(&ack[..ack_len], client)
                .await
                .unwrap();
        });

        let local_cid = ConnectionId::new(0x6677).unwrap();
        let client_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let client = UdpClient::connect_with_socket_via(
            client_socket,
            peer,
            local_cid,
            512,
            ConnectionLimits::default(),
            None,
            None,
        )
        .await
        .expect("connectionless discovery must not consume the OPEN ACK wait");
        assert_eq!(
            client.peer_connection_id(),
            Some(ConnectionId::new(0x7788).unwrap())
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn udp_rejects_stream_only_record_before_direct_handler() {
        let probe = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let bind = probe.local_addr().unwrap();
        drop(probe);
        let direct = Arc::new(CountingDirect::default());
        let server = tokio::spawn(run(UdpConfig {
            bind,
            direct_handler: Some(direct.clone()),
            ..UdpConfig::default()
        }));
        tokio::time::sleep(Duration::from_millis(10)).await;

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut payload = [0u8; 32];
        let payload_len =
            crate::tagged::encode_numeric_empty_request(7, 1, 9, &mut payload).unwrap();
        let mut packet = [0u8; 64];
        let packet_len =
            crate::direct::ConnectionlessMessage::encode(&payload[..payload_len], &mut packet)
                .unwrap();
        client.send_to(&packet[..packet_len], bind).await.unwrap();
        let mut response = [0u8; 64];
        assert!(
            timeout(Duration::from_millis(50), client.recv_from(&mut response))
                .await
                .is_err()
        );
        assert_eq!(direct.0.load(Ordering::Relaxed), 0);
        server.abort();
    }

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
    fn active_scheduler_honors_sub_millisecond_transport_deadline() {
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
    fn active_unpaced_probe_never_falls_back_to_idle_50ms_tick() {
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
    fn probe_request_ack_policy_is_scoped_to_the_tagged_request() {
        assert_eq!(
            probe_ack_policy(ProbeServiceRequest::new(1024, 1200)),
            (2, RECOVERY_MAX_ACK_DELAY_US)
        );
        let mut request = ProbeServiceRequest::new(1024, 1200);
        request.ack_frequency = Some(8);
        request.ack_delay_ms = Some(1);
        assert_eq!(probe_ack_policy(request), (8, 1_000));
        request.ack_frequency = Some(u8::MAX);
        assert_eq!(
            probe_ack_policy(request).0,
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
    fn probe_send_gap_bins_have_the_compact_numeric_order() {
        assert_eq!(interpacket_gap_bucket(Duration::from_micros(999)), 0);
        assert_eq!(interpacket_gap_bucket(Duration::from_micros(1_000)), 1);
        assert_eq!(interpacket_gap_bucket(Duration::from_micros(5_000)), 2);
        assert_eq!(interpacket_gap_bucket(Duration::from_micros(10_000)), 3);
        assert_eq!(interpacket_gap_bucket(Duration::from_micros(25_000)), 4);
        assert_eq!(interpacket_gap_bucket(Duration::from_micros(50_000)), 5);
    }
    use crate::verified_object::{
        BLOCK_SIZE, ImageManifest, ImageSink, RECORD_BLOB, RECORD_MANIFEST, encode_get_request,
    };
    use quic_lite::callback::{CallbackStreams, CopyingStreamEvents};
    use quic_lite::{
        ConnectionId, EndpointState, FIRST_CLIENT_BIDI_STREAM_ID, FLAG_FIXED, Frame, ShortHeader,
    };
    use std::format;
    use std::string::String;
    use std::sync::Arc;
    use std::vec;
    use tempfile::tempdir;

    // Host-side constrained consumer profile. These are injected storage and
    // parser capacities, not a Recovery or QUIC transport constant.
    const TEST_MANIFEST_CAPACITY: usize = 20 * 1024;
    const TEST_DATA_RECORD_CAPACITY: usize = 12 + BLOCK_SIZE;
    const TEST_SINK_WINDOW_BYTES: usize = 4 * BLOCK_SIZE;
    // This deliberately generous callback/reordering budget belongs only to
    // the host UDP download matrix. The verified-object consumer advertises
    // its exact current parser/storage window dynamically; production code
    // must not reuse this worst-case sum as initial peer credit.
    const TEST_OBJECT_RECEIVE_WINDOW: usize =
        TEST_MANIFEST_CAPACITY + TEST_DATA_RECORD_CAPACITY + TEST_SINK_WINDOW_BYTES;
    const TEST_DOWNLOAD_HISTORY_CEILING: usize = 64;
    const TEST_DOWNLOAD_HISTORY: usize = 32;
    const TEST_DOWNLOAD_REORDER_BYTES: usize = 64 * MTU;

    struct FakeFlash {
        bytes: Vec<u8>,
    }

    #[test]
    fn two_connections_register_and_report_multiple_service_streams() {
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
            for (stream_id, method) in [
                (4u64, crate::services::DIAGNOSTIC_STATUS_METHOD),
                (8, crate::services::DIAGNOSTIC_STATUS_METHOD),
                (16, crate::services::DIAGNOSTIC_METRICS_METHOD),
                (20, crate::services::DIAGNOSTIC_EVENTS_METHOD),
            ] {
                client
                    .open_send_stream(stream_id, INITIAL_MAX_STREAM_DATA)
                    .unwrap();
                let mut packet = [0u8; MTU];
                let request = diagnostic_request(method, stream_id);
                let (used, _) = client
                    .encode_stream_packet(server_cid, stream_id, 0, true, &request, &mut packet)
                    .unwrap();
                let quic_lite::TransportPacket::Stream { frame, .. } =
                    server.receive_datagram(&packet[..used]).unwrap()
                else {
                    panic!("expected service stream");
                };
                let response = crate::services::dispatch_diagnostic_tagged_stream(
                    &server,
                    None,
                    server.local_connection_id().unwrap(),
                    stream_id,
                    &frame.data,
                )
                .unwrap();
                let response_text = diagnostic_text(&response);
                assert!(response_text.contains(&format!("connection_dcid={server_value}")));
                assert!(response_text.contains(&format!("stream_id={stream_id}")));
                if method == crate::services::DIAGNOSTIC_METRICS_METHOD {
                    assert!(response_text.contains("slow_start_threshold="));
                    assert!(response_text.contains("max_streams_bidi="));
                } else if method == crate::services::DIAGNOSTIC_EVENTS_METHOD {
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
        let connections = ConnectionTable::<UdpConnectionRoute, MAX_ACTIVE_CONNECTIONS, 1>::new([
            PathState::new(),
        ]);
        let next = NEXT_SERVER_CID.load(Ordering::Relaxed);
        let avoid = ConnectionId::new(next & ConnectionId::MAX_VALUE).unwrap();
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

        let (release_server, keep_server) = tokio::sync::oneshot::channel();
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
            // Retain the ephemeral port through every client retry. Dropping
            // it here lets another parallel UDP test rebind the same port and
            // accidentally answer this client's later OPEN with a valid ACK.
            let _ = keep_server.await;
        });
        let result = UdpClient::connect(
            "127.0.0.1:0".parse().unwrap(),
            server_addr,
            ConnectionId::new(7).unwrap(),
        )
        .await;
        let _ = release_server.send(());
        assert!(result.is_err());
        task.await.unwrap();
    }

    #[tokio::test]
    async fn udp_connect_retries_open_after_loss() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let mut input = [0u8; MTU];
            let (first_len, source) = server.recv_from(&mut input).await.unwrap();
            let first_client = decode_bootstrap_open(&input[..first_len]).unwrap();
            assert_ne!(first_client.value(), 0);
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
            client.endpoint().peer_connection_id(),
            Some(ConnectionId::new(0xe3).unwrap())
        );
        task.await.unwrap();
    }

    #[test]
    fn udp_path_id_ignores_local_ipv6_link_local_scope() {
        let address: std::net::Ipv6Addr = "fe80::44".parse().unwrap();
        let on_br_lan = SocketAddr::V6(std::net::SocketAddrV6::new(address, 3339, 0, 5));
        let on_wlan = SocketAddr::V6(std::net::SocketAddrV6::new(address, 3339, 0, 7));

        assert_eq!(udp_path_id(on_br_lan), udp_path_id(on_wlan));
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
        let path = udp_path_id(server_addr);
        let mut client = UdpClient {
            socket: Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap()),
            ingress: None,
            peer: server_addr,
            connection: established_client_connection(local, peer, path),
            path,
            quic_lite_wire_dcid: None,
            deferred_receive_credit: false,
        };
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
        assert_eq!(client.connection.active_path(), Some(path));
        assert_eq!(client.connection.known_paths()[0], Some(path));
        task.await.unwrap();
    }

    #[tokio::test]
    async fn udp_client_ignores_delayed_completed_response_before_next_call() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();
        let local = ConnectionId::new(1).unwrap();
        let peer = ConnectionId::new(2).unwrap();
        let path = udp_path_id(server_addr);
        let mut client = UdpClient {
            socket: Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap()),
            ingress: None,
            peer: server_addr,
            connection: established_client_connection(local, peer, path),
            path,
            quic_lite_wire_dcid: None,
            deferred_receive_credit: false,
        };
        let first = ReceivedStream {
            id: quic_lite::FIRST_SERVER_BIDI_STREAM_ID,
            offset: 0,
            fin: true,
            data: vec![1],
        };
        assert!(
            client
                .connection
                .accept_server_response_stream(first.id, first.fin)
                .unwrap()
        );
        // A peer may retransmit this final response after the client has
        // already ACKed it. It is not the next request's result.
        assert!(
            !client
                .connection
                .accept_server_response_stream(first.id, first.fin)
                .unwrap()
        );
        let next = ReceivedStream {
            id: quic_lite::FIRST_SERVER_BIDI_STREAM_ID + 4,
            offset: 0,
            fin: true,
            data: vec![2],
        };
        assert!(
            client
                .connection
                .accept_server_response_stream(next.id, next.fin)
                .unwrap()
        );
    }

    #[tokio::test]
    async fn udp_client_send_stream_rejects_application_stream_response() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();
        let local = ConnectionId::new(1).unwrap();
        let peer = ConnectionId::new(2).unwrap();
        let path = udp_path_id(server_addr);
        let mut client = UdpClient {
            socket: Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap()),
            ingress: None,
            peer: server_addr,
            connection: established_client_connection(local, peer, path),
            path,
            quic_lite_wire_dcid: None,
            deferred_receive_credit: false,
        };
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

    impl crate::verified_object::StreamingImageSink for FakeFlash {
        fn poll_completed(&mut self) -> Result<crate::verified_object::StoragePoll, Self::Error> {
            Ok(crate::verified_object::StoragePoll::Ready)
        }
    }

    async fn run_object_transfer(size: usize, object_chunk: usize) {
        let directory = tempdir().unwrap();
        let artifact_root = directory.path().join("flash");
        let artifact = artifact_root.join("esp32c6/main-app.bin");
        std::fs::create_dir_all(artifact.parent().unwrap()).unwrap();
        let expected = (0..size).map(|n| (n % 251) as u8).collect::<Vec<_>>();
        std::fs::write(&artifact, &expected).unwrap();

        let mut request_body = [0u8; 96];
        // Exercise the real Main-flash request path.
        let request_len = encode_get_request(&mut request_body, 1, None, 13, 6).unwrap();
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
        let mut receiver =
            crate::verified_object::SignedObjectReceiver::<_, _, 10240, 4096>::new(FakeFlash {
                bytes: Vec::new(),
            });
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
            let mut data = data.as_slice();
            while !data.is_empty() {
                let used = receiver.push_ordered(data).unwrap();
                assert_ne!(used, 0);
                data = &data[used..];
            }
            if finished && !receiver.is_complete() {
                receiver.finish_ordered().unwrap();
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

    struct ObjectDownloadSink<'a> {
        receiver: &'a mut crate::verified_object::SignedObjectReceiver<
            FakeFlash,
            crate::verified_object::NoSignatureVerifier,
            10240,
            4096,
        >,
        bytes: usize,
    }

    impl CopyingStreamEvents for ObjectDownloadSink<'_> {
        type Error = ();

        fn stream_chunk(
            &mut self,
            stream: u64,
            _offset: u64,
            end: bool,
            bytes: &[u8],
        ) -> Result<usize, Self::Error> {
            if stream != OBJECT_STREAM {
                return Err(());
            }
            let used = self.receiver.push_ordered(bytes).map_err(|_| ())?;
            self.bytes = self.bytes.saturating_add(used);
            if end && used == bytes.len() && !self.receiver.is_complete() {
                self.receiver.finish_ordered().map_err(|_| ())?;
            }
            Ok(used)
        }
    }

    struct ObjectDownloadHarness {
        endpoint: EndpointState<2, TEST_DOWNLOAD_HISTORY_CEILING, MTU>,
        ordered: CallbackStreams<Arc<Vec<u8>>>,
        receiver: crate::verified_object::SignedObjectReceiver<
            FakeFlash,
            crate::verified_object::NoSignatureVerifier,
            10240,
            4096,
        >,
        drop_outbound_control: usize,
        /// Keep accepted application consumption pending until the harness timer runs;
        /// otherwise a lock-step test can hide a sender-waits-for-MAX_*
        /// deadlock when the initial receive window is exhausted.
        pending_application_consumption: usize,
        /// Optional storage barrier: ACK accepted bytes before completed
        /// records return their application storage credit.
        hold_credit_until_bootstrap: bool,
        delivered_stream_bytes: usize,
        timer_consumption_updates: usize,
        /// Bearer-only ACK/control latency. The stream callback and transport
        /// policy remain unchanged, so this models the measured Wi-Fi
        /// refill-cycle delay without inventing handler-side ACK logic.
        outbound_control_delay: Duration,
        /// Control waiting in the simulated bearer. Delaying a packet on the
        /// air must not suspend the receiver loop.
        pending_outbound: Vec<(Instant, Vec<u8>)>,
    }

    impl ObjectDownloadHarness {
        fn new() -> Self {
            Self {
                endpoint: EndpointState::<2, TEST_DOWNLOAD_HISTORY_CEILING, MTU>::new_with_history_capacity(
                    Role::Client,
                    ConnectionLimits {
                        max_data: TEST_OBJECT_RECEIVE_WINDOW as u64,
                        max_stream_data: TEST_OBJECT_RECEIVE_WINDOW as u64,
                        ..ConnectionLimits::default()
                    },
                    MTU as u64,
                    TEST_DOWNLOAD_HISTORY,
                ),
                // This is a generic host download receiver, deliberately
                // separate from the current host-opened Recovery upload path.
                ordered: CallbackStreams::new(2, TEST_DOWNLOAD_REORDER_BYTES),
                receiver: crate::verified_object::SignedObjectReceiver::new(FakeFlash {
                    bytes: Vec::new(),
                }),
                drop_outbound_control: 0,
                pending_application_consumption: 0,
                hold_credit_until_bootstrap: false,
                delivered_stream_bytes: 0,
                timer_consumption_updates: 0,
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

        async fn receive_one(
            &mut self,
            socket: &UdpSocket,
            peer: SocketAddr,
            packet: &[u8],
            now_ms: u64,
        ) -> Result<()> {
            self.flush_outbound(socket, peer).await?;
            // Match constrained receiver's receive loop: packet arrival advances the
            // transport clock before delayed ACK eligibility is evaluated.
            // Without this, a continuously nonempty host socket can leave a
            // mirror's ACK timer at its old value indefinitely.
            self.endpoint.set_time(now_ms);
            let mut transport_out = [0u8; MTU];
            let mut outputs: Vec<Vec<u8>> = Vec::new();
            let (endpoint, ordered, receiver) =
                (&mut self.endpoint, &mut self.ordered, &mut self.receiver);
            let mut released_credit = 0usize;
            let mut delivered_bytes = 0usize;
            endpoint
                .receive_with_committed_callback_dispositions(packet, |stream| {
                    let consumed = {
                        let mut sink = ObjectDownloadSink { receiver, bytes: 0 };
                        ordered
                            .receive_copying_borrowed(
                                stream.id,
                                stream.data,
                                stream.offset,
                                stream.fin,
                                || Arc::new(stream.data.to_vec()),
                                &mut sink,
                            )
                            .map_err(|_| quic_lite::Error::Invalid)?;
                        sink.bytes
                    };
                    if consumed != 0 {
                        delivered_bytes = delivered_bytes.saturating_add(consumed);
                        released_credit = released_credit.saturating_add(consumed);
                    }
                    Ok(if consumed == 0 {
                        CommittedStreamDisposition::Reack
                    } else {
                        // constrained download receiver first ACKs the drained burst, then
                        // returns credit only after its record storage is
                        // reusable. This catches a benchmark path that
                        // accidentally retains bootstrap credit forever.
                        CommittedStreamDisposition::Deferred
                    })
                })
                .map_err(|error| anyhow::anyhow!("object download harness input: {error:?}"))?;
            self.delivered_stream_bytes =
                self.delivered_stream_bytes.saturating_add(delivered_bytes);
            if let Some(used) = endpoint
                .poll_transmit(&mut transport_out)
                .map_err(|error| anyhow::anyhow!("object download harness ACK: {error:?}"))?
            {
                outputs.push(transport_out[..used].to_vec());
            }
            if released_credit != 0 {
                self.pending_application_consumption = self
                    .pending_application_consumption
                    .saturating_add(released_credit);
            }
            for output in outputs {
                self.queue_outbound(output);
            }
            self.flush_outbound(socket, peer).await?;
            Ok(())
        }

        /// Mirror constrained receiver's bounded `recvfrom` timeout.  Delayed ACKs and
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
            let storage_blocked = self.hold_credit_until_bootstrap
                // Hold one body block behind the injected storage barrier.
                && self.delivered_stream_bytes
                    < TEST_OBJECT_RECEIVE_WINDOW - BLOCK_SIZE;
            if !storage_blocked {
                let mut sink = ObjectDownloadSink {
                    receiver: &mut self.receiver,
                    bytes: 0,
                };
                self.ordered
                    .resume_copying(OBJECT_STREAM, &mut sink)
                    .map_err(|_| anyhow::anyhow!("object download resume"))?;
                self.delivered_stream_bytes =
                    self.delivered_stream_bytes.saturating_add(sink.bytes);
                self.pending_application_consumption = self
                    .pending_application_consumption
                    .saturating_add(sink.bytes);
            }
            let released_credit = if storage_blocked {
                0
            } else {
                core::mem::take(&mut self.pending_application_consumption)
            };
            if released_credit != 0 {
                self.timer_consumption_updates = self.timer_consumption_updates.saturating_add(1);
                self.endpoint
                    .stream_consumed_deferred(OBJECT_STREAM, released_credit)
                    .map_err(|error| {
                        anyhow::anyhow!("object download harness timer credit: {error:?}")
                    })?;
            }
            let mut output = [0u8; MTU];
            if let Some(used) = self
                .endpoint
                .poll_transmit(&mut output)
                .map_err(|error| anyhow::anyhow!("object download harness timer: {error:?}"))?
            {
                self.queue_outbound(output[..used].to_vec());
            }
            self.flush_outbound(socket, peer).await?;
            Ok(())
        }
    }

    #[derive(Debug, Default)]
    struct ObjectDownloadResult {
        /// Stream datagrams intentionally withheld before constrained receiver's
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
        /// was empty, so the constrained consumer had to report its ordinary
        /// application consumption from a timer turn.
        timer_consumption_updates: usize,
    }

    async fn run_object_download_harness(
        size: usize,
        object_chunk: usize,
        history_capacity: usize,
        ack_frequency: u8,
        drop_outbound_control: usize,
        drop_first_stream: bool,
        late_loss_burst: bool,
        drop_initial_alternate: bool,
        outbound_control_delay: Duration,
    ) -> ObjectDownloadResult {
        run_object_download_with_storage_barrier(
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

    async fn run_object_download_with_storage_barrier(
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
    ) -> ObjectDownloadResult {
        let directory = tempdir().unwrap();
        let artifact_root = directory.path().join("flash");
        let artifact = artifact_root.join("esp32c6/main-app.bin");
        std::fs::create_dir_all(artifact.parent().unwrap()).unwrap();
        let expected = (0..size).map(|n| (n % 251) as u8).collect::<Vec<_>>();
        std::fs::write(&artifact, &expected).unwrap();

        let mut request_body = [0u8; 96];
        let request_len = encode_get_request(&mut request_body, 1, None, 13, 6).unwrap();
        let probe = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let bind = probe.local_addr().unwrap();
        drop(probe);
        let control = Arc::new(TransportControl::default());
        let server_task = tokio::spawn(run(UdpConfig {
            bind,
            artifact_root,
            history_capacity,
            object_chunk,
            // Exercise the explicit constrained download receiver profile while the automatic
            // memory-policy tick is active. A regression must not widen the
            // four-packet service profile behind the test's back.
            ledger_memory: Some(LedgerMemorySnapshot {
                total_bytes: 512 * 1024 * 1024,
                available_bytes: 512 * 1024 * 1024,
            }),
            control: Some(control.clone()),
            ..UdpConfig::default()
        }));
        tokio::time::sleep(Duration::from_millis(10)).await;

        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_cid = ConnectionId::new(1).unwrap();
        let receiver_limits = ConnectionLimits {
            max_data: TEST_OBJECT_RECEIVE_WINDOW as u64,
            max_stream_data: TEST_OBJECT_RECEIVE_WINDOW as u64,
            ..ConnectionLimits::default()
        };
        let mut open = [0u8; MTU];
        let open_len = quic_lite::encode_bootstrap_open_packet_with_profile(
            client_cid,
            0,
            receiver_limits,
            TEST_DOWNLOAD_HISTORY as u16,
            &mut open,
        )
        .unwrap();
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
        let mut mirror = ObjectDownloadHarness::new();
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
        // The host suite runs several constrained download receiver fault profiles concurrently.
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
        let mut result = ObjectDownloadResult::default();
        while !mirror.receiver.is_complete() {
            if mirror.delivered_stream_bytes != last_delivered_bytes {
                last_delivered_bytes = mirror.delivered_stream_bytes;
                last_delivery = Instant::now();
            }
            assert!(
                last_delivery.elapsed() < Duration::from_secs(10),
                "object download harness made no delivery progress for 10 seconds after {mirror_datagrams} datagrams; delivered={} pending_credit={} credit={:?} client_stats={:?} server_stats={:?} server_errors={:?}",
                mirror.delivered_stream_bytes,
                mirror.pending_application_consumption,
                mirror.endpoint.receive_credit_state(OBJECT_STREAM),
                mirror.endpoint.stats(),
                control.server_stats(),
                control.take_errors(),
            );
            let remaining = deadline.saturating_duration_since(Instant::now());
            assert!(
                !remaining.is_zero(),
                "object download harness transfer timed out after {mirror_datagrams} datagrams; delivered={} pending_credit={}",
                mirror.delivered_stream_bytes,
                mirror.pending_application_consumption,
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
                        // frames transmitted, while constrained download receiver observes only
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
                        // constrained download receiver keeps its socket loop alive when the
                        // bounded callback credit rejects far-ahead data.
                        // Earlier selective ACKs make the sender repair the
                        // missing range; this is backpressure, not a session
                        // failure.
                        Err(error)
                            if error.to_string().contains("FlowControl")
                                || error.to_string().contains("Invalid") => {}
                        Err(error) => panic!("object download harness input failed: {error}"),
                    }
                }
                Ok(Err(error)) => panic!("object download harness receive failed: {error}"),
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
        result.timer_consumption_updates = mirror.timer_consumption_updates;
        result
    }

    #[tokio::test]
    async fn object_download_matrix_uses_injected_receiver_profiles() {
        for history_capacity in [2, 4, 16, 32] {
            // Exercise both the 512-byte diagnostic profile and the normal
            // MTU-friendly production profile.
            for object_chunk in [512, OBJECT_CHUNK] {
                let result = run_object_download_harness(
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
    async fn object_download_large_transfer_benchmark() {
        let size = 2_122_528;
        let started = Instant::now();
        let object_chunk = OBJECT_CHUNK;
        let result = run_object_download_harness(
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
            result.timer_consumption_updates != 0,
            "the constrained receiver must exercise timer-driven application consumption",
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
    async fn object_download_recovers_when_first_delayed_ack_is_lost() {
        // A 2 MiB image has a manifest larger than the initial congestion
        // window.  Drop the first timer-driven ACK exactly as Wi-Fi can; the
        // server must PTO a retained packet even though its history is not
        // yet full, then resume the same ordered response stream.
        let result = run_object_download_harness(
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
    async fn object_download_recovers_from_late_three_packet_loss_burst() {
        // Matches the device stall boundary: do not let a late selective-ACK
        // gap turn an otherwise healthy 2 MiB constrained download receiver transfer into silence.
        let result = run_object_download_harness(
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
    async fn object_download_reorders_one_stream_packet_with_bounded_credit() {
        // This mirrors the Wi-Fi fault that previously let the server send
        // roughly 256 KiB past a missing early range, overflowing constrained receiver's
        // callback buffer.  The receiver must advertise only its bounded
        // reorder budget and the sender must repair the gap.
        let result = run_object_download_harness(
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
    async fn object_download_delayed_ack_refills_without_spurious_retransmission() {
        // The live AP shows roughly one sender refill per ACK and recurrent
        // 10--25 ms gaps.  Model only that bearer delay: constrained download receiver continues
        // to use its normal callback, flow credit, and transport-owned ACK
        // policy. A contiguous delayed ACK must refill the sender without a
        // replacement stream packet or congestion-loss episode.
        let result = run_object_download_harness(
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
    async fn object_download_storage_barrier_acks_bootstrap_before_releasing_credit() {
        // Mirror MainSink's real-flash ordering: receive and ACK the whole
        // initial 76 KiB application window, withhold MAX_* while erase owns
        // the radio, then resume only through returned storage slots. This
        // must resume by the timer-driven MAX_* update rather than deadlock
        // below a partial record boundary.
        let result = run_object_download_with_storage_barrier(
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
        assert!(result.timer_consumption_updates > 0);
    }

    #[tokio::test]
    async fn object_download_recovers_after_a_full_window_of_lost_acks() {
        // This is the exact host-side analogue of a live sender retaining a
        // full 32-packet flight while constrained download receiver emits no usable ACKs. Once a
        // PTO probe reaches the receiver, duplicate re-ACK and normal window
        // refill must complete the stream; the connection may not wait for a
        // new application record or an external socket event.
        let result = run_object_download_harness(
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
    async fn object_download_recovers_from_initial_alternating_loss_burst() {
        // The fault is confined to the first 64 stream datagrams (32 drops).
        // 128 KiB leaves enough post-repair data to verify resumed progress
        // without making this host determinism gate compete with the larger
        // multi-megabyte constrained download receiver benchmark tests.
        let result = run_object_download_harness(
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
    fn object_download_window_fits_callback_reorder_budget() {
        const RECEIVER_PACKET_BUDGET: usize = TEST_DOWNLOAD_HISTORY_CEILING;
        const HOST_PAYLOAD_BYTES: usize = quic_lite::DEFAULT_MAX_DATAGRAM_SIZE;
        assert!(
            RECEIVER_PACKET_BUDGET * HOST_PAYLOAD_BYTES <= TEST_DOWNLOAD_REORDER_BYTES,
            "constrained download receiver callback reassembly must cover every outstanding host payload"
        );
        assert!(
            TEST_DOWNLOAD_HISTORY_CEILING >= RECEIVER_PACKET_BUDGET,
            "host retransmission ledger must cover constrained receiver's packet budget"
        );
        // Packet history and byte credit are independent. The object
        // consumer derives its initial window from its parser and sink
        // capacities; QUIC has no flash-record or fixed-slot policy.
        assert_eq!(
            TEST_OBJECT_RECEIVE_WINDOW,
            TEST_MANIFEST_CAPACITY + TEST_DATA_RECORD_CAPACITY + TEST_SINK_WINDOW_BYTES
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
        assert_eq!(
            client.endpoint().local_connection_id().unwrap().value(),
            0x55
        );
        assert_eq!(client.endpoint().next_packet_number, 1);
        let server_cid = client.endpoint().peer_connection_id().unwrap();
        assert_ne!(server_cid.value(), 0);
        assert_ne!(server_cid, client.endpoint().local_connection_id().unwrap());
        let response = request_diagnostic_text(
            &mut client,
            quic_lite::FIRST_CLIENT_BIDI_STREAM_ID,
            crate::services::DIAGNOSTIC_METRICS_METHOD,
        )
        .await;
        assert!(response.contains("metrics_version=2"));
        assert!(response.contains("history_capacity=2"));
        assert!(response.contains("next_packet_number=1"));
        server_task.abort();
    }

    #[tokio::test]
    async fn udp_listener_routes_outbound_association_on_its_own_socket() {
        let root = tempdir().unwrap();
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let bind = socket.local_addr().unwrap();
        let ingress = UdpClientIngress::new();
        let server_task = tokio::spawn(run(UdpConfig {
            bind,
            socket: Some(socket.clone()),
            client_ingress: Some(ingress.clone()),
            artifact_root: root.path().to_path_buf(),
            history_capacity: 2,
            ..UdpConfig::default()
        }));
        tokio::time::sleep(Duration::from_millis(10)).await;
        let mut client = UdpClient::connect_with_listener(
            socket.clone(),
            ingress,
            bind,
            ConnectionId::new(0x66).unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(client.socket.local_addr().unwrap(), bind);
        let response = request_diagnostic_text(
            &mut client,
            quic_lite::FIRST_CLIENT_BIDI_STREAM_ID,
            crate::services::DIAGNOSTIC_METRICS_METHOD,
        )
        .await;
        assert!(response.contains("metrics_version=2"));

        // A listener-owned socket must behave exactly like the private
        // diagnostic socket: opening an ordinary tagged stream cannot leave
        // the association unable to start a later normal probe stream.  This
        // is the host regression for lmesh keeping one association per
        // device while HTTP requests select different paths on it.
        let mut probe_request = [0u8; crate::probe::PROBE_RUN_REQUEST_MAX];
        let request_len = crate::probe::encode_probe_run_request(
            ProbeServiceRequest::new(4096, 512),
            2,
            &mut probe_request,
        )
        .unwrap();
        let (_, first, mut finished) = client
            .request_stream(
                quic_lite::FIRST_CLIENT_BIDI_STREAM_ID + 4,
                &probe_request[..request_len],
                true,
            )
            .await
            .unwrap();
        let mut bytes = first;
        while !finished {
            let (_, frame, frame_finished) = client.recv_stream().await.unwrap();
            bytes.extend_from_slice(&frame);
            finished = frame_finished;
        }
        assert_eq!(bytes.len(), 4096);

        // Completion does not pin the one producer slot. A later probe has a
        // new client stream but retains this association and listener socket.
        let request_len = crate::probe::encode_probe_run_request(
            ProbeServiceRequest::new(1024, 512),
            3,
            &mut probe_request,
        )
        .unwrap();
        let (_, first, mut finished) = client
            .request_stream(
                quic_lite::FIRST_CLIENT_BIDI_STREAM_ID + 8,
                &probe_request[..request_len],
                true,
            )
            .await
            .unwrap();
        let mut bytes = first;
        while !finished {
            let (_, frame, frame_finished) = client.recv_stream().await.unwrap();
            bytes.extend_from_slice(&frame);
            finished = frame_finished;
        }
        assert_eq!(bytes.len(), 1024);
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
        let metrics = request_diagnostic_text(
            &mut client,
            quic_lite::FIRST_CLIENT_BIDI_STREAM_ID,
            crate::services::DIAGNOSTIC_METRICS_METHOD,
        )
        .await;
        assert!(metrics.contains("history_capacity=16"));
        assert!(metrics.contains("history_storage_slots=16"));
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
            server_cids.push(client.endpoint().peer_connection_id().unwrap());
            let stream = quic_lite::FIRST_CLIENT_BIDI_STREAM_ID + index as u64 * 4;
            let metrics =
                request_diagnostic_text(client, stream, crate::services::DIAGNOSTIC_METRICS_METHOD)
                    .await;
            assert!(metrics.contains("metrics_version=2"));
            let event_stream = stream + 4;
            let events = request_diagnostic_text(
                client,
                event_stream,
                crate::services::DIAGNOSTIC_EVENTS_METHOD,
            )
            .await;
            assert!(events.contains("events_version="));
            assert!(events.contains("events="));
            let probe_stream = event_stream + 4;
            let mut probe_request = [0u8; crate::probe::PROBE_RUN_REQUEST_MAX];
            let probe_request_len = crate::probe::encode_probe_run_request(
                ProbeServiceRequest::new(4096, 512),
                1,
                &mut probe_request,
            )
            .unwrap();
            let (_, first, mut probe_finished) = client
                .request_stream(probe_stream, &probe_request[..probe_request_len], true)
                .await
                .unwrap();
            let mut probe = first;
            while !probe_finished {
                let (_, bytes, finished) = client.recv_stream().await.unwrap();
                probe.extend_from_slice(&bytes);
                probe_finished = finished;
            }
            assert_eq!(probe.len(), 4096);
            let mut offset = 0usize;
            let mut packet_id = 0u32;
            while offset < probe.len() {
                let used = (probe.len() - offset).min(512);
                assert_eq!(
                    u32::from_be_bytes(probe[offset..offset + 4].try_into().unwrap()),
                    packet_id,
                );
                assert!(
                    probe[offset + 4..offset + used]
                        .iter()
                        .enumerate()
                        .all(|(index, byte)| { *byte == (offset + 4 + index) as u8 })
                );
                offset += used;
                packet_id = packet_id.wrapping_add(1);
            }
            let registry_stream = probe_stream + 4;
            let registry_request =
                diagnostic_request(crate::services::DIAGNOSTIC_SERVICES_METHOD, registry_stream);
            let (_, registry_response, _) = client
                .request_stream(registry_stream, &registry_request, true)
                .await
                .unwrap();
            let registry_record = crate::tagged::decode(&registry_response).unwrap();
            let registry = registry_record.result.unwrap();
            // `services` is compact CBOR
            // `[[component, method, name], ...]`, not a text command surface.
            assert_eq!(registry.first(), Some(&0x8a));
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
        let first_metrics = request_diagnostic_text(
            &mut first,
            FIRST_CLIENT_BIDI_STREAM_ID,
            crate::services::DIAGNOSTIC_METRICS_METHOD,
        )
        .await;
        assert!(first_metrics.contains("metrics_version=2"));
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
        let second_metrics = request_diagnostic_text(
            &mut second,
            FIRST_CLIENT_BIDI_STREAM_ID,
            crate::services::DIAGNOSTIC_METRICS_METHOD,
        )
        .await;
        assert!(second_metrics.contains("metrics_version=2"));
        server_task.abort();
    }

    #[tokio::test]
    async fn udp_probe_honors_recovery_bootstrap_credit_before_first_ack() {
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
            max_data: TEST_OBJECT_RECEIVE_WINDOW as u64,
            max_stream_data: TEST_OBJECT_RECEIVE_WINDOW as u64,
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
        let mut request = [0u8; crate::probe::PROBE_RUN_REQUEST_MAX];
        let request_len = crate::probe::encode_probe_run_request(
            ProbeServiceRequest::new(120_000, 1200),
            1,
            &mut request,
        )
        .unwrap();
        let (_, first, mut finished) = client
            .request_stream(4, &request[..request_len], true)
            .await
            .unwrap();
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
        let server_cid = legitimate.endpoint().peer_connection_id().unwrap();

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
        let attacker_request = diagnostic_request(crate::services::DIAGNOSTIC_METRICS_METHOD, 4);
        let (used, _) = endpoint
            .encode_stream_packet(server_cid, 4, 0, true, &attacker_request, &mut packet)
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

        let metrics = request_diagnostic_text(
            &mut legitimate,
            quic_lite::FIRST_CLIENT_BIDI_STREAM_ID,
            crate::services::DIAGNOSTIC_METRICS_METHOD,
        )
        .await;
        assert!(metrics.contains("metrics_version=2"));
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
        let server_cid = client.endpoint().peer_connection_id().unwrap();
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

        let metrics = request_diagnostic_text(
            &mut client,
            quic_lite::FIRST_CLIENT_BIDI_STREAM_ID,
            crate::services::DIAGNOSTIC_METRICS_METHOD,
        )
        .await;
        assert!(metrics.contains("metrics_version=2"));
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
        let metrics = request_diagnostic_text(
            &mut first,
            quic_lite::FIRST_CLIENT_BIDI_STREAM_ID,
            crate::services::DIAGNOSTIC_METRICS_METHOD,
        )
        .await;
        assert!(metrics.contains("metrics_version=2"));
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
        let metrics = request_diagnostic_text(
            &mut surviving,
            quic_lite::FIRST_CLIENT_BIDI_STREAM_ID,
            crate::services::DIAGNOSTIC_METRICS_METHOD,
        )
        .await;
        assert!(metrics.contains("metrics_version=2"));
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
        let server_cid = client.endpoint().peer_connection_id().unwrap();
        client.endpoint_mut().close(0x77);
        let mut close = [0u8; MTU];
        let close_len = client
            .endpoint_mut()
            .poll_close(&mut close)
            .unwrap()
            .unwrap();
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
        let get_len = encode_get_request(&mut request, 1, None, 13, 6).unwrap();
        let (stream_id, first, fin) = client
            .request_stream(
                quic_lite::FIRST_CLIENT_BIDI_STREAM_ID,
                &request[..get_len],
                true,
            )
            .await
            .unwrap();
        assert!(!fin);
        assert_eq!(stream_id, OBJECT_STREAM);
        let mut object = first;
        let mut saw_fin = false;
        for _ in 0..16 {
            let (id, data, finished) = client.recv_stream().await.unwrap();
            assert_eq!(id, OBJECT_STREAM);
            object.extend_from_slice(&data);
            if finished {
                saw_fin = true;
                break;
            }
        }
        assert!(saw_fin);
        let (manifest, used) = ImageManifest::decode_prefix(&object).unwrap();
        assert_eq!(object.len() - used, manifest.image_size as usize);
        server_task.abort();
    }

    /// Repeatable host-to-host UDP PROBE measurement. It deliberately drives
    /// the production `run` listener and `UdpClient` through localhost, so it
    /// catches scheduler, ACK, flow-credit, and socket regressions without a
    /// shell-launched service or a Wi-Fi device. Keep it ignored: throughput
    /// is host-load dependent, while the printed conditions are the fast
    /// iteration signal. It never starts or restarts lmesh/lmesh-wifi.
    #[tokio::test]
    #[ignore = "explicit UDP PROBE throughput measurement"]
    async fn udp_probe_loopback_measurement() {
        let bytes = std::env::var("DMESH_PROBE_BYTES")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(64 * 1024);
        let packet_size = std::env::var("DMESH_PROBE_PACKET_SIZE")
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
        let mut request = [0u8; crate::probe::PROBE_RUN_REQUEST_MAX];
        let request_len = crate::probe::encode_probe_run_request(
            ProbeServiceRequest::new(bytes, packet_size),
            1,
            &mut request,
        )
        .unwrap();
        let started = Instant::now();
        let (_, first, mut fin) = client
            .request_stream(FIRST_CLIENT_BIDI_STREAM_ID, &request[..request_len], true)
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
                    "UDP PROBE receive timeout bytes={received} server_stats={stats:?} errors={errors:?}"
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
            "host-host udp-probe bytes={received} elapsed_us={} first_response_us={first_response_us} bps={bps} history=512 packet={packet_size} deferred_receive_credit=true server_stats={server_stats:?}",
            elapsed.as_micros(),
        );
        assert_eq!(received, bytes);
        server_task.abort();
    }

    #[test]
    fn object_request_is_a_correlated_tagged_handler() {
        let mut encoded = [0u8; 96];
        let used = encode_get_request(&mut encoded, 17, None, 13, 6).unwrap();
        assert_eq!(
            object_request(&encoded[..used]).unwrap(),
            crate::verified_object::GetRequest {
                name: None,
                cpu: 13,
                target: 6,
            }
        );
        assert!(object_request(&[1, 0xa2, 0x01, 0x0d, 0x02, 0x06]).is_err());
    }

    #[derive(Debug)]
    struct AsyncTaggedEcho;

    impl TaggedStreamHandler for AsyncTaggedEcho {
        fn handle<'a>(
            &'a self,
            _context: TaggedStreamContext,
            request: Vec<u8>,
        ) -> Pin<Box<dyn Future<Output = Option<Vec<u8>>> + Send + 'a>> {
            Box::pin(async move { request.starts_with(b"tagged:").then_some(request) })
        }
    }

    #[derive(Debug)]
    struct AsyncTaggedLarge;

    impl TaggedStreamHandler for AsyncTaggedLarge {
        fn handle<'a>(
            &'a self,
            _context: TaggedStreamContext,
            request: Vec<u8>,
        ) -> Pin<Box<dyn Future<Output = Option<Vec<u8>>> + Send + 'a>> {
            Box::pin(async move {
                request.starts_with(b"tagged:").then(|| {
                    let mut response = Vec::with_capacity(MTU * 20);
                    while response.len() < MTU * 20 {
                        response.extend_from_slice(&request);
                    }
                    response.truncate(MTU * 20);
                    response
                })
            })
        }
    }

    #[derive(Debug)]
    struct FixedTaggedApplication(Vec<u8>);

    impl TaggedApplicationHandler for FixedTaggedApplication {
        fn handle_tagged<'a>(
            &'a self,
            _context: TaggedStreamContext,
            _request: Vec<u8>,
        ) -> Pin<Box<dyn Future<Output = Option<Vec<u8>>> + Send + 'a>> {
            Box::pin(async move { Some(self.0.clone()) })
        }
    }

    fn tagged_test_context() -> TaggedStreamContext {
        TaggedStreamContext {
            peer: "127.0.0.1:3339".parse().unwrap(),
        }
    }

    #[tokio::test]
    async fn canonical_tagged_handler_requires_a_correlated_terminal_response() {
        // {1: 1, 2: 2, 3: 7}
        let request = vec![0xa3, 1, 1, 2, 2, 3, 7];

        // {1: 1, 2: 2, 3: 7, 6: {}}
        let response = vec![0xa4, 1, 1, 2, 2, 3, 7, 6, 0xa0];
        let handler =
            CanonicalTaggedStreamHandler::new(Arc::new(FixedTaggedApplication(response.clone())));
        assert_eq!(
            handler.handle(tagged_test_context(), request.clone()).await,
            Some(response)
        );

        // A different id, routing destination, missing terminal value, or both
        // result and error are never admitted as the stream's response.
        for rejected in [
            vec![0xa4, 1, 1, 2, 2, 3, 8, 6, 0xa0],
            vec![0xa5, 1, 1, 2, 2, 3, 7, 6, 0xa0, 9, 0x62, b'e', b'7'],
            vec![0xa3, 1, 1, 2, 2, 3, 7],
            vec![0xa5, 1, 1, 2, 2, 3, 7, 6, 0xa0, 7, 0x61, b'x'],
        ] {
            let handler =
                CanonicalTaggedStreamHandler::new(Arc::new(FixedTaggedApplication(rejected)));
            assert_eq!(
                handler.handle(tagged_test_context(), request.clone()).await,
                None
            );
        }
    }

    #[tokio::test]
    async fn canonical_tagged_handler_rejects_malformed_or_uncorrelated_requests() {
        let response = vec![0xa4, 1, 1, 2, 2, 3, 7, 6, 0xa0];
        let handler = CanonicalTaggedStreamHandler::new(Arc::new(FixedTaggedApplication(response)));
        assert_eq!(
            handler
                .handle(tagged_test_context(), b"not-cbor".to_vec())
                .await,
            None
        );
        // {1: 1, 2: 2}: a valid tagged request, but without an id.
        assert_eq!(
            handler
                .handle(tagged_test_context(), vec![0xa2, 1, 1, 2, 2])
                .await,
            None
        );
    }

    #[tokio::test]
    async fn udp_quic_stream_uses_async_tagged_handler() {
        let root = tempdir().unwrap();
        let probe = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let bind = probe.local_addr().unwrap();
        drop(probe);
        let server_task = tokio::spawn(run(UdpConfig {
            bind,
            artifact_root: root.path().to_path_buf(),
            tagged_handler: Some(Arc::new(AsyncTaggedEcho)),
            ..UdpConfig::default()
        }));
        tokio::time::sleep(Duration::from_millis(10)).await;
        let mut client = UdpClient::connect(
            "127.0.0.1:0".parse().unwrap(),
            bind,
            ConnectionId::new(0x5a5).unwrap(),
        )
        .await
        .unwrap();
        let request = b"tagged:normal-quic-stream";
        let (stream, response, fin) = client
            .request_stream(FIRST_CLIENT_BIDI_STREAM_ID, request, true)
            .await
            .unwrap();
        assert_eq!(stream, quic_lite::FIRST_SERVER_BIDI_STREAM_ID);
        assert!(fin);
        assert_eq!(response, request);
        server_task.abort();
    }

    #[tokio::test]
    async fn udp_quic_stream_reassembles_a_multi_datagram_tagged_response() {
        let root = tempdir().unwrap();
        let probe = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let bind = probe.local_addr().unwrap();
        drop(probe);
        let server_task = tokio::spawn(run(UdpConfig {
            bind,
            artifact_root: root.path().to_path_buf(),
            tagged_handler: Some(Arc::new(AsyncTaggedLarge)),
            ..UdpConfig::default()
        }));
        tokio::time::sleep(Duration::from_millis(10)).await;
        let mut client = UdpClient::connect(
            "127.0.0.1:0".parse().unwrap(),
            bind,
            ConnectionId::new(0x5a6).unwrap(),
        )
        .await
        .unwrap();
        let request = b"tagged:large-terminal-response";
        let response = client
            .request_stream_all(FIRST_CLIENT_BIDI_STREAM_ID, request, true, MTU * 20)
            .await
            .unwrap();
        assert_eq!(response.len(), MTU * 20);
        assert_eq!(&response[..request.len()], request);
        server_task.abort();
    }

    #[tokio::test]
    async fn udp_quic_stream_dispatches_tagged_connection_status() {
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
            ConnectionId::new(0x5b5).unwrap(),
        )
        .await
        .unwrap();
        let mut request = [0u8; 32];
        let request_len = crate::tagged::encode_numeric_empty_request(
            crate::services::DIAGNOSTIC_COMPONENT,
            crate::services::DIAGNOSTIC_STATUS_METHOD,
            81,
            &mut request,
        )
        .unwrap();
        let (_, response, fin) = client
            .request_stream(FIRST_CLIENT_BIDI_STREAM_ID, &request[..request_len], true)
            .await
            .unwrap();
        assert!(fin);
        let record = crate::tagged::decode(&response).unwrap();
        assert_eq!(record.id, Some(81));
        let mut result = crate::cbor::Decoder::new(record.result.unwrap());
        assert!(result.text_ref().unwrap().starts_with(b"status_version=1;"));
        assert!(result.is_finished());
        server_task.abort();
    }
}
