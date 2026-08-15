//! Feature-gated host UDP QUIC server and connection/mux harness.
//!
//! UDP is the datagram bearer. The first packet creates a connection keyed by
//! its opaque DCID; subsequent packets are routed to that connection. Stream
//! services run above the endpoint. The object store is the production service
//! currently installed here, while the same connection table is intended for
//! additional host-test services on other stream IDs.

pub use crate::handlers::{StreamHandler, StreamRegistry};
use crate::ledger::{
    select_capacity, system_memory_snapshot, LedgerCapacityController, LedgerMemoryPolicy,
    LedgerMemorySnapshot,
};
use crate::mux::StreamMux;
use crate::{ConnectionLimits, EndpointState, Role, INITIAL_MAX_STREAM_DATA};
use anyhow::{bail, Context, Result};
use dmesh_object_store::{ObjectServer, ServerConfig, RECORD_DONE, RECORD_MANIFEST};
use std::boxed::Box;
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::string::ToString;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::vec::Vec;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time::{timeout, Duration, Instant};

const MTU: usize = 1400;
// Keep Recovery object datagrams below the Wi-Fi driver's large-frame edge
// while retaining normal UDP/IP overhead. This is deliberately independent
// of the bearer MTU: object transfer favors reliable small frames over
// packing a whole 4 KiB record into three large Wi-Fi aggregates.
const OBJECT_CHUNK: usize = 512;
const MAX_OBJECT_CHUNK: usize = MTU - 64;
const UDP_MIN_RETRANSMIT_PTO_MS: u64 = 250;
/// One ordered object-response stream: manifest, blobs, then done.
const OBJECT_STREAM: u64 = 3;
const ACK_TIMEOUT: Duration = Duration::from_millis(500);
const BOOTSTRAP_ATTEMPTS: u32 = 4;
const STREAM_ATTEMPTS: u32 = 4;
const MAX_ACTIVE_CONNECTIONS: usize = 64;
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);
static NEXT_SERVER_CID: AtomicU64 = AtomicU64::new(0x100);

/// First byte on an application stream selects the connection service.
/// Remaining bytes belong to that service's schema.
pub use crate::{
    SERVICE_CONTROL, SERVICE_ECHO, SERVICE_EVENTS, SERVICE_IPERF, SERVICE_METRICS,
    SERVICE_OBJECT, SERVICE_STATUS, SERVICE_STREAM,
};

const CONTROL_LOG: u8 = 0;
const CONTROL_POLL: u8 = 1;
const CONTROL_RESPONSE: u8 = 2;
const CONTROL_QUEUE_CAPACITY: usize = 64;

/// Bounded command/log bridge for a transport test scaffold or a future
/// managed control service. Its contents are opaque compact CBOR records;
/// only Recovery's shared command parser interprets commands.
#[derive(Debug, Default)]
pub struct TransportControl {
    commands: Mutex<VecDeque<Vec<u8>>>,
    logs: Mutex<VecDeque<Vec<u8>>>,
}

impl TransportControl {
    pub fn queue_command(&self, record: Vec<u8>) {
        let mut commands = self.commands.lock().expect("control commands lock");
        if commands.len() == CONTROL_QUEUE_CAPACITY { commands.pop_front(); }
        commands.push_back(record);
    }

    pub fn take_log(&self) -> Option<Vec<u8>> {
        self.logs.lock().expect("control logs lock").pop_front()
    }

    fn receive_log(&self, record: &[u8]) {
        let mut logs = self.logs.lock().expect("control logs lock");
        if logs.len() == CONTROL_QUEUE_CAPACITY { logs.pop_front(); }
        logs.push_back(record.to_vec());
    }

    fn next_response(&self) -> Vec<u8> {
        let command = self.commands.lock().expect("control commands lock").pop_front();
        let mut response = Vec::with_capacity(2 + command.as_ref().map_or(0, Vec::len));
        response.push(SERVICE_CONTROL);
        response.push(CONTROL_RESPONSE);
        if let Some(command) = command { response.extend_from_slice(&command); }
        response
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
    records: Vec<(u8, Vec<u8>)>,
    record_index: usize,
    current: Vec<u8>,
    current_kind: u8,
    current_offset: usize,
    stream_offset: u64,
    sent_bytes: usize,
    chunk_size: usize,
}

/// Transport-only response source for IPERF. It deliberately has no object
/// record header, manifest, store lookup, or flash semantics.
struct PendingByteTransfer {
    stream_id: u64,
    offset: u64,
    remaining: usize,
    chunk_size: usize,
    packet_id: u32,
}

impl PendingByteTransfer {
    fn new(stream_id: u64, bytes: usize, chunk_size: usize) -> Self {
        Self { stream_id, offset: 0, remaining: bytes, chunk_size, packet_id: 0 }
    }
}

impl PendingObjectTransfer {
    fn new(records: Vec<(u8, Vec<u8>)>) -> Self {
        Self::with_chunk(records, OBJECT_CHUNK)
    }

    fn with_chunk(records: Vec<(u8, Vec<u8>)>, chunk_size: usize) -> Self {
        assert!((1..=MAX_OBJECT_CHUNK).contains(&chunk_size));
        Self {
            records,
            record_index: 0,
            current: Vec::new(),
            current_kind: RECORD_MANIFEST,
            current_offset: 0,
            stream_offset: 0,
            sent_bytes: 0,
            chunk_size,
        }
    }

    fn load_current(&mut self) -> bool {
        if !self.current.is_empty() {
            return true;
        }
        let Some((kind, body)) = self.records.get(self.record_index) else {
            return false;
        };
        self.current_kind = *kind;
        self.current.clear();
        self.current.reserve(5 + body.len());
        self.current.push(*kind);
        self.current
            .extend_from_slice(&(body.len() as u32).to_be_bytes());
        self.current.extend_from_slice(body);
        self.current_offset = 0;
        true
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
    /// the transport window: 512-byte records must still be sent in flight as
    /// a window, not as stop-and-wait packets.
    pub object_chunk: usize,
    /// Optional opaque Recovery command/log mailbox. Normal object serving
    /// leaves it unset; host hardware tests can install it on a third port.
    pub control: Option<Arc<TransportControl>>,
}

impl Default for UdpConfig {
    fn default() -> Self {
        Self {
            bind: "0.0.0.0:3336".parse().unwrap(),
            artifact_root: PathBuf::from("."),
            history_capacity: 0,
            ledger_memory_policy: LedgerMemoryPolicy::default(),
            ledger_memory: None,
            max_active_connections: MAX_ACTIVE_CONNECTIONS,
            idle_timeout: IDLE_TIMEOUT,
            receive_timeout: Duration::from_secs(1),
            ledger_resize_interval: Duration::from_secs(5),
            object_chunk: OBJECT_CHUNK,
            control: None,
        }
    }
}

/// Minimal host client for the feature-gated UDP QUIC bearer. It owns one
/// transport connection and exposes only datagram/stream operations; service
/// schemas remain above this type.
pub struct UdpClient {
    socket: UdpSocket,
    peer: SocketAddr,
    endpoint: EndpointState<8, 512>,
    local_cid: crate::ConnectionId,
}

impl UdpClient {
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
        local_cid: crate::ConnectionId,
    ) -> Result<Self> {
        Self::connect_with_history_capacity(bind, peer, local_cid, 512).await
    }

    pub async fn connect_with_history_capacity(
        bind: SocketAddr,
        peer: SocketAddr,
        local_cid: crate::ConnectionId,
        history_capacity: usize,
    ) -> Result<Self> {
        if local_cid.value() == 0 {
            bail!("bootstrap local CID must be non-zero");
        }
        if !(1..=512).contains(&history_capacity) {
            bail!("UDP history capacity must be in 1..=512");
        }
        let socket = UdpSocket::bind(bind).await?;
        let mut client = Self {
            socket,
            peer,
            endpoint: EndpointState::new_with_history_capacity(
                Role::Client,
                ConnectionLimits::default(),
                MTU as u64,
                history_capacity,
            ),
            local_cid: local_cid,
        };
        let mut response = [0u8; MTU];
        for packet_number in 0..BOOTSTRAP_ATTEMPTS {
            let mut open = [0u8; MTU];
            let used = encode_bootstrap_open(local_cid, packet_number, &mut open)?;
            client.socket.send_to(&open[..used], client.peer).await?;
            let received = timeout(ACK_TIMEOUT, client.socket.recv_from(&mut response)).await;
            let Ok(Ok((len, response_peer))) = received else {
                continue;
            };
            if response_peer != client.peer {
                continue;
            }
            let Ok((header, server_cid)) = decode_bootstrap_ack(&response[..len], local_cid) else {
                continue;
            };
            if header.dcid != local_cid || server_cid.value() == 0 {
                continue;
            }
            client
                .endpoint
                .install_connection_ids(local_cid, server_cid)
                .map_err(|error| anyhow::anyhow!("install bootstrap CIDs: {error:?}"))?;
            client
                .endpoint
                .continue_packet_numbers_from(packet_number.saturating_add(1))
                .map_err(|error| anyhow::anyhow!("continue bootstrap packet numbers: {error:?}"))?;
            return Ok(client);
        }
        bail!("UDP bootstrap timeout after {BOOTSTRAP_ATTEMPTS} attempts")
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
            crate::TransportPacket::Control => Ok(()),
            crate::TransportPacket::Stream { .. } => {
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
                    crate::TransportPacket::Control => continue,
                    crate::TransportPacket::Stream { frame, .. } => {
                        let response = frame.data.to_vec();
                        self.endpoint
                            .stream_consumed(frame.id, frame.data.len())
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
                        return Ok((frame.id, response, frame.fin));
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
                crate::TransportPacket::Control => continue,
                crate::TransportPacket::Stream { frame, .. } => frame,
            };
            self.endpoint
                .stream_consumed(stream.id, stream.data.len())
                .map_err(|error| anyhow::anyhow!("client stream accounting: {error:?}"))?;
            let mut control = [0u8; MTU];
            if let Some(used) = self
                .endpoint
                .poll_transmit(&mut control)
                .map_err(|error| anyhow::anyhow!("client ACK: {error:?}"))?
            {
                self.socket.send_to(&control[..used], self.peer).await?;
            }
            return Ok((stream.id, stream.data.to_vec(), stream.fin));
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
    tracing::info!(bind = %config.bind, "object_udp_bound");
    let server = ObjectServer::new(ServerConfig {
        bind: config.bind.ip().to_string(),
        port: config.bind.port(),
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
        let (len, peer) =
            match timeout(config.receive_timeout, socket.recv_from(&mut datagram)).await {
                Ok(result) => result?,
                Err(_) => {
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
                    continue;
                }
            };
        let packet = datagram[..len].to_vec();
        let (header, _) = match crate::ShortHeader::decode(&packet) {
            Ok(value) => value,
            Err(error) => {
                tracing::warn!(%peer, error = ?error, "udp_transport_malformed_header");
                continue;
            }
        };
        if header.dcid.value() == 0 {
            let Some(client_cid) = decode_bootstrap_open(&packet) else {
                tracing::warn!(%peer, "udp_transport_invalid_bootstrap");
                continue;
            };
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
                crate::ConnectionId::new(existing)
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
                let (sender, receiver) = mpsc::channel(128);
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
                        history_capacity,
                        bootstrap_numbers,
                        config.max_active_connections,
                        config.ledger_memory_policy,
                        config.ledger_memory,
                        ledger_resize_interval,
                        config.object_chunk,
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
            if bootstrap_numbers.application_started.load(Ordering::Acquire) {
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
            if sender
                .try_send(ConnectionDatagram {
                    peer,
                    bytes: packet.clone(),
                })
                .is_ok()
            {
                continue;
            }
            connections.remove(&key);
            connection_peers.remove(&key);
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
    local_cid: crate::ConnectionId,
    peer_cid: crate::ConnectionId,
    history_capacity: usize,
    bootstrap_packet_numbers: Arc<BootstrapPacketNumbers>,
    max_active_connections: usize,
    ledger_memory_policy: LedgerMemoryPolicy,
    ledger_memory: Option<LedgerMemorySnapshot>,
    ledger_resize_interval: Duration,
    object_chunk: usize,
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
    mux.registry = registry;
    mux.install_connection_ids(local_cid, peer_cid)
        .map_err(|error| anyhow::anyhow!("persistent CIDs: {error:?}"))?;
    let mut response_stream = crate::FIRST_SERVER_BIDI_STREAM_ID;
    let mut object_transfer = None;
    let mut byte_transfer = None;
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
            &mut response_stream,
            &mut object_transfer,
            &mut byte_transfer,
            started,
            object_chunk,
            control.as_deref(),
        )
        .await
        .context("initial persistent packet")?;
        if mux.is_closed() {
            return Ok(());
        }
    }
    loop {
        match timeout(Duration::from_millis(50), receiver.recv()).await {
            Ok(Some(datagram)) if datagram.peer == peer => {
                let next = bootstrap_packet_numbers.next.load(Ordering::Acquire);
                if next > mux.endpoint.next_packet_number {
                    mux.endpoint
                        .continue_packet_numbers_from(next)
                        .map_err(|error| anyhow::anyhow!("continue bootstrap packet numbers: {error:?}"))?;
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
                    &mut response_stream,
                    &mut object_transfer,
                    &mut byte_transfer,
                    started,
                    object_chunk,
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
                    let sent = filled
                        && transfer.record_index >= transfer.records.len()
                        && transfer.current.is_empty();
                    if sent {
                        object_transfer = None;
                    }
                } else if let Some(transfer) = byte_transfer.as_mut() {
                    let _ = retransmit_due_packet(&socket, peer, &mut mux, started).await?;
                    let mut packet = [0u8; MTU];
                    if fill_byte_window(&socket, peer, &mut mux, transfer, &mut packet).await?
                        && transfer.remaining == 0 {
                        byte_transfer = None;
                    }
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
    avoid: crate::ConnectionId,
) -> Result<crate::ConnectionId> {
    for _ in 0..1024 {
        let value = NEXT_SERVER_CID.fetch_add(1, Ordering::Relaxed) & ((1u64 << 62) - 1);
        if value != 0 && value != avoid.value() && !connections.contains_key(&value) {
            return crate::ConnectionId::new(value)
                .ok_or_else(|| anyhow::anyhow!("CID allocation overflow"));
        }
    }
    bail!("CID allocation exhausted")
}

fn decode_bootstrap_open(packet: &[u8]) -> Option<crate::ConnectionId> {
    crate::decode_bootstrap_open_packet(packet)
        .ok()
        .map(|(_, client_cid)| client_cid)
}

fn decode_bootstrap_open_payload(packet: &[u8]) -> Option<&[u8]> {
    let (_, header_len) = crate::ShortHeader::decode(packet).ok()?;
    let (frame, used) = crate::decode_frame(&packet[header_len..]).ok()?;
    if used != packet.len().saturating_sub(header_len) {
        return None;
    }
    let crate::Frame::Stream(stream) = frame else {
        return None;
    };
    (stream.id == crate::CONTROL_STREAM_ID && stream.fin && stream.offset == 0)
        .then_some(stream.data)
}

fn encode_bootstrap_open(
    client_cid: crate::ConnectionId,
    packet_number: u32,
    out: &mut [u8],
) -> Result<usize> {
    crate::encode_bootstrap_open_packet(client_cid, packet_number, out)
        .map_err(|error| anyhow::anyhow!("bootstrap OPEN: {error:?}"))
}

fn decode_bootstrap_ack(
    packet: &[u8],
    expected_dcid: crate::ConnectionId,
) -> Result<(crate::ShortHeader, crate::ConnectionId)> {
    crate::decode_bootstrap_open_ack_packet(packet, expected_dcid)
        .map_err(|error| anyhow::anyhow!("bootstrap ACK: {error:?}"))
}

fn encode_bootstrap_ack(
    client_cid: crate::ConnectionId,
    packet_number: u32,
    server_cid: crate::ConnectionId,
    out: &mut [u8],
) -> Result<usize> {
    crate::encode_bootstrap_open_ack_packet(client_cid, server_cid, packet_number, out)
        .map_err(|error| anyhow::anyhow!("bootstrap ACK: {error:?}"))
}

async fn process_persistent_packet<const H: usize>(
    socket: &UdpSocket,
    peer: SocketAddr,
    server: &ObjectServer,
    bytes: &[u8],
    mux: &mut StreamMux<8, H>,
    response_stream: &mut u64,
    object_transfer: &mut Option<PendingObjectTransfer>,
    byte_transfer: &mut Option<PendingByteTransfer>,
    started: Instant,
    object_chunk: usize,
    control: Option<&TransportControl>,
) -> Result<()> {
    mux.endpoint.set_time(started.elapsed().as_millis() as u64);
    let mut packet = [0u8; MTU];
    let request = mux
        .receive_request(bytes)
        .map_err(|error| anyhow::anyhow!("persistent input: {error:?}"))?;
    if let Some(request) = request {
        if request.data.first() == Some(&SERVICE_CONTROL) {
            let record = request.data.get(2..).unwrap_or_default();
            match request.data.get(1).copied() {
                Some(CONTROL_LOG) => {
                    if let Some(control) = control { control.receive_log(record); }
                }
                Some(CONTROL_POLL) => {}
                _ => bail!("invalid control record"),
            }
            mux.complete_request(request.stream_id, request.data.len())
                .map_err(|error| anyhow::anyhow!("control request accounting: {error:?}"))?;
            let response = control.map_or_else(
                || Vec::from([SERVICE_CONTROL, CONTROL_RESPONSE]),
                TransportControl::next_response,
            );
            let (used, _) = mux.encode_response(*response_stream, &response, true, &mut packet)
                .map_err(|error| anyhow::anyhow!("control response: {error:?}"))?;
            socket.send_to(&packet[..used], peer).await?;
            *response_stream = response_stream.saturating_add(4);
            return Ok(());
        } else if request.data.first() == Some(&SERVICE_OBJECT) {
            if object_transfer.is_some() {
                bail!("object transfer already active");
            }
            let get = dmesh_object_store::protocol::decode_get(&request.data[1..])
                .ok_or_else(|| anyhow::anyhow!("invalid bootstrapped object GET"))?;
            if get.target == 0 || get.name.as_ref().is_some_and(|name| name.len() > 128) {
                bail!("invalid bootstrapped object target");
            }
            let records = server.response_records(get)?;
            tracing::info!(%peer, stream = request.stream_id, records = records.len(),
                "object_udp_get_accepted");
            *object_transfer = Some(PendingObjectTransfer::with_chunk(records, object_chunk));
            mux.complete_request(request.stream_id, request.data.len())
                .map_err(|error| anyhow::anyhow!("object request accounting: {error:?}"))?;
        } else if request.data.first() == Some(&SERVICE_IPERF) {
            if byte_transfer.is_some() {
                bail!("iperf transfer already active");
            }
            let requested = request.data.get(1..9)
                .map(|bytes| u64::from_be_bytes(bytes.try_into().unwrap()))
                .unwrap_or(0)
                .clamp(1, 64 * 1024 * 1024) as usize;
            let packet_size = request.data.get(9..11)
                .map(|bytes| u16::from_be_bytes(bytes.try_into().unwrap()) as usize)
                .unwrap_or(object_chunk)
                .clamp(8, MAX_OBJECT_CHUNK);
            mux.complete_request(request.stream_id, request.data.len())
                .map_err(|error| anyhow::anyhow!("iperf request accounting: {error:?}"))?;
            *byte_transfer = Some(PendingByteTransfer::new(
                *response_stream, requested, packet_size,
            ));
            *response_stream = response_stream.saturating_add(4);
        } else {
            let connection = mux
                .endpoint
                .local_connection_id()
                .or_else(|| mux.endpoint.peer_connection_id())
                .ok_or(crate::Error::WrongConnectionId)
                .map_err(|error| anyhow::anyhow!("service CID: {error:?}"))?;
            let service = *request
                .data
                .first()
                .ok_or(crate::Error::Invalid)
                .map_err(|error| anyhow::anyhow!("empty service: {error:?}"))?;
            let response = crate::handlers::handle_stream_with_events(
                &mux.endpoint,
                Some(&mux.events),
                connection,
                request.stream_id,
                &mux.registry,
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
        if fill_object_window(socket, peer, mux, transfer, &mut packet).await? {
            if transfer.record_index >= transfer.records.len() && transfer.current.is_empty() {
                *object_transfer = None;
            }
        }
    } else if let Some(transfer) = byte_transfer.as_mut() {
        let _ = retransmit_due_packet(socket, peer, mux, started).await?;
        if fill_byte_window(socket, peer, mux, transfer, &mut packet).await?
            && transfer.remaining == 0 {
            *byte_transfer = None;
        }
    } else if let Some(used) = mux
        .endpoint
        .poll_transmit(&mut packet)
        .map_err(|error| anyhow::anyhow!("persistent ACK: {error:?}"))?
    {
        socket.send_to(&packet[..used], peer).await?;
    }
    Ok(())
}

async fn fill_byte_window<const H: usize>(
    socket: &UdpSocket,
    peer: SocketAddr,
    mux: &mut StreamMux<8, H>,
    transfer: &mut PendingByteTransfer,
    packet: &mut [u8; MTU],
) -> Result<bool> {
    let mut sent = false;
    while transfer.remaining != 0
        && mux.endpoint.history_len() < mux.endpoint.history_capacity()
        && mux.endpoint.congestion.can_send(MTU as u64)
    {
        mux.endpoint.open_send_stream(transfer.stream_id, INITIAL_MAX_STREAM_DATA).ok();
        let length = transfer.remaining.min(transfer.chunk_size);
        let mut payload = [0u8; MAX_OBJECT_CHUNK];
        payload[..4].copy_from_slice(&transfer.packet_id.to_be_bytes());
        for (index, byte) in payload[4..length].iter_mut().enumerate() {
            *byte = transfer.offset.wrapping_add(4 + index as u64) as u8;
        }
        let fin = length == transfer.remaining;
        let (used, _) = mux.endpoint.encode_stream_packet(
            mux.endpoint.peer_connection_id().ok_or(crate::Error::WrongConnectionId)
                .map_err(|error| anyhow::anyhow!("iperf peer CID: {error:?}"))?,
            transfer.stream_id, transfer.offset, fin, &payload[..length], packet,
        ).map_err(|error| anyhow::anyhow!("iperf response packet: {error:?}"))?;
        socket.send_to(&packet[..used], peer).await?;
        transfer.offset = transfer.offset.saturating_add(length as u64);
        transfer.remaining -= length;
        transfer.packet_id = transfer.packet_id.wrapping_add(1);
        sent = true;
    }
    Ok(sent)
}

async fn retransmit_due_packet<const H: usize>(
    socket: &UdpSocket,
    peer: SocketAddr,
    mux: &mut StreamMux<8, H>,
    started: Instant,
) -> Result<bool> {
    let now = started.elapsed().as_millis() as u64;
    mux.endpoint.set_time(now);
    let mut packet = [0u8; MTU];
    let pto = mux.endpoint.pto_timeout().max(UDP_MIN_RETRANSMIT_PTO_MS);
    if let Some((used, _packet_number)) = mux
        .endpoint
        .retransmit_due(now, pto, &mut packet)
        .map_err(|error| anyhow::anyhow!("persistent retransmission: {error:?}"))?
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
    if !transfer.load_current() {
        return Ok(false);
    }
    let stream_id = OBJECT_STREAM;
    mux.endpoint
        .open_send_stream(stream_id, INITIAL_MAX_STREAM_DATA)
        .ok();
    let remaining = transfer
        .current
        .len()
        .saturating_sub(transfer.current_offset);
    let chunk = remaining.min(transfer.chunk_size);
    let end = transfer.current_offset + chunk;
    let fin = transfer.current_kind == RECORD_DONE && end == transfer.current.len();
    let offset = transfer.stream_offset;
    let (used, _) = mux
        .endpoint
        .encode_stream_packet(
            mux.endpoint
                .peer_connection_id()
                .ok_or(crate::Error::WrongConnectionId)
                .map_err(|error| anyhow::anyhow!("object peer CID: {error:?}"))?,
            stream_id,
            offset,
            fin,
            &transfer.current[transfer.current_offset..end],
            packet,
        )
        .map_err(|error| {
            anyhow::anyhow!(
                "object response packet: {error:?} history={} bytes_in_flight={} congestion_window={} stream_credit={:?} connection_credit={} stream_offset={} chunk={}",
                mux.endpoint.history_len(),
                mux.endpoint.bytes_in_flight(),
                mux.endpoint.congestion.congestion_window,
                mux.endpoint.send.stream_credit(stream_id),
                mux.endpoint.send.max_data,
                offset,
                chunk,
            )
        })?;
    socket.send_to(&packet[..used], peer).await?;
    transfer.current_offset = end;
    transfer.stream_offset = transfer.stream_offset.saturating_add(chunk as u64);
    let previous_bytes = transfer.sent_bytes;
    transfer.sent_bytes = transfer.sent_bytes.saturating_add(chunk);
    if transfer.sent_bytes / (64 * 1024) != previous_bytes / (64 * 1024) {
        tracing::info!(%peer, stream = stream_id, record = transfer.record_index,
            sent_bytes = transfer.sent_bytes, "object_udp_transfer_progress");
    }
    if end == transfer.current.len() {
        transfer.current.clear();
        transfer.record_index += 1;
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
    while mux.endpoint.history_len() < mux.endpoint.history_capacity()
        && mux.endpoint.congestion.can_send(MTU as u64)
    {
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
    use std::eprintln;

    use super::*;
    use crate::callback::{CallbackStreams, CopyingStreamEvents};
    use crate::handlers::handle_stream;
    use crate::{
        ConnectionId, EndpointState, Frame, RecoveryEndpoint, ShortHeader,
        FIRST_CLIENT_BIDI_STREAM_ID, FLAG_FIXED, RECOVERY_MAX_HISTORY_PACKETS,
        RECOVERY_REORDER_CAPACITY_BYTES,
    };
    use dmesh_object_store::protocol::{
        encode_get, ImageEvent, ImageManifest, ImageReceiver, ImageSink, RecordBuffer, RECORD_BLOB,
        RECORD_DONE, RECORD_MANIFEST,
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
        assert_eq!(registry.handlers().len(), 8);
        assert!(registry
            .handlers()
            .iter()
            .any(|handler| handler.tag == SERVICE_IPERF));
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
                let crate::TransportPacket::Stream { frame, .. } =
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
        assert!(UdpClient::connect(
            "127.0.0.1:0".parse().unwrap(),
            server_addr,
            ConnectionId::new(0).unwrap(),
        )
        .await
        .is_err());

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
        assert!(UdpClient::connect(
            "127.0.0.1:0".parse().unwrap(),
            server_addr,
            ConnectionId::new(7).unwrap(),
        )
        .await
        .is_err());
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
    fn pending_object_transfer_switches_records_and_offsets() {
        let mut pending = PendingObjectTransfer::new(vec![
            (RECORD_MANIFEST, b"manifest".to_vec()),
            (RECORD_BLOB, b"blob".to_vec()),
        ]);
        assert!(pending.load_current());
        assert_eq!(pending.current_kind, RECORD_MANIFEST);
        assert_eq!(&pending.current[5..], b"manifest");
        pending.current.clear();
        pending.record_index = 1;
        assert!(pending.load_current());
        assert_eq!(pending.current_kind, RECORD_BLOB);
        assert_eq!(pending.stream_offset, 0);
        pending.current.clear();
        pending.record_index = 2;
        assert!(!pending.load_current());
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
                crate::FIRST_CLIENT_BIDI_STREAM_ID,
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
            if stream != OBJECT_STREAM { return Err(()); }
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
    }

    impl RecoveryMirror {
        fn new() -> Self {
            Self {
                endpoint: RecoveryEndpoint::<2>::new(
                    Role::Client,
                    ConnectionLimits {
                        max_data: crate::RECOVERY_INITIAL_MAX_DATA,
                        max_stream_data: crate::RECOVERY_INITIAL_MAX_DATA,
                        ..ConnectionLimits::default()
                    },
                    MTU as u64,
                ),
                // Match fw/recovery-rust/src/udp_flash.rs. This is deliberately
                // not UdpClient: the test must exercise Recovery's callback,
                // flow-credit, and two-stage ACK behavior.
                ordered: CallbackStreams::new(2, RECOVERY_REORDER_CAPACITY_BYTES),
                records: RecordBuffer::new(),
                receiver: ImageReceiver::new(FakeFlash { bytes: Vec::new() }),
                drop_outbound_control: 0,
            }
        }

        fn accept_recovery_records(
            stream: u64,
            records: &mut RecordBuffer,
            receiver: &mut ImageReceiver<FakeFlash>,
        ) {
            assert_eq!(stream, OBJECT_STREAM);
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
            }
        }

        async fn receive_one(
            &mut self,
            socket: &UdpSocket,
            peer: SocketAddr,
            packet: &[u8],
        ) -> Result<()> {
            let mut transport_out = [0u8; MTU];
            let mut outputs: Vec<Vec<u8>> = Vec::new();
            let (endpoint, ordered, records, receiver) = (
                &mut self.endpoint,
                &mut self.ordered,
                &mut self.records,
                &mut self.receiver,
            );
            endpoint
                .receive_with_callbacks(
                    packet,
                    &mut transport_out,
                    |out| {
                        // The bearer test only forwards opaque transport
                        // output. It must not know which frames it contains.
                        outputs.push(out.to_vec());
                    },
                    |stream| {
                        let consumed = {
                            let mut sink = RecoveryMirrorSink {
                                records,
                                bytes: 0,
                            };
                            ordered
                                .receive_copying(
                                    stream.id,
                                    Arc::new(stream.data.to_vec()),
                                    stream.offset,
                                    0..stream.data.len(),
                                    stream.fin,
                                    &mut sink,
                                )
                                .map_err(|_| crate::Error::Invalid)?;
                            sink.bytes
                        };
                        if consumed != 0 {
                            Self::accept_recovery_records(stream.id, records, receiver);
                        }
                        Ok(consumed)
                    },
                )
                .map_err(|error| anyhow::anyhow!("Recovery mirror input: {error:?}"))?;
            for output in outputs {
                if self.drop_outbound_control != 0 {
                    self.drop_outbound_control -= 1;
                } else {
                    socket.send_to(&output, peer).await?;
                }
            }
            Ok(())
        }

        /// Mirror Recovery's bounded `recvfrom` timeout.  Delayed ACKs and
        /// other transport control are clock-driven; they must not depend on
        /// another application datagram arriving.  This deliberately emits
        /// opaque transport output only, matching `fw/recovery-rust`.
        async fn poll_timer(
            &mut self,
            socket: &UdpSocket,
            peer: SocketAddr,
            now_ms: u64,
        ) -> Result<()> {
            self.endpoint.set_time(now_ms);
            let mut output = [0u8; MTU];
            if let Some(used) = self
                .endpoint
                .poll_transmit(&mut output)
                .map_err(|error| anyhow::anyhow!("Recovery mirror timer: {error:?}"))?
            {
                if self.drop_outbound_control != 0 {
                    self.drop_outbound_control -= 1;
                } else {
                    socket.send_to(&output[..used], peer).await?;
                }
            }
            Ok(())
        }
    }

    async fn run_recovery_mirror(
        size: usize,
        object_chunk: usize,
        history_capacity: usize,
        ack_frequency: u8,
        drop_first_control: bool,
        drop_first_stream: bool,
        late_loss_burst: bool,
    ) {
        let directory = tempdir().unwrap();
        let artifact_root = directory.path().join("flash");
        let artifact = artifact_root.join("esp32c6/main-app.bin");
        std::fs::create_dir_all(artifact.parent().unwrap()).unwrap();
        let expected = (0..size).map(|n| (n % 251) as u8).collect::<Vec<_>>();
        std::fs::write(&artifact, &expected).unwrap();

        let mut request_body = [0u8; 64];
        let encoded_len = encode_get(&mut request_body[1..], None, 13, 6).unwrap();
        request_body[0] = SERVICE_OBJECT;
        let request_len = encoded_len + 1;
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
        mirror
            .endpoint
            .install_connection_ids(client_cid, server_cid)
            .unwrap();
        mirror
            .endpoint
            .set_ack_frequency(ack_frequency);
        mirror.drop_outbound_control = usize::from(drop_first_control);
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
        let deadline = started + Duration::from_secs(20);
        let mut mirror_datagrams = 0usize;
        let mut drop_first_stream = drop_first_stream;
        let mut stream_datagrams = 0usize;
        let mut late_drops_remaining = if late_loss_burst { 3usize } else { 0 };
        while !mirror.receiver.is_complete() {
            let remaining = deadline.saturating_duration_since(Instant::now());
            assert!(!remaining.is_zero(), "Recovery mirror transfer timed out after {mirror_datagrams} datagrams");
            match tokio::time::timeout(remaining.min(Duration::from_millis(10)), socket.recv_from(&mut input)).await {
                Ok(Ok((len, peer))) => {
                    assert_eq!(peer, bind);
                    mirror_datagrams += 1;
                    let (_, header_len) = ShortHeader::decode(&input[..len]).unwrap();
                    let (frame, _) = crate::decode_frame(&input[header_len..]).unwrap();
                    if drop_first_stream && matches!(frame, Frame::Stream(_)) {
                        drop_first_stream = false;
                        continue;
                    }
                    if matches!(frame, Frame::Stream(_)) {
                        stream_datagrams += 1;
                        if stream_datagrams >= 849 && late_drops_remaining != 0 {
                            late_drops_remaining -= 1;
                            continue;
                        }
                    }
                    match mirror.receive_one(&socket, peer, &input[..len]).await {
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
    }

    #[tokio::test]
    async fn recovery_receive_loop_matrix_matches_device_profiles() {
        for history_capacity in [2, 4, 16, 32] {
            for object_chunk in [OBJECT_CHUNK, 1200] {
                run_recovery_mirror(128 * 1024 + 123, object_chunk, history_capacity, 2, false, false, false).await;
            }
        }
    }

    #[tokio::test]
    async fn recovery_profile_benchmark_matches_esp32_dry_run_size() {
        let size = 2_122_528;
        let started = Instant::now();
        let object_chunk = 1200;
        run_recovery_mirror(size, object_chunk, 32, 8, false, false, false).await;
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
        run_recovery_mirror(2_122_528, 1200, 16, 8, true, false, false).await;
    }

    #[tokio::test]
    async fn recovery_profile_recovers_from_late_three_packet_loss_burst() {
        // Matches the device stall boundary: do not let a late selective-ACK
        // gap turn an otherwise healthy 2 MiB Recovery transfer into silence.
        run_recovery_mirror(2_122_528, 1200, 32, 8, false, false, true).await;
    }

    #[tokio::test]
    async fn recovery_profile_reorders_one_stream_packet_with_bounded_credit() {
        // This mirrors the Wi-Fi fault that previously let the server send
        // roughly 256 KiB past a missing early range, overflowing Recovery's
        // callback buffer.  The receiver must advertise only its bounded
        // reorder budget and the sender must repair the gap.
        run_recovery_mirror(2_122_528, 1200, 16, 8, false, true, false).await;
    }

    #[test]
    fn recovery_production_window_fits_callback_reorder_budget() {
        const HOST_HISTORY_PACKETS: usize = RECOVERY_MAX_HISTORY_PACKETS;
        const HOST_PAYLOAD_BYTES: usize = 1200;
        assert!(
            HOST_HISTORY_PACKETS * HOST_PAYLOAD_BYTES <= RECOVERY_REORDER_CAPACITY_BYTES,
            "Recovery callback reassembly must cover every outstanding host payload"
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
        for object_chunk in [OBJECT_CHUNK, 1200] {
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
            .request_stream(crate::FIRST_CLIENT_BIDI_STREAM_ID, &[SERVICE_METRICS], true)
            .await
            .unwrap();
        assert!(fin);
        assert!(core::str::from_utf8(&response)
            .unwrap()
            .contains("metrics_version=1"));
        assert!(core::str::from_utf8(&response)
            .unwrap()
            .contains("history_capacity=2"));
        assert!(core::str::from_utf8(&response)
            .unwrap()
            .contains("next_packet_number=1"));
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
            ledger_memory_policy: crate::ledger::LedgerMemoryPolicy {
                min_packets: 4,
                max_packets: 16,
                reserve_bytes: 0,
                ..crate::ledger::LedgerMemoryPolicy::default()
            },
            ledger_memory: Some(crate::ledger::LedgerMemorySnapshot {
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
            .request_stream(crate::FIRST_CLIENT_BIDI_STREAM_ID, &[SERVICE_METRICS], true)
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
            ledger_memory_policy: crate::ledger::LedgerMemoryPolicy {
                min_packets: 4,
                max_packets: 16,
                reserve_bytes: 0,
                ..crate::ledger::LedgerMemoryPolicy::default()
            },
            ledger_memory: Some(crate::ledger::LedgerMemorySnapshot {
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
            let stream = crate::FIRST_CLIENT_BIDI_STREAM_ID + index as u64 * 4;
            let (_, metrics, _) = client
                .request_stream(stream, &[SERVICE_METRICS], true)
                .await
                .unwrap();
            assert!(core::str::from_utf8(&metrics)
                .unwrap()
                .contains("metrics_version=1"));
            let event_stream = stream + 4;
            let (_, events, _) = client
                .request_stream(event_stream, &[SERVICE_EVENTS], true)
                .await
                .unwrap();
            assert!(core::str::from_utf8(&events)
                .unwrap()
                .contains("events_version="));
            assert!(core::str::from_utf8(&events).unwrap().contains("events="));
            let echo_stream = event_stream + 4;
            let (_, echo, _) = client
                .request_stream(echo_stream, &[SERVICE_ECHO, b'p', b'r', b'o', b'b'], true)
                .await
                .unwrap();
            let echo_text = core::str::from_utf8(&echo).unwrap();
            assert!(echo_text.contains("service=2"));
            assert!(echo_text.contains("connection_dcid="));
            assert!(echo_text.contains("stream_id="));
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
                assert!(iperf[offset + 4..offset + used].iter().enumerate().all(|(index, byte)| {
                    *byte == (offset + 4 + index) as u8
                }));
                offset += used;
                packet_id = packet_id.wrapping_add(1);
            }
            let registry_stream = iperf_stream + 4;
            let (_, registry, _) = client
                .request_stream(registry_stream, &[SERVICE_STREAM], true)
                .await
                .unwrap();
            let registry_text = core::str::from_utf8(&registry).unwrap();
            assert!(registry_text.contains("metrics"));
            assert!(registry_text.contains("events"));
        }
        assert_ne!(server_cids[0], server_cids[1]);
        server_task.abort();
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
            "127.0.0.1:0".parse().unwrap(), bind, ConnectionId::new(0x8c).unwrap(),
        ).await.unwrap();
        let log = [SERVICE_CONTROL, CONTROL_LOG, 0xa1, 0x04, 0x62, b'o', b'k'];
        let (_, response, finished) = client
            .request_stream(FIRST_CLIENT_BIDI_STREAM_ID, &log, true).await.unwrap();
        assert!(finished);
        assert_eq!(response, [SERVICE_CONTROL, CONTROL_RESPONSE, 0xa1, 0x00, 0x18, 0x44]);
        assert_eq!(control.take_log().as_deref(), Some(&log[2..]));
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
        assert!(timeout(
            Duration::from_millis(100),
            attacker.recv_from(&mut response)
        )
        .await
        .is_err());

        let (_, metrics, _) = legitimate
            .request_stream(crate::FIRST_CLIENT_BIDI_STREAM_ID, &[SERVICE_METRICS], true)
            .await
            .unwrap();
        assert!(core::str::from_utf8(&metrics)
            .unwrap()
            .contains("metrics_version=1"));
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
            .request_stream(crate::FIRST_CLIENT_BIDI_STREAM_ID, &[SERVICE_METRICS], true)
            .await
            .unwrap();
        assert!(core::str::from_utf8(&metrics)
            .unwrap()
            .contains("metrics_version=1"));
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
            .request_stream(crate::FIRST_CLIENT_BIDI_STREAM_ID, &[SERVICE_METRICS], true)
            .await
            .unwrap();
        assert!(core::str::from_utf8(&metrics)
            .unwrap()
            .contains("metrics_version=1"));
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
        client.send_to(&retry_open[..retry_open_len], bind).await.unwrap();
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
            .request_stream(crate::FIRST_CLIENT_BIDI_STREAM_ID, &[SERVICE_METRICS], true)
            .await
            .unwrap();
        assert!(core::str::from_utf8(&metrics)
            .unwrap()
            .contains("metrics_version=1"));
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
            receive_timeout: Duration::from_millis(1),
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
        tokio::time::sleep(Duration::from_millis(15)).await;
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
        let (response_len, _) = timeout(Duration::from_millis(50), client.socket.recv_from(&mut response))
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
                crate::FIRST_CLIENT_BIDI_STREAM_ID,
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
}
