//! QUIC-lite server attachment for raw-injected ESP-NOW action-frame data.
//!
//! NAN discovers peers; this module owns only complete action-frame datagrams
//! and routes them by DCID. It is intentionally independent of NAN state.

use anyhow::{Result, anyhow};
use dmesh_server::stream_server::{
    BinaryEventHistory, PassiveAssociations, StreamClientConnection, StreamServerConnection,
};
use dmesh_server::{
    iperf::{IperfServicePlan, decode_iperf_service_request},
    services::{
        BinaryEventRecord, CONTROL_PATH_POLICY, decode_path_policy, diagnostic_stream_registry,
        encode_binary_events, encode_path_policy_response, handle_stream_with_events,
    },
};
use quic_lite::{
    ConnectionId, ConnectionTable, FLAG_FIXED, PathState, SERVICE_CONTROL, SERVICE_EVENTS,
    SERVICE_IPERF, SERVICE_LOG_WATCH, SERVICE_STATUS, ShortHeader, StreamRegistry,
    iperf::IperfSender,
};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};
use std::vec::Vec;

use super::wifi;

/// Stream-bearing peers admitted at the same time. This is deliberately
/// independent of the compact passive association cache below. Classic ESP32
/// has no PSRAM in this fleet and keeps a small relay profile; S3/C6 retain
/// the sixteen-active-peer target.
#[cfg(all(not(target_feature = "esp32s3ops"), not(target_arch = "riscv32")))]
const MAX_ACTIVE_CONNECTIONS: usize = 3;
#[cfg(any(target_feature = "esp32s3ops", target_arch = "riscv32"))]
const MAX_ACTIVE_CONNECTIONS: usize = 16;
/// Remembered NAN/action peers. These records retain identity/DCID only; they
/// do not reserve a stream mux, packet ledger, or service buffers.
const MAX_PASSIVE_ASSOCIATIONS: usize = 256;
/// Normal relay/control connections retain one packet. High-throughput
/// transfers will use a separately admitted bulk profile instead of giving a
/// full retransmission window to every associated peer.
// Match Recovery's shared endpoint ledger. Connection admission, not a
// one-packet QUIC profile, is the classic-board memory boundary.
const ACTIVE_HISTORY_PACKETS: usize = 4;
const ACTIVE_CONNECTION_HEAP_RESERVE: usize = 16 * 1024;
const MTU: usize = quic_lite::DEFAULT_MAX_DATAGRAM_SIZE;
// A UDP receive routes a full MTU through the short-header parser, bootstrap
// encoder, and stream mux.  ESP-IDF's Rust thread default is too small for
// that call chain: the task can idle successfully, then reset the board on
// its first datagram.  Keep this explicit, just as the shared UART L2 task
// does, rather than making packet processing depend on a toolchain default.
// UART enters the same DCID/server path as UDP.  Do not dispatch it from
// Main's application task: creating a server connection and encoding its
// bootstrap ACK has the same stack depth as the UDP path, and classic ESP32
// can otherwise stall on its first valid UART transport packet.
// IPERF adds a producer and validation state on top of the normal request
// decoder. The measured classic ESP32 overflow at 20 KiB, so retain 32 KiB
// for this one active server task rather than letting a valid stream reset the
// board. Active-connection admission remains separately bounded.
const UART_BEARER_TASK_STACK_BYTES: usize = 32 * 1024;
const UART_BEARER_TASK_PRIORITY: u32 = 5;
/// An OPEN without a stream request reserves a server CID briefly so its ACK
/// can be retransmitted, but must not consume all three classic slots forever.
const BOOTSTRAP_RESERVATION_MS: u64 = 3_000;
const ACTION_PATH: usize = 0;
const UART_PATH: usize = 1;
const UDP_PATH: usize = 2;
const SERVICE_LORA: u8 = 43;
const SERVICE_HARDWARE: u8 = 45;
/// Send one complete raw NOW-like action through the shared transport lane.
/// The body is destination MAC followed by the portable `rawnan` payload;
/// this is a radio/filter diagnostic, not an ESP-IDF ESP-NOW operation.
const HARDWARE_ESPNOW_ACTION_PREFIX: &[u8] = b"espnow-action:";
const HARDWARE_NAN_PUBLIC_ACTION_PREFIX: &[u8] = b"nan-public-action:";
/// Main-only source for the shared Recovery/Main non-promiscuous beacon-IE
/// receive experiment. This is not an ESP-NOW or NAN data-path command.
const HARDWARE_NAN_VENDOR_IE_PROBE_PREFIX: &[u8] = b"nan-vendor-ie-probe:";
const MODULE_EVENT_HISTORY: usize = 16;
const MODULE_EVENT_RESPONSE_MAX: usize = MTU - 64;
/// All IP bearers use the same QUIC-lite port. This is an L2 adapter socket,
/// not a TCP command listener.
pub const UDP_TRANSPORT_PORT: u16 = 3339;

/// ESP-specific binding around bearer-neutral client/server connection state.
/// It intentionally owns only an action-frame peer address; DCID/mux,
/// bootstrap, handler registry, events, and response stream IDs live in
/// dmesh-server.
struct EspConnectionBinding {
    /// Table key used for routing and deterministic stale-bootstrap removal.
    dcid: ConnectionId,
    peer: [u8; 6],
    client: Option<StreamClientConnection<ACTIVE_HISTORY_PACKETS>>,
    server: Option<StreamServerConnection<ACTIVE_HISTORY_PACKETS>>,
    /// The standard, no-std dmesh-server IPERF plan expands one handler
    /// request into bounded normal/high/low producers. The adapter only
    /// drives them when an L2 packet/ACK makes the shared endpoint writable.
    iperf: Option<IperfProducers>,
    /// Set after the FIN-bearing IPERF packet is queued. The next peer packet
    /// is its transport ACK/window update, after which the active mux can be
    /// reclaimed without dropping the final packet from its loss ledger.
    iperf_finished: bool,
    /// Time of the server-side OPEN reservation. Only an unrequested server
    /// connection is eligible for expiry; active streams retain normal QUIC
    /// flow-control and completion ownership.
    opened_at_ms: u64,
    awaiting_first_request: bool,
}

/// Firmware realization of the socket-free `IperfServicePlan`. Host UDP and
/// Main therefore accept the same request bounds, stream count, priority
/// lanes, packet size, and ACK policy; only their bearer scheduling differs.
struct IperfProducers {
    normal: [Option<IperfSender>; dmesh_server::iperf::IPERF_MAX_NORMAL_STREAMS],
    high: Option<IperfSender>,
    low: Option<IperfSender>,
    next_normal: usize,
}

impl IperfProducers {
    fn new(
        plan: IperfServicePlan,
        server: &mut StreamServerConnection<ACTIVE_HISTORY_PACKETS>,
    ) -> Option<Self> {
        let mut normal = core::array::from_fn(|_| None);
        for (index, sender) in normal.iter_mut().take(plan.normal_streams).enumerate() {
            *sender = IperfSender::new(
                server.reserve_response_stream(),
                plan.normal_bytes[index],
                plan.packet_size,
            );
        }
        let high = (plan.high_priority_bytes != 0)
            .then(|| {
                IperfSender::new(
                    server.reserve_response_stream(),
                    plan.high_priority_bytes,
                    plan.packet_size,
                )
            })
            .flatten();
        let low = (plan.low_priority_bytes != 0)
            .then(|| {
                IperfSender::new(
                    server.reserve_response_stream(),
                    plan.low_priority_bytes,
                    plan.packet_size,
                )
            })
            .flatten();
        Some(Self {
            normal,
            high,
            low,
            next_normal: 0,
        })
    }

    fn is_complete(&self) -> bool {
        self.normal.iter().all(Option::is_none) && self.high.is_none() && self.low.is_none()
    }

    fn poll(
        &mut self,
        endpoint: &mut quic_lite::EndpointState<6, ACTIVE_HISTORY_PACKETS, MTU>,
        out: &mut [u8; MTU],
    ) -> Result<Option<(usize, bool)>, quic_lite::Error> {
        // Keep the service's priority boundary explicit: one high packet is
        // eligible before normal lanes, and low gets a turn after them. A
        // blocked lane returns `None` without blocking the task or growing a
        // bearer queue.
        if let Some(sender) = self.high.as_mut() {
            if let Some(packet) = sender.poll(endpoint, out)? {
                if packet.1 {
                    self.high = None;
                }
                return Ok(Some(packet));
            }
        }
        for offset in 0..self.normal.len() {
            let index = (self.next_normal + offset) % self.normal.len();
            let Some(sender) = self.normal[index].as_mut() else {
                continue;
            };
            if let Some(packet) = sender.poll(endpoint, out)? {
                self.next_normal = (index + 1) % self.normal.len();
                if packet.1 {
                    self.normal[index] = None;
                }
                return Ok(Some(packet));
            }
        }
        if let Some(sender) = self.low.as_mut() {
            if let Some(packet) = sender.poll(endpoint, out)? {
                if packet.1 {
                    self.low = None;
                }
                return Ok(Some(packet));
            }
        }
        Ok(None)
    }
}

/// Start a client connection over the raw ESP-NOW bearer.  The
/// caller can subsequently send stream requests through this same owner once
/// the peer returns its OPEN ACK. NAN is only expected to discover `peer`.
pub fn open_espnow_client(peer: [u8; 6]) -> Result<ConnectionId> {
    open_espnow_client_request(peer, None)
}

/// Start an ESP-NOW client connection and queue one standard service request.
/// The request begins with a registered dmesh-server service tag; it is not a
/// raw action command schema.
pub fn open_espnow_client_request(peer: [u8; 6], request: Option<Vec<u8>>) -> Result<ConnectionId> {
    if request
        .as_ref()
        .is_some_and(|request| request.is_empty() || request.len() > MTU)
    {
        return Err(anyhow!(
            "action client request exceeds one transport packet"
        ));
    }
    let (client, open) = {
        let mut active = connections()
            .lock()
            .map_err(|_| anyhow!("action transport lock"))?;
        if active.connections.len() >= MAX_ACTIVE_CONNECTIONS {
            return Err(anyhow!("action connection capacity"));
        }
        if !can_admit_active_connection() {
            return Err(anyhow!("action connection memory admission"));
        }
        let avoid = ConnectionId::new(1).expect("nonzero CID");
        let client = allocate_cid(avoid).ok_or_else(|| anyhow!("action CID exhausted"))?;
        let mut client_connection = StreamClientConnection::new(client, 500_000, 4, request)
            .map_err(|_| anyhow!("action client bootstrap"))?;
        let mut open = [0u8; MTU];
        let used = client_connection
            .start_open(0, &mut open)
            .map_err(|_| anyhow!("action client OPEN"))?;
        active
            .connections
            .insert(
                client,
                Box::new(EspConnectionBinding {
                    dcid: client,
                    peer,
                    client: Some(client_connection),
                    server: None,
                    iperf: None,
                    iperf_finished: false,
                    opened_at_ms: now_ms(),
                    awaiting_first_request: false,
                }),
            )
            .map_err(|_| anyhow!("action DCID route capacity"))?;
        active
            .connections
            .set_path_available(ACTION_PATH, true)
            .map_err(|_| anyhow!("action path unavailable"))?;
        remember_association(peer, client);
        (client, open[..used].to_vec())
    };
    if !dmesh_fw_transport::wifi_espnow_esp::transmit(
        dmesh_fw_transport::wifi_espnow_esp::EspNowPeer { mac: peer },
        &open,
    ) {
        return Err(anyhow!("ESP-NOW client OPEN send failed"));
    }
    Ok(client)
}

/// Ask a discovered ESP-NOW peer to run the standard IPERF service. This
/// queues a QUIC-lite stream after bootstrap; it never emits a raw flood.
pub fn open_espnow_iperf_client(peer: [u8; 6], bytes: u64) -> Result<ConnectionId> {
    if bytes == 0 {
        return Err(anyhow!("IPERF byte count must be nonzero"));
    }
    let mut request = Vec::with_capacity(11);
    request.push(SERVICE_IPERF);
    request.extend_from_slice(&bytes.to_be_bytes());
    request.extend_from_slice(&(MTU as u16).to_be_bytes());
    open_espnow_client_request(peer, Some(request))
}

struct ConnectionOwner {
    /// QUIC-lite owns the fixed DCID slots and bearer liveness. Main only
    /// supplies ESP-NOW peer binding plus its registered server handlers.
    connections: ConnectionTable<Box<EspConnectionBinding>, MAX_ACTIVE_CONNECTIONS, 3>,
}

/// Main contributes module handlers to the common diagnostic registry. The
/// names are discovery/debug metadata only: dispatch below is exclusively by
/// numeric stream tag.
fn main_stream_registry() -> StreamRegistry {
    let mut registry = diagnostic_stream_registry();
    let _lora_registered = registry.register(SERVICE_LORA, b"lora");
    let _hardware_registered = registry.register(SERVICE_HARDWARE, b"hw");
    debug_assert!(_lora_registered && _hardware_registered);
    registry
}

impl ConnectionOwner {
    fn new() -> Self {
        Self {
            connections: ConnectionTable::new([
                PathState::new(), // raw-injected ESP-NOW action frame
                PathState::new(), // PPP UART
                PathState::new(), // STA UDP
            ]),
        }
    }
}

static CONNECTIONS: OnceLock<Mutex<ConnectionOwner>> = OnceLock::new();
static PASSIVE_ASSOCIATIONS: OnceLock<
    Mutex<PassiveAssociations<[u8; 6], MAX_PASSIVE_ASSOCIATIONS>>,
> = OnceLock::new();
static ASSOCIATION_EPOCH: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
static NEXT_CID: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0x2000);

/// Main owns only the lock and producer wiring. The bounded event record and
/// replacement policy are bearer-neutral dmesh-server state.
fn event_history() -> &'static Mutex<BinaryEventHistory> {
    static HISTORY: OnceLock<Mutex<BinaryEventHistory>> = OnceLock::new();
    HISTORY.get_or_init(|| Mutex::new(BinaryEventHistory::new(MODULE_EVENT_HISTORY)))
}

/// Publish one module callback unchanged for the common numeric `events`
/// stream. The record itself is generic: traces, logs, and hardware producers
/// use the same nonblocking bounded history.
pub fn publish_module_event(event_id: u16, value_type: u8, flags: u8, payload: &[u8]) -> bool {
    let Ok(mut history) = event_history().try_lock() else {
        return false;
    };
    history.push(event_id, value_type, flags, payload)
}

/// Main's `events` response is canonical CBOR `[next, [[seq,id,type,flags,
/// payload], ...]]`. The payload is copied unchanged from the module ABI.
/// `since=<u64>` is shared with the generic diagnostic events poll.
fn events_response(request: &[u8]) -> Result<Vec<u8>, &'static str> {
    let since = core::str::from_utf8(request)
        .ok()
        .and_then(|value| value.strip_prefix("since=")?.parse::<u64>().ok())
        .unwrap_or(0);
    let history = event_history()
        .lock()
        .map_err(|_| "module event history lock")?;
    let records: Vec<_> = history
        .records_since(since)
        .map(|event| BinaryEventRecord {
            sequence: event.sequence,
            event_id: event.event_id,
            value_type: event.value_type,
            flags: event.flags,
            payload: &event.payload,
        })
        .collect();
    encode_binary_events(history.next_sequence(), &records, MODULE_EVENT_RESPONSE_MAX)
        .ok_or("events encode")
}

fn connections() -> &'static Mutex<ConnectionOwner> {
    CONNECTIONS.get_or_init(|| Mutex::new(ConnectionOwner::new()))
}

fn now_ms() -> u64 {
    unsafe { (esp_idf_sys::esp_timer_get_time().max(0) as u64) / 1_000 }
}

fn remember_association(peer: [u8; 6], dcid: ConnectionId) {
    if peer == [0; 6] {
        return;
    }
    let associations = PASSIVE_ASSOCIATIONS.get_or_init(|| Mutex::new(PassiveAssociations::new()));
    if let Ok(mut associations) = associations.lock() {
        let seen = ASSOCIATION_EPOCH.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        associations.remember(peer, dcid, seen);
    }
}

/// Avoid an allocator abort when a busy relay has insufficient internal
/// byte-addressable RAM for another full mux. This is an admission decision,
/// not a passive-association limit: the peer remains remembered and may be
/// promoted once another active connection closes.
fn can_admit_active_connection() -> bool {
    let required = core::mem::size_of::<EspConnectionBinding>() + ACTIVE_CONNECTION_HEAP_RESERVE;
    unsafe { esp_idf_sys::esp_get_free_heap_size() as usize >= required }
}

fn allocate_cid(avoid: ConnectionId) -> Option<ConnectionId> {
    for _ in 0..1024 {
        let value = NEXT_CID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if let Some(cid) = ConnectionId::new(u64::from(value)) {
            if cid != avoid && cid.value() != 0 {
                return Some(cid);
            }
        }
    }
    None
}

/// Consume a complete raw-injected ESP-NOW datagram. Returns false only when
/// the payload is not a QUIC-lite short-header packet. Direct CBOR commands
/// are intentionally not accepted on this bearer.
pub fn receive_espnow(peer: [u8; 6], packet: &[u8]) -> bool {
    receive(peer, packet, ACTION_PATH, false)
}

/// Route a UART-marked datagram to the same DCID table. A zero peer is an L2
/// path label only; it never replaces an action-frame peer binding.
pub fn receive_uart(packet: &[u8]) -> bool {
    receive([0; 6], packet, UART_PATH, true)
}

/// Route a UDP datagram through the same DCID table as UART and ESP-NOW.
/// The caller retains the UDP peer address and sends this optional response
/// back on that bearer; the connection itself never knows socket details.
pub fn receive_udp(packet: &[u8]) -> Option<Vec<u8>> {
    receive_response([0; 6], packet, UDP_PATH, false)
}

/// Allocation-free bridge used by Main's optional raw UDP6 bearer. Connection
/// ownership remains in this Main-specific multipath table; the shared ESP
/// adapter only supplies the received Ethernet peer and caller-owned output.
pub fn receive_raw_udp6(packet: &[u8], output: &mut [u8; MTU]) -> Option<usize> {
    let response = receive_udp(packet)?;
    if response.len() > output.len() {
        return None;
    }
    output[..response.len()].copy_from_slice(&response);
    Some(response.len())
}

/// Bounded UDP egress after a bearer ingress drain. The socket loop, rather
/// than a single request/response callback, owns burst scheduling.
pub fn poll_udp() -> Option<Vec<u8>> {
    let mut active = connections().lock().ok()?;
    for (_, connection) in active.connections.iter_mut() {
        let Some(server) = connection.server.as_mut() else {
            continue;
        };
        let mut out = [0u8; MTU];
        if let Some(producer) = connection.iperf.as_mut() {
            if let Ok(Some((used, _))) = producer.poll(&mut server.mux.endpoint, &mut out) {
                if producer.is_complete() {
                    connection.iperf = None;
                    connection.iperf_finished = true;
                }
                return Some(out[..used].to_vec());
            }
        }
        if let Ok(Some(used)) = server.poll_transmit(&mut out) {
            return Some(out[..used].to_vec());
        }
    }
    None
}

fn receive(peer: [u8; 6], packet: &[u8], path: usize, uart: bool) -> bool {
    let Some(response) = receive_response(peer, packet, path, uart) else {
        return false;
    };
    if !response.is_empty() {
        if uart {
            let _ = super::serial::write_transport_packet(&response);
        } else {
            let _ = dmesh_fw_transport::wifi_espnow_esp::transmit(
                dmesh_fw_transport::wifi_espnow_esp::EspNowPeer { mac: peer },
                &response,
            );
        }
    }
    true
}

fn receive_response(peer: [u8; 6], packet: &[u8], path: usize, uart: bool) -> Option<Vec<u8>> {
    let Ok((header, _)) = ShortHeader::decode(packet) else {
        return None;
    };
    if header.flags & FLAG_FIXED == 0 || packet.len() > MTU {
        return Some(Vec::new());
    }
    // Today's services are request/response streams.  Reclaim their active
    // DCID slot after a final response so serial polling cannot exhaust the
    // small embedded connection table. A future persistent subscription sets
    // this only after its explicit close, not after each delivered record.
    let mut reclaim_after_response = None;
    let response = (|| -> Result<Vec<u8>> {
        let mut active = connections()
            .lock()
            .map_err(|_| anyhow!("action transport lock"))?;
        if header.dcid.value() == 0 {
            let now_ms = now_ms();
            let stale: Vec<ConnectionId> = active
                .connections
                .iter()
                .filter_map(|(_, connection)| {
                    (connection.server.is_some()
                        && connection.awaiting_first_request
                        && now_ms.saturating_sub(connection.opened_at_ms)
                            >= BOOTSTRAP_RESERVATION_MS)
                        .then_some(connection.dcid)
                })
                .collect();
            for cid in stale {
                let _ = active.connections.remove(cid);
            }
            let (_, open) = quic_lite::decode_bootstrap_open_packet_with_limits(packet)
                .map_err(|_| anyhow!("invalid action bootstrap"))?;
            let client = open.client_receive_cid;
            let server = active
                .connections
                .iter()
                .find(|(_, connection)| {
                    connection.peer == peer
                        && connection.server.as_ref().is_some_and(|server| {
                            server.mux.endpoint.peer_connection_id() == Some(client)
                        })
                })
                .and_then(|(_, connection)| {
                    connection
                        .server
                        .as_ref()
                        .and_then(|server| server.mux.endpoint.local_connection_id())
                })
                .or_else(|| allocate_cid(client))
                .ok_or_else(|| anyhow!("action CID exhausted"))?;
            let (server_connection, ack) =
                StreamServerConnection::accept_open(packet, server, main_stream_registry(), 16)
                    .map_err(|_| anyhow!("action bootstrap"))?;
            if !active.connections.iter().any(|(_, connection)| {
                connection.server.as_ref().is_some_and(|server_connection| {
                    server_connection.mux.endpoint.local_connection_id() == Some(server)
                })
            }) {
                if active.connections.len() >= MAX_ACTIVE_CONNECTIONS {
                    return Err(anyhow!("action connection capacity"));
                }
                if !can_admit_active_connection() {
                    return Err(anyhow!("action connection memory admission"));
                }
                active
                    .connections
                    .insert(
                        server,
                        Box::new(EspConnectionBinding {
                            dcid: server,
                            peer,
                            client: None,
                            server: Some(server_connection),
                            iperf: None,
                            iperf_finished: false,
                            opened_at_ms: now_ms,
                            awaiting_first_request: true,
                        }),
                    )
                    .map_err(|_| anyhow!("action DCID route capacity"))?;
                remember_association(peer, server);
            }
            return Ok(ack);
        }
        active
            .connections
            .set_path_available(path, true)
            .map_err(|_| anyhow!("action path unavailable"))?;
        let active_connections = active.connections.len();
        let slot = active
            .connections
            .route_mut(path, packet)
            .map_err(|_| anyhow!("unknown action DCID"))?;
        let connection = slot;
        connection.awaiting_first_request = false;
        if peer != [0; 6] && connection.peer != peer {
            return Err(anyhow!("action peer mismatch"));
        }
        if let Some(client_connection) = connection.client.as_mut() {
            let mut out = [0u8; MTU];
            let Some(used) = client_connection
                .receive_open_ack_and_request(packet, &mut out)
                .map_err(|_| anyhow!("action client OPEN ACK"))?
            else {
                return Ok(Vec::new());
            };
            return Ok(out[..used].to_vec());
        }
        let server_connection = connection
            .server
            .as_mut()
            .ok_or_else(|| anyhow!("connection has no server state"))?;
        let request = server_connection
            .receive_request(packet)
            .map_err(|_| anyhow!("action packet"))?;
        let mut out = [0u8; MTU];
        if let Some(request) = request {
            let Some((&service, body)) = request.data.split_first() else {
                return Err(anyhow!("empty action service"));
            };
            let cid = server_connection
                .mux
                .endpoint
                .local_connection_id()
                .unwrap();
            // A sleepy node may have entered this connection after an
            // explicit NAN/UART bootstrap. Keep its STA session alive for
            // the whole handler transaction; the session owner adds the
            // short grace tail after the final stream completes.
            super::transport_runtime::stream_started();
            if service == SERVICE_IPERF {
                let request_stream_id = request.stream_id;
                let request_len = request.data.len();
                let request = decode_iperf_service_request(&request.data)
                    .ok_or_else(|| anyhow!("invalid iperf request"))?;
                if connection.iperf.is_some() {
                    return Err(anyhow!("iperf transfer already active"));
                }
                // Shared with the host listener: accept and normalize the
                // exact same handler request before the ESP bearer drives
                // its bounded producers. No UART/UDP/ESP-NOW branch gets a
                // private packet size, stream count, or ACK interpretation.
                let plan = IperfServicePlan::from_request(request, MTU - 32);
                server_connection
                    .mux
                    .complete_request(request_stream_id, request_len)
                    .map_err(|_| anyhow!("iperf request accounting"))?;
                server_connection
                    .mux
                    .endpoint
                    .request_ack_frequency(
                        0,
                        u64::from(plan.ack_frequency.saturating_sub(1)),
                        u64::from(plan.ack_delay_ms) * 1_000,
                        1,
                    )
                    .map_err(|_| anyhow!("iperf ACK_FREQUENCY"))?;
                connection.iperf = IperfProducers::new(plan, server_connection);
                let producer = connection
                    .iperf
                    .as_mut()
                    .ok_or_else(|| anyhow!("iperf producer allocation"))?;
                let Some((used, _)) = producer
                    .poll(&mut server_connection.mux.endpoint, &mut out)
                    .map_err(|_| anyhow!("iperf first packet"))?
                else {
                    return Err(anyhow!("iperf initial peer credit"));
                };
                if producer.is_complete() {
                    connection.iperf = None;
                    connection.iperf_finished = true;
                }
                return Ok(out[..used].to_vec());
            }
            reclaim_after_response = Some(cid);
            let response = if service == SERVICE_CONTROL {
                match body.split_first() {
                    Some((subtype, policy_body)) if *subtype == CONTROL_PATH_POLICY => {
                        if let Some(policy) = decode_path_policy(policy_body) {
                            server_connection.set_path_policy(policy);
                            Ok(encode_path_policy_response(policy))
                        } else {
                            Err("invalid path policy")
                        }
                    }
                    Some(_) => Err("unsupported control request"),
                    None => Err("control request missing subtype"),
                }
            } else if service == SERVICE_LOG_WATCH {
                // Log production was already completed before this request:
                // pop at most one intact record, never wait for a producer or
                // generate a background transport task. A caller that wants
                // more records issues bounded follow-up watch requests.
                Ok(super::telemetry::take_log_stream_record()
                    .map(|record| record.bytes().to_vec())
                    .unwrap_or_default())
            } else if service == SERVICE_EVENTS {
                events_response(body)
            } else if service == SERVICE_HARDWARE && body.starts_with(HARDWARE_ESPNOW_ACTION_PREFIX)
            {
                let bytes = send_hardware_espnow_action(body).map_err(anyhow::Error::msg)?;
                Ok(format!("espnow_action_sent bytes={bytes}").into_bytes())
            } else if service == SERVICE_HARDWARE
                && body.starts_with(HARDWARE_NAN_VENDOR_IE_PROBE_PREFIX)
            {
                start_hardware_nan_vendor_ie_probe(body).map_err(anyhow::Error::msg)?;
                Ok(b"nan_vendor_ie_beacon_probe_started".to_vec())
            } else if service == SERVICE_HARDWARE
                && body.starts_with(HARDWARE_NAN_PUBLIC_ACTION_PREFIX)
            {
                send_hardware_nan_public_action(body).map_err(anyhow::Error::msg)?;
                Ok(b"nan_public_action_sent".to_vec())
            } else if service == SERVICE_HARDWARE {
                if let Ok(request) = dmesh_server::raw_wifi::decode_raw_wifi_handler(body) {
                    let mut response = [0u8; 192];
                    let used = dmesh_fw_transport::wifi_radio_lab_esp::handle_encoded(
                        request,
                        &mut response,
                    )
                    .map_err(anyhow::Error::msg)?;
                    Ok(response[..used].to_vec())
                } else {
                    match inject_hardware_raw_80211(body) {
                        Ok(bytes) => Ok(format!("raw80211_sent bytes={bytes}").into_bytes()),
                        Err("hardware raw CBOR") => {
                            if super::module::enqueue_stream_service(service, body) {
                                Ok(vec![0x81, 0x00])
                            } else {
                                Err("module stream queue full or invalid request")
                            }
                        }
                        Err(error) => Err(error),
                    }
                }
            } else if service == SERVICE_LORA {
                // Module tasks must never run on a UART/UDP/ESP-NOW bearer
                // task. A bounded Main-owned queue gives this stream an
                // immediate result without bypassing flow control. [0] is
                // the compact CBOR response "accepted"; completion is an
                // asynchronous module event/log record.
                if super::module::enqueue_stream_service(service, body) {
                    Ok(vec![0x81, 0x00])
                } else {
                    Err("module stream queue full or invalid request")
                }
            } else if service == SERVICE_STATUS {
                let mut status = handle_stream_with_events(
                    &server_connection.mux.endpoint,
                    Some(&server_connection.events),
                    cid,
                    request.stream_id,
                    &server_connection.registry,
                    service,
                    body,
                )
                .map_err(|error| anyhow!(error))?;
                let uart = dmesh_fw_transport::uart_esp::uart_l2_stats();
                let raw = dmesh_fw_transport::wifi_raw_udp6_esp::stats();
                let raw_start_status = dmesh_fw_transport::wifi_raw_udp6_esp::start_status();
                let espnow_client = dmesh_fw_transport::wifi_espnow_esp::raw_client_result();
                let espnow_client = (0, 0, 0);
                let espnow = dmesh_fw_transport::wifi_espnow_esp::stats();
                let espnow_rx_diagnostics =
                    dmesh_fw_transport::wifi_espnow_esp::receive_diagnostics();
                let espnow_client_diagnostics =
                    dmesh_fw_transport::wifi_espnow_esp::client_diagnostics();
                let espnow = (0, 0, 0, 0);
                let espnow_rx_diagnostics = (0, 0, 0, 0);
                let espnow_client_diagnostics = (0, 0, 0, 0, 0, 0, 0);
                let wifi_promiscuous = dmesh_fw_transport::wifi_esp::promiscuous_enabled()
                    .map(u8::from)
                    .unwrap_or(u8::MAX);
                let nan_dw_sync = dmesh_fw_transport::wifi_nan_dw_capture_esp::sync_diagnostics();
                let nan_dw_sync = ([0; 6], 0, false);
                status.extend_from_slice(
                    format!(
                        ";build_timestamp={};active_connections={};uart_l2_baud={};uart_l2_rx_events={};uart_l2_rx_bytes={};raw_start_status={raw_start_status};raw_rx={};raw_drops={};raw_invalid={};raw_delivered={};raw_tx={};raw_tx_failures={};espnow_rx={};espnow_drops={};espnow_tx={};espnow_tx_failures={};espnow_dispatcher_rx={};espnow_tx_hook_rx={};espnow_parse_drops={};espnow_self_echoes={};espnow_client_peer_mismatches={};espnow_client_receive_ok={};espnow_client_receive_errors={};espnow_client_last_error={};espnow_client_bootstrap_acks={};espnow_client_stream_packets={};espnow_client_other_packets={};espnow_client_bytes={};espnow_client_errors={};espnow_client_elapsed_us={};nan_dw_bssid={:02x}{:02x}{:02x}{:02x}{:02x}{:02x};nan_dw_anchor_us={};nan_dw_capturing={};wifi_promiscuous={wifi_promiscuous}",
                        env!("DMESH_BUILD_TIMESTAMP"),
                        active_connections,
                        uart.physical_baud,
                        uart.rx_events,
                        uart.rx_bytes,
                        raw.0,
                        raw.1,
                        raw.2,
                        raw.3,
                        raw.4,
                        raw.5,
                        espnow.0,
                        espnow.1,
                        espnow.2,
                        espnow.3,
                        espnow_rx_diagnostics.0,
                        espnow_rx_diagnostics.1,
                        espnow_rx_diagnostics.2,
                        espnow_rx_diagnostics.3,
                        espnow_client_diagnostics.0,
                        espnow_client_diagnostics.1,
                        espnow_client_diagnostics.2,
                        espnow_client_diagnostics.3,
                        espnow_client_diagnostics.4,
                        espnow_client_diagnostics.5,
                        espnow_client_diagnostics.6,
                        espnow_client.0,
                        espnow_client.1,
                        espnow_client.2,
                        nan_dw_sync.0[0], nan_dw_sync.0[1], nan_dw_sync.0[2],
                        nan_dw_sync.0[3], nan_dw_sync.0[4], nan_dw_sync.0[5],
                        nan_dw_sync.1,
                        u8::from(nan_dw_sync.2),
                    )
                    .as_bytes(),
                );
                Ok(status)
            } else {
                handle_stream_with_events(
                    &server_connection.mux.endpoint,
                    Some(&server_connection.events),
                    cid,
                    request.stream_id,
                    &server_connection.registry,
                    service,
                    body,
                )
            };
            super::transport_runtime::stream_completed();
            // Preserve the adapter error on the direct UART diagnostic path.
            // In particular, raw 802.11 lab injection needs to distinguish a
            // frame-format rejection from an interface/rate-policy error;
            // collapsing either to "action service" makes a non-promiscuous
            // RX experiment impossible to interpret.
            let body = response.map_err(|error| anyhow!("action service: {error}"))?;
            let (used, _) = server_connection
                .encode_response(&body, &mut out)
                .map_err(|_| anyhow!("action response"))?;
            return Ok(out[..used].to_vec());
        }
        if let Some(producer) = connection.iperf.as_mut() {
            if let Some((used, _)) = producer
                .poll(&mut server_connection.mux.endpoint, &mut out)
                .map_err(|_| anyhow!("iperf packet"))?
            {
                if producer.is_complete() {
                    connection.iperf = None;
                    connection.iperf_finished = true;
                }
                return Ok(out[..used].to_vec());
            }
        }
        // A bearer retry (or a later ACK) is also the bounded timer wake for
        // this connection. Recover one due QUIC-lite packet before emitting
        // ordinary ACK/window control; otherwise a lost first IPERF frame can
        // leave the one-slot embedded ledger full forever. The endpoint owns
        // the PTO gate, so repeated UDP/UART input cannot create a flood.
        let now_ms = unsafe { (esp_idf_sys::esp_timer_get_time().max(0) as u64 / 1_000) };
        server_connection.mux.endpoint.set_time(now_ms);
        let pto = server_connection.mux.endpoint.pto_timeout();
        if let Some((used, _)) = server_connection
            .mux
            .endpoint
            .retransmit_due(now_ms, pto, &mut out)
            .map_err(|_| anyhow!("iperf retransmit"))?
        {
            return Ok(out[..used].to_vec());
        }
        if connection.iperf_finished {
            let cid = server_connection
                .mux
                .endpoint
                .local_connection_id()
                .ok_or_else(|| anyhow!("iperf connection CID"))?;
            reclaim_after_response = Some(cid);
        }
        let Some(used) = server_connection
            .poll_transmit(&mut out)
            .map_err(|_| anyhow!("action ACK"))?
        else {
            return Ok(Vec::new());
        };
        Ok(out[..used].to_vec())
    })();
    if let Some(cid) = reclaim_after_response {
        if let Ok(mut active) = connections().lock() {
            let _ = active.connections.remove(cid);
        }
    }
    match response {
        Ok(response) => Some(response),
        Err(error) => {
            // Every bearer records dispatch failures in the bounded log
            // service. UART additionally mirrors this single breadcrumb as
            // direct text because it is the baseline when QUIC-lite itself
            // is under investigation.
            super::telemetry::record_log(format!(
                "event type=transport.dispatch_error path={path} message={error}"
            ));
            // The stream response itself cannot report a dispatch failure if
            // it was never encoded.  During UART-QUIC bring-up retain one
            // deliberately narrow escape hatch: a complete text PPP record
            // owned by the UART L2 writer.  It lets the serial owner report
            // parser/credit/dispatch failures without reviving raw CBOR
            // commands or making normal firmware logs bypass streams.
            if uart {
                let diagnostic = format!("uart-quic-error={error}");
                let _ = super::serial::write_direct_record(diagnostic.as_bytes());
            }
            None
        }
    }
}

/// Send a portable raw NOW-like payload without creating a QUIC-lite client.
/// This keeps the receive-filter test distinct from connection admission,
/// loss recovery, or IPERF scheduling.
fn send_hardware_espnow_action(body: &[u8]) -> Result<usize, &'static str> {
    let value = body
        .strip_prefix(HARDWARE_ESPNOW_ACTION_PREFIX)
        .ok_or("hardware request prefix")?;
    if value.len() < 7 {
        return Err("hardware espnow action must contain destination plus payload");
    }
    let destination: [u8; 6] = value[..6]
        .try_into()
        .map_err(|_| "hardware espnow destination")?;
    let payload = &value[6..];
    if payload.len() > dmesh_rawnan::espnow::MAX_ACTION_PAYLOAD {
        return Err("hardware espnow action payload too large");
    }
    if dmesh_fw_transport::wifi_espnow_esp::transmit(
        dmesh_fw_transport::wifi_espnow_esp::EspNowPeer { mac: destination },
        payload,
    ) {
        Ok(payload.len())
    } else {
        Err("hardware espnow action transmission failed")
    }
}

fn start_hardware_nan_vendor_ie_probe(body: &[u8]) -> Result<(), &'static str> {
    let channel = body
        .strip_prefix(HARDWARE_NAN_VENDOR_IE_PROBE_PREFIX)
        .ok_or("hardware request prefix")?;
    let channel = match channel {
        [] => 6,
        [channel] if (1..=13).contains(channel) => *channel,
        _ => return Err("hardware NAN vendor-IE probe channel must be one byte 1..13"),
    };
    super::wifi::start_nan_vendor_ie_beacon_probe(channel)
        .map_err(|_| "could not start NAN vendor-IE beacon probe")
}

/// Hardware request: `nan-public-action:` followed by destination MAC,
/// BSSID, and complete public-action body. The host uses the portable rawnan
/// SDF/follow-up builders; this adapter only selects the ESP action-TX lane.
fn send_hardware_nan_public_action(body: &[u8]) -> Result<(), &'static str> {
    let value = body
        .strip_prefix(HARDWARE_NAN_PUBLIC_ACTION_PREFIX)
        .ok_or("hardware NAN action prefix")?;
    if value.len() < 18 || !value[12..].starts_with(&[0x04, 0x09, 0x50, 0x6f, 0x9a, 0x13]) {
        return Err("hardware NAN action requires destination, BSSID, and public NAN body");
    }
    let destination: [u8; 6] = value[..6]
        .try_into()
        .map_err(|_| "hardware NAN destination")?;
    let bssid: [u8; 6] = value[6..12].try_into().map_err(|_| "hardware NAN BSSID")?;
    if dmesh_fw_transport::wifi_espnow_esp::transmit_public_action(destination, bssid, &value[12..])
    {
        Ok(())
    } else {
        Err("hardware NAN action transmission failed")
    }
}

fn inject_hardware_raw_80211(body: &[u8]) -> Result<usize, &'static str> {
    let request =
        dmesh_server::raw_wifi::decode_raw_wifi_tx(body).map_err(|_| "hardware raw CBOR")?;
    let bytes = request.frame.len();
    if let Err(error) = super::wifi::apply_raw_wifi_tx_for_lab(request) {
        // The client receives a stable compact error, while the detailed
        // driver return stays in the bounded firmware log for the paired
        // e7->e6 raw-action experiment.
        super::telemetry::record_log(format!(
            "event type=wifi.raw_lab_tx ok=false error={}",
            crate::commands::protocol::escape_value(&error.to_string())
        ));
        return Err("hardware raw injection failed");
    }
    Ok(bytes)
}

/// Main's only UART-specific policy callback. Framing, admission and egress
/// are all in `dmesh-fw-transport`, shared with Recovery.
pub fn dispatch_uart_ingress(
    _item: dmesh_fw_transport::shared_ingress_esp::IngressPacket,
    packet: &[u8],
) {
    // A valid framed packet is also the in-band wake for Main's bounded
    // console window.  Arm egress before processing its OPEN so the
    // bootstrap ACK is not dropped by `write_transport_packet`.
    super::serial::activate_window();
    let _ = receive_uart(packet);
}

/// Raw PPP record callback. It bypasses QUIC-lite but still uses the same
/// common bounded ingress worker and raw-record egress as Recovery.
pub fn dispatch_uart_raw_ingress(
    _item: dmesh_fw_transport::shared_ingress_esp::IngressPacket,
    record: &[u8],
) {
    if let Ok(request) = dmesh_server::raw_wifi::decode_raw_wifi_handler(record) {
        let mut response = [0u8; 192];
        match dmesh_fw_transport::wifi_radio_lab_esp::handle_encoded(request, &mut response) {
            Ok(used) => {
                let _ = super::serial::write_direct_record(&response[..used]);
            }
            Err(error) => {
                // Raw PPP is an operational diagnostic path.  Return an
                // explicit bounded record on the same bearer so host tests
                // can distinguish an unavailable radio client from a UART
                // timeout; the identical CBOR request is usable on streams.
                let _ = super::serial::write_direct_record(error.as_bytes());
                let _ = super::telemetry::record_log(format!(
                    "event type=radio.lab error={}",
                    crate::commands::protocol::escape_value(error)
                ));
            }
        }
        return;
    }
    if let Ok(request) = dmesh_server::raw_wifi::decode_raw_wifi_tx(record) {
        match dmesh_fw_transport::wifi_radio_lab_esp::transmit_raw_action(request) {
            Ok(bytes) => {
                let _ = super::serial::write_direct_record(
                    format!("radio raw action sent bytes={bytes}").as_bytes(),
                );
            }
            Err(error) => {
                let _ = super::serial::write_direct_record(error.as_bytes());
            }
        }
        return;
    }
    if !super::transport_runtime::apply_direct_record(record) {
        super::telemetry::record_log(format!(
            "event type=direct_record rejected=true bytes={}",
            record.len()
        ));
    }
}
