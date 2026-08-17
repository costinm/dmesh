//! QUIC-lite server attachment for raw-injected ESP-NOW action-frame data.
//!
//! NAN discovers peers; this module owns only complete action-frame datagrams
//! and routes them by DCID. It is intentionally independent of NAN state.

use anyhow::{anyhow, Result};
use dmesh_server::services::{
    handle_stream_with_events, EventRing, StreamRegistry, SERVICE_LOG_WATCH,
};
use quic_lite::mux::StreamMux;
use quic_lite::{
    BootstrapClient, ConnectionId, ConnectionLimits, ConnectionTable, PathState, Role, ShortHeader,
    FIRST_CLIENT_BIDI_STREAM_ID, FLAG_FIXED, INITIAL_MAX_STREAM_DATA, SERVICE_IPERF,
};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};
use std::thread;
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
const ACTIVE_HISTORY_PACKETS: usize = 1;
const ACTIVE_CONNECTION_HEAP_RESERVE: usize = 16 * 1024;
const MTU: usize = quic_lite::DEFAULT_MAX_DATAGRAM_SIZE;
const ACTION_PATH: usize = 0;
const UART_PATH: usize = 1;
const UDP_PATH: usize = 2;
/// All IP bearers use the same QUIC-lite port. This is an L2 adapter socket,
/// not a TCP command listener.
pub const UDP_TRANSPORT_PORT: u16 = 3339;

struct Connection {
    peer: [u8; 6],
    mux: StreamMux<4, ACTIVE_HISTORY_PACKETS>,
    /// Present only while a locally initiated connection awaits its OPEN ACK.
    bootstrap: Option<BootstrapClient>,
    /// One request may be queued before OPEN_ACK. It is encoded only after
    /// the peer CID and advertised transport credits are installed.
    pending_client_request: Option<Vec<u8>>,
    registry: StreamRegistry,
    events: EventRing,
}

#[derive(Clone, Copy)]
struct PassiveAssociation {
    peer: [u8; 6],
    dcid: ConnectionId,
    seen: u32,
}

struct PassiveAssociations {
    entries: [Option<PassiveAssociation>; MAX_PASSIVE_ASSOCIATIONS],
}

impl PassiveAssociations {
    fn new() -> Self {
        Self {
            entries: [None; MAX_PASSIVE_ASSOCIATIONS],
        }
    }

    fn remember(&mut self, peer: [u8; 6], dcid: ConnectionId) {
        if peer == [0; 6] {
            return;
        }
        let seen = ASSOCIATION_EPOCH.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if let Some(entry) = self
            .entries
            .iter_mut()
            .find(|entry| entry.is_some_and(|entry| entry.peer == peer))
        {
            *entry = Some(PassiveAssociation { peer, dcid, seen });
            return;
        }
        if let Some(entry) = self.entries.iter_mut().find(|entry| entry.is_none()) {
            *entry = Some(PassiveAssociation { peer, dcid, seen });
            return;
        }
        let oldest = self
            .entries
            .iter()
            .enumerate()
            .min_by_key(|(_, entry)| entry.map(|entry| entry.seen).unwrap_or(u32::MAX))
            .map(|(index, _)| index)
            .expect("passive association cache has fixed nonzero capacity");
        self.entries[oldest] = Some(PassiveAssociation { peer, dcid, seen });
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
        let mut bootstrap = BootstrapClient::new(client, 500_000, 4)
            .map_err(|_| anyhow!("action client bootstrap"))?;
        let mut open = [0u8; MTU];
        let used = bootstrap
            .start_open(0, &mut open)
            .map_err(|_| anyhow!("action client OPEN"))?;
        let mux = StreamMux::new(
            Role::Client,
            ConnectionLimits::default(),
            MTU as u64,
            1,
            4,
            4096,
        );
        active
            .connections
            .insert(
                client,
                Box::new(Connection {
                    peer,
                    mux,
                    bootstrap: Some(bootstrap),
                    pending_client_request: request,
                    registry: StreamRegistry::default(),
                    events: EventRing::new(16),
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
    wifi::send_espnow_payload_to(peer, &open)
        .map_err(|error| anyhow!("ESP-NOW client OPEN send: {error}"))?;
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
    connections: ConnectionTable<Box<Connection>, MAX_ACTIVE_CONNECTIONS, 3>,
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
static PASSIVE_ASSOCIATIONS: OnceLock<Mutex<PassiveAssociations>> = OnceLock::new();
static ASSOCIATION_EPOCH: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
static NEXT_CID: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0x2000);
static UDP_BEARER_ENABLED: AtomicBool = AtomicBool::new(false);
static UDP_BEARER_STARTED: AtomicBool = AtomicBool::new(false);

fn connections() -> &'static Mutex<ConnectionOwner> {
    CONNECTIONS.get_or_init(|| Mutex::new(ConnectionOwner::new()))
}

fn remember_association(peer: [u8; 6], dcid: ConnectionId) {
    let associations = PASSIVE_ASSOCIATIONS.get_or_init(|| Mutex::new(PassiveAssociations::new()));
    if let Ok(mut associations) = associations.lock() {
        associations.remember(peer, dcid);
    }
}

/// Avoid an allocator abort when a busy relay has insufficient internal
/// byte-addressable RAM for another full mux. This is an admission decision,
/// not a passive-association limit: the peer remains remembered and may be
/// promoted once another active connection closes.
fn can_admit_active_connection() -> bool {
    let required = core::mem::size_of::<Connection>() + ACTIVE_CONNECTION_HEAP_RESERVE;
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

fn receive(peer: [u8; 6], packet: &[u8], path: usize, uart: bool) -> bool {
    let Some(response) = receive_response(peer, packet, path, uart) else {
        return false;
    };
    if !response.is_empty() {
        if uart {
            let _ = super::serial::write_transport_packet(&response);
        } else {
            let _ = wifi::send_espnow_payload_to(peer, &response);
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
    let response = (|| -> Result<Vec<u8>> {
        let mut active = connections()
            .lock()
            .map_err(|_| anyhow!("action transport lock"))?;
        if header.dcid.value() == 0 {
            let (_, client) = quic_lite::decode_bootstrap_open_packet(packet)
                .map_err(|_| anyhow!("invalid action bootstrap"))?;
            let server = active
                .connections
                .iter()
                .find(|(_, connection)| {
                    connection.peer == peer
                        && connection.mux.endpoint.peer_connection_id() == Some(client)
                })
                .and_then(|(_, connection)| connection.mux.endpoint.local_connection_id())
                .or_else(|| allocate_cid(client))
                .ok_or_else(|| anyhow!("action CID exhausted"))?;
            let mut ack = [0u8; MTU];
            let used = quic_lite::encode_bootstrap_open_ack_packet(client, server, 0, &mut ack)
                .map_err(|_| anyhow!("action bootstrap ACK"))?;
            if !active.connections.iter().any(|(_, connection)| {
                connection.mux.endpoint.local_connection_id() == Some(server)
            }) {
                if active.connections.len() >= MAX_ACTIVE_CONNECTIONS {
                    return Err(anyhow!("action connection capacity"));
                }
                if !can_admit_active_connection() {
                    return Err(anyhow!("action connection memory admission"));
                }
                let mut mux = StreamMux::new(
                    quic_lite::Role::Server,
                    ConnectionLimits::default(),
                    MTU as u64,
                    1,
                    4,
                    4096,
                );
                mux.install_connection_ids(server, client)
                    .map_err(|_| anyhow!("action CIDs"))?;
                active
                    .connections
                    .insert(
                        server,
                        Box::new(Connection {
                            peer,
                            mux,
                            bootstrap: None,
                            pending_client_request: None,
                            registry: StreamRegistry::default(),
                            events: EventRing::new(16),
                        }),
                    )
                    .map_err(|_| anyhow!("action DCID route capacity"))?;
                remember_association(peer, server);
            }
            return Ok(ack[..used].to_vec());
        }
        active
            .connections
            .set_path_available(path, true)
            .map_err(|_| anyhow!("action path unavailable"))?;
        let slot = active
            .connections
            .route_mut(path, packet)
            .map_err(|_| anyhow!("unknown action DCID"))?;
        let connection = slot;
        if peer != [0; 6] && connection.peer != peer {
            return Err(anyhow!("action peer mismatch"));
        }
        if let Some(bootstrap) = connection.bootstrap.as_mut() {
            let server = bootstrap
                .on_open_ack(packet)
                .map_err(|_| anyhow!("action client OPEN ACK"))?;
            connection
                .mux
                .install_connection_ids(bootstrap.local_cid(), server)
                .map_err(|_| anyhow!("action client CIDs"))?;
            connection.bootstrap = None;
            let Some(request) = connection.pending_client_request.take() else {
                return Ok(Vec::new());
            };
            connection
                .mux
                .endpoint
                .open_send_stream(FIRST_CLIENT_BIDI_STREAM_ID, INITIAL_MAX_STREAM_DATA)
                .map_err(|_| anyhow!("action client stream"))?;
            let mut out = [0u8; MTU];
            let (used, _) = connection
                .mux
                .endpoint
                .encode_stream_packet(
                    server,
                    FIRST_CLIENT_BIDI_STREAM_ID,
                    0,
                    true,
                    &request,
                    &mut out,
                )
                .map_err(|_| anyhow!("action client request"))?;
            return Ok(out[..used].to_vec());
        }
        let request = connection
            .mux
            .receive_request(packet)
            .map_err(|_| anyhow!("action packet"))?;
        let mut out = [0u8; MTU];
        if let Some(request) = request {
            let Some((&service, body)) = request.data.split_first() else {
                return Err(anyhow!("empty action service"));
            };
            let cid = connection.mux.endpoint.local_connection_id().unwrap();
            // A sleepy node may have entered this connection after an
            // explicit NAN/UART bootstrap. Keep its STA session alive for
            // the whole handler transaction; the session owner adds the
            // short grace tail after the final stream completes.
            super::transport_runtime::stream_started();
            let response = if service == SERVICE_LOG_WATCH {
                // Log production was already completed before this request:
                // pop at most one intact record, never wait for a producer or
                // generate a background transport task. A caller that wants
                // more records issues bounded follow-up watch requests.
                Ok(super::telemetry::take_log_stream_record()
                    .map(|record| record.bytes().to_vec())
                    .unwrap_or_default())
            } else {
                handle_stream_with_events(
                    &connection.mux.endpoint,
                    Some(&connection.events),
                    cid,
                    request.stream_id,
                    &connection.registry,
                    service,
                    body,
                )
            };
            super::transport_runtime::stream_completed();
            let body = response.map_err(|_| anyhow!("action service"))?;
            let (used, _) = connection
                .mux
                .encode_response(request.stream_id, &body, true, &mut out)
                .map_err(|_| anyhow!("action response"))?;
            return Ok(out[..used].to_vec());
        }
        let Some(used) = connection
            .mux
            .endpoint
            .poll_transmit(&mut out)
            .map_err(|_| anyhow!("action ACK"))?
        else {
            return Ok(Vec::new());
        };
        Ok(out[..used].to_vec())
    })();
    response.ok()
}

/// Enable or suspend Main's UDP bearer without creating another transport
/// endpoint. The task performs only nonblocking receives and yields to
/// FreeRTOS between polls; STA association stays owned by `transport_runtime`.
pub fn set_udp_bearer_enabled(enabled: bool) {
    UDP_BEARER_ENABLED.store(enabled, Ordering::Release);
    if !enabled || UDP_BEARER_STARTED.swap(true, Ordering::AcqRel) {
        return;
    }
    let _ = thread::Builder::new()
        .name("dmesh-udp-l2".to_owned())
        .spawn(udp_bearer_task);
}

fn udp_bearer_task() {
    loop {
        if !UDP_BEARER_ENABLED.load(Ordering::Acquire) {
            unsafe { esp_idf_sys::vTaskDelay(10) };
            continue;
        }
        let fd = unsafe {
            esp_idf_sys::lwip_socket(
                esp_idf_sys::AF_INET as _,
                esp_idf_sys::SOCK_DGRAM as _,
                esp_idf_sys::IPPROTO_UDP as _,
            )
        };
        if fd < 0 {
            unsafe { esp_idf_sys::vTaskDelay(10) };
            continue;
        }
        let local = esp_idf_sys::sockaddr_in {
            sin_len: core::mem::size_of::<esp_idf_sys::sockaddr_in>() as u8,
            sin_family: esp_idf_sys::AF_INET as u8,
            sin_port: UDP_TRANSPORT_PORT.to_be(),
            sin_addr: esp_idf_sys::in_addr { s_addr: 0 },
            sin_zero: [0; 8],
        };
        let bound = unsafe {
            esp_idf_sys::lwip_bind(
                fd,
                (&local as *const esp_idf_sys::sockaddr_in).cast(),
                core::mem::size_of::<esp_idf_sys::sockaddr_in>() as _,
            ) == 0
        };
        if !bound {
            unsafe { esp_idf_sys::lwip_close(fd) };
            unsafe { esp_idf_sys::vTaskDelay(10) };
            continue;
        }
        // The transport task must not block the FreeRTOS scheduler. Mark the
        // socket nonblocking and let the task yield on an empty receive.
        unsafe {
            let flags = esp_idf_sys::fcntl(fd, esp_idf_sys::F_GETFL);
            if flags >= 0 {
                let _ =
                    esp_idf_sys::fcntl(fd, esp_idf_sys::F_SETFL, flags | esp_idf_sys::O_NONBLOCK);
            }
        }
        let mut packet = [0u8; MTU];
        while UDP_BEARER_ENABLED.load(Ordering::Acquire) {
            let mut peer = esp_idf_sys::sockaddr_in::default();
            let mut peer_len = core::mem::size_of::<esp_idf_sys::sockaddr_in>() as _;
            let received = unsafe {
                esp_idf_sys::lwip_recvfrom(
                    fd,
                    packet.as_mut_ptr().cast(),
                    packet.len(),
                    0,
                    (&mut peer as *mut esp_idf_sys::sockaddr_in).cast(),
                    &mut peer_len,
                )
            };
            if received > 0 {
                if let Some(response) = receive_udp(&packet[..received as usize]) {
                    if !response.is_empty() {
                        unsafe {
                            let _ = esp_idf_sys::lwip_sendto(
                                fd,
                                response.as_ptr().cast(),
                                response.len(),
                                0,
                                (&peer as *const esp_idf_sys::sockaddr_in).cast(),
                                peer_len,
                            );
                        }
                    }
                }
            } else {
                unsafe { esp_idf_sys::vTaskDelay(1) };
            }
        }
        unsafe { esp_idf_sys::lwip_close(fd) };
    }
}
