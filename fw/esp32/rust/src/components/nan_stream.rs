//! DMesh transport over the ESP32 NAN follow-up bearer.
//!
//! This module is deliberately an adapter, not a second transport. NAN owns
//! peer addressing and bounded radio queues in `nan.rs`; the shared
//! `dmesh-transport` endpoint owns packet numbers, ACKs, flow control,
//! retransmission, stream reassembly, and the bearer-neutral handlers.

use anyhow::{anyhow, bail, Result};
use dmesh_transport::mux::StreamMux;
use dmesh_transport::{
    decode_frame, ConnectionId, ConnectionLimits, DatagramBearer, Error as TransportError, Role,
    ShortHeader,
};
use std::collections::VecDeque;
use std::sync::{Mutex, OnceLock};
use std::vec::Vec;

use super::nan;

// NAN fragments are reassembled by the bearer adapter before transport sees a
// packet. Keep this equal to the normal ESP32 transport profile.
const MAX_DATAGRAM: usize = dmesh_transport::DEFAULT_MAX_DATAGRAM_SIZE;
const MAX_NAN_SESSIONS: usize = 4;
const MAX_PENDING_RESPONSES: usize = 4;
const BOOTSTRAP_RETRY_MS: u64 = 500;
const BOOTSTRAP_ATTEMPTS: u8 = 4;

enum ManagedState {
    Opening {
        local: ConnectionId,
        packet: Vec<u8>,
        last_sent_ms: u64,
        packet_number: u32,
        attempts: u8,
    },
    Established(NanStreamSession),
}

struct ManagedSession {
    peer: [u8; 6],
    state: ManagedState,
}

static SESSIONS: OnceLock<Mutex<Vec<ManagedSession>>> = OnceLock::new();

fn sessions() -> &'static Mutex<Vec<ManagedSession>> {
    SESSIONS.get_or_init(|| Mutex::new(Vec::with_capacity(MAX_NAN_SESSIONS)))
}

fn allocate_server_cid(avoid: ConnectionId) -> ConnectionId {
    // This is a forwarding label, not an identity. A production allocator can
    // replace this deterministic fallback once device entropy is available.
    static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0x1000);
    loop {
        let value = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if let Some(cid) = ConnectionId::new(u64::from(value)) {
            if cid.value() != 0 && cid != avoid {
                return cid;
            }
        }
    }
}

/// Encode the client side of the version-0 short-header bootstrap.
pub fn encode_bootstrap_open(
    client_receive_cid: ConnectionId,
    packet_number: u32,
    out: &mut [u8],
) -> Result<usize> {
    dmesh_transport::encode_bootstrap_open_packet(client_receive_cid, packet_number, out)
        .map_err(|error| anyhow!("NAN OPEN encode failed: {error:?}"))
}

/// Validate an OPEN and encode the server's directional OPEN_ACK. The caller
/// allocates the server receive CID only after this succeeds and installs its
/// peer route using the returned client CID.
pub fn accept_bootstrap_open(
    input: &[u8],
    server_receive_cid: ConnectionId,
    packet_number: u32,
    out: &mut [u8],
) -> Result<ConnectionId> {
    let (_, client_cid) = dmesh_transport::decode_bootstrap_open_packet(input)
        .map_err(|error| anyhow!("NAN OPEN decode failed: {error:?}"))?;
    dmesh_transport::encode_bootstrap_open_ack_packet(
        client_cid,
        server_receive_cid,
        packet_number,
        out,
    )
    .map_err(|error| anyhow!("NAN OPEN_ACK encode failed: {error:?}"))?;
    Ok(client_cid)
}

/// Validate a server OPEN_ACK and return the server receive CID to install as
/// the client's peer CID.
pub fn accept_bootstrap_open_ack(
    input: &[u8],
    client_receive_cid: ConnectionId,
) -> Result<ConnectionId> {
    let (_, server_cid) = dmesh_transport::decode_bootstrap_open_ack_packet(input, client_receive_cid)
        .map_err(|error| anyhow!("NAN OPEN_ACK decode failed: {error:?}"))?;
    Ok(server_cid)
}

/// A NAN bearer bound to one discovered peer. The source address is checked
/// on receive; migration is intentionally not implemented by this adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NanDatagramBearer {
    peer: [u8; 6],
}

impl NanDatagramBearer {
    pub const fn new(peer: [u8; 6]) -> Self {
        Self { peer }
    }

    pub const fn peer(&self) -> [u8; 6] {
        self.peer
    }
}

impl DatagramBearer for NanDatagramBearer {
    type Error = anyhow::Error;

    fn send_datagram(&mut self, _now: u64, payload: &[u8]) -> Result<(), Self::Error> {
        if payload.len() > MAX_DATAGRAM {
            bail!("NAN transport datagram exceeds {MAX_DATAGRAM} bytes");
        }
        nan::send_transport_datagram(self.peer, payload)
    }

    fn receive_datagram(
        &mut self,
        _now: u64,
        out: &mut [u8],
    ) -> Result<Option<usize>, Self::Error> {
        let Some(len) = nan::take_transport_datagram_from(self.peer, out)? else {
            return Ok(None);
        };
        Ok(Some(len))
    }
}

/// A small persistent NAN connection using the same mux and handlers as the
/// UDP and fake bearers. The caller drives it from the firmware task and can
/// use the event/metrics streams for remote diagnostics.
pub struct NanStreamSession {
    /// ESP32 keeps a deliberately smaller retained-payload ledger than host
    /// UDP. The const profile bounds retransmission memory per connection.
    pub mux: StreamMux<4, 4, 512>,
    peer: [u8; 6],
    role: Role,
    next_stream_id: u64,
    responses: VecDeque<(u64, Vec<u8>)>,
}

impl NanStreamSession {
    pub fn new(
        role: Role,
        local: ConnectionId,
        peer: ConnectionId,
        peer_mac: [u8; 6],
    ) -> Result<Self> {
        let mut mux = StreamMux::new(
            role,
            ConnectionLimits::default(),
            MAX_DATAGRAM as u64,
            16,
            4,
            4096,
        );
        mux.install_connection_ids(local, peer)
            .map_err(|error| anyhow!("NAN transport CID setup failed: {error:?}"))?;
        Ok(Self {
            mux,
            peer: peer_mac,
            role,
            next_stream_id: dmesh_transport::FIRST_CLIENT_BIDI_STREAM_ID,
            responses: VecDeque::with_capacity(MAX_PENDING_RESPONSES),
        })
    }

    pub const fn peer_mac(&self) -> [u8; 6] {
        self.peer
    }

    /// Queue one client-side diagnostic operation on a fresh bidirectional
    /// stream. This is intentionally a stream operation rather than a bearer
    /// command so the same remote test can run over UDP, NAN, or a fake link.
    pub fn request(&mut self, service: u8, body: &[u8], now: u64) -> Result<u64> {
        if self.role != Role::Client {
            bail!("NAN stream request requires a client session");
        }
        let stream_id = self.next_stream_id;
        self.next_stream_id = self.next_stream_id.saturating_add(4);
        self.mux
            .endpoint
            .open_send_stream(stream_id, dmesh_transport::INITIAL_MAX_STREAM_DATA)
            .map_err(|error| anyhow!("NAN request stream setup failed: {error:?}"))?;
        let mut request = Vec::with_capacity(body.len().saturating_add(1));
        request.push(service);
        request.extend_from_slice(body);
        self.mux.endpoint.set_time(now);
        let mut packet = [0u8; MAX_DATAGRAM];
        let peer = self
            .mux
            .endpoint
            .peer_connection_id()
            .ok_or_else(|| anyhow!("NAN request peer CID is not installed"))?;
        let (used, _) = self
            .mux
            .endpoint
            .encode_stream_packet(peer, stream_id, 0, true, &request, &mut packet)
            .map_err(|error| anyhow!("NAN request encode failed: {error:?}"))?;
        NanDatagramBearer::new(self.peer).send_datagram(now, &packet[..used])?;
        Ok(stream_id)
    }

    pub fn take_response(&mut self) -> Option<(u64, Vec<u8>)> {
        self.responses.pop_front()
    }

    /// Process at most one received datagram and emit its handler response and
    /// transport ACK/control output. The caller supplies the monotonic clock;
    /// the shared endpoint also drives PTO retransmission for NAN, just as it
    /// does for UDP and the deterministic fake bearer.
    pub fn poll_once(&mut self, bearer: &mut NanDatagramBearer, now: u64) -> Result<bool> {
        self.mux.endpoint.set_time(now);
        let mut input = [0u8; MAX_DATAGRAM];
        let mut had_input = false;
        if let Some(len) = bearer.receive_datagram(now, &mut input)? {
            had_input = true;
            if self.role == Role::Server {
                match self.mux.receive_datagram(&input[..len]) {
                    Ok(Some(response)) => {
                        let mut output = [0u8; MAX_DATAGRAM];
                        let (used, _) = self
                            .mux
                            .encode_response(response.stream_id, &response.data, true, &mut output)
                            .map_err(|error| {
                                anyhow!("NAN transport response encode failed: {error:?}")
                            })?;
                        bearer.send_datagram(now, &output[..used])?;
                    }
                    Ok(None) => {}
                    Err(_error) => self.mux.events.push(255, 0, 0, len as u64),
                }
            } else {
                match self.mux.endpoint.receive_datagram(&input[..len]) {
                    Ok(dmesh_transport::TransportPacket::Control) => {}
                    Ok(dmesh_transport::TransportPacket::Stream { frame, .. }) => {
                        self.mux
                            .endpoint
                            .stream_consumed(frame.id, frame.data.len())
                            .map_err(|error| {
                                anyhow!("NAN response accounting failed: {error:?}")
                            })?;
                        if self.responses.len() == MAX_PENDING_RESPONSES {
                            self.responses.pop_front();
                        }
                        self.responses.push_back((frame.id, frame.data.to_vec()));
                    }
                    Err(_) => self.mux.events.push(255, 0, 0, len as u64),
                }
            }
        }
        let mut control = [0u8; MAX_DATAGRAM];
        if let Some(used) =
            self.mux
                .endpoint
                .poll_transmit(&mut control)
                .map_err(|error: TransportError| {
                    anyhow!("NAN transport ACK encode failed: {error:?}")
                })?
        {
            bearer.send_datagram(now, &control[..used])?;
        }
        let mut retry = [0u8; MAX_DATAGRAM];
        if let Some((used, _packet_number)) = self
            .mux
            .endpoint
            .retransmit_due(now, self.mux.endpoint.pto_timeout(), &mut retry)
            .map_err(|error| anyhow!("NAN transport retransmit failed: {error:?}"))?
        {
            bearer.send_datagram(now, &retry[..used])?;
        }
        Ok(had_input)
    }
}

/// Start a client-side NAN connection. The OPEN is retransmitted byte-for-
/// byte with increasing packet numbers until `poll` receives the matching
/// OPEN_ACK. The caller supplies the client receive CID so test and device
/// allocators can use different policies.
pub fn open(peer: [u8; 6], client_receive_cid: ConnectionId) -> Result<()> {
    let now = nan::transport_monotonic_ms();
    let mut packet = vec![0u8; MAX_DATAGRAM];
    let used = encode_bootstrap_open(client_receive_cid, 0, &mut packet)?;
    packet.truncate(used);
    let mut bearer = NanDatagramBearer::new(peer);
    bearer.send_datagram(now, &packet)?;
    let mut active = sessions()
        .lock()
        .map_err(|_| anyhow!("NAN stream session lock poisoned"))?;
    if active.len() >= MAX_NAN_SESSIONS
        || active.iter().any(|session| {
            session.peer == peer
                && match &session.state {
                    ManagedState::Opening { local, .. } => *local == client_receive_cid,
                    ManagedState::Established(connection) => {
                        connection.mux.endpoint.local_connection_id() == Some(client_receive_cid)
                    }
                }
        })
    {
        bail!("NAN stream session capacity or peer limit reached");
    }
    active.push(ManagedSession {
        peer,
        state: ManagedState::Opening {
            local: client_receive_cid,
            packet,
            last_sent_ms: now,
            packet_number: 0,
            attempts: 1,
        },
    });
    Ok(())
}

pub fn session_count() -> usize {
    sessions().lock().map(|active| active.len()).unwrap_or(0)
}

pub fn close_all() {
    if let Ok(mut active) = sessions().lock() {
        active.clear();
    }
}

pub fn request(peer: [u8; 6], service: u8, body: &[u8]) -> Result<u64> {
    request_for(peer, None, service, body)
}

/// Queue a stream operation on a selected client connection. `local_cid` is
/// optional for compatibility with the single-session command, but remote
/// test drivers should provide it when two sessions share one NAN peer.
pub fn request_for(
    peer: [u8; 6],
    local_cid: Option<ConnectionId>,
    service: u8,
    body: &[u8],
) -> Result<u64> {
    let now = nan::transport_monotonic_ms();
    let mut active = sessions()
        .lock()
        .map_err(|_| anyhow!("NAN stream session lock poisoned"))?;
    let session = active
        .iter_mut()
        .find(|session| {
            if session.peer != peer {
                return false;
            }
            let ManagedState::Established(connection) = &session.state else {
                return false;
            };
            local_cid
                .map(|cid| connection.mux.endpoint.local_connection_id() == Some(cid))
                .unwrap_or(true)
        })
        .ok_or_else(|| anyhow!("NAN stream session is not established"))?;
    let ManagedState::Established(connection) = &mut session.state else {
        unreachable!();
    };
    connection.request(service, body, now)
}

pub fn take_response(peer: [u8; 6]) -> Option<(u64, Vec<u8>)> {
    take_response_for(peer, None)
}

pub fn take_response_for(peer: [u8; 6], local_cid: Option<ConnectionId>) -> Option<(u64, Vec<u8>)> {
    let mut active = sessions().lock().ok()?;
    let session = active.iter_mut().find(|session| {
        if session.peer != peer {
            return false;
        }
        let ManagedState::Established(connection) = &session.state else {
            return false;
        };
        local_cid
            .map(|cid| connection.mux.endpoint.local_connection_id() == Some(cid))
            .unwrap_or(true)
    })?;
    let ManagedState::Established(connection) = &mut session.state else {
        return None;
    };
    connection.take_response()
}

/// Poll all NAN transport sessions. This is called after `nan::poll_rx()` in
/// the main firmware loop. Established sessions use the shared mux; unknown
/// DCID=0 packets are accepted as server-side OPENs and get one connection
/// entry, so multiple peers can coexist without a radio-specific state machine.
pub fn poll() -> Result<()> {
    let now = nan::transport_monotonic_ms();
    let mut active = sessions()
        .lock()
        .map_err(|_| anyhow!("NAN stream session lock poisoned"))?;

    for session in active.iter_mut() {
        match &mut session.state {
            ManagedState::Established(connection) => {
                let mut bearer = NanDatagramBearer::new(session.peer);
                // Bootstrap packets can be duplicated after either side has
                // transitioned. Replay the server's ACK or harmlessly absorb
                // a duplicate client ACK before handing established traffic
                // to the mux.
                let mut probe = [0u8; MAX_DATAGRAM];
                if let Some(len) = nan::peek_transport_datagram_from(session.peer, &mut probe)? {
                    if let Ok((header, _)) = ShortHeader::decode(&probe[..len]) {
                        if let Some(local) = connection.mux.endpoint.local_connection_id() {
                            if header.dcid.value() == 0 {
                                let mut ack = [0u8; MAX_DATAGRAM];
                                if let Ok(client_cid) = accept_bootstrap_open(
                                    &probe[..len],
                                    local,
                                    0,
                                    &mut ack,
                                ) {
                                    let duplicate = connection.mux.endpoint.peer_connection_id()
                                        == Some(client_cid);
                                    if !duplicate {
                                        // A new client CID from this peer is a
                                        // separate connection, not a replay.
                                        continue;
                                    }
                                    let _ = nan::take_transport_datagram_from(
                                        session.peer,
                                        &mut probe,
                                    )?;
                                    let ack_header = ShortHeader::decode(&ack)
                                        .map(|(_, used)| used)
                                        .map_err(|error| {
                                            anyhow!(
                                                "NAN duplicate OPEN_ACK header failed: {error:?}"
                                            )
                                        })?;
                                    let (_, ack_frame) =
                                        decode_frame(&ack[ack_header..]).map_err(|error| {
                                            anyhow!(
                                                "NAN duplicate OPEN_ACK frame failed: {error:?}"
                                            )
                                        })?;
                                    NanDatagramBearer::new(session.peer)
                                        .send_datagram(now, &ack[..ack_header + ack_frame])?;
                                    let _ = client_cid;
                                }
                                continue;
                            }
                            if accept_bootstrap_open_ack(&probe[..len], local).is_ok() {
                                let _ =
                                    nan::take_transport_datagram_from(session.peer, &mut probe)?;
                                continue;
                            }
                        }
                    }
                }
                let _ = connection.poll_once(&mut bearer, now)?;
            }
            ManagedState::Opening {
                local,
                packet,
                last_sent_ms,
                packet_number,
                attempts,
            } => {
                let mut input = [0u8; MAX_DATAGRAM];
                if let Some(len) = nan::take_transport_datagram_from(session.peer, &mut input)? {
                    if let Ok(server_cid) = accept_bootstrap_open_ack(&input[..len], *local) {
                        let mut connection =
                            NanStreamSession::new(Role::Client, *local, server_cid, session.peer)?;
                        connection
                            .mux
                            .endpoint
                            .continue_packet_numbers_from(packet_number.saturating_add(1))
                            .map_err(|error| {
                                anyhow!("NAN bootstrap packet-number continuation failed: {error:?}")
                            })?;
                        session.state = ManagedState::Established(connection);
                        continue;
                    }
                }
                if now.saturating_sub(*last_sent_ms) >= BOOTSTRAP_RETRY_MS {
                    if *attempts >= BOOTSTRAP_ATTEMPTS {
                        *attempts = BOOTSTRAP_ATTEMPTS.saturating_add(1);
                        continue;
                    }
                    *packet_number = packet_number.saturating_add(1);
                    // Re-encode only the packet number. The stream bytes remain
                    // byte-identical while each retry occupies a new PN.
                    let mut retry = [0u8; MAX_DATAGRAM];
                    let used = encode_bootstrap_open(*local, *packet_number, &mut retry)?;
                    packet.clear();
                    packet.extend_from_slice(&retry[..used]);
                    NanDatagramBearer::new(session.peer).send_datagram(now, packet)?;
                    *last_sent_ms = now;
                    *attempts = attempts.saturating_add(1);
                }
            }
        }
    }

    // Accept at most one new OPEN per poll. Established sessions were given
    // first access to their peer-specific queue above.
    let mut input = [0u8; MAX_DATAGRAM];
    if let Some((peer, len)) = nan::take_any_transport_datagram(&mut input)? {
        let Ok((header, _)) = ShortHeader::decode(&input[..len]) else {
            return Ok(());
        };
        if header.dcid.value() == 0 {
            let Ok((_, client_cid)) =
                dmesh_transport::decode_bootstrap_open_packet(&input[..len])
            else {
                return Ok(());
            };
            let candidate_cid = allocate_server_cid(client_cid);
            let mut ack = [0u8; MAX_DATAGRAM];
            if accept_bootstrap_open(&input[..len], candidate_cid, 0, &mut ack).is_err() {
                return Ok(());
            }
            let existing_index = active.iter().position(|session| {
                if session.peer != peer {
                    return false;
                }
                matches!(
                    &session.state,
                    ManagedState::Established(connection)
                        if connection.mux.endpoint.peer_connection_id() == Some(client_cid)
                )
            });
            let server_cid = existing_index
                .and_then(|index| match &active[index].state {
                    ManagedState::Established(connection) => {
                        connection.mux.endpoint.local_connection_id()
                    }
                    _ => None,
                })
                .unwrap_or(candidate_cid);
            if existing_index.is_none() && active.len() >= MAX_NAN_SESSIONS {
                return Ok(());
            }
            if let Some(index) = existing_index {
                let packet_number = match &mut active[index].state {
                    ManagedState::Established(_) => 0,
                    _ => 0,
                };
                accept_bootstrap_open(&input[..len], server_cid, packet_number, &mut ack)?;
            }
            let ack_len = ShortHeader::decode(&ack)
                .map(|(_, used)| used)
                .map_err(|error| anyhow!("NAN OPEN_ACK header decode failed: {error:?}"))?;
            // The encoded frame extends beyond the header; find its complete
            // length by decoding once, avoiding a second wire format.
            let (_, frame_len) = decode_frame(&ack[ack_len..])
                .map_err(|error| anyhow!("NAN OPEN_ACK frame decode failed: {error:?}"))?;
            NanDatagramBearer::new(peer).send_datagram(now, &ack[..ack_len + frame_len])?;
            if existing_index.is_none() {
                let mut connection =
                    NanStreamSession::new(Role::Server, server_cid, client_cid, peer)?;
                connection
                    .mux
                    .endpoint
                    .continue_packet_numbers_from(1)
                    .map_err(|error| {
                        anyhow!("NAN bootstrap packet-number continuation failed: {error:?}")
                    })?;
                active.push(ManagedSession {
                    peer,
                    state: ManagedState::Established(connection),
                });
            }
        }
    }
    active.retain(|session| {
        !matches!(
            &session.state,
            ManagedState::Opening { attempts, .. } if *attempts > BOOTSTRAP_ATTEMPTS
        )
    });
    Ok(())
}
