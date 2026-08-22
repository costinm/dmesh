//! Socket-free QUIC-lite object server for ESP-NOW/vendor-action datagrams.
//!
//! This module deliberately knows nothing about nl80211, channels, NAN, or
//! raw-frame injection. `lmesh-wifi` provides those privileged operations and
//! passes each complete action payload plus its source MAC to [`ActionServer`].
//! The returned payloads are sent back over that same action bearer.

use crate::protocol::{ObjectRecordStream, decode_get};
use crate::services::{dispatch_tagged_stream, handle_stream, object_stream_registry};
use crate::{ObjectServer, ServerConfig};
use anyhow::{Result, anyhow, bail};
use quic_lite::callback::{CallbackStreams, CopyingError, CopyingStreamEvents};
use quic_lite::mux::StreamMux;
use quic_lite::{
    ConnectionId, ConnectionLimits, DEFAULT_MAX_DATAGRAM_SIZE, EndpointState, Frame, Role,
    SERVICE_OBJECT, ShortHeader, TransportPacket, TransportStats,
};
use std::collections::HashMap;
use std::sync::Arc;

const MTU: usize = DEFAULT_MAX_DATAGRAM_SIZE;
const OBJECT_STREAM: u64 = 3;
const MAX_CONNECTIONS: usize = 64;
const OBJECT_CHUNK: usize = MTU - 64;
const FIRST_SERVER_UNI_STREAM_ID: u64 = 3;
/// Bound an adapter operation so a lost FIN or peer disappearance returns a
/// useful snapshot instead of creating an unbounded raw-action session.
pub const MAX_ACTION_OPERATION_TIMEOUT_MS: u32 = 300_000;

struct Connection {
    peer: [u8; 6],
    mux: StreamMux<8, 512>,
    registry: quic_lite::StreamRegistry,
    transfer: Option<ObjectRecordStream>,
}

/// Host object service bound to complete action-frame payloads.
///
/// There is one QUIC-lite connection table across action paths. The caller may
/// retain this value inside `lmesh-wifi`; it does not open a socket or thread.
pub struct ActionServer {
    objects: ObjectServer,
    connections: HashMap<u64, Connection>,
    next_cid: u64,
    object_chunk: usize,
}

/// Socket-free client half of the action bearer. A privileged adapter owns
/// raw-frame send/receive and peer discovery; this type owns only the common
/// QUIC-lite bootstrap, stream packet construction, and ACK processing.
pub struct ActionClient {
    endpoint: EndpointState<8, 512>,
    local_cid: ConnectionId,
    limits: ConnectionLimits,
    ordered: CallbackStreams<Arc<Vec<u8>>>,
}

/// One complete application response received by [`ActionClient`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActionStreamResponse {
    pub stream_id: u64,
    pub offset: u64,
    pub fin: bool,
    pub data: Vec<u8>,
}

/// Adapter-owned absolute deadline for one action operation.
///
/// `dmesh-server` deliberately does not own a clock or thread. The raw-frame
/// adapter supplies its monotonic millisecond clock to [`ActionClient`]
/// polling calls and can report timeout state uniformly with UDP/UART tools.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActionOperationDeadline {
    deadline_ms: u32,
}

/// Bounded action-operation state suitable for a CLI, service response, or
/// test report. It exposes bearer-neutral transport facts and never parses
/// action frames in the caller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActionOperationStatus {
    pub connected: bool,
    pub timed_out: bool,
    pub deadline_ms: u32,
    pub pending_send_packets: usize,
    pub pending_ordered_streams: usize,
    pub bytes_in_flight: u64,
    pub stats: TransportStats,
}

#[derive(Default)]
struct ActionResponseCollector {
    responses: Vec<ActionStreamResponse>,
}

impl CopyingStreamEvents for ActionResponseCollector {
    type Error = ();

    fn stream_chunk(
        &mut self,
        stream_id: u64,
        offset: u64,
        fin: bool,
        data: &[u8],
    ) -> Result<(), Self::Error> {
        self.responses.push(ActionStreamResponse {
            stream_id,
            offset,
            fin,
            data: data.to_vec(),
        });
        Ok(())
    }
}

impl ActionClient {
    pub fn new(local_cid: ConnectionId) -> Self {
        Self::with_limits(local_cid, ConnectionLimits::default())
    }

    pub fn with_limits(local_cid: ConnectionId, limits: ConnectionLimits) -> Self {
        Self {
            endpoint: EndpointState::new_with_history_capacity(
                Role::Client,
                limits,
                MTU as u64,
                512,
            ),
            local_cid,
            limits,
            // Action receive is a stream operation just like UDP: retain only
            // a bounded 256 KiB gap across eight active streams, then deliver
            // contiguous chunks to the object/control client. The raw action
            // adapter itself never attempts packet-order reassembly.
            ordered: CallbackStreams::new(8, 256 * 1024),
        }
    }

    /// Construct a bounded, wrap-safe deadline from an adapter monotonic
    /// millisecond clock. Raw-action setup is intentionally never unbounded.
    pub fn operation_deadline(
        &self,
        now_ms: u32,
        timeout_ms: u32,
    ) -> Result<ActionOperationDeadline> {
        if timeout_ms == 0 || timeout_ms > MAX_ACTION_OPERATION_TIMEOUT_MS {
            bail!("action operation timeout must be in 1..={MAX_ACTION_OPERATION_TIMEOUT_MS} ms");
        }
        Ok(ActionOperationDeadline {
            deadline_ms: now_ms.wrapping_add(timeout_ms),
        })
    }

    /// Return a report at any point, including after a timeout. The caller
    /// may emit it even when a peer never sends a terminal stream frame.
    pub fn operation_status(
        &self,
        now_ms: u32,
        deadline: ActionOperationDeadline,
    ) -> ActionOperationStatus {
        ActionOperationStatus {
            connected: self.endpoint.peer_connection_id().is_some(),
            timed_out: time_after_or_equal(now_ms, deadline.deadline_ms),
            deadline_ms: deadline.deadline_ms,
            pending_send_packets: self.endpoint.history_len(),
            pending_ordered_streams: self.ordered.stream_count(),
            bytes_in_flight: self.endpoint.bytes_in_flight(),
            stats: self.endpoint.stats(),
        }
    }

    /// First datagram for a raw action adapter to send to its selected peer.
    pub fn start_open(&self) -> Result<Vec<u8>> {
        let mut packet = [0u8; MTU];
        let used = quic_lite::encode_bootstrap_open_packet_with_limits(
            self.local_cid,
            0,
            self.limits,
            &mut packet,
        )
        .map_err(|error| anyhow!("action client OPEN: {error:?}"))?;
        Ok(packet[..used].to_vec())
    }

    /// Install the DCID/credit state from an action OPEN_ACK.
    pub fn on_open_ack(&mut self, packet: &[u8]) -> Result<()> {
        let (_, ack) =
            quic_lite::decode_bootstrap_open_ack_packet_with_limits(packet, self.local_cid)
                .map_err(|error| anyhow!("action client OPEN_ACK: {error:?}"))?;
        self.endpoint
            .install_connection_ids(self.local_cid, ack.server_receive_cid)
            .map_err(|error| anyhow!("action client CIDs: {error:?}"))?;
        self.endpoint
            .set_initial_peer_credit(ack.max_data, ack.max_stream_data)
            .map_err(|error| anyhow!("action client credit: {error:?}"))?;
        self.endpoint
            .continue_packet_numbers_from(1)
            .map_err(|error| anyhow!("action client packet numbers: {error:?}"))?;
        Ok(())
    }

    /// Encode one application request stream for the raw action adapter.
    pub fn request(&mut self, stream_id: u64, data: &[u8], fin: bool) -> Result<Vec<u8>> {
        let peer = self
            .endpoint
            .peer_connection_id()
            .ok_or_else(|| anyhow!("action client not connected"))?;
        self.endpoint
            .open_send_stream(stream_id, quic_lite::INITIAL_MAX_STREAM_DATA)
            .map_err(|error| anyhow!("action client stream: {error:?}"))?;
        let mut packet = [0u8; MTU];
        let (used, _) = self
            .endpoint
            .encode_stream_packet(peer, stream_id, 0, fin, data, &mut packet)
            .map_err(|error| anyhow!("action client request: {error:?}"))?;
        Ok(packet[..used].to_vec())
    }

    /// Consume one complete action payload and return newly contiguous stream
    /// chunks. Control packets are consumed internally. Responses remain in
    /// stream-offset order even if complete action frames arrive reordered.
    pub fn receive(&mut self, packet: &[u8]) -> Result<Vec<ActionStreamResponse>> {
        let (_header, header_len) =
            ShortHeader::decode_with_expected(packet, self.endpoint.expected_packet_number())
                .map_err(|error| anyhow!("action client header: {error:?}"))?;
        let mut offset = header_len;
        let mut frames = Vec::new();
        while offset < packet.len() {
            let (frame, used) = quic_lite::decode_frame(&packet[offset..])
                .map_err(|error| anyhow!("action client frame: {error:?}"))?;
            if let Frame::Stream(stream) = frame {
                let start = stream.data.as_ptr() as usize - packet.as_ptr() as usize;
                frames.push((
                    stream.id,
                    stream.offset,
                    stream.fin,
                    start,
                    stream.data.len(),
                ));
            }
            offset += used;
        }
        if !matches!(
            self.endpoint
                .receive_datagram(packet)
                .map_err(|error| anyhow!("action client input: {error:?}"))?,
            TransportPacket::Stream { .. }
        ) {
            return Ok(Vec::new());
        }

        let mut collector = ActionResponseCollector::default();
        for (stream_id, stream_offset, fin, start, len) in frames {
            self.ordered
                .receive_copying_borrowed(
                    stream_id,
                    &packet[start..start + len],
                    stream_offset,
                    fin,
                    // `receive_copying_borrowed` retains a packet beginning
                    // at range zero on its reordering path. Retain precisely
                    // this stream slice, not the enclosing QUIC packet whose
                    // header would otherwise be delivered as object bytes.
                    || Arc::new(packet[start..start + len].to_vec()),
                    &mut collector,
                )
                .map_err(|error| match error {
                    CopyingError::Transport(error) => anyhow!("action client ordering: {error:?}"),
                    CopyingError::Callback(()) => anyhow!("action client response callback"),
                })?;
        }
        for response in &collector.responses {
            self.endpoint
                .stream_consumed(response.stream_id, response.data.len())
                .map_err(|error| anyhow!("action client response accounting: {error:?}"))?;
        }
        Ok(collector.responses)
    }

    /// Optional ACK/control datagram to send through the same action adapter.
    pub fn poll_transmit(&mut self) -> Result<Option<Vec<u8>>> {
        let mut packet = [0u8; MTU];
        let used = self
            .endpoint
            .poll_transmit(&mut packet)
            .map_err(|error| anyhow!("action client ACK: {error:?}"))?;
        Ok(used.map(|used| packet[..used].to_vec()))
    }

    /// Ask QUIC-lite for one retransmission after the action bearer timeout.
    ///
    /// The raw-action adapter owns its clock and calls this after a sent frame
    /// has not produced traffic by the transport PTO.  It must send the
    /// returned datagram through the same selected action path.  This keeps
    /// loss recovery in the shared transport rather than in an ESP-NOW- or
    /// nl80211-specific retry loop.
    pub fn on_timeout(&mut self, now: u64) -> Result<Option<Vec<u8>>> {
        let mut packet = [0u8; MTU];
        let pto = self.endpoint.pto_timeout();
        let used = self
            .endpoint
            .retransmit_due(now, pto, &mut packet)
            .map_err(|error| anyhow!("action client timeout: {error:?}"))?;
        Ok(used.map(|(used, _packet_number)| packet[..used].to_vec()))
    }
}

fn time_after_or_equal(now: u32, deadline: u32) -> bool {
    now.wrapping_sub(deadline) < i32::MAX as u32
}

/// Map a client-initiated bidi request to a server-initiated unidirectional
/// response. A server may not send response bytes on the client-owned stream
/// ID: strict stream-direction checks correctly reject that on the client.
fn server_response_stream_id(request_stream_id: u64) -> Result<u64> {
    if request_stream_id % 4 != quic_lite::FIRST_CLIENT_BIDI_STREAM_ID % 4 {
        bail!("action request is not a client bidi stream");
    }
    let index = request_stream_id / 4;
    FIRST_SERVER_UNI_STREAM_ID
        .checked_add(index.saturating_mul(4))
        .ok_or_else(|| anyhow!("action response stream overflow"))
}

impl ActionServer {
    pub fn new(config: ServerConfig) -> Self {
        Self {
            objects: ObjectServer::new(config),
            connections: HashMap::new(),
            next_cid: 0x5000,
            object_chunk: OBJECT_CHUNK,
        }
    }

    pub fn with_object_chunk(config: ServerConfig, object_chunk: usize) -> Result<Self> {
        if !(1..=OBJECT_CHUNK).contains(&object_chunk) {
            bail!("action object chunk must be in 1..={OBJECT_CHUNK}");
        }
        let mut server = Self::new(config);
        server.object_chunk = object_chunk;
        Ok(server)
    }

    pub fn connection_count(&self) -> usize {
        self.connections.len()
    }

    /// Process one complete action payload and return zero or more payloads
    /// to send to `peer`. Invalid/unroutable data returns an error rather than
    /// creating an implicit connection.
    pub fn receive(&mut self, peer: [u8; 6], packet: &[u8]) -> Result<Vec<Vec<u8>>> {
        if packet.len() > MTU {
            bail!("action packet exceeds common MTU");
        }
        let (header, _) =
            ShortHeader::decode(packet).map_err(|error| anyhow!("action header: {error:?}"))?;
        if header.dcid.value() == 0 {
            return self.accept_open(peer, packet);
        }
        let connection = self
            .connections
            .get_mut(&header.dcid.value())
            .ok_or_else(|| anyhow!("unknown action DCID"))?;
        if connection.peer != peer {
            bail!("action peer does not own DCID");
        }
        let request = connection
            .mux
            .receive_request(packet)
            .map_err(|error| anyhow!("action transport input: {error:?}"))?;
        if let Some(request) = request {
            // Direct tagged-CBOR is the common handler envelope. QUIC stream
            // IDs only provide ordering/lifetime; component+method select
            // the handler and may be used on many concurrent streams.
            if let Some(response) = dispatch_tagged_stream(&request.data) {
                connection
                    .mux
                    .complete_request(request.stream_id, request.data.len())
                    .map_err(|error| anyhow!("action tagged accounting: {error:?}"))?;
                let response_stream_id = server_response_stream_id(request.stream_id)?;
                let mut response_packet = [0u8; MTU];
                let (used, _) = connection
                    .mux
                    .encode_response(response_stream_id, &response, true, &mut response_packet)
                    .map_err(|error| anyhow!("action tagged response: {error:?}"))?;
                let mut output = vec![response_packet[..used].to_vec()];
                output.extend(Self::drain(connection, self.object_chunk)?);
                return Ok(output);
            }
            let Some((&service, body)) = request.data.split_first() else {
                bail!("empty action stream service");
            };
            if service == SERVICE_OBJECT {
                if connection.transfer.is_some() {
                    bail!("action object transfer already active");
                }
                let get = decode_get(body).ok_or_else(|| anyhow!("invalid action object GET"))?;
                let records = self.objects.response_records(get)?;
                connection
                    .mux
                    .complete_request(request.stream_id, request.data.len())
                    .map_err(|error| anyhow!("action request accounting: {error:?}"))?;
                connection.transfer = Some(ObjectRecordStream::new(records));
            } else {
                let cid = connection
                    .mux
                    .endpoint
                    .local_connection_id()
                    .ok_or_else(|| anyhow!("action missing local CID"))?;
                let response = handle_stream(
                    &connection.mux.endpoint,
                    cid,
                    request.stream_id,
                    &connection.registry,
                    service,
                    body,
                )
                .map_err(|error| anyhow!("action service: {error}"))?;
                connection
                    .mux
                    .complete_request(request.stream_id, request.data.len())
                    .map_err(|error| anyhow!("action request accounting: {error:?}"))?;
                let response_stream_id = server_response_stream_id(request.stream_id)?;
                let mut response_packet = [0u8; MTU];
                let (used, _) = connection
                    .mux
                    .encode_response(response_stream_id, &response, true, &mut response_packet)
                    .map_err(|error| anyhow!("action service response: {error:?}"))?;
                let mut output = vec![response_packet[..used].to_vec()];
                output.extend(Self::drain(connection, self.object_chunk)?);
                return Ok(output);
            }
        }
        Self::drain(connection, self.object_chunk)
    }

    fn accept_open(&mut self, peer: [u8; 6], packet: &[u8]) -> Result<Vec<Vec<u8>>> {
        let (_, open) = quic_lite::decode_bootstrap_open_packet_with_limits(packet)
            .map_err(|error| anyhow!("invalid action bootstrap: {error:?}"))?;
        if self.connections.len() >= MAX_CONNECTIONS {
            bail!("action connection capacity");
        }
        let client_cid = open.client_receive_cid;
        let server_cid = self.allocate_cid(client_cid)?;
        let mut mux = StreamMux::new_with_history_capacity(
            Role::Server,
            ConnectionLimits::default(),
            MTU as u64,
            16,
            8,
            256 * 1024,
            512,
        );
        mux.install_connection_ids(server_cid, client_cid)
            .map_err(|error| anyhow!("action bootstrap CIDs: {error:?}"))?;
        mux.endpoint
            .set_initial_peer_budget(
                open.max_data,
                open.max_stream_data,
                open.max_in_flight_packets,
            )
            .map_err(|error| anyhow!("action bootstrap credit: {error:?}"))?;
        let mut ack = [0u8; MTU];
        let used = quic_lite::encode_bootstrap_open_ack_packet_with_limits(
            client_cid,
            server_cid,
            0,
            ConnectionLimits::default(),
            &mut ack,
        )
        .map_err(|error| anyhow!("action bootstrap ACK: {error:?}"))?;
        self.connections.insert(
            server_cid.value(),
            Connection {
                peer,
                mux,
                registry: object_stream_registry(),
                transfer: None,
            },
        );
        Ok(vec![ack[..used].to_vec()])
    }

    fn allocate_cid(&mut self, avoid: ConnectionId) -> Result<ConnectionId> {
        for _ in 0..1024 {
            let value = self.next_cid;
            self.next_cid = self.next_cid.saturating_add(1);
            if let Some(cid) = ConnectionId::new(value)
                && cid != avoid
                && !self.connections.contains_key(&cid.value())
            {
                return Ok(cid);
            }
        }
        bail!("action CID exhausted")
    }

    fn drain(connection: &mut Connection, object_chunk: usize) -> Result<Vec<Vec<u8>>> {
        let mut output = Vec::new();
        let mut control = [0u8; MTU];
        if let Some(used) = connection
            .mux
            .endpoint
            .poll_transmit(&mut control)
            .map_err(|error| anyhow!("action control output: {error:?}"))?
        {
            output.push(control[..used].to_vec());
        }
        let mut packet = [0u8; MTU];
        while let Some(transfer) = connection.transfer.as_mut() {
            if connection.mux.endpoint.history_len() >= connection.mux.endpoint.history_capacity() {
                break;
            }
            let mut bytes = [0u8; OBJECT_CHUNK];
            let Some(chunk) = transfer.copy_next(&mut bytes[..object_chunk]) else {
                connection.transfer = None;
                break;
            };
            let peer = connection
                .mux
                .endpoint
                .peer_connection_id()
                .ok_or_else(|| anyhow!("action missing peer CID"))?;
            connection
                .mux
                .endpoint
                .open_send_stream(OBJECT_STREAM, quic_lite::INITIAL_MAX_STREAM_DATA)
                .ok();
            let (used, _) = match connection.mux.endpoint.encode_stream_packet(
                peer,
                OBJECT_STREAM,
                chunk.offset,
                chunk.fin,
                &bytes[..chunk.len],
                &mut packet,
            ) {
                Ok(value) => value,
                Err(quic_lite::Error::FlowControl | quic_lite::Error::Invalid) => break,
                Err(error) => return Err(anyhow!("action object packet: {error:?}")),
            };
            if !transfer.advance(chunk) {
                bail!("action object stream advancement failed");
            }
            output.push(packet[..used].to_vec());
            if transfer.is_complete() {
                connection.transfer = None;
                break;
            }
        }
        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{RECORD_BLOB, RECORD_DONE, RECORD_MANIFEST, RecordBuffer, encode_get};

    #[test]
    fn action_server_bootstraps_by_dcid_and_binds_the_peer_mac() {
        let directory = tempfile::tempdir().unwrap();
        let mut server = ActionServer::new(ServerConfig {
            artifact_root: directory.path().to_owned(),
            ..ServerConfig::default()
        });
        let client = ConnectionId::new(17).unwrap();
        let mut open = [0u8; MTU];
        let used = quic_lite::encode_bootstrap_open_packet_with_limits(
            client,
            0,
            ConnectionLimits::default(),
            &mut open,
        )
        .unwrap();
        let peer = [1, 2, 3, 4, 5, 6];
        let response = server.receive(peer, &open[..used]).unwrap();
        assert_eq!(server.connection_count(), 1);
        assert_eq!(response.len(), 1);
        let (_, ack) =
            quic_lite::decode_bootstrap_open_ack_packet_with_limits(&response[0], client).unwrap();
        assert_ne!(ack.server_receive_cid, client);
        assert!(server.receive([6, 5, 4, 3, 2, 1], &response[0]).is_err());
    }

    #[test]
    fn action_server_rejects_unknown_application_services() {
        let directory = tempfile::tempdir().unwrap();
        let mut server = ActionServer::new(ServerConfig {
            artifact_root: directory.path().to_owned(),
            ..ServerConfig::default()
        });
        let client = ConnectionId::new(17).unwrap();
        let mut open = [0u8; MTU];
        let used = quic_lite::encode_bootstrap_open_packet_with_limits(
            client,
            0,
            ConnectionLimits::default(),
            &mut open,
        )
        .unwrap();
        let peer = [1, 2, 3, 4, 5, 6];
        let response = server.receive(peer, &open[..used]).unwrap();
        let (_, ack) =
            quic_lite::decode_bootstrap_open_ack_packet_with_limits(&response[0], client).unwrap();
        let mut endpoint = quic_lite::EndpointState::<8, 8>::new(
            Role::Client,
            ConnectionLimits::default(),
            MTU as u64,
        );
        endpoint
            .install_connection_ids(client, ack.server_receive_cid)
            .unwrap();
        endpoint
            .set_initial_peer_budget(ack.max_data, ack.max_stream_data, 8)
            .unwrap();
        endpoint.continue_packet_numbers_from(1).unwrap();
        endpoint
            .open_send_stream(4, quic_lite::INITIAL_MAX_STREAM_DATA)
            .unwrap();
        let mut packet = [0u8; MTU];
        let (used, _) = endpoint
            .encode_stream_packet(ack.server_receive_cid, 4, 0, true, &[0xff], &mut packet)
            .unwrap();
        assert!(server.receive(peer, &packet[..used]).is_err());
    }

    #[test]
    fn action_server_uses_the_standard_handler_registry() {
        let directory = tempfile::tempdir().unwrap();
        let mut server = ActionServer::new(ServerConfig {
            artifact_root: directory.path().to_owned(),
            ..ServerConfig::default()
        });
        let peer = [1, 2, 3, 4, 5, 6];
        let mut client = ActionClient::new(ConnectionId::new(17).unwrap());
        let open = client.start_open().unwrap();
        let open_reply = server.receive(peer, &open).unwrap();
        client.on_open_ack(&open_reply[0]).unwrap();
        let request = client
            .request(
                quic_lite::FIRST_CLIENT_BIDI_STREAM_ID,
                &[quic_lite::SERVICE_STREAM],
                true,
            )
            .unwrap();
        let responses = server.receive(peer, &request).unwrap();
        let mut received = Vec::new();
        for packet in &responses {
            received.extend(client.receive(packet).unwrap());
        }
        let response = received.into_iter().next().expect("handler-list response");
        assert_eq!(
            response.stream_id,
            server_response_stream_id(quic_lite::FIRST_CLIENT_BIDI_STREAM_ID).unwrap()
        );
        assert!(response.fin);
        assert_eq!(
            response.data,
            object_stream_registry().encode_handler_list()
        );
    }

    #[test]
    fn action_operation_deadline_is_bounded_wrap_safe_and_reports_progress() {
        let client = ActionClient::new(ConnectionId::new(17).unwrap());
        assert!(client.operation_deadline(0, 0).is_err());
        assert!(
            client
                .operation_deadline(0, MAX_ACTION_OPERATION_TIMEOUT_MS + 1)
                .is_err()
        );
        let deadline = client.operation_deadline(u32::MAX - 4, 8).unwrap();
        let before = client.operation_status(2, deadline);
        assert!(!before.connected);
        assert!(!before.timed_out);
        assert_eq!(before.pending_send_packets, 0);
        assert!(client.operation_status(3, deadline).timed_out);
    }

    #[test]
    fn action_object_get_round_trips_over_injected_datagrams() {
        let directory = tempfile::tempdir().unwrap();
        let artifact_root = directory.path().join("flash");
        let artifact = artifact_root.join("esp32c6/main-app.bin");
        std::fs::create_dir_all(artifact.parent().unwrap()).unwrap();
        std::fs::write(&artifact, b"action-object-payload").unwrap();
        let mut server = ActionServer::new(ServerConfig {
            artifact_root,
            ..ServerConfig::default()
        });
        let peer = [1, 2, 3, 4, 5, 6];
        let client_cid = ConnectionId::new(17).unwrap();
        let mut client = ActionClient::new(client_cid);
        let open = client.start_open().unwrap();
        let open_reply = server.receive(peer, &open).unwrap();
        client.on_open_ack(&open_reply[0]).unwrap();
        let mut request = [0u8; 64];
        request[0] = SERVICE_OBJECT;
        let request_len = 1 + encode_get(&mut request[1..], None, 13, 6).unwrap();
        let packet = client.request(4, &request[..request_len], true).unwrap();
        let responses = server.receive(peer, &packet).unwrap();
        assert!(responses.len() >= 4, "control plus object records");

        let mut stream = Vec::new();
        for response in responses {
            for response in client.receive(&response).unwrap() {
                assert_eq!(response.stream_id, OBJECT_STREAM);
                stream.extend_from_slice(&response.data);
            }
        }
        let mut records = RecordBuffer::new();
        records.push(&stream);
        assert_eq!(records.next().unwrap().0, RECORD_MANIFEST);
        let (kind, body) = records.next().unwrap();
        assert_eq!(kind, RECORD_BLOB);
        assert!(body.ends_with(b"action-object-payload"));
        assert_eq!(records.next(), Some((RECORD_DONE, Vec::new())));
        assert_eq!(records.next(), None);
    }

    #[test]
    fn action_client_recovers_a_dropped_request_through_its_timeout_hook() {
        let directory = tempfile::tempdir().unwrap();
        let artifact_root = directory.path().join("flash");
        let artifact = artifact_root.join("esp32c6/main-app.bin");
        std::fs::create_dir_all(artifact.parent().unwrap()).unwrap();
        std::fs::write(&artifact, b"action-timeout-payload").unwrap();
        let mut server = ActionServer::new(ServerConfig {
            artifact_root,
            ..ServerConfig::default()
        });
        let peer = [1, 2, 3, 4, 5, 6];
        let mut client = ActionClient::new(ConnectionId::new(17).unwrap());
        let open = client.start_open().unwrap();
        let open_reply = server.receive(peer, &open).unwrap();
        client.on_open_ack(&open_reply[0]).unwrap();

        let mut request = [0u8; 64];
        request[0] = SERVICE_OBJECT;
        let request_len = 1 + encode_get(&mut request[1..], None, 13, 6).unwrap();
        let _dropped = client.request(4, &request[..request_len], true).unwrap();

        assert!(client.on_timeout(0).unwrap().is_none());
        let retry = client
            .on_timeout(client.endpoint.pto_timeout())
            .unwrap()
            .unwrap();
        let responses = server.receive(peer, &retry).unwrap();

        let mut stream = Vec::new();
        for response in responses {
            for response in client.receive(&response).unwrap() {
                stream.extend_from_slice(&response.data);
            }
        }
        let mut records = RecordBuffer::new();
        records.push(&stream);
        assert_eq!(records.next().unwrap().0, RECORD_MANIFEST);
        assert_eq!(records.next().unwrap().0, RECORD_BLOB);
        assert_eq!(records.next(), Some((RECORD_DONE, Vec::new())));
    }

    #[test]
    fn action_client_reassembles_reordered_object_chunks_by_stream_offset() {
        let directory = tempfile::tempdir().unwrap();
        let artifact_root = directory.path().join("flash");
        let artifact = artifact_root.join("esp32c6/main-app.bin");
        std::fs::create_dir_all(artifact.parent().unwrap()).unwrap();
        std::fs::write(&artifact, vec![0x5a; 192]).unwrap();
        let mut server = ActionServer::with_object_chunk(
            ServerConfig {
                artifact_root,
                ..ServerConfig::default()
            },
            16,
        )
        .unwrap();
        let peer = [1, 2, 3, 4, 5, 6];
        let mut client = ActionClient::new(ConnectionId::new(17).unwrap());
        let open = client.start_open().unwrap();
        let open_reply = server.receive(peer, &open).unwrap();
        client.on_open_ack(&open_reply[0]).unwrap();
        let mut request = [0u8; 64];
        request[0] = SERVICE_OBJECT;
        let request_len = 1 + encode_get(&mut request[1..], None, 13, 6).unwrap();
        let request = client.request(4, &request[..request_len], true).unwrap();
        let mut responses = server.receive(peer, &request).unwrap();
        assert!(
            responses.len() > 4,
            "small action chunks produce a stream sequence"
        );
        responses.reverse();

        let mut stream = Vec::new();
        for response in responses {
            for response in client.receive(&response).unwrap() {
                assert_eq!(response.stream_id, OBJECT_STREAM);
                stream.extend_from_slice(&response.data);
            }
        }
        let mut records = RecordBuffer::new();
        records.push(&stream);
        assert_eq!(records.next().unwrap().0, RECORD_MANIFEST);
        let (kind, body) = records.next().unwrap();
        assert_eq!(kind, RECORD_BLOB);
        assert!(body.ends_with(&[0x5a; 192]));
        assert_eq!(records.next(), Some((RECORD_DONE, Vec::new())));
        assert_eq!(records.next(), None);
    }
}
