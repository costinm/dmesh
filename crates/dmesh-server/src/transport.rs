//! Bearer-neutral QUIC connection clients and server dispatcher.
//!
//! Ethernet, ESP-NOW, UART, and simulated bearers supply complete QUIC-lite
//! datagrams and send optional responses unchanged. This module owns service
//! clients and the DMesh server glue; it has no socket, task, ESP-IDF, or
//! peer-address dependency. Core packet and connection state remains in
//! `quic-lite`.

use alloc::{boxed::Box, vec::Vec};
use core::mem::MaybeUninit;

pub use quic_lite::Error;
use quic_lite::{AssociationProfile, ConnectionCounters, ConnectionDebugState, DatagramClient};
use quic_lite::{ConnectionId, ConnectionLimits, PathId, ServerStreamConfig, TransportPacket};

#[cfg(test)]
use crate::verified_object::ObjectBodyStream as ObjectRecordStream;
use crate::{
    probe::{ProbeRun, ProbeSender, ProbeServicePlan},
    stream_server::StreamServerConnection,
    verified_object::{GetRequest, ObjectBodyStream, REQUEST_MAX, encode_get_request},
};

/// Largest conservative application slice that fits with the QUIC-lite short
/// header and STREAM frame in the normal 1200-byte datagram. This is shared by
/// every ObjectUploadClient bearer; it is not a UDP fragment size or a
/// handler-owned retransmission unit.
const OBJECT_UPLOAD_STREAM_CHUNK: usize = 1024;

/// Bearer-neutral client for the `object.flash` two-stream operation.
///
/// Adapters drive this through [`quic_lite::DatagramClientDriver`]. They only
/// exchange complete datagrams; this type owns the association, command and
/// object streams, response correlation, ACK/credit polling, and loss repair.
pub struct ObjectUploadClient<const HISTORY: usize, const PACKET: usize> {
    association: quic_lite::ClientAssociation<HISTORY, PACKET>,
    command: [u8; PACKET],
    command_len: usize,
    object_stream: Option<u64>,
    records: ObjectBodyStream,
    scratch: [u8; OBJECT_UPLOAD_STREAM_CHUNK],
    command_admitted: bool,
    complete: bool,
    response: [u8; PACKET],
    response_len: usize,
    terminal_before_records: bool,
    path: PathId,
    last_admission_block: Option<Error>,
}

impl<const HISTORY: usize, const PACKET: usize> ObjectUploadClient<HISTORY, PACKET> {
    pub fn new(
        client_cid: ConnectionId,
        command: &[u8],
        records: ObjectBodyStream,
    ) -> Result<Self, Error> {
        if command.is_empty() || command.len() > PACKET {
            return Err(Error::BufferTooSmall);
        }
        let path = PathId::new(1).ok_or(Error::Invalid)?;
        let mut stored = [0; PACKET];
        stored[..command.len()].copy_from_slice(command);
        let mut association = quic_lite::ClientAssociation::new(client_cid);
        association.select_path(path);
        Ok(Self {
            association,
            command: stored,
            command_len: command.len(),
            object_stream: None,
            records,
            scratch: [0; OBJECT_UPLOAD_STREAM_CHUNK],
            command_admitted: false,
            complete: false,
            response: [0; PACKET],
            response_len: 0,
            terminal_before_records: false,
            path,
            last_admission_block: None,
        })
    }

    /// Request a lower receiver profile from the object peer before this
    /// association opens. The peer clamps the request to its device-owned
    /// hard limit and reports the resulting profile in OPEN_ACK.
    pub fn set_requested_peer_receive_profile(
        &mut self,
        request: quic_lite::ReceiveWindowRequest,
    ) -> Result<(), Error> {
        self.association
            .connection_mut()
            .set_requested_peer_receive_profile(request)
    }

    fn poll_application(&mut self, output: &mut [u8; PACKET]) -> Result<Option<usize>, Error> {
        if self.command_admitted && !self.records.is_complete() {
            let object_stream = self.object_stream.ok_or(Error::Invalid)?;
            let offset = self.records.sent_bytes() as u64;
            let available = self
                .association
                .available_stream_send_bytes(object_stream, offset)
                .unwrap_or(0)
                .min(self.scratch.len() as u64) as usize;
            if available == 0 {
                self.last_admission_block = Some(Error::FlowControl);
            } else if let Some(next) = self.records.copy_next(&mut self.scratch[..available]) {
                match self.association.encode_stream_payload_at(
                    object_stream,
                    next.offset,
                    &self.scratch[..next.len],
                    next.fin,
                    output,
                ) {
                    Ok((_path, used)) => {
                        self.last_admission_block = None;
                        if !self.records.advance(next) {
                            return Err(Error::Invalid);
                        }
                        return Ok(Some(used));
                    }
                    Err(error @ (Error::FlowControl | Error::HistoryFull | Error::Invalid)) => {
                        self.last_admission_block = Some(error);
                    }
                    Err(error) => return Err(error),
                }
            }
        }
        Ok(self
            .association
            .poll_transmit(output)?
            .map(|(_, used)| used))
    }

    pub fn response(&self) -> Option<&[u8]> {
        self.complete.then_some(&self.response[..self.response_len])
    }

    /// A terminal handler response received before the upload completed.
    /// This is an application rejection (for example, an unavailable flash
    /// target), rather than a malformed QUIC packet.
    pub fn rejected_response(&self) -> Option<&[u8]> {
        self.terminal_before_records
            .then(|| &self.response[..self.response_len])
    }

    pub fn record_index(&self) -> usize {
        self.records.record_index()
    }

    pub fn sent_bytes(&self) -> usize {
        self.records.sent_bytes()
    }

    /// Most recent ordinary QUIC-lite admission boundary encountered while
    /// offering the next object fragment. This is diagnostic state only;
    /// retransmission and scheduling remain in the driver.
    pub const fn last_admission_block(&self) -> Option<Error> {
        self.last_admission_block
    }

    /// Transport-owned admission facts for a bounded progress report. They
    /// distinguish a retained-ledger limit from byte/congestion backpressure
    /// without exposing packets or giving an adapter scheduling authority.
    pub fn admission_state(&self) -> Option<(usize, usize, u64, usize, u64, u64)> {
        let endpoint = self.association.connection().endpoint()?;
        let object_stream = self.object_stream?;
        let (connection_credit, stream_credit) = endpoint.peer_send_credit(object_stream)?;
        Some((
            endpoint.history_len(),
            endpoint.peer_max_in_flight_packets(),
            endpoint.bytes_in_flight(),
            endpoint.history_storage_slots(),
            connection_credit,
            stream_credit,
        ))
    }

    /// Bounded QUIC packet/control state for diagnosing a stalled operation.
    /// This is the same endpoint view used by server adapters and contains no
    /// object, flash, UART, or UDP-specific state.
    pub fn connection_debug_state(&self) -> Option<ConnectionDebugState> {
        self.association
            .connection()
            .endpoint()
            .map(ConnectionDebugState::from_endpoint)
    }

    pub fn transport_stats(&self) -> Option<quic_lite::TransportStats> {
        self.association
            .connection()
            .endpoint()
            .map(|endpoint| endpoint.stats())
    }

    /// Retire this one-shot association after its terminal response has been
    /// acknowledged.  The caller sends the ACK produced by `receive_at`
    /// first, then this ordinary QUIC CLOSE; no UDP or object-specific
    /// teardown packet exists.
    pub fn poll_close(&mut self, output: &mut [u8; PACKET]) -> Result<Option<usize>, Error> {
        self.association.close(0)?;
        self.association
            .poll_close(output)
            .map(|packet| packet.map(|(_, used)| used))
    }
}

impl<const HISTORY: usize, const PACKET: usize> DatagramClient<PACKET>
    for ObjectUploadClient<HISTORY, PACKET>
{
    fn start(&mut self, output: &mut [u8; PACKET]) -> Result<usize, Error> {
        self.association.start(output).map(|(_, used)| used)
    }

    fn receive_at(
        &mut self,
        input: &[u8],
        now_ms: u64,
        output: &mut [u8; PACKET],
    ) -> Result<Option<usize>, Error> {
        if self.association.peer_cid().is_none() {
            self.association
                .receive_open_ack(self.path, input, now_ms)?;
            let command_stream = self.association.open_next_client_bidi_stream()?;
            let object_stream = self.association.open_next_client_bidi_stream()?;
            self.object_stream = Some(object_stream);
            // The command and object are two streams in the same accepted
            // association. Opening the object stream must not wait for a
            // delayed ACK of the command stream: QUIC already supplied the
            // peer receive limits in OPEN_ACK, and a terminal application
            // rejection still stops the upload as soon as it arrives.
            self.command_admitted = true;
            return self
                .association
                .encode_stream_payload(
                    command_stream,
                    &self.command[..self.command_len],
                    true,
                    output,
                )
                .map(|(_, used)| Some(used));
        }
        // The transport driver admits a replayed OPEN_ACK as valid
        // association traffic before it considers opaque reset tokens.  Do
        // not hand that long-header setup replay to the ordinary short-header
        // response parser.
        if self.association.is_duplicate_open_ack(input) {
            return Ok(None);
        }
        let payload = self
            .association
            .receive_serial_response_payload(self.path, input, false)?;
        self.command_admitted = true;
        if let Some(payload) = payload {
            if payload.offset != self.response_len as u64
                || self.response_len.saturating_add(payload.data.len()) > PACKET
            {
                return Err(Error::Invalid);
            }
            self.response[self.response_len..self.response_len + payload.data.len()]
                .copy_from_slice(payload.data);
            self.response_len += payload.data.len();
            if payload.fin {
                self.terminal_before_records = !self.records.is_complete();
                self.complete = true;
                // A terminal application response is still an ordinary QUIC
                // stream packet.  Send the endpoint's ACK/control turn before
                // exposing completion to the bearer: Recovery arms its RTC
                // Main handoff only after QUIC observes this response as
                // delivered.  `poll_close` here discarded that ACK edge and
                // let a one-shot CLI exit strand Recovery after a durable
                // write.
                return Ok(self
                    .association
                    .poll_transmit(output)?
                    .map(|(_, used)| used));
            }
        }
        // This receive turn may have declared an earlier stream range lost.
        // Return only endpoint control here; DatagramClientDriver gives due
        // retransmission priority before asking for another fresh object
        // slice on its following service turn.
        Ok(self
            .association
            .poll_transmit(output)?
            .map(|(_, used)| used))
    }

    fn accepts(&self, input: &[u8]) -> bool {
        self.association.connection().accepts(input)
    }

    fn is_peer_stateless_reset(&self, input: &[u8]) -> bool {
        self.association.is_peer_stateless_reset(input)
    }

    fn is_complete(&self) -> bool {
        self.complete
    }

    fn poll_transmit_at(
        &mut self,
        _now_ms: u64,
        output: &mut [u8; PACKET],
    ) -> Result<Option<usize>, Error> {
        // Re-offer one ordered source slice after a prior congestion or
        // retained-history admission boundary.  The endpoint still decides
        // whether it can encode it; a rejected offer falls through to its
        // ordinary ACK/MAX/PTO control.  Waiting solely for another inbound
        // packet strands a sender when the last ACK freed congestion space
        // but did not itself cause an application callback.
        self.poll_application(output)
    }

    fn poll_control_at(
        &mut self,
        _now_ms: u64,
        output: &mut [u8; PACKET],
    ) -> Result<Option<usize>, Error> {
        Ok(self
            .association
            .poll_transmit(output)?
            .map(|(_, used)| used))
    }

    fn poll_application_at(
        &mut self,
        _now_ms: u64,
        output: &mut [u8; PACKET],
    ) -> Result<Option<usize>, Error> {
        self.poll_application(output)
    }

    fn poll_retransmit(
        &mut self,
        now_ms: u64,
        pto_ms: u64,
        output: &mut [u8; PACKET],
    ) -> Result<Option<usize>, Error> {
        Ok(self
            .association
            .poll_retransmit(now_ms, pto_ms, output)?
            .map(|(_, used)| used))
    }
}

/// Typed host-side outcome after a bounded association request exhausts its
/// retransmission budget. This does not assert a peer restart: it records only
/// that the retained association cannot serve another request without a fresh
/// bootstrap attempt.
#[cfg(feature = "std")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AssociationStreamTimeout {
    pub attempts: u32,
}

#[cfg(feature = "std")]
impl core::fmt::Display for AssociationStreamTimeout {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            formatter,
            "UDP stream request timeout after {} attempts",
            self.attempts
        )
    }
}

#[cfg(feature = "std")]
impl std::error::Error for AssociationStreamTimeout {}

/// Test whether an adapter error represents a token-verified peer restart.
/// Token recognition and packet framing remain private to quic-lite; a
/// timeout, TX failure, or malformed packet deliberately does not match.
#[cfg(feature = "std")]
pub fn is_peer_restarted_error(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause.downcast_ref::<quic_lite::Error>() == Some(&quic_lite::Error::PeerRestarted)
    })
}

/// A read-only service may make one fresh-association retry after either a
/// token-verified restart or a bounded stream timeout. The latter is not proof
/// of a restart, but the retained association has already been discarded and
/// replaying a catalogued read is safe. Mutations must retain their ambiguous
/// result and are never covered by this helper.
#[cfg(feature = "std")]
pub fn is_fresh_association_retry_error(error: &anyhow::Error) -> bool {
    is_peer_restarted_error(error)
        || error
            .chain()
            .any(|cause| cause.downcast_ref::<AssociationStreamTimeout>().is_some())
}

/// Result of driving a bounded connection egress burst.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EgressPumpResult {
    pub sent: usize,
    pub invalid_length: bool,
    pub submit_failed: bool,
}

/// Bearer-neutral diagnostic snapshot of the active QUIC association.
///
/// Path IDs are opaque adapter handles; callers may render a path as UART,
/// UDP, or NOW only at the frame-I/O boundary. CID, stream, and packet facts
/// are produced by QUIC-lite and have exactly the same meaning on every path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActiveConnectionStatus {
    pub receive_cid: ConnectionId,
    pub peer_cid: ConnectionId,
    pub active_path: Option<PathId>,
    pub known_paths: [Option<PathId>; 4],
    pub streams: quic_lite::ConnectionStreamStats,
    pub transport: quic_lite::TransportStats,
    /// Monotonic timestamp supplied to [`ConnectionDispatcher::set_time`] at
    /// the latest completed QUIC CLOSE. It is `None` until a peer closes an
    /// association; replacement by a fresh Initial is not a close.
    pub last_close_at: Option<u64>,
}

/// Opaque identity of one encoded terminal application response.
///
/// The stream number remains transport-private. Runtimes may retain this
/// value across one receive/poll turn solely to detect that a new terminal
/// response entered QUIC-lite.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TerminalResponseSnapshot {
    receive_cid: ConnectionId,
    stream: u64,
}

/// Join an application completion edge with terminal response delivery.
///
/// Persistent sinks commonly finish in the receive turn that also encodes
/// their response, so either edge may be observed first by a platform loop.
/// Keeping this order-independent join in host code prevents each runtime
/// from recreating a fragile pending-transition heuristic.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TerminalCompletionGate {
    application_complete: bool,
    response_delivered: bool,
}

impl TerminalCompletionGate {
    pub fn application_complete(&mut self) {
        self.application_complete = true;
    }

    pub fn response_delivered(&mut self) {
        self.response_delivered = true;
    }

    pub const fn application_is_complete(&self) -> bool {
        self.application_complete
    }

    pub fn take_complete(&mut self) -> bool {
        if !self.application_complete || !self.response_delivered {
            return false;
        }
        *self = Self::default();
        true
    }
}

/// Submit an optional immediate response and then poll up to the remaining
/// packet credit. The connection retains retransmission history; this helper
/// owns no packet, path, peer, or bearer queue.
pub fn pump_egress<const N: usize, P, T>(
    response: &mut [u8; N],
    packet_credit: usize,
    immediate: Option<usize>,
    mut poll: P,
    mut submit: T,
) -> EgressPumpResult
where
    P: FnMut(&mut [u8; N]) -> Option<usize>,
    T: FnMut(&[u8]) -> bool,
{
    let mut result = EgressPumpResult::default();
    let mut remaining = packet_credit;
    macro_rules! submit_one {
        ($used:expr) => {{
            let used = $used;
            if used > response.len() {
                result.invalid_length = true;
                false
            } else if !submit(&response[..used]) {
                result.submit_failed = true;
                false
            } else {
                result.sent += 1;
                remaining = remaining.saturating_sub(1);
                true
            }
        }};
    }
    if let Some(used) = immediate {
        if !submit_one!(used) {
            return result;
        }
    }
    while remaining != 0 {
        let Some(used) = poll(response) else {
            break;
        };
        if !submit_one!(used) {
            break;
        }
    }
    result
}

/// One active diagnostic connection is sufficient for the initial Recovery
/// raw-UDP6 validation. The bearer remains responsible for peer/MAC binding
/// and can allocate a separate server instance when it admits more peers.
pub struct ConnectionServer<const HISTORY: usize, const PACKET: usize> {
    local_cid: ConnectionId,
    local_limits: ConnectionLimits,
    // This ledger contains the bounded receive history and ordered-stream
    // state. Keep it off the Wi-Fi ingress task's stack: a raw bearer starts
    // with no connection and allocates this only after an accepted OPEN.
    // The association profile still bounds the live history/window.
    connection: Option<Box<StreamServerConnection<HISTORY, PACKET>>>,
    // A Wi-Fi unicast retry can redeliver the Initial OPEN after the server
    // already admitted it. Preserve the established packet-number state and
    // merely resend the deterministic ACK in that case.
    sender: Option<ProbeSender>,
    /// Client stream which created `sender`. A completed producer stays
    /// identifiable for a retransmission of that exact request, but must not
    /// prevent the same association from starting a later probe on a new
    /// stream.
    probe_request_stream: Option<u64>,
    // A handler-neutral two-stream operation.  The first peer bidi stream is
    // a tagged command; its next peer bidi stream carries ordered bytes for
    // the application that claimed that command.  Transport never decodes a
    // component-specific request or record format here.
    pending_stream_command: Option<Vec<u8>>,
    command_stream: Option<u64>,
    terminal_stream_response: Option<Vec<u8>>,
    terminal_response_stream: Option<u64>,
    inbound_stream: Option<u64>,
    /// Optional generic ordered-byte handler. New storage-bound consumers use
    /// this path so QUIC-lite retains an unread suffix instead of materializing
    /// dispatcher-owned fragment copies.
    inbound_stream_consumer: Option<InboundStreamConsumer>,
    inbound_stream_chunks: Vec<(Vec<u8>, bool)>,
    association: AssociationProfile,
}

/// A handler consumes an ordered prefix and returns its exact length. QUIC-lite
/// owns packet retention, reordering, acknowledgement, and receive credit.
pub type InboundStreamConsumer = fn(&[u8], bool) -> Result<usize, ()>;

/// Server-side application dispatcher for the one QUIC-lite association owned
/// by the firmware image.
///
/// `quic_lite::ServerConnection` owns CID admission, packet-number state,
/// stream state, retransmission, and the active/selected path. This wrapper
/// supplies DMesh-specific handler construction and dispatch only. It must
/// never become a second connection implementation or a bearer-state table.
///
/// The present embedded application policy admits one authenticated peer. A
/// future multi-device table belongs above `quic_lite::ServerConnection` and
/// is keyed by authenticated identity—not by UART port, UDP tuple, or NOW MAC.
pub struct ConnectionDispatcher<
    const HISTORY: usize,
    const PACKET: usize,
    const ASSOCIATIONS: usize = 1,
> {
    core: quic_lite::ServerAssociationTable<ConnectionServer<HISTORY, PACKET>, ASSOCIATIONS>,
    limits: ConnectionLimits,
    association: AssociationProfile,
    /// Optional higher association envelope which a host may select only in
    /// its OPEN. Normal admission keeps `association`; this is deliberately
    /// an association-time test/capability control rather than a handler or
    /// bearer setting.
    receive_profile_ceiling: AssociationProfile,
    stateless_reset_key: Option<quic_lite::StatelessResetKey>,
    last_stateless_reset: Option<StatelessResetDiagnostic>,
    last_time: u64,
    last_close_at: Option<u64>,
    last_closed_receive_cid: Option<ConnectionId>,
    // A CLOSE may carry the ACK for a terminal response.  The association
    // table correctly releases the connection in that same receive turn, so
    // retain this handler-neutral lifecycle edge outside the retired ledger
    // until the runtime consumes it.
    terminal_response_delivered: Option<ConnectionId>,
    // The dispatcher is long-lived firmware state.  Its server metadata is
    // small and fixed-size, so keeping it inline avoids a first-packet heap
    // allocation in every bearer.  The potentially large QUIC ledger remains
    // separately boxed by `ConnectionServer` only after an accepted OPEN.
}

/// Local-only explanation for an opaque stateless reset.
///
/// Stateless resets remain deliberately unparseable on the wire.  The
/// listener retains this bounded diagnostic so an operator can distinguish a
/// missing destination CID from an error inside an already-admitted stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StatelessResetDiagnostic {
    pub cause: StatelessResetCause,
    pub connection_id: quic_lite::ConnectionIdDiagnostic,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StatelessResetCause {
    /// The packet was a short-header datagram whose destination CID has no
    /// live association. Initial OPEN is never this case: it creates one.
    UnknownDestinationCid,
}

impl<const HISTORY: usize, const PACKET: usize, const ASSOCIATIONS: usize>
    ConnectionDispatcher<HISTORY, PACKET, ASSOCIATIONS>
{
    pub fn new(
        server_cid: ConnectionId,
        limits: ConnectionLimits,
        association: AssociationProfile,
    ) -> Self {
        Self {
            core: quic_lite::ServerAssociationTable::new(server_cid),
            limits,
            association,
            receive_profile_ceiling: association,
            stateless_reset_key: None,
            last_stateless_reset: None,
            last_time: 0,
            last_close_at: None,
            last_closed_receive_cid: None,
            terminal_response_delivered: None,
        }
    }

    /// Feed a complete datagram from any registered bearer. An immediate
    /// response is returned to the caller on the path selected by QUIC-lite:
    /// after successful admission it is this latest valid `path`; an invalid
    /// frame cannot redirect a response or retransmission.
    pub fn receive(
        &mut self,
        path: PathId,
        packet: &[u8],
        output: &mut [u8; PACKET],
    ) -> Result<Option<usize>, Error> {
        let addressed_receive_cid = match quic_lite::classify_server_datagram(packet) {
            Ok(quic_lite::ServerDatagram::Established { destination }) => Some(destination),
            _ => None,
        };
        let (limits, association) = self.requested_receive_profile(packet);
        self.core.set_time(self.last_time);
        // The table removes a peer as soon as it accepts CLOSE.  Capture a
        // terminal-response ACK while the ConnectionServer is still live:
        // short-lived UDP clients commonly combine their delayed ACK with
        // CLOSE, and a runtime post-turn query must not lose that delivery
        // edge merely because it is intentionally releasing the ledger.
        let mut terminal_response_delivered = None;
        let ingress = self.core.receive_admitted(
            path,
            packet,
            output,
            |server_cid, output| {
                ConnectionServer::accept(
                    packet,
                    server_cid,
                    limits,
                    association,
                    self.stateless_reset_key
                        .map(|key| key.token_for(server_cid)),
                    output,
                )
            },
            |server, output| server.replay_open(packet, output),
            |server, output| {
                let result = server.receive_established(packet, output);
                if result.is_ok() && server.take_terminal_response_delivered() {
                    terminal_response_delivered = server.expected_receive_cid();
                }
                result
            },
            ConnectionServer::is_closed,
            ConnectionServer::active_stream_count,
            ConnectionServer::peer_cid,
            ConnectionServer::expected_receive_cid,
        );
        let ingress = match ingress {
            Ok(ingress) => ingress,
            // Only a packet that the association table could not route is an
            // unknown-CID candidate.  `ConnectionServer` also uses
            // `WrongConnectionId` for post-admission endpoint state (for
            // example, an incomplete bootstrap handoff); turning those into
            // stateless resets falsely tells a valid peer that its live
            // association was discarded.
            Err(Error::WrongConnectionId)
                if self.stateless_reset_key.is_some()
                    && !self
                        .core
                        .owns_packet(packet, ConnectionServer::expected_receive_cid) =>
            {
                self.last_stateless_reset = Some(StatelessResetDiagnostic {
                    cause: StatelessResetCause::UnknownDestinationCid,
                    connection_id: self.connection_id_diagnostic(packet),
                });
                let Some(used) = self
                    .stateless_reset_key
                    .expect("checked above")
                    .encode_for_unknown_packet(packet, output)?
                else {
                    return Err(Error::WrongConnectionId);
                };
                return Ok(Some(used));
            }
            Err(error) => return Err(error),
        };
        if terminal_response_delivered.is_some() {
            self.terminal_response_delivered = terminal_response_delivered;
        }
        match ingress {
            quic_lite::ServerConnectionIngress::IgnoredOpen => Ok(None),
            quic_lite::ServerConnectionIngress::Accepted { result, retired } => {
                if retired {
                    self.last_close_at = Some(self.last_time);
                    self.last_closed_receive_cid = addressed_receive_cid;
                }
                Ok(result)
            }
        }
    }

    fn requested_receive_profile(&self, packet: &[u8]) -> (ConnectionLimits, AssociationProfile) {
        let base_association = self.association.clamp::<HISTORY>();
        let base_limits = self.limits;
        let Ok((_, open)) = quic_lite::decode_bootstrap_open_packet_with_limits(packet) else {
            return (base_limits, base_association);
        };
        let Some(request) = open.requested_peer_limits else {
            return (base_limits, base_association);
        };
        let ceiling = self.receive_profile_ceiling.clamp::<HISTORY>();
        let ceiling_limits = ceiling.receive_limits(PACKET as u64, base_limits.max_streams_bidi);
        let limits = ConnectionLimits::with_receive_profile(
            request.max_data.min(ceiling_limits.max_data),
            request.max_stream_data.min(ceiling_limits.max_stream_data),
            base_limits.max_streams_bidi,
        );
        let packets = usize::try_from(limits.max_data.div_ceil(PACKET as u64))
            .unwrap_or(HISTORY)
            .clamp(1, ceiling.history_packets);
        let association = AssociationProfile {
            history_packets: packets,
            initial_window_packets: packets,
            tx_burst_packets: base_association.tx_burst_packets.min(packets).max(1),
            ..base_association
        }
        .clamp::<HISTORY>();
        (limits, association)
    }

    /// Advance the connection-owned millisecond transport clock before
    /// receive or egress work. Platform adapters convert their monotonic
    /// source once at this boundary; keeping one unit here makes PTO, ACK,
    /// credit retry, and idle timing identical across UDP6, action, and UART.
    pub fn set_time(&mut self, now: u64) {
        self.last_time = now;
        self.core.set_time(now);
        for server in self.core.associations_mut() {
            if let Some(connection) = server.connection.as_mut() {
                connection.set_time(now);
            }
        }
        let _ = self
            .core
            .reclaim_idle(ConnectionServer::active_stream_count);
    }

    /// Configure idle association reclamation in the same monotonic units
    /// supplied to [`Self::set_time`]. Full-table admission may additionally
    /// reclaim the oldest association with no active streams.
    pub fn set_association_idle_timeout(&mut self, timeout: Option<u64>) {
        self.core.set_idle_timeout(timeout);
    }

    /// Install the reset-key branch derived from the platform's provisioned
    /// device/control-plane secret. It affects new OPEN_ACKs and unknown-CID
    /// recovery only; it never changes a live association's stream state.
    pub fn set_stateless_reset_key(&mut self, key: Option<quic_lite::StatelessResetKey>) {
        self.stateless_reset_key = key;
    }

    /// Last reset generated by this listener, if any. This is local
    /// observability only; the reset datagram itself stays opaque.
    pub const fn last_stateless_reset(&self) -> Option<StatelessResetDiagnostic> {
        self.last_stateless_reset
    }

    /// Active endpoint receive CID, if bootstrap has created an association.
    pub fn expected_receive_cid(&self) -> Option<ConnectionId> {
        self.core
            .active_path()
            .and_then(|path| self.core.association_for_path(path))
            .and_then(ConnectionServer::expected_receive_cid)
    }

    /// Select a live association by its local receive CID and return its
    /// current opaque path. Deferred handler work must use this instead of a
    /// bearer path, because several associations may share one UDP tuple.
    pub fn select_receive_cid(&mut self, receive_cid: ConnectionId) -> Option<PathId> {
        self.core
            .select_receive_cid(receive_cid, ConnectionServer::expected_receive_cid)
    }

    /// Terminate one application-aborted association. This is used only when
    /// a handler has released its own state after an error or idle deadline;
    /// the next normal poll sends the ordinary QUIC CLOSE. Bearers neither
    /// construct nor interpret the close packet.
    pub fn close_receive_cid(&mut self, receive_cid: ConnectionId, code: u64) -> bool {
        let Some(path) = self.select_receive_cid(receive_cid) else {
            return false;
        };
        let Some(server) = self.core.association_for_path_mut(path) else {
            return false;
        };
        let Some(connection) = server.connection.as_mut() else {
            return false;
        };
        connection.close(code);
        server.abandon_stream_command();
        true
    }

    /// Peer receive CID for the currently selected association.  Recovery
    /// uses this only to distinguish a fresh bootstrap from a replay when it
    /// replaces an abandoned flash receiver; bearer adapters never route on
    /// this value.
    pub fn active_peer_cid(&self) -> Option<ConnectionId> {
        self.core
            .active_path()
            .and_then(|path| self.core.association_for_path(path))
            .and_then(ConnectionServer::peer_cid)
    }

    /// Snapshot the one active logical association. This remains valid when
    /// the peer moves from UART to UDP or NOW: only the opaque path fields
    /// change after a valid packet; the CIDs and stream totals do not.
    pub fn active_connection_status(&self) -> Option<ActiveConnectionStatus> {
        let path = self.core.active_path()?;
        let server = self.core.association_for_path(path)?;
        let connection = server.connection.as_ref()?;
        Some(ActiveConnectionStatus {
            receive_cid: connection.local_connection_id()?,
            peer_cid: connection.peer_connection_id()?,
            active_path: Some(path),
            known_paths: self.core.known_paths_for(path),
            streams: connection.stream_stats(),
            transport: connection.transport_stats(),
            last_close_at: self.last_close_at,
        })
    }

    /// Number of independently live QUIC associations. This is endpoint
    /// state, not a count of bearer paths: one peer may have UART, UDP and
    /// NOW paths while consuming a single table entry.
    pub fn active_association_count(&self) -> usize {
        self.core.active_len()
    }

    /// Timestamp of the latest accepted QUIC CLOSE, retained even after the
    /// endpoint ledger has been released.
    pub const fn last_close_at(&self) -> Option<u64> {
        self.last_close_at
    }

    /// Receive CID retired by the latest accepted CLOSE. Application
    /// operation ownership is association-scoped, so a rejected contender
    /// sharing the same bearer path cannot close another association's sink.
    pub const fn last_closed_receive_cid(&self) -> Option<ConnectionId> {
        self.last_closed_receive_cid
    }

    /// Poll delayed control only for the path that last made valid service
    /// progress. This gives current single-association measurements stable
    /// same-bearer replies while preserving a clean hook for multipath policy.
    pub fn poll_for(
        &mut self,
        path: PathId,
        output: &mut [u8; PACKET],
    ) -> Result<Option<usize>, Error> {
        if self.core.active_path() != Some(path) {
            return Ok(None);
        }
        self.core
            .association_for_path_mut(path)
            .map_or(Ok(None), |server| server.poll(output))
    }

    /// Finish one application receive turn after its stream consumer ran.
    ///
    /// An inbound packet can cause an ACK/control datagram before the consumer
    /// releases storage. If consumption subsequently queues a newer QUIC
    /// control or response packet, send that packet now; otherwise retain the
    /// already encoded packet. This keeps one receive turn to one bearer
    /// datagram without making a flash/file/prober handler depend on a later
    /// timer turn for its MAX_* update.
    pub fn finish_receive_turn(
        &mut self,
        path: PathId,
        immediate: Option<usize>,
        output: &mut [u8; PACKET],
    ) -> Result<Option<usize>, Error> {
        // A service response is already the one useful packet for this
        // receive turn. Do not replace it with a fresh ACK-only packet merely
        // because the endpoint also has ordinary control pending. ACK/MAX
        // packets, in contrast, may be superseded by capacity the consumer
        // just released.
        if immediate.is_some_and(|used| quic_lite::packet_has_stream_frame(&output[..used])) {
            return Ok(immediate);
        }
        match self.poll_for(path, output)? {
            Some(used) => Ok(Some(used)),
            None => Ok(immediate),
        }
    }

    /// Drive one endpoint-owned PTO retransmission on the bearer which last
    /// made service progress.  The dispatcher retains no copy of a response:
    /// the QUIC-lite endpoint ledger owns the retransmittable packet.
    pub fn poll_retransmit_for(
        &mut self,
        path: PathId,
        now_us: u64,
        pto_us: u64,
        output: &mut [u8; PACKET],
    ) -> Result<Option<usize>, Error> {
        if self.core.active_path() != Some(path) {
            return Ok(None);
        }
        self.core
            .association_for_path_mut(path)
            .map_or(Ok(None), |server| {
                server.poll_retransmit(now_us, pto_us, output)
            })
    }

    /// Drive the next association-owned service packet on a valid path.
    ///
    /// Newly queued QUIC control (for example a receive-window update after
    /// any stream consumer releases storage) takes precedence over a due
    /// retransmission.  Otherwise a flow-blocked peer can repeatedly receive
    /// an older packet while the one packet that grants it more credit stays
    /// queued.  Both packets remain wholly QUIC-lite owned; this only chooses
    /// their service order and is independent of bearer and handler.
    pub fn poll_service_for(
        &mut self,
        path: PathId,
        now_us: u64,
        pto_us: u64,
        output: &mut [u8; PACKET],
    ) -> Result<Option<usize>, Error> {
        self.poll_for(path, output)?.map_or_else(
            || self.poll_retransmit_for(path, now_us, pto_us, output),
            |used| Ok(Some(used)),
        )
    }

    pub fn reply_path(&self) -> Option<PathId> {
        self.core.active_path()
    }

    /// Whether an admitted association still owns this opaque platform path.
    /// Adapters use this only to reclaim stale address bindings; it exposes no
    /// CID, peer address, or transport state.
    pub fn has_path(&self, path: PathId) -> bool {
        self.core.association_for_path(path).is_some()
    }

    /// Whether `packet` is addressed to this dispatcher's live server
    /// association on `path`.
    ///
    /// A board can be an action client and an action server for the same peer
    /// at once: for example, the peer may start PROBE while this board is
    /// still draining a completed discovery check. The adapter must then
    /// demultiplex by QUIC-lite DCID, not by source MAC alone. An Initial OPEN
    /// is admitted by the connection owner; an established packet must name
    /// the live endpoint receive CID, but may arrive on any bearer path and
    /// thereby migrate the association's return path.
    /// This method retains no packet and performs no transport
    /// work, so it is safe for the shared ingress owner to use as its routing
    /// predicate.
    pub fn owns_packet_for_path(&self, path: PathId, packet: &[u8]) -> bool {
        let _ = path;
        self.core.owns_packet(packet, |server| {
            server
                .connection
                .as_ref()
                .and_then(|connection| connection.local_connection_id())
        })
    }

    /// Return rejected-packet CID context without requiring the firmware or
    /// host bearer adapter to parse a QUIC header.
    pub fn connection_id_diagnostic(&self, packet: &[u8]) -> quic_lite::ConnectionIdDiagnostic {
        let received = quic_lite::classify_server_datagram(packet)
            .ok()
            .and_then(|datagram| match datagram {
                quic_lite::ServerDatagram::Established { destination } => Some(destination),
                _ => None,
            });
        quic_lite::ConnectionIdDiagnostic {
            received,
            expected: self.expected_receive_cid(),
        }
    }

    /// Maximum number of fresh stream packets the bearer may emit from one
    /// ingress callback.  The value comes from the association profile rather
    /// than the radio adapter, so host and firmware use the same burst policy.
    pub const fn tx_burst_packets(&self) -> usize {
        self.association.tx_burst_packets
    }

    /// Replace defaults for the next raw QUIC-lite association.
    ///
    /// ACK cadence and egress burst are negotiated/applied while accepting
    /// OPEN. They cannot safely mutate an active endpoint's history or ACK
    /// timer, so changing them retires only that endpoint and its reply path.
    /// The physical bearer remains entirely untouched.
    pub fn replace_association(&mut self, association: AssociationProfile) {
        self.association = association.clamp::<HISTORY>();
        self.core.replace_all();
    }

    /// Update defaults used by the next association without disturbing a
    /// live logical connection. Physical bearer changes call this method so
    /// the current DCID, streams, and handler state can migrate when a valid
    /// packet arrives on the new path.
    pub fn set_association_defaults(&mut self, association: AssociationProfile) {
        self.association = association.clamp::<HISTORY>();
    }

    /// Defaults used only for the next admitted association.  Platform code
    /// may resample its current allocator state between short-lived peers,
    /// while a live CID keeps the profile it accepted in OPEN_ACK.
    pub const fn association_defaults(&self) -> AssociationProfile {
        self.association
    }

    /// Permit a host OPEN to select a larger initial receive profile for a
    /// controlled capability or stress test. The ceiling is an allocation
    /// bound, never an automatic increase: without an OPEN request the
    /// ordinary memory-selected association remains in force.
    pub fn set_receive_profile_ceiling(&mut self, ceiling: AssociationProfile) {
        self.receive_profile_ceiling = ceiling.clamp::<HISTORY>();
    }

    /// Snapshot common QUIC counters for a bearer-neutral diagnostic report.
    pub fn transport_stats(&self) -> Option<quic_lite::TransportStats> {
        match self
            .core
            .active_path()
            .and_then(|path| self.core.association_for_path(path))
        {
            Some(server) => match server.connection.as_ref() {
                Some(connection) => Some(connection.transport_stats()),
                None => None,
            },
            None => None,
        }
    }

    /// Profile accepted by the currently live association.  This is useful
    /// to a constrained callback adapter only for sizing its temporary
    /// packet handoff; QUIC's advertised credit, loss recovery and pacing
    /// remain entirely inside the connection.
    pub fn active_association_profile(&self) -> Option<AssociationProfile> {
        self.core
            .active_path()
            .and_then(|path| self.core.association_for_path(path))
            .map(ConnectionServer::association_profile)
    }

    /// ACK/congestion state needed to distinguish radio loss from a stalled
    /// peer ACK path in a raw-bearer report.
    pub fn transport_ack_state(&self) -> Option<(Option<u32>, u64, u64)> {
        match self
            .core
            .active_path()
            .and_then(|path| self.core.association_for_path(path))
        {
            Some(server) => match server.connection.as_ref() {
                Some(connection) => Some(connection.transport_ack_state()),
                None => None,
            },
            None => None,
        }
    }

    /// Return the current association's transport-owned timer deadline.
    /// `now` and `pto` remain caller supplied so UART, UDP6, and NOW can use
    /// their native monotonic clock without giving the shared dispatcher a
    /// task, timer, or bearer-specific service loop.
    pub fn next_service_deadline(&self, pto: u64) -> Option<u64> {
        self.core
            .active_path()
            .and_then(|path| self.core.association_for_path(path))
            .and_then(|server| server.next_service_deadline(pto))
    }

    /// Earliest timer target across all live associations. The receive CID
    /// keeps two clients on one physical path distinct.
    pub fn next_service_target(&self, pto: u64) -> Option<(ConnectionId, PathId, u64)> {
        self.core
            .earliest_deadline(ConnectionServer::expected_receive_cid, |server| {
                server.next_service_deadline(pto)
            })
    }

    /// Select the next transport deadline, or the active association for an
    /// explicitly requested application-maintenance turn.
    ///
    /// The fallback does not create a timer or force a packet: callers still
    /// use `poll_service_for`, which asks QUIC-lite whether any ACK, MAX_*,
    /// or PTO packet is due.  It only lets a handler start asynchronous work
    /// (for example, a verified-object sink's erase) without waiting for a
    /// further peer datagram to manufacture a QUIC deadline.
    pub fn service_target_or_active(&self, pto: u64) -> Option<(ConnectionId, PathId, u64)> {
        self.next_service_target(pto).or_else(|| {
            let path = self.core.active_path()?;
            let server = self.core.association_for_path(path)?;
            Some((server.expected_receive_cid()?, path, 0))
        })
    }

    /// Return bounded ACK ranges and retained packet numbers for automated
    /// bearer diagnostics.  The host action adapter serializes this into its
    /// event history; firmware can consume the same structure without a
    /// socket-shaped API.
    pub fn connection_debug_state(&self) -> Option<ConnectionDebugState> {
        let path = self.core.active_path()?;
        let connection = self.core.association_for_path(path)?.connection.as_ref()?;
        Some(connection.debug_state())
    }

    /// Take one tagged command which requires a following inbound stream.
    /// The application owns decoding and decides whether to accept it.
    pub fn take_stream_command(&mut self) -> Option<Vec<u8>> {
        let path = self.core.active_path()?;
        self.core
            .association_for_path_mut(path)?
            .take_stream_command()
    }

    fn take_inbound_stream_chunks(&mut self) -> Vec<(Vec<u8>, bool)> {
        let Some(path) = self.core.active_path() else {
            return Vec::new();
        };
        self.core
            .association_for_path_mut(path)
            .map_or_else(Vec::new, ConnectionServer::take_inbound_stream_chunks)
    }

    fn restore_inbound_stream_chunks(&mut self, mut chunks: Vec<(Vec<u8>, bool)>) {
        let Some(path) = self.core.active_path() else {
            return;
        };
        if let Some(server) = self.core.association_for_path_mut(path) {
            server.restore_inbound_stream_chunks(&mut chunks);
        }
    }

    pub fn has_inbound_stream_chunks(&self) -> bool {
        let Some(path) = self.core.active_path() else {
            return false;
        };
        self.core
            .association_for_path(path)
            .is_some_and(ConnectionServer::has_inbound_stream_chunks)
    }

    /// Queue an already encoded handler response after its inbound stream is
    /// complete. Tagged response construction is deliberately handler code.
    pub fn complete_stream_command(&mut self, response: Vec<u8>) -> Result<(), Error> {
        let path = self.core.active_path().ok_or(Error::Invalid)?;
        self.core
            .association_for_path_mut(path)
            .ok_or(Error::Invalid)?
            .complete_stream_command(response)
    }

    /// Whether the active application operation has queued a terminal
    /// response. Runtimes use this only for lifecycle transitions after the
    /// connection emits that response; packet ownership remains in QUIC-lite.
    pub fn terminal_response_pending(&self) -> bool {
        self.core
            .active_path()
            .and_then(|path| self.core.association_for_path(path))
            .is_some_and(ConnectionServer::terminal_response_pending)
    }

    /// Opaque snapshot of the currently encoded terminal response.
    pub fn terminal_response_snapshot(&self) -> Option<TerminalResponseSnapshot> {
        let path = self.core.active_path()?;
        let server = self.core.association_for_path(path)?;
        Some(TerminalResponseSnapshot {
            receive_cid: server.expected_receive_cid()?,
            stream: server.terminal_response_stream?,
        })
    }

    /// Association whose encoded response differs from `before`.
    pub fn terminal_response_started_after(
        &self,
        before: Option<TerminalResponseSnapshot>,
    ) -> Option<ConnectionId> {
        let current = self.terminal_response_snapshot()?;
        (Some(current) != before).then_some(current.receive_cid)
    }

    /// Take the active association's generic terminal-response delivery edge.
    /// QUIC-lite has already processed the peer acknowledgement internally.
    pub fn take_terminal_response_delivered(&mut self) -> Option<ConnectionId> {
        if let Some(receive_cid) = self.terminal_response_delivered.take() {
            return Some(receive_cid);
        }
        let Some(path) = self.core.active_path() else {
            return None;
        };
        let server = self.core.association_for_path_mut(path)?;
        let receive_cid = server.expected_receive_cid()?;
        server
            .take_terminal_response_delivered()
            .then_some(receive_cid)
    }

    fn consume_inbound_stream_bytes(&mut self, bytes: usize) -> Result<(), Error> {
        let path = self.core.active_path().ok_or(Error::Invalid)?;
        self.core
            .association_for_path_mut(path)
            .ok_or(Error::Invalid)?
            .consume_inbound_stream_bytes(bytes)
    }

    fn prepare_inbound_stream(&mut self) -> Result<(), Error> {
        let path = self.core.active_path().ok_or(Error::Invalid)?;
        self.core
            .association_for_path_mut(path)
            .ok_or(Error::Invalid)?
            .prepare_inbound_stream()
    }

    fn prepare_inbound_stream_with_consumer(
        &mut self,
        consumer: InboundStreamConsumer,
    ) -> Result<(), Error> {
        let path = self.core.active_path().ok_or(Error::Invalid)?;
        self.core
            .association_for_path_mut(path)
            .ok_or(Error::Invalid)?
            .prepare_inbound_stream_with_consumer(consumer)
    }

    pub fn resume_inbound_stream_consumer(&mut self) -> Result<usize, Error> {
        let path = self.core.active_path().ok_or(Error::Invalid)?;
        self.core
            .association_for_path_mut(path)
            .ok_or(Error::Invalid)?
            .resume_inbound_stream_consumer()
    }

    /// Release the active handler-neutral stream command after its QUIC
    /// association has explicitly closed. The platform consumer owns its
    /// sink lifetime.
    pub fn abandon_stream_command(&mut self) {
        if let Some(path) = self.core.active_path()
            && let Some(server) = self.core.association_for_path_mut(path)
        {
            server.abandon_stream_command();
        }
    }
}

/// Run one complete server ingress turn for every datagram bearer.
///
/// Host simulations, Main, and Recovery use this same ordering: advance the
/// transport clock, let the application expire stale state, admit the packet,
/// deliver ordered stream bytes, then prefer newly released MAX_* credit over
/// an older ACK-only packet. The physical adapter only supplies complete
/// datagrams, an opaque path, time, and a buffer for the returned datagram.
pub fn receive_server_turn<
    Before,
    After,
    const HISTORY: usize,
    const PACKET: usize,
    const ASSOCIATIONS: usize,
>(
    service: &mut ConnectionDispatcher<HISTORY, PACKET, ASSOCIATIONS>,
    path: PathId,
    packet: &[u8],
    now: u64,
    output: &mut [u8; PACKET],
    before_receive: Before,
    after_receive: After,
) -> Result<Option<usize>, Error>
where
    Before: FnOnce(&mut ConnectionDispatcher<HISTORY, PACKET, ASSOCIATIONS>, u64),
    After: FnOnce(&mut ConnectionDispatcher<HISTORY, PACKET, ASSOCIATIONS>, PathId, u64, bool),
{
    service.set_time(now);
    before_receive(service, now);
    let close_before = service.last_close_at();
    let immediate = service.receive(path, packet, output)?;
    let closed = service.last_close_at() != close_before;
    after_receive(service, path, now, closed);
    service.finish_receive_turn(path, immediate, output)
}

/// Run the common application-maintenance and QUIC control/PTO turn.
/// Adapters schedule this at [`ConnectionDispatcher::next_service_deadline`]
/// and transmit the returned datagram without interpreting it.
pub fn poll_server_turn<
    Before,
    const HISTORY: usize,
    const PACKET: usize,
    const ASSOCIATIONS: usize,
>(
    service: &mut ConnectionDispatcher<HISTORY, PACKET, ASSOCIATIONS>,
    path: PathId,
    now: u64,
    pto: u64,
    output: &mut [u8; PACKET],
    before_poll: Before,
) -> Result<Option<usize>, Error>
where
    Before: FnOnce(&mut ConnectionDispatcher<HISTORY, PACKET, ASSOCIATIONS>, PathId, u64),
{
    service.set_time(now);
    before_poll(service, path, now);
    service.poll_service_for(path, now, pto, output)
}

/// Publish application storage completion and immediately run the same
/// control/PTO selection used by an ordinary timer turn.
pub fn stream_consumer_ready_server_turn<
    Ready,
    const HISTORY: usize,
    const PACKET: usize,
    const ASSOCIATIONS: usize,
>(
    service: &mut ConnectionDispatcher<HISTORY, PACKET, ASSOCIATIONS>,
    now: u64,
    pto: u64,
    output: &mut [u8; PACKET],
    consumer_ready: Ready,
) -> Result<Option<(PathId, usize)>, Error>
where
    Ready: FnOnce(
        &mut ConnectionDispatcher<HISTORY, PACKET, ASSOCIATIONS>,
        u64,
    ) -> Result<Option<PathId>, ()>,
{
    service.set_time(now);
    let Some(path) = consumer_ready(service, now).map_err(|_| Error::Invalid)? else {
        return Ok(None);
    };
    service
        .poll_service_for(path, now, pto, output)
        .map(|packet| packet.map(|used| (path, used)))
}

/// Handler-neutral ordered stream reader.
///
/// QUIC chunking, FIN markers, packet retention, and flow-control accounting
/// stay private. A normal handler copies bytes into its own bounded parser or
/// storage buffer through [`Self::read`]; when this reader is dropped the
/// dispatcher restores any unread suffix and returns credit for precisely the
/// copied prefix. A future owned-packet lease can share this same release edge
/// without changing handler protocol code.
pub struct InboundStreamReader {
    chunks: Vec<(Vec<u8>, bool)>,
    chunk: usize,
    offset: usize,
    consumed: usize,
}

impl InboundStreamReader {
    fn new(chunks: Vec<(Vec<u8>, bool)>) -> Self {
        Self {
            chunks,
            chunk: 0,
            offset: 0,
            consumed: 0,
        }
    }

    pub const fn consumed_bytes(&self) -> usize {
        self.consumed
    }

    pub fn read(&mut self, out: &mut [u8]) -> usize {
        let mut written = 0;
        while written < out.len() && self.chunk < self.chunks.len() {
            let bytes = &self.chunks[self.chunk].0;
            let available = bytes.len().saturating_sub(self.offset);
            if available == 0 {
                self.chunk += 1;
                self.offset = 0;
                continue;
            }
            let count = available.min(out.len() - written);
            out[written..written + count].copy_from_slice(&bytes[self.offset..self.offset + count]);
            written += count;
            self.offset += count;
            self.consumed = self.consumed.saturating_add(count);
        }
        written
    }

    fn into_remaining(mut self) -> Vec<(Vec<u8>, bool)> {
        let mut remaining = Vec::new();
        if self.chunk < self.chunks.len() {
            let (bytes, fin) = &mut self.chunks[self.chunk];
            if self.offset < bytes.len() {
                remaining.push((bytes.split_off(self.offset), *fin));
            }
            self.chunk += 1;
        }
        remaining.extend(self.chunks.drain(self.chunk..));
        remaining
    }
}

impl crate::verified_object::OrderedStreamRead for InboundStreamReader {
    fn read(&mut self, out: &mut [u8]) -> usize {
        Self::read(self, out)
    }

    fn is_finished(&self) -> bool {
        let Some((bytes, fin)) = self.chunks.get(self.chunk) else {
            return false;
        };
        *fin && self.offset == bytes.len() && self.chunk + 1 == self.chunks.len()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InboundStreamTurn {
    pub had_chunks: bool,
    pub application_progress: bool,
    pub consumed_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InboundStreamTurnError<E> {
    Consumer(E),
    Transport(Error),
}

#[derive(Debug, Eq, PartialEq)]
pub enum ExclusiveInboundStreamTurnError<T, E> {
    /// The application rejected the ordered bytes. The failed operation has
    /// already been removed, so a later request cannot remain falsely busy.
    Consumer { request_id: u64, value: T, error: E },
    /// QUIC could not publish the resulting receive boundary. The application
    /// remains owned because its already-consumed state must not be discarded.
    Transport(Error),
}

/// Reserve the application stream following an admitted command and publish
/// the consumer's initial storage boundary. Keeping this beside
/// [`consume_inbound_stream`] prevents handlers from manipulating QUIC flow
/// control directly.
pub fn prepare_inbound_stream<
    const HISTORY: usize,
    const PACKET: usize,
    const ASSOCIATIONS: usize,
>(
    service: &mut ConnectionDispatcher<HISTORY, PACKET, ASSOCIATIONS>,
) -> Result<(), Error> {
    service.prepare_inbound_stream()
}

pub fn prepare_inbound_stream_with_consumer<
    const HISTORY: usize,
    const PACKET: usize,
    const ASSOCIATIONS: usize,
>(
    service: &mut ConnectionDispatcher<HISTORY, PACKET, ASSOCIATIONS>,
    consumer: InboundStreamConsumer,
) -> Result<(), Error> {
    service.prepare_inbound_stream_with_consumer(consumer)
}

pub fn consume_inbound_stream<
    Consume,
    ConsumerError,
    const HISTORY: usize,
    const PACKET: usize,
    const ASSOCIATIONS: usize,
>(
    service: &mut ConnectionDispatcher<HISTORY, PACKET, ASSOCIATIONS>,
    consume: Consume,
) -> Result<InboundStreamTurn, InboundStreamTurnError<ConsumerError>>
where
    Consume: FnOnce(&mut InboundStreamReader) -> Result<bool, ConsumerError>,
{
    let chunks = service.take_inbound_stream_chunks();
    let had_chunks = !chunks.is_empty();
    let mut reader = InboundStreamReader::new(chunks);
    let application_progress = consume(&mut reader).map_err(InboundStreamTurnError::Consumer)?;
    let consumed_bytes = reader.consumed_bytes();
    service.restore_inbound_stream_chunks(reader.into_remaining());
    if consumed_bytes != 0 {
        service
            .consume_inbound_stream_bytes(consumed_bytes)
            .map_err(InboundStreamTurnError::Transport)?;
    }
    Ok(InboundStreamTurn {
        had_chunks,
        application_progress,
        consumed_bytes,
    })
}

pub fn consume_exclusive_inbound_stream<
    T,
    Consume,
    ConsumerError,
    const HISTORY: usize,
    const PACKET: usize,
    const ASSOCIATIONS: usize,
>(
    service: &mut ConnectionDispatcher<HISTORY, PACKET, ASSOCIATIONS>,
    operation: &mut crate::verified_object::ExclusiveTransfer<T>,
    owner: ConnectionId,
    now: u64,
    idle_timeout: u64,
    consume: Consume,
) -> Result<InboundStreamTurn, ExclusiveInboundStreamTurnError<T, ConsumerError>>
where
    Consume: FnOnce(&mut T, &mut InboundStreamReader) -> Result<bool, ConsumerError>,
{
    let turn = match consume_inbound_stream(service, |reader| {
        let value = operation
            .get_mut_for(owner)
            .expect("exclusive stream owner must remain active during consume");
        consume(value, reader)
    }) {
        Ok(turn) => turn,
        Err(InboundStreamTurnError::Consumer(error)) => {
            let request_id = operation
                .request_id_for(owner)
                .expect("exclusive owner request id");
            let value = operation
                .take_for(owner)
                .expect("exclusive stream owner remains active after error");
            return Err(ExclusiveInboundStreamTurnError::Consumer {
                request_id,
                value,
                error,
            });
        }
        Err(InboundStreamTurnError::Transport(error)) => {
            return Err(ExclusiveInboundStreamTurnError::Transport(error));
        }
    };
    if turn.application_progress {
        debug_assert!(operation.touch(owner, now, idle_timeout));
    }
    Ok(turn)
}

pub fn consume_available_exclusive_inbound_stream<
    T,
    Consume,
    ConsumerError,
    const HISTORY: usize,
    const PACKET: usize,
    const ASSOCIATIONS: usize,
>(
    service: &mut ConnectionDispatcher<HISTORY, PACKET, ASSOCIATIONS>,
    operation: &mut crate::verified_object::ExclusiveTransfer<T>,
    owner: ConnectionId,
    now: u64,
    idle_timeout: u64,
    consume: Consume,
) -> Result<Option<InboundStreamTurn>, ExclusiveInboundStreamTurnError<T, ConsumerError>>
where
    Consume: FnOnce(&mut T, &mut InboundStreamReader) -> Result<bool, ConsumerError>,
{
    if !service.has_inbound_stream_chunks() {
        return Ok(None);
    }
    consume_exclusive_inbound_stream(service, operation, owner, now, idle_timeout, consume)
        .map(Some)
}

/// Thread-safe owner for one bearer-neutral connection dispatcher.
///
/// Linux and Android adapters clone this handle and inject complete frames
/// with opaque path IDs. They never construct, inspect, or reset QUIC state
/// themselves; stopping one physical bearer only asks this owner to retire
/// the association.
#[cfg(feature = "std")]
#[derive(Clone)]
pub struct SharedConnectionRuntime<const HISTORY: usize, const PACKET: usize> {
    dispatcher: std::sync::Arc<std::sync::Mutex<ConnectionDispatcher<HISTORY, PACKET>>>,
}

#[cfg(feature = "std")]
impl<const HISTORY: usize, const PACKET: usize> SharedConnectionRuntime<HISTORY, PACKET> {
    pub fn new(
        server_cid: ConnectionId,
        limits: ConnectionLimits,
        association: AssociationProfile,
    ) -> Self {
        Self {
            dispatcher: std::sync::Arc::new(std::sync::Mutex::new(ConnectionDispatcher::new(
                server_cid,
                limits,
                association,
            ))),
        }
    }

    fn with<R>(&self, f: impl FnOnce(&mut ConnectionDispatcher<HISTORY, PACKET>) -> R) -> R {
        let mut dispatcher = self
            .dispatcher
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        f(&mut dispatcher)
    }

    pub fn receive_at(
        &self,
        path: PathId,
        packet: &[u8],
        now: u64,
        output: &mut [u8; PACKET],
    ) -> Result<Option<usize>, Error> {
        self.with(|dispatcher| {
            dispatcher.set_time(now);
            dispatcher.receive(path, packet, output)
        })
    }

    pub fn poll_for(
        &self,
        path: PathId,
        output: &mut [u8; PACKET],
    ) -> Result<Option<usize>, Error> {
        self.with(|dispatcher| dispatcher.poll_for(path, output))
    }

    pub fn poll_retransmit_for(
        &self,
        path: PathId,
        now: u64,
        pto: u64,
        output: &mut [u8; PACKET],
    ) -> Result<Option<usize>, Error> {
        self.with(|dispatcher| dispatcher.poll_retransmit_for(path, now, pto, output))
    }

    pub fn reply_path(&self) -> Option<PathId> {
        self.with(|dispatcher| dispatcher.reply_path())
    }

    pub fn tx_burst_packets(&self) -> usize {
        self.with(|dispatcher| dispatcher.tx_burst_packets())
    }

    pub fn transport_stats(&self) -> Option<quic_lite::TransportStats> {
        self.with(|dispatcher| dispatcher.transport_stats())
    }

    pub fn transport_ack_state(&self) -> Option<(Option<u32>, u64, u64)> {
        self.with(|dispatcher| dispatcher.transport_ack_state())
    }

    pub fn connection_debug_state(&self) -> Option<ConnectionDebugState> {
        self.with(|dispatcher| dispatcher.connection_debug_state())
    }
}

/// Host-testable client state for a complete-datagram bearer such as raw
/// ESP-NOW action frames. It has no socket, radio, timer, or ESP dependency:
/// an adapter sends each returned packet and feeds received packets back in.
///
/// Keeping this next to [`ConnectionServer`] prevents UART, UDP, and raw-action
/// tools from growing subtly different bootstrap/ACK/PROBE client loops.
pub struct ProbeClient<const HISTORY: usize, const PACKET: usize> {
    connection: quic_lite::ClientConnection<HISTORY, PACKET>,
    request: [u8; crate::probe::PROBE_RUN_REQUEST_MAX],
    request_len: usize,
    run: ProbeRun<{ crate::probe::PROBE_MAX_NORMAL_STREAMS }>,
    complete: bool,
    close_when_complete: bool,
    bootstrap_acks: u32,
    stream_packets: u32,
    other_packets: u32,
    /// First server-created stream expected for this run. A retained
    /// association may already have completed tagged requests, so this is not
    /// necessarily `FIRST_SERVER_BIDI_STREAM_ID`.
    first_response_stream_id: u64,
    /// The next association-global server stream after this probe completes.
    /// It is returned when the transitional caller restores its tagged
    /// collector, preventing a later request from reusing a consumed stream.
    next_server_bidi_stream_id: u64,
    /// The next locally initiated stream remains association state while this
    /// ordinary probe temporarily owns the operation collector.
    next_client_bidi_stream_id: u64,
    deferred_consumption: [DeferredConsumption; crate::probe::PROBE_MAX_NORMAL_STREAMS + 2],
    initial_consume_delay_ms: u32,
    consume_delay_ms: u32,
    first_chunk_seen: bool,
    consume_barrier_until_ms: Option<u64>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct DeferredConsumption {
    stream: u64,
    bytes: usize,
    release_at_ms: u64,
    active: bool,
}

/// Bounded tagged-CBOR request/response client for a complete-datagram
/// bearer.  It uses the same QUIC-lite association and ACK ownership as the
/// connection client, but carries one whole tagged record without inserting a
/// legacy service byte. The application response is retained in the same
/// packet-sized bound, so a raw adapter never grows a private queue.
pub struct TaggedClient<const HISTORY: usize, const PACKET: usize> {
    connection: quic_lite::ClientConnection<HISTORY, PACKET>,
    request: [u8; PACKET],
    request_len: usize,
    complete: bool,
    close_when_complete: bool,
    response: [u8; PACKET],
    response_len: usize,
    response_stream_id: Option<u64>,
    /// The client-created bidirectional stream carrying the outstanding
    /// request.  A peer may send delayed data for an earlier stream while a
    /// retained association has advanced to the next request; that packet is
    /// acknowledged by QUIC-lite but must never become this request's tagged
    /// response.
    expected_response_stream_id: Option<u64>,
    /// The dispatcher opens each tagged result on its next server-initiated
    /// bidirectional stream. This sequence is association-global and is not
    /// derived from the client request stream number.
    next_server_bidi_stream_id: u64,
    /// Client-created stream IDs are association state.  The temporary
    /// complete-frame adapter retains it here until it is replaced by the
    /// common `quic_lite::ClientAssociation` driver.
    next_client_bidi_stream_id: u64,
    counters: ConnectionCounters,
}

/// Bearer-neutral, incremental signed-object GET client.
///
/// It retains only the bounded QUIC-lite ledger and the small GET request.
/// Every authenticated object-response fragment is handed to `on_fragment`
/// before receive credit is returned, so a firmware flash sink can defer
/// credit until durable storage is available without a bearer-private queue.
pub struct ObjectClient<const HISTORY: usize, const PACKET: usize> {
    connection: quic_lite::ClientConnection<HISTORY, PACKET>,
    request: [u8; REQUEST_MAX + 64],
    request_len: usize,
    complete: bool,
    received: u64,
    counters: ConnectionCounters,
}

impl<const HISTORY: usize, const PACKET: usize> ObjectClient<HISTORY, PACKET> {
    pub fn new(client_cid: ConnectionId, request: GetRequest<'_>) -> Result<Self, Error> {
        let mut encoded = [0u8; REQUEST_MAX + 64];
        let request_len =
            encode_get_request(&mut encoded, 1, request.name, request.cpu, request.target)
                .ok_or(Error::Invalid)?;
        if request_len > PACKET {
            return Err(Error::BufferTooSmall);
        }
        Ok(Self {
            connection: quic_lite::ClientConnection::new(client_cid),
            request: encoded,
            request_len,
            complete: false,
            received: 0,
            counters: ConnectionCounters::default(),
        })
    }

    pub fn start(&mut self, output: &mut [u8; PACKET]) -> Result<usize, Error> {
        self.connection.start(output)
    }

    pub fn accepts(&self, input: &[u8]) -> bool {
        self.connection.accepts(input)
    }

    /// Object transfer is an ordinary client-side QUIC stream. The caller
    /// uses this before its normal CID filter so a peer restart aborts the
    /// transfer explicitly instead of appearing as an unrelated bearer frame.
    pub fn is_peer_stateless_reset(&self, input: &[u8]) -> bool {
        self.connection.is_peer_stateless_reset(input)
    }

    /// Receive one complete bearer packet. `on_fragment` is invoked in stream
    /// order before QUIC receive credit is returned.
    pub fn receive<F>(
        &mut self,
        input: &[u8],
        output: &mut [u8; PACKET],
        on_fragment: F,
    ) -> Result<Option<usize>, Error>
    where
        F: FnMut(&[u8]) -> Result<(), Error>,
    {
        self.receive_at(input, 0, output, on_fragment)
    }

    /// Feed an object datagram with the bearer's monotonic millisecond clock.
    /// QUIC-lite retains packet timestamps in milliseconds, so an ESP adapter
    /// must convert its microsecond timer before loss/PTO comparisons.
    pub fn receive_at<F>(
        &mut self,
        input: &[u8],
        now_ms: u64,
        output: &mut [u8; PACKET],
        mut on_fragment: F,
    ) -> Result<Option<usize>, Error>
    where
        F: FnMut(&[u8]) -> Result<(), Error>,
    {
        match self.connection.receive_bootstrap(
            input,
            now_ms,
            &self.request[..self.request_len],
            output,
        )? {
            quic_lite::ClientBootstrapIngress::RequestEncoded(used) => {
                self.counters.bootstrap_acks = self.counters.bootstrap_acks.saturating_add(1);
                return Ok(Some(used));
            }
            quic_lite::ClientBootstrapIngress::DuplicateAck => {
                self.counters.bootstrap_acks = self.counters.bootstrap_acks.saturating_add(1);
                return Ok(None);
            }
            quic_lite::ClientBootstrapIngress::EstablishedPacket => {}
        }
        let endpoint = self.connection.endpoint_mut()?;
        endpoint.set_time(now_ms);
        let TransportPacket::Stream { frame, .. } = endpoint.receive_datagram(input)? else {
            self.counters.other_packets = self.counters.other_packets.saturating_add(1);
            return endpoint.poll_transmit(output);
        };
        if frame.id == quic_lite::FIRST_SERVER_BIDI_STREAM_ID
            && frame.offset.saturating_add(frame.data.len() as u64) <= self.received
        {
            // The endpoint has recorded the duplicate for ACK already. Do
            // not feed a retransmitted object record to the flash receiver.
            self.counters.other_packets = self.counters.other_packets.saturating_add(1);
            return endpoint.poll_transmit(output);
        }
        if frame.id != quic_lite::FIRST_SERVER_BIDI_STREAM_ID || frame.offset != self.received {
            return Err(Error::Invalid);
        }
        on_fragment(frame.data)?;
        self.received = self.received.saturating_add(frame.data.len() as u64);
        self.counters.stream_packets = self.counters.stream_packets.saturating_add(1);
        endpoint.stream_consumed(frame.id, frame.data.len())?;
        self.complete = frame.fin;
        endpoint.poll_transmit(output)
    }

    pub fn poll_transmit(&mut self, output: &mut [u8; PACKET]) -> Result<Option<usize>, Error> {
        self.connection.poll_transmit(output)
    }

    pub fn poll_retransmit(
        &mut self,
        now_ms: u64,
        pto_ms: u64,
        output: &mut [u8; PACKET],
    ) -> Result<Option<usize>, Error> {
        self.connection.poll_retransmit(now_ms, pto_ms, output)
    }

    /// Ask the QUIC-lite object association for its next datagram.  PTO,
    /// loss repair, delayed ACKs, and flow-control output remain internal to
    /// the transport; application sinks only supply ordered object fragments.
    pub fn poll(&mut self, now_ms: u64, output: &mut [u8; PACKET]) -> Result<Option<usize>, Error> {
        self.poll_retransmit(now_ms, 600, output)?
            .map_or_else(|| self.poll_transmit(output), |used| Ok(Some(used)))
    }

    pub const fn is_complete(&self) -> bool {
        self.complete
    }
    pub const fn bytes(&self) -> u64 {
        self.received
    }
    pub const fn server_cid(&self) -> Option<ConnectionId> {
        self.connection.peer_cid()
    }
    pub const fn counters(&self) -> ConnectionCounters {
        self.counters
    }
}

impl<const HISTORY: usize, const PACKET: usize> TaggedClient<HISTORY, PACKET> {
    /// Replace the tagged-response collector with the ordinary probe stream
    /// collector without exposing the underlying QUIC association to a
    /// bearer adapter. The returned client keeps the same CIDs, packet
    /// numbers, response-stream sequence, and client stream sequence.
    pub fn into_probe(
        mut self,
        request: crate::probe::ProbeServiceRequest,
        output: &mut [u8; PACKET],
    ) -> Result<(ProbeClient<HISTORY, PACKET>, usize), Error> {
        let stream_id = self.allocate_client_bidi_stream()?;
        ProbeClient::from_tagged_association(
            self.connection,
            request,
            stream_id,
            self.next_server_bidi_stream_id,
            self.next_client_bidi_stream_id,
            output,
        )
    }

    /// Restore the complete association stream namespace after another
    /// normal stream collector (such as probe) completed. This stays within
    /// dmesh-server so a bearer never extracts or reconstructs QUIC state.
    fn from_established_with_stream_state(
        connection: quic_lite::ClientConnection<HISTORY, PACKET>,
        next_server_bidi_stream_id: u64,
        next_client_bidi_stream_id: u64,
    ) -> Self {
        Self {
            connection,
            request: [0; PACKET],
            request_len: 0,
            complete: true,
            close_when_complete: false,
            response: [0; PACKET],
            response_len: 0,
            response_stream_id: None,
            expected_response_stream_id: None,
            next_server_bidi_stream_id,
            next_client_bidi_stream_id,
            counters: ConnectionCounters::default(),
        }
    }

    /// `record` is a complete tagged-CBOR envelope.  It is deliberately not
    /// prefixed by a legacy service selector: the server dispatches component
    /// and method from the envelope itself on every bearer.
    pub fn new(client_cid: ConnectionId, record: &[u8]) -> Result<Self, Error> {
        if record.is_empty() || record.len() > PACKET {
            return Err(Error::BufferTooSmall);
        }
        let mut request = [0u8; PACKET];
        request[..record.len()].copy_from_slice(record);
        Ok(Self {
            connection: quic_lite::ClientConnection::new(client_cid),
            request,
            request_len: record.len(),
            complete: false,
            close_when_complete: true,
            response: [0; PACKET],
            response_len: 0,
            response_stream_id: None,
            expected_response_stream_id: Some(quic_lite::FIRST_SERVER_BIDI_STREAM_ID),
            next_server_bidi_stream_id: quic_lite::FIRST_SERVER_BIDI_STREAM_ID,
            next_client_bidi_stream_id: quic_lite::FIRST_CLIENT_BIDI_STREAM_ID + 4,
            counters: ConnectionCounters::default(),
        })
    }

    /// Keep the established QUIC association after a terminal response.  A
    /// one-shot diagnostic client retains the historical close-on-complete
    /// default; a device association manager opts out and sends later calls
    /// on fresh stream IDs.
    pub fn set_close_when_complete(&mut self, close_when_complete: bool) {
        self.close_when_complete = close_when_complete;
    }

    pub fn start(&mut self, output: &mut [u8; PACKET]) -> Result<usize, Error> {
        self.connection.start(output)
    }

    pub fn accepts(&self, input: &[u8]) -> bool {
        self.connection.accepts(input)
    }

    /// The association owns the token obtained in OPEN_ACK. Keep this public
    /// only for the generic complete-frame driver; radio/UART adapters remain
    /// unaware of reset packet structure.
    pub fn is_peer_stateless_reset(&self, input: &[u8]) -> bool {
        self.connection.is_peer_stateless_reset(input)
    }

    pub fn receive_at(
        &mut self,
        input: &[u8],
        now_ms: u64,
        output: &mut [u8; PACKET],
    ) -> Result<Option<usize>, Error> {
        match self.connection.receive_bootstrap(
            input,
            now_ms,
            &self.request[..self.request_len],
            output,
        )? {
            quic_lite::ClientBootstrapIngress::RequestEncoded(used) => {
                self.counters.bootstrap_acks = self.counters.bootstrap_acks.saturating_add(1);
                return Ok(Some(used));
            }
            quic_lite::ClientBootstrapIngress::DuplicateAck => {
                self.counters.bootstrap_acks = self.counters.bootstrap_acks.saturating_add(1);
                return Ok(None);
            }
            quic_lite::ClientBootstrapIngress::EstablishedPacket => {}
        }
        if self.complete {
            self.counters.other_packets = self.counters.other_packets.saturating_add(1);
            return if self.close_when_complete {
                self.connection.poll_close(output)
            } else {
                self.connection.poll_transmit(output)
            };
        }
        let endpoint = self.connection.endpoint_mut()?;
        endpoint.set_time(now_ms);
        let packet = endpoint.receive_datagram_batch(input)?;
        if !packet.has_streams() {
            self.counters.other_packets = self.counters.other_packets.saturating_add(1);
            return endpoint.poll_transmit(output);
        }
        let expected_stream = self.expected_response_stream_id.ok_or(Error::Invalid)?;
        for frame in packet.streams() {
            if frame.id != expected_stream {
                // This association can receive delayed responses for a
                // previous locally initiated stream, or a peer-initiated
                // stream. Endpoint packet/ACK state is still updated above,
                // but the bounded caller-owned collector must not attach the
                // unrelated payload to the request currently in flight.
                self.counters.other_packets = self.counters.other_packets.saturating_add(1);
                continue;
            }
            if self
                .response_stream_id
                .is_some_and(|stream_id| stream_id == frame.id)
                && frame.offset.saturating_add(frame.data.len() as u64) <= self.response_len as u64
            {
                self.counters.other_packets = self.counters.other_packets.saturating_add(1);
                continue;
            }
            self.counters.stream_packets = self.counters.stream_packets.saturating_add(1);
            if frame.offset != self.response_len as u64
                || self.response_len.saturating_add(frame.data.len()) > self.response.len()
            {
                return Err(Error::Invalid);
            }
            match self.response_stream_id {
                Some(stream_id) if stream_id != frame.id => return Err(Error::Invalid),
                Some(_) => {}
                None if frame.offset == 0 => self.response_stream_id = Some(frame.id),
                None => return Err(Error::Invalid),
            }
            self.response[self.response_len..self.response_len + frame.data.len()]
                .copy_from_slice(frame.data);
            self.response_len += frame.data.len();
            endpoint.stream_consumed(frame.id, frame.data.len())?;
            if frame.fin {
                endpoint.request_stream_reack();
                self.complete = true;
                self.next_server_bidi_stream_id =
                    expected_stream.checked_add(4).ok_or(Error::Invalid)?;
            }
        }
        if self.complete {
            if self.close_when_complete {
                endpoint.close(0);
                return endpoint.poll_close(output);
            }
            return endpoint.poll_transmit(output);
        }
        endpoint.poll_transmit(output)
    }

    /// Encode a later request on an established retained association. The
    /// caller owns stream-ID allocation; this client only resets its bounded
    /// correlated response collector and lets QUIC-lite encode the stream.
    pub fn begin_request(
        &mut self,
        stream_id: u64,
        record: &[u8],
        output: &mut [u8; PACKET],
    ) -> Result<usize, Error> {
        if record.is_empty() || record.len() > self.request.len() {
            return Err(Error::BufferTooSmall);
        }
        let peer = self.connection.peer_cid().ok_or(Error::Invalid)?;
        self.request[..record.len()].copy_from_slice(record);
        self.request_len = record.len();
        self.response_len = 0;
        self.response_stream_id = None;
        self.expected_response_stream_id = Some(self.next_server_bidi_stream_id);
        self.complete = false;
        let endpoint = self.connection.endpoint_mut()?;
        endpoint.open_send_stream(stream_id, quic_lite::INITIAL_MAX_STREAM_DATA)?;
        let (used, _) = endpoint.encode_stream_packet(
            peer,
            stream_id,
            0,
            true,
            &self.request[..self.request_len],
            output,
        )?;
        Ok(used)
    }

    /// Allocate the next client-created stream from this retained
    /// association. Bearer maps must not maintain a duplicate counter.
    pub fn allocate_client_bidi_stream(&mut self) -> Result<u64, Error> {
        let stream = self.next_client_bidi_stream_id;
        self.next_client_bidi_stream_id = self
            .next_client_bidi_stream_id
            .checked_add(4)
            .ok_or(Error::StreamLimit)?;
        Ok(stream)
    }

    pub fn receive(
        &mut self,
        input: &[u8],
        output: &mut [u8; PACKET],
    ) -> Result<Option<usize>, Error> {
        self.receive_at(input, 0, output)
    }

    pub const fn is_complete(&self) -> bool {
        self.complete
    }
    pub const fn bytes(&self) -> u64 {
        self.response_len as u64
    }
    pub const fn server_cid(&self) -> Option<ConnectionId> {
        self.connection.peer_cid()
    }
    pub const fn counters(&self) -> ConnectionCounters {
        self.counters
    }
    pub fn response(&self) -> Option<&[u8]> {
        self.complete.then_some(&self.response[..self.response_len])
    }
    pub fn poll_transmit(&mut self, output: &mut [u8; PACKET]) -> Result<Option<usize>, Error> {
        self.connection.poll_transmit(output)
    }
    pub fn poll_close(&mut self, output: &mut [u8; PACKET]) -> Result<Option<usize>, Error> {
        self.connection.poll_close(output)
    }
    pub fn poll_retransmit(
        &mut self,
        now_us: u64,
        pto_us: u64,
        output: &mut [u8; PACKET],
    ) -> Result<Option<usize>, Error> {
        self.connection.poll_retransmit(now_us, pto_us, output)
    }
}

impl<const HISTORY: usize, const PACKET: usize> ProbeClient<HISTORY, PACKET> {
    /// Request a lower peer receive profile for this new association.  The
    /// peer's OPEN_ACK remains authoritative after applying its hard cap.
    pub fn set_requested_peer_receive_profile(
        &mut self,
        request: quic_lite::ReceiveWindowRequest,
    ) -> Result<(), Error> {
        self.connection
            .set_requested_peer_receive_profile(request)
            .map_err(Error::from)
    }

    /// Attach a multi-stream probe collector to an already-established tagged
    /// association. This is intentionally private to the shared client
    /// implementation: bearer adapters use [`TaggedClient::into_probe`] and
    /// never transfer CIDs or stream sequences themselves.
    fn from_tagged_association(
        connection: quic_lite::ClientConnection<HISTORY, PACKET>,
        request: crate::probe::ProbeServiceRequest,
        stream_id: u64,
        first_response_stream_id: u64,
        next_client_bidi_stream_id: u64,
        output: &mut [u8; PACKET],
    ) -> Result<(Self, usize), Error> {
        // The public probe request is bearer-neutral.  Its requested packet
        // size is normalized by `ProbeServicePlan` below to this association's
        // path MTU, so do not make clients learn a UART/UDP packet bound just
        // to issue the same stream handler.
        if request.packet_size < 4 {
            return Err(Error::Invalid);
        }
        let mut request_wire = [0u8; crate::probe::PROBE_RUN_REQUEST_MAX];
        let request_len = crate::probe::encode_probe_run_request(request, 1, &mut request_wire)
            .ok_or(Error::Invalid)?;
        let plan = crate::probe::ProbeServicePlan::from_request(request, PACKET.saturating_sub(32));
        let mut client = Self {
            connection,
            request: request_wire,
            request_len,
            run: ProbeRun::new(
                2,
                plan.normal_streams,
                plan.high_priority_bytes != 0,
                plan.low_priority_bytes != 0,
            ),
            complete: false,
            close_when_complete: false,
            bootstrap_acks: 0,
            stream_packets: 0,
            other_packets: 0,
            first_response_stream_id,
            next_server_bidi_stream_id: first_response_stream_id,
            next_client_bidi_stream_id,
            deferred_consumption: [DeferredConsumption::default();
                crate::probe::PROBE_MAX_NORMAL_STREAMS + 2],
            initial_consume_delay_ms: request.initial_consume_delay_ms.unwrap_or(0),
            consume_delay_ms: request.consume_delay_ms.unwrap_or(0),
            first_chunk_seen: false,
            consume_barrier_until_ms: None,
        };
        let peer = client.connection.peer_cid().ok_or(Error::Invalid)?;
        let endpoint = client.connection.endpoint_mut()?;
        endpoint.open_send_stream(stream_id, quic_lite::INITIAL_MAX_STREAM_DATA)?;
        let (used, _) = endpoint.encode_stream_packet(
            peer,
            stream_id,
            0,
            true,
            &client.request[..client.request_len],
            output,
        )?;
        Ok((client, used))
    }

    /// Restore the tagged collector after a completed ordinary probe stream.
    /// This is the inverse of [`TaggedClient::into_probe`]; both operations
    /// retain the same QUIC association inside dmesh-server.
    pub fn into_tagged_client(self) -> TaggedClient<HISTORY, PACKET> {
        TaggedClient::from_established_with_stream_state(
            self.connection,
            self.next_server_bidi_stream_id,
            self.next_client_bidi_stream_id,
        )
    }

    /// Keep the association after a completed probe so later ordinary streams
    /// share the same negotiated QUIC state. A one-shot diagnostic still
    /// defaults to closing on completion; the device-keyed MeshClient opts
    /// out before driving the first packet, exactly as it does for tagged
    /// handlers.
    pub fn set_close_when_complete(&mut self, close_when_complete: bool) {
        self.close_when_complete = close_when_complete;
    }

    pub fn new(client_cid: ConnectionId, bytes: u64) -> Result<Self, Error> {
        Self::new_with_packet_size(client_cid, bytes, PACKET as u16)
    }

    /// Construct a probe whose receiving side advertises an explicit,
    /// application-selected byte window.  This is deliberately a generic
    /// QUIC connection limit, rather than a probe-specific packet credit, so
    /// host tests can model slow flash/file consumers exactly.
    pub fn new_with_receive_window(
        client_cid: ConnectionId,
        bytes: u64,
        receive_window_bytes: u64,
    ) -> Result<Self, Error> {
        Self::from_request_with_limits(
            client_cid,
            crate::probe::ProbeServiceRequest::new(bytes, PACKET as u16),
            ConnectionLimits::with_receive_window(receive_window_bytes),
        )
    }

    /// Construct a complete-datagram client with a caller-selected payload
    /// size.  Radio adapters use this to compare a small robust action frame
    /// against the normal MTU-sized UDP path; the service request remains the
    /// same host-tested PROBE schema.
    pub fn new_with_packet_size(
        client_cid: ConnectionId,
        bytes: u64,
        packet_size: u16,
    ) -> Result<Self, Error> {
        Self::from_request(
            client_cid,
            crate::probe::ProbeServiceRequest::new(bytes, packet_size),
        )
    }

    /// Construct the same client from the complete public probe request.
    /// CLI, HTTP, and bearer adapters must not reinterpret its stream, pacing,
    /// or priority fields before the shared connection client receives them.
    pub fn from_request(
        client_cid: ConnectionId,
        request: crate::probe::ProbeServiceRequest,
    ) -> Result<Self, Error> {
        Self::from_request_with_limits(client_cid, request, ConnectionLimits::default())
    }

    /// As [`Self::from_request`], with the receiver's ordinary QUIC byte
    /// limits supplied by the caller.  The probe request remains handler
    /// policy; bootstrap flow control remains a QUIC-lite setting.
    pub fn from_request_with_limits(
        client_cid: ConnectionId,
        request: crate::probe::ProbeServiceRequest,
        local_limits: ConnectionLimits,
    ) -> Result<Self, Error> {
        // See `from_tagged_association`: the common plan clamps this request
        // to the active path's payload budget.
        if request.packet_size < 4 {
            return Err(Error::Invalid);
        }
        let mut request_wire = [0u8; crate::probe::PROBE_RUN_REQUEST_MAX];
        let request_len = crate::probe::encode_probe_run_request(request, 1, &mut request_wire)
            .ok_or(Error::Invalid)?;
        let plan = crate::probe::ProbeServicePlan::from_request(request, PACKET.saturating_sub(32));
        Ok(Self {
            connection: quic_lite::ClientConnection::with_limits(client_cid, local_limits),
            request: request_wire,
            request_len,
            run: ProbeRun::new(
                2,
                plan.normal_streams,
                plan.high_priority_bytes != 0,
                plan.low_priority_bytes != 0,
            ),
            complete: false,
            close_when_complete: true,
            bootstrap_acks: 0,
            stream_packets: 0,
            other_packets: 0,
            first_response_stream_id: quic_lite::FIRST_SERVER_BIDI_STREAM_ID,
            next_server_bidi_stream_id: quic_lite::FIRST_SERVER_BIDI_STREAM_ID,
            next_client_bidi_stream_id: quic_lite::FIRST_CLIENT_BIDI_STREAM_ID + 4,
            deferred_consumption: [DeferredConsumption::default();
                crate::probe::PROBE_MAX_NORMAL_STREAMS + 2],
            initial_consume_delay_ms: request.initial_consume_delay_ms.unwrap_or(0),
            consume_delay_ms: request.consume_delay_ms.unwrap_or(0),
            first_chunk_seen: false,
            consume_barrier_until_ms: None,
        })
    }

    /// Construct the client directly in caller-provided static storage.
    ///
    /// ESP radio command tasks have deliberately small stacks. The QUIC
    /// ledger itself is the same heap-backed `Vec` used by host, but the probe
    /// receiver's bounded multi-stream callback state is still large enough
    /// that returning the complete client by value can transiently exceed an
    /// embedded task stack. This changes only construction placement: every
    /// subsequently executed driver, stream, and ledger method is identical
    /// to [`Self::new`]. Host tests cover both constructors' wire state.
    pub fn new_in_place(
        storage: &mut MaybeUninit<Self>,
        client_cid: ConnectionId,
        bytes: u64,
        packet_size: u16,
    ) -> Result<&mut Self, Error> {
        if packet_size < 4 {
            return Err(Error::Invalid);
        }
        let mut request = [0u8; crate::probe::PROBE_RUN_REQUEST_MAX];
        let request_spec = crate::probe::ProbeServiceRequest::new(bytes, packet_size);
        let request_len = crate::probe::encode_probe_run_request(request_spec, 1, &mut request)
            .ok_or(Error::Invalid)?;
        let plan =
            crate::probe::ProbeServicePlan::from_request(request_spec, PACKET.saturating_sub(32));
        // Field-by-field writes deliberately avoid a whole `Self` temporary.
        // See the method-level rationale above; this is called once per
        // explicit device-originated run, never from packet ingress.
        let client = storage.as_mut_ptr();
        unsafe {
            core::ptr::addr_of_mut!((*client).connection)
                .write(quic_lite::ClientConnection::new(client_cid));
            core::ptr::addr_of_mut!((*client).request).write(request);
            core::ptr::addr_of_mut!((*client).request_len).write(request_len);
            core::ptr::addr_of_mut!((*client).run).write(ProbeRun::new(
                2,
                plan.normal_streams,
                plan.high_priority_bytes != 0,
                plan.low_priority_bytes != 0,
            ));
            core::ptr::addr_of_mut!((*client).complete).write(false);
            core::ptr::addr_of_mut!((*client).close_when_complete).write(true);
            core::ptr::addr_of_mut!((*client).bootstrap_acks).write(0);
            core::ptr::addr_of_mut!((*client).stream_packets).write(0);
            core::ptr::addr_of_mut!((*client).other_packets).write(0);
            core::ptr::addr_of_mut!((*client).first_response_stream_id)
                .write(quic_lite::FIRST_SERVER_BIDI_STREAM_ID);
            core::ptr::addr_of_mut!((*client).next_server_bidi_stream_id)
                .write(quic_lite::FIRST_SERVER_BIDI_STREAM_ID);
            core::ptr::addr_of_mut!((*client).next_client_bidi_stream_id)
                .write(quic_lite::FIRST_CLIENT_BIDI_STREAM_ID + 4);
            core::ptr::addr_of_mut!((*client).deferred_consumption).write(
                [DeferredConsumption::default(); crate::probe::PROBE_MAX_NORMAL_STREAMS + 2],
            );
            core::ptr::addr_of_mut!((*client).initial_consume_delay_ms).write(0);
            core::ptr::addr_of_mut!((*client).consume_delay_ms).write(0);
            core::ptr::addr_of_mut!((*client).first_chunk_seen).write(false);
            core::ptr::addr_of_mut!((*client).consume_barrier_until_ms).write(None);
            Ok(&mut *client)
        }
    }

    fn release_due_consumption(&mut self, now_ms: u64) -> Result<(), Error> {
        for pending in &mut self.deferred_consumption {
            if !pending.active || pending.release_at_ms > now_ms {
                continue;
            }
            self.connection
                .endpoint_mut()?
                .stream_consumed(pending.stream, pending.bytes)?;
            *pending = DeferredConsumption::default();
        }
        Ok(())
    }

    fn defer_consumption(
        &mut self,
        stream: u64,
        bytes: usize,
        release_at_ms: u64,
    ) -> Result<(), Error> {
        let index = self
            .deferred_consumption
            .iter()
            .position(|pending| pending.active && pending.stream == stream)
            .or_else(|| {
                self.deferred_consumption
                    .iter()
                    .position(|pending| !pending.active)
            })
            .ok_or(Error::StreamLimit)?;
        let pending = &mut self.deferred_consumption[index];
        if pending.active {
            pending.bytes = pending.bytes.saturating_add(bytes);
            pending.release_at_ms = pending.release_at_ms.max(release_at_ms);
        } else {
            *pending = DeferredConsumption {
                stream,
                bytes,
                release_at_ms,
                active: true,
            };
        }
        Ok(())
    }

    /// Start bootstrap. Call once, then transmit the returned packet.
    pub fn start(&mut self, output: &mut [u8; PACKET]) -> Result<usize, Error> {
        self.connection.start(output)
    }

    /// This keeps client/server coexistence on one peer/bearer a
    /// connection-level decision, not a radio one.
    pub fn accepts(&self, input: &[u8]) -> bool {
        self.connection.accepts(input)
    }

    /// See [`TaggedClient::is_peer_stateless_reset`]. Probe is a normal stream
    /// client and uses the identical association recovery path.
    pub fn is_peer_stateless_reset(&self, input: &[u8]) -> bool {
        self.connection.is_peer_stateless_reset(input)
    }

    /// Consume one peer packet and optionally produce exactly one outbound
    /// packet. `Ok(None)` means the client made progress but has no immediate
    /// packet to send; the caller must still continue receiving.
    pub fn receive(
        &mut self,
        input: &[u8],
        output: &mut [u8; PACKET],
    ) -> Result<Option<usize>, Error> {
        self.receive_at(input, 0, output)
    }

    /// Feed a datagram with the bearer's monotonic millisecond clock.  Raw
    /// action adapters use this so the ordinary QUIC delayed-ACK timer does
    /// not accidentally become the firmware's coarse housekeeping interval.
    /// The clock is supplied by the adapter; this type remains timer-free.
    pub fn receive_at(
        &mut self,
        input: &[u8],
        now_ms: u64,
        output: &mut [u8; PACKET],
    ) -> Result<Option<usize>, Error> {
        if !self.connection.is_started() || self.complete {
            return Err(Error::Invalid);
        }
        self.release_due_consumption(now_ms)?;
        match self.connection.receive_bootstrap(
            input,
            now_ms,
            &self.request[..self.request_len],
            output,
        )? {
            quic_lite::ClientBootstrapIngress::RequestEncoded(used) => {
                self.bootstrap_acks = self.bootstrap_acks.saturating_add(1);
                return Ok(Some(used));
            }
            quic_lite::ClientBootstrapIngress::DuplicateAck => {
                self.bootstrap_acks = self.bootstrap_acks.saturating_add(1);
                return Ok(None);
            }
            quic_lite::ClientBootstrapIngress::EstablishedPacket => {}
        }
        if self.complete {
            // A final PROBE stream packet can be repeated before the server
            // receives CLOSE. Re-send the terminal record while keeping the
            // application complete and the one-association ledger bounded.
            self.other_packets = self.other_packets.saturating_add(1);
            return self.connection.poll_close(output);
        }
        let packet = {
            let endpoint = self.connection.endpoint_mut()?;
            endpoint.set_time(now_ms);
            endpoint.receive_datagram(input)?
        };
        if let TransportPacket::Stream { frame, .. } = packet {
            self.stream_packets = self.stream_packets.saturating_add(1);
            let (complete, consumed) = self
                .run
                .handle(self.first_response_stream_id, frame)
                .map_err(|_| Error::Invalid)?;
            self.next_server_bidi_stream_id = self
                .next_server_bidi_stream_id
                .max(frame.id.checked_add(4).ok_or(Error::Invalid)?);
            if !self.first_chunk_seen {
                self.first_chunk_seen = true;
                self.consume_barrier_until_ms =
                    Some(now_ms.saturating_add(u64::from(self.initial_consume_delay_ms)));
            }
            let release_at = now_ms
                .saturating_add(u64::from(self.consume_delay_ms))
                .max(self.consume_barrier_until_ms.unwrap_or(0));
            if release_at <= now_ms {
                self.connection
                    .endpoint_mut()?
                    .stream_consumed(frame.id, consumed)?;
            } else {
                self.defer_consumption(frame.id, consumed, release_at)?;
            }
            self.complete = complete;
            if complete {
                // Raw-action servers deliberately own one bounded association
                // at a time. A one-shot PROBE client must therefore retire
                // its CID on FIN; otherwise the next explicit check or
                // transfer is a fresh OPEN competing with a stale ledger.
                // The adapter sends this returned CLOSE on the same bearer
                // and then drops the completed client state.
                if self.close_when_complete {
                    let endpoint = self.connection.endpoint_mut()?;
                    endpoint.close(0);
                    return endpoint.poll_close(output);
                }
                return self.connection.endpoint_mut()?.poll_transmit(output);
            }
        } else {
            self.other_packets = self.other_packets.saturating_add(1);
        }
        self.connection.endpoint_mut()?.poll_transmit(output)
    }

    /// Poll an ACK/window/control datagram after a bearer clock advance.
    /// This is separate from loss/PTO retransmission: a packet-at-a-time
    /// action bearer must send its scheduled ACK promptly to release the
    /// peer's one-packet window.
    pub fn poll_transmit_at(
        &mut self,
        now_ms: u64,
        output: &mut [u8; PACKET],
    ) -> Result<Option<usize>, Error> {
        self.release_due_consumption(now_ms)?;
        self.connection.poll_transmit_at(now_ms, output)
    }

    /// Return the next ACK/PTO deadline owned by this PROBE association.
    /// It is a scalar scheduling hint only; packet production remains in the
    /// shared ingress owner after that deadline fires.
    pub fn next_service_deadline_ms(&self, pto_ms: u64) -> Option<u64> {
        let transport = self
            .connection
            .endpoint()
            .and_then(|endpoint| endpoint.next_bearer_deadline(pto_ms));
        let consumption = self
            .deferred_consumption
            .iter()
            .filter(|pending| pending.active)
            .map(|pending| pending.release_at_ms)
            .min();
        match (transport, consumption) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (Some(deadline), None) | (None, Some(deadline)) => Some(deadline),
            (None, None) => None,
        }
    }

    /// Re-emit the terminal CLOSE after a completed one-shot PROBE run.
    ///
    /// A raw action adapter calls this from its bounded close-drain deadline,
    /// not from a polling loop.  Repeating only CLOSE gives the remote
    /// one-association server a reliable retirement signal without restarting
    /// the transfer or preserving stream payloads.
    pub fn poll_close(&mut self, output: &mut [u8; PACKET]) -> Result<Option<usize>, Error> {
        self.connection.poll_close(output)
    }

    /// Drive one QUIC-lite PTO/loss retransmission for a sparse bearer. The
    /// caller supplies its monotonic clock and sends the returned datagram;
    /// no socket, radio, or timer is retained here.
    pub fn poll_retransmit(
        &mut self,
        now_us: u64,
        pto_us: u64,
        output: &mut [u8; PACKET],
    ) -> Result<Option<usize>, Error> {
        self.connection.poll_retransmit(now_us, pto_us, output)
    }

    pub fn is_complete(&self) -> bool {
        self.complete
    }
    pub fn bytes(&self) -> u64 {
        self.run.bytes()
    }
    pub fn normal_bytes(&self) -> u64 {
        self.run.normal_bytes()
    }
    pub fn high_bytes(&self) -> u64 {
        self.run.high_bytes()
    }
    pub fn low_bytes(&self) -> u64 {
        self.run.low_bytes()
    }
    pub fn callback_errors(&self) -> [u64; 6] {
        self.run.callback_errors()
    }
    pub fn server_cid(&self) -> Option<ConnectionId> {
        self.connection.peer_cid()
    }
    /// `(bootstrap_acks, stream_packets, other_transport_packets)` for
    /// adapters that need bounded bring-up diagnostics.
    pub const fn packet_classes(&self) -> (u32, u32, u32) {
        (self.bootstrap_acks, self.stream_packets, self.other_packets)
    }

    pub const fn counters(&self) -> ConnectionCounters {
        ConnectionCounters {
            bootstrap_acks: self.bootstrap_acks,
            stream_packets: self.stream_packets,
            other_packets: self.other_packets,
        }
    }
}

impl<const HISTORY: usize, const PACKET: usize> ConnectionServer<HISTORY, PACKET> {
    pub fn new(local_cid: ConnectionId) -> Self {
        Self::new_with_association(
            local_cid,
            ConnectionLimits::default(),
            AssociationProfile::c6_default(),
        )
    }

    /// Whether the admitted QUIC peer explicitly retired this connection
    /// association. A dispatcher uses this to release the association-owned,
    /// admission-sized ledger before accepting the next bootstrap.
    pub fn is_closed(&self) -> bool {
        self.connection
            .as_ref()
            .is_some_and(|connection| connection.is_closed())
    }

    /// Number of streams which still have unfinished send or receive state.
    /// Association-table eviction uses this transport-neutral fact and never
    /// inspects an application handler or bearer.
    pub fn active_stream_count(&self) -> usize {
        self.connection.as_ref().map_or(0, |connection| {
            let stats = connection.stream_stats();
            stats.locally_initiated.active as usize + stats.peer_initiated.active as usize
        })
    }

    /// Construct with a device-derived receive-window limit. This is used by
    /// bounded firmware bearers; `new` remains the host-compatible default.
    pub fn new_with_limits(local_cid: ConnectionId, local_limits: ConnectionLimits) -> Self {
        Self::new_with_association(local_cid, local_limits, AssociationProfile::c6_default())
    }

    pub fn new_with_association(
        local_cid: ConnectionId,
        local_limits: ConnectionLimits,
        association: AssociationProfile,
    ) -> Self {
        Self {
            local_cid,
            local_limits,
            connection: None,
            sender: None,
            probe_request_stream: None,
            pending_stream_command: None,
            command_stream: None,
            terminal_stream_response: None,
            terminal_response_stream: None,
            inbound_stream: None,
            inbound_stream_consumer: None,
            inbound_stream_chunks: Vec::new(),
            association: association.clamp::<HISTORY>(),
        }
    }

    /// Receive CID installed in the live QUIC endpoint. This diagnostic view
    /// distinguishes a bad relay rewrite from receiver-side state drift.
    pub fn expected_receive_cid(&self) -> Option<ConnectionId> {
        self.connection
            .as_ref()
            .and_then(|connection| connection.local_connection_id())
    }

    pub fn peer_cid(&self) -> Option<ConnectionId> {
        self.connection
            .as_ref()
            .and_then(|connection| connection.peer_connection_id())
    }

    /// The profile which was accepted with this association's OPEN.  This is
    /// association state, not a handler or bearer policy: a callback-driven
    /// adapter may use it to acquire its temporary ingress storage while the
    /// association is live.
    pub const fn association_profile(&self) -> AssociationProfile {
        self.association
    }

    /// Compatibility entry point for an application endpoint used without a
    /// multi-path dispatcher. Header semantics still come from quic-lite.
    pub fn receive(
        &mut self,
        packet: &[u8],
        output: &mut [u8; PACKET],
    ) -> Result<Option<usize>, Error> {
        match quic_lite::classify_server_packet(packet)? {
            quic_lite::ServerPacket::Initial(open) => {
                if self.connection.is_some() && self.peer_cid() == Some(open.client_receive_cid) {
                    self.replay_open(packet, output)
                } else if self.connection.is_some() {
                    Err(Error::BootstrapInvalid)
                } else {
                    let replacement = Self::accept(
                        packet,
                        self.local_cid,
                        self.local_limits,
                        self.association,
                        None,
                        output,
                    )?;
                    *self = replacement.0;
                    Ok(replacement.1)
                }
            }
            quic_lite::ServerPacket::Established => self.receive_established(packet, output),
        }
    }

    fn accept(
        packet: &[u8],
        local_cid: ConnectionId,
        local_limits: ConnectionLimits,
        association: AssociationProfile,
        stateless_reset_token: Option<quic_lite::StatelessResetToken>,
        output: &mut [u8; PACKET],
    ) -> Result<(Self, Option<usize>), Error> {
        // Ordered stream callbacks retain only datagrams which arrived ahead
        // of a gap.  Size that shared reordering allowance from this
        // association's already-bounded packet ledger, rather than the old
        // 4 KiB generic RPC default: a normal bounded Wi-Fi flight can
        // otherwise be rejected before it reaches the application sink.
        let stream_config = ServerStreamConfig {
            history_packets: association.history_packets,
            max_pending_streams: quic_lite::DEFAULT_STREAM_STATE_SLOTS,
            // The callback retains only out-of-order datagrams, but a gap can
            // span the receiver's admitted byte window even when its local
            // outbound retransmission ledger is smaller. Bound retention by
            // that configured window (Recovery: flash slots; host: selected
            // memory policy), never by a bearer-private queue.
            max_stream_bytes: usize::try_from(local_limits.max_data)
                .unwrap_or(usize::MAX)
                .max(association.history_packets.saturating_mul(PACKET)),
        };
        let (mut connection, _default_ack) =
            StreamServerConnection::accept_open_boxed_with_config_and_reset_token(
                packet,
                local_cid,
                0,
                local_limits,
                stream_config,
                stateless_reset_token,
            )?;
        // The RFC initial window is intentionally conservative for a
        // generic path.  A raw action association has already supplied a
        // Apply the one shared association policy before the first service
        // response. The local retransmission ledger is bounded, while peer
        // receive backpressure remains ordinary QUIC-lite byte credit rather
        // than a bearer-specific packet counter.
        let initial_window =
            (association.initial_window_packets as u64).saturating_mul(PACKET as u64);
        connection.configure_transport(
            association.history_packets,
            initial_window,
            association.ack_frequency,
            u64::from(association.ack_delay_ms),
        )?;
        // Re-encode the deterministic OPEN_ACK from the configured shared
        // transport state before returning it to the client.
        let ack = connection.replay_open_ack(packet)?;
        if ack.len() > output.len() {
            return Err(Error::Invalid);
        }
        output[..ack.len()].copy_from_slice(&ack);
        Ok((
            Self {
                local_cid,
                local_limits,
                connection: Some(connection),
                sender: None,
                probe_request_stream: None,
                pending_stream_command: None,
                command_stream: None,
                terminal_stream_response: None,
                terminal_response_stream: None,
                inbound_stream: None,
                inbound_stream_consumer: None,
                inbound_stream_chunks: Vec::new(),
                association: association.clamp::<HISTORY>(),
            },
            Some(ack.len()),
        ))
    }

    fn replay_open(
        &mut self,
        packet: &[u8],
        output: &mut [u8; PACKET],
    ) -> Result<Option<usize>, Error> {
        let ack = self
            .connection
            .as_ref()
            .ok_or(Error::WrongConnectionId)?
            .replay_open_ack(packet)?;
        if ack.len() > output.len() {
            return Err(Error::Invalid);
        }
        output[..ack.len()].copy_from_slice(&ack);
        Ok(Some(ack.len()))
    }

    /// Consume established traffic after QUIC-lite has classified its header.
    fn receive_established(
        &mut self,
        packet: &[u8],
        output: &mut [u8; PACKET],
    ) -> Result<Option<usize>, Error> {
        let connection = self.connection.as_mut().ok_or(Error::WrongConnectionId)?;
        let inbound_stream = self.inbound_stream;
        let inbound_consumer = self.inbound_stream_consumer;
        let mut inbound_chunks = Vec::new();
        let request = match inbound_stream {
            Some(stream) => {
                if let Some(consumer) = inbound_consumer {
                    connection.mux.receive_request_with_consuming_stream(
                        packet,
                        stream,
                        |id, fin, bytes| {
                            if id == stream {
                                return consumer(bytes, fin);
                            }
                            (Some(id) == self.command_stream)
                                .then_some(bytes.len())
                                .ok_or(())
                        },
                    )?
                } else {
                    connection.mux.receive_request_with_deferred_stream(
                        packet,
                        stream,
                        |id, fin, bytes| {
                            if id == stream {
                                inbound_chunks.push((bytes.to_vec(), fin));
                                return Ok(bytes.len());
                            }
                            (Some(id) == self.command_stream)
                                .then_some(bytes.len())
                                .ok_or(())
                        },
                    )?
                }
            }
            None => connection.receive_request(packet)?,
        };
        if inbound_consumer.is_none() {
            self.inbound_stream_chunks.extend(inbound_chunks);
        }
        if request.is_none()
            && (inbound_consumer.is_some() || !self.inbound_stream_chunks.is_empty())
        {
            return self.poll(output);
        }
        if let Some(request) = request {
            let tagged_probe = crate::tagged::decode(&request.data)
                .and_then(crate::probe::decode_probe_run_record)
                .map(|(_, request)| request);
            // A tagged-CBOR request is the modern, bearer-neutral handler
            // envelope. It has no leading service selector: its component
            // and method identify the handler, while this QUIC stream only
            // provides ordered request/response transport.
            if tagged_probe.is_none() {
                let diagnostic = crate::services::dispatch_diagnostic_tagged_stream(
                    &connection.mux.endpoint,
                    None,
                    self.local_cid,
                    request.stream_id,
                    &request.data,
                );
                if let Some(response) =
                    diagnostic.or_else(|| crate::services::dispatch_tagged_stream(&request.data))
                {
                    connection.complete_request(request.stream_id, request.data.len())?;
                    let response_stream = connection.response_stream_id();
                    match connection.encode_response(&response, output) {
                        Ok((used, _)) => {
                            self.terminal_response_stream = Some(response_stream);
                            return Ok(Some(used));
                        }
                        Err(Error::FlowControl | Error::HistoryFull) => {
                            // Immediate and deferred handlers share the same
                            // terminal-response queue. QUIC-lite may need an
                            // ACK/control turn before its send ledger admits
                            // this result; never discard handler completion.
                            self.terminal_stream_response = Some(response);
                            return connection.poll_transmit(output);
                        }
                        Err(error) => return Err(error),
                    }
                }
            }
            // A lost response can make the client retransmit the final
            // service request while the producer is already active. QUIC has
            // accepted and ACKed that duplicate at the endpoint; treating it
            // as an application error poisons the raw bearer and prevents the
            // sender from continuing. Keep the existing producer and emit
            // the next ledger-owned response instead.
            if let Some(sender) = self.sender.as_ref()
                && tagged_probe.is_some()
            {
                // Preserve duplicate delivery semantics for the request
                // that created this producer.  Once it has completed, a
                // request on a later client stream is a new regular QUIC
                // service run, not a duplicate of the old one.
                if !sender.is_complete() || self.probe_request_stream == Some(request.stream_id) {
                    return self.poll(output);
                }
                self.sender = None;
                self.probe_request_stream = None;
            }
            if self.sender.is_some() {
                return Err(Error::Invalid);
            }
            if tagged_probe.is_none() {
                // Keep command semantics above this generic transport layer.
                // A client-side bidi stream sequence is assigned by QUIC-lite;
                // this only reserves the following peer stream as opaque
                // ordered application input.
                if self.command_stream == Some(request.stream_id) && self.inbound_stream.is_some() {
                    return self.poll(output);
                }
                if self.pending_stream_command.is_some()
                    || self.command_stream.is_some()
                    || self.terminal_stream_response.is_some()
                {
                    return Err(Error::Invalid);
                }
                self.pending_stream_command = Some(request.data.to_vec());
                self.command_stream = Some(request.stream_id);
                self.inbound_stream = Some(request.stream_id.checked_add(4).ok_or(Error::Invalid)?);
                connection.complete_request(request.stream_id, request.data.len())?;
                return Ok(None);
            }
            let request_spec = tagged_probe.ok_or(Error::Invalid)?;
            let plan = ProbeServicePlan::from_request(request_spec, PACKET.saturating_sub(32));
            // The first raw bearer has one bounded producer. Parallel and
            // priority lanes remain available to the established UDP/action
            // service, and will be added here only when e6 proves the basic
            // zero-copy bearer path.
            if plan.normal_streams != 1
                || plan.high_priority_bytes != 0
                || plan.low_priority_bytes != 0
            {
                return Err(Error::Invalid);
            }
            connection.complete_request(request.stream_id, request.data.len())?;
            connection.request_ack_frequency(
                0,
                u64::from(self.association.ack_frequency.saturating_sub(1)),
                u64::from(self.association.ack_delay_ms) * 1_000,
                1,
            )?;
            self.sender = ProbeSender::new(
                connection.reserve_response_stream(),
                plan.normal_bytes[0],
                plan.packet_size,
            );
            self.probe_request_stream = Some(request.stream_id);
        }
        self.poll(output)
    }

    /// Produce one PROBE packet when transport flow credit permits it.
    pub fn poll(&mut self, output: &mut [u8; PACKET]) -> Result<Option<usize>, Error> {
        let connection = self.connection.as_mut().ok_or(Error::WrongConnectionId)?;
        if let Some(response) = self.terminal_stream_response.as_deref() {
            let response_stream = connection.response_stream_id();
            match connection.encode_response(response, output) {
                Ok((used, _)) => {
                    self.terminal_stream_response = None;
                    self.terminal_response_stream = Some(response_stream);
                    return Ok(Some(used));
                }
                // The response has not entered QUIC-lite's retransmission
                // ledger yet. Keep application completion state intact and
                // let ordinary transport ACK/MAX/PTO output free admission;
                // a later poll retries on the same server stream.
                Err(Error::FlowControl | Error::HistoryFull) => {
                    return connection.poll_transmit(output);
                }
                Err(error) => return Err(error),
            }
        }
        let Some(sender) = self.sender.as_mut() else {
            return connection.poll_transmit(output);
        };
        let packet = sender.poll(output, |stream, offset, fin, payload, out| {
            connection
                .encode_server_stream_fragment(stream, offset, fin, payload, out)
                .map(|(used, _)| used)
        })?;
        // Retain a completed producer until this association observes CLOSE
        // or a fresh OPEN replaces it. A connectionless bearer can lose the
        // final server packet, so the client legitimately retransmits its
        // original PROBE request. Dropping `sender` here made that duplicate
        // start a second producer on the same endpoint, overrun the client's
        // expected stream, and flood the shared ingress pool. A completed
        // sender owns no packet queue or payload; it is just the bounded
        // association marker that makes duplicate requests idempotent.
        Ok(packet.map(|(used, _)| used))
    }

    /// Return the next ACK/PTO deadline for the accepted raw association.
    /// It is only a scheduling value: the common worker still owns packet
    /// production after the timer fires.
    pub fn next_service_deadline(&self, pto: u64) -> Option<u64> {
        self.connection
            .as_ref()
            .and_then(|connection| connection.next_bearer_deadline(pto))
    }

    /// Take one validated tagged command for a handler which consumes the
    /// next peer bidi stream. This server deliberately does not decode it.
    pub fn take_stream_command(&mut self) -> Option<Vec<u8>> {
        self.pending_stream_command.take()
    }

    fn take_inbound_stream_chunks(&mut self) -> Vec<(Vec<u8>, bool)> {
        core::mem::take(&mut self.inbound_stream_chunks)
    }
    fn restore_inbound_stream_chunks(&mut self, chunks: &mut Vec<(Vec<u8>, bool)>) {
        chunks.append(&mut self.inbound_stream_chunks);
        self.inbound_stream_chunks = core::mem::take(chunks);
    }
    fn has_inbound_stream_chunks(&self) -> bool {
        !self.inbound_stream_chunks.is_empty()
    }

    fn consume_inbound_stream_bytes(&mut self, bytes: usize) -> Result<(), Error> {
        let Some(stream) = self.inbound_stream else {
            return Ok(());
        };
        if bytes == 0 {
            return Ok(());
        }
        self.connection
            .as_mut()
            .ok_or(Error::WrongConnectionId)?
            .mux
            .endpoint
            .stream_consumed_deferred(stream, bytes)
    }

    /// Reserve the stream following the accepted command. Its initial credit
    /// was already negotiated in OPEN, independent of the handler.
    fn prepare_inbound_stream(&mut self) -> Result<(), Error> {
        let Some(stream) = self.inbound_stream else {
            return Ok(());
        };
        let endpoint = &mut self
            .connection
            .as_mut()
            .ok_or(Error::WrongConnectionId)?
            .mux
            .endpoint;
        endpoint.prepare_receive_stream(stream)
    }

    fn prepare_inbound_stream_with_consumer(
        &mut self,
        consumer: InboundStreamConsumer,
    ) -> Result<(), Error> {
        self.prepare_inbound_stream()?;
        self.inbound_stream_consumer = Some(consumer);
        Ok(())
    }

    fn resume_inbound_stream_consumer(&mut self) -> Result<usize, Error> {
        let Some(stream) = self.inbound_stream else {
            return Ok(0);
        };
        let consumer = self.inbound_stream_consumer.ok_or(Error::Invalid)?;
        self.connection
            .as_mut()
            .ok_or(Error::WrongConnectionId)?
            .mux
            .resume_consuming_request_stream(stream, |_, fin, bytes| consumer(bytes, fin))
    }

    /// Queue a handler-owned terminal response. This never blocks ingress.
    pub fn complete_stream_command(&mut self, response: Vec<u8>) -> Result<(), Error> {
        if self.pending_stream_command.is_some() || self.terminal_stream_response.is_some() {
            return Err(Error::Invalid);
        }
        if self.command_stream.is_none() {
            return Err(Error::Invalid);
        }
        self.terminal_stream_response = Some(response);
        self.terminal_response_stream = None;
        Ok(())
    }

    /// Consume the lifecycle edge after QUIC-lite has retired the terminal
    /// response from its retransmission ledger. Applications can attach a
    /// post-response action without learning ACK or packet-number details.
    pub fn take_terminal_response_delivered(&mut self) -> bool {
        let Some(stream) = self.terminal_response_stream else {
            return false;
        };
        let delivered = self
            .connection
            .as_mut()
            .is_some_and(|connection| connection.take_acknowledged_fin_stream(stream));
        if delivered {
            self.terminal_response_stream = None;
        }
        delivered
    }

    /// True until `poll` encodes the terminal application response.
    pub const fn terminal_response_pending(&self) -> bool {
        self.terminal_stream_response.is_some()
    }

    /// Forget handler-neutral inbound-stream bookkeeping when CLOSE retires
    /// the peer.
    pub fn abandon_stream_command(&mut self) {
        self.pending_stream_command = None;
        self.command_stream = None;
        self.terminal_stream_response = None;
        self.terminal_response_stream = None;
        self.inbound_stream = None;
        self.inbound_stream_consumer = None;
        self.inbound_stream_chunks.clear();
    }

    /// Let the connection-owned ledger produce a retransmission. The raw
    /// bearer deliberately owns neither packet copies nor an egress queue.
    pub fn poll_retransmit(
        &mut self,
        now_us: u64,
        pto_us: u64,
        output: &mut [u8; PACKET],
    ) -> Result<Option<usize>, Error> {
        let connection = self.connection.as_mut().ok_or(Error::WrongConnectionId)?;
        Ok(connection
            .mux
            .endpoint
            .retransmit_due(now_us, pto_us, output)?
            .map(|(used, _packet_number)| used))
    }
}

impl<const HISTORY: usize, const PACKET: usize> DatagramClient<PACKET>
    for TaggedClient<HISTORY, PACKET>
{
    fn start(&mut self, output: &mut [u8; PACKET]) -> Result<usize, Error> {
        TaggedClient::start(self, output)
    }

    fn receive_at(
        &mut self,
        input: &[u8],
        now_ms: u64,
        output: &mut [u8; PACKET],
    ) -> Result<Option<usize>, Error> {
        TaggedClient::receive_at(self, input, now_ms, output)
    }

    fn accepts(&self, input: &[u8]) -> bool {
        TaggedClient::accepts(self, input)
    }

    fn is_peer_stateless_reset(&self, input: &[u8]) -> bool {
        TaggedClient::is_peer_stateless_reset(self, input)
    }

    fn is_complete(&self) -> bool {
        TaggedClient::is_complete(self)
    }

    fn poll_transmit_at(
        &mut self,
        _now_ms: u64,
        output: &mut [u8; PACKET],
    ) -> Result<Option<usize>, Error> {
        TaggedClient::poll_transmit(self, output)
    }

    fn poll_retransmit(
        &mut self,
        now_us: u64,
        pto_us: u64,
        output: &mut [u8; PACKET],
    ) -> Result<Option<usize>, Error> {
        TaggedClient::poll_retransmit(self, now_us, pto_us, output)
    }
}

impl<const HISTORY: usize, const PACKET: usize> DatagramClient<PACKET>
    for ProbeClient<HISTORY, PACKET>
{
    fn start(&mut self, output: &mut [u8; PACKET]) -> Result<usize, Error> {
        ProbeClient::start(self, output)
    }

    fn receive_at(
        &mut self,
        input: &[u8],
        now_ms: u64,
        output: &mut [u8; PACKET],
    ) -> Result<Option<usize>, Error> {
        ProbeClient::receive_at(self, input, now_ms, output)
    }

    fn accepts(&self, input: &[u8]) -> bool {
        ProbeClient::accepts(self, input)
    }

    fn is_peer_stateless_reset(&self, input: &[u8]) -> bool {
        ProbeClient::is_peer_stateless_reset(self, input)
    }

    fn is_complete(&self) -> bool {
        ProbeClient::is_complete(self)
    }

    fn poll_transmit_at(
        &mut self,
        now_ms: u64,
        output: &mut [u8; PACKET],
    ) -> Result<Option<usize>, Error> {
        ProbeClient::poll_transmit_at(self, now_ms, output)
    }

    fn poll_retransmit(
        &mut self,
        now_us: u64,
        pto_us: u64,
        output: &mut [u8; PACKET],
    ) -> Result<Option<usize>, Error> {
        ProbeClient::poll_retransmit(self, now_us, pto_us, output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn consume_all(bytes: &[u8], _fin: bool) -> Result<usize, ()> {
        Ok(bytes.len())
    }

    #[test]
    fn terminal_completion_gate_accepts_both_platform_event_orders() {
        let mut durable_first = TerminalCompletionGate::default();
        durable_first.application_complete();
        assert!(!durable_first.take_complete());
        durable_first.response_delivered();
        assert!(durable_first.take_complete());
        assert!(!durable_first.take_complete());

        // This is the Recovery device regression: the response can leave in
        // the receive turn before its outer loop observes sink durability.
        let mut response_first = TerminalCompletionGate::default();
        response_first.response_delivered();
        assert!(!response_first.take_complete());
        response_first.application_complete();
        assert!(response_first.take_complete());
    }

    #[test]
    fn firmware_association_memory_budget_is_bounded() {
        type Server = ConnectionServer<8, { quic_lite::DEFAULT_MAX_DATAGRAM_SIZE }>;
        type Ledger = StreamServerConnection<8, { quic_lite::DEFAULT_MAX_DATAGRAM_SIZE }>;
        type Four = ConnectionDispatcher<8, { quic_lite::DEFAULT_MAX_DATAGRAM_SIZE }, 4>;
        type Twenty = ConnectionDispatcher<8, { quic_lite::DEFAULT_MAX_DATAGRAM_SIZE }, 20>;
        eprintln!(
            "association memory: server_inline={} ledger_heap={} dispatcher_4={} dispatcher_20={} incremental_slot={}",
            core::mem::size_of::<Server>(),
            core::mem::size_of::<Ledger>(),
            core::mem::size_of::<Four>(),
            core::mem::size_of::<Twenty>(),
            (core::mem::size_of::<Twenty>() - core::mem::size_of::<Four>()) / 16,
        );
        // The stream ledger is heap-backed. Raising table capacity therefore
        // adds only fixed association metadata until a peer is admitted.
        assert!(core::mem::size_of::<Server>() < core::mem::size_of::<Ledger>());
    }

    #[cfg(feature = "std")]
    #[test]
    fn fresh_association_retry_accepts_only_reset_or_typed_stream_timeout() {
        assert!(is_fresh_association_retry_error(&anyhow::Error::new(
            quic_lite::Error::PeerRestarted,
        )));
        assert!(is_fresh_association_retry_error(&anyhow::Error::new(
            AssociationStreamTimeout { attempts: 4 },
        )));
        assert!(!is_fresh_association_retry_error(&anyhow::anyhow!(
            "unrelated bearer failure"
        )));
    }

    #[test]
    fn dispatcher_answers_phone_bootstrap_open() {
        let packet = [
            0xc0, 0x44, 0x4d, 0x00, 0x01, 0x00, 0x08, 0xc0, 0xd5, 0xfc, 0xe0, 0x15, 0xfc, 0x35,
            0x15, 0x00, 0x11, 0x00, 0x0f, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x09, 0x80, 0x04, 0x00,
            0x00, 0x80, 0x04, 0x00, 0x00, 0x00,
        ];
        let server_cid = ConnectionId::new(0x999).unwrap();
        let path = PathId::new(1).unwrap();
        let mut dispatcher = ConnectionDispatcher::<64, 1100, 12>::new(
            server_cid,
            ConnectionLimits::default(),
            AssociationProfile::c6_default(),
        );
        let mut out = [0u8; 1100];
        let response = dispatcher.receive(path, &packet, &mut out).unwrap();
        assert!(
            response.is_some(),
            "dispatcher ignored the phone bootstrap OPEN"
        );
    }

    #[test]
    fn firmware_turn_returns_open_ack_before_stream_response() {
        let packet = [
            0xc0, 0x44, 0x4d, 0x00, 0x01, 0x00, 0x08, 0xc0, 0xd5, 0xfc, 0xe0, 0x15, 0xfc, 0x35,
            0x15, 0x00, 0x11, 0x00, 0x0f, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x09, 0x80, 0x04, 0x00,
            0x00, 0x80, 0x04, 0x00, 0x00, 0x00,
        ];
        let association = quic_lite::AssociationProfile::datagram_with_memory::<64>(
            quic_lite::ledger::LedgerMemorySnapshot {
                total_bytes: 240_000,
                available_bytes: 240_000,
            },
            1,
            1100,
            quic_lite::ledger::LedgerMemoryPolicy {
                min_packets: 2,
                ..Default::default()
            },
        );
        let limits = association.receive_limits(1100, 4);
        let _ = (association, limits);
        crate::services::register_tagged_component(104, |record| {
            let component = match record.component? {
                crate::tagged::Name::Tag(value) => value,
                _ => return None,
            };
            let method = match record.method? {
                crate::tagged::Name::Tag(value) => value,
                _ => return None,
            };
            let id = record.id?;
            let mut result = [0u8; 16];
            let mut encoder = crate::cbor::Encoder::new(&mut result);
            let len = encoder
                .map(1)
                .and_then(|()| encoder.uint(1))
                .and_then(|()| encoder.boolean(true))
                .map(|()| encoder.len())?;
            let mut response = [0u8; 64];
            let used = crate::tagged::encode_numeric_response(
                component,
                method,
                id,
                &result[..len],
                &mut response,
            )?;
            Some(response[..used].to_vec())
        });
        let server_cid = ConnectionId::new(0x999).unwrap();
        let path = PathId::new(1).unwrap();
        let mut dispatcher =
            ConnectionDispatcher::<64, 1100, 12>::new(server_cid, limits, association);
        dispatcher.set_association_idle_timeout(Some(0));
        let mut out = [0u8; 1100];
        let result = receive_server_turn(
            &mut dispatcher,
            path,
            &packet,
            10,
            &mut out,
            |_, _| {},
            |_, _, _, _| {},
        )
        .unwrap();
        let first = result.expect("firmware turn produced no packet");
        let kind = quic_lite::classify_server_datagram(&out[..first]).unwrap();
        let mut hex = String::new();
        for byte in &out[..first] {
            hex.push_str(&format!("{byte:02x}"));
        }
        eprintln!("open_ack_hex={hex}");
        match kind {
            quic_lite::ServerDatagram::BootstrapAck { .. } => {}
            other => panic!("first firmware-turn packet was {other:?}, not OPEN_ACK"),
        }
    }

    #[test]
    fn dispatcher_advertises_and_recovers_a_reset_from_device_secret_branch() {
        let client_cid = ConnectionId::new(0x91).unwrap();
        let server_cid = ConnectionId::new(0x92).unwrap();
        let path = PathId::new(1).unwrap();
        let reset_key = quic_lite::StatelessResetKey::from_device_secret(&[0x7c; 32]).unwrap();
        let mut client = quic_lite::ClientAssociation::<4, 1200>::new(client_cid);
        let mut packet = [0u8; 1200];
        client.select_path(path);
        let (_, open_len) = client.start(&mut packet).unwrap();

        let mut first = ConnectionDispatcher::<4, 1200>::new(
            server_cid,
            ConnectionLimits::default(),
            AssociationProfile::c6_default(),
        );
        first.set_stateless_reset_key(Some(reset_key));
        let open = packet[..open_len].to_vec();
        let ack_len = first.receive(path, &open, &mut packet).unwrap().unwrap();
        client
            .receive(path, &packet[..ack_len], |connection| {
                connection.receive_open_ack(&packet[..ack_len], 0)
            })
            .unwrap();

        // The rebooted dispatcher has the same device-secret branch but no
        // association table. A stale established packet receives a reset;
        // the client recognizes it without involving a UART/NOW/UDP adapter.
        let mut restarted = ConnectionDispatcher::<4, 1200>::new(
            server_cid,
            ConnectionLimits::default(),
            AssociationProfile::c6_default(),
        );
        restarted.set_stateless_reset_key(Some(reset_key));
        let issued_server_cid = client.connection().peer_cid().unwrap();
        let request_len = quic_lite::ShortHeader {
            flags: quic_lite::FLAG_FIXED,
            dcid: issued_server_cid,
            packet_number: 1,
            packet_number_len: 1,
        }
        .encode(&mut packet)
        .unwrap();
        packet[request_len..request_len + 21].fill(0);
        let stale_request = packet[..request_len + 21].to_vec();
        let reset_len = restarted
            .receive(path, &stale_request, &mut packet)
            .unwrap()
            .unwrap();
        assert_eq!(
            client.receive(path, &packet[..reset_len], |_| Ok::<_, Error>(())),
            Err(Error::PeerRestarted)
        );
    }
    use crate::probe::{ProbeServiceRequest, encode_probe_run_request};
    use quic_lite::{
        ConnectionLimits, DatagramClientDriver, EndpointState, Role,
        encode_bootstrap_open_packet_with_profile,
    };

    struct HostDelayedObjectSink {
        bytes: Vec<u8>,
        polls: usize,
        durable: bool,
        erase_work: crate::verified_object::DeferredStorageWork,
        erase_complete: bool,
    }

    impl crate::verified_object::ImageSink for HostDelayedObjectSink {
        type Error = ();

        fn begin(&mut self, _: &crate::verified_object::ImageManifest) -> Result<(), Self::Error> {
            // Match ESP flash: manifest admission schedules a cache-disrupting
            // erase for the following application maintenance turn.
            self.erase_work.request();
            Ok(())
        }

        fn write_block(&mut self, _: u32, data: &[u8]) -> Result<(), Self::Error> {
            if !self.erase_complete {
                return Err(());
            }
            self.bytes.extend_from_slice(data);
            Ok(())
        }

        fn finish(&mut self, _: &crate::verified_object::ImageManifest) -> Result<(), Self::Error> {
            self.durable = true;
            Ok(())
        }

        fn abort(&mut self) {}
    }

    impl crate::verified_object::StreamingImageSink for HostDelayedObjectSink {
        fn poll_completed(&mut self) -> Result<crate::verified_object::StoragePoll, Self::Error> {
            self.polls = self.polls.saturating_add(1);
            // `poll_before_transport` owns advancing this fake erase.  The
            // read turn only observes its actual storage result; its cadence
            // must not manufacture a transport-credit cadence.
            Ok(if self.erase_complete {
                crate::verified_object::StoragePoll::Ready
            } else {
                crate::verified_object::StoragePoll::Pending
            })
        }

        fn poll_before_transport(&mut self) -> Result<(), Self::Error> {
            if self.erase_work.take() {
                self.erase_complete = true;
            }
            Ok(())
        }
    }

    #[test]
    fn retained_tagged_client_owns_later_client_stream_ids() {
        let mut client = TaggedClient::<4, 1200>::new(
            ConnectionId::new(0x7100).unwrap(),
            &[0xa3, 1, 6, 2, 1, 3, 1],
        )
        .unwrap();
        assert_eq!(
            client.allocate_client_bidi_stream().unwrap(),
            quic_lite::FIRST_CLIENT_BIDI_STREAM_ID + 4
        );
        assert_eq!(
            client.allocate_client_bidi_stream().unwrap(),
            quic_lite::FIRST_CLIENT_BIDI_STREAM_ID + 8
        );
    }

    #[test]
    fn retained_probe_reuses_the_tagged_association_and_allocates_a_new_stream() {
        let client_cid = ConnectionId::new(0x7101).unwrap();
        let server_cid = ConnectionId::new(0x7102).unwrap();
        let path = PathId::new(0x7103).unwrap();
        let request = [0xa3, 1, 0x1a, 0, 0, 0xea, 0x61, 2, 1, 3, 1];
        let mut tagged = TaggedClient::<4, 1200>::new(client_cid, &request).unwrap();
        tagged.set_close_when_complete(false);
        let mut dispatcher = ConnectionDispatcher::<4, 1200>::new(
            server_cid,
            ConnectionLimits::default(),
            AssociationProfile::c6_default(),
        );
        let mut client_out = [0u8; 1200];
        let mut server_out = [0u8; 1200];
        let open = tagged.start(&mut client_out).unwrap();
        let ack = dispatcher
            .receive(path, &client_out[..open], &mut server_out)
            .unwrap()
            .unwrap();
        let _first_stream = tagged.receive(&server_out[..ack], &mut client_out).unwrap();
        let issued_server_cid = tagged.server_cid().unwrap();

        let (probe, probe_packet) = tagged
            .into_probe(ProbeServiceRequest::new(64, 64), &mut client_out)
            .unwrap();
        assert!(probe_packet > 0);
        assert_eq!(probe.server_cid(), Some(issued_server_cid));

        let tagged = probe.into_tagged_client();
        assert_eq!(tagged.server_cid(), Some(issued_server_cid));
        assert_eq!(
            tagged.next_server_bidi_stream_id,
            quic_lite::FIRST_SERVER_BIDI_STREAM_ID,
            "an uncompleted probe must not advance the association response sequence"
        );
    }

    fn status_test_client(cid: ConnectionId, request_id: u64) -> TaggedClient<4, 1200> {
        let mut request = [0u8; 32];
        let used = crate::tagged::encode_numeric_empty_request(
            crate::services::DIAGNOSTIC_COMPONENT,
            crate::services::DIAGNOSTIC_STATUS_METHOD,
            request_id,
            &mut request,
        )
        .expect("bounded status test request");
        TaggedClient::new(cid, &request[..used]).expect("bounded status test client")
    }

    fn diagnostic_fields_test_client(
        cid: ConnectionId,
        method: u64,
        request_id: u64,
        since: u64,
        records: Option<u64>,
    ) -> TaggedClient<4, 1200> {
        let mut request = [0u8; 64];
        let mut encoder = crate::cbor::Encoder::new(&mut request);
        encoder.map(4).unwrap();
        encoder.uint(1).unwrap();
        encoder.uint(crate::services::DIAGNOSTIC_COMPONENT).unwrap();
        encoder.uint(2).unwrap();
        encoder.uint(method).unwrap();
        encoder.uint(3).unwrap();
        encoder.uint(request_id).unwrap();
        encoder.uint(5).unwrap();
        encoder.map(if records.is_some() { 2 } else { 1 }).unwrap();
        encoder.uint(1).unwrap();
        encoder.uint(since).unwrap();
        if let Some(records) = records {
            encoder.uint(2).unwrap();
            encoder.uint(records).unwrap();
        }
        let used = encoder.len();
        TaggedClient::new(cid, &request[..used]).expect("bounded diagnostic-fields test client")
    }

    fn raw_tagged_test_handler(_record: crate::tagged::Record<'_>) -> Option<Vec<u8>> {
        Some(b"tagged-response".to_vec())
    }

    #[test]
    fn raw_object_client_streams_response_into_callback_without_a_response_buffer() {
        let client_cid = ConnectionId::new(41).unwrap();
        let server_cid = ConnectionId::new(42).unwrap();
        let request = GetRequest {
            name: None,
            cpu: 13,
            target: 6,
        };
        let mut client = ObjectClient::<4, 1200>::new(client_cid, request).unwrap();
        let mut packet = [0u8; 1200];
        client.start(&mut packet).unwrap();

        let ack_len = quic_lite::encode_bootstrap_open_ack_packet_with_limits(
            client_cid,
            server_cid,
            0,
            ConnectionLimits::default(),
            &mut packet,
        )
        .unwrap();
        let mut request_packet = [0u8; 1200];
        let request_len = client
            .receive(&packet[..ack_len], &mut request_packet, |_| Ok(()))
            .unwrap()
            .unwrap();
        assert!(request_len > 0);

        let mut server =
            EndpointState::<8, 4, 1200>::new(Role::Server, ConnectionLimits::default(), 1200);
        server
            .install_connection_ids(server_cid, client_cid)
            .unwrap();
        server.set_initial_peer_credit(4096, 4096).unwrap();
        server.continue_packet_numbers_from(1).unwrap();
        server
            .open_send_stream(
                quic_lite::FIRST_SERVER_BIDI_STREAM_ID,
                quic_lite::INITIAL_MAX_STREAM_DATA,
            )
            .unwrap();
        let (response_len, _) = server
            .encode_stream_packet(
                client_cid,
                quic_lite::FIRST_SERVER_BIDI_STREAM_ID,
                0,
                true,
                b"object-records",
                &mut packet,
            )
            .unwrap();
        let mut received = alloc::vec::Vec::new();
        let mut client_ack = [0u8; 1200];
        client
            .receive(&packet[..response_len], &mut client_ack, |fragment| {
                received.extend_from_slice(fragment);
                Ok(())
            })
            .unwrap();
        assert_eq!(received, b"object-records");
        assert!(client.is_complete());
    }

    #[test]
    fn flash_command_defers_its_response_until_the_sink_reports_completion() {
        let client = ConnectionId::new(51).unwrap();
        let server = ConnectionId::new(52).unwrap();
        let mut listener = ConnectionServer::<4, 1200>::new(server);
        let mut open = [0u8; 1200];
        let open_len = encode_bootstrap_open_packet_with_profile(
            client,
            0,
            ConnectionLimits::default(),
            4,
            &mut open,
        )
        .unwrap();
        let mut out = [0u8; 1200];
        listener.receive(&open[..open_len], &mut out).unwrap();

        let request = crate::verified_object::FlashRequest {
            object: GetRequest {
                name: None,
                cpu: 13,
                target: 6,
            },
            address: None,
            transport: 0,
            dry_run: true,
        };
        let mut body = [0u8; 128];
        let body_len =
            crate::verified_object::encode_flash_handler_request(request, 7, &mut body).unwrap();
        let mut endpoint =
            EndpointState::<4, 4, 1200>::new(Role::Client, ConnectionLimits::default(), 1200);
        endpoint.install_connection_ids(client, server).unwrap();
        endpoint.set_initial_peer_budget(4096, 4096, 4).unwrap();
        endpoint.continue_packet_numbers_from(1).unwrap();
        endpoint
            .open_send_stream(
                quic_lite::FIRST_CLIENT_BIDI_STREAM_ID,
                quic_lite::INITIAL_MAX_STREAM_DATA,
            )
            .unwrap();
        let mut packet = [0u8; 1200];
        let (used, _) = endpoint
            .encode_stream_packet(
                server,
                quic_lite::FIRST_CLIENT_BIDI_STREAM_ID,
                0,
                true,
                &body[..body_len],
                &mut packet,
            )
            .unwrap();
        assert_eq!(listener.receive(&packet[..used], &mut out).unwrap(), None);
        assert_eq!(listener.take_stream_command().unwrap(), body[..body_len]);
        // A lost ACK can replay the command-stream FIN while the dynamically
        // selected object stream is
        // already owned by the platform flash sink. That replay must retain
        // the sink and yield ordinary transport progress, not reject it as a
        // second flash command.
        assert!(listener.receive(&packet[..used], &mut out).is_ok());
        // The request may have released a transport ACK, but not an
        // application response before durable flash completion.
        let _ = listener.poll(&mut out).unwrap();
        let mut tagged = [0_u8; 128];
        let tagged_len = crate::tagged::encode_numeric_data_response(
            crate::verified_object::OBJECT_COMPONENT,
            crate::verified_object::OBJECT_FLASH_METHOD,
            7,
            b"flash complete",
            true,
            &mut tagged,
        )
        .unwrap();
        listener
            .complete_stream_command(tagged[..tagged_len].to_vec())
            .unwrap();
        assert!(listener.terminal_response_pending());
        let response_len = listener.poll(&mut out).unwrap().unwrap();
        assert!(!listener.terminal_response_pending());
        assert!(!listener.take_terminal_response_delivered());
        let response = endpoint.receive_datagram(&out[..response_len]).unwrap();
        let TransportPacket::Stream { frame, .. } = response else {
            panic!("expected tagged flash response stream");
        };
        let record = crate::tagged::decode(frame.data).unwrap();
        assert_eq!(record.component, Some(crate::tagged::Name::Tag(10)));
        assert_eq!(record.method, Some(crate::tagged::Name::Tag(2)));
        assert_eq!(record.id, Some(7));
        let mut result = crate::cbor::Decoder::new(record.result.unwrap());
        assert_eq!(result.text_ref(), Some(&b"flash complete"[..]));
        assert!(result.is_finished());
        // The terminal response ACK must make this association reclaimable
        // even if the client's subsequent CLOSE is lost. Firmware cannot
        // retain one heap-backed ledger per short-lived CLI process until a
        // large host-style table fills.
        endpoint.set_time(100);
        let ack_len = endpoint.poll_transmit(&mut packet).unwrap().unwrap();
        listener.receive(&packet[..ack_len], &mut out).unwrap();
        assert!(listener.take_terminal_response_delivered());
        assert!(!listener.take_terminal_response_delivered());
        assert_eq!(listener.active_stream_count(), 0);
    }

    #[test]
    fn finish_receive_turn_preserves_an_immediate_transport_packet() {
        let path = PathId::new(1).unwrap();
        let mut dispatcher = ConnectionDispatcher::<2, 1200>::new(
            ConnectionId::new(61).unwrap(),
            ConnectionLimits::default(),
            AssociationProfile::conservative(),
        );
        let mut output = [0u8; 1200];
        assert_eq!(
            dispatcher
                .finish_receive_turn(path, Some(73), &mut output)
                .unwrap(),
            Some(73)
        );
        assert_eq!(
            dispatcher
                .finish_receive_turn(path, None, &mut output)
                .unwrap(),
            None
        );
    }

    #[test]
    fn inbound_consumer_turn_distinguishes_idle_consumer_and_transport_failures() {
        let mut dispatcher = ConnectionDispatcher::<2, 1200>::new(
            ConnectionId::new(71).unwrap(),
            ConnectionLimits::default(),
            AssociationProfile::conservative(),
        );
        assert_eq!(
            consume_inbound_stream(&mut dispatcher, |reader| {
                assert_eq!(reader.read(&mut []), 0);
                Ok::<_, u8>(false)
            }),
            Ok(InboundStreamTurn {
                had_chunks: false,
                application_progress: false,
                consumed_bytes: 0,
            })
        );
        assert_eq!(
            consume_inbound_stream(&mut dispatcher, |_| Err::<bool, _>(7)),
            Err(InboundStreamTurnError::Consumer(7))
        );
        // Empty maintenance turns have no consumed bytes to report. They are
        // intentionally harmless even when no receive stream was selected.
        assert!(consume_inbound_stream(&mut dispatcher, |_| { Ok::<_, u8>(false) }).is_ok());
    }

    #[test]
    fn exclusive_consumer_turn_refreshes_timeout_from_application_progress() {
        let owner = ConnectionId::new(91).unwrap();
        let mut operation = crate::verified_object::ExclusiveTransfer::new();
        operation
            .try_start_with(owner, 7, 0, 10, || Ok::<_, ()>(0_u8))
            .unwrap();
        let mut dispatcher = ConnectionDispatcher::<4, 1200>::new(
            ConnectionId::new(92).unwrap(),
            ConnectionLimits::default(),
            AssociationProfile::conservative(),
        );

        let turn = consume_exclusive_inbound_stream(
            &mut dispatcher,
            &mut operation,
            owner,
            5,
            10,
            |value, reader| {
                assert_eq!(reader.read(&mut []), 0);
                *value += 1;
                Ok::<_, ()>(true)
            },
        )
        .unwrap();
        assert!(turn.application_progress);
        assert_eq!(operation.get_mut_for(owner).copied(), Some(1));
        assert!(operation.take_expired(14).is_none());
        assert!(operation.take_expired(15).is_some());
    }

    #[test]
    fn exclusive_consumer_failure_releases_operation_for_next_request() {
        let owner = ConnectionId::new(93).unwrap();
        let mut operation = crate::verified_object::ExclusiveTransfer::new();
        operation
            .try_start_with(owner, 17, 0, 10, || Ok::<_, ()>(41_u8))
            .unwrap();
        let mut dispatcher = ConnectionDispatcher::<4, 1200>::new(
            ConnectionId::new(94).unwrap(),
            ConnectionLimits::default(),
            AssociationProfile::conservative(),
        );

        assert_eq!(
            consume_exclusive_inbound_stream(
                &mut dispatcher,
                &mut operation,
                owner,
                5,
                10,
                |_value, _reader| Err::<bool, _>(7_u8),
            ),
            Err(ExclusiveInboundStreamTurnError::Consumer {
                request_id: 17,
                value: 41,
                error: 7,
            })
        );
        assert_eq!(operation.owner(), None);
        operation
            .try_start_with(owner, 18, 6, 10, || Ok::<_, ()>(42_u8))
            .unwrap();
        assert_eq!(operation.get_mut_for(owner).copied(), Some(42));
    }

    #[test]
    fn flash_object_credit_after_an_immediate_ack_advances_selected_stream() {
        let client = ConnectionId::new(81).unwrap();
        let server = ConnectionId::new(82).unwrap();
        let path = PathId::new(81).unwrap();
        let limits = ConnectionLimits {
            max_data: 64,
            max_stream_data: 64,
            ..ConnectionLimits::default()
        };
        let mut listener = ConnectionDispatcher::<4, 1200>::new(
            server,
            limits,
            AssociationProfile::datagram_default(),
        );
        let mut open = [0u8; 1200];
        let open_len =
            encode_bootstrap_open_packet_with_profile(client, 0, limits, 4, &mut open).unwrap();
        let mut out = [0u8; 1200];
        let _ack_len = listener
            .receive(path, &open[..open_len], &mut out)
            .unwrap()
            .unwrap();

        let mut endpoint =
            EndpointState::<4, 4, 1200>::new(Role::Client, ConnectionLimits::default(), 1200);
        endpoint.install_connection_ids(client, server).unwrap();
        endpoint.set_initial_peer_credit(64, 64).unwrap();
        endpoint.continue_packet_numbers_from(1).unwrap();

        let request = crate::verified_object::FlashRequest {
            object: GetRequest {
                name: None,
                cpu: 13,
                target: 6,
            },
            address: None,
            transport: 0,
            dry_run: true,
        };
        let mut body = [0u8; 128];
        let body_len =
            crate::verified_object::encode_flash_handler_request(request, 9, &mut body).unwrap();
        // This deliberately makes the flash command the second client bidi
        // stream. The receiver must derive its object stream from the command
        // stream, not assume the first association's numerical IDs.
        let command_stream = quic_lite::FIRST_CLIENT_BIDI_STREAM_ID + 4;
        let object_stream = command_stream + 4;
        endpoint.open_send_stream(command_stream, 64).unwrap();
        let mut packet = [0u8; 1200];
        let (used, _) = endpoint
            .encode_stream_packet(
                server,
                command_stream,
                0,
                true,
                &body[..body_len],
                &mut packet,
            )
            .unwrap();
        assert_eq!(
            listener.receive(path, &packet[..used], &mut out).unwrap(),
            None
        );
        let _ = listener.take_stream_command();

        // The sink learns of the command before the selected stream has a fragment. It
        // must be able to publish its current storage window at that point:
        // waiting for a first fragment deadlocks when the generic bootstrap
        // window is intentionally only one datagram.
        prepare_inbound_stream_with_consumer(&mut listener, consume_all).unwrap();
        // The client reserves the application-named stream before accepting
        // its peer's first MAX_STREAM_DATA update.
        endpoint.open_send_stream(object_stream, 64).unwrap();
        let initial_credit = listener.poll_for(path, &mut out).unwrap().unwrap();
        endpoint.receive_datagram(&out[..initial_credit]).unwrap();
        // The command consumed 30 bytes of the original connection window;
        // the prepared storage window extends that absolute bound to 128.
        assert_eq!(endpoint.peer_send_credit(object_stream), Some((98, 64)));

        let (used, _) = endpoint
            .encode_stream_packet(server, object_stream, 0, false, &[0x5a; 16], &mut packet)
            .unwrap();
        assert!(
            listener
                .receive(path, &packet[..used], &mut out)
                .unwrap()
                .is_none()
        );
        // The memory-selected ACK policy batches this ordinary stream packet;
        // the timer turn below owns its eventual ACK/MAX emission.
        let before = endpoint.peer_send_credit(object_stream).unwrap();
        assert_eq!(before, (98, 64));
        assert_eq!(
            listener
                .core
                .association_for_path(path)
                .unwrap()
                .connection
                .as_ref()
                .unwrap()
                .mux
                .endpoint
                .receive_credit_state(object_stream),
            // The handler receives only ordered bytes and reports the prefix
            // it consumed; QUIC-lite owns the resulting receive credit.
            Some((50, 16, 80))
        );
        assert!(
            !listener.has_inbound_stream_chunks(),
            "generic consumer must retain suffixes in QUIC-lite, not the dispatcher queue"
        );
        let credit = poll_server_turn(&mut listener, path, 8, 600, &mut out, |_, _, _| {})
            .unwrap()
            .unwrap();
        endpoint.receive_datagram(&out[..credit]).unwrap();
        // The dispatcher must replenish the selected object stream, not the
        // earlier command stream. This is the host counterpart of Recovery's
        // command-stream 4 / object-stream 8 upload layout.
        assert_eq!(endpoint.peer_send_credit(object_stream), Some((114, 80)));
    }

    #[test]
    fn accepts_a_socket_free_probe_request_and_produces_stream_data() {
        let client = ConnectionId::new(7).unwrap();
        let server = ConnectionId::new(9).unwrap();
        let mut listener = ConnectionServer::<4, 1200>::new(server);
        let mut open = [0u8; 1200];
        let open_len = encode_bootstrap_open_packet_with_profile(
            client,
            0,
            ConnectionLimits::default(),
            8,
            &mut open,
        )
        .unwrap();
        let mut out = [0u8; 1200];
        assert!(
            listener
                .receive(&open[..open_len], &mut out)
                .unwrap()
                .is_some()
        );
        // Wi-Fi retries may redeliver OPEN after its ACK was queued. It must
        // not replace the admitted endpoint or advance its receive packet
        // number before the client's first stream packet.
        assert!(
            listener
                .receive(&open[..open_len], &mut out)
                .unwrap()
                .is_some()
        );

        let mut endpoint =
            EndpointState::<4, 4, 1200>::new(Role::Client, ConnectionLimits::default(), 1200);
        endpoint.install_connection_ids(client, server).unwrap();
        endpoint.set_initial_peer_budget(4096, 4096, 8).unwrap();
        endpoint
            .open_send_stream(
                quic_lite::FIRST_CLIENT_BIDI_STREAM_ID,
                quic_lite::INITIAL_MAX_STREAM_DATA,
            )
            .unwrap();
        let mut body = [0u8; crate::probe::PROBE_RUN_REQUEST_MAX];
        let body_len =
            encode_probe_run_request(ProbeServiceRequest::new(64, 64), 1, &mut body).unwrap();
        let mut request = [0u8; 1200];
        let (request_len, _) = endpoint
            .encode_stream_packet(
                server,
                quic_lite::FIRST_CLIENT_BIDI_STREAM_ID,
                0,
                true,
                &body[..body_len],
                &mut request,
            )
            .unwrap();
        let response = listener.receive(&request[..request_len], &mut out).unwrap();
        assert!(response.is_some());
    }

    #[test]
    fn client_and_server_complete_over_a_packet_at_a_time_bearer() {
        let client_cid = ConnectionId::new(0x44).unwrap();
        let server_cid = ConnectionId::new(0x55).unwrap();
        let mut client = ProbeClient::<4, 1200>::new(client_cid, 8 * 1024).unwrap();
        let mut server = ConnectionServer::<4, 1200>::new(server_cid);
        let mut client_out = [0u8; 1200];
        let mut server_out = [0u8; 1200];

        let open_len = client.start(&mut client_out).unwrap();
        let open_ack_len = server
            .receive(&client_out[..open_len], &mut server_out)
            .unwrap()
            .unwrap();
        let request_len = client
            .receive(&server_out[..open_ack_len], &mut client_out)
            .unwrap()
            .unwrap();
        // A DW-gated bearer can repeat OPEN before the first OPEN-ACK reaches
        // the client; accepting the repeated ACK must not turn into an
        // invalid stream packet after bootstrap has completed.
        assert_eq!(
            client
                .receive(&server_out[..open_ack_len], &mut client_out)
                .unwrap(),
            None
        );
        let mut server_len = server
            .receive(&client_out[..request_len], &mut server_out)
            .unwrap()
            .unwrap();

        for _ in 0..128 {
            let client_len = client
                .receive(&server_out[..server_len], &mut client_out)
                .unwrap();
            if client.is_complete() {
                break;
            }
            let client_len = client_len.expect("PROBE stream packet must produce ACK");
            server_len = server
                .receive(&client_out[..client_len], &mut server_out)
                .unwrap()
                .unwrap();
        }
        assert!(client.is_complete());
        assert_eq!(client.bytes(), 8 * 1024);
        assert_eq!(client.callback_errors(), [0; 6]);
    }

    #[test]
    fn constrained_client_completes_a_64k_transfer() {
        // Firmware's raw UDP6 client and service association both retain a
        // bounded small-packet history. Exercise a transfer substantially
        // larger than one flight so a future capacity mismatch cannot strand
        // the client after its initial window while appearing to work for a
        // 4 KiB smoke test.
        let client_cid = ConnectionId::new(0x46).unwrap();
        let server_cid = ConnectionId::new(0x56).unwrap();
        let mut client = ProbeClient::<8, 1200>::new(client_cid, 64 * 1024).unwrap();
        let mut server = ConnectionServer::<8, 1200>::new(server_cid);
        let mut client_out = [0u8; 1200];
        let mut server_out = [0u8; 1200];

        let open_len = client.start(&mut client_out).unwrap();
        let open_ack_len = server
            .receive(&client_out[..open_len], &mut server_out)
            .unwrap()
            .unwrap();
        let request_len = client
            .receive(&server_out[..open_ack_len], &mut client_out)
            .unwrap()
            .unwrap();
        let mut server_len = server
            .receive(&client_out[..request_len], &mut server_out)
            .unwrap()
            .unwrap();

        for _ in 0..512 {
            let client_len = client
                .receive(&server_out[..server_len], &mut client_out)
                .unwrap();
            if client.is_complete() {
                break;
            }
            let client_len = client_len.expect("PROBE stream packet must produce ACK");
            server_len = server
                .receive(&client_out[..client_len], &mut server_out)
                .unwrap()
                .unwrap();
        }
        assert!(client.is_complete());
        assert_eq!(client.bytes(), 64 * 1024);
        assert_eq!(client.callback_errors(), [0; 6]);
    }

    #[test]
    fn large_prober_transfer_completes_with_32_and_64_packet_ledgers() {
        // Exercise the same selected ledger sizes Recovery exposes for a
        // controlled host test.  The payload is deliberately far larger than
        // either flight, so ACK, credit, and loss-ledger rotation all occur.
        fn run<const HISTORY: usize>() {
            let client_cid = ConnectionId::new(0x4a00 + HISTORY as u64).unwrap();
            let server_cid = ConnectionId::new(0x5a00 + HISTORY as u64).unwrap();
            let local_limits = ConnectionLimits::with_receive_profile(
                (HISTORY * 1200) as u64,
                ((HISTORY / 2) * 1200) as u64,
                4,
            );
            let mut client = ProbeClient::<HISTORY, 1200>::from_request_with_limits(
                client_cid,
                ProbeServiceRequest::new(1024 * 1024, 1_100),
                local_limits,
            )
            .unwrap();
            let mut server = ConnectionServer::<HISTORY, 1200>::new(server_cid);
            let mut client_out = [0u8; 1200];
            let mut server_out = [0u8; 1200];
            let open_len = client.start(&mut client_out).unwrap();
            let open_ack_len = server
                .receive(&client_out[..open_len], &mut server_out)
                .unwrap()
                .unwrap();
            let request_len = client
                .receive(&server_out[..open_ack_len], &mut client_out)
                .unwrap()
                .unwrap();
            let mut server_len = server
                .receive(&client_out[..request_len], &mut server_out)
                .unwrap()
                .unwrap();
            for _ in 0..10_000 {
                let client_len = client
                    .receive(&server_out[..server_len], &mut client_out)
                    .unwrap();
                if client.is_complete() {
                    break;
                }
                let client_len = client_len.expect("probe packet requires response");
                server_len = server
                    .receive(&client_out[..client_len], &mut server_out)
                    .unwrap()
                    .unwrap();
            }
            assert!(client.is_complete(), "history={HISTORY}");
            assert_eq!(client.bytes(), 1024 * 1024, "history={HISTORY}");
            assert_eq!(client.callback_errors(), [0; 6], "history={HISTORY}");
        }
        run::<32>();
        run::<64>();
    }

    #[test]
    fn prober_stress_completes_ten_large_transfers_with_small_configurable_receive_windows() {
        // This is deliberately receiver-side flow control, not a packet
        // bearer setting.  It exercises the same pattern a flash/file sink
        // uses: accept an MTU-sized stream fragment, defer consumption while
        // work is pending, then let ordinary QUIC MAX_* credit resume the
        // sender.  Keep the transfer much larger than every tested window.
        for run in 0..10u64 {
            let window = [1_200u64, 2_400, 4_800][run as usize % 3];
            let client_cid = ConnectionId::new(0x6000 + run).unwrap();
            let server_cid = ConnectionId::new(0x7000 + run).unwrap();
            let request = ProbeServiceRequest {
                initial_consume_delay_ms: Some(3),
                consume_delay_ms: Some(1),
                ..ProbeServiceRequest::new(1024 * 1024, 1_100)
            };
            let mut client = ProbeClient::<8, 1200>::from_request_with_limits(
                client_cid,
                request,
                ConnectionLimits::with_receive_window(window),
            )
            .unwrap();
            let mut server = ConnectionServer::<8, 1200>::new(server_cid);
            let mut client_out = [0u8; 1200];
            let mut server_out = [0u8; 1200];
            let mut to_server = std::collections::VecDeque::new();
            let mut to_client = std::collections::VecDeque::new();
            let started = client.start(&mut client_out).unwrap();
            to_server.push_back(client_out[..started].to_vec());

            for now_ms in 0..200_000 {
                while let Some(packet) = to_server.pop_front() {
                    if let Some(used) = server.receive(&packet, &mut server_out).unwrap() {
                        to_client.push_back(server_out[..used].to_vec());
                    }
                }
                while let Some(packet) = to_client.pop_front() {
                    if let Some(used) = client.receive_at(&packet, now_ms, &mut client_out).unwrap()
                    {
                        to_server.push_back(client_out[..used].to_vec());
                    }
                }
                if let Some(used) = client.poll_transmit_at(now_ms, &mut client_out).unwrap() {
                    to_server.push_back(client_out[..used].to_vec());
                }
                if client.is_complete() {
                    break;
                }
            }
            assert!(client.is_complete(), "run={run} window={window}");
            assert_eq!(client.bytes(), 1024 * 1024, "run={run} window={window}");
            assert_eq!(
                client.callback_errors(),
                [0; 6],
                "run={run} window={window}"
            );
        }
    }

    #[test]
    fn in_place_client_has_the_same_wire_state_as_the_normal_constructor() {
        // Firmware constructs the raw action client directly in its final
        // heap allocation so a large bounded ledger is never copied through
        // the shared packet-worker stack. Keep that memory-safety path under
        // the exact same OPEN/request/server exchange as the usual host
        // constructor; a partially initialized field would otherwise first
        // appear as an unexplained on-air `Invalid` request.
        let client_cid = ConnectionId::new(0x147).unwrap();
        let server_cid = ConnectionId::new(0x247).unwrap();
        let mut storage = MaybeUninit::<ProbeClient<4, 1200>>::uninit();
        let client = ProbeClient::new_in_place(&mut storage, client_cid, 4 * 1024, 256).unwrap();
        let mut server = ConnectionServer::<8, 1200>::new(server_cid);
        let mut client_out = [0u8; 1200];
        let mut server_out = [0u8; 1200];

        let open_len = client.start(&mut client_out).unwrap();
        let open_ack_len = server
            .receive(&client_out[..open_len], &mut server_out)
            .unwrap()
            .unwrap();
        let request_len = client
            .receive(&server_out[..open_ack_len], &mut client_out)
            .unwrap()
            .unwrap();
        let first_stream_len = server
            .receive(&client_out[..request_len], &mut server_out)
            .unwrap()
            .unwrap();
        assert!(first_stream_len > 0);
        unsafe { core::ptr::drop_in_place(client) };
    }

    #[test]
    fn raw_server_can_fill_the_configured_eight_packet_burst_before_ack() {
        let client_cid = ConnectionId::new(0x64).unwrap();
        let server_cid = ConnectionId::new(0x65).unwrap();
        let association = AssociationProfile {
            history_packets: 8,
            ack_frequency: 2,
            ack_delay_ms: 5,
            tx_burst_packets: 8,
            initial_window_packets: 8,
        };
        let mut client = ProbeClient::<8, 1200>::new(client_cid, 64 * 1024).unwrap();
        let mut server = ConnectionServer::<8, 1200>::new_with_association(
            server_cid,
            ConnectionLimits::default(),
            association,
        );
        let mut client_out = [0u8; 1200];
        let mut server_out = [0u8; 1200];
        let open_len = client.start(&mut client_out).unwrap();
        let open_ack_len = server
            .receive(&client_out[..open_len], &mut server_out)
            .unwrap()
            .unwrap();
        assert_eq!(
            server
                .connection
                .as_ref()
                .expect("OPEN installs raw association")
                .mux
                .endpoint
                .ack_frequency(),
            association.ack_frequency,
            "accepted raw association must apply its QUIC ACK policy"
        );
        let (_, advertised) = quic_lite::decode_bootstrap_open_ack_packet_with_limits(
            &server_out[..open_ack_len],
            client_cid,
        )
        .unwrap();
        assert_eq!(
            advertised.max_in_flight_packets, 0,
            "shared byte credit must not be coupled to a raw-bearer packet cap"
        );
        let request_len = client
            .receive(&server_out[..open_ack_len], &mut client_out)
            .unwrap()
            .unwrap();
        assert!(
            server
                .receive(&client_out[..request_len], &mut server_out)
                .unwrap()
                .is_some()
        );
        let mut emitted = 1;
        for _ in 1..8 {
            emitted += usize::from(server.poll(&mut server_out).unwrap().is_some());
        }
        assert_eq!(emitted, 8, "eight-packet association must not wait for ACK");
    }

    #[test]
    fn status_test_client_receives_tagged_response_over_raw_bearer() {
        let client_cid = ConnectionId::new(0x66).unwrap();
        let server_cid = ConnectionId::new(0x77).unwrap();
        let mut client = status_test_client(client_cid, 0x1234);
        let mut server = ConnectionServer::<4, 1200>::new(server_cid);
        let mut client_out = [0u8; 1200];
        let mut server_out = [0u8; 1200];

        let open_len = client.start(&mut client_out).unwrap();
        let open_ack_len = server
            .receive(&client_out[..open_len], &mut server_out)
            .unwrap()
            .unwrap();
        let request_len = client
            .receive(&server_out[..open_ack_len], &mut client_out)
            .unwrap()
            .unwrap();
        let response_len = server
            .receive(&client_out[..request_len], &mut server_out)
            .unwrap()
            .unwrap();
        let _ = client
            .receive(&server_out[..response_len], &mut client_out)
            .unwrap();

        assert!(client.is_complete());
        assert!(
            client
                .response()
                .is_some_and(|response| !response.is_empty())
        );
        assert_eq!(client.bytes(), client.response().unwrap().len() as u64);
    }

    #[test]
    fn zero_retention_dispatcher_keeps_open_across_adapter_clock_turn() {
        let client_cid = ConnectionId::new(0x1660).unwrap();
        let server_cid = ConnectionId::new(0x1770).unwrap();
        let path = PathId::new(1).unwrap();
        let mut client = status_test_client(client_cid, 0x1235);
        let mut server = ConnectionDispatcher::<4, 1200, 4>::new(
            server_cid,
            ConnectionLimits::default(),
            AssociationProfile::c6_default(),
        );
        server.set_association_idle_timeout(Some(0));
        let mut client_out = [0_u8; 1200];
        let mut server_out = [0_u8; 1200];

        let open_len = client.start(&mut client_out).unwrap();
        let open_ack_len = server
            .receive(path, &client_out[..open_len], &mut server_out)
            .unwrap()
            .unwrap();
        let request_len = client
            .receive(&server_out[..open_ack_len], &mut client_out)
            .unwrap()
            .unwrap();

        // Main and Recovery run their clock/deadline scheduler between UART
        // or UDP datagrams. This exact turn was absent from the old host test
        // and used to reclaim the association before its first request.
        server.set_time(1);
        let response_len = server
            .receive(path, &client_out[..request_len], &mut server_out)
            .unwrap()
            .expect("the first established request must retain its OPEN");
        let _ = client
            .receive(&server_out[..response_len], &mut client_out)
            .unwrap();
        assert!(client.is_complete());
        assert!(server.last_stateless_reset().is_none());
    }

    #[test]
    fn tagged_client_round_trips_a_direct_record_over_raw_bearer() {
        const COMPONENT: u64 = 60_001;
        assert!(crate::services::register_tagged_component(
            COMPONENT,
            raw_tagged_test_handler
        ));
        // {1: component, 2: method, 3: request id}; no legacy service byte.
        let request = [0xa3, 1, 0x1a, 0, 0, 0xea, 0x61, 2, 1, 3, 7];
        let client_cid = ConnectionId::new(0x166).unwrap();
        let server_cid = ConnectionId::new(0x177).unwrap();
        let mut client = TaggedClient::<4, 1200>::new(client_cid, &request).unwrap();
        client.set_close_when_complete(false);
        let mut server = ConnectionServer::<4, 1200>::new(server_cid);
        let mut client_out = [0u8; 1200];
        let mut server_out = [0u8; 1200];

        let open_len = client.start(&mut client_out).unwrap();
        let open_ack_len = server
            .receive(&client_out[..open_len], &mut server_out)
            .unwrap()
            .unwrap();
        let request_len = client
            .receive_at(&server_out[..open_ack_len], 1, &mut client_out)
            .unwrap()
            .unwrap();
        let response_len = server
            .receive(&client_out[..request_len], &mut server_out)
            .unwrap()
            .unwrap();
        assert!(!server.take_terminal_response_delivered());
        let ack_len = client
            .receive_at(&server_out[..response_len], 2, &mut client_out)
            .unwrap()
            .expect("terminal tagged response must produce transport control");
        server
            .receive(&client_out[..ack_len], &mut server_out)
            .unwrap();
        let in_flight = server
            .connection
            .as_ref()
            .map_or(u64::MAX, |connection| connection.bytes_in_flight());
        assert!(
            server.take_terminal_response_delivered(),
            "terminal response remained in flight: {in_flight}"
        );
        assert!(!server.take_terminal_response_delivered());

        assert!(client.is_complete());
        assert_eq!(client.response(), Some(b"tagged-response".as_slice()));
        assert_eq!(client.counters().stream_packets, 1);
    }

    #[test]
    fn tagged_client_round_trips_bounded_events_and_log_watch_over_raw_bearer() {
        for (method, records, expected) in [
            (
                crate::services::DIAGNOSTIC_EVENTS_METHOD,
                None,
                b"events_version=".as_slice(),
            ),
            (
                crate::services::DIAGNOSTIC_LOG_WATCH_METHOD,
                Some(1),
                b"log_watch_version=".as_slice(),
            ),
        ] {
            let client_cid = ConnectionId::new(0x188 + method).unwrap();
            let server_cid = ConnectionId::new(0x198 + method).unwrap();
            let mut client = diagnostic_fields_test_client(client_cid, method, 71, 0, records);
            let mut server = ConnectionServer::<4, 1200>::new(server_cid);
            let mut client_out = [0u8; 1200];
            let mut server_out = [0u8; 1200];

            let open_len = client.start(&mut client_out).unwrap();
            let open_ack_len = server
                .receive(&client_out[..open_len], &mut server_out)
                .unwrap()
                .unwrap();
            let request_len = client
                .receive_at(&server_out[..open_ack_len], 1, &mut client_out)
                .unwrap()
                .unwrap();
            let response_len = server
                .receive(&client_out[..request_len], &mut server_out)
                .unwrap()
                .expect("connection diagnostic produces a tagged response");
            let _ = client
                .receive_at(&server_out[..response_len], 2, &mut client_out)
                .unwrap();

            assert!(client.is_complete());
            let response =
                crate::tagged::decode(client.response().expect("diagnostic response bytes"))
                    .and_then(|record| record.result)
                    .and_then(|result| crate::cbor::Decoder::new(result).text_ref())
                    .expect("diagnostic response text");
            assert!(
                response.starts_with(expected),
                "method={method} response={response:?}"
            );
        }
    }

    #[test]
    fn tagged_stream_handler_survives_uart_to_action_path_migration() {
        const COMPONENT: u64 = 60_002;
        assert!(crate::services::register_tagged_component(
            COMPONENT,
            raw_tagged_test_handler
        ));
        let request = [0xa3, 1, 0x1a, 0, 0, 0xea, 0x62, 2, 1, 3, 8];
        let uart_path = PathId::new(0x6001).unwrap();
        let action_path = PathId::new(0x6002).unwrap();
        let mut client =
            TaggedClient::<4, 1200>::new(ConnectionId::new(0x168).unwrap(), &request).unwrap();
        let mut dispatcher = ConnectionDispatcher::<4, 1200>::new(
            ConnectionId::new(0x178).unwrap(),
            ConnectionLimits::default(),
            AssociationProfile::c6_default(),
        );
        let mut client_out = [0u8; 1200];
        let mut server_out = [0u8; 1200];

        let open_len = client.start(&mut client_out).unwrap();
        let ack_len = dispatcher
            .receive(uart_path, &client_out[..open_len], &mut server_out)
            .unwrap()
            .expect("UART frame admits the connection");
        let request_len = client
            .receive(&server_out[..ack_len], &mut client_out)
            .unwrap()
            .expect("OPEN_ACK produces tagged stream request");
        let response_len = dispatcher
            .receive(action_path, &client_out[..request_len], &mut server_out)
            .unwrap()
            .expect("same DCID is accepted on the action path");
        let _ = client
            .receive(&server_out[..response_len], &mut client_out)
            .unwrap();

        assert!(client.is_complete());
        assert_eq!(client.response(), Some(b"tagged-response".as_slice()));
        assert_eq!(dispatcher.reply_path(), Some(action_path));
    }

    #[test]
    fn receive_turn_keeps_an_immediate_tagged_stream_response() {
        // Component IDs are process-global production registrations. Keep
        // every test ID unique so parallel host tests cannot accidentally
        // share or reject a handler registration.
        const COMPONENT: u64 = 60_007;
        assert!(crate::services::register_tagged_component(
            COMPONENT,
            raw_tagged_test_handler
        ));
        let request = [0xa3, 1, 0x1a, 0, 0, 0xea, 0x67, 2, 1, 3, 9];
        let path = PathId::new(0x6007).unwrap();
        let mut client =
            TaggedClient::<4, 1200>::new(ConnectionId::new(0x16d).unwrap(), &request).unwrap();
        let mut dispatcher = ConnectionDispatcher::<4, 1200>::new(
            ConnectionId::new(0x17d).unwrap(),
            ConnectionLimits::default(),
            AssociationProfile::c6_default(),
        );
        let mut client_out = [0u8; 1200];
        let mut server_out = [0u8; 1200];

        let open_len = client.start(&mut client_out).unwrap();
        let open_ack = dispatcher
            .receive(path, &client_out[..open_len], &mut server_out)
            .unwrap()
            .unwrap();
        let request_len = client
            .receive(&server_out[..open_ack], &mut client_out)
            .unwrap()
            .unwrap();
        let immediate = dispatcher
            .receive(path, &client_out[..request_len], &mut server_out)
            .unwrap()
            .expect("tagged handler encodes an immediate stream response");
        assert!(quic_lite::packet_has_stream_frame(&server_out[..immediate]));
        let response = dispatcher
            .finish_receive_turn(path, Some(immediate), &mut server_out)
            .unwrap()
            .expect("receive turn retains the stream response");
        assert!(quic_lite::packet_has_stream_frame(&server_out[..response]));
        client
            .receive(&server_out[..response], &mut client_out)
            .unwrap();
        assert_eq!(client.response(), Some(b"tagged-response".as_slice()));
    }

    #[test]
    fn terminal_delivery_survives_a_close_that_carries_its_ack() {
        // A one-shot UDP client commonly receives a terminal response, then
        // emits CLOSE with its delayed ACK rather than a separate control
        // datagram. The association table releases the connection during
        // that CLOSE, but Main still needs the generic response-delivered
        // edge to arm its Stage2 Recovery handoff.
        const COMPONENT: u64 = 60_008;
        assert!(crate::services::register_tagged_component(
            COMPONENT,
            raw_tagged_test_handler
        ));
        let request = [0xa3, 1, 0x1a, 0, 0, 0xea, 0x68, 2, 1, 3, 10];
        let path = PathId::new(0x6008).unwrap();
        let mut client =
            TaggedClient::<4, 1200>::new(ConnectionId::new(0x16e).unwrap(), &request).unwrap();
        client.set_close_when_complete(false);
        let mut dispatcher = ConnectionDispatcher::<4, 1200>::new(
            ConnectionId::new(0x17e).unwrap(),
            ConnectionLimits::default(),
            AssociationProfile::c6_default(),
        );
        let mut client_out = [0u8; 1200];
        let mut server_out = [0u8; 1200];

        let open_len = client.start(&mut client_out).unwrap();
        let open_ack = dispatcher
            .receive(path, &client_out[..open_len], &mut server_out)
            .unwrap()
            .unwrap();
        let request_len = client
            .receive(&server_out[..open_ack], &mut client_out)
            .unwrap()
            .unwrap();
        let response_len = dispatcher
            .receive(path, &client_out[..request_len], &mut server_out)
            .unwrap()
            .unwrap();
        let delayed_ack = client
            .receive(&server_out[..response_len], &mut client_out)
            .unwrap();
        assert!(client.is_complete());

        // The UDP adapter waits for and sends this delayed ACK before its
        // one-shot CLOSE. Do not consume the dispatcher edge yet: model a
        // platform runtime which performs its post-turn lifecycle action
        // after the table has already retired that association.
        let delayed_ack = delayed_ack.expect("terminal response queues delayed ACK");
        dispatcher
            .receive(path, &client_out[..delayed_ack], &mut server_out)
            .unwrap();

        client.connection.close(0).unwrap();
        let close_len = client
            .connection
            .poll_close(&mut client_out)
            .unwrap()
            .expect("CLOSE follows the terminal response ACK");
        dispatcher
            .receive(path, &client_out[..close_len], &mut server_out)
            .unwrap();

        assert!(dispatcher.last_close_at().is_some());
        assert!(dispatcher.take_terminal_response_delivered().is_some());
        assert!(dispatcher.take_terminal_response_delivered().is_none());
    }

    #[test]
    fn retained_tagged_client_reuses_association_on_a_later_stream() {
        const COMPONENT: u64 = 60_005;
        assert!(crate::services::register_tagged_component(
            COMPONENT,
            raw_tagged_test_handler
        ));
        let first = [0xa3, 1, 0x1a, 0, 0, 0xea, 0x65, 2, 1, 3, 1];
        let path = PathId::new(0x6005).unwrap();
        let client_cid = ConnectionId::new(0x16b).unwrap();
        let mut client = TaggedClient::<16, 1200>::new(client_cid, &first).unwrap();
        client.set_close_when_complete(false);
        let mut dispatcher = ConnectionDispatcher::<16, 1200>::new(
            ConnectionId::new(0x17b).unwrap(),
            ConnectionLimits::default(),
            AssociationProfile::c6_default(),
        );
        let mut client_out = [0u8; 1200];
        let mut server_out = [0u8; 1200];

        let open_len = client.start(&mut client_out).unwrap();
        let ack_len = dispatcher
            .receive(path, &client_out[..open_len], &mut server_out)
            .unwrap()
            .unwrap();
        let first_len = client
            .receive(&server_out[..ack_len], &mut client_out)
            .unwrap()
            .unwrap();
        let first_response = dispatcher
            .receive(path, &client_out[..first_len], &mut server_out)
            .unwrap()
            .unwrap();
        let first_control = client
            .receive(&server_out[..first_response], &mut client_out)
            .unwrap();
        if let Some(control_len) = first_control {
            if let Some(server_control_len) = dispatcher
                .receive(path, &client_out[..control_len], &mut server_out)
                .unwrap()
            {
                let _ = client
                    .receive(&server_out[..server_control_len], &mut client_out)
                    .unwrap();
            }
        }
        assert!(client.is_complete());

        // A catalog pass must not reconnect after the fourth RPC merely
        // because each tagged request/response uses one stream in each
        // direction.  This failed with the former eight combined slots.
        for sequence in 2..=16u8 {
            let request = [0xa3, 1, 0x1a, 0, 0, 0xea, 0x65, 2, 1, 3, sequence];
            let request_len = client
                .begin_request(u64::from(sequence) * 4, &request, &mut client_out)
                .unwrap_or_else(|error| panic!("sequence={sequence} begin request: {error:?}"));
            let result = dispatcher
                .receive(path, &client_out[..request_len], &mut server_out)
                .unwrap_or_else(|error| panic!("sequence={sequence} server receive: {error:?}"));
            let response = result
                .or_else(|| dispatcher.poll_for(path, &mut server_out).unwrap())
                .expect("catalog stream response");
            let control = client
                .receive(&server_out[..response], &mut client_out)
                .unwrap();
            if let Some(control_len) = control {
                if let Some(server_control_len) = dispatcher
                    .receive(path, &client_out[..control_len], &mut server_out)
                    .unwrap()
                {
                    let _ = client
                        .receive(&server_out[..server_control_len], &mut client_out)
                        .unwrap();
                }
            }
            if !client.is_complete() {
                let delayed = dispatcher
                    .poll_for(path, &mut server_out)
                    .unwrap()
                    .expect("catalog response is queued after ACK");
                let _ = client
                    .receive(&server_out[..delayed], &mut client_out)
                    .unwrap();
            }
            assert!(client.is_complete(), "sequence={sequence}");
        }
        assert_eq!(client.response(), Some(b"tagged-response".as_slice()));
        let status = dispatcher.active_connection_status().unwrap();
        assert_eq!(status.peer_cid, client_cid);
        assert_eq!(status.streams.peer_initiated.total, 16);
        assert_eq!(status.streams.locally_initiated.total, 16);
    }

    #[test]
    fn one_association_serves_uart_now_and_udp_streams() {
        // This is the host adapter matrix: a bearer supplies only a complete
        // frame and an opaque path.  The same OPEN and tagged STREAM frames
        // must be accepted on UART, NOW, and UDP without replacing the QUIC
        // association or giving an adapter its own CID/stream state.
        const COMPONENT: u64 = 60_006;
        assert!(crate::services::register_tagged_component(
            COMPONENT,
            raw_tagged_test_handler
        ));
        let first = [0xa3, 1, 0x1a, 0, 0, 0xea, 0x66, 2, 1, 3, 1];
        let second = [0xa3, 1, 0x1a, 0, 0, 0xea, 0x66, 2, 1, 3, 2];
        let uart_path = PathId::new(0x6201).unwrap();
        let now_path = PathId::new(0x6202).unwrap();
        let udp_path = PathId::new(0x6203).unwrap();
        let client_cid = ConnectionId::new(0x16c).unwrap();
        let mut client = TaggedClient::<4, 1200>::new(client_cid, &first).unwrap();
        client.set_close_when_complete(false);
        let mut dispatcher = ConnectionDispatcher::<4, 1200>::new(
            ConnectionId::new(0x17c).unwrap(),
            ConnectionLimits::default(),
            AssociationProfile::c6_default(),
        );
        let mut client_out = [0u8; 1200];
        let mut server_out = [0u8; 1200];

        // Bootstrap on UART, then inject the first normal stream through NOW.
        let open_len = client.start(&mut client_out).unwrap();
        let ack_len = dispatcher
            .receive(uart_path, &client_out[..open_len], &mut server_out)
            .unwrap()
            .expect("UART admits the association");
        let first_len = client
            .receive(&server_out[..ack_len], &mut client_out)
            .unwrap()
            .expect("OPEN_ACK produces first tagged request");
        let first_response = dispatcher
            .receive(now_path, &client_out[..first_len], &mut server_out)
            .unwrap()
            .expect("NOW delivers the first normal stream");
        let first_control = client
            .receive(&server_out[..first_response], &mut client_out)
            .unwrap();
        if let Some(control_len) = first_control {
            let _ = dispatcher
                .receive(now_path, &client_out[..control_len], &mut server_out)
                .unwrap();
        }
        assert!(client.is_complete());
        assert_eq!(client.response(), Some(b"tagged-response".as_slice()));

        // A later bidirectional stream moves to UDP while retaining exactly
        // the same association CIDs and completed-stream history.
        let second_len = client.begin_request(8, &second, &mut client_out).unwrap();
        let second_response = dispatcher
            .receive(udp_path, &client_out[..second_len], &mut server_out)
            .unwrap()
            .or_else(|| dispatcher.poll_for(udp_path, &mut server_out).unwrap())
            .expect("UDP delivers the later normal stream");
        let second_control = client
            .receive(&server_out[..second_response], &mut client_out)
            .unwrap();
        if let Some(control_len) = second_control {
            let _ = dispatcher
                .receive(udp_path, &client_out[..control_len], &mut server_out)
                .unwrap();
        }
        if !client.is_complete() {
            let delayed = dispatcher
                .poll_for(udp_path, &mut server_out)
                .unwrap()
                .expect("UDP queues a delayed response after ACK");
            let _ = client
                .receive(&server_out[..delayed], &mut client_out)
                .unwrap();
        }
        assert!(client.is_complete());
        assert_eq!(client.response(), Some(b"tagged-response".as_slice()));

        let status = dispatcher.active_connection_status().unwrap();
        assert_eq!(status.peer_cid, client_cid);
        assert_eq!(status.active_path, Some(udp_path));
        assert_eq!(status.known_paths[0], Some(udp_path));
        assert_eq!(status.known_paths[1], Some(now_path));
        assert_eq!(status.known_paths[2], Some(uart_path));
        assert_eq!(status.streams.peer_initiated.total, 2);
        assert_eq!(status.streams.peer_initiated.active, 0);
        assert_eq!(status.streams.locally_initiated.total, 2);
        assert_eq!(status.streams.locally_initiated.active, 0);
    }

    #[test]
    fn association_status_reports_cids_streams_paths_and_last_close() {
        const COMPONENT: u64 = 60_004;
        assert!(crate::services::register_tagged_component(
            COMPONENT,
            raw_tagged_test_handler
        ));
        let request = [0xa3, 1, 0x1a, 0, 0, 0xea, 0x64, 2, 1, 3, 10];
        let uart_path = PathId::new(0x6101).unwrap();
        let udp_path = PathId::new(0x6102).unwrap();
        let client_cid = ConnectionId::new(0x16a).unwrap();
        let mut client = TaggedClient::<4, 1200>::new(client_cid, &request).unwrap();
        let mut dispatcher = ConnectionDispatcher::<4, 1200>::new(
            ConnectionId::new(0x17a).unwrap(),
            ConnectionLimits::default(),
            AssociationProfile::c6_default(),
        );
        let mut client_out = [0u8; 1200];
        let mut server_out = [0u8; 1200];

        dispatcher.set_time(100);
        let open_len = client.start(&mut client_out).unwrap();
        let ack_len = dispatcher
            .receive(uart_path, &client_out[..open_len], &mut server_out)
            .unwrap()
            .unwrap();
        let request_len = client
            .receive(&server_out[..ack_len], &mut client_out)
            .unwrap()
            .unwrap();
        dispatcher.set_time(200);
        let response_len = dispatcher
            .receive(udp_path, &client_out[..request_len], &mut server_out)
            .unwrap()
            .unwrap();
        let status = dispatcher.active_connection_status().unwrap();
        assert_eq!(status.peer_cid, client_cid);
        assert_eq!(status.active_path, Some(udp_path));
        assert_eq!(status.known_paths[0], Some(udp_path));
        assert_eq!(status.known_paths[1], Some(uart_path));
        assert_eq!(status.streams.peer_initiated.total, 1);
        assert_eq!(status.streams.peer_initiated.active, 0);
        assert_eq!(status.streams.locally_initiated.total, 1);
        assert_eq!(status.streams.locally_initiated.active, 0);

        let _ = client
            .receive(&server_out[..response_len], &mut client_out)
            .unwrap();
        let close_len = client.poll_close(&mut client_out).unwrap().unwrap();
        dispatcher.set_time(300);
        assert!(
            dispatcher
                .receive(udp_path, &client_out[..close_len], &mut server_out)
                .unwrap()
                .is_some()
        );
        assert!(dispatcher.active_connection_status().is_none());
        assert_eq!(dispatcher.last_close_at(), Some(300));
        assert_eq!(
            dispatcher.last_closed_receive_cid(),
            Some(ConnectionId::new(0x17a).unwrap())
        );
    }

    #[test]
    fn tagged_driver_flushes_close_and_releases_peer_association() {
        const COMPONENT: u64 = 60_003;
        assert!(crate::services::register_tagged_component(
            COMPONENT,
            raw_tagged_test_handler
        ));
        let request = [0xa3, 1, 0x1a, 0, 0, 0xea, 0x63, 2, 1, 3, 9];
        let path = PathId::new(0x6003).unwrap();
        let mut client =
            TaggedClient::<4, 1200>::new(ConnectionId::new(0x169).unwrap(), &request).unwrap();
        let mut driver = DatagramClientDriver::start(&mut client, 0).unwrap();
        let mut dispatcher = ConnectionDispatcher::<4, 1200>::new(
            ConnectionId::new(0x179).unwrap(),
            ConnectionLimits::default(),
            AssociationProfile::c6_default(),
        );
        let mut server_out = [0u8; 1200];

        let open = driver.packet().unwrap().to_vec();
        driver.mark_sent(0);
        let open_ack_len = dispatcher
            .receive(path, &open, &mut server_out)
            .unwrap()
            .unwrap();
        driver
            .receive(&mut client, &server_out[..open_ack_len], 1)
            .unwrap();
        driver.poll(&mut client, 1, 100, 400).unwrap();
        let request_packet = driver.packet().unwrap().to_vec();
        driver.mark_sent(1);
        let response_len = dispatcher
            .receive(path, &request_packet, &mut server_out)
            .unwrap()
            .unwrap();
        driver
            .receive(&mut client, &server_out[..response_len], 2)
            .unwrap();

        assert!(client.is_complete());
        let close = driver
            .packet()
            .expect("completed tagged client queues CLOSE")
            .to_vec();
        driver.mark_sent(2);
        let _ = dispatcher.receive(path, &close, &mut server_out).unwrap();
        assert!(dispatcher.core.association().is_none());
    }

    #[test]
    fn status_test_client_reacks_a_retransmitted_final_response() {
        let client_cid = ConnectionId::new(0xa6).unwrap();
        let server_cid = ConnectionId::new(0xb7).unwrap();
        let mut client = status_test_client(client_cid, 0x3456);
        let mut server = ConnectionServer::<4, 1200>::new(server_cid);
        let mut client_out = [0u8; 1200];
        let mut server_out = [0u8; 1200];
        let open_len = client.start(&mut client_out).unwrap();
        let open_ack_len = server
            .receive(&client_out[..open_len], &mut server_out)
            .unwrap()
            .unwrap();
        let request_len = client
            .receive(&server_out[..open_ack_len], &mut client_out)
            .unwrap()
            .unwrap();
        let response_len = server
            .receive(&client_out[..request_len], &mut server_out)
            .unwrap()
            .unwrap();
        let _ = client
            .receive(&server_out[..response_len], &mut client_out)
            .unwrap();
        assert!(client.is_complete());
        // A peer can repeat its packet before seeing the delayed ACK. This is
        // still a valid response, not an invalid second service result.
        let _ = client
            .receive(&server_out[..response_len], &mut client_out)
            .unwrap();
        assert_eq!(client.counters().stream_packets, 1);
        assert_eq!(client.counters().other_packets, 1);
    }

    #[test]
    fn probe_server_accepts_retransmitted_service_request_while_streaming() {
        let client_cid = ConnectionId::new(0xd6).unwrap();
        let server_cid = ConnectionId::new(0xe7).unwrap();
        let mut client = ProbeClient::<8, 1200>::new(client_cid, 2048).unwrap();
        let mut server = ConnectionServer::<8, 1200>::new(server_cid);
        let mut client_out = [0u8; 1200];
        let mut server_out = [0u8; 1200];
        let open_len = client.start(&mut client_out).unwrap();
        let open_ack_len = server
            .receive(&client_out[..open_len], &mut server_out)
            .unwrap()
            .unwrap();
        let request_len = client
            .receive(&server_out[..open_ack_len], &mut client_out)
            .unwrap()
            .unwrap();
        let first_response = server
            .receive(&client_out[..request_len], &mut server_out)
            .unwrap()
            .unwrap();
        // The request packet may be retransmitted when its first response is
        // lost. It must not invalidate the already-active PROBE producer.
        assert!(
            server
                .receive(&client_out[..request_len], &mut server_out)
                .is_ok()
        );
        assert!(first_response > 0);
    }

    #[test]
    fn completed_probe_request_duplicate_does_not_start_another_stream() {
        // A no-ACK action link can lose the final response and retransmit the
        // original request after the bounded producer has emitted FIN. The
        // association must remain idempotent until CLOSE/new OPEN, otherwise
        // the duplicate creates a second server stream and overfills a small
        // firmware ingress pool.
        let client_cid = ConnectionId::new(0xd8).unwrap();
        let server_cid = ConnectionId::new(0xe9).unwrap();
        let mut client = ProbeClient::<4, 1200>::new_with_packet_size(client_cid, 8, 8).unwrap();
        let mut server = ConnectionServer::<4, 1200>::new(server_cid);
        let mut client_out = [0u8; 1200];
        let mut server_out = [0u8; 1200];
        let open_len = client.start(&mut client_out).unwrap();
        let open_ack_len = server
            .receive(&client_out[..open_len], &mut server_out)
            .unwrap()
            .unwrap();
        let request_len = client
            .receive(&server_out[..open_ack_len], &mut client_out)
            .unwrap()
            .unwrap();
        assert!(
            server
                .receive(&client_out[..request_len], &mut server_out)
                .unwrap()
                .is_some()
        );
        assert_eq!(
            server
                .receive(&client_out[..request_len], &mut server_out)
                .unwrap(),
            None
        );
    }

    #[test]
    fn status_test_client_ignores_a_retransmitted_bootstrap_ack() {
        let client_cid = ConnectionId::new(0xc6).unwrap();
        let server_cid = ConnectionId::new(0xd7).unwrap();
        let mut client = status_test_client(client_cid, 0x5678);
        let mut server = ConnectionServer::<4, 1200>::new(server_cid);
        let mut client_out = [0u8; 1200];
        let mut server_out = [0u8; 1200];
        let open_len = client.start(&mut client_out).unwrap();
        let open_ack_len = server
            .receive(&client_out[..open_len], &mut server_out)
            .unwrap()
            .unwrap();
        let request_len = client
            .receive(&server_out[..open_ack_len], &mut client_out)
            .unwrap()
            .unwrap();
        // The peer did not yet observe the request, so it may repeat the
        // bootstrap response. This must not become a raw-client callback
        // error or replace the request packet.
        assert_eq!(
            client
                .receive(&server_out[..open_ack_len], &mut client_out)
                .unwrap(),
            None
        );
        assert_eq!(client.counters().bootstrap_acks, 2);
        let response_len = server
            .receive(&client_out[..request_len], &mut server_out)
            .unwrap()
            .unwrap();
        let _ = client
            .receive(&server_out[..response_len], &mut client_out)
            .unwrap();
        assert!(client.is_complete());
        let close_len = client
            .poll_close(&mut client_out)
            .unwrap()
            .expect("a completed test echo retains its terminal CLOSE");
        assert!(close_len > 0);
    }

    #[test]
    fn application_server_does_not_replace_its_connection_owner() {
        let first_cid = ConnectionId::new(0xc8).unwrap();
        let second_cid = ConnectionId::new(0xc9).unwrap();
        let server_cid = ConnectionId::new(0xd9).unwrap();
        let mut first = status_test_client(first_cid, 1);
        let mut second = status_test_client(second_cid, 2);
        let mut server = ConnectionServer::<4, 1200>::new(server_cid);
        let mut first_out = [0u8; 1200];
        let mut second_out = [0u8; 1200];
        let mut server_out = [0u8; 1200];

        let first_open = first.start(&mut first_out).unwrap();
        let first_ack = server
            .receive(&first_out[..first_open], &mut server_out)
            .unwrap()
            .unwrap();
        let (_, first_bootstrap) = quic_lite::decode_bootstrap_open_ack_packet_with_limits(
            &server_out[..first_ack],
            first_cid,
        )
        .unwrap();
        let first_request = first
            .receive(&server_out[..first_ack], &mut first_out)
            .unwrap()
            .unwrap();

        let second_open = second.start(&mut second_out).unwrap();
        assert_eq!(
            server.receive(&second_out[..second_open], &mut server_out),
            Err(Error::BootstrapInvalid),
            "only the shared connection owner may replace an association"
        );
        assert_eq!(
            server.expected_receive_cid(),
            Some(first_bootstrap.server_receive_cid)
        );
        assert!(
            server
                .receive(&first_out[..first_request], &mut server_out)
                .is_ok()
        );
    }

    #[test]
    fn status_test_recovers_a_lost_action_response_from_the_shared_ledger() {
        let client_cid = ConnectionId::new(0x86).unwrap();
        let server_cid = ConnectionId::new(0x97).unwrap();
        let path = PathId::new(0x0207).unwrap();
        let mut client = status_test_client(client_cid, 0x2345);
        let mut server = ConnectionDispatcher::<4, 1200>::new(
            server_cid,
            ConnectionLimits::default(),
            AssociationProfile::c6_default(),
        );
        let mut client_out = [0u8; 1200];
        let mut server_out = [0u8; 1200];

        let open_len = client.start(&mut client_out).unwrap();
        let open_ack_len = server
            .receive(path, &client_out[..open_len], &mut server_out)
            .unwrap()
            .unwrap();
        let request_len = client
            .receive(&server_out[..open_ack_len], &mut client_out)
            .unwrap()
            .unwrap();
        // The first service response is deliberately lost, as can happen on
        // a no-ACK raw action bearer after the driver accepted TX.
        let _lost_response = server
            .receive(path, &client_out[..request_len], &mut server_out)
            .unwrap()
            .unwrap();

        let retry_len = client
            .poll_retransmit(600_000, 600_000, &mut client_out)
            .unwrap()
            .expect("client retransmits its outstanding request");
        let _ = server
            .receive(path, &client_out[..retry_len], &mut server_out)
            .unwrap();
        let response_len = server
            .poll_retransmit_for(path, 600_000, 600_000, &mut server_out)
            .unwrap()
            .expect("server retransmits its response from the endpoint ledger");
        let _ = client
            .receive(&server_out[..response_len], &mut client_out)
            .unwrap();
        assert!(client.is_complete());
    }

    #[test]
    fn dispatcher_releases_closed_udp_association_for_fresh_bootstrap() {
        let server_cid = ConnectionId::new(0x9876).unwrap();
        let first_cid = ConnectionId::new(0x9877).unwrap();
        let second_cid = ConnectionId::new(0x9878).unwrap();
        let path = PathId::new(0x0108).unwrap();
        let mut dispatcher = ConnectionDispatcher::<8, 1200>::new(
            server_cid,
            ConnectionLimits::default(),
            AssociationProfile::c6_default(),
        );
        let mut first = ProbeClient::<8, 1200>::new(first_cid, 1024).unwrap();
        let mut second = ProbeClient::<8, 1200>::new(second_cid, 1024).unwrap();
        let mut client_out = [0u8; 1200];
        let mut server_out = [0u8; 1200];

        let open_len = first.start(&mut client_out).unwrap();
        let open_ack_len = dispatcher
            .receive(path, &client_out[..open_len], &mut server_out)
            .unwrap()
            .unwrap();
        let (_, first_ack) = quic_lite::decode_bootstrap_open_ack_packet_with_limits(
            &server_out[..open_ack_len],
            first_cid,
        )
        .unwrap();
        let request_len = first
            .receive(&server_out[..open_ack_len], &mut client_out)
            .unwrap()
            .unwrap();
        let _ = dispatcher
            .receive(path, &client_out[..request_len], &mut server_out)
            .unwrap();

        let endpoint = first.connection.endpoint_mut().unwrap();
        endpoint.close(0);
        let close_len = endpoint.poll_close(&mut client_out).unwrap().unwrap();
        let _ = dispatcher
            .receive(path, &client_out[..close_len], &mut server_out)
            .unwrap();
        assert!(
            dispatcher.core.association().is_none(),
            "CLOSE must release stale ledger"
        );

        let new_open_len = second.start(&mut client_out).unwrap();
        let new_ack_len = dispatcher
            .receive(path, &client_out[..new_open_len], &mut server_out)
            .unwrap()
            .expect("fresh CID must bootstrap immediately after CLOSE");
        let (_, second_ack) = quic_lite::decode_bootstrap_open_ack_packet_with_limits(
            &server_out[..new_ack_len],
            second_cid,
        )
        .unwrap();
        assert_ne!(
            first_ack.server_receive_cid, second_ack.server_receive_cid,
            "a closed raw association must not reuse its receive CID"
        );
    }

    #[test]
    fn dispatcher_replaces_stale_open_from_a_new_path_and_migrates_valid_packets() {
        let mut dispatcher = ConnectionDispatcher::<8, 1200>::new(
            ConnectionId::new(0x9910).unwrap(),
            ConnectionLimits::default(),
            AssociationProfile::conservative(),
        );
        let first_path = PathId::new(0x0201).unwrap();
        let foreign_path = PathId::new(0x0202).unwrap();
        let mut first =
            ProbeClient::<8, 1200>::new(ConnectionId::new(0x9911).unwrap(), 64).unwrap();
        let mut foreign =
            ProbeClient::<8, 1200>::new(ConnectionId::new(0x9912).unwrap(), 64).unwrap();
        let mut client_out = [0u8; 1200];
        let mut server_out = [0u8; 1200];

        let first_open = first.start(&mut client_out).unwrap();
        let first_ack = dispatcher
            .receive(first_path, &client_out[..first_open], &mut server_out)
            .unwrap()
            .expect("first peer OPEN_ACK");
        let first_request = first
            .receive(&server_out[..first_ack], &mut client_out)
            .unwrap()
            .expect("first peer request");
        let mut first_request_packet = [0u8; 1200];
        first_request_packet[..first_request].copy_from_slice(&client_out[..first_request]);

        let foreign_open = foreign.start(&mut client_out).unwrap();
        let foreign_ack = dispatcher
            .receive(foreign_path, &client_out[..foreign_open], &mut server_out)
            .unwrap()
            .expect("a fresh long-header OPEN must reclaim a stale association");
        let (_, foreign_open_ack) = quic_lite::decode_bootstrap_open_ack_packet_with_limits(
            &server_out[..foreign_ack],
            ConnectionId::new(0x9912).unwrap(),
        )
        .unwrap();
        assert_ne!(
            foreign_open_ack.server_receive_cid,
            ConnectionId::new(0x9910).unwrap(),
            "reclaimed association must rotate its server CID"
        );
        assert_eq!(dispatcher.reply_path(), Some(foreign_path));
        assert_eq!(dispatcher.core.active_path(), Some(foreign_path));

        assert!(
            dispatcher
                .receive(
                    first_path,
                    &first_request_packet[..first_request],
                    &mut server_out,
                )
                .is_err(),
            "old established packets must not enter the replacement association"
        );

        let foreign_request = foreign
            .receive(&server_out[..foreign_ack], &mut client_out)
            .unwrap()
            .expect("replacement peer request");

        assert!(
            dispatcher
                .receive(first_path, &client_out[..foreign_request], &mut server_out,)
                .unwrap()
                .is_some(),
            "a correctly addressed connection packet may migrate bearers"
        );
        assert_eq!(dispatcher.reply_path(), Some(first_path));
        assert_eq!(dispatcher.core.active_path(), Some(first_path));
    }

    #[test]
    fn multi_association_dispatcher_keeps_two_firmware_peers_live() {
        let first_path = PathId::new(0x5101).unwrap();
        // Two independent UDP clients can share the same peer tuple when the
        // host falls back to an ephemeral local port. The path is therefore
        // deliberately identical; only each association's CID is unique.
        let second_path = first_path;
        let mut dispatcher = ConnectionDispatcher::<4, 1200, 2>::new(
            ConnectionId::new(0x5100).unwrap(),
            ConnectionLimits::default(),
            AssociationProfile::c6_default(),
        );
        let mut first = status_test_client(ConnectionId::new(0x5111).unwrap(), 1);
        let mut second = status_test_client(ConnectionId::new(0x5112).unwrap(), 2);
        let mut first_out = [0u8; 1200];
        let mut second_out = [0u8; 1200];
        let mut server_out = [0u8; 1200];

        let first_open = first.start(&mut first_out).unwrap();
        let first_ack = dispatcher
            .receive(first_path, &first_out[..first_open], &mut server_out)
            .unwrap()
            .unwrap();
        let (_, first_open_ack) = quic_lite::decode_bootstrap_open_ack_packet_with_limits(
            &server_out[..first_ack],
            ConnectionId::new(0x5111).unwrap(),
        )
        .unwrap();
        let first_request = first
            .receive(&server_out[..first_ack], &mut first_out)
            .unwrap()
            .unwrap();

        let second_open = second.start(&mut second_out).unwrap();
        let second_ack = dispatcher
            .receive(second_path, &second_out[..second_open], &mut server_out)
            .unwrap()
            .unwrap();
        let (_, second_open_ack) = quic_lite::decode_bootstrap_open_ack_packet_with_limits(
            &server_out[..second_ack],
            ConnectionId::new(0x5112).unwrap(),
        )
        .unwrap();
        let second_request = second
            .receive(&server_out[..second_ack], &mut second_out)
            .unwrap()
            .unwrap();
        assert_eq!(dispatcher.active_association_count(), 2);
        assert_eq!(
            dispatcher.select_receive_cid(first_open_ack.server_receive_cid),
            Some(first_path)
        );
        assert_eq!(
            dispatcher.expected_receive_cid(),
            Some(first_open_ack.server_receive_cid)
        );
        assert_eq!(
            dispatcher.select_receive_cid(second_open_ack.server_receive_cid),
            Some(second_path)
        );

        // The second peer's Initial must not retire the first peer. Both
        // established requests remain routable by their separate server CID.
        assert!(
            dispatcher
                .receive(first_path, &first_out[..first_request], &mut server_out)
                .unwrap()
                .is_some()
        );
        assert!(
            dispatcher
                .receive(second_path, &second_out[..second_request], &mut server_out)
                .unwrap()
                .is_some()
        );
        assert_eq!(dispatcher.active_association_count(), 2);
    }

    #[test]
    fn replacing_association_retires_only_quic_state() {
        let server_cid = ConnectionId::new(0x9981).unwrap();
        let client_cid = ConnectionId::new(0x9982).unwrap();
        let path = PathId::new(0x0209).unwrap();
        let mut dispatcher = ConnectionDispatcher::<8, 1200>::new(
            server_cid,
            ConnectionLimits::default(),
            AssociationProfile::c6_default(),
        );
        let mut client = ProbeClient::<8, 1200>::new(client_cid, 64).unwrap();
        let mut client_out = [0u8; 1200];
        let mut server_out = [0u8; 1200];
        let open_len = client.start(&mut client_out).unwrap();
        dispatcher
            .receive(path, &client_out[..open_len], &mut server_out)
            .unwrap();
        assert!(dispatcher.core.association().is_some());
        assert_eq!(dispatcher.reply_path(), Some(path));

        let association = AssociationProfile {
            tx_burst_packets: 1,
            ..AssociationProfile::c6_default()
        };
        dispatcher.replace_association(association);
        assert_eq!(dispatcher.tx_burst_packets(), 1);
        assert!(dispatcher.core.association().is_none());
        assert_eq!(dispatcher.reply_path(), None);
    }

    #[test]
    fn bearer_profile_change_preserves_live_connection_for_path_migration() {
        let server_cid = ConnectionId::new(0x99a1).unwrap();
        let client_cid = ConnectionId::new(0x99a2).unwrap();
        let uart_path = PathId::new(0x0301).unwrap();
        let udp_path = PathId::new(0x0302).unwrap();
        let mut dispatcher = ConnectionDispatcher::<8, 1200>::new(
            server_cid,
            ConnectionLimits::default(),
            AssociationProfile::c6_default(),
        );
        let mut client = ProbeClient::<8, 1200>::new(client_cid, 64).unwrap();
        let mut client_out = [0u8; 1200];
        let mut server_out = [0u8; 1200];

        let open_len = client.start(&mut client_out).unwrap();
        let ack_len = dispatcher
            .receive(uart_path, &client_out[..open_len], &mut server_out)
            .unwrap()
            .unwrap();
        let request_len = client
            .receive(&server_out[..ack_len], &mut client_out)
            .unwrap()
            .unwrap();

        dispatcher.set_association_defaults(AssociationProfile {
            tx_burst_packets: 1,
            ..AssociationProfile::conservative()
        });
        assert!(dispatcher.core.association().is_some());
        assert_eq!(dispatcher.reply_path(), Some(uart_path));

        dispatcher
            .receive(udp_path, &client_out[..request_len], &mut server_out)
            .unwrap();
        assert_eq!(dispatcher.reply_path(), Some(udp_path));
        assert_eq!(dispatcher.expected_receive_cid(), Some(server_cid));
        assert_eq!(dispatcher.tx_burst_packets(), 1);
    }

    #[test]
    fn resampled_defaults_apply_to_the_next_association_only() {
        let server_cid = ConnectionId::new(0x99b1).unwrap();
        let first_client_cid = ConnectionId::new(0x99b2).unwrap();
        let second_client_cid = ConnectionId::new(0x99b3).unwrap();
        let first_path = PathId::new(0x0311).unwrap();
        let second_path = PathId::new(0x0312).unwrap();
        let original = AssociationProfile::c6_default();
        let resampled = AssociationProfile::conservative();
        let mut dispatcher =
            ConnectionDispatcher::<8, 1200>::new(server_cid, ConnectionLimits::default(), original);
        let mut first = ProbeClient::<8, 1200>::new(first_client_cid, 64).unwrap();
        let mut second = ProbeClient::<8, 1200>::new(second_client_cid, 64).unwrap();
        let mut client_out = [0u8; 1200];
        let mut server_out = [0u8; 1200];

        let first_open = first.start(&mut client_out).unwrap();
        dispatcher
            .receive(first_path, &client_out[..first_open], &mut server_out)
            .unwrap();
        assert_eq!(dispatcher.active_association_profile(), Some(original));

        // Platform code may refresh its allocator sample after driver setup.
        // The current CID must keep its OPEN_ACK contract unchanged.
        dispatcher.set_association_defaults(resampled);
        assert_eq!(dispatcher.active_association_profile(), Some(original));

        // Retire the first logical peer, then admit a distinct OPEN. This is
        // the same boundary used by the ESP adapter before it refreshes the
        // dynamic callback-frame budget for a newly admitted association.
        dispatcher.replace_association(resampled);
        let second_open = second.start(&mut client_out).unwrap();
        dispatcher
            .receive(second_path, &client_out[..second_open], &mut server_out)
            .unwrap();
        assert_eq!(dispatcher.active_association_profile(), Some(resampled));
    }

    #[test]
    fn conservative_action_profile_completes_16k_in_256_byte_packets() {
        // This is the exact packet-at-a-time association used by the raw
        // ESP-NOW-compatible adapter. It deliberately contains no radio,
        // task, or timer dependency: a failure here would be a shared
        // protocol/ledger problem, while an on-air timeout is adapter/RF
        // evidence to investigate separately.
        let client_cid = ConnectionId::new(0x46).unwrap();
        let server_cid = ConnectionId::new(0x56).unwrap();
        let mut client =
            ProbeClient::<4, 1200>::new_with_packet_size(client_cid, 16 * 1024, 256).unwrap();
        let mut server = ConnectionServer::<4, 1200>::new_with_association(
            server_cid,
            ConnectionLimits::default(),
            AssociationProfile::conservative(),
        );
        let mut client_out = [0u8; 1200];
        let mut server_out = [0u8; 1200];

        let open_len = client.start(&mut client_out).unwrap();
        let open_ack_len = server
            .receive(&client_out[..open_len], &mut server_out)
            .unwrap()
            .unwrap();
        let request_len = client
            .receive(&server_out[..open_ack_len], &mut client_out)
            .unwrap()
            .unwrap();
        let mut server_len = server
            .receive(&client_out[..request_len], &mut server_out)
            .unwrap()
            .unwrap();

        for _ in 0..512 {
            let client_len = client
                .receive(&server_out[..server_len], &mut client_out)
                .unwrap();
            if client.is_complete() {
                break;
            }
            let client_len = client_len.expect("stream packet must produce an ACK");
            server_len = server
                .receive(&client_out[..client_len], &mut server_out)
                .unwrap()
                .unwrap();
        }
        assert!(client.is_complete());
        assert_eq!(client.bytes(), 16 * 1024);
        assert_eq!(client.callback_errors(), [0; 6]);
    }

    #[test]
    fn probe_recovers_through_bounded_callback_handoff_and_rejected_egress() {
        // This is the host counterpart of the ESP raw-UDP adapter boundary:
        // an eight-slot packet pool reserves two slots for an admitted reply,
        // leaving six callback-to-worker ingress slots. The worker consumes
        // one packet per turn, while the physical egress occasionally rejects
        // submission. Neither condition is exposed to the probe handler.
        let client_cid = ConnectionId::new(0x470).unwrap();
        let server_cid = ConnectionId::new(0x570).unwrap();
        let mut client = ProbeClient::<16, 1200>::from_request(
            client_cid,
            crate::probe::ProbeServiceRequest {
                // Match the classic Recovery artifact scale. A short probe
                // can survive one callback-pool overflow while hiding a
                // cumulative loss-recovery stall near a real image length.
                bytes: 800 * 1024,
                packet_size: 512,
                ack_frequency: None,
                ack_delay_ms: None,
                low_priority_bytes: None,
                high_priority_bytes: None,
                parallel_streams: None,
                // Exercise a storage-like consumer barrier through the same
                // handler-neutral stream consumption API used by flash.
                initial_consume_delay_ms: Some(100),
                consume_delay_ms: Some(10),
            },
        )
        .unwrap();
        let mut client_driver = quic_lite::DatagramClientDriver::start(&mut client, 0).unwrap();
        // Match a C6 Recovery boot with heap selecting a 20-packet ledger.
        // Bootstrap uses the platform's tiny always-present callback scratch;
        // after OPEN admission the callback handoff grows to this selected
        // association capacity and is released with the association. The host
        // must exercise that lifecycle rather than a permanently reserved
        // flash-sized pool.
        let recovery_association = AssociationProfile {
            history_packets: 20,
            ack_frequency: AssociationProfile::datagram_default().ack_frequency,
            ack_delay_ms: AssociationProfile::datagram_default().ack_delay_ms,
            tx_burst_packets: 20,
            initial_window_packets: 20,
        }
        .clamp::<32>();
        let mut server = ConnectionServer::<32, 1200>::new_with_association(
            server_cid,
            recovery_association.receive_limits(1100, 4),
            recovery_association,
        );
        let mut server_packet = [0u8; 1200];
        let mut egress = quic_lite::connection::DatagramEgressDriver::<PathId, 1200>::new();
        let path = PathId::new(1).unwrap();
        let mut callback_queue = std::collections::VecDeque::new();
        let mut callback_drops = 0usize;
        let callback_capacity = recovery_association.initial_window_packets;
        let mut to_client: std::collections::VecDeque<Vec<u8>> = std::collections::VecDeque::new();
        let mut rejected_submissions = 3usize;

        // Bootstrap is handled before the constrained steady-state queue,
        // matching the adapter's already-running association handshake.
        let initial = client_driver.packet().unwrap().to_vec();
        client_driver.mark_sent(0);
        let open_ack = server
            .receive(&initial, &mut server_packet)
            .unwrap()
            .unwrap();
        client_driver
            .receive(&mut client, &server_packet[..open_ack], 1)
            .unwrap();

        for now in 2..120_000 {
            // A writable bearer can accept a burst before the worker next
            // runs. Generate up to four ordinary client packets at this same
            // clock value; only callback admission is bounded.
            for _ in 0..4 {
                let Some(packet) = client_driver.packet().map(ToOwned::to_owned) else {
                    break;
                };
                client_driver.mark_sent(now);
                // One duplicated Wi-Fi callback burst is enough to fill the
                // dynamically selected association handoff. It is still an ordinary identical
                // QUIC datagram: the server's packet-number handling, not a
                // probe/flash retry hook, decides its effect.
                // Keep exercising full callback bursts throughout the image,
                // rather than proving recovery from only one early loss. The
                // device reports cumulative callback drops on a busy STA.
                let copies = (client.packet_classes().1 >= 2 && now % 17 == 0)
                    .then_some(8)
                    .unwrap_or(1);
                for _ in 0..copies {
                    if callback_queue.len() < callback_capacity {
                        callback_queue.push_back(packet.clone());
                    } else {
                        callback_drops += 1;
                    }
                }
                client_driver.poll(&mut client, now, 600, 400).unwrap();
            }

            // The worker drains the currently queued burst before blocking
            // again. A one-tick sleep after each callback frame is an ESP
            // adapter bug: it turns a normal Wi-Fi burst into a full queue.
            while let Some(packet) = callback_queue.pop_front() {
                let first = server.receive(&packet, &mut server_packet).unwrap();
                let _ = egress
                    .drain(
                        path,
                        &mut server_packet,
                        16,
                        first,
                        |packet| server.poll(packet),
                        |_, packet| {
                            if rejected_submissions != 0 {
                                rejected_submissions -= 1;
                                false
                            } else {
                                to_client.push_back(packet.to_vec());
                                true
                            }
                        },
                    )
                    .unwrap();
            }

            // A quiet/flow-blocked sender does not own the responder clock.
            // Service the same common poll turn while its retained egress
            // packet is retried first by DatagramEgressDriver.
            let _ = egress
                .drain(
                    path,
                    &mut server_packet,
                    16,
                    None,
                    |packet| server.poll(packet),
                    |_, packet| {
                        if rejected_submissions != 0 {
                            rejected_submissions -= 1;
                            false
                        } else {
                            to_client.push_back(packet.to_vec());
                            true
                        }
                    },
                )
                .unwrap();

            if let Some(packet) = to_client.pop_front() {
                client_driver.receive(&mut client, &packet, now).unwrap();
            }
            client_driver.poll(&mut client, now, 600, 400).unwrap();
            if client.is_complete() {
                break;
            }
        }
        assert_eq!(
            callback_drops, 0,
            "association-sized handoff must absorb its advertised flight"
        );
        assert_eq!(rejected_submissions, 0);
        assert!(
            client.is_complete(),
            "probe stalled queue={}",
            callback_queue.len()
        );
        assert_eq!(client.bytes(), 800 * 1024);
        assert_eq!(client.callback_errors(), [0; 6]);
    }

    #[test]
    fn client_preserves_requested_radio_packet_size() {
        let client = ProbeClient::<4, 1200>::new_with_packet_size(
            ConnectionId::new(0x44).unwrap(),
            1024,
            256,
        )
        .unwrap();
        let (_, request) = crate::probe::decode_probe_run_record(
            crate::tagged::decode(&client.request[..client.request_len]).unwrap(),
        )
        .unwrap();
        assert_eq!(request.packet_size, 256);
    }

    #[test]
    fn client_accepts_a_bearer_neutral_size_above_its_current_path_mtu() {
        let client = ProbeClient::<4, 1100>::new_with_packet_size(
            ConnectionId::new(0x46).unwrap(),
            1024,
            1200,
        )
        .unwrap();
        let (_, request) = crate::probe::decode_probe_run_record(
            crate::tagged::decode(&client.request[..client.request_len]).unwrap(),
        )
        .unwrap();
        assert_eq!(request.packet_size, 1200);
    }

    #[test]
    fn client_preserves_complete_probe_request_without_adapter_reinterpretation() {
        let expected = crate::probe::ProbeServiceRequest {
            bytes: 65_536,
            packet_size: 512,
            ack_frequency: None,
            ack_delay_ms: None,
            low_priority_bytes: Some(1_024),
            high_priority_bytes: Some(2_048),
            parallel_streams: Some(3),
            initial_consume_delay_ms: Some(500),
            consume_delay_ms: Some(10),
        };
        let client =
            ProbeClient::<8, 1200>::from_request(ConnectionId::new(0x45).unwrap(), expected)
                .unwrap();
        let (_, request) = crate::probe::decode_probe_run_record(
            crate::tagged::decode(&client.request[..client.request_len]).unwrap(),
        )
        .unwrap();
        assert_eq!(request, expected);
    }

    #[test]
    fn object_upload_initial_is_accepted_by_conservative_recovery_dispatcher() {
        let client_cid = ConnectionId::new(0x881).unwrap();
        let server_cid = ConnectionId::new(0x882).unwrap();
        let mut client = ObjectUploadClient::<8, 1200>::new(
            client_cid,
            &[0xa0],
            ObjectRecordStream::new(Vec::new()),
        )
        .unwrap();
        let driver = quic_lite::DatagramClientDriver::start(&mut client, 0).unwrap();
        let initial = driver.packet().unwrap();
        let mut dispatcher = ConnectionDispatcher::<8, 1200>::new(
            server_cid,
            ConnectionLimits::with_receive_window(1200),
            AssociationProfile::conservative(),
        );
        let mut response = [0_u8; 1200];
        assert!(
            dispatcher
                .receive(PathId::new(1).unwrap(), initial, &mut response)
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn object_upload_initial_is_accepted_by_recovery_sta_dispatcher() {
        let client_cid = ConnectionId::new(0x885).unwrap();
        let server_cid = ConnectionId::new(0x886).unwrap();
        let mut client = ObjectUploadClient::<512, { quic_lite::DEFAULT_MAX_DATAGRAM_SIZE }>::new(
            client_cid,
            &[0xa0],
            ObjectRecordStream::new(Vec::new()),
        )
        .unwrap();
        let driver = quic_lite::DatagramClientDriver::start(&mut client, 0).unwrap();
        let initial = driver.packet().unwrap();
        let mut dispatcher =
            ConnectionDispatcher::<8, { quic_lite::DEFAULT_MAX_DATAGRAM_SIZE }, 12>::new(
                server_cid,
                ConnectionLimits::with_receive_window(quic_lite::DEFAULT_MAX_DATAGRAM_SIZE as u64),
                AssociationProfile::datagram_default(),
            );
        let mut response = [0_u8; quic_lite::DEFAULT_MAX_DATAGRAM_SIZE];
        assert!(
            dispatcher
                .receive(PathId::new(1).unwrap(), initial, &mut response)
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn dispatcher_open_ack_preserves_the_memory_selected_receive_profile() {
        const MTU: usize = quic_lite::DEFAULT_MAX_DATAGRAM_SIZE;
        let client_cid = ConnectionId::new(0x887).unwrap();
        let server_cid = ConnectionId::new(0x888).unwrap();
        let association = AssociationProfile::datagram_default();
        let limits = association.receive_limits(MTU as u64, 4);
        let mut initial = [0_u8; MTU];
        let initial_len =
            quic_lite::encode_bootstrap_open_packet(client_cid, 0, &mut initial).unwrap();
        let mut dispatcher =
            ConnectionDispatcher::<8, MTU, 12>::new(server_cid, limits, association);
        let mut response = [0_u8; MTU];
        let response_len = dispatcher
            .receive(
                PathId::new(1).unwrap(),
                &initial[..initial_len],
                &mut response,
            )
            .unwrap()
            .unwrap();
        let (_, open_ack) = quic_lite::decode_bootstrap_open_ack_packet_with_limits(
            &response[..response_len],
            client_cid,
        )
        .unwrap();
        assert_eq!(open_ack.max_data, 8 * MTU as u64);
        assert_eq!(open_ack.max_stream_data, 4 * MTU as u64);
        assert_eq!(open_ack.max_in_flight_packets, 0);
    }

    #[test]
    fn dispatcher_open_request_exercises_32_and_64_packet_test_profiles() {
        const MTU: usize = quic_lite::DEFAULT_MAX_DATAGRAM_SIZE;
        let server_cid = ConnectionId::new(0x88a).unwrap();
        let base = AssociationProfile::datagram_default();
        for packets in [32_u64, 64] {
            let mut dispatcher = ConnectionDispatcher::<64, MTU, 1>::new(
                server_cid,
                base.receive_limits(MTU as u64, 4),
                base,
            );
            dispatcher.set_receive_profile_ceiling(AssociationProfile {
                history_packets: 64,
                initial_window_packets: 64,
                tx_burst_packets: 8,
                ..base
            });
            let client_cid = ConnectionId::new(0x889 + packets).unwrap();
            let request = quic_lite::ReceiveWindowRequest {
                max_data: packets * MTU as u64,
                max_stream_data: (packets / 2) * MTU as u64,
            };
            let mut initial = [0_u8; MTU];
            let initial_len =
                quic_lite::encode_bootstrap_open_packet_with_profile_and_peer_receive_request(
                    client_cid,
                    0,
                    ConnectionLimits::default(),
                    0,
                    Some(request),
                    &mut initial,
                )
                .unwrap();
            let mut response = [0_u8; MTU];
            let response_len = dispatcher
                .receive(
                    PathId::new(packets).unwrap(),
                    &initial[..initial_len],
                    &mut response,
                )
                .unwrap()
                .unwrap();
            let (_, open_ack) = quic_lite::decode_bootstrap_open_ack_packet_with_limits(
                &response[..response_len],
                client_cid,
            )
            .unwrap();
            assert_eq!(open_ack.max_data, request.max_data, "packets={packets}");
            assert_eq!(
                open_ack.max_stream_data, request.max_stream_data,
                "packets={packets}"
            );
        }
    }

    #[test]
    fn object_upload_reserves_allocated_stream_before_initial_flash_credit() {
        let client_cid = ConnectionId::new(0x883).unwrap();
        let server_cid = ConnectionId::new(0x884).unwrap();
        let request = crate::verified_object::FlashRequest {
            object: GetRequest {
                name: None,
                cpu: 13,
                target: 6,
            },
            address: None,
            transport: 0,
            dry_run: true,
        };
        let mut command = [0_u8; 128];
        let command_len =
            crate::verified_object::encode_flash_handler_request(request, 1, &mut command).unwrap();
        let mut client = ObjectUploadClient::<8, 1200>::new(
            client_cid,
            &command[..command_len],
            ObjectRecordStream::new(Vec::new()),
        )
        .unwrap();
        let mut driver = quic_lite::DatagramClientDriver::start(&mut client, 0).unwrap();
        let mut listener = ConnectionServer::<8, 1200>::new_with_association(
            server_cid,
            ConnectionLimits::with_receive_window(1200),
            AssociationProfile::conservative(),
        );
        let mut response = [0_u8; 1200];
        let open_ack = listener
            .receive(driver.packet().unwrap(), &mut response)
            .unwrap()
            .unwrap();
        driver.mark_sent(0);
        driver
            .receive(&mut client, &response[..open_ack], 1)
            .unwrap();
        let command_packet = driver.packet().unwrap().to_vec();
        driver.mark_sent(1);
        assert_eq!(
            listener.receive(&command_packet, &mut response).unwrap(),
            None
        );
        assert!(listener.take_stream_command().is_some());
        // This unit exercises ConnectionServer directly, below the public
        // dispatcher adapter used by applications.
        listener.prepare_inbound_stream().unwrap();
        let credit = listener.poll(&mut response).unwrap().unwrap();
        assert!(driver.receive(&mut client, &response[..credit], 2).unwrap());
        assert_eq!(client.last_admission_block(), None);
        assert!(client.admission_state().is_some());
    }

    #[test]
    fn command_only_receive_does_not_poll_the_object_sink() {
        // Recovery selects this profile from live heap headroom. Cover every
        // possible small C6 result, not only the roomy host default of eight.
        for history_packets in 2..=8 {
            let client_cid = ConnectionId::new(0x889 + history_packets as u64 * 2).unwrap();
            let server_cid = ConnectionId::new(0x88a + history_packets as u64 * 2).unwrap();
            let request = crate::verified_object::FlashRequest {
                object: GetRequest {
                    name: None,
                    cpu: 13,
                    target: 6,
                },
                address: None,
                transport: 0,
                dry_run: true,
            };
            let mut command = [0_u8; 128];
            let command_len =
                crate::verified_object::encode_flash_handler_request(request, 1, &mut command)
                    .unwrap();
            let mut client = ObjectUploadClient::<8, 1200>::new(
                client_cid,
                &command[..command_len],
                ObjectRecordStream::new(Vec::new()),
            )
            .unwrap();
            let mut driver = quic_lite::DatagramClientDriver::start(&mut client, 0).unwrap();
            let path = PathId::new(1).unwrap();
            let mut listener = ConnectionDispatcher::<8, 1200>::new(
                server_cid,
                ConnectionLimits::with_receive_window(1200),
                AssociationProfile {
                    history_packets,
                    ack_frequency: 8,
                    ack_delay_ms: 5,
                    tx_burst_packets: history_packets,
                    initial_window_packets: history_packets,
                },
            );
            let mut operation = crate::verified_object::ExclusiveTransfer::new();
            let mut response = [0_u8; 1200];
            let open_ack = receive_server_turn(
                &mut listener,
                path,
                driver.packet().unwrap(),
                0,
                &mut response,
                |_, _| {},
                |_, _, _, _| {},
            )
            .unwrap()
            .unwrap();
            driver.mark_sent(0);
            driver
                .receive(&mut client, &response[..open_ack], 1)
                .unwrap();
            let command_packet = driver.packet().unwrap().to_vec();
            driver.mark_sent(1);
            let mut consumer_called = false;
            let credit = receive_server_turn(
                &mut listener,
                path,
                &command_packet,
                1,
                &mut response,
                |_, _| {},
                |service, _, now, _| {
                    assert!(service.take_stream_command().is_some());
                    let owner = service.expected_receive_cid().unwrap();
                    operation
                        .try_start_with(owner, 1, now, 100, || Ok::<_, ()>(()))
                        .unwrap();
                    prepare_inbound_stream(service).unwrap();
                    assert_eq!(
                        consume_available_exclusive_inbound_stream(
                            service,
                            &mut operation,
                            owner,
                            now,
                            100,
                            |_, _reader| {
                                consumer_called = true;
                                Ok::<_, ()>(false)
                            },
                        )
                        .unwrap(),
                        None
                    );
                },
            )
            .unwrap()
            .unwrap();
            assert!(!consumer_called);
            assert!(driver.receive(&mut client, &response[..credit], 2).unwrap());
            assert!(client.admission_state().is_some());
        }
    }

    #[test]
    fn object_upload_advances_past_a_small_initial_window() {
        // Match the constrained firmware's current receive contract: two
        // complete MTU-sized object fragments fit on its stream before the
        // application returns credit.  A one-packet stream window forces
        // stop-and-wait at an ordinary Wi-Fi RTT, which is not a useful
        // baseline for this transport regression.
        let limits = quic_lite::ConnectionLimits::with_receive_profile(8_800, 2_200, 4);
        let path = PathId::new(1).unwrap();
        // Keep the real long-lived firmware dispatcher across every client.
        // Each completed client intentionally leaves its final CLOSE pending,
        // reproducing a UART/UDP process exit where that last packet is lost.
        // Mirror the constrained firmware association without leaking its
        // callback-pool depth into QUIC's contract. The retransmission ledger
        // is selected from memory; adapter callback-to-worker pressure is
        // ordinary bearer loss, as it is on UART, NOW, and the host.
        let association = AssociationProfile::datagram_with_memory::<64>(
            quic_lite::ledger::LedgerMemorySnapshot {
                // Match the smallest live ESP heap envelope rather than
                // letting a host-only 51-packet ledger conceal a credit or
                // scheduling boundary that cannot exist on Recovery.
                total_bytes: 48 * 1024,
                available_bytes: 48 * 1024,
            },
            1,
            quic_lite::DEFAULT_MAX_DATAGRAM_SIZE,
            quic_lite::ledger::LedgerMemoryPolicy {
                min_packets: 2,
                max_packets: 64,
                memory_fraction_numerator: 1,
                memory_fraction_denominator: 8,
                reserve_bytes: 32 * 1024,
                metadata_bytes_per_packet: 96,
            },
        );
        assert_eq!(association.history_packets, 2);
        assert_eq!(association.initial_window_packets, 2);
        assert_eq!(association.tx_burst_packets, 2);
        let mut listener =
            ConnectionDispatcher::<64, { quic_lite::DEFAULT_MAX_DATAGRAM_SIZE }, 12>::new(
                ConnectionId::new(0x886).unwrap(),
                limits,
                association,
            );
        // Keep every prior association for the real firmware idle interval.
        // A one-shot client's final CLOSE can be lost on a datagram bearer;
        // opening the next CID on the same physical path must still make
        // progress without an artificial zero-time host-only cleanup.
        listener.set_association_idle_timeout(Some(120_000));
        for run in 0_u64..10 {
            let client_cid = ConnectionId::new(0x885 + run * 2).unwrap();
            let request = crate::verified_object::FlashRequest {
                object: GetRequest {
                    name: None,
                    cpu: 13,
                    target: 6,
                },
                address: None,
                transport: 0,
                dry_run: true,
            };
            let mut command = [0_u8; 128];
            let command_len =
                crate::verified_object::encode_flash_handler_request(request, 1, &mut command)
                    .unwrap();
            // Build the same manifest/block/DONE sequence used by the host file
            // server. The receiver below is the same incremental consumer used by
            // ESP flash, with only its storage sink replaced.
            let directory = tempfile::tempdir().unwrap();
            let artifact = directory.path().join("esp32c6/main-app.bin");
            std::fs::create_dir_all(artifact.parent().unwrap()).unwrap();
            // Exceed the current Recovery artifact so the host gate covers the
            // same sustained-transfer duration and record count as the device.
            let expected = (0..1_292_323)
                .map(|index| (index % 251) as u8)
                .collect::<Vec<_>>();
            std::fs::write(&artifact, &expected).unwrap();
            let object_server = crate::host::ObjectServer::new(crate::host::ServerConfig {
                artifact_root: directory.path().to_path_buf(),
                archive_root: None,
            });
            let (manifest, image) = object_server.response_object(request.object).unwrap();
            let records = ObjectRecordStream::from_object(manifest, image);
            // Match dmesh-cli's actual host sender allocation. The receiver still
            // selects its smaller runtime history/window below; using an 8-entry
            // client here hid the many-retained-gap condition observed on UART.
            let mut client =
                ObjectUploadClient::<512, { quic_lite::DEFAULT_MAX_DATAGRAM_SIZE }>::new(
                    client_cid,
                    &command[..command_len],
                    records,
                )
                .unwrap();
            let mut driver = quic_lite::DatagramClientDriver::start(&mut client, 0).unwrap();
            type Receiver = crate::verified_object::SignedObjectReceiver<
                HostDelayedObjectSink,
                crate::verified_object::NoSignatureVerifier,
                // Recovery's fixed parser bounds are part of the operation's
                // real memory shape.  A larger host-only manifest buffer can
                // conceal an incremental-record boundary failure.
                { 10 * 1024 },
                { 12 + crate::verified_object::BLOCK_SIZE },
            >;
            // Keep the large receiver in the same final heap allocation used
            // by firmware. An inline host value hides stack/heap placement and
            // move differences precisely where constrained ESP runs have
            // exposed bugs that the protocol simulation otherwise missed.
            let mut operation: crate::verified_object::ExclusiveTransfer<Box<Receiver>> =
                crate::verified_object::ExclusiveTransfer::new();
            operation
                .try_start_with(client_cid, 1, 0, 120_000, || {
                    Receiver::try_new_boxed(HostDelayedObjectSink {
                        bytes: Vec::new(),
                        polls: 0,
                        durable: false,
                        erase_work: crate::verified_object::DeferredStorageWork::new(),
                        erase_complete: false,
                    })
                })
                .unwrap();
            let mut reply = [0_u8; quic_lite::DEFAULT_MAX_DATAGRAM_SIZE];
            let open_ack = receive_server_turn(
                &mut listener,
                path,
                driver.packet().unwrap(),
                0,
                &mut reply,
                |_, _| {},
                |_, _, _, _| {},
            )
            .unwrap()
            .unwrap();
            driver.mark_sent(0);
            driver.receive(&mut client, &reply[..open_ack], 1).unwrap();
            let command_packet = driver.packet().unwrap().to_vec();
            driver.mark_sent(1);
            let initial_credit = receive_server_turn(
                &mut listener,
                path,
                &command_packet,
                1,
                &mut reply,
                |_, _| {},
                |service, _, _, _| {
                    assert!(service.take_stream_command().is_some());
                    prepare_inbound_stream(service).unwrap();
                },
            )
            .unwrap()
            .or_else(|| {
                poll_server_turn(&mut listener, path, 2, 600, &mut reply, |_, _, _| {}).unwrap()
            })
            .unwrap();
            driver
                .receive(&mut client, &reply[..initial_credit], 2)
                .unwrap();

            // Drop one receiver response after several complete records. This is
            // the device failure shape: the sender must stop at congestion/credit,
            // retransmit from QUIC's ledger, receive a duplicate re-ACK, and then
            // resume without an upload-specific retry loop.
            let mut dropped_response = false;
            let mut response_blackout_until = None;
            let mut delayed_client_packets = std::collections::VecDeque::new();
            let mut delayed_responses = std::collections::VecDeque::new();
            let mut reordered_client_packet = false;
            let mut dropped_client_packet = false;
            let mut client_drop_budget = if run == 0 { 24usize } else { 0 };
            let mut response_drop_budget = if run == 0 { 24usize } else { 0 };
            let mut reordered_response = false;
            let mut client_packet_attempts = 0usize;
            // The live UDP6 capture has a roughly 16 ms median turn from a
            // host packet to the device's ACK/MAX response.  Keep one full
            // run at that cadence, delivering at most one control datagram
            // per turn.  The older <= 7 ms burst delivery is useful for loss
            // and reordering, but it could conceal a stop-and-wait regression
            // that becomes painfully slow on the real Wi-Fi link.
            let observed_wifi_rtt_cadence = run == 9;
            // Deliberately non-periodic loss: a modulo-by-send-count loss
            // model can phase-lock a PTO retransmission so it drops the same
            // logical range forever. Wi-Fi loss may be bursty, but it is not
            // synchronized to our service-loop cadence.
            let mut client_loss_state = 0x9e37_79b9_u32 ^ run as u32;
            let mut sustained_client_losses = 0usize;
            let mut sustained_response_losses = 0usize;
            let mut terminal_queued = false;
            let mut completed = false;
            let mut completed_at = None;
            let mut generated_responses = 0usize;
            let mut delivered_responses = 0usize;
            for now in 3..60_000 {
                if let Some(packet) = driver.packet().map(ToOwned::to_owned) {
                    driver.mark_sent(now);
                    delayed_client_packets.push_back(packet);
                }
                let client_packet =
                    if run == 0 && client.sent_bytes() >= 32 * 1024 && !reordered_client_packet {
                        if delayed_client_packets.len() >= 2 {
                            reordered_client_packet = true;
                            delayed_client_packets.pop_back()
                        } else {
                            None
                        }
                    } else {
                        delayed_client_packets.pop_front()
                    };
                if let Some(packet) = client_packet {
                    client_packet_attempts = client_packet_attempts.saturating_add(1);
                    // The C6 USB-JTAG ingress queue can discard a complete frame
                    // while Wi-Fi callbacks occupy the shared worker. Exercise
                    // that adapter fact as ordinary datagram loss; neither the
                    // object consumer nor its stream API receives a retry hook.
                    if run == 0
                        && client.sent_bytes() >= 32 * 1024
                        && client_packet_attempts % 3 == 0
                        && client_drop_budget != 0
                    {
                        dropped_client_packet = true;
                        client_drop_budget -= 1;
                        driver.poll(&mut client, now, 600, 400).unwrap();
                        continue;
                    }
                    // Every non-corner run sustains deterministic loss for the
                    // complete image, rather than proving only that one early
                    // hole eventually recovers. This is the host counterpart
                    // of the bidirectional loss observed on ESP STA UDP.
                    client_loss_state = client_loss_state
                        .wrapping_mul(1_664_525)
                        .wrapping_add(1_013_904_223);
                    if run != 0
                        && !observed_wifi_rtt_cadence
                        && now < 10_000
                        && (client_loss_state >> 16) % (7 + run as u32 % 3) == 0
                    {
                        sustained_client_losses += 1;
                        driver.poll(&mut client, now, 600, 400).unwrap();
                        continue;
                    }
                    let response = receive_server_turn(
                    &mut listener,
                    path,
                    &packet,
                    now,
                    &mut reply,
                    |_, _| {},
                    |service, _, _, _| {
                        let consumed = consume_exclusive_inbound_stream(
                            service,
                            &mut operation,
                            client_cid,
                            now,
                            120_000,
                            |consumer, reader| {
                                let read = consumer.consume_stream_body(reader)?;
                                Ok::<_, crate::verified_object::ImageError>(read.application_progress)
                            },
                        );
                        match consumed {
                            Ok(_) => {}
                            Err(ExclusiveInboundStreamTurnError::Consumer {
                                request_id,
                                error,
                                ..
                            }) => panic!(
                                "host object consumer rejected request {request_id}: {error:?}"
                            ),
                            Err(ExclusiveInboundStreamTurnError::Transport(error)) => {
                                panic!("host object credit publication failed: {error:?}")
                            }
                        }
                    },
                )
                .unwrap_or_else(|error| {
                    panic!(
                        "server rejected reordered upload packet at now={now} records={} bytes={} error={error:?}",
                        client.record_index(),
                        client.sent_bytes(),
                    )
                })
                .or_else(|| {
                    poll_server_turn(
                        &mut listener,
                        path,
                        now,
                        600,
                        &mut reply,
                        |_, _, _| {},
                    )
                    .unwrap()
                });
                    if let Some(used) = response {
                        generated_responses += 1;
                        if run == 0
                            && response_blackout_until.is_none()
                            && client.record_index() >= 9
                        {
                            dropped_response = true;
                            // Reproduce the sparse ESP failure: lose every ACK
                            // and MAX_* packet for longer than the transport's
                            // credit retry interval while sender PTO packets keep
                            // reaching the same shared server turn.
                            // Lose the first storage-credit flight for longer
                            // than one 600 ms PTO. The sender is then flow
                            // blocked and can provoke recovery only with its
                            // retained stream retransmission, matching the live
                            // UART 41,040-byte boundary.
                            response_blackout_until = Some(now + 750);
                        }
                        if response_blackout_until.is_some_and(|deadline| now < deadline) {
                            dropped_response = true;
                        } else if run == 0
                            && generated_responses % 3 == 1
                            && response_drop_budget != 0
                        {
                            // Keep losing sparse server ACK/control packets after
                            // the initial blackout. This is the duplex-loss shape
                            // seen on the physical UART run: acknowledgements make
                            // progress, but no handler or bearer may assume every
                            // fresh re-ACK reaches the sender.
                            response_drop_budget -= 1;
                            dropped_response = true;
                        } else if !dropped_response && client.sent_bytes() >= 32 * 1024 {
                            dropped_response = true;
                        } else if run != 0 && generated_responses % (11 + run as usize % 3) == 0 {
                            sustained_response_losses += 1;
                        } else {
                            delayed_responses.push_back(reply[..used].to_vec());
                        }
                    }
                }
                // Model the one application-maintenance turn requested by a
                // persistent sink after manifest admission.  It uses the
                // receiver's storage hook before the next input datagram;
                // QUIC is otherwise driven only by the ordinary server turn.
                operation
                    .get_mut_for(client_cid)
                    .unwrap()
                    .poll_storage_before_transport()
                    .unwrap();
                // Match the event-driven Main adapter: a quiet or flow-blocked
                // sender cannot be the server's clock. Service QUIC's exact
                // delayed-ACK/PTO deadline even when no ingress packet arrived.
                if listener
                    .next_service_deadline(600)
                    .is_some_and(|deadline| deadline <= now)
                    && let Some(used) =
                        poll_server_turn(&mut listener, path, now, 600, &mut reply, |_, _, _| {})
                            .unwrap()
                {
                    delayed_responses.push_back(reply[..used].to_vec());
                    generated_responses += 1;
                }
                // Deliver receiver packets in bounded bursts and deliberately
                // reverse some adjacent packet numbers. This matches a Wi-Fi
                // callback/task boundary much more closely than the former
                // lock-step request/ACK test.
                let deliver_response = if observed_wifi_rtt_cadence {
                    now % 16 == 0 && !delayed_responses.is_empty()
                } else {
                    delayed_responses.len() >= 4 || (now % 7 == 0 && !delayed_responses.is_empty())
                };
                if deliver_response {
                    let response = if !observed_wifi_rtt_cadence && delayed_responses.len() >= 2 {
                        reordered_response = true;
                        delayed_responses.pop_back().unwrap()
                    } else {
                        delayed_responses.pop_front().unwrap()
                    };
                    driver.receive(&mut client, &response, now).unwrap();
                    delivered_responses += 1;
                }
                if operation
                    .get_mut_for(client_cid)
                    .is_some_and(|consumer| consumer.is_complete())
                    && !terminal_queued
                {
                    if run == 0 {
                        assert!(dropped_response);
                    }
                    // The client-side packet queue below always injects a
                    // concrete out-of-order receive on the corner run.  A
                    // server response reordering is opportunistic here: an
                    // event-driven delayed-credit endpoint may correctly
                    // need each control packet to release the next sender
                    // fragment, leaving no second response to hold.  Do not
                    // turn a transport pacing improvement into a fake test
                    // failure merely because this higher-level loss harness
                    // had no independently deliverable response pair.
                    let _response_reordering_observed = reordered_response;
                    if run == 0 {
                        assert!(reordered_client_packet);
                        assert!(dropped_client_packet);
                    }
                    let consumer = operation.get_mut_for(client_cid).unwrap();
                    assert_eq!(consumer.sink_mut().bytes, expected);
                    assert!(consumer.sink_mut().durable);
                    let mut tagged = [0_u8; 128];
                    let tagged_len = crate::tagged::encode_numeric_data_response(
                        crate::verified_object::OBJECT_COMPONENT,
                        crate::verified_object::OBJECT_FLASH_METHOD,
                        1,
                        b"flash complete",
                        true,
                        &mut tagged,
                    )
                    .unwrap();
                    listener
                        .complete_stream_command(tagged[..tagged_len].to_vec())
                        .unwrap();
                    terminal_queued = true;
                }
                if terminal_queued {
                    if let Some(used) =
                        poll_server_turn(&mut listener, path, now, 600, &mut reply, |_, _, _| {})
                            .unwrap()
                    {
                        delayed_responses.push_back(reply[..used].to_vec());
                    }
                }
                driver.poll(&mut client, now, 600, 400).unwrap();
                if client.is_complete() {
                    let response = crate::tagged::decode(client.response().unwrap()).unwrap();
                    assert_eq!(response.component, Some(crate::tagged::Name::Tag(10)));
                    assert_eq!(response.method, Some(crate::tagged::Name::Tag(2)));
                    assert_eq!(response.id, Some(1));
                    let mut result = crate::cbor::Decoder::new(response.result.unwrap());
                    assert_eq!(result.text_ref(), Some(&b"flash complete"[..]));
                    assert!(result.is_finished());
                    completed = true;
                    completed_at = Some(now);
                    break;
                }
            }
            assert!(
                completed,
                "object upload run {run} stalled records={} bytes={} blocked={:?} admission={:?} client_retransmits={} client_packets={client_packet_attempts} client_stats={:?} generated_responses={generated_responses} delivered_responses={delivered_responses} queued_responses={} client={:?} server={:?}",
                client.record_index(),
                client.sent_bytes(),
                client.last_admission_block(),
                client.admission_state(),
                driver.retransmit_packets(),
                client.transport_stats(),
                delayed_responses.len(),
                client.connection_debug_state(),
                listener.connection_debug_state(),
            );
            assert_eq!(operation.request_id_for(client_cid), Some(1));
            assert!(operation.take_for(client_cid).is_some());
            if run != 0 {
                // The deterministic fault source drops client and response
                // datagrams during the first ten simulated seconds. Some
                // loss is repaired by selective ACK before a PTO is due, so
                // completion—not a handler-visible retry count—is the
                // contract this shared host/device test proves.
                let _faults_observed = sustained_client_losses + sustained_response_losses;
                assert!(
                    completed_at.is_some_and(|now| now < 30_000),
                    "object upload run {run} exceeded the 30 s virtual budget: completed_at={completed_at:?} records={} bytes={} retransmits={} client_packets={client_packet_attempts} generated_responses={generated_responses} delivered_responses={delivered_responses}",
                    client.record_index(),
                    client.sent_bytes(),
                    driver.retransmit_packets(),
                );
            }
        }
    }
}
