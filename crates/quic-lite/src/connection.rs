//! Bearer-neutral QUIC-lite connection policy.
//!
//! A connection can be carried by UART, UDP6, ESP-NOW, LoRa, or a host-only
//! test bearer.  The connection owns the association: connection IDs, packet
//! numbers, stream multiplexing, handshake/peer-authentication state, and its
//! current plus previously validated paths. Consequently this module owns no
//! radio lifecycle, socket, peer address, or task state. Those belong to
//! physical transport adapters.
//!
//! Stream opening, RPC, forwarding, and service selection are connection
//! operations built on this policy.  They must not be represented as a
//! `transport.start` request: starting a bearer merely makes paths available.

use alloc::vec::Vec;

/// Partial policy applied when a QUIC-lite association is created.
///
/// Omitted fields preserve the connection manager's existing/default values.
/// Bounds are enforced by the schema adapter before this value reaches a
/// connection manager, allowing this type to remain CBOR-free and reusable by
/// host tests.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ConnectionPolicy {
    pub ack_frequency: Option<u8>,
    pub ack_delay_ms: Option<u8>,
    pub tx_burst_packets: Option<u8>,
    pub path_policy: Option<u8>,
    pub timeout_ms: Option<u32>,
}

/// Opaque identifier assigned by a frame-I/O adapter to one usable path.
///
/// The value deliberately carries no MAC address, socket address, UART port,
/// or bearer kind. The adapter retains those facts and resolves this handle
/// when the connection selects an outgoing frame. A single logical
/// connection can therefore move between unlike bearers without changing its
/// DCID or stream state.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct PathId(u64);

impl PathId {
    pub const fn new(value: u64) -> Option<Self> {
        if value == 0 { None } else { Some(Self(value)) }
    }

    pub const fn value(self) -> u64 {
        self.0
    }
}

/// Associates transport-independent connection state with its active path.
///
/// `receive` changes the return path only after the connection has accepted
/// the packet. Parsing failures, unknown DCIDs, and future authentication
/// failures therefore cannot redirect delayed ACKs or retransmissions.
pub struct PathConnection<T> {
    connection: T,
    /// Paths that have carried a valid packet for this association.  The
    /// adapter resolves these opaque handles to UART ports, UDP tuples, or
    /// NOW peers; QUIC never learns or chooses bearer-specific addresses.
    known_paths: [Option<PathId>; 4],
    /// A caller-selected egress path, for example the exact address named by
    /// a `to` field.  This is deliberately distinct from `active_path`: an
    /// unverified outbound attempt must not claim that the peer has migrated
    /// to that path.
    selected_path: Option<PathId>,
    active_path: Option<PathId>,
}

/// Bounded packet-number evidence for connection diagnostics.
///
/// This deliberately exposes no payload, peer address, or bearer identity.
/// Every adapter therefore reports the same connection-layer state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConnectionDebugState {
    pub received_ranges: [Option<(u32, u32)>; crate::ACK_RANGE_CAPACITY],
    pub peer_ack_ranges: [Option<(u32, u32)>; crate::ACK_RANGE_CAPACITY],
    pub outstanding_packets: [Option<u32>; 16],
    pub outstanding_count: usize,
}

impl ConnectionDebugState {
    pub fn from_endpoint<const N: usize, const HISTORY: usize, const PACKET: usize>(
        endpoint: &crate::EndpointState<N, HISTORY, PACKET>,
    ) -> Self {
        let received_ranges = endpoint
            .ack_ranges_snapshot()
            .map(|range| range.map(|range| (range.start, range.end)));
        let peer_ack_ranges = endpoint
            .peer_ack_ranges_snapshot()
            .map(|range| range.map(|range| (range.start, range.end)));
        let (numbers, outstanding_count) = endpoint.outstanding_packet_numbers();
        let mut outstanding_packets = [None; 16];
        for (index, number) in numbers.into_iter().enumerate().take(16) {
            outstanding_packets[index] = number;
        }
        Self {
            received_ranges,
            peer_ack_ranges,
            outstanding_packets,
            outstanding_count,
        }
    }
}

/// Progress counters shared by complete-datagram connection clients.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ConnectionCounters {
    pub bootstrap_acks: u32,
    pub stream_packets: u32,
    pub other_packets: u32,
}

/// Persistent server-side QUIC stream state, independent of application
/// registries, events, sockets, and bearer addresses.
pub struct ServerStreamConnection<
    const STREAMS: usize,
    const HISTORY: usize,
    const PACKET: usize = { crate::DEFAULT_MAX_DATAGRAM_SIZE },
> {
    // Kept public temporarily for the dmesh-server diagnostic formatter.
    // New bearer/runtime operations must use the narrow methods below; once
    // diagnostics consume a snapshot rather than EndpointState this becomes
    // private as well.
    pub mux: crate::mux::StreamMux<STREAMS, HISTORY, PACKET>,
    local_limits: crate::ConnectionLimits,
    peer_open: crate::BootstrapOpen,
    /// Opaque token advertised with this server CID. It is association state
    /// owned by QUIC-lite so replayed OPENs cannot accidentally omit it.
    stateless_reset_token: Option<crate::StatelessResetToken>,
    path_policy: crate::PathPolicy,
    next_response_stream: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServerStreamConfig {
    pub max_pending_streams: usize,
    pub max_stream_bytes: usize,
}

impl Default for ServerStreamConfig {
    fn default() -> Self {
        Self {
            // CallbackStreams retains a stream identity until the association
            // closes so duplicate FIN frames are harmless.  Keep its bound in
            // lockstep with EndpointState rather than making a long-lived
            // association fail after four completed tagged RPCs.
            max_pending_streams: crate::DEFAULT_STREAM_STATE_SLOTS,
            max_stream_bytes: 4096,
        }
    }
}

impl<const STREAMS: usize, const HISTORY: usize, const PACKET: usize>
    ServerStreamConnection<STREAMS, HISTORY, PACKET>
{
    /// Construct persistent stream state after an external connection table
    /// has admitted an OPEN. This is used by async adapters that send the
    /// OPEN-ACK in their listener before handing established packets to a
    /// per-connection task.
    #[allow(clippy::too_many_arguments)]
    pub fn established_with_config(
        local_cid: crate::ConnectionId,
        peer_cid: crate::ConnectionId,
        local_limits: crate::ConnectionLimits,
        peer_max_data: u64,
        peer_max_stream_data: u64,
        peer_max_in_flight_packets: u16,
        next_packet_number: u32,
        history_capacity: usize,
        config: ServerStreamConfig,
    ) -> Result<Self, crate::Error> {
        let mut mux = crate::mux::StreamMux::new_with_history_capacity(
            crate::Role::Server,
            local_limits,
            PACKET as u64,
            1,
            config.max_pending_streams,
            config.max_stream_bytes,
            history_capacity,
        );
        mux.install_connection_ids(local_cid, peer_cid)?;
        mux.endpoint.set_initial_peer_budget(
            peer_max_data,
            peer_max_stream_data,
            peer_max_in_flight_packets,
        )?;
        mux.endpoint
            .continue_packet_numbers_from(next_packet_number)?;
        Ok(Self {
            mux,
            local_limits,
            peer_open: crate::BootstrapOpen {
                client_receive_cid: peer_cid,
                max_data: peer_max_data,
                max_stream_data: peer_max_stream_data,
                max_in_flight_packets: peer_max_in_flight_packets,
            },
            stateless_reset_token: None,
            path_policy: crate::PathPolicy::HighestMeasuredSpeed,
            next_response_stream: crate::FIRST_SERVER_BIDI_STREAM_ID,
        })
    }

    pub fn accept_open_with_limits(
        packet: &[u8],
        server_cid: crate::ConnectionId,
        local_limits: crate::ConnectionLimits,
    ) -> Result<(Self, Vec<u8>), crate::Error> {
        Self::accept_open_with_config_and_reset_token(
            packet,
            server_cid,
            local_limits,
            ServerStreamConfig::default(),
            None,
        )
    }

    pub fn accept_open_with_config(
        packet: &[u8],
        server_cid: crate::ConnectionId,
        local_limits: crate::ConnectionLimits,
        config: ServerStreamConfig,
    ) -> Result<(Self, Vec<u8>), crate::Error> {
        Self::accept_open_with_config_and_reset_token(
            packet,
            server_cid,
            local_limits,
            config,
            None,
        )
    }

    /// Accept an Initial and advertise an association-specific reset token.
    /// The caller obtains the token from its persistent device-secret branch;
    /// no bearer receives the root secret or builds the ACK itself.
    pub fn accept_open_with_config_and_reset_token(
        packet: &[u8],
        server_cid: crate::ConnectionId,
        local_limits: crate::ConnectionLimits,
        config: ServerStreamConfig,
        stateless_reset_token: Option<crate::StatelessResetToken>,
    ) -> Result<(Self, Vec<u8>), crate::Error> {
        let (bootstrap_header, open) = crate::decode_bootstrap_open_packet_with_limits(packet)?;
        let mut mux = crate::mux::StreamMux::new(
            crate::Role::Server,
            local_limits,
            PACKET as u64,
            1,
            config.max_pending_streams,
            config.max_stream_bytes,
        );
        Self::finish_open(&mut mux, bootstrap_header.packet_number, open, server_cid)?;
        let ack = Self::encode_open_ack(
            open.client_receive_cid,
            server_cid,
            local_limits,
            stateless_reset_token,
        )?;
        Ok((
            Self {
                mux,
                local_limits,
                peer_open: open,
                stateless_reset_token,
                path_policy: crate::PathPolicy::HighestMeasuredSpeed,
                next_response_stream: crate::FIRST_SERVER_BIDI_STREAM_ID,
            },
            ack,
        ))
    }

    /// Initialize directly in final storage so embedded callers never copy
    /// the bounded retransmission ledger through an ingress-task stack frame.
    ///
    /// # Safety
    /// `out` must be valid, aligned, uninitialized storage for one `Self`.
    pub unsafe fn accept_open_in_place(
        out: *mut Self,
        packet: &[u8],
        server_cid: crate::ConnectionId,
        local_limits: crate::ConnectionLimits,
    ) -> Result<Vec<u8>, crate::Error> {
        unsafe {
            Self::accept_open_in_place_with_config_and_reset_token(
                out,
                packet,
                server_cid,
                local_limits,
                ServerStreamConfig::default(),
                None,
            )
        }
    }

    /// Configurable counterpart to [`Self::accept_open_in_place`].
    ///
    /// # Safety
    /// `out` must be valid, aligned, uninitialized storage for one `Self`.
    pub unsafe fn accept_open_in_place_with_config(
        out: *mut Self,
        packet: &[u8],
        server_cid: crate::ConnectionId,
        local_limits: crate::ConnectionLimits,
        config: ServerStreamConfig,
    ) -> Result<Vec<u8>, crate::Error> {
        unsafe {
            Self::accept_open_in_place_with_config_and_reset_token(
                out,
                packet,
                server_cid,
                local_limits,
                config,
                None,
            )
        }
    }

    /// In-place variant with the same token ownership as the heap-backed
    /// accept path. This keeps firmware bootstrap stack usage bounded.
    pub unsafe fn accept_open_in_place_with_config_and_reset_token(
        out: *mut Self,
        packet: &[u8],
        server_cid: crate::ConnectionId,
        local_limits: crate::ConnectionLimits,
        config: ServerStreamConfig,
        stateless_reset_token: Option<crate::StatelessResetToken>,
    ) -> Result<Vec<u8>, crate::Error> {
        let (bootstrap_header, open) = crate::decode_bootstrap_open_packet_with_limits(packet)?;
        unsafe {
            crate::mux::StreamMux::init_in_place(
                core::ptr::addr_of_mut!((*out).mux),
                crate::Role::Server,
                local_limits,
                PACKET as u64,
                config.max_pending_streams,
                config.max_stream_bytes,
            );
            core::ptr::addr_of_mut!((*out).path_policy)
                .write(crate::PathPolicy::HighestMeasuredSpeed);
            core::ptr::addr_of_mut!((*out).local_limits).write(local_limits);
            core::ptr::addr_of_mut!((*out).peer_open).write(open);
            core::ptr::addr_of_mut!((*out).stateless_reset_token).write(stateless_reset_token);
            core::ptr::addr_of_mut!((*out).next_response_stream)
                .write(crate::FIRST_SERVER_BIDI_STREAM_ID);
            Self::finish_open(
                &mut (*out).mux,
                bootstrap_header.packet_number,
                open,
                server_cid,
            )?;
        }
        Self::encode_open_ack(
            open.client_receive_cid,
            server_cid,
            local_limits,
            stateless_reset_token,
        )
    }

    fn finish_open(
        mux: &mut crate::mux::StreamMux<STREAMS, HISTORY, PACKET>,
        bootstrap_packet_number: u32,
        open: crate::BootstrapOpen,
        server_cid: crate::ConnectionId,
    ) -> Result<(), crate::Error> {
        mux.install_connection_ids(server_cid, open.client_receive_cid)?;
        mux.endpoint.set_initial_peer_budget(
            open.max_data,
            open.max_stream_data,
            open.max_in_flight_packets,
        )?;
        mux.endpoint
            .continue_packet_numbers_from(bootstrap_packet_number.saturating_add(1))
    }

    fn encode_open_ack(
        client_cid: crate::ConnectionId,
        server_cid: crate::ConnectionId,
        local_limits: crate::ConnectionLimits,
        stateless_reset_token: Option<crate::StatelessResetToken>,
    ) -> Result<Vec<u8>, crate::Error> {
        let mut ack = [0u8; PACKET];
        let used = crate::encode_bootstrap_open_ack_packet_with_limits_and_reset_token(
            client_cid,
            server_cid,
            0,
            local_limits,
            stateless_reset_token,
            &mut ack,
        )?;
        Ok(ack[..used].to_vec())
    }

    /// Validate a retransmitted OPEN and reproduce this connection's ACK.
    /// Adapters may use the peer address to locate a candidate connection,
    /// but OPEN identity, negotiated limits, and response encoding remain
    /// connection-layer state.
    pub fn replay_open_ack(&self, packet: &[u8]) -> Result<Vec<u8>, crate::Error> {
        let (_, open) = crate::decode_bootstrap_open_packet_with_limits(packet)?;
        if open != self.peer_open {
            return Err(crate::Error::BootstrapInvalid);
        }
        let local_cid = self
            .mux
            .endpoint
            .local_connection_id()
            .ok_or(crate::Error::WrongConnectionId)?;
        Self::encode_open_ack(
            open.client_receive_cid,
            local_cid,
            self.local_limits,
            self.stateless_reset_token,
        )
    }

    pub const fn path_policy(&self) -> crate::PathPolicy {
        self.path_policy
    }

    pub fn set_path_policy(&mut self, policy: crate::PathPolicy) {
        self.path_policy = policy;
    }

    pub fn reserve_response_stream(&mut self) -> u64 {
        let stream = self.next_response_stream;
        self.next_response_stream = self.next_response_stream.saturating_add(4);
        stream
    }

    pub fn receive_request(
        &mut self,
        packet: &[u8],
    ) -> Result<Option<crate::mux::MuxRequest>, crate::Error> {
        self.mux.receive_request(packet)
    }

    pub fn encode_response(
        &mut self,
        body: &[u8],
        out: &mut [u8],
    ) -> Result<(usize, u32), crate::Error> {
        let stream = self.reserve_response_stream();
        self.mux.encode_response(stream, body, true, out)
    }

    pub fn poll_transmit(&mut self, out: &mut [u8]) -> Result<Option<usize>, crate::Error> {
        self.mux.endpoint.poll_transmit(out)
    }

    /// Association-owned clock used for ACK and PTO calculations.
    pub fn set_time(&mut self, now: u64) {
        self.mux.endpoint.set_time(now);
    }

    /// Immutable connection facts for dispatch and diagnostics.  These avoid
    /// handing a bearer or service the endpoint implementation.
    pub fn local_connection_id(&self) -> Option<crate::ConnectionId> {
        self.mux.endpoint.local_connection_id()
    }

    pub fn peer_connection_id(&self) -> Option<crate::ConnectionId> {
        self.mux.endpoint.peer_connection_id()
    }

    pub fn stream_stats(&self) -> crate::ConnectionStreamStats {
        self.mux.endpoint.stream_stats()
    }

    pub fn transport_stats(&self) -> crate::TransportStats {
        self.mux.endpoint.stats()
    }

    pub fn is_closed(&self) -> bool {
        self.mux.endpoint.is_closed()
    }

    pub fn next_bearer_deadline(&self, pto: u64) -> Option<u64> {
        self.mux.endpoint.next_bearer_deadline(pto)
    }

    pub fn debug_state(&self) -> ConnectionDebugState {
        ConnectionDebugState::from_endpoint(&self.mux.endpoint)
    }

    /// Apply bounded raw-bearer policy while the association is being
    /// accepted.  The caller supplies policy values, never the endpoint, so
    /// UART/NOW/UDP adapters cannot alter packet framing or ledger state.
    pub fn configure_raw_bearer(
        &mut self,
        history_packets: usize,
        initial_window_bytes: u64,
    ) -> Result<(), crate::Error> {
        self.mux.endpoint.set_history_capacity(history_packets)?;
        self.mux.endpoint.congestion.congestion_window = initial_window_bytes;
        self.mux.endpoint.congestion.slow_start_threshold = initial_window_bytes;
        Ok(())
    }

    /// ACK/congestion facts used by a bearer-neutral diagnostic report.
    pub fn transport_ack_state(&self) -> (Option<u32>, u64, u64) {
        (
            self.mux.endpoint.largest_acked_by_peer(),
            self.mux.endpoint.congestion.bytes_in_flight,
            self.mux.endpoint.congestion.congestion_window,
        )
    }

    /// Mark an admitted request complete.  Stream bookkeeping remains inside
    /// the association rather than exposing its mux to application handlers.
    pub fn complete_request(
        &mut self,
        stream_id: u64,
        received_len: usize,
    ) -> Result<(), crate::Error> {
        self.mux.complete_request(stream_id, received_len)
    }

    /// Apply the negotiated ACK cadence for this association.
    pub fn request_ack_frequency(
        &mut self,
        sequence: u64,
        packet_tolerance: u64,
        max_ack_delay_us: u64,
        reorder_threshold: u64,
    ) -> Result<(), crate::Error> {
        self.mux.endpoint.request_ack_frequency(
            sequence,
            packet_tolerance,
            max_ack_delay_us,
            reorder_threshold,
        )
    }

    /// Encode one server-originated stream fragment.  Payload construction is
    /// application work; stream state, peer CID, flow control, and packet
    /// framing remain private to QUIC-lite.
    pub fn encode_server_stream_fragment(
        &mut self,
        stream_id: u64,
        offset: u64,
        fin: bool,
        payload: &[u8],
        out: &mut [u8; PACKET],
    ) -> Result<(usize, u32), crate::Error> {
        let peer = self
            .mux
            .endpoint
            .peer_connection_id()
            .ok_or(crate::Error::WrongConnectionId)?;
        let _ = self
            .mux
            .endpoint
            .open_send_stream(stream_id, crate::INITIAL_MAX_STREAM_DATA);
        self.mux
            .endpoint
            .encode_stream_packet(peer, stream_id, offset, fin, payload, out)
    }
}

impl<T> PathConnection<T> {
    pub const fn new(connection: T) -> Self {
        Self {
            connection,
            known_paths: [None; 4],
            selected_path: None,
            active_path: None,
        }
    }

    pub const fn active_path(&self) -> Option<PathId> {
        self.active_path
    }

    /// Path selected for an outbound operation before the peer has answered.
    /// Once a packet is accepted, [`Self::receive`] makes its ingress path
    /// active and that path takes precedence for ordinary ACK/retransmit
    /// traffic.
    pub const fn selected_path(&self) -> Option<PathId> {
        self.selected_path
    }

    /// Preferred egress path. A caller-specified path wins for its immediate
    /// operation; otherwise a connection returns traffic on its most recent
    /// valid ingress path.
    pub const fn egress_path(&self) -> Option<PathId> {
        match self.selected_path {
            Some(path) => Some(path),
            None => self.active_path,
        }
    }

    /// Select an adapter-owned path for the next outbound operation. This
    /// does not validate, remember, or migrate the association.
    pub fn select_path(&mut self, path: PathId) {
        self.selected_path = Some(path);
    }

    /// Clear a one-operation egress selection so normal traffic resumes on
    /// the last valid ingress path.
    pub fn clear_selected_path(&mut self) {
        self.selected_path = None;
    }

    /// Paths currently attached to this association, newest valid ingress
    /// first. The final path is not removed merely because the connection
    /// temporarily sends over another bearer; expiry and explicit close are
    /// connection-manager policy above this no-std state.
    pub const fn known_paths(&self) -> [Option<PathId>; 4] {
        self.known_paths
    }

    pub const fn connection(&self) -> &T {
        &self.connection
    }

    pub fn connection_mut(&mut self) -> &mut T {
        &mut self.connection
    }

    pub fn into_inner(self) -> T {
        self.connection
    }

    /// Process one complete frame and adopt its path only on success.
    ///
    /// A valid established packet may arrive via a different bearer than the
    /// previous one. It retains the same QUIC association and makes its path
    /// the return path; malformed packets and failed future authentication do
    /// not alter either the active or remembered paths.
    pub fn receive<R, E>(
        &mut self,
        path: PathId,
        receive: impl FnOnce(&mut T) -> Result<R, E>,
    ) -> Result<R, E> {
        let result = receive(&mut self.connection)?;
        self.remember_path(path);
        self.active_path = Some(path);
        self.selected_path = None;
        Ok(result)
    }

    pub fn clear_active_path(&mut self) {
        self.active_path = None;
    }

    fn remember_path(&mut self, path: PathId) {
        if self.known_paths[0] == Some(path) {
            return;
        }
        let mut index = self.known_paths.len() - 1;
        while index != 0 {
            self.known_paths[index] = self.known_paths[index - 1];
            index -= 1;
        }
        self.known_paths[0] = Some(path);
    }
}

/// Outcome of routing one frame through a server association owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServerConnectionIngress<R> {
    /// A foreign Initial OPEN cannot replace the active association.
    IgnoredOpen,
    /// The frame was accepted. `retired` means it also completed CLOSE and
    /// the bounded association state was released after producing `result`.
    Accepted { result: R, retired: bool },
}

/// Header classification shared by every server-side connection owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServerPacket {
    Initial(crate::BootstrapOpen),
    Established,
}

/// Complete-datagram classification for a shared listener.
///
/// The listener uses this to select a terminating direct endpoint, a new
/// association, or an existing association route.  It deliberately exposes
/// only the destination CID required for route-table lookup: packet headers,
/// packet numbers, and all frame data remain private to QUIC-lite.  UART,
/// NOW, and UDP adapters must pass the same opaque frame bytes after this
/// one classification step.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServerDatagram {
    /// A private custom-version long-header direct request. It terminates at
    /// the direct endpoint and is never an association route.
    Direct,
    /// A custom-version Initial OPEN that may create or replay an association.
    Initial(crate::BootstrapOpen),
    /// A custom-version Initial OPEN_ACK for an association initiated by this
    /// listener.  A shared listener routes it by the client CID in the long
    /// header; the receiving association alone validates its payload and
    /// packet number.  This must be recognized before short-header decoding:
    /// the fixed bit is shared by the two QUIC header forms.
    BootstrapAck { destination: crate::ConnectionId },
    /// An established short-header packet, identified only by its destination.
    Established { destination: crate::ConnectionId },
}

/// Classify one completed inbound datagram for a shared QUIC-lite listener.
///
/// Direct framing, Initial parsing, and short-header CID extraction all live
/// here so socket/radio adapters do not grow their own header peeking paths.
pub fn classify_server_datagram(packet: &[u8]) -> Result<ServerDatagram, crate::Error> {
    if crate::DirectMessageEndpoint::is_packet(packet) {
        return Ok(ServerDatagram::Direct);
    }
    if let Ok((_, open)) = crate::decode_bootstrap_open_packet_with_limits(packet) {
        return Ok(ServerDatagram::Initial(open));
    }
    if let Ok((long, _, _)) = crate::decode_long_packet(packet) {
        if long.packet_type == crate::LONG_PACKET_INITIAL {
            if let Some(destination) = long.dcid {
                return Ok(ServerDatagram::BootstrapAck { destination });
            }
        }
        return Err(crate::Error::Invalid);
    }
    let (header, _) = crate::ShortHeader::decode(packet)?;
    Ok(ServerDatagram::Established {
        destination: header.dcid,
    })
}

pub fn classify_server_packet(packet: &[u8]) -> Result<ServerPacket, crate::Error> {
    match classify_server_datagram(packet)? {
        ServerDatagram::Initial(open) => Ok(ServerPacket::Initial(open)),
        ServerDatagram::Established { .. } => Ok(ServerPacket::Established),
        // Long-header direct and client-side bootstrap ACK records cannot
        // enter a server association owner.
        ServerDatagram::Direct | ServerDatagram::BootstrapAck { .. } => {
            Err(crate::Error::Invalid)
        }
    }
}

/// Bounded connection-ID context for a rejected datagram.
///
/// This is produced by the connection owner so bearer adapters never decode
/// QUIC headers merely to report an error. It contains no payload or bearer
/// address and is safe to project into platform diagnostics.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ConnectionIdDiagnostic {
    pub received: Option<crate::ConnectionId>,
    pub expected: Option<crate::ConnectionId>,
}

/// Shared server-side association, CID rotation, and multi-path lifecycle.
///
/// `T` is application glue supplied by the caller. This owner parses only the
/// QUIC short header and never sees tagged records, services, peers, or bearer
/// addresses; those remain behind the caller's opaque [`PathId`] mapping.
pub struct ServerConnection<T> {
    local_cid: crate::ConnectionId,
    cid_epoch: u32,
    association: Option<PathConnection<T>>,
}

/// Fixed-capacity owner for independent server-side QUIC associations.
///
/// This is the server equivalent of a real QUIC endpoint's connection table.
/// It belongs in QUIC-lite because CID admission, packet-number state and
/// multi-path state are QUIC concerns; UART, UDP and NOW adapters supply only
/// an opaque [`PathId`] plus a complete frame.  Each entry is one logical,
/// bidirectional association and may remember several validated paths.
///
/// The table is intentionally bounded and allocation-free.  `T` may itself
/// place its large stream ledger behind a `Box`, so an embedded endpoint pays
/// for that ledger only after a valid Initial is admitted.
pub struct ServerAssociationTable<T, const ASSOCIATIONS: usize> {
    next_local_cid: crate::ConnectionId,
    cid_epoch: u32,
    associations: [Option<PathConnection<T>>; ASSOCIATIONS],
    last_active_path: Option<PathId>,
}

impl<T, const ASSOCIATIONS: usize> ServerAssociationTable<T, ASSOCIATIONS> {
    pub fn new(first_local_cid: crate::ConnectionId) -> Self {
        Self {
            next_local_cid: first_local_cid,
            cid_epoch: 0,
            associations: core::array::from_fn(|_| None),
            last_active_path: None,
        }
    }

    /// Route one complete packet to its independent association.  A fresh
    /// Initial creates a new entry rather than replacing an unrelated live
    /// peer.  A retransmitted Initial replays only its own OPEN_ACK.
    pub fn receive_admitted<R, C>(
        &mut self,
        path: PathId,
        packet: &[u8],
        context: &mut C,
        accept: impl FnOnce(crate::ConnectionId, &mut C) -> Result<(T, R), crate::Error>,
        replay: impl FnOnce(&mut T, &mut C) -> Result<R, crate::Error>,
        receive: impl FnOnce(&mut T, &mut C) -> Result<R, crate::Error>,
        is_closed: impl Fn(&T) -> bool,
        peer_cid: impl Fn(&T) -> Option<crate::ConnectionId>,
        receive_cid: impl Fn(&T) -> Option<crate::ConnectionId>,
    ) -> Result<ServerConnectionIngress<R>, crate::Error> {
        match classify_server_datagram(packet)? {
            ServerDatagram::Initial(open) => {
                if let Some(slot) = self.associations.iter().position(|association| {
                    association
                        .as_ref()
                        .is_some_and(|association| peer_cid(association.connection()) == Some(open.client_receive_cid))
                }) {
                    let result = self.associations[slot]
                        .as_mut()
                        .expect("matched association remains installed")
                        .receive(path, |connection| replay(connection, context))?;
                    self.last_active_path = Some(path);
                    return Ok(ServerConnectionIngress::Accepted {
                        result,
                        retired: false,
                    });
                }

                let slot = match self.associations.iter().position(Option::is_none) {
                    Some(slot) => slot,
                    // Preserve the historical single-association owner for
                    // callers that deliberately instantiate a one-slot
                    // endpoint. Multi-peer endpoints must never evict an
                    // unrelated live association merely because another peer
                    // sends an Initial.
                    None if ASSOCIATIONS == 1 => {
                        self.associations[0] = None;
                        0
                    }
                    None => {
                        // A bounded endpoint must reject a new peer rather
                        // than evicting an unrelated live association. The
                        // caller can expose this as admission pressure and
                        // retry after an idle/CLOSE eviction.
                        return Err(crate::Error::StreamLimit);
                    }
                };
                let local_cid = self.allocate_cid(Some(open.client_receive_cid));
                let (connection, result) = accept(local_cid, context)?;
                let mut association = PathConnection::new(connection);
                association.remember_path(path);
                association.active_path = Some(path);
                self.associations[slot] = Some(association);
                self.last_active_path = Some(path);
                Ok(ServerConnectionIngress::Accepted {
                    result,
                    retired: false,
                })
            }
            ServerDatagram::Established { destination } => {
                let Some(slot) = self.associations.iter().position(|association| {
                    association.as_ref().is_some_and(|association| {
                        receive_cid(association.connection()) == Some(destination)
                    })
                }) else {
                    return Err(crate::Error::WrongConnectionId);
                };
                let association = self.associations[slot]
                    .as_mut()
                    .expect("routed association remains installed");
                let result = association.receive(path, |connection| receive(connection, context))?;
                self.last_active_path = Some(path);
                let retired = is_closed(association.connection());
                if retired {
                    self.associations[slot] = None;
                    // A close retires only this peer. Keep diagnostics and
                    // no-path egress pointed at another live association if
                    // one exists; a closed peer must not make the endpoint
                    // appear globally idle.
                    self.last_active_path = self
                        .associations
                        .iter()
                        .filter_map(Option::as_ref)
                        .find_map(PathConnection::active_path);
                }
                Ok(ServerConnectionIngress::Accepted { result, retired })
            }
            ServerDatagram::Direct | ServerDatagram::BootstrapAck { .. } => {
                Err(crate::Error::Invalid)
            }
        }
    }

    pub fn association_for_path_mut(&mut self, path: PathId) -> Option<&mut T> {
        self.associations
            .iter_mut()
            .filter_map(Option::as_mut)
            .find(|association| association.active_path() == Some(path))
            .map(PathConnection::connection_mut)
    }

    pub fn association_for_path(&self, path: PathId) -> Option<&T> {
        self.associations
            .iter()
            .filter_map(Option::as_ref)
            .find(|association| association.active_path() == Some(path))
            .map(PathConnection::connection)
    }

    /// True when the frame is either a new Initial or addresses one of this
    /// endpoint's live associations. This keeps DCID parsing in QUIC-lite.
    pub fn owns_packet(
        &self,
        packet: &[u8],
        receive_cid: impl Fn(&T) -> Option<crate::ConnectionId>,
    ) -> bool {
        match classify_server_datagram(packet) {
            Ok(ServerDatagram::Initial(_)) => true,
            Ok(ServerDatagram::Established { destination }) => self
                .associations
                .iter()
                .filter_map(Option::as_ref)
                .any(|association| receive_cid(association.connection()) == Some(destination)),
            _ => false,
        }
    }

    pub fn associations(&self) -> impl Iterator<Item = &T> {
        self.associations
            .iter()
            .filter_map(Option::as_ref)
            .map(PathConnection::connection)
    }

    pub fn associations_mut(&mut self) -> impl Iterator<Item = &mut T> {
        self.associations
            .iter_mut()
            .filter_map(Option::as_mut)
            .map(PathConnection::connection_mut)
    }

    /// Compatibility view of the most recently active association. New code
    /// that has a path must use [`Self::association_for_path`] so unrelated
    /// peers cannot be conflated.
    pub fn association(&self) -> Option<&T> {
        self.last_active_path
            .and_then(|path| self.association_for_path(path))
    }

    /// Mutable compatibility view of the most recently active association.
    pub fn association_mut(&mut self) -> Option<&mut T> {
        self.last_active_path
            .and_then(|path| self.association_for_path_mut(path))
    }

    pub fn active_path(&self) -> Option<PathId> {
        self.last_active_path
    }

    pub fn known_paths_for(&self, path: PathId) -> [Option<PathId>; 4] {
        self.associations
            .iter()
            .filter_map(Option::as_ref)
            .find(|association| association.active_path() == Some(path))
            .map_or([None; 4], PathConnection::known_paths)
    }

    pub fn active_len(&self) -> usize {
        self.associations.iter().filter(|entry| entry.is_some()).count()
    }

    pub fn replace_all(&mut self) {
        self.associations.iter_mut().for_each(|entry| *entry = None);
        self.last_active_path = None;
    }

    fn allocate_cid(&mut self, excluded_peer_cid: Option<crate::ConnectionId>) -> crate::ConnectionId {
        loop {
            let candidate = self.next_local_cid;
            self.cid_epoch = self.cid_epoch.wrapping_add(1).max(1);
            let next = candidate.value().wrapping_add(1).max(1);
            self.next_local_cid = crate::ConnectionId::new(next)
                .expect("rotated server CID must remain nonzero");
            // CIDs are allocated monotonically, so a live table entry cannot
            // collide before the u32 sequence wraps. The explicit peer-CID
            // exclusion avoids reflecting a client CID during the rare
            // bootstrap collision.
            if excluded_peer_cid != Some(candidate) {
                return candidate;
            }
        }
    }
}

impl<T> ServerConnection<T> {
    /// Admit a custom-version Initial or route an established short-header
    /// packet without requiring application glue to classify QUIC headers.
    ///
    /// `accept` constructs the complete application-wrapped connection and
    /// its immediate Initial response. `replay` reproduces that response for
    /// the live peer. Only `receive` sees established traffic.
    pub fn receive_admitted<R, C>(
        &mut self,
        path: PathId,
        packet: &[u8],
        context: &mut C,
        accept: impl FnOnce(crate::ConnectionId, &mut C) -> Result<(T, R), crate::Error>,
        replay: impl FnOnce(&mut T, &mut C) -> Result<R, crate::Error>,
        receive: impl FnOnce(&mut T, &mut C) -> Result<R, crate::Error>,
        is_closed: impl Fn(&T) -> bool,
        peer_cid: impl Fn(&T) -> Option<crate::ConnectionId>,
    ) -> Result<ServerConnectionIngress<R>, crate::Error> {
        if let ServerPacket::Initial(open) = classify_server_packet(packet)? {
            if let Some(association) = self.association.as_ref() {
                if peer_cid(association.connection()) == Some(open.client_receive_cid) {
                    let result = self
                        .association
                        .as_mut()
                        .expect("association remains installed")
                        .receive(path, |connection| replay(connection, context))?;
                    return Ok(ServerConnectionIngress::Accepted {
                        result,
                        retired: false,
                    });
                }
                // A fresh long-header OPEN is a new QUIC connection, not a
                // bearer-local control record.  It must be allowed to retire
                // an abandoned association even when it arrived on another
                // path: a host may move from UART/NOW/one monitor VIF to
                // another while the peer never received its final CLOSE.
                // The accepted OPEN's path becomes the return path below.
                // Established packets still require the active connection
                // ID, so an unrelated short-header packet cannot migrate or
                // replace connection state.
                self.association = None;
                self.rotate_cid(Some(open.client_receive_cid));
            }
            if self.local_cid == open.client_receive_cid {
                self.rotate_cid(Some(open.client_receive_cid));
            }
            let (connection, result) = accept(self.local_cid, context)?;
            let mut association = PathConnection::new(connection);
            association.remember_path(path);
            association.active_path = Some(path);
            self.association = Some(association);
            return Ok(ServerConnectionIngress::Accepted {
                result,
                retired: false,
            });
        }

        let association = self
            .association
            .as_mut()
            .ok_or(crate::Error::WrongConnectionId)?;
        let result = association.receive(path, |connection| receive(connection, context))?;
        let retired = is_closed(association.connection());
        if retired {
            let retired_peer = peer_cid(association.connection());
            self.association = None;
            self.rotate_cid(retired_peer);
        }
        Ok(ServerConnectionIngress::Accepted { result, retired })
    }

    pub const fn new(local_cid: crate::ConnectionId) -> Self {
        Self {
            local_cid,
            cid_epoch: 0,
            association: None,
        }
    }

    pub const fn local_cid(&self) -> crate::ConnectionId {
        self.local_cid
    }

    pub const fn active_path(&self) -> Option<PathId> {
        match self.association.as_ref() {
            Some(association) => association.active_path(),
            None => None,
        }
    }

    /// Recently validated bearer paths for the one logical association.
    /// Egress uses [`Self::active_path`]; this list exists for connection
    /// managers that apply idle expiry, explicit path retirement, or future
    /// authenticated path validation without making those bearer concerns
    /// part of stream handling.
    pub const fn known_paths(&self) -> [Option<PathId>; 4] {
        match self.association.as_ref() {
            Some(association) => association.known_paths(),
            None => [None; 4],
        }
    }

    pub const fn association(&self) -> Option<&T> {
        match self.association.as_ref() {
            Some(association) => Some(association.connection()),
            None => None,
        }
    }

    pub fn association_mut(&mut self) -> Option<&mut T> {
        self.association
            .as_mut()
            .map(PathConnection::connection_mut)
    }

    /// Return whether a complete datagram belongs to this server association.
    ///
    /// This is connection demultiplexing, not bearer policy: adapters supply
    /// only an opaque path and the application-owned endpoint supplies its
    /// receive CID. An established packet with that CID is admissible on any
    /// adapter path; once QUIC accepts it, [`PathConnection`] records that
    /// path and makes it the return path. Keeping this here prevents UART,
    /// UDP, and action adapters from growing separate CID parsers or pinning
    /// a connection to the bearer on which it bootstrapped.
    pub fn owns_packet_for_path(
        &self,
        _path: PathId,
        packet: &[u8],
        receive_cid: impl FnOnce(&T) -> Option<crate::ConnectionId>,
    ) -> bool {
        if crate::decode_bootstrap_open_packet_with_limits(packet).is_ok() {
            return true;
        }
        let Ok((header, _)) = crate::ShortHeader::decode(packet) else {
            return false;
        };
        self.association
            .as_ref()
            .is_some_and(|association| receive_cid(association.connection()) == Some(header.dcid))
    }

    /// Decode connection-ID diagnostics inside the connection layer.
    pub fn connection_id_diagnostic(
        &self,
        packet: &[u8],
        receive_cid: impl FnOnce(&T) -> Option<crate::ConnectionId>,
    ) -> ConnectionIdDiagnostic {
        ConnectionIdDiagnostic {
            received: crate::ShortHeader::decode(packet)
                .ok()
                .map(|(header, _)| header.dcid),
            expected: self.association().and_then(receive_cid),
        }
    }

    fn rotate_cid(&mut self, excluded_peer_cid: Option<crate::ConnectionId>) {
        self.cid_epoch = self.cid_epoch.wrapping_add(1).max(1);
        let mut value = self.local_cid.value().wrapping_add(1).max(1);
        if excluded_peer_cid.is_some_and(|cid| cid.value() == value) {
            value = value.wrapping_add(1).max(1);
        }
        self.local_cid =
            crate::ConnectionId::new(value).expect("rotated server CID must remain nonzero");
    }

    /// Route a complete frame, adopting its path only after `receive` accepts
    /// it. A fresh long-header OPEN may replace abandoned state on any path;
    /// established traffic still requires the active connection ID.
    pub fn receive<R>(
        &mut self,
        path: PathId,
        packet: &[u8],
        create: impl FnOnce(crate::ConnectionId) -> T,
        is_live: impl Fn(&T) -> bool,
        receive: impl FnOnce(&mut T) -> Result<R, crate::Error>,
        is_closed: impl Fn(&T) -> bool,
        peer_cid: impl Fn(&T) -> Option<crate::ConnectionId>,
    ) -> Result<ServerConnectionIngress<R>, crate::Error> {
        if let Ok((_, open)) = crate::decode_bootstrap_open_packet_with_limits(packet) {
            if let Some(association) = self.association.as_ref() {
                if is_live(association.connection()) {
                    if peer_cid(association.connection()) == Some(open.client_receive_cid) {
                        // A retransmitted OPEN belongs to the live association and
                        // must receive its deterministic OPEN-ACK again.
                    } else {
                        // A different client bootstrapping on any adapter
                        // replaces the old association. Rotate before construction
                        // so delayed packets cannot enter the new endpoint. This
                        // also reclaims an association when a final CLOSE was lost
                        // as the client moved between UART, NOW, or UDP.
                        self.association = None;
                        self.rotate_cid(Some(open.client_receive_cid));
                    }
                }
            }
            if self.local_cid == open.client_receive_cid {
                self.rotate_cid(Some(open.client_receive_cid));
            }
        } else {
            // Established traffic alone uses the short header. Parsing it
            // here also rejects unknown long-header packet types before they
            // can create endpoint state.
            crate::ShortHeader::decode(packet)?;
        }
        if self.association.is_none() {
            self.association = Some(PathConnection::new(create(self.local_cid)));
        }
        let result = self
            .association
            .as_mut()
            .expect("association just installed")
            .receive(path, receive)?;
        let retired = self
            .association
            .as_ref()
            .is_some_and(|association| is_closed(association.connection()));
        if retired {
            let retired_peer = self
                .association
                .as_ref()
                .and_then(|association| peer_cid(association.connection()));
            self.association = None;
            self.rotate_cid(retired_peer);
        }
        Ok(ServerConnectionIngress::Accepted { result, retired })
    }

    /// Retire the active association after a policy/profile replacement.
    pub fn replace_association(&mut self) {
        self.association = None;
        self.rotate_cid(None);
    }
}

/// Bearer-neutral connection manager boundary.
///
/// Implementations own connection IDs, peer identity, stream allocation, RPC,
/// and forwarding. A physical transport only submits/receives datagrams for
/// the connection manager and never owns these queues or policies.
pub trait ConnectionManager {
    type Error;

    fn configure_connection(&mut self, policy: ConnectionPolicy) -> Result<(), Self::Error>;
}

/// Bearer-neutral client connection driven one complete datagram at a time.
///
/// UART, UDP, NOW, and test adapters supply frames and a monotonic clock.
/// NAN is discovery/activation, not a QUIC stream bearer.
/// They do not inspect connection IDs, streams, retransmission, or completion.
pub trait DatagramClient<const PACKET: usize> {
    fn start(&mut self, output: &mut [u8; PACKET]) -> Result<usize, crate::Error>;
    fn receive_at(
        &mut self,
        input: &[u8],
        now_ms: u64,
        output: &mut [u8; PACKET],
    ) -> Result<Option<usize>, crate::Error>;
    fn accepts(&self, input: &[u8]) -> bool;
    /// Recognize the opaque reset token issued during this association's
    /// OPEN_ACK before the normal short-header CID filter. Bearers must not
    /// parse reset framing themselves: they submit one complete frame and the
    /// common driver turns a matching token into `PeerRestarted`.
    fn is_peer_stateless_reset(&self, _input: &[u8]) -> bool {
        false
    }
    fn is_complete(&self) -> bool;
    fn poll_transmit_at(
        &mut self,
        now_ms: u64,
        output: &mut [u8; PACKET],
    ) -> Result<Option<usize>, crate::Error>;
    fn poll_retransmit(
        &mut self,
        now_us: u64,
        pto_us: u64,
        output: &mut [u8; PACKET],
    ) -> Result<Option<usize>, crate::Error>;
}

/// Bearer-neutral driver for a one-shot complete-datagram client operation.
///
/// The adapter supplies a monotonic clock and moves the bytes returned by
/// [`packet`](Self::packet). This type owns OPEN replay, transport polling,
/// retransmission cadence, completion, and packet counters so UART, UDP,
/// NOW, NAN, and Android adapters do not each grow a private client loop.
pub struct DatagramClientDriver<const PACKET: usize> {
    packet: [u8; PACKET],
    bootstrap: [u8; PACKET],
    pending: Option<usize>,
    bootstrap_len: usize,
    bootstrap_pending: bool,
    last_bootstrap_tx: u64,
    tx_packets: u64,
    rx_packets: u64,
    retransmit_packets: u64,
}

impl<const PACKET: usize> DatagramClientDriver<PACKET> {
    pub fn start<C: DatagramClient<PACKET>>(
        client: &mut C,
        now: u64,
    ) -> Result<Self, crate::Error> {
        let mut packet = [0u8; PACKET];
        let used = client.start(&mut packet)?;
        if used > PACKET {
            return Err(crate::Error::BufferTooSmall);
        }
        let mut bootstrap = [0u8; PACKET];
        bootstrap[..used].copy_from_slice(&packet[..used]);
        Ok(Self {
            packet,
            bootstrap,
            pending: Some(used),
            bootstrap_len: used,
            bootstrap_pending: true,
            last_bootstrap_tx: now,
            tx_packets: 0,
            rx_packets: 0,
            retransmit_packets: 0,
        })
    }

    /// Begin driving an already-established association from one caller-made
    /// packet. This is the counterpart to [`start`](Self::start) for a later
    /// stream request: it retains the same receive/poll/retransmission loop
    /// without replaying an Initial OPEN.
    pub fn from_packet(packet: &[u8], now: u64) -> Result<Self, crate::Error> {
        if packet.is_empty() || packet.len() > PACKET {
            return Err(crate::Error::BufferTooSmall);
        }
        let mut stored = [0u8; PACKET];
        stored[..packet.len()].copy_from_slice(packet);
        Ok(Self {
            packet: stored,
            bootstrap: [0u8; PACKET],
            pending: Some(packet.len()),
            bootstrap_len: 0,
            bootstrap_pending: false,
            last_bootstrap_tx: now,
            tx_packets: 0,
            rx_packets: 0,
            retransmit_packets: 0,
        })
    }

    pub fn packet(&self) -> Option<&[u8]> {
        self.pending.map(|used| &self.packet[..used])
    }

    pub fn mark_sent(&mut self, now: u64) {
        if self.pending.take().is_some() {
            self.tx_packets = self.tx_packets.saturating_add(1);
            if self.bootstrap_pending {
                self.last_bootstrap_tx = now;
            }
        }
    }

    /// Admit one received datagram. `Ok(false)` means it belongs to another
    /// connection and was not passed to the client parser.
    pub fn receive<C: DatagramClient<PACKET>>(
        &mut self,
        client: &mut C,
        input: &[u8],
        now: u64,
    ) -> Result<bool, crate::Error> {
        if client.is_peer_stateless_reset(input) {
            return Err(crate::Error::PeerRestarted);
        }
        if !client.accepts(input) {
            return Ok(false);
        }
        self.bootstrap_pending = false;
        self.rx_packets = self.rx_packets.saturating_add(1);
        self.pending = client.receive_at(input, now, &mut self.packet)?;
        Ok(true)
    }

    /// Poll delayed control, established-packet retransmission, and finally
    /// bounded OPEN replay. Returns whether a packet is ready for the adapter.
    pub fn poll<C: DatagramClient<PACKET>>(
        &mut self,
        client: &mut C,
        now: u64,
        pto: u64,
        bootstrap_retry: u64,
    ) -> Result<bool, crate::Error> {
        if self.pending.is_some() {
            return Ok(true);
        }
        self.pending = client.poll_transmit_at(now, &mut self.packet)?;
        if self.pending.is_some() {
            return Ok(true);
        }
        self.pending = client.poll_retransmit(now, pto, &mut self.packet)?;
        if self.pending.is_some() {
            self.retransmit_packets = self.retransmit_packets.saturating_add(1);
            return Ok(true);
        }
        if self.bootstrap_len != 0
            && self.bootstrap_pending
            && now.saturating_sub(self.last_bootstrap_tx) >= bootstrap_retry
        {
            self.packet[..self.bootstrap_len]
                .copy_from_slice(&self.bootstrap[..self.bootstrap_len]);
            self.pending = Some(self.bootstrap_len);
            self.retransmit_packets = self.retransmit_packets.saturating_add(1);
            return Ok(true);
        }
        Ok(false)
    }

    pub const fn tx_packets(&self) -> u64 {
        self.tx_packets
    }

    pub const fn rx_packets(&self) -> u64 {
        self.rx_packets
    }

    pub const fn retransmit_packets(&self) -> u64 {
        self.retransmit_packets
    }
}

/// Result of admitting one packet through the client bootstrap boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientBootstrapIngress {
    /// The OPEN-ACK established the endpoint and encoded the first request.
    RequestEncoded(usize),
    /// A duplicate OPEN-ACK for the already installed peer CID was ignored.
    DuplicateAck,
    /// The endpoint was already established; process this as a normal packet.
    EstablishedPacket,
}

/// Shared client-side OPEN, CID, packet-number, and endpoint lifecycle.
///
/// Application clients retain only their request/response state. This core is
/// deliberately unaware of tagged CBOR, object records, or probe payloads.
pub struct ClientConnection<const HISTORY: usize, const PACKET: usize> {
    local_cid: crate::ConnectionId,
    local_limits: crate::ConnectionLimits,
    peer_cid: Option<crate::ConnectionId>,
    peer_reset_token: Option<crate::StatelessResetToken>,
    endpoint: Option<crate::EndpointState<{ crate::DEFAULT_STREAM_STATE_SLOTS }, HISTORY, PACKET>>,
    started: bool,
    open_packet_number: u32,
}

/// Locally initiated persistent stream connection with bounded bootstrap
/// retries and an optional first request. This contains no application or
/// bearer behavior and is shared by host and firmware adapters.
pub struct ClientStreamConnection<
    const HISTORY: usize,
    const PACKET: usize = { crate::DEFAULT_MAX_DATAGRAM_SIZE },
> {
    // The association owns endpoint framing and packet state.  Callers use
    // `mux()` only for read-only diagnostics or `mux_mut()` while the legacy
    // adapter migration is in progress; no bearer may replace it.
    mux: crate::mux::StreamMux<4, HISTORY, PACKET>,
    bootstrap: Option<crate::BootstrapClient>,
    pending_request: Option<Vec<u8>>,
}

impl<const HISTORY: usize, const PACKET: usize> ClientStreamConnection<HISTORY, PACKET> {
    pub fn new(
        local_cid: crate::ConnectionId,
        retry_timeout_us: u64,
        max_attempts: u8,
        request: Option<Vec<u8>>,
    ) -> Result<Self, crate::Error> {
        Ok(Self {
            mux: crate::mux::StreamMux::new(
                crate::Role::Client,
                crate::ConnectionLimits::default(),
                PACKET as u64,
                1,
                4,
                4096,
            ),
            bootstrap: Some(crate::BootstrapClient::new(
                local_cid,
                retry_timeout_us,
                max_attempts,
            )?),
            pending_request: request,
        })
    }

    pub fn start_open(&mut self, now_us: u64, out: &mut [u8]) -> Result<usize, crate::Error> {
        self.bootstrap
            .as_mut()
            .ok_or(crate::Error::BootstrapInvalid)?
            .start_open(now_us, out)
    }

    pub fn receive_open_ack_and_request(
        &mut self,
        packet: &[u8],
        out: &mut [u8],
    ) -> Result<Option<usize>, crate::Error> {
        let bootstrap = self
            .bootstrap
            .as_mut()
            .ok_or(crate::Error::BootstrapInvalid)?;
        let peer = bootstrap.on_open_ack(packet)?;
        let (ack_header, _) =
            crate::decode_bootstrap_open_ack_packet(packet, bootstrap.local_cid())?;
        self.mux
            .install_connection_ids(bootstrap.local_cid(), peer)?;
        self.mux
            .endpoint
            .continue_packet_numbers_from(ack_header.packet_number.saturating_add(1))?;
        self.bootstrap = None;
        let Some(request) = self.pending_request.take() else {
            return Ok(None);
        };
        self.mux.endpoint.open_send_stream(
            crate::FIRST_CLIENT_BIDI_STREAM_ID,
            crate::INITIAL_MAX_STREAM_DATA,
        )?;
        let (used, _) = self.mux.endpoint.encode_stream_packet(
            peer,
            crate::FIRST_CLIENT_BIDI_STREAM_ID,
            0,
            true,
            &request,
            out,
        )?;
        Ok(Some(used))
    }

    pub const fn mux(&self) -> &crate::mux::StreamMux<4, HISTORY, PACKET> {
        &self.mux
    }

    pub fn mux_mut(&mut self) -> &mut crate::mux::StreamMux<4, HISTORY, PACKET> {
        &mut self.mux
    }
}

impl<const HISTORY: usize, const PACKET: usize> ClientConnection<HISTORY, PACKET> {
    pub fn new(local_cid: crate::ConnectionId) -> Self {
        Self::with_limits(local_cid, crate::ConnectionLimits::default())
    }

    pub const fn with_limits(
        local_cid: crate::ConnectionId,
        local_limits: crate::ConnectionLimits,
    ) -> Self {
        Self {
            local_cid,
            local_limits,
            peer_cid: None,
            peer_reset_token: None,
            endpoint: None,
            started: false,
            open_packet_number: 0,
        }
    }

    pub const fn local_cid(&self) -> crate::ConnectionId {
        self.local_cid
    }

    pub const fn peer_cid(&self) -> Option<crate::ConnectionId> {
        self.peer_cid
    }

    /// Classify an opaque packet as a peer restart only after normal CID and
    /// packet parsing failed.  The token was received in the peer's Initial
    /// OPEN_ACK, so no bearer needs to decode or retain reset state.
    pub fn is_peer_stateless_reset(&self, input: &[u8]) -> bool {
        self.peer_reset_token
            .is_some_and(|token| token.matches_packet(input))
    }

    pub const fn is_started(&self) -> bool {
        self.started
    }

    pub const fn is_established(&self) -> bool {
        self.endpoint.is_some()
    }

    pub fn accepts(&self, input: &[u8]) -> bool {
        crate::ShortHeader::decode(input).is_ok_and(|(header, _)| header.dcid == self.local_cid)
            || (self.started
                && crate::decode_bootstrap_open_ack_packet_with_limits(input, self.local_cid)
                    .is_ok())
    }

    pub fn start(&mut self, output: &mut [u8; PACKET]) -> Result<usize, crate::Error> {
        if self.started {
            return Err(crate::Error::Invalid);
        }
        self.started = true;
        self.open_packet_number = 0;
        self.encode_open(output)
    }

    /// Encode a numbered OPEN attempt for adapters with an explicit retry
    /// loop. The connection remembers the last bootstrap packet number so
    /// established application packets continue in the same sender space.
    pub fn encode_open_attempt(
        &mut self,
        packet_number: u32,
        output: &mut [u8; PACKET],
    ) -> Result<usize, crate::Error> {
        if self.is_established() {
            return Err(crate::Error::Invalid);
        }
        self.started = true;
        self.open_packet_number = packet_number;
        self.encode_open(output)
    }

    fn encode_open(&self, output: &mut [u8; PACKET]) -> Result<usize, crate::Error> {
        crate::encode_bootstrap_open_packet_with_profile(
            self.local_cid,
            self.open_packet_number,
            self.local_limits,
            0,
            output,
        )
    }

    /// Establish on an OPEN-ACK and encode the first client request, or
    /// classify a packet for an already established endpoint.
    pub fn receive_bootstrap(
        &mut self,
        input: &[u8],
        now_ms: u64,
        request: &[u8],
        output: &mut [u8; PACKET],
    ) -> Result<ClientBootstrapIngress, crate::Error> {
        if !self.started {
            return Err(crate::Error::Invalid);
        }
        if self.endpoint.is_none() {
            self.receive_open_ack(input, now_ms)?;
            let peer_cid = self.peer_cid.ok_or(crate::Error::Invalid)?;
            let endpoint = self.endpoint.as_mut().ok_or(crate::Error::Invalid)?;
            endpoint.open_send_stream(
                crate::FIRST_CLIENT_BIDI_STREAM_ID,
                crate::INITIAL_MAX_STREAM_DATA,
            )?;
            let (used, _) = endpoint.encode_stream_packet(
                peer_cid,
                crate::FIRST_CLIENT_BIDI_STREAM_ID,
                0,
                true,
                request,
                output,
            )?;
            return Ok(ClientBootstrapIngress::RequestEncoded(used));
        }
        if let Ok((_, ack)) =
            crate::decode_bootstrap_open_ack_packet_with_limits(input, self.local_cid)
        {
            if self.peer_cid == Some(ack.server_receive_cid) {
                return Ok(ClientBootstrapIngress::DuplicateAck);
            }
        }
        Ok(ClientBootstrapIngress::EstablishedPacket)
    }

    /// Install one OPEN-ACK without opening an application stream.
    /// Returns `true` for a newly established endpoint and `false` for a
    /// duplicate ACK belonging to the already installed peer.
    pub fn receive_open_ack(&mut self, input: &[u8], now_ms: u64) -> Result<bool, crate::Error> {
        if !self.started {
            return Err(crate::Error::Invalid);
        }
        let (_, ack) = crate::decode_bootstrap_open_ack_packet_with_limits(input, self.local_cid)?;
        if self.endpoint.is_some() {
            return if self.peer_cid == Some(ack.server_receive_cid) {
                Ok(false)
            } else {
                Err(crate::Error::WrongConnectionId)
            };
        }
        let mut endpoint =
            crate::EndpointState::new(crate::Role::Client, self.local_limits, PACKET as u64);
        endpoint.set_time(now_ms);
        endpoint.install_connection_ids(self.local_cid, ack.server_receive_cid)?;
        endpoint.set_initial_peer_credit(ack.max_data, ack.max_stream_data)?;
        endpoint.continue_packet_numbers_from(self.open_packet_number.saturating_add(1))?;
        self.peer_cid = Some(ack.server_receive_cid);
        self.peer_reset_token = ack.stateless_reset_token;
        self.endpoint = Some(endpoint);
        Ok(true)
    }

    pub fn endpoint(
        &self,
    ) -> Option<&crate::EndpointState<{ crate::DEFAULT_STREAM_STATE_SLOTS }, HISTORY, PACKET>> {
        self.endpoint.as_ref()
    }

    pub fn endpoint_mut(
        &mut self,
    ) -> Result<
        &mut crate::EndpointState<{ crate::DEFAULT_STREAM_STATE_SLOTS }, HISTORY, PACKET>,
        crate::Error,
    > {
        self.endpoint.as_mut().ok_or(crate::Error::Invalid)
    }

    pub fn poll_transmit(
        &mut self,
        output: &mut [u8; PACKET],
    ) -> Result<Option<usize>, crate::Error> {
        self.endpoint
            .as_mut()
            .map_or(Ok(None), |endpoint| endpoint.poll_transmit(output))
    }

    pub fn poll_transmit_at(
        &mut self,
        now_ms: u64,
        output: &mut [u8; PACKET],
    ) -> Result<Option<usize>, crate::Error> {
        let Some(endpoint) = self.endpoint.as_mut() else {
            return Ok(None);
        };
        endpoint.set_time(now_ms);
        endpoint.poll_transmit(output)
    }

    pub fn poll_close(&mut self, output: &mut [u8; PACKET]) -> Result<Option<usize>, crate::Error> {
        self.endpoint
            .as_mut()
            .map_or(Ok(None), |endpoint| endpoint.poll_close(output))
    }

    pub fn poll_retransmit(
        &mut self,
        now_us: u64,
        pto_us: u64,
        output: &mut [u8; PACKET],
    ) -> Result<Option<usize>, crate::Error> {
        let Some(endpoint) = self.endpoint.as_mut() else {
            return Ok(None);
        };
        Ok(endpoint
            .retransmit_due(now_us, pto_us, output)?
            .map(|(used, _)| used))
    }
}

/// One logical client-side QUIC association with adapter-owned paths.
///
/// A connection manager keys this object by a stable device identity once
/// discovery/authentication has supplied one.  A UDP tuple, NOW MAC, or UART
/// port is only a [`PathId`]: choosing one with [`Self::select_path`] sends a
/// particular operation there, but does not create another CID or another
/// handshake.  Any subsequently accepted QUIC packet makes its ingress path
/// the normal return path.  The manager above this no-std core owns path I/O,
/// identity binding, idle-close policy, and application request correlation.
pub struct ClientAssociation<const HISTORY: usize, const PACKET: usize> {
    state: PathConnection<ClientConnection<HISTORY, PACKET>>,
    /// Client-initiated bidirectional stream IDs are association state, not
    /// bearer state. A caller may select UART, NOW, or UDP for an operation,
    /// but it must never restart this sequence merely because the path
    /// changes.
    next_client_bidi_stream_id: u64,
    /// Server-initiated response stream correlation belongs to the
    /// association as well.  A delayed final frame remains a delayed frame
    /// after the client moves the request from NOW to UDP or UART.
    next_server_response_stream_id: Option<u64>,
    active_server_response_stream_id: Option<u64>,
}

/// One admitted stream payload projected from an association packet.
///
/// This is the narrowest packet-derived fact needed by a normal stream
/// consumer.  The consumer never receives a QUIC header, CID, packet number,
/// or endpoint object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AssociationStreamPayload<'a> {
    pub stream_id: u64,
    pub offset: u64,
    pub fin: bool,
    pub data: &'a [u8],
}

impl<const HISTORY: usize, const PACKET: usize> ClientAssociation<HISTORY, PACKET> {
    pub fn new(local_cid: crate::ConnectionId) -> Self {
        Self::with_limits(local_cid, crate::ConnectionLimits::default())
    }

    pub const fn with_limits(
        local_cid: crate::ConnectionId,
        local_limits: crate::ConnectionLimits,
    ) -> Self {
        Self {
            state: PathConnection::new(ClientConnection::with_limits(local_cid, local_limits)),
            next_client_bidi_stream_id: crate::FIRST_CLIENT_BIDI_STREAM_ID,
            next_server_response_stream_id: None,
            active_server_response_stream_id: None,
        }
    }

    pub const fn connection(&self) -> &ClientConnection<HISTORY, PACKET> {
        self.state.connection()
    }

    pub fn connection_mut(&mut self) -> &mut ClientConnection<HISTORY, PACKET> {
        self.state.connection_mut()
    }

    pub const fn active_path(&self) -> Option<PathId> {
        self.state.active_path()
    }

    pub const fn selected_path(&self) -> Option<PathId> {
        self.state.selected_path()
    }

    pub const fn egress_path(&self) -> Option<PathId> {
        self.state.egress_path()
    }

    pub const fn known_paths(&self) -> [Option<PathId>; 4] {
        self.state.known_paths()
    }

    /// Select the exact adapter path for a caller's next outbound operation.
    /// This is the core representation of a `to` selector; it is not a new
    /// connection and is not treated as validated peer-path evidence.
    pub fn select_path(&mut self, path: PathId) {
        self.state.select_path(path);
    }

    pub fn clear_selected_path(&mut self) {
        self.state.clear_selected_path();
    }

    /// Allocate the next client-initiated bidirectional stream for this
    /// association. The stream-ID namespace is shared by every current and
    /// future path; adapters receive only the resulting stream ID.
    pub fn allocate_client_bidi_stream(&mut self) -> Result<u64, crate::Error> {
        let stream = self.next_client_bidi_stream_id;
        self.next_client_bidi_stream_id = self
            .next_client_bidi_stream_id
            .checked_add(4)
            .ok_or(crate::Error::StreamLimit)?;
        Ok(stream)
    }

    /// Admit a server-initiated response stream for the serialized request
    /// caller.  The first server stream is learned because QUIC permits the
    /// peer to choose its initial server stream class.  Thereafter response
    /// streams advance by four.  Lower delayed streams are already-completed
    /// duplicates; a higher stream would be an unimplemented concurrent or
    /// unsolicited response and is rejected rather than mis-correlated.
    ///
    /// This only exposes stream facts to callers: packet framing and CID
    /// ownership stay private to QUIC-lite.
    pub fn accept_server_response_stream(
        &mut self,
        stream_id: u64,
        fin: bool,
    ) -> Result<bool, crate::Error> {
        let expected = self
            .active_server_response_stream_id
            .or(self.next_server_response_stream_id);
        let Some(expected) = expected else {
            self.active_server_response_stream_id = Some(stream_id);
            if fin {
                self.active_server_response_stream_id = None;
                self.next_server_response_stream_id = Some(stream_id.saturating_add(4));
            }
            return Ok(true);
        };
        if stream_id < expected {
            return Ok(false);
        }
        if stream_id != expected {
            return Err(crate::Error::Invalid);
        }
        self.active_server_response_stream_id = Some(stream_id);
        if fin {
            self.active_server_response_stream_id = None;
            self.next_server_response_stream_id = Some(expected.saturating_add(4));
        }
        Ok(true)
    }

    /// Whether the serialized response consumer is waiting for FIN on its
    /// current server-initiated stream.
    pub const fn has_active_server_response_stream(&self) -> bool {
        self.active_server_response_stream_id.is_some()
    }

    /// Encode the client Initial for the selected path. The returned path is
    /// deliberately explicit so a frame adapter cannot infer CID ownership.
    pub fn start(&mut self, output: &mut [u8; PACKET]) -> Result<(PathId, usize), crate::Error> {
        let path = self.egress_path().ok_or(crate::Error::Invalid)?;
        let used = self.connection_mut().start(output)?;
        Ok((path, used))
    }

    /// Encode a numbered Initial attempt for the currently selected path.
    ///
    /// This is deliberately an association operation rather than an adapter
    /// call to `ClientConnection`: a UDP, UART, or NOW adapter only injects
    /// the returned complete frame and must not learn bootstrap/CID details.
    pub fn encode_open_attempt(
        &mut self,
        packet_number: u32,
        output: &mut [u8; PACKET],
    ) -> Result<(PathId, usize), crate::Error> {
        let path = self.egress_path().ok_or(crate::Error::Invalid)?;
        let used = self
            .connection_mut()
            .encode_open_attempt(packet_number, output)?;
        Ok((path, used))
    }

    /// Admit an OPEN_ACK received on `path`. Long-header parsing, CID
    /// matching, and stateless-reset recognition remain private association
    /// policy; the frame adapter supplies only the complete packet.
    pub fn receive_open_ack(
        &mut self,
        path: PathId,
        input: &[u8],
        now_ms: u64,
    ) -> Result<(), crate::Error> {
        self.receive(path, input, |connection| {
            connection.receive_open_ack(input, now_ms).map(|_| ())
        })
    }

    /// Encode one ordinary client-initiated stream payload.  Handlers and
    /// frame-I/O adapters work with stream bytes; packet headers, peer CIDs,
    /// and send-credit accounting stay inside QUIC-lite.
    pub fn encode_stream_payload(
        &mut self,
        stream_id: u64,
        data: &[u8],
        fin: bool,
        output: &mut [u8; PACKET],
    ) -> Result<(PathId, usize), crate::Error> {
        let path = self.egress_path().ok_or(crate::Error::Invalid)?;
        let connection = self.connection_mut();
        let destination = connection
            .peer_cid()
            .unwrap_or_else(|| connection.local_cid());
        let endpoint = connection.endpoint_mut()?;
        endpoint.open_send_stream(stream_id, crate::INITIAL_MAX_STREAM_DATA)?;
        let (used, _) =
            endpoint.encode_stream_packet(destination, stream_id, 0, fin, data, output)?;
        Ok((path, used))
    }

    /// Admit one complete packet and project a normal stream frame to payload
    /// facts. No bearer caller decodes QUIC frames or packet headers.
    pub fn receive_stream_payload<'a>(
        &mut self,
        path: PathId,
        input: &'a [u8],
    ) -> Result<Option<(u64, u64, bool, &'a [u8])>, crate::Error> {
        self.receive(path, input, |connection| {
            let packet = connection.endpoint_mut()?.receive_datagram(input)?;
            Ok(match packet {
                crate::TransportPacket::Control => None,
                crate::TransportPacket::Stream { frame, .. } => {
                    Some((frame.id, frame.offset, frame.fin, frame.data))
                }
            })
        })
    }

    /// Admit the next payload for the serialized request/response consumer.
    ///
    /// A completed lower-numbered response is a harmless delayed duplicate;
    /// it is consumed and omitted.  A higher stream is rejected so an
    /// unsolicited peer stream cannot be attached to the active request.
    /// This is association policy, not an adapter decision: moving a request
    /// between UART, NOW, and UDP preserves the same response sequence.
    pub fn receive_serial_response_payload<'a>(
        &mut self,
        path: PathId,
        input: &'a [u8],
        deferred_credit: bool,
    ) -> Result<Option<AssociationStreamPayload<'a>>, crate::Error> {
        let Some((stream_id, offset, fin, data)) = self.receive_stream_payload(path, input)? else {
            return Ok(None);
        };
        if !self.accept_server_response_stream(stream_id, fin)? {
            return Ok(None);
        }
        self.stream_consumed(stream_id, data.len(), deferred_credit)?;
        Ok(Some(AssociationStreamPayload {
            stream_id,
            offset,
            fin,
            data,
        }))
    }

    /// Return receive credit after the application has accepted payload bytes.
    pub fn stream_consumed(
        &mut self,
        stream_id: u64,
        bytes: usize,
        deferred: bool,
    ) -> Result<(), crate::Error> {
        let endpoint = self.connection_mut().endpoint_mut()?;
        if deferred {
            endpoint.stream_consumed_deferred(stream_id, bytes)
        } else {
            endpoint.stream_consumed(stream_id, bytes)
        }
    }

    /// True only for the reset token issued to this association. Frame
    /// adapters use this before discarding a delayed packet; they never parse
    /// the opaque reset body themselves.
    pub fn is_peer_stateless_reset(&self, input: &[u8]) -> bool {
        self.connection().is_peer_stateless_reset(input)
    }

    pub fn peer_cid(&self) -> Option<crate::ConnectionId> {
        self.connection().peer_cid()
    }

    /// Continue the established packet number space after an accepted
    /// long-header setup response. This is setup state, not an adapter policy.
    pub fn continue_packet_numbers_from(&mut self, next: u32) -> Result<(), crate::Error> {
        self.connection_mut()
            .endpoint_mut()?
            .continue_packet_numbers_from(next)
    }

    /// Admit a frame only after the client CID/bootstrap boundary recognizes
    /// it. `receive` is supplied by the connection manager and may decode
    /// stream frames or complete a request; a failure leaves path state
    /// unchanged.
    pub fn receive<R>(
        &mut self,
        path: PathId,
        input: &[u8],
        receive: impl FnOnce(&mut ClientConnection<HISTORY, PACKET>) -> Result<R, crate::Error>,
    ) -> Result<R, crate::Error> {
        if !self.connection().accepts(input) {
            if self.connection().is_peer_stateless_reset(input) {
                return Err(crate::Error::PeerRestarted);
            }
            return Err(crate::Error::WrongConnectionId);
        }
        self.state.receive(path, receive)
    }

    /// Poll a queued connection-layer packet and pair it with the path the
    /// adapter must write. Normal queued traffic follows the latest valid
    /// ingress unless a caller has selected a path for its immediate request.
    pub fn poll_transmit(
        &mut self,
        output: &mut [u8; PACKET],
    ) -> Result<Option<(PathId, usize)>, crate::Error> {
        let Some(path) = self.egress_path() else {
            return Ok(None);
        };
        Ok(self
            .connection_mut()
            .poll_transmit(output)?
            .map(|used| (path, used)))
    }

    /// Poll the association CLOSE on the selected or current return path.
    /// The caller may then drop this association once that frame has been
    /// injected, or retain it until its manager's idle policy expires.
    pub fn poll_close(
        &mut self,
        output: &mut [u8; PACKET],
    ) -> Result<Option<(PathId, usize)>, crate::Error> {
        let Some(path) = self.egress_path() else {
            return Ok(None);
        };
        Ok(self
            .connection_mut()
            .poll_close(output)?
            .map(|used| (path, used)))
    }

    /// Poll a PTO/loss retransmission on the selected or current return path.
    /// Packet timing and retransmission history remain in QUIC-lite; frame
    /// adapters only write the selected complete datagram.
    pub fn poll_retransmit(
        &mut self,
        now_us: u64,
        pto_us: u64,
        output: &mut [u8; PACKET],
    ) -> Result<Option<(PathId, usize)>, crate::Error> {
        let Some(path) = self.egress_path() else {
            return Ok(None);
        };
        Ok(self
            .connection_mut()
            .poll_retransmit(now_us, pto_us, output)?
            .map(|used| (path, used)))
    }
}

impl<const HISTORY: usize, const PACKET: usize> mesh_api::MeshAssociation
    for ClientAssociation<HISTORY, PACKET>
{
    type Error = crate::Error;
    type Path = PathId;

    fn selected_path(&self) -> Option<Self::Path> {
        self.selected_path()
    }

    fn active_path(&self) -> Option<Self::Path> {
        self.active_path()
    }

    fn known_paths(&self) -> [Option<Self::Path>; 4] {
        self.known_paths()
    }

    fn select_path(&mut self, path: Self::Path) {
        self.select_path(path);
    }

    fn clear_selected_path(&mut self) {
        self.clear_selected_path();
    }
}

/// Runtime connection limits negotiated for a complete-datagram path.
///
/// The const history size is an allocation ceiling. These values select what
/// one association advertises and retains, independently of its bearer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AssociationProfile {
    pub history_packets: usize,
    pub ack_frequency: u8,
    pub ack_delay_ms: u8,
    pub tx_burst_packets: usize,
    pub initial_window_packets: usize,
}

impl AssociationProfile {
    pub const fn conservative() -> Self {
        Self {
            history_packets: 1,
            ack_frequency: 1,
            ack_delay_ms: 5,
            tx_burst_packets: 1,
            initial_window_packets: 1,
        }
    }

    pub const fn c6_default() -> Self {
        Self {
            history_packets: 8,
            ack_frequency: 8,
            ack_delay_ms: 5,
            tx_burst_packets: 8,
            initial_window_packets: 8,
        }
    }

    pub fn clamp<const HISTORY: usize>(self) -> Self {
        Self {
            history_packets: self.history_packets.clamp(1, HISTORY),
            ack_frequency: self.ack_frequency.clamp(1, crate::ACK_RANGE_CAPACITY as u8),
            ack_delay_ms: self.ack_delay_ms.clamp(1, 25),
            tx_burst_packets: self.tx_burst_packets.clamp(1, HISTORY),
            initial_window_packets: self.initial_window_packets.clamp(1, HISTORY),
        }
    }
}

/// Stable compact diagnostic code for a connection error at an adapter edge.
pub const fn receive_error_code(error: crate::Error) -> u8 {
    match error {
        crate::Error::BufferTooSmall => 1,
        crate::Error::Truncated => 2,
        crate::Error::Invalid => 3,
        crate::Error::InvalidVarint => 4,
        crate::Error::FlowControl => 5,
        crate::Error::StreamLimit => 6,
        crate::Error::PacketNumberExhausted => 7,
        crate::Error::WrongConnectionId => 8,
        crate::Error::PeerRestarted => 12,
        crate::Error::BootstrapInvalid => 9,
        crate::Error::HistoryFull => 10,
        crate::Error::RetransmissionTooLarge => 11,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listener_classification_keeps_direct_initial_and_established_distinct() {
        let client = crate::ConnectionId::new(0x31).unwrap();
        let server = crate::ConnectionId::new(0x47).unwrap();
        let mut packet = [0u8; 256];
        let mut direct_packet = [0u8; 256];

        let direct_len = crate::DirectMessageEndpoint::new()
            .send(b"bounded direct", &mut direct_packet)
            .unwrap();
        assert_eq!(
            classify_server_datagram(&direct_packet[..direct_len]),
            Ok(ServerDatagram::Direct)
        );

        let initial_len = crate::encode_bootstrap_open_packet(client, 0, &mut packet).unwrap();
        assert!(matches!(
            classify_server_datagram(&packet[..initial_len]),
            Ok(ServerDatagram::Initial(open)) if open.client_receive_cid == client
        ));

        let ack_len = crate::encode_bootstrap_open_ack_packet(client, server, 0, &mut packet)
            .unwrap();
        assert_eq!(
            classify_server_datagram(&packet[..ack_len]),
            Ok(ServerDatagram::BootstrapAck {
                destination: client,
            })
        );

        let established_len = crate::ShortHeader {
            flags: crate::FLAG_FIXED,
            dcid: server,
            packet_number: 1,
            packet_number_len: 1,
        }
        .encode(&mut packet)
        .unwrap();
        assert_eq!(
            classify_server_datagram(&packet[..established_len]),
            Ok(ServerDatagram::Established {
                destination: server,
            })
        );
        // Association owners reject the connectionless envelope rather than
        // mistaking it for a short-header stream packet.
        assert_eq!(
            classify_server_packet(&direct_packet[..direct_len]),
            Err(crate::Error::Invalid)
        );
    }

    #[test]
    fn mesh_api_association_exposes_selected_active_and_known_paths() {
        use mesh_api::MeshAssociation;

        let cid = crate::ConnectionId::new(0x61).unwrap();
        let uart = PathId::new(1).unwrap();
        let udp = PathId::new(2).unwrap();
        let mut association = ClientAssociation::<4, 256>::new(cid);
        assert_eq!(MeshAssociation::selected_path(&association), None);
        assert_eq!(MeshAssociation::active_path(&association), None);
        association.select_path(uart);
        assert_eq!(MeshAssociation::selected_path(&association), Some(uart));

        // A valid inbound frame is what verifies/activates a return path; a
        // caller's selection alone does not fabricate path history.
        association
            .state
            .receive(udp, |_| Ok::<_, crate::Error>(()))
            .unwrap();
        assert_eq!(MeshAssociation::active_path(&association), Some(udp));
        assert_eq!(MeshAssociation::known_paths(&association)[0], Some(udp));
        association.clear_selected_path();
        assert_eq!(MeshAssociation::selected_path(&association), None);
    }

    #[test]
    fn policy_has_no_bearer_identity() {
        let policy = ConnectionPolicy {
            ack_frequency: Some(8),
            tx_burst_packets: Some(16),
            ..ConnectionPolicy::default()
        };
        assert_eq!(policy.ack_frequency, Some(8));
        assert_eq!(policy.tx_burst_packets, Some(16));
    }

    #[test]
    fn latest_valid_frame_changes_path_without_replacing_connection() {
        let uart = PathId::new(1).unwrap();
        let udp = PathId::new(2).unwrap();
        let mut connection = PathConnection::new(40_u64);

        connection
            .receive(uart, |packet_number| {
                *packet_number += 1;
                Ok::<_, ()>(())
            })
            .unwrap();
        connection
            .receive(udp, |packet_number| {
                *packet_number += 1;
                Ok::<_, ()>(())
            })
            .unwrap();

        assert_eq!(connection.active_path(), Some(udp));
        assert_eq!(*connection.connection(), 42);
    }

    #[test]
    fn rejected_frame_cannot_redirect_return_path() {
        let uart = PathId::new(1).unwrap();
        let hostile = PathId::new(9).unwrap();
        let mut connection = PathConnection::new(7_u64);
        connection
            .receive(uart, |_| Ok::<_, &'static str>(()))
            .unwrap();

        let error = connection
            .receive(hostile, |_| Err::<(), _>("unknown dcid"))
            .unwrap_err();

        assert_eq!(error, "unknown dcid");
        assert_eq!(connection.active_path(), Some(uart));
        assert_eq!(*connection.connection(), 7);
    }

    #[test]
    fn association_profile_is_bounded_by_connection_storage() {
        let profile = AssociationProfile {
            history_packets: 40,
            ack_frequency: 40,
            ack_delay_ms: 0,
            tx_burst_packets: 40,
            initial_window_packets: 40,
        }
        .clamp::<8>();

        assert_eq!(profile.history_packets, 8);
        assert_eq!(profile.ack_frequency, crate::ACK_RANGE_CAPACITY as u8);
        assert_eq!(profile.ack_delay_ms, 1);
        assert_eq!(profile.tx_burst_packets, 8);
        assert_eq!(profile.initial_window_packets, 8);
    }

    #[test]
    fn connection_error_codes_are_stable_for_adapter_diagnostics() {
        assert_eq!(receive_error_code(crate::Error::WrongConnectionId), 8);
        assert_eq!(receive_error_code(crate::Error::PeerRestarted), 12);
        assert_eq!(receive_error_code(crate::Error::BootstrapInvalid), 9);
        assert_eq!(receive_error_code(crate::Error::HistoryFull), 10);
    }

    #[test]
    fn association_reports_peer_restart_before_a_timeout() {
        let client_cid = crate::ConnectionId::new(0x41).unwrap();
        let server_cid = crate::ConnectionId::new(0x42).unwrap();
        let path = PathId::new(7).unwrap();
        let reset_key = crate::StatelessResetKey::from_device_secret(&[0x33; 32]).unwrap();
        let mut association = ClientAssociation::<4, 1200>::new(client_cid);
        let mut packet = [0u8; 1200];
        association.select_path(path);
        association.start(&mut packet).unwrap();
        let ack_len = crate::encode_bootstrap_open_ack_packet_with_limits_and_reset_token(
            client_cid,
            server_cid,
            0,
            crate::ConnectionLimits::default(),
            Some(reset_key.token_for(server_cid)),
            &mut packet,
        )
        .unwrap();
        association
            .receive(path, &packet[..ack_len], |connection| {
                connection.receive_open_ack(&packet[..ack_len], 0)
            })
            .unwrap();

        let mut stale = [0u8; 48];
        let stale_len = reset_key
            .encode_for_unknown_cid(&[crate::FLAG_FIXED; 48], server_cid, &mut stale)
            .unwrap()
            .unwrap();
        assert_eq!(
            association.receive(path, &stale[..stale_len], |_| Ok::<_, crate::Error>(())),
            Err(crate::Error::PeerRestarted)
        );
        // A reset is not valid association traffic and cannot redirect the
        // current return path.
        assert_eq!(association.active_path(), Some(path));
    }

    #[test]
    fn client_connection_owns_bootstrap_cids_and_first_request() {
        let client_cid = crate::ConnectionId::new(0x41).unwrap();
        let server_cid = crate::ConnectionId::new(0x42).unwrap();
        let mut connection = ClientConnection::<4, 1200>::new(client_cid);
        let mut packet = [0u8; 1200];

        let open_len = connection.start(&mut packet).unwrap();
        assert_eq!(
            crate::decode_bootstrap_open_packet(&packet[..open_len])
                .unwrap()
                .1,
            client_cid
        );

        let mut ack = [0u8; 1200];
        let ack_len = crate::encode_bootstrap_open_ack_packet_with_limits(
            client_cid,
            server_cid,
            0,
            crate::ConnectionLimits::default(),
            &mut ack,
        )
        .unwrap();
        let ingress = connection
            .receive_bootstrap(&ack[..ack_len], 9, b"request", &mut packet)
            .unwrap();
        assert!(matches!(ingress, ClientBootstrapIngress::RequestEncoded(_)));
        assert_eq!(connection.peer_cid(), Some(server_cid));
        assert!(connection.endpoint().is_some());

        assert_eq!(
            connection
                .receive_bootstrap(&ack[..ack_len], 10, b"request", &mut packet)
                .unwrap(),
            ClientBootstrapIngress::DuplicateAck
        );
    }

    #[test]
    fn client_association_keeps_one_cid_while_an_ack_migrates_the_return_path() {
        let client_cid = crate::ConnectionId::new(0x61).unwrap();
        let server_cid = crate::ConnectionId::new(0x62).unwrap();
        let uart = PathId::new(1).unwrap();
        let udp = PathId::new(2).unwrap();
        let mut association = ClientAssociation::<4, 1200>::new(client_cid);
        let mut packet = [0u8; 1200];

        association.select_path(uart);
        let (egress, open_len) = association.start(&mut packet).unwrap();
        assert_eq!(egress, uart);
        assert_eq!(association.connection().local_cid(), client_cid);
        assert_eq!(open_len > 0, true);

        // An explicit later `to=udp://...` selects UDP for an operation, but
        // it does not create another association or validate that path.
        association.select_path(udp);
        assert_eq!(association.egress_path(), Some(udp));
        assert_eq!(association.active_path(), None);

        let mut ack = [0u8; 1200];
        let ack_len = crate::encode_bootstrap_open_ack_packet_with_limits(
            client_cid,
            server_cid,
            0,
            crate::ConnectionLimits::default(),
            &mut ack,
        )
        .unwrap();
        association
            .receive_open_ack(udp, &ack[..ack_len], 7)
            .unwrap();

        assert_eq!(association.connection().local_cid(), client_cid);
        assert_eq!(association.peer_cid(), Some(server_cid));
        assert_eq!(association.active_path(), Some(udp));
        assert_eq!(association.selected_path(), None);
        assert_eq!(association.known_paths(), [Some(udp), None, None, None]);
    }

    #[test]
    fn client_association_owns_client_bidi_stream_sequence_across_paths() {
        let mut association =
            ClientAssociation::<4, 1200>::new(crate::ConnectionId::new(0x63).unwrap());
        let uart = PathId::new(1).unwrap();
        let now = PathId::new(2).unwrap();
        let udp = PathId::new(3).unwrap();

        association.select_path(uart);
        assert_eq!(
            association.allocate_client_bidi_stream().unwrap(),
            crate::FIRST_CLIENT_BIDI_STREAM_ID
        );
        association.select_path(now);
        assert_eq!(
            association.allocate_client_bidi_stream().unwrap(),
            crate::FIRST_CLIENT_BIDI_STREAM_ID + 4
        );
        association.select_path(udp);
        assert_eq!(
            association.allocate_client_bidi_stream().unwrap(),
            crate::FIRST_CLIENT_BIDI_STREAM_ID + 8
        );
    }

    #[test]
    fn client_association_keeps_response_correlation_when_a_request_changes_path() {
        let mut association =
            ClientAssociation::<4, 1200>::new(crate::ConnectionId::new(0x64).unwrap());
        let uart = PathId::new(1).unwrap();
        let udp = PathId::new(2).unwrap();
        association.select_path(uart);

        let first = crate::FIRST_SERVER_BIDI_STREAM_ID;
        assert!(association.accept_server_response_stream(first, true).unwrap());
        assert!(!association.has_active_server_response_stream());

        // Moving this logical association to UDP cannot turn the delayed
        // UART response into the result of the next operation.
        association.select_path(udp);
        assert!(!association.accept_server_response_stream(first, true).unwrap());
        assert!(association
            .accept_server_response_stream(first + 4, false)
            .unwrap());
        assert!(association.has_active_server_response_stream());
        assert!(association
            .accept_server_response_stream(first + 4, true)
            .unwrap());
        assert!(!association.has_active_server_response_stream());
        assert_eq!(association.active_path(), None);
        assert_eq!(association.selected_path(), Some(udp));
    }

    #[test]
    fn one_association_accepts_concurrent_streams_across_paths_and_uses_latest_valid_return_path() {
        let client_cid = crate::ConnectionId::new(0x81).unwrap();
        let server_cid = crate::ConnectionId::new(0x82).unwrap();
        let uart = PathId::new(1).unwrap();
        let udp = PathId::new(2).unwrap();
        let now = PathId::new(3).unwrap();
        let mut client = ClientAssociation::<4, 1200>::new(client_cid);
        let mut initial = [0u8; 1200];
        client.select_path(uart);
        client.start(&mut initial).unwrap();

        let mut ack = [0u8; 1200];
        let ack_len = crate::encode_bootstrap_open_ack_packet_with_limits(
            client_cid,
            server_cid,
            0,
            crate::ConnectionLimits::default(),
            &mut ack,
        )
        .unwrap();
        client.receive_open_ack(uart, &ack[..ack_len], 1).unwrap();

        // The sender has one peer association, but may open independent
        // server-initiated streams.  The packet paths are adapter facts and
        // must not allocate another CID or reset stream accounting.
        let mut server = crate::EndpointState::<{ crate::DEFAULT_STREAM_STATE_SLOTS }, 512>::new(
            crate::Role::Server,
            crate::ConnectionLimits::default(),
            1200,
        );
        server
            .install_connection_ids(server_cid, client_cid)
            .unwrap();
        server
            .open_send_stream(1, crate::INITIAL_MAX_STREAM_DATA)
            .unwrap();
        server
            .open_send_stream(5, crate::INITIAL_MAX_STREAM_DATA)
            .unwrap();

        let mut first = [0u8; 1200];
        let (first_len, _) = server
            .encode_stream_packet(client_cid, 1, 0, true, b"uart", &mut first)
            .unwrap();
        let first_stream = client
            .receive_stream_payload(udp, &first[..first_len])
            .unwrap()
            .map(|(id, _offset, _fin, data)| (id, data.to_vec()));
        assert_eq!(first_stream, Some((1, b"uart".to_vec())));
        assert_eq!(client.connection().local_cid(), client_cid);
        assert_eq!(client.active_path(), Some(udp));

        let mut second = [0u8; 1200];
        let (second_len, _) = server
            .encode_stream_packet(client_cid, 5, 0, true, b"now", &mut second)
            .unwrap();
        let second_stream = client
            .receive_stream_payload(now, &second[..second_len])
            .unwrap()
            .map(|(id, _offset, _fin, data)| (id, data.to_vec()));
        assert_eq!(second_stream, Some((5, b"now".to_vec())));
        assert_eq!(client.connection().local_cid(), client_cid);
        assert_eq!(client.active_path(), Some(now));
        assert_eq!(
            client.known_paths(),
            [Some(now), Some(udp), Some(uart), None]
        );

        // A packet for a different association is never allowed to redirect
        // the response path or disturb the two completed stream states.
        let wrong_cid = crate::ConnectionId::new(0x83).unwrap();
        let mut wrong = [0u8; 1200];
        let wrong_len = crate::rewrite_dcid(&first[..first_len], wrong_cid, &mut wrong).unwrap();
        assert_eq!(
            client.receive_stream_payload(uart, &wrong[..wrong_len]),
            Err(crate::Error::WrongConnectionId)
        );
        assert_eq!(client.active_path(), Some(now));
    }

    #[test]
    fn server_connection_replaces_stale_open_from_another_path_and_rotates_after_close() {
        #[derive(Debug)]
        struct Association {
            peer: crate::ConnectionId,
            packets: u8,
            closed: bool,
        }

        let initial = crate::ConnectionId::new(0x51).unwrap();
        let peer = crate::ConnectionId::new(0x52).unwrap();
        let replacement_peer = crate::ConnectionId::new(0x53).unwrap();
        let first_path = PathId::new(1).unwrap();
        let second_path = PathId::new(2).unwrap();
        let mut server = ServerConnection::new(initial);
        let mut open = [0u8; 64];
        let open_len = crate::encode_bootstrap_open_packet(peer, 0, &mut open).unwrap();

        let accepted = server
            .receive(
                first_path,
                &open[..open_len],
                |_| Association {
                    peer,
                    packets: 0,
                    closed: false,
                },
                |_| true,
                |association| {
                    association.packets += 1;
                    Ok(association.packets)
                },
                |association| association.closed,
                |association| Some(association.peer),
            )
            .unwrap();
        assert_eq!(
            accepted,
            ServerConnectionIngress::Accepted {
                result: 1,
                retired: false
            }
        );
        assert_eq!(server.active_path(), Some(first_path));

        let replacement_len =
            crate::encode_bootstrap_open_packet(replacement_peer, 0, &mut open).unwrap();
        let replaced: ServerConnectionIngress<u8> = server
            .receive(
                second_path,
                &open[..replacement_len],
                |_server_cid| Association {
                    peer: replacement_peer,
                    packets: 0,
                    closed: false,
                },
                |_| true,
                |association| {
                    association.packets += 1;
                    Ok(association.packets)
                },
                |_| false,
                |association| Some(association.peer),
            )
            .unwrap();
        assert_eq!(
            replaced,
            ServerConnectionIngress::Accepted {
                result: 1,
                retired: false
            }
        );
        assert_eq!(server.active_path(), Some(second_path));
        assert_ne!(server.local_cid(), initial);

        let mut established = [0u8; 16];
        let established_len = crate::ShortHeader {
            flags: crate::FLAG_FIXED,
            dcid: server.local_cid(),
            packet_number: 1,
            packet_number_len: 1,
        }
        .encode(&mut established)
        .unwrap();
        let migrated = server
            .receive(
                second_path,
                &established[..established_len],
                |_| unreachable!(),
                |_| true,
                |association| {
                    association.packets += 1;
                    association.closed = true;
                    Ok(association.packets)
                },
                |association| association.closed,
                |association| Some(association.peer),
            )
            .unwrap();
        assert_eq!(
            migrated,
            ServerConnectionIngress::Accepted {
                result: 2,
                retired: true
            }
        );
        assert!(server.association().is_none());
        assert_eq!(server.active_path(), None);
        assert_ne!(server.local_cid(), initial);
        assert_ne!(server.local_cid(), peer);
    }

    #[test]
    fn server_connection_replaces_same_path_open_in_shared_owner() {
        #[derive(Debug)]
        struct Association {
            peer: crate::ConnectionId,
        }

        let initial = crate::ConnectionId::new(0x61).unwrap();
        let first_peer = crate::ConnectionId::new(0x62).unwrap();
        let second_peer = crate::ConnectionId::new(0x63).unwrap();
        let path = PathId::new(7).unwrap();
        let mut server = ServerConnection::new(initial);
        let mut packet = [0u8; 64];
        let first_len = crate::encode_bootstrap_open_packet(first_peer, 0, &mut packet).unwrap();
        server
            .receive(
                path,
                &packet[..first_len],
                |_| Association { peer: first_peer },
                |_| true,
                |_| Ok(()),
                |_| false,
                |association| Some(association.peer),
            )
            .unwrap();

        let first_server_cid = server.local_cid();
        let second_len = crate::encode_bootstrap_open_packet(second_peer, 0, &mut packet).unwrap();
        server
            .receive(
                path,
                &packet[..second_len],
                |local_cid| {
                    assert_ne!(local_cid, first_server_cid);
                    assert_ne!(local_cid, second_peer);
                    Association { peer: second_peer }
                },
                |_| true,
                |_| Ok(()),
                |_| false,
                |association| Some(association.peer),
            )
            .unwrap();

        assert_eq!(
            server.association().map(|association| association.peer),
            Some(second_peer)
        );
        assert_eq!(server.active_path(), Some(path));
    }

    #[test]
    fn server_association_table_keeps_two_peers_and_their_paths_independent() {
        #[derive(Debug)]
        struct Association {
            local: crate::ConnectionId,
            peer: crate::ConnectionId,
            packets: u8,
        }

        let first_peer = crate::ConnectionId::new(0x71).unwrap();
        let second_peer = crate::ConnectionId::new(0x72).unwrap();
        let first_path = PathId::new(0x101).unwrap();
        let second_path = PathId::new(0x202).unwrap();
        let mut table = ServerAssociationTable::<Association, 2>::new(
            crate::ConnectionId::new(0x70).unwrap(),
        );
        let mut packet = [0u8; 64];
        let mut context = ();

        for (peer, path) in [(first_peer, first_path), (second_peer, second_path)] {
            let used = crate::encode_bootstrap_open_packet(peer, 0, &mut packet).unwrap();
            table
                .receive_admitted(
                    path,
                    &packet[..used],
                    &mut context,
                    |local, _| Ok((Association { local, peer, packets: 0 }, ())),
                    |_, _| Ok(()),
                    |association, _| {
                        association.packets += 1;
                        Ok(())
                    },
                    |_| false,
                    |association| Some(association.peer),
                    |association| Some(association.local),
                )
                .unwrap();
        }
        assert_eq!(table.active_len(), 2);
        let first_local = table.association_for_path(first_path).unwrap().local;
        let second_local = table.association_for_path(second_path).unwrap().local;
        assert_ne!(first_local, second_local);

        let used = crate::ShortHeader {
            flags: crate::FLAG_FIXED,
            dcid: first_local,
            packet_number: 1,
            packet_number_len: 1,
        }
        .encode(&mut packet)
        .unwrap();
        table
            .receive_admitted(
                first_path,
                &packet[..used],
                &mut context,
                |_, _| unreachable!(),
                |_, _| unreachable!(),
                |association, _| {
                    association.packets += 1;
                    Ok(())
                },
                |_| false,
                |association| Some(association.peer),
                |association| Some(association.local),
            )
            .unwrap();
        assert_eq!(table.association_for_path(first_path).unwrap().packets, 1);
        assert_eq!(table.association_for_path(second_path).unwrap().packets, 0);
    }

    #[test]
    fn server_connection_owns_cid_demux_instead_of_bearer_adapter() {
        #[derive(Debug)]
        struct Association {
            receive_cid: crate::ConnectionId,
        }

        let server_cid = crate::ConnectionId::new(0x71).unwrap();
        let peer_cid = crate::ConnectionId::new(0x72).unwrap();
        let first_path = PathId::new(11).unwrap();
        let other_path = PathId::new(12).unwrap();
        let mut server = ServerConnection::new(server_cid);
        let mut packet = [0u8; 64];

        let open_len = crate::encode_bootstrap_open_packet(peer_cid, 0, &mut packet).unwrap();
        assert!(server.owns_packet_for_path(first_path, &packet[..open_len], |_| None));
        server
            .receive(
                first_path,
                &packet[..open_len],
                |receive_cid| Association { receive_cid },
                |_| true,
                |_| Ok(()),
                |_| false,
                |_| Some(peer_cid),
            )
            .unwrap();

        let established_len = crate::ShortHeader {
            flags: crate::FLAG_FIXED,
            dcid: server_cid,
            packet_number: 1,
            packet_number_len: 1,
        }
        .encode(&mut packet)
        .unwrap();
        assert!(server.owns_packet_for_path(
            first_path,
            &packet[..established_len],
            |association| Some(association.receive_cid),
        ));
        assert!(server.owns_packet_for_path(
            other_path,
            &packet[..established_len],
            |association| Some(association.receive_cid),
        ));
        server
            .receive(
                other_path,
                &packet[..established_len],
                |receive_cid| Association { receive_cid },
                |_| true,
                |_| Ok(()),
                |_| false,
                |_| Some(peer_cid),
            )
            .unwrap();
        assert_eq!(server.active_path(), Some(other_path));
        assert_eq!(server.known_paths()[0], Some(other_path));
        assert_eq!(server.known_paths()[1], Some(first_path));
        assert_eq!(
            server.connection_id_diagnostic(&packet[..established_len], |association| {
                Some(association.receive_cid)
            }),
            ConnectionIdDiagnostic {
                received: Some(server_cid),
                expected: Some(server_cid),
            }
        );
        assert_eq!(
            server.connection_id_diagnostic(b"not-quic", |association| {
                Some(association.receive_cid)
            }),
            ConnectionIdDiagnostic {
                received: None,
                expected: Some(server_cid),
            }
        );
    }

    #[test]
    fn datagram_driver_owns_open_replay_filtering_and_counters() {
        struct Client {
            complete: bool,
        }

        impl DatagramClient<16> for Client {
            fn start(&mut self, output: &mut [u8; 16]) -> Result<usize, crate::Error> {
                output[..4].copy_from_slice(b"open");
                Ok(4)
            }

            fn receive_at(
                &mut self,
                input: &[u8],
                _now_ms: u64,
                output: &mut [u8; 16],
            ) -> Result<Option<usize>, crate::Error> {
                assert_eq!(input, b"ack");
                output[..3].copy_from_slice(b"req");
                self.complete = true;
                Ok(Some(3))
            }

            fn accepts(&self, input: &[u8]) -> bool {
                input == b"ack"
            }

            fn is_complete(&self) -> bool {
                self.complete
            }

            fn poll_transmit_at(
                &mut self,
                _now_ms: u64,
                _output: &mut [u8; 16],
            ) -> Result<Option<usize>, crate::Error> {
                Ok(None)
            }

            fn poll_retransmit(
                &mut self,
                _now_us: u64,
                _pto_us: u64,
                _output: &mut [u8; 16],
            ) -> Result<Option<usize>, crate::Error> {
                Ok(None)
            }
        }

        let mut client = Client { complete: false };
        let mut driver = DatagramClientDriver::start(&mut client, 10).unwrap();
        assert_eq!(driver.packet(), Some(&b"open"[..]));
        driver.mark_sent(10);
        assert_eq!(driver.packet(), None);
        assert!(!driver.poll(&mut client, 409, 100, 400).unwrap());
        assert!(driver.poll(&mut client, 410, 100, 400).unwrap());
        assert_eq!(driver.packet(), Some(&b"open"[..]));
        driver.mark_sent(410);
        assert!(!driver.receive(&mut client, b"foreign", 411).unwrap());
        assert!(driver.receive(&mut client, b"ack", 412).unwrap());
        assert_eq!(driver.packet(), Some(&b"req"[..]));
        assert_eq!(driver.tx_packets(), 2);
        assert_eq!(driver.rx_packets(), 1);
        assert_eq!(driver.retransmit_packets(), 1);
    }

    #[test]
    fn datagram_driver_reports_an_opaque_peer_reset_before_cid_filtering() {
        struct Client;

        impl DatagramClient<16> for Client {
            fn start(&mut self, output: &mut [u8; 16]) -> Result<usize, crate::Error> {
                output[0] = 1;
                Ok(1)
            }

            fn receive_at(
                &mut self,
                _input: &[u8],
                _now_ms: u64,
                _output: &mut [u8; 16],
            ) -> Result<Option<usize>, crate::Error> {
                unreachable!("opaque reset must not enter an application client")
            }

            fn accepts(&self, _input: &[u8]) -> bool {
                false
            }

            fn is_peer_stateless_reset(&self, input: &[u8]) -> bool {
                input == b"opaque-reset"
            }

            fn is_complete(&self) -> bool {
                false
            }

            fn poll_transmit_at(
                &mut self,
                _now_ms: u64,
                _output: &mut [u8; 16],
            ) -> Result<Option<usize>, crate::Error> {
                Ok(None)
            }

            fn poll_retransmit(
                &mut self,
                _now_us: u64,
                _pto_us: u64,
                _output: &mut [u8; 16],
            ) -> Result<Option<usize>, crate::Error> {
                Ok(None)
            }
        }

        let mut client = Client;
        let mut driver = DatagramClientDriver::start(&mut client, 0).unwrap();
        assert_eq!(
            driver.receive(&mut client, b"opaque-reset", 1),
            Err(crate::Error::PeerRestarted)
        );
    }
}
