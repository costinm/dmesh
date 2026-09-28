//! Bearer-neutral QUIC-lite connection policy.
//!
//! A connection can be carried by UART, UDP6, ESP-NOW, LoRa, or a host-only
//! test bearer.  The connection owns the association: connection IDs, packet
//! numbers, stream multiplexing, handshake/peer-authentication state, and its
//! current plus previously validated paths. Consequently this module owns no
//! radio lifecycle, socket, peer L2 address, or task state. Those belong to
//! physical transport adapters.
//!
//! Stream opening, RPC, forwarding, and service selection are connection
//! operations built on this policy.  They must not be represented as a
//! `transport.start` request: starting a bearer merely makes paths available.

use alloc::vec::Vec;

use crate::bearer::{BearerId, PacketMeta, PeerL2Address};

/// Private, complete physical return address for an association.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BearerL2Address {
    bearer: BearerId,
    peer_l2_address: PeerL2Address,
}

/// Stored path during migration. New packet-owner ingress always uses the
/// paired form; `Legacy` preserves existing address-only adapter APIs without
/// assigning a fake bearer ID that could collide with a real registration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AssociationL2Address {
    Bearer(BearerL2Address),
    Legacy(PeerL2Address),
}

impl AssociationL2Address {
    const fn from_meta(meta: PacketMeta) -> Self {
        Self::Bearer(BearerL2Address {
            bearer: meta.bearer,
            peer_l2_address: meta.peer_l2_address,
        })
    }

    const fn legacy(peer_l2_address: PeerL2Address) -> Self {
        Self::Legacy(peer_l2_address)
    }

    const fn peer_l2_address(self) -> PeerL2Address {
        match self {
            Self::Bearer(address) => address.peer_l2_address,
            Self::Legacy(address) => address,
        }
    }

    const fn bearer_l2_address(self) -> Option<BearerL2Address> {
        match self {
            Self::Bearer(address) => Some(address),
            Self::Legacy(_) => None,
        }
    }
}

/// Associates transport-independent connection state with its active path.
///
/// `receive` changes the return path only after the connection has accepted
/// the packet. Parsing failures, unknown DCIDs, and future authentication
/// failures therefore cannot redirect delayed ACKs or retransmissions.
pub(crate) struct PathConnection<T> {
    connection: T,
    /// Monotonic caller-supplied time of the latest valid packet. QUIC-lite
    /// uses this only for association lifecycle; it deliberately assigns no
    /// unit or wall-clock meaning to the value.
    last_activity_at: u64,
    /// Paths that have carried a valid packet for this association.  The
    /// adapter resolves these opaque handles to UART ports, UDP tuples, or
    /// NOW peers; QUIC never learns or chooses bearer-specific addresses.
    known_paths: [Option<AssociationL2Address>; 4],
    /// A caller-selected egress path, for example the exact address named by
    /// a `to` field.  This is deliberately distinct from `active_path`: an
    /// unverified outbound attempt must not claim that the peer has migrated
    /// to that path.
    selected_path: Option<AssociationL2Address>,
    active_path: Option<AssociationL2Address>,
}

/// Persistent server-side QUIC stream state, independent of application
/// registries, events, sockets, and bearer addresses.
pub(crate) struct ServerStreamConnection<
    const STREAMS: usize,
    const HISTORY: usize,
    const PACKET: usize = { crate::DEFAULT_MAX_PACKET_SIZE },
> {
    // Kept public temporarily for the dmesh-server diagnostic formatter.
    // New bearer/runtime operations must use the narrow methods below; once
    // diagnostics consume a snapshot rather than EndpointState this becomes
    // private as well.
    pub mux: crate::mux::StreamMux<STREAMS, HISTORY, PACKET>,
    local_limits: crate::ConnectionLimits,
    /// Packet-count receive budget advertised in OPEN_ACK. Zero retains the
    /// compatibility profile used by ordinary socket transports.
    local_max_in_flight_packets: u16,
    peer_open: crate::BootstrapOpen,
    /// Opaque token advertised with this server CID. It is association state
    /// owned by QUIC-lite so replayed OPENs cannot accidentally omit it.
    stateless_reset_token: Option<crate::StatelessResetToken>,
    next_response_stream: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ServerStreamConfig {
    /// Heap-backed retransmission records allocated for this association.
    /// Zero selects the connection type's compile-time ceiling for callers
    /// which do not have an admission-time memory policy.
    pub history_packets: usize,
    pub max_pending_streams: usize,
    pub max_stream_bytes: usize,
}

impl Default for ServerStreamConfig {
    fn default() -> Self {
        Self {
            history_packets: 0,
            // CallbackStreams retains a stream identity until the association
            // closes so duplicate FIN frames are harmless.  Keep its bound in
            // lockstep with EndpointState rather than making a long-lived
            // association fail after four completed tagged RPCs.
            max_pending_streams: crate::DEFAULT_STREAM_STATE_LIMIT,
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
    pub(crate) fn established_with_config(
        local_cid: crate::ConnectionId,
        peer_cid: crate::ConnectionId,
        local_limits: crate::ConnectionLimits,
        peer_max_data: u64,
        peer_max_stream_data: u64,
        peer_max_in_flight_packets: u16,
        next_packet_number: u32,
        config: ServerStreamConfig,
    ) -> Result<Self, crate::Error> {
        if config.history_packets > HISTORY {
            return Err(crate::Error::Invalid);
        }
        let mut mux = crate::mux::StreamMux::new_with_history_capacity(
            crate::Role::Server,
            local_limits,
            PACKET as u64,
            1,
            config.max_pending_streams,
            config.max_stream_bytes,
            if config.history_packets == 0 {
                HISTORY
            } else {
                config.history_packets
            },
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
            local_max_in_flight_packets: 0,
            peer_open: crate::BootstrapOpen {
                client_receive_cid: peer_cid,
                max_data: peer_max_data,
                max_stream_data: peer_max_stream_data,
                max_in_flight_packets: peer_max_in_flight_packets,
                stateless_reset_token: None,
                requested_peer_limits: None,
            },
            stateless_reset_token: None,
            next_response_stream: crate::FIRST_SERVER_BIDI_STREAM_ID,
        })
    }

    pub(crate) fn accept_open_with_limits(
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

    pub(crate) fn accept_open_with_config(
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
    pub(crate) fn accept_open_with_config_and_reset_token(
        packet: &[u8],
        server_cid: crate::ConnectionId,
        local_limits: crate::ConnectionLimits,
        config: ServerStreamConfig,
        stateless_reset_token: Option<crate::StatelessResetToken>,
    ) -> Result<(Self, Vec<u8>), crate::Error> {
        let server = Self::accept_open_state(
            packet,
            server_cid,
            local_limits,
            config,
            stateless_reset_token,
        )?;
        let ack = Self::encode_open_ack(
            server.peer_open.client_receive_cid,
            server_cid,
            server.local_limits,
            server.local_max_in_flight_packets,
            server.stateless_reset_token,
        )?;
        Ok((server, ack))
    }

    fn accept_open_state(
        packet: &[u8],
        server_cid: crate::ConnectionId,
        local_limits: crate::ConnectionLimits,
        config: ServerStreamConfig,
        stateless_reset_token: Option<crate::StatelessResetToken>,
    ) -> Result<Self, crate::Error> {
        let history_packets = if config.history_packets == 0 {
            HISTORY
        } else {
            config.history_packets
        };
        if history_packets > HISTORY {
            return Err(crate::Error::Invalid);
        }
        let (bootstrap_header, open) = crate::decode_bootstrap_open_packet_with_limits(packet)?;
        let local_limits = local_limits.clamped_to_request(open.requested_peer_limits);
        let mut mux = crate::mux::StreamMux::new_with_history_capacity(
            crate::Role::Server,
            local_limits,
            PACKET as u64,
            1,
            config.max_pending_streams,
            config.max_stream_bytes,
            history_packets,
        );
        Self::finish_open(&mut mux, bootstrap_header.packet_number, open, server_cid)?;
        Ok(Self {
            mux,
            local_limits,
            local_max_in_flight_packets: 0,
            peer_open: open,
            stateless_reset_token,
            next_response_stream: crate::FIRST_SERVER_BIDI_STREAM_ID,
        })
    }

    pub(crate) fn accept_open_with_limits_and_reset_token_into(
        packet: &[u8],
        server_cid: crate::ConnectionId,
        local_limits: crate::ConnectionLimits,
        stateless_reset_token: Option<crate::StatelessResetToken>,
        output: &mut [u8; PACKET],
    ) -> Result<(Self, usize), crate::Error> {
        let server = Self::accept_open_state(
            packet,
            server_cid,
            local_limits,
            ServerStreamConfig::default(),
            stateless_reset_token,
        )?;
        let used = Self::encode_open_ack_into(
            server.peer_open.client_receive_cid,
            server_cid,
            server.local_limits,
            server.local_max_in_flight_packets,
            server.stateless_reset_token,
            output,
        )?;
        Ok((server, used))
    }

    /// Initialize directly in final storage so embedded callers never copy
    /// the bounded retransmission ledger through an ingress-task stack frame.
    ///
    /// # Safety
    /// `out` must be valid, aligned, uninitialized storage for one `Self`.
    pub(crate) unsafe fn accept_open_in_place(
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
    pub(crate) unsafe fn accept_open_in_place_with_config(
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
    pub(crate) unsafe fn accept_open_in_place_with_config_and_reset_token(
        out: *mut Self,
        packet: &[u8],
        server_cid: crate::ConnectionId,
        local_limits: crate::ConnectionLimits,
        config: ServerStreamConfig,
        stateless_reset_token: Option<crate::StatelessResetToken>,
    ) -> Result<Vec<u8>, crate::Error> {
        let history_packets = if config.history_packets == 0 {
            HISTORY
        } else {
            config.history_packets
        };
        if history_packets == 0 || history_packets > HISTORY {
            return Err(crate::Error::Invalid);
        }
        let (bootstrap_header, open) = crate::decode_bootstrap_open_packet_with_limits(packet)?;
        let local_limits = local_limits.clamped_to_request(open.requested_peer_limits);
        unsafe {
            crate::mux::StreamMux::init_in_place(
                core::ptr::addr_of_mut!((*out).mux),
                crate::Role::Server,
                local_limits,
                PACKET as u64,
                config.max_pending_streams,
                config.max_stream_bytes,
                history_packets,
            );
            core::ptr::addr_of_mut!((*out).local_limits).write(local_limits);
            core::ptr::addr_of_mut!((*out).local_max_in_flight_packets).write(0);
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
            0,
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
        max_in_flight_packets: u16,
        stateless_reset_token: Option<crate::StatelessResetToken>,
    ) -> Result<Vec<u8>, crate::Error> {
        let mut ack = [0u8; PACKET];
        let used = Self::encode_open_ack_into(
            client_cid,
            server_cid,
            local_limits,
            max_in_flight_packets,
            stateless_reset_token,
            &mut ack,
        )?;
        Ok(ack[..used].to_vec())
    }

    fn encode_open_ack_into(
        client_cid: crate::ConnectionId,
        server_cid: crate::ConnectionId,
        local_limits: crate::ConnectionLimits,
        max_in_flight_packets: u16,
        stateless_reset_token: Option<crate::StatelessResetToken>,
        output: &mut [u8],
    ) -> Result<usize, crate::Error> {
        crate::encode_bootstrap_open_ack_packet_with_profile_and_reset_token(
            client_cid,
            server_cid,
            0,
            local_limits,
            max_in_flight_packets,
            stateless_reset_token,
            output,
        )
    }

    /// Validate a retransmitted OPEN and reproduce this connection's ACK.
    /// The connection owner locates this association by CID. The peer L2
    /// address is only a possible return route; OPEN identity, negotiated
    /// limits, and response encoding remain connection-layer state.
    pub(crate) fn replay_open_ack(&self, packet: &[u8]) -> Result<Vec<u8>, crate::Error> {
        let mut ack = [0u8; PACKET];
        let used = self.replay_open_ack_into(packet, &mut ack)?;
        Ok(ack[..used].to_vec())
    }

    pub(crate) const fn peer_receive_cid(&self) -> crate::ConnectionId {
        self.peer_open.client_receive_cid
    }

    pub(crate) fn accepts_replayed_open(&self, open: crate::BootstrapOpen) -> bool {
        self.peer_open == open
    }

    pub(crate) fn is_peer_stateless_reset(&self, input: &[u8]) -> bool {
        self.peer_open
            .stateless_reset_token
            .is_some_and(|token| token.matches_packet(input))
    }

    pub(crate) fn replay_open_ack_into(
        &self,
        packet: &[u8],
        output: &mut [u8; PACKET],
    ) -> Result<usize, crate::Error> {
        let (_, open) = crate::decode_bootstrap_open_packet_with_limits(packet)?;
        if open != self.peer_open {
            return Err(crate::Error::BootstrapInvalid);
        }
        let local_cid = self
            .mux
            .endpoint
            .local_connection_id()
            .ok_or(crate::Error::WrongConnectionId)?;
        Self::encode_open_ack_into(
            open.client_receive_cid,
            local_cid,
            self.local_limits,
            self.local_max_in_flight_packets,
            self.stateless_reset_token,
            output,
        )
    }

    pub(crate) fn reserve_response_stream(&mut self) -> u64 {
        let stream = self.next_response_stream;
        self.next_response_stream = self.next_response_stream.saturating_add(4);
        stream
    }

    /// Open the next locally initiated response stream and its send-credit
    /// state. New applications enter through `QuicNode::open_stream`;
    /// this role-specific operation remains hidden behind that facade.
    pub(crate) fn open_response_stream(&mut self) -> Result<u64, crate::Error> {
        let stream = self.reserve_response_stream();
        self.mux
            .endpoint
            .open_send_stream(stream, crate::INITIAL_MAX_STREAM_DATA)?;
        Ok(stream)
    }

    pub(crate) fn available_stream_send_bytes(&self, stream_id: u64, offset: u64) -> Option<u64> {
        self.mux
            .endpoint
            .available_stream_send_bytes(stream_id, offset)
    }

    pub(crate) fn prepare_peer_bidi_response(
        &mut self,
        stream_id: u64,
    ) -> Result<(), crate::Error> {
        self.mux
            .endpoint
            .open_send_stream(stream_id, crate::INITIAL_MAX_STREAM_DATA)
    }

    pub(crate) fn receive_stream_events<F>(
        &mut self,
        packet: &[u8],
        on_stream: F,
    ) -> Result<(), crate::mux::StreamDeliveryError>
    where
        F: FnMut(u64, u64, bool, &[u8]) -> Result<usize, crate::Error>,
    {
        self.mux.receive_stream_events(packet, on_stream)
    }

    /// Encode one caller-selected server stream range.
    ///
    /// Stream allocation and packet ownership normally enter through
    /// `QuicNode`; this crate-private operation keeps the role-specific mux
    /// behind that node facade.
    pub(crate) fn encode_stream_payload_at(
        &mut self,
        stream_id: u64,
        offset: u64,
        data: &[u8],
        fin: bool,
        out: &mut [u8],
    ) -> Result<usize, crate::Error> {
        self.mux
            .encode_response_at(stream_id, offset, data, fin, out)
            .map(|(used, _)| used)
    }

    pub(crate) fn poll_transmit(&mut self, out: &mut [u8]) -> Result<Option<usize>, crate::Error> {
        self.mux.endpoint.poll_transmit(out)
    }

    /// Association-owned clock used for ACK and PTO calculations.
    pub(crate) fn set_time(&mut self, now: u64) {
        self.mux.endpoint.set_time(now);
    }

    /// Immutable connection facts for dispatch and diagnostics.  These avoid
    /// handing a bearer or service the endpoint implementation.
    pub(crate) fn local_connection_id(&self) -> Option<crate::ConnectionId> {
        self.mux.endpoint.local_connection_id()
    }

    pub(crate) fn peer_connection_id(&self) -> Option<crate::ConnectionId> {
        self.mux.endpoint.peer_connection_id()
    }

    #[cfg(test)]
    pub(crate) fn stream_stats(&self) -> crate::ConnectionStreamStats {
        self.mux.endpoint.stream_stats()
    }

    pub(crate) fn transport_stats(&self) -> crate::TransportStats {
        self.mux.endpoint.stats()
    }

    /// Bytes retained until acknowledged by the peer. This supports generic
    /// terminal-response lifecycle without exposing ACK frames to handlers.
    pub(crate) fn bytes_in_flight(&self) -> u64 {
        self.mux.endpoint.bytes_in_flight()
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.mux.endpoint.is_closed()
    }

    pub(crate) fn close_code(&self) -> Option<u64> {
        self.mux.close_code()
    }

    /// End this association after its application has abandoned an
    /// interrupted operation. Packet encoding remains endpoint-owned and is
    /// emitted by the normal bearer poll.
    pub(crate) fn close(&mut self, code: u64) {
        self.mux.endpoint.close(code);
    }

    pub(crate) fn poll_close(&mut self, output: &mut [u8]) -> Result<Option<usize>, crate::Error> {
        self.mux.endpoint.poll_close(output)
    }

    pub(crate) fn next_bearer_deadline(&self, pto: u64) -> Option<u64> {
        let _ = pto;
        self.mux
            .endpoint
            .next_bearer_deadline(self.mux.endpoint.pto_timeout())
    }

    pub(crate) fn poll_timer(
        &mut self,
        now: u64,
        pto: u64,
        output: &mut [u8],
    ) -> Result<Option<usize>, crate::Error> {
        self.set_time(now);
        if let Some(used) = self.poll_transmit(output)? {
            return Ok(Some(used));
        }
        let _ = pto;
        let adaptive_pto = self.mux.endpoint.pto_timeout();
        Ok(self
            .mux
            .endpoint
            .retransmit_due(now, adaptive_pto, output)?
            .map(|(used, _)| used))
    }

    /// Apply the association's shared transport policy while it is accepted.
    /// The caller supplies policy values, never the endpoint, so UART, UDP,
    /// NOW, and NAN adapters cannot alter packet framing or ledger state.
    ///
    /// `history_packets` bounds this endpoint's own retransmission ledger. It
    /// is deliberately not advertised as a peer packet credit: an outbound
    /// ledger size says nothing about how many inbound packets the
    /// application can consume. Receive backpressure is expressed by the
    /// ordinary connection and stream byte credit returned after consumption.
    pub(crate) fn configure_transport(
        &mut self,
        history_packets: usize,
        initial_window_bytes: u64,
        ack_frequency: u8,
        ack_delay: u64,
    ) -> Result<(), crate::Error> {
        self.mux.endpoint.set_history_capacity(history_packets)?;
        self.mux.endpoint.congestion.congestion_window = initial_window_bytes;
        self.mux.endpoint.congestion.slow_start_threshold = initial_window_bytes;
        self.mux
            .endpoint
            .set_ack_policy(ack_frequency, ack_delay.saturating_mul(1_000));
        self.local_max_in_flight_packets = 0;
        Ok(())
    }

    /// ACK/congestion facts used by a bearer-neutral diagnostic report.
    pub(crate) fn transport_ack_state(&self) -> (Option<u32>, u64, u64) {
        (
            self.mux.endpoint.largest_acked_by_peer(),
            self.mux.endpoint.congestion.bytes_in_flight,
            self.mux.endpoint.congestion.congestion_window,
        )
    }

    /// Apply the negotiated ACK cadence for this association.
    pub(crate) fn request_ack_frequency(
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
    pub(crate) fn encode_server_stream_fragment(
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
    pub(crate) const fn new(connection: T) -> Self {
        Self {
            connection,
            last_activity_at: 0,
            known_paths: [None; 4],
            selected_path: None,
            active_path: None,
        }
    }

    pub(crate) const fn last_activity_at(&self) -> u64 {
        self.last_activity_at
    }

    pub(crate) const fn active_path(&self) -> Option<PeerL2Address> {
        match self.active_path {
            Some(path) => Some(path.peer_l2_address()),
            None => None,
        }
    }

    const fn active_bearer_l2_address(&self) -> Option<AssociationL2Address> {
        self.active_path
    }

    /// Path selected for an outbound operation before the peer has answered.
    /// Once a packet is accepted, [`Self::receive`] makes its ingress path
    /// active and that path takes precedence for ordinary ACK/retransmit
    /// traffic.
    pub(crate) const fn selected_path(&self) -> Option<PeerL2Address> {
        match self.selected_path {
            Some(path) => Some(path.peer_l2_address()),
            None => None,
        }
    }

    /// Preferred egress path. A caller-specified path wins for its immediate
    /// operation; otherwise a connection returns traffic on its most recent
    /// valid ingress path.
    pub(crate) const fn egress_path(&self) -> Option<PeerL2Address> {
        match self.selected_path {
            Some(path) => Some(path.peer_l2_address()),
            None => self.active_path(),
        }
    }

    #[allow(dead_code)] // Used by the packet-owner facade in the next migration step.
    const fn egress_bearer_l2_address(&self) -> Option<AssociationL2Address> {
        match self.selected_path {
            Some(path) => Some(path),
            None => self.active_path,
        }
    }

    /// Select an adapter-owned path for the next outbound operation. This
    /// does not validate, remember, or migrate the association.
    pub(crate) fn select_path(&mut self, path: PeerL2Address) {
        self.selected_path = Some(AssociationL2Address::legacy(path));
    }

    #[allow(dead_code)] // Used by the packet-owner facade in the next migration step.
    fn select_packet_path(&mut self, meta: PacketMeta) {
        self.selected_path = Some(AssociationL2Address::from_meta(meta));
    }

    /// Clear a one-operation egress selection so normal traffic resumes on
    /// the last valid ingress path.
    pub(crate) fn clear_selected_path(&mut self) {
        self.selected_path = None;
    }

    /// Paths currently attached to this association, newest valid ingress
    /// first. The final path is not removed merely because the connection
    /// temporarily sends over another bearer; expiry and explicit close are
    /// connection-manager policy above this no-std state.
    pub(crate) const fn known_paths(&self) -> [Option<PeerL2Address>; 4] {
        [
            Self::peer_l2_address(self.known_paths[0]),
            Self::peer_l2_address(self.known_paths[1]),
            Self::peer_l2_address(self.known_paths[2]),
            Self::peer_l2_address(self.known_paths[3]),
        ]
    }

    #[allow(dead_code)] // Kept private; tests verify bearer/address disambiguation.
    const fn known_bearer_l2_addresses(&self) -> [Option<AssociationL2Address>; 4] {
        self.known_paths
    }

    const fn peer_l2_address(path: Option<AssociationL2Address>) -> Option<PeerL2Address> {
        match path {
            Some(path) => Some(path.peer_l2_address()),
            None => None,
        }
    }

    pub(crate) const fn connection(&self) -> &T {
        &self.connection
    }

    pub(crate) fn connection_mut(&mut self) -> &mut T {
        &mut self.connection
    }

    pub(crate) fn into_inner(self) -> T {
        self.connection
    }

    /// Process one complete frame and adopt its path only on success.
    ///
    /// A valid established packet may arrive via a different bearer than the
    /// previous one. It retains the same QUIC association and makes its path
    /// the return path; malformed packets and failed future authentication do
    /// not alter either the active or remembered paths.
    pub(crate) fn receive<R, E>(
        &mut self,
        path: PeerL2Address,
        receive: impl FnOnce(&mut T) -> Result<R, E>,
    ) -> Result<R, E> {
        self.receive_on(AssociationL2Address::legacy(path), receive)
    }

    fn receive_on<R, E>(
        &mut self,
        path: AssociationL2Address,
        receive: impl FnOnce(&mut T) -> Result<R, E>,
    ) -> Result<R, E> {
        let result = receive(&mut self.connection)?;
        self.remember_bearer_l2_address(path);
        self.active_path = Some(path);
        self.selected_path = None;
        Ok(result)
    }

    pub(crate) fn clear_active_path(&mut self) {
        self.active_path = None;
    }

    fn remember_path(&mut self, path: PeerL2Address) {
        self.remember_bearer_l2_address(AssociationL2Address::legacy(path));
    }

    fn remember_bearer_l2_address(&mut self, path: AssociationL2Address) {
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

/// Complete-packet classification for a shared listener.
///
/// The listener uses this to select a terminating direct endpoint, a new
/// association, or an existing association route.  It deliberately exposes
/// only the destination CID required for route-table lookup: packet headers,
/// packet numbers, and all frame data remain private to QUIC-lite.  UART,
/// NOW, and UDP adapters must pass the same opaque frame bytes after this
/// one classification step.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ServerPacket {
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

/// Classify one completed inbound packet for a shared QUIC-lite listener.
///
/// Direct framing, Initial parsing, and short-header CID extraction all live
/// here so socket/radio adapters do not grow their own header peeking paths.
pub(crate) fn classify_server_packet(packet: &[u8]) -> Result<ServerPacket, crate::Error> {
    if crate::DirectMessageEndpoint::is_packet(packet) {
        return Ok(ServerPacket::Direct);
    }
    if let Ok((_, open)) = crate::decode_bootstrap_open_packet_with_limits(packet) {
        return Ok(ServerPacket::Initial(open));
    }
    if let Ok((long, _, _)) = crate::decode_long_packet(packet) {
        if long.packet_type == crate::LONG_PACKET_INITIAL {
            if let Some(destination) = long.dcid {
                return Ok(ServerPacket::BootstrapAck { destination });
            }
        }
        return Err(crate::Error::Invalid);
    }
    let (header, _) = crate::ShortHeader::decode(packet)?;
    Ok(ServerPacket::Established {
        destination: header.dcid,
    })
}

/// Result of admitting one packet through the client bootstrap boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ClientBootstrapIngress {
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
pub(crate) struct ClientConnection<const HISTORY: usize, const PACKET: usize> {
    local_cid: crate::ConnectionId,
    local_limits: crate::ConnectionLimits,
    requested_peer_limits: Option<crate::ReceiveWindowRequest>,
    peer_cid: Option<crate::ConnectionId>,
    peer_reset_token: Option<crate::StatelessResetToken>,
    local_reset_token: Option<crate::StatelessResetToken>,
    endpoint: Option<crate::EndpointState<{ crate::DEFAULT_STREAM_STATE_LIMIT }, HISTORY, PACKET>>,
    started: bool,
    open_packet_number: u32,
}

impl<const HISTORY: usize, const PACKET: usize> ClientConnection<HISTORY, PACKET> {
    pub(crate) fn new(local_cid: crate::ConnectionId) -> Self {
        Self::with_limits(local_cid, crate::ConnectionLimits::default())
    }

    pub(crate) const fn with_limits(
        local_cid: crate::ConnectionId,
        local_limits: crate::ConnectionLimits,
    ) -> Self {
        Self {
            local_cid,
            local_limits,
            requested_peer_limits: None,
            peer_cid: None,
            peer_reset_token: None,
            local_reset_token: None,
            endpoint: None,
            started: false,
            open_packet_number: 0,
        }
    }

    pub(crate) const fn local_cid(&self) -> crate::ConnectionId {
        self.local_cid
    }

    /// Ask the peer to select no more than this receive profile for this new
    /// association. The peer's OPEN_ACK reports the effective, hard-clamped
    /// value; this is intended for host stress tests and capability-aware
    /// provisioning, not a way to expand peer memory.
    pub(crate) fn set_requested_peer_receive_profile(
        &mut self,
        request: crate::ReceiveWindowRequest,
    ) -> Result<(), crate::Error> {
        if self.started || request.max_data == 0 || request.max_stream_data == 0 {
            return Err(crate::Error::Invalid);
        }
        self.requested_peer_limits = Some(request);
        Ok(())
    }

    pub(crate) const fn peer_cid(&self) -> Option<crate::ConnectionId> {
        self.peer_cid
    }

    pub(crate) fn set_local_reset_token(&mut self, token: crate::StatelessResetToken) {
        debug_assert!(!self.started);
        self.local_reset_token = Some(token);
    }

    /// Classify an opaque packet as a peer restart only after normal CID and
    /// packet parsing failed.  The token was received in the peer's Initial
    /// OPEN_ACK, so no bearer needs to decode or retain reset state.
    pub(crate) fn is_peer_stateless_reset(&self, input: &[u8]) -> bool {
        self.peer_reset_token
            .is_some_and(|token| token.matches_packet(input))
    }

    pub(crate) const fn is_started(&self) -> bool {
        self.started
    }

    pub(crate) const fn is_established(&self) -> bool {
        self.endpoint.is_some()
    }

    pub(crate) fn accepts(&self, input: &[u8]) -> bool {
        crate::ShortHeader::decode(input).is_ok_and(|(header, _)| header.dcid == self.local_cid)
            || (self.started
                && crate::decode_bootstrap_open_ack_packet_with_limits(input, self.local_cid)
                    .is_ok())
    }

    pub(crate) fn start(&mut self, output: &mut [u8; PACKET]) -> Result<usize, crate::Error> {
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
    pub(crate) fn encode_open_attempt(
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
        crate::encode_bootstrap_open_packet_with_profile_reset_token_and_peer_receive_request(
            self.local_cid,
            self.open_packet_number,
            self.local_limits,
            0,
            self.local_reset_token,
            self.requested_peer_limits,
            output,
        )
    }

    /// Establish on an OPEN-ACK and encode the first client request, or
    /// classify a packet for an already established endpoint.
    pub(crate) fn receive_bootstrap(
        &mut self,
        input: &[u8],
        now_us: u64,
        request: &[u8],
        output: &mut [u8; PACKET],
    ) -> Result<ClientBootstrapIngress, crate::Error> {
        if !self.started {
            return Err(crate::Error::Invalid);
        }
        if self.endpoint.is_none() {
            self.receive_open_ack(input, now_us)?;
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
    pub(crate) fn receive_open_ack(
        &mut self,
        input: &[u8],
        now_us: u64,
    ) -> Result<bool, crate::Error> {
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
        endpoint.set_time(now_us);
        endpoint.install_connection_ids(self.local_cid, ack.server_receive_cid)?;
        endpoint.set_initial_peer_credit(ack.max_data, ack.max_stream_data)?;
        endpoint.continue_packet_numbers_from(self.open_packet_number.saturating_add(1))?;
        self.peer_cid = Some(ack.server_receive_cid);
        self.peer_reset_token = ack.stateless_reset_token;
        self.endpoint = Some(endpoint);
        Ok(true)
    }

    /// Establish an association from the first valid short-header packet.
    ///
    /// This is the original QUIC-lite wire contract used by deployed peers:
    /// the client CID from OPEN is symmetric, and the server's first ACK and
    /// flow-control packet proves that it accepted the association. A newer
    /// peer may instead send OPEN_ACK and negotiate a distinct server CID.
    pub(crate) fn receive_initial_short_header(
        &mut self,
        input: &[u8],
        now_us: u64,
    ) -> Result<(), crate::Error> {
        if !self.started || self.endpoint.is_some() {
            return Err(crate::Error::Invalid);
        }
        let (header, _) = crate::ShortHeader::decode(input)?;
        if header.dcid != self.local_cid {
            return Err(crate::Error::WrongConnectionId);
        }
        let mut endpoint =
            crate::EndpointState::new(crate::Role::Client, self.local_limits, PACKET as u64);
        endpoint.set_time(now_us);
        endpoint.install_connection_ids(self.local_cid, self.local_cid)?;
        endpoint.continue_packet_numbers_from(self.open_packet_number.saturating_add(1))?;
        // Stable peers grant stream 4 credit in this first control packet.
        // Register it before parsing that packet; the application still sees
        // no stream until it explicitly opens one through QuicAssociation.
        endpoint.open_send_stream(
            crate::FIRST_CLIENT_BIDI_STREAM_ID,
            crate::INITIAL_MAX_STREAM_DATA,
        )?;
        endpoint.prepare_local_bidi_receive(crate::FIRST_CLIENT_BIDI_STREAM_ID)?;
        self.peer_cid = Some(self.local_cid);
        self.endpoint = Some(endpoint);
        Ok(())
    }

    pub(crate) fn endpoint(
        &self,
    ) -> Option<&crate::EndpointState<{ crate::DEFAULT_STREAM_STATE_LIMIT }, HISTORY, PACKET>> {
        self.endpoint.as_ref()
    }

    pub(crate) fn endpoint_mut(
        &mut self,
    ) -> Result<
        &mut crate::EndpointState<{ crate::DEFAULT_STREAM_STATE_LIMIT }, HISTORY, PACKET>,
        crate::Error,
    > {
        self.endpoint.as_mut().ok_or(crate::Error::Invalid)
    }

    pub(crate) fn poll_transmit(
        &mut self,
        output: &mut [u8; PACKET],
    ) -> Result<Option<usize>, crate::Error> {
        self.endpoint
            .as_mut()
            .map_or(Ok(None), |endpoint| endpoint.poll_transmit(output))
    }

    pub(crate) fn poll_transmit_at(
        &mut self,
        now_us: u64,
        output: &mut [u8; PACKET],
    ) -> Result<Option<usize>, crate::Error> {
        let Some(endpoint) = self.endpoint.as_mut() else {
            return Ok(None);
        };
        endpoint.set_time(now_us);
        endpoint.poll_transmit(output)
    }

    pub(crate) fn poll_close(
        &mut self,
        output: &mut [u8; PACKET],
    ) -> Result<Option<usize>, crate::Error> {
        self.endpoint
            .as_mut()
            .map_or(Ok(None), |endpoint| endpoint.poll_close(output))
    }

    /// Mark the established association terminal.  This is deliberately
    /// separate from `poll_close`: polling never invents a close merely
    /// because an application happens to be one-shot.
    pub(crate) fn close(&mut self, code: u64) -> Result<(), crate::Error> {
        self.endpoint_mut()?.close(code);
        Ok(())
    }

    pub(crate) fn poll_retransmit(
        &mut self,
        now_us: u64,
        initial_pto_us: u64,
        output: &mut [u8; PACKET],
    ) -> Result<Option<usize>, crate::Error> {
        let Some(endpoint) = self.endpoint.as_mut() else {
            return Ok(None);
        };
        // This is the same caller-owned monotonic clock as
        // `poll_transmit_at`. In particular, a retransmission replaces the
        // ledger entry with a fresh send timestamp; leaving the endpoint at
        // its previous clock made that replacement immediately eligible for
        // time-threshold loss on the next ACK. Every bearer reaches this
        // method through the node state machine, so keep timing ownership here
        // rather than teaching UDP/UART/NOW bearers separate rules.
        endpoint.set_time(now_us);
        let _ = initial_pto_us;
        let adaptive_pto = endpoint.pto_timeout();
        Ok(endpoint
            .retransmit_due(now_us, adaptive_pto, output)?
            .map(|(used, _)| used))
    }
}

/// One logical client-side QUIC association with adapter-owned paths.
///
/// A connection manager keys this object by a stable device identity once
/// discovery/authentication has supplied one.  A UDP tuple, NOW MAC, or UART
/// port is only a [`PeerL2Address`]: choosing one with [`Self::select_path`] sends a
/// particular operation there, but does not create another CID or another
/// handshake.  Any subsequently accepted QUIC packet makes its ingress path
/// the normal return path.  The manager above this no-std core owns path I/O,
/// identity binding, idle-close policy, and application request correlation.
pub(crate) struct ClientAssociation<const HISTORY: usize, const PACKET: usize> {
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
pub(crate) struct AssociationStreamPayload<'a> {
    pub stream_id: u64,
    pub offset: u64,
    pub fin: bool,
    pub data: &'a [u8],
}

impl<const HISTORY: usize, const PACKET: usize> ClientAssociation<HISTORY, PACKET> {
    pub(crate) fn new(local_cid: crate::ConnectionId) -> Self {
        Self::with_limits(local_cid, crate::ConnectionLimits::default())
    }

    pub(crate) const fn with_limits(
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

    pub(crate) const fn connection(&self) -> &ClientConnection<HISTORY, PACKET> {
        self.state.connection()
    }

    pub(crate) fn connection_mut(&mut self) -> &mut ClientConnection<HISTORY, PACKET> {
        self.state.connection_mut()
    }

    pub(crate) const fn active_path(&self) -> Option<PeerL2Address> {
        self.state.active_path()
    }

    pub(crate) const fn selected_path(&self) -> Option<PeerL2Address> {
        self.state.selected_path()
    }

    pub(crate) const fn egress_path(&self) -> Option<PeerL2Address> {
        self.state.egress_path()
    }

    pub(crate) const fn known_paths(&self) -> [Option<PeerL2Address>; 4] {
        self.state.known_paths()
    }

    /// Select the exact adapter path for a caller's next outbound operation.
    /// This is the core representation of a `to` selector; it is not a new
    /// connection and is not treated as validated peer-path evidence.
    pub(crate) fn select_path(&mut self, path: PeerL2Address) {
        self.state.select_path(path);
    }

    /// Internal packet-owner selection. Adapters identify a route with the
    /// already-public [`PacketMeta`] rather than learning a second path API.
    #[allow(dead_code)] // Used by the packet-owner facade in the next migration step.
    pub(crate) fn select_packet_path(&mut self, meta: PacketMeta) {
        self.state.select_packet_path(meta);
    }

    #[allow(dead_code)] // Used by the packet-owner facade in the next migration step.
    pub(crate) fn egress_bearer_l2_address(&self) -> Option<(BearerId, PeerL2Address)> {
        let path = self.state.egress_bearer_l2_address()?;
        let path = path.bearer_l2_address()?;
        Some((path.bearer, path.peer_l2_address))
    }

    pub(crate) fn clear_selected_path(&mut self) {
        self.state.clear_selected_path();
    }

    /// Allocate the next client-initiated bidirectional stream for this
    /// association. The stream-ID namespace is shared by every current and
    /// future path; adapters receive only the resulting stream ID.
    pub(crate) fn allocate_client_bidi_stream(&mut self) -> Result<u64, crate::Error> {
        let stream = self.next_client_bidi_stream_id;
        self.next_client_bidi_stream_id = self
            .next_client_bidi_stream_id
            .checked_add(4)
            .ok_or(crate::Error::StreamLimit)?;
        Ok(stream)
    }

    /// Open the next client-initiated bidirectional stream. Stream-number
    /// selection remains association-owned; a caller receives only the
    /// opaque stream handle needed to attach its ordered byte producer.
    pub(crate) fn open_next_client_bidi_stream(&mut self) -> Result<u64, crate::Error> {
        let stream = self.next_client_bidi_stream_id;
        self.prepare_client_bidi_stream(stream)?;
        self.next_client_bidi_stream_id = self
            .next_client_bidi_stream_id
            .checked_add(4)
            .ok_or(crate::Error::StreamLimit)?;
        Ok(stream)
    }

    /// Register a client-initiated stream before its first payload.  A
    /// request can name a second stream whose receiver immediately publishes
    /// MAX_STREAM_DATA; reserving it lets the normal QUIC flow-control parser
    /// admit that credit before the sender has bytes to offer.
    pub(crate) fn prepare_client_bidi_stream(
        &mut self,
        stream_id: u64,
    ) -> Result<(), crate::Error> {
        let endpoint = self.connection_mut().endpoint_mut()?;
        endpoint.open_send_stream(stream_id, crate::INITIAL_MAX_STREAM_DATA)?;
        endpoint.prepare_local_bidi_receive(stream_id)
    }

    /// Remaining ordinary QUIC stream credit at an ordered producer offset.
    /// Applications use this only to size their next slice; packetisation,
    /// ACKs, loss recovery, and accounting remain private to QUIC-lite.
    pub(crate) fn available_stream_send_bytes(&self, stream_id: u64, offset: u64) -> Option<u64> {
        self.connection()
            .endpoint()?
            .available_stream_send_bytes(stream_id, offset)
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
    pub(crate) fn accept_server_response_stream(
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
    pub(crate) const fn has_active_server_response_stream(&self) -> bool {
        self.active_server_response_stream_id.is_some()
    }

    /// Encode the client Initial for the selected path. The returned path is
    /// deliberately explicit so a frame adapter cannot infer CID ownership.
    pub(crate) fn start(
        &mut self,
        output: &mut [u8; PACKET],
    ) -> Result<(PeerL2Address, usize), crate::Error> {
        let path = self.egress_path().ok_or(crate::Error::Invalid)?;
        let used = self.connection_mut().start(output)?;
        Ok((path, used))
    }

    /// Encode a numbered Initial attempt for the currently selected path.
    ///
    /// This is deliberately an association operation rather than an adapter
    /// call to `ClientConnection`: a UDP, UART, or NOW adapter only injects
    /// the returned complete frame and must not learn bootstrap/CID details.
    pub(crate) fn encode_open_attempt(
        &mut self,
        packet_number: u32,
        output: &mut [u8; PACKET],
    ) -> Result<(PeerL2Address, usize), crate::Error> {
        let path = self.egress_path().ok_or(crate::Error::Invalid)?;
        let used = self
            .connection_mut()
            .encode_open_attempt(packet_number, output)?;
        Ok((path, used))
    }

    /// Admit an OPEN_ACK received on `path`. Long-header parsing, CID
    /// matching, and stateless-reset recognition remain private association
    /// policy; the frame adapter supplies only the complete packet.
    pub(crate) fn receive_open_ack(
        &mut self,
        path: PeerL2Address,
        input: &[u8],
        now_us: u64,
    ) -> Result<(), crate::Error> {
        self.receive(path, input, |connection| {
            connection.receive_open_ack(input, now_us).map(|_| ())
        })
    }

    /// Packet-owner OPEN_ACK admission. The complete bearer/address pair is
    /// retained only after bootstrap validation succeeds.
    pub(crate) fn receive_open_ack_packet(
        &mut self,
        meta: PacketMeta,
        input: &[u8],
    ) -> Result<(), crate::Error> {
        self.receive_packet(meta, input, |connection| {
            connection
                .receive_open_ack(input, meta.received_at_us)
                .map(|_| ())
        })
    }

    /// Admit the deployed symmetric-CID bootstrap response without exposing
    /// that compatibility rule to a bearer or application.
    pub(crate) fn receive_initial_short_header_packet(
        &mut self,
        meta: PacketMeta,
        input: &[u8],
    ) -> Result<(), crate::Error> {
        self.receive_packet(meta, input, |connection| {
            connection.receive_initial_short_header(input, meta.received_at_us)
        })
    }

    /// Encode one ordinary client-initiated stream payload.  Handlers and
    /// frame-I/O adapters work with stream bytes; packet headers, peer CIDs,
    /// and send-credit accounting stay inside QUIC-lite.
    pub(crate) fn encode_stream_payload(
        &mut self,
        stream_id: u64,
        data: &[u8],
        fin: bool,
        output: &mut [u8; PACKET],
    ) -> Result<(PeerL2Address, usize), crate::Error> {
        self.encode_stream_payload_at(stream_id, 0, data, fin, output)
    }

    /// Encode one ordered client stream range at its caller-supplied offset.
    /// The association still owns CIDs, packet numbering, stream credit,
    /// congestion, and retransmission history; a streamed application source
    /// owns only the already-ordered byte position it is offering.
    pub(crate) fn encode_stream_payload_at(
        &mut self,
        stream_id: u64,
        offset: u64,
        data: &[u8],
        fin: bool,
        output: &mut [u8; PACKET],
    ) -> Result<(PeerL2Address, usize), crate::Error> {
        let path = self.egress_path().ok_or(crate::Error::Invalid)?;
        let connection = self.connection_mut();
        let destination = connection
            .peer_cid()
            .unwrap_or_else(|| connection.local_cid());
        let endpoint = connection.endpoint_mut()?;
        endpoint.open_send_stream(stream_id, crate::INITIAL_MAX_STREAM_DATA)?;
        let (used, _) =
            endpoint.encode_stream_packet(destination, stream_id, offset, fin, data, output)?;
        Ok((path, used))
    }

    /// Admit one complete packet and project a normal stream frame to payload
    /// facts. No bearer caller decodes QUIC frames or packet headers.
    pub(crate) fn receive_stream_payload<'a>(
        &mut self,
        path: PeerL2Address,
        input: &'a [u8],
    ) -> Result<Option<(u64, u64, bool, &'a [u8])>, crate::Error> {
        self.receive(path, input, |connection| {
            let packet = connection.endpoint_mut()?.receive_packet(input)?;
            Ok(match packet {
                crate::TransportFrame::Control => None,
                crate::TransportFrame::Stream { frame, .. } => {
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
    pub(crate) fn receive_serial_response_payload<'a>(
        &mut self,
        path: PeerL2Address,
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
        if fin {
            // A one-shot caller may return immediately after this terminal
            // response. Make its delivery acknowledgement available in the
            // same bearer turn instead of waiting for another packet or an
            // adapter-specific delayed-ACK timer.
            self.connection_mut().endpoint_mut()?.request_stream_reack();
        }
        Ok(Some(AssociationStreamPayload {
            stream_id,
            offset,
            fin,
            data,
        }))
    }

    /// Packet-owner equivalent of [`Self::receive_serial_response_payload`].
    /// DCID validation is independent of the physical return address, and the
    /// bearer/address pair is retained only after transport parsing succeeds.
    pub(crate) fn receive_serial_response_payload_packet<'a>(
        &mut self,
        meta: PacketMeta,
        input: &'a [u8],
        _deferred_credit: bool,
    ) -> Result<Option<AssociationStreamPayload<'a>>, crate::Error> {
        let payload = self.receive_packet(meta, input, |connection| {
            let packet = connection.endpoint_mut()?.receive_packet(input)?;
            Ok(match packet {
                crate::TransportFrame::Control => None,
                crate::TransportFrame::Stream { frame, .. } => {
                    Some((frame.id, frame.offset, frame.fin, frame.data))
                }
            })
        })?;
        let Some((stream_id, offset, fin, data)) = payload else {
            return Ok(None);
        };
        // The node API multiplexes independent bidirectional streams. It
        // records consumption after the application callback accepts bytes;
        // this parser must neither serialize stream IDs nor return credit.
        if fin {
            self.connection_mut().endpoint_mut()?.request_stream_reack();
        }
        Ok(Some(AssociationStreamPayload {
            stream_id,
            offset,
            fin,
            data,
        }))
    }

    pub(crate) fn next_bearer_deadline(&self, pto: u64) -> Option<u64> {
        let _ = pto;
        self.connection()
            .endpoint()
            .and_then(|endpoint| endpoint.next_bearer_deadline(endpoint.pto_timeout()))
    }

    pub(crate) fn poll_timer(
        &mut self,
        now: u64,
        pto: u64,
        output: &mut [u8; PACKET],
    ) -> Result<Option<usize>, crate::Error> {
        if let Some(used) = self.connection_mut().poll_transmit_at(now, output)? {
            return Ok(Some(used));
        }
        self.connection_mut().poll_retransmit(now, pto, output)
    }

    /// Return receive credit after the application has accepted payload bytes.
    pub(crate) fn stream_consumed(
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
    pub(crate) fn is_peer_stateless_reset(&self, input: &[u8]) -> bool {
        self.connection().is_peer_stateless_reset(input)
    }

    pub(crate) fn peer_cid(&self) -> Option<crate::ConnectionId> {
        self.connection().peer_cid()
    }

    /// Whether `input` is a replay of the OPEN_ACK which established this
    /// association. It remains a valid association packet, but it is not an
    /// established short-header response and must not enter a stream parser.
    pub(crate) fn is_duplicate_open_ack(&self, input: &[u8]) -> bool {
        let connection = self.connection();
        let Some(peer_cid) = connection.peer_cid() else {
            return false;
        };
        crate::decode_bootstrap_open_ack_packet_with_limits(input, connection.local_cid())
            .is_ok_and(|(_, ack)| ack.server_receive_cid == peer_cid)
    }

    /// Continue the established packet number space after an accepted
    /// long-header setup response. This is setup state, not an adapter policy.
    pub(crate) fn continue_packet_numbers_from(&mut self, next: u32) -> Result<(), crate::Error> {
        self.connection_mut()
            .endpoint_mut()?
            .continue_packet_numbers_from(next)
    }

    /// Admit a frame only after the client CID/bootstrap boundary recognizes
    /// it. `receive` is supplied by the connection manager and may decode
    /// stream frames or complete a request; a failure leaves path state
    /// unchanged.
    pub(crate) fn receive<R>(
        &mut self,
        path: PeerL2Address,
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

    /// Bearer-aware equivalent of [`Self::receive`] for the QUIC packet
    /// owner. Routing still depends on DCID alone; metadata is retained only
    /// as the accepted packet's possible return route.
    #[allow(dead_code)] // Used by the packet-owner facade in the next migration step.
    pub(crate) fn receive_packet<R>(
        &mut self,
        meta: PacketMeta,
        input: &[u8],
        receive: impl FnOnce(&mut ClientConnection<HISTORY, PACKET>) -> Result<R, crate::Error>,
    ) -> Result<R, crate::Error> {
        if !self.connection().accepts(input) {
            if self.connection().is_peer_stateless_reset(input) {
                return Err(crate::Error::PeerRestarted);
            }
            return Err(crate::Error::WrongConnectionId);
        }
        self.state
            .receive_on(AssociationL2Address::from_meta(meta), receive)
    }

    /// Poll a queued connection-layer packet and pair it with the path the
    /// adapter must write. Normal queued traffic follows the latest valid
    /// ingress unless a caller has selected a path for its immediate request.
    pub(crate) fn poll_transmit(
        &mut self,
        output: &mut [u8; PACKET],
    ) -> Result<Option<(PeerL2Address, usize)>, crate::Error> {
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
    pub(crate) fn poll_close(
        &mut self,
        output: &mut [u8; PACKET],
    ) -> Result<Option<(PeerL2Address, usize)>, crate::Error> {
        let Some(path) = self.egress_path() else {
            return Ok(None);
        };
        Ok(self
            .connection_mut()
            .poll_close(output)?
            .map(|used| (path, used)))
    }

    /// Retire this client association through ordinary QUIC framing.  The
    /// path is selected by the association; a UDP/UART/NOW adapter only
    /// transmits the returned complete packet.
    pub(crate) fn close(&mut self, code: u64) -> Result<(), crate::Error> {
        self.connection_mut().close(code)
    }

    /// Poll a PTO/loss retransmission on the selected or current return path.
    /// Packet timing and retransmission history remain in QUIC-lite; frame
    /// adapters only write the selected complete packet.
    pub(crate) fn poll_retransmit(
        &mut self,
        now_us: u64,
        pto_us: u64,
        output: &mut [u8; PACKET],
    ) -> Result<Option<(PeerL2Address, usize)>, crate::Error> {
        let Some(path) = self.egress_path() else {
            return Ok(None);
        };
        Ok(self
            .connection_mut()
            .poll_retransmit(now_us, pto_us, output)?
            .map(|used| (path, used)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        decode_bootstrap_open_ack_packet, encode_bootstrap_open_packet, ConnectionId,
        ConnectionLimits, EndpointState, Role, ShortHeader, FLAG_FIXED, INITIAL_MAX_STREAM_DATA,
    };

    #[test]
    fn listener_classification_keeps_direct_initial_and_established_distinct() {
        let client = crate::ConnectionId::new(0x31).unwrap();
        let server = crate::ConnectionId::new(0x47).unwrap();
        let mut packet = [0u8; 256];
        let mut direct_packet = [0u8; 256];

        let direct_len =
            crate::encode_direct_packet(1, b"bounded direct", &mut direct_packet).unwrap();
        assert_eq!(
            classify_server_packet(&direct_packet[..direct_len]),
            Ok(ServerPacket::Direct)
        );
        let initial_len = crate::encode_bootstrap_open_packet(client, 0, &mut packet).unwrap();
        assert!(matches!(
            classify_server_packet(&packet[..initial_len]),
            Ok(ServerPacket::Initial(open)) if open.client_receive_cid == client
        ));
        let ack_len =
            crate::encode_bootstrap_open_ack_packet(client, server, 0, &mut packet).unwrap();
        assert_eq!(
            classify_server_packet(&packet[..ack_len]),
            Ok(ServerPacket::BootstrapAck {
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
            classify_server_packet(&packet[..established_len]),
            Ok(ServerPacket::Established {
                destination: server,
            })
        );
    }

    #[test]
    fn association_exposes_selected_active_and_known_peer_l2_addresses() {
        let cid = crate::ConnectionId::new(0x61).unwrap();
        let uart = PeerL2Address::new(1).unwrap();
        let udp = PeerL2Address::new(2).unwrap();
        let mut association = ClientAssociation::<4, 256>::new(cid);
        assert_eq!(association.selected_path(), None);
        assert_eq!(association.active_path(), None);
        association.select_path(uart);
        assert_eq!(association.selected_path(), Some(uart));

        // A valid inbound frame is what verifies/activates a return path; a
        // caller's selection alone does not fabricate path history.
        association
            .state
            .receive(udp, |_| Ok::<_, crate::Error>(()))
            .unwrap();
        assert_eq!(association.active_path(), Some(udp));
        assert_eq!(association.known_paths()[0], Some(udp));
        association.clear_selected_path();
        assert_eq!(association.selected_path(), None);
    }

    #[test]
    fn latest_valid_frame_changes_path_without_replacing_connection() {
        let uart = PeerL2Address::new(1).unwrap();
        let udp = PeerL2Address::new(2).unwrap();
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
        let uart = PeerL2Address::new(1).unwrap();
        let hostile = PeerL2Address::new(9).unwrap();
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
    fn server_open_allocates_selected_history_not_compile_time_ceiling() {
        let peer = crate::ConnectionId::new(0x611).unwrap();
        let local = crate::ConnectionId::new(0x612).unwrap();
        let mut packet = [0_u8; 1200];
        let used = crate::encode_bootstrap_open_packet(peer, 0, &mut packet).unwrap();
        let (connection, _) = ServerStreamConnection::<8, 64, 1200>::accept_open_with_config(
            &packet[..used],
            local,
            crate::ConnectionLimits::with_receive_window(1200),
            ServerStreamConfig {
                history_packets: 3,
                max_pending_streams: 8,
                max_stream_bytes: 3600,
            },
        )
        .unwrap();

        assert_eq!(connection.mux.endpoint.history_capacity(), 3);
        assert_eq!(connection.mux.endpoint.allocated_history_packets(), 3);
    }

    #[test]
    fn association_reports_peer_restart_before_a_timeout() {
        let client_cid = crate::ConnectionId::new(0x41).unwrap();
        let server_cid = crate::ConnectionId::new(0x42).unwrap();
        let path = PeerL2Address::new(7).unwrap();
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
        let uart = PeerL2Address::new(1).unwrap();
        let udp = PeerL2Address::new(2).unwrap();
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
    fn client_association_preserves_explicit_stream_offsets() {
        let client_cid = crate::ConnectionId::new(0x51).unwrap();
        let server_cid = crate::ConnectionId::new(0x52).unwrap();
        let path = PeerL2Address::new(1).unwrap();
        let mut client = ClientAssociation::<4, 256>::new(client_cid);
        client.select_path(path);
        let mut open = [0u8; 256];
        client.start(&mut open).unwrap();
        let mut ack = [0u8; 256];
        let ack_len = crate::encode_bootstrap_open_ack_packet_with_limits(
            client_cid,
            server_cid,
            0,
            crate::ConnectionLimits::default(),
            &mut ack,
        )
        .unwrap();
        client.receive_open_ack(path, &ack[..ack_len], 0).unwrap();

        let mut packet = [0u8; 256];
        let (_, first_len) = client
            .encode_stream_payload_at(
                crate::FIRST_CLIENT_BIDI_STREAM_ID + 4,
                0,
                b"one",
                false,
                &mut packet,
            )
            .unwrap();
        let mut server = crate::EndpointState::<{ crate::DEFAULT_STREAM_STATE_LIMIT }, 256>::new(
            crate::Role::Server,
            crate::ConnectionLimits::default(),
            256,
        );
        server
            .install_connection_ids(server_cid, client_cid)
            .unwrap();
        let first = server.receive_packet(&packet[..first_len]).unwrap();
        assert!(
            matches!(first, crate::TransportFrame::Stream { frame, .. } if frame.offset == 0 && frame.data == b"one")
        );

        let (_, second_len) = client
            .encode_stream_payload_at(
                crate::FIRST_CLIENT_BIDI_STREAM_ID + 4,
                3,
                b"two",
                true,
                &mut packet,
            )
            .unwrap();
        let second = server.receive_packet(&packet[..second_len]).unwrap();
        assert!(
            matches!(second, crate::TransportFrame::Stream { frame, .. } if frame.offset == 3 && frame.fin && frame.data == b"two")
        );
    }

    #[test]
    fn client_association_distinguishes_equal_addresses_on_different_bearers() {
        let client_cid = crate::ConnectionId::new(0x5a).unwrap();
        let server_cid = crate::ConnectionId::new(0x5b).unwrap();
        let address = PeerL2Address::new(7).unwrap();
        let udp = PacketMeta {
            bearer: BearerId::new(1).unwrap(),
            peer_l2_address: address,
            received_at_us: 10,
        };
        let uart = PacketMeta {
            bearer: BearerId::new(2).unwrap(),
            peer_l2_address: address,
            received_at_us: 20,
        };
        let mut client = ClientAssociation::<4, 256>::new(client_cid);
        client.select_packet_path(udp);
        let mut open = [0u8; 256];
        client.start(&mut open).unwrap();

        let mut ack = [0u8; 256];
        let ack_len = crate::encode_bootstrap_open_ack_packet_with_limits(
            client_cid,
            server_cid,
            0,
            crate::ConnectionLimits::default(),
            &mut ack,
        )
        .unwrap();
        client
            .receive_packet(udp, &ack[..ack_len], |connection| {
                connection.receive_open_ack(&ack[..ack_len], 0).map(|_| ())
            })
            .unwrap();
        client
            .receive_packet(uart, &ack[..ack_len], |_| Ok(()))
            .unwrap();

        assert_eq!(
            client.egress_bearer_l2_address(),
            Some((uart.bearer, address))
        );
        assert_eq!(
            client.state.known_bearer_l2_addresses(),
            [
                Some(AssociationL2Address::from_meta(uart)),
                Some(AssociationL2Address::from_meta(udp)),
                None,
                None,
            ]
        );

        let wrong_cid = crate::ConnectionId::new(0x5c).unwrap();
        let wrong_len = crate::encode_bootstrap_open_ack_packet_with_limits(
            wrong_cid,
            server_cid,
            0,
            crate::ConnectionLimits::default(),
            &mut ack,
        )
        .unwrap();
        assert_eq!(
            client.receive_packet(udp, &ack[..wrong_len], |_| Ok(())),
            Err(crate::Error::WrongConnectionId)
        );
        assert_eq!(
            client.egress_bearer_l2_address(),
            Some((uart.bearer, address))
        );
    }

    #[test]
    fn client_association_owns_client_bidi_stream_sequence_across_paths() {
        let mut association =
            ClientAssociation::<4, 1200>::new(crate::ConnectionId::new(0x63).unwrap());
        let uart = PeerL2Address::new(1).unwrap();
        let now = PeerL2Address::new(2).unwrap();
        let udp = PeerL2Address::new(3).unwrap();

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
        let uart = PeerL2Address::new(1).unwrap();
        let udp = PeerL2Address::new(2).unwrap();
        association.select_path(uart);

        let first = crate::FIRST_SERVER_BIDI_STREAM_ID;
        assert!(association
            .accept_server_response_stream(first, true)
            .unwrap());
        assert!(!association.has_active_server_response_stream());

        // Moving this logical association to UDP cannot turn the delayed
        // UART response into the result of the next operation.
        association.select_path(udp);
        assert!(!association
            .accept_server_response_stream(first, true)
            .unwrap());
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
        let uart = PeerL2Address::new(1).unwrap();
        let udp = PeerL2Address::new(2).unwrap();
        let now = PeerL2Address::new(3).unwrap();
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
        let mut server = crate::EndpointState::<{ crate::DEFAULT_STREAM_STATE_LIMIT }, 512>::new(
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

}
