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

use crate::bearer::PacketMeta;

/// Persistent server-side QUIC stream state, independent of application
/// registries, events, sockets, and bearer addresses.
pub(crate) struct ServerStreamConnection<const PACKET: usize = { crate::DEFAULT_MAX_PACKET_SIZE }> {
    // Kept public temporarily for the dmesh-server diagnostic formatter.
    // New bearer/runtime operations must use the narrow methods below; once
    // diagnostics consume a snapshot rather than EndpointState this becomes
    // private as well.
    pub mux: crate::mux::StreamMux<PACKET>,
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
    /// Zero selects one packet for compatibility callers which do not yet
    /// provide an admission-time memory policy.
    pub history_packets: usize,
    pub max_pending_streams: usize,
    pub max_stream_bytes: usize,
}

impl Default for ServerStreamConfig {
    fn default() -> Self {
        Self {
            history_packets: 0,
            // CallbackStreams retains only live ordered-delivery state. The
            // endpoint is the single source for completed and retired stream
            // IDs, so keep this live limit in lockstep with EndpointState.
            max_pending_streams: crate::DEFAULT_STREAM_STATE_LIMIT,
            max_stream_bytes: 4096,
        }
    }
}

impl<const PACKET: usize> ServerStreamConnection<PACKET> {
    pub(crate) fn set_runtime_limits(
        &mut self,
        limits: crate::AssociationLimits,
    ) -> Result<(), crate::Error> {
        self.mux
            .endpoint
            .set_receive_growth_limits(limits.connection)?;
        self.mux
            .endpoint
            .set_history_capacity(limits.history_packets)?;
        self.mux
            .set_delivery_limits(limits.max_pending_streams, limits.max_buffered_stream_bytes);
        Ok(())
    }
    fn accept_open_state(
        packet: &[u8],
        server_cid: crate::ConnectionId,
        local_limits: crate::ConnectionLimits,
        config: ServerStreamConfig,
        stateless_reset_token: Option<crate::StatelessResetToken>,
    ) -> Result<Self, crate::Error> {
        let history_packets = config.history_packets.max(1);
        let (bootstrap_header, open) = crate::decode_bootstrap_open_packet_with_limits(packet)?;
        let local_limits = local_limits.clamped_to_request(open.requested_peer_limits);
        let mut mux = crate::mux::StreamMux::new_with_history_capacity(
            crate::Role::Server,
            local_limits,
            PACKET as u64,
            1,
            config.max_pending_streams,
            crate::callback::retention_for_receive_window(local_limits, config.max_stream_bytes),
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
        Self::accept_open_with_config_into(
            packet,
            server_cid,
            local_limits,
            ServerStreamConfig::default(),
            stateless_reset_token,
            output,
        )
    }

    pub(crate) fn accept_open_with_config_into(
        packet: &[u8],
        server_cid: crate::ConnectionId,
        local_limits: crate::ConnectionLimits,
        config: ServerStreamConfig,
        stateless_reset_token: Option<crate::StatelessResetToken>,
        output: &mut [u8; PACKET],
    ) -> Result<(Self, usize), crate::Error> {
        let server = Self::accept_open_state(
            packet,
            server_cid,
            local_limits,
            config,
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

    fn finish_open(
        mux: &mut crate::mux::StreamMux<PACKET>,
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

    pub(crate) fn resume_stream_events<F>(
        &mut self,
        stream_id: u64,
        on_stream: F,
    ) -> Result<usize, crate::mux::StreamDeliveryError>
    where
        F: FnMut(u64, u64, bool, &[u8]) -> Result<usize, crate::Error>,
    {
        self.mux.resume_stream_events(stream_id, on_stream)
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

    pub(crate) fn next_bearer_deadline(&self) -> Option<u64> {
        self.mux.endpoint.next_bearer_deadline()
    }

    pub(crate) fn poll_timer(
        &mut self,
        now: u64,
        output: &mut [u8],
    ) -> Result<Option<usize>, crate::Error> {
        self.set_time(now);
        if let Some(used) = self.poll_transmit(output)? {
            return Ok(Some(used));
        }
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
        // Start at the configured initial window and grow in slow start.
        self.mux.endpoint.congestion.slow_start_threshold = u64::MAX;
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
}

/// Complete-packet classification for a shared listener.
///
/// The listener uses this to select a new association or an existing
/// association route. It deliberately exposes
/// only the destination CID required for route-table lookup: packet headers,
/// packet numbers, and all frame data remain private to QUIC-lite.  UART,
/// NOW, and UDP adapters must pass the same opaque frame bytes after this
/// one classification step.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ServerPacket {
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
/// Initial parsing and short-header CID extraction live here so socket/radio
/// adapters do not grow their own header peeking paths.
pub(crate) fn classify_server_packet(packet: &[u8]) -> Result<ServerPacket, crate::Error> {
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

/// Shared client-side OPEN, CID, packet-number, and endpoint lifecycle.
///
/// Application clients retain only their request/response state. This core is
/// deliberately unaware of tagged CBOR, object records, or probe payloads.
pub(crate) struct ClientConnection<const PACKET: usize> {
    local_cid: crate::ConnectionId,
    local_limits: crate::ConnectionLimits,
    requested_peer_limits: Option<crate::ReceiveWindowRequest>,
    peer_cid: Option<crate::ConnectionId>,
    peer_reset_token: Option<crate::StatelessResetToken>,
    local_reset_token: Option<crate::StatelessResetToken>,
    endpoint: Option<crate::EndpointState<PACKET>>,
    started: bool,
    open_packet_number: u32,
    history_packets: usize,
}

impl<const PACKET: usize> ClientConnection<PACKET> {
    pub(crate) fn new(local_cid: crate::ConnectionId) -> Self {
        Self::with_limits(local_cid, crate::ConnectionLimits::default())
    }

    pub(crate) const fn with_limits(
        local_cid: crate::ConnectionId,
        local_limits: crate::ConnectionLimits,
    ) -> Self {
        Self::with_limits_and_history(local_cid, local_limits, 1)
    }

    pub(crate) const fn with_limits_and_history(
        local_cid: crate::ConnectionId,
        local_limits: crate::ConnectionLimits,
        history_packets: usize,
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
            history_packets,
        }
    }

    pub(crate) const fn local_cid(&self) -> crate::ConnectionId {
        self.local_cid
    }

    /// Receive limits this client advertises to its peer.
    pub(crate) const fn local_limits(&self) -> crate::ConnectionLimits {
        self.local_limits
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
        let mut endpoint = crate::EndpointState::new_with_history_capacity(
            crate::Role::Client,
            self.local_limits,
            PACKET as u64,
            self.history_packets,
        );
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
        let mut endpoint = crate::EndpointState::new_with_history_capacity(
            crate::Role::Client,
            self.local_limits,
            PACKET as u64,
            self.history_packets,
        );
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

    pub(crate) fn endpoint(&self) -> Option<&crate::EndpointState<PACKET>> {
        self.endpoint.as_ref()
    }

    pub(crate) fn endpoint_mut(
        &mut self,
    ) -> Result<&mut crate::EndpointState<PACKET>, crate::Error> {
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

/// One logical client-side QUIC association.
///
/// [`crate::QuicNode`] owns bearer addresses and association routing. This
/// state owns only connection IDs, stream allocation, flow control, and loss
/// recovery.
pub(crate) struct ClientAssociation<const PACKET: usize> {
    connection: ClientConnection<PACKET>,
    /// Client-initiated bidirectional stream IDs are association state, not
    /// bearer state. A caller may select UART, NOW, or UDP for an operation,
    /// but it must never restart this sequence merely because the path
    /// changes.
    next_client_bidi_stream_id: u64,
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
    pub delivery_complete_before_packet: bool,
}

impl<const PACKET: usize> ClientAssociation<PACKET> {
    pub(crate) fn set_runtime_limits(
        &mut self,
        limits: crate::AssociationLimits,
    ) -> Result<(), crate::Error> {
        let endpoint = self.connection_mut().endpoint_mut()?;
        endpoint.set_receive_growth_limits(limits.connection)?;
        endpoint.set_history_capacity(limits.history_packets)
    }
    pub(crate) fn new(local_cid: crate::ConnectionId) -> Self {
        Self::with_limits(local_cid, crate::ConnectionLimits::default())
    }

    pub(crate) const fn with_limits(
        local_cid: crate::ConnectionId,
        local_limits: crate::ConnectionLimits,
    ) -> Self {
        Self {
            connection: ClientConnection::with_limits(local_cid, local_limits),
            next_client_bidi_stream_id: crate::FIRST_CLIENT_BIDI_STREAM_ID,
        }
    }

    pub(crate) const fn with_runtime_limits(
        local_cid: crate::ConnectionId,
        local_limits: crate::ConnectionLimits,
        history_packets: usize,
    ) -> Self {
        Self {
            connection: ClientConnection::with_limits_and_history(
                local_cid,
                local_limits,
                history_packets,
            ),
            next_client_bidi_stream_id: crate::FIRST_CLIENT_BIDI_STREAM_ID,
        }
    }

    pub(crate) const fn connection(&self) -> &ClientConnection<PACKET> {
        &self.connection
    }

    pub(crate) fn connection_mut(&mut self) -> &mut ClientConnection<PACKET> {
        &mut self.connection
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

    /// Encode the client Initial. The node supplies its bearer route
    /// independently from this connection state.
    pub(crate) fn start(&mut self, output: &mut [u8; PACKET]) -> Result<usize, crate::Error> {
        self.connection.start(output)
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
    ) -> Result<usize, crate::Error> {
        self.connection.encode_open_attempt(packet_number, output)
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
    ) -> Result<usize, crate::Error> {
        let connection = self.connection_mut();
        let destination = connection
            .peer_cid()
            .unwrap_or_else(|| connection.local_cid());
        let endpoint = connection.endpoint_mut()?;
        endpoint.open_send_stream(stream_id, crate::INITIAL_MAX_STREAM_DATA)?;
        let (used, _) =
            endpoint.encode_stream_packet(destination, stream_id, offset, fin, data, output)?;
        Ok(used)
    }

    /// Admit one packet through the bearer-aware association boundary and
    /// project an ordinary stream frame to payload facts. Stream correlation
    /// remains with the caller's retained stream handle.
    pub(crate) fn receive_stream_payload_packet<'a>(
        &mut self,
        meta: PacketMeta,
        input: &'a [u8],
    ) -> Result<Option<AssociationStreamPayload<'a>>, crate::Error> {
        let completed_stream = self.connection().endpoint().and_then(|endpoint| {
            let (_, header_len) =
                crate::ShortHeader::decode_with_expected(input, endpoint.expected_packet_number())
                    .ok()?;
            let mut offset = header_len;
            while offset < input.len() {
                let (frame, used) = crate::decode_frame(&input[offset..]).ok()?;
                if let crate::Frame::Stream(stream) = frame
                    && endpoint.stream_delivery_complete(stream.id)
                {
                    return Some(stream.id);
                }
                offset += used;
            }
            None
        });
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
            delivery_complete_before_packet: completed_stream == Some(stream_id),
        }))
    }

    pub(crate) fn next_bearer_deadline(&self) -> Option<u64> {
        self.connection()
            .endpoint()
            .and_then(|endpoint| endpoint.next_bearer_deadline())
    }

    pub(crate) fn poll_timer(
        &mut self,
        now: u64,
        output: &mut [u8; PACKET],
    ) -> Result<Option<usize>, crate::Error> {
        if let Some(used) = self.connection_mut().poll_transmit_at(now, output)? {
            return Ok(Some(used));
        }
        let adaptive_pto = self
            .connection()
            .endpoint()
            .map_or(crate::node::DEFAULT_INITIAL_PTO_US, |endpoint| {
                endpoint.pto_timeout()
            });
        self.connection_mut()
            .poll_retransmit(now, adaptive_pto, output)
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
    /// it. Bearer metadata remains owned by the node.
    pub(crate) fn receive_packet<R>(
        &mut self,
        meta: PacketMeta,
        input: &[u8],
        receive: impl FnOnce(&mut ClientConnection<PACKET>) -> Result<R, crate::Error>,
    ) -> Result<R, crate::Error> {
        if !self.connection().accepts(input) {
            if self.connection().is_peer_stateless_reset(input) {
                return Err(crate::Error::PeerRestarted);
            }
            return Err(crate::Error::WrongConnectionId);
        }
        let _ = meta;
        receive(&mut self.connection)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listener_classification_keeps_initial_and_established_distinct() {
        let client = crate::ConnectionId::new(0x31).unwrap();
        let server = crate::ConnectionId::new(0x47).unwrap();
        let mut packet = [0u8; 256];
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
    fn server_runtime_limits_update_ordered_delivery_policy() {
        const PACKET: usize = 256;
        let client = crate::ConnectionId::new(0x31).unwrap();
        let server_cid = crate::ConnectionId::new(0x47).unwrap();
        let mut input = [0u8; PACKET];
        let used = crate::encode_bootstrap_open_packet(client, 0, &mut input).unwrap();
        let mut output = [0u8; PACKET];
        let (mut server, _) = ServerStreamConnection::<PACKET>::accept_open_with_config_into(
            &input[..used],
            server_cid,
            crate::ConnectionLimits::default(),
            ServerStreamConfig::default(),
            None,
            &mut output,
        )
        .unwrap();
        let limits = crate::AssociationLimits {
            max_pending_streams: 3,
            max_buffered_stream_bytes: 1234,
            ..crate::AssociationLimits::embedded()
        };
        server.set_runtime_limits(limits).unwrap();
        assert_eq!(server.mux.delivery_limits(), (3, 1234));
        server.configure_transport(8, 6_000, 2, 25).unwrap();
        assert_eq!(server.mux.endpoint.congestion.congestion_window, 6_000);
        assert_eq!(
            server.mux.endpoint.congestion.slow_start_threshold,
            u64::MAX
        );
    }
}
