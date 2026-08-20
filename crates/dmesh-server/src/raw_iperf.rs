//! Bounded IPERF server for a socket-free datagram bearer.
//!
//! Ethernet, ESP-NOW, UART, and simulated bearers supply complete QUIC-lite
//! datagrams to this type and send its optional response unchanged. The type
//! has no socket, task, ESP-IDF, or peer-address dependency.

use alloc::{boxed::Box, vec::Vec};

use quic_lite::{
    decode_bootstrap_open_packet_with_limits, encode_bootstrap_open_ack_packet_with_limits,
    iperf::{IperfRun, IperfSender},
    ConnectionId, ConnectionLimits, EndpointState, Role, ShortHeader, TransportPacket,
    SERVICE_ECHO, SERVICE_FLASH, SERVICE_IPERF,
};
pub use quic_lite::Error;

use crate::{
    iperf::{decode_iperf_service_request, IperfServicePlan},
    protocol::{decode_flash_request, encode_get, FlashRequest, GetRequest, REQUEST_MAX},
    services::{diagnostic_stream_registry, handle_stream},
    stream_server::StreamServerConnection,
};

/// Stable compact diagnostic code for a QUIC-lite error at a raw-IPERF
/// adapter boundary. Firmware has a small status channel, while host tests
/// need the same classification without depending on ESP logging or sockets.
pub const fn receive_error_code(error: Error) -> u8 {
    match error {
        Error::BufferTooSmall => 1,
        Error::Truncated => 2,
        Error::Invalid => 3,
        Error::InvalidVarint => 4,
        Error::FlowControl => 5,
        Error::StreamLimit => 6,
        Error::PacketNumberExhausted => 7,
        Error::WrongConnectionId => 8,
        Error::BootstrapInvalid => 9,
        Error::HistoryFull => 10,
        Error::RetransmissionTooLarge => 11,
    }
}

/// Runtime controls for a raw ESP-NOW-compatible IPERF client.  The radio
/// adapter supplies the actual action frame I/O; this parser deliberately has
/// no ESP, socket, timer, or task dependency so a host tool can generate the
/// same start request and test its bounds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RawActionIperfRequest {
    pub peer: [u8; 6],
    pub bytes: u64,
    pub packet_size: u16,
    pub timeout_ms: u32,
    /// `0` selects driver rate control; otherwise a permitted legacy OFDM
    /// fixed rate in Mbps.
    pub tx_rate_mbps: u8,
}

pub const RAW_ACTION_IPERF_DEFAULT_TIMEOUT_MS: u32 = 10_000;
pub const RAW_ACTION_IPERF_MAX_TIMEOUT_MS: u32 = 60_000;

/// Decode the bytes after the `espnow-iperf:` hardware-service prefix.
///
/// Existing 14- and 16-byte requests remain valid. New callers append a
/// big-endian timeout (20 bytes total) and optionally one PHY-rate byte (21
/// bytes total), so a measurement can change timing/rate without reflashing.
pub fn decode_raw_action_iperf_request(
    value: &[u8],
) -> Result<RawActionIperfRequest, &'static str> {
    if !matches!(value.len(), 14 | 16 | 20 | 21) {
        return Err(
            "hardware espnow request must contain MAC, u64 bytes, optional u16 packet size, optional u32 timeout, and optional rate",
        );
    }
    let peer: [u8; 6] = value[..6]
        .try_into()
        .map_err(|_| "hardware ESP-NOW peer MAC")?;
    let bytes = u64::from_be_bytes(value[6..14].try_into().map_err(|_| "hardware byte count")?);
    if bytes == 0 {
        return Err("hardware espnow byte count must be nonzero");
    }
    let packet_size = if value.len() >= 16 {
        u16::from_be_bytes(
            value[14..16]
                .try_into()
                .map_err(|_| "hardware packet size")?,
        )
    } else {
        quic_lite::DEFAULT_MAX_DATAGRAM_SIZE as u16
    };
    if packet_size < 4 || usize::from(packet_size) > quic_lite::DEFAULT_MAX_DATAGRAM_SIZE {
        return Err("hardware espnow packet size");
    }
    let timeout_ms = if value.len() >= 20 {
        u32::from_be_bytes(value[16..20].try_into().map_err(|_| "hardware timeout")?)
    } else {
        RAW_ACTION_IPERF_DEFAULT_TIMEOUT_MS
    };
    if !(1_000..=RAW_ACTION_IPERF_MAX_TIMEOUT_MS).contains(&timeout_ms) {
        return Err("hardware espnow timeout must be 1000..=60000 ms");
    }
    let tx_rate_mbps = if value.len() == 21 { value[20] } else { 0 };
    if tx_rate_mbps != 0 && !matches!(tx_rate_mbps, 6 | 9 | 12 | 18 | 24 | 36 | 48 | 54) {
        return Err("hardware espnow rate must be auto or 6,9,12,18,24,36,48,54 Mbps");
    }
    Ok(RawActionIperfRequest {
        peer,
        bytes,
        packet_size,
        timeout_ms,
        tx_rate_mbps,
    })
}

/// Runtime settings selected while establishing a complete-datagram bearer.
/// The type-level history is only an allocation ceiling; these values select
/// what one association actually advertises and retains.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RawAssociationProfile {
    pub history_packets: usize,
    pub ack_frequency: u8,
    pub ack_delay_ms: u8,
    pub tx_burst_packets: usize,
    /// Initial congestion window for a complete-datagram bearer.  This is
    /// association-scoped: host links can start with the full bounded ledger,
    /// while a small device can select a lower value without changing QUIC's
    /// packet format or the adapter API.
    pub initial_window_packets: usize,
}

impl RawAssociationProfile {
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
            ack_frequency: self
                .ack_frequency
                .clamp(1, quic_lite::ACK_RANGE_CAPACITY as u8),
            ack_delay_ms: self.ack_delay_ms.clamp(1, 25),
            tx_burst_packets: self.tx_burst_packets.clamp(1, HISTORY),
            initial_window_packets: self.initial_window_packets.clamp(1, HISTORY),
        }
    }
}

/// One active diagnostic connection is sufficient for the initial Recovery
/// raw-UDP6 validation. The bearer remains responsible for peer/MAC binding
/// and can allocate a separate server instance when it admits more peers.
pub struct RawIperfServer<const HISTORY: usize, const PACKET: usize> {
    local_cid: ConnectionId,
    local_limits: ConnectionLimits,
    // This ledger contains the bounded receive history and ordered-stream
    // state. Keep it off the Wi-Fi ingress task's stack: a raw bearer starts
    // with no connection and allocates this only after an accepted OPEN.
    // The association profile still bounds the live history/window.
    connection: Option<Box<StreamServerConnection<HISTORY, PACKET>>>,
    // A Wi-Fi unicast retry can redeliver the DCID-zero OPEN after the server
    // already admitted it. Preserve the established packet-number state and
    // merely resend the deterministic ACK in that case.
    open_client_cid: Option<ConnectionId>,
    sender: Option<IperfSender>,
    pending_flash: Option<Vec<u8>>,
    flash_response: Option<Vec<u8>>,
    association: RawAssociationProfile,
}

/// Identity of the bearer that supplied a complete raw QUIC-lite datagram.
///
/// This is intentionally transport-neutral and small enough for firmware:
/// adapters translate an Ethernet peer or action-frame peer into its MAC and
/// select a stable local transport ID.  The service layer uses it solely to
/// return immediate ACK/control data on the ingress path; it contains no
/// socket, ESP-IDF, or 802.11 framing state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RawIngressPath {
    pub transport_id: u8,
    pub peer: [u8; 6],
}

/// Bounded wire-state evidence shared by host and firmware diagnostics.  It
/// intentionally contains packet numbers/ranges only, never packet payloads.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RawTransportDebugState {
    pub received_ranges: [Option<(u32, u32)>; quic_lite::ACK_RANGE_CAPACITY],
    pub peer_ack_ranges: [Option<(u32, u32)>; quic_lite::ACK_RANGE_CAPACITY],
    pub outstanding_packets: [Option<u32>; 16],
    pub outstanding_count: usize,
}

/// Counters common to every packet-at-a-time raw bearer client.  They are
/// deliberately independent of Wi-Fi driver details, so host monitor, raw
/// UDP6, ESP-NOW-compatible action, UART, and simulated links report the
/// same progress vocabulary.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RawServiceCounters {
    pub bootstrap_acks: u32,
    pub stream_packets: u32,
    pub other_packets: u32,
}

/// One lazily allocated diagnostic service endpoint shared by all raw
/// bearers of a firmware image.
///
/// This replaces the former one-`RawIperfServer`-per-UDP/NOW/UART pattern.
/// QUIC-lite/DCID and stream state belong to the service, not to an adapter;
/// the adapter only supplies [`RawIngressPath`] and sends the returned bytes.
/// The initial bounded implementation admits one active association, which
/// is sufficient for the current e6/e7 measurements.  A future connection
/// table extends this type by keying several entries on authenticated DCID,
/// without changing adapter callbacks or service handlers.
pub struct RawIperfDispatcher<const HISTORY: usize, const PACKET: usize> {
    server_cid: ConnectionId,
    limits: ConnectionLimits,
    association: RawAssociationProfile,
    // The dispatcher is long-lived firmware state.  Its server metadata is
    // small and fixed-size, so keeping it inline avoids a first-packet heap
    // allocation in every bearer.  The potentially large QUIC ledger remains
    // separately boxed by `RawIperfServer` only after an accepted OPEN.
    server: Option<RawIperfServer<HISTORY, PACKET>>,
    reply_path: Option<RawIngressPath>,
}

impl<const HISTORY: usize, const PACKET: usize> RawIperfDispatcher<HISTORY, PACKET> {
    pub const fn new(
        server_cid: ConnectionId,
        limits: ConnectionLimits,
        association: RawAssociationProfile,
    ) -> Self {
        Self {
            server_cid,
            limits,
            association,
            server: None,
            reply_path: None,
        }
    }

    /// Feed a datagram from any registered bearer. An immediate response is
    /// returned to the caller, which must send it on this same `path`.
    pub fn receive(
        &mut self,
        path: RawIngressPath,
        packet: &[u8],
        output: &mut [u8; PACKET],
    ) -> Result<Option<usize>, Error> {
        if self.server.is_none() {
            self.server = Some(RawIperfServer::new_with_association(
                self.server_cid,
                self.limits,
                self.association,
            ));
        }
        let response = self
            .server
            .as_mut()
            .expect("server just installed")
            .receive(packet, output)?;
        // Record after successful parsing so malformed radio noise cannot
        // redirect a later timer-driven ACK to another bearer.
        self.reply_path = Some(path);
        Ok(response)
    }

    /// Advance the connection-owned transport clock before receive or egress
    /// work. Raw bearers supply their monotonic clock; keeping it here makes
    /// PTO and ACK timing identical across UDP6, action, and UART.
    pub fn set_time(&mut self, now: u64) {
        if let Some(connection) = self.server.as_mut().and_then(|server| server.connection.as_mut()) {
            connection.mux.endpoint.set_time(now);
        }
    }

    /// Poll delayed control only for the path that last made valid service
    /// progress. This gives current single-association measurements stable
    /// same-bearer replies while preserving a clean hook for multipath policy.
    pub fn poll_for(
        &mut self,
        path: RawIngressPath,
        output: &mut [u8; PACKET],
    ) -> Result<Option<usize>, Error> {
        if self.reply_path != Some(path) {
            return Ok(None);
        }
        self.server
            .as_mut()
            .map_or(Ok(None), |server| server.poll(output))
    }

    /// Drive one endpoint-owned PTO retransmission on the bearer which last
    /// made service progress.  The dispatcher retains no copy of a response:
    /// the QUIC-lite endpoint ledger owns the retransmittable packet.
    pub fn poll_retransmit_for(
        &mut self,
        path: RawIngressPath,
        now_us: u64,
        pto_us: u64,
        output: &mut [u8; PACKET],
    ) -> Result<Option<usize>, Error> {
        if self.reply_path != Some(path) {
            return Ok(None);
        }
        self.server.as_mut().map_or(Ok(None), |server| {
            server.poll_retransmit(now_us, pto_us, output)
        })
    }

    pub const fn reply_path(&self) -> Option<RawIngressPath> {
        self.reply_path
    }

    /// Maximum number of fresh stream packets the bearer may emit from one
    /// ingress callback.  The value comes from the association profile rather
    /// than the radio adapter, so host and firmware use the same burst policy.
    pub const fn tx_burst_packets(&self) -> usize {
        self.association.tx_burst_packets
    }

    /// Snapshot common QUIC counters for a bearer-neutral diagnostic report.
    pub const fn transport_stats(&self) -> Option<quic_lite::TransportStats> {
        match self.server.as_ref() {
            Some(server) => match server.connection.as_ref() {
                Some(connection) => Some(connection.mux.endpoint.stats()),
                None => None,
            },
            None => None,
        }
    }

    /// ACK/congestion state needed to distinguish radio loss from a stalled
    /// peer ACK path in a raw-bearer report.
    pub fn transport_ack_state(&self) -> Option<(Option<u32>, u64, u64)> {
        match self.server.as_ref() {
            Some(server) => match server.connection.as_ref() {
                Some(connection) => Some((
                    connection.mux.endpoint.largest_acked_by_peer(),
                    connection.mux.endpoint.congestion.bytes_in_flight,
                    connection.mux.endpoint.congestion.congestion_window,
                )),
                None => None,
            },
            None => None,
        }
    }

    /// Return bounded ACK ranges and retained packet numbers for automated
    /// bearer diagnostics.  The host action adapter serializes this into its
    /// event history; firmware can consume the same structure without a
    /// socket-shaped API.
    pub fn transport_debug_state(&self) -> Option<RawTransportDebugState> {
        let connection = self.server.as_ref()?.connection.as_ref()?;
        let endpoint = &connection.mux.endpoint;
        let received_ranges = endpoint.ack_ranges_snapshot().map(|range| {
            range.map(|range| (range.start, range.end))
        });
        let peer_ack_ranges = endpoint.peer_ack_ranges_snapshot().map(|range| {
            range.map(|range| (range.start, range.end))
        });
        let (numbers, outstanding_count) = endpoint.outstanding_packet_numbers();
        let mut outstanding_packets = [None; 16];
        for (index, number) in numbers.into_iter().enumerate().take(16) {
            outstanding_packets[index] = number;
        }
        Some(RawTransportDebugState {
            received_ranges,
            peer_ack_ranges,
            outstanding_packets,
            outstanding_count,
        })
    }

    pub fn take_flash_request(&mut self) -> Option<Vec<u8>> {
        self.server.as_mut()?.take_flash_request()
    }

    pub fn complete_flash(&mut self, response: Vec<u8>) -> Result<(), Error> {
        self.server
            .as_mut()
            .ok_or(Error::Invalid)?
            .complete_flash(response)
    }
}

/// Host-testable client state for a complete-datagram bearer such as raw
/// ESP-NOW action frames. It has no socket, radio, timer, or ESP dependency:
/// an adapter sends each returned packet and feeds received packets back in.
///
/// Keeping this next to [`RawIperfServer`] prevents UART, UDP, and raw-action
/// tools from growing subtly different bootstrap/ACK/IPERF client loops.
pub struct RawIperfClient<const HISTORY: usize, const PACKET: usize> {
    client_cid: ConnectionId,
    server_cid: Option<ConnectionId>,
    endpoint: Option<EndpointState<8, HISTORY, PACKET>>,
    request: [u8; 31],
    request_len: usize,
    run: IperfRun<{ crate::iperf::IPERF_MAX_NORMAL_STREAMS }>,
    started: bool,
    complete: bool,
    bootstrap_acks: u32,
    stream_packets: u32,
    other_packets: u32,
}

/// One bounded service-level liveness check over a complete-datagram bearer.
///
/// Unlike IPERF this sends no bulk payload.  It proves the same OPEN,
/// request, response, and QUIC ACK path and uses the standard compact echo
/// service. Radio adapters add their RSSI and driver-counter sample beside
/// this result; those values are intentionally not invented by the
/// bearer-neutral server. This keeps an on-air probe within one vendor IE;
/// verbose status remains available through the normal status service.
pub struct RawCheckClient<const HISTORY: usize, const PACKET: usize> {
    client_cid: ConnectionId,
    server_cid: Option<ConnectionId>,
    endpoint: Option<EndpointState<8, HISTORY, PACKET>>,
    request: [u8; 9],
    started: bool,
    complete: bool,
    response: [u8; 512],
    response_len: usize,
    counters: RawServiceCounters,
}

/// Bearer-neutral, incremental signed-object GET client.
///
/// It retains only the bounded QUIC-lite ledger and the small GET request.
/// Every authenticated object-response fragment is handed to `on_fragment`
/// before receive credit is returned, so a firmware flash sink can defer
/// credit until durable storage is available without a bearer-private queue.
pub struct RawObjectClient<const HISTORY: usize, const PACKET: usize> {
    client_cid: ConnectionId,
    server_cid: Option<ConnectionId>,
    endpoint: Option<EndpointState<8, HISTORY, PACKET>>,
    request: [u8; REQUEST_MAX + 1],
    request_len: usize,
    started: bool,
    complete: bool,
    received: u64,
    counters: RawServiceCounters,
}

impl<const HISTORY: usize, const PACKET: usize> RawObjectClient<HISTORY, PACKET> {
    pub fn new(client_cid: ConnectionId, request: GetRequest<'_>) -> Result<Self, Error> {
        let mut encoded = [0u8; REQUEST_MAX + 1];
        encoded[0] = quic_lite::SERVICE_OBJECT;
        let body_len = encode_get(&mut encoded[1..], request.name, request.cpu, request.target)
            .ok_or(Error::Invalid)?;
        let request_len = body_len.checked_add(1).ok_or(Error::Invalid)?;
        if request_len > PACKET {
            return Err(Error::BufferTooSmall);
        }
        Ok(Self {
            client_cid,
            server_cid: None,
            endpoint: None,
            request: encoded,
            request_len,
            started: false,
            complete: false,
            received: 0,
            counters: RawServiceCounters::default(),
        })
    }

    pub fn start(&mut self, output: &mut [u8; PACKET]) -> Result<usize, Error> {
        if self.started {
            return Err(Error::Invalid);
        }
        self.started = true;
        quic_lite::encode_bootstrap_open_packet_with_profile(
            self.client_cid,
            0,
            ConnectionLimits::default(),
            0,
            output,
        )
    }

    pub fn accepts(&self, input: &[u8]) -> bool {
        ShortHeader::decode(input).is_ok_and(|(header, _)| header.dcid == self.client_cid)
    }

    pub fn retry_bootstrap(&self, output: &mut [u8; PACKET]) -> Result<usize, Error> {
        if !self.started || self.server_cid.is_some() || self.complete {
            return Err(Error::Invalid);
        }
        quic_lite::encode_bootstrap_open_packet_with_profile(
            self.client_cid,
            0,
            ConnectionLimits::default(),
            0,
            output,
        )
    }

    /// Receive one complete bearer packet. `on_fragment` is invoked in stream
    /// order before QUIC receive credit is returned.
    pub fn receive<F>(
        &mut self,
        input: &[u8],
        output: &mut [u8; PACKET],
        mut on_fragment: F,
    ) -> Result<Option<usize>, Error>
    where
        F: FnMut(&[u8]) -> Result<(), Error>,
    {
        if !self.started {
            return Err(Error::Invalid);
        }
        if self.endpoint.is_none() {
            let (_, ack) =
                quic_lite::decode_bootstrap_open_ack_packet_with_limits(input, self.client_cid)?;
            let mut endpoint =
                EndpointState::new(Role::Client, ConnectionLimits::default(), PACKET as u64);
            endpoint.install_connection_ids(self.client_cid, ack.server_receive_cid)?;
            endpoint.set_initial_peer_credit(ack.max_data, ack.max_stream_data)?;
            endpoint.continue_packet_numbers_from(1)?;
            endpoint.open_send_stream(
                quic_lite::FIRST_CLIENT_BIDI_STREAM_ID,
                quic_lite::INITIAL_MAX_STREAM_DATA,
            )?;
            let (used, _) = endpoint.encode_stream_packet(
                ack.server_receive_cid,
                quic_lite::FIRST_CLIENT_BIDI_STREAM_ID,
                0,
                true,
                &self.request[..self.request_len],
                output,
            )?;
            self.server_cid = Some(ack.server_receive_cid);
            self.endpoint = Some(endpoint);
            self.counters.bootstrap_acks = self.counters.bootstrap_acks.saturating_add(1);
            return Ok(Some(used));
        }
        if let Ok((_, ack)) =
            quic_lite::decode_bootstrap_open_ack_packet_with_limits(input, self.client_cid)
        {
            if self.server_cid == Some(ack.server_receive_cid) {
                self.counters.bootstrap_acks = self.counters.bootstrap_acks.saturating_add(1);
                return Ok(None);
            }
        }
        let endpoint = self.endpoint.as_mut().ok_or(Error::Invalid)?;
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
        self.endpoint
            .as_mut()
            .map_or(Ok(None), |endpoint| endpoint.poll_transmit(output))
    }

    pub fn poll_retransmit(
        &mut self,
        now_us: u64,
        pto_us: u64,
        output: &mut [u8; PACKET],
    ) -> Result<Option<usize>, Error> {
        let Some(endpoint) = self.endpoint.as_mut() else {
            return Ok(None);
        };
        Ok(endpoint
            .retransmit_due(now_us, pto_us, output)?
            .map(|(used, _)| used))
    }

    pub const fn is_complete(&self) -> bool {
        self.complete
    }
    pub const fn bytes(&self) -> u64 {
        self.received
    }
    pub const fn server_cid(&self) -> Option<ConnectionId> {
        self.server_cid
    }
    pub const fn counters(&self) -> RawServiceCounters {
        self.counters
    }
}

impl<const HISTORY: usize, const PACKET: usize> RawCheckClient<HISTORY, PACKET> {
    /// `nonce` is returned as echo request data, so a caller can associate
    /// a delayed result with its own probe without a transport-private tag.
    pub fn new(client_cid: ConnectionId, nonce: u64) -> Self {
        let mut request = [0u8; 9];
        request[0] = SERVICE_ECHO;
        request[1..].copy_from_slice(&nonce.to_be_bytes());
        Self {
            client_cid,
            server_cid: None,
            endpoint: None,
            request,
            started: false,
            complete: false,
            response: [0; 512],
            response_len: 0,
            counters: RawServiceCounters::default(),
        }
    }

    pub fn start(&mut self, output: &mut [u8; PACKET]) -> Result<usize, Error> {
        if self.started {
            return Err(Error::Invalid);
        }
        self.started = true;
        quic_lite::encode_bootstrap_open_packet_with_profile(
            self.client_cid,
            0,
            ConnectionLimits::default(),
            0,
            output,
        )
    }

    /// Whether a complete raw datagram targets this client's receive CID.
    /// A peer may concurrently have a server-side association, so bearer
    /// adapters must demultiplex by DCID rather than treating every packet
    /// from the selected MAC as a client reply.
    pub fn accepts(&self, input: &[u8]) -> bool {
        ShortHeader::decode(input).is_ok_and(|(header, _)| header.dcid == self.client_cid)
    }

    /// Regenerate an OPEN while a sparse raw bearer has not yet delivered its
    /// first OPEN_ACK. This has the same bounded discovery role as IPERF's
    /// bootstrap retry and retains no additional packet state.
    pub fn retry_bootstrap(&self, output: &mut [u8; PACKET]) -> Result<usize, Error> {
        if !self.started || self.server_cid.is_some() || self.complete {
            return Err(Error::Invalid);
        }
        quic_lite::encode_bootstrap_open_packet_with_profile(
            self.client_cid,
            0,
            ConnectionLimits::default(),
            0,
            output,
        )
    }

    pub fn receive(
        &mut self,
        input: &[u8],
        output: &mut [u8; PACKET],
    ) -> Result<Option<usize>, Error> {
        self.receive_at(input, 0, output)
    }

    /// Feed a check response with the bearer monotonic millisecond clock.
    /// Keeping the clock update here prevents a raw adapter from resetting
    /// delayed-ACK and RTT state to zero on every received action frame.
    pub fn receive_at(
        &mut self,
        input: &[u8],
        now_ms: u64,
        output: &mut [u8; PACKET],
    ) -> Result<Option<usize>, Error> {
        if self.endpoint.is_none() {
            let (_, ack) =
                quic_lite::decode_bootstrap_open_ack_packet_with_limits(input, self.client_cid)?;
            let mut endpoint =
                EndpointState::new(Role::Client, ConnectionLimits::default(), PACKET as u64);
            endpoint.set_time(now_ms);
            endpoint.install_connection_ids(self.client_cid, ack.server_receive_cid)?;
            endpoint.set_initial_peer_credit(ack.max_data, ack.max_stream_data)?;
            endpoint.continue_packet_numbers_from(1)?;
            endpoint.open_send_stream(
                quic_lite::FIRST_CLIENT_BIDI_STREAM_ID,
                quic_lite::INITIAL_MAX_STREAM_DATA,
            )?;
            let (used, _) = endpoint.encode_stream_packet(
                ack.server_receive_cid,
                quic_lite::FIRST_CLIENT_BIDI_STREAM_ID,
                0,
                true,
                &self.request,
                output,
            )?;
            self.server_cid = Some(ack.server_receive_cid);
            self.endpoint = Some(endpoint);
            self.counters.bootstrap_acks = self.counters.bootstrap_acks.saturating_add(1);
            return Ok(Some(used));
        }
        // A sparse raw bearer can redeliver OPEN_ACK after the client has
        // already emitted its first request. That bootstrap packet is not a
        // normal endpoint frame, but it is harmless control duplication;
        // accept it exactly as RawIperfClient does instead of reporting an
        // application-facing `Invalid` error.
        if let Ok((_, ack)) =
            quic_lite::decode_bootstrap_open_ack_packet_with_limits(input, self.client_cid)
        {
            if self.server_cid == Some(ack.server_receive_cid) {
                self.counters.bootstrap_acks = self.counters.bootstrap_acks.saturating_add(1);
                return Ok(None);
            }
        }
        let endpoint = self.endpoint.as_mut().ok_or(Error::Invalid)?;
        endpoint.set_time(now_ms);
        let TransportPacket::Stream { frame, .. } = endpoint.receive_datagram(input)? else {
            self.counters.other_packets = self.counters.other_packets.saturating_add(1);
            return endpoint.poll_transmit(output);
        };
        // A raw action response can be retransmitted with a fresh packet
        // number after the receiver already recorded its stream range. The
        // endpoint has marked the duplicate for ACK; do not turn that normal
        // no-MAC-ACK recovery case into a service error or copy the response
        // twice.
        if frame.id == quic_lite::FIRST_SERVER_BIDI_STREAM_ID
            && frame.offset.saturating_add(frame.data.len() as u64) <= self.response_len as u64
        {
            self.counters.other_packets = self.counters.other_packets.saturating_add(1);
            return endpoint.poll_transmit(output);
        }
        self.counters.stream_packets = self.counters.stream_packets.saturating_add(1);
        if frame.id != quic_lite::FIRST_SERVER_BIDI_STREAM_ID
            || frame.offset != self.response_len as u64
            || self.response_len.saturating_add(frame.data.len()) > self.response.len()
        {
            return Err(Error::Invalid);
        }
        self.response[self.response_len..self.response_len + frame.data.len()]
            .copy_from_slice(frame.data);
        self.response_len += frame.data.len();
        endpoint.stream_consumed(frame.id, frame.data.len())?;
        self.complete = frame.fin;
        endpoint.poll_transmit(output)
    }

    pub const fn is_complete(&self) -> bool {
        self.complete
    }

    /// Number of service-response bytes accepted on the standard server
    /// stream.  This gives a bounded health check the same truthful progress
    /// metric as raw IPERF without allocating an IPERF payload buffer.
    pub const fn bytes(&self) -> u64 {
        self.response_len as u64
    }

    pub const fn server_cid(&self) -> Option<ConnectionId> {
        self.server_cid
    }

    pub fn poll_transmit(&mut self, output: &mut [u8; PACKET]) -> Result<Option<usize>, Error> {
        self.endpoint
            .as_mut()
            .map_or(Ok(None), |endpoint| endpoint.poll_transmit(output))
    }

    /// Re-send the outstanding request through the endpoint's bounded ledger
    /// after PTO. This is needed on a connectionless action bearer where a
    /// driver-accepted response can still be lost on air.
    pub fn poll_retransmit(
        &mut self,
        now_us: u64,
        pto_us: u64,
        output: &mut [u8; PACKET],
    ) -> Result<Option<usize>, Error> {
        let Some(endpoint) = self.endpoint.as_mut() else {
            return Ok(None);
        };
        Ok(endpoint
            .retransmit_due(now_us, pto_us, output)?
            .map(|(used, _packet_number)| used))
    }

    pub fn response(&self) -> Option<&[u8]> {
        self.complete.then_some(&self.response[..self.response_len])
    }

    pub const fn counters(&self) -> RawServiceCounters {
        self.counters
    }
}

impl<const HISTORY: usize, const PACKET: usize> RawIperfClient<HISTORY, PACKET> {
    pub fn new(client_cid: ConnectionId, bytes: u64) -> Result<Self, Error> {
        Self::new_with_packet_size(client_cid, bytes, PACKET as u16)
    }

    /// Construct a complete-datagram client with a caller-selected payload
    /// size.  Radio adapters use this to compare a small robust action frame
    /// against the normal MTU-sized UDP path; the service request remains the
    /// same host-tested IPERF schema.
    pub fn new_with_packet_size(
        client_cid: ConnectionId,
        bytes: u64,
        packet_size: u16,
    ) -> Result<Self, Error> {
        if packet_size < 4 || usize::from(packet_size) > PACKET {
            return Err(Error::Invalid);
        }
        let mut request = [0u8; 31];
        let request_len = crate::iperf::encode_iperf_service_request(
            crate::iperf::IperfServiceRequest::new(bytes, packet_size),
            &mut request,
        )
        .ok_or(Error::Invalid)?;
        let plan = crate::iperf::decode_iperf_service_request(&request[..request_len])
            .ok_or(Error::Invalid)?;
        let plan = crate::iperf::IperfServicePlan::from_request(plan, PACKET.saturating_sub(32));
        Ok(Self {
            client_cid,
            server_cid: None,
            endpoint: None,
            request,
            request_len,
            run: IperfRun::new(
                2,
                plan.normal_streams,
                plan.high_priority_bytes != 0,
                plan.low_priority_bytes != 0,
            ),
            started: false,
            complete: false,
            bootstrap_acks: 0,
            stream_packets: 0,
            other_packets: 0,
        })
    }

    /// Start bootstrap. Call once, then transmit the returned packet.
    pub fn start(&mut self, output: &mut [u8; PACKET]) -> Result<usize, Error> {
        if self.started {
            return Err(Error::Invalid);
        }
        self.started = true;
        self.encode_bootstrap(output)
    }

    /// See [`RawCheckClient::accepts`]. This keeps client/server coexistence
    /// on one peer/bearer a connection-level decision, not a radio one.
    pub fn accepts(&self, input: &[u8]) -> bool {
        ShortHeader::decode(input).is_ok_and(|(header, _)| header.dcid == self.client_cid)
    }

    /// Regenerate the initial OPEN while discovery is still in progress.
    ///
    /// A raw action bearer can have deliberately sparse receive windows.  The
    /// adapter may therefore retry this one control datagram until it gets an
    /// OPEN-ACK, without retaining a second packet buffer or depending on a
    /// socket timer.  Once a peer CID is known, normal QUIC-lite packet/ACK
    /// handling owns any further transmission.
    pub fn retry_bootstrap(&self, output: &mut [u8; PACKET]) -> Result<usize, Error> {
        if !self.started || self.server_cid.is_some() || self.complete {
            return Err(Error::Invalid);
        }
        self.encode_bootstrap(output)
    }

    fn encode_bootstrap(&self, output: &mut [u8; PACKET]) -> Result<usize, Error> {
        quic_lite::encode_bootstrap_open_packet_with_profile(
            self.client_cid,
            0,
            ConnectionLimits::default(),
            0,
            output,
        )
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
        if !self.started || self.complete {
            return Err(Error::Invalid);
        }
        if self.endpoint.is_none() {
            let (_, ack) =
                quic_lite::decode_bootstrap_open_ack_packet_with_limits(input, self.client_cid)?;
            let mut endpoint =
                EndpointState::new(Role::Client, ConnectionLimits::default(), PACKET as u64);
            endpoint.set_time(now_ms);
            endpoint.install_connection_ids(self.client_cid, ack.server_receive_cid)?;
            endpoint.set_initial_peer_credit(ack.max_data, ack.max_stream_data)?;
            endpoint.continue_packet_numbers_from(1)?;
            endpoint.open_send_stream(
                quic_lite::FIRST_CLIENT_BIDI_STREAM_ID,
                quic_lite::INITIAL_MAX_STREAM_DATA,
            )?;
            let (used, _) = endpoint.encode_stream_packet(
                ack.server_receive_cid,
                quic_lite::FIRST_CLIENT_BIDI_STREAM_ID,
                0,
                true,
                &self.request[..self.request_len],
                output,
            )?;
            self.server_cid = Some(ack.server_receive_cid);
            self.endpoint = Some(endpoint);
            self.bootstrap_acks = self.bootstrap_acks.saturating_add(1);
            return Ok(Some(used));
        }
        // A sparse bearer (for example a NAN discovery-window action path)
        // can retransmit OPEN before the first OPEN-ACK reaches the client.
        // The server is entitled to resend that same ACK. It is control-plane
        // duplication, not a stream packet or protocol error; ignore it once
        // the peer CID has already been installed.
        if let Ok((_, ack)) =
            quic_lite::decode_bootstrap_open_ack_packet_with_limits(input, self.client_cid)
        {
            if self.server_cid == Some(ack.server_receive_cid) {
                self.bootstrap_acks = self.bootstrap_acks.saturating_add(1);
                return Ok(None);
            }
        }
        let endpoint = self.endpoint.as_mut().ok_or(Error::Invalid)?;
        endpoint.set_time(now_ms);
        let packet = endpoint.receive_datagram(input)?;
        if let TransportPacket::Stream { frame, .. } = packet {
            self.stream_packets = self.stream_packets.saturating_add(1);
            let (complete, consumed) = self
                .run
                .handle(quic_lite::FIRST_SERVER_BIDI_STREAM_ID, frame)
                .map_err(|_| Error::Invalid)?;
            endpoint.stream_consumed(frame.id, consumed)?;
            self.complete = complete;
        } else {
            self.other_packets = self.other_packets.saturating_add(1);
        }
        endpoint.poll_transmit(output)
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
        let Some(endpoint) = self.endpoint.as_mut() else {
            return Ok(None);
        };
        endpoint.set_time(now_ms);
        endpoint.poll_transmit(output)
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
        let Some(endpoint) = self.endpoint.as_mut() else {
            return Ok(None);
        };
        Ok(endpoint
            .retransmit_due(now_us, pto_us, output)?
            .map(|(used, _packet_number)| used))
    }

    pub fn is_complete(&self) -> bool {
        self.complete
    }
    pub fn bytes(&self) -> u64 {
        self.run.bytes()
    }
    pub fn callback_errors(&self) -> [u64; 6] {
        self.run.callback_errors()
    }
    pub fn server_cid(&self) -> Option<ConnectionId> {
        self.server_cid
    }
    /// `(bootstrap_acks, stream_packets, other_transport_packets)` for
    /// adapters that need bounded bring-up diagnostics.
    pub const fn packet_classes(&self) -> (u32, u32, u32) {
        (self.bootstrap_acks, self.stream_packets, self.other_packets)
    }

    pub const fn counters(&self) -> RawServiceCounters {
        RawServiceCounters {
            bootstrap_acks: self.bootstrap_acks,
            stream_packets: self.stream_packets,
            other_packets: self.other_packets,
        }
    }
}

impl<const HISTORY: usize, const PACKET: usize> RawIperfServer<HISTORY, PACKET> {
    pub fn new(local_cid: ConnectionId) -> Self {
        Self::new_with_association(
            local_cid,
            ConnectionLimits::default(),
            RawAssociationProfile::c6_default(),
        )
    }

    /// Construct with a device-derived receive-window limit. This is used by
    /// bounded firmware bearers; `new` remains the host-compatible default.
    pub fn new_with_limits(local_cid: ConnectionId, local_limits: ConnectionLimits) -> Self {
        Self::new_with_association(local_cid, local_limits, RawAssociationProfile::c6_default())
    }

    pub fn new_with_association(
        local_cid: ConnectionId,
        local_limits: ConnectionLimits,
        association: RawAssociationProfile,
    ) -> Self {
        Self {
            local_cid,
            local_limits,
            connection: None,
            open_client_cid: None,
            sender: None,
            pending_flash: None,
            flash_response: None,
            association: association.clamp::<HISTORY>(),
        }
    }

    /// Consume one complete datagram and write at most one immediate response.
    /// `Ok(None)` is normal transport backpressure or an ACK that created no
    /// immediate packet. The caller supplies future input/timer polls.
    pub fn receive(
        &mut self,
        packet: &[u8],
        output: &mut [u8; PACKET],
    ) -> Result<Option<usize>, Error> {
        let (header, _) = ShortHeader::decode(packet)?;
        if header.dcid.value() == 0 {
            let (_, open) = decode_bootstrap_open_packet_with_limits(packet)?;
            if self.connection.is_some() && self.open_client_cid == Some(open.client_receive_cid) {
                let used = encode_bootstrap_open_ack_packet_with_limits(
                    open.client_receive_cid,
                    self.local_cid,
                    0,
                    self.local_limits,
                    output,
                )?;
                return Ok(Some(used));
            }
            let (mut connection, ack) = StreamServerConnection::accept_open_boxed_with_limits(
                packet,
                self.local_cid,
                diagnostic_stream_registry(),
                0,
                self.local_limits,
            )?;
            connection
                .mux
                .endpoint
                .set_history_capacity(self.association.history_packets)?;
            // The RFC initial window is intentionally conservative for a
            // generic path.  A raw action association has already supplied a
            // bounded packet budget, so apply its runtime window here before
            // the first service response.  This lets host links use their
            // full eight-packet ledger while firmware can choose less.
            let initial_window = (self.association.initial_window_packets as u64)
                .saturating_mul(PACKET as u64);
            connection.mux.endpoint.congestion.congestion_window = initial_window;
            connection.mux.endpoint.congestion.slow_start_threshold = initial_window;
            if ack.len() > output.len() {
                return Err(Error::Invalid);
            }
            output[..ack.len()].copy_from_slice(&ack);
            self.connection = Some(connection);
            self.open_client_cid = Some(open.client_receive_cid);
            self.sender = None;
            return Ok(Some(ack.len()));
        }
        let connection = self.connection.as_mut().ok_or(Error::WrongConnectionId)?;
        let request = connection.receive_request(packet)?;
        if let Some(request) = request {
            let Some((&service, _)) = request.data.split_first() else {
                return Err(Error::Invalid);
            };
            // A lost response can make the client retransmit the final
            // service request while the producer is already active. QUIC has
            // accepted and ACKed that duplicate at the endpoint; treating it
            // as an application error poisons the raw bearer and prevents the
            // sender from continuing. Keep the existing producer and emit
            // the next ledger-owned response instead.
            if self.sender.is_some() && service == SERVICE_IPERF {
                return self.poll(output);
            }
            if self.sender.is_some() {
                return Err(Error::Invalid);
            }
            if service == SERVICE_FLASH {
                if self.pending_flash.is_some() || self.flash_response.is_some() {
                    return Err(Error::Invalid);
                }
                let body = &request.data[1..];
                let _: FlashRequest<'_> = decode_flash_request(body).ok_or(Error::Invalid)?;
                self.pending_flash = Some(body.to_vec());
                connection
                    .mux
                    .complete_request(request.stream_id, request.data.len())?;
                return Ok(None);
            }
            if service != SERVICE_IPERF {
                let response = handle_stream(
                    &connection.mux.endpoint,
                    self.local_cid,
                    request.stream_id,
                    &connection.registry,
                    service,
                    &request.data[1..],
                )
                .map_err(|_| Error::Invalid)?;
                connection
                    .mux
                    .complete_request(request.stream_id, request.data.len())?;
                return connection
                    .encode_response(&response, output)
                    .map(|(used, _)| Some(used));
            }
            let request_spec = decode_iperf_service_request(&request.data).ok_or(Error::Invalid)?;
            let plan = IperfServicePlan::from_request(request_spec, PACKET.saturating_sub(32));
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
            connection
                .mux
                .complete_request(request.stream_id, request.data.len())?;
            connection.mux.endpoint.request_ack_frequency(
                0,
                u64::from(self.association.ack_frequency.saturating_sub(1)),
                u64::from(self.association.ack_delay_ms) * 1_000,
                1,
            )?;
            self.sender = IperfSender::new(
                connection.reserve_response_stream(),
                plan.normal_bytes[0],
                plan.packet_size,
            );
        }
        self.poll(output)
    }

    /// Produce one IPERF packet when transport flow credit permits it.
    pub fn poll(&mut self, output: &mut [u8; PACKET]) -> Result<Option<usize>, Error> {
        let connection = self.connection.as_mut().ok_or(Error::WrongConnectionId)?;
        if let Some(response) = self.flash_response.take() {
            return connection
                .encode_response(&response, output)
                .map(|(used, _)| Some(used));
        }
        let Some(sender) = self.sender.as_mut() else {
            return connection.poll_transmit(output);
        };
        let packet = sender.poll(&mut connection.mux.endpoint, output)?;
        if sender.is_complete() {
            self.sender = None;
        }
        Ok(packet.map(|(used, _)| used))
    }

    /// Take one validated device-flash command. The platform handler owns the
    /// sink and object-client lifecycle, while this shared server retains the
    /// original request stream until [`Self::complete_flash`] supplies its
    /// final response.
    pub fn take_flash_request(&mut self) -> Option<Vec<u8>> {
        self.pending_flash.take()
    }

    /// Queue the final response only after the platform reports that its
    /// signed-object sink is durable. This never blocks packet ingress.
    pub fn complete_flash(&mut self, response: Vec<u8>) -> Result<(), Error> {
        if self.pending_flash.is_some() || self.flash_response.is_some() {
            return Err(Error::Invalid);
        }
        self.flash_response = Some(response);
        Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::iperf::{encode_iperf_service_request, IperfServiceRequest};
    use quic_lite::{
        encode_bootstrap_open_packet_with_profile, ConnectionLimits, EndpointState, Role,
    };

    #[test]
    fn receive_error_codes_are_stable_for_firmware_diagnostics() {
        assert_eq!(receive_error_code(Error::WrongConnectionId), 8);
        assert_eq!(receive_error_code(Error::BootstrapInvalid), 9);
        assert_eq!(receive_error_code(Error::HistoryFull), 10);
    }

    #[test]
    fn raw_action_iperf_start_request_accepts_runtime_timeout_and_rate() {
        let request = decode_raw_action_iperf_request(&[
            1, 2, 3, 4, 5, 6, // peer
            0, 0, 0, 0, 0, 0, 0x40, 0, // bytes
            0x04, 0xb0, // packet size
            0, 0, 0x4e, 0x20, // 20 seconds
            54,
        ])
        .unwrap();
        assert_eq!(request.peer, [1, 2, 3, 4, 5, 6]);
        assert_eq!(request.bytes, 16 * 1024);
        assert_eq!(request.packet_size, 1200);
        assert_eq!(request.timeout_ms, 20_000);
        assert_eq!(request.tx_rate_mbps, 54);
    }

    #[test]
    fn raw_action_iperf_start_request_preserves_legacy_defaults() {
        let request =
            decode_raw_action_iperf_request(&[1, 2, 3, 4, 5, 6, 0, 0, 0, 0, 0, 0, 0, 4]).unwrap();
        assert_eq!(request.packet_size, 1200);
        assert_eq!(request.timeout_ms, RAW_ACTION_IPERF_DEFAULT_TIMEOUT_MS);
        assert_eq!(request.tx_rate_mbps, 0);
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
        let mut client = RawObjectClient::<4, 1200>::new(client_cid, request).unwrap();
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
        let mut listener = RawIperfServer::<4, 1200>::new(server);
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

        let request = FlashRequest {
            object: GetRequest {
                name: None,
                cpu: 13,
                target: 6,
            },
            address: None,
            transport: 0,
            dry_run: true,
        };
        let mut body = [0u8; 64];
        body[0] = SERVICE_FLASH;
        let body_len = crate::protocol::encode_flash_request(request, &mut body[1..]).unwrap() + 1;
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
        assert_eq!(listener.take_flash_request().unwrap(), body[1..body_len]);
        // The request may have released a transport ACK, but not an
        // application response before durable flash completion.
        let _ = listener.poll(&mut out).unwrap();
        listener.complete_flash(b"flash complete".to_vec()).unwrap();
        assert!(listener.poll(&mut out).unwrap().is_some());
    }

    #[test]
    fn accepts_a_socket_free_iperf_request_and_produces_stream_data() {
        let client = ConnectionId::new(7).unwrap();
        let server = ConnectionId::new(9).unwrap();
        let mut listener = RawIperfServer::<4, 1200>::new(server);
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
        assert!(listener
            .receive(&open[..open_len], &mut out)
            .unwrap()
            .is_some());
        // Wi-Fi retries may redeliver OPEN after its ACK was queued. It must
        // not replace the admitted endpoint or advance its receive packet
        // number before the client's first stream packet.
        assert!(listener
            .receive(&open[..open_len], &mut out)
            .unwrap()
            .is_some());

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
        let mut body = [0u8; 31];
        let body_len =
            encode_iperf_service_request(IperfServiceRequest::new(64, 64), &mut body).unwrap();
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
        let mut client = RawIperfClient::<4, 1200>::new(client_cid, 8 * 1024).unwrap();
        let mut server = RawIperfServer::<4, 1200>::new(server_cid);
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
            let client_len = client_len.expect("IPERF stream packet must produce ACK");
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
    fn check_client_receives_compact_echo_over_raw_bearer() {
        let client_cid = ConnectionId::new(0x66).unwrap();
        let server_cid = ConnectionId::new(0x77).unwrap();
        let mut client = RawCheckClient::<4, 1200>::new(client_cid, 0x1234);
        let mut server = RawIperfServer::<4, 1200>::new(server_cid);
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
        assert!(client
            .response()
            .is_some_and(|response| !response.is_empty()));
        assert_eq!(client.bytes(), client.response().unwrap().len() as u64);
    }

    #[test]
    fn check_client_reacks_a_retransmitted_final_response() {
        let client_cid = ConnectionId::new(0xa6).unwrap();
        let server_cid = ConnectionId::new(0xb7).unwrap();
        let mut client = RawCheckClient::<4, 1200>::new(client_cid, 0x3456);
        let mut server = RawIperfServer::<4, 1200>::new(server_cid);
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
    fn iperf_server_accepts_retransmitted_service_request_while_streaming() {
        let client_cid = ConnectionId::new(0xd6).unwrap();
        let server_cid = ConnectionId::new(0xe7).unwrap();
        let mut client = RawIperfClient::<8, 1200>::new(client_cid, 2048).unwrap();
        let mut server = RawIperfServer::<8, 1200>::new(server_cid);
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
        // lost. It must not invalidate the already-active IPERF producer.
        assert!(server
            .receive(&client_out[..request_len], &mut server_out)
            .is_ok());
        assert!(first_response > 0);
    }

    #[test]
    fn check_client_ignores_a_retransmitted_bootstrap_ack() {
        let client_cid = ConnectionId::new(0xc6).unwrap();
        let server_cid = ConnectionId::new(0xd7).unwrap();
        let mut client = RawCheckClient::<4, 1200>::new(client_cid, 0x5678);
        let mut server = RawIperfServer::<4, 1200>::new(server_cid);
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
    }

    #[test]
    fn check_recovers_a_lost_action_response_from_the_shared_ledger() {
        let client_cid = ConnectionId::new(0x86).unwrap();
        let server_cid = ConnectionId::new(0x97).unwrap();
        let path = RawIngressPath {
            transport_id: 2,
            peer: [7; 6],
        };
        let mut client = RawCheckClient::<4, 1200>::new(client_cid, 0x2345);
        let mut server = RawIperfDispatcher::<4, 1200>::new(
            server_cid,
            ConnectionLimits::default(),
            RawAssociationProfile::c6_default(),
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
    fn conservative_action_profile_completes_16k_in_256_byte_packets() {
        // This is the exact packet-at-a-time association used by the raw
        // ESP-NOW-compatible adapter. It deliberately contains no radio,
        // task, or timer dependency: a failure here would be a shared
        // protocol/ledger problem, while an on-air timeout is adapter/RF
        // evidence to investigate separately.
        let client_cid = ConnectionId::new(0x46).unwrap();
        let server_cid = ConnectionId::new(0x56).unwrap();
        let mut client =
            RawIperfClient::<4, 1200>::new_with_packet_size(client_cid, 16 * 1024, 256).unwrap();
        let mut server = RawIperfServer::<4, 1200>::new_with_association(
            server_cid,
            ConnectionLimits::default(),
            RawAssociationProfile::conservative(),
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
    fn client_preserves_requested_radio_packet_size() {
        let client = RawIperfClient::<4, 1200>::new_with_packet_size(
            ConnectionId::new(0x44).unwrap(),
            1024,
            256,
        )
        .unwrap();
        assert_eq!(
            decode_iperf_service_request(&client.request[..client.request_len])
                .unwrap()
                .packet_size,
            256
        );
    }
}
