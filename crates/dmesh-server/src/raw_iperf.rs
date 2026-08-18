//! Bounded IPERF server for a socket-free datagram bearer.
//!
//! Ethernet, ESP-NOW, UART, and simulated bearers supply complete QUIC-lite
//! datagrams to this type and send its optional response unchanged. The type
//! has no socket, task, ESP-IDF, or peer-address dependency.

use quic_lite::{
    ConnectionId, ConnectionLimits, EndpointState, Error, Role, SERVICE_IPERF, ShortHeader,
    TransportPacket,
    iperf::{IperfRun, IperfSender},
};

use crate::{
    iperf::{IperfServicePlan, decode_iperf_service_request},
    services::diagnostic_stream_registry,
    stream_server::StreamServerConnection,
};

/// Runtime settings selected while establishing a complete-datagram bearer.
/// The type-level history is only an allocation ceiling; these values select
/// what one association actually advertises and retains.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RawAssociationProfile {
    pub history_packets: usize,
    pub ack_frequency: u8,
    pub ack_delay_ms: u8,
    pub tx_burst_packets: usize,
}

impl RawAssociationProfile {
    pub const fn conservative() -> Self {
        Self {
            history_packets: 1,
            ack_frequency: 1,
            ack_delay_ms: 5,
            tx_burst_packets: 1,
        }
    }
    pub const fn c6_default() -> Self {
        Self {
            history_packets: 8,
            ack_frequency: 8,
            ack_delay_ms: 5,
            tx_burst_packets: 8,
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
        }
    }
}

/// One active diagnostic connection is sufficient for the initial Recovery
/// raw-UDP6 validation. The bearer remains responsible for peer/MAC binding
/// and can allocate a separate server instance when it admits more peers.
pub struct RawIperfServer<const HISTORY: usize, const PACKET: usize> {
    local_cid: ConnectionId,
    local_limits: ConnectionLimits,
    connection: Option<StreamServerConnection<HISTORY, PACKET>>,
    sender: Option<IperfSender>,
    association: RawAssociationProfile,
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
}

impl<const HISTORY: usize, const PACKET: usize> RawIperfClient<HISTORY, PACKET> {
    pub fn new(client_cid: ConnectionId, bytes: u64) -> Result<Self, Error> {
        let mut request = [0u8; 31];
        let request_len = crate::iperf::encode_iperf_service_request(
            crate::iperf::IperfServiceRequest::new(bytes, PACKET as u16),
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
        })
    }

    /// Start bootstrap. Call once, then transmit the returned packet.
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

    /// Consume one peer packet and optionally produce exactly one outbound
    /// packet. `Ok(None)` means the client made progress but has no immediate
    /// packet to send; the caller must still continue receiving.
    pub fn receive(
        &mut self,
        input: &[u8],
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
            return Ok(Some(used));
        }
        let endpoint = self.endpoint.as_mut().ok_or(Error::Invalid)?;
        let packet = endpoint.receive_datagram(input)?;
        if let TransportPacket::Stream { frame, .. } = packet {
            let (complete, consumed) = self
                .run
                .handle(quic_lite::FIRST_SERVER_BIDI_STREAM_ID, frame)
                .map_err(|_| Error::Invalid)?;
            endpoint.stream_consumed(frame.id, consumed)?;
            self.complete = complete;
        }
        endpoint.poll_transmit(output)
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
            sender: None,
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
            let (mut connection, ack) = StreamServerConnection::accept_open_with_limits(
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
            if ack.len() > output.len() {
                return Err(Error::Invalid);
            }
            output[..ack.len()].copy_from_slice(&ack);
            self.connection = Some(connection);
            self.sender = None;
            return Ok(Some(ack.len()));
        }
        let connection = self.connection.as_mut().ok_or(Error::WrongConnectionId)?;
        let request = connection.receive_request(packet)?;
        if let Some(request) = request {
            let Some((&service, _)) = request.data.split_first() else {
                return Err(Error::Invalid);
            };
            if service != SERVICE_IPERF || self.sender.is_some() {
                return Err(Error::Invalid);
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
        let Some(sender) = self.sender.as_mut() else {
            return connection.poll_transmit(output);
        };
        let packet = sender.poll(&mut connection.mux.endpoint, output)?;
        if sender.is_complete() {
            self.sender = None;
        }
        Ok(packet.map(|(used, _)| used))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::iperf::{IperfServiceRequest, encode_iperf_service_request};
    use quic_lite::{
        ConnectionLimits, EndpointState, Role, encode_bootstrap_open_packet_with_profile,
    };

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
}
