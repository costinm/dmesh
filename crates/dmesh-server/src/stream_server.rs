//! Bearer-neutral QUIC-lite server-side connection state.
//!
//! IMPORTANT: this module has no sockets, tasks, peer-address type, ESP-IDF,
//! or application-module dependency. A bearer owns peer identity, DCID-table
//! admission, packet I/O, and lifecycle; an application supplies service
//! results. Keeping this state here makes UART, UDP, simulated links, and
//! firmware use the same bootstrap and response-stream rules.

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::vec::Vec;

#[cfg(test)]
use quic_lite::encode_bootstrap_open_ack_packet;
use quic_lite::mux::MuxRequest;
use quic_lite::mux::StreamMux;
use quic_lite::{
    decode_bootstrap_open_packet_with_limits, encode_bootstrap_open_ack_packet_with_limits,
    BootstrapClient, ConnectionId, ConnectionLimits, Error, PathPolicy, Role, ShortHeader,
    StreamRegistry, FIRST_CLIENT_BIDI_STREAM_ID, FIRST_SERVER_BIDI_STREAM_ID,
    INITIAL_MAX_STREAM_DATA,
};

use crate::services::{EventRing, MAX_BINARY_EVENT_PAYLOAD_BYTES};

/// Compact peer/DCID association retained after an active stream connection
/// is reclaimed. The peer type is bearer-owned: MACs, socket addresses, and
/// host simulation keys all use the same bounded replacement policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PassiveAssociation<Peer> {
    pub peer: Peer,
    pub dcid: ConnectionId,
    pub seen: u32,
}

/// Fixed-capacity passive association cache. It owns no mux, packet ledger,
/// service buffer, socket, or task state.
pub struct PassiveAssociations<Peer, const CAPACITY: usize> {
    entries: [Option<PassiveAssociation<Peer>>; CAPACITY],
}

impl<Peer: Copy + Eq, const CAPACITY: usize> PassiveAssociations<Peer, CAPACITY> {
    pub fn new() -> Self {
        Self {
            entries: core::array::from_fn(|_| None),
        }
    }

    /// Remember or refresh an association. `seen` is supplied by the adapter
    /// so the cache remains clock/atomic-free and host-testable.
    pub fn remember(&mut self, peer: Peer, dcid: ConnectionId, seen: u32) {
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
        if let Some((oldest, _)) = self
            .entries
            .iter()
            .enumerate()
            .min_by_key(|(_, entry)| entry.map(|entry| entry.seen).unwrap_or(u32::MAX))
        {
            self.entries[oldest] = Some(PassiveAssociation { peer, dcid, seen });
        }
    }

    pub fn get(&self, peer: Peer) -> Option<PassiveAssociation<Peer>> {
        self.entries
            .iter()
            .flatten()
            .copied()
            .find(|entry| entry.peer == peer)
    }

    pub fn len(&self) -> usize {
        self.entries.iter().flatten().count()
    }
}

/// One opaque application event. The transport and its bearers never infer
/// module, log, trace, or hardware meaning from these fields.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BinaryEvent {
    pub sequence: u64,
    pub event_id: u16,
    pub value_type: u8,
    pub flags: u8,
    pub payload: Vec<u8>,
}

/// Bounded event/trace history shared by any server adapter. Producers can
/// hold their own nonblocking lock and call `push`; a full history discards
/// the oldest whole event rather than blocking or retaining unbounded memory.
pub struct BinaryEventHistory {
    next_sequence: u64,
    capacity: usize,
    records: VecDeque<BinaryEvent>,
}

impl BinaryEventHistory {
    pub fn new(capacity: usize) -> Self {
        Self {
            next_sequence: 0,
            capacity,
            records: VecDeque::with_capacity(capacity),
        }
    }

    /// Retain only a bounded payload. At capacity, the oldest complete event
    /// expires before the newest is copied into the history.
    pub fn push(&mut self, event_id: u16, value_type: u8, flags: u8, payload: &[u8]) -> bool {
        if self.capacity == 0 || payload.len() > MAX_BINARY_EVENT_PAYLOAD_BYTES {
            return false;
        }
        let event = BinaryEvent {
            sequence: self.next_sequence,
            event_id,
            value_type,
            flags,
            payload: payload.to_vec(),
        };
        self.next_sequence = self.next_sequence.saturating_add(1);
        if self.records.len() == self.capacity {
            self.records.pop_front();
        }
        self.records.push_back(event);
        true
    }

    pub fn next_sequence(&self) -> u64 {
        self.next_sequence
    }

    pub fn records_since(&self, sequence: u64) -> impl Iterator<Item = &BinaryEvent> {
        self.records
            .iter()
            .filter(move |event| event.sequence >= sequence)
    }
}

/// Server-side persistent QUIC-lite stream state.
///
/// The response stream is server initiated. It must never reuse a client
/// request stream ID: direction validation is deliberately identical on host
/// and embedded clients.
pub struct StreamServerConnection<
    const HISTORY: usize,
    const PACKET: usize = { quic_lite::DEFAULT_MAX_DATAGRAM_SIZE },
> {
    /// Four normal IPERF streams plus high/low diagnostic lanes. This is a
    /// server-wide handler capacity, shared by host and firmware adapters;
    /// it must not be smaller than `IperfServicePlan` can advertise.
    pub mux: StreamMux<6, HISTORY, PACKET>,
    pub registry: StreamRegistry,
    pub events: EventRing,
    path_policy: PathPolicy,
    next_response_stream: u64,
}

impl<const HISTORY: usize, const PACKET: usize> StreamServerConnection<HISTORY, PACKET> {
    /// Accept one complete DCID-zero OPEN and encode its OPEN_ACK.
    ///
    /// The caller chooses the local DCID after its own fixed-capacity
    /// admission check. The returned ACK is a complete bearer datagram.
    pub fn accept_open(
        packet: &[u8],
        server_cid: ConnectionId,
        registry: StreamRegistry,
        event_capacity: usize,
    ) -> Result<(Self, Vec<u8>), Error> {
        Self::accept_open_with_limits(
            packet,
            server_cid,
            registry,
            event_capacity,
            ConnectionLimits::default(),
        )
    }

    /// Accept a bootstrap with a caller-owned local RAM/flow-control limit.
    /// The encoded OPEN_ACK carries these exact limits, so an embedded bearer
    /// cannot accidentally advertise the host default receive window.
    pub fn accept_open_with_limits(
        packet: &[u8],
        server_cid: ConnectionId,
        registry: StreamRegistry,
        event_capacity: usize,
        local_limits: ConnectionLimits,
    ) -> Result<(Self, Vec<u8>), Error> {
        let (bootstrap_header, open) = decode_bootstrap_open_packet_with_limits(packet)?;
        let client_cid = open.client_receive_cid;
        let mut mux = StreamMux::new(Role::Server, local_limits, PACKET as u64, 1, 4, 4096);
        mux.install_connection_ids(server_cid, client_cid)?;
        // OPEN and OPEN_ACK are bearer-owned packets. Persist the negotiated
        // receive budget and packet-number boundary before processing streams,
        // otherwise the first response can be mistaken for ACK packet zero.
        mux.endpoint.set_initial_peer_budget(
            open.max_data,
            open.max_stream_data,
            open.max_in_flight_packets,
        )?;
        mux.endpoint
            .continue_packet_numbers_from(bootstrap_header.packet_number.saturating_add(1))?;

        let mut ack = [0u8; PACKET];
        let used = encode_bootstrap_open_ack_packet_with_limits(
            client_cid,
            server_cid,
            0,
            local_limits,
            &mut ack,
        )?;
        Ok((
            Self {
                mux,
                registry,
                events: EventRing::new(event_capacity),
                path_policy: PathPolicy::HighestMeasuredSpeed,
                next_response_stream: FIRST_SERVER_BIDI_STREAM_ID,
            },
            ack[..used].to_vec(),
        ))
    }

    /// Heap-backed counterpart to [`Self::accept_open_with_limits`].
    ///
    /// A complete-datagram firmware bearer calls this from its shared Wi-Fi
    /// ingress task. `EndpointState` includes the bounded retransmission
    /// ledger, so constructing the connection as a local return value can
    /// transiently consume several copies of that ledger on the task stack.
    /// Construct the `StreamMux` directly in its final allocation instead;
    /// this changes neither wire behavior nor the per-association budget.
    pub fn accept_open_boxed_with_limits(
        packet: &[u8],
        server_cid: ConnectionId,
        registry: StreamRegistry,
        event_capacity: usize,
        local_limits: ConnectionLimits,
    ) -> Result<(Box<Self>, Vec<u8>), Error> {
        let (bootstrap_header, open) = decode_bootstrap_open_packet_with_limits(packet)?;
        let client_cid = open.client_receive_cid;

        let mut ack = [0u8; PACKET];
        let used = encode_bootstrap_open_ack_packet_with_limits(
            client_cid,
            server_cid,
            0,
            local_limits,
            &mut ack,
        )?;

        // `Box::new_uninit` gives `StreamMux::new` its final return place,
        // avoiding a full endpoint ledger in the caller's stack frame.
        let mut connection = Box::<Self>::new_uninit();
        let pointer = connection.as_mut_ptr().cast::<Self>();
        unsafe {
            StreamMux::init_in_place(
                core::ptr::addr_of_mut!((*pointer).mux),
                Role::Server,
                local_limits,
                PACKET as u64,
                4,
                4096,
            );
            core::ptr::addr_of_mut!((*pointer).registry).write(registry);
            core::ptr::addr_of_mut!((*pointer).events).write(EventRing::new(event_capacity));
            core::ptr::addr_of_mut!((*pointer).path_policy).write(PathPolicy::HighestMeasuredSpeed);
            core::ptr::addr_of_mut!((*pointer).next_response_stream)
                .write(FIRST_SERVER_BIDI_STREAM_ID);
            let mut connection = connection.assume_init();
            connection
                .mux
                .install_connection_ids(server_cid, client_cid)?;
            connection.mux.endpoint.set_initial_peer_budget(
                open.max_data,
                open.max_stream_data,
                open.max_in_flight_packets,
            )?;
            connection
                .mux
                .endpoint
                .continue_packet_numbers_from(bootstrap_header.packet_number.saturating_add(1))?;
            Ok((connection, ack[..used].to_vec()))
        }
    }

    pub fn path_policy(&self) -> PathPolicy {
        self.path_policy
    }

    pub fn set_path_policy(&mut self, policy: PathPolicy) {
        self.path_policy = policy;
    }

    /// Reserve the next server-initiated bidirectional stream ID for a
    /// multi-packet producer. The producer still uses `mux.endpoint` for
    /// every packet, so packet numbers, ACK/loss state, and peer flow credit
    /// remain in the shared QUIC-lite endpoint.
    pub fn reserve_response_stream(&mut self) -> u64 {
        let stream = self.next_response_stream;
        self.next_response_stream = self.next_response_stream.saturating_add(4);
        stream
    }

    pub fn receive_request(&mut self, packet: &[u8]) -> Result<Option<MuxRequest>, Error> {
        self.mux.receive_request(packet)
    }

    /// Encode a final service response on the next server bidi stream.
    pub fn encode_response(&mut self, body: &[u8], out: &mut [u8]) -> Result<(usize, u32), Error> {
        let stream = self.reserve_response_stream();
        self.mux.encode_response(stream, body, true, out)
    }

    pub fn poll_transmit(&mut self, out: &mut [u8]) -> Result<Option<usize>, Error> {
        self.mux.endpoint.poll_transmit(out)
    }
}

/// Bearer-neutral locally initiated connection state. A bearer chooses the
/// peer and sends the returned complete datagrams; it never owns bootstrap
/// credit, connection IDs, or the first request stream.
pub struct StreamClientConnection<
    const HISTORY: usize,
    const PACKET: usize = { quic_lite::DEFAULT_MAX_DATAGRAM_SIZE },
> {
    mux: StreamMux<4, HISTORY, PACKET>,
    bootstrap: Option<BootstrapClient>,
    pending_request: Option<Vec<u8>>,
}

impl<const HISTORY: usize, const PACKET: usize> StreamClientConnection<HISTORY, PACKET> {
    pub fn new(
        local_cid: ConnectionId,
        retry_timeout_us: u64,
        max_attempts: u8,
        request: Option<Vec<u8>>,
    ) -> Result<Self, Error> {
        Ok(Self {
            mux: StreamMux::new(
                Role::Client,
                ConnectionLimits::default(),
                PACKET as u64,
                1,
                4,
                4096,
            ),
            bootstrap: Some(BootstrapClient::new(
                local_cid,
                retry_timeout_us,
                max_attempts,
            )?),
            pending_request: request,
        })
    }

    pub fn start_open(&mut self, now_us: u64, out: &mut [u8]) -> Result<usize, Error> {
        self.bootstrap
            .as_mut()
            .ok_or(Error::BootstrapInvalid)?
            .start_open(now_us, out)
    }

    /// Apply a complete OPEN_ACK and, when one was queued, encode its request
    /// stream. The response uses the peer's advertised credit and a fresh
    /// packet number; packet zero remains reserved for OPEN_ACK.
    pub fn receive_open_ack_and_request(
        &mut self,
        packet: &[u8],
        out: &mut [u8],
    ) -> Result<Option<usize>, Error> {
        let (ack_header, _) = ShortHeader::decode(packet)?;
        let bootstrap = self.bootstrap.as_mut().ok_or(Error::BootstrapInvalid)?;
        let peer = bootstrap.on_open_ack(packet)?;
        self.mux
            .install_connection_ids(bootstrap.local_cid(), peer)?;
        // OPEN_ACK is bearer-owned packet zero. The first persistent request
        // must start after it or the peer's duplicate detector discards it.
        self.mux
            .endpoint
            .continue_packet_numbers_from(ack_header.packet_number.saturating_add(1))?;
        self.bootstrap = None;
        let Some(request) = self.pending_request.take() else {
            return Ok(None);
        };
        self.mux
            .endpoint
            .open_send_stream(FIRST_CLIENT_BIDI_STREAM_ID, INITIAL_MAX_STREAM_DATA)?;
        let (used, _) = self.mux.endpoint.encode_stream_packet(
            peer,
            FIRST_CLIENT_BIDI_STREAM_ID,
            0,
            true,
            &request,
            out,
        )?;
        Ok(Some(used))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quic_lite::{
        decode_bootstrap_open_ack_packet_with_limits, decode_frame, BootstrapClient, Frame,
        ShortHeader, StreamRegistry,
    };

    #[test]
    fn accepts_open_with_budget_and_nonzero_response_packet_number() {
        let client = ConnectionId::new(20).unwrap();
        let server = ConnectionId::new(21).unwrap();
        let mut bootstrap = BootstrapClient::new(client, 500_000, 4).unwrap();
        let mut open = [0u8; 1200];
        let open_len = bootstrap.start_open(0, &mut open).unwrap();
        let (mut connection, ack) = StreamServerConnection::<1>::accept_open(
            &open[..open_len],
            server,
            StreamRegistry::empty(),
            2,
        )
        .unwrap();
        let (_, parsed_ack) = decode_bootstrap_open_ack_packet_with_limits(&ack, client).unwrap();
        assert_eq!(parsed_ack.server_receive_cid, server);
        assert_eq!(connection.mux.endpoint.local_connection_id(), Some(server));
        assert_eq!(connection.mux.endpoint.peer_connection_id(), Some(client));

        let mut response = [0u8; 1200];
        let used = connection.encode_response(b"ok", &mut response).unwrap().0;
        let (header, header_len) = ShortHeader::decode(&response[..used]).unwrap();
        assert_eq!(header.packet_number, 1);
        let (frame, _) = decode_frame(&response[header_len..used]).unwrap();
        let Frame::Stream(stream) = frame else {
            panic!("response stream")
        };
        assert_eq!(stream.id, FIRST_SERVER_BIDI_STREAM_ID);
    }

    #[test]
    fn response_stream_ids_are_server_bidi_and_monotonic() {
        let client = ConnectionId::new(30).unwrap();
        let server = ConnectionId::new(31).unwrap();
        let mut bootstrap = BootstrapClient::new(client, 500_000, 4).unwrap();
        let mut open = [0u8; 1200];
        let open_len = bootstrap.start_open(0, &mut open).unwrap();
        let (mut connection, _) = StreamServerConnection::<2>::accept_open(
            &open[..open_len],
            server,
            StreamRegistry::empty(),
            0,
        )
        .unwrap();
        let mut output = [0u8; 1200];
        let first = connection.encode_response(b"one", &mut output).unwrap().0;
        let (_, first_header_len) = ShortHeader::decode(&output[..first]).unwrap();
        let (Frame::Stream(first_stream), _) =
            decode_frame(&output[first_header_len..first]).unwrap()
        else {
            panic!("first stream")
        };
        let first_stream_id = first_stream.id;
        let second = connection.encode_response(b"two", &mut output).unwrap().0;
        let (_, second_header_len) = ShortHeader::decode(&output[..second]).unwrap();
        let (Frame::Stream(second_stream), _) =
            decode_frame(&output[second_header_len..second]).unwrap()
        else {
            panic!("second stream")
        };
        assert_eq!(first_stream_id, FIRST_SERVER_BIDI_STREAM_ID);
        assert_eq!(second_stream.id, FIRST_SERVER_BIDI_STREAM_ID + 4);
    }

    #[test]
    fn passive_associations_replace_only_the_oldest_entry() {
        let mut associations = PassiveAssociations::<u8, 2>::new();
        associations.remember(1, ConnectionId::new(10).unwrap(), 10);
        associations.remember(2, ConnectionId::new(11).unwrap(), 11);
        associations.remember(1, ConnectionId::new(12).unwrap(), 12);
        associations.remember(3, ConnectionId::new(13).unwrap(), 13);
        assert_eq!(associations.len(), 2);
        assert_eq!(associations.get(1).unwrap().dcid.value(), 12);
        assert_eq!(associations.get(2), None);
        assert_eq!(associations.get(3).unwrap().dcid.value(), 13);
    }

    #[test]
    fn binary_event_history_is_bounded_and_payload_opaque() {
        let mut history = BinaryEventHistory::new(2);
        assert!(history.push(1, 2, 3, b"first"));
        assert!(history.push(4, 5, 6, b"second"));
        assert!(history.push(7, 8, 9, b"third"));
        let events: Vec<_> = history.records_since(0).collect();
        assert_eq!(history.next_sequence(), 3);
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].sequence, 1);
        assert_eq!(events[0].payload, b"second");
        assert_eq!(events[1].payload, b"third");
    }

    #[test]
    fn binary_event_history_rejects_an_unbounded_payload() {
        let mut history = BinaryEventHistory::new(1);
        assert!(!history.push(1, 2, 3, &[0; MAX_BINARY_EVENT_PAYLOAD_BYTES + 1],));
        assert_eq!(history.records_since(0).count(), 0);
    }

    #[test]
    fn client_bootstrap_uses_peer_credit_and_first_client_stream() {
        let client = ConnectionId::new(40).unwrap();
        let server = ConnectionId::new(41).unwrap();
        let mut connection = StreamClientConnection::<2>::new(
            client,
            500_000,
            4,
            Some(vec![quic_lite::SERVICE_ECHO, b'o', b'k']),
        )
        .unwrap();
        let mut open = [0u8; 1200];
        let open_len = connection.start_open(0, &mut open).unwrap();
        let (_, received_open) =
            decode_bootstrap_open_packet_with_limits(&open[..open_len]).unwrap();
        assert_eq!(received_open.client_receive_cid, client);
        let mut ack = [0u8; 1200];
        let ack_len = encode_bootstrap_open_ack_packet(client, server, 0, &mut ack).unwrap();
        let mut request = [0u8; 1200];
        let used = connection
            .receive_open_ack_and_request(&ack[..ack_len], &mut request)
            .unwrap()
            .unwrap();
        let (header, header_len) = ShortHeader::decode(&request[..used]).unwrap();
        assert_eq!(header.packet_number, 1);
        let (Frame::Stream(stream), _) = decode_frame(&request[header_len..used]).unwrap() else {
            panic!("client stream")
        };
        assert_eq!(stream.id, FIRST_CLIENT_BIDI_STREAM_ID);
        assert_eq!(stream.data, &[quic_lite::SERVICE_ECHO, b'o', b'k']);
    }
}
