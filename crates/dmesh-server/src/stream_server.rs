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

pub use quic_lite::ClientStreamConnection as StreamClientConnection;
use quic_lite::{ConnectionId, ConnectionLimits, Error, ServerStreamConnection};
#[cfg(test)]
use quic_lite::{
    FIRST_CLIENT_BIDI_STREAM_ID, FIRST_SERVER_BIDI_STREAM_ID,
    decode_bootstrap_open_packet_with_limits, encode_bootstrap_open_ack_packet,
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
    core: ServerStreamConnection<{ quic_lite::DEFAULT_STREAM_STATE_SLOTS }, HISTORY, PACKET>,
    pub events: EventRing,
}

impl<const HISTORY: usize, const PACKET: usize> core::ops::Deref
    for StreamServerConnection<HISTORY, PACKET>
{
    type Target =
        ServerStreamConnection<{ quic_lite::DEFAULT_STREAM_STATE_SLOTS }, HISTORY, PACKET>;

    fn deref(&self) -> &Self::Target {
        &self.core
    }
}

impl<const HISTORY: usize, const PACKET: usize> core::ops::DerefMut
    for StreamServerConnection<HISTORY, PACKET>
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.core
    }
}

impl<const HISTORY: usize, const PACKET: usize> StreamServerConnection<HISTORY, PACKET> {
    /// Accept one complete custom-version Initial OPEN and encode its OPEN_ACK.
    ///
    /// The caller chooses the local DCID after its own fixed-capacity
    /// admission check. The returned ACK is a complete bearer datagram.
    pub fn accept_open(
        packet: &[u8],
        server_cid: ConnectionId,
        event_capacity: usize,
    ) -> Result<(Self, Vec<u8>), Error> {
        Self::accept_open_with_limits(
            packet,
            server_cid,
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
        event_capacity: usize,
        local_limits: ConnectionLimits,
    ) -> Result<(Self, Vec<u8>), Error> {
        let (core, ack) =
            ServerStreamConnection::accept_open_with_limits(packet, server_cid, local_limits)?;
        Ok((
            Self {
                core,
                events: EventRing::new(event_capacity),
            },
            ack,
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
        event_capacity: usize,
        local_limits: ConnectionLimits,
    ) -> Result<(Box<Self>, Vec<u8>), Error> {
        Self::accept_open_boxed_with_limits_and_reset_token(
            packet,
            server_cid,
            event_capacity,
            local_limits,
            None,
        )
    }

    /// In-place firmware accept that advertises the token derived by
    /// quic-lite from the device's provisioned control-plane secret.
    pub fn accept_open_boxed_with_limits_and_reset_token(
        packet: &[u8],
        server_cid: ConnectionId,
        event_capacity: usize,
        local_limits: ConnectionLimits,
        stateless_reset_token: Option<quic_lite::StatelessResetToken>,
    ) -> Result<(Box<Self>, Vec<u8>), Error> {
        Self::accept_open_boxed_with_config_and_reset_token(
            packet,
            server_cid,
            event_capacity,
            local_limits,
            quic_lite::ServerStreamConfig::default(),
            stateless_reset_token,
        )
    }

    /// Heap-backed accept with an association-specific callback reordering
    /// allowance. The allowance remains bounded by the caller's negotiated
    /// packet ledger; it is not a bearer queue.
    pub fn accept_open_boxed_with_config_and_reset_token(
        packet: &[u8],
        server_cid: ConnectionId,
        event_capacity: usize,
        local_limits: ConnectionLimits,
        config: quic_lite::ServerStreamConfig,
        stateless_reset_token: Option<quic_lite::StatelessResetToken>,
    ) -> Result<(Box<Self>, Vec<u8>), Error> {
        // Initialize the generic connection core directly in its final outer
        // allocation, then add only DMesh event state around it.
        let mut connection = Box::<Self>::new_uninit();
        let pointer = connection.as_mut_ptr().cast::<Self>();
        unsafe {
            let ack = ServerStreamConnection::accept_open_in_place_with_config_and_reset_token(
                core::ptr::addr_of_mut!((*pointer).core),
                packet,
                server_cid,
                local_limits,
                config,
                stateless_reset_token,
            )?;
            core::ptr::addr_of_mut!((*pointer).events).write(EventRing::new(event_capacity));
            Ok((connection.assume_init(), ack))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quic_lite::{
        BootstrapClient, Frame, ShortHeader, decode_bootstrap_open_ack_packet_with_limits,
        decode_frame,
    };

    #[test]
    fn accepts_open_with_budget_and_nonzero_response_packet_number() {
        let client = ConnectionId::new(20).unwrap();
        let server = ConnectionId::new(21).unwrap();
        let mut bootstrap = BootstrapClient::new(client, 500_000, 4).unwrap();
        let mut open = [0u8; 1200];
        let open_len = bootstrap.start_open(0, &mut open).unwrap();
        let (mut connection, ack) =
            StreamServerConnection::<1>::accept_open(&open[..open_len], server, 2).unwrap();
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
        let (mut connection, _) =
            StreamServerConnection::<2>::accept_open(&open[..open_len], server, 0).unwrap();
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
        let mut connection =
            StreamClientConnection::<2>::new(client, 500_000, 4, Some(vec![2, b'o', b'k']))
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
        assert_eq!(stream.data, &[2, b'o', b'k']);
    }
}
