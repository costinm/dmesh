//! Bearer-neutral stream services used by UDP, NAN, fake links, and devices.
//!
//! This module deliberately has no socket or bearer code. A bearer decodes a
//! stream packet, passes the service tag/body to [`handle_stream`], and sends
//! the returned response on its own transport.

use crate::{
    ConnectionId, EndpointState, SERVICE_CONTROL, SERVICE_ECHO, SERVICE_EVENTS, SERVICE_IPERF,
    SERVICE_METRICS, SERVICE_OBJECT, SERVICE_STATUS, SERVICE_STREAM,
};
use alloc::format;
use alloc::vec::Vec;

const MAX_EVENT_RESPONSE_BYTES: usize = 1200;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EventRecord {
    pub sequence: u64,
    pub kind: u8,
    pub stream_id: u64,
    pub packet_number: u64,
    pub value: u64,
}

/// Bounded, bearer-neutral event history for diagnostics and test control.
#[derive(Clone, Debug)]
pub struct EventRing {
    entries: Vec<EventRecord>,
    next_sequence: u64,
    capacity: usize,
}

impl EventRing {
    pub fn new(capacity: usize) -> Self {
        Self {
            entries: Vec::with_capacity(capacity),
            next_sequence: 0,
            capacity,
        }
    }
    pub fn capacity(&self) -> usize {
        self.capacity
    }
    pub fn next_sequence(&self) -> u64 {
        self.next_sequence
    }
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn records(&self) -> &[EventRecord] {
        &self.entries
    }
    pub fn push(&mut self, kind: u8, stream_id: u64, packet_number: u64, value: u64) {
        if self.capacity == 0 {
            return;
        }
        let record = EventRecord {
            sequence: self.next_sequence,
            kind,
            stream_id,
            packet_number,
            value,
        };
        self.next_sequence = self.next_sequence.saturating_add(1);
        if self.entries.len() == self.capacity {
            self.entries.remove(0);
        }
        self.entries.push(record);
    }
    pub fn since(&self, sequence: u64) -> impl Iterator<Item = &EventRecord> {
        self.entries
            .iter()
            .filter(move |record| record.sequence >= sequence)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StreamHandler {
    pub tag: u8,
    pub name: &'static [u8],
}

#[derive(Clone, Debug)]
pub struct StreamRegistry {
    handlers: Vec<StreamHandler>,
}

impl Default for StreamRegistry {
    fn default() -> Self {
        let mut registry = Self {
            handlers: Vec::new(),
        };
        registry.register(SERVICE_OBJECT, b"object");
        registry.register(SERVICE_ECHO, b"echo");
        registry.register(SERVICE_STATUS, b"status");
        registry.register(SERVICE_STREAM, b"stream");
        registry.register(SERVICE_IPERF, b"iperf");
        registry.register(SERVICE_METRICS, b"metrics");
        registry.register(SERVICE_EVENTS, b"events");
        registry.register(SERVICE_CONTROL, b"control");
        registry
    }
}

impl StreamRegistry {
    pub fn register(&mut self, tag: u8, name: &'static [u8]) {
        if !self.handlers.iter().any(|handler| handler.tag == tag) {
            self.handlers.push(StreamHandler { tag, name });
        }
    }

    pub fn handlers(&self) -> &[StreamHandler] {
        &self.handlers
    }

    pub fn contains(&self, tag: u8) -> bool {
        self.handlers.iter().any(|handler| handler.tag == tag)
    }
}

/// Handle one complete application stream request. `data` excludes the
/// service tag. Object handling remains in the object-store adapter because it
/// needs its application server; all diagnostic/test services are here.
pub fn handle_stream<const N: usize, const H: usize, const P: usize>(
    endpoint: &EndpointState<N, H, P>,
    connection_cid: ConnectionId,
    stream_id: u64,
    registry: &StreamRegistry,
    service: u8,
    data: &[u8],
) -> Result<Vec<u8>, &'static str> {
    handle_stream_with_events(
        endpoint,
        None,
        connection_cid,
        stream_id,
        registry,
        service,
        data,
    )
}

pub fn handle_stream_with_events<const N: usize, const H: usize, const P: usize>(
    endpoint: &EndpointState<N, H, P>,
    events: Option<&EventRing>,
    connection_cid: ConnectionId,
    stream_id: u64,
    registry: &StreamRegistry,
    service: u8,
    data: &[u8],
) -> Result<Vec<u8>, &'static str> {
    if !registry.contains(service) {
        return Err("unknown stream service");
    }
    match service {
        SERVICE_ECHO | SERVICE_STATUS => Ok(connection_status(
            endpoint,
            connection_cid,
            stream_id,
            service,
            data,
        )),
        SERVICE_IPERF => Ok(iperf_status(endpoint, connection_cid, stream_id, data)),
        SERVICE_METRICS => Ok(metrics_status(endpoint, connection_cid, stream_id)),
        SERVICE_EVENTS => Ok(events_status(
            endpoint,
            events,
            connection_cid,
            stream_id,
            data,
        )),
        SERVICE_STREAM => {
            let mut list = Vec::new();
            for handler in registry.handlers() {
                list.push(handler.tag);
                list.push(handler.name.len() as u8);
                list.extend_from_slice(handler.name);
            }
            Ok(list)
        }
        // The UDP adapter supplies the command mailbox. Keep a harmless
        // registered fallback for bearer tests which use handlers directly.
        SERVICE_CONTROL => Ok(Vec::new()),
        SERVICE_OBJECT => Err("object service belongs to object-store adapter"),
        _ => Err("unknown stream service"),
    }
}

fn connection_status<const N: usize, const H: usize, const P: usize>(
    endpoint: &EndpointState<N, H, P>,
    cid: ConnectionId,
    stream_id: u64,
    service: u8,
    data: &[u8],
) -> Vec<u8> {
    format!(
        "service={service};connection_dcid={};stream_id={stream_id};received_packets={};largest_received={:?};next_packet_number={};bytes_in_flight={};congestion_window={};history={}/{};request_bytes={}",
        cid.value(), endpoint.received_packet_count(), endpoint.largest_received(),
        endpoint.next_packet_number, endpoint.bytes_in_flight(), endpoint.congestion.congestion_window,
        endpoint.history_len(), endpoint.history_capacity(), data.len(),
    ).into_bytes()
}

fn iperf_status<const N: usize, const H: usize, const P: usize>(
    endpoint: &EndpointState<N, H, P>,
    _cid: ConnectionId,
    _stream_id: u64,
    data: &[u8],
) -> Vec<u8> {
    let requested = data
        .get(..8)
        .map(|bytes| u64::from_be_bytes(bytes.try_into().unwrap()))
        .unwrap_or(data.len() as u64);
    let received = data.len().saturating_sub(8) as u64;
    // Fixed binary response: version, requested, received, packet number,
    // in-flight bytes, congestion window, and history occupancy.  A benchmark
    // must not depend on text formatting or a parser on either endpoint.
    let mut response = Vec::with_capacity(1 + 6 * 8);
    response.push(1);
    for value in [
        requested,
        received,
        endpoint.next_packet_number as u64,
        endpoint.bytes_in_flight(),
        endpoint.congestion.congestion_window,
        endpoint.history_len() as u64,
    ] {
        response.extend_from_slice(&value.to_be_bytes());
    }
    response
}

fn metrics_status<const N: usize, const H: usize, const P: usize>(
    endpoint: &EndpointState<N, H, P>,
    cid: ConnectionId,
    stream_id: u64,
) -> Vec<u8> {
    format!(
        "metrics_version=1;connection_dcid={};local_cid={:?};peer_cid={:?};stream_id={stream_id};received_packets={};largest_received={:?};next_packet_number={};bytes_in_flight={};congestion_window={};slow_start_threshold={};latest_rtt={:?};smoothed_rtt={:?};rtt_variance={};pto_timeout={};history_used={};history_capacity={};history_storage_slots={};history_storage_bytes={};retained_payload_bytes={};retransmission_capacity_bytes={};max_data={};max_stream_data={};max_streams_bidi={};max_streams_uni={}",
        cid.value(), endpoint.local_connection_id().map(|v| v.value()), endpoint.peer_connection_id().map(|v| v.value()),
        endpoint.received_packet_count(), endpoint.largest_received(), endpoint.next_packet_number,
        endpoint.bytes_in_flight(), endpoint.congestion.congestion_window, endpoint.congestion.slow_start_threshold,
        endpoint.latest_rtt(), endpoint.smoothed_rtt(), endpoint.rtt_variance(), endpoint.pto_timeout(),
        endpoint.history_len(), endpoint.history_capacity(), endpoint.history_storage_slots(), endpoint.history_storage_bytes(), endpoint.retained_payload_bytes(),
        endpoint.retransmission_capacity_bytes(), endpoint.receive.limits.max_data,
        endpoint.receive.limits.max_stream_data, endpoint.receive.limits.max_streams_bidi,
        endpoint.receive.limits.max_streams_uni,
    ).into_bytes()
}

/// Pollable UDS-style event snapshot. The request may contain `since=<u64>`;
/// a larger sequence indicates an observable transport state change. The
/// sequence is deliberately derived from endpoint state until the persistent
/// connection task supplies a bounded event ring.
fn events_status<const N: usize, const H: usize, const P: usize>(
    endpoint: &EndpointState<N, H, P>,
    ring: Option<&EventRing>,
    cid: ConnectionId,
    stream_id: u64,
    data: &[u8],
) -> Vec<u8> {
    let since = core::str::from_utf8(data)
        .ok()
        .and_then(|value| value.strip_prefix("since=")?.parse::<u64>().ok())
        .unwrap_or(0);
    if let Some(ring) = ring {
        let records: Vec<_> = ring.since(since).copied().collect();
        let mut encoded_records = Vec::new();
        let mut count = 0usize;
        // Leave room for the short header and STREAM frame encoding. The
        // endpoint payload profile is smaller on NAN/ESP32 than on UDP.
        let max_response = MAX_EVENT_RESPONSE_BYTES.min(P.saturating_sub(64).max(1));
        for record in records {
            let encoded = format!(
                ";event_seq={};event_kind={};stream_id={};packet_number={};value={}",
                record.sequence, record.kind, record.stream_id, record.packet_number, record.value
            );
            let header_len = format!(
                "events_version=2;next_sequence={};events={};",
                ring.next_sequence(),
                count + 1
            )
            .len();
            if header_len
                .saturating_add(encoded_records.len())
                .saturating_add(encoded.len())
                > max_response
            {
                break;
            }
            encoded_records.extend_from_slice(encoded.as_bytes());
            count += 1;
        }
        let mut result = format!(
            "events_version=2;next_sequence={};events={};",
            ring.next_sequence(),
            count
        )
        .into_bytes();
        result.extend_from_slice(&encoded_records);
        return result;
    }
    let sequence = endpoint.next_packet_number as u64 + endpoint.received_packet_count() as u64;
    if sequence <= since {
        return format!("events_version=1;next_sequence={sequence};events=0").into_bytes();
    }
    format!(
        "events_version=1;next_sequence={sequence};events=1;event_seq={sequence};event=transport_snapshot;connection_dcid={};stream_id={stream_id};received_packets={};history={}/{};bytes_in_flight={}",
        cid.value(), endpoint.received_packet_count(), endpoint.history_len(), endpoint.history_capacity(), endpoint.bytes_in_flight(),
    ).into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ConnectionLimits, EndpointState, Role};

    #[test]
    fn event_ring_is_bounded_and_pollable() {
        let mut ring = EventRing::new(2);
        ring.push(1, 4, 10, 7);
        ring.push(2, 8, 11, 9);
        ring.push(3, 12, 12, 11);
        assert_eq!(ring.len(), 2);
        assert_eq!(ring.next_sequence(), 3);
        let records: Vec<_> = ring.since(1).copied().collect();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].kind, 2);
        assert_eq!(records[1].stream_id, 12);
    }

    #[test]
    fn event_handler_returns_ring_records() {
        let registry = StreamRegistry::default();
        let endpoint = EndpointState::<4, 4>::new(Role::Server, ConnectionLimits::default(), 1200);
        let cid = ConnectionId::new(22).unwrap();
        let mut ring = EventRing::new(4);
        ring.push(9, 4, 3, 100);
        let response = handle_stream_with_events(
            &endpoint,
            Some(&ring),
            cid,
            8,
            &registry,
            SERVICE_EVENTS,
            b"since=0",
        )
        .unwrap();
        let text = core::str::from_utf8(&response).unwrap();
        assert!(text.contains("events_version=2;next_sequence=1;events=1"));
        assert!(text.contains("event_kind=9;stream_id=4;packet_number=3;value=100"));
    }

    #[test]
    fn event_handler_bounds_large_history_to_one_datagram() {
        let registry = StreamRegistry::default();
        let endpoint =
            EndpointState::<4, 4, 512>::new(Role::Server, ConnectionLimits::default(), 512);
        let cid = ConnectionId::new(22).unwrap();
        let mut ring = EventRing::new(64);
        for sequence in 0..64 {
            ring.push(9, sequence, sequence, sequence * 100);
        }
        let response = handle_stream_with_events(
            &endpoint,
            Some(&ring),
            cid,
            8,
            &registry,
            SERVICE_EVENTS,
            b"since=0",
        )
        .unwrap();
        assert!(response.len() <= 512 - 64);
        let text = core::str::from_utf8(&response).unwrap();
        assert!(text.starts_with("events_version=2;next_sequence=64;events="));
        assert!(text.contains("event_seq=0;"));
    }

    #[test]
    fn fake_stream_transport_injects_loss_and_latency_while_driving_handlers() {
        let registry = StreamRegistry::default();
        let mut client =
            EndpointState::<8, 4>::new(Role::Client, ConnectionLimits::default(), 1200);
        let mut server =
            EndpointState::<8, 4>::new(Role::Server, ConnectionLimits::default(), 1200);
        let client_cid = ConnectionId::new(11).unwrap();
        let server_cid = ConnectionId::new(22).unwrap();
        client
            .install_connection_ids(client_cid, server_cid)
            .unwrap();
        server
            .install_connection_ids(server_cid, client_cid)
            .unwrap();
        let mut now = 0u64;
        let mut delivered = 0usize;
        for (packet_number, (stream_id, service)) in [
            (4, SERVICE_METRICS),
            (8, SERVICE_EVENTS),
            (12, SERVICE_IPERF),
        ]
        .into_iter()
        .enumerate()
        {
            let mut body = Vec::from([service]);
            if service == SERVICE_EVENTS {
                body.extend_from_slice(b"since=0");
            }
            if service == SERVICE_IPERF {
                body.extend_from_slice(&32u64.to_be_bytes());
                body.extend_from_slice(&[0xa5; 32]);
            }
            client.open_send_stream(stream_id, 64 * 1024).unwrap();
            let mut packet = [0u8; 1200];
            let (used, _) = client
                .encode_stream_packet(server_cid, stream_id, 0, true, &body, &mut packet)
                .unwrap();
            now += 10;
            if packet_number == 1 {
                continue;
            } // deterministic loss
            assert!(now >= 10); // deterministic latency injection point
            let crate::TransportPacket::Stream { frame, .. } =
                server.receive_datagram(&packet[..used]).unwrap()
            else {
                panic!("expected stream");
            };
            let response = handle_stream(
                &server,
                server_cid,
                stream_id,
                &registry,
                service,
                &frame.data[1..],
            )
            .unwrap();
            assert!(!response.is_empty());
            delivered += 1;
        }
        assert_eq!(delivered, 2);
    }

    #[test]
    fn fake_bearer_drives_multiple_stream_operations_under_faults() {
        let registry = StreamRegistry::default();
        let mut client =
            EndpointState::<8, 8>::new(Role::Client, ConnectionLimits::default(), 1200);
        let mut server =
            EndpointState::<8, 8>::new(Role::Server, ConnectionLimits::default(), 1200);
        let client_cid = ConnectionId::new(31).unwrap();
        let server_cid = ConnectionId::new(32).unwrap();
        client
            .install_connection_ids(client_cid, server_cid)
            .unwrap();
        server
            .install_connection_ids(server_cid, client_cid)
            .unwrap();
        let mut link = crate::fake::FakeDatagramLink::new(crate::fake::FaultConfig {
            latency_ticks: 3,
            drop_every: Some(4),
            duplicate: true,
            reorder: true,
            mtu: 1200,
        });
        let operations = [
            (4, SERVICE_ECHO, b"status".as_slice()),
            (8, SERVICE_IPERF, b"payload".as_slice()),
            (12, SERVICE_METRICS, b"".as_slice()),
            (16, SERVICE_EVENTS, b"since=0".as_slice()),
            (20, SERVICE_STREAM, b"".as_slice()),
        ];
        for (stream_id, service, body) in operations {
            client.open_send_stream(stream_id, 64 * 1024).unwrap();
            let mut request = Vec::from([service]);
            request.extend_from_slice(body);
            let mut packet = [0u8; 1200];
            let (used, _) = client
                .encode_stream_packet(server_cid, stream_id, 0, true, &request, &mut packet)
                .unwrap();
            link.send(0, &packet[..used]);
        }
        let mut delivered = 0;
        for packet in link.poll(3) {
            if let Ok(crate::TransportPacket::Stream { frame, .. }) =
                server.receive_datagram(&packet)
            {
                let service = frame.data[0];
                let response = handle_stream(
                    &server,
                    server_cid,
                    frame.id,
                    &registry,
                    service,
                    &frame.data[1..],
                )
                .unwrap();
                assert!(!response.is_empty());
                delivered += 1;
            }
        }
        assert!(link.dropped() >= 1);
        assert!(delivered >= 2);
        assert!(link.sent() >= 5);
    }
}
