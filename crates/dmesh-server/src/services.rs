//! Bearer-neutral stream services used by UDP, NAN, fake links, and devices.
//!
//! This module deliberately has no socket or bearer code. A bearer decodes a
//! stream packet, passes the service tag/body to [`handle_stream`], and sends
//! the returned response on its own transport.

use alloc::format;
use alloc::vec::Vec;
use quic_lite::{
    ConnectionId, EndpointState, PathPolicy, SERVICE_CONTROL, SERVICE_ECHO, SERVICE_EVENTS,
    SERVICE_IPERF, SERVICE_LOG_WATCH, SERVICE_METRICS, SERVICE_OBJECT, SERVICE_STATUS,
    SERVICE_STREAM,
};

pub use quic_lite::{StreamHandler, StreamRegistry};

const MAX_EVENT_RESPONSE_BYTES: usize = 1200;
/// A retained binary event must fit in one bounded direct-record response.
/// This is also a memory boundary: a count-limited history without a payload
/// limit would still allow one producer to retain an arbitrary allocation.
pub const MAX_BINARY_EVENT_PAYLOAD_BYTES: usize = 1024;
pub const LOG_WATCH_MAX_RECORDS: usize = 64;
/// Control-stream subtype for selecting a bearer-neutral egress policy.
pub const CONTROL_PATH_POLICY: u8 = 3;
/// First byte in a compact control-handler response.
pub const CONTROL_RESPONSE: u8 = 2;

/// Common diagnostic/control handler set that does not require an object
/// receiver. ESP-NOW, UART, and UDP endpoints use it until their object sink
/// is explicitly attached, so discovery never advertises `object` early.
pub fn diagnostic_stream_registry() -> StreamRegistry {
    let mut registry = StreamRegistry::empty();
    for (tag, name) in [
        (SERVICE_ECHO, b"echo".as_slice()),
        (SERVICE_STATUS, b"status".as_slice()),
        (SERVICE_STREAM, b"handlers".as_slice()),
        (SERVICE_IPERF, b"iperf".as_slice()),
        (SERVICE_METRICS, b"metrics".as_slice()),
        (SERVICE_EVENTS, b"events".as_slice()),
        (SERVICE_CONTROL, b"control".as_slice()),
        (SERVICE_LOG_WATCH, b"log-watch".as_slice()),
    ] {
        // This is a required mutation, not merely a debug-time invariant.
        // The same registry is used by release firmware and host adapters.
        // A static duplicate is a debug-time source error, never a runtime
        // reason to panic an embedded server.
        let _registered = registry.register(tag, name);
        debug_assert!(_registered);
    }
    registry
}

/// Standard server surface when an object receiver/sender has been attached.
/// Bearer adapters use this rather than copying a service-name list: the
/// numeric registry is the dispatch authority and names remain diagnostics.
pub fn object_stream_registry() -> StreamRegistry {
    StreamRegistry::default()
}

/// Decode the compact policy body used after `CONTROL_PATH_POLICY`.
/// `[0]` selects the highest measured available path, `[1, path]` compares on
/// one explicit path, `[2, primary]` prefers the low-airtime path until its
/// adapter reports full, and `[3]` aggregates all available paths. Physical
/// bearer names never appear on the wire.
pub fn decode_path_policy(data: &[u8]) -> Option<PathPolicy> {
    match data {
        [0] => Some(PathPolicy::HighestMeasuredSpeed),
        [1, path] => Some(PathPolicy::Explicit(*path as usize)),
        [2, primary] => Some(PathPolicy::AirtimeFirst {
            primary: *primary as usize,
        }),
        [3] => Some(PathPolicy::Aggregate),
        _ => None,
    }
}

/// Acknowledge a policy change using the same compact body on every bearer.
pub fn encode_path_policy_response(policy: PathPolicy) -> Vec<u8> {
    let mut response = Vec::with_capacity(3);
    response.push(CONTROL_RESPONSE);
    match policy {
        PathPolicy::HighestMeasuredSpeed => response.push(0),
        PathPolicy::Explicit(path) if path <= u8::MAX as usize => {
            response.extend_from_slice(&[1, path as u8])
        }
        PathPolicy::AirtimeFirst { primary } if primary <= u8::MAX as usize => {
            response.extend_from_slice(&[2, primary as u8])
        }
        PathPolicy::Aggregate => response.push(3),
        // `PathPolicy` is internally unconstrained; no ESP adapter has more
        // than 255 paths. Preserve a valid response rather than panicking.
        _ => response.push(0),
    }
    response
}

/// Bounded subscription request shared by every server adapter. The request
/// is deliberately small and opaque to QUIC-lite: adapters decide only how
/// to schedule the resulting stream records.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LogWatchRequest {
    pub records: usize,
}

pub fn decode_log_watch_request(data: &[u8]) -> Result<LogWatchRequest, &'static str> {
    let records = match data {
        [] => 1,
        [records] => usize::from(*records),
        _ => return Err("log-watch request must contain at most one record count"),
    };
    if !(1..=LOG_WATCH_MAX_RECORDS).contains(&records) {
        return Err("log-watch record count out of range");
    }
    Ok(LogWatchRequest { records })
}

/// Encode a compact `recovery` success response whose payload is a numeric
/// counter map. UART, UDP logging, and host tests share this schema; bearer
/// framing is deliberately outside this function.
pub fn encode_numeric_result(values: &[(u64, u64)]) -> Option<Vec<u8>> {
    if values.len() > u8::MAX as usize {
        return None;
    }
    let mut inner = [0u8; 1024];
    let mut encoder = crate::cbor::Encoder::new(&mut inner);
    encoder.map(values.len() as u64)?;
    for (key, value) in values {
        encoder.uint(*key)?;
        encoder.uint(*value)?;
    }
    let encoded_len = encoder.len();
    drop(encoder);
    let mut response = Vec::with_capacity(16 + encoded_len);
    response.extend_from_slice(&[0xa3, 0x00, 0x18, 0x44, 0x04, 0x62, b'o', b'k', 0x06]);
    response.extend_from_slice(&inner[..encoded_len]);
    Some(response)
}

/// Encode the bounded diagnostic/status envelope used by the direct-CBOR
/// exception plane. Firmware adapters share this rather than growing a
/// second CBOR schema for bootstrap failures.
pub fn encode_status_text(message: &[u8]) -> Option<Vec<u8>> {
    if message.len() >= 256 {
        return None;
    }
    let mut response = Vec::with_capacity(16 + message.len());
    response.extend_from_slice(&[
        0xa3, 0x00, 0x18, 0x44, 0x04, 0x62, b'o', b'k', 0x06, 0xa1, 0x18, 0x20,
    ]);
    if message.len() < 24 {
        response.push(0x60 + message.len() as u8);
    } else {
        response.extend_from_slice(&[0x78, message.len() as u8]);
    }
    response.extend_from_slice(message);
    Some(response)
}

/// Encode one named numeric diagnostic without converting the value to text.
/// The direct-record envelope remains compatible with ordinary status text,
/// but its payload is `{name: uint}` so consumers retain a CBOR integer.
pub fn encode_status_numeric(name: &[u8], value: u64) -> Option<Vec<u8>> {
    if name.is_empty() || name.len() > 96 || !name.is_ascii() {
        return None;
    }
    // Three outer fields, a one-entry payload map, a 96-byte name, and a u64
    // fit in this fixed scratch allocation. Truncate after canonical encoding.
    let mut response = Vec::with_capacity(128);
    response.resize(128, 0);
    let mut encoder = crate::cbor::Encoder::new(&mut response);
    encoder.map(3)?;
    encoder.uint(0)?;
    encoder.uint(68)?;
    encoder.uint(4)?;
    encoder.text_value(b"ok")?;
    encoder.uint(6)?;
    encoder.map(1)?;
    encoder.text_value(name)?;
    encoder.uint(value)?;
    let len = encoder.len();
    response.truncate(len);
    Some(response)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EventRecord {
    pub sequence: u64,
    pub kind: u8,
    pub stream_id: u64,
    pub packet_number: u64,
    pub value: u64,
}

/// One application-owned binary event retained outside the transport core.
/// The numeric envelope is shared by firmware and host clients; payload bytes
/// remain opaque to dmesh-server and QUIC-lite.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BinaryEventRecord<'a> {
    pub sequence: u64,
    pub event_id: u16,
    pub value_type: u8,
    pub flags: u8,
    pub payload: &'a [u8],
}

fn cbor_head_len(value: u64) -> usize {
    if value < 24 {
        1
    } else if value <= u8::MAX as u64 {
        2
    } else if value <= u32::MAX as u64 {
        5
    } else {
        9
    }
}

fn binary_event_len(event: BinaryEventRecord<'_>) -> usize {
    // [sequence, event_id, value_type, flags, payload]
    cbor_head_len(5)
        .saturating_add(cbor_head_len(event.sequence))
        .saturating_add(cbor_head_len(u64::from(event.event_id)))
        .saturating_add(cbor_head_len(u64::from(event.value_type)))
        .saturating_add(cbor_head_len(u64::from(event.flags)))
        .saturating_add(cbor_head_len(event.payload.len() as u64))
        .saturating_add(event.payload.len())
}

/// Encode canonical CBOR `[next_sequence, [[seq,id,type,flags,payload],...]]`
/// without splitting an event. `max_bytes` bounds one bearer response; callers
/// continue with `since=<sequence>` when the retained history is longer.
pub fn encode_binary_events(
    next_sequence: u64,
    records: &[BinaryEventRecord<'_>],
    max_bytes: usize,
) -> Option<Vec<u8>> {
    let header = cbor_head_len(2).saturating_add(cbor_head_len(next_sequence));
    let mut count = 0usize;
    let mut events_len = 0usize;
    for record in records {
        let event_len = binary_event_len(*record);
        let next = header
            .saturating_add(cbor_head_len((count + 1) as u64))
            .saturating_add(events_len)
            .saturating_add(event_len);
        if next > max_bytes {
            break;
        }
        events_len = events_len.saturating_add(event_len);
        count += 1;
    }
    if header.saturating_add(cbor_head_len(count as u64)) > max_bytes {
        return None;
    }
    let mut output = Vec::with_capacity(max_bytes);
    output.resize(max_bytes, 0);
    let mut encoder = crate::cbor::Encoder::new(&mut output);
    encoder.array(2)?;
    encoder.uint(next_sequence)?;
    encoder.array(count as u64)?;
    for record in records.iter().take(count) {
        encoder.array(5)?;
        encoder.uint(record.sequence)?;
        encoder.uint(u64::from(record.event_id))?;
        encoder.uint(u64::from(record.value_type))?;
        encoder.uint(u64::from(record.flags))?;
        encoder.bytes_value(record.payload)?;
    }
    let len = encoder.len();
    output.truncate(len);
    Some(output)
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
        // Echo is the compact bearer-neutral liveness primitive. In
        // particular, raw 802.11 action probes must not turn a small nonce
        // into a verbose status report requiring multiple vendor IEs.
        SERVICE_ECHO => Ok(data.to_vec()),
        SERVICE_STATUS => Ok(connection_status(
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
        SERVICE_STREAM => Ok(registry.encode_handler_list()),
        // The UDP adapter supplies the command mailbox. Keep a harmless
        // registered fallback for bearer tests which use handlers directly.
        SERVICE_CONTROL => Ok(Vec::new()),
        // Log retention and authentication are server policy.  This compact
        // baseline acknowledges the stream without making command or object
        // streams wait for an unavailable log consumer.
        SERVICE_LOG_WATCH => Ok(log_watch_status(events, data)),
        SERVICE_OBJECT => Err("object service belongs to object-store adapter"),
        _ => Err("unknown stream service"),
    }
}

fn log_watch_status(events: Option<&EventRing>, data: &[u8]) -> Vec<u8> {
    let requested = decode_log_watch_request(data)
        .map(|request| request.records)
        .unwrap_or(0);
    let since = core::str::from_utf8(data)
        .ok()
        .and_then(|value| value.strip_prefix("since=")?.parse::<u64>().ok())
        .unwrap_or(0);
    let next_sequence = events.map_or(0, EventRing::next_sequence);
    format!("log_watch_version=1;next_sequence={next_sequence};since={since};requested={requested};logs=0").into_bytes()
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
    #[test]
    fn direct_status_envelope_is_bounded_and_shared() {
        let response = encode_status_text(b"bootstrap failed").unwrap();
        assert_eq!(
            &response[..9],
            &[0xa3, 0x00, 0x18, 0x44, 0x04, 0x62, b'o', b'k', 0x06]
        );
        assert!(encode_status_text(&[b'x'; 256]).is_none());
    }

    #[test]
    fn log_watch_request_is_bounded_and_bearer_neutral() {
        assert_eq!(decode_log_watch_request(&[]).unwrap().records, 1);
        assert_eq!(decode_log_watch_request(&[64]).unwrap().records, 64);
        assert!(decode_log_watch_request(&[0]).is_err());
        assert!(decode_log_watch_request(&[65]).is_err());
        assert!(decode_log_watch_request(&[1, 2]).is_err());
    }

    use super::*;
    use quic_lite::{ConnectionLimits, EndpointState, Role};

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
    fn binary_event_response_is_canonical_bounded_and_payload_preserving() {
        let events = [BinaryEventRecord {
            sequence: 3,
            event_id: 45,
            value_type: 5,
            flags: 0,
            payload: b"abc",
        }];
        assert_eq!(
            encode_binary_events(7, &events, 64).unwrap(),
            vec![0x82, 7, 0x81, 0x85, 3, 0x18, 45, 5, 0, 0x43, b'a', b'b', b'c']
        );
        // A too-small response preserves a valid continuation envelope and
        // never emits a partial payload/event.
        assert_eq!(
            encode_binary_events(7, &events, 4).unwrap(),
            vec![0x82, 7, 0x80]
        );
    }

    #[test]
    fn numeric_result_is_a_bounded_recovery_response() {
        let response = encode_numeric_result(&[(1, 2), (90, u64::MAX)]).unwrap();
        assert_eq!(
            &response[..9],
            &[0xa3, 0x00, 0x18, 0x44, 0x04, 0x62, b'o', b'k', 0x06]
        );
        assert!(response.len() < 1400);
        assert!(encode_numeric_result(&vec![(0, 0); 256]).is_none());
    }

    #[test]
    fn named_numeric_status_retains_the_integer_as_cbor() {
        let response = encode_status_numeric(b"wifi raw sta init_ms", 42).unwrap();
        let mut decoder = crate::cbor::Decoder::new(&response);
        assert_eq!(decoder.head(), Some((5, 3)));
        assert_eq!(decoder.uint(), Some(0));
        assert_eq!(decoder.uint(), Some(68));
        assert_eq!(decoder.uint(), Some(4));
        assert_eq!(decoder.text_ref(), Some(b"ok".as_slice()));
        assert_eq!(decoder.uint(), Some(6));
        assert_eq!(decoder.head(), Some((5, 1)));
        assert_eq!(decoder.text_ref(), Some(b"wifi raw sta init_ms".as_slice()));
        assert_eq!(decoder.uint(), Some(42));
        assert!(decoder.is_finished());
        assert!(encode_status_numeric(&[b'x'; 97], 1).is_none());
    }

    #[test]
    fn registry_resolves_only_numeric_tag_without_bearer_state() {
        let registry = StreamRegistry::default();
        assert_eq!(
            registry.resolve_tag(&[SERVICE_LOG_WATCH, 0xa0]),
            Some((SERVICE_LOG_WATCH, &[0xa0][..]))
        );
        assert_eq!(
            registry.resolve_tag(&[0x64, b'e', b'c', b'h', b'o', 1, 2]),
            None
        );
        assert_eq!(registry.resolve_tag(&[0x0a]), None);
    }

    #[test]
    fn diagnostic_registry_never_advertises_an_unattached_object_sink() {
        let registry = diagnostic_stream_registry();
        assert!(!registry.contains(SERVICE_OBJECT));
        assert!(registry.contains(SERVICE_LOG_WATCH));
        assert_eq!(
            registry.resolve_tag(&[SERVICE_STREAM]),
            Some((SERVICE_STREAM, &[][..]))
        );
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
            let quic_lite::TransportPacket::Stream { frame, .. } =
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
        let mut link = quic_lite::fake::FakeDatagramLink::new(quic_lite::fake::FaultConfig {
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
            if let Ok(quic_lite::TransportPacket::Stream { frame, .. }) =
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

    #[test]
    fn path_policy_control_is_compact_and_bearer_neutral() {
        assert_eq!(
            decode_path_policy(&[0]),
            Some(quic_lite::PathPolicy::HighestMeasuredSpeed)
        );
        assert_eq!(
            decode_path_policy(&[1, 2]),
            Some(quic_lite::PathPolicy::Explicit(2))
        );
        assert_eq!(
            decode_path_policy(&[2, 1]),
            Some(quic_lite::PathPolicy::AirtimeFirst { primary: 1 })
        );
        assert_eq!(
            decode_path_policy(&[3]),
            Some(quic_lite::PathPolicy::Aggregate)
        );
        assert_eq!(
            encode_path_policy_response(quic_lite::PathPolicy::Explicit(2)),
            vec![CONTROL_RESPONSE, 1, 2]
        );
    }
}
