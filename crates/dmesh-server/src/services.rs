//! Bearer-neutral stream services used by UDP, NAN, fake links, and devices.
//!
//! This module deliberately has no socket or bearer code. A bearer decodes a
//! stream packet and passes the complete request to the shared tagged
//! dispatcher. Bearers do not select application handlers.

use alloc::format;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};
use quic_lite::{ConnectionId, EndpointState};

const MAX_EVENT_RESPONSE_BYTES: usize = 1200;
/// A retained binary event must fit in one bounded direct-record response.
/// This is also a memory boundary: a count-limited history without a payload
/// limit would still allow one producer to retain an arbitrary allocation.
pub const MAX_BINARY_EVENT_PAYLOAD_BYTES: usize = 1024;
pub const LOG_WATCH_MAX_RECORDS: usize = 64;

/// Common read-only connection diagnostics. These are application handlers,
/// not QUIC service numbers; every request uses the normal tagged envelope.
pub const DIAGNOSTIC_COMPONENT: u64 = 9;
pub const DIAGNOSTIC_STATUS_METHOD: u64 = 1;
pub const DIAGNOSTIC_SERVICES_METHOD: u64 = 2;
pub const DIAGNOSTIC_METRICS_METHOD: u64 = 3;
pub const DIAGNOSTIC_EVENTS_METHOD: u64 = 4;
pub const DIAGNOSTIC_LOG_WATCH_METHOD: u64 = 5;

const BUILTIN_TAGGED_SERVICES: &[(u64, u64, &[u8])] = &[
    (DIAGNOSTIC_COMPONENT, DIAGNOSTIC_STATUS_METHOD, b"status"),
    (
        DIAGNOSTIC_COMPONENT,
        DIAGNOSTIC_SERVICES_METHOD,
        b"services",
    ),
    (DIAGNOSTIC_COMPONENT, DIAGNOSTIC_METRICS_METHOD, b"metrics"),
    (DIAGNOSTIC_COMPONENT, DIAGNOSTIC_EVENTS_METHOD, b"events"),
    (
        DIAGNOSTIC_COMPONENT,
        DIAGNOSTIC_LOG_WATCH_METHOD,
        b"log-watch",
    ),
    (
        crate::probe::PROBE_COMPONENT,
        crate::probe::PROBE_RUN,
        b"probe",
    ),
    (
        crate::protocol::OBJECT_COMPONENT,
        crate::protocol::OBJECT_GET_METHOD,
        b"object.get",
    ),
    (
        crate::protocol::OBJECT_COMPONENT,
        crate::protocol::OBJECT_FLASH_METHOD,
        b"object.flash",
    ),
];

/// Encode the built-in tagged QUIC handler catalog as
/// `[[component, method, "service"], ...]`.
///
/// Compatibility stream selectors are intentionally excluded: they are
/// framing for object transfer and connection migration, not application
/// handler identities.
pub fn encode_tagged_service_catalog() -> Vec<u8> {
    let mut output = alloc::vec![0; 192];
    let mut encoder = crate::cbor::Encoder::new(&mut output);
    encoder
        .array(BUILTIN_TAGGED_SERVICES.len() as u64)
        .expect("fixed service catalog capacity");
    for (component, method, name) in BUILTIN_TAGGED_SERVICES {
        encoder.array(3).expect("fixed service catalog capacity");
        encoder
            .uint(*component)
            .expect("fixed service catalog capacity");
        encoder
            .uint(*method)
            .expect("fixed service catalog capacity");
        encoder
            .text_value(name)
            .expect("fixed service catalog capacity");
    }
    let used = encoder.len();
    output.truncate(used);
    output
}

/// Platform extension for tagged-CBOR requests carried directly in an
/// application stream. Component IDs remain `u64` inside the envelope, so
/// board modules can use the 1000+ range without colliding with legacy
/// one-byte stream-service selectors. Handlers are registered per component
/// by an application (Main, Recovery, or a host server); the bearer runtime
/// remains unaware of them.
pub type TaggedComponentHandler = fn(crate::tagged::Record<'_>) -> Option<Vec<u8>>;

const TAGGED_COMPONENT_CAPACITY: usize = 16;
// Each slot is published handler-first, component-second. A reader that sees
// the component with Acquire ordering therefore sees the matching function.
// Components use small numeric IDs today (1000+) and fit `usize` on every
// ESP target; the decoded `u64` is checked before the cast.
static TAGGED_COMPONENT_IDS: [AtomicUsize; TAGGED_COMPONENT_CAPACITY] =
    [const { AtomicUsize::new(0) }; TAGGED_COMPONENT_CAPACITY];
static TAGGED_COMPONENT_HANDLERS: [AtomicUsize; TAGGED_COMPONENT_CAPACITY] =
    [const { AtomicUsize::new(0) }; TAGGED_COMPONENT_CAPACITY];

/// Register one tagged-CBOR component. It is called at application startup,
/// before transports accept traffic; duplicate component IDs are rejected.
/// The fixed table bounds the handler surface without heap allocations.
pub fn register_tagged_component(component: u64, handler: TaggedComponentHandler) -> bool {
    let Ok(component) = usize::try_from(component) else {
        return false;
    };
    if component == 0 {
        return false;
    }
    for index in 0..TAGGED_COMPONENT_CAPACITY {
        let existing = TAGGED_COMPONENT_IDS[index].load(Ordering::Acquire);
        if existing == component {
            return false;
        }
        if existing == 0
            && TAGGED_COMPONENT_IDS[index]
                .compare_exchange(0, usize::MAX, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
        {
            TAGGED_COMPONENT_HANDLERS[index].store(handler as usize, Ordering::Release);
            TAGGED_COMPONENT_IDS[index].store(component, Ordering::Release);
            return true;
        }
    }
    false
}

/// Dispatch a complete tagged-CBOR stream request.
///
/// A stream is an HTTP-like request channel, not a handler identity: each
/// stream may carry any component and multiple streams may concurrently call
/// the same component.
pub fn dispatch_tagged_stream(data: &[u8]) -> Option<Vec<u8>> {
    dispatch_tagged_record(crate::tagged::decode(data)?)
}

/// Dispatch an already-decoded tagged record from a canonical stream handler.
/// This registry is deliberately not a direct-message allowlist: connectionless
/// ingress must apply its explicit policy before invoking any operation.
pub fn dispatch_tagged_record(record: crate::tagged::Record<'_>) -> Option<Vec<u8>> {
    let crate::tagged::Name::Tag(component) = record.component? else {
        return None;
    };
    let component = usize::try_from(component).ok()?;
    for index in 0..TAGGED_COMPONENT_CAPACITY {
        if TAGGED_COMPONENT_IDS[index].load(Ordering::Acquire) == component {
            let handler = TAGGED_COMPONENT_HANDLERS[index].load(Ordering::Acquire);
            let handler: TaggedComponentHandler =
                (handler != 0).then(|| unsafe { core::mem::transmute(handler) })?;
            return handler(record);
        }
    }
    None
}

/// Dispatch connection-aware diagnostic tagged requests.
///
/// Unlike static application components, these results need the live QUIC
/// endpoint state and event ring. The connection owner supplies that context after a
/// complete stream request has been admitted; bearer adapters never do.
pub fn dispatch_diagnostic_tagged_stream<const N: usize, const H: usize, const P: usize>(
    endpoint: &EndpointState<N, H, P>,
    events: Option<&EventRing>,
    connection_cid: ConnectionId,
    stream_id: u64,
    data: &[u8],
) -> Option<Vec<u8>> {
    let record = crate::tagged::decode(data)?;
    if record.component != Some(crate::tagged::Name::Tag(DIAGNOSTIC_COMPONENT))
        || record.to.is_some()
        || record.params.is_some()
        || record.data.is_some()
        || record.result.is_some()
        || record.error.is_some()
    {
        return None;
    }
    let crate::tagged::Name::Tag(method) = record.method? else {
        return None;
    };
    let id = record.id?;
    let fields = diagnostic_fields(record.fields)?;
    if method == DIAGNOSTIC_SERVICES_METHOD {
        if fields != (None, None) {
            return None;
        }
        let result = encode_tagged_service_catalog();
        let mut response = alloc::vec![0; result.len().checked_add(64)?];
        let used = crate::tagged::encode_numeric_response(
            DIAGNOSTIC_COMPONENT,
            method,
            id,
            &result,
            &mut response,
        )?;
        response.truncate(used);
        return Some(response);
    }
    let result = match method {
        DIAGNOSTIC_STATUS_METHOD => {
            if fields != (None, None) {
                return None;
            }
            tagged_connection_status(endpoint, connection_cid, stream_id)
        }
        DIAGNOSTIC_METRICS_METHOD => {
            if fields != (None, None) {
                return None;
            }
            metrics_status(endpoint, connection_cid, stream_id)
        }
        DIAGNOSTIC_EVENTS_METHOD => {
            if fields.1.is_some() {
                return None;
            }
            events_status(
                endpoint,
                events,
                connection_cid,
                stream_id,
                format!("since={}", fields.0.unwrap_or(0)).as_bytes(),
            )
        }
        DIAGNOSTIC_LOG_WATCH_METHOD => {
            let since = fields.0.unwrap_or(0);
            let records = fields.1.unwrap_or(1);
            if records == 0 || records > LOG_WATCH_MAX_RECORDS as u64 {
                return None;
            }
            format!(
                "log_watch_version=1;next_sequence={};since={since};requested={records};logs=0",
                events.map_or(0, EventRing::next_sequence)
            )
            .into_bytes()
        }
        _ => return None,
    };
    let mut response = alloc::vec![0; result.len().checked_add(64)?];
    let used = crate::tagged::encode_numeric_data_response(
        DIAGNOSTIC_COMPONENT,
        method,
        id,
        &result,
        true,
        &mut response,
    )?;
    response.truncate(used);
    Some(response)
}

/// Decode `{1: since?, 2: records?}` without allowing unknown or duplicate
/// fields. An omitted fields map is the same as an empty map.
fn diagnostic_fields(fields: Option<&[u8]>) -> Option<(Option<u64>, Option<u64>)> {
    let Some(fields) = fields else {
        return Some((None, None));
    };
    let mut decoder = crate::cbor::Decoder::new(fields);
    let (major, count) = decoder.head()?;
    if major != 5 || count == u64::MAX {
        return None;
    }
    let mut since = None;
    let mut records = None;
    for _ in 0..count {
        match decoder.uint()? {
            1 if since.is_none() => since = Some(decoder.uint()?),
            2 if records.is_none() => records = Some(decoder.uint()?),
            _ => return None,
        }
    }
    decoder.is_finished().then_some((since, records))
}

fn tagged_connection_status<const N: usize, const H: usize, const P: usize>(
    endpoint: &EndpointState<N, H, P>,
    cid: ConnectionId,
    stream_id: u64,
) -> Vec<u8> {
    format!(
        "status_version=1;connection_dcid={};stream_id={stream_id};received_packets={};largest_received={:?};next_packet_number={};bytes_in_flight={};congestion_window={};history={}/{}",
        cid.value(), endpoint.received_packet_count(), endpoint.largest_received(),
        endpoint.next_packet_number, endpoint.bytes_in_flight(), endpoint.congestion.congestion_window,
        endpoint.history_len(), endpoint.history_capacity(),
    )
    .into_bytes()
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

/// Decode the text form of the bounded direct status record. This is useful
/// on connectionless bearers during discovery: the record is intentionally
/// not a QUIC-lite datagram and must be recognized before a bearer attempts
/// transport dispatch.
pub fn decode_status_text(record: &[u8]) -> Option<&[u8]> {
    let mut decoder = crate::cbor::Decoder::new(record);
    (decoder.head()? == (5, 3)).then_some(())?;
    (decoder.uint()? == 0).then_some(())?;
    (decoder.uint()? == 68).then_some(())?;
    (decoder.uint()? == 4).then_some(())?;
    (decoder.text_ref()? == b"ok").then_some(())?;
    (decoder.uint()? == 6).then_some(())?;
    (decoder.head()? == (5, 1)).then_some(())?;
    (decoder.uint()? == 32).then_some(())?;
    let message = decoder.text_ref()?;
    decoder.is_finished().then_some(message)
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

fn metrics_status<const N: usize, const H: usize, const P: usize>(
    endpoint: &EndpointState<N, H, P>,
    cid: ConnectionId,
    stream_id: u64,
) -> Vec<u8> {
    let stats = endpoint.stats();
    format!(
        "metrics_version=1;connection_dcid={};local_cid={:?};peer_cid={:?};stream_id={stream_id};received_packets={};largest_received={:?};next_packet_number={};bytes_in_flight={};congestion_window={};slow_start_threshold={};latest_rtt={:?};smoothed_rtt={:?};rtt_variance={};pto_timeout={};history_used={};history_capacity={};history_storage_slots={};history_storage_bytes={};retained_payload_bytes={};retransmission_capacity_bytes={};max_data={};max_stream_data={};max_streams_bidi={};max_streams_uni={};received_datagrams={};stream_datagrams={};control_datagrams={};duplicate_datagrams={};out_of_order_datagrams={};inferred_missing_packets={};sent_datagrams={};sent_stream_datagrams={};sent_control_datagrams={};retransmitted_datagrams={};loss_packet_threshold_datagrams={};loss_time_threshold_datagrams={};loss_events={};loss_retransmitted_datagrams={};pto_retransmitted_datagrams={};ack_datagrams={};ack_immediate_datagrams={};ack_threshold_datagrams={};ack_timer_datagrams={}",
        cid.value(), endpoint.local_connection_id().map(|v| v.value()), endpoint.peer_connection_id().map(|v| v.value()),
        endpoint.received_packet_count(), endpoint.largest_received(), endpoint.next_packet_number,
        endpoint.bytes_in_flight(), endpoint.congestion.congestion_window, endpoint.congestion.slow_start_threshold,
        endpoint.latest_rtt(), endpoint.smoothed_rtt(), endpoint.rtt_variance(), endpoint.pto_timeout(),
        endpoint.history_len(), endpoint.history_capacity(), endpoint.history_storage_slots(), endpoint.history_storage_bytes(), endpoint.retained_payload_bytes(),
        endpoint.retransmission_capacity_bytes(), endpoint.receive.limits.max_data,
        endpoint.receive.limits.max_stream_data, endpoint.receive.limits.max_streams_bidi,
        endpoint.receive.limits.max_streams_uni,
        stats.received_datagrams, stats.stream_datagrams, stats.control_datagrams,
        stats.duplicate_datagrams, stats.out_of_order_datagrams, stats.inferred_missing_packets,
        stats.sent_datagrams, stats.sent_stream_datagrams, stats.sent_control_datagrams,
        stats.retransmitted_datagrams, stats.loss_packet_threshold_datagrams,
        stats.loss_time_threshold_datagrams, stats.loss_events,
        stats.loss_retransmitted_datagrams, stats.pto_retransmitted_datagrams,
        stats.ack_datagrams, stats.ack_immediate_datagrams, stats.ack_threshold_datagrams,
        stats.ack_timer_datagrams,
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

    fn tagged_test_handler(record: crate::tagged::Record<'_>) -> Option<Vec<u8>> {
        matches!(record.component, Some(crate::tagged::Name::Tag(1999)))
            .then(|| b"module-response".to_vec())
    }

    fn diagnostic_request(method: u64, id: u64, since: Option<u64>) -> Vec<u8> {
        let mut request = vec![0; 64];
        let used = if let Some(since) = since {
            let mut encoder = crate::cbor::Encoder::new(&mut request);
            encoder.map(4).unwrap();
            encoder.uint(1).unwrap();
            encoder.uint(DIAGNOSTIC_COMPONENT).unwrap();
            encoder.uint(2).unwrap();
            encoder.uint(method).unwrap();
            encoder.uint(3).unwrap();
            encoder.uint(id).unwrap();
            encoder.uint(5).unwrap();
            encoder.map(1).unwrap();
            encoder.uint(1).unwrap();
            encoder.uint(since).unwrap();
            encoder.len()
        } else {
            crate::tagged::encode_numeric_empty_request(
                DIAGNOSTIC_COMPONENT,
                method,
                id,
                &mut request,
            )
            .unwrap()
        };
        request.truncate(used);
        request
    }

    fn tagged_result_text(response: &[u8]) -> &str {
        let record = crate::tagged::decode(response).unwrap();
        let mut result = crate::cbor::Decoder::new(record.result.unwrap());
        let text = core::str::from_utf8(result.text_ref().unwrap()).unwrap();
        assert!(result.is_finished());
        text
    }

    #[test]
    fn tagged_stream_dispatch_uses_component_not_stream_or_service_id() {
        // {1: 1999, 2: 1}; there is intentionally no leading service byte.
        let request = [0xa2, 1, 0x19, 0x07, 0xcf, 2, 1];
        assert!(register_tagged_component(1999, tagged_test_handler));
        assert_eq!(
            dispatch_tagged_stream(&request),
            Some(b"module-response".to_vec())
        );
        assert!(!register_tagged_component(1999, tagged_test_handler));
    }

    #[test]
    fn connection_diagnostics_are_correlated_tagged_handlers() {
        let local = ConnectionId::new(41).unwrap();
        let peer = ConnectionId::new(42).unwrap();
        let mut endpoint =
            EndpointState::<8, 4>::new(Role::Server, ConnectionLimits::default(), 1200);
        endpoint.install_connection_ids(local, peer).unwrap();
        let mut request = [0u8; 32];
        let used = crate::tagged::encode_numeric_empty_request(
            DIAGNOSTIC_COMPONENT,
            DIAGNOSTIC_STATUS_METHOD,
            77,
            &mut request,
        )
        .unwrap();
        let response =
            dispatch_diagnostic_tagged_stream(&endpoint, None, local, 4, &request[..used]).unwrap();
        let record = crate::tagged::decode(&response).unwrap();
        assert_eq!(record.id, Some(77));
        let mut result = crate::cbor::Decoder::new(record.result.unwrap());
        let status = result.text_ref().unwrap();
        assert!(result.is_finished());
        assert!(status.starts_with(b"status_version="));

        let mut ring = EventRing::new(4);
        ring.push(7, 8, 9, 10);
        let mut request = [0u8; 64];
        let mut encoder = crate::cbor::Encoder::new(&mut request);
        encoder.map(4).unwrap();
        encoder.uint(1).unwrap();
        encoder.uint(DIAGNOSTIC_COMPONENT).unwrap();
        encoder.uint(2).unwrap();
        encoder.uint(DIAGNOSTIC_EVENTS_METHOD).unwrap();
        encoder.uint(3).unwrap();
        encoder.uint(78).unwrap();
        encoder.uint(5).unwrap();
        encoder.map(1).unwrap();
        encoder.uint(1).unwrap();
        encoder.uint(0).unwrap();
        let used = encoder.len();
        let response =
            dispatch_diagnostic_tagged_stream(&endpoint, Some(&ring), local, 8, &request[..used])
                .unwrap();
        let record = crate::tagged::decode(&response).unwrap();
        assert_eq!(record.id, Some(78));
        let mut result = crate::cbor::Decoder::new(record.result.unwrap());
        let events = result.text_ref().unwrap();
        assert!(result.is_finished());
        assert!(events.starts_with(b"events_version=2;next_sequence=1;events=1;"));
    }

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
            vec![
                0x82, 7, 0x81, 0x85, 3, 0x18, 45, 5, 0, 0x43, b'a', b'b', b'c'
            ]
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
    fn text_status_round_trips_without_a_transport_envelope() {
        let record = encode_status_text(b"recovery boot").unwrap();
        assert_eq!(decode_status_text(&record), Some(&b"recovery boot"[..]));
    }

    #[test]
    fn event_handler_returns_ring_records() {
        let endpoint = EndpointState::<4, 4>::new(Role::Server, ConnectionLimits::default(), 1200);
        let cid = ConnectionId::new(22).unwrap();
        let mut ring = EventRing::new(4);
        ring.push(9, 4, 3, 100);
        let request = diagnostic_request(DIAGNOSTIC_EVENTS_METHOD, 81, Some(0));
        let response =
            dispatch_diagnostic_tagged_stream(&endpoint, Some(&ring), cid, 8, &request).unwrap();
        let text = tagged_result_text(&response);
        assert!(text.contains("events_version=2;next_sequence=1;events=1"));
        assert!(text.contains("event_kind=9;stream_id=4;packet_number=3;value=100"));
    }

    #[test]
    fn event_handler_bounds_large_history_to_one_datagram() {
        let endpoint =
            EndpointState::<4, 4, 512>::new(Role::Server, ConnectionLimits::default(), 512);
        let cid = ConnectionId::new(22).unwrap();
        let mut ring = EventRing::new(64);
        for sequence in 0..64 {
            ring.push(9, sequence, sequence, sequence * 100);
        }
        let request = diagnostic_request(DIAGNOSTIC_EVENTS_METHOD, 82, Some(0));
        let response =
            dispatch_diagnostic_tagged_stream(&endpoint, Some(&ring), cid, 8, &request).unwrap();
        let text = tagged_result_text(&response);
        assert!(text.len() <= 512 - 64);
        assert!(text.starts_with("events_version=2;next_sequence=64;events="));
        assert!(text.contains("event_seq=0;"));
    }

    #[test]
    fn fake_stream_transport_injects_loss_and_latency_while_driving_handlers() {
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
        for (packet_number, (stream_id, method)) in [
            (4, DIAGNOSTIC_METRICS_METHOD),
            (8, DIAGNOSTIC_EVENTS_METHOD),
        ]
        .into_iter()
        .enumerate()
        {
            let body = diagnostic_request(method, stream_id, None);
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
            let response = dispatch_diagnostic_tagged_stream(
                &server,
                None,
                server_cid,
                stream_id,
                &frame.data,
            )
            .unwrap();
            assert!(!tagged_result_text(&response).is_empty());
            delivered += 1;
        }
        assert_eq!(delivered, 1);
    }

    #[test]
    fn fake_bearer_drives_multiple_stream_operations_under_faults() {
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
            (4, DIAGNOSTIC_STATUS_METHOD),
            (12, DIAGNOSTIC_METRICS_METHOD),
            (16, DIAGNOSTIC_EVENTS_METHOD),
            (20, DIAGNOSTIC_SERVICES_METHOD),
        ];
        for (stream_id, method) in operations {
            client.open_send_stream(stream_id, 64 * 1024).unwrap();
            let request = diagnostic_request(method, stream_id, None);
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
                let response = dispatch_diagnostic_tagged_stream(
                    &server,
                    None,
                    server_cid,
                    frame.id,
                    &frame.data,
                )
                .unwrap();
                assert!(!response.is_empty());
                delivered += 1;
            }
        }
        assert!(link.dropped() >= 1);
        assert!(delivered >= 2);
        assert!(link.sent() >= 4);
    }
}
