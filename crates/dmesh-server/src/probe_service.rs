//! Bearer-neutral PROBE stream request layout.
//!
//! `probe.start` uses the same tagged-CBOR envelope as every other callable
//! operation.

use crate::{
    cbor::{Decoder, Encoder},
    tagged::{Name, Record},
};

pub use quic_lite::probe::{
    MAX_BYTES as PROBE_MAX_BYTES, MAX_NORMAL_STREAMS as PROBE_MAX_NORMAL_STREAMS,
    ProbePlan as ProbeServicePlan, ProbeRequest as ProbeWorkloadRequest,
};

pub const PROBE_COMPONENT: u64 = 8;
/// `probe.start`: ask a node to run a probe against `peer`. Header only, in both
/// directions; the response header reports the outcome.
pub const PROBE_START: u64 = 1;
/// `probe.handler`: the probed node's handler. The response header announces
/// the exchange and the response body is the probe payload.
pub const PROBE_HANDLER: u64 = 2;
/// Bounded storage for one complete canonical `probe.start` request.
pub const PROBE_REQUEST_MAX: usize = 160;

/// How long a `probe.start` job may run, in milliseconds: the caller's
/// `timeout` envelope field when given, else a default that grows with the
/// transfer (30 s up to 300 s, assuming at least 8 KiB/s).
pub fn probe_timeout_ms(requested: Option<u64>, bytes: u64) -> u64 {
    match requested {
        Some(timeout) => timeout,
        None => (bytes / 8_192).clamp(30, 300) * 1000,
    }
}
const FIELD_BYTES: u64 = 1;
const FIELD_PACKET_SIZE: u64 = 2;
const FIELD_ACK_FREQUENCY: u64 = 6;
const FIELD_ACK_DELAY_MS: u64 = 7;
const FIELD_LOW_PRIORITY_BYTES: u64 = 8;
const FIELD_HIGH_PRIORITY_BYTES: u64 = 9;
const FIELD_PARALLEL_STREAMS: u64 = 10;
const FIELD_INITIAL_CONSUME_DELAY_MS: u64 = 11;
const FIELD_CONSUME_DELAY_MS: u64 = 12;
const FIELD_PEER: u64 = 13;
pub const MAX_PROBE_DESTINATION_URI: usize = 96;

/// Normalized URI destination shared by probe `to` and `peer` selectors.
/// Bare node identifiers are treated as `mesh://` VIPs. The URI is kept
/// opaque after parsing so registered bearer names can be added without
/// changing this service contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProbeDestination {
    uri: [u8; MAX_PROBE_DESTINATION_URI],
    len: u8,
}

impl ProbeDestination {
    pub fn parse(value: &str) -> Option<Self> {
        let (scheme, target) = match value.split_once("://") {
            Some(parts) => parts,
            None => ("mesh", value),
        };
        if scheme.is_empty()
            || !scheme
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            || target.is_empty()
            || target
                .bytes()
                .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
            || target.contains(',')
            || target.contains('#')
            || target.contains('?')
            || target.contains('/')
        {
            return None;
        }
        let uri_len = scheme.len().checked_add(3)?.checked_add(target.len())?;
        if uri_len > MAX_PROBE_DESTINATION_URI || uri_len > u8::MAX as usize {
            return None;
        }
        let mut uri = [0; MAX_PROBE_DESTINATION_URI];
        let mut offset = 0;
        uri[offset..offset + scheme.len()].copy_from_slice(scheme.as_bytes());
        offset += scheme.len();
        uri[offset..offset + 3].copy_from_slice(b"://");
        offset += 3;
        uri[offset..offset + target.len()].copy_from_slice(target.as_bytes());
        Some(Self {
            uri,
            len: uri_len as u8,
        })
    }

    pub fn as_str(&self) -> &str {
        core::str::from_utf8(&self.uri[..usize::from(self.len)])
            .expect("parsed destination URI is valid UTF-8")
    }

    pub fn scheme(&self) -> &str {
        self.as_str().split_once("://").expect("normalized URI").0
    }

    pub fn target(&self) -> &str {
        self.as_str().split_once("://").expect("normalized URI").1
    }

    /// Extract an explicit ESP-NOW unicast address. Discovery-resolved mesh
    /// destinations are handled by the platform resolver instead.
    pub fn espnow_mac(&self) -> Option<[u8; 6]> {
        let mac = (self.scheme() == "espnow")
            .then(|| parse_mac(self.target().as_bytes()))
            .flatten()?;
        (mac != [0; 6] && mac[0] & 1 == 0).then_some(mac)
    }
}

/// Existing `probe` workload plus an optional device-directed peer route.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProbeServiceRequest {
    pub bytes: u64,
    pub packet_size: u16,
    pub ack_frequency: Option<u8>,
    pub ack_delay_ms: Option<u8>,
    pub low_priority_bytes: Option<u32>,
    pub high_priority_bytes: Option<u32>,
    pub parallel_streams: Option<u8>,
    pub initial_consume_delay_ms: Option<u32>,
    pub consume_delay_ms: Option<u32>,
    /// Responder destination URI or discovery-resolved mesh VIP.
    pub peer: Option<ProbeDestination>,
}

impl ProbeServiceRequest {
    pub const fn new(bytes: u64, packet_size: u16) -> Self {
        Self {
            bytes,
            packet_size,
            ack_frequency: None,
            ack_delay_ms: None,
            low_priority_bytes: None,
            high_priority_bytes: None,
            parallel_streams: None,
            initial_consume_delay_ms: None,
            consume_delay_ms: None,
            peer: None,
        }
    }

    pub const fn workload(self) -> ProbeWorkloadRequest {
        ProbeWorkloadRequest {
            bytes: self.bytes,
            packet_size: self.packet_size,
            ack_frequency: self.ack_frequency,
            ack_delay_ms: self.ack_delay_ms,
            low_priority_bytes: self.low_priority_bytes,
            high_priority_bytes: self.high_priority_bytes,
            parallel_streams: self.parallel_streams,
            initial_consume_delay_ms: self.initial_consume_delay_ms,
            consume_delay_ms: self.consume_delay_ms,
        }
    }
}

/// Encode the canonical correlated `probe.start` request.
pub fn encode_probe_start_request(
    request: ProbeServiceRequest,
    id: u64,
    output: &mut [u8],
) -> Option<usize> {
    encode_probe_request(PROBE_START, request, id, output)
}

/// Encode the correlated `probe.handler` request sent to the probed node.
pub fn encode_probe_handler_request(
    request: ProbeServiceRequest,
    id: u64,
    output: &mut [u8],
) -> Option<usize> {
    encode_probe_request(PROBE_HANDLER, request, id, output)
}

fn encode_probe_request(
    method: u64,
    request: ProbeServiceRequest,
    id: u64,
    output: &mut [u8],
) -> Option<usize> {
    let optional = usize::from(request.ack_frequency.is_some())
        + usize::from(request.ack_delay_ms.is_some())
        + usize::from(request.low_priority_bytes.is_some())
        + usize::from(request.high_priority_bytes.is_some())
        + usize::from(request.parallel_streams.is_some())
        + usize::from(request.initial_consume_delay_ms.is_some())
        + usize::from(request.consume_delay_ms.is_some())
        + usize::from(request.peer.is_some());
    let mut e = Encoder::new(output);
    e.map(4)?;
    e.uint(1)?;
    e.uint(PROBE_COMPONENT)?;
    e.uint(2)?;
    e.uint(method)?;
    e.uint(3)?;
    e.uint(id)?;
    e.uint(5)?;
    e.map((2 + optional) as u64)?;
    e.uint(FIELD_BYTES)?;
    e.uint(request.bytes)?;
    e.uint(FIELD_PACKET_SIZE)?;
    e.uint(u64::from(request.packet_size))?;
    for (field, value) in [
        (FIELD_ACK_FREQUENCY, request.ack_frequency.map(u64::from)),
        (FIELD_ACK_DELAY_MS, request.ack_delay_ms.map(u64::from)),
        (
            FIELD_LOW_PRIORITY_BYTES,
            request.low_priority_bytes.map(u64::from),
        ),
        (
            FIELD_HIGH_PRIORITY_BYTES,
            request.high_priority_bytes.map(u64::from),
        ),
        (
            FIELD_PARALLEL_STREAMS,
            request.parallel_streams.map(u64::from),
        ),
        (
            FIELD_INITIAL_CONSUME_DELAY_MS,
            request.initial_consume_delay_ms.map(u64::from),
        ),
        (
            FIELD_CONSUME_DELAY_MS,
            request.consume_delay_ms.map(u64::from),
        ),
    ] {
        if let Some(value) = value {
            e.uint(field)?;
            e.uint(value)?;
        }
    }
    if let Some(peer) = request.peer {
        e.uint(FIELD_PEER)?;
        e.text_value(peer.as_str().as_bytes())?;
    }
    Some(e.len())
}

/// Decode a canonical `probe.start` request already extracted from a QUIC
/// stream. Directed records are routing input and are never executed locally.
pub fn decode_probe_start_record(record: Record<'_>) -> Option<(u64, ProbeServiceRequest)> {
    decode_probe_record(record, PROBE_START)
}

/// Decode a `probe.handler` request.
pub fn decode_probe_handler_record(record: Record<'_>) -> Option<(u64, ProbeServiceRequest)> {
    decode_probe_record(record, PROBE_HANDLER)
}

fn decode_probe_record(record: Record<'_>, method: u64) -> Option<(u64, ProbeServiceRequest)> {
    if record.component != Some(Name::Tag(PROBE_COMPONENT))
        || record.method != Some(Name::Tag(method))
        || record.params.is_some()
    {
        return None;
    }
    if let Some(destination) = record.to {
        match destination {
            Name::Text(value) => ProbeDestination::parse(core::str::from_utf8(value).ok()?)?,
            Name::Tag(_) | Name::Bytes(_) => return None,
        };
    }
    let mut d = Decoder::new(record.fields?);
    let (major, count) = d.head()?;
    if major != 5 || count == u64::MAX || count > 13 {
        return None;
    }
    let mut seen = 0u16;
    let mut request = ProbeServiceRequest::new(0, 0);
    for _ in 0..count {
        let field = d.uint()?;
        if !(1..=13).contains(&field) || matches!(field, 3..=5) {
            return None;
        }
        let bit = 1u16.checked_shl((field - 1) as u32)?;
        if seen & bit != 0 {
            return None;
        }
        seen |= bit;
        match field {
            FIELD_PEER => {
                request.peer = ProbeDestination::parse(core::str::from_utf8(d.text_ref()?).ok()?)
            }
            FIELD_BYTES => request.bytes = d.uint()?,
            FIELD_PACKET_SIZE => request.packet_size = u16::try_from(d.uint()?).ok()?,
            FIELD_ACK_FREQUENCY => request.ack_frequency = Some(u8::try_from(d.uint()?).ok()?),
            FIELD_ACK_DELAY_MS => request.ack_delay_ms = Some(u8::try_from(d.uint()?).ok()?),
            FIELD_LOW_PRIORITY_BYTES => {
                request.low_priority_bytes = Some(u32::try_from(d.uint()?).ok()?)
            }
            FIELD_HIGH_PRIORITY_BYTES => {
                request.high_priority_bytes = Some(u32::try_from(d.uint()?).ok()?)
            }
            FIELD_PARALLEL_STREAMS => {
                request.parallel_streams = Some(u8::try_from(d.uint()?).ok()?)
            }
            FIELD_INITIAL_CONSUME_DELAY_MS => {
                request.initial_consume_delay_ms = Some(u32::try_from(d.uint()?).ok()?)
            }
            FIELD_CONSUME_DELAY_MS => {
                request.consume_delay_ms = Some(u32::try_from(d.uint()?).ok()?)
            }
            _ => return None,
        }
    }
    if seen & 0b11 != 0b11 || !d.is_finished() || request.bytes == 0 || request.packet_size == 0 {
        return None;
    }
    Some((record.id?, request))
}

/// Encode the result of a device-directed `probe` request using the ordinary
/// probe method and correlation id.
pub fn encode_probe_result_response(
    id: u64,
    request: ProbeServiceRequest,
    success: bool,
    received_bytes: u64,
    elapsed_us: u64,
    output: &mut [u8],
) -> Option<usize> {
    let peer = request.peer?;
    let status = if success {
        b"ok".as_slice()
    } else {
        b"error".as_slice()
    };
    let mut value = [0u8; 160];
    let mut e = Encoder::new(&mut value);
    e.map(5)?;
    e.uint(1)?;
    e.text_value(status)?;
    e.uint(2)?;
    e.text_value(peer.as_str().as_bytes())?;
    e.uint(3)?;
    e.uint(request.bytes)?;
    e.uint(4)?;
    e.uint(received_bytes)?;
    e.uint(5)?;
    e.uint(elapsed_us)?;
    let value_len = e.len();
    crate::tagged::encode_numeric_response(
        PROBE_COMPONENT,
        PROBE_START,
        id,
        &value[..value_len],
        output,
    )
}

/// The response header of `probe.handler`: the length of the payload that
/// follows and the packet size it is built from.
pub fn encode_probe_handler_response(
    id: u64,
    bytes: u64,
    packet_size: usize,
    output: &mut [u8],
) -> Option<usize> {
    let mut value = [0u8; 32];
    let mut e = Encoder::new(&mut value);
    e.map(2)?;
    e.uint(1)?;
    e.uint(bytes)?;
    e.uint(2)?;
    e.uint(packet_size as u64)?;
    let value_len = e.len();
    crate::tagged::encode_numeric_response(
        PROBE_COMPONENT,
        PROBE_HANDLER,
        id,
        &value[..value_len],
        output,
    )
}

/// The probed node's end of a probe: answer with a header, then stream the
/// probe payload as the response body. It wraps the transport-neutral
/// `quic_lite::probe` workload; the request header is the only CBOR involved.
pub struct ProbeHandler;

struct ProbeBody(quic_lite::probe::ProbePayload);

impl crate::stream::BodySource for ProbeBody {
    fn read(&mut self, out: &mut [u8]) -> (usize, bool) {
        let count = self.0.fill(out);
        (count, self.0.is_complete())
    }
}

impl ProbeHandler {
    /// The request limits shared by every platform.
    fn accept(request: &ProbeServiceRequest) -> bool {
        request.bytes != 0
            && request.bytes <= PROBE_MAX_BYTES
            && request.peer.is_none()
            && request.parallel_streams.is_none_or(|streams| streams == 1)
            && request.high_priority_bytes.is_none_or(|bytes| bytes == 0)
            && request.low_priority_bytes.is_none_or(|bytes| bytes == 0)
            && request.ack_frequency.is_none()
            && request.ack_delay_ms.is_none()
    }
}

impl crate::stream::StreamHandler for ProbeHandler {
    fn open<'a>(&'a self, request: crate::stream::Request<'a>) -> crate::stream::OpenFuture<'a> {
        let outcome = (|| {
            let (id, probe) = decode_probe_handler_record(request.record)?;
            if !Self::accept(&probe) {
                return None;
            }
            let plan = ProbeServicePlan::from_request(
                probe.workload(),
                quic_lite::DEFAULT_MAX_STREAM_PAYLOAD,
            );
            let payload = quic_lite::probe::ProbePayload::new(probe.bytes, plan.packet_size)?;
            let mut header = alloc::vec![0u8; 64];
            let used = encode_probe_handler_response(id, probe.bytes, plan.packet_size, &mut header)?;
            header.truncate(used);
            Some(crate::stream::Outcome::Respond(
                crate::stream::Response::with_body(header, ProbeBody(payload)),
            ))
        })();
        alloc::boxed::Box::pin(core::future::ready(outcome))
    }
}

/// Why a probe response was not a valid probe.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProbeClientError {
    /// The response header was malformed or not a `probe.handler` result.
    Header,
    /// The peer answered with an error header.
    Rejected,
    /// A payload byte differs from the probe pattern, or there are too many.
    Payload,
}

/// The caller's end of a probe: feeds the bytes of the response stream (header,
/// then payload) and validates the payload, however the transport chunks it.
pub struct ProbeResponseReader {
    buffer: alloc::vec::Vec<u8>,
    payload: Option<quic_lite::probe::ProbePayload>,
    expected: u64,
}

impl ProbeResponseReader {
    /// `expected` is the byte count that was requested.
    pub fn new(expected: u64) -> Self {
        Self {
            buffer: alloc::vec::Vec::new(),
            payload: None,
            expected,
        }
    }

    /// Feed the next ordered response bytes.
    pub fn push(&mut self, bytes: &[u8]) -> Result<(), ProbeClientError> {
        let mut bytes = bytes;
        if self.payload.is_none() {
            self.buffer.extend_from_slice(bytes);
            match crate::stream::scan_header(&self.buffer) {
                crate::stream::Header::NeedMore => return Ok(()),
                crate::stream::Header::Invalid => return Err(ProbeClientError::Header),
                crate::stream::Header::Complete(length) => {
                    let record = crate::tagged::decode(&self.buffer[..length])
                        .ok_or(ProbeClientError::Header)?;
                    if record.error.is_some() {
                        return Err(ProbeClientError::Rejected);
                    }
                    let mut d = Decoder::new(record.result.ok_or(ProbeClientError::Header)?);
                    let (major, count) = d.head().ok_or(ProbeClientError::Header)?;
                    if major != 5 || count != 2 {
                        return Err(ProbeClientError::Header);
                    }
                    let (mut length_field, mut packet_size) = (None, None);
                    for _ in 0..count {
                        match d.uint().ok_or(ProbeClientError::Header)? {
                            1 => length_field = d.uint(),
                            2 => packet_size = d.uint(),
                            _ => return Err(ProbeClientError::Header),
                        }
                    }
                    let announced = length_field.ok_or(ProbeClientError::Header)?;
                    if announced != self.expected {
                        return Err(ProbeClientError::Header);
                    }
                    let packet_size = usize::try_from(packet_size.ok_or(ProbeClientError::Header)?)
                        .map_err(|_| ProbeClientError::Header)?;
                    self.payload = Some(
                        quic_lite::probe::ProbePayload::new(announced, packet_size)
                            .ok_or(ProbeClientError::Header)?,
                    );
                    let body = self.buffer.split_off(length);
                    self.buffer.clear();
                    return self.check(&body);
                }
            }
        }
        let _ = &mut bytes;
        self.check(bytes)
    }

    fn check(&mut self, bytes: &[u8]) -> Result<(), ProbeClientError> {
        match self.payload.as_mut() {
            Some(payload) => payload
                .check(bytes)
                .map_err(|_| ProbeClientError::Payload),
            None => Ok(()),
        }
    }

    /// Payload bytes validated so far.
    pub fn bytes(&self) -> u64 {
        self.payload.as_ref().map_or(0, |payload| payload.offset())
    }

    /// Whether the whole payload arrived and was valid.
    pub fn is_complete(&self) -> bool {
        self.payload.as_ref().is_some_and(|payload| payload.is_complete())
    }
}

fn parse_mac(value: &[u8]) -> Option<[u8; 6]> {
    if value.len() != 17 {
        return None;
    }
    let mut mac = [0; 6];
    for (index, part) in value.split(|byte| *byte == b':').enumerate() {
        if index >= mac.len() || part.len() != 2 {
            return None;
        }
        let high = hex_nibble(part[0])?;
        let low = hex_nibble(part[1])?;
        mac[index] = (high << 4) | low;
    }
    (value.iter().filter(|byte| **byte == b':').count() == 5).then_some(mac)
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        PROBE_MAX_NORMAL_STREAMS, ProbeDestination, ProbeServicePlan, ProbeServiceRequest,
        decode_probe_start_record, encode_probe_start_request,
    };

    #[test]
    fn tagged_probe_run_round_trips_with_a_uri_destination() {
        let request = ProbeServiceRequest {
            bytes: 65_536,
            packet_size: 1200,
            ack_frequency: Some(8),
            ack_delay_ms: Some(5),
            low_priority_bytes: Some(100),
            high_priority_bytes: Some(200),
            parallel_streams: Some(2),
            initial_consume_delay_ms: Some(250),
            consume_delay_ms: Some(7),
            peer: Some(ProbeDestination::parse("espnow://20:6e:f1:13:b1:70").unwrap()),
        };
        let mut wire = [0u8; 128];
        let used = encode_probe_start_request(request, 42, &mut wire).unwrap();
        let record = crate::tagged::decode(&wire[..used]).unwrap();
        assert_eq!(decode_probe_start_record(record), Some((42, request)));
    }

    #[test]
    fn destination_uri_is_shared_by_explicit_bearers_and_mesh_vips() {
        let now = ProbeDestination::parse("espnow://02:11:22:33:44:55").unwrap();
        assert_eq!(now.scheme(), "espnow");
        assert_eq!(now.espnow_mac(), Some([2, 0x11, 0x22, 0x33, 0x44, 0x55]));
        let vip = ProbeDestination::parse("fc00::1234").unwrap();
        assert_eq!(vip.as_str(), "mesh://fc00::1234");
        assert_eq!(vip.espnow_mac(), None);
        assert!(ProbeDestination::parse("espnow://02:11:22:33:44:55,udp://host").is_none());
        assert!(ProbeDestination::parse("espnow://02:11:22:33:44:55?channel=6").is_none());
    }

    #[test]
    fn plan_has_one_shared_bounded_stream_and_ack_shape() {
        let request = ProbeServiceRequest {
            bytes: 10,
            packet_size: 65_535,
            ack_frequency: Some(255),
            ack_delay_ms: Some(0),
            low_priority_bytes: Some(7),
            high_priority_bytes: Some(3),
            parallel_streams: Some(255),
            initial_consume_delay_ms: Some(500),
            consume_delay_ms: Some(11),
            peer: None,
        };
        let plan = ProbeServicePlan::from_request(request.workload(), 1168);
        assert_eq!(plan.packet_size, 1168);
        assert_eq!(plan.normal_streams, PROBE_MAX_NORMAL_STREAMS);
        assert_eq!(plan.normal_bytes, [3, 3, 2, 2]);
        assert_eq!(plan.high_priority_bytes, 3);
        assert_eq!(plan.low_priority_bytes, 7);
        assert_eq!(plan.ack_frequency, 8);
        assert_eq!(plan.ack_delay_ms, 1);
        assert_eq!(plan.total_bytes(), 20);
    }

    #[test]
    fn the_probed_node_answers_with_a_header_then_a_validated_payload() {
        use crate::registry::{CallContext, Method, Registry};
        use crate::stream::{Outcome, Request};
        let registry = Registry::new();
        assert!(registry.register_stream(
            Method::new(super::PROBE_COMPONENT, "probe", super::PROBE_HANDLER, "source"),
            super::ProbeHandler
        ));
        let request = ProbeServiceRequest::new(5000, 512);
        let mut wire = [0u8; 128];
        let used = super::encode_probe_handler_request(request, 8, &mut wire).unwrap();
        let record = crate::tagged::decode(&wire[..used]).unwrap();
        let Some(Outcome::Respond(response)) = registry.open_now(Request {
            record,
            header: &wire[..used],
            context: CallContext::default(),
        }) else {
            panic!("probe.handler must answer")
        };
        let mut reader = response.into_reader();
        let mut client = super::ProbeResponseReader::new(5000);
        let mut chunk = [0u8; 333];
        loop {
            let (count, done) = reader.read(&mut chunk);
            client.push(&chunk[..count]).unwrap();
            if done {
                break;
            }
        }
        assert!(client.is_complete());
        assert_eq!(client.bytes(), 5000);
    }

    #[test]
    fn the_client_accepts_the_header_and_payload_in_one_chunk() {
        use crate::registry::{CallContext, Method, Registry};
        use crate::stream::{Outcome, Request};
        let registry = Registry::new();
        assert!(registry.register_stream(
            Method::new(super::PROBE_COMPONENT, "probe", super::PROBE_HANDLER, "source"),
            super::ProbeHandler
        ));
        let request = ProbeServiceRequest::new(700, 100);
        let mut wire = [0u8; 128];
        let used = super::encode_probe_handler_request(request, 3, &mut wire).unwrap();
        let record = crate::tagged::decode(&wire[..used]).unwrap();
        let Some(Outcome::Respond(response)) = registry.open_now(Request {
            record,
            header: &wire[..used],
            context: CallContext::default(),
        }) else {
            panic!("probe.handler must answer")
        };
        let mut reader = response.into_reader();
        let mut all = std::vec::Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            let (count, done) = reader.read(&mut chunk);
            all.extend_from_slice(&chunk[..count]);
            if done {
                break;
            }
        }
        let mut client = super::ProbeResponseReader::new(700);
        client.push(&all).unwrap();
        assert!(client.is_complete());
    }

    #[test]
    fn a_rejected_probe_is_an_error_header_not_payload() {
        use crate::registry::{CallContext, Method, Registry};
        use crate::stream::{Outcome, Request};
        let registry = Registry::new();
        assert!(registry.register_stream(
            Method::new(super::PROBE_COMPONENT, "probe", super::PROBE_HANDLER, "source"),
            super::ProbeHandler
        ));
        let mut request = ProbeServiceRequest::new(100, 512);
        request.ack_frequency = Some(2); // unsupported by the source
        let mut wire = [0u8; 128];
        let used = super::encode_probe_handler_request(request, 9, &mut wire).unwrap();
        let record = crate::tagged::decode(&wire[..used]).unwrap();
        let Some(Outcome::Respond(response)) = registry.open_now(Request {
            record,
            header: &wire[..used],
            context: CallContext::default(),
        }) else {
            panic!("a rejection is still an answer")
        };
        let mut reader = response.into_reader();
        let mut bytes = [0u8; 128];
        let (count, done) = reader.read(&mut bytes);
        assert!(done);
        let mut client = super::ProbeResponseReader::new(100);
        assert_eq!(
            client.push(&bytes[..count]),
            Err(super::ProbeClientError::Rejected)
        );
    }
}
