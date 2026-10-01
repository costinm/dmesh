//! Bearer-neutral PROBE stream request layout.
//!
//! `probe.run` uses the same tagged-CBOR envelope as every other callable
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
pub const PROBE_RUN: u64 = 1;
/// Bounded storage for one complete canonical `probe.run` request.
pub const PROBE_RUN_REQUEST_MAX: usize = 160;
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

/// Encode the canonical correlated `probe.run` request.
pub fn encode_probe_run_request(
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
    e.uint(PROBE_RUN)?;
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

/// Decode a canonical `probe.run` request already extracted from a QUIC
/// stream. Directed records are routing input and are never executed locally.
pub fn decode_probe_run_record(record: Record<'_>) -> Option<(u64, ProbeServiceRequest)> {
    if record.component != Some(Name::Tag(PROBE_COMPONENT))
        || record.method != Some(Name::Tag(PROBE_RUN))
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
        PROBE_RUN,
        id,
        &value[..value_len],
        output,
    )
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
        decode_probe_run_record, encode_probe_run_request,
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
        let used = encode_probe_run_request(request, 42, &mut wire).unwrap();
        let record = crate::tagged::decode(&wire[..used]).unwrap();
        assert_eq!(decode_probe_run_record(record), Some((42, request)));
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
}
