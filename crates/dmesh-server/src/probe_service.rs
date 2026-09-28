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
    ProbePlan as ProbeServicePlan, ProbeRequest as ProbeServiceRequest,
    ProbeResult as ProbeServiceResult,
};

pub const PROBE_COMPONENT: u64 = 8;
pub const PROBE_RUN: u64 = 1;
/// Bounded storage for one complete canonical `probe.run` request.
pub const PROBE_RUN_REQUEST_MAX: usize = 128;
const FIELD_BYTES: u64 = 1;
const FIELD_PACKET_SIZE: u64 = 2;
const FIELD_ACK_FREQUENCY: u64 = 6;
const FIELD_ACK_DELAY_MS: u64 = 7;
const FIELD_LOW_PRIORITY_BYTES: u64 = 8;
const FIELD_HIGH_PRIORITY_BYTES: u64 = 9;
const FIELD_PARALLEL_STREAMS: u64 = 10;
const FIELD_INITIAL_CONSUME_DELAY_MS: u64 = 11;
const FIELD_CONSUME_DELAY_MS: u64 = 12;

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
        + usize::from(request.consume_delay_ms.is_some());
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
    Some(e.len())
}

/// Decode a canonical `probe.run` request already extracted from a QUIC
/// stream. Directed records are routing input and are never executed locally.
pub fn decode_probe_run_record(record: Record<'_>) -> Option<(u64, ProbeServiceRequest)> {
    if record.to.is_some()
        || record.component != Some(Name::Tag(PROBE_COMPONENT))
        || record.method != Some(Name::Tag(PROBE_RUN))
        || record.params.is_some()
    {
        return None;
    }
    let mut d = Decoder::new(record.fields?);
    let (major, count) = d.head()?;
    if major != 5 || count == u64::MAX || count > 12 {
        return None;
    }
    let mut seen = 0u16;
    let mut request = ProbeServiceRequest::new(0, 0);
    for _ in 0..count {
        let field = d.uint()?;
        if !(1..=12).contains(&field) || matches!(field, 3..=5) {
            return None;
        }
        let bit = 1u16.checked_shl((field - 1) as u32)?;
        if seen & bit != 0 {
            return None;
        }
        seen |= bit;
        let value = d.uint()?;
        match field {
            FIELD_BYTES => request.bytes = value,
            FIELD_PACKET_SIZE => request.packet_size = u16::try_from(value).ok()?,
            FIELD_ACK_FREQUENCY => request.ack_frequency = Some(u8::try_from(value).ok()?),
            FIELD_ACK_DELAY_MS => request.ack_delay_ms = Some(u8::try_from(value).ok()?),
            FIELD_LOW_PRIORITY_BYTES => {
                request.low_priority_bytes = Some(u32::try_from(value).ok()?)
            }
            FIELD_HIGH_PRIORITY_BYTES => {
                request.high_priority_bytes = Some(u32::try_from(value).ok()?)
            }
            FIELD_PARALLEL_STREAMS => request.parallel_streams = Some(u8::try_from(value).ok()?),
            FIELD_INITIAL_CONSUME_DELAY_MS => {
                request.initial_consume_delay_ms = Some(u32::try_from(value).ok()?)
            }
            FIELD_CONSUME_DELAY_MS => request.consume_delay_ms = Some(u32::try_from(value).ok()?),
            _ => return None,
        }
    }
    if seen & 0b11 != 0b11 || !d.is_finished() || request.bytes == 0 || request.packet_size == 0 {
        return None;
    }
    Some((record.id?, request))
}

#[cfg(test)]
mod tests {
    use super::{
        PROBE_MAX_NORMAL_STREAMS, ProbeServicePlan, ProbeServiceRequest, decode_probe_run_record,
        encode_probe_run_request,
    };

    #[test]
    fn tagged_probe_run_round_trips_without_bearer_metadata() {
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
        };
        let mut wire = [0u8; 128];
        let used = encode_probe_run_request(request, 42, &mut wire).unwrap();
        let record = crate::tagged::decode(&wire[..used]).unwrap();
        assert_eq!(decode_probe_run_record(record), Some((42, request)));
    }

    #[test]
    fn plan_has_one_shared_bounded_stream_and_ack_shape() {
        let plan = ProbeServicePlan::from_request(
            ProbeServiceRequest {
                bytes: 10,
                packet_size: 65_535,
                ack_frequency: Some(255),
                ack_delay_ms: Some(0),
                low_priority_bytes: Some(7),
                high_priority_bytes: Some(3),
                parallel_streams: Some(255),
                initial_consume_delay_ms: Some(500),
                consume_delay_ms: Some(11),
            },
            1168,
        );
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
