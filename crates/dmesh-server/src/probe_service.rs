//! Bearer-neutral PROBE stream request layout.
//!
//! `probe.run` uses the same tagged-CBOR envelope as every other callable
//! operation.

use crate::{
    cbor::{Decoder, Encoder},
    tagged::{Name, Record},
};

pub const PROBE_COMPONENT: u64 = 8;
pub const PROBE_RUN: u64 = 1;
/// Bounded storage for one complete canonical `probe.run` request.
pub const PROBE_RUN_REQUEST_MAX: usize = 128;
const FIELD_BYTES: u64 = 1;
const FIELD_PACKET_SIZE: u64 = 2;
const FIELD_PACE_US: u64 = 3;
const FIELD_BURST_PACKETS: u64 = 4;
const FIELD_BURST_DELAY_US: u64 = 5;
const FIELD_ACK_FREQUENCY: u64 = 6;
const FIELD_ACK_DELAY_MS: u64 = 7;
const FIELD_LOW_PRIORITY_BYTES: u64 = 8;
const FIELD_HIGH_PRIORITY_BYTES: u64 = 9;
const FIELD_PARALLEL_STREAMS: u64 = 10;

/// Maximum number of normal diagnostic streams in one handler invocation.
/// Keep this aligned with the bounded QUIC-lite service profile rather than
/// letting a host-only adapter accept a shape firmware cannot represent.
pub const PROBE_MAX_NORMAL_STREAMS: usize = 4;
/// The service-level byte bound is deliberately independent of a bearer MTU.
/// A caller supplies the latter when constructing an [`ProbeServicePlan`].
pub const PROBE_MAX_BYTES: u64 = 64 * 1024 * 1024;

/// Decoded PROBE request. Optional scheduling fields inherit server policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProbeServiceRequest {
    pub bytes: u64,
    pub packet_size: u16,
    pub pace_us: Option<u32>,
    pub burst_packets: Option<u8>,
    pub burst_delay_us: Option<u32>,
    pub ack_frequency: Option<u8>,
    pub ack_delay_ms: Option<u8>,
    pub low_priority_bytes: Option<u32>,
    pub high_priority_bytes: Option<u32>,
    pub parallel_streams: Option<u8>,
}

impl ProbeServiceRequest {
    pub const fn new(bytes: u64, packet_size: u16) -> Self {
        Self {
            bytes,
            packet_size,
            pace_us: None,
            burst_packets: None,
            burst_delay_us: None,
            ack_frequency: None,
            ack_delay_ms: None,
            low_priority_bytes: None,
            high_priority_bytes: None,
            parallel_streams: None,
        }
    }
}

/// Encode the canonical correlated `probe.run` request.
pub fn encode_probe_run_request(
    request: ProbeServiceRequest,
    id: u64,
    output: &mut [u8],
) -> Option<usize> {
    let optional = usize::from(request.pace_us.is_some())
        + usize::from(request.burst_packets.is_some())
        + usize::from(request.burst_delay_us.is_some())
        + usize::from(request.ack_frequency.is_some())
        + usize::from(request.ack_delay_ms.is_some())
        + usize::from(request.low_priority_bytes.is_some())
        + usize::from(request.high_priority_bytes.is_some())
        + usize::from(request.parallel_streams.is_some());
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
        (FIELD_PACE_US, request.pace_us.map(u64::from)),
        (FIELD_BURST_PACKETS, request.burst_packets.map(u64::from)),
        (FIELD_BURST_DELAY_US, request.burst_delay_us.map(u64::from)),
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
    if major != 5 || count == u64::MAX || count > 10 {
        return None;
    }
    let mut seen = 0u16;
    let mut request = ProbeServiceRequest::new(0, 0);
    for _ in 0..count {
        let field = d.uint()?;
        if !(1..=10).contains(&field) {
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
            FIELD_PACE_US => request.pace_us = Some(u32::try_from(value).ok()?),
            FIELD_BURST_PACKETS => request.burst_packets = Some(u8::try_from(value).ok()?),
            FIELD_BURST_DELAY_US => request.burst_delay_us = Some(u32::try_from(value).ok()?),
            FIELD_ACK_FREQUENCY => request.ack_frequency = Some(u8::try_from(value).ok()?),
            FIELD_ACK_DELAY_MS => request.ack_delay_ms = Some(u8::try_from(value).ok()?),
            FIELD_LOW_PRIORITY_BYTES => {
                request.low_priority_bytes = Some(u32::try_from(value).ok()?)
            }
            FIELD_HIGH_PRIORITY_BYTES => {
                request.high_priority_bytes = Some(u32::try_from(value).ok()?)
            }
            FIELD_PARALLEL_STREAMS => request.parallel_streams = Some(u8::try_from(value).ok()?),
            _ => return None,
        }
    }
    if seen & 0b11 != 0b11 || !d.is_finished() || request.bytes == 0 || request.packet_size == 0 {
        return None;
    }
    Some((record.id?, request))
}

/// Fully normalized, bearer-neutral PROBE handler work plan.
///
/// This is the single place where the stream service turns its compact wire
/// request into bounded normal/high/low producers and an ACK policy.  ESP
/// adapters and the host UDP listener must consume this plan instead of
/// independently clamping byte counts or choosing a different stream shape.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProbeServicePlan {
    pub packet_size: usize,
    pub normal_streams: usize,
    pub normal_bytes: [usize; PROBE_MAX_NORMAL_STREAMS],
    pub high_priority_bytes: usize,
    pub low_priority_bytes: usize,
    /// Human-facing ACK ratio, not the `frequency - 1` wire encoding.
    pub ack_frequency: u8,
    pub ack_delay_ms: u8,
    pub pace_us: u32,
    pub burst_packets: u8,
    pub burst_delay_us: u32,
}

impl ProbeServicePlan {
    /// Normalize a decoded service request for a specific complete-datagram
    /// payload budget. `max_packet_size` is supplied by the bearer adapter,
    /// but every other decision is shared by host and firmware.
    pub fn from_request(request: ProbeServiceRequest, max_packet_size: usize) -> Self {
        let normal_streams =
            usize::from(request.parallel_streams.unwrap_or(1)).clamp(1, PROBE_MAX_NORMAL_STREAMS);
        let requested = request.bytes.clamp(1, PROBE_MAX_BYTES) as usize;
        let each = requested / normal_streams;
        let remainder = requested % normal_streams;
        let mut normal_bytes = [0; PROBE_MAX_NORMAL_STREAMS];
        for (index, bytes) in normal_bytes.iter_mut().take(normal_streams).enumerate() {
            *bytes = each + usize::from(index < remainder);
        }
        Self {
            // Four bytes of deterministic PROBE sequence occupy each stream
            // payload. A smaller value cannot produce a valid frame.
            packet_size: usize::from(request.packet_size).clamp(8, max_packet_size.max(8)),
            normal_streams,
            normal_bytes,
            high_priority_bytes: request
                .high_priority_bytes
                .map(usize::try_from)
                .and_then(Result::ok)
                .unwrap_or(0)
                .min(PROBE_MAX_BYTES as usize),
            low_priority_bytes: request
                .low_priority_bytes
                .map(usize::try_from)
                .and_then(Result::ok)
                .unwrap_or(0)
                .min(PROBE_MAX_BYTES as usize),
            ack_frequency: request
                .ack_frequency
                .unwrap_or(2)
                .clamp(1, quic_lite::ACK_RANGE_CAPACITY as u8),
            ack_delay_ms: request.ack_delay_ms.unwrap_or(5).clamp(1, 25),
            pace_us: request.pace_us.unwrap_or(0),
            burst_packets: request.burst_packets.unwrap_or(0).min(32),
            burst_delay_us: request.burst_delay_us.unwrap_or(0),
        }
    }

    pub fn total_bytes(&self) -> u64 {
        self.normal_bytes[..self.normal_streams]
            .iter()
            .copied()
            .sum::<usize>()
            .saturating_add(self.high_priority_bytes)
            .saturating_add(self.low_priority_bytes) as u64
    }
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
            pace_us: Some(7_500),
            burst_packets: Some(3),
            burst_delay_us: Some(500),
            ack_frequency: Some(8),
            ack_delay_ms: Some(5),
            low_priority_bytes: Some(100),
            high_priority_bytes: Some(200),
            parallel_streams: Some(2),
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
                pace_us: Some(9),
                burst_packets: Some(255),
                burst_delay_us: Some(11),
                ack_frequency: Some(255),
                ack_delay_ms: Some(0),
                low_priority_bytes: Some(7),
                high_priority_bytes: Some(3),
                parallel_streams: Some(255),
            },
            1168,
        );
        assert_eq!(plan.packet_size, 1168);
        assert_eq!(plan.normal_streams, PROBE_MAX_NORMAL_STREAMS);
        assert_eq!(plan.normal_bytes, [3, 3, 2, 2]);
        assert_eq!(plan.high_priority_bytes, 3);
        assert_eq!(plan.low_priority_bytes, 7);
        assert_eq!(plan.ack_frequency, quic_lite::ACK_RANGE_CAPACITY as u8);
        assert_eq!(plan.ack_delay_ms, 1);
        assert_eq!(plan.burst_packets, 32);
        assert_eq!(plan.total_bytes(), 20);
    }
}
