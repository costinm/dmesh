//! Bearer-neutral IPERF stream request layout.
//!
//! This is intentionally not CBOR and has no socket/ESP dependency. It
//! describes the fixed payload after `SERVICE_IPERF`, so UDP, UART, ESP-NOW,
//! and host tests do not grow separate benchmark request parsers.

/// Fixed `SERVICE_IPERF` request length including the service tag.
pub const IPERF_REQUEST_LEN: usize = 31;
/// Maximum number of normal diagnostic streams in one handler invocation.
/// Keep this aligned with the bounded QUIC-lite service profile rather than
/// letting a host-only adapter accept a shape firmware cannot represent.
pub const IPERF_MAX_NORMAL_STREAMS: usize = 4;
/// The service-level byte bound is deliberately independent of a bearer MTU.
/// A caller supplies the latter when constructing an [`IperfServicePlan`].
pub const IPERF_MAX_BYTES: u64 = 64 * 1024 * 1024;

/// Decoded IPERF request. Optional scheduling fields are absent on the old
/// eleven-byte base request and inherit the server adapter's policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IperfServiceRequest {
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

impl IperfServiceRequest {
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

/// Fully normalized, bearer-neutral IPERF handler work plan.
///
/// This is the single place where the stream service turns its compact wire
/// request into bounded normal/high/low producers and an ACK policy.  ESP
/// adapters and the host UDP listener must consume this plan instead of
/// independently clamping byte counts or choosing a different stream shape.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IperfServicePlan {
    pub packet_size: usize,
    pub normal_streams: usize,
    pub normal_bytes: [usize; IPERF_MAX_NORMAL_STREAMS],
    pub high_priority_bytes: usize,
    pub low_priority_bytes: usize,
    /// Human-facing ACK ratio, not the `frequency - 1` wire encoding.
    pub ack_frequency: u8,
    pub ack_delay_ms: u8,
    pub pace_us: u32,
    pub burst_packets: u8,
    pub burst_delay_us: u32,
}

impl IperfServicePlan {
    /// Normalize a decoded service request for a specific complete-datagram
    /// payload budget. `max_packet_size` is supplied by the bearer adapter,
    /// but every other decision is shared by host and firmware.
    pub fn from_request(request: IperfServiceRequest, max_packet_size: usize) -> Self {
        let normal_streams =
            usize::from(request.parallel_streams.unwrap_or(1)).clamp(1, IPERF_MAX_NORMAL_STREAMS);
        let requested = request.bytes.clamp(1, IPERF_MAX_BYTES) as usize;
        let each = requested / normal_streams;
        let remainder = requested % normal_streams;
        let mut normal_bytes = [0; IPERF_MAX_NORMAL_STREAMS];
        for (index, bytes) in normal_bytes.iter_mut().take(normal_streams).enumerate() {
            *bytes = each + usize::from(index < remainder);
        }
        Self {
            // Four bytes of deterministic IPERF sequence occupy each stream
            // payload. A smaller value cannot produce a valid frame.
            packet_size: usize::from(request.packet_size).clamp(8, max_packet_size.max(8)),
            normal_streams,
            normal_bytes,
            high_priority_bytes: request
                .high_priority_bytes
                .map(usize::try_from)
                .and_then(Result::ok)
                .unwrap_or(0)
                .min(IPERF_MAX_BYTES as usize),
            low_priority_bytes: request
                .low_priority_bytes
                .map(usize::try_from)
                .and_then(Result::ok)
                .unwrap_or(0)
                .min(IPERF_MAX_BYTES as usize),
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

/// Decode one complete service request, including `SERVICE_IPERF` at byte 0.
/// The original byte-count/packet-size request remains valid; only complete
/// optional fields are interpreted.
pub fn decode_iperf_service_request(input: &[u8]) -> Option<IperfServiceRequest> {
    if input.first() != Some(&quic_lite::SERVICE_IPERF) {
        return None;
    }
    let bytes = input
        .get(1..9)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u64::from_be_bytes)?;
    let packet_size = input
        .get(9..11)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u16::from_be_bytes)?;
    Some(IperfServiceRequest {
        bytes,
        packet_size,
        pace_us: input
            .get(11..15)
            .and_then(|bytes| bytes.try_into().ok())
            .map(u32::from_be_bytes),
        burst_packets: input.get(15).copied(),
        burst_delay_us: input
            .get(16..20)
            .and_then(|bytes| bytes.try_into().ok())
            .map(u32::from_be_bytes),
        ack_frequency: input.get(20).copied(),
        ack_delay_ms: input.get(21).copied(),
        low_priority_bytes: input
            .get(22..26)
            .and_then(|bytes| bytes.try_into().ok())
            .map(u32::from_be_bytes),
        high_priority_bytes: input
            .get(26..30)
            .and_then(|bytes| bytes.try_into().ok())
            .map(u32::from_be_bytes),
        parallel_streams: input.get(30).copied(),
    })
}

/// Encode the complete extended request, including its service tag.
pub fn encode_iperf_service_request(
    request: IperfServiceRequest,
    output: &mut [u8],
) -> Option<usize> {
    let output = output.get_mut(..IPERF_REQUEST_LEN)?;
    output[0] = quic_lite::SERVICE_IPERF;
    output[1..9].copy_from_slice(&request.bytes.to_be_bytes());
    output[9..11].copy_from_slice(&request.packet_size.to_be_bytes());
    output[11..15].copy_from_slice(&request.pace_us.unwrap_or(0).to_be_bytes());
    output[15] = request.burst_packets.unwrap_or(0);
    output[16..20].copy_from_slice(&request.burst_delay_us.unwrap_or(0).to_be_bytes());
    output[20] = request.ack_frequency.unwrap_or(0);
    output[21] = request.ack_delay_ms.unwrap_or(0);
    output[22..26].copy_from_slice(&request.low_priority_bytes.unwrap_or(0).to_be_bytes());
    output[26..30].copy_from_slice(&request.high_priority_bytes.unwrap_or(0).to_be_bytes());
    output[30] = request.parallel_streams.unwrap_or(1);
    Some(IPERF_REQUEST_LEN)
}

#[cfg(test)]
mod tests {
    use super::{
        IPERF_MAX_NORMAL_STREAMS, IperfServicePlan, IperfServiceRequest,
        decode_iperf_service_request, encode_iperf_service_request,
    };

    #[test]
    fn extended_request_round_trips_without_a_bearer() {
        let request = IperfServiceRequest {
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
        let mut wire = [0u8; 31];
        assert_eq!(encode_iperf_service_request(request, &mut wire), Some(31));
        assert_eq!(decode_iperf_service_request(&wire), Some(request));
    }

    #[test]
    fn base_request_retains_server_defaults() {
        let wire = [quic_lite::SERVICE_IPERF, 0, 0, 0, 0, 0, 0, 1, 0, 0x04, 0xb0];
        let request = decode_iperf_service_request(&wire).unwrap();
        assert_eq!(request, IperfServiceRequest::new(256, 1200));
    }

    #[test]
    fn plan_has_one_shared_bounded_stream_and_ack_shape() {
        let plan = IperfServicePlan::from_request(
            IperfServiceRequest {
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
        assert_eq!(plan.normal_streams, IPERF_MAX_NORMAL_STREAMS);
        assert_eq!(plan.normal_bytes, [3, 3, 2, 2]);
        assert_eq!(plan.high_priority_bytes, 3);
        assert_eq!(plan.low_priority_bytes, 7);
        assert_eq!(plan.ack_frequency, quic_lite::ACK_RANGE_CAPACITY as u8);
        assert_eq!(plan.ack_delay_ms, 1);
        assert_eq!(plan.burst_packets, 32);
        assert_eq!(plan.total_bytes(), 20);
    }
}
