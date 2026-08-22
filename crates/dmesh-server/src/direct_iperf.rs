//! Bearer-neutral direct IPERF request/result records.
//!
//! This module deliberately contains no Recovery command grammar. Recovery,
//! Main, and host tests register the same tagged request and may carry it over
//! a direct record or a QUIC-lite stream according to their bearer policy.

use crate::cbor::{Decoder, Encoder};

pub const IPERF_COMPONENT: u64 = 2;
pub const IPERF_START: u64 = 1;

/// Bounded bootstrap identity used before a QUIC-lite connection exists.
/// This is a shared Stage2-adjacent diagnostic exception, not a service API.
pub const fn boot_identity_payload(role: u8, partition: u8) -> [u8; 11] {
    [
        0xbf, 0x07, 0x19, 0xea, 0x60, 0x06, 0x9f, role, partition, 0xff, 0xff,
    ]
}

/// Decode the bounded pre-connection boot identity exception.
pub const fn decode_boot_identity_payload(packet: &[u8]) -> Option<(u8, u8)> {
    if packet.len() == 11
        && packet[0] == 0xbf
        && packet[1] == 0x07
        && packet[2] == 0x19
        && packet[3] == 0xea
        && packet[4] == 0x60
        && packet[5] == 0x06
        && packet[6] == 0x9f
        && packet[9] == 0xff
        && packet[10] == 0xff
    {
        Some((packet[7], packet[8]))
    } else {
        None
    }
}

/// Request for a deterministic QUIC-lite IPERF stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IperfRequest {
    pub port: u16,
    pub bytes: u32,
    pub parallel_streams: u8,
    pub high_priority_bytes: u32,
    pub low_priority_bytes: u32,
    pub pace_us: u32,
    pub packet_size: u16,
    pub validation: u8,
    pub ack_frequency: u8,
    pub timeout_ms: u32,
    pub run_id: u32,
    pub window_packets: u8,
    pub ack_delay_ms: u8,
    pub path_policy: u8,
}

impl IperfRequest {
    pub fn uart(port: u16, bytes: u32, run_id: u32) -> Self {
        Self {
            port,
            bytes,
            parallel_streams: 1,
            high_priority_bytes: 0,
            low_priority_bytes: 0,
            pace_us: 0,
            packet_size: quic_lite::DEFAULT_MAX_STREAM_PAYLOAD as u16,
            validation: 1,
            ack_frequency: 8,
            timeout_ms: 40_000,
            run_id,
            window_packets: 8,
            ack_delay_ms: 5,
            path_policy: 2,
        }
    }
}

/// Terminal measurement emitted through the direct-record status channel.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IperfResult {
    pub run_id: u32,
    pub bytes: u64,
    pub elapsed_us: u64,
    pub normal_priority_bytes: u64,
    pub high_priority_bytes: u64,
    pub low_priority_bytes: u64,
}

impl IperfResult {
    pub fn bits_per_second(self) -> u64 {
        self.bytes.saturating_mul(8_000_000) / self.elapsed_us.max(1)
    }
}

/// Encode a tagged IPERF-start request into caller-provided storage.
pub fn encode_iperf_request(request: IperfRequest, out: &mut [u8]) -> Option<usize> {
    if request.port == 0
        || request.bytes < 8
        || !(1..=4).contains(&request.parallel_streams)
        || request.packet_size < 8
        || request.ack_frequency == 0
        || request.ack_frequency as usize > quic_lite::ACK_RANGE_CAPACITY
        || request.ack_delay_ms == 0
        || request.ack_delay_ms > 25
        || request.path_policy > 4
    {
        return None;
    }
    let mut cbor = Encoder::new(out);
    cbor.map(3)?;
    cbor.uint(1)?;
    cbor.uint(IPERF_COMPONENT)?;
    cbor.uint(2)?;
    cbor.uint(IPERF_START)?;
    cbor.uint(5)?;
    cbor.map(16)?;
    for (key, value) in [
        (248, 1),
        (251, 1),
        (252, u64::from(request.packet_size)),
        (253, u64::from(request.bytes)),
        (239, u64::from(request.parallel_streams)),
        (238, u64::from(request.high_priority_bytes)),
        (240, u64::from(request.low_priority_bytes)),
        (243, u64::from(request.pace_us)),
        (254, u64::from(request.validation)),
        (249, u64::from(request.ack_frequency)),
        (250, u64::from(request.timeout_ms)),
        (191, u64::from(request.port)),
        (255, u64::from(request.run_id)),
        (242, u64::from(request.window_packets)),
        (241, u64::from(request.ack_delay_ms)),
    ] {
        cbor.uint(key)?;
        if key == 248 || key == 251 {
            cbor.boolean(value != 0)?;
        } else {
            cbor.uint(value)?;
        }
    }
    cbor.text_value(b"path")?;
    cbor.uint(u64::from(request.path_policy))?;
    Some(cbor.len())
}

/// Decode the terminal numeric result envelope. Text/log records return None.
pub fn decode_iperf_result(packet: &[u8]) -> Option<IperfResult> {
    let mut root = Decoder::new(packet);
    let (major, fields) = root.head()?;
    if major != 5 {
        return None;
    }
    let mut entry = 0;
    while (fields == u64::MAX && !root.consume_break()) || (fields != u64::MAX && entry < fields) {
        entry += 1;
        if root.uint()? != 6 {
            root.skip()?;
            continue;
        }
        let (major, values) = root.head()?;
        if major != 5 {
            return None;
        }
        let (mut run_id, mut bytes, mut elapsed_us) = (None, None, None);
        let (mut normal, mut high, mut low) = (None, None, None);
        for _ in 0..values {
            match root.uint()? {
                59 => run_id = Some(root.uint()? as u32),
                34 => bytes = Some(root.uint()?),
                35 => elapsed_us = Some(root.uint()?),
                107 => normal = Some(root.uint()?),
                108 => high = Some(root.uint()?),
                109 => low = Some(root.uint()?),
                _ => root.skip()?,
            }
        }
        let bytes = bytes?;
        return Some(IperfResult {
            run_id: run_id?,
            bytes,
            elapsed_us: elapsed_us?,
            normal_priority_bytes: normal.unwrap_or(bytes),
            high_priority_bytes: high.unwrap_or(0),
            low_priority_bytes: low.unwrap_or(0),
        });
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_uses_the_common_tagged_envelope() {
        let mut request = IperfRequest::uart(3350, 131_072, 0x4455_6688);
        request.path_policy = 4;
        let mut packet = [0u8; 128];
        let used = encode_iperf_request(request, &mut packet).unwrap();
        let record = crate::tagged::decode(&packet[..used]).unwrap();
        assert_eq!(
            record.component,
            Some(crate::tagged::Name::Tag(IPERF_COMPONENT))
        );
        assert_eq!(record.method, Some(crate::tagged::Name::Tag(IPERF_START)));
        assert!(record.fields.is_some());
    }

    #[test]
    fn result_uses_the_common_numeric_result_envelope() {
        let packet = crate::services::encode_numeric_result(&[
            (34, 131_072),
            (35, 20_887_581),
            (59, 0x4455_6688),
        ])
        .unwrap();
        let result = decode_iperf_result(&packet).unwrap();
        assert_eq!(result.run_id, 0x4455_6688);
        assert_eq!(result.bytes, 131_072);
        assert_eq!(result.elapsed_us, 20_887_581);
        assert_eq!(result.bits_per_second(), 50_200);
    }

    #[test]
    fn boot_identity_is_a_small_bearer_neutral_exception() {
        assert_eq!(
            boot_identity_payload(1, 1),
            [0xbf, 0x07, 0x19, 0xea, 0x60, 0x06, 0x9f, 1, 1, 0xff, 0xff]
        );
        assert_eq!(
            decode_boot_identity_payload(&boot_identity_payload(2, 2)),
            Some((2, 2))
        );
    }
}
