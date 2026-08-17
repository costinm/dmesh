//! Shared compact-CBOR envelope for Recovery and Main-adjacent services.
//!
//! This module has no ESP, socket, or bearer dependency. Platform adapters
//! decide how to apply the decoded operation and persistent profile fields.

use crate::cbor::{Decoder, Encoder};

/// Numeric method identifier for the Recovery command schema.
pub const RECOVERY_METHOD: u64 = 68;

/// Bearer-neutral request for Recovery's deterministic QUIC-lite IPERF
/// stream. Host CLI adapters may transport the encoded record over UART,
/// UDP, or a future privileged action-frame bearer without reimplementing the
/// Recovery CBOR schema.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IperfRequest {
    pub port: u16,
    pub bytes: u32,
    /// Number of equal-priority IPERF streams carrying `bytes` in total.
    /// Bounded so the no_std firmware receiver can retain a fixed handler set.
    pub parallel_streams: u8,
    /// Optional stream scheduled ahead of ordinary IPERF. This models a
    /// latency-sensitive control response, rather than a UART control record.
    pub high_priority_bytes: u32,
    /// Optional log-like stream scheduled behind ordinary IPERF.
    pub low_priority_bytes: u32,
    /// Per-datagram sender interval for a controlled offered-load test.
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

/// Terminal Recovery IPERF measurement emitted through the direct-record
/// status channel. The same result format is independent of the bearer that
/// carried the stream.
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

/// Encode a compact command-scoped Recovery IPERF request. Returns `None`
/// for invalid values or an insufficient output buffer.
pub fn encode_iperf_request(request: IperfRequest, out: &mut [u8]) -> Option<usize> {
    if request.port == 0
        || request.bytes < 8
        || !(1..=4).contains(&request.parallel_streams)
        || request.packet_size < 8
        || request.ack_frequency == 0
        || request.ack_frequency as usize > quic_lite::ACK_RANGE_CAPACITY
        || request.ack_delay_ms == 0
        || request.ack_delay_ms > 25
        || request.path_policy > 3
    {
        return None;
    }
    let mut cbor = Encoder::new(out);
    cbor.map(2)?;
    cbor.uint(0)?;
    cbor.uint(RECOVERY_METHOD)?;
    cbor.uint(6)?;
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

/// Decode the terminal numeric result envelope. Ordinary text/log direct
/// records return `None` and remain opaque to the benchmark runner.
pub fn decode_iperf_result(packet: &[u8]) -> Option<IperfResult> {
    let mut root = Decoder::new(packet);
    let (major, fields) = root.head()?;
    if major != 5 {
        return None;
    }
    for _ in 0..fields {
        let key = root.uint()?;
        if key != 6 {
            root.skip()?;
            continue;
        }
        let (major, values) = root.head()?;
        if major != 5 {
            return None;
        }
        let mut run_id = None;
        let mut bytes = None;
        let mut elapsed_us = None;
        let mut normal_priority_bytes = None;
        let mut high_priority_bytes = None;
        let mut low_priority_bytes = None;
        for _ in 0..values {
            let key = root.uint()?;
            let value = root.uint()?;
            match key {
                59 => run_id = Some(value as u32),
                34 => bytes = Some(value),
                35 => elapsed_us = Some(value),
                // These result keys are intentionally outside Recovery's
                // existing transport-stat diagnostic range.  Older firmware
                // has no priority breakdown, so it falls back below.
                107 => normal_priority_bytes = Some(value),
                108 => high_priority_bytes = Some(value),
                109 => low_priority_bytes = Some(value),
                _ => {}
            }
        }
        let bytes = bytes?;
        return Some(IperfResult {
            run_id: run_id?,
            bytes,
            elapsed_us: elapsed_us?,
            normal_priority_bytes: normal_priority_bytes.unwrap_or(bytes),
            high_priority_bytes: high_priority_bytes.unwrap_or(0),
            low_priority_bytes: low_priority_bytes.unwrap_or(0),
        });
    }
    None
}

/// Borrowed, bearer-neutral Recovery command fields. Firmware applies these
/// values to its NVS-backed profile; host/server code can validate exactly
/// the same schema without ESP dependencies.
#[derive(Clone, Copy, Debug, Default)]
pub struct RecoveryCommand<'a> {
    pub operation: Option<&'a [u8]>,
    pub ssid: Option<&'a [u8]>,
    pub server: Option<&'a [u8]>,
    pub local_ip: Option<&'a [u8]>,
    pub gateway: Option<&'a [u8]>,
    pub mask: Option<&'a [u8]>,
    pub port: Option<u16>,
    pub profile_updated: bool,
    pub log_level: Option<u8>,
    pub benchmark: Option<bool>,
    pub transport_test: Option<bool>,
    pub iperf_packet_size: Option<u16>,
    pub iperf_bytes: Option<u32>,
    pub iperf_parallel_streams: Option<u8>,
    pub iperf_high_priority_bytes: Option<u32>,
    pub iperf_low_priority_bytes: Option<u32>,
    pub iperf_validation: Option<u8>,
    pub iperf_pace_us: Option<u32>,
    pub iperf_burst_packets: Option<u8>,
    pub iperf_burst_delay_us: Option<u32>,
    pub iperf_window_packets: Option<u8>,
    pub benchmark_run_id: Option<u32>,
    pub ack_frequency: Option<u8>,
    pub ack_delay_ms: Option<u8>,
    pub timeout_ms: Option<u32>,
    pub path_policy: Option<u8>,
}

/// Return the raw CBOR payload map from a canonical Recovery command envelope.
/// The envelope is `{0: 68|"recovery", 6: <map>}`; unrelated keys are
/// skipped so transport metadata can be added without changing adapters.
pub fn recovery_command_payload(packet: &[u8]) -> Option<&[u8]> {
    let mut root = Decoder::new(packet);
    let (major, fields) = root.head()?;
    if major != 5 {
        return None;
    }
    let mut recovery_method = false;
    let mut payload = None;
    for _ in 0..fields {
        let key = root.uint()?;
        if key == 0 {
            let (kind, value) = root.head()?;
            recovery_method = if kind == 0 {
                value == RECOVERY_METHOD
            } else if kind == 3 && value != u64::MAX {
                root.take(value as usize)? == b"recovery"
            } else {
                false
            };
        } else if key == 6 {
            let start = root.position();
            root.skip()?;
            payload = Some(&packet[start..root.position()]);
        } else {
            root.skip()?;
        }
    }
    recovery_method.then_some(payload?).filter(|payload| {
        let mut body = Decoder::new(payload);
        matches!(body.head(), Some((5, _)))
    })
}

fn bytes_or_text<'a>(decoder: &mut Decoder<'a>) -> Option<&'a [u8]> {
    let saved = decoder.position();
    if let Some(value) = decoder.bytes_ref() {
        return Some(value);
    }
    decoder.set_position(saved);
    decoder.text_ref()
}

/// Decode the common Recovery command fields. Unknown keys are skipped for
/// forward compatibility; known values are range-clamped at the schema edge.
pub fn decode_recovery_command(packet: &[u8]) -> Option<RecoveryCommand<'_>> {
    let payload = recovery_command_payload(packet)?;
    let mut body = Decoder::new(payload);
    let (major, fields) = body.head()?;
    if major != 5 {
        return None;
    }
    let mut command = RecoveryCommand::default();
    for _ in 0..fields {
        let (kind, numeric_key) = body.head()?;
        let text_key = if kind == 3 && numeric_key != u64::MAX {
            body.take(numeric_key as usize)?
        } else {
            &[]
        };
        let named = |name: &[u8]| text_key == name;
        if named(b"op") || (kind == 0 && numeric_key == 87) {
            command.operation = Some(body.text_ref()?);
        } else if named(b"ssid") {
            command.ssid = Some(bytes_or_text(&mut body)?);
            command.profile_updated = true;
        } else if named(b"server") || (kind == 0 && numeric_key == 246) {
            command.server = Some(bytes_or_text(&mut body)?);
            command.profile_updated = true;
        } else if named(b"ip") {
            command.local_ip = Some(bytes_or_text(&mut body)?);
            command.profile_updated = true;
        } else if named(b"gw") || named(b"gateway") {
            command.gateway = Some(bytes_or_text(&mut body)?);
            command.profile_updated = true;
        } else if named(b"mask") {
            command.mask = Some(bytes_or_text(&mut body)?);
            command.profile_updated = true;
        } else if named(b"port") || (kind == 0 && numeric_key == 191) {
            command.port = Some(body.uint_or_text()? as u16);
            command.profile_updated |= !text_key.is_empty();
        } else if named(b"log_level") {
            command.log_level = Some(body.uint_or_text()?.min(5) as u8);
        } else if named(b"benchmark") || (kind == 0 && numeric_key == 248) {
            command.benchmark = Some(body.boolean_or_text()?);
        } else if named(b"transport_test") || (kind == 0 && numeric_key == 251) {
            command.transport_test = Some(body.boolean_or_text()?);
        } else if named(b"iperf_packet_size") || (kind == 0 && numeric_key == 252) {
            command.iperf_packet_size = Some(
                body.uint_or_text()?
                    .clamp(8, quic_lite::DEFAULT_MAX_STREAM_PAYLOAD as u64) as u16,
            );
        } else if named(b"iperf_bytes") || (kind == 0 && numeric_key == 253) {
            command.iperf_bytes = Some(body.uint_or_text()?.clamp(8, 64 * 1024 * 1024) as u32);
        } else if named(b"iperf_parallel_streams") || (kind == 0 && numeric_key == 239) {
            command.iperf_parallel_streams = Some(body.uint_or_text()?.clamp(1, 4) as u8);
        } else if named(b"iperf_high_bytes") || (kind == 0 && numeric_key == 238) {
            command.iperf_high_priority_bytes =
                Some(body.uint_or_text()?.min(64 * 1024 * 1024) as u32);
        } else if named(b"iperf_low_bytes") || (kind == 0 && numeric_key == 240) {
            command.iperf_low_priority_bytes =
                Some(body.uint_or_text()?.min(64 * 1024 * 1024) as u32);
        } else if named(b"iperf_validation") || (kind == 0 && numeric_key == 254) {
            command.iperf_validation = Some(body.uint_or_text()?.min(2) as u8);
        } else if named(b"pace_us") || (kind == 0 && numeric_key == 243) {
            command.iperf_pace_us = Some(body.uint_or_text()?.min(1_000_000) as u32);
        } else if named(b"burst") || (kind == 0 && numeric_key == 244) {
            command.iperf_burst_packets = Some(body.uint_or_text()?.min(32) as u8);
        } else if named(b"burst_us") || (kind == 0 && numeric_key == 245) {
            command.iperf_burst_delay_us = Some(body.uint_or_text()?.min(1_000_000) as u32);
        } else if named(b"window") || (kind == 0 && numeric_key == 242) {
            command.iperf_window_packets = Some(
                body.uint_or_text()?
                    .min(quic_lite::RECOVERY_MAX_DIAGNOSTIC_IN_FLIGHT_PACKETS as u64)
                    as u8,
            );
        } else if named(b"run_id") || (kind == 0 && numeric_key == 255) {
            command.benchmark_run_id = Some(body.uint_or_text()? as u32);
        } else if named(b"ack") || named(b"af") || (kind == 0 && numeric_key == 249) {
            command.ack_frequency = Some(
                body.uint_or_text()?
                    .clamp(1, quic_lite::ACK_RANGE_CAPACITY as u64) as u8,
            );
        } else if named(b"ack_ms") || named(b"ack_delay") || (kind == 0 && numeric_key == 241) {
            command.ack_delay_ms = Some(body.uint_or_text()?.clamp(1, 25) as u8);
        } else if named(b"timeout_ms") || (kind == 0 && numeric_key == 250) {
            command.timeout_ms = Some(body.uint_or_text()?.clamp(1_000, 300_000) as u32);
        } else if named(b"path_policy") || named(b"path") {
            command.path_policy = Some(body.uint_or_text()?.min(3) as u8);
        } else {
            body.skip()?;
        }
    }
    Some(command)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn isolates_numeric_or_text_recovery_envelope() {
        let numeric = [
            0xa3, 0x00, 0x18, 0x44, 0x06, 0xa1, 0x64, b'p', b'a', b't', b'h', 0x03, 0x01, 0x00,
        ];
        assert_eq!(recovery_command_payload(&numeric), Some(&numeric[5..12]));
        let text = [
            0xa2, 0x00, 0x68, b'r', b'e', b'c', b'o', b'v', b'e', b'r', b'y', 0x06, 0xa0,
        ];
        assert_eq!(recovery_command_payload(&text), Some(&text[12..]));
    }

    #[test]
    fn rejects_non_recovery_or_non_map_payload() {
        assert_eq!(
            recovery_command_payload(&[0xa2, 0x00, 0x01, 0x06, 0xa0]),
            None
        );
        assert_eq!(
            recovery_command_payload(&[0xa2, 0x00, 0x18, 0x44, 0x06, 0x01]),
            None
        );
    }

    #[test]
    fn decodes_compact_transport_controls_without_firmware() {
        // {0: 68, 6: {248: true, 252: 1200, 249: 8, "path": 3}}
        let packet = [
            0xa2, 0x00, 0x18, 0x44, 0x06, 0xa4, 0x18, 0xf8, 0xf5, 0x18, 0xfc, 0x19, 0x04, 0xb0,
            0x18, 0xf9, 0x08, 0x64, b'p', b'a', b't', b'h', 0x03,
        ];
        let command = decode_recovery_command(&packet).unwrap();
        assert_eq!(command.benchmark, Some(true));
        assert_eq!(
            command.iperf_packet_size,
            Some(quic_lite::DEFAULT_MAX_STREAM_PAYLOAD as u16)
        );
        assert_eq!(command.ack_frequency, Some(8));
        assert_eq!(command.path_policy, Some(3));
    }

    #[test]
    fn iperf_request_round_trips_through_the_recovery_schema() {
        let request = IperfRequest::uart(3350, 131_072, 0x4455_6688);
        let mut packet = [0u8; 128];
        let used = encode_iperf_request(request, &mut packet).unwrap();
        let decoded = decode_recovery_command(&packet[..used]).unwrap();
        assert_eq!(decoded.port, Some(3350));
        assert_eq!(decoded.iperf_bytes, Some(131_072));
        assert_eq!(decoded.iperf_packet_size, Some(request.packet_size));
        assert_eq!(decoded.benchmark_run_id, Some(request.run_id));
        assert_eq!(decoded.path_policy, Some(2));
    }

    #[test]
    fn iperf_result_uses_the_common_numeric_result_envelope() {
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
    fn retains_binary_profile_values_without_copying() {
        let packet = [
            0xa2, 0x00, 0x18, 0x44, 0x06, 0xa2, 0x64, b's', b's', b'i', b'd', 0x43, b'a', 0, b'b',
            0x66, b's', b'e', b'r', b'v', b'e', b'r', 0x68, b'1', b'0', b'.', b'0', b'.', b'0',
            b'.', b'1',
        ];
        let command = decode_recovery_command(&packet).unwrap();
        assert_eq!(command.ssid, Some(&[b'a', 0, b'b'][..]));
        assert_eq!(command.server, Some(b"10.0.0.1".as_slice()));
        assert!(command.profile_updated);
    }
}
