// IMPORTANT: This is shared no-std ESP firmware code. Host-testable CBOR
// decoding and schemas belong in dmesh-server; this module only applies the
// result to firmware state and uses the ESP UART adapter for exceptions.
//! Recovery command handler boundary.
//!
//! CBOR decoding is shared in `dmesh-server`; this module applies the decoded
//! request to the Recovery-owned parameter image. UART, UDP, and future L2
//! bearers call this handler without inheriting USB, PPP, or FreeRTOS code.

use alloc::vec::Vec;
use dmesh_server::services::{encode_numeric_result, encode_status_text};

use crate::TransportProfile;

/// Emit the shared Recovery diagnostic envelope over the configured direct
/// record egress.  This stays with the schema/command boundary; UART merely
/// transports the resulting opaque record.
pub fn send_response(message: &[u8]) {
    let Some(cbor) = encode_status_text(message) else {
        return;
    };
    let _ = crate::uart_esp::send_direct_record(&cbor);
}

pub fn send_stat(prefix: &[u8], value: u64) {
    let mut message = [0u8; 96];
    if prefix.len() >= message.len() {
        return;
    }
    message[..prefix.len()].copy_from_slice(prefix);
    let mut digits = [0u8; 20];
    let mut number = value;
    let mut count = 0;
    loop {
        digits[count] = b'0' + (number % 10) as u8;
        count += 1;
        number /= 10;
        if number == 0 {
            break;
        }
    }
    for index in 0..count {
        message[prefix.len() + index] = digits[count - index - 1];
    }
    send_response(&message[..prefix.len() + count]);
}

/// Emit compact numeric benchmark telemetry. Numeric keys are part of the
/// dmesh-server schema and deliberately never leak into UART transport code.
pub fn send_benchmark_stats(values: &[(u64, u64)]) {
    let Some(cbor) = encode_benchmark_stats(values) else {
        return;
    };
    let _ = crate::uart_esp::send_direct_record(&cbor);
}

/// Encode completion telemetry once for every direct-record path. An
/// oversized diagnostic is omitted rather than fragmented at the L2 layer.
fn encode_benchmark_stats(values: &[(u64, u64)]) -> Option<Vec<u8>> {
    encode_numeric_result(values)
}

#[cfg(test)]
mod tests {
    use super::encode_benchmark_stats;
    use alloc::vec::Vec;

    #[test]
    fn full_transport_benchmark_map_fits_shared_mtu() {
        let values: Vec<(u64, u64)> = (0..84)
            .map(|key| (key, u64::MAX.saturating_sub(key)))
            .collect();
        let encoded = encode_benchmark_stats(&values).expect("full benchmark map encodes");
        assert!(encoded.len() <= dmesh_fw_transport::TRANSPORT_MTU);
    }
}

/// Apply a transport-neutral Recovery request. Device persistence remains an
/// explicit callback on the parameter image; the handler owns no bearer I/O.
pub fn apply_packet(packet: &[u8], params: &mut TransportProfile) -> Option<bool> {
    let result = crate::apply_recovery_packet(packet, params)?;
    if result.profile_updated {
        unsafe {
            let _ = crate::esp_nvs::persist_profile(params);
        }
    }
    Some(result.request_main_handoff)
}

/// Dispatch one direct Recovery CBOR record from any bearer.  UART and UDP
/// only enqueue opaque records; this handler owns the schema and worker wake.
pub fn accept_packet(packet: &[u8], params: &mut TransportProfile) -> Option<bool> {
    let reboot_main = apply_packet(packet, params)?;
    crate::state::command_accepted();
    Some(reboot_main)
}

#[cfg(test)]
mod command_tests {
    use super::apply_packet;
    use crate::{state::command_generation_changed_from, TransportProfile};

    #[test]
    fn command_arrival_during_worker_is_not_missed() {
        assert!(command_generation_changed_from(41, 42));
        assert!(!command_generation_changed_from(42, 42));
    }

    #[test]
    fn explicit_transport_window_accepts_the_declared_64_packet_ceiling() {
        let packet = [0xa2, 0x00, 0x18, 0x44, 0x06, 0xa1, 0x18, 0xf2, 0x18, 0x40];
        let mut params = TransportProfile::new();
        assert_eq!(apply_packet(&packet, &mut params), Some(true));
        assert_eq!(
            params.iperf_window_packets,
            quic_lite::RECOVERY_MAX_DIAGNOSTIC_IN_FLIGHT_PACKETS as u8
        );
    }

    #[test]
    fn transport_ack_delay_and_path_policy_are_command_scoped() {
        let delay = [0xa2, 0x00, 0x18, 0x44, 0x06, 0xa1, 0x18, 0xf1, 0x01];
        let path = [
            0xa2, 0x00, 0x18, 0x44, 0x06, 0xa1, 0x64, b'p', b'a', b't', b'h', 0x03,
        ];
        let mut params = TransportProfile::new();
        assert_eq!(apply_packet(&delay, &mut params), Some(true));
        assert_eq!(params.ack_delay_ms, 1);
        assert_eq!(apply_packet(&path, &mut params), Some(true));
        assert_eq!(params.path_policy, 3);
    }

    #[test]
    fn full_host_transport_command_is_accepted() {
        let packet = [
            0xa2, 0x00, 0x18, 0x44, 0x06, 0xad, 0x18, 0xf8, 0xf5, 0x18, 0xfb, 0xf5, 0x18, 0xfc,
            0x19, 0x04, 0xb0, 0x18, 0xfd, 0x19, 0x70, 0x80, 0x18, 0xfe, 0x00, 0x18, 0xf9, 0x08,
            0x18, 0xfa, 0x19, 0x27, 0x10, 0x18, 0xbf, 0x19, 0x0d, 0x0b, 0x18, 0xff, 0x18, 0x7b,
            0x18, 0xf2, 0x00, 0x18, 0xf3, 0x00, 0x18, 0xf4, 0x00, 0x18, 0xf5, 0x00,
        ];
        let mut params = TransportProfile::new();
        assert_eq!(apply_packet(&packet, &mut params), Some(true));
        assert!(params.benchmark && params.transport_test);
        assert_eq!(params.port, 3339);
        assert_eq!(params.iperf_bytes, 28_800);
        assert_eq!(
            params.iperf_packet_size,
            quic_lite::DEFAULT_MAX_STREAM_PAYLOAD as u16
        );
        assert_eq!(params.ack_frequency, 8);
        assert_eq!(params.timeout_ms, 10_000);
        assert_eq!(params.benchmark_run_id, 123);
    }
}
