// IMPORTANT: This is shared no-std ESP firmware code. Host-testable CBOR
// decoding and schemas belong in dmesh-server; this module only applies the
// result to firmware state and uses the ESP UART adapter for exceptions.
//! Recovery command handler boundary.
//!
//! CBOR decoding is shared in `dmesh-server`; this module applies the decoded
//! request to the Recovery-owned parameter image. UART, UDP, and future L2
//! bearers call this handler without inheriting USB, PPP, or FreeRTOS code.

use dmesh_server::services::{encode_status_numeric, encode_status_text};

use crate::TransportProfile;

/// Emit a pre-encoded schema record through the selected direct bearer.
/// This is the bounded UART bootstrap fallback only: it is used before a
/// stream client can request status/events. Normal on-demand replies belong
/// on their requesting stream, and state transitions belong in event history.
pub fn send_record(record: &[u8]) -> bool {
    crate::uart_esp::send_direct_record(record)
}

/// Emit the shared diagnostic envelope over the registered direct-record
/// bearer. The selected bearer is a runtime policy, not a command concern.
pub fn send_response(message: &[u8]) {
    let Some(cbor) = encode_status_text(message) else {
        return;
    };
    let _ = send_record(&cbor);
}

pub fn send_stat(prefix: &[u8], value: u64) {
    let Some(cbor) = encode_status_numeric(prefix, value) else {
        return;
    };
    let _ = send_record(&cbor);
}

/// Apply an already-dispatched raw command to the device's transient profile.
/// Persisting settings is the registered NVS handler's responsibility; packet
/// decoding and reply routing belong to `dmesh-server` and the shared
/// dispatcher respectively.
pub fn apply_profile_command(packet: &[u8], params: &mut TransportProfile) -> Option<bool> {
    let result = crate::apply_recovery_packet(packet, params)?;
    Some(result.request_main_handoff)
}

#[cfg(test)]
mod command_tests {
    use super::apply_profile_command;
    use crate::{state::direct_record_generation_changed_from, TransportProfile};

    #[test]
    fn direct_record_arrival_during_worker_is_not_missed() {
        assert!(direct_record_generation_changed_from(41, 42));
        assert!(!direct_record_generation_changed_from(42, 42));
    }

    #[test]
    fn profile_command_keeps_runtime_values_out_of_device_state() {
        let packet = [0xa2, 0x00, 0x18, 0x44, 0x06, 0xa1, 0x18, 0xf2, 0x18, 0x40];
        let mut params = TransportProfile::new();
        assert_eq!(apply_profile_command(&packet, &mut params), Some(true));
        assert_eq!(params.ack_frequency, 0);
    }

    #[test]
    fn transport_ack_delay_and_path_policy_are_command_scoped() {
        let delay = [0xa2, 0x00, 0x18, 0x44, 0x06, 0xa1, 0x18, 0xf1, 0x01];
        let path = [
            0xa2, 0x00, 0x18, 0x44, 0x06, 0xa1, 0x64, b'p', b'a', b't', b'h', 0x03,
        ];
        let mut params = TransportProfile::new();
        assert_eq!(apply_profile_command(&delay, &mut params), Some(true));
        assert_eq!(params.ack_delay_ms, 1);
        assert_eq!(apply_profile_command(&path, &mut params), Some(true));
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
        assert_eq!(apply_profile_command(&packet, &mut params), Some(true));
        assert_eq!(params.ack_frequency, 8);
        assert_eq!(params.timeout_ms, 10_000);
    }
}
