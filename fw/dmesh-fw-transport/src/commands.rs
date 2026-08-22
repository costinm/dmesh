// IMPORTANT: This is shared no-std ESP firmware code. Host-testable CBOR
// decoding and schemas belong in dmesh-server; this module only applies the
// result to firmware state and uses the ESP UART adapter for exceptions.
//! Firmware control-application boundary.
//!
//! CBOR decoding is shared in `dmesh-server`; this module applies the decoded
//! request to the Recovery-owned parameter image. UART, UDP, and future L2
//! bearers call this handler without inheriting USB, PPP, or FreeRTOS code.

use dmesh_server::{
    connection::{self, ConnectionManager, ConnectionPolicy},
    control::{self, Handler, TransportConfig, TransportKind},
    firmware_profile::{apply_connection_policy, apply_transport_config, set_ssid},
    services::{encode_status_numeric, encode_status_text},
};

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

#[derive(Clone, Copy)]
enum ProfileControlError {
    Unsupported,
    InvalidSetting,
}

/// ESP application of common typed operations. It owns neither CBOR decoding
/// nor method routing: those stay in `dmesh-server::control` and are reused by
/// host adapters. Settings persistence and radio start/stop remain explicitly
/// unsupported until they have shared store/owner adapters.
struct ProfileControl<'a> {
    profile: &'a mut TransportProfile,
}

/// Result of applying one control record to the fixed-size radio profile.
///
/// A `transport.start` is a declaration of an immutable radio epoch, not an
/// imperative restart command.  Its Service Info may be repeated in multiple
/// NAN DWs, so callers must replace Wi-Fi only when this result reports an
/// actual profile change.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ControlApplyResult {
    pub transport_start: bool,
    pub changed: bool,
}

impl Handler for ProfileControl<'_> {
    type Error = ProfileControlError;

    fn settings_get(&mut self, _key: &[u8]) -> Result<(), Self::Error> {
        Err(ProfileControlError::Unsupported)
    }

    fn settings_set(&mut self, _key: &[u8], _value: &[u8]) -> Result<(), Self::Error> {
        Err(ProfileControlError::Unsupported)
    }

    fn settings_list(&mut self) -> Result<(), Self::Error> {
        Err(ProfileControlError::Unsupported)
    }

    fn transport_start(
        &mut self,
        kind: TransportKind,
        config: TransportConfig<'_>,
    ) -> Result<(), Self::Error> {
        match kind {
            TransportKind::Sta => {
                // One start selects one complete, ephemeral radio profile.
                // Do not persist it: UART and NAN Service Info must take the
                // same command path and replace the previous radio epoch.
                if config.ssid.is_none() && config.bssid.is_none() {
                    return Err(ProfileControlError::InvalidSetting);
                }
                if let Some(ssid) = config.ssid {
                    if !set_ssid(ssid, self.profile) {
                        return Err(ProfileControlError::InvalidSetting);
                    }
                }
                apply_transport_config(config, self.profile);
                self.profile.requested_transport = Some(kind);
                self.profile.run_requested = true;
                Ok(())
            }
            // Unassociated is the NOW-only radio epoch. It has no SSID, raw
            // UDP6 bearer, or DW capture unless a future nonzero interval is
            // explicitly implemented by its Wi-Fi owner.
            TransportKind::Nan => {
                apply_transport_config(config, self.profile);
                self.profile.requested_transport = Some(kind);
                self.profile.run_requested = true;
                Ok(())
            }
            // UART is Recovery's always-on bootstrap ingress and cannot be
            // stopped by the only control channel.
            TransportKind::Uart => Err(ProfileControlError::Unsupported),
        }
    }

    fn transport_stop(&mut self, kind: TransportKind) -> Result<(), Self::Error> {
        if self.profile.requested_transport == Some(kind) {
            self.profile.requested_transport = None;
            self.profile.run_requested = false;
            Ok(())
        } else {
            Err(ProfileControlError::Unsupported)
        }
    }
}

/// QUIC-lite owns this policy boundary, independently of bearer start/stop.
/// The firmware profile is only a fixed-capacity cache used while constructing
/// the next raw association; it does not make the radio an owner of streams.
impl ConnectionManager for ProfileControl<'_> {
    type Error = ProfileControlError;

    fn configure_connection(&mut self, policy: ConnectionPolicy) -> Result<(), Self::Error> {
        apply_connection_policy(policy, self.profile);
        Ok(())
    }
}

/// Apply one common tagged control request to transient transport state.
/// The only firmware responsibility is applying typed values to ESP-owned
/// state. It contains no command grammar, method tags, or CBOR traversal.
pub fn apply_control_record(packet: &[u8], params: &mut TransportProfile) -> Option<bool> {
    apply_control_record_result(packet, params).map(|_| true)
}

/// Apply one shared control record and report whether it changed the selected
/// immutable radio profile.  UART and NAN SD use this exact helper so a
/// repeated active Subscribe/Publish command remains idempotent.
pub fn apply_control_record_result(
    packet: &[u8],
    params: &mut TransportProfile,
) -> Option<ControlApplyResult> {
    let request = control::decode_request(packet);
    if let Some(request) = request {
        let transport_start = matches!(request, control::Request::TransportStart { .. });
        let before = *params;
        return control::dispatch_request(request, &mut ProfileControl { profile: params })
            .ok()
            .map(|()| ControlApplyResult {
                transport_start,
                changed: *params != before,
            });
    }
    let request = connection::decode_request(packet)?;
    connection::dispatch_request(request, &mut ProfileControl { profile: params })
        .ok()
        .map(|()| ControlApplyResult {
            transport_start: false,
            changed: false,
        })
}

/// True when bytes use one of the common direct-CBOR command envelopes.
/// Wi-Fi uses this only to select a Service Descriptor before copying it out
/// of a driver-owned receive buffer; application of the record remains on the
/// shared ingress worker through [`apply_control_record_result`].
pub fn is_control_record(packet: &[u8]) -> bool {
    control::decode_request(packet).is_some() || connection::decode_request(packet).is_some()
}

/// Response projection is shared with host tests; firmware only selects the
/// physical direct bearer used to return the encoded record.
pub use dmesh_server::firmware_profile::encode_profile_control_response as encode_control_response;

#[cfg(test)]
mod command_tests {
    use super::{ControlApplyResult, apply_control_record, apply_control_record_result};
    use crate::{TransportProfile, state::direct_record_generation_changed_from};

    #[test]
    fn direct_record_arrival_during_worker_is_not_missed() {
        assert!(direct_record_generation_changed_from(41, 42));
        assert!(!direct_record_generation_changed_from(42, 42));
    }

    #[test]
    fn tagged_connection_configuration_updates_the_shared_profile() {
        // {component: connection, method: configure,
        //  fields: {ack_frequency: 8, path_policy: 3}}
        let packet = [0xa3, 1, 3, 2, 1, 5, 0xa2, 2, 8, 11, 3];
        let mut params = TransportProfile::new();
        assert_eq!(apply_control_record(&packet, &mut params), Some(true));
        assert_eq!(params.ack_frequency, 8);
        assert_eq!(params.path_policy, 3);
    }

    #[test]
    fn legacy_profile_map_is_rejected() {
        let legacy = [0xa2, 0x00, 0x18, 0x44, 0x06, 0xa0];
        let mut params = TransportProfile::new();
        assert_eq!(apply_control_record(&legacy, &mut params), None);
    }

    #[test]
    fn tagged_ssid_setting_is_bounded() {
        let packet = [
            0xa3, 1, 1, 2, 2, 5, 0xa2, 1, 0x64, b's', b's', b'i', b'd', 2, 0x64, b't', b'e', b's',
            b't',
        ];
        let mut params = TransportProfile::new();
        assert_eq!(apply_control_record(&packet, &mut params), Some(true));
        assert_eq!(&params.ssid[..params.ssid_len], b"test");
    }

    #[test]
    fn transport_lifecycle_is_independent_from_connection_policy() {
        let mut params = TransportProfile::new();
        assert!(super::set_ssid(b"DIRECT-test", &mut params));
        // {1: control, 2: transport.start, 5: {1: sta}}
        let start_sta = [0xa3, 1, 1, 2, 4, 5, 0xa1, 1, 1];
        assert_eq!(apply_control_record(&start_sta, &mut params), Some(true));
        assert_eq!(
            params.requested_transport,
            Some(dmesh_server::control::TransportKind::Sta)
        );
        assert_eq!(params.ack_frequency, 0);

        // {1: control, 2: transport.stop, 5: {1: sta}}
        let stop_sta = [0xa3, 1, 1, 2, 5, 5, 0xa1, 1, 1];
        assert_eq!(apply_control_record(&stop_sta, &mut params), Some(true));
        assert_eq!(params.requested_transport, None);
    }

    #[test]
    fn repeated_nan_transport_start_is_an_idempotent_profile_declaration() {
        // {1: control, 2: transport.start, 5: {1: nan, 14: DW1}}
        // This is the same bounded CBOR payload that can arrive in more than
        // one active NAN Publish/Subscribe discovery window.
        let start_nan = [0xa3, 1, 1, 2, 4, 5, 0xa2, 1, 6, 14, 1];
        let mut params = TransportProfile::new();
        assert_eq!(
            apply_control_record_result(&start_nan, &mut params),
            Some(ControlApplyResult {
                transport_start: true,
                changed: true,
            })
        );
        let committed = params;
        assert_eq!(
            apply_control_record_result(&start_nan, &mut params),
            Some(ControlApplyResult {
                transport_start: true,
                changed: false,
            })
        );
        assert_eq!(params, committed);
    }

    #[test]
    fn repeated_android_sta_publish_is_an_idempotent_profile_declaration() {
        // Captured Android primary DMesh Service Info: STA, SSID, BSSID,
        // channel 6, DW off, NOW on, AP on, driver TX on, and 11b enabled.
        // Active Publish repeats this exact payload in later discovery
        // windows; only the first arrival may request a radio replacement.
        let start_sta = [
            0xa3, 1, 1, 2, 4, 5, 0xa9, 1, 1, 2, 0x78, 0x1b, b'D', b'i', b'r', b'e', b'c', b't',
            b'-', b'F', b'8', b'1', b'7', b'D', b'E', b'6', b'5', b'-', b'D', b'm', b'e', b's',
            b'h', b'-', b'l', b'o', b'c', b'a', b'l', 3, 0x46, 0x74, 0x19, 0xf8, 0x17, 0xde, 0x65,
            4, 6, 14, 0, 15, 0, 16, 1, 6, 0xf5, 9, 0xf4,
        ];
        let mut params = TransportProfile::new();
        assert_eq!(
            apply_control_record_result(&start_sta, &mut params),
            Some(ControlApplyResult {
                transport_start: true,
                changed: true,
            })
        );
        let committed = params;
        assert_eq!(
            apply_control_record_result(&start_sta, &mut params),
            Some(ControlApplyResult {
                transport_start: true,
                changed: false,
            })
        );
        assert_eq!(params, committed);
    }
}
