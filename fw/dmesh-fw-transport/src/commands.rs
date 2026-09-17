// IMPORTANT: This is shared no-std ESP firmware code. Host-testable CBOR
// decoding and schemas belong in dmesh-server; this module only applies the
// result to firmware state and uses the ESP UART adapter for exceptions.
//!
//! CBOR decoding is shared in `dmesh-server`; this module applies the decoded
//! request to the Recovery-owned parameter image. UART, UDP, and future L2
//! bearers call this handler without inheriting USB, PPP, or FreeRTOS code.

extern crate alloc;

use dmesh_server::{
    connection::{self, ConnectionManager, ConnectionPolicy},
    control::{self, Handler, TransportConfig, TransportKind},
    firmware_profile::{
        apply_connection_policy, apply_transport_config, clear_sta_passphrase, set_ssid,
    },
    services::{encode_status_numeric, encode_status_text},
};

use crate::TransportProfile;

/// Emit a pre-encoded schema record through the selected direct bearer.
/// This is the bounded UART bootstrap fallback only: it is used before a
/// stream client can request status/events. Normal on-demand replies belong
/// on their requesting stream, and state transitions belong in event history.
pub fn send_record(record: &[u8]) -> bool {
    #[cfg(feature = "uart-transport")]
    {
        crate::uart_esp::send_direct_record(record)
    }
    #[cfg(not(feature = "uart-transport"))]
    {
        let _ = record;
        false
    }
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

/// Emit one bounded multi-field diagnostic event. Values describing a single
/// physical boundary remain together in a passive UART/NOW observation.
pub fn send_stats(entries: &[(&[u8], u64)]) {
    let Some(cbor) = dmesh_server::services::encode_status_numbers(entries) else {
        return;
    };
    let _ = send_record(&cbor);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProfileControlError {
    Unsupported,
    InvalidSetting,
    Settings,
}

/// ESP application of common typed operations. It owns neither CBOR decoding
/// nor method routing: those stay in `dmesh-server::control` and are reused by
/// host adapters. Settings persistence and radio start/stop remain explicitly
/// unsupported until they have shared store/owner adapters.
struct ProfileControl<'a> {
    profile: &'a mut TransportProfile,
    nan_wake_sta_requested: bool,
}

/// Result of applying one control record to the fixed-size radio profile.
///
/// A `transport.set` is a declaration of an immutable radio epoch, not an
/// imperative restart command.  Its Service Info may be repeated in multiple
/// NAN DWs, so callers must replace Wi-Fi only when this result reports an
/// actual profile change.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ControlApplyResult {
    pub transport_set: bool,
    pub changed: bool,
}

impl Handler for ProfileControl<'_> {
    type Error = ProfileControlError;

    fn settings_get(&mut self, key: &[u8]) -> Result<(), Self::Error> {
        if key.starts_with(b"sec:") {
            return Err(ProfileControlError::Unsupported);
        }
        let mut value = [0u8; 64];
        let Some(used) = crate::main_runtime::read_setting(key, &mut value) else {
            return Err(ProfileControlError::InvalidSetting);
        };
        // The correlated stream response is emitted by the tagged handler.
        // Do not leak a second status record through UART/NOW merely because
        // a setting happened to be read over a stream.
        let _ = core::str::from_utf8(key).map_err(|_| ProfileControlError::InvalidSetting)?;
        let _ = core::str::from_utf8(&value[..used]).map_err(|_| ProfileControlError::Settings)?;
        Ok(())
    }

    fn settings_set(&mut self, key: &[u8], value: &[u8]) -> Result<(), Self::Error> {
        if crate::main_runtime::write_binary_setting(key, value) {
            return Ok(());
        }
        if let Some(secret_key) = key.strip_prefix(b"sec:") {
            if !crate::main_runtime::write_secret_setting(secret_key, value) {
                return Err(ProfileControlError::InvalidSetting);
            }
            return Ok(());
        }
        if !crate::main_runtime::write_setting(key, value) {
            return Err(ProfileControlError::InvalidSetting);
        }
        Ok(())
    }

    fn settings_list(&mut self) -> Result<(), Self::Error> {
        let mut value = [0u8; 64];
        for key in crate::main_runtime::setting_keys() {
            let Some(used) = crate::main_runtime::read_setting(key, &mut value) else {
                continue;
            };
            let _ = core::str::from_utf8(key).map_err(|_| ProfileControlError::Settings)?;
            let _ =
                core::str::from_utf8(&value[..used]).map_err(|_| ProfileControlError::Settings)?;
        }
        for key in crate::main_runtime::secret_setting_keys() {
            if crate::main_runtime::secret_setting_exists(key) {
                let _ = core::str::from_utf8(key).map_err(|_| ProfileControlError::Settings)?;
            }
        }
        Ok(())
    }

    fn transport_set(
        &mut self,
        kind: TransportKind,
        config: TransportConfig<'_>,
    ) -> Result<(), Self::Error> {
        // NAN active-Subscribe frames are broadcast at the 802.11 layer. A
        // wake record therefore carries its intended receiver explicitly;
        // never let a neighbouring sleepy device promote itself merely
        // because it shares the DMesh service ID.  Ordinary UART/NOW control
        // records omit this field and retain their existing semantics.
        if let Some(target) = config.wake_target {
            let station = crate::wifi_esp::interface_mac(crate::wifi_esp::RadioInterface::Sta);
            let ap = crate::wifi_esp::interface_mac(crate::wifi_esp::RadioInterface::Ap);
            let matched = station == Some(target) || ap == Some(target);
            // A NAN wake is deliberately rare and is the only direct
            // transport mutation sent over a broadcast Service Discovery
            // action.  Preserve enough local evidence to distinguish RF
            // delivery from target admission without exposing credentials.
            crate::commands::send_stats(&[
                (b"nan wake target_le", mac_le(target)),
                (b"nan wake station_le", station.map(mac_le).unwrap_or(0)),
                (b"nan wake ap_le", ap.map(mac_le).unwrap_or(0)),
                (b"nan wake target_match", matched as u64),
            ]);
            if !matched {
                return Err(ProfileControlError::InvalidSetting);
            }
        }
        match kind {
            TransportKind::Sta => {
                // One start selects one complete, ephemeral radio profile.
                // Do not persist it: UART and NAN Service Info must take the
                // same command path and replace the previous radio epoch.
                let configured_profile = config.ssid.is_none() && config.bssid.is_none();
                // A configured STA profile is a legitimate on-demand target:
                // `transport.start {mode: sta}` must be able to return from
                // NAN/NOW without repeating a protected credential over the
                // control bearer.  An entirely empty profile remains invalid
                // so an unauthenticated request cannot make the adapter try
                // an unspecified network.
                if configured_profile && !self.profile.has_flash_profile() {
                    crate::commands::send_response(b"nan wake rejected: no STA profile");
                    return Err(ProfileControlError::InvalidSetting);
                }
                let mut candidate = *self.profile;
                if let Some(ssid) = config.ssid {
                    if !set_ssid(ssid, &mut candidate) {
                        return Err(ProfileControlError::InvalidSetting);
                    }
                }
                // An explicit target replaces the radio epoch: an omitted
                // PSK then selects the fixed DMesh WPA2 key and must not
                // accidentally reuse a prior Android P2P secret.  By
                // contrast, target-less `mode=sta` selects the provisioned
                // profile and deliberately retains its protected PSK.
                if !configured_profile {
                    clear_sta_passphrase(&mut candidate);
                }
                apply_transport_config(config, &mut candidate);
                candidate.requested_transport = Some(kind);
                candidate.run_requested = true;
                *self.profile = candidate;
                if config.wake_target.is_some() {
                    self.nan_wake_sta_requested = true;
                    crate::commands::send_response(b"nan wake accepted: STA requested");
                }
                Ok(())
            }
            // Unassociated is the NOW-only radio epoch. It has no SSID, raw
            // UDP6 bearer, or DW capture unless a future nonzero interval is
            // explicitly implemented by its Wi-Fi owner.
            TransportKind::Nan => {
                let mut candidate = *self.profile;
                apply_transport_config(config, &mut candidate);
                // DW8 retains its control UART. It is not a light-sleep
                // precondition, and keeping it available makes a sleepy node
                // observable without a physical reconfiguration cycle.
                candidate.requested_transport = Some(kind);
                candidate.run_requested = true;
                *self.profile = candidate;
                Ok(())
            }
            // UART is Recovery's always-on bootstrap ingress and cannot be
            // stopped by the only control channel.
            TransportKind::Uart => Err(ProfileControlError::Unsupported),
        }
    }
}

const fn mac_le(mac: [u8; 6]) -> u64 {
    u64::from_le_bytes([mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], 0, 0])
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
    apply_control_record_result(packet, params)
        .and_then(Result::ok)
        .map(|_| true)
}

/// Apply one shared control record and report whether it changed the selected
/// immutable radio profile.  UART and NAN SD use this exact helper so a
/// repeated active Subscribe/Publish command remains idempotent.
pub fn apply_control_record_result(
    packet: &[u8],
    params: &mut TransportProfile,
) -> Option<Result<ControlApplyResult, ProfileControlError>> {
    let request = control::decode_request(packet);
    if let Some(request) = request {
        let transport_set = matches!(request, control::Request::TransportSet { .. });
        let before = *params;
        let mut handler = ProfileControl {
            profile: params,
            nan_wake_sta_requested: false,
        };
        let outcome = control::dispatch_request(request, &mut handler).map(|()| {
            let changed = *handler.profile != before;
            if changed && handler.nan_wake_sta_requested {
                crate::main_runtime::note_nan_wake_sta_requested();
            }
            ControlApplyResult {
                transport_set,
                changed,
            }
        });
        return Some(outcome);
    }
    let request = connection::decode_request(packet)?;
    Some(
        connection::dispatch_request(
            request,
            &mut ProfileControl {
                profile: params,
                nan_wake_sta_requested: false,
            },
        )
        .map(|()| ControlApplyResult {
            transport_set: false,
            changed: false,
        }),
    )
}

/// Apply the sole mutable application-control record admitted on the direct
/// plane.  Settings, stop/discover, connection policy, relay, and radio-lab
/// records remain normal stream handlers even when their CBOR payload happens
/// to fit in one datagram.
///
/// `TransportSet` is the Rust spelling for wire method `1/4` and the public
/// contract and catalog call it `transport.set`.
pub fn apply_direct_transport_set_record_result(
    packet: &[u8],
    params: &mut TransportProfile,
) -> Option<Result<ControlApplyResult, ProfileControlError>> {
    let request = control::decode_request(packet)?;
    if !matches!(request, control::Request::TransportSet { .. }) {
        return None;
    }
    let before = *params;
    let mut handler = ProfileControl {
        profile: params,
        nan_wake_sta_requested: false,
    };
    let outcome = control::dispatch_request(request, &mut handler).map(|()| {
        let changed = *handler.profile != before;
        if changed && handler.nan_wake_sta_requested {
            crate::main_runtime::note_nan_wake_sta_requested();
        }
        ControlApplyResult {
            transport_set: true,
            changed,
        }
    });
    Some(outcome)
}

/// Apply a decoded local tagged record. UDP6/QUIC dispatch has already parsed
/// the envelope before invoking the registered firmware handler, so retaining
/// this record-based entry point avoids rebuilding a temporary packet merely
/// to reuse the UART/NAN profile implementation.
pub fn apply_control_record_decoded(
    record: dmesh_server::tagged::Record<'_>,
    params: &mut TransportProfile,
) -> Option<Result<ControlApplyResult, ProfileControlError>> {
    if record.to.is_some() {
        return None;
    }
    if let Some(request) = control::decode_record(record) {
        let transport_set = matches!(request, control::Request::TransportSet { .. });
        let before = *params;
        let mut handler = ProfileControl {
            profile: params,
            nan_wake_sta_requested: false,
        };
        let outcome = control::dispatch_request(request, &mut handler).map(|()| {
            let changed = *handler.profile != before;
            if changed && handler.nan_wake_sta_requested {
                crate::main_runtime::note_nan_wake_sta_requested();
            }
            ControlApplyResult {
                transport_set,
                changed,
            }
        });
        return Some(outcome);
    }
    let request = connection::decode_record(record)?;
    Some(
        connection::dispatch_request(
            request,
            &mut ProfileControl {
                profile: params,
                nan_wake_sta_requested: false,
            },
        )
        .map(|()| ControlApplyResult {
            transport_set: false,
            changed: false,
        }),
    )
}

/// Encode the empty successful result for a decoded control/connection record.
/// The request id and method remain in the common tagged envelope, allowing a
/// UDP6 caller to correlate a one-shot `transport.start` response.
pub fn encode_control_response_decoded(
    record: dmesh_server::tagged::Record<'_>,
    out: &mut [u8],
) -> Option<usize> {
    let id = record.id?;
    if let Some(request) = control::decode_record(record) {
        return dmesh_server::tagged::encode_numeric_response(
            control::CONTROL_COMPONENT,
            control_method(request),
            id,
            &[0xa0],
            out,
        );
    }
    if let Some(request) = connection::decode_record(record) {
        return dmesh_server::tagged::encode_numeric_response(
            connection::CONNECTION_COMPONENT,
            connection_method(request),
            id,
            &[0xa0],
            out,
        );
    }
    None
}

/// True when bytes use one of the common direct-CBOR command envelopes.
/// Wi-Fi uses this only to select a Service Descriptor before copying it out
/// of a driver-owned receive buffer; application of the record remains on the
/// shared ingress worker through [`apply_control_record_result`].
pub fn is_control_record(packet: &[u8]) -> bool {
    control::decode_request(packet).is_some() || connection::decode_request(packet).is_some()
}

/// True only for wire method `1/4`, published as `transport.set`.
///
/// This is the mutable application record admitted on the connectionless
/// direct plane. The broader [`is_control_record`] remains for normal stream
/// dispatch and must not be used by a direct bearer.
pub fn is_direct_transport_set_record(packet: &[u8]) -> bool {
    matches!(
        control::decode_request(packet),
        Some(control::Request::TransportSet { .. })
    )
}

/// Response projection is shared with host tests; firmware only selects the
/// physical direct bearer used to return the encoded record.
pub use dmesh_server::firmware_profile::encode_profile_control_response as encode_control_response;

/// Encode a handler rejection with the original request id. Fire-and-forget
/// records have no id and therefore continue to use the bounded text fallback
/// at the bearer adapter; correlated callers always receive `err` instead.
pub fn encode_control_error(
    packet: &[u8],
    error: ProfileControlError,
    out: &mut [u8],
) -> Option<usize> {
    let record = dmesh_server::tagged::decode(packet)?;
    let id = record.id?;
    let (component, method) = if let Some(request) = control::decode_record(record) {
        (control::CONTROL_COMPONENT, control_method(request))
    } else if let Some(request) = connection::decode_record(record) {
        (connection::CONNECTION_COMPONENT, connection_method(request))
    } else {
        return None;
    };
    dmesh_server::tagged::encode_numeric_error(component, method, id, error.as_bytes(), out)
}

/// Decoded-record counterpart used by the UDP6 tagged handler. Rejections keep
/// the request id instead of becoming an uncorrelated diagnostic string.
pub fn encode_control_error_decoded(
    record: dmesh_server::tagged::Record<'_>,
    error: ProfileControlError,
    out: &mut [u8],
) -> Option<usize> {
    let id = record.id?;
    let (component, method) = if let Some(request) = control::decode_record(record) {
        (control::CONTROL_COMPONENT, control_method(request))
    } else if let Some(request) = connection::decode_record(record) {
        (connection::CONNECTION_COMPONENT, connection_method(request))
    } else {
        return None;
    };
    dmesh_server::tagged::encode_numeric_error(component, method, id, error.as_bytes(), out)
}

fn control_method(request: control::Request<'_>) -> u64 {
    match request {
        control::Request::SettingsGet { .. } => control::SETTINGS_GET,
        control::Request::SettingsSet { .. } => control::SETTINGS_SET,
        control::Request::SettingsList => control::SETTINGS_LIST,
        control::Request::TransportSet { .. } => control::TRANSPORT_SET,
    }
}

fn connection_method(request: connection::Request) -> u64 {
    match request {
        connection::Request::Configure(_) => connection::CONNECTION_CONFIGURE,
    }
}

impl ProfileControlError {
    fn as_bytes(self) -> &'static [u8] {
        match self {
            Self::Unsupported => b"unsupported",
            Self::InvalidSetting => b"invalid_setting",
            Self::Settings => b"settings",
        }
    }
}

#[cfg(test)]
mod command_tests {
    use super::{apply_control_record, apply_control_record_result, ControlApplyResult};
    use crate::{state::direct_record_generation_changed_from, TransportProfile};

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
        params.sta_passphrase[..8].copy_from_slice(b"test-psk");
        params.sta_passphrase_len = 8;
        // {1: control, 2: transport.start, 5: {1: sta}}
        let start_sta = [0xa3, 1, 1, 2, 4, 5, 0xa1, 1, 1];
        assert_eq!(apply_control_record(&start_sta, &mut params), Some(true));
        assert_eq!(
            params.requested_transport,
            Some(dmesh_server::control::TransportKind::Sta)
        );
        assert_eq!(params.ack_frequency, 0);
        assert_eq!(
            &params.sta_passphrase[..params.sta_passphrase_len],
            b"test-psk"
        );

        assert_eq!(params.requested_transport, None);
    }

    #[test]
    fn repeated_nan_transport_set_is_an_idempotent_profile_declaration() {
        // {1: control, 2: transport.start, 5: {1: nan, 14: DW1}}
        // This is the same bounded CBOR payload that can arrive in more than
        // one active NAN Publish/Subscribe discovery window.
        let start_nan = [0xa3, 1, 1, 2, 4, 5, 0xa2, 1, 6, 14, 1];
        let mut params = TransportProfile::new();
        assert_eq!(
            apply_control_record_result(&start_nan, &mut params),
            Some(Ok(ControlApplyResult {
                transport_set: true,
                changed: true,
            }))
        );
        let committed = params;
        assert_eq!(
            apply_control_record_result(&start_nan, &mut params),
            Some(Ok(ControlApplyResult {
                transport_set: true,
                changed: false,
            }))
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
            Some(Ok(ControlApplyResult {
                transport_set: true,
                changed: true,
            }))
        );
        let committed = params;
        assert_eq!(
            apply_control_record_result(&start_sta, &mut params),
            Some(Ok(ControlApplyResult {
                transport_set: true,
                changed: false,
            }))
        );
        assert_eq!(params, committed);
    }
}
