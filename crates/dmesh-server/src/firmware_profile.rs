//! Shared firmware connection/bootstrap profile.
//!
//! This is intentionally a host crate: it describes CBOR-controlled values
//! and has no ESP-IDF, FreeRTOS, NVS, socket, or bearer dependency. Firmware
//! supplies persistence and applies the resulting profile to its radio.

use crate::{
    cbor::Encoder,
    control::{self, TransportConfig, TransportKind},
    tagged,
};

/// Stable `lmesh-wifi` event destination until an event handler selects a
/// different endpoint. This is not the raw UDP6 bearer port (3339), and it
/// is not persisted as part of STA association.
pub const DEFAULT_EVENT_PORT: u16 = 3336;

/// Association and radio-role changes do not invalidate a Wi-Fi driver.
pub fn wifi_driver_policy_changed(initialized: bool, ampdu: bool, rates_11b_disabled: bool, desired_ampdu: bool, desired_rates_11b_disabled: bool) -> bool {
    initialized && (ampdu != desired_ampdu || rates_11b_disabled != desired_rates_11b_disabled)
}

/// A target-only wake is a lease renewal once STA is selected, including
/// while association is in progress. Requests carrying settings remain edits.
pub fn targeted_wake_renews_sta(profile: &TransportProfile, config: TransportConfig<'_>) -> bool {
    config.wake_target.is_some()
        && config == (TransportConfig { wake_target: config.wake_target, iface: config.iface, ..TransportConfig::default() })
        && profile.requested_transport == Some(TransportKind::Sta)
}

#[cfg(test)]
mod driver_policy_tests {
    use super::*;
    #[test]
    fn unchanged_policy_preserves_driver() {
        for ampdu in [false, true] {
            for rates in [false, true] {
                assert!(!wifi_driver_policy_changed(true, ampdu, rates, ampdu, rates));
                assert!(wifi_driver_policy_changed(true, ampdu, rates, !ampdu, rates));
                assert!(wifi_driver_policy_changed(true, ampdu, rates, ampdu, !rates));
                assert!(!wifi_driver_policy_changed(false, ampdu, rates, !ampdu, !rates));
            }
        }
    }
    #[test]
    fn repeated_wake_is_a_lease_renewal_not_a_new_radio_epoch() {
        let mut profile = TransportProfile::default();
        let config = TransportConfig { wake_target: Some([1; 6]), ..Default::default() };
        profile.requested_transport = Some(TransportKind::Nan);
        assert!(!targeted_wake_renews_sta(&profile, config));
        profile.requested_transport = Some(TransportKind::Sta);
        for run_requested in [false, true] {
            profile.run_requested = run_requested;
            assert!(targeted_wake_renews_sta(&profile, config));
        }
        assert!(!targeted_wake_renews_sta(&profile, TransportConfig { channel: Some(7), ..config }));
        assert!(!targeted_wake_renews_sta(&profile, TransportConfig::default()));
    }
}

pub use crate::transport_profile::{UART_DEFAULT, UART_115200, UART_OFF, UART_921600, normalize_uart_selector};
pub use crate::transport_profile::parse_uart_baud;

/// DMesh protocol and diagnostic controls, kept outside the host bearer store.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DmeshPolicy {
    pub event_port: u16,
    pub log_level: u8,
    pub benchmark: bool,
    pub transport_test: bool,
    pub command_mode: bool,
    pub ack_frequency: u8,
    pub ack_delay_ms: u8,
    pub tx_burst_packets: u8,
    pub path_policy: u8,
    pub timeout_ms: u32,
 }
impl DmeshPolicy { pub const fn new() -> Self { Self {
            event_port: DEFAULT_EVENT_PORT,
            log_level: 2,
            benchmark: false,
            transport_test: false,
            command_mode: false,
            ack_frequency: 0,
            ack_delay_ms: 0,
            tx_burst_packets: 0,
            path_policy: 0,
            timeout_ms: 300_000,
 } } }
/// DMesh view of the shared transport profile used across firmware, Android
/// and host. `bearers` is `transport_profile::TransportProfile`: the transport
/// structure and tagged-CBOR representation (`docs/transport-cbor.md`).
/// Android/host also use `control::TransportConfig` and the generated
/// `platform_api::TransportSetRequest`. Keep their field meanings, tags,
/// defaults and encodings in sync with that schema.
/// The additional fields below hold DMesh application policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransportProfile {
    pub bearers: crate::transport_profile::TransportProfile,
    pub event_port: u16,
    pub log_level: u8,
    pub benchmark: bool,
    pub transport_test: bool,
    pub command_mode: bool,
    pub ack_frequency: u8,
    pub ack_delay_ms: u8,
    pub tx_burst_packets: u8,
    pub path_policy: u8,
    pub timeout_ms: u32,
 }
impl TransportProfile {
    pub const fn new() -> Self { Self { bearers: crate::transport_profile::TransportProfile::new(),
            event_port: DEFAULT_EVENT_PORT,
            log_level: 2,
            benchmark: false,
            transport_test: false,
            command_mode: false,
            ack_frequency: 0,
            ack_delay_ms: 0,
            tx_burst_packets: 0,
            path_policy: 0,
            timeout_ms: 300_000,
 } }
    pub fn with_policy(bearers: crate::transport_profile::TransportProfile, policy: DmeshPolicy) -> Self {
        Self { bearers,
            event_port: policy.event_port,
            log_level: policy.log_level,
            benchmark: policy.benchmark,
            transport_test: policy.transport_test,
            command_mode: policy.command_mode,
            ack_frequency: policy.ack_frequency,
            ack_delay_ms: policy.ack_delay_ms,
            tx_burst_packets: policy.tx_burst_packets,
            path_policy: policy.path_policy,
            timeout_ms: policy.timeout_ms,
 }
    }
    pub fn policy(&self) -> DmeshPolicy { DmeshPolicy {
            event_port: self.event_port,
            log_level: self.log_level,
            benchmark: self.benchmark,
            transport_test: self.transport_test,
            command_mode: self.command_mode,
            ack_frequency: self.ack_frequency,
            ack_delay_ms: self.ack_delay_ms,
            tx_burst_packets: self.tx_burst_packets,
            path_policy: self.path_policy,
            timeout_ms: self.timeout_ms,
 } }
}
impl Default for TransportProfile { fn default() -> Self { Self::new() } }
impl core::ops::Deref for TransportProfile {
    type Target = crate::transport_profile::TransportProfile;
    fn deref(&self) -> &Self::Target { &self.bearers }
}
impl core::ops::DerefMut for TransportProfile {
    fn deref_mut(&mut self) -> &mut Self::Target { &mut self.bearers }
}

/// Apply a physical-bearer configuration. Omitted fields leave the active
/// bearer unchanged; persistence is handled through `settings.*`.
pub fn apply_transport_config(config: TransportConfig, profile: &mut TransportProfile) {
    let _ = crate::transport_profile::apply_config(config, &mut profile.bearers);
}

/// Remove the volatile WPA2 credential before applying a replacement STA
/// epoch. `transport.start` is a complete radio declaration: an omitted
/// passphrase selects the fixed DMesh WPA2 key unless the replacement epoch
/// explicitly selected `open=1`; neither spelling retains a prior secret.
///
/// This is portable policy, not an ESP adapter concern, so host-side command
/// tests can verify the credential lifecycle without ESP-IDF.
pub fn clear_sta_passphrase(profile: &mut TransportProfile) {
    profile.sta_passphrase.fill(0);
    profile.sta_passphrase_len = 0;
}

/// Validate the bounded, transient STA SSID carried by `transport.start`.
/// The ESP adapter consumes it as a C string and 802.11 SSIDs are at most 32
/// octets, so embedded NUL is intentionally not a supported control value.
pub fn valid_ssid(value: &[u8]) -> bool {
    !value.is_empty() && value.len() <= 32 && !value.contains(&0)
}

/// Apply a validated volatile SSID value. `transport.start` is the sole
/// source; the profile must never parse a command itself or persist it.
pub fn set_ssid(value: &[u8], profile: &mut TransportProfile) -> bool {
    if !valid_ssid(value) {
        return false;
    }
    profile.ssid[..value.len()].copy_from_slice(value);
    profile.ssid_len = value.len();
    true
}

/// Build a correlated tagged response from an accepted shared profile request.
/// ESP adapters only send these bytes; the profile/result encoding remains
/// portable and host-testable. No request id means fire-and-forget bootstrap.
pub fn encode_profile_control_response(
    packet: &[u8],
    profile: &TransportProfile,
    out: &mut [u8],
) -> Option<usize> {
    let record = tagged::decode(packet)?;
    let id = record.id?;
    if let Some(request) = control::decode_record(record) {
        let mut result = [0u8; 80];
        let mut encoder = Encoder::new(&mut result);
        let _ = profile;
        let _ = request;
        encoder.map(0)?;
        let used = encoder.len();
        drop(encoder);
        return tagged::encode_numeric_response(
            control::CONTROL_COMPONENT,
            control_method(request),
            id,
            &result[..used],
            out,
        );
    }
    None
}

fn control_method(request: control::Request<'_>) -> u64 {
    match request {
        control::Request::SettingsGet { .. } => control::SETTINGS_GET,
        control::Request::SettingsSet { .. } => control::SETTINGS_SET,
        control::Request::SettingsList => control::SETTINGS_LIST,
        control::Request::TransportSet { .. } => control::TRANSPORT_SET,
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn persistent_uart_rates_reject_unsupported_or_malformed_values() {
        for (text, rate) in [(b"115200".as_slice(), 115200), (b"230400", 230400),
            (b"460800", 460800), (b"921600", 921600)] {
            assert_eq!(super::parse_uart_baud(text), Some(rate));
        }
        for text in [b"0".as_slice(), b"128000", b"115200\0", b"", b"-1"] {
            assert_eq!(super::parse_uart_baud(text), None);
        }
    }
    #[test]
    fn nan_only_sleep_policy_ignores_stored_credentials_and_uart() {
        let mut profile = super::TransportProfile::new();
        profile.requested_transport = Some(super::TransportKind::Nan);
        profile.now = 2;
        profile.ap = 0;
        profile.ssid_len = 4;
        profile.ssid[..4].copy_from_slice(b"test");
        profile.uart = super::UART_115200;
        assert!(profile.is_nan_only());
        // The default NOW spelling is active, not an off/sleepy value.
        // NAN discovery windows may coexist with it but must not turn the
        // shared Wi-Fi driver into modem power-save between those windows.
        profile.now = 0;
        assert!(!profile.is_nan_only());
        profile.now = 1;
        assert!(!profile.is_nan_only());
        profile.now = 2;
        profile.ap = 1;
        assert!(!profile.is_nan_only());
        profile.ap = 0;
        profile.requested_transport = Some(super::TransportKind::Sta);
        assert!(!profile.is_nan_only());
    }
    use super::*;
    use crate::control::TransportConfig;

    #[test]
    fn event_port_defaults_to_stable_lmesh_wifi() {
        assert_eq!(TransportProfile::new().event_port, DEFAULT_EVENT_PORT);
    }

    #[test]
    fn associated_sta_driver_egress_is_the_default() {
        assert!(TransportProfile::new().sta_driver_tx);
    }

    #[test]
    fn open_requires_an_explicit_transport_set_field() {
        let mut profile = TransportProfile::new();
        assert!(!profile.open, "WPA2 is the safe boot default");

        apply_transport_config(
            TransportConfig {
                open: Some(true),
                ..TransportConfig::default()
            },
            &mut profile,
        );
        assert!(profile.open);

        apply_transport_config(
            TransportConfig {
                open: Some(false),
                ..TransportConfig::default()
            },
            &mut profile,
        );
        assert!(!profile.open);
    }

    #[test]
    fn uart_zero_selects_the_default_and_eight_is_explicit_off() {
        let mut profile = TransportProfile::new();
        apply_transport_config(
            TransportConfig {
                uart: Some(UART_DEFAULT),
                ..TransportConfig::default()
            },
            &mut profile,
        );
        assert_eq!(profile.uart, UART_115200);

        apply_transport_config(
            TransportConfig {
                uart: Some(UART_OFF),
                ..TransportConfig::default()
            },
            &mut profile,
        );
        assert_eq!(profile.uart, UART_OFF);
        assert_eq!(normalize_uart_selector(UART_921600), Some(UART_921600));
        apply_transport_config(TransportConfig { uart: Some(UART_921600), ..Default::default() }, &mut profile);
        assert_eq!(profile.uart, UART_921600);
        assert_eq!(normalize_uart_selector(10), None);
    }

    #[test]
    fn canonical_transport_patch_preserves_unmentioned_controls() {
        let mut profile = TransportProfile::new();
        profile.espnow_capture = true;
        profile.raw_tx_rate = 24;
        profile.ack_frequency = 8;
        apply_transport_config(
            TransportConfig {
                sta_driver_tx: Some(true),
                ndp: Some(1),
                ..TransportConfig::default()
            },
            &mut profile,
        );
        assert!(profile.sta_driver_tx);
        assert_eq!(profile.ndp, 1);
        assert!(profile.espnow_capture);
        assert_eq!(profile.raw_tx_rate, 24);
        assert_eq!(profile.ack_frequency, 8);
    }

    #[test]
    fn replacement_sta_epoch_clears_the_volatile_wpa_credential() {
        let mut profile = TransportProfile::new();
        apply_transport_config(
            TransportConfig {
                passphrase: Some(b"correct-horse-battery-staple"),
                ..TransportConfig::default()
            },
            &mut profile,
        );
        assert_eq!(profile.sta_passphrase_len, 28);
        clear_sta_passphrase(&mut profile);
        assert_eq!(profile.sta_passphrase_len, 0);
        assert!(profile.sta_passphrase.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn ssid_is_bounded_and_has_no_command_decoder() {
        let mut profile = TransportProfile::new();
        assert!(set_ssid(b"DIRECT-test", &mut profile));
        assert_eq!(&profile.ssid[..profile.ssid_len], b"DIRECT-test");
        assert!(!set_ssid(&[0; 33], &mut profile));
        assert!(!set_ssid(b"bad\0ssid", &mut profile));
    }
}
