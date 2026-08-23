//! Shared firmware connection/bootstrap profile.
//!
//! This is intentionally a host crate: it describes CBOR-controlled values
//! and has no ESP-IDF, FreeRTOS, NVS, socket, or bearer dependency. Firmware
//! supplies persistence and applies the resulting profile to its radio.

use crate::{
    cbor::Encoder,
    connection,
    control::{self, TransportConfig, TransportKind},
    tagged,
};
use quic_lite::connection::ConnectionPolicy;

/// Stable `lmesh-wifi` event destination until an event handler selects a
/// different endpoint. This is not the raw UDP6 bearer port (3339), and it
/// is not persisted as part of STA association.
pub const DEFAULT_EVENT_PORT: u16 = 3336;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransportProfile {
    pub ssid: [u8; 33],
    pub ssid_len: usize,
    /// Ephemeral WPA2 credential from transport.start; never stored in NVS.
    pub sta_passphrase: [u8; 64],
    pub sta_passphrase_len: usize,
    /// Optional exact AP identity supplied with the transient STA start.
    pub sta_bssid: [u8; 6],
    pub sta_bssid_set: bool,
    /// `0` lets ESP-IDF choose; a nonzero value pins the association scan.
    pub sta_channel: u8,
    /// Default UDP destination for unsolicited events. A handler-owned
    /// connection may select its own destination instead.
    pub event_port: u16,
    pub log_level: u8,
    pub benchmark: bool,
    pub transport_test: bool,
    /// Explicit opt-in for the tested associated STA+NAN+NOW coexistence
    /// personality. It is false by default so STA/UDP6 remains the baseline.
    /// It is not the planned unassociated NAN+NOW boot policy, nor does it
    /// encode NAN SD rendezvous/retry timing.
    pub espnow_capture: bool,
    /// NAN discovery-window interval in 512 ms DWs. Zero is off; one is each
    /// DW; eight and sixteen select the four- and eight-second cadences.
    pub nan_dw_interval: u8,
    /// `now=0` is the default private NOW action path; `now=1` is an explicit
    /// on spelling and `now=2` is the raw-UDP6-only regression baseline. A
    /// future `udp6` setting remains independent.
    pub now: u8,
    /// Requested NAN Data Path policy. ESP adapters currently retain this
    /// common transport-start parameter without implementing NDP; Android
    /// turns it into a Wi-Fi Aware data-path capability for the epoch.
    pub ndp: u8,
    /// `ap=1` enables a local AP alongside the selected STA or NAN mode.
    pub ap: u8,
    /// UART selector: `0` disables it, `1` is 115200 baud, and `2..=7` are
    /// other common speeds. USB packet mode ignores the speed value.
    pub uart: u8,
    pub run_requested: bool,
    pub command_mode: bool,
    /// Requested physical bearer personality. `None` means the shared Wi-Fi
    /// owner must be stopped; it has no QUIC-lite connection semantics.
    pub requested_transport: Option<TransportKind>,
    /// Association policy belongs to a connection, not to a benchmark run.
    pub ack_frequency: u8,
    pub ack_delay_ms: u8,
    /// Maximum raw-bearer packets emitted from one ingress turn. Zero keeps
    /// the transport's C6 default; a nonzero value is an association-scoped
    /// pacing control, not an IPERF request field.
    pub tx_burst_packets: u8,
    pub raw_tx_rate: u8,
    /// Associated-STA egress policy: true submits Ethernet through ESP-IDF's
    /// normal STA data path. Raw 802.11 injection remains a runtime
    /// diagnostic opt-out for A/B investigations.
    pub sta_driver_tx: bool,
    /// Preserve the previously proven raw-receive policy by default, while
    /// allowing a direct runtime A/B with standard STA BSSID filtering.
    pub sta_bssid_check_disabled: bool,
    /// Association-scoped A-MPDU policy. Changing this requires a controlled
    /// Wi-Fi driver reinitialization so ESP-IDF sees it in wifi_init_config_t.
    pub sta_ampdu_enabled: bool,
    /// Pre-start 802.11b rate suppression.  Keep the existing raw UDP6
    /// baseline by default, but make the association policy testable.
    pub sta_11b_rates_disabled: bool,
    /// Raw UDP6 takes ownership of the driver RX buffer only when explicitly
    /// enabled. `false` is the standard ESP-IDF esp-netif/lwIP RX path.
    pub sta_raw_rx_enabled: bool,
    pub path_policy: u8,
    pub timeout_ms: u32,
}

impl TransportProfile {
    pub const fn new() -> Self {
        Self {
            ssid: [0; 33],
            ssid_len: 0,
            sta_passphrase: [0; 64],
            sta_passphrase_len: 0,
            sta_bssid: [0; 6],
            sta_bssid_set: false,
            sta_channel: 0,
            event_port: DEFAULT_EVENT_PORT,
            log_level: 2,
            benchmark: false,
            transport_test: false,
            espnow_capture: false,
            nan_dw_interval: 0,
            now: 0,
            ndp: 0,
            // The out-of-box unassociated radio is AP+NOW on channel 6 for
            // the current NOW/NAN validation lane. An explicit start can
            // replace it with `ap=0` or associated STA later.
            ap: 1,
            uart: 1,
            run_requested: false,
            command_mode: false,
            requested_transport: None,
            ack_frequency: 0,
            ack_delay_ms: 0,
            tx_burst_packets: 0,
            raw_tx_rate: 0,
            sta_driver_tx: true,
            sta_bssid_check_disabled: true,
            sta_ampdu_enabled: true,
            sta_11b_rates_disabled: true,
            sta_raw_rx_enabled: true,
            path_policy: 0,
            timeout_ms: 300_000,
        }
    }

    pub const fn has_flash_profile(&self) -> bool {
        self.ssid_len != 0 || self.sta_bssid_set
    }
}

impl Default for TransportProfile {
    fn default() -> Self {
        Self::new()
    }
}

/// Apply a physical-bearer configuration. Omitted fields leave the active
/// bearer unchanged; persistence is handled through `settings.*`.
pub fn apply_transport_config(config: TransportConfig, profile: &mut TransportProfile) {
    if let Some(value) = config.passphrase {
        profile.sta_passphrase[..value.len()].copy_from_slice(value);
        profile.sta_passphrase_len = value.len();
    }
    if let Some(value) = config.bssid {
        profile.sta_bssid = value;
        profile.sta_bssid_set = true;
    }
    if let Some(value) = config.channel {
        profile.sta_channel = value;
    }
    if let Some(value) = config.espnow_capture {
        profile.espnow_capture = value;
    }
    if let Some(value) = config.nan_dw_interval {
        profile.nan_dw_interval = value;
    }
    if let Some(value) = config.ndp {
        profile.ndp = value;
    }
    if let Some(value) = config.now {
        profile.now = value;
    }
    if let Some(value) = config.ap {
        profile.ap = value;
    }
    if let Some(value) = config.uart {
        profile.uart = value;
    }
    if let Some(value) = config.raw_tx_rate {
        profile.raw_tx_rate = value;
    }
    if let Some(value) = config.sta_driver_tx {
        profile.sta_driver_tx = value;
    }
    if let Some(value) = config.sta_bssid_check_disabled {
        profile.sta_bssid_check_disabled = value;
    }
    if let Some(value) = config.sta_ampdu_enabled {
        profile.sta_ampdu_enabled = value;
    }
    if let Some(value) = config.sta_11b_rates_disabled {
        profile.sta_11b_rates_disabled = value;
    }
    if let Some(value) = config.sta_raw_rx_enabled {
        profile.sta_raw_rx_enabled = value;
    }
}

/// Remove the volatile WPA2 credential before applying a replacement STA
/// epoch. `transport.start` is a complete radio declaration: an omitted
/// passphrase means open authentication, never "reuse the old secret".
///
/// This is portable policy, not an ESP adapter concern, so host-side command
/// tests can verify the credential lifecycle without ESP-IDF.
pub fn clear_sta_passphrase(profile: &mut TransportProfile) {
    profile.sta_passphrase.fill(0);
    profile.sta_passphrase_len = 0;
}

/// Apply bearer-neutral QUIC-lite association policy.  The profile is merely
/// an ESP adapter cache; the request schema itself has no bearer dependency.
pub fn apply_connection_policy(policy: ConnectionPolicy, profile: &mut TransportProfile) {
    if let Some(value) = policy.tx_burst_packets {
        profile.tx_burst_packets = value;
    }
    if let Some(value) = policy.ack_frequency {
        profile.ack_frequency = value;
    }
    if let Some(value) = policy.ack_delay_ms {
        profile.ack_delay_ms = value;
    }
    if let Some(value) = policy.path_policy {
        profile.path_policy = value;
    }
    if let Some(value) = policy.timeout_ms {
        profile.timeout_ms = value;
    }
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
    if let Some(request) = connection::decode_record(record) {
        return tagged::encode_numeric_response(
            connection::CONNECTION_COMPONENT,
            connection_method(request),
            id,
            &[0xa0],
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
        control::Request::TransportStart { .. } => control::TRANSPORT_START,
        control::Request::TransportStop { .. } => control::TRANSPORT_STOP,
    }
}

fn connection_method(request: connection::Request) -> u64 {
    match request {
        connection::Request::Configure(_) => connection::CONNECTION_CONFIGURE,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::TransportConfig;
    use quic_lite::connection::ConnectionPolicy;

    #[test]
    fn event_port_defaults_to_stable_lmesh_wifi() {
        assert_eq!(TransportProfile::new().event_port, DEFAULT_EVENT_PORT);
    }

    #[test]
    fn associated_sta_driver_egress_is_the_default() {
        assert!(TransportProfile::new().sta_driver_tx);
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
        apply_connection_policy(
            ConnectionPolicy {
                tx_burst_packets: Some(1),
                ..ConnectionPolicy::default()
            },
            &mut profile,
        );
        assert_eq!(profile.tx_burst_packets, 1);
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
