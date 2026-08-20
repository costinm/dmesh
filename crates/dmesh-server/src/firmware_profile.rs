//! Shared firmware connection/bootstrap profile.
//!
//! This is intentionally a host crate: it describes CBOR-controlled values
//! and has no ESP-IDF, FreeRTOS, NVS, socket, or bearer dependency. Firmware
//! supplies persistence and applies the resulting profile to its radio.

use crate::{raw_dispatch::{RawDispatchError, dispatch_recovery_command}, recovery::RecoveryCommand};

/// Stable `lmesh-wifi` event destination until an event handler selects a
/// different endpoint. This is not the raw UDP6 bearer port (3339), and it
/// is not persisted as part of STA association.
pub const DEFAULT_EVENT_PORT: u16 = 3336;

#[derive(Clone, Copy)]
pub struct TransportProfile {
    pub ssid: [u8; 33],
    pub ssid_len: usize,
    /// Default UDP destination for unsolicited events. A handler-owned
    /// connection may select its own destination instead.
    pub event_port: u16,
    pub log_level: u8,
    pub benchmark: bool,
    pub transport_test: bool,
    pub espnow_capture: bool,
    pub run_requested: bool,
    pub command_mode: bool,
    /// Association policy belongs to a connection, not to a benchmark run.
    pub ack_frequency: u8,
    pub ack_delay_ms: u8,
    /// Maximum raw-bearer packets emitted from one ingress turn. Zero keeps
    /// the transport's C6 default; a nonzero value is an association-scoped
    /// pacing control, not an IPERF request field.
    pub tx_burst_packets: u8,
    pub raw_tx_rate: u8,
    /// Runtime STA egress experiment: false is raw 802.11 injection, true
    /// asks ESP-IDF to submit Ethernet to the associated STA data path.
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
            ssid: [0; 33], ssid_len: 0, event_port: DEFAULT_EVENT_PORT, log_level: 2,
            benchmark: false, transport_test: false, espnow_capture: false,
            run_requested: false, command_mode: false, ack_frequency: 0,
            ack_delay_ms: 0, tx_burst_packets: 0, raw_tx_rate: 0, sta_driver_tx: false,
            sta_bssid_check_disabled: true, sta_ampdu_enabled: true,
            sta_11b_rates_disabled: true, sta_raw_rx_enabled: true, path_policy: 0,
            timeout_ms: 300_000,
        }
    }

    pub const fn has_flash_profile(&self) -> bool {
        self.ssid_len != 0
    }
}

impl Default for TransportProfile { fn default() -> Self { Self::new() } }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApplyResult { pub profile_updated: bool, pub request_main_handoff: bool }

pub fn apply_recovery_packet(packet: &[u8], profile: &mut TransportProfile) -> Option<ApplyResult> {
    let mut result = None;
    dispatch_recovery_command(packet, |command| {
        result = apply_recovery_command(command, profile);
        result.map_or(Err(RawDispatchError::Rejected), |_| Ok(()))
    }).ok()?;
    result
}

pub fn apply_recovery_command(command: RecoveryCommand<'_>, profile: &mut TransportProfile) -> Option<ApplyResult> {
    // Direct UART commands are live patches.  In particular, toggling one
    // diagnostic must not silently turn off NAN/NOW or reset the current
    // association controls merely because those fields were omitted.
    if let Some(value) = command.benchmark { profile.benchmark = value; }
    if let Some(value) = command.transport_test { profile.transport_test = value; }
    if let Some(value) = command.espnow_capture { profile.espnow_capture = value; }
    // The IPERF byte/count fields are service requests carried on the active
    // association. `burst`, however, is also the operator-facing raw bearer
    // pacing control and must survive the controlled reassociation that
    // applies it.
    if let Some(value) = command.iperf_burst_packets { profile.tx_burst_packets = value; }
    if let Some(value) = command.ack_frequency { profile.ack_frequency = value; }
    if let Some(value) = command.ack_delay_ms { profile.ack_delay_ms = value; }
    if let Some(value) = command.raw_tx_rate { profile.raw_tx_rate = value; }
    if let Some(value) = command.sta_driver_tx { profile.sta_driver_tx = value; }
    if let Some(value) = command.sta_bssid_check_disabled {
        profile.sta_bssid_check_disabled = value;
    }
    if let Some(value) = command.sta_ampdu_enabled { profile.sta_ampdu_enabled = value; }
    if let Some(value) = command.sta_11b_rates_disabled {
        profile.sta_11b_rates_disabled = value;
    }
    if let Some(value) = command.sta_raw_rx_enabled { profile.sta_raw_rx_enabled = value; }
    if let Some(value) = command.path_policy { profile.path_policy = value; }
    if let Some(value) = command.timeout_ms { profile.timeout_ms = value; }
    profile.run_requested = false;
    copy(command.ssid, &mut profile.ssid, &mut profile.ssid_len)?;
    if let Some(value) = command.log_level { profile.log_level = value; }
    profile.run_requested = true;
    Some(ApplyResult {
        profile_updated: command.profile_updated && profile.has_flash_profile(),
        request_main_handoff: command.operation.is_none_or(|op| op != b"main" && op != b"reboot_main"),
    })
}

fn copy(value: Option<&[u8]>, destination: &mut [u8], length: &mut usize) -> Option<()> {
    let Some(value) = value else { return Some(()); };
    if value.len() > destination.len() { return None; }
    destination[..value.len()].copy_from_slice(value);
    *length = value.len();
    Some(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn benchmark_fields_do_not_become_device_profile_state() {
        let packet = [0xa2, 0x00, 0x18, 0x44, 0x06, 0xa1, 0x18, 0xf2, 0x18, 0x40];
        let mut profile = TransportProfile::new();
        assert_eq!(apply_recovery_packet(&packet, &mut profile).unwrap().request_main_handoff, true);
        assert_eq!(profile.ack_frequency, 0);
    }

    #[test]
    fn event_port_defaults_to_stable_lmesh_wifi() {
        assert_eq!(TransportProfile::new().event_port, DEFAULT_EVENT_PORT);
    }

    #[test]
    fn runtime_sta_egress_path_is_applied_not_persisted() {
        let packet = [
            0xa2, 0x00, 0x18, 0x44, 0x06, 0xa1, 0x6d, b's', b't', b'a', b'_', b'd',
            b'r', b'i', b'v', b'e', b'r', b'_', b't', b'x', 0xf5,
        ];
        let mut profile = TransportProfile::new();
        let result = apply_recovery_packet(&packet, &mut profile).unwrap();
        assert!(profile.sta_driver_tx);
        assert!(!result.profile_updated);
    }

    #[test]
    fn direct_runtime_patch_preserves_unmentioned_radio_controls() {
        let packet = [
            0xa2, 0x00, 0x18, 0x44, 0x06, 0xa1, 0x6d, b's', b't', b'a', b'_', b'd',
            b'r', b'i', b'v', b'e', b'r', b'_', b't', b'x', 0xf5,
        ];
        let mut profile = TransportProfile::new();
        profile.espnow_capture = true;
        profile.raw_tx_rate = 24;
        profile.ack_frequency = 8;
        apply_recovery_packet(&packet, &mut profile).unwrap();
        assert!(profile.sta_driver_tx);
        assert!(profile.espnow_capture);
        assert_eq!(profile.raw_tx_rate, 24);
        assert_eq!(profile.ack_frequency, 8);
    }

    #[test]
    fn direct_runtime_patch_applies_sta_bssid_filter_control() {
        let packet = [
            0xa2, 0x00, 0x18, 0x44, 0x06, 0xa1, 0x74, b'b', b's', b's', b'i', b'd', b'_',
            b'c', b'h', b'e', b'c', b'k', b'_', b'd', b'i', b's', b'a', b'b', b'l', b'e',
            b'd', 0xf4,
        ];
        let mut profile = TransportProfile::new();
        assert!(profile.sta_bssid_check_disabled);
        apply_recovery_packet(&packet, &mut profile).unwrap();
        assert!(!profile.sta_bssid_check_disabled);
    }

    #[test]
    fn direct_runtime_patch_applies_sta_ampdu_control() {
        let packet = [
            0xa2, 0x00, 0x18, 0x44, 0x06, 0xa1, 0x65, b'a', b'm', b'p', b'd', b'u', 0xf4,
        ];
        let mut profile = TransportProfile::new();
        assert!(profile.sta_ampdu_enabled);
        apply_recovery_packet(&packet, &mut profile).unwrap();
        assert!(!profile.sta_ampdu_enabled);
    }

    #[test]
    fn direct_runtime_patch_applies_sta_11b_rate_policy() {
        let packet = [
            0xa2, 0x00, 0x18, 0x44, 0x06, 0xa1, 0x6b, b'd', b'i', b's', b'a', b'b', b'l',
            b'e', b'_', b'1', b'1', b'b', 0xf4,
        ];
        let mut profile = TransportProfile::new();
        assert!(profile.sta_11b_rates_disabled);
        apply_recovery_packet(&packet, &mut profile).unwrap();
        assert!(!profile.sta_11b_rates_disabled);
    }

    #[test]
    fn direct_runtime_patch_applies_sta_raw_rx_owner() {
        let packet = [
            0xa2, 0x00, 0x18, 0x44, 0x06, 0xa1, 0x66, b'r', b'a', b'w', b'_', b'r', b'x',
            0xf4,
        ];
        let mut profile = TransportProfile::new();
        assert!(profile.sta_raw_rx_enabled);
        apply_recovery_packet(&packet, &mut profile).unwrap();
        assert!(!profile.sta_raw_rx_enabled);
    }

    #[test]
    fn direct_runtime_patch_applies_raw_burst_pacing() {
        // {0: 68, 6: {"burst": 1}}
        let packet = [
            0xa2, 0x00, 0x18, 0x44, 0x06, 0xa1, 0x65, b'b', b'u', b'r', b's', b't', 0x01,
        ];
        let mut profile = TransportProfile::new();
        apply_recovery_packet(&packet, &mut profile).unwrap();
        assert_eq!(profile.tx_burst_packets, 1);
    }
}
