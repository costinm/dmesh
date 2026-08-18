// IMPORTANT: This crate is for firmware/platform-only glue. If code can be
// host-tested or reused without ESP/FreeRTOS ownership, it probably belongs
// in `quic-lite` (QUIC-lite transport mechanics) or `dmesh-server` (shared
// service/protocol behavior), not here.

//! Apply the common Recovery/Main control schema without bearer or reboot I/O.

use crate::TransportProfile;
use dmesh_server::recovery::{decode_recovery_command, RecoveryCommand};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApplyResult {
    /// The caller must persist the profile through its own NVS adapter.
    pub profile_updated: bool,
    /// Recovery interprets this as its sole post-successful-Main-flash handoff.
    /// Main must not reboot merely because it accepted a flash command.
    pub request_main_handoff: bool,
}

pub fn apply_recovery_packet(packet: &[u8], profile: &mut TransportProfile) -> Option<ApplyResult> {
    apply_recovery_command(decode_recovery_command(packet)?, profile)
}

pub fn apply_recovery_command(
    command: RecoveryCommand<'_>,
    profile: &mut TransportProfile,
) -> Option<ApplyResult> {
    profile.benchmark = command.benchmark.unwrap_or(false);
    profile.transport_test = command.transport_test.unwrap_or(false);
    profile.iperf_packet_size = command
        .iperf_packet_size
        .unwrap_or(quic_lite::DEFAULT_MAX_STREAM_PAYLOAD as u16);
    profile.iperf_bytes = command.iperf_bytes.unwrap_or(2 * 1024 * 1024);
    profile.iperf_parallel_streams = command.iperf_parallel_streams.unwrap_or(1);
    profile.iperf_high_priority_bytes = command.iperf_high_priority_bytes.unwrap_or(0);
    profile.iperf_low_priority_bytes = command.iperf_low_priority_bytes.unwrap_or(0);
    profile.iperf_validation = command.iperf_validation.unwrap_or(2);
    profile.iperf_pace_us = command.iperf_pace_us.unwrap_or(0);
    profile.iperf_burst_packets = command.iperf_burst_packets.unwrap_or(0);
    profile.iperf_burst_delay_us = command.iperf_burst_delay_us.unwrap_or(0);
    profile.iperf_window_packets = command.iperf_window_packets.unwrap_or(0);
    profile.benchmark_run_id = command.benchmark_run_id.unwrap_or(0);
    profile.ack_frequency = command.ack_frequency.unwrap_or(0);
    profile.ack_delay_ms = command.ack_delay_ms.unwrap_or(0);
    profile.raw_tx_rate = command.raw_tx_rate.unwrap_or(0);
    profile.path_policy = command.path_policy.unwrap_or(0);
    profile.timeout_ms = command.timeout_ms.unwrap_or(300_000);
    profile.run_requested = false;
    copy(command.ssid, &mut profile.ssid, &mut profile.ssid_len)?;
    copy(command.server, &mut profile.server, &mut profile.server_len)?;
    copy(
        command.local_ip,
        &mut profile.local_ip,
        &mut profile.local_ip_len,
    )?;
    copy(
        command.gateway,
        &mut profile.gateway,
        &mut profile.gateway_len,
    )?;
    copy(command.mask, &mut profile.mask, &mut profile.mask_len)?;
    if let Some(value) = command.port {
        profile.port = value;
    }
    if let Some(value) = command.log_level {
        profile.log_level = value;
    }
    profile.run_requested = true;
    Some(ApplyResult {
        profile_updated: command.profile_updated && profile.has_flash_profile(),
        request_main_handoff: command
            .operation
            .is_none_or(|op| op != b"main" && op != b"reboot_main"),
    })
}

fn copy(value: Option<&[u8]>, destination: &mut [u8], length: &mut usize) -> Option<()> {
    let Some(value) = value else {
        return Some(());
    };
    if value.len() > destination.len() {
        return None;
    }
    destination[..value.len()].copy_from_slice(value);
    *length = value.len();
    Some(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_defaults_are_shared_without_reboot_side_effects() {
        let packet = [0xa2, 0x00, 0x18, 0x44, 0x06, 0xa1, 0x18, 0xf2, 0x18, 0x40];
        let mut profile = TransportProfile::new();
        let result = apply_recovery_packet(&packet, &mut profile).unwrap();
        assert!(result.request_main_handoff);
        assert_eq!(
            profile.iperf_window_packets,
            quic_lite::RECOVERY_MAX_DIAGNOSTIC_IN_FLIGHT_PACKETS as u8
        );
    }
}
