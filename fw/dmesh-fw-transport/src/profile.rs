// IMPORTANT: This crate is for firmware/platform-only glue. If code can be
// host-tested or reused without ESP/FreeRTOS ownership, it probably belongs
// in `quic-lite` (QUIC-lite transport mechanics) or `dmesh-server` (shared
// service/protocol behavior), not here.

//! Shared firmware-side transport profile.
//!
//! This type has no NVS, socket, task, or reboot dependency.  Recovery and
//! Main use the same byte layout and command defaults; each platform binary
//! decides how the profile is loaded and persisted.  In particular, a flash
//! target never implies a reboot here.

#[derive(Clone, Copy)]
pub struct TransportProfile {
    pub ssid: [u8; 33],
    pub ssid_len: usize,
    pub server: [u8; 64],
    pub server_len: usize,
    pub local_ip: [u8; 64],
    pub local_ip_len: usize,
    pub gateway: [u8; 64],
    pub gateway_len: usize,
    pub mask: [u8; 64],
    pub mask_len: usize,
    pub port: u16,
    pub log_level: u8,
    /// Command-scoped fields are never loaded from persistent storage.
    pub benchmark: bool,
    pub transport_test: bool,
    pub iperf_packet_size: u16,
    pub iperf_bytes: u32,
    pub iperf_parallel_streams: u8,
    pub iperf_high_priority_bytes: u32,
    pub iperf_low_priority_bytes: u32,
    pub iperf_validation: u8,
    pub iperf_pace_us: u32,
    pub iperf_burst_packets: u8,
    pub iperf_burst_delay_us: u32,
    pub iperf_window_packets: u8,
    pub benchmark_run_id: u32,
    pub run_requested: bool,
    pub command_mode: bool,
    pub ack_frequency: u8,
    pub ack_delay_ms: u8,
    /// 0 dynamic, 1 UDP, 2 UART, 3 UART-first airtime spillover.
    pub path_policy: u8,
    pub timeout_ms: u32,
}

impl TransportProfile {
    pub const fn new() -> Self {
        Self {
            ssid: [0; 33],
            ssid_len: 0,
            server: [0; 64],
            server_len: 0,
            local_ip: [0; 64],
            local_ip_len: 0,
            gateway: [0; 64],
            gateway_len: 0,
            mask: [0; 64],
            mask_len: 0,
            port: 3336,
            log_level: 2,
            benchmark: false,
            transport_test: false,
            iperf_packet_size: quic_lite::DEFAULT_MAX_STREAM_PAYLOAD as u16,
            iperf_bytes: 2 * 1024 * 1024,
            iperf_parallel_streams: 1,
            iperf_high_priority_bytes: 0,
            iperf_low_priority_bytes: 0,
            iperf_validation: 2,
            iperf_pace_us: 0,
            iperf_burst_packets: 0,
            iperf_burst_delay_us: 0,
            iperf_window_packets: 0,
            benchmark_run_id: 0,
            run_requested: false,
            command_mode: false,
            ack_frequency: 0,
            ack_delay_ms: 0,
            path_policy: 0,
            timeout_ms: 300_000,
        }
    }

    pub const fn has_flash_profile(&self) -> bool {
        self.ssid_len != 0 && self.server_len != 0 && self.local_ip_len != 0 && self.port != 0
    }
}

impl Default for TransportProfile {
    fn default() -> Self {
        Self::new()
    }
}
