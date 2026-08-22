//! Privileged control-plane A-to-B probe contract.
//!
//! A probe is executed by a host or Android control plane using existing
//! signed low-level control and data requests. It is intentionally **not** a
//! firmware handler: ESP endpoints only receive their normal `transport.start`
//! and bearer commands. Keeping the plan and its result here gives host and
//! Android one versioned record without coupling it to UART, UDP6, NAN, or
//! ESP-NOW framing.

/// One endpoint's complete requested radio personality.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "std", derive(serde::Deserialize, serde::Serialize))]
pub struct ProbeMode {
    /// `1=STA` (associated) and `6=NAN` (unassociated), matching
    /// `control::TransportKind` wire values.
    pub transport_kind: u8,
    /// `now=0/1` enables NOW; `2` explicitly disables it.
    pub now: u8,
    /// NAN discovery-window interval: 0 off, 1 every DW, 8 every 4 seconds,
    /// and 16 every 8 seconds.
    pub nan_dw_interval: u8,
    /// Start a colocated AP while this mode is active.
    pub ap: bool,
}

impl ProbeMode {
    pub const STA_NAN_NOW: Self = Self {
        transport_kind: 1,
        now: 0,
        nan_dw_interval: 1,
        ap: false,
    };
    pub const NAN_NOW: Self = Self {
        transport_kind: 6,
        now: 0,
        nan_dw_interval: 1,
        ap: false,
    };
}

/// The endpoint implementation selected by the control plane.
///
/// The same probe can put an ESP in a radio mode, have an Android controller
/// attach to an AP through the platform API, or use a privileged Host radio.
/// ESP never implements the probe handler itself; it only receives normal
/// low-level transport commands.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "std", derive(serde::Deserialize, serde::Serialize))]
pub enum ProbeEndpointKind {
    Host = 1,
    Android = 2,
    Esp = 3,
}

/// A controller-resolved endpoint. `node` is the stable radio/device identity
/// used by the control plane; `bssid` is supplied only for a directed STA
/// association measurement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "std", derive(serde::Deserialize, serde::Serialize))]
pub struct ProbeEndpoint {
    pub kind: ProbeEndpointKind,
    pub node: [u8; 6],
    pub mode: ProbeMode,
    pub bssid: Option<[u8; 6]>,
}

/// A signed-control-plane request to configure endpoint A and B, then measure
/// whether either can safely serve as a mesh-chain forwarder. `udp6=false` is
/// normal for unassociated NAN+NOW-only endpoints; `now=false` is normal for
/// Android endpoints.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "std", derive(serde::Deserialize, serde::Serialize))]
pub struct ProbeRequest {
    pub request_id: u64,
    pub source: ProbeEndpoint,
    pub target: ProbeEndpoint,
    pub test_nan: bool,
    pub test_now: bool,
    pub test_udp6: bool,
    /// Run a small loss/latency exchange before sustained transfer.
    pub short_bytes: u32,
    /// Requested sustained transfer size. `0` disables the long row.
    pub long_bytes: u32,
    /// Include complete mode replacement and directed-BSSID association timing.
    pub measure_mode_switch: bool,
}

/// One bearer measurement. Unknown quantities are omitted, never represented
/// as zero, so Host, Android, and ESP diagnostics retain one schema.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "std", derive(serde::Deserialize, serde::Serialize))]
pub struct ProbeMeasurement {
    pub attempted: bool,
    pub succeeded: bool,
    pub tx_packets: Option<u32>,
    pub rx_packets: Option<u32>,
    pub lost_packets: Option<u32>,
    pub latency_us: Option<u64>,
    pub bytes: Option<u64>,
    pub elapsed_us: Option<u64>,
    pub rssi_dbm: Option<i8>,
}

/// Timing and result of replacing an endpoint's immutable radio epoch.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "std", derive(serde::Deserialize, serde::Serialize))]
pub struct ProbeModeResult {
    pub attempted: bool,
    pub succeeded: bool,
    pub elapsed_us: Option<u64>,
    pub bssid_connect_us: Option<u64>,
    pub associated: Option<bool>,
    /// Whether the requested colocated open AP actually stayed active.
    /// Android AP+STA availability is device/firmware dependent, so this is a
    /// measured result, not an assumption from the requested `mode.ap` bit.
    pub ap_active: Option<bool>,
    pub rssi_dbm: Option<i8>,
}

/// The controller's complete A-to-B outcome. This lets policy select a
/// forwarder, RF rate/profile, DW cadence, and timeout without reparsing text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "std", derive(serde::Deserialize, serde::Serialize))]
pub struct ProbeResponse {
    pub request_id: u64,
    pub source_mode: ProbeModeResult,
    pub target_mode: ProbeModeResult,
    pub nan: ProbeMeasurement,
    pub now: ProbeMeasurement,
    pub udp6: ProbeMeasurement,
    /// `0=none`, `1=NAN control only`, `2=NOW`, `3=UDP6`.
    pub recommendation: u8,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn android_udp_plan_can_omit_now_and_request_bssid_timing() {
        let request = ProbeRequest {
            request_id: 7,
            source: ProbeEndpoint {
                kind: ProbeEndpointKind::Android,
                node: [1; 6],
                mode: ProbeMode::NAN_NOW,
                bssid: None,
            },
            target: ProbeEndpoint {
                kind: ProbeEndpointKind::Esp,
                node: [2; 6],
                mode: ProbeMode::STA_NAN_NOW,
                bssid: Some([3; 6]),
            },
            test_nan: true,
            test_now: false,
            test_udp6: true,
            short_bytes: 1_100,
            long_bytes: 64 * 1024,
            measure_mode_switch: true,
        };
        assert!(request.test_nan && request.test_udp6 && !request.test_now);
        assert_eq!(request.source.kind, ProbeEndpointKind::Android);
        assert_eq!(request.target.kind, ProbeEndpointKind::Esp);
        assert_eq!(request.target.bssid, Some([3; 6]));
    }
}
