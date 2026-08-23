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
    /// Requested NAN Data Path policy for the radio epoch. It maps directly
    /// to `transport.start.ndp`; only Android implements NDP today.
    pub ndp: bool,
    /// Start a colocated AP while this mode is active.
    pub ap: bool,
}

impl ProbeMode {
    pub const STA_NAN_NOW: Self = Self {
        transport_kind: 1,
        now: 0,
        nan_dw_interval: 1,
        ndp: false,
        ap: false,
    };
    pub const NAN_NOW: Self = Self {
        transport_kind: 6,
        now: 0,
        nan_dw_interval: 1,
        ndp: false,
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

/// Capabilities declared by a device descriptor, rather than inferred from a
/// board name.  A control plane may only schedule rows for capabilities held
/// by both endpoints; an unsupported row is absent from the full plan rather
/// than reported as a transport failure.
pub const PROBE_CAP_NAN: u16 = 1 << 0;
pub const PROBE_CAP_NOW: u16 = 1 << 1;
pub const PROBE_CAP_STA: u16 = 1 << 2;
pub const PROBE_CAP_AP: u16 = 1 << 3;
pub const PROBE_CAP_UDP6: u16 = 1 << 4;

/// Stable endpoint identity and radio capabilities supplied to a pair probe.
///
/// This deliberately does not contain a serial path, host interface name, or
/// Android handle.  Those are private adapter details.  The same descriptor
/// can therefore be passed through `lmesh-wifi`, `lmesh`, and Android before
/// the local control-plane adapter resolves its own bearer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "std", derive(serde::Deserialize, serde::Serialize))]
pub struct ProbeDeviceDescriptor {
    pub endpoint: ProbeEndpoint,
    pub capabilities: u16,
}

impl ProbeDeviceDescriptor {
    pub const fn supports(self, capability: u16) -> bool {
        self.capabilities & capability == capability
    }
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
    /// Request an Android-to-Android Wi-Fi Aware data path after discovery.
    /// This is distinct from NAN Service Discovery: it yields an IPv6 link
    /// which can carry the ordinary UDP/IPERF service on supported phones.
    pub test_nan_data: bool,
    pub test_now: bool,
    /// Establish the requested AP/P2P/STA topology, then prove the IPv6
    /// bearer in order: multicast discovery, one-way datagram, QUIC-lite,
    /// and IPERF. This is deliberately distinct from an already-associated
    /// UDP6 throughput check.
    pub test_udp6_association: bool,
    pub test_udp6: bool,
    /// Collect a bounded passive channel-6 AP observation at both endpoints.
    pub test_scan: bool,
    /// Request the platform's ordinary local SoftAP capability where present.
    pub test_soft_ap: bool,
    /// Run a small loss/latency exchange before sustained transfer.
    pub short_bytes: u32,
    /// Requested sustained transfer size. `0` disables the long row.
    pub long_bytes: u32,
    /// Include complete mode replacement and directed-BSSID association timing.
    pub measure_mode_switch: bool,
}

/// One regular control-plane handler input.  `request` says what to measure;
/// the two descriptors say which devices can perform it.  An adapter must
/// configure only these descriptors' endpoints.  It must never change its
/// own host-radio mode as a side effect of executing the pair probe.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "std", derive(serde::Deserialize, serde::Serialize))]
pub struct PairProbeRequest {
    pub request: ProbeRequest,
    pub source: ProbeDeviceDescriptor,
    pub target: ProbeDeviceDescriptor,
}

/// Build the complete ESP pair characterization matrix.
///
/// The control plane calls this once for its main integration operation.  Each
/// returned request is a complete mode replacement for both endpoints, so a
/// failed row cannot inherit state from the preceding row.  Narrow development
/// operations use one of these requests (or a caller-supplied request) rather
/// than growing pair-name-specific test functions.
///
/// Rows are omitted when the descriptors do not jointly support their radio
/// features. NAN remains requested in every scheduled row where it is a
/// shared capability, but an active pair may still run NOW-only rows when the
/// control host cannot form or observe a NAN cluster. Sleepy-policy admission
/// is intentionally an executor decision because it depends on the selected
/// endpoints' current/default mode, not their radio capability bits.
#[cfg(feature = "std")]
pub fn full_pair_probe_requests(
    request_id: u64,
    source: ProbeDeviceDescriptor,
    target: ProbeDeviceDescriptor,
    short_bytes: u32,
    long_bytes: u32,
) -> Vec<PairProbeRequest> {
    let common = source.capabilities & target.capabilities;
    let has = |capability| common & capability == capability;
    let mut rows = Vec::new();
    let now = has(PROBE_CAP_NOW);
    let has_nan = has(PROBE_CAP_NAN);
    let mut push = |offset: u64, source_mode: ProbeMode, target_mode: ProbeMode,
                    test_now: bool, test_udp6: bool| {
        rows.push(PairProbeRequest {
            request: ProbeRequest {
                request_id: request_id.saturating_add(offset),
                source: ProbeEndpoint { mode: source_mode, ..source.endpoint },
                target: ProbeEndpoint { mode: target_mode, ..target.endpoint },
                // NAN is measured when both endpoints support it, but an
                // active device pair can still be characterized over NOW if
                // a particular host cannot form or observe a NAN cluster.
                test_nan: has_nan,
                test_nan_data: false,
                test_now,
                test_udp6_association: test_udp6,
                test_udp6,
                test_scan: false,
                test_soft_ap: false,
                short_bytes,
                long_bytes,
                measure_mode_switch: true,
            },
            source,
            target,
        });
    };

    // First establish the normal NAN session.  NOW is included only when it
    // is a shared capability; this row performs command, short, and long
    // checks through the executor's requested byte counts.
    push(0, ProbeMode::NAN_NOW, ProbeMode::NAN_NOW, now, false);

    // UDP6 needs a reachable AP and a peer capable of STA association.  The
    // source advertises NAN while serving its AP; the target is STA+NAN.
    if has(PROBE_CAP_AP | PROBE_CAP_STA | PROBE_CAP_UDP6) {
        push(
            1,
            ProbeMode { ap: true, ..ProbeMode::NAN_NOW },
            ProbeMode::STA_NAN_NOW,
            false,
            true,
        );
        // Repeat under STA+AP on the associated endpoint.  AP coexistence is
        // an explicit requested mode and must be measured by the executor.
        push(
            2,
            ProbeMode { ap: true, ..ProbeMode::NAN_NOW },
            ProbeMode { ap: true, ..ProbeMode::STA_NAN_NOW },
            false,
            true,
        );
    }

    // End in the shared associated personality and re-run NOW.  This detects
    // regressions where NAN remains visible but coexistence breaks raw action
    // traffic after an STA epoch.
    if now && has(PROBE_CAP_STA) {
        push(3, ProbeMode::STA_NAN_NOW, ProbeMode::STA_NAN_NOW, true, false);
    }
    rows
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

/// Evidence for a complete IPv6 local-link association probe.  Association is
/// not inferred from a successful `transport.start`: the executor records the
/// platform/radio completion, then requires multicast discovery before it can
/// use an observed scoped address for directed traffic.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "std", derive(serde::Deserialize, serde::Serialize))]
pub struct ProbeUdp6AssociationResult {
    pub attempted: bool,
    pub source_ready: bool,
    pub target_ready: bool,
    pub multicast: ProbeMeasurement,
    pub one_way: ProbeMeasurement,
    pub quic_lite: ProbeMeasurement,
    pub iperf: ProbeMeasurement,
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
    /// Result of the requested ordinary/local SoftAP lifecycle.
    pub soft_ap: ProbeApResult,
}

/// A bounded P2P Group Owner lifecycle result. Credentials are deliberately
/// omitted: they remain in the correlated, privileged `transport.start` reply,
/// never in a persisted control-plane probe record.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "std", derive(serde::Deserialize, serde::Serialize))]
pub struct ProbeApResult {
    pub attempted: bool,
    pub succeeded: bool,
    pub channel: Option<u8>,
    pub rssi_dbm: Option<i8>,
}

/// Compact passive scan evidence. `ap_count` is the observed count of all
/// beacons/probe responses; `dmesh_ap_count` is the number classified as
/// `dmesh-*` candidates. Detailed SSIDs stay in per-node status
/// storage, not the fixed-size shared probe contract.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "std", derive(serde::Deserialize, serde::Serialize))]
pub struct ProbeScanResult {
    pub attempted: bool,
    pub succeeded: bool,
    pub ap_count: Option<u16>,
    pub channel6_ap_count: Option<u16>,
    pub dmesh_ap_count: Option<u16>,
    pub last_dmesh_rssi_dbm: Option<i8>,
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
    /// Wi-Fi Aware data-path lifecycle and, when requested, the standard
    /// UDP/IPERF measurement over that NDP IPv6 link.
    pub nan_data: ProbeMeasurement,
    pub now: ProbeMeasurement,
    /// Stage-by-stage outcome for a bearer brought up by this probe.
    pub udp6_association: ProbeUdp6AssociationResult,
    pub udp6: ProbeMeasurement,
    pub source_scan: ProbeScanResult,
    pub target_scan: ProbeScanResult,
    /// `0=none`, `1=NAN control only`, `2=NOW`, `3=UDP6`, `4=NAN data`.
    pub recommendation: u8,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn descriptor(node: u8, capabilities: u16) -> ProbeDeviceDescriptor {
        ProbeDeviceDescriptor {
            endpoint: ProbeEndpoint {
                kind: ProbeEndpointKind::Esp,
                node: [node; 6],
                mode: ProbeMode::NAN_NOW,
                bssid: None,
            },
            capabilities,
        }
    }

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
            test_nan_data: false,
            test_now: false,
            test_udp6_association: true,
            test_udp6: true,
            test_scan: true,
            test_soft_ap: true,
            short_bytes: 1_100,
            long_bytes: 64 * 1024,
            measure_mode_switch: true,
        };
        assert!(request.test_nan && request.test_udp6 && !request.test_now);
        assert!(request.test_udp6_association);
        assert!(!request.test_nan_data);
        assert_eq!(request.source.kind, ProbeEndpointKind::Android);
        assert_eq!(request.target.kind, ProbeEndpointKind::Esp);
        assert_eq!(request.target.bssid, Some([3; 6]));
    }

    #[test]
    fn full_pair_matrix_is_capability_driven_and_keeps_nan_in_every_row() {
        let capabilities = PROBE_CAP_NAN | PROBE_CAP_NOW | PROBE_CAP_STA | PROBE_CAP_AP | PROBE_CAP_UDP6;
        let rows = full_pair_probe_requests(40, descriptor(1, capabilities), descriptor(2, capabilities), 4096, 65536);
        assert_eq!(rows.len(), 4);
        assert!(rows.iter().all(|row| row.request.test_nan));
        assert!(rows[0].request.test_now);
        assert!(rows[1].request.test_udp6);
        assert!(rows[1].request.test_udp6_association);
        assert!(rows[2].request.target.mode.ap);
        assert!(rows[3].request.test_now);
        assert_eq!(rows[3].request.source.mode.transport_kind, 1);
    }

    #[test]
    fn full_pair_matrix_skips_now_and_udp_rows_not_supported_by_both_nodes() {
        let rows = full_pair_probe_requests(
            1,
            descriptor(1, PROBE_CAP_NAN | PROBE_CAP_STA | PROBE_CAP_AP | PROBE_CAP_UDP6),
            descriptor(2, PROBE_CAP_NAN),
            0,
            0,
        );
        assert_eq!(rows.len(), 1);
        assert!(!rows[0].request.test_now);
        assert!(!rows[0].request.test_udp6);
    }

    #[test]
    fn active_now_pair_remains_schedulable_without_nan_capability() {
        let rows = full_pair_probe_requests(
            1,
            descriptor(1, PROBE_CAP_NOW),
            descriptor(2, PROBE_CAP_NOW),
            256,
            1024,
        );
        assert_eq!(rows.len(), 1);
        assert!(!rows[0].request.test_nan);
        assert!(rows[0].request.test_now);
    }
}
