//! CBOR schema for bounded raw 802.11 hardware experiments.
//!
//! This is deliberately host- and ESP-independent. Adapters apply the typed
//! request to their radio APIs; the request never implies a socket API.

use crate::cbor::{Decoder, Encoder};

pub const RAW_WIFI_OP_TX: u64 = 1;
/// Configure the receiver/transmitter lab state, then return a snapshot.
pub const RAW_WIFI_OP_CONTROL: u64 = 2;
/// Return one bounded radio snapshot without changing state.
pub const RAW_WIFI_OP_SNAPSHOT: u64 = 3;
/// Advance the counter epoch and return the reset snapshot.
pub const RAW_WIFI_OP_RESET_COUNTERS: u64 = 4;
/// Start a bounded raw service health check.
pub const RAW_WIFI_OP_CHECK: u64 = 5;
/// Start a bounded bulk raw service client on the selected action bearer.
pub const RAW_WIFI_OP_IPERF: u64 = 6;
/// Registered CBOR method identifiers for the independently callable radio
/// control, snapshot, and counter-reset handlers.
pub const RAW_WIFI_METHOD_CONTROL: u64 = 72;
pub const RAW_WIFI_METHOD_SNAPSHOT: u64 = 73;
pub const RAW_WIFI_METHOD_RESET_COUNTERS: u64 = 74;
/// Start one bounded, connection-owned raw service check on the selected
/// action bearer.  The check itself is `SERVICE_STATUS`; this method only
/// supplies the radio adapter with its peer and deadline.
pub const RAW_WIFI_METHOD_CHECK: u64 = 75;
/// Start one runtime-configured raw IPERF client without a private text or
/// socket command grammar.
pub const RAW_WIFI_METHOD_IPERF: u64 = 76;
pub const RAW_WIFI_MAX_FRAME: usize = 1500;
/// Maximum encoded snapshot response. The response carries a fixed set of
/// monotonic counters plus optional applied radio state, so callers can use a
/// small fixed stack/packet buffer rather than allocate for diagnostics.
pub const RAW_WIFI_SNAPSHOT_MAX_BYTES: usize = 256;

/// Encode an empty-payload registered snapshot/reset request.  This is shared
/// by direct UART control, QUIC hardware service callers, and Rust E2E tests;
/// callers never need to hand-write a radio command map merely to sample
/// counters.
pub fn encode_raw_wifi_snapshot_request(method: u64, out: &mut [u8]) -> Option<usize> {
    if !matches!(
        method,
        RAW_WIFI_METHOD_SNAPSHOT | RAW_WIFI_METHOD_RESET_COUNTERS
    ) {
        return None;
    }
    let mut encoder = Encoder::new(out);
    encoder.map(2)?;
    encoder.uint(0)?;
    encoder.uint(method)?;
    encoder.uint(6)?;
    encoder.map(0)?;
    Some(encoder.len())
}

/// Encode a typed partial radio update in the registered handler envelope.
/// This is the sole host/firmware command constructor for dynamic lab and
/// production diagnostic changes; it deliberately contains no persistence or
/// transport-specific fields.
pub fn encode_raw_wifi_control_request(
    control: RawWifiControlRequest,
    out: &mut [u8],
) -> Option<usize> {
    let entries = 1
        + usize::from(control.channel.is_some())
        + usize::from(control.interface.is_some())
        + usize::from(control.rate.is_some())
        + usize::from(control.disable_11b.is_some())
        + usize::from(control.sta_state.is_some())
        + usize::from(control.comparator_bssid.is_some())
        + usize::from(control.comparator_enabled.is_some())
        + usize::from(control.promiscuous.is_some())
        + usize::from(control.dw_policy.is_some())
        + usize::from(control.rx_filter.is_some())
        + usize::from(control.ap_mode.is_some())
        + usize::from(control.ap_beacon_tu.is_some())
        + usize::from(control.raw_sta_mode.is_some())
        + usize::from(control.mac_ack.is_some())
        + usize::from(control.action_destination_broadcast.is_some())
        + usize::from(control.roc_listen_ms.is_some())
        + usize::from(control.roc_loop.is_some())
        + usize::from(control.action_dispatcher.is_some());
    let mut encoder = Encoder::new(out);
    encoder.map(2)?;
    encoder.uint(0)?;
    encoder.uint(RAW_WIFI_METHOD_CONTROL)?;
    encoder.uint(6)?;
    encoder.map(entries as u64)?;
    encoder.uint(0)?;
    encoder.uint(RAW_WIFI_OP_CONTROL)?;
    if let Some(value) = control.channel {
        encoder.uint(2)?;
        encoder.uint(u64::from(value))?;
    }
    if let Some(value) = control.interface {
        encoder.uint(3)?;
        encoder.uint(interface_value(value))?;
    }
    if let Some(value) = control.rate {
        encoder.uint(5)?;
        encoder.uint(rate_value(value))?;
    }
    if let Some(value) = control.disable_11b {
        encoder.uint(6)?;
        encoder.boolean(value)?;
    }
    if let Some(value) = control.sta_state {
        encoder.uint(7)?;
        encoder.uint(match value {
            RawWifiStaState::Reconnect => 0,
            RawWifiStaState::DisconnectHold => 1,
        })?;
    }
    if let Some(value) = control.comparator_bssid {
        encoder.uint(8)?;
        encoder.bytes_value(&value)?;
    }
    if let Some(value) = control.comparator_enabled {
        encoder.uint(9)?;
        encoder.boolean(value)?;
    }
    if let Some(value) = control.promiscuous {
        encoder.uint(10)?;
        encoder.boolean(value)?;
    }
    if let Some(value) = control.dw_policy {
        encoder.uint(11)?;
        encoder.uint(match value {
            RawWifiDwPolicy::Normal => 0,
            RawWifiDwPolicy::Disabled => 1,
            RawWifiDwPolicy::Manual => 2,
        })?;
    }
    if let Some(value) = control.rx_filter {
        encoder.uint(12)?;
        encoder.uint(match value {
            RawWifiRxFilter::Management => 0,
            RawWifiRxFilter::ManagementAndData => 1,
        })?;
    }
    if let Some(value) = control.ap_mode {
        encoder.uint(13)?;
        encoder.uint(match value {
            RawWifiApMode::Disabled => 0,
            RawWifiApMode::Open => 1,
        })?;
    }
    if let Some(value) = control.ap_beacon_tu {
        encoder.uint(14)?;
        encoder.uint(u64::from(value))?;
    }
    if let Some(value) = control.raw_sta_mode {
        encoder.uint(15)?;
        encoder.uint(match value {
            RawWifiStaMode::MainStyle => 1,
        })?;
    }
    if let Some(value) = control.mac_ack {
        encoder.uint(16)?;
        encoder.boolean(value)?;
    }
    if let Some(value) = control.action_destination_broadcast {
        encoder.uint(20)?;
        encoder.boolean(value)?;
    }
    if let Some(value) = control.roc_listen_ms {
        encoder.uint(25)?;
        encoder.uint(u64::from(value))?;
    }
    if let Some(value) = control.roc_loop {
        encoder.uint(26)?;
        encoder.boolean(value)?;
    }
    if let Some(value) = control.action_dispatcher {
        encoder.uint(27)?;
        encoder.boolean(value)?;
    }
    Some(encoder.len())
}

/// Build the registered raw-action check request.  This is intentionally a
/// typed CBOR constructor shared by host tests and firmware: no bearer gets a
/// private text command grammar merely to start a health probe.
pub fn encode_raw_wifi_check_request(check: RawWifiCheckRequest, out: &mut [u8]) -> Option<usize> {
    if !(100..=60_000).contains(&check.timeout_ms) {
        return None;
    }
    let mut encoder = Encoder::new(out);
    encoder.map(2)?;
    encoder.uint(0)?;
    encoder.uint(RAW_WIFI_METHOD_CHECK)?;
    encoder.uint(6)?;
    encoder.map(4)?;
    encoder.uint(0)?;
    encoder.uint(RAW_WIFI_OP_CHECK)?;
    encoder.uint(17)?;
    encoder.bytes_value(&check.peer)?;
    encoder.uint(18)?;
    encoder.uint(check.nonce)?;
    encoder.uint(19)?;
    encoder.uint(u64::from(check.timeout_ms))?;
    Some(encoder.len())
}

/// Encode a bounded action-bearer bulk service request. The service packet
/// format remains the common `SERVICE_IPERF` format; this handler supplies
/// only peer selection and runtime limits to the ESP action adapter.
pub fn encode_raw_wifi_iperf_request(
    request: RawWifiIperfRequest,
    out: &mut [u8],
) -> Option<usize> {
    if !request.valid() {
        return None;
    }
    let mut encoder = Encoder::new(out);
    encoder.map(2)?;
    encoder.uint(0)?;
    encoder.uint(RAW_WIFI_METHOD_IPERF)?;
    encoder.uint(6)?;
    encoder.map(5)?;
    encoder.uint(0)?;
    encoder.uint(RAW_WIFI_OP_IPERF)?;
    encoder.uint(21)?;
    encoder.bytes_value(&request.peer)?;
    encoder.uint(22)?;
    encoder.uint(request.bytes)?;
    encoder.uint(23)?;
    encoder.uint(u64::from(request.packet_size))?;
    encoder.uint(24)?;
    encoder.uint(u64::from(request.timeout_ms))?;
    Some(encoder.len())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RawWifiInterface {
    Auto,
    Sta,
    Ap,
    /// ESP-IDF's NAN interface.  The common schema permits a caller to ask
    /// for it so lab results can report the actual driver result; the public
    /// `esp_wifi_80211_tx` contract does not promise NAN support.
    Nan,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RawWifiRate {
    Auto,
    Mbps6,
    Mbps9,
    Mbps12,
    Mbps18,
    Mbps24,
    Mbps36,
    Mbps48,
    Mbps54,
}

/// Explicit STA state for a connectionless radio experiment.  It is not a
/// persisted Wi-Fi profile setting: `DisconnectHold` retains the initialized
/// radio on a selected channel while suppressing automatic reassociation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RawWifiStaState {
    Reconnect,
    DisconnectHold,
}

/// Promiscuous capture policy used by the lab handler.  Normal NAN policy is
/// separate from a raw-action experiment, so callers must state which one is
/// desired rather than accidentally inheriting a prior test's capture mode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RawWifiDwPolicy {
    Normal,
    Disabled,
    Manual,
}

/// Receiver filter class.  The ESP adapter maps these portable values to the
/// platform's available filter controls and reports the applied state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RawWifiRxFilter {
    Management,
    ManagementAndData,
}

/// Ephemeral SoftAP state used by the raw-radio matrix. `Open` creates an
/// APSTA owner on the selected channel without creating an IP/lwIP data
/// plane. It is never a persisted Wi-Fi profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RawWifiApMode {
    Disabled,
    Open,
}

/// Select an explicit volatile raw-STA setup sequence for a lab case.  The
/// Main-style mode is intentionally non-promiscuous: normal action/data
/// callbacks remain registered through the driver, rather than turning a
/// monitor experiment into the default receive path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RawWifiStaMode {
    MainStyle,
}

/// A partial, explicit radio-state update.  `None` means leave that setting
/// unchanged; this lets a host alter exactly one dimension of a matrix row.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Default)]
pub struct RawWifiControlRequest {
    pub channel: Option<u8>,
    pub interface: Option<RawWifiInterface>,
    pub rate: Option<RawWifiRate>,
    pub disable_11b: Option<bool>,
    pub sta_state: Option<RawWifiStaState>,
    pub comparator_bssid: Option<[u8; 6]>,
    pub comparator_enabled: Option<bool>,
    pub promiscuous: Option<bool>,
    pub dw_policy: Option<RawWifiDwPolicy>,
    pub rx_filter: Option<RawWifiRxFilter>,
    pub ap_mode: Option<RawWifiApMode>,
    pub ap_beacon_tu: Option<u16>,
    pub raw_sta_mode: Option<RawWifiStaMode>,
    /// Require an 802.11 MAC ACK for action TX. This is a lab transport
    /// policy; QUIC's end-to-end ACK/credit policy remains separate.
    pub mac_ack: Option<bool>,
    /// Use broadcast Address-1 for the NOW-like action bearer.  This is a
    /// runtime receive-filter experiment for an unassociated STA; it does
    /// not alter QUIC peer identity, which remains the action source MAC.
    pub action_destination_broadcast: Option<bool>,
    /// Request one bounded same-channel ROC action listener. This is an
    /// observation lease, never a channel retune or a second transport.
    pub roc_listen_ms: Option<u16>,
    /// Enable repeated same-channel ROC windows using `roc_listen_ms`. This
    /// is a bounded receive experiment, not normal NOW operation.
    pub roc_loop: Option<bool>,
    /// Enable the continuous private NOW dispatcher. ROC-only experiments
    /// disable this so private callback delivery cannot mask ROC evidence.
    pub action_dispatcher: Option<bool>,
}

/// One bounded action-bearer health check.  The adapter owns only raw frame
/// I/O; `dmesh-server` owns the STATUS service's framing and response state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RawWifiCheckRequest {
    pub peer: [u8; 6],
    pub nonce: u64,
    pub timeout_ms: u32,
}

/// One bounded raw action IPERF request. This does not create a socket or a
/// per-packet queue: the common QUIC-lite client retains the bounded ledger.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RawWifiIperfRequest {
    pub peer: [u8; 6],
    pub bytes: u64,
    pub packet_size: u16,
    pub timeout_ms: u32,
}

impl RawWifiIperfRequest {
    pub const fn valid(self) -> bool {
        self.bytes > 0
            && self.packet_size >= 4
            && (self.packet_size as usize) <= quic_lite::DEFAULT_MAX_DATAGRAM_SIZE
            && self.timeout_ms >= 1_000
            && self.timeout_ms <= 60_000
    }
}

/// The complete host-testable radio-lab request.  UART direct PPP and the
/// QUIC hardware service carry these same bytes; neither bearer gets a
/// private command grammar.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RawWifiLabRequest {
    Control(RawWifiControlRequest),
    Snapshot,
    ResetCounters,
    Check(RawWifiCheckRequest),
    Iperf(RawWifiIperfRequest),
}

/// Monotonic counters sampled before and after one raw-radio matrix case.
/// They deliberately separate driver acceptance from a receive dispatch and
/// parser acceptance: a transmit completion or local action-TX hook is not
/// evidence that a peer received the frame.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RawWifiCounters {
    pub tx_attempted: u32,
    pub tx_driver_accepted: u32,
    pub tx_driver_failed: u32,
    pub rx_driver_dispatch: u32,
    pub rx_parser_accepted: u32,
    pub rx_parser_rejected: u32,
    pub rx_self_echo: u32,
    pub rx_dropped: u32,
    pub nan_beacons: u32,
    pub nan_sdfs: u32,
    pub nan_followups: u32,
    pub tx_duration_us_total: u32,
    pub tx_duration_us_max: u32,
    pub tx_duration_le_250us: u32,
    pub tx_duration_le_750us: u32,
    pub tx_duration_le_2ms: u32,
    pub tx_duration_gt_2ms: u32,
    pub raw_client_receive_ok: u32,
    pub raw_client_receive_errors: u32,
    pub raw_client_bootstrap_acks: u32,
    pub raw_client_stream_packets: u32,
    pub raw_client_other_packets: u32,
    /// ESP-IDF bounded action-listener requests (ROC); hardware-specific but
    /// retained in the shared snapshot vocabulary for host/device tests.
    pub roc_action_listen_requests: u32,
    pub roc_action_listen_failures: u32,
    pub roc_action_frames: u32,
    /// Non-promiscuous vendor-IE callback evidence. The ESP adapter exposes
    /// only scalar counts, not a retained beacon/frame queue.
    pub vendor_beacon_ies: u32,
    pub vendor_nan_beacon_ies: u32,
    pub vendor_other_ies: u32,
    /// Classification of the bounded ROC callback's action bodies.
    pub roc_espnow_actions: u32,
    pub roc_nan_actions: u32,
    pub roc_other_actions: u32,
    /// Raw IPv6 bearer observations, independent of the action/NOW path.
    /// These are the STA Ethernet callback and bounded ingress results, not
    /// MAC-level receive/ACK accounting (which ESP-IDF does not expose).
    pub udp6_rx_frames: u32,
    pub udp6_rx_queue_drops: u32,
    pub udp6_rx_invalid: u32,
    pub udp6_udp_delivered: u32,
    pub udp6_ndp_advertisements: u32,
    pub udp6_tx_failures: u32,
    pub udp6_last_tx_result: u32,
    /// Completion evidence for public raw-802.11 STA TX. A completion failure
    /// means ESP-IDF did not receive the expected MAC-level acknowledgement.
    pub udp6_raw_tx_completions: u32,
    pub udp6_raw_tx_completion_failures: u32,
    pub udp6_raw_tx_completion_rate: u32,
}

impl RawWifiCounters {
    /// Counter delta for a single test case.  Saturation makes an epoch/reset
    /// mismatch visible as zero rather than wrapping into a false success.
    pub const fn delta_since(self, before: Self) -> Self {
        Self {
            tx_attempted: self.tx_attempted.saturating_sub(before.tx_attempted),
            tx_driver_accepted: self
                .tx_driver_accepted
                .saturating_sub(before.tx_driver_accepted),
            tx_driver_failed: self
                .tx_driver_failed
                .saturating_sub(before.tx_driver_failed),
            rx_driver_dispatch: self
                .rx_driver_dispatch
                .saturating_sub(before.rx_driver_dispatch),
            rx_parser_accepted: self
                .rx_parser_accepted
                .saturating_sub(before.rx_parser_accepted),
            rx_parser_rejected: self
                .rx_parser_rejected
                .saturating_sub(before.rx_parser_rejected),
            rx_self_echo: self.rx_self_echo.saturating_sub(before.rx_self_echo),
            rx_dropped: self.rx_dropped.saturating_sub(before.rx_dropped),
            nan_beacons: self.nan_beacons.saturating_sub(before.nan_beacons),
            nan_sdfs: self.nan_sdfs.saturating_sub(before.nan_sdfs),
            nan_followups: self.nan_followups.saturating_sub(before.nan_followups),
            tx_duration_us_total: self
                .tx_duration_us_total
                .saturating_sub(before.tx_duration_us_total),
            tx_duration_us_max: self.tx_duration_us_max,
            tx_duration_le_250us: self
                .tx_duration_le_250us
                .saturating_sub(before.tx_duration_le_250us),
            tx_duration_le_750us: self
                .tx_duration_le_750us
                .saturating_sub(before.tx_duration_le_750us),
            tx_duration_le_2ms: self
                .tx_duration_le_2ms
                .saturating_sub(before.tx_duration_le_2ms),
            tx_duration_gt_2ms: self
                .tx_duration_gt_2ms
                .saturating_sub(before.tx_duration_gt_2ms),
            raw_client_receive_ok: self
                .raw_client_receive_ok
                .saturating_sub(before.raw_client_receive_ok),
            raw_client_receive_errors: self
                .raw_client_receive_errors
                .saturating_sub(before.raw_client_receive_errors),
            raw_client_bootstrap_acks: self
                .raw_client_bootstrap_acks
                .saturating_sub(before.raw_client_bootstrap_acks),
            raw_client_stream_packets: self
                .raw_client_stream_packets
                .saturating_sub(before.raw_client_stream_packets),
            raw_client_other_packets: self
                .raw_client_other_packets
                .saturating_sub(before.raw_client_other_packets),
            roc_action_listen_requests: self
                .roc_action_listen_requests
                .saturating_sub(before.roc_action_listen_requests),
            roc_action_listen_failures: self
                .roc_action_listen_failures
                .saturating_sub(before.roc_action_listen_failures),
            roc_action_frames: self
                .roc_action_frames
                .saturating_sub(before.roc_action_frames),
            vendor_beacon_ies: self.vendor_beacon_ies.saturating_sub(before.vendor_beacon_ies),
            vendor_nan_beacon_ies: self
                .vendor_nan_beacon_ies
                .saturating_sub(before.vendor_nan_beacon_ies),
            vendor_other_ies: self.vendor_other_ies.saturating_sub(before.vendor_other_ies),
            roc_espnow_actions: self
                .roc_espnow_actions
                .saturating_sub(before.roc_espnow_actions),
            roc_nan_actions: self.roc_nan_actions.saturating_sub(before.roc_nan_actions),
            roc_other_actions: self
                .roc_other_actions
                .saturating_sub(before.roc_other_actions),
            udp6_rx_frames: self.udp6_rx_frames.saturating_sub(before.udp6_rx_frames),
            udp6_rx_queue_drops: self
                .udp6_rx_queue_drops
                .saturating_sub(before.udp6_rx_queue_drops),
            udp6_rx_invalid: self.udp6_rx_invalid.saturating_sub(before.udp6_rx_invalid),
            udp6_udp_delivered: self
                .udp6_udp_delivered
                .saturating_sub(before.udp6_udp_delivered),
            udp6_ndp_advertisements: self
                .udp6_ndp_advertisements
                .saturating_sub(before.udp6_ndp_advertisements),
            udp6_tx_failures: self.udp6_tx_failures.saturating_sub(before.udp6_tx_failures),
            udp6_last_tx_result: self.udp6_last_tx_result,
            udp6_raw_tx_completions: self
                .udp6_raw_tx_completions
                .saturating_sub(before.udp6_raw_tx_completions),
            udp6_raw_tx_completion_failures: self
                .udp6_raw_tx_completion_failures
                .saturating_sub(before.udp6_raw_tx_completion_failures),
            udp6_raw_tx_completion_rate: self.udp6_raw_tx_completion_rate,
        }
    }
}

/// One applied-state and counter snapshot.  This is the response model for
/// the `radio.control`, `radio.snapshot`, and `radio.reset_counters` handlers;
/// ESP and Linux adapters fill only properties their driver can observe and
/// report unavailable properties as `None`, never as invented success.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RawWifiSnapshot {
    pub epoch: u32,
    pub channel: Option<u8>,
    pub sta_associated: Option<bool>,
    pub promiscuous: Option<bool>,
    pub dw_capturing: Option<bool>,
    pub comparator_bssid: Option<[u8; 6]>,
    pub comparator_armed: Option<bool>,
    pub comparator_errors: u32,
    pub tx_interface: Option<RawWifiInterface>,
    pub tx_rate: Option<RawWifiRate>,
    pub ap_active: Option<bool>,
    pub mac_ack: Option<bool>,
    /// Whether a bounded raw service client currently owns the action path.
    /// This is a device-wide resource indicator, not a packet queue depth.
    pub raw_service_active: Option<bool>,
    /// Last ESP/action driver result represented as its unsigned platform
    /// value. Zero is success; absent means the adapter has no such driver.
    pub last_tx_error: Option<u32>,
    /// Last common QUIC-lite error observed by an active raw service client.
    /// Its numeric value is the stable `raw_transport::receive_error_code`.
    pub last_raw_client_error: Option<u32>,
    /// MAC currently owned by the STA interface.  This is a link identity,
    /// not an inferred IPv6 address; APSTA tests must not assume it equals
    /// the AP MAC.
    pub sta_mac: Option<[u8; 6]>,
    /// MAC currently owned by the AP interface when the adapter can expose
    /// it.  A raw action peer must select this identity when it targets AP
    /// egress, rather than guessing a vendor-specific `STA + 1` convention.
    pub ap_mac: Option<[u8; 6]>,
    /// Current runtime Address-1 policy for the shared NOW-like bearer.
    pub action_destination_broadcast: Option<bool>,
    /// Bytes delivered by the currently or recently completed raw QUIC-lite
    /// service client. This is transport progress, not a driver frame count.
    pub raw_service_bytes: Option<u32>,
    /// Device monotonic elapsed time for that service client, for host-side
    /// goodput calculation alongside `raw_service_bytes`.
    pub raw_service_elapsed_us: Option<u32>,
    /// Current STA UDP6 egress selection. `false` is explicit raw 802.11;
    /// `true` is ESP-IDF's associated Ethernet handoff.
    pub sta_driver_tx: Option<bool>,
    /// Current private STA BSSID-filter policy. `true` means the filter has
    /// been bypassed for the selected STA receive lane.
    pub sta_bssid_check_disabled: Option<bool>,
    /// Current STA aggregation setting used when the ESP Wi-Fi driver was
    /// initialized. It is absent for adapters which do not expose AMPDU.
    pub sta_ampdu_enabled: Option<bool>,
    /// Whether this STA driver's negotiated legacy rate set suppresses 11b.
    pub sta_11b_rates_disabled: Option<bool>,
    /// Whether the raw bearer currently owns the STA driver's Ethernet RX
    /// callback rather than ESP-IDF's normal esp-netif/lwIP path.
    pub sta_raw_rx_enabled: Option<bool>,
    /// RSSI reported by the ESP STA for its associated AP. This is a
    /// best-effort local PHY observation; it is not association authority.
    pub sta_ap_rssi_dbm: Option<i8>,
    pub counters: RawWifiCounters,
}

const fn interface_value(value: RawWifiInterface) -> u64 {
    match value {
        RawWifiInterface::Auto => 0,
        RawWifiInterface::Sta => 1,
        RawWifiInterface::Ap => 2,
        RawWifiInterface::Nan => 3,
    }
}

const fn rate_value(value: RawWifiRate) -> u64 {
    match value {
        RawWifiRate::Auto => 0,
        RawWifiRate::Mbps6 => 6,
        RawWifiRate::Mbps9 => 9,
        RawWifiRate::Mbps12 => 12,
        RawWifiRate::Mbps18 => 18,
        RawWifiRate::Mbps24 => 24,
        RawWifiRate::Mbps36 => 36,
        RawWifiRate::Mbps48 => 48,
        RawWifiRate::Mbps54 => 54,
    }
}

/// Encode the common response envelope for a radio-lab handler.  The method
/// is one of [`RAW_WIFI_METHOD_CONTROL`], [`RAW_WIFI_METHOD_SNAPSHOT`], or
/// [`RAW_WIFI_METHOD_RESET_COUNTERS`].  Optional applied-state fields are
/// absent when a driver cannot observe them; they are never represented as a
/// made-up zero/false value.
pub fn encode_raw_wifi_snapshot(
    method: u64,
    snapshot: RawWifiSnapshot,
    out: &mut [u8],
) -> Option<usize> {
    if !matches!(
        method,
        RAW_WIFI_METHOD_CONTROL
            | RAW_WIFI_METHOD_SNAPSHOT
            | RAW_WIFI_METHOD_RESET_COUNTERS
            | RAW_WIFI_METHOD_CHECK
            | RAW_WIFI_METHOD_IPERF
    ) {
        return None;
    }
    let optional = usize::from(snapshot.channel.is_some())
        + usize::from(snapshot.sta_associated.is_some())
        + usize::from(snapshot.promiscuous.is_some())
        + usize::from(snapshot.dw_capturing.is_some())
        + usize::from(snapshot.comparator_bssid.is_some())
        + usize::from(snapshot.comparator_armed.is_some())
        + usize::from(snapshot.tx_interface.is_some())
        + usize::from(snapshot.tx_rate.is_some())
        + usize::from(snapshot.ap_active.is_some())
        + usize::from(snapshot.mac_ack.is_some())
        + usize::from(snapshot.raw_service_active.is_some())
        + usize::from(snapshot.last_tx_error.is_some())
        + usize::from(snapshot.last_raw_client_error.is_some())
        + usize::from(snapshot.sta_mac.is_some())
        + usize::from(snapshot.ap_mac.is_some())
        + usize::from(snapshot.action_destination_broadcast.is_some())
        + usize::from(snapshot.raw_service_bytes.is_some())
        + usize::from(snapshot.raw_service_elapsed_us.is_some())
        + usize::from(snapshot.sta_driver_tx.is_some())
        + usize::from(snapshot.sta_bssid_check_disabled.is_some())
        + usize::from(snapshot.sta_ampdu_enabled.is_some())
        + usize::from(snapshot.sta_11b_rates_disabled.is_some())
        + usize::from(snapshot.sta_raw_rx_enabled.is_some())
        + usize::from(snapshot.sta_ap_rssi_dbm.is_some());
    let mut e = Encoder::new(out);
    e.map(2)?;
    e.uint(0)?;
    e.uint(method)?;
    e.uint(6)?;
    // Epoch, comparator errors, and monotonic counters are always
    // present, letting the host calculate deltas without retaining FW state.
    e.map((43 + optional) as u64)?;
    e.uint(20)?;
    e.uint(u64::from(snapshot.epoch))?;
    if let Some(channel) = snapshot.channel {
        e.uint(21)?;
        e.uint(u64::from(channel))?;
    }
    if let Some(value) = snapshot.sta_associated {
        e.uint(22)?;
        e.boolean(value)?;
    }
    if let Some(value) = snapshot.promiscuous {
        e.uint(23)?;
        e.boolean(value)?;
    }
    if let Some(value) = snapshot.dw_capturing {
        e.uint(24)?;
        e.boolean(value)?;
    }
    if let Some(bssid) = snapshot.comparator_bssid {
        e.uint(25)?;
        e.bytes_value(&bssid)?;
    }
    if let Some(value) = snapshot.comparator_armed {
        e.uint(26)?;
        e.boolean(value)?;
    }
    e.uint(27)?;
    e.uint(u64::from(snapshot.comparator_errors))?;
    if let Some(value) = snapshot.tx_interface {
        e.uint(28)?;
        e.uint(interface_value(value))?;
    }
    if let Some(value) = snapshot.tx_rate {
        e.uint(29)?;
        e.uint(rate_value(value))?;
    }
    if let Some(value) = snapshot.ap_active {
        e.uint(30)?;
        e.boolean(value)?;
    }
    if let Some(value) = snapshot.mac_ack {
        e.uint(31)?;
        e.boolean(value)?;
    }
    if let Some(value) = snapshot.raw_service_active {
        e.uint(32)?;
        e.boolean(value)?;
    }
    if let Some(value) = snapshot.last_tx_error {
        e.uint(33)?;
        e.uint(u64::from(value))?;
    }
    if let Some(value) = snapshot.last_raw_client_error {
        e.uint(34)?;
        e.uint(u64::from(value))?;
    }
    if let Some(value) = snapshot.sta_mac {
        e.uint(35)?;
        e.bytes_value(&value)?;
    }
    if let Some(value) = snapshot.ap_mac {
        e.uint(36)?;
        e.bytes_value(&value)?;
    }
    if let Some(value) = snapshot.action_destination_broadcast {
        e.uint(37)?;
        e.boolean(value)?;
    }
    if let Some(value) = snapshot.raw_service_bytes {
        e.uint(38)?;
        e.uint(u64::from(value))?;
    }
    if let Some(value) = snapshot.raw_service_elapsed_us {
        e.uint(39)?;
        e.uint(u64::from(value))?;
    }
    if let Some(value) = snapshot.sta_driver_tx {
        e.uint(74)?;
        e.boolean(value)?;
    }
    if let Some(value) = snapshot.sta_bssid_check_disabled {
        e.uint(78)?;
        e.boolean(value)?;
    }
    if let Some(value) = snapshot.sta_ampdu_enabled {
        e.uint(83)?;
        e.boolean(value)?;
    }
    if let Some(value) = snapshot.sta_11b_rates_disabled {
        e.uint(84)?;
        e.boolean(value)?;
    }
    if let Some(value) = snapshot.sta_raw_rx_enabled {
        e.uint(85)?;
        e.boolean(value)?;
    }
    if let Some(value) = snapshot.sta_ap_rssi_dbm {
        e.uint(86)?;
        e.int(i64::from(value))?;
    }
    for (key, value) in [
        (40, snapshot.counters.tx_attempted),
        (41, snapshot.counters.tx_driver_accepted),
        (42, snapshot.counters.tx_driver_failed),
        (43, snapshot.counters.rx_driver_dispatch),
        (44, snapshot.counters.rx_parser_accepted),
        (45, snapshot.counters.rx_parser_rejected),
        (46, snapshot.counters.rx_self_echo),
        (47, snapshot.counters.rx_dropped),
        (48, snapshot.counters.nan_beacons),
        (49, snapshot.counters.nan_sdfs),
        (50, snapshot.counters.nan_followups),
        (51, snapshot.counters.tx_duration_us_total),
        (52, snapshot.counters.tx_duration_us_max),
        (53, snapshot.counters.tx_duration_le_250us),
        (54, snapshot.counters.tx_duration_le_750us),
        (55, snapshot.counters.tx_duration_le_2ms),
        (56, snapshot.counters.tx_duration_gt_2ms),
        (57, snapshot.counters.raw_client_receive_ok),
        (58, snapshot.counters.raw_client_receive_errors),
        (59, snapshot.counters.raw_client_bootstrap_acks),
        (60, snapshot.counters.raw_client_stream_packets),
        (61, snapshot.counters.raw_client_other_packets),
        (62, snapshot.counters.roc_action_listen_requests),
        (63, snapshot.counters.roc_action_listen_failures),
        (64, snapshot.counters.roc_action_frames),
        (65, snapshot.counters.vendor_beacon_ies),
        (66, snapshot.counters.vendor_nan_beacon_ies),
        (67, snapshot.counters.vendor_other_ies),
        (68, snapshot.counters.roc_espnow_actions),
        (69, snapshot.counters.roc_nan_actions),
        (70, snapshot.counters.roc_other_actions),
        (79, snapshot.counters.udp6_rx_frames),
        (80, snapshot.counters.udp6_rx_queue_drops),
        (81, snapshot.counters.udp6_rx_invalid),
        (82, snapshot.counters.udp6_udp_delivered),
        (71, snapshot.counters.udp6_ndp_advertisements),
        (72, snapshot.counters.udp6_tx_failures),
        (73, snapshot.counters.udp6_last_tx_result),
        (75, snapshot.counters.udp6_raw_tx_completions),
        (76, snapshot.counters.udp6_raw_tx_completion_failures),
        (77, snapshot.counters.udp6_raw_tx_completion_rate),
    ] {
        e.uint(key)?;
        e.uint(u64::from(value))?;
    }
    Some(e.len())
}

/// Decode an applied radio snapshot returned by any registered radio method.
/// This is intentionally in the shared schema crate so the Rust E2E runner
/// and firmware/host adapters compare the same counter names.
pub fn decode_raw_wifi_snapshot(data: &[u8]) -> Result<(u64, RawWifiSnapshot), &'static str> {
    // UART direct commands retain the standard firmware response envelope
    // `{0: 68, 4: "ok", 6: <handler-response>}`.  Unwrap it here so the
    // same decoder serves direct UART, QUIC hardware service, and host tests.
    let mut outer = Decoder::new(data);
    // Firmware's common direct-response envelope is a map whose optional
    // diagnostic fields vary by transport.  Do not require a historical
    // fixed map size here: UART can return the minimal `{0,4,6}` form while
    // QUIC/host adapters may add metadata.
    if let Some((5, entries)) = outer.head() {
        let mut response_method = None;
        let mut payload = None;
        for _ in 0..entries {
            let key = outer.uint().ok_or("radio response key")?;
            if key == 0 {
                response_method = Some(outer.uint().ok_or("radio response method")?);
            } else if key == 6 {
                let start = outer.position();
                outer.skip().ok_or("radio response payload")?;
                payload = Some(&data[start..outer.position()]);
            } else {
                outer.skip().ok_or("radio response value")?;
            }
        }
        if response_method == Some(68) {
            return decode_raw_wifi_snapshot(payload.ok_or("radio response payload")?);
        }
    }
    let mut decoder = Decoder::new(data);
    let (major, entries) = decoder.head().ok_or("radio snapshot CBOR")?;
    if major != 5 || entries != 2 || decoder.uint() != Some(0) {
        return Err("radio snapshot envelope");
    }
    let method = decoder.uint().ok_or("radio snapshot method")?;
    if !matches!(
        method,
        RAW_WIFI_METHOD_CONTROL
            | RAW_WIFI_METHOD_SNAPSHOT
            | RAW_WIFI_METHOD_RESET_COUNTERS
            | RAW_WIFI_METHOD_CHECK
            | RAW_WIFI_METHOD_IPERF
    ) || decoder.uint() != Some(6)
    {
        return Err("radio snapshot method");
    }
    let (major, fields) = decoder.head().ok_or("radio snapshot fields")?;
    if major != 5 || fields == u64::MAX {
        return Err("radio snapshot fields");
    }
    let mut snapshot = RawWifiSnapshot::default();
    for _ in 0..fields {
        let key = decoder.uint().ok_or("radio snapshot key")?;
        match key {
            20 => {
                snapshot.epoch = u32::try_from(decoder.uint().ok_or("radio epoch")?)
                    .map_err(|_| "radio epoch")?
            }
            21 => {
                snapshot.channel = Some(
                    u8::try_from(decoder.uint().ok_or("radio channel")?)
                        .map_err(|_| "radio channel")?,
                )
            }
            22 => snapshot.sta_associated = Some(decoder.boolean().ok_or("radio STA")?),
            23 => snapshot.promiscuous = Some(decoder.boolean().ok_or("radio promiscuous")?),
            24 => snapshot.dw_capturing = Some(decoder.boolean().ok_or("radio DW")?),
            25 => {
                snapshot.comparator_bssid = Some(
                    decoder
                        .bytes_ref()
                        .and_then(|v| v.try_into().ok())
                        .ok_or("radio comparator BSSID")?,
                )
            }
            26 => snapshot.comparator_armed = Some(decoder.boolean().ok_or("radio comparator")?),
            27 => {
                snapshot.comparator_errors =
                    u32::try_from(decoder.uint().ok_or("radio comparator errors")?)
                        .map_err(|_| "radio comparator errors")?
            }
            28 => {
                snapshot.tx_interface =
                    Some(decode_interface(decoder.uint().ok_or("radio interface")?)?)
            }
            29 => snapshot.tx_rate = Some(decode_rate(decoder.uint().ok_or("radio rate")?)?),
            30 => snapshot.ap_active = Some(decoder.boolean().ok_or("radio AP")?),
            31 => snapshot.mac_ack = Some(decoder.boolean().ok_or("radio MAC ACK")?),
            32 => snapshot.raw_service_active = Some(decoder.boolean().ok_or("radio raw service")?),
            33 => {
                snapshot.last_tx_error = Some(
                    u32::try_from(decoder.uint().ok_or("radio tx error")?)
                        .map_err(|_| "radio tx error")?,
                )
            }
            34 => {
                snapshot.last_raw_client_error = Some(
                    u32::try_from(decoder.uint().ok_or("radio client error")?)
                        .map_err(|_| "radio client error")?,
                )
            }
            35 => {
                snapshot.sta_mac = Some(
                    decoder
                        .bytes_ref()
                        .and_then(|v| v.try_into().ok())
                        .ok_or("radio STA MAC")?,
                )
            }
            36 => {
                snapshot.ap_mac = Some(
                    decoder
                        .bytes_ref()
                        .and_then(|v| v.try_into().ok())
                        .ok_or("radio AP MAC")?,
                )
            }
            37 => {
                snapshot.action_destination_broadcast =
                    Some(decoder.boolean().ok_or("radio action broadcast")?)
            }
            38 => {
                snapshot.raw_service_bytes = Some(
                    u32::try_from(decoder.uint().ok_or("radio service bytes")?)
                        .map_err(|_| "radio service bytes")?,
                )
            }
            39 => {
                snapshot.raw_service_elapsed_us = Some(
                    u32::try_from(decoder.uint().ok_or("radio service elapsed")?)
                        .map_err(|_| "radio service elapsed")?,
                )
            }
            74 => snapshot.sta_driver_tx = Some(decoder.boolean().ok_or("radio STA egress")?),
            78 => {
                snapshot.sta_bssid_check_disabled =
                    Some(decoder.boolean().ok_or("radio STA BSSID policy")?)
            }
            83 => snapshot.sta_ampdu_enabled = Some(decoder.boolean().ok_or("radio STA AMPDU")?),
            84 => {
                snapshot.sta_11b_rates_disabled =
                    Some(decoder.boolean().ok_or("radio STA 11b policy")?)
            }
            85 => snapshot.sta_raw_rx_enabled = Some(decoder.boolean().ok_or("radio raw RX")?),
            86 => {
                snapshot.sta_ap_rssi_dbm = Some(
                    i8::try_from(decoder.int().ok_or("radio STA AP RSSI")?)
                        .map_err(|_| "radio STA AP RSSI")?,
                )
            }
            40 => {
                snapshot.counters.tx_attempted =
                    u32::try_from(decoder.uint().ok_or("radio tx attempted")?)
                        .map_err(|_| "radio counter")?
            }
            41 => {
                snapshot.counters.tx_driver_accepted =
                    u32::try_from(decoder.uint().ok_or("radio tx accepted")?)
                        .map_err(|_| "radio counter")?
            }
            42 => {
                snapshot.counters.tx_driver_failed =
                    u32::try_from(decoder.uint().ok_or("radio tx failed")?)
                        .map_err(|_| "radio counter")?
            }
            43 => {
                snapshot.counters.rx_driver_dispatch =
                    u32::try_from(decoder.uint().ok_or("radio rx dispatch")?)
                        .map_err(|_| "radio counter")?
            }
            44 => {
                snapshot.counters.rx_parser_accepted =
                    u32::try_from(decoder.uint().ok_or("radio rx accepted")?)
                        .map_err(|_| "radio counter")?
            }
            45 => {
                snapshot.counters.rx_parser_rejected =
                    u32::try_from(decoder.uint().ok_or("radio rx rejected")?)
                        .map_err(|_| "radio counter")?
            }
            46 => {
                snapshot.counters.rx_self_echo =
                    u32::try_from(decoder.uint().ok_or("radio self echo")?)
                        .map_err(|_| "radio counter")?
            }
            47 => {
                snapshot.counters.rx_dropped = u32::try_from(decoder.uint().ok_or("radio drops")?)
                    .map_err(|_| "radio counter")?
            }
            48 => {
                snapshot.counters.nan_beacons =
                    u32::try_from(decoder.uint().ok_or("radio NAN beacons")?)
                        .map_err(|_| "radio counter")?
            }
            49 => {
                snapshot.counters.nan_sdfs = u32::try_from(decoder.uint().ok_or("radio NAN SDF")?)
                    .map_err(|_| "radio counter")?
            }
            50 => {
                snapshot.counters.nan_followups =
                    u32::try_from(decoder.uint().ok_or("radio NAN followup")?)
                        .map_err(|_| "radio counter")?
            }
            51 => {
                snapshot.counters.tx_duration_us_total =
                    u32::try_from(decoder.uint().ok_or("radio tx time")?)
                        .map_err(|_| "radio counter")?
            }
            52 => {
                snapshot.counters.tx_duration_us_max =
                    u32::try_from(decoder.uint().ok_or("radio tx max")?)
                        .map_err(|_| "radio counter")?
            }
            53 => {
                snapshot.counters.tx_duration_le_250us =
                    u32::try_from(decoder.uint().ok_or("radio tx bucket")?)
                        .map_err(|_| "radio counter")?
            }
            54 => {
                snapshot.counters.tx_duration_le_750us =
                    u32::try_from(decoder.uint().ok_or("radio tx bucket")?)
                        .map_err(|_| "radio counter")?
            }
            55 => {
                snapshot.counters.tx_duration_le_2ms =
                    u32::try_from(decoder.uint().ok_or("radio tx bucket")?)
                        .map_err(|_| "radio counter")?
            }
            56 => {
                snapshot.counters.tx_duration_gt_2ms =
                    u32::try_from(decoder.uint().ok_or("radio tx bucket")?)
                        .map_err(|_| "radio counter")?
            }
            57 => {
                snapshot.counters.raw_client_receive_ok =
                    u32::try_from(decoder.uint().ok_or("radio client receive")?)
                        .map_err(|_| "radio counter")?
            }
            58 => {
                snapshot.counters.raw_client_receive_errors =
                    u32::try_from(decoder.uint().ok_or("radio client errors")?)
                        .map_err(|_| "radio counter")?
            }
            59 => {
                snapshot.counters.raw_client_bootstrap_acks =
                    u32::try_from(decoder.uint().ok_or("radio client bootstrap")?)
                        .map_err(|_| "radio counter")?
            }
            60 => {
                snapshot.counters.raw_client_stream_packets =
                    u32::try_from(decoder.uint().ok_or("radio client streams")?)
                        .map_err(|_| "radio counter")?
            }
            61 => {
                snapshot.counters.raw_client_other_packets =
                    u32::try_from(decoder.uint().ok_or("radio client packets")?)
                        .map_err(|_| "radio counter")?
            }
            62 => {
                snapshot.counters.roc_action_listen_requests =
                    u32::try_from(decoder.uint().ok_or("radio ROC requests")?)
                        .map_err(|_| "radio counter")?
            }
            63 => {
                snapshot.counters.roc_action_listen_failures =
                    u32::try_from(decoder.uint().ok_or("radio ROC failures")?)
                        .map_err(|_| "radio counter")?
            }
            64 => {
                snapshot.counters.roc_action_frames =
                    u32::try_from(decoder.uint().ok_or("radio ROC frames")?)
                        .map_err(|_| "radio counter")?
            }
            65 => {
                snapshot.counters.vendor_beacon_ies =
                    u32::try_from(decoder.uint().ok_or("radio vendor beacon IEs")?)
                        .map_err(|_| "radio counter")?
            }
            66 => {
                snapshot.counters.vendor_nan_beacon_ies =
                    u32::try_from(decoder.uint().ok_or("radio vendor NAN IEs")?)
                        .map_err(|_| "radio counter")?
            }
            67 => {
                snapshot.counters.vendor_other_ies =
                    u32::try_from(decoder.uint().ok_or("radio vendor other IEs")?)
                        .map_err(|_| "radio counter")?
            }
            68 => {
                snapshot.counters.roc_espnow_actions =
                    u32::try_from(decoder.uint().ok_or("radio ROC NOW actions")?)
                        .map_err(|_| "radio counter")?
            }
            69 => {
                snapshot.counters.roc_nan_actions =
                    u32::try_from(decoder.uint().ok_or("radio ROC NAN actions")?)
                        .map_err(|_| "radio counter")?
            }
            70 => {
                snapshot.counters.roc_other_actions =
                    u32::try_from(decoder.uint().ok_or("radio ROC other actions")?)
                        .map_err(|_| "radio counter")?
            }
            79 => {
                snapshot.counters.udp6_rx_frames =
                    u32::try_from(decoder.uint().ok_or("radio UDP6 RX frames")?)
                        .map_err(|_| "radio counter")?
            }
            80 => {
                snapshot.counters.udp6_rx_queue_drops =
                    u32::try_from(decoder.uint().ok_or("radio UDP6 RX drops")?)
                        .map_err(|_| "radio counter")?
            }
            81 => {
                snapshot.counters.udp6_rx_invalid =
                    u32::try_from(decoder.uint().ok_or("radio UDP6 RX invalid")?)
                        .map_err(|_| "radio counter")?
            }
            82 => {
                snapshot.counters.udp6_udp_delivered =
                    u32::try_from(decoder.uint().ok_or("radio UDP6 delivered")?)
                        .map_err(|_| "radio counter")?
            }
            71 => {
                snapshot.counters.udp6_ndp_advertisements =
                    u32::try_from(decoder.uint().ok_or("radio UDP6 NDP")?)
                        .map_err(|_| "radio counter")?
            }
            72 => {
                snapshot.counters.udp6_tx_failures =
                    u32::try_from(decoder.uint().ok_or("radio UDP6 TX failures")?)
                        .map_err(|_| "radio counter")?
            }
            73 => {
                snapshot.counters.udp6_last_tx_result =
                    u32::try_from(decoder.uint().ok_or("radio UDP6 TX result")?)
                        .map_err(|_| "radio counter")?
            }
            75 => {
                snapshot.counters.udp6_raw_tx_completions =
                    u32::try_from(decoder.uint().ok_or("radio UDP6 raw TX completions")?)
                        .map_err(|_| "radio counter")?
            }
            76 => {
                snapshot.counters.udp6_raw_tx_completion_failures =
                    u32::try_from(decoder.uint().ok_or("radio UDP6 raw TX failures")?)
                        .map_err(|_| "radio counter")?
            }
            77 => {
                snapshot.counters.udp6_raw_tx_completion_rate =
                    u32::try_from(decoder.uint().ok_or("radio UDP6 raw TX rate")?)
                        .map_err(|_| "radio counter")?
            }
            _ => decoder.skip().ok_or("radio snapshot value")?,
        }
    }
    if !decoder.is_finished() {
        return Err("radio snapshot trailing bytes");
    }
    Ok((method, snapshot))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RawWifiTxRequest<'a> {
    pub channel: u8,
    pub interface: RawWifiInterface,
    pub system_sequence: bool,
    pub rate: RawWifiRate,
    pub disable_11b: bool,
    pub frame: &'a [u8],
}

fn decode_interface(value: u64) -> Result<RawWifiInterface, &'static str> {
    match value {
        0 => Ok(RawWifiInterface::Auto),
        1 => Ok(RawWifiInterface::Sta),
        2 => Ok(RawWifiInterface::Ap),
        3 => Ok(RawWifiInterface::Nan),
        _ => Err("raw wifi interface"),
    }
}

fn decode_rate(value: u64) -> Result<RawWifiRate, &'static str> {
    match value {
        0 => Ok(RawWifiRate::Auto),
        6 => Ok(RawWifiRate::Mbps6),
        9 => Ok(RawWifiRate::Mbps9),
        12 => Ok(RawWifiRate::Mbps12),
        18 => Ok(RawWifiRate::Mbps18),
        24 => Ok(RawWifiRate::Mbps24),
        36 => Ok(RawWifiRate::Mbps36),
        48 => Ok(RawWifiRate::Mbps48),
        54 => Ok(RawWifiRate::Mbps54),
        _ => Err("raw wifi rate"),
    }
}

fn decode_mac(value: &[u8]) -> Result<[u8; 6], &'static str> {
    if let Ok(mac) = <[u8; 6]>::try_from(value) {
        return Ok(mac);
    }
    let text = core::str::from_utf8(value).map_err(|_| "raw wifi comparator BSSID")?;
    let mut mac = [0u8; 6];
    let mut values = text.split(':');
    for byte in &mut mac {
        let part = values.next().ok_or("raw wifi comparator BSSID")?;
        if part.len() != 2 {
            return Err("raw wifi comparator BSSID");
        }
        *byte = u8::from_str_radix(part, 16).map_err(|_| "raw wifi comparator BSSID")?;
    }
    if values.next().is_some() {
        return Err("raw wifi comparator BSSID");
    }
    Ok(mac)
}

fn decode_bytes_or_text<'a>(decoder: &mut Decoder<'a>) -> Option<&'a [u8]> {
    let saved = decoder.position();
    if let Some(value) = decoder.bytes_ref() {
        return Some(value);
    }
    decoder.set_position(saved);
    decoder.text_ref()
}

/// Decode canonical CBOR map keys: 0=operation, 1=frame bytes, 2=channel,
/// 3=interface (0 auto, 1 sta, 2 ap, 3 nan), 4=system sequence, 5=rate, 6=disable
/// 11b. Unknown keys are skipped so host tooling can add observation-only
/// fields without changing firmware parsers.
pub fn decode_raw_wifi_tx(data: &[u8]) -> Result<RawWifiTxRequest<'_>, &'static str> {
    let mut decoder = Decoder::new(data);
    let (major, entries) = decoder.head().ok_or("raw wifi CBOR")?;
    if major != 5 {
        return Err("raw wifi map");
    }
    let mut operation = None;
    let mut frame = None;
    let mut channel = 6u8;
    let mut interface = RawWifiInterface::Auto;
    let mut system_sequence = true;
    let mut rate = RawWifiRate::Auto;
    let mut disable_11b = true;
    let mut entry = 0;
    while (entries == u64::MAX && !decoder.consume_break())
        || (entries != u64::MAX && entry < entries)
    {
        entry += 1;
        let key = decoder.uint().ok_or("raw wifi key")?;
        match key {
            0 => operation = Some(decoder.uint().ok_or("raw wifi operation")?),
            1 => frame = Some(decoder.bytes_ref().ok_or("raw wifi frame")?),
            2 => {
                channel = u8::try_from(decoder.uint().ok_or("raw wifi channel")?)
                    .map_err(|_| "raw wifi channel")?
            }
            3 => interface = decode_interface(decoder.uint().ok_or("raw wifi interface")?)?,
            4 => system_sequence = decoder.boolean().ok_or("raw wifi system sequence")?,
            5 => rate = decode_rate(decoder.uint().ok_or("raw wifi rate")?)?,
            6 => disable_11b = decoder.boolean().ok_or("raw wifi disable 11b")?,
            _ => decoder.skip().ok_or("raw wifi value")?,
        }
    }
    if !decoder.is_finished() || operation != Some(RAW_WIFI_OP_TX) {
        return Err("raw wifi operation");
    }
    let frame = frame.ok_or("raw wifi frame")?;
    if !(24..=RAW_WIFI_MAX_FRAME).contains(&frame.len()) || !(1..=13).contains(&channel) {
        return Err("raw wifi bounds");
    }
    Ok(RawWifiTxRequest {
        channel,
        interface,
        system_sequence,
        rate,
        disable_11b,
        frame,
    })
}

/// Decode the non-TX subset of the canonical raw Wi-Fi schema.
///
/// Map keys are shared with [`decode_raw_wifi_tx`] where their meaning
/// overlaps: 0=operation, 2=channel, 3=interface, 5=rate and 6=disable 11b.
/// Lab-only keys are 7=STA state (0 reconnect, 1 disconnect-hold), 8=A3
/// comparator BSSID (six bytes), 9=comparator enabled, 10=promiscuous,
/// 11=DW policy (0 normal, 1 disabled, 2 manual), and 12=RX filter (0 mgmt,
/// 1 mgmt+data), 13=AP mode (0 disabled, 1 open), 14=AP beacon interval in
/// TU, 15=raw STA mode (1 Main-style non-promiscuous), and 16=MAC ACK
/// required. 25 is one bounded same-channel ROC listener duration in ms.
/// Unknown keys are
/// skipped for forward-compatible snapshots.
fn decode_raw_wifi_lab_inner(
    data: &[u8],
    implied_operation: Option<u64>,
) -> Result<RawWifiLabRequest, &'static str> {
    let mut decoder = Decoder::new(data);
    let (major, entries) = decoder.head().ok_or("raw wifi CBOR")?;
    if major != 5 {
        return Err("raw wifi map");
    }
    let mut operation = None;
    let mut control = RawWifiControlRequest::default();
    let mut check_peer = None;
    let mut check_nonce = None;
    let mut check_timeout_ms = None;
    let mut iperf_peer = None;
    let mut iperf_bytes = None;
    let mut iperf_packet_size = None;
    let mut iperf_timeout_ms = None;
    let mut entry = 0;
    while (entries == u64::MAX && !decoder.consume_break())
        || (entries != u64::MAX && entry < entries)
    {
        entry += 1;
        let key = decoder.uint().ok_or("raw wifi key")?;
        match key {
            0 => operation = Some(decoder.uint().ok_or("raw wifi operation")?),
            2 => {
                control.channel = Some(
                    u8::try_from(decoder.uint().ok_or("raw wifi channel")?)
                        .map_err(|_| "raw wifi channel")?,
                )
            }
            3 => {
                control.interface = Some(decode_interface(
                    decoder.uint().ok_or("raw wifi interface")?,
                )?)
            }
            5 => control.rate = Some(decode_rate(decoder.uint().ok_or("raw wifi rate")?)?),
            6 => control.disable_11b = Some(decoder.boolean().ok_or("raw wifi disable 11b")?),
            7 => {
                control.sta_state = Some(match decoder.uint().ok_or("raw wifi STA state")? {
                    0 => RawWifiStaState::Reconnect,
                    1 => RawWifiStaState::DisconnectHold,
                    _ => return Err("raw wifi STA state"),
                })
            }
            8 => {
                let bssid =
                    decode_bytes_or_text(&mut decoder).ok_or("raw wifi comparator BSSID")?;
                control.comparator_bssid = Some(decode_mac(bssid)?);
            }
            9 => control.comparator_enabled = Some(decoder.boolean().ok_or("raw wifi comparator")?),
            10 => control.promiscuous = Some(decoder.boolean().ok_or("raw wifi promiscuous")?),
            11 => {
                control.dw_policy = Some(match decoder.uint().ok_or("raw wifi DW policy")? {
                    0 => RawWifiDwPolicy::Normal,
                    1 => RawWifiDwPolicy::Disabled,
                    2 => RawWifiDwPolicy::Manual,
                    _ => return Err("raw wifi DW policy"),
                })
            }
            12 => {
                control.rx_filter = Some(match decoder.uint().ok_or("raw wifi RX filter")? {
                    0 => RawWifiRxFilter::Management,
                    1 => RawWifiRxFilter::ManagementAndData,
                    _ => return Err("raw wifi RX filter"),
                })
            }
            13 => {
                control.ap_mode = Some(match decoder.uint().ok_or("raw wifi AP mode")? {
                    0 => RawWifiApMode::Disabled,
                    1 => RawWifiApMode::Open,
                    _ => return Err("raw wifi AP mode"),
                })
            }
            14 => {
                control.ap_beacon_tu = Some(
                    u16::try_from(decoder.uint().ok_or("raw wifi AP beacon interval")?)
                        .map_err(|_| "raw wifi AP beacon interval")?,
                )
            }
            15 => {
                control.raw_sta_mode = Some(match decoder.uint().ok_or("raw wifi STA mode")? {
                    1 => RawWifiStaMode::MainStyle,
                    _ => return Err("raw wifi STA mode"),
                })
            }
            16 => control.mac_ack = Some(decoder.boolean().ok_or("raw wifi MAC ACK")?),
            20 => {
                control.action_destination_broadcast =
                    Some(decoder.boolean().ok_or("raw wifi action broadcast")?)
            }
            25 => {
                control.roc_listen_ms = Some(
                    u16::try_from(decoder.uint().ok_or("raw wifi ROC duration")?)
                        .map_err(|_| "raw wifi ROC duration")?,
                )
            }
            26 => control.roc_loop = Some(decoder.boolean().ok_or("raw wifi ROC loop")?),
            27 => control.action_dispatcher = Some(decoder.boolean().ok_or("raw wifi action dispatcher")?),
            17 => {
                let peer = decoder.bytes_ref().ok_or("raw wifi check peer")?;
                check_peer = Some(peer.try_into().map_err(|_| "raw wifi check peer")?);
            }
            18 => check_nonce = Some(decoder.uint().ok_or("raw wifi check nonce")?),
            19 => {
                check_timeout_ms = Some(
                    u32::try_from(decoder.uint().ok_or("raw wifi check timeout")?)
                        .map_err(|_| "raw wifi check timeout")?,
                )
            }
            21 => {
                let peer = decoder.bytes_ref().ok_or("raw wifi iperf peer")?;
                iperf_peer = Some(peer.try_into().map_err(|_| "raw wifi iperf peer")?);
            }
            22 => iperf_bytes = Some(decoder.uint().ok_or("raw wifi iperf bytes")?),
            23 => {
                iperf_packet_size = Some(
                    u16::try_from(decoder.uint().ok_or("raw wifi iperf packet size")?)
                        .map_err(|_| "raw wifi iperf packet size")?,
                )
            }
            24 => {
                iperf_timeout_ms = Some(
                    u32::try_from(decoder.uint().ok_or("raw wifi iperf timeout")?)
                        .map_err(|_| "raw wifi iperf timeout")?,
                )
            }
            _ => decoder.skip().ok_or("raw wifi value")?,
        }
    }
    if !decoder.is_finished() {
        return Err("raw wifi trailing data");
    }
    match operation.or(implied_operation) {
        Some(RAW_WIFI_OP_CONTROL) => {
            if control
                .channel
                .is_some_and(|channel| !(1..=13).contains(&channel))
            {
                return Err("raw wifi channel");
            }
            if control.comparator_enabled == Some(true) && control.comparator_bssid.is_none() {
                return Err("raw wifi comparator BSSID");
            }
            if control
                .ap_beacon_tu
                .is_some_and(|value| !(100..=60_000).contains(&value))
            {
                return Err("raw wifi AP beacon interval");
            }
            if control
                .roc_listen_ms
                .is_some_and(|value| !(10..=10_000).contains(&value))
            {
                return Err("raw wifi ROC duration");
            }
            if control.roc_loop == Some(true) && control.roc_listen_ms.is_none() {
                return Err("raw wifi ROC loop duration");
            }
            Ok(RawWifiLabRequest::Control(control))
        }
        Some(RAW_WIFI_OP_SNAPSHOT) => Ok(RawWifiLabRequest::Snapshot),
        Some(RAW_WIFI_OP_RESET_COUNTERS) => Ok(RawWifiLabRequest::ResetCounters),
        Some(RAW_WIFI_OP_CHECK) => {
            let check = RawWifiCheckRequest {
                peer: check_peer.ok_or("raw wifi check peer")?,
                nonce: check_nonce.ok_or("raw wifi check nonce")?,
                timeout_ms: check_timeout_ms.ok_or("raw wifi check timeout")?,
            };
            if !(100..=60_000).contains(&check.timeout_ms) {
                return Err("raw wifi check timeout");
            }
            Ok(RawWifiLabRequest::Check(check))
        }
        Some(RAW_WIFI_OP_IPERF) => {
            let request = RawWifiIperfRequest {
                peer: iperf_peer.ok_or("raw wifi iperf peer")?,
                bytes: iperf_bytes.ok_or("raw wifi iperf bytes")?,
                packet_size: iperf_packet_size.ok_or("raw wifi iperf packet size")?,
                timeout_ms: iperf_timeout_ms.ok_or("raw wifi iperf timeout")?,
            };
            request
                .valid()
                .then_some(RawWifiLabRequest::Iperf(request))
                .ok_or("raw wifi iperf")
        }
        _ => Err("raw wifi operation"),
    }
}

/// Decode the compact operation-map form.  This is useful to adapters that
/// already reserve an outer service tag and therefore carry only a body map.
pub fn decode_raw_wifi_lab(data: &[u8]) -> Result<RawWifiLabRequest, &'static str> {
    decode_raw_wifi_lab_inner(data, None)
}

fn command_payload(packet: &[u8], expected_method: u64) -> Result<&[u8], &'static str> {
    let mut root = Decoder::new(packet);
    let (major, fields) = root.head().ok_or("radio command CBOR")?;
    if major != 5 {
        return Err("radio command map");
    }
    let mut method = None;
    let mut payload = None;
    let mut entry = 0;
    while (fields == u64::MAX && !root.consume_break()) || (fields != u64::MAX && entry < fields) {
        entry += 1;
        let key = root.uint().ok_or("radio command key")?;
        if key == 0 {
            method = Some(root.uint().ok_or("radio command method")?);
        } else if key == 6 {
            let start = root.position();
            root.skip().ok_or("radio command payload")?;
            payload = Some(&packet[start..root.position()]);
        } else {
            root.skip().ok_or("radio command value")?;
        }
    }
    if method != Some(expected_method) {
        return Err("radio command method");
    }
    let payload = payload.ok_or("radio command payload")?;
    let mut body = Decoder::new(payload);
    if !matches!(body.head(), Some((5, _))) {
        return Err("radio command payload");
    }
    Ok(payload)
}

/// Decode a complete registered handler envelope.  Direct PPP and QUIC
/// service bodies call this exact function; no UART-specific parser exists.
pub fn decode_raw_wifi_handler(packet: &[u8]) -> Result<RawWifiLabRequest, &'static str> {
    let mut root = Decoder::new(packet);
    let (major, fields) = root.head().ok_or("radio command CBOR")?;
    if major != 5 {
        return Err("radio command map");
    }
    let mut method = None;
    let mut entry = 0;
    while (fields == u64::MAX && !root.consume_break()) || (fields != u64::MAX && entry < fields) {
        entry += 1;
        let key = root.uint().ok_or("radio command key")?;
        if key == 0 {
            method = Some(root.uint().ok_or("radio command method")?);
        } else {
            root.skip().ok_or("radio command value")?;
        }
    }
    match method {
        Some(RAW_WIFI_METHOD_CONTROL) => decode_raw_wifi_lab_inner(
            command_payload(packet, RAW_WIFI_METHOD_CONTROL)?,
            Some(RAW_WIFI_OP_CONTROL),
        ),
        Some(RAW_WIFI_METHOD_SNAPSHOT) => decode_raw_wifi_lab_inner(
            command_payload(packet, RAW_WIFI_METHOD_SNAPSHOT)?,
            Some(RAW_WIFI_OP_SNAPSHOT),
        ),
        Some(RAW_WIFI_METHOD_RESET_COUNTERS) => decode_raw_wifi_lab_inner(
            command_payload(packet, RAW_WIFI_METHOD_RESET_COUNTERS)?,
            Some(RAW_WIFI_OP_RESET_COUNTERS),
        ),
        Some(RAW_WIFI_METHOD_CHECK) => decode_raw_wifi_lab_inner(
            command_payload(packet, RAW_WIFI_METHOD_CHECK)?,
            Some(RAW_WIFI_OP_CHECK),
        ),
        Some(RAW_WIFI_METHOD_IPERF) => decode_raw_wifi_lab_inner(
            command_payload(packet, RAW_WIFI_METHOD_IPERF)?,
            Some(RAW_WIFI_OP_IPERF),
        ),
        _ => Err("radio command method"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cbor::Encoder;

    #[test]
    fn raw_tx_schema_decodes_all_radio_controls() {
        let frame = [0xd0; 24];
        let mut wire = [0; 80];
        let mut e = Encoder::new(&mut wire);
        e.map(7).unwrap();
        e.uint(0).unwrap();
        e.uint(RAW_WIFI_OP_TX).unwrap();
        e.uint(1).unwrap();
        e.bytes_value(&frame).unwrap();
        e.uint(2).unwrap();
        e.uint(6).unwrap();
        e.uint(3).unwrap();
        e.uint(2).unwrap();
        e.uint(4).unwrap();
        e.boolean(false).unwrap();
        e.uint(5).unwrap();
        e.uint(24).unwrap();
        e.uint(6).unwrap();
        e.boolean(false).unwrap();
        let used = e.len();
        drop(e);
        let request = decode_raw_wifi_tx(&wire[..used]).unwrap();
        assert_eq!(request.interface, RawWifiInterface::Ap);
        assert_eq!(request.rate, RawWifiRate::Mbps24);
        assert!(!request.system_sequence && !request.disable_11b);
        assert_eq!(request.frame, frame);
    }

    #[test]
    fn raw_tx_schema_preserves_nan_interface_request() {
        let frame = [0xd0; 24];
        let mut wire = [0; 64];
        let mut e = Encoder::new(&mut wire);
        e.map(4).unwrap();
        e.uint(0).unwrap();
        e.uint(RAW_WIFI_OP_TX).unwrap();
        e.uint(1).unwrap();
        e.bytes_value(&frame).unwrap();
        e.uint(2).unwrap();
        e.uint(6).unwrap();
        e.uint(3).unwrap();
        e.uint(3).unwrap();
        let used = e.len();
        drop(e);
        assert_eq!(
            decode_raw_wifi_tx(&wire[..used]).unwrap().interface,
            RawWifiInterface::Nan
        );
    }

    #[test]
    fn radio_control_schema_decodes_prom_off_unassociated_matrix_state() {
        let mut wire = [0; 96];
        let mut e = Encoder::new(&mut wire);
        e.map(8).unwrap();
        e.uint(0).unwrap();
        e.uint(RAW_WIFI_OP_CONTROL).unwrap();
        e.uint(2).unwrap();
        e.uint(6).unwrap();
        e.uint(5).unwrap();
        e.uint(54).unwrap();
        e.uint(7).unwrap();
        e.uint(1).unwrap();
        e.uint(8).unwrap();
        e.bytes_value(&[0x50, 0x6f, 0x9a, 0x01, 0x34, 0x4a])
            .unwrap();
        e.uint(9).unwrap();
        e.boolean(true).unwrap();
        e.uint(10).unwrap();
        e.boolean(false).unwrap();
        e.uint(11).unwrap();
        e.uint(1).unwrap();
        let used = e.len();
        drop(e);
        let RawWifiLabRequest::Control(control) = decode_raw_wifi_lab(&wire[..used]).unwrap()
        else {
            panic!("control request")
        };
        assert_eq!(control.channel, Some(6));
        assert_eq!(control.rate, Some(RawWifiRate::Mbps54));
        assert_eq!(control.sta_state, Some(RawWifiStaState::DisconnectHold));
        assert_eq!(
            control.comparator_bssid,
            Some([0x50, 0x6f, 0x9a, 0x01, 0x34, 0x4a])
        );
        assert_eq!(control.comparator_enabled, Some(true));
        assert_eq!(control.promiscuous, Some(false));
        assert_eq!(control.dw_policy, Some(RawWifiDwPolicy::Disabled));
    }

    #[test]
    fn radio_control_schema_decodes_ephemeral_open_ap_mode() {
        let wire = [0xa2, 0x00, RAW_WIFI_OP_CONTROL as u8, 0x0d, 0x01];
        let RawWifiLabRequest::Control(control) = decode_raw_wifi_lab(&wire).unwrap() else {
            panic!("control request")
        };
        assert_eq!(control.ap_mode, Some(RawWifiApMode::Open));
    }

    #[test]
    fn radio_control_rejects_an_enabled_comparator_without_a_bssid() {
        let wire = [0xa2, 0x00, RAW_WIFI_OP_CONTROL as u8, 0x09, 0xf5];
        assert_eq!(decode_raw_wifi_lab(&wire), Err("raw wifi comparator BSSID"));
    }

    #[test]
    fn radio_control_accepts_the_cli_mac_spelling() {
        let mut wire = [0; 64];
        let mut e = Encoder::new(&mut wire);
        e.map(3).unwrap();
        e.uint(0).unwrap();
        e.uint(RAW_WIFI_OP_CONTROL).unwrap();
        e.uint(8).unwrap();
        e.text_value(b"50:6f:9a:01:34:4a").unwrap();
        e.uint(9).unwrap();
        e.boolean(true).unwrap();
        let used = e.len();
        drop(e);
        let RawWifiLabRequest::Control(control) = decode_raw_wifi_lab(&wire[..used]).unwrap()
        else {
            panic!("control request")
        };
        assert_eq!(
            control.comparator_bssid,
            Some([0x50, 0x6f, 0x9a, 0x01, 0x34, 0x4a])
        );
    }

    #[test]
    fn radio_snapshot_and_reset_need_no_radio_fields() {
        assert_eq!(
            decode_raw_wifi_lab(&[0xa1, 0x00, RAW_WIFI_OP_SNAPSHOT as u8]),
            Ok(RawWifiLabRequest::Snapshot)
        );
        assert_eq!(
            decode_raw_wifi_lab(&[0xa1, 0x00, RAW_WIFI_OP_RESET_COUNTERS as u8]),
            Ok(RawWifiLabRequest::ResetCounters)
        );
    }

    #[test]
    fn registered_control_handler_uses_the_same_typed_schema() {
        // {0: 72, 6: {2: 6, 7: 1, 10: false, 11: 1}}
        let command = [
            0xa2, 0x00, 0x18, 0x48, 0x06, 0xa4, 0x02, 0x06, 0x07, 0x01, 0x0a, 0xf4, 0x0b, 0x01,
        ];
        let RawWifiLabRequest::Control(control) = decode_raw_wifi_handler(&command).unwrap() else {
            panic!("control request")
        };
        assert_eq!(control.channel, Some(6));
        assert_eq!(control.sta_state, Some(RawWifiStaState::DisconnectHold));
        assert_eq!(control.promiscuous, Some(false));
        assert_eq!(control.dw_policy, Some(RawWifiDwPolicy::Disabled));
    }

    #[test]
    fn registered_snapshot_and_reset_are_separate_handlers() {
        assert_eq!(
            decode_raw_wifi_handler(&[0xa2, 0x00, 0x18, 0x49, 0x06, 0xa0]),
            Ok(RawWifiLabRequest::Snapshot)
        );
        assert_eq!(
            decode_raw_wifi_handler(&[0xa2, 0x00, 0x18, 0x4a, 0x06, 0xa0]),
            Ok(RawWifiLabRequest::ResetCounters)
        );
    }

    #[test]
    fn snapshot_request_encoder_uses_the_registered_handler_envelope() {
        let mut wire = [0; 16];
        let used = encode_raw_wifi_snapshot_request(RAW_WIFI_METHOD_SNAPSHOT, &mut wire).unwrap();
        assert_eq!(
            decode_raw_wifi_handler(&wire[..used]),
            Ok(RawWifiLabRequest::Snapshot)
        );
        assert!(encode_raw_wifi_snapshot_request(RAW_WIFI_METHOD_CONTROL, &mut wire).is_none());
    }

    #[test]
    fn check_request_uses_the_registered_typed_schema() {
        let check = RawWifiCheckRequest {
            peer: [0x14, 0xc1, 0x9f, 0xe5, 0x98, 0x00],
            nonce: 0x0102_0304_0506_0708,
            timeout_ms: 5_000,
        };
        let mut wire = [0; 64];
        let used = encode_raw_wifi_check_request(check, &mut wire).unwrap();
        assert_eq!(
            decode_raw_wifi_handler(&wire[..used]),
            Ok(RawWifiLabRequest::Check(check))
        );
        assert!(
            encode_raw_wifi_check_request(
                RawWifiCheckRequest {
                    timeout_ms: 99,
                    ..check
                },
                &mut wire
            )
            .is_none()
        );
    }

    #[test]
    fn iperf_request_uses_the_registered_typed_schema() {
        let request = RawWifiIperfRequest {
            peer: [0x14, 0xc1, 0x9f, 0xe5, 0x98, 0x00],
            bytes: 64 * 1024,
            packet_size: 1_136,
            timeout_ms: 10_000,
        };
        let mut wire = [0; 64];
        let used = encode_raw_wifi_iperf_request(request, &mut wire).unwrap();
        assert_eq!(
            decode_raw_wifi_handler(&wire[..used]),
            Ok(RawWifiLabRequest::Iperf(request))
        );
        assert!(
            encode_raw_wifi_iperf_request(
                RawWifiIperfRequest {
                    bytes: 0,
                    ..request
                },
                &mut wire
            )
            .is_none()
        );
    }

    #[test]
    fn control_request_encoder_round_trips_dynamic_dw_and_ap_state() {
        let control = RawWifiControlRequest {
            channel: Some(6),
            dw_policy: Some(RawWifiDwPolicy::Normal),
            ap_mode: Some(RawWifiApMode::Open),
            ap_beacon_tu: Some(500),
            promiscuous: Some(false),
            // Ten seconds is the ESP-IDF-supported maximum shared by host,
            // Main, and Recovery. The sustained hardware test uses a smaller
            // four-second dwell, but schema validation must not constrain it.
            roc_listen_ms: Some(10_000),
            roc_loop: Some(true),
            action_dispatcher: Some(false),
            ..RawWifiControlRequest::default()
        };
        let mut wire = [0; 96];
        let used = encode_raw_wifi_control_request(control, &mut wire).unwrap();
        assert_eq!(
            decode_raw_wifi_handler(&wire[..used]),
            Ok(RawWifiLabRequest::Control(control))
        );
        let out_of_range = RawWifiControlRequest {
            roc_listen_ms: Some(10_001),
            roc_loop: Some(true),
            ..RawWifiControlRequest::default()
        };
        let used = encode_raw_wifi_control_request(out_of_range, &mut wire).unwrap();
        assert_eq!(
            decode_raw_wifi_handler(&wire[..used]),
            Err("raw wifi ROC duration")
        );
    }

    #[test]
    fn metric_delta_never_wraps_across_a_counter_epoch() {
        let before = RawWifiCounters {
            tx_attempted: 9,
            rx_parser_accepted: 12,
            udp6_rx_frames: 10,
            ..RawWifiCounters::default()
        };
        let after = RawWifiCounters {
            tx_attempted: 12,
            rx_parser_accepted: 3,
            udp6_rx_frames: 14,
            ..RawWifiCounters::default()
        };
        let delta = after.delta_since(before);
        assert_eq!(delta.tx_attempted, 3);
        assert_eq!(delta.rx_parser_accepted, 0);
        assert_eq!(delta.udp6_rx_frames, 4);
    }

    #[test]
    fn snapshot_encoder_omits_unknown_driver_state_but_keeps_counters() {
        let mut out = [0u8; RAW_WIFI_SNAPSHOT_MAX_BYTES];
        let used = encode_raw_wifi_snapshot(
            RAW_WIFI_METHOD_SNAPSHOT,
            RawWifiSnapshot {
                epoch: 7,
                promiscuous: Some(false),
                counters: RawWifiCounters {
                    tx_attempted: 3,
                    rx_parser_accepted: 2,
                    ..RawWifiCounters::default()
                },
                ..RawWifiSnapshot::default()
            },
            &mut out,
        )
        .unwrap();
        let mut decoder = Decoder::new(&out[..used]);
        assert_eq!(decoder.head(), Some((5, 2)));
        assert_eq!(decoder.uint(), Some(0));
        assert_eq!(decoder.uint(), Some(RAW_WIFI_METHOD_SNAPSHOT));
        assert_eq!(decoder.uint(), Some(6));
        let (major, fields) = decoder.head().unwrap();
        assert_eq!(major, 5);
        let mut has_promiscuous = false;
        let mut has_tx_attempted = false;
        let mut has_channel = false;
        for _ in 0..fields {
            let key = decoder.uint().unwrap();
            match key {
                21 => {
                    has_channel = true;
                    decoder.skip().unwrap();
                }
                23 => {
                    has_promiscuous = decoder.boolean() == Some(false);
                }
                40 => {
                    has_tx_attempted = decoder.uint() == Some(3);
                }
                _ => decoder.skip().unwrap(),
            }
        }
        assert!(has_promiscuous && has_tx_attempted);
        assert!(!has_channel);
    }

    #[test]
    fn snapshot_decoder_round_trips_common_and_radio_counters() {
        let expected = RawWifiSnapshot {
            epoch: 9,
            channel: Some(6),
            dw_capturing: Some(true),
            sta_mac: Some([0x10, 0, 0, 0, 0, 1]),
            ap_mac: Some([0x10, 0, 0, 0, 0, 2]),
            sta_ap_rssi_dbm: Some(-42),
            counters: RawWifiCounters {
                rx_parser_accepted: 7,
                nan_beacons: 3,
                tx_duration_le_750us: 2,
                vendor_beacon_ies: 4,
                vendor_nan_beacon_ies: 2,
                vendor_other_ies: 1,
                roc_espnow_actions: 3,
                roc_nan_actions: 4,
                roc_other_actions: 5,
                udp6_rx_frames: 7,
                udp6_rx_queue_drops: 2,
                udp6_rx_invalid: 6,
                udp6_udp_delivered: 1,
                ..RawWifiCounters::default()
            },
            ..RawWifiSnapshot::default()
        };
        let mut wire = [0; RAW_WIFI_SNAPSHOT_MAX_BYTES];
        let used = encode_raw_wifi_snapshot(RAW_WIFI_METHOD_SNAPSHOT, expected, &mut wire).unwrap();
        assert_eq!(
            decode_raw_wifi_snapshot(&wire[..used]),
            Ok((RAW_WIFI_METHOD_SNAPSHOT, expected))
        );
    }
}
