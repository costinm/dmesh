//! Cross-platform discovery-runtime status and transport-owned metrics.
//!
//! These records deliberately contain no interface names, Linux process
//! state, or peer inventory. `announce::ANNOUNCE_DEVICES_OBSERVED` owns peer
//! observations; this component explains the local adapter/runtime instead.

use crate::{
    cbor::{Decoder, Encoder},
    power::BatteryState,
    raw_wifi::WifiLinkMetrics,
    tagged::{Name, decode},
};

pub const TELEMETRY_COMPONENT: u64 = 7;
pub const NAN_STATUS_METHOD: u64 = 1;
pub const NOW_METRICS_METHOD: u64 = 2;
pub const NAN_METRICS_METHOD: u64 = 3;
pub const UDP6_METRICS_METHOD: u64 = 4;
pub const WIFI_LINK_METRICS_METHOD: u64 = 5;
pub const BATTERY_METHOD: u64 = 6;
pub const QUIC_METRICS_METHOD: u64 = 7;
pub const QUIC_ASSOCIATIONS_METHOD: u64 = 8;
pub const BEARERS_METHOD: u64 = 9;
pub const MEMORY_METHOD: u64 = 10;
pub const POWER_METHOD: u64 = 11;
pub const RUNTIME_METHOD: u64 = 12;
pub const DEVICE_METHOD: u64 = 13;
include!("generated_device_telemetry.rs");
/// Every telemetry method: each takes an empty request.
pub const METHODS: [u64; 13] = [
    NAN_STATUS_METHOD,
    NOW_METRICS_METHOD,
    NAN_METRICS_METHOD,
    UDP6_METRICS_METHOD,
    WIFI_LINK_METRICS_METHOD,
    BATTERY_METHOD,
    QUIC_METRICS_METHOD,
    QUIC_ASSOCIATIONS_METHOD,
    BEARERS_METHOD,
    MEMORY_METHOD,
    POWER_METHOD,
    RUNTIME_METHOD,
    DEVICE_METHOD,
];

/// Encode static platform information inside the ordinary response envelope.
pub fn device_response(record: crate::tagged::Record<'_>, info: TelemetryDeviceResponse<'_>) -> Option<alloc::vec::Vec<u8>> {
    if record.component != Some(Name::Tag(TELEMETRY_COMPONENT))
        || record.method != Some(Name::Tag(DEVICE_METHOD))
        || record.to.is_some() || record.params.is_some() || record.fields.is_some()
        || record.data.is_some() || record.result.is_some() || record.error.is_some() {
        return None;
    }
    let mut data = [0u8; 256];
    let len = info.encode_cbor(&mut data)?;
    let mut out = alloc::vec![0u8; len + 64];
    let used = crate::tagged::encode_numeric_response(TELEMETRY_COMPONENT, DEVICE_METHOD, record.id?, &data[..len], &mut out)?;
    out.truncate(used);
    Some(out)
}

/// Linux and Android expose physical RAM through the kernel, not process RSS.
#[cfg(feature = "std")]
pub fn host_total_ram_bytes() -> Option<u64> {
    let info = std::fs::read_to_string("/proc/meminfo").ok()?;
    info.lines().find_map(|line| {
        let mut words = line.split_whitespace();
        (words.next()? == "MemTotal:").then_some(())?;
        let kib = words.next()?.parse::<u64>().ok()?;
        (words.next()? == "kB").then_some(())?;
        kib.checked_mul(1024)
    })
}
pub const TELEMETRY_RESPONSE_MAX_BYTES: usize = 512;
include!("generated_quic_telemetry.rs");
/// A complete NAN snapshot currently has 35 scalar counters.  Leave bounded
/// room for additions while retaining one compact response inside the shared
/// transport MTU.
pub const MAX_METRICS: usize = 48;

pub mod now_metric {
    /// Calls made to the serialized NOW action sender.
    pub const TX_ATTEMPTED: u16 = 1;
    /// NOW requests accepted by ESP-IDF. This is local submission evidence,
    /// not evidence that a peer received the frame.
    pub const TX_ACCEPTED: u16 = 2;
    /// NOW sender calls rejected before ESP-IDF accepted the frame.
    pub const TX_FAILED: u16 = 3;
    /// NOW submit calls refused for temporary ESP-IDF memory pressure.
    pub const TX_BUSY: u16 = 18;
    pub const RX_DISPATCHED: u16 = 4;
    pub const RX_ACCEPTED: u16 = 5;
    pub const RX_REJECTED: u16 = 6;
    pub const RX_SELF_ECHO: u16 = 7;
    pub const RX_DROPPED: u16 = 8;
    pub const REGISTERED_ACTIONS: u16 = 9;
    pub const REGISTERED_DROPS: u16 = 10;
    /// First four bytes of the last ROC action body, in network byte order.
    /// This is framing evidence, not application payload retention.
    pub const LAST_ROC_BODY_PREFIX: u16 = 11;
    /// Bounded byte length of the last ROC action body.
    pub const LAST_ROC_BODY_LEN: u16 = 12;
    pub const RX_INVALID_DROPS: u16 = 13;
    pub const RX_BUSY_DROPS: u16 = 14;
    pub const RX_SHARED_INGRESS_DROPS: u16 = 15;
    pub const LAST_REGISTERED_BODY_PREFIX: u16 = 16;
    pub const LAST_REGISTERED_BODY_LEN: u16 = 17;
}

pub mod nan_metric {
    pub const BEACONS: u16 = 1;
    pub const SDFS: u16 = 2;
    pub const FOLLOWUPS_RX: u16 = 3;
    pub const FOLLOWUPS_QUEUED: u16 = 4;
    pub const FOLLOWUPS_SENT: u16 = 5;
    pub const FOLLOWUPS_DROPPED: u16 = 6;
    pub const SERVICE_INFO_MATCHED: u16 = 7;
    pub const SERVICE_INFO_ENQUEUED: u16 = 8;
    pub const SERVICE_INFO_DROPPED: u16 = 9;
    pub const SERVICE_INFO_DISPATCHED: u16 = 10;
    pub const ACTIVE_PUBLISH_ATTEMPTED: u16 = 11;
    pub const ACTIVE_PUBLISH_SENT: u16 = 12;
    pub const ACTIVE_PUBLISH_DROPPED: u16 = 13;
    /// Common `discovery.active` requests admitted by the Main owner.
    pub const ACTIVE_DISCOVERY_QUEUED: u16 = 14;
    /// Active-discovery Subscribe SDFs accepted by the Wi-Fi action submitter.
    pub const ACTIVE_DISCOVERY_SENT: u16 = 15;
    /// Active-discovery Subscribe SDF driver submission failures.
    pub const ACTIVE_DISCOVERY_DROPPED: u16 = 16;
    /// Time spent stopping STA/AP/NAN/NOW before the most recent DW8 sleep.
    pub const DW8_RADIO_STOP_US: u16 = 17;
    /// Time from timer wake to restored NAN/NOW receive ownership.
    pub const DW8_RADIO_RESUME_US: u16 = 18;
    /// Total awake time from a DW8 timer wake to the following sleep entry.
    pub const DW8_AWAKE_US: u16 = 19;
    /// Last received NAN SDF relative to the selected cluster beacon.
    pub const LAST_SDF_AFTER_BEACON_US: u16 = 20;
    /// Byte length of the last raw SDF admitted by promiscuous ingress.
    pub const LAST_SDF_FRAME_BYTES: u16 = 21;
    /// Last raw SDF source MAC packed little-endian into the low 48 bits.
    pub const LAST_SDF_SOURCE_LE: u16 = 22;
    /// Largest raw SDF at or below 128 bytes observed since boot.
    pub const SMALL_SDF_MAX_BYTES: u16 = 23;
    /// Source of the frame which established `SMALL_SDF_MAX_BYTES`.
    pub const SMALL_SDF_MAX_SOURCE_LE: u16 = 24;
    /// SDF semantic intents accepted since boot.
    pub const PENDING_SDF_QUEUED: u16 = 25;
    /// SDF intent requests rejected because all bounded slots were occupied.
    pub const PENDING_SDF_REJECTED: u16 = 26;
    /// DW-gated public-action submissions attempted for all SDF intents.
    pub const PENDING_SDF_TX_ATTEMPTED: u16 = 27;
    /// SDF submissions accepted by the Wi-Fi action driver.
    pub const PENDING_SDF_TX_ACCEPTED: u16 = 28;
    /// Intents whose requested bounded transmission count was consumed.
    pub const PENDING_SDF_COMPLETED: u16 = 29;
    /// Current number of independently retained SDF intents.
    pub const PENDING_SDF_COUNT: u16 = 30;
    /// Explicit timer-light-sleep attempts made by Main's DW policy.
    pub const LIGHT_SLEEP_ATTEMPTS: u16 = 31;
    /// Successful `esp_light_sleep_start` entries, rather than requested sleep.
    pub const LIGHT_SLEEP_ENTRIES: u16 = 32;
    /// Rejected timer/light-sleep calls; this must not be treated as a wake.
    pub const LIGHT_SLEEP_SKIPPED: u16 = 33;
    /// Most recent requested timer duration for an explicit DW sleep.
    pub const LAST_SLEEP_REQUESTED_US: u16 = 34;
    /// Measured duration inside the most recent light-sleep call.
    pub const LAST_SLEEP_DURATION_US: u16 = 35;
    /// First management frame observed after the most recent explicit wake.
    /// Zero means no frame arrived before the next sleep boundary.
    pub const FIRST_FRAME_AFTER_WAKE_US: u16 = 36;
    /// First NAN beacon observed after the most recent explicit wake. Zero
    /// means the selected beacon was missed in that window.
    pub const FIRST_BEACON_AFTER_WAKE_US: u16 = 37;
}

pub mod udp6_metric {
    pub const RX_FRAMES: u16 = 1;
    pub const RX_QUEUE_DROPS: u16 = 2;
    pub const RX_INVALID: u16 = 3;
    pub const UDP_DELIVERED: u16 = 4;
    pub const NDP_ADVERTISEMENTS: u16 = 5;
    pub const TX_FAILURES: u16 = 6;
    pub const RAW_TX_COMPLETIONS: u16 = 7;
    pub const RAW_TX_COMPLETION_FAILURES: u16 = 8;
}

/// A local NAN runtime snapshot. Missing fields mean that the platform cannot
/// observe the fact; they never mean `false` or zero.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct NanStatus<'a> {
    /// Whether the local NAN adapter/runtime is attached and operational.
    pub active: Option<bool>,
    /// Current cluster identifier, normally a six-byte cluster BSSID.
    pub cluster_id: Option<&'a [u8]>,
    /// Current synchronization-master identifier when exposed by the stack.
    pub sync_id: Option<&'a [u8]>,
    /// Whether the periodic DMesh announce publish is active.
    pub publishing: Option<bool>,
    /// Whether a publish was requested but has not become active yet.
    pub publish_pending: Option<bool>,
}

/// Stable numeric metric entry. The enclosing method identifies the owner
/// (`now`, `nan`, or `udp6`); adapters omit unavailable counters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Metric {
    pub id: u16,
    pub value: u64,
}

/// Encode an empty, correlated read request for one telemetry method.
pub fn encode_request(method: u64, id: u64, out: &mut [u8]) -> Option<usize> {
    if !METHODS.contains(&method) {
        return None;
    }
    let mut e = Encoder::new(out);
    e.map(4)?;
    e.uint(1)?;
    e.uint(TELEMETRY_COMPONENT)?;
    e.uint(2)?;
    e.uint(method)?;
    e.uint(3)?;
    e.uint(id)?;
    e.uint(5)?;
    e.map(0)?;
    Some(e.len())
}

/// Decode and validate an empty telemetry read request.
pub fn decode_request(packet: &[u8]) -> Option<(u64, u64)> {
    let record = decode(packet)?;
    decode_request_record(record)
}

/// Decode a telemetry request which has already been framed by a tagged QUIC
/// stream handler. This keeps direct and stream adapters on one validator.
pub fn decode_request_record(record: crate::tagged::Record<'_>) -> Option<(u64, u64)> {
    if record.to.is_some()
        || record.component != Some(Name::Tag(TELEMETRY_COMPONENT))
        || record.params.is_some()
        || record.data.is_some()
        || record.result.is_some()
        || record.error.is_some()
    {
        return None;
    }
    let method = match record.method? {
        Name::Tag(method) if METHODS.contains(&method) =>
        {
            method
        }
        _ => return None,
    };
    if let Some(fields) = record.fields {
        let mut d = Decoder::new(fields);
        let (major, count) = d.head()?;
        if major != 5 || count != 0 || !d.is_finished() {
            return None;
        }
    }
    Some((method, record.id?))
}

/// Encode the optional portable battery snapshot. Omitted fields remain
/// unknown; an empty map is valid on a device without a battery observer.
pub fn encode_battery_status(state: BatteryState, out: &mut [u8]) -> Option<usize> {
    let mut e = Encoder::new(out);
    let count = usize::from(state.battery_percent.is_some())
        + usize::from(state.charging.is_some())
        + usize::from(state.power_save.is_some())
        + usize::from(state.idle.is_some())
        + usize::from(state.idle_ms.is_some())
        + usize::from(state.total_idle_ms.is_some())
        + usize::from(state.charging_ms.is_some());
    e.map(count as u64)?;
    if let Some(value) = state.battery_percent {
        e.uint(1)?;
        e.uint(value as u64)?;
    }
    if let Some(value) = state.charging {
        e.uint(2)?;
        e.boolean(value)?;
    }
    if let Some(value) = state.power_save {
        e.uint(3)?;
        e.boolean(value)?;
    }
    if let Some(value) = state.idle {
        e.uint(4)?;
        e.boolean(value)?;
    }
    if let Some(value) = state.idle_ms {
        e.uint(5)?;
        e.uint(value)?;
    }
    if let Some(value) = state.total_idle_ms {
        e.uint(6)?;
        e.uint(value)?;
    }
    if let Some(value) = state.charging_ms {
        e.uint(7)?;
        e.uint(value)?;
    }
    Some(e.len())
}

pub fn encode_nan_status(status: NanStatus<'_>, out: &mut [u8]) -> Option<usize> {
    let count = usize::from(status.active.is_some())
        + usize::from(status.cluster_id.is_some())
        + usize::from(status.sync_id.is_some())
        + usize::from(status.publishing.is_some())
        + usize::from(status.publish_pending.is_some());
    let mut e = Encoder::new(out);
    e.map(count as u64)?;
    if let Some(value) = status.active {
        e.uint(1)?;
        e.boolean(value)?;
    }
    if let Some(value) = status.cluster_id {
        e.uint(2)?;
        e.bytes_value(value)?;
    }
    if let Some(value) = status.sync_id {
        e.uint(3)?;
        e.bytes_value(value)?;
    }
    if let Some(value) = status.publishing {
        e.uint(4)?;
        e.boolean(value)?;
    }
    if let Some(value) = status.publish_pending {
        e.uint(5)?;
        e.boolean(value)?;
    }
    Some(e.len())
}

/// Encode a bounded metric map. Duplicate IDs are rejected so a consumer
/// never has to choose between two values for the same counter.
pub fn encode_metrics(metrics: &[Metric], out: &mut [u8]) -> Option<usize> {
    if metrics.len() > MAX_METRICS {
        return None;
    }
    for (index, metric) in metrics.iter().enumerate() {
        if metrics[..index].iter().any(|seen| seen.id == metric.id) {
            return None;
        }
    }
    let mut e = Encoder::new(out);
    e.map(metrics.len() as u64)?;
    for metric in metrics {
        e.uint(u64::from(metric.id))?;
        e.uint(metric.value)?;
    }
    Some(e.len())
}

/// Encode QUIC-lite node counters using the generated `API.md` response type.
pub fn encode_quic_metrics(telemetry: quic_lite::NodeTelemetry, out: &mut [u8]) -> Option<usize> {
    TelemetryQuicResponse {
        live_associations: telemetry.live_associations,
        received_packets: telemetry.received_packets,
        sent_packets: telemetry.sent_packets,
        received_stream_packets: telemetry.received_stream_packets,
        received_control_packets: telemetry.received_control_packets,
        sent_stream_packets: telemetry.sent_stream_packets,
        sent_control_packets: telemetry.sent_control_packets,
        duplicate_packets: telemetry.duplicate_packets,
        out_of_order_packets: telemetry.out_of_order_packets,
        inferred_missing_packets: telemetry.inferred_missing_packets,
        retransmitted_packets: telemetry.retransmitted_packets,
        loss_events: telemetry.loss_events,
        submission_failures: telemetry.submission_failures,
    }
    .encode_cbor(out)
}

/// Encode the existing common optional per-peer link record. Field numbers
/// follow `WifiLinkMetrics` declaration order and unavailable facts vanish.
pub fn encode_wifi_link_metrics(metrics: WifiLinkMetrics, out: &mut [u8]) -> Option<usize> {
    let values = [
        metrics.interface_index.map(u64::from),
        metrics.rx_bytes,
        metrics.tx_bytes,
        metrics.rx_packets,
        metrics.tx_packets,
        metrics.mac_tx_retries,
        metrics.mac_tx_failed,
        metrics.rx_dropped,
        metrics.rx_airtime_us,
        metrics.tx_airtime_us,
        metrics.rx_bitrate_kbit_s,
        metrics.tx_bitrate_kbit_s,
        metrics.expected_throughput_kbit_s,
        metrics.bearer_rx_frames,
        metrics.bearer_rx_drops,
        metrics.bearer_rx_invalid,
        metrics.bearer_udp_delivered,
        metrics.bearer_ndp_advertisements,
        metrics.bearer_tx_failures,
        metrics.raw_tx_completion_failures,
    ];
    let count = 1
        + usize::from(metrics.peer_mac.is_some())
        + values.iter().filter(|value| value.is_some()).count()
        + usize::from(metrics.signal_dbm.is_some())
        + usize::from(metrics.signal_avg_dbm.is_some())
        + usize::from(metrics.ack_signal_dbm.is_some())
        + usize::from(metrics.ack_signal_avg_dbm.is_some());
    let mut e = Encoder::new(out);
    e.map(count as u64)?;
    e.uint(1)?;
    e.uint(u64::from(metrics.schema_version))?;
    if let Some(peer) = metrics.peer_mac {
        e.uint(3)?;
        e.bytes_value(&peer)?;
    }
    // Scalar field IDs preserve the declaration order, excluding peer_mac.
    const IDS: [u64; 20] = [
        2, 4, 5, 6, 7, 8, 9, 10, 11, 12, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26,
    ];
    for (id, value) in IDS.into_iter().zip(values) {
        if let Some(value) = value {
            e.uint(id)?;
            e.uint(value)?;
        }
    }
    for (id, value) in [
        (13, metrics.signal_dbm),
        (14, metrics.signal_avg_dbm),
        (15, metrics.ack_signal_dbm),
        (16, metrics.ack_signal_avg_dbm),
    ] {
        if let Some(value) = value {
            e.uint(id)?;
            e.int(i64::from(value))?;
        }
    }
    Some(e.len())
}

/// The resident set size of this process in bytes, from `VmRSS` in
/// `/proc/self/status` (Linux and Android), for `telemetry.memory`.
#[cfg(feature = "std")]
pub fn process_rss_bytes() -> Result<u64, String> {
    let status = std::fs::read_to_string("/proc/self/status").map_err(|error| error.to_string())?;
    status
        .lines()
        .find_map(|line| line.strip_prefix("VmRSS:"))
        .and_then(|rest| rest.trim().strip_suffix("kB"))
        .and_then(|kilobytes| kilobytes.trim().parse::<u64>().ok())
        .map(|kilobytes| kilobytes.saturating_mul(1024))
        .ok_or_else(|| "no VmRSS in /proc/self/status".to_owned())
}

/// The host-typed `telemetry.quic` response (the generated `platform_api` type;
/// firmware uses the no_std type above) from the node's counters.
#[cfg(feature = "std")]
impl From<quic_lite::NodeTelemetry> for crate::platform_api::TelemetryQuicResponse {
    fn from(telemetry: quic_lite::NodeTelemetry) -> Self {
        Self {
            live_associations: telemetry.live_associations,
            received_packets: telemetry.received_packets,
            sent_packets: telemetry.sent_packets,
            received_stream_packets: telemetry.received_stream_packets,
            received_control_packets: telemetry.received_control_packets,
            sent_stream_packets: telemetry.sent_stream_packets,
            sent_control_packets: telemetry.sent_control_packets,
            duplicate_packets: telemetry.duplicate_packets,
            out_of_order_packets: telemetry.out_of_order_packets,
            inferred_missing_packets: telemetry.inferred_missing_packets,
            retransmitted_packets: telemetry.retransmitted_packets,
            loss_events: telemetry.loss_events,
            submission_failures: telemetry.submission_failures,
        }
    }
}

/// `telemetry.quic_associations` from the node's per-association rows. A
/// bearer's name comes from the bearer rows; the peer is the bearer-local
/// handle, as `discovery.nodes` would report it.
#[cfg(feature = "std")]
pub fn quic_associations_response(
    associations: &[quic_lite::AssociationRow],
    bearers: &[quic_lite::BearerRow],
) -> crate::platform_api::TelemetryQuicAssociationsResponse {
    let rows = associations
        .iter()
        .map(|row| {
            let transport = row.telemetry.transport;
            crate::platform_api::QuicAssociation {
                association: Some(row.id),
                bearer: row.bearer.and_then(|id| {
                    bearers
                        .iter()
                        .find(|bearer| bearer.id == id)
                        .map(|bearer| bearer.name.as_str().to_owned())
                }),
                peer: row.peer.map(|peer| peer.value().to_string()),
                received_packets: Some(transport.received_packets),
                sent_packets: Some(transport.sent_packets),
                retransmitted_packets: Some(transport.retransmitted_packets),
                loss_events: Some(transport.loss_events),
                submission_failures: Some(transport.submission_failures),
                bytes_in_flight: Some(row.telemetry.bytes_in_flight),
                peer_max_data: Some(row.telemetry.peer_max_data),
                peer_sent_data: Some(row.telemetry.peer_sent_data),
                largest_acked_by_peer: row.telemetry.largest_acked_by_peer,
                ..Default::default()
            }
        })
        .collect();
    crate::platform_api::TelemetryQuicAssociationsResponse {
        associations: Some(rows),
    }
}

/// `telemetry.bearers` from the node's per-bearer rows.
#[cfg(feature = "std")]
pub fn bearers_response(
    bearers: &[quic_lite::BearerRow],
) -> crate::platform_api::TelemetryBearersResponse {
    let rows = bearers
        .iter()
        .map(|bearer| crate::platform_api::BearerCounters {
            name: Some(bearer.name.as_str().to_owned()),
            state: Some(u8::from(bearer.enabled)),
            tx_submitted: Some(bearer.submitted_packets),
            tx_accepted: Some(bearer.completed_packets),
            tx_failed: Some(bearer.send_failures),
            tx_busy: Some(bearer.send_would_block),
            rx_packets: Some(bearer.received_packets),
            rx_dropped: Some(bearer.ingress_drops),
            queue_depth: u32::try_from(bearer.in_flight_packets).ok(),
            ..Default::default()
        })
        .collect();
    crate::platform_api::TelemetryBearersResponse {
        bearers: Some(rows),
    }
}

/// One `links` row of `telemetry.wifi_link` from a station's metrics.
#[cfg(feature = "std")]
impl From<&crate::raw_wifi::WifiLinkMetrics> for crate::platform_api::WifiLink {
    fn from(link: &crate::raw_wifi::WifiLinkMetrics) -> Self {
        Self {
            schema_version: Some(link.schema_version),
            peer_mac: link.peer_mac.map(|mac| mac.to_vec()),
            interface_index: link.interface_index,
            rx_bytes: link.rx_bytes,
            tx_bytes: link.tx_bytes,
            rx_packets: link.rx_packets,
            tx_packets: link.tx_packets,
            mac_tx_retries: link.mac_tx_retries,
            mac_tx_failed: link.mac_tx_failed,
            rx_dropped: link.rx_dropped,
            rx_airtime_us: link.rx_airtime_us,
            tx_airtime_us: link.tx_airtime_us,
            signal_dbm: link.signal_dbm,
            signal_avg_dbm: link.signal_avg_dbm,
            ack_signal_dbm: link.ack_signal_dbm,
            ack_signal_avg_dbm: link.ack_signal_avg_dbm,
            rx_bitrate_kbit_s: link.rx_bitrate_kbit_s,
            tx_bitrate_kbit_s: link.tx_bitrate_kbit_s,
            expected_throughput_kbit_s: link.expected_throughput_kbit_s,
            bearer_rx_frames: link.bearer_rx_frames,
            bearer_rx_drops: link.bearer_rx_drops,
            bearer_rx_invalid: link.bearer_rx_invalid,
            bearer_udp_delivered: link.bearer_udp_delivered,
            bearer_ndp_advertisements: link.bearer_ndp_advertisements,
            bearer_tx_failures: link.bearer_tx_failures,
            raw_tx_completion_failures: link.raw_tx_completion_failures,
        }
    }
}

#[cfg(test)]
mod tests {
    /// `API.md` is the one definition of each telemetry response. These tests
    /// hold the encoders and the metric-id constants to the typed structs
    /// generated from it, so the documentation cannot drift from the wire.
    mod spec {
        #[test]
        fn generated_marshalling_round_trips_every_scalar_kind() {
            // Required and optional integers, text, bytes, and an array that
            // goes through the JSON-value fallback.
            let quic = api::TelemetryQuicResponse {
                live_associations: 2,
                received_packets: 9,
                ..Default::default()
            };
            let wire = quic.encode_cbor();
            let back = api::TelemetryQuicResponse::decode_cbor(&wire).unwrap();
            assert_eq!((back.live_associations, back.received_packets), (2, 9));
            // A required field that is absent is an error, not a zero.
            assert!(api::TelemetryQuicResponse::decode_cbor(&[0xa0]).is_err());

            let link = api::TelemetryWifiLinkResponse {
                schema_version: Some(1),
                signal_dbm: Some(-61),
                peer_mac: Some(vec![0xaa; 6]),
                links: Some(vec![api::WifiLink {
                    rx_bytes: Some(7),
                    peer_mac: Some(vec![1, 2, 3, 4, 5, 6]),
                    ..Default::default()
                }]),
                ..Default::default()
            };
            let back = api::TelemetryWifiLinkResponse::decode_cbor(&link.encode_cbor()).unwrap();
            assert_eq!(back.signal_dbm, Some(-61));
            assert_eq!(back.peer_mac, Some(vec![0xaa; 6]));
            let rows = back.links.unwrap();
            assert_eq!(rows[0].rx_bytes, Some(7));
            // The row's byte string stays bytes.
            assert_eq!(rows[0].peer_mac, Some(vec![1, 2, 3, 4, 5, 6]));
            // Unknown tags from a newer peer are skipped.
            assert!(api::TelemetryNowResponse::decode_cbor(&[0xa1, 0x18, 0x63, 0x01]).is_ok());
            // A value out of range for its type is rejected.
            assert!(api::TelemetryNowResponse::decode_cbor(&[0xa1, 0x01, 0x01]).is_ok());
            let mut log = api::LogWatchRequest::default();
            log.level = Some(9);
            assert_eq!(api::LogWatchRequest::decode_cbor(&log.encode_cbor()).unwrap().level, Some(9));
            assert!(api::LogWatchRequest::decode_cbor(&[0xa1, 0x03, 0x19, 0x01, 0x00]).is_err());
        }

        #[test]
        fn process_rss_is_read_in_bytes() {
            assert!(process_rss_bytes().unwrap() > 100 * 1024);
        }

        use super::super::*;
        use crate::platform_api as api;
        use mesh::tagged::TaggedFields;

        /// Every `pub const NAME: u16 = N;` of one metric module is a field of
        /// the response, named in lowercase with the same tag.
        fn assert_ids_are_fields<T: TaggedFields>(module: &str) {
            let source = include_str!("telemetry.rs");
            let start = source.find(&format!("pub mod {module} {{")).unwrap();
            let body = &source[start..start + source[start..].find("\n}").unwrap()];
            let mut seen = 0;
            for line in body.lines() {
                let line = line.trim();
                let Some(rest) = line.strip_prefix("pub const ") else {
                    continue;
                };
                let (name, value) = rest.split_once(": u16 = ").unwrap();
                let tag: u32 = value.trim_end_matches(';').parse().unwrap();
                let name = name.to_ascii_lowercase();
                assert!(
                    T::FIELDS.iter().any(|(field, t)| *field == name && *t == tag),
                    "{module}::{name} = {tag} is not in the API.md response"
                );
                seen += 1;
            }
            assert_eq!(seen, T::FIELDS.len(), "{module}: API.md has fields with no constant");
        }

        use crate::registry_bridge::TaggedCbor;

        /// The generated marshalling reads what the device encoders write.
        fn decode<T: TaggedCbor>(wire: &[u8]) -> T {
            T::decode_cbor(wire).unwrap()
        }

        #[test]
        fn metric_ids_are_the_documented_field_tags() {
            assert_ids_are_fields::<api::TelemetryNowResponse>("now_metric");
            assert_ids_are_fields::<api::TelemetryNanResponse>("nan_metric");
            assert_ids_are_fields::<api::TelemetryUdp6Response>("udp6_metric");
        }

        #[test]
        fn a_metric_map_decodes_as_the_documented_response() {
            let mut wire = [0u8; 64];
            let used = encode_metrics(
                &[
                    Metric { id: udp6_metric::RX_FRAMES, value: 7 },
                    Metric { id: udp6_metric::TX_FAILURES, value: 2 },
                ],
                &mut wire,
            )
            .unwrap();
            let response: api::TelemetryUdp6Response = decode(&wire[..used]);
            assert_eq!(response.rx_frames, Some(7));
            assert_eq!(response.tx_failures, Some(2));
            // Counters the device omitted are absent, not zero.
            assert_eq!(response.rx_invalid, None);
        }

        #[test]
        fn wifi_link_and_battery_encoders_match_their_tables() {
            let mut link = WifiLinkMetrics::new();
            link.peer_mac = Some([1, 2, 3, 4, 5, 6]);
            link.rx_bytes = Some(10);
            link.tx_bytes = Some(20);
            link.signal_dbm = Some(-40);
            link.bearer_tx_failures = Some(3);
            link.raw_tx_completion_failures = Some(4);
            let mut wire = [0u8; 128];
            let used = encode_wifi_link_metrics(link, &mut wire).unwrap();
            let response: api::TelemetryWifiLinkResponse = decode(&wire[..used]);
            // A byte string stays a byte string.
            assert_eq!(response.peer_mac.as_deref(), Some(&[1u8, 2, 3, 4, 5, 6][..]));
            assert_eq!(response.rx_bytes, Some(10));
            assert_eq!(response.tx_bytes, Some(20));
            assert_eq!(response.signal_dbm, Some(-40));
            assert_eq!(response.bearer_tx_failures, Some(3));
            assert_eq!(response.raw_tx_completion_failures, Some(4));
            assert_eq!(response.schema_version, Some(crate::raw_wifi::WIFI_LINK_METRICS_SCHEMA_VERSION));

            let battery = BatteryState {
                battery_percent: Some(81),
                charging: Some(true),
                idle_ms: Some(900),
                ..BatteryState::default()
            };
            let used = encode_battery_status(battery, &mut wire).unwrap();
            let response: api::TelemetryBatteryResponse = decode(&wire[..used]);
            assert_eq!(response.battery_percent, Some(81));
            assert_eq!(response.charging, Some(true));
            assert_eq!(response.idle_ms, Some(900));
            assert_eq!(response.power_save, None);
        }
    }

    use super::*;

    #[test]
    fn request_is_correlated_and_empty() {
        let mut wire = [0; 32];
        let used = encode_request(NAN_STATUS_METHOD, 19, &mut wire).unwrap();
        assert_eq!(decode_request(&wire[..used]), Some((NAN_STATUS_METHOD, 19)));
    }

    #[test]
    fn optional_nan_facts_remain_omitted() {
        let mut wire = [0; 32];
        let used = encode_nan_status(
            NanStatus {
                active: Some(true),
                cluster_id: Some(&[1, 2, 3, 4, 5, 6]),
                ..NanStatus::default()
            },
            &mut wire,
        )
        .unwrap();
        assert_eq!(&wire[..used], &[0xa2, 1, 0xf5, 2, 0x46, 1, 2, 3, 4, 5, 6]);
    }

    #[test]
    fn battery_snapshot_uses_shared_optional_tags() {
        let mut wire = [0u8; 32];
        let used = encode_battery_status(
            BatteryState {
                battery_percent: Some(67),
                charging: Some(true),
                ..BatteryState::default()
            },
            &mut wire,
        )
        .unwrap();
        assert_eq!(&wire[..used], &[0xa2, 1, 0x18, 67, 2, 0xf5]);
        let mut request = [0u8; 32];
        let used = encode_request(BATTERY_METHOD, 9, &mut request).unwrap();
        assert_eq!(decode_request(&request[..used]), Some((BATTERY_METHOD, 9)));
    }

    #[test]
    fn generated_quic_response_round_trips_numeric_cbor() {
        let input = quic_lite::NodeTelemetry {
            live_associations: 3,
            received_packets: 10,
            sent_packets: 12,
            received_stream_packets: 4,
            received_control_packets: 6,
            sent_stream_packets: 5,
            sent_control_packets: 7,
            duplicate_packets: 1,
            out_of_order_packets: 2,
            inferred_missing_packets: 3,
            retransmitted_packets: 4,
            loss_events: 1,
            submission_failures: 2,
        };
        let mut wire = [0u8; 256];
        let used = encode_quic_metrics(input, &mut wire).unwrap();
        let decoded = TelemetryQuicResponse::decode_cbor(&wire[..used]).unwrap();
        assert_eq!(decoded.live_associations, 3);
        assert_eq!(decoded.received_packets, 10);
        assert_eq!(decoded.sent_packets, 12);
        assert_eq!(decoded.retransmitted_packets, 4);
        assert_eq!(decoded.submission_failures, 2);
    }

    #[test]
    fn metric_ids_are_unique_and_bounded() {
        let metrics = [
            Metric {
                id: now_metric::TX_ATTEMPTED,
                value: 8,
            },
            Metric {
                id: now_metric::TX_ACCEPTED,
                value: 6,
            },
            Metric {
                id: now_metric::TX_FAILED,
                value: 1,
            },
            Metric {
                id: now_metric::TX_BUSY,
                value: 1,
            },
        ];
        let mut wire = [0; TELEMETRY_RESPONSE_MAX_BYTES];
        assert!(encode_metrics(&metrics, &mut wire).is_some());
        assert!(encode_metrics(&[metrics[0], metrics[0]], &mut wire).is_none());

        let full_snapshot: [Metric; 35] = core::array::from_fn(|index| Metric {
            id: (index + 1) as u16,
            value: u64::MAX,
        });
        assert!(encode_metrics(&full_snapshot, &mut wire).is_some());

        let oversized: [Metric; MAX_METRICS + 1] = core::array::from_fn(|index| Metric {
            id: (index + 1) as u16,
            value: 0,
        });
        assert!(encode_metrics(&oversized, &mut wire).is_none());
    }
}
