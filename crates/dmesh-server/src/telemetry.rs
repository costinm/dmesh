//! Cross-platform discovery-runtime status and transport-owned metrics.
//!
//! These records deliberately contain no interface names, Linux process
//! state, or peer inventory. `announce::ANNOUNCE_DEVICES_OBSERVED` owns peer
//! observations; this component explains the local adapter/runtime instead.

use crate::{
    cbor::{Decoder, Encoder},
    raw_wifi::WifiLinkMetrics,
    tagged::{Name, decode},
};

pub const TELEMETRY_COMPONENT: u64 = 7;
pub const NAN_STATUS_METHOD: u64 = 1;
pub const NOW_METRICS_METHOD: u64 = 2;
pub const NAN_METRICS_METHOD: u64 = 3;
pub const UDP6_METRICS_METHOD: u64 = 4;
pub const WIFI_LINK_METRICS_METHOD: u64 = 5;
pub const TELEMETRY_RESPONSE_MAX_BYTES: usize = 512;

pub mod now_metric {
    pub const TX_ATTEMPTED: u16 = 1;
    pub const TX_ACCEPTED: u16 = 2;
    pub const TX_FAILED: u16 = 3;
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
    if !matches!(
        method,
        NAN_STATUS_METHOD
            | NOW_METRICS_METHOD
            | NAN_METRICS_METHOD
            | UDP6_METRICS_METHOD
            | WIFI_LINK_METRICS_METHOD
    ) {
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
        Name::Tag(method)
            if matches!(
                method,
                NAN_STATUS_METHOD
                    | NOW_METRICS_METHOD
                    | NAN_METRICS_METHOD
                    | UDP6_METRICS_METHOD
                    | WIFI_LINK_METRICS_METHOD
            ) =>
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
    if metrics.len() > 32 {
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

#[cfg(test)]
mod tests {
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
    fn metric_ids_are_unique_and_bounded() {
        let metrics = [Metric { id: 1, value: 2 }, Metric { id: 3, value: 5 }];
        let mut wire = [0; 32];
        assert!(encode_metrics(&metrics, &mut wire).is_some());
        assert!(encode_metrics(&[metrics[0], metrics[0]], &mut wire).is_none());
    }
}
