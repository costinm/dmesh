//! Wire types, CBOR encoders, and local method/stream dispatch for Android.
//!
//! Android exposes its platform-owned services and shared mesh methods directly
//! over `mesh`, `mesh-api`, `dmesh-discovery`, and `quic-tools`.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, OnceLock, RwLock};
use std::time::Duration;

use async_trait::async_trait;
use mesh::tagged::{NameOrTag, TaggedFields, TaggedRecord};
use mesh::wire::TaggedRecordHandler;
use mesh_api::cbor::{Decoder, Encoder};
use mesh_api::envelope::{
    Name, Record, decode as decode_envelope, encode_error_header, encode_numeric_error,
    encode_numeric_response,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use crate::power::BatteryState;

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

pub const TELEMETRY_METHODS: [u64; 13] = [
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

pub const TELEMETRY_RESPONSE_MAX_BYTES: usize = 512;

pub const DIAGNOSTIC_COMPONENT: u64 = 9;
pub const DIAGNOSTIC_STATUS_METHOD: u64 = 1;
pub const DIAGNOSTIC_SERVICES_METHOD: u64 = 2;

pub const BLE_COMPONENT: u64 = 104;
pub const BLE_SCAN_METHOD: u64 = 82;
pub const BLE_STATUS_METHOD: u64 = 83;
pub const BLE_SCAN_STOP_METHOD: u64 = 84;
pub const BLE_CONNECT_METHOD: u64 = 85;

/// Identity of one registered method.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Method {
    pub component: u64,
    pub component_name: &'static str,
    pub method: u64,
    pub method_name: &'static str,
}

impl Method {
    pub const fn new(
        component: u64,
        component_name: &'static str,
        method: u64,
        method_name: &'static str,
    ) -> Self {
        Self {
            component,
            component_name,
            method,
            method_name,
        }
    }

    /// Presentation name used by `services`, HTTP, and CLI callers.
    pub fn wire_name(&self) -> String {
        if self.component_name.is_empty() {
            self.method_name.to_owned()
        } else {
            format!("{}.{}", self.component_name, self.method_name)
        }
    }
}

pub mod methods {
    use super::*;

    pub const DISCOVERY_NODES: Method = Method::new(
        dmesh_discovery::announce::ANNOUNCE_COMPONENT,
        "discovery",
        dmesh_discovery::announce::ANNOUNCE_DEVICES_OBSERVED,
        "nodes",
    );
    pub const DISCOVERY_ACTIVE: Method = Method::new(
        dmesh_discovery::announce::ANNOUNCE_COMPONENT,
        "discovery",
        dmesh_discovery::announce::ANNOUNCE_DISCOVERY_ACTIVE,
        "active",
    );
    pub const NAN_WAKEUP: Method = Method::new(
        dmesh_discovery::announce::ANNOUNCE_COMPONENT,
        "nan",
        dmesh_discovery::announce::ANNOUNCE_NAN_WAKEUP,
        "wakeup",
    );

    pub const TELEMETRY_NAN_STATUS: Method =
        Method::new(TELEMETRY_COMPONENT, "telemetry", NAN_STATUS_METHOD, "nan_status");
    pub const TELEMETRY_BATTERY: Method =
        Method::new(TELEMETRY_COMPONENT, "telemetry", BATTERY_METHOD, "battery");
    pub const TELEMETRY_QUIC_METRICS: Method =
        Method::new(TELEMETRY_COMPONENT, "telemetry", QUIC_METRICS_METHOD, "quic");
    pub const TELEMETRY_QUIC_ASSOCIATIONS: Method = Method::new(
        TELEMETRY_COMPONENT,
        "telemetry",
        QUIC_ASSOCIATIONS_METHOD,
        "quic_associations",
    );
    pub const TELEMETRY_BEARERS: Method =
        Method::new(TELEMETRY_COMPONENT, "telemetry", BEARERS_METHOD, "bearers");
    pub const TELEMETRY_MEMORY: Method =
        Method::new(TELEMETRY_COMPONENT, "telemetry", MEMORY_METHOD, "memory");
    pub const TELEMETRY_DEVICE: Method =
        Method::new(TELEMETRY_COMPONENT, "telemetry", DEVICE_METHOD, "device");

    pub const STATUS: Method = Method::new(DIAGNOSTIC_COMPONENT, "", DIAGNOSTIC_STATUS_METHOD, "status");
    pub const SERVICES: Method =
        Method::new(DIAGNOSTIC_COMPONENT, "", DIAGNOSTIC_SERVICES_METHOD, "services");

    pub const BLE_SCAN: Method = Method::new(BLE_COMPONENT, "ble", BLE_SCAN_METHOD, "scan");
    pub const BLE_STATUS: Method = Method::new(BLE_COMPONENT, "ble", BLE_STATUS_METHOD, "status");
    pub const BLE_SCAN_STOP: Method =
        Method::new(BLE_COMPONENT, "ble", BLE_SCAN_STOP_METHOD, "scan_stop");
    pub const BLE_CONNECT: Method =
        Method::new(BLE_COMPONENT, "ble", BLE_CONNECT_METHOD, "connect");

    pub const PROBE_START: Method = Method::new(
        quic_tools::PROBE_COMPONENT,
        "probe",
        quic_tools::PROBE_START,
        "start",
    );
    pub const PROBE_HANDLER: Method = Method::new(
        quic_tools::PROBE_COMPONENT,
        "probe",
        quic_tools::PROBE_HANDLER,
        "handler",
    );

    pub const RADIO_HISTORY: Method = Method::new(202, "radio", 1, "history");
    pub const STATUS_TEXT: Method = Method::new(203, "status", 1, "text");
    pub const COMPANION_PAIR: Method = Method::new(209, "companion", 1, "pair");
    pub const COMPANION_UNPAIR: Method = Method::new(209, "companion", 2, "unpair");
}

/// Encode an empty, correlated read request for one telemetry method.
pub fn encode_telemetry_request(method: u64, id: u64, out: &mut [u8]) -> Option<usize> {
    if !TELEMETRY_METHODS.contains(&method) {
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

/// Validate a decoded telemetry read request record.
pub fn decode_telemetry_request_record(record: Record<'_>) -> Option<(u64, u64)> {
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
        Name::Tag(method) if TELEMETRY_METHODS.contains(&method) => method,
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

/// Encode the optional portable battery snapshot (`telemetry.battery`, `7/6`).
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

/// Local NAN runtime snapshot (`telemetry.nan_status`, `7/1`).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct NanStatus<'a> {
    pub active: Option<bool>,
    pub cluster_id: Option<&'a [u8]>,
    pub sync_id: Option<&'a [u8]>,
    pub publishing: Option<bool>,
    pub publish_pending: Option<bool>,
}

/// Encode `NanStatus` as a numeric-tagged CBOR map.
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

/// Current Main identity and infrastructure-link state exposed by `status` (`9/1`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeviceStatus<'a> {
    pub uptime_secs: u64,
    pub sta_enabled: bool,
    pub sta_associated: bool,
    pub sta_bssid: &'a [u8],
    pub sta_ipv4: &'a [u8],
}

/// Encode a correlated compact status response (`9/1`).
pub fn encode_device_status_response(id: u64, status: DeviceStatus<'_>) -> Option<Vec<u8>> {
    if !status.sta_bssid.is_ascii() || !status.sta_ipv4.is_ascii() {
        return None;
    }
    let mut result = [0u8; 224];
    let mut encoder = Encoder::new(&mut result);
    encoder.map(7)?;
    encoder.text_value(b"status")?;
    encoder.text_value(b"ok")?;
    encoder.text_value(b"role")?;
    encoder.text_value(b"main")?;
    encoder.text_value(b"uptime_secs")?;
    encoder.uint(status.uptime_secs)?;
    encoder.text_value(b"sta_enabled")?;
    encoder.boolean(status.sta_enabled)?;
    encoder.text_value(b"sta_associated")?;
    encoder.boolean(status.sta_associated)?;
    encoder.text_value(b"sta_bssid")?;
    encoder.text_value(status.sta_bssid)?;
    encoder.text_value(b"sta_ipv4")?;
    encoder.text_value(status.sta_ipv4)?;
    let result_len = encoder.len();

    let mut response = [0u8; 288];
    let response_len = encode_numeric_response(
        DIAGNOSTIC_COMPONENT,
        DIAGNOSTIC_STATUS_METHOD,
        id,
        &result[..result_len],
        &mut response,
    )?;
    Some(response[..response_len].to_vec())
}

/// Encode a host JSON value as a CBOR value with text object keys.
pub fn encode_json_value(value: &Value, out: &mut [u8]) -> Option<usize> {
    fn encode(encoder: &mut Encoder<'_>, value: &Value) -> Option<()> {
        match value {
            Value::Null => encoder.encoded_value(&[0xf6]),
            Value::Bool(value) => encoder.bool(*value),
            Value::Number(number) => {
                if let Some(value) = number.as_u64() {
                    encoder.uint(value)
                } else {
                    encoder.int(number.as_i64()?)
                }
            }
            Value::String(value) => encoder.text_value(value.as_bytes()),
            Value::Array(items) => {
                encoder.array(items.len() as u64)?;
                for item in items {
                    encode(encoder, item)?;
                }
                Some(())
            }
            Value::Object(fields) => {
                encoder.map(fields.len() as u64)?;
                for (key, item) in fields {
                    encoder.text_value(key.as_bytes())?;
                    encode(encoder, item)?;
                }
                Some(())
            }
        }
    }

    let mut encoder = Encoder::new(out);
    encode(&mut encoder, value)?;
    Some(encoder.len())
}

fn encode_json_value_vec(value: &Value) -> Vec<u8> {
    let mut size = 256;
    loop {
        let mut out = vec![0u8; size];
        if let Some(used) = encode_json_value(value, &mut out) {
            out.truncate(used);
            return out;
        }
        size *= 2;
    }
}

fn grow_encode<F>(mut f: F) -> Vec<u8>
where
    F: FnMut(&mut [u8]) -> Option<usize>,
{
    let mut size = 256;
    loop {
        let mut out = vec![0u8; size];
        if let Some(used) = f(&mut out) {
            out.truncate(used);
            return out;
        }
        size *= 2;
    }
}

/// Aggregate QUIC counters for live associations (`telemetry.quic`, `7/7`).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TelemetryQuicResponse {
    pub live_associations: u64,
    pub received_packets: u64,
    pub sent_packets: u64,
    pub received_stream_packets: u64,
    pub received_control_packets: u64,
    pub sent_stream_packets: u64,
    pub sent_control_packets: u64,
    pub duplicate_packets: u64,
    pub out_of_order_packets: u64,
    pub inferred_missing_packets: u64,
    pub retransmitted_packets: u64,
    pub loss_events: u64,
    pub submission_failures: u64,
}

impl TelemetryQuicResponse {
    pub fn encode_cbor(&self, out: &mut [u8]) -> Option<usize> {
        let mut encoder = Encoder::new(out);
        encoder.map(13)?;
        encoder.uint(1)?;
        encoder.uint(self.live_associations)?;
        encoder.uint(2)?;
        encoder.uint(self.received_packets)?;
        encoder.uint(3)?;
        encoder.uint(self.sent_packets)?;
        encoder.uint(4)?;
        encoder.uint(self.received_stream_packets)?;
        encoder.uint(5)?;
        encoder.uint(self.received_control_packets)?;
        encoder.uint(6)?;
        encoder.uint(self.sent_stream_packets)?;
        encoder.uint(7)?;
        encoder.uint(self.sent_control_packets)?;
        encoder.uint(8)?;
        encoder.uint(self.duplicate_packets)?;
        encoder.uint(9)?;
        encoder.uint(self.out_of_order_packets)?;
        encoder.uint(10)?;
        encoder.uint(self.inferred_missing_packets)?;
        encoder.uint(11)?;
        encoder.uint(self.retransmitted_packets)?;
        encoder.uint(12)?;
        encoder.uint(self.loss_events)?;
        encoder.uint(13)?;
        encoder.uint(self.submission_failures)?;
        Some(encoder.len())
    }
}

/// Per-association QUIC telemetry row (`telemetry.quic_associations`, `7/8`).
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
pub struct QuicAssociation {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub association: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bearer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub received_packets: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sent_packets: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retransmitted_packets: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub loss_events: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub submission_failures: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes_in_flight: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer_max_data: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer_sent_data: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub largest_acked_by_peer: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub streams_local_active: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub streams_peer_active: Option<u64>,
}

impl TaggedFields for QuicAssociation {
    const FIELDS: &'static [(&'static str, u32)] = &[
        ("association", 1),
        ("bearer", 2),
        ("peer", 3),
        ("received_packets", 4),
        ("sent_packets", 5),
        ("retransmitted_packets", 6),
        ("loss_events", 7),
        ("submission_failures", 8),
        ("bytes_in_flight", 9),
        ("peer_max_data", 10),
        ("peer_sent_data", 11),
        ("largest_acked_by_peer", 12),
        ("streams_local_active", 13),
        ("streams_peer_active", 14),
    ];
}

impl QuicAssociation {
    pub fn encode_cbor_into(&self, e: &mut Encoder<'_>) -> Option<()> {
        let count = u64::from(self.association.is_some())
            + u64::from(self.bearer.is_some())
            + u64::from(self.peer.is_some())
            + u64::from(self.received_packets.is_some())
            + u64::from(self.sent_packets.is_some())
            + u64::from(self.retransmitted_packets.is_some())
            + u64::from(self.loss_events.is_some())
            + u64::from(self.submission_failures.is_some())
            + u64::from(self.bytes_in_flight.is_some())
            + u64::from(self.peer_max_data.is_some())
            + u64::from(self.peer_sent_data.is_some())
            + u64::from(self.largest_acked_by_peer.is_some())
            + u64::from(self.streams_local_active.is_some())
            + u64::from(self.streams_peer_active.is_some());
        e.map(count)?;
        if let Some(v) = self.association {
            e.uint(1)?;
            e.uint(v)?;
        }
        if let Some(v) = &self.bearer {
            e.uint(2)?;
            e.text_value(v.as_bytes())?;
        }
        if let Some(v) = &self.peer {
            e.uint(3)?;
            e.text_value(v.as_bytes())?;
        }
        if let Some(v) = self.received_packets {
            e.uint(4)?;
            e.uint(v)?;
        }
        if let Some(v) = self.sent_packets {
            e.uint(5)?;
            e.uint(v)?;
        }
        if let Some(v) = self.retransmitted_packets {
            e.uint(6)?;
            e.uint(v)?;
        }
        if let Some(v) = self.loss_events {
            e.uint(7)?;
            e.uint(v)?;
        }
        if let Some(v) = self.submission_failures {
            e.uint(8)?;
            e.uint(v)?;
        }
        if let Some(v) = self.bytes_in_flight {
            e.uint(9)?;
            e.uint(v)?;
        }
        if let Some(v) = self.peer_max_data {
            e.uint(10)?;
            e.uint(v)?;
        }
        if let Some(v) = self.peer_sent_data {
            e.uint(11)?;
            e.uint(v)?;
        }
        if let Some(v) = self.largest_acked_by_peer {
            e.uint(12)?;
            e.uint(u64::from(v))?;
        }
        if let Some(v) = self.streams_local_active {
            e.uint(13)?;
            e.uint(v)?;
        }
        if let Some(v) = self.streams_peer_active {
            e.uint(14)?;
            e.uint(v)?;
        }
        Some(())
    }
}

pub fn encode_quic_associations_response(associations: &[QuicAssociation]) -> Vec<u8> {
    grow_encode(|out| {
        let mut e = Encoder::new(out);
        e.map(1)?;
        e.uint(1)?;
        e.array(associations.len() as u64)?;
        for assoc in associations {
            assoc.encode_cbor_into(&mut e)?;
        }
        Some(e.len())
    })
}

/// Per-bearer packet counters (`telemetry.bearers`, `7/9`).
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
pub struct BearerCounters {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tx_submitted: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tx_accepted: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tx_failed: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tx_busy: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rx_packets: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rx_rejected: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rx_dropped: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub queue_depth: Option<u32>,
}

impl TaggedFields for BearerCounters {
    const FIELDS: &'static [(&'static str, u32)] = &[
        ("name", 1),
        ("state", 2),
        ("tx_submitted", 3),
        ("tx_accepted", 4),
        ("tx_failed", 5),
        ("tx_busy", 6),
        ("rx_packets", 7),
        ("rx_rejected", 8),
        ("rx_dropped", 9),
        ("queue_depth", 10),
    ];
}

impl BearerCounters {
    pub fn encode_cbor_into(&self, e: &mut Encoder<'_>) -> Option<()> {
        let count = u64::from(self.name.is_some())
            + u64::from(self.state.is_some())
            + u64::from(self.tx_submitted.is_some())
            + u64::from(self.tx_accepted.is_some())
            + u64::from(self.tx_failed.is_some())
            + u64::from(self.tx_busy.is_some())
            + u64::from(self.rx_packets.is_some())
            + u64::from(self.rx_rejected.is_some())
            + u64::from(self.rx_dropped.is_some())
            + u64::from(self.queue_depth.is_some());
        e.map(count)?;
        if let Some(v) = &self.name {
            e.uint(1)?;
            e.text_value(v.as_bytes())?;
        }
        if let Some(v) = self.state {
            e.uint(2)?;
            e.uint(u64::from(v))?;
        }
        if let Some(v) = self.tx_submitted {
            e.uint(3)?;
            e.uint(v)?;
        }
        if let Some(v) = self.tx_accepted {
            e.uint(4)?;
            e.uint(v)?;
        }
        if let Some(v) = self.tx_failed {
            e.uint(5)?;
            e.uint(v)?;
        }
        if let Some(v) = self.tx_busy {
            e.uint(6)?;
            e.uint(v)?;
        }
        if let Some(v) = self.rx_packets {
            e.uint(7)?;
            e.uint(v)?;
        }
        if let Some(v) = self.rx_rejected {
            e.uint(8)?;
            e.uint(v)?;
        }
        if let Some(v) = self.rx_dropped {
            e.uint(9)?;
            e.uint(v)?;
        }
        if let Some(v) = self.queue_depth {
            e.uint(10)?;
            e.uint(u64::from(v))?;
        }
        Some(())
    }
}

pub fn encode_bearers_response(bearers: &[BearerCounters]) -> Vec<u8> {
    grow_encode(|out| {
        let mut e = Encoder::new(out);
        e.map(1)?;
        e.uint(1)?;
        e.array(bearers.len() as u64)?;
        for bearer in bearers {
            bearer.encode_cbor_into(&mut e)?;
        }
        Some(e.len())
    })
}

/// Encode `telemetry.memory` (`7/10`) with `process_rss_bytes` (tag `12`).
pub fn encode_memory_response(process_rss_bytes: u64) -> Vec<u8> {
    let mut out = [0u8; 24];
    let mut e = Encoder::new(&mut out);
    e.map(1).expect("memory buffer");
    e.uint(12).expect("memory buffer");
    e.uint(process_rss_bytes).expect("memory buffer");
    let used = e.len();
    out[..used].to_vec()
}

/// `status.text` (`203/1`) response.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
pub struct StatusTextResponse {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_text: Option<String>,
}

impl TaggedFields for StatusTextResponse {
    const FIELDS: &'static [(&'static str, u32)] = &[("status_text", 1)];
}

impl StatusTextResponse {
    pub fn encode_cbor(&self) -> Vec<u8> {
        grow_encode(|out| {
            let mut e = Encoder::new(out);
            e.map(u64::from(self.status_text.is_some()))?;
            if let Some(text) = &self.status_text {
                e.uint(1)?;
                e.text_value(text.as_bytes())?;
            }
            Some(e.len())
        })
    }
}

/// `radio.history` (`202/1`) request.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
pub struct RadioHistoryRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keys: Option<String>,
}

impl TaggedFields for RadioHistoryRequest {
    const FIELDS: &'static [(&'static str, u32)] =
        &[("limit", 1), ("since_ms", 2), ("keys", 3)];
}

impl RadioHistoryRequest {
    pub fn decode_cbor(input: &[u8]) -> Result<Self, String> {
        let mut d = Decoder::new(input);
        let (major, count) = d.head().ok_or("not a CBOR map")?;
        if major != 5 {
            return Err("not a CBOR map".to_owned());
        }
        let mut out = Self::default();
        for _ in 0..count {
            let tag = d.uint().ok_or("invalid field tag")?;
            match tag {
                1 => out.limit = Some(d.uint().ok_or("invalid unsigned integer")?),
                2 => out.since_ms = Some(d.uint().ok_or("invalid unsigned integer")?),
                3 => {
                    let bytes = d.text_ref().ok_or("invalid text")?.to_vec();
                    out.keys = Some(String::from_utf8(bytes).map_err(|_| "invalid UTF-8")?);
                }
                _ => d.skip().ok_or("invalid value")?,
            }
        }
        Ok(out)
    }
}

/// Encode the JSON output of `android_radio_history` into the tag-keyed CBOR map
/// of `radio.history` (`1`: `events`, `2`: `followups`, `3`: `ble_scan_results`, `4`: `count`).
pub fn encode_radio_history_value(history: &Value) -> Result<Vec<u8>, String> {
    let events: Vec<Vec<u8>> = history
        .get("events")
        .and_then(Value::as_array)
        .map(|items| items.iter().map(encode_json_value_vec).collect())
        .ok_or_else(|| "radio.history missing events array".to_owned())?;
    let followups: Vec<Vec<u8>> = history
        .get("followups")
        .and_then(Value::as_array)
        .map(|items| items.iter().map(encode_json_value_vec).collect())
        .ok_or_else(|| "radio.history missing followups array".to_owned())?;
    let ble_scan = history
        .get("ble_scan_results")
        .map(encode_json_value_vec)
        .ok_or_else(|| "radio.history missing ble_scan_results".to_owned())?;
    let count = history
        .get("count")
        .and_then(Value::as_u64)
        .unwrap_or((events.len() + followups.len()) as u64);

    Ok(grow_encode(|out| {
        let mut e = Encoder::new(out);
        e.map(4)?;
        e.uint(1)?;
        e.array(events.len() as u64)?;
        for item in &events {
            e.encoded_value(item)?;
        }
        e.uint(2)?;
        e.array(followups.len() as u64)?;
        for item in &followups {
            e.encoded_value(item)?;
        }
        e.uint(3)?;
        e.encoded_value(&ble_scan)?;
        e.uint(4)?;
        e.uint(count)?;
        Some(e.len())
    }))
}

/// Decode `companion.pair` (`209/1`) CBOR fields into [`dmesh_discovery::controller::PairInput`].
pub fn decode_companion_pair_cbor(
    input: &[u8],
) -> Result<dmesh_discovery::controller::PairInput, String> {
    let mut d = Decoder::new(input);
    let (major, count) = d.head().ok_or("not a CBOR map")?;
    if major != 5 {
        return Err("not a CBOR map".to_owned());
    }
    let mut out = dmesh_discovery::controller::PairInput::default();
    for _ in 0..count {
        let tag = d.uint().ok_or("invalid field tag")?;
        match tag {
            1 => {
                out.kind = Some(
                    String::from_utf8(d.text_ref().ok_or("invalid text")?.to_vec())
                        .map_err(|_| "invalid UTF-8")?,
                );
            }
            2 => {
                out.id = Some(
                    String::from_utf8(d.text_ref().ok_or("invalid text")?.to_vec())
                        .map_err(|_| "invalid UTF-8")?,
                );
            }
            3 => {
                out.vip6 = Some(
                    String::from_utf8(d.text_ref().ok_or("invalid text")?.to_vec())
                        .map_err(|_| "invalid UTF-8")?,
                );
            }
            4 => {
                out.baud = Some(
                    u32::try_from(d.uint().ok_or("invalid unsigned integer")?)
                        .map_err(|_| "baud out of range")?,
                );
            }
            5 => {
                out.psm = Some(
                    u16::try_from(d.uint().ok_or("invalid unsigned integer")?)
                        .map_err(|_| "psm out of range")?,
                );
            }
            6 => {
                out.name = Some(
                    String::from_utf8(d.text_ref().ok_or("invalid text")?.to_vec())
                        .map_err(|_| "invalid UTF-8")?,
                );
            }
            7 => {
                out.root_public_key_b64 = Some(
                    String::from_utf8(d.text_ref().ok_or("invalid text")?.to_vec())
                        .map_err(|_| "invalid UTF-8")?,
                );
            }
            _ => d.skip().ok_or("invalid value")?,
        }
    }
    Ok(out)
}

/// Decode `companion.unpair` (`209/2`) CBOR fields into [`dmesh_discovery::controller::UnpairInput`].
pub fn decode_companion_unpair_cbor(
    input: &[u8],
) -> Result<dmesh_discovery::controller::UnpairInput, String> {
    let mut d = Decoder::new(input);
    let (major, count) = d.head().ok_or("not a CBOR map")?;
    if major != 5 {
        return Err("not a CBOR map".to_owned());
    }
    let mut out = dmesh_discovery::controller::UnpairInput::default();
    for _ in 0..count {
        let tag = d.uint().ok_or("invalid field tag")?;
        match tag {
            1 => {
                out.kind = Some(
                    String::from_utf8(d.text_ref().ok_or("invalid text")?.to_vec())
                        .map_err(|_| "invalid UTF-8")?,
                );
            }
            2 => {
                out.id = Some(
                    String::from_utf8(d.text_ref().ok_or("invalid text")?.to_vec())
                        .map_err(|_| "invalid UTF-8")?,
                );
            }
            _ => d.skip().ok_or("invalid value")?,
        }
    }
    Ok(out)
}

/// Correlated success or error response helper for `component`/`method`.
pub fn encode_result_or_error(
    component: u64,
    method: u64,
    id: u64,
    outcome: Result<Vec<u8>, String>,
) -> Option<Vec<u8>> {
    match outcome {
        Ok(result) => {
            let mut out = vec![0u8; result.len() + 48];
            let used = encode_numeric_response(component, method, id, &result, &mut out)?;
            out.truncate(used);
            Some(out)
        }
        Err(message) => {
            let mut out = vec![0u8; message.len() + 48];
            let used = encode_numeric_error(component, method, id, message.as_bytes(), &mut out)?;
            out.truncate(used);
            Some(out)
        }
    }
}

pub type UnaryReply = Pin<Box<dyn Future<Output = Option<Vec<u8>>> + Send>>;

pub trait UnaryHandler: Send + Sync + 'static {
    fn call(&self, request: &[u8], timeout_ms: Option<u64>) -> UnaryReply;
}

#[derive(Clone, Copy)]
pub struct SyncBytesFn(pub fn(&[u8]) -> Option<Vec<u8>>);

impl UnaryHandler for SyncBytesFn {
    fn call(&self, request: &[u8], _timeout_ms: Option<u64>) -> UnaryReply {
        let response = (self.0)(request);
        Box::pin(std::future::ready(response))
    }
}

pub struct AsyncUnaryFn<F>(F);

impl<F> AsyncUnaryFn<F>
where
    F: Fn(Vec<u8>, Option<u64>) -> UnaryReply + Send + Sync + 'static,
{
    pub fn new(handler: F) -> Self {
        Self(handler)
    }
}

impl<F> UnaryHandler for AsyncUnaryFn<F>
where
    F: Fn(Vec<u8>, Option<u64>) -> UnaryReply + Send + Sync + 'static,
{
    fn call(&self, request: &[u8], timeout_ms: Option<u64>) -> UnaryReply {
        (self.0)(request.to_vec(), timeout_ms)
    }
}

pub trait AsyncStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + ?Sized> AsyncStream for T {}

pub trait StreamMethodHandler: Send + Sync + 'static {
    fn serve<'a>(
        &'a self,
        raw_header: &'a [u8],
        stream: &'a mut dyn AsyncStream,
    ) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + 'a>>;
}

/// Shared `probe.handler` (`8/2`) stream adapter backed by `quic-tools`.
pub struct ProbeStreamHandler;

impl StreamMethodHandler for ProbeStreamHandler {
    fn serve<'a>(
        &'a self,
        raw_header: &'a [u8],
        stream: &'a mut dyn AsyncStream,
    ) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + 'a>> {
        Box::pin(async move {
            let Some(record) = decode_envelope(raw_header) else {
                stream
                    .write_all(&encode_error_header(None, b"invalid request header"))
                    .await?;
                return stream.shutdown().await;
            };
            let Some(id) = record.id else {
                return stream.shutdown().await;
            };
            quic_tools::serve_framed_probe_stream(id, record.fields, stream).await
        })
    }
}

#[derive(Clone)]
enum HandlerKind {
    Unary(Arc<dyn UnaryHandler>),
    Stream(Arc<dyn StreamMethodHandler>),
}

#[derive(Clone)]
struct RouterEntry {
    method: Method,
    local_only: bool,
    kind: HandlerKind,
}

/// Method and stream router for Android's numbered mesh surface.
#[derive(Default)]
pub struct AndroidRouter {
    entries: RwLock<Vec<RouterEntry>>,
}

static GLOBAL_ROUTER: OnceLock<AndroidRouter> = OnceLock::new();

pub fn global_router() -> &'static AndroidRouter {
    GLOBAL_ROUTER.get_or_init(AndroidRouter::new)
}

impl AndroidRouter {
    pub fn new() -> Self {
        Self {
            entries: RwLock::new(Vec::new()),
        }
    }

    pub fn register(&self, method: Method, handler: impl UnaryHandler) -> bool {
        self.insert(method, false, HandlerKind::Unary(Arc::new(handler)))
    }

    pub fn register_local_only(&self, method: Method, handler: impl UnaryHandler) -> bool {
        self.insert(method, true, HandlerKind::Unary(Arc::new(handler)))
    }

    pub fn register_all<H: UnaryHandler + Clone>(&self, methods: &[Method], handler: H) -> bool {
        let mut all_ok = true;
        for method in methods {
            all_ok &= self.register(*method, handler.clone());
        }
        all_ok
    }

    pub fn register_stream(&self, method: Method, handler: impl StreamMethodHandler) -> bool {
        self.insert(method, false, HandlerKind::Stream(Arc::new(handler)))
    }

    fn insert(&self, method: Method, local_only: bool, kind: HandlerKind) -> bool {
        if method.component == 0 {
            return false;
        }
        let mut guard = self
            .entries
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if guard.iter().any(|entry| {
            entry.method.component == method.component && entry.method.method == method.method
        }) {
            return false;
        }
        guard.push(RouterEntry {
            method,
            local_only,
            kind,
        });
        true
    }

    fn lookup(&self, component: u64, method: u64) -> Option<RouterEntry> {
        let guard = self
            .entries
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard
            .iter()
            .find(|entry| entry.method.component == component && entry.method.method == method)
            .cloned()
    }

    fn resolve_named(&self, component: &NameOrTag, method: &NameOrTag) -> Option<(u32, u32)> {
        let guard = self
            .entries
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        for entry in guard.iter() {
            let comp_matches = match component {
                NameOrTag::Tag(tag) => u64::from(*tag) == entry.method.component,
                NameOrTag::Name(name) => {
                    name == entry.method.component_name
                        || (entry.method.component_name.is_empty()
                            && name == entry.method.method_name)
                }
            };
            let wire_name = entry.method.wire_name();
            let meth_matches = match method {
                NameOrTag::Tag(tag) => u64::from(*tag) == entry.method.method,
                NameOrTag::Name(name) => name == entry.method.method_name || name == &wire_name,
            };
            if comp_matches && meth_matches {
                return Some((
                    u32::try_from(entry.method.component).ok()?,
                    u32::try_from(entry.method.method).ok()?,
                ));
            }
        }
        None
    }

    /// Sorted, deduplicated `[[component, method, "wire_name"], ...]` CBOR array for `services` (`9/2`).
    pub fn encode_service_catalog(&self) -> Vec<u8> {
        let mut methods: Vec<Method> = {
            let guard = self
                .entries
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            guard.iter().map(|entry| entry.method).collect()
        };
        methods.sort_by_key(|m| (m.component, m.method));
        methods.dedup_by_key(|m| (m.component, m.method));
        let names: Vec<String> = methods.iter().map(Method::wire_name).collect();
        let capacity = 9
            + names
                .iter()
                .map(|name| 1 + 9 + 9 + 9 + name.len())
                .sum::<usize>();
        let mut output = vec![0u8; capacity];
        let mut encoder = Encoder::new(&mut output);
        encoder
            .array(methods.len() as u64)
            .expect("service catalog capacity");
        for (method, name) in methods.iter().zip(&names) {
            encoder.array(3).expect("service catalog capacity");
            encoder
                .uint(method.component)
                .expect("service catalog capacity");
            encoder
                .uint(method.method)
                .expect("service catalog capacity");
            encoder
                .text_value(name.as_bytes())
                .expect("service catalog capacity");
        }
        let used = encoder.len();
        output.truncate(used);
        output
    }

    /// Dispatch a unary header-only request buffer.
    pub async fn dispatch(&self, data: &[u8], local: bool) -> Option<Vec<u8>> {
        let record = decode_envelope(data)?;
        if record.to.is_some() {
            return None;
        }
        let (Name::Tag(component), Name::Tag(method)) = (record.component?, record.method?) else {
            return None;
        };
        let timeout_ms = record.timeout;
        let id = record.id;
        if let Some(entry) = self.lookup(component, method)
            && (!entry.local_only || local)
        {
            match entry.kind {
                HandlerKind::Unary(handler) => {
                    if let Some(response) = handler.call(data, timeout_ms).await {
                        return Some(response);
                    }
                }
                HandlerKind::Stream(_) => {
                    return numeric_error_vec(
                        component,
                        method,
                        id?,
                        b"method requires a stream body",
                    );
                }
            }
        }
        numeric_error_vec(
            component,
            method,
            id?,
            b"unsupported or invalid stream request",
        )
    }

    /// Serve one accepted bidirectional stream (`local = false` for network peers).
    pub async fn serve_stream<S>(&self, mut stream: S, local: bool) -> io::Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let (envelope, mut framed) = match mesh::read_envelope_prefix(&mut stream).await {
            Ok(parts) => parts,
            Err(_) => {
                stream
                    .write_all(&encode_error_header(None, b"invalid request header"))
                    .await?;
                return stream.shutdown().await;
            }
        };
        let Some(record) = envelope.record() else {
            framed
                .write_all(&encode_error_header(None, b"invalid request header"))
                .await?;
            return framed.shutdown().await;
        };
        if record.to.is_some() {
            return framed.shutdown().await;
        }
        let (Some(Name::Tag(component)), Some(Name::Tag(method))) =
            (record.component, record.method)
        else {
            return framed.shutdown().await;
        };
        let id = record.id;
        let timeout_ms = record.timeout;
        let raw_header = envelope.raw_header;
        let entry = self
            .lookup(component, method)
            .filter(|entry| !entry.local_only || local);

        let exchange = async {
            match entry.map(|e| e.kind) {
                Some(HandlerKind::Unary(handler)) => {
                    match handler.call(&raw_header, timeout_ms).await {
                        Some(response) => {
                            framed.write_all(&response).await?;
                            framed.shutdown().await
                        }
                        None => write_unsupported_and_close(&mut framed, component, method, id).await,
                    }
                }
                Some(HandlerKind::Stream(handler)) => handler.serve(&raw_header, &mut framed).await,
                None => write_unsupported_and_close(&mut framed, component, method, id).await,
            }
        };

        match timeout_ms.map(Duration::from_millis) {
            None => exchange.await,
            Some(limit) => match tokio::time::timeout(limit, exchange).await {
                Ok(result) => result,
                Err(_) => {
                    framed
                        .write_all(&encode_error_header(id, b"timeout"))
                        .await?;
                    framed.shutdown().await
                }
            },
        }
    }
}

pub fn numeric_error_vec(
    component: u64,
    method: u64,
    id: u64,
    message: &[u8],
) -> Option<Vec<u8>> {
    let mut out = vec![0u8; message.len() + 48];
    let used = encode_numeric_error(component, method, id, message, &mut out)?;
    out.truncate(used);
    Some(out)
}

async fn write_unsupported_and_close<S>(
    stream: &mut S,
    component: u64,
    method: u64,
    id: Option<u64>,
) -> io::Result<()>
where
    S: AsyncWrite + Unpin + ?Sized,
{
    if let Some(id) = id
        && let Some(err) = numeric_error_vec(
            component,
            method,
            id,
            b"unsupported or invalid stream request",
        )
    {
        stream.write_all(&err).await?;
    }
    stream.shutdown().await
}

/// Local gateway `TaggedRecordHandler` bridging `ssh_mesh::mesh_rest::MeshServiceRegistry`
/// to [`AndroidRouter`] with `local = true`.
#[derive(Clone, Default)]
pub struct AndroidGatewayHandler {
    router: Option<Arc<AndroidRouter>>,
}

impl AndroidGatewayHandler {
    pub fn global() -> Self {
        Self { router: None }
    }

    pub fn new(router: Arc<AndroidRouter>) -> Self {
        Self {
            router: Some(router),
        }
    }

    fn router(&self) -> &AndroidRouter {
        match &self.router {
            Some(router) => router,
            None => global_router(),
        }
    }
}

#[async_trait]
impl TaggedRecordHandler for AndroidGatewayHandler {
    async fn handle_record(&self, mut record: TaggedRecord) -> anyhow::Result<Option<TaggedRecord>> {
        let router = self.router();
        if (!matches!(record.component, NameOrTag::Tag(_))
            || !matches!(record.method, NameOrTag::Tag(_)))
            && let Some((comp, meth)) = router.resolve_named(&record.component, &record.method)
        {
            record.component = NameOrTag::Tag(comp);
            record.method = NameOrTag::Tag(meth);
        }
        let original_id = record.id.clone();
        let needs_id_restore = match &record.id {
            Some(v) => v.as_u64().is_none(),
            None => false,
        };
        if needs_id_restore {
            record.id = Some(serde_json::json!(1));
        }
        let request = mesh::cbor::encode_record(&record)?;
        match router.dispatch(&request, true).await {
            Some(bytes) => {
                let mut decoded = mesh::cbor::decode_record(&bytes)?;
                if needs_id_restore {
                    decoded.id = original_id;
                }
                Ok(Some(decoded))
            }
            None => Ok(None),
        }
    }
}

/// Register `companion.pair` (`209/1`) and `companion.unpair` (`209/2`) as local-only
/// control methods backed by [`dmesh_discovery::controller::Controllers`].
pub fn register_companion_local_only(
    controllers: Arc<dmesh_discovery::controller::Controllers>,
    router: &AndroidRouter,
) {
    let pair_controllers = controllers.clone();
    router.register_local_only(
        methods::COMPANION_PAIR,
        AsyncUnaryFn::new(move |request, _timeout_ms| {
            let controllers = pair_controllers.clone();
            Box::pin(async move {
                let record = decode_envelope(&request)?;
                let id = record.id?;
                let outcome = match decode_companion_pair_cbor(record.fields.unwrap_or(&[0xa0])) {
                    Ok(input) => controllers
                        .pair_input(&input)
                        .await
                        .map(|()| vec![0xa0]),
                    Err(err) => Err(format!("invalid request: {err}")),
                };
                encode_result_or_error(
                    methods::COMPANION_PAIR.component,
                    methods::COMPANION_PAIR.method,
                    id,
                    outcome,
                )
            })
        }),
    );

    router.register_local_only(
        methods::COMPANION_UNPAIR,
        AsyncUnaryFn::new(move |request, _timeout_ms| {
            let controllers = controllers.clone();
            Box::pin(async move {
                let record = decode_envelope(&request)?;
                let id = record.id?;
                let outcome = match decode_companion_unpair_cbor(record.fields.unwrap_or(&[0xa0])) {
                    Ok(input) => controllers
                        .unpair_input(&input)
                        .await
                        .map(|()| vec![0xa0]),
                    Err(err) => Err(format!("invalid request: {err}")),
                };
                encode_result_or_error(
                    methods::COMPANION_UNPAIR.component,
                    methods::COMPANION_UNPAIR.method,
                    id,
                    outcome,
                )
            })
        }),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn router_enforces_local_only_and_serves_gateway_and_streams() {
        let router = Arc::new(AndroidRouter::new());
        assert!(router.register(
            methods::STATUS,
            SyncBytesFn(|request| {
                let record = decode_envelope(request)?;
                encode_device_status_response(
                    record.id?,
                    DeviceStatus {
                        uptime_secs: 42,
                        sta_enabled: false,
                        sta_associated: false,
                        sta_bssid: b"unavailable",
                        sta_ipv4: b"unavailable",
                    },
                )
            }),
        ));
        let router_for_services = router.clone();
        assert!(router.register(
            methods::SERVICES,
            AsyncUnaryFn::new(move |request, _| {
                let router = router_for_services.clone();
                Box::pin(async move {
                    let record = decode_envelope(&request)?;
                    encode_result_or_error(
                        DIAGNOSTIC_COMPONENT,
                        DIAGNOSTIC_SERVICES_METHOD,
                        record.id?,
                        Ok(router.encode_service_catalog()),
                    )
                })
            }),
        ));
        assert!(router.register_local_only(
            methods::STATUS_TEXT,
            SyncBytesFn(|request| {
                let record = decode_envelope(request)?;
                encode_result_or_error(
                    methods::STATUS_TEXT.component,
                    methods::STATUS_TEXT.method,
                    record.id?,
                    Ok(StatusTextResponse {
                        status_text: Some("DMesh nodes 0".to_owned()),
                    }
                    .encode_cbor()),
                )
            }),
        ));
        assert!(router.register_stream(methods::PROBE_HANDLER, ProbeStreamHandler));

        // Gateway handler resolves named local-only requests (`status.text`).
        let gateway = AndroidGatewayHandler::new(router.clone());
        let resp = gateway
            .handle_record(TaggedRecord {
                component: NameOrTag::Name("status".to_owned()),
                method: NameOrTag::Name("text".to_owned()),
                id: Some(json!("req-1")),
                ..Default::default()
            })
            .await
            .unwrap()
            .unwrap();
        assert_eq!(resp.id, Some(json!("req-1")));
        assert_eq!(resp.result.unwrap()["1"], "DMesh nodes 0");

        // Network stream caller (`local = false`) is denied `status.text` with numeric error.
        let (mut client, server) = tokio::io::duplex(512);
        let server_router = router.clone();
        let server_task = tokio::spawn(async move {
            server_router.serve_stream(server, false).await.unwrap();
        });
        let mut req_buf = [0u8; 64];
        let req_len = mesh_api::envelope::encode_numeric_empty_request(
            methods::STATUS_TEXT.component,
            methods::STATUS_TEXT.method,
            11,
            &mut req_buf,
        )
        .unwrap();
        let raw_reply = quic_tools::exchange(&mut client, &[&req_buf[..req_len]])
            .await
            .unwrap();
        server_task.await.unwrap();
        let decoded = decode_envelope(&raw_reply).unwrap();
        assert_eq!(decoded.id, Some(11));
        assert!(decoded.error.is_some());

        // Service catalog (`9/2`) lists registered methods sorted by (component, method).
        let catalog = router.encode_service_catalog();
        let mut d = Decoder::new(&catalog);
        assert_eq!(d.head(), Some((4, 4)));
    }

    #[test]
    fn radio_history_and_telemetry_encoders_emit_documented_tags() {
        let history = json!({
            "events": [{"kind": "event", "peer": "aa:bb"}],
            "followups": [],
            "ble_scan_results": {"results": [], "count": 0},
            "count": 1
        });
        let encoded = encode_radio_history_value(&history).unwrap();
        let mut d = Decoder::new(&encoded);
        assert_eq!(d.head(), Some((5, 4)));
        assert_eq!(d.uint(), Some(1));
        assert_eq!(d.head(), Some((4, 1)));
        d.skip().unwrap();
        assert_eq!(d.uint(), Some(2));
        assert_eq!(d.head(), Some((4, 0)));
        assert_eq!(d.uint(), Some(3));
        d.skip().unwrap();
        assert_eq!(d.uint(), Some(4));
        assert_eq!(d.uint(), Some(1));
        assert!(d.is_finished());

        let mut quic_buf = [0u8; 128];
        let quic = TelemetryQuicResponse {
            live_associations: 2,
            received_packets: 10,
            sent_packets: 12,
            ..Default::default()
        };
        let used = quic.encode_cbor(&mut quic_buf).unwrap();
        let mut qd = Decoder::new(&quic_buf[..used]);
        assert_eq!(qd.head(), Some((5, 13)));
        assert_eq!(qd.uint(), Some(1));
        assert_eq!(qd.uint(), Some(2));

        let assocs = encode_quic_associations_response(&[QuicAssociation {
            association: Some(1),
            bearer: Some("udp".to_owned()),
            ..Default::default()
        }]);
        let mut ad = Decoder::new(&assocs);
        assert_eq!(ad.head(), Some((5, 1)));
        assert_eq!(ad.uint(), Some(1));
        assert_eq!(ad.head(), Some((4, 1)));

        let bearers = encode_bearers_response(&[BearerCounters {
            name: Some("usb".to_owned()),
            state: Some(1),
            ..Default::default()
        }]);
        let mut bd = Decoder::new(&bearers);
        assert_eq!(bd.head(), Some((5, 1)));
        assert_eq!(bd.uint(), Some(1));
        assert_eq!(bd.head(), Some((4, 1)));

        let mem = encode_memory_response(4096);
        let mut md = Decoder::new(&mem);
        assert_eq!(md.head(), Some((5, 1)));
        assert_eq!(md.uint(), Some(12));
        assert_eq!(md.uint(), Some(4096));
    }
}
