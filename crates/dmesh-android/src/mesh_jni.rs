//! JNI bindings for the mesh node.
//!
//! This module provides Java/Android bindings via JNI. All core logic
//! is delegated to [`crate::mesh_common`]; this module handles only
//! JNI-specific marshalling (JString ↔ Rust String, jlong ↔ pointer casts)
//! and callback plumbing.
//!
//! See also:
//! - Java wrapper: `android/app-dmesh/src/main/java/...`

#[cfg(target_os = "android")]
use anyhow::Context;
#[cfg(target_os = "android")]
use async_trait::async_trait;
use dmesh_server::discovery::{
    DiscoveredDevice,
};
use dmesh_server::radio_history::{RadioEvent, RadioHistory};
use jni::objects::{GlobalRef, JByteArray, JClass, JObject, JString};
#[cfg(target_os = "android")]
use jni::sys::JNI_VERSION_1_6;
use jni::sys::{JNI_FALSE, JNI_TRUE, jboolean, jint, jlong};
use jni::{JNIEnv, JavaVM};
use serde_json::{Value, json};
use ssh_mesh::MeshListener;
use ssh_mesh::sshc::SshClientListener;
use std::collections::{BTreeMap, HashMap, VecDeque};
#[cfg(target_os = "android")]
use std::ffi::{CString, c_char, c_int, c_void};
use std::io;
#[cfg(target_os = "android")]
use std::io::Write;
use std::net::Ipv6Addr;
#[cfg(target_os = "android")]
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
#[cfg(target_os = "android")]
use std::sync::Once;
use std::sync::{Mutex, OnceLock};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::sync::mpsc::{UnboundedSender, unbounded_channel};
#[cfg(target_os = "android")]
use tracing_subscriber::fmt::MakeWriter;
#[cfg(target_os = "android")]
use tracing_subscriber::layer::SubscriberExt;
#[cfg(target_os = "android")]
use tracing_subscriber::util::SubscriberInitExt;

use crate::{
    android_nan_protocol as radio_protocol,
    mesh_common::{MeshHandle, MeshStreamHandle},
};

const BRIDGE_HOST: &str = "dmesh-msg";
const BRIDGE_PORT: u16 = 1;
const MAX_BRIDGE_MESSAGE_BYTES: usize = 2 * 1024;
static BRIDGE_SENDERS: OnceLock<Mutex<HashMap<u64, UnboundedSender<Vec<u8>>>>> = OnceLock::new();
/// Discovered devices live in the shared `dmesh-discovery` engine inventory:
/// UDP multicast, NAN Service Info and follow-ups, and future control-plane
/// observations all update that one inventory, and short-lived NAN
/// `PeerHandle`s are never kept by Java. The inventory is advisory and unsigned
/// for peers that send no key; entries expire after one hour.
/// Platform adapters report the device's current interface/address snapshot;
/// Rust owns this table so routing and multicast discovery make the same
/// decision on Android and Linux.  It is a replacement snapshot, not a Java
/// policy cache.
static LOCAL_NETWORKS: OnceLock<Mutex<dmesh_server::local_networks::LocalNetworkTable>> =
    OnceLock::new();
/// Latest Android platform power/memory telemetry. This is an input to Rust
/// scheduling; Java reports facts and does not decide admission policy.
static POWER_STATE: OnceLock<Mutex<dmesh_server::power::PowerState>> = OnceLock::new();
/// Last received NAN follow-ups, so Android status and E2E use the same receipt view as the host
/// and ESP adapters.
static NAN_FOLLOWUPS: Mutex<RadioHistory> = Mutex::new(RadioHistory::new(32));
/// Android framework lifecycle/configuration events: forwarded to Rust as well, but they are not
/// directed follow-ups, so they keep their own history.
static NAN_EVENTS: Mutex<RadioHistory> = Mutex::new(RadioHistory::new(64));
const BLE_SCAN_RESULT_MAX: usize = 32;
static BLE_SCAN_RESULTS: OnceLock<Mutex<BTreeMap<String, Value>>> = OnceLock::new();

fn nan_followups() -> &'static Mutex<RadioHistory> {
    &NAN_FOLLOWUPS
}

fn nan_events() -> &'static Mutex<RadioHistory> {
    &NAN_EVENTS
}

fn ble_scan_results_store() -> &'static Mutex<BTreeMap<String, Value>> {
    BLE_SCAN_RESULTS.get_or_init(|| Mutex::new(BTreeMap::new()))
}

pub(crate) fn record_ble_scan_result(event: &str, payload: &[u8]) {
    let mut parts = event.splitn(3, ':');
    if parts.next() != Some("scan_result") {
        return;
    }
    let rssi = parts
        .next()
        .and_then(|item| item.strip_prefix("rssi="))
        .and_then(|value| value.parse::<i32>().ok());
    let rest = parts.next().unwrap_or_default();
    let (address_field, mode_field) = rest.rsplit_once(":mode=").unwrap_or((rest, "unknown"));
    let address = address_field
        .strip_prefix("addr=")
        .filter(|value| !value.is_empty())
        .unwrap_or_default();
    let mode = if matches!(mode_field, "unpaired" | "operational") {
        mode_field
    } else {
        "unknown"
    };
    if address.is_empty() || !address.chars().all(|c| c.is_ascii_hexdigit() || c == ':') {
        return;
    }
    tracing::info!(
        target: "dmesh.event",
        event_type = "ble.scan_result",
        trace_prechecked = true,
        address = %address,
        mode = %mode,
        rssi = %rssi.map_or_else(String::new, |value| value.to_string()),
        message = "event"
    );
    let mut results = match ble_scan_results_store().lock() {
        Ok(guard) => guard,
        Err(guard) => guard.into_inner(),
    };
    if results.len() == BLE_SCAN_RESULT_MAX && !results.contains_key(address) {
        if let Some(oldest) = results.keys().next().cloned() {
            results.remove(&oldest);
        }
    }
    results.insert(
        address.to_owned(),
        json!({
            "address": address,
            "mode": mode,
            "rssi": rssi,
            "service_data": bytes_to_hex(payload),
            "last_seen_ms": chrono::Utc::now().timestamp_millis(),
        }),
    );
}

#[cfg_attr(not(target_os = "android"), allow(dead_code))]
pub(crate) fn ble_scan_results(limit: Option<u64>) -> Value {
    let results = match ble_scan_results_store().lock() {
        Ok(guard) => guard,
        Err(guard) => guard.into_inner(),
    };
    let mut entries: Vec<&Value> = results.values().collect();
    entries.sort_by(|a, b| {
        b.get("last_seen_ms")
            .and_then(Value::as_i64)
            .unwrap_or(i64::MIN)
            .cmp(
                &a.get("last_seen_ms")
                    .and_then(Value::as_i64)
                    .unwrap_or(i64::MIN),
            )
    });
    let entries = entries
        .into_iter()
        .take(limit.unwrap_or(BLE_SCAN_RESULT_MAX as u64) as usize)
        .cloned()
        .collect::<Vec<_>>();
    json!({"results": entries, "count": entries.len()})
}

#[cfg_attr(not(target_os = "android"), allow(dead_code))]
pub(crate) fn ble_scan_clear() -> Value {
    let mut results = match ble_scan_results_store().lock() {
        Ok(guard) => guard,
        Err(guard) => guard.into_inner(),
    };
    results.clear();
    json!({"status": "cleared"})
}

/// Retain one NAN observation as a `log.watch` record: `kind` is the event
/// type and the other fields describe the frame.
fn trace_nan_frame(event_type: &str, frame: &RadioEvent) {
    let msg_type = frame.event.as_deref().unwrap_or("");
    let target = frame.target.as_deref().unwrap_or("");
    tracing::info!(
        target: "dmesh.event",
        event_type = %event_type,
        trace_prechecked = true,
        protocol = %frame.protocol,
        event = %msg_type,
        peer = %frame.source,
        target_device = %target,
        payload_hash = %frame.payload_hash,
        message = "event"
    );
}

fn record_nan_followup(frame: RadioEvent) {
    trace_nan_frame("nan.followup", &frame);
    if let Ok(mut history) = nan_followups().lock() {
        history.push(frame);
    }
}

fn record_nan_event(frame: RadioEvent) {
    trace_nan_frame("nan.event", &frame);
    if let Ok(mut history) = nan_events().lock() {
        history.push_keeping_lifecycle(frame);
    }
}

#[cfg(target_os = "android")]
static ANDROID_LOGGER: AndroidLog = AndroidLog;
#[cfg(target_os = "android")]
static ANDROID_LOG_INIT: Once = Once::new();
#[cfg(target_os = "android")]
static ANDROID_MESSAGE_CALLBACK: OnceLock<Mutex<Option<(Arc<JavaVM>, GlobalRef)>>> =
    OnceLock::new();
/// The same bounded telemetry source used by ssh-mesh binaries. Android keeps
/// it in-process and exposes it through the SSH JSON/text bridge.
#[cfg(target_os = "android")]
static ANDROID_TELEMETRY: OnceLock<mesh::local_trace::LogBuffer> = OnceLock::new();

#[cfg(target_os = "android")]
struct AndroidVpnHandle {
    _runtime: tokio::runtime::Runtime,
    _injector: Arc<dyn mesh::tun::TunInjector>,
}

// The JNI handle is a small positive id into this registry, never a raw
// pointer: pointer values can be negative when cast to jlong, which the
// Java side (and the instrumentation test) interpret as failure and would
// then close the TUN fd that Rust owns.
#[cfg(target_os = "android")]
static ANDROID_VPN_NEXT_HANDLE: std::sync::atomic::AtomicI64 = std::sync::atomic::AtomicI64::new(1);

#[cfg(target_os = "android")]
static ANDROID_VPN_HANDLES: OnceLock<Mutex<HashMap<i64, AndroidVpnHandle>>> = OnceLock::new();

#[cfg(target_os = "android")]
fn android_vpn_handles() -> &'static Mutex<HashMap<i64, AndroidVpnHandle>> {
    ANDROID_VPN_HANDLES.get_or_init(|| Mutex::new(HashMap::new()))
}

fn bridge_senders() -> &'static Mutex<HashMap<u64, UnboundedSender<Vec<u8>>>> {
    BRIDGE_SENDERS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// The discovered devices in the shape the JSON-reading consumers (status
/// text, the JSON bridge, companion lookup) read, from the engine inventory.
/// Empty before the mesh has started and installed the engine.
fn discovered_devices_view() -> BTreeMap<String, DiscoveredDevice> {
    discovery_engine()
        .map(|engine| engine.discovered_view())
        .unwrap_or_default()
}

fn local_networks() -> &'static Mutex<dmesh_server::local_networks::LocalNetworkTable> {
    LOCAL_NETWORKS
        .get_or_init(|| Mutex::new(dmesh_server::local_networks::LocalNetworkTable::default()))
}

fn power_state() -> &'static Mutex<dmesh_server::power::PowerState> {
    POWER_STATE.get_or_init(|| Mutex::new(dmesh_server::power::PowerState::default()))
}

fn update_power_state(payload: &[u8]) -> anyhow::Result<Value> {
    let observation =
        dmesh_server::power::decode_json_observation(payload).map_err(anyhow::Error::msg)?;
    let mut state = power_state()
        .lock()
        .map_err(|_| anyhow::anyhow!("power state poisoned"))?;
    state.apply(observation);
    Ok(dmesh_server::power::json_status(*state))
}

fn update_battery_state(payload: &[u8]) -> anyhow::Result<Value> {
    let observation = dmesh_server::power::decode_battery_cbor_observation(payload)
        .map_err(anyhow::Error::msg)?;
    let mut state = power_state()
        .lock()
        .map_err(|_| anyhow::anyhow!("power state poisoned"))?;
    state.battery.apply(observation);
    Ok(dmesh_server::power::battery_json_status(state.battery))
}

#[cfg(target_os = "android")]
pub(crate) fn android_battery_response(request: &[u8]) -> Option<Vec<u8>> {
    let record = dmesh_server::tagged::decode(request)?;
    let (method, id) = dmesh_server::telemetry::decode_request_record(record)?;
    if method != dmesh_server::telemetry::BATTERY_METHOD {
        return None;
    }
    let state = power_state().lock().ok()?.battery;
    let mut result = [0u8; 128];
    let used = dmesh_server::telemetry::encode_battery_status(state, &mut result)?;
    let mut response = [0u8; 160];
    let size = dmesh_server::tagged::encode_numeric_response(
        dmesh_server::telemetry::TELEMETRY_COMPONENT,
        method,
        id,
        &result[..used],
        &mut response,
    )?;
    Some(response[..size].to_vec())
}

pub(crate) fn android_telemetry_response(request: &[u8]) -> Option<Vec<u8>> {
    use dmesh_server::telemetry::{self, NanStatus};

    let record = dmesh_server::tagged::decode(request)?;
    let (method, id) = telemetry::decode_request_record(record)?;
    let mut result = [0u8; 128];
    let used = match method {
        telemetry::NAN_STATUS_METHOD => {
            let status: Value =
                serde_json::from_slice(&radio_message("telemetry.nan_status", "", &[], -1).ok()?)
                    .ok()?;
            telemetry::encode_nan_status(
                NanStatus {
                    active: status["active"].as_bool(),
                    publishing: status["publish_active"].as_bool(),
                    ..NanStatus::default()
                },
                &mut result,
            )?
        }
        _ => return None,
    };
    let mut response = [0u8; 160];
    let size = dmesh_server::tagged::encode_numeric_response(
        telemetry::TELEMETRY_COMPONENT,
        method,
        id,
        &result[..used],
        &mut response,
    )?;
    Some(response[..size].to_vec())
}

/// The running node's per-association and per-bearer rows.
#[cfg(target_os = "android")]
async fn android_node_rows(
) -> Result<(Vec<quic_lite::AssociationRow>, Vec<quic_lite::BearerRow>), String> {
    crate::bearer::current()
        .ok_or_else(|| "the QUIC node is not running".to_owned())?
        .rows()
        .await
        .ok_or_else(|| "QUIC telemetry is unavailable".to_owned())
}

#[cfg(target_os = "android")]
fn android_quic_metrics_handler<'a>(
    call: dmesh_server::registry::Call<'a>,
) -> dmesh_server::registry::Reply<'a> {
    Box::pin(async move {
        let record = dmesh_server::tagged::decode(call.data)?;
        let (method, id) = dmesh_server::telemetry::decode_request_record(record)?;
        if method != dmesh_server::telemetry::QUIC_METRICS_METHOD {
            return None;
        }
        let telemetry = crate::bearer::current()?.telemetry().await?;
        let mut result = [0u8; dmesh_server::telemetry::TELEMETRY_RESPONSE_MAX_BYTES];
        let used = dmesh_server::telemetry::encode_quic_metrics(telemetry, &mut result)?;
        let mut response = [0u8; 640];
        let size = dmesh_server::tagged::encode_numeric_response(
            dmesh_server::telemetry::TELEMETRY_COMPONENT,
            method,
            id,
            &result[..used],
            &mut response,
        )?;
        Some(response[..size].to_vec())
    })
}

/// Android QUIC-stream uptime. The mesh owner records its start so shared
/// component responses can report bounded runtime facts without Java.
#[cfg(target_os = "android")]
static ANDROID_STARTED: OnceLock<std::time::Instant> = OnceLock::new();

#[cfg(target_os = "android")]
pub(crate) fn android_note_started() {
    let _ = ANDROID_STARTED.set(std::time::Instant::now());
}

#[cfg(target_os = "android")]
fn android_uptime_secs() -> u64 {
    ANDROID_STARTED
        .get()
        .map(|started| started.elapsed().as_secs())
        .unwrap_or(0)
}

/// Shared numeric-correlated response for one documented method whose result
/// already exists as JSON.
#[cfg(target_os = "android")]
fn android_json_response(
    request: &[u8],
    component: u64,
    method: u64,
    result: &Value,
) -> Option<Vec<u8>> {
    let record = dmesh_server::tagged::decode(request)?;
    let id = record.id?;
    let mut encoded = [0u8; 1400];
    let used = dmesh_server::cbor::encode_json_value(result, &mut encoded)?;
    let mut response = [0u8; 1500];
    let size = dmesh_server::tagged::encode_numeric_response(
        component,
        method,
        id,
        &encoded[..used],
        &mut response,
    )?;
    Some(response[..size].to_vec())
}

/// Shared numeric-correlated error for a documented method the Android host
/// role deliberately does not implement.
#[cfg(target_os = "android")]
fn android_numeric_error(request: &[u8], message: &[u8]) -> Option<Vec<u8>> {
    let record = dmesh_server::tagged::decode(request)?;
    let component = match record.component? {
        dmesh_server::tagged::Name::Tag(value) => u64::from(value),
        _ => return None,
    };
    let method = match record.method? {
        dmesh_server::tagged::Name::Tag(value) => u64::from(value),
        _ => return None,
    };
    let id = record.id?;
    let mut response = [0u8; 160];
    let size =
        dmesh_server::tagged::encode_numeric_error(component, method, id, message, &mut response)?;
    Some(response[..size].to_vec())
}

/// Shared component-9 `status`: bounded connection diagnostics with the
/// firmware result shape. Android reports its framework-observed link facts
/// conservatively: fields without a retained observation stay unavailable.
#[cfg(target_os = "android")]
pub(crate) fn android_diag_status_response(request: &[u8]) -> Option<Vec<u8>> {
    let record = dmesh_server::tagged::decode(request)?;
    let dmesh_server::tagged::Name::Tag(component) = record.component? else {
        return None;
    };
    let dmesh_server::tagged::Name::Tag(method) = record.method? else {
        return None;
    };
    if u64::from(component) != dmesh_server::services::DIAGNOSTIC_COMPONENT
        || u64::from(method) != dmesh_server::services::DIAGNOSTIC_STATUS_METHOD
    {
        return None;
    }
    dmesh_server::services::encode_device_status_response(
        record.id?,
        dmesh_server::services::DeviceStatus {
            uptime_secs: android_uptime_secs(),
            sta_enabled: false,
            sta_associated: false,
            sta_bssid: b"unavailable",
            sta_ipv4: b"unavailable",
        },
    )
}

/// Shared component-9 `services`: the built-in tagged service catalog.
#[cfg(target_os = "android")]
pub(crate) fn android_services_response(request: &[u8]) -> Option<Vec<u8>> {
    let record = dmesh_server::tagged::decode(request)?;
    let dmesh_server::tagged::Name::Tag(component) = record.component? else {
        return None;
    };
    let dmesh_server::tagged::Name::Tag(method) = record.method? else {
        return None;
    };
    if u64::from(component) != dmesh_server::services::DIAGNOSTIC_COMPONENT
        || u64::from(method) != dmesh_server::services::DIAGNOSTIC_SERVICES_METHOD
    {
        return None;
    }
    let id = record.id?;
    let catalog = dmesh_server::services::encode_tagged_service_catalog();
    let mut response = [0u8; 512];
    let size = dmesh_server::tagged::encode_numeric_response(
        dmesh_server::services::DIAGNOSTIC_COMPONENT,
        method,
        id,
        &catalog,
        &mut response,
    )?;
    Some(response[..size].to_vec())
}

/// `firmware.identity`: the running service's name, version and uptime.
#[cfg(target_os = "android")]
pub(crate) fn android_identity_response(request: &[u8]) -> Option<Vec<u8>> {
    android_json_response(
        request,
        dmesh_server::telemetry::TELEMETRY_COMPONENT,
        dmesh_server::telemetry::DEVICE_METHOD,
        &serde_json::json!({
            "version": env!("CARGO_PKG_VERSION"),
            "cpu_type": std::env::consts::ARCH,
            "role": "android",
            "total_ram_bytes": dmesh_server::telemetry::host_total_ram_bytes(),
        }),
    )
}

/// Shared BLE component surface for the Android stream path. The framework
/// adapter keeps its own command names; the numeric surface projects them.
#[cfg(target_os = "android")]
pub(crate) fn android_ble_component_response(request: &[u8]) -> Option<Vec<u8>> {
    let record = dmesh_server::tagged::decode(request)?;
    let dmesh_server::tagged::Name::Tag(component) = record.component? else {
        return None;
    };
    let dmesh_server::tagged::Name::Tag(method) = record.method? else {
        return None;
    };
    if u64::from(component) != dmesh_server::services::BLE_COMPONENT {
        return None;
    }
    let method = u64::from(method);
    let fields = record.fields;
    let field_uint = |tag: u64| -> Option<u64> {
        let fields = fields?;
        let mut decoder = dmesh_server::cbor::Decoder::new(fields);
        let (major, count) = decoder.head()?;
        if major != 5 {
            return None;
        }
        for _ in 0..count {
            let key = decoder.uint()?;
            if key == tag {
                return decoder.uint_or_text();
            }
            decoder.skip()?;
        }
        None
    };
    let value: anyhow::Result<Value> = match method {
        dmesh_server::services::BLE_SCAN_METHOD => android_ble_command("ble.scan", &json!({}))
            .context("Android BLE callback is unavailable"),
        dmesh_server::services::BLE_STATUS_METHOD => android_ble_command("ble.status", &json!({}))
            .context("Android BLE callback is unavailable"),
        dmesh_server::services::BLE_SCAN_STOP_METHOD => {
            android_ble_command("ble.scan_stop", &json!({}))
                .context("Android BLE callback is unavailable")
        }
        dmesh_server::services::BLE_CONNECT_METHOD => {
            if field_uint(2).is_none() {
                Err(anyhow::anyhow!("ble.connect requires addr"))
            } else {
                // The framework callback owns the real address decoding; the
                // numeric surface forwards the decoded shared fields.
                android_ble_command(
                    "ble.connect",
                    &json!({
                        "addr": field_uint(2),
                        "addr_type": field_uint(3),
                        "psm": field_uint(4),
                    }),
                )
                .context("Android BLE callback is unavailable")
            }
        }
        _ => return None,
    };
    android_json_response(
        request,
        dmesh_server::services::BLE_COMPONENT,
        method,
        &match value {
            Ok(value) => value,
            Err(error) => return android_numeric_error(request, error.to_string().as_bytes()),
        },
    )
}

fn update_local_networks(payload: &[u8]) -> anyhow::Result<usize> {
    let snapshot = dmesh_server::local_networks::decode_snapshot(payload)
        .ok_or_else(|| anyhow::anyhow!("invalid local-networks CBOR snapshot"))?;
    let mut current = local_networks()
        .lock()
        .map_err(|_| anyhow::anyhow!("local-networks table poisoned"))?;
    current
        .replace(snapshot)
        .ok_or_else(|| anyhow::anyhow!("local-networks snapshot has duplicate interface"))?;
    Ok(current.networks.len())
}

/// Synchronous retained snapshot in the common signed-record wire. Network
/// calls use AndroidDiscoveryNodes below for retained plus live observations;
/// Android's UI can still read its local JSON inventory.
#[cfg_attr(not(target_os = "android"), allow(dead_code))]
pub(crate) fn android_discovery_nodes_response(request: &[u8]) -> Option<Vec<u8>> {
    let record = dmesh_server::tagged::decode(request)?;
    if record.to.is_some()
        || record.id.is_none()
        || !dmesh_server::announce::is_devices_observed_request(request)
    {
        return None;
    }
    // One row per device and bearer, from the shared inventory.
    let devices = discovery_engine()
        .map(|engine| engine.devices())
        .unwrap_or_default();
    dmesh_discovery::nodes::response(&devices, record.id?, false)
}

struct AndroidDiscoveryNodes;
impl dmesh_server::stream::StreamHandler for AndroidDiscoveryNodes {
    fn open<'a>(&'a self, request:dmesh_server::stream::Request<'a>) -> dmesh_server::stream::OpenFuture<'a> {
        Box::pin(async move {
            if request.record.to.is_some() || request.record.params.is_some() {return None;}
            let options=dmesh_server::discovery_nodes::Options::decode(request.record.fields)?;
            let response=dmesh_discovery::nodes::stream_response(discovery_engine()?.clone(),request.record.id?,options,false)?;
            #[cfg(target_os="android")]
            if options.active && options.duration_ms != 0 {
                let _=crate::mesh_common::solicit_discovery();
                let _=schedule_android_discovery_active();
            }
            Some(dmesh_server::stream::Outcome::Respond(response))
        })
    }
}

/// Schedule Android's framework-owned NAN active-discovery operation from the
/// common correlated QUIC action. Rust validates/correlates the request; Java
/// only calls the Wi-Fi Aware API through the already-installed callback.
#[cfg(target_os = "android")]
pub(crate) fn android_discovery_active_response(request: &[u8]) -> Option<Vec<u8>> {
    let record = dmesh_server::tagged::decode(request)?;
    if record.to.is_some()
        || record.component
            != Some(dmesh_server::tagged::Name::Tag(
                dmesh_server::announce::ANNOUNCE_COMPONENT,
            ))
        || record.method
            != Some(dmesh_server::tagged::Name::Tag(
                dmesh_server::announce::ANNOUNCE_DISCOVERY_ACTIVE,
            ))
        || record.id.is_none()
        || record.params.is_some()
    {
        return None;
    }
    // One pass on every bearer: the UDP multicast announce and request here,
    // and the framework NAN/BLE scans through the Java owner.
    let multicast = crate::mesh_common::solicit_discovery();
    let framework = schedule_android_discovery_active().is_some();
    if !multicast && !framework {
        return None;
    }
    let mut response = [0u8; 32];
    let used = dmesh_server::tagged::encode_numeric_response(
        dmesh_server::announce::ANNOUNCE_COMPONENT,
        dmesh_server::announce::ANNOUNCE_DISCOVERY_ACTIVE,
        record.id?,
        &[0xa1, 1, 0xf5],
        &mut response,
    )?;
    Some(response[..used].to_vec())
}

#[cfg(target_os = "android")]
fn schedule_android_discovery_active() -> Option<()> {
    let (jvm, callback) = android_message_callback().lock().ok()?.clone()?;
    let mut env = jvm.attach_current_thread().ok()?;
    env.call_method(&callback, "onDiscoveryActive", "()V", &[])
        .ok()?;
    Some(())
}

/// Schedule a targeted framework-owned NAN Subscribe from the common
/// `nan.wakeup` action.  This is deliberately adjacent to discovery.active:
/// direct UDP/QUIC callers reach the same Android Aware owner as Binder and
/// HTTP callers, while Rust retains validation and request correlation.
#[cfg(target_os = "android")]
pub(crate) fn android_nan_wakeup_response(request: &[u8]) -> Option<Vec<u8>> {
    let record = dmesh_server::tagged::decode(request)?;
    let id = record.id?;
    let target = dmesh_server::announce::decode_nan_wakeup_request(record)?;
    let target = target
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let (jvm, callback) = android_message_callback().lock().ok()?.clone()?;
    let mut env = jvm.attach_current_thread().ok()?;
    let target = env.new_string(target).ok()?;
    if env
        .call_method(
            &callback,
            "onNanWakeup",
            "(Ljava/lang/String;)V",
            &[jni::objects::JValue::Object((&*target).into())],
        )
        .is_err()
    {
        return None;
    }
    let mut response = [0u8; 32];
    let used = dmesh_server::tagged::encode_numeric_response(
        dmesh_server::announce::ANNOUNCE_COMPONENT,
        dmesh_server::announce::ANNOUNCE_NAN_WAKEUP,
        id,
        &[0xa1, 1, 0xf5],
        &mut response,
    )?;
    Some(response[..used].to_vec())
}

#[cfg(target_os = "android")]
struct AndroidBleBackend;

#[cfg(target_os = "android")]
fn android_ble_command(method: &str, params: &Value) -> Option<Value> {
    let (jvm, callback) = android_message_callback().lock().ok()?.clone()?;
    let mut env = jvm.attach_current_thread().ok()?;
    let method = env.new_string(method).ok()?;
    let params = env.new_string(params.to_string()).ok()?;
    let result = env
        .call_method(
            &callback,
            "onBleCommand",
            "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;",
            &[
                jni::objects::JValue::Object((&*method).into()),
                jni::objects::JValue::Object((&*params).into()),
            ],
        )
        .ok()?;
    let object = match result {
        jni::objects::JValueGen::Object(object) => object,
        _ => return None,
    };
    let text: String = env.get_string(&JString::from(object)).ok()?.into();
    Some(serde_json::from_str(&text).unwrap_or(Value::String(text)))
}

#[cfg(target_os = "android")]
#[async_trait]
impl dmesh_server::ble_service::BleBackend for AndroidBleBackend {
    async fn status(&self) -> anyhow::Result<Value> {
        android_ble_command("ble.status", &json!({})).context("Android BLE callback is unavailable")
    }
    async fn scan(&self) -> anyhow::Result<Value> {
        android_ble_command("ble.scan", &json!({})).context("Android BLE callback is unavailable")
    }
    async fn scan_stop(&self) -> anyhow::Result<Value> {
        android_ble_command("ble.scan_stop", &json!({}))
            .context("Android BLE callback is unavailable")
    }
    async fn scan_results(&self, limit: Option<u64>) -> anyhow::Result<Value> {
        Ok(ble_scan_results(limit))
    }
    async fn scan_clear(&self) -> anyhow::Result<Value> {
        Ok(ble_scan_clear())
    }
    async fn connect(&self, address: String, psm: u16) -> anyhow::Result<Value> {
        android_ble_command("ble.connect", &json!({"address": address, "psm": psm}))
            .context("Android BLE callback is unavailable")
    }
    async fn disconnect(&self) -> anyhow::Result<Value> {
        android_ble_command("ble.disconnect", &json!({}))
            .context("Android BLE callback is unavailable")
    }
}

/// Register a platform service's methods in the one registry as local-only
/// (the device's own control surface, never a network peer), and route its
/// HTTP gateway name to the registry so the gateway reaches it the same way.
#[cfg(target_os = "android")]
fn register_local_service(
    services: &ssh_mesh::mesh_rest::MeshServiceRegistry,
    name: &str,
    methods: Vec<dmesh_server::registry::Method>,
    handler: impl mesh::wire::TaggedRecordHandler + 'static,
) -> bool {
    use dmesh_server::registry::{LocalOnly, register_all};
    use dmesh_server::registry_bridge::RecordHandlerAdapter;
    let registered = register_all(&methods, LocalOnly(RecordHandlerAdapter(Arc::new(handler))));
    if !registered {
        // A restart in the same process re-registers the same methods.
        log::debug!("Android {name} methods were already registered");
    }
    register_gateway_route(services, name);
    true
}

/// Route one HTTP gateway service name to the registry as local ingress.
#[cfg(target_os = "android")]
fn register_gateway_route(services: &ssh_mesh::mesh_rest::MeshServiceRegistry, name: &str) {
    use dmesh_server::registry_bridge::RegistryRecordHandler;
    services.register(
        name,
        ssh_mesh::mesh_rest::MeshService {
            backend: ssh_mesh::mesh_rest::MeshServiceBackend::Direct(Arc::new(
                RegistryRecordHandler::global(),
            )),
            encoding: ssh_mesh::mesh_rest::MeshServiceEncoding::TaggedCbor,
            component: name.to_owned(),
        },
    );
}

/// Register the numbered methods Android implements for network peers. Only
/// real implementations are registered: Android has no allocator telemetry,
/// per-bearer metrics, device-side BLE start/stop/CoC send, or flash/boot
/// control, so those methods are absent and answer the shared numeric error.
#[cfg(target_os = "android")]
pub(crate) fn register_android_methods() {
    use dmesh_server::platform_api::{RadioHistoryRequest, StatusTextRequest};
    use dmesh_server::registry::{
        AsyncFn, CallContext, LocalOnly, Method, SyncBytesFn, methods, register, register_all,
    };
    use dmesh_server::registry_bridge::TypedHandler;
    let registered = register(
        methods::DISCOVERY_ACTIVE,
        SyncBytesFn(android_discovery_active_response),
    ) & register(
        methods::NAN_WAKEUP,
        SyncBytesFn(android_nan_wakeup_response),
    ) & dmesh_server::registry::register_stream(
        methods::DISCOVERY_NODES,
        AndroidDiscoveryNodes,
    ) & register(
        methods::TELEMETRY_BATTERY,
        SyncBytesFn(android_battery_response),
    ) & register(
        methods::TELEMETRY_NAN_STATUS,
        SyncBytesFn(android_telemetry_response),
    ) & register(
        methods::TELEMETRY_QUIC_METRICS,
        AsyncFn::new(android_quic_metrics_handler),
    ) & register(
        methods::TELEMETRY_QUIC_ASSOCIATIONS,
        TypedHandler::new(
            |_: dmesh_server::platform_api::TelemetryQuicAssociationsRequest, _: CallContext| async {
                let (associations, bearers) = android_node_rows().await?;
                Ok(dmesh_server::telemetry::quic_associations_response(&associations, &bearers))
            },
        ),
    ) & register(
        methods::TELEMETRY_BEARERS,
        TypedHandler::new(
            |_: dmesh_server::platform_api::TelemetryBearersRequest, _: CallContext| async {
                let (_, bearers) = android_node_rows().await?;
                Ok(dmesh_server::telemetry::bearers_response(&bearers))
            },
        ),
    ) & register(methods::STATUS, SyncBytesFn(android_diag_status_response))
        & register(methods::SERVICES, SyncBytesFn(android_services_response))
        & register(
            methods::TELEMETRY_MEMORY,
            TypedHandler::new(
                |_: dmesh_server::platform_api::TelemetryMemoryRequest, _: CallContext| async {
                    dmesh_server::telemetry::process_rss_bytes().map(|rss| {
                        dmesh_server::platform_api::TelemetryMemoryResponse {
                            process_rss_bytes: Some(rss),
                            ..Default::default()
                        }
                    })
                },
            ),
        )
        & register_all(
            &[
                methods::BLE_SCAN,
                methods::BLE_STATUS,
                methods::BLE_SCAN_STOP,
                methods::BLE_CONNECT,
            ],
            SyncBytesFn(android_ble_component_response),
        )
        & register(
            Method::new(203, "status", 1, "text"),
            LocalOnly(TypedHandler::new(
                |_: StatusTextRequest, _: CallContext| async { Ok(status_text_response()) },
            )),
        )
        & register(
            Method::new(202, "radio", 1, "history"),
            LocalOnly(TypedHandler::new(
                |request: RadioHistoryRequest, _: CallContext| async move {
                    radio_history_response(request)
                },
            )),
        )
        // Probing: this node can start a probe (as the client over its UDP, USB
        // or BLE bearer) and can be probed (`probe.handler`), so any node can
        // probe any other.
        & register_all(
            &[
                methods::SETTINGS_GET,
                methods::SETTINGS_SET,
                methods::SETTINGS_LIST,
            ],
            SyncBytesFn(android_settings_response),
        )
        & register(methods::PROBE_START, crate::bearer::ProbeStartHandler)
        & dmesh_server::registry::register_stream(
            methods::PROBE_HANDLER,
            dmesh_server::probe::ProbeHandler,
        )
        & register(
            methods::TELEMETRY_DEVICE,
            SyncBytesFn(android_identity_response),
        );
    if !registered {
        log::debug!("Android numbered methods were already registered");
    }
    register_android_log_watch();
}

/// `log.watch` over the process's `tracing` history. Periodic snapshots go
/// through the process registry, so a snapshot is exactly the response of the
/// telemetry method it names; `telemetry.quic` needs an async runtime and is
/// reported as skipped.
#[cfg(target_os = "android")]
fn register_android_log_watch() {
    let Some(buffer) = ANDROID_TELEMETRY.get().cloned() else {
        return;
    };
    let dispatch: dmesh_server::log_watch::Dispatch = Arc::new(|request| {
        dmesh_server::registry::dispatch_now(
            request,
            dmesh_server::registry::CallContext::local(),
        )
    });
    let registered = dmesh_server::registry::register_stream(
        dmesh_server::registry::methods::LOG_WATCH_RECORDS,
        dmesh_server::log_watch::LogWatchHandler::new(
            Arc::new(dmesh_server::log_watch::MeshLogSource(buffer)),
            Some(dispatch),
        ),
    );
    if !registered {
        log::debug!("Android log.watch was already registered");
    }
}

#[cfg(target_os = "android")]
pub(crate) fn register_ble_service(services: &ssh_mesh::mesh_rest::MeshServiceRegistry) -> bool {
    match dmesh_server::ble_service::BleService::new(Arc::new(AndroidBleBackend)) {
        Ok(handler) => register_local_service(
            services,
            dmesh_server::ble_service::SERVICE_NAME,
            dmesh_server::ble_service::methods(),
            handler,
        ),
        Err(error) => {
            log::error!("Failed to register ble service: {error}");
            false
        }
    }
}

/// The BLE companion link: Android's Bluetooth stack reaches the device.
#[cfg(target_os = "android")]
struct AndroidBleLink;

/// Directory of the device records (one TOML file per device). Set on Android by
/// `configure_android_mesh_paths`; host tests may set it to a temporary directory to exercise
/// companion-aware surfaces.
static ANDROID_DEVICE_RECORDS_PATH: OnceLock<std::path::PathBuf> = OnceLock::new();

#[cfg(target_os = "android")]
fn accepted_android_companion(value: Value) -> anyhow::Result<Value> {
    match value.get("status").and_then(Value::as_str) {
        Some("rejected" | "unsupported" | "invalid") => {
            anyhow::bail!("Android companion operation rejected: {value}")
        }
        _ => Ok(value),
    }
}

#[cfg(target_os = "android")]
fn android_require_paired_companion(
    id: &str,
    expected_vip6: Option<&str>,
) -> anyhow::Result<(String, String)> {
    let devices = discovered_devices_view();
    let (device_id, device) = devices
        .iter()
        .find(|(device_id, device)| {
            device.info.get("signed").and_then(Value::as_bool) == Some(true)
                && (*device_id == id
                    || device.peer.eq_ignore_ascii_case(id)
                    || device
                        .transports
                        .values()
                        .any(|address| address.eq_ignore_ascii_case(id))
                    || device.info.get("vip6").and_then(Value::as_str) == Some(id))
                && expected_vip6.is_none_or(|expected| {
                    device.info.get("vip6").and_then(Value::as_str) == Some(expected)
                })
        })
        .context("companion has no matching signed discovery identity")?;
    let vip6 = device
        .info
        .get("vip6")
        .and_then(Value::as_str)
        .context("signed companion has no VIP6")?
        .to_owned();
    let public_key = device
        .info
        .get("public_key")
        .and_then(Value::as_str)
        .context("signed companion has no public key")?
        .to_owned();
    let device_id = device_id.clone();
    let path = ANDROID_DEVICE_RECORDS_PATH
        .get()
        .context("Android device record path unavailable")?;
    let owned = dmesh_server::device_record::DeviceStore::new(path)
        .load(&vip6)
        .map_err(anyhow::Error::msg)?
        .context("companion has no private pairing result")?;
    if owned.device_id != device_id {
        anyhow::bail!("paired device ID differs from signed discovery");
    }
    if owned.secret.len() < 16 {
        anyhow::bail!("companion has no provisioned control secret");
    }
    if !owned.public_key.is_empty()
        && owned
            .public_key
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
            != public_key
    {
        anyhow::bail!("companion public key differs from signed discovery");
    }
    if owned.vip6.as_deref().is_some_and(|stored| stored != vip6) {
        anyhow::bail!("companion VIP differs from signed discovery");
    }
    Ok((device_id, vip6))
}

#[cfg(target_os = "android")]
#[async_trait]
impl dmesh_server::companion::CompanionLink for AndroidBleLink {
    async fn pair(&self, request: dmesh_server::companion::PairRequest<'_>) -> Result<(), String> {
        // TODO(pairing): BLE currently acknowledges starting a native bond; it does not provision
        // and durably commit a new secret to an unpaired device and its record.
        if request.name.is_some() || request.root_public_key.is_some() {
            return Err("pairing name and root-key provisioning are not implemented".to_owned());
        }
        let command = json!({"kind": "ble", "id": request.id, "psm": request.psm.unwrap_or(128)});
        let result = android_ble_command("companion.pair", &command)
            .context("Android BLE callback is unavailable")
            .and_then(accepted_android_companion);
        result.map(|_| ()).map_err(|error| format!("{error:#}"))
    }

    async fn unpair(
        &self,
        id: &str,
        _store: &dmesh_server::device_record::DeviceStore,
    ) -> Result<(), String> {
        // Keep the BLE path for local lifecycle tests. It currently releases
        // local state, not a confirmed firmware ownership reset. Once security
        // is enabled, BLE unpair must prove the companion secret; physical
        // UART/USB remains the force-unpair recovery path.
        let result = (|| {
            android_require_paired_companion(id, None)?;
            accepted_android_companion(
                android_ble_command("companion.unpair", &json!({"kind": "ble", "id": id}))
                    .context("Android BLE callback is unavailable")?,
            )
        })();
        result.map(|_| ()).map_err(|error| format!("{error:#}"))
    }
}

#[cfg(target_os = "android")]
pub(crate) fn register_companion_service(
    services: &ssh_mesh::mesh_rest::MeshServiceRegistry,
) -> bool {
    // The shared handlers (dmesh_server::companion) do the request handling; Android contributes
    // the BLE link. It holds no control-plane root key yet, so a pairing installs none.
    let store = dmesh_server::device_record::DeviceStore::new(
        ANDROID_DEVICE_RECORDS_PATH.get().cloned().unwrap_or_default(),
    );
    std::sync::Arc::new(
        dmesh_server::companion::Companions::new(&[], store)
            .with_link("ble", Arc::new(AndroidBleLink)),
    )
    .register_local_only(&dmesh_server::registry::REGISTRY);
    register_gateway_route(services, dmesh_server::companion::SERVICE_NAME);
    true
}

#[cfg(target_os = "android")]
struct AndroidUsbBackend;

#[cfg(target_os = "android")]
fn android_usb_command(method: &str, params: &Value) -> Option<Value> {
    let (jvm, callback) = android_message_callback().lock().ok()?.clone()?;
    let mut env = jvm.attach_current_thread().ok()?;
    let method = env.new_string(method).ok()?;
    let params = env.new_string(params.to_string()).ok()?;
    let result = env
        .call_method(
            &callback,
            "onUsbCommand",
            "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;",
            &[
                jni::objects::JValue::Object((&*method).into()),
                jni::objects::JValue::Object((&*params).into()),
            ],
        )
        .ok()?;
    let object = match result {
        jni::objects::JValueGen::Object(object) => object,
        _ => return None,
    };
    let text: String = env.get_string(&JString::from(object)).ok()?.into();
    Some(serde_json::from_str(&text).unwrap_or(Value::String(text)))
}

#[cfg(target_os = "android")]
#[async_trait]
impl dmesh_server::usb_service::UsbBackend for AndroidUsbBackend {
    async fn status(&self) -> anyhow::Result<Value> {
        android_usb_command("usb.status", &json!({})).context("Android USB callback is unavailable")
    }
    async fn devices(&self) -> anyhow::Result<Value> {
        android_usb_command("usb.devices", &json!({}))
            .context("Android USB callback is unavailable")
    }
    async fn open(&self, params: Value) -> anyhow::Result<Value> {
        android_usb_command("usb.open", &params).context("Android USB callback is unavailable")
    }
    async fn close(&self) -> anyhow::Result<Value> {
        android_usb_command("usb.close", &json!({})).context("Android USB callback is unavailable")
    }
    async fn discover(&self) -> anyhow::Result<Value> {
        let runtime = crate::bearer::current().context("USB bearer is not running")?;
        let id = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_micros() as u64;
        let mut request = [0u8; 96];
        let len = dmesh_server::announce::encode_discovery_request(id, &mut request)
            .context("encode USB discovery request")?;
        let response = runtime
            .request("usb", &request[..len])
            .await
            .map_err(anyhow::Error::msg)?;
        let record = dmesh_server::tagged::decode(&response)
            .context("USB discovery response is not tagged CBOR")?;
        anyhow::ensure!(record.id == Some(id), "USB discovery reply ID differs");
        let announce = dmesh_server::announce::decode_announce(&response)
            .context("USB peer did not return a discovery announcement")?;
        anyhow::ensure!(
            announce.has_identity() && dmesh_server::announce::verify_identity(announce),
            "USB discovery identity signature is invalid"
        );
        let vip6 = dmesh_server::announce::virtual_ip6(announce.public_key())
            .map(Ipv6Addr::from)
            .context("USB identity has no VIP6")?;
        Ok(json!({
            "signed": true,
            "vip6": vip6,
            "name": announce.device_name(),
            "device_id": announce.device_id().iter().map(|byte| format!("{byte:02x}")).collect::<String>(),
            "public_key": announce.public_key().iter().map(|byte| format!("{byte:02x}")).collect::<String>(),
        }))
    }
}

#[cfg(target_os = "android")]
pub(crate) fn register_usb_service(services: &ssh_mesh::mesh_rest::MeshServiceRegistry) -> bool {
    match dmesh_server::usb_service::UsbService::new(Arc::new(AndroidUsbBackend)) {
        Ok(handler) => register_local_service(
            services,
            dmesh_server::usb_service::SERVICE_NAME,
            dmesh_server::usb_service::methods(),
            handler,
        ),
        Err(error) => {
            log::error!("Failed to register usb service: {error}");
            false
        }
    }
}

#[cfg(target_os = "android")]
fn android_java_command(java_method: &str, method: &str, params: &Value) -> Option<Value> {
    let (jvm, callback) = android_message_callback().lock().ok()?.clone()?;
    let mut env = jvm.attach_current_thread().ok()?;
    let method = env.new_string(method).ok()?;
    let params = env.new_string(params.to_string()).ok()?;
    let result = env
        .call_method(
            &callback,
            java_method,
            "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;",
            &[
                jni::objects::JValue::Object((&*method).into()),
                jni::objects::JValue::Object((&*params).into()),
            ],
        )
        .ok()?;
    let object = match result {
        jni::objects::JValueGen::Object(object) => object,
        _ => return None,
    };
    let text: String = env.get_string(&JString::from(object)).ok()?.into();
    Some(serde_json::from_str(&text).unwrap_or(Value::String(text)))
}

/// Invoke a Rust-selected Android platform stream handler with one opaque CBOR
/// record. The callback is private to this process; it is not a mesh method.
#[cfg(target_os = "android")]
#[allow(dead_code)]
pub(crate) fn android_stream_request(handler: &str, record: &[u8]) -> anyhow::Result<Vec<u8>> {
    anyhow::ensure!(
        record.len() <= 64 * 1024,
        "Android stream request exceeds limit"
    );
    let (jvm, callback) = android_message_callback()
        .lock()
        .map_err(|_| anyhow::anyhow!("Android callback lock poisoned"))?
        .clone()
        .context("Android stream callback unavailable")?;
    let mut env = jvm.attach_current_thread()?;
    let name = env.new_string(handler)?;
    let input = env.byte_array_from_slice(record)?;
    let result = env.call_method(
        &callback,
        "onStreamRequest",
        "(Ljava/lang/String;[B)[B",
        &[
            jni::objects::JValue::Object((&*name).into()),
            jni::objects::JValue::Object((&*input).into()),
        ],
    );
    let result = match result {
        Ok(value) => value.l()?,
        Err(error) => {
            if env.exception_check()? {
                env.exception_clear()?;
            }
            return Err(error).context("Android stream handler failed");
        }
    };
    anyhow::ensure!(!result.is_null(), "Android stream handler returned null");
    let output = env.convert_byte_array(&JByteArray::from(result))?;
    anyhow::ensure!(
        output.len() <= 64 * 1024,
        "Android stream response exceeds limit"
    );
    Ok(output)
}

#[cfg(target_os = "android")]
struct AndroidWifiBackend;

#[cfg(target_os = "android")]
#[async_trait]
impl dmesh_server::wifi_service::WifiBackend for AndroidWifiBackend {
    async fn status(&self) -> anyhow::Result<Value> {
        android_java_command("onWifiCommand", "wifi.status", &json!({}))
            .context("Android Wi-Fi callback is unavailable")
    }
    async fn scan(&self) -> anyhow::Result<Value> {
        android_java_command("onWifiCommand", "wifi.scan", &json!({}))
            .context("Android Wi-Fi callback is unavailable")
    }
}

#[cfg(target_os = "android")]
pub(crate) fn register_wifi_service(services: &ssh_mesh::mesh_rest::MeshServiceRegistry) -> bool {
    match dmesh_server::wifi_service::WifiService::new(Arc::new(AndroidWifiBackend)) {
        Ok(handler) => register_local_service(
            services,
            dmesh_server::wifi_service::SERVICE_NAME,
            dmesh_server::wifi_service::methods(),
            handler,
        ),
        Err(error) => {
            log::error!("Failed to register wifi service: {error}");
            false
        }
    }
}

fn android_transport_set_projection(params: &Value) -> anyhow::Result<Value> {
    let object = params
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("transport.set params must be an object"))?;
    let transport_mode = object.get("mode");
    let mode_nan = transport_mode.is_some_and(|mode| {
        matches!(mode.as_str(), Some("nan" | "aware")) || mode.as_u64() == Some(6)
    });
    let enabled = |value: Option<&Value>| {
        value.is_some_and(|value| value.as_u64() == Some(1) || value.as_str() == Some("1"))
    };
    let p2p_go = enabled(object.get("ap")) || enabled(object.get("p2p_go"));
    let sta =
        transport_mode.is_some_and(|mode| mode.as_str() == Some("sta") || mode.as_u64() == Some(1));
    let radio_off = transport_mode
        .is_some_and(|mode| mode.as_str() == Some("uart") || mode.as_u64() == Some(5));
    let operation = if radio_off {
        "stop"
    } else if sta {
        "sta"
    } else if mode_nan && p2p_go {
        "p2p_go"
    } else if mode_nan {
        "nan"
    } else {
        anyhow::bail!("no Android backend for transport.set mode");
    };
    Ok(json!({
        "status": "accepted",
        "operation": operation,
        "request": {"method": "transport.set", "params": params}
    }))
}

#[cfg(target_os = "android")]
struct AndroidTransportBackend;

#[cfg(target_os = "android")]
#[async_trait]
impl dmesh_server::transport_service::TransportBackend for AndroidTransportBackend {
    async fn set(&self, params: Value) -> anyhow::Result<Value> {
        if let Some(target) = params
            .get("wake_target")
            .and_then(Value::as_str)
            .filter(|target| !target.is_empty())
        {
            let mut activation = params.clone();
            activation["target_mac"] = json!(target);
            return android_java_command("onTransportCommand", "transport.wake", &activation)
                .context("Android NAN callback is unavailable");
        }
        let projection = android_transport_set_projection(&params)?;
        let result = android_java_command(
            "onTransportCommand",
            "transport.apply_projection",
            &json!({"projection": projection.to_string()}),
        )
        .context("Android transport callback is unavailable")?;
        let mut output = projection;
        output["result"] = result;
        Ok(output)
    }
}

#[cfg(target_os = "android")]
pub(crate) fn register_transport_service(
    services: &ssh_mesh::mesh_rest::MeshServiceRegistry,
) -> bool {
    match dmesh_server::transport_service::TransportService::new(Arc::new(AndroidTransportBackend))
    {
        Ok(handler) => register_local_service(
            services,
            dmesh_server::transport_service::SERVICE_NAME,
            dmesh_server::transport_service::methods(),
            handler,
        ),
        Err(error) => {
            log::error!("Failed to register transport service: {error}");
            false
        }
    }
}

#[cfg(target_os = "android")]
fn android_radio_history(limit: Option<u64>, since_ms: Option<u64>, keys: Option<String>) -> Value {
    let now_ms = chrono::Utc::now().timestamp_millis();
    let cutoff = since_ms
        .map(|value| value as i64)
        .unwrap_or_else(|| now_ms.saturating_sub(1_500));
    let filters: Vec<String> = keys
        .map(|keys| {
            keys.split(',')
                .map(|key| key.trim().to_ascii_lowercase())
                .filter(|key| !key.is_empty())
                .collect()
        })
        .unwrap_or_default();
    let matches = |texts: &[&str]| -> bool {
        filters.is_empty()
            || texts.iter().any(|text| {
                let text = text.to_ascii_lowercase();
                filters.iter().any(|filter| text.contains(filter))
            })
    };
    let take = limit.unwrap_or(64).min(256) as usize;
    let events = {
        let history = nan_events()
            .lock()
            .map_or_else(|guard| guard.into_inner(), |guard| guard);
        history
            .iter()
            .rev()
            .filter(|entry| entry.timestamp_ms >= cutoff)
            .filter(|entry| {
                matches(&[
                    entry.protocol.as_str(),
                    entry.event.as_deref().unwrap_or(""),
                    entry.source.as_str(),
                ])
            })
            .take(take)
            .map(|entry| {
                json!({
                    "kind": "event",
                    "last_seen_ms": entry.timestamp_ms,
                    "protocol": entry.protocol,
                    "event": entry.event,
                    "peer": entry.source,
                    "payload_hash": entry.payload_hash,
                })
            })
            .collect::<Vec<_>>()
    };
    let followups = {
        let history = nan_followups()
            .lock()
            .map_or_else(|guard| guard.into_inner(), |guard| guard);
        history
            .iter()
            .rev()
            .filter(|entry| entry.timestamp_ms >= cutoff)
            .filter(|entry| {
                matches(&[
                    entry.protocol.as_str(),
                    entry.event.as_deref().unwrap_or(""),
                    entry.source.as_str(),
                    entry.target.as_deref().unwrap_or(""),
                ])
            })
            .take(take)
            .map(|entry| {
                json!({
                    "kind": "followup",
                    "last_seen_ms": entry.timestamp_ms,
                    "protocol": entry.protocol,
                    "event": entry.event,
                    "source": entry.source,
                    "target": entry.target,
                    "seq": entry.seq,
                    "payload_hash": entry.payload_hash,
                })
            })
            .collect::<Vec<_>>()
    };
    let ble_results = {
        let ble = ble_scan_results(None);
        let results = ble
            .get("results")
            .and_then(Value::as_array)
            .map(|results| {
                results
                    .iter()
                    .filter(|entry| {
                        entry
                            .get("last_seen_ms")
                            .and_then(Value::as_i64)
                            .unwrap_or(i64::MIN)
                            >= cutoff
                    })
                    .filter(|entry| {
                        matches(&[
                            "ble",
                            entry.get("address").and_then(Value::as_str).unwrap_or(""),
                        ])
                    })
                    .take(take)
                    .cloned()
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        json!({"results": results, "count": results.len()})
    };
    json!({
        "events": events,
        "followups": followups,
        "ble_scan_results": ble_results,
        "count": events.len() + followups.len() + ble_results["count"].as_u64().unwrap_or(0) as usize
    })
}

/// Route the HTTP `history` service to the registry; `radio.history` itself is
/// a typed handler registered by [`register_android_methods`].
#[cfg(target_os = "android")]
pub(crate) fn register_history_service(
    services: &ssh_mesh::mesh_rest::MeshServiceRegistry,
) -> bool {
    register_gateway_route(services, "history");
    true
}

/// One compact letter per discovery bearer: A=Wifi Aware, B=BLE, N=ESP-NOW,
/// U=USB, W=WiFi UDP6. Unknown bearers keep their first letter so new
/// adapters surface without a formatter change.
fn bearer_letter(bearer: &str) -> char {
    match bearer {
        "nan" | "nan_followup" | "nan_sd" => 'A',
        "ble" => 'B',
        "now" | "espnow" | "raw_action" => 'N',
        "usb" => 'U',
        "udp" | "udp_multicast" => 'W',
        other => other
            .chars()
            .next()
            .map(|letter| letter.to_ascii_uppercase())
            .unwrap_or('?'),
    }
}

/// Last four bytes of a hex device address; identities stay short and stable.
fn short_address(id: &str) -> &str {
    if id.len() > 8 {
        &id[id.len() - 8..]
    } else {
        id
    }
}

fn compact_age(age_ms: i64) -> String {
    let seconds = (age_ms / 1000).max(0);
    if seconds < 60 {
        format!("{seconds}s")
    } else if seconds < 3600 {
        format!("{}m", seconds / 60)
    } else if seconds < 86400 {
        format!("{}h", seconds / 3600)
    } else {
        format!("{}d", seconds / 86400)
    }
}

/// Paired companion display names keyed by `vip6:` and `pk:` identity forms.
/// Pairing state is private controller data, never carried by discovery.
fn companion_names() -> BTreeMap<String, String> {
    let mut names = BTreeMap::new();
    let Some(directory) = ANDROID_DEVICE_RECORDS_PATH.get() else {
        return names;
    };
    let Ok(devices) = dmesh_server::device_record::DeviceStore::new(directory).list() else {
        return names;
    };
    for device in devices
        .iter()
        .filter(|device| device.trust.as_deref() == Some(dmesh_server::device_record::trust::PAIRED))
    {
        let Some(name) = device.name.as_deref().filter(|name| !name.is_empty()) else {
            continue;
        };
        if let Some(vip6) = &device.vip6 {
            names.insert(format!("vip6:{vip6}"), name.to_owned());
        }
        if !device.public_key.is_empty() {
            names.insert(
                format!("pk:{}", bytes_to_hex(&device.public_key)),
                name.to_owned(),
            );
        }
    }
    names
}

struct StatusRow {
    flags: String,
    id: String,
    name: String,
    via: String,
    rssi: Option<i16>,
    age_ms: Option<i64>,
    companion: bool,
}

impl StatusRow {
    fn sort_key(&self) -> (u8, String, String) {
        let name = if self.name == "-" {
            String::new()
        } else {
            self.name.to_ascii_lowercase()
        };
        (if self.companion { 0 } else { 1 }, name, self.id.clone())
    }

    fn render(&self, out: &mut String) {
        let rssi = self
            .rssi
            .map(|value| format!("{value}"))
            .unwrap_or_default();
        let age = self
            .age_ms
            .map(compact_age)
            .unwrap_or_else(|| "?".to_owned());
        let name: String = self.name.chars().take(16).collect();
        out.push_str(&format!(
            "\n{:<2}{:<8} {:<16} {:<5} {:>4} {:>5}",
            self.flags, self.id, name, self.via, rssi, age
        ));
    }
}

/// Render the bounded, human-oriented cross-bearer status table. The same
/// generator feeds the Android status TextView and the HTTP `status.text`
/// mesh service, so Java never formats discovery state itself.
pub(crate) fn status_text() -> String {
    let now_ms = chrono::Utc::now().timestamp_millis();
    let devices = discovered_devices_view();
    let networks = local_networks()
        .lock()
        .map_or_else(|_| BTreeMap::new(), |table| table.networks.clone());
    let battery = power_state()
        .lock()
        .map(|power| power.battery.clone())
        .unwrap_or_default();
    let ble_results = ble_scan_results_store()
        .lock()
        .map_or_else(|_| BTreeMap::new(), |results| results.clone());
    let companions = companion_names();

    let mut rows: Vec<StatusRow> = Vec::new();
    let mut matched_companions: BTreeMap<String, String> = BTreeMap::new();
    for (id, device) in &devices {
        let companion_name = device
            .info
            .get("vip6")
            .and_then(Value::as_str)
            .and_then(|vip6| companions.get(&format!("vip6:{vip6}")))
            .cloned()
            .or_else(|| {
                device
                    .info
                    .get("public_key")
                    .and_then(Value::as_str)
                    .filter(|key| !key.is_empty())
                    .and_then(|key| companions.get(&format!("pk:{key}")))
                    .cloned()
            });
        if let Some(name) = companion_name.as_ref() {
            matched_companions.insert(name.clone(), id.clone());
        }
        let mut via: Vec<char> = device
            .observations
            .keys()
            .map(String::as_str)
            .map(bearer_letter)
            .collect();
        let rssi = device
            .observations
            .values()
            .filter(|observation| observation.last_rssi_dbm.is_some())
            .max_by_key(|observation| observation.last_seen_ms)
            .and_then(|observation| observation.last_rssi_dbm);
        let name = companion_name
            .clone()
            .or_else(|| {
                device
                    .info
                    .get("device_name")
                    .and_then(Value::as_str)
                    .filter(|name| !name.is_empty())
                    .map(str::to_owned)
            })
            .unwrap_or_else(|| "-".to_owned());
        let mut flags = String::new();
        if companion_name.is_some() {
            flags.push('P');
        }
        if device.info.get("kind").and_then(Value::as_u64)
            == Some(dmesh_server::announce::ANNOUNCE_SLEEP_PENDING)
        {
            flags.push('z');
        }
        rows.push(StatusRow {
            flags,
            id: short_address(id).to_owned(),
            name,
            via: {
                via.sort_unstable();
                via.dedup();
                if via.is_empty() {
                    "-".to_owned()
                } else {
                    via.into_iter().collect::<String>()
                }
            },
            rssi,
            age_ms: Some(now_ms.saturating_sub(device.last_seen_ms)),
            companion: companion_name.is_some(),
        });
    }
    // Paired companions stay visible even before any discovery observation
    // arrives; they have no radio row yet, only their pairing identity.
    for (key, name) in &companions {
        let Some(vip6) = key.strip_prefix("vip6:") else {
            continue;
        };
        if matched_companions.contains_key(name) {
            continue;
        }
        let id = vip6
            .parse::<std::net::Ipv6Addr>()
            .ok()
            .map(|address| bytes_to_hex(&address.octets()[12..16]))
            .unwrap_or_else(|| "?".to_owned());
        rows.push(StatusRow {
            flags: "P".to_owned(),
            id,
            name: name.clone(),
            via: "-".to_owned(),
            rssi: None,
            age_ms: None,
            companion: true,
        });
    }
    // A BLE scan result with no matching discovered identity stays a
    // provisional row: the rendezvous advertisement proves presence, not a
    // verified DMesh identity. The advertisement carries the sender's short
    // source id after its two-byte service UUID, matching the first bytes of
    // a full device id when both come from the same node.
    for (address, result) in &ble_results {
        let mac = address.replace(':', "");
        let service_data = result
            .get("service_data")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let source = service_data.get(4..12).unwrap_or_default();
        let matched = (!source.is_empty() && source.chars().all(|c| c.is_ascii_hexdigit()))
            .then(|| devices.keys().find(|id| id.starts_with(source)))
            .flatten();
        if let Some(matched_id) = matched {
            if let Some(row) = rows
                .iter_mut()
                .find(|row| row.id == short_address(matched_id))
            {
                if !row.via.contains('B') {
                    let mut letters: Vec<char> = row.via.chars().collect();
                    letters.push('B');
                    letters.sort_unstable();
                    letters.dedup();
                    row.via = letters.into_iter().collect();
                }
                if row.rssi.is_none() {
                    row.rssi = result
                        .get("rssi")
                        .and_then(Value::as_i64)
                        .and_then(|value| i16::try_from(value).ok());
                }
            }
            continue;
        }
        rows.push(StatusRow {
            flags: String::new(),
            id: short_address(&mac).to_owned(),
            name: "-".to_owned(),
            via: "B".to_owned(),
            rssi: result
                .get("rssi")
                .and_then(Value::as_i64)
                .and_then(|value| i16::try_from(value).ok()),
            age_ms: Some(
                now_ms.saturating_sub(
                    result
                        .get("last_seen_ms")
                        .and_then(Value::as_i64)
                        .unwrap_or(now_ms),
                ),
            ),
            companion: false,
        });
    }
    rows.sort_by(|left, right| left.sort_key().cmp(&right.sort_key()));

    let mut text = String::from("DMesh");
    if let Some(percent) = battery.battery_percent {
        text.push_str(&format!(" bat {percent}%"));
        if battery.charging == Some(true) {
            text.push_str("chg");
        }
    }
    if battery.power_save == Some(true) {
        text.push_str(" psm");
    }
    let internet = networks
        .values()
        .any(|network| network.validated && network.internet);
    text.push_str(&format!(" net {}", networks.len()));
    if internet {
        text.push_str("(inet)");
    }
    text.push_str(&format!(" nodes {}", rows.len()));

    for (name, network) in networks.iter().take(8) {
        let transports = if network.transports.is_empty() {
            "-".to_owned()
        } else {
            network.transports.join("+")
        };
        let mut flags = String::new();
        if network.internet {
            flags.push_str("inet");
        }
        if network.validated {
            if !flags.is_empty() {
                flags.push(',');
            }
            flags.push_str("val");
        }
        if network.metered {
            if !flags.is_empty() {
                flags.push(',');
            }
            flags.push_str("mtr");
        }
        let address = network
            .addresses
            .iter()
            .find(|address| address.starts_with("fe80:"))
            .map(|address| address.split('%').next().unwrap_or(address))
            .unwrap_or("-");
        text.push_str(&format!("\n  {name} {transports}"));
        if !flags.is_empty() {
            text.push(' ');
            text.push_str(&flags);
        }
        text.push(' ');
        text.push_str(address);
    }
    for row in &rows {
        row.render(&mut text);
    }
    text
}

/// Tools catalog for the HTTP `status` service, generated from `API.md`.
pub(crate) fn status_tools_json() -> Value {
    dmesh_server::platform_catalog::tools_for("status.")
}

/// `status.text` (203/1): the status table, typed from `API.md`.
pub(crate) fn status_text_response() -> dmesh_server::platform_api::StatusTextResponse {
    dmesh_server::platform_api::StatusTextResponse {
        status_text: Some(status_text()),
    }
}

/// `radio.history` (202/1), typed from `API.md`.
#[cfg(target_os = "android")]
pub(crate) fn radio_history_response(
    request: dmesh_server::platform_api::RadioHistoryRequest,
) -> Result<dmesh_server::platform_api::RadioHistoryResponse, String> {
    serde_json::from_value(android_radio_history(
        request.limit,
        request.since_ms,
        request.keys,
    ))
    .map_err(|error| error.to_string())
}

/// Route the HTTP `probe` service to the registry, so the web UI and any HTTP
/// client can start a probe (`probe.start`, with `to` naming the node that runs
/// it and `peer` the node being probed) through the JSON-to-CBOR translator.
#[cfg(target_os = "android")]
pub(crate) fn register_probe_service(services: &ssh_mesh::mesh_rest::MeshServiceRegistry) -> bool {
    register_gateway_route(services, "probe");
    true
}

/// Route the HTTP `status` service to the registry.
/// Route the HTTP `telemetry` and `log` services to the registry, so the web UI
/// and any HTTP client reach `telemetry.*` and `log.watch` through the
/// JSON-to-CBOR translator.
#[cfg(target_os = "android")]
pub(crate) fn register_telemetry_services(
    services: &ssh_mesh::mesh_rest::MeshServiceRegistry,
) -> bool {
    register_gateway_route(services, "telemetry");
    register_gateway_route(services, "log");
    true
}

#[cfg(target_os = "android")]
pub(crate) fn register_status_service(services: &ssh_mesh::mesh_rest::MeshServiceRegistry) -> bool {
    register_gateway_route(services, "status");
    true
}

/// The discovery engine for this process, installed when the mesh starts.
static DISCOVERY_ENGINE: OnceLock<Arc<dmesh_discovery::Engine>> = OnceLock::new();

pub(crate) fn discovery_engine() -> Option<&'static Arc<dmesh_discovery::Engine>> {
    DISCOVERY_ENGINE.get()
}

/// Install (once) the engine whose device id is the hash of this node's SSH
/// public key, as Android has always advertised it.
pub(crate) fn install_discovery_engine(public_key: &str) -> Arc<dmesh_discovery::Engine> {
    DISCOVERY_ENGINE
        .get_or_init(|| {
            Arc::new(dmesh_discovery::Engine::new(
                Arc::new(dmesh_discovery::UnsignedIdentity::from_seed(
                    public_key.as_bytes(),
                )),
                Arc::new(AndroidFacts),
            ))
        })
        .clone()
}

/// What Android says about itself in its announce, from framework facts
/// already retained by Rust. UDP directed discovery and the Java NAN
/// projection use this one identity/routing shape: Android must not advertise
/// a second, UDP-only identity or a synthetic endpoint.
pub(crate) struct AndroidFacts;

/// Publish the service endpoint only while the corresponding listener exists.
/// Java may supply a route-marked socket with a different port from the Rust
/// fallback, so discovery must use the adopted socket rather than a default.
fn set_android_udp_endpoint(announce: &mut dmesh_server::announce::Announce, address: Ipv6Addr) {
    if let Some(listener) = crate::bearer::current().and_then(|runtime| runtime.udp_local_addr()) {
        announce.set_udp_link_local_v6(address.octets());
        announce.set_udp_port(listener.port());
    }
}

impl dmesh_discovery::LocalFacts for AndroidFacts {
    fn describe(&self, announce: &mut dmesh_server::announce::Announce) {
        announce.set_probe_descriptor(
            dmesh_server::announce::DEVICE_CLASS_ANDROID,
            dmesh_server::probe::PROBE_CAP_NAN
                | dmesh_server::probe::PROBE_CAP_STA
                | dmesh_server::probe::PROBE_CAP_AP
                | dmesh_server::probe::PROBE_CAP_UDP6,
        );
        let Ok(networks) = local_networks().lock() else {
            return;
        };
        let Some(network) = networks.networks.values().find(|network| {
            network.active
                && network
                    .transports
                    .iter()
                    .any(|transport| transport == "wifi")
        }) else {
            return;
        };
        if let Some(ssid) = network.ssid.as_deref().filter(|ssid| !ssid.is_empty()) {
            let _ = announce.set_network_name(ssid);
        }
        if let Some(address) = network.addresses.iter().find_map(|address| {
            address
                .parse::<Ipv6Addr>()
                .ok()
                .filter(Ipv6Addr::is_unicast_link_local)
        }) {
            announce.set_sta_link_local_v6(address.octets());
            set_android_udp_endpoint(announce, address);
        }
    }

    /// The unsigned, receiver-side NAN facts carried beside Android's
    /// discovery record. Wi-Fi Aware does not expose a peer cluster/BSSID
    /// through its public API, so the cluster suffix stays absent; service
    /// receipt and visible-node counts come from the NAN observation cache
    /// returned by `discovery.nodes`.
    fn radio_facts(&self) -> Option<dmesh_server::announce::DiscoveryFacts> {
        let devices = discovery_engine()?.devices();
        let mut services = 0u16;
        let mut nodes = 0u16;
        for device in &devices {
            if let Some(observation) = device.observations.get("nan") {
                nodes = nodes.saturating_add(1);
                services = services
                    .saturating_add(u16::try_from(observation.packets).unwrap_or(u16::MAX));
            }
        }
        Some(dmesh_server::announce::DiscoveryFacts {
            nan_cluster_suffix: None,
            nan_service_observations: services,
            nan_visible_nodes: nodes,
        })
    }
}

/// Admit one received NAN directed message into the common device inventory.
/// The frame remains an observation until the portable follow-up parser has
/// validated it; no Android-only command or follow-up protocol is introduced.
fn observe_nan_followup_packet(
    peer: &str,
    payload: &[u8],
    rssi_dbm: Option<i32>,
) -> anyhow::Result<Value> {
    // Android's public Wi-Fi Aware callback may retain the SDEA Generic
    // protocol OUI/type before the Service Specific Info. ESP/Linux adapters
    // already pass SSI itself. Normalize only this standard transport wrapper
    // so all three reach the one DMesh follow-up parser with identical bytes.
    let payload = payload
        .strip_prefix(&[0x50, 0x6f, 0x9a, 0x02])
        .unwrap_or(payload);
    let parsed = match radio_protocol::parse_nan_followup(payload) {
        Ok(parsed) => parsed,
        Err(error) => {
            // Android framework delivery is meaningful evidence even when a
            // peer has not used the DMesh follow-up envelope. Keep that fact
            // bounded and payload-free so the caller can distinguish a
            // framework/session mismatch from a portable framing mismatch.
            return Ok(json!({
                "ok": false,
                "error": error.to_string(),
                "payload_len": payload.len(),
                "payload_hash": dmesh_server::discovery::payload_hash(payload),
                "prefix_hex": bytes_to_hex(&payload[..payload.len().min(4)]),
            }));
        }
    };
    let src_device = parsed
        .get("device_id")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let target_device = parsed
        .get("target_id")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let seq = parsed.get("seq").and_then(|v| v.as_u64()).map(|s| s as u16);
    let msg_type = parsed
        .get("msg_type")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let packet_hash = parsed
        .get("payload_hash_u32")
        .and_then(|v| v.as_u64())
        .map(|h| h as u32)
        .unwrap_or_else(|| dmesh_server::discovery::payload_hash(payload));
    let frame = RadioEvent {
        protocol: "dmesh_nan_followup".to_string(),
        payload_hash: packet_hash,
        source: src_device.to_string(),
        target: (!target_device.is_empty()).then(|| target_device.to_string()),
        seq,
        event: (!msg_type.is_empty()).then(|| msg_type.to_string()),
        payload: payload.to_vec(),
        timestamp_ms: chrono::Utc::now().timestamp_millis(),
    };
    record_nan_followup(frame.clone());
    // A directed Follow-up carries the same tagged-CBOR announce bytes as
    // NAN Service Info and UDP discovery. Promote that semantic record through
    // the one inventory ingress before retaining a provisional radio address;
    // otherwise a host P2P group MAC becomes a second, Android-only device.
    if let Some(followup) = dmesh_rawnan::parse_dmesh_nan_followup(payload)
        && let Some(announce) = dmesh_server::announce::decode_announce(followup.payload)
    {
        let semantic_id = bytes_to_hex(announce.device_id());
        observe_announce(announce, peer.to_owned(), "nan_followup", followup.payload);
        return Ok(json!({
            "status": "ok",
            "packet_kind": "followup",
            "source": src_device,
            "semantic_id": semantic_id,
        }));
    }
    if !src_device.is_empty() {
        if let Some(engine) = discovery_engine() {
            let mut carrier = dmesh_discovery::Carrier::radio(
                "nan",
                peer,
                dmesh_server::discovery::DiscoveryPacketKind::Followup,
            );
            carrier.rssi_dbm = rssi_dbm.and_then(|value| i16::try_from(value).ok());
            engine.observe_provisional(&carrier, src_device, payload);
        }
    }
    Ok(json!({"status": "ok", "packet_kind": "followup", "source": src_device}))
}

/// Record a common announce from any Android discovery bearer.
/// `source` is provenance only: boot and periodic presence records update the
/// one inventory whether UDP multicast, NAN Service Info, or a future
/// control-plane adapter delivered them. UDP datagrams the engine reads itself
/// are recorded by its own receive path; this entry is for adapters (NAN) that
/// decode the announce themselves.
pub(crate) fn observe_announce(
    announce: dmesh_server::announce::Announce,
    peer: String,
    source: &str,
    payload: &[u8],
) {
    use dmesh_server::discovery::DiscoveryPacketKind;
    let Some(engine) = discovery_engine() else {
        return;
    };
    let (bearer, kind) = match source {
        "nan_followup" => ("nan", DiscoveryPacketKind::Followup),
        source if source.starts_with("nan") => ("nan", DiscoveryPacketKind::ActivePublish),
        other => (other, DiscoveryPacketKind::Other),
    };
    engine.observe_announce(
        &dmesh_discovery::Carrier::radio(bearer, &peer, kind),
        announce,
        payload,
    );
}

/// The Android settings file: app-private, next to the paired-device store.
fn android_settings_store() -> Option<dmesh_server::settings::FileSettings> {
    let base = ANDROID_DEVICE_RECORDS_PATH.get()?.parent()?;
    Some(dmesh_server::settings::FileSettings::new(
        base.join("settings.conf"),
        "android",
    ))
}

/// `settings.get`/`set`/`list` on one settings store, in the same result
/// shape the firmware returns: `{key, value}`, `{key, set}` or `{entries}`.
/// Secrets (`sec:*`) are never read or written through this handler.
pub(crate) fn settings_response_for(
    store: &mut dmesh_server::settings::FileSettings,
    request: &[u8],
) -> Option<Vec<u8>> {
    use dmesh_server::{cbor::Encoder, control, settings::SettingsHandler, tagged};
    let id = tagged::decode(request)?.id?;
    let request = control::decode_request(request)?;
    let mut result = [0u8; 1024];
    let mut encoder = Encoder::new(&mut result);
    let method = match request {
        control::Request::SettingsGet { key } => {
            let name = core::str::from_utf8(key).ok().filter(|name| !name.starts_with("sec:"))?;
            let value = SettingsHandler::new(store).get(name).ok()?;
            encoder.map(2)?;
            encoder.text_value(b"key")?;
            encoder.text_value(key)?;
            encoder.text_value(b"value")?;
            encoder.text_value(value.as_bytes())?;
            control::SETTINGS_GET
        }
        control::Request::SettingsSet { key, value } => {
            let name = core::str::from_utf8(key).ok().filter(|name| !name.starts_with("sec:"))?;
            let value = core::str::from_utf8(value).ok()?;
            SettingsHandler::new(store).set(name, value).ok()?;
            encoder.map(2)?;
            encoder.text_value(b"key")?;
            encoder.text_value(key)?;
            encoder.text_value(b"set")?;
            encoder.bool(true)?;
            control::SETTINGS_SET
        }
        control::Request::SettingsList => {
            let entries: Vec<_> = SettingsHandler::new(store)
                .list()
                .ok()?
                .into_iter()
                .filter(|(key, _)| !key.starts_with("sec:"))
                .collect();
            encoder.map(1)?;
            encoder.text_value(b"entries")?;
            encoder.array(entries.len() as u64)?;
            for (key, value) in &entries {
                encoder.map(2)?;
                encoder.text_value(b"key")?;
                encoder.text_value(key.as_bytes())?;
                encoder.text_value(b"value")?;
                encoder.text_value(value.as_bytes())?;
            }
            control::SETTINGS_LIST
        }
        _ => return None,
    };
    let used = encoder.len();
    drop(encoder);
    let mut out = vec![0u8; used + 32];
    let written =
        tagged::encode_numeric_response(control::CONTROL_COMPONENT, method, id, &result[..used], &mut out)?;
    out.truncate(written);
    Some(out)
}

fn android_settings_response(request: &[u8]) -> Option<Vec<u8>> {
    settings_response_for(&mut android_settings_store()?, request)
}

/// The UDP endpoint to use for a node identifier (`mesh://VIP`, a hex device id,
/// or a name), from the shared discovery inventory: the address the device
/// advertised with the interface scope of the datagram that carried it. A
/// device seen only over NAN or BLE is reported as unroutable, not guessed.
pub(crate) fn discovered_udp_endpoint(key: &str) -> Result<std::net::SocketAddr, String> {
    discovery_engine()
        .ok_or_else(|| "discovery is not running".to_owned())?
        .resolve_udp(key)
        .map_err(|error| error.to_string())
}

#[cfg(target_os = "android")]
fn configure_android_mesh_paths(base_dir: &str) {
    let base = std::path::Path::new(base_dir);
    let _ = ANDROID_DEVICE_RECORDS_PATH.set(base.join("paired"));
    let run_base = base.join("run").join("mesh");
    let home_base = base.join("home");
    let opt_base = base.join("opt");
    let schema_base = base.join("schemas");

    for dir in [&run_base, &home_base, &opt_base] {
        if let Err(e) = std::fs::create_dir_all(dir) {
            log::warn!(
                "Failed to create Android mesh path {}: {}",
                dir.display(),
                e
            );
        }
    }

    // The upstream HTTP gateway resolves one generated catalog per service.
    // Keep these app-private files in sync with the Rust adapters while Java
    // remains the platform callback boundary.
    for (component, tools) in [
        ("companion", dmesh_server::companion::tools_json()),
        ("ble", dmesh_server::ble_service::tools_json()),
        ("usb", dmesh_server::usb_service::tools_json()),
        ("wifi", dmesh_server::wifi_service::tools_json()),
        ("transport", dmesh_server::transport_service::tools_json()),
        ("radio", dmesh_server::platform_catalog::tools_for("radio.")),
        ("status", status_tools_json()),
        ("probe", dmesh_server::platform_catalog::tools_for("probe.")),
        (
            "telemetry",
            dmesh_server::platform_catalog::tools_for("telemetry."),
        ),
        ("log", dmesh_server::platform_catalog::tools_for("log.")),
    ] {
        let dir = schema_base.join(component);
        let result = (|| -> std::io::Result<()> {
            std::fs::create_dir_all(&dir)?;
            let path = dir.join("tools.json");
            let temporary = dir.join("tools.json.tmp");
            let bytes = serde_json::to_vec(&tools).map_err(std::io::Error::other)?;
            std::fs::write(&temporary, bytes)?;
            std::fs::rename(temporary, path)
        })();
        if let Err(error) = result {
            log::warn!("Failed to install {component} mesh schema: {error}");
        }
    }

    // Android has no system mesh runtime directory. Keep any defensive UDS
    // fallback under the app's files/ tree and route web commands by bridge.
    unsafe {
        std::env::set_var("MESH_HOME", base);
        std::env::set_var("MESH_RUN_BASE", &run_base);
        std::env::set_var("MESH_HOME_BASE", &home_base);
        std::env::set_var("MESH_OPT_BASE", &opt_base);
        std::env::set_var("MESH_SCHEMA_DIR", &schema_base);
        std::env::set_var("SSH_MESH_HOME_ROOT", &home_base);
        std::env::set_var("LMESH_UDS", run_base.join("lmesh").join("mesh.sock"));
        std::env::set_var(
            "MESH_INIT_UDS",
            run_base.join("mesh-init").join("mesh.sock"),
        );
    }
}

#[cfg(target_os = "android")]
const ANDROID_LOG_DEBUG: c_int = 3;
#[cfg(target_os = "android")]
const ANDROID_LOG_INFO: c_int = 4;
#[cfg(target_os = "android")]
const ANDROID_LOG_WARN: c_int = 5;
#[cfg(target_os = "android")]
const ANDROID_LOG_ERROR: c_int = 6;

#[cfg(target_os = "android")]
#[link(name = "log")]
unsafe extern "C" {
    fn __android_log_write(prio: c_int, tag: *const c_char, text: *const c_char) -> c_int;
}

#[cfg(target_os = "android")]
struct AndroidLog;

#[cfg(target_os = "android")]
impl log::Log for AndroidLog {
    fn enabled(&self, metadata: &log::Metadata<'_>) -> bool {
        metadata.level() <= log::Level::Trace
    }

    fn log(&self, record: &log::Record<'_>) {
        if self.enabled(record.metadata()) {
            let line = json!({
                "level": record.level().to_string(),
                "target": record.target(),
                "message": record.args().to_string(),
            })
            .to_string();
            android_log_write(android_log_priority(record.level()), "dmesh-rust", &line);
        }
    }

    fn flush(&self) {}
}

#[cfg(target_os = "android")]
struct AndroidTraceWriter {
    buf: Vec<u8>,
}

#[cfg(target_os = "android")]
impl Write for AndroidTraceWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.buf.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(target_os = "android")]
impl Drop for AndroidTraceWriter {
    fn drop(&mut self) {
        let line = String::from_utf8_lossy(&self.buf);
        let line = line.trim();
        if !line.is_empty() {
            android_log_write(ANDROID_LOG_INFO, "dmesh-trace", line);
        }
    }
}

#[cfg(target_os = "android")]
struct AndroidTraceMakeWriter;

#[cfg(target_os = "android")]
impl<'a> MakeWriter<'a> for AndroidTraceMakeWriter {
    type Writer = AndroidTraceWriter;

    fn make_writer(&'a self) -> Self::Writer {
        AndroidTraceWriter { buf: Vec::new() }
    }
}

#[cfg(target_os = "android")]
fn android_log_priority(level: log::Level) -> c_int {
    match level {
        log::Level::Error => ANDROID_LOG_ERROR,
        log::Level::Warn => ANDROID_LOG_WARN,
        log::Level::Info => ANDROID_LOG_INFO,
        log::Level::Debug | log::Level::Trace => ANDROID_LOG_DEBUG,
    }
}

#[cfg(target_os = "android")]
fn android_log_write(priority: c_int, tag: &str, message: &str) {
    let tag = cstring_lossy(tag);
    let message = cstring_lossy(message);
    unsafe {
        __android_log_write(priority, tag.as_ptr(), message.as_ptr());
    }
}

#[cfg(target_os = "android")]
fn android_message_callback() -> &'static Mutex<Option<(Arc<JavaVM>, GlobalRef)>> {
    ANDROID_MESSAGE_CALLBACK.get_or_init(|| Mutex::new(None))
}

#[cfg(target_os = "android")]
fn cstring_lossy(value: &str) -> CString {
    CString::new(value).unwrap_or_else(|_| {
        CString::new(value.replace('\0', "\\0")).unwrap_or_else(|_| CString::default())
    })
}

#[cfg(target_os = "android")]
fn init_android_logging() {
    ANDROID_LOG_INIT.call_once(|| {
        if log::set_logger(&ANDROID_LOGGER).is_ok() {
            log::set_max_level(log::LevelFilter::Info);
        }

        let filter = tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
        let buffer_layer = mesh::local_trace::LogBufferLayer::new();
        let _ = ANDROID_TELEMETRY.set(buffer_layer.buffer());
        let _ = tracing_subscriber::registry()
            .with(filter)
            .with(buffer_layer)
            .with(
                tracing_subscriber::fmt::layer()
                    .with_ansi(false)
                    .json()
                    .with_writer(AndroidTraceMakeWriter),
            )
            .try_init();

        log::info!("Android Rust logging initialized");
    });
}

#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
pub extern "system" fn JNI_OnLoad(_vm: *mut jni::sys::JavaVM, _reserved: *mut c_void) -> jint {
    init_android_logging();
    JNI_VERSION_1_6
}

#[cfg(target_os = "android")]
fn catch_jni_jlong<F>(name: &str, f: F) -> jlong
where
    F: FnOnce() -> anyhow::Result<jlong>,
{
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(Ok(value)) => value,
        Ok(Err(error)) => {
            log::error!("{} failed: {}", name, error);
            -1
        }
        Err(payload) => {
            let message = payload
                .downcast_ref::<&str>()
                .map(|s| (*s).to_string())
                .or_else(|| payload.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "unknown panic payload".to_string());
            log::error!("{} panicked: {}", name, message);
            -1
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BridgeCommand {
    id: Option<String>,
    method: String,
    data: BTreeMap<String, String>,
}

fn radio_message(method: &str, args: &str, payload: &[u8], _fd: i32) -> anyhow::Result<Vec<u8>> {
    let cmd = parse_bridge_human(&format!("{} {}", method, args.trim()))?;
    if let Some(uid) = cmd.data.get("caller_uid") {
        let pkg = cmd
            .data
            .get("caller_package")
            .map(String::as_str)
            .unwrap_or("");
        let same_sig = cmd
            .data
            .get("caller_same_sig")
            .map(String::as_str)
            .unwrap_or("false");
        let cert = cmd
            .data
            .get("caller_cert_sha256")
            .map(String::as_str)
            .unwrap_or("");
        log::info!(
            "radio_message caller identity: uid={} pkg={} same_sig={} cert_sha256={}",
            uid,
            pkg,
            same_sig,
            cert
        );
    }
    let response = match cmd.method.as_str() {
        "radio.nan.build_service_info" => {
            let role = cmd
                .data
                .get("role")
                .map(String::as_str)
                .unwrap_or("android");
            let device_id = hex_to_bytes(required_data(&cmd, "device_id")?)?;
            let wake_count = parse_u32(&cmd, "wake_count", 0)?;
            radio_protocol::build_nan_service_info(role, &device_id, wake_count)?
        }
        "radio.nan.build_announce" => {
            let device_id = hex_to_bytes(required_data(&cmd, "device_id")?)?;
            let uptime_secs = parse_u32(&cmd, "uptime_secs", 0)?;
            let mut id = [0; 16];
            if device_id.is_empty() || device_id.len() > id.len() {
                anyhow::bail!("announce device id must be 1..16 bytes");
            }
            id[..device_id.len()].copy_from_slice(&device_id);
            let announce =
                dmesh_server::announce::Announce::discovery(id, device_id.len() as u8, uptime_secs);
            // Android emits the same descriptor used by Linux and ESP.  The
            // advertised subset avoids scheduling ESP-NOW rows for phones;
            // Android-specific NAN data-path capability remains a separate
            // request bit because it is framework- and permission-dependent.
            let mut announce = announce;
            announce.set_probe_descriptor(
                dmesh_server::announce::DEVICE_CLASS_ANDROID,
                dmesh_server::probe::PROBE_CAP_NAN
                    | dmesh_server::probe::PROBE_CAP_STA
                    | dmesh_server::probe::PROBE_CAP_AP
                    | dmesh_server::probe::PROBE_CAP_UDP6,
            );
            if let Some(name) = cmd.data.get("device_name").filter(|name| !name.is_empty())
                && !announce.set_device_name(name)
            {
                anyhow::bail!("device_name must be valid UTF-8 and at most 8 bytes");
            }
            if let Some(name) = cmd.data.get("network_name").filter(|name| !name.is_empty())
                && !announce.set_network_name(name)
            {
                anyhow::bail!("network_name must be valid UTF-8 and at most 32 bytes");
            }
            if let Some(address) = cmd
                .data
                .get("sta_link_local_v6")
                .filter(|value| !value.is_empty())
            {
                let address = address
                    .parse::<Ipv6Addr>()
                    .map_err(|_| anyhow::anyhow!("sta_link_local_v6 must be IPv6"))?;
                if !address.is_unicast_link_local() {
                    anyhow::bail!("sta_link_local_v6 must be link-local");
                }
                announce.set_sta_link_local_v6(address.octets());
                // NAN is discovery/activation, not a separate data bearer.
                // A peer that learns Android's link-local endpoint over NAN
                // must use the same normal QUIC UDP listener as multicast and
                // directed discovery, not an Android-only port convention.
                set_android_udp_endpoint(&mut announce, address);
            }
            let mut out = [0; 96];
            let used = dmesh_server::announce::encode(announce, &mut out)
                .ok_or_else(|| anyhow::anyhow!("announce encoding exceeded bound"))?;
            out[..used].to_vec()
        }
        "radio.nan.parse_service_info" => radio_protocol::parse_nan_service_info(payload)?
            .to_string()
            .into_bytes(),
        "radio.nan.observe_service_info" => {
            let peer = cmd.data.get("peer").cloned().unwrap_or_default();
            let announce = dmesh_server::announce::decode_announce(payload);
            let parsed = if let Some(announce) = announce {
                // This is exactly the same presence ingress as UDP multicast,
                // not a NAN-specific device cache.
                observe_announce(announce, peer.clone(), "nan_sd", payload);
                json!({
                    "protocol": "dmesh_announce",
                    "source": "nan_sd",
                    "device_id": bytes_to_hex(announce.device_id()),
                    "kind": announce.kind,
                    "uptime_secs": announce.uptime_secs,
                    "device_name": announce.device_name(),
                    "network_name": announce.network_name(),
                    "sta_link_local_v6": announce.sta_link_local_v6().map(std::net::Ipv6Addr::from).map(|address| address.to_string()),
                    "vip6": dmesh_server::announce::virtual_ip6(announce.public_key()).map(std::net::Ipv6Addr::from).map(|address| address.to_string()),
                })
            } else {
                radio_protocol::parse_nan_service_info(payload)?
            };
            let device_id = parsed
                .get("device_id")
                .and_then(|value| value.as_str())
                .unwrap_or("");
            // Non-announce NAN Service Info has its own wire schema but
            // still belongs in the same cross-bearer device inventory.
            if announce.is_none() && !device_id.is_empty() {
                if let Some(engine) = discovery_engine() {
                    engine.observe_provisional(
                        &dmesh_discovery::Carrier::radio(
                            "nan",
                            &peer,
                            dmesh_server::discovery::DiscoveryPacketKind::ActivePublish,
                        ),
                        device_id,
                        payload,
                    );
                }
            }
            parsed.to_string().into_bytes()
        }
        "radio.local_networks.update" => {
            let count = update_local_networks(payload)?;
            json!({"ok": true, "interfaces": count})
                .to_string()
                .into_bytes()
        }
        "discovery.status" => {
            let networks = local_networks()
                .lock()
                .map_err(|_| anyhow::anyhow!("local-networks table poisoned"))?
                .networks
                .values()
                .map(dmesh_server::local_networks::json_network)
                .collect::<Vec<_>>();
            json!({"networks": networks, "local_networks": networks, "stats": {"devices": discovered_devices_view().len()}}).to_string().into_bytes()
        }
        "discovery.active" => {
            #[cfg(target_os = "android")]
            {
                schedule_android_discovery_active()
                    .ok_or_else(|| anyhow::anyhow!("discovery fan-out callback unavailable"))?;
                json!({"ok": true, "status": "accepted", "operation": "discovery.active"})
                    .to_string()
                    .into_bytes()
            }
            #[cfg(not(target_os = "android"))]
            anyhow::bail!("discovery.active requires an installed platform adapter")
        }
        "battery.state.update" => update_battery_state(payload)?.to_string().into_bytes(),
        "radio.power.status" => update_power_state(payload)?.to_string().into_bytes(),
        "radio.power.state" => dmesh_server::power::json_status(
            *power_state()
                .lock()
                .map_err(|_| anyhow::anyhow!("power state poisoned"))?,
        )
        .to_string()
        .into_bytes(),
        "telemetry.battery" => dmesh_server::power::battery_json_status(
            power_state()
                .lock()
                .map_err(|_| anyhow::anyhow!("power state poisoned"))?
                .battery,
        )
        .to_string()
        .into_bytes(),
        "discovery.nodes" | "radio.nan.known_devices" => {
            dmesh_server::discovery::inventory_json(&discovered_devices_view())
                .to_string()
                .into_bytes()
        }
        "radio.status_text" => status_text().into_bytes(),
        "probe.plan" => {
            let source_id = required_data(&cmd, "source_id")?;
            let target_id = required_data(&cmd, "target_id")?;
            if source_id == target_id {
                anyhow::bail!("source_id and target_id must differ");
            }
            let short_bytes = parse_u32(&cmd, "short_bytes", 4 * 1024)?;
            let long_bytes = parse_u32(&cmd, "long_bytes", 64 * 1024)?;
            let devices = discovered_devices_view();
            let descriptor =
                |id: &str| -> anyhow::Result<dmesh_server::probe::ProbeDeviceDescriptor> {
                    let device = devices
                        .get(id)
                        .ok_or_else(|| anyhow::anyhow!("Android discovery has no device {id:?}"))?;
                    let class = device
                        .info
                        .get("device_class")
                        .and_then(Value::as_u64)
                        .and_then(|value| u8::try_from(value).ok())
                        .unwrap_or(dmesh_server::announce::DEVICE_CLASS_UNKNOWN);
                    let kind = match class {
                        class if dmesh_server::announce::is_esp_device_class(class) => {
                            dmesh_server::probe::ProbeEndpointKind::Esp
                        }
                        dmesh_server::announce::DEVICE_CLASS_HOST => {
                            dmesh_server::probe::ProbeEndpointKind::Host
                        }
                        dmesh_server::announce::DEVICE_CLASS_ANDROID => {
                            dmesh_server::probe::ProbeEndpointKind::Android
                        }
                        _ => anyhow::bail!(
                            "Android discovery device {id:?} has no supported device_class"
                        ),
                    };
                    let capabilities = device
                        .info
                        .get("probe_capabilities")
                        .and_then(Value::as_u64)
                        .and_then(|value| u16::try_from(value).ok())
                        .filter(|value| *value != 0)
                        .ok_or_else(|| {
                            anyhow::anyhow!(
                                "Android discovery device {id:?} has no probe capabilities"
                            )
                        })?;
                    let id_bytes = hex_to_bytes(id)?;
                    if id_bytes.len() < 6 {
                        anyhow::bail!(
                            "Android discovery device {id:?} has no six-byte radio identity"
                        );
                    }
                    let mut node = [0; 6];
                    node.copy_from_slice(&id_bytes[..6]);
                    Ok(dmesh_server::probe::ProbeDeviceDescriptor {
                        endpoint: dmesh_server::probe::ProbeEndpoint {
                            kind,
                            node,
                            mode: dmesh_server::probe::ProbeMode::NAN_NOW,
                            bssid: None,
                        },
                        capabilities,
                    })
                };
            let source = descriptor(source_id)?;
            let target = descriptor(target_id)?;
            let rows = dmesh_server::probe::full_pair_probe_requests(
                0x4D_50_3000,
                source,
                target,
                short_bytes,
                long_bytes,
            );
            if rows.is_empty() {
                anyhow::bail!("selected Android-control-plane endpoints share no NAN row");
            }
            // Match the lmesh-wifi plan response: the local controller can
            // present a live ESP/Android/Host fleet picker before it selects
            // two endpoints. This is observation only and does not alter the
            // Android controller's own NAN, AP, or STA state.
            let discovered = devices
                .iter()
                .filter_map(|(_, device)| {
                    let class = device.info.get("device_class")?.as_u64()? as u8;
                    let kind = match class {
                        class if dmesh_server::announce::is_esp_device_class(class) => "esp",
                        dmesh_server::announce::DEVICE_CLASS_HOST => "host",
                        dmesh_server::announce::DEVICE_CLASS_ANDROID => "android",
                        _ => return None,
                    };
                    let capabilities = device.info.get("probe_capabilities")?.as_u64()?;
                    let identity = device
                        .info
                        .get("device_name")
                        .and_then(Value::as_str)
                        .filter(|value| !value.is_empty())
                        .or_else(|| device.info.get("vip6").and_then(Value::as_str));
                    let mut value = json!({
                        "kind": kind,
                        "capabilities": capabilities,
                    });
                    if let Some(identity) = identity {
                        value["identity"] = Value::String(identity.to_owned());
                    }
                    Some(value)
                })
                .collect::<Vec<_>>();
            json!({
                "ok": true,
                "control_plane": "android",
                "control_plane_mode_changed": false,
                "discovered": discovered,
                "source": source,
                "target": target,
                "rows": rows,
            })
            .to_string()
            .into_bytes()
        }
        "radio.nan.followups" => {
            let history = nan_followups()
                .lock()
                .map_err(|_| anyhow::anyhow!("NAN follow-up cache poisoned"))?;
            let entries = history
                .iter()
                .rev()
                .map(|entry| {
                    json!({
                        "last_seen_ms": entry.timestamp_ms,
                        "source": entry.source,
                        "target": entry.target,
                        "seq": entry.seq,
                        "msg_type": entry.event,
                        "payload_hash": entry.payload_hash,
                        "payload_hex": bytes_to_hex(&entry.payload),
                    })
                })
                .collect::<Vec<_>>();
            json!({"followups": entries}).to_string().into_bytes()
        }
        "radio.nan.events" => {
            let history = nan_events()
                .lock()
                .map_err(|_| anyhow::anyhow!("NAN event cache poisoned"))?;
            let entries = history
                .iter()
                .rev()
                .map(|entry| {
                    json!({
                        "last_seen_ms": entry.timestamp_ms,
                        "event": entry.event,
                        "peer": entry.source,
                        "payload_hex": bytes_to_hex(&entry.payload),
                    })
                })
                .collect::<Vec<_>>();
            json!({"events": entries}).to_string().into_bytes()
        }
        "telemetry.nan_status" => {
            let now_ms = chrono::Utc::now().timestamp_millis();
            let events = nan_events()
                .lock()
                .map_err(|_| anyhow::anyhow!("NAN event cache poisoned"))?;
            // Android's public Wi-Fi Aware callbacks are the authority for
            // local session state. Preserve their ordering: a terminated
            // callback must win over an older successful attach, while a new
            // attach can make the session active again. Discovery receipt
            // records are peer facts and intentionally do not imply that the
            // local Aware session remains attached.
            let mut active = false;
            let mut publish_active = false;
            let mut subscribe_active = false;
            let mut last_event = None;
            for entry in events
                .iter()
                .filter(|entry| now_ms.saturating_sub(entry.timestamp_ms) <= 10 * 60 * 1_000)
            {
                let Some(event) = entry.event.as_deref() else {
                    continue;
                };
                last_event = Some(event);
                match event {
                    "attached" | "aware.on_attached" => active = true,
                    "aware.on_session_terminated"
                    | "aware.on_attach_failed"
                    | "aware.session_close" => {
                        active = false;
                        publish_active = false;
                        subscribe_active = false;
                    }
                    "aware.on_publish_started" if active => publish_active = true,
                    "aware.on_publish_terminated" | "aware.publish_close" => {
                        publish_active = false;
                    }
                    "aware.on_subscribe_started" if active => subscribe_active = true,
                    "aware.on_subscribe_terminated" | "aware.subscribe_close" => {
                        subscribe_active = false;
                    }
                    _ => {}
                }
            }
            json!({
                "active": active,
                "publish_active": publish_active,
                "subscribe_active": subscribe_active,
                "last_event": last_event,
            })
            .to_string()
            .into_bytes()
        }
        // Connection packet counters are supplied by the shared QUIC server;
        // this platform handler contributes only Android's bounded endpoint
        // identity.  Keeping the bare service name here makes numeric
        // component 9/status work through the same catalog projection as
        // Linux and ESP instead of growing an Android-only alias.
        "status" => json!({"status_version": 1, "platform": "android"})
            .to_string()
            .into_bytes(),
        "telemetry.now" | "telemetry.udp6" | "telemetry.wifi_link" => {
            b"{}".to_vec()
        }
        "telemetry.nan" => {
            let followups = nan_followups()
                .lock()
                .map_err(|_| anyhow::anyhow!("NAN follow-up cache poisoned"))?;
            let events = nan_events()
                .lock()
                .map_err(|_| anyhow::anyhow!("NAN event cache poisoned"))?;
            json!({"events": events.len(), "followups": followups.len()})
                .to_string()
                .into_bytes()
        }
        "radio.nan.event" => {
            let event = cmd.data.get("event").cloned().unwrap_or_default();
            let peer = cmd.data.get("peer").cloned().unwrap_or_default();
            let frame = RadioEvent {
                protocol: "android_nan_event".to_string(),
                payload_hash: 0,
                source: peer,
                target: None,
                seq: None,
                event: (!event.is_empty()).then_some(event),
                payload: payload.to_vec(),
                timestamp_ms: chrono::Utc::now().timestamp_millis(),
            };
            record_nan_event(frame.clone());
            json!({"status": "ok"}).to_string().into_bytes()
        }
        "radio.transport.event" => {
            let transport = cmd.data.get("transport").cloned().unwrap_or_default();
            let event = cmd.data.get("event").cloned().unwrap_or_default();
            if transport == "ble" && event.starts_with("scan_result:") {
                record_ble_scan_result(&event, payload);
            }
            json!({"status": "ok"}).to_string().into_bytes()
        }
        "radio.nan.build_followup" => {
            let msg_type = cmd
                .data
                .get("msg_type")
                .map(String::as_str)
                .unwrap_or("hello");
            let device_id = hex_to_bytes(required_data(&cmd, "device_id")?)?;
            let target_id = hex_to_bytes(required_data(&cmd, "target_id")?)?;
            radio_protocol::build_nan_followup(msg_type, &device_id, &target_id, payload)?
        }
        "radio.nan.build_sta_activation" => {
            let source = hex_to_bytes(required_data(&cmd, "source_id")?)?;
            let source: [u8; 6] = source
                .as_slice()
                .try_into()
                .map_err(|_| anyhow::anyhow!("source_id must be exactly six bytes"))?;
            let wake_target = hex_to_bytes(required_data(&cmd, "wake_target")?)?;
            let wake_target: [u8; 6] = wake_target
                .as_slice()
                .try_into()
                .map_err(|_| anyhow::anyhow!("wake_target must be exactly six bytes"))?;
            let request = dmesh_server::control::Request::TransportSet {
                kind: dmesh_server::control::TransportKind::Sta,
                config: dmesh_server::control::TransportConfig {
                    wake_target: Some(wake_target),
                    ..dmesh_server::control::TransportConfig::default()
                },
            };
            let mut out = [0u8; 96];
            let used = dmesh_server::control::encode_request(request, None, &mut out)
                .ok_or_else(|| anyhow::anyhow!("encode targeted STA activation"))?;
            radio_protocol::build_nan_followup("wake_request", &source, &wake_target, &out[..used])?
        }
        "radio.nan.build_activation" => {
            let source = hex_to_bytes(required_data(&cmd, "source_id")?)?;
            let source: [u8; 6] = source
                .as_slice()
                .try_into()
                .map_err(|_| anyhow::anyhow!("source_id must be exactly six bytes"))?;
            let wake_target = hex_to_bytes(required_data(&cmd, "wake_target")?)?;
            let wake_target: [u8; 6] = wake_target
                .as_slice()
                .try_into()
                .map_err(|_| anyhow::anyhow!("wake_target must be exactly six bytes"))?;
            let id = parse_u32(&cmd, "id", 1)?.max(1) as u64;
            let kind = match parse_i32(&cmd, "kind", 6)? {
                1 => dmesh_server::control::TransportKind::Sta,
                5 => dmesh_server::control::TransportKind::Uart,
                6 => dmesh_server::control::TransportKind::Nan,
                other => anyhow::bail!("unsupported transport kind {other}"),
            };
            let nan = matches!(kind, dmesh_server::control::TransportKind::Nan);
            let default_on = if nan { 1 } else { 0 };
            let ap = parse_i32(&cmd, "ap", default_on)?;
            let now = parse_i32(&cmd, "now", default_on)?;
            let ble = parse_i32(&cmd, "ble", 0)?;
            let dw = parse_i32(&cmd, "nan_dw_interval", default_on)?;
            if !matches!(ap, 0..=1) {
                anyhow::bail!("ap must be 0 or 1");
            }
            if !matches!(now, 0..=2) {
                anyhow::bail!("now must be 0, 1, or 2");
            }
            if !matches!(ble, 0..=2) {
                anyhow::bail!("ble must be 0, 1, or 2");
            }
            if !matches!(dw, 0 | 1 | 8 | 16) {
                anyhow::bail!("nan_dw_interval must be 0, 1, 8, or 16");
            }
            let request = dmesh_server::control::Request::TransportSet {
                kind,
                config: dmesh_server::control::TransportConfig {
                    nan_dw_interval: nan.then_some(dw as u8),
                    now: Some(now as u8),
                    ap: Some(ap as u8),
                    ble: Some(ble as u8),
                    wake_target: Some(wake_target),
                    ..dmesh_server::control::TransportConfig::default()
                },
            };
            let mut out = [0u8; 160];
            let used = dmesh_server::control::encode_request(request, Some(id), &mut out)
                .ok_or_else(|| anyhow::anyhow!("encode targeted activation"))?;
            radio_protocol::build_nan_followup("wake_request", &source, &wake_target, &out[..used])?
        }
        "radio.nan.parse_followup" => radio_protocol::parse_nan_followup(payload)?
            .to_string()
            .into_bytes(),
        "radio.nan.inject_frame" | "radio.nan.observe_packet" => {
            let peer = cmd.data.get("peer").map(String::as_str).unwrap_or("");
            let rssi = parse_i32(&cmd, "rssi", -1)?;
            observe_nan_followup_packet(peer, payload, (rssi != -1).then_some(rssi))?
                .to_string()
                .into_bytes()
        }
        "chat.message" => {
            let from = cmd
                .data
                .get("from")
                .cloned()
                .unwrap_or_else(|| "remote".to_string());
            let text = cmd.data.get("text").cloned().unwrap_or_default();
            log::info!("Rust chat.message from {}: {}", from, text);
            json!({"method": "chat.message", "from": from, "text": text, "status": "ok"})
                .to_string()
                .into_bytes()
        }
        "messages.subscribe" => {
            let keys = cmd
                .data
                .get("keys")
                .cloned()
                .unwrap_or_else(|| "all".to_string());
            log::info!("Rust messages.subscribe keys: {}", keys);
            json!({"method": "messages.subscribed", "keys": keys, "status": "ok"})
                .to_string()
                .into_bytes()
        }
        _ => anyhow::bail!("unknown radio method: {}", cmd.method),
    };

    Ok(response)
}

fn required_data<'a>(cmd: &'a BridgeCommand, key: &str) -> anyhow::Result<&'a str> {
    cmd.data
        .get(key)
        .map(String::as_str)
        .ok_or_else(|| anyhow::anyhow!("missing radio field: {}", key))
}

fn parse_i32(cmd: &BridgeCommand, key: &str, default: i32) -> anyhow::Result<i32> {
    cmd.data
        .get(key)
        .map(|value| value.parse::<i32>())
        .transpose()?
        .map_or(Ok(default), Ok)
}

fn parse_u32(cmd: &BridgeCommand, key: &str, default: u32) -> anyhow::Result<u32> {
    cmd.data
        .get(key)
        .map(|value| value.parse::<u32>())
        .transpose()?
        .map_or(Ok(default), Ok)
}

fn hex_to_bytes(value: &str) -> anyhow::Result<Vec<u8>> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(Vec::new());
    }
    if value.len() % 2 != 0 {
        anyhow::bail!("hex value has odd length");
    }
    let mut out = Vec::with_capacity(value.len() / 2);
    let bytes = value.as_bytes();
    for pair in bytes.chunks_exact(2) {
        let hi = hex_nibble(pair[0])?;
        let lo = hex_nibble(pair[1])?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn bytes_to_hex(value: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(value.len() * 2);
    for byte in value {
        out.push(HEX[usize::from(byte >> 4)] as char);
        out.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    out
}

fn hex_nibble(byte: u8) -> anyhow::Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => anyhow::bail!("invalid hex byte: {}", byte as char),
    }
}

fn parse_bridge_human(line: &str) -> anyhow::Result<BridgeCommand> {
    let parts = split_command_line(line);
    if parts.is_empty() {
        anyhow::bail!("empty command");
    }

    let mut id = None;
    let mut data = BTreeMap::new();
    let mut method = String::new();
    let mut saw_method = false;

    let mut i = 0;
    while i < parts.len() {
        let part = &parts[i];
        if let Some((k, v)) = part.split_once('=') {
            put_human_value(&mut id, &mut data, strip_option_prefix(k), v.to_string());
            i += 1;
            continue;
        }
        if part.starts_with("--") && part.len() > 2 {
            let key = strip_option_prefix(part);
            let mut value = "1".to_string();
            if i + 1 < parts.len() && !parts[i + 1].starts_with("--") && !parts[i + 1].contains('=')
            {
                i += 1;
                value = parts[i].clone();
            }
            put_human_value(&mut id, &mut data, key, value);
            i += 1;
            continue;
        }

        if !saw_method && is_method_name(part) {
            method.clear();
            method.push_str(part);
            saw_method = true;
        } else {
            if method.is_empty() {
                method.push_str(part);
            } else {
                method.push('.');
                method.push_str(part);
            }
            saw_method = true;
        }
        i += 1;
    }

    if method.is_empty() {
        anyhow::bail!("missing command method");
    }
    Ok(BridgeCommand { id, method, data })
}

fn is_method_name(value: &str) -> bool {
    value.contains('.') && !value.contains('/') && !value.contains('=')
}

fn put_human_value(
    id: &mut Option<String>,
    data: &mut BTreeMap<String, String>,
    key: String,
    value: String,
) {
    if key.is_empty() {
        return;
    }
    if key == "id" {
        *id = Some(value);
    } else {
        data.insert(key, value);
    }
}

fn strip_option_prefix(key: &str) -> String {
    key.trim_start_matches('-').to_string()
}

fn split_command_line(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    let mut quote = '\0';
    let mut escaped = false;

    for c in line.chars() {
        if escaped {
            cur.push(c);
            escaped = false;
            continue;
        }
        if c == '\\' {
            escaped = true;
            continue;
        }
        if quoted {
            if c == quote {
                quoted = false;
            } else {
                cur.push(c);
            }
            continue;
        }
        if c == '\'' || c == '"' {
            quoted = true;
            quote = c;
            continue;
        }
        if c.is_whitespace() {
            if !cur.is_empty() {
                out.push(std::mem::take(&mut cur));
            }
            continue;
        }
        cur.push(c);
    }
    if escaped {
        cur.push('\\');
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

struct JniMeshListener {
    jvm: Arc<JavaVM>,
    callback: GlobalRef,
    runtime: tokio::runtime::Handle,
}

impl MeshListener for JniMeshListener {
    fn on_ssh_connection(&self, client_id: u64, user: &str) {
        let jvm = self.jvm.clone();
        let callback = self.callback.clone();
        let user_str = user.to_string();

        std::thread::spawn(move || {
            let mut env = match jvm.attach_current_thread() {
                Ok(e) => e,
                Err(e) => {
                    log::error!("Failed to attach thread: {}", e);
                    return;
                }
            };
            let j_user = match env.new_string(user_str) {
                Ok(value) => value,
                Err(e) => {
                    log::error!("Failed to create Java user string: {}", e);
                    return;
                }
            };
            let _ = env.call_method(
                &callback,
                "onTransportConnection",
                "(JLjava/lang/String;)V",
                &[(client_id as i64).into(), (&j_user).into()],
            );
        });
    }

    fn on_stream(&self, client_id: u64, host: &str, port: u16, stream: DuplexStream) {
        if host == BRIDGE_HOST && port == BRIDGE_PORT {
            let jvm = self.jvm.clone();
            let callback = self.callback.clone();
            self.runtime.spawn(async move {
                handle_bridge_stream(jvm, callback, client_id, stream).await;
            });
            return;
        }

        let jvm = self.jvm.clone();
        let callback = self.callback.clone();
        let host_str = host.to_string();
        let rt = self.runtime.clone();

        std::thread::spawn(move || {
            let mut env = match jvm.attach_current_thread() {
                Ok(e) => e,
                Err(e) => {
                    log::error!("Failed to attach thread: {}", e);
                    return;
                }
            };
            let j_host = match env.new_string(host_str) {
                Ok(value) => value,
                Err(e) => {
                    log::error!("Failed to create Java host string: {}", e);
                    return;
                }
            };

            let stream_handle = MeshStreamHandle {
                stream,
                runtime_handle: rt,
            };

            let h = Box::into_raw(Box::new(stream_handle)) as jlong;

            let _ = env.call_method(
                &callback,
                "onInboundStream",
                "(JLjava/lang/String;IJ)V",
                &[
                    (client_id as i64).into(),
                    (&j_host).into(),
                    (port as i32).into(),
                    h.into(),
                ],
            );
        });
    }

    fn on_session(
        &self,
        client_id: u64,
        _user: &str,
        command: Option<&str>,
        _env: &HashMap<String, String>,
        stream: DuplexStream,
    ) -> bool {
        let jvm = self.jvm.clone();
        let callback = self.callback.clone();
        let command = command.map(|value| value.to_string());
        self.runtime.spawn(async move {
            match command {
                Some(command) => {
                    handle_exec_session(jvm, callback, client_id, command, stream).await
                }
                None => handle_bridge_stream(jvm, callback, client_id, stream).await,
            }
        });
        true
    }
}

async fn handle_exec_session(
    _jvm: Arc<JavaVM>,
    _callback: GlobalRef,
    _client_id: u64,
    _command: String,
    mut stream: DuplexStream,
) {
    let message = b"dmesh-msg:1 accepts length-prefixed message records; SSH exec text is not a message API\n";
    if let Err(e) = stream.write_all(message).await {
        log::warn!("SSH exec response write failed: {}", e);
    }
    let _ = stream.shutdown().await;
}

async fn handle_bridge_stream(
    jvm: Arc<JavaVM>,
    callback: GlobalRef,
    client_id: u64,
    mut stream: DuplexStream,
) {
    let (tx, mut rx) = unbounded_channel::<Vec<u8>>();
    match bridge_senders().lock() {
        Ok(mut senders) => {
            senders.insert(client_id, tx);
        }
        Err(e) => {
            log::error!("SSH message bridge sender map is poisoned: {}", e);
            return;
        }
    }
    let mut pending = Vec::new();
    let mut buf = [0u8; 4096];

    'stream_loop: loop {
        tokio::select! {
            read = stream.read(&mut buf) => {
                let n = match read {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(e) => {
                        log::warn!("SSH message bridge read failed: {}", e);
                        break;
                    }
                };
                pending.extend_from_slice(&buf[..n]);
                loop {
                    let record = match take_bridge_record(&mut pending) {
                        Ok(Some(record)) => record,
                        Ok(None) => break,
                        Err(error) => {
                            log::warn!("SSH message bridge rejected record: {}", error);
                            break 'stream_loop;
                        }
                    };
                    if let Err(error) = dispatch_bridge_message(&jvm, &callback, client_id, &record) {
                        log::warn!("SSH message bridge Java callback failed: {}", error);
                        break 'stream_loop;
                    }
                }
            }
            outbound = rx.recv() => {
                match outbound {
                    Some(record) => {
                        if let Err(e) = write_bridge_record(&mut stream, &record).await {
                            log::warn!("SSH message bridge event write failed: {}", e);
                            break 'stream_loop;
                        }
                    }
                    None => break 'stream_loop,
                }
            }
        }
    }

    if let Ok(mut senders) = bridge_senders().lock() {
        senders.remove(&client_id);
    }
    dispatch_bridge_closed(&jvm, &callback, client_id);
}

fn dispatch_bridge_message(
    jvm: &JavaVM,
    callback: &GlobalRef,
    client_id: u64,
    record: &[u8],
) -> anyhow::Result<()> {
    let mut env = jvm.attach_current_thread()?;
    let bytes = env.byte_array_from_slice(record)?;
    env.call_method(
        callback,
        "onMessage",
        "(J[B)V",
        &[(client_id as i64).into(), (&bytes).into()],
    )?;
    Ok(())
}

fn dispatch_bridge_closed(jvm: &JavaVM, callback: &GlobalRef, client_id: u64) {
    let mut env = match jvm.attach_current_thread() {
        Ok(env) => env,
        Err(error) => {
            log::warn!("SSH message bridge close callback attach failed: {}", error);
            return;
        }
    };
    if let Err(error) = env.call_method(
        callback,
        "onMessageClosed",
        "(J)V",
        &[(client_id as i64).into()],
    ) {
        log::warn!("SSH message bridge close callback failed: {}", error);
    }
}

fn take_bridge_record(pending: &mut Vec<u8>) -> anyhow::Result<Option<Vec<u8>>> {
    if pending.len() < 4 {
        return Ok(None);
    }
    let size = u32::from_be_bytes([pending[0], pending[1], pending[2], pending[3]]) as usize;
    if size == 0 || size > MAX_BRIDGE_MESSAGE_BYTES {
        anyhow::bail!(
            "message size {} is outside 1..={}",
            size,
            MAX_BRIDGE_MESSAGE_BYTES
        );
    }
    if pending.len() < size + 4 {
        return Ok(None);
    }
    let record = pending[4..size + 4].to_vec();
    pending.drain(..size + 4);
    Ok(Some(record))
}

async fn write_bridge_record(stream: &mut DuplexStream, record: &[u8]) -> io::Result<()> {
    if record.is_empty() || record.len() > MAX_BRIDGE_MESSAGE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid bridge message size",
        ));
    }
    stream
        .write_all(&(record.len() as u32).to_be_bytes())
        .await?;
    stream.write_all(record).await
}

struct JniSshClientListener {
    jvm: Arc<JavaVM>,
    callback: GlobalRef,
    runtime: tokio::runtime::Handle,
}

impl SshClientListener for JniSshClientListener {
    fn on_forwarded_tcpip(&self, conn_id: u64, host: &str, port: u16, stream: DuplexStream) {
        let jvm = self.jvm.clone();
        let callback = self.callback.clone();
        let host_str = host.to_string();
        let rt = self.runtime.clone();

        std::thread::spawn(move || {
            let mut env = match jvm.attach_current_thread() {
                Ok(e) => e,
                Err(e) => {
                    log::error!("Failed to attach thread: {}", e);
                    return;
                }
            };
            let j_host = match env.new_string(host_str) {
                Ok(value) => value,
                Err(e) => {
                    log::error!("Failed to create Java host string: {}", e);
                    return;
                }
            };

            let stream_handle = MeshStreamHandle {
                stream,
                runtime_handle: rt,
            };

            let h = Box::into_raw(Box::new(stream_handle)) as jlong;

            let _ = env.call_method(
                &callback,
                "onForwardedStream",
                "(JLjava/lang/String;IJ)V",
                &[
                    (conn_id as i64).into(),
                    (&j_host).into(),
                    (port as i32).into(),
                    h.into(),
                ],
            );
        });
    }
}

struct JavaBearerEgress {
    jvm: Arc<JavaVM>,
    callback: GlobalRef,
    frame: GlobalRef,
    scratch: Mutex<[u8; crate::bearer::BEARER_FRAME_MAX]>,
}

impl crate::bearer::BearerEgress for JavaBearerEgress {
    fn send_packet(&self, bearer: &str, packet: &[u8]) {
        if packet.is_empty() || packet.len() > crate::bearer::COC_PACKET_MAX {
            log::error!("Rejected bearer egress packet of {} bytes", packet.len());
            return;
        }
        let mut env = match self.jvm.attach_current_thread() {
            Ok(value) => value,
            Err(error) => {
                log::error!("Failed to attach bearer egress thread: {}", error);
                return;
            }
        };
        let j_bearer = match env.new_string(bearer) {
            Ok(value) => value,
            Err(error) => {
                log::error!("Failed to create bearer egress string: {}", error);
                return;
            }
        };
        let mut scratch = match self.scratch.lock() {
            Ok(value) => value,
            Err(value) => value.into_inner(),
        };
        let length = if crate::bearer::is_uart_bearer(bearer) {
            crate::bearer::encode_uart_packet(bearer, packet, &mut scratch[..]).unwrap_or(0)
        } else {
            crate::bearer::coc_packet(packet, &mut scratch[..]).unwrap_or(0)
        };
        if length == 0 {
            return;
        }
        let frame = <&JByteArray>::from(self.frame.as_obj());
        if let Err(error) = env.set_byte_array_region(frame, 0, unsafe {
            std::slice::from_raw_parts(scratch.as_ptr() as *const jni::sys::jbyte, length)
        }) {
            log::error!("Failed to stage bearer egress frame: {}", error);
            return;
        }
        if let Err(error) = env.call_method(
            &self.callback,
            "onBearerFrame",
            "(Ljava/lang/String;[BI)V",
            &[(&j_bearer).into(), (&frame).into(), (length as i32).into()],
        ) {
            log::error!("Failed to deliver bearer egress frame: {}", error);
        }
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_github_costinm_dmeshnative_MeshNode_nativeSetCallback(
    env: JNIEnv,
    _class: JClass,
    handle: jlong,
    callback: jni::objects::JObject,
) {
    if handle == 0 {
        log::error!("nativeSetCallback called with null mesh handle");
        return;
    }
    let handle = unsafe { &*(handle as *const MeshHandle) };
    let jvm = match env.get_java_vm() {
        Ok(jvm) => Arc::new(jvm),
        Err(e) => {
            log::error!("Failed to get Java VM: {}", e);
            return;
        }
    };
    let callback_ref = match env.new_global_ref(callback) {
        Ok(callback_ref) => callback_ref,
        Err(e) => {
            log::error!("Failed to create callback global ref: {}", e);
            return;
        }
    };

    #[cfg(target_os = "android")]
    if let Ok(mut message_callback) = android_message_callback().lock() {
        *message_callback = Some((jvm.clone(), callback_ref.clone()));
    }
    let mesh_listener = Arc::new(JniMeshListener {
        jvm: jvm.clone(),
        callback: callback_ref.clone(),
        runtime: handle.runtime.handle().clone(),
    });
    handle.node.add_listener(mesh_listener);

    let frame = match env
        .byte_array_from_slice(&[0u8; crate::bearer::BEARER_FRAME_MAX])
        .and_then(|value| env.new_global_ref(&value))
    {
        Ok(value) => value,
        Err(e) => {
            log::error!("Failed to create bearer egress frame buffer: {}", e);
            return;
        }
    };
    let bearer_egress = Arc::new(JavaBearerEgress {
        jvm: jvm.clone(),
        callback: callback_ref.clone(),
        frame,
        scratch: Mutex::new([0u8; crate::bearer::BEARER_FRAME_MAX]),
    });
    #[cfg(target_os = "android")]
    let udp_socket = handle
        .android_udp_socket
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .take();
    #[cfg(not(target_os = "android"))]
    let udp_socket = None;
    crate::bearer::set_current(Some(crate::bearer::BearerRuntime::spawn_with_udp(
        handle.runtime.handle().clone(),
        bearer_egress,
        udp_socket,
    )));
    // The discovery worker can start before callback registration installs
    // the UDP bearer. Refresh presence now that its actual endpoint exists.
    crate::mesh_common::trigger_announce(handle);

    let client_listener = Arc::new(JniSshClientListener {
        jvm,
        callback: callback_ref,
        runtime: handle.runtime.handle().clone(),
    });
    handle.client_manager.add_listener(client_listener);
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_github_costinm_dmeshnative_MeshNode_nativeSendBridgeMessage(
    env: JNIEnv,
    _class: JClass,
    client_id: jlong,
    message: JByteArray,
) -> jboolean {
    let message = match env.convert_byte_array(&message) {
        Ok(message) if !message.is_empty() && message.len() <= MAX_BRIDGE_MESSAGE_BYTES => message,
        Ok(message) => {
            log::warn!("Rejected bridge message of {} bytes", message.len());
            return JNI_FALSE;
        }
        Err(e) => {
            log::warn!("Failed to read bridge message bytes: {}", e);
            return JNI_FALSE;
        }
    };
    let sender = {
        match bridge_senders().lock() {
            Ok(senders) => senders.get(&(client_id as u64)).cloned(),
            Err(e) => {
                log::error!("SSH message bridge sender map is poisoned: {}", e);
                None
            }
        }
    };
    match sender {
        Some(tx) if tx.send(message).is_ok() => JNI_TRUE,
        _ => JNI_FALSE,
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_github_costinm_dmeshnative_MeshNode_nativeStartMesh(
    mut env: JNIEnv,
    _class: JClass,
    base_dir: JString,
    ssh_port: jint,
    http_port: jint,
    udp_fd: jint,
    discovery_fd: jint,
) -> jlong {
    #[cfg(target_os = "android")]
    init_android_logging();

    let base_dir_str: String = match env.get_string(&base_dir) {
        Ok(s) => s.into(),
        Err(_) => return 0,
    };
    #[cfg(target_os = "android")]
    configure_android_mesh_paths(&base_dir_str);

    match crate::mesh_common::start_mesh(
        &base_dir_str,
        ssh_port,
        http_port,
        (udp_fd >= 0).then_some(udp_fd),
        (discovery_fd >= 0).then_some(discovery_fd),
    ) {
        Ok(handle) => Box::into_raw(Box::new(handle)) as jlong,
        Err(e) => {
            log::error!("Failed to start mesh: {}", e);
            0
        }
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_github_costinm_dmeshnative_MeshNode_nativeStop(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
) {
    if handle != 0 {
        crate::bearer::set_current(None);
        let handle = unsafe { Box::from_raw(handle as *mut MeshHandle) };
        crate::mesh_common::stop_mesh(*handle);
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_github_costinm_dmeshnative_MeshNode_nativeBearerOpen(
    mut env: JNIEnv,
    _class: JClass,
    _handle: jlong,
    bearer: JString,
    args: JString,
) -> jboolean {
    let bearer: String = match env.get_string(&bearer) {
        Ok(value) => value.into(),
        Err(_) => return JNI_FALSE,
    };
    let args: String = match env.get_string(&args) {
        Ok(value) => value.into(),
        Err(_) => return JNI_FALSE,
    };
    if crate::bearer::open(&bearer, &args) {
        JNI_TRUE
    } else {
        JNI_FALSE
    }
}

static BEARER_CHUNK_BUFFER: OnceLock<Mutex<Vec<u8>>> = OnceLock::new();

fn bearer_chunk_buffer(length: usize) -> std::sync::MutexGuard<'static, Vec<u8>> {
    let buffer = BEARER_CHUNK_BUFFER.get_or_init(|| Mutex::new(Vec::new()));
    let mut guard = buffer.lock().unwrap_or_else(|value| value.into_inner());
    guard.resize(length, 0);
    guard
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_github_costinm_dmeshnative_MeshNode_nativeBearerChunk(
    mut env: JNIEnv,
    _class: JClass,
    _handle: jlong,
    bearer: JString,
    chunk: JByteArray,
    length: jint,
) -> jboolean {
    let Ok(value) = env.get_string(&bearer) else {
        return JNI_FALSE;
    };
    let bearer: String = value.into();
    let length = (length.max(0) as usize).min(65535);
    if length == 0 {
        return JNI_TRUE;
    }
    let mut buffer = bearer_chunk_buffer(length);
    if let Err(error) = env.get_byte_array_region(&chunk, 0, unsafe {
        std::slice::from_raw_parts_mut(buffer.as_mut_ptr() as *mut jni::sys::jbyte, length)
    }) {
        log::error!("Failed to read bearer chunk bytes: {}", error);
        return JNI_FALSE;
    }
    if crate::bearer::chunk(&bearer, &buffer[..length]) {
        JNI_TRUE
    } else {
        JNI_FALSE
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_github_costinm_dmeshnative_MeshNode_nativeBearerClose(
    mut env: JNIEnv,
    _class: JClass,
    _handle: jlong,
    bearer: JString,
) {
    let Ok(value) = env.get_string(&bearer) else {
        return;
    };
    let bearer: String = value.into();
    crate::bearer::close(&bearer);
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_github_costinm_dmeshnative_MeshNode_nativeBearerStatus<'a>(
    mut env: JNIEnv<'a>,
    _class: JClass<'a>,
    _handle: jlong,
    bearer: JString<'a>,
) -> JString<'a> {
    let Ok(value) = env.get_string(&bearer) else {
        return env
            .new_string("")
            .unwrap_or_else(|_| JString::from(JObject::null()));
    };
    let bearer: String = value.into();
    let status = crate::bearer::status(&bearer).to_string();
    env.new_string(status)
        .unwrap_or_else(|_| JString::from(JObject::null()))
}

/// Notify the Rust-owned announce worker that Android has gained a new local
/// link. The Java P2P adapter supplies no address or payload; it only signals
/// a platform lifecycle transition.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_github_costinm_dmeshnative_MeshNode_nativeTriggerAnnounce(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
) -> jboolean {
    if handle == 0 {
        return JNI_FALSE;
    }
    let handle = unsafe { &*(handle as *const MeshHandle) };
    if crate::mesh_common::trigger_announce(handle) {
        JNI_TRUE
    } else {
        JNI_FALSE
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_github_costinm_dmeshnative_MeshNode_nativeConnect(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
    host: JString,
    port: jint,
    user: JString,
    server_key: JString,
) -> jlong {
    if handle == 0 {
        log::error!("nativeConnect called with null mesh handle");
        return -1;
    }
    let handle = unsafe { &*(handle as *const MeshHandle) };
    let host_str: String = match env.get_string(&host) {
        Ok(value) => value.into(),
        Err(e) => {
            log::error!("Failed to read connect host: {}", e);
            return -1;
        }
    };
    let user_str: String = match env.get_string(&user) {
        Ok(value) => value.into(),
        Err(e) => {
            log::error!("Failed to read connect user: {}", e);
            return -1;
        }
    };
    let key_str: String = match env.get_string(&server_key) {
        Ok(value) => value.into(),
        Err(e) => {
            log::error!("Failed to read connect server key: {}", e);
            return -1;
        }
    };

    match crate::mesh_common::mesh_connect(handle, &host_str, port as u16, &user_str, &key_str) {
        Ok(id) => id as jlong,
        Err(e) => {
            log::error!("Connect failed: {}", e);
            -1
        }
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_github_costinm_dmeshnative_MeshNode_nativeExec<'a>(
    mut env: JNIEnv<'a>,
    _class: JClass<'a>,
    handle: jlong,
    conn_id: jlong,
    command: JString<'a>,
) -> JString<'a> {
    if handle == 0 {
        log::error!("nativeExec called with null mesh handle");
        return env
            .new_string("")
            .unwrap_or_else(|_| JString::from(JObject::null()));
    }
    let handle = unsafe { &*(handle as *const MeshHandle) };
    let cmd_str: String = match env.get_string(&command) {
        Ok(value) => value.into(),
        Err(e) => {
            log::error!("Failed to read exec command: {}", e);
            return env
                .new_string("")
                .unwrap_or_else(|_| JString::from(JObject::null()));
        }
    };

    match crate::mesh_common::mesh_exec(handle, conn_id as u64, &cmd_str) {
        Ok(stdout) => env.new_string(stdout).unwrap_or_else(|e| {
            log::error!("Failed to create exec result string: {}", e);
            JString::from(JObject::null())
        }),
        Err(e) => {
            log::error!("Exec failed: {}", e);
            env.new_string("")
                .unwrap_or_else(|_| JString::from(JObject::null()))
        }
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_github_costinm_dmeshnative_MeshNode_nativeGetPublicKey<'a>(
    env: JNIEnv<'a>,
    _class: JClass<'a>,
    handle: jlong,
) -> JString<'a> {
    if handle == 0 {
        log::error!("nativeGetPublicKey called with null mesh handle");
        return env
            .new_string("")
            .unwrap_or_else(|_| JString::from(JObject::null()));
    }
    let handle = unsafe { &*(handle as *const MeshHandle) };
    let pk_str = crate::mesh_common::mesh_get_public_key(handle);
    env.new_string(pk_str).unwrap_or_else(|e| {
        log::error!("Failed to create public key string: {}", e);
        JString::from(JObject::null())
    })
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_github_costinm_dmeshnative_MeshNode_nativeOpenStream(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
    conn_id: jlong,
    host: JString,
    port: jint,
) -> jlong {
    if handle == 0 {
        log::error!("nativeOpenStream called with null mesh handle");
        return 0;
    }
    let handle = unsafe { &*(handle as *const MeshHandle) };
    let host_str: String = match env.get_string(&host) {
        Ok(value) => value.into(),
        Err(e) => {
            log::error!("Failed to read stream host: {}", e);
            return 0;
        }
    };

    match crate::mesh_common::mesh_open_stream(handle, conn_id as u64, &host_str, port as u16) {
        Ok(stream_handle) => Box::into_raw(Box::new(stream_handle)) as jlong,
        Err(e) => {
            log::error!("Open stream failed: {}", e);
            0
        }
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_github_costinm_dmeshnative_MeshNode_nativeAddLocalForward(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
    conn_id: jlong,
    local_port: jint,
    remote_host: JString,
    remote_port: jint,
) {
    if handle == 0 {
        log::error!("nativeAddLocalForward called with null mesh handle");
        return;
    }
    let handle = unsafe { &*(handle as *const MeshHandle) };
    let host_str: String = match env.get_string(&remote_host) {
        Ok(value) => value.into(),
        Err(e) => {
            log::error!("Failed to read local forward host: {}", e);
            return;
        }
    };

    let _ = crate::mesh_common::mesh_add_local_forward(
        handle,
        conn_id as u64,
        local_port as u16,
        &host_str,
        remote_port as u16,
    );
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_github_costinm_dmeshnative_MeshNode_nativeAddRemoteForward(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
    conn_id: jlong,
    remote_port: jint,
    local_host: JString,
    local_port: jint,
) -> jint {
    if handle == 0 {
        log::error!("nativeAddRemoteForward called with null mesh handle");
        return -1;
    }
    let handle = unsafe { &*(handle as *const MeshHandle) };
    let host_str: String = match env.get_string(&local_host) {
        Ok(value) => value.into(),
        Err(e) => {
            log::error!("Failed to read remote forward host: {}", e);
            return -1;
        }
    };

    match crate::mesh_common::mesh_add_remote_forward(
        handle,
        conn_id as u64,
        remote_port as u16,
        &host_str,
        local_port as u16,
    ) {
        Ok(port) => port as jint,
        Err(e) => {
            log::error!("Remote forward failed: {}", e);
            -1
        }
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_github_costinm_dmeshnative_MeshNode_nativeRadioMessage<'a>(
    mut env: JNIEnv<'a>,
    _class: JClass<'a>,
    method: JString<'a>,
    args: JString<'a>,
    data: JByteArray<'a>,
    fd: jint,
) -> JByteArray<'a> {
    let method: String = env
        .get_string(&method)
        .map(|v| v.into())
        .unwrap_or_default();
    let args: String = env.get_string(&args).map(|v| v.into()).unwrap_or_default();
    let data = env.convert_byte_array(&data).unwrap_or_default();
    let bytes = radio_message(&method, &args, &data, fd).unwrap_or_else(|error| {
        log::error!("nativeRadioMessage failed: {}", error);
        Vec::new()
    });
    env.byte_array_from_slice(&bytes)
        .unwrap_or_else(|_| JByteArray::from(JObject::null()))
}

/// Text-only companion to `nativeRadioMessage`.
///
/// Binary radio builders intentionally receive an empty byte array on failure:
/// returning an error string there could be transmitted as malformed service
/// data.  Control and probe callers instead need a structured error so their
/// persisted result distinguishes a failed handler from an empty success.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_github_costinm_dmeshnative_MeshNode_nativeRadioMessageText<'a>(
    mut env: JNIEnv<'a>,
    _class: JClass<'a>,
    method: JString<'a>,
    args: JString<'a>,
    data: JByteArray<'a>,
    fd: jint,
) -> JString<'a> {
    let method: String = env
        .get_string(&method)
        .map(|value| value.into())
        .unwrap_or_default();
    let args: String = env
        .get_string(&args)
        .map(|value| value.into())
        .unwrap_or_default();
    let data = env.convert_byte_array(&data).unwrap_or_default();
    let text = match radio_message(&method, &args, &data, fd) {
        Ok(bytes) => String::from_utf8(bytes).unwrap_or_else(|error| {
            serde_json::json!({
                "ok": false,
                "error": "radio_text_non_utf8",
                "detail": error.to_string(),
            })
            .to_string()
        }),
        Err(error) => {
            log::error!("nativeRadioMessageText failed: {}", error);
            serde_json::json!({"ok": false, "error": error.to_string()}).to_string()
        }
    };
    env.new_string(text).unwrap_or_else(|_| JString::default())
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_github_costinm_dmeshnative_MeshStream_nativeStreamRead(
    env: JNIEnv,
    _class: JClass,
    handle: jlong,
    buf: JByteArray,
) -> jint {
    if handle == 0 {
        log::error!("nativeStreamRead called with null stream handle");
        return -1;
    }
    let handle = unsafe { &mut *(handle as *mut MeshStreamHandle) };
    let len = match env.get_array_length(&buf) {
        Ok(len) if len >= 0 => len as usize,
        Ok(len) => {
            log::error!("nativeStreamRead got negative buffer length: {}", len);
            return -1;
        }
        Err(e) => {
            log::error!("Failed to read stream buffer length: {}", e);
            return -1;
        }
    };
    let mut data = vec![0u8; len];

    match crate::mesh_common::stream_read(handle, &mut data) {
        Ok(n) => {
            let byte_data: Vec<i8> = data[..n].iter().map(|&b| b as i8).collect();
            match env.set_byte_array_region(&buf, 0, &byte_data) {
                Ok(()) => n as jint,
                Err(e) => {
                    log::error!("Failed to write stream bytes to Java buffer: {}", e);
                    -1
                }
            }
        }
        Err(e) => {
            log::error!("Stream read failed: {}", e);
            -1
        }
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_github_costinm_dmeshnative_MeshStream_nativeStreamWrite(
    env: JNIEnv,
    _class: JClass,
    handle: jlong,
    data: JByteArray,
) {
    if handle == 0 {
        log::error!("nativeStreamWrite called with null stream handle");
        return;
    }
    let handle = unsafe { &mut *(handle as *mut MeshStreamHandle) };
    let bytes = match env.convert_byte_array(&data) {
        Ok(bytes) => bytes,
        Err(e) => {
            log::error!("Failed to read Java stream bytes: {}", e);
            return;
        }
    };

    if let Err(e) = crate::mesh_common::stream_write(handle, &bytes) {
        log::error!("Stream write failed: {}", e);
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_github_costinm_dmeshnative_MeshStream_nativeStreamClose(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
) {
    if handle != 0 {
        let _ = unsafe { Box::from_raw(handle as *mut MeshStreamHandle) };
        // Dropping closes the stream
    }
}

#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_github_costinm_dmeshnative_MeshNode_nativeTestTunFd(
    env: JNIEnv,
    class: JClass,
    fd: jint,
) -> jlong {
    Java_com_github_costinm_dmeshnative_MeshNode_nativeStartTunFd(env, class, fd)
}

#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_github_costinm_dmeshnative_MeshNode_nativeStartTunFd(
    mut _env: JNIEnv,
    _class: JClass,
    fd: jint,
) -> jlong {
    init_android_logging();
    catch_jni_jlong("nativeStartTunFd", || {
        log::info!("nativeStartTunFd called with fd: {}", fd);
        if fd < 0 {
            anyhow::bail!("invalid Android TUN fd: {fd}");
        }
        if unsafe { libc::fcntl(fd, libc::F_GETFD) } < 0 {
            return Err(std::io::Error::last_os_error())
                .map_err(|error| anyhow::anyhow!("invalid Android TUN fd {fd}: {error}"));
        }

        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 {
            return Err(std::io::Error::last_os_error())
                .map_err(|error| anyhow::anyhow!("failed to inspect Android TUN fd: {error}"));
        }
        log::info!(
            "Android TUN fd {} accepted, fd flags=0x{:x}; starting mesh-tun",
            fd,
            flags
        );

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("dmesh-vpn")
            .enable_all()
            .build()?;
        let tun = unsafe { mesh_tun::MeshTun::from_fd(fd) }?;
        let passthrough = Arc::new(mesh_tun::flow::MeshPassthrough::new("android-vpn"));
        let passthrough_udp = passthrough.clone();
        let passthrough_dns = passthrough.clone();
        let injector = runtime.block_on(async move {
            let injector = tun
                .run_with_policy(
                    Arc::new(mesh_tun::policy::AllowAllPolicy),
                    passthrough_udp,
                    passthrough_dns,
                )
                .await?;
            passthrough.set_injector(injector.clone());
            anyhow::Ok(injector)
        })?;
        let vpn_handle = AndroidVpnHandle {
            _runtime: runtime,
            _injector: injector,
        };
        let handle_id = ANDROID_VPN_NEXT_HANDLE.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        android_vpn_handles()
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .insert(handle_id, vpn_handle);
        log::info!("Android VPN mesh-tun started handle={}", handle_id);
        Ok(handle_id)
    })
}

#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_github_costinm_dmeshnative_MeshNode_nativeStopTunFd(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
) {
    init_android_logging();
    if handle == 0 {
        return;
    }
    log::info!("Stopping Android VPN mesh-tun handle={}", handle);
    let _ = android_vpn_handles()
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
        .remove(&handle);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shared engine, installed once per test process.
    fn test_engine() -> Arc<dmesh_discovery::Engine> {
        install_discovery_engine("test-android-key")
    }

    /// An empty device inventory, with the engine running.
    fn reset_discovery() {
        test_engine().clear_devices();
    }

    // The JNI adapter deliberately owns process-wide bounded radio caches.
    // Tests which clear/inject those caches must not run concurrently.
    static RADIO_STATE_TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn bridge_record_accepts_fragmented_bounded_messages() {
        let mut pending = vec![0, 0, 0, 3, 1];
        assert!(take_bridge_record(&mut pending).unwrap().is_none());
        pending.extend_from_slice(&[2, 3, 0, 0, 0, 1, 4]);
        assert_eq!(
            take_bridge_record(&mut pending).unwrap(),
            Some(vec![1, 2, 3])
        );
        assert_eq!(take_bridge_record(&mut pending).unwrap(), Some(vec![4]));
        assert!(pending.is_empty());
    }

    #[test]
    fn bridge_record_rejects_empty_and_oversized_messages() {
        let mut empty = vec![0, 0, 0, 0];
        assert!(take_bridge_record(&mut empty).is_err());
        let mut oversized = ((MAX_BRIDGE_MESSAGE_BYTES + 1) as u32)
            .to_be_bytes()
            .to_vec();
        assert!(take_bridge_record(&mut oversized).is_err());
    }

    #[test]
    fn local_network_snapshot_is_bounded_and_rust_owned() {
        local_networks().lock().unwrap().networks.clear();
        let mut snapshot = [0u8; 512];
        let mut cbor = dmesh_server::cbor::Encoder::new(&mut snapshot);
        cbor.map(1).unwrap();
        cbor.text_value(b"networks").unwrap();
        cbor.array(1).unwrap();
        cbor.map(11).unwrap();
        cbor.text_value(b"interface").unwrap();
        cbor.text_value(b"wlan0").unwrap();
        for key in [
            b"up".as_slice(),
            b"multicast",
            b"active",
            b"internet",
            b"validated",
        ] {
            cbor.text_value(key).unwrap();
            cbor.boolean(true).unwrap();
        }
        cbor.text_value(b"metered").unwrap();
        cbor.boolean(false).unwrap();
        for (key, values) in [
            (
                b"addresses".as_slice(),
                &[b"192.0.2.10".as_slice(), b"fe80::10%wlan0".as_slice()][..],
            ),
            (b"dns_servers".as_slice(), &[b"192.0.2.53".as_slice()][..]),
            (b"gateways".as_slice(), &[b"192.0.2.1".as_slice()][..]),
            (b"transports".as_slice(), &[b"wifi".as_slice()][..]),
        ] {
            cbor.text_value(key).unwrap();
            cbor.array(values.len() as u64).unwrap();
            for value in values {
                cbor.text_value(value).unwrap();
            }
        }
        let length = cbor.len();
        let update =
            radio_message("radio.local_networks.update", "", &snapshot[..length], -1).unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&update).unwrap()["interfaces"],
            1
        );
        let table = radio_message("discovery.status", "", &[], -1).unwrap();
        let table: Value = serde_json::from_slice(&table).unwrap();
        assert_eq!(table["networks"][0]["interface"], "wlan0");
        assert_eq!(table["networks"][0]["validated"], true);
        let status =
            String::from_utf8(radio_message("radio.status_text", "", &[], -1).unwrap()).unwrap();
        assert!(status.starts_with("DMesh"));
        assert!(status.contains("net 1(inet)"));
        assert!(status.contains("wlan0 wifi inet,val"));
    }

    #[test]
    fn status_text_orders_companions_marks_sleep_and_short_ids() {
        let _guard = RADIO_STATE_TEST_LOCK.lock().unwrap();
        reset_discovery();
        ble_scan_results_store().lock().unwrap().clear();

        let companion_vip6 = {
            let mut id = [0_u8; 16];
            id[..8].copy_from_slice(b"paired01");
            let announce = dmesh_server::announce::Announce::discovery(id, 8, 12);
            dmesh_server::announce::virtual_ip6_from_identity_hint(announce.device_id())
                .map(std::net::Ipv6Addr::from)
                .map(|address| address.to_string())
                .unwrap()
        };
        let paired_dir = tempfile::tempdir().unwrap();
        let owned = dmesh_server::device_record::DeviceRecord {
            device_id: "paired-id".to_owned(),
            name: Some("kitchen".to_owned()),
            mac: None,
            public_key: vec![2; 33],
            root_public_key: vec![3; 33],
            vip6: Some(companion_vip6.clone()),
            endpoints: BTreeMap::new(),
            secret: vec![7; 16],
            ..Default::default()
        };
        dmesh_server::device_record::DeviceStore::new(paired_dir.path())
            .save_paired(&owned)
            .unwrap();
        let _ = ANDROID_DEVICE_RECORDS_PATH.set(paired_dir.path().to_path_buf());

        // Companion over Aware with a recent RSSI.
        let mut id = [0_u8; 16];
        id[..8].copy_from_slice(b"paired01");
        let mut companion = dmesh_server::announce::Announce::discovery(id, 8, 12);
        assert!(companion.set_device_name("tmp"));
        let mut companion_carrier = dmesh_discovery::Carrier::radio(
            "nan",
            "aa:bb:cc:dd:ee:01",
            dmesh_server::discovery::DiscoveryPacketKind::ActivePublish,
        );
        companion_carrier.rssi_dbm = Some(-70);
        test_engine().observe_announce(&companion_carrier, companion, b"p");

        // Sleepy unnamed device seen by UDP multicast.
        let mut sleepy_id = [0_u8; 16];
        sleepy_id[..8].copy_from_slice(b"sleepy01");
        let mut sleepy = dmesh_server::announce::Announce::discovery(sleepy_id, 8, 60);
        sleepy.kind = dmesh_server::announce::ANNOUNCE_SLEEP_PENDING;
        observe_announce(
            sleepy,
            "[fe80::2]:5227".to_owned(),
            "udp_multicast",
            b"sleepy",
        );

        // Provisional BLE rendezvous row with no matching identity.
        record_ble_scan_result(
            "scan_result:rssi=-70:addr=01:02:03:04:05:06:mode=unpaired",
            &[0x20, 0x00, 1, 2, 3, 4],
        );
        assert_eq!(
            ble_scan_results_store().lock().unwrap()["01:02:03:04:05:06"]["mode"],
            "unpaired"
        );

        let text = status_text();
        let companion_line = text
            .lines()
            .find(|line| line.contains("kitchen"))
            .expect("companion row must be present");
        let sleepy_line = text
            .lines()
            .find(|line| line.starts_with("z "))
            .expect("sleepy row must carry the sleep marker");
        let ble_line = text
            .lines()
            .find(|line| line.contains("03040506"))
            .expect("BLE row must show the last four address bytes");

        assert!(companion_line.starts_with("P "));
        assert!(companion_line.contains("65643031"));
        assert!(companion_line.contains('A'));
        assert!(companion_line.contains("-70"));
        assert!(sleepy_line.contains("70793031"));
        assert!(sleepy_line.contains('W'));
        assert!(ble_line.contains('B'));
        // Companions are listed before all other devices.
        let companion_index = text.find(companion_line).unwrap();
        let sleepy_index = text.find(sleepy_line).unwrap();
        let ble_index = text.find(ble_line).unwrap();
        assert!(companion_index < sleepy_index && companion_index < ble_index);
        // Paired but never-discovered companions still surface.
        let unseen = dmesh_server::device_record::DeviceRecord {
            device_id: "lost".to_owned(),
            name: Some("lost-pair".to_owned()),
            mac: None,
            public_key: vec![2; 33],
            root_public_key: vec![3; 33],
            vip6: Some("fc00::5".to_owned()),
            endpoints: BTreeMap::new(),
            secret: vec![7; 16],
            ..Default::default()
        };
        dmesh_server::device_record::DeviceStore::new(paired_dir.path())
            .put(&dmesh_server::device_record::DeviceRecord {
                trust: Some(dmesh_server::device_record::trust::PAIRED.to_owned()),
                ..unseen
            })
            .unwrap();
        let text = status_text();
        assert!(
            text.lines().any(|line| line.contains("lost-pair")),
            "paired-but-absent companions must be listed: {text}"
        );
    }

    #[test]
    fn power_telemetry_is_validated_and_retained_in_rust() {
        // Power state is process-global; tests that reset it must serialize.
        let _guard = RADIO_STATE_TEST_LOCK.lock().unwrap();
        *power_state().lock().unwrap() = dmesh_server::power::PowerState::default();
        radio_message(
            "radio.power.status",
            "",
            br#"{"source":"android","event":"battery","battery_percent":67,"power_save":true,"idle":false,"idle_ms":0,"total_idle_ms":2,"charging_ms":3,"status":2,"plugged":1}"#,
            -1,
        )
        .unwrap();
        let state: Value =
            serde_json::from_slice(&radio_message("radio.power.state", "", &[], -1).unwrap())
                .unwrap();
        assert_eq!(state["battery_percent"], 67);
        assert_eq!(state["power_save"], true);
        assert!(radio_message("radio.power.status", "", br#"{"unexpected":1}"#, -1).is_err());
    }

    #[test]
    fn private_battery_cbor_update_reaches_shared_telemetry() {
        use dmesh_server::cbor::Encoder;

        // Power state is process-global; tests that reset it must serialize.
        let _guard = RADIO_STATE_TEST_LOCK.lock().unwrap();
        *power_state().lock().unwrap() = dmesh_server::power::PowerState::default();
        let mut record = [0u8; 128];
        let mut encoder = Encoder::new(&mut record);
        encoder.map(3).unwrap();
        encoder.text_value(b"battery_percent").unwrap();
        encoder.uint(83).unwrap();
        encoder.text_value(b"charging").unwrap();
        encoder.boolean(true).unwrap();
        encoder.text_value(b"idle_ms").unwrap();
        encoder.uint(700).unwrap();
        let used = encoder.len();

        radio_message("battery.state.update", "", &record[..used], -1).unwrap();
        let status: Value =
            serde_json::from_slice(&radio_message("telemetry.battery", "", &[], -1).unwrap())
                .unwrap();
        assert_eq!(status["battery_percent"], 83);
        assert_eq!(status["charging"], true);
        assert_eq!(status["idle_ms"], 700);
        assert!(radio_message("battery.state.update", "", b"{}", -1).is_err());
    }

    #[test]
    fn shared_nan_telemetry_reaches_android_observation() {
        let mut request = [0u8; 32];
        let used = dmesh_server::telemetry::encode_request(
            dmesh_server::telemetry::NAN_STATUS_METHOD,
            17,
            &mut request,
        )
        .unwrap();
        let response = android_telemetry_response(&request[..used]).unwrap();
        let record = dmesh_server::tagged::decode(&response).unwrap();
        assert_eq!(record.id, Some(17));
        let mut result = dmesh_server::cbor::Decoder::new(record.result.unwrap());
        assert_eq!(result.head(), Some((5, 2)));
        assert_eq!(result.uint(), Some(1));
        assert!(result.boolean().is_some());
        assert_eq!(result.uint(), Some(4));
        assert!(result.boolean().is_some());
    }

    #[test]
    fn radio_message_builds_and_parses_nan_followup() {
        let built = radio_message(
            "radio.nan.build_followup",
            "msg_type=command_text device_id=010101010101 target_id=020202020202",
            b"ble stats=true",
            -1,
        )
        .unwrap();
        assert_eq!(&built[0..3], b"DM\x01");

        let parsed = radio_message("radio.nan.parse_followup", "", &built, -1).unwrap();
        let parsed = String::from_utf8(parsed).unwrap();
        assert!(parsed.contains(r#""msg_type":"command_text""#));
        assert!(parsed.contains(r#""payload_text":"ble stats=true""#));
    }

    #[test]
    fn android_nan_followup_receipts_are_bounded_rust_state() {
        let _guard = RADIO_STATE_TEST_LOCK.lock().unwrap();
        nan_followups().lock().unwrap().clear();
        nan_events().lock().unwrap().clear();
        radio_message("radio.nan.event", "event=attached peer=framework", &[], -1).unwrap();
        let followup = radio_message(
            "radio.nan.build_followup",
            "msg_type=command_cbor device_id=010101010101 target_id=020202020202",
            &[0xa1, 1, 1],
            -1,
        )
        .unwrap();
        let mut android_sdea_message = vec![0x50, 0x6f, 0x9a, 0x02];
        android_sdea_message.extend_from_slice(&followup);
        radio_message(
            "radio.nan.inject_frame",
            "rssi=-55",
            &android_sdea_message,
            -1,
        )
        .unwrap();
        let receipts = radio_message("radio.nan.followups", "", &[], -1).unwrap();
        let receipts: Value = serde_json::from_slice(&receipts).unwrap();
        assert_eq!(receipts["followups"].as_array().unwrap().len(), 1);
        assert_eq!(receipts["followups"][0]["msg_type"], "command_cbor");
        let events = radio_message("radio.nan.events", "", &[], -1).unwrap();
        let events: Value = serde_json::from_slice(&events).unwrap();
        assert_eq!(events["events"].as_array().unwrap().len(), 1);
        assert_eq!(events["events"][0]["event"], "attached");
    }

    #[test]
    fn android_nan_status_follows_framework_lifecycle_order() {
        let _guard = RADIO_STATE_TEST_LOCK.lock().unwrap();
        nan_events().lock().unwrap().clear();
        radio_message(
            "radio.nan.event",
            "event=aware.on_attached peer=framework",
            &[],
            -1,
        )
        .unwrap();
        radio_message(
            "radio.nan.event",
            "event=aware.on_publish_started peer=framework",
            &[],
            -1,
        )
        .unwrap();
        radio_message(
            "radio.nan.event",
            "event=aware.on_subscribe_started peer=framework",
            &[],
            -1,
        )
        .unwrap();
        let status = radio_message("telemetry.nan_status", "", &[], -1).unwrap();
        let status: Value = serde_json::from_slice(&status).unwrap();
        assert_eq!(status["active"], true);
        assert_eq!(status["publish_active"], true);
        assert_eq!(status["subscribe_active"], true);
        assert_eq!(status["last_event"], "aware.on_subscribe_started");

        radio_message(
            "radio.nan.event",
            "event=aware.on_session_terminated peer=framework",
            &[],
            -1,
        )
        .unwrap();
        let status = radio_message("telemetry.nan_status", "", &[], -1).unwrap();
        let status: Value = serde_json::from_slice(&status).unwrap();
        assert_eq!(status["active"], false);
        assert_eq!(status["publish_active"], false);
        assert_eq!(status["subscribe_active"], false);
    }

    #[test]
    fn android_nan_status_survives_routine_discovery_history_pressure() {
        let _guard = RADIO_STATE_TEST_LOCK.lock().unwrap();
        nan_events().lock().unwrap().clear();
        for event in [
            "aware.on_attached",
            "aware.on_publish_started",
            "aware.on_subscribe_started",
        ] {
            radio_message(
                "radio.nan.event",
                &format!("event={event} peer=framework"),
                &[],
                -1,
            )
            .unwrap();
        }
        for _ in 0..(64 * 2) {
            radio_message(
                "radio.nan.event",
                "event=aware.on_service_discovered peer=peer",
                &[],
                -1,
            )
            .unwrap();
        }

        let status = radio_message("telemetry.nan_status", "", &[], -1).unwrap();
        let status: Value = serde_json::from_slice(&status).unwrap();
        assert_eq!(status["active"], true);
        assert_eq!(status["publish_active"], true);
        assert_eq!(status["subscribe_active"], true);
    }

    #[test]
    fn android_nan_followup_promotes_embedded_announce_identity() {
        let _guard = RADIO_STATE_TEST_LOCK.lock().unwrap();
        reset_discovery();
        nan_followups().lock().unwrap().clear();
        let mut id = [0_u8; 16];
        id.copy_from_slice(b"host-followup-id");
        let announce = dmesh_server::announce::Announce::discovery(id, 16, 9);
        let mut announce_wire = [0_u8; 96];
        let announce_len = dmesh_server::announce::encode(announce, &mut announce_wire).unwrap();
        let followup = radio_message(
            "radio.nan.build_followup",
            "msg_type=command_cbor device_id=7219f817de65 target_id=020102030405",
            &announce_wire[..announce_len],
            -1,
        )
        .unwrap();
        let mut android_sdea_message = vec![0x50, 0x6f, 0x9a, 0x02];
        android_sdea_message.extend_from_slice(&followup);
        radio_message(
            "radio.nan.inject_frame",
            "peer=android-peer rssi=-55",
            &android_sdea_message,
            -1,
        )
        .unwrap();
        let devices = radio_message("discovery.nodes", "", &[], -1).unwrap();
        let devices: Value = serde_json::from_slice(&devices).unwrap();
        let host = devices["devices"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["observations"]["nan"]["last_kind"] == "followup")
            .expect("embedded announce must replace the P2P group-MAC placeholder");
        assert_eq!(host["observations"]["nan"]["last_kind"], "followup");
        assert_eq!(host["observations"]["nan"]["followup_rx"], 1);
        assert!(
            devices["devices"]
                .as_array()
                .unwrap()
                .iter()
                .all(|entry| entry.get("id").is_none())
        );
    }

    #[test]
    fn android_device_inventory_unifies_udp_and_nan_discovery() {
        let _guard = RADIO_STATE_TEST_LOCK.lock().unwrap();
        reset_discovery();
        let mut id = [0_u8; 16];
        id[..6].copy_from_slice(b"udp-a1");
        observe_announce(
            dmesh_server::announce::Announce::discovery(id, 6, 12),
            "[fe80::1]:5227".to_string(),
            "udp_multicast",
            b"udp-announce",
        );
        let service_info = radio_message(
            "radio.nan.build_announce",
            "kind=discovery device_id=6e616e2d6232 uptime_secs=13",
            &[],
            -1,
        )
        .unwrap();
        radio_message(
            "radio.nan.observe_service_info",
            "peer=aware:7",
            &service_info,
            -1,
        )
        .unwrap();
        let devices = radio_message("discovery.nodes", "", &[], -1).unwrap();
        let devices: Value = serde_json::from_slice(&devices).unwrap();
        let entries = devices["devices"].as_array().unwrap();
        assert_eq!(entries.len(), 2);
        assert!(entries.iter().all(|entry| entry.get("id").is_none()));
        let udp = entries
            .iter()
            .find(|device| device["observations"].get("udp_multicast").is_some())
            .unwrap();
        let nan = entries
            .iter()
            .find(|device| device["observations"].get("nan").is_some())
            .unwrap();
        assert_eq!(udp["observations"]["udp_multicast"]["last_kind"], "other");
        assert_eq!(nan["observations"]["nan"]["last_kind"], "active_publish");
        assert_eq!(
            nan["observations"]["nan"]["last_payload_len"],
            service_info.len()
        );
        assert_ne!(
            nan["observations"]["nan"]["last_payload_hash"],
            0x811c_9dc5u32
        );
        assert_eq!(nan["observations"]["nan"]["unavailable_fields"], 14);
    }

    #[test]
    fn android_nan_announce_retains_sta_network_name() {
        let _guard = RADIO_STATE_TEST_LOCK.lock().unwrap();
        struct NoEgress;
        impl crate::bearer::BearerEgress for NoEgress {
            fn send_packet(&self, _: &str, _: &[u8]) {}
        }
        let socket = std::net::UdpSocket::bind("[::1]:0").unwrap();
        let listener = socket.local_addr().unwrap();
        let runtime = tokio::runtime::Runtime::new().unwrap();
        crate::bearer::set_current(Some(crate::bearer::BearerRuntime::spawn_with_udp(
            runtime.handle().clone(), Arc::new(NoEgress), Some(socket),
        )));
        let wire = radio_message(
            "radio.nan.build_announce",
            "kind=discovery device_id=616e64726f69642d31 uptime_secs=13 device_name=Pixel network_name=costin sta_link_local_v6=fe80::1234",
            &[],
            -1,
        )
        .unwrap();
        let announce = dmesh_server::announce::decode_announce(&wire)
            .expect("Android presence must decode as a common announce");
        assert_eq!(announce.device_name(), Some("Pixel"));
        assert_eq!(announce.network_name(), Some("costin"));
        assert_eq!(
            announce.sta_link_local_v6(),
            Some("fe80::1234".parse::<Ipv6Addr>().unwrap().octets())
        );
        assert_eq!(
            announce.udp_link_local_v6(),
            Some("fe80::1234".parse::<Ipv6Addr>().unwrap().octets())
        );
        assert_eq!(announce.udp_port, listener.port());
        crate::bearer::set_current(None);
        let mut without_listener = dmesh_server::announce::Announce::discovery([0; 16], 8, 0);
        set_android_udp_endpoint(&mut without_listener, "fe80::1234".parse().unwrap());
        assert_eq!(without_listener.udp_link_local_v6(), None);
        assert_eq!(without_listener.udp_port, 0);
    }

    #[test]
    fn android_transport_projection_accepts_numeric_p2p_flags() {
        let projection = android_transport_set_projection(&json!({
            "mode": "nan",
            "ap": 1,
        }))
        .unwrap();
        assert_eq!(projection["operation"], "p2p_go");
    }

    #[test]
    fn android_nan_sta_activation_is_a_targeted_common_transport_set() {
        let wire = radio_message(
            "radio.nan.build_sta_activation",
            "source_id=010203040506 wake_target=d8a01d4c5e1c",
            &[],
            -1,
        )
        .unwrap();
        assert!(matches!(
            dmesh_rawnan::parse_dmesh_nan_followup(&wire)
                .and_then(|followup| dmesh_server::control::decode_request(followup.payload)),
            Some(dmesh_server::control::Request::TransportSet {
                kind: dmesh_server::control::TransportKind::Sta,
                config: dmesh_server::control::TransportConfig {
                    wake_target: Some([0xd8, 0xa0, 0x1d, 0x4c, 0x5e, 0x1c]),
                    ..
                },
            })
        ));
    }

    #[test]
    fn android_nan_activation_is_a_parameterized_targeted_transport_set() {
        let wire = radio_message(
            "radio.nan.build_activation",
            "source_id=010203040506 wake_target=d8a01d4c5e1c kind=6 ap=1 now=1 ble=1 nan_dw_interval=1",
            &[],
            -1,
        )
        .unwrap();
        assert!(matches!(
            dmesh_rawnan::parse_dmesh_nan_followup(&wire)
                .and_then(|followup| dmesh_server::control::decode_request(followup.payload)),
            Some(dmesh_server::control::Request::TransportSet {
                kind: dmesh_server::control::TransportKind::Nan,
                config: dmesh_server::control::TransportConfig {
                    wake_target: Some([0xd8, 0xa0, 0x1d, 0x4c, 0x5e, 0x1c]),
                    nan_dw_interval: Some(1),
                    now: Some(1),
                    ap: Some(1),
                    ble: Some(1),
                    ..
                },
            })
        ));
    }

    #[test]
    fn status_text_is_typed_from_api_md() {
        let value = mesh::tagged::to_tagged_value(&status_text_response()).unwrap();
        assert!(value["1"].is_string());
    }

    #[test]
    fn android_settings_use_the_shared_store_and_firmware_result_shape() {
        use dmesh_server::{control, tagged};
        let directory = std::env::temp_dir().join(format!("dmesh-settings-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let mut store =
            dmesh_server::settings::FileSettings::new(directory.join("settings.conf"), "android");
        let call = |store: &mut _, request: control::Request<'_>| {
            let mut wire = [0u8; 128];
            let used = control::encode_request(request, Some(5), &mut wire).unwrap();
            settings_response_for(store, &wire[..used])
        };
        let set = call(
            &mut store,
            control::Request::SettingsSet { key: b"name", value: b"pixel" },
        )
        .expect("set");
        assert!(set.windows(3).any(|window| window == b"set"));
        let get = call(&mut store, control::Request::SettingsGet { key: b"name" }).expect("get");
        let record = tagged::decode(&get).unwrap();
        assert_eq!(record.id, Some(5));
        assert!(get.windows(5).any(|window| window == b"pixel"));
        let list = call(&mut store, control::Request::SettingsList).expect("list");
        assert!(list.windows(7).any(|window| window == b"entries"));
        // Secrets are not reachable through this handler.
        assert!(call(&mut store, control::Request::SettingsGet { key: b"sec:key" }).is_none());
        assert!(
            call(
                &mut store,
                control::Request::SettingsSet { key: b"sec:key", value: b"x" }
            )
            .is_none()
        );
        std::fs::remove_dir_all(&directory).unwrap();
    }

    #[test]
    fn a_nan_announce_reaches_the_shared_engine_and_is_not_a_udp_path() {
        use dmesh_server::announce::{Announce, encode};
        let _guard = RADIO_STATE_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_discovery();
        let engine = test_engine();
        // Android announces itself as an Android device with a stable id.
        let own = engine.local_announce().unwrap();
        assert_eq!(own.device_class, dmesh_server::announce::DEVICE_CLASS_ANDROID);
        assert!(!own.has_identity());
        // A peer seen only over NAN is in the same inventory the UDP path uses,
        // but has no UDP address to route to.
        let mut peer = Announce::discovery([0x5a; 16], 16, 3);
        assert!(peer.set_device_name("nanpeer"));
        let mut wire = [0u8; 256];
        let used = encode(peer, &mut wire).unwrap();
        observe_announce(peer, "aa:bb:cc:dd:ee:5a".to_owned(), "nan_sd", &wire[..used]);
        let error = discovered_udp_endpoint("5a5a5a5a").unwrap_err();
        assert!(error.contains("no_quic_route"), "{error}");
        let found = engine.devices();
        assert!(
            found
                .iter()
                .any(|device| device.name() == Some("nanpeer")
                    && device.observations.contains_key("nan"))
        );
    }

    #[test]
    fn discovery_nodes_rows_come_from_the_shared_inventory_one_per_bearer() {
        use dmesh_server::announce::{Announce, encode};
        let _guard = RADIO_STATE_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_discovery();
        let engine = test_engine();
        let mut peer = Announce::discovery([0x77; 16], 16, 42);
        assert!(peer.set_device_name("rowpeer"));
        peer.set_probe_descriptor(dmesh_server::announce::DEVICE_CLASS_HOST, 0x0f);
        peer.set_udp_link_local_v6("fe80::77".parse::<Ipv6Addr>().unwrap().octets());
        peer.set_udp_port(3336);
        let mut wire = [0u8; 256];
        let used = encode(peer, &mut wire).unwrap();
        // Seen on UDP (with a scoped sender) and on NAN (with a signal level).
        let sender: std::net::SocketAddr = "[fe80::77%5]:5227".parse().unwrap();
        engine.on_datagram(&dmesh_discovery::Carrier::udp("[fe80::77%5]:5227", sender), &wire[..used]);
        let mut nan = dmesh_discovery::Carrier::radio(
            "nan",
            "aware:3",
            dmesh_server::discovery::DiscoveryPacketKind::ActivePublish,
        );
        nan.rssi_dbm = Some(-58);
        engine.on_datagram(&nan, &wire[..used]);
        let original=wire[..used].to_vec();

        let mut request = [0u8; 32];
        let used = dmesh_server::tagged::encode_numeric_empty_request(
            dmesh_server::announce::ANNOUNCE_COMPONENT,
            dmesh_server::announce::ANNOUNCE_DEVICES_OBSERVED,
            9,
            &mut request,
        )
        .unwrap();
        let response = android_discovery_nodes_response(&request[..used]).expect("response");
        let mut decoder=dmesh_server::cbor::Decoder::new(&response);
        decoder.skip().unwrap();
        let mut rows=Vec::new();
        while !decoder.is_finished() {
            let at=decoder.position();decoder.skip().unwrap();let item=&response[at..decoder.position()];
            if item==dmesh_server::discovery_nodes::END {break;}
            rows.push(dmesh_server::discovery_nodes::Observation::decode(item).unwrap());
        }
        assert_eq!(rows.len(),2);
        assert!(rows.iter().all(|row|row.record==original));
        let nan=rows.iter().find(|row|row.bearer=="nan").unwrap();
        assert_eq!(nan.rssi_dbm,Some(-58));assert_eq!(nan.peer,None,"Android PeerHandle is not a MAC");
        let decoded=dmesh_server::announce::decode_announce(nan.record).unwrap();
        assert_eq!(decoded.device_name(),Some("rowpeer"));assert_eq!(decoded.uptime_secs,42);

    }

    #[test]
    fn android_companion_pages_target_the_registered_http_services() {
        let ble = include_str!("../../../android/app-dmesh/src/main/assets/ble.html");
        for method in [
            "ble.status",
            "ble.scan",
            "ble.scan_stop",
            "ble.scan_clear",
            "ble.scan_results",
            "companion.pair",
            "companion.unpair",
        ] {
            assert!(ble.contains(method), "BLE companion omits {method}");
        }
        assert!(ble.contains("services/${encodeURIComponent(service)}/call/"));
        assert!(ble.contains("'transport'"));

        let usb = include_str!("../../../android/app-dmesh/src/main/assets/usb.html");
        for method in ["usb.status", "usb.devices", "usb.open", "usb.close"] {
            assert!(usb.contains(method), "USB companion omits {method}");
        }
        assert!(usb.contains("services/usb/call/"));
    }
}
