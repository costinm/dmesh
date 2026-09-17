//! JNI bindings for the mesh node.
//!
//! This module provides Java/Android bindings via JNI. All core logic
//! is delegated to [`crate::mesh_common`]; this module handles only
//! JNI-specific marshalling (JString ↔ Rust String, jlong ↔ pointer casts)
//! and callback plumbing.
//!
//! See also:
//! - Java wrapper: `android/app-dmesh/src/main/java/...`

use dmesh_server::discovery::{
    DiscoveryObservation, DiscoveryPacketKind, OBSERVATION_PAYLOAD_FINGERPRINT, OBSERVATION_PEER,
    OBSERVATION_RSSI,
};
use dmesh_store::{FrameRecord, StoreCommand};
use jni::objects::{GlobalRef, JByteArray, JClass, JObject, JString};
#[cfg(target_os = "android")]
use jni::sys::JNI_VERSION_1_6;
use jni::sys::{JNI_FALSE, JNI_TRUE, jboolean, jint, jlong};
use jni::{JNIEnv, JavaVM};
use mesh::{
    tagged::{NameOrTag, TaggedRecord},
    wire::response_ok,
};
use serde_json::{Value, json};
#[cfg(target_os = "android")]
use sha2::{Digest, Sha256};
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
static STORE_SENDER: OnceLock<UnboundedSender<StoreCommand>> = OnceLock::new();
/// Every discovery bearer updates this Rust-owned view before Java keeps any
/// short-lived NAN `PeerHandle`. The inventory is advisory and unsigned;
/// entries expire after one hour. NAN Service Info, UDP multicast announces,
/// and future control-plane observations therefore share one device map.
static DISCOVERED_DEVICES: OnceLock<Mutex<BTreeMap<String, DiscoveredDevice>>> = OnceLock::new();
/// Platform adapters report the device's current interface/address snapshot;
/// Rust owns this table so routing and multicast discovery make the same
/// decision on Android and Linux.  It is a replacement snapshot, not a Java
/// policy cache.
static LOCAL_NETWORKS: OnceLock<Mutex<dmesh_server::local_networks::LocalNetworkTable>> =
    OnceLock::new();
/// Latest Android platform power/memory telemetry. This is an input to Rust
/// scheduling; Java reports facts and does not decide admission policy.
static POWER_STATE: OnceLock<Mutex<dmesh_server::power::PowerState>> = OnceLock::new();
/// Last received NAN follow-ups are retained independently of the optional
/// persistent frame store so Android status and E2E use the same bounded
/// receipt view as host/ESP adapters.
static NAN_FOLLOWUPS: OnceLock<Mutex<VecDeque<FrameRecord>>> = OnceLock::new();
/// Android framework lifecycle/configuration events are forwarded to Rust as
/// well, but they are not directed NAN follow-ups. Keep their diagnostic
/// history distinct so `radio.nan.followups` has the same receipt semantics
/// as the host and ESP handlers.
static NAN_EVENTS: OnceLock<Mutex<VecDeque<FrameRecord>>> = OnceLock::new();
const DISCOVERED_DEVICE_TTL_MS: i64 = 60 * 60 * 1000;
const NAN_FOLLOWUP_HISTORY_LEN: usize = 32;
const NAN_EVENT_HISTORY_LEN: usize = 64;

#[derive(Clone)]
struct DiscoveredDevice {
    last_seen_ms: i64,
    peer: String,
    info: Value,
    /// Compatibility projection: newest peer identity per bearer.
    transports: BTreeMap<String, String>,
    /// Bounded packet facts per bearer.  Discovery UI and E2E use these
    /// receiver-side facts rather than inferring reachability from a local
    /// transmit submission.
    observations: BTreeMap<String, DiscoveryObservation>,
}

fn nan_followups() -> &'static Mutex<VecDeque<FrameRecord>> {
    NAN_FOLLOWUPS.get_or_init(|| Mutex::new(VecDeque::with_capacity(NAN_FOLLOWUP_HISTORY_LEN)))
}

fn nan_events() -> &'static Mutex<VecDeque<FrameRecord>> {
    NAN_EVENTS.get_or_init(|| Mutex::new(VecDeque::with_capacity(NAN_EVENT_HISTORY_LEN)))
}

fn record_nan_followup(frame: FrameRecord) {
    if let Ok(mut history) = nan_followups().lock() {
        if history.len() == NAN_FOLLOWUP_HISTORY_LEN {
            history.pop_front();
        }
        history.push_back(frame);
    }
}

fn record_nan_event(frame: FrameRecord) {
    if let Ok(mut history) = nan_events().lock() {
        // Lifecycle callbacks describe the state used by `telemetry.nan_status`.
        // Routine discovery callbacks can be arbitrarily frequent, so they must
        // not evict the last attach/publish/subscribe transition and make a live
        // Android Aware session look inactive.
        if history.len() == NAN_EVENT_HISTORY_LEN {
            if let Some(index) = history
                .iter()
                .position(|entry| !nan_event_is_lifecycle(entry.msg_type.as_deref()))
            {
                history.remove(index);
            } else if nan_event_is_lifecycle(frame.msg_type.as_deref()) {
                // A lifecycle-only history is exceptionally small; retain the
                // latest transition rather than rejecting it.
                history.pop_front();
            } else {
                // Keep the lifecycle state intact. The raw persistent frame
                // store still receives this diagnostic callback below.
                return;
            }
        }
        history.push_back(frame);
    }
}

fn nan_event_is_lifecycle(event: Option<&str>) -> bool {
    matches!(
        event,
        Some(
            "attached"
                | "aware.on_attached"
                | "aware.on_session_terminated"
                | "aware.on_attach_failed"
                | "aware.session_close"
                | "aware.on_publish_started"
                | "aware.on_publish_terminated"
                | "aware.publish_close"
                | "aware.on_subscribe_started"
                | "aware.on_subscribe_terminated"
                | "aware.subscribe_close"
        )
    )
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

pub fn init_store_sender(sender: UnboundedSender<StoreCommand>) {
    STORE_SENDER.set(sender).ok();
}

fn store_sender() -> Option<&'static UnboundedSender<StoreCommand>> {
    STORE_SENDER.get()
}

fn discovered_devices() -> &'static Mutex<BTreeMap<String, DiscoveredDevice>> {
    DISCOVERED_DEVICES.get_or_init(|| Mutex::new(BTreeMap::new()))
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

/// Serve the compact, bearer-neutral `discovery.nodes` result used by ESP and
/// lmesh. Android's JSON inventory remains useful to its UI, but a QUIC peer
/// must receive this CBOR shape so controller-side discovery can merge
/// observer provenance without a platform exception.
#[cfg(target_os = "android")]
pub(crate) fn android_discovery_nodes_response(request: &[u8]) -> Option<Vec<u8>> {
    let record = dmesh_server::tagged::decode(request)?;
    if record.to.is_some()
        || record.id.is_none()
        || !dmesh_server::announce::is_devices_observed_request(request)
    {
        return None;
    }
    let id = record.id?;
    let devices = discovered_devices().lock().ok()?;
    let mut ids = Vec::<[u8; 16]>::new();
    let mut device_keys = Vec::<String>::new();
    for (device_id, _) in devices.iter().take(8) {
        let Ok(value) = hex_to_bytes(device_id) else {
            continue;
        };
        if value.is_empty() || value.len() > 16 {
            continue;
        }
        let mut stable_id = [0u8; 16];
        stable_id[..value.len()].copy_from_slice(&value);
        ids.push(stable_id);
        device_keys.push(device_id.clone());
    }
    let mut metadata = Vec::<dmesh_server::announce::ObservedDevice>::new();
    for (device_id, stable_id) in device_keys.iter().zip(ids.iter()) {
        let device = devices.get(device_id)?;
        let value = hex_to_bytes(device_id).ok()?;
        let observation = device.observations.values().next();
        let available_fields = observation
            .map(|observation| observation.available_fields)
            .unwrap_or(dmesh_server::discovery::OBSERVATION_PAYLOAD_FINGERPRINT);
        metadata.push(dmesh_server::announce::ObservedDevice {
            device_id: &stable_id[..value.len()],
            // Android's PeerHandle is intentionally opaque. It is not a MAC
            // and must not be serialized as one; a nonzero semantic id above
            // is the cross-bearer merge key.
            peer: [0; 6],
            bssid: None,
            channel: None,
            available_fields,
            first_seen_ms: observation
                .map(|value| u32::try_from(value.first_seen_ms).unwrap_or(u32::MAX))
                .unwrap_or(0),
            last_seen_ms: observation
                .map(|value| u32::try_from(value.last_seen_ms).unwrap_or(u32::MAX))
                .unwrap_or(0),
            packets: observation.map(|value| value.packets).unwrap_or(0),
            active_publish_rx: observation
                .map(|value| value.active_publish_rx)
                .unwrap_or(0),
            active_subscribe_rx: observation
                .map(|value| value.active_subscribe_rx)
                .unwrap_or(0),
            followup_rx: observation.map(|value| value.followup_rx).unwrap_or(0),
            last_kind: observation.map(|value| value.last_kind as u8).unwrap_or(0),
            last_payload_len: observation.map(|value| value.last_payload_len).unwrap_or(0),
            last_payload_hash: observation
                .map(|value| value.last_payload_hash)
                .unwrap_or(0),
        });
    }
    let mut direct = [0u8; 1024];
    let direct_len =
        dmesh_server::announce::encode_devices_observed_response(&metadata, &mut direct)?;
    let fields = dmesh_server::tagged::decode(&direct[..direct_len])?.fields?;
    let mut response = [0u8; 1100];
    let response_len = dmesh_server::tagged::encode_numeric_response(
        dmesh_server::announce::ANNOUNCE_COMPONENT,
        dmesh_server::announce::ANNOUNCE_DEVICES_OBSERVED,
        id,
        fields,
        &mut response,
    )?;
    Some(response[..response_len].to_vec())
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
    let (jvm, callback) = android_message_callback().lock().ok()?.clone()?;
    let mut env = jvm.attach_current_thread().ok()?;
    if env
        .call_method(&callback, "onDiscoveryActive", "()V", &[])
        .is_err()
    {
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

/// Build Android's current bearer-neutral presence record from framework
/// facts already retained by Rust.  Both UDP directed discovery and the
/// Java NAN projection use this identity/routing shape: Android must not
/// advertise a second, UDP-only identity or a synthetic endpoint.
#[cfg(target_os = "android")]
pub(crate) fn android_discovery_announce(
    public_key: &str,
    uptime_secs: u32,
) -> dmesh_server::announce::Announce {
    let digest = Sha256::digest(public_key.as_bytes());
    let mut device_id = [0u8; 16];
    device_id.copy_from_slice(&digest[..16]);
    let mut announce =
        dmesh_server::announce::Announce::discovery(device_id, device_id.len() as u8, uptime_secs);
    announce.set_probe_descriptor(
        dmesh_server::announce::DEVICE_CLASS_ANDROID,
        dmesh_server::probe::PROBE_CAP_NAN
            | dmesh_server::probe::PROBE_CAP_STA
            | dmesh_server::probe::PROBE_CAP_AP
            | dmesh_server::probe::PROBE_CAP_UDP6,
    );
    if let Ok(networks) = local_networks().lock() {
        let Some(network) = networks.networks.values().find(|network| {
            network.active
                && network
                    .transports
                    .iter()
                    .any(|transport| transport == "wifi")
        }) else {
            return announce;
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
            announce.set_udp_link_local_v6(address.octets());
            announce.set_udp_port(dmesh_server::udp::STABLE_WIFI_UDP_PORT);
        }
    }
    announce
}

/// Return the unsigned, receiver-side NAN facts carried beside Android's
/// signed discovery record. Wi-Fi Aware does not expose a peer cluster/BSSID
/// through its public API, so the cluster suffix stays absent; service receipt
/// and visible-node counts come from the same bounded NAN observation cache
/// returned by `discovery.nodes`.
#[cfg(target_os = "android")]
pub(crate) fn android_discovery_facts() -> dmesh_server::announce::DiscoveryFacts {
    let now_ms = chrono::Utc::now().timestamp_millis();
    let Ok(mut devices) = discovered_devices().lock() else {
        return dmesh_server::announce::DiscoveryFacts::default();
    };
    prune_discovered_devices(&mut devices, now_ms);
    let mut services = 0u16;
    let mut nodes = 0u16;
    for device in devices.values() {
        if let Some(observation) = device.observations.get("nan") {
            nodes = nodes.saturating_add(1);
            services =
                services.saturating_add(u16::try_from(observation.packets).unwrap_or(u16::MAX));
        }
    }
    dmesh_server::announce::DiscoveryFacts {
        nan_cluster_suffix: None,
        nan_service_observations: services,
        nan_visible_nodes: nodes,
    }
}

fn prune_discovered_devices(devices: &mut BTreeMap<String, DiscoveredDevice>, now_ms: i64) {
    devices
        .retain(|_, device| now_ms.saturating_sub(device.last_seen_ms) <= DISCOVERED_DEVICE_TTL_MS);
}

fn observe_packet(
    device: &mut DiscoveredDevice,
    bearer: &str,
    kind: &str,
    peer: &str,
    payload: &[u8],
    rssi_dbm: Option<i32>,
    now_ms: i64,
) {
    let kind = match kind {
        "active_publish" => DiscoveryPacketKind::ActivePublish,
        "active_subscribe" => DiscoveryPacketKind::ActiveSubscribe,
        "followup" => DiscoveryPacketKind::Followup,
        _ => DiscoveryPacketKind::Other,
    };
    let available_fields = OBSERVATION_PEER
        | OBSERVATION_PAYLOAD_FINGERPRINT
        | if rssi_dbm.is_some() {
            OBSERVATION_RSSI
        } else {
            0
        };
    let observation = device
        .observations
        .entry(bearer.to_owned())
        .or_insert_with(|| DiscoveryObservation::new(now_ms, available_fields));
    // A framework RSSI callback is an actual available fact; leave the bit
    // clear when Android did not supply one rather than displaying a made-up
    // zero. Keep earlier capability facts if a later callback omits RSSI.
    observation.available_fields |= available_fields;
    observation.observe(
        now_ms,
        kind,
        peer,
        None,
        None,
        rssi_dbm.and_then(|value| i16::try_from(value).ok()),
        payload,
    );
    device.last_seen_ms = now_ms;
    if !peer.is_empty() {
        device.peer = peer.to_owned();
        device.transports.insert(bearer.to_owned(), peer.to_owned());
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
    let frame = FrameRecord {
        protocol: "dmesh_nan_followup".to_string(),
        payload_hash: packet_hash,
        src_device: src_device.to_string(),
        target_device: (!target_device.is_empty()).then(|| target_device.to_string()),
        seq,
        msg_type: (!msg_type.is_empty()).then(|| msg_type.to_string()),
        payload: payload.to_vec(),
        rssi: rssi_dbm,
        timestamp: chrono::Utc::now().timestamp_millis(),
    };
    record_nan_followup(frame.clone());
    if let Some(sender) = store_sender() {
        let _ = sender.send(StoreCommand::InsertFrame(frame));
    }
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
        let now_ms = chrono::Utc::now().timestamp_millis();
        if let Ok(mut devices) = discovered_devices().lock() {
            prune_discovered_devices(&mut devices, now_ms);
            let device = devices
                .entry(src_device.to_ascii_lowercase())
                .or_insert_with(|| DiscoveredDevice {
                    last_seen_ms: now_ms,
                    peer: String::new(),
                    info: json!({"protocol": "dmesh_nan_followup"}),
                    transports: BTreeMap::new(),
                    observations: BTreeMap::new(),
                });
            observe_packet(device, "nan", "followup", peer, payload, rssi_dbm, now_ms);
        }
    }
    Ok(json!({"status": "ok", "packet_kind": "followup", "source": src_device}))
}

/// Record a validated common announce from any Android discovery bearer.
/// `source` is provenance only: boot and periodic presence records update one
/// Rust-owned inventory whether UDP multicast, NAN Service Info, or a future
/// control-plane adapter delivered them.
pub(crate) fn observe_announce(
    announce: dmesh_server::announce::Announce,
    peer: String,
    source: &str,
    payload: &[u8],
) {
    let now_ms = chrono::Utc::now().timestamp_millis();
    let Ok(mut devices) = discovered_devices().lock() else {
        return;
    };
    prune_discovered_devices(&mut devices, now_ms);
    let id = bytes_to_hex(announce.device_id());
    let device = devices.entry(id).or_insert_with(|| DiscoveredDevice {
        last_seen_ms: now_ms,
        peer: String::new(),
        info: Value::Null,
        transports: BTreeMap::new(),
        observations: BTreeMap::new(),
    });
    let bearer = if source.starts_with("nan") {
        "nan"
    } else {
        source
    };
    let kind = match source {
        "nan_followup" => "followup",
        _ if bearer == "nan" => "active_publish",
        _ => "announce",
    };
    observe_packet(device, bearer, kind, &peer, payload, None, now_ms);
    device.info = json!({
        "protocol": "dmesh_announce",
        "kind": announce.kind,
        "uptime_secs": announce.uptime_secs,
        "device_class": announce.device_class,
        "probe_capabilities": announce.probe_capabilities,
        "device_name": announce.device_name(),
        "network_name": announce.network_name(),
        "sta_link_local_v6": announce.sta_link_local_v6().map(std::net::Ipv6Addr::from).map(|address| address.to_string()),
        "vip6": dmesh_server::announce::virtual_ip6(announce.public_key())
            .or_else(|| dmesh_server::announce::virtual_ip6_from_identity_hint(announce.device_id()))
            .map(std::net::Ipv6Addr::from).map(|address| address.to_string()),
    });
}

#[cfg(target_os = "android")]
fn configure_android_mesh_paths(base_dir: &str) {
    let base = std::path::Path::new(base_dir);
    let run_base = base.join("run").join("mesh");
    let home_base = base.join("home");
    let opt_base = base.join("opt");

    for dir in [&run_base, &home_base, &opt_base] {
        if let Err(e) = std::fs::create_dir_all(dir) {
            log::warn!(
                "Failed to create Android mesh path {}: {}",
                dir.display(),
                e
            );
        }
    }

    // Android has no system mesh runtime directory. Keep any defensive UDS
    // fallback under the app's files/ tree and route web commands by bridge.
    unsafe {
        std::env::set_var("MESH_HOME", base);
        std::env::set_var("MESH_RUN_BASE", &run_base);
        std::env::set_var("MESH_HOME_BASE", &home_base);
        std::env::set_var("MESH_OPT_BASE", &opt_base);
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
                announce.set_udp_link_local_v6(address.octets());
                announce.set_udp_port(dmesh_server::udp::STABLE_WIFI_UDP_PORT);
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
                let now_ms = chrono::Utc::now().timestamp_millis();
                let mut devices = discovered_devices()
                    .lock()
                    .map_err(|_| anyhow::anyhow!("discovered-device cache poisoned"))?;
                prune_discovered_devices(&mut devices, now_ms);
                let device = devices
                    .entry(device_id.to_ascii_lowercase())
                    .or_insert_with(|| DiscoveredDevice {
                        last_seen_ms: now_ms,
                        peer: String::new(),
                        info: Value::Null,
                        transports: BTreeMap::new(),
                        observations: BTreeMap::new(),
                    });
                observe_packet(
                    device,
                    "nan",
                    "active_publish",
                    &peer,
                    payload,
                    None,
                    now_ms,
                );
                device.info = parsed.clone();
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
            json!({"networks": networks, "local_networks": networks, "stats": {"devices": discovered_devices().lock().map(|devices| devices.len()).unwrap_or(0)}}).to_string().into_bytes()
        }
        "radio.power.status" => update_power_state(payload)?.to_string().into_bytes(),
        "radio.power.state" => dmesh_server::power::json_status(
            *power_state()
                .lock()
                .map_err(|_| anyhow::anyhow!("power state poisoned"))?,
        )
        .to_string()
        .into_bytes(),
        "discovery.nodes" | "radio.nan.known_devices" => {
            let now_ms = chrono::Utc::now().timestamp_millis();
            let mut devices = discovered_devices()
                .lock()
                .map_err(|_| anyhow::anyhow!("discovered-device cache poisoned"))?;
            prune_discovered_devices(&mut devices, now_ms);
            let devices: Vec<Value> = devices
                .iter()
                .map(|(_, device)| {
                    let identity = device
                        .info
                        .get("device_name")
                        .and_then(Value::as_str)
                        .filter(|value| !value.is_empty())
                        .or_else(|| device.info.get("vip6").and_then(Value::as_str));
                    let mut value = json!({
                        "identity_state": "semantic",
                        "last_seen_ms": device.last_seen_ms,
                        "announce": device.info,
                        "observations": device.observations.iter().map(|(bearer, observation)| {
                            (bearer.clone(), json!({
                                "first_seen_ms": observation.first_seen_ms,
                                "last_seen_ms": observation.last_seen_ms,
                                "available_fields": observation.available_fields,
                                "unavailable_fields": observation.unavailable_fields(),
                                "packets": observation.packets,
                                "active_publish_rx": observation.active_publish_rx,
                                "active_subscribe_rx": observation.active_subscribe_rx,
                                "followup_rx": observation.followup_rx,
                                "last_kind": observation.last_kind.as_str(),
                                "last_bssid": observation.last_bssid,
                                "last_channel": observation.last_channel,
                                "last_rssi_dbm": observation.last_rssi_dbm,
                                "last_payload_len": observation.last_payload_len,
                                "last_payload_hash": observation.last_payload_hash,
                            }))
                        }).collect::<serde_json::Map<_, _>>(),
                    });
                    if let Some(identity) = identity {
                        value["identity"] = Value::String(identity.to_owned());
                    }
                    value
                })
                .collect();
            json!({"devices": devices}).to_string().into_bytes()
        }
        "radio.status_text" => {
            let now_ms = chrono::Utc::now().timestamp_millis();
            let mut devices = discovered_devices()
                .lock()
                .map_err(|_| anyhow::anyhow!("discovered-device cache poisoned"))?;
            prune_discovered_devices(&mut devices, now_ms);
            let networks = local_networks()
                .lock()
                .map_err(|_| anyhow::anyhow!("local-networks table poisoned"))?;
            let internet = networks
                .networks
                .values()
                .any(|network| network.validated && network.internet);
            let mut text = format!(
                "DMesh\nLocal networks: {}{}\nDiscovered devices: {}",
                networks.networks.len(),
                if internet {
                    " (validated internet)"
                } else {
                    ""
                },
                devices.len()
            );
            if let Ok(power) = power_state().lock() {
                if let Some(percent) = power.battery_percent {
                    text.push_str("\nBattery: ");
                    text.push_str(&percent.to_string());
                    text.push('%');
                }
                if power.power_save.unwrap_or(false) {
                    text.push_str(" (power save)");
                }
            }
            for (id, device) in devices.iter() {
                text.push_str("\n- ");
                text.push_str(id);
                if !device.peer.is_empty() {
                    text.push(' ');
                    text.push_str(&device.peer);
                }
                if let Some(source) = device.info.get("source").and_then(Value::as_str) {
                    if !source.is_empty() {
                        text.push_str(" via ");
                        text.push_str(source);
                    }
                }
            }
            text.into_bytes()
        }
        "probe.plan" => {
            let source_id = required_data(&cmd, "source_id")?;
            let target_id = required_data(&cmd, "target_id")?;
            if source_id == target_id {
                anyhow::bail!("source_id and target_id must differ");
            }
            let short_bytes = parse_u32(&cmd, "short_bytes", 4 * 1024)?;
            let long_bytes = parse_u32(&cmd, "long_bytes", 64 * 1024)?;
            let now_ms = chrono::Utc::now().timestamp_millis();
            let mut devices = discovered_devices()
                .lock()
                .map_err(|_| anyhow::anyhow!("discovered-device cache poisoned"))?;
            prune_discovered_devices(&mut devices, now_ms);
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
                        "last_seen_ms": entry.timestamp,
                        "source": entry.src_device,
                        "target": entry.target_device,
                        "seq": entry.seq,
                        "msg_type": entry.msg_type,
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
                        "last_seen_ms": entry.timestamp,
                        "event": entry.msg_type,
                        "peer": entry.src_device,
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
                .filter(|entry| now_ms.saturating_sub(entry.timestamp) <= 10 * 60 * 1_000)
            {
                let Some(event) = entry.msg_type.as_deref() else {
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
        "telemetry.now_metrics" | "telemetry.udp6_metrics" | "telemetry.wifi_link_metrics" => {
            b"{}".to_vec()
        }
        "telemetry.nan_metrics" => {
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
            let frame = FrameRecord {
                protocol: "android_nan_event".to_string(),
                payload_hash: 0,
                src_device: peer,
                target_device: None,
                seq: None,
                msg_type: (!event.is_empty()).then_some(event),
                payload: payload.to_vec(),
                rssi: None,
                timestamp: chrono::Utc::now().timestamp_millis(),
            };
            record_nan_event(frame.clone());
            if let Some(sender) = store_sender() {
                let _ = sender.send(StoreCommand::InsertFrame(frame));
            }
            json!({"status": "ok"}).to_string().into_bytes()
        }
        "radio.transport.event" => {
            let transport = cmd.data.get("transport").cloned().unwrap_or_default();
            let event = cmd.data.get("event").cloned().unwrap_or_default();
            let frame = FrameRecord {
                protocol: format!("android_{transport}_event"),
                payload_hash: 0,
                src_device: String::new(),
                target_device: None,
                seq: None,
                msg_type: (!event.is_empty()).then_some(event),
                payload: payload.to_vec(),
                rssi: None,
                timestamp: chrono::Utc::now().timestamp_millis(),
            };
            if let Some(sender) = store_sender() {
                let _ = sender.send(StoreCommand::InsertFrame(frame));
            }
            json!({"status": "ok"}).to_string().into_bytes()
        }
        // Kept only for the root/ADB ContentProvider compatibility path. It
        // will be removed once that provider submits common tagged control
        // records directly; HTTP and embedded mesh dispatch never use it.
        "radio.shell.command" => {
            let line = std::str::from_utf8(payload)?.trim();
            let schema = mesh::schema::ResourceSchema::from_embedded(include_str!(
                "../../lmesh/resources/firmware-schema.json"
            ))?;
            let request = schema.parse_shell(line)?;
            let method = request
                .get("method")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let params = request.get("params").and_then(Value::as_object);
            // The root/ADB compatibility provider must expose the same
            // bounded inventory as the app UI and Linux/ESP diagnostics.
            // This is a read-only projection of the existing JNI command;
            // it does not create a provider-specific discovery cache.
            if matches!(
                method,
                "discovery.nodes"
                    | "telemetry.nan_status"
                    | "telemetry.now_metrics"
                    | "telemetry.nan_metrics"
                    | "telemetry.udp6_metrics"
                    | "telemetry.wifi_link_metrics"
                    | "radio.nan.followups"
                    | "radio.nan.events"
                    | "discovery.status"
            ) {
                return radio_message(method, "", &[], -1);
            }
            // Schema enum fields are represented by their stable numeric tag
            // at this adapter boundary. Accept the text form as well for an
            // older local caller, but project both forms through the one
            // `transport.set` Android operation.
            let transport_mode = params.and_then(|params| params.get("mode"));
            let mode_nan = method == "transport.set"
                && transport_mode.is_some_and(|mode| {
                    matches!(mode.as_str(), Some("nan" | "aware")) || mode.as_u64() == Some(6)
                });
            let p2p_go = params
                .and_then(|params| params.get("ap"))
                .and_then(Value::as_str)
                .is_some_and(|value| value == "1")
                || params
                    .and_then(|params| params.get("p2p_go"))
                    .and_then(Value::as_str)
                    .is_some_and(|value| value == "1");
            let sta = method == "transport.set"
                && transport_mode
                    .is_some_and(|mode| mode.as_str() == Some("sta") || mode.as_u64() == Some(1));
            // `uart` is the portable all-radio-off profile.  Android has no
            // UART bearer, so its projection only tears down the Android
            // Wi-Fi personalities; it does not invent a separate
            // `wifi.nan.stop` command surface.
            let radio_off = method == "transport.set"
                && transport_mode
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
                anyhow::bail!("no Android backend for schema command: {method}");
            };
            json!({"status": "accepted", "operation": operation, "request": request})
                .to_string()
                .into_bytes()
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
            // WifiAware's `sendMessage` payload is the service-info body of
            // a NAN Follow-up, not a bare DMesh control channel. Keep the
            // same envelope consumed by ESP/host adapters so the receiver can
            // validate framing before it dispatches the target-checked CBOR.
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
        "radio.coc.store_frame" => {
            let src_device = required_data(&cmd, "src_device")?;
            let seq = parse_i32(&cmd, "seq", -1)?;
            let hash = parse_u32(&cmd, "hash", 0)?;
            if seq < 0 || seq > u16::MAX as i32 {
                anyhow::bail!("radio.coc.store_frame requires seq=0..{}", u16::MAX);
            }
            if payload.is_empty() {
                anyhow::bail!("radio.coc.store_frame requires a non-empty payload");
            }
            let frame = FrameRecord {
                protocol: "dmesh_coc_lora".to_string(),
                payload_hash: hash,
                src_device: src_device.to_string(),
                target_device: None,
                seq: Some(seq as u16),
                msg_type: Some("lora".to_string()),
                payload: payload.to_vec(),
                rssi: None,
                timestamp: chrono::Utc::now().timestamp_millis(),
            };
            let sender =
                store_sender().ok_or_else(|| anyhow::anyhow!("dmesh-store is not initialized"))?;
            let (reply_tx, reply_rx) = std::sync::mpsc::channel();
            sender
                .send(StoreCommand::InsertFrameWithReply(frame, reply_tx))
                .map_err(|_| anyhow::anyhow!("dmesh-store service is unavailable"))?;
            let id = reply_rx
                .recv_timeout(std::time::Duration::from_secs(5))
                .map_err(|_| anyhow::anyhow!("timed out waiting for dmesh-store"))?
                .map_err(anyhow::Error::msg)?;
            json!({"status": "stored", "id": id})
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

/// Execute an embedded tagged-record request through the existing Rust-owned
/// Android control dispatcher.  This deliberately stays below JNI: the HTTP
/// bridge calls it directly and never creates a socket, CBOR session, or Java
/// command parser.  Android exposes named methods until it publishes a tagged
/// catalog; numeric identities are rejected rather than guessed.
pub(crate) fn handle_tagged_control_record(
    record: TaggedRecord,
) -> anyhow::Result<Option<TaggedRecord>> {
    let component = match &record.component {
        NameOrTag::Name(component) => component,
        NameOrTag::Tag(tag) => {
            anyhow::bail!("Android control has no catalog mapping for numeric component @{tag}")
        }
    };
    let method = match &record.method {
        NameOrTag::Name(method) => method,
        NameOrTag::Tag(tag) => {
            anyhow::bail!("Android control has no catalog mapping for numeric method @{tag}")
        }
    };
    if method.is_empty() {
        anyhow::bail!("tagged control record is missing a method")
    }
    // This handler is registered with the localhost HTTP service. Framework
    // callbacks still enter through their dedicated JNI functions.
    let supported = matches!(
        (component.as_str(), method.as_str()),
        ("", "status")
            | ("discovery", "devices" | "nodes" | "status")
            | (
                "telemetry",
                "nan_status" | "now_metrics" | "nan_metrics" | "udp6_metrics" | "wifi_link_metrics"
            )
            | (
                "radio",
                "status_text"
                    | "devices"
                    | "nan.followups"
                    | "nan.events"
                    | "local_networks"
                    | "power.state"
            )
    );
    if !supported {
        anyhow::bail!("method is not exposed by the Android mesh HTTP service")
    }
    if !record.params.is_empty() {
        anyhow::bail!("Android tagged control does not support positional parameters")
    }
    if record.data.is_some() {
        anyhow::bail!("Android HTTP control methods do not accept opaque data")
    }
    if !record.env.is_empty() {
        anyhow::bail!("Android HTTP observation methods do not accept fields or data")
    }

    let full_method = match (component.as_str(), method.as_str()) {
        // The common tagged name is discovery.nodes while Android's internal
        // callback predates the catalog and exposes it as discovery/devices.
        // Keep this translation here, at the platform boundary.
        ("discovery", "devices" | "nodes") => "discovery.nodes".to_owned(),
        _ if component.is_empty() => method.clone(),
        _ => format!("{component}.{method}"),
    };
    let output = radio_message(&full_method, "", &[], -1)?;
    let Some(id) = record.id else {
        return Ok(None);
    };
    let result = serde_json::from_slice(&output)
        .or_else(|_| std::str::from_utf8(&output).map(|text| Value::String(text.to_owned())))
        .unwrap_or_else(|_| Value::Array(output.into_iter().map(Value::from).collect()));
    Ok(Some(response_ok(id, result)))
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
}

impl crate::bearer::BearerEgress for JavaBearerEgress {
    fn send_packet(&self, bearer: &str, packet: &[u8]) {
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
        let j_packet = match env.byte_array_from_slice(packet) {
            Ok(value) => value,
            Err(error) => {
                log::error!("Failed to create bearer egress bytes: {}", error);
                return;
            }
        };
        if let Err(error) = env.call_method(
            &self.callback,
            "onBearerPacket",
            "(Ljava/lang/String;[B)V",
            &[(&j_bearer).into(), (&j_packet).into()],
        ) {
            log::error!("Failed to deliver bearer egress packet: {}", error);
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

    let bearer_egress = Arc::new(JavaBearerEgress {
        jvm: jvm.clone(),
        callback: callback_ref.clone(),
    });
    crate::bearer::set_current(Some(crate::bearer::BearerRuntime::spawn(
        handle.runtime.handle().clone(),
        bearer_egress,
    )));

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

/// Provision the private device/control-plane root before the next mesh
/// start. Java only supplies Android's app-private base directory and opaque
/// bytes; the shared Rust settings helper owns validation and the atomic
/// mode-0600 write. The secret is never returned through JNI, settings, HTTP,
/// SSH, or a QUIC handler.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_github_costinm_dmeshnative_MeshNode_nativeProvisionDeviceSecret(
    mut env: JNIEnv,
    _class: JClass,
    base_dir: JString,
    secret: JByteArray,
) -> jboolean {
    let base_dir: String = match env.get_string(&base_dir) {
        Ok(value) => value.into(),
        Err(_) => return JNI_FALSE,
    };
    let secret = match env.convert_byte_array(&secret) {
        Ok(secret) => secret,
        Err(_) => return JNI_FALSE,
    };
    match dmesh_server::settings::write_private_device_secret_file(
        std::path::Path::new(&base_dir).join("device-secret.bin"),
        &secret,
    ) {
        Ok(()) => JNI_TRUE,
        Err(error) => {
            // Deliberately log only the operation error, never length or
            // contents of provisioning material.
            log::warn!("Android device-secret provisioning rejected: {error}");
            JNI_FALSE
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

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_github_costinm_dmeshnative_MeshNode_nativeBearerPacket(
    mut env: JNIEnv,
    _class: JClass,
    _handle: jlong,
    bearer: JString,
    packet: JByteArray,
) -> jboolean {
    let bearer: String = match env.get_string(&bearer) {
        Ok(value) => value.into(),
        Err(_) => return JNI_FALSE,
    };
    let packet = match env.convert_byte_array(&packet) {
        Ok(value) => value,
        Err(_) => return JNI_FALSE,
    };
    if crate::bearer::packet(&bearer, &packet) {
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
        assert!(status.contains("Local networks: 1 (validated internet)"));
    }

    #[test]
    fn power_telemetry_is_validated_and_retained_in_rust() {
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
        for _ in 0..(NAN_EVENT_HISTORY_LEN * 2) {
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
        discovered_devices().lock().unwrap().clear();
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
        discovered_devices().lock().unwrap().clear();
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
        assert_eq!(announce.udp_port, dmesh_server::udp::STABLE_WIFI_UDP_PORT);
    }

    #[test]
    fn tagged_control_dispatch_is_in_process_and_preserves_request_id() {
        let response = handle_tagged_control_record(TaggedRecord {
            component: NameOrTag::Name("radio".to_owned()),
            method: NameOrTag::Name("status_text".to_owned()),
            id: Some(json!(17)),
            ..Default::default()
        })
        .unwrap()
        .unwrap();
        assert_eq!(response.id, Some(json!(17)));
        assert!(
            response
                .result
                .and_then(|value| value.as_str().map(str::to_owned))
                .is_some_and(|text| text.starts_with("DMesh"))
        );
    }

    #[test]
    fn android_shell_projects_numeric_transport_set_nan_to_the_nan_adapter() {
        let projection =
            radio_message("radio.shell.command", "", b"transport.set mode=nan", -1).unwrap();
        let projection: Value = serde_json::from_slice(&projection).unwrap();
        assert_eq!(projection["status"], "accepted");
        assert_eq!(projection["operation"], "nan");
        assert_eq!(projection["request"]["params"]["mode"], 6);
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
    fn android_shell_projects_uart_transport_set_to_the_all_radio_off_adapter() {
        let projection =
            radio_message("radio.shell.command", "", b"transport.set mode=uart", -1).unwrap();
        let projection: Value = serde_json::from_slice(&projection).unwrap();
        assert_eq!(projection["status"], "accepted");
        assert_eq!(projection["operation"], "stop");
        assert_eq!(projection["request"]["params"]["mode"], 5);
    }

    #[test]
    fn tagged_control_without_id_is_oneway() {
        let response = handle_tagged_control_record(TaggedRecord {
            component: NameOrTag::Name("radio".to_owned()),
            method: NameOrTag::Name("status_text".to_owned()),
            ..Default::default()
        })
        .unwrap();
        assert!(response.is_none());
    }

    #[test]
    fn tagged_http_control_rejects_unreviewed_radio_actions() {
        let error = handle_tagged_control_record(TaggedRecord {
            component: NameOrTag::Name("radio".to_owned()),
            method: NameOrTag::Name("nan.event".to_owned()),
            id: Some(json!(18)),
            ..Default::default()
        })
        .unwrap_err();
        assert!(error.to_string().contains("not exposed"));
    }

    #[test]
    fn tagged_http_observations_reject_untyped_inputs() {
        let error = handle_tagged_control_record(TaggedRecord {
            component: NameOrTag::Name("radio".to_owned()),
            method: NameOrTag::Name("devices".to_owned()),
            id: Some(json!(19)),
            env: BTreeMap::from([(NameOrTag::Name("limit".to_owned()), json!(10))]),
            ..Default::default()
        })
        .unwrap_err();
        assert!(error.to_string().contains("do not accept"));
    }
}
