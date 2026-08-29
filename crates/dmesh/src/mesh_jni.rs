//! JNI bindings for the mesh node.
//!
//! This module provides Java/Android bindings via JNI. All core logic
//! is delegated to [`crate::mesh_common`]; this module handles only
//! JNI-specific marshalling (JString ↔ Rust String, jlong ↔ pointer casts)
//! and callback plumbing.
//!
//! See also:
//! - Java wrapper: `android/app-dmesh/src/main/java/...`

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
use ssh_mesh::MeshListener;
use ssh_mesh::sshc::SshClientListener;
use std::collections::{BTreeMap, HashMap, VecDeque};
#[cfg(target_os = "android")]
use std::ffi::{CString, c_char, c_int, c_void};
use std::io;
#[cfg(target_os = "android")]
use std::io::Write;
use std::net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV6};
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

use crate::mesh_common::{MeshHandle, MeshStreamHandle};
use lmesh::radio_protocol;

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
    transports: BTreeMap<String, String>,
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
        if history.len() == NAN_EVENT_HISTORY_LEN {
            history.pop_front();
        }
        history.push_back(frame);
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
    LOCAL_NETWORKS.get_or_init(|| Mutex::new(dmesh_server::local_networks::LocalNetworkTable::default()))
}

fn power_state() -> &'static Mutex<dmesh_server::power::PowerState> {
    POWER_STATE.get_or_init(|| Mutex::new(dmesh_server::power::PowerState::default()))
}

fn update_power_state(payload: &[u8]) -> anyhow::Result<Value> {
    let observation = dmesh_server::power::decode_json_observation(payload)
        .map_err(anyhow::Error::msg)?;
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

fn prune_discovered_devices(devices: &mut BTreeMap<String, DiscoveredDevice>, now_ms: i64) {
    devices
        .retain(|_, device| now_ms.saturating_sub(device.last_seen_ms) <= DISCOVERED_DEVICE_TTL_MS);
}

/// Record a validated common announce from any Android discovery bearer.
/// `source` is provenance only: boot and periodic presence records update one
/// Rust-owned inventory whether UDP multicast, NAN Service Info, or a future
/// control-plane adapter delivered them.
pub(crate) fn observe_announce(
    announce: dmesh_server::announce::Announce,
    peer: String,
    source: &str,
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
    });
    device.last_seen_ms = now_ms;
    if !peer.is_empty() {
        device.transports.insert(source.to_owned(), peer.clone());
        device.peer = peer;
    }
    device.info = json!({
                "protocol": "dmesh_announce",
                "source": source,
                "kind": announce.kind,
                "uptime_secs": announce.uptime_secs,
                "transport_mode": announce.transport_mode,
                "counters": announce.counters,
                "device_class": announce.device_class,
                "probe_capabilities": announce.probe_capabilities,
                "device_name": announce.device_name(),
                "network_name": announce.network_name(),
                "sta_link_local_v6": announce.sta_link_local_v6().map(std::net::Ipv6Addr::from).map(|address| address.to_string()),
                "ap_link_local_v6": announce.ap_link_local_v6().map(std::net::Ipv6Addr::from).map(|address| address.to_string()),
                "public_key": (!announce.public_key().is_empty()).then(|| bytes_to_hex(announce.public_key())),
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
            let transport_mode = parse_u32(&cmd, "transport_mode", 0)? as u8;
            let counters = parse_u32(&cmd, "counters", 0)?;
            let kind = match cmd.data.get("kind").map(String::as_str) {
                Some("boot") => dmesh_server::announce::ANNOUNCE_BOOT,
                _ => dmesh_server::announce::ANNOUNCE_DISCOVERY,
            };
            let mut id = [0; 16];
            if device_id.is_empty() || device_id.len() > id.len() {
                anyhow::bail!("announce device id must be 1..16 bytes");
            }
            id[..device_id.len()].copy_from_slice(&device_id);
            let announce = if kind == dmesh_server::announce::ANNOUNCE_BOOT {
                let mut boot = dmesh_server::announce::Announce::boot(
                    id,
                    device_id.len() as u8,
                    transport_mode,
                );
                boot.uptime_secs = uptime_secs;
                boot.counters = counters;
                boot
            } else {
                dmesh_server::announce::Announce::discovery(
                    id,
                    device_id.len() as u8,
                    uptime_secs,
                    transport_mode,
                    counters,
                )
            };
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
            if let Some(address) = cmd.data.get("sta_link_local_v6").filter(|value| !value.is_empty()) {
                let address = address
                    .parse::<Ipv6Addr>()
                    .map_err(|_| anyhow::anyhow!("sta_link_local_v6 must be IPv6"))?;
                if !address.is_unicast_link_local() { anyhow::bail!("sta_link_local_v6 must be link-local"); }
                announce.set_sta_link_local_v6(address.octets());
            }
            if let Some(address) = cmd.data.get("ap_link_local_v6").filter(|value| !value.is_empty()) {
                let address = address
                    .parse::<Ipv6Addr>()
                    .map_err(|_| anyhow::anyhow!("ap_link_local_v6 must be IPv6"))?;
                if !address.is_unicast_link_local() { anyhow::bail!("ap_link_local_v6 must be link-local"); }
                announce.set_ap_link_local_v6(address.octets());
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
                observe_announce(announce, peer.clone(), "nan_sd");
                json!({
                    "protocol": "dmesh_announce",
                    "source": "nan_sd",
                    "device_id": bytes_to_hex(announce.device_id()),
                    "kind": announce.kind,
                    "uptime_secs": announce.uptime_secs,
                    "transport_mode": announce.transport_mode,
                    "counters": announce.counters,
                    "device_name": announce.device_name(),
                    "network_name": announce.network_name(),
                    "sta_link_local_v6": announce.sta_link_local_v6().map(std::net::Ipv6Addr::from).map(|address| address.to_string()),
                    "ap_link_local_v6": announce.ap_link_local_v6().map(std::net::Ipv6Addr::from).map(|address| address.to_string()),
                    "public_key": (!announce.public_key().is_empty()).then(|| bytes_to_hex(announce.public_key())),
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
                devices.insert(
                    device_id.to_ascii_lowercase(),
                    DiscoveredDevice {
                        last_seen_ms: now_ms,
                        peer: peer.clone(),
                        info: parsed.clone(),
                        transports: BTreeMap::from([("nan_service_info".to_owned(), peer.clone())]),
                    },
                );
            }
            parsed.to_string().into_bytes()
        }
        "radio.local_networks.update" => {
            let count = update_local_networks(payload)?;
            json!({"ok": true, "interfaces": count})
                .to_string()
                .into_bytes()
        }
        "radio.local_networks" => {
            let networks = local_networks()
                .lock()
                .map_err(|_| anyhow::anyhow!("local-networks table poisoned"))?
                .networks
                .values()
                .map(dmesh_server::local_networks::json_network)
                .collect::<Vec<_>>();
            json!({"networks": networks}).to_string().into_bytes()
        }
        "radio.power.status" => update_power_state(payload)?.to_string().into_bytes(),
        "radio.power.state" => dmesh_server::power::json_status(
            *power_state()
                .lock()
                .map_err(|_| anyhow::anyhow!("power state poisoned"))?,
        )
        .to_string()
        .into_bytes(),
        "radio.devices" | "radio.nan.known_devices" => {
            let now_ms = chrono::Utc::now().timestamp_millis();
            let mut devices = discovered_devices()
                .lock()
                .map_err(|_| anyhow::anyhow!("discovered-device cache poisoned"))?;
            prune_discovered_devices(&mut devices, now_ms);
            let devices: Vec<Value> = devices
                .iter()
                .map(|(id, device)| {
                    json!({
                        "id": id,
                        "last_seen_ms": device.last_seen_ms,
                        "peer": device.peer,
                        "info": device.info,
                        "transports": device.transports,
                    })
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
        "radio.probe.plan" => {
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
                        dmesh_server::announce::DEVICE_CLASS_ESP => {
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
                .filter_map(|(id, device)| {
                    let class = device.info.get("device_class")?.as_u64()? as u8;
                    let kind = match class {
                        dmesh_server::announce::DEVICE_CLASS_ESP => "esp",
                        dmesh_server::announce::DEVICE_CLASS_HOST => "host",
                        dmesh_server::announce::DEVICE_CLASS_ANDROID => "android",
                        _ => return None,
                    };
                    let capabilities = device.info.get("probe_capabilities")?.as_u64()?;
                    Some(json!({
                        "id": id,
                        "kind": kind,
                        "capabilities": capabilities,
                    }))
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
        "radio.probe.udp6_echo" => {
            // The controller supplies the address learned from the shared
            // multicast announce and the *local* P2P interface index. A
            // link-local address without that scope is not a usable P2P
            // destination, so reject it here rather than silently using an
            // unrelated default Wi-Fi route.
            let address = required_data(&cmd, "address")?
                .parse::<Ipv6Addr>()
                .map_err(|_| anyhow::anyhow!("udp6 echo address must be IPv6"))?;
            if !address.is_unicast_link_local() {
                anyhow::bail!("udp6 echo requires an IPv6 link-local address");
            }
            let scope = parse_u32(&cmd, "scope", 0)?;
            if scope == 0 {
                anyhow::bail!("udp6 echo requires a nonzero local interface scope");
            }
            let port = u16::try_from(parse_u32(
                &cmd,
                "port",
                u32::from(dmesh_server::udp::STABLE_WIFI_UDP_PORT),
            )?)
            .map_err(|_| anyhow::anyhow!("udp6 echo port is outside u16"))?;
            let body = cmd
                .data
                .get("payload")
                .map(String::as_bytes)
                .unwrap_or(b"dmesh-p2p-probe");
            if body.is_empty() || body.len() > 256 {
                anyhow::bail!("udp6 echo payload must be 1..=256 bytes");
            }
            let peer = SocketAddr::V6(SocketAddrV6::new(address, port, 0, scope));
            let bind = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0);
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|error| anyhow::anyhow!("udp6 echo runtime: {error}"))?;
            let started = std::time::Instant::now();
            let payload = body.to_vec();
            let payload_len = payload.len();
            let result = runtime.block_on(async move {
                let cid_value = (chrono::Utc::now().timestamp_micros() as u64) | 1;
                let cid = quic_lite::ConnectionId::new(cid_value)
                    .ok_or_else(|| anyhow::anyhow!("udp6 echo CID"))?;
                let mut client = tokio::time::timeout(
                    std::time::Duration::from_secs(3),
                    dmesh_server::udp::UdpClient::connect(bind, peer, cid),
                )
                .await
                .map_err(|_| anyhow::anyhow!("udp6 echo bootstrap timeout"))??;
                let mut request = Vec::with_capacity(1 + payload.len());
                request.push(quic_lite::SERVICE_ECHO);
                request.extend_from_slice(&payload);
                let (_, echoed, _) = tokio::time::timeout(
                    std::time::Duration::from_secs(3),
                    client.request_stream(quic_lite::FIRST_CLIENT_BIDI_STREAM_ID, &request, true),
                )
                .await
                .map_err(|_| anyhow::anyhow!("udp6 echo response timeout"))??;
                let _ = client.close(0).await;
                if echoed != payload {
                    anyhow::bail!("udp6 echo payload mismatch");
                }
                Ok::<_, anyhow::Error>(client.transport_stats())
            })?;
            json!({
                "ok": true,
                "peer": peer.to_string(),
                "bytes": payload_len,
                "elapsed_us": started.elapsed().as_micros(),
                "packets_tx": result.sent_datagrams,
                "packets_rx": result.received_datagrams,
            })
            .to_string()
            .into_bytes()
        }
        "radio.probe.udp6_iperf" => {
            // This is the same scoped-P2P UDP bearer and common SERVICE_IPERF
            // schema used by host/firmware tests. Java only marshals the
            // request; stream reassembly and transport accounting stay Rust.
            let address = required_data(&cmd, "address")?
                .parse::<Ipv6Addr>()
                .map_err(|_| anyhow::anyhow!("udp6 iperf address must be IPv6"))?;
            if !address.is_unicast_link_local() {
                anyhow::bail!("udp6 iperf requires an IPv6 link-local address");
            }
            let scope = parse_u32(&cmd, "scope", 0)?;
            if scope == 0 {
                anyhow::bail!("udp6 iperf requires a nonzero local interface scope");
            }
            let port = u16::try_from(parse_u32(
                &cmd,
                "port",
                u32::from(dmesh_server::udp::STABLE_WIFI_UDP_PORT),
            )?)
            .map_err(|_| anyhow::anyhow!("udp6 iperf port is outside u16"))?;
            let bytes = u64::from(parse_u32(&cmd, "bytes", 32 * 1024)?);
            if !(1..=256 * 1024).contains(&bytes) {
                anyhow::bail!("udp6 iperf bytes must be 1..=262144");
            }
            let packet_size = u16::try_from(parse_u32(&cmd, "packet_size", 1_100)?)
                .map_err(|_| anyhow::anyhow!("udp6 iperf packet size is outside u16"))?;
            if !(64..=1_100).contains(&packet_size) {
                anyhow::bail!("udp6 iperf packet size must be 64..=1100");
            }
            let peer = SocketAddr::V6(SocketAddrV6::new(address, port, 0, scope));
            let bind = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0);
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|error| anyhow::anyhow!("udp6 iperf runtime: {error}"))?;
            let started = std::time::Instant::now();
            let result = runtime.block_on(async move {
                let cid_value = (chrono::Utc::now().timestamp_micros() as u64) | 1;
                let cid = quic_lite::ConnectionId::new(cid_value)
                    .ok_or_else(|| anyhow::anyhow!("udp6 iperf CID"))?;
                let mut client = tokio::time::timeout(
                    std::time::Duration::from_secs(4),
                    dmesh_server::udp::UdpClient::connect(bind, peer, cid),
                )
                .await
                .map_err(|_| anyhow::anyhow!("udp6 iperf bootstrap timeout"))??;
                let mut request = [0u8; 64];
                let request_len = dmesh_server::iperf::encode_iperf_service_request(
                    dmesh_server::iperf::IperfServiceRequest::new(bytes, packet_size),
                    &mut request,
                )
                .ok_or_else(|| anyhow::anyhow!("udp6 iperf request encoding"))?;
                // IPERF is an asymmetric service: the client opens the
                // request stream, while the server schedules its payload on
                // a server-initiated response stream (normally ID 1). Do
                // not use `request_stream_all`, which correctly enforces
                // same-stream request/response semantics for RPC services
                // but would reject this IPERF response as `1 expected 4`.
                let expected =
                    usize::try_from(bytes).map_err(|_| anyhow::anyhow!("udp6 iperf size"))?;
                let (response_stream, first, mut finished) = tokio::time::timeout(
                    std::time::Duration::from_secs(12),
                    client.request_stream(
                        quic_lite::FIRST_CLIENT_BIDI_STREAM_ID,
                        &request[..request_len],
                        true,
                    ),
                )
                .await
                .map_err(|_| anyhow::anyhow!("udp6 iperf first response timeout"))??;
                let mut received = first;
                while !finished {
                    let (stream, chunk, fin) = tokio::time::timeout(
                        std::time::Duration::from_secs(12),
                        client.recv_stream(),
                    )
                    .await
                    .map_err(|_| anyhow::anyhow!("udp6 iperf transfer timeout"))??;
                    if stream != response_stream {
                        anyhow::bail!(
                            "udp6 iperf response stream {stream} expected {response_stream}"
                        );
                    }
                    if received.len().saturating_add(chunk.len()) > expected {
                        anyhow::bail!("udp6 iperf response exceeds requested {bytes} bytes");
                    }
                    received.extend_from_slice(&chunk);
                    finished = fin;
                }
                if received.len() != usize::try_from(bytes).unwrap_or(usize::MAX) {
                    anyhow::bail!("udp6 iperf received {} expected {bytes}", received.len());
                }
                let stats = client.transport_stats();
                let _ = client.close(0).await;
                Ok::<_, anyhow::Error>(stats)
            })?;
            let elapsed_us = started.elapsed().as_micros().max(1) as u64;
            json!({
                "ok": true,
                "peer": peer.to_string(),
                "bytes": bytes,
                "packet_size": packet_size,
                "elapsed_us": elapsed_us,
                "bps": bytes.saturating_mul(8_000_000) / elapsed_us,
                "packets_tx": result.sent_datagrams,
                "packets_rx": result.received_datagrams,
                "retransmitted": result.retransmitted_datagrams,
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
            let method = request.get("method").and_then(Value::as_str).unwrap_or_default();
            let params = request.get("params").and_then(Value::as_object);
            let mode_nan = method == "transport.start"
                && params
                    .and_then(|params| params.get("mode"))
                    .and_then(Value::as_str)
                    .is_some_and(|mode| mode == "nan" || mode == "aware");
            let p2p_go = params
                .and_then(|params| params.get("ap"))
                .and_then(Value::as_str)
                .is_some_and(|value| value == "1")
                || params
                    .and_then(|params| params.get("p2p_go"))
                    .and_then(Value::as_str)
                    .is_some_and(|value| value == "1");
            let sta = method == "transport.start"
                && params
                    .and_then(|params| params.get("mode"))
                    .and_then(Value::as_str)
                    .is_some_and(|mode| mode == "sta");
            let operation = if method == "transport.stop" {
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
        "radio.nan.parse_followup" => radio_protocol::parse_nan_followup(payload)?
            .to_string()
            .into_bytes(),
        "radio.nan.inject_frame" => {
            let parsed = radio_protocol::parse_nan_followup(payload)?;
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
            let payload_hash = parsed
                .get("payload_hash_u32")
                .and_then(|v| v.as_u64())
                .map(|h| h as u32)
                .unwrap_or(0);
            let frame = FrameRecord {
                protocol: "dmesh_nan_followup".to_string(),
                payload_hash,
                src_device: src_device.to_string(),
                target_device: if target_device.is_empty() {
                    None
                } else {
                    Some(target_device.to_string())
                },
                seq,
                msg_type: if msg_type.is_empty() {
                    None
                } else {
                    Some(msg_type.to_string())
                },
                payload: payload.to_vec(),
                rssi: None,
                timestamp: chrono::Utc::now().timestamp_millis(),
            };
            // The framework callback has supplied an actual directed
            // follow-up. Retain it in the Rust-owned bounded receipt view;
            // generic NAN lifecycle events use the separate `nan.events`
            // cache above and must not pollute this protocol-level list.
            record_nan_followup(frame.clone());
            if let Some(sender) = store_sender() {
                let _ = sender.send(StoreCommand::InsertFrame(frame));
            }
            json!({"status": "ok"}).to_string().into_bytes()
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
    // callbacks still enter through their dedicated JNI functions. The one
    // mutating operation below is a bounded common UDP6 perf service selected
    // from shared discovery facts, not an Android-private radio command.
    if component != "radio"
        || !matches!(method.as_str(), "status_text" | "devices" | "local_networks" | "power.state" | "perf.udp6")
    {
        anyhow::bail!("method is not exposed by the Android mesh HTTP service")
    }
    if !record.params.is_empty() {
        anyhow::bail!("Android tagged control does not support positional parameters")
    }
    if record.data.is_some() {
        anyhow::bail!("Android HTTP control methods do not accept opaque data")
    }
    if method != "perf.udp6" && !record.env.is_empty() {
        anyhow::bail!("Android HTTP observation methods do not accept fields or data")
    }

    let mut args = String::new();
    if method == "perf.udp6" {
        let field = |name: &str| {
            record.env.iter().find_map(|(key, value)| match key {
                NameOrTag::Name(key) if key == name => Some(value),
                _ => None,
            })
        };
        let target_id = field("target_id")
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty())
            .ok_or_else(|| anyhow::anyhow!("perf.udp6 requires target_id"))?;
        let bytes = field("bytes").and_then(Value::as_u64).unwrap_or(32 * 1024);
        let packet_size = field("packet_size").and_then(Value::as_u64).unwrap_or(1_100);
        if !(1..=256 * 1024).contains(&bytes) || !(64..=1_100).contains(&packet_size) {
            anyhow::bail!("perf.udp6 bytes or packet_size is outside the published bounds")
        }
        let device = discovered_devices()
            .lock()
            .map_err(|_| anyhow::anyhow!("discovered-device cache poisoned"))?
            .get(target_id)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("unknown discovered target_id"))?;
        let network_name = device.info.get("network_name").and_then(Value::as_str)
            .filter(|name| !name.is_empty())
            .ok_or_else(|| anyhow::anyhow!("target has not announced a current STA SSID"))?;
        let local_matches = local_networks()
            .lock()
            .map_err(|_| anyhow::anyhow!("local-networks table poisoned"))?
            .networks
            .values()
            .any(|network| network.ssid.as_deref() == Some(network_name));
        if !local_matches {
            anyhow::bail!("target STA SSID does not match a local active STA attachment")
        }
        let peer = device.transports.get("udp_multicast")
            .ok_or_else(|| anyhow::anyhow!("target has no UDP multicast transport observation"))?
            .parse::<SocketAddr>()
            .map_err(|_| anyhow::anyhow!("target UDP multicast address is invalid"))?;
        let SocketAddr::V6(peer) = peer else {
            anyhow::bail!("target UDP multicast address is not IPv6")
        };
        if !peer.ip().is_unicast_link_local() || peer.scope_id() == 0 {
            anyhow::bail!("target UDP multicast address lacks a scoped IPv6 link-local route")
        }
        args = format!(
            "address={} scope={} port={} bytes={} packet_size={}",
            peer.ip(), peer.scope_id(), peer.port(), bytes, packet_size
        );
    }

    let full_method = if component.is_empty() {
        method.clone()
    } else {
        format!("{component}.{method}")
    };
    let full_method = if method == "perf.udp6" { "radio.probe.udp6_iperf".to_owned() } else { full_method };
    let output = radio_message(&full_method, &args, &[], -1)?;
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
) -> jlong {
    #[cfg(target_os = "android")]
    init_android_logging();

    let base_dir_str: String = match env.get_string(&base_dir) {
        Ok(s) => s.into(),
        Err(_) => return 0,
    };
    #[cfg(target_os = "android")]
    configure_android_mesh_paths(&base_dir_str);

    match crate::mesh_common::start_mesh(&base_dir_str, ssh_port, http_port) {
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
        let handle = unsafe { Box::from_raw(handle as *mut MeshHandle) };
        crate::mesh_common::stop_mesh(*handle);
    }
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
        let handle = AndroidVpnHandle {
            _runtime: runtime,
            _injector: injector,
        };
        let ptr = Box::into_raw(Box::new(handle)) as jlong;
        log::info!("Android VPN mesh-tun started handle={}", ptr);
        Ok(ptr)
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
    let _ = unsafe { Box::from_raw(handle as *mut AndroidVpnHandle) };
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let table = radio_message("radio.local_networks", "", &[], -1).unwrap();
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
        radio_message("radio.nan.inject_frame", "rssi=-55", &followup, -1).unwrap();
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
    fn android_device_inventory_unifies_udp_and_nan_discovery() {
        discovered_devices().lock().unwrap().clear();
        let mut id = [0_u8; 16];
        id[..6].copy_from_slice(b"udp-a1");
        observe_announce(
            dmesh_server::announce::Announce::discovery(id, 6, 12, 1, 3),
            "[fe80::1]:5227".to_string(),
            "udp_multicast",
        );
        let service_info = radio_message(
            "radio.nan.build_announce",
            "kind=discovery device_id=6e616e2d6232 uptime_secs=13 transport_mode=0 counters=4",
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
        let devices = radio_message("radio.devices", "", &[], -1).unwrap();
        let devices: Value = serde_json::from_slice(&devices).unwrap();
        let ids = devices["devices"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|entry| entry["id"].as_str())
            .collect::<Vec<_>>();
        assert!(ids.contains(&"7564702d6131"));
        assert!(ids.contains(&"6e616e2d6232"));
        let entries = devices["devices"].as_array().unwrap();
        let udp = entries
            .iter()
            .find(|device| device["id"] == "7564702d6131")
            .unwrap();
        let nan = entries
            .iter()
            .find(|device| device["id"] == "6e616e2d6232")
            .unwrap();
        assert_eq!(udp["info"]["source"], "udp_multicast");
        assert_eq!(nan["info"]["source"], "nan_sd");
    }

    #[test]
    fn android_nan_announce_retains_sta_network_name() {
        let wire = radio_message(
            "radio.nan.build_announce",
            "kind=discovery device_id=616e64726f69642d31 uptime_secs=13 transport_mode=1 counters=4 device_name=Pixel network_name=costin sta_link_local_v6=fe80::1234 ap_link_local_v6=fe80::5678",
            &[],
            -1,
        )
        .unwrap();
        let announce = dmesh_server::announce::decode_announce(&wire)
            .expect("Android presence must decode as a common announce");
        assert_eq!(announce.device_name(), Some("Pixel"));
        assert_eq!(announce.network_name(), Some("costin"));
        assert_eq!(announce.sta_link_local_v6(), Some("fe80::1234".parse::<Ipv6Addr>().unwrap().octets()));
        assert_eq!(announce.ap_link_local_v6(), Some("fe80::5678".parse::<Ipv6Addr>().unwrap().octets()));
        assert_eq!(announce.transport_mode, 1);
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
