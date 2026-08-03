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
use serde_json::{Map, Value, json};
use ssh_mesh::MeshListener;
use ssh_mesh::sshc::SshClientListener;
use std::collections::{BTreeMap, HashMap};
#[cfg(target_os = "android")]
use std::ffi::{CString, c_char, c_int, c_void};
#[cfg(target_os = "android")]
use std::io::{self, Write};
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
use lmesh::radio_protocol::{self, BleEvent};

const BRIDGE_HOST: &str = "dmesh-msg";
const LEGACY_BRIDGE_HOST: &str = "local";
const BRIDGE_PORT: u16 = 1;
static BRIDGE_SENDERS: OnceLock<Mutex<HashMap<u64, UnboundedSender<String>>>> = OnceLock::new();
static STORE_SENDER: OnceLock<UnboundedSender<StoreCommand>> = OnceLock::new();
const WEB_BRIDGE_CLIENT_ID: u64 = 9_000_000;
#[cfg(target_os = "android")]
static WEB_BRIDGE_LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
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

fn bridge_senders() -> &'static Mutex<HashMap<u64, UnboundedSender<String>>> {
    BRIDGE_SENDERS.get_or_init(|| Mutex::new(HashMap::new()))
}

pub fn init_store_sender(sender: UnboundedSender<StoreCommand>) {
    STORE_SENDER.set(sender).ok();
}

fn store_sender() -> Option<&'static UnboundedSender<StoreCommand>> {
    STORE_SENDER.get()
}

#[cfg(target_os = "android")]
fn register_android_proxy_bridge() {
    static REGISTER: Once = Once::new();
    REGISTER.call_once(|| {
        let _ =
            ssh_mesh::generic_proxy::set_generic_proxy_bridge(|app, method, params| async move {
                if app != "lmesh" && app != "dmesh" {
                    return Err(format!("android bridge does not handle app {app}"));
                }
                dispatch_android_proxy_command(method, params).await
            });
    });
}

#[cfg(target_os = "android")]
async fn dispatch_android_proxy_command(method: String, params: Value) -> Result<Value, String> {
    let _guard = WEB_BRIDGE_LOCK
        .get_or_init(|| tokio::sync::Mutex::new(()))
        .lock()
        .await;
    let callback = android_message_callback()
        .lock()
        .map_err(|_| "android callback lock poisoned".to_string())?
        .clone()
        .ok_or_else(|| "android message callback not registered".to_string())?;

    let client_id = WEB_BRIDGE_CLIENT_ID;
    let (tx, mut rx) = unbounded_channel::<String>();
    bridge_senders()
        .lock()
        .map_err(|_| "bridge sender map lock poisoned".to_string())?
        .insert(client_id, tx);

    let command = bridge_command_from_proxy(method, params);
    let dispatch_result = dispatch_bridge_command(&callback.0, &callback.1, client_id, &command)
        .map_err(|e| e.to_string());
    if dispatch_result.is_err() {
        let _ = bridge_senders().lock().map(|mut senders| {
            senders.remove(&client_id);
        });
        return dispatch_result.map(|_| Value::Null);
    }

    let timeout = tokio::time::sleep(std::time::Duration::from_millis(650));
    tokio::pin!(timeout);
    let mut last = None;
    loop {
        tokio::select! {
            line = rx.recv() => {
                let Some(line) = line else {
                    break;
                };
                if let Ok(value) = serde_json::from_str::<Value>(&line) {
                    last = Some(android_proxy_response_value(value));
                    break;
                }
            }
            _ = &mut timeout => {
                break;
            }
        }
    }

    let _ = bridge_senders().lock().map(|mut senders| {
        senders.remove(&client_id);
    });

    Ok(last.unwrap_or_else(|| {
        json!({
            "ok": true,
            "status": "sent",
            "method": command.method,
        })
    }))
}

#[cfg(target_os = "android")]
fn bridge_command_from_proxy(method: String, params: Value) -> BridgeCommand {
    let mut data = BTreeMap::new();
    if let Some(obj) = params.as_object() {
        insert_json_map(&mut data, obj);
    }
    let method = match method.as_str() {
        "status" => "messages.status".to_string(),
        "messages.history" => "messages.history".to_string(),
        value => value.to_string(),
    };
    BridgeCommand {
        id: None,
        method,
        data,
    }
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
fn android_proxy_response_value(mut value: Value) -> Value {
    let method = value
        .get("method")
        .and_then(Value::as_str)
        .map(str::to_string)
        .unwrap_or_default();
    if let Some(data) = value.get_mut("data") {
        if let Some(obj) = data.as_object_mut()
            && !method.is_empty()
        {
            obj.entry("method".to_string())
                .or_insert(Value::String(method));
        }
        return data.take();
    }
    value
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
            emit_android_message_line(0, rust_trace_frame(&line));
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
            emit_android_message_line(0, rust_trace_frame(line));
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
fn emit_android_message_line(client_id: u64, line: String) {
    // Rust tracing is useful to both Android's local message history and open
    // SSH clients. Do not route it through MsgMux first: the bridge sender is
    // the transport-neutral remote socket surface.
    if client_id == 0 {
        if let Ok(senders) = bridge_senders().lock() {
            for sender in senders.values() {
                let _ = sender.send(line.clone());
            }
        }
    }
    let callback = match android_message_callback().lock() {
        Ok(guard) => guard.clone(),
        Err(_) => None,
    };
    let Some((jvm, callback)) = callback else {
        return;
    };
    let mut env = match jvm.attach_current_thread() {
        Ok(env) => env,
        Err(_) => return,
    };
    let j_line = match env.new_string(line) {
        Ok(line) => line,
        Err(_) => return,
    };
    let _ = env.call_method(
        &callback,
        "onMessage",
        "(JLjava/lang/String;)V",
        &[(client_id as i64).into(), (&j_line).into()],
    );
}

#[cfg(target_os = "android")]
fn rust_trace_frame(line: &str) -> String {
    let payload =
        serde_json::from_str::<Value>(line).unwrap_or_else(|_| Value::String(line.into()));
    json!({
        "method": "messages.event",
        "data": {
            "source": "rust.trace",
            "json": payload,
        }
    })
    .to_string()
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
fn local_bridge_response(cmd: &BridgeCommand) -> Option<Value> {
    if cmd.method != "telemetry.history" && cmd.method != "telemetry.status" {
        return None;
    }
    let buffer = ANDROID_TELEMETRY.get();
    let limit = cmd
        .data
        .get("limit")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(100)
        .min(1000);
    let entries = buffer
        .map(|buffer| {
            let mut entries = buffer.get_all();
            if entries.len() > limit {
                entries.drain(..entries.len() - limit);
            }
            entries
        })
        .unwrap_or_default();
    let count = entries.len();
    let entries = if cmd.method == "telemetry.history" {
        serde_json::to_value(entries).unwrap_or(Value::Null)
    } else {
        Value::Null
    };
    Some(json!({
        "id": cmd.id,
        "ok": true,
        "method": cmd.method,
        "data": {
            "entries": entries,
            "count": count,
            "capacity": 1000,
        },
    }))
}

#[cfg(not(target_os = "android"))]
fn local_bridge_response(_cmd: &BridgeCommand) -> Option<Value> {
    None
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

impl BridgeCommand {
    fn to_json_value(&self) -> Value {
        let mut root = Map::new();
        if let Some(id) = &self.id {
            root.insert("id".to_string(), Value::String(id.clone()));
        }
        root.insert("method".to_string(), Value::String(self.method.clone()));
        let mut data = Map::new();
        for (key, value) in &self.data {
            data.insert(key.clone(), Value::String(value.clone()));
        }
        if !data.is_empty() {
            root.insert("data".to_string(), Value::Object(data));
        }
        Value::Object(root)
    }

    fn to_json_line(&self) -> String {
        self.to_json_value().to_string()
    }
}

fn parse_bridge_line(line: &str) -> anyhow::Result<BridgeCommand> {
    let line = line.trim();
    if line.is_empty() {
        anyhow::bail!("empty command");
    }
    if line.starts_with('{') {
        parse_bridge_json(line)
    } else {
        parse_bridge_human(line)
    }
}

fn parse_bridge_json(line: &str) -> anyhow::Result<BridgeCommand> {
    let value: Value = serde_json::from_str(line)?;
    let obj = value
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("command must be a JSON object"))?;
    let method = obj
        .get("method")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("missing method"))?
        .to_string();
    let id = obj.get("id").map(json_value_to_string);
    let mut data = BTreeMap::new();

    if let Some(payload) = obj.get("data").and_then(Value::as_object) {
        insert_json_map(&mut data, payload);
    } else {
        insert_json_map(&mut data, obj);
        data.remove("id");
        data.remove("method");
        data.remove("data");
    }

    Ok(BridgeCommand { id, method, data })
}

fn insert_json_map(data: &mut BTreeMap<String, String>, obj: &Map<String, Value>) {
    for (k, v) in obj {
        data.insert(k.clone(), json_value_to_string(v));
    }
}

fn json_value_to_string(v: &Value) -> String {
    v.as_str()
        .map(str::to_string)
        .unwrap_or_else(|| v.to_string())
}

fn radio_message(method: &str, args: &str, payload: &[u8], _fd: i32) -> anyhow::Result<Vec<u8>> {
    let cmd = parse_bridge_human(&format!("{} {}", method, args.trim()))?;
    let response = match cmd.method.as_str() {
        "radio.ble.build_service_data" => {
            let event = cmd
                .data
                .get("event")
                .map(String::as_str)
                .unwrap_or("generic");
            let device_id = hex_to_bytes(required_data(&cmd, "device_id")?)?;
            let rssi = parse_i32(&cmd, "rssi", 0)?;
            let snr_q4 = parse_i32(&cmd, "snr_q4", 0)?;
            radio_protocol::build_ble_service_data(
                BleEvent::parse(event),
                &device_id,
                payload,
                rssi,
                snr_q4,
            )?
        }
        "radio.ble.parse_service_data" => {
            let scan_rssi = parse_i32(&cmd, "scan_rssi", 0)?;
            let address = cmd.data.get("address").map(String::as_str).unwrap_or("");
            radio_protocol::parse_ble_service_data(payload, scan_rssi, address)?
                .to_string()
                .into_bytes()
        }
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
        "radio.nan.parse_service_info" => radio_protocol::parse_nan_service_info(payload)?
            .to_string()
            .into_bytes(),
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
            if let Some(sender) = store_sender() {
                let _ = sender.send(StoreCommand::InsertFrame(frame));
            }
            json!({"status": "ok"}).to_string().into_bytes()
        }
        "radio.ble.inject_frame" => {
            let parsed = radio_protocol::parse_ble_service_data(
                payload,
                parse_i32(&cmd, "scan_rssi", 0)?,
                cmd.data.get("address").map(String::as_str).unwrap_or(""),
            )?;
            let src_hex = parsed.get("src_hex").and_then(|v| v.as_str()).unwrap_or("");
            let packet_id = parsed
                .get("packet_id")
                .and_then(|v| v.as_u64())
                .map(|s| s as u16);
            let event = parsed.get("event").and_then(|v| v.as_str()).unwrap_or("");
            let payload_hash = parsed
                .get("packet_id")
                .and_then(|v| v.as_u64())
                .map(|h| h as u32)
                .unwrap_or(0);
            let frame = FrameRecord {
                protocol: "dmesh_ble".to_string(),
                payload_hash,
                src_device: src_hex.to_string(),
                target_device: None,
                seq: packet_id,
                msg_type: if event.is_empty() {
                    None
                } else {
                    Some(event.to_string())
                },
                payload: payload.to_vec(),
                rssi: parsed
                    .get("scan_rssi")
                    .and_then(|v| v.as_i64())
                    .map(|r| r as i32),
                timestamp: chrono::Utc::now().timestamp_millis(),
            };
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
                "onSshConnection",
                "(JLjava/lang/String;)V",
                &[(client_id as i64).into(), (&j_user).into()],
            );
        });
    }

    fn on_stream(&self, client_id: u64, host: &str, port: u16, stream: DuplexStream) {
        if (host == BRIDGE_HOST || host == LEGACY_BRIDGE_HOST) && port == BRIDGE_PORT {
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
                "onStream",
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
    jvm: Arc<JavaVM>,
    callback: GlobalRef,
    client_id: u64,
    command: String,
    mut stream: DuplexStream,
) {
    let (tx, mut rx) = unbounded_channel::<String>();
    match bridge_senders().lock() {
        Ok(mut senders) => {
            senders.insert(client_id, tx);
        }
        Err(e) => {
            log::error!("SSH exec sender map is poisoned: {}", e);
            return;
        }
    }

    let response = match parse_bridge_line(&command) {
        Ok(cmd) => local_bridge_response(&cmd).unwrap_or_else(|| {
            match dispatch_bridge_command(&jvm, &callback, client_id, &cmd) {
                Ok(()) => json!({
                    "id": cmd.id,
                    "ok": true,
                    "method": cmd.method,
                }),
                Err(e) => json!({
                    "id": cmd.id,
                    "ok": false,
                    "error": e.to_string(),
                }),
            }
        }),
        Err(e) => json!({
            "id": Value::Null,
            "ok": false,
            "error": e.to_string(),
        }),
    };

    let mut out = response.to_string();
    out.push('\n');
    if let Err(e) = stream.write_all(out.as_bytes()).await {
        log::warn!("SSH exec response write failed: {}", e);
    }

    let drain_until = tokio::time::Instant::now() + std::time::Duration::from_millis(750);
    loop {
        tokio::select! {
            outbound = rx.recv() => {
                let Some(mut out) = outbound else {
                    break;
                };
                out.push('\n');
                if let Err(e) = stream.write_all(out.as_bytes()).await {
                    log::warn!("SSH exec event write failed: {}", e);
                    break;
                }
            }
            _ = tokio::time::sleep_until(drain_until) => {
                break;
            }
        }
    }

    let _ = stream.shutdown().await;
    if let Ok(mut senders) = bridge_senders().lock() {
        senders.remove(&client_id);
    }
}

async fn handle_bridge_stream(
    jvm: Arc<JavaVM>,
    callback: GlobalRef,
    client_id: u64,
    mut stream: DuplexStream,
) {
    let (tx, mut rx) = unbounded_channel::<String>();
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
                for b in &buf[..n] {
                    if *b == b'\n' {
                        let line = String::from_utf8_lossy(&pending).trim().to_string();
                        pending.clear();
                        if line.is_empty() {
                            continue;
                        }
                        if line == "exit" || line == "quit" {
                            let response = json!({
                                "ok": true,
                                "method": "shell.exit",
                            });
                            let mut out = response.to_string();
                            out.push('\n');
                            let _ = stream.write_all(out.as_bytes()).await;
                            break 'stream_loop;
                        }
                        let response = match parse_bridge_line(&line) {
                            Ok(cmd) => {
                                if let Some(open) = mesh::message::StreamOpenRequest::parse(
                                    &cmd.to_json_value(),
                                    format!("ssh:{client_id}"),
                                ) {
                                    let ack = open.opened_response();
                                    let mut out = ack.to_string();
                                    out.push('\n');
                                    if let Err(e) = stream.write_all(out.as_bytes()).await {
                                        log::warn!("SSH stream upgrade ACK write failed: {}", e);
                                        break 'stream_loop;
                                    }
                                    if let Err(e) = notify_stream_opened(&jvm, &callback, client_id, &ack.to_string()) {
                                        log::warn!("stream-opened callback failed: {}", e);
                                    }
                                    hand_stream_to_java(&jvm, &callback, client_id, stream, "mesh-stream", 0);
                                    break 'stream_loop;
                                }
                                local_bridge_response(&cmd).unwrap_or_else(|| {
                                    match dispatch_bridge_command(&jvm, &callback, client_id, &cmd) {
                                        Ok(()) => json!({
                                            "id": cmd.id,
                                            "ok": true,
                                            "method": cmd.method,
                                        }),
                                        Err(e) => json!({
                                            "id": cmd.id,
                                            "ok": false,
                                            "error": e.to_string(),
                                        }),
                                    }
                                })
                            },
                            Err(e) => json!({
                                "id": Value::Null,
                                "ok": false,
                                "error": e.to_string(),
                            }),
                        };
                        let mut out = response.to_string();
                        out.push('\n');
                        if let Err(e) = stream.write_all(out.as_bytes()).await {
                            log::warn!("SSH message bridge write failed: {}", e);
                            break 'stream_loop;
                        }
                    } else if *b != b'\r' {
                        pending.push(*b);
                    }
                }
            }
            outbound = rx.recv() => {
                match outbound {
                    Some(mut out) => {
                        out.push('\n');
                        if let Err(e) = stream.write_all(out.as_bytes()).await {
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
}

fn notify_stream_opened(
    jvm: &JavaVM,
    callback: &GlobalRef,
    client_id: u64,
    line: &str,
) -> anyhow::Result<()> {
    let mut env = jvm.attach_current_thread()?;
    let j_line = env.new_string(line)?;
    env.call_method(
        callback,
        "onStreamOpened",
        "(JLjava/lang/String;)V",
        &[(client_id as i64).into(), (&j_line).into()],
    )?;
    Ok(())
}

fn hand_stream_to_java(
    jvm: &JavaVM,
    callback: &GlobalRef,
    client_id: u64,
    stream: DuplexStream,
    host: &str,
    port: u16,
) {
    let mut env = match jvm.attach_current_thread() {
        Ok(env) => env,
        Err(e) => {
            log::error!("Failed to attach thread for upgraded stream: {}", e);
            return;
        }
    };
    let j_host = match env.new_string(host) {
        Ok(value) => value,
        Err(e) => {
            log::error!("Failed to create upgraded stream host string: {}", e);
            return;
        }
    };
    let stream_handle = MeshStreamHandle {
        stream,
        runtime_handle: tokio::runtime::Handle::current(),
    };
    let h = Box::into_raw(Box::new(stream_handle)) as jlong;
    let _ = env.call_method(
        callback,
        "onStream",
        "(JLjava/lang/String;IJ)V",
        &[
            (client_id as i64).into(),
            (&j_host).into(),
            (port as i32).into(),
            h.into(),
        ],
    );
}

fn dispatch_bridge_command(
    jvm: &JavaVM,
    callback: &GlobalRef,
    client_id: u64,
    cmd: &BridgeCommand,
) -> anyhow::Result<()> {
    let mut env = jvm.attach_current_thread()?;
    let j_line = env.new_string(cmd.to_json_line())?;
    env.call_method(
        callback,
        "onMessage",
        "(JLjava/lang/String;)V",
        &[(client_id as i64).into(), (&j_line).into()],
    )?;
    Ok(())
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
                "onForwardedTcpip",
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
    #[cfg(target_os = "android")]
    register_android_proxy_bridge();

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
    mut env: JNIEnv,
    _class: JClass,
    client_id: jlong,
    line: JString,
) -> jboolean {
    let line: String = match env.get_string(&line) {
        Ok(line) => line.into(),
        Err(e) => {
            log::warn!("Failed to read bridge line: {}", e);
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
        Some(tx) if tx.send(line).is_ok() => JNI_TRUE,
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
    fn parses_json_command() {
        let cmd =
            parse_bridge_line(r#"{"id":"j1","method":"wifi.scan","data":{"reason":"json","n":2}}"#)
                .unwrap();
        assert_eq!(cmd.id.as_deref(), Some("j1"));
        assert_eq!(cmd.method, "wifi.scan");
        assert_eq!(cmd.data.get("reason").unwrap(), "json");
        assert_eq!(cmd.data.get("n").unwrap(), "2");
    }

    #[test]
    fn parses_json_method_command() {
        let cmd =
            parse_bridge_line(r#"{"id":"m1","method":"wifi.scan","data":{"reason":"json","n":2}}"#)
                .unwrap();
        assert_eq!(cmd.id.as_deref(), Some("m1"));
        assert_eq!(cmd.method, "wifi.scan");
        assert_eq!(cmd.to_json_value()["method"], "wifi.scan");
    }

    #[test]
    fn parses_human_key_value_command() {
        let cmd = parse_bridge_line(r#"wifi scan id=h1 reason="human value""#).unwrap();
        assert_eq!(cmd.id.as_deref(), Some("h1"));
        assert_eq!(cmd.method, "wifi.scan");
        assert_eq!(cmd.data.get("reason").unwrap(), "human value");
    }

    #[test]
    fn parses_human_method_name_command() {
        let cmd = parse_bridge_line(r#"wifi.scan id=h3 reason="human value""#).unwrap();
        assert_eq!(cmd.id.as_deref(), Some("h3"));
        assert_eq!(cmd.method, "wifi.scan");
        assert_eq!(cmd.data.get("reason").unwrap(), "human value");
    }

    #[test]
    fn parses_app_alias_method_name_command() {
        let cmd = parse_bridge_line(r#"app.chat.send id=a1 text=hello"#).unwrap();
        assert_eq!(cmd.id.as_deref(), Some("a1"));
        assert_eq!(cmd.method, "app.chat.send");
        assert_eq!(cmd.to_json_value()["method"], "app.chat.send");
    }

    #[test]
    fn parses_telemetry_text_command() {
        let cmd = parse_bridge_line("telemetry.history --id traces --limit 8").unwrap();
        assert_eq!(cmd.id.as_deref(), Some("traces"));
        assert_eq!(cmd.method, "telemetry.history");
        assert_eq!(cmd.data.get("limit").unwrap(), "8");
    }

    #[test]
    fn parses_human_long_options_command() {
        let cmd = parse_bridge_line("wifi.scan --id h2 --reason human --enabled").unwrap();
        assert_eq!(cmd.id.as_deref(), Some("h2"));
        assert_eq!(cmd.method, "wifi.scan");
        assert_eq!(cmd.data.get("reason").unwrap(), "human");
        assert_eq!(cmd.data.get("enabled").unwrap(), "1");
    }

    #[test]
    fn radio_message_builds_and_parses_ble_service_data() {
        let device_id = "010203040506";
        let payload = b"abcdef";
        let built = radio_message(
            "radio.ble.build_service_data",
            &format!("event=lora_rx device_id={device_id} rssi=-70 snr_q4=6"),
            payload,
            -1,
        )
        .unwrap();
        // Current ESP32 advertisements begin with the DMesh BLE UUID16; the
        // legacy `DM\x01` header remains accepted only by the parser.
        assert_eq!(
            u16::from_le_bytes([built[0], built[1]]),
            lmesh::radio_protocol::DMESH_BLE_SERVICE_UUID16
        );

        let parsed = radio_message(
            "radio.ble.parse_service_data",
            "scan_rssi=-62 address=aa:bb",
            &built,
            -1,
        )
        .unwrap();
        let parsed = String::from_utf8(parsed).unwrap();
        assert!(parsed.contains(r#""layout":"esp32_service_data""#));
        assert!(parsed.contains(r#""event":"lora_rx""#));
        assert!(parsed.contains(r#""src_hex":"0x04030201""#));
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
}
