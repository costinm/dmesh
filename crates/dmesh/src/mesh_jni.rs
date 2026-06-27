//! JNI bindings for the mesh node.
//!
//! This module provides Java/Android bindings via JNI. All core logic
//! is delegated to [`crate::mesh_common`]; this module handles only
//! JNI-specific marshalling (JString ↔ Rust String, jlong ↔ pointer casts)
//! and callback plumbing.
//!
//! See also:
//! - Rust binary: `src/main.rs`
//! - Java wrapper: `java/rust/src/main/java/...`

use jni::objects::{GlobalRef, JByteArray, JClass, JObject, JObjectArray, JString};
use jni::sys::{jboolean, jint, jlong, JNI_FALSE, JNI_TRUE};
use jni::{JNIEnv, JavaVM};
use serde_json::{Map, Value, json};
use ssh_mesh::sshc::SshClientListener;
use ssh_mesh::MeshListener;
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::sync::{Mutex, OnceLock};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::sync::mpsc::{UnboundedSender, unbounded_channel};

use crate::mesh_common::{MeshHandle, MeshStreamHandle};

const BRIDGE_HOST: &str = "dmesh-msg";
const LEGACY_BRIDGE_HOST: &str = "local";
const BRIDGE_PORT: u16 = 1;
static BRIDGE_SENDERS: OnceLock<Mutex<HashMap<u64, UnboundedSender<String>>>> = OnceLock::new();

fn bridge_senders() -> &'static Mutex<HashMap<u64, UnboundedSender<String>>> {
    BRIDGE_SENDERS.get_or_init(|| Mutex::new(HashMap::new()))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BridgeCommand {
    id: Option<String>,
    uri: String,
    data: BTreeMap<String, String>,
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
    let uri = obj
        .get("uri")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("missing uri"))?
        .to_string();
    let id = obj.get("id").map(json_value_to_string);
    let mut data = BTreeMap::new();

    if let Some(payload) = obj.get("data").and_then(Value::as_object) {
        insert_json_map(&mut data, payload);
    } else {
        insert_json_map(&mut data, obj);
        data.remove("id");
        data.remove("uri");
        data.remove("data");
    }

    Ok(BridgeCommand { id, uri, data })
}

fn insert_json_map(data: &mut BTreeMap<String, String>, obj: &Map<String, Value>) {
    for (k, v) in obj {
        data.insert(k.clone(), json_value_to_string(v));
    }
}

fn json_value_to_string(v: &Value) -> String {
    v.as_str().map(str::to_string).unwrap_or_else(|| v.to_string())
}

fn parse_bridge_human(line: &str) -> anyhow::Result<BridgeCommand> {
    let parts = split_command_line(line);
    if parts.is_empty() {
        anyhow::bail!("empty command");
    }

    let mut id = None;
    let mut data = BTreeMap::new();
    let mut uri = String::new();
    let mut saw_path = false;

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

        if !saw_path && part.starts_with('/') {
            uri.clear();
            uri.push_str(part);
            saw_path = true;
        } else {
            if uri.is_empty() {
                uri.push('/');
            } else if !uri.ends_with('/') {
                uri.push('/');
            }
            uri.push_str(part);
            saw_path = true;
        }
        i += 1;
    }

    if uri.is_empty() {
        anyhow::bail!("missing command path");
    }
    Ok(BridgeCommand { id, uri, data })
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
            let j_user = env.new_string(user_str).unwrap();
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
            let j_host = env.new_string(host_str).unwrap();

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
}

async fn handle_bridge_stream(
    jvm: Arc<JavaVM>,
    callback: GlobalRef,
    client_id: u64,
    mut stream: DuplexStream,
) {
    let (tx, mut rx) = unbounded_channel::<String>();
    bridge_senders().lock().unwrap().insert(client_id, tx);
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
                        let response = match parse_bridge_line(&line) {
                            Ok(cmd) => match dispatch_bridge_command(&jvm, &callback, client_id, &cmd) {
                                Ok(()) => json!({
                                    "id": cmd.id,
                                    "ok": true,
                                    "uri": cmd.uri,
                                }),
                                Err(e) => json!({
                                    "id": cmd.id,
                                    "ok": false,
                                    "error": e.to_string(),
                                }),
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

    bridge_senders().lock().unwrap().remove(&client_id);
}

fn dispatch_bridge_command(
    jvm: &JavaVM,
    callback: &GlobalRef,
    client_id: u64,
    cmd: &BridgeCommand,
) -> anyhow::Result<()> {
    let mut env = jvm.attach_current_thread()?;
    let j_id = env.new_string(cmd.id.as_deref().unwrap_or(""))?;
    let j_uri = env.new_string(&cmd.uri)?;
    let keys = cmd.data.keys().cloned().collect::<Vec<_>>();
    let values = cmd.data.values().cloned().collect::<Vec<_>>();
    let j_keys = new_string_array(&mut env, &keys)?;
    let j_values = new_string_array(&mut env, &values)?;
    env.call_method(
        callback,
        "onMessage",
        "(JLjava/lang/String;Ljava/lang/String;[Ljava/lang/String;[Ljava/lang/String;)V",
        &[
            (client_id as i64).into(),
            (&j_id).into(),
            (&j_uri).into(),
            (&j_keys).into(),
            (&j_values).into(),
        ],
    )?;
    Ok(())
}

fn new_string_array<'a>(
    env: &mut JNIEnv<'a>,
    values: &[String],
) -> anyhow::Result<JObjectArray<'a>> {
    let string_cls = env.find_class("java/lang/String")?;
    let out = env.new_object_array(values.len() as i32, string_cls, JObject::null())?;
    for (idx, value) in values.iter().enumerate() {
        let j_value = env.new_string(value)?;
        env.set_object_array_element(&out, idx as i32, j_value)?;
    }
    Ok(out)
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
            let j_host = env.new_string(host_str).unwrap();

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
    let handle = unsafe { &*(handle as *const MeshHandle) };
    let jvm = Arc::new(env.get_java_vm().unwrap());
    let callback_ref = env.new_global_ref(callback).unwrap();

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
        bridge_senders()
            .lock()
            .unwrap()
            .get(&(client_id as u64))
            .cloned()
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
    let base_dir_str: String = match env.get_string(&base_dir) {
        Ok(s) => s.into(),
        Err(_) => return 0,
    };

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
    let handle = unsafe { &*(handle as *const MeshHandle) };
    let host_str: String = env.get_string(&host).unwrap().into();
    let user_str: String = env.get_string(&user).unwrap().into();
    let key_str: String = env.get_string(&server_key).unwrap().into();

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
    let handle = unsafe { &*(handle as *const MeshHandle) };
    let cmd_str: String = env.get_string(&command).unwrap().into();

    match crate::mesh_common::mesh_exec(handle, conn_id as u64, &cmd_str) {
        Ok(stdout) => env.new_string(stdout).unwrap(),
        Err(e) => {
            log::error!("Exec failed: {}", e);
            env.new_string("").unwrap()
        }
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_github_costinm_dmeshnative_MeshNode_nativeGetPublicKey<'a>(
    env: JNIEnv<'a>,
    _class: JClass<'a>,
    handle: jlong,
) -> JString<'a> {
    let handle = unsafe { &*(handle as *const MeshHandle) };
    let pk_str = crate::mesh_common::mesh_get_public_key(handle);
    env.new_string(pk_str).unwrap()
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
    let handle = unsafe { &*(handle as *const MeshHandle) };
    let host_str: String = env.get_string(&host).unwrap().into();

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
    let handle = unsafe { &*(handle as *const MeshHandle) };
    let host_str: String = env.get_string(&remote_host).unwrap().into();

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
    let handle = unsafe { &*(handle as *const MeshHandle) };
    let host_str: String = env.get_string(&local_host).unwrap().into();

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
pub extern "system" fn Java_com_github_costinm_dmeshnative_MeshStream_nativeStreamRead(
    env: JNIEnv,
    _class: JClass,
    handle: jlong,
    buf: JByteArray,
) -> jint {
    let handle = unsafe { &mut *(handle as *mut MeshStreamHandle) };
    let mut data = vec![0u8; env.get_array_length(&buf).unwrap() as usize];

    match crate::mesh_common::stream_read(handle, &mut data) {
        Ok(n) => {
            let byte_data: Vec<i8> = data[..n].iter().map(|&b| b as i8).collect();
            env.set_byte_array_region(&buf, 0, &byte_data).unwrap();
            n as jint
        }
        Err(_) => -1,
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_github_costinm_dmeshnative_MeshStream_nativeStreamWrite(
    env: JNIEnv,
    _class: JClass,
    handle: jlong,
    data: JByteArray,
) {
    let handle = unsafe { &mut *(handle as *mut MeshStreamHandle) };
    let bytes = env.convert_byte_array(&data).unwrap();

    let _ = crate::mesh_common::stream_write(handle, &bytes);
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
    mut _env: JNIEnv,
    _class: JClass,
    fd: jint,
) -> jlong {
    log::info!("nativeTestTunFd called with fd: {}", fd);

    match unsafe { tun_rs::AsyncDevice::from_fd(fd) } {
        Ok(_device) => fd as jlong,
        Err(e) => {
            log::error!("Failed to create AsyncDevice from Android TUN fd: {}", e);
            -1
        }
    }
}

#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
pub extern "C" fn Java_costinm_dmesh_MeshNode_nativeCreateTun(
    env: JNIEnv,
    class: JClass,
    fd: jint,
) -> jlong {
    Java_com_github_costinm_dmeshnative_MeshNode_nativeTestTunFd(env, class, fd)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_json_command() {
        let cmd = parse_bridge_line(
            r#"{"id":"j1","uri":"/wifi/scan","data":{"reason":"json","n":2}}"#,
        )
        .unwrap();
        assert_eq!(cmd.id.as_deref(), Some("j1"));
        assert_eq!(cmd.uri, "/wifi/scan");
        assert_eq!(cmd.data.get("reason").unwrap(), "json");
        assert_eq!(cmd.data.get("n").unwrap(), "2");
    }

    #[test]
    fn parses_human_key_value_command() {
        let cmd = parse_bridge_line(r#"wifi scan id=h1 reason="human value""#).unwrap();
        assert_eq!(cmd.id.as_deref(), Some("h1"));
        assert_eq!(cmd.uri, "/wifi/scan");
        assert_eq!(cmd.data.get("reason").unwrap(), "human value");
    }

    #[test]
    fn parses_human_long_options_command() {
        let cmd = parse_bridge_line("/wifi/scan --id h2 --reason human --enabled").unwrap();
        assert_eq!(cmd.id.as_deref(), Some("h2"));
        assert_eq!(cmd.uri, "/wifi/scan");
        assert_eq!(cmd.data.get("reason").unwrap(), "human");
        assert_eq!(cmd.data.get("enabled").unwrap(), "1");
    }
}
