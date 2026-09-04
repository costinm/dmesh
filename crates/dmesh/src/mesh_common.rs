//! Common mesh node handle and operations shared by the JNI wrapper.
//!
//! The JNI wrapper (`mesh_jni.rs`) delegates to these functions for the actual
//! mesh logic. JNI-specific marshalling stays in the wrapper module.

use dmesh_store::StoreService;
use mesh::{
    tagged::{NameOrTag, TaggedRecord},
    wire::TaggedRecordHandler,
};
#[cfg(target_os = "android")]
use p256::SecretKey;
#[cfg(target_os = "android")]
use p256::ecdsa::signature::Signer;
#[cfg(target_os = "android")]
use p256::ecdsa::{Signature, SigningKey};
#[cfg(target_os = "android")]
use p256::elliptic_curve::sec1::ToSec1Point;
use serde_json::json;
#[cfg(target_os = "android")]
use sha2::{Digest, Sha256};
use ssh_mesh::sshc::SshClientManager;
use ssh_mesh::{MeshNode, MeshNodeConfig, run_ssh_server};
#[cfg(target_os = "android")]
use std::collections::BTreeSet;
#[cfg(target_os = "android")]
use std::ffi::CStr;
use std::net::SocketAddr;
#[cfg(target_os = "android")]
use std::net::{Ipv6Addr, SocketAddrV6};
#[cfg(target_os = "android")]
use std::os::fd::FromRawFd;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::runtime::Runtime;

/// Opaque handle for a running mesh node instance.
///
/// Owns the tokio runtime, the `MeshNode`, the SSH client manager,
/// and join handles for the SSH, HTTP, and shared UDP service tasks.
pub struct MeshHandle {
    pub node: Arc<MeshNode>,
    pub client_manager: Arc<SshClientManager>,
    pub runtime: Runtime,
    pub ssh_server_handle: Option<tokio::task::JoinHandle<()>>,
    pub http_server_handle: Option<tokio::task::JoinHandle<()>>,
    pub udp_server_handle: Option<tokio::task::JoinHandle<()>>,
    pub announce_server_handle: Option<tokio::task::JoinHandle<()>>,
    /// Platform network transitions request an immediate announce without
    /// changing the five-minute periodic cadence.
    pub announce_trigger: Option<tokio::sync::mpsc::UnboundedSender<()>>,
}

/// Opaque handle for a bidirectional stream (channel).
pub struct MeshStreamHandle {
    pub stream: DuplexStream,
    pub runtime_handle: tokio::runtime::Handle,
}

/// DMesh's Android registration for the generic ssh-mesh service registry.
/// This is an in-process adapter only: request execution is a direct Rust
/// call into the established Rust control dispatcher.  The only platform
/// input is the private data-directory path for the portable settings store.
#[derive(Clone)]
struct AndroidControlHandler {
    settings_path: PathBuf,
}

/// Convert a shared numeric stream identity using the dmesh-server catalog.
///
/// Android owns neither numeric aliases nor a second service list: it only
/// projects the common dotted service name into the existing Rust platform
/// dispatcher. Unknown numeric records remain rejected by that dispatcher.
fn normalize_android_control_record(mut record: TaggedRecord) -> TaggedRecord {
    if let (NameOrTag::Tag(component), NameOrTag::Tag(method)) = (&record.component, &record.method)
        && let Some(service) =
            dmesh_server::service_catalog::stream_service(u64::from(*component), u64::from(*method))
    {
        if let Some((component, method)) = service.name.rsplit_once('.') {
            record.component = NameOrTag::Name(component.to_owned());
            record.method = NameOrTag::Name(method.to_owned());
        } else {
            // Bare catalog names (`status`, `services`, `metrics`, ...)
            // are still canonical stream identities. Keep the empty
            // component explicit so Android does not reject the numeric
            // record merely because its presentation name has no dot.
            record.component = NameOrTag::Name(String::new());
            record.method = NameOrTag::Name(service.name.to_owned());
        }
    }
    // Catalog/HTTP presentation may split a dotted handler at its final dot
    // (`radio.nan.followups` -> component `radio.nan`, method `followups`).
    // The Android Rust terminal uses the same component/method form as the
    // shared tagged dispatcher (`radio`, `nan.followups`). Normalize that
    // grammar once here rather than adding Android-only aliases per service.
    if let Some((base, method)) = match (&record.component, &record.method) {
        (NameOrTag::Name(component), NameOrTag::Name(method)) => component
            .rsplit_once('.')
            .map(|(base, prefix)| (base.to_owned(), format!("{prefix}.{method}"))),
        _ => None,
    }
    {
        record.component = NameOrTag::Name(base);
        record.method = NameOrTag::Name(method);
    }
    record
}

fn android_setting_field(record: &TaggedRecord, tag: u32, name: &str) -> anyhow::Result<String> {
    let value = record
        .env
        .get(&NameOrTag::Tag(tag))
        .or_else(|| record.env.get(&NameOrTag::Name(name.to_owned())))
        .ok_or_else(|| anyhow::anyhow!("settings.{name} requires `{name}`"))?;
    value
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| anyhow::anyhow!("settings.{name} field `{name}` must be text"))
}

fn handle_android_settings_record(
    record: &TaggedRecord,
    settings_path: &std::path::Path,
) -> anyhow::Result<Option<TaggedRecord>> {
    let (NameOrTag::Name(component), NameOrTag::Name(method)) = (&record.component, &record.method)
    else {
        return Ok(None);
    };
    if component != "settings" {
        return Ok(None);
    }
    if !record.params.is_empty() || record.data.is_some() {
        anyhow::bail!("settings accepts named text fields only")
    }
    let id = record
        .id
        .clone()
        .ok_or_else(|| anyhow::anyhow!("settings stream request requires id"))?;
    let mut store = dmesh_server::settings::FileSettings::new(settings_path, "android");
    let mut settings = dmesh_server::settings::SettingsHandler::new(&mut store);
    let result = match method.as_str() {
        "get" => {
            let key = android_setting_field(record, 1, "key")?;
            json!({
                "key": key,
                "value": settings.get(&key).map_err(anyhow::Error::msg)?
            })
        }
        "set" => {
            let key = android_setting_field(record, 1, "key")?;
            let value = android_setting_field(record, 2, "value")?;
            settings.set(&key, &value).map_err(anyhow::Error::msg)?;
            json!({})
        }
        "list" => {
            if !record.env.is_empty() {
                anyhow::bail!("settings.list does not accept fields")
            }
            let entries = settings
                .list()
                .map_err(anyhow::Error::msg)?
                .into_iter()
                .map(|(key, value)| json!({"key": key, "value": value}))
                .collect::<Vec<_>>();
            json!({"entries": entries})
        }
        _ => return Ok(None),
    };
    Ok(Some(mesh::wire::response_ok(id, result)))
}

fn handle_android_control_record(
    record: TaggedRecord,
    settings_path: &std::path::Path,
) -> anyhow::Result<Option<TaggedRecord>> {
    let record = normalize_android_control_record(record);
    if let Some(response) = handle_android_settings_record(&record, settings_path)? {
        return Ok(Some(response));
    }
    crate::mesh_jni::handle_tagged_control_record(record)
}

/// Identity material used only to produce a signed, authenticated discovery
/// record. QUIC endpoint authentication remains independent of this presence
/// signature; the public-key DER is the stable `to` selector used by the
/// discovery-to-QUIC bridge.
#[cfg(target_os = "android")]
struct AndroidAnnounceIdentity {
    public_key: Vec<u8>,
    signing_key: SigningKey,
    /// Android's private mesh data directory hosts the same restricted
    /// key=value settings file used by Linux; Java never parses it.
    settings_path: PathBuf,
}

#[cfg(target_os = "android")]
fn configured_device_name(settings_path: &std::path::Path) -> Option<String> {
    let mut store = dmesh_server::settings::FileSettings::new(settings_path, "android");
    dmesh_server::settings::SettingsHandler::new(&mut store)
        .get("name")
        .ok()
        .filter(|name| !name.is_empty())
}

#[cfg(target_os = "android")]
fn android_signed_discovery(
    identity: &AndroidAnnounceIdentity,
    uptime_secs: u64,
) -> Option<dmesh_server::announce::Announce> {
    let digest = Sha256::digest(&identity.public_key);
    let mut device_id = [0; 16];
    let device_id_len = device_id.len();
    device_id.copy_from_slice(&digest[..device_id_len]);
    let mut announce = dmesh_server::announce::Announce::discovery(
        device_id,
        device_id.len() as u8,
        u32::try_from(uptime_secs).unwrap_or(u32::MAX),
    );
    announce.set_probe_descriptor(
        dmesh_server::announce::DEVICE_CLASS_ANDROID,
        dmesh_server::probe::PROBE_CAP_NAN | dmesh_server::probe::PROBE_CAP_UDP6,
    );
    // This is a directed reply, not a multicast send.  The generic UDP
    // responder currently receives the peer tuple but not the local ingress
    // interface, so picking the first enabled link-local address here would
    // advertise (for example) a Wi-Fi Direct address in a reply received on
    // infrastructure Wi-Fi.  That signed-but-unusable endpoint is worse than
    // omitting it: the response source tuple is already the checked path.
    // `send_android_announce` below has the precise egress interface and is
    // the only Android path that advertises a UDP6 address.
    if let Some(name) = configured_device_name(&identity.settings_path) {
        let _ = announce.set_device_name(&name);
    }
    if let Ok(domain) = std::env::var("DMESH_DISCOVERY_DOMAIN") {
        let domain = domain.trim();
        if !domain.is_empty() && domain.len() <= dmesh_server::announce::MAX_DEVICE_DOMAIN {
            let _ = announce.set_device_domain(domain);
        }
    }
    if !announce.set_public_key(&identity.public_key) {
        log::error!("Android signed discovery public key exceeds announce bound");
        return None;
    }
    let mut signing_wire = [0u8; quic_lite::DEFAULT_MAX_DATAGRAM_SIZE];
    let Some(signing_used) = dmesh_server::announce::signing_bytes(announce, &mut signing_wire)
    else {
        log::error!("Android signed discovery signing bytes exceed bound");
        return None;
    };
    let signature: Signature = identity.signing_key.sign(&signing_wire[..signing_used]);
    if !announce.set_signature(signature.to_bytes().as_ref()) {
        log::error!("Android signed discovery signature exceeds announce bound");
        return None;
    }
    Some(announce)
}

impl dmesh_server::udp::TaggedApplicationHandler for AndroidControlHandler {
    fn handle_tagged<'a>(
        &'a self,
        _context: dmesh_server::udp::TaggedStreamContext,
        request: Vec<u8>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Option<Vec<u8>>> + Send + 'a>> {
        Box::pin(async move {
            let record = match mesh::cbor::decode_record(&request) {
                Ok(record) => record,
                Err(error) => {
                    log::warn!("Android QUIC tagged request decode failed: {error}");
                    return None;
                }
            };
            let request_id = record.id.clone()?;
            let response = match handle_android_control_record(record, &self.settings_path) {
                Ok(Some(response)) => response,
                Ok(None) => return None,
                Err(error) => {
                    log::warn!("Android QUIC tagged request rejected: {error}");
                    mesh::wire::response_error(
                        request_id,
                        serde_json::json!({"error": error.to_string()}),
                    )
                }
            };
            match mesh::cbor::encode_record(&response) {
                Ok(wire) => Some(wire),
                Err(error) => {
                    log::warn!("Android QUIC tagged response encoding failed: {error}");
                    None
                }
            }
        })
    }
}

fn android_http_catalog() -> serde_json::Value {
    // Deliberately small until each mutating platform action implements the
    // common dmesh-server tagged control schema and reports capabilities.
    let mut catalog = json!({"tools": [
        {"name":"settings.get","description":"Read one portable Rust-owned mesh setting from Android private storage.","x-ui-visibility":"masked","inputSchema":{"type":"object","properties":{"key":{"type":"string"}},"required":["key"],"additionalProperties":false}},
        {"name":"settings.set","description":"Write one portable Rust-owned mesh setting to Android private storage.","x-ui-visibility":"masked","inputSchema":{"type":"object","properties":{"key":{"type":"string"},"value":{"type":"string"}},"required":["key","value"],"additionalProperties":false}},
        {"name":"settings.list","description":"List populated portable Rust-owned mesh settings.","x-ui-visibility":"masked","inputSchema":{"type":"object","properties":{},"additionalProperties":false}},
        {"name":"status","description":"Read the bounded common mesh endpoint status.","x-ui-visibility":"masked","inputSchema":{"type":"object","properties":{},"additionalProperties":false}},
        {"name":"radio.status_text","description":"Read the Rust-owned mesh status summary.","x-ui-visibility":"masked","inputSchema":{"type":"object","properties":{},"additionalProperties":false}},
        {"name":"discovery.nodes","title":"Nodes","description":"Read the bounded cross-bearer node inventory, including physical devices and future control-plane nodes.","x-ui-visibility":"default","inputSchema":{"type":"object","properties":{},"additionalProperties":false}},
        {"name":"discovery.status","title":"This node","description":"Read this node's currently announced local network and capability facts.","x-ui-visibility":"default","inputSchema":{"type":"object","properties":{},"additionalProperties":false}},
        {"name":"telemetry.nan_status","description":"Read local Wi-Fi Aware attach and publish state; peer inventory is in discovery.nodes.","x-ui-visibility":"masked","inputSchema":{"type":"object","properties":{},"additionalProperties":false}},
        {"name":"telemetry.now_metrics","description":"Read local ESP-NOW runtime counters when supported.","x-ui-visibility":"masked","inputSchema":{"type":"object","properties":{},"additionalProperties":false}},
        {"name":"telemetry.nan_metrics","description":"Read local Wi-Fi Aware event and Follow-up counters.","x-ui-visibility":"masked","inputSchema":{"type":"object","properties":{},"additionalProperties":false}},
        {"name":"telemetry.udp6_metrics","description":"Read local raw IPv6, UDP, and NDP counters when supported.","x-ui-visibility":"masked","inputSchema":{"type":"object","properties":{},"additionalProperties":false}},
        {"name":"telemetry.wifi_link_metrics","description":"Read common optional per-peer Wi-Fi link observations when supported.","x-ui-visibility":"masked","inputSchema":{"type":"object","properties":{},"additionalProperties":false}},
        {"name":"radio.nan.followups","description":"Read bounded receiver-proven NAN follow-up receipts.","x-ui-visibility":"masked","inputSchema":{"type":"object","properties":{},"additionalProperties":false}},
        {"name":"radio.nan.events","description":"Read bounded Android Wi-Fi Aware callback events.","x-ui-visibility":"masked","inputSchema":{"type":"object","properties":{},"additionalProperties":false}},
        {"name":"radio.power.state","description":"Read bounded power and memory observations.","x-ui-visibility":"masked","inputSchema":{"type":"object","properties":{},"additionalProperties":false}}
    ]});

    // The same catalog contract drives fleet checks on Linux and firmware.
    // Mark only bounded reads that the Android Rust terminal implements; a
    // missing capability remains visible rather than being called as a
    // mutating or platform-private operation.
    let Some(tools) = catalog.get_mut("tools").and_then(serde_json::Value::as_array_mut) else {
        return catalog;
    };
    for tool in tools {
        let Some(name) = tool.get("name").and_then(serde_json::Value::as_str) else {
            continue;
        };
        let request = match name {
            "settings.get" => Some(json!({"key":"name"})),
            "settings.list"
            | "status"
            | "radio.status_text"
            | "discovery.nodes"
            | "discovery.status"
            | "telemetry.nan_status"
            | "telemetry.now_metrics"
            | "telemetry.nan_metrics"
            | "telemetry.udp6_metrics"
            | "telemetry.wifi_link_metrics"
            | "radio.nan.followups"
            | "radio.nan.events"
            | "radio.power.state" => Some(json!({})),
            _ => None,
        };
        if let Some(request) = request {
            tool["x-check-all"] = request;
            tool["x-check-all-platforms"] = json!(["android"]);
        }
    }
    catalog
}

#[async_trait::async_trait]
impl TaggedRecordHandler for AndroidControlHandler {
    async fn handle_record(&self, record: TaggedRecord) -> anyhow::Result<Option<TaggedRecord>> {
        handle_android_control_record(record, &self.settings_path)
    }
}

/// Create and start a mesh node.
///
/// Initialises the node from `base_dir`, spawns SSH server (and optionally
/// HTTP server), and returns a handle that can be used for subsequent
/// operations.
pub fn start_mesh(
    base_dir: &str,
    ssh_port: i32,
    http_port: i32,
    #[cfg_attr(not(target_os = "android"), allow(unused_variables))] android_udp_fd: Option<i32>,
) -> Result<MeshHandle, anyhow::Error> {
    let base_path = PathBuf::from(base_dir);
    let _ = std::fs::create_dir_all(&base_path);

    let runtime = Runtime::new()?;

    let mut cfg = MeshNodeConfig::default();
    cfg.base_dir = Some(base_path.clone());
    cfg.ssh_port = if ssh_port > 0 {
        Some(ssh_port as u16)
    } else {
        Some(0)
    };
    cfg.http_port = if http_port > 0 {
        Some(http_port as u16)
    } else {
        None
    };

    let node = Arc::new(MeshNode::new(Some(base_path.clone()), Some(cfg)));

    let client_manager = Arc::new(SshClientManager::new(
        node.private_key().clone(),
        (*node.ca_keys).clone(),
        Some(base_path.join("config")),
        None,
    ));

    // Initialize dmesh-store service
    let db_path = base_path.join("dmesh-store.db");
    runtime.block_on(async {
        match StoreService::new(db_path.to_str().unwrap()).await {
            Ok(svc) => {
                let sender = svc.sender();
                crate::mesh_jni::init_store_sender(sender);
                tokio::spawn(async move {
                    svc.run().await;
                });
            }
            Err(e) => {
                log::warn!("Failed to initialize dmesh-store: {}", e);
            }
        }
    });

    // Spawn SSH server
    let node_clone = node.clone();
    let ssh_server_handle = runtime.spawn(async move {
        let config = node_clone.get_config();
        let port = node_clone.ssh_port();
        if let Err(e) = run_ssh_server(port, config, (*node_clone).clone()).await {
            log::error!("SSH server failed: {}", e);
        }
    });

    // Spawn HTTP server if port configured
    let mut http_server_handle = None;
    if let Some(h_port) = node.http_port() {
        let config = dmesh_server::http::HttpConfig {
            bind: SocketAddr::from(([127, 0, 0, 1], h_port)),
            node: node.clone(),
            client_manager: client_manager.clone(),
            service: dmesh_server::http::HttpService {
                name: "android".to_owned(),
                backend: ssh_mesh::mesh_rest::MeshServiceBackend::Direct(Arc::new(
                    AndroidControlHandler {
                        settings_path: base_path.join("settings.conf"),
                    },
                )),
                catalog: Some(android_http_catalog()),
            },
            web_root: std::env::var_os("DMESH_HTTP_WEB_DIR").map(std::path::PathBuf::from),
        };
        http_server_handle = Some(runtime.spawn(async move {
            if let Err(error) = dmesh_server::http::serve(config).await {
                log::error!("HTTP server failed on port {}: {}", h_port, error);
            }
        }));
    }

    // Android participates in the same bearer-neutral service surface as
    // lmesh-wifi and firmware. Bind IPv6 explicitly: link-local and NAN
    // data-path tests use scoped IPv6 addresses, while the shared registry
    // supplies status, handlers, and probe without an Android-only replacement.
    // Keep this Android-only: host MeshNode users must not unexpectedly claim
    // the stable Wi-Fi UDP port merely by constructing a node.
    #[cfg(target_os = "android")]
    let android_announce_identity = {
        let ecdsa_key = node
            .private_key()
            .key_data()
            .ecdsa()
            .ok_or_else(|| anyhow::anyhow!("Android mesh identity is not ECDSA P-256"))?;
        let secret_key = SecretKey::from_slice(ecdsa_key.private_key_bytes())?;
        let public_key = secret_key
            .public_key()
            .to_sec1_point(true)
            .as_bytes()
            .to_vec();
        Arc::new(AndroidAnnounceIdentity {
            public_key,
            signing_key: SigningKey::from(secret_key),
            settings_path: base_path.join("settings.conf"),
        })
    };
    // Android has two IPv6 UDP ports: the normal QUIC listener and multicast
    // receive-only 5227.  Keep the normal socket in Rust so QUIC streams,
    // directed checks, and multicast sends all share its configured source
    // port; Java supplies only platform network lifecycle facts.
    #[cfg(target_os = "android")]
    let android_udp_socket = runtime.block_on(async move {
        // Construct through Tokio's Android reactor.  Converting a std UDP
        // descriptor here is safe only when Android supplied a nonblocking,
        // network-marked FD. Otherwise create the normal listener through
        // Tokio. This is never the multicast receiver.
        match android_udp_fd {
            Some(fd) => {
                let socket = unsafe { std::net::UdpSocket::from_raw_fd(fd) };
                socket.set_nonblocking(true)?;
                tokio::net::UdpSocket::from_std(socket).map(Arc::new)
            }
            None => tokio::net::UdpSocket::bind((
                Ipv6Addr::UNSPECIFIED,
                dmesh_server::udp::STABLE_WIFI_UDP_PORT,
            ))
            .await
            .map(Arc::new),
        }
    })?;
    #[cfg(target_os = "android")]
    let udp_server_handle = {
        // Android keeps the provisioned control-plane root in its app-private
        // data directory. Only a labeled quic-lite reset-key branch is handed
        // to the UDP association owner; the common settings.conf remains
        // text-only and cannot expose this secret.
        let stateless_reset_key =
            match dmesh_server::settings::stateless_reset_key_from_private_file(
                base_path.join("device-secret.bin"),
            ) {
                Ok(key) => key,
                Err(error) => {
                    log::warn!("Android UDP reset secret unavailable: {error}");
                    None
                }
            };
        let application_handler: Arc<dyn dmesh_server::udp::TaggedStreamHandler> = Arc::new(
            dmesh_server::udp::CanonicalTaggedStreamHandler::new(Arc::new(AndroidControlHandler {
                settings_path: base_path.join("settings.conf"),
            })),
        );
        let discovery_handler: Arc<dyn dmesh_server::udp::TaggedStreamHandler> =
            Arc::new(dmesh_server::direct::SignedDiscoveryResponder::new({
                let identity = android_announce_identity.clone();
                let started = std::time::Instant::now();
                Arc::new(move || android_signed_discovery(&identity, started.elapsed().as_secs()))
            }));
        let shared_handler: Arc<dyn dmesh_server::udp::TaggedStreamHandler> =
            Arc::new(dmesh_server::udp::FallbackTaggedStreamHandler::new(
                discovery_handler,
                application_handler,
            ));
        let udp_config = dmesh_server::udp::UdpConfig {
            bind: SocketAddr::from((
                Ipv6Addr::UNSPECIFIED,
                dmesh_server::udp::STABLE_WIFI_UDP_PORT,
            )),
            socket: Some(android_udp_socket.clone()),
            artifact_root: base_path.clone(),
            stateless_reset_key,
            tagged_handler: Some(shared_handler.clone()),
            direct_handler: Some(shared_handler),
            ..dmesh_server::udp::UdpConfig::default()
        };
        Some(runtime.spawn(async move {
            if let Err(error) = dmesh_server::udp::run(udp_config).await {
                log::error!("Android UDP service failed: {error}");
            }
        }))
    };
    #[cfg(not(target_os = "android"))]
    let udp_server_handle = None;

    #[cfg(target_os = "android")]
    let (announce_server_handle, announce_trigger) = {
        let (trigger, receiver) = tokio::sync::mpsc::unbounded_channel();
        (
            Some(runtime.spawn(android_announce_loop(
                android_announce_identity,
                receiver,
                android_udp_socket,
            ))),
            Some(trigger),
        )
    };
    #[cfg(not(target_os = "android"))]
    let (announce_server_handle, announce_trigger) = (None, None);

    Ok(MeshHandle {
        node,
        client_manager,
        runtime,
        ssh_server_handle: Some(ssh_server_handle),
        http_server_handle,
        udp_server_handle,
        announce_server_handle,
        announce_trigger,
    })
}

/// Ask the Android announce worker to join/send on a newly available local
/// link, such as a P2P group. The message contains no radio policy or payload.
pub fn trigger_announce(handle: &MeshHandle) -> bool {
    handle
        .announce_trigger
        .as_ref()
        .is_some_and(|trigger| trigger.send(()).is_ok())
}

/// Stop a mesh node, aborting all server tasks and shutting down the runtime.
pub fn stop_mesh(handle: MeshHandle) {
    if let Some(h) = handle.ssh_server_handle {
        h.abort();
    }
    if let Some(h) = handle.http_server_handle {
        h.abort();
    }
    if let Some(h) = handle.udp_server_handle {
        h.abort();
    }
    if let Some(h) = handle.announce_server_handle {
        h.abort();
    }
    handle.runtime.shutdown_background();
}

/// Android receives local-link multicast on 5227. Its normal QUIC socket is
/// supplied separately and is the source for all multicast sends.
#[cfg(target_os = "android")]
async fn android_announce_loop(
    identity: Arc<AndroidAnnounceIdentity>,
    mut trigger: tokio::sync::mpsc::UnboundedReceiver<()>,
    egress_socket: Arc<tokio::net::UdpSocket>,
) {
    const PORT: u16 = 5227;
    let group = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x5227);
    let socket = match tokio::net::UdpSocket::bind((Ipv6Addr::UNSPECIFIED, PORT)).await {
        Ok(socket) => socket,
        Err(error) => {
            log::error!("Android announce UDP bind failed: {error}");
            return;
        }
    };
    let digest = Sha256::digest(&identity.public_key);
    let mut id = [0; 16];
    id.copy_from_slice(&digest[..16]);
    let take = id.len();
    let started = tokio::time::Instant::now();
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(5 * 60));
    let mut receive = [0u8; 256];
    let mut joined_interfaces = BTreeSet::new();
    loop {
        tokio::select! {
            _ = interval.tick() => {
                let _ = send_android_announce(&socket, &egress_socket, group, PORT, &mut joined_interfaces,
                    id, take as u8, started.elapsed().as_secs(), &identity).await;
            }
            Some(()) = trigger.recv() => {
                // A P2P group may appear long after service boot. Join its
                // scoped multicast interface and emit the same bounded record
                // now, rather than waiting for the periodic interval.
                let _ = send_android_announce(&socket, &egress_socket, group, PORT, &mut joined_interfaces,
                    id, take as u8, started.elapsed().as_secs(), &identity).await;
            }
            received = socket.recv_from(&mut receive) => match received {
                Ok((len, sender)) => {
                    let Some(payload) = dmesh_server::direct::ConnectionlessMessage::decode(
                        &receive[..len],
                    ) else {
                        continue;
                    };
                    if let Some(announce) = dmesh_server::announce::decode_announce(payload)
                        && announce.device_id() != &id[..take]
                    {
                        crate::mesh_jni::observe_announce(
                            announce,
                            sender.to_string(),
                            "udp_multicast",
                            &receive[..len],
                        );
                    }
                }
                Err(error) => {
                    log::warn!("Android announce UDP receive failed: {error}");
                }
            },
        }
    }
}

#[cfg(target_os = "android")]
async fn send_android_announce(
    multicast_receiver: &tokio::net::UdpSocket,
    egress_socket: &tokio::net::UdpSocket,
    group: Ipv6Addr,
    port: u16,
    joined_interfaces: &mut BTreeSet<u32>,
    id: [u8; 16],
    id_len: u8,
    uptime_secs: u64,
    identity: &AndroidAnnounceIdentity,
) -> bool {
    let mut announce = dmesh_server::announce::Announce::discovery(
        id,
        id_len,
        u32::try_from(uptime_secs).unwrap_or(u32::MAX),
    );
    announce.set_probe_descriptor(
        dmesh_server::announce::DEVICE_CLASS_ANDROID,
        dmesh_server::probe::PROBE_CAP_NAN | dmesh_server::probe::PROBE_CAP_UDP6,
    );
    if let Some(name) = configured_device_name(&identity.settings_path) {
        let _ = announce.set_device_name(&name);
    }
    if let Ok(domain) = std::env::var("DMESH_DISCOVERY_DOMAIN") {
        let domain = domain.trim();
        if !domain.is_empty() && domain.len() <= dmesh_server::announce::MAX_DEVICE_DOMAIN {
            let _ = announce.set_device_domain(domain);
        }
    }
    let interfaces = multicast_interfaces();
    for interface in &interfaces {
        if joined_interfaces.insert(interface.index)
            && let Err(error) = multicast_receiver.join_multicast_v6(&group, interface.index)
        {
            log::warn!(
                "Android announce multicast join failed on {} ({}): {error}",
                interface.name,
                interface.index,
            );
        }
    }
    let mut sent = false;
    for interface in interfaces {
        // One bounded common record is sent on each live multicast interface.
        // Its advertised UDP6 endpoint must be the link-local address for the
        // exact interface carrying this datagram; a peer supplies its own
        // scope when replying. Do not leak a first/random interface address.
        let mut per_interface = announce;
        if let Some(address) = interface.link_local {
            per_interface.set_sta_link_local_v6(address.octets());
            // Advertise only the device-local UDP6 address and listener port.
            // The receiving node retains the ingress interface/scope; an
            // Android sender must not serialize its interface name or SSID.
            per_interface.set_udp_port(dmesh_server::udp::STABLE_WIFI_UDP_PORT);
            per_interface.set_udp_link_local_v6(address.octets());
        }
        if !per_interface.set_public_key(&identity.public_key) {
            log::error!("Android announce public key exceeds common bound");
            continue;
        }
        let mut signing_wire = [0u8; quic_lite::DEFAULT_MAX_DATAGRAM_SIZE];
        let Some(signing_used) =
            dmesh_server::announce::signing_bytes(per_interface, &mut signing_wire)
        else {
            log::error!("Android announce signing record exceeded bound");
            continue;
        };
        let signature: Signature = identity.signing_key.sign(&signing_wire[..signing_used]);
        if !per_interface.set_signature(signature.to_bytes().as_ref()) {
            log::error!("Android announce signature has invalid length");
            continue;
        }
        let mut announce_wire = [0u8; quic_lite::DEFAULT_MAX_DATAGRAM_SIZE];
        let Some(announce_used) = dmesh_server::announce::encode(per_interface, &mut announce_wire)
        else {
            log::warn!(
                "Android announce encoding exceeded bound on {}",
                interface.name
            );
            continue;
        };
        let mut wire = [0u8; 448];
        let Some(used) = dmesh_server::direct::ConnectionlessMessage::encode(
            &announce_wire[..announce_used],
            &mut wire,
        ) else {
            log::warn!(
                "Android announce direct envelope exceeded bound on {}",
                interface.name
            );
            continue;
        };
        let destination = SocketAddr::V6(SocketAddrV6::new(group, port, 0, interface.index));
        match egress_socket.send_to(&wire[..used], destination).await {
            Ok(_) => {
                sent = true;
                log::debug!(
                    "Android announce UDP6 submitted on {} ({}) addr={:?}",
                    interface.name,
                    interface.index,
                    interface.link_local,
                );
            }
            Err(error) => log::warn!(
                "Android announce multicast send failed on {} ({}): {error}",
                interface.name,
                interface.index,
            ),
        }
    }
    sent
}

/// Return each enabled, non-loopback IPv6 interface index. Android's
/// link-local multicast routes require this scope; `0` is not enough to select
/// Wi-Fi and would make a service-start boot announce disappear before a
/// network becomes available.
#[cfg(target_os = "android")]
struct MulticastInterface {
    index: u32,
    name: String,
    link_local: Option<Ipv6Addr>,
}

#[cfg(target_os = "android")]
fn multicast_interfaces() -> Vec<MulticastInterface> {
    let mut interfaces = std::collections::BTreeMap::<u32, MulticastInterface>::new();
    unsafe {
        let mut head = std::ptr::null_mut();
        if libc::getifaddrs(&mut head) != 0 {
            log::warn!(
                "Android announce could not enumerate interfaces: {}",
                std::io::Error::last_os_error()
            );
            return Vec::new();
        }
        let mut current = head;
        while !current.is_null() {
            let entry = &*current;
            let enabled = entry.ifa_flags & (libc::IFF_UP as u32) != 0;
            let loopback = entry.ifa_flags & (libc::IFF_LOOPBACK as u32) != 0;
            let multicast = entry.ifa_flags & (libc::IFF_MULTICAST as u32) != 0;
            if enabled
                && !loopback
                && multicast
                && !entry.ifa_addr.is_null()
                && (*entry.ifa_addr).sa_family as i32 == libc::AF_INET6
            {
                let index = libc::if_nametoindex(CStr::from_ptr(entry.ifa_name).as_ptr());
                if index != 0 {
                    let name = CStr::from_ptr(entry.ifa_name)
                        .to_string_lossy()
                        .into_owned();
                    let address = Ipv6Addr::from(
                        (*(entry.ifa_addr as *const libc::sockaddr_in6))
                            .sin6_addr
                            .s6_addr,
                    );
                    let interface = interfaces
                        .entry(index)
                        .or_insert_with(|| MulticastInterface {
                            index,
                            name,
                            link_local: None,
                        });
                    if address.is_unicast_link_local() {
                        interface.link_local = Some(address);
                    }
                }
            }
            current = entry.ifa_next;
        }
        libc::freeifaddrs(head);
    }
    interfaces.into_values().collect()
}

/// Connect to a remote SSH server.
pub fn mesh_connect(
    handle: &MeshHandle,
    host: &str,
    port: u16,
    user: &str,
    server_key: &str,
) -> Result<u64, anyhow::Error> {
    handle.runtime.block_on(async {
        handle
            .client_manager
            .connect(host, port, user, server_key)
            .await
    })
}

/// Execute a command on an existing SSH connection.
pub fn mesh_exec(
    handle: &MeshHandle,
    conn_id: u64,
    command: &str,
) -> Result<String, anyhow::Error> {
    let res = handle
        .runtime
        .block_on(async { handle.client_manager.exec(conn_id, command).await })?;
    Ok(res.stdout)
}

/// Open a bidirectional stream to a remote host through an SSH connection.
pub fn mesh_open_stream(
    handle: &MeshHandle,
    conn_id: u64,
    host: &str,
    port: u16,
) -> Result<MeshStreamHandle, anyhow::Error> {
    let stream = handle
        .runtime
        .block_on(async { handle.client_manager.open_stream(conn_id, host, port).await })?;
    Ok(MeshStreamHandle {
        stream,
        runtime_handle: handle.runtime.handle().clone(),
    })
}

/// Get the node's public key in OpenSSH format.
pub fn mesh_get_public_key(handle: &MeshHandle) -> String {
    handle
        .node
        .private_key()
        .public_key()
        .to_openssh()
        .unwrap_or_default()
}

/// Add a local port forward on an SSH connection.
pub fn mesh_add_local_forward(
    handle: &MeshHandle,
    conn_id: u64,
    local_port: u16,
    remote_host: &str,
    remote_port: u16,
) -> Result<(), anyhow::Error> {
    handle.runtime.block_on(async {
        handle
            .client_manager
            .add_local_forward(conn_id, local_port, remote_host, remote_port)
            .await
    })?;
    Ok(())
}

/// Add a remote port forward on an SSH connection.
pub fn mesh_add_remote_forward(
    handle: &MeshHandle,
    conn_id: u64,
    remote_port: u16,
    local_host: &str,
    local_port: u16,
) -> Result<u32, anyhow::Error> {
    handle.runtime.block_on(async {
        handle
            .client_manager
            .add_remote_forward(conn_id, remote_port, local_host, local_port)
            .await
    })
}

/// Read from a stream into a buffer. Returns the number of bytes read.
pub fn stream_read(handle: &mut MeshStreamHandle, buf: &mut [u8]) -> Result<usize, anyhow::Error> {
    let n = handle
        .runtime_handle
        .block_on(async { handle.stream.read(buf).await })?;
    Ok(n)
}

/// Write data to a stream.
pub fn stream_write(handle: &mut MeshStreamHandle, data: &[u8]) -> Result<(), anyhow::Error> {
    handle
        .runtime_handle
        .block_on(async { handle.stream.write_all(data).await })?;
    Ok(())
}

/// Shutdown and close a stream.
pub fn stream_close(handle: &mut MeshStreamHandle) -> Result<(), anyhow::Error> {
    handle.runtime_handle.block_on(async {
        let _ = handle.stream.shutdown().await;
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn android_quic_uses_shared_numeric_stream_catalog() {
        let record = TaggedRecord {
            component: NameOrTag::Tag(6),
            method: NameOrTag::Tag(9),
            id: Some(json!("request-1")),
            ..TaggedRecord::default()
        };

        let normalized = normalize_android_control_record(record);
        assert_eq!(
            normalized.component,
            NameOrTag::Name("discovery".to_owned())
        );
        assert_eq!(normalized.method, NameOrTag::Name("nodes".to_owned()));
        assert_eq!(normalized.id, Some(json!("request-1")));

        let telemetry = normalize_android_control_record(TaggedRecord {
            component: NameOrTag::Tag(7),
            method: NameOrTag::Tag(3),
            ..TaggedRecord::default()
        });
        assert_eq!(telemetry.component, NameOrTag::Name("telemetry".to_owned()));
        assert_eq!(telemetry.method, NameOrTag::Name("nan_metrics".to_owned()));

        let settings = normalize_android_control_record(TaggedRecord {
            component: NameOrTag::Tag(1),
            method: NameOrTag::Tag(2),
            ..TaggedRecord::default()
        });
        assert_eq!(settings.component, NameOrTag::Name("settings".to_owned()));
        assert_eq!(settings.method, NameOrTag::Name("set".to_owned()));
    }

    #[test]
    fn android_catalog_marks_only_bounded_read_handlers_for_fleet_checks() {
        let catalog = android_http_catalog();
        let tools = catalog["tools"].as_array().expect("tools array");
        let checked = tools
            .iter()
            .filter(|tool| tool.get("x-check-all").is_some())
            .collect::<Vec<_>>();
        assert!(!checked.is_empty());
        assert!(checked.iter().all(|tool| {
            tool["x-check-all-platforms"] == json!(["android"])
        }));
        assert!(checked.iter().any(|tool| tool["name"] == "settings.get"));
        assert!(checked.iter().any(|tool| tool["name"] == "telemetry.nan_status"));
        assert!(tools.iter().all(|tool| {
            tool["name"] != "settings.set" || tool.get("x-check-all").is_none()
        }));
    }

    #[test]
    fn every_android_catalogued_check_reaches_the_shared_tagged_terminal() {
        let directory = tempfile::tempdir().expect("settings directory");
        let path = directory.path().join("settings.conf");
        let catalog = android_http_catalog();
        for (index, tool) in catalog["tools"]
            .as_array()
            .expect("tools array")
            .iter()
            .filter(|tool| tool.get("x-check-all").is_some())
            .enumerate()
        {
            let name = tool["name"].as_str().expect("catalogue name");
            let (component, method) = name.rsplit_once('.').unwrap_or(("", name));
            let mut record = TaggedRecord {
                component: NameOrTag::Name(component.to_owned()),
                method: NameOrTag::Name(method.to_owned()),
                id: Some(json!(index + 1)),
                ..TaggedRecord::default()
            };
            if let Some(fields) = tool["x-check-all"].as_object() {
                record.env = fields
                    .iter()
                    .map(|(key, value)| (NameOrTag::Name(key.clone()), value.clone()))
                    .collect();
            }
            let response = handle_android_control_record(record, &path)
                .unwrap_or_else(|error| panic!("{name} failed: {error}"))
                .unwrap_or_else(|| panic!("{name} was not handled"));
            assert_eq!(response.id, Some(json!(index + 1)), "{name}");
            assert!(response.error.is_none(), "{name}: {:?}", response.error);
        }
    }

    #[test]
    fn android_quic_terminal_returns_a_correlated_discovery_response() {
        let request = TaggedRecord {
            component: NameOrTag::Tag(6),
            method: NameOrTag::Tag(9),
            id: Some(json!(2)),
            ..TaggedRecord::default()
        };
        let wire = mesh::cbor::encode_record(&request).expect("encode request");
        let directory = tempfile::tempdir().expect("settings directory");
        let handler =
            dmesh_server::udp::CanonicalTaggedStreamHandler::new(Arc::new(AndroidControlHandler {
                settings_path: directory.path().join("settings.conf"),
            }));
        let response_wire = tokio::runtime::Runtime::new()
            .expect("runtime")
            .block_on(dmesh_server::udp::TaggedStreamHandler::handle(
                &handler,
                dmesh_server::udp::TaggedStreamContext {
                    peer: "127.0.0.1:3339".parse().unwrap(),
                },
                wire,
            ))
            .expect("terminal response");
        let response = mesh::cbor::decode_record(&response_wire).expect("decode response");

        assert_eq!(response.id, Some(json!(2)));
        assert!(response.result.is_some());
        assert!(response.error.is_none());
    }

    #[test]
    fn android_quic_terminal_uses_shared_telemetry_identity() {
        let request = TaggedRecord {
            component: NameOrTag::Tag(7),
            method: NameOrTag::Tag(3),
            id: Some(json!(3)),
            ..TaggedRecord::default()
        };
        let wire = mesh::cbor::encode_record(&request).expect("encode request");
        let directory = tempfile::tempdir().expect("settings directory");
        let handler =
            dmesh_server::udp::CanonicalTaggedStreamHandler::new(Arc::new(AndroidControlHandler {
                settings_path: directory.path().join("settings.conf"),
            }));
        let response_wire = tokio::runtime::Runtime::new()
            .expect("runtime")
            .block_on(dmesh_server::udp::TaggedStreamHandler::handle(
                &handler,
                dmesh_server::udp::TaggedStreamContext {
                    peer: "127.0.0.1:3339".parse().unwrap(),
                },
                wire,
            ))
            .expect("terminal response");
        let response = mesh::cbor::decode_record(&response_wire).expect("decode response");
        assert_eq!(response.id, Some(json!(3)));
        assert_eq!(response.result, Some(json!({"events": 0, "followups": 0})));
        assert!(response.error.is_none());
    }

    #[test]
    fn android_quic_terminal_uses_shared_bare_status_identity() {
        let request = TaggedRecord {
            component: NameOrTag::Tag(dmesh_server::services::DIAGNOSTIC_COMPONENT as u32),
            method: NameOrTag::Tag(dmesh_server::services::DIAGNOSTIC_STATUS_METHOD as u32),
            id: Some(json!(4)),
            ..TaggedRecord::default()
        };
        let wire = mesh::cbor::encode_record(&request).expect("encode request");
        let directory = tempfile::tempdir().expect("settings directory");
        let handler =
            dmesh_server::udp::CanonicalTaggedStreamHandler::new(Arc::new(AndroidControlHandler {
                settings_path: directory.path().join("settings.conf"),
            }));
        let response_wire = tokio::runtime::Runtime::new()
            .expect("runtime")
            .block_on(dmesh_server::udp::TaggedStreamHandler::handle(
                &handler,
                dmesh_server::udp::TaggedStreamContext {
                    peer: "127.0.0.1:3339".parse().unwrap(),
                },
                wire,
            ))
            .expect("terminal response");
        let response = mesh::cbor::decode_record(&response_wire).expect("decode response");
        assert_eq!(response.id, Some(json!(4)));
        assert_eq!(response.result, Some(json!({"status_version": 1, "platform": "android"})));
        assert!(response.error.is_none());
    }

    #[test]
    fn android_settings_are_normal_tagged_streams_backed_by_private_file() {
        let directory = tempfile::tempdir().expect("settings directory");
        let path = directory.path().join("settings.conf");
        let set = TaggedRecord {
            component: NameOrTag::Tag(1),
            method: NameOrTag::Tag(2),
            id: Some(json!(4)),
            env: [
                (NameOrTag::Tag(1), json!("name")),
                (NameOrTag::Tag(2), json!("android-9")),
            ]
            .into_iter()
            .collect(),
            ..TaggedRecord::default()
        };
        let set_response = handle_android_control_record(set, &path)
            .expect("settings set")
            .expect("correlated response");
        assert_eq!(set_response.id, Some(json!(4)));
        assert_eq!(set_response.result, Some(json!({})));

        let get = TaggedRecord {
            component: NameOrTag::Name("settings".to_owned()),
            method: NameOrTag::Name("get".to_owned()),
            id: Some(json!(5)),
            env: [(NameOrTag::Name("key".to_owned()), json!("name"))]
                .into_iter()
                .collect(),
            ..TaggedRecord::default()
        };
        let get_response = handle_android_control_record(get, &path)
            .expect("settings get")
            .expect("correlated response");
        assert_eq!(get_response.id, Some(json!(5)));
        assert_eq!(
            get_response.result,
            Some(json!({"key":"name", "value":"android-9"}))
        );
        assert_eq!(
            std::fs::read_to_string(path).expect("private file"),
            "# DMesh common settings\nname=android-9\n"
        );
    }
}
