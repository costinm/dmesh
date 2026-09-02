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
#[cfg(target_os = "android")]
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};
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

/// DMesh's Android-specific registration for the generic ssh-mesh service
/// registry.  This is an in-process adapter only: request execution is a
/// direct Rust call into the established Android control dispatcher.
struct AndroidControlHandler;

/// The public discovery numeric identities are shared with lmesh. Android's
/// handwritten catalog still advertises names, so normalize just the reviewed
/// common aliases at the QUIC terminal before invoking that dispatcher.
/// Unknown numeric records remain rejected by `handle_tagged_control_record`.
fn normalize_android_tagged_record(mut record: TaggedRecord) -> TaggedRecord {
    match (&record.component, &record.method) {
        (NameOrTag::Tag(6), NameOrTag::Tag(1)) => {
            record.component = NameOrTag::Name("discovery".to_owned());
            record.method = NameOrTag::Name("devices".to_owned());
        }
        (NameOrTag::Tag(6), NameOrTag::Tag(2)) => {
            record.component = NameOrTag::Name("discovery".to_owned());
            record.method = NameOrTag::Name("status".to_owned());
        }
        _ => {}
    }
    record
}

/// Identity material used only to produce a signed, authenticated discovery
/// record. QUIC endpoint authentication remains independent of this presence
/// signature; the public-key DER is the stable `to` selector used by the
/// discovery-to-QUIC bridge.
#[cfg(target_os = "android")]
struct AndroidAnnounceIdentity {
    public_key: Vec<u8>,
    signing_key: SigningKey,
}

/// Android terminates normal QUIC streams in the same Rust catalog dispatcher
/// as its local HTTP service. This keeps `to` forwarding bearer-neutral: the
/// caller chooses a discovered identity, then the target executes locally.
struct AndroidUdpTaggedHandler;

impl dmesh_server::udp::TaggedStreamHandler for AndroidUdpTaggedHandler {
    fn handle<'a>(
        &'a self,
        _context: dmesh_server::udp::TaggedStreamContext,
        request: Vec<u8>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Option<Vec<u8>>> + Send + 'a>> {
        Box::pin(async move {
            let record = match mesh::cbor::decode_record(&request) {
                Ok(record) => normalize_android_tagged_record(record),
                Err(error) => {
                    log::warn!("Android QUIC tagged request decode failed: {error}");
                    return None;
                }
            };
            let request_id = record.id.clone()?;
            let response = match crate::mesh_jni::handle_tagged_control_record(record) {
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
    json!({"tools": [
        {"name":"radio.status_text","description":"Read the Rust-owned mesh status summary.","x-ui-visibility":"masked","inputSchema":{"type":"object","properties":{},"additionalProperties":false}},
        {"name":"discovery.nodes","title":"Nodes","description":"Read the bounded cross-bearer node inventory, including physical devices and future control-plane nodes.","x-ui-visibility":"default","inputSchema":{"type":"object","properties":{},"additionalProperties":false}},
        {"name":"discovery.status","title":"This node","description":"Read this node's currently announced local network and capability facts.","x-ui-visibility":"default","inputSchema":{"type":"object","properties":{},"additionalProperties":false}},
        {"name":"nan.status","description":"Read local Wi-Fi Aware attach and publish state; peer inventory is in discovery.nodes.","x-ui-visibility":"masked","inputSchema":{"type":"object","properties":{},"additionalProperties":false}},
        {"name":"now.metrics","description":"Read local ESP-NOW runtime counters when supported.","x-ui-visibility":"masked","inputSchema":{"type":"object","properties":{},"additionalProperties":false}},
        {"name":"nan.metrics","description":"Read local Wi-Fi Aware event and Follow-up counters.","x-ui-visibility":"masked","inputSchema":{"type":"object","properties":{},"additionalProperties":false}},
        {"name":"udp6.metrics","description":"Read local raw IPv6, UDP, and NDP counters when supported.","x-ui-visibility":"masked","inputSchema":{"type":"object","properties":{},"additionalProperties":false}},
        {"name":"wifi.link.metrics","description":"Read common optional per-peer Wi-Fi link observations when supported.","x-ui-visibility":"masked","inputSchema":{"type":"object","properties":{},"additionalProperties":false}},
        {"name":"radio.nan.followups","description":"Read bounded receiver-proven NAN follow-up receipts.","x-ui-visibility":"masked","inputSchema":{"type":"object","properties":{},"additionalProperties":false}},
        {"name":"radio.nan.events","description":"Read bounded Android Wi-Fi Aware callback events.","x-ui-visibility":"masked","inputSchema":{"type":"object","properties":{},"additionalProperties":false}},
        {"name":"radio.perf.udp6","description":"Run the common bounded perf service over a discovered peer's shared STA UDP6 path. Both peers must announce the same current SSID and the peer must have a fresh UDP multicast address.","x-ui-visibility":"default","inputSchema":{"type":"object","properties":{"target_id":{"type":"string","description":"Discovered node ID."},"bytes":{"type":"integer","minimum":1,"maximum":262144,"default":32768},"packet_size":{"type":"integer","minimum":64,"maximum":1100,"default":1100}},"required":["target_id"],"additionalProperties":false}},
        {"name":"radio.power.state","description":"Read bounded power and memory observations.","x-ui-visibility":"masked","inputSchema":{"type":"object","properties":{},"additionalProperties":false}}
    ]})
}

#[async_trait::async_trait]
impl TaggedRecordHandler for AndroidControlHandler {
    async fn handle_record(&self, record: TaggedRecord) -> anyhow::Result<Option<TaggedRecord>> {
        crate::mesh_jni::handle_tagged_control_record(record)
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
        let mesh_services = ssh_mesh::mesh_rest::MeshServiceRegistry::default();
        mesh_services.register(
            "android",
            ssh_mesh::mesh_rest::MeshService {
                backend: ssh_mesh::mesh_rest::MeshServiceBackend::Direct(Arc::new(
                    AndroidControlHandler,
                )),
                catalog: Some(android_http_catalog()),
            },
        );
        let app_state = ssh_mesh::AppState {
            ssh_server: node.clone(),
            target_http_address: None,
            ssh_client_manager: client_manager.clone(),
            mesh_services,
            web_root: std::env::var_os("DMESH_HTTP_WEB_DIR").map(std::path::PathBuf::from),
        };
        let app = ssh_mesh::handlers::app(app_state);
        http_server_handle = Some(runtime.spawn(async move {
            let addr = format!("127.0.0.1:{}", h_port);
            match tokio::net::TcpListener::bind(&addr).await {
                Ok(listener) => {
                    if let Err(e) = axum::serve(listener, app.into_make_service()).await {
                        log::error!("HTTP server failed: {}", e);
                    }
                }
                Err(e) => log::error!("Failed to bind HTTP server to {}: {}", addr, e),
            }
        }));
    }

    // Android participates in the same bearer-neutral service surface as
    // lmesh-wifi and firmware. Bind IPv6 explicitly: link-local and NAN
    // data-path tests use scoped IPv6 addresses, while the shared registry
    // supplies status/handlers/iperf without an Android-only replacement.
    // Keep this Android-only: host MeshNode users must not unexpectedly claim
    // the stable Wi-Fi UDP port merely by constructing a node.
    #[cfg(target_os = "android")]
    let udp_server_handle = {
        let udp_config = dmesh_server::udp::UdpConfig {
            bind: SocketAddr::from((
                Ipv6Addr::UNSPECIFIED,
                dmesh_server::udp::STABLE_WIFI_UDP_PORT,
            )),
            artifact_root: base_path.clone(),
            tagged_handler: Some(Arc::new(AndroidUdpTaggedHandler)),
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
        let identity = AndroidAnnounceIdentity {
            public_key,
            signing_key: SigningKey::from(secret_key),
        };
        let (trigger, receiver) = tokio::sync::mpsc::unbounded_channel();
        (
            Some(runtime.spawn(android_announce_loop(identity, receiver))),
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

/// Android's local-link presence socket is intentionally distinct from the
/// QUIC-lite port. It uses the established lmesh group and shared CBOR record,
/// while the QUIC UDP listener remains unicast-only.
#[cfg(target_os = "android")]
async fn android_announce_loop(
    identity: AndroidAnnounceIdentity,
    mut trigger: tokio::sync::mpsc::UnboundedReceiver<()>,
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
    let mut boot_pending = true;
    let mut joined_interfaces = BTreeSet::new();
    loop {
        tokio::select! {
            _ = interval.tick() => {
                let sent = send_android_announce(&socket, group, PORT, &mut joined_interfaces,
                    id, take as u8, started.elapsed().as_secs(), boot_pending, &identity).await;
                if sent { boot_pending = false; }
            }
            Some(()) = trigger.recv() => {
                // A P2P group may appear long after service boot. Join its
                // scoped multicast interface and emit the same bounded record
                // now, rather than waiting for the periodic interval.
                let sent = send_android_announce(&socket, group, PORT, &mut joined_interfaces,
                    id, take as u8, started.elapsed().as_secs(), boot_pending, &identity).await;
                if sent { boot_pending = false; }
            }
            received = socket.recv_from(&mut receive) => match received {
                Ok((len, sender)) => {
                    let payload = quic_lite::decode_direct_packet(&receive[..len])
                        .map_or(&receive[..len], |(_, payload)| payload);
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
    socket: &tokio::net::UdpSocket,
    group: Ipv6Addr,
    port: u16,
    joined_interfaces: &mut BTreeSet<u32>,
    id: [u8; 16],
    id_len: u8,
    uptime_secs: u64,
    boot: bool,
    identity: &AndroidAnnounceIdentity,
) -> bool {
    let mut announce = if boot {
        dmesh_server::announce::Announce::boot(id, id_len)
    } else {
        dmesh_server::announce::Announce::discovery(
            id,
            id_len,
            u32::try_from(uptime_secs).unwrap_or(u32::MAX),
        )
    };
    if let Ok(domain) = std::env::var("DMESH_DISCOVERY_DOMAIN") {
        let domain = domain.trim();
        if !domain.is_empty() && domain.len() <= dmesh_server::announce::MAX_DEVICE_DOMAIN {
            let _ = announce.set_device_domain(domain);
        }
    }
    let interfaces = multicast_interfaces();
    for interface in &interfaces {
        if joined_interfaces.insert(interface.index)
            && let Err(error) = socket.join_multicast_v6(&group, interface.index)
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
        let mut signing_wire = [0u8; 384];
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
        let mut announce_wire = [0u8; 384];
        let Some(announce_used) = dmesh_server::announce::encode(per_interface, &mut announce_wire)
        else {
            log::warn!(
                "Android announce encoding exceeded bound on {}",
                interface.name
            );
            continue;
        };
        let mut wire = [0u8; 448];
        let Some(used) =
            quic_lite::encode_direct_packet(0, &announce_wire[..announce_used], &mut wire).ok()
        else {
            log::warn!(
                "Android announce direct envelope exceeded bound on {}",
                interface.name
            );
            continue;
        };
        let destination = SocketAddr::V6(SocketAddrV6::new(group, port, 0, interface.index));
        match socket.send_to(&wire[..used], destination).await {
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
    fn android_quic_normalizes_public_discovery_numeric_tags() {
        let record = TaggedRecord {
            component: NameOrTag::Tag(6),
            method: NameOrTag::Tag(2),
            id: Some(json!("request-1")),
            ..TaggedRecord::default()
        };

        let normalized = normalize_android_tagged_record(record);
        assert_eq!(
            normalized.component,
            NameOrTag::Name("discovery".to_owned())
        );
        assert_eq!(normalized.method, NameOrTag::Name("status".to_owned()));
        assert_eq!(normalized.id, Some(json!("request-1")));
    }

    #[test]
    fn android_quic_terminal_returns_a_correlated_discovery_response() {
        let request = TaggedRecord {
            component: NameOrTag::Tag(6),
            method: NameOrTag::Tag(2),
            id: Some(json!("request-2")),
            ..TaggedRecord::default()
        };
        let wire = mesh::cbor::encode_record(&request).expect("encode request");
        let response_wire = tokio::runtime::Runtime::new()
            .expect("runtime")
            .block_on(dmesh_server::udp::TaggedStreamHandler::handle(
                &AndroidUdpTaggedHandler,
                wire,
            ))
            .expect("terminal response");
        let response = mesh::cbor::decode_record(&response_wire).expect("decode response");

        assert_eq!(response.id, Some(json!("request-2")));
        assert!(response.result.is_some());
        assert!(response.error.is_none());
    }
}
