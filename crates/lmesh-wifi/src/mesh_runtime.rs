use std::{
    future::Future,
    path::PathBuf,
    pin::Pin,
    sync::{Arc, LazyLock},
    time::Instant,
};

use crate::mesh_core::{LmeshService, LocalDiscovery};
use anyhow::{Context, Result};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, UnixStream};
use tokio::time::{Duration, sleep};
use tracing::{debug, error, warn};

/// Keep host multicast presence aligned with NAN/NOW/ESP refreshes. Operators
/// may still override this through `LMESH_ANNOUNCE_INTERVAL_SECS`.
const DEFAULT_ANNOUNCE_INTERVAL_SECS: u64 = 5 * 60;
const ANNOUNCE_INTERVAL_ENV: &str = "LMESH_ANNOUNCE_INTERVAL_SECS";
const WIFI_DISCOVERY_SOCKET_ENV: &str = "LMESH_WIFI_CONTROL_SOCKET";
const DEFAULT_WIFI_DISCOVERY_SOCKET: &str = "/run/mesh/lmesh-wifi/mesh.sock";
const RAW_WIFI_CHANNEL_ENV: &str = "LMESH_RAW_WIFI_CHANNEL";

/// Process-local endpoints for a Linux mesh service.
///
/// These are code defaults, deliberately selected by each binary rather than
/// injected through environment variables.  Deployment configuration may still
/// control radio interfaces and credentials, but not the identity of the
/// control/admin endpoints.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeDefaults {
    pub control_socket: &'static str,
    pub http_port: u16,
    /// Normal unicast object/QUIC-lite listener. This is intentionally not a
    /// discovery port and must remain distinct per supervised service.
    pub udp_port: u16,
}

/// Defaults for the BLE-enabled `lmesh` launcher.
pub const LMESH_DEFAULTS: RuntimeDefaults = RuntimeDefaults {
    control_socket: "/run/mesh/lmesh/mesh.sock",
    http_port: 18982,
    udp_port: dmesh_server::udp::DEVELOPMENT_WIFI_UDP_PORT,
};

/// Defaults for the privileged `lmesh-wifi` launcher.
pub const LMESH_WIFI_DEFAULTS: RuntimeDefaults = RuntimeDefaults {
    control_socket: "/run/mesh/lmesh-wifi/mesh.sock",
    http_port: 18981,
    udp_port: dmesh_server::udp::STABLE_WIFI_UDP_PORT,
};

/// Generated public catalog. Only reviewed entries carry numeric tags, so the
/// CBOR path cannot accidentally expose or number a legacy control method.
static CONTROL_CATALOG: LazyLock<mesh::tagged::TaggedCatalog> = LazyLock::new(|| {
    mesh::tagged::TaggedCatalog::from_tools_json(&public_tools_json())
        .expect("lmesh tools.json must be a valid tagged catalog")
});

fn public_tools_json() -> serde_json::Value {
    serde_json::from_str::<serde_json::Value>(include_str!("../../lmesh/resources/tools.json"))
        .expect("shared tools.json must be valid JSON")
}

/// Run the shared Linux mesh control plane.
pub async fn run_mesh_service(defaults: RuntimeDefaults) -> Result<()> {
    let (trace_buffer, _trace_guard) = mesh::local_trace::init("lmesh");
    mesh::local_trace::serve("lmesh", trace_buffer.clone());
    if let Err(error) = run_server(trace_buffer, defaults).await {
        // mesh-init intentionally discards child stderr in the production
        // service unit. Persist the startup failure in the service log so a
        // stale control socket is diagnosable without changing radio state or
        // replacing the supervised process by hand.
        error!(error = %error, "lmesh_server_terminated");
        return Err(error);
    }
    Ok(())
}

async fn run_server(
    trace_buffer: mesh::local_trace::LogBuffer,
    defaults: RuntimeDefaults,
) -> Result<()> {
    let mut discovery = LocalDiscovery::new(None).await?;
    // The shared LAN label is local configuration only. The wire announce
    // carries the resulting IPv6 address and this service's distinct UDP
    // port; a receiver records the ingress interface/scope itself.
    discovery.configure_announce_udp6("costin", defaults.udp_port);
    discovery.start().await?;
    let discovery = Arc::new(discovery);
    let service = Arc::new(LmeshService::new(discovery.clone()));
    // Use the shared owned-interface watcher for wlan1 as well as wlan0.  The
    // callback receives only events whose interface passed this process's
    // LMESH_INTERFACES allowlist, so a wlan0 reset cannot restart lmesh.
    let owned_interfaces = service.wifi_owned_interfaces();
    let (link_events, mut link_event_rx) = tokio::sync::mpsc::unbounded_channel();
    std::thread::spawn(move || {
        lmesh_wifi::recovery::watch_link_events(owned_interfaces, link_events)
    });
    let recovery_service = service.clone();
    tokio::spawn(async move {
        while let Some(event) = link_event_rx.recv().await {
            sleep(Duration::from_millis(250)).await;
            let result = recovery_service.reconcile_wifi_health();
            if result.get("state").and_then(serde_json::Value::as_str) != Some("healthy") {
                warn!(?event, ?result, "lmesh_wifi_link_reconcile");
            }
        }
    });
    let udp_started = service.start_udp_tagged_handler(
        defaults.udp_port,
        Arc::new(LmeshUdpTaggedHandler {
            service: service.clone(),
        }),
    );
    if udp_started.get("ok").and_then(serde_json::Value::as_bool) == Some(true) {
        debug!(?udp_started, "lmesh_development_quic_started");
    } else {
        warn!(?udp_started, "lmesh_development_quic_start_failed");
    }
    // The multicast receiver validates a common announce before invoking this
    // local callback. Its radio-side destination is the same bounded registry
    // used by raw NAN, so host discovery does not split by bearer.
    let announce_service = service.clone();
    let wifi_discovery_socket = wifi_discovery_socket();
    discovery
        .set_announce_observer(Arc::new(move |peer, announce| {
            announce_service.observe_multicast_announce(peer, announce);
            // Mirror the already-validated semantic record to the stable
            // wlan0 service. The send is intentionally best-effort: its
            // absence must not stall UDP multicast receive or alter radios.
            let socket = wifi_discovery_socket.clone();
            tokio::spawn(async move {
                if let Err(error) = forward_wifi_discovery_announce(socket, peer, announce).await {
                    debug!(%error, "lmesh_wifi_discovery_forward_failed");
                }
            });
        }))
        .await;
    discovery.announce().await?;
    let active_publish_started = Instant::now();
    match service.refresh_active_nan_publish(0) {
        Ok(status) => debug!(?status, "rawnan_active_publish_configured"),
        Err(error) => warn!(%error, "rawnan_active_publish_configure_failed"),
    }
    let channel = raw_wifi_channel();
    // lmesh owns wlan1 as the experimental/default peer radio: boot a
    // channel-6 P2P GO and then attach the same monitor receive/TX fixture
    // used by the stable wlan0 AP. The P2P implementation has an explicit
    // pure-Rust open-AP fallback when unsupported.
    let p2p_started = service.start_default_p2p_go(channel);
    if p2p_started.get("ok").and_then(serde_json::Value::as_bool) == Some(true) {
        debug!(?p2p_started, channel, "lmesh_default_p2p_nan_started");
    } else {
        warn!(?p2p_started, channel, "lmesh_default_p2p_nan_start_failed");
    }
    debug!(
        public_key = %service.public_key_b64(),
        "service_started"
    );

    let discovery_periodic = discovery.clone();
    let announce_interval = announce_interval();
    tokio::spawn(async move {
        loop {
            sleep(announce_interval).await;
            if let Err(e) = discovery_periodic.announce().await {
                warn!("Failed to send announcement: {}", e);
            }
        }
    });
    // Keep NAN publish aligned with UDP multicast. Updating the descriptor
    // makes it pending for the next DW; it does not send from this timer or
    // change the permanent monitor fixture.
    let active_publish_service = service.clone();
    tokio::spawn(async move {
        loop {
            sleep(Duration::from_secs(DEFAULT_ANNOUNCE_INTERVAL_SECS)).await;
            let uptime_secs = active_publish_started.elapsed().as_secs();
            if let Err(error) = active_publish_service.refresh_active_nan_publish(uptime_secs) {
                warn!(%error, "rawnan_active_publish_refresh_failed");
            }
        }
    });

    let listen_path = standalone_listen_path(defaults)?;
    let listen_path = listen_path.to_string_lossy().into_owned();
    start_http_admin(&listen_path, defaults.http_port).await?;
    let mut listener = mesh::server::MeshListener::new("lmesh", Some(&listen_path))
        .map_err(|e| anyhow::anyhow!("lmesh listener error: {}", e))?;
    // lmesh is the local control-plane endpoint.  Once both its UDS and
    // optional HTTP listener are ready, actively ask every enabled bearer for
    // current peer presence.  This complements (rather than replaces) the
    // boot/periodic multicast announcement above: it prompts NAN/NOW peers to
    // publish immediately and sends the matching UDP6 multicast announce.
    // Run it outside the accept loop so a slow or unavailable optional radio
    // never delays control-socket readiness.
    let boot_discovery_service = service.clone();
    tokio::spawn(async move {
        sleep(Duration::from_secs(1)).await;
        let response = boot_discovery_service
            .handle_request(crate::mesh_core::Request::DiscoveryPing { medium: None })
            .await;
        if response.success {
            debug!("lmesh_boot_discovery_submitted");
        } else {
            warn!(error = ?response.error, "lmesh_boot_discovery_failed");
        }
    });
    let mcp = Arc::new(mesh::jsonl::McpRegistry::new("lmesh"));
    while let Some(stream) = listener
        .accept()
        .await
        .map_err(|e| anyhow::anyhow!("lmesh accept error: {}", e))?
    {
        let service = service.clone();
        let mcp = mcp.clone();
        let trace_buffer = trace_buffer.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, service, mcp, trace_buffer.clone()).await {
                error!("lmesh JSONL connection error: {}", e);
            }
        });
    }

    Ok(())
}

async fn dispatch_directed_jsonl(
    request: &str,
    service: Arc<LmeshService>,
) -> Result<Option<serde_json::Value>> {
    let value = match serde_json::from_str::<serde_json::Value>(request) {
        Ok(value) => value,
        Err(_) => return Ok(None),
    };
    if value.get("to").is_none() {
        return Ok(None);
    }
    let record = tagged_record_from_jsonl(&value)?;
    let handler = LmeshCborHandler { service };
    let response = mesh::wire::TaggedRecordHandler::forward_record(&handler, record)
        .await?
        .context("directed UDS request produced no response")?;
    Ok(Some(CONTROL_CATALOG.to_jsonl(&response)))
}

fn tagged_record_from_jsonl(value: &serde_json::Value) -> Result<mesh::tagged::TaggedRecord> {
    let object = value
        .as_object()
        .context("directed UDS request must be a JSON object")?;
    let method = object
        .get("method")
        .and_then(serde_json::Value::as_str)
        .context("directed UDS request lacks method")?;
    let schema = CONTROL_CATALOG
        .method(method)
        .context("directed UDS method is outside the reviewed lmesh catalog")?;
    let mut record = mesh::tagged::TaggedRecord {
        component: schema.component.clone(),
        method: schema.method.clone(),
        id: object.get("id").cloned(),
        to: object.get("to").cloned(),
        ..Default::default()
    };
    if record.id.is_none() {
        anyhow::bail!("directed UDS request requires id");
    }
    for (name, field) in object {
        if matches!(name.as_str(), "id" | "method" | "to" | "jsonrpc") {
            continue;
        }
        let key = schema
            .fields
            .get(name)
            .map(|field| mesh::tagged::NameOrTag::Tag(field.tag))
            .unwrap_or_else(|| mesh::tagged::NameOrTag::Name(name.clone()));
        record.env.insert(key, field.clone());
    }
    Ok(record)
}

/// Start the generic ssh-mesh admin REST server only when explicitly enabled.
/// It talks to this supervised lmesh instance through the existing UDS instead
/// of constructing another service or taking ownership of any radio.
async fn start_http_admin(socket: &str, port: u16) -> Result<()> {
    let node = Arc::new(ssh_mesh::MeshNode::new(None, None));
    let manager = Arc::new(ssh_mesh::sshc::SshClientManager::new(
        node.private_key().clone(),
        (*node.ca_keys).clone(),
        None,
        None,
    ));
    let registry = ssh_mesh::mesh_rest::MeshServiceRegistry::default();
    registry.register(
        "lmesh",
        ssh_mesh::mesh_rest::MeshService {
            backend: ssh_mesh::mesh_rest::MeshServiceBackend::Uds(PathBuf::from(socket)),
            catalog: Some(public_tools_json()),
        },
    );
    let app = ssh_mesh::handlers::app(ssh_mesh::AppState {
        ssh_server: node,
        target_http_address: None,
        ssh_client_manager: manager,
        mesh_services: registry,
        web_root: http_web_root("LMESH_HTTP_WEB_DIR"),
    });
    let listener = match TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port)).await {
        Ok(listener) => listener,
        Err(error) => {
            return Err(error).with_context(|| format!("bind lmesh HTTP admin port {port}"));
        }
    };
    tokio::spawn(async move {
        if let Err(error) = axum::serve(listener, app.into_make_service()).await {
            error!(%error, "lmesh_http_admin_terminated");
        }
    });
    debug!(port, "lmesh_http_admin_started");
    Ok(())
}

/// Serve admin assets from a configured development directory when requested;
/// the embedded ssh-mesh bundle remains the normal production fallback.
fn http_web_root(service_env: &str) -> Option<PathBuf> {
    std::env::var_os(service_env)
        .or_else(|| std::env::var_os("MESH_HTTP_WEB_DIR"))
        .map(PathBuf::from)
}

fn announce_interval() -> Duration {
    let secs = std::env::var(ANNOUNCE_INTERVAL_ENV)
        .ok()
        .and_then(|value| parse_announce_interval_secs(&value));
    Duration::from_secs(secs.unwrap_or(DEFAULT_ANNOUNCE_INTERVAL_SECS))
}

fn raw_wifi_channel() -> u8 {
    std::env::var(RAW_WIFI_CHANNEL_ENV)
        .ok()
        .and_then(|value| value.parse::<u8>().ok())
        .filter(|channel| (1..=13).contains(channel))
        .unwrap_or(6)
}

fn parse_announce_interval_secs(value: &str) -> Option<u64> {
    let secs = value.trim().parse::<u64>().ok()?;
    (secs > 0).then_some(secs)
}

fn standalone_listen_path(defaults: RuntimeDefaults) -> Result<PathBuf> {
    resolve_relative_path(PathBuf::from(defaults.control_socket))
}

fn wifi_discovery_socket() -> PathBuf {
    std::env::var_os(WIFI_DISCOVERY_SOCKET_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_WIFI_DISCOVERY_SOCKET))
}

async fn forward_wifi_discovery_announce(
    socket: PathBuf,
    peer: std::net::SocketAddr,
    announce: dmesh_server::announce::Announce,
) -> Result<()> {
    let mut wire = [0_u8; 512];
    let used = dmesh_server::announce::encode(announce, &mut wire)
        .ok_or_else(|| anyhow::anyhow!("failed to encode validated announce"))?;
    let request = serde_json::json!({
        "method": "wifi.discovery.observe",
        "source": "udp_multicast",
        "peer": peer.to_string(),
        "announce_hex": hex_encode(&wire[..used]),
    });
    let mut stream = UnixStream::connect(&socket)
        .await
        .with_context(|| format!("connect {}", socket.display()))?;
    stream.write_all(request.to_string().as_bytes()).await?;
    stream.write_all(b"\n").await?;
    stream.flush().await?;
    let mut response = String::new();
    BufReader::new(stream).read_line(&mut response).await?;
    let response: serde_json::Value = serde_json::from_str(response.trim())?;
    if response.get("error").is_some() {
        anyhow::bail!("lmesh-wifi rejected discovery observation: {response}");
    }
    Ok(())
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        text.push(HEX[(byte >> 4) as usize] as char);
        text.push(HEX[(byte & 0x0f) as usize] as char);
    }
    text
}

fn resolve_relative_path(path: PathBuf) -> Result<PathBuf> {
    let path = if path.is_absolute() {
        path
    } else {
        std::env::current_dir()
            .context("failed to resolve current working directory")?
            .join(path)
    };
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    Ok(path)
}

async fn handle_connection(
    stream: mesh::server::MeshStream,
    service: Arc<LmeshService>,
    mcp: Arc<mesh::jsonl::McpRegistry>,
    trace_buffer: mesh::local_trace::LogBuffer,
) -> Result<()> {
    let mut stream = stream;
    let mut first = [0_u8; 1];
    if stream.read(&mut first).await? == 0 {
        return Ok(());
    }
    let mut stream = mesh::wire::PrefixedStream::new(first[0], stream);
    if first[0] == 0 {
        return mesh::wire::serve_cbor_session(&mut stream, &LmeshCborHandler { service }).await;
    }
    handle_json_connection(&mut stream, service, mcp, trace_buffer).await
}

/// The JSON/text branch is a gateway-only compatibility path. The stream has
/// its first byte restored by `PrefixedStream`, so protocol selection never
/// corrupts a request line.
async fn handle_json_connection<S>(
    stream: &mut S,
    service: Arc<LmeshService>,
    mcp: Arc<mesh::jsonl::McpRegistry>,
    trace_buffer: mesh::local_trace::LogBuffer,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (reader, mut writer) = tokio::io::split(stream);
    let mut reader = BufReader::new(reader);
    let mut line = String::new();

    loop {
        line.clear();
        let bytes_read = reader
            .read_line(&mut line)
            .await
            .context("failed to read JSONL request")?;
        if bytes_read == 0 {
            break;
        }

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        if let Ok(request) = serde_json::from_str::<serde_json::Value>(trimmed)
            && request
                .get("method")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|method| {
                    matches!(method, "subscribe" | "trace.subscribe" | "events.subscribe")
                        || method.ends_with(".subscribe")
                })
        {
            let mut params = request.get("params").cloned().unwrap_or(request);
            if let Some(object) = params.as_object_mut() {
                if let Some(serde_json::Value::Array(values)) = object.remove("params") {
                    for value in values {
                        if let Some(value) = value.as_str()
                            && let Some((key, value)) = value.split_once('=')
                        {
                            object.insert(
                                key.to_owned(),
                                serde_json::Value::String(value.to_owned()),
                            );
                        }
                    }
                }
                if let Some(serde_json::Value::String(targets)) = object.get("targets").cloned() {
                    object.insert(
                        "targets".to_owned(),
                        serde_json::Value::Array(
                            targets
                                .split(',')
                                .filter(|target| !target.is_empty())
                                .map(|target| serde_json::Value::String(target.to_owned()))
                                .collect(),
                        ),
                    );
                }
            }
            let config: mesh::local_trace::TraceConfig = serde_json::from_value(params)
                .context("invalid trace subscription configuration")?;
            let ack = serde_json::json!({
                "response": {"subscribed": true, "service": "lmesh", "targets": config.targets.clone()}
            });
            writer.write_all(ack.to_string().as_bytes()).await?;
            writer.write_all(b"\n").await?;
            writer.flush().await?;
            for entry in trace_buffer.get_all() {
                if config.matches(&entry) {
                    writer
                        .write_all(serde_json::to_string(&entry).unwrap_or_default().as_bytes())
                        .await?;
                    writer.write_all(b"\n").await?;
                }
            }
            let mut events = trace_buffer.subscribe();
            while let Ok(entry) = events.recv().await {
                if config.matches(&entry) {
                    writer
                        .write_all(serde_json::to_string(&entry).unwrap_or_default().as_bytes())
                        .await?;
                    writer.write_all(b"\n").await?;
                    writer.flush().await?;
                }
            }
            break;
        }

        // Preserve mesh routing metadata on the UDS JSONL surface.  The
        // generic JSONL dispatcher intentionally deserializes only a local
        // request, so it cannot be allowed to silently drop `to` and execute
        // a directed command on this host.  Reuse the same tagged forwarder
        // used by HTTP/QUIC records instead.
        if let Some(response) = dispatch_directed_jsonl(trimmed, service.clone()).await? {
            writer.write_all(response.to_string().as_bytes()).await?;
            writer.write_all(b"\n").await?;
            writer.flush().await?;
            continue;
        }
        let service = service.clone();
        let (format, response) = mesh::jsonl::dispatch_request(trimmed, &mcp, move |request| {
            let service = service.clone();
            async move {
                debug!(?request, "lmesh request");
                service.handle_request(request).await
            }
        })
        .await;
        let Some(response) = response else {
            continue;
        };
        let response = mesh::jsonl::format_response(response, &format)?;
        writer
            .write_all(response.as_bytes())
            .await
            .context("failed to write JSONL response")?;
        writer.write_all(b"\n").await?;
        writer.flush().await?;
    }

    Ok(())
}

struct LmeshCborHandler {
    service: Arc<LmeshService>,
}

/// Terminates a normal QUIC stream in the existing lmesh catalog handler.
/// It deliberately has no bearer or destination logic: route selection is
/// owned by the initiating `mesh.con`/forwarding side.
struct LmeshUdpTaggedHandler {
    service: Arc<LmeshService>,
}

impl dmesh_server::udp::TaggedStreamHandler for LmeshUdpTaggedHandler {
    fn handle<'a>(
        &'a self,
        _context: dmesh_server::udp::TaggedStreamContext,
        request: Vec<u8>,
    ) -> Pin<Box<dyn Future<Output = Option<Vec<u8>>> + Send + 'a>> {
        Box::pin(async move {
            let record = mesh::cbor::decode_record(&request).ok()?;
            let handler = LmeshCborHandler {
                service: self.service.clone(),
            };
            let response = mesh::wire::TaggedRecordHandler::handle_record(&handler, record)
                .await
                .ok()??;
            mesh::cbor::encode_record(&response).ok()
        })
    }
}

#[async_trait::async_trait]
impl mesh::wire::TaggedRecordHandler for LmeshCborHandler {
    async fn handle_record(
        &self,
        record: mesh::tagged::TaggedRecord,
    ) -> Result<Option<mesh::tagged::TaggedRecord>> {
        let id = record
            .id
            .clone()
            .context("tagged-CBOR request missing id")?;
        let response = match decode_lmesh_tagged_request(&record) {
            Ok(request) => self.service.handle_request(request).await,
            Err(error) => mesh::protocol::Response::err(format!("invalid request: {error}")),
        };
        let response = if response.success {
            mesh::wire::response_ok(id, response.data.unwrap_or(serde_json::Value::Null))
        } else {
            mesh::wire::response_error(
                id,
                serde_json::json!({
                    "message": response.error.unwrap_or_else(|| "Unknown error".to_owned()),
                }),
            )
        };
        Ok(Some(response))
    }

    async fn forward_record(
        &self,
        mut record: mesh::tagged::TaggedRecord,
    ) -> Result<Option<mesh::tagged::TaggedRecord>> {
        let id = record
            .id
            .clone()
            .context("tagged-CBOR request missing id")?;
        let destination = record
            .to
            .as_ref()
            .and_then(serde_json::Value::as_str)
            .context("tagged-CBOR destination must be a discovered node identity")?
            .to_owned();
        // The remote terminal executes the original request locally. `to` is
        // route selection at this HTTP/QUIC boundary, never a recursively
        // forwarded application field.
        record.to = None;
        let wire = mesh::cbor::encode_record(&record)?;
        let response = self
            .service
            .forward_tagged_record(&destination, &wire)
            .await;
        match response {
            Ok(response) if response.id == Some(id.clone()) => Ok(Some(response)),
            Ok(_) => Ok(Some(mesh::wire::response_error(
                id,
                serde_json::json!({"error": "directed QUIC response ID mismatch"}),
            ))),
            Err(error) => Ok(Some(mesh::wire::response_error(
                id,
                serde_json::json!({"error": error.to_string(), "to": destination}),
            ))),
        }
    }
}

fn decode_lmesh_tagged_request(
    record: &mesh::tagged::TaggedRecord,
) -> Result<crate::mesh_core::Request> {
    if CONTROL_CATALOG.method_name(record).is_none() {
        anyhow::bail!("tagged-CBOR method is outside the reviewed lmesh catalog");
    }
    let mut value = CONTROL_CATALOG.to_jsonl(record);
    let method = value["method"]
        .as_str()
        .context("tagged-CBOR request has no documented method")?
        .to_owned();
    value["method"] =
        serde_json::Value::String(method.strip_prefix("lmesh.").unwrap_or(&method).to_owned());
    match method.as_str() {
        "send" => serde_json::from_value::<crate::mesh_core::api::LmeshSendRequest>(value).map(
            |request| crate::mesh_core::Request::Send {
                radio: request.radio,
                destination: request.destination,
                payload: request.payload,
            },
        ),
        "messages.history" => serde_json::from_value::<
            crate::mesh_core::api::LmeshMessagesHistoryRequest,
        >(value)
        .map(|request| crate::mesh_core::Request::MessagesHistory {
            keys: request.keys,
            limit: request
                .limit
                .map(|limit| limit.min(usize::MAX as u64) as usize),
        }),
        "discovery.nodes" => Ok(crate::mesh_core::Request::RadioDevices),
        "discovery.status" => Ok(crate::mesh_core::Request::DiscoveryStatus),
        "nan.status" => Ok(crate::mesh_core::Request::NanStatus),
        "now.metrics" => Ok(crate::mesh_core::Request::NowMetrics),
        "nan.metrics" => Ok(crate::mesh_core::Request::NanMetrics),
        "udp6.metrics" => Ok(crate::mesh_core::Request::Udp6Metrics),
        "wifi.link.metrics" => Ok(crate::mesh_core::Request::WifiLinkMetrics),
        "wifi.mgmt.capture" => serde_json::from_value::<
            crate::mesh_core::api::WifiMgmtCaptureRequest,
        >(value)
        .map(|request| crate::mesh_core::Request::WifiMgmtCapture {
            iface: request.iface,
            channel: request.channel,
            capture_ms: request.capture_ms,
            max_frames: request
                .max_frames
                .map(|value| value.min(usize::MAX as u64) as usize),
            active: request.active,
        }),
        _ => serde_json::from_value(value),
    }
    .context("deserialize tagged lmesh request")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::UnixListener;

    #[test]
    fn parse_announce_interval_accepts_positive_seconds() {
        assert_eq!(parse_announce_interval_secs("5"), Some(5));
        assert_eq!(parse_announce_interval_secs(" 30 "), Some(30));
    }

    #[test]
    fn parse_announce_interval_rejects_zero_and_invalid_values() {
        assert_eq!(parse_announce_interval_secs("0"), None);
        assert_eq!(parse_announce_interval_secs("nope"), None);
    }

    #[test]
    fn resolve_relative_path_uses_cwd() {
        let cwd = std::env::current_dir().unwrap();
        assert_eq!(
            resolve_relative_path(PathBuf::from("lmesh/mesh.sock")).unwrap(),
            cwd.join("lmesh").join("mesh.sock")
        );
    }

    #[tokio::test]
    async fn validated_multicast_announce_is_forwarded_as_common_wire() {
        let path = std::env::temp_dir().join(format!(
            "lmesh-discovery-forward-{}-{}.sock",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        let listener = UnixListener::bind(&path).unwrap();
        let receiver = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (reader, mut writer) = tokio::io::split(stream);
            let mut reader = BufReader::new(reader);
            let mut line = String::new();
            reader.read_line(&mut line).await.unwrap();
            writer.write_all(b"{\"success\":true}\n").await.unwrap();
            serde_json::from_str::<serde_json::Value>(line.trim()).unwrap()
        });
        let announce = dmesh_server::announce::Announce::discovery([0xC6; 16], 16, 9);
        forward_wifi_discovery_announce(
            path.clone(),
            std::net::SocketAddr::from(([192, 0, 2, 6], 5_227)),
            announce,
        )
        .await
        .unwrap();
        let request = receiver.await.unwrap();
        assert_eq!(request["method"], "wifi.discovery.observe");
        assert_eq!(request["source"], "udp_multicast");
        let bytes = request["announce_hex"].as_str().unwrap();
        assert!(bytes.len() > 8);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn discovery_nodes_is_the_only_inventory_name() {
        let record = CONTROL_CATALOG
            .record_from_value("discovery.nodes", &serde_json::json!({}))
            .unwrap();
        assert!(matches!(
            decode_lmesh_tagged_request(&record).unwrap(),
            crate::mesh_core::Request::RadioDevices
        ));
        assert!(
            serde_json::from_value::<crate::mesh_core::Request>(serde_json::json!({
                "method": "discovery.devices"
            }))
            .is_err()
        );
    }

    #[test]
    fn combined_catalog_marks_only_the_intended_surface_default_visible() {
        let catalog = public_tools_json();
        let visible = catalog
            .as_array()
            .unwrap()
            .iter()
            .filter(|tool| tool["x-ui-visibility"] == "default")
            .filter_map(|tool| tool["name"].as_str())
            .collect::<Vec<_>>();
        assert!(visible.contains(&"discovery.nodes"));
        assert!(visible.contains(&"transport.start"));
        assert!(visible.contains(&"transport.discover"));
        assert!(!visible.contains(&"wifi.raw.send"));
        assert!(!visible.contains(&"wifi.rawnan.status"));
        assert!(!visible.contains(&"lmesh.nodes"));
        assert!(!visible.contains(&"lmesh.neighbors"));
        let names = catalog
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|tool| tool["name"].as_str())
            .collect::<Vec<_>>();
        assert!(names.contains(&"nan.status"));
        assert!(!names.contains(&"lmesh.nodes"));
        assert!(!names.contains(&"lmesh.neighbors"));
        for retired in [
            "discovery.devices",
            "lmesh.announces",
            "lmesh.get_node",
            "lmesh.announce",
            "lmesh.status",
            "lmesh.links.list",
            "lmesh.ping",
            "wifi.rawnan.status",
            "wifi.raw.metrics",
            "wifi.probe.plan",
            "wifi.raw.send",
            "wifi.raw.check",
            "wifi.raw.iperf",
        ] {
            assert!(
                !names.contains(&retired),
                "retired method {retired} remains catalogued"
            );
        }
    }

    #[test]
    fn common_numeric_transport_start_decodes_for_local_or_directed_use() {
        let request = decode_lmesh_tagged_request(&mesh::tagged::TaggedRecord {
            component: mesh::tagged::NameOrTag::Tag(1),
            method: mesh::tagged::NameOrTag::Tag(4),
            id: Some(serde_json::json!(4)),
            env: [
                (mesh::tagged::NameOrTag::Tag(1), serde_json::json!(1)),
                (
                    mesh::tagged::NameOrTag::Tag(2),
                    serde_json::json!("mesh-test"),
                ),
                (mesh::tagged::NameOrTag::Tag(14), serde_json::json!(8)),
                (mesh::tagged::NameOrTag::Tag(15), serde_json::json!(1)),
                (
                    mesh::tagged::NameOrTag::Tag(17),
                    serde_json::json!("correct-horse-battery-staple"),
                ),
                (mesh::tagged::NameOrTag::Tag(24), serde_json::json!(true)),
            ]
            .into_iter()
            .collect(),
            ..Default::default()
        })
        .unwrap();
        assert!(matches!(
            request,
            crate::mesh_core::Request::TransportStart {
                kind: Some(crate::mesh_core::TransportKindRequest::Tag(1)),
                ssid,
                passphrase: Some(passphrase),
                nan_dw_interval: Some(8),
                now: Some(1),
                open: Some(crate::mesh_core::TransportFlagRequest::Boolean(true)),
                ..
            } if ssid == "mesh-test" && passphrase == "correct-horse-battery-staple"
        ));
    }

    #[test]
    fn retired_lmesh_ping_tag_is_rejected() {
        let error = decode_lmesh_tagged_request(&mesh::tagged::TaggedRecord {
            component: mesh::tagged::NameOrTag::Tag(4),
            method: mesh::tagged::NameOrTag::Tag(7),
            id: Some(serde_json::json!(4)),
            env: [
                (mesh::tagged::NameOrTag::Tag(1), serde_json::json!("rawnan")),
                (mesh::tagged::NameOrTag::Tag(2), serde_json::json!(250)),
                (
                    mesh::tagged::NameOrTag::Tag(3),
                    serde_json::json!("probe-4"),
                ),
            ]
            .into_iter()
            .collect(),
            ..Default::default()
        })
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("outside the reviewed lmesh catalog")
        );
    }

    #[test]
    fn common_nan_metrics_decode_from_the_shared_component() {
        let request = decode_lmesh_tagged_request(&mesh::tagged::TaggedRecord {
            component: mesh::tagged::NameOrTag::Tag(7),
            method: mesh::tagged::NameOrTag::Tag(3),
            id: Some(serde_json::json!(3)),
            ..Default::default()
        })
        .unwrap();
        assert!(matches!(request, crate::mesh_core::Request::NanMetrics));
    }

    #[test]
    fn unreviewed_lmesh_method_cannot_enter_cbor_dispatch() {
        let error = decode_lmesh_tagged_request(&mesh::tagged::TaggedRecord {
            component: mesh::tagged::NameOrTag::Name("lmesh".to_owned()),
            method: mesh::tagged::NameOrTag::Name("neighbors".to_owned()),
            id: Some(serde_json::json!(3)),
            ..Default::default()
        })
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("outside the reviewed lmesh catalog")
        );
    }
}
