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
use tokio::net::UnixStream;
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

/// Project the canonical firmware method schema into ssh-mesh tool entries.
/// This keeps CLI and HTTP names, component/method tags, and field tags on one
/// source of truth without teaching the HTTP adapter about individual DMesh
/// operations.
fn firmware_stream_tools() -> Vec<serde_json::Value> {
    let schema: serde_json::Value =
        serde_json::from_str(include_str!("../../lmesh/resources/firmware-schema.json"))
            .expect("firmware-schema.json must be valid JSON");
    schema["methods"]
        .as_array()
        .expect("firmware schema methods must be an array")
        .iter()
        .filter_map(|method| {
            let component = method["component"].as_u64()?;
            let method_id = method["id"].as_u64()?;
            let name = method["name"].as_str()?;
            let mut properties = serde_json::Map::new();
            for field in method["fields"].as_array().into_iter().flatten() {
                let field_name = field["name"].as_str()?;
                let field_id = field["id"].as_u64()?;
                let value_type = match field["kind"].as_str() {
                    Some("bool") => "boolean",
                    Some("text" | "mac" | "hex") => "string",
                    _ => "integer",
                };
                let mut property = serde_json::json!({
                    "type": value_type,
                    "x-protobuf-index": field_id,
                });
                if field["kind"].as_str() == Some("hex") {
                    property["format"] = serde_json::json!("hex");
                }
                properties.insert(field_name.to_owned(), property);
            }
            Some(serde_json::json!({
                "name": name,
                "description": format!("Call the {name} QUIC stream handler"),
                "inputSchema": {"type": "object", "properties": properties},
                "outputSchema": {"type": "object"},
                "x-component-index": component,
                "x-method-index": method_id,
                "x-ui-visibility": method
                    .get("x-ui-visibility")
                    .cloned()
                    .unwrap_or_else(|| serde_json::json!("advanced")),
                // `x-check-all` is deliberately supplied by the versioned
                // firmware schema.  It makes the fleet report a catalog
                // consumer: only explicit, side-effect-free request shapes
                // are run against every discovered address.
                "x-check-all": method.get("x-check-all").cloned(),
                "x-check-all-platforms": method.get("x-check-all-platforms").cloned(),
            }))
        })
        .collect()
}

fn public_tools_json() -> serde_json::Value {
    let mut tools =
        serde_json::from_str::<serde_json::Value>(include_str!("../../lmesh/resources/tools.json"))
            .expect("shared tools.json must be valid JSON");
    // These controller methods terminate locally.  They deliberately have no
    // numeric wire tags: their operations retain host-owned circuit state and
    // use normal tagged QUIC streams for every remote relay or endpoint call.
    // Advertising them here lets the HTTP/UI bridge use the same JSON request
    // surface as the local UDS client without opening an unauthenticated
    // direct-message path on any mesh node.
    let local = serde_json::json!([
        {
            "name": "discovery.active",
            "description": "Send an active broadcast or directed discovery check",
            "inputSchema": {"type":"object", "properties": {
                "to":{"type":"string"},
                "timeout_ms":{"type":"integer", "minimum":100}
            }},
            "outputSchema":{"type":"object"}, "x-ui-visibility":"default"
        },
        {
            "name": "probe",
            "description": "Run the normal QUIC probe stream to a routed node",
            "inputSchema": {"type":"object", "required":["to"], "properties": {
                "to":{"type":"string"},
                "bytes":{"type":"integer", "minimum":1},
                "packet_size":{"type":"integer", "minimum":8},
                "timeout_ms":{"type":"integer", "minimum":100}
            }},
            "outputSchema":{"type":"object"}, "x-ui-visibility":"advanced"
        },
        {
            "name": "relay.connect",
            "description": "Create the first relay leg through a directly reachable relay",
            "inputSchema": {"type":"object", "required":["relay_endpoint", "next_hop_mac"], "properties": {
                "relay_endpoint":{"type":"string"}, "next_hop_mac":{"type":"string"}
            }},
            "outputSchema":{"type":"object"}, "x-ui-visibility":"default"
        },
        {
            "name": "relay.open",
            "description": "Open and verify the endpoint QUIC connection through a retained relay leg",
            "inputSchema": {"type":"object", "required":["relay_endpoint"], "properties": {
                "relay_endpoint":{"type":"string"}
            }},
            "outputSchema":{"type":"object"}, "x-ui-visibility":"default"
        },
        {
            "name": "relay.endpoint.status",
            "description": "Read endpoint status through a completed relay circuit",
            "inputSchema": {"type":"object", "required":["relay_endpoint"], "properties": {
                "relay_endpoint":{"type":"string"}
            }},
            "outputSchema":{"type":"object"}, "x-ui-visibility":"default"
        },
        {
            "name": "relay.close",
            "description": "Remove one retained relay circuit and its relay pair",
            "inputSchema": {"type":"object", "required":["relay_endpoint"], "properties": {
                "relay_endpoint":{"type":"string"}
            }},
            "outputSchema":{"type":"object"}, "x-ui-visibility":"default"
        },
        {
            "name": "relay.status",
            "description": "List retained local relay circuits",
            "inputSchema":{"type":"object"}, "outputSchema":{"type":"object"}, "x-ui-visibility":"default"
        }
    ]);
    let tools = tools
        .as_array_mut()
        .expect("shared tools.json must be an array");
    let mut known = tools
        .iter()
        .filter_map(|tool| tool["name"].as_str().map(str::to_owned))
        .collect::<std::collections::BTreeSet<_>>();
    for tool in firmware_stream_tools().into_iter().chain(
        local
            .as_array()
            .expect("local tool list must be an array")
            .iter()
            .cloned(),
    ) {
        let Some(name) = tool["name"].as_str() else {
            continue;
        };
        if known.insert(name.to_owned()) {
            tools.push(tool);
        }
    }
    serde_json::Value::Array(tools.clone())
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
    // Multicast discovery is intentionally the separate shared 5227 socket.
    // Normal QUIC and directed-check traffic starts below on the service port.
    discovery.start().await?;
    let discovery = Arc::new(discovery);
    let service = Arc::new(LmeshService::new(discovery.clone()));
    // Netlink is only an advisory hint. A base-device event waits for the USB
    // driver to settle, then runs the same presence-edge check as the periodic
    // fallback. AP, monitor, carrier, and P2P events are ignored.
    let owned_interfaces = service.wifi_owned_interfaces();
    let owned_base_interfaces = owned_interfaces.names().to_vec();
    let owns_wifi = !owned_base_interfaces.is_empty();
    let (link_events, mut link_event_rx) = tokio::sync::mpsc::unbounded_channel();
    std::thread::spawn(move || {
        lmesh_wifi::recovery::watch_link_events(owned_interfaces, link_events)
    });
    let recovery_service = service.clone();
    tokio::spawn(async move {
        while let Some(event) = link_event_rx.recv().await {
            let is_base = event
                .iface
                .as_deref()
                .is_some_and(|iface| owned_base_interfaces.iter().any(|owned| owned == iface));
            if !is_base {
                continue;
            }
            sleep(Duration::from_secs(30)).await;
            let result = recovery_service.reconcile_wifi_health();
            if result.get("state").and_then(serde_json::Value::as_str)
                == Some("reappeared_reinitialized")
            {
                warn!(?event, ?result, "lmesh_wifi_reappeared_reinitialized");
            }
        }
    });
    let presence_service = service.clone();
    tokio::spawn(async move {
        // Establish the initial presence state without disturbing an already
        // initialized radio, then provide a five-minute fallback for missed
        // USB/netlink events.
        let _ = presence_service.reconcile_wifi_health();
        loop {
            sleep(Duration::from_secs(5 * 60)).await;
            let result = presence_service.reconcile_wifi_health();
            if result.get("state").and_then(serde_json::Value::as_str)
                == Some("reappeared_reinitialized")
            {
                warn!(?result, "lmesh_wifi_periodic_reappeared_reinitialized");
            }
        }
    });
    let udp_started = service.start_udp_tagged_handler(
        defaults.udp_port,
        Arc::new(dmesh_server::udp::CanonicalTaggedStreamHandler::new(
            Arc::new(LmeshCborHandler {
                service: service.clone(),
            }),
        )),
    );
    if udp_started.get("ok").and_then(serde_json::Value::as_bool) == Some(true) {
        if let Some(socket) = service.udp_listener_socket() {
            discovery.set_shared_udp_socket(socket);
        } else {
            warn!("normal UDP listener started without an outbound socket handle");
        }
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
    if owns_wifi {
        match service.refresh_active_nan_publish(0) {
            Ok(status) => debug!(?status, "rawnan_active_publish_configured"),
            Err(error) => warn!(%error, "rawnan_active_publish_configure_failed"),
        }
        let channel = raw_wifi_channel();
        // A Wi-Fi-owning launcher may opt into its local P2P/NAN fixture. The
        // UDP-only lmesh companion never enters this branch.
        let p2p_started = service.start_default_p2p_go(channel);
        if p2p_started.get("ok").and_then(serde_json::Value::as_bool) == Some(true) {
            debug!(?p2p_started, channel, "lmesh_default_p2p_nan_started");
        } else {
            warn!(?p2p_started, channel, "lmesh_default_p2p_nan_start_failed");
        }
    } else {
        debug!("lmesh_udp_only_no_wifi_owner");
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
    if owns_wifi {
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
    }

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
            .handle_request(crate::mesh_core::Request::DiscoveryActive {
                medium: None,
                to: None,
            })
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
    if value.get("to").is_none() || keeps_to_as_local_argument(&value) {
        return Ok(None);
    }
    let record = tagged_record_from_jsonl(&value)?;
    let handler = LmeshCborHandler { service };
    let response = mesh::wire::TaggedRecordHandler::forward_record(&handler, record)
        .await?
        .context("directed UDS request produced no response")?;
    Ok(Some(CONTROL_CATALOG.to_jsonl(&response)))
}

/// Most `to` fields select a remote QUIC destination at the JSONL boundary.
/// Active discovery and probe are deliberately different: their `to` selects
/// the local association path under test, so `LmeshService` must execute the
/// corresponding client operation rather than forward that controller method
/// as a remote tagged record.
fn keeps_to_as_local_argument(value: &serde_json::Value) -> bool {
    matches!(
        value.get("method").and_then(serde_json::Value::as_str),
        Some("discovery.active" | "lmesh.discovery.active" | "probe" | "lmesh.probe")
    )
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
    let config = dmesh_server::http::HttpConfig {
        bind: std::net::SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, port)),
        node,
        client_manager: manager,
        service: dmesh_server::http::HttpService {
            name: "lmesh".to_owned(),
            backend: ssh_mesh::mesh_rest::MeshServiceBackend::Uds(PathBuf::from(socket)),
            catalog: Some(public_tools_json()),
        },
        web_root: http_web_root("LMESH_HTTP_WEB_DIR"),
    };
    tokio::spawn(async move {
        if let Err(error) = dmesh_server::http::serve(config).await {
            error!(%error, "lmesh_http_admin_terminated");
        }
    });
    debug!(port, "lmesh_http_admin_started");
    Ok(())
}

/// Serve the LMesh-owned dashboard before falling back to generic ssh-mesh
/// admin assets. Keeping the discovery UI in `crates/lmesh/web` lets DMesh
/// evolve its device/transport presentation without making ssh-mesh depend on
/// DMesh or accepting an upstream asset change. `LMESH_HTTP_WEB_DIR` remains
/// an explicit runtime override for packaged deployments and UI iteration.
fn http_web_root(service_env: &str) -> Option<PathBuf> {
    std::env::var_os(service_env)
        .or_else(|| std::env::var_os("MESH_HTTP_WEB_DIR"))
        .map(PathBuf::from)
        .or_else(|| Some(default_http_web_root()))
}

fn default_http_web_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("lmesh-wifi crate has a parent directory")
        .join("lmesh/web")
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

impl dmesh_server::udp::TaggedApplicationHandler for LmeshCborHandler {
    fn handle_tagged<'a>(
        &'a self,
        _context: dmesh_server::udp::TaggedStreamContext,
        request: Vec<u8>,
    ) -> Pin<Box<dyn Future<Output = Option<Vec<u8>>> + Send + 'a>> {
        Box::pin(async move {
            let record = mesh::cbor::decode_record(&request).ok()?;
            // Component 9 belongs to the connection owner.  In particular,
            // its event history is per QUIC association, so projecting it
            // through lmesh's process-local JSON request enum would both
            // lose that context and shadow the shared diagnostic terminal.
            // Declining here lets `dmesh_server::udp` call the common
            // connection-aware handler after this application adapter.
            if is_connection_diagnostic(&record) {
                return None;
            }
            let response = mesh::wire::TaggedRecordHandler::handle_record(self, record)
                .await
                .ok()??;
            mesh::cbor::encode_record(&response).ok()
        })
    }
}

fn is_connection_diagnostic(record: &mesh::tagged::TaggedRecord) -> bool {
    let (mesh::tagged::NameOrTag::Tag(component), mesh::tagged::NameOrTag::Tag(method)) =
        (&record.component, &record.method)
    else {
        return false;
    };
    *component == dmesh_server::services::DIAGNOSTIC_COMPONENT as u32
        && matches!(
            *method as u64,
            dmesh_server::services::DIAGNOSTIC_STATUS_METHOD
                | dmesh_server::services::DIAGNOSTIC_SERVICES_METHOD
                | dmesh_server::services::DIAGNOSTIC_METRICS_METHOD
                | dmesh_server::services::DIAGNOSTIC_EVENTS_METHOD
                | dmesh_server::services::DIAGNOSTIC_LOG_WATCH_METHOD
        )
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
        // `to` normally selects a remote QUIC destination.  For the active
        // discovery service it instead identifies the exact local bearer
        // path under test, so preserve it for `Request::DiscoveryActive`.
        if record_keeps_to_as_local_argument(&record) {
            return self.handle_record(record).await;
        }
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
        let wire = raw_wifi_tx_wire(&record, &id)?.unwrap_or(mesh::cbor::encode_record(&record)?);
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
                // Preserve the frame-adapter cause (including its bounded
                // transmit/receive and QUIC bootstrap counters) in the HTTP
                // result.  The outer context alone cannot distinguish a
                // handler problem from a path/connection failure.
                serde_json::json!({"error": format!("{error:#}"), "to": destination}),
            ))),
        }
    }
}

/// Encode the one raw-frame handler through DMesh's shared adapter. JSON and
/// text use `hex:` only at this boundary; the forwarded tagged-CBOR record
/// contains the compact byte string expected by firmware.
fn raw_wifi_tx_wire(
    record: &mesh::tagged::TaggedRecord,
    id: &serde_json::Value,
) -> Result<Option<Vec<u8>>> {
    let is_tx = matches!(
        (&record.component, &record.method),
        (
            mesh::tagged::NameOrTag::Tag(4),
            mesh::tagged::NameOrTag::Tag(71)
        )
    );
    if !is_tx {
        return Ok(None);
    }
    let id = id
        .as_u64()
        .context("radio.tx request ID must be an unsigned integer")?;
    let mut fields = serde_json::Map::new();
    for (key, value) in &record.env {
        let name = match key {
            mesh::tagged::NameOrTag::Tag(1) => "frame",
            mesh::tagged::NameOrTag::Tag(2) => "channel",
            mesh::tagged::NameOrTag::Tag(3) => "interface",
            mesh::tagged::NameOrTag::Tag(4) => "system_sequence",
            mesh::tagged::NameOrTag::Tag(5) => "rate",
            mesh::tagged::NameOrTag::Tag(6) => "disable_11b",
            _ => anyhow::bail!("unknown radio.tx field"),
        };
        fields.insert(name.to_owned(), value.clone());
    }
    let mut wire = vec![0; dmesh_server::raw_wifi::RAW_WIFI_MAX_FRAME + 64];
    let used = dmesh_server::raw_wifi::encode_raw_wifi_tx_json_request(&fields, id, &mut wire)?;
    wire.truncate(used);
    Ok(Some(wire))
}

fn record_keeps_to_as_local_argument(record: &mesh::tagged::TaggedRecord) -> bool {
    matches!(
        decode_lmesh_tagged_request(record),
        Ok(crate::mesh_core::Request::DiscoveryActive { .. }
            | crate::mesh_core::Request::Probe { .. })
    )
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
        "discovery.active" => serde_json::from_value(value),
        "discovery.status" => Ok(crate::mesh_core::Request::DiscoveryStatus),
        "telemetry.nan_status" => Ok(crate::mesh_core::Request::NanStatus),
        "telemetry.now_metrics" => Ok(crate::mesh_core::Request::NowMetrics),
        "telemetry.nan_metrics" => Ok(crate::mesh_core::Request::NanMetrics),
        "telemetry.udp6_metrics" => Ok(crate::mesh_core::Request::Udp6Metrics),
        "telemetry.wifi_link_metrics" => Ok(crate::mesh_core::Request::WifiLinkMetrics),
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
    fn default_http_assets_are_owned_by_lmesh() {
        let root = default_http_web_root();
        assert!(root.ends_with("crates/lmesh/web"));
        assert!(root.join("index.html").is_file());
        assert!(root.join("dashboard.html").is_file());
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
        assert!(visible.contains(&"discovery.active"));
        assert!(visible.contains(&"transport.set"));
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
        assert!(names.contains(&"probe"));
        assert!(names.contains(&"telemetry.nan_status"));
        assert!(names.contains(&"settings.get"));
        assert!(names.contains(&"settings.set"));
        assert!(names.contains(&"settings.list"));
        assert!(names.contains(&"radio.snapshot"));
        assert!(names.contains(&"radio.control"));
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
            "wifi.raw.send",
            "wifi.raw.ping",
            "wifi.raw.check",
        ] {
            assert!(
                !names.contains(&retired),
                "retired method {retired} remains catalogued"
            );
        }
    }

    #[test]
    fn catalog_declares_the_safe_fleet_stream_matrix() {
        let catalog = public_tools_json();
        let selected = catalog
            .as_array()
            .unwrap()
            .iter()
            .filter(|tool| {
                tool.get("x-check-all")
                    .is_some_and(serde_json::Value::is_object)
            })
            .filter_map(|tool| tool["name"].as_str())
            .collect::<std::collections::BTreeSet<_>>();

        let expected = [
            "discovery.nodes",
            "events",
            "log-watch",
            "memory.snapshot",
            "metrics",
            "power.snapshot",
            "probe",
            "radio.snapshot",
            "relay.list",
            "runtime.snapshot",
            "services",
            "settings.get",
            "settings.list",
            "status",
            "telemetry.nan_metrics",
            "telemetry.nan_status",
            "telemetry.now_metrics",
            "telemetry.udp6_metrics",
            "telemetry.wifi_link_metrics",
            "wifi.scan",
        ]
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(selected, expected);
        let probe = catalog
            .as_array()
            .unwrap()
            .iter()
            .find(|tool| tool["name"] == "probe")
            .expect("probe must be catalogued for fleet checks");
        assert_eq!(
            probe["x-check-all"],
            serde_json::json!({"bytes": 65536, "packet_size": 1024, "parallel_streams": 1})
        );
        assert_eq!(
            probe["x-check-all-platforms"],
            serde_json::json!(["esp32", "host", "android"])
        );
        for tool in catalog.as_array().unwrap().iter().filter(|tool| {
            tool.get("x-check-all")
                .is_some_and(serde_json::Value::is_object)
        }) {
            assert!(
                tool.get("x-check-all-platforms")
                    .and_then(serde_json::Value::as_array)
                    .is_some_and(|platforms| !platforms.is_empty()),
                "{} needs an explicit supported-platform list",
                tool["name"].as_str().unwrap_or("unnamed")
            );
        }
    }

    #[test]
    fn common_numeric_transport_set_decodes_for_local_or_directed_use() {
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
            crate::mesh_core::Request::TransportSet {
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
    fn connection_diagnostics_bypass_the_lmesh_application_adapter() {
        for method in [
            dmesh_server::services::DIAGNOSTIC_STATUS_METHOD,
            dmesh_server::services::DIAGNOSTIC_SERVICES_METHOD,
            dmesh_server::services::DIAGNOSTIC_METRICS_METHOD,
            dmesh_server::services::DIAGNOSTIC_EVENTS_METHOD,
            dmesh_server::services::DIAGNOSTIC_LOG_WATCH_METHOD,
        ] {
            assert!(is_connection_diagnostic(&mesh::tagged::TaggedRecord {
                component: mesh::tagged::NameOrTag::Tag(
                    dmesh_server::services::DIAGNOSTIC_COMPONENT as u32,
                ),
                method: mesh::tagged::NameOrTag::Tag(method as u32),
                id: Some(serde_json::json!(7)),
                ..Default::default()
            }));
        }
        assert!(!is_connection_diagnostic(&mesh::tagged::TaggedRecord {
            component: mesh::tagged::NameOrTag::Tag(7),
            method: mesh::tagged::NameOrTag::Tag(3),
            id: Some(serde_json::json!(7)),
            ..Default::default()
        }));
    }

    #[test]
    fn diagnostic_fields_use_the_shared_tagged_fields_map() {
        let record = CONTROL_CATALOG
            .record_from_value("events", &serde_json::json!({"since": 0}))
            .unwrap();
        let wire = mesh::cbor::encode_record(&record).unwrap();
        let record = dmesh_server::tagged::decode(&wire).unwrap();
        assert_eq!(
            record.component,
            Some(dmesh_server::tagged::Name::Tag(
                dmesh_server::services::DIAGNOSTIC_COMPONENT
            ))
        );
        assert_eq!(
            record.method,
            Some(dmesh_server::tagged::Name::Tag(
                dmesh_server::services::DIAGNOSTIC_EVENTS_METHOD
            ))
        );
        assert!(record.params.is_none());
        let fields = record.fields.unwrap();
        let mut decoder = dmesh_server::cbor::Decoder::new(fields);
        assert_eq!(decoder.head(), Some((5, 1)));
        assert_eq!(decoder.uint(), Some(1));
        assert_eq!(decoder.uint(), Some(0));
        assert!(decoder.is_finished());
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

    #[test]
    fn active_discovery_keeps_its_explicit_path_local() {
        assert!(keeps_to_as_local_argument(&serde_json::json!({
            "method": "discovery.active",
            "to": "udp://[fe80::44]:3339"
        })));
        assert!(keeps_to_as_local_argument(&serde_json::json!({
            "method": "lmesh.discovery.active",
            "to": "02:00:00:00:00:44"
        })));
        assert!(keeps_to_as_local_argument(&serde_json::json!({
            "method": "probe",
            "to": "e7",
            "bytes": 4096
        })));
        assert!(!keeps_to_as_local_argument(&serde_json::json!({
            "method": "telemetry.nan_metrics",
            "to": "udp://[fe80::44]:3339"
        })));

        let mut record = CONTROL_CATALOG
            .record_from_value("discovery.active", &serde_json::json!({}))
            .unwrap();
        record.id = Some(serde_json::json!(1));
        record.to = Some(serde_json::json!("udp://[fe80::44]:3339"));
        assert!(record_keeps_to_as_local_argument(&record));
    }

    #[test]
    fn radio_tx_ui_and_forwarder_share_a_byte_frame_encoder() {
        let catalog = public_tools_json();
        let tool = catalog
            .as_array()
            .unwrap()
            .iter()
            .find(|tool| tool["name"] == "radio.tx")
            .unwrap();
        assert_eq!(tool["inputSchema"]["properties"]["frame"]["type"], "string");
        assert_eq!(tool["inputSchema"]["properties"]["frame"]["format"], "hex");

        let record = tagged_record_from_jsonl(&serde_json::json!({
            "id": 43,
            "to": "e9",
            "method": "radio.tx",
            "frame": "hex:d000ffffffff00112233445566778899aabbccddeeff00112233445566",
            "channel": 6,
            "interface": 1,
            "rate": 6,
        }))
        .unwrap();
        let wire = raw_wifi_tx_wire(&record, record.id.as_ref().unwrap())
            .unwrap()
            .unwrap();
        let request = dmesh_server::raw_wifi::decode_raw_wifi_tx_record(
            dmesh_server::tagged::decode(&wire).unwrap(),
        )
        .unwrap();
        assert_eq!(request.channel, 6);
        assert_eq!(request.frame[0], 0xd0);
    }
}
