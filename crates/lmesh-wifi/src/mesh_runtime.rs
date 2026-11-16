use std::{
    path::PathBuf,
    sync::{Arc, LazyLock},
    time::Instant,
};

use crate::mesh_core::{LmeshService, LocalDiscovery};
use crate::rpc_router::{
    AcceptedStream, Call, CallContext, Handler, LocalOnly, Method, MethodStreamHandler,
    OpenStreamFuture, Registry, RegistryStreamHandler, Reply, StreamHandler, StreamOutcome,
    TypedHandler, methods,
};
use anyhow::{Context, Result};
use tokio::time::{Duration, sleep};
use tracing::{debug, error, warn};

/// Keep host multicast presence aligned with NAN/NOW/ESP refreshes. Operators
/// may still override this through `LMESH_ANNOUNCE_INTERVAL_SECS`.
const DEFAULT_ANNOUNCE_INTERVAL_SECS: u64 = 5 * 60;
const ANNOUNCE_INTERVAL_ENV: &str = "LMESH_ANNOUNCE_INTERVAL_SECS";
const RAW_WIFI_CHANNEL_ENV: &str = "LMESH_RAW_WIFI_CHANNEL";
const MUX_TCP_ENV: &str = "LMESH_MUX_TCP";
const MUX_UDS_ENV: &str = "LMESH_MUX_UDS";

/// Process-local endpoints for a Linux mesh service.
///
/// These are code defaults, deliberately selected by each binary rather than
/// injected through environment variables.  Deployment configuration may still
/// control radio interfaces and credentials, but not the identity of the
/// control/admin endpoints.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeDefaults {
    pub control_socket: &'static str,
    /// Local `quic-mux` Unix stream socket (`""` disables it unless `LMESH_MUX_UDS` overrides).
    pub mux_socket: &'static str,
    pub http_port: u16,
    /// Normal unicast object/QUIC-lite listener: the one DMesh UDP port every platform
    /// (ESP32, Android, Linux) serves, so a peer needs no per-platform port. A client such
    /// as `dmesh-cli` binds an ephemeral port instead of this one.
    pub udp_port: u16,
    /// `quic-mux` TCP stream listener port (`5229`, matching ESP `mod_mux` `--stream 4`; `0` disables unless `LMESH_MUX_TCP` overrides).
    pub mux_tcp_port: u16,
}

/// Stable endpoints for the Linux mesh daemon.
pub const LMESH_DEFAULTS: RuntimeDefaults = RuntimeDefaults {
    control_socket: "/run/mesh/lmesh/mesh.sock.cbor",
    mux_socket: "/run/mesh/lmesh/mesh.mux.sock",
    http_port: 18981,
    udp_port: 3339,
    mux_tcp_port: 5229,
};

static COMMON_REGISTRY: LazyLock<mesh::registry::ServiceRegistry> =
    LazyLock::new(|| mesh::registry::ServiceRegistry::new("lmesh"));

/// Resolve the installed lmesh schema catalog dynamically from disk via the
/// shared `CatalogResolver` (re-reading automatically if the file changes).
fn resolve_lmesh_catalog() -> Result<Arc<mesh::catalog::ResolvedCatalog>> {
    if let Some(resolved) = mesh::catalog::service_catalog_resolver().resolve("lmesh") {
        return resolved;
    }
    #[cfg(test)]
    {
        let dev_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../lmesh/resources/tools.json");
        if dev_path.is_file() {
            return mesh::catalog::service_catalog_resolver().load_path("lmesh", dev_path);
        }
    }
    mesh::catalog::service_catalog_resolver().require("lmesh")
}

/// Registers an executable's own handlers (for example a bearer it owns) with
/// the service registry. It receives this node's compressed P-256 public key,
/// the default control-plane root a pairing installs.
pub type RegistryExtension =
    Box<dyn FnOnce(&Registry, &[u8], &Arc<LocalDiscovery>) + Send>;

/// Who owns the Wi-Fi radio. `Internal` is this crate's `RadioService` (the
/// experimental AP/NAN/NOW stack). `External` means the executable runs the radio
/// itself (`rawnan`'s raw bearer) and registers every radio-facing method; this crate
/// then neither starts the radio nor registers those methods.
pub enum RadioOwner {
    Internal(Arc<dyn crate::espnow_bearer::EspNowIngress>),
    External,
}

/// Run the shared Linux mesh control plane.
pub async fn run_mesh_service(
    defaults: RuntimeDefaults,
    now_mux: Option<quic_mux::TokioMux>,
    mux_acceptors: Vec<quic_mux::TokioMuxAcceptor>,
    radio: RadioOwner,
    extend: RegistryExtension,
) -> Result<()> {
    let (trace_buffer, _trace_guard) = mesh::local_trace::init("lmesh");
    mesh::local_trace::serve("lmesh", trace_buffer.clone());
    if let Err(error) = run_server(defaults, now_mux, mux_acceptors, radio, extend).await {
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
    defaults: RuntimeDefaults,
    now_mux: Option<quic_mux::TokioMux>,
    mux_acceptors: Vec<quic_mux::TokioMuxAcceptor>,
    radio: RadioOwner,
    extend: RegistryExtension,
) -> Result<()> {
    crate::mesh_core::note_service_started();
    let external_radio = matches!(radio, RadioOwner::External);
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
    if let Some(mux) = now_mux {
        service.set_now_mux(mux);
    }
    if let RadioOwner::Internal(ingress) = radio {
        service.set_espnow_ingress(ingress);
    }
    // Netlink is only an advisory hint. A base-device event waits for the USB
    // driver to settle, then runs the same presence-edge check as the periodic
    // fallback. AP, monitor, carrier, and P2P events are ignored.
    let owned_interfaces = service.wifi_owned_interfaces();
    let owned_base_interfaces = owned_interfaces.names().to_vec();
    let owns_wifi = !owned_base_interfaces.is_empty() && !external_radio;
    if owns_wifi {
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
    }
    // One registry serves both the QUIC streams and the control socket.
    let public_key = discovery.public_key_bytes().to_vec();
    let extension_discovery = discovery.clone();
    let cbor_handler = LmeshCborHandler::new(service.clone(), external_radio, move |registry| {
        extend(registry, &public_key, &extension_discovery)
    });
    // QUIC streams route passive `ComponentDirectory` components first (single-pass
    // envelope decode + lazy activation) and fall back to `RegistryStreamHandler`
    // for legacy numeric methods. A text-named common ssh-mesh method is numbered
    // at the edge before fallback dispatch.
    let udp_fallback = Arc::new(
        RegistryStreamHandler::new(cbor_handler.registry.clone())
            .with_header_rewrite(number_common_names_in_header),
    );
    let mux_net_fallback = udp_fallback.clone();
    let mux_local_fallback = Arc::new(
        RegistryStreamHandler::new(cbor_handler.registry.clone())
            .local()
            .with_header_rewrite(number_common_names_in_header),
    );
    let udp_handler = Arc::new(LmeshNodeStreamHandler {
        components: cbor_handler.components.clone(),
        fallback: udp_fallback,
    });
    for mut acceptor in mux_acceptors {
        let udp_handler = udp_handler.clone();
        tokio::task::spawn_local(async move {
            while let Some(mut stream) = acceptor.accept().await {
                if let Err(error) = udp_handler.accept(&mut stream).await {
                    warn!(%error, "lmesh_quic_stream_failed");
                }
            }
        });
    }
    debug!(port = defaults.udp_port, "lmesh_quic_node_started");
    if let Some(mux_tcp_addr) = resolve_mux_tcp_bind(defaults)? {
        let tcp_listener = bind_mux_tcp_listener(mux_tcp_addr).await?;
        let local_addr = tcp_listener.local_addr().unwrap_or(mux_tcp_addr);
        tokio::spawn(serve_component_mux_tcp_listener(
            tcp_listener,
            cbor_handler.components.clone(),
            mux_net_fallback,
        ));
        debug!(addr = %local_addr, "lmesh_mux_tcp_started");
    }
    if let Some(mux_uds_path) = resolve_mux_uds_path(defaults)? {
        let uds_listener = bind_mux_uds_listener(&mux_uds_path).await?;
        tokio::spawn(serve_component_mux_uds_listener(
            uds_listener,
            cbor_handler.components.clone(),
            mux_local_fallback,
        ));
        debug!(path = %mux_uds_path.display(), "lmesh_mux_uds_started");
    }
    // The validated multicast observation updates this daemon's radio inventory.
    let announce_service = service.clone();
    discovery
        .set_announce_observer(Arc::new(move |peer, announce| {
            announce_service.observe_multicast_announce(peer, announce);
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
        // A Wi-Fi-owning lmesh launcher may opt into its local P2P/NAN fixture.
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
    let cbor_path = listen_path;
    if std::path::Path::new(&cbor_path).exists() {
        anyhow::ensure!(
            mesh::seqpacket::UnixSeqpacket::connect(&cbor_path)
                .await
                .is_err(),
            "lmesh control socket {cbor_path} is already active"
        );
    }
    if let Err(error) = std::fs::remove_file(&cbor_path)
        && error.kind() != std::io::ErrorKind::NotFound
    {
        return Err(error).with_context(|| format!("remove stale {cbor_path}"));
    }
    let listener = mesh::seqpacket::UnixSeqpacketListener::bind(&cbor_path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&cbor_path, std::fs::Permissions::from_mode(0o660))?;
    }
    // lmesh is the local control-plane endpoint. Once its UDS listener is
    // ready, actively ask every enabled bearer for current peer presence.
    // This complements (rather than replaces) the boot/periodic multicast
    // announcement above: it prompts NAN/NOW peers to publish immediately
    // and sends the matching UDP6 multicast announce.
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
    loop {
        let stream = listener.accept().await.context("lmesh CBOR accept")?;
        let handler = cbor_handler.clone();
        tokio::spawn(async move {
            if let Err(error) = handle_seqpacket_connection(stream, handler).await {
                error!(%error, "lmesh_cbor_connection_error");
            }
        });
    }
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

fn is_disabled_endpoint_value(value: &str) -> bool {
    let trimmed = value.trim();
    trimmed.is_empty()
        || trimmed == "0"
        || trimmed.eq_ignore_ascii_case("none")
        || trimmed.eq_ignore_ascii_case("off")
}

fn parse_mux_tcp_override(value: &str) -> Result<Option<std::net::SocketAddr>> {
    let trimmed = value.trim();
    if is_disabled_endpoint_value(trimmed) {
        return Ok(None);
    }
    if let Ok(port) = trimmed.parse::<u16>() {
        return Ok((port != 0).then(|| {
            std::net::SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, port))
        }));
    }
    let addr = trimmed
        .parse::<std::net::SocketAddr>()
        .with_context(|| format!("invalid {MUX_TCP_ENV} address {trimmed:?}"))?;
    Ok(Some(addr))
}

fn resolve_mux_tcp_bind(defaults: RuntimeDefaults) -> Result<Option<std::net::SocketAddr>> {
    if let Ok(raw) = std::env::var(MUX_TCP_ENV) {
        return parse_mux_tcp_override(&raw);
    }
    Ok((defaults.mux_tcp_port != 0).then(|| {
        std::net::SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, defaults.mux_tcp_port))
    }))
}

fn resolve_mux_uds_path(defaults: RuntimeDefaults) -> Result<Option<PathBuf>> {
    let raw = std::env::var(MUX_UDS_ENV).unwrap_or_else(|_| defaults.mux_socket.to_owned());
    let trimmed = raw.trim();
    if is_disabled_endpoint_value(trimmed) {
        return Ok(None);
    }
    Ok(Some(resolve_relative_path(PathBuf::from(trimmed))?))
}

/// Bind a TCP listener for `quic-mux`, falling back to `0.0.0.0` if `[::]` is unavailable.
pub async fn bind_mux_tcp_listener(addr: std::net::SocketAddr) -> Result<tokio::net::TcpListener> {
    match tokio::net::TcpListener::bind(addr).await {
        Ok(listener) => Ok(listener),
        Err(err) if addr.ip() == std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED) => {
            let v4 = std::net::SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, addr.port()));
            tokio::net::TcpListener::bind(v4)
                .await
                .with_context(|| format!("bind lmesh mux TCP listener on {addr} (and {v4}): {err}"))
        }
        Err(err) => Err(err).with_context(|| format!("bind lmesh mux TCP listener on {addr}")),
    }
}

/// Bind a local Unix stream listener for `quic-mux`, refusing to clobber an active daemon socket.
pub async fn bind_mux_uds_listener(path: &std::path::Path) -> Result<tokio::net::UnixListener> {
    if path.exists() {
        anyhow::ensure!(
            tokio::net::UnixStream::connect(path).await.is_err(),
            "lmesh mux socket {} is already active",
            path.display()
        );
    }
    if let Err(error) = std::fs::remove_file(path)
        && error.kind() != std::io::ErrorKind::NotFound
    {
        return Err(error).with_context(|| format!("remove stale {}", path.display()));
    }
    let listener = tokio::net::UnixListener::bind(path)
        .with_context(|| format!("bind lmesh mux socket {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))?;
    }
    Ok(listener)
}

/// Serve one `quic-mux` byte-stream bearer (`TcpStream` or `UnixStream`), dispatching every
/// peer-opened [`quic_mux::MuxStream`] through `handler`.
pub async fn serve_mux_stream_connection<S>(
    stream: S,
    handler: Arc<RegistryStreamHandler>,
    config: quic_mux::TokioMuxConfig,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + 'static,
{
    let (mux, mut acceptor) = quic_mux::TokioMux::server(stream, config);
    while let Some(mut mux_stream) = acceptor.accept().await {
        let h = handler.clone();
        tokio::spawn(async move {
            if let Err(error) = h.serve(&mut mux_stream).await {
                warn!(%error, "lmesh_mux_stream_failed");
            }
        });
    }
    drop(mux);
}

/// Alias for [`serve_mux_stream_connection`] dispatching peer-opened [`quic_mux::MuxStream`]s
/// on a `quic-mux` connection through `handler`.
pub async fn serve_mux_connection<S>(
    stream: S,
    handler: Arc<RegistryStreamHandler>,
    config: quic_mux::TokioMuxConfig,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + 'static,
{
    serve_mux_stream_connection(stream, handler, config).await;
}

/// Accept `quic-mux` connections on `listener` and dispatch peer streams through `handler`.
pub async fn serve_mux_tcp_listener(
    listener: tokio::net::TcpListener,
    handler: Arc<RegistryStreamHandler>,
) {
    loop {
        match listener.accept().await {
            Ok((stream, _peer)) => {
                let _ = stream.set_nodelay(true);
                let h = handler.clone();
                tokio::spawn(async move {
                    serve_mux_stream_connection(stream, h, quic_mux::TokioMuxConfig::default())
                        .await;
                });
            }
            Err(error) => {
                warn!(%error, "lmesh_mux_tcp_accept_failed");
                sleep(Duration::from_millis(50)).await;
            }
        }
    }
}

/// Accept local `quic-mux` connections on `listener` and dispatch peer streams through `handler`.
pub async fn serve_mux_uds_listener(
    listener: tokio::net::UnixListener,
    handler: Arc<RegistryStreamHandler>,
) {
    loop {
        match listener.accept().await {
            Ok((stream, _peer)) => {
                let h = handler.clone();
                tokio::spawn(async move {
                    serve_mux_stream_connection(stream, h, quic_mux::TokioMuxConfig::default())
                        .await;
                });
            }
            Err(error) => {
                warn!(%error, "lmesh_mux_uds_accept_failed");
                sleep(Duration::from_millis(50)).await;
            }
        }
    }
}

/// Serve one `MeshStream` (`quic_mux::MuxStream`, TCP, or UDS): decode the opening envelope
/// in a single pass, route passively registered components through [`mesh::ComponentDirectory`]
/// (activating on demand), and rewind into `fallback` for legacy numeric methods.
pub async fn serve_component_mux_stream<S>(
    mut stream: S,
    components: &mesh::ComponentDirectory,
    fallback: &RegistryStreamHandler,
) -> Result<()>
where
    S: mesh::MeshStream + 'static,
{
    let (envelope, framed) = match mesh::read_envelope_prefix(&mut stream).await {
        Ok(parts) => parts,
        Err(error) => {
            if error.kind() == std::io::ErrorKind::InvalidData {
                let _ = tokio::io::AsyncWriteExt::write_all(
                    &mut stream,
                    &mesh::mesh_api::envelope::encode_error_header(
                        None,
                        b"invalid stream envelope header",
                    ),
                )
                .await;
                let _ = tokio::io::AsyncWriteExt::shutdown(&mut stream).await;
            }
            return Err(error.into());
        }
    };
    let is_component = envelope
        .component()
        .is_some_and(|comp| components.has_component(comp));
    if is_component {
        let (_, remaining) = framed.into_parts();
        let boxed: Box<dyn mesh::MeshStream> = Box::new(stream);
        let framed_owned = mesh::FramedStream::new(boxed, remaining);
        return components.serve_framed_stream(envelope, framed_owned).await;
    }
    let mut rewound = mesh::rewind_envelope(envelope, framed);
    fallback.serve(&mut rewound).await.map_err(Into::into)
}

/// Serve one `quic-mux` connection, routing peer streams through `components` first and
/// falling back to `fallback` for legacy numeric methods.
pub async fn serve_component_mux_connection<S>(
    stream: S,
    components: Arc<mesh::ComponentDirectory>,
    fallback: Arc<RegistryStreamHandler>,
    config: quic_mux::TokioMuxConfig,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + 'static,
{
    let (mux, mut acceptor) = quic_mux::TokioMux::server(stream, config);
    while let Some(mux_stream) = acceptor.accept().await {
        let c = components.clone();
        let f = fallback.clone();
        tokio::spawn(async move {
            if let Err(error) = serve_component_mux_stream(mux_stream, &c, &f).await {
                warn!(%error, "lmesh_mux_stream_failed");
            }
        });
    }
    drop(mux);
}

/// Accept `quic-mux` TCP connections and route streams through `components` then `fallback`.
pub async fn serve_component_mux_tcp_listener(
    listener: tokio::net::TcpListener,
    components: Arc<mesh::ComponentDirectory>,
    fallback: Arc<RegistryStreamHandler>,
) {
    loop {
        match listener.accept().await {
            Ok((stream, _peer)) => {
                let _ = stream.set_nodelay(true);
                let c = components.clone();
                let f = fallback.clone();
                tokio::spawn(async move {
                    serve_component_mux_connection(
                        stream,
                        c,
                        f,
                        quic_mux::TokioMuxConfig::default(),
                    )
                    .await;
                });
            }
            Err(error) => {
                warn!(%error, "lmesh_mux_tcp_accept_failed");
                sleep(Duration::from_millis(50)).await;
            }
        }
    }
}

/// Accept local `quic-mux` UDS connections and route streams through `components` then `fallback`.
pub async fn serve_component_mux_uds_listener(
    listener: tokio::net::UnixListener,
    components: Arc<mesh::ComponentDirectory>,
    fallback: Arc<RegistryStreamHandler>,
) {
    loop {
        match listener.accept().await {
            Ok((stream, _peer)) => {
                let c = components.clone();
                let f = fallback.clone();
                tokio::spawn(async move {
                    serve_component_mux_connection(
                        stream,
                        c,
                        f,
                        quic_mux::TokioMuxConfig::default(),
                    )
                    .await;
                });
            }
            Err(error) => {
                warn!(%error, "lmesh_mux_uds_accept_failed");
                sleep(Duration::from_millis(50)).await;
            }
        }
    }
}

/// Adapter for `!Send` `quic-lite` `TokioNode` streams in `LocalSet`, routing
/// [`mesh::ComponentDirectory`] components first and rewinding into `fallback` otherwise.
struct LmeshNodeStreamHandler {
    components: Arc<mesh::ComponentDirectory>,
    fallback: Arc<RegistryStreamHandler>,
}

impl StreamHandler for LmeshNodeStreamHandler {
    fn accept<'a>(
        &'a self,
        stream: &'a mut dyn AcceptedStream,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = std::io::Result<()>> + 'a>> {
        Box::pin(async move {
            let (envelope, framed) = match mesh::read_envelope_prefix(&mut *stream).await {
                Ok(parts) => parts,
                Err(error) => {
                    if error.kind() == std::io::ErrorKind::InvalidData {
                        let _ = tokio::io::AsyncWriteExt::write_all(
                            stream,
                            &mesh::mesh_api::envelope::encode_error_header(
                                None,
                                b"invalid stream envelope header",
                            ),
                        )
                        .await;
                        let _ = tokio::io::AsyncWriteExt::shutdown(stream).await;
                        return Ok(());
                    }
                    return Err(error);
                }
            };
            let is_component = envelope
                .component()
                .is_some_and(|comp| self.components.has_component(comp));
            if is_component {
                let (_, remaining) = framed.into_parts();
                let (mut bridge_io, handler_io) = tokio::io::duplex(32 * 1024);
                let boxed: Box<dyn mesh::MeshStream> = Box::new(handler_io);
                let framed_owned = mesh::FramedStream::new(boxed, remaining);
                let (_, comp_res) = tokio::join!(
                    tokio::io::copy_bidirectional(stream, &mut bridge_io),
                    self.components.serve_framed_stream(envelope, framed_owned),
                );
                return comp_res.map_err(std::io::Error::other);
            }
            let mut rewound = mesh::rewind_envelope(envelope, framed);
            self.fallback.serve(&mut rewound).await
        })
    }
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

async fn handle_seqpacket_connection(
    stream: mesh::seqpacket::UnixSeqpacket,
    handler: LmeshCborHandler,
) -> Result<()> {
    while let Some((record, fds)) = stream.recv_cbor_record().await? {
        anyhow::ensure!(
            fds.is_empty(),
            "lmesh control requests do not accept file descriptors"
        );
        let kind = record.kind()?;
        let id = record.id.clone();
        let response = if record.to.is_some() {
            mesh::wire::TaggedRecordHandler::forward_record(&handler, record).await?
        } else {
            mesh::wire::TaggedRecordHandler::handle_record(&handler, record).await?
        };
        match (kind, response) {
            (mesh::tagged::RecordKind::Request, Some(response)) => {
                anyhow::ensure!(response.id == id, "uncorrelated lmesh CBOR response");
                stream.send_cbor_record(&response, &[]).await?;
            }
            (mesh::tagged::RecordKind::Message, None) => {}
            _ => anyhow::bail!("invalid lmesh CBOR request/response pairing"),
        }
    }
    Ok(())
}

#[derive(Clone)]
struct LmeshCborHandler {
    service: Arc<LmeshService>,
    components: Arc<mesh::ComponentDirectory>,
    registry: Arc<Registry>,
}

impl LmeshCborHandler {
    fn new(
        service: Arc<LmeshService>,
        external_radio: bool,
        extend: impl FnOnce(&Registry),
    ) -> Self {
        let components = Arc::new(mesh::ComponentDirectory::from_static(
            LMESH_COMPONENTS,
            service.clone(),
        ));
        let registry = linux_registry(
            service.clone(),
            Arc::downgrade(&components),
            external_radio,
            extend,
        );
        Self {
            service,
            components,
            registry,
        }
    }

    /// Dispatch one request through the registry, by number. `context` says
    /// whether the caller is the local control socket or a network peer.
    async fn dispatch_numbered(&self, request: &[u8], context: CallContext) -> Option<Vec<u8>> {
        self.registry.dispatch(request, true, context).await
    }
}

/// Edge translation for a gateway that addresses a common ssh-mesh method by
/// text name (for example `mesh mesh-init`-style `mesh.initialize`): rewrite it
/// to its number, so only the numeric registry dispatches.
fn number_common_names(mut record: mesh::tagged::TaggedRecord) -> mesh::tagged::TaggedRecord {
    use mesh::tagged::NameOrTag;
    let (NameOrTag::Name(_) | NameOrTag::Tag(_), NameOrTag::Name(_)) =
        (&record.component, &record.method)
    else {
        return record;
    };
    let name = match (&record.component, &record.method) {
        (NameOrTag::Name(component), NameOrTag::Name(method)) if !component.is_empty() => {
            format!("{component}.{method}")
        }
        (_, NameOrTag::Name(method)) => method.clone(),
        _ => return record,
    };
    if let Some((component, method)) = mesh::registry::common_method_identity(&name) {
        record.component = NameOrTag::Tag(component as u32);
        record.method = NameOrTag::Tag(method as u32);
    }
    record
}

/// [`number_common_names`] for a raw header: `None` when it needs no change.
fn number_common_names_in_header(header: &[u8]) -> Option<Vec<u8>> {
    let record = mesh::cbor::decode_record(header).ok()?;
    let numbered = number_common_names(record.clone());
    (numbered.component != record.component || numbered.method != record.method)
        .then(|| mesh::cbor::encode_record(&numbered).ok())
        .flatten()
}

/// Host methods answered directly by [`host_component_response`].
/// The host identity and settings methods every Linux node answers.
const COMMON_HOST_METHODS: &[Method] = &[
    methods::STATUS,
    methods::SETTINGS_GET,
    methods::SETTINGS_SET,
    methods::SETTINGS_LIST,
    methods::TELEMETRY_DEVICE,
];

const HOST_METHODS: &[Method] = &[
    methods::STATUS,
    methods::SETTINGS_GET,
    methods::SETTINGS_SET,
    methods::SETTINGS_LIST,
    methods::RADIO_TX,
    methods::RADIO_CONTROL,
    methods::RADIO_SNAPSHOT,
    methods::RADIO_RESET_COUNTERS,
    methods::NAN_PAIR_WAKEUP,
    methods::TELEMETRY_DEVICE,
];

const fn lmesh(
    component: u64,
    component_name: &'static str,
    method: u64,
    name: &'static str,
) -> Method {
    Method::new(component, component_name, method, name)
}

/// Methods answered by the lmesh request adapter ([`decode_lmesh_tagged_request`]
/// and `LmeshService::handle_request`): the common methods Linux implements
/// plus the Linux-only and development methods.
const REQUEST_METHODS: &[Method] = &[
    methods::TRANSPORT_SET,
    methods::DISCOVERY_ACTIVE,
    methods::NAN_WAKEUP,
    methods::TELEMETRY_NAN_STATUS,
    lmesh(4, "lmesh", 8, "send"),
    lmesh(4, "lmesh", 10, "messages.history"),
    lmesh(221, "link", 30, "steer"),
    lmesh(224, "object", 30, "nan.dry_run"),
    lmesh(5, "wifi", 30, "interface.list"),
    lmesh(5, "wifi", 31, "interface.up"),
    lmesh(5, "wifi", 32, "interface.channel"),
    lmesh(5, "wifi", 37, "ap.start_open"),
    lmesh(5, "wifi", 38, "ap.stop"),
    lmesh(5, "wifi", 40, "sta.join_open"),
    lmesh(5, "wifi", 41, "sta.configure_ipv4"),
];

/// How a registered Linux method is executed.
#[derive(Clone, Copy)]
enum Executor {
    Host,
    Request,
}

/// A registered Linux handler: decode the tagged request, run it against the
/// service, and answer with a correlated tagged record. A handler that
/// returns `None` leaves the dispatcher to answer the shared numeric error.
#[derive(Clone)]
struct LinuxHandler {
    service: Arc<LmeshService>,
    executor: Executor,
}

impl Handler for LinuxHandler {
    fn call<'a>(&'a self, call: Call<'a>) -> Reply<'a> {
        Box::pin(async move {
            let record = mesh::cbor::decode_record(call.data).ok()?;
            let id = record.id.clone()?;
            let response = match self.executor {
                Executor::Host => host_component_response(&self.service, &record).await?,
                Executor::Request => match decode_lmesh_tagged_request(&record) {
                    Ok(request) => self.service.handle_request(request).await,
                    Err(error) => {
                        mesh::protocol::Response::err(format!("invalid request: {error}"))
                    }
                },
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
            mesh::cbor::encode_record(&response).ok()
        })
    }
}

/// The registry for one lmesh service: every method Linux implements, and
/// nothing else. `battery`, `power.snapshot`, `memory.snapshot` and the BLE
/// scan/connect methods have no Linux source today and are not registered.
fn linux_registry(
    service: Arc<LmeshService>,
    components: std::sync::Weak<mesh::ComponentDirectory>,
    external_radio: bool,
    extend: impl FnOnce(&Registry),
) -> Arc<Registry> {
    Arc::new_cyclic(|this: &std::sync::Weak<Registry>| {
        let registry = Registry::new();
        // With an external radio the executable registers every radio-facing method
        // (and Linux has no extensions beyond the common API); only the host
        // identity methods remain here.
        let host: &[Method] = if external_radio { COMMON_HOST_METHODS } else { HOST_METHODS };
        let request: &[Method] = if external_radio { &[] } else { REQUEST_METHODS };
        for (list, executor) in [(host, Executor::Host), (request, Executor::Request)] {
            if list.is_empty() {
                continue;
            }
            let registered = registry.register_all(
                list,
                LinuxHandler {
                    service: service.clone(),
                    executor,
                },
            );
            assert!(registered, "lmesh method registered twice or table full");
        }
        register_telemetry(&registry, &service, external_radio);
        assert!(
            registry.register(
                methods::SERVICES,
                ServicesHandler {
                    registry: this.clone(),
                    components,
                },
            ),
            "services registered twice"
        );
        assert!(
            registry.register_stream(methods::DISCOVERY_NODES, DiscoveryNodesHandler(service.clone())),
            "discovery.nodes registered twice"
        );
        register_common_methods(&registry);
        extend(&registry);
        registry
    })
}

/// The telemetry methods Linux has a source for, each an ordinary registered
/// handler returning its generated struct (`API.md`). `bearers`, `power` and
/// `runtime` have no Linux source and are not registered.
fn register_telemetry(registry: &Registry, service: &Arc<LmeshService>, external_radio: bool) {
    use crate::rpc_router as api;
    macro_rules! typed {
        ($method:expr, $request:ty, $call:ident) => {{
            let service = service.clone();
            assert!(
                registry.register(
                    $method,
                    TypedHandler::new(move |_: $request, _: CallContext| {
                        let service = service.clone();
                        async move { service.$call() }
                    }),
                ),
                "telemetry method registered twice"
            );
        }};
    }
    if !external_radio {
        typed!(methods::TELEMETRY_NOW_METRICS, api::TelemetryNowRequest, telemetry_now);
        typed!(methods::TELEMETRY_NAN_METRICS, api::TelemetryNanRequest, telemetry_nan);
        typed!(methods::TELEMETRY_UDP6_METRICS, api::TelemetryUdp6Request, telemetry_udp6);
        typed!(
            methods::TELEMETRY_WIFI_LINK_METRICS,
            api::TelemetryWifiLinkRequest,
            telemetry_wifi_link
        );
    }
    typed!(methods::TELEMETRY_MEMORY, api::TelemetryMemoryRequest, telemetry_memory);
    let quic = service.clone();
    assert!(
        registry.register(
            methods::TELEMETRY_QUIC_METRICS,
            TypedHandler::new(move |_: api::TelemetryQuicRequest, _: CallContext| {
                let service = quic.clone();
                async move { service.telemetry_quic().await }
            }),
        ),
        "telemetry.quic registered twice"
    );
    let associations = service.clone();
    assert!(
        registry.register(
            methods::TELEMETRY_QUIC_ASSOCIATIONS,
            TypedHandler::new(move |_: api::TelemetryQuicAssociationsRequest, _: CallContext| {
                let service = associations.clone();
                async move { service.telemetry_quic_associations().await }
            }),
        ),
        "telemetry.quic_associations registered twice"
    );
    let bearers = service.clone();
    assert!(
        registry.register(
            methods::TELEMETRY_BEARERS,
            TypedHandler::new(move |_: api::TelemetryBearersRequest, _: CallContext| {
                let service = bearers.clone();
                async move { service.telemetry_bearers().await }
            }),
        ),
        "telemetry.bearers registered twice"
    );
}

/// The common ssh-mesh methods (`mesh.*`, `trace.*`) have reserved numbers
/// and dispatch by CBOR. The supervisor-private `mesh.lifecycle` and the
/// mutating `trace.set_level` are local-only.
fn register_common_methods(registry: &Registry) {
    for (component, method, name) in mesh::registry::COMMON_METHODS {
        let (component_name, method_name) = name.split_once('.').unwrap_or(("", name));
        let handler = CommonHandler;
        let method = Method::new(*component, component_name, *method, method_name);
        let registered = if matches!(*name, "mesh.lifecycle" | "trace.set_level") {
            registry.register(method, LocalOnly(handler))
        } else {
            registry.register(method, handler)
        };
        assert!(registered, "common method registered twice");
    }
}

/// Passive `probe` component (`# \`probe\` API (8)`), instantiated lazily on
/// the first `probe.start` unary request or `probe.handler` stream.
struct ProbeComponentHandler(Arc<LmeshService>);

#[async_trait::async_trait]
impl mesh::ComponentHandler for ProbeComponentHandler {
    async fn call_cbor(
        &self,
        method: mesh::MethodCall<'_>,
        fields_cbor: &[u8],
    ) -> Result<Vec<u8>> {
        if method.name != "start" && method.id != Some(1) {
            anyhow::bail!("unsupported unary probe method `{}`", method.name);
        }
        let request = quic_tools::decode_probe_fields(fields_cbor)
            .context("invalid probe.start request fields")?;
        let peer = request
            .peer
            .context("probe.start requires a target `peer` URI")?;
        let mut outbound = request;
        outbound.peer = None;
        let started = std::time::Instant::now();
        let timeout = std::time::Duration::from_millis(quic_tools::probe_timeout_ms(
            method.timeout_ms,
            request.total_bytes(),
        ));
        let outcome = self.0.probe_exchange(peer.as_str(), outbound, timeout).await;
        let (success, received, elapsed) = match outcome {
            Ok(result) => (true, result.bytes, result.elapsed_us),
            Err(_) => (
                false,
                0,
                started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64,
            ),
        };
        let mut out = vec![0u8; 160];
        let used =
            quic_tools::encode_probe_result_value(request, success, received, elapsed, &mut out)
                .context("failed to encode probe.start result")?;
        out.truncate(used);
        Ok(out)
    }

    async fn open_stream(
        &self,
        method: mesh::MethodCall<'_>,
        envelope: mesh::OwnedEnvelope,
        mut stream: mesh::FramedStream<Box<dyn mesh::MeshStream>>,
    ) -> Result<()> {
        if method.name != "handler" && method.id != Some(2) {
            anyhow::bail!("unsupported stream probe method `{}`", method.name);
        }
        let record = envelope.record().context("invalid probe.handler envelope")?;
        let req_id = record.id.context("probe.handler envelope missing id")?;
        quic_tools::serve_framed_probe_stream(req_id, record.fields, &mut stream)
            .await
            .context("probe.handler stream failed")
    }
}

fn create_probe_component(service: &Arc<LmeshService>) -> Arc<dyn mesh::ComponentHandler> {
    Arc::new(ProbeComponentHandler(Arc::clone(service)))
}

/// Passively registered `lmesh` components in `.rodata`. Zero component handlers
/// are instantiated at boot; each `create` function runs only on the first matching request.
const LMESH_COMPONENTS: &[mesh::StaticComponent<Arc<LmeshService>>] = &[mesh::StaticComponent {
    spec: &quic_tools::COMPONENT_PROBE,
    create: create_probe_component,
}];

/// Original announcement records and receiver metadata, using the same
/// retained/live response source as Android and the same wire as ESP.
#[derive(Clone)]
struct DiscoveryNodesHandler(Arc<LmeshService>);

impl MethodStreamHandler for DiscoveryNodesHandler {
    fn open<'a>(&'a self, call: Call<'a>) -> OpenStreamFuture<'a> {
        Box::pin(async move {
            let options = dmesh_discovery::discovery_nodes::Options::decode(call.record.fields)?;
            if call.record.to.is_some() || call.record.params.is_some() {
                return None;
            }
            // Snapshot/subscription creation precedes solicitation.
            let (header, source) = dmesh_discovery::nodes::open_stream(
                self.0.discovery_engine().clone(),
                call.record.id?,
                options,
                true,
            )?;
            if options.active && options.duration_ms != 0 {
                let _ = self
                    .0
                    .handle_request(crate::mesh_core::Request::DiscoveryActive {
                        medium: None,
                        to: None,
                    })
                    .await;
            }
            Some(StreamOutcome::Nodes { header, source })
        })
    }
}

/// `services`: the methods this service's registry and passive [`mesh::ComponentDirectory`]
/// hold, as `[component, method, name]` rows. Inspecting passive component specs never
/// instantiates their handlers.
#[derive(Clone)]
struct ServicesHandler {
    registry: std::sync::Weak<Registry>,
    components: std::sync::Weak<mesh::ComponentDirectory>,
}

impl Handler for ServicesHandler {
    fn call<'a>(&'a self, call: Call<'a>) -> Reply<'a> {
        Box::pin(async move {
            let id = mesh::cbor::decode_record(call.data).ok()?.id?;
            let registry = self.registry.upgrade()?;
            let mut rows: Vec<(u64, u64, String)> = registry
                .methods()
                .into_iter()
                .map(|m| (m.component, m.method, m.wire_name()))
                .collect();
            if let Some(components) = self.components.upgrade() {
                rows.extend(components.catalog_rows());
            }
            rows.sort_by_key(|(c, m, _)| (*c, *m));
            rows.dedup_by_key(|(c, m, _)| (*c, *m));
            let services = serde_json::Value::Array(
                rows.into_iter()
                    .map(|(c, m, name)| serde_json::json!([c, m, name]))
                    .collect(),
            );
            mesh::cbor::encode_record(&mesh::wire::response_ok(id, services)).ok()
        })
    }
}

/// ssh-mesh's common methods, dispatched by number as tagged CBOR.
#[derive(Clone, Copy)]
struct CommonHandler;

impl Handler for CommonHandler {
    fn call<'a>(&'a self, call: Call<'a>) -> Reply<'a> {
        Box::pin(async move {
            COMMON_REGISTRY
                .dispatch_cbor(call.data)
                .await
                .ok()
                .flatten()
        })
    }
}

#[async_trait::async_trait]
impl mesh::wire::TaggedRecordHandler for LmeshCborHandler {
    async fn handle_record(
        &self,
        record: mesh::tagged::TaggedRecord,
    ) -> Result<Option<mesh::tagged::TaggedRecord>> {
        anyhow::ensure!(record.id.is_some(), "tagged-CBOR request missing id");
        let comp_name = match &record.component {
            mesh::tagged::NameOrTag::Name(s) => mesh::mesh_api::envelope::Name::Text(s.as_bytes()),
            mesh::tagged::NameOrTag::Tag(t) => mesh::mesh_api::envelope::Name::Tag(u64::from(*t)),
        };
        if self.components.has_component(comp_name) {
            return mesh::wire::TaggedRecordHandler::handle_record(&*self.components, record).await;
        }
        // The control socket is local ingress.
        let request = mesh::cbor::encode_record(&number_common_names(record))?;
        let response = self
            .dispatch_numbered(&request, CallContext::local())
            .await
            .context("lmesh registry did not answer the request")?;
        Ok(Some(mesh::cbor::decode_record(&response)?))
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
        let wire = resolve_lmesh_catalog()?.catalog.encode_request(&record)?;
        // The caller's `timeout` bounds the whole directed exchange; the
        // remote gets the same allowance in the record it receives.
        let response = match record.timeout {
            Some(timeout) => {
                self.service
                    .forward_tagged_record_with_timeout(
                        &destination,
                        &wire,
                        std::time::Duration::from_millis(timeout),
                    )
                    .await
            }
            None => self.service.forward_tagged_record(&destination, &wire).await,
        };
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

fn record_keeps_to_as_local_argument(record: &mesh::tagged::TaggedRecord) -> bool {
    matches!(
        decode_lmesh_tagged_request(record),
        Ok(crate::mesh_core::Request::DiscoveryActive { .. }
            | crate::mesh_core::Request::NanWakeup { .. })
    )
}

/// Serve the shared numeric-tagged components that the local JSON `Request`
/// surface does not model. One dispatch backs the UDS control socket, QUIC
/// streams, and the HTTP/REST gateway, so every catalogued method has the
/// same handler on every path.
async fn host_component_response(
    service: &crate::mesh_core::LmeshService,
    record: &mesh::tagged::TaggedRecord,
) -> Option<mesh::protocol::Response> {
    use mesh::tagged::NameOrTag;

    let (NameOrTag::Tag(component), NameOrTag::Tag(method)) = (&record.component, &record.method)
    else {
        return None;
    };
    let (component, method) = (u64::from(*component), u64::from(*method));
    let fields = resolve_lmesh_catalog().ok()?.catalog.to_jsonl(record);
    let response = match (component, method) {
        // Connection diagnostics (`services` is `ServicesHandler`).
        (
            crate::rpc_router::DIAGNOSTIC_COMPONENT,
            crate::rpc_router::DIAGNOSTIC_STATUS_METHOD,
        ) => service.host_status(),
        // Common control-plane settings, backed by the shared settings store.
        (dmesh_discovery::control::CONTROL_COMPONENT, dmesh_discovery::control::SETTINGS_GET) => {
            host_settings_get(fields.get("key").and_then(serde_json::Value::as_str))
        }
        (dmesh_discovery::control::CONTROL_COMPONENT, dmesh_discovery::control::SETTINGS_SET) => {
            host_settings_set(
                fields.get("key").and_then(serde_json::Value::as_str),
                fields.get("value").and_then(serde_json::Value::as_str),
            )
        }
        (dmesh_discovery::control::CONTROL_COMPONENT, dmesh_discovery::control::SETTINGS_LIST) => {
            host_settings_list()
        }
        // Raw-radio laboratory surface.
        (
            dmesh_rawnan::raw_wifi::RAW_WIFI_COMPONENT,
            dmesh_rawnan::raw_wifi::RAW_WIFI_METHOD_TX,
        ) => host_radio_tx(service, record, &fields),
        (
            dmesh_rawnan::raw_wifi::RAW_WIFI_COMPONENT,
            dmesh_rawnan::raw_wifi::RAW_WIFI_METHOD_CONTROL,
        ) => service.host_radio_control(&fields),
        (
            dmesh_rawnan::raw_wifi::RAW_WIFI_COMPONENT,
            dmesh_rawnan::raw_wifi::RAW_WIFI_METHOD_SNAPSHOT,
        ) => service.host_radio_snapshot(),
        (
            dmesh_rawnan::raw_wifi::RAW_WIFI_COMPONENT,
            dmesh_rawnan::raw_wifi::RAW_WIFI_METHOD_RESET_COUNTERS,
        ) => service.host_radio_reset_counters(),
        // Directed pairing wake.
        (
            dmesh_discovery::announce::ANNOUNCE_COMPONENT,
            dmesh_discovery::announce::ANNOUNCE_NAN_PAIR_WAKEUP,
        ) => match fields.get("to").and_then(serde_json::Value::as_str) {
            Some(to) => service.host_pair_wakeup(to),
            None => mesh::protocol::Response::err("nan.pair_wakeup requires to"),
        },
        // Host identity.
        (
            crate::rpc_router::TELEMETRY_COMPONENT,
            crate::rpc_router::DEVICE_METHOD,
        ) => host_device_telemetry(),
        _ => return None,
    };
    Some(response)
}

/// The host settings file: an explicit path wins over the service home.
fn host_settings_store() -> Result<crate::settings::FileSettings, String> {
    let path = std::env::var_os("DMESH_SETTINGS_FILE")
        .map(std::path::PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME")
                .map(|home| std::path::PathBuf::from(home).join("etc/settings.conf"))
        })
        .ok_or_else(|| "no settings file: set DMESH_SETTINGS_FILE".to_owned())?;
    Ok(crate::settings::FileSettings::new(path, "linux"))
}

fn host_settings_get(key: Option<&str>) -> mesh::protocol::Response {
    let Some(key) = key else {
        return mesh::protocol::Response::err("settings.get requires key=<name>");
    };
    match host_settings_store() {
        Ok(mut store) => {
            let handler = crate::settings::SettingsHandler::new(&mut store);
            match handler.get(key) {
                Ok(value) => mesh::protocol::Response::ok_with_data(
                    serde_json::json!({"key": key, "value": value}),
                ),
                Err(error) => mesh::protocol::Response::err(error),
            }
        }
        Err(error) => mesh::protocol::Response::err(error),
    }
}

fn host_settings_set(key: Option<&str>, value: Option<&str>) -> mesh::protocol::Response {
    let (Some(key), Some(value)) = (key, value) else {
        return mesh::protocol::Response::err("settings.set requires key=<name> value=<text>");
    };
    match host_settings_store() {
        Ok(mut store) => {
            let mut handler = crate::settings::SettingsHandler::new(&mut store);
            match handler.set(key, value) {
                Ok(()) => mesh::protocol::Response::ok_with_data(
                    serde_json::json!({"key": key, "set": true}),
                ),
                Err(error) => mesh::protocol::Response::err(error),
            }
        }
        Err(error) => mesh::protocol::Response::err(error),
    }
}

fn host_settings_list() -> mesh::protocol::Response {
    match host_settings_store() {
        Ok(mut store) => {
            let handler = crate::settings::SettingsHandler::new(&mut store);
            match handler.list() {
                Ok(entries) => mesh::protocol::Response::ok_with_data(serde_json::json!({
                    "entries": entries
                        .into_iter()
                        .map(|(key, value)| serde_json::json!({"key": key, "value": value}))
                        .collect::<Vec<_>>(),
                })),
                Err(error) => mesh::protocol::Response::err(error),
            }
        }
        Err(error) => mesh::protocol::Response::err(error),
    }
}

/// Decode and transmit one undirected `radio.tx` request locally. Directed
/// `to` requests are forwarded before this handler runs.
fn host_radio_tx(
    service: &crate::mesh_core::LmeshService,
    record: &mesh::tagged::TaggedRecord,
    fields: &serde_json::Value,
) -> mesh::protocol::Response {
    let Some(frame) = fields
        .get("frame")
        .and_then(serde_json::Value::as_str)
        .and_then(|frame| hex_decode_bytes(frame))
    else {
        return mesh::protocol::Response::err("radio.tx requires frame=<hex>");
    };
    let channel = fields
        .get("channel")
        .and_then(serde_json::Value::as_u64)
        .and_then(|channel| u8::try_from(channel).ok())
        .filter(|channel| (1..=13).contains(channel))
        .unwrap_or(6);
    let rate_mbps = fields
        .get("rate")
        .and_then(serde_json::Value::as_u64)
        .and_then(raw_wifi_rate_mbps);
    let iface = raw_wifi_interface(fields.get("interface").cloned());
    let _ = record;
    service.host_radio_tx_local(iface, channel, &frame, rate_mbps)
}

/// Map the shared raw-rate enum onto a physical Mbps value. `0` is Auto.
fn raw_wifi_rate_mbps(rate: u64) -> Option<u8> {
    match rate {
        1 => Some(6),
        2 => Some(9),
        3 => Some(12),
        4 => Some(18),
        5 => Some(24),
        6 => Some(36),
        7 => Some(48),
        8 => Some(54),
        _ => None,
    }
}

/// Map the shared raw interface enum onto an owned Linux interface name.
/// `Auto` and `Sta` select the default owned interface; dedicated AP/NAN
/// VIF selection is a firmware adapter concept.
fn raw_wifi_interface(interface: Option<serde_json::Value>) -> Option<String> {
    match interface {
        Some(serde_json::Value::Number(number)) if number.as_u64() == Some(2) => {
            Some("ap".to_owned())
        }
        _ => None,
    }
}

fn hex_decode_bytes(value: &str) -> Option<Vec<u8>> {
    let value = value.trim().trim_start_matches("hex:");
    (0..value.len() / 2)
        .map(|index| u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).ok())
        .collect()
}

/// Host service identity for the shared firmware-identity surface.
fn host_device_telemetry() -> mesh::protocol::Response {
    mesh::protocol::Response::ok_with_data(serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "cpu_type": std::env::consts::ARCH,
        "role": "linux",
        "total_ram_bytes": dmesh_discovery::host_total_ram_bytes(),
    }))
}

fn decode_lmesh_tagged_request(
    record: &mesh::tagged::TaggedRecord,
) -> Result<crate::mesh_core::Request> {
    let resolved = resolve_lmesh_catalog()?;
    if resolved.catalog.method_name(record).is_none() {
        anyhow::bail!("tagged-CBOR method is outside the reviewed lmesh catalog");
    }
    let mut value = resolved.catalog.to_jsonl(record);
    let method = value["method"]
        .as_str()
        .context("tagged-CBOR request has no documented method")?
        .to_owned();
    value["method"] =
        serde_json::Value::String(method.strip_prefix("lmesh.").unwrap_or(&method).to_owned());
    match method.as_str() {
        "send" => serde_json::from_value::<crate::mesh_core::api::LmeshSendRequest>(value)
            .and_then(|request| {
                let payload = request
                    .payload
                    .ok_or_else(|| serde::de::Error::custom("send.payload is required"))?;
                Ok(crate::mesh_core::Request::Send {
                    radio: request.radio,
                    destination: request.destination,
                    payload,
                })
            }),
        "messages.history" => serde_json::from_value::<
            crate::mesh_core::api::LmeshMessagesHistoryRequest,
        >(value)
        .map(|request| crate::mesh_core::Request::MessagesHistory {
            keys: request.keys,
            limit: request
                .limit
                .map(|limit| limit.min(usize::MAX as u64) as usize),
        }),
        "discovery.active" => serde_json::from_value(value),
        "discovery.status" => Ok(crate::mesh_core::Request::DiscoveryStatus),
        "telemetry.nan_status" => Ok(crate::mesh_core::Request::NanStatus),
        _ => serde_json::from_value(value),
    }
    .context("deserialize tagged lmesh request")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_catalog() -> Arc<mesh::tagged::TaggedSchema> {
        resolve_lmesh_catalog().unwrap().catalog.clone()
    }

    fn public_tools_json() -> serde_json::Value {
        (*resolve_lmesh_catalog().unwrap().tools).clone()
    }

    #[test]
    fn shared_method_names_keep_linux_fields() {
        let transport = test_catalog()
            .parse_argv(
                "transport.set",
                &["--mode=6".into(), "--iface=wlan0".into()],
            )
            .unwrap();
        assert!(matches!(
            decode_lmesh_tagged_request(&transport).unwrap(),
            crate::mesh_core::Request::TransportSet { iface: Some(iface), .. } if iface == "wlan0"
        ));
    }

    #[test]
    fn registered_methods_match_the_installed_catalog_numbers_and_names() {
        let catalog = public_tools_json();
        let tools = catalog.as_array().unwrap();
        let mut seen = std::collections::HashSet::new();
        for method in HOST_METHODS.iter().chain(REQUEST_METHODS) {
            assert!(
                seen.insert((method.component, method.method)),
                "{} is registered twice",
                method.wire_name()
            );
            let tool = tools
                .iter()
                .find(|tool| tool["name"] == method.wire_name().as_str())
                .unwrap_or_else(|| panic!("{} is not in tools.json", method.wire_name()));
            assert_eq!(
                tool["x-component-index"],
                method.component,
                "{}",
                method.wire_name()
            );
            assert_eq!(
                tool["x-method-index"],
                method.method,
                "{}",
                method.wire_name()
            );
        }
    }

    #[test]
    fn typed_linux_methods_match_the_installed_catalog() {
        let catalog = public_tools_json();
        let tools = catalog.as_array().unwrap();
        for method in [
            methods::TELEMETRY_NOW_METRICS,
            methods::TELEMETRY_NAN_METRICS,
            methods::TELEMETRY_UDP6_METRICS,
            methods::TELEMETRY_WIFI_LINK_METRICS,
            methods::TELEMETRY_QUIC_METRICS,
            methods::TELEMETRY_MEMORY,
        ] {
            let tool = tools
                .iter()
                .find(|tool| tool["name"] == method.wire_name().as_str())
                .unwrap_or_else(|| panic!("{} is not in tools.json", method.wire_name()));
            assert_eq!(
                (&tool["x-component-index"], &tool["x-method-index"]),
                (&serde_json::json!(method.component), &serde_json::json!(method.method)),
                "{}",
                method.wire_name()
            );
        }
    }

    #[test]
    fn text_named_common_methods_are_numbered_at_the_edge() {
        use mesh::tagged::{NameOrTag, TaggedRecord};
        let named = TaggedRecord {
            component: NameOrTag::Name("mesh".to_owned()),
            method: NameOrTag::Name("initialize".to_owned()),
            id: Some(serde_json::json!(1)),
            ..Default::default()
        };
        let numbered = number_common_names(named);
        assert_eq!(numbered.component, NameOrTag::Tag(2000));
        assert_eq!(numbered.method, NameOrTag::Tag(1));

        let whole_name = TaggedRecord {
            component: NameOrTag::Name(String::new()),
            method: NameOrTag::Name("trace.get_level".to_owned()),
            ..Default::default()
        };
        assert_eq!(
            number_common_names(whole_name).component,
            NameOrTag::Tag(2001)
        );

        let own = TaggedRecord {
            component: NameOrTag::Tag(7),
            method: NameOrTag::Tag(1),
            ..Default::default()
        };
        assert_eq!(number_common_names(own.clone()).component, own.component);
    }

    #[tokio::test]
    async fn common_methods_dispatch_by_number_and_private_ones_are_local_only() {
        let registry = Registry::new();
        register_common_methods(&registry);
        let request = |component: u64, method: u64| {
            mesh::cbor::encode_record(&mesh::tagged::TaggedRecord {
                component: mesh::tagged::NameOrTag::Tag(component as u32),
                method: mesh::tagged::NameOrTag::Tag(method as u32),
                id: Some(serde_json::json!(4)),
                ..Default::default()
            })
            .unwrap()
        };
        // mesh.initialize is answered for a network caller.
        let reply = registry
            .dispatch(&request(2000, 1), true, CallContext::default())
            .await
            .unwrap();
        let reply = mesh::cbor::decode_record(&reply).unwrap();
        assert_eq!(reply.id, Some(serde_json::json!(4)));
        assert!(reply.result.is_some());
        // trace.set_level is declined for a network caller, accepted locally.
        let network = registry
            .dispatch(&request(2001, 2), true, CallContext::default())
            .await
            .unwrap();
        assert!(
            mesh_api::envelope::decode(&network)
                .unwrap()
                .error
                .is_some()
        );
        assert_eq!(
            registry.methods().len(),
            mesh::registry::COMMON_METHODS.len()
        );
    }

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

    #[test]
    fn discovery_nodes_is_the_only_inventory_name() {
        // `discovery.nodes` is a registered handler (the shared typed rows), not
        // a JSON request, and no second inventory name exists.
        assert!(
            decode_lmesh_tagged_request(
                &test_catalog()
                    .record_from_value("discovery.nodes", &serde_json::json!({}))
                    .unwrap()
            )
            .is_err()
        );
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
        assert!(names.contains(&"probe.start"));
        assert!(names.contains(&"probe.handler"));
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
            "log.watch",
            "probe.start",
            "radio.snapshot",
            "services",
            "settings.get",
            "settings.list",
            "status",
            "telemetry.bearers",
            "telemetry.memory",
            "telemetry.nan",
            "telemetry.nan_status",
            "telemetry.now",
            "telemetry.power",
            "telemetry.runtime",
            "telemetry.udp6",
            "telemetry.wifi_link",
            "wifi.scan",
        ]
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(selected, expected);
        let probe = catalog
            .as_array()
            .unwrap()
            .iter()
            .find(|tool| tool["name"] == "probe.start")
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
    fn telemetry_is_a_typed_registered_method_not_a_json_request() {
        // `telemetry.nan` is answered by its typed handler (`register_telemetry`),
        // so the JSON-lines request adapter no longer knows it.
        let error = decode_lmesh_tagged_request(&mesh::tagged::TaggedRecord {
            component: mesh::tagged::NameOrTag::Tag(7),
            method: mesh::tagged::NameOrTag::Tag(3),
            id: Some(serde_json::json!(3)),
            ..Default::default()
        })
        .unwrap_err();
        // It is rejected rather than decoded into a request.
        assert!(!error.to_string().is_empty());
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
    fn local_wifi_method_uses_generated_numeric_tags() {
        let record = test_catalog()
            .record_from_value(
                "wifi.interface.channel",
                &serde_json::json!({
                    "iface": "wlan0", "channel": 6
                }),
            )
            .unwrap();
        assert_eq!(record.component, mesh::tagged::NameOrTag::Tag(5));
        assert_eq!(record.method, mesh::tagged::NameOrTag::Tag(32));
        assert!(matches!(
            decode_lmesh_tagged_request(&record).unwrap(),
            crate::mesh_core::Request::WifiInterfaceChannel { channel: 6, .. }
        ));
    }

    #[test]
    fn active_discovery_keeps_its_explicit_path_local() {
        let mut record = test_catalog()
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

        // `forward_record` clears `to` at the QUIC boundary (route selection
        // is never a forwarded application field), so decode the same way the
        // remote handler receives it.
        let mut record = test_catalog()
            .record_from_value(
                "radio.tx",
                &serde_json::json!({
                    "id": 43,
                    "to": "e9",
                    "frame": "hex:d000ffffffff00112233445566778899aabbccddeeff00112233445566",
                    "channel": 6,
                    "interface": 1,
                    "rate": 6,
                }),
            )
            .unwrap();
        record.to = None;
        let wire = test_catalog().encode_request(&record).unwrap();
        let request = dmesh_rawnan::raw_wifi::decode_raw_wifi_tx_record(
            mesh_api::envelope::decode(&wire).unwrap(),
        )
        .unwrap();
        assert_eq!(request.channel, 6);
        assert_eq!(request.frame[0], 0xd0);
    }

    #[test]
    fn parse_mux_tcp_override_handles_ports_addresses_and_disabled_tokens() {
        assert_eq!(parse_mux_tcp_override("").unwrap(), None);
        assert_eq!(parse_mux_tcp_override("0").unwrap(), None);
        assert_eq!(parse_mux_tcp_override("none").unwrap(), None);
        assert_eq!(parse_mux_tcp_override("OFF").unwrap(), None);
        assert_eq!(
            parse_mux_tcp_override("5229").unwrap(),
            Some(std::net::SocketAddr::from((
                std::net::Ipv6Addr::UNSPECIFIED,
                5229
            )))
        );
        assert_eq!(
            parse_mux_tcp_override("127.0.0.1:15229").unwrap(),
            Some("127.0.0.1:15229".parse().unwrap())
        );
        assert!(parse_mux_tcp_override("not-an-addr").is_err());
    }

    #[tokio::test]
    async fn mux_tcp_and_uds_listeners_serve_registry_local_policy_and_duplex_probes() {
        use crate::rpc_router::ProbeStreamHandler;
        use quic_tools::{
            ProbeDirection, ProbeServiceRequest, encode_probe_handler_request, exchange,
            probe_duplex, probe_stream,
        };

        let registry = Arc::new(Registry::new());
        register_common_methods(&registry);
        registry.register_stream(methods::PROBE_HANDLER, ProbeStreamHandler);

        let mux_net_handler = Arc::new(
            RegistryStreamHandler::new(registry.clone())
                .with_header_rewrite(number_common_names_in_header),
        );
        let mux_local_handler = Arc::new(
            RegistryStreamHandler::new(registry.clone())
                .local()
                .with_header_rewrite(number_common_names_in_header),
        );

        let tcp_listener = bind_mux_tcp_listener("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let tcp_addr = tcp_listener.local_addr().unwrap();
        let tcp_task = tokio::spawn(serve_mux_tcp_listener(tcp_listener, mux_net_handler));

        let tmp = tempfile::tempdir().unwrap();
        let uds_path = tmp.path().join("mesh.mux.sock");
        let uds_listener = bind_mux_uds_listener(&uds_path).await.unwrap();
        // Refuses to clobber an active listener socket.
        assert!(bind_mux_uds_listener(&uds_path).await.is_err());
        let uds_task = tokio::spawn(serve_mux_uds_listener(uds_listener, mux_local_handler));

        let tcp_stream = tokio::net::TcpStream::connect(tcp_addr).await.unwrap();
        let _ = tcp_stream.set_nodelay(true);
        let (tcp_mux, _tcp_acc) =
            quic_mux::TokioMux::client(tcp_stream, quic_mux::TokioMuxConfig::default());

        let uds_stream = tokio::net::UnixStream::connect(&uds_path).await.unwrap();
        let (uds_mux, _uds_acc) =
            quic_mux::TokioMux::client(uds_stream, quic_mux::TokioMuxConfig::default());

        // 1. Text-named `mesh.initialize` rewritten at edge succeeds on both TCP and UDS.
        let init_req = mesh::cbor::encode_record(&mesh::tagged::TaggedRecord {
            component: mesh::tagged::NameOrTag::Name("mesh".to_owned()),
            method: mesh::tagged::NameOrTag::Name("initialize".to_owned()),
            id: Some(serde_json::json!(11)),
            ..Default::default()
        })
        .unwrap();
        for mux in [&tcp_mux, &uds_mux] {
            let mut s = mux.open_bidi().await.unwrap();
            let raw = exchange(&mut s, &[&init_req]).await.unwrap();
            let reply = mesh::cbor::decode_record(&raw).unwrap();
            assert_eq!(reply.id, Some(serde_json::json!(11)));
            assert!(reply.result.is_some());
        }

        #[derive(Clone, Copy)]
        struct LocalEchoHandler;
        impl Handler for LocalEchoHandler {
            fn call<'a>(&'a self, call: Call<'a>) -> Reply<'a> {
                Box::pin(async move {
                    let id = mesh::cbor::decode_record(call.data).ok()?.id?;
                    let v = mesh::cbor::decode_value_bytes(&[0xa1, 0x65, b'l', b'o', b'c', b'a', b'l', 0xf5]).ok()?;
                    mesh::cbor::encode_record(&mesh::wire::response_ok(id, v)).ok()
                })
            }
        }
        registry.register(Method::new(99, "test", 1, "local_echo"), LocalOnly(LocalEchoHandler));

        // 2. `LocalOnly` method (`test.local_echo`, 99.1) is declined on TCP (`local: false`)
        //    and accepted on UDS (`local: true`), alongside `trace.set_level` (2001.2) declined on TCP.
        for (comp, meth) in [(99u32, 1u32), (2001u32, 2u32)] {
            let req = mesh::cbor::encode_record(&mesh::tagged::TaggedRecord {
                component: mesh::tagged::NameOrTag::Tag(comp),
                method: mesh::tagged::NameOrTag::Tag(meth),
                id: Some(serde_json::json!(12)),
                ..Default::default()
            })
            .unwrap();
            let mut s = tcp_mux.open_bidi().await.unwrap();
            let raw = exchange(&mut s, &[&req]).await.unwrap();
            assert!(mesh_api::envelope::decode(&raw).unwrap().error.is_some());
        }
        {
            let local_req = mesh::cbor::encode_record(&mesh::tagged::TaggedRecord {
                component: mesh::tagged::NameOrTag::Tag(99),
                method: mesh::tagged::NameOrTag::Tag(1),
                id: Some(serde_json::json!(13)),
                ..Default::default()
            })
            .unwrap();
            let mut s = uds_mux.open_bidi().await.unwrap();
            let raw = exchange(&mut s, &[&local_req]).await.unwrap();
            let reply = mesh::cbor::decode_record(&raw).unwrap();
            assert!(reply.error.is_none(), "expected local UDS success, got {reply:?}");
            assert_eq!(reply.result, Some(serde_json::json!({ "local": true })));
        }

        // 3. Validated `probe` (`upload`, `download`, `both`) over both TCP and UDS `quic-mux`.
        for mux in [&tcp_mux, &uds_mux] {
            let mut up_req = ProbeServiceRequest::new(24_577, 1024);
            up_req.direction = ProbeDirection::Upload;
            up_req.verify = true;
            let mut hdr = [0u8; 160];
            let n = encode_probe_handler_request(up_req, 201, &mut hdr).unwrap();
            let mut s = mux.open_bidi().await.unwrap();
            let up_res = probe_stream(&mut s, &hdr[..n], up_req).await.unwrap();
            assert_eq!(up_res.bytes, 24_577);
            assert_eq!(up_res.callback_errors, [0; 6]);

            let mut down_req = ProbeServiceRequest::new(24_577, 1024);
            down_req.direction = ProbeDirection::Download;
            down_req.verify = true;
            let n = encode_probe_handler_request(down_req, 202, &mut hdr).unwrap();
            let mut s = mux.open_bidi().await.unwrap();
            let down_res = probe_stream(&mut s, &hdr[..n], down_req).await.unwrap();
            assert_eq!(down_res.bytes, 24_577);
            assert_eq!(down_res.callback_errors, [0; 6]);

            let mut both_req = ProbeServiceRequest::new(24_577, 1024);
            both_req.direction = ProbeDirection::Both;
            both_req.verify = true;
            let mut s_up = mux.open_bidi().await.unwrap();
            let mut s_down = mux.open_bidi().await.unwrap();
            let both_res = probe_duplex(&mut s_up, &mut s_down, both_req, 203)
                .await
                .unwrap();
            assert_eq!(both_res.bytes, 2 * 24_577);
            assert_eq!(both_res.callback_errors, [0; 6]);
        }

        tcp_mux.close();
        uds_mux.close();
        tcp_task.abort();
        uds_task.abort();
    }

    #[tokio::test]
    async fn passive_probe_component_stays_unloaded_at_boot_and_serves_named_and_numeric_mux_streams() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use quic_tools::{
            ProbeDirection, ProbeServiceRequest, exchange, probe_duplex, probe_stream,
        };

        struct StreamOnlyProbeComponent;

        #[async_trait::async_trait]
        impl mesh::ComponentHandler for StreamOnlyProbeComponent {
            async fn open_stream(
                &self,
                method: mesh::MethodCall<'_>,
                envelope: mesh::OwnedEnvelope,
                mut stream: mesh::FramedStream<Box<dyn mesh::MeshStream>>,
            ) -> Result<()> {
                anyhow::ensure!(method.name == "handler" || method.id == Some(2));
                let record = envelope.record().context("invalid probe envelope")?;
                let req_id = record.id.context("probe envelope missing id")?;
                quic_tools::serve_framed_probe_stream(req_id, record.fields, &mut stream)
                    .await
                    .context("probe stream failed")
            }
        }

        fn create_counted_probe(counter: &Arc<AtomicUsize>) -> Arc<dyn mesh::ComponentHandler> {
            counter.fetch_add(1, Ordering::SeqCst);
            Arc::new(StreamOnlyProbeComponent)
        }

        const TEST_COMPONENTS: &[mesh::StaticComponent<Arc<AtomicUsize>>] =
            &[mesh::StaticComponent {
                spec: &quic_tools::COMPONENT_PROBE,
                create: create_counted_probe,
            }];

        let instantiations = Arc::new(AtomicUsize::new(0));
        let components = Arc::new(mesh::ComponentDirectory::from_static(
            TEST_COMPONENTS,
            instantiations.clone(),
        ));
        assert_eq!(instantiations.load(Ordering::SeqCst), 0);
        assert!(!components.is_active("probe"));

        let comp_weak = Arc::downgrade(&components);
        let registry = Arc::new_cyclic(|this: &std::sync::Weak<Registry>| {
            let r = Registry::new();
            register_common_methods(&r);
            assert!(r.register(
                methods::SERVICES,
                ServicesHandler {
                    registry: this.clone(),
                    components: comp_weak,
                },
            ));
            r
        });

        let fallback = Arc::new(
            RegistryStreamHandler::new(registry)
                .with_header_rewrite(number_common_names_in_header),
        );

        let tcp_listener = bind_mux_tcp_listener("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let tcp_addr = tcp_listener.local_addr().unwrap();
        let tcp_task = tokio::spawn(serve_component_mux_tcp_listener(
            tcp_listener,
            components.clone(),
            fallback,
        ));

        let tcp_stream = tokio::net::TcpStream::connect(tcp_addr).await.unwrap();
        let _ = tcp_stream.set_nodelay(true);
        let (mux, _acc) =
            quic_mux::TokioMux::client(tcp_stream, quic_mux::TokioMuxConfig::default());

        // 1. Querying `services` lists `[8, 1, "probe.start"]` and `[8, 2, "probe.handler"]`
        //    from passive `.rodata` metadata WITHOUT instantiating `StreamOnlyProbeComponent`!
        let services_req = mesh::cbor::encode_record(&mesh::tagged::TaggedRecord {
            component: mesh::tagged::NameOrTag::Tag(methods::SERVICES.component as u32),
            method: mesh::tagged::NameOrTag::Tag(methods::SERVICES.method as u32),
            id: Some(serde_json::json!(41)),
            ..Default::default()
        })
        .unwrap();
        let mut s_srv = mux.open_bidi().await.unwrap();
        let raw_srv = exchange(&mut s_srv, &[&services_req]).await.unwrap();
        let srv_reply = mesh::cbor::decode_record(&raw_srv).unwrap();
        let srv_rows = srv_reply.result.unwrap();
        let rows = srv_rows.as_array().unwrap();
        assert!(rows.contains(&serde_json::json!([8, 1, "probe.start"])));
        assert!(rows.contains(&serde_json::json!([8, 2, "probe.handler"])));
        assert_eq!(instantiations.load(Ordering::SeqCst), 0);
        assert!(!components.is_active("probe"));

        // 2. String-named, string-keyed `probe.handler` upload activates `probe` lazily!
        let mut up_req = ProbeServiceRequest::new(12_288, 1024);
        up_req.direction = ProbeDirection::Upload;
        up_req.verify = true;
        let mut named_hdr = [0u8; 256];
        let mut enc = mesh::mesh_api::cbor::Encoder::new(&mut named_hdr);
        enc.map(4).unwrap();
        enc.str(b"component").unwrap();
        enc.str(b"probe").unwrap();
        enc.str(b"method").unwrap();
        enc.str(b"handler").unwrap();
        enc.str(b"id").unwrap();
        enc.uint(301).unwrap();
        enc.str(b"fields").unwrap();
        enc.map(4).unwrap();
        enc.str(b"bytes").unwrap();
        enc.uint(12_288).unwrap();
        enc.str(b"packet_size").unwrap();
        enc.uint(1024).unwrap();
        enc.str(b"direction").unwrap();
        enc.str(b"upload").unwrap();
        enc.str(b"verify").unwrap();
        enc.bool(true).unwrap();
        let hdr_len = enc.len();

        let mut s_up = mux.open_bidi().await.unwrap();
        let up_res = probe_stream(&mut s_up, &named_hdr[..hdr_len], up_req)
            .await
            .unwrap();
        assert_eq!(up_res.bytes, 12_288);
        assert_eq!(up_res.callback_errors, [0; 6]);
        assert_eq!(instantiations.load(Ordering::SeqCst), 1);
        assert!(components.is_active("probe"));

        // 3. Numeric `probe.handler` (8.2) duplex probe reuses the active instance.
        let mut both_req = ProbeServiceRequest::new(16_384, 1024);
        both_req.direction = ProbeDirection::Both;
        both_req.verify = true;
        let mut d_up = mux.open_bidi().await.unwrap();
        let mut d_down = mux.open_bidi().await.unwrap();
        let both_res = probe_duplex(&mut d_up, &mut d_down, both_req, 302)
            .await
            .unwrap();
        assert_eq!(both_res.bytes, 2 * 16_384);
        assert_eq!(both_res.callback_errors, [0; 6]);
        assert_eq!(instantiations.load(Ordering::SeqCst), 1);

        // 4. Idle eviction reclaims the active instance once streams close.
        tokio::task::yield_now().await;
        assert_eq!(components.evict_idle(Duration::ZERO), 1);
        assert!(!components.is_active("probe"));

        mux.close();
        tcp_task.abort();
    }
}
