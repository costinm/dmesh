use std::{
    path::PathBuf,
    sync::{Arc, LazyLock},
    time::Instant,
};

use crate::mesh_core::{LmeshService, LocalDiscovery};
use anyhow::{Context, Result};
use dmesh_server::registry::{
    Call, CallContext, Handler, LocalOnly, Method, Registry, Reply, methods,
};
use tokio::time::{Duration, sleep};
use tracing::{debug, error, warn};

pub type HostPacketPool =
    quic_lite::packet_pool::PacketPool<32, { quic_lite::DEFAULT_PACKET_POOL_SLOT_SIZE }>;
pub type HostQuicNode = quic_lite::QuicNode<HostPacketPool>;

/// Keep host multicast presence aligned with NAN/NOW/ESP refreshes. Operators
/// may still override this through `LMESH_ANNOUNCE_INTERVAL_SECS`.
const DEFAULT_ANNOUNCE_INTERVAL_SECS: u64 = 5 * 60;
const ANNOUNCE_INTERVAL_ENV: &str = "LMESH_ANNOUNCE_INTERVAL_SECS";
const RAW_WIFI_CHANNEL_ENV: &str = "LMESH_RAW_WIFI_CHANNEL";

fn quic_driver_exit_error(
    result: Result<Result<(), quic_lite::QuicNodeEgressError>, tokio::task::JoinError>,
) -> anyhow::Error {
    match result {
        Ok(Ok(())) => anyhow::anyhow!("lmesh QUIC node driver exited unexpectedly"),
        Ok(Err(error)) => anyhow::anyhow!("lmesh QUIC node driver failed: {error:?}"),
        Err(error) => anyhow::anyhow!("lmesh QUIC node driver task failed: {error}"),
    }
}

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

/// Stable endpoints for the Linux mesh daemon.
pub const LMESH_DEFAULTS: RuntimeDefaults = RuntimeDefaults {
    control_socket: "/run/mesh/lmesh/mesh.sock.cbor",
    http_port: 18981,
    udp_port: 3337,
};

/// Generated public catalog. Only reviewed entries carry numeric tags, so the
/// CBOR path cannot accidentally expose or number a legacy control method.
static CONTROL_CATALOG: LazyLock<mesh::tagged::TaggedCatalog> = LazyLock::new(|| {
    mesh::tagged::TaggedCatalog::from_tools_json(&public_tools_json())
        .expect("lmesh tools.json must be a valid tagged catalog")
});
static COMMON_REGISTRY: LazyLock<mesh::registry::ServiceRegistry> = LazyLock::new(|| {
    mesh::registry::ServiceRegistry::new("lmesh").with_tools_json(public_tools_json())
});

/// Installed catalog shared by the local daemon and device clients.
fn public_tools_json() -> serde_json::Value {
    let catalog: serde_json::Value =
        serde_json::from_str(include_str!("../../lmesh/resources/tools.json"))
            .expect("lmesh tools.json must be valid JSON");
    catalog
        .get("tools")
        .cloned()
        .expect("lmesh tools.json must contain tools")
}

/// Run the shared Linux mesh control plane.
pub async fn run_mesh_service(
    defaults: RuntimeDefaults,
    node: HostQuicNode,
    now_bearer: quic_lite::BearerId,
    espnow_ingress: Arc<dyn crate::espnow_bearer::EspNowIngress>,
) -> Result<()> {
    let (trace_buffer, _trace_guard) = mesh::local_trace::init("lmesh");
    mesh::local_trace::serve("lmesh", trace_buffer.clone());
    if let Err(error) = run_server(defaults, node, now_bearer, espnow_ingress).await {
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
    node: HostQuicNode,
    now_bearer: quic_lite::BearerId,
    espnow_ingress: Arc<dyn crate::espnow_bearer::EspNowIngress>,
) -> Result<()> {
    crate::mesh_core::note_service_started();
    let (node, driver) = quic_lite::tokio::TokioNodeDriver::new(
        node,
        quic_lite::AssociationLimits::host().connection,
    );
    // Keep the driver task handle so the service cannot remain "healthy" with
    // a closed QUIC stream receiver. In particular, if the driver exits or
    // panics, let mesh-init restart the whole service (and its radio/bearers)
    // instead of spinning in the accept loop and logging BrokenPipe forever.
    let mut quic_driver = tokio::task::spawn_local(async move { driver.run().await });
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
    service.set_now_quic_client(node.clone(), now_bearer);
    service.set_espnow_ingress(espnow_ingress);
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
    // One registry serves both the QUIC streams and the control socket.
    let cbor_handler = LmeshCborHandler::new(service.clone());
    // QUIC streams are served from the registry as handler streams (header,
    // then an optional raw body). A text-named common ssh-mesh method is
    // numbered at the edge, before dispatch.
    let udp_handler = Arc::new(
        dmesh_server::stream_service::RegistryStreamHandler::new(cbor_handler.registry.clone())
            .with_header_rewrite(number_common_names_in_header),
    );
    tokio::task::spawn_local(async move {
        loop {
            if let Err(error) =
                dmesh_server::stream_service::accept_one(&node, udp_handler.as_ref()).await
            {
                warn!(%error, "lmesh_quic_stream_failed");
            }
        }
    });
    debug!(port = defaults.udp_port, "lmesh_quic_node_started");
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
        let stream = tokio::select! {
            result = &mut quic_driver => {
                let error = quic_driver_exit_error(result);
                error!(%error, "lmesh_quic_driver_stopped");
                return Err(error);
            }
            result = listener.accept() => result.context("lmesh CBOR accept")?,
        };
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
    registry: Arc<Registry>,
}

impl LmeshCborHandler {
    fn new(service: Arc<LmeshService>) -> Self {
        Self {
            registry: linux_registry(service.clone()),
            service,
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
const HOST_METHODS: &[Method] = &[
    methods::STATUS,
    methods::SERVICES,
    methods::METRICS,
    methods::EVENTS,
    methods::LOG_WATCH,
    methods::SETTINGS_GET,
    methods::SETTINGS_SET,
    methods::SETTINGS_LIST,
    methods::RADIO_TX,
    methods::RADIO_CONTROL,
    methods::RADIO_SNAPSHOT,
    methods::RADIO_RESET_COUNTERS,
    methods::NAN_PAIR_WAKEUP,
    methods::RUNTIME_SNAPSHOT,
    methods::FIRMWARE_IDENTITY,
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
    methods::DISCOVERY_NODES,
    methods::DISCOVERY_ACTIVE,
    methods::NAN_WAKEUP,
    methods::TELEMETRY_NAN_STATUS,
    methods::TELEMETRY_NOW_METRICS,
    methods::TELEMETRY_NAN_METRICS,
    methods::TELEMETRY_UDP6_METRICS,
    methods::TELEMETRY_WIFI_LINK_METRICS,
    methods::TELEMETRY_QUIC_METRICS,
    methods::WIFI_SCAN,
    lmesh(209, "companion", 1, "pair"),
    lmesh(209, "companion", 2, "unpair"),
    lmesh(4, "lmesh", 8, "send"),
    lmesh(4, "lmesh", 10, "messages.history"),
    lmesh(221, "link", 30, "steer"),
    lmesh(224, "object", 30, "nan.dry_run"),
    lmesh(5, "wifi", 13, "mgmt.capture"),
    lmesh(5, "wifi", 30, "interface.list"),
    lmesh(5, "wifi", 31, "interface.up"),
    lmesh(5, "wifi", 32, "interface.channel"),
    lmesh(5, "wifi", 33, "ocb.start"),
    lmesh(5, "wifi", 34, "rate.profile"),
    lmesh(5, "wifi", 35, "data.listen"),
    lmesh(5, "wifi", 36, "data.send"),
    lmesh(5, "wifi", 37, "ap.start_open"),
    lmesh(5, "wifi", 38, "ap.stop"),
    lmesh(5, "wifi", 39, "ap.station.add"),
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
fn linux_registry(service: Arc<LmeshService>) -> Arc<Registry> {
    let registry = Registry::new();
    for (list, executor) in [
        (HOST_METHODS, Executor::Host),
        (REQUEST_METHODS, Executor::Request),
    ] {
        let registered = registry.register_all(
            list,
            LinuxHandler {
                service: service.clone(),
                executor,
            },
        );
        assert!(registered, "lmesh method registered twice or table full");
    }
    // The probed node's end of a probe: a header, then the payload as the
    // response body. Any node can be probed by any other.
    assert!(
        registry.register_stream(methods::PROBE_HANDLER, dmesh_server::probe::ProbeHandler),
        "probe.handler registered twice"
    );
    // `probe`: run a probe against `peer` with this node as the client. Header
    // only in both directions; the response header is the outcome.
    assert!(
        registry.register(methods::PROBE_START, ProbeStartHandler(service.clone())),
        "probe registered twice"
    );
    register_common_methods(&registry);
    Arc::new(registry)
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

/// `probe` on Linux: run the exchange with the node named by `peer` and answer
/// with the outcome header.
#[derive(Clone)]
struct ProbeStartHandler(Arc<LmeshService>);

impl Handler for ProbeStartHandler {
    fn call<'a>(&'a self, call: Call<'a>) -> Reply<'a> {
        Box::pin(async move {
            let (id, request) = dmesh_server::probe::decode_probe_start_record(call.record)?;
            let peer = request.peer?;
            let mut outbound = request;
            outbound.peer = None;
            let started = std::time::Instant::now();
            let timeout = std::time::Duration::from_millis(dmesh_server::probe::probe_timeout_ms(
                call.context.timeout_ms,
                request.bytes,
            ));
            let outcome = self
                .0
                .probe_exchange(peer.as_str(), outbound, timeout)
                .await;
            let (success, received, elapsed) = match outcome {
                Ok(result) => (true, result.bytes, result.elapsed_us),
                Err(_) => (
                    false,
                    0,
                    started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64,
                ),
            };
            let mut response = vec![0u8; 256];
            let used = dmesh_server::probe::encode_probe_result_response(
                id, request, success, received, elapsed, &mut response,
            )?;
            response.truncate(used);
            Some(response)
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
        let wire = raw_wifi_tx_wire(&record, &id)?.unwrap_or(mesh::cbor::encode_record(&record)?);
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
    let fields = CONTROL_CATALOG.to_jsonl(record);
    let field_u64 = |name: &str| fields.get(name).and_then(serde_json::Value::as_u64);
    let response = match (component, method) {
        // Connection diagnostics (status/services/metrics/events/log-watch).
        (
            dmesh_server::services::DIAGNOSTIC_COMPONENT,
            dmesh_server::services::DIAGNOSTIC_STATUS_METHOD,
        ) => service.host_status(),
        (
            dmesh_server::services::DIAGNOSTIC_COMPONENT,
            dmesh_server::services::DIAGNOSTIC_SERVICES_METHOD,
        ) => host_services_response(),
        (
            dmesh_server::services::DIAGNOSTIC_COMPONENT,
            dmesh_server::services::DIAGNOSTIC_METRICS_METHOD,
        ) => service.host_metrics(),
        (
            dmesh_server::services::DIAGNOSTIC_COMPONENT,
            dmesh_server::services::DIAGNOSTIC_EVENTS_METHOD,
        ) => service.host_events(field_u64("since"), Some(field_u64("records").unwrap_or(64))),
        (
            dmesh_server::services::DIAGNOSTIC_COMPONENT,
            dmesh_server::services::DIAGNOSTIC_LOG_WATCH_METHOD,
        ) => service.host_log_watch(field_u64("since"), Some(field_u64("records").unwrap_or(16))),
        // Common control-plane settings, backed by the shared settings store.
        (dmesh_server::control::CONTROL_COMPONENT, dmesh_server::control::SETTINGS_GET) => {
            host_settings_get(fields.get("key").and_then(serde_json::Value::as_str))
        }
        (dmesh_server::control::CONTROL_COMPONENT, dmesh_server::control::SETTINGS_SET) => {
            host_settings_set(
                fields.get("key").and_then(serde_json::Value::as_str),
                fields.get("value").and_then(serde_json::Value::as_str),
            )
        }
        (dmesh_server::control::CONTROL_COMPONENT, dmesh_server::control::SETTINGS_LIST) => {
            host_settings_list()
        }
        // Raw-radio laboratory surface.
        (
            dmesh_server::raw_wifi::RAW_WIFI_COMPONENT,
            dmesh_server::raw_wifi::RAW_WIFI_METHOD_TX,
        ) => host_radio_tx(service, record, &fields),
        (
            dmesh_server::raw_wifi::RAW_WIFI_COMPONENT,
            dmesh_server::raw_wifi::RAW_WIFI_METHOD_CONTROL,
        ) => service.host_radio_control(&fields),
        (
            dmesh_server::raw_wifi::RAW_WIFI_COMPONENT,
            dmesh_server::raw_wifi::RAW_WIFI_METHOD_SNAPSHOT,
        ) => service.host_radio_snapshot(),
        (
            dmesh_server::raw_wifi::RAW_WIFI_COMPONENT,
            dmesh_server::raw_wifi::RAW_WIFI_METHOD_RESET_COUNTERS,
        ) => service.host_radio_reset_counters(),
        // Directed pairing wake.
        (
            dmesh_server::announce::ANNOUNCE_COMPONENT,
            dmesh_server::announce::ANNOUNCE_NAN_PAIR_WAKEUP,
        ) => match fields.get("to").and_then(serde_json::Value::as_str) {
            Some(to) => service.host_pair_wakeup(to),
            None => mesh::protocol::Response::err("nan.pair_wakeup requires to"),
        },
        // Host runtime and identity.
        (
            dmesh_server::services::RUNTIME_SNAPSHOT_COMPONENT,
            dmesh_server::services::RUNTIME_SNAPSHOT_METHOD,
        ) => host_runtime_snapshot(),
        (
            dmesh_server::services::FIRMWARE_COMPONENT,
            dmesh_server::services::FIRMWARE_IDENTITY_METHOD,
        ) => host_firmware_identity(),
        _ => return None,
    };
    Some(response)
}

/// The built-in tagged service catalog as a correlated result value.
fn host_services_response() -> mesh::protocol::Response {
    match mesh::cbor::decode_value_bytes(&dmesh_server::services::encode_tagged_service_catalog()) {
        Ok(services) => mesh::protocol::Response::ok_with_data(services),
        Err(error) => mesh::protocol::Response::err(format!("service catalog: {error}")),
    }
}

/// The host settings file: an explicit path wins over the service home.
fn host_settings_store() -> Result<dmesh_server::settings::FileSettings, String> {
    let path = std::env::var_os("DMESH_SETTINGS_FILE")
        .map(std::path::PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME")
                .map(|home| std::path::PathBuf::from(home).join("etc/settings.conf"))
        })
        .ok_or_else(|| "no settings file: set DMESH_SETTINGS_FILE".to_owned())?;
    Ok(dmesh_server::settings::FileSettings::new(path, "linux"))
}

fn host_settings_get(key: Option<&str>) -> mesh::protocol::Response {
    let Some(key) = key else {
        return mesh::protocol::Response::err("settings.get requires key=<name>");
    };
    match host_settings_store() {
        Ok(mut store) => {
            let handler = dmesh_server::settings::SettingsHandler::new(&mut store);
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
            let mut handler = dmesh_server::settings::SettingsHandler::new(&mut store);
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
            let handler = dmesh_server::settings::SettingsHandler::new(&mut store);
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

/// Bounded host runtime snapshot for the shared runtime component.
fn host_runtime_snapshot() -> mesh::protocol::Response {
    mesh::protocol::Response::ok_with_data(serde_json::json!({
        "role": "host",
        "service": "lmesh",
        "version": env!("CARGO_PKG_VERSION"),
        "uptime_secs": crate::mesh_core::service_uptime_secs(),
        "udp_port": LMESH_DEFAULTS.udp_port,
        "http_port": LMESH_DEFAULTS.http_port,
        "announce_interval_secs": announce_interval().as_secs(),
    }))
}

/// Host service identity for the shared firmware-identity surface.
fn host_firmware_identity() -> mesh::protocol::Response {
    mesh::protocol::Response::ok_with_data(serde_json::json!({
        "name": "lmesh",
        "version": env!("CARGO_PKG_VERSION"),
        "role": "host",
        "uptime_secs": crate::mesh_core::service_uptime_secs(),
    }))
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
        "discovery.nodes" => Ok(crate::mesh_core::Request::RadioDevices),
        "discovery.active" => serde_json::from_value(value),
        "discovery.status" => Ok(crate::mesh_core::Request::DiscoveryStatus),
        "telemetry.nan_status" => Ok(crate::mesh_core::Request::NanStatus),
        "telemetry.now" => Ok(crate::mesh_core::Request::NowMetrics),
        "telemetry.nan" => Ok(crate::mesh_core::Request::NanMetrics),
        "telemetry.udp6" => Ok(crate::mesh_core::Request::Udp6Metrics),
        "telemetry.wifi_link" => Ok(crate::mesh_core::Request::WifiLinkMetrics),
        "telemetry.quic" => Ok(crate::mesh_core::Request::QuicMetrics),
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

    #[test]
    fn quic_driver_clean_exit_is_reported_as_unexpected() {
        let error = quic_driver_exit_error(Ok(Ok(())));
        assert!(error.to_string().contains("exited unexpectedly"));
    }

    #[test]
    fn quic_driver_error_is_preserved_for_service_supervision() {
        let error =
            quic_driver_exit_error(Ok(Err(quic_lite::QuicNodeEgressError::AssociationTimedOut)));
        assert!(error.to_string().contains("AssociationTimedOut"));
    }

    #[test]
    fn shared_method_names_keep_linux_fields() {
        let scan = CONTROL_CATALOG
            .parse_argv(
                "wifi.scan",
                &["--iface=wlan0".into(), "--last_results=true".into()],
            )
            .unwrap();
        assert!(matches!(
            decode_lmesh_tagged_request(&scan).unwrap(),
            crate::mesh_core::Request::WifiScan {
                iface: Some(iface),
                last_results: Some(true),
                ..
            } if iface == "wlan0"
        ));
        let transport = CONTROL_CATALOG
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
            dmesh_server::tagged::decode(&network)
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
            "events",
            "log-watch",
            "log.watch",
            "metrics",
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
    fn local_wifi_method_uses_generated_numeric_tags() {
        let record = CONTROL_CATALOG
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

        let record = CONTROL_CATALOG
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
