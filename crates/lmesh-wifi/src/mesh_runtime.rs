use std::{
    future::Future,
    path::PathBuf,
    pin::Pin,
    sync::{Arc, LazyLock},
    time::Instant,
};

use crate::mesh_core::{LmeshService, LocalDiscovery};
use anyhow::{Context, Result};
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
    let (node, driver) = quic_lite::tokio::TokioNodeDriver::new(
        node,
        quic_lite::AssociationLimits::host().connection,
    );
    tokio::task::spawn_local(async move {
        if let Err(error) = driver.run().await {
            warn!(?error, "lmesh_quic_driver_stopped");
        }
    });
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
    let udp_handler = Arc::new(dmesh_server::stream_service::RecordStreamHandler::new(
        LmeshRecordHandler {
            handler: LmeshCborHandler {
                service: service.clone(),
            },
        },
        64 * 1024,
    ));
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
        let stream = listener.accept().await.context("lmesh CBOR accept")?;
        let service = service.clone();
        tokio::spawn(async move {
            if let Err(error) = handle_seqpacket_connection(stream, service).await {
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
    service: Arc<LmeshService>,
) -> Result<()> {
    let handler = LmeshCborHandler { service };
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

struct LmeshCborHandler {
    service: Arc<LmeshService>,
}

struct LmeshRecordHandler {
    handler: LmeshCborHandler,
}

impl dmesh_server::stream_service::RecordHandler for LmeshRecordHandler {
    fn handle<'a>(
        &'a self,
        request: Vec<u8>,
    ) -> Pin<Box<dyn Future<Output = std::io::Result<Vec<u8>>> + 'a>> {
        Box::pin(async move {
            let record = mesh::cbor::decode_record(&request).map_err(std::io::Error::other)?;
            if is_connection_diagnostic(&record) {
                return dmesh_server::services::dispatch_tagged_stream(&request).ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::Unsupported,
                        "diagnostic handler rejected request",
                    )
                });
            }
            let response = mesh::wire::TaggedRecordHandler::handle_record(&self.handler, record)
                .await
                .map_err(std::io::Error::other)?
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::Unsupported,
                        "lmesh handler declined request",
                    )
                })?;
            mesh::cbor::encode_record(&response).map_err(std::io::Error::other)
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
        if let Some(response) = COMMON_REGISTRY.dispatch_tagged(&record).await? {
            return Ok(Some(response));
        }
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
            | crate::mesh_core::Request::Probe { .. }
            | crate::mesh_core::Request::NanWakeup { .. })
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
    fn http_assets_use_upstream_default_without_override() {
        let unique = "LMESH_UNSET_HTTP_WEB_DIR_TEST";
        assert!(std::env::var_os(unique).is_none());
        if std::env::var_os("MESH_HTTP_WEB_DIR").is_none() {
            assert!(http_web_root(unique).is_none());
        }
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
