use std::{
    path::PathBuf,
    sync::{Arc, LazyLock},
    time::Instant,
};

use anyhow::{Context, Result};
use lmesh::{LmeshService, LocalDiscovery};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::time::{Duration, sleep};
use tracing::{debug, error, warn};

const DEFAULT_ANNOUNCE_INTERVAL_SECS: u64 = 60;
const DEFAULT_STANDALONE_SOCKET: &str = "lmesh/mesh.sock";
const ANNOUNCE_INTERVAL_ENV: &str = "LMESH_ANNOUNCE_INTERVAL_SECS";
const CONTROL_SOCKET_ENV: &str = "LMESH_CONTROL_SOCKET";
const WIFI_DISCOVERY_SOCKET_ENV: &str = "LMESH_WIFI_CONTROL_SOCKET";
const DEFAULT_WIFI_DISCOVERY_SOCKET: &str = "/run/mesh/lmesh-wifi/mesh.sock";
const RAWNAN_AUTOSTART_ENV: &str = "LMESH_RAWNAN_AUTOSTART";
const RAW_WIFI_CHANNEL_ENV: &str = "LMESH_RAW_WIFI_CHANNEL";
const AP_AUTOSTART_ENV: &str = "LMESH_AP_AUTOSTART";
const AP_IFACE_ENV: &str = "LMESH_AP_IFACE";
const AP_BEACON_INTERVAL_ENV: &str = "LMESH_AP_BEACON_INTERVAL_TU";
const DEFAULT_LMESH_AP_BEACON_INTERVAL_TU: u16 = 500;

/// Generated public catalog. Only reviewed entries carry numeric tags, so the
/// CBOR path cannot accidentally expose or number a legacy control method.
static CONTROL_CATALOG: LazyLock<mesh::tagged::TaggedCatalog> = LazyLock::new(|| {
    let mut tools =
        serde_json::from_str::<serde_json::Value>(include_str!("../resources/tools.json"))
            .expect("lmesh tools.json must be valid JSON");
    let wifi_tools = serde_json::from_str::<serde_json::Value>(include_str!(
        "../../lmesh-wifi/resources/tools.json"
    ))
    .expect("lmesh-wifi tools.json must be valid JSON");
    tools
        .as_array_mut()
        .expect("lmesh tools catalog must be an array")
        .extend(
            wifi_tools
                .as_array()
                .expect("lmesh-wifi tools catalog must be an array")
                .iter()
                .cloned(),
        );
    mesh::tagged::TaggedCatalog::from_tools_json(&tools)
        .expect("lmesh tools.json must be a valid tagged catalog")
});

#[tokio::main]
async fn main() -> Result<()> {
    let (trace_buffer, _trace_guard) = mesh::local_trace::init("lmesh");
    mesh::local_trace::serve("lmesh", trace_buffer.clone());
    if let Err(error) = run_server(trace_buffer).await {
        // mesh-init intentionally discards child stderr in the production
        // service unit. Persist the startup failure in the service log so a
        // stale control socket is diagnosable without changing radio state or
        // replacing the supervised process by hand.
        error!(error = %error, "lmesh_server_terminated");
        return Err(error);
    }
    Ok(())
}

async fn run_server(trace_buffer: mesh::local_trace::LogBuffer) -> Result<()> {
    let mut discovery = LocalDiscovery::new(None).await?;
    discovery.start().await?;
    let discovery = Arc::new(discovery);
    let service = Arc::new(LmeshService::new(discovery.clone()));
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
    // `lmesh` starts unassociated by default. A lab AP is an explicit startup
    // choice; unlike lmesh-wifi's normal infrastructure AP it uses 500 TU so
    // it can be a quiet channel-6 fallback NAN timing anchor.
    let ap_started = if ap_autostart_enabled() {
        let iface = std::env::var(AP_IFACE_ENV).unwrap_or_else(|_| "wlan1".to_owned());
        let result = service.start_default_open_ap(iface, channel, ap_beacon_interval_tu());
        if !result
            .get("ok")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false)
        {
            warn!(?result, "lmesh_optional_ap_start_failed");
        }
        result
            .get("ok")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false)
    } else {
        false
    };
    let monitor_fixture = if ap_started {
        service.prepare_default_ap_rawnan_monitor(channel)
    } else {
        service.prepare_default_rawnan_monitor(channel)
    };
    let monitor_ready = monitor_fixture
        .get("ok")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    if monitor_ready {
        debug!(?monitor_fixture, channel, "raw_monitor_fixture_started");
    } else {
        warn!(
            ?monitor_fixture,
            channel, "raw_monitor_fixture_start_failed"
        );
    }
    // Startup is always the unassociated NAN+NOW monitor personality.  STA
    // is a replacement epoch selected later by the common transport.start
    // CBOR command, exactly as on firmware.
    // The fixture preparation report is diagnostic only. An externally
    // prepared permanent monitor can be usable even when that report is not
    // affirmative (for example after a supervised process restart), and the
    // listener itself is the non-mutating capability check. Do not leave NAN
    // receive disabled merely because a prior lifecycle step was inconclusive.
    let rawnan_started = if rawnan_autostart_enabled() {
        let result = service.start_default_rawnan();
        debug!(?result, "rawnan_default_started");
        result
            .get("ok")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false)
    } else {
        false
    };
    if !rawnan_started && rawnan_autostart_enabled() {
        warn!("rawnan_autostart_failed");
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
    // NAN uses a much lower presence cadence than UDP multicast. Updating the
    // descriptor itself makes it pending for the next DW; it does not send
    // from this timer or change the permanent monitor fixture.
    let active_publish_service = service.clone();
    tokio::spawn(async move {
        loop {
            sleep(Duration::from_secs(15 * 60)).await;
            let uptime_secs = active_publish_started.elapsed().as_secs();
            if let Err(error) = active_publish_service.refresh_active_nan_publish(uptime_secs) {
                warn!(%error, "rawnan_active_publish_refresh_failed");
            }
        }
    });

    let listen_path = standalone_listen_path()?;
    let listen_path = listen_path.to_string_lossy().into_owned();
    let mut listener = mesh::server::MeshListener::new("lmesh", Some(&listen_path))
        .map_err(|e| anyhow::anyhow!("lmesh listener error: {}", e))?;
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

fn announce_interval() -> Duration {
    let secs = std::env::var(ANNOUNCE_INTERVAL_ENV)
        .ok()
        .and_then(|value| parse_announce_interval_secs(&value));
    Duration::from_secs(secs.unwrap_or(DEFAULT_ANNOUNCE_INTERVAL_SECS))
}

fn rawnan_autostart_enabled() -> bool {
    std::env::var(RAWNAN_AUTOSTART_ENV)
        .map(|value| !matches!(value.as_str(), "0" | "false" | "FALSE" | "off" | "OFF"))
        .unwrap_or(true)
}

fn ap_autostart_enabled() -> bool {
    std::env::var(AP_AUTOSTART_ENV)
        .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "on" | "ON"))
        // lmesh is the channel-6 NAN/NOW lab service. Keep its independently
        // owned AP up at the 500-TU fallback cadence unless an operator
        // explicitly selects the AP-off experiment. This is startup policy,
        // never an E2E-test side effect.
        .unwrap_or(true)
}

fn ap_beacon_interval_tu() -> u16 {
    std::env::var(AP_BEACON_INTERVAL_ENV)
        .ok()
        .and_then(|value| value.parse::<u16>().ok())
        .map(|value| value.clamp(10, 1000))
        .unwrap_or(DEFAULT_LMESH_AP_BEACON_INTERVAL_TU)
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

fn standalone_listen_path() -> Result<PathBuf> {
    let path = std::env::var_os(CONTROL_SOCKET_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_STANDALONE_SOCKET));
    resolve_relative_path(path)
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
    if response.get("success").and_then(serde_json::Value::as_bool) != Some(true) {
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
                "success": true,
                "data": {"subscribed": true, "service": "lmesh", "targets": config.targets.clone()}
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
        Ok(Some(mesh::wire::response_ok(
            id,
            serde_json::to_value(response)?,
        )))
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
            .context("tagged-CBOR destination must be a six-byte MAC string")?
            .to_owned();
        // `to` selects this directed next hop.  Do not carry it into the
        // one-hop radio payload or the receiving host/device would classify
        // the same record as another forwarding request instead of executing
        // its documented method.
        record.to = None;
        let wire = mesh::cbor::encode_record(&record)?;
        let result = self.service.forward_tagged_record(&destination, &wire);
        Ok(Some(mesh::wire::response_ok(id, result)))
    }
}

fn decode_lmesh_tagged_request(record: &mesh::tagged::TaggedRecord) -> Result<lmesh::Request> {
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
        "nodes" => serde_json::from_value::<lmesh::api::LmeshNodesRequest>(value)
            .map(|_| lmesh::Request::Nodes),
        "announces" => serde_json::from_value::<lmesh::api::LmeshAnnouncesRequest>(value)
            .map(|_| lmesh::Request::Announces),
        "get_node" => {
            serde_json::from_value::<lmesh::api::LmeshGetNodeRequest>(value).map(|request| {
                lmesh::Request::GetNode {
                    public_key: request.public_key,
                }
            })
        }
        "announce" => {
            serde_json::from_value::<lmesh::api::LmeshAnnounceRequest>(value).map(|request| {
                lmesh::Request::Announce {
                    metadata: request
                        .metadata
                        .and_then(|metadata| serde_json::from_value(metadata).ok()),
                }
            })
        }
        "status" => serde_json::from_value::<lmesh::api::LmeshStatusRequest>(value)
            .map(|_| lmesh::Request::Status),
        "neighbors" => {
            serde_json::from_value::<lmesh::api::LmeshNeighborsRequest>(value).map(|request| {
                lmesh::Request::Neighbors {
                    seen_within_sec: request.seen_within_sec,
                }
            })
        }
        "links.list" => {
            serde_json::from_value::<lmesh::api::LmeshLinksListRequest>(value).map(|request| {
                lmesh::Request::LinksList {
                    seen_within_sec: request.seen_within_sec,
                }
            })
        }
        "ping" => serde_json::from_value::<lmesh::api::LmeshPingRequest>(value).map(|request| {
            lmesh::Request::Ping {
                radio: request.radio,
                wait_ms: request.wait_ms,
                nonce: request.nonce,
            }
        }),
        "send" => serde_json::from_value::<lmesh::api::LmeshSendRequest>(value).map(|request| {
            lmesh::Request::Send {
                radio: request.radio,
                destination: request.destination,
                payload: request.payload,
            }
        }),
        "radios.list" => serde_json::from_value::<lmesh::api::LmeshRadiosListRequest>(value)
            .map(|_| lmesh::Request::RadiosList),
        "messages.history" => serde_json::from_value::<lmesh::api::LmeshMessagesHistoryRequest>(
            value,
        )
        .map(|request| lmesh::Request::MessagesHistory {
            keys: request.keys,
            limit: request
                .limit
                .map(|limit| limit.min(usize::MAX as u64) as usize),
        }),
        "wifi.ap.status" => {
            serde_json::from_value::<lmesh_wifi::api::ApStatusRequest>(value).map(|request| {
                lmesh::Request::WifiApStatus {
                    iface: request.iface,
                }
            })
        }
        "wifi.sta.status" => serde_json::from_value::<lmesh_wifi::api::StaStatusRequest>(value)
            .map(|request| lmesh::Request::WifiStaStatus {
                iface: request.iface,
            }),
        "wifi.rawnan.status" => {
            serde_json::from_value::<lmesh_wifi::api::RawNanStatusRequest>(value).map(|request| {
                lmesh::Request::WifiRawNanStatus {
                    iface: request.iface,
                }
            })
        }
        "wifi.rawnan.active_publish" => {
            serde_json::from_value::<lmesh_wifi::api::WifiRawnanActivePublishRequest>(value)
                .and_then(|request| {
                    let enabled = request.enabled.ok_or_else(|| {
                        serde_json::Error::io(std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            "enabled is required",
                        ))
                    })?;
                    Ok(lmesh::Request::WifiRawNanActivePublish {
                        iface: request.iface,
                        enabled,
                        service_info_hex: request.service_info_hex,
                    })
                })
        }
        "wifi.interface.status" => {
            serde_json::from_value::<lmesh_wifi::api::InterfaceStatusRequest>(value).map(
                |request| lmesh::Request::WifiInterfaceStatus {
                    iface: request.iface,
                },
            )
        }
        "wifi.ap.stations" => serde_json::from_value::<lmesh_wifi::api::ApStationsRequest>(value)
            .map(|request| lmesh::Request::WifiApStations {
                iface: request.iface,
            }),
        "wifi.raw.metrics" => serde_json::from_value::<lmesh_wifi::api::RawMetricsRequest>(value)
            .map(|request| lmesh::Request::WifiRawMetrics {
                iface: request.iface,
            }),
        "wifi.probe.plan" => serde_json::from_value::<lmesh_wifi::api::ProbePlanRequest>(value)
            .map(|request| lmesh::Request::WifiProbePlan {
                iface: request.iface,
                source_id: request.source_id,
                target_id: request.target_id,
                short_bytes: request.short_bytes,
                long_bytes: request.long_bytes,
            }),
        "wifi.mgmt.capture" => serde_json::from_value::<lmesh::api::WifiMgmtCaptureRequest>(value)
            .map(|request| lmesh::Request::WifiMgmtCapture {
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
        let announce = dmesh_server::announce::Announce::discovery([0xC6; 16], 16, 9, 1, 4);
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
    fn reviewed_numeric_catalog_decodes_into_lmesh_request() {
        let request = decode_lmesh_tagged_request(&mesh::tagged::TaggedRecord {
            component: mesh::tagged::NameOrTag::Tag(4),
            method: mesh::tagged::NameOrTag::Tag(2),
            id: Some(serde_json::json!(3)),
            env: [(
                mesh::tagged::NameOrTag::Tag(1),
                serde_json::json!("node-key"),
            )]
            .into_iter()
            .collect(),
            ..Default::default()
        })
        .unwrap();
        assert!(matches!(
            request,
            lmesh::Request::GetNode { public_key } if public_key == "node-key"
        ));
    }

    #[test]
    fn reviewed_discovery_tags_decode_through_typed_request_shape() {
        let request = decode_lmesh_tagged_request(&mesh::tagged::TaggedRecord {
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
        .unwrap();
        assert!(matches!(
            request,
            lmesh::Request::Ping {
                radio: Some(radio),
                wait_ms: Some(250),
                nonce: Some(nonce),
            } if radio == "rawnan" && nonce == "probe-4"
        ));
    }

    #[test]
    fn reviewed_history_tags_decode_with_bounded_request_shape() {
        let request = decode_lmesh_tagged_request(&mesh::tagged::TaggedRecord {
            component: mesh::tagged::NameOrTag::Tag(4),
            method: mesh::tagged::NameOrTag::Tag(10),
            id: Some(serde_json::json!(10)),
            env: [
                (
                    mesh::tagged::NameOrTag::Tag(1),
                    serde_json::json!("wifi.raw.dispatch"),
                ),
                (mesh::tagged::NameOrTag::Tag(2), serde_json::json!(20)),
            ]
            .into_iter()
            .collect(),
            ..Default::default()
        })
        .unwrap();
        assert!(matches!(
            request,
            lmesh::Request::MessagesHistory {
                keys: Some(keys),
                limit: Some(20),
            } if keys == "wifi.raw.dispatch"
        ));
    }

    #[test]
    fn reviewed_wifi_tags_are_available_from_lmesh_too() {
        let request = decode_lmesh_tagged_request(&mesh::tagged::TaggedRecord {
            component: mesh::tagged::NameOrTag::Tag(5),
            method: mesh::tagged::NameOrTag::Tag(1),
            id: Some(serde_json::json!(5)),
            env: [(mesh::tagged::NameOrTag::Tag(1), serde_json::json!("wlan1"))]
                .into_iter()
                .collect(),
            ..Default::default()
        })
        .unwrap();
        assert!(matches!(
            request,
            lmesh::Request::WifiApStatus { iface: Some(iface) } if iface == "wlan1"
        ));
    }

    #[test]
    fn reviewed_management_capture_tags_decode_through_typed_request_shape() {
        let request = decode_lmesh_tagged_request(&mesh::tagged::TaggedRecord {
            component: mesh::tagged::NameOrTag::Tag(5),
            method: mesh::tagged::NameOrTag::Tag(13),
            id: Some(serde_json::json!(13)),
            env: [
                (mesh::tagged::NameOrTag::Tag(1), serde_json::json!("wlan1")),
                (mesh::tagged::NameOrTag::Tag(2), serde_json::json!(6)),
                (mesh::tagged::NameOrTag::Tag(3), serde_json::json!(4_000)),
                (mesh::tagged::NameOrTag::Tag(4), serde_json::json!(128)),
                (mesh::tagged::NameOrTag::Tag(5), serde_json::json!(false)),
            ]
            .into_iter()
            .collect(),
            ..Default::default()
        })
        .unwrap();
        assert!(matches!(
            request,
            lmesh::Request::WifiMgmtCapture {
                iface: Some(iface),
                channel: Some(6),
                capture_ms: Some(4_000),
                max_frames: Some(128),
                active: Some(false),
            } if iface == "wlan1"
        ));
    }

    #[test]
    fn reviewed_wifi_metrics_are_available_from_lmesh_too() {
        let request = decode_lmesh_tagged_request(&mesh::tagged::TaggedRecord {
            component: mesh::tagged::NameOrTag::Tag(5),
            method: mesh::tagged::NameOrTag::Tag(6),
            id: Some(serde_json::json!(6)),
            env: [(mesh::tagged::NameOrTag::Tag(1), serde_json::json!("wlan1"))]
                .into_iter()
                .collect(),
            ..Default::default()
        })
        .unwrap();
        assert!(matches!(
            request,
            lmesh::Request::WifiRawMetrics { iface: Some(iface) } if iface == "wlan1"
        ));
    }

    #[test]
    fn reviewed_pair_probe_plan_is_available_from_lmesh_too() {
        let request = decode_lmesh_tagged_request(&mesh::tagged::TaggedRecord {
            component: mesh::tagged::NameOrTag::Tag(5),
            method: mesh::tagged::NameOrTag::Tag(16),
            id: Some(serde_json::json!(16)),
            env: [
                (mesh::tagged::NameOrTag::Tag(1), serde_json::json!("wlan1")),
                (mesh::tagged::NameOrTag::Tag(2), serde_json::json!("111111111111")),
                (mesh::tagged::NameOrTag::Tag(3), serde_json::json!("222222222222")),
                (mesh::tagged::NameOrTag::Tag(4), serde_json::json!(4096)),
                (mesh::tagged::NameOrTag::Tag(5), serde_json::json!(65536)),
            ]
            .into_iter()
            .collect(),
            ..Default::default()
        })
        .unwrap();
        assert!(matches!(
            request,
            lmesh::Request::WifiProbePlan {
                iface: Some(iface),
                source_id,
                target_id,
                short_bytes: Some(4096),
                long_bytes: Some(65536),
            } if iface == "wlan1" && source_id == "111111111111" && target_id == "222222222222"
        ));
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
