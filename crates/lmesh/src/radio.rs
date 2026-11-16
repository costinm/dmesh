//! The Wi-Fi radio of this node: `rawnan`'s raw bearer (open AP on the shared channel +
//! monitor, carrying NOW and NAN), started from the configured WLAN and wired to the
//! discovery engine and the registry. No `lmesh-wifi` is involved.
//!
//! Linux implements the common API only: `transport.set` (NAN mode),
//! `discovery.active`, `nan.wakeup` and `telemetry.nan_status`. Discovery is the same
//! request and the same announce on every medium (UDP multicast, NAN, NOW); the radio
//! answers a request that arrives on NOW, like it does on UDP.

use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use dmesh_discovery::{Carrier, Engine, Received};
use dmesh_rawnan::linux::{
    DEFAULT_SSID, NL80211_IFTYPE_AP, NL80211_IFTYPE_STATION, NanAnnounce, NanPacketKind,
    Nl80211Socket, NowKind, Observer, Radio, RadioConfig, SHARED_CHANNEL, channel_to_freq,
    ensure_link_local_address, freq_to_channel, ifindex, link_state_result, link_up_confirmed,
};
use dmesh_discovery::discovery::DiscoveryPacketKind;
use dmesh_rawnan::raw_wifi::{
    RAW_WIFI_COMPONENT, RAW_WIFI_METHOD_SCAN, RAW_WIFI_SCAN_MAX_RECORDS, RawWifiLabRequest,
    RawWifiScanEntry, RawWifiScanRequest, RawWifiScanResponse, decode_raw_wifi_handler_record,
    encode_raw_wifi_scan_response,
};
use lmesh_wifi::mesh_core::LocalDiscovery;
use lmesh_wifi::rpc_router::{
    Call, CallContext, DiscoveryActiveRequest, DiscoveryActiveResponse, Handler, Registry, Reply,
    TelemetryNanRequest, TelemetryNanResponse, TelemetryNanStatusRequest,
    TelemetryNanStatusResponse, TelemetryNowRequest, TelemetryNowResponse, TelemetryUdp6Request,
    TelemetryUdp6Response, TelemetryWifiLinkRequest, TelemetryWifiLinkResponse,
    TransportSetRequest, TransportSetResponse, TypedHandler, methods,
};
use serde_json::json;

/// How often the interface state is re-checked and the NAN publish refreshed.
const MAINTAIN_INTERVAL: Duration = Duration::from_secs(30);
/// `transport.set` mode values (`TransportKind` on the wire).
const MODE_OFF: u8 = 0;
const MODE_STA: u8 = 1;
const MODE_NAN: u8 = 6;
/// Default WPA2 passphrase for DMesh softAP when WPA2 AP mode is selected without an explicit passphrase.
const DEFAULT_AP_PASSPHRASE: &str = "dmesh-p2p";

#[derive(Clone, Debug, Eq, PartialEq)]
enum DesiredTransportMode {
    Off,
    NanOpenAp,
    NanWpa2Ap {
        ssid: String,
        passphrase: String,
    },
    Sta {
        ssid: String,
        channel: u8,
        nan_coexist: bool,
    },
}

struct TransportRuntime {
    iface: String,
    mode: DesiredTransportMode,
    supplicant: Option<lmesh_wpa::WpaSupplicant>,
}

impl TransportRuntime {
    fn new(iface: String, configured: bool) -> Self {
        Self {
            iface,
            mode: if configured {
                DesiredTransportMode::NanOpenAp
            } else {
                DesiredTransportMode::Off
            },
            supplicant: None,
        }
    }
}

fn wpa_runtime_dir() -> PathBuf {
    if let Some(path) = std::env::var_os("LMESH_WPA_RUNTIME_DIR") {
        return PathBuf::from(path);
    }
    if let Some(socket) = std::env::var_os("LMESH_CONTROL_SOCKET")
        && let Some(parent) = PathBuf::from(socket).parent()
    {
        return parent.join("wpa");
    }
    PathBuf::from("/run/mesh/lmesh/wpa")
}

/// Feeds what the radio observes into the discovery engine, which decodes, validates
/// and records it. The engine only exists once the service is running, so it is set
/// late.
#[derive(Default)]
pub struct EngineObserver {
    engine: OnceLock<Arc<Engine>>,
}

impl EngineObserver {
    fn observe(
        &self,
        bearer: &str,
        peer: [u8; 6],
        bssid: Option<[u8; 6]>,
        kind: DiscoveryPacketKind,
        payload: &[u8],
    ) -> Received {
        let Some(engine) = self.engine.get() else {
            return Received::Ignored;
        };
        let peer_text = mac_text(&peer);
        let carrier = Carrier {
            bearer,
            peer: &peer_text,
            sender: None,
            rssi_dbm: None,
            bssid,
            channel: None,
            kind,
        };
        if payload.is_empty() {
            engine.observe_provisional(&carrier, &peer_text, payload);
            return Received::Ignored;
        }
        engine.on_datagram(&carrier, payload)
    }
}

fn mac_text(mac: &[u8; 6]) -> String {
    mac.iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

impl Observer for EngineObserver {
    fn nan(&self, peer: [u8; 6], bssid: Option<[u8; 6]>, payloads: &[&[u8]]) -> NanAnnounce {
        let mut seen = NanAnnounce::default();
        if payloads.is_empty() {
            let _ = self.observe("nan", peer, bssid, DiscoveryPacketKind::ActivePublish, &[]);
            return seen;
        }
        for payload in payloads {
            match self.observe("nan", peer, bssid, DiscoveryPacketKind::ActivePublish, payload) {
                Received::Announce { key, .. } => {
                    seen.summary = Some(json!({"device_id": key}));
                }
                Received::Rejected => seen.invalid_identity = true,
                _ => {}
            }
        }
        seen
    }

    fn nan_packet(&self, peer: [u8; 6], bssid: Option<[u8; 6]>, kind: NanPacketKind, payload: &[u8]) {
        let kind = match kind {
            NanPacketKind::ActiveSubscribe => DiscoveryPacketKind::ActiveSubscribe,
            NanPacketKind::Followup => DiscoveryPacketKind::Followup,
        };
        self.observe("nan", peer, bssid, kind, payload);
    }

    fn now(
        &self,
        peer: [u8; 6],
        bssid: Option<[u8; 6]>,
        _kind: NowKind,
        payload: &[u8],
    ) -> Option<Vec<u8>> {
        // NOW discovery is NAN's discovery in NOW's envelope: the same bytes, the same
        // engine, and a request is answered on the medium it came on. Anything that is
        // not an announce or a request is ignored.
        match self.observe("now", peer, bssid, DiscoveryPacketKind::ActivePublish, payload) {
            Received::Request { reply, .. } => Some(reply),
            _ => None,
        }
    }
}

/// The interface lmesh runs the radio on: the first of `LMESH_INTERFACES`, else
/// `LMESH_WIFI_IFACE`, else `wlan1`. The flag says whether a WLAN is configured, so
/// the radio should be started; without one the bearer exists but nothing runs.
pub fn interface() -> (String, bool) {
    if let Some(first) = lmesh_wifi::InterfaceSet::from_environment().names().first() {
        return (first.clone(), true);
    }
    (
        std::env::var("LMESH_WIFI_IFACE").unwrap_or_else(|_| "wlan1".to_owned()),
        false,
    )
}

/// The raw bearer: the QUIC bearer to attach to the node, the handle, and the
/// observer to give the engine to later.
pub fn create<P>() -> (
    dmesh_rawnan::linux::espnow_bearer::EspNowBearer<P>,
    Radio,
    Arc<EngineObserver>,
    bool,
)
where
    P: mesh_api::pool::PacketPool + Clone + Send + Sync + 'static,
    P::Packet: Send,
{
    let (iface, configured) = interface();
    let observer = Arc::new(EngineObserver::default());
    let (bearer, radio) = Radio::new::<P>(RadioConfig::for_interface(&iface), observer.clone());
    (bearer, radio, observer, configured)
}

/// Start the radio when a WLAN is configured, keep it in its target state, and
/// register the radio's methods.
pub fn register(
    registry: &Registry,
    radio: Radio,
    observer: &EngineObserver,
    discovery: &Arc<LocalDiscovery>,
    configured: bool,
) {
    let _ = observer.engine.set(discovery.engine().clone());
    let iface = interface().0;
    let runtime = Arc::new(Mutex::new(TransportRuntime::new(iface.clone(), configured)));
    if configured {
        maintain(radio.clone(), discovery.clone(), runtime.clone());
    }
    persist_nodes(discovery.clone());
    register_methods(registry, radio, discovery.clone(), iface, runtime);
}

/// Keep the stable part of the inventory on disk: every minute, the authenticated devices are
/// merged into the node directory (identity, name, domain, type, a stable ESP MAC). The inventory
/// itself, live endpoints and sleep state stay in RAM and are rebuilt by discovery after a restart.
fn persist_nodes(discovery: Arc<LocalDiscovery>) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(60)).await;
            let devices = discovery.engine().devices();
            let store = crate::companion::device_store();
            match tokio::task::spawn_blocking(move || {
                dmesh_discovery::persist::persist_devices(&store, &devices)
            })
            .await
            {
                Ok(Ok(0)) | Err(_) => {}
                Ok(Ok(written)) => tracing::info!(written, "lmesh_node_records_updated"),
                Ok(Err(error)) => tracing::warn!(%error, "lmesh_node_records_failed"),
            }
        }
    });
}

/// Bring the interface to the chain's target state, and keep it there. Starting is
/// idempotent, so the periodic check changes nothing while the interface is right and
/// recovers when the adapter reappears. The announce is published (NAN and NOW) once it
/// is available and then at the shared interval, like the firmware: every publish
/// restarts a burst of window transmissions, so it is not repeated at the check rate.
fn maintain(radio: Radio, discovery: Arc<LocalDiscovery>, runtime: Arc<Mutex<TransportRuntime>>) {
    let started = std::time::Instant::now();
    let interval = Duration::from_millis(dmesh_rawnan::NAN_ACTIVE_PUBLISH_INTERVAL_MS);
    tokio::spawn(async move {
        let mut last_publish: Option<std::time::Instant> = None;
        loop {
            let mode = runtime
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .mode
                .clone();
            let worker = radio.clone();
            let started_ok = match mode {
                DesiredTransportMode::NanOpenAp => {
                    match tokio::task::spawn_blocking(move || worker.start()).await {
                        Ok(Ok(outcome)) => {
                            tracing::debug!(?outcome, "lmesh_radio_checked");
                            true
                        }
                        Ok(Err(error)) => {
                            tracing::warn!(error = %format!("{error:#}"), "lmesh_radio_start_failed");
                            false
                        }
                        Err(error) => {
                            tracing::warn!(%error, "lmesh_radio_task_failed");
                            false
                        }
                    }
                }
                DesiredTransportMode::NanWpa2Ap { .. }
                | DesiredTransportMode::Sta {
                    channel: SHARED_CHANNEL,
                    nan_coexist: true,
                    ..
                } => match tokio::task::spawn_blocking(move || {
                    worker.start_monitor_only(SHARED_CHANNEL)
                })
                .await
                {
                    Ok(Ok(())) => true,
                    Ok(Err(error)) => {
                        tracing::warn!(
                            error = %format!("{error:#}"),
                            "lmesh_radio_monitor_only_failed"
                        );
                        false
                    }
                    Err(error) => {
                        tracing::warn!(%error, "lmesh_radio_task_failed");
                        false
                    }
                },
                DesiredTransportMode::Sta { .. } | DesiredTransportMode::Off => false,
            };
            if started_ok && last_publish.is_none_or(|at| at.elapsed() >= interval) {
                match discovery.nan_announce_service_info(started.elapsed().as_secs()) {
                    Ok(service_info) => match radio.set_publish(&service_info) {
                        Ok(()) => last_publish = Some(std::time::Instant::now()),
                        Err(error) => {
                            tracing::warn!(error = %format!("{error:#}"), "lmesh_nan_publish_failed");
                        }
                    },
                    Err(error) => {
                        tracing::warn!(error = %format!("{error:#}"), "lmesh_nan_announce_failed");
                    }
                }
            }
            tokio::time::sleep(MAINTAIN_INTERVAL).await;
        }
    });
}

/// `telemetry.now`, `telemetry.nan`, `telemetry.udp6` and `telemetry.wifi_link`: the counters
/// Linux has a source for (API.md names them per method); the rest stay absent, never zero.
fn register_telemetry(registry: &Registry, radio: &Radio, iface: String) {
    let now = radio.clone();
    assert!(
        registry.register(
            methods::TELEMETRY_NOW_METRICS,
            TypedHandler::new(move |_: TelemetryNowRequest, _: CallContext| {
                let counters = now.counters();
                async move {
                    Ok::<_, String>(TelemetryNowResponse {
                        tx_attempted: Some(counters.now_tx_attempted),
                        tx_accepted: Some(counters.now_tx_accepted),
                        tx_failed: Some(counters.now_tx_failed),
                        rx_dispatched: Some(counters.now_quic),
                        rx_accepted: Some(counters.now_actions),
                        rx_self_echo: Some(counters.now_reflections),
                        ..Default::default()
                    })
                }
            }),
        ),
        "telemetry.now registered twice"
    );
    let nan = radio.clone();
    assert!(
        registry.register(
            methods::TELEMETRY_NAN_METRICS,
            TypedHandler::new(move |_: TelemetryNanRequest, _: CallContext| {
                let counters = nan.counters();
                async move {
                    Ok::<_, String>(TelemetryNanResponse {
                        beacons: Some(counters.nan_beacons),
                        sdfs: Some(counters.nan_service_frames),
                        ..Default::default()
                    })
                }
            }),
        ),
        "telemetry.nan registered twice"
    );
    assert!(
        registry.register(
            methods::TELEMETRY_UDP6_METRICS,
            TypedHandler::new(|_: TelemetryUdp6Request, _: CallContext| async {
                Ok::<_, String>(TelemetryUdp6Response {
                    rx_invalid: Some(lmesh_wifi::mesh_core::announce_parse_errors()),
                    ..Default::default()
                })
            }),
        ),
        "telemetry.udp6 registered twice"
    );
    assert!(
        registry.register(
            methods::TELEMETRY_WIFI_LINK_METRICS,
            TypedHandler::new(move |_: TelemetryWifiLinkRequest, _: CallContext| {
                let iface = iface.clone();
                async move {
                    let links = tokio::task::spawn_blocking(move || lmesh_wifi::station_links(&iface))
                        .await
                        .map_err(|error| error.to_string())?
                        .map_err(|error| format!("{error:#}"))?;
                    Ok::<_, String>(TelemetryWifiLinkResponse {
                        links: Some(links),
                        ..Default::default()
                    })
                }
            }),
        ),
        "telemetry.wifi_link registered twice"
    );
}

fn register_methods(
    registry: &Registry,
    radio: Radio,
    discovery: Arc<LocalDiscovery>,
    iface: String,
    runtime: Arc<Mutex<TransportRuntime>>,
) {
    register_telemetry(registry, &radio, iface.clone());
    let status_radio = radio.clone();
    assert!(
        registry.register(
            methods::TELEMETRY_NAN_STATUS,
            TypedHandler::new(move |_: TelemetryNanStatusRequest, _: CallContext| {
                let status = status_radio.nan_status();
                async move {
                    Ok::<_, String>(TelemetryNanStatusResponse {
                        active: Some(status.active),
                        cluster_id: status.cluster_id.map(|mac| mac.to_vec()),
                        sync_id: status.sync_id.map(|mac| mac.to_vec()),
                        publishing: Some(status.publishing),
                        publish_pending: None,
                    })
                }
            }),
        ),
        "telemetry.nan_status registered twice"
    );

    let transport_radio = radio.clone();
    let transport_runtime = runtime.clone();
    assert!(
        registry.register(
            methods::TRANSPORT_SET,
            TypedHandler::new(move |request: TransportSetRequest, _: CallContext| {
                let radio = transport_radio.clone();
                let runtime = transport_runtime.clone();
                async move {
                    tokio::task::spawn_blocking(move || apply_transport_set(&radio, &runtime, request))
                        .await
                        .map_err(|error| error.to_string())?
                }
            }),
        ),
        "transport.set registered twice"
    );

    assert!(
        registry.register(
            methods::WIFI_SCAN,
            WifiScanHandler {
                iface,
                runtime,
            }
        ),
        "wifi.scan registered twice"
    );

    let active_radio = radio.clone();
    let active_discovery = discovery.clone();
    assert!(
        registry.register(
            methods::DISCOVERY_ACTIVE,
            TypedHandler::new(move |request: DiscoveryActiveRequest, _: CallContext| {
                let (radio, discovery) = (active_radio.clone(), active_discovery.clone());
                async move { discovery_active(&radio, &discovery, request).await }
            }),
        ),
        "discovery.active registered twice"
    );

    assert!(
        registry.register(
            methods::NAN_WAKEUP,
            WakeupHandler { radio: radio.clone(), pair: false }
        ),
        "nan.wakeup registered twice"
    );
    assert!(
        registry.register(
            methods::NAN_PAIR_WAKEUP,
            WakeupHandler { radio, pair: true }
        ),
        "nan.pair_wakeup registered twice"
    );
}

/// How long a directed NOW request waits for its reply: a sleepy peer answers in a
/// DW0/DW8 window, up to a few seconds away.
const DIRECTED_WAIT: Duration = Duration::from_secs(8);

fn parse_mac(text: &str) -> Option<[u8; 6]> {
    let mut mac = [0u8; 6];
    let mut parts = text.split(':');
    for byte in &mut mac {
        *byte = u8::from_str_radix(parts.next()?, 16).ok()?;
    }
    parts.next().is_none().then_some(mac)
}

/// `discovery.active`: discovery on every medium, with the same request on each. UDP
/// multicast is sent once; NOW and NAN are sent now and again in the next discovery
/// windows (sleepy peers only listen in DW0 and DW8). `to` selects one peer: a
/// `udp://` endpoint, or a NOW MAC (a directed request whose reply is awaited).
async fn discovery_active(
    radio: &Radio,
    discovery: &Arc<LocalDiscovery>,
    request: DiscoveryActiveRequest,
) -> Result<DiscoveryActiveResponse, String> {
    if let Some(destination) = request.to.as_deref() {
        if destination.starts_with("udp://") {
            discovery
                .directed_request(destination)
                .await
                .map_err(|error| format!("{error:#}"))?;
            return Ok(DiscoveryActiveResponse::default());
        }
        let Some(peer) = parse_mac(destination) else {
            return Err(format!(
                "discovery.active to={destination}: expected udp://HOST or a MAC address"
            ));
        };
        let id = now_ms();
        let mut record = [0u8; 96];
        let used = dmesh_discovery::announce::encode_discovery_request(id, &mut record)
            .ok_or("encode announce.discovery")?;
        let waiting = discovery.engine().expect_response(id);
        // Directed: NOW and NAN, now and in the next discovery windows.
        radio.request(record[..used].to_vec(), Some(peer), true);
        let outcome = tokio::task::spawn_blocking(move || waiting.recv_timeout(DIRECTED_WAIT))
            .await
            .map_err(|error| error.to_string())?;
        discovery.engine().forget_response(id);
        return outcome
            .map(|_| DiscoveryActiveResponse::default())
            .map_err(|_| format!("no discovery reply from {destination}"));
    }
    let medium = request.medium.as_deref();
    let wants = |names: &[&str]| medium.is_none_or(|medium| names.contains(&medium));
    let mut failures = Vec::new();
    if wants(&["all", "mcast", "udp", "udp6"]) {
        if let Err(error) = discovery.broadcast_request().await {
            failures.push(format!("udp: {error:#}"));
        }
    }
    if wants(&["all", "nan", "now", "best"]) {
        let id = now_ms();
        let mut record = [0u8; 96];
        match dmesh_discovery::announce::encode_discovery_request(id, &mut record) {
            Some(used) => {
                radio.request(record[..used].to_vec(), None, wants(&["all", "nan", "best"]));
            }
            None => failures.push("encode announce.discovery".to_owned()),
        }
    }
    if failures.is_empty() {
        Ok(DiscoveryActiveResponse::default())
    } else {
        Err(failures.join("; "))
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as u64)
        .unwrap_or(1)
        .max(1)
}

fn apply_transport_set(
    radio: &Radio,
    runtime: &Arc<Mutex<TransportRuntime>>,
    request: TransportSetRequest,
) -> Result<TransportSetResponse, String> {
    let mode = request.mode.unwrap_or(MODE_NAN);
    let iface = {
        let guard = runtime
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        request
            .iface
            .clone()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| guard.iface.clone())
    };
    match mode {
        MODE_OFF => {
            {
                let mut guard = runtime
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                guard.mode = DesiredTransportMode::Off;
                guard.supplicant = None;
            }
            radio
                .stop_and_release()
                .map_err(|error| format!("{error:#}"))?;
            Ok(TransportSetResponse::default())
        }
        MODE_NAN => {
            if request.channel.is_some_and(|channel| channel != SHARED_CHANNEL) {
                return Err(format!(
                    "the shared channel is {SHARED_CHANNEL}, not {:?}",
                    request.channel
                ));
            }
            let ap_passphrase = request
                .ap_passphrase
                .as_deref()
                .or(request.passphrase.as_deref())
                .filter(|s| !s.is_empty());
            let wants_wpa2_ap = ap_passphrase.is_some() || request.open == Some(false);
            if wants_wpa2_ap {
                let passphrase = ap_passphrase.unwrap_or(DEFAULT_AP_PASSPHRASE);
                if !(8..=63).contains(&passphrase.len()) || passphrase.contains('\0') {
                    return Err(
                        "transport.set passphrase must contain 8 through 63 non-NUL bytes"
                            .to_owned(),
                    );
                }
                let ssid = request
                    .ap_ssid
                    .as_deref()
                    .or(request.ssid.as_deref())
                    .filter(|s| !s.is_empty())
                    .unwrap_or(DEFAULT_SSID)
                    .to_owned();
                {
                    let mut guard = runtime
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    guard.supplicant = None;
                }
                radio
                    .stop_and_release()
                    .map_err(|error| format!("{error:#}"))?;
                let _ = link_up_confirmed(&iface, 3);
                let supplicant = lmesh_wpa::WpaSupplicant::start(
                    &iface,
                    wpa_runtime_dir(),
                    Duration::from_secs(5),
                )
                .map_err(|error| format!("wpa_supplicant start failed: {error:#}"))?;
                supplicant
                    .start_wpa2_ap(
                        ssid.as_bytes(),
                        passphrase,
                        channel_to_freq(SHARED_CHANNEL),
                        Duration::from_secs(15),
                    )
                    .map_err(|error| format!("WPA2 AP start failed: {error:#}"))?;
                let _ = ensure_link_local_address(&iface);
                radio
                    .start_monitor_only(SHARED_CHANNEL)
                    .map_err(|error| format!("monitor start failed: {error:#}"))?;
                let mut guard = runtime
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                guard.mode = DesiredTransportMode::NanWpa2Ap { ssid, passphrase: passphrase.to_owned() };
                guard.supplicant = Some(supplicant);
                Ok(TransportSetResponse::default())
            } else {
                {
                    let mut guard = runtime
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    guard.mode = DesiredTransportMode::NanOpenAp;
                    guard.supplicant = None;
                }
                radio.start().map_err(|error| format!("{error:#}"))?;
                let _ = ensure_link_local_address(&iface);
                Ok(TransportSetResponse::default())
            }
        }
        MODE_STA => {
            let infra = lmesh_wifi::load_default_infrastructure_credentials()
                .map_err(|error| format!("load infrastructure credentials: {error:#}"))?;
            let ssid = match request.ssid.as_deref().filter(|s| !s.is_empty()) {
                Some(ssid) => ssid.to_owned(),
                None => infra
                    .as_ref()
                    .map(|creds| creds.ssid().to_owned())
                    .ok_or_else(|| "transport.set mode=1 (STA) requires ssid or a default profile in infra-sta.toml".to_owned())?,
            };
            let bssid = match request.bssid.as_deref().filter(|s| !s.is_empty()) {
                Some(text) => Some(
                    parse_mac(text)
                        .ok_or_else(|| format!("transport.set bssid={text:?} is not a MAC address"))?,
                ),
                None => None,
            };
            let supplied_passphrase = request.passphrase.as_deref().filter(|s| !s.is_empty());
            if let Some(passphrase) = supplied_passphrase
                && (!(8..=63).contains(&passphrase.len()) || passphrase.contains('\0'))
            {
                return Err(
                    "transport.set passphrase must contain 8 through 63 non-NUL bytes".to_owned(),
                );
            }
            let credentials = if request.open == Some(true) {
                None
            } else if let Some(passphrase) = supplied_passphrase {
                Some((
                    passphrase.to_owned(),
                    lmesh_wifi::InfrastructureSecurity::Wpa2Psk,
                ))
            } else {
                infra
                    .as_ref()
                    .and_then(|creds| creds.find_by_ssid(&ssid))
                    .map(|p| (p.password().to_owned(), p.security()))
            };

            {
                let mut guard = runtime
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                guard.mode = DesiredTransportMode::Off;
                guard.supplicant = None;
            }
            radio
                .stop_and_release()
                .map_err(|error| format!("{error:#}"))?;

            let (associated_channel, supplicant_opt) = if let Some((passphrase, security)) = credentials {
                let _ = link_state_result(&iface, true);
                let supplicant = lmesh_wpa::WpaSupplicant::start(
                    &iface,
                    wpa_runtime_dir(),
                    Duration::from_secs(5),
                )
                .map_err(|error| format!("wpa_supplicant start failed: {error:#}"))?;
                let connect_res = match security {
                    lmesh_wifi::InfrastructureSecurity::Wpa2Psk => {
                        supplicant.connect_wpa2(ssid.as_bytes(), &passphrase, Duration::from_secs(20))
                    }
                    lmesh_wifi::InfrastructureSecurity::Wpa3Sae => {
                        supplicant.connect_wpa3_sae(ssid.as_bytes(), &passphrase, Duration::from_secs(20))
                    }
                };
                connect_res.map_err(|error| format!("WPA STA connect to {ssid:?} failed: {error:#}"))?;
                let freq = supplicant
                    .connected_frequency(Duration::from_secs(2))
                    .map_err(|error| format!("query connected frequency: {error:#}"))?;
                let ch = freq_to_channel(freq).unwrap_or(request.channel.unwrap_or(0));
                (ch, Some(supplicant))
            } else {
                if request.open == Some(false) {
                    return Err(format!("no WPA credentials found for SSID {ssid:?}"));
                }
                let channel = request.channel.unwrap_or(SHARED_CHANNEL);
                if !(1..=13).contains(&channel) {
                    return Err(format!("open STA channel must be in 1..=13, not {channel}"));
                }
                let freq = channel_to_freq(channel);
                let index = ifindex(&iface).map_err(|error| format!("{error:#}"))?;
                let socket = Nl80211Socket::open().map_err(|error| format!("{error:#}"))?;
                socket
                    .set_interface_type(index, NL80211_IFTYPE_STATION)
                    .map_err(|error| format!("{error:#}"))?;
                let up = link_up_confirmed(&iface, 3);
                if up.get("ok").and_then(serde_json::Value::as_bool) != Some(true) {
                    return Err(format!("failed to bring {iface} up: {up}"));
                }
                socket
                    .connect_open(index, &ssid, freq, bssid)
                    .map_err(|error| format!("{error:#}"))?;
                let deadline = Instant::now() + Duration::from_secs(8);
                loop {
                    let peers = socket
                        .station_dump(index)
                        .map_err(|error| format!("{error:#}"))?;
                    if !peers.is_empty() {
                        break;
                    }
                    if Instant::now() >= deadline {
                        return Err(format!("timed out waiting for open STA association to {ssid:?}"));
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
                (channel, None)
            };

            let _ = ensure_link_local_address(&iface);
            // NAN is only active in STA mode when the associated AP is on channel 6 (2437 MHz)
            // and NOW is not explicitly disabled (`now == 2`).
            let nan_coexist = associated_channel == SHARED_CHANNEL && request.now != Some(2);
            if nan_coexist {
                if let Err(error) = radio.start_monitor_only(SHARED_CHANNEL) {
                    tracing::warn!(
                        error = %format!("{error:#}"),
                        "lmesh_sta_channel6_monitor_unavailable"
                    );
                }
            }
            let mut guard = runtime
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            guard.mode = DesiredTransportMode::Sta {
                ssid,
                channel: associated_channel,
                nan_coexist,
            };
            guard.supplicant = supplicant_opt;
            Ok(TransportSetResponse::default())
        }
        other => Err(format!(
            "unsupported transport.set mode {other}; expected {MODE_OFF} (Off), {MODE_STA} (STA), or {MODE_NAN} (NAN)"
        )),
    }
}

struct WifiScanHandler {
    iface: String,
    runtime: Arc<Mutex<TransportRuntime>>,
}

impl Handler for WifiScanHandler {
    fn call<'a>(&'a self, call: Call<'a>) -> Reply<'a> {
        Box::pin(async move {
            let id = call.record.id?;
            let parsed = decode_raw_wifi_handler_record(call.record);
            let req = match parsed {
                Ok(RawWifiLabRequest::Scan(scan)) => scan,
                _ => RawWifiScanRequest {
                    fresh: false,
                    last_results: false,
                },
            };
            let iface = self.iface.clone();
            let runtime = self.runtime.clone();
            let outcome = tokio::task::spawn_blocking(move || execute_wifi_scan(&iface, &runtime, req))
                .await
                .map_err(|error| error.to_string())
                .and_then(|res| res);
            let mut out = [0u8; 2048];
            let used = match outcome {
                Ok(payload) => mesh_api::envelope::encode_numeric_response(
                    RAW_WIFI_COMPONENT,
                    RAW_WIFI_METHOD_SCAN,
                    id,
                    &payload,
                    &mut out,
                )?,
                Err(message) => mesh_api::envelope::encode_numeric_error(
                    RAW_WIFI_COMPONENT,
                    RAW_WIFI_METHOD_SCAN,
                    id,
                    message.as_bytes(),
                    &mut out,
                )?,
            };
            Some(out[..used].to_vec())
        })
    }
}

fn is_direct_dmesh_ssid(ssid: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(ssid) else {
        return false;
    };
    text.eq_ignore_ascii_case(DEFAULT_SSID)
        || (text.starts_with("DIRECT-") && text.to_ascii_lowercase().ends_with("dmesh"))
}

fn execute_wifi_scan(
    iface: &str,
    runtime: &Arc<Mutex<TransportRuntime>>,
    req: RawWifiScanRequest,
) -> Result<Vec<u8>, String> {
    let index = ifindex(iface).map_err(|error| format!("{error:#}"))?;
    let socket = Nl80211Socket::open().map_err(|error| format!("{error:#}"))?;
    let info = socket
        .interface_info(index)
        .map_err(|error| format!("{error:#}"))?;
    let is_ap = info.iftype == Some(NL80211_IFTYPE_AP);

    let mut did_fresh = false;
    if req.fresh && !req.last_results {
        if socket.trigger_scan(index, is_ap).is_ok() {
            did_fresh = true;
            let deadline = Instant::now() + Duration::from_millis(2_500);
            while Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(250));
                if let Ok(list) = socket.scan_dump(index)
                    && list.iter().any(|bss| bss.seen_ms_ago < 2_000)
                {
                    break;
                }
            }
        }
    }

    let mut bss_list = socket
        .scan_dump(index)
        .map_err(|error| format!("{error:#}"))?;
    if bss_list.is_empty() && !req.last_results && !did_fresh {
        if socket.trigger_scan(index, is_ap).is_ok() {
            did_fresh = true;
            std::thread::sleep(Duration::from_millis(1_500));
            bss_list = socket
                .scan_dump(index)
                .map_err(|error| format!("{error:#}"))?;
        }
    }

    // Sort strongest first and deduplicate by BSSID.
    bss_list.sort_by(|a, b| b.signal_dbm.cmp(&a.signal_dbm));
    let mut seen_bssids = Vec::new();
    let mut unique = Vec::new();
    for bss in bss_list {
        if !seen_bssids.contains(&bss.bssid) {
            seen_bssids.push(bss.bssid);
            unique.push(bss);
        }
    }

    let total_aps = unique.len().min(u16::MAX as usize) as u16;
    let direct_dmesh_aps = unique
        .iter()
        .filter(|bss| is_direct_dmesh_ssid(&bss.ssid))
        .count()
        .min(u16::MAX as usize) as u16;
    let age_ms = unique
        .iter()
        .map(|bss| bss.seen_ms_ago)
        .min()
        .unwrap_or(0);

    let mut entries = [RawWifiScanEntry {
        ssid: [0u8; 32],
        ssid_len: 0,
        bssid: [0u8; 6],
        channel: 0,
        signal_dbm: -100,
    }; RAW_WIFI_SCAN_MAX_RECORDS];
    let count = unique.len().min(RAW_WIFI_SCAN_MAX_RECORDS);
    for (slot, bss) in entries.iter_mut().zip(unique.iter().take(count)) {
        let len = bss.ssid.len().min(32);
        slot.ssid[..len].copy_from_slice(&bss.ssid[..len]);
        slot.ssid_len = len as u8;
        slot.bssid = bss.bssid;
        slot.channel = bss.channel;
        slot.signal_dbm = bss.signal_dbm;
    }

    let mut configured_sta_ssid = [0u8; 32];
    let mut configured_sta_ssid_len = 0u8;
    let mut configured_sta_auth_mode = None;
    let mode_ssid = {
        let guard = runtime
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match &guard.mode {
            DesiredTransportMode::Sta { ssid, .. } => Some(ssid.clone()),
            _ => None,
        }
    };
    if let Some(ssid) = mode_ssid {
        let bytes = ssid.as_bytes();
        let len = bytes.len().min(32);
        configured_sta_ssid[..len].copy_from_slice(&bytes[..len]);
        configured_sta_ssid_len = len as u8;
        configured_sta_auth_mode = Some(3);
    } else if let Ok(Some(creds)) = lmesh_wifi::load_default_infrastructure_credentials()
        && let Some(profile) = creds.find_by_ssid(creds.ssid())
    {
        let bytes = creds.ssid().as_bytes();
        let len = bytes.len().min(32);
        configured_sta_ssid[..len].copy_from_slice(&bytes[..len]);
        configured_sta_ssid_len = len as u8;
        configured_sta_auth_mode = Some(match profile.security() {
            lmesh_wifi::InfrastructureSecurity::Wpa2Psk => 3,
            lmesh_wifi::InfrastructureSecurity::Wpa3Sae => 6,
        });
    }

    let response = RawWifiScanResponse {
        entries: count,
        total_aps,
        direct_dmesh_aps,
        age_ms,
        fresh: did_fresh,
        configured_sta_ssid,
        configured_sta_ssid_len,
        configured_sta_auth_mode,
    };
    let mut scan_cbor = [0u8; 1536];
    let used = encode_raw_wifi_scan_response(&entries[..count], response, &mut scan_cbor)
        .ok_or_else(|| "encode wifi.scan response".to_owned())?;
    Ok(scan_cbor[..used].to_vec())
}

/// `nan.wakeup {to}`: queue a targeted STA activation as an active Subscribe; with `pair`,
/// `nan.pair_wakeup {to}`, the invitation an unpaired device accepts to open its pairing window.
struct WakeupHandler {
    radio: Radio,
    pair: bool,
}

impl Handler for WakeupHandler {
    fn call<'a>(&'a self, call: Call<'a>) -> Reply<'a> {
        Box::pin(async move {
            let id = call.record.id?;
            let component = dmesh_discovery::announce::ANNOUNCE_COMPONENT;
            let method = if self.pair {
                dmesh_discovery::announce::ANNOUNCE_NAN_PAIR_WAKEUP
            } else {
                dmesh_discovery::announce::ANNOUNCE_NAN_WAKEUP
            };
            // A wake is a NAN service-discovery request addressed to one device: sent
            // on NOW and NAN, now and in the next discovery windows. Linux and the
            // firmware sync on NOW when no Android device runs NAN.
            let outcome = wake_request(call.record, self.pair).map(|(target, record)| {
                self.radio.request(record, Some(target), true);
            });
            let mut out = [0u8; 160];
            let used = match outcome {
                Ok(()) => mesh_api::envelope::encode_numeric_response(component, method, id, &[0xf5], &mut out)?,
                Err(message) => mesh_api::envelope::encode_numeric_error(
                    component,
                    method,
                    id,
                    message.as_bytes(),
                    &mut out,
                )?,
            };
            Some(out[..used].to_vec())
        })
    }
}

fn wake_request(
    record: mesh_api::envelope::Record<'_>,
    pair: bool,
) -> Result<([u8; 6], Vec<u8>), String> {
    let name = if pair { "nan.pair_wakeup" } else { "nan.wakeup" };
    let target = if pair {
        dmesh_discovery::announce::decode_nan_pair_wakeup_request(record)
    } else {
        dmesh_discovery::announce::decode_nan_wakeup_request(record)
    }
    .ok_or_else(|| format!("{name} needs `to`, a MAC address"))?;
    if target == [0; 6] || target[0] & 1 != 0 {
        return Err(format!("{name} to must be a unicast MAC"));
    }
    if pair {
        let mut record = [0u8; 96];
        let used = dmesh_discovery::announce::encode_nan_pair_wakeup_request(target, 0, &mut record)
            .ok_or("encode pairing invitation")?;
        return Ok((target, record[..used].to_vec()));
    }
    let request = dmesh_discovery::control::Request::TransportSet {
        kind: dmesh_discovery::control::TransportKind::Sta,
        config: dmesh_discovery::control::TransportConfig {
            wake_target: Some(target),
            ..dmesh_discovery::control::TransportConfig::default()
        },
    };
    let mut record = [0u8; 96];
    let used = dmesh_discovery::control::encode_request(request, None, &mut record)
        .ok_or("encode targeted STA activation")?;
    Ok((target, record[..used].to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_observer_ignores_everything_until_the_engine_exists() {
        let observer = EngineObserver::default();
        let seen = observer.nan([2, 0, 0, 0, 0, 1], None, &[b"not an announce".as_slice()]);
        assert!(seen.summary.is_none() && !seen.invalid_identity);
    }

    #[test]
    fn a_wake_request_for_a_unicast_mac_encodes_the_sta_activation() {
        let mut wire = [0u8; 96];
        let target = [0x02, 1, 2, 3, 4, 5];
        let used = dmesh_discovery::announce::encode_nan_wakeup_request(target, 7, &mut wire).unwrap();
        let record = mesh_api::envelope::decode(&wire[..used]).unwrap();
        let (to, bytes) = wake_request(record, false).unwrap();
        assert_eq!(to, target);
        assert!(!bytes.is_empty());
    }

    #[test]
    fn a_pair_wakeup_carries_the_pairing_invitation_not_the_sta_activation() {
        let mut wire = [0u8; 96];
        let target = [0x02, 1, 2, 3, 4, 5];
        let used =
            dmesh_discovery::announce::encode_nan_pair_wakeup_request(target, 7, &mut wire).unwrap();
        let record = mesh_api::envelope::decode(&wire[..used]).unwrap();
        let (to, bytes) = wake_request(record, true).unwrap();
        assert_eq!(to, target);
        let sent = mesh_api::envelope::decode(&bytes).unwrap();
        assert_eq!(dmesh_discovery::announce::decode_nan_pair_wakeup_request(sent), Some(target));
        // A plain wake request is not accepted as an invitation.
        let used = dmesh_discovery::announce::encode_nan_wakeup_request(target, 7, &mut wire).unwrap();
        let record = mesh_api::envelope::decode(&wire[..used]).unwrap();
        assert!(wake_request(record, true).is_err());
    }

    #[test]
    fn a_wake_request_for_a_multicast_mac_is_refused() {
        let mut wire = [0u8; 96];
        let used =
            dmesh_discovery::announce::encode_nan_wakeup_request([0x01, 0, 0, 0, 0, 1], 7, &mut wire).unwrap();
        let record = mesh_api::envelope::decode(&wire[..used]).unwrap();
        assert!(wake_request(record, false).unwrap_err().contains("unicast"));
    }

    #[test]
    fn a_mac_is_six_colon_separated_hex_bytes() {
        assert_eq!(parse_mac("02:a1:b2:c3:d4:e5"), Some([0x02, 0xa1, 0xb2, 0xc3, 0xd4, 0xe5]));
        assert_eq!(parse_mac("udp://[fe80::1]"), None);
        assert_eq!(parse_mac("02:a1:b2:c3:d4"), None);
        assert_eq!(parse_mac("02:a1:b2:c3:d4:e5:f6"), None);
    }

    fn observer_with_engine(seed: &[u8]) -> (EngineObserver, Arc<Engine>) {
        let engine = Arc::new(Engine::new(
            Arc::new(dmesh_discovery::UnsignedIdentity::from_seed(seed)),
            Arc::new(dmesh_discovery::NoFacts),
        ));
        let observer = EngineObserver::default();
        observer.engine.set(engine.clone()).ok();
        (observer, engine)
    }

    #[test]
    fn a_now_discovery_request_is_answered_with_a_reply_that_resolves_its_waiter() {
        // We (B) hear a request from A on NOW and answer; A, waiting on that id,
        // hears the reply on NOW and is resolved: the same exchange as UDP.
        let (b, _) = observer_with_engine(b"b");
        let (a, a_engine) = observer_with_engine(b"a");
        let id = 99;
        let waiting = a_engine.expect_response(id);
        let mut request = [0u8; 96];
        let used = dmesh_discovery::announce::encode_discovery_request(id, &mut request).unwrap();
        let a_mac = [0x02, 0, 0, 0, 0, 0xa];
        let b_mac = [0x02, 0, 0, 0, 0, 0xb];
        let reply = b
            .now(a_mac, None, NowKind::Discovery, &request[..used])
            .expect("a request must be answered");
        assert!(a.now(b_mac, None, NowKind::Discovery, &reply).is_none());
        let device = waiting.recv_timeout(Duration::from_millis(200)).unwrap();
        assert!(device.observations.contains_key("now"));
    }

    #[test]
    fn nan_service_info_and_now_discovery_land_in_one_inventory_with_their_own_bearers() {
        let (observer, engine) = observer_with_engine(b"me");
        let (other, other_engine) = observer_with_engine(b"other");
        let announce = other_engine.local_announce().unwrap();
        let mut wire = [0u8; 256];
        let used = dmesh_discovery::announce::encode(announce, &mut wire).unwrap();
        let peer = [0x02, 1, 2, 3, 4, 5];
        let seen = observer.nan(peer, None, &[&wire[..used]]);
        assert!(seen.summary.is_some());
        assert!(observer.now(peer, None, NowKind::Discovery, &wire[..used]).is_none());
        let devices = engine.devices();
        assert_eq!(devices.len(), 1);
        assert!(devices[0].observations.contains_key("nan"));
        assert!(devices[0].observations.contains_key("now"));
        let _ = other;
    }

    #[test]
    fn empty_nan_and_now_frames_record_provisional_unpaired_devices() {
        let (observer, engine) = observer_with_engine(b"me");
        let peer_nan = [0x20, 0x6e, 0xf1, 0x13, 0xa4, 0x00];
        let peer_now = [0x98, 0x88, 0xe0, 0x01, 0x29, 0x14];
        observer.nan(peer_nan, None, &[]);
        observer.now(peer_now, None, NowKind::Sync, &[]);
        let view = engine.discovered_view();
        assert_eq!(view.len(), 2);
        assert!(view.contains_key("20:6e:f1:13:a4:00"));
        assert!(view.contains_key("98:88:e0:01:29:14"));
    }

    #[test]
    fn outbound_now_payload_is_wrapped_in_now_sync_envelope() {
        let nan = Arc::new(Mutex::new(dmesh_rawnan::NanState::new(
            dmesh_rawnan::NAN_CLUSTER_STALE_AFTER_US,
        )));
        let local = [0x74, 0x19, 0xf8, 0x17, 0xde, 0x65];
        let mut request = [0u8; 96];
        let used = dmesh_discovery::announce::encode_discovery_request(42, &mut request).unwrap();
        let wrapped =
            dmesh_rawnan::linux::wrap_now_sync_payload(local, &nan, &request[..used]);
        let parsed = dmesh_rawnan::parse_now_sync_body(&wrapped).expect("valid NOW_SYNC body");
        assert_eq!(parsed.service_info, &request[..used]);
    }
}
