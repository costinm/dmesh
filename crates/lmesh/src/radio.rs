//! The Wi-Fi radio of this node: `rawnan`'s raw bearer (open AP on the shared channel +
//! monitor, carrying NOW and NAN), started from the configured WLAN and wired to the
//! discovery engine and the registry. No `lmesh-wifi` is involved.
//!
//! Linux implements the common API only: `transport.set` (NAN mode),
//! `discovery.active`, `nan.wakeup` and `telemetry.nan_status`. Discovery is the same
//! request and the same announce on every medium (UDP multicast, NAN, NOW); the radio
//! answers a request that arrives on NOW, like it does on UDP.

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use dmesh_discovery::{Carrier, Engine, Received};
use dmesh_rawnan::linux::{
    NanAnnounce, NanPacketKind, NowKind, Observer, Radio, RadioConfig, SHARED_CHANNEL,
};
use dmesh_server::discovery::DiscoveryPacketKind;
use dmesh_server::platform_api::{
    DiscoveryActiveRequest, DiscoveryActiveResponse, TelemetryNanRequest, TelemetryNanResponse,
    TelemetryNanStatusRequest, TelemetryNanStatusResponse, TelemetryNowRequest,
    TelemetryNowResponse, TelemetryUdp6Request, TelemetryUdp6Response, TelemetryWifiLinkRequest,
    TelemetryWifiLinkResponse, TransportSetRequest, TransportSetResponse,
};
use dmesh_server::registry::{Call, CallContext, Handler, Registry, Reply, methods};
use dmesh_server::registry_bridge::TypedHandler;
use lmesh_wifi::mesh_core::LocalDiscovery;
use serde_json::json;

/// How often the interface state is re-checked and the NAN publish refreshed.
const MAINTAIN_INTERVAL: Duration = Duration::from_secs(30);
/// `transport.set` mode value for NAN.
const MODE_NAN: u8 = 6;

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
    P: quic_lite::bearer::PacketPool + Sync + 'static,
    P::Buffer: Send,
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
    if configured {
        maintain(radio.clone(), discovery.clone());
    }
    persist_nodes(discovery.clone());
    register_methods(registry, radio, discovery.clone(), interface().0);
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
fn maintain(radio: Radio, discovery: Arc<LocalDiscovery>) {
    let started = std::time::Instant::now();
    let interval = Duration::from_millis(dmesh_rawnan::NAN_ACTIVE_PUBLISH_INTERVAL_MS);
    tokio::spawn(async move {
        let mut last_publish: Option<std::time::Instant> = None;
        loop {
            let worker = radio.clone();
            let started_ok = match tokio::task::spawn_blocking(move || worker.start()).await {
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

fn register_methods(registry: &Registry, radio: Radio, discovery: Arc<LocalDiscovery>, iface: String) {
    register_telemetry(registry, &radio, iface);
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

    // `transport.set`: Linux has one physical transport, NAN with the open AP and
    // monitor on the shared channel. Anything else is not available here.
    let transport_radio = radio.clone();
    assert!(
        registry.register(
            methods::TRANSPORT_SET,
            TypedHandler::new(move |request: TransportSetRequest, _: CallContext| {
                let radio = transport_radio.clone();
                async move {
                    if !matches!(request.mode, None | Some(MODE_NAN)) {
                        return Err(format!(
                            "Linux runs transport mode {MODE_NAN} (NAN with the open AP) only, not {:?}",
                            request.mode
                        ));
                    }
                    if request.channel.is_some_and(|channel| channel != SHARED_CHANNEL) {
                        return Err(format!(
                            "the shared channel is {SHARED_CHANNEL}, not {:?}",
                            request.channel
                        ));
                    }
                    tokio::task::spawn_blocking(move || radio.start())
                        .await
                        .map_err(|error| error.to_string())?
                        .map_err(|error| format!("{error:#}"))?;
                    Ok(TransportSetResponse::default())
                }
            }),
        ),
        "transport.set registered twice"
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
        let used = dmesh_server::announce::encode_discovery_request(id, &mut record)
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
        match dmesh_server::announce::encode_discovery_request(id, &mut record) {
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
            let component = dmesh_server::announce::ANNOUNCE_COMPONENT;
            let method = if self.pair {
                dmesh_server::announce::ANNOUNCE_NAN_PAIR_WAKEUP
            } else {
                dmesh_server::announce::ANNOUNCE_NAN_WAKEUP
            };
            // A wake is a NAN service-discovery request addressed to one device: sent
            // on NOW and NAN, now and in the next discovery windows. Linux and the
            // firmware sync on NOW when no Android device runs NAN.
            let outcome = wake_request(call.record, self.pair).map(|(target, record)| {
                self.radio.request(record, Some(target), true);
            });
            let mut out = [0u8; 160];
            let used = match outcome {
                Ok(()) => dmesh_server::tagged::encode_numeric_response(component, method, id, &[0xf5], &mut out)?,
                Err(message) => dmesh_server::tagged::encode_numeric_error(
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
    record: dmesh_server::tagged::Record<'_>,
    pair: bool,
) -> Result<([u8; 6], Vec<u8>), String> {
    let name = if pair { "nan.pair_wakeup" } else { "nan.wakeup" };
    let target = if pair {
        dmesh_server::announce::decode_nan_pair_wakeup_request(record)
    } else {
        dmesh_server::announce::decode_nan_wakeup_request(record)
    }
    .ok_or_else(|| format!("{name} needs `to`, a MAC address"))?;
    if target == [0; 6] || target[0] & 1 != 0 {
        return Err(format!("{name} to must be a unicast MAC"));
    }
    if pair {
        let mut record = [0u8; 96];
        let used = dmesh_server::announce::encode_nan_pair_wakeup_request(target, 0, &mut record)
            .ok_or("encode pairing invitation")?;
        return Ok((target, record[..used].to_vec()));
    }
    let request = dmesh_server::control::Request::TransportSet {
        kind: dmesh_server::control::TransportKind::Sta,
        config: dmesh_server::control::TransportConfig {
            wake_target: Some(target),
            ..dmesh_server::control::TransportConfig::default()
        },
    };
    let mut record = [0u8; 96];
    let used = dmesh_server::control::encode_request(request, None, &mut record)
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
        let used = dmesh_server::announce::encode_nan_wakeup_request(target, 7, &mut wire).unwrap();
        let record = dmesh_server::tagged::decode(&wire[..used]).unwrap();
        let (to, bytes) = wake_request(record, false).unwrap();
        assert_eq!(to, target);
        assert!(!bytes.is_empty());
    }

    #[test]
    fn a_pair_wakeup_carries_the_pairing_invitation_not_the_sta_activation() {
        let mut wire = [0u8; 96];
        let target = [0x02, 1, 2, 3, 4, 5];
        let used =
            dmesh_server::announce::encode_nan_pair_wakeup_request(target, 7, &mut wire).unwrap();
        let record = dmesh_server::tagged::decode(&wire[..used]).unwrap();
        let (to, bytes) = wake_request(record, true).unwrap();
        assert_eq!(to, target);
        let sent = dmesh_server::tagged::decode(&bytes).unwrap();
        assert_eq!(dmesh_server::announce::decode_nan_pair_wakeup_request(sent), Some(target));
        // A plain wake request is not accepted as an invitation.
        let used = dmesh_server::announce::encode_nan_wakeup_request(target, 7, &mut wire).unwrap();
        let record = dmesh_server::tagged::decode(&wire[..used]).unwrap();
        assert!(wake_request(record, true).is_err());
    }

    #[test]
    fn a_wake_request_for_a_multicast_mac_is_refused() {
        let mut wire = [0u8; 96];
        let used =
            dmesh_server::announce::encode_nan_wakeup_request([0x01, 0, 0, 0, 0, 1], 7, &mut wire).unwrap();
        let record = dmesh_server::tagged::decode(&wire[..used]).unwrap();
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
        let used = dmesh_server::announce::encode_discovery_request(id, &mut request).unwrap();
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
        let used = dmesh_server::announce::encode(announce, &mut wire).unwrap();
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
}
