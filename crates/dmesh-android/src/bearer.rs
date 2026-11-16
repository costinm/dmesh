use mesh_api::envelope as tagged;
use quic_base::{
    AssociationEgress, DEFAULT_HEADROOM, PacketPool, PoolPacket, StreamPriority, TxPacketMeta,
    XipLazyPacket, XipLazyPool,
};
use quic_link::{AssocConfig, ConnectionId, LinkId, LinkProfile, LinkTxOutcome, QuicLinkAssoc};
use quic_mux::{MuxStream, TokioMux, TokioMuxConfig};
use serde_json::{Value, json};
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::{
    Arc, Mutex, OnceLock,
    atomic::{AtomicU64, Ordering},
};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

const PACKET: usize = 1100;
const USB_MTU: usize = 1024;
const BLE_MTU: usize = 244;
const UDP_MTU: usize = 1200;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
const CHANNEL_CAPACITY: usize = 128;

pub trait BearerEgress: Send + Sync {
    fn send_packet(&self, bearer: &str, packet: &[u8]);
}

#[derive(Default)]
struct ConnectionStatus {
    open: bool,
    complete: bool,
    error: Option<String>,
    rx_packets: u64,
    tx_packets: u64,
    last_response: Vec<u8>,
}

impl ConnectionStatus {
    fn json(&self) -> Value {
        json!({
            "open": self.open,
            "complete": self.complete,
            "error": self.error,
            "rx_packets": self.rx_packets,
            "tx_packets": self.tx_packets,
            "retransmits": 0,
            "last_response_hex": hex(&self.last_response),
        })
    }
}

#[derive(Default)]
struct BearerMetrics {
    enabled: bool,
    tx_submitted: u64,
    tx_accepted: u64,
    tx_failed: u64,
    tx_busy: u64,
    rx_packets: u64,
    rx_dropped: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct PeerKey {
    bearer: String,
    peer: String,
}

struct PeerStats {
    id: u64,
    bearer: String,
    peer: String,
    received_packets: AtomicU64,
    sent_packets: AtomicU64,
    retransmitted_packets: AtomicU64,
    loss_events: AtomicU64,
    submission_failures: AtomicU64,
}

impl PeerStats {
    fn new(id: u64, bearer: &str, peer: &str) -> Arc<Self> {
        Arc::new(Self {
            id,
            bearer: bearer.to_owned(),
            peer: peer.to_owned(),
            received_packets: AtomicU64::new(0),
            sent_packets: AtomicU64::new(0),
            retransmitted_packets: AtomicU64::new(0),
            loss_events: AtomicU64::new(0),
            submission_failures: AtomicU64::new(0),
        })
    }

    fn to_quic_association(&self) -> crate::android_api::QuicAssociation {
        crate::android_api::QuicAssociation {
            association: Some(self.id),
            bearer: Some(self.bearer.clone()),
            peer: Some(self.peer.clone()),
            received_packets: Some(self.received_packets.load(Ordering::Relaxed)),
            sent_packets: Some(self.sent_packets.load(Ordering::Relaxed)),
            retransmitted_packets: Some(self.retransmitted_packets.load(Ordering::Relaxed)),
            loss_events: Some(self.loss_events.load(Ordering::Relaxed)),
            submission_failures: Some(self.submission_failures.load(Ordering::Relaxed)),
            bytes_in_flight: Some(0),
            peer_max_data: Some(0),
            peer_sent_data: Some(0),
            largest_acked_by_peer: None,
            ..Default::default()
        }
    }
}

struct PeerSession {
    mux: TokioMux,
    inbound_tx: mpsc::Sender<Vec<u8>>,
    driver_task: JoinHandle<()>,
    accept_task: Option<JoinHandle<()>>,
    stats: Arc<PeerStats>,
}

impl PeerSession {
    fn is_alive(&self) -> bool {
        !self.inbound_tx.is_closed() && !self.driver_task.is_finished()
    }

    fn shutdown(self) {
        self.mux.close();
        if let Some(accept_task) = self.accept_task {
            accept_task.abort();
        }
        self.driver_task.abort();
    }
}

pub struct BearerRuntime {
    udp_socket: Option<Arc<tokio::net::UdpSocket>>,
    udp_local_addr: Option<SocketAddr>,
    udp_rx_task: Option<JoinHandle<()>>,
    egress: Arc<dyn BearerEgress>,
    bearer_metrics: Arc<Mutex<HashMap<String, BearerMetrics>>>,
    peers: Arc<Mutex<HashMap<PeerKey, PeerSession>>>,
    next_assoc_id: AtomicU64,
    state: Arc<Mutex<HashMap<String, ConnectionStatus>>>,
    usb_outbound: Arc<Mutex<VecDeque<Vec<u8>>>>,
    ble_outbound: Arc<Mutex<VecDeque<Vec<u8>>>>,
    started: Instant,
    runtime: tokio::runtime::Handle,
}

impl Drop for BearerRuntime {
    fn drop(&mut self) {
        if let Some(task) = self.udp_rx_task.take() {
            task.abort();
        }
        if let Ok(mut peers) = self.peers.lock() {
            for (_, session) in peers.drain() {
                session.shutdown();
            }
        }
    }
}

impl BearerRuntime {
    /// Address of the socket actually attached to the UDP bearer.
    pub fn udp_local_addr(&self) -> Option<SocketAddr> {
        self.udp_local_addr
    }

    pub fn spawn(runtime: tokio::runtime::Handle, egress: Arc<dyn BearerEgress>) -> Arc<Self> {
        Self::spawn_with_udp(runtime, egress, None)
    }

    pub fn spawn_with_udp(
        runtime: tokio::runtime::Handle,
        egress: Arc<dyn BearerEgress>,
        udp_socket: Option<std::net::UdpSocket>,
    ) -> Arc<Self> {
        let mut metrics = HashMap::new();
        for name in ["usb", "ble"] {
            metrics.insert(
                name.to_owned(),
                BearerMetrics {
                    enabled: true,
                    ..Default::default()
                },
            );
        }

        let (udp_tokio, udp_local_addr) = match udp_socket {
            Some(socket) => {
                let _guard = runtime.enter();
                let _ = socket.set_nonblocking(true);
                let local_addr = socket.local_addr().ok();
                match tokio::net::UdpSocket::from_std(socket) {
                    Ok(tokio_sock) => {
                        metrics.insert(
                            "udp".to_owned(),
                            BearerMetrics {
                                enabled: true,
                                ..Default::default()
                            },
                        );
                        (Some(Arc::new(tokio_sock)), local_addr)
                    }
                    Err(error) => {
                        log::error!("failed to attach Android UDP bearer: {error}");
                        (None, None)
                    }
                }
            }
            None => (None, None),
        };

        let bearer_metrics = Arc::new(Mutex::new(metrics));
        let peers = Arc::new(Mutex::new(HashMap::new()));
        let state = Arc::new(Mutex::new(HashMap::new()));
        let usb_outbound = Arc::new(Mutex::new(VecDeque::new()));
        let ble_outbound = Arc::new(Mutex::new(VecDeque::new()));

        let mut this = Self {
            udp_socket: udp_tokio.clone(),
            udp_local_addr,
            udp_rx_task: None,
            egress,
            bearer_metrics,
            peers,
            next_assoc_id: AtomicU64::new(1),
            state,
            usb_outbound,
            ble_outbound,
            started: Instant::now(),
            runtime: runtime.clone(),
        };

        if let Some(sock) = udp_tokio {
            let weak_peers = this.peers.clone();
            let weak_metrics = this.bearer_metrics.clone();
            let weak_egress = this.egress.clone();
            let weak_state = this.state.clone();
            let weak_usb_out = this.usb_outbound.clone();
            let weak_ble_out = this.ble_outbound.clone();
            let rt_handle = runtime.clone();
            let sock_for_rx = sock.clone();
            let rx_task = runtime.spawn(async move {
                let mut buf = vec![0u8; 2048];
                loop {
                    let (len, from) = match sock_for_rx.recv_from(&mut buf).await {
                        Ok(pair) => pair,
                        Err(_) => break,
                    };
                    if len == 0 {
                        continue;
                    }
                    let data = buf[..len].to_vec();
                    if let Ok(mut m) = weak_metrics.lock() {
                        m.entry("udp".to_owned()).or_default().rx_packets += 1;
                    }
                    let peer_str = from.to_string();
                    let key = PeerKey {
                        bearer: "udp".to_owned(),
                        peer: peer_str.clone(),
                    };
                    let inbound_tx = {
                        let mut map = weak_peers.lock().unwrap_or_else(|e| e.into_inner());
                        if let Some(existing) = map.get(&key) {
                            if existing.is_alive() {
                                Some((existing.inbound_tx.clone(), existing.stats.clone()))
                            } else {
                                if let Some(dead) = map.remove(&key) {
                                    dead.shutdown();
                                }
                                None
                            }
                        } else {
                            None
                        }
                    };
                    let (tx, stats) = match inbound_tx {
                        Some(pair) => pair,
                        None => {
                            let session = spawn_peer_session(
                                &rt_handle,
                                false,
                                "udp",
                                &peer_str,
                                Some((sock.clone(), from)),
                                weak_egress.clone(),
                                weak_metrics.clone(),
                                weak_state.clone(),
                                weak_usb_out.clone(),
                                weak_ble_out.clone(),
                                1000,
                            );
                            let tx = session.inbound_tx.clone();
                            let stats = session.stats.clone();
                            let mut map = weak_peers.lock().unwrap_or_else(|e| e.into_inner());
                            map.insert(key, session);
                            (tx, stats)
                        }
                    };
                    stats.received_packets.fetch_add(1, Ordering::Relaxed);
                    if tx.try_send(data).is_err() {
                        if let Ok(mut m) = weak_metrics.lock() {
                            m.entry("udp".to_owned()).or_default().rx_dropped += 1;
                        }
                    }
                }
            });
            this.udp_rx_task = Some(rx_task);
        }

        Arc::new(this)
    }

    fn get_or_create_client_mux(
        &self,
        bearer: &str,
        peer: &str,
        udp_target: Option<SocketAddr>,
    ) -> Result<(TokioMux, PeerKey), String> {
        let key = PeerKey {
            bearer: bearer.to_owned(),
            peer: peer.to_owned(),
        };
        let mut map = self.peers.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(existing) = map.remove(&key) {
            existing.shutdown();
        }
        let udp_pair = match udp_target {
            Some(addr) => {
                let sock = self
                    .udp_socket
                    .as_ref()
                    .ok_or_else(|| "Android has no UDP bearer".to_owned())?
                    .clone();
                Some((sock, addr))
            }
            None => None,
        };
        let assoc_id = self.next_assoc_id.fetch_add(1, Ordering::Relaxed);
        let session = spawn_peer_session(
            &self.runtime,
            true,
            bearer,
            peer,
            udp_pair,
            self.egress.clone(),
            self.bearer_metrics.clone(),
            self.state.clone(),
            self.usb_outbound.clone(),
            self.ble_outbound.clone(),
            assoc_id,
        );
        let mux = session.mux.clone();
        map.insert(key.clone(), session);
        Ok((mux, key))
    }

    fn finish_client_session(&self, key: &PeerKey) {
        if let Ok(mut map) = self.peers.lock() {
            if let Some(session) = map.remove(key) {
                session.shutdown();
            }
        }
    }

    pub async fn request(&self, bearer: &str, record: &[u8]) -> Result<Vec<u8>, String> {
        let has_bearer = self
            .bearer_metrics
            .lock()
            .ok()
            .is_some_and(|m| m.contains_key(bearer));
        if !has_bearer {
            return Err(format!("unknown Android bearer {bearer}"));
        }
        self.set_open(bearer);
        let (mux, key) = self.get_or_create_client_mux(bearer, "1", None)?;
        let operation = async {
            let mut stream = mux
                .open_bidi()
                .await
                .map_err(|error| format!("open request stream: {error}"))?;
            let response = quic_tools::exchange(&mut stream, &[record])
                .await
                .map_err(|error| format!("request exchange: {error}"))?;
            Ok(response)
        };
        let result: Result<Vec<u8>, String> = match tokio::time::timeout(REQUEST_TIMEOUT, operation)
            .await
        {
            Ok(inner) => inner,
            Err(_) => Err("Android bearer request timed out".to_owned()),
        };
        self.finish_client_session(&key);
        match result {
            Ok(response) => {
                if let Ok(mut state) = self.state.lock() {
                    let status = state.entry(bearer.to_owned()).or_default();
                    status.open = false;
                    status.complete = true;
                    status.last_response = response.clone();
                }
                Ok(response)
            }
            Err(error) => {
                self.set_error(bearer, error.clone());
                Err(error)
            }
        }
    }

    /// Run a probe with this node as the QUIC client: call the probed node's
    /// registered `probe.handler` and validate the payload that follows its
    /// response header. `destination` is `udp://HOST:PORT`, `usb://` or `ble://`.
    pub async fn probe(
        &self,
        destination: &quic_tools::ProbeDestination,
        request: quic_tools::ProbeServiceRequest,
        timeout: Duration,
    ) -> Result<quic_tools::StreamProbeResult, String> {
        let (bearer, peer_str, udp_target) = match destination.scheme() {
            "udp" => {
                let address = dmesh_discovery::endpoint::parse_udp_endpoint(
                    destination.target(),
                    &dmesh_discovery::endpoint::EndpointDefaults {
                        port: dmesh_discovery::DEFAULT_EVENT_PORT,
                        scope: None,
                    },
                )
                .map_err(|error| error.to_string())?
                .ok_or("invalid udp probe destination")?;
                if self.udp_socket.is_none() {
                    return Err("Android has no UDP bearer".to_owned());
                }
                ("udp", address.to_string(), Some(address))
            }
            scheme @ ("usb" | "ble") => {
                let has_bearer = self
                    .bearer_metrics
                    .lock()
                    .ok()
                    .is_some_and(|m| m.contains_key(scheme));
                if !has_bearer {
                    return Err(format!("unknown Android bearer {scheme}"));
                }
                (scheme, "1".to_owned(), None)
            }
            other => return Err(format!("Android cannot probe over {other}://")),
        };

        let (mux, key) = self.get_or_create_client_mux(bearer, &peer_str, udp_target)?;
        let operation = async {
            let mut header = [0u8; quic_tools::PROBE_REQUEST_MAX];
            let mut outbound = request;
            outbound.peer = None;
            let used = quic_tools::encode_probe_handler_request(outbound, 1, &mut header)
                .ok_or("probe request does not fit a probe.handler header")?;
            let result = quic_tools::probe_mux(&mux, &header[..used], outbound)
                .await
                .map_err(|error| format!("probe exchange: {error}"))?;
            Ok(result)
        };
        let res = match tokio::time::timeout(timeout, operation).await {
            Ok(inner) => inner,
            Err(_) => Err("Android probe timed out".to_owned()),
        };
        self.finish_client_session(&key);
        res
    }

    pub async fn telemetry(&self) -> Option<crate::android_api::TelemetryQuicResponse> {
        let peers = self.peers.lock().ok()?;
        let mut resp = crate::android_api::TelemetryQuicResponse::default();
        for session in peers.values() {
            if session.is_alive() {
                resp.live_associations += 1;
            }
            let rx = session.stats.received_packets.load(Ordering::Relaxed);
            let tx = session.stats.sent_packets.load(Ordering::Relaxed);
            resp.received_packets += rx;
            resp.sent_packets += tx;
            resp.received_stream_packets += rx;
            resp.sent_stream_packets += tx;
            resp.retransmitted_packets +=
                session.stats.retransmitted_packets.load(Ordering::Relaxed);
            resp.loss_events += session.stats.loss_events.load(Ordering::Relaxed);
            resp.submission_failures += session.stats.submission_failures.load(Ordering::Relaxed);
        }
        if let Ok(metrics) = self.bearer_metrics.lock() {
            for m in metrics.values() {
                resp.received_packets = resp.received_packets.max(m.rx_packets);
                resp.sent_packets = resp.sent_packets.max(m.tx_accepted);
                resp.submission_failures = resp.submission_failures.max(m.tx_failed);
            }
        }
        Some(resp)
    }

    /// Per-association and per-bearer rows of the node.
    pub async fn rows(
        &self,
    ) -> Option<(
        Vec<crate::android_api::QuicAssociation>,
        Vec<crate::android_api::BearerCounters>,
    )> {
        let associations = {
            let peers = self.peers.lock().ok()?;
            peers
                .values()
                .filter(|s| s.is_alive())
                .map(|s| s.stats.to_quic_association())
                .collect::<Vec<_>>()
        };
        let bearers = {
            let metrics = self.bearer_metrics.lock().ok()?;
            let mut rows = Vec::with_capacity(metrics.len());
            for name in ["usb", "ble", "udp"] {
                if let Some(m) = metrics.get(name) {
                    rows.push(crate::android_api::BearerCounters {
                        name: Some(name.to_owned()),
                        state: Some(u8::from(m.enabled)),
                        tx_submitted: Some(m.tx_submitted),
                        tx_accepted: Some(m.tx_accepted),
                        tx_failed: Some(m.tx_failed),
                        tx_busy: Some(m.tx_busy),
                        rx_packets: Some(m.rx_packets),
                        rx_dropped: Some(m.rx_dropped),
                        queue_depth: Some(0),
                        ..Default::default()
                    });
                }
            }
            rows
        };
        Some((associations, bearers))
    }

    pub fn inject_usb(&self, data: &[u8]) -> bool {
        self.packet("usb", data)
    }

    pub fn inject_ble(&self, data: &[u8]) -> bool {
        self.packet("ble", data)
    }

    pub fn take_usb(&self) -> Option<Vec<u8>> {
        self.usb_outbound.lock().ok()?.pop_front()
    }

    pub fn take_ble(&self) -> Option<Vec<u8>> {
        self.ble_outbound.lock().ok()?.pop_front()
    }

    fn open(&self, bearer: &str, args: &str) -> bool {
        let has_bearer = self
            .bearer_metrics
            .lock()
            .ok()
            .is_some_and(|m| m.contains_key(bearer));
        if !has_bearer {
            return false;
        }
        let (component, method, id) = parse_request_args(args);
        let mut wire = [0_u8; 64];
        let Some(used) = tagged::encode_numeric_empty_request(component, method, id, &mut wire)
        else {
            self.set_error(bearer, "unable to encode bearer request".to_owned());
            return false;
        };
        let runtime = current();
        let bearer = bearer.to_owned();
        let record = wire[..used].to_vec();
        self.runtime.spawn(async move {
            if let Some(runtime) = runtime {
                if let Err(error) = runtime.request(&bearer, &record).await {
                    log::warn!("Android bearer request failed: {error}");
                }
            }
        });
        true
    }

    fn packet(&self, bearer: &str, data: &[u8]) -> bool {
        if data.is_empty() || data.len() > PACKET {
            return false;
        }
        let has_bearer = self
            .bearer_metrics
            .lock()
            .ok()
            .is_some_and(|m| m.contains_key(bearer));
        if !has_bearer {
            return false;
        }
        if let Ok(mut m) = self.bearer_metrics.lock() {
            m.entry(bearer.to_owned()).or_default().rx_packets += 1;
        }
        if let Ok(mut state) = self.state.lock() {
            state.entry(bearer.to_owned()).or_default().rx_packets += 1;
        }

        let key = PeerKey {
            bearer: bearer.to_owned(),
            peer: "1".to_owned(),
        };
        let existing = {
            let mut map = self.peers.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(session) = map.get(&key) {
                if session.is_alive() {
                    Some((session.inbound_tx.clone(), session.stats.clone()))
                } else {
                    if let Some(dead) = map.remove(&key) {
                        dead.shutdown();
                    }
                    None
                }
            } else {
                None
            }
        };
        let (tx, stats) = match existing {
            Some(pair) => pair,
            None => {
                let assoc_id = self.next_assoc_id.fetch_add(1, Ordering::Relaxed);
                let session = spawn_peer_session(
                    &self.runtime,
                    false,
                    bearer,
                    "1",
                    None,
                    self.egress.clone(),
                    self.bearer_metrics.clone(),
                    self.state.clone(),
                    self.usb_outbound.clone(),
                    self.ble_outbound.clone(),
                    assoc_id,
                );
                let tx = session.inbound_tx.clone();
                let stats = session.stats.clone();
                let mut map = self.peers.lock().unwrap_or_else(|e| e.into_inner());
                map.insert(key, session);
                (tx, stats)
            }
        };
        stats.received_packets.fetch_add(1, Ordering::Relaxed);
        if tx.try_send(data.to_vec()).is_err() {
            if let Ok(mut m) = self.bearer_metrics.lock() {
                m.entry(bearer.to_owned()).or_default().rx_dropped += 1;
            }
            return false;
        }
        true
    }

    fn close(&self, bearer: &str) {
        if let Ok(mut state) = self.state.lock() {
            state.remove(bearer);
        }
        if let Ok(mut map) = self.peers.lock() {
            let keys: Vec<PeerKey> = map
                .keys()
                .filter(|k| k.bearer == bearer)
                .cloned()
                .collect();
            for key in keys {
                if let Some(session) = map.remove(&key) {
                    session.shutdown();
                }
            }
        }
    }

    fn connection_status(&self, bearer: &str) -> Option<Value> {
        self.state
            .lock()
            .ok()?
            .get(bearer)
            .map(ConnectionStatus::json)
    }

    fn set_open(&self, bearer: &str) {
        if let Ok(mut state) = self.state.lock() {
            state.insert(
                bearer.to_owned(),
                ConnectionStatus {
                    open: true,
                    ..Default::default()
                },
            );
        }
    }

    fn set_error(&self, bearer: &str, error: String) {
        if let Ok(mut state) = self.state.lock() {
            let status = state.entry(bearer.to_owned()).or_default();
            status.open = false;
            status.error = Some(error);
        }
    }

    #[allow(dead_code)]
    fn now_us(&self) -> u64 {
        self.started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64
    }
}

#[allow(clippy::too_many_arguments)]
fn spawn_peer_session(
    runtime: &tokio::runtime::Handle,
    is_client: bool,
    bearer: &str,
    peer: &str,
    udp_target: Option<(Arc<tokio::net::UdpSocket>, SocketAddr)>,
    egress: Arc<dyn BearerEgress>,
    bearer_metrics: Arc<Mutex<HashMap<String, BearerMetrics>>>,
    state: Arc<Mutex<HashMap<String, ConnectionStatus>>>,
    usb_outbound: Arc<Mutex<VecDeque<Vec<u8>>>>,
    ble_outbound: Arc<Mutex<VecDeque<Vec<u8>>>>,
    assoc_id: u64,
) -> PeerSession {
    let _guard = runtime.enter();
    let (mux, mut acceptor) = TokioMux::spawn(is_client, TokioMuxConfig::default());
    let (mux_to_link_tx, mut mux_to_link_rx) = mpsc::channel::<Vec<u8>>(CHANNEL_CAPACITY);
    let (link_to_mux_tx, link_to_mux_rx) = mpsc::channel::<Vec<u8>>(CHANNEL_CAPACITY);
    let (inbound_tx, mut inbound_rx) = mpsc::channel::<Vec<u8>>(CHANNEL_CAPACITY);

    let (mtu, cost, tier) = match bearer {
        "udp" => (UDP_MTU, 10u16, 1u8),
        "usb" => (USB_MTU, 20u16, 2u8),
        "ble" => (BLE_MTU, 30u16, 2u8),
        _ => (PACKET, 20u16, 2u8),
    };
    let mux_mtu = mtu.saturating_sub(QuicLinkAssoc::<XipLazyPacket>::MAX_OUTER_HEADER_OVERHEAD);
    mux.add_packet_link(mux_to_link_tx, link_to_mux_rx, mux_mtu, cost);

    let stats = PeerStats::new(assoc_id, bearer, peer);
    let stats_driver = stats.clone();
    let bearer_name = bearer.to_owned();

    let driver_task = runtime.spawn(async move {
        let pool = XipLazyPool::with_default_geometry(256);
        let cid = ConnectionId::new(1).expect("valid connection id");
        let assoc_config = AssocConfig {
            local_cid: None,
            default_peer_cid: cid,
            ..AssocConfig::default()
        };
        let mut assoc = QuicLinkAssoc::<XipLazyPacket>::new(assoc_config);
        let link_id = LinkId(1);
        let mut profile = LinkProfile::udp_datagram(tier, mtu, cid);
        if let quic_link::CongestionMode::NewRenoPaced {
            initial_window_bytes,
            ..
        } = profile.congestion_mode
        {
            profile.congestion_mode = quic_link::CongestionMode::NewRenoPaced {
                initial_window_bytes: initial_window_bytes.max(64 * 1024),
                pacing: quic_link::PacingConfig::disabled(profile.mtu),
            };
        }
        assoc.upsert_link(link_id, profile);
        let start = Instant::now();
        let mut pending_mux_frames: VecDeque<Vec<u8>> = VecDeque::new();

        loop {
            let now_us = u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX);
            assoc.set_now_us(now_us);

            while let Some(raw) = pending_mux_frames.pop_front() {
                let Ok(mut pkt) = pool.alloc() else {
                    pending_mux_frames.push_front(raw);
                    break;
                };
                if pkt.append(&raw).is_err() {
                    continue;
                }
                let meta = TxPacketMeta {
                    association: assoc.config().assoc_id,
                    stream_id: None,
                    priority: StreamPriority::NORMAL,
                    retransmittable: true,
                };
                if assoc.send_packet(meta, pkt).is_err() {
                    pending_mux_frames.push_front(raw);
                    break;
                }
            }

            let mut pool_clone = pool.clone();
            assoc.poll_timers(&mut pool_clone, now_us);

            while let Some(out) = assoc.pop_outbound_packet() {
                let wire = out.packet.bytes().to_vec();
                let outcome = if let Some((ref sock, peer_addr)) = udp_target {
                    if let Ok(mut m) = bearer_metrics.lock() {
                        m.entry(bearer_name.clone()).or_default().tx_submitted += 1;
                    }
                    match sock.send_to(&wire, peer_addr).await {
                        Ok(sent) if sent == wire.len() => {
                            if let Ok(mut m) = bearer_metrics.lock() {
                                m.entry(bearer_name.clone()).or_default().tx_accepted += 1;
                            }
                            stats_driver.sent_packets.fetch_add(1, Ordering::Relaxed);
                            LinkTxOutcome::Sent
                        }
                        _ => {
                            if let Ok(mut m) = bearer_metrics.lock() {
                                m.entry(bearer_name.clone()).or_default().tx_failed += 1;
                            }
                            stats_driver
                                .submission_failures
                                .fetch_add(1, Ordering::Relaxed);
                            LinkTxOutcome::Failed
                        }
                    }
                } else {
                    if let Ok(mut m) = bearer_metrics.lock() {
                        let entry = m.entry(bearer_name.clone()).or_default();
                        entry.tx_submitted += 1;
                        entry.tx_accepted += 1;
                    }
                    if let Ok(mut st) = state.lock() {
                        st.entry(bearer_name.clone()).or_default().tx_packets += 1;
                    }
                    if bearer_name == "usb" {
                        if let Ok(mut q) = usb_outbound.lock() {
                            q.push_back(wire.clone());
                        }
                    } else if bearer_name == "ble" {
                        if let Ok(mut q) = ble_outbound.lock() {
                            q.push_back(wire.clone());
                        }
                    }
                    egress.send_packet(&bearer_name, &wire);
                    stats_driver.sent_packets.fetch_add(1, Ordering::Relaxed);
                    LinkTxOutcome::Sent
                };
                let done_us = u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX);
                assoc.on_driver_complete(out.link_id, out.packet_number, outcome, done_us);
            }

            if let Some(link) = assoc.link(link_id) {
                stats_driver
                    .retransmitted_packets
                    .store(link.stats.retransmissions_sent, Ordering::Relaxed);
                stats_driver
                    .loss_events
                    .store(link.stats.packets_lost, Ordering::Relaxed);
            }

            let now_us = u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX);
            let sleep_dur = match assoc.next_deadline_us() {
                Some(dl) => Duration::from_micros(dl.saturating_sub(now_us).max(500)),
                None if !pending_mux_frames.is_empty() => Duration::from_millis(2),
                None => Duration::from_millis(25),
            };

            tokio::select! {
                biased;
                maybe_in = inbound_rx.recv() => {
                    let Some(raw_in) = maybe_in else {
                        break;
                    };
                    // If the incoming packet begins with a ShortHeader (fixed bit 0x40 set),
                    // demux through `QuicLinkAssoc`; otherwise pass raw quic-mux frames directly.
                    let is_short_header = raw_in.first().is_some_and(|b| (b & 0x40) != 0);
                    if is_short_header {
                        if let Ok(mut pkt) = pool.alloc_with_headroom(DEFAULT_HEADROOM) {
                            if pkt.append(&raw_in).is_ok() {
                                let rx_us = u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX);
                                if let Ok(outcome) = assoc.receive_packet(link_id, pkt, rx_us) {
                                    if let Some(mux_pkt) = outcome.mux_packet {
                                        let bytes = mux_pkt.bytes().to_vec();
                                        drop(mux_pkt);
                                        if link_to_mux_tx.send(bytes).await.is_err() {
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    } else if link_to_mux_tx.send(raw_in).await.is_err() {
                        break;
                    }
                }
                maybe_raw = mux_to_link_rx.recv(), if pending_mux_frames.len() < CHANNEL_CAPACITY => {
                    match maybe_raw {
                        Some(raw) => {
                            pending_mux_frames.push_back(raw);
                            while pending_mux_frames.len() < CHANNEL_CAPACITY {
                                match mux_to_link_rx.try_recv() {
                                    Ok(next) => pending_mux_frames.push_back(next),
                                    Err(_) => break,
                                }
                            }
                        }
                        None => {
                            if pending_mux_frames.is_empty() {
                                break;
                            }
                        }
                    }
                }
                _ = tokio::time::sleep(sleep_dur) => {}
            }
        }
    });

    let accept_task = if !is_client {
        Some(runtime.spawn(async move {
            while let Some(stream) = acceptor.accept().await {
                tokio::spawn(serve_android_stream(stream));
            }
        }))
    } else {
        None
    };

    PeerSession {
        mux,
        inbound_tx,
        driver_task,
        accept_task,
        stats,
    }
}

async fn serve_android_stream(stream: MuxStream) {
    // One router serves every ingress, as handler streams (a header, then an
    // optional raw body). A method Android does not implement is not
    // registered and receives the shared numeric error, so a correlated
    // request is never left without a reply. Network peers are not local
    // ingress.
    if let Err(error) = crate::android_api::global_router()
        .serve_stream(stream, false)
        .await
    {
        log::warn!("Android QUIC stream failed: {error}");
    }
}

fn parse_request_args(args: &str) -> (u64, u64, u64) {
    let (mut component, mut method, mut id) = (104, 83, 1);
    for part in args.split_whitespace() {
        let Some((key, value)) = part.split_once('=') else {
            continue;
        };
        let Ok(value) = value.parse::<u64>() else {
            continue;
        };
        match key {
            "component" => component = value,
            "method" => method = value,
            "id" => id = value,
            _ => {}
        }
    }
    (component, method, id)
}

fn hex(value: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(value.len() * 2);
    for byte in value {
        out.push(HEX[usize::from(byte >> 4)] as char);
        out.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    out
}

static CURRENT: OnceLock<Mutex<Option<Arc<BearerRuntime>>>> = OnceLock::new();

fn slot() -> &'static Mutex<Option<Arc<BearerRuntime>>> {
    CURRENT.get_or_init(|| Mutex::new(None))
}

pub fn set_current(runtime: Option<Arc<BearerRuntime>>) {
    if let Ok(mut slot) = slot().lock() {
        *slot = runtime;
    }
}

pub fn current() -> Option<Arc<BearerRuntime>> {
    slot().lock().ok()?.clone()
}

pub fn open(bearer: &str, args: &str) -> bool {
    current().is_some_and(|runtime| runtime.open(bearer, args))
}

pub fn packet(bearer: &str, data: &[u8]) -> bool {
    current().is_some_and(|runtime| runtime.packet(bearer, data))
}

pub fn close(bearer: &str) {
    if let Some(runtime) = current() {
        runtime.close(bearer);
    }
    uart_reset(bearer);
}

pub fn status(bearer: &str) -> Value {
    let Some(runtime) = current() else {
        return json!({"bearer": bearer, "runtime": false, "connection": null});
    };
    json!({
        "bearer": bearer,
        "runtime": true,
        "connection": runtime.connection_status(bearer),
    })
}

pub const COC_PACKET_MAX: usize = PACKET;
pub const UART_PACKET_MAX: usize = PACKET;
pub const UART_FRAME_MAX: usize = (PACKET + 1) * 2 + 4;
pub const BEARER_FRAME_MAX: usize = UART_FRAME_MAX;

pub fn is_uart_bearer(bearer: &str) -> bool {
    bearer == "usb" || bearer == "uart"
}

pub fn chunk(bearer: &str, data: &[u8]) -> bool {
    if is_uart_bearer(bearer) {
        uart_chunk(bearer, data)
    } else {
        coc_chunk(bearer, data)
    }
}

/// BLE CoC preserves packet boundaries: one SDU is one opaque QUIC packet.
pub fn coc_packet(packet: &[u8], out: &mut [u8]) -> Option<usize> {
    if packet.is_empty() || packet.len() > COC_PACKET_MAX || out.len() < packet.len() {
        return None;
    }
    out[..packet.len()].copy_from_slice(packet);
    Some(packet.len())
}

pub fn coc_chunk(bearer: &str, packet_bytes: &[u8]) -> bool {
    if bearer.is_empty() || packet_bytes.is_empty() || packet_bytes.len() > COC_PACKET_MAX {
        return false;
    }
    packet(bearer, packet_bytes)
}

struct UartFrameState {
    decoder: uart_codec::codec::Decoder,
}

impl UartFrameState {
    fn new() -> Self {
        Self {
            decoder: uart_codec::codec::Decoder::with_max(UART_PACKET_MAX + 1),
        }
    }
}

#[derive(Default)]
pub struct UartFramer {
    states: Mutex<HashMap<String, UartFrameState>>,
}

impl UartFramer {
    pub fn feed_chunk<F: FnMut(&[u8])>(&self, bearer: &str, chunk: &[u8], mut emit: F) {
        let Ok(mut states) = self.states.lock() else {
            return;
        };
        let state = states
            .entry(bearer.to_owned())
            .or_insert_with(UartFrameState::new);
        if let Ok(records) = state.decoder.push(chunk) {
            for payload in records {
                if let Ok(packet) = uart_codec::decode_packet(&payload) {
                    emit(packet);
                }
            }
        }
    }

    pub fn reset(&self, bearer: &str) {
        if let Ok(mut states) = self.states.lock() {
            states.remove(bearer);
        }
    }
}

static UART_FRAMER: OnceLock<UartFramer> = OnceLock::new();

pub fn uart_framer() -> &'static UartFramer {
    UART_FRAMER.get_or_init(UartFramer::default)
}

pub fn uart_chunk(bearer: &str, chunk: &[u8]) -> bool {
    if bearer.is_empty() || chunk.is_empty() || current().is_none() {
        return false;
    }
    uart_framer().feed_chunk(bearer, chunk, |inner| {
        packet(bearer, inner);
    });
    true
}

pub fn uart_reset(bearer: &str) {
    uart_framer().reset(bearer);
}

pub fn encode_uart_packet(bearer: &str, packet: &[u8], out: &mut [u8]) -> Option<usize> {
    if !is_uart_bearer(bearer) || packet.is_empty() || packet.len() > UART_PACKET_MAX {
        return None;
    }
    let mut encoder = uart_codec::encode_packet(packet).ok()?;
    let used = encoder.write(out);
    encoder.is_finished().then_some(used)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coc_is_one_packet_per_sdu() {
        let mut out = [0_u8; 8];
        let used = coc_packet(&[1, 2, 3], &mut out).unwrap();
        assert_eq!(&out[..used], &[1, 2, 3]);
    }

    #[test]
    fn uart_framer_round_trips_marked_quic_packets() {
        let mut wire = [0_u8; UART_FRAME_MAX];
        let used = encode_uart_packet("usb", &[0x40, 1, 2], &mut wire).unwrap();
        let framer = UartFramer::default();
        let mut sent = Vec::new();
        framer.feed_chunk("usb", &wire[..used / 2], |inner| sent.push(inner.to_vec()));
        assert!(sent.is_empty());
        framer.feed_chunk("usb", &wire[used / 2..used], |inner| {
            sent.push(inner.to_vec())
        });
        assert_eq!(sent, vec![vec![0x40, 1, 2]]);
    }

    struct NoEgress;
    impl BearerEgress for NoEgress {
        fn send_packet(&self, _bearer: &str, _packet: &[u8]) {}
    }

    /// Android as the probe's client reaches a probed node's registered
    /// `probe.handler` over its UDP bearer, and validates the payload.
    #[test]
    fn android_probes_a_registered_handler_over_udp() {
        let server_socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let server_address = server_socket.local_addr().unwrap();
        let client_socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let client_address = client_socket.local_addr().unwrap();

        let server = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async move {
                let udp_link = quic_link::TokioUdpLink::from_std(server_socket).unwrap();
                let cid = ConnectionId::new(1).unwrap();
                let (tx, rx, link_task) =
                    quic_link::spawn_udp_packet_link(udp_link, client_address, cid);
                let (mux, mut acceptor) = TokioMux::spawn(false, TokioMuxConfig::default());
                mux.add_packet_link(tx, rx, 1180, 10);

                let router = crate::android_api::AndroidRouter::new();
                assert!(router.register_stream(
                    crate::android_api::methods::PROBE_HANDLER,
                    crate::android_api::ProbeStreamHandler,
                ));
                let stream =
                    tokio::time::timeout(Duration::from_secs(5), acceptor.accept())
                        .await
                        .expect("probe stream accepted")
                        .expect("stream");
                router.serve_stream(stream, false).await.unwrap();
                // Allow final FIN and ACK packets to flush before tearing down the link task.
                tokio::time::sleep(Duration::from_millis(20)).await;
                mux.close();
                link_task.abort();
            });
        });

        let runtime = tokio::runtime::Runtime::new().unwrap();
        let bearers = BearerRuntime::spawn_with_udp(
            runtime.handle().clone(),
            Arc::new(NoEgress),
            Some(client_socket),
        );
        let destination =
            quic_tools::ProbeDestination::parse(&format!("udp://{server_address}")).unwrap();
        let request = quic_tools::ProbeServiceRequest::new(100_000, 1000);
        let result = runtime
            .block_on(bearers.probe(&destination, request, Duration::from_secs(10)))
            .expect("Android probe");
        server.join().unwrap();
        assert_eq!(result.bytes, 100_000);
        assert!(result.elapsed_us > 0);
        // An unsupported destination is refused, not guessed.
        let mesh = quic_tools::ProbeDestination::parse("mesh://fc00::1").unwrap();
        assert!(runtime
            .block_on(bearers.probe(&mesh, request, Duration::from_secs(1)))
            .is_err());
    }

    #[test]
    fn android_usb_and_ble_packet_channels_and_telemetry_work() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let bearers = BearerRuntime::spawn(runtime.handle().clone(), Arc::new(NoEgress));
        let (assocs, rows) = runtime.block_on(bearers.rows()).unwrap();
        assert!(assocs.is_empty());
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].name.as_deref(), Some("usb"));
        assert_eq!(rows[1].name.as_deref(), Some("ble"));

        let telemetry = runtime.block_on(bearers.telemetry()).unwrap();
        assert_eq!(telemetry.live_associations, 0);
        assert_eq!(telemetry.received_packets, 0);
        assert_eq!(telemetry.sent_packets, 0);
    }
}

/// `probe.start` on Android: run the probe with this node as the client, over
/// its UDP, USB or BLE bearer, and answer with the outcome header.
#[derive(Clone, Copy)]
pub struct ProbeStartHandler;

impl crate::android_api::UnaryHandler for ProbeStartHandler {
    fn call(&self, raw_request: &[u8], timeout_ms: Option<u64>) -> crate::android_api::UnaryReply {
        let raw_request = raw_request.to_vec();
        Box::pin(async move {
            let record = mesh_api::envelope::decode(&raw_request)?;
            let (id, request) = quic_tools::decode_probe_start_record(record)?;
            let requested = request.peer?;
            // A `mesh://` or bare node identifier is looked up in the discovery
            // inventory (multicast and NAN announces) and probed over UDP.
            let peer = if requested.scheme() == "mesh" {
                let resolved_endpoint: Result<std::net::SocketAddr, String> = {
                    #[cfg(feature = "jni-wrapper")]
                    {
                        crate::mesh_jni::discovered_udp_endpoint(requested.target())
                    }
                    #[cfg(not(feature = "jni-wrapper"))]
                    {
                        Err("discovery is not running".to_owned())
                    }
                };
                match resolved_endpoint.and_then(|address| {
                    quic_tools::ProbeDestination::parse(&format!("udp://{address}"))
                        .ok_or_else(|| "resolved endpoint is not a probe destination".to_owned())
                }) {
                    Ok(resolved) => resolved,
                    Err(error) => {
                        log::warn!(
                            "Android probe lookup of {} failed: {error}",
                            requested.as_str()
                        );
                        let mut response = vec![0u8; 256];
                        let used = quic_tools::encode_probe_result_response(
                            id,
                            request,
                            false,
                            0,
                            0,
                            &mut response,
                        )?;
                        response.truncate(used);
                        return Some(response);
                    }
                }
            } else {
                requested
            };
            let runtime = current();
            let started = Instant::now();
            let timeout =
                Duration::from_millis(quic_tools::probe_timeout_ms(timeout_ms, request.total_bytes()));
            let outcome = match runtime {
                Some(runtime) => runtime.probe(&peer, request, timeout).await,
                None => Err("Android QUIC node is not running".to_owned()),
            };
            let (success, received, elapsed) = match outcome {
                Ok(result) => (true, result.bytes, result.elapsed_us),
                Err(error) => {
                    log::warn!("Android probe to {} failed: {error}", peer.as_str());
                    (
                        false,
                        0,
                        started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64,
                    )
                }
            };
            let mut response = vec![0u8; 256];
            let used = quic_tools::encode_probe_result_response(
                id,
                request,
                success,
                received,
                elapsed,
                &mut response,
            )?;
            response.truncate(used);
            Some(response)
        })
    }
}
