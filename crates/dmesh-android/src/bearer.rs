use dmesh_server::tagged;
use quic_lite::bearer::{
    BearerContext, BearerInfo, BearerName, EgressSubmission, PacketBearer, PacketEgress,
    PacketSendOutcome, PacketSubmitError,
};
use quic_lite::packet_pool::PacketPool as FixedPacketPool;
use quic_lite::{
    ConnectionLimits, DEFAULT_PACKET_POOL_SLOT_SIZE, PACKET_PREFIX_RESERVE, PacketMeta,
    PacketPool as PacketPoolTrait, PacketWriter, PeerL2Address, QuicNode,
};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const PACKET: usize = 1100;
const POOL_SLOTS: usize = 32;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
const PEER: PeerL2Address = match PeerL2Address::new(1) {
    Some(peer) => peer,
    None => unreachable!(),
};

type Pool = FixedPacketPool<POOL_SLOTS, DEFAULT_PACKET_POOL_SLOT_SIZE>;
type Node = QuicNode<(), 16, 8, Pool>;

static PACKET_POOL: Pool = Pool::new();

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

struct JavaPacketBearer {
    name: &'static str,
    egress: Arc<dyn BearerEgress>,
    contexts: Arc<Mutex<HashMap<String, BearerContext<Pool>>>>,
    state: Arc<Mutex<HashMap<String, ConnectionStatus>>>,
}

impl PacketEgress<<Pool as PacketPoolTrait>::Buffer> for JavaPacketBearer {
    fn submit(
        &mut self,
        _peer: PeerL2Address,
        submission: EgressSubmission<<Pool as PacketPoolTrait>::Buffer>,
    ) -> Result<(), PacketSubmitError<<Pool as PacketPoolTrait>::Buffer>> {
        self.egress
            .send_packet(self.name, submission.packet().bytes());
        if let Ok(mut state) = self.state.lock() {
            state.entry(self.name.to_owned()).or_default().tx_packets += 1;
        }
        submission.complete(PacketSendOutcome::Sent, 0);
        Ok(())
    }
}

impl PacketBearer<Pool> for JavaPacketBearer {
    type AttachError = Infallible;

    fn info(&self) -> BearerInfo {
        BearerInfo {
            name: BearerName::new(self.name).expect("static Android bearer name"),
            max_packet_size: PACKET,
            prefix_required: 0,
            suffix_required: 0,
            requires_packet_encryption: false,
            secure_link: true,
            nominal_bitrate_bps: 0,
            local_mac: None,
        }
    }

    fn attach(&mut self, context: BearerContext<Pool>) -> Result<(), Self::AttachError> {
        self.contexts
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .insert(self.name.to_owned(), context);
        Ok(())
    }
}

pub struct BearerRuntime {
    node: quic_lite::tokio::TokioNode,
    bearers: HashMap<String, quic_lite::BearerId>,
    contexts: Arc<Mutex<HashMap<String, BearerContext<Pool>>>>,
    state: Arc<Mutex<HashMap<String, ConnectionStatus>>>,
    started: Instant,
    runtime: tokio::runtime::Handle,
}

impl BearerRuntime {
    pub fn spawn(runtime: tokio::runtime::Handle, egress: Arc<dyn BearerEgress>) -> Arc<Self> {
        Self::spawn_with_udp(runtime, egress, None)
    }

    pub fn spawn_with_udp(
        runtime: tokio::runtime::Handle,
        egress: Arc<dyn BearerEgress>,
        udp_socket: Option<std::net::UdpSocket>,
    ) -> Arc<Self> {
        let contexts = Arc::new(Mutex::new(HashMap::new()));
        let state = Arc::new(Mutex::new(HashMap::new()));
        let thread_contexts = contexts.clone();
        let thread_state = state.clone();
        let (ready, initialized) = std::sync::mpsc::sync_channel(1);
        std::thread::Builder::new()
            .name("dmesh-quic".to_owned())
            .spawn(move || {
                let driver_runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("create Android QUIC driver runtime");
                driver_runtime.block_on(async move {
                    let mut raw_node = Node::new(None, &PACKET_POOL);
                    let mut bearers = HashMap::new();
                    for name in ["usb", "ble"] {
                        let bearer = JavaPacketBearer {
                            name,
                            egress: egress.clone(),
                            contexts: thread_contexts.clone(),
                            state: thread_state.clone(),
                        };
                        match raw_node.add_bearer(bearer) {
                            Ok(id) => {
                                bearers.insert(name.to_owned(), id);
                            }
                            Err(error) => {
                                log::error!("failed to attach Android {name} bearer: {error:?}")
                            }
                        }
                    }
                    if let Some(socket) = udp_socket {
                        match quic_lite::bearer_udp::TokioUdpBearer::<16>::from_std(socket)
                            .map_err(|error| error.to_string())
                            .and_then(|bearer| {
                                raw_node
                                    .add_bearer(bearer)
                                    .map_err(|error| format!("{error:?}"))
                            }) {
                            Ok(id) => {
                                bearers.insert("udp".to_owned(), id);
                            }
                            Err(error) => {
                                log::error!("failed to attach Android UDP bearer: {error}")
                            }
                        }
                    }
                    let (node, driver) = quic_lite::tokio::TokioNodeDriver::new(
                        raw_node,
                        ConnectionLimits::default(),
                    );
                    if ready.send((node, bearers)).is_err() {
                        return;
                    }
                    if let Err(error) = driver.run().await {
                        log::error!("Android QUIC node stopped: {error:?}");
                    }
                });
            })
            .expect("start Android QUIC driver thread");
        let (node, bearers) = initialized
            .recv()
            .expect("Android QUIC driver initialized without a handle");
        #[cfg(target_os = "android")]
        {
            let server = node.clone();
            runtime.spawn(async move {
                while let Some(stream) = server.accept_stream().await {
                    tokio::spawn(serve_android_stream(stream));
                }
            });
        }
        Arc::new(Self {
            node,
            bearers,
            contexts,
            state,
            started: Instant::now(),
            runtime,
        })
    }

    pub async fn request(&self, bearer: &str, record: &[u8]) -> Result<Vec<u8>, String> {
        let bearer_id = *self
            .bearers
            .get(bearer)
            .ok_or_else(|| format!("unknown Android bearer {bearer}"))?;
        self.set_open(bearer);
        let operation = async {
            let association = self
                .node
                .associate(
                    PacketMeta {
                        bearer: bearer_id,
                        peer_l2_address: PEER,
                        received_at_us: self.now_us(),
                    },
                    self.now_us(),
                )
                .await
                .map_err(|error| format!("start association: {error:?}"))?;
            association
                .wait_established()
                .await
                .map_err(|error| format!("establish association: {error:?}"))?;
            let mut stream = association
                .open_stream()
                .await
                .map_err(|error| format!("open request stream: {error:?}"))?;
            stream
                .write_all(record)
                .await
                .map_err(|error| format!("write request: {error}"))?;
            stream
                .shutdown()
                .await
                .map_err(|error| format!("finish request: {error}"))?;
            let mut response = Vec::new();
            stream
                .read_to_end(&mut response)
                .await
                .map_err(|error| format!("read response: {error}"))?;
            association
                .finish()
                .await
                .map_err(|error| format!("finish association: {error:?}"))?;
            Ok(response)
        };
        let result: Result<Vec<u8>, String> = tokio::time::timeout(REQUEST_TIMEOUT, operation)
            .await
            .map_err(|_| "Android bearer request timed out".to_owned())?;
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

    fn open(&self, bearer: &str, args: &str) -> bool {
        if !self.bearers.contains_key(bearer) {
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
        let context = self
            .contexts
            .lock()
            .ok()
            .and_then(|contexts| contexts.get(bearer).cloned());
        let Some(context) = context else { return false };
        let Some(mut writer) = context.pool().acquire_writer(PACKET_PREFIX_RESERVE, 0) else {
            return false;
        };
        if data.len() > writer.payload_mut().len() {
            return false;
        }
        writer.payload_mut()[..data.len()].copy_from_slice(data);
        let Some(packet) = writer.commit(data.len()) else {
            return false;
        };
        context.enqueue_packet(
            PacketMeta {
                bearer: context.bearer(),
                peer_l2_address: PEER,
                received_at_us: self.now_us(),
            },
            packet,
        );
        if let Ok(mut state) = self.state.lock() {
            state.entry(bearer.to_owned()).or_default().rx_packets += 1;
        }
        true
    }

    fn close(&self, bearer: &str) {
        if let Ok(mut state) = self.state.lock() {
            state.remove(bearer);
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

    fn now_us(&self) -> u64 {
        self.started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64
    }
}

#[cfg(target_os = "android")]
async fn serve_android_stream(mut stream: quic_lite::tokio::TokioStream) {
    let mut request = Vec::new();
    if let Err(error) = stream.read_to_end(&mut request).await {
        log::warn!("Android QUIC request read failed: {error}");
        return;
    }
    let response = crate::mesh_jni::android_discovery_active_response(&request)
        .or_else(|| crate::mesh_jni::android_nan_wakeup_response(&request))
        .or_else(|| crate::mesh_jni::android_battery_response(&request))
        .or_else(|| crate::mesh_jni::android_telemetry_response(&request))
        .or_else(|| crate::mesh_jni::android_discovery_nodes_response(&request));
    if let Some(response) = response
        && let Err(error) = stream.write_all(&response).await
    {
        log::warn!("Android QUIC response write failed: {error}");
    }
    if let Err(error) = stream.shutdown().await {
        log::warn!("Android QUIC response finish failed: {error}");
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
}
