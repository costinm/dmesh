use dmesh_server::tagged;
use dmesh_server::transport::TaggedClient;
use quic_lite::{ConnectionId, DatagramClientDriver};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};
use tokio::time::MissedTickBehavior;

const PACKET: usize = 1100;
const HISTORY: usize = 16;

pub trait BearerEgress: Send + Sync {
    fn send_packet(&self, bearer: &str, packet: &[u8]);
}

enum Event {
    Open { bearer: String, args: String },
    Packet { bearer: String, data: Vec<u8> },
    Close { bearer: String },
}

pub struct BearerRuntime {
    sender: UnboundedSender<Event>,
    state: Arc<Mutex<HashMap<String, Connection>>>,
}

struct Connection {
    client: Option<TaggedClient<HISTORY, PACKET>>,
    driver: Option<DatagramClientDriver<PACKET>>,
    last_response: Vec<u8>,
    complete: bool,
    error: Option<String>,
    rx_packets: u64,
    tx_packets: u64,
    retransmits: u64,
}

impl Connection {
    fn new() -> Self {
        Self {
            client: None,
            driver: None,
            last_response: Vec::new(),
            complete: false,
            error: None,
            rx_packets: 0,
            tx_packets: 0,
            retransmits: 0,
        }
    }

    fn open(&mut self, args: &str, now: u64) -> Result<Option<Vec<u8>>, String> {
        self.client = None;
        self.driver = None;
        self.last_response.clear();
        self.complete = false;
        self.error = None;
        self.rx_packets = 0;
        self.tx_packets = 0;
        self.retransmits = 0;

        let (component, method, id) = parse_request_args(args);
        let mut wire = [0u8; 64];
        let used = tagged::encode_numeric_empty_request(component, method, id, &mut wire)
            .ok_or_else(|| "unable to encode bearer request".to_string())?;
        let mut client = TaggedClient::new(fresh_cid(), &wire[..used])
            .map_err(|error| format!("tagged client: {error:?}"))?;
        client.set_close_when_complete(false);
        let driver = DatagramClientDriver::start(&mut client, now)
            .map_err(|error| format!("bearer OPEN: {error:?}"))?;
        let packet = driver
            .packet()
            .ok_or_else(|| "started bearer has no OPEN packet".to_string())?
            .to_vec();
        self.tx_packets = driver.tx_packets();
        self.retransmits = driver.retransmit_packets();
        self.client = Some(client);
        self.driver = Some(driver);
        Ok(Some(packet))
    }

    fn receive(&mut self, data: &[u8], now: u64) -> Result<Option<Vec<u8>>, String> {
        let (client, driver) = match (self.client.as_mut(), self.driver.as_mut()) {
            (Some(client), Some(driver)) => (client, driver),
            _ => return Err("bearer is not open".to_string()),
        };
        let accepted = driver
            .receive(client, data, now)
            .map_err(|error| format!("bearer receive: {error:?}"))?;
        let packet = driver.packet().map(|value| value.to_vec());
        let retransmits = driver.retransmit_packets();
        if accepted {
            self.rx_packets += 1;
        }
        if packet.is_some() {
            self.tx_packets += 1;
        }
        self.retransmits = retransmits;
        self.apply_completion();
        Ok(packet)
    }

    fn poll(&mut self, now: u64) -> Result<Option<Vec<u8>>, String> {
        let (client, driver) = match (self.client.as_mut(), self.driver.as_mut()) {
            (Some(client), Some(driver)) => (client, driver),
            _ => return Ok(None),
        };
        driver
            .poll(client, now, 600, 400)
            .map_err(|error| format!("bearer poll: {error:?}"))?;
        let packet = driver.packet().map(|value| value.to_vec());
        let retransmits = driver.retransmit_packets();
        if packet.is_some() {
            self.tx_packets += 1;
        }
        self.retransmits = retransmits;
        self.apply_completion();
        Ok(packet)
    }

    fn apply_completion(&mut self) {
        let snapshot = self.client.as_ref().map(|client| {
            (
                client.is_complete(),
                client.response().map(|value| value.to_vec()),
            )
        });
        if let Some((true, response)) = snapshot {
            self.complete = true;
            if let Some(response) = response {
                self.last_response = response;
            }
        }
    }

    fn status(&self) -> Value {
        json!({
            "open": self.client.is_some(),
            "complete": self.complete,
            "error": self.error,
            "rx_packets": self.rx_packets,
            "tx_packets": self.tx_packets,
            "retransmits": self.retransmits,
            "last_response_hex": hex(&self.last_response),
        })
    }
}

fn parse_request_args(args: &str) -> (u64, u64, u64) {
    let mut component = 104;
    let mut method = 83;
    let mut id = 1;
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

fn fresh_cid() -> ConnectionId {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos() as u64)
        .unwrap_or(1);
    ConnectionId::new(1 | (now & 0x00ff_ffff_ffff_ffff)).expect("bounded bearer connection id")
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
}

pub fn status(bearer: &str) -> Value {
    let Some(runtime) = current() else {
        return json!({
            "bearer": bearer,
            "runtime": false,
            "connection": null,
        });
    };
    let connection = runtime.connection_status(bearer);
    json!({
        "bearer": bearer,
        "runtime": true,
        "connection": connection,
    })
}

impl BearerRuntime {
    pub fn spawn(runtime: tokio::runtime::Handle, egress: Arc<dyn BearerEgress>) -> Arc<Self> {
        let (sender, receiver) = unbounded_channel();
        let state = Arc::new(Mutex::new(HashMap::new()));
        let (egress_sender, egress_receiver): (
            std::sync::mpsc::SyncSender<(String, Vec<u8>)>,
            std::sync::mpsc::Receiver<(String, Vec<u8>)>,
        ) = std::sync::mpsc::sync_channel(128);
        let egress_thread = egress.clone();
        std::thread::spawn(move || {
            for item in egress_receiver {
                let (bearer, packet) = item;
                egress_thread.send_packet(&bearer, &packet);
            }
        });
        runtime.spawn(bearer_loop(receiver, state.clone(), egress_sender));
        Arc::new(Self { sender, state })
    }

    fn open(&self, bearer: &str, args: &str) -> bool {
        if bearer.is_empty() {
            return false;
        }
        self.sender
            .send(Event::Open {
                bearer: bearer.to_string(),
                args: args.to_string(),
            })
            .is_ok()
    }

    fn packet(&self, bearer: &str, data: &[u8]) -> bool {
        if bearer.is_empty() || data.is_empty() || data.len() > PACKET {
            return false;
        }
        self.sender
            .send(Event::Packet {
                bearer: bearer.to_string(),
                data: data.to_vec(),
            })
            .is_ok()
    }

    fn close(&self, bearer: &str) {
        if bearer.is_empty() {
            return;
        }
        let _ = self.sender.send(Event::Close {
            bearer: bearer.to_string(),
        });
    }

    fn connection_status(&self, bearer: &str) -> Option<Value> {
        self.state
            .lock()
            .ok()?
            .get(bearer)
            .map(|connection| connection.status())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dmesh_server::cbor::Encoder;
    use dmesh_server::tagged::{Name, Record};
    use dmesh_server::transport::ConnectionServer;

    struct TestEgress {
        sent: Arc<Mutex<Vec<Vec<u8>>>>,
    }

    impl BearerEgress for TestEgress {
        fn send_packet(&self, _bearer: &str, packet: &[u8]) {
            self.sent
                .lock()
                .unwrap_or_else(|value| value.into_inner())
                .push(packet.to_vec());
        }
    }

    fn test_handler(record: Record<'_>) -> Option<Vec<u8>> {
        let component = match record.component? {
            Name::Tag(value) if value == 60_001 => value,
            _ => return None,
        };
        let method = match record.method? {
            Name::Tag(value) => value,
            _ => return None,
        };
        let id = record.id?;
        let mut result = [0u8; 16];
        let mut encoder = Encoder::new(&mut result);
        let len = encoder
            .map(1)
            .and_then(|()| encoder.uint(1))
            .and_then(|()| encoder.boolean(true))
            .map(|()| encoder.len())?;
        let mut response = [0u8; 64];
        let used =
            tagged::encode_numeric_response(component, method, id, &result[..len], &mut response)?;
        Some(response[..used].to_vec())
    }

    fn phone_ble_handler(record: Record<'_>) -> Option<Vec<u8>> {
        let component = match record.component? {
            Name::Tag(value) if value == 104 => value,
            _ => return None,
        };
        let method = match record.method? {
            Name::Tag(value) => value,
            _ => return None,
        };
        let id = record.id?;
        let mut result = [0u8; 16];
        let mut encoder = Encoder::new(&mut result);
        let len = encoder
            .map(1)
            .and_then(|()| encoder.uint(1))
            .and_then(|()| encoder.boolean(true))
            .map(|()| encoder.len())?;
        let mut response = [0u8; 64];
        let used =
            tagged::encode_numeric_response(component, method, id, &result[..len], &mut response)?;
        Some(response[..used].to_vec())
    }

    #[test]
    fn phone_open_packet_is_accepted_by_connection_server() {
        dmesh_server::services::register_tagged_component(104, phone_ble_handler);
        let packet = [
            0xc0, 0x44, 0x4d, 0x00, 0x01, 0x00, 0x08, 0xc0, 0xd5, 0xfc, 0xe0, 0x15, 0xfc, 0x35,
            0x15, 0x00, 0x11, 0x00, 0x0f, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x09, 0x80, 0x04, 0x00,
            0x00, 0x80, 0x04, 0x00, 0x00, 0x00,
        ];
        let mut server = ConnectionServer::<16, 1100>::new(ConnectionId::new(0x999).unwrap());
        let mut out = [0u8; 1100];
        let response = server.receive(&packet, &mut out).unwrap();
        assert!(response.is_some(), "server did not answer the phone OPEN");
    }

    #[test]
    fn bearer_round_trips_a_tagged_request() {
        dmesh_server::services::register_tagged_component(60_001, test_handler);
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let sent = Arc::new(Mutex::new(Vec::new()));
        let egress = Arc::new(TestEgress { sent: sent.clone() });
        let bearer = BearerRuntime::spawn(runtime.handle().clone(), egress);
        set_current(Some(bearer));
        assert!(open("test", "component=60001 method=1 id=9"));
        let mut server = ConnectionServer::<16, 1100>::new(ConnectionId::new(0x999).unwrap());
        let mut server_out = [0u8; 1100];
        for _ in 0..300 {
            let queued = {
                let mut sent = sent.lock().unwrap_or_else(|value| value.into_inner());
                sent.drain(..).collect::<Vec<_>>()
            };
            for packet in queued {
                if let Some(len) = server.receive(&packet, &mut server_out).unwrap() {
                    assert!(crate::bearer::packet("test", &server_out[..len]));
                }
            }
            if status("test")
                .pointer("/connection/complete")
                .and_then(Value::as_bool)
                == Some(true)
            {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let complete = status("test")
            .pointer("/connection/complete")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        set_current(None);
        assert!(complete);
    }
}

async fn bearer_loop(
    mut receiver: UnboundedReceiver<Event>,
    state: Arc<Mutex<HashMap<String, Connection>>>,
    egress: std::sync::mpsc::SyncSender<(String, Vec<u8>)>,
) {
    let started = Instant::now();
    let mut interval = tokio::time::interval(Duration::from_millis(5));
    interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut pending: Vec<(String, Vec<u8>)> = Vec::new();
    let resume = Arc::new(tokio::sync::Notify::new());
    let mut active = 0usize;

    loop {
        pending.clear();
        let resume_wait = resume.clone();
        let tick = async {
            if active > 0 {
                interval.tick().await;
            } else {
                resume_wait.notified().await;
            }
        };
        tokio::select! {
            event = receiver.recv() => {
                let Some(event) = event else {
                    break;
                };
                let now = started.elapsed().as_millis() as u64;
                let mut state = state.lock().unwrap_or_else(|value| value.into_inner());
                match event {
                    Event::Open { bearer, args } => {
                        let connection = state.entry(bearer.clone()).or_insert_with(Connection::new);
                        if let Err(error) = connection.open(&args, now) {
                            connection.error = Some(error.clone());
                            log::warn!("bearer open failed: {error}");
                        }
                        if let Some(packet) = connection.driver.as_ref().and_then(|driver| driver.packet()) {
                            pending.push((bearer, packet.to_vec()));
                        }
                    }
                    Event::Packet { bearer, data } => {
                        if let Some(connection) = state.get_mut(&bearer) {
                            match connection.receive(&data, now) {
                                Ok(Some(packet)) => pending.push((bearer, packet)),
                                Ok(None) => {}
                                Err(error) => {
                                    connection.error = Some(error.clone());
                                    log::warn!("bearer packet failed: {error}");
                                    state.remove(&bearer);
                                }
                            }
                        }
                    }
                    Event::Close { bearer } => {
                        state.remove(&bearer);
                    }
                }
                let next = state
                    .values()
                    .filter(|connection| connection.client.is_some())
                    .count();
                if active == 0 && next > 0 {
                    resume.notify_one();
                }
                active = next;
            }
            _ = tick => {
                let now = started.elapsed().as_millis() as u64;
                let mut state = state.lock().unwrap_or_else(|value| value.into_inner());
                for (bearer, connection) in state.iter_mut() {
                    if connection.client.is_none() {
                        continue;
                    }
                    match connection.poll(now) {
                        Ok(Some(packet)) => pending.push((bearer.clone(), packet)),
                        Ok(None) => {}
                        Err(error) => {
                            connection.error = Some(error.clone());
                            log::warn!("bearer poll failed: {error}");
                        }
                    }
                }
                let next = state
                    .values()
                    .filter(|connection| connection.client.is_some())
                    .count();
                if active == 0 && next > 0 {
                    resume.notify_one();
                }
                active = next;
            }
        }
        for (bearer, packet) in pending.drain(..) {
            if egress.try_send((bearer, packet)).is_err() {
                log::warn!("bearer egress queue full");
            }
        }
    }
}
