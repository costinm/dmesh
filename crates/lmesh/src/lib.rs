/// Local mesh announce and discovery
/// Each mesh node will listen for UDP multicast announcements on
/// all interfaces. The announcement includes the public key of the
/// node, the (claimed - untrusted) name.
///
///
use anyhow::{Context, Result};

use p256::SecretKey;
use p256::elliptic_curve::Generate;
use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::net::UdpSocket;
use tokio::sync::RwLock;

use tracing::{debug, error, info, instrument, warn};

pub mod radio;
pub mod radio_protocol;

const MULTICAST_PORT: u16 = 5227;
const MULTICAST_IPV4: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 250);
const MULTICAST_IPV6: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x5227);
const MAX_STORED_ANNOUNCES: usize = 16;

/// Announcement message sent over multicast
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Announce {
    /// Base64url encoded public key (P256)
    pub public_key: String,
    /// Optional node metadata
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<HashMap<String, String>>,
}

/// Represents a discovered node
#[derive(Debug, Clone)]
pub struct Node {
    /// Base64url encoded public key
    pub public_key: String,
    /// Last seen address
    pub address: SocketAddr,
    /// Last announcement received
    pub last_seen: std::time::Instant,
    /// Optional metadata from the announcement
    pub metadata: Option<HashMap<String, String>>,
}

/// Link-local discovery service
pub struct LocalDiscovery {
    /// EC P256 private key (DER encoded)
    #[allow(dead_code)]
    private_key: Vec<u8>,
    /// EC P256 public key (DER encoded)
    #[allow(dead_code)]
    public_key: Vec<u8>,
    /// Base64url encoded public key for announcements
    public_key_b64: String,
    /// Map of discovered nodes, keyed by base64url encoded public key
    nodes: Arc<RwLock<HashMap<String, Node>>>,
    /// Directory where per-node discovery files are written.
    node_store_dir: Arc<PathBuf>,
    /// IPv4 UDP socket
    socket_v4: Option<Arc<UdpSocket>>,
    /// IPv6 UDP socket
    socket_v6: Option<Arc<UdpSocket>>,
}

impl LocalDiscovery {
    /// Create a new LocalDiscovery instance with an optional EC P256 private key
    /// If no key is provided, attempts to load from $HOME/.ssh/key.pem or generates a new one
    #[instrument(skip(key))]
    pub async fn new(key: Option<SecretKey>) -> Result<Self> {
        // Get the private key either from parameter or by loading/generating
        let private_key_ec = match key {
            Some(key) => key,
            None => {
                debug!("No key provided, loading or generating new key");
                Self::load_or_generate_key()?
            }
        };

        // Serialize the private key to DER format
        let secret_key_der = private_key_ec
            .to_pkcs8_der()
            .context("Failed to serialize private key")?;
        let private_key = secret_key_der.to_bytes().to_vec();

        // Get the public key and serialize it to DER format (SPKI)
        let public_key_ec = private_key_ec.public_key();
        let public_key_der = public_key_ec
            .to_public_key_der()
            .context("Failed to serialize public key")?;
        let public_key = public_key_der.to_vec();

        let public_key_b64 = base64_url_encode(&public_key);

        Ok(Self {
            private_key,
            public_key,
            public_key_b64,
            nodes: Arc::new(RwLock::new(HashMap::new())),
            node_store_dir: Arc::new(Self::default_node_store_dir()?),
            socket_v4: None,
            socket_v6: None,
        })
    }

    /// Load key from file or generate a new one
    fn load_or_generate_key() -> Result<SecretKey> {
        // Try to load key from file
        let home_dir = std::env::var("HOME").context("HOME environment variable not set")?;
        let key_path = Path::new(&home_dir).join(".ssh").join("key.pem");

        if key_path.exists() {
            // Load key from file
            let key_data = fs::read_to_string(&key_path).context("Failed to read key file")?;
            // Check if the file is not empty before trying to parse it
            if !key_data.is_empty() {
                if let Ok(key) = SecretKey::from_pkcs8_pem(&key_data) {
                    return Ok(key);
                }
            }
        }

        // Generate new keypair
        let key = SecretKey::generate();

        // Save the generated key to file
        if let Some(parent) = key_path.parent() {
            std::fs::create_dir_all(parent).context("Failed to create .ssh directory")?;
        }
        let key_pem = key
            .to_pkcs8_pem(Default::default())
            .context("Failed to serialize private key to PEM")?;
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(&key_path)
            .context("Failed to write key to file")?;
        std::io::Write::write_all(&mut file, key_pem.as_bytes())
            .context("Failed to write key to file")?;

        Ok(key)
    }

    /// Start the UDP multicast listeners
    #[instrument(skip(self))]
    pub async fn start(&mut self) -> Result<()> {
        // Setup IPv4 multicast socket
        match Self::setup_multicast_v4().await {
            Ok(socket) => {
                self.socket_v4 = Some(Arc::new(socket));
                debug!(
                    multicast_ip = %MULTICAST_IPV4,
                    multicast_port = MULTICAST_PORT,
                    "mcast_v4"
                );
            }
            Err(e) => {
                warn!("Failed to setup IPv4 multicast: {}", e);
            }
        }

        // Setup IPv6 multicast socket
        match Self::setup_multicast_v6().await {
            Ok(socket) => {
                self.socket_v6 = Some(Arc::new(socket));
                debug!(
                    multicast_ip = %MULTICAST_IPV6,
                    multicast_port = MULTICAST_PORT,
                    "mcast_v6"
                );
            }
            Err(e) => {
                warn!("Failed to setup IPv6 multicast: {}", e);
            }
        }

        if self.socket_v4.is_none() && self.socket_v6.is_none() {
            debug!("mcast_none");
        }

        // Start receiver tasks
        if let Some(socket) = &self.socket_v4 {
            let nodes = self.nodes.clone();
            let socket = socket.clone();
            let local_public_key = self.public_key_b64.clone();
            let node_store_dir = self.node_store_dir.clone();
            tokio::spawn(async move {
                if let Err(e) =
                    Self::receive_loop(socket, nodes, local_public_key, node_store_dir).await
                {
                    error!("IPv4 receive loop error: {}", e);
                }
            });
        }

        if let Some(socket) = &self.socket_v6 {
            let nodes = self.nodes.clone();
            let socket = socket.clone();
            let local_public_key = self.public_key_b64.clone();
            let node_store_dir = self.node_store_dir.clone();
            tokio::spawn(async move {
                if let Err(e) =
                    Self::receive_loop(socket, nodes, local_public_key, node_store_dir).await
                {
                    error!("IPv6 receive loop error: {}", e);
                }
            });
        }

        Ok(())
    }

    /// Setup IPv4 multicast socket
    async fn setup_multicast_v4() -> Result<UdpSocket> {
        let socket = UdpSocket::bind(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            MULTICAST_PORT,
        ))
        .await
        .context("Failed to bind IPv4 socket")?;

        // Join multicast group
        socket
            .join_multicast_v4(MULTICAST_IPV4, Ipv4Addr::UNSPECIFIED)
            .context("Failed to join IPv4 multicast group")?;

        Ok(socket)
    }

    /// Setup IPv6 multicast socket
    async fn setup_multicast_v6() -> Result<UdpSocket> {
        let socket = UdpSocket::bind(SocketAddr::new(
            IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            MULTICAST_PORT,
        ))
        .await
        .context("Failed to bind IPv6 socket")?;

        // Join multicast group on all interfaces (interface index 0)
        socket
            .join_multicast_v6(&MULTICAST_IPV6, 0)
            .context("Failed to join IPv6 multicast group")?;

        Ok(socket)
    }

    /// Receive and process announcements
    #[instrument(
        skip(socket, nodes, local_public_key, node_store_dir),
        fields(buf_size = 65536)
    )]
    async fn receive_loop(
        socket: Arc<UdpSocket>,
        nodes: Arc<RwLock<HashMap<String, Node>>>,
        local_public_key: String,
        node_store_dir: Arc<PathBuf>,
    ) -> Result<()> {
        let mut buf = vec![0u8; 65536];

        loop {
            let (len, addr) = socket
                .recv_from(&mut buf)
                .await
                .context("Failed to receive from socket")?;

            let data = &buf[..len];

            // Parse the announcement
            match serde_json::from_slice::<Announce>(data) {
                Ok(announce) => {
                    // Check if this is our own announcement and skip processing if so
                    if announce.public_key == local_public_key {
                        continue;
                    }
                    debug!(
                        "Received valid announcement from {}: {}",
                        addr, announce.public_key
                    );

                    let node = Node {
                        public_key: announce.public_key.clone(),
                        address: addr,
                        last_seen: std::time::Instant::now(),
                        metadata: announce.metadata.clone(),
                    };

                    let public_key = node.public_key.clone();
                    let address = node.address;
                    let metadata = node.metadata.clone();
                    let is_new = {
                        let mut nodes_map = nodes.write().await;
                        let is_new = !nodes_map.contains_key(&announce.public_key);
                        nodes_map.insert(announce.public_key.clone(), node);
                        is_new
                    };

                    if let Err(e) = persist_announcement(&node_store_dir, &announce, addr) {
                        warn!(
                            public_key = %public_key,
                            address = %address,
                            error = %e,
                            "persist_fail"
                        );
                    }

                    if is_new {
                        info!(
                            public_key = %public_key,
                            address = %address,
                            metadata = ?metadata,
                            "node_seen"
                        );
                    } else {
                        info!(
                            public_key = %public_key,
                            address = %address,
                            metadata = ?metadata,
                            "node_updated"
                        );
                    }
                }
                Err(e) => {
                    warn!("Failed to parse announcement from {}: {}", addr, e);
                }
            }
        }
    }

    /// Send an announcement to the multicast group
    #[instrument(skip(self))]
    pub async fn announce(&self) -> Result<()> {
        self.announce_with_metadata(None).await
    }

    /// Send an announcement with optional metadata
    #[instrument(skip(self, metadata))]
    pub async fn announce_with_metadata(
        &self,
        metadata: Option<HashMap<String, String>>,
    ) -> Result<()> {
        let announce = Announce {
            public_key: self.public_key_b64.clone(),
            metadata,
        };

        let json = serde_json::to_vec(&announce).context("Failed to serialize announcement")?;

        // Send to IPv4 multicast
        if let Some(socket) = &self.socket_v4 {
            let addr = SocketAddr::new(IpAddr::V4(MULTICAST_IPV4), MULTICAST_PORT);
            socket
                .send_to(&json, addr)
                .await
                .context("Failed to send IPv4 announcement")?;
        }

        // Send to IPv6 multicast
        if let Some(socket) = &self.socket_v6 {
            let addr = SocketAddr::new(IpAddr::V6(MULTICAST_IPV6), MULTICAST_PORT);
            socket
                .send_to(&json, addr)
                .await
                .context("Failed to send IPv6 announcement")?;
        }

        Ok(())
    }

    /// Get the public key in base64url encoding
    pub fn public_key_b64(&self) -> &str {
        &self.public_key_b64
    }

    /// Get a snapshot of currently discovered nodes
    #[instrument(skip(self))]
    pub async fn get_nodes(&self) -> HashMap<String, Node> {
        self.nodes.read().await.clone()
    }

    /// Get a specific node by its public key
    #[instrument(skip(self), fields(public_key = %public_key))]
    pub async fn get_node(&self, public_key: &str) -> Option<Node> {
        debug!("Getting node by public key");
        let nodes = self.nodes.read().await;
        let result = nodes.get(public_key).cloned();
        debug!("Node {}found", if result.is_some() { "" } else { "not " });
        result
    }

    fn default_node_store_dir() -> Result<PathBuf> {
        Ok(std::env::current_dir()
            .context("failed to resolve current working directory")?
            .join("lmesh")
            .join("nodes"))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredNode {
    public_key: String,
    address: String,
    announces: Vec<serde_json::Value>,
}

fn persist_announcement(dir: &Path, announce: &Announce, addr: SocketAddr) -> Result<()> {
    fs::create_dir_all(dir).with_context(|| format!("failed to create {}", dir.display()))?;

    let path = node_record_path(dir, &announce.public_key);
    let mut record = if path.exists() {
        let data = fs::read_to_string(&path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        serde_json::from_str::<StoredNode>(&data).unwrap_or_else(|e| {
            warn!(
                path = %path.display(),
                error = %e,
                "replacing invalid lmesh node record"
            );
            StoredNode::new(&announce.public_key, addr)
        })
    } else {
        StoredNode::new(&announce.public_key, addr)
    };

    record.public_key = announce.public_key.clone();
    record.address = addr.to_string();
    record.announces.push(serde_json::json!([
        current_timestamp_millis(),
        announce.public_key.clone(),
        addr.to_string(),
        announce.clone()
    ]));

    if record.announces.len() > MAX_STORED_ANNOUNCES {
        let overflow = record.announces.len() - MAX_STORED_ANNOUNCES;
        record.announces.drain(0..overflow);
    }

    let data = serde_json::to_vec_pretty(&record).context("failed to serialize node record")?;
    let temp_path = path.with_extension("json.tmp");
    fs::write(&temp_path, data)
        .with_context(|| format!("failed to write {}", temp_path.display()))?;
    fs::rename(&temp_path, &path).with_context(|| {
        format!(
            "failed to move {} to {}",
            temp_path.display(),
            path.display()
        )
    })?;

    Ok(())
}

impl StoredNode {
    fn new(public_key: &str, addr: SocketAddr) -> Self {
        Self {
            public_key: public_key.to_string(),
            address: addr.to_string(),
            announces: Vec::new(),
        }
    }
}

fn node_record_path(dir: &Path, public_key: &str) -> PathBuf {
    dir.join(format!("{}.json", public_key_sha(public_key)))
}

fn public_key_sha(public_key: &str) -> String {
    let digest = Sha256::digest(public_key.as_bytes());
    hex_encode(&digest)
}

fn hex_encode(data: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(data.len() * 2);
    for byte in data {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn current_timestamp_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

/// Serializable node info returned by the JSON-lines API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeInfo {
    /// Base64url encoded public key.
    pub public_key: String,
    /// Last seen address.
    pub address: SocketAddr,
    /// Optional metadata from the announcement.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<HashMap<String, String>>,
}

impl From<Node> for NodeInfo {
    fn from(node: Node) -> Self {
        Self {
            public_key: node.public_key,
            address: node.address,
            metadata: node.metadata,
        }
    }
}

/// JSON-lines request methods for lmesh.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "method")]
pub enum Request {
    /// Return all currently discovered nodes.
    #[serde(rename = "nodes", alias = "list_nodes")]
    Nodes,
    /// Return one discovered node by public key.
    #[serde(rename = "get_node")]
    GetNode { public_key: String },
    /// Send a multicast announcement.
    #[serde(rename = "announce")]
    Announce {
        /// Optional metadata to include in the announcement.
        #[serde(default)]
        metadata: Option<HashMap<String, String>>,
    },
    /// Return Linux radio and helper status.
    #[serde(rename = "status")]
    Status,
    /// Return configured local, remote, serial, and future radio adapters.
    #[serde(rename = "radios.list")]
    RadiosList,
    /// Return recently observed neighbors.
    #[serde(rename = "neighbors")]
    Neighbors {
        #[serde(default)]
        seen_within_sec: Option<u64>,
    },
    /// Return lmesh link observations and selected radio paths.
    #[serde(rename = "links.list")]
    LinksList {
        #[serde(default)]
        seen_within_sec: Option<u64>,
    },
    /// Discover peers over one radio or all radios.
    #[serde(rename = "ping", alias = "disc")]
    Ping {
        #[serde(default)]
        radio: Option<String>,
        #[serde(default)]
        wait_ms: Option<u64>,
        #[serde(default)]
        nonce: Option<String>,
    },
    /// Send a mesh payload over the selected radio.
    #[serde(rename = "send")]
    Send {
        #[serde(default)]
        radio: Option<String>,
        #[serde(default)]
        destination: Option<String>,
        payload: String,
    },
    /// List USB serial devices visible to lmesh.
    #[serde(rename = "usb.serial.list")]
    UsbSerialList {
        #[serde(default)]
        handshake: Option<bool>,
    },
    /// Run a generic or firmware-specific USB serial handshake.
    #[serde(rename = "usb.serial.handshake")]
    UsbSerialHandshake {
        #[serde(default)]
        port: Option<String>,
        #[serde(default)]
        profile: Option<String>,
        #[serde(default)]
        timeout_sec: Option<f64>,
    },
    /// Reset an ESP USB serial adapter into bootloader or running firmware mode.
    #[serde(rename = "usb.serial.reset")]
    UsbSerialReset {
        #[serde(default)]
        port: Option<String>,
        #[serde(default)]
        mode: Option<String>,
    },
    /// Start a managed USB serial byte forward on a UDS.
    #[serde(rename = "usb.serial.forward.start", alias = "usb.serial.connect")]
    UsbSerialForwardStart {
        #[serde(default)]
        port: Option<String>,
        #[serde(default)]
        baud: Option<u32>,
        #[serde(default)]
        tcp_port: Option<u16>,
        #[serde(default)]
        tcp_mode: Option<String>,
        #[serde(default)]
        handshake: Option<bool>,
        #[serde(default)]
        dtr: Option<bool>,
        #[serde(default)]
        multi: Option<bool>,
    },
    /// Stop a managed USB serial byte forward.
    #[serde(rename = "usb.serial.forward.stop", alias = "usb.serial.disconnect")]
    UsbSerialForwardStop {
        #[serde(default)]
        port: Option<String>,
    },
    /// List managed USB serial byte forwards.
    #[serde(rename = "usb.serial.forward.list")]
    UsbSerialForwardList,
    /// Run one low-level command against an ESP firmware adapter.
    #[serde(rename = "esp.serial.command")]
    EspSerialCommand {
        #[serde(default)]
        adapter: Option<String>,
        #[serde(default)]
        port: Option<String>,
        command: String,
        #[serde(default)]
        timeout_sec: Option<f64>,
    },
    /// Enter or leave the runtime-only ESP powered/transfer radio mode.
    #[serde(rename = "esp.active")]
    EspActive {
        #[serde(default)]
        adapter: Option<String>,
        #[serde(default)]
        port: Option<String>,
        #[serde(default)]
        active: Option<bool>,
        #[serde(default)]
        active_ms: Option<u32>,
        /// Powered serial gateway that queues an addressed raw-NAN command.
        /// When absent, operate on the directly attached adapter/port.
        #[serde(default)]
        gateway: Option<String>,
        /// Destination Wi-Fi MAC or four-byte suffix for gateway delivery.
        #[serde(default)]
        target: Option<String>,
    },
    /// Return LoRa status from an ESP firmware adapter.
    #[serde(rename = "esp.lora.status")]
    EspLoraStatus {
        #[serde(default)]
        adapter: Option<String>,
        #[serde(default)]
        port: Option<String>,
    },
    /// Return raw Wi-Fi status from an ESP firmware adapter.
    #[serde(rename = "esp.wifi.raw_status")]
    EspWifiRawStatus {
        #[serde(default)]
        adapter: Option<String>,
        #[serde(default)]
        port: Option<String>,
    },
    /// Return power/sleep status from an ESP firmware adapter.
    #[serde(rename = "esp.sleep.status")]
    EspSleepStatus {
        #[serde(default)]
        adapter: Option<String>,
        #[serde(default)]
        port: Option<String>,
    },
    /// Return telemetry counters from an ESP firmware adapter.
    #[serde(rename = "esp.telemetry.stats")]
    EspTelemetryStats {
        #[serde(default)]
        adapter: Option<String>,
        #[serde(default)]
        port: Option<String>,
        #[serde(default)]
        reset: Option<bool>,
    },
    /// Start a background LoRa and host-NAN discovery stability runner.
    #[serde(rename = "esp.stability.start")]
    EspStabilityStart {
        #[serde(default)]
        source: Option<String>,
        #[serde(default)]
        expected: Option<String>,
        #[serde(default)]
        interval_sec: Option<u64>,
        #[serde(default)]
        wait_sec: Option<u64>,
        #[serde(default)]
        cycles: Option<u32>,
        #[serde(default)]
        host_nan: Option<bool>,
    },
    /// Return the latest managed LoRa discovery stability result.
    #[serde(rename = "esp.stability.status")]
    EspStabilityStatus,
    /// Stop the managed LoRa discovery stability runner.
    #[serde(rename = "esp.stability.stop")]
    EspStabilityStop,
    /// Probe ESP ADC pins used for battery detection.
    #[serde(rename = "esp.battery.adc_probe")]
    EspBatteryAdcProbe {
        #[serde(default)]
        adapter: Option<String>,
        #[serde(default)]
        port: Option<String>,
        #[serde(default)]
        adc1_pins: Option<String>,
        #[serde(default)]
        count: Option<u32>,
    },
    /// Record an explicit steering hint for a peer.
    #[serde(rename = "link.steer")]
    LinkSteer {
        #[serde(default)]
        node: Option<String>,
        #[serde(default)]
        radio: Option<String>,
        #[serde(default)]
        reason: Option<String>,
    },
    /// Fan out a discovery ping over one medium or all configured media.
    #[serde(rename = "discovery.ping")]
    DiscoveryPing {
        #[serde(default)]
        medium: Option<String>,
    },
    /// Return recent radio/backend message history.
    #[serde(rename = "messages.history")]
    MessagesHistory {
        #[serde(default)]
        keys: Option<String>,
        #[serde(default)]
        limit: Option<usize>,
    },
    /// Listen for ESP32-compatible raw DMesh Wi-Fi action frames.
    #[serde(rename = "wifi.raw.listen")]
    WifiRawListen {
        #[serde(default)]
        iface: Option<String>,
        #[serde(default)]
        ctrl_dir: Option<String>,
        #[serde(default)]
        channel: Option<u8>,
        #[serde(default)]
        listen_sec: Option<u64>,
        #[serde(default)]
        rx_variant: Option<String>,
    },
    /// Send an ESP32-compatible raw DMesh Wi-Fi action frame.
    #[serde(rename = "wifi.raw.send")]
    WifiRawSend {
        #[serde(default)]
        iface: Option<String>,
        #[serde(default)]
        ctrl_dir: Option<String>,
        #[serde(default)]
        channel: Option<u8>,
        #[serde(default)]
        listen_sec: Option<u64>,
        #[serde(default)]
        destination: Option<String>,
        #[serde(default)]
        source: Option<String>,
        #[serde(default)]
        tx_variant: Option<String>,
        #[serde(default)]
        tx_duration_ms: Option<u32>,
        payload: String,
    },
    /// Send a raw Wi-Fi DMesh status ping and collect replies.
    #[serde(rename = "wifi.raw.ping")]
    WifiRawPing {
        #[serde(default)]
        iface: Option<String>,
        #[serde(default)]
        ctrl_dir: Option<String>,
        #[serde(default)]
        channel: Option<u8>,
        #[serde(default)]
        listen_sec: Option<u64>,
        #[serde(default)]
        wait_ms: Option<u64>,
        #[serde(default)]
        nonce: Option<String>,
    },
    /// Listen for DMesh Ethernet frames on the normal AP/STA netdev path.
    #[serde(rename = "wifi.data.listen")]
    WifiDataListen {
        #[serde(default)]
        iface: Option<String>,
        #[serde(default)]
        listen_sec: Option<u64>,
    },
    /// Send a DMesh Ethernet frame on the normal AP/STA netdev path.
    #[serde(rename = "wifi.data.send")]
    WifiDataSend {
        #[serde(default)]
        iface: Option<String>,
        #[serde(default)]
        destination: Option<String>,
        payload: String,
    },
    /// Capture Wi-Fi management frames from a monitor interface.
    #[serde(rename = "wifi.mgmt.capture")]
    WifiMgmtCapture {
        #[serde(default)]
        iface: Option<String>,
        #[serde(default)]
        channel: Option<u8>,
        #[serde(default)]
        capture_ms: Option<u64>,
        #[serde(default)]
        max_frames: Option<usize>,
        #[serde(default)]
        active: Option<bool>,
    },
    /// Start an open AP on the shared DMesh channel.
    #[serde(rename = "wifi.ap.start_open")]
    WifiApStartOpen {
        #[serde(default)]
        iface: Option<String>,
        #[serde(default)]
        ssid: Option<String>,
    },
    /// Stop AP operation.
    #[serde(rename = "wifi.ap.stop")]
    WifiApStop {
        #[serde(default)]
        iface: Option<String>,
    },
    /// Return AP defaults and station metrics where available.
    #[serde(rename = "wifi.ap.status")]
    WifiApStatus {
        #[serde(default)]
        iface: Option<String>,
    },
    /// Return associated station metrics for an AP interface.
    #[serde(rename = "wifi.ap.stations")]
    WifiApStations {
        #[serde(default)]
        iface: Option<String>,
    },
    /// Experimentally add a station without a normal auth/assoc exchange.
    #[serde(rename = "wifi.ap.station.add")]
    WifiApStationAdd {
        #[serde(default)]
        iface: Option<String>,
        mac: String,
        #[serde(default)]
        aid: Option<u16>,
    },
    /// Scan for nearby Wi-Fi BSS entries.
    #[serde(rename = "wifi.scan")]
    WifiScan {
        #[serde(default)]
        iface: Option<String>,
        #[serde(default)]
        ssid: Option<String>,
    },
    /// Join an open AP on the shared DMesh channel.
    #[serde(rename = "wifi.sta.join_open")]
    WifiStaJoinOpen {
        #[serde(default)]
        iface: Option<String>,
        ssid: String,
    },
    /// Return station-mode association metrics.
    #[serde(rename = "wifi.sta.status")]
    WifiStaStatus {
        #[serde(default)]
        iface: Option<String>,
    },
    /// Request a BLE scan through raw Linux HCI sockets.
    #[serde(rename = "ble.scan")]
    BleScan {
        #[serde(default)]
        dev_id: Option<u16>,
        #[serde(default)]
        reason: Option<String>,
        #[serde(default)]
        scan_ms: Option<u64>,
    },
    /// Enable or disable BLE advertising through raw Linux HCI sockets.
    #[serde(rename = "ble.adv")]
    BleAdv {
        #[serde(default)]
        dev_id: Option<u16>,
        #[serde(default)]
        on: Option<bool>,
        #[serde(default)]
        payload: Option<String>,
    },
    /// Probe/attach NAN through wpa_supplicant control.
    #[serde(rename = "wifi.nan.start")]
    WifiNanStart {
        #[serde(default)]
        iface: Option<String>,
        #[serde(default)]
        ctrl_dir: Option<String>,
    },
    /// Return NAN status, capabilities, and recent control events.
    #[serde(rename = "wifi.nan.status")]
    WifiNanStatus {
        #[serde(default)]
        iface: Option<String>,
        #[serde(default)]
        ctrl_dir: Option<String>,
        #[serde(default)]
        events_ms: Option<u64>,
    },
    /// Apply the default DMesh NAN configuration and start publish/subscribe.
    #[serde(rename = "wifi.nan.default")]
    WifiNanDefault {
        #[serde(default)]
        iface: Option<String>,
        #[serde(default)]
        ctrl_dir: Option<String>,
        #[serde(default)]
        service_name: Option<String>,
        #[serde(default)]
        ttl: Option<u32>,
    },
    /// Stop NAN publish/subscribe sessions through wpa_supplicant control.
    #[serde(rename = "wifi.nan.stop")]
    WifiNanStop {
        #[serde(default)]
        iface: Option<String>,
        #[serde(default)]
        ctrl_dir: Option<String>,
    },
    /// Start NAN publish through wpa_supplicant control with optional custom SSI.
    #[serde(rename = "wifi.nan.publish")]
    WifiNanPublish {
        #[serde(default)]
        iface: Option<String>,
        #[serde(default)]
        ctrl_dir: Option<String>,
        #[serde(default)]
        service_name: Option<String>,
        #[serde(default)]
        ssi_hex: Option<String>,
        #[serde(default)]
        ttl: Option<u32>,
        #[serde(default)]
        freq: Option<u32>,
        #[serde(default)]
        srv_proto_type: Option<u8>,
    },
    /// Start NAN subscribe through wpa_supplicant control with optional custom SSI.
    #[serde(rename = "wifi.nan.subscribe")]
    WifiNanSubscribe {
        #[serde(default)]
        iface: Option<String>,
        #[serde(default)]
        ctrl_dir: Option<String>,
        #[serde(default)]
        service_name: Option<String>,
        #[serde(default)]
        ssi_hex: Option<String>,
        #[serde(default)]
        ttl: Option<u32>,
        #[serde(default)]
        freq: Option<u32>,
        #[serde(default)]
        active: Option<bool>,
        #[serde(default)]
        srv_proto_type: Option<u8>,
    },
    /// Send one NAN follow-up through wpa_supplicant control.
    #[serde(rename = "wifi.nan.transmit")]
    WifiNanTransmit {
        #[serde(default)]
        iface: Option<String>,
        #[serde(default)]
        ctrl_dir: Option<String>,
        handle: u32,
        address: String,
        #[serde(default)]
        req_instance_id: Option<u32>,
        #[serde(default)]
        ssi_hex: Option<String>,
        #[serde(default)]
        payload: Option<String>,
        #[serde(default)]
        cookie: Option<u32>,
    },
    /// Attach to the WPA control socket and collect NAN events.
    #[serde(rename = "wifi.nan.events")]
    WifiNanEvents {
        #[serde(default)]
        iface: Option<String>,
        #[serde(default)]
        ctrl_dir: Option<String>,
        #[serde(default)]
        wait_ms: Option<u64>,
        #[serde(default)]
        max_events: Option<usize>,
    },
    /// Probe NAN service-info and follow-up payload sizes through wpa_supplicant.
    #[serde(rename = "wifi.nan.size_probe")]
    WifiNanSizeProbe {
        #[serde(default)]
        iface: Option<String>,
        #[serde(default)]
        ctrl_dir: Option<String>,
        #[serde(default)]
        sizes: Option<String>,
        #[serde(default)]
        mode: Option<String>,
    },
    /// Start NAN publish through wpa_supplicant control.
    #[serde(rename = "wifi.nan.adv")]
    WifiNanAdv {
        #[serde(default)]
        iface: Option<String>,
        #[serde(default)]
        ctrl_dir: Option<String>,
    },
    /// Start NAN subscribe through wpa_supplicant control.
    #[serde(rename = "wifi.nan.sub")]
    WifiNanSub {
        #[serde(default)]
        iface: Option<String>,
        #[serde(default)]
        ctrl_dir: Option<String>,
    },
    /// Send a NAN follow-up ping through wpa_supplicant control.
    #[serde(rename = "wifi.nan.ping")]
    WifiNanPing {
        #[serde(default)]
        iface: Option<String>,
        #[serde(default)]
        ctrl_dir: Option<String>,
        #[serde(default)]
        peer: Option<String>,
        #[serde(default)]
        payload: Option<String>,
    },
}

/// Reusable lmesh command service.
pub struct LmeshService {
    discovery: Arc<LocalDiscovery>,
    radio: radio::RadioService,
}

impl LmeshService {
    /// Create a service around an initialized discovery instance.
    pub fn new(discovery: Arc<LocalDiscovery>) -> Self {
        Self {
            discovery,
            radio: radio::RadioService::from_environment(),
        }
    }

    /// Start the default host NAN control-plane setup.
    pub fn start_default_nan(&self) -> serde_json::Value {
        self.radio.nan_default(None, None, None, None)
    }

    /// Report whether the configured WPA control socket is available for NAN startup.
    pub fn default_nan_control_socket_exists(&self) -> bool {
        self.radio.default_nan_control_socket_exists()
    }

    /// Start the default open channel-6 access point on the supplied interface.
    pub fn start_default_open_ap(&self, iface: String) -> serde_json::Value {
        self.radio.wifi_ap_start_open(Some(iface), None)
    }

    /// Collect and record NAN events from the default host control socket.
    pub fn collect_default_nan_events(&self, wait_ms: u64, max_events: usize) -> serde_json::Value {
        self.radio
            .nan_events(None, None, Some(wait_ms), Some(max_events))
    }

    /// Return the local public key used for announcements.
    pub fn public_key_b64(&self) -> &str {
        self.discovery.public_key_b64()
    }

    /// Handle a single JSON-lines request.
    pub async fn handle_request(&self, request: Request) -> mesh::protocol::Response {
        match request {
            Request::Nodes => {
                let nodes = self
                    .discovery
                    .get_nodes()
                    .await
                    .into_values()
                    .map(NodeInfo::from)
                    .collect::<Vec<_>>();
                mesh::protocol::Response::ok_with_data(serde_json::json!(nodes))
            }
            Request::GetNode { public_key } => match self.discovery.get_node(&public_key).await {
                Some(node) => {
                    mesh::protocol::Response::ok_with_data(serde_json::json!(NodeInfo::from(node)))
                }
                None => mesh::protocol::Response::err("node not found"),
            },
            Request::Announce { metadata } => {
                match self.discovery.announce_with_metadata(metadata).await {
                    Ok(()) => mesh::protocol::Response::ok(),
                    Err(e) => mesh::protocol::Response::err(e.to_string()),
                }
            }
            Request::Status => mesh::protocol::Response::ok_with_data(self.radio.status()),
            Request::RadiosList => mesh::protocol::Response::ok_with_data(self.radio.list_radios()),
            Request::Neighbors { seen_within_sec } => {
                mesh::protocol::Response::ok_with_data(self.radio.neighbors(seen_within_sec))
            }
            Request::LinksList { seen_within_sec } => {
                mesh::protocol::Response::ok_with_data(self.radio.links_list(seen_within_sec))
            }
            Request::Ping {
                radio,
                wait_ms,
                nonce,
            } => mesh::protocol::Response::ok_with_data(self.radio.ping(radio, wait_ms, nonce)),
            Request::Send {
                radio,
                destination,
                payload,
            } => {
                mesh::protocol::Response::ok_with_data(self.radio.send(radio, payload, destination))
            }
            Request::UsbSerialList { handshake } => {
                mesh::protocol::Response::ok_with_data(self.radio.usb_serial_list(handshake))
            }
            Request::UsbSerialHandshake {
                port,
                profile,
                timeout_sec,
            } => mesh::protocol::Response::ok_with_data(self.radio.usb_serial_handshake(
                port,
                profile,
                timeout_sec,
            )),
            Request::UsbSerialReset { port, mode } => {
                mesh::protocol::Response::ok_with_data(self.radio.usb_serial_reset(port, mode))
            }
            Request::UsbSerialForwardStart {
                port,
                baud,
                tcp_port,
                tcp_mode,
                handshake,
                dtr,
                multi,
            } => mesh::protocol::Response::ok_with_data(
                self.radio
                    .serial_forward_start(port, baud, tcp_port, tcp_mode, handshake, dtr, multi),
            ),
            Request::UsbSerialForwardStop { port } => {
                mesh::protocol::Response::ok_with_data(self.radio.serial_forward_stop(port))
            }
            Request::UsbSerialForwardList => {
                mesh::protocol::Response::ok_with_data(self.radio.serial_forward_list())
            }
            Request::EspSerialCommand {
                adapter,
                port,
                command,
                timeout_sec,
            } => mesh::protocol::Response::ok_with_data(self.radio.esp_serial_command(
                adapter,
                port,
                command,
                timeout_sec,
            )),
            Request::EspActive {
                adapter,
                port,
                active,
                active_ms,
                gateway,
                target,
            } => mesh::protocol::Response::ok_with_data(
                self.radio
                    .esp_active(adapter, port, active, active_ms, gateway, target),
            ),
            Request::EspLoraStatus { adapter, port } => {
                mesh::protocol::Response::ok_with_data(self.radio.esp_lora_status(adapter, port))
            }
            Request::EspWifiRawStatus { adapter, port } => mesh::protocol::Response::ok_with_data(
                self.radio.esp_wifi_raw_status(adapter, port),
            ),
            Request::EspSleepStatus { adapter, port } => {
                mesh::protocol::Response::ok_with_data(self.radio.esp_sleep_status(adapter, port))
            }
            Request::EspTelemetryStats {
                adapter,
                port,
                reset,
            } => mesh::protocol::Response::ok_with_data(
                self.radio.esp_telemetry_stats(adapter, port, reset),
            ),
            Request::EspStabilityStart {
                source,
                expected,
                interval_sec,
                wait_sec,
                cycles,
                host_nan,
            } => mesh::protocol::Response::ok_with_data(self.radio.stability_start(
                source,
                expected,
                interval_sec,
                wait_sec,
                cycles,
                host_nan,
            )),
            Request::EspStabilityStatus => {
                mesh::protocol::Response::ok_with_data(self.radio.stability_status())
            }
            Request::EspStabilityStop => {
                mesh::protocol::Response::ok_with_data(self.radio.stability_stop())
            }
            Request::EspBatteryAdcProbe {
                adapter,
                port,
                adc1_pins,
                count,
            } => mesh::protocol::Response::ok_with_data(
                self.radio
                    .esp_battery_adc_probe(adapter, port, adc1_pins, count),
            ),
            Request::LinkSteer {
                node,
                radio,
                reason,
            } => mesh::protocol::Response::ok_with_data(self.radio.link_steer(node, radio, reason)),
            Request::DiscoveryPing { medium } => {
                mesh::protocol::Response::ok_with_data(self.radio.discovery_ping(medium))
            }
            Request::MessagesHistory { keys, limit } => {
                mesh::protocol::Response::ok_with_data(self.radio.history(keys, limit))
            }
            Request::WifiRawListen {
                iface,
                ctrl_dir,
                channel,
                listen_sec,
                rx_variant,
            } => mesh::protocol::Response::ok_with_data(
                self.radio
                    .wifi_raw_listen(iface, ctrl_dir, channel, listen_sec, rx_variant),
            ),
            Request::WifiRawSend {
                iface,
                ctrl_dir,
                channel,
                listen_sec,
                destination,
                source,
                tx_variant,
                tx_duration_ms,
                payload,
            } => mesh::protocol::Response::ok_with_data(self.radio.wifi_raw_send(
                iface,
                ctrl_dir,
                channel,
                listen_sec,
                destination,
                source,
                tx_variant,
                tx_duration_ms,
                payload,
            )),
            Request::WifiRawPing {
                iface,
                ctrl_dir,
                channel,
                listen_sec,
                wait_ms,
                nonce,
            } => mesh::protocol::Response::ok_with_data(
                self.radio
                    .wifi_raw_ping(iface, ctrl_dir, channel, listen_sec, wait_ms, nonce),
            ),
            Request::WifiDataListen { iface, listen_sec } => {
                mesh::protocol::Response::ok_with_data(
                    self.radio.wifi_data_listen(iface, listen_sec),
                )
            }
            Request::WifiDataSend {
                iface,
                destination,
                payload,
            } => mesh::protocol::Response::ok_with_data(self.radio.wifi_data_send(
                iface,
                destination,
                payload,
            )),
            Request::WifiMgmtCapture {
                iface,
                channel,
                capture_ms,
                max_frames,
                active,
            } => match self
                .radio
                .wifi_mgmt_capture(iface, channel, capture_ms, max_frames, active)
            {
                Ok(value) => mesh::protocol::Response::ok_with_data(value),
                Err(error) => {
                    mesh::protocol::Response::err(format!("wifi.mgmt.capture failed: {error:#}"))
                }
            },
            Request::WifiApStartOpen { iface, ssid } => {
                mesh::protocol::Response::ok_with_data(self.radio.wifi_ap_start_open(iface, ssid))
            }
            Request::WifiApStop { iface } => {
                mesh::protocol::Response::ok_with_data(self.radio.wifi_ap_stop(iface))
            }
            Request::WifiApStatus { iface } => {
                mesh::protocol::Response::ok_with_data(self.radio.wifi_ap_status(iface))
            }
            Request::WifiApStations { iface } => {
                mesh::protocol::Response::ok_with_data(self.radio.wifi_ap_stations(iface))
            }
            Request::WifiApStationAdd { iface, mac, aid } => {
                mesh::protocol::Response::ok_with_data(
                    self.radio.wifi_ap_station_add(iface, mac, aid),
                )
            }
            Request::WifiScan { iface, ssid } => {
                mesh::protocol::Response::ok_with_data(self.radio.wifi_scan(iface, ssid))
            }
            Request::WifiStaJoinOpen { iface, ssid } => {
                mesh::protocol::Response::ok_with_data(self.radio.wifi_sta_join_open(iface, ssid))
            }
            Request::WifiStaStatus { iface } => {
                mesh::protocol::Response::ok_with_data(self.radio.wifi_sta_status(iface))
            }
            Request::BleScan {
                dev_id,
                reason,
                scan_ms,
            } => match self.radio.ble_scan(dev_id, reason, scan_ms) {
                Ok(data) => mesh::protocol::Response::ok_with_data(data),
                Err(e) => mesh::protocol::Response::err(e.to_string()),
            },
            Request::BleAdv {
                dev_id,
                on,
                payload,
            } => match self.radio.ble_adv(dev_id, on, payload) {
                Ok(data) => mesh::protocol::Response::ok_with_data(data),
                Err(e) => mesh::protocol::Response::err(e.to_string()),
            },
            Request::WifiNanStart { iface, ctrl_dir } => {
                mesh::protocol::Response::ok_with_data(self.radio.nan_start(iface, ctrl_dir))
            }
            Request::WifiNanStatus {
                iface,
                ctrl_dir,
                events_ms,
            } => mesh::protocol::Response::ok_with_data(
                self.radio.nan_status(iface, ctrl_dir, events_ms),
            ),
            Request::WifiNanDefault {
                iface,
                ctrl_dir,
                service_name,
                ttl,
            } => mesh::protocol::Response::ok_with_data(self.radio.nan_default(
                iface,
                ctrl_dir,
                service_name,
                ttl,
            )),
            Request::WifiNanStop { iface, ctrl_dir } => {
                mesh::protocol::Response::ok_with_data(self.radio.nan_stop(iface, ctrl_dir))
            }
            Request::WifiNanPublish {
                iface,
                ctrl_dir,
                service_name,
                ssi_hex,
                ttl,
                freq,
                srv_proto_type,
            } => mesh::protocol::Response::ok_with_data(self.radio.nan_publish(
                iface,
                ctrl_dir,
                service_name,
                ssi_hex,
                ttl,
                freq,
                srv_proto_type,
            )),
            Request::WifiNanSubscribe {
                iface,
                ctrl_dir,
                service_name,
                ssi_hex,
                ttl,
                freq,
                active,
                srv_proto_type,
            } => mesh::protocol::Response::ok_with_data(self.radio.nan_subscribe(
                iface,
                ctrl_dir,
                service_name,
                ssi_hex,
                ttl,
                freq,
                active,
                srv_proto_type,
            )),
            Request::WifiNanTransmit {
                iface,
                ctrl_dir,
                handle,
                address,
                req_instance_id,
                ssi_hex,
                payload,
                cookie,
            } => mesh::protocol::Response::ok_with_data(self.radio.nan_transmit(
                iface,
                ctrl_dir,
                handle,
                address,
                req_instance_id,
                ssi_hex,
                payload,
                cookie,
            )),
            Request::WifiNanEvents {
                iface,
                ctrl_dir,
                wait_ms,
                max_events,
            } => mesh::protocol::Response::ok_with_data(
                self.radio.nan_events(iface, ctrl_dir, wait_ms, max_events),
            ),
            Request::WifiNanSizeProbe {
                iface,
                ctrl_dir,
                sizes,
                mode,
            } => mesh::protocol::Response::ok_with_data(
                self.radio.nan_size_probe(iface, ctrl_dir, sizes, mode),
            ),
            Request::WifiNanAdv { iface, ctrl_dir } => match self.radio.nan_adv(iface, ctrl_dir) {
                Ok(data) => mesh::protocol::Response::ok_with_data(data),
                Err(e) => mesh::protocol::Response::err(e.to_string()),
            },
            Request::WifiNanSub { iface, ctrl_dir } => {
                mesh::protocol::Response::ok_with_data(self.radio.nan_sub(iface, ctrl_dir))
            }
            Request::WifiNanPing {
                iface,
                ctrl_dir,
                peer,
                payload,
            } => match self.radio.nan_ping(iface, ctrl_dir, peer, payload) {
                Ok(data) => mesh::protocol::Response::ok_with_data(data),
                Err(e) => mesh::protocol::Response::err(e.to_string()),
            },
        }
    }
}

/// Encode bytes as base64url (RFC 4648)
fn base64_url_encode(data: &[u8]) -> String {
    // Simple base64url encoding
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut result = Vec::new();

    for chunk in data.chunks(3) {
        let mut buf = [0u8; 3];
        for (i, &b) in chunk.iter().enumerate() {
            buf[i] = b;
        }

        let b1 = buf[0] >> 2;
        let b2 = ((buf[0] & 0x03) << 4) | (buf[1] >> 4);
        let b3 = ((buf[1] & 0x0f) << 2) | (buf[2] >> 6);
        let b4 = buf[2] & 0x3f;

        result.push(alphabet[b1 as usize]);
        result.push(alphabet[b2 as usize]);

        if chunk.len() > 1 {
            result.push(alphabet[b3 as usize]);
        }
        if chunk.len() > 2 {
            result.push(alphabet[b4 as usize]);
        }
    }

    String::from_utf8(result).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_DIR_COUNTER: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn test_base64_url_encode() {
        let data = b"hello world";
        let encoded = base64_url_encode(data);
        assert!(!encoded.contains('+'));
        assert!(!encoded.contains('/'));
        assert!(!encoded.contains('='));
    }

    #[test]
    fn test_persist_announcement_caps_history_and_updates_address() {
        let dir = unique_test_dir();
        let announce = Announce {
            public_key: "test_key_12345".to_string(),
            metadata: Some(HashMap::from([(
                "version".to_string(),
                "1.0.0".to_string(),
            )])),
        };

        for port in 10_000..10_017 {
            let addr = SocketAddr::from(([127, 0, 0, 1], port));
            persist_announcement(&dir, &announce, addr).unwrap();
        }

        let path = node_record_path(&dir, &announce.public_key);
        let record: StoredNode = serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap();
        assert_eq!(record.public_key, announce.public_key);
        assert_eq!(record.address, "127.0.0.1:10016");
        assert_eq!(record.announces.len(), MAX_STORED_ANNOUNCES);
        assert_eq!(record.announces[0][2], "127.0.0.1:10001");
        assert_eq!(record.announces[15][2], "127.0.0.1:10016");

        fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn test_local_discovery_creation() {
        let discovery = LocalDiscovery::new(None).await.unwrap();
        assert!(!discovery.public_key_b64().is_empty());
    }

    #[tokio::test]
    async fn test_announce_serialization() {
        let mut metadata = HashMap::new();
        metadata.insert("version".to_string(), "1.0.0".to_string());

        let announce = Announce {
            public_key: "test_key_12345".to_string(),
            metadata: Some(metadata),
        };

        let json = serde_json::to_string(&announce).unwrap();
        assert!(json.contains("test_key_12345"));
        assert!(json.contains("version"));
        assert!(json.contains("1.0.0"));

        // Test deserialization
        let parsed: Announce = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.public_key, "test_key_12345");
        assert!(parsed.metadata.is_some());
    }

    #[tokio::test]
    async fn test_local_discovery_node_management() {
        let discovery = LocalDiscovery::new(None).await.unwrap();

        // Initially, no nodes should be discovered
        let nodes = discovery.get_nodes().await;
        assert_eq!(nodes.len(), 0);

        // Get a non-existent node
        let node = discovery.get_node("non_existent_key").await;
        assert!(node.is_none());
    }

    #[tokio::test]
    async fn test_local_discovery_full_lifecycle() {
        // Create a discovery instance
        let mut discovery = LocalDiscovery::new(None).await.unwrap();
        let key = discovery.public_key_b64().to_string();

        tracing::info!("Discovery key: {}", key);

        // Start the discovery service
        // Note: This may fail in test environments due to permission issues
        // or if another test is already using the multicast port
        if let Err(e) = discovery.start().await {
            tracing::warn!("Could not start discovery in test: {}", e);
            // This is acceptable in test environments where multicast may not be available
            return;
        }

        // Wait a moment for sockets to be ready
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // Send an announcement
        if let Err(e) = discovery.announce().await {
            tracing::warn!("Could not send announcement in test: {}", e);
            return;
        }

        // Wait for the announcement to be processed
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

        // Check if we received our own announcement (multicast loopback)
        let nodes = discovery.get_nodes().await;
        tracing::info!("Discovery received {} nodes", nodes.len());

        // In some systems, multicast loopback is enabled and we'll receive our own announcement
        // In others, it may not work in test environments
        // So we don't assert a specific count, just that the test completes successfully
    }

    fn unique_test_dir() -> PathBuf {
        let counter = TEST_DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("lmesh-test-{}-{}", std::process::id(), counter))
    }

    #[test]
    fn default_node_store_dir_is_cwd_relative() {
        let cwd = std::env::current_dir().unwrap();
        assert_eq!(
            LocalDiscovery::default_node_store_dir().unwrap(),
            cwd.join("lmesh").join("nodes")
        );
    }
}
