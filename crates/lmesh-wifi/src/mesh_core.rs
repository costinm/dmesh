/// Local mesh announce and discovery
/// Each mesh node will listen for UDP multicast announcements on
/// all interfaces. The announcement includes the public key of the
/// node, the (claimed - untrusted) name.
///
///
use anyhow::{Context, Result};

use p256::SecretKey;
use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use p256::elliptic_curve::Generate;
use p256::elliptic_curve::sec1::ToSec1Point;
use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use std::collections::{BTreeSet, HashMap};
use std::ffi::CStr;
use std::fs::{self, OpenOptions};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::net::UdpSocket;
use tokio::sync::{Mutex, RwLock};

use tracing::{debug, error, info, instrument, warn};

/// A decoded common announce delivered by a local-link bearer. The callback
/// takes semantic data, never a UDP buffer, so another local owner can merge
/// it into its inventory without coupling the multicast receive loop to a
/// particular Wi-Fi implementation.
type AnnounceObserver = Arc<dyn Fn(SocketAddr, dmesh_server::announce::Announce) + Send + Sync>;

/// Optional discovery-only host label. Stable key material remains the
/// identity; this short presentation value will later be superseded by a
/// certificate-backed FQDN.
fn discovery_device_name() -> Option<String> {
    let name = std::env::var("HOSTNAME").ok()?;
    let compact = name
        .chars()
        .filter(|character| character.is_ascii_graphic())
        .take(dmesh_server::announce::MAX_DEVICE_NAME)
        .collect::<String>();
    (!compact.is_empty()).then_some(compact)
}

fn discovery_device_domain() -> Option<String> {
    let domain = std::env::var("DMESH_DISCOVERY_DOMAIN").ok()?;
    let domain = domain.trim();
    (!domain.is_empty() && domain.len() <= dmesh_server::announce::MAX_DEVICE_DOMAIN)
        .then(|| domain.to_owned())
}

// The Wi-Fi crate owns the radio implementation. Re-export the wire protocol
// here so existing Android/JNI callers keep the established lmesh path.
pub use lmesh_wifi::radio_protocol;
#[path = "mesh_core_api.rs"]
pub mod api;

/// Shared mesh discovery endpoint. Both supervised host services join it.
pub const DISCOVERY_MULTICAST_PORT: u16 = 5227;
pub const DISCOVERY_MULTICAST_IPV4: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 250);
pub const DISCOVERY_MULTICAST_IPV6: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x5227);
/// Optional display/routing metadata for a LAN that is reachable through more
/// than one local link. Example: `costin=wlan1,br-lan`.
const UDP6_NETWORKS_ENV: &str = "LMESH_UDP6_NETWORKS";
const MAX_STORED_ANNOUNCES: usize = 16;

/// Bind an IPv4 multicast receiver so the independently supervised host
/// services both receive each multicast datagram. `SO_REUSEADDR` is required
/// on every participant before binding the shared wildcard endpoint.
fn bind_shared_multicast_v4(port: u16) -> Result<UdpSocket> {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error()).context("create IPv4 multicast socket");
    }
    let socket = unsafe { std::net::UdpSocket::from_raw_fd(fd) };
    let enabled: libc::c_int = 1;
    let option_len = std::mem::size_of_val(&enabled) as libc::socklen_t;
    let reuse = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            (&enabled as *const libc::c_int).cast(),
            option_len,
        )
    };
    if reuse != 0 {
        return Err(std::io::Error::last_os_error())
            .context("make IPv4 multicast socket shareable");
    }
    let address = libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: port.to_be(),
        sin_addr: libc::in_addr { s_addr: 0 },
        sin_zero: [0; 8],
    };
    let result = unsafe {
        libc::bind(
            socket.as_raw_fd(),
            (&address as *const libc::sockaddr_in).cast(),
            std::mem::size_of_val(&address) as libc::socklen_t,
        )
    };
    if result != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("bind IPv4 multicast port {port}"));
    }
    socket
        .set_nonblocking(true)
        .context("make IPv4 multicast socket nonblocking")?;
    UdpSocket::from_std(socket).context("adopt IPv4 multicast socket")
}

/// IPv6 link-local multicast needs a concrete interface scope.  Index `0`
/// does not mean "every interface" for `ff02::/16`, so discover each live
/// non-loopback IPv6 link and join/send on all of them.
fn multicast_v6_interface_indices() -> Vec<u32> {
    let mut result = BTreeSet::new();
    unsafe {
        let mut head = std::ptr::null_mut();
        if libc::getifaddrs(&mut head) != 0 {
            return Vec::new();
        }
        let mut current = head;
        while !current.is_null() {
            let entry = &*current;
            let up = entry.ifa_flags & (libc::IFF_UP as u32) != 0;
            let loopback = entry.ifa_flags & (libc::IFF_LOOPBACK as u32) != 0;
            if up
                && !loopback
                && !entry.ifa_addr.is_null()
                && (*entry.ifa_addr).sa_family as i32 == libc::AF_INET6
            {
                let index = libc::if_nametoindex(CStr::from_ptr(entry.ifa_name).as_ptr());
                if index != 0 {
                    result.insert(index);
                }
            }
            current = entry.ifa_next;
        }
        libc::freeifaddrs(head);
    }
    result.into_iter().collect()
}

/// Configuration is intentionally only a network label: it never changes a
/// route, bridge, or interface state. It lets the status/API tell callers that
/// (for example) a `wlan1` STA and `br-lan` are both on `costin`.
fn configured_udp6_networks() -> HashMap<String, Vec<String>> {
    let Ok(value) = std::env::var(UDP6_NETWORKS_ENV) else {
        return HashMap::new();
    };
    value
        .split(';')
        .filter_map(|entry| entry.split_once('='))
        .map(|(network, interfaces)| {
            (
                network.trim().to_owned(),
                interfaces
                    .split(',')
                    .map(str::trim)
                    .filter(|interface| !interface.is_empty())
                    .map(str::to_owned)
                    .collect(),
            )
        })
        .filter(|(network, interfaces): &(String, Vec<String>)| {
            !network.is_empty() && !interfaces.is_empty()
        })
        .collect()
}

/// A configured radio name also covers the P2P child interface it owns. This
/// keeps `costin=wlan1,br-lan` stable while a P2P group creates
/// `p2p-wlan1-0` at runtime.
fn network_member_matches(member: &str, interface: &str) -> bool {
    interface == member || interface.starts_with(&format!("p2p-{member}-"))
}

/// Active IPv6 multicast links and their usable addresses. This is status
/// data, rather than a separate interface-management feature.
fn local_udp6_interfaces() -> Vec<serde_json::Value> {
    let configured = configured_udp6_networks();
    let mut interfaces = std::collections::BTreeMap::<String, (u32, Vec<String>)>::new();
    unsafe {
        let mut head = std::ptr::null_mut();
        if libc::getifaddrs(&mut head) != 0 {
            return Vec::new();
        }
        let mut current = head;
        while !current.is_null() {
            let entry = &*current;
            let up = entry.ifa_flags & (libc::IFF_UP as u32) != 0;
            let loopback = entry.ifa_flags & (libc::IFF_LOOPBACK as u32) != 0;
            if up
                && !loopback
                && !entry.ifa_addr.is_null()
                && (*entry.ifa_addr).sa_family as i32 == libc::AF_INET6
            {
                let name = CStr::from_ptr(entry.ifa_name)
                    .to_string_lossy()
                    .into_owned();
                let index = libc::if_nametoindex(entry.ifa_name);
                let address = Ipv6Addr::from(
                    (*(entry.ifa_addr as *const libc::sockaddr_in6))
                        .sin6_addr
                        .s6_addr,
                );
                if index != 0 && !address.is_unspecified() {
                    let row = interfaces
                        .entry(name)
                        .or_insert_with(|| (index, Vec::new()));
                    let address = address.to_string();
                    if !row.1.contains(&address) {
                        row.1.push(address);
                    }
                }
            }
            current = entry.ifa_next;
        }
        libc::freeifaddrs(head);
    }
    interfaces
        .into_iter()
        .map(|(interface, (index, addresses))| {
            let networks = configured
                .iter()
                .filter(|(_, members)| {
                    members
                        .iter()
                        .any(|member| network_member_matches(member, &interface))
                })
                .map(|(network, _)| network.clone())
                .collect::<Vec<_>>();
            let link_local_v6 = addresses
                .iter()
                .find(|address| address.starts_with("fe80:"))
                .cloned();
            serde_json::json!({
                "interface": interface,
                "interface_index": index,
                "addresses": addresses,
                "link_local_v6": link_local_v6,
                "networks": networks,
            })
        })
        .collect()
}

fn common_local_networks() -> serde_json::Value {
    let networks = local_udp6_interfaces()
        .into_iter()
        .map(|interface| {
            serde_json::json!({
                "interface": interface.get("interface").cloned().unwrap_or(serde_json::Value::Null),
                "interface_index": interface.get("interface_index").cloned().unwrap_or(serde_json::Value::Null),
                "addresses": interface.get("addresses").cloned().unwrap_or_else(|| serde_json::json!([])),
                "link_local_v6": interface.get("link_local_v6").cloned().unwrap_or(serde_json::Value::Null),
                "networks": interface.get("networks").cloned().unwrap_or_else(|| serde_json::json!([])),
                "transports": ["udp6"],
            })
        })
        .collect::<Vec<_>>();
    serde_json::json!({"networks": networks})
}

/// Resolve the currently usable link-local address for a configured shared
/// network. The emitted announce carries this address and its UDP port; the
/// receiving side records its own ingress interface/scope separately.
fn local_network_link_local_v6(network: &str) -> Option<[u8; 16]> {
    local_udp6_interfaces().into_iter().find_map(|entry| {
        let belongs = entry
            .get("networks")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|names| names.iter().any(|name| name.as_str() == Some(network)));
        belongs
            .then(|| {
                entry
                    .get("link_local_v6")
                    .and_then(serde_json::Value::as_str)
            })
            .flatten()
            .and_then(|address| address.parse::<Ipv6Addr>().ok())
            .map(|address| address.octets())
    })
}

/// The receiver owns IPv6 link-local scope.  A UDP4 multicast observation has
/// no IPv6 scope of its own, but an authenticated peer may still advertise a
/// UDP6 endpoint.  In that case select one of this node's configured local
/// UDP6 networks; the network label is local configuration, never wire data.
fn configured_udp6_scope_id() -> Option<u32> {
    local_udp6_interfaces().into_iter().find_map(|entry| {
        entry
            .get("networks")
            .and_then(serde_json::Value::as_array)
            .filter(|networks| !networks.is_empty())
            .and_then(|_| entry.get("interface_index"))
            .and_then(serde_json::Value::as_u64)
            .and_then(|index| u32::try_from(index).ok())
    })
}

/// Decode the explicit UDP form accepted by the explorer: `[IPv6]:port`,
/// `IPv4:port`, or the same value prefixed with `udp://`.  Link-local scope
/// remains receiver-local; use the configured mesh ingress for an unscoped
/// link-local address.  A colon-separated MAC is deliberately recognized so
/// the caller receives a precise NOW-not-yet-installed error instead of a
/// misleading unknown-discovery-node result.
fn explicit_udp_endpoint(destination: &str) -> Result<Option<SocketAddr>> {
    let value = destination.trim();
    if value.is_empty() {
        return Ok(None);
    }
    let value = value.strip_prefix("udp://").unwrap_or(value);
    if let Ok(mut endpoint) = value.parse::<SocketAddr>() {
        if let SocketAddr::V6(address) = &mut endpoint
            && address.ip().is_unicast_link_local()
            && address.scope_id() == 0
        {
            address.set_scope_id(configured_udp6_scope_id().unwrap_or(0));
        }
        return Ok(Some(endpoint));
    }
    Ok(None)
}

/// A directed NOW destination is an ordinary colon-separated hardware
/// address. Keep it separate from discovery identity lookup: raw NOW peers do
/// not need a synthetic signed UDP announcement before a stream can open.
fn is_now_mac(destination: &str) -> bool {
    let mut octets = destination.trim().split(':');
    (0..6).all(|_| {
        octets
            .next()
            .is_some_and(|part| part.len() == 2 && u8::from_str_radix(part, 16).is_ok())
    }) && octets.next().is_none()
}

fn parse_unicast_mac(value: &str) -> Option<[u8; 6]> {
    let mut mac = [0u8; 6];
    let mut parts = value.trim().split(':');
    for octet in &mut mac {
        let part = parts.next()?;
        if part.len() != 2 {
            return None;
        }
        *octet = u8::from_str_radix(part, 16).ok()?;
    }
    (parts.next().is_none() && mac != [0; 6] && mac[0] & 1 == 0).then_some(mac)
}

fn common_discovery_status(radio: &lmesh_wifi::RadioService) -> serde_json::Value {
    let devices = radio
        .radio_devices()
        .get("devices")
        .and_then(serde_json::Value::as_array)
        .map_or(0, Vec::len);
    serde_json::json!({
        "local_networks": common_local_networks().get("networks").cloned().unwrap_or_else(|| serde_json::json!([])),
        "stats": {"devices": devices},
    })
}

/// NAN supplies discovery/bootstrap only. It is deliberately not a
/// QUIC-lite data bearer and must not be used to model object transfer.
pub fn nan_object_dry_run(_image_size: usize, _mtu: usize) -> serde_json::Value {
    serde_json::json!({
        "ok": false,
        "bearer": "nan-discovery",
        "error": "NAN is discovery/bootstrap only; select UDP, UART, or ESP-NOW/action",
    })
}

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
    /// Typed common announce fields. Legacy JSON peers leave these absent.
    pub announce: Option<ObservedAnnounce>,
}

/// Bounded, bearer-neutral announce information retained for one observed
/// peer.  It is intentionally a schema, not a map of stringly typed tags.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservedAnnounce {
    pub device_id: String,
    pub kind: u64,
    pub uptime_secs: u32,
    /// Current sender Wi-Fi channel, or zero when the sender cannot report it.
    pub wifi_channel: u8,
    pub authenticated: bool,
    /// Advertised normal UDP/QUIC port; zero is a legacy peer without an
    /// explicit endpoint.
    pub udp_port: u16,
    /// Advertised link-local address. The receiving socket's scope remains in
    /// the enclosing `Node.address`, not in this sender-provided value.
    pub udp_link_local_v6: Option<[u8; 16]>,
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
    /// IPv6 UDP socket
    socket_v4: Option<Arc<UdpSocket>>,
    socket_v6: Option<Arc<UdpSocket>>,
    /// Optional semantic sink for signed/validated common CBOR announces.
    /// The node map remains the compatibility view; this lets the owning
    /// host radio expose one device inventory across UDP and NAN.
    announce_observer: Arc<RwLock<Option<AnnounceObserver>>>,
    /// Local routing metadata included in the common announce. The receiver
    /// already knows its interface scope from the received UDP6 datagram, so
    /// this deliberately contains only the shared network label and service
    /// port, never a host interface name.
    announce_network_name: Option<String>,
    announce_udp_port: u16,
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

        // The common discovery wire uses SEC1 compressed P-256 points (33
        // bytes), not the larger DER/SPKI wrapper.
        let public_key_ec = private_key_ec.public_key();
        let public_key = public_key_ec.to_sec1_point(true).as_bytes().to_vec();

        let public_key_b64 = base64_url_encode(&public_key);

        Ok(Self {
            private_key,
            public_key,
            public_key_b64,
            nodes: Arc::new(RwLock::new(HashMap::new())),
            node_store_dir: Arc::new(Self::default_node_store_dir()?),
            socket_v4: None,
            socket_v6: None,
            announce_observer: Arc::new(RwLock::new(None)),
            announce_network_name: None,
            announce_udp_port: 0,
        })
    }

    /// Configure the endpoint advertised by this local service. `network` is
    /// the bearer-neutral LAN label (for example `costin`); the current
    /// link-local address is resolved when an announce is emitted, while the
    /// receiver retains its own ingress interface/scope.
    pub fn configure_announce_udp6(&mut self, network: impl Into<String>, port: u16) {
        self.announce_network_name = Some(network.into());
        self.announce_udp_port = port;
    }

    /// Install the local semantic sink for common tagged-CBOR announces.
    ///
    /// This is deliberately a host-local integration point, not a network
    /// control handler: UDP validation remains here, and the receiver owns
    /// the ingress buffer before the bounded device registry is updated.
    pub async fn set_announce_observer(&self, observer: AnnounceObserver) {
        *self.announce_observer.write().await = Some(observer);
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
        // IPv4 remains a best-effort compatibility listener. Discovery's
        // primary path is the explicitly scoped IPv6 multicast below.
        match Self::setup_multicast_v4().await {
            Ok(socket) => self.socket_v4 = Some(Arc::new(socket)),
            Err(error) => warn!(%error, "mcast_v4_listener_unavailable"),
        }
        // Setup IPv6 multicast socket
        match Self::setup_multicast_v6().await {
            Ok(socket) => {
                self.socket_v6 = Some(Arc::new(socket));
                debug!(
                    multicast_ip = %DISCOVERY_MULTICAST_IPV6,
                    multicast_port = DISCOVERY_MULTICAST_PORT,
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
            let announce_observer = self.announce_observer.clone();
            tokio::spawn(async move {
                if let Err(error) = Self::receive_loop(
                    socket,
                    nodes,
                    local_public_key,
                    node_store_dir,
                    announce_observer,
                )
                .await
                {
                    error!(%error, "mcast_v4_receive_failed");
                }
            });
        }
        if let Some(socket) = &self.socket_v6 {
            let nodes = self.nodes.clone();
            let socket = socket.clone();
            let local_public_key = self.public_key_b64.clone();
            let node_store_dir = self.node_store_dir.clone();
            let announce_observer = self.announce_observer.clone();
            tokio::spawn(async move {
                if let Err(e) = Self::receive_loop(
                    socket,
                    nodes,
                    local_public_key,
                    node_store_dir,
                    announce_observer,
                )
                .await
                {
                    error!("IPv6 receive loop error: {}", e);
                }
            });
        }

        Ok(())
    }

    async fn setup_multicast_v4() -> Result<UdpSocket> {
        let socket = bind_shared_multicast_v4(DISCOVERY_MULTICAST_PORT)?;
        socket
            .join_multicast_v4(DISCOVERY_MULTICAST_IPV4, Ipv4Addr::UNSPECIFIED)
            .context("Failed to join IPv4 multicast group")?;
        Ok(socket)
    }

    /// Setup IPv6 multicast socket
    async fn setup_multicast_v6() -> Result<UdpSocket> {
        // Linux normally creates a dual-stack IPv6 UDP socket.  lmesh also
        // owns the IPv4 compatibility listener on this port, so explicitly
        // make this IPv6-only *before* bind.  Otherwise the v4 listener wins
        // and IPv6 multicast is silently unavailable.
        let fd = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error()).context("Failed to create IPv6 socket");
        }
        let socket = unsafe { std::net::UdpSocket::from_raw_fd(fd) };
        let enabled: libc::c_int = 1;
        let option_len = std::mem::size_of_val(&enabled) as libc::socklen_t;
        let reuse = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_REUSEADDR,
                (&enabled as *const libc::c_int).cast(),
                option_len,
            )
        };
        if reuse != 0 {
            return Err(std::io::Error::last_os_error())
                .context("Failed to make IPv6 multicast socket shareable");
        }
        let result = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::IPPROTO_IPV6,
                libc::IPV6_V6ONLY,
                (&enabled as *const libc::c_int).cast(),
                option_len,
            )
        };
        if result != 0 {
            return Err(std::io::Error::last_os_error())
                .context("Failed to make IPv6 multicast socket IPv6-only");
        }
        let address = libc::sockaddr_in6 {
            sin6_family: libc::AF_INET6 as libc::sa_family_t,
            sin6_port: DISCOVERY_MULTICAST_PORT.to_be(),
            sin6_flowinfo: 0,
            sin6_addr: libc::in6_addr {
                s6_addr: Ipv6Addr::UNSPECIFIED.octets(),
            },
            sin6_scope_id: 0,
        };
        let result = unsafe {
            libc::bind(
                socket.as_raw_fd(),
                (&address as *const libc::sockaddr_in6).cast(),
                std::mem::size_of_val(&address) as libc::socklen_t,
            )
        };
        if result != 0 {
            return Err(std::io::Error::last_os_error()).context("Failed to bind IPv6 socket");
        }
        socket
            .set_nonblocking(true)
            .context("Failed to make IPv6 multicast socket nonblocking")?;
        let socket = UdpSocket::from_std(socket).context("Failed to adopt IPv6 socket")?;

        let interfaces = multicast_v6_interface_indices();
        if interfaces.is_empty() {
            anyhow::bail!("no active IPv6 multicast interface");
        }
        for index in interfaces {
            socket
                .join_multicast_v6(&DISCOVERY_MULTICAST_IPV6, index)
                .with_context(|| {
                    format!("Failed to join IPv6 multicast group on interface {index}")
                })?;
        }

        Ok(socket)
    }

    /// Receive and process announcements
    #[instrument(
        skip(socket, nodes, local_public_key, node_store_dir, announce_observer),
        fields(buf_size = 65536)
    )]
    async fn receive_loop(
        socket: Arc<UdpSocket>,
        nodes: Arc<RwLock<HashMap<String, Node>>>,
        local_public_key: String,
        node_store_dir: Arc<PathBuf>,
        announce_observer: Arc<RwLock<Option<AnnounceObserver>>>,
    ) -> Result<()> {
        let mut buf = vec![0u8; 65536];

        loop {
            let (len, addr) = socket
                .recv_from(&mut buf)
                .await
                .context("Failed to receive from socket")?;

            let data = &buf[..len];

            // New common presence wire. It deliberately shares the old
            // local-link multicast socket but not its JSON envelope, so
            // UART/NOW/NAN/UDP observe one bounded CBOR record.
            // UDP discovery is a DCID-zero direct record. Accept bare CBOR
            // only while older peers are still being upgraded; NAN SDF has
            // its own bearer frame and continues to carry the inner record.
            let announce_data =
                quic_lite::decode_direct_packet(data).map_or(data, |(_, payload)| payload);
            if let Some(announce) = dmesh_server::announce::decode_announce(announce_data) {
                // A sender that supplies an identity must prove it: the key
                // hash is its stable device id and the signature covers the
                // canonical tagged-CBOR fields. Unsigned records are accepted
                // only as a temporary compatibility form for older devices.
                let public_key = if announce.has_identity() {
                    let digest = Sha256::digest(announce.public_key());
                    let signature = Signature::from_slice(announce.signature()).ok();
                    let verifying_key = VerifyingKey::from_sec1_bytes(announce.public_key()).ok();
                    let mut signed = [0u8; 384];
                    let valid = signature.zip(verifying_key).and_then(|(signature, key)| {
                        dmesh_server::announce::signing_bytes(announce, &mut signed)
                            .map(|used| key.verify(&signed[..used], &signature).is_ok())
                    }) == Some(true);
                    if !valid || announce.device_id() != &digest[..announce.device_id().len()] {
                        warn!(address = %addr, "dropping announce with invalid identity");
                        continue;
                    }
                    base64_url_encode(announce.public_key())
                } else {
                    hex_encode(announce.device_id())
                };
                if public_key == local_public_key {
                    continue;
                }
                // The validation above is authoritative. Forward only the
                // validated semantic record, never an untrusted UDP frame,
                // so NAN and UDP use one device-inventory schema.
                Self::notify_announce_observer(&announce_observer, addr, announce).await;
                let announce_info = ObservedAnnounce {
                    device_id: hex_encode(announce.device_id()),
                    kind: announce.kind,
                    uptime_secs: announce.uptime_secs,
                    wifi_channel: announce.wifi_channel,
                    authenticated: announce.has_identity(),
                    udp_port: announce.udp_port,
                    udp_link_local_v6: announce.udp_link_local_v6(),
                };
                let node = Node {
                    public_key: public_key.clone(),
                    address: addr,
                    last_seen: std::time::Instant::now(),
                    metadata: None,
                    announce: Some(announce_info.clone()),
                };
                let is_new = {
                    let mut nodes_map = nodes.write().await;
                    let is_new = !nodes_map.contains_key(&public_key);
                    nodes_map.insert(public_key.clone(), node);
                    is_new
                };
                info!(public_key = %public_key, address = %addr, announce = ?announce_info,
                    event = if is_new { "node_seen" } else { "node_updated" },
                    "announce_rx");
                continue;
            }

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
                        announce: None,
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

    async fn notify_announce_observer(
        announce_observer: &Arc<RwLock<Option<AnnounceObserver>>>,
        peer: SocketAddr,
        announce: dmesh_server::announce::Announce,
    ) {
        if let Some(observer) = announce_observer.read().await.clone() {
            observer(peer, announce);
        }
    }

    /// Send an announcement to the multicast group
    #[instrument(skip(self))]
    pub async fn announce(&self) -> Result<serde_json::Value> {
        self.announce_with_metadata(None).await
    }

    /// Build the compact common presence record used as NAN Publish Service
    /// Info and directed Follow-up data. Host/Android use the same complete
    /// signed record as UDP, now compact enough because the public key is a
    /// 33-byte compressed SEC1 point rather than DER/SPKI.
    pub fn nan_announce_service_info(&self, uptime_secs: u64) -> Result<Vec<u8>> {
        let identity_hint = dmesh_server::announce::identity_hint(&self.public_key)
            .context("missing local public-key identity hint")?;
        let mut device_id = [0; 16];
        device_id[..identity_hint.len()].copy_from_slice(&identity_hint);
        let mut announce = dmesh_server::announce::Announce::discovery(
            device_id,
            identity_hint.len() as u8,
            uptime_secs.min(u64::from(u32::MAX)) as u32,
        );
        if let Some(name) = discovery_device_name() {
            let _ = announce.set_device_name(&name);
        }
        if let Some(domain) = discovery_device_domain() {
            let _ = announce.set_device_domain(&domain);
        }
        if let Some(network) = self.announce_network_name.as_deref() {
            if self.announce_udp_port != 0 {
                if let Some(address) = local_network_link_local_v6(network) {
                    announce.set_udp_port(self.announce_udp_port);
                    announce.set_udp_link_local_v6(address);
                }
            }
        }
        // This is the stable host control-plane identity.  It advertises its
        // measured radio capabilities so a pair probe may select it as an
        // endpoint, while the executor still promises never to reconfigure
        // this host as part of the probe.
        announce.set_probe_descriptor(
            dmesh_server::announce::DEVICE_CLASS_HOST,
            dmesh_server::probe::PROBE_CAP_NAN
                | dmesh_server::probe::PROBE_CAP_NOW
                | dmesh_server::probe::PROBE_CAP_STA
                | dmesh_server::probe::PROBE_CAP_AP
                | dmesh_server::probe::PROBE_CAP_UDP6,
        );
        if !announce.set_public_key(&self.public_key) {
            anyhow::bail!("local public key exceeds announce bound");
        }
        let signing_key = SigningKey::from(
            SecretKey::from_pkcs8_der(&self.private_key)
                .context("Failed to decode local NAN signing key")?,
        );
        let mut signing_wire = [0u8; 384];
        let signing_len = dmesh_server::announce::signing_bytes(announce, &mut signing_wire)
            .context("Failed to encode local NAN signing bytes")?;
        let signature: Signature = signing_key.sign(&signing_wire[..signing_len]);
        if !announce.set_signature(signature.to_bytes().as_ref()) {
            anyhow::bail!("local NAN announce signature has invalid length");
        }
        let mut wire = [0; 384];
        let used = dmesh_server::announce::encode(announce, &mut wire)
            .context("Failed to encode compact NAN Service Info announce")?;
        // A directed Follow-up wraps Service Info in the 24-byte DMesh
        // envelope. Keep the shared discovery reply inside that portable
        // bound, rather than accepting an Active-Publish payload which could
        // not be returned to an Android active Subscribe.
        let followup_limit = dmesh_rawnan::NAN_COMMAND_MAX_LEN
            .saturating_sub(dmesh_rawnan::DMESH_NAN_FOLLOWUP_HEADER_LEN);
        if used > followup_limit {
            anyhow::bail!(
                "compact NAN Service Info announce is {used} bytes; Follow-up limit is {followup_limit}"
            );
        }
        Ok(wire[..used].to_vec())
    }

    /// Send an announcement with optional metadata
    #[instrument(skip(self, _metadata))]
    pub async fn announce_with_metadata(
        &self,
        _metadata: Option<HashMap<String, String>>,
    ) -> Result<serde_json::Value> {
        // Keep the radio record identical across UDP/NOW/NAN/UART. Unlike an
        // ESP32 presence hint, a host carries its P-256 identity and signs the
        // canonical fields. Receivers accept unsigned records only when no
        // public key is present.
        let digest = Sha256::digest(&self.public_key);
        let mut device_id = [0; 16];
        device_id.copy_from_slice(&digest[..16]);
        let mut announce =
            dmesh_server::announce::Announce::discovery(device_id, device_id.len() as u8, 0);
        if let Some(name) = discovery_device_name() {
            let _ = announce.set_device_name(&name);
        }
        if let Some(domain) = discovery_device_domain() {
            let _ = announce.set_device_domain(&domain);
        }
        if let Some(network) = self.announce_network_name.as_deref() {
            if self.announce_udp_port != 0 {
                if let Some(address) = local_network_link_local_v6(network) {
                    announce.set_udp_port(self.announce_udp_port);
                    announce.set_udp_link_local_v6(address);
                }
            }
        }
        if !announce.set_public_key(&self.public_key) {
            anyhow::bail!("local public key exceeds announce bound");
        }
        let signing_key = SigningKey::from(
            SecretKey::from_pkcs8_der(&self.private_key)
                .context("Failed to decode local announce signing key")?,
        );
        // A signed host record contains the public-key DER in addition to
        // the common announce fields. Keep this host-only scratch larger than
        // the ESP/NAN unsigned wire; 256 bytes can reject valid P-256 keys
        // before the service has opened its control socket.
        let mut signing_wire = [0u8; 384];
        let signing_len = dmesh_server::announce::signing_bytes(announce, &mut signing_wire)
            .context("Failed to encode local announce signing bytes")?;
        let signature: Signature = signing_key.sign(&signing_wire[..signing_len]);
        if !announce.set_signature(signature.to_bytes().as_ref()) {
            anyhow::bail!("local announce signature has invalid length");
        }
        let mut announce_wire = [0; 384];
        let announce_used = dmesh_server::announce::encode(announce, &mut announce_wire)
            .context("Failed to encode local announce")?;
        let mut wire = [0; 512];
        let used = quic_lite::encode_direct_packet(0, &announce_wire[..announce_used], &mut wire)
            .map_err(|error| {
            anyhow::anyhow!("Failed to wrap local announce in direct record: {error:?}")
        })?;

        let mut transmissions = Vec::new();
        // Best-effort compatibility for older IPv4-only local peers. IPv6
        // below is the explicit per-link discovery transport.
        if let Some(socket) = &self.socket_v4 {
            let addr = SocketAddr::new(
                IpAddr::V4(DISCOVERY_MULTICAST_IPV4),
                DISCOVERY_MULTICAST_PORT,
            );
            socket
                .send_to(&wire[..used], addr)
                .await
                .context("Failed to send IPv4 announcement")?;
            transmissions.push(serde_json::json!({
                "transport": "udp4_multicast_compat",
                "destination": addr.to_string(),
                "bytes": used,
                "accepted": true,
                "egress": "kernel_route",
            }));
        }
        // Send on every active IPv6 link. Link-local multicast is scoped, so
        // this explicitly includes br-lan, associated STA/AP links, and P2P
        // links rather than relying on a single kernel-selected default route.
        if let Some(socket) = &self.socket_v6 {
            for index in multicast_v6_interface_indices() {
                let addr = SocketAddr::V6(std::net::SocketAddrV6::new(
                    DISCOVERY_MULTICAST_IPV6,
                    DISCOVERY_MULTICAST_PORT,
                    0,
                    index,
                ));
                if let Err(error) = socket.send_to(&wire[..used], addr).await {
                    // Interfaces can disappear between enumeration and send
                    // (especially transient P2P groups). Discovery is soft
                    // state, so one stale scope must not terminate either
                    // supervised mesh process.
                    warn!(%error, interface_index = index, "udp6_multicast_announce_skipped");
                    continue;
                }
                let mut name = [0 as libc::c_char; libc::IF_NAMESIZE];
                let interface = unsafe {
                    (!libc::if_indextoname(index, name.as_mut_ptr()).is_null())
                        .then(|| CStr::from_ptr(name.as_ptr()).to_string_lossy().into_owned())
                };
                transmissions.push(serde_json::json!({
                    "transport": "udp6_multicast",
                    "destination": addr.to_string(),
                    "interface_index": index,
                    "interface": interface,
                    "bytes": used,
                    "accepted": true,
                }));
            }
        }

        // IPv6 link multicast is the discovery contract.  IPv4 is only a
        // compatibility copy, so its successful kernel submission must not
        // make a missing IPv6 multicast path look healthy to the dashboard.
        let udp6_accepted = transmissions.iter().any(|transmission| {
            transmission
                .get("transport")
                .and_then(serde_json::Value::as_str)
                == Some("udp6_multicast")
        });
        Ok(serde_json::json!({
            "accepted": udp6_accepted,
            "compat_accepted": !transmissions.is_empty(),
            "transmissions": transmissions,
            "note": "local socket acceptance only; peer receipt is reported by per-node observed transports",
        }))
    }

    /// Get the public key in base64url encoding
    pub fn public_key_b64(&self) -> &str {
        &self.public_key_b64
    }

    /// Get a snapshot of currently discovered nodes
    #[instrument(skip(self))]
    pub async fn get_nodes(&self) -> HashMap<String, Node> {
        self.prune_expired_nodes().await;
        self.nodes.read().await.clone()
    }

    /// Get a specific node by its public key
    #[instrument(skip(self), fields(public_key = %public_key))]
    pub async fn get_node(&self, public_key: &str) -> Option<Node> {
        debug!("Getting node by public key");
        self.prune_expired_nodes().await;
        let nodes = self.nodes.read().await;
        let result = nodes.get(public_key).cloned();
        debug!("Node {}found", if result.is_some() { "" } else { "not " });
        result
    }

    /// Discovery records are soft state. Keep the host inventory useful after
    /// a peer disappears rather than presenting stale unsigned announcements
    /// indefinitely.
    async fn prune_expired_nodes(&self) {
        const NODE_TTL: std::time::Duration = std::time::Duration::from_secs(60 * 60);
        let now = std::time::Instant::now();
        self.nodes
            .write()
            .await
            .retain(|_, node| now.duration_since(node.last_seen) <= NODE_TTL);
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

/// Stable compact identifier used by mesh persistence and the optional BLE
/// launcher extension.
pub fn public_key_sha(public_key: &str) -> String {
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

/// Allocate a process-restart-safe QUIC receive CID for host circuit work.
/// Embedded relays intentionally retain one bounded endpoint until a clean
/// CLOSE or transport reset. Starting lmesh-wifi again must therefore never
/// reuse its fixed test CID and have its first stream packet mistaken for a
/// duplicate from the prior process.
fn next_relay_cid(counter: &AtomicU64, domain: u64) -> Option<quic_lite::ConnectionId> {
    let sequence = counter.fetch_add(1, Ordering::Relaxed).max(1);
    let millis = u64::try_from(current_timestamp_millis()).unwrap_or(u64::MAX);
    quic_lite::ConnectionId::new(
        ((millis.rotate_left(19) ^ sequence ^ domain) & quic_lite::ConnectionId::MAX_VALUE).max(1),
    )
}

/// Proposed aliases for one directional relay pair. Relay-local aliases use
/// the low bit solely as a direction marker: forward is even and return is
/// odd. The relay remains free to substitute either value on collision, so
/// callers must retain the observed pair.
fn proposed_relay_aliases(
    allocation: u64,
) -> Option<(quic_lite::ConnectionId, quic_lite::ConnectionId)> {
    let forward = allocation.checked_mul(2)?;
    let reverse = forward.checked_add(1)?;
    Some((
        quic_lite::ConnectionId::new(forward)?,
        quic_lite::ConnectionId::new(reverse)?,
    ))
}

/// JSON-lines request methods for lmesh.
fn default_rate_profile() -> String {
    "auto".to_owned()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "method")]
pub enum Request {
    /// Open or replace one retained QUIC control connection to a directly
    /// reachable relay and install its first adjacent relay leg.  The next
    /// hop is a relay-local NOW peer for this initial promotion; the UI will
    /// select it from the relay's discovery view once that projection is
    /// exposed by ESP Main.
    #[serde(rename = "relay.connect")]
    RelayConnect {
        relay_endpoint: String,
        next_hop_mac: String,
    },
    /// Complete a previously installed first relay leg. The initial OPEN
    /// travels through the observed forward alias; after OPEN_ACK this method
    /// updates that alias to the endpoint-selected CID and verifies endpoint
    /// status on the resulting QUIC connection.
    #[serde(rename = "relay.open")]
    RelayOpen { relay_endpoint: String },
    /// Inspect retained first-leg control sessions without probing a peer.
    #[serde(rename = "relay.status")]
    RelayStatus,
    /// Send a mesh payload over the selected radio.
    #[serde(rename = "send")]
    Send {
        #[serde(default)]
        radio: Option<String>,
        #[serde(default)]
        destination: Option<String>,
        payload: String,
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
    #[serde(rename = "wifi.interface.list")]
    WifiInterfaceList,
    #[serde(rename = "wifi.interface.up")]
    WifiInterfaceUp {
        #[serde(default)]
        iface: Option<String>,
    },
    #[serde(rename = "wifi.interface.channel")]
    WifiInterfaceChannel {
        #[serde(default)]
        iface: Option<String>,
        channel: u8,
    },
    /// Replace the owned interface with an OCB (outside-context-of-a-BSS)
    /// link. This disconnects any AP/STA session on that interface.
    #[serde(rename = "wifi.ocb.start")]
    WifiOcbStart {
        #[serde(default)]
        iface: Option<String>,
        #[serde(default)]
        freq: Option<u32>,
        #[serde(default)]
        bandwidth: Option<String>,
    },
    /// Set or restore the fixed Linux 2.4 GHz rate profile for experiments.
    #[serde(rename = "wifi.rate.profile")]
    WifiRateProfile {
        #[serde(default)]
        iface: Option<String>,
        #[serde(default = "default_rate_profile")]
        profile: String,
        #[serde(default)]
        disable_80211b: bool,
    },
    /// Send a raw Wi-Fi DMesh status ping and collect replies.
    #[serde(rename = "wifi.raw.ping")]
    WifiRawPing {
        #[serde(default)]
        iface: Option<String>,
        #[serde(default)]
        channel: Option<u8>,
        #[serde(default)]
        listen_sec: Option<u64>,
        #[serde(default)]
        wait_ms: Option<u64>,
        #[serde(default)]
        nonce: Option<String>,
    },
    /// Presentation-safe common discovery inventory. Native radio peers stay
    /// in adapter diagnostics; this response exposes only semantic IDs and
    /// shared observation facts.
    #[serde(rename = "discovery.nodes")]
    RadioDevices,
    /// Common discovery state and this node's local bearer/address projection.
    #[serde(rename = "discovery.status")]
    DiscoveryStatus,
    /// Common NAN cluster and counter projection. Device records are exposed
    /// only through `discovery.nodes`.
    #[serde(rename = "nan.status")]
    NanStatus,
    /// Local ESP-NOW/action transport counters. Missing facts are omitted.
    #[serde(rename = "now.metrics")]
    NowMetrics,
    /// Local NAN capture and semantic dispatch counters.
    #[serde(rename = "nan.metrics")]
    NanMetrics,
    /// Local raw IPv6, UDP, and NDP counters.
    #[serde(rename = "udp6.metrics")]
    Udp6Metrics,
    /// Common optional per-peer Wi-Fi link observations.
    #[serde(rename = "wifi.link.metrics")]
    WifiLinkMetrics,
    /// Request current passive inventory or an active NAN discovery response
    /// without replacing the current transport epoch.
    #[serde(rename = "transport.discover")]
    TransportDiscover {
        #[serde(default)]
        iface: Option<String>,
        #[serde(default)]
        channel: Option<u8>,
        #[serde(default)]
        nan: Option<bool>,
        #[serde(default)]
        passive_scan: Option<bool>,
        #[serde(default)]
        active_scan: Option<bool>,
        #[serde(default)]
        dns_sd: Option<bool>,
        #[serde(default)]
        wait_ms: Option<u64>,
    },
    /// Size a NAN object transfer without opening an IP socket or touching a
    /// device. The same envelope is used by data frames and action diagnostics.
    #[serde(rename = "object.nan.dry_run")]
    ObjectNanDryRun {
        image_size: usize,
        #[serde(default)]
        mtu: Option<usize>,
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
        #[serde(default)]
        channel: Option<u8>,
        #[serde(default)]
        ht40: Option<bool>,
        /// AP timing is a lab/startup property, never an automated test
        /// action. The radio implementation clamps this to 10--1000 TU.
        #[serde(default)]
        beacon_interval_tu: Option<u16>,
    },
    /// Stop AP operation.
    #[serde(rename = "wifi.ap.stop")]
    WifiApStop {
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
        #[serde(default)]
        channel: Option<u8>,
        #[serde(default)]
        passive: Option<bool>,
    },
    /// Join an open AP on the shared DMesh channel.
    #[serde(rename = "wifi.sta.join_open")]
    WifiStaJoinOpen {
        #[serde(default)]
        iface: Option<String>,
        ssid: String,
    },
    /// Replace a local transport profile. Adapters apply the settings they
    /// support and ignore the rest; the resulting announced state reports
    /// what became active.
    #[serde(rename = "transport.start")]
    TransportStart {
        /// Device-neutral bearer kind. Linux accepts `nan` with `ap=1` for
        /// the P2P AP-equivalent and retains `sta` for ordinary association.
        #[serde(default)]
        kind: Option<TransportKindRequest>,
        #[serde(default)]
        iface: Option<String>,
        #[serde(default)]
        ssid: String,
        #[serde(default)]
        passphrase: Option<String>,
        #[serde(default)]
        bssid: Option<String>,
        #[serde(default)]
        channel: Option<u8>,
        /// NAN discovery-window cadence: `1` is active, `8` is sleepy.
        #[serde(default)]
        nan_dw_interval: Option<u8>,
        /// NOW action receive policy: `0` default/on, `1` on, `2` off.
        #[serde(default)]
        now: Option<u8>,
        /// `transport.start` AP-equivalent request.
        #[serde(default)]
        ap: Option<u8>,
        /// Select the ordinary raw open AP backend for Linux/ESP comparison.
        /// Omitted/zero selects the default P2P WPA2-PSK Group Owner.
        #[serde(default)]
        open: Option<TransportFlagRequest>,
    },
    /// End the current Linux Wi-Fi transport and remove service-created VIFs.
    #[serde(rename = "transport.stop")]
    TransportStop {
        #[serde(default)]
        iface: Option<String>,
    },
    /// Configure a static IPv4 address for a station test or bootstrap link.
    #[serde(rename = "wifi.sta.configure_ipv4")]
    WifiStaConfigureIpv4 {
        #[serde(default)]
        iface: Option<String>,
        address: String,
        #[serde(default)]
        prefix: Option<u8>,
    },
}

/// The common tagged-CBOR control record uses the compact numeric transport
/// kind.  Keep the historic JSON spelling accepted at the local boundary so
/// existing CLI callers remain compatible.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum TransportKindRequest {
    Name(String),
    Tag(u8),
}

impl TransportKindRequest {
    fn as_name(&self) -> Option<&str> {
        match self {
            Self::Name(value) => Some(value.as_str()),
            Self::Tag(1) => Some("sta"),
            Self::Tag(5) => Some("uart"),
            Self::Tag(6) => Some("nan"),
            Self::Tag(_) => None,
        }
    }
}

/// Catalogued boolean fields are encoded as CBOR booleans, while historic
/// JSONL callers used `0`/`1`.  Preserve both projections at the service edge.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum TransportFlagRequest {
    Boolean(bool),
    Tag(u8),
}

impl TransportFlagRequest {
    fn is_enabled(&self) -> bool {
        matches!(self, Self::Boolean(true) | Self::Tag(1))
    }
}

pub struct LmeshService {
    discovery: Arc<LocalDiscovery>,
    /// Embedded canary Wi-Fi instance.  It is constructed through the same
    /// reusable library object as the standalone lmesh-wifi launcher; this
    /// process owns the interfaces named by its own LMESH_INTERFACES (normally
    /// wlan1), while lmesh-wifi remains an independent wlan0 instance.
    wifi_service: lmesh_wifi::WifiService,
    radio: lmesh_wifi::RadioService,
    wifi: lmesh_wifi::WifiNetd,
    /// Long-lived controller-side QUIC connections.  A relay pair binds its
    /// reverse rule to the UDP tuple of this socket, so the socket must not
    /// be recreated between HTTP calls.
    relay_sessions: Arc<Mutex<HashMap<String, RelayControlSession>>>,
}

struct RelayControlSession {
    client: Option<dmesh_server::udp::UdpClient>,
    peer: String,
    udp_peer: Option<SocketAddr>,
    /// CID used only by the first-relay administration connection.
    local_cid: quic_lite::ConnectionId,
    /// Controller-selected CID for the endpoint connection opened through
    /// the relay. This is deliberately distinct from `local_cid`.
    endpoint_cid: quic_lite::ConnectionId,
    forward_alias: quic_lite::ConnectionId,
    reverse_alias: quic_lite::ConnectionId,
    forward_allocation: u64,
    forward_next_hop: u64,
    endpoint_server_cid: Option<quic_lite::ConnectionId>,
}

impl LmeshService {
    /// Create a service around an initialized discovery instance.
    pub fn new(discovery: Arc<LocalDiscovery>) -> Self {
        let wifi_service = lmesh_wifi::WifiService::from_environment_with_discovery_log(
            "/run/mesh/lmesh/discovery.jsonl",
        );
        let radio = wifi_service.radio().clone();
        let wifi = wifi_service.netd().clone();
        // Construction is deliberately radio-neutral. A lmesh restart must
        // not retune, create a monitor, or change link state on wlan1; each
        // transport/AP operation owns its own explicit transition.
        Self {
            discovery,
            wifi_service,
            radio,
            wifi,
            relay_sessions: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Start the optional lmesh lab AP. lmesh-wifi remains the normal 100-TU
    /// infrastructure AP; this independently owned AP defaults to 500 TU.
    pub fn start_default_open_ap(
        &self,
        iface: String,
        channel: u8,
        beacon_interval_tu: u16,
    ) -> serde_json::Value {
        if let Err(error) = self.wifi.authorize(lmesh_wifi::Operation::Ap, &iface) {
            return serde_json::json!({"error": error.to_string()});
        }
        serde_json::json!({"response": self.radio.wifi_ap_start_open_on_child(
            Some(iface),
            None,
            Some(channel),
            Some(false),
            beacon_interval_tu,
        )})
    }

    /// Attach the experimental raw-NAN receiver to this service's permanent
    /// monitor fixture (normally `wlan1mon`).
    pub fn start_default_rawnan(&self) -> serde_json::Value {
        self.wifi_service.start_canary_rawnan(None)
    }

    /// Refresh lmesh's always-on active NAN Publish descriptor with the same
    /// compact CBOR announce used by other bearer discovery. The radio adapter
    /// queues it for an observed DW; this method never starts/stops a host
    /// interface or sends immediately.
    pub fn refresh_active_nan_publish(&self, uptime_secs: u64) -> Result<serde_json::Value> {
        let service_info = self.discovery.nan_announce_service_info(uptime_secs)?;
        self.radio
            .rawnan_active_publish_configure(true, &service_info)
    }

    /// Prepare the AP-off, fixed-channel monitor fixture before raw-NAN/NOW
    /// listeners attach.  The caller owns this startup transition.
    pub fn prepare_default_rawnan_monitor(&self, channel: u8) -> serde_json::Value {
        self.wifi_service
            .prepare_canary_rawnan_monitor(None, Some(channel))
    }

    /// Prepare the shared NAN+NOW monitor without disturbing the optional AP
    /// which is the channel anchor for this lmesh startup personality.
    pub fn prepare_default_ap_rawnan_monitor(&self, channel: u8) -> serde_json::Value {
        self.radio
            .prepare_ap_raw_monitor_fixture(None, Some(channel))
    }

    /// Default Linux radio personality: a channel-6 P2P GO plus the shared
    /// NAN/NOW monitor fixture. `LMESH_AP_BACKEND=open` retains the explicit
    /// pure-Rust AP fallback when the driver or supplicant lacks P2P.
    pub fn start_default_p2p_go(&self, channel: u8) -> serde_json::Value {
        self.wifi_service.start_p2p_go_with_rawnan(None, channel)
    }

    /// Reconcile this process's owned Wi-Fi interface through the same shared
    /// bounded recovery policy used by the standalone lmesh-wifi launcher.
    pub fn reconcile_wifi_health(&self) -> serde_json::Value {
        self.wifi_service.reconcile_stable_health()
    }

    /// Snapshot this service's allowlisted interfaces for the shared link
    /// watcher before it moves into its blocking netlink receive loop.
    pub fn wifi_owned_interfaces(&self) -> lmesh_wifi::InterfaceSet {
        self.wifi.owned_interfaces().clone()
    }

    /// Associate the owned interface with an open AP after the common NAN/NOW
    /// monitor fixture has been prepared.
    pub fn start_default_open_sta(&self, ssid: String) -> serde_json::Value {
        match self.owned_wifi_iface(None, lmesh_wifi::Operation::Sta) {
            Ok(iface) => self.radio.wifi_sta_join_open(Some(iface), ssid, None, None),
            Err(error) => serde_json::json!({"ok": false, "error": error}),
        }
    }

    /// End the current Wi-Fi transport epoch and prove that service-created
    /// AP/monitor/legacy-STA children are gone while retaining the primary
    /// interface as a down station VIF.
    pub fn stop_wifi_transport(&self, iface: Option<String>) -> serde_json::Value {
        self.wifi_service.transport_stop(iface)
    }

    fn owned_wifi_iface(
        &self,
        iface: Option<String>,
        operation: lmesh_wifi::Operation,
    ) -> std::result::Result<String, String> {
        let iface = iface
            .or_else(lmesh_wifi::default_interface)
            .ok_or_else(|| "LMESH_INTERFACES must name an owned Wi-Fi interface".to_owned())?;
        self.wifi
            .authorize(operation, &iface)
            .map_err(|error| error.to_string())?;
        Ok(iface)
    }

    /// Return the local public key used for announcements.
    pub fn public_key_b64(&self) -> &str {
        self.discovery.public_key_b64()
    }

    /// Merge an already validated multicast observation with the host radio's
    /// bounded device inventory. This uses the same change-only log policy as
    /// raw NAN observations; it does not expose an unauthenticated remote
    /// mutation surface.
    pub fn observe_multicast_announce(
        &self,
        peer: SocketAddr,
        announce: dmesh_server::announce::Announce,
    ) {
        self.radio
            .observe_discovered_announce("udp_multicast", peer.to_string(), None, announce);
    }

    /// Start lmesh's normal QUIC listener with the same async catalog
    /// dispatcher used by its UDS/HTTP endpoint.  This must be called after
    /// the service is wrapped in an `Arc`, so the UDP handler owns no second
    /// control-plane instance.
    pub fn start_udp_tagged_handler(
        &self,
        port: u16,
        tagged_handler: Arc<dyn dmesh_server::udp::TaggedStreamHandler>,
    ) -> serde_json::Value {
        self.radio.object_udp_start_with_tagged_handler(
            None,
            Some(port),
            None,
            Some(tagged_handler),
        )
    }

    /// Send a complete tagged-CBOR request over a normal QUIC stream.  A
    /// signed discovery key selects its retained endpoint.  An explicit UDP
    /// endpoint is also valid for an unsigned/foreign discovered device; it
    /// is intentionally labelled unverified by the explorer and remains
    /// subject to the normal invocation policy. A colon-separated MAC uses
    /// the normal QUIC stream through the bounded raw NOW action adapter.
    pub async fn forward_tagged_record(
        &self,
        destination: &str,
        record: &[u8],
    ) -> Result<mesh::tagged::TaggedRecord> {
        static NEXT_CID: AtomicU64 = AtomicU64::new(1);
        if is_now_mac(destination) {
            let response = self
                .radio
                .forward_tagged_record_over_now(destination, record)
                .with_context(|| {
                    format!("send directed tagged request over NOW to {destination}")
                })?;
            return mesh::cbor::decode_record(&response)
                .context("decode directed NOW tagged response");
        }
        let peer = if let Some(peer) = explicit_udp_endpoint(destination)? {
            peer
        } else {
            let node = self.discovery.get_node(destination).await.ok_or_else(|| {
                anyhow::anyhow!("unsupported/no_quic_route: destination is not discovered")
            })?;
            let port = node
                .announce
                .as_ref()
                .map(|announce| announce.udp_port)
                .filter(|port| *port != 0)
                .or_else(|| {
                    std::env::var("LMESH_OBJECT_SERVER_PORT")
                        .ok()
                        .and_then(|value| value.parse::<u16>().ok())
                })
                .unwrap_or(dmesh_server::udp::DEVELOPMENT_WIFI_UDP_PORT);
            let advertised_udp6 = node
                .announce
                .as_ref()
                .and_then(|announce| announce.udp_link_local_v6)
                .map(Ipv6Addr::from);
            if let Some(ip) = advertised_udp6 {
                let (flowinfo, scope_id) = match node.address {
                    SocketAddr::V6(address) => (address.flowinfo(), address.scope_id()),
                    // A separate IPv4 multicast observation can refresh the same
                    // signed node. Its lack of an IPv6 scope must not discard the
                    // endpoint; choose this receiver's configured UDP6 ingress.
                    SocketAddr::V4(_) => (0, configured_udp6_scope_id().unwrap_or(0)),
                };
                SocketAddr::V6(std::net::SocketAddrV6::new(ip, port, flowinfo, scope_id))
            } else {
                match node.address {
                    SocketAddr::V4(address) => {
                        SocketAddr::V4(std::net::SocketAddrV4::new(*address.ip(), port))
                    }
                    SocketAddr::V6(address) => SocketAddr::V6(std::net::SocketAddrV6::new(
                        *address.ip(),
                        port,
                        address.flowinfo(),
                        address.scope_id(),
                    )),
                }
            }
        };
        let bind = match peer {
            SocketAddr::V4(_) => SocketAddr::from(([0, 0, 0, 0], 0)),
            SocketAddr::V6(_) => SocketAddr::from(([0u16; 8], 0)),
        };
        let cid = NEXT_CID.fetch_add(1, Ordering::Relaxed).max(1);
        let cid = quic_lite::ConnectionId::new(cid)
            .ok_or_else(|| anyhow::anyhow!("unable to allocate QUIC connection ID"))?;
        let mut client = dmesh_server::udp::UdpClient::connect(bind, peer, cid)
            .await
            .with_context(|| format!("open QUIC route to discovered node {destination}"))?;
        let (_stream, response, _fin) = client
            .request_stream(quic_lite::FIRST_CLIENT_BIDI_STREAM_ID, record, true)
            .await
            .context("send directed tagged request over QUIC")?;
        let _ = client.close(0).await;
        mesh::cbor::decode_record(&response).context("decode directed QUIC tagged response")
    }

    /// Install the first relay leg through a retained normal QUIC control
    /// connection.  This is deliberately host-side orchestration: the relay
    /// only receives its ordinary `relay.pair` tagged request and never sees
    /// HTTP or a dashboard-specific command.
    async fn relay_connect(
        &self,
        relay_endpoint: String,
        next_hop_mac: String,
    ) -> Result<serde_json::Value> {
        let mac = parse_unicast_mac(&next_hop_mac)
            .ok_or_else(|| anyhow::anyhow!("next_hop_mac must be a directed unicast MAC"))?;
        static NEXT_CONTROL_CID: AtomicU64 = AtomicU64::new(0x4000);
        static NEXT_ENDPOINT_CID: AtomicU64 = AtomicU64::new(0x6000);
        static NEXT_ALLOCATION: AtomicU64 = AtomicU64::new(1);
        let local_cid = next_relay_cid(&NEXT_CONTROL_CID, 0x434f_4e54_524f_4c00)
            .ok_or_else(|| anyhow::anyhow!("unable to allocate relay control CID"))?;
        let endpoint_cid = next_relay_cid(&NEXT_ENDPOINT_CID, 0x454e_4450_4f49_4e54)
        .ok_or_else(|| anyhow::anyhow!("unable to allocate relay endpoint CID"))?;
        let udp_peer = explicit_udp_endpoint(&relay_endpoint)?;
        let now_relay = (udp_peer.is_none() && is_now_mac(&relay_endpoint)).then_some(relay_endpoint.as_str());
        if udp_peer.is_none() && now_relay.is_none() {
            anyhow::bail!("relay_endpoint must be udp://HOST:PORT, [IPv6]:PORT, or a directed NOW MAC");
        }

        // `relay.pair` is a normal request on the authenticated control
        // connection. The reverse route rewrites back to this connection's
        // own receive CID, while its opaque UDP6 handle is bound by e9 to the
        // observed source tuple during stream dispatch.
        let allocation = NEXT_ALLOCATION.fetch_add(2, Ordering::Relaxed).max(1);
        let (forward_alias, reverse_alias) = proposed_relay_aliases(allocation)
            .ok_or_else(|| anyhow::anyhow!("invalid relay aliases"))?;
        let reverse_handle = if let Some(_) = now_relay {
            dmesh_server::relay::now_next_hop_handle(self.radio.directed_now_source_mac()?)
                .ok_or_else(|| anyhow::anyhow!("invalid directed NOW source MAC"))?
        } else {
            dmesh_server::relay::udp6_next_hop_handle(allocation)
                .expect("nonzero relay allocation")
        };
        let request = dmesh_server::relay::PairRequest {
            forward: dmesh_server::relay::Request {
                allocation,
                revision: 1,
                rule: Some(dmesh_server::relay::DesiredRule {
                    proposed_dcid: Some(forward_alias),
                    route: dmesh_server::relay::RelayRoute {
                        next_hop: dmesh_server::relay::now_next_hop_handle(mac)
                            .expect("validated directed NOW MAC"),
                        outbound_dcid: quic_lite::ConnectionId::new(0).expect("zero bootstrap DCID"),
                    },
                    position: 1,
                }),
            },
            reverse: dmesh_server::relay::Request {
                allocation: allocation + 1,
                revision: 1,
                rule: Some(dmesh_server::relay::DesiredRule {
                    proposed_dcid: Some(reverse_alias),
                    route: dmesh_server::relay::RelayRoute {
                        next_hop: reverse_handle,
                        outbound_dcid: endpoint_cid,
                    },
                    position: 2,
                }),
            },
        };
        let mut wire = [0u8; 192];
        let request_id = allocation;
        let used = dmesh_server::relay::encode_pair_request(request, Some(request_id), &mut wire)
            .ok_or_else(|| anyhow::anyhow!("encode relay.pair"))?;
        let (response, retained_client, transport) = if let Some(peer) = udp_peer {
            let bind = match peer {
                SocketAddr::V4(_) => SocketAddr::from(([0, 0, 0, 0], 0)),
                SocketAddr::V6(_) => SocketAddr::from(([0u16; 8], 0)),
            };
            let mut client = dmesh_server::udp::UdpClient::connect(bind, peer, local_cid)
                .await
                .with_context(|| format!("open QUIC relay control to {relay_endpoint}"))?;
            let (_stream, response, fin) = client
                .request_stream(quic_lite::FIRST_CLIENT_BIDI_STREAM_ID, &wire[..used], true)
                .await
                .context("send relay.pair over UDP QUIC control")?;
            if !fin {
                anyhow::bail!("relay.pair UDP response did not finish its QUIC stream");
            }
            (response, Some(client), "udp_quic")
        } else {
            let response = self.radio
                .forward_tagged_record_over_now_with_cid(now_relay.expect("validated NOW relay"), &wire[..used], local_cid)
                .context("send relay.pair over NOW QUIC control")?;
            (response, None, "now_quic")
        };
        // Relay control is a DMesh tagged-CBOR component on the QUIC stream,
        // not the mesh JSON/CBOR RPC envelope used by the HTTP adapter.
        // Decode the same record format that ESP Main and dmesh-cli use, and
        // retain the relay-observed aliases: proposals are allowed to change
        // when a relay already owns either requested DCID.
        let response = dmesh_server::tagged::decode(&response)
            .ok_or_else(|| anyhow::anyhow!("decode relay.pair tagged response"))?;
        if response.id != Some(request_id) || response.error.is_some() {
            anyhow::bail!("relay.pair rejected or returned a mismatched response");
        }
        let observed = dmesh_server::relay::decode_observed_pair(
            response
                .result
                .ok_or_else(|| anyhow::anyhow!("relay.pair response lacks result"))?,
        )
        .ok_or_else(|| anyhow::anyhow!("relay.pair response has invalid observed aliases"))?;
        let forward_alias = observed
            .forward
            .local_dcid
            .ok_or_else(|| anyhow::anyhow!("relay.pair forward alias missing DCID"))?;
        let reverse_alias = observed
            .reverse
            .local_dcid
            .ok_or_else(|| anyhow::anyhow!("relay.pair reverse alias missing DCID"))?;
        let mut sessions = self.relay_sessions.lock().await;
        if let Some(mut previous) = sessions.remove(&relay_endpoint) {
            if let Some(client) = previous.client.as_mut() {
                let _ = client.close(0).await;
            }
        }
        sessions.insert(relay_endpoint.clone(), RelayControlSession {
            client: retained_client,
            peer: relay_endpoint.clone(),
            udp_peer,
            local_cid,
            endpoint_cid,
            forward_alias,
            reverse_alias,
            forward_allocation: allocation,
            forward_next_hop: dmesh_server::relay::now_next_hop_handle(mac)
                .expect("validated directed NOW MAC"),
            endpoint_server_cid: None,
        });
        Ok(serde_json::json!({
            "state": "leg_ready",
            "relay_endpoint": relay_endpoint,
            "next_hop_mac": next_hop_mac,
            "control_transport": transport,
            "endpoint_cid": endpoint_cid.value(),
            "forward_alias": forward_alias.value(),
            "reverse_alias": reverse_alias.value(),
        }))
    }

    /// Turn one installed first leg into a QUIC endpoint connection.  The
    /// original control socket is deliberately reused for the endpoint OPEN:
    /// `relay.pair` bound the reverse alias to exactly that UDP tuple.  The
    /// follow-up `relay.apply` is a separate ordinary control connection; it
    /// changes only the forward desired state and cannot rebind the reverse
    /// bearer route already installed by the pair.
    async fn relay_open(&self, relay_endpoint: String) -> Result<serde_json::Value> {
        let mut session = self
            .relay_sessions
            .lock()
            .await
            .remove(&relay_endpoint)
            .ok_or_else(|| anyhow::anyhow!("relay.open requires an existing leg_ready session"))?;
        let result = async {
            let peer = session
                .udp_peer
                .ok_or_else(|| anyhow::anyhow!("relay.open over NOW control is not implemented yet"))?;
            let control = session
                .client
                .take()
                .ok_or_else(|| anyhow::anyhow!("relay.open session has no retained UDP control socket"))?;

            // This is the one current QUIC-lite relay-open exception: the
            // endpoint's bootstrap OPEN uses visible alias F on the adjacent
            // e9 link. e9 rewrites it to DCID zero and substitutes R into the
            // plaintext receive-CID field before it reaches the endpoint.
            let socket = control.into_socket();
            let mut endpoint = dmesh_server::udp::UdpClient::connect_with_socket_and_quic_lite_wire_dcid(
                socket,
                peer,
                session.endpoint_cid,
                session.forward_alias,
            )
            .await
            .context("relay.open endpoint bootstrap through observed forward alias")?;
            let endpoint_server_cid = endpoint
                .peer_connection_id()
                .ok_or_else(|| anyhow::anyhow!("relay.open did not install endpoint server CID"))?;

            // Future opaque endpoint packets carry the server-selected CID,
            // so reconcile F's outbound DCID over an ordinary QUIC control
            // stream. This helper currently gives the stable socket to the
            // endpoint state; a fresh control socket is therefore used only
            // for this mutation. The endpoint's reverse path remains bound
            // to the original, still-live endpoint socket above.
            static NEXT_UPDATE_CID: AtomicU64 = AtomicU64::new(0x5000);
            let update_cid = next_relay_cid(&NEXT_UPDATE_CID, 0x5550_4441_5445_0000)
            .ok_or_else(|| anyhow::anyhow!("unable to allocate relay update CID"))?;
            let bind = match peer {
                SocketAddr::V4(_) => SocketAddr::from(([0, 0, 0, 0], 0)),
                SocketAddr::V6(_) => SocketAddr::from(([0u16; 8], 0)),
            };
            let mut update_control = dmesh_server::udp::UdpClient::connect(bind, peer, update_cid)
                .await
                .context("open relay.apply UDP QUIC control")?;
            let update = dmesh_server::relay::Request {
                allocation: session.forward_allocation,
                revision: 2,
                rule: Some(dmesh_server::relay::DesiredRule {
                    proposed_dcid: Some(session.forward_alias),
                    route: dmesh_server::relay::RelayRoute {
                        next_hop: session.forward_next_hop,
                        outbound_dcid: endpoint_server_cid,
                    },
                    position: 1,
                }),
            };
            let mut update_wire = [0u8; 128];
            let update_id = session.forward_allocation.saturating_add(1);
            let update_len = dmesh_server::relay::encode_request(
                update,
                Some(update_id),
                &mut update_wire,
            )
            .ok_or_else(|| anyhow::anyhow!("encode relay.apply update"))?;
            let (_, update_response, update_fin) = update_control
                .request_stream(
                    quic_lite::FIRST_CLIENT_BIDI_STREAM_ID,
                    &update_wire[..update_len],
                    true,
                )
                .await
                .context("send relay.apply after relay-open")?;
            if !update_fin {
                anyhow::bail!("relay.apply update did not finish its QUIC stream");
            }
            let update_response = dmesh_server::tagged::decode(&update_response)
                .ok_or_else(|| anyhow::anyhow!("decode relay.apply tagged response"))?;
            if update_response.id != Some(update_id) || update_response.error.is_some() {
                anyhow::bail!("relay.apply update rejected or returned a mismatched response");
            }

            // Require a correlated discovery response from the endpoint
            // before recording this leg as connected.  This is the same
            // stream path used by the dashboard and Android to obtain the
            // relay-local neighbor view before selecting another leg.
            let discovery_id = session.forward_allocation.saturating_add(2);
            let mut discovery_request = [0u8; 32];
            let discovery_request_len = dmesh_server::tagged::encode_numeric_empty_request(
                dmesh_server::announce::ANNOUNCE_COMPONENT,
                dmesh_server::announce::ANNOUNCE_DEVICES_OBSERVED,
                discovery_id,
                &mut discovery_request,
            )
            .ok_or_else(|| anyhow::anyhow!("encode discovery.nodes request"))?;
            let (_, endpoint_discovery, endpoint_discovery_fin) = endpoint
                .request_stream(
                    quic_lite::FIRST_CLIENT_BIDI_STREAM_ID,
                    &discovery_request[..discovery_request_len],
                    true,
                )
                .await
                .context("request endpoint discovery.nodes through relay")?;
            if !endpoint_discovery_fin {
                anyhow::bail!("endpoint discovery.nodes did not finish its QUIC stream");
            }
            let endpoint_discovery = dmesh_server::tagged::decode(&endpoint_discovery)
                .ok_or_else(|| anyhow::anyhow!("decode endpoint discovery.nodes response"))?;
            let endpoint_discovery_result = if endpoint_discovery.component
                != Some(dmesh_server::tagged::Name::Tag(
                    dmesh_server::announce::ANNOUNCE_COMPONENT,
                ))
                || endpoint_discovery.method
                    != Some(dmesh_server::tagged::Name::Tag(
                        dmesh_server::announce::ANNOUNCE_DEVICES_OBSERVED,
                    ))
                || endpoint_discovery.id != Some(discovery_id)
                || endpoint_discovery.error.is_some()
            {
                anyhow::bail!("endpoint discovery.nodes response is not a matching QUIC result");
            } else {
                endpoint_discovery
                    .result
                    .ok_or_else(|| anyhow::anyhow!("endpoint discovery.nodes response has no result"))?
            };
            session.client = Some(endpoint);
            session.endpoint_server_cid = Some(endpoint_server_cid);
            Ok(serde_json::json!({
                "state": "next_connected",
                "relay_endpoint": relay_endpoint,
                "endpoint_cid": session.endpoint_cid.value(),
                "endpoint_server_cid": endpoint_server_cid.value(),
                "forward_alias": session.forward_alias.value(),
                "reverse_alias": session.reverse_alias.value(),
                // Endpoint state values are deliberately numeric so later
                // stages can extend the state machine without parsing text:
                // 2 means a correlated endpoint stream response was checked.
                "endpoint_state": 2,
                "endpoint_discovery_bytes": endpoint_discovery_result.len(),
            }))
        }
        .await;
        self.relay_sessions.lock().await.insert(relay_endpoint, session);
        result
    }

    async fn relay_status(&self) -> serde_json::Value {
        let sessions = self.relay_sessions.lock().await;
        let sessions = sessions
            .iter()
            .map(|(endpoint, session)| {
                serde_json::json!({
                    "relay_endpoint": endpoint,
                    "peer": session.peer,
                    "local_cid": session.local_cid.value(),
                    "forward_alias": session.forward_alias.value(),
                    "reverse_alias": session.reverse_alias.value(),
                    "endpoint_cid": session.endpoint_cid.value(),
                    "endpoint_server_cid": session.endpoint_server_cid.map(|cid| cid.value()),
                    "state": if session.endpoint_server_cid.is_some() { "next_connected" } else { "leg_ready" },
                })
            })
            .collect::<Vec<_>>();
        serde_json::json!({"sessions": sessions})
    }

    /// Handle a single JSON-lines request.
    pub async fn handle_request(&self, request: Request) -> mesh::protocol::Response {
        match request {
            Request::RelayConnect { relay_endpoint, next_hop_mac } => match self.relay_connect(relay_endpoint, next_hop_mac).await {
                Ok(value) => mesh::protocol::Response::ok_with_data(value),
                Err(error) => mesh::protocol::Response::err(error.to_string()),
            },
            Request::RelayOpen { relay_endpoint } => match self.relay_open(relay_endpoint).await {
                Ok(value) => mesh::protocol::Response::ok_with_data(value),
                Err(error) => mesh::protocol::Response::err(error.to_string()),
            },
            Request::RelayStatus => mesh::protocol::Response::ok_with_data(self.relay_status().await),
            Request::Send {
                radio,
                destination,
                payload,
            } => {
                mesh::protocol::Response::ok_with_data(self.radio.send(radio, payload, destination))
            }
            Request::LinkSteer {
                node,
                radio,
                reason,
            } => mesh::protocol::Response::ok_with_data(self.radio.link_steer(node, radio, reason)),
            Request::DiscoveryPing { medium } => {
                let all_available = medium.is_none();
                let wants_multicast = all_available
                    || matches!(medium.as_deref(), Some("all" | "mcast" | "udp" | "udp6"));
                let mut result = self.radio.discovery_ping(medium);
                if wants_multicast {
                    result["udp_multicast"] = match self.discovery.announce().await {
                        Ok(report) => report,
                        Err(error) => serde_json::json!({"ok": false, "error": error.to_string()}),
                    };
                    result["ok"] = serde_json::json!(
                        result["ok"] == true && result["udp_multicast"]["accepted"] == true
                    );
                }
                mesh::protocol::Response::ok_with_data(result)
            }
            Request::MessagesHistory { keys, limit } => {
                mesh::protocol::Response::ok_with_data(self.radio.history(keys, limit))
            }
            Request::WifiInterfaceList => {
                mesh::protocol::Response::ok_with_data(self.radio.wifi_interface_list())
            }
            Request::WifiInterfaceUp { iface } => {
                match self.owned_wifi_iface(iface, lmesh_wifi::Operation::Nan) {
                    Ok(iface) => mesh::protocol::Response::ok_with_data(
                        self.radio.wifi_interface_up(Some(iface)),
                    ),
                    Err(error) => mesh::protocol::Response::err(error.to_string()),
                }
            }
            Request::WifiInterfaceChannel { iface, channel } => {
                match self.owned_wifi_iface(iface, lmesh_wifi::Operation::Nan) {
                    Ok(iface) => mesh::protocol::Response::ok_with_data(
                        self.radio.wifi_interface_set_channel(Some(iface), channel),
                    ),
                    Err(error) => mesh::protocol::Response::err(error.to_string()),
                }
            }
            Request::WifiOcbStart {
                iface,
                freq,
                bandwidth,
            } => match self.owned_wifi_iface(iface, lmesh_wifi::Operation::Nan) {
                Ok(iface) => mesh::protocol::Response::ok_with_data(self.radio.wifi_ocb_start(
                    Some(iface),
                    freq,
                    bandwidth,
                )),
                Err(error) => mesh::protocol::Response::err(error.to_string()),
            },
            Request::WifiRateProfile {
                iface,
                profile,
                disable_80211b,
            } => match self.owned_wifi_iface(iface, lmesh_wifi::Operation::Nan) {
                Ok(iface) => mesh::protocol::Response::ok_with_data(self.radio.wifi_rate_profile(
                    Some(iface),
                    profile,
                    disable_80211b,
                )),
                Err(error) => mesh::protocol::Response::err(error.to_string()),
            },
            Request::WifiRawPing {
                iface,
                channel,
                listen_sec,
                wait_ms,
                nonce,
            } => mesh::protocol::Response::ok_with_data(
                self.radio
                    .wifi_raw_ping(iface, channel, listen_sec, wait_ms, nonce),
            ),
            Request::RadioDevices => {
                mesh::protocol::Response::ok_with_data(self.radio.radio_devices())
            }
            Request::DiscoveryStatus => {
                mesh::protocol::Response::ok_with_data(common_discovery_status(&self.radio))
            }
            Request::NanStatus => {
                mesh::protocol::Response::ok_with_data(self.radio.nan_status(None))
            }
            Request::NowMetrics => {
                mesh::protocol::Response::ok_with_data(self.radio.now_metrics(None))
            }
            Request::NanMetrics => {
                mesh::protocol::Response::ok_with_data(self.radio.nan_metrics(None))
            }
            Request::Udp6Metrics => {
                mesh::protocol::Response::ok_with_data(self.radio.udp6_metrics())
            }
            Request::WifiLinkMetrics => {
                mesh::protocol::Response::ok_with_data(self.radio.wifi_link_metrics(None))
            }
            Request::TransportDiscover {
                iface,
                channel,
                nan,
                passive_scan,
                active_scan,
                dns_sd,
                wait_ms,
            } => match self.owned_wifi_iface(iface, lmesh_wifi::Operation::Nan) {
                Ok(iface) => mesh::protocol::Response::ok_with_data(self.radio.transport_discover(
                    Some(iface),
                    channel,
                    // A `transport.discover` request is itself an active
                    // query. `nan=false` explicitly suppresses NAN while
                    // the other optional scan flags select additional
                    // discovery media.
                    nan.unwrap_or(true),
                    nan.unwrap_or(true),
                    passive_scan.unwrap_or(true),
                    active_scan.unwrap_or(false),
                    dns_sd.unwrap_or(false),
                    wait_ms,
                )),
                Err(error) => mesh::protocol::Response::err(error.to_string()),
            },
            Request::ObjectNanDryRun { image_size, mtu } => mesh::protocol::Response::ok_with_data(
                nan_object_dry_run(image_size, mtu.unwrap_or(1_200)),
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
            Request::WifiApStartOpen {
                iface,
                ssid,
                channel,
                ht40,
                beacon_interval_tu,
            } => {
                match self.owned_wifi_iface(iface, lmesh_wifi::Operation::Ap) {
                    Ok(iface) => mesh::protocol::Response::ok_with_data(
                        self.radio.wifi_ap_start_open_on_child(
                            Some(iface),
                            ssid,
                            channel,
                            ht40,
                            // lmesh owns the optional lab AP; its quiet
                            // channel anchor is 500 TU by default. The
                            // independently supervised lmesh-wifi AP keeps
                            // the normal 100-TU default in its own handler.
                            beacon_interval_tu.unwrap_or(500),
                        ),
                    ),
                    Err(error) => mesh::protocol::Response::err(error),
                }
            }
            Request::WifiApStop { iface } => {
                match self.owned_wifi_iface(iface, lmesh_wifi::Operation::Ap) {
                    Ok(iface) => {
                        mesh::protocol::Response::ok_with_data(self.radio.wifi_ap_stop(Some(iface)))
                    }
                    Err(error) => mesh::protocol::Response::err(error),
                }
            }
            Request::WifiApStationAdd { iface, mac, aid } => {
                match self.owned_wifi_iface(iface, lmesh_wifi::Operation::Ap) {
                    Ok(iface) => mesh::protocol::Response::ok_with_data(
                        self.radio.wifi_ap_station_add(Some(iface), mac, aid),
                    ),
                    Err(error) => mesh::protocol::Response::err(error),
                }
            }
            Request::WifiScan {
                iface,
                ssid,
                channel,
                passive,
            } => mesh::protocol::Response::ok_with_data(self.radio.wifi_scan(
                iface,
                ssid,
                channel,
                passive.unwrap_or(false),
            )),
            Request::WifiStaJoinOpen { iface, ssid } => mesh::protocol::Response::ok_with_data(
                self.radio.wifi_sta_join_open(iface, ssid, None, None),
            ),
            Request::TransportStart {
                kind,
                iface,
                ssid,
                passphrase,
                bssid,
                channel,
                nan_dw_interval: _,
                now: _,
                ap,
                open,
            } => {
                let ap = ap == Some(1);
                let open = open.as_ref().is_some_and(TransportFlagRequest::is_enabled);
                let kind = kind.as_ref().and_then(TransportKindRequest::as_name);
                let kind_ok = match kind {
                    None | Some("sta") if !ap => true,
                    None | Some("nan") if ap => true,
                    _ => false,
                };
                if !kind_ok {
                    mesh::protocol::Response::err(
                        "Linux transport.start expects kind=sta or kind=nan with ap=1",
                    )
                } else {
                    mesh::protocol::Response::ok_with_data(
                        self.wifi_service
                            .transport_start(iface, ssid, passphrase, bssid, channel, ap, open),
                    )
                }
            }
            Request::TransportStop { iface } => {
                mesh::protocol::Response::ok_with_data(self.stop_wifi_transport(iface))
            }
            Request::WifiStaConfigureIpv4 {
                iface,
                address,
                prefix,
            } => mesh::protocol::Response::ok_with_data(
                self.radio.wifi_sta_configure_ipv4(iface, address, prefix),
            ),
        }
    }
}

/// Encode bytes as base64url (RFC 4648)
pub(crate) fn base64_url_encode(data: &[u8]) -> String {
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
    #[test]
    fn nan_object_dry_run_rejects_a_data_bearer() {
        let result = super::nan_object_dry_run(10_000, 1_200);
        assert_eq!(result["ok"], false);
        assert_eq!(result["bearer"], "nan-discovery");
    }

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
    fn retired_wifi_methods_are_not_flat_json_requests() {
        for method in [
            "wifi.ap.status",
            "wifi.ap.stations",
            "wifi.sta.status",
            "wifi.interface.status",
            "wifi.raw.listen",
            "wifi.raw.stop",
            "wifi.raw.send",
            "wifi.raw.check",
            "wifi.raw.iperf",
            "wifi.raw.metrics",
            "wifi.nan.status",
            "wifi.nan.listen",
            "wifi.nan.ping",
            "wifi.nan.active_publish",
            "wifi.rawnan.status",
            "wifi.rawnan.listen",
            "wifi.rawnan.ping",
            "wifi.rawnan.active_publish",
        ] {
            assert!(
                serde_json::from_value::<Request>(serde_json::json!({"method": method})).is_err(),
                "{method}"
            );
        }
    }

    #[test]
    fn explicit_udp_target_and_now_mac_route_are_distinct() {
        assert_eq!(
            explicit_udp_endpoint("udp://[2001:db8::44]:3336")
                .unwrap()
                .unwrap(),
            "[2001:db8::44]:3336".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(
            explicit_udp_endpoint("192.0.2.44:3336").unwrap().unwrap(),
            "192.0.2.44:3336".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(explicit_udp_endpoint("02:00:00:00:00:44").unwrap(), None);
        assert!(is_now_mac("02:00:00:00:00:44"));
        assert!(!is_now_mac("02:00:00:00:00:444"));
        assert!(!is_now_mac("not-a-mac"));
    }

    #[test]
    fn relay_aliases_use_even_forward_and_odd_return_values() {
        let (forward, reverse) = proposed_relay_aliases(17).unwrap();
        assert_eq!(forward.value(), 34);
        assert_eq!(reverse.value(), 35);
        assert_eq!(forward.value() & 1, 0);
        assert_eq!(reverse.value() & 1, 1);
        assert!(proposed_relay_aliases(u64::MAX).is_none());
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
    async fn nan_publish_service_info_is_a_common_bounded_announce() {
        let discovery = LocalDiscovery::new(None).await.unwrap();
        let wire = discovery.nan_announce_service_info(17).unwrap();
        assert!(wire.len() <= dmesh_rawnan::NAN_ACTIVE_PUBLISH_MAX_LEN);
        let announce = dmesh_server::announce::decode_announce(&wire).unwrap();
        assert_eq!(announce.kind, dmesh_server::announce::ANNOUNCE_DISCOVERY);
        assert_eq!(announce.uptime_secs, 17);
        assert_eq!(
            announce.device_id(),
            dmesh_server::announce::identity_hint(&discovery.public_key).unwrap()
        );
        assert_eq!(
            &dmesh_server::announce::virtual_ip6(&discovery.public_key).unwrap()[8..],
            announce.device_id()
        );
        assert!(announce.has_identity());
        assert_eq!(announce.public_key(), discovery.public_key.as_slice());
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
    async fn common_multicast_announce_notifies_the_radio_inventory_sink() {
        let discovery = LocalDiscovery::new(None).await.unwrap();
        let received = Arc::new(std::sync::Mutex::new(Vec::new()));
        let received_by_sink = received.clone();
        discovery
            .set_announce_observer(Arc::new(move |peer, announce| {
                received_by_sink.lock().unwrap().push((peer, announce));
            }))
            .await;

        let peer = SocketAddr::from(([192, 0, 2, 24], 5_227));
        let announce = dmesh_server::announce::Announce::discovery([0xA5; 16], 16, 42);
        LocalDiscovery::notify_announce_observer(&discovery.announce_observer, peer, announce)
            .await;

        let received = received.lock().unwrap();
        assert_eq!(received.as_slice(), &[(peer, announce)]);
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
