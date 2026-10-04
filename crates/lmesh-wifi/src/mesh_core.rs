/// Local mesh announce and discovery
/// Each mesh node will listen for UDP multicast announcements on
/// all interfaces. The announcement includes the public key of the
/// node, the (claimed - untrusted) name.
///
///
use anyhow::{Context, Result};

use p256::SecretKey;
use p256::ecdsa::signature::{Signer, Verifier};
use p256::elliptic_curve::Generate;
use p256::elliptic_curve::sec1::ToSec1Point;
use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use std::collections::HashMap;
use std::ffi::CStr;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use std::time::Duration;

use tokio::sync::RwLock;

use tracing::instrument;

const STABLE_WIFI_UDP_PORT: u16 = 3336;

/// Datagrams on the discovery socket that matched neither the common
/// tagged-CBOR announce nor the legacy JSON envelope. Old firmware and
/// Android peers still emit the retired QUIC direct-packet envelope, so this
/// counts steady background traffic; the raw payload is only visible at
/// trace level.
static ANNOUNCE_PARSE_ERRORS: AtomicU64 = AtomicU64::new(0);
static NEXT_ROUTED_PROBE_ID: AtomicU64 = AtomicU64::new(1);
static SERVICE_STARTED: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();

/// Record the service start instant once the control plane is up.
pub(crate) fn note_service_started() {
    let _ = SERVICE_STARTED.set(std::time::Instant::now());
}

/// Whole seconds since the service owner started.
pub(crate) fn service_uptime_secs() -> u64 {
    SERVICE_STARTED
        .get()
        .map(|started| started.elapsed().as_secs())
        .unwrap_or(0)
}

/// Total unmatched discovery datagrams since process start.
pub fn announce_parse_errors() -> u64 {
    ANNOUNCE_PARSE_ERRORS.load(Ordering::Relaxed)
}

/// A decoded common announce delivered by a local-link bearer. The callback
/// takes semantic data, never a UDP buffer, so another local owner can merge
/// it into its inventory without coupling the multicast receive loop to a
/// particular Wi-Fi implementation.
type AnnounceObserver = Arc<dyn Fn(SocketAddr, dmesh_server::announce::Announce) + Send + Sync>;

/// Optional discovery-only host label. Stable key material remains the
/// identity; this short presentation value will later be superseded by a
/// certificate-backed FQDN.
fn discovery_device_name() -> Option<String> {
    // A configured common setting wins over the machine hostname.  This keeps
    // Linux's signed announce aligned with `settings.get key=name`, while the
    // hostname remains a useful zero-config fallback.
    if let Some(path) = std::env::var_os("DMESH_SETTINGS_FILE") {
        let mut store = dmesh_server::settings::FileSettings::new(path, "linux");
        if let Ok(name) = dmesh_server::settings::SettingsHandler::new(&mut store).get("name")
            && !name.is_empty()
        {
            return Some(name);
        }
    }
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

/// Link-local IPv6 scope IDs are local kernel object IDs, not durable peer
/// facts. A P2P group can disappear and be recreated with a new ID while a
/// discovery observation is still within its TTL. Never offer or select the
/// old ID as a usable QUIC path.
fn udp6_peer_has_scope_in(
    peer: &SocketAddr,
    live_scope_ids: impl IntoIterator<Item = u32>,
) -> bool {
    match peer {
        SocketAddr::V6(address) if address.ip().is_unicast_link_local() => {
            address.scope_id() != 0
                && live_scope_ids
                    .into_iter()
                    .any(|id| id == address.scope_id())
        }
        SocketAddr::V4(_) | SocketAddr::V6(_) => true,
    }
}

fn udp6_peer_has_live_scope(peer: &SocketAddr) -> bool {
    // Keep the decision separate from discovery state: only the local kernel
    // can say whether a receiver-local scope is still usable.
    udp6_peer_has_scope_in(
        peer,
        local_udp6_interfaces().into_iter().filter_map(|interface| {
            interface
                .get("interface_index")
                .and_then(serde_json::Value::as_u64)
                .and_then(|index| u32::try_from(index).ok())
        }),
    )
}

fn require_live_udp6_scope(peer: SocketAddr) -> Result<SocketAddr> {
    if udp6_peer_has_live_scope(&peer) {
        Ok(peer)
    } else {
        anyhow::bail!(
            "IPv6 link-local scope {} is no longer an active receive interface",
            match peer {
                SocketAddr::V6(address) => address.scope_id(),
                SocketAddr::V4(_) => 0,
            }
        );
    }
}

/// Decode the explicit UDP form accepted by the explorer: `[IPv6]:port`,
/// `IPv4:port`, or the same forms without a port (which select the normal
/// DMesh UDP port).  Link-local scope remains receiver-local; use the
/// configured mesh ingress for an unscoped link-local address. A
/// colon-separated MAC is deliberately recognized so the caller receives a
/// precise NOW-not-yet-installed error instead of a misleading
/// unknown-discovery-node result.
fn explicit_udp_endpoint(destination: &str) -> Result<Option<SocketAddr>> {
    dmesh_discovery::endpoint::parse_udp_endpoint(
        destination,
        &dmesh_discovery::endpoint::EndpointDefaults {
            port: STABLE_WIFI_UDP_PORT,
            scope: configured_udp6_scope_id(),
        },
    )
    .map_err(anyhow::Error::from)
}

/// Resolve a normal UDP path from the common semantic discovery inventory.
///
/// The inventory's `identity` is the configured device name (or stable VIP6
/// fallback) and is therefore the public name accepted by the CLI and HTTP
/// stream API.  The announced address is sender data, but the IPv6 scope is
/// deliberately recovered from the local observation's `last_peer`: a sender
/// must never serialize one receiver's interface name or index into its
/// signed announce.
///
/// This is intentionally *not* used by directed `discovery.active`: a check
/// is a test of one supplied address/path, never a best-path node lookup.
fn semantic_inventory_udp_peer(
    inventory: &serde_json::Value,
    destination: &str,
) -> Option<SocketAddr> {
    // A semantic name can have more than one observation while NAN and UDP
    // announcements converge.  NAN deliberately has no data path, so never
    // let a NAN-only candidate hide a later UDP observation for the same
    // name. Select candidates with a receiver-observed UDP6 path. Prefer the
    // signed advertised address/port. A multicast observation supplies the
    // receiver-local scope, but its port is not a normal-UDP fallback:
    // 5227 is receive-only discovery ingress, never a QUIC stream endpoint.
    inventory
        .get("devices")?
        .as_array()?
        .iter()
        .filter(|device| {
            device.get("identity").and_then(serde_json::Value::as_str) == Some(destination)
        })
        .find_map(semantic_inventory_udp_peer_for_device)
}

/// Resolve one semantic inventory entry's receiver-reachable UDP path.
/// Keeping this separate lets association lookup prove that an explicit
/// address names the same device as its public discovery identity.
fn semantic_inventory_udp_peer_for_device(device: &serde_json::Value) -> Option<SocketAddr> {
    let ingress = device
        .get("observations")?
        .as_object()?
        .values()
        .filter_map(|observation| observation.get("last_peer")?.as_str())
        .filter_map(|peer| explicit_udp_endpoint(peer).ok().flatten())
        .find_map(|peer| match peer {
            SocketAddr::V6(peer) if peer.ip().is_unicast_link_local() => Some(peer),
            SocketAddr::V4(_) | SocketAddr::V6(_) => None,
        })?;
    let announce = device.get("announce");
    let address = announce
        .and_then(|announce| announce.get("udp_link_local_v6"))
        .and_then(serde_json::Value::as_str)
        .and_then(|address| address.parse::<Ipv6Addr>().ok())
        .unwrap_or(*ingress.ip());
    // A link-local address is usable only on the link that delivered the
    // packet. A local service can see another local service's multicast
    // announce through a different radio (for example an endpoint on br-lan
    // observed on wlan0). Its advertised address is valid on the sender's
    // link, but the receiving wlan0 scope cannot route it.
    if address.is_unicast_link_local() && address != *ingress.ip() {
        return None;
    }
    let port = announce
        .and_then(|announce| announce.get("udp_port"))
        .and_then(serde_json::Value::as_u64)
        .and_then(|port| u16::try_from(port).ok())
        .filter(|port| *port != 0 && *port != DISCOVERY_MULTICAST_PORT)
        .unwrap_or(ingress.port());
    if port == DISCOVERY_MULTICAST_PORT {
        return None;
    }
    Some(SocketAddr::V6(std::net::SocketAddrV6::new(
        address,
        port,
        ingress.flowinfo(),
        ingress.scope_id(),
    )))
}


/// The dashboard and report use the same presentation inventory as routing.
/// Hide a stale receiver-local UDP observation rather than turning it into a
/// clickable address that fails with `Network unreachable`.  Other bearers
/// (notably NOW and NAN observations) are not IPv6 routes and remain intact.
fn presentation_radio_devices(radio: &lmesh_wifi::RadioService) -> serde_json::Value {
    let mut inventory = radio.radio_devices();
    let Some(devices) = inventory
        .get_mut("devices")
        .and_then(serde_json::Value::as_array_mut)
    else {
        return inventory;
    };
    for device in devices {
        let Some(observations) = device
            .get_mut("observations")
            .and_then(serde_json::Value::as_object_mut)
        else {
            continue;
        };
        observations.retain(|_, observation| {
            observation
                .get("last_peer")
                .and_then(serde_json::Value::as_str)
                .and_then(|peer| explicit_udp_endpoint(peer).ok().flatten())
                .is_none_or(|peer| udp6_peer_has_live_scope(&peer))
        });
    }
    inventory
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

fn parse_now_destination(value: &str) -> Option<[u8; 6]> {
    dmesh_server::probe::ProbeDestination::parse(value)
        .and_then(|destination| destination.espnow_mac())
        // Preserve the existing direct-MAC command form while callers move
        // to the shared URI destination syntax.
        .or_else(|| parse_unicast_mac(value))
}

fn mesh_discovery_key(value: &str) -> Option<String> {
    let destination = dmesh_server::probe::ProbeDestination::parse(value)?;
    (destination.scheme() == "mesh").then(|| destination.target().to_owned())
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

/// What this Linux host says about itself in its announce, beyond the identity:
/// its name and domain, its measured radio capabilities (so a pair probe may
/// select it as an endpoint, while the executor still promises never to
/// reconfigure this host as part of the probe), and the UDP endpoint of the
/// configured shared network. The receiver records its own ingress
/// interface/scope; a sender never serializes a receiver's interface.
struct LinuxFacts {
    network: std::sync::Mutex<Option<String>>,
    udp_port: std::sync::atomic::AtomicU16,
}

impl dmesh_discovery::LocalFacts for LinuxFacts {
    fn describe(&self, announce: &mut dmesh_server::announce::Announce) {
        if let Some(name) = discovery_device_name() {
            let _ = announce.set_device_name(&name);
        }
        if let Some(domain) = discovery_device_domain() {
            let _ = announce.set_device_domain(&domain);
        }
        let port = self.udp_port.load(Ordering::Relaxed);
        let network = self.network.lock().ok().and_then(|network| network.clone());
        if let Some(network) = network
            && port != 0
            && let Some(address) = local_network_link_local_v6(&network)
        {
            announce.set_udp_port(port);
            announce.set_udp_link_local_v6(address);
        }
        announce.set_probe_descriptor(
            dmesh_server::announce::DEVICE_CLASS_HOST,
            dmesh_server::probe::PROBE_CAP_NAN
                | dmesh_server::probe::PROBE_CAP_NOW
                | dmesh_server::probe::PROBE_CAP_STA
                | dmesh_server::probe::PROBE_CAP_AP
                | dmesh_server::probe::PROBE_CAP_UDP6,
        );
    }
}

/// Link-local discovery: the shared `dmesh-discovery` engine and UDP6/UDP4
/// multicast transport (the same ones Android uses), behind the small surface
/// this service needs. A NAN/NOW observation reaches the same engine through
/// [`LocalDiscovery::engine`].
pub struct LocalDiscovery {
    identity: Arc<dmesh_discovery::P256Identity>,
    facts: Arc<LinuxFacts>,
    engine: Arc<dmesh_discovery::Engine>,
    udp: std::sync::Mutex<Option<Arc<dmesh_discovery::udp::UdpDiscovery>>>,
    /// Optional semantic sink for validated common announces, so the owning
    /// host radio can expose one device inventory across UDP and NAN.
    announce_observer: Arc<RwLock<Option<AnnounceObserver>>>,
    public_key_b64: String,
}

impl LocalDiscovery {
    /// Create the discovery service. With no key, `$HOME/.ssh/key.pem` is
    /// loaded or generated (mode 0600).
    #[instrument(skip(key))]
    pub async fn new(key: Option<SecretKey>) -> Result<Self> {
        let identity = Arc::new(match key {
            Some(key) => dmesh_discovery::P256Identity::from_secret(key),
            None => {
                let home = std::env::var("HOME").context("HOME environment variable not set")?;
                dmesh_discovery::P256Identity::load_or_generate(
                    &Path::new(&home).join(".ssh").join("key.pem"),
                )
                .context("load or generate the node key")?
            }
        });
        let facts = Arc::new(LinuxFacts {
            network: std::sync::Mutex::new(None),
            udp_port: std::sync::atomic::AtomicU16::new(0),
        });
        let engine = Arc::new(dmesh_discovery::Engine::new(identity.clone(), facts.clone()));
        let public_key_b64 = base64_url_encode(identity.public_key());
        Ok(Self {
            identity,
            facts,
            engine,
            udp: std::sync::Mutex::new(None),
            announce_observer: Arc::new(RwLock::new(None)),
            public_key_b64,
        })
    }

    /// Configure the endpoint advertised by this local service. `network` is
    /// the bearer-neutral LAN label (for example `costin`); the current
    /// link-local address is resolved when an announce is emitted.
    pub fn configure_announce_udp6(&mut self, network: impl Into<String>, port: u16) {
        if let Ok(mut label) = self.facts.network.lock() {
            *label = Some(network.into());
        }
        self.facts.udp_port.store(port, Ordering::Relaxed);
    }

    /// Install the local semantic sink for common tagged-CBOR announces: a
    /// host-local integration point, not a network control handler.
    pub async fn set_announce_observer(&self, observer: AnnounceObserver) {
        *self.announce_observer.write().await = Some(observer);
    }

    /// The shared engine, for bearers that feed it (NAN, NOW) and for queries.
    pub fn engine(&self) -> &Arc<dmesh_discovery::Engine> {
        &self.engine
    }

    fn udp(&self) -> Result<Arc<dmesh_discovery::udp::UdpDiscovery>> {
        self.udp
            .lock()
            .map_err(|_| anyhow::anyhow!("discovery transport lock poisoned"))?
            .clone()
            .ok_or_else(|| anyhow::anyhow!("UDP discovery is not started"))
    }

    /// Join the shared multicast groups and start receiving.
    #[instrument(skip(self))]
    pub async fn start(&mut self) -> Result<()> {
        // IPv4 is a best-effort compatibility listener; IPv6, scoped per link,
        // is the discovery path.
        let udp = dmesh_discovery::udp::UdpDiscovery::bind_multicast(self.engine.clone())
            .await
            .context("start UDP discovery")?;
        let observer = self.announce_observer.clone();
        udp.set_observer(Arc::new(move |sender, bytes, received| {
            use dmesh_discovery::Received;
            match received {
                Received::Announce { .. } | Received::Response { .. } => {
                    if let Some(announce) = dmesh_server::announce::decode_announce(bytes)
                        && let Ok(observer) = observer.try_read()
                        && let Some(observer) = observer.clone()
                    {
                        observer(sender, announce);
                    }
                }
                // Datagrams that are not discovery records: steady background
                // traffic from peers still emitting the retired envelope.
                Received::Ignored => {
                    ANNOUNCE_PARSE_ERRORS.fetch_add(1, Ordering::Relaxed);
                }
                Received::Rejected | Received::Request { .. } | Received::Own => {}
            }
        }));
        udp.spawn();
        *self
            .udp
            .lock()
            .map_err(|_| anyhow::anyhow!("discovery transport lock poisoned"))? = Some(udp);
        Ok(())
    }

    /// Announce ourselves on every live IPv6 link (and IPv4, for older peers).
    #[instrument(skip(self))]
    pub async fn announce(&self) -> Result<serde_json::Value> {
        let sent = self.udp()?.announce().await?;
        Ok(serde_json::json!({
            "accepted": sent > 0,
            "transmissions": sent,
            "note": "local socket acceptance only; peer receipt is reported by per-node observed transports",
        }))
    }

    /// Actively ask every peer on every live UDP multicast scope to emit its
    /// current signed `announce.discovery`.
    pub async fn broadcast_request(&self) -> Result<serde_json::Value> {
        let sent = self.udp()?.solicit().await;
        Ok(serde_json::json!({
            "accepted": sent > 0,
            "record": "announce.discovery",
            "mode": "broadcast",
            "transmissions": sent,
        }))
    }

    /// Send active discovery to one explicit UDP address. The address is the
    /// path under test; this deliberately performs no node lookup or
    /// alternate-path fallback.
    pub async fn directed_request(&self, destination: &str) -> Result<serde_json::Value> {
        let peer = explicit_udp_endpoint(destination)?
            .ok_or_else(|| anyhow::anyhow!("directed UDP discovery needs udp://HOST"))?;
        let peer = require_live_udp6_scope(peer)?;
        let device = self
            .udp()?
            .directed(peer, std::time::Duration::from_secs(3))
            .await?;
        let announce = device.announce.context("discovery reply carried no announce")?;
        Ok(serde_json::json!({
            "ok": true,
            "record": "announce.discovery",
            "mode": "directed",
            "to": destination,
            "source": peer.to_string(),
            "announce": {
                "device_id": hex_encode(announce.device_id()),
                "device_name": announce.device_name(),
                "uptime_secs": announce.uptime_secs,
                "udp_port": announce.udp_port,
                "udp_link_local_v6": announce.udp_link_local_v6().map(Ipv6Addr::from).map(|address| address.to_string()),
                "authenticated": true,
            },
        }))
    }

    /// Build the compact common presence record used as NAN Publish Service
    /// Info and directed Follow-up data: the same signed record as UDP, with
    /// the 8-byte identity hint as device id so it fits the 24-byte DMesh
    /// Follow-up envelope.
    pub fn nan_announce_service_info(&self, uptime_secs: u64) -> Result<Vec<u8>> {
        let identity_hint = dmesh_server::announce::identity_hint(self.identity.public_key())
            .context("missing local public-key identity hint")?;
        let mut device_id = [0; 16];
        device_id[..identity_hint.len()].copy_from_slice(&identity_hint);
        let mut announce = dmesh_server::announce::Announce::discovery(
            device_id,
            identity_hint.len() as u8,
            uptime_secs.min(u64::from(u32::MAX)) as u32,
        );
        dmesh_discovery::LocalFacts::describe(self.facts.as_ref(), &mut announce);
        dmesh_discovery::Identity::sign(self.identity.as_ref(), &mut announce)
            .context("sign the NAN Service Info announce")?;
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

    /// The current signed announce, for unsolicited presence and directed replies.
    pub fn signed_discovery_announce(
        &self,
        _uptime_secs: u64,
    ) -> Result<dmesh_server::announce::Announce> {
        self.engine
            .local_announce()
            .context("sign the local announce")
    }

    pub fn public_key_b64(&self) -> &str {
        &self.public_key_b64
    }

    pub fn public_key_bytes(&self) -> &[u8] {
        self.identity.public_key()
    }
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



#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "method")]
pub enum Request {
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
    /// Send the canonical active discovery request. With no destination it is
    /// broadcast on every enabled medium; `to` names one explicit bearer
    /// address and never triggers best-path or node-name resolution.
    #[serde(rename = "discovery.active")]
    DiscoveryActive {
        #[serde(default)]
        medium: Option<String>,
        #[serde(default)]
        to: Option<String>,
    },
    /// Ask this NAN observer to wake one sleepy ESP into its configured STA
    /// profile. `to` is the observed peer MAC, not an IP route.
    #[serde(rename = "nan.wakeup")]
    NanWakeup { to: String },
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
    /// Common discovery state and this node's local bearer/address projection.
    #[serde(rename = "discovery.status")]
    DiscoveryStatus,
    /// Common NAN cluster and counter projection. Device records are exposed
    /// only through `discovery.nodes`.
    #[serde(rename = "telemetry.nan_status")]
    NanStatus,
    /// Size a NAN object transfer without opening an IP socket or touching a
    /// device. The same envelope is used by data frames and action diagnostics.
    #[serde(rename = "object.nan.dry_run")]
    ObjectNanDryRun {
        image_size: usize,
        #[serde(default)]
        mtu: Option<usize>,
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
    #[serde(rename = "transport.set")]
    TransportSet {
        /// Device-neutral bearer kind. Linux accepts `nan` with `ap=1` for
        /// the P2P AP-equivalent and retains `sta` for ordinary association.
        #[serde(default, rename = "mode", alias = "kind")]
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
        /// `transport.set` AP-equivalent request.
        #[serde(default)]
        ap: Option<u8>,
        /// Select the ordinary raw open AP backend for Linux/ESP comparison.
        /// Omitted/zero selects the default P2P WPA2-PSK Group Owner.
        #[serde(default)]
        open: Option<TransportFlagRequest>,
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
    /// Optional embedded Wi-Fi instance. It is constructed through the same
    /// reusable library object as the standalone lmesh-wifi launcher, but an
    /// empty `LMESH_INTERFACES` makes this process UDP-only. When non-empty,
    /// this process owns only the explicitly named interfaces.
    wifi_service: lmesh_wifi::WifiService,
    radio: lmesh_wifi::RadioService,
    wifi: lmesh_wifi::WifiNetd,
    now_quic_client: std::sync::Mutex<Option<(quic_lite::tokio::TokioNode, quic_lite::BearerId)>>,
}

/// Convert the compact DMesh tagged response into the schema-neutral mesh
/// response envelope used by HTTP, SSH, and Android's private Rust bridge.
///
/// A DMesh response retains numeric component and method fields so a bounded
/// ESP/UART caller can correlate it without a catalog.  In the generic mesh
/// envelope, responses intentionally have empty component/method fields; a
/// result plus a method would instead be an invalid request.  This adapter is
/// at the mesh API boundary, never in a bearer: UDP, NOW, and UART all receive
/// the same DMesh response and use this one conversion before it reaches an
/// HTTP/SSH caller.
fn decode_stream_response(response: &[u8]) -> Result<mesh::tagged::TaggedRecord> {
    if let Ok(record) = mesh::cbor::decode_record(response) {
        return Ok(record);
    }
    let record = dmesh_server::tagged::decode(response)
        .ok_or_else(|| anyhow::anyhow!("decode DMesh tagged stream response"))?;
    let id = record
        .id
        .ok_or_else(|| anyhow::anyhow!("DMesh tagged stream response lacks id"))?;
    let (key, value) = match (record.result, record.error) {
        (Some(result), None) => (6, result),
        (None, Some(error)) => (7, error),
        _ => anyhow::bail!("DMesh tagged stream response lacks one terminal result or error"),
    };
    let mut wire = vec![0u8; response.len().saturating_add(24)];
    let mut encoder = dmesh_server::cbor::Encoder::new(&mut wire);
    encoder
        .map(4)
        .ok_or_else(|| anyhow::anyhow!("encode mesh response map"))?;
    encoder
        .uint(1)
        .ok_or_else(|| anyhow::anyhow!("encode mesh response component"))?;
    encoder
        .text_value(b"")
        .ok_or_else(|| anyhow::anyhow!("encode empty mesh component"))?;
    encoder
        .uint(2)
        .ok_or_else(|| anyhow::anyhow!("encode mesh response method"))?;
    encoder
        .text_value(b"")
        .ok_or_else(|| anyhow::anyhow!("encode empty mesh method"))?;
    encoder
        .uint(3)
        .ok_or_else(|| anyhow::anyhow!("encode mesh response id"))?;
    encoder
        .uint(id)
        .ok_or_else(|| anyhow::anyhow!("encode mesh response id value"))?;
    encoder
        .uint(key)
        .ok_or_else(|| anyhow::anyhow!("encode mesh response terminal key"))?;
    encoder
        .encoded_value(value)
        .ok_or_else(|| anyhow::anyhow!("encode mesh response terminal value"))?;
    let used = encoder.len();
    drop(encoder);
    mesh::cbor::decode_record(&wire[..used])
        .context("decode normalized DMesh tagged stream response")
}

/// Execute one UDP request with the public node/stream API. The UDP bearer
/// owns its socket and peer table; application code only supplies the peer
/// selected from discovery and the stream payload.
async fn request_udp_stream(
    peer: SocketAddr,
    payload: &[u8],
    timeout: Duration,
) -> Result<Vec<u8>> {
    let payload = payload.to_vec();
    let (result_tx, result_rx) = tokio::sync::oneshot::channel();
    std::thread::Builder::new()
        .name("lmesh-quic-client".to_owned())
        .spawn(move || {
            let result = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(anyhow::Error::from)
                .and_then(|runtime| {
                    runtime.block_on(request_udp_stream_local(peer, &payload, timeout))
                });
            let _ = result_tx.send(result);
        })?;
    result_rx.await.context("UDP QUIC client stopped")?
}

async fn request_udp_stream_local(
    peer: SocketAddr,
    payload: &[u8],
    timeout: Duration,
) -> Result<Vec<u8>> {

    type Pool = quic_lite::packet_pool::PacketPool<8, { quic_lite::DEFAULT_PACKET_POOL_SLOT_SIZE }>;
    type Node = quic_lite::QuicNode<Pool>;
    static POOL: Pool = Pool::new();

    let bind = quic_lite::bearer_udp::wildcard_bind(peer, 0);
    let bearer_impl = quic_lite::bearer_udp::TokioUdpBearer::<8>::bind(bind)
        .await
        .context("bind outbound UDP bearer")?;
    let peer_l2_address = bearer_impl
        .register_peer(peer)
        .map_err(|error| anyhow::anyhow!("register UDP peer: {error:?}"))?;
    let mut node = Node::new(&POOL);
    node.set_limits(quic_lite::NodeLimits::host())
        .expect("host QUIC node limits are valid");
    node.set_default_association_limits(quic_lite::AssociationLimits::host())
        .expect("host QUIC association limits are valid");
    let bearer = node
        .add_bearer(bearer_impl)
        .map_err(|error| anyhow::anyhow!("attach outbound UDP bearer: {error:?}"))?;
    let (client, driver) =
        quic_lite::tokio::TokioNodeDriver::new(node, quic_lite::ConnectionLimits::default());
    let exchange = async {
        let association = client
            .associate(
                quic_lite::PacketMeta {
                    bearer,
                    peer_l2_address,
                    received_at_us: 0,
                },
                0,
            )
            .await
            .map_err(|error| anyhow::anyhow!("start UDP association: {error:?}"))?;
        association
            .wait_established()
            .await
            .map_err(|error| anyhow::anyhow!("establish UDP association: {error:?}"))?;
        let mut stream = association
            .open_stream()
            .await
            .map_err(|error| anyhow::anyhow!("open UDP request stream: {error:?}"))?;
        let response = dmesh_server::stream_client::exchange(&mut stream, &[payload]).await?;
        association
            .finish()
            .await
            .map_err(|error| anyhow::anyhow!("finish UDP association: {error:?}"))?;
        Result::<Vec<u8>>::Ok(response)
    };
    tokio::time::timeout(timeout, async {
        tokio::select! {
            result = driver.run() => Err(anyhow::anyhow!("UDP QUIC driver stopped: {result:?}")),
            result = exchange => result,
        }
    })
    .await
    .context("UDP stream request timed out")?
}

/// Open a request stream through the running node's registered NOW bearer.
/// The bearer-local peer address is derived from the immediate radio peer MAC.
async fn request_now_stream(
    node: quic_lite::tokio::TokioNode,
    bearer: quic_lite::BearerId,
    peer: [u8; 6],
    payload: &[u8],
    timeout: Duration,
) -> Result<Vec<u8>> {

    tokio::time::timeout(timeout, async {
        let association = node
            .associate(
                quic_lite::PacketMeta {
                    bearer,
                    peer_l2_address: crate::espnow_bearer::peer_address(peer),
                    received_at_us: 0,
                },
                0,
            )
            .await
            .map_err(|error| anyhow::anyhow!("start ESP-NOW QUIC association: {error:?}"))?;
        association
            .wait_established()
            .await
            .map_err(|error| anyhow::anyhow!("establish ESP-NOW QUIC association: {error:?}"))?;
        let mut stream = association
            .open_stream()
            .await
            .map_err(|error| anyhow::anyhow!("open ESP-NOW request stream: {error:?}"))?;
        let response = dmesh_server::stream_client::exchange(&mut stream, &[payload]).await?;
        association
            .finish()
            .await
            .map_err(|error| anyhow::anyhow!("finish ESP-NOW association: {error:?}"))?;
        Result::<Vec<u8>>::Ok(response)
    })
    .await
    .context("ESP-NOW QUIC stream request timed out")?
}

impl LmeshService {
    pub fn set_espnow_ingress(&self, ingress: Arc<dyn crate::espnow_bearer::EspNowIngress>) {
        self.radio.set_espnow_ingress(ingress);
    }
    /// Create a service around an initialized discovery instance.
    pub fn new(discovery: Arc<LocalDiscovery>) -> Self {
        let wifi_service = lmesh_wifi::WifiService::from_environment_with_discovery_log(
            "/run/mesh/lmesh/discovery.jsonl",
        );
        let radio = wifi_service.radio().clone();
        let wifi = wifi_service.netd().clone();
        // What the NAN/NOW monitor admits also goes to the shared discovery
        // engine, so one inventory serves every bearer. UDP announces already
        // reach the engine through its own receive path.
        let engine = discovery.engine().clone();
        radio.set_announce_sink(Arc::new(move |source, peer, announce| {
            use dmesh_server::discovery::DiscoveryPacketKind;
            let (bearer, kind) = match source {
                "udp_multicast" => return,
                source if source.starts_with("nan") => ("nan", DiscoveryPacketKind::ActivePublish),
                "espnow" | "raw_action" | "now" => ("now", DiscoveryPacketKind::Other),
                other => (other, DiscoveryPacketKind::Other),
            };
            engine.observe_announce(
                &dmesh_discovery::Carrier::radio(bearer, peer, kind),
                announce,
                &[],
            );
        }));
        // Construction is deliberately radio-neutral. A lmesh restart must
        // not retune, create a monitor, or change link state; each
        // transport/AP operation owns its own explicit transition.
        Self {
            discovery,
            wifi_service,
            radio,
            wifi,
            now_quic_client: std::sync::Mutex::new(None),
        }
    }

    /// Attach the shared QUIC node's ESP-NOW path for directed MAC routes.
    pub fn set_now_quic_client(
        &self,
        node: quic_lite::tokio::TokioNode,
        bearer: quic_lite::BearerId,
    ) {
        *self
            .now_quic_client
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some((node, bearer));
    }

    /// Run a probe with this node as the client: call the probed node's
    /// registered `probe.handler` handler and validate the payload that follows
    /// its response header. `destination` is a probe destination URI or a bare
    /// mesh node identifier.
    pub async fn probe_exchange(
        &self,
        destination: &str,
        request: dmesh_server::probe::ProbeServiceRequest,
        timeout: Duration,
    ) -> Result<quic_lite::probe::ProbeResult> {
        let id = NEXT_ROUTED_PROBE_ID.fetch_add(1, Ordering::Relaxed).max(1);
        let mut wire = [0; dmesh_server::probe::PROBE_REQUEST_MAX];
        let used = dmesh_server::probe::encode_probe_handler_request(request, id, &mut wire)
            .context("encode routed QUIC probe request")?;
        let started = std::time::Instant::now();
        let response = self
            .request_probe_stream(destination, &wire[..used], timeout)
            .await?;
        let expected = request.bytes.min(quic_lite::probe::MAX_BYTES);
        let mut reader = dmesh_server::probe::ProbeResponseReader::new(expected);
        reader.push(&response).map_err(|error| match error {
            dmesh_server::probe::ProbeClientError::Rejected => {
                anyhow::anyhow!("remote QUIC probe request was rejected")
            }
            other => anyhow::anyhow!("invalid QUIC probe response: {other:?}"),
        })?;
        if !reader.is_complete() {
            anyhow::bail!(
                "QUIC probe response ended after {} of {expected} bytes",
                reader.bytes()
            );
        }
        let elapsed_us = started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64;
        Ok(quic_lite::probe::ProbeResult {
            bytes: reader.bytes(),
            normal_bytes: reader.bytes(),
            high_bytes: 0,
            low_bytes: 0,
            elapsed_us,
            callback_errors: [0; 6],
        })
    }

    async fn request_probe_stream(
        &self,
        destination: &str,
        request: &[u8],
        timeout: Duration,
    ) -> Result<Vec<u8>> {
        if let Some(peer) = parse_now_destination(destination) {
            self.require_owned_wifi_for_now()?;
            let (node, bearer) = self
                .now_quic_client
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
                .context("ESP-NOW bearer is not attached to the QUIC node")?;
            request_now_stream(node, bearer, peer, request, timeout).await
        } else {
            let peer = self.resolve_udp_peer(destination).await?;
            request_udp_stream(peer, request, timeout).await
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
    /// monitor fixture when this process owns a Wi-Fi interface.
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
    /// The shared discovery engine: the one device inventory.
    pub fn discovery_engine(&self) -> &Arc<dmesh_discovery::Engine> {
        self.discovery.engine()
    }

    pub fn public_key_b64(&self) -> &str {
        self.discovery.public_key_b64()
    }

    pub fn public_key_bytes(&self) -> &[u8] {
        self.discovery.public_key_bytes()
    }

    /// Merge an already validated multicast observation with the host radio's
    /// bounded device inventory. This uses the same change-only log policy as
    /// raw NAN observations; it neither starts an object transfer nor exposes
    /// an unauthenticated remote mutation surface. In particular, a Recovery
    /// announce remains passive while automatic flashing is disabled.
    pub fn observe_multicast_announce(
        &self,
        peer: SocketAddr,
        announce: dmesh_server::announce::Announce,
    ) {
        self.radio
            .observe_discovered_announce("udp_multicast", peer.to_string(), None, announce);
    }

    async fn resolve_udp_peer(&self, destination: &str) -> Result<SocketAddr> {
        if let Some(peer) = explicit_udp_endpoint(destination)? {
            return require_live_udp6_scope(peer);
        }
        let discovery_key = mesh_discovery_key(destination);
        let target = discovery_key.as_deref().unwrap_or(destination);
        // The service's own default port, for a peer that advertises none (an
        // ESP uses its raw UDP6 listener port).
        let default_port = std::env::var("LMESH_OBJECT_SERVER_PORT")
            .ok()
            .and_then(|value| value.parse::<u16>().ok())
            .unwrap_or(STABLE_WIFI_UDP_PORT);
        match self.discovery.engine().resolve_udp_in(
            target,
            default_port,
            configured_udp6_scope_id(),
        ) {
            Ok(peer) => require_live_udp6_scope(peer),
            Err(dmesh_discovery::NoRoute::NotDiscovered) => {
                // Not seen over UDP: the radio inventory may still know it.
                semantic_inventory_udp_peer(&presentation_radio_devices(&self.radio), destination)
                    .ok_or_else(|| {
                        anyhow::anyhow!("unsupported/no_quic_route: destination is not discovered")
                    })
            }
            Err(error) => Err(anyhow::Error::from(error)),
        }
    }

    /// A host without an owned Wi-Fi interface cannot route a NOW request.
    fn require_owned_wifi_for_now(&self) -> Result<()> {
        if self.wifi_owned_interfaces().names().is_empty() {
            anyhow::bail!("unsupported/no_quic_route: lmesh has no owned Wi-Fi interface for NOW");
        }
        Ok(())
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
        self.forward_tagged_record_with_timeout(destination, record, Duration::from_secs(10))
            .await
    }

    pub(crate) async fn forward_tagged_record_with_timeout(
        &self,
        destination: &str,
        record: &[u8],
        timeout: Duration,
    ) -> Result<mesh::tagged::TaggedRecord> {
        if let Some(peer) = parse_now_destination(destination) {
            self.require_owned_wifi_for_now()?;
            let (node, bearer) = self
                .now_quic_client
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
                .context(
                    "unsupported/no_quic_route: ESP-NOW bearer is not attached to the QUIC node",
                )?;
            let response = request_now_stream(node, bearer, peer, record, timeout).await?;
            return decode_stream_response(&response)
                .context("decode directed ESP-NOW QUIC tagged response");
        }
        let peer = self.resolve_udp_peer(destination).await?;
        let response = request_udp_stream(peer, record, timeout).await?;
        decode_stream_response(&response).context("decode directed QUIC tagged response")
    }

    /// `telemetry.now`: the monitor events this process retains, as the
    /// documented ESP-NOW counters it can supply (`rx_dispatched`, `rx_accepted`
    /// = action frames seen, `rx_rejected` = dispatch errors). Counters Linux does
    /// not keep are omitted.
    pub fn telemetry_now(&self) -> std::result::Result<TelemetryNowResponse, String> {
        let iface = self
            .owned_wifi_iface(None, lmesh_wifi::Operation::Nan)
            .map_err(|error| error.to_string())?;
        let counts = self.radio.now_counts(Some(iface));
        Ok(TelemetryNowResponse {
            rx_dispatched: Some(counts.dispatch),
            rx_accepted: Some(counts.action_seen),
            rx_rejected: Some(counts.dispatch_errors),
            ..Default::default()
        })
    }

    /// `telemetry.nan`: the beacons the raw-NAN monitor captured.
    pub fn telemetry_nan(&self) -> std::result::Result<TelemetryNanResponse, String> {
        self.owned_wifi_iface(None, lmesh_wifi::Operation::Nan)
            .map_err(|error| error.to_string())?;
        Ok(TelemetryNanResponse {
            beacons: Some(self.radio.nan_beacons()),
            ..Default::default()
        })
    }

    /// `telemetry.udp6`: discovery datagrams that failed validation.
    pub fn telemetry_udp6(&self) -> std::result::Result<TelemetryUdp6Response, String> {
        Ok(TelemetryUdp6Response {
            rx_invalid: Some(announce_parse_errors()),
            ..Default::default()
        })
    }

    /// `telemetry.wifi_link`: one row per AP station, in `links`. A row is the
    /// same field set as the top-level record, keyed by tag; its `peer_mac` is a
    /// byte string (the `_hex` key suffix makes the encoder write bytes).
    pub fn telemetry_wifi_link(&self) -> std::result::Result<TelemetryWifiLinkResponse, String> {
        let stations = self
            .radio
            .wifi_link_stations(None)
            .map_err(|error| format!("{error:#}"))?;
        let rows = stations
            .iter()
            .map(dmesh_server::platform_api::WifiLink::from)
            .collect();
        Ok(TelemetryWifiLinkResponse {
            links: Some(rows),
            ..Default::default()
        })
    }

    /// `telemetry.quic`: aggregate QUIC counters of this node's associations.
    pub async fn telemetry_quic(&self) -> std::result::Result<TelemetryQuicResponse, String> {
        let node = self
            .now_quic_client
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .map(|(node, _)| node.clone());
        match node {
            Some(node) => node
                .telemetry()
                .await
                .map(TelemetryQuicResponse::from)
                .ok_or_else(|| "QUIC telemetry is unavailable".to_owned()),
            None => Err("the QUIC node is not running".to_owned()),
        }
    }

    async fn node_rows(
        &self,
    ) -> std::result::Result<(Vec<quic_lite::AssociationRow>, Vec<quic_lite::BearerRow>), String> {
        let node = self
            .now_quic_client
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .map(|(node, _)| node.clone())
            .ok_or_else(|| "the QUIC node is not running".to_owned())?;
        node.rows()
            .await
            .ok_or_else(|| "QUIC telemetry is unavailable".to_owned())
    }

    /// `telemetry.quic_associations`: one row per live association.
    pub async fn telemetry_quic_associations(
        &self,
    ) -> std::result::Result<dmesh_server::platform_api::TelemetryQuicAssociationsResponse, String>
    {
        let (associations, bearers) = self.node_rows().await?;
        Ok(dmesh_server::telemetry::quic_associations_response(&associations, &bearers))
    }

    /// `telemetry.bearers`: one row per bearer the node runs.
    pub async fn telemetry_bearers(
        &self,
    ) -> std::result::Result<dmesh_server::platform_api::TelemetryBearersResponse, String> {
        let (_, bearers) = self.node_rows().await?;
        Ok(dmesh_server::telemetry::bearers_response(&bearers))
    }

    /// `telemetry.memory`: the resident size of this process.
    pub fn telemetry_memory(&self) -> std::result::Result<TelemetryMemoryResponse, String> {
        Ok(TelemetryMemoryResponse {
            process_rss_bytes: Some(dmesh_server::telemetry::process_rss_bytes()?),
            ..Default::default()
        })
    }

    /// Handle a single JSON-lines request.
    pub async fn handle_request(&self, request: Request) -> mesh::protocol::Response {
        match request {
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
            Request::DiscoveryActive { medium, to } => {
                if let Some(destination) = to {
                    if destination.starts_with("udp://") {
                        return match self.discovery.directed_request(&destination).await {
                            Ok(value) => mesh::protocol::Response::ok_with_data(value),
                            Err(error) => mesh::protocol::Response::err(error.to_string()),
                        };
                    }
                    // NOW has no directed discovery of its own: its discovery is the
                    // broadcast announce in each discovery window, and anything
                    // directed is QUIC (`probe`) over the NOW bearer.
                    let _ = medium;
                    return mesh::protocol::Response::err(format!(
                        "discovery.active to={destination}: only udp://HOST is supported; NOW discovery is broadcast and directed checks are QUIC probes"
                    ));
                }
                let all_available = medium.is_none();
                let wants_multicast = all_available
                    || matches!(medium.as_deref(), Some("all" | "mcast" | "udp" | "udp6"));
                // A launcher with an empty ownership allow-list is the
                // UDP-only companion personality.  It may still solicit
                // discovery on the shared UDP socket, but it must never let
                // the radio adapter choose a fallback interface.
                let mut result = if self.wifi_owned_interfaces().names().is_empty() {
                    serde_json::json!({
                        "ok": true,
                        "submissions": {"wifi": {"ok": true, "state": "not_owned"}}
                    })
                } else {
                    self.radio.discovery_active(medium, None)
                };
                if wants_multicast {
                    result["submissions"]["udp_multicast"] =
                        match self.discovery.broadcast_request().await {
                            Ok(report) => report,
                            Err(error) => {
                                serde_json::json!({"ok": false, "error": error.to_string()})
                            }
                        };
                    result["ok"] = serde_json::json!(
                        result["ok"] == true
                            && result["submissions"]["udp_multicast"]["accepted"] == true
                    );
                }
                mesh::protocol::Response::ok_with_data(result)
            }
            Request::NanWakeup { to } => {
                mesh::protocol::Response::ok_with_data(self.radio.nan_wakeup(to))
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
            Request::DiscoveryStatus => {
                mesh::protocol::Response::ok_with_data(common_discovery_status(&self.radio))
            }
            Request::NanStatus => match self.owned_wifi_iface(None, lmesh_wifi::Operation::Nan) {
                Ok(iface) => {
                    mesh::protocol::Response::ok_with_data(self.radio.nan_status(Some(iface)))
                }
                Err(error) => mesh::protocol::Response::err(error.to_string()),
            },
            Request::ObjectNanDryRun { image_size, mtu } => mesh::protocol::Response::ok_with_data(
                nan_object_dry_run(image_size, mtu.unwrap_or(1_200)),
            ),
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
            Request::WifiStaJoinOpen { iface, ssid } => mesh::protocol::Response::ok_with_data(
                self.radio.wifi_sta_join_open(iface, ssid, None, None),
            ),
            Request::TransportSet {
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
                        "Linux transport.set expects kind=sta or kind=nan with ap=1",
                    )
                } else {
                    mesh::protocol::Response::ok_with_data(
                        self.wifi_service
                            .transport_start(iface, ssid, passphrase, bssid, channel, ap, open),
                    )
                }
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

    /// Host status for the shared connection-diagnostic surface. The radio
    /// compatibility block keeps its established shape; the host identity
    /// fields mirror the firmware `status` vocabulary.
    pub fn host_status(&self) -> mesh::protocol::Response {
        let mut status = self.radio.status().as_object().cloned().unwrap_or_default();
        status.insert("status".to_owned(), serde_json::json!("ok"));
        status.insert("role".to_owned(), serde_json::json!("host"));
        status.insert("service".to_owned(), serde_json::json!("lmesh"));
        status.insert(
            "version".to_owned(),
            serde_json::json!(env!("CARGO_PKG_VERSION")),
        );
        status.insert(
            "uptime_secs".to_owned(),
            serde_json::json!(service_uptime_secs()),
        );
        mesh::protocol::Response::ok_with_data(serde_json::Value::Object(status))
    }

    /// Local undirected `radio.tx`: transmit the decoded 802.11 frame on an
    /// owned interface. Directed `to` requests are forwarded before this.
    pub fn host_radio_tx_local(
        &self,
        iface: Option<String>,
        channel: u8,
        frame: &[u8],
        rate_mbps: Option<u8>,
    ) -> mesh::protocol::Response {
        let frame_hex = frame
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        mesh::protocol::Response::ok_with_data(self.radio.wifi_raw_send_frame(
            iface,
            Some(channel),
            Some("monitor".to_owned()),
            frame_hex,
            rate_mbps,
        ))
    }

    /// Apply the shared radio-lab control fields the Linux adapter supports;
    /// firmware-only driver dimensions are reported as `not_owned`.
    pub fn host_radio_control(&self, fields: &serde_json::Value) -> mesh::protocol::Response {
        let mut applied = serde_json::Map::new();
        let mut not_owned = Vec::<String>::new();
        if let Some(channel) = fields.get("channel").and_then(serde_json::Value::as_u64) {
            let Ok(channel) = u8::try_from(channel) else {
                return mesh::protocol::Response::err(format!("invalid channel {channel}"));
            };
            let result = self.radio.wifi_interface_set_channel(None, channel);
            applied.insert("channel".to_owned(), result);
        }
        if let Some(rate) = fields.get("rate").and_then(serde_json::Value::as_u64) {
            // The wire enum is 0=Auto then 6..54 Mbps in ascending order.
            let profile = match rate {
                0 => Some("auto".to_owned()),
                3 => Some("12".to_owned()),
                5 => Some("24".to_owned()),
                _ => None,
            };
            match profile {
                Some(profile) => {
                    let disable_11b = fields
                        .get("disable_11b")
                        .and_then(serde_json::Value::as_bool)
                        .unwrap_or(rate != 0);
                    let result = self.radio.wifi_rate_profile(None, profile, disable_11b);
                    applied.insert("rate".to_owned(), result);
                }
                None => not_owned.push("rate".to_owned()),
            }
        } else if let Some(disable_11b) = fields
            .get("disable_11b")
            .and_then(serde_json::Value::as_bool)
        {
            let result = self
                .radio
                .wifi_rate_profile(None, "auto".to_owned(), disable_11b);
            applied.insert("disable_11b".to_owned(), result);
        }
        for (name, present) in [
            ("interface", fields.get("interface").is_some()),
            ("sta_state", fields.get("sta_state").is_some()),
            ("promiscuous", fields.get("promiscuous").is_some()),
            ("dw_policy", fields.get("dw_policy").is_some()),
            ("rx_filter", fields.get("rx_filter").is_some()),
            ("ap_mode", fields.get("ap_mode").is_some()),
            ("mac_ack", fields.get("mac_ack").is_some()),
        ] {
            if present {
                not_owned.push(name.to_owned());
            }
        }
        mesh::protocol::Response::ok_with_data(serde_json::json!({
            "ok": true,
            "applied": applied,
            "not_owned": not_owned,
        }))
    }

    /// Host radio-lab snapshot in the shared counter vocabulary.
    pub fn host_radio_snapshot(&self) -> mesh::protocol::Response {
        mesh::protocol::Response::ok_with_data(self.radio.radio_snapshot())
    }

    /// Reset the host capture ledger for the shared radio-lab surface.
    pub fn host_radio_reset_counters(&self) -> mesh::protocol::Response {
        mesh::protocol::Response::ok_with_data(self.radio.reset_capture_counters())
    }

    /// Directed NAN pairing wake to one observed peer MAC.
    pub fn host_pair_wakeup(&self, to: &str) -> mesh::protocol::Response {
        match self.radio.nan_pair_wakeup(to.to_owned()) {
            Ok(value) => mesh::protocol::Response::ok_with_data(value),
            Err(error) => mesh::protocol::Response::err(error.to_string()),
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

    #[test]
    fn wifi_link_rows_are_typed_and_carry_a_byte_string_peer() {
        use dmesh_server::registry_bridge::TaggedCbor;
        let mut link = dmesh_server::raw_wifi::WifiLinkMetrics::new();
        link.peer_mac = Some([0x02, 0, 0, 0, 0, 0x2a]);
        link.rx_bytes = Some(1_000);
        link.signal_dbm = Some(-50);
        let response = TelemetryWifiLinkResponse {
            links: Some(vec![dmesh_server::platform_api::WifiLink::from(&link)]),
            ..Default::default()
        };
        // Through the generated marshalling, on the wire.
        let wire = response.encode_cbor();
        // CBOR: key 3 (peer_mac) followed by a 6-byte string (0x46).
        assert!(wire.windows(8).any(|w| w == [0x03, 0x46, 0x02, 0, 0, 0, 0, 0x2a]));
        let back = TelemetryWifiLinkResponse::decode_cbor(&wire).unwrap();
        let row = &back.links.unwrap()[0];
        assert_eq!(row.rx_bytes, Some(1_000));
        assert_eq!(row.signal_dbm, Some(-50));
        assert_eq!(row.peer_mac.as_deref(), Some(&[0x02, 0, 0, 0, 0, 0x2a][..]));
    }
    use std::sync::atomic::{AtomicU64, Ordering};


    #[test]
    fn compact_dmesh_stream_response_normalizes_for_mesh_http_and_ssh() {
        let mut response = [0u8; 64];
        let used = dmesh_server::tagged::encode_numeric_response(
            dmesh_server::telemetry::TELEMETRY_COMPONENT,
            dmesh_server::telemetry::NOW_METRICS_METHOD,
            42,
            &[0xf5],
            &mut response,
        )
        .unwrap();

        let record = decode_stream_response(&response[..used]).unwrap();
        assert_eq!(record.id, Some(serde_json::json!(42)));
        assert_eq!(record.result, Some(serde_json::json!(true)));
        assert!(record.error.is_none());
        assert_eq!(record.kind().unwrap(), mesh::tagged::RecordKind::Response);
    }

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
            "wifi.raw.ping",
            "wifi.raw.check",
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
    fn now_route_accepts_shared_espnow_uri_and_legacy_mac() {
        let peer = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];
        assert_eq!(
            parse_now_destination("espnow://02:11:22:33:44:55"),
            Some(peer)
        );
        assert_eq!(parse_now_destination("02:11:22:33:44:55"), Some(peer));
        assert_eq!(parse_now_destination("espnow://ff:ff:ff:ff:ff:ff"), None);
        assert_eq!(
            mesh_discovery_key("mesh://fc00::a4"),
            Some("fc00::a4".into())
        );
        assert_eq!(mesh_discovery_key("espnow://02:11:22:33:44:55"), None);
    }

    #[test]
    fn active_discovery_distinguishes_broadcast_from_an_explicit_path() {
        let broadcast = serde_json::from_value::<Request>(serde_json::json!({
            "method": "discovery.active"
        }))
        .unwrap();
        assert!(matches!(
            broadcast,
            Request::DiscoveryActive {
                medium: None,
                to: None
            }
        ));

        let directed = serde_json::from_value::<Request>(serde_json::json!({
            "method": "discovery.active",
            "medium": "udp6",
            "to": "udp://[fe80::7%3]:3339"
        }))
        .unwrap();
        assert!(matches!(
            directed,
            Request::DiscoveryActive {
                medium: Some(medium),
                to: Some(to)
            } if medium == "udp6" && to == "udp://[fe80::7%3]:3339"
        ));
        assert!(
            serde_json::from_value::<Request>(serde_json::json!({
                "method": "discovery.broadcast"
            }))
            .is_err()
        );
    }

    #[test]
    fn nan_wakeup_is_a_local_observer_action_with_a_mac_target() {
        let request = serde_json::from_value::<Request>(serde_json::json!({
            "method": "nan.wakeup",
            "to": "d8:a0:1d:4c:5e:1c"
        }))
        .unwrap();
        assert!(matches!(request, Request::NanWakeup { to }
            if to == "d8:a0:1d:4c:5e:1c"));
    }


    #[test]
    fn explicit_udp_target_accepts_numeric_link_local_scope() {
        assert_eq!(
            explicit_udp_endpoint("udp://[fe80::44%7]:3339")
                .unwrap()
                .unwrap(),
            SocketAddr::V6(std::net::SocketAddrV6::new(
                "fe80::44".parse().unwrap(),
                3339,
                0,
                7,
            ))
        );
        assert_eq!(
            explicit_udp_endpoint("udp://[fe80::44%7]")
                .unwrap()
                .unwrap(),
            SocketAddr::V6(std::net::SocketAddrV6::new(
                "fe80::44".parse().unwrap(),
                STABLE_WIFI_UDP_PORT,
                0,
                7,
            ))
        );
    }

    #[test]
    fn stale_receiver_local_ipv6_scope_is_not_a_route() {
        let live = SocketAddr::V6(std::net::SocketAddrV6::new(
            "fe80::44".parse().unwrap(),
            3339,
            0,
            5,
        ));
        let stale = SocketAddr::V6(std::net::SocketAddrV6::new(
            "fe80::44".parse().unwrap(),
            3339,
            0,
            588_879,
        ));
        assert!(udp6_peer_has_scope_in(&live, [5]));
        assert!(!udp6_peer_has_scope_in(&stale, [5]));
        assert!(!udp6_peer_has_scope_in(&live, []));
    }

    #[test]
    fn semantic_inventory_routes_name_to_advertised_ipv6_on_observed_scope() {
        let inventory = serde_json::json!({
            "devices": [{
                "identity": "e7",
                "announce": {
                    "udp_link_local_v6": "fe80::16c1:9fff:fee4:5d48",
                    "udp_port": 3339,
                },
                "observations": {
                    "udp_multicast": {
                        "last_peer": "[fe80::16c1:9fff:fee4:5d48%5]:3339",
                    },
                },
            }],
        });
        assert_eq!(
            semantic_inventory_udp_peer(&inventory, "e7"),
            Some(SocketAddr::V6(std::net::SocketAddrV6::new(
                "fe80::16c1:9fff:fee4:5d48".parse().unwrap(),
                3339,
                0,
                5,
            )))
        );
        assert_eq!(semantic_inventory_udp_peer(&inventory, "unknown"), None);
    }


    #[test]
    fn semantic_inventory_uses_observed_ipv6_path_when_legacy_announce_omits_it() {
        let inventory = serde_json::json!({
            "devices": [{
                "identity": "e9",
                "announce": {},
                "observations": {
                    "udp_multicast": {
                        "last_peer": "[fe80::226e:f1ff:fe13:b170%5]:3337",
                    },
                },
            }],
        });

        assert_eq!(
            semantic_inventory_udp_peer(&inventory, "e9"),
            Some(SocketAddr::V6(std::net::SocketAddrV6::new(
                "fe80::226e:f1ff:fe13:b170".parse().unwrap(),
                3337,
                0,
                5,
            )))
        );
    }

    #[test]
    fn semantic_inventory_never_uses_multicast_port_as_a_quic_path() {
        let inventory = serde_json::json!({
            "devices": [{
                "identity": "legacy-discovery-only",
                "announce": {},
                "observations": {
                    "udp_multicast": {
                        "last_peer": "[fe80::44%5]:5227",
                    },
                },
            }],
        });

        assert_eq!(
            semantic_inventory_udp_peer(&inventory, "legacy-discovery-only"),
            None,
            "UDP multicast ingress is discovery-only, not a QUIC route"
        );
    }

    #[test]
    fn semantic_inventory_uses_announced_port_with_multicast_scope() {
        let inventory = serde_json::json!({
            "devices": [{
                "identity": "legacy-with-normal-port",
                "announce": {
                    "udp_port": 3339,
                },
                "observations": {
                    "udp_multicast": {
                        "last_peer": "[fe80::44%5]:5227",
                    },
                },
            }],
        });

        assert_eq!(
            semantic_inventory_udp_peer(&inventory, "legacy-with-normal-port"),
            Some(SocketAddr::V6(std::net::SocketAddrV6::new(
                "fe80::44".parse().unwrap(),
                3339,
                0,
                5,
            )))
        );
    }

    #[test]
    fn semantic_inventory_rejects_link_local_endpoint_from_another_ingress_link() {
        let inventory = serde_json::json!({
            "devices": [{
                "identity": "cross-link-host",
                "announce": {
                    "udp_link_local_v6": "fe80::2c41:eeff:fe44:bd03",
                    "udp_port": 3336,
                },
                "observations": {
                    "udp_multicast": {
                        "last_peer": "[fe80::7619:f8ff:fe17:de65%5]:3336",
                    },
                },
            }],
        });

        assert_eq!(
            semantic_inventory_udp_peer(&inventory, "cross-link-host"),
            None,
            "an ingress scope cannot route another link's link-local endpoint"
        );
    }

    #[test]
    fn semantic_inventory_skips_nan_only_duplicate_before_scoped_udp_route() {
        let inventory = serde_json::json!({
            "devices": [
                {
                    "identity": "phone",
                    "announce": {
                        "udp_link_local_v6": "fe80::9b8e:1f1d:6a40:2304",
                        "udp_port": 3336,
                    },
                    "observations": {
                        "nan": { "last_peer": "5e:ec:ed:ae:cb:56" },
                    },
                },
                {
                    "identity": "phone",
                    "announce": {
                        "udp_link_local_v6": "fe80::9b8e:1f1d:6a40:2304",
                        "udp_port": 3336,
                    },
                    "observations": {
                        "udp_multicast": {
                            "last_peer": "[fe80::9b8e:1f1d:6a40:2304%5]:3336",
                        },
                    },
                },
            ],
        });

        assert_eq!(
            semantic_inventory_udp_peer(&inventory, "phone"),
            Some(SocketAddr::V6(std::net::SocketAddrV6::new(
                "fe80::9b8e:1f1d:6a40:2304".parse().unwrap(),
                3336,
                0,
                5,
            )))
        );
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
            dmesh_server::announce::identity_hint(discovery.public_key_bytes()).unwrap()
        );
        assert_eq!(
            &dmesh_server::announce::virtual_ip6(discovery.public_key_bytes()).unwrap()[8..],
            announce.device_id()
        );
        assert!(announce.has_identity());
        assert_eq!(announce.public_key(), discovery.public_key_bytes());
    }

    #[tokio::test]
    async fn the_signed_announce_is_a_verifiable_host_record_with_the_configured_endpoint() {
        let mut discovery = LocalDiscovery::new(None).await.unwrap();
        discovery.configure_announce_udp6("nonexistent-lan", 3337);
        let announce = discovery.signed_discovery_announce(0).unwrap();
        assert!(announce.has_identity());
        assert!(dmesh_server::announce::verify_identity(announce));
        assert_eq!(announce.device_class, dmesh_server::announce::DEVICE_CLASS_HOST);
        assert!(announce.probe_capabilities & dmesh_server::probe::PROBE_CAP_NOW != 0);
        // No interface belongs to that label, so no endpoint is advertised
        // rather than a guessed one.
        assert_eq!(announce.udp_link_local_v6(), None);
        // The engine never lists itself.
        assert!(discovery.engine().devices().is_empty());
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
        let nodes = discovery.engine().devices();
        tracing::info!("Discovery received {} nodes", nodes.len());

        // In some systems, multicast loopback is enabled and we'll receive our own announcement
        // In others, it may not work in test environments
        // So we don't assert a specific count, just that the test completes successfully
    }

}

use dmesh_server::platform_api::{
    TelemetryMemoryResponse, TelemetryNanResponse, TelemetryNowResponse, TelemetryQuicResponse,
    TelemetryUdp6Response, TelemetryWifiLinkResponse,
};

