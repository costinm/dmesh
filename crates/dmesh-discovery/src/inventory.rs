//! The typed set of discovered devices.

use std::collections::BTreeMap;
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};

use dmesh_server::announce::{self, Announce, DiscoveryFacts};
use dmesh_server::discovery::{
    DiscoveryObservation, OBSERVATION_BSSID, OBSERVATION_CHANNEL, OBSERVATION_PAYLOAD_FINGERPRINT,
    OBSERVATION_PEER, OBSERVATION_RSSI,
};

use crate::engine::Carrier;

/// A device is keyed by its announced id, as lowercase hex.
pub type NodeKey = String;

/// Port assumed for an ESP device that advertises none (its raw UDP6 listener).
pub const ESP_UDP_PORT: u16 = 3339;

/// One discovered device: its latest validated announce, and what each bearer
/// has observed of it. A device seen only over NAN or BLE has no UDP sender.
#[derive(Clone, Debug)]
pub struct Device {
    /// The hex device id the inventory keys this device by.
    pub id: NodeKey,
    /// The latest validated announce; `None` for a provisional device, seen
    /// on a bearer that carried only an identifier (a legacy NAN follow-up).
    pub announce: Option<Announce>,
    /// Volatile radio facts the peer attached to its announce, if any.
    pub facts: Option<DiscoveryFacts>,
    /// The announce carried a public key whose signature verified.
    pub authenticated: bool,
    pub first_seen_ms: i64,
    pub last_seen_ms: i64,
    /// Per bearer (`udp_multicast`, `nan`, `now`, `ble`): the receiver-local view.
    pub observations: BTreeMap<String, DiscoveryObservation>,
    /// The last UDP sender, with the receiver-local IPv6 scope.
    pub udp_sender: Option<SocketAddr>,
}

impl Device {
    pub fn key(&self) -> &str {
        &self.id
    }

    pub fn name(&self) -> Option<&str> {
        self.announce
            .as_ref()?
            .device_name()
            .filter(|name| !name.is_empty())
    }

    /// The device's virtual IPv6 address, from its public key or identity hint.
    pub fn vip6(&self) -> Option<Ipv6Addr> {
        let announce = self.announce.as_ref()?;
        announce::virtual_ip6(announce.public_key())
            .or_else(|| announce::virtual_ip6_from_identity_hint(announce.device_id()))
            .map(Ipv6Addr::from)
    }

    /// Where this device accepts QUIC over UDP: the address and port it
    /// advertised, with the interface scope of the datagram that carried it
    /// (a sender never serializes a receiver's interface index). `None` for a
    /// device never seen over UDP and advertising no address.
    pub fn udp_endpoint(&self) -> Result<SocketAddr, NoRoute> {
        self.udp_endpoint_with(dmesh_server::firmware_profile::DEFAULT_EVENT_PORT)
    }

    /// [`Self::udp_endpoint`] with the port to assume for a device that
    /// advertises none and is not an ESP (each service has its own default).
    pub fn udp_endpoint_with(&self, default_port: u16) -> Result<SocketAddr, NoRoute> {
        self.udp_endpoint_in(default_port, None)
    }

    /// [`Self::udp_endpoint_with`], also taking a link-local scope to use when
    /// the datagram that carried the advertised address had none (an IPv4
    /// multicast sender): the receiver's configured ingress interface.
    pub fn udp_endpoint_in(
        &self,
        default_port: u16,
        fallback_scope: Option<u32>,
    ) -> Result<SocketAddr, NoRoute> {
        let announce = self.announce.as_ref().ok_or(NoRoute::NoUdpPath)?;
        let port = match announce.udp_port {
            0 if announce::is_esp_device_class(announce.device_class) => ESP_UDP_PORT,
            0 => default_port,
            port => port,
        };
        let sender_scope = match self.udp_sender {
            Some(SocketAddr::V6(sender)) => sender.scope_id(),
            _ => 0,
        };
        let scope = if sender_scope != 0 {
            sender_scope
        } else {
            fallback_scope.unwrap_or(0)
        };
        let ip = match (announce.udp_link_local_v6().map(Ipv6Addr::from), self.udp_sender) {
            (Some(ip), _) => ip,
            (None, Some(SocketAddr::V6(sender))) => *sender.ip(),
            // An IPv4 sender with nothing advertised: its own address.
            (None, Some(SocketAddr::V4(sender))) => {
                return Ok(SocketAddr::new((*sender.ip()).into(), port));
            }
            (None, None) => return Err(NoRoute::NoUdpPath),
        };
        if ip.is_unicast_link_local() && scope == 0 {
            return Err(NoRoute::NoScope);
        }
        Ok(SocketAddr::V6(SocketAddrV6::new(ip, port, 0, scope)))
    }
}

/// Why a device cannot be reached over UDP.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NoRoute {
    NotDiscovered,
    /// Seen only over NAN, NOW or BLE, and it advertises no UDP address.
    NoUdpPath,
    /// A link-local address with no known interface scope.
    NoScope,
}

impl std::fmt::Display for NoRoute {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::NotDiscovered => "unsupported/no_quic_route: destination is not discovered",
            Self::NoUdpPath => {
                "unsupported/no_quic_route: device was seen only over a radio bearer and advertises no UDP address"
            }
            Self::NoScope => {
                "unsupported/no_quic_route: no interface scope is known for the link-local address"
            }
        })
    }
}

impl std::error::Error for NoRoute {}

/// The discovered devices, with expiry. Records are soft state.
#[derive(Debug)]
pub struct Inventory {
    devices: BTreeMap<NodeKey, Device>,
    ttl_ms: i64,
}

impl Default for Inventory {
    fn default() -> Self {
        Self::new(60 * 60 * 1000)
    }
}

impl Inventory {
    pub fn new(ttl_ms: i64) -> Self {
        Self {
            devices: BTreeMap::new(),
            ttl_ms,
        }
    }

    /// Record one validated announce that reached us on `carrier`. Returns
    /// whether the device is new.
    pub fn observe(
        &mut self,
        now_ms: i64,
        carrier: &Carrier<'_>,
        announce: Announce,
        facts: Option<DiscoveryFacts>,
        authenticated: bool,
        payload: &[u8],
    ) -> bool {
        self.prune(now_ms);
        let key = hex(announce.device_id());
        let is_new = !self.devices.contains_key(&key);
        let device = self.devices.entry(key.clone()).or_insert_with(|| Device {
            id: key,
            announce: Some(announce),
            facts: None,
            authenticated,
            first_seen_ms: now_ms,
            last_seen_ms: now_ms,
            observations: BTreeMap::new(),
            udp_sender: None,
        });
        device.announce = Some(announce);
        device.facts = facts.or(device.facts);
        device.authenticated = authenticated;
        device.last_seen_ms = now_ms;
        if carrier.sender.is_some() {
            device.udp_sender = carrier.sender;
        }
        Self::record_observation(device, now_ms, carrier, payload);
        is_new
    }

    /// Record a sighting of a device known only by an identifier: a bearer that
    /// carried no announce (a legacy NAN follow-up). It is merged into the
    /// device when an announce with the same id arrives.
    pub fn observe_provisional(
        &mut self,
        now_ms: i64,
        carrier: &Carrier<'_>,
        id: &str,
        payload: &[u8],
    ) -> bool {
        self.prune(now_ms);
        let key = id.to_ascii_lowercase();
        let is_new = !self.devices.contains_key(&key);
        let device = self.devices.entry(key.clone()).or_insert_with(|| Device {
            id: key,
            announce: None,
            facts: None,
            authenticated: false,
            first_seen_ms: now_ms,
            last_seen_ms: now_ms,
            observations: BTreeMap::new(),
            udp_sender: None,
        });
        device.last_seen_ms = now_ms;
        Self::record_observation(device, now_ms, carrier, payload);
        is_new
    }

    fn record_observation(device: &mut Device, now_ms: i64, carrier: &Carrier<'_>, payload: &[u8]) {
        let fields = OBSERVATION_PEER
            | OBSERVATION_PAYLOAD_FINGERPRINT
            | if carrier.rssi_dbm.is_some() { OBSERVATION_RSSI } else { 0 }
            | if carrier.bssid.is_some() { OBSERVATION_BSSID } else { 0 }
            | if carrier.channel.is_some() { OBSERVATION_CHANNEL } else { 0 };
        let observation = device
            .observations
            .entry(carrier.bearer.to_owned())
            .or_insert_with(|| DiscoveryObservation::new(now_ms, fields));
        // A later callback that omits a field keeps the capability it showed before.
        observation.available_fields |= fields;
        observation.observe(
            now_ms,
            carrier.kind,
            carrier.peer,
            carrier.bssid,
            carrier.channel,
            carrier.rssi_dbm,
            payload,
        );
    }

    /// Forget every device (a service restart; tests).
    pub fn clear(&mut self) {
        self.devices.clear();
    }

    pub fn prune(&mut self, now_ms: i64) {
        let ttl = self.ttl_ms;
        self.devices
            .retain(|_, device| now_ms.saturating_sub(device.last_seen_ms) <= ttl);
    }

    pub fn get(&self, key: &str) -> Option<&Device> {
        self.devices.get(key)
    }

    pub fn devices(&self) -> impl Iterator<Item = &Device> {
        self.devices.values()
    }

    pub fn len(&self) -> usize {
        self.devices.len()
    }

    pub fn is_empty(&self) -> bool {
        self.devices.is_empty()
    }

    /// Find a device by a node identifier: a virtual IPv6 address (with or
    /// without `mesh://`), the hex device id (a prefix of at least eight
    /// digits), or its name.
    pub fn find(&self, target: &str) -> Option<&Device> {
        let target = target.trim();
        let target = target.strip_prefix("mesh://").unwrap_or(target);
        if let Ok(vip) = target.parse::<Ipv6Addr>() {
            return self.devices().find(|device| device.vip6() == Some(vip));
        }
        let lower = target.to_ascii_lowercase();
        if lower.len() >= 8 && lower.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            if let Some(device) = self
                .devices
                .iter()
                .find(|(key, _)| key.starts_with(&lower))
                .map(|(_, device)| device)
            {
                return Some(device);
            }
        }
        self.devices().find(|device| device.name() == Some(target))
    }

    /// The UDP endpoint to use for `target`.
    pub fn resolve_udp(&self, target: &str) -> Result<SocketAddr, NoRoute> {
        self.resolve_udp_with(target, dmesh_server::firmware_profile::DEFAULT_EVENT_PORT)
    }

    pub fn resolve_udp_with(&self, target: &str, default_port: u16) -> Result<SocketAddr, NoRoute> {
        self.resolve_udp_in(target, default_port, None)
    }

    pub fn resolve_udp_in(
        &self,
        target: &str,
        default_port: u16,
        fallback_scope: Option<u32>,
    ) -> Result<SocketAddr, NoRoute> {
        self.find(target)
            .ok_or(NoRoute::NotDiscovered)?
            .udp_endpoint_in(default_port, fallback_scope)
    }
}

impl Device {
    /// The compatibility view for consumers that read a device as JSON (the
    /// Android status text, `discovery.nodes` over the JSON bridge): the shared
    /// `DiscoveredDevice` shape with an `info` projection of the announce.
    pub fn discovered_view(&self) -> dmesh_server::discovery::DiscoveredDevice {
        let ipv6 = |address: [u8; 16]| Ipv6Addr::from(address).to_string();
        let info = match &self.announce {
            Some(announce) => serde_json::json!({
                "protocol": "dmesh_announce",
                "device_id": self.id,
                "signed": announce.has_identity(),
                "public_key": hex(announce.public_key()),
                "kind": announce.kind,
                "uptime_secs": announce.uptime_secs,
                "device_class": announce.device_class,
                "probe_capabilities": announce.probe_capabilities,
                "device_name": announce.device_name(),
                "network_name": announce.network_name(),
                "sta_link_local_v6": announce.sta_link_local_v6().map(ipv6),
                "udp_link_local_v6": announce.udp_link_local_v6().map(ipv6),
                "udp_port": announce.udp_port,
                "vip6": self.vip6().map(|vip| vip.to_string()),
            }),
            None => serde_json::Value::Null,
        };
        let transports: BTreeMap<String, String> = self
            .observations
            .iter()
            .filter(|(_, observation)| !observation.last_peer.is_empty())
            .map(|(bearer, observation)| (bearer.clone(), observation.last_peer.clone()))
            .collect();
        let peer = self
            .observations
            .values()
            .max_by_key(|observation| observation.last_seen_ms)
            .map(|observation| observation.last_peer.clone())
            .unwrap_or_default();
        dmesh_server::discovery::DiscoveredDevice {
            last_seen_ms: self.last_seen_ms,
            peer,
            info,
            transports,
            observations: self.observations.clone(),
        }
    }
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use dmesh_server::announce::{DEVICE_CLASS_ANDROID, DEVICE_CLASS_ESP};
    use dmesh_server::discovery::DiscoveryPacketKind;

    fn announce(id_byte: u8, name: &str, port: u16, link_local: Option<&str>, class: u8) -> Announce {
        let mut announce = Announce::discovery([id_byte; 16], 16, 1);
        assert!(announce.set_device_name(name));
        announce.set_probe_descriptor(class, 0);
        if let Some(address) = link_local {
            announce.set_udp_link_local_v6(address.parse::<Ipv6Addr>().unwrap().octets());
        }
        announce.set_udp_port(port);
        announce
    }

    fn see(inventory: &mut Inventory, announce: Announce, sender: Option<&str>) {
        let mut carrier = Carrier::radio(crate::BEARER_UDP, "peer", DiscoveryPacketKind::Other);
        carrier.sender = sender.map(|sender| sender.parse().unwrap());
        inventory.observe(1_000, &carrier, announce, None, false, b"");
    }

    #[test]
    fn a_device_resolves_to_its_advertised_endpoint_with_the_receivers_scope() {
        let mut inventory = Inventory::default();
        // A signed announce has a public key, so the device has a virtual IPv6.
        let identity = crate::identity::P256Identity::generate();
        let mut advertised = Announce::discovery(crate::identity::Identity::device_id(&identity), 16, 1);
        assert!(advertised.set_device_name("alpha"));
        advertised.set_udp_link_local_v6("fe80::aa".parse::<Ipv6Addr>().unwrap().octets());
        advertised.set_udp_port(3337);
        crate::identity::Identity::sign(&identity, &mut advertised).unwrap();
        see(&mut inventory, advertised, Some("[fe80::bb%7]:5227"));
        let key = hex(advertised.device_id());
        let vip = inventory.get(&key).unwrap().vip6().unwrap();
        for target in [
            format!("mesh://{vip}"),
            vip.to_string(),
            key[..8].to_owned(),
            key.to_uppercase(),
            "alpha".to_owned(),
        ] {
            assert_eq!(
                inventory.resolve_udp(&target).unwrap().to_string(),
                "[fe80::aa%7]:3337",
                "{target}"
            );
        }
        assert_eq!(inventory.resolve_udp("nobody"), Err(NoRoute::NotDiscovered));
    }

    #[test]
    fn ports_default_by_device_class_and_the_sender_address_is_the_fallback() {
        let mut inventory = Inventory::default();
        // No advertised address: the datagram's own sender is the path.
        see(&mut inventory, announce(2, "droid", 0, None, DEVICE_CLASS_ANDROID), Some("[fe80::cc%9]:5227"));
        assert_eq!(
            inventory.resolve_udp("droid").unwrap().to_string(),
            format!("[fe80::cc%9]:{}", dmesh_server::firmware_profile::DEFAULT_EVENT_PORT)
        );
        // An ESP that advertises no port uses its raw UDP6 listener.
        see(&mut inventory, announce(3, "esp", 0, None, DEVICE_CLASS_ESP), Some("[fe80::dd%9]:5227"));
        assert_eq!(inventory.resolve_udp("esp").unwrap().port(), ESP_UDP_PORT);
    }

    #[test]
    fn a_device_seen_only_over_a_radio_has_no_udp_path_and_none_is_guessed() {
        let mut inventory = Inventory::default();
        let mut carrier = Carrier::radio("nan", "aa:bb:cc:dd:ee:ff", DiscoveryPacketKind::ActivePublish);
        carrier.rssi_dbm = Some(-60);
        inventory.observe(1_000, &carrier, announce(4, "nanonly", 0, None, DEVICE_CLASS_ANDROID), None, false, b"");
        assert_eq!(inventory.resolve_udp("nanonly"), Err(NoRoute::NoUdpPath));
        let observation = &inventory.get(&hex(&[4; 16])).unwrap().observations["nan"];
        assert_eq!(observation.last_rssi_dbm, Some(-60));
        // A link-local address with no known scope is not a usable path either.
        see(&mut inventory, announce(5, "noscope", 3337, Some("fe80::ee"), DEVICE_CLASS_ANDROID), None);
        assert_eq!(inventory.resolve_udp("noscope"), Err(NoRoute::NoScope));
    }

    #[test]
    fn records_expire_and_the_bearers_stay_separate() {
        let mut inventory = Inventory::new(10_000);
        let record = announce(6, "gamma", 3337, None, DEVICE_CLASS_ANDROID);
        see(&mut inventory, record, Some("[fe80::1%2]:5227"));
        let nan = Carrier::radio("nan", "mac", DiscoveryPacketKind::Followup);
        inventory.observe(2_000, &nan, record, None, false, b"");
        let device = inventory.get(&hex(&[6; 16])).unwrap();
        assert_eq!(device.observations.len(), 2);
        assert_eq!(device.last_seen_ms, 2_000);
        inventory.prune(11_999);
        assert_eq!(inventory.len(), 1);
        inventory.prune(12_001);
        assert!(inventory.is_empty());
    }
}
