//! The sans-IO discovery engine.

use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use dmesh_server::announce::{self, Announce, DiscoveryFacts};
use dmesh_server::discovery::DiscoveryPacketKind;

use crate::identity::{Identity, IdentityError};
use crate::inventory::{Device, Inventory, hex};

/// What this node says about itself and its radios, beyond its identity.
pub trait LocalFacts: Send + Sync {
    /// Fill in the announce: device name and domain, probe capabilities, and
    /// the UDP endpoint (`set_udp_port`, `set_udp_link_local_v6`).
    fn describe(&self, _announce: &mut Announce) {}

    /// Volatile radio facts sent beside (not inside) the signed announce.
    fn radio_facts(&self) -> Option<DiscoveryFacts> {
        None
    }
}

/// A node that says nothing beyond its identity.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoFacts;

impl LocalFacts for NoFacts {}

/// The bearer name of UDP discovery in observations, as the dashboard, the
/// fleet checks and the Linux inventory already call it.
pub const BEARER_UDP: &str = "udp_multicast";

/// How one datagram reached us: the receiver-local facts about its carrier.
#[derive(Clone, Copy, Debug)]
pub struct Carrier<'a> {
    /// The bearer: [`BEARER_UDP`], `nan`, `now`, `ble`.
    pub bearer: &'a str,
    /// The receiver-local address text of the sender (a UDP endpoint, a MAC).
    pub peer: &'a str,
    /// The UDP source with its IPv6 scope, when the bearer is UDP.
    pub sender: Option<SocketAddr>,
    pub rssi_dbm: Option<i16>,
    pub bssid: Option<[u8; 6]>,
    pub channel: Option<u8>,
    /// What kind of discovery packet this was on that bearer.
    pub kind: DiscoveryPacketKind,
}

impl<'a> Carrier<'a> {
    /// A datagram read from a UDP socket.
    pub fn udp(peer: &'a str, sender: SocketAddr) -> Self {
        Self {
            bearer: BEARER_UDP,
            peer,
            sender: Some(sender),
            rssi_dbm: None,
            bssid: None,
            channel: None,
            kind: DiscoveryPacketKind::Other,
        }
    }

    /// A packet from a radio bearer, with no UDP address.
    pub fn radio(bearer: &'a str, peer: &'a str, kind: DiscoveryPacketKind) -> Self {
        Self {
            bearer,
            peer,
            sender: None,
            rssi_dbm: None,
            bssid: None,
            channel: None,
            kind,
        }
    }
}

/// What one received datagram was.
#[derive(Clone, Debug)]
pub enum Received {
    /// A valid announce of another device; recorded in the inventory.
    Announce { key: String, is_new: bool },
    /// A directed discovery request: send `reply` back to the sender.
    Request { id: u64, reply: Vec<u8> },
    /// A discovery reply to request `id`; recorded in the inventory.
    Response { id: u64, device: Box<Device> },
    /// One of our own announces coming back on a multicast socket.
    Own,
    /// A well-formed announce whose identity does not verify.
    Rejected,
    /// Not a discovery record.
    Ignored,
}

/// Builds our announce, answers requests, validates and records what arrives.
/// It performs no I/O; a transport (UDP, NAN, NOW, BLE) moves the bytes.
pub struct Engine {
    identity: Arc<dyn Identity>,
    facts: Arc<dyn LocalFacts>,
    inventory: RwLock<Inventory>,
    started: Instant,
    /// Callers waiting for the reply to one directed request, by request id.
    waiters: std::sync::Mutex<std::collections::HashMap<u64, std::sync::mpsc::SyncSender<Device>>>,
}

impl Engine {
    pub fn new(identity: Arc<dyn Identity>, facts: Arc<dyn LocalFacts>) -> Self {
        Self {
            identity,
            facts,
            inventory: RwLock::new(Inventory::default()),
            started: Instant::now(),
            waiters: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// Wait for the reply to request `id` over any carrier. The receiver gets the
    /// device that answered, once; drop it (or call [`Self::forget_response`]) when
    /// the caller gives up.
    pub fn expect_response(&self, id: u64) -> std::sync::mpsc::Receiver<Device> {
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        self.waiters
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(id, sender);
        receiver
    }

    /// Stop waiting for request `id`.
    pub fn forget_response(&self, id: u64) {
        self.waiters.lock().unwrap_or_else(|e| e.into_inner()).remove(&id);
    }

    pub fn device_id(&self) -> [u8; 16] {
        self.identity.device_id()
    }

    pub fn uptime_secs(&self) -> u32 {
        u32::try_from(self.started.elapsed().as_secs()).unwrap_or(u32::MAX)
    }

    /// The current signed announce.
    pub fn local_announce(&self) -> Result<Announce, IdentityError> {
        let mut announce = Announce::discovery(self.device_id(), 16, self.uptime_secs());
        self.facts.describe(&mut announce);
        self.identity.sign(&mut announce)?;
        Ok(announce)
    }

    /// Our announce as a datagram, with the radio facts attached.
    pub fn announce_wire(&self) -> Result<Vec<u8>, IdentityError> {
        let announce = self.local_announce()?;
        let mut signed = [0u8; 384];
        let used = announce::encode(announce, &mut signed).ok_or(IdentityError::TooLarge)?;
        self.attach_facts(&signed[..used])
    }

    /// The reply to directed discovery request `id`.
    pub fn reply_wire(&self, id: u64) -> Result<Vec<u8>, IdentityError> {
        let announce = self.local_announce()?;
        let mut signed = [0u8; 384];
        let used =
            announce::encode_discovery_response(announce, id, &mut signed).ok_or(IdentityError::TooLarge)?;
        self.attach_facts(&signed[..used])
    }

    fn attach_facts(&self, signed: &[u8]) -> Result<Vec<u8>, IdentityError> {
        let Some(facts) = self.facts.radio_facts() else {
            return Ok(signed.to_vec());
        };
        let mut wire = [0u8; 448];
        let used = announce::encode_with_discovery_facts(signed, facts, &mut wire)
            .ok_or(IdentityError::TooLarge)?;
        Ok(wire[..used].to_vec())
    }

    /// A discovery request (`discovery.active`, directed or multicast).
    pub fn request_wire(id: u64) -> Vec<u8> {
        let mut wire = [0u8; 96];
        let used = announce::encode_discovery_request(id, &mut wire)
            .expect("a discovery request fits its buffer");
        wire[..used].to_vec()
    }

    /// A request id that is unique in practice: milliseconds since the epoch.
    pub fn new_request_id() -> u64 {
        now_ms().max(1) as u64
    }

    /// Process one received datagram.
    pub fn on_datagram(&self, carrier: &Carrier<'_>, bytes: &[u8]) -> Received {
        if let Some(id) = announce::discovery_request_id(bytes) {
            return match self.reply_wire(id) {
                Ok(reply) => Received::Request { id, reply },
                Err(error) => {
                    tracing::warn!(%error, "discovery reply could not be built");
                    Received::Ignored
                }
            };
        }
        let Some(record) = dmesh_server::tagged::decode(bytes) else {
            return Received::Ignored;
        };
        let reply_id = record.id;
        let facts = announce::discovery_facts(record);
        let Some(announce) = announce::decode_announce(bytes) else {
            return Received::Ignored;
        };
        self.observe_announce_with(carrier, announce, facts, reply_id, bytes)
    }

    /// Record an announce a bearer has already decoded (a radio adapter that
    /// parses NAN Service Info itself). Validated like a received datagram;
    /// `payload` is the original record when available; hosts retain it so
    /// discovery.nodes can forward signatures without trusting a decoded projection.
    pub fn observe_announce(
        &self,
        carrier: &Carrier<'_>,
        announce: Announce,
        payload: &[u8],
    ) -> Received {
        self.observe_announce_with(carrier, announce, None, None, payload)
    }

    fn observe_announce_with(
        &self,
        carrier: &Carrier<'_>,
        announce: Announce,
        facts: Option<DiscoveryFacts>,
        reply_id: Option<u64>,
        payload: &[u8],
    ) -> Received {
        // A sender that supplies an identity must prove it: the key hash is
        // its device id and the signature covers the canonical fields. An
        // announce with no key is the compatibility form for older devices.
        if !announce::verify_identity(announce) {
            return Received::Rejected;
        }
        if announce.device_id() == &self.device_id()[..announce.device_id().len()] {
            return Received::Own;
        }
        let authenticated = announce.has_identity();
        let key = hex(announce.device_id());
        let (is_new, device) = {
            let mut inventory = self.inventory.write().unwrap_or_else(|e| e.into_inner());
            let is_new =
                inventory.observe(now_ms(), carrier, announce, facts, authenticated, payload);
            (is_new, inventory.get(&key).cloned())
        };
        match (reply_id, device) {
            (Some(id), Some(device)) => {
                if let Some(waiter) = self.waiters.lock().unwrap_or_else(|e| e.into_inner()).remove(&id) {
                    let _ = waiter.try_send(device.clone());
                }
                Received::Response {
                    id,
                    device: Box::new(device),
                }
            }
            _ => Received::Announce { key, is_new },
        }
    }

    /// Record a sighting of a device known only by an identifier, from a
    /// bearer that carried no announce. Returns whether the device is new.
    pub fn observe_provisional(&self, carrier: &Carrier<'_>, id: &str, payload: &[u8]) -> bool {
        self.inventory
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .observe_provisional(now_ms(), carrier, id, payload)
    }

    /// Import a signed announcement learned from another observer. Its signature
    /// authenticates the announcer, not the supplied receiver metadata. Crawling
    /// never replaces a direct observation on the same bearer or fulfills a
    /// directed-discovery waiter.
    pub fn observe_crawled(&self, via: &[u8], row: &dmesh_server::discovery_nodes::Observation<'_>) -> bool {
        let Some(announce)=announce::decode_announce(row.record) else {return false};
        if !announce.has_identity() || !announce::verify_identity(announce) || via.len()!=8 {return false;}
        if announce.device_id()==&self.device_id()[..announce.device_id().len()] {return false;}
        let key=hex(announce.device_id());
        let mut inventory=self.inventory.write().unwrap_or_else(|e|e.into_inner());
        if inventory.get(&key).is_some_and(|d| d.observations.contains_key(row.bearer) && !d.crawled_via.contains_key(row.bearer)) {return false;}
        let peer=row.peer.map(|m|m.iter().map(|b|format!("{b:02x}")).collect::<Vec<_>>().join(":" )).unwrap_or_default();
        let carrier=Carrier {bearer:row.bearer,peer:&peer,sender:None,rssi_dbm:row.rssi_dbm,bssid:None,channel:row.channel,kind:DiscoveryPacketKind::Other};
        let now=now_ms();
        let seen=row.age_ms.map(|age|now.saturating_sub(i64::try_from(age).unwrap_or(i64::MAX)))
            .or_else(||row.last_seen_ms.and_then(|t|i64::try_from(t).ok()).map(|t|t.min(now)));
        inventory.observe(now,&carrier,announce,None,announce.has_identity(),row.record);
        inventory.set_crawled_source(&key,row.bearer,row.via.unwrap_or(via),seen);
        inventory.prune(now);
        true
    }

    /// The devices in the shape JSON consumers read (see
    /// [`Device::discovered_view`]), keyed by device id.
    pub fn discovered_view(&self) -> std::collections::BTreeMap<String, dmesh_server::discovery::DiscoveredDevice> {
        self.devices()
            .into_iter()
            .map(|device| (device.id.clone(), device.discovered_view()))
            .collect()
    }

    /// Forget every discovered device.
    pub fn clear_devices(&self) {
        self.inventory.write().unwrap_or_else(|e| e.into_inner()).clear();
    }

    /// A snapshot of the discovered devices.
    pub fn devices(&self) -> Vec<Device> {
        let mut inventory = self.inventory.write().unwrap_or_else(|e| e.into_inner());
        inventory.prune(now_ms());
        inventory.devices().cloned().collect()
    }

    pub fn device(&self, key: &str) -> Option<Device> {
        self.inventory
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(key)
            .cloned()
    }

    /// The UDP endpoint for a node identifier (see [`Inventory::find`]).
    pub fn resolve_udp(&self, target: &str) -> Result<SocketAddr, crate::inventory::NoRoute> {
        self.inventory
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .resolve_udp(target)
    }

    /// [`Self::resolve_udp`] with this service's default port for a device that
    /// advertises none, and the scope to assume when the datagram that carried
    /// its link-local address had none.
    pub fn resolve_udp_in(
        &self,
        target: &str,
        default_port: u16,
        fallback_scope: Option<u32>,
    ) -> Result<SocketAddr, crate::inventory::NoRoute> {
        self.inventory
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .resolve_udp_in(target, default_port, fallback_scope)
    }
}

pub(crate) fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{P256Identity, UnsignedIdentity};
    use dmesh_server::announce::DEVICE_CLASS_HOST;

    struct Named(&'static str);

    impl LocalFacts for Named {
        fn describe(&self, announce: &mut Announce) {
            announce.set_device_name(self.0);
            announce.set_probe_descriptor(DEVICE_CLASS_HOST, 0);
        }

        fn radio_facts(&self) -> Option<DiscoveryFacts> {
            Some(DiscoveryFacts {
                nan_cluster_suffix: Some([1, 2, 3]),
                nan_service_observations: 4,
                nan_visible_nodes: 5,
            })
        }
    }

    fn test_carrier(peer: &str) -> Carrier<'_> {
        Carrier::radio(BEARER_UDP, peer, DiscoveryPacketKind::Other)
    }

    fn engine(name: &'static str) -> Engine {
        Engine::new(Arc::new(P256Identity::generate()), Arc::new(Named(name)))
    }

    #[test]
    fn an_announce_is_recorded_by_the_receiver_and_ignored_by_its_sender() {
        let (a, b) = (engine("alpha"), engine("beta"));
        let wire = a.announce_wire().unwrap();
        let Received::Announce { key, is_new } = b.on_datagram(&test_carrier("peer-a"), &wire) else {
            panic!("expected an announce");
        };
        assert!(is_new);
        let device = b.device(&key).unwrap();
        assert_eq!(device.name(), Some("alpha"));
        assert!(device.authenticated);
        assert_eq!(device.facts.unwrap().nan_visible_nodes, 5);
        assert!(device.observations.contains_key(BEARER_UDP));
        // The same announce again updates the record, it is not new.
        let Received::Announce { is_new, .. } = b.on_datagram(&test_carrier("peer-a"), &wire) else {
            panic!("expected an announce");
        };
        assert!(!is_new);
        assert_eq!(b.devices().len(), 1);
        // Our own announce coming back is dropped.
        assert!(matches!(a.on_datagram(&test_carrier("me"), &wire), Received::Own));
        assert!(a.devices().is_empty());
    }

    #[test]
    fn a_tampered_announce_is_rejected() {
        let (a, b) = (engine("alpha"), engine("beta"));
        let mut wire = a.announce_wire().unwrap();
        // Corrupt a byte inside the signed fields (the device name).
        let at = wire.windows(5).position(|w| w == b"alpha").unwrap();
        wire[at] = b'z';
        assert!(matches!(b.on_datagram(&test_carrier("peer"), &wire), Received::Rejected));
        assert!(b.devices().is_empty());
    }

    #[test]
    fn a_directed_request_gets_a_correlated_signed_reply() {
        let (a, b) = (engine("alpha"), engine("beta"));
        let request = Engine::request_wire(77);
        let Received::Request { id, reply } = a.on_datagram(&test_carrier("b"), &request) else {
            panic!("expected a request");
        };
        assert_eq!(id, 77);
        let Received::Response { id, device } = b.on_datagram(&test_carrier("a"), &reply) else {
            panic!("expected a response");
        };
        assert_eq!(id, 77);
        assert!(device.authenticated);
        assert_eq!(device.name(), Some("alpha"));
    }

    #[test]
    fn garbage_and_unrelated_records_are_ignored() {
        let a = engine("alpha");
        assert!(matches!(a.on_datagram(&test_carrier("x"), b"not cbor at all"), Received::Ignored));
        assert!(matches!(a.on_datagram(&test_carrier("x"), &[]), Received::Ignored));
    }

    #[test]
    fn a_radio_bearer_can_feed_a_decoded_announce_or_just_an_identifier() {
        let b = engine("beta");
        // A provisional sighting (a follow-up that carried only a device id) ...
        let nan = |peer| Carrier::radio("nan", peer, DiscoveryPacketKind::Followup);
        assert!(b.observe_provisional(&nan("aa:bb:cc:dd:ee:01"), "AABBCCDD11223344", b"x"));
        let provisional = b.device("aabbccdd11223344").unwrap();
        assert!(provisional.announce.is_none());
        assert_eq!(provisional.observations["nan"].followup_rx, 1);
        assert!(provisional.discovered_view().info.is_null());
        // ... is merged into the device when an announce with that id arrives.
        let mut announce = Announce::discovery([0; 16], 8, 5);
        announce.device_id[..8].copy_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0x11, 0x22, 0x33, 0x44]);
        announce.set_device_name("gamma");
        let Received::Announce { key, is_new } =
            b.observe_announce(&nan("aa:bb:cc:dd:ee:01"), announce, b"y")
        else {
            panic!("expected an announce");
        };
        assert_eq!(key, "aabbccdd11223344");
        assert!(!is_new);
        let device = b.device(&key).unwrap();
        assert_eq!(device.name(), Some("gamma"));
        assert_eq!(device.observations["nan"].followup_rx, 2);
        let view = device.discovered_view();
        assert_eq!(view.info["device_name"], "gamma");
        assert_eq!(view.transports["nan"], "aa:bb:cc:dd:ee:01");
        assert_eq!(b.discovered_view().len(), 1);
    }

    #[test]
    fn an_unsigned_peer_is_accepted_but_not_authenticated() {
        let a = Engine::new(Arc::new(UnsignedIdentity::from_seed(b"key-a")), Arc::new(Named("droid")));
        let b = engine("beta");
        let wire = a.announce_wire().unwrap();
        let Received::Announce { key, .. } = b.on_datagram(&test_carrier("a"), &wire) else {
            panic!("expected an announce");
        };
        assert!(!b.device(&key).unwrap().authenticated);
    }

    #[test]
    fn a_reply_resolves_the_caller_waiting_for_its_request_id_over_any_carrier() {
        let a = Engine::new(Arc::new(UnsignedIdentity::from_seed(b"a")), Arc::new(NoFacts));
        let b = Engine::new(Arc::new(UnsignedIdentity::from_seed(b"b")), Arc::new(NoFacts));
        let id = 4242;
        let waiting = a.expect_response(id);
        let mut request = [0u8; 96];
        let used = announce::encode_discovery_request(id, &mut request).unwrap();
        let carrier = Carrier::radio("now", "02:00:00:00:00:01", dmesh_server::discovery::DiscoveryPacketKind::ActiveSubscribe);
        let Received::Request { reply, .. } = b.on_datagram(&carrier, &request[..used]) else {
            panic!("a request must produce a reply");
        };
        let back = Carrier::radio("now", "02:00:00:00:00:02", dmesh_server::discovery::DiscoveryPacketKind::ActivePublish);
        assert!(matches!(a.on_datagram(&back, &reply), Received::Response { .. }));
        let device = waiting.recv_timeout(std::time::Duration::from_millis(100)).unwrap();
        assert_eq!(device.id, hex(&b.device_id()));
        // Once only: a second reply finds nobody waiting.
        assert!(matches!(a.on_datagram(&back, &reply), Received::Response { .. }));
        assert!(waiting.try_recv().is_err());
    }
}
