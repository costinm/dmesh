//! Bounded, bearer-neutral discovery observation vocabulary.
//!
//! Adapters own their radio callbacks and local retention, but Android, Linux,
//! and ESP project their discovered-device lists through these same facts. A
//! missing field is an explicit unavailable platform observation, never an
//! inferred success.

use alloc::string::String;

#[cfg(feature = "std")]
use alloc::collections::BTreeMap;
#[cfg(feature = "std")]
use alloc::vec::Vec;

/// One correlated response from a host IPv6 multicast discovery sweep.
///
/// Discovery is its own application protocol. `peer` is the UDP source tuple
/// observed by the socket and is not a QUIC path or association address.
#[cfg(feature = "std")]
#[derive(Clone, Debug)]
pub struct MulticastDiscoveryPeer {
    pub peer: std::net::SocketAddr,
    pub announce: crate::announce::Announce,
    pub facts: Option<crate::announce::DiscoveryFacts>,
}

/// Send one tagged discovery request on every local IPv6 multicast scope and
/// collect its correlated tagged responses.
///
/// This function deliberately owns both CBOR interpretation and multicast
/// socket I/O. Discovery datagrams are not QUIC packets and never enter a
/// QUIC node or bearer.
#[cfg(feature = "std")]
pub fn discover_multicast_ipv6() -> Result<Vec<MulticastDiscoveryPeer>, String> {
    use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6, UdpSocket};
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    const DISCOVERY_PORT: u16 = 5227;
    let request_id = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(1, |duration| duration.as_micros() as u64)
        .max(1);
    let mut request = [0u8; 96];
    let request_len = crate::announce::encode_discovery_request(request_id, &mut request)
        .ok_or_else(|| "encode UDP6 multicast discovery request".to_owned())?;
    let socket = UdpSocket::bind(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0))
        .map_err(|error| format!("bind UDP6 multicast discovery socket: {error}"))?;
    socket
        .set_read_timeout(Some(Duration::from_millis(250)))
        .map_err(|error| format!("configure UDP6 multicast discovery socket: {error}"))?;
    let group = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x5227);
    let mut submitted = 0usize;
    let interfaces = std::fs::read_dir("/sys/class/net")
        .map_err(|error| format!("enumerate network interfaces: {error}"))?;
    for entry in interfaces {
        let entry = entry.map_err(|error| format!("read network interface: {error}"))?;
        if entry.file_name() == "lo" {
            continue;
        }
        let Some(index) = std::fs::read_to_string(entry.path().join("ifindex"))
            .ok()
            .and_then(|value| value.trim().parse::<u32>().ok())
        else {
            continue;
        };
        let destination = SocketAddrV6::new(group, DISCOVERY_PORT, 0, index);
        if socket.send_to(&request[..request_len], destination).is_ok() {
            submitted += 1;
        }
    }
    if submitted == 0 {
        return Err("UDP6 multicast discovery was not submitted on any interface".to_owned());
    }

    let deadline = Instant::now() + Duration::from_secs(5);
    let mut peers = Vec::new();
    let mut input = [0u8; 1500];
    while Instant::now() < deadline {
        let Ok((used, source)) = socket.recv_from(&mut input) else {
            continue;
        };
        let Some(record) = crate::tagged::decode(&input[..used]) else {
            continue;
        };
        if record.id != Some(request_id) {
            continue;
        }
        let facts = crate::announce::discovery_facts(record);
        let Some(announce) = crate::announce::decode_record(record) else {
            continue;
        };
        let peer = multicast_service_endpoint(source, &announce);
        if peers
            .iter()
            .any(|known: &MulticastDiscoveryPeer| known.peer == peer)
        {
            continue;
        }
        peers.push(MulticastDiscoveryPeer {
            peer,
            announce,
            facts,
        });
    }
    Ok(peers)
}

/// Resolve a multicast reply to its service on the same observed network path.
/// A node's cached announcement may describe a different interface; combining
/// that address with this packet's scope produces an unusable link-local tuple.
#[cfg(feature = "std")]
pub fn multicast_service_endpoint(mut source: std::net::SocketAddr, announce: &crate::announce::Announce) -> std::net::SocketAddr {
    let port = if announce.udp_port != 0 { announce.udp_port }
        else if crate::announce::is_esp_device_class(announce.device_class) { crate::announce::DEFAULT_ESP_UDP_PORT }
        else { source.port() };
    source.set_port(port);
    source
}

/// Exchange one raw discovery record with an already known UDP endpoint.
/// The endpoint commonly uses the service port (`3339` on ESP), but the
/// payload remains discovery protocol data and never enters QUIC.
#[cfg(feature = "std")]
pub fn discover_udp(
    peer: std::net::SocketAddr,
    request_id: u64,
    response_timeout: std::time::Duration,
) -> Result<crate::announce::Announce, String> {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};

    let bind = match peer {
        SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    };
    let socket = UdpSocket::bind(bind)
        .map_err(|error| format!("bind directed discovery socket: {error}"))?;
    socket
        .set_read_timeout(Some(response_timeout))
        .map_err(|error| format!("configure directed discovery socket: {error}"))?;
    let mut request = [0u8; 96];
    let used = crate::announce::encode_discovery_request(request_id, &mut request)
        .ok_or_else(|| "encode directed discovery request".to_owned())?;
    socket
        .send_to(&request[..used], peer)
        .map_err(|error| format!("send directed discovery request: {error}"))?;
    let mut response = [0u8; 1500];
    let (used, source) = socket
        .recv_from(&mut response)
        .map_err(|error| format!("receive directed discovery response: {error}"))?;
    if source.ip() != peer.ip() {
        return Err(format!(
            "directed discovery response came from unexpected peer {source}"
        ));
    }
    let record = crate::tagged::decode(&response[..used])
        .ok_or_else(|| "directed discovery response is not tagged CBOR".to_owned())?;
    if record.id != Some(request_id) {
        return Err("directed discovery response has the wrong request ID".to_owned());
    }
    crate::announce::decode_record(record)
        .filter(|announce| announce.kind == crate::announce::ANNOUNCE_DISCOVERY)
        .ok_or_else(|| "directed discovery response is not announce.discovery".to_owned())
}

pub const OBSERVATION_PEER: u32 = 1 << 0;
pub const OBSERVATION_BSSID: u32 = 1 << 1;
pub const OBSERVATION_CHANNEL: u32 = 1 << 2;
pub const OBSERVATION_RSSI: u32 = 1 << 3;
pub const OBSERVATION_PAYLOAD_FINGERPRINT: u32 = 1 << 4;
pub const OBSERVATION_ALL_FIELDS: u32 = OBSERVATION_PEER
    | OBSERVATION_BSSID
    | OBSERVATION_CHANNEL
    | OBSERVATION_RSSI
    | OBSERVATION_PAYLOAD_FINGERPRINT;

pub fn payload_hash(payload: &[u8]) -> u32 {
    payload.iter().fold(0x811c_9dc5u32, |hash, byte| {
        (hash ^ u32::from(*byte)).wrapping_mul(0x0100_0193)
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "std", serde(rename_all = "snake_case"))]
pub enum DiscoveryPacketKind {
    ActivePublish,
    ActiveSubscribe,
    Followup,
    Other,
}

impl DiscoveryPacketKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ActivePublish => "active_publish",
            Self::ActiveSubscribe => "active_subscribe",
            Self::Followup => "followup",
            Self::Other => "other",
        }
    }
}

/// Receiver-side facts for one bearer and one discovered peer.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize))]
pub struct DiscoveryObservation {
    /// Bitset of fields this adapter can report. A UI must render unavailable
    /// fields as unavailable, not as an RF failure or a zero-value fact.
    pub available_fields: u32,
    pub first_seen_ms: i64,
    pub last_seen_ms: i64,
    pub packets: u32,
    pub active_publish_rx: u32,
    pub active_subscribe_rx: u32,
    pub followup_rx: u32,
    pub last_kind: DiscoveryPacketKind,
    pub last_peer: String,
    pub last_bssid: Option<[u8; 6]>,
    pub last_channel: Option<u8>,
    pub last_rssi_dbm: Option<i16>,
    pub last_payload_len: u16,
    pub last_payload_hash: u32,
}

/// Cross-bearer retained device state used by Linux and Android services.
/// `info` is the schema-derived announce projection; transport observations
/// remain keyed by bearer and keep their observer-local meaning.
#[cfg(feature = "std")]
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct DiscoveredDevice {
    pub last_seen_ms: i64,
    pub peer: String,
    pub info: serde_json::Value,
    pub transports: BTreeMap<String, String>,
    pub observations: BTreeMap<String, DiscoveryObservation>,
}

/// Stable JSON response for the shared HTTP/UI `discovery.nodes` handler.
#[cfg(feature = "std")]
pub fn inventory_json(devices: &BTreeMap<String, DiscoveredDevice>) -> serde_json::Value {
    let devices = devices
        .values()
        .map(|device| {
            let identity = device
                .info
                .get("device_name")
                .and_then(serde_json::Value::as_str)
                .filter(|value| !value.is_empty())
                .or_else(|| device.info.get("vip6").and_then(serde_json::Value::as_str));
            let observations = device
                .observations
                .iter()
                .map(|(bearer, observation)| {
                    (
                        bearer.clone(),
                        serde_json::json!({
                            "first_seen_ms": observation.first_seen_ms,
                            "last_seen_ms": observation.last_seen_ms,
                            "available_fields": observation.available_fields,
                            "unavailable_fields": observation.unavailable_fields(),
                            "packets": observation.packets,
                            "active_publish_rx": observation.active_publish_rx,
                            "active_subscribe_rx": observation.active_subscribe_rx,
                            "followup_rx": observation.followup_rx,
                            "last_kind": observation.last_kind.as_str(),
                            "last_bssid": observation.last_bssid,
                            "last_channel": observation.last_channel,
                            "last_rssi_dbm": observation.last_rssi_dbm,
                            "last_payload_len": observation.last_payload_len,
                            "last_payload_hash": observation.last_payload_hash,
                        }),
                    )
                })
                .collect::<serde_json::Map<_, _>>();
            let mut value = serde_json::json!({
                "identity_state": "semantic",
                "last_seen_ms": device.last_seen_ms,
                "announce": device.info,
                "observations": observations,
            });
            if let Some(identity) = identity {
                value["identity"] = serde_json::Value::String(identity.to_owned());
            }
            value
        })
        .collect::<Vec<_>>();
    serde_json::json!({"devices": devices})
}

impl DiscoveryObservation {
    pub fn new(now_ms: i64, available_fields: u32) -> Self {
        Self {
            available_fields,
            first_seen_ms: now_ms,
            last_seen_ms: now_ms,
            packets: 0,
            active_publish_rx: 0,
            active_subscribe_rx: 0,
            followup_rx: 0,
            last_kind: DiscoveryPacketKind::Other,
            last_peer: String::new(),
            last_bssid: None,
            last_channel: None,
            last_rssi_dbm: None,
            last_payload_len: 0,
            last_payload_hash: 0,
        }
    }

    pub fn observe(
        &mut self,
        now_ms: i64,
        kind: DiscoveryPacketKind,
        peer: &str,
        bssid: Option<[u8; 6]>,
        channel: Option<u8>,
        rssi_dbm: Option<i16>,
        payload: &[u8],
    ) {
        self.last_seen_ms = now_ms;
        self.packets = self.packets.saturating_add(1);
        match kind {
            DiscoveryPacketKind::ActivePublish => {
                self.active_publish_rx = self.active_publish_rx.saturating_add(1)
            }
            DiscoveryPacketKind::ActiveSubscribe => {
                self.active_subscribe_rx = self.active_subscribe_rx.saturating_add(1)
            }
            DiscoveryPacketKind::Followup => self.followup_rx = self.followup_rx.saturating_add(1),
            DiscoveryPacketKind::Other => {}
        }
        self.last_kind = kind;
        self.last_peer.clear();
        self.last_peer.push_str(peer);
        self.last_bssid = bssid;
        self.last_channel = channel;
        self.last_rssi_dbm = rssi_dbm;
        self.last_payload_len = payload.len().min(u16::MAX as usize) as u16;
        self.last_payload_hash = payload_hash(payload);
    }

    /// Facts which the producing adapter cannot provide for this observation.
    /// Consumers render these explicitly as unavailable rather than treating a
    /// missing RSSI/channel/BSSID as a received zero value.
    pub const fn unavailable_fields(&self) -> u32 {
        OBSERVATION_ALL_FIELDS & !self.available_fields
    }
}

#[cfg(test)]
mod tests {
    use super::{DiscoveryObservation, DiscoveryPacketKind, OBSERVATION_ALL_FIELDS};
    use alloc::collections::BTreeMap;

    #[test]
    fn observation_distinguishes_nan_packet_kinds() {
        let mut observation = DiscoveryObservation::new(10, OBSERVATION_ALL_FIELDS);
        observation.observe(
            11,
            DiscoveryPacketKind::ActivePublish,
            "peer",
            None,
            None,
            None,
            b"a",
        );
        observation.observe(
            12,
            DiscoveryPacketKind::ActiveSubscribe,
            "peer",
            None,
            None,
            None,
            b"b",
        );
        observation.observe(
            13,
            DiscoveryPacketKind::Followup,
            "peer",
            None,
            None,
            Some(-42),
            b"c",
        );
        assert_eq!(observation.first_seen_ms, 10);
        assert_eq!(observation.last_seen_ms, 13);
        assert_eq!(observation.packets, 3);
        assert_eq!(observation.active_publish_rx, 1);
        assert_eq!(observation.active_subscribe_rx, 1);
        assert_eq!(observation.followup_rx, 1);
        assert_eq!(observation.last_rssi_dbm, Some(-42));
        assert_eq!(observation.unavailable_fields(), 0);
    }
}
