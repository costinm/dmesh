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
        let peer = match source {
            SocketAddr::V6(source) if announce.udp_port != 0 => {
                let address = announce
                    .udp_link_local_v6()
                    .or_else(|| announce.sta_link_local_v6())
                    .map(Ipv6Addr::from)
                    .unwrap_or(*source.ip());
                SocketAddr::V6(SocketAddrV6::new(
                    address,
                    announce.udp_port,
                    source.flowinfo(),
                    source.scope_id(),
                ))
            }
            source => source,
        };
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

/// Private controller-owned attributes for a stable device identity. This is
/// persisted by the shared Rust layer; platform adapters choose the directory
/// and obtain credentials (for example Android BLE pairing).
#[cfg(feature = "std")]
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct OwnedDevice {
    pub device_id: String,
    pub name: Option<String>,
    pub mac: Option<[u8; 6]>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub public_key: Vec<u8>,
    /// Control-plane root installed during pairing (controller key or CA).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub root_public_key: Vec<u8>,
    pub vip6: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub endpoints: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub secret: Vec<u8>,
}

#[cfg(feature = "std")]
impl core::fmt::Debug for OwnedDevice {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("OwnedDevice")
            .field("device_id", &self.device_id)
            .field("name", &self.name)
            .field("mac", &self.mac)
            .field("public_key", &self.public_key)
            .field("root_public_key", &self.root_public_key)
            .field("vip6", &self.vip6)
            .field("endpoints", &self.endpoints)
            .field("secret", &"<redacted>")
            .finish()
    }
}

/// Private pairing result files. Each signed VIP6 node suffix has one file;
/// discovery catalogs are never treated as an ownership database.
#[cfg(feature = "std")]
pub struct PairedDevices;

#[cfg(feature = "std")]
impl PairedDevices {
    fn path(directory: &std::path::Path, vip6: &str) -> Result<std::path::PathBuf, String> {
        let address: std::net::Ipv6Addr = vip6.parse().map_err(|_| "invalid paired device VIP6")?;
        let mut name = String::with_capacity(21);
        for byte in &address.octets()[8..] {
            use core::fmt::Write;
            write!(&mut name, "{byte:02x}").map_err(|_| "encode paired device VIP6")?;
        }
        name.push_str(".json");
        Ok(directory.join(name))
    }

    pub fn load(directory: &std::path::Path, vip6: &str) -> Result<Option<OwnedDevice>, String> {
        let path = Self::path(directory, vip6)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            match std::fs::metadata(&path) {
                Ok(metadata) if metadata.permissions().mode() & 0o077 != 0 => {
                    return Err("paired device file must be mode 0600".into());
                }
                Ok(_) => (),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                Err(error) => return Err(format!("stat paired device: {error}")),
            }
        }
        let bytes = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(format!("read paired device: {error}")),
        };
        let device: OwnedDevice = serde_json::from_slice(&bytes)
            .map_err(|error| format!("parse paired device: {error}"))?;
        if device
            .vip6
            .as_deref()
            .and_then(|value| value.parse::<std::net::Ipv6Addr>().ok())
            != vip6.parse::<std::net::Ipv6Addr>().ok()
        {
            return Err("paired device VIP6 does not match filename".into());
        }
        Ok(Some(device))
    }

    pub fn save(directory: &std::path::Path, device: &OwnedDevice) -> Result<(), String> {
        use std::io::Write;
        #[cfg(unix)]
        use std::os::unix::fs::OpenOptionsExt;
        if device.secret.len() < 16
            || device.public_key.len() != 33
            || !matches!(device.public_key[0], 2 | 3)
            || device.root_public_key.len() != 33
            || !matches!(device.root_public_key[0], 2 | 3)
            || device.vip6.is_none()
            || device
                .name
                .as_deref()
                .is_none_or(|name| name.is_empty() || name.len() > crate::announce::MAX_DEVICE_NAME)
        {
            return Err("pairing result needs name, secret, signed public key, control-plane root, and VIP6".into());
        }
        std::fs::create_dir_all(directory)
            .map_err(|error| format!("create pairing directory: {error}"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700))
                .map_err(|error| format!("protect pairing directory: {error}"))?;
        }
        let path = Self::path(directory, device.vip6.as_deref().unwrap())?;
        if path.exists() {
            return Err("device already has a pairing result".into());
        }
        let temporary = path.with_extension("json.tmp");
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = options
            .open(&temporary)
            .map_err(|error| format!("create pairing result: {error}"))?;
        let bytes = serde_json::to_vec_pretty(device)
            .map_err(|error| format!("encode pairing result: {error}"))?;
        file.write_all(&bytes)
            .and_then(|_| file.sync_all())
            .map_err(|error| format!("write pairing result: {error}"))?;
        std::fs::hard_link(&temporary, &path)
            .map_err(|error| format!("commit pairing result: {error}"))?;
        std::fs::remove_file(&temporary)
            .map_err(|error| format!("remove pairing temporary file: {error}"))
    }

    pub fn remove(directory: &std::path::Path, vip6: &str) -> Result<(), String> {
        let path = Self::path(directory, vip6)?;
        std::fs::remove_file(path).map_err(|error| format!("remove pairing result: {error}"))
    }
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
    use super::{
        DiscoveryObservation, DiscoveryPacketKind, OBSERVATION_ALL_FIELDS, OwnedDevice,
        PairedDevices,
    };
    use alloc::collections::BTreeMap;

    #[test]
    fn pairing_result_is_private_per_device_and_cannot_replace_an_owner() {
        let directory = tempfile::tempdir().unwrap();
        let device = OwnedDevice {
            device_id: "device/one".into(),
            name: Some("sensor".into()),
            mac: Some([1, 2, 3, 4, 5, 6]),
            public_key: vec![2; 33],
            root_public_key: vec![3; 33],
            vip6: Some("fc00::1".into()),
            endpoints: BTreeMap::new(),
            secret: vec![7; 32],
        };
        PairedDevices::save(directory.path(), &device).unwrap();
        assert_eq!(
            PairedDevices::load(directory.path(), "fc00::1")
                .unwrap()
                .unwrap()
                .secret,
            device.secret
        );
        assert!(PairedDevices::save(directory.path(), &device).is_err());
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let file = PairedDevices::path(directory.path(), "fc00::1").unwrap();
            assert_eq!(file.file_name().unwrap(), "0000000000000001.json");
            assert_eq!(
                std::fs::metadata(file).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        PairedDevices::remove(directory.path(), "fc00::1").unwrap();
        assert!(
            PairedDevices::load(directory.path(), "fc00::1")
                .unwrap()
                .is_none()
        );
    }

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
