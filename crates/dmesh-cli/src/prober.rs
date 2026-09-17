//! File-backed device descriptors for the shared control-plane prober.
//!
//! This module deliberately contains configuration and name resolution only.
//! Hardware adapters (UART, UDP6, host NAN, and Android APIs) execute the
//! bearer-neutral `dmesh_server::probe::ProbeRequest`; tests and production
//! evaluators therefore consume the same descriptor file without embedding
//! board names or serial paths in their probe logic.

// TODO: move parts to dmesh-server ( generic code ), integrate into android/fw/lmesh-wifi as core handler/feature

use serde::{Deserialize, Serialize};
use std::path::Path;

/// Checked-in test catalog used unless an operator supplies
/// `DMESH_DEVICE_CATALOG`.
pub const DEFAULT_DEVICE_CATALOG: &str =
    concat!(env!("CARGO_MANIFEST_DIR"), "/examples/device-catalog.toml");
/// E2E scheduling policy is separate from the canonical device inventory.
pub const DEFAULT_E2E_MATRIX: &str = "notes/e2e-matrix.toml.example";

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct E2eDeviceConfig {
    pub name: String,
    /// Catalogued device P-256 public key. The matching private key is created
    /// and retained by the ESP; it must never be placed in this catalog.
    #[serde(default)]
    pub device_public_key_b64: Option<String>,
    /// Shared secret for the owning control plane. It is intentionally
    /// catalogued for development and later derives sender-specific traffic
    /// keys and control-plane authentication/encryption keys.
    #[serde(default)]
    pub shared_secret_b64: Option<String>,
    pub kind: String,
    #[serde(default)]
    pub serial: Option<String>,
    /// Optional glob below `/dev/serial/by-id` for direct provisioning.  This
    /// is inventory, not an E2E test identity; generic tests select a
    /// descriptor and derive it from here.
    #[serde(default)]
    pub serial_glob: Option<String>,
    /// Physical speed for a real USB-UART bridge. Packetized USB/JTAG
    /// endpoints omit this because their transport is not baud-clocked.
    #[serde(default)]
    pub uart_baud: Option<u32>,
    #[serde(default)]
    pub mac: Option<String>,
    /// Radio identity used by NAN advertisements (often the AP MAC, which
    /// can differ from the base/STA MAC kept in `mac`).
    #[serde(default)]
    pub nan_mac: Option<String>,
    #[serde(default)]
    pub transport_kind: Option<u8>,
    #[serde(default)]
    pub now: Option<u8>,
    #[serde(default)]
    pub nan_dw_interval: Option<u8>,
    #[serde(default)]
    pub ndp: Option<bool>,
    #[serde(default)]
    pub ap: Option<bool>,
    #[serde(default)]
    pub bssid: Option<String>,
    #[serde(default)]
    pub service: Option<String>,
    #[serde(default)]
    pub iface: Option<String>,
    #[serde(default)]
    pub ipv4: Option<String>,
    /// Stable signed overlay identity. The low 64 bits are the compact
    /// identity hint carried by discovery announcements.
    #[serde(default)]
    pub vip6: Option<String>,
    /// Link-local address advertised while in STA/AP mode.  Callers must add
    /// their local interface scope before constructing a UDP endpoint.
    #[serde(default)]
    pub ipv6_link_local: Option<String>,
    /// Local egress interface used to scope this device's catalogued IPv6
    /// link-local endpoint. This is host routing metadata, not a radio
    /// interface name carried by the device.
    #[serde(default)]
    pub udp6_iface: Option<String>,
    #[serde(default = "default_udp_port")]
    pub udp_port: u16,
    /// Authentication key selector.  The matching material is held in the
    /// catalog's protected security section and is never rendered by clients.
    #[serde(default)]
    pub auth_secret_ref: Option<String>,
    /// Direct JTAG adapter selectors for the provisioning script.
    #[serde(default)]
    pub jtag_adapter_serial: Option<String>,
    #[serde(default)]
    pub jtag_adapter_location: Option<String>,
    #[serde(default = "default_baseline")]
    pub baseline: String,
    #[serde(default)]
    pub supports_now: bool,
    /// Discovery/control is required for a remotely selected probe.  ESP
    /// descriptors default to NAN support; other kinds must state support in
    /// the shared inventory override when it is not advertised yet.
    #[serde(default = "default_true")]
    pub supports_nan: bool,
    #[serde(default = "default_true")]
    pub supports_sta: bool,
    #[serde(default = "default_true")]
    pub supports_ap: bool,
    #[serde(default = "default_true")]
    pub supports_udp6: bool,
    /// Whether this descriptor participates in generic hardware E2E rows.
    /// Keep capability fields truthful when a known-broken or quarantined
    /// board is temporarily excluded; the matrix, not a test body, owns that
    /// operational decision.
    #[serde(default = "default_true")]
    pub e2e_enabled: bool,
    /// A sleepy endpoint has no always-on command path. Its probe requires a
    /// live NAN clock/control plane before it can enter an active test mode.
    /// Active endpoints retain NOW as the fallback when a host lacks NAN.
    #[serde(default)]
    pub sleepy: bool,
}

fn default_baseline() -> String {
    "nan".to_owned()
}

fn default_udp_port() -> u16 {
    3337
}

fn default_true() -> bool {
    true
}

/// Optional catalog-wide policy shared by NAN, NOW, and QUIC test matrices.
/// It deliberately describes test orchestration, not a radio personality;
/// individual device descriptors continue to own their baseline and bearer
/// capabilities. `min_android_witnesses` is consumed by NAN; other matrices
/// may use the same live-device, source, target, timing, and retry policy.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DeviceMatrixConfig {
    /// At least this many responsive Android witnesses must be present.
    #[serde(default = "default_android_witnesses")]
    pub min_android_witnesses: usize,
    /// Milliseconds to wait after a discovery request before inspecting the
    /// receiver inventory. Retries use the same bounded window.
    #[serde(default = "default_matrix_settle_ms")]
    pub settle_ms: u64,
    #[serde(default = "default_matrix_attempts")]
    pub attempts: u8,
    /// Sources are logical catalog kinds: android, host, and esp.
    #[serde(default = "default_matrix_sources")]
    pub sources: Vec<String>,
    /// Optional device names. Empty means every responsive non-Android entry.
    #[serde(default)]
    pub targets: Vec<String>,
}

fn default_android_witnesses() -> usize {
    1
}
fn default_matrix_settle_ms() -> u64 {
    15_000
}
fn default_matrix_attempts() -> u8 {
    2
}
fn default_matrix_sources() -> Vec<String> {
    vec!["android".to_owned(), "host".to_owned(), "esp".to_owned()]
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct E2ePairConfig {
    pub name: String,
    pub source: String,
    pub target: String,
    pub tests: Vec<String>,
    /// Optional explicit forwarding chain. Entries include the receiving node
    /// and the bearer/address used by the preceding node to reach it.
    #[serde(default)]
    pub path: Vec<E2ePathNode>,
}

/// One node in a configured direct-control/relay chain. `transport` is
/// currently `now` (six-byte MAC) or `udp6` (IPv6 link-local address).
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct E2ePathNode {
    pub node: String,
    pub transport: String,
    pub address: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct E2eConfig {
    /// DNS suffix for catalog device names, initially `test.webinf.info`.
    #[serde(default)]
    pub domain: Option<String>,
    pub devices: Vec<E2eDeviceConfig>,
    /// Common P-256 control-plane identity used by the flasher and dmesh-cli.
    #[serde(default)]
    pub security: Option<DeviceSecurityConfig>,
    #[serde(default)]
    pub pairs: Vec<E2ePairConfig>,
    #[serde(default)]
    pub device_matrix: Option<DeviceMatrixConfig>,
}

/// Matrix-only overlay. It intentionally has no device descriptors: every
/// endpoint reference must resolve in the canonical catalog.
#[derive(Clone, Debug, Deserialize)]
pub struct E2eMatrix {
    #[serde(default)]
    pub pairs: Vec<E2ePairConfig>,
    #[serde(default)]
    pub device_matrix: Option<DeviceMatrixConfig>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DeviceSecurityConfig {
    /// Raw 32-byte P-256 test/control-plane private scalar. A protected
    /// production catalog will replace this development-only field with its
    /// database/key-store integration.
    #[serde(default)]
    pub control_plane_private_key_b64: Option<String>,
    /// Optional PEM/PKCS#8 private-key path used by the local control plane.
    /// Relative paths resolve beside the shared catalog.
    #[serde(default)]
    pub control_plane_private_key: Option<String>,
    /// Public P-256 counterpart, encoded for catalog/NVS transport.
    #[serde(default)]
    pub control_plane_public_key_b64: Option<String>,
}

impl E2eConfig {
    pub fn from_path(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|error| format!("read {}: {error}", path.display()))?;
        let config = toml::from_str::<Self>(&text)
            .map_err(|error| format!("parse {}: {error}", path.display()))?;
        config.validate(path)?;
        Ok(config)
    }

    pub fn from_catalog_and_matrix(catalog: &Path, matrix: &Path) -> Result<Self, String> {
        let mut config = Self::from_path(catalog)?;
        let text = std::fs::read_to_string(matrix)
            .map_err(|error| format!("read {}: {error}", matrix.display()))?;
        let overlay = toml::from_str::<E2eMatrix>(&text)
            .map_err(|error| format!("parse {}: {error}", matrix.display()))?;
        config.pairs = overlay.pairs;
        config.device_matrix = overlay.device_matrix;
        config.validate(matrix)?;
        Ok(config)
    }

    pub fn validate(&self, path: &Path) -> Result<(), String> {
        let mut names = std::collections::BTreeSet::new();
        for device in &self.devices {
            if !names.insert(device.name.as_str()) {
                return Err(format!(
                    "duplicate device {:?} in {}",
                    device.name,
                    path.display()
                ));
            }
            if !matches!(device.kind.as_str(), "host" | "android" | "esp") {
                return Err(format!(
                    "device {} has unsupported kind {:?}",
                    device.name, device.kind
                ));
            }
            // Serial is optional: production control-plane evaluation uses
            // the descriptor MAC plus host NAN/UDP6, while the legacy local
            // matrix may still require a serial adapter explicitly.
            if let Some(baud) = device.uart_baud {
                if !matches!(
                    baud,
                    9_600 | 19_200 | 38_400 | 57_600 | 115_200 | 230_400 | 460_800 | 921_600
                ) {
                    return Err(format!(
                        "device {} has unsupported uart_baud {baud}",
                        device.name
                    ));
                }
            }
        }
        let known = names;
        if let Some(matrix) = &self.device_matrix {
            if matrix.min_android_witnesses == 0 {
                return Err("device_matrix.min_android_witnesses must be positive".to_owned());
            }
            if matrix.settle_ms == 0 || matrix.attempts == 0 {
                return Err("device_matrix settle_ms and attempts must be positive".to_owned());
            }
            for source in &matrix.sources {
                if !matches!(source.as_str(), "android" | "host" | "esp") {
                    return Err(format!("device_matrix has unsupported source {source:?}"));
                }
            }
            for target in &matrix.targets {
                if !known.contains(target.as_str()) {
                    return Err(format!(
                        "device_matrix target {target} is not a configured device"
                    ));
                }
            }
        }
        for pair in &self.pairs {
            if !known.contains(pair.source.as_str()) || !known.contains(pair.target.as_str()) {
                return Err(format!("pair {} references an undefined device", pair.name));
            }
            // An empty list means the normal integration matrix: select every
            // row jointly supported by the two discovered descriptors. A
            // non-empty list remains a narrow developer/reproduction filter.
            for test in &pair.tests {
                if !matches!(
                    test.as_str(),
                    "now-short"
                        | "now-probe"
                        | "udp6-association"
                        | "udp6-probe"
                        | "nan"
                        | "scan"
                        | "android-handlers"
                ) {
                    return Err(format!(
                        "pair {} has unsupported test {:?}",
                        pair.name, test
                    ));
                }
            }
            if !pair.path.is_empty() {
                if pair.path.len() < 3 {
                    return Err(format!(
                        "pair {} path must contain source, at least one relay, and target",
                        pair.name
                    ));
                }
                if pair
                    .path
                    .first()
                    .is_none_or(|node| node.node != pair.source)
                    || pair.path.last().is_none_or(|node| node.node != pair.target)
                {
                    return Err(format!(
                        "pair {} path must start at {} and end at {}",
                        pair.name, pair.source, pair.target
                    ));
                }
                for node in &pair.path {
                    if !known.contains(node.node.as_str()) {
                        return Err(format!(
                            "pair {} path references undefined device {}",
                            pair.name, node.node
                        ));
                    }
                    parse_chain_node(node).map_err(|error| {
                        format!("pair {} path node {}: {error}", pair.name, node.node)
                    })?;
                }
            }
        }
        Ok(())
    }

    pub fn device(&self, name: &str) -> Option<&E2eDeviceConfig> {
        self.devices.iter().find(|device| device.name == name)
    }

    pub fn require_device(&self, name: &str) -> Result<&E2eDeviceConfig, String> {
        self.device(name)
            .ok_or_else(|| format!("configured device {name} is missing"))
    }

    /// Devices selected as candidate matrix targets before live probing.
    /// Android is a witness/source rather than a target unless named
    /// explicitly by the operator.
    pub fn device_matrix_targets(&self) -> Vec<&E2eDeviceConfig> {
        let configured = self.device_matrix.as_ref().map(|matrix| &matrix.targets);
        self.devices
            .iter()
            .filter(|device| match configured {
                Some(targets) if !targets.is_empty() => targets.contains(&device.name),
                _ => device.kind != "android",
            })
            .collect()
    }

    pub fn pair(&self, source: &str, target: &str) -> Option<&E2ePairConfig> {
        self.pairs
            .iter()
            .find(|pair| pair.source == source && pair.target == target)
    }

    /// Resolve an optional TOML path to the CP chain-handler representation.
    /// The returned list is `[source, relay..., destination]` and can be
    /// passed directly to `relay::install_symmetric_chain` after the local
    /// adapter resolves each bearer/address into a device-local next-hop.
    pub fn relay_chain(
        &self,
        source: &str,
        target: &str,
    ) -> Result<Option<Vec<dmesh_server::relay::ChainNode>>, String> {
        let Some(pair) = self.pair(source, target) else {
            return Ok(None);
        };
        if pair.path.is_empty() {
            return Ok(None);
        }
        pair.path
            .iter()
            .map(parse_chain_node)
            .collect::<Result<Vec<_>, _>>()
            .map(Some)
    }

    /// Resolve the two human-selected descriptor names used by a local bench
    /// invocation.  Names select local adapters only; radio discovery still
    /// uses `nan_mac`/`mac` after the executor has begun the probe.
    pub fn select_esp_pair_by_name(
        &self,
        source_name: Option<&str>,
        target_name: Option<&str>,
    ) -> Result<(&E2eDeviceConfig, &E2eDeviceConfig), String> {
        match (source_name, target_name) {
            (Some(source_name), Some(target_name)) => {
                let source = self.require_device(source_name)?;
                let target = self.require_device(target_name)?;
                if source.name == target.name {
                    return Err("source and target must select distinct devices".to_owned());
                }
                if source.kind != "esp" || target.kind != "esp" {
                    return Err(
                        "the current firmware pair prober requires two ESP descriptors".to_owned(),
                    );
                }
                if !source.e2e_enabled || !target.e2e_enabled {
                    return Err("selected ESP descriptor is disabled for generic E2E".to_owned());
                }
                Ok((source, target))
            }
            (None, None) => self.select_esp_pair(None, None),
            _ => Err("set both DMESH_E2E_SOURCE and DMESH_E2E_TARGET, or neither".to_owned()),
        }
    }

    /// Resolve a live discovery identity to its local adapter descriptor.
    ///
    /// Discovery identities are deliberately the selection key for the
    /// prober: a board nickname is useful only to a human reading a config
    /// file, while NAN announcements and control commands use the six-byte
    /// radio identity.  `nan_mac` wins because it is the advertised identity;
    /// `mac` remains the fallback for devices whose two addresses are equal.
    pub fn device_by_discovery_id(&self, id: &str) -> Option<&E2eDeviceConfig> {
        let wanted = normalize_discovery_id(id)?;
        self.devices.iter().find(|device| {
            device
                .nan_mac
                .as_deref()
                .or(device.mac.as_deref())
                .and_then(normalize_discovery_id)
                .is_some_and(|candidate| candidate == wanted)
        })
    }

    /// Return the two explicitly selected discovery identities, or the only
    /// two configured ESP adapters when a lab contains exactly two.  The
    /// latter is a convenience for a small bench, not a board-name contract:
    /// any larger fleet must name two radio identities explicitly.
    pub fn select_esp_pair(
        &self,
        source_id: Option<&str>,
        target_id: Option<&str>,
    ) -> Result<(&E2eDeviceConfig, &E2eDeviceConfig), String> {
        match (source_id, target_id) {
            (Some(source_id), Some(target_id)) => {
                let source = self.device_by_discovery_id(source_id).ok_or_else(|| {
                    format!("no configured device advertises discovery id {source_id:?}")
                })?;
                let target = self.device_by_discovery_id(target_id).ok_or_else(|| {
                    format!("no configured device advertises discovery id {target_id:?}")
                })?;
                if source.name == target.name {
                    return Err("source_id and target_id must select distinct devices".to_owned());
                }
                if !source.e2e_enabled || !target.e2e_enabled {
                    return Err("selected ESP descriptor is disabled for generic E2E".to_owned());
                }
                Ok((source, target))
            }
            (None, None) => {
                let mut endpoints = self
                    .devices
                    .iter()
                    .filter(|device| device.kind == "esp" && device.e2e_enabled);
                let source = endpoints
                    .next()
                    .ok_or_else(|| "no configured ESP device".to_owned())?;
                let target = endpoints.next().ok_or_else(|| "need exactly two configured ESP devices or DMESH_E2E_SOURCE_ID/DMESH_E2E_TARGET_ID".to_owned())?;
                if endpoints.next().is_some() {
                    return Err("more than two configured ESP devices: select the pair with DMESH_E2E_SOURCE_ID and DMESH_E2E_TARGET_ID".to_owned());
                }
                Ok((source, target))
            }
            _ => Err("set both DMESH_E2E_SOURCE_ID and DMESH_E2E_TARGET_ID, or neither".to_owned()),
        }
    }
}

fn normalize_discovery_id(id: &str) -> Option<String> {
    let compact: String = id.chars().filter(|character| *character != ':').collect();
    if compact.len() != 12 || !compact.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    Some(compact.to_ascii_lowercase())
}

fn parse_chain_node(node: &E2ePathNode) -> Result<dmesh_server::relay::ChainNode, String> {
    use dmesh_server::{
        relay::{ChainNode, LinkAddress},
        transport_path::TransportId,
    };

    match node.transport.as_str() {
        "now" => {
            let compact = normalize_discovery_id(&node.address)
                .ok_or_else(|| "NOW address must be a six-byte MAC".to_owned())?;
            let mut mac = [0; 6];
            for (index, byte) in mac.iter_mut().enumerate() {
                *byte = u8::from_str_radix(&compact[index * 2..index * 2 + 2], 16)
                    .map_err(|_| "NOW address must be hexadecimal".to_owned())?;
            }
            Ok(ChainNode {
                transport: TransportId::NOW,
                address: LinkAddress::Mac(mac),
            })
        }
        "udp6" => {
            let address = node.address.parse::<std::net::Ipv6Addr>().map_err(|_| {
                "UDP6 address must be IPv6 link-local without an interface scope".to_owned()
            })?;
            let address = address.octets();
            if address[0] != 0xfe || address[1] & 0xc0 != 0x80 {
                return Err("UDP6 address must be in fe80::/10".to_owned());
            }
            Ok(ChainNode {
                transport: TransportId::UDP6,
                address: LinkAddress::Ipv6LinkLocal(address),
            })
        }
        _ => Err("transport must be now or udp6".to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_named_pair_without_hardware_names() {
        let config: E2eConfig = toml::from_str(
            r#"
                [[devices]]
                name = "a"
                kind = "esp"
                serial = "/dev/a"
                [[devices]]
                name = "b"
                kind = "esp"
                serial = "/dev/b"
                [[pairs]]
                name = "a-b"
                source = "a"
                target = "b"
                tests = ["nan"]
            "#,
        )
        .unwrap();
        config.validate(Path::new("fixture.toml")).unwrap();
        assert_eq!(
            config.require_device("a").unwrap().serial.as_deref(),
            Some("/dev/a")
        );
        assert_eq!(config.pair("a", "b").unwrap().name, "a-b");
    }

    #[test]
    fn resolves_mixed_now_udp6_relay_path() {
        let config: E2eConfig = toml::from_str(
            r#"
                [[devices]]
                name = "a"
                kind = "esp"
                [[devices]]
                name = "b"
                kind = "esp"
                [[devices]]
                name = "c"
                kind = "esp"
                [[devices]]
                name = "d"
                kind = "esp"
                [[pairs]]
                name = "a-d"
                source = "a"
                target = "d"
                tests = []
                path = [
                    { node = "a", transport = "now", address = "02:00:00:00:00:0a" },
                    { node = "b", transport = "now", address = "02:00:00:00:00:0b" },
                    { node = "c", transport = "udp6", address = "fe80::c" },
                    { node = "d", transport = "udp6", address = "fe80::d" },
                ]
            "#,
        )
        .unwrap();
        config.validate(Path::new("fixture.toml")).unwrap();
        let path = config.relay_chain("a", "d").unwrap().unwrap();
        assert_eq!(path.len(), 4);
        assert_eq!(
            path[1].transport,
            dmesh_server::transport_path::TransportId::NOW
        );
        assert_eq!(
            path[3].transport,
            dmesh_server::transport_path::TransportId::UDP6
        );
    }

    #[test]
    fn resolves_explicit_esp_descriptor_names() {
        let config: E2eConfig = toml::from_str(
            r#"
                [[devices]]
                name = "one"
                kind = "esp"
                [[devices]]
                name = "two"
                kind = "esp"
                [[devices]]
                name = "phone"
                kind = "android"
            "#,
        )
        .unwrap();
        let (source, target) = config
            .select_esp_pair_by_name(Some("two"), Some("one"))
            .unwrap();
        assert_eq!(source.name, "two");
        assert_eq!(target.name, "one");
    }

    #[test]
    fn selects_a_pair_by_advertised_identity_not_nickname() {
        let config: E2eConfig = toml::from_str(
            r#"
                [[devices]]
                name = "bench-left"
                kind = "esp"
                mac = "001122334455"
                nan_mac = "aabbccddeeff"
                [[devices]]
                name = "bench-right"
                kind = "esp"
                mac = "102132435465"
            "#,
        )
        .unwrap();
        let (source, target) = config
            .select_esp_pair(Some("aa:bb:cc:dd:ee:ff"), Some("102132435465"))
            .unwrap();
        assert_eq!(source.name, "bench-left");
        assert_eq!(target.name, "bench-right");
    }

    #[test]
    fn parses_catalog_device_matrix_and_selects_non_android_targets() {
        let config: E2eConfig = toml::from_str(
            r#"
                [device_matrix]
                min_android_witnesses = 1
                settle_ms = 12000
                attempts = 3
                sources = ["android", "host", "esp"]
                targets = ["esp-a"]

                [[devices]]
                name = "android-a"
                kind = "android"
                [[devices]]
                name = "host"
                kind = "host"
                [[devices]]
                name = "esp-a"
                kind = "esp"
            "#,
        )
        .unwrap();
        config.validate(Path::new("fixture.toml")).unwrap();
        let matrix = config.device_matrix.as_ref().unwrap();
        assert_eq!(matrix.attempts, 3);
        assert_eq!(
            config
                .device_matrix_targets()
                .iter()
                .map(|device| device.name.as_str())
                .collect::<Vec<_>>(),
            vec!["esp-a"]
        );
    }

    #[test]
    fn rejects_unknown_catalog_device_matrix_target() {
        let config: E2eConfig = toml::from_str(
            r#"
                [device_matrix]
                targets = ["missing"]
                [[devices]]
                name = "android-a"
                kind = "android"
            "#,
        )
        .unwrap();
        assert!(config.validate(Path::new("fixture.toml")).is_err());
    }
}
