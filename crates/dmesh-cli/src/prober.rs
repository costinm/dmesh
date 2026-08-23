//! File-backed device descriptors for the shared control-plane prober.
//!
//! This module deliberately contains configuration and name resolution only.
//! Hardware adapters (UART, UDP6, host NAN, and Android APIs) execute the
//! bearer-neutral `dmesh_server::probe::ProbeRequest`; tests and production
//! evaluators therefore consume the same descriptor file without embedding
//! board names or serial paths in their probe logic.

use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct E2eDeviceConfig {
    pub name: String,
    pub kind: String,
    #[serde(default)]
    pub serial: Option<String>,
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
    /// A sleepy endpoint has no always-on command path. Its probe requires a
    /// live NAN clock/control plane before it can enter an active test mode.
    /// Active endpoints retain NOW as the fallback when a host lacks NAN.
    #[serde(default)]
    pub sleepy: bool,
}

fn default_baseline() -> String {
    "nan".to_owned()
}

fn default_true() -> bool {
    true
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct E2ePairConfig {
    pub name: String,
    pub source: String,
    pub target: String,
    pub tests: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct E2eConfig {
    pub devices: Vec<E2eDeviceConfig>,
    #[serde(default)]
    pub pairs: Vec<E2ePairConfig>,
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

    pub fn validate(&self, path: &Path) -> Result<(), String> {
        let mut names = std::collections::BTreeSet::new();
        for device in &self.devices {
            if !names.insert(device.name.as_str()) {
                return Err(format!("duplicate device {:?} in {}", device.name, path.display()));
            }
            if !matches!(device.kind.as_str(), "host" | "android" | "esp") {
                return Err(format!("device {} has unsupported kind {:?}", device.name, device.kind));
            }
            // Serial is optional: production control-plane evaluation uses
            // the descriptor MAC plus host NAN/UDP6, while the legacy local
            // matrix may still require a serial adapter explicitly.
        }
        let known = names;
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
                    "now-short" | "now-iperf" | "udp6-association" | "udp6-iperf" | "nan" | "scan" | "android-handlers"
                ) {
                    return Err(format!("pair {} has unsupported test {:?}", pair.name, test));
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

    pub fn pair(&self, source: &str, target: &str) -> Option<&E2ePairConfig> {
        self.pairs
            .iter()
            .find(|pair| pair.source == source && pair.target == target)
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
                let source = self
                    .device_by_discovery_id(source_id)
                    .ok_or_else(|| format!("no configured device advertises discovery id {source_id:?}"))?;
                let target = self
                    .device_by_discovery_id(target_id)
                    .ok_or_else(|| format!("no configured device advertises discovery id {target_id:?}"))?;
                if source.name == target.name {
                    return Err("source_id and target_id must select distinct devices".to_owned());
                }
                Ok((source, target))
            }
            (None, None) => {
                let mut endpoints = self.devices.iter().filter(|device| device.kind == "esp");
                let source = endpoints.next().ok_or_else(|| "no configured ESP device".to_owned())?;
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
        assert_eq!(config.require_device("a").unwrap().serial.as_deref(), Some("/dev/a"));
        assert_eq!(config.pair("a", "b").unwrap().name, "a-b");
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
}
