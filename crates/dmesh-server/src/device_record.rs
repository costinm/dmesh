//! Device records: what a node persists about a device it knows.
//!
//! A [`DeviceRecord`] holds the long- and medium-lived attributes of one device (identity, name,
//! domain, type, static addresses, wake capability) and, when there is one, the secret shared with
//! it. A [`DeviceStore`] keeps them as one TOML file per device. Everything dynamic (live endpoints
//! per bearer, last-seen, RTT, sleep state) stays in RAM and is rebuilt by discovery.
//!
//! Records are written by pairing, by discovery observations (merged without ever replacing a
//! secret or lowering trust) and by an operator importing known devices. The code that decides what
//! is persisted lives here, so Linux, Android and the CLI behave the same.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Bytes in a record file are hex text; a legacy JSON file wrote them as number arrays and is
/// still read.
mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        let mut text = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            use core::fmt::Write;
            let _ = write!(text, "{byte:02x}");
        }
        serializer.serialize_str(&text)
    }

    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Text {
        Hex(String),
        Array(Vec<u8>),
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        match Text::deserialize(deserializer)? {
            Text::Array(bytes) => Ok(bytes),
            Text::Hex(text) => {
                let text: String = text.chars().filter(|c| !c.is_whitespace() && *c != ':').collect();
                if text.len() % 2 != 0 {
                    return Err(serde::de::Error::custom("odd-length hex"));
                }
                (0..text.len())
                    .step_by(2)
                    .map(|i| {
                        u8::from_str_radix(&text[i..i + 2], 16).map_err(serde::de::Error::custom)
                    })
                    .collect()
            }
        }
    }
}

/// A MAC in a record file: `aa:bb:cc:dd:ee:ff` (a legacy file wrote six numbers).
mod mac_text {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(mac: &Option<[u8; 6]>, serializer: S) -> Result<S::Ok, S::Error> {
        match mac {
            Some(mac) => serializer.serialize_str(&format!(
                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
            )),
            None => serializer.serialize_none(),
        }
    }

    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Text {
        Text(String),
        Array([u8; 6]),
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<[u8; 6]>, D::Error> {
        let Some(value) = Option::<Text>::deserialize(deserializer)? else {
            return Ok(None);
        };
        match value {
            Text::Array(mac) => Ok(Some(mac)),
            Text::Text(text) => {
                let mut mac = [0u8; 6];
                let mut parts = text.split(':');
                for byte in &mut mac {
                    *byte = u8::from_str_radix(parts.next().ok_or_else(|| serde::de::Error::custom("short MAC"))?, 16)
                        .map_err(serde::de::Error::custom)?;
                }
                if parts.next().is_some() {
                    return Err(serde::de::Error::custom("long MAC"));
                }
                Ok(Some(mac))
            }
        }
    }
}

/// Where a record's identity came from, weakest to strongest.
pub mod trust {
    /// Seen in discovery with a valid signature; never confirmed by the owner.
    pub const FIRST_SEEN: &str = "first-seen";
    /// Paired by this controller (a secret was installed).
    pub const PAIRED: &str = "paired";
    /// Verified against a certificate (the ssh-mesh work).
    pub const VERIFIED: &str = "verified";
}

/// One node's persisted record: the attributes that are long- or medium-lived and a stale copy of
/// which is still a good hint after a day. Everything dynamic (live endpoints per bearer,
/// last-seen, RTT, sleep state) lives in RAM and is rebuilt by discovery.
///
/// One TOML file per node (see [`DeviceStore`]). It holds a secret when one was installed or
/// provisioned, whether or not this controller owns the device; how secrets are stored may change
/// with the security work.
#[derive(Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct DeviceRecord {
    pub device_id: String,
    pub name: Option<String>,
    /// Stable MAC, when the device has one that does not change.
    #[serde(default, with = "mac_text", skip_serializing_if = "Option::is_none")]
    pub mac: Option<[u8; 6]>,
    /// The NAN interface MAC when it differs from `mac`.
    #[serde(default, with = "mac_text", skip_serializing_if = "Option::is_none")]
    pub nan_mac: Option<[u8; 6]>,
    #[serde(default, with = "hex_bytes", skip_serializing_if = "Vec::is_empty")]
    pub public_key: Vec<u8>,
    /// Control-plane root installed during pairing (controller key or CA).
    #[serde(default, with = "hex_bytes", skip_serializing_if = "Vec::is_empty")]
    pub root_public_key: Vec<u8>,
    pub vip6: Option<String>,
    /// Administrative domain; with `name` it forms the node's FQDN `NAME.DOMAIN`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    /// Device type as announced (for example `esp32c6`, `android`, `host`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_type: Option<String>,
    /// A static IPv4 (an ESP32's address from provisioning, not DHCP).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ipv4: Option<String>,
    /// A static or last-known IPv6 or other base ("home") address: a hint, never the live address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub home_address: Option<String>,
    /// The UDP port the node serves, when it is not the standard one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub udp_port: Option<u16>,
    /// The node sleeps (a capability, not whether it is asleep now).
    #[serde(default, skip_serializing_if = "core::ops::Not::not")]
    pub sleepy: bool,
    /// Bearers that can wake it (`nan`, `now`, `uart`, `ble`, ...).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub wake_bearers: Vec<String>,
    /// UART speed of its serial endpoint, when not the default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uart_baud: Option<u32>,
    /// `first-seen`, `paired` or `verified` (see [`trust`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust: Option<String>,
    /// Bearer-local identifiers that reach the node: the serial path, the BLE address.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub endpoints: BTreeMap<String, String>,
    #[serde(default, with = "hex_bytes", skip_serializing_if = "Vec::is_empty")]
    pub secret: Vec<u8>,
}

impl core::fmt::Debug for DeviceRecord {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("DeviceRecord")
            .field("device_id", &self.device_id)
            .field("name", &self.name)
            .field("mac", &self.mac)
            .field("public_key", &self.public_key)
            .field("root_public_key", &self.root_public_key)
            .field("vip6", &self.vip6)
            .field("domain", &self.domain)
            .field("device_type", &self.device_type)
            .field("trust", &self.trust)
            .field("endpoints", &self.endpoints)
            .field("secret", &"<redacted>")
            .finish()
    }
}

impl DeviceRecord {
    /// The persisted part of what a signed announce says about a node: identity (device id, public
    /// key, VIP6), name and domain, device type and the UDP port it serves. `mac` is the radio MAC
    /// the caller correlated to the announce (an announce does not carry one). Everything dynamic in
    /// the announce (uptime, endpoints, NAN visibility) is left out; it stays in RAM. `None` when the
    /// announce has no valid signed identity: an unproven node gets no record.
    pub fn from_announce(announce: &crate::announce::Announce, mac: Option<[u8; 6]>) -> Option<Self> {
        if !announce.has_identity()
            || !crate::announce::verify_identity(*announce)
            || announce.public_key().len() != 33
        {
            return None;
        }
        let vip6 = crate::announce::virtual_ip6(announce.public_key())?;
        let mut device_id = String::new();
        for byte in announce.device_id() {
            use core::fmt::Write;
            let _ = write!(device_id, "{byte:02x}");
        }
        Some(Self {
            device_id,
            name: announce.device_name().map(str::to_owned),
            mac,
            public_key: announce.public_key().to_vec(),
            vip6: Some(std::net::Ipv6Addr::from(vip6).to_string()),
            domain: announce.device_domain().map(str::to_owned),
            device_type: (announce.device_class != crate::announce::DEVICE_CLASS_UNKNOWN)
                .then(|| crate::announce::device_class_name(announce.device_class).to_owned()),
            udp_port: (announce.udp_port != 0 && announce.udp_port != 3339).then_some(announce.udp_port),
            trust: Some(trust::FIRST_SEEN.to_owned()),
            ..Default::default()
        })
    }

    /// Fold what discovery observed into this record without lowering what is known: a field the
    /// observation lacks stays; `secret`, `root_public_key` and a stronger `trust` are never
    /// changed. Returns whether anything changed (callers write only then).
    pub fn merge_observed(&mut self, observed: &DeviceRecord) -> bool {
        let before = toml::to_string(&*self).unwrap_or_default();
        fn fill<T: Clone>(slot: &mut Option<T>, value: &Option<T>) {
            if value.is_some() {
                *slot = value.clone();
            }
        }
        fill(&mut self.name, &observed.name);
        fill(&mut self.mac, &observed.mac);
        fill(&mut self.nan_mac, &observed.nan_mac);
        fill(&mut self.domain, &observed.domain);
        fill(&mut self.device_type, &observed.device_type);
        fill(&mut self.ipv4, &observed.ipv4);
        fill(&mut self.home_address, &observed.home_address);
        fill(&mut self.udp_port, &observed.udp_port);
        fill(&mut self.uart_baud, &observed.uart_baud);
        if !observed.public_key.is_empty() && self.public_key.is_empty() {
            self.public_key = observed.public_key.clone();
        }
        self.sleepy |= observed.sleepy;
        for bearer in &observed.wake_bearers {
            if !self.wake_bearers.contains(bearer) {
                self.wake_bearers.push(bearer.clone());
            }
        }
        for (bearer, address) in &observed.endpoints {
            self.endpoints.entry(bearer.clone()).or_insert_with(|| address.clone());
        }
        let rank = |trust: &Option<String>| match trust.as_deref() {
            Some(trust::VERIFIED) => 3,
            Some(trust::PAIRED) => 2,
            Some(trust::FIRST_SEEN) => 1,
            _ => 0,
        };
        if rank(&observed.trust) > rank(&self.trust) {
            self.trust = observed.trust.clone();
        }
        // A record that holds a secret was paired, whatever an older file said.
        if !self.secret.is_empty() && rank(&self.trust) < 2 {
            self.trust = Some(trust::PAIRED.to_owned());
        }
        before != toml::to_string(&*self).unwrap_or_default()
    }
}


/// The device record files of one node: one or more directories, the first being where records are
/// written (mode 0700; files 0600, they may hold a secret). Each device has one
/// `<16 hex digits of its VIP6>.toml`, or `mac-<12 hex digits>.toml` while a declared device has no
/// identity yet; a legacy `.json` file is read and replaced by a `.toml` on the next write.
#[derive(Clone, Debug)]
pub struct DeviceStore {
    directories: Vec<PathBuf>,
}

impl DeviceStore {
    /// `:`-separated directories of device records; the first is written.
    pub const NODES_ENV: &'static str = "DMESH_NODES_DIR";
    /// The directory lmesh and Android write their records to.
    pub const PAIRED_ENV: &'static str = "DMESH_PAIRED_DEVICES_DIR";

    /// A store of one directory.
    pub fn new(directory: impl Into<PathBuf>) -> Self {
        Self { directories: vec![directory.into()] }
    }

    /// A store of several directories, in priority order (a device in two keeps the first).
    pub fn with_directories(directories: Vec<PathBuf>) -> Self {
        assert!(!directories.is_empty(), "a device store needs a directory");
        Self { directories }
    }

    /// The store the environment names (`DMESH_NODES_DIR`, then `DMESH_PAIRED_DEVICES_DIR`). With
    /// neither set it is `default`, or `$HOME/.config/dmesh/nodes`.
    pub fn from_env(default: Option<&Path>) -> Self {
        let mut directories = Vec::new();
        for variable in [Self::NODES_ENV, Self::PAIRED_ENV] {
            if let Some(value) = std::env::var_os(variable) {
                directories.extend(std::env::split_paths(&value).filter(|path| !path.as_os_str().is_empty()));
            }
        }
        if directories.is_empty() {
            directories.push(default.map(Path::to_path_buf).unwrap_or_else(|| {
                std::env::var_os("HOME")
                    .map(|home| PathBuf::from(home).join(".config/dmesh/nodes"))
                    .unwrap_or_else(|| PathBuf::from("dmesh-nodes"))
            }));
        }
        Self { directories }
    }

    /// Add a lower-priority directory that is searched but never written.
    pub fn also_read(mut self, directory: impl Into<PathBuf>) -> Self {
        self.directories.push(directory.into());
        self
    }

    pub fn directories(&self) -> &[PathBuf] {
        &self.directories
    }

    /// Where records are written.
    pub fn write_directory(&self) -> &Path {
        &self.directories[0]
    }

    fn stem(vip6: &str) -> Result<String, String> {
        let address: std::net::Ipv6Addr = vip6.parse().map_err(|_| "invalid device VIP6")?;
        let mut name = String::with_capacity(16);
        for byte in &address.octets()[8..] {
            use core::fmt::Write;
            write!(&mut name, "{byte:02x}").map_err(|_| "encode device VIP6")?;
        }
        Ok(name)
    }

    /// A record is keyed by its VIP6; a declared device that has not been seen yet (no identity) by
    /// its MAC, until discovery supplies the VIP6 and the record moves to the VIP6 key.
    fn stem_of(device: &DeviceRecord) -> Result<String, String> {
        if let Some(vip6) = device.vip6.as_deref() {
            return Self::stem(vip6);
        }
        let mac = device.mac.ok_or("record needs a VIP6 or a MAC")?;
        Ok(format!("mac-{}", mac.iter().map(|byte| format!("{byte:02x}")).collect::<String>()))
    }

    fn read_file(path: &Path) -> Result<Option<DeviceRecord>, String> {
        let bytes = match std::fs::read(path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(format!("read device record: {error}")),
        };
        let device: DeviceRecord = if path.extension().is_some_and(|ext| ext == "json") {
            serde_json::from_slice(&bytes).map_err(|error| format!("parse device record: {error}"))?
        } else {
            toml::from_str(std::str::from_utf8(&bytes).map_err(|error| error.to_string())?)
                .map_err(|error| format!("parse device record: {error}"))?
        };
        // A record with a secret must be private; one without (a discovered or declared device,
        // a checked-in fixture) may be shared.
        #[cfg(unix)]
        if !device.secret.is_empty() {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(path)
                .map_err(|error| format!("stat device record: {error}"))?
                .permissions()
                .mode();
            if mode & 0o077 != 0 {
                return Err("device record with a secret must be mode 0600".into());
            }
        }
        Ok(Some(device))
    }

    fn read_directory(directory: &Path) -> Result<BTreeMap<String, DeviceRecord>, String> {
        let mut found: BTreeMap<String, DeviceRecord> = BTreeMap::new();
        let entries = match std::fs::read_dir(directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(found),
            Err(error) => return Err(format!("read device directory: {error}")),
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let is_toml = path.extension().is_some_and(|ext| ext == "toml");
            let is_json = path.extension().is_some_and(|ext| ext == "json");
            if !(is_toml || is_json) {
                continue;
            }
            let stem = path.file_stem().and_then(|stem| stem.to_str()).unwrap_or_default().to_owned();
            if is_json && found.contains_key(&stem) {
                continue;
            }
            if let Some(device) = Self::read_file(&path)? {
                found.insert(stem, device);
            }
        }
        Ok(found)
    }

    /// Every record, the first directory winning for a device present in several.
    pub fn list(&self) -> Result<Vec<DeviceRecord>, String> {
        let mut seen = std::collections::BTreeSet::new();
        let mut devices = Vec::new();
        for directory in &self.directories {
            for (_, device) in Self::read_directory(directory)? {
                let key = device
                    .vip6
                    .clone()
                    .or_else(|| device.mac.map(|mac| format!("mac-{mac:02x?}")))
                    .unwrap_or_else(|| device.device_id.clone());
                if seen.insert(key) {
                    devices.push(device);
                }
            }
        }
        Ok(devices)
    }

    /// The record of a device by its VIP6.
    pub fn load(&self, vip6: &str) -> Result<Option<DeviceRecord>, String> {
        let stem = Self::stem(vip6)?;
        let wanted = vip6.parse::<std::net::Ipv6Addr>().ok();
        for directory in &self.directories {
            for extension in ["toml", "json"] {
                if let Some(device) = Self::read_file(&directory.join(format!("{stem}.{extension}")))? {
                    if device.vip6.as_deref().and_then(|value| value.parse::<std::net::Ipv6Addr>().ok()) != wanted {
                        return Err("device record VIP6 does not match its file name".into());
                    }
                    return Ok(Some(device));
                }
            }
        }
        Ok(None)
    }

    /// The record of a device by VIP6, name (case-insensitive) or FQDN `NAME.DOMAIN`.
    pub fn find(&self, target: &str) -> Result<Option<DeviceRecord>, String> {
        if let Ok(address) = target.parse::<std::net::Ipv6Addr>() {
            return self.load(&address.to_string());
        }
        Ok(self.list()?.into_iter().find(|device| {
            device.name.as_deref().is_some_and(|name| {
                name.eq_ignore_ascii_case(target)
                    || device.domain.as_deref().is_some_and(|domain| format!("{name}.{domain}").eq_ignore_ascii_case(target))
            })
        }))
    }

    fn write(&self, device: &DeviceRecord, replace: bool) -> Result<(), String> {
        use std::io::Write;
        #[cfg(unix)]
        use std::os::unix::fs::OpenOptionsExt;
        let directory = self.write_directory();
        let stem = Self::stem_of(device)?;
        std::fs::create_dir_all(directory)
            .map_err(|error| format!("create device directory: {error}"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700))
                .map_err(|error| format!("protect device directory: {error}"))?;
        }
        let path = directory.join(format!("{stem}.toml"));
        let legacy = directory.join(format!("{stem}.json"));
        if !replace && (path.exists() || legacy.exists()) {
            return Err("device already has a record".into());
        }
        let temporary = path.with_extension("toml.tmp");
        let _ = std::fs::remove_file(&temporary);
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = options
            .open(&temporary)
            .map_err(|error| format!("create device record: {error}"))?;
        let text = toml::to_string_pretty(device)
            .map_err(|error| format!("encode device record: {error}"))?;
        file.write_all(text.as_bytes())
            .and_then(|_| file.sync_all())
            .map_err(|error| format!("write device record: {error}"))?;
        std::fs::rename(&temporary, &path)
            .map_err(|error| format!("commit device record: {error}"))?;
        let _ = std::fs::remove_file(&legacy);
        Ok(())
    }

    /// Write a record, replacing the device's: an operator's declaration, a provisioning result. No
    /// secret is required.
    pub fn put(&self, device: &DeviceRecord) -> Result<(), String> {
        self.write(device, true)
    }

    /// Commit a pairing result. It needs the secret, the signed identity and the control-plane root,
    /// and it does not replace an existing record in the write directory (a re-pair removes the old
    /// one first).
    pub fn save_paired(&self, device: &DeviceRecord) -> Result<(), String> {
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
        let mut device = device.clone();
        device.trust = Some(trust::PAIRED.to_owned());
        self.write(&device, false)
    }

    /// Merge a discovery observation into the device's record, creating a `first-seen` record when
    /// there is none. Writes only when something changed; a record that holds a secret keeps it.
    /// Returns whether a file was written.
    pub fn observe(&self, observed: &DeviceRecord) -> Result<bool, String> {
        let vip6 = observed.vip6.as_deref().ok_or("observed device has no VIP6")?;
        if let Some(mut existing) = self.load(vip6)? {
            if existing.merge_observed(observed) {
                self.write(&existing, true)?;
                return Ok(true);
            }
            return Ok(false);
        }
        // A declared device with no identity yet, recognised by its MAC, becomes this device.
        if let Some(mac) = observed.mac
            && let Some(mut declared) = self
                .list()?
                .into_iter()
                .find(|device| device.vip6.is_none() && device.mac == Some(mac))
        {
            let old = self.write_directory().join(format!("{}.toml", Self::stem_of(&declared)?));
            declared.vip6 = observed.vip6.clone();
            declared.device_id = observed.device_id.clone();
            declared.merge_observed(observed);
            declared.trust = declared.trust.or_else(|| Some(trust::FIRST_SEEN.to_owned()));
            self.write(&declared, false)?;
            let _ = std::fs::remove_file(old);
            return Ok(true);
        }
        let mut created = observed.clone();
        created.secret.clear();
        created.root_public_key.clear();
        created.trust = Some(trust::FIRST_SEEN.to_owned());
        self.write(&created, false)?;
        Ok(true)
    }

    /// Record what a signed announce says about its sender (see [`DeviceRecord::from_announce`]);
    /// `Ok(false)` when the announce proves no identity or nothing changed.
    pub fn observe_announce(&self, announce: &crate::announce::Announce, mac: Option<[u8; 6]>) -> Result<bool, String> {
        match DeviceRecord::from_announce(announce, mac) {
            Some(record) => self.observe(&record),
            None => Ok(false),
        }
    }

    pub fn remove(&self, vip6: &str) -> Result<(), String> {
        let stem = Self::stem(vip6)?;
        let directory = self.write_directory();
        let removed_legacy = std::fs::remove_file(directory.join(format!("{stem}.json"))).is_ok();
        match std::fs::remove_file(directory.join(format!("{stem}.toml"))) {
            Ok(()) => Ok(()),
            Err(_) if removed_legacy => Ok(()),
            Err(error) => Err(format!("remove device record: {error}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paired() -> DeviceRecord {
        DeviceRecord {
            device_id: "d1".into(),
            name: Some("light1".into()),
            mac: Some([0x20, 0x6e, 0xf1, 0x13, 0xb1, 0x70]),
            public_key: vec![2; 33],
            root_public_key: vec![3; 33],
            vip6: Some("fc00::1".into()),
            secret: vec![7; 32],
            ..Default::default()
        }
    }

    #[test]
    fn a_pairing_result_is_private_and_does_not_replace_an_existing_record() {
        let directory = tempfile::tempdir().unwrap();
        let store = DeviceStore::new(directory.path());
        let device = paired();
        store.save_paired(&device).unwrap();
        assert_eq!(store.load("fc00::1").unwrap().unwrap().secret, device.secret);
        assert!(store.save_paired(&device).is_err());
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let file = directory.path().join("0000000000000001.toml");
            assert_eq!(std::fs::metadata(file).unwrap().permissions().mode() & 0o777, 0o600);
        }
        store.remove("fc00::1").unwrap();
        assert!(store.load("fc00::1").unwrap().is_none());
    }

    #[test]
    fn a_record_is_toml_with_hex_bytes_and_a_text_mac_and_round_trips() {
        let directory = tempfile::tempdir().unwrap();
        let store = DeviceStore::new(directory.path());
        let mut device = paired();
        device.domain = Some("mesh.example.com".into());
        device.sleepy = true;
        device.wake_bearers = vec!["nan".into(), "uart".into()];
        device.ipv4 = Some("10.78.0.101".into());
        store.save_paired(&device).unwrap();
        let text = std::fs::read_to_string(directory.path().join("0000000000000001.toml")).unwrap();
        assert!(text.contains("mac = \"20:6e:f1:13:b1:70\""), "{text}");
        assert!(text.contains(&format!("public_key = \"{}\"", "02".repeat(33))), "{text}");
        assert!(text.contains("trust = \"paired\""));
        let loaded = store.load("fc00::1").unwrap().unwrap();
        assert_eq!((loaded.mac, loaded.public_key.clone()), (device.mac, device.public_key.clone()));
        assert_eq!(loaded.wake_bearers, device.wake_bearers);
        assert!(loaded.sleepy);
        for name in ["light1", "LIGHT1", "light1.mesh.example.com", "fc00::1"] {
            assert!(store.find(name).unwrap().is_some(), "{name}");
        }
    }

    #[test]
    fn a_legacy_json_record_is_read_and_replaced_by_toml_on_the_next_write() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        let store = DeviceStore::new(directory.path());
        let legacy = directory.path().join("0000000000000001.json");
        std::fs::write(
            &legacy,
            r#"{"device_id":"d1","name":"light1","mac":[1,2,3,4,5,6],"public_key":[2,2],"vip6":"fc00::1","secret":[7,7]}"#,
        )
        .unwrap();
        std::fs::set_permissions(&legacy, std::fs::Permissions::from_mode(0o600)).unwrap();
        let loaded = store.load("fc00::1").unwrap().unwrap();
        assert_eq!((loaded.mac, loaded.secret.len()), (Some([1, 2, 3, 4, 5, 6]), 2));
        assert_eq!(store.list().unwrap().len(), 1);
        let mut observed = loaded.clone();
        observed.ipv4 = Some("10.0.0.9".into());
        assert!(store.observe(&observed).unwrap());
        assert!(!legacy.exists());
        assert!(directory.path().join("0000000000000001.toml").exists());
        assert_eq!(store.list().unwrap().len(), 1);
    }

    #[test]
    fn observing_never_replaces_the_secret_or_lowers_trust_and_writes_only_on_change() {
        let directory = tempfile::tempdir().unwrap();
        let store = DeviceStore::new(directory.path());
        store.save_paired(&paired()).unwrap();
        let mut seen = DeviceRecord {
            device_id: "d1".into(),
            vip6: Some("fc00::1".into()),
            device_type: Some("esp32c6".into()),
            secret: vec![9; 32],
            root_public_key: vec![9; 33],
            trust: Some(trust::FIRST_SEEN.into()),
            ..Default::default()
        };
        assert!(store.observe(&seen).unwrap());
        let record = store.load("fc00::1").unwrap().unwrap();
        assert_eq!(record.secret, vec![7; 32]);
        assert_eq!(record.root_public_key, vec![3; 33]);
        assert_eq!(record.trust.as_deref(), Some("paired"));
        assert_eq!(record.device_type.as_deref(), Some("esp32c6"));
        // An older record with a secret and no trust is upgraded to paired.
        let mut legacy = record.clone();
        legacy.trust = None;
        assert!(legacy.merge_observed(&DeviceRecord::default()));
        assert_eq!(legacy.trust.as_deref(), Some("paired"));
        // The same observation again changes nothing.
        assert!(!store.observe(&seen).unwrap());
        // An unknown device becomes a first-seen record with no secret.
        seen.vip6 = Some("fc00::2".into());
        assert!(store.observe(&seen).unwrap());
        let created = store.load("fc00::2").unwrap().unwrap();
        assert!(created.secret.is_empty() && created.root_public_key.is_empty());
        assert_eq!(created.trust.as_deref(), Some("first-seen"));
    }

    #[test]
    fn a_declared_device_with_only_a_mac_becomes_the_discovered_device_and_keeps_its_declared_facts() {
        let directory = tempfile::tempdir().unwrap();
        let store = DeviceStore::new(directory.path());
        store
            .put(&DeviceRecord {
                name: Some("lora3".into()),
                mac: Some([1, 2, 3, 4, 5, 6]),
                ipv4: Some("10.78.0.113".into()),
                sleepy: true,
                ..Default::default()
            })
            .unwrap();
        assert!(directory.path().join("mac-010203040506.toml").exists());
        let seen = DeviceRecord {
            device_id: "d3".into(),
            name: Some("lora3".into()),
            mac: Some([1, 2, 3, 4, 5, 6]),
            vip6: Some("fc00::3".into()),
            public_key: vec![2; 33],
            device_type: Some("esp32".into()),
            ..Default::default()
        };
        assert!(store.observe(&seen).unwrap());
        assert!(!directory.path().join("mac-010203040506.toml").exists());
        let record = store.load("fc00::3").unwrap().unwrap();
        assert_eq!(record.ipv4.as_deref(), Some("10.78.0.113"));
        assert!(record.sleepy);
        assert_eq!(record.device_type.as_deref(), Some("esp32"));
        assert_eq!(store.list().unwrap().len(), 1);
    }

    #[test]
    fn a_read_only_directory_after_the_first_is_searched_and_never_written() {
        let (writable, fixtures) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        DeviceStore::new(fixtures.path())
            .put(&DeviceRecord {
                device_id: "d4".into(),
                name: Some("fixture".into()),
                vip6: Some("fc00::4".into()),
                ..Default::default()
            })
            .unwrap();
        let store = DeviceStore::with_directories(vec![writable.path().into(), fixtures.path().into()]);
        assert!(store.find("fixture").unwrap().is_some());
        let observed = DeviceRecord {
            device_id: "d4".into(),
            vip6: Some("fc00::4".into()),
            device_type: Some("esp32".into()),
            ..Default::default()
        };
        assert!(store.observe(&observed).unwrap());
        // The merged record is written to the first directory; the fixture is untouched.
        assert!(writable.path().join("0000000000000004.toml").exists());
        assert!(!std::fs::read_to_string(fixtures.path().join("0000000000000004.toml")).unwrap().contains("esp32"));
    }
}
