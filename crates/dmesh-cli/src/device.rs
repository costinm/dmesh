//! The CLI's view of the device records (`dmesh_server::device_record`): the same files lmesh and
//! Android write when they pair or discover a device. Reading, merging and writing them is
//! `DeviceStore`; this file only turns a record into what the CLI connects to.

use dmesh_server::device_record::{DeviceRecord, DeviceStore};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::{Path, PathBuf},
};

/// Tracked lab fixture, read after the operator's own records.
pub const DEFAULT_NODES_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/examples/nodes");
pub const DEFAULT_UDP_PORT: u16 = 3339;

/// The CLI's device records: `DMESH_NODES_DIR` / `DMESH_PAIRED_DEVICES_DIR` when set, else the
/// user's `~/.config/dmesh/nodes` followed by the tracked fixture. The first directory is written.
pub fn store() -> DeviceStore {
    if std::env::var_os(DeviceStore::NODES_ENV).is_some()
        || std::env::var_os(DeviceStore::PAIRED_ENV).is_some()
    {
        return DeviceStore::from_env(None);
    }
    DeviceStore::from_env(None).also_read(DEFAULT_NODES_DIR)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceProfile {
    /// Explicit caller policy; missing discovery is not proof of sleep.
    pub sleepy: bool,
    /// Optional redundant guard against placing the wrong file in a directory.
    pub name: Option<String>,
    /// Static STA address, preferred for the current host UDP bearer.
    pub static_ipv4: Option<Ipv4Addr>,
    /// Stable signed overlay identity. This is an identity selector, not a
    /// directly routable LAN endpoint.
    pub vip6: Option<Ipv6Addr>,
    /// A link-local base address hint. A route also requires an interface
    /// scope, which belongs to the caller's bearer configuration.
    pub ipv6_link_local: Option<Ipv6Addr>,
    /// Local interface name used to scope `ipv6_link_local`.
    pub udp6_iface: Option<String>,
    /// Base/STA radio identity for discovery/NAN activation.
    pub mac: Option<[u8; 6]>,
    /// `/dev/serial/by-id` basename or an explicit absolute serial path.
    pub serial_id: Option<String>,
    /// Physical speed for a real UART bridge. Packetized USB/JTAG endpoints
    /// leave this unset; callers must carry the profile value through to the
    /// common serial framing adapter instead of treating every named device as
    /// USB-JTAG.
    pub uart_baud: Option<u32>,
    pub udp_port: u16,
}

impl DeviceProfile {
    pub fn udp_peer(&self) -> Option<SocketAddr> {
        self.static_ipv4
            .map(|ip| SocketAddr::new(IpAddr::V4(ip), self.udp_port))
    }

    pub fn serial_path(&self) -> Result<Option<PathBuf>, String> {
        let Some(id) = self.serial_id.as_deref() else {
            return Ok(None);
        };
        let path = Path::new(id);
        let candidate = if path.is_absolute() {
            path.to_owned()
        } else {
            Path::new("/dev/serial/by-id").join(path)
        };
        if !id.contains('*') && !id.contains('?') && !id.contains('[') {
            return Ok(Some(candidate));
        }
        let pattern = candidate.to_string_lossy();
        let matches = glob::glob(&pattern)
            .map_err(|error| format!("invalid serial glob {id:?}: {error}"))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| format!("expand serial glob {id:?}: {error}"))?;
        match matches.as_slice() {
            [single] => Ok(Some(single.clone())),
            [] => Err(format!("serial glob {id:?} matched no device")),
            _ => Err(format!(
                "serial glob {id:?} matched multiple devices: {matches:?}"
            )),
        }
    }
}

/// Load a node record by name (or FQDN `NAME.DOMAIN`).
pub fn load_device(name: &str) -> Result<DeviceProfile, String> {
    if name.is_empty() || name.contains('/') || name == "." || name == ".." {
        return Err(format!("invalid device name {name:?}"));
    }
    let store = store();
    let node = store.find(name)?.ok_or_else(|| {
        format!(
            "no device record named {name:?} in {}",
            store
                .directories()
                .iter()
                .map(|path| path.display().to_string())
                .collect::<Vec<_>>()
                .join(":")
        )
    })?;
    profile_from_node(&node)
}

/// Resolve either a VIP6 identity or a node name. Other address literals deliberately remain
/// explicit bearer targets.
pub fn resolve_catalog_target(target: &str) -> Result<Option<DeviceProfile>, String> {
    // Explicit bearer endpoints do not depend on an inventory. This also keeps the installed CLI
    // usable from a firmware package without a checkout-specific node directory.
    let vip6 = target.parse::<Ipv6Addr>().ok();
    if target.is_empty() || target.contains('/') || (target.contains(':') && vip6.is_none()) {
        return Ok(None);
    }
    if let Some(vip6) = vip6 {
        if vip6.octets()[0] != 0xfc {
            return Ok(None);
        }
        let node = store()
            .load(&vip6.to_string())?
            .ok_or_else(|| format!("VIP6 target {vip6} has no device record"))?;
        return profile_from_node(&node).map(Some);
    }
    store()
        .list()?
        .into_iter()
        .find(|node| node_is_target(node, target))
        .map(|node| profile_from_node(&node))
        .transpose()
}

fn node_is_target(node: &DeviceRecord, target: &str) -> bool {
    node.name.as_deref().is_some_and(|name| name.eq_ignore_ascii_case(target))
        && (node.vip6.is_some() || node.mac.is_some())
}

fn profile_from_node(node: &DeviceRecord) -> Result<DeviceProfile, String> {
    let name = node.name.clone().unwrap_or_else(|| node.device_id.clone());
    let static_ipv4 = node
        .ipv4
        .as_deref()
        .map(str::parse)
        .transpose()
        .map_err(|error| format!("node {name:?} has invalid ipv4: {error}"))?;
    let ipv6_link_local = node
        .home_address
        .as_deref()
        .and_then(|value| value.parse::<Ipv6Addr>().ok());
    let vip6 = node
        .vip6
        .as_deref()
        .map(str::parse)
        .transpose()
        .map_err(|error| format!("node {name:?} has invalid vip6: {error}"))?;
    Ok(DeviceProfile {
        sleepy: node.sleepy,
        name: node.name.clone(),
        static_ipv4,
        vip6,
        ipv6_link_local,
        udp6_iface: node.endpoints.get("udp6_iface").cloned(),
        mac: node.mac,
        serial_id: node.endpoints.get("uart").cloned(),
        uart_baud: node.uart_baud,
        udp_port: node.udp_port.unwrap_or(DEFAULT_UDP_PORT),
    })
}

/// Resolve an explicit `udp://IP:PORT`, `IP[:PORT]`, or a node name to the current UDP bearer. A
/// node with only serial/link-local information remains valid but cannot be silently treated as a
/// UDP target.
pub fn resolve_udp_peer(target: &str) -> Result<Option<SocketAddr>, String> {
    let raw = target.strip_prefix("udp://").unwrap_or(target);
    if let Ok(peer) = raw.parse::<SocketAddr>() {
        return Ok(Some(peer));
    }
    if let Ok(ip) = raw.parse::<IpAddr>() {
        if ip.is_ipv6() {
            return Err(
                "an IPv6 link-local target needs an interface scope; use a device profile".into(),
            );
        }
        return Ok(Some(SocketAddr::new(ip, DEFAULT_UDP_PORT)));
    }
    if target.starts_with('/') {
        return Ok(None);
    }
    let profile = load_device(target)?;
    profile
        .udp_peer()
        .ok_or_else(|| format!("device {target:?} has no static ipv4 UDP target"))
        .map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node() -> DeviceRecord {
        let mut node = DeviceRecord {
            device_id: "0000000000000006".into(),
            name: Some("e6".into()),
            vip6: Some("fc00::6".into()),
            ipv4: Some("192.0.2.6".into()),
            home_address: Some("fe80::6".into()),
            mac: Some([0, 1, 2, 3, 4, 5]),
            ..Default::default()
        };
        node.endpoints.insert("uart".into(), "usb-e6".into());
        node.endpoints.insert("udp6_iface".into(), "wlan0".into());
        node
    }

    #[test]
    fn profile_prefers_static_ip_and_expands_serial_id() {
        let profile = profile_from_node(&node()).unwrap();
        assert_eq!(profile.udp_peer().unwrap().to_string(), "192.0.2.6:3339");
        assert_eq!(
            profile.serial_path().unwrap().unwrap().to_string_lossy(),
            "/dev/serial/by-id/usb-e6"
        );
        assert_eq!(profile.udp6_iface.as_deref(), Some("wlan0"));
        assert_eq!(profile.ipv6_link_local, Some("fe80::6".parse().unwrap()));
    }

    #[test]
    fn explicit_ipv4_is_a_default_port_udp_target() {
        assert_eq!(
            resolve_udp_peer("192.0.2.9").unwrap().unwrap().to_string(),
            "192.0.2.9:3339"
        );
        assert!(resolve_udp_peer("fe80::9").is_err());
    }

    #[test]
    fn a_record_resolves_by_name_fqdn_and_vip6_through_the_store() {
        let directory = tempfile::tempdir().unwrap();
        let store = DeviceStore::new(directory.path());
        let mut record = node();
        record.domain = Some("lab.example".into());
        record.sleepy = true;
        store.put(&record).unwrap();
        for target in ["e6", "e6.lab.example", "fc00::6"] {
            let found = store.find(target).unwrap().unwrap();
            let profile = profile_from_node(&found).unwrap();
            assert!(profile.sleepy, "{target}");
            assert_eq!(profile.vip6, Some("fc00::6".parse().unwrap()));
        }
    }

    #[test]
    fn a_node_is_a_target_by_name_when_it_has_an_identity_or_a_mac() {
        assert!(node_is_target(&node(), "E6"));
        let mut anonymous = node();
        anonymous.vip6 = None;
        anonymous.mac = None;
        assert!(!node_is_target(&anonymous, "e6"));
    }
}
