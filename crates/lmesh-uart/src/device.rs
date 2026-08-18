//! Shared host inventory for one device per directory.
//!
//! This module contains names and stable bearer addresses only. It does not
//! create a transport connection, open a serial adapter, or read credentials.
//! `lmesh-uart`, `lmesh-wifi`, and `lmesh` can therefore make identical target
//! choices without recreating the retired forwarding configuration.

use serde::Deserialize;
use std::{
    fs,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::{Path, PathBuf},
};

/// The default shared inventory. Tests and isolated deployments may override
/// it with `LMESH_DEVICE_DIR`; production intentionally converges on the
/// common lmesh home rather than a per-daemon forwarding file.
pub const DEFAULT_DEVICE_DIRECTORY: &str = "/home/lmesh/etc/lmesh/devices";
pub const DEFAULT_UDP_PORT: u16 = 3337;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct DeviceProfile {
    /// Optional redundant guard against placing the wrong file in a directory.
    #[serde(default)]
    pub name: Option<String>,
    /// Static STA address, preferred for the current host UDP bearer.
    #[serde(default)]
    pub static_ipv4: Option<Ipv4Addr>,
    /// Inventory only for now. A link-local route also requires an interface
    /// scope, which belongs to the caller's bearer configuration.
    #[serde(default)]
    pub ipv6_link_local: Option<Ipv6Addr>,
    /// `/dev/serial/by-id` basename or an explicit absolute serial path.
    #[serde(default)]
    pub serial_id: Option<String>,
    /// Reserved for the future end-to-end authentication layer. This is a
    /// reference/name, never secret bytes read or logged by this module.
    #[serde(default)]
    pub auth_secret_ref: Option<String>,
    #[serde(default = "default_udp_port")]
    pub udp_port: u16,
}

fn default_udp_port() -> u16 {
    DEFAULT_UDP_PORT
}

impl DeviceProfile {
    pub fn udp_peer(&self) -> Option<SocketAddr> {
        self.static_ipv4
            .map(|ip| SocketAddr::new(IpAddr::V4(ip), self.udp_port))
    }

    pub fn serial_path(&self) -> Option<PathBuf> {
        self.serial_id.as_deref().map(|id| {
            let path = Path::new(id);
            if path.is_absolute() {
                path.to_owned()
            } else {
                Path::new("/dev/serial/by-id").join(path)
            }
        })
    }
}

pub fn device_directory() -> PathBuf {
    std::env::var_os("LMESH_DEVICE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_DEVICE_DIRECTORY))
}

/// Load `/home/lmesh/etc/lmesh/devices/<name>/device.toml`. Device names are
/// path components, not arbitrary paths.
pub fn load_device(name: &str) -> Result<DeviceProfile, String> {
    if name.is_empty() || name.contains('/') || name == "." || name == ".." {
        return Err(format!("invalid device name {name:?}"));
    }
    let path = device_directory().join(name).join("device.toml");
    let contents =
        fs::read_to_string(&path).map_err(|error| format!("read {}: {error}", path.display()))?;
    let profile: DeviceProfile =
        toml::from_str(&contents).map_err(|error| format!("parse {}: {error}", path.display()))?;
    if let Some(declared) = &profile.name
        && declared != name
    {
        return Err(format!(
            "device profile {} declares name {declared:?}",
            path.display()
        ));
    }
    Ok(profile)
}

/// Resolve an explicit `udp://IP:PORT`, `IP[:PORT]`, or an inventory name to
/// the current UDP bearer. A profile with only serial/link-local information
/// remains valid inventory but cannot be silently treated as a UDP target.
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
        .ok_or_else(|| format!("device {target:?} has no static_ipv4 UDP target"))
        .map(Some)
}

#[cfg(test)]
mod tests {
    use super::{DEFAULT_UDP_PORT, DeviceProfile, resolve_udp_peer};
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn profile_prefers_static_ip_and_expands_serial_id() {
        let profile = DeviceProfile {
            name: Some("e6".into()),
            static_ipv4: Some("192.0.2.6".parse::<Ipv4Addr>().unwrap()),
            ipv6_link_local: Some("fe80::6".parse::<Ipv6Addr>().unwrap()),
            serial_id: Some("usb-e6".into()),
            auth_secret_ref: Some("reserved".into()),
            udp_port: DEFAULT_UDP_PORT,
        };
        assert_eq!(profile.udp_peer().unwrap().to_string(), "192.0.2.6:3337");
        assert_eq!(
            profile.serial_path().unwrap().to_string_lossy(),
            "/dev/serial/by-id/usb-e6"
        );
    }

    #[test]
    fn explicit_ipv4_is_a_default_port_udp_target() {
        assert_eq!(
            resolve_udp_peer("192.0.2.9").unwrap().unwrap().to_string(),
            "192.0.2.9:3337"
        );
        assert!(resolve_udp_peer("fe80::9").is_err());
    }
}
