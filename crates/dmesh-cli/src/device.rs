//! Shared host inventory resolved from the common E2E/device catalog.
//!
//! This module contains names and stable bearer addresses only. It does not
//! create a transport connection, open a serial adapter, or read credentials.
//! `dmesh-cli`, the flasher, and E2E can therefore make identical target
//! choices without recreating a per-tool forwarding inventory.

use crate::prober::{DEFAULT_DEVICE_CATALOG, E2eConfig, E2eDeviceConfig};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::{Path, PathBuf},
};

/// Optional override for the one shared inventory location.
pub const DEVICE_CATALOG_ENV: &str = "DMESH_DEVICE_CATALOG";
pub const DEFAULT_UDP_PORT: u16 = 3337;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceProfile {
    /// Optional redundant guard against placing the wrong file in a directory.
    pub name: Option<String>,
    /// Static STA address, preferred for the current host UDP bearer.
    pub static_ipv4: Option<Ipv4Addr>,
    /// Stable signed overlay identity. This is an identity selector, not a
    /// directly routable LAN endpoint.
    pub vip6: Option<Ipv6Addr>,
    /// Inventory only for now. A link-local route also requires an interface
    /// scope, which belongs to the caller's bearer configuration.
    pub ipv6_link_local: Option<Ipv6Addr>,
    /// Local interface name used to scope `ipv6_link_local`.
    pub udp6_iface: Option<String>,
    /// Catalogued base/STA radio identity for discovery/NAN activation.
    pub mac: Option<[u8; 6]>,
    /// `/dev/serial/by-id` basename or an explicit absolute serial path.
    pub serial_id: Option<String>,
    /// Physical speed for a real UART bridge.  Packetized USB/JTAG endpoints
    /// leave this unset; callers must carry the profile value through to the
    /// common serial framing adapter instead of treating every named device as
    /// USB-JTAG.
    pub uart_baud: Option<u32>,
    /// Reserved for the future end-to-end authentication layer. This is a
    /// reference/name, never secret bytes read or logged by this module.
    pub auth_secret_ref: Option<String>,
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
            .map_err(|error| format!("invalid serial_glob {id:?}: {error}"))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| format!("expand serial_glob {id:?}: {error}"))?;
        match matches.as_slice() {
            [single] => Ok(Some(single.clone())),
            [] => Err(format!("serial_glob {id:?} matched no device")),
            _ => Err(format!(
                "serial_glob {id:?} matched multiple devices: {matches:?}"
            )),
        }
    }
}

pub fn device_catalog_path() -> PathBuf {
    std::env::var_os(DEVICE_CATALOG_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_DEVICE_CATALOG))
}

/// Load a named device from the shared E2E/device catalog. The parser never
/// reads or exposes the catalog's secret fields.
pub fn load_device(name: &str) -> Result<DeviceProfile, String> {
    if name.is_empty() || name.contains('/') || name == "." || name == ".." {
        return Err(format!("invalid device name {name:?}"));
    }
    let path = device_catalog_path();
    let catalog = E2eConfig::from_path(&path)?;
    let device = catalog.require_device(name)?;
    profile_from_device(device)
}

/// Resolve either a VIP6 identity or an exact catalog device name. Other
/// address literals deliberately remain explicit bearer targets.
pub fn resolve_catalog_target(target: &str) -> Result<Option<DeviceProfile>, String> {
    let path = device_catalog_path();
    let catalog = E2eConfig::from_path(&path)?;
    if let Ok(vip6) = target.parse::<Ipv6Addr>() {
        if vip6.octets()[0] != 0xfc {
            return Ok(None);
        }
        let device = catalog
            .devices
            .iter()
            .find(|device| {
                device
                    .vip6
                    .as_deref()
                    .and_then(|value| value.parse::<Ipv6Addr>().ok())
                    == Some(vip6)
            })
            .ok_or_else(|| {
                format!(
                    "VIP6 target {vip6} is not in device catalog {}",
                    path.display()
                )
            })?;
        return profile_from_device(device).map(Some);
    }
    if target.is_empty() || target.contains('/') || target.contains(':') {
        return Ok(None);
    }
    catalog
        .devices
        .iter()
        .find(|device| device.name.eq_ignore_ascii_case(target) && device.vip6.is_some())
        .map(profile_from_device)
        .transpose()
}

fn profile_from_device(device: &E2eDeviceConfig) -> Result<DeviceProfile, String> {
    let name = &device.name;
    let static_ipv4 = device
        .ipv4
        .as_deref()
        .map(str::parse)
        .transpose()
        .map_err(|error| format!("catalog device {name:?} has invalid ipv4: {error}"))?;
    let ipv6_link_local = device
        .ipv6_link_local
        .as_deref()
        .map(str::parse)
        .transpose()
        .map_err(|error| format!("catalog device {name:?} has invalid ipv6_link_local: {error}"))?;
    let vip6 = device
        .vip6
        .as_deref()
        .map(str::parse)
        .transpose()
        .map_err(|error| format!("catalog device {name:?} has invalid vip6: {error}"))?;
    let mac = device
        .mac
        .as_deref()
        .map(parse_mac)
        .transpose()
        .map_err(|error| format!("catalog device {name:?} has invalid mac: {error}"))?;
    Ok(DeviceProfile {
        name: Some(device.name.clone()),
        static_ipv4,
        vip6,
        ipv6_link_local,
        udp6_iface: device.udp6_iface.clone(),
        mac,
        serial_id: device.serial.clone().or_else(|| device.serial_glob.clone()),
        uart_baud: device.uart_baud,
        auth_secret_ref: device.auth_secret_ref.clone(),
        udp_port: device.udp_port,
    })
}

fn parse_mac(value: &str) -> Result<[u8; 6], String> {
    let mut mac = [0; 6];
    let mut fields = value.split(':');
    for byte in &mut mac {
        *byte = u8::from_str_radix(fields.next().ok_or("MAC has fewer than six octets")?, 16)
            .map_err(|error| error.to_string())?;
    }
    if fields.next().is_some() {
        return Err("MAC has more than six octets".into());
    }
    Ok(mac)
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
    use super::{
        DEFAULT_UDP_PORT, DeviceProfile, device_catalog_path, load_device, resolve_catalog_target,
        resolve_udp_peer,
    };
    use crate::prober::DEFAULT_DEVICE_CATALOG;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn profile_prefers_static_ip_and_expands_serial_id() {
        let profile = DeviceProfile {
            name: Some("e6".into()),
            static_ipv4: Some("192.0.2.6".parse::<Ipv4Addr>().unwrap()),
            vip6: Some("fc00::6".parse::<Ipv6Addr>().unwrap()),
            ipv6_link_local: Some("fe80::6".parse::<Ipv6Addr>().unwrap()),
            udp6_iface: Some("wlan0".into()),
            mac: Some([0, 1, 2, 3, 4, 5]),
            serial_id: Some("usb-e6".into()),
            uart_baud: None,
            auth_secret_ref: Some("reserved".into()),
            udp_port: DEFAULT_UDP_PORT,
        };
        assert_eq!(profile.udp_peer().unwrap().to_string(), "192.0.2.6:3337");
        assert_eq!(
            profile.serial_path().unwrap().unwrap().to_string_lossy(),
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

    #[test]
    fn default_catalog_is_a_tracked_source_fixture() {
        assert!(DEFAULT_DEVICE_CATALOG.ends_with("examples/device-catalog.toml"));
        if std::env::var_os("DMESH_DEVICE_CATALOG").is_none() {
            assert_eq!(
                device_catalog_path().to_string_lossy(),
                DEFAULT_DEVICE_CATALOG
            );
        }
    }

    #[test]
    fn default_catalog_keeps_current_c6_role_selection() {
        if std::env::var_os("DMESH_DEVICE_CATALOG").is_none() {
            let profile = load_device("e8").unwrap();
            assert!(
                profile
                    .serial_id
                    .as_deref()
                    .is_some_and(|serial| serial.contains("10:BD:A3:AC:5A:20"))
            );
            assert_eq!(profile.static_ipv4, Some("10.78.0.103".parse().unwrap()));
            assert_eq!(
                profile.vip6,
                Some("fc00::918b:ab88:305f:78ad".parse().unwrap())
            );
        }
    }

    #[test]
    fn catalog_target_resolves_vip6_and_name_to_the_same_device() {
        if std::env::var_os("DMESH_DEVICE_CATALOG").is_none() {
            let by_name = resolve_catalog_target("e8").unwrap().unwrap();
            let by_vip6 = resolve_catalog_target("fc00::918b:ab88:305f:78ad")
                .unwrap()
                .unwrap();
            assert_eq!(by_name, by_vip6);
            assert!(resolve_catalog_target("2001:db8::8").unwrap().is_none());
        }
    }
}
