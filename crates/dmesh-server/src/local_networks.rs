//! Bounded CBOR snapshot of local interfaces, addresses, and reachability.

extern crate alloc;

use crate::cbor::Decoder;
use alloc::{
    string::{String, ToString},
    vec::Vec,
};

pub const MAX_NETWORKS: usize = 32;
pub const MAX_VALUES: usize = 32;
pub const MAX_TEXT: usize = 256;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LocalNetwork {
    pub interface: String,
    pub up: bool,
    pub multicast: bool,
    pub active: bool,
    pub internet: bool,
    pub validated: bool,
    pub metered: bool,
    pub addresses: Vec<String>,
    pub dns_servers: Vec<String>,
    pub gateways: Vec<String>,
    pub transports: Vec<String>,
    /// Optional Wi-Fi SSID. It is routing metadata reported by an adapter;
    /// callers must not use it as peer identity or authorization.
    pub ssid: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LocalNetworks {
    pub networks: Vec<LocalNetwork>,
}

/// Replace-only view of platform-observed networks.  Android, Linux, and
/// test adapters submit the same bounded snapshot; none owns a parallel
/// platform-specific network schema.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LocalNetworkTable {
    pub networks: alloc::collections::BTreeMap<String, LocalNetwork>,
}

impl LocalNetworkTable {
    pub fn replace(&mut self, snapshot: LocalNetworks) -> Option<()> {
        let mut replacement = alloc::collections::BTreeMap::new();
        for network in snapshot.networks {
            if replacement.insert(network.interface.clone(), network).is_some() {
                return None;
            }
        }
        self.networks = replacement;
        Some(())
    }
}

#[cfg(feature = "std")]
pub fn json_network(network: &LocalNetwork) -> serde_json::Value {
    serde_json::json!({
        "interface": network.interface,
        "up": network.up,
        "multicast": network.multicast,
        "active": network.active,
        "internet": network.internet,
        "validated": network.validated,
        "metered": network.metered,
        "addresses": network.addresses,
        "dns_servers": network.dns_servers,
        "gateways": network.gateways,
        "transports": network.transports,
        "ssid": network.ssid,
    })
}

fn text(d: &mut Decoder<'_>) -> Option<String> {
    let value = d.text_ref()?;
    if value.len() > MAX_TEXT {
        return None;
    }
    core::str::from_utf8(value).ok().map(ToString::to_string)
}

fn texts(d: &mut Decoder<'_>) -> Option<Vec<String>> {
    let (major, count) = d.head()?;
    if major != 4 || count as usize > MAX_VALUES {
        return None;
    }
    (0..count).map(|_| text(d)).collect()
}

fn field(d: &mut Decoder<'_>, row: &mut LocalNetwork, key: &str) -> Option<()> {
    match key {
        "interface" => row.interface = text(d)?,
        "up" => row.up = d.boolean()?,
        "multicast" => row.multicast = d.boolean()?,
        "active" => row.active = d.boolean()?,
        "internet" => row.internet = d.boolean()?,
        "validated" => row.validated = d.boolean()?,
        "metered" => row.metered = d.boolean()?,
        "addresses" => row.addresses = texts(d)?,
        "dns_servers" => row.dns_servers = texts(d)?,
        "gateways" => row.gateways = texts(d)?,
        "transports" => row.transports = texts(d)?,
        "ssid" => row.ssid = Some(text(d)?),
        _ => d.skip()?,
    }
    Some(())
}

fn network(d: &mut Decoder<'_>) -> Option<LocalNetwork> {
    let (major, count) = d.head()?;
    if major != 5 || count == u64::MAX {
        return None;
    }
    let mut row = LocalNetwork::default();
    for _ in 0..count {
        let key = core::str::from_utf8(d.text_ref()?).ok()?.to_string();
        field(d, &mut row, &key)?;
    }
    (!row.interface.is_empty() && row.interface.len() <= MAX_TEXT).then_some(row)
}

/// Decode the shared definite-length CBOR snapshot. Unknown fields are
/// skipped, so compatible adapters can add observations without a Java-only
/// schema fork.
pub fn decode_snapshot(input: &[u8]) -> Option<LocalNetworks> {
    let mut d = Decoder::new(input);
    let (major, count) = d.head()?;
    if major != 5 || count == u64::MAX {
        return None;
    }
    let mut result = LocalNetworks::default();
    for _ in 0..count {
        let key = core::str::from_utf8(d.text_ref()?).ok()?;
        if key != "networks" {
            d.skip()?;
            continue;
        }
        let (array, rows) = d.head()?;
        if array != 4 || rows as usize > MAX_NETWORKS {
            return None;
        }
        for _ in 0..rows {
            result.networks.push(network(&mut d)?);
        }
    }
    d.is_finished().then_some(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cbor::Encoder;

    #[test]
    fn decodes_bounded_snapshot() {
        let mut wire = [0u8; 256];
        let mut e = Encoder::new(&mut wire);
        e.map(1).unwrap();
        e.text_value(b"networks").unwrap();
        e.array(1).unwrap();
        e.map(11).unwrap();
        for (key, value) in [(b"interface".as_slice(), b"wlan0".as_slice())] {
            e.text_value(key).unwrap();
            e.text_value(value).unwrap();
        }
        for key in [
            b"up".as_slice(),
            b"multicast",
            b"active",
            b"internet",
            b"validated",
            b"metered",
        ] {
            e.text_value(key).unwrap();
            e.boolean(true).unwrap();
        }
        for key in [
            b"addresses".as_slice(),
            b"dns_servers",
            b"gateways",
            b"transports",
        ] {
            e.text_value(key).unwrap();
            e.array(0).unwrap();
        }
        let used = e.len();
        drop(e);
        let snapshot = decode_snapshot(&wire[..used]).unwrap();
        assert_eq!(snapshot.networks[0].interface, "wlan0");
        assert!(snapshot.networks[0].validated);
    }

    #[test]
    fn replacement_table_rejects_duplicate_interfaces() {
        let mut table = LocalNetworkTable::default();
        assert!(table
            .replace(LocalNetworks {
                networks: vec![LocalNetwork {
                    interface: "wlan0".into(),
                    ..LocalNetwork::default()
                }],
            })
            .is_some());
        assert!(table
            .replace(LocalNetworks {
                networks: vec![
                    LocalNetwork {
                        interface: "wlan0".into(),
                        ..LocalNetwork::default()
                    },
                    LocalNetwork {
                        interface: "wlan0".into(),
                        ..LocalNetwork::default()
                    },
                ],
            })
            .is_none());
    }
}
