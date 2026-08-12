//! Shared host Wi-Fi ownership and netd policy.
//!
//! The full `lmesh` service and the Wi-Fi-only `lmesh-wifi` service use this
//! crate. Linux Wi-Fi, host NAN transport, discovery, and AP/STA operations
//! live here; UART forwarding is provided by the separate `lmesh-uart` crate.

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

mod radio;
mod schema;

pub use radio::RadioService;

pub(crate) fn public_key_sha(public_key: &str) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(public_key.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct InterfaceSet(Vec<String>);

impl InterfaceSet {
    /// Read the ownership allow-list from `LMESH_INTERFACES`.
    pub fn from_environment() -> Self {
        Self::parse(&std::env::var("LMESH_INTERFACES").unwrap_or_default())
    }

    /// Parse, normalize, and deduplicate a comma-separated ownership list.
    pub fn parse(value: &str) -> Self {
        let mut interfaces = value
            .split(',')
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .map(str::to_owned)
            .collect::<Vec<_>>();
        interfaces.sort();
        interfaces.dedup();
        Self(interfaces)
    }

    /// Return whether this service owns `iface`.
    pub fn contains(&self, iface: &str) -> bool {
        self.0.iter().any(|owned| owned == iface)
    }

    /// Return the normalized interface names in stable order.
    pub fn names(&self) -> &[String] {
        &self.0
    }

    /// Reject an operation on an interface owned by another service.
    pub fn require(&self, iface: &str) -> Result<()> {
        if self.contains(iface) {
            Ok(())
        } else if self.0.is_empty() {
            bail!("Wi-Fi interface {iface:?} is not owned; LMESH_INTERFACES is empty")
        } else {
            bail!("Wi-Fi interface {iface:?} is not owned by this service")
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Operation {
    Ap,
    Sta,
    Nan,
}

#[derive(Clone, Debug)]
pub struct WifiNetd {
    owned: InterfaceSet,
}

impl WifiNetd {
    /// Construct ownership policy from the process environment.
    pub fn from_environment() -> Self {
        Self {
            owned: InterfaceSet::from_environment(),
        }
    }

    /// Construct ownership policy explicitly, which is useful for tests.
    pub fn new(owned: InterfaceSet) -> Self {
        Self { owned }
    }

    /// Return the interfaces this service may operate.
    pub fn owned_interfaces(&self) -> &InterfaceSet {
        &self.owned
    }

    /// Authorize one operation without allowing cross-service interface use.
    pub fn authorize(&self, _operation: Operation, iface: &str) -> Result<()> {
        self.owned.require(iface)
    }
}

/// Select the first normalized interface owned by the current service.
pub fn default_interface() -> Option<String> {
    InterfaceSet::from_environment().names().first().cloned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_deduplicates_interfaces() {
        assert_eq!(
            InterfaceSet::parse(" wlan1,wlan0,wlan1, ").names(),
            &["wlan0", "wlan1"]
        );
    }

    #[test]
    fn empty_set_denies_operations() {
        assert!(InterfaceSet::default().require("wlan0").is_err());
    }

    #[test]
    fn owned_interface_is_authorized() {
        let netd = WifiNetd::new(InterfaceSet::parse("wlan0"));
        assert!(netd.authorize(Operation::Ap, "wlan0").is_ok());
        assert!(netd.authorize(Operation::Nan, "wlan1").is_err());
    }
}
