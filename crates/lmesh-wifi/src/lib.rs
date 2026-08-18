//! Shared host Wi-Fi ownership and netd policy.
//!
//! The full `lmesh` service and the Wi-Fi-only `lmesh-wifi` service use this
//! crate. Linux Wi-Fi, host NAN transport, discovery, and AP/STA operations
//! live here; UART forwarding is provided by the separate `lmesh-uart` crate.

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

pub mod dispatch;
mod ndp;
mod radio;
/// Host-side JSON/compatibility conversion for raw NAN and legacy BLE commands.
/// The byte/state core remains in `dmesh-rawnan`.
pub mod radio_protocol;
mod schema;

pub use radio::RadioService;

/// Reusable Wi-Fi service instance.
///
/// The standalone `lmesh-wifi` binary and the experimental `lmesh` binary use
/// this same library object.  Keeping ownership and radio state together is
/// important: two processes can own different interfaces without sharing
/// mutable global state or a control socket.
#[derive(Clone)]
pub struct WifiService {
    netd: WifiNetd,
    radio: RadioService,
}

impl WifiService {
    pub fn new(netd: WifiNetd, radio: RadioService) -> Self {
        Self { netd, radio }
    }

    pub fn from_environment() -> Self {
        Self::new(
            WifiNetd::from_environment(),
            RadioService::from_environment_without_uart(),
        )
    }

    pub fn netd(&self) -> &WifiNetd {
        &self.netd
    }

    pub fn radio(&self) -> &RadioService {
        &self.radio
    }

    /// Apply the common startup policy used by the stable service.  The
    /// canary service can call the individual operations instead, allowing it
    /// to restart without changing the stable AP policy.
    pub fn start_stable(&self) -> Vec<serde_json::Value> {
        let mut results = self
            .radio
            .apply_startup_rate_profile(self.netd.owned_interfaces().names());
        if let Some(iface) = self.netd.owned_interfaces().names().first().cloned() {
            if self.netd.authorize(Operation::Ap, &iface).is_ok() {
                let channel = std::env::var("LMESH_AP_CHANNEL")
                    .ok()
                    .and_then(|value| value.parse::<u8>().ok());
                results.push(self.radio.wifi_ap_start_open_on_channel(
                    Some(iface.clone()),
                    None,
                    channel,
                ));
                let cidr =
                    std::env::var("LMESH_AP_ADDRESS").unwrap_or_else(|_| "10.78.0.1/16".to_owned());
                if let Some((address, prefix)) = cidr.split_once('/') {
                    if let Ok(prefix) = prefix.parse::<u8>() {
                        results.push(self.radio.wifi_sta_configure_ipv4(
                            Some(iface.clone()),
                            address.to_owned(),
                            Some(prefix),
                        ));
                    }
                }
            }
        }
        results
    }

    pub fn start_canary_rawnan(&self, iface: Option<String>) -> serde_json::Value {
        let iface = iface.or_else(|| self.netd.owned_interfaces().names().first().cloned());
        let Some(iface) = iface else {
            return serde_json::json!({"ok": false, "error": "LMESH_INTERFACES is empty"});
        };
        if let Err(error) = self.netd.authorize(Operation::Nan, &iface) {
            return serde_json::json!({"ok": false, "iface": iface, "error": error.to_string()});
        }
        self.radio.wifi_raw_listen(
            Some(iface),
            Some(6),
            Some(86_400),
            Some("monitor".to_owned()),
        )
    }
}

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
