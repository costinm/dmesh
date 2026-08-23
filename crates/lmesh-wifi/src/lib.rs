//! Shared host Wi-Fi ownership and netd policy.
//!
//! The full `lmesh` service and the Wi-Fi-only `lmesh-wifi` service use this
//! crate. Linux Wi-Fi, host NAN transport, discovery, and AP/STA operations
//! live here; direct UART sessions are owned by `dmesh-cli`, not this service.

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[path = "api.rs"]
mod api_generated;
pub mod dispatch;
mod infra_credentials;
/// Generated API structs plus stable compatibility aliases used by the
/// reviewed service adapters. The generated artifact itself remains untouched.
pub mod api {
    pub use super::api_generated::*;
    pub type ApStatusRequest = WifiApStatusRequest;
    pub type StaStatusRequest = WifiStaStatusRequest;
    pub type RawNanStatusRequest = WifiRawnanStatusRequest;
    pub type ProbePlanRequest = WifiProbePlanRequest;
    pub type InterfaceStatusRequest = WifiInterfaceStatusRequest;
    pub type ApStationsRequest = WifiApStationsRequest;
    pub type RawMetricsRequest = WifiRawMetricsRequest;
    pub type RawStopRequest = WifiRawStopRequest;
    pub type RawListenRequest = WifiRawListenRequest;
    pub type RawCheckRequest = WifiRawCheckRequest;
    pub type RawIperfRequest = WifiRawIperfRequest;
    pub type RawSendRequest = WifiRawSendRequest;
    pub type RawNanPingRequest = WifiRawnanPingRequest;
    pub type RawNanListenRequest = WifiRawnanListenRequest;
}
mod ndp;
mod radio;
/// Host-side JSON/compatibility conversion for raw NAN and legacy BLE commands.
/// The byte/state core remains in `dmesh-rawnan`.
pub mod radio_protocol;
pub mod reviewed;

pub use radio::RadioService;
pub use infra_credentials::{
    INFRA_STA_CREDENTIALS_PATH, InfrastructureCredentials,
    load_default_infrastructure_credentials, load_infrastructure_credentials,
};

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

    /// Construct an independently supervised service with its own default
    /// change log. `LMESH_DISCOVERY_LOG` remains an explicit operator override
    /// when multiple services intentionally feed one durable inventory.
    pub fn from_environment_with_discovery_log(default_change_log: impl Into<PathBuf>) -> Self {
        Self::new(
            WifiNetd::from_environment(),
            RadioService::from_environment_with_discovery_log(default_change_log),
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
                let ht40 = std::env::var("LMESH_AP_HT40").ok().and_then(|value| {
                    match value.trim().to_ascii_lowercase().as_str() {
                        "1" | "true" | "yes" | "on" => Some(true),
                        "0" | "false" | "no" | "off" => Some(false),
                        _ => None,
                    }
                });
                let beacon_interval_tu = std::env::var("LMESH_AP_BEACON_INTERVAL_TU")
                    .ok()
                    .and_then(|value| value.parse::<u16>().ok())
                    .map(|value| value.clamp(10, 1000))
                    .unwrap_or(100);
                results.push(self.radio.wifi_ap_start_open_on_channel_with_interval(
                    Some(iface.clone()),
                    None,
                    channel,
                    ht40,
                    beacon_interval_tu,
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
                // NAN and NOW share one permanent active monitor.  The AP
                // remains the channel anchor; the monitor has broad receive
                // flags for foreign cluster beacons and also injects NOW.
                results.push(
                    self.radio
                        .prepare_ap_raw_monitor_fixture(Some(iface.clone()), channel),
                );
                // Listeners only consume the fixture; packet tests never
                // create, retune, or otherwise alter host radio state.
                results.push(self.radio.wifi_raw_listen(
                    Some(iface.clone()),
                    Some(6),
                    Some(86_400),
                    Some("monitor".to_owned()),
                ));
                // Some adapters only deliver foreign NAN beacons through an
                // nl80211 management registration while the monitor remains
                // active for NOW TX. Keep that receive lane permanent too.
                results.push(self.radio.wifi_nan_beacon_listen(Some(iface)));
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
        let monitor = self.radio.wifi_raw_listen(
            Some(iface),
            Some(6),
            Some(86_400),
            Some("monitor".to_owned()),
        );
        let beacon = self.radio.wifi_nan_beacon_listen(None);
        serde_json::json!({
            "ok": monitor.get("ok").and_then(serde_json::Value::as_bool).unwrap_or(false),
            "monitor": monitor,
            "beacon_listener": beacon,
        })
    }

    /// Prepare the long-lived AP-off raw monitor before attaching the
    /// canary receiver.  Only supervised startup calls this; E2E uses the
    /// existing fixture without reconfiguring it.
    pub fn prepare_canary_rawnan_monitor(
        &self,
        iface: Option<String>,
        channel: Option<u8>,
    ) -> serde_json::Value {
        let iface = iface.or_else(|| self.netd.owned_interfaces().names().first().cloned());
        let Some(iface) = iface else {
            return serde_json::json!({"ok": false, "error": "LMESH_INTERFACES is empty"});
        };
        if let Err(error) = self.netd.authorize(Operation::Nan, &iface) {
            return serde_json::json!({"ok": false, "iface": iface, "error": error.to_string()});
        }
        self.radio.prepare_raw_monitor_fixture(Some(iface), channel)
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
    ///
    /// A monitor interface is a child VIF of its base radio, not an
    /// independently-owned radio.  Permit the conventional `<base>mon` name
    /// only when the corresponding base interface is in this service's
    /// allow-list.  This keeps `wlan0mon` with `lmesh-wifi` while rejecting
    /// unrelated monitor VIFs such as `wlan1mon`.
    pub fn contains(&self, iface: &str) -> bool {
        self.0.iter().any(|owned| {
            owned == iface
                || iface.strip_suffix("mon").is_some_and(|base| base == owned)
        })
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

    #[test]
    fn monitor_child_is_authorized_with_its_owned_base() {
        let owned = InterfaceSet::parse("wlan0");
        assert!(owned.contains("wlan0mon"));
        assert!(!owned.contains("wlan1mon"));
        assert!(!owned.contains("wlan0monitor"));
    }

}
