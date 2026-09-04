//! Shared host Wi-Fi ownership and netd policy.
//!
//! The full `lmesh` service and the Wi-Fi-only `lmesh-wifi` service use this
//! crate. Linux Wi-Fi, host NAN discovery/activation, and AP/STA operations
//! live here; direct UART sessions are owned by `dmesh-cli`, not this service.

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

mod infra_credentials;
mod radio;
/// Host-side JSON/compatibility conversion for raw NAN and legacy BLE commands.
/// The byte/state core remains in `dmesh-rawnan`.
pub mod radio_protocol;
pub mod recovery;

// The shared Linux mesh discovery/routing core. `lmesh` re-exports this
// module and contributes only its BLE launcher integration.
extern crate self as lmesh_wifi;
pub mod mesh_core;
pub mod mesh_runtime;

pub use infra_credentials::{
    INFRA_STA_CREDENTIALS_PATH, InfrastructureCredentials, load_default_infrastructure_credentials,
    load_infrastructure_credentials,
};
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
    wifi_was_absent: Arc<AtomicBool>,
}

impl WifiService {
    pub fn new(netd: WifiNetd, radio: RadioService) -> Self {
        Self {
            netd,
            radio,
            wifi_was_absent: Arc::new(AtomicBool::new(false)),
        }
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

    /// Start one owned STA transport epoch.  Both host binaries use this
    /// boundary so interface ownership, BSSID decoding, and the complete
    /// previous-epoch cleanup remain in the shared Wi-Fi implementation.
    pub fn transport_start(
        &self,
        iface: Option<String>,
        ssid: String,
        passphrase: Option<String>,
        bssid: Option<String>,
        channel: Option<u8>,
        ap: bool,
        open: bool,
    ) -> serde_json::Value {
        let iface = match self.owned_sta_iface(iface) {
            Ok(iface) => iface,
            Err(error) => return serde_json::json!({"ok": false, "error": error.to_string()}),
        };
        if ap {
            if open && passphrase.as_deref().is_some_and(|value| !value.is_empty()) {
                return serde_json::json!({"ok": false, "iface": iface, "error": "open AP cannot accept a passphrase"});
            }
            // A normal AP is the safe default for clients. P2P-GO remains a
            // service-startup diagnostic personality, not the implicit
            // meaning of an AP request.
            let backend = if open { "open" } else { "wpa2-ap" };
            return self.radio.wifi_p2p_transport_start(
                Some(iface),
                &backend,
                passphrase.as_deref().filter(|value| !value.is_empty()),
            );
        }
        let bssid = match parse_bssid(bssid.as_deref()) {
            Ok(bssid) => bssid,
            Err(error) => {
                return serde_json::json!({"ok": false, "iface": iface, "error": error.to_string()});
            }
        };
        self.radio
            .wifi_sta_transport_start(Some(iface), ssid, passphrase, bssid, channel)
    }

    /// Start the configured channel-6 AP personality and then attach the
    /// long-lived NAN/NOW monitor fixture. `wpa2-ap` is a conventional WPA2
    /// infrastructure AP, `open` uses the native diagnostic AP path, and
    /// `p2p` retains the P2P-GO compatibility backend.
    /// Transport replacement owns cleanup, so monitor setup deliberately
    /// follows the actual settled radio channel.
    pub fn start_p2p_go_with_rawnan(
        &self,
        iface: Option<String>,
        channel: u8,
    ) -> serde_json::Value {
        let iface = match self.owned_sta_iface(iface) {
            Ok(iface) => iface,
            Err(error) => return serde_json::json!({"ok": false, "error": error.to_string()}),
        };
        let backend = match std::env::var("LMESH_AP_BACKEND").as_deref() {
            Ok("open") => "open",
            Ok("p2p") => "p2p",
            Ok("wpa2-ap") | Err(_) => "wpa2-ap",
            Ok(_) => "wpa2-ap",
        };
        let transport = self
            .radio
            .wifi_p2p_transport_start(Some(iface.clone()), backend, None);
        if transport.get("ok").and_then(serde_json::Value::as_bool) != Some(true) {
            return serde_json::json!({
                "ok": false,
                "iface": iface,
                "transport": transport,
            });
        }
        let monitor = self
            .radio
            .prepare_ap_raw_monitor_fixture(Some(iface.clone()), Some(channel));
        let listener = if monitor.get("ok").and_then(serde_json::Value::as_bool) == Some(true) {
            self.radio.wifi_raw_listen(
                Some(iface.clone()),
                Some(channel),
                Some(86_400),
                Some("monitor".to_owned()),
            )
        } else {
            serde_json::json!({"ok": false, "state": "not_started", "reason": "monitor setup failed"})
        };
        let beacon_listener = if monitor.get("ok").and_then(serde_json::Value::as_bool)
            == Some(true)
        {
            self.radio.wifi_nan_beacon_listen(Some(iface.clone()))
        } else {
            serde_json::json!({"ok": false, "state": "not_started", "reason": "monitor setup failed"})
        };
        serde_json::json!({
            "ok": transport.get("ok").and_then(serde_json::Value::as_bool) == Some(true)
                && monitor.get("ok").and_then(serde_json::Value::as_bool) == Some(true)
                && listener.get("ok").and_then(serde_json::Value::as_bool) == Some(true),
            "iface": iface,
            "ap_backend": backend,
            "transport": transport,
            "monitor": monitor,
            "listener": listener,
            "beacon_listener": beacon_listener,
        })
    }

    fn owned_sta_iface(&self, iface: Option<String>) -> Result<String> {
        let iface = iface
            .or_else(|| self.netd.owned_interfaces().names().first().cloned())
            .ok_or_else(|| {
                anyhow::anyhow!("LMESH_INTERFACES must name an owned Wi-Fi interface")
            })?;
        self.netd.authorize(Operation::Sta, &iface)?;
        Ok(iface)
    }

    /// Apply the common startup policy used by the stable service. The stable
    /// The stable AP is a WPA2-PSK infrastructure AP; P2P-GO and native open
    /// AP are explicitly selected diagnostic backends.
    pub fn start_stable(&self) -> Vec<serde_json::Value> {
        let mut results = self
            .radio
            .apply_startup_rate_profile(self.netd.owned_interfaces().names());
        if let Some(iface) = self.netd.owned_interfaces().names().first().cloned() {
            if self.netd.authorize(Operation::Sta, &iface).is_ok() {
                let channel = std::env::var("LMESH_AP_CHANNEL")
                    .ok()
                    .and_then(|value| value.parse::<u8>().ok())
                    .unwrap_or(6)
                    .clamp(1, 13);
                results.push(self.start_p2p_go_with_rawnan(Some(iface), channel));
            }
        }
        results
    }

    /// Observe whether the owned base adapter exists. Startup is rerun only
    /// after a confirmed absent-to-present transition; this never reacts to
    /// carrier, AP, P2P, or monitor state.
    pub fn reconcile_stable_health(&self) -> serde_json::Value {
        let Some(iface) = self.netd.owned_interfaces().names().first().cloned() else {
            return serde_json::json!({"ok": true, "state": "no_owned_interface"});
        };
        if self.netd.authorize(Operation::Ap, &iface).is_err() {
            return serde_json::json!({"ok": true, "state": "not_an_ap_owner", "iface": iface});
        }
        let link = self.radio.wifi_interface_status(Some(iface.clone()));
        if link.get("ok").and_then(serde_json::Value::as_bool) != Some(true) {
            self.wifi_was_absent.store(true, Ordering::Release);
            return serde_json::json!({"ok": true, "state": "absent", "iface": iface, "link": link});
        }
        if !self.wifi_was_absent.swap(false, Ordering::AcqRel) {
            return serde_json::json!({"ok": true, "state": "present", "iface": iface, "link": link});
        }
        let recovery = self.start_stable();
        serde_json::json!({
            "ok": recovery.iter().any(|result| result.get("ok").and_then(serde_json::Value::as_bool) == Some(true)),
            "state": "reappeared_reinitialized",
            "iface": iface,
            "prior_link": link,
            "recovery": recovery,
        })
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
            owned == iface || iface.strip_suffix("mon").is_some_and(|base| base == owned)
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

fn parse_bssid(value: Option<&str>) -> Result<Option<[u8; 6]>> {
    let Some(value) = value else {
        return Ok(None);
    };
    let hex = value.trim().replace([':', '-'], "");
    if hex.len() != 12 {
        bail!("bssid must contain exactly six octets");
    }
    let mut bssid = [0_u8; 6];
    for (index, byte) in bssid.iter_mut().enumerate() {
        let offset = index * 2;
        *byte = u8::from_str_radix(&hex[offset..offset + 2], 16)
            .map_err(|_| anyhow::anyhow!("bssid must contain hexadecimal octets"))?;
    }
    Ok(Some(bssid))
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

    #[test]
    fn parses_transport_bssid_without_lmesh_adapter() {
        assert_eq!(
            parse_bssid(Some("14:c1:9f:e5:98:01")).unwrap(),
            Some([0x14, 0xc1, 0x9f, 0xe5, 0x98, 0x01])
        );
        assert!(parse_bssid(Some("14:c1:9f:e5:98")).is_err());
        assert!(parse_bssid(Some("14:c1:9f:e5:98:zz")).is_err());
    }
}
