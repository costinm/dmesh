//! Host-side mDNS discovery of ADB wireless-debugging services.
//!
//! On Android the equivalent is `NsdManager` (see `app-control`'s
//! `NsdDiscovery.java`); on the host we use `mdns-sd`'s `ServiceDaemon`, which
//! drives a plain UDP socket on the mDNS multicast group directly (no
//! `systemd-resolved` or helper daemon).
//!
//! Browsing is a battery/network-sensitive operation, so every call is bounded
//! by an explicit `timeout` (a time limit, not an open-ended scan). `browse_many`
//! collects *all* distinct instances over the whole window instead of stopping at
//! the first responder, so a fleet operation can see every advertising device.

use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use mdns_sd::{ServiceDaemon, ServiceEvent};

/// ADB wireless-debugging service types (browse with `.local.` suffix).
pub const SERVICE_PAIRING: &str = "_adb-tls-pairing._tcp.local.";
pub const SERVICE_CONNECT: &str = "_adb-tls-connect._tcp.local.";

/// A discovered ADB endpoint.
#[derive(Debug, Clone)]
pub struct DiscoveredAdb {
    pub service_type: String,
    /// Full instance name, e.g. `adb-<guid>-<rand>._adb-tls-pairing._tcp.local.`
    pub name: String,
    pub host: Option<String>,
    pub port: Option<u16>,
}

impl DiscoveredAdb {
    pub fn addr(&self) -> Option<String> {
        match (&self.host, self.port) {
            (Some(h), Some(p)) => Some(format!("{h}:{p}")),
            _ => None,
        }
    }
}

fn to_discovered(service_type: &str, svc: &mdns_sd::ResolvedService) -> DiscoveredAdb {
    let host = svc
        .get_addresses_v4()
        .into_iter()
        .next()
        .map(|a| a.to_string())
        .or_else(|| {
            if svc.get_hostname().is_empty() {
                None
            } else {
                Some(svc.get_hostname().to_string())
            }
        });
    DiscoveredAdb {
        service_type: service_type.to_string(),
        name: svc.get_fullname().to_string(),
        host,
        port: Some(svc.get_port()),
    }
}

fn upsert(seen: &mut Vec<DiscoveredAdb>, d: DiscoveredAdb) {
    match seen.iter_mut().position(|s| s.name == d.name) {
        Some(i) => seen[i] = d, // refresh address/port on re-resolve
        None => seen.push(d),
    }
}

/// Browse one or more service types for the full `timeout`, returning *every*
/// distinct valid instance seen (not just the first). A single daemon polls all
/// requested types round-robin. Blocking (CLI use); the only bound is `timeout`.
pub fn browse_many(service_types: &[&str], timeout: Duration) -> Result<Vec<DiscoveredAdb>> {
    let daemon = ServiceDaemon::new().context("start mdns daemon")?;
    let mut rxs: Vec<(&str, mdns_sd::Receiver<ServiceEvent>)> = Vec::new();
    for st in service_types {
        let rx = daemon
            .browse(st)
            .with_context(|| format!("browse {st}"))?;
        rxs.push((st, rx));
    }

    let deadline = Instant::now() + timeout;
    let tick = Duration::from_millis(25);
    let mut seen: Vec<DiscoveredAdb> = Vec::new();

    while Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        let per = remaining.min(tick);
        for (st, rx) in rxs.iter_mut() {
            match rx.recv_timeout(per) {
                Ok(ServiceEvent::ServiceResolved(svc)) if svc.is_valid() => {
                    upsert(&mut seen, to_discovered(st, &svc));
                }
                Ok(ServiceEvent::ServiceRemoved(_, name)) => {
                    seen.retain(|s| s.name != name);
                }
                Ok(_) => {}
                Err(_) => {}
            }
        }
    }

    let _ = daemon.shutdown();
    Ok(seen)
}

/// Browse a single service type for the full `timeout`, collecting all matches.
pub fn browse(service_type: &str, timeout: Duration) -> Result<Vec<DiscoveredAdb>> {
    browse_many(&[service_type], timeout)
}

/// Browse both pairing and connect service types for the full `timeout`.
pub fn browse_all(timeout: Duration) -> Result<Vec<DiscoveredAdb>> {
    browse_many(&[SERVICE_PAIRING, SERVICE_CONNECT], timeout)
}

/// Convenience: discover pairing endpoints.
pub fn find_pairing(timeout: Duration) -> Result<Vec<DiscoveredAdb>> {
    browse(SERVICE_PAIRING, timeout)
}

/// Convenience: discover connect endpoints.
pub fn find_connect(timeout: Duration) -> Result<Vec<DiscoveredAdb>> {
    browse(SERVICE_CONNECT, timeout)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_type_constants_have_local_suffix() {
        assert!(SERVICE_PAIRING.ends_with("._tcp.local."));
        assert!(SERVICE_CONNECT.ends_with("._tcp.local."));
    }

    #[test]
    fn addr_format() {
        let d = DiscoveredAdb {
            service_type: SERVICE_PAIRING.into(),
            name: "adb-abc-1234".into(),
            host: Some("192.168.1.10".into()),
            port: Some(37891),
        };
        assert_eq!(d.addr().as_deref(), Some("192.168.1.10:37891"));
    }

    #[test]
    fn addr_none_when_incomplete() {
        let d = DiscoveredAdb {
            service_type: SERVICE_CONNECT.into(),
            name: "x".into(),
            host: None,
            port: None,
        };
        assert_eq!(d.addr(), None);
    }

    #[test]
    fn upsert_refreshes_and_dedups() {
        let mut seen = Vec::new();
        upsert(
            &mut seen,
            DiscoveredAdb {
                service_type: SERVICE_PAIRING.into(),
                name: "n".into(),
                host: Some("1.1.1.1".into()),
                port: Some(1),
            },
        );
        upsert(
            &mut seen,
            DiscoveredAdb {
                service_type: SERVICE_PAIRING.into(),
                name: "n".into(),
                host: Some("2.2.2.2".into()),
                port: Some(2),
            },
        );
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].host.as_deref(), Some("2.2.2.2"));
        assert_eq!(seen[0].port, Some(2));
    }
}
