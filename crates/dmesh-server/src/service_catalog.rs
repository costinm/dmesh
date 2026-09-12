//! Canonical public service identities shared by every Rust host.
//!
//! The numeric tagged-CBOR identities are the wire contract.  HTTP, SSH,
//! Android, and CLI presentation may use the returned dotted name, but none
//! of them owns a second numeric-to-name table.  Platform adapters still own
//! whether they implement a service, never what its wire identity means.

/// One named public service and its stable tagged-CBOR component/method IDs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServiceIdentity {
    pub component: u64,
    pub method: u64,
    pub name: &'static str,
}

/// Return the reviewed portable service identity for a numeric tagged record.
///
/// This deliberately covers only common stream services. One-way announces,
/// direct discovery activation, and platform-private callbacks do not become
/// named stream aliases through this function.
pub const fn stream_service(component: u64, method: u64) -> Option<ServiceIdentity> {
    use crate::{announce, control, raw_wifi, services, telemetry};

    let name = match (component, method) {
        (control::CONTROL_COMPONENT, control::SETTINGS_GET) => "settings.get",
        (control::CONTROL_COMPONENT, control::SETTINGS_SET) => "settings.set",
        (control::CONTROL_COMPONENT, control::SETTINGS_LIST) => "settings.list",
        (announce::ANNOUNCE_COMPONENT, announce::ANNOUNCE_DEVICES_OBSERVED) => "discovery.nodes",
        (services::DIAGNOSTIC_COMPONENT, services::DIAGNOSTIC_STATUS_METHOD) => "status",
        (services::DIAGNOSTIC_COMPONENT, services::DIAGNOSTIC_SERVICES_METHOD) => "services",
        (services::DIAGNOSTIC_COMPONENT, services::DIAGNOSTIC_METRICS_METHOD) => "metrics",
        (services::DIAGNOSTIC_COMPONENT, services::DIAGNOSTIC_EVENTS_METHOD) => "events",
        (services::DIAGNOSTIC_COMPONENT, services::DIAGNOSTIC_LOG_WATCH_METHOD) => "log-watch",
        (services::BOOT_COMPONENT, services::BOOT_RECOVERY_METHOD) => "boot.recovery",
        (telemetry::TELEMETRY_COMPONENT, telemetry::NAN_STATUS_METHOD) => "telemetry.nan_status",
        (telemetry::TELEMETRY_COMPONENT, telemetry::NOW_METRICS_METHOD) => "telemetry.now_metrics",
        (telemetry::TELEMETRY_COMPONENT, telemetry::NAN_METRICS_METHOD) => "telemetry.nan_metrics",
        (telemetry::TELEMETRY_COMPONENT, telemetry::UDP6_METRICS_METHOD) => {
            "telemetry.udp6_metrics"
        }
        (telemetry::TELEMETRY_COMPONENT, telemetry::WIFI_LINK_METRICS_METHOD) => {
            "telemetry.wifi_link_metrics"
        }
        (raw_wifi::RAW_WIFI_COMPONENT, raw_wifi::RAW_WIFI_METHOD_SCAN) => "wifi.scan",
        _ => return None,
    };
    Some(ServiceIdentity {
        component,
        method,
        name,
    })
}

/// Resolve the canonical public dotted name back to its tagged-CBOR identity.
///
/// HTTP/SSH presentation may retain names until the last forwarding hop,
/// whereas firmware ingress normally carries numeric tags. Keeping this
/// inverse lookup beside [`stream_service`] prevents recovery and policy code
/// from growing a second transport-local list of read-only services.
pub fn stream_service_by_name(name: &str) -> Option<ServiceIdentity> {
    use crate::{announce, control, raw_wifi, services, telemetry};

    let (component, method) = match name {
        "settings.get" => (control::CONTROL_COMPONENT, control::SETTINGS_GET),
        "settings.set" => (control::CONTROL_COMPONENT, control::SETTINGS_SET),
        "settings.list" => (control::CONTROL_COMPONENT, control::SETTINGS_LIST),
        "discovery.nodes" => (
            announce::ANNOUNCE_COMPONENT,
            announce::ANNOUNCE_DEVICES_OBSERVED,
        ),
        "status" => (
            services::DIAGNOSTIC_COMPONENT,
            services::DIAGNOSTIC_STATUS_METHOD,
        ),
        "services" => (
            services::DIAGNOSTIC_COMPONENT,
            services::DIAGNOSTIC_SERVICES_METHOD,
        ),
        "metrics" => (
            services::DIAGNOSTIC_COMPONENT,
            services::DIAGNOSTIC_METRICS_METHOD,
        ),
        "events" => (
            services::DIAGNOSTIC_COMPONENT,
            services::DIAGNOSTIC_EVENTS_METHOD,
        ),
        "log-watch" => (
            services::DIAGNOSTIC_COMPONENT,
            services::DIAGNOSTIC_LOG_WATCH_METHOD,
        ),
        "boot.recovery" => (services::BOOT_COMPONENT, services::BOOT_RECOVERY_METHOD),
        "telemetry.nan_status" => (telemetry::TELEMETRY_COMPONENT, telemetry::NAN_STATUS_METHOD),
        "telemetry.now_metrics" => (
            telemetry::TELEMETRY_COMPONENT,
            telemetry::NOW_METRICS_METHOD,
        ),
        "telemetry.nan_metrics" => (
            telemetry::TELEMETRY_COMPONENT,
            telemetry::NAN_METRICS_METHOD,
        ),
        "telemetry.udp6_metrics" => (
            telemetry::TELEMETRY_COMPONENT,
            telemetry::UDP6_METRICS_METHOD,
        ),
        "telemetry.wifi_link_metrics" => (
            telemetry::TELEMETRY_COMPONENT,
            telemetry::WIFI_LINK_METRICS_METHOD,
        ),
        "wifi.scan" => (raw_wifi::RAW_WIFI_COMPONENT, raw_wifi::RAW_WIFI_METHOD_SCAN),
        _ => return None,
    };
    stream_service(component, method)
}

/// Whether replaying this request after a proven-dead peer association is
/// safe.  This is deliberately narrower than "stream service": a stale CID
/// can be recovered by opening a fresh association for reads, whereas a
/// settings write, radio control, or injection request must report an
/// uncertain timeout rather than risk applying an action twice.
pub const fn is_read_only_stream_service(component: u64, method: u64) -> bool {
    use crate::{announce, control, raw_wifi, services, telemetry};

    matches!(
        (component, method),
        (
            control::CONTROL_COMPONENT,
            control::SETTINGS_GET | control::SETTINGS_LIST
        ) | (
            services::DIAGNOSTIC_COMPONENT,
            services::DIAGNOSTIC_STATUS_METHOD
                | services::DIAGNOSTIC_SERVICES_METHOD
                | services::DIAGNOSTIC_METRICS_METHOD
                | services::DIAGNOSTIC_EVENTS_METHOD
                | services::DIAGNOSTIC_LOG_WATCH_METHOD
        ) | (
            announce::ANNOUNCE_COMPONENT,
            announce::ANNOUNCE_DEVICES_OBSERVED
        ) | (telemetry::TELEMETRY_COMPONENT, telemetry::NAN_STATUS_METHOD)
            | (
                telemetry::TELEMETRY_COMPONENT,
                telemetry::NOW_METRICS_METHOD
            )
            | (
                telemetry::TELEMETRY_COMPONENT,
                telemetry::NAN_METRICS_METHOD
            )
            | (
                telemetry::TELEMETRY_COMPONENT,
                telemetry::UDP6_METRICS_METHOD
            )
            | (
                telemetry::TELEMETRY_COMPONENT,
                telemetry::WIFI_LINK_METRICS_METHOD
            )
            | (raw_wifi::RAW_WIFI_COMPONENT, raw_wifi::RAW_WIFI_METHOD_SCAN)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_numeric_stream_services_have_one_canonical_name() {
        assert_eq!(
            stream_service(
                crate::announce::ANNOUNCE_COMPONENT,
                crate::announce::ANNOUNCE_DEVICES_OBSERVED
            ),
            Some(ServiceIdentity {
                component: 6,
                method: 9,
                name: "discovery.nodes",
            })
        );
        assert_eq!(
            stream_service(
                crate::telemetry::TELEMETRY_COMPONENT,
                crate::telemetry::NAN_METRICS_METHOD
            )
            .unwrap()
            .name,
            "telemetry.nan_metrics"
        );
        assert!(is_read_only_stream_service(1, crate::control::SETTINGS_GET));
        assert!(is_read_only_stream_service(
            crate::services::DIAGNOSTIC_COMPONENT,
            crate::services::DIAGNOSTIC_STATUS_METHOD
        ));
        assert!(!is_read_only_stream_service(
            1,
            crate::control::SETTINGS_SET
        ));
        assert_eq!(
            stream_service_by_name("telemetry.nan_metrics")
                .unwrap()
                .method,
            crate::telemetry::NAN_METRICS_METHOD
        );
        assert!(stream_service_by_name("unknown").is_none());
    }
}
