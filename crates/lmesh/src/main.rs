use anyhow::{Context, Result};
use lmesh::{LmeshService, LocalDiscovery};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::time::{Duration, sleep};
use tracing::{debug, error, warn};

const DEFAULT_ANNOUNCE_INTERVAL_SECS: u64 = 60;
const DEFAULT_STANDALONE_SOCKET: &str = "lmesh/mesh.sock";
const ANNOUNCE_INTERVAL_ENV: &str = "LMESH_ANNOUNCE_INTERVAL_SECS";
const CONTROL_SOCKET_ENV: &str = "LMESH_CONTROL_SOCKET";
const NAN_AUTOSTART_ENV: &str = "LMESH_NAN_AUTOSTART";
const NAN_EVENT_LOG_ENV: &str = "LMESH_NAN_EVENT_LOG";
const AP_AUTOSTART_ENV: &str = "LMESH_AP_AUTOSTART";
const AP_IFACE_ENV: &str = "LMESH_AP_IFACE";
const DEFAULT_AP_IFACE: &str = "wlan0";

#[tokio::main]
async fn main() -> Result<()> {
    let (trace_buffer, _trace_guard) = mesh::local_trace::init("lmesh");
    mesh::local_trace::serve("lmesh", trace_buffer);

    run_server().await
}

async fn run_server() -> Result<()> {
    let mut discovery = LocalDiscovery::new(None).await?;
    discovery.start().await?;
    discovery.announce().await?;

    let discovery = Arc::new(discovery);
    let service = Arc::new(LmeshService::new(discovery.clone()));
    let nan_socket_available =
        nan_autostart_enabled() && service.default_nan_control_socket_exists();
    let nan_started = if nan_socket_available {
        let result = service.start_default_nan();
        debug!(?result, "nan_default_started");
        nan_start_succeeded(&result)
    } else {
        false
    };
    if nan_started {
        if nan_event_log_enabled() {
            spawn_nan_event_logger(service.clone());
        }
    } else if nan_socket_available {
        warn!("nan_autostart_failed");
    } else if nan_autostart_enabled() {
        debug!("nan_autostart_skipped_no_wpa_control_socket");
    }
    if nan_started && ap_autostart_enabled() {
        let nan_iface = wifi_iface();
        let ap_iface = ap_iface();
        if ap_can_coexist_with_nan(&nan_iface, &ap_iface) {
            let result = service.start_default_open_ap(ap_iface);
            debug!(?result, "open_ap_autostarted");
        } else {
            debug!(
                nan_iface,
                ap_iface, "open_ap_autostart_skipped_no_safe_coexistence"
            );
        }
    }
    debug!(
        public_key = %service.public_key_b64(),
        "service_started"
    );

    let discovery_periodic = discovery.clone();
    let announce_interval = announce_interval();
    tokio::spawn(async move {
        loop {
            sleep(announce_interval).await;
            if let Err(e) = discovery_periodic.announce().await {
                warn!("Failed to send announcement: {}", e);
            }
        }
    });

    let listen_path = standalone_listen_path()?;
    let listen_path = listen_path.to_string_lossy().into_owned();
    let mut listener = mesh::server::MeshListener::new("lmesh", Some(&listen_path))
        .map_err(|e| anyhow::anyhow!("lmesh listener error: {}", e))?;
    let mcp = Arc::new(mesh::jsonl::McpRegistry::new("lmesh"));
    while let Some(stream) = listener
        .accept()
        .await
        .map_err(|e| anyhow::anyhow!("lmesh accept error: {}", e))?
    {
        let service = service.clone();
        let mcp = mcp.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, service, mcp).await {
                error!("lmesh JSONL connection error: {}", e);
            }
        });
    }

    Ok(())
}

fn announce_interval() -> Duration {
    let secs = std::env::var(ANNOUNCE_INTERVAL_ENV)
        .ok()
        .and_then(|value| parse_announce_interval_secs(&value));
    Duration::from_secs(secs.unwrap_or(DEFAULT_ANNOUNCE_INTERVAL_SECS))
}

fn nan_autostart_enabled() -> bool {
    std::env::var(NAN_AUTOSTART_ENV)
        .map(|value| !matches!(value.as_str(), "0" | "false" | "FALSE" | "off" | "OFF"))
        .unwrap_or(true)
}

fn nan_event_log_enabled() -> bool {
    std::env::var(NAN_EVENT_LOG_ENV)
        .map(|value| !matches!(value.as_str(), "0" | "false" | "FALSE" | "off" | "OFF"))
        .unwrap_or(true)
}

fn ap_autostart_enabled() -> bool {
    std::env::var(AP_AUTOSTART_ENV)
        .map(|value| !matches!(value.as_str(), "0" | "false" | "FALSE" | "off" | "OFF"))
        .unwrap_or(true)
}

fn wifi_iface() -> String {
    std::env::var("LMESH_WIFI_IFACE").unwrap_or_else(|_| "wlan1".to_string())
}

fn ap_iface() -> String {
    std::env::var(AP_IFACE_ENV).unwrap_or_else(|_| DEFAULT_AP_IFACE.to_string())
}

fn ap_can_coexist_with_nan(nan_iface: &str, ap_iface: &str) -> bool {
    if nan_iface == ap_iface {
        return false;
    }
    let nan_phy = std::fs::read_link(format!("/sys/class/net/{nan_iface}/phy80211"));
    let ap_phy = std::fs::read_link(format!("/sys/class/net/{ap_iface}/phy80211"));
    matches!((nan_phy, ap_phy), (Ok(nan_phy), Ok(ap_phy)) if nan_phy != ap_phy)
}

fn spawn_nan_event_logger(service: Arc<LmeshService>) {
    tokio::spawn(async move {
        let mut consecutive_errors = 0_u32;
        loop {
            let service = service.clone();
            let poll_service = service.clone();
            let result = tokio::task::spawn_blocking(move || {
                poll_service.collect_default_nan_events(30_000, 128)
            })
            .await;
            match result {
                Ok(value) => {
                    let should_restart = nan_events_need_restart(&value);
                    if value.get("ok").and_then(serde_json::Value::as_bool) == Some(false) {
                        consecutive_errors = consecutive_errors.saturating_add(1);
                        if consecutive_errors == 1 || consecutive_errors % 12 == 0 {
                            warn!(?value, consecutive_errors, "nan_event_poll_failed");
                        }
                    } else {
                        consecutive_errors = 0;
                        if should_restart || nan_events_count(&value) > 0 {
                            debug!(?value, should_restart, "nan_events_polled");
                        }
                    }
                    if should_restart {
                        let result = service.start_default_nan();
                        warn!(?result, "nan_default_restarted_after_termination");
                    }
                }
                Err(error) => {
                    consecutive_errors = consecutive_errors.saturating_add(1);
                    if consecutive_errors == 1 || consecutive_errors % 12 == 0 {
                        warn!("NAN event logger task failed: {}", error);
                    }
                }
            }
            let idle = if consecutive_errors == 0 {
                Duration::from_millis(100)
            } else {
                Duration::from_secs(5)
            };
            sleep(idle).await;
        }
    });
}

fn nan_events_count(value: &serde_json::Value) -> usize {
    value
        .get("events")
        .and_then(serde_json::Value::as_array)
        .map(Vec::len)
        .unwrap_or(0)
}

fn nan_events_need_restart(value: &serde_json::Value) -> bool {
    value
        .get("events")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|event| event.get("event").and_then(serde_json::Value::as_str))
        .any(|event| event == "NAN-PUBLISH-TERMINATED" || event == "NAN-SUBSCRIBE-TERMINATED")
}

fn nan_start_succeeded(value: &serde_json::Value) -> bool {
    value
        .pointer("/start/nan_capability/ok")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
}

fn parse_announce_interval_secs(value: &str) -> Option<u64> {
    let secs = value.trim().parse::<u64>().ok()?;
    (secs > 0).then_some(secs)
}

fn standalone_listen_path() -> Result<PathBuf> {
    let path = std::env::var_os(CONTROL_SOCKET_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_STANDALONE_SOCKET));
    resolve_relative_path(path)
}

fn resolve_relative_path(path: PathBuf) -> Result<PathBuf> {
    let path = if path.is_absolute() {
        path
    } else {
        std::env::current_dir()
            .context("failed to resolve current working directory")?
            .join(path)
    };
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    Ok(path)
}

async fn handle_connection(
    stream: mesh::server::MeshStream,
    service: Arc<LmeshService>,
    mcp: Arc<mesh::jsonl::McpRegistry>,
) -> Result<()> {
    let (reader, mut writer) = tokio::io::split(stream);
    let mut reader = BufReader::new(reader);
    let mut line = String::new();

    loop {
        line.clear();
        let bytes_read = reader
            .read_line(&mut line)
            .await
            .context("failed to read JSONL request")?;
        if bytes_read == 0 {
            break;
        }

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let service = service.clone();
        let (format, response) = mesh::jsonl::dispatch_request(trimmed, &mcp, move |request| {
            let service = service.clone();
            async move {
                debug!(?request, "lmesh request");
                service.handle_request(request).await
            }
        })
        .await;
        let Some(response) = response else {
            continue;
        };
        let response = mesh::jsonl::format_response(response, &format)?;
        writer
            .write_all(response.as_bytes())
            .await
            .context("failed to write JSONL response")?;
        writer.write_all(b"\n").await?;
        writer.flush().await?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_announce_interval_accepts_positive_seconds() {
        assert_eq!(parse_announce_interval_secs("5"), Some(5));
        assert_eq!(parse_announce_interval_secs(" 30 "), Some(30));
    }

    #[test]
    fn parse_announce_interval_rejects_zero_and_invalid_values() {
        assert_eq!(parse_announce_interval_secs("0"), None);
        assert_eq!(parse_announce_interval_secs("nope"), None);
    }

    #[test]
    fn nan_autostart_defaults_on() {
        unsafe {
            std::env::remove_var(NAN_AUTOSTART_ENV);
        }
        assert!(nan_autostart_enabled());
    }

    #[test]
    fn nan_event_log_defaults_on() {
        unsafe {
            std::env::remove_var(NAN_EVENT_LOG_ENV);
        }
        assert!(nan_event_log_enabled());
    }

    #[test]
    fn ap_does_not_coexist_on_the_nan_interface() {
        assert!(!ap_can_coexist_with_nan("wlan1", "wlan1"));
    }

    #[test]
    fn nan_start_requires_a_successful_wpa_response() {
        assert!(!nan_start_succeeded(&serde_json::json!({
            "start": {"nan_capability": {"ok": false}}
        })));
        assert!(nan_start_succeeded(&serde_json::json!({
            "start": {"nan_capability": {"ok": true}}
        })));
    }

    #[test]
    fn resolve_relative_path_uses_cwd() {
        let cwd = std::env::current_dir().unwrap();
        assert_eq!(
            resolve_relative_path(PathBuf::from("lmesh/mesh.sock")).unwrap(),
            cwd.join("lmesh").join("mesh.sock")
        );
    }
}
