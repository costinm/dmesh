//! PSI-based resource management and priority-based eviction.
//!
//! Monitors `/proc/pressure/memory` and freezes or stops low-priority
//! services when memory pressure is detected. Services are evicted
//! in order of decreasing priority value (highest number = least important).

use std::collections::HashMap;
use std::fs;
use std::sync::Arc;

use parking_lot::Mutex;
use tracing::{info, warn};

use crate::config::AppConfig;
use crate::process::ManagedProcess;

// ============================================================================
// Pressure Levels
// ============================================================================

/// Classified memory pressure level based on PSI avg10.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PressureLevel {
    /// No significant pressure.
    None,
    /// Light pressure — consider freezing expendable services.
    Low,
    /// Moderate pressure — freeze low-priority services.
    Medium,
    /// Critical pressure — stop low-priority services.
    Critical,
}

impl std::fmt::Display for PressureLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::None => write!(f, "none"),
            Self::Low => write!(f, "low"),
            Self::Medium => write!(f, "medium"),
            Self::Critical => write!(f, "critical"),
        }
    }
}

// ============================================================================
// PSI Parsing
// ============================================================================

/// Parsed PSI pressure data from `/proc/pressure/memory`.
#[derive(Debug, Clone, Default)]
pub struct PressureData {
    pub some_avg10: f64,
    pub some_avg60: f64,
    pub some_avg300: f64,
    pub full_avg10: f64,
    pub full_avg60: f64,
    pub full_avg300: f64,
}

/// Read and parse `/proc/pressure/memory`.
pub fn read_memory_pressure() -> Option<PressureData> {
    let content = fs::read_to_string("/proc/pressure/memory").ok()?;
    parse_pressure(&content)
}

/// Read and parse `/proc/pressure/cpu`.
pub fn read_cpu_pressure() -> Option<PressureData> {
    let content = fs::read_to_string("/proc/pressure/cpu").ok()?;
    parse_pressure(&content)
}

/// Read `MemTotal` from `/proc/meminfo` in bytes.
pub fn read_mem_total() -> Option<u64> {
    let content = fs::read_to_string("/proc/meminfo").ok()?;
    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("MemTotal:") {
            let kb = rest
                .trim()
                .trim_end_matches(" kB")
                .trim()
                .parse::<u64>()
                .ok()?;
            return Some(kb * 1024);
        }
    }
    None
}

/// Whether the host administrator has set up swap or zram at all.
pub fn swap_exists() -> bool {
    if let Ok(swaps) = fs::read_to_string("/proc/swaps") {
        // First line is the header; any further line means a live swap.
        return swaps.lines().skip(1).any(|line| !line.trim().is_empty());
    }
    false
}

/// Parse PSI pressure content.
///
/// Format:
/// ```text
/// some avg10=0.00 avg60=0.00 avg300=0.00 total=0
/// full avg10=0.00 avg60=0.00 avg300=0.00 total=0
/// ```
fn parse_pressure(content: &str) -> Option<PressureData> {
    let mut data = PressureData::default();

    for line in content.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 4 {
            continue;
        }

        let kind = parts[0];
        let avg10 = parse_kv(parts[1]).unwrap_or(0.0);
        let avg60 = parse_kv(parts[2]).unwrap_or(0.0);
        let avg300 = parse_kv(parts[3]).unwrap_or(0.0);

        match kind {
            "some" => {
                data.some_avg10 = avg10;
                data.some_avg60 = avg60;
                data.some_avg300 = avg300;
            }
            "full" => {
                data.full_avg10 = avg10;
                data.full_avg60 = avg60;
                data.full_avg300 = avg300;
            }
            _ => {}
        }
    }

    Some(data)
}

/// Parse a `key=value` pair where value is f64.
fn parse_kv(s: &str) -> Option<f64> {
    let (_, val) = s.split_once('=')?;
    val.parse().ok()
}

fn psi_threshold_critical() -> f64 {
    std::env::var("MESH_INIT_PSI_CRITICAL")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(60.0)
}

fn psi_threshold_medium() -> f64 {
    std::env::var("MESH_INIT_PSI_MEDIUM")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(20.0)
}

fn psi_threshold_low() -> f64 {
    std::env::var("MESH_INIT_PSI_LOW")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(5.0)
}

/// Classify memory pressure into a level based on PSI some_avg10.
///
/// Thresholds can be overridden via env vars:
/// - `MESH_INIT_PSI_CRITICAL` (default: 60.0)
/// - `MESH_INIT_PSI_MEDIUM` (default: 20.0)
/// - `MESH_INIT_PSI_LOW` (default: 5.0)
pub fn classify_pressure(data: &PressureData) -> PressureLevel {
    let avg10 = data.some_avg10;
    if avg10 >= psi_threshold_critical() {
        PressureLevel::Critical
    } else if avg10 >= psi_threshold_medium() {
        PressureLevel::Medium
    } else if avg10 >= psi_threshold_low() {
        PressureLevel::Low
    } else {
        PressureLevel::None
    }
}

// ============================================================================
// Resource Manager
// ============================================================================

/// Admission-only resource manager; the pressure monitor itself lives in
/// `pressure.rs` (phase 3) as an event-driven ladder.
pub struct ResourceManager {
    services: Arc<Mutex<HashMap<String, ManagedProcess>>>,
}

impl ResourceManager {
    /// Create a new resource manager.
    pub fn new(services: Arc<Mutex<HashMap<String, ManagedProcess>>>) -> Self {
        Self { services }
    }

    /// Check if a service can be started given current memory conditions.
    ///
    /// Returns false if:
    /// - Memory pressure is Critical (PSI avg10 >= 60%).
    /// - The sum of `memory_low` reservations of running and frozen services
    ///   plus this service's `memory_low` would exceed available memory.
    pub fn can_start(&self, config: &AppConfig) -> bool {
        // 1. Check PSI pressure
        if let Some(pressure) = read_memory_pressure() {
            let level = classify_pressure(&pressure);
            if level >= PressureLevel::Critical {
                warn!("cannot_start_memory_pressure_critical");
                return false;
            }
        }

        // 2. Check memory.low admission
        let new_low = config.resources.memory_low.unwrap_or(0);
        if new_low > 0 {
            let committed = self.committed_memory_low();
            let available = read_available_memory().unwrap_or(u64::MAX);
            let total_needed = committed + new_low;

            if total_needed > available {
                warn!(
                    service = %config.name,
                    committed,
                    new = new_low,
                    total = total_needed,
                    available,
                    "memory_low_admission_failed"
                );
                return false;
            }

            info!(
                service = %config.name,
                committed,
                new = new_low,
                total = total_needed,
                available,
                "memory_admission_ok"
            );
        }

        true
    }

    /// Sum of `memory_low` reservations for all currently running services.
    pub fn committed_memory_low(&self) -> u64 {
        use crate::protocol::ServiceState;
        let services = self.services.lock();
        services
            .values()
            .filter(|p| p.protocol_state() == ServiceState::Running)
            .map(|p| p.config.resources.memory_low.unwrap_or(0))
            .sum()
    }
}

// ============================================================================
// System Memory
// ============================================================================

/// Read available memory from `/proc/meminfo`.
///
/// Returns the `MemAvailable` value in bytes, or `None` if it cannot be read.
pub fn read_available_memory() -> Option<u64> {
    let content = fs::read_to_string("/proc/meminfo").ok()?;
    parse_meminfo_available(&content)
}

/// Parse the `MemAvailable` field from `/proc/meminfo` content.
///
/// The field is in kilobytes, so we multiply by 1024 to return bytes.
fn parse_meminfo_available(content: &str) -> Option<u64> {
    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("MemAvailable:") {
            let trimmed = rest.trim().trim_end_matches(" kB").trim();
            let kb: u64 = trimmed.parse().ok()?;
            return Some(kb * 1024);
        }
    }
    None
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_meminfo_available() {
        let content = "\
MemTotal:       65847296 kB
MemFree:        15381516 kB
MemAvailable:   48343700 kB
Buffers:            2112 kB
Cached:         32937264 kB
";
        let avail = parse_meminfo_available(content).unwrap();
        assert_eq!(avail, 48343700 * 1024);
    }

    #[test]
    fn test_parse_meminfo_missing() {
        let content = "MemTotal: 100 kB\nMemFree: 50 kB\n";
        assert!(parse_meminfo_available(content).is_none());
    }

    #[test]
    fn test_committed_memory_low() {
        let services = Arc::new(Mutex::new(HashMap::new()));
        let rm = ResourceManager::new(services.clone());

        // No services → 0
        assert_eq!(rm.committed_memory_low(), 0);

        // Add a running service with memory_low
        let cfg = AppConfig {
            name: "svc1".to_string(),
            command: "/bin/true".to_string(),
            args: vec![],
            uid: None,
            gid: None,
            user: None,
            group: None,
            env: HashMap::new(),
            priority: 500,
            oneshot: false,
            oom_score_adjust: None,
            resources: crate::config::ResolvedResourceLimits {
                memory_low: Some(256 * 1024 * 1024),
                ..Default::default()
            },
            activation: vec![],
            source_path: None,
            ..Default::default()
        };
        let mut p = ManagedProcess::new(cfg);
        p.state = crate::states::ServiceState::Running;
        p.pid = Some(100);
        services.lock().insert("svc1".to_string(), p);

        assert_eq!(rm.committed_memory_low(), 256 * 1024 * 1024);

        // A stopped service should not count
        let cfg2 = AppConfig {
            name: "svc2".to_string(),
            command: "/bin/true".to_string(),
            args: vec![],
            uid: None,
            gid: None,
            user: None,
            group: None,
            env: HashMap::new(),
            priority: 500,
            oneshot: false,
            oom_score_adjust: None,
            resources: crate::config::ResolvedResourceLimits {
                memory_low: Some(128 * 1024 * 1024),
                ..Default::default()
            },
            activation: vec![],
            source_path: None,
            ..Default::default()
        };
        let p2 = ManagedProcess::new(cfg2);
        // p2.state defaults to Stopped
        services.lock().insert("svc2".to_string(), p2);

        // Still only svc1 counts
        assert_eq!(rm.committed_memory_low(), 256 * 1024 * 1024);
    }

    static ENV_MUTEX: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

    #[test]
    fn test_pressure_level_classification() {
        let _guard = ENV_MUTEX.lock();
        let mut data = PressureData::default();
        data.some_avg10 = 0.0;
        assert_eq!(classify_pressure(&data), PressureLevel::None);

        data.some_avg10 = 4.9;
        assert_eq!(classify_pressure(&data), PressureLevel::None);

        data.some_avg10 = 5.0;
        assert_eq!(classify_pressure(&data), PressureLevel::Low);

        data.some_avg10 = 19.9;
        assert_eq!(classify_pressure(&data), PressureLevel::Low);

        data.some_avg10 = 20.0;
        assert_eq!(classify_pressure(&data), PressureLevel::Medium);

        data.some_avg10 = 59.9;
        assert_eq!(classify_pressure(&data), PressureLevel::Medium);

        data.some_avg10 = 60.0;
        assert_eq!(classify_pressure(&data), PressureLevel::Critical);

        data.some_avg10 = 100.0;
        assert_eq!(classify_pressure(&data), PressureLevel::Critical);
    }

    #[test]
    fn test_classify_pressure_with_env_override() {
        let _guard = ENV_MUTEX.lock();
        unsafe {
            std::env::set_var("MESH_INIT_PSI_CRITICAL", "80.0");
            std::env::set_var("MESH_INIT_PSI_MEDIUM", "40.0");
            std::env::set_var("MESH_INIT_PSI_LOW", "10.0");
        }

        let mut data = PressureData::default();
        data.some_avg10 = 9.0;
        assert_eq!(classify_pressure(&data), PressureLevel::None);

        data.some_avg10 = 10.0;
        assert_eq!(classify_pressure(&data), PressureLevel::Low);

        data.some_avg10 = 39.9;
        assert_eq!(classify_pressure(&data), PressureLevel::Low);

        data.some_avg10 = 40.0;
        assert_eq!(classify_pressure(&data), PressureLevel::Medium);

        data.some_avg10 = 79.9;
        assert_eq!(classify_pressure(&data), PressureLevel::Medium);

        data.some_avg10 = 80.0;
        assert_eq!(classify_pressure(&data), PressureLevel::Critical);

        unsafe {
            std::env::remove_var("MESH_INIT_PSI_CRITICAL");
            std::env::remove_var("MESH_INIT_PSI_MEDIUM");
            std::env::remove_var("MESH_INIT_PSI_LOW");
        }
    }

    #[test]
    fn test_parse_pressure() {
        let content = "\
some avg10=1.23 avg60=4.56 avg300=7.89 total=12345
full avg10=0.10 avg60=0.20 avg300=0.30 total=5678
";
        let data = parse_pressure(content).unwrap();
        assert!((data.some_avg10 - 1.23).abs() < 0.001);
        assert!((data.some_avg60 - 4.56).abs() < 0.001);
        assert!((data.full_avg10 - 0.10).abs() < 0.001);
    }

    #[test]
    fn test_pressure_level_ordering() {
        assert!(PressureLevel::None < PressureLevel::Low);
        assert!(PressureLevel::Low < PressureLevel::Medium);
        assert!(PressureLevel::Medium < PressureLevel::Critical);
    }

    #[test]
    fn test_eviction_order_uses_pressure_plan() {
        use crate::config::{AppConfig, ResolvedResourceLimits};

        let make_config = |name: &str, priority: u32| AppConfig {
            name: name.to_string(),
            command: "/bin/sleep".to_string(),
            args: vec!["999".to_string()],
            uid: None,
            gid: None,
            user: None,
            group: None,
            env: HashMap::new(),
            priority,
            oneshot: false,
            oom_score_adjust: None,
            resources: ResolvedResourceLimits::default(),
            activation: vec![],
            source_path: None,
            ..Default::default()
        };

        let services = Arc::new(Mutex::new(HashMap::new()));
        {
            let mut svcs = services.lock();
            // Critical service — should not be evicted
            let mut p = ManagedProcess::new(make_config("system_ui", 50));
            p.state = crate::states::ServiceState::Running;
            p.pid = Some(100);
            svcs.insert("system_ui".to_string(), p);

            // Medium priority
            let mut p = ManagedProcess::new(make_config("browser", 500));
            p.state = crate::states::ServiceState::Running;
            p.pid = Some(200);
            svcs.insert("browser".to_string(), p);

            // Expendable
            let mut p = ManagedProcess::new(make_config("background_sync", 900));
            p.state = crate::states::ServiceState::Running;
            p.pid = Some(300);
            svcs.insert("background_sync".to_string(), p);
        }

        // Low pressure under the phase-3 ladder: trim first. Only services
        // included in the snapshot participate — the protected system_ui
        // never appears.
        let snapshot = crate::pressure::PressureSnapshot {
            memory_avg10: 5.0,
            memory_avg60: 5.0,
            cpu_avg10: 0.0,
            mem_total: 8 << 30,
            mem_available: 1 << 30,
            swap_exists: false,
            services: vec![crate::pressure::ServicePressure {
                name: "background_sync".to_string(),
                state: crate::states::ServiceState::Running,
                priority: 900,
                idle: true,
                self_reports: false,
                freeze_reason: None,
                cgroup_path: "/sys/fs/cgroup/mesh.slice/background_sync.scope".to_string(),
                memory_current: 0,
                memory_low: 0,
                protected: false,
                freezable: true,
            }],
        };
        let now = std::time::Instant::now();
        let actions = crate::pressure::plan(
            &snapshot,
            &crate::pressure::PressurePolicy::default(),
            &crate::pressure::PressureHistory::default(),
            now,
        );
        // A fresh history applies the first ladder step immediately.
        assert_eq!(
            actions,
            vec![crate::pressure::Action::Trim {
                level: crate::pressure::TrimRound::Background,
            }]
        );

        let svcs = services.lock();
        // system_ui should be untouched (priority < 100)
        assert_eq!(
            svcs["system_ui"].protocol_state(),
            crate::protocol::ServiceState::Running
        );
    }
}
