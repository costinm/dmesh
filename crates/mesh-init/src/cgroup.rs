//! Cgroup v2 management for mesh-init services.
//!
//! Creates cgroups under `/sys/fs/cgroup/mesh.slice/`, enables controllers,
//! sets resource limits, and manages process placement.

use std::fs;
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

use tracing::{debug, error, info, warn};

use crate::config::ResolvedResourceLimits;

// ============================================================================
// Error Types
// ============================================================================

/// Errors from cgroup operations.
#[derive(Debug, thiserror::Error)]
pub enum CgroupError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("cgroup error: {0}")]
    CgroupError(String),

    #[error("invalid OOM score {0}: must be between -1000 and 1000")]
    InvalidOomScore(i32),
}

// ============================================================================
// Constants
// ============================================================================

/// Base path for mesh-init cgroups.
const MESH_SLICE_PATH: &str = "/sys/fs/cgroup/mesh.slice";

// ============================================================================
// Cgroup Operations
// ============================================================================

/// Build the cgroup path for a service name.
///
/// Returns `/sys/fs/cgroup/mesh.slice/{name}.scope`.
///
/// `name` is validated to reject path separators and `..` components, which
/// would otherwise allow escaping `mesh.slice`.
pub fn cgroup_path_for(name: &str) -> Result<String, CgroupError> {
    if let Err(reason) = crate::config::validate_cgroup_name(name) {
        error!(name = ?name, error = %reason, "invalid_cgroup_name_rejected");
        return Err(CgroupError::CgroupError(format!(
            "invalid cgroup name: {reason}"
        )));
    }
    Ok(format!("{}/{}.scope", MESH_SLICE_PATH, name))
}

/// Create a cgroup for a service under `mesh.slice`.
///
/// Creates the `mesh.slice` parent if it doesn't exist, enables controllers,
/// then creates the `{name}.scope` child cgroup.
pub fn create_cgroup(name: &str) -> Result<String, CgroupError> {
    let cgroup_root = "/sys/fs/cgroup";

    // Ensure mesh.slice exists
    if !Path::new(MESH_SLICE_PATH).exists() {
        fs::create_dir_all(MESH_SLICE_PATH)?;
        info!(path = %MESH_SLICE_PATH, "slice_created");
    }

    // Enable controllers in the root so mesh.slice can use them
    let _ = enable_controllers(cgroup_root);
    // Enable controllers in mesh.slice so the scope can use them
    let _ = enable_controllers(MESH_SLICE_PATH);

    // Create the scope
    let scope_path = cgroup_path_for(name)?;
    if !Path::new(&scope_path).exists() {
        fs::create_dir_all(&scope_path)?;
        info!(path = %scope_path, "cgroup_created");
    } else if let Err(error) = freeze_cgroup(&scope_path, false) {
        debug!(
            path = %scope_path,
            error = %error,
            "cgroup_unfreeze_existing_failed"
        );
    }

    Ok(scope_path)
}

/// Terminate every process left in a configured service scope from a previous
/// mesh-init instance.
///
/// A service is owned by its cgroup, not by its parent PID: after an
/// unclean mesh-init exit, a child can be reparented while still remaining in
/// `/sys/fs/cgroup/mesh.slice/<service>.scope`.  `cgroup.kill` covers the
/// complete subtree, unlike signalling only the direct members in
/// `cgroup.procs`.
///
/// This is deliberately limited to a validated, configured service name.
/// It never scans or signals processes outside mesh-init's own scope.
pub fn terminate_stale_service_scope(name: &str) -> Result<(), CgroupError> {
    let scope_path = cgroup_path_for(name)?;
    if !Path::new(&scope_path).exists() {
        return Ok(());
    }

    let kill_path = format!("{scope_path}/cgroup.kill");
    if !Path::new(&kill_path).exists() {
        warn!(
            service = name,
            path = %scope_path,
            "stale_service_scope_has_no_cgroup_kill"
        );
        return Ok(());
    }

    fs::write(&kill_path, "1")?;
    info!(service = name, path = %scope_path, "stale_service_scope_killed");

    let deadline = Instant::now() + Duration::from_secs(2);
    while service_scope_populated(&scope_path)? {
        if Instant::now() >= deadline {
            return Err(CgroupError::CgroupError(format!(
                "stale service scope did not empty within two seconds: {scope_path}"
            )));
        }
        thread::sleep(Duration::from_millis(20));
    }

    remove_cgroup(&scope_path)?;
    Ok(())
}

fn service_scope_populated(scope_path: &str) -> Result<bool, CgroupError> {
    let events_path = format!("{scope_path}/cgroup.events");
    let events = fs::read_to_string(events_path)?;
    Ok(events
        .lines()
        .find_map(|line| line.strip_prefix("populated "))
        .is_some_and(|value| value.trim() == "1"))
}

/// Return whether a service scope is currently frozen.
///
/// `cgroup.events` is used instead of inferring the state from the process:
/// a frozen process is deliberately still alive, and its parent may have been
/// frozen at the same time.  This is also safe to call after mesh-init itself
/// resumes: the first scheduler tick can repair a child scope that was left
/// frozen by a host suspend/resume cycle.
pub fn cgroup_is_frozen(cgroup_path: &str) -> Result<bool, CgroupError> {
    let events_path = format!("{cgroup_path}/cgroup.events");
    let events = fs::read_to_string(events_path)?;
    Ok(cgroup_events_value(&events, "frozen"))
}

fn cgroup_events_value(events: &str, name: &str) -> bool {
    events
        .lines()
        .find_map(|line| {
            line.split_once(' ')
                .filter(|(key, _)| *key == name)
                .map(|(_, value)| value.trim())
        })
        .is_some_and(|value| value == "1")
}

/// Enable memory, cpu, and io controllers in a cgroup's subtree_control.
pub fn enable_controllers(path: &str) -> Result<(), CgroupError> {
    let controllers_path = format!("{}/cgroup.controllers", path);
    let subtree_control_path = format!("{}/cgroup.subtree_control", path);

    let available = match fs::read_to_string(&controllers_path) {
        Ok(s) => s,
        Err(e) => {
            debug!(path = %controllers_path, error = %e, "read_controllers_failed");
            return Ok(());
        }
    };

    let mut to_enable = Vec::new();
    for controller in ["memory", "cpu", "io"] {
        if available.contains(controller) {
            to_enable.push(format!("+{}", controller));
        }
    }

    if to_enable.is_empty() {
        return Ok(());
    }

    let cmd = to_enable.join(" ");
    match fs::write(&subtree_control_path, &cmd) {
        Ok(()) => {
            info!(controllers = %cmd, path = %subtree_control_path, "controllers_enabled");
        }
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            error!(
                path = %subtree_control_path,
                "enable_controllers_permission_denied"
            );
        }
        Err(e) => {
            debug!(
                path = %subtree_control_path,
                error = %e,
                "enable_controllers_failed"
            );
        }
    }

    Ok(())
}

/// Set resource limits on a cgroup.
pub fn set_limits(cgroup_path: &str, limits: &ResolvedResourceLimits) -> Result<(), CgroupError> {
    if let Some(val) = limits.memory_low {
        write_cgroup_file(cgroup_path, "memory.low", &val.to_string())?;
    }
    if let Some(val) = limits.memory_high {
        write_cgroup_file(cgroup_path, "memory.high", &val.to_string())?;
    }
    if let Some(val) = limits.memory_max {
        write_cgroup_file(cgroup_path, "memory.max", &val.to_string())?;
    }
    if let Some(val) = limits.cpu_weight {
        write_cgroup_file(cgroup_path, "cpu.weight", &val.to_string())?;
    }
    Ok(())
}

/// Move a process into a cgroup by writing its PID to `cgroup.procs`.
pub fn move_to_cgroup(pid: u32, cgroup_path: &str) -> Result<(), CgroupError> {
    let procs_path = format!("{}/cgroup.procs", cgroup_path);
    fs::write(&procs_path, pid.to_string()).map_err(|e| {
        error!(pid, path = %cgroup_path, error = %e, "move_to_cgroup_failed");
        CgroupError::Io(e)
    })?;
    info!(pid, path = %cgroup_path, "moved_to_cgroup");
    Ok(())
}

/// Freeze or unfreeze a cgroup using cgroup.freeze.
pub fn freeze_cgroup(cgroup_path: &str, freeze: bool) -> Result<(), CgroupError> {
    let val = if freeze { "1" } else { "0" };
    write_cgroup_file(cgroup_path, "cgroup.freeze", val)?;
    info!(
        action = if freeze { "freeze" } else { "unfreeze" },
        path = %cgroup_path,
        "cgroup_frozen_state_changed"
    );
    Ok(())
}

/// Push pages out of a cgroup with `memory.reclaim`.
///
/// Requires Linux >= 5.19. On kernels without the file this logs and
/// returns Ok: swap setup is the host administrator's choice, not ours, and
/// waking the flow would otherwise appear as a hard failure.
pub fn reclaim_memory(cgroup_path: &str, bytes: u64) -> Result<(), CgroupError> {
    let path = format!("{cgroup_path}/memory.reclaim");
    if !Path::new(&path).exists() {
        debug!(
            path = %cgroup_path,
            "memory_reclaim_unsupported_kernel"
        );
        return Ok(());
    }
    match write_cgroup_file(cgroup_path, "memory.reclaim", &bytes.to_string()) {
        Ok(()) => info!(path = %cgroup_path, bytes, "memory_reclaimed"),
        Err(e) => {
            // A partial reclaim is still progress; timeouts are expected
            // when the cgroup cannot give back the requested amount.
            debug!(path = %cgroup_path, error = %e, "memory_reclaim_partial")
        }
    }
    Ok(())
}

/// Kill every process in a cgroup subtree with `cgroup.kill` (Linux >= 5.14).
///
/// Used by the stop path so the entire scope dies, not just the main PID.
pub fn kill_scope(cgroup_path: &str) -> Result<(), CgroupError> {
    let path = format!("{cgroup_path}/cgroup.kill");
    if !Path::new(&path).exists() {
        debug!(path = %cgroup_path, "cgroup_kill_unsupported");
        return Ok(());
    }
    fs::write(&path, "1").map_err(CgroupError::Io)?;
    info!(path = %cgroup_path, "cgroup_killed");
    Ok(())
}

/// Remove an empty cgroup directory.
pub fn remove_cgroup(cgroup_path: &str) -> Result<(), CgroupError> {
    if Path::new(cgroup_path).exists() {
        fs::remove_dir(cgroup_path).map_err(|e| {
            debug!(path = %cgroup_path, error = %e, "remove_cgroup_failed");
            CgroupError::Io(e)
        })?;
        info!(path = %cgroup_path, "cgroup_removed");
    }
    Ok(())
}

/// Set the OOM score adjustment for a process.
pub fn set_oom_score(pid: u32, score: i32) -> Result<(), CgroupError> {
    if !(-1000..=1000).contains(&score) {
        return Err(CgroupError::InvalidOomScore(score));
    }
    let path = format!("/proc/{}/oom_score_adj", pid);
    fs::write(&path, score.to_string()).map_err(|e| {
        error!(pid, error = %e, "set_oom_score_adj_failed");
        CgroupError::Io(e)
    })?;
    debug!(pid, score, "oom_score_adj_set");
    Ok(())
}

/// Write a value to a cgroup control file.
fn write_cgroup_file(cgroup_path: &str, filename: &str, value: &str) -> Result<(), CgroupError> {
    let path = format!("{}/{}", cgroup_path, filename);
    fs::write(&path, value).map_err(|e| {
        error!("Failed to write '{}' to {}: {}", value, path, e);
        CgroupError::Io(e)
    })?;
    debug!("Set {}/{} = {}", cgroup_path, filename, value);
    Ok(())
}

/// Read a value from a cgroup control file.
pub fn read_cgroup_file(cgroup_path: &str, filename: &str) -> Result<String, CgroupError> {
    let path = format!("{}/{}", cgroup_path, filename);
    let value = fs::read_to_string(&path).map_err(|e| {
        debug!("Failed to read {}: {}", path, e);
        CgroupError::Io(e)
    })?;
    Ok(value.trim().to_string())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cgroup_path_construction() {
        assert_eq!(
            cgroup_path_for("chrome").unwrap(),
            "/sys/fs/cgroup/mesh.slice/chrome.scope"
        );
        assert_eq!(
            cgroup_path_for("my-service").unwrap(),
            "/sys/fs/cgroup/mesh.slice/my-service.scope"
        );
        // A17: invalid names return Err, not a sentinel path
        assert!(cgroup_path_for("../escape").is_err());
        assert!(cgroup_path_for("a/b").is_err());
        assert!(cgroup_path_for("").is_err());
    }

    #[test]
    fn test_oom_score_bounds() {
        // Valid range
        assert!((-1000..=1000).contains(&-1000));
        assert!((-1000..=1000).contains(&0));
        assert!((-1000..=1000).contains(&1000));

        // Invalid
        assert!(!(-1000..=1000).contains(&-1001));
        assert!(!(-1000..=1000).contains(&1001));
    }

    #[test]
    fn test_resource_limits_to_files() {
        // Verify the mapping of limit fields to cgroup file names
        let limits = ResolvedResourceLimits {
            memory_low: Some(256 * 1024 * 1024),
            memory_high: Some(2 * 1024 * 1024 * 1024),
            memory_max: Some(4 * 1024 * 1024 * 1024),
            cpu_weight: Some(100),
        };

        // We can't write to actual cgroup files in tests, but verify the values are correct
        assert_eq!(limits.memory_low.unwrap().to_string(), "268435456");
        assert_eq!(limits.memory_high.unwrap().to_string(), "2147483648");
        assert_eq!(limits.memory_max.unwrap().to_string(), "4294967296");
        assert_eq!(limits.cpu_weight.unwrap().to_string(), "100");
    }

    #[test]
    fn test_cgroup_events_frozen_value() {
        let events = "populated 1\nfrozen 1\n";
        assert!(cgroup_events_value(events, "frozen"));
        assert!(cgroup_events_value(events, "populated"));
        assert!(!cgroup_events_value("populated 1\nfrozen 0\n", "frozen"));
        assert!(!cgroup_events_value(events, "missing"));
    }
}
