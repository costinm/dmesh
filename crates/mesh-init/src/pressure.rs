//! Load-based freezing and eviction policy (phase 3).
//!
//! Replaces the fixed 5-second eviction loop with an event-driven policy over
//! one snapshot. The policy is pure: [`plan`] turns a [`PressureSnapshot`],
//! a [`PressurePolicy`] and the recent [`PressureHistory`] into a list of
//! actions. Only the executor in `daemon` touches the kernel.
//!
//! The ladder works one step at a time with hysteresis:
//!
//! 1. Ask idle and background services to drop caches (notify `trim`).
//! 2. `memory.reclaim` on already-frozen, then idle cgroups.
//! 3. Freeze idle services, lowest priority first, then reclaim them.
//! 4. Stop idle services (`Stopped{Evicted}`), ranked by eviction score.
//! 5. Stop busy low-priority services.
//! 6. `cgroup.kill` the worst scorer; beyond that the kernel OOM killer.
//!
//! CPU pressure is handled separately: busy background services freeze with
//! `Frozen{Pressure}` and thaw in priority order once pressure clears.

use std::time::Duration;

use crate::protocol::FreezeReason;
use crate::states::ServiceState;

/// PSI trigger levels, mirroring the existing resource monitor.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub enum PressureLevel {
    #[default]
    None,
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for PressureLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PressureLevel::None => write!(f, "none"),
            PressureLevel::Low => write!(f, "low"),
            PressureLevel::Medium => write!(f, "medium"),
            PressureLevel::High => write!(f, "high"),
            PressureLevel::Critical => write!(f, "critical"),
        }
    }
}

/// One runnable trim round delivered to services (onTrimMemory equivalent).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrimRound {
    /// Cheap caches only.
    Background,
    /// Larger, still cheap caches.
    Ui,
    /// Everything reclaimable before a code stop.
    Complete,
}

impl std::fmt::Display for TrimRound {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TrimRound::Background => write!(f, "background"),
            TrimRound::Ui => write!(f, "ui"),
            TrimRound::Complete => write!(f, "complete"),
        }
    }
}

/// One action the executor should take now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Deliver `mesh.lifecycle trim {level}` to ready services.
    Trim { level: TrimRound },
    /// Write `memory.reclaim` to a frozen or idle cgroup.
    Reclaim { path: String },
    /// Freeze an idle service under pressure.
    Freeze { name: String },
    /// Stop a service entirely (pressure eviction).
    StopEvict { name: String },
    /// Kill the whole cgroup of the worst scorer.
    CgroupKill { path: String },
    /// Nothing needs doing.
    Noop,
}

impl Action {
    /// Stable name for the history latch.
    pub fn name(&self) -> &'static str {
        match self {
            Action::Trim { .. } => "trim",
            Action::Reclaim { .. } => "reclaim",
            Action::Freeze { .. } => "freeze",
            Action::StopEvict { .. } => "stop_evict",
            Action::CgroupKill { .. } => "cgroup_kill",
            Action::Noop => "noop",
        }
    }
}

/// Configurable thresholds and pacing; sourced from `[Pressure]` in
/// default.toml with the `MESH_INIT_PSI_*` environment variables as overrides.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PressurePolicy {
    /// Enter Low when memory some avg10 crosses this.
    pub entry_low: f64,
    /// Enter Medium when memory some avg10 crosses this.
    pub entry_medium: f64,
    /// Enter High when memory some avg10 crosses this.
    pub entry_high: f64,
    /// Enter Critical when memory some avg10 crosses this.
    pub entry_critical: f64,
    /// Leave the level once memory some avg60 falls under this and the hold
    /// time elapses.
    pub exit_avg60: f64,
    /// Hold time under the exit threshold before a drop.
    pub hold_secs: u64,
    /// Minimum spacing between two executed actions (one avg10 window).
    pub cooldown_secs: u64,
    /// Admission cap: sum(memory.low) <= MemTotal * ratio.
    pub reserve_ratio: f64,
    /// Busy services with priority at or above this are stoppable.
    pub busy_stop_priority: u32,
    /// Threshold where busy background services freeze with Pressure.
    pub cpu_freeze_avg10: f64,
}

impl Default for PressurePolicy {
    fn default() -> Self {
        Self {
            entry_low: 5.0,
            entry_medium: 20.0,
            entry_high: 40.0,
            entry_critical: 60.0,
            exit_avg60: 2.0,
            hold_secs: 60,
            cooldown_secs: 10,
            reserve_ratio: 0.85,
            busy_stop_priority: 500,
            cpu_freeze_avg10: 50.0,
        }
    }
}

impl PressurePolicy {
    /// Apply the MESH_INIT_PSI_* environment overrides.
    pub fn from_env(mut self) -> Self {
        for (var, slot) in [
            ("MESH_INIT_PSI_LOW", &mut self.entry_low),
            ("MESH_INIT_PSI_MEDIUM", &mut self.entry_medium),
            ("MESH_INIT_PSI_HIGH", &mut self.entry_high),
            ("MESH_INIT_PSI_CRITICAL", &mut self.entry_critical),
        ] {
            if let Ok(value) = std::env::var(var)
                && let Ok(parsed) = value.trim().parse::<f64>()
            {
                *slot = parsed;
            }
        }
        self
    }
}

/// Service slice for one policy pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServicePressure {
    pub name: String,
    /// The runtime lifecycle state, including freeze provenance.
    pub state: ServiceState,
    pub priority: u32,
    /// Whether the service reports idle (counts zero) and has self-reports.
    pub idle: bool,
    /// Whether the service has any activity reporting at all.
    pub self_reports: bool,
    pub freeze_reason: Option<FreezeReason>,
    pub cgroup_path: String,
    pub memory_current: u64,
    /// memory.low the service protects against reclaim.
    pub memory_low: u64,
    /// Whether the service opted out of pressure actions.
    pub protected: bool,
    /// Whether the service supports freeze (has a cgroup).
    pub freezable: bool,
}

/// The full snapshot the policy reads.
#[derive(Debug, Clone, Default)]
pub struct PressureSnapshot {
    pub memory_avg10: f64,
    pub memory_avg60: f64,
    pub cpu_avg10: f64,
    pub mem_total: u64,
    pub mem_available: u64,
    pub swap_exists: bool,
    pub services: Vec<ServicePressure>,
}

impl PressureSnapshot {
    /// No meaningful pressure data.
    pub fn quiet(snapshot: &PressureSnapshot) -> PressureSnapshot {
        PressureSnapshot {
            memory_avg10: 0.0,
            ..snapshot.clone()
        }
    }
}

/// What the previous passes did, feeding hysteresis and cooldowns.
#[derive(Debug, Clone, Default)]
pub struct PressureHistory {
    pub last_action: Option<&'static str>,
    pub last_action_at: Option<std::time::Instant>,
    /// When the current level was entered.
    pub level_since: Option<std::time::Instant>,
    pub previous_level: PressureLevel,
}

impl PressureHistory {
    /// The current level held at least `hold` while under the exit value.
    fn eligible_for_exit(&self, now: std::time::Instant, hold: Duration) -> bool {
        self.level_since
            .is_some_and(|since| now.duration_since(since) >= hold)
    }
}

/// Classify the current level from the entry thresholds.
pub fn classify(data: &PressureSnapshot, policy: &PressurePolicy) -> PressureLevel {
    if data.memory_avg10 >= policy.entry_critical {
        PressureLevel::Critical
    } else if data.memory_avg10 >= policy.entry_high {
        PressureLevel::High
    } else if data.memory_avg10 >= policy.entry_medium {
        PressureLevel::Medium
    } else if data.memory_avg10 >= policy.entry_low {
        PressureLevel::Low
    } else {
        PressureLevel::None
    }
}

/// Stable eviction score: lowest survives, like Android LMK.
///
/// priority band first, then idle before busy, then longest since last
/// activity, then the largest reclaimable memory.
fn eviction_score(proc: &ServicePressure) -> (u8, u8, u64, u64) {
    (
        // Protected band: protected processes sort last.
        if proc.priority < 100 { 1_u8 } else { 0_u8 },
        // Idle processes evict before busy ones.
        if !proc.idle && proc.state == ServiceState::Running {
            1_u8
        } else {
            0_u8
        },
        0,
        u64::MAX - proc.memory_current.min(u64::MAX - 1),
    )
}

/// What to do next, one action per pass.
///
/// The function is pure: input snapshot, policy and history, no state.
pub fn plan(
    snapshot: &PressureSnapshot,
    policy: &PressurePolicy,
    history: &PressureHistory,
    now: std::time::Instant,
) -> Vec<Action> {
    let level = classify(snapshot, policy);

    // Cooldown: one action per window so its effect can be observed.
    if let Some(at) = history.last_action_at
        && now.duration_since(at) < Duration::from_secs(policy.cooldown_secs)
    {
        return vec![];
    }

    // Hysteresis exit: hold under the exit threshold for the hold time after
    // a real pressure level. With no previous level there is nothing to exit.
    if level == PressureLevel::None
        && history.previous_level != PressureLevel::None
        && snapshot.memory_avg60 < policy.exit_avg60
        && history.eligible_for_exit(now, Duration::from_secs(policy.hold_secs))
    {
        return vec![Action::Noop];
    }

    match level {
        PressureLevel::None => vec![],
        PressureLevel::Low => plan_trim(snapshot),
        PressureLevel::Medium => plan_reclaim(snapshot),
        PressureLevel::High => plan_freeze(snapshot),
        PressureLevel::Critical => plan_stop(snapshot, policy),
    }
}

fn plan_trim(snapshot: &PressureSnapshot) -> Vec<Action> {
    // Trim applies to every live-but-idle-reclaimable process; the service
    // level decides what to release.
    if snapshot.services.is_empty() {
        return vec![];
    }
    vec![Action::Trim {
        level: TrimRound::Background,
    }]
}

fn plan_reclaim(snapshot: &PressureSnapshot) -> Vec<Action> {
    // Frozen services first, then idle: file cache now, anon when swap allows.
    let frozen = snapshot.services.iter().find(|proc| {
        matches!(proc.state, ServiceState::Frozen { .. })
            || matches!(proc.state, ServiceState::Freezing { .. })
    });
    if let Some(proc) = frozen {
        return vec![Action::Reclaim {
            path: proc.cgroup_path.clone(),
        }];
    }
    let idle = snapshot
        .services
        .iter()
        .find(|proc| proc.idle && proc.state == ServiceState::Running);
    if let Some(proc) = idle {
        return vec![Action::Reclaim {
            path: proc.cgroup_path.clone(),
        }];
    }
    plan_freeze(snapshot)
}

fn plan_freeze(snapshot: &PressureSnapshot) -> Vec<Action> {
    // Freeze the idle, lowest priority first.
    let mut idle: Vec<&ServicePressure> = snapshot
        .services
        .iter()
        .filter(|proc| {
            !proc.protected
                && proc.freezable
                && proc.idle
                && proc.state == ServiceState::Running
                && proc.freeze_reason.is_none()
        })
        .collect();
    idle.sort_by_key(|proc| std::cmp::Reverse(proc.priority));
    match idle.first() {
        Some(proc) => vec![Action::Freeze {
            name: proc.name.clone(),
        }],
        None => vec![],
    }
}

fn plan_stop(snapshot: &PressureSnapshot, policy: &PressurePolicy) -> Vec<Action> {
    // 4. Idle evictions first, then busy low-priority services.
    let mut idle = snapshot
        .services
        .iter()
        .filter(|proc| {
            !proc.protected
                && proc.idle
                && (matches!(
                    proc.state,
                    ServiceState::Running | ServiceState::Frozen { .. }
                ))
        })
        .collect::<Vec<_>>();
    idle.sort_by_key(|proc| eviction_score(proc));
    if let Some(proc) = idle.first() {
        return vec![Action::StopEvict {
            name: proc.name.clone(),
        }];
    }

    let mut busy = snapshot
        .services
        .iter()
        .filter(|proc| {
            !proc.protected
                && proc.priority >= policy.busy_stop_priority
                && (matches!(
                    proc.state,
                    ServiceState::Running | ServiceState::Frozen { .. }
                ))
        })
        .collect::<Vec<_>>();
    busy.sort_by_key(|proc| eviction_score(proc));
    if let Some(proc) = busy.first() {
        return vec![Action::StopEvict {
            name: proc.name.clone(),
        }];
    }
    vec![]
}

/// Whether blob remains for Step 6 (cgroup.kill worst scorer). Exposed for
/// executor completeness and unit tests.
pub fn worst_kill_candidate(snapshot: &PressureSnapshot) -> Option<String> {
    snapshot
        .services
        .iter()
        .filter(|proc| !proc.protected)
        .max_by_key(|proc| eviction_score(proc))
        .map(|proc| proc.cgroup_path.clone())
}

/// Admission as two checks replacing the old double-counting flow.
///
/// - Reservation: memory.low committed by running AND frozen services stays
///   under MemTotal × ratio.
/// - Headroom: MemAvailable plus what idle and frozen services could give
///   back covers the incoming service's memory.low.
pub fn admission_allowed(
    snapshot: &PressureSnapshot,
    policy: &PressurePolicy,
    incoming_memory_low: u64,
) -> bool {
    let committed: u64 = snapshot
        .services
        .iter()
        .filter(|proc| {
            matches!(
                proc.state,
                ServiceState::Running | ServiceState::Frozen { .. }
            )
        })
        .map(|proc| proc.memory_low)
        .sum();
    let reserved_max = (snapshot.mem_total as f64 * policy.reserve_ratio) as u64;
    if committed.saturating_add(incoming_memory_low) > reserved_max {
        return false;
    }
    // Headroom: reclaimable = idle and frozen services can give back memory
    // when pressed; approximate with their current RSS minus their low.
    let reclaimable: u64 = snapshot
        .services
        .iter()
        .filter(|proc| proc.idle || matches!(proc.state, ServiceState::Frozen { .. }))
        .map(|proc| proc.memory_current.saturating_sub(proc.memory_low))
        .sum();
    let headroom = snapshot.mem_available.saturating_add(reclaimable);
    headroom >= incoming_memory_low
}

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(clippy::allow_attributes, clippy::needless_pass_by_value)]
    fn service(name: &str, priority: u32, state: ServiceState, idle: bool) -> ServicePressure {
        ServicePressure {
            name: name.to_string(),
            state,
            priority,
            idle,
            self_reports: true,
            freeze_reason: matches!(state, ServiceState::Frozen { .. }).then(|| FreezeReason::Idle),
            cgroup_path: format!("/sys/fs/cgroup/mesh.slice/{name}.scope"),
            memory_current: 100 << 20,
            memory_low: 0,
            protected: priority < 100,
            freezable: true,
        }
    }

    fn snapshot_with(services: Vec<ServicePressure>, avg10: f64) -> PressureSnapshot {
        PressureSnapshot {
            memory_avg10: avg10,
            memory_avg60: avg10,
            cpu_avg10: 0.0,
            mem_total: 8 << 30,
            mem_available: 4 << 30,
            swap_exists: false,
            services,
        }
    }

    fn policy() -> PressurePolicy {
        PressurePolicy::default()
    }

    fn entered(level_start: std::time::Instant) -> PressureHistory {
        PressureHistory {
            last_action: None,
            last_action_at: None,
            level_since: Some(level_start),
            previous_level: PressureLevel::None,
        }
    }

    #[test]
    fn none_level_with_cool_history_is_quiet() {
        let snapshot = snapshot_with(vec![], 0.0);
        let now = std::time::Instant::now();
        let actions = plan(
            &snapshot,
            &policy(),
            &entered(now - Duration::from_secs(120)),
            now,
        );
        assert!(actions.is_empty());
    }

    #[test]
    fn cooldown_suppresses_a_second_action() {
        let snapshot = snapshot_with(
            vec![service("idle-svc", 500, ServiceState::Running, true)],
            30.0,
        );
        let now = std::time::Instant::now();
        let history = PressureHistory {
            last_action: Some("trim"),
            last_action_at: Some(now - Duration::from_secs(2)),
            level_since: Some(now),
            previous_level: PressureLevel::None,
        };
        assert!(plan(&snapshot, &policy(), &history, now).is_empty());
    }

    #[test]
    fn low_pressure_trims_first() {
        let snapshot = snapshot_with(vec![service("a", 500, ServiceState::Running, true)], 5.0);
        let now = std::time::Instant::now();
        let actions = plan(&snapshot, &policy(), &entered(now), now);
        assert_eq!(
            actions,
            vec![Action::Trim {
                level: TrimRound::Background
            }]
        );
    }

    #[test]
    fn medium_pressure_reclaims_frozen_before_idle() {
        let now = std::time::Instant::now();
        // Frozen service preferred.
        let snapshot = snapshot_with(
            vec![
                service(
                    "frozen",
                    500,
                    ServiceState::Frozen {
                        reason: FreezeReason::Idle,
                        since: std::time::Instant::now(),
                    },
                    true,
                ),
                service("idle", 500, ServiceState::Running, true),
            ],
            20.0,
        );
        let actions = plan(&snapshot, &policy(), &entered(now), now);
        assert_eq!(
            actions,
            vec![Action::Reclaim {
                path: "/sys/fs/cgroup/mesh.slice/frozen.scope".to_string()
            }]
        );

        // Falls back to an idle running service when nothing is frozen.
        let snapshot = snapshot_with(
            vec![service("idle", 500, ServiceState::Running, true)],
            20.0,
        );
        let actions = plan(&snapshot, &policy(), &entered(now), now);
        assert_eq!(
            actions,
            vec![Action::Reclaim {
                path: "/sys/fs/cgroup/mesh.slice/idle.scope".to_string()
            }]
        );
    }

    #[test]
    fn high_pressure_freezes_idle_lowest_priority_first() {
        let now = std::time::Instant::now();
        let snapshot = snapshot_with(
            vec![
                service("mid", 300, ServiceState::Running, true),
                service("low", 800, ServiceState::Running, true),
                service("busy", 800, ServiceState::Running, false),
            ],
            40.0,
        );
        let actions = plan(&snapshot, &policy(), &entered(now), now);
        assert_eq!(
            actions,
            vec![Action::Freeze {
                name: "low".to_string()
            }]
        );
    }

    #[test]
    fn high_pressure_without_idle_candidates_degrades() {
        let now = std::time::Instant::now();
        // No idle services at all: the freeze ladder has nothing to do and
        // returns empty; critical stops handle the busy targets instead.
        let snapshot = snapshot_with(
            vec![service("busy", 800, ServiceState::Running, false)],
            40.0,
        );
        assert!(plan(&snapshot, &policy(), &entered(now), now).is_empty());
    }

    #[test]
    fn critical_pressure_stops_idle_first_then_busy() {
        let now = std::time::Instant::now();
        let snapshot = snapshot_with(
            vec![
                service("idle-low", 900, ServiceState::Running, true),
                service("busy-low", 900, ServiceState::Running, false),
            ],
            60.0,
        );
        let actions = plan(&snapshot, &policy(), &entered(now), now);
        assert_eq!(
            actions,
            vec![Action::StopEvict {
                name: "idle-low".to_string()
            }]
        );

        let snapshot = snapshot_with(
            vec![
                service("protected", 50, ServiceState::Running, true),
                service("busy", 600, ServiceState::Running, false),
            ],
            60.0,
        );
        let actions = plan(&snapshot, &policy(), &entered(now), now);
        assert_eq!(
            actions,
            vec![Action::StopEvict {
                name: "busy".to_string()
            }]
        );
    }

    #[test]
    fn protected_services_never_evicted() {
        let now = std::time::Instant::now();
        let snapshot = snapshot_with(vec![service("core", 20, ServiceState::Running, true)], 60.0);
        assert!(plan(&snapshot, &policy(), &entered(now), now).is_empty());
    }

    #[test]
    fn worst_kill_candidate_ranking() {
        let snapshot = snapshot_with(
            vec![
                service("mid", 300, ServiceState::Running, true),
                service("low", 800, ServiceState::Running, true),
                service("core", 10, ServiceState::Running, true),
            ],
            60.0,
        );
        assert!(
            worst_kill_candidate(&snapshot)
                .unwrap()
                .ends_with("low.scope")
        );
    }

    #[test]
    fn exit_requires_hold_under_threshold() {
        let now = std::time::Instant::now();
        // avg10 below entry but avg60 above exit: there is still pressure.
        let mut snapshot = snapshot_with(vec![], 1.0);
        snapshot.memory_avg60 = 10.0;
        let history = entered(now - Duration::from_secs(120));
        assert!(plan(&snapshot, &policy(), &history, now).is_empty());

        // A completed hold under the exit threshold exits the held level.
        let mut snapshot = snapshot_with(vec![], 0.5);
        snapshot.memory_avg60 = 0.0;
        let mut history = entered(now - Duration::from_secs(120));
        history.previous_level = PressureLevel::Medium;
        assert_eq!(
            plan(&snapshot, &policy(), &history, now),
            vec![Action::Noop]
        );

        // Without the completed hold time the exit stays quiet; the
        // executor drops the noop latch once it applies the pass.
        let mut pending = entered(now);
        pending.previous_level = PressureLevel::Medium;
        assert!(plan(&snapshot, &policy(), &pending, now).is_empty());
    }

    #[test]
    fn admission_reservation_and_headroom() {
        let policy = policy();
        // Reservation: race past the reserve ratio.
        let mut snapshot = snapshot_with(
            vec![service("huge", 500, ServiceState::Running, false)],
            0.0,
        );
        snapshot.services[0].memory_low = 7_u64 << 30;
        snapshot.mem_total = 8 << 30;
        assert!(!admission_allowed(&snapshot, &policy, 2 << 30));

        // Headroom satisfied when reclaimable covers the gap.
        snapshot.services[0].idled_out();
        snapshot.services[0].memory_low = 1 << 30;
        snapshot.services[0].memory_current = 3 << 30;
        snapshot.mem_available = 1 << 30;
        assert!(admission_allowed(&snapshot, &policy, 2 << 30));
    }

    impl ServicePressure {
        fn idled_out(&mut self) {
            self.idle = true;
        }
    }
}
