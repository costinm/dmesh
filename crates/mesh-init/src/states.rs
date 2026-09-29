//! One state model for managed services (phase 0).
//!
//! Every change to [`crate::process::ManagedProcess`] lifecycle state flows
//! through [`transition`]. Events come from the control API, socket
//! activation, child exit, idle notices, the pressure policy, and timers. The
//! function runs under the service lock; and never calls the kernel. The
//! returned [`Effect`]s run after the lock is released.

use std::time::Instant;

pub use crate::protocol::{FreezeReason, StopReason};

/// Enhanced runtime lifecycle state for a managed service.
///
/// Unlike [`crate::protocol::ServiceState`] (the wire serialization), this
/// keeps the freeze epoch, freeze reason and stop deadline in the state
/// itself so a transition can make decisions from provenance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceState {
    /// Not running. `stop_reason` is authoritative for why.
    Stopped,
    /// Spawn is in progress. Guarded so double-spawn cannot happen.
    Starting,
    Running,
    /// Waiting for the app's reply to `prepare_freeze`.
    Freezing {
        epoch: u64,
    },
    /// Cgroup confirmed frozen.
    Frozen {
        reason: FreezeReason,
        since: Instant,
    },
    /// Child was signalled and the scheduler waits for exit.
    Stopping {
        since: Instant,
    },
}

impl From<ServiceState> for crate::protocol::ServiceState {
    fn from(state: ServiceState) -> Self {
        match state {
            ServiceState::Stopped => Self::Stopped,
            ServiceState::Starting => Self::Starting,
            ServiceState::Running => Self::Running,
            // A pending freeze is still a running service as far as any
            // client of the status protocol is concerned.
            ServiceState::Freezing { .. } => Self::Running,
            ServiceState::Frozen { .. } => Self::Frozen,
            ServiceState::Stopping { .. } => Self::Stopping,
        }
    }
}

impl std::fmt::Display for ServiceState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServiceState::Stopped | ServiceState::Starting | ServiceState::Running => {
                write!(f, "{}", crate::protocol::ServiceState::from(*self))
            }
            ServiceState::Freezing { .. } => write!(f, "freezing"),
            ServiceState::Frozen { .. } => write!(f, "frozen"),
            ServiceState::Stopping { .. } => write!(f, "stopping"),
        }
    }
}

impl ServiceState {
    /// Whether a live child exists in this state.
    pub fn is_alive(&self) -> bool {
        matches!(
            self,
            ServiceState::Starting
                | ServiceState::Running
                | ServiceState::Freezing { .. }
                | ServiceState::Frozen { .. }
                | ServiceState::Stopping { .. }
        )
    }
}

/// Why a stop is being requested. Mapped into `stop_reason` when the child
/// finally exits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopInitiator {
    /// A control request, watchdog, or host shutdown.
    Requested,
    /// IdleTerminationSec elapsed.
    Idle,
    /// The pressure policy stopped the service to free memory (eviction).
    Evicted,
}

impl StopInitiator {
    fn stop_reason(self) -> StopReason {
        match self {
            StopInitiator::Requested => StopReason::Requested,
            StopInitiator::Idle => StopReason::Idle,
            StopInitiator::Evicted => StopReason::Evicted,
        }
    }
}

/// Why a frozen service is being thawed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnfreezeCause {
    /// The user explicitly unfroze the service.
    Requested,
    /// A connection or request arrived.
    Activity,
    /// Pressure cleared; the policy thawed the service.
    PressureCleared,
}

/// Events the state model accepts.
#[derive(Debug)]
pub enum LifecycleEvent {
    /// A start request or activation decided the service must be running.
    StartRequested,
    /// The spawn actually forked/execed a child.
    Spawned,
    /// The spawn or sidecar start failed before a child existed.
    SpawnFailed,
    /// SIGCHLD: the child exited; `intentional` means target was Stopped.
    Exited { intentional: bool },
    /// A control or policy stop request.
    StopRequested { initiator: StopInitiator },
    /// A control freeze request; `epoch` orders concurrent freeze attempts.
    Freeze { reason: FreezeReason, epoch: u64 },
    /// The kernel confirmed `cgroup.events frozen 1`.
    FrozenConfirmed,
    /// A control unfreeze request or an activity/pressure wake.
    Unfreeze { cause: UnfreezeCause },
    /// A freeze attempt was cancelled before the cgroup was frozen, or the
    /// freeze handshake failed/timed out.
    FreezeCancelled,
    /// The scheduler found a Stopping service still alive past its grace.
    Escalate,
}

/// Queued side effects produced by a transition. They run after the lock is
/// released so kernel calls never hold the service mutex.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Effect {
    /// Write cgroup.freeze=1 and await confirmation.
    FreezeCgroup,
    /// Write cgroup.freeze=0.
    UnfreezeCgroup,
    /// Send a signal to the live child.
    Signal(i32),
    /// The whole cgroup must die: `cgroup.kill`.
    KillCgroup,
}

impl Effect {
    /// Whether the effect requires a live process.
    pub fn needs_pid(&self) -> bool {
        matches!(self, Effect::Signal(_) | Effect::KillCgroup)
    }
}

/// Freeze epoch counter used by callers to order freeze attempts.
pub fn next_epoch(current: Option<u64>) -> u64 {
    current.unwrap_or(0).saturating_add(1)
}

/// Rollback helper: transition the process back through `FreezeCancelled`.
///
/// Whether the service was pending a freeze; used by the executor after a
/// failed handshake.
pub fn is_freezing(proc: &crate::process::ManagedProcess) -> bool {
    matches!(proc.state, ServiceState::Freezing { .. })
}

/// Apply one event to the lifecycle state of a managed process.
///
/// This is the only function that assigns `state`. It never touches the
/// kernel and never blocks.
pub fn transition(proc: &mut crate::process::ManagedProcess, event: LifecycleEvent) -> Vec<Effect> {
    match event {
        LifecycleEvent::StartRequested => {
            if proc.state == ServiceState::Stopped {
                proc.stop_reason = None;
                proc.state = ServiceState::Starting;
            }
            vec![]
        }
        LifecycleEvent::Spawned => {
            proc.state = ServiceState::Running;
            proc.target_state = ServiceState::Running;
            proc.ready = proc.config.ready_match.is_none();
            vec![]
        }
        LifecycleEvent::SpawnFailed => {
            proc.state = ServiceState::Stopped;
            proc.pid = None;
            proc.pidfd = None;
            vec![]
        }
        LifecycleEvent::Exited { intentional } => {
            let stop_reason = if intentional {
                proc.stop_reason.unwrap_or(StopReason::Requested)
            } else {
                StopReason::Exited
            };
            proc.state = ServiceState::Stopped;
            proc.pid = None;
            proc.pidfd = None;
            proc.stop_reason = Some(stop_reason);
            vec![]
        }
        LifecycleEvent::StopRequested { initiator } => {
            proc.stop_reason = Some(initiator.stop_reason());
            match proc.state {
                ServiceState::Stopped | ServiceState::Starting => {
                    if matches!(initiator, StopInitiator::Requested) {
                        proc.target_state = ServiceState::Stopped;
                    }
                    vec![]
                }
                ServiceState::Running
                | ServiceState::Frozen { .. }
                | ServiceState::Freezing { .. } => {
                    proc.target_state = ServiceState::Stopped;
                    proc.state = ServiceState::Stopping {
                        since: Instant::now(),
                    };
                    vec![Effect::Signal(libc::SIGTERM)]
                }
                ServiceState::Stopping { .. } => vec![],
            }
        }
        LifecycleEvent::Escalate => {
            if matches!(proc.state, ServiceState::Stopping { .. }) && proc.pid.is_some() {
                vec![Effect::Signal(libc::SIGKILL)]
            } else {
                vec![]
            }
        }
        LifecycleEvent::Freeze { reason, epoch } => match proc.state {
            // A freeze on a service without a cgroup is refused by the caller;
            // no SIGSTOP fallback here either.
            ServiceState::Running if proc.cgroup_path.is_some() => {
                proc.state = ServiceState::Freezing { epoch };
                proc.freeze_reason = Some(reason);
                proc.explicit_freeze = reason == FreezeReason::User;
                vec![]
            }
            ServiceState::Freezing { epoch: current } if epoch >= current => {
                proc.state = ServiceState::Freezing { epoch };
                proc.freeze_reason = Some(reason);
                proc.explicit_freeze = reason == FreezeReason::User;
                vec![]
            }
            _ => vec![],
        },
        LifecycleEvent::FrozenConfirmed => match (proc.state, proc.freeze_reason) {
            (ServiceState::Freezing { epoch }, Some(reason)) => {
                proc.state = ServiceState::Frozen {
                    reason,
                    since: Instant::now(),
                };
                let _ = epoch;
                vec![]
            }
            _ => vec![Effect::UnfreezeCgroup],
        },
        LifecycleEvent::Unfreeze { cause } => {
            let explicit =
                proc.explicit_freeze && !matches!(proc.state, ServiceState::Stopping { .. });
            let may_thaw = !explicit || cause == UnfreezeCause::Requested;
            match proc.state {
                ServiceState::Frozen { .. } if may_thaw => {
                    proc.state = ServiceState::Running;
                    proc.freeze_reason = None;
                    if cause == UnfreezeCause::Requested {
                        proc.explicit_freeze = false;
                    }
                    vec![Effect::UnfreezeCgroup]
                }
                // A pending freeze is cancelled in-state: the cgroup was never
                // frozen, so no kernel write is needed.
                ServiceState::Freezing { .. } if may_thaw => {
                    proc.state = ServiceState::Running;
                    proc.freeze_reason = None;
                    if cause == UnfreezeCause::Requested {
                        proc.explicit_freeze = false;
                    }
                    vec![]
                }
                _ => vec![],
            }
        }
        LifecycleEvent::FreezeCancelled => {
            if let ServiceState::Freezing { .. } = proc.state {
                proc.state = ServiceState::Running;
                proc.freeze_reason = None;
            }
            vec![]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AppConfig;

    fn proc() -> crate::process::ManagedProcess {
        crate::process::ManagedProcess::new(AppConfig::default())
    }

    fn running() -> crate::process::ManagedProcess {
        let mut p = proc();
        p.state = ServiceState::Running;
        p.target_state = ServiceState::Running;
        p.pid = Some(42);
        p.cgroup_path = Some("/sys/fs/cgroup/mesh.slice/demo.scope".to_string());
        p
    }

    fn frozen(reason: FreezeReason) -> crate::process::ManagedProcess {
        let mut p = proc();
        p.state = ServiceState::Frozen {
            reason,
            since: Instant::now(),
        };
        p.freeze_reason = Some(reason);
        p.explicit_freeze = reason == FreezeReason::User;
        p.target_state = ServiceState::Running;
        p.pid = Some(42);
        p.cgroup_path = Some("/sys/fs/cgroup/mesh.slice/demo.scope".to_string());
        p
    }

    #[test]
    fn start_requested_moves_stopped_to_starting() {
        let mut p = proc();
        let effects = transition(&mut p, LifecycleEvent::StartRequested);
        assert_eq!(p.state, ServiceState::Starting);
        assert!(effects.is_empty());
    }

    #[test]
    fn start_requested_ignored_when_not_stopped() {
        let mut p = running();
        transition(&mut p, LifecycleEvent::StartRequested);
        assert_eq!(p.state, ServiceState::Running);
    }

    #[test]
    fn spawned_sets_running_and_reads_ready_flag() {
        let mut p = proc();
        p.config.ready_match = Some("ready".to_string());
        transition(&mut p, LifecycleEvent::Spawned);
        assert_eq!(p.state, ServiceState::Running);
        assert!(!p.ready);
    }

    #[test]
    fn spawn_failed_returns_stopped_without_pid() {
        let mut p = proc();
        p.pid = Some(1);
        transition(&mut p, LifecycleEvent::SpawnFailed);
        assert_eq!(p.state, ServiceState::Stopped);
        assert!(p.pid.is_none());
    }

    #[test]
    fn exit_records_requested_stop_reason_when_intentional() {
        let mut p = proc();
        p.stop_reason = Some(StopReason::Idle);
        transition(&mut p, LifecycleEvent::Exited { intentional: true });
        assert_eq!(p.state, ServiceState::Stopped);
        assert_eq!(p.stop_reason, Some(StopReason::Idle));
    }

    #[test]
    fn exit_records_exited_stop_reason_when_unintentional() {
        let mut p = proc();
        p.target_state = ServiceState::Running;
        transition(&mut p, LifecycleEvent::Exited { intentional: false });
        assert_eq!(p.stop_reason, Some(StopReason::Exited));
    }

    #[test]
    fn stop_requested_running_enters_stopping_with_signal_effect() {
        let mut p = running();
        let effects = transition(
            &mut p,
            LifecycleEvent::StopRequested {
                initiator: StopInitiator::Requested,
            },
        );
        assert!(matches!(p.state, ServiceState::Stopping { .. }));
        assert_eq!(p.stop_reason, Some(StopReason::Requested));
        assert_eq!(effects, vec![Effect::Signal(libc::SIGTERM)]);
    }

    #[test]
    fn stop_requested_on_frozen_thaws_and_stops() {
        let mut p = frozen(FreezeReason::Idle);
        let effects = transition(
            &mut p,
            LifecycleEvent::StopRequested {
                initiator: StopInitiator::Requested,
            },
        );
        assert!(matches!(p.state, ServiceState::Stopping { .. }));
        assert!(effects.contains(&Effect::Signal(libc::SIGTERM)));
    }

    #[test]
    fn stop_requested_on_stopped_sets_target_only() {
        let mut p = proc();
        let effects = transition(
            &mut p,
            LifecycleEvent::StopRequested {
                initiator: StopInitiator::Requested,
            },
        );
        assert!(effects.is_empty());
        assert_eq!(p.target_state, ServiceState::Stopped);
        assert_eq!(p.stop_reason, Some(StopReason::Requested));
    }

    #[test]
    fn stop_requested_evicted_keeps_restart_target_when_stopped() {
        let mut p = proc();
        p.target_state = ServiceState::Running;
        transition(
            &mut p,
            LifecycleEvent::StopRequested {
                initiator: StopInitiator::Evicted,
            },
        );
        // Eviction of a stopped service changes the reason, not the target.
        assert_eq!(p.target_state, ServiceState::Running);
        assert_eq!(p.stop_reason, Some(StopReason::Evicted));
    }

    #[test]
    fn freeze_on_running_with_cgroup_enters_freezing() {
        let mut p = running();
        let effects = transition(
            &mut p,
            LifecycleEvent::Freeze {
                reason: FreezeReason::User,
                epoch: 1,
            },
        );
        assert_eq!(p.state, ServiceState::Freezing { epoch: 1 });
        assert_eq!(p.freeze_reason, Some(FreezeReason::User));
        assert!(effects.is_empty());
    }

    #[test]
    fn freeze_without_cgroup_is_refused() {
        let mut p = running();
        p.cgroup_path = None;
        let effects = transition(
            &mut p,
            LifecycleEvent::Freeze {
                reason: FreezeReason::User,
                epoch: 1,
            },
        );
        assert_eq!(p.state, ServiceState::Running);
        assert!(effects.is_empty());
    }

    #[test]
    fn frozen_confirmed_promotes_freezing() {
        let mut p = running();
        transition(
            &mut p,
            LifecycleEvent::Freeze {
                reason: FreezeReason::Idle,
                epoch: 3,
            },
        );
        transition(&mut p, LifecycleEvent::FrozenConfirmed);
        assert!(matches!(p.state, ServiceState::Frozen { .. }));
        assert_eq!(p.freeze_reason, Some(FreezeReason::Idle));
    }

    #[test]
    fn frozen_confirmed_on_unexpected_state_unfreezes() {
        // Contradictory confirmation: the executor should write freeze=0.
        let mut p = running();
        let effects = transition(&mut p, LifecycleEvent::FrozenConfirmed);
        assert_eq!(effects, vec![Effect::UnfreezeCgroup]);
    }

    #[test]
    fn unfreeze_reads_explicit_flag() {
        // Idle-frozen: activity thaws.
        let mut p = frozen(FreezeReason::Idle);
        let effects = transition(
            &mut p,
            LifecycleEvent::Unfreeze {
                cause: UnfreezeCause::Activity,
            },
        );
        assert_eq!(p.state, ServiceState::Running);
        assert!(effects.contains(&Effect::UnfreezeCgroup));

        // User-frozen: activity must NOT thaw.
        let mut p2 = frozen(FreezeReason::User);
        let effects2 = transition(
            &mut p2,
            LifecycleEvent::Unfreeze {
                cause: UnfreezeCause::Activity,
            },
        );
        assert!(matches!(p2.state, ServiceState::Frozen { .. }));
        assert!(effects2.is_empty());

        // User request always thaws.
        let effects3 = transition(
            &mut p2,
            LifecycleEvent::Unfreeze {
                cause: UnfreezeCause::Requested,
            },
        );
        assert_eq!(p2.state, ServiceState::Running);
        assert!(effects3.contains(&Effect::UnfreezeCgroup));
    }

    #[test]
    fn unfreeze_cancels_pending_freeze() {
        let mut p = running();
        transition(
            &mut p,
            LifecycleEvent::Freeze {
                reason: FreezeReason::Idle,
                epoch: 1,
            },
        );
        let effects = transition(
            &mut p,
            LifecycleEvent::Unfreeze {
                cause: UnfreezeCause::Activity,
            },
        );
        assert_eq!(p.state, ServiceState::Running);
        assert!(
            effects.is_empty(),
            "cancel is pure state, no kernel write yet"
        );
    }

    #[test]
    fn freeze_cancelled_returns_running() {
        let mut p = running();
        transition(
            &mut p,
            LifecycleEvent::Freeze {
                reason: FreezeReason::Idle,
                epoch: 1,
            },
        );
        assert!(matches!(p.state, ServiceState::Freezing { .. }));
        transition(&mut p, LifecycleEvent::FreezeCancelled);
        assert_eq!(p.state, ServiceState::Running);
    }

    #[test]
    fn escalate_signals_only_live_stopping_services() {
        let mut p = running();
        transition(
            &mut p,
            LifecycleEvent::StopRequested {
                initiator: StopInitiator::Requested,
            },
        );
        let effects = transition(&mut p, LifecycleEvent::Escalate);
        assert_eq!(effects, vec![Effect::Signal(libc::SIGKILL)]);

        // A Stopped service gets nothing.
        let mut stopped = proc();
        let none = transition(&mut stopped, LifecycleEvent::Escalate);
        assert!(none.is_empty());
    }

    #[test]
    fn serialization_of_runtime_state_matches_protocol_names() {
        assert_eq!(
            crate::protocol::ServiceState::from(ServiceState::Freezing { epoch: 1 }),
            crate::protocol::ServiceState::Running
        );
        assert_eq!(ServiceState::Starting.to_string(), "starting");
        assert_eq!(ServiceState::Freezing { epoch: 0 }.to_string(), "freezing");
    }
}
