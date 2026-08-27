//! Portable Main-runtime state transitions and diagnostic projection.
//!
//! The one ESP runtime task owns [`MainRuntimeState`].  ESP-IDF callbacks and
//! timers must enqueue a [`MainEvent`] and return; they never mutate this
//! state.  The task reduces one event at a time, then performs the returned
//! [`MainEffect`] through platform adapters.  Keeping that decision point
//! socket-, FreeRTOS-, and ESP-independent gives host tests the same rules as
//! firmware without exposing credentials in a diagnostic response.

/// Requested physical radio personality after a complete `transport.start`.
///
/// This is intentionally a compact projection rather than `TransportProfile`:
/// a runtime snapshot must never include an SSID or passphrase.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum RequestedMode {
    Stopped = 0,
    NanNow = 1,
    Sta = 2,
    StaNanNow = 3,
    StaAp = 4,
    StaApNanNow = 5,
}

/// Confirmed lifecycle reported by an adapter completion, not inferred from a
/// requested mode.  The runtime reports `Starting`/`Stopping` while an effect
/// is outstanding so status callers cannot mistake accepted control for live
/// radio state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum RadioLifecycle {
    Stopped = 0,
    Starting = 1,
    NanNow = 2,
    Sta = 3,
    StaNanNow = 4,
    StaAp = 5,
    StaApNanNow = 6,
    Stopping = 7,
    Failed = 8,
}

impl RadioLifecycle {
    const fn from_requested(mode: RequestedMode) -> Self {
        match mode {
            RequestedMode::Stopped => Self::Stopped,
            RequestedMode::NanNow => Self::NanNow,
            RequestedMode::Sta => Self::Sta,
            RequestedMode::StaNanNow => Self::StaNanNow,
            RequestedMode::StaAp => Self::StaAp,
            RequestedMode::StaApNanNow => Self::StaApNanNow,
        }
    }
}

/// Main's power state, updated only by explicit power/sleep completions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum PowerLifecycle {
    Awake = 0,
    PreparingSleep = 1,
    LightSleeping = 2,
    Waking = 3,
    Blocked = 4,
}

/// Bounded reasons why a sleep request cannot enter light sleep yet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub struct SleepBlockers(pub u16);

impl SleepBlockers {
    pub const NONE: Self = Self(0);
    pub const RADIO_TRANSITION: Self = Self(1 << 0);
    pub const CORRELATED_RESPONSE: Self = Self(1 << 1);
    pub const RAW_SERVICE_DEADLINE: Self = Self(1 << 2);
    pub const NAN_DEADLINE: Self = Self(1 << 3);

    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

/// Input to the state owner.  Queue payloads are copyable and bounded so an
/// ESP callback can enqueue one without allocating or retaining driver data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MainEvent {
    Boot,
    /// Declare the Main-specific boot personality after NVS policy has been
    /// read. This is separate from `Boot` because the portable default is the
    /// active NAN/NOW state, while a flashed Main may begin sleepy.
    BootProfile {
        mode: RequestedMode,
        sleepy: bool,
    },
    ProfileRequested {
        mode: RequestedMode,
        sleepy: bool,
        generation: u32,
        request_id: u32,
    },
    RadioApplied {
        generation: u32,
        lifecycle: RadioLifecycle,
    },
    RadioFailed {
        generation: u32,
        error: u16,
    },
    SleepDeadline {
        generation: u32,
        blockers: SleepBlockers,
    },
    SleepEntered {
        generation: u32,
    },
    Wake {
        generation: u32,
        cause: u8,
    },
    /// Platform PM configuration observed after Main applies a boot or
    /// profile policy. This is a completion record, never a request made by
    /// a packet or Wi-Fi callback.
    PowerApplied {
        cpu_mhz: u16,
        min_mhz: u16,
        max_mhz: u16,
        automatic_light_sleep: bool,
        configured: bool,
        light_sleep_attempts: u32,
        light_sleep_entries: u32,
        light_sleep_skipped: u32,
        last_sleep_requested_us: u32,
        last_sleep_duration_us: u32,
    },
    QueueOverflow,
}

/// Bounded work the state owner asks a platform adapter to perform after a
/// state transition.  The effect is submitted once; the adapter later reports
/// success or failure as a new [`MainEvent`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MainEffect {
    None,
    ApplyRadio {
        mode: RequestedMode,
        generation: u32,
    },
    EnterLightSleep {
        generation: u32,
    },
    EmitWakeAnnouncement {
        generation: u32,
    },
}

/// Copyable, credential-free status returned by the read-only runtime handler.
#[cfg_attr(feature = "std", derive(serde::Deserialize, serde::Serialize))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MainRuntimeSnapshot {
    pub desired_mode: u8,
    pub desired_generation: u32,
    pub request_id: u32,
    pub sleepy: bool,
    pub radio_lifecycle: u8,
    pub applied_generation: u32,
    pub power_lifecycle: u8,
    pub sleep_blockers: u16,
    pub last_error: u16,
    pub stale_completion_count: u32,
    pub queue_overflow_count: u32,
    pub wake_cause: u8,
    pub cpu_mhz: u16,
    pub pm_min_mhz: u16,
    pub pm_max_mhz: u16,
    pub pm_automatic_light_sleep: bool,
    pub pm_configured: bool,
    pub light_sleep_attempts: u32,
    pub light_sleep_entries: u32,
    pub light_sleep_skipped: u32,
    pub last_sleep_requested_us: u32,
    pub last_sleep_duration_us: u32,
}

/// The complete policy state, owned by one Main task for its whole lifetime.
///
/// It is constructed during `Boot`, changed when the task dequeues an event,
/// and projected through [`Self::snapshot`] for a status request.  It carries
/// no SSID, passphrase, BSSID, or other credential-bearing profile field.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MainRuntimeState {
    desired_mode: RequestedMode,
    desired_generation: u32,
    request_id: u32,
    sleepy: bool,
    radio_lifecycle: RadioLifecycle,
    applied_generation: u32,
    power_lifecycle: PowerLifecycle,
    sleep_blockers: SleepBlockers,
    last_error: u16,
    stale_completion_count: u32,
    queue_overflow_count: u32,
    wake_cause: u8,
    cpu_mhz: u16,
    pm_min_mhz: u16,
    pm_max_mhz: u16,
    pm_automatic_light_sleep: bool,
    pm_configured: bool,
    light_sleep_attempts: u32,
    light_sleep_entries: u32,
    light_sleep_skipped: u32,
    last_sleep_requested_us: u32,
    last_sleep_duration_us: u32,
}

impl Default for MainRuntimeState {
    fn default() -> Self {
        Self {
            desired_mode: RequestedMode::NanNow,
            desired_generation: 0,
            request_id: 0,
            sleepy: false,
            radio_lifecycle: RadioLifecycle::Stopped,
            applied_generation: 0,
            power_lifecycle: PowerLifecycle::Awake,
            sleep_blockers: SleepBlockers::NONE,
            last_error: 0,
            stale_completion_count: 0,
            queue_overflow_count: 0,
            wake_cause: 0,
            cpu_mhz: 0,
            pm_min_mhz: 0,
            pm_max_mhz: 0,
            pm_automatic_light_sleep: false,
            pm_configured: false,
            light_sleep_attempts: 0,
            light_sleep_entries: 0,
            light_sleep_skipped: 0,
            last_sleep_requested_us: 0,
            last_sleep_duration_us: 0,
        }
    }
}

impl MainRuntimeState {
    /// Apply one queued event and return the one adapter operation it requires.
    /// Called only by the Main owner task after it dequeues an event; it never
    /// polls hardware or waits, so host tests can exhaustively cover ordering.
    pub fn reduce(&mut self, event: MainEvent) -> MainEffect {
        match event {
            MainEvent::Boot => MainEffect::ApplyRadio {
                mode: self.desired_mode,
                generation: self.desired_generation,
            },
            MainEvent::BootProfile { mode, sleepy } => {
                self.desired_mode = mode;
                self.sleepy = sleepy;
                self.radio_lifecycle = RadioLifecycle::Starting;
                self.power_lifecycle = PowerLifecycle::Awake;
                self.sleep_blockers = SleepBlockers::RADIO_TRANSITION;
                MainEffect::ApplyRadio {
                    mode,
                    generation: self.desired_generation,
                }
            }
            MainEvent::ProfileRequested {
                mode,
                sleepy,
                generation,
                request_id,
            } => {
                if generation <= self.desired_generation {
                    self.stale_completion_count = self.stale_completion_count.saturating_add(1);
                    return MainEffect::None;
                }
                self.desired_mode = mode;
                self.desired_generation = generation;
                self.request_id = request_id;
                self.sleepy = sleepy;
                self.radio_lifecycle = if mode == RequestedMode::Stopped {
                    RadioLifecycle::Stopping
                } else {
                    RadioLifecycle::Starting
                };
                self.power_lifecycle = PowerLifecycle::Awake;
                self.sleep_blockers = SleepBlockers::RADIO_TRANSITION;
                MainEffect::ApplyRadio { mode, generation }
            }
            MainEvent::RadioApplied {
                generation,
                lifecycle,
            } => {
                if generation != self.desired_generation {
                    self.stale_completion_count = self.stale_completion_count.saturating_add(1);
                    return MainEffect::None;
                }
                self.radio_lifecycle = lifecycle;
                self.applied_generation = generation;
                self.sleep_blockers = SleepBlockers::NONE;
                self.last_error = 0;
                MainEffect::None
            }
            MainEvent::RadioFailed { generation, error } => {
                if generation != self.desired_generation {
                    self.stale_completion_count = self.stale_completion_count.saturating_add(1);
                    return MainEffect::None;
                }
                self.radio_lifecycle = RadioLifecycle::Failed;
                self.sleep_blockers = SleepBlockers::RADIO_TRANSITION;
                self.last_error = error;
                MainEffect::None
            }
            MainEvent::SleepDeadline {
                generation,
                blockers,
            } => {
                if generation != self.desired_generation || !self.sleepy {
                    self.stale_completion_count = self.stale_completion_count.saturating_add(1);
                    return MainEffect::None;
                }
                self.sleep_blockers = blockers;
                if blockers.is_empty() {
                    self.power_lifecycle = PowerLifecycle::PreparingSleep;
                    MainEffect::EnterLightSleep { generation }
                } else {
                    self.power_lifecycle = PowerLifecycle::Blocked;
                    MainEffect::None
                }
            }
            MainEvent::SleepEntered { generation } => {
                if generation != self.desired_generation {
                    self.stale_completion_count = self.stale_completion_count.saturating_add(1);
                    return MainEffect::None;
                }
                self.power_lifecycle = PowerLifecycle::LightSleeping;
                MainEffect::None
            }
            MainEvent::Wake { generation, cause } => {
                if generation != self.desired_generation {
                    self.stale_completion_count = self.stale_completion_count.saturating_add(1);
                    return MainEffect::None;
                }
                self.power_lifecycle = PowerLifecycle::Waking;
                self.wake_cause = cause;
                MainEffect::EmitWakeAnnouncement { generation }
            }
            MainEvent::PowerApplied {
                cpu_mhz,
                min_mhz,
                max_mhz,
                automatic_light_sleep,
                configured,
                light_sleep_attempts,
                light_sleep_entries,
                light_sleep_skipped,
                last_sleep_requested_us,
                last_sleep_duration_us,
            } => {
                self.cpu_mhz = cpu_mhz;
                self.pm_min_mhz = min_mhz;
                self.pm_max_mhz = max_mhz;
                self.pm_automatic_light_sleep = automatic_light_sleep;
                self.pm_configured = configured;
                self.light_sleep_attempts = light_sleep_attempts;
                self.light_sleep_entries = light_sleep_entries;
                self.light_sleep_skipped = light_sleep_skipped;
                self.last_sleep_requested_us = last_sleep_requested_us;
                self.last_sleep_duration_us = last_sleep_duration_us;
                MainEffect::None
            }
            MainEvent::QueueOverflow => {
                self.queue_overflow_count = self.queue_overflow_count.saturating_add(1);
                MainEffect::None
            }
        }
    }

    /// Return a bounded status projection for a read-only control response.
    /// Called on demand after a status request; callers must encode this as
    /// bounded CBOR rather than build an unbounded debug string.
    pub const fn snapshot(&self) -> MainRuntimeSnapshot {
        MainRuntimeSnapshot {
            desired_mode: self.desired_mode as u8,
            desired_generation: self.desired_generation,
            request_id: self.request_id,
            sleepy: self.sleepy,
            radio_lifecycle: self.radio_lifecycle as u8,
            applied_generation: self.applied_generation,
            power_lifecycle: self.power_lifecycle as u8,
            sleep_blockers: self.sleep_blockers.0,
            last_error: self.last_error,
            stale_completion_count: self.stale_completion_count,
            queue_overflow_count: self.queue_overflow_count,
            wake_cause: self.wake_cause,
            cpu_mhz: self.cpu_mhz,
            pm_min_mhz: self.pm_min_mhz,
            pm_max_mhz: self.pm_max_mhz,
            pm_automatic_light_sleep: self.pm_automatic_light_sleep,
            pm_configured: self.pm_configured,
            light_sleep_attempts: self.light_sleep_attempts,
            light_sleep_entries: self.light_sleep_entries,
            light_sleep_skipped: self.light_sleep_skipped,
            last_sleep_requested_us: self.last_sleep_requested_us,
            last_sleep_duration_us: self.last_sleep_duration_us,
        }
    }

    /// The expected confirmed lifecycle for a mode.  Tests and platform
    /// adapters use it when reporting a successful transition completion.
    pub const fn lifecycle_for(mode: RequestedMode) -> RadioLifecycle {
        RadioLifecycle::from_requested(mode)
    }

    /// Account for a coalesced queue-overflow count in constant time. Called
    /// by the one runtime owner after it atomically drains an adapter counter;
    /// it never loops in response to a pathological producer.
    pub fn record_queue_overflow(&mut self, count: u32) {
        self.queue_overflow_count = self.queue_overflow_count.saturating_add(count);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boot_requests_the_active_nan_now_default() {
        let mut state = MainRuntimeState::default();
        assert_eq!(
            state.reduce(MainEvent::Boot),
            MainEffect::ApplyRadio {
                mode: RequestedMode::NanNow,
                generation: 0,
            }
        );
    }

    #[test]
    fn boot_profile_makes_sleepy_policy_explicit_before_radio_completion() {
        let mut state = MainRuntimeState::default();
        assert_eq!(
            state.reduce(MainEvent::BootProfile {
                mode: RequestedMode::NanNow,
                sleepy: true,
            }),
            MainEffect::ApplyRadio {
                mode: RequestedMode::NanNow,
                generation: 0,
            }
        );
        assert!(state.snapshot().sleepy);
        assert_eq!(
            state.snapshot().radio_lifecycle,
            RadioLifecycle::Starting as u8
        );
    }

    #[test]
    fn profile_is_requested_then_only_completion_makes_it_live() {
        let mut state = MainRuntimeState::default();
        assert_eq!(
            state.reduce(MainEvent::ProfileRequested {
                mode: RequestedMode::StaApNanNow,
                sleepy: false,
                generation: 4,
                request_id: 9,
            }),
            MainEffect::ApplyRadio {
                mode: RequestedMode::StaApNanNow,
                generation: 4,
            }
        );
        assert_eq!(
            state.snapshot().radio_lifecycle,
            RadioLifecycle::Starting as u8
        );
        state.reduce(MainEvent::RadioApplied {
            generation: 4,
            lifecycle: MainRuntimeState::lifecycle_for(RequestedMode::StaApNanNow),
        });
        let snapshot = state.snapshot();
        assert_eq!(snapshot.applied_generation, 4);
        assert_eq!(snapshot.radio_lifecycle, RadioLifecycle::StaApNanNow as u8);
    }

    #[test]
    fn stale_completion_cannot_replace_a_newer_request() {
        let mut state = MainRuntimeState::default();
        state.reduce(MainEvent::ProfileRequested {
            mode: RequestedMode::Sta,
            sleepy: false,
            generation: 2,
            request_id: 1,
        });
        state.reduce(MainEvent::ProfileRequested {
            mode: RequestedMode::NanNow,
            sleepy: true,
            generation: 3,
            request_id: 2,
        });
        assert_eq!(
            state.reduce(MainEvent::RadioApplied {
                generation: 2,
                lifecycle: RadioLifecycle::Sta,
            }),
            MainEffect::None
        );
        let snapshot = state.snapshot();
        assert_eq!(snapshot.desired_generation, 3);
        assert_eq!(snapshot.radio_lifecycle, RadioLifecycle::Starting as u8);
        assert_eq!(snapshot.stale_completion_count, 1);
    }

    #[test]
    fn sleepy_deadline_enters_sleep_only_without_blockers() {
        let mut state = MainRuntimeState::default();
        state.reduce(MainEvent::ProfileRequested {
            mode: RequestedMode::NanNow,
            sleepy: true,
            generation: 1,
            request_id: 7,
        });
        assert_eq!(
            state.reduce(MainEvent::SleepDeadline {
                generation: 1,
                blockers: SleepBlockers::NAN_DEADLINE,
            }),
            MainEffect::None
        );
        assert_eq!(
            state.snapshot().power_lifecycle,
            PowerLifecycle::Blocked as u8
        );
        assert_eq!(
            state.reduce(MainEvent::SleepDeadline {
                generation: 1,
                blockers: SleepBlockers::NONE,
            }),
            MainEffect::EnterLightSleep { generation: 1 }
        );
    }

    #[test]
    fn snapshot_is_bounded_and_credential_free() {
        // The fixed 64-byte ceiling includes observed CPU/PM configuration as
        // well as radio/power lifecycle. It is still a copyable control-plane
        // record, never a profile or credential container.
        assert!(core::mem::size_of::<MainRuntimeSnapshot>() <= 64);
        let mut state = MainRuntimeState::default();
        state.reduce(MainEvent::QueueOverflow);
        assert_eq!(state.snapshot().queue_overflow_count, 1);
    }

    #[test]
    fn power_completion_projects_measured_sleep_metrics() {
        let mut state = MainRuntimeState::default();
        assert_eq!(
            state.reduce(MainEvent::PowerApplied {
                cpu_mhz: 160,
                min_mhz: 80,
                max_mhz: 160,
                automatic_light_sleep: true,
                configured: true,
                light_sleep_attempts: 3,
                light_sleep_entries: 2,
                light_sleep_skipped: 1,
                last_sleep_requested_us: 4_194_304,
                last_sleep_duration_us: 4_194_012,
            }),
            MainEffect::None
        );
        let snapshot = state.snapshot();
        assert_eq!(snapshot.cpu_mhz, 160);
        assert_eq!(snapshot.pm_min_mhz, 80);
        assert!(snapshot.pm_automatic_light_sleep);
        assert_eq!(snapshot.light_sleep_entries, 2);
        assert_eq!(snapshot.last_sleep_duration_us, 4_194_012);
    }
}
