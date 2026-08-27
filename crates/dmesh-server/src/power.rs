//! Platform power and memory facts shared by Android, Linux, and firmware.
//!
//! This module deliberately contains no framework callbacks, clocks, or
//! admission policy. Adapters submit partial observations; the common runtime
//! retains the latest known values for scheduling policy.

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PowerObservation {
    pub battery_percent: Option<u8>,
    pub charging: Option<bool>,
    pub power_save: Option<bool>,
    pub idle: Option<bool>,
    pub idle_ms: Option<u64>,
    pub total_idle_ms: Option<u64>,
    pub charging_ms: Option<u64>,
    pub memory_available_bytes: Option<u64>,
    pub memory_low: Option<bool>,
    pub memory_threshold_bytes: Option<u64>,
    pub trim_level: Option<u32>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PowerState {
    pub battery_percent: Option<u8>,
    pub charging: Option<bool>,
    pub power_save: Option<bool>,
    pub idle: Option<bool>,
    pub idle_ms: Option<u64>,
    pub total_idle_ms: Option<u64>,
    pub charging_ms: Option<u64>,
    pub memory_available_bytes: Option<u64>,
    pub memory_low: Option<bool>,
    pub memory_threshold_bytes: Option<u64>,
    pub trim_level: Option<u32>,
}

impl PowerState {
    /// Merge a platform's partial observation without inventing values for
    /// fields that adapter cannot observe.
    pub fn apply(&mut self, update: PowerObservation) {
        macro_rules! apply {
            ($field:ident) => {
                if update.$field.is_some() {
                    self.$field = update.$field;
                }
            };
        }
        apply!(battery_percent);
        apply!(charging);
        apply!(power_save);
        apply!(idle);
        apply!(idle_ms);
        apply!(total_idle_ms);
        apply!(charging_ms);
        apply!(memory_available_bytes);
        apply!(memory_low);
        apply!(memory_threshold_bytes);
        apply!(trim_level);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partial_observations_preserve_other_platform_facts() {
        let mut state = PowerState::default();
        state.apply(PowerObservation {
            battery_percent: Some(54),
            power_save: Some(true),
            ..PowerObservation::default()
        });
        state.apply(PowerObservation {
            memory_available_bytes: Some(1024),
            memory_low: Some(false),
            ..PowerObservation::default()
        });
        assert_eq!(state.battery_percent, Some(54));
        assert_eq!(state.power_save, Some(true));
        assert_eq!(state.memory_available_bytes, Some(1024));
    }
}
