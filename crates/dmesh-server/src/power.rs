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

/// Decode the bounded platform-fact JSON projection used by Android, host
/// diagnostics, and test adapters.  It deliberately accepts no framework
/// names or callbacks: an adapter may report only facts it can observe.
#[cfg(feature = "std")]
pub fn decode_json_observation(input: &[u8]) -> Result<PowerObservation, &'static str> {
    use serde_json::Value;

    const MAX_BYTES: usize = 2 * 1024;
    const MAX_TEXT: usize = 256;
    if input.len() > MAX_BYTES {
        return Err("power observation exceeds byte bound");
    }
    let value: Value = serde_json::from_slice(input).map_err(|_| "invalid power observation")?;
    let values = value.as_object().ok_or("power observation must be an object")?;
    const FIELDS: &[&str] = &[
        "source",
        "event",
        "battery_percent",
        "charging",
        "status",
        "plugged",
        "power_save",
        "idle",
        "idle_ms",
        "total_idle_ms",
        "charging_ms",
        "memory_available_bytes",
        "memory_low",
        "memory_threshold_bytes",
        "trim_level",
    ];
    if values.keys().any(|key| !FIELDS.contains(&key.as_str())) {
        return Err("power observation contains unsupported field");
    }
    for key in ["source", "event"] {
        if let Some(value) = values.get(key) {
            if !value.as_str().is_some_and(|text| text.len() <= MAX_TEXT) {
                return Err("power observation metadata must be bounded text");
            }
        }
    }
    let uint = |key| uint(values, key);
    let battery_percent = match uint("battery_percent")? {
        Some(value) if value <= 100 => Some(value as u8),
        Some(_) => return Err("battery percentage must be 0..100"),
        None => None,
    };
    // `status` and `plugged` are retained as accepted Android source facts
    // for compatibility, but the common state intentionally does not turn
    // Android constants into part of the mesh schema.
    let _ = uint("status")?;
    let _ = uint("plugged")?;
    Ok(PowerObservation {
        battery_percent,
        charging: boolean(values, "charging")?,
        power_save: boolean(values, "power_save")?,
        idle: boolean(values, "idle")?,
        idle_ms: uint("idle_ms")?,
        total_idle_ms: uint("total_idle_ms")?,
        charging_ms: uint("charging_ms")?,
        memory_available_bytes: uint("memory_available_bytes")?,
        memory_low: boolean(values, "memory_low")?,
        memory_threshold_bytes: uint("memory_threshold_bytes")?,
        trim_level: match uint("trim_level")? {
            Some(value) => Some(u32::try_from(value).map_err(|_| "trim level exceeds u32")?),
            None => None,
        },
    })
}

#[cfg(feature = "std")]
fn uint(values: &serde_json::Map<String, serde_json::Value>, key: &str) -> Result<Option<u64>, &'static str> {
    values.get(key).map_or(Ok(None), |value| value.as_u64().map(Some).ok_or("power observation integer must be unsigned"))
}

#[cfg(feature = "std")]
fn boolean(values: &serde_json::Map<String, serde_json::Value>, key: &str) -> Result<Option<bool>, &'static str> {
    values.get(key).map_or(Ok(None), |value| value.as_bool().map(Some).ok_or("power observation boolean must be boolean"))
}

/// JSON status projection for generic HTTP and text adapters.  It has no
/// Android fields, so platform-specific constants cannot leak into clients.
#[cfg(feature = "std")]
pub fn json_status(state: PowerState) -> serde_json::Value {
    serde_json::json!({
        "battery_percent": state.battery_percent,
        "charging": state.charging,
        "power_save": state.power_save,
        "idle": state.idle,
        "idle_ms": state.idle_ms,
        "total_idle_ms": state.total_idle_ms,
        "charging_ms": state.charging_ms,
        "memory_available_bytes": state.memory_available_bytes,
        "memory_low": state.memory_low,
        "memory_threshold_bytes": state.memory_threshold_bytes,
        "trim_level": state.trim_level,
    })
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

    #[cfg(feature = "std")]
    #[test]
    fn json_projection_is_platform_neutral_and_bounded() {
        let observation = decode_json_observation(
            br#"{"source":"android","event":"battery","battery_percent":67,"power_save":true,"status":2}"#,
        )
        .unwrap();
        let mut state = PowerState::default();
        state.apply(observation);
        assert_eq!(json_status(state)["battery_percent"], 67);
        assert!(decode_json_observation(br#"{"unknown":true}"#).is_err());
    }
}
