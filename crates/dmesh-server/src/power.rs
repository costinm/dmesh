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
pub struct BatteryState {
    pub battery_percent: Option<u8>,
    pub charging: Option<bool>,
    pub power_save: Option<bool>,
    pub idle: Option<bool>,
    pub idle_ms: Option<u64>,
    pub total_idle_ms: Option<u64>,
    pub charging_ms: Option<u64>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PowerState {
    pub battery: BatteryState,
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
        self.battery.apply(update);
        apply!(memory_available_bytes);
        apply!(memory_low);
        apply!(memory_threshold_bytes);
        apply!(trim_level);
    }
}

impl BatteryState {
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
    }
}

/// Decode the private Android CBOR update into the portable battery fields.
/// Public telemetry uses the numeric tags in API.md; this ingress uses field
/// names so Android can use the shared Bundle/CBOR stream codec.
pub fn decode_battery_cbor_observation(input: &[u8]) -> Result<PowerObservation, &'static str> {
    use crate::cbor::Decoder;

    if input.len() > 512 {
        return Err("battery observation exceeds byte bound");
    }
    let mut decoder = Decoder::new(input);
    let (major, count) = decoder.head().ok_or("invalid battery CBOR")?;
    if major != 5 || count == 0 || count > 7 {
        return Err("battery observation must be a bounded map");
    }
    let mut observation = PowerObservation::default();
    let mut seen = 0u8;
    for _ in 0..count {
        let key = decoder.text_ref().ok_or("battery field must be text")?;
        let bit: u8 = match key {
            b"battery_percent" => {
                let value = decoder.uint().ok_or("invalid battery percentage")?;
                observation.battery_percent = Some(
                    u8::try_from(value)
                        .ok()
                        .filter(|value| *value <= 100)
                        .ok_or("battery percentage must be 0..100")?,
                );
                1
            }
            b"charging" => {
                observation.charging = Some(decoder.boolean().ok_or("invalid charging flag")?);
                2
            }
            b"power_save" => {
                observation.power_save = Some(decoder.boolean().ok_or("invalid power-save flag")?);
                4
            }
            b"idle" => {
                observation.idle = Some(decoder.boolean().ok_or("invalid idle flag")?);
                8
            }
            b"idle_ms" => {
                observation.idle_ms = Some(decoder.uint().ok_or("invalid idle duration")?);
                16
            }
            b"total_idle_ms" => {
                observation.total_idle_ms =
                    Some(decoder.uint().ok_or("invalid total idle duration")?);
                32
            }
            b"charging_ms" => {
                observation.charging_ms = Some(decoder.uint().ok_or("invalid charging duration")?);
                64
            }
            _ => return Err("unsupported battery field"),
        };
        if seen & bit != 0 {
            return Err("duplicate battery field");
        }
        seen |= bit;
    }
    if !decoder.is_finished() {
        return Err("trailing battery CBOR data");
    }
    Ok(observation)
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
    let values = value
        .as_object()
        .ok_or("power observation must be an object")?;
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
fn uint(
    values: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<Option<u64>, &'static str> {
    values.get(key).map_or(Ok(None), |value| {
        value
            .as_u64()
            .map(Some)
            .ok_or("power observation integer must be unsigned")
    })
}

#[cfg(feature = "std")]
fn boolean(
    values: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<Option<bool>, &'static str> {
    values.get(key).map_or(Ok(None), |value| {
        value
            .as_bool()
            .map(Some)
            .ok_or("power observation boolean must be boolean")
    })
}

/// JSON status projection for generic HTTP and text adapters.  It has no
/// Android fields, so platform-specific constants cannot leak into clients.
#[cfg(feature = "std")]
pub fn json_status(state: PowerState) -> serde_json::Value {
    serde_json::json!({
        "battery_percent": state.battery.battery_percent,
        "charging": state.battery.charging,
        "power_save": state.battery.power_save,
        "idle": state.battery.idle,
        "idle_ms": state.battery.idle_ms,
        "total_idle_ms": state.battery.total_idle_ms,
        "charging_ms": state.battery.charging_ms,
        "memory_available_bytes": state.memory_available_bytes,
        "memory_low": state.memory_low,
        "memory_threshold_bytes": state.memory_threshold_bytes,
        "trim_level": state.trim_level,
    })
}

#[cfg(feature = "std")]
pub fn battery_json_status(state: BatteryState) -> serde_json::Value {
    serde_json::json!({
        "battery_percent": state.battery_percent,
        "charging": state.charging,
        "power_save": state.power_save,
        "idle": state.idle,
        "idle_ms": state.idle_ms,
        "total_idle_ms": state.total_idle_ms,
        "charging_ms": state.charging_ms,
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
        assert_eq!(state.battery.battery_percent, Some(54));
        assert_eq!(state.battery.power_save, Some(true));
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

    #[test]
    fn battery_cbor_update_is_bounded_and_rejects_duplicate_fields() {
        use crate::cbor::Encoder;

        let mut wire = [0u8; 128];
        let mut encoder = Encoder::new(&mut wire);
        encoder.map(3).unwrap();
        encoder.text_value(b"battery_percent").unwrap();
        encoder.uint(67).unwrap();
        encoder.text_value(b"charging").unwrap();
        encoder.boolean(true).unwrap();
        encoder.text_value(b"idle_ms").unwrap();
        encoder.uint(1200).unwrap();
        let used = encoder.len();
        let observation = decode_battery_cbor_observation(&wire[..used]).unwrap();
        let mut state = BatteryState::default();
        state.apply(observation);
        assert_eq!(state.battery_percent, Some(67));
        assert_eq!(state.charging, Some(true));
        assert_eq!(state.idle_ms, Some(1200));

        let mut duplicate = [0u8; 80];
        let mut encoder = Encoder::new(&mut duplicate);
        encoder.map(2).unwrap();
        for _ in 0..2 {
            encoder.text_value(b"battery_percent").unwrap();
            encoder.uint(67).unwrap();
        }
        let used = encoder.len();
        assert!(decode_battery_cbor_observation(&duplicate[..used]).is_err());
    }
}
