//! Platform-independent decision only; adapters validate their hardware and
//! sleep state before applying an SDK clock correction. Never a QUIC policy.

/// Conservative advance after a large backwards native-clock observation.
/// Independent ticks must be known to run continuously over this interval.
/// One tick of uncertainty is excluded; the result restores at least the last
/// observation but does not claim sub-tick wall-clock accuracy.
pub fn rollback_advance_us(
    previous_us: u64,
    now_us: u64,
    previous_ticks: u32,
    ticks: u32,
    tick_hz: u32,
    continuously_awake: bool,
) -> Option<u64> {
    if !continuously_awake || tick_hz == 0 || now_us >= previous_us {
        return None;
    }
    let rollback = previous_us - now_us;
    // Small sampling anomalies do not justify modifying a global clock.
    if !(100_000..=86_400_000_000).contains(&rollback) {
        return None;
    }
    let elapsed_ticks = ticks.wrapping_sub(previous_ticks);
    // Reject a reversed independent clock or an ambiguous half-range interval.
    if elapsed_ticks >= 1 << 31 {
        return None;
    }
    let elapsed_us = u64::from(elapsed_ticks.saturating_sub(1))
        .checked_mul(1_000_000)? / u64::from(tick_hz);
    let advance = rollback.checked_add(elapsed_us)?;
    (advance <= 86_400_000_000).then_some(advance)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordinary_advance_and_duplicate_do_not_repair() {
        for now in [100_000, 120_000] {
            assert_eq!(rollback_advance_us(100_000, now, 10, 12, 100, true), None);
        }
    }

    #[test]
    fn captured_c6_fault_restores_previous_time_conservatively() {
        let delta = rollback_advance_us(104_097_827, 70_546_028, 10380, 10381, 100, true).unwrap();
        assert_eq!(70_546_028 + delta, 104_097_827);
    }

    #[test]
    fn sustained_elapsed_time_excludes_one_tick_uncertainty() {
        assert_eq!(rollback_advance_us(1_000_000, 500_000, 10, 15, 100, true), Some(540_000));
    }

    #[test]
    fn independent_tick_wrap_is_valid() {
        assert_eq!(rollback_advance_us(1_000_000, 500_000, u32::MAX - 1, 1, 100, true), Some(520_000));
    }

    #[test]
    fn repaired_observation_does_not_trigger_another_advance() {
        let advance = rollback_advance_us(104_097_827, 70_546_028, 10380, 10381, 100, true).unwrap();
        let repaired = 70_546_028 + advance;
        assert_eq!(rollback_advance_us(repaired, repaired + 500, 10381, 10381, 100, true), None);
    }

    #[test]
    fn multi_bit_captured_fault_with_no_elapsed_tick_is_repaired() {
        let advance = rollback_advance_us(278_342_576, 1_520_100, 31189, 31189, 100, true).unwrap();
        assert_eq!(1_520_100 + advance, 278_342_576);
    }

    #[test]
    fn sleep_or_independent_clock_regression_rejects_repair() {
        assert_eq!(rollback_advance_us(1_000_000, 500_000, 10, 15, 100, false), None);
        assert_eq!(rollback_advance_us(1_000_000, 500_000, 15, 10, 100, true), None);
    }

    #[test]
    fn invalid_frequency_small_jump_and_excessive_jump_are_rejected() {
        assert_eq!(rollback_advance_us(1_000_000, 500_000, 10, 15, 0, true), None);
        assert_eq!(rollback_advance_us(1_000_000, 999_999, 10, 15, 100, true), None);
        assert_eq!(rollback_advance_us(u64::MAX, 0, 10, 15, 100, true), None);
    }
}
