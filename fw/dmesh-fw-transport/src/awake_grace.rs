//! Private owner policy; no SDK calls or transport behavior.

/// A committed active profile cancels the sleepy-policy timer. Leaving an
/// expired grace armed while STA/NOW prevents sleep makes every owner wait
/// immediately due. A new sleepy profile gets its normal command grace.
pub(super) fn profile_deadline(sleepy: bool, now_ms: u64, grace_ms: u64) -> u64 {
    if sleepy {
        now_ms.saturating_add(grace_ms)
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sleepy_sta_sleepy_cancels_old_timer_and_arms_fresh_grace() {
        let mut deadline = profile_deadline(true, 0, 60_000);
        assert_eq!(deadline, 60_000);
        // STA stays up beyond the old grace: no sleepy deadline may survive.
        deadline = profile_deadline(false, 10_000, 60_000);
        assert_eq!(deadline, 0);
        assert_eq!(profile_deadline(false, 90_000, 60_000), 0);
        deadline = profile_deadline(true, 100_000, 60_000);
        assert_eq!(deadline, 160_000);
    }

    #[test]
    fn active_transition_cancels_even_an_already_expired_grace() {
        assert_eq!(profile_deadline(false, 100_000, 60_000), 0);
        assert_eq!(profile_deadline(true, u64::MAX - 1, 60_000), u64::MAX);
    }
}
