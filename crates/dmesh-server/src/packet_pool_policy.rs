//! Owner-task policy for a reclaimable shared packet pool, independent of allocator.

pub struct PacketPoolPolicy {
    pub minimum: usize,
    pub maximum: usize,
    pub free_target: usize,
    pub idle_ms: u64,
    low_since: Option<u64>,
    pressure_capacity: Option<usize>,
}

impl PacketPoolPolicy {
    pub const fn new(minimum: usize, maximum: usize, free_target: usize, idle_ms: u64) -> Self {
        Self {
            minimum,
            maximum,
            free_target,
            idle_ms,
            low_since: None,
            pressure_capacity: None,
        }
    }

    /// Growth is immediate; excess free storage must remain idle before shrink.
    /// Allocation failure is handled by the pool, not by this policy.
    pub fn target(&mut self, now_ms: u64, capacity: usize, in_use: usize) -> usize {
        let pressure = self
            .pressure_capacity
            .take()
            .map_or(0, |capacity| capacity.saturating_add(self.free_target));
        let desired = in_use
            .saturating_add(self.free_target)
            .max(pressure)
            .max(self.minimum)
            .min(self.maximum);
        if desired >= capacity {
            self.low_since = None;
            return desired;
        }
        let since = *self.low_since.get_or_insert(now_ms);
        if now_ms.saturating_sub(since) >= self.idle_ms {
            desired
        } else {
            capacity
        }
    }

    pub fn shrink_deadline(&self) -> Option<u64> {
        self.low_since
            .map(|since| since.saturating_add(self.idle_ms))
    }

    /// A callback pressure latch survives until the owner samples the pool,
    /// even if the burst's leases have already drained by then.
    pub fn note_pressure(&mut self, capacity: usize) {
        self.pressure_capacity = Some(capacity);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn floor_growth_and_idle_shrink() {
        let mut policy = PacketPoolPolicy::new(8, 128, 8, 2_000);
        assert_eq!(policy.target(0, 0, 0), 8);
        assert_eq!(policy.target(1, 8, 6), 14);
        assert_eq!(policy.target(2, 14, 0), 14);
        assert_eq!(policy.shrink_deadline(), Some(2_002));
        assert_eq!(policy.target(2_001, 14, 0), 14);
        assert_eq!(policy.target(2_002, 14, 0), 8);
    }

    #[test]
    fn pressure_cancels_idle_and_limit_is_enforced() {
        let mut policy = PacketPoolPolicy::new(8, 32, 8, 2_000);
        assert_eq!(policy.target(0, 16, 0), 16);
        assert_eq!(policy.target(1, 16, 8), 16);
        assert_eq!(policy.shrink_deadline(), None);
        assert_eq!(policy.target(2, 16, usize::MAX), 32);
        assert_eq!(policy.target(3, 32, 0), 32);
        assert_eq!(policy.target(2_003, 32, 0), 8);
    }

    #[test]
    fn drained_burst_still_grows_and_later_reclaims() {
        let mut policy = PacketPoolPolicy::new(8, 128, 8, 2_000);
        policy.note_pressure(8);
        assert_eq!(policy.target(0, 8, 0), 16);
        assert_eq!(policy.target(1, 16, 0), 16);
        assert_eq!(policy.target(2_001, 16, 0), 8);
    }
}
