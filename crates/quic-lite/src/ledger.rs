//! Retransmission-ledger sizing policy.
//!
//! The packet store itself remains owned by `EndpointState`.  This module
//! keeps memory-policy decisions deterministic and bearer-neutral so host
//! adapters can size a heap-backed ledger while embedded adapters continue to
//! use fixed profiles.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LedgerMemoryPolicy {
    pub min_packets: usize,
    pub max_packets: usize,
    pub memory_fraction_numerator: u64,
    pub memory_fraction_denominator: u64,
    pub reserve_bytes: u64,
    pub metadata_bytes_per_packet: usize,
}

impl Default for LedgerMemoryPolicy {
    fn default() -> Self {
        Self {
            min_packets: 4,
            max_packets: 512,
            memory_fraction_numerator: 1,
            memory_fraction_denominator: 8,
            reserve_bytes: 64 * 1024 * 1024,
            metadata_bytes_per_packet: 96,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LedgerMemorySnapshot {
    pub total_bytes: u64,
    pub available_bytes: u64,
}

/// Allocation-free hysteresis for adapting a host ledger to changing memory
/// pressure.  The bearer samples memory and calls [`observe`] periodically;
/// the controller only proposes a resize after the same target has remained
/// stable for the configured number of observations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LedgerCapacityController {
    current: usize,
    pending: usize,
    stable_observations: u8,
    required_observations: u8,
}

impl LedgerCapacityController {
    pub fn new(current: usize, required_observations: u8) -> Self {
        assert!(current > 0);
        Self {
            current,
            pending: current,
            stable_observations: 0,
            required_observations: required_observations.max(1),
        }
    }

    pub const fn current(&self) -> usize {
        self.current
    }

    pub const fn pending(&self) -> usize {
        self.pending
    }

    pub const fn stable_observations(&self) -> u8 {
        self.stable_observations
    }

    /// Observe a new memory budget.  Returns a new capacity only when it is
    /// safe to apply immediately; a shrink below `live_entries` is deferred
    /// without evicting or overwriting retransmittable packets.
    pub fn observe(
        &mut self,
        memory: LedgerMemorySnapshot,
        active_connections: usize,
        payload_bytes: usize,
        policy: LedgerMemoryPolicy,
        live_entries: usize,
    ) -> Option<usize> {
        let target = select_capacity(memory, active_connections, payload_bytes, policy);
        if target == self.current || target < live_entries {
            self.pending = target;
            self.stable_observations = 0;
            return None;
        }
        if self.pending != target {
            self.pending = target;
            self.stable_observations = 1;
            return None;
        }
        self.stable_observations = self.stable_observations.saturating_add(1);
        if self.stable_observations < self.required_observations {
            return None;
        }
        self.current = target;
        self.pending = target;
        self.stable_observations = 0;
        Some(target)
    }
}

/// Select a per-connection ledger capacity. The result is deterministic for
/// tests and never exceeds the policy or the available memory budget.
pub fn select_capacity(
    memory: LedgerMemorySnapshot,
    active_connections: usize,
    payload_bytes: usize,
    policy: LedgerMemoryPolicy,
) -> usize {
    let min_packets = policy.min_packets.max(1);
    let max_packets = policy.max_packets.max(min_packets);
    // MemAvailable is authoritative when present. A zero value is treated as
    // an unavailable probe and gets a conservative total-memory fallback;
    // never substitute a quarter of total memory for a genuinely low
    // available-memory reading.
    let available = (if memory.available_bytes == 0 {
        memory.total_bytes / 4
    } else {
        memory.available_bytes
    })
    .saturating_sub(policy.reserve_bytes);
    let fraction = available.saturating_mul(policy.memory_fraction_numerator)
        / policy.memory_fraction_denominator.max(1);
    let per_connection = fraction / active_connections.max(1) as u64;
    let slot_bytes = payload_bytes
        .saturating_add(policy.metadata_bytes_per_packet)
        .max(1) as u64;
    let by_memory = (per_connection / slot_bytes) as usize;
    by_memory.clamp(min_packets, max_packets)
}

#[cfg(feature = "std")]
pub fn system_memory_snapshot() -> Option<LedgerMemorySnapshot> {
    let text = std::fs::read_to_string("/proc/meminfo").ok()?;
    let mut total = None;
    let mut available = None;
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        let Some(key) = fields.next() else { continue };
        let Some(raw_value) = fields.next() else {
            continue;
        };
        let Ok(value) = raw_value.parse::<u64>() else {
            continue;
        };
        let value = value.saturating_mul(1024);
        match key {
            "MemTotal:" => total = Some(value),
            "MemAvailable:" => available = Some(value),
            _ => {}
        }
    }
    Some(LedgerMemorySnapshot {
        total_bytes: total?,
        available_bytes: available?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capacity_scales_with_memory_and_connection_count() {
        let policy = LedgerMemoryPolicy {
            reserve_bytes: 0,
            ..LedgerMemoryPolicy::default()
        };
        let memory = LedgerMemorySnapshot {
            total_bytes: 16 * 1024 * 1024,
            available_bytes: 16 * 1024 * 1024,
        };
        let one = select_capacity(memory, 1, 1400, policy);
        let eight = select_capacity(memory, 8, 1400, policy);
        assert!(one > eight);
        assert!(one <= policy.max_packets);
        assert!(eight >= policy.min_packets);
    }

    #[test]
    fn capacity_respects_reserve_and_bounds() {
        let policy = LedgerMemoryPolicy {
            min_packets: 4,
            max_packets: 128,
            reserve_bytes: 1 << 30,
            ..LedgerMemoryPolicy::default()
        };
        let memory = LedgerMemorySnapshot {
            total_bytes: 64 * 1024 * 1024,
            available_bytes: 64 * 1024 * 1024,
        };
        assert_eq!(select_capacity(memory, 4, 1400, policy), 4);
    }

    #[test]
    fn low_available_memory_is_not_replaced_by_total_memory() {
        let policy = LedgerMemoryPolicy {
            reserve_bytes: 0,
            ..LedgerMemoryPolicy::default()
        };
        let constrained = select_capacity(
            LedgerMemorySnapshot {
                total_bytes: 1 << 30,
                available_bytes: 1 << 20,
            },
            1,
            1400,
            policy,
        );
        assert!(constrained < policy.max_packets);
    }

    #[test]
    fn capacity_never_exceeds_policy_max_for_large_hosts() {
        let policy = LedgerMemoryPolicy {
            reserve_bytes: 0,
            ..LedgerMemoryPolicy::default()
        };
        let memory = LedgerMemorySnapshot {
            total_bytes: 1 << 40,
            available_bytes: 1 << 40,
        };
        assert_eq!(select_capacity(memory, 1, 1400, policy), 512);
    }

    #[test]
    fn capacity_controller_requires_stability_and_preserves_live_entries() {
        let policy = LedgerMemoryPolicy {
            min_packets: 4,
            max_packets: 64,
            reserve_bytes: 0,
            ..LedgerMemoryPolicy::default()
        };
        let low = LedgerMemorySnapshot {
            total_bytes: 16 * 1024,
            available_bytes: 16 * 1024,
        };
        let high = LedgerMemorySnapshot {
            total_bytes: 4 * 1024 * 1024,
            available_bytes: 4 * 1024 * 1024,
        };
        let mut controller = LedgerCapacityController::new(4, 2);
        assert_eq!(controller.observe(high, 1, 1400, policy, 0), None);
        assert_eq!(controller.observe(high, 1, 1400, policy, 0), Some(64));
        assert_eq!(controller.current(), 64);
        assert_eq!(controller.observe(low, 1, 1400, policy, 8), None);
        assert_eq!(controller.current(), 64);
        assert_eq!(controller.observe(low, 1, 1400, policy, 4), None);
        assert_eq!(controller.observe(low, 1, 1400, policy, 4), Some(4));
        assert_eq!(controller.current(), 4);
    }

    #[test]
    fn capacity_controller_ignores_oscillation_until_target_is_stable() {
        let policy = LedgerMemoryPolicy {
            min_packets: 4,
            max_packets: 64,
            reserve_bytes: 0,
            ..LedgerMemoryPolicy::default()
        };
        let low = LedgerMemorySnapshot {
            total_bytes: 16 * 1024,
            available_bytes: 16 * 1024,
        };
        let high = LedgerMemorySnapshot {
            total_bytes: 4 * 1024 * 1024,
            available_bytes: 4 * 1024 * 1024,
        };
        let mut controller = LedgerCapacityController::new(16, 3);
        assert_eq!(controller.observe(high, 1, 1400, policy, 0), None);
        assert_eq!(controller.observe(low, 1, 1400, policy, 0), None);
        assert_eq!(controller.observe(high, 1, 1400, policy, 0), None);
        assert_eq!(controller.current(), 16);
        assert_eq!(controller.observe(high, 1, 1400, policy, 0), None);
        assert_eq!(controller.observe(high, 1, 1400, policy, 0), Some(64));
    }
}
