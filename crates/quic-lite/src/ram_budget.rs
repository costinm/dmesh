//! Device-wide RAM admission policy for QUIC-lite paths and connections.
//!
//! Packet storage is one shared pool: a relay transfers a slot from RX to TX
//! without another MTU allocation. Connection receive credit is admitted from
//! the same device budget, with a safety margin never visible to peers.

use crate::{ConnectionLimits, EndpointState};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RamBudgetError {
    InvalidPacketSlots,
    PacketGrowthWouldViolateConnectionGrants,
    ConnectionCapacityReached,
    InsufficientRam,
}

/// A connection's current advertised receive credit reservation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConnectionRamGrant {
    slot: u8,
    /// Absolute connection credit advertised to the peer.
    pub advertised_max_data: u64,
    /// Application-consumed bytes. The effective receive window is the
    /// difference and can shrink when replenishment is withheld.
    pub consumed_data: u64,
}

impl ConnectionRamGrant {
    pub const fn effective_window(self) -> u64 {
        self.advertised_max_data.saturating_sub(self.consumed_data)
    }
}

/// One device-wide bounded allocation plan.
pub struct TransportRamBudget<const CONNECTIONS: usize> {
    total_bytes: usize,
    safety_margin_bytes: usize,
    packet_bytes: usize,
    max_packet_slots: usize,
    packet_slots: usize,
    grants: [Option<ConnectionRamGrant>; CONNECTIONS],
}

impl<const CONNECTIONS: usize> TransportRamBudget<CONNECTIONS> {
    pub fn new(
        total_bytes: usize,
        packet_bytes: usize,
        max_packet_slots: usize,
        packet_slots: usize,
    ) -> Result<Self, RamBudgetError> {
        Self::new_with_margin(total_bytes, 0, packet_bytes, max_packet_slots, packet_slots)
    }

    pub fn new_with_margin(
        total_bytes: usize,
        safety_margin_bytes: usize,
        packet_bytes: usize,
        max_packet_slots: usize,
        packet_slots: usize,
    ) -> Result<Self, RamBudgetError> {
        if safety_margin_bytes > total_bytes || packet_slots > max_packet_slots {
            return Err(RamBudgetError::InvalidPacketSlots);
        }
        let budget = Self {
            total_bytes,
            safety_margin_bytes,
            packet_bytes,
            max_packet_slots,
            packet_slots,
            grants: [None; CONNECTIONS],
        };
        if budget
            .packet_bytes_reserved()
            .saturating_add(safety_margin_bytes)
            > total_bytes
        {
            return Err(RamBudgetError::InsufficientRam);
        }
        Ok(budget)
    }

    pub const fn total_bytes(&self) -> usize {
        self.total_bytes
    }
    pub const fn safety_margin_bytes(&self) -> usize {
        self.safety_margin_bytes
    }
    pub const fn packet_capacity(&self) -> usize {
        self.packet_slots
    }
    pub const fn packet_bytes_reserved(&self) -> usize {
        self.packet_slots * self.packet_bytes
    }

    pub fn connection_bytes_reserved(&self) -> usize {
        self.grants
            .iter()
            .flatten()
            .map(|grant| grant.effective_window() as usize)
            .sum()
    }

    pub fn free_bytes(&self) -> usize {
        self.total_bytes
            .saturating_sub(self.safety_margin_bytes)
            .saturating_sub(self.packet_bytes_reserved())
            .saturating_sub(self.connection_bytes_reserved())
    }

    /// Change active shared-pool capacity. This affects all bearers together,
    /// never one bearer at a time.
    pub fn resize_packets(&mut self, packet_slots: usize) -> Result<(), RamBudgetError> {
        if packet_slots > self.max_packet_slots {
            return Err(RamBudgetError::InvalidPacketSlots);
        }
        let candidate = packet_slots
            .checked_mul(self.packet_bytes)
            .ok_or(RamBudgetError::InvalidPacketSlots)?;
        if candidate
            .saturating_add(self.connection_bytes_reserved())
            .saturating_add(self.safety_margin_bytes)
            > self.total_bytes
        {
            return Err(RamBudgetError::PacketGrowthWouldViolateConnectionGrants);
        }
        self.packet_slots = packet_slots;
        Ok(())
    }

    /// Admit a new connection fairly. Its initial advertised limit is bounded
    /// by capacity left for every currently free connection slot.
    pub fn admit_connection(
        &mut self,
        requested_window_bytes: usize,
    ) -> Result<(ConnectionRamGrant, ConnectionLimits), RamBudgetError> {
        let slot = self
            .grants
            .iter()
            .position(Option::is_none)
            .ok_or(RamBudgetError::ConnectionCapacityReached)?;
        let remaining_slots = self
            .grants
            .iter()
            .filter(|grant| grant.is_none())
            .count()
            .max(1);
        let window = requested_window_bytes.min(self.free_bytes() / remaining_slots);
        if window == 0 {
            return Err(RamBudgetError::InsufficientRam);
        }
        let grant = ConnectionRamGrant {
            slot: slot as u8,
            advertised_max_data: window as u64,
            consumed_data: 0,
        };
        self.grants[slot] = Some(grant);
        Ok((grant, limits(grant)))
    }

    /// Report durable application consumption. This shrinks the effective
    /// window and frees budget; no peer credit is returned yet.
    pub fn consume(&mut self, grant: &mut ConnectionRamGrant, bytes: usize) -> bool {
        let Some(stored) = self
            .grants
            .get_mut(grant.slot as usize)
            .and_then(Option::as_mut)
        else {
            return false;
        };
        if *stored != *grant || bytes as u64 > grant.effective_window() {
            return false;
        }
        grant.consumed_data = grant.consumed_data.saturating_add(bytes as u64);
        *stored = *grant;
        true
    }

    /// Replenish an active connection only from currently free device RAM.
    /// Idle paths simply skip this call and their effective windows contract
    /// as data is consumed. All active connections get a fair share of the
    /// remaining budget when their schedulers call this method.
    pub fn extend_active(
        &mut self,
        grant: &mut ConnectionRamGrant,
        requested_window_bytes: usize,
        active_connections: usize,
    ) -> Result<ConnectionLimits, RamBudgetError> {
        let slot = grant.slot as usize;
        if self.grants.get(slot).copied().flatten() != Some(*grant) {
            return Err(RamBudgetError::ConnectionCapacityReached);
        }
        let needed = requested_window_bytes.saturating_sub(grant.effective_window() as usize);
        let extension = needed.min(self.free_bytes() / active_connections.max(1));
        if extension == 0 {
            return Ok(limits(*grant));
        }
        grant.advertised_max_data = grant.advertised_max_data.saturating_add(extension as u64);
        self.grants[slot] = Some(*grant);
        Ok(limits(*grant))
    }

    /// Bridge durable application consumption to QUIC-lite flow control.
    /// The endpoint ACKs the consumed bytes immediately, but receives a
    /// MAX_* update only when the shared device budget can maintain the
    /// requested effective window alongside every active connection.
    pub fn consume_and_replenish<const N: usize, const H: usize, const P: usize>(
        &mut self,
        grant: &mut ConnectionRamGrant,
        endpoint: &mut EndpointState<N, H, P>,
        stream_id: u64,
        consumed_bytes: usize,
        requested_window_bytes: usize,
        active_connections: usize,
    ) -> Result<(), RamBudgetError> {
        endpoint
            .stream_consumed_without_credit(stream_id, consumed_bytes)
            .map_err(|_| RamBudgetError::InsufficientRam)?;
        if !self.consume(grant, consumed_bytes) {
            return Err(RamBudgetError::ConnectionCapacityReached);
        }
        self.extend_active(grant, requested_window_bytes, active_connections)?;
        endpoint
            .grant_receive_window(stream_id, grant.effective_window())
            .map_err(|_| RamBudgetError::InsufficientRam)
    }

    pub fn close_connection(&mut self, grant: ConnectionRamGrant) -> bool {
        let slot = grant.slot as usize;
        if self.grants.get(slot).copied().flatten() != Some(grant) {
            return false;
        }
        self.grants[slot] = None;
        true
    }
}

fn limits(grant: ConnectionRamGrant) -> ConnectionLimits {
    ConnectionLimits {
        max_data: grant.advertised_max_data,
        max_stream_data: grant.advertised_max_data,
        ..ConnectionLimits::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Role;

    #[test]
    fn relay_pool_is_counted_once_and_packet_growth_cannot_revoke_credit() {
        let mut budget = TransportRamBudget::<2>::new(12_000, 1_000, 8, 4).unwrap();
        let (first, first_limits) = budget.admit_connection(8_000).unwrap();
        let (_, second_limits) = budget.admit_connection(8_000).unwrap();
        assert_eq!(budget.packet_bytes_reserved(), 4_000);
        assert_eq!(first_limits.max_data, 4_000);
        assert_eq!(second_limits.max_data, 4_000);
        assert_eq!(
            budget.resize_packets(5),
            Err(RamBudgetError::PacketGrowthWouldViolateConnectionGrants)
        );
        assert!(budget.close_connection(first));
    }

    #[test]
    fn consumed_idle_credit_is_not_replenished_until_scheduler_allows_it() {
        let mut budget =
            TransportRamBudget::<1>::new_with_margin(12_000, 2_000, 1_000, 4, 2).unwrap();
        let (mut grant, limits) = budget.admit_connection(20_000).unwrap();
        assert_eq!(limits.max_data, 8_000);
        assert!(budget.consume(&mut grant, 3_000));
        assert_eq!(grant.effective_window(), 5_000);
        let limits = budget.extend_active(&mut grant, 7_000, 1).unwrap();
        assert_eq!(limits.max_data, 10_000);
        assert_eq!(grant.effective_window(), 7_000);
    }

    #[test]
    fn endpoint_credit_advances_only_after_shared_budget_admission() {
        let mut budget =
            TransportRamBudget::<1>::new_with_margin(12_000, 2_000, 1_000, 4, 2).unwrap();
        let (mut grant, limits) = budget.admit_connection(20_000).unwrap();
        let mut endpoint = EndpointState::<2, 2, 1200>::new(Role::Server, limits, 1200);
        endpoint.receive.accept(0, 0, 3_000, false).unwrap();

        // Durable delivery alone sends an ACK but cannot reopen the peer's
        // receive window. This is the backpressure point for a full relay.
        endpoint.stream_consumed_without_credit(0, 3_000).unwrap();
        assert_eq!(endpoint.receive.connection.max_data, 8_000);
        assert_eq!(endpoint.receive.stream_max_data(0), Some(8_000));

        // Once the device-wide pool admits the replacement credit, MAX_DATA
        // and MAX_STREAM_DATA advance together to the newly admitted limit.
        let mut admitted_endpoint = EndpointState::<2, 2, 1200>::new(Role::Server, limits, 1200);
        admitted_endpoint
            .receive
            .accept(0, 0, 3_000, false)
            .unwrap();
        budget
            .consume_and_replenish(&mut grant, &mut admitted_endpoint, 0, 3_000, 7_000, 1)
            .unwrap();
        assert_eq!(grant.advertised_max_data, 10_000);
        assert_eq!(admitted_endpoint.receive.connection.max_data, 10_000);
        assert_eq!(admitted_endpoint.receive.stream_max_data(0), Some(10_000));
    }
}
