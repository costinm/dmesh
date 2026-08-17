//! Fixed-capacity DCID routing and bearer-path availability.
//!
//! This is transport core: it has no socket, CBOR, task, or platform
//! dependency. Adapters assign their own meaning to a path index.

use crate::{ConnectionId, ShortHeader};

/// Immediate L2 egress feedback. A bearer reports its bounded local queue or
/// credit here; transport policy uses it for spillover and service scheduling
/// without knowing whether the path is UART, UDP, action frames, or radio.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PathCapacity {
    pub queued_packets: usize,
    pub capacity_packets: usize,
}

impl PathCapacity {
    pub const fn new(queued_packets: usize, capacity_packets: usize) -> Self {
        Self {
            queued_packets,
            capacity_packets,
        }
    }

    pub const fn has_capacity(self) -> bool {
        self.capacity_packets == 0 || self.queued_packets < self.capacity_packets
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PathState {
    pub available: bool,
    pub received_packets: u64,
    pub sent_packets: u64,
    pub measured_bytes_per_us: u64,
    pub loss_events: u64,
    pub last_probe_us: u64,
    pub capacity: PathCapacity,
}

impl PathState {
    pub const fn new() -> Self {
        Self {
            available: false,
            received_packets: 0,
            sent_packets: 0,
            measured_bytes_per_us: 0,
            loss_events: 0,
            last_probe_us: 0,
            capacity: PathCapacity::new(0, 0),
        }
    }
}

/// Connection-wide egress policy. Adapters map UART, UDP, or radio bearers
/// to path indexes; the transport does not name physical protocols.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PathPolicy {
    /// Pin a comparison run to one bearer, with availability fallback.
    Explicit(usize),
    /// Use the best measured bearer and periodically probe all paths so a
    /// recovered faster bearer is selected again.
    HighestMeasuredSpeed,
    /// Prefer a low-airtime bearer until its local queue/credit is full, then
    /// spill to the best available alternate.
    AirtimeFirst { primary: usize },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DcidRouterError {
    InvalidPacket,
    UnknownConnection,
    PathUnavailable,
    RouteTableFull,
}

/// Route short-header packets to fixed connection slots and retain path
/// liveness independently of those connections.
pub struct DcidRouter<const CONNECTIONS: usize, const PATHS: usize> {
    routes: [Option<ConnectionId>; CONNECTIONS],
    paths: [PathState; PATHS],
}

/// Fixed-capacity owner for per-connection state. The table deliberately
/// knows only DCIDs and bearer paths; `T` can be a mux, server handler state,
/// or a platform-specific peer binding. This keeps connection ownership out
/// of UART, UDP, and radio adapters while remaining no_std.
pub struct ConnectionTable<T, const CONNECTIONS: usize, const PATHS: usize> {
    entries: [Option<T>; CONNECTIONS],
    router: DcidRouter<CONNECTIONS, PATHS>,
    policy: PathPolicy,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectionTableError {
    Router(DcidRouterError),
    Occupied,
    Missing,
}

impl<T, const CONNECTIONS: usize, const PATHS: usize> ConnectionTable<T, CONNECTIONS, PATHS> {
    pub fn new(paths: [PathState; PATHS]) -> Self {
        Self {
            entries: core::array::from_fn(|_| None),
            router: DcidRouter::new(paths),
            policy: PathPolicy::HighestMeasuredSpeed,
        }
    }

    pub fn insert(&mut self, dcid: ConnectionId, value: T) -> Result<usize, ConnectionTableError> {
        let slot = self
            .router
            .register(dcid)
            .map_err(ConnectionTableError::Router)?;
        if self.entries[slot].is_some() {
            return Err(ConnectionTableError::Occupied);
        }
        self.entries[slot] = Some(value);
        Ok(slot)
    }

    /// Remove both the DCID route and its owned active connection state.
    /// Adapters retain any compact peer/association record separately, so a
    /// relay can free stream buffers without forgetting discovered peers.
    pub fn remove(&mut self, dcid: ConnectionId) -> Result<T, ConnectionTableError> {
        let Some(slot) = self
            .router
            .routes
            .iter()
            .position(|route| *route == Some(dcid))
        else {
            return Err(ConnectionTableError::Missing);
        };
        let value = self.entries[slot]
            .take()
            .ok_or(ConnectionTableError::Missing)?;
        let removed = self.router.remove(dcid);
        debug_assert!(removed);
        Ok(value)
    }

    pub fn get_mut(&mut self, slot: usize) -> Option<&mut T> {
        self.entries.get_mut(slot)?.as_mut()
    }

    pub fn len(&self) -> usize {
        self.entries.iter().filter(|entry| entry.is_some()).count()
    }

    pub fn iter(&self) -> impl Iterator<Item = (usize, &T)> {
        self.entries
            .iter()
            .enumerate()
            .filter_map(|(slot, entry)| entry.as_ref().map(|value| (slot, value)))
    }

    pub fn route_mut(
        &mut self,
        path: usize,
        packet: &[u8],
    ) -> Result<&mut T, ConnectionTableError> {
        let slot = self
            .router
            .route(path, packet)
            .map_err(ConnectionTableError::Router)?;
        self.entries
            .get_mut(slot)
            .and_then(Option::as_mut)
            .ok_or(ConnectionTableError::Missing)
    }

    pub fn set_path_available(
        &mut self,
        path: usize,
        available: bool,
    ) -> Result<(), ConnectionTableError> {
        self.router
            .set_path_available(path, available)
            .map_err(ConnectionTableError::Router)
    }

    pub fn set_path_capacity(
        &mut self,
        path: usize,
        capacity: PathCapacity,
    ) -> Result<(), ConnectionTableError> {
        self.router
            .set_path_capacity(path, capacity)
            .map_err(ConnectionTableError::Router)
    }

    pub fn set_policy(&mut self, policy: PathPolicy) {
        self.policy = policy;
    }

    pub fn select_outbound(&mut self, primary_full: bool) -> Result<usize, ConnectionTableError> {
        self.router
            .select_with_policy(self.policy, primary_full)
            .map_err(ConnectionTableError::Router)
    }

    pub fn select_probe(&mut self, now_us: u64, interval_us: u64) -> Option<usize> {
        self.router.select_probe(now_us, interval_us)
    }
}

impl<const CONNECTIONS: usize, const PATHS: usize> DcidRouter<CONNECTIONS, PATHS> {
    pub const fn new(paths: [PathState; PATHS]) -> Self {
        Self {
            routes: [None; CONNECTIONS],
            paths,
        }
    }

    pub fn set_path_available(
        &mut self,
        path: usize,
        available: bool,
    ) -> Result<(), DcidRouterError> {
        let Some(state) = self.paths.get_mut(path) else {
            return Err(DcidRouterError::PathUnavailable);
        };
        state.available = available;
        Ok(())
    }

    pub fn path(&self, path: usize) -> Option<PathState> {
        self.paths.get(path).copied()
    }

    /// Update adapter-provided immediate egress feedback. A zero capacity is
    /// an explicitly unknown/unbounded queue, not a full path.
    pub fn set_path_capacity(
        &mut self,
        path: usize,
        capacity: PathCapacity,
    ) -> Result<(), DcidRouterError> {
        let Some(state) = self.paths.get_mut(path) else {
            return Err(DcidRouterError::PathUnavailable);
        };
        state.capacity = capacity;
        Ok(())
    }

    /// Record an adapter-confirmed delivery sample. This is selection data;
    /// it does not alter QUIC-lite loss or retransmission state.
    pub fn record_path_sample(
        &mut self,
        path: usize,
        bytes: usize,
        elapsed_us: u64,
    ) -> Result<(), DcidRouterError> {
        let Some(state) = self.paths.get_mut(path) else {
            return Err(DcidRouterError::PathUnavailable);
        };
        if elapsed_us != 0 {
            let sample = (bytes as u64).saturating_div(elapsed_us).max(1);
            state.measured_bytes_per_us = if state.measured_bytes_per_us == 0 {
                sample
            } else {
                (state
                    .measured_bytes_per_us
                    .saturating_mul(3)
                    .saturating_add(sample))
                    / 4
            };
        }
        Ok(())
    }

    /// A bearer-level failure makes a path less preferable without mutating
    /// connection stream state.
    pub fn record_path_loss(&mut self, path: usize) -> Result<(), DcidRouterError> {
        let Some(state) = self.paths.get_mut(path) else {
            return Err(DcidRouterError::PathUnavailable);
        };
        state.loss_events = state.loss_events.saturating_add(1);
        state.measured_bytes_per_us = state.measured_bytes_per_us.saturating_div(2);
        Ok(())
    }

    pub fn register(&mut self, dcid: ConnectionId) -> Result<usize, DcidRouterError> {
        if let Some(index) = self.routes.iter().position(|route| *route == Some(dcid)) {
            return Ok(index);
        }
        let Some(index) = self.routes.iter().position(Option::is_none) else {
            return Err(DcidRouterError::RouteTableFull);
        };
        self.routes[index] = Some(dcid);
        Ok(index)
    }

    pub fn remove(&mut self, dcid: ConnectionId) -> bool {
        let Some(index) = self.routes.iter().position(|route| *route == Some(dcid)) else {
            return false;
        };
        self.routes[index] = None;
        true
    }

    pub fn route(&mut self, path: usize, packet: &[u8]) -> Result<usize, DcidRouterError> {
        let Some(state) = self.paths.get_mut(path) else {
            return Err(DcidRouterError::PathUnavailable);
        };
        if !state.available {
            return Err(DcidRouterError::PathUnavailable);
        }
        let (header, _) =
            ShortHeader::decode(packet).map_err(|_| DcidRouterError::InvalidPacket)?;
        let Some(index) = self
            .routes
            .iter()
            .position(|route| *route == Some(header.dcid))
        else {
            return Err(DcidRouterError::UnknownConnection);
        };
        state.received_packets = state.received_packets.saturating_add(1);
        Ok(index)
    }

    pub fn select_outbound(&mut self, preferred: usize) -> Result<usize, DcidRouterError> {
        let selected = self
            .paths
            .get(preferred)
            .filter(|state| state.available)
            .map(|_| preferred)
            .or_else(|| self.paths.iter().position(|state| state.available))
            .ok_or(DcidRouterError::PathUnavailable)?;
        self.paths[selected].sent_packets = self.paths[selected].sent_packets.saturating_add(1);
        Ok(selected)
    }

    /// Select an available bearer. `primary_full` is an adapter's immediate
    /// queue/credit observation, so services never wait on a full path.
    pub fn select_with_policy(
        &mut self,
        policy: PathPolicy,
        primary_full: bool,
    ) -> Result<usize, DcidRouterError> {
        let preferred = match policy {
            PathPolicy::Explicit(path) => Some(path),
            PathPolicy::AirtimeFirst { primary }
                if !primary_full
                    && self
                        .paths
                        .get(primary)
                        .is_some_and(|state| state.capacity.has_capacity()) =>
            {
                Some(primary)
            }
            PathPolicy::AirtimeFirst { .. } | PathPolicy::HighestMeasuredSpeed => self
                .paths
                .iter()
                .enumerate()
                .filter(|(_, state)| state.available)
                .max_by_key(|(_, state)| {
                    (
                        state.measured_bytes_per_us,
                        core::cmp::Reverse(state.loss_events),
                    )
                })
                .map(|(path, _)| path),
        };
        let selected = preferred
            .filter(|path| self.paths.get(*path).is_some_and(|state| state.available))
            .or_else(|| self.paths.iter().position(|state| state.available))
            .ok_or(DcidRouterError::PathUnavailable)?;
        self.paths[selected].sent_packets = self.paths[selected].sent_packets.saturating_add(1);
        Ok(selected)
    }

    /// Select one overdue live path for a normal small control/probe packet.
    /// Periodic probes restore measurements after a temporary bearer loss.
    pub fn select_probe(&mut self, now_us: u64, interval_us: u64) -> Option<usize> {
        let selected = self
            .paths
            .iter()
            .enumerate()
            .filter(|(_, state)| {
                state.available && now_us.saturating_sub(state.last_probe_us) >= interval_us
            })
            .min_by_key(|(_, state)| state.last_probe_us)
            .map(|(path, _)| path)?;
        self.paths[selected].last_probe_us = now_us;
        Some(selected)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FLAG_FIXED;

    #[test]
    fn routes_one_connection_across_available_paths_and_fails_over() {
        let cid = ConnectionId::new(42).unwrap();
        let mut router = DcidRouter::<2, 2>::new([PathState::new(), PathState::new()]);
        assert_eq!(router.register(cid), Ok(0));
        router.set_path_available(0, true).unwrap();
        router.set_path_available(1, true).unwrap();
        let mut packet = [0_u8; 16];
        let used = ShortHeader {
            flags: FLAG_FIXED,
            dcid: cid,
            packet_number: 1,
            packet_number_len: 1,
        }
        .encode(&mut packet)
        .unwrap();
        assert_eq!(router.route(0, &packet[..used]), Ok(0));
        assert_eq!(router.route(1, &packet[..used]), Ok(0));
        assert_eq!(router.select_outbound(0), Ok(0));
        router.set_path_available(0, false).unwrap();
        assert_eq!(router.select_outbound(0), Ok(1));
    }

    #[test]
    fn connection_table_removal_frees_a_dcid_slot() {
        let first = ConnectionId::new(41).unwrap();
        let second = ConnectionId::new(42).unwrap();
        let mut table = ConnectionTable::<u8, 1, 1>::new([PathState::new()]);
        assert_eq!(table.insert(first, 7), Ok(0));
        assert_eq!(table.remove(first), Ok(7));
        assert_eq!(table.len(), 0);
        assert_eq!(table.insert(second, 9), Ok(0));
    }

    #[test]
    fn path_policy_pins_compares_probes_and_restores_faster_path() {
        let mut router = DcidRouter::<1, 2>::new([PathState::new(), PathState::new()]);
        router.set_path_available(0, true).unwrap();
        router.set_path_available(1, true).unwrap();
        router.record_path_sample(0, 1000, 100).unwrap();
        router.record_path_sample(1, 2000, 100).unwrap();
        assert_eq!(
            router.select_with_policy(PathPolicy::Explicit(0), false),
            Ok(0)
        );
        assert_eq!(
            router.select_with_policy(PathPolicy::HighestMeasuredSpeed, false),
            Ok(1)
        );
        router.record_path_loss(1).unwrap();
        assert_eq!(router.select_probe(1_000, 500), Some(0));
        assert_eq!(router.select_probe(1_000, 500), Some(1));
        router.record_path_sample(1, 4_000, 100).unwrap();
        assert_eq!(
            router.select_with_policy(PathPolicy::HighestMeasuredSpeed, false),
            Ok(1)
        );
        assert_eq!(
            router.select_with_policy(PathPolicy::AirtimeFirst { primary: 0 }, true),
            Ok(1)
        );
    }

    #[test]
    fn connection_table_routes_payload_state_across_bearers() {
        let cid = ConnectionId::new(9).unwrap();
        let mut table = ConnectionTable::<u32, 2, 2>::new([PathState::new(), PathState::new()]);
        table.set_path_available(0, true).unwrap();
        table.set_path_available(1, true).unwrap();
        assert_eq!(table.insert(cid, 7), Ok(0));
        let packet = [FLAG_FIXED, 9, 0, 0];
        *table.route_mut(1, &packet).unwrap() = 8;
        assert_eq!(*table.get_mut(0).unwrap(), 8);
    }

    #[test]
    fn airtime_first_spills_when_primary_reports_full() {
        let mut router = DcidRouter::<1, 2>::new([PathState::new(), PathState::new()]);
        router.set_path_available(0, true).unwrap();
        router.set_path_available(1, true).unwrap();
        router.record_path_sample(1, 2_000, 100).unwrap();
        router
            .set_path_capacity(0, PathCapacity::new(8, 8))
            .unwrap();
        assert_eq!(
            router.select_with_policy(PathPolicy::AirtimeFirst { primary: 0 }, false),
            Ok(1)
        );
        router
            .set_path_capacity(0, PathCapacity::new(7, 8))
            .unwrap();
        assert_eq!(
            router.select_with_policy(PathPolicy::AirtimeFirst { primary: 0 }, false),
            Ok(0)
        );
    }
}
