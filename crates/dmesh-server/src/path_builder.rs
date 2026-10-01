//! Discovery-driven route selection above `quic-lite`.
//!
//! Discovery records are candidate routes, not trusted instructions. This
//! module merges those observations, rejects stale routes, applies local
//! reputation only to routes this endpoint built, and selects a route for an
//! explicit destination VIP. The caller performs CREATE/JOIN with the
//! selected hops through `QuicNode`; transport scheduling remains there.

use alloc::vec::Vec;

use quic_lite::{
    AssociationEvent, BearerId, CircuitId, CircuitStatus, NearbyRelayHints, PacketMeta, PacketPool,
    PeerL2Address, QuicAssociation, QuicNode, QuicNodeEgressError, RelayHop,
};

pub const MAX_RELAY_PATH_HINTS: usize = 64;
pub const MAX_RELAYS_PER_HINT: usize = 8;
pub const MAX_RELAY_REPUTATION_ENTRIES: usize = 256;
pub const MAX_TRACKED_ROUTE_USES: usize = 64;
pub const DEFAULT_RELAY_HINT_TTL_US: u64 = 30_000_000;
const MAX_RELAY_FAILURE_PENALTY_US: u64 = 250_000;

pub type RelayId = [u8; 8];
pub type DestinationVip = [u8; 8];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HintSource {
    LocalDiscovery,
    Directory,
    PeerSupplied,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouteMode {
    /// Send the complete ordered hop list in the layered setup transaction.
    Layered,
    /// Extend the route one hop at a time, preserving the same join identity.
    Telescoping,
    /// Ask the first gateway to route explicitly toward the destination VIP.
    VipRouted,
}

impl From<RouteMode> for quic_lite::RelayRouteMode {
    fn from(mode: RouteMode) -> Self {
        match mode {
            RouteMode::Layered => Self::Layered,
            RouteMode::Telescoping => Self::Telescoping,
            RouteMode::VipRouted => Self::VipRouted,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouteOwnership {
    /// The local endpoint selected and opened this relay chain.
    SelfBuilt,
    /// The peer selected this chain and advertised it to the local endpoint.
    PeerBuilt,
    /// A gateway or other router selected this chain.
    GatewayBuilt,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelayPathHint {
    pub destination: DestinationVip,
    /// A caller-stable key for explicit route selection and retry records.
    pub route_id: u64,
    /// Local observation time, in the planner's monotonic clock domain.
    pub observed_at_us: u64,
    /// Route expires after this age even if the discovery source retains it.
    pub ttl_us: u64,
    /// Discovery's initial estimate only; matched circuit measurements take
    /// over after the route carries traffic.
    pub estimated_rtt_us: u32,
    pub mode: RouteMode,
    pub ownership: RouteOwnership,
    pub source: HintSource,
    /// Optional local bearer and first-hop address selected by this route.
    /// When absent, the address supplied to `create` or `join` is used.
    pub egress: Option<RouteEgress>,
    pub relay_ids: Vec<RelayId>,
    pub hops: Vec<RelayHop>,
}

impl RelayPathHint {
    pub fn is_fresh_at(&self, now_us: u64) -> bool {
        now_us >= self.observed_at_us && now_us.saturating_sub(self.observed_at_us) <= self.ttl_us
    }

    fn same_route(&self, other: &Self) -> bool {
        self.destination == other.destination
            && self.route_id == other.route_id
            && self.mode == other.mode
            && self.ownership == other.ownership
            && self.egress == other.egress
            && self.relay_ids == other.relay_ids
            && self.hops == other.hops
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RouteEgress {
    pub bearer: BearerId,
    pub peer_l2_address: PeerL2Address,
}

impl RouteEgress {
    fn apply(self, mut address: PacketMeta, now_us: u64) -> PacketMeta {
        address.bearer = self.bearer;
        address.peer_l2_address = self.peer_l2_address;
        address.received_at_us = now_us;
        address
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HintError {
    EmptyRoute,
    TooManyHops,
    RelayHopCountMismatch,
    DuplicateRelay,
    InvalidHopAddress,
    FutureObservation,
    RouteIdConflict,
    Capacity,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RelayReputation {
    pub relay_id: RelayId,
    pub successful_paths: u32,
    pub failed_paths: u32,
}

impl RelayReputation {
    fn failure_penalty_us(self) -> u64 {
        if self.failed_paths == 0 {
            return 0;
        }
        let attempts =
            u64::from(self.successful_paths).saturating_add(u64::from(self.failed_paths));
        u64::from(self.failed_paths)
            .saturating_mul(MAX_RELAY_FAILURE_PENALTY_US)
            .checked_div(attempts.max(1))
            .unwrap_or(MAX_RELAY_FAILURE_PENALTY_US)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RouteRequest {
    pub destination: DestinationVip,
    /// If set, try this route first. When it is stale or has failed, fallback
    /// is an explicit caller choice rather than an implicit route rewrite.
    pub preferred_route_id: Option<u64>,
    pub allow_fallback: bool,
    /// Route excluded for this decision, for example after a reported failure.
    pub avoid_route_id: Option<u64>,
    pub now_us: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SelectionError {
    NoFreshRoute,
    PreferredRouteUnavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CircuitBuildError<E> {
    Selection(SelectionError),
    UnsupportedMode(SelectedRoute),
    TrackingCapacity,
    Setup { route: SelectedRoute, source: E },
}

/// Thin adapter used by the external planner to ask a `QuicNode` owner to
/// perform CREATE/JOIN. It carries selected hop instructions unchanged.
pub trait CircuitRuntime {
    type Association: Copy;
    type Circuit: Copy;
    type Error;

    /// Return the public QUIC association handle when this runtime exposes one.
    /// Policy-only adapters may leave the default untracked.
    fn quic_association(_association: Self::Association) -> Option<QuicAssociation> {
        None
    }

    /// Return the public QUIC circuit handle when this runtime exposes one.
    fn quic_circuit(_circuit: Self::Circuit) -> Option<CircuitId> {
        None
    }

    fn create_relayed(
        &mut self,
        address: PacketMeta,
        destination_vip: u64,
        mode: RouteMode,
        hops: &[RelayHop],
        return_hints: NearbyRelayHints,
        now_us: u64,
    ) -> Result<Self::Association, Self::Error>;

    fn join_relayed(
        &mut self,
        association: Self::Association,
        address: PacketMeta,
        destination_vip: u64,
        mode: RouteMode,
        hops: &[RelayHop],
        now_us: u64,
    ) -> Result<Self::Circuit, Self::Error>;
}

impl<P, const PACKET: usize> CircuitRuntime for QuicNode<P, PACKET>
where
    P: PacketPool + 'static,
    P::Buffer: Send,
{
    type Association = QuicAssociation;
    type Circuit = CircuitId;
    type Error = QuicNodeEgressError;

    fn quic_association(association: Self::Association) -> Option<QuicAssociation> {
        Some(association)
    }

    fn quic_circuit(circuit: Self::Circuit) -> Option<CircuitId> {
        Some(circuit)
    }

    fn create_relayed(
        &mut self,
        address: PacketMeta,
        destination_vip: u64,
        mode: RouteMode,
        hops: &[RelayHop],
        return_hints: NearbyRelayHints,
        now_us: u64,
    ) -> Result<Self::Association, Self::Error> {
        self.associate_relayed_with_route_mode(
            address,
            Some(destination_vip),
            hops,
            return_hints,
            mode.into(),
            now_us,
        )
    }

    fn join_relayed(
        &mut self,
        association: Self::Association,
        address: PacketMeta,
        destination_vip: u64,
        mode: RouteMode,
        hops: &[RelayHop],
        now_us: u64,
    ) -> Result<Self::Circuit, Self::Error> {
        self.join_relayed_path_with_route_mode(
            association,
            address,
            hops,
            mode.into(),
            Some(destination_vip),
            now_us,
        )
    }
}

impl<P, const PACKET: usize> CircuitRuntime for quic_lite::nostd::NoStdRuntime<P, PACKET>
where
    P: PacketPool + 'static,
    P::Buffer: Send,
{
    type Association = QuicAssociation;
    type Circuit = CircuitId;
    type Error = QuicNodeEgressError;

    fn quic_association(association: Self::Association) -> Option<QuicAssociation> {
        Some(association)
    }

    fn quic_circuit(circuit: Self::Circuit) -> Option<CircuitId> {
        Some(circuit)
    }

    fn create_relayed(
        &mut self,
        address: PacketMeta,
        destination_vip: u64,
        mode: RouteMode,
        hops: &[RelayHop],
        return_hints: NearbyRelayHints,
        now_us: u64,
    ) -> Result<Self::Association, Self::Error> {
        self.associate_relayed_with_route_mode(
            address,
            Some(destination_vip),
            hops,
            return_hints,
            mode.into(),
            now_us,
        )
    }

    fn join_relayed(
        &mut self,
        association: Self::Association,
        address: PacketMeta,
        destination_vip: u64,
        mode: RouteMode,
        hops: &[RelayHop],
        now_us: u64,
    ) -> Result<Self::Circuit, Self::Error> {
        self.join_relayed_path_with_route_mode(
            association,
            address,
            hops,
            mode.into(),
            Some(destination_vip),
            now_us,
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SelectedRoute {
    pub route_id: u64,
    pub estimated_cost_us: u64,
    pub mode: RouteMode,
    pub ownership: RouteOwnership,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RouteFailure {
    pub association: QuicAssociation,
    pub circuit: Option<CircuitId>,
    pub destination: DestinationVip,
    /// The event retired the association, so recovery must start a new CREATE.
    pub association_retired: bool,
    pub failed_route: SelectedRoute,
    pub replacement: Option<SelectedRoute>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouteEventOutcome {
    Ignored,
    CircuitOpened,
    CircuitHealthy { route_id: u64 },
    CircuitSuspended { route_id: u64 },
    CircuitClosed { route_id: u64 },
    AssociationClosed { association: QuicAssociation },
    Failed(RouteFailure),
    AmbiguousSetupFailure { association: QuicAssociation },
    EventsDropped { count: u64 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouteRecovery<A, C> {
    Observed(RouteEventOutcome),
    NoReplacement(RouteFailure),
    Created {
        failure: RouteFailure,
        association: A,
        route: SelectedRoute,
    },
    Joined {
        failure: RouteFailure,
        circuit: C,
        route: SelectedRoute,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RouteUse {
    association: QuicAssociation,
    circuit: Option<CircuitId>,
    association_create: bool,
    destination: DestinationVip,
    route_id: u64,
    mode: RouteMode,
    ownership: RouteOwnership,
    estimated_cost_us: u64,
    relay_ids: [RelayId; MAX_RELAYS_PER_HINT],
    relay_count: u8,
    healthy: bool,
    success_recorded: bool,
    failed: bool,
}

impl RouteUse {
    fn selected_route(self) -> SelectedRoute {
        SelectedRoute {
            route_id: self.route_id,
            estimated_cost_us: self.estimated_cost_us,
            mode: self.mode,
            ownership: self.ownership,
        }
    }
}

/// Device-local route hints and reputation, retained across associations by
/// the owner that keeps this value alive. All capacities are explicit.
pub struct PathBuilder {
    hints: Vec<RelayPathHint>,
    reputation: Vec<RelayReputation>,
    route_uses: Vec<RouteUse>,
    hop_cost_us: u64,
}

impl Default for PathBuilder {
    fn default() -> Self {
        Self::new(10_000)
    }
}

impl PathBuilder {
    pub fn new(hop_cost_us: u64) -> Self {
        Self {
            hints: Vec::new(),
            reputation: Vec::new(),
            route_uses: Vec::new(),
            hop_cost_us,
        }
    }

    pub fn hint_count(&self) -> usize {
        self.hints.len()
    }

    pub fn merge_hint(&mut self, mut hint: RelayPathHint, now_us: u64) -> Result<(), HintError> {
        validate_hint(&hint)?;
        if hint.observed_at_us > now_us {
            return Err(HintError::FutureObservation);
        }
        self.expire_stale(now_us);
        hint.ttl_us = hint.ttl_us.min(DEFAULT_RELAY_HINT_TTL_US);
        if self.hints.iter().any(|entry| {
            entry.destination == hint.destination
                && entry.route_id == hint.route_id
                && !entry.same_route(&hint)
        }) {
            return Err(HintError::RouteIdConflict);
        }
        if let Some(existing) = self.hints.iter_mut().find(|entry| entry.same_route(&hint)) {
            if hint.observed_at_us >= existing.observed_at_us {
                *existing = hint;
            }
            return Ok(());
        }
        if self.hints.len() == MAX_RELAY_PATH_HINTS {
            return Err(HintError::Capacity);
        }
        self.hints.push(hint);
        Ok(())
    }

    /// Remove discovery routes whose local observation TTL has elapsed.
    pub fn expire_stale(&mut self, now_us: u64) -> usize {
        let before = self.hints.len();
        self.hints.retain(|hint| hint.is_fresh_at(now_us));
        before - self.hints.len()
    }

    pub fn select(&self, request: RouteRequest) -> Result<SelectedRoute, SelectionError> {
        self.candidate_routes(request)?
            .first()
            .copied()
            .ok_or(SelectionError::NoFreshRoute)
    }

    fn candidate_routes(
        &self,
        request: RouteRequest,
    ) -> Result<Vec<SelectedRoute>, SelectionError> {
        let mut candidates = Vec::new();
        for hint in &self.hints {
            if hint.destination != request.destination || !hint.is_fresh_at(request.now_us) {
                continue;
            }
            if request.avoid_route_id == Some(hint.route_id) {
                continue;
            }
            candidates.push(SelectedRoute {
                route_id: hint.route_id,
                estimated_cost_us: self.estimated_cost_us(hint),
                mode: hint.mode,
                ownership: hint.ownership,
            });
        }
        candidates.sort_by_key(|candidate| (candidate.estimated_cost_us, candidate.route_id));
        if let Some(preferred) = request.preferred_route_id {
            if let Some(index) = candidates
                .iter()
                .position(|candidate| candidate.route_id == preferred)
            {
                let route = candidates.remove(index);
                candidates.insert(0, route);
            } else if !request.allow_fallback {
                return Err(SelectionError::PreferredRouteUnavailable);
            }
        }
        if !request.allow_fallback {
            candidates.truncate(1);
        }
        if candidates.is_empty() {
            return Err(SelectionError::NoFreshRoute);
        }
        Ok(candidates)
    }

    /// Open a client association over the selected route, trying
    /// ranked fallback hints only when the request permits fallback.
    pub fn create<R: CircuitRuntime>(
        &mut self,
        runtime: &mut R,
        request: RouteRequest,
        address: PacketMeta,
        return_hints: NearbyRelayHints,
    ) -> Result<(R::Association, SelectedRoute), CircuitBuildError<R::Error>> {
        let candidates = self
            .candidate_routes(request)
            .map_err(CircuitBuildError::Selection)?;
        if self.route_uses.len() == MAX_TRACKED_ROUTE_USES {
            return Err(CircuitBuildError::TrackingCapacity);
        }
        let mut last_setup_error = None;
        let mut unsupported_route = None;
        for candidate in candidates {
            let hint = self
                .hint(request.destination, candidate.route_id)
                .expect("candidate route was read from the retained hint table");
            if candidate.mode == RouteMode::Telescoping && hint.hops.len() != 1 {
                unsupported_route = Some(candidate);
                continue;
            }
            match runtime.create_relayed(
                hint.egress
                    .map_or(address, |egress| egress.apply(address, request.now_us)),
                u64::from_be_bytes(request.destination),
                candidate.mode,
                &hint.hops,
                return_hints,
                request.now_us,
            ) {
                Ok(association) => {
                    if let Some(association_handle) = R::quic_association(association) {
                        self.route_uses.push(Self::make_route_use(
                            association_handle,
                            None,
                            true,
                            &hint,
                            candidate,
                        ));
                    }
                    return Ok((association, candidate));
                }
                Err(source) => last_setup_error = Some((candidate, source)),
            }
        }
        if let Some((route, source)) = last_setup_error {
            return Err(CircuitBuildError::Setup { route, source });
        }
        Err(CircuitBuildError::UnsupportedMode(
            unsupported_route.expect("candidate set is nonempty"),
        ))
    }

    /// Add a circuit to an existing association using the selected route. A
    /// caller records the eventual setup/data result against the
    /// returned route ID after QuicNode reports it.
    pub fn join<R: CircuitRuntime>(
        &mut self,
        runtime: &mut R,
        request: RouteRequest,
        association: R::Association,
        address: PacketMeta,
    ) -> Result<(R::Circuit, SelectedRoute), CircuitBuildError<R::Error>> {
        let candidates = self
            .candidate_routes(request)
            .map_err(CircuitBuildError::Selection)?;
        if self.route_uses.len() == MAX_TRACKED_ROUTE_USES {
            return Err(CircuitBuildError::TrackingCapacity);
        }
        let mut last_setup_error = None;
        let mut unsupported_route = None;
        for candidate in candidates {
            let hint = self
                .hint(request.destination, candidate.route_id)
                .expect("candidate route was read from the retained hint table");
            if candidate.mode == RouteMode::Telescoping && hint.hops.len() != 1 {
                unsupported_route = Some(candidate);
                continue;
            }
            let address = hint
                .egress
                .map_or(address, |egress| egress.apply(address, request.now_us));
            match runtime.join_relayed(
                association,
                address,
                u64::from_be_bytes(request.destination),
                candidate.mode,
                &hint.hops,
                request.now_us,
            ) {
                Ok(circuit) => {
                    if let (Some(association_handle), Some(circuit_handle)) =
                        (R::quic_association(association), R::quic_circuit(circuit))
                    {
                        self.route_uses.push(Self::make_route_use(
                            association_handle,
                            Some(circuit_handle),
                            false,
                            &hint,
                            candidate,
                        ));
                    }
                    return Ok((circuit, candidate));
                }
                Err(source) => last_setup_error = Some((candidate, source)),
            }
        }
        if let Some((route, source)) = last_setup_error {
            return Err(CircuitBuildError::Setup { route, source });
        }
        Err(CircuitBuildError::UnsupportedMode(
            unsupported_route.expect("candidate set is nonempty"),
        ))
    }

    /// Record a circuit result. Failures are attributed only to relays unique
    /// to the failed circuit while another healthy self-built circuit exists;
    /// shared relays are penalized once all observed routes through them fail.
    /// Peer- and gateway-built paths never write local relay reputation.
    pub fn record_result(
        &mut self,
        destination: DestinationVip,
        route_id: u64,
        succeeded: bool,
        healthy_self_built_route_ids: &[u64],
    ) -> bool {
        let Some(hint) = self
            .hints
            .iter()
            .find(|hint| hint.destination == destination && hint.route_id == route_id)
        else {
            return false;
        };
        if hint.ownership != RouteOwnership::SelfBuilt {
            return false;
        }
        let relay_ids = hint.relay_ids.clone();
        let healthy_relays = self
            .hints
            .iter()
            .filter(|route| {
                route.destination == destination
                    && route.ownership == RouteOwnership::SelfBuilt
                    && healthy_self_built_route_ids.contains(&route.route_id)
            })
            .flat_map(|route| route.relay_ids.iter().copied())
            .collect::<Vec<_>>();
        for relay_id in relay_ids {
            if !succeeded && healthy_relays.contains(&relay_id) {
                continue;
            }
            if let Some(entry) = self
                .reputation
                .iter_mut()
                .find(|entry| entry.relay_id == relay_id)
            {
                if succeeded {
                    entry.successful_paths = entry.successful_paths.saturating_add(1);
                } else {
                    entry.failed_paths = entry.failed_paths.saturating_add(1);
                }
            } else if self.reputation.len() < MAX_RELAY_REPUTATION_ENTRIES {
                self.reputation.push(RelayReputation {
                    relay_id,
                    successful_paths: u32::from(succeeded),
                    failed_paths: u32::from(!succeeded),
                });
            }
        }
        true
    }

    /// Apply a failed self-built path result and choose a different fresh
    /// candidate for the same destination.
    pub fn report_failure_and_select_replacement(
        &mut self,
        destination: DestinationVip,
        failed_route_id: u64,
        healthy_self_built_route_ids: &[u64],
        now_us: u64,
    ) -> Result<SelectedRoute, SelectionError> {
        if !self.record_result(
            destination,
            failed_route_id,
            false,
            healthy_self_built_route_ids,
        ) {
            return Err(SelectionError::PreferredRouteUnavailable);
        }
        self.select(RouteRequest {
            destination,
            preferred_route_id: Some(failed_route_id),
            allow_fallback: true,
            avoid_route_id: Some(failed_route_id),
            now_us,
        })
    }

    /// Consume public lifecycle events and map them back to selected routes.
    /// A failed route updates local reputation when it was self-built and
    /// returns a fresh replacement candidate, if one is currently available.
    pub fn observe_event(&mut self, event: AssociationEvent, now_us: u64) -> RouteEventOutcome {
        match event {
            AssociationEvent::CircuitOpened {
                association,
                circuit,
            } => {
                if let Some(route_use) = self
                    .route_uses
                    .iter_mut()
                    .find(|route| route.association == association && route.circuit.is_none())
                {
                    route_use.circuit = Some(circuit);
                    RouteEventOutcome::CircuitOpened
                } else {
                    RouteEventOutcome::Ignored
                }
            }
            AssociationEvent::CircuitStatusChanged {
                association: _,
                circuit,
                status,
            } => {
                let Some(index) = self
                    .route_uses
                    .iter()
                    .position(|route| route.circuit == Some(circuit))
                else {
                    return RouteEventOutcome::Ignored;
                };
                match status {
                    CircuitStatus::Active | CircuitStatus::Standby => {
                        let should_record = !self.route_uses[index].success_recorded;
                        self.route_uses[index].healthy = true;
                        self.route_uses[index].success_recorded = true;
                        if should_record {
                            let route_use = self.route_uses[index];
                            self.record_route_use_result(route_use, true);
                        }
                        RouteEventOutcome::CircuitHealthy {
                            route_id: self.route_uses[index].route_id,
                        }
                    }
                    CircuitStatus::Suspended | CircuitStatus::Probing => {
                        self.route_uses[index].healthy = false;
                        RouteEventOutcome::CircuitSuspended {
                            route_id: self.route_uses[index].route_id,
                        }
                    }
                    CircuitStatus::Failed => {
                        self.fail_route_use_with_lifecycle(index, now_us, false)
                    }
                    CircuitStatus::Opening | CircuitStatus::Closed => {
                        self.route_uses[index].healthy = false;
                        RouteEventOutcome::Ignored
                    }
                }
            }
            AssociationEvent::CircuitClosed {
                association: _,
                circuit,
            } => {
                if let Some(index) = self
                    .route_uses
                    .iter()
                    .position(|route| route.circuit == Some(circuit))
                {
                    let route_id = self.route_uses[index].route_id;
                    self.route_uses.remove(index);
                    RouteEventOutcome::CircuitClosed { route_id }
                } else {
                    RouteEventOutcome::Ignored
                }
            }
            AssociationEvent::Closed { association, .. }
            | AssociationEvent::Reset { association }
            | AssociationEvent::IdleTimeout { association } => {
                self.route_uses
                    .retain(|route| route.association != association);
                RouteEventOutcome::AssociationClosed { association }
            }
            AssociationEvent::SetupTimeout { association } => {
                let mut pending = self.route_uses.iter().enumerate().filter(|(_, route)| {
                    route.association == association && route.association_create && !route.failed
                });
                let Some((index, _)) = pending.next() else {
                    return RouteEventOutcome::Ignored;
                };
                if pending.next().is_some() {
                    return RouteEventOutcome::AmbiguousSetupFailure { association };
                }
                self.fail_route_use_with_lifecycle(index, now_us, true)
            }
            AssociationEvent::SetupRejected {
                association,
                circuit,
                association_retired,
                ..
            } => {
                let index = if let Some(circuit) = circuit {
                    self.route_uses
                        .iter()
                        .position(|route| route.circuit == Some(circuit) && !route.failed)
                } else {
                    self.route_uses.iter().position(|route| {
                        route.association == association
                            && route.association_create
                            && !route.failed
                    })
                };
                let Some(index) = index else {
                    return RouteEventOutcome::Ignored;
                };
                self.fail_route_use_with_lifecycle(index, now_us, association_retired)
            }
            AssociationEvent::EventsDropped { count } => RouteEventOutcome::EventsDropped { count },
            AssociationEvent::PeerReturnPathHints { .. } => RouteEventOutcome::Ignored,
        }
    }

    fn make_route_use(
        association: QuicAssociation,
        circuit: Option<CircuitId>,
        association_create: bool,
        hint: &RelayPathHint,
        selected: SelectedRoute,
    ) -> RouteUse {
        let mut relay_ids = [[0u8; 8]; MAX_RELAYS_PER_HINT];
        for (index, relay_id) in hint.relay_ids.iter().enumerate() {
            relay_ids[index] = *relay_id;
        }
        RouteUse {
            association,
            circuit,
            association_create,
            destination: hint.destination,
            route_id: hint.route_id,
            mode: selected.mode,
            ownership: hint.ownership,
            estimated_cost_us: selected.estimated_cost_us,
            relay_ids,
            relay_count: hint.relay_ids.len() as u8,
            healthy: false,
            success_recorded: false,
            failed: false,
        }
    }

    fn fail_route_use_with_lifecycle(
        &mut self,
        index: usize,
        now_us: u64,
        association_retired: bool,
    ) -> RouteEventOutcome {
        if self.route_uses[index].failed {
            return RouteEventOutcome::Ignored;
        }
        let route_use = self.route_uses[index];
        self.route_uses[index].healthy = false;
        self.route_uses[index].failed = true;
        self.record_route_use_result(route_use, false);
        let replacement = self
            .select(RouteRequest {
                destination: route_use.destination,
                preferred_route_id: None,
                allow_fallback: true,
                avoid_route_id: Some(route_use.route_id),
                now_us,
            })
            .ok();
        RouteEventOutcome::Failed(RouteFailure {
            association: route_use.association,
            circuit: route_use.circuit,
            destination: route_use.destination,
            association_retired,
            failed_route: route_use.selected_route(),
            replacement,
        })
    }

    /// Consume a lifecycle event and immediately build its replacement path.
    /// Failed live circuits JOIN the alternate on the same association;
    /// rejected or timed-out CREATE attempts open a new association.
    pub fn recover_event<R>(
        &mut self,
        runtime: &mut R,
        event: AssociationEvent,
        address: PacketMeta,
        return_hints: NearbyRelayHints,
        now_us: u64,
    ) -> Result<RouteRecovery<R::Association, R::Circuit>, CircuitBuildError<R::Error>>
    where
        R: CircuitRuntime<Association = QuicAssociation, Circuit = CircuitId>,
    {
        let outcome = self.observe_event(event, now_us);
        let RouteEventOutcome::Failed(failure) = outcome else {
            return Ok(RouteRecovery::Observed(outcome));
        };
        let Some(replacement) = failure.replacement else {
            return Ok(RouteRecovery::NoReplacement(failure));
        };
        let request = RouteRequest {
            destination: failure.destination,
            preferred_route_id: Some(replacement.route_id),
            allow_fallback: true,
            avoid_route_id: Some(failure.failed_route.route_id),
            now_us,
        };
        if failure.association_retired {
            let (association, route) = self.create(runtime, request, address, return_hints)?;
            Ok(RouteRecovery::Created {
                failure,
                association,
                route,
            })
        } else {
            let (circuit, route) = self.join(runtime, request, failure.association, address)?;
            Ok(RouteRecovery::Joined {
                failure,
                circuit,
                route,
            })
        }
    }

    fn record_route_use_result(&mut self, route_use: RouteUse, succeeded: bool) {
        if route_use.ownership != RouteOwnership::SelfBuilt {
            return;
        }
        for relay_id in route_use.relay_ids[..usize::from(route_use.relay_count)]
            .iter()
            .copied()
        {
            let shared_with_healthy_route = !succeeded
                && self.route_uses.iter().any(|other| {
                    other.destination == route_use.destination
                        && other.ownership == RouteOwnership::SelfBuilt
                        && other.healthy
                        && (other.association != route_use.association
                            || other.circuit != route_use.circuit)
                        && other.relay_ids[..usize::from(other.relay_count)].contains(&relay_id)
                });
            if shared_with_healthy_route {
                continue;
            }
            if let Some(entry) = self
                .reputation
                .iter_mut()
                .find(|entry| entry.relay_id == relay_id)
            {
                if succeeded {
                    entry.successful_paths = entry.successful_paths.saturating_add(1);
                } else {
                    entry.failed_paths = entry.failed_paths.saturating_add(1);
                }
            } else if self.reputation.len() < MAX_RELAY_REPUTATION_ENTRIES {
                self.reputation.push(RelayReputation {
                    relay_id,
                    successful_paths: u32::from(succeeded),
                    failed_paths: u32::from(!succeeded),
                });
            }
        }
    }

    pub fn reputation(&self, relay_id: RelayId) -> Option<RelayReputation> {
        self.reputation
            .iter()
            .find(|entry| entry.relay_id == relay_id)
            .copied()
    }

    pub fn hint(&self, destination: DestinationVip, route_id: u64) -> Option<&RelayPathHint> {
        self.hints
            .iter()
            .find(|hint| hint.destination == destination && hint.route_id == route_id)
    }

    fn estimated_cost_us(&self, hint: &RelayPathHint) -> u64 {
        let relay_penalty = hint.relay_ids.iter().fold(0u64, |total, relay_id| {
            let penalty = self
                .reputation(*relay_id)
                .map_or(0, RelayReputation::failure_penalty_us);
            total.saturating_add(penalty)
        });
        u64::from(hint.estimated_rtt_us)
            .saturating_add(self.hop_cost_us.saturating_mul(hint.hops.len() as u64))
            .saturating_add(relay_penalty)
    }
}

fn validate_hint(hint: &RelayPathHint) -> Result<(), HintError> {
    if hint.hops.is_empty() || hint.relay_ids.is_empty() {
        return Err(HintError::EmptyRoute);
    }
    if hint.hops.len() > MAX_RELAYS_PER_HINT || hint.relay_ids.len() > MAX_RELAYS_PER_HINT {
        return Err(HintError::TooManyHops);
    }
    if hint.hops.len() != hint.relay_ids.len() {
        return Err(HintError::RelayHopCountMismatch);
    }
    for (index, relay_id) in hint.relay_ids.iter().enumerate() {
        if hint.relay_ids[..index].contains(relay_id) {
            return Err(HintError::DuplicateRelay);
        }
    }
    if hint
        .hops
        .iter()
        .any(|hop| hop.address_len == 0 || hop.address_len as usize > hop.address.len())
    {
        return Err(HintError::InvalidHopAddress);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hint(route_id: u64, relay_ids: &[u8], observed_at_us: u64, rtt_us: u32) -> RelayPathHint {
        RelayPathHint {
            destination: [0xd0; 8],
            route_id,
            observed_at_us,
            ttl_us: 5_000_000,
            estimated_rtt_us: rtt_us,
            mode: RouteMode::Layered,
            ownership: RouteOwnership::SelfBuilt,
            source: HintSource::LocalDiscovery,
            egress: None,
            relay_ids: relay_ids.iter().map(|value| [*value; 8]).collect(),
            hops: relay_ids
                .iter()
                .map(|value| RelayHop::new(1, &[*value], 60_000_000, 1024).unwrap())
                .collect(),
        }
    }

    fn request(preferred_route_id: Option<u64>, allow_fallback: bool, now_us: u64) -> RouteRequest {
        RouteRequest {
            destination: [0xd0; 8],
            preferred_route_id,
            allow_fallback,
            avoid_route_id: None,
            now_us,
        }
    }

    #[derive(Default)]
    struct MockCircuitRuntime {
        fail_address: Option<u8>,
        attempted_addresses: Vec<u8>,
        attempted_bearers: Vec<u16>,
        attempted_peers: Vec<u64>,
        attempted_modes: Vec<RouteMode>,
        observed_vip: Option<u64>,
    }

    impl CircuitRuntime for MockCircuitRuntime {
        type Association = u32;
        type Circuit = u16;
        type Error = u8;

        fn create_relayed(
            &mut self,
            address: PacketMeta,
            destination_vip: u64,
            mode: RouteMode,
            hops: &[RelayHop],
            _return_hints: NearbyRelayHints,
            _now_us: u64,
        ) -> Result<Self::Association, Self::Error> {
            let hop_address = hops[0].address[0];
            self.attempted_addresses.push(hop_address);
            self.attempted_bearers.push(address.bearer.value());
            self.attempted_peers.push(address.peer_l2_address.value());
            self.attempted_modes.push(mode);
            self.observed_vip = Some(destination_vip);
            if self.fail_address == Some(hop_address) {
                Err(hop_address)
            } else {
                Ok(41)
            }
        }

        fn join_relayed(
            &mut self,
            _association: Self::Association,
            address: PacketMeta,
            _destination_vip: u64,
            mode: RouteMode,
            hops: &[RelayHop],
            _now_us: u64,
        ) -> Result<Self::Circuit, Self::Error> {
            let hop_address = hops[0].address[0];
            self.attempted_addresses.push(hop_address);
            self.attempted_bearers.push(address.bearer.value());
            self.attempted_peers.push(address.peer_l2_address.value());
            self.attempted_modes.push(mode);
            if self.fail_address == Some(hop_address) {
                Err(hop_address)
            } else {
                Ok(hop_address as u16)
            }
        }
    }

    fn packet_meta() -> PacketMeta {
        PacketMeta {
            bearer: quic_lite::BearerId::new(1).unwrap(),
            peer_l2_address: quic_lite::PeerL2Address::new(1).unwrap(),
            received_at_us: 10,
        }
    }

    #[test]
    fn merge_replaces_stale_discovery_route_and_fallback_is_explicit() {
        let mut builder = PathBuilder::default();
        builder.merge_hint(hint(1, &[1], 0, 10_000), 0).unwrap();
        builder
            .merge_hint(hint(2, &[2], 4_000_000, 20_000), 4_000_000)
            .unwrap();

        assert_eq!(
            builder.select(request(Some(1), false, 6_000_000)),
            Err(SelectionError::PreferredRouteUnavailable)
        );
        assert_eq!(
            builder
                .select(request(Some(1), true, 6_000_000))
                .unwrap()
                .route_id,
            2
        );
    }

    #[test]
    fn dropping_route_reduces_its_rank_and_selects_a_replacement() {
        let mut builder = PathBuilder::default();
        let fast = hint(1, &[1], 1, 5_000);
        let alternate = hint(2, &[2], 1, 25_000);
        builder.merge_hint(fast.clone(), 1).unwrap();
        builder.merge_hint(alternate, 1).unwrap();
        assert_eq!(builder.select(request(None, true, 2)).unwrap().route_id, 1);

        assert_eq!(
            builder
                .report_failure_and_select_replacement(fast.destination, fast.route_id, &[], 2)
                .unwrap()
                .route_id,
            2
        );
        assert_eq!(builder.reputation([1; 8]).unwrap().failed_paths, 1);
    }

    #[test]
    fn create_executes_preferred_route_then_uses_explicit_fallback() {
        let mut builder = PathBuilder::default();
        let mut primary = hint(1, &[1], 1, 5_000);
        primary.egress = Some(RouteEgress {
            bearer: quic_lite::BearerId::new(2).unwrap(),
            peer_l2_address: quic_lite::PeerL2Address::new(11).unwrap(),
        });
        let mut alternate = hint(2, &[2], 1, 20_000);
        alternate.egress = Some(RouteEgress {
            bearer: quic_lite::BearerId::new(3).unwrap(),
            peer_l2_address: quic_lite::PeerL2Address::new(12).unwrap(),
        });
        builder.merge_hint(primary, 1).unwrap();
        builder.merge_hint(alternate, 1).unwrap();
        let mut runtime = MockCircuitRuntime {
            fail_address: Some(1),
            ..Default::default()
        };
        let (association, selected) = builder
            .create(
                &mut runtime,
                request(Some(1), true, 2),
                packet_meta(),
                NearbyRelayHints::EMPTY,
            )
            .unwrap();
        assert_eq!(association, 41);
        assert_eq!(runtime.attempted_addresses, [1, 2]);
        assert_eq!(runtime.attempted_bearers, [2, 3]);
        assert_eq!(runtime.attempted_peers, [11, 12]);
        assert_eq!(runtime.observed_vip, Some(u64::from_be_bytes([0xd0; 8])));
        assert_eq!(selected.route_id, 2);

        runtime.attempted_addresses.clear();
        assert_eq!(
            builder.create(
                &mut runtime,
                request(Some(1), false, 2),
                packet_meta(),
                NearbyRelayHints::EMPTY,
            ),
            Err(CircuitBuildError::Setup {
                route: SelectedRoute {
                    route_id: 1,
                    estimated_cost_us: 15_000,
                    mode: RouteMode::Layered,
                    ownership: RouteOwnership::SelfBuilt,
                },
                source: 1,
            })
        );
        assert_eq!(runtime.attempted_addresses, [1]);
    }

    #[test]
    fn vip_routed_create_and_join_preserve_the_selected_mode_and_destination() {
        let mut builder = PathBuilder::default();
        let mut vip_route = hint(9, &[9], 1, 8_000);
        vip_route.mode = RouteMode::VipRouted;
        builder.merge_hint(vip_route, 1).unwrap();
        let mut runtime = MockCircuitRuntime::default();

        let (association, selected) = builder
            .create(
                &mut runtime,
                request(Some(9), false, 2),
                packet_meta(),
                NearbyRelayHints::EMPTY,
            )
            .unwrap();
        assert_eq!(association, 41);
        assert_eq!(selected.mode, RouteMode::VipRouted);
        assert_eq!(runtime.attempted_modes, [RouteMode::VipRouted]);
        assert_eq!(runtime.observed_vip, Some(u64::from_be_bytes([0xd0; 8])));

        runtime.attempted_modes.clear();
        let (circuit, selected) = builder
            .join(
                &mut runtime,
                request(Some(9), false, 3),
                association,
                packet_meta(),
            )
            .unwrap();
        assert_eq!(circuit, 9);
        assert_eq!(selected.mode, RouteMode::VipRouted);
        assert_eq!(runtime.attempted_modes, [RouteMode::VipRouted]);
    }

    #[test]
    fn telescoping_route_reaches_runtime_with_its_route_namespace() {
        let mut builder = PathBuilder::default();
        let mut route = hint(10, &[10], 1, 8_000);
        route.mode = RouteMode::Telescoping;
        builder.merge_hint(route, 1).unwrap();
        let mut runtime = MockCircuitRuntime::default();

        let (association, selected) = builder
            .create(
                &mut runtime,
                request(Some(10), false, 2),
                packet_meta(),
                NearbyRelayHints::EMPTY,
            )
            .unwrap();
        assert_eq!(association, 41);
        assert_eq!(selected.mode, RouteMode::Telescoping);
        assert_eq!(runtime.attempted_modes, [RouteMode::Telescoping]);
        assert_eq!(runtime.attempted_addresses, [10]);
    }

    #[test]
    fn join_executes_the_selected_path_on_the_existing_association() {
        let mut builder = PathBuilder::default();
        builder.merge_hint(hint(1, &[1], 1, 20_000), 1).unwrap();
        let mut alternate = hint(2, &[2], 1, 10_000);
        alternate.egress = Some(RouteEgress {
            bearer: quic_lite::BearerId::new(3).unwrap(),
            peer_l2_address: quic_lite::PeerL2Address::new(12).unwrap(),
        });
        builder.merge_hint(alternate, 1).unwrap();
        let mut runtime = MockCircuitRuntime::default();
        let (circuit, selected) = builder
            .join(&mut runtime, request(None, false, 2), 41, packet_meta())
            .unwrap();
        assert_eq!(circuit, 2);
        assert_eq!(selected.route_id, 2);
        assert_eq!(runtime.attempted_addresses, [2]);
        assert_eq!(runtime.attempted_bearers, [3]);
        assert_eq!(runtime.attempted_peers, [12]);
    }

    #[test]
    fn peer_and_gateway_routes_do_not_change_self_built_reputation() {
        let mut builder = PathBuilder::default();
        let mut peer_route = hint(1, &[1], 1, 5_000);
        peer_route.ownership = RouteOwnership::PeerBuilt;
        builder.merge_hint(peer_route.clone(), 1).unwrap();
        assert!(!builder.record_result(peer_route.destination, peer_route.route_id, false, &[]));
        let mut gateway_route = hint(2, &[2], 1, 5_000);
        gateway_route.ownership = RouteOwnership::GatewayBuilt;
        builder.merge_hint(gateway_route.clone(), 1).unwrap();
        assert!(!builder.record_result(
            gateway_route.destination,
            gateway_route.route_id,
            false,
            &[]
        ));
        assert_eq!(builder.reputation([1; 8]), None);
        assert_eq!(builder.reputation([2; 8]), None);
    }

    #[test]
    fn healthy_route_prevents_penalty_for_a_shared_relay() {
        let mut builder = PathBuilder::default();
        let failed = hint(1, &[1, 2], 1, 5_000);
        let healthy = hint(2, &[1, 3], 1, 20_000);
        builder.merge_hint(failed.clone(), 1).unwrap();
        builder.merge_hint(healthy, 1).unwrap();
        assert!(builder.record_result(failed.destination, failed.route_id, false, &[2]));
        assert_eq!(builder.reputation([1; 8]), None);
        assert_eq!(builder.reputation([2; 8]).unwrap().failed_paths, 1);
    }

    #[test]
    fn hints_reject_invalid_hop_sets_and_enforce_table_capacity() {
        let mut builder = PathBuilder::default();
        let mut invalid = hint(1, &[1], 1, 5_000);
        invalid.relay_ids.push([2; 8]);
        assert_eq!(
            builder.merge_hint(invalid, 1),
            Err(HintError::RelayHopCountMismatch)
        );

        for route_id in 0..MAX_RELAY_PATH_HINTS as u64 {
            builder
                .merge_hint(hint(route_id, &[route_id as u8 + 1], 1, 5_000), 1)
                .unwrap();
        }
        assert_eq!(builder.hint_count(), MAX_RELAY_PATH_HINTS);
        assert_eq!(
            builder.merge_hint(hint(99, &[99], 1, 5_000), 1),
            Err(HintError::Capacity)
        );
        assert_eq!(builder.expire_stale(5_000_002), MAX_RELAY_PATH_HINTS);
        builder
            .merge_hint(hint(99, &[99], 5_000_002, 5_000), 5_000_002)
            .unwrap();
        assert_eq!(builder.hint_count(), 1);
    }

    #[test]
    fn future_observations_and_conflicting_route_ids_are_rejected() {
        let mut builder = PathBuilder::default();
        assert_eq!(
            builder.merge_hint(hint(1, &[1], 2, 5_000), 1),
            Err(HintError::FutureObservation)
        );
        builder.merge_hint(hint(1, &[1], 1, 5_000), 1).unwrap();
        assert_eq!(
            builder.merge_hint(hint(1, &[2], 2, 5_000), 2),
            Err(HintError::RouteIdConflict)
        );
        let mut mode_conflict = hint(1, &[1], 2, 5_000);
        mode_conflict.mode = RouteMode::VipRouted;
        assert_eq!(
            builder.merge_hint(mode_conflict, 2),
            Err(HintError::RouteIdConflict)
        );
    }

    #[cfg(feature = "std")]
    #[test]
    fn public_bearer_setup_timeout_selects_and_submits_replacement_route() {
        use quic_lite::fake::{FakeLinkProfile, FakeNetworkConfig, FakePacketBearer};
        use quic_lite::heap_packet_pool::HeapPacketPool;
        use quic_lite::{BearerName, ConnectionLimits};

        type Pool = HeapPacketPool<48, { quic_lite::DEFAULT_PACKET_POOL_SLOT_SIZE }>;
        static CLIENT_POOL: Pool = Pool::new();
        static RELAY_POOL: Pool = Pool::new();
        CLIENT_POOL.resize(48).unwrap();
        RELAY_POOL.resize(48).unwrap();

        let (primary_bearer, primary_relay_bearer, mut primary_network) =
            FakePacketBearer::<Pool>::pair_with_network(
                BearerName::new("primary-out").unwrap(),
                BearerName::new("primary-in").unwrap(),
                FakeNetworkConfig {
                    first_to_second: FakeLinkProfile {
                        loss_per_million: 1_000_000,
                        seed: 0x7060,
                        ..FakeLinkProfile::default()
                    },
                    ..FakeNetworkConfig::default()
                },
            );
        let (alternate_bearer, alternate_relay_bearer, mut alternate_network) =
            FakePacketBearer::<Pool>::pair_with_network(
                BearerName::new("alternate-out").unwrap(),
                BearerName::new("alternate-in").unwrap(),
                FakeNetworkConfig {
                    first_to_second: FakeLinkProfile {
                        seed: 0x7061,
                        ..FakeLinkProfile::default()
                    },
                    ..FakeNetworkConfig::default()
                },
            );
        let mut runtime = quic_lite::nostd::NoStdRuntime::new(
            QuicNode::<Pool>::new(&CLIENT_POOL),
            ConnectionLimits::default(),
        );
        let mut relay_sink = quic_lite::nostd::NoStdRuntime::new(
            QuicNode::<Pool>::new(&RELAY_POOL),
            ConnectionLimits::default(),
        );
        let primary = runtime.add_bearer(primary_bearer).unwrap();
        let alternate = runtime.add_bearer(alternate_bearer).unwrap();
        relay_sink.add_bearer(primary_relay_bearer).unwrap();
        relay_sink.add_bearer(alternate_relay_bearer).unwrap();
        let peer = PeerL2Address::new(1).unwrap();
        let mut primary_hint = hint(1, &[1], 0, 5_000);
        primary_hint.egress = Some(RouteEgress {
            bearer: primary,
            peer_l2_address: peer,
        });
        let mut alternate_hint = hint(2, &[2], 0, 25_000);
        alternate_hint.egress = Some(RouteEgress {
            bearer: alternate,
            peer_l2_address: peer,
        });
        let mut builder = PathBuilder::default();
        builder.merge_hint(primary_hint, 0).unwrap();
        builder.merge_hint(alternate_hint, 0).unwrap();
        let address = PacketMeta {
            bearer: primary,
            peer_l2_address: peer,
            received_at_us: 0,
        };
        let (failed_association, failed_route) = builder
            .create(
                &mut runtime,
                request(Some(1), false, 0),
                address,
                NearbyRelayHints::EMPTY,
            )
            .unwrap();
        assert_eq!(failed_route.route_id, 1);
        assert!(matches!(
            runtime
                .next_event()
                .map(|event| builder.observe_event(event, 0)),
            Some(RouteEventOutcome::CircuitOpened)
        ));

        let mut recovery = None;
        for _ in 0..8 {
            let Some(deadline) = runtime.next_deadline() else {
                break;
            };
            runtime.advance_time(deadline).unwrap();
            primary_network.advance_to(deadline);
            alternate_network.advance_to(deadline);
            while let Some(event) = runtime.next_event() {
                match builder
                    .recover_event(
                        &mut runtime,
                        event,
                        address,
                        NearbyRelayHints::EMPTY,
                        deadline,
                    )
                    .unwrap()
                {
                    RouteRecovery::Created {
                        failure,
                        association,
                        route,
                    } => {
                        recovery = Some((failure, association, route));
                        break;
                    }
                    RouteRecovery::Observed(_) | RouteRecovery::NoReplacement(_) => {}
                    RouteRecovery::Joined { .. } => {
                        panic!("bootstrap timeout recovery creates a new association")
                    }
                }
            }
            if recovery.is_some() {
                break;
            }
        }
        let (failure, replacement_association, replacement_route) =
            recovery.expect("public bearer loss expires and replaces the CREATE attempt");
        assert_eq!(failure.association, failed_association);
        assert_eq!(failure.failed_route.route_id, 1);
        assert_eq!(failure.replacement.unwrap().route_id, 2);
        assert_eq!(builder.reputation([1; 8]).unwrap().failed_paths, 1);
        assert!(primary_network.stats().loss_drops > 0);
        assert_ne!(replacement_association, failed_association);
        assert_eq!(replacement_route.route_id, 2);
        assert!(alternate_network.stats().accepted_submissions > 0);
    }

    #[cfg(feature = "std")]
    #[test]
    fn failed_public_bearer_join_automatically_joins_replacement_on_same_association() {
        use quic_lite::fake::{FakeLinkProfile, FakeNetworkConfig, FakePacketBearer};
        use quic_lite::heap_packet_pool::HeapPacketPool;
        use quic_lite::{BearerName, CircuitNextHop, CircuitStatus, ConnectionLimits};
        use std::sync::{Arc, Mutex};

        type Pool = HeapPacketPool<48, { quic_lite::DEFAULT_PACKET_POOL_SLOT_SIZE }>;
        static CLIENT_POOL: Pool = Pool::new();
        static SERVER_POOL: Pool = Pool::new();
        static SINK_POOL: Pool = Pool::new();
        CLIENT_POOL.resize(48).unwrap();
        SERVER_POOL.resize(48).unwrap();
        SINK_POOL.resize(48).unwrap();
        let (direct_client, direct_server, mut direct_network) =
            FakePacketBearer::<Pool>::pair_with_network(
                BearerName::new("direct-client").unwrap(),
                BearerName::new("direct-server").unwrap(),
                FakeNetworkConfig::default(),
            );
        let (failed_client, failed_sink, mut failed_network) =
            FakePacketBearer::<Pool>::pair_with_network(
                BearerName::new("failed-client").unwrap(),
                BearerName::new("failed-sink").unwrap(),
                FakeNetworkConfig {
                    first_to_second: FakeLinkProfile {
                        loss_per_million: 1_000_000,
                        seed: 0x7062,
                        ..FakeLinkProfile::default()
                    },
                    ..FakeNetworkConfig::default()
                },
            );
        let (replacement_client, replacement_sink, mut replacement_network) =
            FakePacketBearer::<Pool>::pair_with_network(
                BearerName::new("replacement-out").unwrap(),
                BearerName::new("replacement-in").unwrap(),
                FakeNetworkConfig {
                    first_to_second: FakeLinkProfile {
                        seed: 0x7063,
                        ..FakeLinkProfile::default()
                    },
                    ..FakeNetworkConfig::default()
                },
            );
        let (relay_out, server_relay_bearer, mut relay_server_network) =
            FakePacketBearer::<Pool>::pair_with_network(
                BearerName::new("relay-out").unwrap(),
                BearerName::new("server-relay").unwrap(),
                FakeNetworkConfig::default(),
            );
        let mut client = quic_lite::nostd::NoStdRuntime::new(
            QuicNode::<Pool>::new(&CLIENT_POOL),
            ConnectionLimits::default(),
        );
        let mut server = quic_lite::nostd::NoStdRuntime::new(
            QuicNode::<Pool>::new(&SERVER_POOL),
            ConnectionLimits::default(),
        );
        let routes = Arc::new(Mutex::new(Vec::new()));
        let relay_routes = routes.clone();
        let mut relay_node = QuicNode::<Pool>::new(&SINK_POOL);
        relay_node.set_path_open_resolver(move |kind, address| {
            let key = address.first().copied()?;
            relay_routes
                .lock()
                .unwrap()
                .iter()
                .find_map(|(route_kind, route_key, next_hop)| {
                    (*route_kind == kind && *route_key == key).then_some(*next_hop)
                })
        });
        let mut relay =
            quic_lite::nostd::NoStdRuntime::new(relay_node, ConnectionLimits::default());
        let direct = client.add_bearer(direct_client).unwrap();
        let failed = client.add_bearer(failed_client).unwrap();
        let replacement = client.add_bearer(replacement_client).unwrap();
        server.add_bearer(direct_server).unwrap();
        relay.add_bearer(failed_sink).unwrap();
        relay.add_bearer(replacement_sink).unwrap();
        let relay_next = relay.add_bearer(relay_out).unwrap();
        let server_relay = server.add_bearer(server_relay_bearer).unwrap();
        let peer = PeerL2Address::new(1).unwrap();
        routes.lock().unwrap().push((
            2,
            2,
            CircuitNextHop {
                bearer: relay_next,
                peer_l2_address: peer,
            },
        ));
        let association = client
            .associate(
                PacketMeta {
                    bearer: direct,
                    peer_l2_address: peer,
                    received_at_us: 0,
                },
                0,
            )
            .unwrap();
        let mut now_us = 0u64;
        for _ in 0..20_000 {
            direct_network.advance_to(now_us);
            client.advance_time(now_us).unwrap();
            server.advance_time(now_us).unwrap();
            client.progress_all().unwrap();
            server.progress_all().unwrap();
            if client.association_is_established(association) {
                break;
            }
            now_us = now_us.saturating_add(1_000);
        }
        assert!(client.association_is_established(association));
        let server_association = server.next_association().unwrap();

        let mut primary_hint = hint(1, &[1], now_us, 5_000);
        primary_hint.hops = vec![RelayHop::new(2, &[1], 60_000_000, 4096).unwrap()];
        primary_hint.egress = Some(RouteEgress {
            bearer: failed,
            peer_l2_address: peer,
        });
        let mut alternate_hint = hint(2, &[2], now_us, 25_000);
        alternate_hint.hops = vec![RelayHop::new(2, &[2], 60_000_000, 4096).unwrap()];
        alternate_hint.egress = Some(RouteEgress {
            bearer: replacement,
            peer_l2_address: peer,
        });
        let mut builder = PathBuilder::default();
        builder.merge_hint(primary_hint, now_us).unwrap();
        builder.merge_hint(alternate_hint, now_us).unwrap();
        let base_address = PacketMeta {
            bearer: direct,
            peer_l2_address: peer,
            received_at_us: now_us,
        };
        let (failed_circuit, failed_route) = builder
            .join(
                &mut client,
                request(Some(1), false, now_us),
                association,
                base_address,
            )
            .unwrap();
        assert_eq!(failed_route.route_id, 1);

        let mut replacement_join = None;
        for _ in 0..20_000 {
            direct_network.advance_to(now_us);
            failed_network.advance_to(now_us);
            replacement_network.advance_to(now_us);
            relay_server_network.advance_to(now_us);
            client.advance_time(now_us).unwrap();
            server.advance_time(now_us).unwrap();
            relay.advance_time(now_us).unwrap();
            client.progress_all().unwrap();
            server.progress_all().unwrap();
            relay.progress_all().unwrap();
            while let Some(event) = client.next_event() {
                match builder
                    .recover_event(
                        &mut client,
                        event,
                        base_address,
                        NearbyRelayHints::EMPTY,
                        now_us,
                    )
                    .unwrap()
                {
                    RouteRecovery::Joined {
                        failure,
                        circuit,
                        route,
                    } => {
                        replacement_join = Some((failure, circuit, route));
                        break;
                    }
                    RouteRecovery::Observed(_) | RouteRecovery::NoReplacement(_) => {}
                    RouteRecovery::Created { .. } => {
                        panic!("failed live path must join on its existing association")
                    }
                }
            }
            if replacement_join.is_some() {
                break;
            }
            now_us = now_us.saturating_add(1_000);
        }
        let (failure, replacement_circuit, selected) = replacement_join
            .expect("failed relay JOIN should immediately create an alternate JOIN");
        assert_eq!(failure.association, association);
        assert_eq!(failure.circuit, Some(failed_circuit));
        assert_eq!(failure.failed_route.route_id, 1);
        assert_eq!(selected.route_id, 2);
        assert_ne!(replacement_circuit, failed_circuit);
        assert_eq!(builder.reputation([1; 8]).unwrap().failed_paths, 1);
        assert!(failed_network.stats().loss_drops > 0);
        assert!(replacement_network.stats().accepted_submissions > 0);

        let mut replacement_validated = false;
        let mut last_circuits = [quic_lite::CircuitInfo::default(); 8];
        let mut last_circuit_count = 0;
        for _ in 0..20_000 {
            direct_network.advance_to(now_us);
            failed_network.advance_to(now_us);
            replacement_network.advance_to(now_us);
            relay_server_network.advance_to(now_us);
            client.advance_time(now_us).unwrap();
            server.advance_time(now_us).unwrap();
            relay.advance_time(now_us).unwrap();
            client.progress_all().unwrap();
            server.progress_all().unwrap();
            relay.progress_all().unwrap();
            last_circuit_count = client.circuits(association, &mut last_circuits);
            replacement_validated = last_circuits[..last_circuit_count].iter().any(|circuit| {
                circuit.id == replacement_circuit && circuit.status == CircuitStatus::Active
            });
            if replacement_validated {
                break;
            }
            now_us = now_us.saturating_add(1_000);
        }
        assert!(
            replacement_validated,
            "alternate relay JOIN must validate; client circuits={:?}, failed={:?}, replacement={:?}, relay-server={:?}",
            &last_circuits[..last_circuit_count],
            failed_network.stats(),
            replacement_network.stats(),
            relay_server_network.stats(),
        );
        let mut server_circuits = [quic_lite::CircuitInfo::default(); 8];
        let server_circuit_count = server.circuits(server_association, &mut server_circuits);
        assert!(
            server_circuits[..server_circuit_count]
                .iter()
                .any(|circuit| {
                    circuit.first_hop.bearer == server_relay
                        && circuit.status == CircuitStatus::Active
                })
        );

        let direct_circuit = last_circuits[..last_circuit_count]
            .iter()
            .find(|circuit| circuit.id != replacement_circuit)
            .expect("direct circuit remains available for the suspension check")
            .id;
        client.suspend_circuit(direct_circuit).unwrap();
        let mut stream = client.open_stream(association).unwrap();
        let payload = b"replacement path stream and FIN";
        let mut sent = 0usize;
        let mut fin_sent = false;
        let mut received = Vec::new();
        let mut received_fin = false;
        for _ in 0..20_000 {
            direct_network.advance_to(now_us);
            failed_network.advance_to(now_us);
            replacement_network.advance_to(now_us);
            relay_server_network.advance_to(now_us);
            client.advance_time(now_us).unwrap();
            server.advance_time(now_us).unwrap();
            relay.advance_time(now_us).unwrap();
            client.progress_all().unwrap();
            relay.progress_all().unwrap();
            server
                .progress_all_with_stream(|_, offset, fin, bytes| {
                    if offset != received.len() as u64 {
                        return Err(quic_lite::Error::Invalid);
                    }
                    received.extend_from_slice(bytes);
                    received_fin |= fin;
                    Ok(bytes.len())
                })
                .unwrap();
            if sent < payload.len() {
                match client.write_stream(&mut stream, &payload[sent..]) {
                    Ok(count) => sent += count,
                    Err(error) if error.is_retryable() => {}
                    Err(error) => panic!("replacement route stream write failed: {error:?}"),
                }
            } else if !fin_sent {
                match client.finish_stream(&mut stream) {
                    Ok(()) => fin_sent = true,
                    Err(error) if error.is_retryable() => {}
                    Err(error) => panic!("replacement route FIN failed: {error:?}"),
                }
            }
            if received_fin {
                break;
            }
            now_us = now_us.saturating_add(1_000);
        }
        assert_eq!(sent, payload.len());
        assert!(fin_sent);
        assert_eq!(received, payload);
        assert!(received_fin);
    }
}
