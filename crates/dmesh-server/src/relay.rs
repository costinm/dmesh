//! Tagged-CBOR setup records for one-way DCID forwarding.
//!
//! These records are deliberately small enough for the direct-message plane.
//! They configure one local rule at a time; pairing a forward and return path
//! remains a CP operation, not a relay-side transaction.

use crate::transport_path::TransportId;
use crate::{
    cbor::{Decoder, Encoder},
    tagged::{Name, Record, decode},
};
use quic_lite::ConnectionId;

/// Bearer-neutral DCID forwarding component.
pub const RELAY_COMPONENT: u64 = 5;
/// Reconcile one named relay rule to the complete desired state supplied by
/// the control plane. There are deliberately no allocate/update/remove
/// transition methods: retries must converge rather than advance state twice.
pub const RELAY_APPLY: u64 = 1;
/// Install a forward rule plus its independently keyed return rule. The
/// platform binds the return handle to the request's adjacent ingress path.
pub const RELAY_APPLY_PAIR: u64 = 2;

// A portable handle for an adjacent ESP-NOW peer. The forwarding registry
// still keys only on DCID; this value exists solely in relay.apply desired
// state so a platform handler can activate its local bearer route without a
// second, out-of-band configuration transaction.
const NOW_NEXT_HOP_PREFIX: u64 = (TransportId::NOW.0 as u64) << 56;
const UDP6_NEXT_HOP_PREFIX: u64 = (TransportId::UDP6.0 as u64) << 56;

/// Encode one directed ESP-NOW peer as the device-local handle carried by
/// [`RelayRoute`]. Broadcast/multicast and the zero address are not valid
/// relay destinations.
pub fn now_next_hop_handle(mac: [u8; 6]) -> Option<u64> {
    if mac == [0; 6] || mac[0] & 1 != 0 {
        return None;
    }
    let mut value = NOW_NEXT_HOP_PREFIX;
    let mut index = 0;
    while index < mac.len() {
        value |= (mac[index] as u64) << ((5 - index) * 8);
        index += 1;
    }
    Some(value)
}

/// Decode a handle produced by [`now_next_hop_handle`]. Other handle classes
/// remain platform-owned and fail closed until their adapter is implemented.
pub fn now_next_hop_mac(handle: u64) -> Option<[u8; 6]> {
    if handle >> 56 != TransportId::NOW.0 as u64 || (handle >> 48) & 0xff != 0 {
        return None;
    }
    let mac = [
        (handle >> 40) as u8,
        (handle >> 32) as u8,
        (handle >> 24) as u8,
        (handle >> 16) as u8,
        (handle >> 8) as u8,
        handle as u8,
    ];
    if mac == [0; 6] || mac[0] & 1 != 0 {
        return None;
    }
    Some(mac)
}

/// Create an opaque UDP6 handle that a platform binds to the complete ingress
/// tuple (link, MAC, IPv6 address, and source port) while applying a paired
/// rule. The token is controller-selected and scoped to that relay.
pub fn udp6_next_hop_handle(token: u64) -> Option<u64> {
    if token == 0 || token > 0x0000_ffff_ffff_ffff {
        return None;
    }
    Some(UDP6_NEXT_HOP_PREFIX | token)
}

pub fn udp6_next_hop_token(handle: u64) -> Option<u64> {
    if handle >> 56 != TransportId::UDP6.0 as u64 || (handle >> 48) & 0xff != 0 {
        return None;
    }
    let token = handle & 0x0000_ffff_ffff_ffff;
    (token != 0).then_some(token)
}

const FIELD_ALLOCATION: u64 = 1;
const FIELD_PROPOSED_DCID: u64 = 2;
const FIELD_NEXT_HOP: u64 = 3;
const FIELD_OUTBOUND_DCID: u64 = 4;
const FIELD_POSITION: u64 = 5;
const FIELD_REVISION: u64 = 6;
const FIELD_PRESENT: u64 = 7;
const FIELD_GENERATION: u64 = 8;
const FIELD_REVERSE_ALLOCATION: u64 = 11;
const FIELD_REVERSE_DCID: u64 = 12;
const FIELD_REVERSE_NEXT_HOP: u64 = 13;
const FIELD_REVERSE_OUTBOUND_DCID: u64 = 14;
const FIELD_REVERSE_POSITION: u64 = 15;
const FIELD_REVERSE_REVISION: u64 = 16;

/// One opaque platform-local next-hop route. `next_hop` is not a mesh
/// identity and does not appear in a forwarded packet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RelayRoute {
    pub next_hop: u64,
    pub outbound_dcid: ConnectionId,
}

/// Address used by a control-plane chain description. It is consumed only by
/// the adapter that resolves a local next-hop handle; relay packets retain
/// only DCIDs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LinkAddress {
    Mac([u8; 6]),
    Ipv6LinkLocal([u8; 16]),
}

/// One member of an explicitly requested relay chain. `transport` describes
/// how the preceding node reaches this node; the initial implementation uses
/// the same edge information in reverse for a symmetric return path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChainNode {
    pub transport: TransportId,
    pub address: LinkAddress,
}

impl ChainNode {
    pub const fn valid(self) -> bool {
        match (self.transport, self.address) {
            (TransportId::NOW, LinkAddress::Mac(_)) => true,
            (TransportId::UDP6, LinkAddress::Ipv6LinkLocal(address)) => {
                address[0] == 0xfe && (address[1] & 0xc0) == 0x80
            }
            _ => false,
        }
    }
}

/// Adapter used by the CP chain handler. It resolves a physical next-hop at
/// the relay being configured and exchanges one bounded DCID-zero record with
/// that relay. No socket, QUIC endpoint, or private queue is implied here.
pub trait ChainHandler {
    type Error;

    fn resolve_next_hop(&mut self, relay: ChainNode, next: ChainNode) -> Result<u64, Self::Error>;
    fn exchange_direct(
        &mut self,
        relay: ChainNode,
        request: &[u8],
        response: &mut [u8],
    ) -> Result<usize, Self::Error>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChainError<E> {
    TooShort,
    TooLong,
    InvalidNode,
    Packet,
    Response,
    Handler(E),
}

/// Install the forward and symmetric return rules for a chain whose list is
/// `[source, relay..., destination]`. Each setup exchange has a distinct
/// request ID and must return the same ID before the next rule is attempted.
/// The resulting labels are node-local and may be reused on another relay.
pub fn install_symmetric_chain<H: ChainHandler>(
    nodes: &[ChainNode],
    allocation_base: u64,
    request_id_base: u64,
    handler: &mut H,
    request_out: &mut [u8],
    response_in: &mut [u8],
) -> Result<usize, ChainError<H::Error>> {
    if nodes.len() < 3 {
        return Err(ChainError::TooShort);
    }
    let relays = nodes.len() - 2;
    if relays > 16 {
        return Err(ChainError::TooLong);
    }
    if nodes.iter().copied().any(|node| !node.valid()) {
        return Err(ChainError::InvalidNode);
    }
    let mut installed = 0u64;
    for reverse in [false, true] {
        for step in 0..relays {
            let relay_index = if reverse {
                nodes.len() - 2 - step
            } else {
                step + 1
            };
            let next_index = if reverse {
                relay_index - 1
            } else {
                relay_index + 1
            };
            let position = (step + 1) as u8;
            let label = 2 + if reverse { 32 } else { 0 } + u64::from(position);
            let inbound = ConnectionId::relay_local(label, position).ok_or(ChainError::Packet)?;
            let outbound = if step + 1 == relays {
                ConnectionId::new(0).ok_or(ChainError::Packet)?
            } else {
                ConnectionId::relay_local(label + 1, position + 1).ok_or(ChainError::Packet)?
            };
            let relay = nodes[relay_index];
            let next = nodes[next_index];
            let next_hop = handler
                .resolve_next_hop(relay, next)
                .map_err(ChainError::Handler)?;
            let request_id = request_id_base
                .checked_add(installed)
                .ok_or(ChainError::Packet)?;
            let request = Request {
                allocation: allocation_base
                    .checked_add(installed)
                    .ok_or(ChainError::Packet)?,
                revision: 1,
                rule: Some(DesiredRule {
                    proposed_dcid: Some(inbound),
                    route: RelayRoute {
                        next_hop,
                        outbound_dcid: outbound,
                    },
                    position,
                }),
            };
            let mut cbor = [0u8; 128];
            let cbor_len =
                encode_request(request, Some(request_id), &mut cbor).ok_or(ChainError::Packet)?;
            let packet_len =
                quic_lite::encode_direct_packet(request_id as u32, &cbor[..cbor_len], request_out)
                    .map_err(|_| ChainError::Packet)?;
            let response_len = handler
                .exchange_direct(relay, &request_out[..packet_len], response_in)
                .map_err(ChainError::Handler)?;
            if response_len > response_in.len() {
                return Err(ChainError::Response);
            }
            let (_, payload) = quic_lite::decode_direct_packet(&response_in[..response_len])
                .map_err(|_| ChainError::Response)?;
            let response = crate::tagged::decode(payload).ok_or(ChainError::Response)?;
            if response.component != Some(Name::Tag(RELAY_COMPONENT))
                || response.method != Some(Name::Tag(RELAY_APPLY))
                || response.id != Some(request_id)
                || response.error.is_some()
            {
                return Err(ChainError::Response);
            }
            installed += 1;
        }
    }
    Ok(installed as usize)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DesiredRule {
    /// A CP may propose a label, but the relay is free to select and report a
    /// different local label. It is not a transition-only allocation command.
    pub proposed_dcid: Option<ConnectionId>,
    pub route: RelayRoute,
    pub position: u8,
}

/// Full desired state of one named relay rule. `rule: None` is desired
/// absence, so removal has the same idempotent reconciliation semantics as
/// creation and replacement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Request {
    pub allocation: u64,
    pub revision: u64,
    pub rule: Option<DesiredRule>,
}

/// Two independent desired rules installed from one ingress-correlated
/// request. The return rule is still a normal DCID entry; pairing exists only
/// to make the initial forward/return setup converge before bootstrap.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PairRequest {
    pub forward: Request,
    pub reverse: Request,
}

/// The convergence result a handler returns to the direct or stream binding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObservedRule {
    pub allocation: u64,
    pub revision: u64,
    pub local_dcid: Option<ConnectionId>,
    pub generation: u64,
}

/// Effective aliases returned by `relay.pair`.  These are relay-local values:
/// callers must use them for the next relay-open packet even when they differ
/// from the requested aliases because another active allocation occupied one.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObservedPair {
    pub forward: ObservedRule,
    pub reverse: ObservedRule,
}

/// Encode the observed state returned after a successful `relay.apply`.
/// The result is a compact CBOR map suitable for the tagged direct-response
/// envelope; callers retain packet-number ownership.
pub fn encode_observed_rule(observed: ObservedRule, out: &mut [u8]) -> Option<usize> {
    let mut encoder = Encoder::new(out);
    encoder.map(3 + u64::from(observed.local_dcid.is_some()))?;
    put_uint(&mut encoder, FIELD_ALLOCATION, observed.allocation)?;
    put_uint(&mut encoder, FIELD_REVISION, observed.revision)?;
    if let Some(dcid) = observed.local_dcid {
        put_uint(&mut encoder, FIELD_PROPOSED_DCID, dcid.value())?;
    }
    put_uint(&mut encoder, FIELD_GENERATION, observed.generation)?;
    Some(encoder.len())
}

/// Compact result for an atomic local forward/return installation.
pub fn encode_observed_pair(
    forward: ObservedRule,
    reverse: ObservedRule,
    out: &mut [u8],
) -> Option<usize> {
    let mut encoder = Encoder::new(out);
    encoder.map(8)?;
    put_uint(&mut encoder, 1, forward.allocation)?;
    put_uint(&mut encoder, 2, forward.local_dcid?.value())?;
    put_uint(&mut encoder, 3, forward.revision)?;
    put_uint(&mut encoder, 4, forward.generation)?;
    put_uint(&mut encoder, 11, reverse.allocation)?;
    put_uint(&mut encoder, 12, reverse.local_dcid?.value())?;
    put_uint(&mut encoder, 13, reverse.revision)?;
    put_uint(&mut encoder, 14, reverse.generation)?;
    Some(encoder.len())
}

/// Decode the successful result of a `relay.pair` response.
pub fn decode_observed_pair(fields: &[u8]) -> Option<ObservedPair> {
    let mut decoder = Decoder::new(fields);
    let (major, count) = decoder.head()?;
    if major != 5 || count == u64::MAX {
        return None;
    }
    let mut forward_allocation = None;
    let mut forward_dcid = None;
    let mut forward_revision = None;
    let mut forward_generation = None;
    let mut reverse_allocation = None;
    let mut reverse_dcid = None;
    let mut reverse_revision = None;
    let mut reverse_generation = None;
    for _ in 0..count {
        match decoder.uint()? {
            1 => forward_allocation = Some(decoder.uint()?),
            2 => forward_dcid = Some(ConnectionId::new(decoder.uint()?)?),
            3 => forward_revision = Some(decoder.uint()?),
            4 => forward_generation = Some(decoder.uint()?),
            11 => reverse_allocation = Some(decoder.uint()?),
            12 => reverse_dcid = Some(ConnectionId::new(decoder.uint()?)?),
            13 => reverse_revision = Some(decoder.uint()?),
            14 => reverse_generation = Some(decoder.uint()?),
            _ => decoder.skip()?,
        }
    }
    if !decoder.is_finished() {
        return None;
    }
    Some(ObservedPair {
        forward: ObservedRule {
            allocation: forward_allocation?,
            revision: forward_revision?,
            local_dcid: Some(forward_dcid?),
            generation: forward_generation?,
        },
        reverse: ObservedRule {
            allocation: reverse_allocation?,
            revision: reverse_revision?,
            local_dcid: Some(reverse_dcid?),
            generation: reverse_generation?,
        },
    })
}

/// Platform owner for relay-state mutation. The schema has no bearer, queue,
/// radio, or endpoint dependency; adapters resolve `next_hop` and update the
/// shared DCID registry only after this typed validation succeeds.
pub trait Handler {
    type Error;

    fn reconcile(&mut self, desired: Request) -> Result<ObservedRule, Self::Error>;
}

/// Fixed-capacity desired-state reconciler shared by small runtimes. The
/// runtime owns next-hop resolution; this type never learns a bearer address.
#[derive(Clone)]
pub struct RelayState<NextHop, const ENTRIES: usize> {
    registry: quic_lite::DcidRegistry<(), NextHop, ENTRIES>,
    allocations: [Option<StoredRule>; ENTRIES],
    // A pair is not a new forwarding primitive.  It is bootstrap metadata
    // retained solely so a forward DCID can find the relay-owned return CID
    // while transforming the plaintext OPEN.  Once OPEN has completed, both
    // entries are ordinary independently keyed DCID forwarding rules.
    relay_open_returns: [Option<(u64, ConnectionId)>; ENTRIES],
}

#[derive(Clone, Copy)]
struct StoredRule {
    request: Request,
    local_dcid: Option<ConnectionId>,
    generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReconcileError {
    Full,
    StaleRevision,
    SameRevisionConflict,
    UnknownNextHop,
    Registry(quic_lite::DcidRegistryError),
    InvalidAutoDcid,
}

impl<NextHop: Copy + Eq, const ENTRIES: usize> Default for RelayState<NextHop, ENTRIES> {
    fn default() -> Self {
        Self::new()
    }
}

impl<NextHop: Copy + Eq, const ENTRIES: usize> RelayState<NextHop, ENTRIES> {
    pub fn new() -> Self {
        Self {
            registry: quic_lite::DcidRegistry::new(),
            allocations: core::array::from_fn(|_| None),
            relay_open_returns: [None; ENTRIES],
        }
    }

    pub fn registry(&self) -> &quic_lite::DcidRegistry<(), NextHop, ENTRIES> {
        &self.registry
    }

    /// Reconcile a forward/return pair transactionally within this relay.
    /// The rules remain independent DCID entries after installation; pairing
    /// only prevents bootstrap from starting with one direction missing.
    pub fn reconcile_pair<F>(
        &mut self,
        desired: PairRequest,
        mut resolve: F,
    ) -> Result<(ObservedRule, ObservedRule), ReconcileError>
    where
        F: FnMut(u64) -> Option<NextHop>,
    {
        let previous = self.clone();
        let reverse = match self.reconcile(desired.reverse, &mut resolve) {
            Ok(observed) => observed,
            Err(error) => return Err(error),
        };
        match self.reconcile(desired.forward, &mut resolve) {
            Ok(forward) => {
                // The relay may replace either proposed alias.  Record only
                // the observed local values; callers must likewise consume
                // the pair response rather than assume their proposal won.
                if let (Some(forward_dcid), Some(reverse_dcid)) =
                    (forward.local_dcid, reverse.local_dcid)
                {
                    if let Some(slot) = self.relay_open_returns.iter_mut().find(|slot| {
                        slot.is_some_and(|(allocation, _)| allocation == forward.allocation)
                    }) {
                        *slot = Some((forward.allocation, reverse_dcid));
                    } else if let Some(slot) = self
                        .relay_open_returns
                        .iter_mut()
                        .find(|slot| slot.is_none())
                    {
                        *slot = Some((forward.allocation, reverse_dcid));
                    } else {
                        *self = previous;
                        return Err(ReconcileError::Full);
                    }
                    debug_assert!(self.registry.contains(forward_dcid));
                }
                Ok((forward, reverse))
            }
            Err(error) => {
                *self = previous;
                Err(error)
            }
        }
    }

    /// Return the relay-owned ACK alias paired with `forward_dcid`.
    ///
    /// This is intentionally not exposed as a route lookup: it exists only
    /// for relay-open's one plaintext bootstrap transformation.  A missing
    /// association means this is a normal opaque forward rule.
    pub fn relay_open_return_dcid(&self, forward_dcid: ConnectionId) -> Option<ConnectionId> {
        let allocation = self
            .allocations
            .iter()
            .flatten()
            .find(|rule| rule.local_dcid == Some(forward_dcid))?
            .request
            .allocation;
        self.relay_open_returns
            .iter()
            .flatten()
            .find_map(|(forward_allocation, reverse_dcid)| {
                (*forward_allocation == allocation).then_some(*reverse_dcid)
            })
    }

    /// Reconcile the whole named object. `resolve` converts its opaque local
    /// next-hop handle only when a forwarding rule is desired.
    pub fn reconcile<F>(
        &mut self,
        desired: Request,
        mut resolve: F,
    ) -> Result<ObservedRule, ReconcileError>
    where
        F: FnMut(u64) -> Option<NextHop>,
    {
        let existing = self.allocations.iter().position(|entry| {
            entry.is_some_and(|entry| entry.request.allocation == desired.allocation)
        });
        if let Some(index) = existing {
            let current = self.allocations[index].expect("located populated relay rule");
            if desired.revision < current.request.revision {
                return Err(ReconcileError::StaleRevision);
            }
            if desired.revision == current.request.revision {
                if desired != current.request {
                    return Err(ReconcileError::SameRevisionConflict);
                }
                return Ok(observed(current));
            }
            // Validate every possible failure before withdrawing the active
            // rule. This makes a failed newer desired state non-disruptive.
            if let Some(rule) = desired.rule {
                let dcid = self
                    .select_local_dcid(index, rule, current.local_dcid)
                    .ok_or(ReconcileError::InvalidAutoDcid)?;
                if resolve(rule.route.next_hop).is_none() {
                    return Err(ReconcileError::UnknownNextHop);
                }
                if current.local_dcid != Some(dcid) && self.registry.contains(dcid) {
                    return Err(ReconcileError::Registry(
                        quic_lite::DcidRegistryError::Occupied,
                    ));
                }
            }
            if let Some(dcid) = current.local_dcid {
                self.registry.remove(dcid);
            }
            let next = self.apply(index, desired, current.generation + 1, &mut resolve)?;
            self.allocations[index] = Some(next);
            return Ok(observed(next));
        }
        let Some(index) = self.allocations.iter().position(Option::is_none) else {
            return Err(ReconcileError::Full);
        };
        let next = self.apply(index, desired, 1, &mut resolve)?;
        self.allocations[index] = Some(next);
        Ok(observed(next))
    }

    fn apply<F>(
        &mut self,
        index: usize,
        desired: Request,
        generation: u64,
        resolve: &mut F,
    ) -> Result<StoredRule, ReconcileError>
    where
        F: FnMut(u64) -> Option<NextHop>,
    {
        let Some(rule) = desired.rule else {
            return Ok(StoredRule {
                request: desired,
                local_dcid: None,
                generation,
            });
        };
        let dcid = self
            .select_local_dcid(index, rule, None)
            .ok_or(ReconcileError::InvalidAutoDcid)?;
        let next_hop = resolve(rule.route.next_hop).ok_or(ReconcileError::UnknownNextHop)?;
        self.registry
            .install_forward(
                dcid,
                quic_lite::ForwardRule {
                    next_hop,
                    outbound_dcid: rule.route.outbound_dcid,
                },
            )
            .map_err(ReconcileError::Registry)?;
        Ok(StoredRule {
            request: desired,
            local_dcid: Some(dcid),
            generation,
        })
    }

    /// Pick the relay-local alias for one desired rule.  A proposal is a
    /// convenience, not a lease: if another allocation already owns it,
    /// choose a deterministic free local label and report it in ObservedRule.
    /// `retained` permits an in-place revision update to keep its own label.
    fn select_local_dcid(
        &self,
        index: usize,
        rule: DesiredRule,
        retained: Option<ConnectionId>,
    ) -> Option<ConnectionId> {
        if let Some(proposed) = rule.proposed_dcid {
            if Some(proposed) == retained || !self.registry.contains(proposed) {
                return Some(proposed);
            }
        }
        for offset in 0..ENTRIES {
            let label = (index + 2 + offset) as u64;
            let candidate = ConnectionId::relay_local(label, rule.position)?;
            if Some(candidate) == retained || !self.registry.contains(candidate) {
                return Some(candidate);
            }
        }
        None
    }
}

fn observed(rule: StoredRule) -> ObservedRule {
    ObservedRule {
        allocation: rule.request.allocation,
        revision: rule.request.revision,
        local_dcid: rule.local_dcid,
        generation: rule.generation,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DispatchError<E> {
    MalformedOrDirected,
    Handler(E),
}

/// Result of offering a DCID-zero tagged-CBOR record to a platform's shared
/// control dispatcher. `Response` is a complete caller-produced short packet,
/// ready for the bearer to submit; this keeps packet-number ownership with the
/// adapter instead of inventing a relay-specific counter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirectOutcome {
    NotHandled,
    Handled,
    Response(usize),
}

/// Common direct-message binding used by UDP6 first and by ESP bearer owners
/// next. A QUIC stream and a direct message may call the same component
/// dispatcher; this trait represents only the bounded direct envelope.
pub trait DirectHandler: Send + Sync + core::fmt::Debug {
    fn handle_direct(
        &self,
        packet_number: u32,
        payload: &[u8],
        response: &mut [u8],
    ) -> DirectOutcome;
}

/// Fixed-capacity duplicate cache owned only by a *terminating* direct-message
/// handler. A relay never uses this: it rewrites and forwards every matching
/// packet, including duplicates, without inspecting the CBOR body. A
/// tagged-record `id`, when present, is the retry key; otherwise the direct
/// packet number is the key. The request fingerprint rejects accidental reuse
/// of an ID for a different command. Cached complete responses let a terminal
/// handler answer a lost reply without repeating its side effect.
pub struct TerminatingDirectDedup<const ENTRIES: usize, const RESPONSE_CAPACITY: usize> {
    entries: [Option<TerminatingDirectDedupEntry<RESPONSE_CAPACITY>>; ENTRIES],
    next: usize,
}

#[derive(Clone, Copy)]
struct TerminatingDirectDedupEntry<const RESPONSE_CAPACITY: usize> {
    id: Option<u64>,
    packet_number: u32,
    fingerprint: u32,
    response_len: usize,
    response: [u8; RESPONSE_CAPACITY],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TerminatingDirectDedupResult {
    New,
    Replay(usize),
    Conflict,
}

impl<const ENTRIES: usize, const RESPONSE_CAPACITY: usize>
    TerminatingDirectDedup<ENTRIES, RESPONSE_CAPACITY>
{
    pub const fn new() -> Self {
        Self {
            entries: [None; ENTRIES],
            next: 0,
        }
    }

    /// Copy a cached response into `output`, if this is a duplicate. A return
    /// of [`TerminatingDirectDedupResult::Conflict`] means a caller reused the key with a
    /// different payload and must not execute it.
    pub fn check(
        &self,
        packet_number: u32,
        payload: &[u8],
        output: &mut [u8],
    ) -> TerminatingDirectDedupResult {
        let id = decode(payload).and_then(|record| record.id);
        let fingerprint = direct_fingerprint(payload);
        for entry in self.entries.iter().flatten() {
            let same_key = match (id, entry.id) {
                (Some(id), Some(existing)) => id == existing,
                (None, None) => packet_number == entry.packet_number,
                _ => false,
            };
            if !same_key {
                continue;
            }
            if entry.fingerprint != fingerprint || entry.response_len > output.len() {
                return TerminatingDirectDedupResult::Conflict;
            }
            output[..entry.response_len].copy_from_slice(&entry.response[..entry.response_len]);
            return TerminatingDirectDedupResult::Replay(entry.response_len);
        }
        TerminatingDirectDedupResult::New
    }

    /// Remember the complete response after the side effect has succeeded.
    /// This is an overwrite ring, not an unbounded request history.
    pub fn store(&mut self, packet_number: u32, payload: &[u8], response: &[u8]) -> bool {
        if ENTRIES == 0 || response.len() > RESPONSE_CAPACITY {
            return false;
        }
        let mut cached = [0; RESPONSE_CAPACITY];
        cached[..response.len()].copy_from_slice(response);
        self.entries[self.next] = Some(TerminatingDirectDedupEntry {
            id: decode(payload).and_then(|record| record.id),
            packet_number,
            fingerprint: direct_fingerprint(payload),
            response_len: response.len(),
            response: cached,
        });
        self.next = (self.next + 1) % ENTRIES;
        true
    }
}

impl<const ENTRIES: usize, const RESPONSE_CAPACITY: usize> Default
    for TerminatingDirectDedup<ENTRIES, RESPONSE_CAPACITY>
{
    fn default() -> Self {
        Self::new()
    }
}

fn direct_fingerprint(payload: &[u8]) -> u32 {
    payload.iter().fold(0x811c_9dc5, |hash, byte| {
        (hash ^ u32::from(*byte)).wrapping_mul(0x0100_0193)
    })
}

pub fn dispatch<H: Handler>(
    packet: &[u8],
    handler: &mut H,
) -> Result<ObservedRule, DispatchError<H::Error>> {
    let request = decode_request(packet).ok_or(DispatchError::MalformedOrDirected)?;
    dispatch_request(request, handler).map_err(DispatchError::Handler)
}

pub fn dispatch_request<H: Handler>(
    request: Request,
    handler: &mut H,
) -> Result<ObservedRule, H::Error> {
    handler.reconcile(request)
}

/// Decode one local relay request. Directed records are forwarded before a
/// local component decoder runs.
pub fn decode_request(packet: &[u8]) -> Option<Request> {
    let record = decode(packet)?;
    if record.to.is_some() {
        None
    } else {
        decode_record(record)
    }
}

pub fn decode_pair_request(packet: &[u8]) -> Option<PairRequest> {
    let record = decode(packet)?;
    decode_pair_record(record)
}

/// Decoded-record counterpart to [`decode_pair_request`].  Normal QUIC
/// stream dispatch has already decoded the tagged envelope, but relay pairing
/// still needs to reject a directed record before it can mutate local desired
/// state.
pub fn decode_pair_record(record: Record<'_>) -> Option<PairRequest> {
    if record.to.is_some()
        || record.component != Some(Name::Tag(RELAY_COMPONENT))
        || record.method != Some(Name::Tag(RELAY_APPLY_PAIR))
    {
        return None;
    }
    let mut decoder = Decoder::new(record.fields?);
    let (major, count) = decoder.head()?;
    if major != 5 || count == u64::MAX {
        return None;
    }
    let mut fields = Fields::default();
    for _ in 0..count {
        match decoder.uint()? {
            FIELD_ALLOCATION => fields.allocation = Some(decoder.uint()?),
            FIELD_PROPOSED_DCID => fields.proposed_dcid = Some(decoder.uint()?),
            FIELD_NEXT_HOP => fields.next_hop = Some(decoder.uint()?),
            FIELD_OUTBOUND_DCID => fields.outbound_dcid = Some(decoder.uint()?),
            FIELD_POSITION => fields.position = Some(decoder.uint()?),
            FIELD_REVISION => fields.revision = Some(decoder.uint()?),
            FIELD_REVERSE_ALLOCATION => fields.reverse_allocation = Some(decoder.uint()?),
            FIELD_REVERSE_DCID => fields.reverse_dcid = Some(decoder.uint()?),
            FIELD_REVERSE_NEXT_HOP => fields.reverse_next_hop = Some(decoder.uint()?),
            FIELD_REVERSE_OUTBOUND_DCID => fields.reverse_outbound_dcid = Some(decoder.uint()?),
            FIELD_REVERSE_POSITION => fields.reverse_position = Some(decoder.uint()?),
            FIELD_REVERSE_REVISION => fields.reverse_revision = Some(decoder.uint()?),
            _ => decoder.skip()?,
        }
    }
    if !decoder.is_finished() {
        return None;
    }
    let rule = |allocation, revision, dcid, next_hop, outbound_dcid, position| {
        let position = u8::try_from(position?).ok()?;
        if position == 0 || position > 16 {
            return None;
        }
        Some(Request {
            allocation: nonzero(allocation?)?,
            revision: revision?,
            rule: Some(DesiredRule {
                proposed_dcid: Some(ConnectionId::new(dcid?)?),
                route: RelayRoute {
                    next_hop: next_hop?,
                    outbound_dcid: ConnectionId::new(outbound_dcid?)?,
                },
                position,
            }),
        })
    };
    Some(PairRequest {
        forward: rule(
            fields.allocation,
            fields.revision,
            fields.proposed_dcid,
            fields.next_hop,
            fields.outbound_dcid,
            fields.position,
        )?,
        reverse: rule(
            fields.reverse_allocation,
            fields.reverse_revision,
            fields.reverse_dcid,
            fields.reverse_next_hop,
            fields.reverse_outbound_dcid,
            fields.reverse_position,
        )?,
    })
}

pub fn decode_record(record: Record<'_>) -> Option<Request> {
    if record.component != Some(Name::Tag(RELAY_COMPONENT)) {
        return None;
    }
    let fields = record.fields?;
    match record.method? {
        Name::Tag(RELAY_APPLY) => {
            let fields = decode_fields(fields)?;
            let allocation = nonzero(fields.allocation?)?;
            let revision = fields.revision?;
            let present = fields.present?;
            if present > 1 {
                return None;
            }
            let rule = if present == 0 {
                None
            } else {
                let position = u8::try_from(fields.position?).ok()?;
                if position == 0 || position > 16 {
                    return None;
                }
                Some(DesiredRule {
                    proposed_dcid: match fields.proposed_dcid {
                        Some(value) => Some(ConnectionId::new(value)?),
                        None => None,
                    },
                    route: RelayRoute {
                        next_hop: fields.next_hop?,
                        outbound_dcid: ConnectionId::new(fields.outbound_dcid?)?,
                    },
                    position,
                })
            };
            Some(Request {
                allocation,
                revision,
                rule,
            })
        }
        _ => None,
    }
}

fn nonzero(value: u64) -> Option<u64> {
    (value != 0).then_some(value)
}

#[derive(Default)]
struct Fields {
    allocation: Option<u64>,
    proposed_dcid: Option<u64>,
    next_hop: Option<u64>,
    outbound_dcid: Option<u64>,
    position: Option<u64>,
    revision: Option<u64>,
    present: Option<u64>,
    reverse_allocation: Option<u64>,
    reverse_dcid: Option<u64>,
    reverse_next_hop: Option<u64>,
    reverse_outbound_dcid: Option<u64>,
    reverse_position: Option<u64>,
    reverse_revision: Option<u64>,
}

fn decode_fields(encoded: &[u8]) -> Option<Fields> {
    let mut decoder = Decoder::new(encoded);
    let (major, count) = decoder.head()?;
    if major != 5 || count == u64::MAX {
        return None;
    }
    let mut fields = Fields::default();
    for _ in 0..count {
        match decoder.uint()? {
            FIELD_ALLOCATION => fields.allocation = Some(decoder.uint()?),
            FIELD_PROPOSED_DCID => fields.proposed_dcid = Some(decoder.uint()?),
            FIELD_NEXT_HOP => fields.next_hop = Some(decoder.uint()?),
            FIELD_OUTBOUND_DCID => fields.outbound_dcid = Some(decoder.uint()?),
            FIELD_POSITION => fields.position = Some(decoder.uint()?),
            FIELD_REVISION => fields.revision = Some(decoder.uint()?),
            FIELD_PRESENT => fields.present = Some(decoder.uint()?),
            _ => decoder.skip()?,
        }
    }
    decoder.is_finished().then_some(fields)
}

/// Encode a setup request for either a direct DCID-zero message or a normal
/// stream handler. The outer transport selects the delivery semantics.
pub fn encode_request(request: Request, id: Option<u64>, out: &mut [u8]) -> Option<usize> {
    let field_count = 3 + request
        .rule
        .map_or(0, |rule| 3 + usize::from(rule.proposed_dcid.is_some()));
    let mut encoder = Encoder::new(out);
    encoder.map(if id.is_some() { 4 } else { 3 })?;
    encoder.uint(1)?;
    encoder.uint(RELAY_COMPONENT)?;
    encoder.uint(2)?;
    encoder.uint(RELAY_APPLY)?;
    if let Some(id) = id {
        encoder.uint(3)?;
        encoder.uint(id)?;
    }
    encoder.uint(5)?;
    encoder.map(field_count as u64)?;
    put_uint(&mut encoder, FIELD_ALLOCATION, request.allocation)?;
    put_uint(&mut encoder, FIELD_REVISION, request.revision)?;
    put_uint(
        &mut encoder,
        FIELD_PRESENT,
        u64::from(request.rule.is_some()),
    )?;
    if let Some(rule) = request.rule {
        if let Some(dcid) = rule.proposed_dcid {
            put_uint(&mut encoder, FIELD_PROPOSED_DCID, dcid.value())?;
        }
        put_uint(&mut encoder, FIELD_NEXT_HOP, rule.route.next_hop)?;
        put_uint(
            &mut encoder,
            FIELD_OUTBOUND_DCID,
            rule.route.outbound_dcid.value(),
        )?;
        put_uint(&mut encoder, FIELD_POSITION, u64::from(rule.position))?;
    }
    Some(encoder.len())
}

pub fn encode_pair_request(request: PairRequest, id: Option<u64>, out: &mut [u8]) -> Option<usize> {
    let forward = request.forward.rule?;
    let reverse = request.reverse.rule?;
    let mut encoder = Encoder::new(out);
    encoder.map(if id.is_some() { 4 } else { 3 })?;
    encoder.uint(1)?;
    encoder.uint(RELAY_COMPONENT)?;
    encoder.uint(2)?;
    encoder.uint(RELAY_APPLY_PAIR)?;
    if let Some(id) = id {
        encoder.uint(3)?;
        encoder.uint(id)?;
    }
    encoder.uint(5)?;
    encoder.map(12)?;
    put_uint(&mut encoder, FIELD_ALLOCATION, request.forward.allocation)?;
    put_uint(&mut encoder, FIELD_REVISION, request.forward.revision)?;
    put_uint(
        &mut encoder,
        FIELD_PROPOSED_DCID,
        forward.proposed_dcid?.value(),
    )?;
    put_uint(&mut encoder, FIELD_NEXT_HOP, forward.route.next_hop)?;
    put_uint(
        &mut encoder,
        FIELD_OUTBOUND_DCID,
        forward.route.outbound_dcid.value(),
    )?;
    put_uint(&mut encoder, FIELD_POSITION, u64::from(forward.position))?;
    put_uint(
        &mut encoder,
        FIELD_REVERSE_ALLOCATION,
        request.reverse.allocation,
    )?;
    put_uint(
        &mut encoder,
        FIELD_REVERSE_REVISION,
        request.reverse.revision,
    )?;
    put_uint(
        &mut encoder,
        FIELD_REVERSE_DCID,
        reverse.proposed_dcid?.value(),
    )?;
    put_uint(&mut encoder, FIELD_REVERSE_NEXT_HOP, reverse.route.next_hop)?;
    put_uint(
        &mut encoder,
        FIELD_REVERSE_OUTBOUND_DCID,
        reverse.route.outbound_dcid.value(),
    )?;
    put_uint(
        &mut encoder,
        FIELD_REVERSE_POSITION,
        u64::from(reverse.position),
    )?;
    Some(encoder.len())
}

fn put_uint(encoder: &mut Encoder<'_>, key: u64, value: u64) -> Option<()> {
    encoder.uint(key)?;
    encoder.uint(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use quic_lite::{
        DcidIngress, DcidRegistry, ForwardRule, ShortHeader, decode_direct_packet,
        encode_direct_packet, encode_one_way_packet, rewrite_dcid,
    };

    #[test]
    fn now_next_hop_handle_round_trips_and_rejects_group_addresses() {
        let mac = [0x84, 0x0d, 0x8e, 0x07, 0x41, 0x70];
        let handle = now_next_hop_handle(mac).unwrap();
        assert_eq!(handle >> 56, u64::from(TransportId::NOW.0));
        assert_eq!(now_next_hop_mac(handle), Some(mac));
        assert_eq!(now_next_hop_handle([0; 6]), None);
        assert_eq!(now_next_hop_handle([0xff; 6]), None);
        assert_eq!(now_next_hop_mac(handle | (1 << 48)), None);
        let udp = udp6_next_hop_handle(0x1234).unwrap();
        assert_eq!(udp6_next_hop_token(udp), Some(0x1234));
        assert_eq!(udp6_next_hop_handle(0), None);
    }

    #[derive(Default)]
    struct TestHandler(Option<Request>);

    impl Handler for TestHandler {
        type Error = ();

        fn reconcile(&mut self, desired: Request) -> Result<ObservedRule, Self::Error> {
            self.0 = Some(desired);
            Ok(ObservedRule {
                allocation: desired.allocation,
                revision: desired.revision,
                local_dcid: desired.rule.and_then(|rule| rule.proposed_dcid),
                generation: desired.revision,
            })
        }
    }

    #[test]
    fn direct_relay_setup_round_trips_without_quic_state() {
        let request = Request {
            allocation: 9,
            revision: 1,
            rule: Some(DesiredRule {
                proposed_dcid: Some(ConnectionId::relay_local(2, 1).unwrap()),
                route: RelayRoute {
                    next_hop: 77,
                    outbound_dcid: ConnectionId::new(0).unwrap(),
                },
                position: 1,
            }),
        };
        let mut wire = [0; 96];
        let used = encode_request(request, Some(3), &mut wire).unwrap();
        assert_eq!(decode_request(&wire[..used]), Some(request));
        let mut handler = TestHandler::default();
        dispatch(&wire[..used], &mut handler).unwrap();
        assert_eq!(handler.0, Some(request));
    }

    #[test]
    fn relay_setup_rejects_directed_or_invalid_position() {
        let directed = [
            0xa4,
            1,
            RELAY_COMPONENT as u8,
            2,
            RELAY_APPLY as u8,
            5,
            0xa0,
            9,
            1,
        ];
        assert_eq!(decode_request(&directed), None);
        let request = Request {
            allocation: 1,
            revision: 1,
            rule: Some(DesiredRule {
                proposed_dcid: None,
                route: RelayRoute {
                    next_hop: 1,
                    outbound_dcid: ConnectionId::new(0).unwrap(),
                },
                position: 17,
            }),
        };
        let mut wire = [0; 96];
        let used = encode_request(request, None, &mut wire).unwrap();
        assert_eq!(decode_request(&wire[..used]), None);
    }

    #[test]
    fn desired_state_reconcile_is_idempotent_and_revision_guarded() {
        let desired = Request {
            allocation: 42,
            revision: 7,
            rule: Some(DesiredRule {
                proposed_dcid: None,
                route: RelayRoute {
                    next_hop: 9,
                    outbound_dcid: ConnectionId::new(0).unwrap(),
                },
                position: 2,
            }),
        };
        let mut state = RelayState::<u8, 2>::new();
        let first = state
            .reconcile(desired, |handle| (handle == 9).then_some(3))
            .unwrap();
        let repeated = state
            .reconcile(desired, |handle| (handle == 9).then_some(3))
            .unwrap();
        assert_eq!(first, repeated);
        assert_eq!(state.registry().len(), 1);

        let mut stale = desired;
        stale.revision = 6;
        assert_eq!(
            state.reconcile(stale, |_| Some(3)),
            Err(ReconcileError::StaleRevision)
        );

        let unavailable = Request {
            allocation: 42,
            revision: 8,
            rule: Some(DesiredRule {
                proposed_dcid: None,
                route: RelayRoute {
                    next_hop: 10,
                    outbound_dcid: ConnectionId::new(0).unwrap(),
                },
                position: 2,
            }),
        };
        assert_eq!(
            state.reconcile(unavailable, |_| None),
            Err(ReconcileError::UnknownNextHop)
        );
        assert_eq!(state.registry().len(), 1);

        let absent = Request {
            allocation: 42,
            revision: 8,
            rule: None,
        };
        let removed = state.reconcile(absent, |_| Some(3)).unwrap();
        assert_eq!(removed.local_dcid, None);
        assert_eq!(removed.generation, 2);
        assert_eq!(state.registry().len(), 0);
    }

    struct LocalNode {
        registry: DcidRegistry<(), usize, 4>,
        next_response_packet: u32,
    }

    impl LocalNode {
        fn new() -> Self {
            Self {
                registry: DcidRegistry::new(),
                next_response_packet: 1,
            }
        }

        /// Process a local DCID-zero relay setup packet and return its direct
        /// correlated response. Replaying an identical request is accepted by
        /// the unified registry without creating a second rule.
        fn setup(&mut self, packet: &[u8]) -> Vec<u8> {
            let (_, payload) = decode_direct_packet(packet).unwrap();
            let record = crate::tagged::decode(payload).unwrap();
            let id = record.id.unwrap();
            let request = decode_request(payload).unwrap();
            let Some(DesiredRule {
                proposed_dcid: Some(dcid),
                route,
                ..
            }) = request.rule
            else {
                panic!("test setup must propose its local label")
            };
            self.registry
                .install_forward_idempotent(
                    dcid,
                    ForwardRule {
                        next_hop: usize::try_from(route.next_hop).unwrap(),
                        outbound_dcid: route.outbound_dcid,
                    },
                )
                .unwrap();
            let mut response = [0; 32];
            let response_len = crate::tagged::encode_numeric_response(
                RELAY_COMPONENT,
                RELAY_APPLY,
                id,
                &[0xa0],
                &mut response,
            )
            .unwrap();
            let mut direct = vec![0; 64];
            let used = encode_direct_packet(
                self.next_response_packet,
                &response[..response_len],
                &mut direct,
            )
            .unwrap();
            self.next_response_packet += 1;
            direct.truncate(used);
            direct
        }

        fn forward(&self, packet: &[u8]) -> (usize, Vec<u8>) {
            let prefix = ShortHeader::decode_prefix(packet).unwrap();
            let DcidIngress::Forward(_, rule) = self.registry.ingress(prefix).unwrap() else {
                panic!("test packet must select a forwarding rule")
            };
            let mut rewritten = vec![0; packet.len() + 8];
            let used = rewrite_dcid(packet, rule.outbound_dcid, &mut rewritten).unwrap();
            rewritten.truncate(used);
            (rule.next_hop, rewritten)
        }
    }

    fn setup_packet(request: Request, id: u64) -> Vec<u8> {
        let mut cbor = [0; 96];
        let cbor_len = encode_request(request, Some(id), &mut cbor).unwrap();
        let mut packet = vec![0; 128];
        let used = encode_direct_packet(id as u32, &cbor[..cbor_len], &mut packet).unwrap();
        packet.truncate(used);
        packet
    }

    #[test]
    fn pair_record_decoder_matches_the_packet_decoder() {
        let forward = Request {
            allocation: 10,
            revision: 1,
            rule: Some(DesiredRule {
                proposed_dcid: ConnectionId::new(17),
                route: RelayRoute {
                    next_hop: now_next_hop_handle([2, 0, 0, 0, 0, 1]).unwrap(),
                    outbound_dcid: ConnectionId::new(0).unwrap(),
                },
                position: 1,
            }),
        };
        let reverse = Request {
            allocation: 11,
            revision: 1,
            rule: Some(DesiredRule {
                proposed_dcid: ConnectionId::new(18),
                route: RelayRoute {
                    next_hop: udp6_next_hop_handle(3339).unwrap(),
                    outbound_dcid: ConnectionId::new(19).unwrap(),
                },
                position: 2,
            }),
        };
        let expected = PairRequest { forward, reverse };
        let mut wire = [0; 192];
        let used = encode_pair_request(expected, Some(31), &mut wire).unwrap();
        assert_eq!(decode_pair_request(&wire[..used]), Some(expected));
        assert_eq!(
            decode_pair_record(crate::tagged::decode(&wire[..used]).unwrap()),
            Some(expected)
        );
    }

    fn assert_setup_response(packet: &[u8], expected_id: u64) {
        let (_, payload) = decode_direct_packet(packet).unwrap();
        let record = crate::tagged::decode(payload).unwrap();
        assert_eq!(record.component, Some(Name::Tag(RELAY_COMPONENT)));
        assert_eq!(record.method, Some(Name::Tag(RELAY_APPLY)));
        assert_eq!(record.id, Some(expected_id));
        assert_eq!(record.result, Some(&[0xa0][..]));
    }

    #[test]
    fn four_local_nodes_install_retry_and_exchange_direct_messages_over_two_relays() {
        // Node indexes are only local test egress handles: B=1, C=2, D=3.
        let mut b = LocalNode::new();
        let mut c = LocalNode::new();
        let b_forward = ConnectionId::relay_local(2, 1).unwrap();
        let c_forward = ConnectionId::relay_local(2, 2).unwrap();
        let c_return = ConnectionId::relay_local(3, 1).unwrap();
        let b_return = ConnectionId::relay_local(3, 2).unwrap();

        let b_forward_setup = setup_packet(
            Request {
                allocation: 1,
                revision: 1,
                rule: Some(DesiredRule {
                    proposed_dcid: Some(b_forward),
                    route: RelayRoute {
                        next_hop: 2,
                        outbound_dcid: c_forward,
                    },
                    position: 1,
                }),
            },
            101,
        );
        // A retry sees the same direct-message id and receives the same
        // correlated result without consuming a second B rule.
        assert_setup_response(&b.setup(&b_forward_setup), 101);
        assert_setup_response(&b.setup(&b_forward_setup), 101);
        assert_eq!(b.registry.len(), 1);

        let c_forward_setup = setup_packet(
            Request {
                allocation: 2,
                revision: 1,
                rule: Some(DesiredRule {
                    proposed_dcid: Some(c_forward),
                    route: RelayRoute {
                        next_hop: 3,
                        outbound_dcid: ConnectionId::new(0).unwrap(),
                    },
                    position: 2,
                }),
            },
            102,
        );
        assert_setup_response(&c.setup(&c_forward_setup), 102);

        let c_return_setup = setup_packet(
            Request {
                allocation: 3,
                revision: 1,
                rule: Some(DesiredRule {
                    proposed_dcid: Some(c_return),
                    route: RelayRoute {
                        next_hop: 1,
                        outbound_dcid: b_return,
                    },
                    position: 1,
                }),
            },
            103,
        );
        assert_setup_response(&c.setup(&c_return_setup), 103);
        let b_return_setup = setup_packet(
            Request {
                allocation: 4,
                revision: 1,
                rule: Some(DesiredRule {
                    proposed_dcid: Some(b_return),
                    route: RelayRoute {
                        next_hop: 0,
                        outbound_dcid: ConnectionId::new(0).unwrap(),
                    },
                    position: 2,
                }),
            },
            104,
        );
        assert_setup_response(&b.setup(&b_return_setup), 104);
        assert_eq!(b.registry.len(), 2);
        assert_eq!(c.registry.len(), 2);

        // A's ordinary bounded request enters B under B's local label. B and
        // C only rewrite that label; D alone sees the final DCID-zero CBOR.
        let request = [0xa4, 1, 0x18, 99, 2, 1, 3, 0x18, 55, 5, 0xa0];
        let mut a_to_b = [0; 64];
        let a_to_b_len = encode_one_way_packet(b_forward, 500, &request, &mut a_to_b).unwrap();
        let (next, b_to_c) = b.forward(&a_to_b[..a_to_b_len]);
        assert_eq!(next, 2);
        let (next, c_to_d) = c.forward(&b_to_c);
        assert_eq!(next, 3);
        let (_, d_payload) = decode_direct_packet(&c_to_d).unwrap();
        let d_request = crate::tagged::decode(d_payload).unwrap();
        assert_eq!(d_request.id, Some(55));

        // D's correlated direct response uses the independently installed
        // return labels C -> B -> A.
        let mut response = [0; 32];
        let response_len =
            crate::tagged::encode_numeric_response(99, 1, 55, &[0xf5], &mut response).unwrap();
        let mut d_to_c = [0; 64];
        let d_to_c_len =
            encode_one_way_packet(c_return, 501, &response[..response_len], &mut d_to_c).unwrap();
        let (next, c_to_b) = c.forward(&d_to_c[..d_to_c_len]);
        assert_eq!(next, 1);
        let (next, b_to_a) = b.forward(&c_to_b);
        assert_eq!(next, 0);
        let (_, a_payload) = decode_direct_packet(&b_to_a).unwrap();
        let a_response = crate::tagged::decode(a_payload).unwrap();
        assert_eq!(a_response.id, Some(55));
        assert_eq!(a_response.result, Some(&[0xf5][..]));
    }

    struct LocalChainHandler {
        b: LocalNode,
        c: LocalNode,
        b_node: ChainNode,
        c_node: ChainNode,
    }

    impl ChainHandler for LocalChainHandler {
        type Error = ();

        fn resolve_next_hop(
            &mut self,
            _relay: ChainNode,
            next: ChainNode,
        ) -> Result<u64, Self::Error> {
            Ok(match next.address {
                LinkAddress::Mac(mac) => u64::from(mac[5]),
                LinkAddress::Ipv6LinkLocal(address) => u64::from(address[15]),
            })
        }

        fn exchange_direct(
            &mut self,
            relay: ChainNode,
            request: &[u8],
            response: &mut [u8],
        ) -> Result<usize, Self::Error> {
            let reply = if relay == self.b_node {
                self.b.setup(request)
            } else if relay == self.c_node {
                self.c.setup(request)
            } else {
                return Err(());
            };
            response[..reply.len()].copy_from_slice(&reply);
            Ok(reply.len())
        }
    }

    #[test]
    fn chain_handler_accepts_transport_and_link_addresses() {
        let a = ChainNode {
            transport: TransportId::NOW,
            address: LinkAddress::Mac([0, 0, 0, 0, 0, 10]),
        };
        let b = ChainNode {
            transport: TransportId::NOW,
            address: LinkAddress::Mac([0, 0, 0, 0, 0, 11]),
        };
        let c = ChainNode {
            transport: TransportId::UDP6,
            address: LinkAddress::Ipv6LinkLocal([
                0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 12,
            ]),
        };
        let d = ChainNode {
            transport: TransportId::UDP6,
            address: LinkAddress::Ipv6LinkLocal([
                0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 13,
            ]),
        };
        let mut handler = LocalChainHandler {
            b: LocalNode::new(),
            c: LocalNode::new(),
            b_node: b,
            c_node: c,
        };
        let mut request = [0; 192];
        let mut response = [0; 96];
        assert_eq!(
            install_symmetric_chain(
                &[a, b, c, d],
                100,
                200,
                &mut handler,
                &mut request,
                &mut response
            ),
            Ok(4)
        );
        assert_eq!(handler.b.registry.len(), 2);
        assert_eq!(handler.c.registry.len(), 2);
    }

    #[test]
    fn terminating_direct_dedup_replays_id_without_repeating_side_effect() {
        // {1:5(component), 2:1(method), 3:77(id)}
        let request = [0xa3, 1, 5, 2, 1, 3, 0x18, 77];
        let mut cache = TerminatingDirectDedup::<2, 32>::new();
        let mut response = [0; 32];
        assert_eq!(
            cache.check(10, &request, &mut response),
            TerminatingDirectDedupResult::New
        );
        assert!(cache.store(10, &request, b"done"));

        // A retry can have a fresh direct packet number but keeps its tagged
        // record ID. Only a final handler uses the cached response.
        assert_eq!(
            cache.check(11, &request, &mut response),
            TerminatingDirectDedupResult::Replay(4)
        );
        assert_eq!(&response[..4], b"done");

        let conflicting = [0xa3, 1, 5, 2, 2, 3, 0x18, 77];
        assert_eq!(
            cache.check(12, &conflicting, &mut response),
            TerminatingDirectDedupResult::Conflict
        );
    }
}
