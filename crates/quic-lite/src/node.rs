//! Node-wide ownership of QUIC associations and their DCID routes.
//!
//! A [`QuicNode`] owns every locally terminated client and server association
//! for one logical node. Bearers remain physical adapters: they deliver a
//! complete packet, and this owner selects association state by DCID alone.
//!
//! The node is an event-driven state machine. It never starts a
//! thread, task, executor, or internal event loop. A platform adapter calls it
//! for receive, timer, send-readiness, and send-completion events and uses its
//! reported next deadline to arm the platform timer. Tokio is one optional host
//! adapter; an ESP32 task drives the same non-std core methods.

use alloc::{boxed::Box, collections::VecDeque, sync::Arc, vec, vec::Vec};
use smallvec::SmallVec;

#[cfg(feature = "stateless-reset")]
use crate::StatelessResetKey;
use crate::bearer::{
    BearerContext, BearerId, BearerRegistry, CompletionQueue, EgressSubmission, OwnedPacket,
    PacketAcceptance, PacketBearer, PacketBuildError, PacketEgress, PacketMeta, PacketPool,
    PacketSubmitError, PacketWriter, PeerL2Address,
};
use crate::connection::{
    ClientAssociation, ServerPacket, ServerStreamConfig, ServerStreamConnection,
    classify_server_packet,
};
use crate::relay::{
    DEFAULT_SETUP_PENDING_TIMEOUT_US, DEFAULT_SETUP_REPLY_BYTES, DcidRegistryError,
    ForwardDestination, ForwardNextHop, ForwardRule, PacketRouter, RouterTarget, SetupReply,
    SetupResult, SetupTransactionLookup,
};
use crate::{ConnectionId, Error, Frame};
#[path = "node_datagram.rs"]
mod datagram;

/// Initial packet-timeout estimate used until an association has an RTT
/// sample. Runtime adapters share this protocol value; only timer arming is
/// platform-specific.
pub(crate) const DEFAULT_INITIAL_PTO_US: u64 = 250_000;
const DEFAULT_IDLE_TIMEOUT_US: u64 = 30_000_000;

/// Runtime node-wide admission and memory limits.
///
/// These values are policy rather than storage layout. Raising a limit takes
/// effect for later admission; lowering one never evicts live state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NodeLimits {
    /// Maximum simultaneously live associations admitted by this node.
    pub max_associations: usize,
    /// Maximum combined local and relay DCID routes.
    pub max_routes: usize,
    /// Packet-pool slots data forwarding must leave free for control traffic.
    /// The reserve is enforced on ingress, accounting for whether forwarding
    /// reuses the receive lease or allocates another slot. Zero disables it.
    pub relay_control_packet_reserve: usize,
}

impl NodeLimits {
    /// Generous defaults for heap-backed Linux and Android processes.
    pub const fn host() -> Self {
        Self {
            max_associations: 4_096,
            max_routes: 8_192,
            relay_control_packet_reserve: 0,
        }
    }

    /// Conservative defaults for low-RAM firmware. Products may override
    /// these from NVS before admitting associations.
    pub const fn embedded() -> Self {
        Self {
            max_associations: 4,
            max_routes: 8,
            relay_control_packet_reserve: 2,
        }
    }
}

impl Default for NodeLimits {
    fn default() -> Self {
        Self::host()
    }
}

/// Runtime path scoring and step-detection parameters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PathEstimatorConfig {
    /// Age after which the next matched RTT sample replaces the minimum RTT.
    pub minimum_rtt_age_window_us: u64,
    /// Outcome count used by the delivery-probability EWMA.
    pub delivery_horizon_packets: u8,
    /// RTT samples at least this percentage above the baseline count toward a step.
    pub rtt_step_threshold_percent: u16,
    /// Consecutive elevated matched RTT samples required to trigger a step.
    pub rtt_step_consecutive_samples: u8,
    /// Consecutive packet losses required to trigger a step.
    pub loss_step_consecutive_packets: u8,
    /// Time to use conservative path scoring while a fresh probe is pending.
    pub step_conservative_duration_us: u64,
    /// Temporary cost multiplier in Q16 during conservative scheduling.
    pub step_cost_multiplier_q16: u32,
}

impl PathEstimatorConfig {
    /// Fixed-point scale used by `step_cost_multiplier_q16`.
    pub const Q16_ONE: u32 = 1 << 16;

    /// Defaults used by host and embedded associations.
    pub const fn default_config() -> Self {
        Self {
            minimum_rtt_age_window_us: 60_000_000,
            delivery_horizon_packets: 8,
            rtt_step_threshold_percent: 50,
            rtt_step_consecutive_samples: 3,
            loss_step_consecutive_packets: 3,
            step_conservative_duration_us: 5_000_000,
            step_cost_multiplier_q16: Self::Q16_ONE * 2,
        }
    }

    /// Whether every configured age, horizon, threshold and multiplier is usable.
    pub const fn is_valid(self) -> bool {
        self.minimum_rtt_age_window_us != 0
            && self.delivery_horizon_packets != 0
            && self.delivery_horizon_packets <= 64
            && self.rtt_step_threshold_percent != 0
            && self.rtt_step_threshold_percent <= 1_000
            && self.rtt_step_consecutive_samples != 0
            && self.loss_step_consecutive_packets != 0
            && self.step_conservative_duration_us != 0
            && self.step_cost_multiplier_q16 >= Self::Q16_ONE
            && self.step_cost_multiplier_q16 <= Self::Q16_ONE * 16
    }
}

impl Default for PathEstimatorConfig {
    fn default() -> Self {
        Self::default_config()
    }
}

/// Per-path token-bucket pacing limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PacingConfig {
    /// Whether paced admission is active on each path.
    pub enabled: bool,
    /// Maximum packets emitted without waiting for paced refill.
    pub max_burst_packets: u16,
    /// Maximum wire bytes emitted without waiting for paced refill.
    pub max_burst_bytes: u32,
}

impl PacingConfig {
    /// Host defaults, allowing a short startup burst followed by cwnd/RTT pacing.
    pub const fn host() -> Self {
        Self {
            enabled: true,
            max_burst_packets: 8,
            max_burst_bytes: (crate::DEFAULT_MAX_PACKET_SIZE * 8) as u32,
        }
    }

    /// Low-memory defaults keep the initial burst below four packet slots.
    pub const fn embedded() -> Self {
        Self {
            enabled: true,
            max_burst_packets: 4,
            max_burst_bytes: (crate::DEFAULT_MAX_PACKET_SIZE * 4) as u32,
        }
    }

    /// Whether the byte cap can admit one maximum-size DMesh packet.
    pub const fn is_valid(self) -> bool {
        self.max_burst_packets != 0
            && self.max_burst_packets <= 256
            && self.max_burst_bytes >= crate::DEFAULT_MAX_PACKET_SIZE as u32
            && self.max_burst_bytes <= 1_048_576
    }
}

impl Default for PacingConfig {
    fn default() -> Self {
        Self::host()
    }
}

/// Runtime defaults and growth ceilings for newly admitted associations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AssociationLimits {
    /// Receive windows and peer stream concurrency growth policy.
    pub connection: crate::ConnectionLimits,
    /// Maximum retained logical stream ranges for either endpoint role.
    pub history_packets: usize,
    /// Maximum per-transmission metadata records, including retransmissions
    /// and reserved probe capacity.
    pub transmission_records: usize,
    /// Maximum live ordered-delivery stream records.
    pub max_pending_streams: usize,
    /// Maximum chunks queued for one Tokio stream reader before receive
    /// credit is withheld for that stream.
    pub max_queued_chunks_per_stream: usize,
    /// Maximum bytes retained for out-of-order or backpressured delivery.
    pub max_buffered_stream_bytes: usize,
    /// Maximum duplicate/probe byte credit retained by the association.
    /// Accepted original traffic earns 10% of its wire size up to this cap.
    pub duplication_budget_bytes: usize,
    /// Minimum time between padded path challenges on one standby circuit.
    /// One challenge and its response form the idle probe allowance.
    pub path_probe_interval_us: u64,
    /// RTT, delivery and sustained-step estimator policy for each circuit.
    pub path_estimator: PathEstimatorConfig,
    /// Maximum immediate burst and subsequent per-path pacing rate.
    pub pacing: PacingConfig,
}

impl AssociationLimits {
    /// Generous defaults for heap-backed Linux and Android processes.
    pub const fn host() -> Self {
        Self {
            connection: crate::ConnectionLimits::with_receive_profile(
                16 * 1024 * 1024,
                4 * 1024 * 1024,
                256,
            ),
            history_packets: 128,
            transmission_records: 256,
            max_pending_streams: 256,
            max_queued_chunks_per_stream: 64,
            max_buffered_stream_bytes: 16 * 1024 * 1024,
            duplication_budget_bytes: 64 * 1024,
            path_probe_interval_us: 5_000_000,
            path_estimator: PathEstimatorConfig::default_config(),
            pacing: PacingConfig::host(),
        }
    }

    /// Conservative defaults for low-RAM firmware.
    pub const fn embedded() -> Self {
        Self {
            connection: crate::ConnectionLimits::with_receive_profile(32 * 1024, 8 * 1024, 4),
            // Keep receive headroom in the embedded packet pool for inbound
            // ACK and MAX_STREAM_DATA packets; allowing history to occupy
            // every packet slot would prevent those packets from releasing it.
            history_packets: 6,
            transmission_records: 12,
            max_pending_streams: 4,
            max_queued_chunks_per_stream: 2,
            max_buffered_stream_bytes: 32 * 1024,
            duplication_budget_bytes: 1024,
            path_probe_interval_us: 5_000_000,
            path_estimator: PathEstimatorConfig::default_config(),
            pacing: PacingConfig::embedded(),
        }
    }
}

impl Default for AssociationLimits {
    fn default() -> Self {
        Self::host()
    }
}

/// Stable handle for one locally terminated association.
///
/// The slot and generation are intentionally private. A removed handle never
/// names a later association which reuses the same fixed-capacity slot.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct QuicAssociation {
    slot: u32,
    generation: u64,
}

/// One live association: who it runs over and its QUIC transport state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AssociationRow {
    /// Identifier local to this node (the association's slot).
    pub id: u64,
    /// Bearer and bearer-local peer of the association's first path, when known.
    pub bearer: Option<BearerId>,
    /// Bearer-local peer address of that path.
    pub peer: Option<PeerL2Address>,
    /// Transport counters and send state.
    pub telemetry: crate::AssociationTelemetry,
}

/// One registered bearer: its state and the node's counters for it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BearerRow {
    /// Node-local handle.
    pub id: BearerId,
    /// Registered bearer name.
    pub name: crate::BearerName,
    /// Whether the bearer is eligible for new sends and receives.
    pub enabled: bool,
    /// Packets accepted by the bearer and not yet reported complete.
    pub in_flight_packets: u64,
    /// Packets received from the bearer.
    pub received_packets: u64,
    /// Received packets dropped for lack of a packet slot or queue room.
    pub ingress_drops: u64,
    /// Packets handed to the bearer.
    pub submitted_packets: u64,
    /// Packets the bearer reported complete.
    pub completed_packets: u64,
    /// Submissions refused as temporarily busy.
    pub send_would_block: u64,
    /// Submissions that failed.
    pub send_failures: u64,
}

/// Opaque handle for one direct circuit within a locally owned association.
///
/// The local identifier is generation-checked through the owning association;
/// it does not reveal the circuit's wire key or either endpoint CID.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct CircuitId {
    association: QuicAssociation,
    local_id: u64,
}

impl CircuitId {
    pub(crate) const fn association(self) -> QuicAssociation {
        self.association
    }
}

/// Current state observed for a direct circuit. Standby reports that the peer
/// has stopped transmitting on its side; this does not disable reverse sends.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CircuitStatus {
    /// Join was sent or received, but same-circuit traffic has not validated it.
    Opening,
    /// A suspended circuit is being checked on its existing CID pair.
    Probing,
    /// The peer has demonstrated that it can receive on this circuit.
    Active,
    /// The circuit is validated but currently idle for application data.
    Standby,
    /// The bearer or neighbour is unavailable; recovery waits for a matched probe.
    Suspended,
    /// Local loss policy stopped scheduling this circuit.
    Failed,
    /// The circuit was abandoned and its route retired.
    Closed,
}

/// Bearer-local destination of a direct circuit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CircuitNextHop {
    /// Registered bearer used for this circuit.
    pub bearer: BearerId,
    /// Destination understood by that bearer.
    pub peer_l2_address: PeerL2Address,
}

/// One client-selected relay instruction for a layered circuit setup.
///
/// The address is interpreted by the relay selected by `address_kind`; it is
/// opaque to this node. The instruction is copied into PATH_OPEN and replayed
/// unchanged until setup succeeds or times out.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RelayHop {
    /// Address namespace understood by the relay.
    pub address_kind: u8,
    /// Number of meaningful bytes in `address`.
    pub address_len: u8,
    /// Opaque next-hop address bytes.
    pub address: [u8; crate::relay::MAX_SETUP_HOP_ADDRESS_BYTES],
    /// Requested rule lease in microseconds.
    pub lease_us: u64,
    /// Requested packet quota for this rule.
    pub packet_quota: u64,
}

impl RelayHop {
    /// Construct a hop from an address slice.
    pub fn new(
        address_kind: u8,
        address: &[u8],
        lease_us: u64,
        packet_quota: u64,
    ) -> Result<Self, QuicNodeEgressError> {
        if address.is_empty() || address.len() > crate::relay::MAX_SETUP_HOP_ADDRESS_BYTES {
            return Err(QuicNodeEgressError::Transport(Error::Invalid));
        }
        let mut stored = [0; crate::relay::MAX_SETUP_HOP_ADDRESS_BYTES];
        stored[..address.len()].copy_from_slice(address);
        Ok(Self {
            address_kind,
            address_len: address.len() as u8,
            address: stored,
            lease_us,
            packet_quota,
        })
    }
}

/// Maximum number of nearby relays an endpoint advertises for an optional
/// peer-built return circuit.
pub const MAX_NEARBY_RETURN_RELAYS: usize = 3;

/// One untrusted nearby-relay hint supplied with a relayed association open.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NearbyRelayHint {
    /// Stable device identity of the suggested nearby relay.
    pub relay_id: [u8; 8],
    /// Relay-local egress instruction the peer may use for a return route.
    pub hop: RelayHop,
}

/// Fixed-size nearby-relay hints carried from the path opener to the accepted
/// endpoint. These are suggestions for a later JOIN; they do not create a
/// route or change transport state by themselves.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NearbyRelayHints {
    len: u8,
    entries: [Option<NearbyRelayHint>; MAX_NEARBY_RETURN_RELAYS],
}

impl NearbyRelayHints {
    /// Empty hint set, used by legacy callers that do not advertise return relays.
    pub const EMPTY: Self = Self {
        len: 0,
        entries: [None; MAX_NEARBY_RETURN_RELAYS],
    };

    /// Validate and copy at most [`MAX_NEARBY_RETURN_RELAYS`] unique relay hints.
    pub fn new(hints: &[NearbyRelayHint]) -> Option<Self> {
        if hints.len() > MAX_NEARBY_RETURN_RELAYS {
            return None;
        }
        let mut entries = [None; MAX_NEARBY_RETURN_RELAYS];
        for (index, hint) in hints.iter().enumerate() {
            if hint.relay_id == [0; 8]
                || hints[..index]
                    .iter()
                    .any(|previous| previous.relay_id == hint.relay_id)
            {
                return None;
            }
            entries[index] = Some(*hint);
        }
        Some(Self {
            len: hints.len() as u8,
            entries,
        })
    }

    /// Whether no return relay hints are present.
    pub const fn is_empty(self) -> bool {
        self.len == 0
    }

    /// Number of retained nearby relay hints.
    pub const fn len(self) -> usize {
        self.len as usize
    }

    /// Iterate over the copied return relay hints.
    pub fn iter(&self) -> impl Iterator<Item = &NearbyRelayHint> {
        self.entries[..self.len()].iter().flatten()
    }
}

/// Allocation-free, read-only snapshot of one circuit.
///
/// Use [`Default::default`] to initialize an output slice; only entries below
/// the count returned by [`QuicNode::circuits`] contain snapshots.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CircuitInfo {
    /// Opaque local circuit handle.
    pub id: CircuitId,
    /// First hop selected when the circuit was opened.
    pub first_hop: CircuitNextHop,
    /// Whether the remote endpoint initiated this circuit.
    pub opened_by_peer: bool,
    /// Current validation state.
    pub status: CircuitStatus,
    /// Smoothed round-trip time, or zero before a matched sample.
    pub srtt_us: u32,
    /// Minimum observed round-trip time, or zero before a matched sample.
    pub min_rtt_us: u32,
    /// Current congestion window in bytes.
    pub cwnd_bytes: u32,
    /// Current in-flight bytes.
    pub bytes_in_flight: u32,
    /// Number of stream packets prepared on this circuit.
    pub packets_sent: u64,
    /// Number of stream retransmissions prepared on this circuit.
    pub retransmitted_packets: u64,
    /// Receive packet ranges dropped from the association ACK set while
    /// packets arrived on this circuit after the fixed range capacity filled.
    pub ack_ranges_dropped: u64,
    /// Number of packets acknowledged on this circuit.
    pub packets_acked: u64,
    /// Number of packets declared lost on this circuit.
    pub packets_lost: u64,
    /// Packets later acknowledged after transport loss inference.
    pub spurious_losses: u64,
    /// Number of retransmission or proactive duplicate copies prepared here.
    pub packets_duplicated: u64,
    /// Wire bytes in stream retransmissions and duplicate copies prepared here.
    pub duplicate_bytes_prepared: u64,
    /// Wire bytes in PATH_CHALLENGE and PATH_RESPONSE packets prepared here.
    pub probe_bytes_prepared: u64,
    /// Accepted probe wire bytes debited from the association duplication bucket.
    pub probe_bytes_budgeted: u64,
    /// Accepted probe wire bytes sent under the per-circuit idle allowance.
    pub probe_bytes_idle_exempt: u64,
    /// RTT or loss step detections on this circuit.
    pub estimator_step_events: u64,
    /// End of the current conservative scoring period, or zero when inactive.
    pub step_conservative_until_us: u64,
    /// Node clock at the latest ACK observed for this circuit.
    pub last_ack_us: u64,
}

impl Default for CircuitInfo {
    fn default() -> Self {
        Self {
            id: CircuitId {
                association: QuicAssociation {
                    slot: u32::MAX,
                    generation: 0,
                },
                local_id: 0,
            },
            first_hop: CircuitNextHop {
                bearer: BearerId::new(1).expect("nonzero placeholder bearer"),
                peer_l2_address: PeerL2Address::new(1).expect("nonzero placeholder peer"),
            },
            opened_by_peer: false,
            status: CircuitStatus::Opening,
            srtt_us: 0,
            min_rtt_us: 0,
            cwnd_bytes: 0,
            bytes_in_flight: 0,
            packets_sent: 0,
            retransmitted_packets: 0,
            ack_ranges_dropped: 0,
            packets_acked: 0,
            packets_lost: 0,
            spurious_losses: 0,
            packets_duplicated: 0,
            duplicate_bytes_prepared: 0,
            probe_bytes_prepared: 0,
            probe_bytes_budgeted: 0,
            probe_bytes_idle_exempt: 0,
            estimator_step_events: 0,
            step_conservative_until_us: 0,
            last_ack_us: 0,
        }
    }
}

/// Opaque application stream owned by one [`QuicAssociation`].
///
/// Applications do not select stream identifiers or maintain byte offsets.
/// Successful writes advance the ordered send position; a failed write leaves
/// the handle unchanged so the same bytes can be retried after progress.
#[derive(Debug, Eq, PartialEq)]
pub struct QuicStream {
    owner: StreamOwner,
    id: u64,
    send_offset: u64,
    send_finished: bool,
    priority: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StreamOwner {
    Association(QuicAssociation),
}

impl QuicStream {
    /// Transport stream identifier, exposed for protocol-neutral diagnostics
    /// which correlate a fixed set of peer-opened streams.
    pub const fn id(&self) -> u64 {
        self.id
    }

    /// Opaque identity of the association which owns this stream. The handle
    /// is generation checked and reveals no wire connection identifier.
    pub const fn association_id(&self) -> Option<QuicAssociation> {
        self.association()
    }

    /// Mark this stream as latency-sensitive control traffic. Accepted data
    /// packets on a priority stream may be duplicated over an alternate path
    /// when the association's duplication budget allows it.
    pub fn set_priority(&mut self, priority: bool) {
        self.priority = priority;
    }

    /// Whether this stream is marked for budgeted control duplication.
    pub const fn is_priority(&self) -> bool {
        self.priority
    }

    /// Whether two opaque handles refer to the same stream, ignoring their
    /// independently tracked send offsets and FIN state.
    pub const fn same_stream(&self, other: &Self) -> bool {
        let (StreamOwner::Association(left), StreamOwner::Association(right)) =
            (self.owner, other.owner);
        self.id == other.id && left.slot == right.slot && left.generation == right.generation
    }

    pub(crate) fn incoming(association: QuicAssociation, id: u64) -> Self {
        Self {
            owner: StreamOwner::Association(association),
            id,
            send_offset: 0,
            send_finished: false,
            priority: false,
        }
    }

    pub(crate) const fn association(&self) -> Option<QuicAssociation> {
        match self.owner {
            StreamOwner::Association(association) => Some(association),
        }
    }

    pub(crate) const fn owner(&self) -> StreamOwner {
        self.owner
    }

    pub(crate) fn matches(&self, owner: StreamOwner, id: u64) -> bool {
        let same_owner = self.owner == owner;
        same_owner && self.id == id
    }

    pub(crate) const fn send_finished(&self) -> bool {
        self.send_finished
    }
}

/// One ordered application-stream chunk received by a host node.
///
/// `offset == 0` identifies the first delivered chunk. Delivery is currently
/// ordered; a future explicit out-of-order mode may relax that guarantee.
pub struct ReceivedStreamChunk {
    /// Opaque stream handle used for replies and subsequent reads.
    pub stream: QuicStream,
    /// Byte offset of this chunk within the stream.
    pub offset: u64,
    /// Whether this chunk closes the peer's sending half.
    pub fin: bool,
    /// Ordered application bytes carried by this chunk.
    pub bytes: Vec<u8>,
}

#[cfg(feature = "tokio")]
pub(crate) struct QueuedStreamChunk {
    pub owner: StreamOwner,
    pub stream: u64,
    pub offset: u64,
    pub fin: bool,
    pub bytes: Vec<u8>,
}

/// Per-stream admission of received chunks into the Tokio chunk queue.
///
/// Each association stream may have at most `limit` chunks waiting for its
/// reader. Beyond that the callback accepts 0 bytes: QUIC-lite retains them
/// without granting receive credit, so a slow reader backpressures only its
/// own stream (through flow control) instead of stopping node ingress.
/// A zero-length FIN cannot be refused and is always queued.
#[cfg(feature = "tokio")]
pub(crate) struct ChunkAdmission {
    queued: Vec<(StreamOwner, u64, usize)>,
    default_limit: usize,
    association_limits: Vec<(QuicAssociation, usize)>,
    pub chunks: Vec<QueuedStreamChunk>,
    pub deferred: Vec<(QuicAssociation, u64)>,
}

#[cfg(feature = "tokio")]
impl ChunkAdmission {
    pub(crate) fn new(
        queue: &std::collections::VecDeque<QueuedStreamChunk>,
        default_limit: usize,
        association_limits: Vec<(QuicAssociation, usize)>,
    ) -> Self {
        let mut queued: Vec<(StreamOwner, u64, usize)> = Vec::new();
        for chunk in queue {
            match queued
                .iter_mut()
                .find(|(owner, stream, _)| *owner == chunk.owner && *stream == chunk.stream)
            {
                Some(entry) => entry.2 += 1,
                None => queued.push((chunk.owner, chunk.stream, 1)),
            }
        }
        Self {
            queued,
            default_limit: default_limit.max(1),
            association_limits,
            chunks: Vec::new(),
            deferred: Vec::new(),
        }
    }

    pub(crate) fn offer(
        &mut self,
        source: ApplicationStreamSource,
        stream: u64,
        offset: u64,
        fin: bool,
        bytes: &[u8],
    ) -> Result<usize, Error> {
        let ApplicationStreamSource::Association(association) = source;
        let owner = StreamOwner::Association(association);
        let limit = self
            .association_limits
            .iter()
            .find_map(|(owner, limit)| (*owner == association).then_some(*limit))
            .unwrap_or(self.default_limit)
            .max(1);
        let queued = self
            .queued
            .iter()
            .find(|(queued_owner, queued_stream, _)| {
                *queued_owner == owner && *queued_stream == stream
            })
            .map_or(0, |entry| entry.2);
        if !bytes.is_empty() && queued >= limit {
            if !self.deferred.contains(&(association, stream)) {
                self.deferred.push((association, stream));
            }
            return Ok(0);
        }
        match self
            .queued
            .iter_mut()
            .find(|(queued_owner, queued_stream, _)| {
                *queued_owner == owner && *queued_stream == stream
            }) {
            Some(entry) => entry.2 += 1,
            None => self.queued.push((owner, stream, 1)),
        }
        self.chunks.push(QueuedStreamChunk {
            owner,
            stream,
            offset,
            fin,
            bytes: bytes.to_vec(),
        });
        Ok(bytes.len())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Failure while locating or changing association state owned by a node.
///
/// This type is public because association and stream handles report stale or
/// capacity-exhausted state without exposing node slots, CIDs, or routing data.
pub enum QuicNodeError {
    /// The node's configured association slots are all occupied.
    AssociationTableFull,
    /// The handle is stale or its association has already been removed.
    MissingAssociation,
    /// The operation is valid only for the other endpoint role.
    WrongAssociationRole,
    /// The node could not install or remove the private CID route.
    Routing,
    /// A runtime resource policy contains a zero or unrepresentable limit.
    InvalidLimits,
}

/// Why an owned packet could not enter an established local association.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum QuicNodePacketRejection {
    Packet(Error),
    PeerClosed(u64),
    Egress(QuicNodeEgressError),
    /// Transport state accepted the packet, but its registered application
    /// callback failed. The return address has already been updated.
    Application(Error),
}

/// Node policy for admitting one validated Initial.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct InitialAdmission {
    pub local_limits: crate::ConnectionLimits,
}

/// Packet emitted without an association, such as a stateless reset.
pub(crate) struct NodePacket<B> {
    pub bearer: BearerId,
    pub peer_l2_address: PeerL2Address,
    pub packet: OwnedPacket<B>,
}

/// Owner of an application stream delivered by [`QuicNode::receive_packet`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ApplicationStreamSource {
    Association(QuicAssociation),
}

/// Complete outcome of submitting one opaque packet to [`QuicNode`].
pub(crate) enum NodeIngress<B, EgressBuffer, NextHop> {
    Datagram {
        association: AssociationIngress,
    },
    Association {
        association: AssociationIngress,
        packet: OwnedPacket<B>,
    },
    Initial {
        association: QuicAssociation,
        response: NodePacket<EgressBuffer>,
    },
    SetupReply {
        response: NodePacket<EgressBuffer>,
    },
    SetupAccepted {
        association: QuicAssociation,
        return_hints: NearbyRelayHints,
        response: NodePacket<EgressBuffer>,
    },
    PathControl {
        association: QuicAssociation,
        response: NodeEgress<EgressBuffer>,
    },
    InitialDeclined {
        packet: OwnedPacket<B>,
    },
    Forward {
        next_hop: NextHop,
        packet: OwnedPacket<EgressBuffer>,
    },
    StatelessReset {
        response: NodePacket<EgressBuffer>,
    },
    PeerReset {
        association: QuicAssociation,
        packet: OwnedPacket<B>,
    },
    PeerClosed {
        association: QuicAssociation,
        code: u64,
        packet: OwnedPacket<B>,
    },
    Unknown {
        destination: ConnectionId,
        packet: OwnedPacket<B>,
    },
    NonQuic {
        error: Error,
        packet: OwnedPacket<B>,
    },
}

/// Rejected ingress with ownership of the original pool lease preserved.
#[derive(Debug)]
pub(crate) struct RejectedNodePacket<B> {
    pub reason: QuicNodePacketRejection,
    pub packet: OwnedPacket<B>,
}

/// Local association which accepted one received packet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AssociationIngress {
    Client(QuicAssociation),
    Server(QuicAssociation),
}

impl AssociationIngress {
    pub(crate) const fn association(self) -> QuicAssociation {
        match self {
            Self::Client(association) | Self::Server(association) => association,
        }
    }
}

/// Common space before every QUIC packet for relay and physical envelopes.
pub const PACKET_PREFIX_RESERVE: usize = 80;
/// AEAD, future four-byte HMAC, and receive-FCS tail space in a pool slot.
pub const PACKET_SUFFIX_RESERVE: usize = 24;
/// Minimum node-owned pool slot for the default 1,100-byte QUIC packet.
pub const DEFAULT_PACKET_POOL_SLOT_SIZE: usize =
    PACKET_PREFIX_RESERVE + crate::DEFAULT_MAX_PACKET_SIZE + PACKET_SUFFIX_RESERVE;

/// One QUIC-produced packet ready for the registered bearer callback.
///
/// The owner must retain this exact value across `WouldBlock` and must not ask
/// the same association to prepare later output first. It may recover the
/// unchanged packet from the rejected [`crate::EgressSubmission`] and offer it
/// through another eligible registered bearer.
pub(crate) struct NodeEgress<B> {
    pub association: QuicAssociation,
    pub bearer: BearerId,
    pub peer_l2_address: PeerL2Address,
    pub packet: OwnedPacket<B>,
}

#[derive(Clone, Copy)]
struct ControlDuplicationCandidate {
    acceptance: PacketAcceptance,
    source_path: usize,
    include_ack: bool,
    include_max_data: bool,
    stream_credit_count: usize,
    include_max_streams_bidi: bool,
}

#[derive(Clone, Copy)]
struct PendingControlCopy {
    bearer: BearerId,
    candidate: ControlDuplicationCandidate,
}

/// One result from an expired node deadline.
pub(crate) enum NodeTimer<B> {
    /// A complete packet which the runtime must retain across bearer
    /// `WouldBlock` and submit before asking this association for more output.
    Egress(NodeEgress<B>),
    /// The client Initial reached its configured attempt limit without a valid
    /// OPEN_ACK. The association and its DCID have already been retired.
    BootstrapTimedOut { association: QuicAssociation },
    /// No packet activity occurred before the node's enforced idle deadline.
    /// The association and its DCID have already been retired.
    IdleTimedOut { association: QuicAssociation },
    /// A relayed circuit setup exhausted its retry deadline. Its provisional
    /// path and receive CID have already been retired; the association stays
    /// active on its other circuits.
    CircuitSetupTimedOut {
        association: QuicAssociation,
        circuit: CircuitId,
    },
}

/// Terminal lifecycle notification emitted by every runtime adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AssociationEvent {
    /// A new circuit was opened locally or by the peer.
    CircuitOpened {
        /// Association that owns the circuit.
        association: QuicAssociation,
        /// Local opaque handle for the circuit.
        circuit: CircuitId,
    },
    /// A circuit changed between opening, probing, and active validation, or the
    /// peer changed its transmit status for this circuit.
    CircuitStatusChanged {
        /// Association that owns the circuit.
        association: QuicAssociation,
        /// Local opaque handle for the circuit.
        circuit: CircuitId,
        /// Newly observed circuit state. `Standby` is directional: the peer
        /// will not transmit, while this endpoint may still send in reverse.
        status: CircuitStatus,
    },
    /// A direct circuit was closed after its transmission records retired.
    CircuitClosed {
        /// Association that owned the circuit.
        association: QuicAssociation,
        /// Retired local circuit handle.
        circuit: CircuitId,
    },
    /// The peer closed the association with an application or transport code.
    Closed {
        /// Association that was retired.
        association: QuicAssociation,
        /// Close code supplied by the peer.
        code: u64,
    },
    /// A valid stateless reset retired the association.
    Reset {
        /// Association that was retired.
        association: QuicAssociation,
    },
    /// The association reached its enforced idle deadline.
    IdleTimeout {
        /// Association that was retired.
        association: QuicAssociation,
    },
    /// The peer did not complete association setup before the Initial retry
    /// limit was reached.
    SetupTimeout {
        /// Client association that was retired.
        association: QuicAssociation,
    },
    /// A relay or endpoint rejected a client-selected circuit setup.
    SetupRejected {
        /// Association that owned the rejected setup.
        association: QuicAssociation,
        /// Circuit rejected by a JOIN, or `None` when CREATE was rejected.
        circuit: Option<CircuitId>,
        /// Whether this event retired the association itself.
        association_retired: bool,
        /// Rejection code supplied by the rejecting node.
        code: u64,
    },
    /// Untrusted nearby-relay suggestions received with a relayed association
    /// create. Applications may use these to request a server-built return
    /// circuit on the same association.
    PeerReturnPathHints {
        /// Association created by the relayed peer's CREATE transaction.
        association: QuicAssociation,
        /// Untrusted hints that the peer attached to the CREATE transaction.
        hints: NearbyRelayHints,
    },
    /// Lifecycle notifications were discarded because the application did not
    /// drain the fixed-capacity event queue before more associations ended.
    EventsDropped {
        /// Number of notifications discarded since the previous report.
        count: u64,
    },
}

/// Progress from an explicit local association close.
pub(crate) enum NodeClose<B> {
    /// ACK or flow-control output which must precede CLOSE. Submit this packet
    /// and call `close_association` again with the same code.
    Control(NodeEgress<B>),
    /// The final CLOSE packet. The association and DCID have been retired;
    /// this owned packet remains retryable across bearer `WouldBlock`.
    Closed(NodeEgress<B>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Failure to construct or submit output for a public association/stream call.
///
/// This enum is public so Tokio and no-std applications can make the same
/// retry/drop decision without gaining access to packet or driver internals.
pub enum QuicNodeEgressError {
    /// Association lookup or lifecycle failure.
    Association(QuicNodeError),
    /// QUIC protocol or flow-control failure.
    Transport(Error),
    /// No node-owned packet lease is currently free; retry after progress.
    PoolUnavailable,
    /// The configured pool slot cannot provide required prefix/payload space.
    InvalidPoolLayout,
    /// No accepted packet has established a physical return address.
    MissingEgressAddress,
    /// The association's selected bearer is no longer registered.
    MissingBearer,
    /// The bearer retained an earlier packet and cannot accept another yet.
    BearerBusy,
    /// A circuit has transmissions awaiting retirement or its abandon status
    /// has not yet been acknowledged.
    CircuitBusy,
    /// A fixed-capacity node or runtime-adapter event queue has no free slot.
    StreamEventsFull,
    /// The peer did not complete association setup before its retry limit.
    AssociationTimedOut,
    /// Direct circuit setup reached its explicit packet-attempt limit.
    PathSetupAttemptsExhausted,
    /// A relay or endpoint rejected the client-selected circuit setup.
    SetupRejected(u64),
}

impl QuicNodeEgressError {
    /// Whether unchanged stream bytes may be retried after node progress.
    ///
    /// A retryable result never commits the supplied stream bytes or FIN.
    /// Callers must first make node, bearer, packet-pool, or flow-control
    /// progress, then retry the same operation unchanged.
    pub const fn is_retryable(self) -> bool {
        matches!(
            self,
            Self::BearerBusy
                | Self::PoolUnavailable
                | Self::Transport(Error::Blocked)
                | Self::Transport(Error::FlowControl)
                | Self::Transport(Error::HistoryFull)
        )
    }
}

pub(crate) struct NodeBearer<T>(pub(crate) T);

impl<B, T> PacketEgress<B> for NodeBearer<T>
where
    B: AsRef<[u8]>,
    T: PacketEgress<B>,
{
    fn submit(
        &mut self,
        peer_l2_address: PeerL2Address,
        submission: EgressSubmission<B>,
    ) -> Result<(), PacketSubmitError<B>> {
        self.0.submit(peer_l2_address, submission)
    }
}

impl From<QuicNodeError> for QuicNodeEgressError {
    fn from(error: QuicNodeError) -> Self {
        Self::Association(error)
    }
}

impl From<DcidRegistryError> for QuicNodeError {
    fn from(_error: DcidRegistryError) -> Self {
        Self::Routing
    }
}

impl<P, const PACKET: usize> QuicNode<P, PACKET>
where
    P: PacketPool + 'static,
    P::Buffer: Send,
{
    pub(crate) fn register_bearer_with_ingress<T>(
        &mut self,
        bearer: T,
        ingress: Arc<dyn crate::bearer::PacketIngressQueue<P::Buffer>>,
    ) -> Result<BearerId, crate::AddBearerError<T::AttachError>>
    where
        T: PacketBearer<P> + 'static,
    {
        self.register_bearer_ingress(bearer, crate::bearer::PacketIngressHandle::Dynamic(ingress))
    }

    pub(crate) fn register_bearer_with_queue<T>(
        &mut self,
        bearer: T,
        ingress: Arc<crate::nostd::IngressQueue<P::Buffer>>,
    ) -> Result<BearerId, crate::AddBearerError<T::AttachError>>
    where
        T: PacketBearer<P> + 'static,
    {
        self.register_bearer_ingress(bearer, crate::bearer::PacketIngressHandle::Queued(ingress))
    }

    fn register_bearer_ingress<T>(
        &mut self,
        mut bearer: T,
        ingress: crate::bearer::PacketIngressHandle<P::Buffer>,
    ) -> Result<BearerId, crate::AddBearerError<T::AttachError>>
    where
        T: PacketBearer<P> + 'static,
    {
        let info = bearer.info();
        if info.max_packet_size < PACKET {
            return Err(crate::AddBearerError::PacketTooSmall {
                actual: info.max_packet_size,
                required: PACKET,
            });
        }
        let id = self
            .bearers
            .reserve_id(info.name)
            .map_err(crate::AddBearerError::Registry)?;
        bearer
            .attach(BearerContext::new(
                id,
                self.pool,
                ingress,
                self.completions.clone(),
            ))
            .map_err(crate::AddBearerError::Attach)?;
        let id = self
            .bearers
            .register(id, info, NodeBearer(bearer), self.completions.clone())
            .map_err(crate::AddBearerError::Registry)?;
        let bearer = self
            .bearers
            .get_mut(id)
            .expect("new bearer remains registered");
        bearer.set_enabled(true);
        bearer.send_ready();
        Ok(id)
    }

    /// Remove one physical packet bearer from this node.
    ///
    /// Associations remain valid, but addresses learned through this bearer
    /// are forgotten. An association can continue immediately through another
    /// address it has already used; otherwise later sends report
    /// [`QuicNodeEgressError::MissingEgressAddress`]. Any packet retained after
    /// `WouldBlock` is returned to the node-owned pool. A packet already
    /// accepted by the physical bearer is returned by its completion token.
    ///
    /// Bearer IDs are never reused during a node's lifetime, so late readiness
    /// or completion callbacks from the removed bearer cannot affect a later
    /// registration.
    pub fn remove_bearer(&mut self, id: BearerId) -> bool {
        if !self.bearers.remove(id) {
            return false;
        }
        for pending in &mut self.pending_control_copies {
            if pending.is_some_and(|copy| copy.bearer == id) {
                *pending = None;
            }
        }
        for slot_index in 0..self.associations.len() {
            let Some(entry) = self.associations[slot_index].as_ref() else {
                continue;
            };
            let association = QuicAssociation {
                slot: slot_index as u32,
                generation: entry.generation,
            };
            let mut suspended = [None; crate::MAX_PATH_STATES];
            {
                let slot = self.associations[slot_index].as_mut().unwrap();
                for path_id in 0..Self::slot_path_count(slot) {
                    let should_suspend = {
                        let Some(path) = Self::slot_path_state_mut(slot, path_id) else {
                            continue;
                        };
                        path.remove_bearer(id);
                        path.active_address().is_none() && !path.is_suspended()
                    };
                    if should_suspend {
                        let endpoint = match &mut slot.state {
                            Association::Client(client) => client
                                .connection_mut()
                                .endpoint_mut()
                                .expect("established path has endpoint"),
                            Association::Server(server) => &mut server.mux.endpoint,
                        };
                        endpoint.suspend_path(path_id);
                        let _ = endpoint.queue_path_status(path_id, crate::PathStatusKind::Standby);
                        suspended[path_id] =
                            Some(endpoint.path_state(path_id).unwrap().local_circuit_id());
                    }
                }
                if slot
                    .bootstrap_address
                    .is_some_and(|(bearer, _)| bearer == id)
                {
                    slot.bootstrap_address = None;
                }
            }
            for local_id in suspended.into_iter().flatten() {
                self.push_association_event(AssociationEvent::CircuitStatusChanged {
                    association,
                    circuit: CircuitId {
                        association,
                        local_id,
                    },
                    status: CircuitStatus::Suspended,
                });
            }
        }
        true
    }

    pub(crate) fn drain_bearer_events(&mut self) -> bool {
        let mut progressed = false;
        while let Some(completion) = self.completions.pop_completion() {
            progressed = true;
            if completion.outcome == crate::PacketSendOutcome::Failed
                && let Some(acceptance) = completion.acceptance
            {
                self.record_packet_send_failure(acceptance);
            }
            let _ = self.bearers.send_completed(completion);
        }
        while let Some(id) = self.completions.pop_ready() {
            progressed = true;
            #[cfg(feature = "tokio")]
            let capture_offset = self.packet_capture.as_ref().and_then(|capture| {
                self.bearers
                    .get_mut(id)?
                    .pending_packet_bytes()
                    .and_then(|bytes| capture.stage_egress(id, bytes))
            });
            let accepted = self
                .bearers
                .get_mut(id)
                .and_then(|bearer| bearer.retry_pending());
            #[cfg(feature = "tokio")]
            if let (Some(capture), Some(offset)) = (&self.packet_capture, capture_offset) {
                let submitted = self
                    .bearers
                    .get_mut(id)
                    .is_some_and(|bearer| !bearer.has_pending_submission());
                capture.finish_egress(offset, submitted);
            }
            if let Some(accepted) = accepted {
                let control_copy = self.take_pending_control_copy(accepted);
                self.record_packet_acceptance(accepted, self.clock_us);
                self.schedule_proactive_tail_copy(accepted);
                if let Some(candidate) = control_copy {
                    self.schedule_proactive_control_copy(candidate);
                }
            }
        }
        progressed
    }

    /// Whether queued ingress can be processed without generating output for
    /// a bearer that already has an unsubmitted packet retained.
    pub(crate) fn can_progress_ingress(&self) -> bool {
        self.bearers
            .iter()
            .filter(|bearer| bearer.state().enabled)
            .all(|bearer| bearer.can_submit())
    }

    /// Direct setup only needs its own response bearer. An unrelated
    /// unwritable interface must not prevent a fresh association from
    /// establishing. Relay/path setup retains the conservative ordering.
    pub(crate) fn direct_setup_can_progress(&self, meta: PacketMeta, bytes: &[u8]) -> bool {
        let output = match classify_server_packet(bytes) {
            Ok(ServerPacket::Initial(_)) => Some(meta.bearer),
            Ok(ServerPacket::BootstrapAck { .. }) => match self.router.target(bytes) {
                Ok(RouterTarget::Endpoint(id)) => self
                    .slot(*id)
                    .and_then(Self::slot_active_address)
                    .map(|(bearer, _)| bearer),
                _ => None,
            },
            _ => None,
        };
        output
            .and_then(|bearer| self.bearers.get(bearer))
            .is_some_and(|bearer| bearer.can_submit())
    }

    /// Established endpoint traffic can release memory while egress is busy.
    /// Setup, relay and path-control packets may require immediate output and
    /// must retain their existing admission ordering.
    pub(crate) fn ingress_can_defer_output(&self, bytes: &[u8]) -> bool {
        // Ordinary accepted sends awaiting completion retain their historical
        // scheduling. The deadlock escape is for an unaccepted WouldBlock
        // packet, whose retry may depend on draining inbound ACKs/leases.
        if !self
            .bearers
            .iter()
            .any(|bearer| bearer.has_pending_submission())
        {
            return false;
        }
        if !matches!(
            classify_server_packet(bytes),
            Ok(ServerPacket::Established { .. })
        ) {
            return false;
        }
        matches!(self.router.target(bytes), Ok(RouterTarget::Endpoint(id)) if self.slot(*id).is_some())
            && matches!(crate::decode_path_control_packet(bytes), Ok(None))
    }

    pub(crate) fn submit_egress(
        &mut self,
        bearer_id: BearerId,
        peer: PeerL2Address,
        packet: OwnedPacket<P::Buffer>,
    ) -> Result<(), QuicNodeEgressError> {
        self.submit_egress_tagged(bearer_id, peer, packet, None)
            .map(|_| ())
    }

    fn submit_egress_tagged(
        &mut self,
        bearer_id: BearerId,
        peer: PeerL2Address,
        packet: OwnedPacket<P::Buffer>,
        acceptance: Option<PacketAcceptance>,
    ) -> Result<bool, QuicNodeEgressError> {
        self.drain_bearer_events();
        let bearer = self
            .bearers
            .get_mut(bearer_id)
            .ok_or(QuicNodeEgressError::MissingBearer)?;
        // `submit_or_retain` has one slot for the exact lease returned by
        // WouldBlock. A second caller can race the owner-level readiness
        // check (for example, association control generated while delivering
        // an already accepted stream chunk). Surface pressure to QUIC instead
        // of panicking or replacing that first lease.
        if bearer.has_pending_submission() {
            return Err(QuicNodeEgressError::BearerBusy);
        }
        #[cfg(feature = "tokio")]
        let capture_offset = self
            .packet_capture
            .as_ref()
            .and_then(|capture| capture.stage_egress(bearer_id, packet.bytes()));
        let accepted = bearer.submit_or_retain(peer, packet, acceptance);
        #[cfg(feature = "tokio")]
        if let (Some(capture), Some(offset)) = (&self.packet_capture, capture_offset) {
            capture.finish_egress(offset, accepted);
        }
        Ok(accepted)
    }

    pub(crate) fn submit_node_packet(
        &mut self,
        packet: NodeEgress<P::Buffer>,
    ) -> Result<(), QuicNodeEgressError> {
        let clock_us = self.clock_us;
        let acceptance = self.packet_acceptance_for(packet.association, &packet.packet);
        let bearer_id = packet.bearer;
        let control_copy = acceptance.and_then(|acceptance| {
            self.control_duplication_candidate(acceptance, packet.packet.bytes())
        });
        let accepted = match self.submit_egress_tagged(
            packet.bearer,
            packet.peer_l2_address,
            packet.packet,
            acceptance,
        ) {
            Ok(accepted) => accepted,
            Err(error) => {
                if let Some(acceptance) = acceptance {
                    // The packet was dropped, not retained in the bearer's
                    // WouldBlock slot. Retire its prepared flight and make
                    // retained stream bytes eligible for repair; otherwise
                    // an unaccepted record waits forever for a nonexistent
                    // acceptance event and eventually fills the ledger.
                    self.record_packet_send_failure(acceptance);
                }
                return Err(error);
            }
        };
        if let Some(acceptance) = acceptance {
            if accepted {
                self.record_packet_acceptance(acceptance, clock_us);
                self.schedule_proactive_tail_copy(acceptance);
                if let Some(candidate) = control_copy {
                    self.schedule_proactive_control_copy(candidate);
                }
            } else {
                self.record_packet_blocked(acceptance);
                if let Some(candidate) = control_copy {
                    self.retain_pending_control_copy(bearer_id, candidate);
                }
            }
        }
        Ok(())
    }

    fn retain_pending_control_copy(
        &mut self,
        bearer: BearerId,
        candidate: ControlDuplicationCandidate,
    ) {
        let acceptance = candidate.acceptance;
        let slot = self
            .pending_control_copies
            .iter()
            .position(|pending| {
                pending.is_some_and(|copy| {
                    copy.candidate.acceptance.association == acceptance.association
                        && copy.candidate.acceptance.packet_number == acceptance.packet_number
                })
            })
            .or_else(|| self.pending_control_copies.iter().position(Option::is_none));
        if let Some(slot) = slot {
            self.pending_control_copies[slot] = Some(PendingControlCopy { bearer, candidate });
        }
    }

    fn take_pending_control_copy(
        &mut self,
        acceptance: PacketAcceptance,
    ) -> Option<ControlDuplicationCandidate> {
        let index = self.pending_control_copies.iter().position(|pending| {
            pending.is_some_and(|copy| {
                copy.candidate.acceptance.association == acceptance.association
                    && copy.candidate.acceptance.packet_number == acceptance.packet_number
            })
        })?;
        self.pending_control_copies[index]
            .take()
            .map(|copy| copy.candidate)
    }

    fn control_duplication_candidate(
        &self,
        acceptance: PacketAcceptance,
        bytes: &[u8],
    ) -> Option<ControlDuplicationCandidate> {
        let slot = self.slot(acceptance.association)?;
        let endpoint = match &slot.state {
            Association::Client(client) => client.connection().endpoint()?,
            Association::Server(server) => &server.mux.endpoint,
        };
        // No alternate path exists. Avoid a ledger scan and another decode
        // of every ACK/MAX_* packet merely to discard the candidate later.
        if endpoint.path_count() == 1 {
            return None;
        }
        if endpoint.is_proactive_duplicate(acceptance.packet_number) {
            return None;
        }
        let (header, mut offset) =
            crate::ShortHeader::decode_with_expected(bytes, endpoint.next_packet_number).ok()?;
        let source_path = (0..endpoint.path_count())
            .find(|&path_id| endpoint.peer_connection_id_on_path(path_id) == Some(header.dcid))?;
        let mut include_ack = false;
        let mut include_max_data = false;
        let mut stream_credit_count = 0;
        let mut include_max_streams_bidi = false;
        while offset < bytes.len() {
            let (frame, used) = crate::decode_frame(&bytes[offset..]).ok()?;
            if used == 0 {
                return None;
            }
            match frame {
                Frame::Ack { .. } | Frame::AckRanges { .. } => include_ack = true,
                Frame::MaxData(_) => include_max_data = true,
                Frame::MaxStreamData { .. } => stream_credit_count += 1,
                Frame::MaxStreamsBidi(_) => include_max_streams_bidi = true,
                Frame::Padding => {}
                _ => return None,
            }
            offset += used;
        }
        if !include_max_data && stream_credit_count == 0 && !include_max_streams_bidi {
            return None;
        }
        Some(ControlDuplicationCandidate {
            acceptance,
            source_path,
            include_ack,
            include_max_data,
            stream_credit_count,
            include_max_streams_bidi,
        })
    }

    fn packet_acceptance_for<B: AsRef<[u8]>>(
        &self,
        association: QuicAssociation,
        packet: &OwnedPacket<B>,
    ) -> Option<PacketAcceptance> {
        let expected = self.slot(association).and_then(|slot| match &slot.state {
            Association::Client(client) => client
                .connection()
                .endpoint()
                .map(|endpoint| endpoint.next_packet_number),
            Association::Server(server) => Some(server.mux.endpoint.next_packet_number),
        })?;
        let (header, _) =
            crate::ShortHeader::decode_with_expected(packet.bytes(), expected).ok()?;
        Some(PacketAcceptance {
            association,
            packet_number: header.packet_number,
        })
    }

    fn record_packet_acceptance(&mut self, acceptance: PacketAcceptance, now_us: u64) {
        let Some(slot) = self.slot_mut(acceptance.association) else {
            return;
        };
        let ack_eliciting = match &mut slot.state {
            Association::Client(client) => {
                if let Ok(endpoint) = client.connection_mut().endpoint_mut() {
                    let credit = endpoint.credit_packet_number == Some(acceptance.packet_number);
                    endpoint.packet_submission_accepted(acceptance.packet_number, now_us) || credit
                } else {
                    false
                }
            }
            Association::Server(server) => {
                let credit =
                    server.mux.endpoint.credit_packet_number == Some(acceptance.packet_number);
                server
                    .mux
                    .endpoint
                    .packet_submission_accepted(acceptance.packet_number, now_us)
                    || credit
            }
        };
        // Only the first accepted ack-eliciting send after peer activity
        // restarts idle. Retransmissions cannot keep a silent peer alive.
        if ack_eliciting && !slot.ack_eliciting_sent_since_receive {
            slot.last_activity_us = slot.last_activity_us.max(now_us);
            slot.ack_eliciting_sent_since_receive = true;
        }
    }

    fn schedule_proactive_tail_copy(&mut self, acceptance: PacketAcceptance) {
        let Some(slot) = self.slot(acceptance.association) else {
            return;
        };
        let endpoint = match &slot.state {
            Association::Client(client) => client.connection().endpoint(),
            Association::Server(server) => Some(&server.mux.endpoint),
        };
        let Some(endpoint) = endpoint else {
            return;
        };
        if endpoint.path_count() == 1 {
            return;
        }
        let Some(source_path) = endpoint.proactive_copy_source_path(acceptance.packet_number)
        else {
            return;
        };
        let mut candidates = [(u64::MAX, 0usize); crate::MAX_PATH_STATES];
        let mut count = 0;
        for path_id in 0..endpoint.path_count() {
            if path_id == source_path {
                continue;
            }
            let Some(path) = endpoint.path_state(path_id) else {
                continue;
            };
            if !path.is_usable_for_data() {
                continue;
            }
            let Some((bearer_id, _)) = path.active_address() else {
                continue;
            };
            if !self
                .bearers
                .get(bearer_id)
                .is_some_and(|bearer| bearer.can_submit())
            {
                continue;
            }
            let key = (path.measured_send_cost_us(), path_id);
            let mut insert = count;
            while insert > 0 && key < candidates[insert - 1] {
                candidates[insert] = candidates[insert - 1];
                insert -= 1;
            }
            candidates[insert] = key;
            count += 1;
        }
        for &(_, path_id) in candidates.iter().take(count) {
            let Ok(Some(packet)) = self.duplicate_stream_packet_on_path(
                acceptance.association,
                acceptance.packet_number,
                path_id,
            ) else {
                continue;
            };
            // The copy is ordinary QUIC egress: the bearer owns it only after
            // acceptance, and a zero-byte WouldBlock remains retained by the
            // registry for retry. It is deliberately not placed in a second
            // transport or bearer queue.
            let _ = self.submit_node_packet(packet);
            return;
        }
    }

    fn schedule_proactive_control_copy(&mut self, candidate: ControlDuplicationCandidate) {
        let Some(slot) = self.slot(candidate.acceptance.association) else {
            return;
        };
        let endpoint = match &slot.state {
            Association::Client(client) => client.connection().endpoint(),
            Association::Server(server) => Some(&server.mux.endpoint),
        };
        let Some(endpoint) = endpoint else {
            return;
        };
        let mut candidates = [(u64::MAX, 0usize); crate::MAX_PATH_STATES];
        let mut count = 0;
        for path_id in 0..endpoint.path_count() {
            if path_id == candidate.source_path {
                continue;
            }
            let Some(path) = endpoint.path_state(path_id) else {
                continue;
            };
            if !path.is_usable_for_data() {
                continue;
            }
            let Some((bearer_id, _)) = path.active_address() else {
                continue;
            };
            if !self
                .bearers
                .get(bearer_id)
                .is_some_and(|bearer| bearer.can_submit())
            {
                continue;
            }
            let key = (path.measured_send_cost_us(), path_id);
            let mut insert = count;
            while insert > 0 && key < candidates[insert - 1] {
                candidates[insert] = candidates[insert - 1];
                insert -= 1;
            }
            candidates[insert] = key;
            count += 1;
        }
        for &(_, path_id) in candidates.iter().take(count) {
            let Ok(Some(packet)) = self.prepare_duplicate_credit_control(candidate, path_id) else {
                continue;
            };
            let _ = self.submit_node_packet(packet);
            return;
        }
    }

    fn record_packet_blocked(&mut self, acceptance: PacketAcceptance) {
        let Some(slot) = self.slot_mut(acceptance.association) else {
            return;
        };
        match &mut slot.state {
            Association::Client(client) => {
                if let Ok(endpoint) = client.connection_mut().endpoint_mut() {
                    endpoint.packet_submission_blocked(acceptance.packet_number);
                }
            }
            Association::Server(server) => {
                server
                    .mux
                    .endpoint
                    .packet_submission_blocked(acceptance.packet_number);
            }
        }
    }

    fn record_packet_send_failure(&mut self, acceptance: PacketAcceptance) {
        let Some(slot) = self.slot_mut(acceptance.association) else {
            return;
        };
        match &mut slot.state {
            Association::Client(client) => {
                if let Ok(endpoint) = client.connection_mut().endpoint_mut() {
                    endpoint.packet_submission_failed(acceptance.packet_number);
                }
            }
            Association::Server(server) => {
                server
                    .mux
                    .endpoint
                    .packet_submission_failed(acceptance.packet_number);
            }
        }
    }

    pub(crate) fn submit_unassociated_packet(
        &mut self,
        packet: NodePacket<P::Buffer>,
    ) -> Result<(), QuicNodeEgressError> {
        self.submit_egress(packet.bearer, packet.peer_l2_address, packet.packet)
    }

    pub(crate) fn submit_pending_control(
        &mut self,
        association: QuicAssociation,
    ) -> Result<(), QuicNodeEgressError> {
        // `poll_association_control` consumes pending ACK/flow-control state
        // while building a packet. Do not build one while any registered
        // bearer still owns a WouldBlock lease: a later submit would violate
        // the one-retained-packet-per-bearer contract.
        if !self.can_progress_ingress() {
            return Err(QuicNodeEgressError::BearerBusy);
        }
        if let Some(packet) = self.poll_association_control(association)? {
            self.submit_node_packet(packet)?;
        }
        Ok(())
    }

    /// Submit association control output or retain its association for a later
    /// readiness/completion event.
    ///
    /// Deferral belongs to the node state machine rather than to a runtime:
    /// Tokio and an RTOS task must preserve the same ACK and flow-control
    /// progress when the packet pool or selected bearer is temporarily busy.
    pub(crate) fn submit_or_defer_control(
        &mut self,
        association: QuicAssociation,
    ) -> Result<(), QuicNodeEgressError> {
        match self.submit_pending_control(association) {
            Ok(()) => Ok(()),
            Err(error) if error.is_retryable() => self.defer_control(association),
            Err(error) => Err(error),
        }
    }

    /// Give a ready application writer the remainder of this owner turn to
    /// piggyback ACK/credit output. The next progress turn flushes anything
    /// still due; transport deadlines remain armed even without new ingress.
    pub(crate) fn defer_control(
        &mut self,
        association: QuicAssociation,
    ) -> Result<(), QuicNodeEgressError> {
        if !self.association_control_due(association)? {
            return Ok(());
        }
        if !self.pending_controls.contains(&association) {
            if self.pending_controls.len() >= self.node_limits.max_associations
                || self.pending_controls.try_reserve(1).is_err()
            {
                return Err(QuicNodeEgressError::StreamEventsFull);
            }
            self.pending_controls.push_back(association);
        }
        Ok(())
    }

    fn association_control_due(
        &self,
        association: QuicAssociation,
    ) -> Result<bool, QuicNodeEgressError> {
        let slot = self
            .slot(association)
            .ok_or(QuicNodeError::MissingAssociation)?;
        let endpoint = match &slot.state {
            Association::Client(client) => client.connection().endpoint(),
            Association::Server(server) => Some(&server.mux.endpoint),
        };
        Ok(endpoint.is_some_and(|endpoint| {
            endpoint.pending_control_path().is_some()
                || endpoint.pending_path_status(self.clock_us()).is_some()
        }))
    }

    /// Retry at most one deferred association control packet.
    ///
    /// Processing one item keeps scheduling in the platform adapter: it may
    /// call this after a bearer readiness or packet-completion event without
    /// constructing a polling loop inside the protocol state machine.
    pub(crate) fn retry_one_pending_control(&mut self) -> Result<bool, QuicNodeEgressError> {
        while let Some(association) = self.pending_controls.pop_front() {
            // Application output may already have piggybacked this intent.
            // Retire such entries without borrowing a pool packet or
            // reporting another owner turn of fictitious transmit progress.
            if !self.association_control_due(association)? {
                continue;
            }
            return match self.submit_pending_control(association) {
                Ok(()) => Ok(true),
                Err(error) if error.is_retryable() => {
                    self.pending_controls.push_front(association);
                    Ok(false)
                }
                Err(error) => Err(error),
            };
        }
        Ok(false)
    }
}

enum Association<Client, Server> {
    Client(Box<Client>),
    Server(Box<Server>),
}

struct AssociationSlot<Client, Server> {
    generation: u64,
    receive_cid: ConnectionId,
    /// The peer endpoint's base receive CID, retained when path zero is
    /// routed through relay aliases.
    peer_join_cid: Option<ConnectionId>,
    relayed_join_requests: [Option<Vec<u8>>; crate::MAX_PATH_STATES],
    relayed_join_attempts: [u8; crate::MAX_PATH_STATES],
    relayed_join_retry_at_us: [Option<u64>; crate::MAX_PATH_STATES],
    relayed_join_deadline_us: [Option<u64>; crate::MAX_PATH_STATES],
    receive_cids: [Option<ConnectionId>; crate::MAX_PATH_STATES],
    next_circuit_sequence: [u64; 2],
    highest_remote_circuit_sequence: [u64; 2],
    next_transaction_id: u64,
    next_circuit_id: u64,
    state: Association<Client, Server>,
    /// Bootstrap route used before a client has established its endpoint
    /// PathState. Once the peer OPEN_ACK creates that state, addresses live on
    /// the path itself.
    bootstrap_address: Option<(BearerId, PeerL2Address)>,
    bootstrap: Option<ClientBootstrap>,
    close_code: Option<u64>,
    last_activity_us: u64,
    ack_eliciting_sent_since_receive: bool,
    client_delivery: crate::callback::CallbackStreams<Arc<Vec<u8>>>,
    limits: AssociationLimits,
}

#[derive(Clone)]
struct ClientBootstrap {
    next_attempt: u32,
    last_attempt_at: u64,
    setup_transaction_id: Option<u64>,
    setup_relay_count: Option<u8>,
    setup_request: Option<Vec<u8>>,
}

const CLIENT_BOOTSTRAP_ATTEMPTS: u32 = 4;
const DEFAULT_PATH_PROBE_INTERVAL_US: u64 = 5_000_000;

struct OrderedNodeSink<'a, F> {
    association: QuicAssociation,
    handler: &'a mut F,
    consumed: usize,
}

impl<F> crate::callback::CopyingStreamEvents for OrderedNodeSink<'_, F>
where
    F: FnMut(ApplicationStreamSource, u64, u64, bool, &[u8]) -> Result<usize, crate::Error>,
{
    type Error = crate::Error;

    fn stream_chunk(
        &mut self,
        stream: u64,
        offset: u64,
        end: bool,
        bytes: &[u8],
    ) -> Result<usize, Self::Error> {
        let consumed = (self.handler)(
            ApplicationStreamSource::Association(self.association),
            stream,
            offset,
            end,
            bytes,
        )?;
        if consumed > bytes.len() {
            return Err(crate::Error::Invalid);
        }
        self.consumed = self.consumed.saturating_add(consumed);
        Ok(consumed)
    }
}

/// All QUIC association and DCID-routing state for one node.
///
/// Client and server association implementations are private behind
/// generation-checked [`QuicAssociation`] handles; callers configure storage
/// capacities but never construct protocol connection state. The DCID router
/// stores only those handles. Forwarding rules share the same
/// receive-CID namespace as locally terminated associations. All state changes
/// happen in the caller's current event context; this type owns no worker or
/// scheduling loop.
pub struct QuicNode<
    P: PacketPool + 'static,
    const PACKET: usize = { crate::DEFAULT_MAX_PACKET_SIZE },
> {
    pub(crate) pool: &'static P,
    // The normal one-association case stays inline. A second association
    // spills this collection to the heap instead of reserving every complete
    // connection state at node construction.
    associations: SmallVec<
        [Option<AssociationSlot<ClientAssociation<PACKET>, ServerStreamConnection<PACKET>>>; 1],
    >,
    generations: Vec<u64>,
    next_local_cid: u64,
    next_setup_transaction_id: u64,
    clock_us: u64,
    idle_timeout_us: u64,
    router: PacketRouter<QuicAssociation, ForwardNextHop>,
    pub(crate) bearers: BearerRegistry<P::Buffer, 8>,
    pub(crate) completions: Arc<CompletionQueue<P::Buffer>>,
    #[cfg(feature = "tokio")]
    pub(crate) ingress_sender: crate::bearer::tokio::PacketSender<P::Buffer>,
    #[cfg(feature = "tokio")]
    pub(crate) ingress: crate::bearer::tokio::PacketReceiver<P::Buffer>,
    #[cfg(feature = "tokio")]
    pub(crate) stream_chunks: std::collections::VecDeque<QueuedStreamChunk>,
    #[cfg(feature = "tokio")]
    pub(crate) stream_chunk_limit: usize,
    /// Streams whose delivery stopped at the per-stream queue limit. Their
    /// bytes stay retained by QUIC-lite without receive credit until
    /// `resume_deferred_streams` can queue them.
    #[cfg(feature = "tokio")]
    pub(crate) deferred_streams: Vec<(QuicAssociation, u64)>,
    #[cfg(feature = "tokio")]
    pub(crate) packet_capture: Option<crate::tokio::PacketCapture>,
    pending_controls: VecDeque<QuicAssociation>,
    pending_control_copies: [Option<PendingControlCopy>; 8],
    association_events: VecDeque<AssociationEvent>,
    dropped_association_events: u64,
    node_limits: NodeLimits,
    default_association_limits: AssociationLimits,
    datagram_handlers: Vec<(QuicAssociation, datagram::DatagramHandler<P::Buffer>)>,
    local_vip: Option<u64>,
    path_open_route: Option<(u8, [u8; 16], usize, CircuitNextHop)>,
    path_open_resolver:
        Option<Arc<dyn Fn(u8, &[u8]) -> Option<CircuitNextHop> + Send + Sync + 'static>>,
    vip_path_open_resolver:
        Option<Arc<dyn Fn(u8, &[u8], u64) -> Option<CircuitNextHop> + Send + Sync + 'static>>,
}

impl<P: PacketPool, const PACKET: usize> QuicNode<P, PACKET> {
    fn slot_path_count(
        slot: &AssociationSlot<ClientAssociation<PACKET>, ServerStreamConnection<PACKET>>,
    ) -> usize {
        match &slot.state {
            Association::Client(client) => client
                .connection()
                .endpoint()
                .map_or(0, |endpoint| endpoint.path_count()),
            Association::Server(server) => server.mux.endpoint.path_count(),
        }
    }

    fn slot_path_state(
        slot: &AssociationSlot<ClientAssociation<PACKET>, ServerStreamConnection<PACKET>>,
        path_id: usize,
    ) -> Option<&crate::PathState> {
        match &slot.state {
            Association::Client(client) => client
                .connection()
                .endpoint()
                .and_then(|endpoint| endpoint.path_state(path_id)),
            Association::Server(server) => server.path_state_at(path_id),
        }
    }

    fn slot_path_state_mut(
        slot: &mut AssociationSlot<ClientAssociation<PACKET>, ServerStreamConnection<PACKET>>,
        path_id: usize,
    ) -> Option<&mut crate::PathState> {
        match &mut slot.state {
            Association::Client(client) => client
                .connection_mut()
                .endpoint_mut()
                .ok()
                .and_then(|endpoint| endpoint.path_state_mut(path_id)),
            Association::Server(server) => server.path_state_at_mut(path_id),
        }
    }

    fn remove_slot_path_state(
        slot: &mut AssociationSlot<ClientAssociation<PACKET>, ServerStreamConnection<PACKET>>,
        path_id: usize,
    ) -> Result<(), Error> {
        match &mut slot.state {
            Association::Client(client) => client
                .connection_mut()
                .endpoint_mut()?
                .remove_path_state(path_id)?,
            Association::Server(server) => server.mux.endpoint.remove_path_state(path_id)?,
        }
        for index in path_id..crate::MAX_PATH_STATES - 1 {
            slot.receive_cids[index] = slot.receive_cids[index + 1];
            slot.relayed_join_requests[index] = slot.relayed_join_requests[index + 1].take();
            slot.relayed_join_attempts[index] = slot.relayed_join_attempts[index + 1];
            slot.relayed_join_retry_at_us[index] = slot.relayed_join_retry_at_us[index + 1];
            slot.relayed_join_deadline_us[index] = slot.relayed_join_deadline_us[index + 1];
        }
        let last = crate::MAX_PATH_STATES - 1;
        slot.receive_cids[last] = None;
        slot.relayed_join_requests[last] = None;
        slot.relayed_join_attempts[last] = 0;
        slot.relayed_join_retry_at_us[last] = None;
        slot.relayed_join_deadline_us[last] = None;
        Ok(())
    }

    fn slot_active_address(
        slot: &AssociationSlot<ClientAssociation<PACKET>, ServerStreamConnection<PACKET>>,
    ) -> Option<(BearerId, PeerL2Address)> {
        Self::slot_path_state(slot, 0)
            .and_then(crate::PathState::active_address)
            .or(slot.bootstrap_address)
    }

    fn remember_slot_address(
        slot: &mut AssociationSlot<ClientAssociation<PACKET>, ServerStreamConnection<PACKET>>,
        address: (BearerId, PeerL2Address),
    ) {
        if let Some(path_id) = (0..crate::MAX_PATH_STATES).find(|path_id| {
            Self::slot_path_state(slot, *path_id)
                .is_some_and(|path| path.known_addresses().contains(&address))
        }) {
            let path = Self::slot_path_state_mut(slot, path_id).unwrap();
            path.remember_address(address);
            slot.bootstrap_address = None;
        } else if slot.bootstrap_address.is_none()
            && Self::slot_path_state(slot, 0)
                .and_then(crate::PathState::active_address)
                .is_none()
        {
            slot.bootstrap_address = Some(address);
        }
    }

    fn slot_path_id_for_cid(
        slot: &AssociationSlot<ClientAssociation<PACKET>, ServerStreamConnection<PACKET>>,
        cid: ConnectionId,
    ) -> Option<usize> {
        slot.receive_cids
            .iter()
            .position(|candidate| *candidate == Some(cid))
    }

    /// Create a node with the packet pool it owns for all ingress and egress.
    ///
    /// The pool is deliberately selected here rather than by individual
    /// bearers or stream operations. Its leases and current use are therefore
    /// visible to the node's memory and receive-window policy.
    pub fn new(pool: &'static P) -> Self {
        Self::new_with_router(pool, PacketRouter::new())
    }

    /// Create a node that issues and recognizes stateless resets using the
    /// supplied opt-in reset key.
    #[cfg(feature = "stateless-reset")]
    pub fn new_with_stateless_reset(reset_key: StatelessResetKey, pool: &'static P) -> Self {
        Self::new_with_router(pool, PacketRouter::new_with_stateless_reset(reset_key))
    }

    fn new_with_router(
        pool: &'static P,
        mut router: PacketRouter<QuicAssociation, ForwardNextHop>,
    ) -> Self {
        let node_limits = NodeLimits::host();
        let association_limits = AssociationLimits::host();
        let mut associations = SmallVec::new();
        if node_limits.max_associations != 0 {
            associations.push(None);
        }
        #[cfg(feature = "tokio")]
        let (ingress_sender, ingress) = crate::bearer::tokio::channel(pool.capacity().max(1));
        Self {
            pool,
            associations,
            generations: if node_limits.max_associations == 0 {
                Vec::new()
            } else {
                vec![0]
            },
            next_local_cid: {
                #[cfg(feature = "tokio")]
                {
                    crate::tokio::initial_local_cid_seed()
                }
                #[cfg(not(feature = "tokio"))]
                {
                    1
                }
            },
            next_setup_transaction_id: 1,
            clock_us: 0,
            idle_timeout_us: DEFAULT_IDLE_TIMEOUT_US,
            router: {
                router.set_max_entries(node_limits.max_routes);
                router
            },
            bearers: BearerRegistry::new(),
            completions: Arc::new(CompletionQueue::new(pool.capacity().max(1))),
            #[cfg(feature = "tokio")]
            ingress_sender,
            #[cfg(feature = "tokio")]
            ingress,
            #[cfg(feature = "tokio")]
            stream_chunks: std::collections::VecDeque::new(),
            #[cfg(feature = "tokio")]
            stream_chunk_limit: association_limits.max_queued_chunks_per_stream,
            #[cfg(feature = "tokio")]
            deferred_streams: Vec::new(),
            #[cfg(feature = "tokio")]
            packet_capture: crate::tokio::PacketCapture::from_env(),
            pending_controls: VecDeque::new(),
            pending_control_copies: [None; 8],
            association_events: VecDeque::new(),
            dropped_association_events: 0,
            node_limits,
            default_association_limits: association_limits,
            datagram_handlers: Vec::new(),
            local_vip: None,
            path_open_route: None,
            path_open_resolver: None,
            vip_path_open_resolver: None,
        }
    }

    /// Initialize a no-std node directly in its final storage.
    ///
    /// Embedded runtimes use this when complete node state is intentionally
    /// larger than an RTOS packet task's stack. The caller
    /// supplies uninitialized heap or static storage; every field is written
    /// before the returned reference becomes observable.
    pub(crate) unsafe fn new_in_place<'a>(
        storage: &'a mut core::mem::MaybeUninit<Self>,
        pool: &'static P,
    ) -> &'a mut Self {
        // SAFETY: forwarded unchanged to the initialization routine.
        unsafe { Self::new_in_place_with_router(storage, PacketRouter::new(), pool) }
    }

    /// Initialize a node in final storage with stateless-reset support.
    #[cfg(feature = "stateless-reset")]
    pub(crate) unsafe fn new_in_place_with_stateless_reset<'a>(
        storage: &'a mut core::mem::MaybeUninit<Self>,
        reset_key: StatelessResetKey,
        pool: &'static P,
    ) -> &'a mut Self {
        // SAFETY: forwarded unchanged to the initialization routine.
        unsafe {
            Self::new_in_place_with_router(
                storage,
                PacketRouter::new_with_stateless_reset(reset_key),
                pool,
            )
        }
    }

    unsafe fn new_in_place_with_router<'a>(
        storage: &'a mut core::mem::MaybeUninit<Self>,
        mut router: PacketRouter<QuicAssociation, ForwardNextHop>,
        pool: &'static P,
    ) -> &'a mut Self {
        let node_limits = NodeLimits::host();
        let association_limits = AssociationLimits::host();
        // SAFETY: `storage` is one aligned, uninitialized `Self`. Every field
        // is written exactly once before the initialized reference escapes.
        unsafe {
            let node = storage.as_mut_ptr();
            core::ptr::addr_of_mut!((*node).pool).write(pool);
            let associations = core::ptr::addr_of_mut!((*node).associations);
            associations.write(SmallVec::new());
            if node_limits.max_associations != 0 {
                (*associations).push(None);
            }
            core::ptr::addr_of_mut!((*node).generations).write(
                if node_limits.max_associations == 0 {
                    Vec::new()
                } else {
                    vec![0]
                },
            );
            #[cfg(feature = "tokio")]
            let first_local_cid = crate::tokio::initial_local_cid_seed();
            #[cfg(not(feature = "tokio"))]
            let first_local_cid = 1;
            core::ptr::addr_of_mut!((*node).next_local_cid).write(first_local_cid);
            core::ptr::addr_of_mut!((*node).next_setup_transaction_id).write(1);
            core::ptr::addr_of_mut!((*node).clock_us).write(0);
            core::ptr::addr_of_mut!((*node).idle_timeout_us).write(DEFAULT_IDLE_TIMEOUT_US);
            router.set_max_entries(node_limits.max_routes);
            core::ptr::addr_of_mut!((*node).router).write(router);
            core::ptr::addr_of_mut!((*node).bearers).write(BearerRegistry::new());
            core::ptr::addr_of_mut!((*node).completions)
                .write(Arc::new(CompletionQueue::new(pool.capacity().max(1))));
            #[cfg(feature = "tokio")]
            {
                let (ingress_sender, ingress) =
                    crate::bearer::tokio::channel(pool.capacity().max(1));
                core::ptr::addr_of_mut!((*node).ingress_sender).write(ingress_sender);
                core::ptr::addr_of_mut!((*node).ingress).write(ingress);
                core::ptr::addr_of_mut!((*node).stream_chunks)
                    .write(std::collections::VecDeque::new());
                core::ptr::addr_of_mut!((*node).stream_chunk_limit)
                    .write(association_limits.max_queued_chunks_per_stream);
                core::ptr::addr_of_mut!((*node).deferred_streams).write(Vec::new());
                core::ptr::addr_of_mut!((*node).packet_capture)
                    .write(crate::tokio::PacketCapture::from_env());
            }
            core::ptr::addr_of_mut!((*node).pending_controls).write(VecDeque::new());
            core::ptr::addr_of_mut!((*node).pending_control_copies).write([None; 8]);
            core::ptr::addr_of_mut!((*node).association_events).write(VecDeque::new());
            core::ptr::addr_of_mut!((*node).dropped_association_events).write(0);
            core::ptr::addr_of_mut!((*node).node_limits).write(node_limits);
            core::ptr::addr_of_mut!((*node).default_association_limits).write(association_limits);
            core::ptr::addr_of_mut!((*node).datagram_handlers).write(Vec::new());
            core::ptr::addr_of_mut!((*node).local_vip).write(None);
            core::ptr::addr_of_mut!((*node).path_open_route).write(None);
            core::ptr::addr_of_mut!((*node).path_open_resolver).write(None);
            core::ptr::addr_of_mut!((*node).vip_path_open_resolver).write(None);
            storage.assume_init_mut()
        }
    }

    /// Borrow one packet writer from this node's packet pool.
    ///
    /// Bearer receive code uses this before reading a packet. `None` means the
    /// packet must be dropped; the bearer must not allocate fallback storage or
    /// wait for a slot. The committed [`OwnedPacket`] remains owned by this
    /// pool as it moves through ingress, forwarding, egress, and completion.
    pub(crate) fn acquire_packet_writer(&self, headroom: usize) -> Option<P::Writer> {
        self.pool.acquire_writer(headroom, 0)
    }

    /// Install one exact opaque relay destination without a closure/vtable.
    /// Useful for flash-resident modules which cannot relocate static vtables.
    /// Replaces the previous exact route; dynamic resolver remains the fallback.
    pub fn set_path_open_route(&mut self,kind:u8,address:&[u8],next_hop:CircuitNextHop)->Result<(),Error> {
        if kind==0 || address.is_empty() || address.len()>16 {return Err(Error::Invalid);}
        let mut key=[0;16];key[..address.len()].copy_from_slice(address);
        self.path_open_route=Some((kind,key,address.len(),next_hop));Ok(())
    }

    /// Configure local bearer/address resolution for layered PATH_OPEN hops.
    /// The address bytes remain opaque to QUIC-lite; this callback maps the
    /// requested egress namespace and address to a registered local bearer.
    pub fn set_path_open_resolver(
        &mut self,
        resolver: impl Fn(u8, &[u8]) -> Option<CircuitNextHop> + Send + Sync + 'static,
    ) {
        self.path_open_resolver = Some(Arc::new(resolver));
    }

    /// Configure gateway resolution for VIP-routed PATH_OPEN requests.
    ///
    /// The VIP is an untrusted destination hint. The callback applies local
    /// gateway policy and returns a registered bearer/peer for the chosen
    /// next hop.
    pub fn set_vip_path_open_resolver(
        &mut self,
        resolver: impl Fn(u8, &[u8], u64) -> Option<CircuitNextHop> + Send + Sync + 'static,
    ) {
        self.vip_path_open_resolver = Some(Arc::new(resolver));
    }

    /// Set this node's local VIP so telescoping setup can distinguish its
    /// destination from a relay that must resolve and forward the request.
    pub fn set_local_vip(&mut self, vip: u64) -> Result<(), QuicNodeError> {
        if vip == 0 {
            return Err(QuicNodeError::InvalidLimits);
        }
        self.local_vip = Some(vip);
        Ok(())
    }

    fn build_setup_rejection(
        pool: &'static P,
        previous_hop: ForwardNextHop,
        transaction_id: u64,
        circuit: crate::relay::SetupCircuitKey,
        code: u64,
    ) -> Result<NodePacket<P::Buffer>, QuicNodeEgressError> {
        let packet = Self::build_packet(pool, |output| {
            SetupReply {
                transaction_id,
                circuit,
                result: SetupResult::Rejected { code },
                bootstrap_ack: None,
                relay_cids: crate::relay::SetupRelayCids::empty(),
            }
            .encode_packet(output)
        })?;
        Ok(NodePacket {
            bearer: previous_hop.bearer,
            peer_l2_address: previous_hop.peer_l2_address,
            packet,
        })
    }

    /// Replace node-wide runtime admission limits. Lower values do not evict
    /// active associations or routes; they only stop later admission until
    /// usage falls below the new ceiling.
    pub fn set_limits(&mut self, limits: NodeLimits) -> Result<(), QuicNodeError> {
        if limits.max_associations == 0
            || limits.max_associations > u32::MAX as usize
            || limits.max_routes == 0
            || limits.relay_control_packet_reserve > self.pool.capacity()
        {
            return Err(QuicNodeError::InvalidLimits);
        }
        self.router.set_max_entries(limits.max_routes);
        self.node_limits = limits;
        Ok(())
    }

    /// Return the current node-wide runtime limits.
    pub const fn limits(&self) -> NodeLimits {
        self.node_limits
    }

    /// Select defaults for associations admitted after this call.
    pub fn set_default_association_limits(
        &mut self,
        limits: AssociationLimits,
    ) -> Result<(), QuicNodeError> {
        if limits.history_packets == 0
            || limits.transmission_records == 0
            || limits.max_pending_streams == 0
            || limits.max_queued_chunks_per_stream == 0
            || limits.max_buffered_stream_bytes == 0
            || limits.duplication_budget_bytes == 0
            || limits.path_probe_interval_us == 0
            || !limits.path_estimator.is_valid()
            || !limits.pacing.is_valid()
            || limits.connection.max_data == 0
            || limits.connection.max_stream_data == 0
        {
            return Err(QuicNodeError::InvalidLimits);
        }
        self.default_association_limits = limits;
        #[cfg(feature = "tokio")]
        {
            self.stream_chunk_limit = limits.max_queued_chunks_per_stream;
        }
        Ok(())
    }

    /// Return defaults used for associations admitted after the latest update.
    pub const fn default_association_limits(&self) -> AssociationLimits {
        self.default_association_limits
    }

    /// Change one live association's growth policy. Already advertised peer
    /// credit and retained retransmissions are preserved; lower values take
    /// effect as current commitments drain.
    pub fn set_association_limits(
        &mut self,
        association: QuicAssociation,
        limits: AssociationLimits,
    ) -> Result<(), QuicNodeEgressError> {
        if limits.history_packets == 0
            || limits.transmission_records == 0
            || limits.max_pending_streams == 0
            || limits.max_queued_chunks_per_stream == 0
            || limits.max_buffered_stream_bytes == 0
            || limits.duplication_budget_bytes == 0
            || limits.path_probe_interval_us == 0
            || !limits.path_estimator.is_valid()
            || !limits.pacing.is_valid()
            || limits.connection.max_data == 0
            || limits.connection.max_stream_data == 0
        {
            return Err(QuicNodeEgressError::Transport(Error::Invalid));
        }
        let slot = self
            .slot_mut(association)
            .ok_or(QuicNodeEgressError::Association(
                QuicNodeError::MissingAssociation,
            ))?;
        match &mut slot.state {
            Association::Client(client) => client
                .set_runtime_limits(limits)
                .map_err(QuicNodeEgressError::Transport)?,
            Association::Server(server) => server
                .set_runtime_limits(limits)
                .map_err(QuicNodeEgressError::Transport)?,
        }
        slot.client_delivery
            .set_limits(limits.max_pending_streams, limits.max_buffered_stream_bytes);
        slot.limits = limits;
        Ok(())
    }

    /// Return the live growth policy for one association.
    pub fn association_limits(&self, association: QuicAssociation) -> Option<AssociationLimits> {
        Some(self.slot(association)?.limits)
    }

    /// Return read-only transport counters and send state for one live association.
    ///
    /// ACK and packet counters are transport evidence only; they do not imply
    /// that the peer application consumed or committed stream data.
    pub fn association_telemetry(
        &self,
        association: QuicAssociation,
    ) -> Option<crate::AssociationTelemetry> {
        let slot = self.slot(association)?;
        match &slot.state {
            Association::Client(client) => client
                .connection()
                .endpoint()
                .map(crate::EndpointState::telemetry),
            Association::Server(server) => Some(server.mux.endpoint.telemetry()),
        }
    }

    /// One row per live association, with its first path's bearer and peer.
    pub fn association_rows(&self) -> Vec<AssociationRow> {
        self.associations
            .iter()
            .enumerate()
            .filter_map(|(index, slot)| {
                let slot = slot.as_ref()?;
                let telemetry = match &slot.state {
                    Association::Client(client) => client
                        .connection()
                        .endpoint()
                        .map(crate::EndpointState::telemetry),
                    Association::Server(server) => Some(server.mux.endpoint.telemetry()),
                }?;
                let hop = Self::slot_path_state(slot, 0)
                    .and_then(|path| path.active_address())
                    .or(slot.bootstrap_address);
                Some(AssociationRow {
                    id: index as u64,
                    bearer: hop.map(|(bearer, _)| bearer),
                    peer: hop.map(|(_, peer)| peer),
                    telemetry,
                })
            })
            .collect()
    }

    /// The name of the bearer an association's first path runs over (`uart0`, `udp6`, ...),
    /// when it is known. A handler uses it as provenance: it is the node's own fact about
    /// where the request arrived, not anything the request says about itself.
    pub fn association_bearer_name(&self, id: QuicAssociation) -> Option<crate::BearerName> {
        let slot = self.slot(id)?;
        let (bearer, _) = Self::slot_path_state(slot, 0)
            .and_then(|path| path.active_address())
            .or(slot.bootstrap_address)?;
        self.bearer_rows()
            .into_iter()
            .find(|row| row.id == bearer)
            .map(|row| row.name)
    }

    /// One row per registered bearer.
    pub fn bearer_rows(&self) -> Vec<BearerRow> {
        self.bearers
            .iter()
            .map(|bearer| {
                let (state, stats) = (bearer.state(), bearer.stats());
                BearerRow {
                    id: bearer.id(),
                    name: bearer.info().name,
                    enabled: state.enabled,
                    in_flight_packets: state.in_flight_packets as u64,
                    received_packets: stats.received_packets,
                    ingress_drops: stats.ingress_drops,
                    submitted_packets: stats.submitted_packets,
                    completed_packets: stats.completed_packets,
                    send_would_block: stats.send_would_block,
                    send_failures: stats.send_failures,
                }
            })
            .collect()
    }

    /// Aggregate QUIC counters over associations currently live on this node.
    pub fn telemetry(&self) -> crate::NodeTelemetry {
        let mut result = crate::NodeTelemetry::default();
        for slot in self.associations.iter().filter_map(Option::as_ref) {
            let endpoint = match &slot.state {
                Association::Client(client) => client.connection().endpoint(),
                Association::Server(server) => Some(&server.mux.endpoint),
            };
            let Some(endpoint) = endpoint else { continue };
            let stats = endpoint.stats();
            result.live_associations = result.live_associations.saturating_add(1);
            result.received_packets = result
                .received_packets
                .saturating_add(stats.received_packets);
            result.sent_packets = result.sent_packets.saturating_add(stats.sent_packets);
            result.received_stream_packets = result
                .received_stream_packets
                .saturating_add(stats.stream_packets);
            result.received_control_packets = result
                .received_control_packets
                .saturating_add(stats.control_packets);
            result.sent_stream_packets = result
                .sent_stream_packets
                .saturating_add(stats.sent_stream_packets);
            result.sent_control_packets = result
                .sent_control_packets
                .saturating_add(stats.sent_control_packets);
            result.duplicate_packets = result
                .duplicate_packets
                .saturating_add(stats.duplicate_packets);
            result.out_of_order_packets = result
                .out_of_order_packets
                .saturating_add(stats.out_of_order_packets);
            result.inferred_missing_packets = result
                .inferred_missing_packets
                .saturating_add(stats.inferred_missing_packets);
            result.retransmitted_packets = result
                .retransmitted_packets
                .saturating_add(stats.retransmitted_packets);
            result.loss_events = result.loss_events.saturating_add(stats.loss_events);
            result.submission_failures = result
                .submission_failures
                .saturating_add(stats.submission_failures);
        }
        result
    }

    #[cfg(feature = "tokio")]
    pub(crate) fn association_chunk_limits(&self) -> Vec<(QuicAssociation, usize)> {
        self.associations
            .iter()
            .enumerate()
            .filter_map(|(slot, entry)| {
                let entry = entry.as_ref()?;
                Some((
                    QuicAssociation {
                        slot: slot as u32,
                        generation: entry.generation,
                    },
                    entry.limits.max_queued_chunks_per_stream,
                ))
            })
            .collect()
    }

    /// Current active packet slots managed by this node.
    pub fn packet_capacity(&self) -> usize {
        self.pool.capacity()
    }

    /// Packet slots currently available to ingress and egress.
    pub fn available_packets(&self) -> usize {
        self.pool.available()
    }

    pub(crate) fn advance_clock(&mut self, now_us: u64) {
        self.clock_us = self.clock_us.max(now_us);
        let now_us = self.clock_us;
        for slot in self.associations.iter_mut().flatten() {
            match &mut slot.state {
                Association::Client(client) => {
                    if let Ok(endpoint) = client.connection_mut().endpoint_mut() {
                        endpoint.set_time(now_us);
                    }
                }
                Association::Server(server) => server.mux.endpoint.set_time(now_us),
            }
        }
    }

    pub(crate) const fn clock_us(&self) -> u64 {
        self.clock_us
    }

    pub(crate) fn add_client(
        &mut self,
        receive_cid: ConnectionId,
        association: Box<ClientAssociation<PACKET>>,
    ) -> Result<QuicAssociation, QuicNodeError> {
        self.insert(receive_cid, Association::Client(association))
    }

    pub(crate) fn add_server(
        &mut self,
        receive_cid: ConnectionId,
        association: Box<ServerStreamConnection<PACKET>>,
    ) -> Result<QuicAssociation, QuicNodeError> {
        self.insert(receive_cid, Association::Server(association))
    }

    /// Begin a directly reachable circuit join on a new bearer/address pair.
    /// The local receive CID is installed before the join packet is returned,
    /// so the peer's reply can be routed while the circuit is still opening.
    pub(crate) fn open_direct_path(
        &mut self,
        association: QuicAssociation,
        address: (BearerId, PeerL2Address),
    ) -> Result<(crate::CircuitKey, NodeEgress<P::Buffer>), QuicNodeEgressError> {
        let (role, sequence, transaction_id, local_circuit_id, join_cid, peer_cid, path_count) = {
            let slot = self
                .slot(association)
                .ok_or(QuicNodeError::MissingAssociation)?;
            let role = match &slot.state {
                Association::Client(_) => crate::Role::Client,
                Association::Server(_) => crate::Role::Server,
            };
            let role_index = usize::from(role == crate::Role::Server);
            let endpoint = match &slot.state {
                Association::Client(client) => client.connection().endpoint(),
                Association::Server(server) => Some(&server.mux.endpoint),
            }
            .ok_or(QuicNodeEgressError::Transport(Error::Invalid))?;
            (
                role,
                slot.next_circuit_sequence[role_index],
                slot.next_transaction_id,
                slot.next_circuit_id,
                slot.peer_join_cid
                    .or_else(|| endpoint.peer_connection_id_on_path(0))
                    .ok_or(QuicNodeEgressError::Transport(Error::WrongConnectionId))?,
                endpoint
                    .peer_connection_id_on_path(0)
                    .ok_or(QuicNodeEgressError::Transport(Error::WrongConnectionId))?,
                endpoint.path_count(),
            )
        };
        if sequence == 0
            || sequence >= (1 << 62)
            || transaction_id == 0
            || transaction_id >= (1 << 62)
            || local_circuit_id == u64::MAX
        {
            return Err(QuicNodeEgressError::Transport(Error::PacketNumberExhausted));
        }
        if path_count >= crate::MAX_PATH_STATES {
            return Err(QuicNodeEgressError::Transport(Error::PathLimit));
        }
        let key = crate::CircuitKey {
            opener_role: role,
            sequence,
        };
        let local_cid = loop {
            let candidate = self.allocate_local_cid()?;
            if candidate != peer_cid {
                break candidate;
            }
        };
        let pool = self.pool;
        let packet = Self::build_packet(pool, |output| {
            let slot = self.slot_mut(association).ok_or(Error::WrongConnectionId)?;
            let endpoint = match &mut slot.state {
                Association::Client(client) => client.connection_mut().endpoint_mut()?,
                Association::Server(server) => &mut server.mux.endpoint,
            };
            endpoint.encode_path_control_packet(
                0,
                peer_cid,
                Frame::PathJoin {
                    join_cid,
                    key,
                    transaction_id,
                    receive_cid: local_cid,
                },
                output,
            )
        })?;

        self.router
            .register_endpoint(local_cid, association)
            .map_err(|_| QuicNodeEgressError::Association(QuicNodeError::Routing))?;
        let result = (|| {
            let slot = self
                .slot_mut(association)
                .ok_or(QuicNodeEgressError::Association(
                    QuicNodeError::MissingAssociation,
                ))?;
            let endpoint = match &mut slot.state {
                Association::Client(client) => client
                    .connection_mut()
                    .endpoint_mut()
                    .map_err(QuicNodeEgressError::Transport)?,
                Association::Server(server) => &mut server.mux.endpoint,
            };
            let path_id = endpoint
                .add_path_state_with_local_id(local_cid)
                .map_err(QuicNodeEgressError::Transport)?;
            let path = endpoint.path_state_mut(path_id).unwrap();
            path.set_circuit(key, transaction_id, local_circuit_id);
            path.remember_address(address);
            let role_index = usize::from(role == crate::Role::Server);
            slot.next_circuit_sequence[role_index] = sequence.saturating_add(1);
            slot.next_transaction_id = transaction_id.saturating_add(1);
            slot.next_circuit_id = local_circuit_id + 1;
            slot.receive_cids[path_id] = Some(local_cid);
            Ok(NodeEgress {
                association,
                bearer: address.0,
                peer_l2_address: address.1,
                packet,
            })
        })();
        if result.is_err() {
            let _ = self.router.remove_endpoint(local_cid, &association);
        }
        result.map(|packet| (key, packet))
    }

    /// Retry an opening direct circuit with its original key and transaction
    /// identifier. Every retry receives a fresh shared packet number; the
    /// receiver can therefore replay the cached join result idempotently.
    pub(crate) fn retry_direct_path(
        &mut self,
        association: QuicAssociation,
        key: crate::CircuitKey,
    ) -> Result<NodeEgress<P::Buffer>, QuicNodeEgressError> {
        let (transaction_id, receive_cid, peer_cid, address) = {
            let slot = self
                .slot(association)
                .ok_or(QuicNodeError::MissingAssociation)?;
            let endpoint = match &slot.state {
                Association::Client(client) => client.connection().endpoint(),
                Association::Server(server) => Some(&server.mux.endpoint),
            }
            .ok_or(QuicNodeEgressError::Transport(Error::Invalid))?;
            let path_id = endpoint
                .paths
                .iter()
                .position(|path| path.circuit_key() == Some(key))
                .ok_or(QuicNodeEgressError::Transport(Error::Invalid))?;
            let path = endpoint.path_state(path_id).unwrap();
            if path.is_validated() {
                return Err(QuicNodeEgressError::Transport(Error::Invalid));
            }
            if path.join_attempts() >= crate::MAX_PATH_JOIN_ATTEMPTS {
                return Err(QuicNodeEgressError::PathSetupAttemptsExhausted);
            }
            (
                path.transaction_id()
                    .ok_or(QuicNodeEgressError::Transport(Error::Invalid))?,
                endpoint
                    .local_connection_id_on_path(path_id)
                    .ok_or(QuicNodeEgressError::Transport(Error::WrongConnectionId))?,
                endpoint
                    .peer_connection_id_on_path(0)
                    .ok_or(QuicNodeEgressError::Transport(Error::WrongConnectionId))?,
                path.active_address()
                    .ok_or(QuicNodeEgressError::MissingEgressAddress)?,
            )
        };
        let pool = self.pool;
        let packet = Self::build_packet(pool, |output| {
            let slot = self.slot_mut(association).ok_or(Error::WrongConnectionId)?;
            let endpoint = match &mut slot.state {
                Association::Client(client) => client.connection_mut().endpoint_mut()?,
                Association::Server(server) => &mut server.mux.endpoint,
            };
            endpoint.encode_path_control_packet(
                0,
                peer_cid,
                Frame::PathJoin {
                    join_cid: peer_cid,
                    key,
                    transaction_id,
                    receive_cid,
                },
                output,
            )
        })?;
        let slot = self
            .slot_mut(association)
            .ok_or(QuicNodeError::MissingAssociation)?;
        let path = match &mut slot.state {
            Association::Client(client) => client
                .connection_mut()
                .endpoint_mut()
                .map_err(QuicNodeEgressError::Transport)?
                .paths
                .iter_mut()
                .find(|path| path.circuit_key() == Some(key)),
            Association::Server(server) => server
                .mux
                .endpoint
                .paths
                .iter_mut()
                .find(|path| path.circuit_key() == Some(key)),
        }
        .ok_or(QuicNodeEgressError::Transport(Error::Invalid))?;
        let recorded = path.record_join_retry();
        debug_assert!(recorded);
        Ok(NodeEgress {
            association,
            bearer: address.0,
            peer_l2_address: address.1,
            packet,
        })
    }

    fn insert(
        &mut self,
        receive_cid: ConnectionId,
        mut state: Association<ClientAssociation<PACKET>, ServerStreamConnection<PACKET>>,
    ) -> Result<QuicAssociation, QuicNodeError> {
        let slot = self
            .associations
            .iter()
            .position(Option::is_none)
            .or_else(|| {
                (self.associations.len() < self.node_limits.max_associations)
                    .then_some(self.associations.len())
            })
            .ok_or(QuicNodeError::AssociationTableFull)?;
        if slot == self.generations.len() {
            self.generations
                .try_reserve(1)
                .map_err(|_| QuicNodeError::AssociationTableFull)?;
            self.generations.push(0);
        }
        let generation = self.generations[slot]
            .checked_add(1)
            .expect("association generation exhausted");
        let id = QuicAssociation {
            slot: slot as u32,
            generation,
        };
        self.router.register_endpoint(receive_cid, id)?;
        self.generations[slot] = generation;
        match &mut state {
            Association::Client(client) => {
                client.set_duplication_budget_capacity(
                    self.default_association_limits.duplication_budget_bytes as u64,
                );
                client
                    .set_pacing_config(self.default_association_limits.pacing)
                    .expect("admission pacing config is validated");
                client
                    .set_path_estimator_config(self.default_association_limits.path_estimator)
                    .expect("admission estimator config is validated");
                if let Ok(endpoint) = client.connection_mut().endpoint_mut() {
                    endpoint.set_base_circuit_key();
                }
            }
            Association::Server(server) => {
                server.mux.endpoint.set_base_circuit_key();
                server.mux.endpoint.set_duplication_budget_capacity(
                    self.default_association_limits.duplication_budget_bytes as u64,
                );
                server
                    .mux
                    .endpoint
                    .set_path_estimator_config(self.default_association_limits.path_estimator)
                    .expect("admission estimator config is validated");
                server
                    .mux
                    .endpoint
                    .set_pacing_config(self.default_association_limits.pacing)
                    .expect("admission pacing config is validated");
            }
        }
        let client_retention = match &state {
            Association::Client(client) => crate::callback::retention_for_receive_window(
                client.connection().local_limits(),
                crate::DEFAULT_REORDER_CAPACITY_BYTES,
            ),
            Association::Server(_) => crate::DEFAULT_REORDER_CAPACITY_BYTES,
        };
        let entry = Some(AssociationSlot {
            generation,
            receive_cid,
            peer_join_cid: None,
            relayed_join_requests: core::array::from_fn(|_| None),
            relayed_join_attempts: [0; crate::MAX_PATH_STATES],
            relayed_join_retry_at_us: [None; crate::MAX_PATH_STATES],
            relayed_join_deadline_us: [None; crate::MAX_PATH_STATES],
            receive_cids: {
                let mut cids = [None; crate::MAX_PATH_STATES];
                cids[0] = Some(receive_cid);
                cids
            },
            next_circuit_sequence: [1, 1],
            highest_remote_circuit_sequence: [0, 0],
            next_transaction_id: 1,
            next_circuit_id: 1,
            state,
            bootstrap_address: None,
            bootstrap: None,
            close_code: None,
            last_activity_us: self.clock_us,
            ack_eliciting_sent_since_receive: false,
            client_delivery: crate::callback::CallbackStreams::new(
                self.default_association_limits.max_pending_streams,
                client_retention.min(self.default_association_limits.max_buffered_stream_bytes),
            ),
            limits: self.default_association_limits,
        });
        if slot == self.associations.len() {
            self.associations.push(entry);
        } else {
            self.associations[slot] = entry;
        }
        self.push_association_event(AssociationEvent::CircuitOpened {
            association: id,
            circuit: CircuitId {
                association: id,
                local_id: 0,
            },
        });
        Ok(id)
    }

    pub(crate) fn register_forward(
        &mut self,
        receive_cid: ConnectionId,
        rule: ForwardRule<ForwardNextHop>,
    ) -> Result<(), QuicNodeError> {
        self.router.register_forward(receive_cid, rule)?;
        Ok(())
    }

    pub(crate) fn register_forward_pair(
        &mut self,
        first_receive_cid: ConnectionId,
        first_rule: ForwardRule<ForwardNextHop>,
        second_receive_cid: ConnectionId,
        second_rule: ForwardRule<ForwardNextHop>,
    ) -> Result<(), QuicNodeError> {
        self.router.register_forward_pair(
            first_receive_cid,
            first_rule,
            second_receive_cid,
            second_rule,
        )?;
        Ok(())
    }

    pub(crate) fn remove_forward(&mut self, receive_cid: ConnectionId) -> bool {
        self.router.remove_forward(receive_cid)
    }

    fn remove_forward_pair(
        &mut self,
        first_receive_cid: ConnectionId,
        second_receive_cid: ConnectionId,
    ) -> bool {
        self.router
            .remove_forward_pair(first_receive_cid, second_receive_cid)
    }

    #[cfg(test)]
    fn client(&self, id: QuicAssociation) -> Option<&ClientAssociation<PACKET>> {
        match &self.slot(id)?.state {
            Association::Client(client) => Some(client),
            Association::Server(_) => None,
        }
    }

    #[cfg(test)]
    fn server(&self, id: QuicAssociation) -> Option<&ServerStreamConnection<PACKET>> {
        match &self.slot(id)?.state {
            Association::Server(server) => Some(server),
            Association::Client(_) => None,
        }
    }

    #[cfg(test)]
    pub(crate) fn receive_cid(&self, id: QuicAssociation) -> Option<ConnectionId> {
        Some(self.slot(id)?.receive_cid)
    }

    /// Most recent bearer/address pair of a packet accepted by this
    /// association. This is a physical return route, never association
    /// identity or a DCID lookup key.
    ///
    /// Future multipath egress policy belongs at this boundary. Useful policy
    /// options include explicitly pinning a bearer, preferring measured
    /// throughput while periodically probing alternatives, distributing work
    /// across every ready bearer, and preferring a low-airtime bearer until
    /// its queue or credit is exhausted. Such selection must use registered
    /// bearer readiness/capacity plus this association's validated addresses;
    /// it must not introduce a second DCID table, treat a path as association
    /// identity, or make an unacknowledged outbound path active.
    pub(crate) fn association_egress_address(
        &self,
        id: QuicAssociation,
    ) -> Option<(BearerId, PeerL2Address)> {
        Self::slot_active_address(self.slot(id)?)
    }

    /// Accepted physical return addresses, newest first.
    #[cfg(test)]
    fn association_addresses(&self, id: QuicAssociation) -> Option<Vec<(BearerId, PeerL2Address)>> {
        let slot = self.slot(id)?;
        Some(
            (0..crate::MAX_PATH_STATES)
                .flat_map(|path_id| {
                    Self::slot_path_state(slot, path_id)
                        .into_iter()
                        .flat_map(|path| path.known_addresses().iter().copied())
                })
                .chain(slot.bootstrap_address)
                .collect(),
        )
    }

    pub(crate) fn remove_client(
        &mut self,
        id: QuicAssociation,
    ) -> Result<Box<ClientAssociation<PACKET>>, QuicNodeError> {
        if !matches!(
            self.slot(id).map(|slot| &slot.state),
            Some(Association::Client(_))
        ) {
            return Err(if self.slot(id).is_some() {
                QuicNodeError::WrongAssociationRole
            } else {
                QuicNodeError::MissingAssociation
            });
        }
        match self.remove(id)? {
            Association::Client(client) => Ok(client),
            Association::Server(_) => unreachable!("role checked before removal"),
        }
    }

    #[cfg(test)]
    fn remove_server(
        &mut self,
        id: QuicAssociation,
    ) -> Result<Box<ServerStreamConnection<PACKET>>, QuicNodeError> {
        if !matches!(
            self.slot(id).map(|slot| &slot.state),
            Some(Association::Server(_))
        ) {
            return Err(if self.slot(id).is_some() {
                QuicNodeError::WrongAssociationRole
            } else {
                QuicNodeError::MissingAssociation
            });
        }
        match self.remove(id)? {
            Association::Server(server) => Ok(server),
            Association::Client(_) => unreachable!("role checked before removal"),
        }
    }

    fn remove(
        &mut self,
        id: QuicAssociation,
    ) -> Result<Association<ClientAssociation<PACKET>, ServerStreamConnection<PACKET>>, QuicNodeError>
    {
        let slot = self
            .slot_index(id)
            .ok_or(QuicNodeError::MissingAssociation)?;
        let entry = self.associations[slot]
            .take()
            .ok_or(QuicNodeError::MissingAssociation)?;
        // Deferred ACK/credit intents have no endpoint to act on after any
        // close/reset/timeout. Leaving one queued would make a later owner
        // turn fail the whole node with MissingAssociation.
        self.pending_controls
            .retain(|association| *association != id);
        self.datagram_handlers
            .retain(|(association, _)| *association != id);
        let mut removed_all = true;
        for cid in entry.receive_cids.into_iter().flatten() {
            removed_all &= self.router.remove_endpoint(cid, &id);
        }
        debug_assert!(
            removed_all,
            "association and every path DCID route must retire together"
        );
        Ok(entry.state)
    }

    /// Number of live associations currently owned by the node.
    ///
    /// This is public for status, admission, and test assertions; it does not
    /// expose association slots or permit callers to drive protocol state.
    pub fn association_count(&self) -> usize {
        self.associations
            .iter()
            .filter(|slot| slot.is_some())
            .count()
    }

    /// Take the next terminal association lifecycle event.
    pub fn next_association_event(&mut self) -> Option<AssociationEvent> {
        if self.dropped_association_events != 0 {
            let count = core::mem::take(&mut self.dropped_association_events);
            return Some(AssociationEvent::EventsDropped { count });
        }
        self.association_events.pop_front()
    }

    /// Add a directly reachable circuit to an established association.
    ///
    /// The join packet is submitted through the selected registered bearer.
    /// Its exact packet lease remains owned by the bearer across `WouldBlock`.
    pub fn add_direct_circuit(
        &mut self,
        association: QuicAssociation,
        next_hop: CircuitNextHop,
        now_us: u64,
    ) -> Result<CircuitId, QuicNodeEgressError>
    where
        P::Buffer: Send,
    {
        self.advance_clock(now_us);
        self.drain_bearer_events();
        let bearer = self
            .bearers
            .get(next_hop.bearer)
            .ok_or(QuicNodeEgressError::MissingBearer)?;
        if !bearer.can_submit() {
            return Err(QuicNodeEgressError::BearerBusy);
        }
        let (key, packet) =
            self.open_direct_path(association, (next_hop.bearer, next_hop.peer_l2_address))?;
        let local_id = {
            let slot = self
                .slot(association)
                .ok_or(QuicNodeError::MissingAssociation)?;
            let endpoint = match &slot.state {
                Association::Client(client) => client.connection().endpoint().unwrap(),
                Association::Server(server) => &server.mux.endpoint,
            };
            endpoint
                .paths
                .iter()
                .find(|path| path.circuit_key() == Some(key))
                .map(crate::PathState::local_circuit_id)
                .ok_or(QuicNodeEgressError::Transport(Error::Invalid))?
        };
        let circuit = CircuitId {
            association,
            local_id,
        };
        self.submit_node_packet(packet)?;
        self.push_association_event(AssociationEvent::CircuitOpened {
            association,
            circuit,
        });
        Ok(circuit)
    }

    /// Retry a pending direct circuit with its original join transaction.
    pub fn retry_direct_circuit(&mut self, circuit: CircuitId) -> Result<(), QuicNodeEgressError>
    where
        P::Buffer: Send,
    {
        let key = {
            let slot = self
                .slot(circuit.association)
                .ok_or(QuicNodeError::MissingAssociation)?;
            let endpoint = match &slot.state {
                Association::Client(client) => client.connection().endpoint().unwrap(),
                Association::Server(server) => &server.mux.endpoint,
            };
            endpoint
                .paths
                .iter()
                .find(|path| path.local_circuit_id() == circuit.local_id)
                .and_then(crate::PathState::circuit_key)
                .ok_or(QuicNodeEgressError::Transport(Error::Invalid))?
        };
        let packet = self.retry_direct_path(circuit.association, key)?;
        self.submit_node_packet(packet)
    }

    /// Suspend a circuit after an explicit neighbour-down notification.
    /// Outstanding flight is discarded once without treating the neighbour
    /// event as network congestion; retained stream ranges remain repairable
    /// over another validated circuit.
    pub fn suspend_circuit(&mut self, circuit: CircuitId) -> Result<(), QuicNodeEgressError> {
        let (path_id, local_id, was_suspended) = {
            let slot = self
                .slot(circuit.association)
                .ok_or(QuicNodeError::MissingAssociation)?;
            let endpoint = match &slot.state {
                Association::Client(client) => client.connection().endpoint().unwrap(),
                Association::Server(server) => &server.mux.endpoint,
            };
            let path_id = endpoint
                .paths
                .iter()
                .position(|path| path.local_circuit_id() == circuit.local_id)
                .ok_or(QuicNodeEgressError::Transport(Error::Invalid))?;
            let path = endpoint.path_state(path_id).unwrap();
            (path_id, path.local_circuit_id(), path.is_suspended())
        };
        if was_suspended {
            return Ok(());
        }
        let slot = self
            .slot_mut(circuit.association)
            .ok_or(QuicNodeError::MissingAssociation)?;
        let endpoint = match &mut slot.state {
            Association::Client(client) => client
                .connection_mut()
                .endpoint_mut()
                .map_err(QuicNodeEgressError::Transport)?,
            Association::Server(server) => &mut server.mux.endpoint,
        };
        if endpoint
            .path_state(path_id)
            .and_then(crate::PathState::circuit_key)
            .is_some()
        {
            endpoint
                .queue_path_status(path_id, crate::PathStatusKind::Standby)
                .map_err(QuicNodeEgressError::Transport)?;
        }
        endpoint.suspend_path(path_id);
        self.push_association_event(AssociationEvent::CircuitStatusChanged {
            association: circuit.association,
            circuit: CircuitId {
                association: circuit.association,
                local_id,
            },
            status: CircuitStatus::Suspended,
        });
        Ok(())
    }

    /// Resume a suspended direct circuit on a currently registered bearer.
    /// Bulk scheduling stays disabled until a same-circuit challenge response
    /// arrives; the exact challenge packet is retained across `WouldBlock`.
    pub fn resume_circuit(
        &mut self,
        circuit: CircuitId,
        next_hop: CircuitNextHop,
        now_us: u64,
    ) -> Result<(), QuicNodeEgressError>
    where
        P::Buffer: Send,
    {
        self.advance_clock(now_us);
        self.drain_bearer_events();
        let bearer = self
            .bearers
            .get(next_hop.bearer)
            .ok_or(QuicNodeEgressError::MissingBearer)?;
        if !bearer.can_submit() {
            return Err(QuicNodeEgressError::BearerBusy);
        }
        let (path_id, local_id, local_cid, packet_number, status) = {
            let slot = self
                .slot(circuit.association)
                .ok_or(QuicNodeError::MissingAssociation)?;
            let endpoint = match &slot.state {
                Association::Client(client) => client.connection().endpoint().unwrap(),
                Association::Server(server) => &server.mux.endpoint,
            };
            let path_id = endpoint
                .paths
                .iter()
                .position(|path| path.local_circuit_id() == circuit.local_id)
                .ok_or(QuicNodeEgressError::Transport(Error::Invalid))?;
            let path = endpoint.path_state(path_id).unwrap();
            (
                path_id,
                path.local_circuit_id(),
                endpoint
                    .local_connection_id_on_path(path_id)
                    .ok_or(QuicNodeEgressError::Transport(Error::WrongConnectionId))?,
                endpoint.next_packet_number(),
                path.circuit_status(),
            )
        };
        if !matches!(status, CircuitStatus::Suspended | CircuitStatus::Probing) {
            return Err(QuicNodeEgressError::Transport(Error::Invalid));
        }
        if self
            .router
            .path_probe_token_for(local_cid, packet_number)
            .is_none()
        {
            return Err(QuicNodeEgressError::Transport(Error::Invalid));
        }
        {
            let slot = self
                .slot_mut(circuit.association)
                .ok_or(QuicNodeError::MissingAssociation)?;
            let endpoint = match &mut slot.state {
                Association::Client(client) => client
                    .connection_mut()
                    .endpoint_mut()
                    .map_err(QuicNodeEgressError::Transport)?,
                Association::Server(server) => &mut server.mux.endpoint,
            };
            let path = endpoint.path_state_mut(path_id).unwrap();
            path.remember_address((next_hop.bearer, next_hop.peer_l2_address));
            path.mark_probing();
            path.reset_recovery_for_resumption();
            path.schedule_probe(now_us);
        }
        let packet = self.prepare_path_probe(circuit.association, path_id, now_us)?;
        self.submit_node_packet(packet)?;
        self.push_association_event(AssociationEvent::CircuitStatusChanged {
            association: circuit.association,
            circuit: CircuitId {
                association: circuit.association,
                local_id,
            },
            status: CircuitStatus::Probing,
        });
        Ok(())
    }

    /// Close a validated, idle direct circuit after its reliable abandon status
    /// has been acknowledged, then retire its receive-CID route. The first
    /// call queues PATH_STATUS and returns `CircuitBusy`; retry after its ACK.
    pub fn close_circuit(&mut self, circuit: CircuitId) -> Result<(), QuicNodeEgressError> {
        let (path_id, receive_cid, busy, abandon_pending, abandon_complete) = {
            let slot = self
                .slot(circuit.association)
                .ok_or(QuicNodeError::MissingAssociation)?;
            let endpoint = match &slot.state {
                Association::Client(client) => client.connection().endpoint().unwrap(),
                Association::Server(server) => &server.mux.endpoint,
            };
            let path_id = endpoint
                .paths
                .iter()
                .position(|path| path.local_circuit_id() == circuit.local_id)
                .ok_or(QuicNodeEgressError::Transport(Error::Invalid))?;
            if path_id == 0 {
                return Err(QuicNodeEgressError::Transport(Error::Invalid));
            }
            let path = endpoint.path_state(path_id).unwrap();
            (
                path_id,
                slot.receive_cids[path_id]
                    .ok_or(QuicNodeEgressError::Transport(Error::WrongConnectionId))?,
                (!path.is_validated() || endpoint.path_has_outstanding_packets(path_id))
                    && !path.local_abandon_complete(),
                path.local_abandon_pending(),
                path.local_abandon_complete(),
            )
        };
        if busy {
            return Err(QuicNodeEgressError::CircuitBusy);
        }
        if !abandon_complete {
            if !abandon_pending {
                let slot = self
                    .slot_mut(circuit.association)
                    .ok_or(QuicNodeError::MissingAssociation)?;
                let endpoint = match &mut slot.state {
                    Association::Client(client) => client
                        .connection_mut()
                        .endpoint_mut()
                        .map_err(QuicNodeEgressError::Transport)?,
                    Association::Server(server) => &mut server.mux.endpoint,
                };
                endpoint
                    .queue_path_status(path_id, crate::PathStatusKind::Abandon)
                    .map_err(QuicNodeEgressError::Transport)?;
                self.push_association_event(AssociationEvent::CircuitStatusChanged {
                    association: circuit.association,
                    circuit,
                    status: CircuitStatus::Closed,
                });
            }
            return Err(QuicNodeEgressError::CircuitBusy);
        }
        if !self
            .router
            .remove_endpoint(receive_cid, &circuit.association)
        {
            return Err(QuicNodeError::Routing.into());
        }
        let slot = self
            .slot_mut(circuit.association)
            .ok_or(QuicNodeError::MissingAssociation)?;
        Self::remove_slot_path_state(slot, path_id).map_err(QuicNodeEgressError::Transport)?;
        self.push_association_event(AssociationEvent::CircuitClosed {
            association: circuit.association,
            circuit,
        });
        Ok(())
    }

    /// Fill `out` with a prefix of the association's circuit snapshots and
    /// return the total circuit count. This method allocates no memory.
    pub fn circuits(&self, association: QuicAssociation, out: &mut [CircuitInfo]) -> usize {
        let Some(slot) = self.slot(association) else {
            return 0;
        };
        let count = Self::slot_path_count(slot);
        let mut written = 0;
        for path_id in 0..count {
            if written == out.len() {
                break;
            }
            if let Some(info) = Self::circuit_info(association, slot, path_id) {
                out[written] = info;
                written += 1;
            }
        }
        count
    }

    #[cfg(test)]
    pub(crate) fn configure_ack_range_stress_for_test(
        &mut self,
        association: QuicAssociation,
    ) -> bool {
        let Some(slot) = self.slot_mut(association) else {
            return false;
        };
        let endpoint = match &mut slot.state {
            Association::Client(client) => client.connection_mut().endpoint_mut().ok(),
            Association::Server(server) => Some(&mut server.mux.endpoint),
        };
        let Some(endpoint) = endpoint else {
            return false;
        };
        endpoint.configure_ack_range_stress_for_test();
        true
    }

    #[cfg(test)]
    pub(crate) fn restore_ack_policy_after_range_stress_for_test(
        &mut self,
        association: QuicAssociation,
    ) -> bool {
        let Some(slot) = self.slot_mut(association) else {
            return false;
        };
        let endpoint = match &mut slot.state {
            Association::Client(client) => client.connection_mut().endpoint_mut().ok(),
            Association::Server(server) => Some(&mut server.mux.endpoint),
        };
        let Some(endpoint) = endpoint else {
            return false;
        };
        endpoint.restore_ack_policy_after_range_stress_for_test();
        true
    }

    #[cfg(test)]
    pub(crate) fn submit_ping_on_path_for_test(
        &mut self,
        association: QuicAssociation,
        path_id: usize,
    ) -> Result<(), QuicNodeEgressError>
    where
        P::Buffer: Send,
    {
        let (bearer, peer_l2_address, destination) = {
            let slot = self
                .slot(association)
                .ok_or(QuicNodeError::MissingAssociation)?;
            let path = Self::slot_path_state(slot, path_id)
                .ok_or(QuicNodeEgressError::Transport(Error::PathLimit))?;
            let (bearer, peer_l2_address) = path
                .active_address()
                .ok_or(QuicNodeEgressError::MissingEgressAddress)?;
            let endpoint = match &slot.state {
                Association::Client(client) => client.connection().endpoint().unwrap(),
                Association::Server(server) => &server.mux.endpoint,
            };
            (
                bearer,
                peer_l2_address,
                endpoint
                    .peer_connection_id_on_path(path_id)
                    .ok_or(QuicNodeEgressError::Transport(Error::WrongConnectionId))?,
            )
        };
        let packet = Self::build_packet(self.pool, |output| {
            let slot = self.slot_mut(association).ok_or(Error::WrongConnectionId)?;
            let endpoint = match &mut slot.state {
                Association::Client(client) => client.connection_mut().endpoint_mut()?,
                Association::Server(server) => &mut server.mux.endpoint,
            };
            endpoint.encode_path_control_packet(path_id, destination, Frame::Ping, output)
        })?;
        self.submit_node_packet(NodeEgress {
            association,
            bearer,
            peer_l2_address,
            packet,
        })
    }

    #[cfg(test)]
    pub(crate) fn max_ack_delay_for_test(&self, association: QuicAssociation) -> Option<u64> {
        let slot = self.slot(association)?;
        let endpoint = match &slot.state {
            Association::Client(client) => client.connection().endpoint()?,
            Association::Server(server) => &server.mux.endpoint,
        };
        Some(endpoint.max_ack_delay_us())
    }

    #[cfg(test)]
    pub(crate) fn path_pto_timeout_for_test(
        &self,
        association: QuicAssociation,
        path_id: usize,
    ) -> Option<u64> {
        let slot = self.slot(association)?;
        let endpoint = match &slot.state {
            Association::Client(client) => client.connection().endpoint()?,
            Association::Server(server) => &server.mux.endpoint,
        };
        Some(endpoint.pto_timeout_for_test(path_id))
    }

    #[cfg(test)]
    pub(crate) fn pto_retransmissions_for_test(&self, association: QuicAssociation) -> Option<u64> {
        let slot = self.slot(association)?;
        let endpoint = match &slot.state {
            Association::Client(client) => client.connection().endpoint()?,
            Association::Server(server) => &server.mux.endpoint,
        };
        Some(endpoint.stats().pto_retransmitted_packets)
    }

    #[cfg(test)]
    pub(crate) fn set_path_window_for_test(
        &mut self,
        association: QuicAssociation,
        path_id: usize,
        window: u64,
    ) -> bool {
        let Some(slot) = self.slot_mut(association) else {
            return false;
        };
        let endpoint = match &mut slot.state {
            Association::Client(client) => client.connection_mut().endpoint_mut().ok(),
            Association::Server(server) => Some(&mut server.mux.endpoint),
        };
        let Some(path) = endpoint.and_then(|endpoint| endpoint.paths.get_mut(path_id)) else {
            return false;
        };
        path.congestion.congestion_window = window;
        path.congestion.slow_start_threshold = window;
        true
    }

    #[cfg(test)]
    pub(crate) fn seed_packet_number_state_for_test(
        &mut self,
        association: QuicAssociation,
        next_send: Option<u32>,
        largest_acked: Option<u32>,
        receive_expected: Option<u32>,
    ) -> bool {
        let Some(slot) = self.slot_mut(association) else {
            return false;
        };
        let endpoint = match &mut slot.state {
            Association::Client(client) => client.connection_mut().endpoint_mut().ok(),
            Association::Server(server) => Some(&mut server.mux.endpoint),
        };
        let Some(endpoint) = endpoint else {
            return false;
        };
        endpoint.seed_packet_number_state_for_test(next_send, largest_acked, receive_expected);
        true
    }

    #[cfg(test)]
    pub(crate) fn received_ack_ranges_for_test(
        &self,
        association: QuicAssociation,
    ) -> Option<Vec<(u32, u32)>> {
        let slot = self.slot(association)?;
        let endpoint = match &slot.state {
            Association::Client(client) => client.connection().endpoint()?,
            Association::Server(server) => &server.mux.endpoint,
        };
        Some(
            (0..endpoint.received_packets.len())
                .filter_map(|index| {
                    endpoint
                        .received_packets
                        .get(index)
                        .map(|range| (range.start, range.end))
                })
                .collect(),
        )
    }

    #[cfg(feature = "tokio")]
    pub(crate) fn circuits_vec(&self, association: QuicAssociation) -> Vec<CircuitInfo> {
        let Some(slot) = self.slot(association) else {
            return Vec::new();
        };
        (0..Self::slot_path_count(slot))
            .filter_map(|path_id| Self::circuit_info(association, slot, path_id))
            .collect()
    }

    fn circuit_info(
        association: QuicAssociation,
        slot: &AssociationSlot<ClientAssociation<PACKET>, ServerStreamConnection<PACKET>>,
        path_id: usize,
    ) -> Option<CircuitInfo> {
        let local_role = match &slot.state {
            Association::Client(_) => crate::Role::Client,
            Association::Server(_) => crate::Role::Server,
        };
        let path = Self::slot_path_state(slot, path_id)?;
        let (bearer, peer_l2_address) = path
            .first_hop()
            .or_else(|| (path_id == 0).then_some(slot.bootstrap_address).flatten())?;
        let (
            srtt,
            min_rtt,
            cwnd,
            flight,
            sent,
            retransmitted,
            acked,
            lost,
            spurious_losses,
            duplicated,
            duplicate_bytes,
            probe_bytes,
            probe_bytes_budgeted,
            probe_bytes_idle_exempt,
            estimator_step_events,
            step_conservative_until_us,
        ) = path.circuit_telemetry();
        let opened_by_peer = path
            .circuit_key()
            .is_some_and(|key| key.opener_role != local_role);
        Some(CircuitInfo {
            id: CircuitId {
                association,
                local_id: path.local_circuit_id(),
            },
            first_hop: CircuitNextHop {
                bearer,
                peer_l2_address,
            },
            opened_by_peer,
            status: path.circuit_status(),
            srtt_us: srtt.map_or(0, |value| u32::try_from(value).unwrap_or(u32::MAX)),
            min_rtt_us: min_rtt.map_or(0, |value| u32::try_from(value).unwrap_or(u32::MAX)),
            cwnd_bytes: u32::try_from(cwnd).unwrap_or(u32::MAX),
            bytes_in_flight: u32::try_from(flight).unwrap_or(u32::MAX),
            packets_sent: sent,
            retransmitted_packets: retransmitted,
            ack_ranges_dropped: path.ack_ranges_dropped,
            packets_acked: acked,
            packets_lost: lost,
            spurious_losses,
            packets_duplicated: duplicated,
            duplicate_bytes_prepared: duplicate_bytes,
            probe_bytes_prepared: probe_bytes,
            probe_bytes_budgeted,
            probe_bytes_idle_exempt,
            estimator_step_events,
            step_conservative_until_us,
            last_ack_us: path.last_ack_us(),
        })
    }

    fn push_association_event(&mut self, event: AssociationEvent) {
        let capacity = self
            .node_limits
            .max_associations
            .max(1)
            .saturating_mul(crate::MAX_PATH_STATES)
            .saturating_mul(4);
        if self.association_events.len() >= capacity {
            self.association_events.pop_front();
            self.dropped_association_events = self.dropped_association_events.saturating_add(1);
        }
        self.association_events.push_back(event);
    }

    /// Set the inactivity deadline applied to every live association.
    ///
    /// Packet ingress and association egress refresh activity. When no packet
    /// crosses either boundary for this many microseconds, the next platform
    /// timer event retires the association and its private DCID route. This is
    /// the fallback for abrupt peer disappearance; orderly clients should use
    /// their runtime's graceful association-finish operation instead.
    pub fn set_idle_timeout_us(&mut self, timeout_us: u64) {
        self.idle_timeout_us = timeout_us.max(1);
    }

    pub(crate) fn association_is_established(&self, id: QuicAssociation) -> bool {
        self.slot(id).is_some_and(|slot| match &slot.state {
            Association::Client(client) => client.connection().is_established(),
            Association::Server(_) => true,
        })
    }

    pub(crate) fn contains_association(&self, id: QuicAssociation) -> bool {
        self.slot(id).is_some()
    }

    pub(crate) fn allocate_local_cid(&mut self) -> Result<ConnectionId, QuicNodeError> {
        for _ in 0..=self.node_limits.max_associations {
            let value = self.next_local_cid;
            self.next_local_cid = self.next_local_cid.saturating_add(1).max(1);
            let cid = ConnectionId::new(value).expect("node CID counter stays in range");
            if !self.router.contains(cid) {
                return Ok(cid);
            }
        }
        Err(QuicNodeError::AssociationTableFull)
    }

    fn slot(
        &self,
        id: QuicAssociation,
    ) -> Option<&AssociationSlot<ClientAssociation<PACKET>, ServerStreamConnection<PACKET>>> {
        self.associations.get(self.slot_index(id)?)?.as_ref()
    }

    fn slot_mut(
        &mut self,
        id: QuicAssociation,
    ) -> Option<&mut AssociationSlot<ClientAssociation<PACKET>, ServerStreamConnection<PACKET>>>
    {
        let slot = self.slot_index(id)?;
        self.associations.get_mut(slot)?.as_mut()
    }

    fn slot_index(&self, id: QuicAssociation) -> Option<usize> {
        let slot = id.slot as usize;
        let entry = self.associations.get(slot)?.as_ref()?;
        (entry.generation == id.generation).then_some(slot)
    }

    fn association_ingress(&self, id: QuicAssociation) -> Option<AssociationIngress> {
        match &self.slot(id)?.state {
            Association::Client(_) => Some(AssociationIngress::Client(id)),
            Association::Server(_) => Some(AssociationIngress::Server(id)),
        }
    }

    fn remember_address(&mut self, id: QuicAssociation, meta: PacketMeta) {
        let clock_us = self.clock_us;
        let Some(slot) = self.slot_mut(id) else {
            return;
        };
        let address = (meta.bearer, meta.peer_l2_address);
        Self::remember_slot_address(slot, address);
        slot.last_activity_us = clock_us;
        slot.ack_eliciting_sent_since_receive = false;
    }

    fn remember_ingress_path_address(
        &mut self,
        id: QuicAssociation,
        path_id: usize,
        meta: PacketMeta,
        advance_egress: bool,
    ) {
        let clock_us = self.clock_us;
        let Some(slot) = self.slot_mut(id) else {
            return;
        };
        if advance_egress {
            let address = (meta.bearer, meta.peer_l2_address);
            if let Some(path) = Self::slot_path_state_mut(slot, path_id) {
                path.remember_address(address);
            }
        }
        slot.last_activity_us = clock_us;
        slot.ack_eliciting_sent_since_receive = false;
    }
}

impl<P, const PACKET: usize> QuicNode<P, PACKET>
where
    P: PacketPool,
{
    fn build_packet(
        pool: &'static P,
        serialize: impl FnOnce(&mut [u8; PACKET]) -> Result<usize, Error>,
    ) -> Result<OwnedPacket<P::Buffer>, QuicNodeEgressError> {
        let packet = pool
            .build_packet(PACKET_PREFIX_RESERVE, 0, |output| {
                if output.len() < PACKET.saturating_add(PACKET_SUFFIX_RESERVE) {
                    return Err(Error::BufferTooSmall);
                }
                let output = output
                    .get_mut(..PACKET)
                    .and_then(|output| output.try_into().ok())
                    .ok_or(Error::BufferTooSmall)?;
                serialize(output)
            })
            .map_err(|error| match error {
                PacketBuildError::Unavailable => QuicNodeEgressError::PoolUnavailable,
                PacketBuildError::Serialize(error) => QuicNodeEgressError::Transport(error),
                PacketBuildError::InvalidLength => QuicNodeEgressError::InvalidPoolLayout,
            })?;
        if packet.prefix_capacity() < PACKET_PREFIX_RESERVE
            || packet.suffix_capacity() < PACKET_SUFFIX_RESERVE
        {
            return Err(QuicNodeEgressError::InvalidPoolLayout);
        }
        Ok(packet)
    }

    fn build_optional_packet(
        pool: &'static P,
        serialize: impl FnOnce(&mut [u8; PACKET]) -> Result<Option<usize>, Error>,
    ) -> Result<Option<OwnedPacket<P::Buffer>>, QuicNodeEgressError> {
        let mut writer = pool
            .acquire_writer(PACKET_PREFIX_RESERVE, 0)
            .ok_or(QuicNodeEgressError::PoolUnavailable)?;
        if writer.payload_mut().len() < PACKET.saturating_add(PACKET_SUFFIX_RESERVE) {
            return Err(QuicNodeEgressError::InvalidPoolLayout);
        }
        let output = writer
            .payload_mut()
            .get_mut(..PACKET)
            .and_then(|output| output.try_into().ok())
            .ok_or(QuicNodeEgressError::InvalidPoolLayout)?;
        let Some(used) = serialize(output).map_err(QuicNodeEgressError::Transport)? else {
            return Ok(None);
        };
        let packet = writer
            .commit(used)
            .ok_or(QuicNodeEgressError::InvalidPoolLayout)?;
        Ok(Some(packet))
    }

    /// Start a client association through one registered packet bearer.
    ///
    /// This is a runtime-independent state-machine operation. `now` is the
    /// caller's monotonic time in microseconds; a Tokio task, RTOS task, or
    /// interrupt-driven platform supplies it from its own clock. Success means
    /// the Initial packet was accepted by the bearer and the node owns the
    /// association state.
    pub fn associate(
        &mut self,
        address: PacketMeta,
        now: u64,
    ) -> Result<QuicAssociation, QuicNodeEgressError>
    where
        P::Buffer: Send,
    {
        self.advance_clock(now);
        self.drain_bearer_events();
        if !self
            .bearers
            .get(address.bearer)
            .is_some_and(|bearer| bearer.can_submit())
        {
            return Err(QuicNodeEgressError::BearerBusy);
        }
        let receive_cid = self.allocate_local_cid()?;
        let packet = self.start_association(receive_cid, address, now)?;
        let association = packet.association;
        self.submit_node_packet(packet)?;
        Ok(association)
    }

    /// Start a client association through a client-selected layered relay
    /// circuit. Relay instructions and the endpoint Initial are carried in a
    /// connectionless PATH_OPEN; the exact request is retried until a matching
    /// PATH_OPEN_ACK arrives or the bootstrap attempt limit is reached.
    pub fn associate_relayed(
        &mut self,
        address: PacketMeta,
        destination_vip: Option<u64>,
        hops: &[RelayHop],
        now: u64,
    ) -> Result<QuicAssociation, QuicNodeEgressError>
    where
        P::Buffer: Send,
    {
        self.associate_relayed_with_return_hints(
            address,
            destination_vip,
            hops,
            NearbyRelayHints::EMPTY,
            now,
        )
    }

    /// Start a relayed association and include client-selected nearby relay
    /// hints for the peer to use when constructing an independent return path.
    pub fn associate_relayed_with_return_hints(
        &mut self,
        address: PacketMeta,
        destination_vip: Option<u64>,
        hops: &[RelayHop],
        return_hints: NearbyRelayHints,
        now: u64,
    ) -> Result<QuicAssociation, QuicNodeEgressError>
    where
        P::Buffer: Send,
    {
        self.associate_relayed_with_route_mode(
            address,
            destination_vip,
            hops,
            return_hints,
            crate::RelayRouteMode::Layered,
            now,
        )
    }

    /// Start a relayed association using an explicit setup routing mode.
    /// VIP-routed requests carry `destination_vip`; every relay resolves its
    /// own next hop from that untrusted destination hint and local policy.
    pub fn associate_relayed_with_route_mode(
        &mut self,
        address: PacketMeta,
        destination_vip: Option<u64>,
        hops: &[RelayHop],
        return_hints: NearbyRelayHints,
        route_mode: crate::RelayRouteMode,
        now: u64,
    ) -> Result<QuicAssociation, QuicNodeEgressError>
    where
        P::Buffer: Send,
    {
        if matches!(
            route_mode,
            crate::RelayRouteMode::VipRouted | crate::RelayRouteMode::Telescoping
        ) && destination_vip.is_none_or(|vip| vip == 0)
        {
            return Err(QuicNodeEgressError::Transport(Error::Invalid));
        }
        if route_mode == crate::RelayRouteMode::Telescoping && hops.len() != 1 {
            return Err(QuicNodeEgressError::Transport(Error::Invalid));
        }
        if hops.is_empty() || hops.len() >= crate::relay::MAX_SETUP_BLOCKS {
            return Err(QuicNodeEgressError::Transport(Error::Invalid));
        }
        if destination_vip == Some(0)
            || hops.iter().any(|hop| {
                hop.address_kind == 0
                    || hop.address_len == 0
                    || usize::from(hop.address_len) > crate::relay::MAX_SETUP_HOP_ADDRESS_BYTES
                    || hop.lease_us == 0
                    || hop.packet_quota == 0
            })
        {
            return Err(QuicNodeEgressError::Transport(Error::Invalid));
        }
        self.advance_clock(now);
        self.drain_bearer_events();
        if !self
            .bearers
            .get(address.bearer)
            .is_some_and(|bearer| bearer.can_submit())
        {
            return Err(QuicNodeEgressError::BearerBusy);
        }
        let transaction_id = self.next_setup_transaction_id;
        if transaction_id == 0 || transaction_id >= (1 << 62) {
            return Err(QuicNodeEgressError::Transport(Error::PacketNumberExhausted));
        }
        let receive_cid = self.allocate_local_cid()?;
        let initial = self.start_association(receive_cid, address, now)?;
        let association = initial.association;

        let mut payloads =
            [[0u8; crate::relay::MAX_SETUP_BLOCK_BYTES]; crate::relay::MAX_SETUP_BLOCKS - 1];
        let mut payload_lens = [0usize; crate::relay::MAX_SETUP_BLOCKS - 1];
        for (index, hop) in hops.iter().enumerate() {
            let instruction = crate::relay::SetupHopInstruction {
                address_kind: hop.address_kind,
                address_len: hop.address_len,
                address: hop.address,
                lease_us: hop.lease_us,
                packet_quota: hop.packet_quota,
            };
            payload_lens[index] = instruction
                .encode(&mut payloads[index])
                .map_err(QuicNodeEgressError::Transport)?;
        }
        let mut endpoint_payload = [0u8; crate::relay::MAX_SETUP_BLOCK_BYTES];
        let (endpoint_block_version, endpoint_block_payload) = if return_hints.is_empty() {
            (1, initial.packet.bytes())
        } else {
            let endpoint = crate::relay::SetupCreateEndpoint {
                initial_packet: initial.packet.bytes(),
                return_hints,
            };
            let used = endpoint
                .encode(&mut endpoint_payload)
                .map_err(QuicNodeEgressError::Transport)?;
            (2, &endpoint_payload[..used])
        };
        let mut blocks = [crate::relay::SetupBlock {
            kind: crate::relay::SETUP_BLOCK_ENDPOINT,
            version: 1,
            protection: 0,
            payload: &[],
        }; crate::relay::MAX_SETUP_BLOCKS];
        for index in 0..hops.len() {
            blocks[index] = crate::relay::SetupBlock {
                kind: crate::relay::SETUP_BLOCK_RELAY,
                version: 1,
                protection: 0,
                payload: &payloads[index][..payload_lens[index]],
            };
        }
        blocks[hops.len()] = crate::relay::SetupBlock {
            kind: crate::relay::SETUP_BLOCK_ENDPOINT,
            version: endpoint_block_version,
            protection: 0,
            payload: endpoint_block_payload,
        };
        let request = crate::relay::SetupRequest {
            transaction_id,
            mode: crate::relay::SetupMode::Create,
            route_mode,
            circuit: crate::relay::SetupCircuitKey {
                opener_role: crate::Role::Client,
                sequence: 1,
            },
            destination_vip,
            previous_reverse_cid: None,
            blocks: &blocks[..hops.len() + 1],
        };
        let mut encoded = [0u8; crate::DEFAULT_MAX_PACKET_SIZE];
        let encoded_len = request
            .encode_packet(&mut encoded)
            .map_err(QuicNodeEgressError::Transport)?;
        let saved_request = encoded[..encoded_len].to_vec();
        drop(initial);
        let packet = Self::build_packet(self.pool, |output| {
            if output.len() < encoded_len {
                return Err(Error::BufferTooSmall);
            }
            output[..encoded_len].copy_from_slice(&encoded[..encoded_len]);
            Ok(encoded_len)
        })?;
        let slot = self
            .slot_mut(association)
            .ok_or(QuicNodeError::MissingAssociation)?;
        slot.bootstrap = Some(ClientBootstrap {
            next_attempt: 1,
            last_attempt_at: now,
            setup_transaction_id: Some(transaction_id),
            setup_relay_count: Some(hops.len() as u8),
            setup_request: Some(saved_request),
        });
        self.next_setup_transaction_id = transaction_id + 1;
        self.submit_node_packet(NodeEgress {
            association,
            bearer: address.bearer,
            peer_l2_address: address.peer_l2_address,
            packet,
        })?;
        Ok(association)
    }

    /// Start another layered relay circuit on an existing association.
    /// The local endpoint role qualifies the circuit sequence so simultaneous
    /// joins from both peers do not collide. The endpoint join CID identifies
    /// the peer association independently of the relay alias used to route
    /// path zero.
    pub fn join_relayed_path(
        &mut self,
        association: QuicAssociation,
        address: PacketMeta,
        hops: &[RelayHop],
        now: u64,
    ) -> Result<CircuitId, QuicNodeEgressError>
    where
        P::Buffer: Send,
    {
        self.join_relayed_path_with_route_mode(
            association,
            address,
            hops,
            crate::RelayRouteMode::Layered,
            None,
            now,
        )
    }

    /// Add a relayed path with an explicit routing mode and destination VIP.
    /// `VipRouted` requires a non-zero VIP, which every relay passes to its
    /// local resolver; `Layered` may omit it.
    pub fn join_relayed_path_with_route_mode(
        &mut self,
        association: QuicAssociation,
        address: PacketMeta,
        hops: &[RelayHop],
        route_mode: crate::RelayRouteMode,
        destination_vip: Option<u64>,
        now: u64,
    ) -> Result<CircuitId, QuicNodeEgressError>
    where
        P::Buffer: Send,
    {
        if matches!(
            route_mode,
            crate::RelayRouteMode::VipRouted | crate::RelayRouteMode::Telescoping
        ) && destination_vip.is_none_or(|vip| vip == 0)
        {
            return Err(QuicNodeEgressError::Transport(Error::Invalid));
        }
        if route_mode == crate::RelayRouteMode::Telescoping && hops.len() != 1 {
            return Err(QuicNodeEgressError::Transport(Error::Invalid));
        }
        if route_mode == crate::RelayRouteMode::Layered && destination_vip == Some(0) {
            return Err(QuicNodeEgressError::Transport(Error::Invalid));
        }
        if hops.is_empty() || hops.len() >= crate::relay::MAX_SETUP_BLOCKS {
            return Err(QuicNodeEgressError::Transport(Error::Invalid));
        }
        if hops.iter().any(|hop| {
            hop.address_kind == 0
                || hop.address_len == 0
                || usize::from(hop.address_len) > crate::relay::MAX_SETUP_HOP_ADDRESS_BYTES
                || hop.lease_us == 0
                || hop.packet_quota == 0
        }) {
            return Err(QuicNodeEgressError::Transport(Error::Invalid));
        }
        self.advance_clock(now);
        self.drain_bearer_events();
        if !self
            .bearers
            .get(address.bearer)
            .is_some_and(|bearer| bearer.can_submit())
        {
            return Err(QuicNodeEgressError::BearerBusy);
        }
        let (
            local_role,
            role_index,
            sequence,
            transaction_id,
            local_circuit_id,
            join_cid,
            path_count,
        ) = {
            let slot = self
                .slot(association)
                .ok_or(QuicNodeError::MissingAssociation)?;
            let (local_role, endpoint) = match &slot.state {
                Association::Client(client) => (
                    crate::Role::Client,
                    client
                        .connection()
                        .endpoint()
                        .ok_or(QuicNodeEgressError::Transport(Error::Invalid))?,
                ),
                Association::Server(server) => (crate::Role::Server, &server.mux.endpoint),
            };
            let role_index = usize::from(local_role == crate::Role::Server);
            let join_cid = slot
                .peer_join_cid
                .or_else(|| endpoint.peer_connection_id_on_path(0))
                .ok_or(QuicNodeEgressError::Transport(Error::WrongConnectionId))?;
            (
                local_role,
                role_index,
                slot.next_circuit_sequence[role_index],
                slot.next_transaction_id,
                slot.next_circuit_id,
                join_cid,
                endpoint.path_count(),
            )
        };
        if sequence == 0
            || sequence >= (1 << 62)
            || transaction_id == 0
            || transaction_id >= (1 << 62)
            || local_circuit_id == u64::MAX
        {
            return Err(QuicNodeEgressError::Transport(Error::PacketNumberExhausted));
        }
        if path_count >= crate::MAX_PATH_STATES {
            return Err(QuicNodeEgressError::Transport(Error::PathLimit));
        }
        let local_cid = self.allocate_local_cid()?;
        let key = crate::CircuitKey {
            opener_role: local_role,
            sequence,
        };
        let mut payloads =
            [[0u8; crate::relay::MAX_SETUP_BLOCK_BYTES]; crate::relay::MAX_SETUP_BLOCKS - 1];
        let mut payload_lens = [0usize; crate::relay::MAX_SETUP_BLOCKS - 1];
        for (index, hop) in hops.iter().enumerate() {
            let instruction = crate::relay::SetupHopInstruction {
                address_kind: hop.address_kind,
                address_len: hop.address_len,
                address: hop.address,
                lease_us: hop.lease_us,
                packet_quota: hop.packet_quota,
            };
            payload_lens[index] = instruction
                .encode(&mut payloads[index])
                .map_err(QuicNodeEgressError::Transport)?;
        }
        let mut endpoint_payload = [0u8; crate::relay::MAX_SETUP_BLOCK_BYTES];
        let endpoint_payload_len = crate::relay::SetupJoinEndpoint {
            join_cid,
            opener_receive_cid: local_cid,
        }
        .encode(&mut endpoint_payload)
        .map_err(QuicNodeEgressError::Transport)?;
        let mut blocks = [crate::relay::SetupBlock {
            kind: crate::relay::SETUP_BLOCK_ENDPOINT,
            version: 1,
            protection: 0,
            payload: &[],
        }; crate::relay::MAX_SETUP_BLOCKS];
        for index in 0..hops.len() {
            blocks[index] = crate::relay::SetupBlock {
                kind: crate::relay::SETUP_BLOCK_RELAY,
                version: 1,
                protection: 0,
                payload: &payloads[index][..payload_lens[index]],
            };
        }
        blocks[hops.len()] = crate::relay::SetupBlock {
            kind: crate::relay::SETUP_BLOCK_ENDPOINT,
            version: 1,
            protection: 0,
            payload: &endpoint_payload[..endpoint_payload_len],
        };
        let request = crate::relay::SetupRequest {
            transaction_id,
            mode: crate::relay::SetupMode::Join,
            route_mode,
            circuit: crate::relay::SetupCircuitKey {
                opener_role: key.opener_role,
                sequence,
            },
            destination_vip,
            previous_reverse_cid: None,
            blocks: &blocks[..hops.len() + 1],
        };
        let mut encoded = [0u8; crate::DEFAULT_MAX_PACKET_SIZE];
        let encoded_len = request
            .encode_packet(&mut encoded)
            .map_err(QuicNodeEgressError::Transport)?;
        let mut saved_request = Vec::new();
        saved_request
            .try_reserve_exact(encoded_len)
            .map_err(|_| QuicNodeEgressError::Transport(Error::HistoryFull))?;
        saved_request.extend_from_slice(&encoded[..encoded_len]);
        let packet = Self::build_packet(self.pool, |output| {
            if output.len() < encoded_len {
                return Err(Error::BufferTooSmall);
            }
            output[..encoded_len].copy_from_slice(&encoded[..encoded_len]);
            Ok(encoded_len)
        })?;
        self.router
            .register_endpoint(local_cid, association)
            .map_err(|_| QuicNodeEgressError::Association(QuicNodeError::Routing))?;
        let path_id = (|| {
            let slot = self
                .slot_mut(association)
                .ok_or(QuicNodeEgressError::Association(
                    QuicNodeError::MissingAssociation,
                ))?;
            let endpoint = match &mut slot.state {
                Association::Client(client) => client
                    .connection_mut()
                    .endpoint_mut()
                    .map_err(QuicNodeEgressError::Transport)?,
                Association::Server(server) => &mut server.mux.endpoint,
            };
            let path_id = endpoint
                .add_path_state_with_local_id(local_cid)
                .map_err(QuicNodeEgressError::Transport)?;
            let path = endpoint.path_state_mut(path_id).unwrap();
            path.set_circuit(key, transaction_id, local_circuit_id);
            path.remember_address((address.bearer, address.peer_l2_address));
            path.mark_unvalidated();
            slot.receive_cids[path_id] = Some(local_cid);
            slot.relayed_join_requests[path_id] = Some(saved_request);
            slot.relayed_join_attempts[path_id] = 1;
            slot.relayed_join_retry_at_us[path_id] =
                Some(now.saturating_add(DEFAULT_INITIAL_PTO_US));
            slot.relayed_join_deadline_us[path_id] =
                Some(now.saturating_add(DEFAULT_SETUP_PENDING_TIMEOUT_US));
            slot.next_circuit_sequence[role_index] = sequence + 1;
            slot.next_transaction_id = transaction_id + 1;
            slot.next_circuit_id = local_circuit_id + 1;
            Ok::<usize, QuicNodeEgressError>(path_id)
        })();
        let path_id = match path_id {
            Ok(path_id) => path_id,
            Err(error) => {
                let _ = self.router.remove_endpoint(local_cid, &association);
                return Err(error);
            }
        };
        self.push_association_event(AssociationEvent::CircuitOpened {
            association,
            circuit: CircuitId {
                association,
                local_id: local_circuit_id,
            },
        });
        self.submit_node_packet(NodeEgress {
            association,
            bearer: address.bearer,
            peer_l2_address: address.peer_l2_address,
            packet,
        })?;
        let _ = path_id;
        Ok(CircuitId {
            association,
            local_id: local_circuit_id,
        })
    }

    /// Create and register a client association, then serialize its Initial
    /// directly into a lease from the node's packet pool.
    ///
    /// `now` is the caller's monotonic time in the same units later passed to
    /// [`Self::timer_expired`] and [`Self::next_deadline`].
    pub(crate) fn start_association(
        &mut self,
        receive_cid: ConnectionId,
        address: PacketMeta,
        now: u64,
    ) -> Result<NodeEgress<P::Buffer>, QuicNodeEgressError> {
        let limits = self.default_association_limits;
        let mut client = ClientAssociation::boxed_with_runtime_limits(
            receive_cid,
            limits.connection,
            limits.history_packets,
            limits.transmission_records,
        )
        .map_err(QuicNodeEgressError::Transport)?;
        if let Some(token) = self.router.reset_token_for(receive_cid) {
            client.connection_mut().set_local_reset_token(token);
        }
        let packet = Self::build_packet(self.pool, |output| client.start(output))?;
        let association = self.add_client(receive_cid, client)?;
        if let Some(slot) = self.slot_mut(association) {
            if let Some(path) = Self::slot_path_state_mut(slot, 0) {
                path.mark_unvalidated();
            }
        }
        self.remember_address(association, address);
        self.slot_mut(association)
            .expect("new association remains installed")
            .bootstrap = Some(ClientBootstrap {
            next_attempt: 1,
            last_attempt_at: now,
            setup_transaction_id: None,
            setup_relay_count: None,
            setup_request: None,
        });
        Ok(NodeEgress {
            association,
            bearer: address.bearer,
            peer_l2_address: address.peer_l2_address,
            packet,
        })
    }

    /// Admit one client Initial, register its server association by DCID, and
    /// serialize the Initial response into a lease from the node's packet pool.
    ///
    /// The caller supplies the complete opaque QUIC packet. Address metadata
    /// selects only the physical return route; admission and association
    /// selection use the packet and its connection IDs.
    fn accept_initial(
        &mut self,
        address: PacketMeta,
        packet: &[u8],
        server_cid: ConnectionId,
        local_limits: crate::ConnectionLimits,
    ) -> Result<NodeEgress<P::Buffer>, QuicNodeEgressError> {
        let mut server = None;
        let reset_token = self.router.reset_token_for(server_cid);
        let response = Self::build_packet(self.pool, |output| {
            let (accepted, used) = ServerStreamConnection::accept_open_boxed_with_config_into(
                packet,
                server_cid,
                local_limits,
                ServerStreamConfig {
                    history_packets: self.default_association_limits.history_packets,
                    transmission_records: self.default_association_limits.transmission_records,
                    max_pending_streams: self.default_association_limits.max_pending_streams,
                    max_stream_bytes: self.default_association_limits.max_buffered_stream_bytes,
                },
                reset_token,
                output,
            )?;
            server = Some(accepted);
            Ok(used)
        })?;
        let association = self.add_server(
            server_cid,
            server.expect("successful Initial serialization constructs server state"),
        )?;
        self.remember_address(association, address);
        Ok(NodeEgress {
            association,
            bearer: address.bearer,
            peer_l2_address: address.peer_l2_address,
            packet: response,
        })
    }

    #[cfg(test)]
    fn send_message(
        &mut self,
        association: QuicAssociation,
        body: &[u8],
    ) -> Result<NodeEgress<P::Buffer>, QuicNodeEgressError> {
        let stream = self.allocate_stream(association)?;
        self.send_stream(association, stream, 0, true, body)
    }

    /// Open the next locally initiated bidirectional application stream.
    ///
    /// The returned handle owns the stream identifier and ordered byte
    /// position. Applications pass it to [`QuicNode::write_stream`] and
    /// [`QuicNode::finish_stream`], or wrap it in a runtime byte-stream
    /// adapter; stream IDs and offsets remain internal.
    pub fn open_stream(
        &mut self,
        association: QuicAssociation,
    ) -> Result<QuicStream, QuicNodeEgressError> {
        let id = self.allocate_stream(association)?;
        Ok(QuicStream {
            owner: StreamOwner::Association(association),
            id,
            send_offset: 0,
            send_finished: false,
            priority: false,
        })
    }

    /// Submit one ordered stream chunk through the stream's selected bearer.
    ///
    /// This common operation performs no waiting or runtime polling. Success
    /// transfers the packet lease to the bearer and advances the stream. On a
    /// temporary resource error the stream is unchanged, allowing a Tokio or
    /// RTOS adapter to retry the same bytes after a completion/readiness event.
    pub(crate) fn write_stream_packet(
        &mut self,
        stream: &mut QuicStream,
        bytes: &[u8],
        fin: bool,
    ) -> Result<(), QuicNodeEgressError>
    where
        P::Buffer: Send,
    {
        self.drain_bearer_events();
        let association = stream
            .association()
            .ok_or(QuicNodeEgressError::Transport(Error::Invalid))?;
        self.ensure_ready_stream_path(association)?;
        let previous_offset = stream.send_offset;
        let previous_finished = stream.send_finished;
        let packet = self.build_stream_packet(stream, bytes, fin)?;
        match self.submit_node_packet(packet) {
            Ok(()) => Ok(()),
            Err(error) => {
                // Serialization advanced the stream handle, but no packet was
                // accepted or retained by the bearer. Leave the caller's
                // byte range available for a retry after the busy edge clears.
                stream.send_offset = previous_offset;
                stream.send_finished = previous_finished;
                Err(error)
            }
        }
    }

    fn ensure_ready_stream_path(
        &self,
        association: QuicAssociation,
    ) -> Result<(), QuicNodeEgressError> {
        let slot = self
            .slot(association)
            .ok_or(QuicNodeError::MissingAssociation)?;
        let mut saw_address = false;
        let mut saw_registered_bearer = false;
        for path_id in 0..Self::slot_path_count(slot) {
            let Some(path) = Self::slot_path_state(slot, path_id) else {
                continue;
            };
            if !path.is_usable_for_data() || slot.close_code.is_some() {
                continue;
            }
            let Some((bearer_id, _)) = path
                .active_address()
                .or_else(|| (path_id == 0).then_some(slot.bootstrap_address).flatten())
            else {
                continue;
            };
            saw_address = true;
            if let Some(bearer) = self.bearers.get(bearer_id) {
                saw_registered_bearer = true;
                if bearer.can_submit() {
                    return Ok(());
                }
            }
        }
        if !saw_address {
            Err(QuicNodeEgressError::MissingEgressAddress)
        } else if !saw_registered_bearer {
            Err(QuicNodeEgressError::MissingBearer)
        } else {
            Err(QuicNodeEgressError::BearerBusy)
        }
    }

    /// Accept as much of `bytes` as fits one QUIC packet and the peer's
    /// current flow-control window. The returned count advances the stream;
    /// callers retain and retry any suffix. Closing the write half is a
    /// separate [`Self::finish_stream`] operation.
    pub fn write_stream(
        &mut self,
        stream: &mut QuicStream,
        bytes: &[u8],
    ) -> Result<usize, QuicNodeEgressError>
    where
        P::Buffer: Send,
    {
        if bytes.is_empty() {
            return Ok(0);
        }
        self.write_stream_chunk(stream, bytes, false)
    }

    /// Transfer an already pool-backed body packet into reliable stream
    /// retransmission history without copying its bytes into a heap Vec.
    /// The packet must fit one QUIC stream payload and current peer credit; on
    /// a retryable failure, the unchanged packet is returned to the caller.
    /// Once accepted, QUIC owns the source lease until its stream range is
    /// acknowledged or the association is retired.
    pub fn write_stream_owned_packet(
        &mut self,
        stream: &mut QuicStream,
        source: OwnedPacket<crate::ErasedPacketBuffer>,
        fin: bool,
    ) -> Result<usize, (QuicNodeEgressError, OwnedPacket<crate::ErasedPacketBuffer>)>
    where
        P::Buffer: Send,
    {
        if stream.send_finished {
            return Err((QuicNodeEgressError::Transport(Error::Invalid), source));
        }
        let Some(association) = stream.association() else {
            return Err((QuicNodeEgressError::Transport(Error::Invalid), source));
        };
        let length = source.bytes().len();
        if length == 0 || length > crate::DEFAULT_MAX_STREAM_PAYLOAD {
            return Err((QuicNodeEgressError::Transport(Error::Blocked), source));
        }
        let window = match self.stream_send_window(stream) {
            Ok(window) => window,
            Err(error) => return Err((error, source)),
        };
        if window < length as u64 {
            return Err((QuicNodeEgressError::Transport(Error::Blocked), source));
        }
        self.drain_bearer_events();
        let old_offset = stream.send_offset;
        let Some(next_offset) = old_offset.checked_add(length as u64) else {
            return Err((QuicNodeEgressError::Transport(Error::Invalid), source));
        };
        let packet = match self.send_stream_with_owned_packet(
            association,
            stream.id,
            old_offset,
            fin,
            source,
        ) {
            Ok(packet) => packet,
            Err(error) => return Err(error),
        };
        stream.send_offset = next_offset;
        stream.send_finished = fin;
        // After encoding, the source lease is QUIC-owned. Submission failure
        // is recorded in packet history and is repaired by the ordinary loss
        // path; returning the source here would duplicate an already-retained
        // stream range.
        let _ = self.submit_node_packet(packet);
        Ok(length)
    }

    /// Send the largest prefix of non-empty `bytes` that fits one packet and
    /// the send window. FIN is set only when `finish` and the whole slice fit.
    fn write_stream_chunk(
        &mut self,
        stream: &mut QuicStream,
        bytes: &[u8],
        finish: bool,
    ) -> Result<usize, QuicNodeEgressError>
    where
        P::Buffer: Send,
    {
        if stream.send_finished {
            return Err(QuicNodeEgressError::Transport(Error::Invalid));
        }
        let window = self.stream_send_window(stream)?;
        let count = bytes
            .len()
            .min(crate::DEFAULT_MAX_STREAM_PAYLOAD)
            .min(usize::try_from(window).unwrap_or(usize::MAX));
        if count == 0 {
            return Err(QuicNodeEgressError::Transport(Error::Blocked));
        }
        self.write_stream_packet(stream, &bytes[..count], finish && count == bytes.len())?;
        Ok(count)
    }

    /// Accept as much of the final application byte slice as fits one packet
    /// and the peer's current flow-control window. When the complete slice is
    /// accepted, its packet also carries FIN. If only a prefix is accepted,
    /// the stream remains open and the caller retries the unchanged suffix
    /// after progress. An empty slice sends a standalone FIN.
    pub fn write_stream_and_finish(
        &mut self,
        stream: &mut QuicStream,
        bytes: &[u8],
    ) -> Result<usize, QuicNodeEgressError>
    where
        P::Buffer: Send,
    {
        if bytes.is_empty() {
            self.finish_stream(stream)?;
            return Ok(0);
        }
        self.write_stream_chunk(stream, bytes, true)
    }

    /// Close the stream's sending half after all accepted bytes.
    pub fn finish_stream(&mut self, stream: &mut QuicStream) -> Result<(), QuicNodeEgressError>
    where
        P::Buffer: Send,
    {
        if stream.send_finished {
            return Ok(());
        }
        self.write_stream_packet(stream, &[], true)
    }

    /// Peer-advertised byte credit at the stream's current ordered position.
    pub fn stream_send_window(&self, stream: &QuicStream) -> Result<u64, QuicNodeEgressError> {
        let StreamOwner::Association(association) = stream.owner;
        self.stream_flow_control_window(association, stream.id, stream.send_offset)
    }

    /// Write one ordered chunk and return the packet which carries it.
    ///
    /// A successful call advances the stream position. On any error the
    /// stream handle is unchanged, so the same bytes and `fin` value can be
    /// retried after flow-control, packet-pool, or bearer progress. `fin`
    /// closes the sending side after these bytes, like shutting down the
    /// write half of a TCP stream.
    pub(crate) fn build_stream_packet(
        &mut self,
        stream: &mut QuicStream,
        bytes: &[u8],
        fin: bool,
    ) -> Result<NodeEgress<P::Buffer>, QuicNodeEgressError> {
        if stream.send_finished {
            return Err(QuicNodeEgressError::Transport(Error::Invalid));
        }
        let association = stream
            .association()
            .ok_or(QuicNodeEgressError::Transport(Error::Invalid))?;
        let packet = self.send_stream_with_priority(
            association,
            stream.id,
            stream.send_offset,
            fin,
            bytes,
            stream.priority,
        )?;
        stream.send_offset = stream
            .send_offset
            .checked_add(bytes.len() as u64)
            .ok_or(QuicNodeEgressError::Transport(Error::Invalid))?;
        stream.send_finished = fin;
        Ok(packet)
    }

    fn mark_priority_stream_packet(&mut self, association: QuicAssociation, packet_number: u32) {
        let Some(slot) = self.slot_mut(association) else {
            return;
        };
        match &mut slot.state {
            Association::Client(client) => {
                if let Ok(endpoint) = client.connection_mut().endpoint_mut() {
                    endpoint.mark_priority_stream_packet(packet_number);
                }
            }
            Association::Server(server) => server
                .mux
                .endpoint
                .mark_priority_stream_packet(packet_number),
        }
    }

    /// Allocate the next locally initiated bidirectional stream.
    ///
    /// The association owns the stream-number sequence across every bearer.
    /// Allocation does not produce a packet; the caller passes the returned
    /// ID to [`Self::send_stream`] for each ordered range. If a later send is
    /// blocked, the caller retries the same stream ID, offset, FIN, and bytes.
    pub(crate) fn allocate_stream(
        &mut self,
        association: QuicAssociation,
    ) -> Result<u64, QuicNodeEgressError> {
        let slot = self
            .slot_mut(association)
            .ok_or(QuicNodeError::MissingAssociation)?;
        if slot.close_code.is_some() {
            return Err(QuicNodeEgressError::Transport(Error::Invalid));
        }
        match &mut slot.state {
            Association::Client(client) => client
                .open_next_client_bidi_stream()
                .map_err(QuicNodeEgressError::Transport),
            Association::Server(server) => server
                .open_response_stream()
                .map_err(QuicNodeEgressError::Transport),
        }
    }

    /// Peer-advertised byte credit remaining at an ordered stream offset.
    ///
    /// This is the application flow-control window, not a promise that a
    /// packet can be emitted immediately: congestion, retransmission-history
    /// capacity, packet-pool availability, and bearer readiness are separate.
    /// A producer should offer no more than this many new bytes and retry the
    /// unchanged range after association ingress or packet-send completion
    /// signals progress. That event-driven rule maps to a Tokio wakeup on a
    /// host and to a direct callback on firmware without a polling loop here.
    pub(crate) fn stream_flow_control_window(
        &self,
        association: QuicAssociation,
        stream_id: u64,
        offset: u64,
    ) -> Result<u64, QuicNodeEgressError> {
        let slot = self
            .slot(association)
            .ok_or(QuicNodeError::MissingAssociation)?;
        if slot.close_code.is_some() {
            return Err(QuicNodeEgressError::Transport(Error::Invalid));
        }
        match &slot.state {
            Association::Client(client) => client.available_stream_send_bytes(stream_id, offset),
            Association::Server(server) => server.available_stream_send_bytes(stream_id, offset),
        }
        .ok_or(QuicNodeEgressError::Transport(Error::Invalid))
    }

    /// Serialize one complete packet containing one ordered stream range.
    ///
    /// This is the common client/server send path. The caller owns only the
    /// stream byte position and supplies a range which fits one packet;
    /// QUIC-lite owns CIDs, packet numbers, flow credit, congestion, history,
    /// and the current bearer address. Success returns one complete owned
    /// packet. Failure returns no packet, and the caller may retry the exact
    /// `(stream_id, offset, fin, bytes)` range after progress or capacity is
    /// available.
    pub(crate) fn send_stream(
        &mut self,
        association: QuicAssociation,
        stream_id: u64,
        offset: u64,
        fin: bool,
        bytes: &[u8],
    ) -> Result<NodeEgress<P::Buffer>, QuicNodeEgressError> {
        self.send_stream_with_priority(association, stream_id, offset, fin, bytes, false)
    }

    fn send_stream_with_priority(
        &mut self,
        association: QuicAssociation,
        stream_id: u64,
        offset: u64,
        fin: bool,
        bytes: &[u8],
        priority: bool,
    ) -> Result<NodeEgress<P::Buffer>, QuicNodeEgressError> {
        let (candidates, candidate_count, saw_address, saw_ready_bearer) = {
            let slot = self
                .slot(association)
                .ok_or(QuicNodeError::MissingAssociation)?;
            let endpoint = match &slot.state {
                Association::Client(client) => client.connection().endpoint(),
                Association::Server(server) => Some(&server.mux.endpoint),
            }
            .ok_or(QuicNodeEgressError::Transport(Error::Invalid))?;
            let count = endpoint.path_count();
            let rotation = (endpoint.next_packet_number as usize) % count.max(1);
            let mut candidates =
                [(u8::MAX, u8::MAX, u64::MAX, usize::MAX, 0usize); crate::MAX_PATH_STATES];
            let mut candidate_count = 0;
            let mut saw_address = false;
            let mut saw_ready_bearer = false;
            for path_id in 0..count {
                let Some(path) = endpoint.path_state(path_id) else {
                    continue;
                };
                if !path.is_usable_for_data() || slot.close_code.is_some() {
                    continue;
                }
                let Some((bearer, _)) = path
                    .active_address()
                    .or_else(|| (path_id == 0).then_some(slot.bootstrap_address).flatten())
                else {
                    continue;
                };
                saw_address = true;
                let ready = match self.bearers.get(bearer) {
                    Some(bearer) => {
                        if !bearer.can_submit() {
                            continue;
                        }
                        saw_ready_bearer = true;
                        0
                    }
                    None => 1,
                };
                // Congestion does not invalidate an address or make a ready
                // bearer busy. Record both before filtering this candidate,
                // so a full window yields retryable stream backpressure.
                if path.congestion.bytes_in_flight >= path.congestion.congestion_window {
                    continue;
                }
                let key = (
                    ready,
                    u8::from(path.packets_sent != 0),
                    // There is no ranking decision with one circuit. Avoid
                    // RTT/probability divisions whose result cannot affect
                    // the chosen path; retain full scoring for multipath.
                    if count == 1 {
                        0
                    } else {
                        path.measured_send_cost_us()
                    },
                    (path_id + count - rotation) % count.max(1),
                    path_id,
                );
                let mut insert = candidate_count;
                while insert > 0 && key < candidates[insert - 1] {
                    candidates[insert] = candidates[insert - 1];
                    insert -= 1;
                }
                candidates[insert] = key;
                candidate_count += 1;
            }
            (candidates, candidate_count, saw_address, saw_ready_bearer)
        };
        for candidate in candidates.iter().take(candidate_count) {
            let packet_number = self.slot(association).and_then(|slot| match &slot.state {
                Association::Client(client) => client
                    .connection()
                    .endpoint()
                    .map(|endpoint| endpoint.next_packet_number),
                Association::Server(server) => Some(server.mux.endpoint.next_packet_number),
            });
            match self.send_stream_on_path(association, candidate.4, stream_id, offset, fin, bytes)
            {
                Ok(packet) => {
                    if priority {
                        if let Some(packet_number) = packet_number {
                            self.mark_priority_stream_packet(association, packet_number);
                        }
                    }
                    return Ok(packet);
                }
                Err(QuicNodeEgressError::Transport(Error::Blocked)) => {}
                Err(error) => return Err(error),
            }
        }
        if !saw_address {
            return Err(QuicNodeEgressError::MissingEgressAddress);
        }
        if !saw_ready_bearer {
            return Err(QuicNodeEgressError::BearerBusy);
        }
        Err(QuicNodeEgressError::Transport(Error::Blocked))
    }

    fn send_stream_with_owned_packet(
        &mut self,
        association: QuicAssociation,
        stream_id: u64,
        offset: u64,
        fin: bool,
        source: OwnedPacket<crate::ErasedPacketBuffer>,
    ) -> Result<NodeEgress<P::Buffer>, (QuicNodeEgressError, OwnedPacket<crate::ErasedPacketBuffer>)>
    where
        P::Buffer: Send,
    {
        let (candidates, candidate_count, saw_address, saw_ready_bearer) = {
            let Some(slot) = self.slot(association) else {
                return Err((QuicNodeError::MissingAssociation.into(), source));
            };
            let endpoint = match &slot.state {
                Association::Client(client) => client.connection().endpoint(),
                Association::Server(server) => Some(&server.mux.endpoint),
            };
            let Some(endpoint) = endpoint else {
                return Err((QuicNodeEgressError::Transport(Error::Invalid), source));
            };
            let count = endpoint.path_count();
            let rotation = (endpoint.next_packet_number as usize) % count.max(1);
            let mut candidates =
                [(u8::MAX, u8::MAX, u64::MAX, usize::MAX, 0usize); crate::MAX_PATH_STATES];
            let mut candidate_count = 0;
            let mut saw_address = false;
            let mut saw_ready_bearer = false;
            for path_id in 0..count {
                let Some(path) = endpoint.path_state(path_id) else {
                    continue;
                };
                if !path.is_usable_for_data() || slot.close_code.is_some() {
                    continue;
                }
                let Some((bearer, _)) = path
                    .active_address()
                    .or_else(|| (path_id == 0).then_some(slot.bootstrap_address).flatten())
                else {
                    continue;
                };
                saw_address = true;
                let ready = match self.bearers.get(bearer) {
                    Some(bearer) => {
                        if !bearer.can_submit() || bearer.has_pending_submission() {
                            continue;
                        }
                        saw_ready_bearer = true;
                        0
                    }
                    None => 1,
                };
                if path.congestion.bytes_in_flight >= path.congestion.congestion_window {
                    continue;
                }
                let key = (
                    ready,
                    u8::from(path.packets_sent != 0),
                    if count == 1 {
                        0
                    } else {
                        path.measured_send_cost_us()
                    },
                    (path_id + count - rotation) % count.max(1),
                    path_id,
                );
                let mut insert = candidate_count;
                while insert > 0 && key < candidates[insert - 1] {
                    candidates[insert] = candidates[insert - 1];
                    insert -= 1;
                }
                candidates[insert] = key;
                candidate_count += 1;
            }
            (candidates, candidate_count, saw_address, saw_ready_bearer)
        };
        let mut source = source;
        for candidate in candidates.iter().take(candidate_count) {
            match self.send_stream_owned_on_path(
                association,
                candidate.4,
                stream_id,
                offset,
                fin,
                source,
            ) {
                Ok(packet) => return Ok(packet),
                Err((QuicNodeEgressError::Transport(Error::Blocked), returned)) => {
                    source = returned;
                }
                Err((error, returned)) => return Err((error, returned)),
            }
        }
        if !saw_address {
            return Err((QuicNodeEgressError::MissingEgressAddress, source));
        }
        if !saw_ready_bearer {
            return Err((QuicNodeEgressError::BearerBusy, source));
        }
        Err((QuicNodeEgressError::Transport(Error::Blocked), source))
    }

    /// Serialize one stream range on a selected circuit path. The public
    /// circuit scheduler will choose this path; adapters still receive only
    /// a complete packet and its bearer route.
    pub(crate) fn send_stream_on_path(
        &mut self,
        association: QuicAssociation,
        path_id: usize,
        stream_id: u64,
        offset: u64,
        fin: bool,
        bytes: &[u8],
    ) -> Result<NodeEgress<P::Buffer>, QuicNodeEgressError> {
        let pool = self.pool;
        let slot = self
            .slot(association)
            .ok_or(QuicNodeError::MissingAssociation)?;
        let (bearer, peer_l2_address) = Self::slot_path_state(slot, path_id)
            .and_then(crate::PathState::active_address)
            .or_else(|| (path_id == 0).then_some(slot.bootstrap_address).flatten())
            .ok_or(QuicNodeEgressError::MissingEgressAddress)?;
        let slot = self
            .slot_mut(association)
            .ok_or(QuicNodeError::MissingAssociation)?;
        if slot.close_code.is_some()
            || Self::slot_path_state(slot, path_id).is_none_or(|path| !path.is_usable_for_data())
        {
            return Err(QuicNodeEgressError::Transport(Error::Invalid));
        }
        let packet = match &mut slot.state {
            Association::Client(client) => Self::build_packet(pool, |output| {
                client.encode_stream_payload_at_on_path(
                    path_id, stream_id, offset, bytes, fin, output,
                )
            })?,
            Association::Server(server) => Self::build_packet(pool, |output| {
                server.encode_stream_payload_at_on_path(
                    path_id, stream_id, offset, bytes, fin, output,
                )
            })?,
        };
        Ok(NodeEgress {
            association,
            bearer,
            peer_l2_address,
            packet,
        })
    }

    fn send_stream_owned_on_path(
        &mut self,
        association: QuicAssociation,
        path_id: usize,
        stream_id: u64,
        offset: u64,
        fin: bool,
        source: OwnedPacket<crate::ErasedPacketBuffer>,
    ) -> Result<NodeEgress<P::Buffer>, (QuicNodeEgressError, OwnedPacket<crate::ErasedPacketBuffer>)>
    where
        P::Buffer: Send,
    {
        let Some(slot) = self.slot(association) else {
            return Err((QuicNodeError::MissingAssociation.into(), source));
        };
        let Some((bearer, peer_l2_address)) = Self::slot_path_state(slot, path_id)
            .and_then(crate::PathState::active_address)
            .or_else(|| (path_id == 0).then_some(slot.bootstrap_address).flatten())
        else {
            return Err((QuicNodeEgressError::MissingEgressAddress, source));
        };
        if slot.close_code.is_some()
            || Self::slot_path_state(slot, path_id).is_none_or(|path| !path.is_usable_for_data())
        {
            return Err((QuicNodeEgressError::Transport(Error::Invalid), source));
        }
        if !self
            .bearers
            .get(bearer)
            .is_some_and(|bearer| bearer.can_submit() && !bearer.has_pending_submission())
        {
            return Err((QuicNodeEgressError::BearerBusy, source));
        }
        let Some(mut writer) = self.pool.acquire_writer(PACKET_PREFIX_RESERVE, 0) else {
            return Err((QuicNodeEgressError::PoolUnavailable, source));
        };
        let Some(output) = writer
            .payload_mut()
            .get_mut(..PACKET)
            .and_then(|output| output.try_into().ok())
        else {
            return Err((QuicNodeEgressError::InvalidPoolLayout, source));
        };
        let commit_fallback = source.clone_shared();
        let slot = self
            .slot_mut(association)
            .expect("association checked above");
        let encoded = match &mut slot.state {
            Association::Client(client) => client.encode_stream_payload_from_owned_at_on_path(
                path_id, stream_id, offset, fin, source, output,
            ),
            Association::Server(server) => server.encode_stream_payload_from_owned_at_on_path(
                path_id, stream_id, offset, fin, source, output,
            ),
        };
        let used = match encoded {
            Ok(used) => used,
            Err((error, source)) => {
                return Err((QuicNodeEgressError::Transport(error), source));
            }
        };
        let Some(packet) = writer.commit(used) else {
            // The encoder writes at most PACKET bytes into this writer, so a
            // failed commit indicates a pool contract violation after QUIC
            // has already retained the source lease.
            return Err((QuicNodeEgressError::InvalidPoolLayout, commit_fallback));
        };
        Ok(NodeEgress {
            association,
            bearer,
            peer_l2_address,
            packet,
        })
    }

    /// Prepare a budgeted proactive copy of an outstanding stream packet on
    /// another circuit. `None` means the source transmission is no longer
    /// needed or the association has insufficient duplication credit.
    pub(crate) fn duplicate_stream_packet_on_path(
        &mut self,
        association: QuicAssociation,
        packet_number: u32,
        path_id: usize,
    ) -> Result<Option<NodeEgress<P::Buffer>>, QuicNodeEgressError> {
        let pool = self.pool;
        let slot = self
            .slot(association)
            .ok_or(QuicNodeError::MissingAssociation)?;
        let (bearer, peer_l2_address) = Self::slot_path_state(slot, path_id)
            .filter(|path| path.is_usable_for_data())
            .and_then(crate::PathState::active_address)
            .ok_or(QuicNodeEgressError::MissingEgressAddress)?;
        let slot = self
            .slot_mut(association)
            .ok_or(QuicNodeError::MissingAssociation)?;
        if slot.close_code.is_some() {
            return Err(QuicNodeEgressError::Transport(Error::Invalid));
        }
        let packet = match &mut slot.state {
            Association::Client(client) => Self::build_optional_packet(pool, |output| {
                client
                    .connection_mut()
                    .endpoint_mut()?
                    .duplicate_stream_packet_on_path(packet_number, path_id, output)
                    .map(|packet| packet.map(|(used, _)| used))
            })?,
            Association::Server(server) => Self::build_optional_packet(pool, |output| {
                server
                    .mux
                    .endpoint
                    .duplicate_stream_packet_on_path(packet_number, path_id, output)
                    .map(|packet| packet.map(|(used, _)| used))
            })?,
        };
        Ok(packet.map(|packet| NodeEgress {
            association,
            bearer,
            peer_l2_address,
            packet,
        }))
    }

    fn prepare_duplicate_credit_control(
        &mut self,
        candidate: ControlDuplicationCandidate,
        path_id: usize,
    ) -> Result<Option<NodeEgress<P::Buffer>>, QuicNodeEgressError> {
        let association = candidate.acceptance.association;
        let pool = self.pool;
        let slot = self
            .slot(association)
            .ok_or(QuicNodeError::MissingAssociation)?;
        let (bearer, peer_l2_address) = Self::slot_path_state(slot, path_id)
            .filter(|path| path.is_usable_for_data())
            .and_then(crate::PathState::active_address)
            .ok_or(QuicNodeEgressError::MissingEgressAddress)?;
        let slot = self
            .slot_mut(association)
            .ok_or(QuicNodeError::MissingAssociation)?;
        if slot.close_code.is_some() {
            return Err(QuicNodeEgressError::Transport(Error::Invalid));
        }
        let packet = match &mut slot.state {
            Association::Client(client) => Self::build_optional_packet(pool, |output| {
                client
                    .connection_mut()
                    .endpoint_mut()?
                    .duplicate_credit_control_on_path(
                        candidate.acceptance.packet_number,
                        path_id,
                        candidate.include_ack,
                        candidate.include_max_data,
                        candidate.stream_credit_count,
                        candidate.include_max_streams_bidi,
                        output,
                    )
                    .map(|packet| packet.map(|(used, _)| used))
            })?,
            Association::Server(server) => Self::build_optional_packet(pool, |output| {
                server
                    .mux
                    .endpoint
                    .duplicate_credit_control_on_path(
                        candidate.acceptance.packet_number,
                        path_id,
                        candidate.include_ack,
                        candidate.include_max_data,
                        candidate.stream_credit_count,
                        candidate.include_max_streams_bidi,
                        output,
                    )
                    .map(|packet| packet.map(|(used, _)| used))
            })?,
        };
        Ok(packet.map(|packet| NodeEgress {
            association,
            bearer,
            peer_l2_address,
            packet,
        }))
    }

    /// Build at most one ACK or flow-control packet made pending by ingress.
    pub(crate) fn poll_association_control(
        &mut self,
        association: QuicAssociation,
    ) -> Result<Option<NodeEgress<P::Buffer>>, QuicNodeEgressError> {
        let pool = self.pool;
        let status_output = {
            let slot = self
                .slot(association)
                .ok_or(QuicNodeError::MissingAssociation)?;
            let endpoint = match &slot.state {
                Association::Client(client) => client.connection().endpoint().unwrap(),
                Association::Server(server) => &server.mux.endpoint,
            };
            endpoint.pending_path_status(self.clock_us()).and_then(
                |(status_path, key, sequence, status)| {
                    let egress_path = endpoint.status_egress_path()?;
                    let path = endpoint.path_state(egress_path)?;
                    let (bearer, peer_l2_address) = path.active_address().or_else(|| {
                        (egress_path == 0)
                            .then_some(slot.bootstrap_address)
                            .flatten()
                    })?;
                    let destination = endpoint.peer_connection_id_on_path(egress_path)?;
                    Some((
                        status_path,
                        egress_path,
                        key,
                        sequence,
                        status,
                        destination,
                        bearer,
                        peer_l2_address,
                    ))
                },
            )
        };
        if let Some((
            status_path,
            egress_path,
            key,
            sequence,
            status,
            destination,
            bearer,
            peer_l2_address,
        )) = status_output
        {
            let now = self.clock_us();
            let packet = Self::build_packet(pool, |output| {
                let slot = self.slot_mut(association).ok_or(Error::WrongConnectionId)?;
                let endpoint = match &mut slot.state {
                    Association::Client(client) => client.connection_mut().endpoint_mut()?,
                    Association::Server(server) => &mut server.mux.endpoint,
                };
                endpoint.set_time(now);
                endpoint.encode_path_control_packet(
                    egress_path,
                    destination,
                    Frame::PathStatus {
                        key,
                        sequence,
                        status,
                    },
                    output,
                )
            });
            match packet {
                Ok(packet) => {
                    return Ok(Some(NodeEgress {
                        association,
                        bearer,
                        peer_l2_address,
                        packet,
                    }));
                }
                Err(QuicNodeEgressError::Transport(Error::Blocked | Error::HistoryFull)) => {
                    let slot = self
                        .slot_mut(association)
                        .ok_or(QuicNodeError::MissingAssociation)?;
                    let endpoint = match &mut slot.state {
                        Association::Client(client) => client
                            .connection_mut()
                            .endpoint_mut()
                            .map_err(QuicNodeEgressError::Transport)?,
                        Association::Server(server) => &mut server.mux.endpoint,
                    };
                    endpoint.defer_path_status(status_path, egress_path);
                    // Normal ACK/credit output and loss recovery must not be
                    // starved by a congestion-limited path-status record.
                }
                Err(error) => return Err(error),
            }
        }
        let slot = self
            .slot(association)
            .ok_or(QuicNodeError::MissingAssociation)?;
        let path_id = match &slot.state {
            Association::Client(client) => client
                .connection()
                .endpoint()
                .and_then(crate::EndpointState::pending_control_path),
            Association::Server(server) => server.pending_control_path(),
        };
        let Some(path_id) = path_id else {
            return Ok(None);
        };
        let (bearer, peer_l2_address) = Self::slot_path_state(slot, path_id)
            .and_then(crate::PathState::active_address)
            .or_else(|| (path_id == 0).then_some(slot.bootstrap_address).flatten())
            .ok_or(QuicNodeEgressError::MissingEgressAddress)?;
        let slot = self
            .slot_mut(association)
            .ok_or(QuicNodeError::MissingAssociation)?;
        let packet = match &mut slot.state {
            Association::Client(client) => Self::build_optional_packet(pool, |output| {
                client
                    .connection_mut()
                    .poll_transmit_on_path(path_id, output)
            })?,
            Association::Server(server) => Self::build_optional_packet(pool, |output| {
                server.poll_transmit_on_path(path_id, output)
            })?,
        };
        Ok(packet.map(|packet| NodeEgress {
            association,
            bearer,
            peer_l2_address,
            packet,
        }))
    }

    fn prepare_path_probe(
        &mut self,
        association: QuicAssociation,
        path_id: usize,
        now_us: u64,
    ) -> Result<NodeEgress<P::Buffer>, QuicNodeEgressError> {
        let (bearer, peer_l2_address, destination, local_cid, packet_number, probe_interval_us) = {
            let slot = self
                .slot(association)
                .ok_or(QuicNodeError::MissingAssociation)?;
            let path = Self::slot_path_state(slot, path_id)
                .ok_or(QuicNodeEgressError::Transport(Error::PathLimit))?;
            let (bearer, peer_l2_address) = path
                .active_address()
                .ok_or(QuicNodeEgressError::MissingEgressAddress)?;
            let endpoint = match &slot.state {
                Association::Client(client) => client.connection().endpoint().unwrap(),
                Association::Server(server) => &server.mux.endpoint,
            };
            (
                bearer,
                peer_l2_address,
                endpoint
                    .peer_connection_id_on_path(path_id)
                    .ok_or(QuicNodeEgressError::Transport(Error::WrongConnectionId))?,
                endpoint
                    .local_connection_id_on_path(path_id)
                    .ok_or(QuicNodeEgressError::Transport(Error::WrongConnectionId))?,
                endpoint.next_packet_number(),
                slot.limits.path_probe_interval_us,
            )
        };
        let token = self
            .router
            .path_probe_token_for(local_cid, packet_number)
            .ok_or(QuicNodeEgressError::Transport(Error::Invalid))?;
        let packet = Self::build_packet(self.pool, |output| {
            let slot = self.slot_mut(association).ok_or(Error::WrongConnectionId)?;
            let endpoint = match &mut slot.state {
                Association::Client(client) => client.connection_mut().endpoint_mut()?,
                Association::Server(server) => &mut server.mux.endpoint,
            };
            endpoint.begin_path_probe(path_id, token, now_us, probe_interval_us)?;
            endpoint.encode_path_control_packet(
                path_id,
                destination,
                Frame::PathChallenge { token },
                output,
            )
        })?;
        Ok(NodeEgress {
            association,
            bearer,
            peer_l2_address,
            packet,
        })
    }

    /// Emit pending ACK/control before a complete local CLOSE packet.
    ///
    /// This method produces at most one packet. A [`NodeClose::Control`]
    /// result keeps the association installed and must be submitted before
    /// calling again. [`NodeClose::Closed`] carries the final CLOSE and
    /// atomically retires the association's DCID. No bearer-specific state is
    /// inspected or retained by the node.
    pub(crate) fn close_association(
        &mut self,
        association: QuicAssociation,
        code: u64,
    ) -> Result<NodeClose<P::Buffer>, QuicNodeEgressError> {
        let pool = self.pool;
        let (bearer, peer_l2_address) = {
            let slot = self
                .slot_mut(association)
                .ok_or(QuicNodeError::MissingAssociation)?;
            if slot.close_code.is_some_and(|existing| existing != code) {
                return Err(QuicNodeEgressError::Transport(Error::Invalid));
            }
            slot.close_code = Some(code);
            Self::slot_active_address(slot).ok_or(QuicNodeEgressError::MissingEgressAddress)?
        };

        // CLOSE retires the association, so it cannot be regenerated after
        // submission refuses a second lease. Wait before preparing it when
        // this bearer already retains an unsubmitted packet.
        #[cfg(feature = "tokio")]
        if self
            .bearers
            .get_mut(bearer)
            .is_some_and(|bearer| !bearer.can_submit())
        {
            return Err(QuicNodeEgressError::BearerBusy);
        }

        let control = {
            let slot = self
                .slot_mut(association)
                .ok_or(QuicNodeError::MissingAssociation)?;
            match &mut slot.state {
                Association::Client(client) => Self::build_optional_packet(pool, |output| {
                    client.connection_mut().poll_transmit(output)
                })?,
                Association::Server(server) => {
                    Self::build_optional_packet(pool, |output| server.poll_transmit(output))?
                }
            }
        };
        if let Some(packet) = control {
            return Ok(NodeClose::Control(NodeEgress {
                association,
                bearer,
                peer_l2_address,
                packet,
            }));
        }

        let packet = {
            let slot = self
                .slot_mut(association)
                .ok_or(QuicNodeError::MissingAssociation)?;
            match &mut slot.state {
                Association::Client(client) => Self::build_packet(pool, |output| {
                    client.connection_mut().close(code)?;
                    client
                        .connection_mut()
                        .poll_close(output)?
                        .ok_or(Error::Invalid)
                })?,
                Association::Server(server) => Self::build_packet(pool, |output| {
                    server.close(code);
                    server.poll_close(output)?.ok_or(Error::Invalid)
                })?,
            }
        };
        self.remove(association)?;
        Ok(NodeClose::Closed(NodeEgress {
            association,
            bearer,
            peer_l2_address,
            packet,
        }))
    }

    /// Process one expired node deadline and produce at most one Initial
    /// retry, ACK, control packet, retransmission, or bootstrap-timeout event.
    /// Repeated calls are explicit events; this method does not run a timer or
    /// drain loop.
    pub(crate) fn timer_expired(
        &mut self,
        now: u64,
    ) -> Result<Option<NodeTimer<P::Buffer>>, QuicNodeEgressError> {
        self.advance_clock(now);
        // A timer snapshot can predate an ingress turn. Use the same
        // monotonic time for selection, expiry and endpoint processing;
        // otherwise a due pacing/recovery wake can remain perpetually armed.
        let now = self.clock_us;
        self.router.expire_forward_leases(now);
        self.router.expire_setup_transactions(now);
        if let Some((slot_index, _)) = self
            .associations
            .iter()
            .enumerate()
            .filter_map(|(index, slot)| {
                let deadline = slot
                    .as_ref()?
                    .last_activity_us
                    .saturating_add(self.idle_timeout_us);
                (deadline <= now).then_some((index, deadline))
            })
            .min_by_key(|(_, deadline)| *deadline)
        {
            let slot = self.associations[slot_index]
                .as_ref()
                .expect("selected association remains installed");
            let association = QuicAssociation {
                slot: slot_index as u32,
                generation: slot.generation,
            };
            self.remove(association)?;
            self.push_association_event(AssociationEvent::IdleTimeout { association });
            return Ok(Some(NodeTimer::IdleTimedOut { association }));
        }
        let due_relayed_join =
            self.associations
                .iter()
                .enumerate()
                .find_map(|(slot_index, entry)| {
                    let slot = entry.as_ref()?;
                    (0..crate::MAX_PATH_STATES).find_map(|path_id| {
                        slot.relayed_join_requests[path_id].as_ref()?;
                        let retry_at = slot.relayed_join_retry_at_us[path_id]?;
                        let deadline = slot.relayed_join_deadline_us[path_id]?;
                        (retry_at <= now || deadline <= now).then(|| {
                            let association = QuicAssociation {
                                slot: slot_index as u32,
                                generation: slot.generation,
                            };
                            let path = Self::slot_path_state(slot, path_id)?;
                            let address = path.active_address()?;
                            Some((
                                association,
                                path_id,
                                slot.relayed_join_requests[path_id].as_ref()?.clone(),
                                slot.relayed_join_attempts[path_id],
                                deadline,
                                path.local_circuit_id(),
                                slot.receive_cids[path_id]?,
                                address,
                            ))
                        })?
                    })
                });
        if let Some((
            association,
            path_id,
            request,
            attempts,
            deadline,
            local_circuit_id,
            local_cid,
            address,
        )) = due_relayed_join
        {
            if deadline <= now || attempts >= crate::MAX_PATH_JOIN_ATTEMPTS {
                let circuit = CircuitId {
                    association,
                    local_id: local_circuit_id,
                };
                if let Some(slot) = self.slot_mut(association) {
                    Self::remove_slot_path_state(slot, path_id)
                        .map_err(QuicNodeEgressError::Transport)?;
                }
                let _ = self.router.remove_endpoint(local_cid, &association);
                self.push_association_event(AssociationEvent::CircuitStatusChanged {
                    association,
                    circuit,
                    status: CircuitStatus::Failed,
                });
                self.push_association_event(AssociationEvent::CircuitClosed {
                    association,
                    circuit,
                });
                return Ok(Some(NodeTimer::CircuitSetupTimedOut {
                    association,
                    circuit,
                }));
            }
            let packet = Self::build_packet(self.pool, |output| {
                if output.len() < request.len() {
                    return Err(Error::BufferTooSmall);
                }
                output[..request.len()].copy_from_slice(&request);
                Ok(request.len())
            })?;
            if let Some(slot) = self.slot_mut(association) {
                slot.relayed_join_attempts[path_id] = attempts.saturating_add(1);
                slot.relayed_join_retry_at_us[path_id] =
                    Some(now.saturating_add(DEFAULT_INITIAL_PTO_US).min(deadline));
            }
            return Ok(Some(NodeTimer::Egress(NodeEgress {
                association,
                bearer: address.0,
                peer_l2_address: address.1,
                packet,
            })));
        }
        let due_probe = self
            .associations
            .iter()
            .enumerate()
            .filter_map(|(slot_index, slot)| {
                let slot = slot.as_ref()?;
                if slot.bootstrap.is_some() {
                    return None;
                }
                (0..Self::slot_path_count(slot)).find_map(|path_id| {
                    let path = Self::slot_path_state(slot, path_id)?;
                    let endpoint = match &slot.state {
                        Association::Client(client) => client.connection().endpoint().unwrap(),
                        Association::Server(server) => &server.mux.endpoint,
                    };
                    let local_cid = endpoint.local_connection_id_on_path(path_id)?;
                    (path.is_probe_eligible()
                        && self
                            .router
                            .path_probe_token_for(local_cid, endpoint.next_packet_number())
                            .is_some()
                        && path
                            .next_probe_at_us()
                            .is_some_and(|deadline| deadline <= now))
                    .then_some((slot_index, path_id))
                })
            })
            .min_by_key(|(slot_index, path_id)| {
                Self::slot_path_state(
                    self.associations[*slot_index]
                        .as_ref()
                        .expect("selected slot"),
                    *path_id,
                )
                .and_then(crate::PathState::next_probe_at_us)
                .unwrap_or(u64::MAX)
            });
        if let Some((slot_index, path_id)) = due_probe {
            let association = {
                let slot = self.associations[slot_index].as_ref().unwrap();
                QuicAssociation {
                    slot: slot_index as u32,
                    generation: slot.generation,
                }
            };
            let packet = self.prepare_path_probe(association, path_id, now)?;
            return Ok(Some(NodeTimer::Egress(packet)));
        }
        let slot_index = self
            .associations
            .iter()
            .enumerate()
            .filter_map(|(index, slot)| {
                let slot = slot.as_ref()?;
                let deadline = slot.bootstrap.as_ref().map_or_else(
                    || match &slot.state {
                        Association::Client(client) => client.next_bearer_deadline(),
                        Association::Server(server) => server.next_bearer_deadline(),
                    },
                    |bootstrap| {
                        Some(
                            bootstrap
                                .last_attempt_at
                                .saturating_add(DEFAULT_INITIAL_PTO_US),
                        )
                    },
                )?;
                (deadline <= now).then_some((index, deadline))
            })
            .min_by_key(|(_, deadline)| *deadline)
            .map(|(index, _)| index);
        let Some(slot_index) = slot_index else {
            return Ok(None);
        };
        let association = {
            let slot = self.associations[slot_index]
                .as_ref()
                .expect("selected association remains installed");
            QuicAssociation {
                slot: slot_index as u32,
                generation: slot.generation,
            }
        };
        if let Some(bootstrap) = self.associations[slot_index]
            .as_ref()
            .and_then(|slot| slot.bootstrap.as_ref())
            .cloned()
        {
            if bootstrap.next_attempt >= CLIENT_BOOTSTRAP_ATTEMPTS {
                self.remove_client(association)?;
                self.push_association_event(AssociationEvent::SetupTimeout { association });
                return Ok(Some(NodeTimer::BootstrapTimedOut { association }));
            }
            let slot = self.associations[slot_index]
                .as_mut()
                .expect("selected association remains installed");
            let (bearer, peer_l2_address) =
                Self::slot_active_address(slot).ok_or(QuicNodeEgressError::MissingEgressAddress)?;
            let client = match &mut slot.state {
                Association::Client(client) => client,
                Association::Server(_) => unreachable!("only clients bootstrap"),
            };
            let packet = if let Some(request) = bootstrap.setup_request.as_deref() {
                Self::build_packet(self.pool, |output| {
                    if output.len() < request.len() {
                        return Err(Error::BufferTooSmall);
                    }
                    output[..request.len()].copy_from_slice(request);
                    Ok(request.len())
                })?
            } else {
                Self::build_packet(self.pool, |output| {
                    client.encode_open_attempt(bootstrap.next_attempt, output)
                })?
            };
            slot.bootstrap = Some(ClientBootstrap {
                next_attempt: bootstrap.next_attempt.saturating_add(1),
                last_attempt_at: now,
                setup_transaction_id: bootstrap.setup_transaction_id,
                setup_relay_count: bootstrap.setup_relay_count,
                setup_request: bootstrap.setup_request,
            });
            return Ok(Some(NodeTimer::Egress(NodeEgress {
                association,
                bearer,
                peer_l2_address,
                packet,
            })));
        }
        if let Some(packet) = self.poll_association_control(association)? {
            return Ok(Some(NodeTimer::Egress(packet)));
        }
        let slot = self.associations[slot_index]
            .as_mut()
            .expect("selected association remains installed");
        let packet = match &mut slot.state {
            Association::Client(client) => {
                // Select the due association before consuming its pacing
                // wake: that wake must also retry pacing-blocked recovery,
                // not just application writes. Clearing it before selection
                // can postpone recovery until an unrelated future timer.
                Self::build_optional_packet(self.pool, |output| {
                    if let Ok(endpoint) = client.connection_mut().endpoint_mut() {
                        endpoint.on_bearer_timeout();
                    }
                    client.poll_timer(now, output)
                })?
            }
            Association::Server(server) => Self::build_optional_packet(self.pool, |output| {
                server.mux.endpoint.on_bearer_timeout();
                server.poll_timer(now, output)
            })?,
        };
        let Some(packet) = packet else {
            return Ok(None);
        };
        let (header, _) =
            crate::ShortHeader::decode(packet.bytes()).map_err(QuicNodeEgressError::Transport)?;
        let route = {
            let slot = self
                .slot(association)
                .ok_or(QuicNodeError::MissingAssociation)?;
            let endpoint = match &slot.state {
                Association::Client(client) => client.connection().endpoint(),
                Association::Server(server) => Some(&server.mux.endpoint),
            }
            .ok_or(QuicNodeEgressError::Transport(Error::WrongConnectionId))?;
            let path_id = endpoint
                .path_id_for_peer_connection_id(header.dcid)
                .ok_or(QuicNodeEgressError::Transport(Error::WrongConnectionId))?;
            Self::slot_path_state(slot, path_id)
                .and_then(crate::PathState::active_address)
                .or_else(|| (path_id == 0).then_some(slot.bootstrap_address).flatten())
        }
        .ok_or(QuicNodeEgressError::MissingEgressAddress)?;
        Ok(Some(NodeTimer::Egress(NodeEgress {
            association,
            bearer: route.0,
            peer_l2_address: route.1,
            packet,
        })))
    }

    /// Classify and process one complete opaque packet from any bearer.
    ///
    /// Runtime bearer ingress uses this entry point. The bearer does not inspect
    /// QUIC headers or select a follow-up method. `admit_initial` is node policy,
    /// called only after QUIC-lite has validated an Initial; returning `None`
    /// declines admission without changing node state.
    /// `on_stream` receives application bytes in increasing offset order for
    /// each stream. Today QUIC-lite retains ranges received behind a gap and
    /// calls the handler only when the missing prefix arrives. A future
    /// explicitly selected mode may permit out-of-order callbacks; it will not
    /// change this ordered default silently.
    /// Runtime ingress preserves an owned short-header relay lease whenever its
    /// layout and uniqueness permit it. Bootstrap/shared/unsupported layouts
    /// keep the existing serializer path. No companion policy lives here.
    pub(crate) fn receive_owned_packet<Admit, StreamEvent>(
        &mut self,
        meta: PacketMeta,
        mut packet: OwnedPacket<P::Buffer>,
        admit_initial: Admit,
        on_stream: StreamEvent,
    ) -> Result<NodeIngress<P::Buffer, P::Buffer, ForwardNextHop>, RejectedNodePacket<P::Buffer>>
    where
        Admit: FnMut(crate::BootstrapOpen) -> Option<InitialAdmission>,
        StreamEvent:
            FnMut(ApplicationStreamSource, u64, u64, bool, &[u8]) -> Result<usize, crate::Error>,
    {
        self.advance_clock(meta.received_at_us);
        let classified = classify_server_packet(packet.bytes());
        let destination = match classified {
            Ok(ServerPacket::Established { destination }) => destination,
            _ => return self.receive_packet(meta, packet, admit_initial, on_stream),
        };
        let rule = match self.router.target(packet.bytes()) {
            Ok(RouterTarget::Forward(rule)) => *rule,
            Ok(RouterTarget::Endpoint(association)) => {
                let association = *association;
                if let Some(path_id) = self
                    .slot(association)
                    .and_then(|slot| Self::slot_path_id_for_cid(slot, destination))
                {
                    return self.receive_owned_endpoint(
                        association,
                        path_id,
                        meta,
                        packet,
                        admit_initial,
                        on_stream,
                    );
                }
                return self.receive_packet(meta, packet, admit_initial, on_stream);
            }
            _ => return self.receive_packet(meta, packet, admit_initial, on_stream),
        };
        let ForwardDestination::Connection(outbound) = rule.destination else {
            return self.receive_packet(meta, packet, admit_initial, on_stream);
        };
        let info = self
            .bearers
            .get(rule.next_hop.bearer)
            .map(|bearer| bearer.info());
        let prefix_required = info.map_or(PACKET_PREFIX_RESERVE, |info| info.prefix_required);
        let suffix_required = info.map_or(PACKET_SUFFIX_RESERVE, |info| info.suffix_required);
        // Preflight before quota/lease state changes. A shared lease or insufficient
        // framing space falls back without changing bytes, credit or counters.
        if crate::dcid_rewrite_layout(&packet, outbound, prefix_required, PACKET).is_err()
            || packet.suffix_capacity() < suffix_required
            || packet.bytes_mut_unique().is_none()
        {
            return self.receive_packet(meta, packet, admit_initial, on_stream);
        }
        let active = match self
            .router
            .forward_lease_active(packet.bytes(), self.clock_us)
        {
            Ok(active) => active,
            Err(error) => {
                return Err(RejectedNodePacket {
                    reason: QuicNodePacketRejection::Egress(QuicNodeEgressError::Transport(error)),
                    packet,
                });
            }
        };
        if !active {
            return Ok(NodeIngress::Unknown {
                destination,
                packet,
            });
        }
        let control = crate::is_control_only_packet(packet.bytes());
        // No second slot is allocated: equality leaves the configured reserve
        // intact. With reserve zero a full pool can still forward its RX lease.
        if !control && self.pool.available() < self.node_limits.relay_control_packet_reserve {
            return Ok(NodeIngress::Unknown {
                destination,
                packet,
            });
        }
        if !self
            .router
            .consume_forward_quota(destination, control, self.clock_us)
        {
            return Ok(NodeIngress::Unknown {
                destination,
                packet,
            });
        }
        match self
            .router
            .refresh_forward_lease(packet.bytes(), self.clock_us)
        {
            Ok(true) => {}
            Ok(false) => {
                return Ok(NodeIngress::Unknown {
                    destination,
                    packet,
                });
            }
            Err(error) => {
                return Err(RejectedNodePacket {
                    reason: QuicNodePacketRejection::Egress(QuicNodeEgressError::Transport(error)),
                    packet,
                });
            }
        }
        let packet = crate::rewrite_dcid_in_place(packet, outbound, prefix_required, PACKET)
            .map_err(|(error, packet)| RejectedNodePacket {
                reason: QuicNodePacketRejection::Egress(QuicNodeEgressError::Transport(error)),
                packet,
            })?;
        Ok(NodeIngress::Forward {
            next_hop: rule.next_hop,
            packet,
        })
    }

    /// Generic ingress and serializer fallback for packets that cannot reuse a
    /// node-pool lease. Runtime adapters use `receive_owned_packet` instead.
    pub(crate) fn receive_packet<B, Admit, StreamEvent>(
        &mut self,
        meta: PacketMeta,
        packet: OwnedPacket<B>,
        admit_initial: Admit,
        mut on_stream: StreamEvent,
    ) -> Result<NodeIngress<B, P::Buffer, ForwardNextHop>, RejectedNodePacket<B>>
    where
        B: AsRef<[u8]>,
        Admit: FnMut(crate::BootstrapOpen) -> Option<InitialAdmission>,
        StreamEvent:
            FnMut(ApplicationStreamSource, u64, u64, bool, &[u8]) -> Result<usize, crate::Error>,
    {
        // Ordinary endpoint traffic must not pull Initial/PATH_OPEN setup,
        // forwarding, and stateless-reset handling into its instruction cache.
        // Keep classification/association validation identical to the fallback.
        if let Ok(
            ServerPacket::Established { destination } | ServerPacket::BootstrapAck { destination },
        ) = classify_server_packet(packet.bytes())
        {
            if let Ok(RouterTarget::Endpoint(id)) = self.router.target(packet.bytes()) {
                let id = *id;
                if let Some(path_id) = self
                    .slot(id)
                    .and_then(|slot| Self::slot_path_id_for_cid(slot, destination))
                {
                    self.advance_clock(meta.received_at_us);
                    return self.receive_endpoint_packet(id, path_id, meta, packet, &mut on_stream);
                }
            }
        }
        self.receive_packet_slow(meta, packet, admit_initial, on_stream)
    }

    // This path retains the full setup/forward/reset semantics. Mark only the
    // uncommon dispatcher cold, not receive_packet or established delivery.
    #[cold]
    #[inline(never)]
    fn receive_packet_slow<B, Admit, StreamEvent>(
        &mut self,
        meta: PacketMeta,
        packet: OwnedPacket<B>,
        mut admit_initial: Admit,
        mut on_stream: StreamEvent,
    ) -> Result<NodeIngress<B, P::Buffer, ForwardNextHop>, RejectedNodePacket<B>>
    where
        B: AsRef<[u8]>,
        Admit: FnMut(crate::BootstrapOpen) -> Option<InitialAdmission>,
        StreamEvent:
            FnMut(ApplicationStreamSource, u64, u64, bool, &[u8]) -> Result<usize, crate::Error>,
    {
        self.advance_clock(meta.received_at_us);
        let bytes = packet.bytes();
        let classified = match classify_server_packet(bytes) {
            Ok(classified) => classified,
            Err(error) => {
                let associations = &self.associations;
                let id = self
                    .router
                    .opaque_endpoint(|id| {
                        let slot = id.slot as usize;
                        associations
                            .get(slot)
                            .and_then(Option::as_ref)
                            .filter(|entry| entry.generation == id.generation)
                            .is_some_and(|entry| match &entry.state {
                                Association::Client(client) => {
                                    client.is_peer_stateless_reset(bytes)
                                }
                                Association::Server(server) => {
                                    server.is_peer_stateless_reset(bytes)
                                }
                            })
                    })
                    .copied();
                let Some(id) = id else {
                    return Ok(NodeIngress::NonQuic { error, packet });
                };
                // Normal QUIC parsing has already failed and the opaque
                // suffix matched this association's advertised peer token.
                // Retire the association regardless of which bearer carried
                // the reset; bearer state is only path state.
                let _ = self.remove(id);
                self.push_association_event(AssociationEvent::Reset { association: id });
                return Ok(NodeIngress::PeerReset {
                    association: id,
                    packet,
                });
            }
        };

        match classified {
            ServerPacket::PathOpen => {
                let request = match crate::relay::decode_setup_request_packet(bytes) {
                    Ok(request) => request,
                    Err(error) => return Ok(NodeIngress::NonQuic { error, packet }),
                };
                let mut first_block = match request.blocks.get(0).and_then(Result::ok) {
                    Some(block) => block,
                    None => {
                        return Ok(NodeIngress::NonQuic {
                            error: Error::Invalid,
                            packet,
                        });
                    }
                };
                let local_telescoping_endpoint = request.route_mode
                    == crate::RelayRouteMode::Telescoping
                    && request.destination_vip.is_some()
                    && request.destination_vip == self.local_vip;
                if local_telescoping_endpoint {
                    if request.blocks.count() != 2 {
                        return Ok(NodeIngress::NonQuic {
                            error: Error::Invalid,
                            packet,
                        });
                    }
                    first_block = match request
                        .blocks
                        .get(request.blocks.count() - 1)
                        .and_then(Result::ok)
                    {
                        Some(block) if block.kind == crate::relay::SETUP_BLOCK_ENDPOINT => block,
                        _ => {
                            return Ok(NodeIngress::NonQuic {
                                error: Error::Invalid,
                                packet,
                            });
                        }
                    };
                }
                if first_block.kind == crate::relay::SETUP_BLOCK_ENDPOINT {
                    if request.mode == crate::relay::SetupMode::Join {
                        if (request.blocks.count() != 1 && !local_telescoping_endpoint)
                            || first_block.version != 1
                            || first_block.protection != 0
                        {
                            return Ok(NodeIngress::NonQuic {
                                error: Error::Invalid,
                                packet,
                            });
                        }
                        let join =
                            match crate::relay::SetupJoinEndpoint::decode(first_block.payload) {
                                Ok(join) => join,
                                Err(error) => return Ok(NodeIngress::NonQuic { error, packet }),
                            };
                        let previous_hop = ForwardNextHop {
                            bearer: meta.bearer,
                            peer_l2_address: meta.peer_l2_address,
                        };
                        let transaction_id = request.transaction_id;
                        let circuit = request.circuit;
                        let now_us = self.clock_us;
                        let lookup = self.router.begin_setup_transaction(
                            previous_hop,
                            transaction_id,
                            request.request_body(),
                            DEFAULT_SETUP_REPLY_BYTES,
                            now_us,
                            now_us.saturating_add(DEFAULT_SETUP_PENDING_TIMEOUT_US),
                        );
                        match lookup {
                            SetupTransactionLookup::Replay(reply) => {
                                let response = Self::build_packet(self.pool, |output| {
                                    if output.len() < reply.len() {
                                        return Err(Error::BufferTooSmall);
                                    }
                                    output[..reply.len()].copy_from_slice(reply);
                                    Ok(reply.len())
                                })
                                .map_err(|error| RejectedNodePacket {
                                    reason: QuicNodePacketRejection::Egress(error),
                                    packet,
                                })?;
                                return Ok(NodeIngress::SetupReply {
                                    response: NodePacket {
                                        bearer: previous_hop.bearer,
                                        peer_l2_address: previous_hop.peer_l2_address,
                                        packet: response,
                                    },
                                });
                            }
                            SetupTransactionLookup::PendingRetry => {
                                return Ok(NodeIngress::SetupReply {
                                    response: Self::build_setup_rejection(
                                        self.pool,
                                        previous_hop,
                                        transaction_id,
                                        circuit,
                                        2,
                                    )
                                    .map_err(|error| RejectedNodePacket {
                                        reason: QuicNodePacketRejection::Egress(error),
                                        packet,
                                    })?,
                                });
                            }
                            SetupTransactionLookup::Conflict => {
                                return Ok(NodeIngress::SetupReply {
                                    response: Self::build_setup_rejection(
                                        self.pool,
                                        previous_hop,
                                        transaction_id,
                                        circuit,
                                        4,
                                    )
                                    .map_err(|error| RejectedNodePacket {
                                        reason: QuicNodePacketRejection::Egress(error),
                                        packet,
                                    })?,
                                });
                            }
                            SetupTransactionLookup::Expired | SetupTransactionLookup::Full => {
                                return Ok(NodeIngress::SetupReply {
                                    response: Self::build_setup_rejection(
                                        self.pool,
                                        previous_hop,
                                        transaction_id,
                                        circuit,
                                        5,
                                    )
                                    .map_err(|error| RejectedNodePacket {
                                        reason: QuicNodePacketRejection::Egress(error),
                                        packet,
                                    })?,
                                });
                            }
                            SetupTransactionLookup::Invalid => {
                                return Ok(NodeIngress::NonQuic {
                                    error: Error::Invalid,
                                    packet,
                                });
                            }
                            SetupTransactionLookup::New => {}
                        }
                        let association = self
                            .router
                            .endpoint_for_cid(join.join_cid)
                            .copied()
                            .filter(|association| self.slot(*association).is_some());
                        let Some(association) = association else {
                            let response = Self::build_setup_rejection(
                                self.pool,
                                previous_hop,
                                transaction_id,
                                circuit,
                                3,
                            )
                            .map_err(|error| RejectedNodePacket {
                                reason: QuicNodePacketRejection::Egress(error),
                                packet,
                            })?;
                            let _ = self.router.complete_setup_transaction(
                                previous_hop,
                                transaction_id,
                                response.packet.bytes(),
                                now_us,
                            );
                            return Ok(NodeIngress::SetupReply { response });
                        };
                        let (local_role, path_count, highest_sequence, conflicting_key) = {
                            let slot = self.slot(association).unwrap();
                            let local_role = match &slot.state {
                                Association::Client(_) => crate::Role::Client,
                                Association::Server(_) => crate::Role::Server,
                            };
                            let endpoint = match &slot.state {
                                Association::Client(client) => {
                                    client.connection().endpoint().unwrap()
                                }
                                Association::Server(server) => &server.mux.endpoint,
                            };
                            let same_key = endpoint.paths.iter().any(|path| {
                                path.circuit_key()
                                    == Some(crate::CircuitKey {
                                        opener_role: circuit.opener_role,
                                        sequence: circuit.sequence,
                                    })
                            });
                            let role_index =
                                usize::from(circuit.opener_role == crate::Role::Server);
                            (
                                local_role,
                                endpoint.path_count(),
                                slot.highest_remote_circuit_sequence[role_index],
                                same_key,
                            )
                        };
                        if local_role == circuit.opener_role
                            || conflicting_key
                            || circuit.sequence <= highest_sequence
                        {
                            let response = Self::build_setup_rejection(
                                self.pool,
                                previous_hop,
                                transaction_id,
                                circuit,
                                4,
                            )
                            .map_err(|error| RejectedNodePacket {
                                reason: QuicNodePacketRejection::Egress(error),
                                packet,
                            })?;
                            let _ = self.router.complete_setup_transaction(
                                previous_hop,
                                transaction_id,
                                response.packet.bytes(),
                                now_us,
                            );
                            return Ok(NodeIngress::SetupReply { response });
                        }
                        if path_count >= crate::MAX_PATH_STATES {
                            let response = Self::build_setup_rejection(
                                self.pool,
                                previous_hop,
                                transaction_id,
                                circuit,
                                1,
                            )
                            .map_err(|error| RejectedNodePacket {
                                reason: QuicNodePacketRejection::Egress(error),
                                packet,
                            })?;
                            let _ = self.router.complete_setup_transaction(
                                previous_hop,
                                transaction_id,
                                response.packet.bytes(),
                                now_us,
                            );
                            return Ok(NodeIngress::SetupReply { response });
                        }
                        let peer_cid = request
                            .previous_reverse_cid
                            .unwrap_or(join.opener_receive_cid);
                        let local_cid = loop {
                            let cid = match self.allocate_local_cid() {
                                Ok(cid) => cid,
                                Err(_) => {
                                    self.router
                                        .cancel_setup_transaction(previous_hop, transaction_id);
                                    let response = Self::build_setup_rejection(
                                        self.pool,
                                        previous_hop,
                                        transaction_id,
                                        circuit,
                                        1,
                                    )
                                    .map_err(|error| RejectedNodePacket {
                                        reason: QuicNodePacketRejection::Egress(error),
                                        packet,
                                    })?;
                                    return Ok(NodeIngress::SetupReply { response });
                                }
                            };
                            if cid != join.opener_receive_cid && cid != peer_cid {
                                break cid;
                            }
                        };
                        if self
                            .router
                            .register_endpoint(local_cid, association)
                            .is_err()
                        {
                            self.router
                                .cancel_setup_transaction(previous_hop, transaction_id);
                            let response = Self::build_setup_rejection(
                                self.pool,
                                previous_hop,
                                transaction_id,
                                circuit,
                                1,
                            )
                            .map_err(|error| RejectedNodePacket {
                                reason: QuicNodePacketRejection::Egress(error),
                                packet,
                            })?;
                            return Ok(NodeIngress::SetupReply { response });
                        }
                        let local_circuit_id = self.slot(association).unwrap().next_circuit_id;
                        let add_result = (|| {
                            let slot =
                                self.slot_mut(association).ok_or(Error::WrongConnectionId)?;
                            let endpoint = match &mut slot.state {
                                Association::Client(client) => {
                                    client.connection_mut().endpoint_mut()?
                                }
                                Association::Server(server) => &mut server.mux.endpoint,
                            };
                            let path_id = endpoint.add_path_state_with_ids(local_cid, peer_cid)?;
                            let path = endpoint.path_state_mut(path_id).unwrap();
                            path.set_circuit(
                                crate::CircuitKey {
                                    opener_role: circuit.opener_role,
                                    sequence: circuit.sequence,
                                },
                                transaction_id,
                                local_circuit_id,
                            );
                            path.remember_address((meta.bearer, meta.peer_l2_address));
                            path.mark_unvalidated();
                            path.mark_probing();
                            path.schedule_probe(
                                now_us.saturating_add(slot.limits.path_probe_interval_us),
                            );
                            slot.receive_cids[path_id] = Some(local_cid);
                            slot.next_circuit_id = local_circuit_id.saturating_add(1);
                            let role_index =
                                usize::from(circuit.opener_role == crate::Role::Server);
                            slot.highest_remote_circuit_sequence[role_index] = circuit.sequence;
                            Ok::<usize, Error>(path_id)
                        })();
                        let path_id = match add_result {
                            Ok(path_id) => path_id,
                            Err(error) => {
                                let _ = self.router.remove_endpoint(local_cid, &association);
                                self.router
                                    .cancel_setup_transaction(previous_hop, transaction_id);
                                return Ok(NodeIngress::NonQuic { error, packet });
                            }
                        };
                        let reply = SetupReply {
                            transaction_id,
                            circuit,
                            result: SetupResult::Accepted {
                                endpoint_cid: local_cid,
                                lease_us: crate::relay::DEFAULT_SETUP_LEASE_US,
                            },
                            bootstrap_ack: None,
                            relay_cids: crate::relay::SetupRelayCids::empty(),
                        };
                        let response_packet = match Self::build_packet(self.pool, |output| {
                            reply.encode_packet(output)
                        }) {
                            Ok(packet) => packet,
                            Err(error) => {
                                let slot = self.slot_mut(association).unwrap();
                                let endpoint = match &mut slot.state {
                                    Association::Client(client) => {
                                        client.connection_mut().endpoint_mut().ok()
                                    }
                                    Association::Server(server) => Some(&mut server.mux.endpoint),
                                };
                                if let Some(endpoint) = endpoint {
                                    let _ = endpoint.remove_path_state(path_id);
                                }
                                slot.receive_cids[path_id] = None;
                                let _ = self.router.remove_endpoint(local_cid, &association);
                                self.router
                                    .cancel_setup_transaction(previous_hop, transaction_id);
                                return Err(RejectedNodePacket {
                                    reason: QuicNodePacketRejection::Egress(error),
                                    packet,
                                });
                            }
                        };
                        let response = NodePacket {
                            bearer: previous_hop.bearer,
                            peer_l2_address: previous_hop.peer_l2_address,
                            packet: response_packet,
                        };
                        if self
                            .router
                            .complete_setup_transaction(
                                previous_hop,
                                transaction_id,
                                response.packet.bytes(),
                                now_us,
                            )
                            .is_err()
                        {
                            let slot = self.slot_mut(association).unwrap();
                            let endpoint = match &mut slot.state {
                                Association::Client(client) => {
                                    client.connection_mut().endpoint_mut().ok()
                                }
                                Association::Server(server) => Some(&mut server.mux.endpoint),
                            };
                            if let Some(endpoint) = endpoint {
                                let _ = endpoint.remove_path_state(path_id);
                            }
                            slot.receive_cids[path_id] = None;
                            let _ = self.router.remove_endpoint(local_cid, &association);
                            return Ok(NodeIngress::NonQuic {
                                error: Error::Invalid,
                                packet,
                            });
                        }
                        self.push_association_event(AssociationEvent::CircuitOpened {
                            association,
                            circuit: CircuitId {
                                association,
                                local_id: local_circuit_id,
                            },
                        });
                        self.push_association_event(AssociationEvent::CircuitStatusChanged {
                            association,
                            circuit: CircuitId {
                                association,
                                local_id: local_circuit_id,
                            },
                            status: CircuitStatus::Probing,
                        });
                        return Ok(NodeIngress::SetupReply { response });
                    }
                    if (request.blocks.count() != 1 && !local_telescoping_endpoint)
                        || !matches!(first_block.version, 1 | 2)
                        || first_block.protection != 0
                        || request.mode != crate::relay::SetupMode::Create
                    {
                        return Ok(NodeIngress::NonQuic {
                            error: Error::Invalid,
                            packet,
                        });
                    }
                    let previous_hop = ForwardNextHop {
                        bearer: meta.bearer,
                        peer_l2_address: meta.peer_l2_address,
                    };
                    let transaction_id = request.transaction_id;
                    let circuit = request.circuit;
                    let now_us = self.clock_us;
                    let lookup = self.router.begin_setup_transaction(
                        previous_hop,
                        transaction_id,
                        request.request_body(),
                        DEFAULT_SETUP_REPLY_BYTES,
                        now_us,
                        now_us.saturating_add(DEFAULT_SETUP_PENDING_TIMEOUT_US),
                    );
                    match lookup {
                        SetupTransactionLookup::Replay(reply) => {
                            let response = Self::build_packet(self.pool, |output| {
                                if output.len() < reply.len() {
                                    return Err(Error::BufferTooSmall);
                                }
                                output[..reply.len()].copy_from_slice(reply);
                                Ok(reply.len())
                            })
                            .map_err(|error| RejectedNodePacket {
                                reason: QuicNodePacketRejection::Egress(error),
                                packet,
                            })?;
                            return Ok(NodeIngress::SetupReply {
                                response: NodePacket {
                                    bearer: previous_hop.bearer,
                                    peer_l2_address: previous_hop.peer_l2_address,
                                    packet: response,
                                },
                            });
                        }
                        SetupTransactionLookup::PendingRetry => {
                            return Ok(NodeIngress::SetupReply {
                                response: Self::build_setup_rejection(
                                    self.pool,
                                    previous_hop,
                                    transaction_id,
                                    circuit,
                                    2,
                                )
                                .map_err(|error| {
                                    RejectedNodePacket {
                                        reason: QuicNodePacketRejection::Egress(error),
                                        packet,
                                    }
                                })?,
                            });
                        }
                        SetupTransactionLookup::Conflict => {
                            return Ok(NodeIngress::SetupReply {
                                response: Self::build_setup_rejection(
                                    self.pool,
                                    previous_hop,
                                    transaction_id,
                                    circuit,
                                    4,
                                )
                                .map_err(|error| {
                                    RejectedNodePacket {
                                        reason: QuicNodePacketRejection::Egress(error),
                                        packet,
                                    }
                                })?,
                            });
                        }
                        SetupTransactionLookup::Expired | SetupTransactionLookup::Full => {
                            return Ok(NodeIngress::SetupReply {
                                response: Self::build_setup_rejection(
                                    self.pool,
                                    previous_hop,
                                    transaction_id,
                                    circuit,
                                    5,
                                )
                                .map_err(|error| {
                                    RejectedNodePacket {
                                        reason: QuicNodePacketRejection::Egress(error),
                                        packet,
                                    }
                                })?,
                            });
                        }
                        SetupTransactionLookup::Invalid => {
                            return Ok(NodeIngress::NonQuic {
                                error: Error::Invalid,
                                packet,
                            });
                        }
                        SetupTransactionLookup::New => {}
                    }
                    let (endpoint_open, return_hints) =
                        match crate::relay::SetupCreateEndpoint::decode(
                            first_block.payload,
                            first_block.version,
                        ) {
                            Ok(decoded) => decoded,
                            Err(error) => {
                                let response = Self::build_setup_rejection(
                                    self.pool,
                                    previous_hop,
                                    transaction_id,
                                    circuit,
                                    7,
                                )
                                .map_err(|error| {
                                    RejectedNodePacket {
                                        reason: QuicNodePacketRejection::Egress(error),
                                        packet,
                                    }
                                })?;
                                let _ = self.router.complete_setup_transaction(
                                    previous_hop,
                                    transaction_id,
                                    response.packet.bytes(),
                                    now_us,
                                );
                                let _ = error;
                                return Ok(NodeIngress::SetupReply { response });
                            }
                        };
                    let (header, open) =
                        match crate::decode_bootstrap_open_packet_with_limits(endpoint_open) {
                            Ok(decoded) => decoded,
                            Err(error) => {
                                let _ = error;
                                let response = Self::build_setup_rejection(
                                    self.pool,
                                    previous_hop,
                                    transaction_id,
                                    circuit,
                                    7,
                                )
                                .map_err(|error| {
                                    RejectedNodePacket {
                                        reason: QuicNodePacketRejection::Egress(error),
                                        packet,
                                    }
                                })?;
                                let _ = self.router.complete_setup_transaction(
                                    previous_hop,
                                    transaction_id,
                                    response.packet.bytes(),
                                    now_us,
                                );
                                return Ok(NodeIngress::SetupReply { response });
                            }
                        };
                    let _ = header;
                    let Some(admission) = admit_initial(open) else {
                        let response = Self::build_setup_rejection(
                            self.pool,
                            previous_hop,
                            transaction_id,
                            circuit,
                            6,
                        )
                        .map_err(|error| RejectedNodePacket {
                            reason: QuicNodePacketRejection::Egress(error),
                            packet,
                        })?;
                        let reply_bytes = response.packet.bytes();
                        self.router
                            .complete_setup_transaction(
                                previous_hop,
                                transaction_id,
                                reply_bytes,
                                now_us,
                            )
                            .ok();
                        return Ok(NodeIngress::SetupReply { response });
                    };
                    let mut server_cid = match self.allocate_local_cid() {
                        Ok(cid) => cid,
                        Err(error) => {
                            self.router
                                .cancel_setup_transaction(previous_hop, transaction_id);
                            return Err(RejectedNodePacket {
                                reason: QuicNodePacketRejection::Egress(
                                    QuicNodeEgressError::Association(error),
                                ),
                                packet,
                            });
                        }
                    };
                    while server_cid == open.client_receive_cid
                        || request.previous_reverse_cid == Some(server_cid)
                    {
                        server_cid = match self.allocate_local_cid() {
                            Ok(cid) => cid,
                            Err(error) => {
                                self.router
                                    .cancel_setup_transaction(previous_hop, transaction_id);
                                return Err(RejectedNodePacket {
                                    reason: QuicNodePacketRejection::Egress(
                                        QuicNodeEgressError::Association(error),
                                    ),
                                    packet,
                                });
                            }
                        };
                    }
                    let mut relayed_initial = [0u8; crate::DEFAULT_MAX_PACKET_SIZE];
                    let accept_packet = if let Some(reverse_cid) = request.previous_reverse_cid {
                        match crate::rewrite_relay_open(
                            endpoint_open,
                            None,
                            reverse_cid,
                            &mut relayed_initial,
                        ) {
                            Ok(used) => &relayed_initial[..used],
                            Err(error) => {
                                self.router
                                    .cancel_setup_transaction(previous_hop, transaction_id);
                                return Ok(NodeIngress::NonQuic { error, packet });
                            }
                        }
                    } else {
                        endpoint_open
                    };
                    let accepted = match self.accept_initial(
                        meta,
                        accept_packet,
                        server_cid,
                        admission.local_limits,
                    ) {
                        Ok(accepted) => accepted,
                        Err(error) => {
                            self.router
                                .cancel_setup_transaction(previous_hop, transaction_id);
                            return Err(RejectedNodePacket {
                                reason: QuicNodePacketRejection::Egress(error),
                                packet,
                            });
                        }
                    };
                    if let Some(slot) = self.slot_mut(accepted.association) {
                        // The Initial reaching a relayed endpoint carries the
                        // last relay's return alias as its SCID. Retain the
                        // original endpoint CID from the layered setup block
                        // separately so this endpoint can build a return JOIN.
                        slot.peer_join_cid = Some(open.client_receive_cid);
                    }
                    let mut client_ack = [0u8; crate::DEFAULT_MAX_PACKET_SIZE];
                    let client_ack_len = if request.previous_reverse_cid.is_some() {
                        match crate::rewrite_dcid(
                            accepted.packet.bytes(),
                            open.client_receive_cid,
                            &mut client_ack,
                        ) {
                            Ok(used) => used,
                            Err(error) => {
                                let _ = self.remove(accepted.association);
                                self.router
                                    .cancel_setup_transaction(previous_hop, transaction_id);
                                return Ok(NodeIngress::NonQuic { error, packet });
                            }
                        }
                    } else {
                        let bytes = accepted.packet.bytes();
                        client_ack[..bytes.len()].copy_from_slice(bytes);
                        bytes.len()
                    };
                    let bootstrap_ack = match crate::relay::SetupBootstrapAck::from_slice(
                        &client_ack[..client_ack_len],
                    ) {
                        Ok(ack) => ack,
                        Err(error) => {
                            let _ = self.remove(accepted.association);
                            self.router
                                .cancel_setup_transaction(previous_hop, transaction_id);
                            return Ok(NodeIngress::NonQuic { error, packet });
                        }
                    };
                    drop(accepted.packet);
                    let reply = SetupReply {
                        transaction_id,
                        circuit,
                        result: SetupResult::Accepted {
                            endpoint_cid: server_cid,
                            lease_us: crate::relay::DEFAULT_SETUP_LEASE_US,
                        },
                        bootstrap_ack: Some(bootstrap_ack),
                        relay_cids: crate::relay::SetupRelayCids::empty(),
                    };
                    let response =
                        match Self::build_packet(self.pool, |output| reply.encode_packet(output)) {
                            Ok(response) => response,
                            Err(error) => {
                                let _ = self.remove(accepted.association);
                                self.router
                                    .cancel_setup_transaction(previous_hop, transaction_id);
                                return Err(RejectedNodePacket {
                                    reason: QuicNodePacketRejection::Egress(error),
                                    packet,
                                });
                            }
                        };
                    if self
                        .router
                        .complete_setup_transaction(
                            previous_hop,
                            transaction_id,
                            response.bytes(),
                            now_us,
                        )
                        .is_err()
                    {
                        let _ = self.remove(accepted.association);
                        self.router
                            .cancel_setup_transaction(previous_hop, transaction_id);
                        return Err(RejectedNodePacket {
                            reason: QuicNodePacketRejection::Egress(
                                QuicNodeEgressError::Transport(Error::BufferTooSmall),
                            ),
                            packet,
                        });
                    }
                    if !return_hints.is_empty() {
                        self.push_association_event(AssociationEvent::PeerReturnPathHints {
                            association: accepted.association,
                            hints: return_hints,
                        });
                    }
                    return Ok(NodeIngress::SetupAccepted {
                        association: accepted.association,
                        return_hints,
                        response: NodePacket {
                            bearer: previous_hop.bearer,
                            peer_l2_address: previous_hop.peer_l2_address,
                            packet: response,
                        },
                    });
                }
                let instruction = match request.current_hop_instruction() {
                    Ok(instruction) => instruction,
                    Err(error) => return Ok(NodeIngress::NonQuic { error, packet }),
                };
                if request.blocks.count() < 2 {
                    return Ok(NodeIngress::NonQuic {
                        error: Error::Invalid,
                        packet,
                    });
                }
                let endpoint_block = match request
                    .blocks
                    .get(request.blocks.count() - 1)
                    .and_then(Result::ok)
                {
                    Some(block)
                        if block.kind == crate::relay::SETUP_BLOCK_ENDPOINT
                            && matches!(block.version, 1 | 2)
                            && block.protection == 0 =>
                    {
                        block
                    }
                    _ => {
                        return Ok(NodeIngress::NonQuic {
                            error: Error::Invalid,
                            packet,
                        });
                    }
                };
                let opener_receive_cid = match request.mode {
                    crate::relay::SetupMode::Create => {
                        let (initial, _) = match crate::relay::SetupCreateEndpoint::decode(
                            endpoint_block.payload,
                            endpoint_block.version,
                        ) {
                            Ok(decoded) => decoded,
                            Err(error) => return Ok(NodeIngress::NonQuic { error, packet }),
                        };
                        match crate::decode_bootstrap_open_packet_with_limits(initial) {
                            Ok((_, open)) => open.client_receive_cid,
                            Err(error) => return Ok(NodeIngress::NonQuic { error, packet }),
                        }
                    }
                    crate::relay::SetupMode::Join => {
                        if endpoint_block.version != 1 {
                            return Ok(NodeIngress::NonQuic {
                                error: Error::Invalid,
                                packet,
                            });
                        }
                        match crate::relay::SetupJoinEndpoint::decode(endpoint_block.payload) {
                            Ok(join) => join.opener_receive_cid,
                            Err(error) => return Ok(NodeIngress::NonQuic { error, packet }),
                        }
                    }
                };
                let previous_hop = ForwardNextHop {
                    bearer: meta.bearer,
                    peer_l2_address: meta.peer_l2_address,
                };
                let transaction_id = request.transaction_id;
                let circuit = request.circuit;
                let request_body = request.request_body();
                let now_us = self.clock_us;
                let pending_deadline_us = now_us.saturating_add(DEFAULT_SETUP_PENDING_TIMEOUT_US);
                let lookup = self.router.begin_setup_transaction(
                    previous_hop,
                    transaction_id,
                    request_body,
                    DEFAULT_SETUP_REPLY_BYTES,
                    now_us,
                    pending_deadline_us,
                );
                enum PathOpenAction {
                    Forward {
                        downstream: ForwardNextHop,
                        state: crate::relay::SetupRelayState,
                    },
                    Reject(u64),
                }
                let action = match lookup {
                    SetupTransactionLookup::New => {
                        let instruction_address =
                            &instruction.address[..usize::from(instruction.address_len)];
                        let next_hop = match request.route_mode {
                            crate::RelayRouteMode::Layered => {
                                self.path_open_route.and_then(|(kind,key,len,next)|
                                    (kind==instruction.address_kind && &key[..len]==instruction_address).then_some(next))
                                    .or_else(||self.path_open_resolver.as_ref().and_then(|resolver| {
                                        resolver(instruction.address_kind,instruction_address)
                                    }))
                            }
                            crate::RelayRouteMode::VipRouted => {
                                request.destination_vip.and_then(|vip| {
                                    self.vip_path_open_resolver.as_ref().and_then(|resolver| {
                                        resolver(instruction.address_kind, instruction_address, vip)
                                    })
                                })
                            }
                            crate::RelayRouteMode::Telescoping => {
                                request.destination_vip.and_then(|vip| {
                                    self.vip_path_open_resolver.as_ref().and_then(|resolver| {
                                        resolver(instruction.address_kind, instruction_address, vip)
                                    })
                                })
                            }
                        };
                        match next_hop {
                            None => {
                                self.router
                                    .cancel_setup_transaction(previous_hop, transaction_id);
                                PathOpenAction::Reject(3)
                            }
                            Some(next_hop) => {
                                let downstream = ForwardNextHop {
                                    bearer: next_hop.bearer,
                                    peer_l2_address: next_hop.peer_l2_address,
                                };
                                let forward_cid = self.allocate_local_cid().ok();
                                let reverse_cid = self.allocate_local_cid().ok();
                                let (Some(forward_cid), Some(reverse_cid)) =
                                    (forward_cid, reverse_cid)
                                else {
                                    self.router
                                        .cancel_setup_transaction(previous_hop, transaction_id);
                                    return Ok(NodeIngress::SetupReply {
                                        response: Self::build_setup_rejection(
                                            self.pool,
                                            previous_hop,
                                            transaction_id,
                                            circuit,
                                            1,
                                        )
                                        .map_err(|error| RejectedNodePacket {
                                            reason: QuicNodePacketRejection::Egress(error),
                                            packet,
                                        })?,
                                    });
                                };
                                let state = crate::relay::SetupRelayState {
                                    forward_cid,
                                    reverse_cid,
                                    reverse_target: request
                                        .previous_reverse_cid
                                        .unwrap_or(opener_receive_cid),
                                    lease_duration_us: instruction.lease_us,
                                    packet_quota: instruction.packet_quota,
                                };
                                if self
                                    .router
                                    .set_setup_downstream_hop(
                                        previous_hop,
                                        transaction_id,
                                        downstream,
                                    )
                                    .is_err()
                                    || self
                                        .router
                                        .set_setup_relay_state(previous_hop, transaction_id, state)
                                        .is_err()
                                {
                                    self.router
                                        .cancel_setup_transaction(previous_hop, transaction_id);
                                    PathOpenAction::Reject(2)
                                } else {
                                    PathOpenAction::Forward { downstream, state }
                                }
                            }
                        }
                    }
                    SetupTransactionLookup::PendingRetry => match (
                        self.router
                            .setup_downstream_hop(previous_hop, transaction_id),
                        self.router.setup_relay_state(previous_hop, transaction_id),
                    ) {
                        (Some(downstream), Some(state)) => {
                            PathOpenAction::Forward { downstream, state }
                        }
                        _ => PathOpenAction::Reject(2),
                    },
                    SetupTransactionLookup::Replay(reply) => {
                        let response = Self::build_packet(self.pool, |output| {
                            if output.len() < reply.len() {
                                return Err(Error::BufferTooSmall);
                            }
                            output[..reply.len()].copy_from_slice(reply);
                            Ok(reply.len())
                        })
                        .map_err(|error| RejectedNodePacket {
                            reason: QuicNodePacketRejection::Egress(error),
                            packet,
                        })?;
                        return Ok(NodeIngress::SetupReply {
                            response: NodePacket {
                                bearer: previous_hop.bearer,
                                peer_l2_address: previous_hop.peer_l2_address,
                                packet: response,
                            },
                        });
                    }
                    SetupTransactionLookup::Expired => PathOpenAction::Reject(5),
                    SetupTransactionLookup::Conflict => PathOpenAction::Reject(4),
                    SetupTransactionLookup::Full => PathOpenAction::Reject(1),
                    SetupTransactionLookup::Invalid => PathOpenAction::Reject(2),
                };
                let (downstream, state) = match action {
                    PathOpenAction::Forward { downstream, state } => (downstream, state),
                    PathOpenAction::Reject(code) => {
                        let response = Self::build_setup_rejection(
                            self.pool,
                            previous_hop,
                            transaction_id,
                            circuit,
                            code,
                        )
                        .map_err(|error| RejectedNodePacket {
                            reason: QuicNodePacketRejection::Egress(error),
                            packet,
                        })?;
                        return Ok(NodeIngress::SetupReply { response });
                    }
                };
                let forwarded = Self::build_packet(self.pool, |output| {
                    request.encode_packet_after_first_block_with_reverse_cid(
                        Some(state.reverse_cid),
                        output,
                    )
                })
                .map_err(|error| RejectedNodePacket {
                    reason: QuicNodePacketRejection::Egress(error),
                    packet,
                })?;
                Ok(NodeIngress::Forward {
                    next_hop: downstream,
                    packet: forwarded,
                })
            }
            ServerPacket::PathOpenAck => {
                let reply = match crate::relay::decode_setup_reply_packet(bytes) {
                    Ok(reply) => reply,
                    Err(error) => return Ok(NodeIngress::NonQuic { error, packet }),
                };
                let client_setup =
                    self.associations
                        .iter()
                        .enumerate()
                        .find_map(|(index, slot)| {
                            let slot = slot.as_ref()?;
                            let bootstrap = slot.bootstrap.as_ref()?;
                            (bootstrap.setup_transaction_id == Some(reply.transaction_id)
                                && slot.bootstrap_address
                                    == Some((meta.bearer, meta.peer_l2_address)))
                            .then_some(QuicAssociation {
                                slot: index as u32,
                                generation: slot.generation,
                            })
                        });
                if let Some(association) = client_setup {
                    let bootstrap = self
                        .slot(association)
                        .and_then(|slot| slot.bootstrap.as_ref());
                    let expected_relay_count = bootstrap
                        .and_then(|bootstrap| bootstrap.setup_relay_count)
                        .map(usize::from);
                    let telescoping = bootstrap
                        .and_then(|bootstrap| bootstrap.setup_request.as_deref())
                        .and_then(|request| crate::relay::decode_setup_request_packet(request).ok())
                        .is_some_and(|request| {
                            request.route_mode == crate::RelayRouteMode::Telescoping
                        });
                    let relay_count_matches = if telescoping {
                        (1..crate::relay::MAX_SETUP_BLOCKS).contains(&reply.relay_cids.count())
                    } else {
                        expected_relay_count == Some(reply.relay_cids.count())
                    };
                    if reply.circuit
                        != (crate::relay::SetupCircuitKey {
                            opener_role: crate::Role::Client,
                            sequence: 1,
                        })
                        || !relay_count_matches
                    {
                        return Ok(NodeIngress::NonQuic {
                            error: Error::WrongConnectionId,
                            packet,
                        });
                    }
                    let SetupResult::Accepted { endpoint_cid, .. } = reply.result else {
                        let SetupResult::Rejected { code } = reply.result else {
                            unreachable!()
                        };
                        let _ = self.remove_client(association);
                        self.push_association_event(AssociationEvent::SetupRejected {
                            association,
                            circuit: None,
                            association_retired: true,
                            code,
                        });
                        return Ok(NodeIngress::NonQuic {
                            error: Error::Invalid,
                            packet,
                        });
                    };
                    let Some(ack) = reply.bootstrap_ack else {
                        let _ = self.remove_client(association);
                        self.push_association_event(AssociationEvent::SetupRejected {
                            association,
                            circuit: None,
                            association_retired: true,
                            code: 1,
                        });
                        return Ok(NodeIngress::NonQuic {
                            error: Error::Invalid,
                            packet,
                        });
                    };
                    let peer_cid = reply.relay_cids.first().unwrap_or(endpoint_cid);
                    let probe_interval_us = self
                        .slot(association)
                        .map_or(DEFAULT_PATH_PROBE_INTERVAL_US, |slot| {
                            slot.limits.path_probe_interval_us
                        });
                    let probe_deadline = self.clock_us.saturating_add(probe_interval_us);
                    let client = match self.slot_mut(association).map(|slot| &mut slot.state) {
                        Some(Association::Client(client)) => client,
                        _ => {
                            return Ok(NodeIngress::NonQuic {
                                error: Error::WrongConnectionId,
                                packet,
                            });
                        }
                    };
                    if let Err(error) = client.receive_open_ack_packet(meta, ack.as_bytes()) {
                        let _ = self.remove_client(association);
                        self.push_association_event(AssociationEvent::SetupRejected {
                            association,
                            circuit: None,
                            association_retired: true,
                            code: 1,
                        });
                        return Ok(NodeIngress::NonQuic { error, packet });
                    }
                    let slot = self.slot_mut(association).expect("client was admitted");
                    let endpoint = match &mut slot.state {
                        Association::Client(client) => client
                            .connection_mut()
                            .endpoint_mut()
                            .expect("validated OPEN_ACK creates endpoint state"),
                        Association::Server(_) => unreachable!(),
                    };
                    if let Err(error) = endpoint.set_peer_connection_id_on_path(0, peer_cid) {
                        let _ = self.remove_client(association);
                        self.push_association_event(AssociationEvent::SetupRejected {
                            association,
                            circuit: None,
                            association_retired: true,
                            code: 1,
                        });
                        return Ok(NodeIngress::NonQuic { error, packet });
                    }
                    if let Some(path) = endpoint.path_state_mut(0) {
                        path.remember_address((meta.bearer, meta.peer_l2_address));
                        path.mark_validated();
                        path.schedule_probe(probe_deadline);
                    }
                    slot.peer_join_cid = Some(endpoint_cid);
                    slot.bootstrap = None;
                    slot.bootstrap_address = None;
                    return Ok(NodeIngress::Association {
                        association: AssociationIngress::Client(association),
                        packet,
                    });
                }
                let pending_join =
                    self.associations
                        .iter()
                        .enumerate()
                        .find_map(|(index, entry)| {
                            let slot = entry.as_ref()?;
                            let association = QuicAssociation {
                                slot: index as u32,
                                generation: slot.generation,
                            };
                            let endpoint = match &slot.state {
                                Association::Client(client) => client.connection().endpoint()?,
                                Association::Server(server) => &server.mux.endpoint,
                            };
                            slot.relayed_join_requests.iter().enumerate().find_map(
                                |(path_id, request)| {
                                    let request = request.as_ref()?;
                                    let path = endpoint.path_state(path_id)?;
                                    (path.circuit_key()
                                        == Some(crate::CircuitKey {
                                            opener_role: reply.circuit.opener_role,
                                            sequence: reply.circuit.sequence,
                                        })
                                        && path.transaction_id() == Some(reply.transaction_id)
                                        && path
                                            .known_addresses()
                                            .contains(&(meta.bearer, meta.peer_l2_address)))
                                    .then(|| (association, path_id, request.clone()))
                                },
                            )
                        });
                if let Some((association, path_id, request_bytes)) = pending_join {
                    let (expected_relays, telescoping) =
                        crate::relay::decode_setup_request_packet(&request_bytes)
                            .ok()
                            .map(|request| {
                                (
                                    request.blocks.count().saturating_sub(1),
                                    request.route_mode == crate::RelayRouteMode::Telescoping,
                                )
                            })
                            .unwrap_or((0, false));
                    let accepted = matches!(reply.result, SetupResult::Accepted { .. });
                    let local_role = self.slot(association).map(|slot| match &slot.state {
                        Association::Client(_) => crate::Role::Client,
                        Association::Server(_) => crate::Role::Server,
                    });
                    if Some(reply.circuit.opener_role) != local_role
                        || (accepted
                            && if telescoping {
                                !(1..crate::relay::MAX_SETUP_BLOCKS)
                                    .contains(&reply.relay_cids.count())
                            } else {
                                expected_relays != reply.relay_cids.count()
                            })
                    {
                        return Ok(NodeIngress::NonQuic {
                            error: Error::WrongConnectionId,
                            packet,
                        });
                    }
                    let endpoint_cid = match reply.result {
                        SetupResult::Accepted { endpoint_cid, .. }
                            if reply.bootstrap_ack.is_none() =>
                        {
                            endpoint_cid
                        }
                        SetupResult::Accepted { .. } => {
                            return Ok(NodeIngress::NonQuic {
                                error: Error::Invalid,
                                packet,
                            });
                        }
                        SetupResult::Rejected { code } => {
                            let rejected_circuit = self
                                .slot(association)
                                .and_then(|slot| Self::slot_path_state(slot, path_id))
                                .map(|path| CircuitId {
                                    association,
                                    local_id: path.local_circuit_id(),
                                });
                            let local_cid = self
                                .slot(association)
                                .and_then(|slot| slot.receive_cids[path_id]);
                            if let Some(slot) = self.slot_mut(association) {
                                let _ = Self::remove_slot_path_state(slot, path_id);
                            }
                            if let Some(local_cid) = local_cid {
                                let _ = self.router.remove_endpoint(local_cid, &association);
                            }
                            self.push_association_event(AssociationEvent::SetupRejected {
                                association,
                                circuit: rejected_circuit,
                                association_retired: false,
                                code,
                            });
                            return Ok(NodeIngress::NonQuic {
                                error: Error::Invalid,
                                packet,
                            });
                        }
                    };
                    let peer_cid = reply.relay_cids.first().unwrap_or(endpoint_cid);
                    let probe_interval_us = self
                        .slot(association)
                        .map_or(DEFAULT_PATH_PROBE_INTERVAL_US, |slot| {
                            slot.limits.path_probe_interval_us
                        });
                    let probe_deadline = self.clock_us.saturating_add(probe_interval_us);
                    let local_circuit_id = {
                        let Some(slot) = self.slot_mut(association) else {
                            return Ok(NodeIngress::NonQuic {
                                error: Error::WrongConnectionId,
                                packet,
                            });
                        };
                        let endpoint = match &mut slot.state {
                            Association::Client(client) => {
                                match client.connection_mut().endpoint_mut() {
                                    Ok(endpoint) => endpoint,
                                    Err(error) => {
                                        return Err(RejectedNodePacket {
                                            reason: QuicNodePacketRejection::Packet(error),
                                            packet,
                                        });
                                    }
                                }
                            }
                            Association::Server(server) => &mut server.mux.endpoint,
                        };
                        if let Err(error) =
                            endpoint.set_peer_connection_id_on_path(path_id, peer_cid)
                        {
                            return Ok(NodeIngress::NonQuic { error, packet });
                        }
                        let local_circuit_id = endpoint
                            .path_state(path_id)
                            .map_or(0, |path| path.local_circuit_id());
                        if let Some(path) = endpoint.path_state_mut(path_id) {
                            path.remember_address((meta.bearer, meta.peer_l2_address));
                            path.mark_probing();
                            path.schedule_probe(probe_deadline);
                        }
                        slot.relayed_join_requests[path_id] = None;
                        slot.relayed_join_attempts[path_id] = 0;
                        slot.relayed_join_retry_at_us[path_id] = None;
                        slot.relayed_join_deadline_us[path_id] = None;
                        local_circuit_id
                    };
                    self.push_association_event(AssociationEvent::CircuitStatusChanged {
                        association,
                        circuit: CircuitId {
                            association,
                            local_id: local_circuit_id,
                        },
                        status: CircuitStatus::Probing,
                    });
                    return Ok(NodeIngress::Association {
                        association: AssociationIngress::Client(association),
                        packet,
                    });
                }
                let downstream_hop = ForwardNextHop {
                    bearer: meta.bearer,
                    peer_l2_address: meta.peer_l2_address,
                };
                let validated = match self.router.validate_setup_downstream_reply(
                    downstream_hop,
                    reply.transaction_id,
                    reply.circuit,
                    bytes,
                ) {
                    Ok(validated) => validated,
                    Err(_) => {
                        return Ok(NodeIngress::NonQuic {
                            error: Error::WrongConnectionId,
                            packet,
                        });
                    }
                };
                let (previous_hop, mut upstream_reply, relay_state) = match validated {
                    crate::relay::SetupDownstreamReply::Replay {
                        previous_hop,
                        reply,
                    } => {
                        let response = Self::build_packet(self.pool, |output| {
                            if output.len() < reply.len() {
                                return Err(Error::BufferTooSmall);
                            }
                            output[..reply.len()].copy_from_slice(reply);
                            Ok(reply.len())
                        })
                        .map_err(|error| RejectedNodePacket {
                            reason: QuicNodePacketRejection::Egress(error),
                            packet,
                        })?;
                        return Ok(NodeIngress::SetupReply {
                            response: NodePacket {
                                bearer: previous_hop.bearer,
                                peer_l2_address: previous_hop.peer_l2_address,
                                packet: response,
                            },
                        });
                    }
                    crate::relay::SetupDownstreamReply::New {
                        previous_hop,
                        relay_state,
                    } => (previous_hop, reply, relay_state),
                };
                let downstream_next_hop = self
                    .router
                    .setup_downstream_hop(previous_hop, reply.transaction_id)
                    .expect("validated setup transaction retains its downstream hop");
                let mut installed_pair = false;
                if let SetupResult::Accepted {
                    endpoint_cid,
                    lease_us,
                } = upstream_reply.result
                {
                    let downstream_cid = upstream_reply.relay_cids.first().unwrap_or(endpoint_cid);
                    let effective_lease_us = lease_us.min(relay_state.lease_duration_us);
                    upstream_reply.result = SetupResult::Accepted {
                        endpoint_cid,
                        lease_us: effective_lease_us,
                    };
                    if upstream_reply
                        .relay_cids
                        .prepend(relay_state.forward_cid)
                        .is_err()
                    {
                        return Ok(NodeIngress::NonQuic {
                            error: Error::Invalid,
                            packet,
                        });
                    }
                    let lease_expires_at_us = self.clock_us.saturating_add(effective_lease_us);
                    let lease_group_id = relay_state.forward_cid.value();
                    let forward_rule = ForwardRule {
                        next_hop: downstream_next_hop,
                        destination: ForwardDestination::Connection(downstream_cid),
                        lease_duration_us: effective_lease_us,
                        lease_expires_at_us,
                        lease_group_id,
                        packet_quota: relay_state.packet_quota,
                        forwarded_packets: 0,
                        forwarded_control_packets: 0,
                        quota_window_started_us: self.clock_us,
                    };
                    let reverse_rule = ForwardRule {
                        next_hop: previous_hop,
                        destination: ForwardDestination::Connection(relay_state.reverse_target),
                        lease_duration_us: effective_lease_us,
                        lease_expires_at_us,
                        lease_group_id,
                        packet_quota: relay_state.packet_quota,
                        forwarded_packets: 0,
                        forwarded_control_packets: 0,
                        quota_window_started_us: self.clock_us,
                    };
                    if self
                        .register_forward_pair(
                            relay_state.forward_cid,
                            forward_rule,
                            relay_state.reverse_cid,
                            reverse_rule,
                        )
                        .is_err()
                    {
                        upstream_reply.result = SetupResult::Rejected { code: 1 };
                        upstream_reply.bootstrap_ack = None;
                        upstream_reply.relay_cids = crate::relay::SetupRelayCids::empty();
                    } else {
                        installed_pair = true;
                    }
                }
                let mut encoded_reply = [0u8; crate::DEFAULT_MAX_PACKET_SIZE];
                let encoded_reply_len = match upstream_reply.encode_packet(&mut encoded_reply) {
                    Ok(used) => used,
                    Err(error) => {
                        if installed_pair {
                            let _ = self.remove_forward_pair(
                                relay_state.forward_cid,
                                relay_state.reverse_cid,
                            );
                        }
                        return Ok(NodeIngress::NonQuic { error, packet });
                    }
                };
                if self
                    .router
                    .complete_setup_transaction(
                        previous_hop,
                        reply.transaction_id,
                        &encoded_reply[..encoded_reply_len],
                        self.clock_us,
                    )
                    .is_err()
                {
                    if installed_pair {
                        let _ = self
                            .remove_forward_pair(relay_state.forward_cid, relay_state.reverse_cid);
                    }
                    return Ok(NodeIngress::NonQuic {
                        error: Error::Invalid,
                        packet,
                    });
                }
                let response = Self::build_packet(self.pool, |output| {
                    if output.len() < encoded_reply_len {
                        return Err(Error::BufferTooSmall);
                    }
                    output[..encoded_reply_len]
                        .copy_from_slice(&encoded_reply[..encoded_reply_len]);
                    Ok(encoded_reply_len)
                })
                .map_err(|error| RejectedNodePacket {
                    reason: QuicNodePacketRejection::Egress(error),
                    packet,
                })?;
                Ok(NodeIngress::SetupReply {
                    response: NodePacket {
                        bearer: previous_hop.bearer,
                        peer_l2_address: previous_hop.peer_l2_address,
                        packet: response,
                    },
                })
            }
            ServerPacket::Initial(open) => {
                let replay = self
                    .associations
                    .iter()
                    .enumerate()
                    .find_map(|(index, entry)| {
                        let slot = entry.as_ref()?;
                        match &slot.state {
                            Association::Server(server)
                                if server.peer_receive_cid() == open.client_receive_cid =>
                            {
                                Some((
                                    QuicAssociation {
                                        slot: index as u32,
                                        generation: slot.generation,
                                    },
                                    server,
                                ))
                            }
                            _ => None,
                        }
                    });
                if let Some((association, server)) = replay {
                    if !server.accepts_replayed_open(open) {
                        return Err(RejectedNodePacket {
                            reason: QuicNodePacketRejection::Packet(Error::BootstrapInvalid),
                            packet,
                        });
                    }
                    let response = Self::build_packet(self.pool, |output| {
                        server.replay_open_ack_into(bytes, output)
                    })
                    .map_err(|error| RejectedNodePacket {
                        reason: QuicNodePacketRejection::Egress(error),
                        packet,
                    })?;
                    self.remember_address(association, meta);
                    return Ok(NodeIngress::Initial {
                        association,
                        response: NodePacket {
                            bearer: meta.bearer,
                            peer_l2_address: meta.peer_l2_address,
                            packet: response,
                        },
                    });
                }
                let Some(admission) = admit_initial(open) else {
                    return Ok(NodeIngress::InitialDeclined { packet });
                };
                // Allocate only after the validated Initial has passed
                // application admission. The current bootstrap wire contract
                // requires distinct numeric client and server CIDs, so a fresh
                // symmetric peer may require one additional allocation here.
                let mut server_cid = match self.allocate_local_cid() {
                    Ok(cid) => cid,
                    Err(error) => {
                        return Err(RejectedNodePacket {
                            reason: QuicNodePacketRejection::Egress(
                                QuicNodeEgressError::Association(error),
                            ),
                            packet,
                        });
                    }
                };
                if server_cid == open.client_receive_cid {
                    server_cid = match self.allocate_local_cid() {
                        Ok(cid) => cid,
                        Err(error) => {
                            return Err(RejectedNodePacket {
                                reason: QuicNodePacketRejection::Egress(
                                    QuicNodeEgressError::Association(error),
                                ),
                                packet,
                            });
                        }
                    };
                }
                let response =
                    match self.accept_initial(meta, bytes, server_cid, admission.local_limits) {
                        Ok(response) => response,
                        Err(error) => {
                            let reason = QuicNodePacketRejection::Egress(error);
                            return Err(RejectedNodePacket { reason, packet });
                        }
                    };
                Ok(NodeIngress::Initial {
                    association: response.association,
                    response: NodePacket {
                        bearer: response.bearer,
                        peer_l2_address: response.peer_l2_address,
                        packet: response.packet,
                    },
                })
            }
            classified @ (ServerPacket::BootstrapAck { destination }
            | ServerPacket::Established { destination }) => {
                enum Target<N> {
                    Endpoint(QuicAssociation, usize),
                    Forward(ForwardRule<N>),
                    Missing,
                    ExpiredForward,
                }
                let lease_active = match self.router.forward_lease_active(bytes, self.clock_us) {
                    Ok(active) => active,
                    Err(error) => {
                        return Ok(NodeIngress::NonQuic { error, packet });
                    }
                };
                let target = if !lease_active {
                    Target::ExpiredForward
                } else {
                    match self.router.target(bytes) {
                        Ok(RouterTarget::Endpoint(id)) => {
                            let Some(path_id) = self
                                .slot(*id)
                                .and_then(|slot| Self::slot_path_id_for_cid(slot, destination))
                            else {
                                return Ok(NodeIngress::NonQuic {
                                    error: Error::WrongConnectionId,
                                    packet,
                                });
                            };
                            Target::Endpoint(*id, path_id)
                        }
                        Ok(RouterTarget::Forward(rule)) => Target::Forward(*rule),
                        Ok(RouterTarget::Missing) => Target::Missing,
                        Err(error) => return Ok(NodeIngress::NonQuic { error, packet }),
                    }
                };
                match target {
                    Target::Endpoint(id, path_id) => {
                        self.receive_endpoint_packet(id, path_id, meta, packet, &mut on_stream)
                    }
                    Target::Forward(rule) => {
                        let active = match self.router.forward_lease_active(bytes, self.clock_us) {
                            Ok(active) => active,
                            Err(error) => {
                                return Err(RejectedNodePacket {
                                    reason: QuicNodePacketRejection::Egress(
                                        QuicNodeEgressError::Transport(error),
                                    ),
                                    packet,
                                });
                            }
                        };
                        if !active {
                            return Ok(NodeIngress::Unknown {
                                destination,
                                packet,
                            });
                        }
                        let control_packet = crate::is_control_only_packet(bytes);
                        if !control_packet
                            && self.pool.available()
                                <= self.node_limits.relay_control_packet_reserve
                        {
                            return Ok(NodeIngress::Unknown {
                                destination,
                                packet,
                            });
                        }
                        let forwarded =
                            Self::build_packet(self.pool, |output| match rule.destination {
                                ForwardDestination::Connection(dcid) => {
                                    crate::rewrite_dcid(bytes, dcid, output)
                                }
                                ForwardDestination::Bootstrap => {
                                    crate::rewrite_bootstrap_destination(bytes, output)
                                }
                            });
                        let forwarded = match forwarded {
                            Ok(forwarded) => forwarded,
                            Err(error) => {
                                return Err(RejectedNodePacket {
                                    reason: QuicNodePacketRejection::Egress(error),
                                    packet,
                                });
                            }
                        };
                        if !self.router.consume_forward_quota(
                            destination,
                            control_packet,
                            self.clock_us,
                        ) {
                            drop(forwarded);
                            return Ok(NodeIngress::Unknown {
                                destination,
                                packet,
                            });
                        }
                        if matches!(classified, ServerPacket::Established { .. }) {
                            let renewed = self.router.refresh_forward_lease(bytes, self.clock_us);
                            let renewed = match renewed {
                                Ok(renewed) => renewed,
                                Err(error) => {
                                    drop(forwarded);
                                    return Err(RejectedNodePacket {
                                        reason: QuicNodePacketRejection::Egress(
                                            QuicNodeEgressError::Transport(error),
                                        ),
                                        packet,
                                    });
                                }
                            };
                            if !renewed {
                                drop(forwarded);
                                return Ok(NodeIngress::Unknown {
                                    destination,
                                    packet,
                                });
                            }
                        }
                        Ok(NodeIngress::Forward {
                            next_hop: rule.next_hop,
                            packet: forwarded,
                        })
                    }
                    Target::Missing => {
                        if matches!(classified, ServerPacket::Established { .. }) {
                            let response = match Self::build_optional_packet(self.pool, |output| {
                                self.router.encode_stateless_reset(bytes, output)
                            }) {
                                Ok(response) => response,
                                Err(error) => {
                                    return Err(RejectedNodePacket {
                                        reason: QuicNodePacketRejection::Egress(error),
                                        packet,
                                    });
                                }
                            };
                            if let Some(response) = response {
                                return Ok(NodeIngress::StatelessReset {
                                    response: NodePacket {
                                        bearer: meta.bearer,
                                        peer_l2_address: meta.peer_l2_address,
                                        packet: response,
                                    },
                                });
                            }
                        }
                        Ok(NodeIngress::Unknown {
                            destination,
                            packet,
                        })
                    }
                    Target::ExpiredForward => Ok(NodeIngress::Unknown {
                        destination,
                        packet,
                    }),
                }
            }
        }
    }

    // Both the opaque owned path and serializer fallback use the same
    // endpoint semantics. Routing has already selected this association/path.
    #[inline(never)]
    pub(super) fn receive_endpoint_packet<B, StreamEvent>(
        &mut self,
        id: QuicAssociation,
        path_id: usize,
        meta: PacketMeta,
        packet: OwnedPacket<B>,
        on_stream: &mut StreamEvent,
    ) -> Result<NodeIngress<B, P::Buffer, ForwardNextHop>, RejectedNodePacket<B>>
    where
        B: AsRef<[u8]>,
        StreamEvent: FnMut(ApplicationStreamSource, u64, u64, bool, &[u8]) -> Result<usize, Error>,
    {
        let bytes = packet.bytes();
        match self.receive_path_control(id, path_id, meta, bytes) {
            Ok(Some(Some(response))) => Ok(NodeIngress::PathControl {
                association: id,
                response,
            }),
            Ok(Some(None)) => Ok(NodeIngress::Association {
                association: self
                    .association_ingress(id)
                    .expect("path control keeps its association installed"),
                packet,
            }),
            // Local suspension/probing and peer standby only
            // affect the corresponding transmit direction. A
            // circuit remains a valid receive path until it
            // is abandoned.
            Ok(None)
                if self
                    .slot(id)
                    .and_then(|slot| Self::slot_path_state(slot, path_id))
                    .is_some_and(crate::PathState::is_closed)
                    && !crate::is_control_only_packet(bytes) =>
            {
                Ok(NodeIngress::NonQuic {
                    error: Error::Invalid,
                    packet,
                })
            }
            Ok(None) => match self.receive_association_bytes(id, path_id, meta, bytes, on_stream) {
                Ok(association) => Ok(NodeIngress::Association {
                    association,
                    packet,
                }),
                Err(QuicNodePacketRejection::Packet(Error::PeerRestarted)) => {
                    let _ = self.remove(id);
                    self.push_association_event(AssociationEvent::Reset { association: id });
                    Ok(NodeIngress::PeerReset {
                        association: id,
                        packet,
                    })
                }
                Err(QuicNodePacketRejection::PeerClosed(code)) => {
                    self.push_association_event(AssociationEvent::Closed {
                        association: id,
                        code,
                    });
                    Ok(NodeIngress::PeerClosed {
                        association: id,
                        code,
                        packet,
                    })
                }
                Err(reason) => Err(RejectedNodePacket { reason, packet }),
            },
            Err(reason) => Err(RejectedNodePacket { reason, packet }),
        }
    }

    fn receive_path_control(
        &mut self,
        association: QuicAssociation,
        ingress_path: usize,
        meta: PacketMeta,
        input: &[u8],
    ) -> Result<Option<Option<NodeEgress<P::Buffer>>>, QuicNodePacketRejection> {
        let Some(control) =
            crate::decode_path_control_packet(input).map_err(QuicNodePacketRejection::Packet)?
        else {
            return Ok(None);
        };
        self.apply_received_path_control(association, ingress_path, meta, input, control)
    }

    #[cold]
    #[inline(never)]
    fn apply_received_path_control(
        &mut self,
        association: QuicAssociation,
        ingress_path: usize,
        meta: PacketMeta,
        input: &[u8],
        control: crate::Frame<'_>,
    ) -> Result<Option<Option<NodeEgress<P::Buffer>>>, QuicNodePacketRejection> {
        let local_role = match &self
            .slot(association)
            .ok_or(QuicNodePacketRejection::Packet(Error::WrongConnectionId))?
            .state
        {
            Association::Client(_) => crate::Role::Client,
            Association::Server(_) => crate::Role::Server,
        };
        {
            let slot = self
                .slot_mut(association)
                .ok_or(QuicNodePacketRejection::Packet(Error::WrongConnectionId))?;
            let endpoint = match &mut slot.state {
                Association::Client(client) => client
                    .connection_mut()
                    .endpoint_mut()
                    .map_err(QuicNodePacketRejection::Packet)?,
                Association::Server(server) => &mut server.mux.endpoint,
            };
            let previous = endpoint
                .path_state(ingress_path)
                .and_then(crate::PathState::largest_received_packet);
            endpoint
                .receive_packet_batch_on_path(input, ingress_path)
                .map_err(QuicNodePacketRejection::Packet)?;
            let current = endpoint
                .path_state(ingress_path)
                .and_then(crate::PathState::largest_received_packet);
            if current.is_some_and(|number| previous.is_none_or(|old| number > old)) {
                endpoint.record_bearer_arrival(ingress_path, meta.received_at_us);
            }
        }
        let probe_interval_us = self
            .slot(association)
            .map_or(DEFAULT_PATH_PROBE_INTERVAL_US, |slot| {
                slot.limits.path_probe_interval_us
            });
        let probe_deadline_us = self.clock_us().saturating_add(probe_interval_us);

        match control {
            Frame::PathJoin {
                join_cid,
                key,
                transaction_id,
                receive_cid,
            } => {
                if key.opener_role == local_role || ingress_path != 0 {
                    return Err(QuicNodePacketRejection::Packet(Error::Invalid));
                }
                let (existing_path, conflicting_key, highest_sequence) = {
                    let slot = self.slot(association).unwrap();
                    let endpoint = match &slot.state {
                        Association::Client(client) => client.connection().endpoint().unwrap(),
                        Association::Server(server) => &server.mux.endpoint,
                    };
                    if endpoint.local_connection_id_on_path(0) != Some(join_cid) {
                        return Err(QuicNodePacketRejection::Packet(Error::WrongConnectionId));
                    }
                    let existing = endpoint.paths.iter().position(|path| {
                        path.circuit_key() == Some(key)
                            && path.transaction_id() == Some(transaction_id)
                    });
                    let conflict = endpoint
                        .paths
                        .iter()
                        .any(|path| path.circuit_key() == Some(key) && existing.is_none());
                    let role_index = usize::from(key.opener_role == crate::Role::Server);
                    (
                        existing,
                        conflict,
                        slot.highest_remote_circuit_sequence[role_index],
                    )
                };
                if conflicting_key || (existing_path.is_none() && key.sequence <= highest_sequence)
                {
                    return Err(QuicNodePacketRejection::Packet(Error::BootstrapInvalid));
                }
                let path_id = if let Some(path_id) = existing_path {
                    let slot = self.slot(association).unwrap();
                    let endpoint = match &slot.state {
                        Association::Client(client) => client.connection().endpoint().unwrap(),
                        Association::Server(server) => &server.mux.endpoint,
                    };
                    let path = endpoint.path_state(path_id).unwrap();
                    if endpoint.peer_connection_id_on_path(path_id) != Some(receive_cid)
                        || !path
                            .known_addresses()
                            .contains(&(meta.bearer, meta.peer_l2_address))
                    {
                        return Err(QuicNodePacketRejection::Packet(Error::BootstrapInvalid));
                    }
                    path_id
                } else {
                    if self
                        .slot(association)
                        .unwrap()
                        .receive_cids
                        .iter()
                        .flatten()
                        .any(|cid| *cid == receive_cid)
                    {
                        return Err(QuicNodePacketRejection::Packet(Error::WrongConnectionId));
                    }
                    let local_cid = loop {
                        let candidate = self
                            .allocate_local_cid()
                            .map_err(|_| QuicNodePacketRejection::Packet(Error::HistoryFull))?;
                        if candidate != receive_cid {
                            break candidate;
                        }
                    };
                    self.router
                        .register_endpoint(local_cid, association)
                        .map_err(|_| QuicNodePacketRejection::Packet(Error::PathLimit))?;
                    let add_result = (|| {
                        let slot = self.slot_mut(association).unwrap();
                        let local_circuit_id = slot.next_circuit_id;
                        if local_circuit_id == u64::MAX {
                            return Err(QuicNodePacketRejection::Packet(
                                Error::PacketNumberExhausted,
                            ));
                        }
                        let endpoint =
                            match &mut slot.state {
                                Association::Client(client) => client
                                    .connection_mut()
                                    .endpoint_mut()
                                    .map_err(QuicNodePacketRejection::Packet)?,
                                Association::Server(server) => &mut server.mux.endpoint,
                            };
                        let path_id = endpoint
                            .add_path_state_with_ids(local_cid, receive_cid)
                            .map_err(QuicNodePacketRejection::Packet)?;
                        let path = endpoint.path_state_mut(path_id).unwrap();
                        path.set_circuit(key, transaction_id, local_circuit_id);
                        path.remember_address((meta.bearer, meta.peer_l2_address));
                        path.schedule_probe(probe_deadline_us);
                        slot.receive_cids[path_id] = Some(local_cid);
                        slot.next_circuit_id = local_circuit_id + 1;
                        let role_index = usize::from(key.opener_role == crate::Role::Server);
                        slot.highest_remote_circuit_sequence[role_index] = key.sequence;
                        Ok::<usize, QuicNodePacketRejection>(path_id)
                    })();
                    match add_result {
                        Ok(path_id) => path_id,
                        Err(error) => {
                            let _ = self.router.remove_endpoint(local_cid, &association);
                            return Err(error);
                        }
                    }
                };
                if existing_path.is_none() {
                    if let Some(path) = self
                        .slot(association)
                        .and_then(|slot| Self::slot_path_state(slot, path_id))
                    {
                        self.push_association_event(AssociationEvent::CircuitOpened {
                            association,
                            circuit: CircuitId {
                                association,
                                local_id: path.local_circuit_id(),
                            },
                        });
                    }
                }
                let local_receive_cid = {
                    let slot = self.slot(association).unwrap();
                    let endpoint = match &slot.state {
                        Association::Client(client) => client.connection().endpoint().unwrap(),
                        Association::Server(server) => &server.mux.endpoint,
                    };
                    endpoint
                        .local_connection_id_on_path(path_id)
                        .ok_or(QuicNodePacketRejection::Packet(Error::WrongConnectionId))?
                };
                let pool = self.pool;
                let packet = Self::build_packet(pool, |output| {
                    let slot = self.slot_mut(association).ok_or(Error::WrongConnectionId)?;
                    let endpoint = match &mut slot.state {
                        Association::Client(client) => client.connection_mut().endpoint_mut()?,
                        Association::Server(server) => &mut server.mux.endpoint,
                    };
                    endpoint.encode_path_control_packet(
                        path_id,
                        receive_cid,
                        Frame::PathJoinAck {
                            key,
                            transaction_id,
                            receive_cid: local_receive_cid,
                        },
                        output,
                    )
                })
                .map_err(QuicNodePacketRejection::Egress)?;
                Ok(Some(Some(NodeEgress {
                    association,
                    bearer: meta.bearer,
                    peer_l2_address: meta.peer_l2_address,
                    packet,
                })))
            }
            Frame::PathJoinAck {
                key,
                transaction_id,
                receive_cid,
            } => {
                if key.opener_role != local_role || ingress_path == 0 {
                    return Err(QuicNodePacketRejection::Packet(Error::Invalid));
                }
                let (was_opening, local_circuit_id) = {
                    let slot = self
                        .slot_mut(association)
                        .ok_or(QuicNodePacketRejection::Packet(Error::WrongConnectionId))?;
                    let endpoint = match &mut slot.state {
                        Association::Client(client) => client
                            .connection_mut()
                            .endpoint_mut()
                            .map_err(QuicNodePacketRejection::Packet)?,
                        Association::Server(server) => &mut server.mux.endpoint,
                    };
                    let path = endpoint
                        .path_state(ingress_path)
                        .ok_or(QuicNodePacketRejection::Packet(Error::PathLimit))?;
                    if path.circuit_key() != Some(key)
                        || path.transaction_id() != Some(transaction_id)
                    {
                        return Err(QuicNodePacketRejection::Packet(Error::BootstrapInvalid));
                    }
                    let was_opening = !path.is_validated();
                    let local_circuit_id = path.local_circuit_id();
                    endpoint
                        .set_peer_connection_id_on_path(ingress_path, receive_cid)
                        .map_err(QuicNodePacketRejection::Packet)?;
                    let path = endpoint.path_state_mut(ingress_path).unwrap();
                    path.remember_address((meta.bearer, meta.peer_l2_address));
                    path.mark_validated();
                    path.schedule_probe(probe_deadline_us);
                    endpoint.request_path_validation_ack(ingress_path);
                    (was_opening, local_circuit_id)
                };
                if was_opening {
                    self.push_association_event(AssociationEvent::CircuitStatusChanged {
                        association,
                        circuit: CircuitId {
                            association,
                            local_id: local_circuit_id,
                        },
                        status: CircuitStatus::Active,
                    });
                }
                Ok(Some(None))
            }
            Frame::PathChallenge { token } => {
                let now_us = self.clock_us().max(meta.received_at_us);
                let probe_interval_us = self
                    .slot(association)
                    .map_or(DEFAULT_PATH_PROBE_INTERVAL_US, |slot| {
                        slot.limits.path_probe_interval_us
                    });
                let destination = {
                    let slot = self.slot(association).unwrap();
                    let endpoint = match &slot.state {
                        Association::Client(client) => client.connection().endpoint().unwrap(),
                        Association::Server(server) => &server.mux.endpoint,
                    };
                    let path = endpoint
                        .path_state(ingress_path)
                        .ok_or(QuicNodePacketRejection::Packet(Error::PathLimit))?;
                    if !path.is_probe_eligible() {
                        return Err(QuicNodePacketRejection::Packet(Error::Invalid));
                    }
                    if !path.can_respond_to_peer_probe(token, now_us, probe_interval_us) {
                        return Ok(Some(None));
                    }
                    endpoint
                        .peer_connection_id_on_path(ingress_path)
                        .ok_or(QuicNodePacketRejection::Packet(Error::WrongConnectionId))?
                };
                let pool = self.pool;
                let packet = Self::build_packet(pool, |output| {
                    let slot = self.slot_mut(association).ok_or(Error::WrongConnectionId)?;
                    let endpoint = match &mut slot.state {
                        Association::Client(client) => client.connection_mut().endpoint_mut()?,
                        Association::Server(server) => &mut server.mux.endpoint,
                    };
                    endpoint.encode_path_control_packet(
                        ingress_path,
                        destination,
                        Frame::PathResponse { token },
                        output,
                    )
                })
                .map_err(QuicNodePacketRejection::Egress)?;
                let slot = self
                    .slot_mut(association)
                    .ok_or(QuicNodePacketRejection::Packet(Error::WrongConnectionId))?;
                let endpoint = match &mut slot.state {
                    Association::Client(client) => client
                        .connection_mut()
                        .endpoint_mut()
                        .map_err(QuicNodePacketRejection::Packet)?,
                    Association::Server(server) => &mut server.mux.endpoint,
                };
                let path = endpoint
                    .path_state_mut(ingress_path)
                    .ok_or(QuicNodePacketRejection::Packet(Error::PathLimit))?;
                if !path.can_respond_to_peer_probe(token, now_us, probe_interval_us) {
                    return Ok(Some(None));
                }
                path.record_peer_probe_response(token, now_us);
                Ok(Some(Some(NodeEgress {
                    association,
                    bearer: meta.bearer,
                    peer_l2_address: meta.peer_l2_address,
                    packet,
                })))
            }
            Frame::PathResponse { token } => {
                let now = self.clock_us().max(meta.received_at_us);
                let slot = self
                    .slot_mut(association)
                    .ok_or(QuicNodePacketRejection::Packet(Error::WrongConnectionId))?;
                let endpoint = match &mut slot.state {
                    Association::Client(client) => client
                        .connection_mut()
                        .endpoint_mut()
                        .map_err(QuicNodePacketRejection::Packet)?,
                    Association::Server(server) => &mut server.mux.endpoint,
                };
                let resumed = endpoint.path_state_mut(ingress_path).and_then(|path| {
                    let was_probing =
                        path.circuit_status() == CircuitStatus::Probing || path.is_suspended();
                    path.complete_probe(token, now)
                        .map(|_| {
                            if was_probing {
                                path.mark_validated();
                                Some(path.local_circuit_id())
                            } else {
                                None
                            }
                        })
                        .flatten()
                });
                if let Some(local_id) = resumed {
                    let slot = self.slot_mut(association).unwrap();
                    let endpoint = match &mut slot.state {
                        Association::Client(client) => {
                            client.connection_mut().endpoint_mut().unwrap()
                        }
                        Association::Server(server) => &mut server.mux.endpoint,
                    };
                    let _ =
                        endpoint.queue_path_status(ingress_path, crate::PathStatusKind::Available);
                    self.push_association_event(AssociationEvent::CircuitStatusChanged {
                        association,
                        circuit: CircuitId {
                            association,
                            local_id,
                        },
                        status: CircuitStatus::Active,
                    });
                }
                Ok(Some(None))
            }
            Frame::PathStatus {
                key,
                sequence,
                status,
            } => {
                let (local_id, path_status) = {
                    let slot = self
                        .slot_mut(association)
                        .ok_or(QuicNodePacketRejection::Packet(Error::WrongConnectionId))?;
                    let endpoint = match &mut slot.state {
                        Association::Client(client) => client
                            .connection_mut()
                            .endpoint_mut()
                            .map_err(QuicNodePacketRejection::Packet)?,
                        Association::Server(server) => &mut server.mux.endpoint,
                    };
                    let (path_id, changed) = endpoint
                        .receive_path_status(key, sequence, status)
                        .ok_or(QuicNodePacketRejection::Packet(Error::WrongConnectionId))?;
                    endpoint.request_path_validation_ack(ingress_path);
                    let path = endpoint.path_state(path_id).unwrap();
                    (
                        path.local_circuit_id(),
                        changed.then(|| path.circuit_status()),
                    )
                };
                if let Some(status) = path_status {
                    self.push_association_event(AssociationEvent::CircuitStatusChanged {
                        association,
                        circuit: CircuitId {
                            association,
                            local_id,
                        },
                        status,
                    });
                }
                let pool = self.pool;
                let response = Self::build_optional_packet(pool, |output| {
                    let slot = self.slot_mut(association).ok_or(Error::WrongConnectionId)?;
                    match &mut slot.state {
                        Association::Client(client) => client
                            .connection_mut()
                            .poll_transmit_on_path(ingress_path, output),
                        Association::Server(server) => {
                            server.poll_transmit_on_path(ingress_path, output)
                        }
                    }
                })
                .map_err(QuicNodePacketRejection::Egress)?;
                Ok(response
                    .map(|packet| {
                        Some(NodeEgress {
                            association,
                            bearer: meta.bearer,
                            peer_l2_address: meta.peer_l2_address,
                            packet,
                        })
                    })
                    .or(Some(None)))
            }
            _ => unreachable!("path-control decoder returned a non-path frame"),
        }
    }

    fn receive_association_bytes<StreamEvent>(
        &mut self,
        id: QuicAssociation,
        ingress_path: usize,
        meta: PacketMeta,
        bytes: &[u8],
        on_stream: &mut StreamEvent,
    ) -> Result<AssociationIngress, QuicNodePacketRejection>
    where
        StreamEvent:
            FnMut(ApplicationStreamSource, u64, u64, bool, &[u8]) -> Result<usize, crate::Error>,
    {
        let previous_path_largest = self.slot(id).and_then(|slot| match &slot.state {
            Association::Client(client) => client
                .connection()
                .endpoint()
                .and_then(|endpoint| endpoint.path_state(ingress_path))
                .and_then(crate::PathState::largest_received_packet),
            Association::Server(server) => server
                .mux
                .endpoint
                .path_state(ingress_path)
                .and_then(crate::PathState::largest_received_packet),
        });
        let ingress = {
            let slot = self
                .slot_mut(id)
                .ok_or(QuicNodePacketRejection::Packet(Error::WrongConnectionId))?;
            match &mut slot.state {
                Association::Client(client) => {
                    if !client.connection().is_established() {
                        if crate::decode_bootstrap_open_ack_packet_with_limits(
                            bytes,
                            client.connection().local_cid(),
                        )
                        .is_ok()
                        {
                            client
                                .receive_open_ack_packet(meta, bytes)
                                .map_err(QuicNodePacketRejection::Packet)?;
                        } else {
                            client
                                .receive_initial_short_header_packet(meta, bytes)
                                .map_err(QuicNodePacketRejection::Packet)?;
                        }
                        slot.bootstrap = None;
                    }
                    if client.is_duplicate_open_ack(bytes) {
                        client
                            .receive_packet(meta, bytes, |_| Ok(()))
                            .map_err(QuicNodePacketRejection::Packet)?;
                    } else {
                        let admitted = client
                            .receive_packet_on_path(
                                meta,
                                bytes,
                                ingress_path,
                                |connection, path_id| {
                                    connection
                                        .endpoint_mut()?
                                        .receive_packet_before_stream_delivery(bytes, path_id)
                                },
                            )
                            .map_err(QuicNodePacketRejection::Packet)?;
                        for payload in admitted.streams() {
                            if !slot.client_delivery.delivery_finished(payload.id) {
                                let mut sink = OrderedNodeSink {
                                    association: id,
                                    handler: on_stream,
                                    consumed: 0,
                                };
                                let delivery = slot.client_delivery.try_receive_copying_borrowed(
                                    payload.id,
                                    payload.data,
                                    payload.offset,
                                    payload.fin,
                                    || crate::mux::retain_stream_bytes(payload.data),
                                    &mut sink,
                                );
                                if sink.consumed != 0 {
                                    client
                                        .connection_mut()
                                        .endpoint_mut()
                                        .and_then(|endpoint| {
                                            endpoint.stream_consumed_before_packet_ack(
                                                payload.id,
                                                sink.consumed,
                                            )
                                        })
                                        .map_err(QuicNodePacketRejection::Packet)?;
                                }
                                match delivery {
                                    Ok(()) => {}
                                    Err(crate::callback::CopyingError::Transport(
                                        crate::callback::CallbackError::Capacity,
                                    )) => {
                                        return Ok(AssociationIngress::Client(id));
                                    }
                                    Err(crate::callback::CopyingError::Transport(_)) => {
                                        return Err(QuicNodePacketRejection::Packet(
                                            Error::Invalid,
                                        ));
                                    }
                                    Err(crate::callback::CopyingError::Callback(error)) => {
                                        return Err(QuicNodePacketRejection::Application(error));
                                    }
                                }
                            }
                        }
                        let endpoint = client
                            .connection_mut()
                            .endpoint_mut()
                            .map_err(QuicNodePacketRejection::Packet)?;
                        if !admitted.duplicate && admitted.stream_count != 0 {
                            endpoint.commit_stream_packet_receive(
                                admitted.header.packet_number,
                                ingress_path,
                            );
                            if admitted.streams().any(|frame| frame.fin) {
                                endpoint.request_stream_reack();
                            }
                        }
                    }
                    AssociationIngress::Client(id)
                }
                Association::Server(server) => {
                    let mut received_streams = SmallVec::<[u64; 4]>::new();
                    server
                        .receive_stream_events_on_path(
                            bytes,
                            ingress_path,
                            |stream_id, offset, fin, data| {
                                if !received_streams.contains(&stream_id) {
                                    received_streams.push(stream_id);
                                }
                                on_stream(
                                    ApplicationStreamSource::Association(id),
                                    stream_id,
                                    offset,
                                    fin,
                                    data,
                                )
                            },
                        )
                        .map_err(|error| match error {
                            crate::mux::StreamDeliveryError::Packet(error) => {
                                QuicNodePacketRejection::Packet(error)
                            }
                            crate::mux::StreamDeliveryError::Application(error) => {
                                QuicNodePacketRejection::Application(error)
                            }
                        })?;
                    for stream_id in received_streams {
                        server
                            .prepare_peer_bidi_response(stream_id)
                            .map_err(QuicNodePacketRejection::Packet)?;
                    }
                    AssociationIngress::Server(id)
                }
            }
        };
        let peer_close_code = self.slot(id).and_then(|slot| match &slot.state {
            Association::Client(client) => client
                .connection()
                .endpoint()
                .and_then(crate::EndpointState::close_code),
            Association::Server(server) => server.close_code(),
        });
        if let Some(code) = peer_close_code {
            let _ = self.remove(id);
            return Err(QuicNodePacketRejection::PeerClosed(code));
        }
        let primary_opened = self.slot_mut(id).and_then(|slot| {
            let established = matches!(
                &slot.state,
                Association::Client(client) if client.connection().is_established()
            );
            if !established {
                return None;
            }
            let path = Self::slot_path_state_mut(slot, 0)?;
            if path.is_validated() {
                return None;
            }
            let local_id = path.local_circuit_id();
            path.mark_validated();
            Some(local_id)
        });
        if let Some(local_id) = primary_opened {
            self.push_association_event(AssociationEvent::CircuitStatusChanged {
                association: id,
                circuit: CircuitId {
                    association: id,
                    local_id,
                },
                status: CircuitStatus::Active,
            });
        }
        if ingress_path != 0 {
            let opened = self.slot_mut(id).and_then(|slot| {
                let path = Self::slot_path_state_mut(slot, ingress_path)?;
                if path.circuit_key().is_none() || path.circuit_status() != CircuitStatus::Opening {
                    return None;
                }
                let local_id = path.local_circuit_id();
                path.mark_validated();
                Some(local_id)
            });
            if let Some(local_id) = opened {
                self.push_association_event(AssociationEvent::CircuitStatusChanged {
                    association: id,
                    circuit: CircuitId {
                        association: id,
                        local_id,
                    },
                    status: CircuitStatus::Active,
                });
            }
        }
        let current_path_largest = self.slot(id).and_then(|slot| match &slot.state {
            Association::Client(client) => client
                .connection()
                .endpoint()
                .and_then(|endpoint| endpoint.path_state(ingress_path))
                .and_then(crate::PathState::largest_received_packet),
            Association::Server(server) => server
                .mux
                .endpoint
                .path_state(ingress_path)
                .and_then(crate::PathState::largest_received_packet),
        });
        let new_largest = current_path_largest
            .is_some_and(|current| previous_path_largest.is_none_or(|previous| current > previous));
        if new_largest {
            let slot = self.slot_mut(id).unwrap();
            let endpoint = match &mut slot.state {
                Association::Client(client) => client
                    .connection_mut()
                    .endpoint_mut()
                    .map_err(QuicNodePacketRejection::Packet)?,
                Association::Server(server) => &mut server.mux.endpoint,
            };
            endpoint.record_bearer_arrival(ingress_path, meta.received_at_us);
        }
        self.remember_ingress_path_address(id, ingress_path, meta, new_largest);
        Ok(ingress)
    }

    /// Resume ordered bytes retained after an application accepted only a
    /// prefix. This is runtime plumbing: it uses the same stream callback and
    /// receive-credit accounting as packet ingress without owning a transport.
    pub(crate) fn resume_stream_delivery<StreamEvent>(
        &mut self,
        association: QuicAssociation,
        stream_id: u64,
        on_stream: &mut StreamEvent,
    ) -> Result<usize, QuicNodePacketRejection>
    where
        StreamEvent:
            FnMut(ApplicationStreamSource, u64, u64, bool, &[u8]) -> Result<usize, crate::Error>,
    {
        let slot = self
            .slot_mut(association)
            .ok_or(QuicNodePacketRejection::Packet(Error::WrongConnectionId))?;
        match &mut slot.state {
            Association::Client(client) => {
                let mut sink = OrderedNodeSink {
                    association,
                    handler: on_stream,
                    consumed: 0,
                };
                slot.client_delivery
                    .resume_copying(stream_id, &mut sink)
                    .map_err(|error| match error {
                        crate::callback::CopyingError::Transport(_) => {
                            QuicNodePacketRejection::Packet(Error::Invalid)
                        }
                        crate::callback::CopyingError::Callback(error) => {
                            QuicNodePacketRejection::Application(error)
                        }
                    })?;
                if sink.consumed != 0 {
                    client
                        .stream_consumed(stream_id, sink.consumed, true)
                        .map_err(QuicNodePacketRejection::Packet)?;
                }
                Ok(sink.consumed)
            }
            Association::Server(server) => server
                .resume_stream_events(stream_id, |stream, offset, fin, bytes| {
                    on_stream(
                        ApplicationStreamSource::Association(association),
                        stream,
                        offset,
                        fin,
                        bytes,
                    )
                })
                .map_err(|error| match error {
                    crate::mux::StreamDeliveryError::Packet(error) => {
                        QuicNodePacketRejection::Packet(error)
                    }
                    crate::mux::StreamDeliveryError::Application(error) => {
                        QuicNodePacketRejection::Application(error)
                    }
                }),
        }
    }

    /// Earliest Initial retry, ACK, loss, or PTO deadline across the node.
    /// The platform arms its native timer for this value and does not maintain
    /// a second per-transport retry schedule.
    pub(crate) fn next_deadline(&self) -> Option<u64> {
        let association_deadline = self
            .associations
            .iter()
            .flatten()
            .filter_map(|slot| {
                let idle = slot.last_activity_us.saturating_add(self.idle_timeout_us);
                let transport = match slot.bootstrap.as_ref() {
                    Some(bootstrap) => Some(
                        bootstrap
                            .last_attempt_at
                            .saturating_add(DEFAULT_INITIAL_PTO_US),
                    ),
                    None => match &slot.state {
                        Association::Client(client) => client.next_bearer_deadline(),
                        Association::Server(server) => server.next_bearer_deadline(),
                    },
                };
                let probe = if slot.bootstrap.is_none() {
                    (0..Self::slot_path_count(slot))
                        .filter_map(|path_id| {
                            let path = Self::slot_path_state(slot, path_id)?;
                            if !path.is_probe_eligible() {
                                return None;
                            }
                            let endpoint = match &slot.state {
                                Association::Client(client) => {
                                    client.connection().endpoint().unwrap()
                                }
                                Association::Server(server) => &server.mux.endpoint,
                            };
                            let local_cid = endpoint.local_connection_id_on_path(path_id)?;
                            self.router
                                .path_probe_token_for(local_cid, endpoint.next_packet_number())?;
                            path.next_probe_at_us()
                        })
                        .min()
                } else {
                    None
                };
                let setup = (0..crate::MAX_PATH_STATES)
                    .filter(|path_id| slot.relayed_join_requests[*path_id].is_some())
                    .flat_map(|path_id| {
                        [
                            slot.relayed_join_retry_at_us[path_id],
                            slot.relayed_join_deadline_us[path_id],
                        ]
                    })
                    .flatten()
                    .min();
                Some(
                    transport
                        .into_iter()
                        .chain(probe)
                        .chain(setup)
                        .fold(idle, u64::min),
                )
            })
            .min();
        association_deadline
            .into_iter()
            .chain(self.router.next_forward_lease_deadline())
            .chain(self.router.next_setup_deadline())
            .min()
    }
}

#[cfg(test)]
#[path = "forwarding_sim.rs"]
mod forwarding_sim;

#[cfg(test)]
#[path = "datagram_sim.rs"]
mod datagram_sim;

#[cfg(test)]
mod tests {
    #![deny(deprecated)]

    use super::*;
    use crate::{ConnectionId, ConnectionLimits, FLAG_FIXED, ShortHeader};

    type TestPool = crate::packet_pool::PacketPool<1, DEFAULT_PACKET_POOL_SLOT_SIZE>;
    static TEST_POOL: TestPool = TestPool::new();

    fn cid(value: u64) -> ConnectionId {
        ConnectionId::new(value).unwrap()
    }

    #[test]
    fn boxed_associations_keep_their_allocation_across_insert_remove_and_reinsert() {
        let mut node = QuicNode::<TestPool>::new(&TEST_POOL);
        let client =
            ClientAssociation::boxed_with_runtime_limits(cid(1), ConnectionLimits::default(), 2, 4)
                .unwrap();
        let address = &*client as *const _;
        let first = node.add_client(cid(1), client).unwrap();
        let client = node.remove_client(first).unwrap();
        assert_eq!(&*client as *const _, address);
        let second = node.add_client(cid(1), client).unwrap();
        assert_ne!(first, second);
        assert_eq!(&*node.remove_client(second).unwrap() as *const _, address);

        let mut input = [0; crate::DEFAULT_MAX_PACKET_SIZE];
        let n = crate::encode_bootstrap_open_packet(cid(2), 0, &mut input).unwrap();
        let mut output = [0; crate::DEFAULT_MAX_PACKET_SIZE];
        let (server, _) = ServerStreamConnection::accept_open_boxed_with_config_into(
            &input[..n],
            cid(3),
            ConnectionLimits::default(),
            ServerStreamConfig::default(),
            None,
            &mut output,
        )
        .unwrap();
        let address = &*server as *const _;
        let first = node.add_server(cid(3), server).unwrap();
        let server = node.remove_server(first).unwrap();
        assert_eq!(&*server as *const _, address);
        let second = node.add_server(cid(3), server).unwrap();
        assert_ne!(first, second);
        assert_eq!(&*node.remove_server(second).unwrap() as *const _, address);
    }

    #[test]
    fn unspecified_bearer_arrival_uses_dispatch_time_for_ack_delay() {
        type Pool = crate::packet_pool::PacketPool<4, DEFAULT_PACKET_POOL_SLOT_SIZE>;
        static POOL: Pool = Pool::new();
        let mut node = QuicNode::<Pool>::new(&POOL);
        let mut bytes = [0u8; crate::DEFAULT_MAX_PACKET_SIZE];
        let len = crate::encode_bootstrap_open_packet(cid(0x91), 0, &mut bytes).unwrap();
        let initial = node
            .accept_initial(
                ingress_meta(),
                &bytes[..len],
                cid(0x92),
                ConnectionLimits::default(),
            )
            .unwrap();
        let association = initial.association;
        drop(initial);
        let mut len = ShortHeader {
            flags: FLAG_FIXED,
            dcid: cid(0x92),
            packet_number: 1,
            packet_number_len: 4,
        }
        .encode(&mut bytes)
        .unwrap();
        len += Frame::Stream(crate::StreamFrame {
            id: 4,
            offset: 0,
            fin: false,
            data: b"body",
        })
        .encode(&mut bytes[len..])
        .unwrap();
        node.advance_clock(1_000_000);
        let mut meta = ingress_meta();
        meta.received_at_us = 0; // Attached host bearers have no owner-clock epoch.
        node.receive_packet(
            meta,
            OwnedPacket::new(bytes, 0..len).unwrap(),
            |_| None,
            |_, _, _, _, data| Ok(data.len()),
        )
        .unwrap();
        node.advance_clock(1_000_500);
        let Association::Server(server) = &mut node.slot_mut(association).unwrap().state else {
            panic!("server association");
        };
        server.mux.endpoint.paths[0].ack_immediate = true;
        let mut ack = [0u8; crate::DEFAULT_MAX_PACKET_SIZE];
        let used = server
            .mux
            .endpoint
            .poll_transmit(&mut ack)
            .unwrap()
            .unwrap();
        let (_, offset) = ShortHeader::decode(&ack[..used]).unwrap();
        let (frame, _) = crate::decode_frame(&ack[offset..used]).unwrap();
        assert!(
            matches!(
                frame,
                Frame::AckRanges { delay: 500, .. } | Frame::Ack { delay: 500, .. }
            ),
            "unknown arrival must not be interpreted as the clock epoch: {frame:?}"
        );
    }

    #[test]
    fn queued_receive_preserves_arrival_time_for_ack_delay() {
        type Pool = crate::packet_pool::PacketPool<4, DEFAULT_PACKET_POOL_SLOT_SIZE>;
        static POOL: Pool = Pool::new();
        let mut node = QuicNode::<Pool>::new(&POOL);
        let mut bytes = [0u8; crate::DEFAULT_MAX_PACKET_SIZE];
        let len = crate::encode_bootstrap_open_packet(cid(0x91), 0, &mut bytes).unwrap();
        let initial = node
            .accept_initial(
                ingress_meta(),
                &bytes[..len],
                cid(0x92),
                ConnectionLimits::default(),
            )
            .unwrap();
        let association = initial.association;
        drop(initial);
        let mut len = ShortHeader {
            flags: FLAG_FIXED,
            dcid: cid(0x92),
            packet_number: 1,
            packet_number_len: 4,
        }
        .encode(&mut bytes)
        .unwrap();
        len += Frame::Stream(crate::StreamFrame {
            id: 4,
            offset: 0,
            fin: false,
            data: b"body",
        })
        .encode(&mut bytes[len..])
        .unwrap();
        // Physical arrival precedes the owner turn. Advancing the send/timer
        // clock must not replace the timestamp used to report ACK delay.
        node.advance_clock(10_000);
        let mut meta = ingress_meta();
        meta.received_at_us = 1_000;
        node.receive_packet(
            meta,
            OwnedPacket::new(bytes, 0..len).unwrap(),
            |_| None,
            |_, _, _, _, data| Ok(data.len()),
        )
        .unwrap();
        let Association::Server(server) = &mut node.slot_mut(association).unwrap().state else {
            panic!("server association");
        };
        assert_eq!(
            server.mux.endpoint.paths[0].largest_received_at, 1_000,
            "ACK timestamp must reflect bearer arrival, not queued dispatch"
        );
        assert_eq!(server.mux.endpoint.paths[0].send_clock, 10_000);
        // Correct ACK-delay reporting without also changing the coalescing
        // timer policy; those are independent pieces of state.
        assert_eq!(server.mux.endpoint.paths[0].ack_started_at, 10_000);
        server.mux.endpoint.paths[0].ack_immediate = true;
        let mut ack = [0u8; crate::DEFAULT_MAX_PACKET_SIZE];
        let used = server
            .mux
            .endpoint
            .poll_transmit(&mut ack)
            .unwrap()
            .unwrap();
        let (_, offset) = ShortHeader::decode(&ack[..used]).unwrap();
        let (frame, _) = crate::decode_frame(&ack[offset..used]).unwrap();
        assert!(
            matches!(
                frame,
                Frame::AckRanges { delay: 9_000, .. } | Frame::Ack { delay: 9_000, .. }
            ),
            "encoded ACK must include the receive queue delay: {frame:?}"
        );
        // Replayed packets must not replace the largest packet's arrival.
        node.advance_clock(20_000);
        meta.received_at_us = 12_000;
        node.receive_packet(
            meta,
            OwnedPacket::new(bytes, 0..len).unwrap(),
            |_| None,
            |_, _, _, _, data| Ok(data.len()),
        )
        .unwrap();
        let Association::Server(server) = &node.slot(association).unwrap().state else {
            panic!("server association");
        };
        assert_eq!(server.mux.endpoint.paths[0].largest_received_at, 1_000);
    }

    #[test]
    fn single_path_control_does_not_prepare_an_impossible_alternate_copy() {
        type Pool = crate::packet_pool::PacketPool<2, DEFAULT_PACKET_POOL_SLOT_SIZE>;
        static POOL: Pool = Pool::new();
        let mut node = QuicNode::<Pool>::new(&POOL);
        let mut bytes = [0; crate::DEFAULT_MAX_PACKET_SIZE];
        let len = crate::encode_bootstrap_open_packet(cid(0x91), 0, &mut bytes).unwrap();
        let initial = node
            .accept_initial(
                ingress_meta(),
                &bytes[..len],
                cid(0x92),
                ConnectionLimits::default(),
            )
            .unwrap();
        let acceptance = PacketAcceptance {
            association: initial.association,
            packet_number: 20,
        };
        let mut used = ShortHeader {
            flags: FLAG_FIXED,
            dcid: cid(0x91),
            packet_number: 20,
            packet_number_len: 4,
        }
        .encode(&mut bytes)
        .unwrap();
        used += Frame::Ack {
            largest: 1,
            delay: 0,
        }
        .encode(&mut bytes[used..])
        .unwrap();
        used += Frame::MaxData(4096).encode(&mut bytes[used..]).unwrap();
        assert!(
            node.control_duplication_candidate(acceptance, &bytes[..used])
                .is_none()
        );
        let Association::Server(server) = &mut node.slot_mut(initial.association).unwrap().state
        else {
            panic!("server association");
        };
        server.mux.endpoint.add_path_state().unwrap();
        // Do not suppress normal multipath candidate discovery. Readiness,
        // budget and per-path eligibility remain the scheduler's decisions.
        assert!(
            node.control_duplication_candidate(acceptance, &bytes[..used])
                .is_some()
        );
    }

    #[cfg(feature = "tokio")]
    #[test]
    fn local_retransmissions_do_not_keep_a_silent_peer_alive() {
        use crate::{bearer::BearerName, fake::FakePacketBearer};
        type Pool = crate::packet_pool::PacketPool<4, DEFAULT_PACKET_POOL_SLOT_SIZE>;
        static POOL: Pool = Pool::new();
        let mut client = QuicNode::<Pool>::new(&POOL);
        let bearer = client
            .add_bearer(FakePacketBearer::<Pool>::new(
                BearerName::new("silent-peer-test").unwrap(),
            ))
            .unwrap();
        let meta = PacketMeta {
            bearer,
            peer_l2_address: PeerL2Address::new(11).unwrap(),
            received_at_us: 1,
        };
        let open = client.start_association(cid(0x75), meta, 0).unwrap();
        let association = open.association;
        let receive_cid = client.receive_cid(association).unwrap();
        let mut server = QuicNode::<Pool>::new(&POOL);
        let NodeIngress::Initial { response, .. } = server
            .receive_packet(
                meta,
                open.packet,
                |_| {
                    Some(InitialAdmission {
                        local_limits: ConnectionLimits::default(),
                    })
                },
                |_, _, _, _, bytes| Ok(bytes.len()),
            )
            .unwrap()
        else {
            panic!("initial admission");
        };
        client
            .receive_packet(
                meta,
                response.packet,
                |_| None,
                |_, _, _, _, bytes| Ok(bytes.len()),
            )
            .unwrap();
        while client.next_association_event().is_some() {}
        client.set_idle_timeout_us(5_000_000);
        let before = client.slot(association).unwrap().last_activity_us;
        // A packet without a retained ack-eliciting record (e.g. a pure
        // ACK) must not consume the first-send idle extension.
        client.record_packet_acceptance(
            PacketAcceptance {
                association,
                packet_number: u32::MAX,
            },
            50,
        );
        assert_eq!(client.slot(association).unwrap().last_activity_us, before);
        assert!(
            !client
                .slot(association)
                .unwrap()
                .ack_eliciting_sent_since_receive
        );
        client.advance_clock(100);
        let stream = client.allocate_stream(association).unwrap();
        let packet = client
            .send_stream(association, stream, 0, true, b"retained body")
            .unwrap();
        client.submit_node_packet(packet).unwrap();
        assert_eq!(client.slot(association).unwrap().last_activity_us, 100);
        assert!(
            client
                .slot(association)
                .unwrap()
                .ack_eliciting_sent_since_receive
        );
        // The bearer accepts sends, but nothing is delivered back from the
        // peer. Drive ordinary PTOs and submit the retained replacements.
        let mut retransmissions = 0;
        for step in 1..=8 {
            let now = 100 + step * 1_000_000;
            match client.timer_expired(now).unwrap() {
                Some(NodeTimer::Egress(packet)) => {
                    client.submit_node_packet(packet).unwrap();
                    retransmissions += 1;
                }
                Some(NodeTimer::IdleTimedOut {
                    association: expired,
                }) => {
                    assert_eq!(expired, association);
                    break;
                }
                _ => {}
            }
        }
        assert!(
            retransmissions > 0,
            "exercise actual submitted PTO replacements"
        );
        assert_eq!(
            client.association_count(),
            0,
            "local retries must not refresh idle forever"
        );
        assert!(!client.router.contains(receive_cid));
        client.drain_bearer_events();
        assert_eq!(POOL.available(), POOL.capacity());
        assert_eq!(
            client.next_association_event(),
            Some(AssociationEvent::IdleTimeout { association })
        );
    }

    #[cfg(feature = "tokio")]
    #[test]
    fn addressed_congestion_full_path_blocks_and_resumes_without_losing_route() {
        use crate::{bearer::BearerName, fake::FakePacketBearer};
        type Pool = crate::packet_pool::PacketPool<4, DEFAULT_PACKET_POOL_SLOT_SIZE>;
        static POOL: Pool = Pool::new();
        let mut client = QuicNode::<Pool>::new(&POOL);
        let bearer = client
            .add_bearer(FakePacketBearer::<Pool>::new(
                BearerName::new("congestion-test").unwrap(),
            ))
            .unwrap();
        let meta = PacketMeta {
            bearer,
            peer_l2_address: PeerL2Address::new(11).unwrap(),
            received_at_us: 1,
        };
        let open = client.start_association(cid(0x71), meta, 0).unwrap();
        let association = open.association;
        let mut server = QuicNode::<Pool>::new(&POOL);
        let NodeIngress::Initial { response, .. } = server
            .receive_packet(
                meta,
                open.packet,
                |_| {
                    Some(InitialAdmission {
                        local_limits: ConnectionLimits::default(),
                    })
                },
                |_, _, _, _, bytes| Ok(bytes.len()),
            )
            .unwrap()
        else {
            panic!("initial admission");
        };
        client
            .receive_packet(
                meta,
                response.packet,
                |_| None,
                |_, _, _, _, bytes| Ok(bytes.len()),
            )
            .unwrap();
        let stream = client.allocate_stream(association).unwrap();
        let Association::Client(state) = &mut client.slot_mut(association).unwrap().state else {
            panic!("client association");
        };
        let endpoint = state.connection_mut().endpoint_mut().unwrap();
        let next_packet = endpoint.next_packet_number;
        endpoint.paths[0].congestion.congestion_window = 1200;
        endpoint.paths[0].congestion.bytes_in_flight = 1200;
        let address = endpoint.paths[0].active_address();

        assert!(matches!(
            client.send_stream(association, stream, 0, true, b"body"),
            Err(QuicNodeEgressError::Transport(Error::Blocked))
        ));

        // A timer-driven path-control packet obeys the same congestion
        // limit, but must not kill the runtime or leave an immediately due
        // deadline spinning while ACK/loss progress can free capacity.
        let Association::Client(state) = &mut client.slot_mut(association).unwrap().state else {
            unreachable!();
        };
        let endpoint = state.connection_mut().endpoint_mut().unwrap();
        endpoint.set_base_circuit_key();
        endpoint
            .queue_path_status(0, crate::PathStatusKind::Available)
            .unwrap();
        let now = client.clock_us();
        assert!(matches!(client.timer_expired(now), Ok(None)));
        let status_retry = client.next_deadline().unwrap();
        assert!(status_retry > now);

        let Association::Client(state) = &mut client.slot_mut(association).unwrap().state else {
            panic!("client association");
        };
        let endpoint = state.connection_mut().endpoint_mut().unwrap();
        assert_eq!(endpoint.next_packet_number, next_packet);
        assert_eq!(endpoint.paths[0].active_address(), address);
        // Model ACK progress releasing congestion capacity. Retry the same
        // bytes and FIN; the failed attempt must not advance the stream.
        endpoint.paths[0].congestion.bytes_in_flight = 0;
        let sent = client
            .send_stream(association, stream, 0, true, b"body")
            .unwrap();
        assert_eq!(
            (sent.bearer, sent.peer_l2_address),
            (meta.bearer, meta.peer_l2_address)
        );
        drop(sent);
        client.advance_clock(status_retry);
        assert!(
            client
                .poll_association_control(association)
                .unwrap()
                .is_some()
        );
        // Genuine route loss must retain its non-retryable classification.
        assert!(client.remove_bearer(bearer));
        let next_stream = client.allocate_stream(association).unwrap();
        assert!(matches!(
            client.send_stream(association, next_stream, 0, true, b"body"),
            Err(QuicNodeEgressError::MissingEgressAddress)
        ));
    }

    #[test]
    fn path_open_forwards_by_local_resolver_and_replays_downstream_reply() {
        use crate::relay::{
            SETUP_BLOCK_ENDPOINT, SETUP_BLOCK_RELAY, SetupBlock, SetupCircuitKey,
            SetupHopInstruction, SetupMode, SetupRequest, SetupResult, decode_setup_reply_packet,
            decode_setup_request_packet,
        };

        type PathOpenPool = crate::packet_pool::PacketPool<2, DEFAULT_PACKET_POOL_SLOT_SIZE>;
        static PATH_OPEN_POOL: PathOpenPool = PathOpenPool::new();
        let mut node: QuicNode<PathOpenPool, { crate::DEFAULT_MAX_PACKET_SIZE }> =
            QuicNode::new(&PATH_OPEN_POOL);
        let destination_vip = 0x0102_0304_0506_0708;
        node.set_vip_path_open_resolver(move |kind, address, vip| {
            (kind == 3 && address == [9, 8, 7, 6, 5, 4] && vip == destination_vip).then_some(
                CircuitNextHop {
                    bearer: BearerId::new(2).unwrap(),
                    peer_l2_address: PeerL2Address::new(77).unwrap(),
                },
            )
        });

        let instruction = SetupHopInstruction {
            address_kind: 3,
            address_len: 6,
            address: [9, 8, 7, 6, 5, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            lease_us: 5_000_000,
            packet_quota: 100,
        };
        let mut instruction_bytes = [0u8; crate::relay::MAX_SETUP_BLOCK_BYTES];
        let instruction_len = instruction.encode(&mut instruction_bytes).unwrap();
        let mut endpoint_payload = [0u8; crate::DEFAULT_MAX_PACKET_SIZE];
        let endpoint_payload_len =
            crate::encode_bootstrap_open_packet(cid(0x55), 0, &mut endpoint_payload).unwrap();
        let blocks = [
            SetupBlock {
                kind: SETUP_BLOCK_RELAY,
                version: 1,
                protection: 0,
                payload: &instruction_bytes[..instruction_len],
            },
            SetupBlock {
                kind: SETUP_BLOCK_ENDPOINT,
                version: 1,
                protection: 0,
                payload: &endpoint_payload[..endpoint_payload_len],
            },
        ];
        let request = SetupRequest {
            transaction_id: 21,
            mode: SetupMode::Create,
            route_mode: crate::relay::RelayRouteMode::VipRouted,
            circuit: SetupCircuitKey {
                opener_role: crate::Role::Client,
                sequence: 1,
            },
            destination_vip: Some(destination_vip),
            previous_reverse_cid: None,
            blocks: &blocks,
        };
        let mut input = [0u8; crate::DEFAULT_MAX_PACKET_SIZE];
        let input_len = request.encode_packet(&mut input).unwrap();
        let meta = PacketMeta {
            bearer: BearerId::new(1).unwrap(),
            peer_l2_address: PeerL2Address::new(9).unwrap(),
            received_at_us: 10,
        };

        let receive =
            |node: &mut QuicNode<PathOpenPool, { crate::DEFAULT_MAX_PACKET_SIZE }>, meta, bytes| {
                node.receive_packet(
                    meta,
                    OwnedPacket::new(bytes, 0..input_len).unwrap(),
                    |_| {
                        Some(InitialAdmission {
                            local_limits: ConnectionLimits::default(),
                        })
                    },
                    |_, _, _, _, bytes| Ok(bytes.len()),
                )
            };
        let forwarded = receive(&mut node, meta, input).unwrap();
        let NodeIngress::Forward { next_hop, packet } = forwarded else {
            panic!("relay forwards a layered PATH_OPEN to its resolved next hop");
        };
        assert_eq!(next_hop.bearer, BearerId::new(2).unwrap());
        assert_eq!(next_hop.peer_l2_address, PeerL2Address::new(77).unwrap());
        let forwarded_request = decode_setup_request_packet(packet.bytes()).unwrap();
        assert_eq!(
            forwarded_request.route_mode,
            crate::relay::RelayRouteMode::VipRouted
        );
        assert_eq!(forwarded_request.destination_vip, Some(destination_vip));
        assert_eq!(forwarded_request.blocks.count(), 1);
        assert_eq!(forwarded_request.blocks.get(0).unwrap().unwrap(), blocks[1]);
        let reverse_cid = forwarded_request
            .previous_reverse_cid
            .expect("relay passes its reverse ingress CID to the next hop");
        drop(packet);

        node.set_vip_path_open_resolver(|_, _, _| None);
        let retry = receive(&mut node, meta, input).unwrap();
        let NodeIngress::Forward { next_hop, packet } = retry else {
            panic!("an identical pending retry reuses its original downstream hop");
        };
        assert_eq!(next_hop.peer_l2_address, PeerL2Address::new(77).unwrap());
        drop(packet);

        let reply = SetupReply {
            transaction_id: request.transaction_id,
            circuit: request.circuit,
            result: SetupResult::Accepted {
                endpoint_cid: cid(0x99),
                lease_us: crate::relay::DEFAULT_SETUP_LEASE_US,
            },
            bootstrap_ack: None,
            relay_cids: crate::relay::SetupRelayCids::empty(),
        };
        let mut reply_packet = [0u8; crate::DEFAULT_MAX_PACKET_SIZE];
        let reply_len = reply.encode_packet(&mut reply_packet).unwrap();
        let returned = node
            .receive_packet(
                PacketMeta {
                    bearer: BearerId::new(2).unwrap(),
                    peer_l2_address: PeerL2Address::new(77).unwrap(),
                    received_at_us: 20,
                },
                OwnedPacket::new(reply_packet, 0..reply_len).unwrap(),
                |_| None,
                |_, _, _, _, bytes| Ok(bytes.len()),
            )
            .unwrap();
        let NodeIngress::SetupReply { response } = returned else {
            panic!("downstream response returns to the previous setup hop");
        };
        assert_eq!(response.bearer, meta.bearer);
        assert_eq!(response.peer_l2_address, meta.peer_l2_address);
        let installed_reply = decode_setup_reply_packet(response.packet.bytes()).unwrap();
        assert_eq!(
            installed_reply.result,
            SetupResult::Accepted {
                endpoint_cid: cid(0x99),
                lease_us: instruction.lease_us,
            }
        );
        let forward_cid = installed_reply
            .relay_cids
            .first()
            .expect("successful relay setup returns its local forward CID");
        let route = |node: &QuicNode<PathOpenPool, { crate::DEFAULT_MAX_PACKET_SIZE }>, dcid| {
            let mut bytes = [0u8; 16];
            let used = ShortHeader {
                flags: FLAG_FIXED,
                dcid,
                packet_number: 0,
                packet_number_len: 1,
            }
            .encode(&mut bytes)
            .unwrap();
            match node.router.target(&bytes[..used]).unwrap() {
                RouterTarget::Forward(rule) => Some(*rule),
                _ => None,
            }
        };
        let forward_rule = route(&node, forward_cid)
            .expect("the forward alias is installed after endpoint acceptance");
        assert_eq!(forward_rule.next_hop.bearer, BearerId::new(2).unwrap());
        assert_eq!(
            forward_rule.destination,
            ForwardDestination::Connection(cid(0x99))
        );
        let reverse_rule = route(&node, reverse_cid)
            .expect("the reverse alias is installed as part of the same pair");
        assert_eq!(reverse_rule.next_hop.bearer, meta.bearer);
        assert_eq!(
            reverse_rule.destination,
            ForwardDestination::Connection(cid(0x55))
        );
        drop(response);

        let replay = receive(&mut node, meta, input).unwrap();
        let NodeIngress::SetupReply { response } = replay else {
            panic!("a duplicate completed PATH_OPEN replays its cached response");
        };
        assert_eq!(
            decode_setup_reply_packet(response.packet.bytes()),
            Ok(installed_reply)
        );
    }

    #[test]
    fn downstream_setup_rejection_leaves_no_route_or_idle_cache_leak() {
        use crate::relay::{
            SETUP_BLOCK_ENDPOINT, SETUP_BLOCK_RELAY, SetupBlock, SetupCircuitKey,
            SetupHopInstruction, SetupMode, SetupRequest, SetupResult,
        };

        type RejectionPool = crate::packet_pool::PacketPool<2, DEFAULT_PACKET_POOL_SLOT_SIZE>;
        static REJECTION_POOL: RejectionPool = RejectionPool::new();
        let mut node: QuicNode<RejectionPool, { crate::DEFAULT_MAX_PACKET_SIZE }> =
            QuicNode::new(&REJECTION_POOL);
        let vip = 0x0102_0304_0506_0708;
        let next_hop = CircuitNextHop {
            bearer: BearerId::new(2).unwrap(),
            peer_l2_address: PeerL2Address::new(77).unwrap(),
        };
        node.set_vip_path_open_resolver(move |kind, address, found_vip| {
            (kind == 3 && address == [9, 8, 7, 6, 5, 4] && found_vip == vip).then_some(next_hop)
        });

        let instruction = SetupHopInstruction {
            address_kind: 3,
            address_len: 6,
            address: [9, 8, 7, 6, 5, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            lease_us: 5_000_000,
            packet_quota: 100,
        };
        let mut instruction_bytes = [0u8; crate::relay::MAX_SETUP_BLOCK_BYTES];
        let instruction_len = instruction.encode(&mut instruction_bytes).unwrap();
        let mut initial = [0u8; crate::DEFAULT_MAX_PACKET_SIZE];
        let initial_len = crate::encode_bootstrap_open_packet(cid(0x55), 0, &mut initial).unwrap();
        let blocks = [
            SetupBlock {
                kind: SETUP_BLOCK_RELAY,
                version: 1,
                protection: 0,
                payload: &instruction_bytes[..instruction_len],
            },
            SetupBlock {
                kind: SETUP_BLOCK_ENDPOINT,
                version: 1,
                protection: 0,
                payload: &initial[..initial_len],
            },
        ];
        let request = SetupRequest {
            transaction_id: 25,
            mode: SetupMode::Create,
            route_mode: crate::relay::RelayRouteMode::VipRouted,
            circuit: SetupCircuitKey {
                opener_role: crate::Role::Client,
                sequence: 1,
            },
            destination_vip: Some(vip),
            previous_reverse_cid: None,
            blocks: &blocks,
        };
        let mut request_bytes = [0u8; crate::DEFAULT_MAX_PACKET_SIZE];
        let request_len = request.encode_packet(&mut request_bytes).unwrap();
        let ingress = PacketMeta {
            bearer: BearerId::new(1).unwrap(),
            peer_l2_address: PeerL2Address::new(9).unwrap(),
            received_at_us: 10,
        };
        let forwarded = match node
            .receive_packet(
                ingress,
                OwnedPacket::new(request_bytes, 0..request_len).unwrap(),
                |_| None,
                |_, _, _, _, bytes| Ok(bytes.len()),
            )
            .unwrap()
        {
            NodeIngress::Forward {
                next_hop: found,
                packet,
            } => {
                assert_eq!(found.bearer, next_hop.bearer);
                assert_eq!(found.peer_l2_address, next_hop.peer_l2_address);
                packet
            }
            _ => panic!("relay forwards the setup to its resolved next hop"),
        };
        drop(forwarded);
        assert_eq!(node.router.setup_transaction_counts().0, 1);
        assert_eq!(node.router.route_count(), 0);

        let rejection = SetupReply {
            transaction_id: request.transaction_id,
            circuit: request.circuit,
            result: SetupResult::Rejected { code: 3 },
            bootstrap_ack: None,
            relay_cids: crate::relay::SetupRelayCids::empty(),
        };
        let mut reply_bytes = [0u8; crate::DEFAULT_MAX_PACKET_SIZE];
        let reply_len = rejection.encode_packet(&mut reply_bytes).unwrap();
        let result = node
            .receive_packet(
                PacketMeta {
                    bearer: next_hop.bearer,
                    peer_l2_address: next_hop.peer_l2_address,
                    received_at_us: 20,
                },
                OwnedPacket::new(reply_bytes, 0..reply_len).unwrap(),
                |_| None,
                |_, _, _, _, bytes| Ok(bytes.len()),
            )
            .unwrap();
        let NodeIngress::SetupReply { response } = result else {
            panic!("downstream rejection is returned to the setup originator");
        };
        assert_eq!(response.peer_l2_address, ingress.peer_l2_address);
        let returned = crate::relay::decode_setup_reply_packet(response.packet.bytes()).unwrap();
        assert_eq!(returned.result, SetupResult::Rejected { code: 3 });
        let (pending, cached, reserved) = node.router.setup_transaction_counts();
        assert_eq!((pending, cached), (0, 1));
        assert!(reserved > 0);
        assert_eq!(node.router.route_count(), 0);
        drop(response);

        assert!(
            node.timer_expired(20 + crate::relay::DEFAULT_SETUP_REPLY_RETENTION_US)
                .unwrap()
                .is_none()
        );
        assert_eq!(node.router.setup_transaction_counts(), (0, 0, 0));
        assert_eq!(node.router.route_count(), 0);
        assert_eq!(node.next_deadline(), None);
    }

    #[test]
    fn vip_route_mode_is_encoded_by_the_public_association_api() {
        use crate::BearerName;
        use crate::fake::FakePacketBearer;
        use crate::relay::decode_setup_request_packet;

        type VipPool = crate::packet_pool::PacketPool<2, DEFAULT_PACKET_POOL_SLOT_SIZE>;
        static VIP_POOL: VipPool = VipPool::new();
        struct DropIngress;
        impl<B: AsRef<[u8]> + Send> crate::bearer::PacketIngressQueue<B> for DropIngress {
            fn enqueue_packet(&self, _meta: PacketMeta, _packet: OwnedPacket<B>) {}
        }
        let bearer_impl = FakePacketBearer::<VipPool>::new(BearerName::new("vip-open").unwrap());
        let sent = bearer_impl.sent_packets();
        let mut node: QuicNode<VipPool, { crate::DEFAULT_MAX_PACKET_SIZE }> =
            QuicNode::new(&VIP_POOL);
        let bearer = node
            .register_bearer_with_ingress(bearer_impl, Arc::new(DropIngress))
            .unwrap();
        let address = PacketMeta {
            bearer,
            peer_l2_address: PeerL2Address::new(10).unwrap(),
            received_at_us: 1,
        };
        let hop = RelayHop::new(2, &[7], 5_000_000, 100).unwrap();
        let vip = 0x0102_0304_0506_0708;

        node.associate_relayed_with_route_mode(
            address,
            Some(vip),
            &[hop],
            NearbyRelayHints::EMPTY,
            crate::RelayRouteMode::VipRouted,
            1,
        )
        .unwrap();

        let packets = sent.lock().unwrap();
        let request = decode_setup_request_packet(&packets[0]).unwrap();
        assert_eq!(request.route_mode, crate::RelayRouteMode::VipRouted);
        assert_eq!(request.destination_vip, Some(vip));
        drop(packets);

        node.associate_relayed_with_route_mode(
            address,
            Some(vip),
            &[hop],
            NearbyRelayHints::EMPTY,
            crate::RelayRouteMode::Telescoping,
            2,
        )
        .unwrap();
        let packets = sent.lock().unwrap();
        let request = decode_setup_request_packet(&packets[1]).unwrap();
        assert_eq!(request.route_mode, crate::RelayRouteMode::Telescoping);
        assert_eq!(request.destination_vip, Some(vip));
        assert_eq!(request.blocks.count(), 2);
    }

    #[test]
    fn layered_create_installs_both_directions_across_three_relays() {
        use crate::relay::{
            SETUP_BLOCK_ENDPOINT, SETUP_BLOCK_RELAY, SetupBlock, SetupCircuitKey,
            SetupHopInstruction, SetupMode, SetupRequest, SetupResult, decode_setup_reply_packet,
            decode_setup_request_packet,
        };

        type RelayPool = crate::packet_pool::PacketPool<4, DEFAULT_PACKET_POOL_SLOT_SIZE>;
        static RELAY1_POOL: RelayPool = RelayPool::new();
        static RELAY2_POOL: RelayPool = RelayPool::new();
        static RELAY3_POOL: RelayPool = RelayPool::new();
        static ENDPOINT_POOL: RelayPool = RelayPool::new();
        type RelayNode = QuicNode<RelayPool, { crate::DEFAULT_MAX_PACKET_SIZE }>;

        let hop12 = CircuitNextHop {
            bearer: BearerId::new(2).unwrap(),
            peer_l2_address: PeerL2Address::new(22).unwrap(),
        };
        let hop23 = CircuitNextHop {
            bearer: BearerId::new(3).unwrap(),
            peer_l2_address: PeerL2Address::new(33).unwrap(),
        };
        let hop3b = CircuitNextHop {
            bearer: BearerId::new(4).unwrap(),
            peer_l2_address: PeerL2Address::new(44).unwrap(),
        };
        let meta_a1 = PacketMeta {
            bearer: BearerId::new(1).unwrap(),
            peer_l2_address: PeerL2Address::new(11).unwrap(),
            received_at_us: 10,
        };
        let mut relay1 = RelayNode::new(&RELAY1_POOL);
        let mut relay2 = RelayNode::new(&RELAY2_POOL);
        let mut relay3 = RelayNode::new(&RELAY3_POOL);
        let mut endpoint = RelayNode::new(&ENDPOINT_POOL);
        relay1.set_path_open_resolver(move |kind, address| {
            (kind == 2 && address == [2]).then_some(hop12)
        });
        relay2.set_path_open_route(2,&[3],hop23).unwrap();
        relay3.set_path_open_resolver(move |kind, address| {
            (kind == 3 && address == [4]).then_some(hop3b)
        });

        let instructions = [
            SetupHopInstruction {
                address_kind: 2,
                address_len: 1,
                address: [2; crate::relay::MAX_SETUP_HOP_ADDRESS_BYTES],
                lease_us: 60_000_000,
                packet_quota: 4096,
            },
            SetupHopInstruction {
                address_kind: 2,
                address_len: 1,
                address: [3; crate::relay::MAX_SETUP_HOP_ADDRESS_BYTES],
                lease_us: 50_000_000,
                packet_quota: 4096,
            },
            SetupHopInstruction {
                address_kind: 3,
                address_len: 1,
                address: [4; crate::relay::MAX_SETUP_HOP_ADDRESS_BYTES],
                lease_us: 40_000_000,
                packet_quota: 4096,
            },
        ];
        let mut payloads = [[0u8; crate::relay::MAX_SETUP_BLOCK_BYTES]; 3];
        let mut payload_lens = [0usize; 3];
        for index in 0..3 {
            payload_lens[index] = instructions[index].encode(&mut payloads[index]).unwrap();
        }
        let client_cid = cid(0x5151);
        let mut initial = [0u8; crate::DEFAULT_MAX_PACKET_SIZE];
        let initial_len = crate::encode_bootstrap_open_packet(client_cid, 0, &mut initial).unwrap();
        let blocks = [
            SetupBlock {
                kind: SETUP_BLOCK_RELAY,
                version: 1,
                protection: 0,
                payload: &payloads[0][..payload_lens[0]],
            },
            SetupBlock {
                kind: SETUP_BLOCK_RELAY,
                version: 1,
                protection: 0,
                payload: &payloads[1][..payload_lens[1]],
            },
            SetupBlock {
                kind: SETUP_BLOCK_RELAY,
                version: 1,
                protection: 0,
                payload: &payloads[2][..payload_lens[2]],
            },
            SetupBlock {
                kind: SETUP_BLOCK_ENDPOINT,
                version: 1,
                protection: 0,
                payload: &initial[..initial_len],
            },
        ];
        let request = SetupRequest {
            transaction_id: 0x201,
            mode: SetupMode::Create,
            route_mode: crate::relay::RelayRouteMode::Layered,
            circuit: SetupCircuitKey {
                opener_role: crate::Role::Client,
                sequence: 1,
            },
            destination_vip: Some(0x0102_0304_0506_0708),
            previous_reverse_cid: None,
            blocks: &blocks,
        };
        let mut request_packet = [0u8; crate::DEFAULT_MAX_PACKET_SIZE];
        let request_len = request.encode_packet(&mut request_packet).unwrap();
        let admit = || {
            Some(InitialAdmission {
                local_limits: ConnectionLimits::default(),
            })
        };
        let stream = |_, _, _, _, bytes: &[u8]| Ok(bytes.len());

        let first = relay1
            .receive_packet(
                meta_a1,
                OwnedPacket::new(request_packet, 0..request_len).unwrap(),
                |_| admit(),
                stream,
            )
            .unwrap();
        let NodeIngress::Forward {
            packet: packet12, ..
        } = first
        else {
            panic!("first relay forwards after resolving its next hop");
        };
        let reverse1 = decode_setup_request_packet(packet12.bytes())
            .unwrap()
            .previous_reverse_cid
            .unwrap();

        let second = relay2
            .receive_packet(
                PacketMeta {
                    bearer: hop12.bearer,
                    peer_l2_address: hop12.peer_l2_address,
                    received_at_us: 20,
                },
                packet12,
                |_| admit(),
                stream,
            )
            .unwrap();
        let NodeIngress::Forward {
            packet: packet23, ..
        } = second
        else {
            panic!("second relay forwards after resolving its next hop");
        };
        let reverse2 = decode_setup_request_packet(packet23.bytes())
            .unwrap()
            .previous_reverse_cid
            .unwrap();

        let third = relay3
            .receive_packet(
                PacketMeta {
                    bearer: hop23.bearer,
                    peer_l2_address: hop23.peer_l2_address,
                    received_at_us: 30,
                },
                packet23,
                |_| admit(),
                stream,
            )
            .unwrap();
        let NodeIngress::Forward {
            packet: packet3b, ..
        } = third
        else {
            panic!("third relay forwards the terminal Create to the endpoint");
        };
        let reverse3 = decode_setup_request_packet(packet3b.bytes())
            .unwrap()
            .previous_reverse_cid
            .unwrap();

        let endpoint_result = endpoint
            .receive_packet(
                PacketMeta {
                    bearer: hop3b.bearer,
                    peer_l2_address: hop3b.peer_l2_address,
                    received_at_us: 40,
                },
                packet3b,
                |_| admit(),
                stream,
            )
            .unwrap();
        let NodeIngress::SetupAccepted {
            association: endpoint_association,
            response: endpoint_response,
            ..
        } = endpoint_result
        else {
            panic!("endpoint admits Create and replies through the last relay");
        };
        assert!(endpoint.contains_association(endpoint_association));
        assert_eq!(endpoint.association_count(), 1);
        let endpoint_reply = decode_setup_reply_packet(endpoint_response.packet.bytes()).unwrap();
        let SetupResult::Accepted { endpoint_cid, .. } = endpoint_reply.result else {
            panic!("endpoint accepted the bootstrap Initial");
        };
        assert!(endpoint.associations.iter().flatten().any(|slot| {
            matches!(&slot.state, Association::Server(server) if server.peer_receive_cid() == reverse3)
        }));

        let third_reply = relay3
            .receive_packet(
                PacketMeta {
                    bearer: hop3b.bearer,
                    peer_l2_address: hop3b.peer_l2_address,
                    received_at_us: 50,
                },
                endpoint_response.packet,
                |_| None,
                stream,
            )
            .unwrap();
        let NodeIngress::SetupReply {
            response: response3,
        } = third_reply
        else {
            panic!("third relay installs its CID pair");
        };
        let reply3 = decode_setup_reply_packet(response3.packet.bytes()).unwrap();

        let second_reply = relay2
            .receive_packet(
                PacketMeta {
                    bearer: hop23.bearer,
                    peer_l2_address: hop23.peer_l2_address,
                    received_at_us: 60,
                },
                response3.packet,
                |_| None,
                stream,
            )
            .unwrap();
        let NodeIngress::SetupReply {
            response: response2,
        } = second_reply
        else {
            panic!("second relay installs its CID pair");
        };
        let reply2 = decode_setup_reply_packet(response2.packet.bytes()).unwrap();

        let first_reply = relay1
            .receive_packet(
                PacketMeta {
                    bearer: hop12.bearer,
                    peer_l2_address: hop12.peer_l2_address,
                    received_at_us: 70,
                },
                response2.packet,
                |_| None,
                stream,
            )
            .unwrap();
        let NodeIngress::SetupReply {
            response: response1,
        } = first_reply
        else {
            panic!("first relay installs its CID pair");
        };
        let reply1 = decode_setup_reply_packet(response1.packet.bytes()).unwrap();
        assert_eq!(
            reply1.result,
            SetupResult::Accepted {
                endpoint_cid,
                lease_us: instructions[2].lease_us,
            }
        );
        assert_eq!(reply1.relay_cids.count(), 3);
        let forward1 = reply1.relay_cids.get(0).unwrap();
        let forward2 = reply1.relay_cids.get(1).unwrap();
        let forward3 = reply1.relay_cids.get(2).unwrap();
        assert_eq!(reply2.relay_cids.count(), 2);
        assert_eq!(reply2.relay_cids.get(0), Some(forward2));
        assert_eq!(reply3.relay_cids.count(), 1);
        assert_eq!(reply3.relay_cids.get(0), Some(forward3));

        let rule_for = |node: &RelayNode, dcid| {
            let mut input = [0u8; 16];
            let used = ShortHeader {
                flags: FLAG_FIXED,
                dcid,
                packet_number: 0,
                packet_number_len: 1,
            }
            .encode(&mut input)
            .unwrap();
            match node.router.target(&input[..used]).unwrap() {
                RouterTarget::Forward(rule) => Some(*rule),
                _ => None,
            }
        };
        assert_eq!(
            rule_for(&relay1, forward1).unwrap().destination,
            ForwardDestination::Connection(forward2)
        );
        assert_eq!(
            rule_for(&relay2, forward2).unwrap().destination,
            ForwardDestination::Connection(forward3)
        );
        assert_eq!(
            rule_for(&relay3, forward3).unwrap().destination,
            ForwardDestination::Connection(endpoint_cid)
        );
        assert_eq!(
            rule_for(&relay1, reverse1).unwrap().destination,
            ForwardDestination::Connection(client_cid)
        );
        assert_eq!(
            rule_for(&relay2, reverse2).unwrap().destination,
            ForwardDestination::Connection(reverse1)
        );
        assert_eq!(
            rule_for(&relay3, reverse3).unwrap().destination,
            ForwardDestination::Connection(reverse2)
        );
        assert_eq!(
            rule_for(&relay1, forward1)
                .unwrap()
                .next_hop
                .peer_l2_address,
            hop12.peer_l2_address
        );
        assert_eq!(
            rule_for(&relay2, forward2)
                .unwrap()
                .next_hop
                .peer_l2_address,
            hop23.peer_l2_address
        );
        assert_eq!(
            rule_for(&relay3, forward3)
                .unwrap()
                .next_hop
                .peer_l2_address,
            hop3b.peer_l2_address
        );
    }

    #[cfg(feature = "tokio")]
    #[test]
    fn layered_join_adds_a_second_circuit_to_the_existing_association() {
        use crate::bearer::BearerName;
        use crate::fake::FakePacketBearer;
        use crate::relay::{SetupResult, decode_setup_reply_packet};

        type RelayPool = crate::packet_pool::PacketPool<16, DEFAULT_PACKET_POOL_SLOT_SIZE>;
        type RelayNode = QuicNode<RelayPool, { crate::DEFAULT_MAX_PACKET_SIZE }>;
        static POOL: RelayPool = RelayPool::new();

        let client_bearer =
            FakePacketBearer::<RelayPool>::new(BearerName::new("multipath-client").unwrap());
        let sent = client_bearer.sent_packets();
        let mut client_node = RelayNode::new(&POOL);
        let bearer_id = client_node.add_bearer(client_bearer).unwrap();
        let address = PacketMeta {
            bearer: bearer_id,
            peer_l2_address: PeerL2Address::new(11).unwrap(),
            received_at_us: 100,
        };

        let mut server_node = RelayNode::new(&POOL);
        let initial = client_node
            .start_association(cid(0x5151), address, 100)
            .unwrap();
        let association = initial.association;
        let server_association = match server_node
            .receive_packet(
                address,
                initial.packet,
                |_| {
                    Some(InitialAdmission {
                        local_limits: ConnectionLimits::default(),
                    })
                },
                |_, _, _, _, bytes| Ok(bytes.len()),
            )
            .unwrap()
        {
            NodeIngress::Initial {
                association,
                response,
            } => {
                client_node
                    .receive_packet(
                        address,
                        response.packet,
                        |_| None,
                        |_, _, _, _, bytes| Ok(bytes.len()),
                    )
                    .unwrap();
                association
            }
            _ => panic!("the initial direct path establishes one association"),
        };
        assert_eq!(client_node.association_count(), 1);
        assert_eq!(server_node.association_count(), 1);

        let relay_to_endpoint = CircuitNextHop {
            bearer: BearerId::new(2).unwrap(),
            peer_l2_address: PeerL2Address::new(44).unwrap(),
        };
        let relay_to_second = CircuitNextHop {
            bearer: BearerId::new(3).unwrap(),
            peer_l2_address: PeerL2Address::new(55).unwrap(),
        };
        let mut relay = RelayNode::new(&POOL);
        relay.set_path_open_resolver(move |kind, bytes| {
            if kind != 3 {
                return None;
            }
            match bytes {
                [4] => Some(relay_to_endpoint),
                [5] => Some(relay_to_second),
                _ => None,
            }
        });
        let mut second_relay = RelayNode::new(&POOL);
        let relay_hop = RelayHop::new(3, &[4], 30_000_000, 1024).unwrap();
        let second_hop = PacketMeta {
            peer_l2_address: PeerL2Address::new(22).unwrap(),
            received_at_us: 200,
            ..address
        };
        let circuit = client_node
            .join_relayed_path(association, second_hop, &[relay_hop], 200)
            .unwrap();
        assert_eq!(circuit.local_id, 1);
        let join_bytes = sent.lock().unwrap()[0].clone();
        let join_len = join_bytes.len();
        let mut join_buffer = [0u8; crate::DEFAULT_MAX_PACKET_SIZE];
        join_buffer[..join_len].copy_from_slice(&join_bytes);
        let join_packet = OwnedPacket::new(join_buffer, 0..join_len).unwrap();

        let forwarded = relay
            .receive_packet(
                second_hop,
                join_packet,
                |_| None,
                |_, _, _, _, bytes| Ok(bytes.len()),
            )
            .unwrap();
        let (next_hop, forwarded_join) = match forwarded {
            NodeIngress::Forward { next_hop, packet } => (next_hop, packet),
            NodeIngress::NonQuic { error, .. } => {
                panic!("the relay rejected layered JOIN: {error:?}");
            }
            _ => panic!("the relay must forward the layered JOIN"),
        };
        assert_eq!(next_hop.bearer, relay_to_endpoint.bearer);
        assert_eq!(next_hop.peer_l2_address, relay_to_endpoint.peer_l2_address);
        let forwarded_join_bytes = forwarded_join.bytes().to_vec();
        let endpoint_meta = PacketMeta {
            bearer: relay_to_endpoint.bearer,
            peer_l2_address: relay_to_endpoint.peer_l2_address,
            received_at_us: 210,
        };

        let endpoint_reply = server_node
            .receive_packet(
                endpoint_meta,
                forwarded_join,
                |_| None,
                |_, _, _, _, bytes| Ok(bytes.len()),
            )
            .unwrap();
        let NodeIngress::SetupReply {
            response: endpoint_response,
        } = endpoint_reply
        else {
            panic!("the existing endpoint association accepts the JOIN");
        };
        assert_eq!(server_node.association_count(), 1);
        assert_eq!(
            server_node
                .server(server_association)
                .unwrap()
                .mux
                .endpoint
                .path_count(),
            2
        );

        let endpoint_reply_bytes = endpoint_response.packet.bytes().to_vec();
        let mut duplicate_buffer = [0u8; crate::DEFAULT_MAX_PACKET_SIZE];
        duplicate_buffer[..forwarded_join_bytes.len()].copy_from_slice(&forwarded_join_bytes);
        let duplicate = server_node
            .receive_packet(
                endpoint_meta,
                OwnedPacket::new(duplicate_buffer, 0..forwarded_join_bytes.len()).unwrap(),
                |_| None,
                |_, _, _, _, bytes| Ok(bytes.len()),
            )
            .unwrap();
        let NodeIngress::SetupReply {
            response: duplicate_response,
        } = duplicate
        else {
            panic!("the endpoint replays a byte-identical successful JOIN reply");
        };
        assert_eq!(duplicate_response.packet.bytes(), endpoint_reply_bytes);
        assert_eq!(server_node.association_count(), 1);
        assert_eq!(
            server_node
                .server(server_association)
                .unwrap()
                .mux
                .endpoint
                .path_count(),
            2
        );
        drop(duplicate_response);

        let forwarded_view =
            crate::relay::decode_setup_request_packet(&forwarded_join_bytes).unwrap();
        let endpoint_block = forwarded_view.blocks.get(0).unwrap().unwrap();
        let join = crate::relay::SetupJoinEndpoint::decode(endpoint_block.payload).unwrap();
        let mut conflicting_payload = [0u8; crate::relay::MAX_SETUP_BLOCK_BYTES];
        let changed_receive_cid = cid(join.opener_receive_cid.value() + 1);
        let conflicting_payload_len = crate::relay::SetupJoinEndpoint {
            join_cid: join.join_cid,
            opener_receive_cid: changed_receive_cid,
        }
        .encode(&mut conflicting_payload)
        .unwrap();
        let conflicting_block = crate::relay::SetupBlock {
            kind: crate::relay::SETUP_BLOCK_ENDPOINT,
            version: 1,
            protection: 0,
            payload: &conflicting_payload[..conflicting_payload_len],
        };
        let conflicting_request = crate::relay::SetupRequest {
            transaction_id: forwarded_view.transaction_id,
            mode: forwarded_view.mode,
            route_mode: forwarded_view.route_mode,
            circuit: forwarded_view.circuit,
            destination_vip: forwarded_view.destination_vip,
            previous_reverse_cid: forwarded_view.previous_reverse_cid,
            blocks: core::slice::from_ref(&conflicting_block),
        };
        let mut conflicting_packet = [0u8; crate::DEFAULT_MAX_PACKET_SIZE];
        let conflicting_len = conflicting_request
            .encode_packet(&mut conflicting_packet)
            .unwrap();
        let conflict = server_node
            .receive_packet(
                endpoint_meta,
                OwnedPacket::new(conflicting_packet, 0..conflicting_len).unwrap(),
                |_| None,
                |_, _, _, _, bytes| Ok(bytes.len()),
            )
            .unwrap();
        let NodeIngress::SetupReply {
            response: conflict_response,
        } = conflict
        else {
            panic!("a conflicting retry is rejected without adding another circuit");
        };
        assert_eq!(
            decode_setup_reply_packet(conflict_response.packet.bytes())
                .unwrap()
                .result,
            SetupResult::Rejected { code: 4 }
        );
        assert_eq!(server_node.association_count(), 1);
        assert_eq!(
            server_node
                .server(server_association)
                .unwrap()
                .mux
                .endpoint
                .path_count(),
            2
        );
        drop(conflict_response);

        let relay_reply = relay
            .receive_packet(
                PacketMeta {
                    bearer: relay_to_endpoint.bearer,
                    peer_l2_address: relay_to_endpoint.peer_l2_address,
                    received_at_us: 220,
                },
                endpoint_response.packet,
                |_| None,
                |_, _, _, _, bytes| Ok(bytes.len()),
            )
            .unwrap();
        let NodeIngress::SetupReply {
            response: client_response,
        } = relay_reply
        else {
            panic!("the relay installs its paired rules and returns the JOIN reply");
        };
        let reply = decode_setup_reply_packet(client_response.packet.bytes()).unwrap();
        assert!(matches!(reply.result, SetupResult::Accepted { .. }));
        assert_eq!(reply.relay_cids.count(), 1);
        assert_eq!(client_response.bearer, second_hop.bearer);
        assert_eq!(client_response.peer_l2_address, second_hop.peer_l2_address);
        let client_response_bytes = client_response.packet.bytes().to_vec();

        client_node
            .receive_packet(
                second_hop,
                client_response.packet,
                |_| None,
                |_, _, _, _, bytes| Ok(bytes.len()),
            )
            .unwrap();
        assert_eq!(client_node.association_count(), 1);
        assert_eq!(server_node.association_count(), 1);
        let mut client_paths = [CircuitInfo::default(); crate::MAX_PATH_STATES];
        let mut server_paths = [CircuitInfo::default(); crate::MAX_PATH_STATES];
        assert_eq!(client_node.circuits(association, &mut client_paths), 2);
        assert_eq!(
            server_node.circuits(server_association, &mut server_paths),
            2
        );
        assert_eq!(client_paths[1].status, CircuitStatus::Probing);
        assert_eq!(server_paths[1].status, CircuitStatus::Probing);

        let mut retry_buffer = [0u8; crate::DEFAULT_MAX_PACKET_SIZE];
        retry_buffer[..join_len].copy_from_slice(&join_bytes);
        let replayed = relay
            .receive_packet(
                second_hop,
                OwnedPacket::new(retry_buffer, 0..join_len).unwrap(),
                |_| None,
                |_, _, _, _, bytes| Ok(bytes.len()),
            )
            .unwrap();
        let NodeIngress::SetupReply {
            response: replayed_response,
        } = replayed
        else {
            panic!("an identical retry replays the completed relay response");
        };
        assert_eq!(replayed_response.packet.bytes(), client_response_bytes);
        assert_eq!(client_node.association_count(), 1);
        assert_eq!(server_node.association_count(), 1);
        assert_eq!(client_node.circuits(association, &mut client_paths), 2);
        assert_eq!(
            server_node.circuits(server_association, &mut server_paths),
            2
        );

        let failed_first_hop = PacketMeta {
            peer_l2_address: PeerL2Address::new(23).unwrap(),
            received_at_us: 300,
            ..address
        };
        let failed_hops = [
            RelayHop::new(3, &[5], 30_000_000, 1024).unwrap(),
            RelayHop::new(3, &[6], 30_000_000, 1024).unwrap(),
        ];
        let failed_circuit = client_node
            .join_relayed_path(association, failed_first_hop, &failed_hops, 300)
            .unwrap();
        assert_eq!(failed_circuit.local_id, 2);
        let failed_join_bytes = sent.lock().unwrap()[1].clone();
        let failed_join_len = failed_join_bytes.len();
        let mut failed_join_buffer = [0u8; crate::DEFAULT_MAX_PACKET_SIZE];
        failed_join_buffer[..failed_join_len].copy_from_slice(&failed_join_bytes);
        let first_forward = relay
            .receive_packet(
                failed_first_hop,
                OwnedPacket::new(failed_join_buffer, 0..failed_join_len).unwrap(),
                |_| None,
                |_, _, _, _, bytes| Ok(bytes.len()),
            )
            .unwrap();
        let (second_hop, second_request) = match first_forward {
            NodeIngress::Forward { next_hop, packet } => (next_hop, packet),
            _ => panic!("the first relay forwards before the downstream failure"),
        };
        assert_eq!(second_hop.bearer, relay_to_second.bearer);
        let second_failure = second_relay
            .receive_packet(
                PacketMeta {
                    bearer: relay_to_second.bearer,
                    peer_l2_address: relay_to_second.peer_l2_address,
                    received_at_us: 310,
                },
                second_request,
                |_| None,
                |_, _, _, _, bytes| Ok(bytes.len()),
            )
            .unwrap();
        let NodeIngress::SetupReply {
            response: downstream_rejection,
        } = second_failure
        else {
            panic!("the second relay rejects its unresolved next hop");
        };
        let first_failure = relay
            .receive_packet(
                PacketMeta {
                    bearer: relay_to_second.bearer,
                    peer_l2_address: relay_to_second.peer_l2_address,
                    received_at_us: 320,
                },
                downstream_rejection.packet,
                |_| None,
                |_, _, _, _, bytes| Ok(bytes.len()),
            )
            .unwrap();
        let NodeIngress::SetupReply {
            response: client_rejection,
        } = first_failure
        else {
            panic!("the first relay propagates downstream rejection");
        };
        assert_eq!(
            decode_setup_reply_packet(client_rejection.packet.bytes())
                .unwrap()
                .result,
            SetupResult::Rejected { code: 3 }
        );
        assert!(matches!(
            client_node
                .receive_packet(
                    failed_first_hop,
                    client_rejection.packet,
                    |_| None,
                    |_, _, _, _, bytes| Ok(bytes.len()),
                )
                .unwrap(),
            NodeIngress::NonQuic {
                error: Error::Invalid,
                ..
            }
        ));
        assert_eq!(client_node.association_count(), 1);
        assert_eq!(server_node.association_count(), 1);
        assert_eq!(client_node.circuits(association, &mut client_paths), 2);
        assert_eq!(
            server_node.circuits(server_association, &mut server_paths),
            2
        );

        let retry_hop = PacketMeta {
            peer_l2_address: PeerL2Address::new(24).unwrap(),
            received_at_us: 400,
            ..address
        };
        let retry_circuit = client_node
            .join_relayed_path(association, retry_hop, &[relay_hop], 400)
            .unwrap();
        let initial_retry_bytes = sent.lock().unwrap()[2].clone();
        for retry_index in 1..crate::MAX_PATH_JOIN_ATTEMPTS {
            let retry_at = 400 + u64::from(retry_index) * DEFAULT_INITIAL_PTO_US;
            let retry = match client_node.timer_expired(retry_at).unwrap().unwrap() {
                NodeTimer::Egress(egress) => egress,
                _ => panic!("pending relayed JOIN retries at its fixed retry interval"),
            };
            assert_eq!(retry.packet.bytes(), initial_retry_bytes);
            client_node.submit_node_packet(retry).unwrap();
        }
        let timeout_at = 400 + u64::from(crate::MAX_PATH_JOIN_ATTEMPTS) * DEFAULT_INITIAL_PTO_US;
        assert!(matches!(
            client_node.timer_expired(timeout_at).unwrap(),
            Some(NodeTimer::CircuitSetupTimedOut {
                association: timed_out_association,
                circuit: timed_out_circuit,
            }) if timed_out_association == association && timed_out_circuit == retry_circuit
        ));
        assert_eq!(client_node.association_count(), 1);
        assert_eq!(client_node.circuits(association, &mut client_paths), 2);
    }

    #[test]
    fn endpoint_path_open_admits_create_and_replays_bootstrap_ack() {
        use crate::relay::{
            SETUP_BLOCK_ENDPOINT, SetupBlock, SetupCircuitKey, SetupMode, SetupRequest,
            SetupResult, decode_setup_reply_packet,
        };

        type EndpointPool = crate::packet_pool::PacketPool<2, DEFAULT_PACKET_POOL_SLOT_SIZE>;
        static ENDPOINT_POOL: EndpointPool = EndpointPool::new();
        let mut node: QuicNode<EndpointPool, { crate::DEFAULT_MAX_PACKET_SIZE }> =
            QuicNode::new(&ENDPOINT_POOL);
        let client_cid = cid(0x1234);
        let reverse_alias = cid(0x777);
        let mut initial = [0u8; crate::DEFAULT_MAX_PACKET_SIZE];
        let initial_len = crate::encode_bootstrap_open_packet(client_cid, 0, &mut initial).unwrap();
        let block = SetupBlock {
            kind: SETUP_BLOCK_ENDPOINT,
            version: 1,
            protection: 0,
            payload: &initial[..initial_len],
        };
        let request = SetupRequest {
            transaction_id: 31,
            mode: SetupMode::Create,
            route_mode: crate::relay::RelayRouteMode::Layered,
            circuit: SetupCircuitKey {
                opener_role: crate::Role::Client,
                sequence: 1,
            },
            destination_vip: Some(0x0102_0304_0506_0708),
            previous_reverse_cid: Some(reverse_alias),
            blocks: core::slice::from_ref(&block),
        };
        let mut request_packet = [0u8; crate::DEFAULT_MAX_PACKET_SIZE];
        let request_len = request.encode_packet(&mut request_packet).unwrap();
        let meta = PacketMeta {
            bearer: BearerId::new(1).unwrap(),
            peer_l2_address: PeerL2Address::new(9).unwrap(),
            received_at_us: 10,
        };
        let receive = |node: &mut QuicNode<EndpointPool, { crate::DEFAULT_MAX_PACKET_SIZE }>,
                       input| {
            node.receive_packet(
                meta,
                OwnedPacket::new(input, 0..request_len).unwrap(),
                |_| {
                    Some(InitialAdmission {
                        local_limits: ConnectionLimits::default(),
                    })
                },
                |_, _, _, _, bytes| Ok(bytes.len()),
            )
        };

        let first = receive(&mut node, request_packet).unwrap();
        let NodeIngress::SetupAccepted {
            association: accepted_association,
            response,
            ..
        } = first
        else {
            panic!("endpoint Create returns a PATH_OPEN_ACK");
        };
        assert!(node.contains_association(accepted_association));
        let reply = decode_setup_reply_packet(response.packet.bytes()).unwrap();
        assert_eq!(reply.transaction_id, request.transaction_id);
        assert_eq!(reply.circuit, request.circuit);
        let SetupResult::Accepted {
            endpoint_cid,
            lease_us,
        } = reply.result
        else {
            panic!("admitted endpoint Create succeeds");
        };
        assert_ne!(endpoint_cid, client_cid);
        assert_eq!(lease_us, crate::relay::DEFAULT_SETUP_LEASE_US);
        let bootstrap_ack = reply
            .bootstrap_ack
            .expect("Create returns endpoint OPEN_ACK");
        let (_, ack) = crate::decode_bootstrap_open_ack_packet_with_limits(
            bootstrap_ack.as_bytes(),
            client_cid,
        )
        .unwrap();
        assert_eq!(ack.server_receive_cid, endpoint_cid);
        assert!(node.associations.iter().flatten().any(|slot| {
            matches!(&slot.state, Association::Server(server) if server.peer_receive_cid() == reverse_alias)
        }));
        assert_eq!(node.association_count(), 1);
        drop(response);

        let duplicate = receive(&mut node, request_packet).unwrap();
        let NodeIngress::SetupReply { response } = duplicate else {
            panic!("a duplicate endpoint Create replays its cached setup reply");
        };
        assert_eq!(
            decode_setup_reply_packet(response.packet.bytes()),
            Ok(reply)
        );
        assert_eq!(node.association_count(), 1);
    }

    #[test]
    fn credit_acceptance_restarts_idle_once_and_peer_receive_rearms_it() {
        let mut node: QuicNode<TestPool> = QuicNode::new(&TEST_POOL);
        let local = cid(0x76);
        let association = node
            .add_client(local, Box::new(ClientAssociation::new(local)))
            .unwrap();
        let mut open = [0; crate::DEFAULT_MAX_PACKET_SIZE];
        let mut response = [0; 16];
        let len = ShortHeader {
            flags: FLAG_FIXED,
            dcid: local,
            packet_number: 0,
            packet_number_len: 1,
        }
        .encode(&mut response)
        .unwrap();
        let Association::Client(client) = &mut node.slot_mut(association).unwrap().state else {
            panic!("client");
        };
        client.connection_mut().start(&mut open).unwrap();
        client
            .connection_mut()
            .receive_initial_short_header(&response[..len], 0)
            .unwrap();
        client
            .connection_mut()
            .endpoint_mut()
            .unwrap()
            .credit_packet_number = Some(7);
        let acceptance = PacketAcceptance {
            association,
            packet_number: 7,
        };
        node.record_packet_acceptance(acceptance, 100);
        assert_eq!(node.slot(association).unwrap().last_activity_us, 100);
        node.record_packet_acceptance(acceptance, 200);
        assert_eq!(node.slot(association).unwrap().last_activity_us, 100);
        let meta = PacketMeta {
            bearer: BearerId::new(1).unwrap(),
            peer_l2_address: PeerL2Address::new(11).unwrap(),
            received_at_us: 300,
        };
        node.advance_clock(300);
        node.remember_address(association, meta);
        assert!(
            !node
                .slot(association)
                .unwrap()
                .ack_eliciting_sent_since_receive
        );
        node.record_packet_acceptance(acceptance, 400);
        assert_eq!(node.slot(association).unwrap().last_activity_us, 400);
        node.record_packet_acceptance(acceptance, 500);
        assert_eq!(node.slot(association).unwrap().last_activity_us, 400);
        node.advance_clock(600);
        node.remember_ingress_path_address(association, 0, meta, false);
        assert!(
            !node
                .slot(association)
                .unwrap()
                .ack_eliciting_sent_since_receive
        );
        assert_eq!(node.slot(association).unwrap().last_activity_us, 600);
    }

    #[test]
    fn repeated_blocked_bearer_retry_preserves_packet_and_acceptance_identity() {
        use core::cell::Cell;

        struct RejectRepeatedly(Cell<u8>);

        impl PacketEgress<[u8; 8]> for RejectRepeatedly {
            fn submit(
                &mut self,
                peer: PeerL2Address,
                submission: EgressSubmission<[u8; 8]>,
            ) -> Result<(), PacketSubmitError<[u8; 8]>> {
                assert_eq!(peer, PeerL2Address::new(1).unwrap());
                assert_eq!(submission.packet().packet_range(), 2..6);
                assert_eq!(submission.packet().bytes(), &[2, 3, 4, 5]);
                let (packet, completion) = submission.into_parts();
                let (mut storage, range) = packet.into_parts();
                // Model an in-place L2 framing attempt. Only headroom changes;
                // the opaque QUIC bytes and completion identity survive retry.
                storage[..2].copy_from_slice(&[9, 8]);
                let packet = OwnedPacket::new(storage, range).unwrap();
                let submission = EgressSubmission::from_parts(packet, completion);
                if self.0.get() < 3 {
                    self.0.set(self.0.get() + 1);
                    Err(PacketSubmitError::WouldBlock(submission))
                } else {
                    submission.complete(crate::PacketSendOutcome::Sent, 0);
                    Ok(())
                }
            }
        }

        let events = Arc::new(CompletionQueue::<[u8; 8]>::new(1));
        let mut registry = BearerRegistry::<[u8; 8], 1>::new();
        let name = crate::BearerName::new("retry").unwrap();
        let id = registry.reserve_id(name).unwrap();
        registry
            .register(
                id,
                crate::BearerInfo {
                    name,
                    max_packet_size: 8,
                    prefix_required: 0,
                    suffix_required: 0,
                    requires_packet_encryption: false,
                    secure_link: false,
                    nominal_bitrate_bps: 0,
                    local_mac: None,
                },
                RejectRepeatedly(Cell::new(0)),
                events.clone(),
            )
            .unwrap();
        let acceptance = PacketAcceptance {
            association: QuicAssociation {
                slot: 2,
                generation: 7,
            },
            packet_number: 19,
        };
        let bearer = registry.get_mut(id).unwrap();

        assert!(!bearer.submit_or_retain(
            PeerL2Address::new(1).unwrap(),
            OwnedPacket::new([0, 1, 2, 3, 4, 5, 6, 7], 2..6).unwrap(),
            Some(acceptance),
        ));
        for _ in 0..2 {
            assert!(events.pop_completion().is_none());
            assert!(bearer.has_pending_submission());
            assert_eq!(bearer.retry_pending(), None);
        }
        assert!(events.pop_completion().is_none());
        assert_eq!(bearer.retry_pending(), Some(acceptance));
        assert!(!bearer.has_pending_submission());
        let completion = events.pop_completion().unwrap();
        assert_eq!(completion.acceptance, Some(acceptance));
        assert_eq!(completion.packet.bytes(), &[2, 3, 4, 5]);
        assert!(events.pop_completion().is_none());
    }

    #[test]
    fn packet_acceptance_reconstructs_truncated_wire_numbers() {
        const PACKET: usize = crate::DEFAULT_MAX_PACKET_SIZE;
        let mut node: QuicNode<TestPool, PACKET> = QuicNode::new(&TEST_POOL);
        let local = cid(0x71);
        let association = node
            .add_client(local, Box::new(ClientAssociation::new(local)))
            .unwrap();
        let mut open_packet = [0u8; PACKET];
        let mut peer_packet = [0u8; 16];
        let slot = node.slot_mut(association).unwrap();
        let Association::Client(client) = &mut slot.state else {
            panic!("association has the requested client role");
        };
        client.connection_mut().start(&mut open_packet).unwrap();
        let peer_packet_len = ShortHeader {
            flags: FLAG_FIXED,
            dcid: local,
            packet_number: 0,
            packet_number_len: 1,
        }
        .encode(&mut peer_packet)
        .unwrap();
        let slot = node.slot_mut(association).unwrap();
        let Association::Client(client) = &mut slot.state else {
            panic!("association has the requested client role");
        };
        client
            .connection_mut()
            .receive_initial_short_header(&peer_packet[..peer_packet_len], 0)
            .unwrap();
        client
            .connection_mut()
            .endpoint_mut()
            .unwrap()
            .next_packet_number = 257;

        let mut encoded = [0u8; 16];
        let encoded_len = ShortHeader {
            flags: FLAG_FIXED,
            dcid: local,
            packet_number: 256,
            packet_number_len: 1,
        }
        .encode(&mut encoded)
        .unwrap();
        let packet = OwnedPacket::new(encoded, 0..encoded_len).unwrap();

        assert_eq!(
            node.packet_acceptance_for(association, &packet),
            Some(PacketAcceptance {
                association,
                packet_number: 256,
            })
        );
    }

    #[test]
    fn stream_identity_includes_association_but_ignores_local_offsets() {
        let association = QuicAssociation {
            slot: 3,
            generation: 9,
        };
        let sent = QuicStream {
            owner: StreamOwner::Association(association),
            id: 4,
            send_offset: 120,
            send_finished: true,
            priority: false,
        };
        let received = QuicStream::incoming(association, 4);
        let other_association = QuicStream::incoming(
            QuicAssociation {
                slot: 3,
                generation: 10,
            },
            4,
        );
        assert!(sent.same_stream(&received));
        assert_eq!(received.association_id(), Some(association));
        assert!(!sent.same_stream(&other_association));
    }

    #[cfg(feature = "tokio")]
    #[test]
    fn separate_host_nodes_use_distinct_local_cid_namespaces() {
        type TestNode = QuicNode<TestPool, { crate::DEFAULT_MAX_PACKET_SIZE }>;
        let mut first: TestNode = QuicNode::new(&TEST_POOL);
        let mut second: TestNode = QuicNode::new(&TEST_POOL);
        assert_ne!(
            first.allocate_local_cid().unwrap(),
            second.allocate_local_cid().unwrap()
        );
    }

    fn short_packet(destination: ConnectionId, output: &mut [u8]) -> usize {
        ShortHeader {
            flags: FLAG_FIXED,
            dcid: destination,
            packet_number: 1,
            packet_number_len: 1,
        }
        .encode(output)
        .unwrap()
    }

    #[test]
    fn relay_packet_pool_reserve_drops_data_before_control() {
        type Pool = crate::packet_pool::PacketPool<4, DEFAULT_PACKET_POOL_SLOT_SIZE>;
        type Node = QuicNode<Pool>;
        static POOL: Pool = Pool::new();
        let receive_cid = cid(0x41);
        let mut node = Node::new(&POOL);
        node.set_limits(NodeLimits::embedded()).unwrap();
        node.register_forward(
            receive_cid,
            ForwardRule {
                next_hop: ForwardNextHop {
                    bearer: BearerId::new(1).unwrap(),
                    peer_l2_address: PeerL2Address::new(2).unwrap(),
                },
                destination: ForwardDestination::Connection(cid(0x42)),
                lease_duration_us: 1_000_000,
                lease_expires_at_us: 1_000_000,
                lease_group_id: 0,
                packet_quota: 5,
                forwarded_packets: 0,
                forwarded_control_packets: 0,
                quota_window_started_us: 0,
            },
        )
        .unwrap();
        let meta = ingress_meta();

        let mut forwarded = Vec::new();
        for packet_number in 0..2 {
            let mut bytes = [0u8; 128];
            let mut used = ShortHeader {
                flags: FLAG_FIXED,
                dcid: receive_cid,
                packet_number,
                packet_number_len: 1,
            }
            .encode(&mut bytes)
            .unwrap();
            used += crate::Frame::Stream(crate::StreamFrame {
                id: 0,
                offset: u64::from(packet_number),
                fin: false,
                data: &[1],
            })
            .encode(&mut bytes[used..])
            .unwrap();
            match node
                .receive_packet(
                    meta,
                    OwnedPacket::new(bytes, 0..used).unwrap(),
                    |_| None,
                    |_, _, _, _, payload| Ok(payload.len()),
                )
                .unwrap()
            {
                NodeIngress::Forward { packet, .. } => forwarded.push(packet),
                _ => panic!("data should forward while above reserve"),
            }
        }
        assert_eq!(node.available_packets(), 2);

        let mut data = [0u8; 128];
        let mut data_len = short_packet(receive_cid, &mut data);
        data_len += crate::Frame::Stream(crate::StreamFrame {
            id: 0,
            offset: 2,
            fin: false,
            data: &[2],
        })
        .encode(&mut data[data_len..])
        .unwrap();
        assert!(matches!(
            node.receive_packet(
                meta,
                OwnedPacket::new(data, 0..data_len).unwrap(),
                |_| None,
                |_, _, _, _, payload| Ok(payload.len()),
            )
            .unwrap(),
            NodeIngress::Unknown { .. }
        ));
        assert_eq!(node.available_packets(), 2);

        let mut control = [0u8; 128];
        let mut control_len = short_packet(receive_cid, &mut control);
        control_len += crate::Frame::MaxData(32)
            .encode(&mut control[control_len..])
            .unwrap();
        match node
            .receive_packet(
                meta,
                OwnedPacket::new(control, 0..control_len).unwrap(),
                |_| None,
                |_, _, _, _, payload| Ok(payload.len()),
            )
            .unwrap()
        {
            NodeIngress::Forward { packet, .. } => forwarded.push(packet),
            _ => panic!("control packet should be admitted from reserve"),
        }
        assert_eq!(node.available_packets(), 1);
        assert_eq!(forwarded.len(), 3);
        let target = node.router.target(&data[..data_len]).unwrap();
        let RouterTarget::Forward(rule) = target else {
            panic!("forward rule remains installed");
        };
        assert_eq!(rule.forwarded_control_packets, 1);
    }

    #[test]
    fn established_ingress_does_not_consume_server_connection_ids() {
        const PACKET: usize = 256;
        const SLOT: usize = PACKET_PREFIX_RESERVE + PACKET + PACKET_SUFFIX_RESERVE;
        type Pool = crate::packet_pool::PacketPool<2, SLOT>;
        type Node = QuicNode<Pool, PACKET>;
        static POOL: Pool = Pool::new();

        let mut node = Node::new(&POOL);
        let first_server_cid = node.next_local_cid;
        for client_cid in [cid(0x31), cid(0x32)] {
            if client_cid == cid(0x32) {
                for packet_number in 0..1_000_u32 {
                    let mut bytes = [0u8; PACKET];
                    let used = ShortHeader {
                        flags: FLAG_FIXED,
                        dcid: ConnectionId::new(first_server_cid).unwrap(),
                        packet_number,
                        packet_number_len: 2,
                    }
                    .encode(&mut bytes)
                    .unwrap();
                    let used = used + crate::Frame::Ping.encode(&mut bytes[used..]).unwrap();
                    let ingress = node
                        .receive_packet(
                            ingress_meta(),
                            OwnedPacket::new(bytes, 0..used).unwrap(),
                            |_| None,
                            |_, _, _, _, data| Ok(data.len()),
                        )
                        .unwrap();
                    assert!(matches!(ingress, NodeIngress::Association { .. }));
                }
            }
            let mut bytes = [0u8; PACKET];
            let used = crate::encode_bootstrap_open_packet(client_cid, 0, &mut bytes).unwrap();
            let ingress = node
                .receive_packet(
                    ingress_meta(),
                    OwnedPacket::new(bytes, 0..used).unwrap(),
                    |_| {
                        Some(InitialAdmission {
                            local_limits: ConnectionLimits::default(),
                        })
                    },
                    |_, _, _, _, data| Ok(data.len()),
                )
                .unwrap();
            let NodeIngress::Initial {
                association,
                response,
            } = ingress
            else {
                panic!("Initial must be admitted");
            };
            let expected =
                ConnectionId::new(first_server_cid + u64::from(client_cid == cid(0x32))).unwrap();
            assert_eq!(node.receive_cid(association), Some(expected));
            drop(response);
        }
    }

    #[test]
    fn established_fast_dispatch_matches_full_dispatch() {
        type Pool = crate::packet_pool::PacketPool<4, DEFAULT_PACKET_POOL_SLOT_SIZE>;
        static FAST_POOL: Pool = Pool::new();
        static SLOW_POOL: Pool = Pool::new();
        let mut fast = QuicNode::<Pool>::new(&FAST_POOL);
        let mut slow = QuicNode::<Pool>::new(&SLOW_POOL);
        let mut bytes = [0u8; crate::DEFAULT_MAX_PACKET_SIZE];
        let len = crate::encode_bootstrap_open_packet(cid(0x91), 0, &mut bytes).unwrap();
        for node in [&mut fast, &mut slow] {
            drop(
                node.accept_initial(
                    ingress_meta(),
                    &bytes[..len],
                    cid(0x92),
                    ConnectionLimits::default(),
                )
                .unwrap(),
            );
        }
        for packet_number in [0, 1, 1, 2] {
            let mut len = ShortHeader {
                flags: FLAG_FIXED,
                dcid: cid(0x92),
                packet_number,
                packet_number_len: 2,
            }
            .encode(&mut bytes)
            .unwrap();
            len += crate::Frame::Ping.encode(&mut bytes[len..]).unwrap();
            let packet = || OwnedPacket::new(bytes, 0..len).unwrap();
            let a = fast
                .receive_packet(
                    ingress_meta(),
                    packet(),
                    |_| None,
                    |_, _, _, _, data| Ok(data.len()),
                )
                .unwrap();
            let b = slow
                .receive_packet_slow(
                    ingress_meta(),
                    packet(),
                    |_| None,
                    |_, _, _, _, data| Ok(data.len()),
                )
                .unwrap();
            assert!(matches!(a, NodeIngress::Association { .. }));
            assert!(matches!(b, NodeIngress::Association { .. }));
            assert_eq!(fast.clock_us, slow.clock_us);
            assert_eq!(fast.next_local_cid, slow.next_local_cid);
        }
    }

    fn ingress_meta() -> PacketMeta {
        PacketMeta {
            bearer: BearerId::new(1).unwrap(),
            peer_l2_address: PeerL2Address::new(9).unwrap(),
            received_at_us: 1,
        }
    }

    #[test]
    fn second_association_spills_storage_to_heap() {
        let mut node = QuicNode::<TestPool>::new(&TEST_POOL);
        assert!(!node.associations.spilled());

        node.add_client(cid(1), Box::new(ClientAssociation::new(cid(1))))
            .unwrap();
        assert!(!node.associations.spilled());

        node.add_client(cid(2), Box::new(ClientAssociation::new(cid(2))))
            .unwrap();
        assert!(node.associations.spilled());
        assert_eq!(node.association_count(), 2);
    }

    #[test]
    fn association_event_queue_reports_overflow_without_growing_past_capacity() {
        let mut node = QuicNode::<TestPool>::new(&TEST_POOL);
        node.set_limits(NodeLimits {
            max_associations: 2,
            max_routes: 2,
            ..NodeLimits::host()
        })
        .unwrap();
        let association = QuicAssociation {
            slot: 0,
            generation: 1,
        };
        let capacity = 2 * crate::MAX_PATH_STATES * 4;
        for code in 1..=capacity as u64 + 1 {
            node.push_association_event(AssociationEvent::Closed { association, code });
        }
        assert_eq!(node.association_events.len(), capacity);
        assert_eq!(
            node.next_association_event(),
            Some(AssociationEvent::EventsDropped { count: 1 })
        );
        assert_eq!(
            node.next_association_event(),
            Some(AssociationEvent::Closed {
                association,
                code: 2,
            })
        );
        assert_eq!(
            node.next_association_event(),
            Some(AssociationEvent::Closed {
                association,
                code: 3,
            })
        );
    }

    #[test]
    fn removing_an_association_invalidates_its_generation_checked_id() {
        let mut node = QuicNode::<TestPool>::new(&TEST_POOL);
        let first = node
            .add_client(cid(1), Box::new(ClientAssociation::new(cid(1))))
            .unwrap();
        assert!(node.remove_client(first).is_ok());
        assert_eq!(node.association_count(), 0);

        let second = node
            .add_client(cid(2), Box::new(ClientAssociation::new(cid(2))))
            .unwrap();
        assert_ne!(first, second);
        assert!(node.client(first).is_none());
        assert!(node.client(second).is_some());
    }

    #[test]
    fn cid_collision_does_not_install_or_replace_association_state() {
        let mut node = QuicNode::<TestPool>::new(&TEST_POOL);
        let client = node
            .add_client(cid(1), Box::new(ClientAssociation::new(cid(1))))
            .unwrap();
        assert_eq!(
            node.add_client(cid(1), Box::new(ClientAssociation::new(cid(2)))),
            Err(QuicNodeError::Routing)
        );
        assert_eq!(node.association_count(), 1);
        assert!(node.client(client).is_some());
    }

    #[test]
    fn wrong_role_removal_leaves_association_installed() {
        let mut node = QuicNode::<TestPool>::new(&TEST_POOL);
        let client = node
            .add_client(cid(1), Box::new(ClientAssociation::new(cid(1))))
            .unwrap();
        assert!(!node.remove_forward(cid(1)));
        assert!(matches!(
            node.remove_server(client),
            Err(QuicNodeError::WrongAssociationRole)
        ));
        assert!(node.client(client).is_some());
    }

    #[test]
    fn bearer_borrows_packet_storage_from_the_node_pool() {
        static BORROW_POOL: TestPool = TestPool::new();
        let node = QuicNode::<TestPool>::new(&BORROW_POOL);
        assert_eq!(node.packet_capacity(), 1);
        let writer = node
            .acquire_packet_writer(PACKET_PREFIX_RESERVE)
            .expect("one node-owned packet slot");
        assert_eq!(node.available_packets(), 0);
        assert!(node.acquire_packet_writer(PACKET_PREFIX_RESERVE).is_none());
        drop(writer);
        assert_eq!(node.available_packets(), 1);
    }

    #[test]
    fn association_ingress_routes_by_dcid_and_tracks_complete_return_addresses() {
        const PACKET: usize = 256;
        const SLOT: usize = PACKET_PREFIX_RESERVE + PACKET + PACKET_SUFFIX_RESERVE;
        type Pool = crate::packet_pool::PacketPool<2, SLOT>;
        type Node = QuicNode<Pool, PACKET>;
        static POOL: Pool = Pool::new();

        let udp = PacketMeta {
            bearer: BearerId::new(1).unwrap(),
            peer_l2_address: PeerL2Address::new(7).unwrap(),
            received_at_us: 10,
        };
        let uart = PacketMeta {
            bearer: BearerId::new(2).unwrap(),
            peer_l2_address: PeerL2Address::new(7).unwrap(),
            received_at_us: 20,
        };
        let client_cid = cid(0x31);
        let mut node = Node::new(&POOL);
        let open = node.start_association(client_cid, udp, 0).unwrap();
        let association = open.association;
        let mut server_node = Node::new(&POOL);
        let (server_association, ack) = match server_node
            .receive_packet(
                uart,
                open.packet,
                |_| {
                    Some(InitialAdmission {
                        local_limits: ConnectionLimits::default(),
                    })
                },
                |_, _, _, _, bytes| Ok(bytes.len()),
            )
            .unwrap()
        {
            NodeIngress::Initial {
                association,
                response,
            } => (association, response),
            _ => panic!("Initial must be admitted by unified ingress"),
        };
        assert_eq!(server_node.server(server_association).is_some(), true);
        let ack_bytes = ack.packet.bytes().to_vec();

        let (ingress, packet) = match node
            .receive_packet(
                udp,
                ack.packet,
                |_| None,
                |_, _, _, _, bytes| Ok(bytes.len()),
            )
            .unwrap()
        {
            NodeIngress::Association {
                association,
                packet,
            } => (association, packet),
            _ => panic!("OPEN_ACK must reach its client association"),
        };
        assert_eq!(ingress, AssociationIngress::Client(association));
        assert_eq!(packet.bytes(), ack_bytes);
        assert_eq!(
            node.association_egress_address(association),
            Some((udp.bearer, udp.peer_l2_address))
        );

        // A duplicate OPEN_ACK on another bearer must not move the active
        // return address or reorder the known path addresses.
        let mut duplicate_storage = [0u8; PACKET];
        duplicate_storage[..ack_bytes.len()].copy_from_slice(&ack_bytes);
        node.receive_packet(
            uart,
            OwnedPacket::new(duplicate_storage, 0..ack_bytes.len()).unwrap(),
            |_| None,
            |_, _, _, _, bytes| Ok(bytes.len()),
        )
        .unwrap();
        assert_eq!(
            node.association_egress_address(association),
            Some((udp.bearer, udp.peer_l2_address))
        );
        assert_eq!(
            node.association_addresses(association).unwrap(),
            &[(udp.bearer, udp.peer_l2_address)]
        );

        let mut fresh = [0u8; PACKET];
        let header_len = ShortHeader {
            flags: FLAG_FIXED,
            dcid: client_cid,
            packet_number: 10,
            packet_number_len: 1,
        }
        .encode(&mut fresh)
        .unwrap();
        let frame_len = Frame::Ping.encode(&mut fresh[header_len..]).unwrap();
        let fresh_len = header_len + frame_len;
        node.receive_packet(
            uart,
            OwnedPacket::new(fresh, 0..fresh_len).unwrap(),
            |_| None,
            |_, _, _, _, bytes| Ok(bytes.len()),
        )
        .unwrap();
        assert_eq!(
            node.association_egress_address(association),
            Some((uart.bearer, uart.peer_l2_address))
        );

        let late = PacketMeta {
            bearer: BearerId::new(3).unwrap(),
            peer_l2_address: PeerL2Address::new(55).unwrap(),
            received_at_us: 30,
        };
        let mut reordered = [0u8; PACKET];
        let header_len = ShortHeader {
            flags: FLAG_FIXED,
            dcid: client_cid,
            packet_number: 9,
            packet_number_len: 1,
        }
        .encode(&mut reordered)
        .unwrap();
        let frame_len = Frame::Ping.encode(&mut reordered[header_len..]).unwrap();
        let reordered_len = header_len + frame_len;
        node.receive_packet(
            late,
            OwnedPacket::new(reordered, 0..reordered_len).unwrap(),
            |_| None,
            |_, _, _, _, bytes| Ok(bytes.len()),
        )
        .unwrap();
        assert_eq!(
            node.association_egress_address(association),
            Some((uart.bearer, uart.peer_l2_address))
        );
        assert!(
            !node
                .association_addresses(association)
                .unwrap()
                .contains(&(late.bearer, late.peer_l2_address))
        );

        let mut wrong = [0u8; PACKET];
        let wrong_len = short_packet(cid(0x99), &mut wrong);
        let unknown = node
            .receive_packet(
                udp,
                OwnedPacket::new(wrong, 0..wrong_len).unwrap(),
                |_| None,
                |_, _, _, _, bytes| Ok(bytes.len()),
            )
            .unwrap();
        assert!(matches!(
            unknown,
            NodeIngress::Unknown { destination, packet }
                if destination == cid(0x99) && packet.packet_range() == (0..wrong_len)
        ));
        assert_eq!(
            node.association_egress_address(association),
            Some((uart.bearer, uart.peer_l2_address))
        );
    }

    #[test]
    fn ingress_address_updates_only_the_selected_path() {
        const PACKET: usize = 256;
        const SLOT: usize = PACKET_PREFIX_RESERVE + PACKET + PACKET_SUFFIX_RESERVE;
        type Pool = crate::packet_pool::PacketPool<2, SLOT>;
        type Node = QuicNode<Pool, PACKET>;
        static POOL: Pool = Pool::new();

        let primary = PacketMeta {
            bearer: BearerId::new(1).unwrap(),
            peer_l2_address: PeerL2Address::new(7).unwrap(),
            received_at_us: 10,
        };
        let mut node = Node::new(&POOL);
        let initial = node.start_association(cid(0x71), primary, 0).unwrap();
        let association = initial.association;
        let mut peer = Node::new(&POOL);
        let response = match peer
            .receive_packet(
                primary,
                initial.packet,
                |_| {
                    Some(InitialAdmission {
                        local_limits: ConnectionLimits::default(),
                    })
                },
                |_, _, _, _, bytes| Ok(bytes.len()),
            )
            .unwrap()
        {
            NodeIngress::Initial { response, .. } => response,
            _ => panic!("initial association must be accepted"),
        };
        node.receive_packet(
            primary,
            response.packet,
            |_| None,
            |_, _, _, _, bytes| Ok(bytes.len()),
        )
        .unwrap();
        let alternate = PacketMeta {
            bearer: BearerId::new(2).unwrap(),
            peer_l2_address: PeerL2Address::new(8).unwrap(),
            received_at_us: 20,
        };
        let path_id = {
            let slot = node.slot_mut(association).unwrap();
            let Association::Client(client) = &mut slot.state else {
                unreachable!()
            };
            let endpoint = client.connection_mut().endpoint_mut().unwrap();
            endpoint.add_path_state_with_local_id(cid(0x72)).unwrap()
        };
        node.remember_ingress_path_address(association, path_id, alternate, true);

        let unknown_source = PacketMeta {
            bearer: BearerId::new(3).unwrap(),
            peer_l2_address: PeerL2Address::new(9).unwrap(),
            received_at_us: 30,
        };
        node.remember_address(association, unknown_source);

        assert_eq!(
            node.association_egress_address(association),
            Some((primary.bearer, primary.peer_l2_address))
        );
        assert_eq!(
            node.slot(association)
                .and_then(|slot| Node::slot_path_state(slot, path_id))
                .and_then(crate::PathState::active_address),
            Some((alternate.bearer, alternate.peer_l2_address))
        );
    }

    #[test]
    fn path_cids_route_both_directions_to_one_association() {
        struct DropIngress;

        impl<B: AsRef<[u8]> + Send> crate::bearer::PacketIngressQueue<B> for DropIngress {
            fn enqueue_packet(&self, _meta: PacketMeta, _packet: OwnedPacket<B>) {}
        }

        const PACKET: usize = 256;
        const SLOT: usize = PACKET_PREFIX_RESERVE + PACKET + PACKET_SUFFIX_RESERVE;
        type Pool = crate::packet_pool::PacketPool<8, SLOT>;
        type Node = QuicNode<Pool, PACKET>;
        static POOL: Pool = Pool::new();

        let meta = ingress_meta();
        let mut client_node = Node::new(&POOL);
        let mut server_node = Node::new(&POOL);
        let original_bearer = crate::fake::FakePacketBearer::<Pool>::new(
            crate::BearerName::new("multi-primary").unwrap(),
        );
        let original_capture = original_bearer.sent_packets();
        let ingress: Arc<
            dyn crate::bearer::PacketIngressQueue<<Pool as crate::bearer::PacketPool>::Buffer>,
        > = Arc::new(DropIngress);
        assert_eq!(
            client_node
                .register_bearer_with_ingress(original_bearer, ingress.clone())
                .unwrap(),
            meta.bearer
        );
        let duplicate_bearer = crate::fake::FakePacketBearer::<Pool>::new(
            crate::BearerName::new("multi-second").unwrap(),
        );
        let duplicate_capture = duplicate_bearer.sent_packets();
        let secondary_bearer = client_node
            .register_bearer_with_ingress(duplicate_bearer, ingress.clone())
            .unwrap();
        let server_primary = crate::fake::FakePacketBearer::<Pool>::new(
            crate::BearerName::new("srv-primary").unwrap(),
        );
        let server_primary_capture = server_primary.sent_packets();
        assert_eq!(
            server_node
                .register_bearer_with_ingress(server_primary, ingress.clone())
                .unwrap(),
            meta.bearer
        );
        let server_secondary = crate::fake::FakePacketBearer::<Pool>::new(
            crate::BearerName::new("srv-second").unwrap(),
        );
        let server_secondary_capture = server_secondary.sent_packets();
        assert_eq!(
            server_node
                .register_bearer_with_ingress(server_secondary, ingress)
                .unwrap(),
            secondary_bearer
        );
        let probe_interval_us = 7_000_000;
        let mut association_limits = client_node.default_association_limits();
        association_limits.path_probe_interval_us = probe_interval_us;
        association_limits.pacing.enabled = false;
        client_node
            .set_default_association_limits(association_limits)
            .unwrap();
        let mut server_limits = server_node.default_association_limits();
        server_limits.pacing.enabled = false;
        server_node
            .set_default_association_limits(server_limits)
            .unwrap();
        let open = client_node.start_association(cid(0x81), meta, 0).unwrap();
        let client = open.association;
        let (server, response) = match server_node
            .receive_packet(
                meta,
                open.packet,
                |_| {
                    Some(InitialAdmission {
                        local_limits: ConnectionLimits::default(),
                    })
                },
                |_, _, _, _, bytes| Ok(bytes.len()),
            )
            .unwrap()
        {
            NodeIngress::Initial {
                association,
                response,
            } => (association, response.packet),
            _ => panic!("Initial must establish the direct association"),
        };
        client_node
            .receive_packet(
                meta,
                response,
                |_| None,
                |_, _, _, _, bytes| Ok(bytes.len()),
            )
            .unwrap();

        let path_address = (secondary_bearer, PeerL2Address::new(0x44).unwrap());
        let (key, join) = client_node.open_direct_path(client, path_address).unwrap();
        assert_eq!(key.opener_role, crate::Role::Client);
        assert_eq!(key.sequence, 1);
        let client_path = 1;
        let client_path_cid = client_node
            .client(client)
            .unwrap()
            .connection()
            .endpoint()
            .unwrap()
            .local_connection_id_on_path(client_path)
            .unwrap();
        let mut opening_circuits = [CircuitInfo::default(); crate::MAX_PATH_STATES];
        assert_eq!(client_node.circuits(client, &mut opening_circuits), 2);
        assert_eq!(opening_circuits[1].status, CircuitStatus::Opening);
        assert!(matches!(
            client_node.close_circuit(opening_circuits[1].id),
            Err(QuicNodeEgressError::CircuitBusy)
        ));
        let join_result = server_node
            .receive_packet(
                PacketMeta {
                    bearer: path_address.0,
                    peer_l2_address: path_address.1,
                    ..meta
                },
                join.packet,
                |_| None,
                |_, _, _, _, bytes| Ok(bytes.len()),
            )
            .unwrap();
        let lost_join_ack = match join_result {
            NodeIngress::PathControl {
                association,
                response,
            } => {
                assert_eq!(association, server);
                response
            }
            _ => panic!("PATH_JOIN must install a path and return PATH_JOIN_ACK"),
        };
        drop(lost_join_ack);
        for _ in 0..(crate::MAX_PATH_JOIN_ATTEMPTS - 2) {
            drop(client_node.retry_direct_path(client, key).unwrap());
        }
        let retry = client_node.retry_direct_path(client, key).unwrap();
        assert!(matches!(
            client_node.retry_direct_path(client, key),
            Err(QuicNodeEgressError::PathSetupAttemptsExhausted)
        ));
        let retry_result = server_node
            .receive_packet(
                PacketMeta {
                    bearer: path_address.0,
                    peer_l2_address: path_address.1,
                    ..meta
                },
                retry.packet,
                |_| None,
                |_, _, _, _, bytes| Ok(bytes.len()),
            )
            .unwrap();
        let join_ack = match retry_result {
            NodeIngress::PathControl {
                association,
                response,
            } => {
                assert_eq!(association, server);
                response
            }
            _ => panic!("retry must reuse the existing path and replay PATH_JOIN_ACK"),
        };
        assert_eq!(
            server_node
                .server(server)
                .unwrap()
                .mux
                .endpoint
                .path_count(),
            2
        );
        assert_eq!(join_ack.peer_l2_address, path_address.1);
        let (join_ack_header, join_ack_header_len) =
            ShortHeader::decode(join_ack.packet.bytes()).unwrap();
        assert_eq!(join_ack_header.dcid, client_path_cid);
        let (join_ack_frame, _) =
            crate::decode_frame(&join_ack.packet.bytes()[join_ack_header_len..]).unwrap();
        let server_path_cid = match join_ack_frame {
            Frame::PathJoinAck {
                key: ack_key,
                transaction_id: 1,
                receive_cid,
            } if ack_key == key => receive_cid,
            _ => panic!("join ACK must echo the transaction and server receive CID"),
        };
        client_node
            .receive_packet(
                PacketMeta {
                    bearer: path_address.0,
                    peer_l2_address: path_address.1,
                    ..meta
                },
                join_ack.packet,
                |_| None,
                |_, _, _, _, bytes| Ok(bytes.len()),
            )
            .unwrap();
        let server_path = 1;
        let confirmation = client_node
            .poll_association_control(client)
            .unwrap()
            .expect("join ACK triggers a same-path confirmation ACK");
        assert_eq!(confirmation.peer_l2_address, path_address.1);
        assert_eq!(
            ShortHeader::decode(confirmation.packet.bytes())
                .unwrap()
                .0
                .dcid,
            server_path_cid
        );
        server_node
            .receive_packet(
                PacketMeta {
                    bearer: path_address.0,
                    peer_l2_address: path_address.1,
                    ..meta
                },
                confirmation.packet,
                |_| None,
                |_, _, _, _, bytes| Ok(bytes.len()),
            )
            .unwrap();
        assert!(
            Node::slot_path_state(server_node.slot(server).unwrap(), server_path)
                .unwrap()
                .is_validated()
        );
        assert!(
            Node::slot_path_state(client_node.slot(client).unwrap(), client_path)
                .unwrap()
                .is_validated()
        );
        let mut client_circuits = [CircuitInfo::default(); crate::MAX_PATH_STATES];
        let mut server_circuits = [CircuitInfo::default(); crate::MAX_PATH_STATES];
        assert_eq!(client_node.circuits(client, &mut client_circuits), 2);
        assert_eq!(server_node.circuits(server, &mut server_circuits), 2);
        assert_eq!(client_circuits[1].status, CircuitStatus::Active);
        assert_eq!(server_circuits[1].status, CircuitStatus::Active);
        assert!(!client_circuits[1].opened_by_peer);
        assert!(server_circuits[1].opened_by_peer);
        assert_eq!(client_circuits[1].first_hop.bearer, path_address.0);
        assert_eq!(client_circuits[1].first_hop.peer_l2_address, path_address.1);
        let probe_deadline = client_node.next_deadline().unwrap();
        assert_eq!(probe_deadline, probe_interval_us + 1);
        if let Association::Client(client_state) = &mut client_node.slot_mut(client).unwrap().state
        {
            let endpoint = client_state.connection_mut().endpoint_mut().unwrap();
            endpoint.set_duplication_budget_capacity(4096);
            endpoint.duplication_credit_bytes = 4096;
        }
        let probe = match client_node.timer_expired(probe_deadline).unwrap().unwrap() {
            NodeTimer::Egress(packet) => packet,
            _ => panic!("due path probe must produce egress"),
        };
        assert_eq!(probe.packet.bytes().len(), PACKET);
        let probe_bytes = probe.packet.bytes().to_vec();
        assert_eq!(
            Node::slot_path_state(client_node.slot(client).unwrap(), client_path)
                .unwrap()
                .congestion
                .bytes_in_flight,
            PACKET as u64
        );
        client_node.circuits(client, &mut client_circuits);
        assert_eq!(client_circuits[1].probe_bytes_prepared, PACKET as u64);
        client_node.submit_node_packet(probe).unwrap();
        assert!(matches!(
            &client_node.slot(client).unwrap().state,
            Association::Client(client_state)
                if client_state.connection().endpoint().unwrap().duplication_credit_bytes
                    == 4096 - PACKET as u64
                    && client_state.connection().endpoint().unwrap().duplication_reserved_bytes == 0
        ));
        let challenge_meta = PacketMeta {
            received_at_us: probe_deadline,
            bearer: path_address.0,
            peer_l2_address: path_address.1,
        };
        let mut replayed_probe_buffer = [0u8; PACKET];
        let replayed_probe_len = probe_bytes.len();
        replayed_probe_buffer[..replayed_probe_len].copy_from_slice(&probe_bytes);
        let mut challenge_storage = [0u8; PACKET];
        challenge_storage[..probe_bytes.len()].copy_from_slice(&probe_bytes);
        let response = match server_node
            .receive_packet(
                challenge_meta,
                OwnedPacket::new(challenge_storage, 0..probe_bytes.len()).unwrap(),
                |_| None,
                |_, _, _, _, bytes| Ok(bytes.len()),
            )
            .unwrap()
        {
            NodeIngress::PathControl { response, .. } => response,
            _ => panic!("PATH_CHALLENGE must produce a same-path PATH_RESPONSE"),
        };
        let response_bytes = response.packet.bytes().to_vec();
        server_node.circuits(server, &mut server_circuits);
        assert_eq!(
            server_circuits[1].probe_bytes_prepared,
            response_bytes.len() as u64
        );
        server_node.submit_node_packet(response).unwrap();
        let mut response_storage = [0u8; PACKET];
        response_storage[..response_bytes.len()].copy_from_slice(&response_bytes);
        let replayed_probe = server_node
            .receive_packet(
                PacketMeta {
                    received_at_us: probe_deadline + 1,
                    ..challenge_meta
                },
                OwnedPacket::new(replayed_probe_buffer, 0..replayed_probe_len).unwrap(),
                |_| None,
                |_, _, _, _, bytes| Ok(bytes.len()),
            )
            .unwrap();
        assert!(matches!(replayed_probe, NodeIngress::Association { .. }));
        server_node.circuits(server, &mut server_circuits);
        assert_eq!(
            server_circuits[1].probe_bytes_prepared,
            response_bytes.len() as u64
        );
        assert_eq!(server_circuits[1].probe_bytes_budgeted, 0);
        assert_eq!(
            server_circuits[1].probe_bytes_idle_exempt,
            response_bytes.len() as u64
        );
        let rtt_meta = PacketMeta {
            received_at_us: probe_deadline + 60_000,
            ..challenge_meta
        };
        client_node
            .receive_packet(
                rtt_meta,
                OwnedPacket::new(response_storage, 0..response_bytes.len()).unwrap(),
                |_| None,
                |_, _, _, _, bytes| Ok(bytes.len()),
            )
            .unwrap();
        client_node.circuits(client, &mut client_circuits);
        assert_eq!(client_circuits[1].srtt_us, 60_000);
        assert_eq!(client_circuits[1].probe_bytes_budgeted, PACKET as u64);
        assert_eq!(client_circuits[1].probe_bytes_idle_exempt, 0);
        assert_eq!(client_circuits[1].bytes_in_flight, PACKET as u32);
        server_node.advance_clock(probe_deadline + 60_000);
        let probe_ack = server_node
            .poll_association_control(server)
            .unwrap()
            .expect("receiver ACKs the padded path probe on its ingress circuit");
        client_node
            .receive_packet(
                PacketMeta {
                    received_at_us: probe_deadline + 60_000,
                    ..challenge_meta
                },
                probe_ack.packet,
                |_| None,
                |_, _, _, _, bytes| Ok(bytes.len()),
            )
            .unwrap();
        client_node.circuits(client, &mut client_circuits);
        assert_eq!(client_circuits[1].bytes_in_flight, 0);
        assert_eq!(client_circuits[1].srtt_us, 60_000);

        // Accepted original stream traffic earns duplication credit. Bulk
        // packets stay single-path; once the final FIN packet's copy fits the
        // 10% bucket, the node schedules it on the cheapest usable alternate.
        original_capture.lock().unwrap().clear();
        duplicate_capture.lock().unwrap().clear();
        if let Association::Client(client_state) = &mut client_node.slot_mut(client).unwrap().state
        {
            client_state
                .connection_mut()
                .endpoint_mut()
                .unwrap()
                .duplication_credit_bytes = 0;
        }
        let budget_stream = client_node.allocate_stream(client).unwrap();
        for index in 0..11_u64 {
            let packet = client_node
                .send_stream_on_path(
                    client,
                    0,
                    budget_stream,
                    index * 100,
                    index == 10,
                    &[0x5a; 100],
                )
                .unwrap();
            client_node.submit_node_packet(packet).unwrap();
        }
        let original_packets = original_capture.lock().unwrap().clone();
        let duplicate_packets = duplicate_capture.lock().unwrap().clone();
        assert_eq!(original_packets.len(), 11);
        assert_eq!(duplicate_packets.len(), 1);
        client_node.circuits(client, &mut client_circuits);
        assert_eq!(
            client_circuits[1].duplicate_bytes_prepared,
            duplicate_packets[0].len() as u64
        );
        let server_primary_cid = server_node
            .slot(server)
            .and_then(|slot| match &slot.state {
                Association::Server(server) => server.mux.endpoint.local_connection_id_on_path(0),
                Association::Client(_) => None,
            })
            .unwrap();
        for (bytes, default_path) in original_packets
            .iter()
            .map(|packet| (packet, true))
            .chain(duplicate_packets.iter().map(|packet| (packet, false)))
        {
            let (header, _) = ShortHeader::decode(bytes).unwrap();
            let receive_meta = if default_path {
                meta
            } else {
                PacketMeta {
                    bearer: path_address.0,
                    peer_l2_address: path_address.1,
                    received_at_us: probe_deadline + 60_001,
                }
            };
            assert_eq!(
                header.dcid,
                if default_path {
                    server_primary_cid
                } else {
                    server_path_cid
                }
            );
            let mut storage = [0u8; PACKET];
            storage[..bytes.len()].copy_from_slice(bytes);
            server_node
                .receive_packet(
                    receive_meta,
                    OwnedPacket::new(storage, 0..bytes.len()).unwrap(),
                    |_| None,
                    |_, _, _, _, payload| Ok(payload.len()),
                )
                .unwrap();
        }

        let sent_before_two_stream_packets = [
            client_circuits[0].packets_sent,
            client_circuits[1].packets_sent,
        ];

        let stream = client_node.allocate_stream(client).unwrap();
        let client_circuit = client_circuits[1].id;
        let data_start_us = probe_deadline + 80_000;
        if let Association::Client(client_state) = &mut client_node.slot_mut(client).unwrap().state
        {
            client_state
                .connection_mut()
                .endpoint_mut()
                .unwrap()
                .set_time(data_start_us);
        }
        let fast_packet = client_node
            .send_stream_on_path(client, 0, stream, 0, false, b"on path ")
            .unwrap();
        let fast_packet_number = ShortHeader::decode(fast_packet.packet.bytes())
            .unwrap()
            .0
            .packet_number;
        if let Association::Client(client_state) = &client_node.slot(client).unwrap().state {
            let endpoint = client_state.connection().endpoint().unwrap();
            let sent = endpoint
                .sent_packets
                .iter()
                .flatten()
                .find(|sent| sent.packet_number == fast_packet_number)
                .unwrap();
            assert!(sent.rtt_eligible, "fast packet must be RTT-eligible");
        }
        let slow_packet = client_node
            .send_stream_on_path(client, client_path, stream, 8, true, b"two")
            .unwrap();
        // Check refusal while stream data is actually outstanding. Once
        // ACKed, close_circuit starts abandonment (and still returns Busy
        // until that exchange completes), so it is not a read-only probe.
        assert!(matches!(
            client_node.close_circuit(client_circuit),
            Err(QuicNodeEgressError::CircuitBusy)
        ));
        let sent_bytes = slow_packet.packet.bytes().to_vec();
        assert_ne!(
            ShortHeader::decode(fast_packet.packet.bytes())
                .unwrap()
                .0
                .dcid,
            ShortHeader::decode(slow_packet.packet.bytes())
                .unwrap()
                .0
                .dcid,
            "the two circuits use independent destination CIDs"
        );
        assert_eq!(
            ShortHeader::decode(slow_packet.packet.bytes())
                .unwrap()
                .0
                .dcid,
            server_path_cid
        );
        let mut sent_circuits = [CircuitInfo::default(); crate::MAX_PATH_STATES];
        client_node.circuits(client, &mut sent_circuits);
        assert_eq!(
            sent_circuits[0].packets_sent,
            sent_before_two_stream_packets[0] + 1
        );
        assert_eq!(
            sent_circuits[1].packets_sent,
            sent_before_two_stream_packets[1] + 1
        );

        let mut delivered = Vec::new();
        let fast_ingress = server_node
            .receive_packet(
                PacketMeta {
                    received_at_us: data_start_us + 10_000,
                    ..meta
                },
                fast_packet.packet,
                |_| None,
                |source, received_stream, offset, fin, bytes| {
                    assert_eq!(source, ApplicationStreamSource::Association(server));
                    assert_eq!(received_stream, stream);
                    assert_eq!(offset, 0);
                    assert!(!fin);
                    delivered.extend_from_slice(bytes);
                    Ok(bytes.len())
                },
            )
            .unwrap();
        assert!(matches!(
            fast_ingress,
            NodeIngress::Association { association, .. }
                if association == AssociationIngress::Server(server)
        ));

        if let Association::Server(server_state) = &mut server_node.slot_mut(server).unwrap().state
        {
            server_state.mux.endpoint.request_path_validation_ack(0);
        }
        let fast_ack = server_node
            .poll_association_control(server)
            .unwrap()
            .expect("the 20 ms path ACKs its delivered prefix");
        let fast_ack_header_len = ShortHeader::decode(fast_ack.packet.bytes()).unwrap().1;
        let fast_ack_frame = crate::decode_frame(&fast_ack.packet.bytes()[fast_ack_header_len..])
            .unwrap()
            .0;
        assert!(matches!(
            fast_ack_frame,
            Frame::AckRanges { ranges, .. } if ranges.contains(fast_packet_number)
        ));
        if let Association::Client(client_state) = &mut client_node.slot_mut(client).unwrap().state
        {
            client_state
                .connection_mut()
                .endpoint_mut()
                .unwrap()
                .set_time(data_start_us + 20_000);
        }
        client_node
            .receive_packet(
                PacketMeta {
                    received_at_us: data_start_us + 20_000,
                    ..meta
                },
                fast_ack.packet,
                |_| None,
                |_, _, _, _, bytes| Ok(bytes.len()),
            )
            .unwrap();
        client_node.circuits(client, &mut sent_circuits);
        assert_eq!(sent_circuits[0].srtt_us, 20_000);
        assert_eq!(sent_circuits[0].packets_lost, 0);
        assert!(sent_circuits[1].bytes_in_flight > 0);

        let slow_ingress = server_node
            .receive_packet(
                PacketMeta {
                    received_at_us: data_start_us + 30_000,
                    bearer: path_address.0,
                    peer_l2_address: path_address.1,
                },
                slow_packet.packet,
                |_| None,
                |source, received_stream, offset, fin, bytes| {
                    assert_eq!(source, ApplicationStreamSource::Association(server));
                    assert_eq!(received_stream, stream);
                    assert_eq!(offset, 8);
                    assert!(fin);
                    delivered.extend_from_slice(bytes);
                    Ok(bytes.len())
                },
            )
            .unwrap();
        assert!(matches!(
            slow_ingress,
            NodeIngress::Association { association, .. }
                if association == AssociationIngress::Server(server)
        ));
        assert_eq!(delivered, b"on path two");
        if let Association::Server(server_state) = &mut server_node.slot_mut(server).unwrap().state
        {
            server_state
                .mux
                .endpoint
                .request_path_validation_ack(server_path);
        }
        let slow_ack = server_node
            .poll_association_control(server)
            .unwrap()
            .expect("the 60 ms path ACKs the stream FIN");
        if let Association::Client(client_state) = &mut client_node.slot_mut(client).unwrap().state
        {
            client_state
                .connection_mut()
                .endpoint_mut()
                .unwrap()
                .set_time(data_start_us + 60_000);
        }
        client_node.circuits(client, &mut sent_circuits);
        client_node
            .receive_packet(
                PacketMeta {
                    received_at_us: data_start_us + 60_000,
                    bearer: path_address.0,
                    peer_l2_address: path_address.1,
                },
                slow_ack.packet,
                |_| None,
                |_, _, _, _, bytes| Ok(bytes.len()),
            )
            .unwrap();
        client_node.circuits(client, &mut sent_circuits);
        assert!(
            (50_000..=60_000).contains(&sent_circuits[1].srtt_us),
            "matched slow-circuit samples retain the slow-path RTT: {} us",
            sent_circuits[1].srtt_us
        );
        assert_eq!(sent_circuits[1].packets_lost, 0);
        assert_eq!(sent_circuits[1].bytes_in_flight, 0);

        // A duplicate needs an immediate ACK. It must use the ingress path's
        // CID and address while acknowledging the association-wide packet set.
        let mut duplicate_storage = [0u8; PACKET];
        duplicate_storage[..sent_bytes.len()].copy_from_slice(&sent_bytes);
        server_node
            .receive_packet(
                PacketMeta {
                    bearer: path_address.0,
                    peer_l2_address: path_address.1,
                    ..meta
                },
                OwnedPacket::new(duplicate_storage, 0..sent_bytes.len()).unwrap(),
                |_| None,
                |_, _, _, _, bytes| Ok(bytes.len()),
            )
            .unwrap();
        assert_eq!(
            Node::slot_path_state(server_node.slot(server).unwrap(), server_path)
                .unwrap()
                .active_address(),
            Some(path_address)
        );
        let ack = server_node
            .poll_association_control(server)
            .unwrap()
            .unwrap();
        assert_eq!(ack.bearer, path_address.0);
        assert_eq!(ack.peer_l2_address, path_address.1);
        assert_eq!(
            ShortHeader::decode(ack.packet.bytes()).unwrap().0.dcid,
            client_path_cid
        );
        let ack_bytes = ack.packet.bytes().to_vec();
        let mut ack_storage = [0u8; PACKET];
        ack_storage[..ack_bytes.len()].copy_from_slice(&ack_bytes);
        client_node
            .receive_packet(
                PacketMeta {
                    bearer: path_address.0,
                    peer_l2_address: path_address.1,
                    ..meta
                },
                OwnedPacket::new(ack_storage, 0..ack_bytes.len()).unwrap(),
                |_| None,
                |_, _, _, _, bytes| Ok(bytes.len()),
            )
            .unwrap();
        assert_eq!(
            Node::slot_path_state(client_node.slot(client).unwrap(), client_path)
                .unwrap()
                .congestion
                .bytes_in_flight,
            0
        );

        let reverse_stream = server_node.allocate_stream(server).unwrap();
        let primary_cid =
            if let Association::Server(server_state) = &server_node.slot(server).unwrap().state {
                let endpoint = &server_state.mux.endpoint;
                // A piggyback ACK can already have retired the alternate's
                // PATH_RESPONSE. Its cost need not exceed the primary's;
                // neither server circuit has a matched RTT sample yet. Test
                // the actual response CID/routing below, not that incidental
                // pre-piggyback ordering of incompletely measured costs.
                assert!(endpoint.path_state(0).unwrap().is_usable_for_data());
                endpoint.peer_connection_id_on_path(0).unwrap()
            } else {
                panic!("the server association must remain installed");
            };
        if let Association::Server(server_state) = &mut server_node.slot_mut(server).unwrap().state
        {
            let endpoint = &mut server_state.mux.endpoint;
            if endpoint.next_packet_number % 2 == 0 {
                endpoint.next_packet_number += 1;
            }
        }
        let response = server_node
            .send_stream(server, reverse_stream, 0, true, b"return path")
            .unwrap();
        assert_eq!(
            ShortHeader::decode(response.packet.bytes()).unwrap().0.dcid,
            primary_cid
        );
        let mut returned = Vec::new();
        let response_meta = PacketMeta {
            bearer: response.bearer,
            peer_l2_address: response.peer_l2_address,
            received_at_us: data_start_us + 70_000,
        };
        client_node
            .receive_packet(
                response_meta,
                response.packet,
                |_| None,
                |_, _, _, _, bytes| {
                    returned.extend_from_slice(bytes);
                    Ok(bytes.len())
                },
            )
            .unwrap();
        assert_eq!(returned, b"return path");
        if let Association::Client(client_state) = &mut client_node.slot_mut(client).unwrap().state
        {
            client_state
                .connection_mut()
                .endpoint_mut()
                .unwrap()
                .request_path_validation_ack(client_path);
        }
        let final_ack = client_node
            .poll_association_control(client)
            .unwrap()
            .unwrap();
        server_node
            .receive_packet(
                PacketMeta {
                    bearer: path_address.0,
                    peer_l2_address: path_address.1,
                    ..meta
                },
                final_ack.packet,
                |_| None,
                |_, _, _, _, bytes| Ok(bytes.len()),
            )
            .unwrap();
        if let Association::Server(server_state) = &mut server_node.slot_mut(server).unwrap().state
        {
            let endpoint = &mut server_state.mux.endpoint;
            endpoint.request_path_validation_ack(server_path);
            endpoint.credit_pending = true;
            endpoint.credit_dirty = true;
            endpoint.duplication_credit_bytes = 4096;
        }
        server_primary_capture.lock().unwrap().clear();
        server_secondary_capture.lock().unwrap().clear();
        let duplicate_ack = server_node
            .poll_association_control(server)
            .unwrap()
            .expect("the peer ACKs and advertises current flow credit");
        assert_eq!(duplicate_ack.bearer, secondary_bearer);
        server_node.submit_node_packet(duplicate_ack).unwrap();
        let server_primary_packets = server_primary_capture.lock().unwrap().clone();
        let server_secondary_packets = server_secondary_capture.lock().unwrap().clone();
        assert_eq!(server_secondary_packets.len(), 1);
        assert_eq!(server_primary_packets.len(), 1);
        let secondary_control_header = ShortHeader::decode(&server_secondary_packets[0]).unwrap().0;
        let primary_control_header = ShortHeader::decode(&server_primary_packets[0]).unwrap().0;
        assert_eq!(secondary_control_header.dcid, client_path_cid);
        assert_ne!(primary_control_header.dcid, client_path_cid);
        assert_ne!(
            secondary_control_header.packet_number,
            primary_control_header.packet_number
        );
        let (_, mut frame_offset) = ShortHeader::decode(&server_primary_packets[0]).unwrap();
        let mut copied_ack = false;
        let mut copied_credit = false;
        while frame_offset < server_primary_packets[0].len() {
            let (frame, used) =
                crate::decode_frame(&server_primary_packets[0][frame_offset..]).unwrap();
            copied_ack |= matches!(frame, Frame::Ack { .. } | Frame::AckRanges { .. });
            copied_credit |= matches!(
                frame,
                Frame::MaxData(_) | Frame::MaxStreamData { .. } | Frame::MaxStreamsBidi(_)
            );
            frame_offset += used;
        }
        assert!(copied_ack);
        assert!(copied_credit);
        server_node.circuits(server, &mut server_circuits);
        assert_eq!(
            server_circuits[0].duplicate_bytes_prepared,
            server_primary_packets[0].len() as u64
        );
        assert!(match &server_node.slot(server).unwrap().state {
            Association::Server(server_state) => {
                server_state.mux.endpoint.duplication_credit_bytes < 4096
            }
            Association::Client(_) => unreachable!(),
        });

        // Explicitly prioritized control streams may duplicate ordinary data
        // packets before FIN, using the same token bucket as tail copies.
        original_capture.lock().unwrap().clear();
        duplicate_capture.lock().unwrap().clear();
        if let Association::Client(client_state) = &mut client_node.slot_mut(client).unwrap().state
        {
            let endpoint = client_state.connection_mut().endpoint_mut().unwrap();
            endpoint.set_duplication_budget_capacity(4096);
            endpoint.duplication_credit_bytes = 4096;
        }
        let mut priority_stream = client_node.open_stream(client).unwrap();
        priority_stream.set_priority(true);
        assert!(priority_stream.is_priority());
        let priority_stream_id = priority_stream.id();
        assert_eq!(
            client_node.write_stream(&mut priority_stream, b"priority control"),
            Ok(b"priority control".len())
        );
        let priority_original = original_capture.lock().unwrap().clone();
        let priority_duplicate = duplicate_capture.lock().unwrap().clone();
        assert_eq!(priority_original.len(), 1);
        assert_eq!(priority_duplicate.len(), 1);
        let (original_header, _) = ShortHeader::decode(&priority_original[0]).unwrap();
        let (duplicate_header, duplicate_offset) =
            ShortHeader::decode(&priority_duplicate[0]).unwrap();
        assert_ne!(
            original_header.packet_number,
            duplicate_header.packet_number
        );
        assert_eq!(original_header.dcid, server_primary_cid);
        assert_eq!(duplicate_header.dcid, server_path_cid);
        let (duplicate_frame, _) =
            crate::decode_frame(&priority_duplicate[0][duplicate_offset..]).unwrap();
        assert!(matches!(
            duplicate_frame,
            Frame::Stream(frame) if frame.id == priority_stream_id && !frame.fin
        ));
        for (bytes, receive_meta) in [
            (priority_original[0].as_slice(), meta),
            (
                priority_duplicate[0].as_slice(),
                PacketMeta {
                    bearer: path_address.0,
                    peer_l2_address: path_address.1,
                    received_at_us: probe_deadline + 60_002,
                },
            ),
        ] {
            let mut storage = [0u8; PACKET];
            storage[..bytes.len()].copy_from_slice(bytes);
            server_node
                .receive_packet(
                    receive_meta,
                    OwnedPacket::new(storage, 0..bytes.len()).unwrap(),
                    |_| None,
                    |_, _, _, _, payload| Ok(payload.len()),
                )
                .unwrap();
        }
        // Priority is sender-local duplication policy, not a wire request
        // for immediate ACKs. One packet per path can wait for ACK delay.
        let ack_delay = match &server_node.slot(server).unwrap().state {
            Association::Server(server) => server.mux.endpoint.max_ack_delay_us,
            Association::Client(_) => unreachable!(),
        };
        let ack_at = server_node.clock_us().saturating_add(ack_delay.max(1));
        server_node.advance_clock(ack_at);
        let priority_ack = server_node
            .poll_association_control(server)
            .unwrap()
            .expect("priority stream data is acknowledged over its ingress circuit");
        client_node
            .receive_packet(
                PacketMeta {
                    bearer: priority_ack.bearer,
                    peer_l2_address: priority_ack.peer_l2_address,
                    received_at_us: ack_at + 1,
                },
                priority_ack.packet,
                |_| None,
                |_, _, _, _, payload| Ok(payload.len()),
            )
            .unwrap();
        if let Some(pending_ack) = client_node.poll_association_control(client).unwrap() {
            server_node
                .receive_packet(
                    PacketMeta {
                        bearer: pending_ack.bearer,
                        peer_l2_address: pending_ack.peer_l2_address,
                        received_at_us: probe_deadline + 60_004,
                    },
                    pending_ack.packet,
                    |_| None,
                    |_, _, _, _, payload| Ok(payload.len()),
                )
                .unwrap();
        }
        assert!(matches!(
            client_node.close_circuit(client_circuit),
            Err(QuicNodeEgressError::CircuitBusy)
        ));
        let abandon = client_node
            .poll_association_control(client)
            .unwrap()
            .expect("PATH_STATUS abandon is sent as reliable control");
        let (first_header, first_header_len) = ShortHeader::decode(abandon.packet.bytes()).unwrap();
        let (abandon_frame, _) =
            crate::decode_frame(&abandon.packet.bytes()[first_header_len..]).unwrap();
        assert!(
            matches!(
                abandon_frame,
                Frame::PathStatus {
                    key: status_key,
                    sequence: 1,
                    status: crate::PathStatusKind::Abandon,
                } if status_key == key
            ),
            "unexpected initial PATH_STATUS frame: {abandon_frame:?}"
        );
        drop(abandon.packet);
        let mut retried_status = None;
        for _ in 0..8 {
            let retry_deadline = client_node
                .next_deadline()
                .expect("unacknowledged PATH_STATUS has a retry deadline");
            if let Some(NodeTimer::Egress(packet)) =
                client_node.timer_expired(retry_deadline).unwrap()
            {
                let header_len = ShortHeader::decode(packet.packet.bytes()).unwrap().1;
                if matches!(
                    crate::decode_frame(&packet.packet.bytes()[header_len..])
                        .unwrap()
                        .0,
                    Frame::PathStatus { .. }
                ) {
                    retried_status = Some(packet);
                    break;
                }
            }
        }
        let abandon = retried_status.expect("PATH_STATUS PTO must produce a retry");
        let (retry_header, retry_header_len) = ShortHeader::decode(abandon.packet.bytes()).unwrap();
        assert_ne!(retry_header.packet_number, first_header.packet_number);
        let retry_frame = crate::decode_frame(&abandon.packet.bytes()[retry_header_len..])
            .unwrap()
            .0;
        assert!(
            matches!(
                retry_frame,
                Frame::PathStatus {
                    key: retry_key,
                    sequence: 1,
                    status: crate::PathStatusKind::Abandon,
                } if retry_key == key
            ),
            "unexpected PATH_STATUS retry frame: {retry_frame:?}"
        );
        let abandon_ack = match server_node
            .receive_packet(
                PacketMeta {
                    received_at_us: probe_deadline + 30_000,
                    bearer: abandon.bearer,
                    peer_l2_address: abandon.peer_l2_address,
                },
                abandon.packet,
                |_| None,
                |_, _, _, _, bytes| Ok(bytes.len()),
            )
            .unwrap()
        {
            NodeIngress::PathControl { response, .. } => response,
            _ => panic!("PATH_STATUS must receive an immediate ACK"),
        };
        server_node.circuits(server, &mut server_circuits);
        assert_eq!(server_circuits[1].status, CircuitStatus::Closed);
        client_node
            .receive_packet(
                PacketMeta {
                    received_at_us: probe_deadline + 35_000,
                    bearer: abandon_ack.bearer,
                    peer_l2_address: abandon_ack.peer_l2_address,
                },
                abandon_ack.packet,
                |_| None,
                |_, _, _, _, bytes| Ok(bytes.len()),
            )
            .unwrap();
        client_node.close_circuit(client_circuit).unwrap();
        assert!(!client_node.router.contains(client_path_cid));
        assert_eq!(client_node.circuits(client, &mut client_circuits), 1);

        while client_node.next_association_event().is_some() {}
        let primary = client_circuits[0].id;
        client_node.suspend_circuit(primary).unwrap();
        client_node.circuits(client, &mut client_circuits);
        assert_eq!(client_circuits[0].status, CircuitStatus::Suspended);
        assert_eq!(client_circuits[0].bytes_in_flight, 0);
        assert!(matches!(
            client_node.next_association_event(),
            Some(AssociationEvent::CircuitStatusChanged {
                circuit,
                status: CircuitStatus::Suspended,
                ..
            }) if circuit == primary
        ));

        // Suspension is local transmit state. Reverse traffic can still be
        // received on the circuit while the peer continues using its side.
        let reverse_stream = server_node.allocate_stream(server).unwrap();
        let reverse = server_node
            .send_stream_on_path(server, 0, reverse_stream, 0, true, b"reverse")
            .unwrap();
        let mut reverse_bytes = Vec::new();
        client_node
            .receive_packet(
                PacketMeta {
                    received_at_us: probe_deadline + 40_000,
                    ..meta
                },
                reverse.packet,
                |_| None,
                |source, stream, offset, fin, bytes| {
                    assert_eq!(source, ApplicationStreamSource::Association(client));
                    assert_eq!(stream, reverse_stream);
                    assert_eq!(offset, 0);
                    assert!(fin);
                    reverse_bytes.extend_from_slice(bytes);
                    Ok(bytes.len())
                },
            )
            .unwrap();
        assert_eq!(reverse_bytes, b"reverse");

        assert!(client_node.remove(client).is_ok());
        assert!(server_node.remove(server).is_ok());
        assert!(!client_node.router.contains(client_path_cid));
        assert!(!server_node.router.contains(server_path_cid));
    }

    #[test]
    fn public_node_probe_uses_flow_window_and_multi_packet_fin() {
        const PACKET: usize = 256;
        const SLOT: usize = PACKET_PREFIX_RESERVE + PACKET + PACKET_SUFFIX_RESERVE;
        type Pool = crate::packet_pool::PacketPool<4, SLOT>;
        type Node = QuicNode<Pool, PACKET>;
        static POOL: Pool = Pool::new();

        let meta = ingress_meta();
        let mut client_node = Node::new(&POOL);
        let mut server_node = Node::new(&POOL);
        let open = client_node.start_association(cid(0x71), meta, 0).unwrap();
        let client = open.association;
        let server = match server_node
            .receive_packet(
                meta,
                open.packet,
                |_| {
                    Some(InitialAdmission {
                        local_limits: ConnectionLimits::default(),
                    })
                },
                |_, _, _, _, bytes| Ok(bytes.len()),
            )
            .unwrap()
        {
            NodeIngress::Initial {
                association,
                response,
            } => {
                client_node
                    .receive_packet(
                        meta,
                        response.packet,
                        |_| None,
                        |_, _, _, _, bytes| Ok(bytes.len()),
                    )
                    .unwrap();
                association
            }
            _ => panic!("Initial must establish the test association"),
        };

        let stream = client_node.allocate_stream(client).unwrap();
        let initial_window = client_node
            .stream_flow_control_window(client, stream, 0)
            .unwrap();
        assert!(initial_window >= 12);
        let mut sender = crate::probe::ProbeSender::new(stream, 12, 8).unwrap();
        let mut receiver = crate::probe::ProbeReceiver::new(2);
        let mut payload = [0u8; 8];

        for expected_fin in [false, true] {
            let window = client_node
                .stream_flow_control_window(client, stream, sender.bytes_sent())
                .unwrap();
            let chunk = sender.prepare(window, &mut payload).unwrap();
            assert_eq!(chunk.fin, expected_fin);
            let packet = client_node
                .send_stream(
                    client,
                    chunk.stream_id,
                    chunk.offset,
                    chunk.fin,
                    &payload[..chunk.len],
                )
                .unwrap();
            sender.commit(chunk).unwrap();
            server_node
                .receive_packet(
                    meta,
                    packet.packet,
                    |_| None,
                    |source, received_stream, offset, fin, bytes| {
                        assert_eq!(source, ApplicationStreamSource::Association(server));
                        assert_eq!(received_stream, stream);
                        receiver
                            .receive(offset, fin, bytes)
                            .map_err(|_| Error::Invalid)
                    },
                )
                .unwrap();
        }
        assert!(sender.is_complete());
        assert!(receiver.is_complete());
        assert_eq!(receiver.bytes(), 12);
        assert_eq!(
            client_node
                .stream_flow_control_window(client, stream, 12)
                .unwrap(),
            initial_window - 12
        );
    }

    #[test]
    fn node_owned_handshake_and_stream_ranges_deliver_both_roles() {
        const PACKET: usize = 256;
        const SLOT: usize = PACKET_PREFIX_RESERVE + PACKET + PACKET_SUFFIX_RESERVE;
        type Pool = crate::packet_pool::PacketPool<2, SLOT>;
        type Node = QuicNode<Pool, PACKET>;
        static CLIENT_POOL: Pool = Pool::new();
        static SERVER_POOL: Pool = Pool::new();

        let client_meta = PacketMeta {
            bearer: BearerId::new(1).unwrap(),
            peer_l2_address: PeerL2Address::new(11).unwrap(),
            received_at_us: 1,
        };
        let server_meta = PacketMeta {
            bearer: BearerId::new(1).unwrap(),
            peer_l2_address: PeerL2Address::new(12).unwrap(),
            received_at_us: 2,
        };
        let client_cid = cid(0x51);
        let mut client_node = Node::new(&CLIENT_POOL);
        let open = client_node
            .start_association(client_cid, client_meta, 0)
            .unwrap();
        let client_id = open.association;
        let mut server_node = Node::new(&SERVER_POOL);
        let (server_id, ack) = match server_node
            .receive_packet(
                server_meta,
                open.packet,
                |_| {
                    Some(InitialAdmission {
                        local_limits: ConnectionLimits::default(),
                    })
                },
                |_, _, _, _, bytes| Ok(bytes.len()),
            )
            .unwrap()
        {
            NodeIngress::Initial {
                association,
                response,
            } => (association, response),
            _ => panic!("Initial must be admitted"),
        };
        client_node
            .receive_packet(
                client_meta,
                ack.packet,
                |_| None,
                |_, _, _, _, bytes| Ok(bytes.len()),
            )
            .unwrap();
        assert!(client_node.next_deadline().is_some());

        let request = client_node.send_message(client_id, b"request").unwrap();
        assert_eq!(request.packet.prefix_capacity(), PACKET_PREFIX_RESERVE);
        assert!(request.packet.suffix_capacity() >= PACKET_SUFFIX_RESERVE);
        let deadline = client_node.next_deadline().unwrap();
        let retransmission = match client_node.timer_expired(deadline).unwrap().unwrap() {
            NodeTimer::Egress(egress) => egress,
            NodeTimer::BootstrapTimedOut { .. } => panic!("established association timed out"),
            NodeTimer::IdleTimedOut { .. } => panic!("established association idled"),
            NodeTimer::CircuitSetupTimedOut { .. } => panic!("no relayed setup is pending"),
        };
        assert_eq!(retransmission.association, client_id);
        assert_eq!(retransmission.bearer, client_meta.bearer);
        assert_eq!(retransmission.peer_l2_address, client_meta.peer_l2_address);
        drop(retransmission);

        let mut request_body = None;
        let mut request_stream = None;
        server_node
            .receive_owned_packet(
                server_meta,
                request.packet,
                |_| None,
                |source, stream, offset, fin, bytes| {
                    assert_eq!(source, ApplicationStreamSource::Association(server_id));
                    assert_eq!(offset, 0);
                    assert!(fin);
                    request_stream = Some(stream);
                    request_body = Some(bytes.to_vec());
                    Ok(bytes.len())
                },
            )
            .unwrap();
        assert_eq!(request_body.as_deref(), Some(b"request".as_slice()));
        assert_eq!(
            server_node.association_egress_address(server_id),
            Some((server_meta.bearer, server_meta.peer_l2_address))
        );

        let response = server_node
            .send_stream(server_id, request_stream.unwrap(), 0, true, b"response")
            .unwrap();
        // Retention pressure after an accepted prefix must neither ACK the
        // packet nor replay that prefix on retransmission.
        let response_number = {
            let endpoint = client_node
                .client(client_id)
                .unwrap()
                .connection()
                .endpoint()
                .unwrap();
            crate::ShortHeader::decode_with_expected(
                response.packet.bytes(),
                endpoint.expected_packet_number(),
            )
            .unwrap()
            .0
            .packet_number
        };
        let (response_header, _) =
            crate::ShortHeader::decode_with_expected(response.packet.bytes(), response_number)
                .unwrap();
        let mut coalesced = [0u8; PACKET];
        let mut coalesced_len = response_header.encode(&mut coalesced).unwrap();
        for (offset, fin, data) in [(0, false, &b"resp"[..]), (4, true, &b"onse"[..])] {
            coalesced_len += Frame::Stream(crate::StreamFrame {
                id: request_stream.unwrap(),
                offset,
                fin,
                data,
            })
            .encode(&mut coalesced[coalesced_len..])
            .unwrap();
        }
        let old_limits = client_node
            .slot(client_id)
            .unwrap()
            .client_delivery
            .limits();
        client_node
            .slot_mut(client_id)
            .unwrap()
            .client_delivery
            .set_limits(old_limits.0, 0);
        let mut accepted_prefix = Vec::new();
        client_node
            .receive_packet(
                client_meta,
                OwnedPacket::from_buffer(&coalesced[..coalesced_len]),
                |_| None,
                |_, _, offset, _, bytes| {
                    assert_eq!(offset, 0);
                    accepted_prefix.extend_from_slice(&bytes[..2]);
                    Ok(2)
                },
            )
            .unwrap();
        assert_eq!(accepted_prefix, b"re");
        assert!(
            !client_node
                .client(client_id)
                .unwrap()
                .connection()
                .endpoint()
                .unwrap()
                .has_received_packet(response_number)
        );
        client_node
            .slot_mut(client_id)
            .unwrap()
            .client_delivery
            .set_limits(old_limits.0, old_limits.1);
        let mut response_body = None;
        client_node
            .receive_packet(
                client_meta,
                OwnedPacket::from_buffer(&coalesced[..coalesced_len]),
                |_| None,
                |source, _stream, offset, fin, bytes| {
                    assert_eq!(source, ApplicationStreamSource::Association(client_id));
                    assert_eq!(offset as usize, accepted_prefix.len());
                    assert_eq!(fin, offset == 4);
                    accepted_prefix.extend_from_slice(bytes);
                    response_body = Some(accepted_prefix.clone());
                    Ok(bytes.len())
                },
            )
            .unwrap();
        assert_eq!(response_body.as_deref(), Some(b"response".as_slice()));
        assert!(
            client_node
                .client(client_id)
                .unwrap()
                .connection()
                .endpoint()
                .unwrap()
                .has_received_packet(response_number)
        );
        drop(response);

        let client_stream = client_node.allocate_stream(client_id).unwrap();
        assert_eq!(
            client_stream,
            crate::FIRST_CLIENT_BIDI_STREAM_ID.saturating_add(4)
        );
        assert!(matches!(
            client_node.send_stream(
                client_id,
                client_stream,
                crate::INITIAL_MAX_STREAM_DATA,
                false,
                b"blocked",
            ),
            Err(QuicNodeEgressError::Transport(Error::FlowControl))
        ));

        let first = client_node
            .send_stream(client_id, client_stream, 0, false, b"client-")
            .unwrap();
        let mut client_ranges = std::vec::Vec::new();
        server_node
            .receive_packet(
                server_meta,
                first.packet,
                |_| None,
                |source, stream, offset, fin, bytes| {
                    assert_eq!(source, ApplicationStreamSource::Association(server_id));
                    client_ranges.push((stream, offset, fin, bytes.to_vec()));
                    Ok(bytes.len())
                },
            )
            .unwrap();
        let second = client_node
            .send_stream(client_id, client_stream, 7, true, b"stream")
            .unwrap();
        server_node
            .receive_packet(
                server_meta,
                second.packet,
                |_| None,
                |source, stream, offset, fin, bytes| {
                    assert_eq!(source, ApplicationStreamSource::Association(server_id));
                    client_ranges.push((stream, offset, fin, bytes.to_vec()));
                    Ok(bytes.len())
                },
            )
            .unwrap();
        assert_eq!(
            client_ranges,
            [
                (client_stream, 0, false, b"client-".to_vec()),
                (client_stream, 7, true, b"stream".to_vec()),
            ]
        );

        let server_stream = server_node.allocate_stream(server_id).unwrap();
        assert_eq!(server_stream, crate::FIRST_SERVER_BIDI_STREAM_ID);
        let first = server_node
            .send_stream(server_id, server_stream, 0, false, b"server-")
            .unwrap();
        let mut server_ranges = std::vec::Vec::new();
        client_node
            .receive_packet(
                client_meta,
                first.packet,
                |_| None,
                |source, stream, offset, fin, bytes| {
                    assert_eq!(source, ApplicationStreamSource::Association(client_id));
                    server_ranges.push((stream, offset, fin, bytes.to_vec()));
                    Ok(bytes.len())
                },
            )
            .unwrap();
        let second = server_node
            .send_stream(server_id, server_stream, 7, true, b"stream")
            .unwrap();
        client_node
            .receive_packet(
                client_meta,
                second.packet,
                |_| None,
                |source, stream, offset, fin, bytes| {
                    assert_eq!(source, ApplicationStreamSource::Association(client_id));
                    server_ranges.push((stream, offset, fin, bytes.to_vec()));
                    Ok(bytes.len())
                },
            )
            .unwrap();
        assert_eq!(
            server_ranges,
            [
                (server_stream, 0, false, b"server-".to_vec()),
                (server_stream, 7, true, b"stream".to_vec()),
            ]
        );

        // A Tokio/RTOS owner may have queued this ACK intent before the
        // application finishes. CLOSE must retire that scheduling state too.
        client_node.defer_control(client_id).unwrap();
        assert!(client_node.pending_controls.contains(&client_id));
        let terminal_ack = match client_node.close_association(client_id, 0x77).unwrap() {
            NodeClose::Control(egress) => egress,
            NodeClose::Closed(_) => panic!("terminal response ACK must precede CLOSE"),
        };
        assert!(client_node.client(client_id).is_some());
        server_node
            .receive_packet(
                server_meta,
                terminal_ack.packet,
                |_| None,
                |_, _, _, _, bytes| Ok(bytes.len()),
            )
            .unwrap();
        assert!(!server_node.server(server_id).unwrap().is_closed());

        let close = match client_node.close_association(client_id, 0x77).unwrap() {
            NodeClose::Closed(egress) => egress,
            NodeClose::Control(_) => panic!("all pending control was already emitted"),
        };
        assert!(client_node.client(client_id).is_none());
        assert_eq!(client_node.receive_cid(client_id), None);
        assert!(!client_node.retry_one_pending_control().unwrap());
        server_node
            .receive_packet(
                server_meta,
                close.packet,
                |_| None,
                |_, _, _, _, bytes| Ok(bytes.len()),
            )
            .unwrap();
        assert!(server_node.server(server_id).is_none());
        assert_eq!(server_node.receive_cid(server_id), None);
        // Graceful CLOSE must release association storage immediately, not
        // leave completed endpoints allocated until the idle timeout.
        assert_eq!(client_node.association_count(), 0);
        assert_eq!(server_node.association_count(), 0);
    }

    #[test]
    fn client_bootstrap_retries_with_new_packet_numbers_then_retires_its_dcid() {
        const PACKET: usize = 256;
        const SLOT: usize = PACKET_PREFIX_RESERVE + PACKET + PACKET_SUFFIX_RESERVE;
        type Pool = crate::packet_pool::PacketPool<1, SLOT>;
        type Node = QuicNode<Pool, PACKET>;
        static POOL: Pool = Pool::new();

        let meta = PacketMeta {
            bearer: BearerId::new(1).unwrap(),
            peer_l2_address: PeerL2Address::new(9).unwrap(),
            received_at_us: 0,
        };
        let cid = cid(0x91);
        let mut node = Node::new(&POOL);
        let initial = node.start_association(cid, meta, 10).unwrap();
        let association = initial.association;
        let (header, _) =
            crate::decode_bootstrap_open_packet_with_limits(initial.packet.bytes()).unwrap();
        assert_eq!(header.packet_number, 0);
        drop(initial);

        let first_deadline = 10 + DEFAULT_INITIAL_PTO_US;
        assert_eq!(node.next_deadline(), Some(first_deadline));
        assert!(node.timer_expired(first_deadline - 1).unwrap().is_none());
        let held_slot = POOL.acquire_with(&[0x55]).unwrap();
        assert!(matches!(
            node.timer_expired(first_deadline),
            Err(QuicNodeEgressError::PoolUnavailable)
        ));
        drop(held_slot);
        for attempt in 1..CLIENT_BOOTSTRAP_ATTEMPTS {
            let now = 10 + u64::from(attempt) * DEFAULT_INITIAL_PTO_US;
            let retry = match node.timer_expired(now).unwrap().unwrap() {
                NodeTimer::Egress(egress) => egress,
                NodeTimer::BootstrapTimedOut { .. } => panic!("attempt must be emitted"),
                NodeTimer::IdleTimedOut { .. } => panic!("bootstrap association idled"),
                NodeTimer::CircuitSetupTimedOut { .. } => {
                    panic!("bootstrap association has no relayed join")
                }
            };
            assert_eq!(retry.association, association);
            assert_eq!(retry.bearer, meta.bearer);
            assert_eq!(retry.peer_l2_address, meta.peer_l2_address);
            let (header, _) =
                crate::decode_bootstrap_open_packet_with_limits(retry.packet.bytes()).unwrap();
            assert_eq!(header.packet_number, attempt);
            drop(retry);
            assert_eq!(node.next_deadline(), Some(now + DEFAULT_INITIAL_PTO_US));
        }
        assert_eq!(node.association_count(), 1);

        assert!(matches!(
            node.timer_expired(
                10 + u64::from(CLIENT_BOOTSTRAP_ATTEMPTS) * DEFAULT_INITIAL_PTO_US,
            )
                .unwrap(),
            Some(NodeTimer::BootstrapTimedOut { association: timed_out })
                if timed_out == association
        ));
        assert_eq!(node.association_count(), 0);
        assert!(node.client(association).is_none());
        assert_eq!(node.receive_cid(association), None);
        assert!(matches!(
            node.next_association_event(),
            Some(AssociationEvent::CircuitOpened { association: opened, .. })
                if opened == association
        ));
        assert_eq!(
            node.next_association_event(),
            Some(AssociationEvent::SetupTimeout { association })
        );
        assert_eq!(node.next_deadline(), None);
    }

    #[test]
    fn idle_relay_lease_deadline_expires_both_directions_without_ingress() {
        let mut node = QuicNode::<TestPool>::new(&TEST_POOL);
        let next_hop = ForwardNextHop {
            bearer: BearerId::new(1).unwrap(),
            peer_l2_address: PeerL2Address::new(9).unwrap(),
        };
        let make_rule = |destination| ForwardRule {
            next_hop,
            destination: ForwardDestination::Connection(destination),
            lease_duration_us: 1_000,
            lease_expires_at_us: 100,
            lease_group_id: 12,
            packet_quota: 0,
            forwarded_packets: 0,
            forwarded_control_packets: 0,
            quota_window_started_us: 0,
        };
        node.register_forward_pair(
            cid(0x31),
            make_rule(cid(0x41)),
            cid(0x32),
            make_rule(cid(0x42)),
        )
        .unwrap();
        assert_eq!(node.next_deadline(), Some(100));
        assert!(node.timer_expired(99).unwrap().is_none());
        assert_eq!(node.next_deadline(), Some(100));
        assert!(node.timer_expired(100).unwrap().is_none());
        assert_eq!(node.next_deadline(), None);
        assert!(!node.remove_forward(cid(0x31)));
        assert!(!node.remove_forward(cid(0x32)));
    }

    #[test]
    fn expired_forward_is_dropped_before_quota_or_packet_allocation() {
        let mut node = QuicNode::<TestPool>::new(&TEST_POOL);
        let next_hop = ForwardNextHop {
            bearer: BearerId::new(1).unwrap(),
            peer_l2_address: PeerL2Address::new(9).unwrap(),
        };
        let make_rule = |destination| ForwardRule {
            next_hop,
            destination: ForwardDestination::Connection(destination),
            lease_duration_us: 1_000,
            lease_expires_at_us: 100,
            lease_group_id: 17,
            packet_quota: 1,
            forwarded_packets: 0,
            forwarded_control_packets: 0,
            quota_window_started_us: 0,
        };
        node.register_forward_pair(
            cid(0x31),
            make_rule(cid(0x41)),
            cid(0x32),
            make_rule(cid(0x42)),
        )
        .unwrap();

        let mut input = [0u8; 64];
        let header_len = ShortHeader {
            flags: FLAG_FIXED,
            dcid: cid(0x31),
            packet_number: 1,
            packet_number_len: 1,
        }
        .encode(&mut input)
        .unwrap();
        let frame_len = Frame::Ping.encode(&mut input[header_len..]).unwrap();
        let input_len = header_len + frame_len;
        let result = node
            .receive_packet(
                PacketMeta {
                    bearer: BearerId::new(1).unwrap(),
                    peer_l2_address: PeerL2Address::new(9).unwrap(),
                    received_at_us: 100,
                },
                OwnedPacket::new(input, 0..input_len).unwrap(),
                |_| None,
                |_, _, _, _, bytes| Ok(bytes.len()),
            )
            .unwrap();
        assert!(
            matches!(result, NodeIngress::Unknown { destination, .. } if destination == cid(0x31))
        );
        assert_eq!(node.router.route_count(), 0);
        assert_eq!(node.available_packets(), 1);
        assert_eq!(node.next_deadline(), None);
    }

    #[test]
    fn deployed_short_header_response_establishes_symmetric_cid_client() {
        const PACKET: usize = 256;
        const SLOT: usize = PACKET_PREFIX_RESERVE + PACKET + PACKET_SUFFIX_RESERVE;
        type Pool = crate::packet_pool::PacketPool<4, SLOT>;
        type Node = QuicNode<Pool, PACKET>;
        static POOL: Pool = Pool::new();

        let meta = ingress_meta();
        let mut node = Node::new(&POOL);
        let initial = node.start_association(cid(1), meta, 0).unwrap();
        let association = initial.association;
        drop(initial);

        // Captured from a deployed stable UART peer. It is a short-header
        // ACK/MAX_DATA/MAX_STREAM_DATA response, which is the original
        // association-establishment contract (no separate OPEN_ACK packet).
        let captured = [
            0x40, 0x01, 0x19, 0x02, 0x02, 0x05, 0x00, 0x01, 0x10, 0x51, 0x52, 0x11, 0x04, 0x48,
            0xa9,
        ];
        let ingress = node
            .receive_packet(
                meta,
                OwnedPacket::new(captured, 0..captured.len()).unwrap(),
                |_| None,
                |_, _, _, _, bytes| Ok(bytes.len()),
            )
            .unwrap();
        assert!(matches!(
            ingress,
            NodeIngress::Association {
                association: AssociationIngress::Client(found),
                ..
            } if found == association
        ));
        let client = node.client(association).unwrap();
        assert!(client.connection().is_established());
        assert_eq!(client.peer_cid(), Some(cid(1)));
    }

    #[test]
    #[cfg(feature = "stateless-reset")]
    fn unified_ingress_covers_decline_forward_reset_unknown_and_non_quic() {
        const PACKET: usize = 256;
        const SLOT: usize = PACKET_PREFIX_RESERVE + PACKET + PACKET_SUFFIX_RESERVE;
        type Pool = crate::packet_pool::PacketPool<4, SLOT>;
        type Node = QuicNode<Pool, PACKET>;
        static INPUT_POOL: Pool = Pool::new();
        static OUTPUT_POOL: Pool = Pool::new();

        let meta = ingress_meta();
        let mut source = Node::new(&INPUT_POOL);
        let initial = source.start_association(cid(0x21), meta, 0).unwrap();
        let mut node = Node::new_with_stateless_reset(
            StatelessResetKey::from_device_secret(&[0x35; 32]).unwrap(),
            &OUTPUT_POOL,
        );
        let declined = node
            .receive_packet(
                meta,
                initial.packet,
                |_| None,
                |_, _, _, _, bytes| Ok(bytes.len()),
            )
            .unwrap();
        assert!(matches!(declined, NodeIngress::InitialDeclined { .. }));
        assert_eq!(node.association_count(), 0);
        drop(declined);

        let relay_cid = cid(0x31);
        let destination_cid = cid(0x41);
        node.register_forward(
            relay_cid,
            ForwardRule {
                next_hop: ForwardNextHop {
                    bearer: meta.bearer,
                    peer_l2_address: meta.peer_l2_address,
                },
                destination: ForwardDestination::Connection(destination_cid),
                lease_duration_us: 1_000,
                lease_expires_at_us: 2,
                lease_group_id: 0,
                packet_quota: 0,
                forwarded_packets: 0,
                forwarded_control_packets: 0,
                quota_window_started_us: 0,
            },
        )
        .unwrap();
        assert_eq!(node.next_deadline(), Some(2));
        let mut relay_packet = [0x55; PACKET];
        let relay_header = short_packet(relay_cid, &mut relay_packet);
        let relay_len = relay_header + 40;
        let forwarded = node
            .receive_packet(
                meta,
                OwnedPacket::new(relay_packet, 0..relay_len).unwrap(),
                |_| None,
                |_, _, _, _, bytes| Ok(bytes.len()),
            )
            .unwrap();
        match forwarded {
            NodeIngress::Forward { next_hop, packet } => {
                assert_eq!(next_hop.bearer, meta.bearer);
                assert_eq!(next_hop.peer_l2_address, meta.peer_l2_address);
                assert_eq!(
                    ShortHeader::decode(packet.bytes()).unwrap().0.dcid,
                    destination_cid
                );
            }
            _ => panic!("relay CID must return a forwarding action"),
        }
        assert_eq!(node.next_deadline(), Some(1_001));

        let mut expired_packet = [0x55; PACKET];
        let expired_header = short_packet(relay_cid, &mut expired_packet);
        let expired_len = expired_header + 40;
        let expired = node
            .receive_packet(
                PacketMeta {
                    received_at_us: 1_001,
                    ..meta
                },
                OwnedPacket::new(expired_packet, 0..expired_len).unwrap(),
                |_| None,
                |_, _, _, _, bytes| Ok(bytes.len()),
            )
            .unwrap();
        assert!(matches!(expired, NodeIngress::Unknown { .. }));
        assert_eq!(node.next_deadline(), None);

        let unknown_cid = cid(0x51);
        let mut reset_probe = [0x66; PACKET];
        let reset_header = short_packet(unknown_cid, &mut reset_probe);
        let reset_len = reset_header + 40;
        let reset = node
            .receive_packet(
                meta,
                OwnedPacket::new(reset_probe, 0..reset_len).unwrap(),
                |_| None,
                |_, _, _, _, bytes| Ok(bytes.len()),
            )
            .unwrap();
        assert!(matches!(reset, NodeIngress::StatelessReset { .. }));
        drop(reset);

        let mut short_unknown = [0u8; PACKET];
        let short_len = short_packet(unknown_cid, &mut short_unknown);
        let unknown = node
            .receive_packet(
                meta,
                OwnedPacket::new(short_unknown, 0..short_len).unwrap(),
                |_| None,
                |_, _, _, _, bytes| Ok(bytes.len()),
            )
            .unwrap();
        assert!(matches!(
            unknown,
            NodeIngress::Unknown { destination, .. } if destination == unknown_cid
        ));
        drop(unknown);

        let malformed = node
            .receive_packet(
                meta,
                OwnedPacket::new([0u8; PACKET], 0..3).unwrap(),
                |_| None,
                |_, _, _, _, bytes| Ok(bytes.len()),
            )
            .unwrap();
        assert!(matches!(malformed, NodeIngress::NonQuic { .. }));
    }

    #[test]
    #[cfg(feature = "stateless-reset")]
    fn server_association_recognizes_client_stateless_reset_on_any_bearer() {
        const PACKET: usize = 256;
        const SLOT: usize = PACKET_PREFIX_RESERVE + PACKET + PACKET_SUFFIX_RESERVE;
        type Pool = crate::packet_pool::PacketPool<4, SLOT>;
        type Node = QuicNode<Pool, PACKET>;
        static CLIENT_POOL: Pool = Pool::new();
        static SERVER_POOL: Pool = Pool::new();

        let client_key = StatelessResetKey::from_device_secret(&[0x45; 32]).unwrap();
        let server_key = StatelessResetKey::from_device_secret(&[0x46; 32]).unwrap();
        let meta = ingress_meta();
        let client_cid = cid(0x61);
        let mut client = Node::new_with_stateless_reset(client_key, &CLIENT_POOL);
        let initial = client.start_association(client_cid, meta, 0).unwrap();
        let mut server = Node::new_with_stateless_reset(server_key, &SERVER_POOL);
        let admitted = server
            .receive_packet(
                meta,
                initial.packet,
                |_| {
                    Some(InitialAdmission {
                        local_limits: crate::ConnectionLimits::default(),
                    })
                },
                |_, _, _, _, bytes| Ok(bytes.len()),
            )
            .unwrap();
        assert!(matches!(admitted, NodeIngress::Initial { .. }));
        drop(admitted);
        assert_eq!(server.association_count(), 1);

        let mut reset = [0u8; PACKET];
        let reset_len = client_key
            .encode_for_unknown_cid(&[FLAG_FIXED; 48], client_cid, &mut reset)
            .unwrap()
            .unwrap();
        let reset = server
            .receive_packet(
                PacketMeta {
                    bearer: BearerId::new(7).unwrap(),
                    peer_l2_address: PeerL2Address::new(99).unwrap(),
                    received_at_us: 1,
                },
                OwnedPacket::new(reset, 0..reset_len).unwrap(),
                |_| None,
                |_, _, _, _, bytes| Ok(bytes.len()),
            )
            .unwrap();
        assert!(matches!(reset, NodeIngress::PeerReset { .. }));
        assert_eq!(server.association_count(), 0);
        assert!(matches!(
            server.next_association_event(),
            Some(AssociationEvent::CircuitOpened { .. })
        ));
        assert!(matches!(
            server.next_association_event(),
            Some(AssociationEvent::Reset { .. })
        ));
    }

    #[test]
    fn unified_ingress_replays_only_the_exact_initial_without_readmission() {
        const PACKET: usize = 256;
        const SLOT: usize = PACKET_PREFIX_RESERVE + PACKET + PACKET_SUFFIX_RESERVE;
        type Pool = crate::packet_pool::PacketPool<2, SLOT>;
        type Node = QuicNode<Pool, PACKET>;
        static POOL: Pool = Pool::new();

        let client_cid = cid(0x61);
        let mut initial = [0u8; PACKET];
        let initial_len = crate::encode_bootstrap_open_packet(client_cid, 0, &mut initial).unwrap();
        let mut node = Node::new(&POOL);
        let first = node
            .receive_packet(
                ingress_meta(),
                OwnedPacket::new(initial, 0..initial_len).unwrap(),
                |_| {
                    Some(InitialAdmission {
                        local_limits: ConnectionLimits::default(),
                    })
                },
                |_, _, _, _, bytes| Ok(bytes.len()),
            )
            .unwrap();
        let (association, ack) = match first {
            NodeIngress::Initial {
                association,
                response,
            } => (association, response.packet.bytes().to_vec()),
            _ => panic!("first Initial must be admitted"),
        };
        assert_eq!(node.association_count(), 1);

        let mut replay = [0u8; PACKET];
        let replay_len = crate::encode_bootstrap_open_packet(client_cid, 9, &mut replay).unwrap();
        let replayed = node
            .receive_packet(
                ingress_meta(),
                OwnedPacket::new(replay, 0..replay_len).unwrap(),
                |_| panic!("exact replay must not run admission policy"),
                |_, _, _, _, bytes| Ok(bytes.len()),
            )
            .unwrap();
        assert!(matches!(
            replayed,
            NodeIngress::Initial {
                association: found,
                response,
            } if found == association && response.packet.bytes() == ack
        ));
        assert_eq!(node.association_count(), 1);

        let mut conflicting = [0u8; PACKET];
        let mut limits = ConnectionLimits::default();
        limits.max_data -= 1;
        let conflicting_len = crate::encode_bootstrap_open_packet_with_limits(
            client_cid,
            10,
            limits,
            &mut conflicting,
        )
        .unwrap();
        let rejected = node.receive_packet(
            ingress_meta(),
            OwnedPacket::new(conflicting, 0..conflicting_len).unwrap(),
            |_| panic!("conflicting replay must not run admission policy"),
            |_, _, _, _, bytes| Ok(bytes.len()),
        );
        assert!(matches!(
            rejected,
            Err(RejectedNodePacket {
                reason: QuicNodePacketRejection::Packet(Error::BootstrapInvalid),
                ..
            })
        ));
        assert_eq!(node.association_count(), 1);
    }

    #[test]
    fn runtime_limits_can_grow_past_legacy_type_defaults_and_shrink_without_eviction() {
        type Pool = crate::packet_pool::PacketPool<1, DEFAULT_PACKET_POOL_SLOT_SIZE>;
        type Node = QuicNode<Pool>;
        static POOL: Pool = Pool::new();

        let mut node = Node::new(&POOL);
        node.set_limits(NodeLimits {
            max_associations: 3,
            max_routes: 3,
            ..NodeLimits::host()
        })
        .unwrap();
        for value in 1..=3 {
            let id = cid(value);
            node.add_client(id, Box::new(ClientAssociation::new(id)))
                .unwrap();
        }
        assert_eq!(node.association_count(), 3);

        node.set_limits(NodeLimits {
            max_associations: 1,
            max_routes: 1,
            ..NodeLimits::host()
        })
        .unwrap();
        assert_eq!(node.association_count(), 3);
        assert_eq!(
            node.add_client(cid(4), Box::new(ClientAssociation::new(cid(4)))),
            Err(QuicNodeError::AssociationTableFull)
        );
    }
    #[test]
    fn poisoned_node_storage_initializes_setup_counter() {
        type Pool = crate::packet_pool::PacketPool<4, 1204>;
        static POOL: Pool = Pool::new();
        type Node = QuicNode<Pool>;
        let mut storage = core::mem::MaybeUninit::<Node>::uninit();
        unsafe {
            core::ptr::write_bytes(
                storage.as_mut_ptr().cast::<u8>(),
                0xa5,
                core::mem::size_of::<Node>(),
            );
            Node::new_in_place(&mut storage, &POOL);
        }
        let node = unsafe { storage.assume_init() };
        assert_eq!(node.next_setup_transaction_id, 1);
    }
}
