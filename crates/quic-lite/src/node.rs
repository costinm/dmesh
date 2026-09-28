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

use alloc::{collections::VecDeque, sync::Arc, vec, vec::Vec};
use smallvec::SmallVec;

use crate::bearer::{
    BearerContext, BearerId, BearerRegistry, CompletionQueue, EgressSubmission, OwnedPacket,
    PacketBearer, PacketBuildError, PacketEgress, PacketMeta, PacketPool, PacketSubmitError,
    PacketWriter, PeerL2Address,
};
use crate::connection::{
    ClientAssociation, ServerPacket, ServerStreamConnection, classify_server_packet,
};
use crate::relay::{
    DcidRegistryError, ForwardDestination, ForwardRule, PacketRouter, RouterTarget,
};
use crate::{ConnectionId, Error, StatelessResetKey};

/// Initial packet-timeout estimate used until an association has an RTT
/// sample. Runtime adapters share this protocol value; only timer arming is
/// platform-specific.
pub(crate) const DEFAULT_INITIAL_PTO_US: u64 = 250_000;
const DEFAULT_IDLE_TIMEOUT_US: u64 = 30_000_000;

/// Stable handle for one locally terminated association.
///
/// The slot and generation are intentionally private. A removed handle never
/// names a later association which reuses the same fixed-capacity slot.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct QuicAssociation {
    slot: u16,
    generation: u64,
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
    direct_buffer: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StreamOwner {
    Association(QuicAssociation),
    Direct(DirectReply),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DirectReply {
    pub meta: PacketMeta,
    pub packet_number: u32,
}

impl QuicStream {
    /// Transport stream identifier, exposed for protocol-neutral diagnostics
    /// which correlate a fixed set of peer-opened streams.
    pub const fn id(&self) -> u64 {
        self.id
    }

    pub(crate) fn incoming(association: QuicAssociation, id: u64) -> Self {
        Self {
            owner: StreamOwner::Association(association),
            id,
            send_offset: 0,
            send_finished: false,
            direct_buffer: Vec::new(),
        }
    }

    pub(crate) fn direct(reply: DirectReply, id: u64) -> Self {
        Self {
            owner: StreamOwner::Direct(reply),
            id,
            send_offset: 0,
            send_finished: false,
            direct_buffer: Vec::new(),
        }
    }

    pub(crate) const fn association(&self) -> Option<QuicAssociation> {
        match self.owner {
            StreamOwner::Association(association) => Some(association),
            StreamOwner::Direct(_) => None,
        }
    }

    pub(crate) const fn owner(&self) -> StreamOwner {
        self.owner
    }

    pub(crate) fn matches(&self, owner: StreamOwner, id: u64) -> bool {
        let same_owner = match (self.owner, owner) {
            (StreamOwner::Association(left), StreamOwner::Association(right)) => left == right,
            (StreamOwner::Direct(left), StreamOwner::Direct(right)) => left.meta == right.meta,
            _ => false,
        };
        same_owner && self.id == id
    }

    pub(crate) const fn send_finished(&self) -> bool {
        self.send_finished
    }

    pub(crate) const fn is_direct(&self) -> bool {
        matches!(self.owner, StreamOwner::Direct(_))
    }

    pub(crate) fn finish_direct_send(&mut self, bytes: usize) {
        self.send_offset = bytes as u64;
        self.send_finished = true;
    }

    pub(crate) const fn can_send_direct(&self) -> bool {
        !self.send_finished && self.send_offset == 0
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
    pub server_cid: ConnectionId,
    pub local_limits: crate::ConnectionLimits,
}

/// Packet emitted without an association, such as a direct response or reset.
pub(crate) struct NodePacket<B> {
    pub bearer: BearerId,
    pub peer_l2_address: PeerL2Address,
    pub packet: OwnedPacket<B>,
}

/// One parsed direct request retaining its original packet lease.
pub(crate) struct DirectNodeIngress<B> {
    meta: PacketMeta,
    packet: OwnedPacket<B>,
    payload: core::ops::Range<usize>,
    packet_number: u32,
}

/// Owner of an application stream delivered by [`QuicNode::receive_packet`].
///
/// `Direct` is a transient connectionless stream. It uses the same byte
/// callback as an associated client or server stream, so an application never
/// needs to know whether its bytes came from a long or short packet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ApplicationStreamSource {
    Association(QuicAssociation),
    Direct,
}

impl<B: AsRef<[u8]>> DirectNodeIngress<B> {
    pub(crate) fn payload(&self) -> &[u8] {
        &self.packet.bytes()[self.payload.clone()]
    }

    pub(crate) const fn reply(&self) -> DirectReply {
        DirectReply {
            meta: self.meta,
            packet_number: self.packet_number,
        }
    }
}

/// Complete outcome of submitting one opaque packet to [`QuicNode`].
pub(crate) enum NodeIngress<B, EgressBuffer, NextHop> {
    Association {
        association: AssociationIngress,
        packet: OwnedPacket<B>,
    },
    Direct(DirectNodeIngress<B>),
    Initial {
        association: QuicAssociation,
        response: NodePacket<EgressBuffer>,
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

/// One result from an expired node deadline.
pub(crate) enum NodeTimer<B> {
    /// A complete packet which the runtime must retain across bearer
    /// `WouldBlock` and submit before asking this association for more output.
    Egress(NodeEgress<B>),
    /// The client Initial reached its bounded attempt limit without a valid
    /// OPEN_ACK. The association and its DCID have already been retired.
    BootstrapTimedOut { association: QuicAssociation },
    /// No packet activity occurred before the node's enforced idle deadline.
    /// The association and its DCID have already been retired.
    IdleTimedOut { association: QuicAssociation },
}

/// Terminal lifecycle notification emitted by every runtime adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AssociationEvent {
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
    /// A fixed-capacity node or runtime-adapter event queue has no free slot.
    StreamEventsFull,
    /// The peer did not complete association setup before its retry limit.
    AssociationTimedOut,
    /// Core routing selected a relay rule, but this runtime has no public
    /// next-hop forwarding adapter installed.
    RelayUnavailable,
}

impl QuicNodeEgressError {
    /// Whether unchanged stream bytes may be retried after node progress.
    pub(crate) const fn is_stream_retryable(self) -> bool {
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

impl<
    NextHop,
    const ASSOCIATIONS: usize,
    const ROUTES: usize,
    P,
    const CLIENT_HISTORY: usize,
    const SERVER_STREAMS: usize,
    const SERVER_HISTORY: usize,
    const PACKET: usize,
> QuicNode<NextHop, ASSOCIATIONS, ROUTES, P, CLIENT_HISTORY, SERVER_STREAMS, SERVER_HISTORY, PACKET>
where
    P: PacketPool + 'static,
    P::Buffer: Send,
{
    pub(crate) fn register_bearer_with_ingress<T>(
        &mut self,
        mut bearer: T,
        ingress: Arc<dyn crate::bearer::PacketIngressQueue<P::Buffer>>,
    ) -> Result<BearerId, crate::AddBearerError<T::AttachError>>
    where
        T: PacketBearer<P> + 'static,
    {
        let info = bearer.info();
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
        for slot in self.associations.iter_mut().flatten() {
            slot.known_addresses.retain(|(bearer, _)| *bearer != id);
            if slot.active_address.is_some_and(|(bearer, _)| bearer == id) {
                slot.active_address = slot.known_addresses.first().copied();
            }
        }
        true
    }

    pub(crate) fn drain_bearer_events(&mut self) -> bool {
        let mut progressed = false;
        while let Some(completion) = self.completions.pop_completion() {
            progressed = true;
            let _ = self.bearers.send_completed(completion);
        }
        while let Some(id) = self.completions.pop_ready() {
            progressed = true;
            if let Some(bearer) = self.bearers.get_mut(id) {
                let _ = bearer.retry_pending();
            }
        }
        progressed
    }

    pub(crate) fn submit_egress(
        &mut self,
        bearer_id: BearerId,
        peer: PeerL2Address,
        packet: OwnedPacket<P::Buffer>,
    ) -> Result<(), QuicNodeEgressError> {
        self.drain_bearer_events();
        #[cfg(feature = "tokio")]
        if let Some(capture) = &self.packet_capture {
            capture.record(false, bearer_id, packet.bytes());
        }
        self.bearers
            .get_mut(bearer_id)
            .ok_or(QuicNodeEgressError::MissingBearer)?
            .submit_or_retain(peer, packet);
        Ok(())
    }

    pub(crate) fn submit_node_packet(
        &mut self,
        packet: NodeEgress<P::Buffer>,
    ) -> Result<(), QuicNodeEgressError> {
        let clock_us = self.clock_us;
        if let Some(slot) = self.slot_mut(packet.association) {
            slot.last_activity_us = clock_us;
        }
        self.submit_egress(packet.bearer, packet.peer_l2_address, packet.packet)
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
            Err(QuicNodeEgressError::PoolUnavailable | QuicNodeEgressError::BearerBusy) => {
                if !self.pending_controls.contains(&association) {
                    if self.pending_controls.len() == self.pending_controls.capacity() {
                        return Err(QuicNodeEgressError::StreamEventsFull);
                    }
                    self.pending_controls.push_back(association);
                }
                Ok(())
            }
            Err(error) => Err(error),
        }
    }

    /// Retry at most one deferred association control packet.
    ///
    /// Processing one item keeps scheduling in the platform adapter: it may
    /// call this after a bearer readiness or packet-completion event without
    /// constructing a polling loop inside the protocol state machine.
    pub(crate) fn retry_one_pending_control(&mut self) -> Result<bool, QuicNodeEgressError> {
        let Some(association) = self.pending_controls.pop_front() else {
            return Ok(false);
        };
        match self.submit_pending_control(association) {
            Ok(()) => Ok(true),
            Err(QuicNodeEgressError::PoolUnavailable | QuicNodeEgressError::BearerBusy) => {
                self.pending_controls.push_front(association);
                Ok(false)
            }
            Err(error) => Err(error),
        }
    }
}

enum Association<Client, Server> {
    Client(Client),
    Server(Server),
}

struct AssociationSlot<Client, Server> {
    generation: u64,
    receive_cid: ConnectionId,
    state: Association<Client, Server>,
    active_address: Option<(BearerId, PeerL2Address)>,
    known_addresses: Vec<(BearerId, PeerL2Address)>,
    bootstrap: Option<ClientBootstrap>,
    close_code: Option<u64>,
    last_activity_us: u64,
    client_delivery: crate::callback::CallbackStreams<Arc<Vec<u8>>>,
}

#[derive(Clone, Copy)]
struct ClientBootstrap {
    next_attempt: u32,
    last_attempt_at: u64,
}

const CLIENT_BOOTSTRAP_ATTEMPTS: u32 = 4;

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
    NextHop,
    const ASSOCIATIONS: usize,
    const ROUTES: usize,
    P: PacketPool + 'static,
    const CLIENT_HISTORY: usize = 8,
    const SERVER_STREAMS: usize = 8,
    const SERVER_HISTORY: usize = 8,
    const PACKET: usize = { crate::DEFAULT_MAX_PACKET_SIZE },
> {
    pub(crate) pool: &'static P,
    // The normal one-association case stays inline. A second association
    // spills this collection to the heap instead of reserving every complete
    // connection state at node construction.
    associations: SmallVec<
        [Option<
            AssociationSlot<
                ClientAssociation<CLIENT_HISTORY, PACKET>,
                ServerStreamConnection<SERVER_STREAMS, SERVER_HISTORY, PACKET>,
            >,
        >; 1],
    >,
    generations: Vec<u64>,
    next_local_cid: u64,
    next_direct_packet_number: u32,
    clock_us: u64,
    idle_timeout_us: u64,
    router: PacketRouter<QuicAssociation, NextHop, ROUTES>,
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
    #[cfg(feature = "tokio")]
    pub(crate) packet_capture: Option<crate::tokio::PacketCapture>,
    pending_controls: VecDeque<QuicAssociation>,
    association_events: VecDeque<AssociationEvent>,
}

impl<
    NextHop,
    const ASSOCIATIONS: usize,
    const ROUTES: usize,
    P: PacketPool,
    const CLIENT_HISTORY: usize,
    const SERVER_STREAMS: usize,
    const SERVER_HISTORY: usize,
    const PACKET: usize,
>
    QuicNode<
        NextHop,
        ASSOCIATIONS,
        ROUTES,
        P,
        CLIENT_HISTORY,
        SERVER_STREAMS,
        SERVER_HISTORY,
        PACKET,
    >
{
    /// Create a node with the packet pool it owns for all ingress and egress.
    ///
    /// The pool is deliberately selected here rather than by individual
    /// bearers or stream operations. Its leases and current use are therefore
    /// visible to the node's memory and receive-window policy.
    pub fn new(reset_key: Option<StatelessResetKey>, pool: &'static P) -> Self {
        assert!(ASSOCIATIONS <= u16::MAX as usize);
        let mut associations = SmallVec::new();
        if ASSOCIATIONS != 0 {
            associations.push(None);
        }
        #[cfg(feature = "tokio")]
        let (ingress_sender, ingress) = crate::bearer::tokio::channel(pool.capacity().max(1));
        Self {
            pool,
            associations,
            generations: if ASSOCIATIONS == 0 {
                Vec::new()
            } else {
                vec![0]
            },
            next_local_cid: 1,
            next_direct_packet_number: 0,
            clock_us: 0,
            idle_timeout_us: DEFAULT_IDLE_TIMEOUT_US,
            router: PacketRouter::new(reset_key),
            bearers: BearerRegistry::new(),
            completions: Arc::new(CompletionQueue::new(pool.capacity().max(1))),
            #[cfg(feature = "tokio")]
            ingress_sender,
            #[cfg(feature = "tokio")]
            ingress,
            #[cfg(feature = "tokio")]
            stream_chunks: std::collections::VecDeque::with_capacity(
                ASSOCIATIONS.saturating_mul(SERVER_STREAMS).max(1),
            ),
            #[cfg(feature = "tokio")]
            stream_chunk_limit: ASSOCIATIONS.saturating_mul(SERVER_STREAMS).max(1),
            #[cfg(feature = "tokio")]
            packet_capture: crate::tokio::PacketCapture::from_env(),
            pending_controls: VecDeque::with_capacity(ASSOCIATIONS.max(1)),
            association_events: VecDeque::new(),
        }
    }

    /// Initialize a no-std node directly in its final storage.
    ///
    /// Embedded runtimes use this for fixed-capacity association tables that
    /// are intentionally larger than an RTOS packet task's stack. The caller
    /// supplies uninitialized heap or static storage; every field is written
    /// before the returned reference becomes observable.
    pub(crate) unsafe fn new_in_place<'a>(
        storage: &'a mut core::mem::MaybeUninit<Self>,
        reset_key: Option<StatelessResetKey>,
        pool: &'static P,
    ) -> &'a mut Self {
        assert!(ASSOCIATIONS <= u16::MAX as usize);
        // SAFETY: `storage` is one aligned, uninitialized `Self`. Every field
        // is written exactly once before the initialized reference escapes.
        unsafe {
            let node = storage.as_mut_ptr();
            core::ptr::addr_of_mut!((*node).pool).write(pool);
            let associations = core::ptr::addr_of_mut!((*node).associations);
            associations.write(SmallVec::new());
            if ASSOCIATIONS != 0 {
                (*associations).push(None);
            }
            core::ptr::addr_of_mut!((*node).generations).write(if ASSOCIATIONS == 0 {
                Vec::new()
            } else {
                vec![0]
            });
            core::ptr::addr_of_mut!((*node).next_local_cid).write(1);
            core::ptr::addr_of_mut!((*node).next_direct_packet_number).write(0);
            core::ptr::addr_of_mut!((*node).clock_us).write(0);
            core::ptr::addr_of_mut!((*node).idle_timeout_us).write(DEFAULT_IDLE_TIMEOUT_US);
            core::ptr::addr_of_mut!((*node).router).write(PacketRouter::new(reset_key));
            core::ptr::addr_of_mut!((*node).bearers).write(BearerRegistry::new());
            core::ptr::addr_of_mut!((*node).completions)
                .write(Arc::new(CompletionQueue::new(pool.capacity().max(1))));
            #[cfg(feature = "tokio")]
            {
                let (ingress_sender, ingress) =
                    crate::bearer::tokio::channel(pool.capacity().max(1));
                core::ptr::addr_of_mut!((*node).ingress_sender).write(ingress_sender);
                core::ptr::addr_of_mut!((*node).ingress).write(ingress);
                core::ptr::addr_of_mut!((*node).stream_chunks).write(
                    std::collections::VecDeque::with_capacity(
                        ASSOCIATIONS.saturating_mul(SERVER_STREAMS).max(1),
                    ),
                );
                core::ptr::addr_of_mut!((*node).stream_chunk_limit)
                    .write(ASSOCIATIONS.saturating_mul(SERVER_STREAMS).max(1));
                core::ptr::addr_of_mut!((*node).packet_capture)
                    .write(crate::tokio::PacketCapture::from_env());
            }
            core::ptr::addr_of_mut!((*node).pending_controls)
                .write(VecDeque::with_capacity(ASSOCIATIONS.max(1)));
            core::ptr::addr_of_mut!((*node).association_events).write(VecDeque::new());
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
    }

    pub(crate) const fn clock_us(&self) -> u64 {
        self.clock_us
    }

    pub(crate) fn add_client(
        &mut self,
        receive_cid: ConnectionId,
        association: ClientAssociation<CLIENT_HISTORY, PACKET>,
    ) -> Result<QuicAssociation, QuicNodeError> {
        self.insert(receive_cid, Association::Client(association))
    }

    pub(crate) fn add_server(
        &mut self,
        receive_cid: ConnectionId,
        association: ServerStreamConnection<SERVER_STREAMS, SERVER_HISTORY, PACKET>,
    ) -> Result<QuicAssociation, QuicNodeError> {
        self.insert(receive_cid, Association::Server(association))
    }

    fn insert(
        &mut self,
        receive_cid: ConnectionId,
        state: Association<
            ClientAssociation<CLIENT_HISTORY, PACKET>,
            ServerStreamConnection<SERVER_STREAMS, SERVER_HISTORY, PACKET>,
        >,
    ) -> Result<QuicAssociation, QuicNodeError> {
        let slot = self
            .associations
            .iter()
            .position(Option::is_none)
            .or_else(|| (self.associations.len() < ASSOCIATIONS).then_some(self.associations.len()))
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
            slot: slot as u16,
            generation,
        };
        self.router.register_endpoint(receive_cid, id)?;
        self.generations[slot] = generation;
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
            state,
            active_address: None,
            known_addresses: Vec::new(),
            bootstrap: None,
            close_code: None,
            last_activity_us: self.clock_us,
            client_delivery: crate::callback::CallbackStreams::new(
                crate::DEFAULT_STREAM_STATE_LIMIT,
                client_retention,
            ),
        });
        if slot == self.associations.len() {
            self.associations.push(entry);
        } else {
            self.associations[slot] = entry;
        }
        Ok(id)
    }

    pub(crate) fn register_forward(
        &mut self,
        receive_cid: ConnectionId,
        rule: ForwardRule<NextHop>,
    ) -> Result<(), QuicNodeError> {
        self.router.register_forward(receive_cid, rule)?;
        Ok(())
    }

    pub(crate) fn remove_forward(&mut self, receive_cid: ConnectionId) -> bool {
        self.router.remove_forward(receive_cid)
    }

    #[cfg(test)]
    fn client(&self, id: QuicAssociation) -> Option<&ClientAssociation<CLIENT_HISTORY, PACKET>> {
        match &self.slot(id)?.state {
            Association::Client(client) => Some(client),
            Association::Server(_) => None,
        }
    }

    #[cfg(test)]
    fn server(
        &self,
        id: QuicAssociation,
    ) -> Option<&ServerStreamConnection<SERVER_STREAMS, SERVER_HISTORY, PACKET>> {
        match &self.slot(id)?.state {
            Association::Server(server) => Some(server),
            Association::Client(_) => None,
        }
    }

    #[cfg(test)]
    fn receive_cid(&self, id: QuicAssociation) -> Option<ConnectionId> {
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
        self.slot(id)?.active_address
    }

    /// Accepted physical return addresses, newest first.
    #[cfg(test)]
    fn association_addresses(&self, id: QuicAssociation) -> Option<Vec<(BearerId, PeerL2Address)>> {
        Some(self.slot(id)?.known_addresses.clone())
    }

    pub(crate) fn remove_client(
        &mut self,
        id: QuicAssociation,
    ) -> Result<ClientAssociation<CLIENT_HISTORY, PACKET>, QuicNodeError> {
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
    ) -> Result<ServerStreamConnection<SERVER_STREAMS, SERVER_HISTORY, PACKET>, QuicNodeError> {
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
    ) -> Result<
        Association<
            ClientAssociation<CLIENT_HISTORY, PACKET>,
            ServerStreamConnection<SERVER_STREAMS, SERVER_HISTORY, PACKET>,
        >,
        QuicNodeError,
    > {
        let slot = self
            .slot_index(id)
            .ok_or(QuicNodeError::MissingAssociation)?;
        let entry = self.associations[slot]
            .take()
            .ok_or(QuicNodeError::MissingAssociation)?;
        let removed = self.router.remove_endpoint(entry.receive_cid, &id);
        debug_assert!(removed, "association and DCID route must retire together");
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
        self.association_events.pop_front()
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

    pub(crate) fn allocate_local_cid(&mut self) -> Result<ConnectionId, QuicNodeError> {
        for _ in 0..=ASSOCIATIONS {
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
    ) -> Option<
        &AssociationSlot<
            ClientAssociation<CLIENT_HISTORY, PACKET>,
            ServerStreamConnection<SERVER_STREAMS, SERVER_HISTORY, PACKET>,
        >,
    > {
        self.associations.get(self.slot_index(id)?)?.as_ref()
    }

    fn slot_mut(
        &mut self,
        id: QuicAssociation,
    ) -> Option<
        &mut AssociationSlot<
            ClientAssociation<CLIENT_HISTORY, PACKET>,
            ServerStreamConnection<SERVER_STREAMS, SERVER_HISTORY, PACKET>,
        >,
    > {
        let slot = self.slot_index(id)?;
        self.associations.get_mut(slot)?.as_mut()
    }

    fn slot_index(&self, id: QuicAssociation) -> Option<usize> {
        let slot = id.slot as usize;
        let entry = self.associations.get(slot)?.as_ref()?;
        (entry.generation == id.generation).then_some(slot)
    }

    fn remember_address(&mut self, id: QuicAssociation, meta: PacketMeta) {
        let clock_us = self.clock_us;
        let Some(slot) = self.slot_mut(id) else {
            return;
        };
        let address = (meta.bearer, meta.peer_l2_address);
        if slot.known_addresses.first() != Some(&address) {
            if let Some(index) = slot
                .known_addresses
                .iter()
                .position(|known| *known == address)
            {
                slot.known_addresses.remove(index);
            } else if slot.known_addresses.try_reserve(1).is_err() {
                slot.active_address = Some(address);
                slot.last_activity_us = clock_us;
                return;
            }
            slot.known_addresses.insert(0, address);
            slot.known_addresses.truncate(4);
        }
        slot.active_address = Some(address);
        slot.last_activity_us = clock_us;
    }
}

impl<
    NextHop,
    const CLIENT_HISTORY: usize,
    const SERVER_STREAMS: usize,
    const SERVER_HISTORY: usize,
    const PACKET: usize,
    const ASSOCIATIONS: usize,
    const ROUTES: usize,
    P,
> QuicNode<NextHop, ASSOCIATIONS, ROUTES, P, CLIENT_HISTORY, SERVER_STREAMS, SERVER_HISTORY, PACKET>
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
        let mut client = ClientAssociation::new(receive_cid);
        if let Some(token) = self.router.reset_token_for(receive_cid) {
            client.connection_mut().set_local_reset_token(token);
        }
        let packet = Self::build_packet(self.pool, |output| client.start(output))?;
        let association = self.add_client(receive_cid, client)?;
        self.remember_address(association, address);
        self.slot_mut(association)
            .expect("new association remains installed")
            .bootstrap = Some(ClientBootstrap {
            next_attempt: 1,
            last_attempt_at: now,
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
            let (accepted, used) =
                ServerStreamConnection::accept_open_with_limits_and_reset_token_into(
                    packet,
                    server_cid,
                    local_limits,
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
            direct_buffer: Vec::new(),
        })
    }

    pub(crate) fn open_direct_stream(&mut self, address: PacketMeta) -> QuicStream {
        let packet_number = self.next_direct_packet_number;
        self.next_direct_packet_number = self.next_direct_packet_number.wrapping_add(2);
        QuicStream::direct(
            DirectReply {
                meta: address,
                packet_number: packet_number.wrapping_sub(1),
            },
            crate::callback::DIRECT_MESSAGE_STREAM_ID,
        )
    }

    /// Create a stream-shaped handle for one pre-association message.
    ///
    /// Its first write must contain the complete payload and FIN because the
    /// pre-handshake representation occupies one long-header packet. A peer
    /// receives it through the same stream callback or runtime adapter used by
    /// established streams, so application handlers do not inspect packet
    /// form.
    pub fn open_message(&mut self, address: PacketMeta) -> QuicStream {
        self.open_direct_stream(address)
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
        if let StreamOwner::Direct(reply) = stream.owner() {
            if !stream.can_send_direct() || !fin || bytes.is_empty() {
                return Err(QuicNodeEgressError::Transport(Error::Invalid));
            }
            let packet = self.respond_direct_to(reply, bytes)?;
            self.submit_unassociated_packet(packet)?;
            stream.finish_direct_send(bytes.len());
            return Ok(());
        }
        let association = stream
            .association()
            .ok_or(QuicNodeEgressError::Transport(Error::Invalid))?;
        let (bearer, _) = self
            .association_egress_address(association)
            .ok_or(QuicNodeEgressError::MissingEgressAddress)?;
        if !self
            .bearers
            .get(bearer)
            .is_some_and(|bearer| bearer.can_submit())
        {
            return Err(QuicNodeEgressError::BearerBusy);
        }
        let packet = self.build_stream_packet(stream, bytes, fin)?;
        self.submit_node_packet(packet)
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
        if stream.send_finished {
            return Err(QuicNodeEgressError::Transport(Error::Invalid));
        }
        if stream.is_direct() {
            let remaining =
                crate::DEFAULT_MAX_STREAM_PAYLOAD.saturating_sub(stream.direct_buffer.len());
            let count = remaining.min(bytes.len());
            if count == 0 {
                return Err(QuicNodeEgressError::Transport(Error::Blocked));
            }
            stream
                .direct_buffer
                .try_reserve(count)
                .map_err(|_| QuicNodeEgressError::PoolUnavailable)?;
            stream.direct_buffer.extend_from_slice(&bytes[..count]);
            return Ok(count);
        }
        let window = self.stream_send_window(stream)?;
        let count = bytes
            .len()
            .min(crate::DEFAULT_MAX_STREAM_PAYLOAD)
            .min(usize::try_from(window).unwrap_or(usize::MAX));
        if count == 0 {
            return Err(QuicNodeEgressError::Transport(Error::Blocked));
        }
        self.write_stream_packet(stream, &bytes[..count], false)?;
        Ok(count)
    }

    /// Close the stream's sending half after all accepted bytes.
    pub fn finish_stream(&mut self, stream: &mut QuicStream) -> Result<(), QuicNodeEgressError>
    where
        P::Buffer: Send,
    {
        if stream.send_finished {
            return Ok(());
        }
        if stream.is_direct() {
            if stream.direct_buffer.is_empty() {
                return Err(QuicNodeEgressError::Transport(Error::Invalid));
            }
            let bytes = core::mem::take(&mut stream.direct_buffer);
            match self.write_stream_packet(stream, &bytes, true) {
                Ok(()) => Ok(()),
                Err(error) => {
                    stream.direct_buffer = bytes;
                    Err(error)
                }
            }
        } else {
            self.write_stream_packet(stream, &[], true)
        }
    }

    /// Peer-advertised byte credit at the stream's current ordered position.
    pub fn stream_send_window(&self, stream: &QuicStream) -> Result<u64, QuicNodeEgressError> {
        match stream.owner {
            StreamOwner::Association(association) => {
                self.stream_flow_control_window(association, stream.id, stream.send_offset)
            }
            StreamOwner::Direct(_) if stream.send_finished => Ok(0),
            StreamOwner::Direct(_) => Ok(crate::DEFAULT_MAX_STREAM_PAYLOAD as u64),
        }
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
        let packet = self.send_stream(association, stream.id, stream.send_offset, fin, bytes)?;
        stream.send_offset = stream
            .send_offset
            .checked_add(bytes.len() as u64)
            .ok_or(QuicNodeEgressError::Transport(Error::Invalid))?;
        stream.send_finished = fin;
        Ok(packet)
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
        let pool = self.pool;
        let (bearer, peer_l2_address) = self
            .slot(association)
            .ok_or(QuicNodeError::MissingAssociation)?
            .active_address
            .ok_or(QuicNodeEgressError::MissingEgressAddress)?;
        let slot = self
            .slot_mut(association)
            .ok_or(QuicNodeError::MissingAssociation)?;
        if slot.close_code.is_some() {
            return Err(QuicNodeEgressError::Transport(Error::Invalid));
        }
        let packet = match &mut slot.state {
            Association::Client(client) => Self::build_packet(pool, |output| {
                client.encode_stream_payload_at(stream_id, offset, bytes, fin, output)
            })?,
            Association::Server(server) => Self::build_packet(pool, |output| {
                server.encode_stream_payload_at(stream_id, offset, bytes, fin, output)
            })?,
        };
        Ok(NodeEgress {
            association,
            bearer,
            peer_l2_address,
            packet,
        })
    }

    /// Build at most one ACK or flow-control packet made pending by ingress.
    pub(crate) fn poll_association_control(
        &mut self,
        association: QuicAssociation,
    ) -> Result<Option<NodeEgress<P::Buffer>>, QuicNodeEgressError> {
        let pool = self.pool;
        let (bearer, peer_l2_address) = self
            .slot(association)
            .ok_or(QuicNodeError::MissingAssociation)?
            .active_address
            .ok_or(QuicNodeEgressError::MissingEgressAddress)?;
        let slot = self
            .slot_mut(association)
            .ok_or(QuicNodeError::MissingAssociation)?;
        let packet = match &mut slot.state {
            Association::Client(client) => Self::build_optional_packet(pool, |output| {
                client.connection_mut().poll_transmit(output)
            })?,
            Association::Server(server) => {
                Self::build_optional_packet(pool, |output| server.poll_transmit(output))?
            }
        };
        Ok(packet.map(|packet| NodeEgress {
            association,
            bearer,
            peer_l2_address,
            packet,
        }))
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
            slot.active_address
                .ok_or(QuicNodeEgressError::MissingEgressAddress)?
        };

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
        pto: u64,
    ) -> Result<Option<NodeTimer<P::Buffer>>, QuicNodeEgressError> {
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
                slot: slot_index as u16,
                generation: slot.generation,
            };
            self.remove(association)?;
            self.association_events
                .push_back(AssociationEvent::IdleTimeout { association });
            return Ok(Some(NodeTimer::IdleTimedOut { association }));
        }
        let slot_index = self
            .associations
            .iter()
            .enumerate()
            .filter_map(|(index, slot)| {
                let slot = slot.as_ref()?;
                let deadline = slot.bootstrap.map_or_else(
                    || match &slot.state {
                        Association::Client(client) => client.next_bearer_deadline(pto),
                        Association::Server(server) => server.next_bearer_deadline(pto),
                    },
                    |bootstrap| Some(bootstrap.last_attempt_at.saturating_add(pto.max(1))),
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
                slot: slot_index as u16,
                generation: slot.generation,
            }
        };
        if let Some(bootstrap) = self.associations[slot_index]
            .as_ref()
            .and_then(|slot| slot.bootstrap)
        {
            if bootstrap.next_attempt >= CLIENT_BOOTSTRAP_ATTEMPTS {
                self.remove_client(association)?;
                return Ok(Some(NodeTimer::BootstrapTimedOut { association }));
            }
            let slot = self.associations[slot_index]
                .as_mut()
                .expect("selected association remains installed");
            let (bearer, peer_l2_address) = slot
                .active_address
                .ok_or(QuicNodeEgressError::MissingEgressAddress)?;
            let client = match &mut slot.state {
                Association::Client(client) => client,
                Association::Server(_) => unreachable!("only clients bootstrap"),
            };
            let packet = Self::build_packet(self.pool, |output| {
                client.encode_open_attempt(bootstrap.next_attempt, output)
            })?;
            slot.bootstrap = Some(ClientBootstrap {
                next_attempt: bootstrap.next_attempt.saturating_add(1),
                last_attempt_at: now,
            });
            return Ok(Some(NodeTimer::Egress(NodeEgress {
                association,
                bearer,
                peer_l2_address,
                packet,
            })));
        }
        let slot = self.associations[slot_index]
            .as_mut()
            .expect("selected association remains installed");
        let (bearer, peer_l2_address) = slot
            .active_address
            .ok_or(QuicNodeEgressError::MissingEgressAddress)?;
        let packet = match &mut slot.state {
            Association::Client(client) => Self::build_optional_packet(self.pool, |output| {
                client.poll_timer(now, pto, output)
            })?,
            Association::Server(server) => Self::build_optional_packet(self.pool, |output| {
                server.poll_timer(now, pto, output)
            })?,
        };
        Ok(packet.map(|packet| {
            NodeTimer::Egress(NodeEgress {
                association,
                bearer,
                peer_l2_address,
                packet,
            })
        }))
    }

    /// Classify and process one complete opaque packet from any bearer.
    ///
    /// This is the only packet-ingress API. The bearer does not inspect QUIC
    /// headers or select a follow-up method. `admit_initial` is node policy,
    /// called only after QUIC-lite has validated an Initial; returning `None`
    /// declines admission without changing node state.
    /// `on_stream` receives application bytes in increasing offset order for
    /// each stream. Today QUIC-lite retains ranges received behind a gap and
    /// calls the handler only when the missing prefix arrives. A future
    /// explicitly selected mode may permit out-of-order callbacks; it will not
    /// change this ordered default silently. Direct messages are delivered as
    /// one `Direct` chunk at offset zero with `fin == true`.
    pub(crate) fn receive_packet<B, Admit, StreamEvent>(
        &mut self,
        meta: PacketMeta,
        packet: OwnedPacket<B>,
        mut admit_initial: Admit,
        mut on_stream: StreamEvent,
    ) -> Result<NodeIngress<B, P::Buffer, NextHop>, RejectedNodePacket<B>>
    where
        B: AsRef<[u8]>,
        NextHop: Copy,
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
                self.association_events
                    .push_back(AssociationEvent::Reset { association: id });
                return Ok(NodeIngress::PeerReset {
                    association: id,
                    packet,
                });
            }
        };

        match classified {
            ServerPacket::Direct => {
                let request = match crate::receive_direct_message_request(bytes) {
                    Ok(request) => request,
                    Err(error) => return Ok(NodeIngress::NonQuic { error, packet }),
                };
                let start = request.payload().as_ptr() as usize - bytes.as_ptr() as usize;
                let end = start + request.payload().len();
                let packet_number = request.packet_number;
                if let Err(error) = on_stream(
                    ApplicationStreamSource::Direct,
                    crate::callback::DIRECT_MESSAGE_STREAM_ID,
                    0,
                    true,
                    request.payload(),
                ) {
                    return Err(RejectedNodePacket {
                        reason: QuicNodePacketRejection::Application(error),
                        packet,
                    });
                }
                Ok(NodeIngress::Direct(DirectNodeIngress {
                    meta,
                    packet,
                    payload: start..end,
                    packet_number,
                }))
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
                                        slot: index as u16,
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
                let response = match self.accept_initial(
                    meta,
                    bytes,
                    admission.server_cid,
                    admission.local_limits,
                ) {
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
                    Endpoint(QuicAssociation),
                    Forward(ForwardRule<N>),
                    Missing,
                }
                let target = match self.router.target(bytes) {
                    Ok(RouterTarget::Endpoint(id)) => Target::Endpoint(*id),
                    Ok(RouterTarget::Forward(rule)) => Target::Forward(*rule),
                    Ok(RouterTarget::Missing) => Target::Missing,
                    Err(error) => return Ok(NodeIngress::NonQuic { error, packet }),
                };
                match target {
                    Target::Endpoint(id) => {
                        match self.receive_association_bytes(id, meta, bytes, &mut on_stream) {
                            Ok(association) => Ok(NodeIngress::Association {
                                association,
                                packet,
                            }),
                            Err(QuicNodePacketRejection::Packet(Error::PeerRestarted)) => {
                                let _ = self.remove(id);
                                self.association_events
                                    .push_back(AssociationEvent::Reset { association: id });
                                Ok(NodeIngress::PeerReset {
                                    association: id,
                                    packet,
                                })
                            }
                            Err(QuicNodePacketRejection::PeerClosed(code)) => {
                                self.association_events.push_back(AssociationEvent::Closed {
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
                        }
                    }
                    Target::Forward(rule) => {
                        let forwarded =
                            Self::build_packet(self.pool, |output| match rule.destination {
                                ForwardDestination::Connection(dcid) => {
                                    crate::rewrite_dcid(bytes, dcid, output)
                                }
                                ForwardDestination::Bootstrap => {
                                    crate::rewrite_bootstrap_destination(bytes, output)
                                }
                            })
                            .map_err(|error| RejectedNodePacket {
                                reason: QuicNodePacketRejection::Egress(error),
                                packet,
                            })?;
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
                }
            }
        }
    }

    pub(crate) fn respond_direct<B>(
        &mut self,
        request: DirectNodeIngress<B>,
        payload: &[u8],
    ) -> Result<NodePacket<P::Buffer>, QuicNodeEgressError>
    where
        B: AsRef<[u8]>,
    {
        self.respond_direct_to(request.reply(), payload)
    }

    pub(crate) fn respond_direct_to(
        &mut self,
        reply: DirectReply,
        payload: &[u8],
    ) -> Result<NodePacket<P::Buffer>, QuicNodeEgressError> {
        let packet = Self::build_packet(self.pool, |output| {
            crate::encode_direct_packet(reply.packet_number.wrapping_add(1), payload, output)
        })?;
        Ok(NodePacket {
            bearer: reply.meta.bearer,
            peer_l2_address: reply.meta.peer_l2_address,
            packet,
        })
    }

    fn receive_association_bytes<StreamEvent>(
        &mut self,
        id: QuicAssociation,
        meta: PacketMeta,
        bytes: &[u8],
        on_stream: &mut StreamEvent,
    ) -> Result<AssociationIngress, QuicNodePacketRejection>
    where
        StreamEvent:
            FnMut(ApplicationStreamSource, u64, u64, bool, &[u8]) -> Result<usize, crate::Error>,
    {
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
                    } else if let Some(payload) = client
                        .receive_stream_payload_packet(meta, bytes)
                        .map_err(QuicNodePacketRejection::Packet)?
                    {
                        let mut sink = OrderedNodeSink {
                            association: id,
                            handler: on_stream,
                            consumed: 0,
                        };
                        slot.client_delivery
                            .receive_copying_borrowed(
                                payload.stream_id,
                                payload.data,
                                payload.offset,
                                payload.fin,
                                || Arc::new(payload.data.to_vec()),
                                &mut sink,
                            )
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
                                .stream_consumed(payload.stream_id, sink.consumed, false)
                                .map_err(QuicNodePacketRejection::Packet)?;
                        }
                    }
                    AssociationIngress::Client(id)
                }
                Association::Server(server) => {
                    let mut received_streams = Vec::new();
                    server
                        .receive_stream_events(bytes, |stream_id, offset, fin, data| {
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
                        })
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
        self.remember_address(id, meta);
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
                        .stream_consumed(stream_id, sink.consumed, false)
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
    pub(crate) fn next_deadline(&self, pto: u64) -> Option<u64> {
        self.associations
            .iter()
            .flatten()
            .filter_map(|slot| {
                let idle = slot.last_activity_us.saturating_add(self.idle_timeout_us);
                let transport = match slot.bootstrap {
                    Some(bootstrap) => Some(bootstrap.last_attempt_at.saturating_add(pto.max(1))),
                    None => match &slot.state {
                        Association::Client(client) => client.next_bearer_deadline(pto),
                        Association::Server(server) => server.next_bearer_deadline(pto),
                    },
                };
                Some(transport.map_or(idle, |deadline| deadline.min(idle)))
            })
            .min()
    }
}

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

    fn ingress_meta() -> PacketMeta {
        PacketMeta {
            bearer: BearerId::new(1).unwrap(),
            peer_l2_address: PeerL2Address::new(9).unwrap(),
            received_at_us: 1,
        }
    }

    #[test]
    fn second_association_spills_storage_to_heap() {
        let mut node = QuicNode::<(), 2, 2, TestPool>::new(None, &TEST_POOL);
        assert!(!node.associations.spilled());

        node.add_client(cid(1), ClientAssociation::new(cid(1)))
            .unwrap();
        assert!(!node.associations.spilled());

        node.add_client(cid(2), ClientAssociation::new(cid(2)))
            .unwrap();
        assert!(node.associations.spilled());
        assert_eq!(node.association_count(), 2);
    }

    #[test]
    fn removing_an_association_invalidates_its_generation_checked_id() {
        let mut node = QuicNode::<(), 1, 1, TestPool>::new(None, &TEST_POOL);
        let first = node
            .add_client(cid(1), ClientAssociation::new(cid(1)))
            .unwrap();
        assert!(node.remove_client(first).is_ok());
        assert_eq!(node.association_count(), 0);

        let second = node
            .add_client(cid(2), ClientAssociation::new(cid(2)))
            .unwrap();
        assert_ne!(first, second);
        assert!(node.client(first).is_none());
        assert!(node.client(second).is_some());
    }

    #[test]
    fn cid_collision_does_not_install_or_replace_association_state() {
        let mut node = QuicNode::<(), 2, 2, TestPool>::new(None, &TEST_POOL);
        let client = node
            .add_client(cid(1), ClientAssociation::new(cid(1)))
            .unwrap();
        assert_eq!(
            node.add_client(cid(1), ClientAssociation::new(cid(2))),
            Err(QuicNodeError::Routing)
        );
        assert_eq!(node.association_count(), 1);
        assert!(node.client(client).is_some());
    }

    #[test]
    fn wrong_role_removal_leaves_association_installed() {
        let mut node = QuicNode::<(), 1, 1, TestPool>::new(None, &TEST_POOL);
        let client = node
            .add_client(cid(1), ClientAssociation::new(cid(1)))
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
        let node = QuicNode::<(), 1, 1, TestPool>::new(None, &TEST_POOL);
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
        type Node = QuicNode<(), 4, 4, Pool, 8, 4, 8, PACKET>;
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
        let server_cid = cid(0x47);
        let mut node = Node::new(None, &POOL);
        let open = node.start_association(client_cid, udp, 0).unwrap();
        let association = open.association;
        let mut server_node = Node::new(None, &POOL);
        let (server_association, ack) = match server_node
            .receive_packet(
                uart,
                open.packet,
                |_| {
                    Some(InitialAdmission {
                        server_cid,
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

        // A valid duplicate may arrive over a different bearer with the same
        // numeric bearer-local handle. The pair, rather than the handle alone,
        // becomes the new return address.
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
            Some((uart.bearer, uart.peer_l2_address))
        );
        assert_eq!(
            node.association_addresses(association).unwrap()[..2],
            [
                (uart.bearer, uart.peer_l2_address),
                (udp.bearer, udp.peer_l2_address),
            ]
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
    fn public_node_probe_uses_flow_window_and_multi_packet_fin() {
        const PACKET: usize = 256;
        const SLOT: usize = PACKET_PREFIX_RESERVE + PACKET + PACKET_SUFFIX_RESERVE;
        type Pool = crate::packet_pool::PacketPool<4, SLOT>;
        type Node = QuicNode<(), 2, 2, Pool, 8, 4, 8, PACKET>;
        static POOL: Pool = Pool::new();

        let meta = ingress_meta();
        let mut client_node = Node::new(None, &POOL);
        let mut server_node = Node::new(None, &POOL);
        let open = client_node.start_association(cid(0x71), meta, 0).unwrap();
        let client = open.association;
        let server = match server_node
            .receive_packet(
                meta,
                open.packet,
                |_| {
                    Some(InitialAdmission {
                        server_cid: cid(0x72),
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
        type Node = QuicNode<(), 4, 4, Pool, 8, 4, 8, PACKET>;
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
        let server_cid = cid(0x61);
        let mut client_node = Node::new(None, &CLIENT_POOL);
        let open = client_node
            .start_association(client_cid, client_meta, 0)
            .unwrap();
        let client_id = open.association;
        let mut server_node = Node::new(None, &SERVER_POOL);
        let (server_id, ack) = match server_node
            .receive_packet(
                server_meta,
                open.packet,
                |_| {
                    Some(InitialAdmission {
                        server_cid,
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
        assert!(client_node.next_deadline(100).is_some());

        let request = client_node.send_message(client_id, b"request").unwrap();
        assert_eq!(request.packet.prefix_capacity(), PACKET_PREFIX_RESERVE);
        assert!(request.packet.suffix_capacity() >= PACKET_SUFFIX_RESERVE);
        let deadline = client_node.next_deadline(100).unwrap();
        let retransmission = match client_node.timer_expired(deadline, 100).unwrap().unwrap() {
            NodeTimer::Egress(egress) => egress,
            NodeTimer::BootstrapTimedOut { .. } => panic!("established association timed out"),
            NodeTimer::IdleTimedOut { .. } => panic!("established association idled"),
        };
        assert_eq!(retransmission.association, client_id);
        assert_eq!(retransmission.bearer, client_meta.bearer);
        assert_eq!(retransmission.peer_l2_address, client_meta.peer_l2_address);
        drop(retransmission);

        let mut request_body = None;
        let mut request_stream = None;
        server_node
            .receive_packet(
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
        let mut response_body = None;
        client_node
            .receive_packet(
                client_meta,
                response.packet,
                |_| None,
                |source, _stream, offset, fin, bytes| {
                    assert_eq!(source, ApplicationStreamSource::Association(client_id));
                    assert_eq!(offset, 0);
                    assert!(fin);
                    response_body = Some(bytes.to_vec());
                    Ok(bytes.len())
                },
            )
            .unwrap();
        assert_eq!(response_body.as_deref(), Some(b"response".as_slice()));

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
    }

    #[test]
    fn client_bootstrap_retries_with_new_packet_numbers_then_retires_its_dcid() {
        const PACKET: usize = 256;
        const SLOT: usize = PACKET_PREFIX_RESERVE + PACKET + PACKET_SUFFIX_RESERVE;
        type Pool = crate::packet_pool::PacketPool<1, SLOT>;
        type Node = QuicNode<(), 2, 2, Pool, 4, 4, 4, PACKET>;
        static POOL: Pool = Pool::new();

        let meta = PacketMeta {
            bearer: BearerId::new(1).unwrap(),
            peer_l2_address: PeerL2Address::new(9).unwrap(),
            received_at_us: 0,
        };
        let cid = cid(0x91);
        let mut node = Node::new(None, &POOL);
        let initial = node.start_association(cid, meta, 10).unwrap();
        let association = initial.association;
        let (header, _) =
            crate::decode_bootstrap_open_packet_with_limits(initial.packet.bytes()).unwrap();
        assert_eq!(header.packet_number, 0);
        drop(initial);

        assert_eq!(node.next_deadline(100), Some(110));
        assert!(node.timer_expired(109, 100).unwrap().is_none());
        let held_slot = POOL.acquire_with(&[0x55]).unwrap();
        assert!(matches!(
            node.timer_expired(110, 100),
            Err(QuicNodeEgressError::PoolUnavailable)
        ));
        drop(held_slot);
        for attempt in 1..CLIENT_BOOTSTRAP_ATTEMPTS {
            let now = 10 + u64::from(attempt) * 100;
            let retry = match node.timer_expired(now, 100).unwrap().unwrap() {
                NodeTimer::Egress(egress) => egress,
                NodeTimer::BootstrapTimedOut { .. } => panic!("attempt must be emitted"),
                NodeTimer::IdleTimedOut { .. } => panic!("bootstrap association idled"),
            };
            assert_eq!(retry.association, association);
            assert_eq!(retry.bearer, meta.bearer);
            assert_eq!(retry.peer_l2_address, meta.peer_l2_address);
            let (header, _) =
                crate::decode_bootstrap_open_packet_with_limits(retry.packet.bytes()).unwrap();
            assert_eq!(header.packet_number, attempt);
            drop(retry);
            assert_eq!(node.next_deadline(100), Some(now + 100));
        }
        assert_eq!(node.association_count(), 1);

        assert!(matches!(
            node.timer_expired(10 + u64::from(CLIENT_BOOTSTRAP_ATTEMPTS) * 100, 100)
                .unwrap(),
            Some(NodeTimer::BootstrapTimedOut { association: timed_out })
                if timed_out == association
        ));
        assert_eq!(node.association_count(), 0);
        assert!(node.client(association).is_none());
        assert_eq!(node.receive_cid(association), None);
        assert_eq!(node.next_deadline(100), None);
    }

    #[test]
    fn deployed_short_header_response_establishes_symmetric_cid_client() {
        const PACKET: usize = 256;
        const SLOT: usize = PACKET_PREFIX_RESERVE + PACKET + PACKET_SUFFIX_RESERVE;
        type Pool = crate::packet_pool::PacketPool<4, SLOT>;
        type Node = QuicNode<(), 2, 2, Pool, 8, 4, 8, PACKET>;
        static POOL: Pool = Pool::new();

        let meta = ingress_meta();
        let mut node = Node::new(None, &POOL);
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
    fn unified_ingress_covers_decline_forward_reset_unknown_and_non_quic() {
        const PACKET: usize = 256;
        const SLOT: usize = PACKET_PREFIX_RESERVE + PACKET + PACKET_SUFFIX_RESERVE;
        type Pool = crate::packet_pool::PacketPool<4, SLOT>;
        type Node = QuicNode<u8, 4, 5, Pool, 8, 4, 8, PACKET>;
        static INPUT_POOL: Pool = Pool::new();
        static OUTPUT_POOL: Pool = Pool::new();

        let meta = ingress_meta();
        let mut source = Node::new(None, &INPUT_POOL);
        let initial = source.start_association(cid(0x21), meta, 0).unwrap();
        let mut node = Node::new(
            Some(StatelessResetKey::from_device_secret(&[0x35; 32]).unwrap()),
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
                next_hop: 7,
                destination: ForwardDestination::Connection(destination_cid),
            },
        )
        .unwrap();
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
                assert_eq!(next_hop, 7);
                assert_eq!(
                    ShortHeader::decode(packet.bytes()).unwrap().0.dcid,
                    destination_cid
                );
            }
            _ => panic!("relay CID must return a forwarding action"),
        }

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
    fn server_association_recognizes_client_stateless_reset_on_any_bearer() {
        const PACKET: usize = 256;
        const SLOT: usize = PACKET_PREFIX_RESERVE + PACKET + PACKET_SUFFIX_RESERVE;
        type Pool = crate::packet_pool::PacketPool<4, SLOT>;
        type Node = QuicNode<(), 2, 2, Pool, 8, 4, 8, PACKET>;
        static CLIENT_POOL: Pool = Pool::new();
        static SERVER_POOL: Pool = Pool::new();

        let client_key = StatelessResetKey::from_device_secret(&[0x45; 32]).unwrap();
        let server_key = StatelessResetKey::from_device_secret(&[0x46; 32]).unwrap();
        let meta = ingress_meta();
        let client_cid = cid(0x61);
        let mut client = Node::new(Some(client_key), &CLIENT_POOL);
        let initial = client.start_association(client_cid, meta, 0).unwrap();
        let mut server = Node::new(Some(server_key), &SERVER_POOL);
        let admitted = server
            .receive_packet(
                meta,
                initial.packet,
                |_| {
                    Some(InitialAdmission {
                        server_cid: cid(0x62),
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
            Some(AssociationEvent::Reset { .. })
        ));
    }

    #[test]
    fn unified_ingress_replays_only_the_exact_initial_without_readmission() {
        const PACKET: usize = 256;
        const SLOT: usize = PACKET_PREFIX_RESERVE + PACKET + PACKET_SUFFIX_RESERVE;
        type Pool = crate::packet_pool::PacketPool<2, SLOT>;
        type Node = QuicNode<(), 2, 2, Pool, 8, 4, 8, PACKET>;
        static POOL: Pool = Pool::new();

        let client_cid = cid(0x61);
        let server_cid = cid(0x62);
        let mut initial = [0u8; PACKET];
        let initial_len = crate::encode_bootstrap_open_packet(client_cid, 0, &mut initial).unwrap();
        let mut node = Node::new(None, &POOL);
        let first = node
            .receive_packet(
                ingress_meta(),
                OwnedPacket::new(initial, 0..initial_len).unwrap(),
                |_| {
                    Some(InitialAdmission {
                        server_cid,
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
}
