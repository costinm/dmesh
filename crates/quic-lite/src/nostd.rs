//! Immediate node driving for platforms without an async executor.
//!
//! Bearer registration, packet storage, readiness, completion, and physical
//! submission are common [`crate::QuicNode`] behavior. This module only turns
//! one synchronously received bearer packet into node progress and retains the
//! resulting application association/stream events.

use alloc::{boxed::Box, collections::VecDeque, sync::Arc, vec::Vec};
use spin::Mutex;

use crate::node::{
    ApplicationStreamSource, InitialAdmission, NodeIngress, QuicNodePacketRejection,
};
use crate::{
    AddBearerError, ConnectionLimits, OwnedPacket, PacketBearer, PacketMeta, PacketPool,
    QuicAssociation, QuicNode, QuicNodeEgressError, ReceivedStreamChunk,
};

struct IngressQueue<B> {
    packets: Mutex<VecDeque<crate::bearer::ReceivedPacket<B>>>,
    capacity: usize,
}

impl<B> IngressQueue<B> {
    fn new(capacity: usize) -> Self {
        Self {
            packets: Mutex::new(VecDeque::with_capacity(capacity)),
            capacity,
        }
    }

    fn pop(&self) -> Option<crate::bearer::ReceivedPacket<B>> {
        self.packets.lock().pop_front()
    }
}

impl<B: AsRef<[u8]> + Send> crate::bearer::PacketIngressQueue<B> for IngressQueue<B> {
    fn enqueue_packet(&self, meta: PacketMeta, packet: OwnedPacket<B>) {
        let mut packets = self.packets.lock();
        if packets.len() == self.capacity {
            drop(packet);
        } else {
            packets.push_back(crate::bearer::ReceivedPacket { meta, packet });
        }
    }
}

/// Synchronous application adapter around one common QUIC node.
///
/// This type contains no bearer registry, packet pool, ingress queue, or
/// physical submission callback. Those remain owned by `QuicNode` and the
/// common bearer interface.
pub struct NoStdRuntime<
    NextHop,
    const ASSOCIATIONS: usize,
    const ROUTES: usize,
    P: PacketPool + 'static,
    const CLIENT_HISTORY: usize = 8,
    const SERVER_STREAMS: usize = 8,
    const SERVER_HISTORY: usize = 8,
    const PACKET: usize = { crate::DEFAULT_MAX_PACKET_SIZE },
> {
    node: QuicNode<
        NextHop,
        ASSOCIATIONS,
        ROUTES,
        P,
        CLIENT_HISTORY,
        SERVER_STREAMS,
        SERVER_HISTORY,
        PACKET,
    >,
    limits: ConnectionLimits,
    ingress: Arc<IngressQueue<P::Buffer>>,
    accepted: VecDeque<QuicAssociation>,
    streams: VecDeque<ReceivedStreamChunk>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet_pool::PacketPool as FixedPool;
    use crate::{
        BearerContext, BearerInfo, BearerName, EgressSubmission, PacketBearer, PacketEgress,
        PacketSendOutcome, PacketSubmitError, PeerL2Address, StatelessResetKey,
    };
    use std::sync::{Arc, Mutex};

    type Pool = FixedPool<4, { crate::DEFAULT_PACKET_POOL_SLOT_SIZE }>;
    static POOL: Pool = Pool::new();

    struct Probe(Arc<Mutex<Option<BearerContext<Pool>>>>);

    impl PacketEgress<<Pool as PacketPool>::Buffer> for Probe {
        fn submit(
            &mut self,
            _peer: PeerL2Address,
            submission: EgressSubmission<<Pool as PacketPool>::Buffer>,
        ) -> Result<(), PacketSubmitError<<Pool as PacketPool>::Buffer>> {
            submission.complete(PacketSendOutcome::Sent, 0);
            Ok(())
        }
    }

    impl PacketBearer<Pool> for Probe {
        type AttachError = core::convert::Infallible;

        fn info(&self) -> BearerInfo {
            BearerInfo {
                name: BearerName::new("uart0").unwrap(),
                max_packet_size: crate::DEFAULT_MAX_PACKET_SIZE,
                prefix_required: crate::PACKET_PREFIX_RESERVE,
                suffix_required: 0,
                requires_packet_encryption: false,
                secure_link: false,
                nominal_bitrate_bps: 115_200,
                local_mac: None,
            }
        }

        fn attach(&mut self, context: BearerContext<Pool>) -> Result<(), Self::AttachError> {
            *self.0.lock().unwrap() = Some(context);
            Ok(())
        }
    }

    #[test]
    fn immediate_driver_uses_registered_bearer_pool_without_ingress_queue() {
        let retained = Arc::new(Mutex::new(None));
        let node = QuicNode::<(), 2, 2, Pool>::new(
            Some(StatelessResetKey::from_device_secret(&[9; 32]).unwrap()),
            &POOL,
        );
        let mut driver = NoStdRuntime::new(node, ConnectionLimits::default());
        let bearer = driver.add_bearer(Probe(retained.clone())).unwrap();
        let context = retained.lock().unwrap().clone().unwrap();
        let mut writer =
            PacketPool::acquire_writer(context.pool(), crate::PACKET_PREFIX_RESERVE, 0).unwrap();
        writer.payload_mut()[0] = 0;
        let packet = crate::PacketWriter::commit(writer, 1).unwrap();
        context.enqueue_packet(
            PacketMeta {
                bearer,
                peer_l2_address: PeerL2Address::new(1).unwrap(),
                received_at_us: 1,
            },
            packet,
        );
        assert!(driver.progress().unwrap());
        assert!(driver.next_association().is_none());
        assert!(driver.next_stream_chunk().is_none());
    }

    #[test]
    fn immediate_driver_starts_client_association_without_exposing_role_state() {
        let retained = Arc::new(Mutex::new(None));
        let node = QuicNode::<(), 2, 2, Pool>::new(
            Some(StatelessResetKey::from_device_secret(&[7; 32]).unwrap()),
            &POOL,
        );
        let mut driver = NoStdRuntime::new(node, ConnectionLimits::default());
        let bearer = driver.add_bearer(Probe(retained)).unwrap();
        let address = PacketMeta {
            bearer,
            peer_l2_address: PeerL2Address::new(9).unwrap(),
            received_at_us: 10,
        };
        let association = driver.associate(address, 10).unwrap();

        assert!(!driver.association_is_established(association));
        assert!(driver.open_stream(association).is_err());
        assert!(driver.next_association().is_none());
    }

    #[test]
    fn boxed_runtime_initializes_in_final_storage() {
        let mut runtime = NoStdRuntime::<(), 12, 0, Pool>::try_new_boxed(
            Some(StatelessResetKey::from_device_secret(&[5; 32]).unwrap()),
            &POOL,
            ConnectionLimits::default(),
        )
        .unwrap();
        let retained = Arc::new(Mutex::new(None));
        assert!(runtime.add_bearer(Probe(retained.clone())).is_ok());
        assert!(retained.lock().unwrap().is_some());
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
>
    NoStdRuntime<
        NextHop,
        ASSOCIATIONS,
        ROUTES,
        P,
        CLIENT_HISTORY,
        SERVER_STREAMS,
        SERVER_HISTORY,
        PACKET,
    >
where
    NextHop: Copy,
    P: PacketPool + 'static,
    P::Buffer: Send,
{
    /// Bind fixed server admission limits to a node registered with its
    /// physical bearers.
    pub fn new(
        node: QuicNode<
            NextHop,
            ASSOCIATIONS,
            ROUTES,
            P,
            CLIENT_HISTORY,
            SERVER_STREAMS,
            SERVER_HISTORY,
            PACKET,
        >,
        limits: ConnectionLimits,
    ) -> Self {
        let ingress = Arc::new(IngressQueue::new(node.packet_capacity().max(1)));
        Self {
            node,
            limits,
            ingress,
            accepted: VecDeque::with_capacity(ASSOCIATIONS),
            streams: VecDeque::with_capacity(ASSOCIATIONS.saturating_mul(SERVER_STREAMS).max(1)),
        }
    }

    /// Allocate and initialize the complete no-std runtime in its final heap
    /// location.
    ///
    /// This is exported for RTOS integrations whose packet task stack cannot
    /// hold the fixed-capacity association table even temporarily. It exposes
    /// no transport internals: callers receive the same opaque runtime as
    /// [`Self::new`], with allocation failure reported before initialization.
    pub fn try_new_boxed(
        reset_key: Option<crate::StatelessResetKey>,
        pool: &'static P,
        limits: ConnectionLimits,
    ) -> Result<Box<Self>, ()> {
        let mut allocation = Vec::<core::mem::MaybeUninit<Self>>::new();
        allocation.try_reserve_exact(1).map_err(|_| ())?;
        allocation.push(core::mem::MaybeUninit::uninit());
        let mut allocation = allocation.into_boxed_slice();
        unsafe {
            let runtime = allocation[0].as_mut_ptr();
            let node_storage = &mut *core::ptr::addr_of_mut!((*runtime).node)
                .cast::<core::mem::MaybeUninit<
                    QuicNode<
                        NextHop,
                        ASSOCIATIONS,
                        ROUTES,
                        P,
                        CLIENT_HISTORY,
                        SERVER_STREAMS,
                        SERVER_HISTORY,
                        PACKET,
                    >,
                >>();
            let capacity = QuicNode::new_in_place(node_storage, reset_key, pool)
                .packet_capacity()
                .max(1);
            core::ptr::addr_of_mut!((*runtime).limits).write(limits);
            core::ptr::addr_of_mut!((*runtime).ingress)
                .write(Arc::new(IngressQueue::new(capacity)));
            core::ptr::addr_of_mut!((*runtime).accepted)
                .write(VecDeque::with_capacity(ASSOCIATIONS));
            core::ptr::addr_of_mut!((*runtime).streams).write(VecDeque::with_capacity(
                ASSOCIATIONS.saturating_mul(SERVER_STREAMS).max(1),
            ));
            let raw = Box::into_raw(allocation) as *mut core::mem::MaybeUninit<Self>;
            Ok(Box::from_raw(raw.cast::<Self>()))
        }
    }

    /// Add one physical packet bearer to this no-executor node.
    ///
    /// The bearer receives the node-owned pool and a fixed-capacity ingress
    /// queue. Interrupts or RTOS tasks enqueue complete packets through their
    /// retained [`crate::BearerContext`]; application code never injects
    /// packets into QUIC directly.
    pub fn add_bearer<T>(
        &mut self,
        bearer: T,
    ) -> Result<crate::BearerId, AddBearerError<T::AttachError>>
    where
        T: PacketBearer<P> + 'static,
    {
        self.node
            .register_bearer_with_ingress(bearer, self.ingress.clone())
    }

    /// Remove a physical bearer and forget association routes learned through it.
    ///
    /// The association and stream state remain owned by this runtime. They may
    /// continue through another address already learned on another bearer.
    pub fn remove_bearer(&mut self, bearer: crate::BearerId) -> bool {
        self.node.remove_bearer(bearer)
    }

    /// Start a client association through a registered bearer.
    ///
    /// The returned opaque handle names the client side of this association.
    /// Server associations admitted by [`Self::progress`] use the same
    /// handle type; `QuicNode` retains the role and applies the corresponding
    /// stream-number and packet rules internally.
    pub fn associate(
        &mut self,
        address: PacketMeta,
        now_us: u64,
    ) -> Result<QuicAssociation, QuicNodeEgressError> {
        self.node.associate(address, now_us)
    }

    /// Open a locally initiated bidirectional stream on an association.
    pub fn open_stream(
        &mut self,
        association: QuicAssociation,
    ) -> Result<crate::QuicStream, QuicNodeEgressError> {
        self.node.open_stream(association)
    }

    /// Submit the next ordered bytes on an outbound or related stream.
    ///
    /// Temporary pool, flow-control, congestion, or bearer pressure leaves
    /// the stream position unchanged so the caller can retry the same bytes.
    /// A pre-association direct message uses this same interface; QUIC-lite
    /// buffers accepted bytes until [`Self::finish_stream`] selects its
    /// long-packet response representation without exposing that distinction
    /// to a handler.
    pub fn write_stream(
        &mut self,
        stream: &mut crate::QuicStream,
        bytes: &[u8],
    ) -> Result<usize, QuicNodeEgressError> {
        self.node.write_stream(stream, bytes)
    }

    /// Close the stream's sending half after all accepted bytes.
    pub fn finish_stream(
        &mut self,
        stream: &mut crate::QuicStream,
    ) -> Result<(), QuicNodeEgressError> {
        self.node.finish_stream(stream)
    }

    /// Whether the association has completed client establishment or is an
    /// admitted server association. Role remains node-private.
    pub fn association_is_established(&self, association: QuicAssociation) -> bool {
        self.node.association_is_established(association)
    }

    /// Process at most one queued bearer event.
    ///
    /// An RTOS task calls this after its bearer wake notification. Returning
    /// `true` means one packet was consumed; returning `false` means no ingress
    /// packet was pending. The method does not wait or poll in a loop.
    pub fn progress(&mut self) -> Result<bool, QuicNodeEgressError> {
        self.node.drain_bearer_events();
        let Some(received) = self.ingress.pop() else {
            return Ok(false);
        };
        self.process_packet::<fn(crate::QuicStream, u64, bool, &[u8]) -> Result<usize, crate::Error>>(
            received.meta,
            received.packet,
            None,
        )?;
        Ok(true)
    }

    /// Process one bearer event while delivering associated stream bytes
    /// directly from the receive packet.
    ///
    /// Returning `n` accepts exactly the first `n` bytes. QUIC-lite retains an
    /// unread suffix under its ordered-delivery limit and does not grant
    /// receive credit for it. In-order chunks therefore require no per-chunk
    /// allocation. Connectionless direct messages continue through
    /// [`Self::next_stream_chunk`] because their reply handle is constructed
    /// only after packet classification completes.
    pub fn progress_with_stream<F>(&mut self, mut on_stream: F) -> Result<bool, QuicNodeEgressError>
    where
        F: FnMut(crate::QuicStream, u64, bool, &[u8]) -> Result<usize, crate::Error>,
    {
        self.node.drain_bearer_events();
        let Some(received) = self.ingress.pop() else {
            return Ok(false);
        };
        self.process_packet(received.meta, received.packet, Some(&mut on_stream))?;
        Ok(true)
    }

    /// Advance transport timers and retain any terminal association event.
    pub fn advance_time(&mut self, now_us: u64) -> Result<bool, QuicNodeEgressError> {
        self.node.advance_clock(now_us);
        match self
            .node
            .timer_expired(now_us, crate::node::DEFAULT_INITIAL_PTO_US)?
        {
            Some(crate::node::NodeTimer::Egress(packet)) => {
                self.node.submit_node_packet(packet)?;
                Ok(true)
            }
            Some(crate::node::NodeTimer::BootstrapTimedOut { .. }) => {
                Err(QuicNodeEgressError::AssociationTimedOut)
            }
            Some(crate::node::NodeTimer::IdleTimedOut { association }) => {
                let _ = association;
                Ok(true)
            }
            None => Ok(false),
        }
    }

    fn process_packet<F>(
        &mut self,
        meta: PacketMeta,
        packet: OwnedPacket<P::Buffer>,
        mut on_stream: Option<&mut F>,
    ) -> Result<(), QuicNodeEgressError>
    where
        F: FnMut(crate::QuicStream, u64, bool, &[u8]) -> Result<usize, crate::Error>,
    {
        self.node.drain_bearer_events();
        let first_cid = self.node.allocate_local_cid()?;
        let second_cid = self.node.allocate_local_cid()?;
        let limits = self.limits;
        let streams = &mut self.streams;
        let ingress = self
            .node
            .receive_packet(
                meta,
                packet,
                |open| {
                    Some(InitialAdmission {
                        server_cid: if first_cid == open.client_receive_cid {
                            second_cid
                        } else {
                            first_cid
                        },
                        local_limits: limits,
                    })
                },
                |source, stream, offset, fin, bytes| {
                    if let ApplicationStreamSource::Association(association) = source {
                        if let Some(handler) = on_stream.as_deref_mut() {
                            return handler(
                                crate::QuicStream::incoming(association, stream),
                                offset,
                                fin,
                                bytes,
                            );
                        }
                        if streams.len() == streams.capacity() {
                            return Err(crate::Error::BufferTooSmall);
                        }
                        streams.push_back(ReceivedStreamChunk {
                            stream: crate::QuicStream::incoming(association, stream),
                            offset,
                            fin,
                            bytes: bytes.to_vec(),
                        });
                    }
                    Ok(bytes.len())
                },
            )
            .map_err(|rejected| match rejected.reason {
                QuicNodePacketRejection::Egress(error) => error,
                QuicNodePacketRejection::Packet(error)
                | QuicNodePacketRejection::Application(error) => {
                    QuicNodeEgressError::Transport(error)
                }
                QuicNodePacketRejection::PeerClosed(_) => {
                    QuicNodeEgressError::Transport(crate::Error::PeerRestarted)
                }
            })?;

        match ingress {
            NodeIngress::Initial {
                association,
                response,
            } => {
                if self.accepted.len() < self.accepted.capacity() {
                    self.accepted.push_back(association);
                }
                self.node.submit_egress(
                    response.bearer,
                    response.peer_l2_address,
                    response.packet,
                )?;
            }
            NodeIngress::Association { association, .. } => {
                if let Some(packet) = self
                    .node
                    .poll_association_control(association.association())?
                {
                    self.node.submit_egress(
                        packet.bearer,
                        packet.peer_l2_address,
                        packet.packet,
                    )?;
                }
            }
            NodeIngress::StatelessReset { response } => self.node.submit_egress(
                response.bearer,
                response.peer_l2_address,
                response.packet,
            )?,
            NodeIngress::Direct(request) => {
                if self.streams.len() == self.streams.capacity() {
                    return Err(QuicNodeEgressError::StreamEventsFull);
                }
                self.streams.push_back(ReceivedStreamChunk {
                    stream: crate::QuicStream::direct(
                        request.reply(),
                        crate::callback::DIRECT_MESSAGE_STREAM_ID,
                    ),
                    offset: 0,
                    fin: true,
                    bytes: request.payload().to_vec(),
                });
            }
            NodeIngress::PeerReset { .. } | NodeIngress::PeerClosed { .. } => {}
            NodeIngress::Forward { .. } => {
                return Err(QuicNodeEgressError::RelayUnavailable);
            }
            NodeIngress::InitialDeclined { .. }
            | NodeIngress::Unknown { .. }
            | NodeIngress::NonQuic { .. } => {}
        }
        Ok(())
    }

    /// Take the next newly accepted association.
    pub fn next_association(&mut self) -> Option<QuicAssociation> {
        self.accepted.pop_front()
    }

    /// Take the next ordered application stream chunk.
    pub fn next_stream_chunk(&mut self) -> Option<ReceivedStreamChunk> {
        self.streams.pop_front()
    }

    /// Take the next terminal association lifecycle event.
    pub fn next_event(&mut self) -> Option<crate::AssociationEvent> {
        self.node.next_association_event()
    }
}
