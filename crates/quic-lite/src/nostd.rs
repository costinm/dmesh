//! Immediate node driving for platforms without an async executor.
//!
//! Bearer registration, packet storage, readiness, completion, and physical
//! submission are common [`crate::QuicNode`] behavior. This module only turns
//! one synchronously received bearer packet into node progress and retains the
//! resulting application association/stream events.

use alloc::{boxed::Box, collections::VecDeque, sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicUsize, Ordering};
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
    enqueue_drops: AtomicUsize,
}

impl<B> IngressQueue<B> {
    fn new(capacity: usize) -> Self {
        Self {
            packets: Mutex::new(VecDeque::with_capacity(capacity)),
            capacity,
            enqueue_drops: AtomicUsize::new(0),
        }
    }

    fn pop(&self) -> Option<crate::bearer::ReceivedPacket<B>> {
        self.packets.lock().pop_front()
    }

    fn take_enqueue_drops(&self) -> usize {
        self.enqueue_drops.swap(0, Ordering::AcqRel)
    }
}

impl<B: AsRef<[u8]> + Send> crate::bearer::PacketIngressQueue<B> for IngressQueue<B> {
    fn enqueue_packet(&self, meta: PacketMeta, packet: OwnedPacket<B>) {
        // A physical receive callback can preempt the node owner while it
        // briefly holds this queue lock. Spinning in that callback would
        // deadlock a single-core target, so contention is treated like a
        // dropped UDP/UART datagram and left to QUIC retransmission.
        let Some(mut packets) = self.packets.try_lock() else {
            self.enqueue_drops.fetch_add(1, Ordering::Relaxed);
            drop(packet);
            return;
        };
        if packets.len() == self.capacity {
            self.enqueue_drops.fetch_add(1, Ordering::Relaxed);
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
    P: PacketPool + 'static,
    const PACKET: usize = { crate::DEFAULT_MAX_PACKET_SIZE },
> {
    node: QuicNode<P, PACKET>,
    limits: ConnectionLimits,
    ingress: Arc<IngressQueue<P::Buffer>>,
    accepted: VecDeque<QuicAssociation>,
    streams: VecDeque<ReceivedStreamChunk>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bearer::PacketIngressQueue;
    use crate::packet_pool::PacketPool as FixedPool;
    use crate::{
        BearerContext, BearerInfo, BearerName, EgressSubmission, PacketBearer, PacketEgress,
        PacketSendOutcome, PacketSubmitError, PeerL2Address, StatelessResetKey,
    };
    use core::sync::atomic::{AtomicBool, Ordering};
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

    struct ToggleBlocker {
        context: Arc<Mutex<Option<BearerContext<Pool>>>>,
        blocked: Arc<AtomicBool>,
    }

    impl PacketEgress<<Pool as PacketPool>::Buffer> for ToggleBlocker {
        fn submit(
            &mut self,
            _peer: PeerL2Address,
            submission: EgressSubmission<<Pool as PacketPool>::Buffer>,
        ) -> Result<(), PacketSubmitError<<Pool as PacketPool>::Buffer>> {
            if self.blocked.load(Ordering::Acquire) {
                return Err(PacketSubmitError::WouldBlock(submission));
            }
            submission.complete(PacketSendOutcome::Sent, 0);
            Ok(())
        }
    }

    impl PacketBearer<Pool> for ToggleBlocker {
        type AttachError = core::convert::Infallible;

        fn info(&self) -> BearerInfo {
            BearerInfo {
                name: BearerName::new("blocked").unwrap(),
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
            *self.context.lock().unwrap() = Some(context);
            Ok(())
        }
    }

    #[test]
    fn immediate_driver_uses_registered_bearer_pool_without_ingress_queue() {
        let retained = Arc::new(Mutex::new(None));
        let node = QuicNode::<Pool>::new(
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
    fn ingress_callback_drops_on_lock_contention_instead_of_spinning() {
        let queue = IngressQueue::new(1);
        let mut writer =
            PacketPool::acquire_writer(&POOL, crate::PACKET_PREFIX_RESERVE, 0).unwrap();
        writer.payload_mut()[0] = 0;
        let packet = crate::PacketWriter::commit(writer, 1).unwrap();
        let guard = queue.packets.lock();

        crate::bearer::PacketIngressQueue::enqueue_packet(
            &queue,
            PacketMeta {
                bearer: crate::BearerId::new(1).unwrap(),
                peer_l2_address: PeerL2Address::new(1).unwrap(),
                received_at_us: 1,
            },
            packet,
        );

        assert_eq!(queue.take_enqueue_drops(), 1);
        drop(guard);
        assert!(queue.pop().is_none());
    }

    #[test]
    fn blocked_egress_pauses_ingress_until_bearer_readiness() {
        let context = Arc::new(Mutex::new(None));
        let blocked = Arc::new(AtomicBool::new(true));
        let node = QuicNode::<Pool>::new(None, &POOL);
        let mut driver = NoStdRuntime::new(node, ConnectionLimits::default());
        let bearer = driver
            .add_bearer(ToggleBlocker {
                context: context.clone(),
                blocked: blocked.clone(),
            })
            .unwrap();
        let peer = PeerL2Address::new(1).unwrap();

        let mut writer =
            PacketPool::acquire_writer(&POOL, crate::PACKET_PREFIX_RESERVE, 0).unwrap();
        writer.payload_mut()[0] = 1;
        let packet = crate::PacketWriter::commit(writer, 1).unwrap();
        driver
            .node
            .submit_egress(bearer, peer, packet)
            .expect("first blocked send is retained by the bearer registry");

        let mut writer =
            PacketPool::acquire_writer(&POOL, crate::PACKET_PREFIX_RESERVE, 0).unwrap();
        writer.payload_mut()[0] = 0;
        let packet = crate::PacketWriter::commit(writer, 1).unwrap();
        driver.ingress.enqueue_packet(
            PacketMeta {
                bearer,
                peer_l2_address: peer,
                received_at_us: 1,
            },
            packet,
        );

        assert!(!driver.progress().unwrap());
        assert_eq!(driver.ingress.packets.lock().len(), 1);

        blocked.store(false, Ordering::Release);
        context.lock().unwrap().as_ref().unwrap().send_ready();
        // Retry is accepted and completes synchronously; consume that queued
        // completion before allowing the retained ingress packet to proceed.
        assert!(
            !driver
                .progress_with_stream(|_, _, _, bytes| Ok(bytes.len()))
                .unwrap()
        );
        assert!(
            driver
                .progress_with_stream(|_, _, _, bytes| Ok(bytes.len()))
                .unwrap()
        );
        assert!(driver.ingress.packets.lock().is_empty());
    }

    #[test]
    fn immediate_driver_starts_client_association_without_exposing_role_state() {
        let retained = Arc::new(Mutex::new(None));
        let node = QuicNode::<Pool>::new(
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
        let mut runtime = NoStdRuntime::<Pool>::try_new_boxed(
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

impl<P, const PACKET: usize> NoStdRuntime<P, PACKET>
where
    P: PacketPool + 'static,
    P::Buffer: Send,
{
    /// Return and clear the number of ingress packets dropped because the
    /// bounded queue was full or briefly locked by the node owner.
    pub fn take_ingress_drops(&self) -> usize {
        self.ingress.take_enqueue_drops()
    }

    /// Current node-wide admission limits.
    pub fn limits(&self) -> crate::NodeLimits {
        self.node.limits()
    }

    /// Current defaults inherited by associations admitted after this call.
    pub fn default_association_limits(&self) -> crate::AssociationLimits {
        self.node.default_association_limits()
    }

    /// Replace node-wide runtime admission limits.
    pub fn set_limits(&mut self, limits: crate::NodeLimits) -> Result<(), crate::QuicNodeError> {
        self.node.set_limits(limits)
    }

    /// Select limits for associations admitted after this call.
    pub fn set_default_association_limits(
        &mut self,
        limits: crate::AssociationLimits,
    ) -> Result<(), crate::QuicNodeError> {
        self.limits = limits.connection;
        self.node.set_default_association_limits(limits)
    }

    /// Change one live association's growth policy.
    pub fn set_association_limits(
        &mut self,
        association: crate::QuicAssociation,
        limits: crate::AssociationLimits,
    ) -> Result<(), crate::QuicNodeEgressError> {
        self.node.set_association_limits(association, limits)
    }

    /// Bind fixed server admission limits to a node registered with its
    /// physical bearers.
    pub fn new(node: QuicNode<P, PACKET>, limits: ConnectionLimits) -> Self {
        let ingress = Arc::new(IngressQueue::new(node.packet_capacity().max(1)));
        Self {
            node,
            limits,
            ingress,
            accepted: VecDeque::new(),
            streams: VecDeque::new(),
        }
    }

    /// Allocate and initialize the complete no-std runtime in its final heap
    /// location.
    ///
    /// This is exported for RTOS integrations whose packet task stack cannot
    /// hold the complete node state even temporarily. It exposes
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
                .cast::<core::mem::MaybeUninit<QuicNode<P, PACKET>>>();
            let capacity = QuicNode::new_in_place(node_storage, reset_key, pool)
                .packet_capacity()
                .max(1);
            core::ptr::addr_of_mut!((*runtime).limits).write(limits);
            core::ptr::addr_of_mut!((*runtime).ingress)
                .write(Arc::new(IngressQueue::new(capacity)));
            core::ptr::addr_of_mut!((*runtime).accepted).write(VecDeque::new());
            core::ptr::addr_of_mut!((*runtime).streams).write(VecDeque::new());
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
    pub fn write_stream(
        &mut self,
        stream: &mut crate::QuicStream,
        bytes: &[u8],
    ) -> Result<usize, QuicNodeEgressError> {
        self.node.write_stream(stream, bytes)
    }

    /// Write the final application bytes, carrying FIN on the packet that
    /// accepts the complete remaining slice.
    pub fn write_stream_and_finish(
        &mut self,
        stream: &mut crate::QuicStream,
        bytes: &[u8],
    ) -> Result<usize, QuicNodeEgressError> {
        self.node.write_stream_and_finish(stream, bytes)
    }

    /// Close the stream's sending half after all accepted bytes.
    pub fn finish_stream(
        &mut self,
        stream: &mut crate::QuicStream,
    ) -> Result<(), QuicNodeEgressError> {
        self.node.finish_stream(stream)
    }

    /// Peer-advertised byte credit at the stream's current ordered position.
    pub fn stream_send_window(
        &self,
        stream: &crate::QuicStream,
    ) -> Result<u64, QuicNodeEgressError> {
        self.node.stream_send_window(stream)
    }

    /// Whether the association has completed client establishment or is an
    /// admitted server association. Role remains node-private.
    pub fn association_is_established(&self, association: QuicAssociation) -> bool {
        self.node.association_is_established(association)
    }

    /// Process at most one queued bearer event.
    ///
    /// An RTOS task calls this after its bearer wake notification. Returning
    /// `true` means one packet was consumed; returning `false` means ingress
    /// was empty or is paused until a retained egress packet can be retried.
    /// The method does not wait or poll in a loop.
    pub fn progress(&mut self) -> Result<bool, QuicNodeEgressError> {
        self.node.drain_bearer_events();
        if !self.node.can_progress_ingress() {
            return Ok(false);
        }
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

    /// Drain all packets currently queued by bearer callbacks.
    ///
    /// Callback wakeups may coalesce when several datagrams arrive before the
    /// owner task runs. Owners that receive one wake per burst should use this
    /// method (or repeat [`Self::progress`]) so every queued packet is handled
    /// before sleeping again.
    pub fn progress_all(&mut self) -> Result<usize, QuicNodeEgressError> {
        let mut processed = 0usize;
        while self.progress()? {
            processed = processed.saturating_add(1);
        }
        Ok(processed)
    }

    /// Process one bearer event while delivering associated stream bytes
    /// directly from the receive packet.
    ///
    /// Returning `n` accepts exactly the first `n` bytes. QUIC-lite retains an
    /// unread suffix under its ordered-delivery limit and does not grant
    /// receive credit for it. A zero-length chunk (a bare FIN) cannot be
    /// refused: returning 0 for it accepts the end of the stream. In-order
    /// chunks therefore require no per-chunk
    pub fn progress_with_stream<F>(&mut self, mut on_stream: F) -> Result<bool, QuicNodeEgressError>
    where
        F: FnMut(crate::QuicStream, u64, bool, &[u8]) -> Result<usize, crate::Error>,
    {
        self.node.drain_bearer_events();
        // Processing another packet can itself generate an ACK or flow-control
        // packet. Leave ingress queued until any previously blocked egress is
        // retried, rather than submitting past the bearer-owned retained slot.
        if !self.node.can_progress_ingress() {
            return Ok(false);
        }
        let Some(received) = self.ingress.pop() else {
            return Ok(false);
        };
        self.process_packet(received.meta, received.packet, Some(&mut on_stream))?;
        Ok(true)
    }

    /// Drain every currently queued packet while delivering stream bytes to
    /// one application callback. This is the burst-safe form of
    /// [`Self::progress_with_stream`] for event-coalescing bearers.
    pub fn progress_all_with_stream<F>(
        &mut self,
        mut on_stream: F,
    ) -> Result<usize, QuicNodeEgressError>
    where
        F: FnMut(crate::QuicStream, u64, bool, &[u8]) -> Result<usize, crate::Error>,
    {
        let mut processed = 0usize;
        while self.progress_with_stream(&mut on_stream)? {
            processed = processed.saturating_add(1);
        }
        Ok(processed)
    }

    /// Advance transport timers and retain any terminal association event.
    pub fn advance_time(&mut self, now_us: u64) -> Result<bool, QuicNodeEgressError> {
        self.node.advance_clock(now_us);
        match self.node.timer_expired(now_us)? {
            Some(crate::node::NodeTimer::Egress(packet)) => {
                self.node.submit_node_packet(packet)?;
                Ok(true)
            }
            Some(crate::node::NodeTimer::BootstrapTimedOut { .. }) => Ok(true),
            Some(crate::node::NodeTimer::IdleTimedOut { .. }) => Ok(true),
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
        let limits = self.limits;
        let node_limits = self.node.limits();
        let stream_queue_limit = node_limits
            .max_associations
            .saturating_mul(self.node.default_association_limits().max_pending_streams)
            .max(1);
        let streams = &mut self.streams;
        let ingress = self
            .node
            .receive_packet(
                meta,
                packet,
                |_| {
                    Some(InitialAdmission {
                        local_limits: limits,
                    })
                },
                |source, stream, offset, fin, bytes| {
                    let ApplicationStreamSource::Association(association) = source;
                    if let Some(handler) = on_stream.as_deref_mut() {
                        return handler(
                            crate::QuicStream::incoming(association, stream),
                            offset,
                            fin,
                            bytes,
                        );
                    }
                    // A zero-length FIN cannot be refused (it has no bytes
                    // to retain), so it is queued even at capacity.
                    if !bytes.is_empty()
                        && (streams.len() >= stream_queue_limit || streams.try_reserve(1).is_err())
                    {
                        return Ok(0);
                    }
                    streams.push_back(ReceivedStreamChunk {
                        stream: crate::QuicStream::incoming(association, stream),
                        offset,
                        fin,
                        bytes: bytes.to_vec(),
                    });
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
                if self.accepted.len() < node_limits.max_associations
                    && self.accepted.try_reserve(1).is_ok()
                {
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
        let chunk = self.streams.pop_front()?;
        if let Some(association) = chunk.stream.association() {
            let stream_queue_limit = self
                .node
                .limits()
                .max_associations
                .saturating_mul(self.node.default_association_limits().max_pending_streams)
                .max(1);
            let streams = &mut self.streams;
            let resumed = self.node.resume_stream_delivery(
                association,
                chunk.stream.id(),
                &mut |source, stream, offset, fin, bytes| {
                    let ApplicationStreamSource::Association(association) = source;
                    // A zero-length FIN cannot be refused (it has no bytes to
                    // retain), so it is queued even at capacity.
                    if !bytes.is_empty()
                        && (streams.len() >= stream_queue_limit || streams.try_reserve(1).is_err())
                    {
                        return Ok(0);
                    }
                    streams.push_back(ReceivedStreamChunk {
                        stream: crate::QuicStream::incoming(association, stream),
                        offset,
                        fin,
                        bytes: bytes.to_vec(),
                    });
                    Ok(bytes.len())
                },
            );
            debug_assert!(
                resumed.is_ok(),
                "retained stream resume failed: {resumed:?}"
            );
            if resumed.is_ok_and(|bytes| bytes != 0) {
                if let Ok(Some(packet)) = self.node.poll_association_control(association) {
                    let _ = self.node.submit_egress(
                        packet.bearer,
                        packet.peer_l2_address,
                        packet.packet,
                    );
                }
            }
        }
        Some(chunk)
    }

    /// Take the next terminal association lifecycle event.
    pub fn next_event(&mut self) -> Option<crate::AssociationEvent> {
        self.node.next_association_event()
    }
}
