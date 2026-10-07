use super::*;
use crate::bearer::{OwnedPacket, PacketBuffer};
use crate::{DatagramPriority, DatagramSendError, ReceivedDatagram};

pub(super) struct DatagramCommand<B> {
    association: QuicAssociation,
    packet: Option<OwnedPacket<B>>,
    pub(super) priority: DatagramPriority,
    reply: Option<oneshot::Sender<Result<(), DatagramSendError<B>>>>,
    _permit: ::tokio::sync::OwnedSemaphorePermit,
}
impl<B> Drop for DatagramCommand<B> {
    fn drop(&mut self) {
        if let (Some(packet), Some(reply)) = (self.packet.take(), self.reply.take()) {
            let _ = reply.send(Err(DatagramSendError {
                reason: QuicNodeEgressError::Transport(crate::Error::Invalid),
                packet,
            }));
        }
    }
}

/// Completion of driver admission, not peer/application delivery. Dropping
/// this future cancels interest in its outcome, not an already-owned packet.
pub struct DatagramSubmission<B> {
    receive: oneshot::Receiver<Result<(), DatagramSendError<B>>>,
}
impl<B> Future for DatagramSubmission<B> {
    type Output = Result<(), DatagramSendError<B>>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match Pin::new(&mut self.receive).poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => {
                Poll::Ready(result.expect("datagram command always returns ownership or admission"))
            }
        }
    }
}

pub(super) type RegisterHandler<P, const PACKET: usize> =
    Box<dyn FnOnce(&mut QuicNode<P, PACKET>) -> Result<(), QuicNodeEgressError> + Send>;

impl TokioNode {
    /// Nonblocking command admission for an existing payload lease. Reserves
    /// driver capacity before transferring ownership, including when invoked
    /// by a proxy bearer callback. Never await the result inside that owner.
    /// Full/stopped drivers return the exact unchanged packet immediately.
    pub fn try_send_datagram<B: PacketBuffer + Send + 'static>(
        &self,
        association: QuicAssociation,
        packet: OwnedPacket<B>,
        priority: DatagramPriority,
    ) -> Result<DatagramSubmission<B>, DatagramSendError<B>> {
        if self.commands.is_closed() {
            return Err(DatagramSendError {
                reason: QuicNodeEgressError::Transport(crate::Error::Invalid),
                packet,
            });
        }
        let permit = match self.datagram_slots.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                return Err(DatagramSendError {
                    reason: QuicNodeEgressError::Transport(crate::Error::Blocked),
                    packet,
                });
            }
        };
        let (reply, receive) = oneshot::channel();
        let request = DatagramCommand {
            association,
            packet: Some(packet),
            priority,
            reply: Some(reply),
            _permit: permit,
        };
        if let Err(error) = self
            .commands
            .send(DriverCommand::Datagram(Box::new(request)))
        {
            // Dropping the failed command's guard returns the unchanged lease
            // through the same completion channel, without allocating a copy.
            drop(error);
        }
        Ok(DatagramSubmission { receive })
    }

    /// Async convenience over `try_send_datagram`; no application retry loop.
    pub async fn send_datagram<B: PacketBuffer + Send + 'static>(
        &self,
        association: QuicAssociation,
        packet: OwnedPacket<B>,
        priority: DatagramPriority,
    ) -> Result<(), DatagramSendError<B>> {
        self.try_send_datagram(association, packet, priority)?.await
    }

    /// Register the pool-typed receive callback on the serialized owner.
    /// `P`/`PACKET` must match the driver, as with `add_bearer`.
    pub async fn set_datagram_handler<P, const PACKET: usize>(
        &self,
        association: QuicAssociation,
        callback: impl FnMut(ReceivedDatagram<P::Buffer>) + Send + 'static,
    ) -> Result<(), QuicNodeEgressError>
    where
        P: PacketPool + 'static,
        P::Buffer: Send,
    {
        let register: RegisterHandler<P, PACKET> = Box::new(move |node| {
            node.set_datagram_handler(association, callback)
                .map_err(Into::into)
        });
        let (reply, receive) = oneshot::channel();
        self.commands
            .send(DriverCommand::DatagramHandler {
                register: Box::new(register),
                reply,
            })
            .map_err(|_| QuicNodeEgressError::Transport(crate::Error::Invalid))?;
        receive
            .await
            .map_err(|_| QuicNodeEgressError::Transport(crate::Error::Invalid))?
    }
}

impl TokioAssociation {
    /// Nonblocking, ownership-preserving DATAGRAM admission on this association.
    pub fn try_send_datagram<B: PacketBuffer + Send + 'static>(
        &self,
        packet: OwnedPacket<B>,
        priority: DatagramPriority,
    ) -> Result<DatagramSubmission<B>, DatagramSendError<B>> {
        self.node
            .try_send_datagram(self.association, packet, priority)
    }

    /// Send an opaque pool-backed DATAGRAM through the shared driver.
    pub async fn send_datagram<B: PacketBuffer + Send + 'static>(
        &self,
        packet: OwnedPacket<B>,
        priority: DatagramPriority,
    ) -> Result<(), DatagramSendError<B>> {
        self.node
            .send_datagram(self.association, packet, priority)
            .await
    }

    /// Install the association's pool-typed, serialized receive callback.
    pub async fn set_datagram_handler<P, const PACKET: usize>(
        &self,
        callback: impl FnMut(ReceivedDatagram<P::Buffer>) + Send + 'static,
    ) -> Result<(), QuicNodeEgressError>
    where
        P: PacketPool + 'static,
        P::Buffer: Send,
    {
        self.node
            .set_datagram_handler::<P, PACKET>(self.association, callback)
            .await
    }
}

impl<P: PacketPool + 'static, const PACKET: usize> TokioNodeDriver<P, PACKET>
where
    P::Buffer: Send,
{
    pub(super) fn dispatch_datagrams(&mut self, high: bool) {
        let normal_waiting = !self.pending_writes.is_empty() || !self.pending_opens.is_empty();
        let pending = if high {
            &mut self.high_datagrams
        } else {
            &mut self.low_datagrams
        };
        while let Some(mut request) = pending.pop_front() {
            if request.reply.as_ref().is_none_or(|reply| reply.is_closed()) {
                continue;
            }
            let packet = request
                .packet
                .take()
                .expect("pending datagram owns payload");
            let result = if !high && normal_waiting {
                Err(DatagramSendError {
                    reason: QuicNodeEgressError::Transport(crate::Error::Blocked),
                    packet,
                })
            } else {
                self.node
                    .send_datagram(request.association, packet, request.priority)
            };
            if let Some(reply) = request.reply.take() {
                let _ = reply.send(result);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BearerName, ConnectionId, PacketMeta, PeerL2Address};
    use alloc::vec;
    type Pool = crate::packet_pool::PacketPool<4, { crate::DEFAULT_PACKET_POOL_SLOT_SIZE }>;
    type Buffer = <Pool as PacketPool>::Buffer;
    type Node = QuicNode<Pool>;
    fn packet(pool: &'static Pool, bytes: &[u8]) -> OwnedPacket<Buffer> {
        let mut writer = PacketPool::acquire_writer(pool, 80, 0).unwrap();
        crate::PacketWriter::payload_mut(&mut writer)[..bytes.len()].copy_from_slice(bytes);
        crate::PacketWriter::commit(writer, bytes.len()).unwrap()
    }
    fn fixture() -> (
        TokioNode,
        TokioNodeDriver<Pool>,
        QuicAssociation,
        &'static Pool,
        Arc<Mutex<Vec<Vec<u8>>>>,
    ) {
        let pool: &'static Pool = Box::leak(Box::new(Pool::new()));
        let peer_pool: &'static Pool = Box::leak(Box::new(Pool::new()));
        let mut node = Node::new(pool);
        let mut peer = Node::new(peer_pool);
        let limits = crate::ConnectionLimits {
            max_datagram_frame_size: 65535,
            ..crate::ConnectionLimits::default()
        };
        node.set_default_association_limits(crate::AssociationLimits {
            connection: limits,
            ..crate::AssociationLimits::host()
        })
        .unwrap();
        let bearer =
            crate::fake::FakePacketBearer::<Pool>::new(BearerName::new("dg-admission").unwrap());
        let sent = bearer.sent_packets();
        let bearer = node.add_bearer(bearer).unwrap();
        let meta = PacketMeta {
            bearer,
            peer_l2_address: PeerL2Address::new(1).unwrap(),
            received_at_us: 1,
        };
        let initial = node
            .start_association(ConnectionId::new(111).unwrap(), meta, 0)
            .unwrap();
        let association = initial.association;
        let crate::node::NodeIngress::Initial { response, .. } = peer
            .receive_owned_packet(
                meta,
                initial.packet,
                |_| {
                    Some(crate::node::InitialAdmission {
                        local_limits: limits,
                    })
                },
                |_, _, _, _, bytes| Ok(bytes.len()),
            )
            .unwrap()
        else {
            panic!("initial");
        };
        node.receive_owned_packet(
            meta,
            response.packet,
            |_| None,
            |_, _, _, _, bytes| Ok(bytes.len()),
        )
        .unwrap();
        let (handle, driver) = TokioNodeDriver::new(node, limits);
        (handle, driver, association, pool, sent)
    }

    #[::tokio::test]
    async fn full_command_budget_and_queued_shutdown_return_same_packet() {
        let (handle, driver, association, pool, _) = fixture();
        let mut reservations = Vec::new();
        for _ in 0..pool.capacity() {
            reservations.push(handle.datagram_slots.clone().try_acquire_owned().unwrap());
        }
        let input = packet(pool, b"same");
        let pointer = input.bytes().as_ptr();
        let Err(error) = handle.try_send_datagram(association, input, DatagramPriority::High)
        else {
            panic!("full budget");
        };
        assert_eq!(error.packet.bytes().as_ptr(), pointer);
        assert_eq!(error.packet.bytes(), b"same");
        drop(reservations);
        let request = handle
            .try_send_datagram(association, error.packet, DatagramPriority::High)
            .ok()
            .unwrap();
        drop(driver);
        let error = request.await.unwrap_err();
        assert_eq!(error.packet.bytes().as_ptr(), pointer);
        assert_eq!(error.packet.bytes(), b"same");
        drop(error);
        assert_eq!(pool.available(), pool.capacity());
    }

    #[::tokio::test]
    async fn cancellation_releases_once_and_priority_selects_high_before_low() {
        let (handle, mut driver, association, pool, sent) = fixture();
        let cancelled = handle
            .try_send_datagram(association, packet(pool, b"cancel"), DatagramPriority::High)
            .ok()
            .unwrap();
        let command = driver.commands.try_recv().unwrap();
        driver.handle_command(command).unwrap();
        drop(cancelled);
        driver.dispatch_datagrams(true);
        assert_eq!(pool.available(), pool.capacity());
        assert!(sent.lock().unwrap().is_empty());
        let low = handle
            .try_send_datagram(association, packet(pool, b"low"), DatagramPriority::Low)
            .ok()
            .unwrap();
        let high = handle
            .try_send_datagram(association, packet(pool, b"high"), DatagramPriority::High)
            .ok()
            .unwrap();
        for _ in 0..2 {
            let command = driver.commands.try_recv().unwrap();
            driver.handle_command(command).unwrap();
        }
        driver.dispatch_datagrams(true);
        driver.dispatch_datagrams(false);
        high.await.unwrap();
        low.await.unwrap();
        let packets = sent.lock().unwrap();
        assert_eq!(packets.len(), 2);
        let payload = |bytes: &[u8]| {
            crate::datagram::payloads(
                bytes,
                crate::ShortHeader::decode_prefix(bytes).unwrap().header_len,
            )
            .next()
            .unwrap()
            .to_vec()
        };
        assert_eq!(payload(&packets[0]), b"high");
        assert_eq!(payload(&packets[1]), b"low");
        driver.node.drain_bearer_events();
        assert_eq!(pool.available(), pool.capacity());
    }

    #[::tokio::test]
    async fn wrong_buffer_type_returns_unchanged_owned_payload() {
        let (handle, mut driver, association, _, _) = fixture();
        let input = OwnedPacket::new(vec![0x5a; 128], 80..84).ok().unwrap();
        let pointer = input.bytes().as_ptr();
        let request = handle
            .try_send_datagram(association, input, DatagramPriority::High)
            .ok()
            .unwrap();
        let command = driver.commands.try_recv().unwrap();
        driver.handle_command(command).unwrap();
        let error = request.await.unwrap_err();
        assert_eq!(error.packet.bytes(), [0x5a; 4]);
        assert_eq!(error.packet.bytes().as_ptr(), pointer);
    }
}
