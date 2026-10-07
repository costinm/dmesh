use super::*;
use crate::bearer::PacketBuffer;
use crate::{DatagramPriority, DatagramSendError, ReceivedDatagram};
use alloc::boxed::Box;

pub(super) type DatagramHandler<B> = Box<dyn FnMut(ReceivedDatagram<B>) + Send + 'static>;

impl<P: PacketPool + 'static, const PACKET: usize> QuicNode<P, PACKET>
where
    P::Buffer: Send,
{
    /// Install/replace one opaque, leased receive callback for an association.
    /// Invoked by the serialized node owner; never await that owner inside it.
    /// An absent callback drops DATAGRAMs after normal transport processing.
    pub fn set_datagram_handler(
        &mut self,
        association: QuicAssociation,
        handler: impl FnMut(ReceivedDatagram<P::Buffer>) + Send + 'static,
    ) -> Result<(), QuicNodeError> {
        if self.slot(association).is_none() {
            return Err(QuicNodeError::MissingAssociation);
        }
        if let Some((_, existing)) = self
            .datagram_handlers
            .iter_mut()
            .find(|(id, _)| *id == association)
        {
            *existing = Box::new(handler);
        } else {
            self.datagram_handlers
                .push((association, Box::new(handler)));
        }
        Ok(())
    }

    /// Submit one opaque payload lease. Admission consumes ownership, not a
    /// delivery guarantee. Every refusal returns the exact unchanged payload.
    /// Uses normal bearer completion; a late WouldBlock retains the exact
    /// prepared lease, never another copy or a companion-owned packet queue.
    pub fn send_datagram(
        &mut self,
        association: QuicAssociation,
        packet: OwnedPacket<P::Buffer>,
        priority: DatagramPriority,
    ) -> Result<(), DatagramSendError<P::Buffer>> {
        self.drain_bearer_events();
        let output = self.prepare_datagram(association, packet, priority)?;
        let number = self.packet_acceptance_for(association, &output.packet);
        if self.submit_node_packet(output).is_err() {
            if let Some(number) = number {
                self.record_packet_send_failure(number);
            }
        }
        Ok(())
    }

    pub(crate) fn prepare_datagram(
        &mut self,
        association: QuicAssociation,
        mut packet: OwnedPacket<P::Buffer>,
        priority: DatagramPriority,
    ) -> Result<NodeEgress<P::Buffer>, DatagramSendError<P::Buffer>> {
        let prepare = (|| {
            if priority == DatagramPriority::Low
                && self.pool.available() <= self.node_limits.relay_control_packet_reserve
            {
                return Err(QuicNodeEgressError::Transport(Error::Blocked));
            }
            let slot = self
                .slot(association)
                .ok_or(QuicNodeError::MissingAssociation)?;
            if slot.close_code.is_some() {
                return Err(QuicNodeEgressError::Transport(Error::Invalid));
            }
            let count = Self::slot_path_count(slot);
            let mut last = QuicNodeEgressError::Transport(Error::Blocked);
            for path_id in 0..count {
                let slot = self.slot(association).unwrap();
                let Some(path) =
                    Self::slot_path_state(slot, path_id).filter(|path| path.is_usable_for_data())
                else {
                    continue;
                };
                let Some((bearer, peer)) = path
                    .active_address()
                    .or_else(|| (path_id == 0).then_some(slot.bootstrap_address).flatten())
                else {
                    continue;
                };
                let Some(entry) = self.bearers.get(bearer) else {
                    continue;
                };
                if !entry.can_submit() {
                    continue;
                }
                let info = entry.info();
                let endpoint = self
                    .datagram_endpoint(association)
                    .ok_or(QuicNodeError::MissingAssociation)?;
                let layout = endpoint.datagram_send_layout(
                    path_id,
                    packet.packet_range(),
                    packet.packet_range().end + packet.suffix_capacity(),
                    info.prefix_required,
                    info.suffix_required,
                    PACKET.min(info.max_packet_size),
                    priority,
                );
                let (range, header, header_len) = match layout {
                    Ok(layout) => layout,
                    Err(error) => {
                        last = QuicNodeEgressError::Transport(error);
                        continue;
                    }
                };
                if packet.bytes_mut_unique().is_none() {
                    return Err(QuicNodeEgressError::Transport(Error::Blocked));
                }
                let endpoint = self.datagram_endpoint_mut(association).unwrap();
                // Last fallible step (pacing) precedes every payload mutation.
                match endpoint.commit_datagram_transmission(path_id, range.len()) {
                    Ok(()) => {}
                    Err(error) => {
                        last = QuicNodeEgressError::Transport(error);
                        continue;
                    }
                }
                return Ok((bearer, peer, path_id, range, header, header_len));
            }
            Err(last)
        })();
        let (bearer, peer_l2_address, path_id, range, header, header_len) = match prepare {
            Ok(prepared) => prepared,
            Err(reason) => return Err(DatagramSendError { reason, packet }),
        };
        let (mut buffer, payload) = packet.into_parts();
        let storage = buffer
            .as_mut_unique()
            .expect("preflighted unique datagram lease");
        storage[range.start..range.start + header_len].copy_from_slice(&header[..header_len]);
        #[cfg(feature = "packet-protection")]
        {
            let endpoint = self.datagram_endpoint(association).unwrap();
            if endpoint.datagram_tag_len() != 0 {
                // Preflight guarantees CID, tag space, fixed key/nonce sizes
                // and a short payload. AEAD sealing has no recoverable failure
                // under those invariants, so refusal never returns ciphertext.
                endpoint
                    .protect_packet_in_place(
                        path_id,
                        &mut storage[range.start..],
                        payload.end - range.start,
                    )
                    .expect("preflighted bounded AEAD datagram");
            }
        }
        #[cfg(not(feature = "packet-protection"))]
        let _ = (path_id, payload);
        Ok(NodeEgress {
            association,
            bearer,
            peer_l2_address,
            packet: OwnedPacket::new(buffer, range)
                .ok()
                .expect("preflighted datagram range"),
        })
    }
}

impl<P: PacketPool + 'static, const PACKET: usize> QuicNode<P, PACKET> {
    fn datagram_endpoint(
        &self,
        association: QuicAssociation,
    ) -> Option<&crate::EndpointState<PACKET>> {
        match &self.slot(association)?.state {
            Association::Client(client) => client.connection().endpoint(),
            Association::Server(server) => Some(&server.mux.endpoint),
        }
    }
    fn datagram_endpoint_mut(
        &mut self,
        association: QuicAssociation,
    ) -> Option<&mut crate::EndpointState<PACKET>> {
        match &mut self.slot_mut(association)?.state {
            Association::Client(client) => client.connection_mut().endpoint_mut().ok(),
            Association::Server(server) => Some(&mut server.mux.endpoint),
        }
    }

    pub(super) fn receive_owned_endpoint<Admit, StreamEvent>(
        &mut self,
        association: QuicAssociation,
        path_id: usize,
        meta: PacketMeta,
        mut packet: OwnedPacket<P::Buffer>,
        _admit: Admit,
        mut on_stream: StreamEvent,
    ) -> Result<NodeIngress<P::Buffer, P::Buffer, ForwardNextHop>, RejectedNodePacket<P::Buffer>>
    where
        Admit: FnMut(crate::BootstrapOpen) -> Option<InitialAdmission>,
        StreamEvent: FnMut(ApplicationStreamSource, u64, u64, bool, &[u8]) -> Result<usize, Error>,
    {
        let prefix =
            crate::ShortHeader::decode_prefix(packet.bytes()).expect("classified short header");
        let duplicate = self.datagram_endpoint(association).is_some_and(|endpoint| {
            crate::ShortHeader::decode_with_expected(
                packet.bytes(),
                endpoint.expected_packet_number(),
            )
            .is_ok_and(|(header, _)| endpoint.has_received_packet(header.packet_number))
        });
        #[cfg(feature = "packet-protection")]
        if self
            .datagram_endpoint(association)
            .is_some_and(|endpoint| endpoint.datagram_tag_len() != 0)
        {
            let packet_len = packet.bytes().len();
            let result = match packet.bytes_mut_unique() {
                Some(bytes) => self
                    .datagram_endpoint(association)
                    .unwrap()
                    .open_packet_in_place(path_id, bytes, packet_len),
                None => Err(Error::Blocked),
            };
            let plaintext_len = match result {
                Ok(len) => len,
                Err(error) => {
                    return Err(RejectedNodePacket {
                        reason: QuicNodePacketRejection::Packet(error),
                        packet,
                    });
                }
            };
            let number = crate::ShortHeader::decode_with_expected(
                packet.bytes(),
                self.datagram_endpoint(association)
                    .unwrap()
                    .expected_packet_number(),
            )
            .unwrap()
            .0
            .packet_number;
            self.datagram_endpoint_mut(association)
                .unwrap()
                .opened_packet_number = Some(number);
            let range = packet.packet_range();
            let (buffer, _) = packet.into_parts();
            packet = OwnedPacket::new(buffer, range.start..range.start + plaintext_len)
                .ok()
                .unwrap();
        }
        // The caller already classified and routed this owned short-header
        // packet. Do not repeat registry lookup through the bootstrap/relay
        // serializer; share its endpoint handler instead.
        let result = self.receive_endpoint_packet(association, path_id, meta, packet, &mut on_stream);
        #[cfg(feature = "packet-protection")]
        if let Some(endpoint) = self.datagram_endpoint_mut(association) {
            endpoint.opened_packet_number = None;
        }
        if result.is_err()
            && self
                .datagram_endpoint(association)
                .is_some_and(|endpoint| endpoint.close_code() == Some(0x0a))
        {
            let rejected = result.err().unwrap();
            let address = self.slot(association).and_then(Self::slot_active_address);
            let (mut buffer, range) = rejected.packet.into_parts();
            // Reuse RX storage for a best-effort CLOSE even at a full pool.
            let close = buffer.as_mut_unique().and_then(|storage| {
                self.datagram_endpoint_mut(association)
                    .unwrap()
                    .poll_close(&mut storage[range.start..])
                    .ok()
                    .flatten()
            });
            let _ = self.remove(association);
            self.push_association_event(AssociationEvent::Closed {
                association,
                code: 0x0a,
            });
            if let (Some(len), Some((bearer, peer_l2_address))) = (close, address) {
                return Ok(NodeIngress::PathControl {
                    association,
                    response: NodeEgress {
                        association,
                        bearer,
                        peer_l2_address,
                        packet: OwnedPacket::new(buffer, range.start..range.start + len)
                            .ok()
                            .unwrap(),
                    },
                });
            }
            return Err(RejectedNodePacket {
                reason: rejected.reason,
                packet: OwnedPacket::new(buffer, range).ok().unwrap(),
            });
        }
        if duplicate {
            return result;
        }
        match result {
            Ok(NodeIngress::Association {
                association: ingress,
                packet,
            }) => {
                let mut count = 0;
                let mut last_payload = None;
                for data in crate::datagram::payloads(packet.bytes(), prefix.header_len) {
                    count += 1;
                    let offset = data.as_ptr() as usize - packet.bytes().as_ptr() as usize;
                    last_payload = Some(offset..offset + data.len());
                }
                if let Some(payload) = last_payload {
                    if let Some(index) = self
                        .datagram_handlers
                        .iter()
                        .position(|(id, _)| *id == association)
                    {
                        // Our sender never coalesces DATAGRAMs. Accept foreign
                        // peers that do: copy only the earlier payloads into
                        // distinct pool leases, preserving exclusive ownership.
                        // Exhausted fallback capacity drops unreliable payloads.
                        for data in crate::datagram::payloads(packet.bytes(), prefix.header_len)
                            .take(count - 1)
                        {
                            let Some(mut writer) =
                                self.pool.acquire_writer(crate::PACKET_PREFIX_RESERVE, 0)
                            else {
                                continue;
                            };
                            let storage = crate::bearer::PacketWriter::payload_mut(&mut writer);
                            if storage.len() < data.len() {
                                continue;
                            }
                            storage[..data.len()].copy_from_slice(data);
                            let copied = crate::bearer::PacketWriter::commit(writer, data.len())
                                .expect("validated datagram copy range");
                            (self.datagram_handlers[index].1)(ReceivedDatagram {
                                association,
                                meta,
                                packet: copied,
                            });
                        }
                        // Dedicated packets take this path with no acquisition,
                        // no payload copy, and no shared buffer aliases.
                        let (buffer, range) = packet.into_parts();
                        let packet = OwnedPacket::new(
                            buffer,
                            range.start + payload.start..range.start + payload.end,
                        )
                        .ok()
                        .expect("validated datagram payload range");
                        (self.datagram_handlers[index].1)(ReceivedDatagram {
                            association,
                            meta,
                            packet,
                        });
                    }
                    Ok(NodeIngress::Datagram {
                        association: ingress,
                    })
                } else {
                    Ok(NodeIngress::Association {
                        association: ingress,
                        packet,
                    })
                }
            }
            other => other,
        }
    }
}
