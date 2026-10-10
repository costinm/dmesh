//! Bearer-neutral persistent stream multiplexer.
//!
//! A connection feeds complete packets through [`StreamMux::receive_stream_events`]
//! and encodes caller-selected response ranges with
//! [`StreamMux::encode_response_at`]. Socket, radio, timer, and peer-L2-address
//! policy stays outside this module.

use crate::callback::{CallbackError, CallbackStreams, CopyingError, CopyingStreamEvents};
use crate::{ConnectionId, EndpointState, Error, Role};
use alloc::{sync::Arc, vec::Vec};
use smallvec::SmallVec;

pub(crate) fn retain_stream_bytes(bytes: &[u8]) -> Result<Arc<Vec<u8>>, CallbackError> {
    // Allocate small ownership metadata before the large, fallible payload
    // reservation. Payload exhaustion must not invoke Rust's abort handler.
    let mut packet = Arc::new(Vec::new());
    let data = Arc::get_mut(&mut packet).expect("new packet has one owner");
    data.try_reserve_exact(bytes.len())
        .map_err(|_| CallbackError::Capacity)?;
    data.extend_from_slice(bytes);
    Ok(packet)
}

struct ValidationSink;

struct ApplicationStreamSink<'a, F> {
    handler: &'a mut F,
    bytes: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retention_failure_leaves_packet_unacked_and_preserves_consumed_prefix() {
        for mixed_control in [false, true] {
            for partial in [false, true] {
                let local = ConnectionId::new(0x47).unwrap();
                let peer = ConnectionId::new(0x31).unwrap();
                let limits = crate::ConnectionLimits::with_receive_profile(1024, 1024, 4);
                let mut receiver = StreamMux::<256>::new_with_history_capacity(
                    Role::Server,
                    limits,
                    256,
                    1,
                    4,
                    1024,
                    4,
                );
                receiver.install_connection_ids(local, peer).unwrap();
                let mut packet = [0; 256];
                let mut n = crate::ShortHeader {
                    flags: crate::FLAG_FIXED,
                    dcid: local,
                    packet_number: 0,
                    packet_number_len: 4,
                }
                .encode(&mut packet)
                .unwrap();
                if mixed_control {
                    n += crate::Frame::MaxData(2048)
                        .encode(&mut packet[n..])
                        .unwrap();
                }
                n += crate::Frame::Stream(crate::StreamFrame {
                    id: crate::FIRST_CLIENT_BIDI_STREAM_ID,
                    offset: if partial { 0 } else { 4 },
                    fin: true,
                    data: b"efgh",
                })
                .encode(&mut packet[n..])
                .unwrap();
                let mut delivered = Vec::new();
                receiver
                    .receive_stream_events_with_retention(
                        &packet[..n],
                        0,
                        |_, _, _, bytes| {
                            assert!(partial, "out-of-order data reached consumer");
                            delivered.extend_from_slice(&bytes[..2]);
                            Ok(2)
                        },
                        |_| Err(CallbackError::Capacity),
                    )
                    .unwrap();
                assert!(
                    !receiver.endpoint.has_received_packet(0),
                    "failed storage ACKed packet"
                );
                assert!(
                    !receiver.endpoint.ack_pending,
                    "failed admission scheduled an ACK"
                );
                if mixed_control {
                    assert_eq!(receiver.endpoint.send.max_data, 2048);
                }
                assert_eq!(receiver.ordered.retained_bytes(), 0);
                if !partial {
                    let mut prefix = [0; 256];
                    let mut m = crate::ShortHeader {
                        flags: crate::FLAG_FIXED,
                        dcid: local,
                        packet_number: 1,
                        packet_number_len: 4,
                    }
                    .encode(&mut prefix)
                    .unwrap();
                    m += crate::Frame::Stream(crate::StreamFrame {
                        id: crate::FIRST_CLIENT_BIDI_STREAM_ID,
                        offset: 0,
                        fin: false,
                        data: b"abcd",
                    })
                    .encode(&mut prefix[m..])
                    .unwrap();
                    receiver
                        .receive_stream_events(&prefix[..m], |_, _, _, bytes| {
                            delivered.extend_from_slice(bytes);
                            Ok(bytes.len())
                        })
                        .unwrap();
                }
                receiver
                    .receive_stream_events(&packet[..n], |_, _, _, bytes| {
                        delivered.extend_from_slice(bytes);
                        Ok(bytes.len())
                    })
                    .unwrap();
                assert_eq!(
                    delivered,
                    if partial {
                        &b"efgh"[..]
                    } else {
                        &b"abcdefgh"[..]
                    }
                );
                assert!(receiver.endpoint.has_received_packet(0));
                assert_eq!(receiver.ordered.retained_bytes(), 0);
            }
        }
    }

    #[test]
    fn lowered_retention_rejects_out_of_order_packet_before_ack() {
        const PACKET: usize = 256;
        let limits = crate::ConnectionLimits::with_receive_profile(1024, 1024, 4);
        let client = crate::ConnectionId::new(0x31).unwrap();
        let server = crate::ConnectionId::new(0x47).unwrap();
        let mut sender = StreamMux::<PACKET>::new_with_history_capacity(
            Role::Client,
            limits,
            PACKET as u64,
            1,
            4,
            1024,
            4,
        );
        sender.install_connection_ids(client, server).unwrap();
        let mut receiver = StreamMux::<PACKET>::new_with_history_capacity(
            Role::Server,
            limits,
            PACKET as u64,
            1,
            4,
            1024,
            4,
        );
        receiver.install_connection_ids(server, client).unwrap();
        receiver.set_delivery_limits(4, 32);

        let mut packet = [0u8; PACKET];
        let (used, _) = sender
            .encode_response_at(
                crate::FIRST_CLIENT_BIDI_STREAM_ID,
                64,
                &[7; 64],
                false,
                &mut packet,
            )
            .unwrap();
        receiver
            .receive_stream_events(&packet[..used], |_, _, _, bytes| Ok(bytes.len()))
            .unwrap();

        assert_eq!(receiver.endpoint.received_packet_count(), 0);
    }
}

impl<F> CopyingStreamEvents for ApplicationStreamSink<'_, F>
where
    F: FnMut(u64, u64, bool, &[u8]) -> Result<usize, Error>,
{
    type Error = Error;

    fn stream_chunk(
        &mut self,
        stream: u64,
        offset: u64,
        end: bool,
        bytes: &[u8],
    ) -> Result<usize, Self::Error> {
        let consumed = (self.handler)(stream, offset, end, bytes)?;
        if consumed > bytes.len() {
            return Err(Error::Invalid);
        }
        self.bytes = self.bytes.saturating_add(consumed);
        Ok(consumed)
    }
}

impl CopyingStreamEvents for ValidationSink {
    type Error = ();

    fn stream_chunk(
        &mut self,
        _stream: u64,
        _offset: u64,
        _end: bool,
        bytes: &[u8],
    ) -> Result<usize, Self::Error> {
        Ok(bytes.len())
    }
}

#[derive(Debug)]
pub(crate) enum StreamDeliveryError {
    Packet(Error),
    Application(Error),
}

/// Persistent connection state plus bounded stream lifecycle management.
pub(crate) struct StreamMux<const P: usize = { crate::DEFAULT_MAX_PACKET_SIZE }> {
    pub endpoint: EndpointState<P>,
    ordered: CallbackStreams<Arc<Vec<u8>>>,
}

impl<const P: usize> StreamMux<P> {
    pub(crate) fn set_delivery_limits(&mut self, max_streams: usize, max_bytes: usize) {
        self.ordered.set_limits(max_streams, max_bytes);
    }

    #[cfg(test)]
    pub(crate) fn delivery_limits(&self) -> (usize, usize) {
        self.ordered.limits()
    }

    pub(crate) unsafe fn init_in_place(
        out: *mut Self,
        role: Role,
        limits: crate::ConnectionLimits,
        max_packet_size: u64,
        max_pending_streams: usize,
        max_stream_bytes: usize,
        history_capacity: usize,
    ) {
        unsafe {
            crate::EndpointState::init_in_place(
                core::ptr::addr_of_mut!((*out).endpoint),
                role,
                limits,
                max_packet_size,
                history_capacity,
            );
            core::ptr::addr_of_mut!((*out).ordered)
                .write(CallbackStreams::new(max_pending_streams, max_stream_bytes));
        }
    }
    pub(crate) fn new_with_history_capacity(
        role: Role,
        limits: crate::ConnectionLimits,
        max_packet_size: u64,
        _event_capacity: usize,
        max_pending_streams: usize,
        max_stream_bytes: usize,
        history_capacity: usize,
    ) -> Self {
        Self {
            endpoint: EndpointState::new_with_history_capacity(
                role,
                limits,
                max_packet_size,
                history_capacity,
            ),
            ordered: CallbackStreams::new(max_pending_streams, max_stream_bytes),
        }
    }

    pub(crate) fn install_connection_ids(
        &mut self,
        local: ConnectionId,
        peer: ConnectionId,
    ) -> Result<(), Error> {
        self.endpoint.install_connection_ids(local, peer)
    }

    pub(crate) fn close_code(&self) -> Option<u64> {
        self.endpoint.close_code()
    }

    /// Admit one packet and deliver every STREAM frame through one ordered
    /// callback. In-order bytes are borrowed from `input`; only ranges waiting
    /// behind a gap are copied into the mux's fixed stream-capacity ledger.
    pub(crate) fn receive_stream_events<F>(
        &mut self,
        input: &[u8],
        mut on_stream: F,
    ) -> Result<(), StreamDeliveryError>
    where
        F: FnMut(u64, u64, bool, &[u8]) -> Result<usize, Error>,
    {
        self.receive_stream_events_on_path(input, 0, on_stream)
    }

    pub(crate) fn receive_stream_events_on_path<F>(
        &mut self,
        input: &[u8],
        ingress_path: usize,
        mut on_stream: F,
    ) -> Result<(), StreamDeliveryError>
    where
        F: FnMut(u64, u64, bool, &[u8]) -> Result<usize, Error>,
    {
        self.receive_stream_events_with_retention(
            input,
            ingress_path,
            on_stream,
            retain_stream_bytes,
        )
    }

    fn receive_stream_events_with_retention<F, Retain>(
        &mut self,
        input: &[u8],
        ingress_path: usize,
        mut on_stream: F,
        mut retain: Retain,
    ) -> Result<(), StreamDeliveryError>
    where
        F: FnMut(u64, u64, bool, &[u8]) -> Result<usize, Error>,
        Retain: FnMut(&[u8]) -> Result<Arc<Vec<u8>>, CallbackError>,
    {
        let (_header, header_len) =
            crate::ShortHeader::decode_with_expected(input, self.endpoint.expected_packet_number())
                .map_err(StreamDeliveryError::Packet)?;
        if _header.packet_number < self.endpoint.receive_packet_floor {
            self.endpoint
                .receive_packet_on_path(input, ingress_path)
                .map_err(StreamDeliveryError::Packet)?;
            return Ok(());
        }
        let mut offset = header_len;
        let mut has_stream = false;
        // Inline metadata covers ordinary packets without per-packet heap
        // churn. Larger coalesced packets spill, rather than impose a cap.
        let mut packet_frames = SmallVec::<[crate::StreamFrame<'_>; 4]>::new();
        while offset < input.len() {
            let (frame, used) =
                crate::decode_frame(&input[offset..]).map_err(StreamDeliveryError::Packet)?;
            if let crate::Frame::Stream(stream) = frame {
                has_stream = true;
                if self.endpoint.stream_delivery_complete(stream.id) {
                    offset += used;
                    continue;
                }
                packet_frames.push(stream);
            }
            offset += used;
        }
        if !has_stream {
            self.endpoint
                .receive_packet_on_path(input, ingress_path)
                .map_err(StreamDeliveryError::Packet)?;
            return Ok(());
        }
        match self.ordered.validate_packet_frames(
            packet_frames
                .iter()
                .map(|frame| (frame.id, frame.offset, frame.data.len(), frame.fin)),
        ) {
            Ok(()) => {}
            Err(CallbackError::Capacity) => {
                // Leave the packet unacknowledged. Normal loss recovery
                // retries it after live delivery state drains.
                return Ok(());
            }
            Err(_) => return Err(StreamDeliveryError::Packet(Error::Invalid)),
        }
        let packet_stream_bytes = packet_frames.iter().fold(0usize, |total, frame| {
            total.saturating_add(frame.data.len())
        });
        if self.ordered.retention_may_exceed(packet_stream_bytes) {
            // A lowered live retention policy can be smaller than credit the
            // peer has already received. Dry-run only this exceptional case
            // before endpoint state ACKs the packet.
            let mut staged = self.ordered.clone();
            for frame in &packet_frames {
                let mut sink = ValidationSink;
                match staged.try_receive_copying_borrowed(
                    frame.id,
                    frame.data,
                    frame.offset,
                    frame.fin,
                    || retain(frame.data),
                    &mut sink,
                ) {
                    Ok(()) => {}
                    Err(CopyingError::Transport(CallbackError::Capacity)) => return Ok(()),
                    Err(CopyingError::Transport(_)) | Err(CopyingError::Callback(_)) => {
                        return Err(StreamDeliveryError::Packet(Error::Invalid));
                    }
                }
            }
        }
        let admitted = self
            .endpoint
            .receive_packet_before_stream_delivery(input, ingress_path)
            .map_err(StreamDeliveryError::Packet)?;

        // Reuse the preflight's borrowed frame views after endpoint validation.
        // Keep duplicates here: ordered delivery may resume a suffix which
        // the application withheld on the first arrival, without redelivering
        // already-consumed bytes. The endpoint's duplicate view is empty.
        // These are borrowed packet views, not owned payloads. Iterate the
        // views by reference rather than constructing SmallVec's owning
        // iterator (and its separate remaining-elements drop path).
        for frame in &packet_frames {
            let mut sink = ApplicationStreamSink {
                handler: &mut on_stream,
                bytes: 0,
            };
            let delivery = self.ordered.try_receive_copying_borrowed(
                frame.id,
                frame.data,
                frame.offset,
                frame.fin,
                || retain(frame.data),
                &mut sink,
            );
            if sink.bytes != 0 {
                // Consumption in the receive callback is part of this same
                // packet's ACK turn, not an asynchronous credit release.
                // Preserve the negotiated threshold/delay, as the client
                // receive path does, instead of ACKing every STREAM packet.
                self.endpoint
                    .stream_consumed_before_packet_ack(frame.id, sink.bytes)
                    .map_err(StreamDeliveryError::Packet)?;
            }
            match delivery {
                Ok(()) => {}
                Err(CopyingError::Transport(CallbackError::Capacity)) => return Ok(()),
                Err(CopyingError::Transport(_)) => {
                    return Err(StreamDeliveryError::Packet(Error::Invalid));
                }
                Err(CopyingError::Callback(error)) => {
                    return Err(StreamDeliveryError::Application(error));
                }
            }
        }
        if !admitted.duplicate && admitted.stream_count != 0 {
            self.endpoint
                .commit_stream_packet_receive(admitted.header.packet_number, ingress_path);
        }
        Ok(())
    }

    /// Resume bytes retained because an application consumer previously
    /// accepted only a prefix. Receive credit advances only by the number of
    /// bytes accepted by this callback.
    pub(crate) fn resume_stream_events<F>(
        &mut self,
        stream_id: u64,
        mut on_stream: F,
    ) -> Result<usize, StreamDeliveryError>
    where
        F: FnMut(u64, u64, bool, &[u8]) -> Result<usize, Error>,
    {
        let mut sink = ApplicationStreamSink {
            handler: &mut on_stream,
            bytes: 0,
        };
        self.ordered
            .resume_copying(stream_id, &mut sink)
            .map_err(|error| match error {
                CopyingError::Transport(_) => StreamDeliveryError::Packet(Error::Invalid),
                CopyingError::Callback(error) => StreamDeliveryError::Application(error),
            })?;
        if sink.bytes != 0 {
            self.endpoint
                .stream_consumed(stream_id, sink.bytes)
                .map_err(StreamDeliveryError::Packet)?;
        }
        Ok(sink.bytes)
    }

    /// Encode one contiguous response-stream fragment.  Application handlers
    /// remain oblivious to bearer MTU: the QUIC terminal chooses fragments and
    /// retains their shared stream offset for UDP, UART, NOW, and NAN alike.
    pub(crate) fn encode_response_at(
        &mut self,
        stream_id: u64,
        offset: u64,
        data: &[u8],
        fin: bool,
        out: &mut [u8],
    ) -> Result<(usize, u32), Error> {
        self.encode_response_at_on_path(0, stream_id, offset, data, fin, out)
    }

    pub(crate) fn encode_response_at_on_path(
        &mut self,
        path_id: usize,
        stream_id: u64,
        offset: u64,
        data: &[u8],
        fin: bool,
        out: &mut [u8],
    ) -> Result<(usize, u32), Error> {
        if self.endpoint.open_send_stream(stream_id, u64::MAX).is_err() {
            // A response stream may already have been opened by the caller.
        }
        let peer = self
            .endpoint
            .peer_connection_id_on_path(path_id)
            .ok_or(Error::WrongConnectionId)?;
        self.endpoint
            .encode_stream_packet_on_path(path_id, peer, stream_id, offset, fin, data, out)
    }

    pub(crate) fn encode_response_from_owned_at_on_path(
        &mut self,
        path_id: usize,
        stream_id: u64,
        offset: u64,
        fin: bool,
        packet: crate::OwnedPacket<crate::ErasedPacketBuffer>,
        out: &mut [u8],
    ) -> Result<(usize, u32), (Error, crate::OwnedPacket<crate::ErasedPacketBuffer>)> {
        if self.endpoint.open_send_stream(stream_id, u64::MAX).is_err() {
            // A response stream may already have been opened by the caller.
        }
        let Some(peer) = self.endpoint.peer_connection_id_on_path(path_id) else {
            return Err((Error::WrongConnectionId, packet));
        };
        self.endpoint.encode_stream_packet_from_owned_on_path(
            path_id, peer, stream_id, offset, fin, packet, out,
        )
    }
}
