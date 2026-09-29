//! Bearer-neutral persistent stream multiplexer.
//!
//! A connection feeds complete packets through [`StreamMux::receive_stream_events`]
//! and encodes caller-selected response ranges with
//! [`StreamMux::encode_response_at`]. Socket, radio, timer, and peer-L2-address
//! policy stays outside this module.

use crate::callback::{CallbackError, CallbackStreams, CopyingError, CopyingStreamEvents};
use crate::{ConnectionId, EndpointState, Error, Role};
use alloc::{sync::Arc, vec::Vec};

struct ValidationSink;

struct ApplicationStreamSink<'a, F> {
    handler: &'a mut F,
    bytes: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let (_header, header_len) =
            crate::ShortHeader::decode_with_expected(input, self.endpoint.expected_packet_number())
                .map_err(StreamDeliveryError::Packet)?;
        let mut offset = header_len;
        let mut has_stream = false;
        let mut completed_before_packet = Vec::new();
        let mut packet_frames = Vec::new();
        while offset < input.len() {
            let (frame, used) =
                crate::decode_frame(&input[offset..]).map_err(StreamDeliveryError::Packet)?;
            if let crate::Frame::Stream(stream) = frame {
                has_stream = true;
                if self.endpoint.stream_delivery_complete(stream.id) {
                    if !completed_before_packet.contains(&stream.id) {
                        completed_before_packet.push(stream.id);
                    }
                    offset += used;
                    continue;
                }
                packet_frames.push((stream.id, stream.offset, stream.data.len(), stream.fin));
            }
            offset += used;
        }
        if !has_stream {
            self.endpoint
                .receive_packet(input)
                .map_err(StreamDeliveryError::Packet)?;
            return Ok(());
        }
        match self.ordered.validate_packet_frames(&packet_frames) {
            Ok(()) => {}
            Err(CallbackError::Capacity) => {
                // Leave the packet unacknowledged. Normal loss recovery
                // retries it after live delivery state drains.
                return Ok(());
            }
            Err(_) => return Err(StreamDeliveryError::Packet(Error::Invalid)),
        }
        let packet_stream_bytes = packet_frames
            .iter()
            .fold(0usize, |total, (_, _, len, _)| total.saturating_add(*len));
        if self.ordered.retention_may_exceed(packet_stream_bytes) {
            // A lowered live retention policy can be smaller than credit the
            // peer has already received. Dry-run only this exceptional case
            // before endpoint state ACKs the packet.
            let mut staged = self.ordered.clone();
            let mut offset = header_len;
            while offset < input.len() {
                let (decoded, used) =
                    crate::decode_frame(&input[offset..]).map_err(StreamDeliveryError::Packet)?;
                offset += used;
                let crate::Frame::Stream(frame) = decoded else {
                    continue;
                };
                if completed_before_packet.contains(&frame.id) {
                    continue;
                }
                let mut sink = ValidationSink;
                match staged.receive_copying_borrowed(
                    frame.id,
                    frame.data,
                    frame.offset,
                    frame.fin,
                    || Arc::new(frame.data.to_vec()),
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
        self.endpoint
            .receive_packet(input)
            .map_err(StreamDeliveryError::Packet)?;

        let mut offset = header_len;
        while offset < input.len() {
            let (decoded, used) =
                crate::decode_frame(&input[offset..]).map_err(StreamDeliveryError::Packet)?;
            offset += used;
            let crate::Frame::Stream(frame) = decoded else {
                continue;
            };
            if completed_before_packet.contains(&frame.id) {
                continue;
            }
            let mut sink = ApplicationStreamSink {
                handler: &mut on_stream,
                bytes: 0,
            };
            match self.ordered.receive_copying_borrowed(
                frame.id,
                frame.data,
                frame.offset,
                frame.fin,
                || Arc::new(frame.data.to_vec()),
                &mut sink,
            ) {
                Ok(()) => {}
                Err(CopyingError::Transport(_)) => {
                    return Err(StreamDeliveryError::Packet(Error::Invalid));
                }
                Err(CopyingError::Callback(error)) => {
                    return Err(StreamDeliveryError::Application(error));
                }
            }
            if sink.bytes != 0 {
                self.endpoint
                    .stream_consumed(frame.id, sink.bytes)
                    .map_err(StreamDeliveryError::Packet)?;
            }
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
        if self
            .endpoint
            .open_send_stream(stream_id, crate::INITIAL_MAX_STREAM_DATA)
            .is_err()
        {
            // A response stream may already have been opened by the caller.
        }
        let peer = self
            .endpoint
            .peer_connection_id()
            .ok_or(Error::WrongConnectionId)?;
        self.endpoint
            .encode_stream_packet(peer, stream_id, offset, fin, data, out)
    }
}
