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
    finished: bool,
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

    fn stream_finished(&mut self, _stream: u64) {
        self.finished = true;
    }
}

#[derive(Debug)]
pub(crate) enum StreamDeliveryError {
    Packet(Error),
    Application(Error),
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

/// Persistent connection state plus bounded stream lifecycle management.
pub(crate) struct StreamMux<
    const N: usize,
    const H: usize = 16,
    const P: usize = { crate::DEFAULT_MAX_PACKET_SIZE },
> {
    pub endpoint: EndpointState<N, H, P>,
    completed: Vec<u64>,
    max_pending_streams: usize,
    ordered: CallbackStreams<Arc<Vec<u8>>>,
}

impl<const N: usize, const H: usize, const P: usize> StreamMux<N, H, P> {
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
            core::ptr::addr_of_mut!((*out).completed).write(Vec::new());
            core::ptr::addr_of_mut!((*out).max_pending_streams).write(max_pending_streams);
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
            completed: Vec::new(),
            max_pending_streams,
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
        let mut staged = self.ordered.clone();
        while offset < input.len() {
            let (frame, used) =
                crate::decode_frame(&input[offset..]).map_err(StreamDeliveryError::Packet)?;
            if let crate::Frame::Stream(stream) = frame {
                has_stream = true;
                let mut sink = ValidationSink;
                match staged.receive_copying_borrowed(
                    stream.id,
                    stream.data,
                    stream.offset,
                    stream.fin,
                    || Arc::new(stream.data.to_vec()),
                    &mut sink,
                ) {
                    Ok(()) => {}
                    Err(CopyingError::Transport(CallbackError::Capacity)) => {
                        // Leave the packet unacknowledged. Normal loss recovery
                        // retries it after the missing ordered prefix arrives.
                        return Ok(());
                    }
                    Err(CopyingError::Transport(_)) | Err(CopyingError::Callback(_)) => {
                        return Err(StreamDeliveryError::Packet(Error::Invalid));
                    }
                }
            }
            offset += used;
        }
        if !has_stream {
            self.endpoint
                .receive_packet(input)
                .map_err(StreamDeliveryError::Packet)?;
            return Ok(());
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
            if self.completed.contains(&frame.id) {
                continue;
            }
            let mut sink = ApplicationStreamSink {
                handler: &mut on_stream,
                bytes: 0,
                finished: false,
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
            if sink.finished {
                if self.completed.len() >= self.max_pending_streams {
                    self.completed.remove(0);
                }
                self.completed.push(frame.id);
            }
        }
        Ok(())
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
