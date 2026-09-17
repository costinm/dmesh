//! Bearer-neutral persistent stream multiplexer.
//!
//! A bearer feeds complete datagrams to [`StreamMux::receive_datagram`] and
//! encodes returned responses using [`StreamMux::encode_response`].  Socket,
//! radio, timer, and peer-address policy stays outside this module.

use crate::callback::{CallbackError, CallbackStreams, CopyingError, CopyingStreamEvents};
use crate::{ConnectionId, EndpointState, Error, Role};
use alloc::{sync::Arc, vec::Vec};

#[derive(Default)]
struct RequestCollector {
    stream: u64,
    data: Vec<u8>,
    finished: bool,
}

struct ValidationSink;

struct StreamingSink<'a, F> {
    handler: &'a mut F,
    bytes: usize,
    finished: bool,
}

impl<F> CopyingStreamEvents for StreamingSink<'_, F>
where
    F: FnMut(u64, bool, &[u8]) -> Result<usize, ()>,
{
    type Error = ();

    fn stream_chunk(
        &mut self,
        stream: u64,
        _offset: u64,
        end: bool,
        bytes: &[u8],
    ) -> Result<usize, Self::Error> {
        let consumed = (self.handler)(stream, end, bytes)?;
        if consumed > bytes.len() {
            return Err(());
        }
        self.bytes = self.bytes.saturating_add(consumed);
        Ok(consumed)
    }

    fn stream_finished(&mut self, _stream: u64) {
        self.finished = true;
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

impl CopyingStreamEvents for RequestCollector {
    type Error = ();

    fn stream_chunk(
        &mut self,
        stream: u64,
        _offset: u64,
        _end: bool,
        bytes: &[u8],
    ) -> Result<usize, Self::Error> {
        self.stream = stream;
        self.data.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn stream_finished(&mut self, stream: u64) {
        self.stream = stream;
        self.finished = true;
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MuxRequest {
    pub stream_id: u64,
    pub data: Vec<u8>,
}

/// Persistent connection state plus bounded stream lifecycle management.
pub struct StreamMux<
    const N: usize,
    const H: usize = 16,
    const P: usize = { crate::DEFAULT_MAX_DATAGRAM_SIZE },
> {
    pub endpoint: EndpointState<N, H, P>,
    completed: Vec<u64>,
    max_pending_streams: usize,
    ordered: CallbackStreams<Arc<Vec<u8>>>,
    assembled: Vec<(u64, Vec<u8>)>,
    ready: Vec<MuxRequest>,
}

impl<const N: usize, const H: usize, const P: usize> StreamMux<N, H, P> {
    pub unsafe fn init_in_place(
        out: *mut Self,
        role: Role,
        limits: crate::ConnectionLimits,
        max_datagram_size: u64,
        max_pending_streams: usize,
        max_stream_bytes: usize,
        history_capacity: usize,
    ) {
        unsafe {
            crate::EndpointState::init_in_place(
                core::ptr::addr_of_mut!((*out).endpoint),
                role,
                limits,
                max_datagram_size,
                history_capacity,
            );
            core::ptr::addr_of_mut!((*out).completed).write(Vec::new());
            core::ptr::addr_of_mut!((*out).max_pending_streams).write(max_pending_streams);
            core::ptr::addr_of_mut!((*out).ordered)
                .write(CallbackStreams::new(max_pending_streams, max_stream_bytes));
            core::ptr::addr_of_mut!((*out).assembled).write(Vec::new());
            core::ptr::addr_of_mut!((*out).ready).write(Vec::new());
        }
    }
    pub fn new(
        role: Role,
        limits: crate::ConnectionLimits,
        max_datagram_size: u64,
        _event_capacity: usize,
        max_pending_streams: usize,
        max_stream_bytes: usize,
    ) -> Self {
        Self::new_with_history_capacity(
            role,
            limits,
            max_datagram_size,
            _event_capacity,
            max_pending_streams,
            max_stream_bytes,
            H,
        )
    }

    pub fn new_with_history_capacity(
        role: Role,
        limits: crate::ConnectionLimits,
        max_datagram_size: u64,
        _event_capacity: usize,
        max_pending_streams: usize,
        max_stream_bytes: usize,
        history_capacity: usize,
    ) -> Self {
        Self {
            endpoint: EndpointState::new_with_history_capacity(
                role,
                limits,
                max_datagram_size,
                history_capacity,
            ),
            completed: Vec::new(),
            max_pending_streams,
            ordered: CallbackStreams::new(max_pending_streams, max_stream_bytes),
            assembled: Vec::new(),
            ready: Vec::new(),
        }
    }

    pub fn install_connection_ids(
        &mut self,
        local: ConnectionId,
        peer: ConnectionId,
    ) -> Result<(), Error> {
        self.endpoint.install_connection_ids(local, peer)
    }

    pub fn pending_streams(&self) -> usize {
        self.ordered.stream_count()
    }

    pub fn is_closed(&self) -> bool {
        self.endpoint.is_closed()
    }

    pub fn close(&mut self, code: u64) {
        self.endpoint.close(code);
    }

    pub fn poll_close(&mut self, out: &mut [u8]) -> Result<Option<usize>, Error> {
        self.endpoint.poll_close(out)
    }

    pub fn receive_request(&mut self, input: &[u8]) -> Result<Option<MuxRequest>, Error> {
        if !self.ready.is_empty() {
            return Ok(Some(self.ready.remove(0)));
        }
        let (_header, header_len) = crate::ShortHeader::decode_with_expected(
            input,
            self.endpoint.expected_packet_number(),
        )?;
        // This complete dispatch parse validates every frame boundary before
        // consulting or mutating mux state. Do not call `validate_datagram`
        // first: that was a third full parse for STREAM traffic (validation,
        // inspection, endpoint application).
        let mut offset = header_len;
        let mut parsed_streams = Vec::new();
        while offset < input.len() {
            let (frame, used) = crate::decode_frame(&input[offset..])?;
            if let crate::Frame::Stream(stream) = frame {
                parsed_streams.push(stream);
            }
            offset += used;
        }
        if parsed_streams.is_empty() {
            let _ = self.endpoint.receive_datagram(input)?;
            return Ok(None);
        };
        let mut staged = self.ordered.clone();
        for frame in &parsed_streams {
            let mut sink = ValidationSink;
            // The common in-order stream frame is valid only for this
            // receive turn and does not need an owned packet.  Allocate a
            // lease only if ordered delivery must retain a range behind a
            // gap.  This is the same QUIC callback policy on host and ESP;
            // an embedded receiver must not OOM merely by accepting a
            // packet that it can consume synchronously.
            match staged.receive_copying_borrowed(
                frame.id,
                frame.data,
                frame.offset,
                frame.fin,
                || Arc::new(frame.data.to_vec()),
                &mut sink,
            ) {
                Ok(()) => {}
                Err(CopyingError::Transport(CallbackError::Capacity)) => {
                    // Do not admit or ACK a datagram whose out-of-order bytes
                    // cannot be retained. This is receive backpressure, not a
                    // malformed stream: the peer's ordinary QUIC loss repair
                    // will resend it after the preceding gap is consumed.
                    return Ok(None);
                }
                Err(CopyingError::Transport(_)) => {
                    return Err(Error::Invalid);
                }
                Err(CopyingError::Callback(_)) => {
                    return Err(Error::Invalid);
                }
            }
        }
        let packet = match self.endpoint.receive_datagram(input) {
            Ok(packet) => packet,
            Err(error) => return Err(error),
        };
        // EndpointState reports the first transport-class result for a
        // complete datagram. A later request commonly piggybacks its STREAM
        // frame with the ACK for the preceding server response, in which case
        // that result is `Control` even though the validated frame list above
        // contains a stream. The mux has already staged every STREAM frame;
        // deliver those frames after any accepted packet rather than silently
        // losing a valid stream behind an ACK.
        let _ = packet;
        let lease = Arc::new(input.to_vec());
        let mut first = None;
        for frame in parsed_streams {
            let start = frame.data.as_ptr() as usize - input.as_ptr() as usize;
            let range = start..start + frame.data.len();
            if let Some(request) = self.deliver_stream_frame(frame, lease.clone(), range)? {
                if first.is_none() {
                    first = Some(request);
                } else {
                    self.ready.push(request);
                }
            }
        }
        Ok(first)
    }

    /// Receive a normal request stream while delivering one selected peer
    /// stream incrementally and in offset order.  This keeps a large object
    /// upload out of the request collector: packet framing, duplicate
    /// suppression, bounded reordering, ACKs, and receive credit remain in
    /// QUIC-lite, while the caller sees only ordered application bytes.
    pub fn receive_request_with_stream<F>(
        &mut self,
        input: &[u8],
        streamed_id: u64,
        on_stream: F,
    ) -> Result<Option<MuxRequest>, Error>
    where
        F: FnMut(u64, bool, &[u8]) -> Result<usize, ()>,
    {
        self.receive_request_with_stream_inner(input, streamed_id, on_stream, false)
    }

    /// Deliver an ordered stream directly to a consumer which declares that
    /// each returned byte is durably consumed. QUIC-lite may immediately turn
    /// that consumption into receive credit. Use
    /// `receive_request_with_stream` when storage admission is deferred.
    pub fn receive_request_with_consuming_stream<F>(
        &mut self,
        input: &[u8],
        streamed_id: u64,
        on_stream: F,
    ) -> Result<Option<MuxRequest>, Error>
    where
        F: FnMut(u64, bool, &[u8]) -> Result<usize, ()>,
    {
        self.receive_request_with_stream_inner(input, streamed_id, on_stream, true)
    }

    /// Explicit spelling of the deferred-consumption entry point. A handler
    /// has consumed the supplied prefix, but retains responsibility for
    /// granting storage credit later. This is useful for a queued file sink
    /// or deliberately slow probe consumer.
    pub fn receive_request_with_deferred_stream<F>(
        &mut self,
        input: &[u8],
        streamed_id: u64,
        on_stream: F,
    ) -> Result<Option<MuxRequest>, Error>
    where
        F: FnMut(u64, bool, &[u8]) -> Result<usize, ()>,
    {
        self.receive_request_with_stream_inner(input, streamed_id, on_stream, false)
    }

    /// Resume a selected application's ordered stream after it has made
    /// storage progress.  QUIC-lite retains any unread suffix and accounts
    /// the consumed prefix; callers only supply application byte handling.
    pub fn resume_consuming_request_stream<F>(
        &mut self,
        streamed_id: u64,
        mut on_stream: F,
    ) -> Result<usize, Error>
    where
        F: FnMut(u64, bool, &[u8]) -> Result<usize, ()>,
    {
        let mut sink = StreamingSink {
            handler: &mut on_stream,
            bytes: 0,
            finished: false,
        };
        self.ordered
            .resume_copying(streamed_id, &mut sink)
            .map_err(|_| Error::Invalid)?;
        let consumed = sink.bytes;
        let finished = sink.finished;
        drop(sink);
        // A readiness edge can complete asynchronous application work after
        // the stream's final byte was already delivered. Invoke the same
        // consumer once with an empty slice so it can observe that completion;
        // zero bytes are transport-neutral and cannot manufacture credit.
        if consumed == 0 && !finished {
            if on_stream(streamed_id, false, &[]).map_err(|_| Error::Invalid)? != 0 {
                return Err(Error::Invalid);
            }
        }
        if consumed != 0 {
            self.endpoint
                .stream_consumed_deferred(streamed_id, consumed)?;
        }
        if finished && !self.completed.contains(&streamed_id) {
            if self.completed.len() >= self.max_pending_streams {
                self.completed.remove(0);
            }
            self.completed.push(streamed_id);
        }
        Ok(consumed)
    }

    fn receive_request_with_stream_inner<F>(
        &mut self,
        input: &[u8],
        streamed_id: u64,
        mut on_stream: F,
        consume_callback_bytes: bool,
    ) -> Result<Option<MuxRequest>, Error>
    where
        F: FnMut(u64, bool, &[u8]) -> Result<usize, ()>,
    {
        if !self.ready.is_empty() {
            return Ok(Some(self.ready.remove(0)));
        }
        let (_header, header_len) = crate::ShortHeader::decode_with_expected(
            input,
            self.endpoint.expected_packet_number(),
        )?;
        let mut offset = header_len;
        let mut parsed_streams = Vec::new();
        while offset < input.len() {
            let (frame, used) = crate::decode_frame(&input[offset..])?;
            if let crate::Frame::Stream(stream) = frame {
                parsed_streams.push(stream);
            }
            offset += used;
        }
        if parsed_streams.is_empty() {
            let _ = self.endpoint.receive_datagram(input)?;
            return Ok(None);
        }
        let mut staged = self.ordered.clone();
        for frame in &parsed_streams {
            let mut sink = ValidationSink;
            // The selected upload stream can be synchronously consumed from
            // this bearer packet.  Allocate a retained lease only if an
            // out-of-order range actually needs it.
            match staged.receive_copying_borrowed(
                frame.id,
                frame.data,
                frame.offset,
                frame.fin,
                || Arc::new(frame.data.to_vec()),
                &mut sink,
            ) {
                Ok(()) => {}
                Err(CopyingError::Transport(CallbackError::Capacity)) => {
                    // The packet remains unacknowledged. Once the preceding
                    // gap is repaired, ordinary loss recovery may submit it
                    // again without terminating this stream or association.
                    return Ok(None);
                }
                Err(CopyingError::Transport(_)) | Err(CopyingError::Callback(_)) => {
                    return Err(Error::Invalid);
                }
            }
        }
        let _ = self.endpoint.receive_datagram(input)?;
        let mut first = None;
        for frame in parsed_streams {
            if frame.id == streamed_id {
                if self.completed.contains(&frame.id) {
                    continue;
                }
                let mut sink = StreamingSink {
                    handler: &mut on_stream,
                    bytes: 0,
                    finished: false,
                };
                self.ordered
                    .receive_copying_borrowed(
                        frame.id,
                        frame.data,
                        frame.offset,
                        frame.fin,
                        || Arc::new(frame.data.to_vec()),
                        &mut sink,
                    )
                    .map_err(|_| Error::Invalid)?;
                if sink.bytes != 0 && consume_callback_bytes {
                    self.endpoint
                        .stream_consumed_deferred(frame.id, sink.bytes)?;
                } else if sink.bytes != 0 {
                    // The application has consumed the ordered prefix, but
                    // its storage policy has deliberately withheld new
                    // receive capacity.  Remember the cursor so a later
                    // `grant_receive_window` can publish exactly this
                    // progress without replaying application bytes.
                    self.endpoint
                        .stream_consumed_without_credit(frame.id, sink.bytes)?;
                } else if sink.bytes == 0 {
                    // This packet number is new even when its ordered stream
                    // range is a retransmission or remains behind a gap.
                    // Re-ACK it through the same endpoint operation used by
                    // committed callbacks; otherwise sparse loss can rotate
                    // the range out of a bounded ACK summary indefinitely.
                    self.endpoint.request_stream_reack();
                }
                // The deferred entry point leaves `sink.bytes` for its
                // dispatcher to report through `EndpointState::stream_consumed*`.
                // The compatibility entry point retains the historical
                // callback-consumed behavior above.
                if sink.finished {
                    if self.completed.len() >= self.max_pending_streams {
                        self.completed.remove(0);
                    }
                    self.completed.push(frame.id);
                }
                continue;
            }
            let start = frame.data.as_ptr() as usize - input.as_ptr() as usize;
            let range = start..start + frame.data.len();
            // Non-streamed command frames retain the established request
            // collector contract.  Object-stream packets use the borrowed
            // branch above and avoid this allocation entirely.
            let lease = Arc::new(input.to_vec());
            if let Some(request) = self.deliver_stream_frame(frame, lease, range)? {
                if first.is_none() {
                    first = Some(request);
                } else {
                    self.ready.push(request);
                }
            }
        }
        Ok(first)
    }

    fn deliver_stream_frame(
        &mut self,
        frame: crate::StreamFrame<'_>,
        packet: Arc<Vec<u8>>,
        range: core::ops::Range<usize>,
    ) -> Result<Option<MuxRequest>, Error> {
        if self.completed.contains(&frame.id) {
            return Ok(None);
        }
        let mut collector = RequestCollector::default();
        match self.ordered.receive_copying(
            frame.id,
            packet,
            frame.offset,
            range,
            frame.fin,
            &mut collector,
        ) {
            Ok(()) => {}
            Err(CopyingError::Transport(_)) | Err(CopyingError::Callback(_)) => {
                return Err(Error::Invalid);
            }
        }
        if let Some((_, data)) = self.assembled.iter_mut().find(|(id, _)| *id == frame.id) {
            data.extend_from_slice(&collector.data);
        } else if !collector.data.is_empty() {
            self.assembled.push((frame.id, collector.data));
        }
        if !collector.finished {
            return Ok(None);
        }
        let stream_id = collector.stream;
        let index = self
            .assembled
            .iter()
            .position(|(id, _)| *id == stream_id)
            .ok_or(Error::Invalid)?;
        let data = self.assembled.remove(index).1;
        self.endpoint.stream_consumed(stream_id, data.len())?;
        if self.completed.len() >= self.max_pending_streams {
            self.completed.remove(0);
        }
        self.completed.push(stream_id);
        Ok(Some(MuxRequest { stream_id, data }))
    }

    pub fn complete_request(&mut self, stream_id: u64, bytes: usize) -> Result<(), Error> {
        self.endpoint.stream_consumed(stream_id, bytes)
    }

    /// Compatibility spelling for callers that treat the mux as a datagram
    /// consumer. The returned value is the completed *request*, not an
    /// application response; dispatch belongs to `dmesh-server` or another
    /// application layer.
    pub fn receive_datagram(&mut self, input: &[u8]) -> Result<Option<MuxRequest>, Error> {
        self.receive_request(input)
    }

    pub fn encode_response(
        &mut self,
        stream_id: u64,
        data: &[u8],
        fin: bool,
        out: &mut [u8],
    ) -> Result<(usize, u32), Error> {
        self.encode_response_at(stream_id, 0, data, fin, out)
    }

    /// Encode one contiguous response-stream fragment.  Application handlers
    /// remain oblivious to bearer MTU: the QUIC terminal chooses fragments and
    /// retains their shared stream offset for UDP, UART, NOW, and NAN alike.
    pub fn encode_response_at(
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

#[cfg(test)]
mod tests {
    use alloc::vec;

    const SERVICE_ECHO: u8 = 2;
    const SERVICE_STATUS: u8 = 3;
    const SERVICE_METRICS: u8 = 6;
    use super::*;
    use crate::{ConnectionId, ConnectionLimits, FIRST_CLIENT_BIDI_STREAM_ID, Role};

    #[test]
    fn persistent_mux_reassembles_multiple_streams_and_exposes_metrics() {
        let mut client =
            StreamMux::<8, 8>::new(Role::Client, ConnectionLimits::default(), 1200, 8, 8, 4096);
        let mut server =
            StreamMux::<8, 8>::new(Role::Server, ConnectionLimits::default(), 1200, 8, 8, 4096);
        let c = ConnectionId::new(41).unwrap();
        let s = ConnectionId::new(42).unwrap();
        client.install_connection_ids(c, s).unwrap();
        server.install_connection_ids(s, c).unwrap();
        let mut next_stream = FIRST_CLIENT_BIDI_STREAM_ID;
        for _ in 0..3 {
            client
                .endpoint
                .open_send_stream(next_stream, crate::INITIAL_MAX_STREAM_DATA)
                .unwrap();
            let request = [SERVICE_METRICS];
            let mut packet = [0u8; 256];
            let (used, _) = client
                .endpoint
                .encode_stream_packet(s, next_stream, 0, true, &request, &mut packet)
                .unwrap();
            let response = server.receive_datagram(&packet[..used]).unwrap().unwrap();
            assert_eq!(response.stream_id, next_stream);
            assert_eq!(response.data, request);
            next_stream += 4;
        }
        assert_eq!(server.pending_streams(), 0);
    }

    #[test]
    fn persistent_mux_reassembles_out_of_order_fragments_once() {
        let mut client =
            StreamMux::<4, 4>::new(Role::Client, ConnectionLimits::default(), 1200, 8, 4, 1024);
        let mut server =
            StreamMux::<4, 4>::new(Role::Server, ConnectionLimits::default(), 1200, 8, 4, 1024);
        let c = ConnectionId::new(71).unwrap();
        let s = ConnectionId::new(72).unwrap();
        client.install_connection_ids(c, s).unwrap();
        server.install_connection_ids(s, c).unwrap();
        client
            .endpoint
            .open_send_stream(4, crate::INITIAL_MAX_STREAM_DATA)
            .unwrap();
        let mut packet = [0u8; 256];
        let (second_len, _) = client
            .endpoint
            .encode_stream_packet(s, 4, 4, true, b"ics", &mut packet)
            .unwrap();
        assert!(
            server
                .receive_datagram(&packet[..second_len])
                .unwrap()
                .is_none()
        );
        let (first_len, _) = client
            .endpoint
            .encode_stream_packet(
                s,
                4,
                0,
                false,
                &[SERVICE_ECHO, b'b', b'a', b'd'],
                &mut packet,
            )
            .unwrap();
        // The first fragment contains the service tag plus the first body
        // bytes; the second fragment completes the status request.
        let response = server
            .receive_datagram(&packet[..first_len])
            .unwrap()
            .unwrap();
        assert_eq!(
            response.data,
            [SERVICE_ECHO, b'b', b'a', b'd', b'i', b'c', b's']
        );
    }

    #[test]
    fn streamed_reorder_capacity_declines_packet_without_killing_connection() {
        let limits = ConnectionLimits {
            max_data: 32,
            max_stream_data: 32,
            ..ConnectionLimits::default()
        };
        let mut client = StreamMux::<4, 4>::new(Role::Client, limits, 1200, 8, 4, 32);
        let mut server = StreamMux::<4, 4>::new(Role::Server, limits, 1200, 8, 4, 4);
        let client_cid = ConnectionId::new(0x81).unwrap();
        let server_cid = ConnectionId::new(0x82).unwrap();
        client
            .install_connection_ids(client_cid, server_cid)
            .unwrap();
        server
            .install_connection_ids(server_cid, client_cid)
            .unwrap();
        client.endpoint.open_send_stream(8, 32).unwrap();

        let mut packet = [0u8; 128];
        let (tail, _) = client
            .endpoint
            .encode_stream_packet(server_cid, 8, 4, false, b"tail", &mut packet)
            .unwrap();
        assert!(
            server
                .receive_request_with_stream(&packet[..tail], 8, |_, _, bytes| Ok(bytes.len()))
                .unwrap()
                .is_none()
        );
        assert_eq!(server.endpoint.expected_packet_number(), 1);
        assert_eq!(server.ordered.retained_bytes(), 4);

        let (beyond, _) = client
            .endpoint
            .encode_stream_packet(server_cid, 8, 8, false, b"next", &mut packet)
            .unwrap();
        assert!(
            server
                .receive_request_with_stream(&packet[..beyond], 8, |_, _, bytes| Ok(bytes.len()))
                .unwrap()
                .is_none()
        );
        // The unretainable packet was deliberately not admitted or ACKed.
        assert_eq!(server.endpoint.expected_packet_number(), 1);
        assert_eq!(server.ordered.retained_bytes(), 4);

        let (head, _) = client
            .endpoint
            .encode_stream_packet(server_cid, 8, 0, false, b"head", &mut packet)
            .unwrap();
        let mut delivered = Vec::new();
        server
            .receive_request_with_stream(&packet[..head], 8, |_, _, bytes| {
                delivered.extend_from_slice(bytes);
                Ok(bytes.len())
            })
            .unwrap();
        assert_eq!(server.ordered.retained_bytes(), 0);
        assert_eq!(delivered, b"headtail");
        assert_eq!(server.endpoint.expected_packet_number(), 3);
    }

    #[test]
    fn consuming_stream_handler_drains_an_out_of_order_tail_and_credits_it_once() {
        let limits = ConnectionLimits {
            max_data: 32,
            max_stream_data: 32,
            ..ConnectionLimits::default()
        };
        let mut client = StreamMux::<4, 4>::new(Role::Client, limits, 1200, 8, 4, 32);
        let mut server = StreamMux::<4, 4>::new(Role::Server, limits, 1200, 8, 4, 32);
        let client_cid = ConnectionId::new(0x91).unwrap();
        let server_cid = ConnectionId::new(0x92).unwrap();
        client
            .install_connection_ids(client_cid, server_cid)
            .unwrap();
        server
            .install_connection_ids(server_cid, client_cid)
            .unwrap();
        client.endpoint.set_initial_peer_credit(32, 32).unwrap();
        client.endpoint.open_send_stream(8, 32).unwrap();

        let mut packet = [0u8; 128];
        let (tail, _) = client
            .endpoint
            .encode_stream_packet(server_cid, 8, 4, false, b"tail", &mut packet)
            .unwrap();
        let mut received = Vec::new();
        server
            .receive_request_with_consuming_stream(&packet[..tail], 8, |_, _, bytes| {
                received.extend_from_slice(bytes);
                Ok(bytes.len())
            })
            .unwrap();
        assert!(received.is_empty());
        assert_eq!(server.endpoint.receive_credit_state(8), Some((0, 0, 32)));

        let (head, _) = client
            .endpoint
            .encode_stream_packet(server_cid, 8, 0, false, b"head", &mut packet)
            .unwrap();
        server
            .receive_request_with_consuming_stream(&packet[..head], 8, |_, _, bytes| {
                received.extend_from_slice(bytes);
                Ok(bytes.len())
            })
            .unwrap();
        assert_eq!(received, b"headtail");
        assert_eq!(server.ordered.retained_bytes(), 0);
        assert_eq!(server.endpoint.receive_credit_state(8), Some((8, 8, 40)));
    }

    #[test]
    fn persistent_mux_interleaves_multiple_streams_without_cross_delivery() {
        let mut client =
            StreamMux::<8, 8>::new(Role::Client, ConnectionLimits::default(), 1200, 8, 8, 1024);
        let mut server =
            StreamMux::<8, 8>::new(Role::Server, ConnectionLimits::default(), 1200, 8, 8, 1024);
        let client_cid = ConnectionId::new(91).unwrap();
        let server_cid = ConnectionId::new(92).unwrap();
        client
            .install_connection_ids(client_cid, server_cid)
            .unwrap();
        server
            .install_connection_ids(server_cid, client_cid)
            .unwrap();
        let streams = [4_u64, 8, 12];
        let mut packet = [0_u8; 256];
        for stream in streams {
            client
                .endpoint
                .open_send_stream(stream, crate::INITIAL_MAX_STREAM_DATA)
                .unwrap();
            let (used, _) = client
                .endpoint
                .encode_stream_packet(
                    server_cid,
                    stream,
                    0,
                    false,
                    &[SERVICE_ECHO, b'\x10' + stream as u8],
                    &mut packet,
                )
                .unwrap();
            assert!(server.receive_datagram(&packet[..used]).unwrap().is_none());
        }
        assert_eq!(server.pending_streams(), streams.len());

        // Complete in reverse order. Each response must retain the originating
        // stream ID and body marker despite the interleaving.
        for stream in streams.into_iter().rev() {
            let (used, _) = client
                .endpoint
                .encode_stream_packet(server_cid, stream, 2, true, b"done", &mut packet)
                .unwrap();
            let response = server.receive_datagram(&packet[..used]).unwrap().unwrap();
            assert_eq!(response.stream_id, stream);
            assert_eq!(
                response.data,
                [SERVICE_ECHO, b'\x10' + stream as u8, b'd', b'o', b'n', b'e']
            );
        }
        assert_eq!(server.pending_streams(), 0);
    }

    #[test]
    fn persistent_mux_ignores_conflict_entirely_before_consumed_cursor() {
        let mut client =
            StreamMux::<4, 4>::new(Role::Client, ConnectionLimits::default(), 1200, 8, 4, 1024);
        let mut server =
            StreamMux::<4, 4>::new(Role::Server, ConnectionLimits::default(), 1200, 8, 4, 1024);
        let c = ConnectionId::new(81).unwrap();
        let s = ConnectionId::new(82).unwrap();
        client.install_connection_ids(c, s).unwrap();
        server.install_connection_ids(s, c).unwrap();
        client
            .endpoint
            .open_send_stream(4, crate::INITIAL_MAX_STREAM_DATA)
            .unwrap();
        let mut packet = [0u8; 256];
        let (first_len, _) = client
            .endpoint
            .encode_stream_packet(s, 4, 0, false, &[SERVICE_ECHO, b'a', b'b'], &mut packet)
            .unwrap();
        assert!(
            server
                .receive_request(&packet[..first_len])
                .unwrap()
                .is_none()
        );
        let received_before_conflict = server.endpoint.receive.received_data;
        let (conflict_len, _) = client
            .endpoint
            .encode_stream_packet(s, 4, 1, true, b"Z", &mut packet)
            .unwrap();
        assert!(
            server
                .receive_request(&packet[..conflict_len])
                .unwrap()
                .is_none()
        );
        assert_eq!(server.pending_streams(), 1);
        assert_eq!(
            server.endpoint.receive.received_data,
            received_before_conflict
        );
    }

    #[test]
    fn streamed_mux_immediately_reacks_a_fresh_packet_for_consumed_range() {
        let mut client =
            StreamMux::<4, 4, 256>::new(Role::Client, ConnectionLimits::default(), 256, 4, 1, 256);
        let mut server =
            StreamMux::<4, 4, 256>::new(Role::Server, ConnectionLimits::default(), 256, 4, 1, 256);
        let client_cid = ConnectionId::new(91).unwrap();
        let server_cid = ConnectionId::new(92).unwrap();
        client
            .install_connection_ids(client_cid, server_cid)
            .unwrap();
        server
            .install_connection_ids(server_cid, client_cid)
            .unwrap();
        client
            .endpoint
            .open_send_stream(8, crate::INITIAL_MAX_STREAM_DATA)
            .unwrap();
        let mut packet = [0_u8; 256];
        let mut ack = [0_u8; 256];
        let (first_len, _) = client
            .endpoint
            .encode_stream_packet(server_cid, 8, 0, false, b"range", &mut packet)
            .unwrap();
        let mut delivered = Vec::new();
        server
            .receive_request_with_stream(&packet[..first_len], 8, |_, _, bytes| {
                delivered.extend_from_slice(bytes);
                Ok(bytes.len())
            })
            .unwrap();
        assert_eq!(delivered, b"range");
        let _ = server.endpoint.poll_transmit(&mut ack).unwrap();

        let (retry_len, _) = client
            .endpoint
            .encode_stream_packet(server_cid, 8, 0, false, b"range", &mut packet)
            .unwrap();
        let mut duplicate_bytes = 0;
        server
            .receive_request_with_stream(&packet[..retry_len], 8, |_, _, bytes| {
                duplicate_bytes += bytes.len();
                Ok(bytes.len())
            })
            .unwrap();
        assert_eq!(duplicate_bytes, 0);
        assert!(server.endpoint.poll_transmit(&mut ack).unwrap().is_some());
    }

    #[test]
    fn persistent_mux_suppresses_duplicate_completed_stream() {
        let mut client =
            StreamMux::<4, 4>::new(Role::Client, ConnectionLimits::default(), 1200, 8, 4, 1024);
        let mut server =
            StreamMux::<4, 4>::new(Role::Server, ConnectionLimits::default(), 1200, 8, 4, 1024);
        let c = ConnectionId::new(91).unwrap();
        let s = ConnectionId::new(92).unwrap();
        client.install_connection_ids(c, s).unwrap();
        server.install_connection_ids(s, c).unwrap();
        client
            .endpoint
            .open_send_stream(4, crate::INITIAL_MAX_STREAM_DATA)
            .unwrap();
        let mut packet = [0u8; 256];
        let (used, _) = client
            .endpoint
            .encode_stream_packet(s, 4, 0, true, &[SERVICE_METRICS], &mut packet)
            .unwrap();
        let first = server.receive_datagram(&packet[..used]).unwrap();
        assert!(first.is_some());
        assert!(server.receive_datagram(&packet[..used]).unwrap().is_none());
        assert_eq!(server.pending_streams(), 0);
    }

    #[test]
    fn mux_delivers_multiple_stream_frames_from_one_datagram() {
        let mut server =
            StreamMux::<8, 8>::new(Role::Server, ConnectionLimits::default(), 1200, 8, 8, 1024);
        let client_cid = ConnectionId::new(101).unwrap();
        let server_cid = ConnectionId::new(102).unwrap();
        server
            .install_connection_ids(server_cid, client_cid)
            .unwrap();
        let mut packet = [0u8; 256];
        let mut used = crate::ShortHeader {
            flags: crate::FLAG_FIXED,
            dcid: server_cid,
            packet_number: 0,
            packet_number_len: 1,
        }
        .encode(&mut packet)
        .unwrap();
        used += crate::Frame::Stream(crate::StreamFrame {
            id: 4,
            offset: 0,
            fin: true,
            data: &[SERVICE_METRICS],
        })
        .encode(&mut packet[used..])
        .unwrap();
        used += crate::Frame::Stream(crate::StreamFrame {
            id: 8,
            offset: 0,
            fin: true,
            data: &[SERVICE_STATUS],
        })
        .encode(&mut packet[used..])
        .unwrap();
        let first = server.receive_datagram(&packet[..used]).unwrap().unwrap();
        assert_eq!(first.stream_id, 4);
        let second = server.receive_datagram(&packet[..used]).unwrap().unwrap();
        assert_eq!(second.stream_id, 8);
        assert!(server.receive_datagram(&packet[..used]).unwrap().is_none());
    }

    #[test]
    fn mux_stream_callback_keeps_command_and_object_stream_separate() {
        let mut server =
            StreamMux::<8, 8>::new(Role::Server, ConnectionLimits::default(), 1200, 8, 8, 1024);
        let client_cid = ConnectionId::new(111).unwrap();
        let server_cid = ConnectionId::new(112).unwrap();
        server
            .install_connection_ids(server_cid, client_cid)
            .unwrap();
        let mut packet = [0u8; 256];
        let mut used = crate::ShortHeader {
            flags: crate::FLAG_FIXED,
            dcid: server_cid,
            packet_number: 0,
            packet_number_len: 1,
        }
        .encode(&mut packet)
        .unwrap();
        used += crate::Frame::Stream(crate::StreamFrame {
            id: FIRST_CLIENT_BIDI_STREAM_ID,
            offset: 0,
            fin: true,
            data: &[SERVICE_STATUS],
        })
        .encode(&mut packet[used..])
        .unwrap();
        used += crate::Frame::Stream(crate::StreamFrame {
            id: FIRST_CLIENT_BIDI_STREAM_ID + 4,
            offset: 0,
            fin: true,
            data: b"object-records",
        })
        .encode(&mut packet[used..])
        .unwrap();

        let mut chunks = Vec::new();
        let request = server
            .receive_request_with_stream(
                &packet[..used],
                FIRST_CLIENT_BIDI_STREAM_ID + 4,
                |id, fin, bytes| {
                    chunks.push((id, fin, bytes.to_vec()));
                    Ok(bytes.len())
                },
            )
            .unwrap()
            .unwrap();
        assert_eq!(request.stream_id, FIRST_CLIENT_BIDI_STREAM_ID);
        assert_eq!(request.data, [SERVICE_STATUS]);
        assert_eq!(
            chunks,
            vec![(
                FIRST_CLIENT_BIDI_STREAM_ID + 4,
                true,
                b"object-records".to_vec()
            )]
        );
        assert_eq!(server.pending_streams(), 0);
    }

    #[test]
    fn streamed_sink_withholds_credit_until_storage_window_is_granted() {
        let limits = ConnectionLimits {
            max_data: 16,
            max_stream_data: 16,
            ..ConnectionLimits::default()
        };
        let mut client = StreamMux::<8, 8>::new(Role::Client, limits, 1200, 8, 8, 1024);
        let mut server = StreamMux::<8, 8>::new(Role::Server, limits, 1200, 8, 8, 1024);
        let client_cid = ConnectionId::new(121).unwrap();
        let server_cid = ConnectionId::new(122).unwrap();
        client
            .install_connection_ids(client_cid, server_cid)
            .unwrap();
        server
            .install_connection_ids(server_cid, client_cid)
            .unwrap();
        server.endpoint.set_ack_policy(1, 5);
        client.endpoint.set_initial_peer_credit(16, 16).unwrap();
        client.endpoint.open_send_stream(8, 16).unwrap();

        let mut packet = [0u8; 256];
        let (used, _) = client
            .endpoint
            .encode_stream_packet(server_cid, 8, 0, false, &[0x55; 16], &mut packet)
            .unwrap();
        let mut delivered = 0;
        server
            .receive_request_with_stream(&packet[..used], 8, |_, _, bytes| {
                delivered += bytes.len();
                Ok(bytes.len())
            })
            .unwrap();
        assert_eq!(delivered, 16);

        // ACKing receipt must not imply that application storage is free.
        let mut control = [0u8; 256];
        let ack_len = server
            .endpoint
            .poll_transmit(&mut control)
            .unwrap()
            .unwrap();
        client
            .endpoint
            .receive_datagram(&control[..ack_len])
            .unwrap();
        assert_eq!(
            client
                .endpoint
                .encode_stream_packet(server_cid, 8, 16, false, b"x", &mut packet),
            Err(Error::FlowControl)
        );

        server.endpoint.grant_receive_window(8, 16).unwrap();
        let grant_len = server
            .endpoint
            .poll_transmit(&mut control)
            .unwrap()
            .unwrap();
        client
            .endpoint
            .receive_datagram(&control[..grant_len])
            .unwrap();
        assert!(
            client
                .endpoint
                .encode_stream_packet(server_cid, 8, 16, false, b"x", &mut packet)
                .is_ok()
        );
    }

    #[test]
    fn streamed_sink_resumes_a_partial_prefix_and_publishes_only_consumed_credit() {
        let limits = ConnectionLimits {
            max_data: 16,
            max_stream_data: 16,
            ..ConnectionLimits::default()
        };
        let mut client = StreamMux::<8, 8>::new(Role::Client, limits, 1200, 8, 8, 1024);
        let mut server = StreamMux::<8, 8>::new(Role::Server, limits, 1200, 8, 8, 1024);
        let client_cid = ConnectionId::new(131).unwrap();
        let server_cid = ConnectionId::new(132).unwrap();
        client
            .install_connection_ids(client_cid, server_cid)
            .unwrap();
        server
            .install_connection_ids(server_cid, client_cid)
            .unwrap();
        client.endpoint.set_initial_peer_credit(16, 16).unwrap();
        client.endpoint.open_send_stream(8, 16).unwrap();
        let mut packet = [0u8; 256];
        let (used, _) = client
            .endpoint
            .encode_stream_packet(server_cid, 8, 0, false, b"abcdefgh", &mut packet)
            .unwrap();
        let mut received = Vec::new();
        server
            .receive_request_with_consuming_stream(&packet[..used], 8, |_, _, bytes| {
                received.extend_from_slice(&bytes[..4]);
                Ok(4)
            })
            .unwrap();
        assert_eq!(received, b"abcd");
        assert_eq!(server.endpoint.receive_credit_state(8), Some((4, 4, 20)));

        server
            .resume_consuming_request_stream(8, |_, _, bytes| {
                received.extend_from_slice(bytes);
                Ok(bytes.len())
            })
            .unwrap();
        assert_eq!(received, b"abcdefgh");
        assert_eq!(server.endpoint.receive_credit_state(8), Some((8, 8, 24)));
    }

    #[test]
    fn consuming_stream_credit_unblocks_the_peer_through_the_mux() {
        // Exercise the same persistent association boundary as the UDP object
        // sender: a full receive window is consumed by a stream callback,
        // then the peer receives only the mux's opaque ACK/MAX control packet.
        // No handler gets to parse or manufacture flow-control frames.
        let limits = ConnectionLimits {
            max_data: 16,
            max_stream_data: 16,
            ..ConnectionLimits::default()
        };
        let mut client = StreamMux::<8, 8>::new(Role::Client, limits, 1200, 8, 8, 1024);
        let mut server = StreamMux::<8, 8>::new(Role::Server, limits, 1200, 8, 8, 1024);
        let client_cid = ConnectionId::new(151).unwrap();
        let server_cid = ConnectionId::new(152).unwrap();
        client
            .install_connection_ids(client_cid, server_cid)
            .unwrap();
        server
            .install_connection_ids(server_cid, client_cid)
            .unwrap();
        client.endpoint.set_initial_peer_credit(16, 16).unwrap();
        client.endpoint.open_send_stream(8, 16).unwrap();

        let mut packet = [0u8; 256];
        let (used, _) = client
            .endpoint
            .encode_stream_packet(server_cid, 8, 0, false, b"0123456789abcdef", &mut packet)
            .unwrap();
        server
            .receive_request_with_consuming_stream(
                &packet[..used],
                8,
                |_, _, bytes| Ok(bytes.len()),
            )
            .unwrap();

        server.endpoint.set_time(server.endpoint.max_ack_delay_ms());
        let control_len = server.endpoint.poll_transmit(&mut packet).unwrap().unwrap();
        client.receive_request(&packet[..control_len]).unwrap();
        assert_eq!(client.endpoint.send.stream_credit(8), Some(32));
        assert!(
            client
                .endpoint
                .encode_stream_packet(server_cid, 8, 16, false, b"next", &mut packet)
                .is_ok()
        );
    }

    #[test]
    fn resumed_idle_consumer_observes_async_completion_without_credit() {
        let mut mux =
            StreamMux::<8, 8>::new(Role::Server, ConnectionLimits::default(), 1200, 8, 8, 1024);
        let local = ConnectionId::new(141).unwrap();
        let peer = ConnectionId::new(142).unwrap();
        mux.install_connection_ids(local, peer).unwrap();
        let before = mux.endpoint.receive_credit_state(8);
        let mut polls = 0;
        assert_eq!(
            mux.resume_consuming_request_stream(8, |stream, fin, bytes| {
                assert_eq!(stream, 8);
                assert!(!fin);
                assert!(bytes.is_empty());
                polls += 1;
                Ok(0)
            })
            .unwrap(),
            0
        );
        assert_eq!(polls, 1);
        assert_eq!(mux.endpoint.receive_credit_state(8), before);
    }

    #[test]
    fn mux_delivers_a_stream_piggybacked_with_control() {
        let client_cid = ConnectionId::new(41).unwrap();
        let server_cid = ConnectionId::new(42).unwrap();
        let mut server =
            StreamMux::<8, 8>::new(Role::Server, ConnectionLimits::default(), 1200, 8, 8, 4096);
        server
            .install_connection_ids(server_cid, client_cid)
            .unwrap();
        let mut packet = [0u8; 256];
        let mut used = crate::ShortHeader {
            flags: crate::FLAG_FIXED,
            dcid: server_cid,
            packet_number: 0,
            packet_number_len: 1,
        }
        .encode(&mut packet)
        .unwrap();
        used += crate::Frame::MaxData(64 * 1024)
            .encode(&mut packet[used..])
            .unwrap();
        used += crate::Frame::Stream(crate::StreamFrame {
            id: FIRST_CLIENT_BIDI_STREAM_ID,
            offset: 0,
            fin: true,
            data: &[SERVICE_STATUS],
        })
        .encode(&mut packet[used..])
        .unwrap();
        let request = server.receive_request(&packet[..used]).unwrap().unwrap();
        assert_eq!(request.stream_id, FIRST_CLIENT_BIDI_STREAM_ID);
        assert_eq!(request.data, [SERVICE_STATUS]);
    }
}
