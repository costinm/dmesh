//! Bearer-neutral persistent stream multiplexer.
//!
//! A bearer feeds complete datagrams to [`StreamMux::receive_datagram`] and
//! encodes returned responses using [`StreamMux::encode_response`].  Socket,
//! radio, timer, and peer-address policy stays outside this module.

use crate::callback::{CallbackStreams, CopyingError, CopyingStreamEvents};
use crate::{ConnectionId, EndpointState, Error, Role, TransportPacket};
use alloc::{sync::Arc, vec::Vec};

#[derive(Default)]
struct RequestCollector {
    stream: u64,
    data: Vec<u8>,
    finished: bool,
}

struct ValidationSink;

impl CopyingStreamEvents for ValidationSink {
    type Error = ();
    fn stream_chunk(
        &mut self,
        _stream: u64,
        _offset: u64,
        _end: bool,
        _bytes: &[u8],
    ) -> Result<(), Self::Error> {
        Ok(())
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
    ) -> Result<(), Self::Error> {
        self.stream = stream;
        self.data.extend_from_slice(bytes);
        Ok(())
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
        let lease = Arc::new(input.to_vec());
        let mut staged = self.ordered.clone();
        for frame in &parsed_streams {
            let start = frame.data.as_ptr() as usize - input.as_ptr() as usize;
            let mut sink = ValidationSink;
            staged
                .receive_copying(
                    frame.id,
                    lease.clone(),
                    frame.offset,
                    start..start + frame.data.len(),
                    frame.fin,
                    &mut sink,
                )
                .map_err(|_| Error::Invalid)?;
        }
        let packet = match self.endpoint.receive_datagram(input) {
            Ok(packet) => packet,
            Err(error) => return Err(error),
        };
        let TransportPacket::Stream { .. } = packet else {
            return Ok(None);
        };
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
            .encode_stream_packet(peer, stream_id, 0, fin, data, out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ConnectionId, ConnectionLimits, FIRST_CLIENT_BIDI_STREAM_ID, Role, SERVICE_METRICS,
    };

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
                &[crate::SERVICE_ECHO, b'b', b'a', b'd'],
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
            [crate::SERVICE_ECHO, b'b', b'a', b'd', b'i', b'c', b's']
        );
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
                    &[crate::SERVICE_ECHO, b'\x10' + stream as u8],
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
                [
                    crate::SERVICE_ECHO,
                    b'\x10' + stream as u8,
                    b'd',
                    b'o',
                    b'n',
                    b'e'
                ]
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
            .encode_stream_packet(
                s,
                4,
                0,
                false,
                &[crate::SERVICE_ECHO, b'a', b'b'],
                &mut packet,
            )
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
            .encode_stream_packet(s, 4, 0, true, &[crate::SERVICE_METRICS], &mut packet)
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
            data: &[crate::SERVICE_METRICS],
        })
        .encode(&mut packet[used..])
        .unwrap();
        used += crate::Frame::Stream(crate::StreamFrame {
            id: 8,
            offset: 0,
            fin: true,
            data: &[crate::SERVICE_STATUS],
        })
        .encode(&mut packet[used..])
        .unwrap();
        let first = server.receive_datagram(&packet[..used]).unwrap().unwrap();
        assert_eq!(first.stream_id, 4);
        let second = server.receive_datagram(&packet[..used]).unwrap().unwrap();
        assert_eq!(second.stream_id, 8);
        assert!(server.receive_datagram(&packet[..used]).unwrap().is_none());
    }
}
