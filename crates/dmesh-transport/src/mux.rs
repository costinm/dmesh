//! Bearer-neutral persistent stream multiplexer.
//!
//! A bearer feeds complete datagrams to [`StreamMux::receive_datagram`] and
//! encodes returned responses using [`StreamMux::encode_response`].  Socket,
//! radio, timer, and peer-address policy stays outside this module.

use crate::handlers::{EventRing, StreamRegistry, handle_stream_with_events};
use crate::{ConnectionId, EndpointState, Error, Role, TransportPacket};
use alloc::vec::Vec;

#[derive(Debug)]
struct PendingStream {
    id: u64,
    fragments: Vec<(u64, Vec<u8>)>,
    fin: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MuxResponse {
    pub stream_id: u64,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MuxRequest {
    pub stream_id: u64,
    pub data: Vec<u8>,
}

/// Persistent connection state plus bounded stream lifecycle management.
pub struct StreamMux<const N: usize, const H: usize = 16, const P: usize = 1400> {
    pub endpoint: EndpointState<N, H, P>,
    pub registry: StreamRegistry,
    pub events: EventRing,
    pending: Vec<PendingStream>,
    completed: Vec<u64>,
    max_pending_streams: usize,
    max_stream_bytes: usize,
}

impl<const N: usize, const H: usize, const P: usize> StreamMux<N, H, P> {
    pub fn new(
        role: Role,
        limits: crate::ConnectionLimits,
        max_datagram_size: u64,
        event_capacity: usize,
        max_pending_streams: usize,
        max_stream_bytes: usize,
    ) -> Self {
        Self::new_with_history_capacity(
            role,
            limits,
            max_datagram_size,
            event_capacity,
            max_pending_streams,
            max_stream_bytes,
            H,
        )
    }

    pub fn new_with_history_capacity(
        role: Role,
        limits: crate::ConnectionLimits,
        max_datagram_size: u64,
        event_capacity: usize,
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
            registry: StreamRegistry::default(),
            events: EventRing::new(event_capacity),
            pending: Vec::new(),
            completed: Vec::new(),
            max_pending_streams,
            max_stream_bytes,
        }
    }

    pub fn set_connection_ids(
        &mut self,
        local: ConnectionId,
        peer: ConnectionId,
    ) -> Result<(), Error> {
        self.endpoint.set_connection_ids(local, peer)
    }

    pub fn pending_streams(&self) -> usize {
        self.pending.len()
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
        let (header, header_len) = crate::ShortHeader::decode(input)?;
        // Validate the complete datagram before consulting or mutating mux
        // state. In particular, an ACK followed by a malformed trailing
        // frame must not advance stream/accounting state.
        EndpointState::<N, H, P>::validate_datagram(input)?;
        let mut offset = header_len;
        let mut parsed_stream = None;
        while offset < input.len() {
            let (frame, used) = crate::decode_frame(&input[offset..])?;
            if let crate::Frame::Stream(stream) = frame {
                if parsed_stream.is_some() {
                    return Err(Error::Invalid);
                }
                parsed_stream = Some(stream);
            }
            offset += used;
        }
        let Some(frame) = parsed_stream else {
            let _ = self.endpoint.receive_datagram(input)?;
            self.events
                .push(1, 0, header.packet_number as u64, input.len() as u64);
            return Ok(None);
        };
        // Check overlapping fragments before EndpointState accepts the frame.
        // This keeps a conflicting duplicate from consuming receive credit or
        // creating a stream slot before the mux rejects it.
        if !self.completed.contains(&frame.id) {
            if let Some(stream) = self.pending.iter().find(|stream| stream.id == frame.id) {
                for (existing_offset, existing_bytes) in &stream.fragments {
                    let start = (*existing_offset).max(frame.offset);
                    let end = (*existing_offset)
                        .saturating_add(existing_bytes.len() as u64)
                        .min(frame.offset.saturating_add(frame.data.len() as u64));
                    if start < end {
                        let existing_start = (start - *existing_offset) as usize;
                        let incoming_start = (start - frame.offset) as usize;
                        let overlap_len = (end - start) as usize;
                        if existing_bytes[existing_start..existing_start + overlap_len]
                            != frame.data[incoming_start..incoming_start + overlap_len]
                        {
                            return Err(Error::Invalid);
                        }
                    }
                }
            }
        }
        let packet = self.endpoint.receive_datagram(input)?;
        let TransportPacket::Stream { frame, .. } = packet else {
            return Ok(None);
        };
        // Stream IDs are single-use. Once a FIN-delimited request has been
        // delivered, retransmitted/duplicated packets for that stream must
        // still be acknowledged by the endpoint but never reach a handler a
        // second time. Keep this cache bounded with the same cap as pending
        // stream state.
        if self.completed.contains(&frame.id) {
            return Ok(None);
        }
        self.events.push(
            2,
            frame.id,
            header.packet_number as u64,
            frame.data.len() as u64,
        );
        let index =
            if let Some(index) = self.pending.iter().position(|stream| stream.id == frame.id) {
                index
            } else {
                if self.pending.len() >= self.max_pending_streams {
                    return Err(Error::StreamLimit);
                }
                self.pending.push(PendingStream {
                    id: frame.id,
                    fragments: Vec::new(),
                    fin: false,
                });
                self.pending.len() - 1
            };
        let stream = &mut self.pending[index];
        if stream
            .fragments
            .iter()
            .any(|(offset, bytes)| *offset == frame.offset && bytes.as_slice() == frame.data)
        {
            stream.fin |= frame.fin;
        } else {
            let total: usize = stream.fragments.iter().map(|(_, bytes)| bytes.len()).sum();
            if total.saturating_add(frame.data.len()) > self.max_stream_bytes {
                return Err(Error::FlowControl);
            }
            stream.fragments.push((frame.offset, frame.data.to_vec()));
            stream.fin |= frame.fin;
        }
        if !stream.fin {
            return Ok(None);
        }
        let Some((stream_id, data)) = assemble(stream)? else {
            return Ok(None);
        };
        self.pending.remove(index);
        if self.completed.len() >= self.max_pending_streams {
            self.completed.remove(0);
        }
        self.completed.push(stream_id);
        Ok(Some(MuxRequest { stream_id, data }))
    }

    pub fn complete_request(&mut self, stream_id: u64, bytes: usize) -> Result<(), Error> {
        self.endpoint.stream_consumed(stream_id, bytes)
    }

    /// Receive one datagram, reassemble stream fragments, and return a
    /// completed handler response when a stream reaches FIN.
    pub fn receive_datagram<'a>(&mut self, input: &'a [u8]) -> Result<Option<MuxResponse>, Error> {
        let packet_number = crate::ShortHeader::decode(input).map(|(h, _)| h.packet_number)?;
        let Some(request) = self.receive_request(input)? else {
            return Ok(None);
        };
        let stream_id = request.stream_id;
        let data = request.data;
        let service = *data.first().ok_or(Error::Invalid)?;
        let body = &data[1..];
        let connection = self
            .endpoint
            .local_connection_id()
            .or_else(|| self.endpoint.peer_connection_id())
            .ok_or(Error::WrongConnectionId)?;
        let response = handle_stream_with_events(
            &self.endpoint,
            Some(&self.events),
            connection,
            stream_id,
            &self.registry,
            service,
            body,
        )
        .map_err(|_| Error::Invalid)?;
        self.complete_request(stream_id, data.len())?;
        self.events
            .push(3, stream_id, packet_number as u64, response.len() as u64);
        Ok(Some(MuxResponse {
            stream_id,
            data: response,
        }))
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

fn assemble(stream: &PendingStream) -> Result<Option<(u64, Vec<u8>)>, Error> {
    let mut fragments: Vec<_> = stream.fragments.iter().collect();
    fragments.sort_by_key(|(offset, _)| *offset);
    let mut next = 0u64;
    let mut data = Vec::new();
    for (offset, bytes) in fragments {
        if *offset > next {
            return Ok(None);
        }
        let skip = next.saturating_sub(*offset) as usize;
        if skip < bytes.len() {
            data.extend_from_slice(&bytes[skip..]);
            next = next.saturating_add((bytes.len() - skip) as u64);
        }
    }
    Ok(Some((stream.id, data)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;
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
        client.set_connection_ids(c, s).unwrap();
        server.set_connection_ids(s, c).unwrap();
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
            assert!(
                core::str::from_utf8(&response.data)
                    .unwrap()
                    .contains("metrics_version=1")
            );
            assert!(
                core::str::from_utf8(&response.data)
                    .unwrap()
                    .contains("retained_payload_bytes=")
            );
            assert!(
                core::str::from_utf8(&response.data)
                    .unwrap()
                    .contains("history_storage_slots=")
            );
            next_stream += 4;
        }
        assert_eq!(server.pending_streams(), 0);
        assert_eq!(server.events.len(), 6);
    }

    #[test]
    fn persistent_mux_reassembles_out_of_order_fragments_once() {
        let mut client =
            StreamMux::<4, 4>::new(Role::Client, ConnectionLimits::default(), 1200, 8, 4, 1024);
        let mut server =
            StreamMux::<4, 4>::new(Role::Server, ConnectionLimits::default(), 1200, 8, 4, 1024);
        let c = ConnectionId::new(71).unwrap();
        let s = ConnectionId::new(72).unwrap();
        client.set_connection_ids(c, s).unwrap();
        server.set_connection_ids(s, c).unwrap();
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
        assert!(
            core::str::from_utf8(&response.data)
                .unwrap()
                .contains("service=2")
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
        client.set_connection_ids(client_cid, server_cid).unwrap();
        server.set_connection_ids(server_cid, client_cid).unwrap();

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
            let text = core::str::from_utf8(&response.data).unwrap();
            assert!(text.contains("service=2"));
            assert!(text.contains(&format!("stream_id={stream}")));
        }
        assert_eq!(server.pending_streams(), 0);
    }

    #[test]
    fn persistent_mux_rejects_conflicting_overlap() {
        let mut client =
            StreamMux::<4, 4>::new(Role::Client, ConnectionLimits::default(), 1200, 8, 4, 1024);
        let mut server =
            StreamMux::<4, 4>::new(Role::Server, ConnectionLimits::default(), 1200, 8, 4, 1024);
        let c = ConnectionId::new(81).unwrap();
        let s = ConnectionId::new(82).unwrap();
        client.set_connection_ids(c, s).unwrap();
        server.set_connection_ids(s, c).unwrap();
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
        assert_eq!(
            server.receive_request(&packet[..conflict_len]).unwrap_err(),
            Error::Invalid
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
        client.set_connection_ids(c, s).unwrap();
        server.set_connection_ids(s, c).unwrap();
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
}
