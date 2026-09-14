//! Ordered throughput-probe stream implementation, independent of any bearer.

use alloc::{sync::Arc, vec::Vec};

use quic_lite::{
    DEFAULT_REORDER_CAPACITY_BYTES, Error, StreamFrame,
    callback::{CallbackError, CallbackStreams, CopyingError, CopyingStreamEvents},
};

/// Bounded producer for one server-initiated diagnostic stream.
///
/// The producer has no bearer, clock, socket, or task dependency. A caller
/// gives it the connection endpoint and an MTU-sized output buffer each time
/// its selected L2 path can accept another datagram. `None` means normal
/// congestion/flow-control backpressure, not an error and not a reason to
/// block a firmware task.
pub struct ProbeSender {
    stream_id: u64,
    remaining: usize,
    chunk_size: usize,
    offset: u64,
    packet_id: u32,
}

impl ProbeSender {
    pub fn new(stream_id: u64, bytes: usize, chunk_size: usize) -> Option<Self> {
        if bytes == 0 || chunk_size < 4 {
            return None;
        }
        Some(Self {
            stream_id,
            remaining: bytes,
            chunk_size,
            offset: 0,
            packet_id: 0,
        })
    }

    pub fn is_complete(&self) -> bool {
        self.remaining == 0
    }

    pub fn bytes_sent(&self) -> u64 {
        self.offset
    }

    /// Produce at most one new fragment through the association-owned encoder.
    /// The return value is the packet length and FIN flag.  This producer
    /// deliberately never receives an endpoint: flow control, CIDs, and
    /// packet framing belong to QUIC-lite.
    pub fn poll<const P: usize>(
        &mut self,
        output: &mut [u8; P],
        mut encode: impl FnMut(u64, u64, bool, &[u8], &mut [u8; P]) -> Result<usize, Error>,
    ) -> Result<Option<(usize, bool)>, Error> {
        if self.remaining == 0 {
            return Ok(None);
        }
        let payload_len = self.remaining.min(self.chunk_size).min(P);
        if payload_len < 4 {
            return Err(Error::Invalid);
        }
        let mut payload = [0u8; P];
        payload[..4].copy_from_slice(&self.packet_id.to_be_bytes());
        for (index, byte) in payload[4..payload_len].iter_mut().enumerate() {
            *byte = self.offset.wrapping_add(4 + index as u64) as u8;
        }
        let fin = payload_len == self.remaining;
        let used = match encode(
            self.stream_id,
            self.offset,
            fin,
            &payload[..payload_len],
            output,
        ) {
            Ok(used) => used,
            Err(Error::FlowControl | Error::Invalid | Error::HistoryFull) => return Ok(None),
            Err(error) => return Err(error),
        };
        self.offset = self.offset.saturating_add(payload_len as u64);
        self.remaining -= payload_len;
        self.packet_id = self.packet_id.wrapping_add(1);
        Ok(Some((used, fin)))
    }
}

struct Sink<'a> {
    validation: u8,
    bytes: &'a mut u64,
    next_offset: &'a mut u64,
    next_packet_id: &'a mut u32,
    complete: &'a mut bool,
}

impl CopyingStreamEvents for Sink<'_> {
    type Error = ();

    fn stream_chunk(
        &mut self,
        _stream: u64,
        offset: u64,
        end: bool,
        bytes: &[u8],
    ) -> Result<usize, ()> {
        if self.validation >= 1 {
            let packet_id = bytes
                .get(..4)
                .and_then(|id| id.try_into().ok())
                .map(u32::from_be_bytes);
            if offset != *self.next_offset || packet_id != Some(*self.next_packet_id) {
                return Err(());
            }
            if self.validation >= 2
                && bytes[4..]
                    .iter()
                    .enumerate()
                    .any(|(i, byte)| *byte != self.next_offset.wrapping_add(4 + i as u64) as u8)
            {
                return Err(());
            }
            *self.next_packet_id = self.next_packet_id.wrapping_add(1);
        }
        *self.next_offset = self.next_offset.saturating_add(bytes.len() as u64);
        *self.bytes = self.bytes.saturating_add(bytes.len() as u64);
        *self.complete = end;
        Ok(bytes.len())
    }
}

/// Bounded in-order receiver for the diagnostic PROBE stream.
pub struct ProbeReceiver {
    ordered: CallbackStreams<Arc<Vec<u8>>>,
    validation: u8,
    bytes: u64,
    next_offset: u64,
    next_packet_id: u32,
    callback_errors: [u64; 6],
}

/// Bounded multi-stream PROBE run.
///
/// Stream placement, priority-stream completion, ordered validation, and byte
/// accounting are transport-test semantics rather than ESP, UDP, or socket
/// behavior.  Bearers feed committed stream frames here and use the returned
/// byte count to advance QUIC-lite flow control.
pub struct ProbeRun<const NORMAL: usize> {
    normal: [ProbeReceiver; NORMAL],
    high: ProbeReceiver,
    low: ProbeReceiver,
    normal_complete: [bool; NORMAL],
    high_complete: bool,
    low_complete: bool,
    normal_streams: usize,
    high_enabled: bool,
    low_enabled: bool,
}

impl<const NORMAL: usize> ProbeRun<NORMAL> {
    pub fn new(
        validation: u8,
        normal_streams: usize,
        high_enabled: bool,
        low_enabled: bool,
    ) -> Self {
        let normal_streams = normal_streams.clamp(1, NORMAL);
        Self {
            normal: core::array::from_fn(|_| ProbeReceiver::new(validation)),
            high: ProbeReceiver::new(validation),
            low: ProbeReceiver::new(validation),
            normal_complete: [false; NORMAL],
            high_complete: !high_enabled,
            low_complete: !low_enabled,
            normal_streams,
            high_enabled,
            low_enabled,
        }
    }

    /// Deliver one committed server-initiated stream frame. `first_stream` is
    /// normally `FIRST_SERVER_BIDI_STREAM_ID`; consecutive bidirectional
    /// stream IDs differ by four.
    pub fn handle(
        &mut self,
        first_stream: u64,
        stream: StreamFrame<'_>,
    ) -> Result<(bool, usize), ()> {
        let normal_index = stream
            .id
            .checked_sub(first_stream)
            .filter(|delta| *delta % 4 == 0)
            .map(|delta| (delta / 4) as usize)
            .filter(|index| *index < self.normal_streams);
        let high_stream = first_stream + 4 * self.normal_streams as u64;
        let low_stream = high_stream + 4;
        let (_complete, consumed) = if let Some(index) = normal_index {
            let result = self.normal[index].handle(stream)?;
            if result.0 {
                self.normal_complete[index] = true;
            }
            result
        } else if stream.id == high_stream && self.high_enabled {
            let result = self.high.handle(stream)?;
            if result.0 {
                self.high_complete = true;
            }
            result
        } else if stream.id == low_stream && self.low_enabled {
            let result = self.low.handle(stream)?;
            if result.0 {
                self.low_complete = true;
            }
            result
        } else {
            return Err(());
        };
        Ok((self.is_complete(), consumed))
    }

    pub fn is_complete(&self) -> bool {
        self.normal_complete[..self.normal_streams]
            .iter()
            .all(|complete| *complete)
            && self.high_complete
            && self.low_complete
    }

    pub fn normal_bytes(&self) -> u64 {
        self.normal[..self.normal_streams]
            .iter()
            .map(ProbeReceiver::bytes)
            .sum()
    }

    pub fn high_bytes(&self) -> u64 {
        self.high.bytes()
    }
    pub fn low_bytes(&self) -> u64 {
        self.low.bytes()
    }
    pub fn bytes(&self) -> u64 {
        self.normal_bytes()
            .saturating_add(self.high_bytes())
            .saturating_add(self.low_bytes())
    }

    pub fn callback_errors(&self) -> [u64; 6] {
        let mut totals = [0u64; 6];
        for receiver in self.normal[..self.normal_streams]
            .iter()
            .chain(core::iter::once(&self.high))
            .chain(core::iter::once(&self.low))
        {
            for (total, value) in totals.iter_mut().zip(receiver.callback_errors()) {
                *total = (*total).saturating_add(*value);
            }
        }
        totals
    }
}

impl ProbeReceiver {
    pub fn new(validation: u8) -> Self {
        Self {
            ordered: CallbackStreams::new(1, DEFAULT_REORDER_CAPACITY_BYTES),
            validation,
            bytes: 0,
            next_offset: 0,
            next_packet_id: 0,
            callback_errors: [0; 6],
        }
    }
    pub fn bytes(&self) -> u64 {
        self.bytes
    }
    pub fn callback_errors(&self) -> &[u64; 6] {
        &self.callback_errors
    }
    pub fn handle(&mut self, stream: StreamFrame<'_>) -> Result<(bool, usize), ()> {
        let mut complete = false;
        let before = self.bytes;
        let mut sink = Sink {
            validation: self.validation,
            bytes: &mut self.bytes,
            next_offset: &mut self.next_offset,
            next_packet_id: &mut self.next_packet_id,
            complete: &mut complete,
        };
        if let Err(error) = self.ordered.receive_copying_borrowed(
            stream.id,
            stream.data,
            stream.offset,
            stream.fin,
            || Arc::new(stream.data.to_vec()),
            &mut sink,
        ) {
            let index = match error {
                CopyingError::Transport(CallbackError::InvalidOverlap) => 0,
                CopyingError::Transport(CallbackError::InvalidFin) => 1,
                CopyingError::Transport(CallbackError::InvalidCompletion) => 2,
                CopyingError::Transport(CallbackError::Capacity) => 3,
                CopyingError::Transport(CallbackError::Reset) => 4,
                CopyingError::Callback(()) => 5,
            };
            self.callback_errors[index] = self.callback_errors[index].saturating_add(1);
            return Err(());
        }
        Ok((complete, self.bytes.saturating_sub(before) as usize))
    }
}

#[cfg(test)]
mod tests {
    use super::{ProbeReceiver, ProbeRun, ProbeSender};
    use quic_lite::{
        ConnectionId, ConnectionLimits, EndpointState, Role, StreamFrame, TransportPacket,
    };

    #[test]
    fn validates_and_counts_one_complete_packet() {
        let mut receiver = ProbeReceiver::new(2);
        let packet = [0, 0, 0, 0, 4, 5, 6];
        assert_eq!(
            receiver.handle(StreamFrame {
                id: 3,
                offset: 0,
                fin: true,
                data: &packet,
            }),
            Ok((true, packet.len()))
        );
        assert_eq!(receiver.bytes(), packet.len() as u64);
    }

    #[test]
    fn rejects_bad_packet_sequence() {
        let mut receiver = ProbeReceiver::new(1);
        assert!(
            receiver
                .handle(StreamFrame {
                    id: 3,
                    offset: 0,
                    fin: true,
                    data: &[0, 0, 0, 1],
                })
                .is_err()
        );
        assert_eq!(receiver.callback_errors()[5], 1);
    }

    #[test]
    fn multi_stream_run_owns_priority_stream_mapping_and_completion() {
        let mut run = ProbeRun::<4>::new(0, 2, true, true);
        for id in [3, 7, 11, 15] {
            assert_eq!(
                run.handle(
                    3,
                    StreamFrame {
                        id,
                        offset: 0,
                        fin: true,
                        data: &[id as u8]
                    }
                ),
                Ok((id == 15, 1))
            );
        }
        assert!(run.is_complete());
        assert_eq!(run.normal_bytes(), 2);
        assert_eq!(run.high_bytes(), 1);
        assert_eq!(run.low_bytes(), 1);
    }

    #[test]
    fn sender_uses_ordered_payload_and_fin_without_a_bearer() {
        let client = ConnectionId::new(7).unwrap();
        let server = ConnectionId::new(8).unwrap();
        let mut sender_endpoint = EndpointState::<4, 8>::new(
            Role::Server,
            ConnectionLimits::default(),
            quic_lite::DEFAULT_MAX_DATAGRAM_SIZE as u64,
        );
        sender_endpoint
            .install_connection_ids(server, client)
            .unwrap();
        sender_endpoint
            .set_initial_peer_credit(16 * 1024, 16 * 1024)
            .unwrap();
        let mut receiver_endpoint = EndpointState::<4, 8>::new(
            Role::Client,
            ConnectionLimits::default(),
            quic_lite::DEFAULT_MAX_DATAGRAM_SIZE as u64,
        );
        receiver_endpoint
            .install_connection_ids(client, server)
            .unwrap();
        let mut sender = ProbeSender::new(3, 12, 8).unwrap();
        let mut wire = [0u8; quic_lite::DEFAULT_MAX_DATAGRAM_SIZE];
        let mut receiver = ProbeReceiver::new(2);
        let (first, first_fin) = sender
            .poll(&mut wire, |stream, offset, fin, payload, out| {
                let _ =
                    sender_endpoint.open_send_stream(stream, quic_lite::INITIAL_MAX_STREAM_DATA);
                sender_endpoint
                    .encode_stream_packet(client, stream, offset, fin, payload, out)
                    .map(|(used, _)| used)
            })
            .unwrap()
            .unwrap();
        assert!(!first_fin);
        let TransportPacket::Stream { frame, .. } =
            receiver_endpoint.receive_datagram(&wire[..first]).unwrap()
        else {
            panic!("stream packet");
        };
        assert_eq!(receiver.handle(frame), Ok((false, 8)));
        receiver_endpoint.stream_consumed(3, 8).unwrap();
        let (second, second_fin) = sender
            .poll(&mut wire, |stream, offset, fin, payload, out| {
                let _ =
                    sender_endpoint.open_send_stream(stream, quic_lite::INITIAL_MAX_STREAM_DATA);
                sender_endpoint
                    .encode_stream_packet(client, stream, offset, fin, payload, out)
                    .map(|(used, _)| used)
            })
            .unwrap()
            .unwrap();
        assert!(second_fin);
        let TransportPacket::Stream { frame, .. } =
            receiver_endpoint.receive_datagram(&wire[..second]).unwrap()
        else {
            panic!("stream packet");
        };
        assert_eq!(receiver.handle(frame), Ok((true, 4)));
        assert!(sender.is_complete());
        assert_eq!(sender.bytes_sent(), 12);
    }
}
