//! Ordered packet-backed stream delivery.
//!
//! The bearer owns the received datagram lease.  This module keeps ranges as
//! `(lease, range)` references and exposes either an asynchronous completion
//! API or a synchronous copying callback over the same ordering state.

use alloc::{sync::Arc, vec::Vec};
use core::ops::Range;

/// A reference-counted or pool-backed received packet. Cloning this value must
/// retain the packet, not copy its payload.
pub trait PacketLease: Clone {
    fn bytes(&self) -> &[u8];
}

impl<'a> PacketLease for &'a [u8] {
    fn bytes(&self) -> &[u8] {
        self
    }
}

impl PacketLease for Arc<Vec<u8>> {
    fn bytes(&self) -> &[u8] {
        self.as_slice()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StreamChunk<P: PacketLease> {
    pub stream: u64,
    pub offset: u64,
    pub end: bool,
    pub delivery_id: u64,
    pub packet: P,
    pub range: Range<usize>,
}

impl<P: PacketLease> StreamChunk<P> {
    pub fn bytes(&self) -> &[u8] {
        &self.packet.bytes()[self.range.clone()]
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StreamDone {
    pub stream: u64,
    pub delivery_id: u64,
}

pub trait StreamEvents<P: PacketLease> {
    fn stream_chunk(&mut self, chunk: StreamChunk<P>);
    fn stream_finished(&mut self, stream: u64);
    fn stream_reset(&mut self, stream: u64, code: u64);
}

pub trait CopyingStreamEvents {
    type Error;
    fn stream_chunk(
        &mut self,
        stream: u64,
        offset: u64,
        end: bool,
        bytes: &[u8],
    ) -> Result<(), Self::Error>;
    fn stream_finished(&mut self, _stream: u64) {}
    fn stream_reset(&mut self, _stream: u64, _code: u64) {}
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CallbackError {
    InvalidOverlap,
    InvalidFin,
    InvalidCompletion,
    Capacity,
    Reset,
}

#[derive(Debug)]
pub enum CopyingError<E> {
    Transport(CallbackError),
    Callback(E),
}

#[derive(Clone)]
struct Retained<P: PacketLease> {
    offset: u64,
    packet: P,
    range: Range<usize>,
    end: bool,
}

#[derive(Clone)]
struct OrderedStream<P: PacketLease> {
    id: u64,
    consumed: u64,
    final_size: Option<u64>,
    retained: Vec<Retained<P>>,
    outstanding: Option<(StreamDone, u64, bool, P)>,
    next_delivery: u64,
    finished: bool,
}

impl<P: PacketLease> OrderedStream<P> {
    fn new(id: u64) -> Self {
        Self {
            id,
            consumed: 0,
            final_size: None,
            retained: Vec::new(),
            outstanding: None,
            next_delivery: 1,
            finished: false,
        }
    }

    fn insert(
        &mut self,
        packet: P,
        offset: u64,
        range: Range<usize>,
        fin: bool,
    ) -> Result<(), CallbackError> {
        if range.start > range.end || range.end > packet.bytes().len() {
            return Err(CallbackError::InvalidOverlap);
        }
        let len = (range.end - range.start) as u64;
        let end = offset.checked_add(len).ok_or(CallbackError::InvalidFin)?;
        if let Some(final_size) = self.final_size {
            if end > final_size || (fin && end != final_size) {
                return Err(CallbackError::InvalidFin);
            }
        } else if fin {
            self.final_size = Some(end);
        }
        if end <= self.consumed && !(len == 0 && fin && offset == self.consumed) {
            // Packet-number retransmissions intentionally carry a fresh
            // number, so duplicate suppression cannot stop a stream range
            // that was already delivered and released. It is harmless here:
            // all of its bytes precede the ordered application cursor.
            return Ok(());
        }
        let trim = self.consumed.saturating_sub(offset) as usize;
        let range = (range.start + trim)..range.end;
        let offset = offset.saturating_add(trim as u64);
        let end = offset
            .checked_add(range.len() as u64)
            .ok_or(CallbackError::InvalidFin)?;
        if range.start == range.end && !fin {
            return Ok(());
        }
        for existing in &self.retained {
            let a0 = existing.offset;
            let a1 = a0 + (existing.range.end - existing.range.start) as u64;
            let b0 = offset;
            let b1 = end;
            let overlap_start = a0.max(b0);
            let overlap_end = a1.min(b1);
            if overlap_start < overlap_end {
                let al = (overlap_start - a0) as usize;
                let bl = (overlap_start - b0) as usize;
                let n = (overlap_end - overlap_start) as usize;
                if existing.packet.bytes()[existing.range.start + al..existing.range.start + al + n]
                    != packet.bytes()[range.start + bl..range.start + bl + n]
                {
                    return Err(CallbackError::InvalidOverlap);
                }
                // Exact retransmissions are handled below. Partial overlap
                // is rejected so retained-byte accounting remains exact and
                // no range is counted twice.
                if existing.offset != offset
                    || existing.range.len() != range.len()
                    || existing.range.start != range.start
                    || existing.range.end != range.end
                {
                    return Err(CallbackError::InvalidOverlap);
                }
            }
        }
        if self.retained.iter().any(|existing| {
            existing.offset == offset
                && existing.range.len() == range.len()
                && existing.packet.bytes()[existing.range.clone()] == packet.bytes()[range.clone()]
        }) {
            return Ok(());
        }
        self.retained.push(Retained {
            offset,
            packet,
            range,
            end: fin,
        });
        self.retained.sort_by_key(|item| item.offset);
        Ok(())
    }

    fn next_chunk(&mut self) -> Option<StreamChunk<P>> {
        if self.outstanding.is_some() || self.finished {
            return None;
        }
        let index = self
            .retained
            .iter()
            .position(|item| item.offset == self.consumed)?;
        let item = self.retained.remove(index);
        let len = item.range.len() as u64;
        let end = item.end || self.final_size == Some(self.consumed + len);
        let done = StreamDone {
            stream: self.id,
            delivery_id: self.next_delivery,
        };
        self.next_delivery = self.next_delivery.saturating_add(1);
        self.outstanding = Some((done, len, end, item.packet.clone()));
        Some(StreamChunk {
            stream: self.id,
            offset: self.consumed,
            end,
            delivery_id: done.delivery_id,
            packet: item.packet,
            range: item.range,
        })
    }

    fn done(&mut self, completion: StreamDone) -> Result<bool, CallbackError> {
        let Some((expected, len, end, _packet)) = self.outstanding.take() else {
            return Err(CallbackError::InvalidCompletion);
        };
        if expected != completion {
            self.outstanding = Some((expected, len, end, _packet));
            return Err(CallbackError::InvalidCompletion);
        }
        if end {
            if self.final_size != Some(self.consumed.saturating_add(len)) {
                self.outstanding = Some((expected, len, end, _packet));
                return Err(CallbackError::InvalidFin);
            }
        }
        self.consumed = self.consumed.saturating_add(len);
        if end {
            self.finished = true;
            return Ok(true);
        }
        Ok(false)
    }
}

/// Bounded ordered delivery state for one connection. The transport calls
/// `receive` after validating the complete datagram.
#[derive(Clone)]
pub struct CallbackStreams<P: PacketLease> {
    streams: Vec<OrderedStream<P>>,
    max_streams: usize,
    max_retained_bytes: usize,
    retained_bytes: usize,
}

impl<P: PacketLease> CallbackStreams<P> {
    pub fn new(max_streams: usize, max_retained_bytes: usize) -> Self {
        Self {
            streams: Vec::new(),
            max_streams,
            max_retained_bytes,
            retained_bytes: 0,
        }
    }

    fn stream_mut(&mut self, id: u64) -> Result<&mut OrderedStream<P>, CallbackError> {
        if let Some(index) = self.streams.iter().position(|stream| stream.id == id) {
            return Ok(&mut self.streams[index]);
        }
        if self.streams.len() >= self.max_streams {
            return Err(CallbackError::Capacity);
        }
        self.streams.push(OrderedStream::new(id));
        Ok(self.streams.last_mut().unwrap())
    }

    pub fn receive_leased<E: StreamEvents<P>>(
        &mut self,
        stream: u64,
        packet: P,
        offset: u64,
        range: Range<usize>,
        fin: bool,
        events: &mut E,
    ) -> Result<(), CallbackError> {
        let bytes = range.len();
        // A retransmission can arrive after the retained window is full. Do
        // not reject it before OrderedStream has identified it as an exact
        // duplicate; packet-number retransmission must not consume callback
        // storage a second time. Keep a cheap lease-only checkpoint only in
        // the near-capacity case so a genuinely new range can be rolled back.
        let checkpoint = (self.retained_bytes.saturating_add(bytes) > self.max_retained_bytes)
            .then(|| self.clone());
        let (chunk, added) = {
            let state = self.stream_mut(stream)?;
            let before = state.retained.len();
            state.insert(packet, offset, range, fin)?;
            let added = state.retained.len() != before;
            (state.next_chunk(), added)
        };
        if added {
            if self.retained_bytes.saturating_add(bytes) > self.max_retained_bytes {
                *self = checkpoint.expect("checkpoint exists above callback capacity");
                return Err(CallbackError::Capacity);
            }
            self.retained_bytes = self.retained_bytes.saturating_add(bytes);
        }
        if let Some(chunk) = chunk {
            events.stream_chunk(chunk);
        }
        Ok(())
    }

    pub fn receive_copying<E: CopyingStreamEvents>(
        &mut self,
        stream: u64,
        packet: P,
        offset: u64,
        range: Range<usize>,
        fin: bool,
        events: &mut E,
    ) -> Result<(), CopyingError<E::Error>> {
        let mut sink = CopyAdapter {
            events,
            error: None,
        };
        self.receive_leased(stream, packet, offset, range, fin, &mut sink)
            .map_err(CopyingError::Transport)?;
        if let Some(error) = sink.error.take() {
            sink.events.stream_reset(stream, 1);
            return Err(CopyingError::Callback(error));
        }
        loop {
            let Some(done) = self.outstanding(stream) else {
                break;
            };
            self.done(done, &mut sink)
                .map_err(CopyingError::Transport)?;
            if let Some(error) = sink.error.take() {
                sink.events.stream_reset(stream, 1);
                return Err(CopyingError::Callback(error));
            }
        }
        Ok(())
    }

    /// Deliver the common in-order case directly from the bearer's receive
    /// buffer. `retain` is evaluated only when ordering requires us to keep a
    /// packet beyond this callback. This keeps synchronous embedded users out
    /// of the allocator on their normal receive path while retaining the same
    /// bounded reordering behaviour as `receive_copying`.
    pub fn receive_copying_borrowed<E, F>(
        &mut self,
        stream: u64,
        bytes: &[u8],
        offset: u64,
        fin: bool,
        retain: F,
        events: &mut E,
    ) -> Result<(), CopyingError<E::Error>>
    where
        E: CopyingStreamEvents,
        F: FnOnce() -> P,
    {
        let len = bytes.len() as u64;
        let end = offset
            .checked_add(len)
            .ok_or(CopyingError::Transport(CallbackError::InvalidFin))?;
        let state = self.stream_mut(stream).map_err(CopyingError::Transport)?;

        // Only a packet exactly at the application cursor can be borrowed:
        // retained ranges must remain owned until their preceding gap closes.
        if !state.finished
            && state.outstanding.is_none()
            && state.retained.is_empty()
            && offset == state.consumed
        {
            if let Some(final_size) = state.final_size {
                if end > final_size || (fin && end != final_size) {
                    return Err(CopyingError::Transport(CallbackError::InvalidFin));
                }
            }
            if let Err(error) = events.stream_chunk(stream, offset, fin, bytes) {
                events.stream_reset(stream, 1);
                return Err(CopyingError::Callback(error));
            }
            if fin {
                state.final_size = Some(end);
            }
            state.consumed = end;
            if fin {
                state.finished = true;
                events.stream_finished(stream);
            }
            return Ok(());
        }

        self.receive_copying(stream, retain(), offset, 0..bytes.len(), fin, events)
    }

    pub fn done<E: StreamEvents<P>>(
        &mut self,
        completion: StreamDone,
        events: &mut E,
    ) -> Result<(), CallbackError> {
        let index = self
            .streams
            .iter()
            .position(|stream| stream.id == completion.stream)
            .ok_or(CallbackError::InvalidCompletion)?;
        let outstanding_len = self.streams[index]
            .outstanding
            .as_ref()
            .map(|value| value.1 as usize)
            .unwrap_or(0);
        let finished = self.streams[index].done(completion)?;
        self.retained_bytes = self.retained_bytes.saturating_sub(outstanding_len);
        if finished {
            events.stream_finished(completion.stream);
        }
        if self.streams[index].outstanding.is_none() {
            if let Some(chunk) = self.streams[index].next_chunk() {
                events.stream_chunk(chunk);
            }
        }
        Ok(())
    }

    pub fn outstanding(&self, stream: u64) -> Option<StreamDone> {
        self.streams
            .iter()
            .find(|state| state.id == stream)
            .and_then(|state| state.outstanding.as_ref().map(|value| value.0))
    }

    pub fn stream_count(&self) -> usize {
        self.streams
            .iter()
            .filter(|stream| !stream.finished)
            .count()
    }

    pub fn retained_bytes(&self) -> usize {
        self.retained_bytes
    }

    pub fn reset<E: StreamEvents<P>>(&mut self, stream: u64, code: u64, events: &mut E) {
        if let Some(state) = self.streams.iter_mut().find(|state| state.id == stream) {
            let retained = state
                .retained
                .iter()
                .map(|item| item.range.len())
                .sum::<usize>();
            let outstanding = state
                .outstanding
                .as_ref()
                .map(|item| item.1 as usize)
                .unwrap_or(0);
            self.retained_bytes = self.retained_bytes.saturating_sub(retained + outstanding);
            state.retained.clear();
            state.outstanding = None;
            state.finished = true;
            events.stream_reset(stream, code);
        }
    }
}

struct CopyAdapter<'a, E: CopyingStreamEvents> {
    events: &'a mut E,
    error: Option<E::Error>,
}

impl<'a, P: PacketLease, E: CopyingStreamEvents> StreamEvents<P> for CopyAdapter<'a, E> {
    fn stream_chunk(&mut self, chunk: StreamChunk<P>) {
        if self.error.is_none() {
            self.error = self
                .events
                .stream_chunk(chunk.stream, chunk.offset, chunk.end, chunk.bytes())
                .err();
        }
    }
    fn stream_finished(&mut self, stream: u64) {
        self.events.stream_finished(stream);
    }
    fn stream_reset(&mut self, stream: u64, code: u64) {
        self.events.stream_reset(stream, code);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{sync::Arc, vec};

    #[derive(Default)]
    struct LeaseSink {
        chunks: Vec<(u64, u64, bool, u64, *const u8, Vec<u8>)>,
        finished: Vec<u64>,
        reset: Vec<(u64, u64)>,
    }

    impl StreamEvents<Arc<Vec<u8>>> for LeaseSink {
        fn stream_chunk(&mut self, chunk: StreamChunk<Arc<Vec<u8>>>) {
            self.chunks.push((
                chunk.stream,
                chunk.offset,
                chunk.end,
                chunk.delivery_id,
                chunk.bytes().as_ptr(),
                chunk.bytes().to_vec(),
            ));
        }
        fn stream_finished(&mut self, stream: u64) {
            self.finished.push(stream);
        }
        fn stream_reset(&mut self, stream: u64, code: u64) {
            self.reset.push((stream, code));
        }
    }

    #[derive(Default)]
    struct CopySink {
        data: Vec<u8>,
        finished: Vec<u64>,
        reset: Vec<(u64, u64)>,
    }

    impl CopyingStreamEvents for CopySink {
        type Error = ();
        fn stream_chunk(
            &mut self,
            _stream: u64,
            _offset: u64,
            _end: bool,
            bytes: &[u8],
        ) -> Result<(), Self::Error> {
            self.data.extend_from_slice(bytes);
            Ok(())
        }
        fn stream_finished(&mut self, stream: u64) {
            self.finished.push(stream);
        }
        fn stream_reset(&mut self, stream: u64, code: u64) {
            self.reset.push((stream, code));
        }
    }

    #[test]
    fn leased_delivery_preserves_packet_memory_until_done() {
        let packet = Arc::new(b"abcdef".to_vec());
        let pointer = packet.as_ptr();
        let mut streams = CallbackStreams::new(4, 16);
        let mut sink = LeaseSink::default();
        streams
            .receive_leased(4, packet.clone(), 0, 1..4, true, &mut sink)
            .unwrap();
        assert_eq!(sink.chunks[0].5, b"bcd");
        assert_eq!(sink.chunks[0].4, unsafe { pointer.add(1) });
        assert!(streams.outstanding(4).is_some());
        streams
            .done(
                StreamDone {
                    stream: 4,
                    delivery_id: sink.chunks[0].3,
                },
                &mut sink,
            )
            .unwrap();
        assert_eq!(sink.finished, vec![4]);
        assert_eq!(Arc::strong_count(&packet), 1);
    }

    #[test]
    fn copying_delivery_completes_without_done_and_preserves_order() {
        let mut streams = CallbackStreams::new(4, 16);
        let mut sink = CopySink::default();
        streams
            .receive_copying(4, Arc::new(b"world".to_vec()), 0, 0..5, true, &mut sink)
            .unwrap();
        assert_eq!(sink.data, b"world");
        assert_eq!(sink.finished, vec![4]);
        assert!(streams.outstanding(4).is_none());
    }

    #[test]
    fn borrowed_copying_delivery_does_not_acquire_a_packet_lease_in_order() {
        let mut streams = CallbackStreams::<Arc<Vec<u8>>>::new(2, 16);
        let mut sink = CopySink::default();
        streams
            .receive_copying_borrowed(
                4,
                b"in-order",
                0,
                true,
                || panic!("in-order delivery must not retain a packet"),
                &mut sink,
            )
            .unwrap();
        assert_eq!(sink.data, b"in-order");
        assert_eq!(sink.finished, vec![4]);
        assert_eq!(streams.retained_bytes(), 0);
    }

    #[test]
    fn borrowed_copying_delivery_acquires_a_lease_only_for_reordering() {
        let mut streams = CallbackStreams::<Arc<Vec<u8>>>::new(2, 16);
        let mut sink = CopySink::default();
        let mut retained = false;
        streams
            .receive_copying_borrowed(
                4,
                b"tail",
                4,
                true,
                || {
                    retained = true;
                    Arc::new(b"tail".to_vec())
                },
                &mut sink,
            )
            .unwrap();
        assert!(retained);
        streams
            .receive_copying_borrowed(
                4,
                b"head",
                0,
                false,
                // A retained tail exists, so this gap-closing packet joins
                // the bounded queue and drains both ranges in order.
                || Arc::new(b"head".to_vec()),
                &mut sink,
            )
            .unwrap();
        assert_eq!(sink.data, b"headtail");
    }

    #[test]
    fn copying_delivery_is_ordered_and_duplicate_safe_under_reordering() {
        let mut streams = CallbackStreams::new(4, 32);
        let mut sink = CopySink::default();
        let tail = Arc::new(b"tail".to_vec());
        let head = Arc::new(b"head".to_vec());
        streams
            .receive_copying(7, tail, 4, 0..4, true, &mut sink)
            .unwrap();
        assert!(sink.data.is_empty());
        streams
            .receive_copying(7, head.clone(), 0, 0..4, false, &mut sink)
            .unwrap();
        assert_eq!(sink.data, b"headtail");
        // A retransmitted identical range is accepted but never delivered.
        streams
            .receive_copying(7, head, 0, 0..4, false, &mut sink)
            .unwrap();
        assert_eq!(sink.data, b"headtail");
        assert_eq!(sink.finished, vec![7]);
    }

    #[test]
    fn exact_retransmission_does_not_fail_when_callback_window_is_full() {
        let mut streams = CallbackStreams::new(2, 4);
        let mut sink = CopySink::default();
        let packet = Arc::new(b"tail".to_vec());
        streams
            .receive_copying(4, packet.clone(), 4, 0..4, false, &mut sink)
            .unwrap();
        assert_eq!(streams.retained_bytes(), 4);
        // This models a fresh-number transport retransmission of the same
        // stream range after the receiver's bounded reassembly is full.
        streams
            .receive_copying(4, packet, 4, 0..4, false, &mut sink)
            .unwrap();
        assert_eq!(streams.retained_bytes(), 4);
    }

    #[test]
    fn consumed_prefix_is_trimmed_before_new_suffix_delivery() {
        let mut streams = CallbackStreams::new(4, 32);
        let mut sink = CopySink::default();
        streams
            .receive_copying(9, Arc::new(b"abcd".to_vec()), 0, 0..4, false, &mut sink)
            .unwrap();
        let result =
            streams.receive_copying(9, Arc::new(b"wxyz".to_vec()), 2, 0..4, true, &mut sink);
        assert!(result.is_ok());
        assert_eq!(sink.data, b"abcdyz");
    }

    #[test]
    fn zero_length_fin_is_delivered_and_counts_outstanding_lease() {
        let mut streams = CallbackStreams::new(2, 1);
        let mut sink = LeaseSink::default();
        streams
            .receive_leased(3, Arc::new(Vec::new()), 0, 0..0, true, &mut sink)
            .unwrap();
        assert_eq!(sink.chunks.len(), 1);
        assert!(sink.chunks[0].2);
        assert_eq!(streams.retained_bytes(), 0);
        streams
            .done(
                StreamDone {
                    stream: 3,
                    delivery_id: sink.chunks[0].3,
                },
                &mut sink,
            )
            .unwrap();
        assert_eq!(sink.finished, vec![3]);
    }

    #[test]
    fn outstanding_lease_is_included_in_capacity_until_done() {
        let mut streams = CallbackStreams::new(2, 4);
        let mut sink = LeaseSink::default();
        streams
            .receive_leased(1, Arc::new(b"abcd".to_vec()), 0, 0..4, false, &mut sink)
            .unwrap();
        assert_eq!(streams.retained_bytes(), 4);
        assert!(matches!(
            streams.receive_leased(2, Arc::new(b"x".to_vec()), 0, 0..1, false, &mut sink),
            Err(CallbackError::Capacity)
        ));
        streams
            .done(
                StreamDone {
                    stream: 1,
                    delivery_id: sink.chunks[0].3,
                },
                &mut sink,
            )
            .unwrap();
        assert_eq!(streams.retained_bytes(), 0);
    }

    #[test]
    fn retransmission_spanning_consumed_prefix_delivers_only_new_suffix() {
        let mut streams = CallbackStreams::new(2, 16);
        let mut sink = CopySink::default();
        streams
            .receive_copying(5, Arc::new(b"abcd".to_vec()), 0, 0..2, false, &mut sink)
            .unwrap();
        streams
            .receive_copying(5, Arc::new(b"bcde".to_vec()), 1, 0..4, true, &mut sink)
            .unwrap();
        assert_eq!(sink.data, b"abcde");
        assert_eq!(sink.finished, vec![5]);
    }

    #[test]
    fn invalid_fin_does_not_drop_outstanding_chunk() {
        let mut state = OrderedStream::<Arc<Vec<u8>>>::new(11);
        state
            .insert(Arc::new(b"ab".to_vec()), 0, 0..2, true)
            .unwrap();
        let chunk = state.next_chunk().unwrap();
        assert_eq!(chunk.bytes(), b"ab");
        state.final_size = Some(99);
        let result = state.done(StreamDone {
            stream: 11,
            delivery_id: chunk.delivery_id,
        });
        assert_eq!(result, Err(CallbackError::InvalidFin));
        assert!(state.outstanding.is_some());
        assert_eq!(state.consumed, 0);
    }

    #[test]
    fn withheld_stream_completion_does_not_block_other_streams() {
        let mut streams = CallbackStreams::new(4, 32);
        let mut sink = LeaseSink::default();
        streams
            .receive_leased(4, Arc::new(b"one".to_vec()), 0, 0..3, true, &mut sink)
            .unwrap();
        streams
            .receive_leased(8, Arc::new(b"two".to_vec()), 0, 0..3, true, &mut sink)
            .unwrap();
        assert_eq!(sink.chunks.len(), 2);
        assert!(
            streams
                .done(
                    StreamDone {
                        stream: 8,
                        delivery_id: sink.chunks[1].3
                    },
                    &mut sink
                )
                .is_ok()
        );
        assert_eq!(sink.finished, vec![8]);
        assert!(
            streams
                .done(
                    StreamDone {
                        stream: 4,
                        delivery_id: 99
                    },
                    &mut sink
                )
                .is_err()
        );
    }
}
