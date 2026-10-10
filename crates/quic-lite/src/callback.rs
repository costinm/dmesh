//! Ordered packet-backed stream delivery.
//!
//! The bearer owns the received packet lease.  This module keeps ranges as
//! `(lease, range)` references and exposes either an asynchronous completion
//! API or a synchronous copying callback over the same ordering state.
//! Currently callbacks are ordered, so the chunk at `offset == 0` is also the
//! new-stream notification. A future explicitly out-of-order delivery mode may
//! require a separate lifecycle signal, but the ordered API does not pay for
//! that extra callback.

use alloc::{sync::Arc, vec::Vec};
use core::ops::Range;
use smallvec::SmallVec;

/// A reference-counted or pool-backed received packet. Cloning this value must
/// retain the packet, not copy its payload.
pub trait PacketLease: Clone {
    /// Borrow the complete immutable storage retained by this lease.
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
/// One ordered stream range whose packet lease remains owned by the receiver.
///
/// This is public for allocation-sensitive no-std consumers that defer
/// processing without copying packet bytes; host Tokio users receive owned
/// stream chunks from the higher-level API instead.
pub struct StreamChunk<P: PacketLease> {
    /// QUIC stream identifier within the association.
    pub stream: u64,
    /// Byte offset of the first byte in this chunk.
    pub offset: u64,
    /// Whether this range reaches the peer's final stream size.
    pub end: bool,
    /// Opaque token supplied back through [`CallbackStreams::done`].
    pub delivery_id: u64,
    /// Retained packet storage containing this stream range.
    pub packet: P,
    /// Byte range within `packet` containing application data.
    pub range: Range<usize>,
}

impl<P: PacketLease> StreamChunk<P> {
    /// Borrow only the application bytes selected by this chunk.
    pub fn bytes(&self) -> &[u8] {
        &self.packet.bytes()[self.range.clone()]
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Completion token for a leased stream chunk.
pub struct StreamDone {
    /// Stream whose outstanding chunk has finished processing.
    pub stream: u64,
    /// Exact delivery generation being completed.
    pub delivery_id: u64,
}

/// Deferred, zero-copy stream delivery callbacks for no-std integrations.
pub trait StreamEvents<P: PacketLease> {
    /// Deliver the next ordered retained chunk.
    fn stream_chunk(&mut self, chunk: StreamChunk<P>);
    /// Report that ordered delivery reached FIN.
    fn stream_finished(&mut self, stream: u64);
    /// Report that delivery terminated with an application error code.
    fn stream_reset(&mut self, stream: u64, code: u64);
}

/// Synchronous stream consumer which may copy or process bytes immediately.
pub(crate) trait CopyingStreamEvents {
    /// Application callback failure type.
    type Error;
    /// Consume bytes and return the number accepted from the front of `bytes`.
    fn stream_chunk(
        &mut self,
        stream: u64,
        offset: u64,
        end: bool,
        bytes: &[u8],
    ) -> Result<usize, Self::Error>;
    /// Report successful ordered completion; default is no action.
    fn stream_finished(&mut self, _stream: u64) {}
    /// Report a stream reset; default is no action.
    fn stream_reset(&mut self, _stream: u64, _code: u64) {}
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Invalid ordering, completion, or storage state in callback delivery.
pub enum CallbackError {
    /// A new range overlaps retained data without being an exact duplicate.
    InvalidOverlap,
    /// Conflicting FIN ranges imply different final sizes.
    InvalidFin,
    /// Completion does not match the currently outstanding chunk.
    InvalidCompletion,
    /// Configured stream or retained-byte capacity is exhausted.
    Capacity,
}

#[derive(Debug)]
/// Distinguishes callback failure from QUIC-lite delivery-state failure.
pub(crate) enum CopyingError<E> {
    /// Ordered delivery state rejected the operation.
    Transport(CallbackError),
    /// The application callback returned its own error.
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
        max_new_bytes: usize,
    ) -> Result<usize, CallbackError> {
        if range.start > range.end || range.end > packet.bytes().len() {
            return Err(CallbackError::InvalidOverlap);
        }
        let len = (range.end - range.start) as u64;
        let end = offset.checked_add(len).ok_or(CallbackError::InvalidFin)?;
        if let Some(final_size) = self.final_size {
            if end > final_size || (fin && end != final_size) {
                return Err(CallbackError::InvalidFin);
            }
        }
        if end <= self.consumed && !(len == 0 && fin && offset == self.consumed) {
            // Packet-number retransmissions intentionally carry a fresh
            // number, so duplicate suppression cannot stop a stream range
            // that was already delivered and released. It is harmless here:
            // all of its bytes precede the ordered application cursor.
            if fin {
                self.final_size = Some(end);
            }
            return Ok(0);
        }
        let trim = self.consumed.saturating_sub(offset) as usize;
        let range = (range.start + trim)..range.end;
        let offset = offset.saturating_add(trim as u64);
        let end = offset
            .checked_add(range.len() as u64)
            .ok_or(CallbackError::InvalidFin)?;
        if range.start == range.end && !fin {
            return Ok(0);
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
                if existing.offset != offset || existing.range.len() != range.len() {
                    return Err(CallbackError::InvalidOverlap);
                }
            }
        }
        if self.retained.iter().any(|existing| {
            existing.offset == offset
                && existing.range.len() == range.len()
                && existing.packet.bytes()[existing.range.clone()] == packet.bytes()[range.clone()]
        }) {
            if fin {
                self.final_size = Some(end);
            }
            return Ok(0);
        }
        if range.len() > max_new_bytes {
            return Err(CallbackError::Capacity);
        }
        // This is the bounded receive ledger shared by every bearer. Firmware
        // must turn heap pressure into normal transport backpressure, never a
        // Rust allocation abort while an application handler is active.
        self.retained
            .try_reserve(1)
            .map_err(|_| CallbackError::Capacity)?;
        let bytes = range.len();
        let position = self.retained.partition_point(|item| item.offset <= offset);
        self.retained.insert(
            position,
            Retained {
                offset,
                packet,
                range,
                end: fin,
            },
        );
        if fin {
            self.final_size = Some(end);
        }
        Ok(bytes)
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

/// Retained-byte ceiling for ordered delivery on one association.
///
/// A consumer may accept only a prefix of a chunk (or nothing), and the
/// remainder is retained without granting receive credit. Connection flow
/// control bounds unconsumed bytes by the advertised `max_data` window, so a
/// ceiling at least that large means an admitted packet can always be
/// retained. A smaller ceiling would let a packet be acknowledged and then
/// fail retention, losing data the peer will never resend. This is a ceiling,
/// not a preallocation.
pub(crate) fn retention_for_receive_window(
    limits: crate::ConnectionLimits,
    minimum: usize,
) -> usize {
    usize::try_from(limits.max_data)
        .unwrap_or(usize::MAX)
        .max(minimum)
}

/// Size-limited ordered delivery state for one connection. The transport calls
/// `receive` after validating the complete packet and suppresses frames whose
/// receive side is already complete. Stream retirement belongs to the endpoint;
/// this helper retains only live ordering and backpressure state.
#[derive(Clone)]
pub struct CallbackStreams<P: PacketLease> {
    streams: Vec<OrderedStream<P>>,
    max_streams: usize,
    max_retained_bytes: usize,
    retained_bytes: usize,
}

impl<P: PacketLease> CallbackStreams<P> {
    pub(crate) fn delivery_finished(&self, stream: u64) -> bool {
        self.streams
            .iter()
            .any(|state| state.id == stream && state.finished)
    }
    /// Create ordered delivery state with explicit stream and retained-byte limits.
    pub fn new(max_streams: usize, max_retained_bytes: usize) -> Self {
        Self {
            streams: Vec::new(),
            max_streams,
            max_retained_bytes,
            retained_bytes: 0,
        }
    }

    /// Replace future admission ceilings without discarding retained stream
    /// state. Values below current use take effect as that state drains.
    pub(crate) fn set_limits(&mut self, max_streams: usize, max_retained_bytes: usize) {
        self.max_streams = max_streams;
        self.max_retained_bytes = max_retained_bytes;
    }

    #[cfg(test)]
    pub(crate) const fn limits(&self) -> (usize, usize) {
        (self.max_streams, self.max_retained_bytes)
    }

    /// Validate the stream identities and final sizes carried by one packet
    /// without cloning or mutating retained delivery state.
    pub(crate) fn validate_packet_frames(
        &self,
        frames: impl IntoIterator<Item = (u64, u64, usize, bool)>,
    ) -> Result<(), CallbackError> {
        let mut new_streams = SmallVec::<[u64; 4]>::new();
        let mut packet_finals = SmallVec::<[(u64, u64); 4]>::new();
        for (id, offset, len, fin) in frames {
            let end = offset
                .checked_add(len as u64)
                .ok_or(CallbackError::InvalidFin)?;
            let existing = self.streams.iter().find(|stream| stream.id == id);
            if existing.is_none() && !new_streams.contains(&id) {
                new_streams
                    .try_reserve(1)
                    .map_err(|_| CallbackError::Capacity)?;
                new_streams.push(id);
            }
            let known_final = existing.and_then(|stream| stream.final_size).or_else(|| {
                packet_finals
                    .iter()
                    .find_map(|(stream, size)| (*stream == id).then_some(*size))
            });
            if let Some(final_size) = known_final {
                if end > final_size || (fin && end != final_size) {
                    return Err(CallbackError::InvalidFin);
                }
            } else if fin {
                packet_finals
                    .try_reserve(1)
                    .map_err(|_| CallbackError::Capacity)?;
                packet_finals.push((id, end));
            }
        }
        if self.streams.len().saturating_add(new_streams.len()) > self.max_streams {
            return Err(CallbackError::Capacity);
        }
        Ok(())
    }

    pub(crate) fn retention_may_exceed(&self, additional_bytes: usize) -> bool {
        self.retained_bytes.saturating_add(additional_bytes) > self.max_retained_bytes
    }

    fn stream_mut(&mut self, id: u64) -> Result<&mut OrderedStream<P>, CallbackError> {
        self.streams.retain(|stream| !stream.finished);
        if let Some(index) = self.streams.iter().position(|stream| stream.id == id) {
            return Ok(&mut self.streams[index]);
        }
        if self.streams.len() >= self.max_streams {
            return Err(CallbackError::Capacity);
        }
        self.streams
            .try_reserve(1)
            .map_err(|_| CallbackError::Capacity)?;
        self.streams.push(OrderedStream::new(id));
        Ok(self.streams.last_mut().unwrap())
    }

    fn insert_range(
        &mut self,
        stream: u64,
        packet: P,
        offset: u64,
        range: Range<usize>,
        fin: bool,
        available: usize,
    ) -> Result<usize, CallbackError> {
        self.streams.retain(|state| !state.finished);
        if let Some(state) = self.streams.iter_mut().find(|state| state.id == stream) {
            return state.insert(packet, offset, range, fin, available);
        }
        if self.streams.len() >= self.max_streams {
            return Err(CallbackError::Capacity);
        }
        // Refusal must not consume a stream slot. Build its state locally,
        // then publish it only after both payload and metadata admission.
        let mut state = OrderedStream::new(stream);
        let bytes = state.insert(packet, offset, range, fin, available)?;
        self.streams
            .try_reserve(1)
            .map_err(|_| CallbackError::Capacity)?;
        self.streams.push(state);
        Ok(bytes)
    }

    /// Insert one retained packet range and emit the next ordered leased chunk.
    pub fn receive_leased<E: StreamEvents<P>>(
        &mut self,
        stream: u64,
        packet: P,
        offset: u64,
        range: Range<usize>,
        fin: bool,
        events: &mut E,
    ) -> Result<(), CallbackError> {
        // Insertion identifies duplicates before checking new storage. No
        // deep delivery-state checkpoint is needed to refuse a new range.
        let available = self.max_retained_bytes.saturating_sub(self.retained_bytes);
        let bytes = self.insert_range(stream, packet, offset, range, fin, available)?;
        let chunk = self.stream_mut(stream)?.next_chunk();
        self.retained_bytes = self.retained_bytes.saturating_add(bytes);
        if let Some(chunk) = chunk {
            events.stream_chunk(chunk);
        }
        Ok(())
    }

    /// Insert one packet range and synchronously drain available ordered bytes.
    pub(crate) fn receive_copying<E: CopyingStreamEvents>(
        &mut self,
        stream: u64,
        packet: P,
        offset: u64,
        range: Range<usize>,
        fin: bool,
        events: &mut E,
    ) -> Result<(), CopyingError<E::Error>> {
        if range.start > range.end || range.end > packet.bytes().len() {
            return Err(CopyingError::Transport(CallbackError::InvalidOverlap));
        }
        // Immediate consumption needs no retained-byte reservation. An unread
        // suffix must pass the same admission as borrowed ingress.
        let directly_consumable =
            self.streams
                .iter()
                .find(|state| state.id == stream)
                .map_or(offset == 0, |state| {
                    !state.finished
                        && state.outstanding.is_none()
                        && offset == state.consumed
                        && !state
                            .retained
                            .iter()
                            .any(|item| item.offset == state.consumed)
                });
        if directly_consumable {
            return self.try_receive_copying_range(
                stream,
                &packet.bytes()[range.clone()],
                offset,
                fin,
                range.start,
                || Ok(packet.clone()),
                events,
            );
        }
        let available = self.max_retained_bytes.saturating_sub(self.retained_bytes);
        let bytes = self
            .insert_range(stream, packet, offset, range, fin, available)
            .map_err(CopyingError::Transport)?;
        self.retained_bytes = self.retained_bytes.saturating_add(bytes);
        self.resume_copying(stream, events)?;
        Ok(())
    }

    /// Deliver the common in-order case directly from the bearer's receive
    /// buffer. `retain` is evaluated only when ordering requires us to keep a
    /// packet beyond this callback. This keeps synchronous embedded users out
    /// of the allocator on their normal receive path while retaining the same
    /// bounded reordering behaviour as `receive_copying`.
    pub(crate) fn receive_copying_borrowed<E, F>(
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
        self.try_receive_copying_borrowed(stream, bytes, offset, fin, || Ok(retain()), events)
    }

    /// Fallible retention for owners which can refuse packet storage under
    /// memory pressure. Already consumed prefixes remain consumed on failure;
    /// the owner must leave newly received packets unacknowledged until all
    /// unread bytes have been retained or delivered.
    pub(crate) fn try_receive_copying_borrowed<E, F>(
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
        F: FnOnce() -> Result<P, CallbackError>,
    {
        self.try_receive_copying_range(stream, bytes, offset, fin, 0, retain, events)
    }

    fn try_receive_copying_range<E, F>(
        &mut self,
        stream: u64,
        bytes: &[u8],
        offset: u64,
        fin: bool,
        storage_offset: usize,
        retain: F,
        events: &mut E,
    ) -> Result<(), CopyingError<E::Error>>
    where
        E: CopyingStreamEvents,
        F: FnOnce() -> Result<P, CallbackError>,
    {
        let len = bytes.len() as u64;
        let end = offset
            .checked_add(len)
            .ok_or(CopyingError::Transport(CallbackError::InvalidFin))?;
        let retained_before = self.retained_bytes;
        let retention_limit = self.max_retained_bytes;
        let state = self.stream_mut(stream).map_err(CopyingError::Transport)?;

        // Only a packet exactly at the application cursor can be borrowed:
        // retained ranges must remain owned until their preceding gap closes.
        if !state.finished
            && state.outstanding.is_none()
            && offset == state.consumed
            && !state
                .retained
                .iter()
                .any(|item| item.offset == state.consumed)
        {
            if let Some(final_size) = state.final_size {
                if end > final_size || (fin && end != final_size) {
                    return Err(CopyingError::Transport(CallbackError::InvalidFin));
                }
            }
            let consumed = match events.stream_chunk(stream, offset, fin, bytes) {
                Ok(consumed) if consumed <= bytes.len() => consumed,
                Ok(_) => return Err(CopyingError::Transport(CallbackError::InvalidOverlap)),
                Err(error) => {
                    events.stream_reset(stream, 1);
                    return Err(CopyingError::Callback(error));
                }
            };
            if consumed != bytes.len() {
                // The handler may stop exactly at a storage boundary. Keep
                // only the unread suffix under QUIC-lite ordering ownership;
                // never materialize a dispatcher-private fragment queue.
                state.consumed = offset + consumed as u64;
                let retained = bytes.len().saturating_sub(consumed);
                if retained_before.saturating_add(retained) > retention_limit {
                    return Err(CopyingError::Transport(CallbackError::Capacity));
                }
                let packet = retain().map_err(CopyingError::Transport)?;
                let retained = state
                    .insert(
                        packet,
                        offset + consumed as u64,
                        (storage_offset + consumed)..(storage_offset + bytes.len()),
                        fin,
                        retention_limit.saturating_sub(retained_before),
                    )
                    .map_err(CopyingError::Transport)?;
                self.retained_bytes = self.retained_bytes.saturating_add(retained);
                return Ok(());
            }
            if fin {
                state.final_size = Some(end);
            }
            state.consumed = end;
            if fin {
                state.finished = true;
                events.stream_finished(stream);
                self.streams.retain(|state| state.id != stream);
                return Ok(());
            }
            // A borrowed prefix may close a gap in already retained ranges.
            // Drain those ordinary ordered ranges now when the consumer took
            // the full prefix, preserving the historical copying behaviour.
            // Established in-order traffic has no retained fragments. Avoid
            // another stream lookup and the reorder-drain path per packet.
            if !state.retained.is_empty() {
                self.resume_copying(stream, events)?;
            }
            return Ok(());
        }

        self.receive_copying(
            stream,
            retain().map_err(CopyingError::Transport)?,
            offset,
            storage_offset..(storage_offset + bytes.len()),
            fin,
            events,
        )
    }

    /// Resume an ordered copying consumer after application storage becomes
    /// ready.  A consumer that stopped part way through a borrowed packet
    /// leaves only its unread suffix here; this method redelivers that suffix
    /// without inventing a dispatcher- or handler-specific packet queue.
    pub(crate) fn resume_copying<E: CopyingStreamEvents>(
        &mut self,
        stream: u64,
        events: &mut E,
    ) -> Result<usize, CopyingError<E::Error>> {
        let mut total = 0usize;
        loop {
            let Some(index) = self.streams.iter().position(|state| state.id == stream) else {
                return Ok(total);
            };
            let state = &mut self.streams[index];
            if state.finished || state.outstanding.is_some() {
                return Ok(total);
            }
            let Some(item_index) = state
                .retained
                .iter()
                .position(|item| item.offset == state.consumed)
            else {
                return Ok(total);
            };
            let item = &state.retained[item_index];
            let bytes = &item.packet.bytes()[item.range.clone()];
            let consumed = match events.stream_chunk(stream, item.offset, item.end, bytes) {
                Ok(consumed) if consumed <= bytes.len() => consumed,
                Ok(_) => return Err(CopyingError::Transport(CallbackError::InvalidOverlap)),
                Err(error) => {
                    events.stream_reset(stream, 1);
                    return Err(CopyingError::Callback(error));
                }
            };
            // A zero-length FIN chunk carries no bytes to hold back, so it
            // cannot be refused: returning 0 accepts it, exactly as on the
            // borrowed ingress path. Treating it as "not accepted" would
            // re-deliver the same FIN on every resume.
            if consumed == 0 && !bytes.is_empty() {
                return Ok(total);
            }
            total = total.saturating_add(consumed);
            self.retained_bytes = self.retained_bytes.saturating_sub(consumed);
            state.consumed = state.consumed.saturating_add(consumed as u64);
            if consumed != bytes.len() {
                let retained = &mut state.retained[item_index];
                retained.offset = retained.offset.saturating_add(consumed as u64);
                retained.range.start += consumed;
                return Ok(total);
            }
            let item = state.retained.remove(item_index);
            if item.end {
                state.finished = true;
                events.stream_finished(stream);
                self.streams.remove(index);
                return Ok(total);
            }
        }
    }

    /// Release one outstanding leased chunk and deliver subsequent ordered data.
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
            self.streams.remove(index);
            return Ok(());
        }
        if self.streams[index].outstanding.is_none() {
            if let Some(chunk) = self.streams[index].next_chunk() {
                events.stream_chunk(chunk);
            }
        }
        Ok(())
    }

    /// Return the completion token for the chunk currently held by an application.
    pub fn outstanding(&self, stream: u64) -> Option<StreamDone> {
        self.streams
            .iter()
            .find(|state| state.id == stream)
            .and_then(|state| state.outstanding.as_ref().map(|value| value.0))
    }

    /// Number of streams which have not reached FIN or reset.
    pub fn stream_count(&self) -> usize {
        self.streams
            .iter()
            .filter(|stream| !stream.finished)
            .count()
    }

    /// Packet-backed application bytes retained for gaps or deferred completion.
    pub fn retained_bytes(&self) -> usize {
        self.retained_bytes
    }

    /// Drop retained state for one stream and notify the application.
    pub fn reset<E: StreamEvents<P>>(&mut self, stream: u64, code: u64, events: &mut E) {
        if let Some(index) = self.streams.iter().position(|state| state.id == stream) {
            let state = &mut self.streams[index];
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
            self.streams.remove(index);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owned_in_order_suffix_obeys_budget_and_preserves_packet_headroom() {
        for budget in [0, 4] {
            let mut streams = CallbackStreams::new(1, budget);
            let packet = Arc::new(b"XXabcdefZZ".to_vec());
            let mut prefix = PartialSink {
                data: Vec::new(),
                limit: 2,
                finished: Vec::new(),
            };
            let result = streams.receive_copying(7, packet.clone(), 0, 2..8, true, &mut prefix);
            assert_eq!(prefix.data, b"ab");
            assert!(prefix.finished.is_empty());
            if budget == 0 {
                assert!(matches!(
                    result,
                    Err(CopyingError::Transport(CallbackError::Capacity))
                ));
                assert_eq!(streams.retained_bytes(), 0);
            } else {
                result.unwrap();
                assert_eq!(streams.retained_bytes(), 4);
                let mut stopped = PartialSink {
                    data: Vec::new(),
                    limit: 0,
                    finished: Vec::new(),
                };
                streams
                    .receive_copying(7, packet.clone(), 0, 2..8, true, &mut stopped)
                    .unwrap();
                assert_eq!(
                    streams.retained_bytes(),
                    4,
                    "duplicate suffix counted twice"
                );
            }
            streams.set_limits(1, 4);
            let mut suffix = CopySink::default();
            streams
                .receive_copying(7, packet, 0, 2..8, true, &mut suffix)
                .unwrap();
            assert_eq!(suffix.data, b"cdef");
            assert_eq!(suffix.finished, vec![7]);
            assert_eq!(streams.retained_bytes(), 0);
        }
    }

    #[test]
    fn retained_insertion_needs_no_lease_checkpoint_and_refusal_is_atomic() {
        struct NoCheckpoint(&'static [u8]);
        impl Clone for NoCheckpoint {
            fn clone(&self) -> Self {
                panic!("retained insertion cloned a lease checkpoint")
            }
        }
        impl PacketLease for NoCheckpoint {
            fn bytes(&self) -> &[u8] {
                self.0
            }
        }
        let mut streams = CallbackStreams::new(1, 8);
        let mut sink = CopySink::default();
        for (offset, data) in [(4, &b"abcd"[..]), (8, &b"efgh"[..])] {
            streams
                .receive_copying(1, NoCheckpoint(data), offset, 0..4, false, &mut sink)
                .unwrap();
        }
        assert_eq!(streams.retained_bytes(), 8);
        // Exact duplicates fit even when no new byte may be retained.
        streams
            .receive_copying(1, NoCheckpoint(b"abcd"), 4, 0..4, false, &mut sink)
            .unwrap();
        assert!(matches!(
            streams.receive_copying(1, NoCheckpoint(b"ijkl"), 12, 0..4, true, &mut sink),
            Err(CopyingError::Transport(CallbackError::Capacity))
        ));
        assert_eq!(streams.retained_bytes(), 8);
        assert_eq!(streams.streams[0].final_size, None);
        assert_eq!(streams.streams[0].retained.len(), 2);
        assert!(sink.data.is_empty());
        // Closing the gap drains synchronous callbacks without cloning the
        // retained leases, even when their byte budget is completely full.
        streams
            .receive_copying(1, NoCheckpoint(b"head"), 0, 0..4, false, &mut sink)
            .unwrap();
        assert_eq!(sink.data, b"headabcdefgh");
        assert_eq!(streams.retained_bytes(), 0);

        let mut empty = CallbackStreams::new(1, 0);
        assert!(matches!(
            empty.receive_copying(2, NoCheckpoint(b"a"), 1, 0..1, true, &mut sink),
            Err(CopyingError::Transport(CallbackError::Capacity))
        ));
        assert!(
            empty.streams.is_empty(),
            "refused range consumed a stream slot"
        );
    }
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
        ) -> Result<usize, Self::Error> {
            self.data.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn stream_finished(&mut self, stream: u64) {
            self.finished.push(stream);
        }
        fn stream_reset(&mut self, stream: u64, code: u64) {
            self.reset.push((stream, code));
        }
    }

    struct PartialSink {
        data: Vec<u8>,
        limit: usize,
        finished: Vec<u64>,
    }

    impl CopyingStreamEvents for PartialSink {
        type Error = ();

        fn stream_chunk(
            &mut self,
            _stream: u64,
            _offset: u64,
            _end: bool,
            bytes: &[u8],
        ) -> Result<usize, Self::Error> {
            let count = bytes.len().min(self.limit);
            self.data.extend_from_slice(&bytes[..count]);
            Ok(count)
        }

        fn stream_finished(&mut self, stream: u64) {
            self.finished.push(stream);
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
    fn failed_retention_keeps_consumed_prefix_and_retries_only_suffix() {
        let mut streams = CallbackStreams::<Arc<Vec<u8>>>::new(2, 16);
        let mut sink = PartialSink {
            data: Vec::new(),
            limit: 2,
            finished: Vec::new(),
        };
        assert!(matches!(
            streams.try_receive_copying_borrowed(
                4,
                b"abcdef",
                0,
                true,
                || Err(CallbackError::Capacity),
                &mut sink,
            ),
            Err(CopyingError::Transport(CallbackError::Capacity))
        ));
        assert_eq!(sink.data, b"ab");
        assert_eq!(streams.retained_bytes(), 0);
        assert!(sink.finished.is_empty());
        sink.limit = usize::MAX;
        streams
            .try_receive_copying_borrowed(
                4,
                b"abcdef",
                0,
                true,
                || Ok(Arc::new(b"abcdef".to_vec())),
                &mut sink,
            )
            .unwrap();
        assert_eq!(
            sink.data, b"abcdef",
            "accepted prefix must not be delivered twice"
        );
        assert_eq!(sink.finished, vec![4]);
        assert_eq!(streams.retained_bytes(), 0);
    }

    #[test]
    fn failed_out_of_order_retention_is_retryable_and_in_order_needs_no_storage() {
        let mut streams = CallbackStreams::<Arc<Vec<u8>>>::new(2, 16);
        let mut sink = CopySink::default();
        assert!(matches!(
            streams.try_receive_copying_borrowed(
                4,
                b"def",
                3,
                true,
                || Err(CallbackError::Capacity),
                &mut sink,
            ),
            Err(CopyingError::Transport(CallbackError::Capacity))
        ));
        assert!(sink.data.is_empty());
        assert_eq!(streams.retained_bytes(), 0);
        streams
            .try_receive_copying_borrowed(
                4,
                b"abc",
                0,
                false,
                || panic!("in-order delivery requested allocation"),
                &mut sink,
            )
            .unwrap();
        streams
            .try_receive_copying_borrowed(
                4,
                b"def",
                3,
                true,
                || panic!("retry at cursor requested allocation"),
                &mut sink,
            )
            .unwrap();
        assert_eq!(sink.data, b"abcdef");
        assert_eq!(sink.finished, vec![4]);
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
    fn borrowed_partial_prefix_is_retained_and_resumed_without_a_fragment_queue() {
        let mut streams = CallbackStreams::<Arc<Vec<u8>>>::new(2, 16);
        let mut sink = PartialSink {
            data: Vec::new(),
            limit: 3,
            finished: Vec::new(),
        };
        streams
            .receive_copying_borrowed(
                4,
                b"abcdef",
                0,
                true,
                || Arc::new(b"abcdef".to_vec()),
                &mut sink,
            )
            .unwrap();
        assert_eq!(sink.data, b"abc");
        assert_eq!(streams.retained_bytes(), 3);

        sink.limit = usize::MAX;
        assert_eq!(streams.resume_copying(4, &mut sink).unwrap(), 3);
        assert_eq!(sink.data, b"abcdef");
        assert_eq!(sink.finished, vec![4]);
        assert_eq!(streams.retained_bytes(), 0);
    }

    /// Regression: an empty FIN retained behind unread bytes was never
    /// finished by `resume_copying`, because a consumer's 0 for a zero-length
    /// chunk was read as "not accepted". Every later resume re-delivered the
    /// same FIN, and a no-std drain loop spun forever.
    #[test]
    fn retained_empty_fin_is_delivered_once() {
        let mut streams = CallbackStreams::<Arc<Vec<u8>>>::new(2, 16);
        let mut sink = PartialSink {
            data: Vec::new(),
            limit: 0,
            finished: Vec::new(),
        };
        streams
            .receive_copying_borrowed(4, b"abc", 0, false, || Arc::new(b"abc".to_vec()), &mut sink)
            .unwrap();
        streams
            .receive_copying_borrowed(4, b"", 3, true, || Arc::new(Vec::new()), &mut sink)
            .unwrap();
        assert!(sink.data.is_empty());

        sink.limit = usize::MAX;
        assert_eq!(streams.resume_copying(4, &mut sink).unwrap(), 3);
        assert_eq!(sink.data, b"abc");
        assert_eq!(sink.finished, vec![4]);
        assert_eq!(streams.resume_copying(4, &mut sink).unwrap(), 0);
        assert_eq!(
            sink.finished,
            vec![4],
            "the FIN must not be delivered again"
        );
    }

    #[test]
    fn partial_consumer_resumes_in_order_across_an_out_of_order_tail() {
        let mut streams = CallbackStreams::<Arc<Vec<u8>>>::new(2, 16);
        let mut sink = PartialSink {
            data: Vec::new(),
            limit: 2,
            finished: Vec::new(),
        };
        // The tail arrives first and is retained by the same bounded QUIC
        // ordering state. It must not be exposed before the missing prefix.
        streams
            .receive_copying_borrowed(4, b"ef", 4, true, || Arc::new(b"ef".to_vec()), &mut sink)
            .unwrap();
        assert!(sink.data.is_empty());
        streams
            .receive_copying_borrowed(
                4,
                b"abcd",
                0,
                false,
                || Arc::new(b"abcd".to_vec()),
                &mut sink,
            )
            .unwrap();
        assert_eq!(sink.data, b"ab");
        // The remainder of the prefix and the previously out-of-order tail
        // are both resumed through one handler-neutral QUIC operation.
        sink.limit = usize::MAX;
        assert_eq!(streams.resume_copying(4, &mut sink).unwrap(), 4);
        assert_eq!(sink.data, b"abcdef");
        assert_eq!(sink.finished, vec![4]);
        assert_eq!(streams.retained_bytes(), 0);
    }

    #[test]
    fn established_in_order_borrowed_delivery_has_no_retained_work() {
        let mut streams = CallbackStreams::<Arc<Vec<u8>>>::new(2, 16);
        let mut sink = CopySink::default();
        for index in 0..128_u64 {
            streams
                .receive_copying_borrowed(
                    4,
                    b"data",
                    index * 4,
                    false,
                    || panic!("ordinary in-order delivery must remain borrowed"),
                    &mut sink,
                )
                .unwrap();
            assert_eq!(streams.retained_bytes(), 0);
            assert_eq!(sink.data.len(), (index as usize + 1) * 4);
        }
        streams
            .receive_copying_borrowed(
                4,
                b"",
                512,
                true,
                || panic!("bare in-order FIN must remain borrowed"),
                &mut sink,
            )
            .unwrap();
        assert_eq!(sink.finished, vec![4]);
        assert!(sink.reset.is_empty());
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
                // Borrow the prefix, then drain the already-owned tail.
                || panic!("gap-closing prefix must remain borrowed"),
                &mut sink,
            )
            .unwrap();
        assert_eq!(sink.data, b"headtail");
        assert_eq!(sink.finished, vec![4]);
        assert_eq!(streams.retained_bytes(), 0);
    }

    #[test]
    fn borrowed_repair_replays_many_retained_packets_byte_for_byte() {
        let source = (0..(48 * 1036))
            .map(|index| (index % 251) as u8)
            .collect::<Vec<_>>();
        let mut streams = CallbackStreams::<Arc<Vec<u8>>>::new(2, source.len());
        let mut sink = CopySink::default();
        // Model a lost first packet followed by one repaired fresh-number
        // copy. The callback layer must replay the retained tail exactly once
        // and preserve every byte; object/flash parsing is intentionally not
        // involved in this transport regression.
        for (packet, bytes) in source[1036..].chunks(1036).enumerate() {
            let offset = (packet + 1) as u64 * 1036;
            streams
                .receive_copying_borrowed(
                    8,
                    bytes,
                    offset,
                    offset as usize + bytes.len() == source.len(),
                    || Arc::new(bytes.to_vec()),
                    &mut sink,
                )
                .unwrap();
        }
        assert!(sink.data.is_empty());
        streams
            .receive_copying_borrowed(
                8,
                &source[..1036],
                0,
                false,
                || Arc::new(source[..1036].to_vec()),
                &mut sink,
            )
            .unwrap();
        assert_eq!(sink.data, source);
        assert_eq!(streams.retained_bytes(), 0);
    }

    #[test]
    fn copying_delivery_is_ordered_under_reordering() {
        let mut streams = CallbackStreams::new(4, 32);
        let mut sink = CopySink::default();
        let tail = Arc::new(b"tail".to_vec());
        let head = Arc::new(b"head".to_vec());
        streams
            .receive_copying(7, tail, 4, 0..4, true, &mut sink)
            .unwrap();
        assert!(sink.data.is_empty());
        streams
            .receive_copying(7, head, 0, 0..4, false, &mut sink)
            .unwrap();
        assert_eq!(sink.data, b"headtail");
        assert_eq!(sink.finished, vec![7]);
    }

    #[test]
    fn reordering_allowance_covers_the_configured_packet_window() {
        const PACKET: usize = 1200;
        let mut too_small = CallbackStreams::new(2, 4096);
        let mut sink = CopySink::default();
        for offset in [PACKET, PACKET * 2, PACKET * 3, PACKET * 4] {
            let result = too_small.receive_copying(
                8,
                Arc::new(vec![0x5a; PACKET]),
                offset as u64,
                0..PACKET,
                false,
                &mut sink,
            );
            if offset == PACKET * 4 {
                assert!(matches!(
                    result,
                    Err(CopyingError::Transport(CallbackError::Capacity))
                ));
            } else {
                result.unwrap();
            }
        }

        let mut streams = CallbackStreams::new(2, 8 * PACKET);
        let mut sink = CopySink::default();
        for offset in [PACKET, PACKET * 2, PACKET * 3, PACKET * 4, 0] {
            streams
                .receive_copying(
                    8,
                    Arc::new(vec![0x5a; PACKET]),
                    offset as u64,
                    0..PACKET,
                    false,
                    &mut sink,
                )
                .unwrap();
        }
        assert_eq!(sink.data.len(), 5 * PACKET);
        assert_eq!(streams.retained_bytes(), 0);
    }

    #[test]
    fn exact_retransmission_does_not_fail_when_callback_window_is_full() {
        let mut streams = CallbackStreams::new(2, 4);
        let mut sink = CopySink::default();
        let packet = Arc::new(b"hdr1tail".to_vec());
        streams
            .receive_copying(4, packet, 4, 4..8, false, &mut sink)
            .unwrap();
        assert_eq!(streams.retained_bytes(), 4);
        // This models a fresh-number transport retransmission of the same
        // stream range after the receiver's bounded reassembly is full. Its
        // packet-number/header encoding may put the payload at a different
        // offset in the replacement packet.
        streams
            .receive_copying(4, Arc::new(b"htail".to_vec()), 4, 1..5, false, &mut sink)
            .unwrap();
        assert_eq!(streams.retained_bytes(), 4);
    }

    #[test]
    fn full_reorder_window_accepts_the_missing_prefix_and_drains() {
        let mut streams = CallbackStreams::new(2, 4);
        let mut sink = CopySink::default();
        streams
            .receive_copying(8, Arc::new(b"tail".to_vec()), 4, 0..4, false, &mut sink)
            .unwrap();
        assert_eq!(streams.retained_bytes(), 4);
        assert!(matches!(
            streams.receive_copying(8, Arc::new(b"next".to_vec()), 8, 0..4, false, &mut sink),
            Err(CopyingError::Transport(CallbackError::Capacity))
        ));
        assert_eq!(streams.streams[0].consumed, 0);
        assert!(streams.streams[0].outstanding.is_none());
        assert_eq!(streams.streams[0].retained.len(), 1);
        assert_eq!(streams.streams[0].retained[0].offset, 4);
        streams
            .receive_copying(8, Arc::new(b"head".to_vec()), 0, 0..4, false, &mut sink)
            .unwrap();
        assert_eq!(sink.data, b"headtail");
        assert_eq!(streams.retained_bytes(), 0);
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
            .insert(Arc::new(b"ab".to_vec()), 0, 0..2, true, usize::MAX)
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
