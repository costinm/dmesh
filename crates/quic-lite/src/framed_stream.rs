//! Bounded application-message queue for a QUIC-lite stream.
//!
//! Each queued write is one application frame and is emitted as one complete
//! STREAM payload.  The queue deliberately never fragments a write to fill a
//! datagram: a caller either obtains the whole next frame or leaves it queued
//! for a later packet.  This keeps logging and command services message-aware
//! while endpoint flow control remains transport-only.

/// A queued application frame with its enqueue timestamp for drop policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FramedStreamRecord<const BYTES: usize> {
    bytes: [u8; BYTES],
    len: usize,
    enqueued_at_us: u64,
}

impl<const BYTES: usize> FramedStreamRecord<BYTES> {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    pub const fn enqueued_at_us(&self) -> u64 {
        self.enqueued_at_us
    }
}

/// Fixed-capacity no_std record queue for one stream.
pub struct FramedStream<const RECORDS: usize, const BYTES: usize> {
    records: [Option<FramedStreamRecord<BYTES>>; RECORDS],
    head: usize,
    len: usize,
    dropped_full: u64,
    dropped_expired: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FramedStreamError {
    Oversized,
    Full,
}

/// Immediate result of a producer write.  This is deliberately a value, not
/// a future or retry handle: trace/log/event producers must never wait for
/// peer connection state or QUIC stream credit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FramedStreamEnqueue {
    Queued,
    DroppedFull,
    DroppedOversized,
}

/// Allocation-free snapshot for producer-facing diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FramedStreamStats {
    pub queued_records: usize,
    pub record_capacity: usize,
    pub max_record_bytes: usize,
    pub dropped_full: u64,
    pub dropped_expired: u64,
}

impl<const RECORDS: usize, const BYTES: usize> FramedStream<RECORDS, BYTES> {
    pub fn new() -> Self {
        Self {
            records: core::array::from_fn(|_| None),
            head: 0,
            len: 0,
            dropped_full: 0,
            dropped_expired: 0,
        }
    }

    pub const fn len(&self) -> usize {
        self.len
    }
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
    pub const fn dropped_full(&self) -> u64 {
        self.dropped_full
    }
    pub const fn dropped_expired(&self) -> u64 {
        self.dropped_expired
    }

    pub const fn stats(&self) -> FramedStreamStats {
        FramedStreamStats {
            queued_records: self.len,
            record_capacity: RECORDS,
            max_record_bytes: BYTES,
            dropped_full: self.dropped_full,
            dropped_expired: self.dropped_expired,
        }
    }

    /// Try to enqueue one complete application record without any retry,
    /// allocation, fragmentation, or dependency on transport credit.
    pub fn try_enqueue(&mut self, bytes: &[u8], now_us: u64) -> FramedStreamEnqueue {
        if bytes.len() > BYTES {
            return FramedStreamEnqueue::DroppedOversized;
        }
        if self.len == RECORDS {
            self.dropped_full = self.dropped_full.saturating_add(1);
            return FramedStreamEnqueue::DroppedFull;
        }
        let slot = (self.head + self.len) % RECORDS;
        let mut stored = [0; BYTES];
        stored[..bytes.len()].copy_from_slice(bytes);
        self.records[slot] = Some(FramedStreamRecord {
            bytes: stored,
            len: bytes.len(),
            enqueued_at_us: now_us,
        });
        self.len += 1;
        FramedStreamEnqueue::Queued
    }

    pub fn push(&mut self, bytes: &[u8], now_us: u64) -> Result<(), FramedStreamError> {
        match self.try_enqueue(bytes, now_us) {
            FramedStreamEnqueue::Queued => Ok(()),
            FramedStreamEnqueue::DroppedFull => Err(FramedStreamError::Full),
            FramedStreamEnqueue::DroppedOversized => Err(FramedStreamError::Oversized),
        }
    }

    /// Drop oldest records which waited beyond this stream's service budget.
    /// A log producer can call this whenever local path capacity is full.
    pub fn drop_expired(&mut self, now_us: u64, max_age_us: u64) -> usize {
        let mut dropped = 0;
        while let Some(record) = self.peek() {
            if now_us.saturating_sub(record.enqueued_at_us) <= max_age_us {
                break;
            }
            self.pop();
            self.dropped_expired = self.dropped_expired.saturating_add(1);
            dropped += 1;
        }
        dropped
    }

    pub fn peek(&self) -> Option<&FramedStreamRecord<BYTES>> {
        if self.len == 0 {
            None
        } else {
            self.records[self.head].as_ref()
        }
    }

    pub fn pop(&mut self) -> Option<FramedStreamRecord<BYTES>> {
        if self.len == 0 {
            return None;
        }
        let record = self.records[self.head].take();
        self.head = (self.head + 1) % RECORDS;
        self.len -= 1;
        record
    }
}

impl<const RECORDS: usize, const BYTES: usize> Default for FramedStream<RECORDS, BYTES> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_record_boundaries_and_drops_only_oldest_expired_records() {
        let mut queue = FramedStream::<3, 8>::new();
        queue.push(b"one", 10).unwrap();
        queue.push(b"two", 20).unwrap();
        queue.push(b"three", 30).unwrap();
        assert_eq!(queue.drop_expired(35, 10), 2);
        assert_eq!(queue.peek().unwrap().bytes(), b"three");
        assert_eq!(queue.dropped_expired(), 2);
    }

    #[test]
    fn bounded_queue_reports_full_without_discarding_a_newer_record() {
        let mut queue = FramedStream::<1, 4>::new();
        queue.push(b"old", 0).unwrap();
        assert_eq!(queue.push(b"new", 1), Err(FramedStreamError::Full));
        assert_eq!(queue.pop().unwrap().bytes(), b"old");
        assert_eq!(queue.dropped_full(), 1);
    }

    #[test]
    fn non_blocking_enqueue_reports_immediate_queue_state() {
        let mut queue = FramedStream::<1, 3>::new();
        assert_eq!(queue.try_enqueue(b"ok", 1), FramedStreamEnqueue::Queued);
        assert_eq!(
            queue.try_enqueue(b"new", 2),
            FramedStreamEnqueue::DroppedFull
        );
        assert_eq!(
            queue.try_enqueue(b"long", 3),
            FramedStreamEnqueue::DroppedOversized
        );
        assert_eq!(
            queue.stats(),
            FramedStreamStats {
                queued_records: 1,
                record_capacity: 1,
                max_record_bytes: 3,
                dropped_full: 1,
                dropped_expired: 0,
            }
        );
    }
}
