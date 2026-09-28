//! Protocol-neutral stream workload used by transport tests and diagnostics.
//!
//! These types know only ordered stream IDs, offsets, byte ranges, and FIN.
//! They do not encode packets, inspect connection state, or select a bearer.
//! A driver uses the public `QuicNode` stream API for those operations.

/// Maximum number of ordinary streams in one diagnostic run.
pub const MAX_NORMAL_STREAMS: usize = 4;
/// Transport-independent safety limit for one requested workload.
pub const MAX_BYTES: u64 = 64 * 1024 * 1024;

/// Application-decoded probe parameters. This contains no wire encoding or
/// bearer selection; CBOR, JSON, or another service layer may populate it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(missing_docs)]
pub struct ProbeRequest {
    pub bytes: u64,
    pub packet_size: u16,
    pub ack_frequency: Option<u8>,
    pub ack_delay_ms: Option<u8>,
    pub low_priority_bytes: Option<u32>,
    pub high_priority_bytes: Option<u32>,
    pub parallel_streams: Option<u8>,
    pub initial_consume_delay_ms: Option<u32>,
    pub consume_delay_ms: Option<u32>,
}

#[allow(missing_docs)]
impl ProbeRequest {
    pub const fn new(bytes: u64, packet_size: u16) -> Self {
        Self {
            bytes,
            packet_size,
            ack_frequency: None,
            ack_delay_ms: None,
            low_priority_bytes: None,
            high_priority_bytes: None,
            parallel_streams: None,
            initial_consume_delay_ms: None,
            consume_delay_ms: None,
        }
    }
}

/// Normalized workload consumed by probe stream drivers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(missing_docs)]
pub struct ProbePlan {
    pub packet_size: usize,
    pub normal_streams: usize,
    pub normal_bytes: [usize; MAX_NORMAL_STREAMS],
    pub high_priority_bytes: usize,
    pub low_priority_bytes: usize,
    pub ack_frequency: u8,
    pub ack_delay_ms: u8,
    pub initial_consume_delay_ms: u32,
    pub consume_delay_ms: u32,
}

#[allow(missing_docs)]
impl ProbePlan {
    pub fn from_request(request: ProbeRequest, max_packet_size: usize) -> Self {
        let normal_streams =
            usize::from(request.parallel_streams.unwrap_or(1)).clamp(1, MAX_NORMAL_STREAMS);
        let requested = request.bytes.clamp(1, MAX_BYTES) as usize;
        let each = requested / normal_streams;
        let remainder = requested % normal_streams;
        let mut normal_bytes = [0; MAX_NORMAL_STREAMS];
        for (index, bytes) in normal_bytes.iter_mut().take(normal_streams).enumerate() {
            *bytes = each + usize::from(index < remainder);
        }
        Self {
            packet_size: usize::from(request.packet_size).clamp(8, max_packet_size.max(8)),
            normal_streams,
            normal_bytes,
            high_priority_bytes: request
                .high_priority_bytes
                .and_then(|bytes| usize::try_from(bytes).ok())
                .unwrap_or(0)
                .min(MAX_BYTES as usize),
            low_priority_bytes: request
                .low_priority_bytes
                .and_then(|bytes| usize::try_from(bytes).ok())
                .unwrap_or(0)
                .min(MAX_BYTES as usize),
            ack_frequency: request.ack_frequency.unwrap_or(2).clamp(1, 8),
            ack_delay_ms: request.ack_delay_ms.unwrap_or(5).clamp(1, 25),
            initial_consume_delay_ms: request.initial_consume_delay_ms.unwrap_or(0),
            consume_delay_ms: request.consume_delay_ms.unwrap_or(0),
        }
    }

    pub fn total_bytes(&self) -> u64 {
        self.normal_bytes[..self.normal_streams]
            .iter()
            .copied()
            .sum::<usize>()
            .saturating_add(self.high_priority_bytes)
            .saturating_add(self.low_priority_bytes) as u64
    }
}

/// Transport-level result returned to a service adapter for presentation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(missing_docs)]
pub struct ProbeResult {
    pub bytes: u64,
    pub normal_bytes: u64,
    pub high_bytes: u64,
    pub low_bytes: u64,
    pub elapsed_us: u64,
    pub callback_errors: [u64; 6],
}

#[allow(missing_docs)]
impl ProbeResult {
    pub const fn bits_per_second(&self) -> u64 {
        if self.elapsed_us == 0 {
            0
        } else {
            self.bytes.saturating_mul(8).saturating_mul(1_000_000) / self.elapsed_us
        }
    }
}

/// One deterministic range offered by [`ProbeSender`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProbeChunk {
    /// Application stream selected by the transport-independent workload.
    pub stream_id: u64,
    /// Ordered byte position at which this range must be submitted.
    pub offset: u64,
    /// Initialized bytes in the caller's scratch buffer.
    pub len: usize,
    /// Whether this range completes the workload stream.
    pub fin: bool,
    packet_id: u32,
}

/// Ordered deterministic byte producer for one ordinary QUIC stream.
///
/// `prepare` does not advance state. The caller commits the returned token
/// only after `QuicNode::send_stream` accepts the same bytes. This preserves
/// the range unchanged across flow-control, history, pool, or bearer stalls.
pub struct ProbeSender {
    stream_id: u64,
    remaining: usize,
    chunk_size: usize,
    offset: u64,
    packet_id: u32,
}

impl ProbeSender {
    /// Create a deterministic workload, rejecting empty or undersized chunks.
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

    /// Whether every configured byte has been accepted by the transport.
    pub const fn is_complete(&self) -> bool {
        self.remaining == 0
    }

    /// Bytes committed after successful transport submissions.
    pub const fn bytes_sent(&self) -> u64 {
        self.offset
    }

    /// Fill one range, limited by the current peer-advertised byte window.
    ///
    /// `None` means completion or zero usable credit. The supplied storage is
    /// application scratch, not packet storage; `QuicNode::send_stream`
    /// obtains the actual packet from the `QuicNode` packet pool.
    pub fn prepare(&self, flow_window: u64, output: &mut [u8]) -> Option<ProbeChunk> {
        let available = usize::try_from(flow_window).unwrap_or(usize::MAX);
        let len = self
            .remaining
            .min(self.chunk_size)
            .min(output.len())
            .min(available);
        if len < 4 {
            return None;
        }
        output[..4].copy_from_slice(&self.packet_id.to_be_bytes());
        for (index, byte) in output[4..len].iter_mut().enumerate() {
            *byte = self.offset.wrapping_add(4 + index as u64) as u8;
        }
        Some(ProbeChunk {
            stream_id: self.stream_id,
            offset: self.offset,
            len,
            fin: len == self.remaining,
            packet_id: self.packet_id,
        })
    }

    /// Commit a range after the node has accepted it into normal QUIC state.
    pub fn commit(&mut self, chunk: ProbeChunk) -> Result<(), ProbeError> {
        if chunk.stream_id != self.stream_id
            || chunk.offset != self.offset
            || chunk.packet_id != self.packet_id
            || chunk.len < 4
            || chunk.len > self.remaining
            || chunk.fin != (chunk.len == self.remaining)
        {
            return Err(ProbeError::UnexpectedRange);
        }
        self.offset = self.offset.saturating_add(chunk.len as u64);
        self.remaining -= chunk.len;
        self.packet_id = self.packet_id.wrapping_add(1);
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Validation failure shared by TCP and QUIC probe runs.
///
/// This is public so tests can apply the exact same workload and assertions to
/// standard stream APIs and quic-lite streams.
pub enum ProbeError {
    /// Offset, length, FIN, or commit token differs from the prepared range.
    UnexpectedRange,
    /// Deterministic sequence bytes do not match the sender.
    InvalidPayload,
    /// A chunk arrived on a stream not configured for this run.
    UnexpectedStream,
}

/// In-order validator for one ordinary stream callback.
pub struct ProbeReceiver {
    validation: u8,
    bytes: u64,
    next_offset: u64,
    next_packet_id: u32,
    complete: bool,
    callback_errors: [u64; 6],
}

impl ProbeReceiver {
    /// Create a receiver at offset zero with the selected validation level.
    pub const fn new(validation: u8) -> Self {
        Self {
            validation,
            bytes: 0,
            next_offset: 0,
            next_packet_id: 0,
            complete: false,
            callback_errors: [0; 6],
        }
    }

    /// Total validated application bytes.
    pub const fn bytes(&self) -> u64 {
        self.bytes
    }

    /// Whether a valid FIN has been received.
    pub const fn is_complete(&self) -> bool {
        self.complete
    }

    /// Diagnostic counters matching the probe's stable reporting layout.
    pub const fn callback_errors(&self) -> &[u64; 6] {
        &self.callback_errors
    }

    /// Validate one ordered chunk delivered by the normal stream API.
    /// Ordered delivery is currently guaranteed by the node; an explicitly
    /// selected future out-of-order mode would need a different validator.
    pub fn receive(&mut self, offset: u64, fin: bool, bytes: &[u8]) -> Result<usize, ProbeError> {
        if self.complete || bytes.len() < 4 || offset != self.next_offset {
            self.callback_errors[2] = self.callback_errors[2].saturating_add(1);
            return Err(ProbeError::UnexpectedRange);
        }
        if self.validation >= 1 {
            let packet_id = bytes
                .get(..4)
                .and_then(|id| id.try_into().ok())
                .map(u32::from_be_bytes);
            if packet_id != Some(self.next_packet_id) {
                self.callback_errors[5] = self.callback_errors[5].saturating_add(1);
                return Err(ProbeError::InvalidPayload);
            }
            if self.validation >= 2
                && bytes[4..].iter().enumerate().any(|(index, byte)| {
                    *byte != self.next_offset.wrapping_add(4 + index as u64) as u8
                })
            {
                self.callback_errors[5] = self.callback_errors[5].saturating_add(1);
                return Err(ProbeError::InvalidPayload);
            }
        }
        self.next_packet_id = self.next_packet_id.wrapping_add(1);
        self.next_offset = self.next_offset.saturating_add(bytes.len() as u64);
        self.bytes = self.bytes.saturating_add(bytes.len() as u64);
        self.complete = fin;
        Ok(bytes.len())
    }
}

/// Fixed-capacity collection of normal and priority probe streams.
pub struct ProbeRun<const NORMAL: usize> {
    normal: [ProbeReceiver; NORMAL],
    high: ProbeReceiver,
    low: ProbeReceiver,
    normal_streams: usize,
    high_enabled: bool,
    low_enabled: bool,
}

impl<const NORMAL: usize> ProbeRun<NORMAL> {
    /// Configure a fixed-capacity group of ordinary and optional priority streams.
    pub fn new(
        validation: u8,
        normal_streams: usize,
        high_enabled: bool,
        low_enabled: bool,
    ) -> Self {
        Self {
            normal: core::array::from_fn(|_| ProbeReceiver::new(validation)),
            high: ProbeReceiver::new(validation),
            low: ProbeReceiver::new(validation),
            normal_streams: normal_streams.clamp(1, NORMAL),
            high_enabled,
            low_enabled,
        }
    }

    /// Route and validate one ordered stream chunk.
    pub fn receive(
        &mut self,
        first_stream: u64,
        stream_id: u64,
        offset: u64,
        fin: bool,
        bytes: &[u8],
    ) -> Result<(bool, usize), ProbeError> {
        let normal_index = stream_id
            .checked_sub(first_stream)
            .filter(|delta| *delta % 4 == 0)
            .map(|delta| (delta / 4) as usize)
            .filter(|index| *index < self.normal_streams);
        let high_stream = first_stream + 4 * self.normal_streams as u64;
        let low_stream = high_stream + 4;
        let consumed = if let Some(index) = normal_index {
            self.normal[index].receive(offset, fin, bytes)?
        } else if stream_id == high_stream && self.high_enabled {
            self.high.receive(offset, fin, bytes)?
        } else if stream_id == low_stream && self.low_enabled {
            self.low.receive(offset, fin, bytes)?
        } else {
            return Err(ProbeError::UnexpectedStream);
        };
        Ok((self.is_complete(), consumed))
    }

    /// Whether every enabled stream has received a valid FIN.
    pub fn is_complete(&self) -> bool {
        self.normal[..self.normal_streams]
            .iter()
            .all(ProbeReceiver::is_complete)
            && (!self.high_enabled || self.high.is_complete())
            && (!self.low_enabled || self.low.is_complete())
    }

    /// Validated bytes across normal streams.
    pub fn normal_bytes(&self) -> u64 {
        self.normal[..self.normal_streams]
            .iter()
            .map(ProbeReceiver::bytes)
            .sum()
    }

    /// Validated bytes on the optional high-priority stream.
    pub const fn high_bytes(&self) -> u64 {
        self.high.bytes()
    }

    /// Validated bytes on the optional low-priority stream.
    pub const fn low_bytes(&self) -> u64 {
        self.low.bytes()
    }

    /// Validated bytes across all enabled streams.
    pub fn bytes(&self) -> u64 {
        self.normal_bytes()
            .saturating_add(self.high_bytes())
            .saturating_add(self.low_bytes())
    }

    /// Sum diagnostic counters across all configured receivers.
    pub fn callback_errors(&self) -> [u64; 6] {
        let mut totals = [0u64; 6];
        for receiver in self.normal[..self.normal_streams]
            .iter()
            .chain(core::iter::once(&self.high))
            .chain(core::iter::once(&self.low))
        {
            for (total, value) in totals.iter_mut().zip(receiver.callback_errors()) {
                *total = total.saturating_add(*value);
            }
        }
        totals
    }

    /// Snapshot the completed workload in a wire- and bearer-neutral form.
    pub fn result(&self, elapsed_us: u64) -> ProbeResult {
        ProbeResult {
            bytes: self.bytes(),
            normal_bytes: self.normal_bytes(),
            high_bytes: self.high_bytes(),
            low_bytes: self.low_bytes(),
            elapsed_us,
            callback_errors: self.callback_errors(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ProbeError, ProbeReceiver, ProbeRun, ProbeSender};

    #[test]
    fn sender_waits_for_credit_and_commits_only_accepted_ranges() {
        let mut sender = ProbeSender::new(3, 12, 8).unwrap();
        let mut bytes = [0u8; 8];
        assert!(sender.prepare(0, &mut bytes).is_none());
        let first = sender.prepare(8, &mut bytes).unwrap();
        assert!(!first.fin);
        assert_eq!(sender.bytes_sent(), 0);
        assert_eq!(sender.prepare(8, &mut bytes), Some(first));
        sender.commit(first).unwrap();
        let second = sender.prepare(4, &mut bytes).unwrap();
        assert!(second.fin);
        sender.commit(second).unwrap();
        assert!(sender.is_complete());
    }

    #[test]
    fn receiver_validates_multiple_ranges_and_fin() {
        let mut sender = ProbeSender::new(3, 12, 8).unwrap();
        let mut receiver = ProbeReceiver::new(2);
        let mut bytes = [0u8; 8];
        while !sender.is_complete() {
            let chunk = sender.prepare(8, &mut bytes).unwrap();
            assert_eq!(
                receiver.receive(chunk.offset, chunk.fin, &bytes[..chunk.len]),
                Ok(chunk.len)
            );
            sender.commit(chunk).unwrap();
        }
        assert!(receiver.is_complete());
        assert_eq!(receiver.bytes(), 12);
    }

    #[test]
    fn receiver_rejects_wrong_sequence() {
        let mut receiver = ProbeReceiver::new(1);
        assert_eq!(
            receiver.receive(0, true, &[0, 0, 0, 1]),
            Err(ProbeError::InvalidPayload)
        );
    }

    #[test]
    fn run_maps_normal_and_priority_streams() {
        let mut run = ProbeRun::<4>::new(0, 2, true, true);
        for id in [3, 7, 11, 15] {
            assert_eq!(
                run.receive(3, id, 0, true, &[0, 0, 0, 0]),
                Ok((id == 15, 4))
            );
        }
        assert_eq!(run.bytes(), 16);
        let result = run.result(8);
        assert_eq!(result.bytes, 16);
        assert_eq!(result.bits_per_second(), 16_000_000);
    }
}
