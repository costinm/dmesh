//! Ordered IPERF diagnostic stream validation, independent of any bearer.

use alloc::{sync::Arc, vec::Vec};

use crate::{
    RECOVERY_REORDER_CAPACITY_BYTES, StreamFrame,
    callback::{CallbackError, CallbackStreams, CopyingError, CopyingStreamEvents},
};

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
    ) -> Result<(), ()> {
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
        Ok(())
    }
}

/// Bounded in-order receiver for the diagnostic IPERF stream.
pub struct IperfReceiver {
    ordered: CallbackStreams<Arc<Vec<u8>>>,
    validation: u8,
    bytes: u64,
    next_offset: u64,
    next_packet_id: u32,
    callback_errors: [u64; 6],
}

/// Bounded multi-stream IPERF run.
///
/// Stream placement, priority-stream completion, ordered validation, and byte
/// accounting are transport-test semantics rather than ESP, UDP, or socket
/// behavior.  Bearers feed committed stream frames here and use the returned
/// byte count to advance QUIC-lite flow control.
pub struct IperfRun<const NORMAL: usize> {
    normal: [IperfReceiver; NORMAL],
    high: IperfReceiver,
    low: IperfReceiver,
    normal_complete: [bool; NORMAL],
    high_complete: bool,
    low_complete: bool,
    normal_streams: usize,
    high_enabled: bool,
    low_enabled: bool,
}

impl<const NORMAL: usize> IperfRun<NORMAL> {
    pub fn new(
        validation: u8,
        normal_streams: usize,
        high_enabled: bool,
        low_enabled: bool,
    ) -> Self {
        let normal_streams = normal_streams.clamp(1, NORMAL);
        Self {
            normal: core::array::from_fn(|_| IperfReceiver::new(validation)),
            high: IperfReceiver::new(validation),
            low: IperfReceiver::new(validation),
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
            .map(IperfReceiver::bytes)
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

impl IperfReceiver {
    pub fn new(validation: u8) -> Self {
        Self {
            ordered: CallbackStreams::new(1, RECOVERY_REORDER_CAPACITY_BYTES),
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
    use super::{IperfReceiver, IperfRun};
    use crate::StreamFrame;

    #[test]
    fn validates_and_counts_one_complete_packet() {
        let mut receiver = IperfReceiver::new(2);
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
        let mut receiver = IperfReceiver::new(1);
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
        let mut run = IperfRun::<4>::new(0, 2, true, true);
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
}
