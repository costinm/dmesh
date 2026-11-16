//! Pool-backed PPP decoding shared by host and firmware UART adapters.

use alloc::vec::Vec;
use mesh_api::pool::{DEFAULT_MAX_PAYLOAD, PacketPool, PoolPacket};

use crate::{
    PACKET_MARKER, WAKE_MARKER,
    codec::{DEFAULT_RECORD_MAX, UART_ESCAPE, UART_ESCAPE_XOR, UART_FLAG},
};

pub enum PooledFrame<P> {
    /// A complete marked record backed by the shared packet pool.
    Packet(P),
    /// One exact, non-packet wake request record.
    Wake,
    /// Unmarked UART sideband. It is diagnostic/log data, never a packet for
    /// upper-layer transport or an application-control handler.
    Log(Vec<u8>),
    /// A marker was decoded, but no shared-pool slot was available. The rest
    /// of that record is discarded so it cannot be mistaken for sideband.
    PoolUnavailable,
}

/// Incremental PPP decoder which writes marked packets directly into the
/// shared `mesh-api` packet pool. Unmarked records are retained separately for
/// boot/crash or application-specific sideband handling.
pub struct PooledDecoder<P: PacketPool> {
    pool: P,
    /// At least one opening [`UART_FLAG`] has been observed.
    in_frame: bool,
    /// The previous wire byte was [`UART_ESCAPE`].
    escaped: bool,
    /// Ignore bytes until the next flag after an oversize frame or pool miss.
    discard: bool,
    /// Classification of the current record's first decoded byte. `None`
    /// means that the marker/sideband decision has not yet been made.
    marked: Option<FrameKind>,
    wake_payload_len: usize,
    /// Reserved immediately after decoding [`PACKET_MARKER`]. Marked payload
    /// bytes are written here directly and the active range is committed at EOF.
    packet: Option<P::Packet>,
    /// Starting headroom offset within `packet`.
    start: usize,
    /// Number of initialized packet payload bytes written at `start..start + len`.
    len: usize,
    /// Smaller of the slot's payload capacity and `DEFAULT_MAX_PAYLOAD`.
    packet_limit: usize,
    /// Storage only for unmarked diagnostic records. Packet data never enters
    /// this allocation.
    other: Vec<u8>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum FrameKind {
    Packet,
    Wake,
    Log,
}

impl<P: PacketPool> PooledDecoder<P> {
    pub fn new(pool: P) -> Self {
        Self {
            pool,
            in_frame: false,
            escaped: false,
            discard: false,
            marked: None,
            wake_payload_len: 0,
            packet: None,
            start: 0,
            len: 0,
            packet_limit: 0,
            other: Vec::new(),
        }
    }

    pub fn reset(&mut self) {
        self.in_frame = false;
        self.escaped = false;
        self.discard = false;
        self.marked = None;
        self.wake_payload_len = 0;
        self.packet = None;
        self.start = 0;
        self.len = 0;
        self.packet_limit = 0;
        self.other.clear();
    }

    pub fn push(
        &mut self,
        bytes: &[u8],
        payload_offset: usize,
        mut frame: impl FnMut(PooledFrame<P::Packet>),
    ) {
        for &wire_byte in bytes {
            if wire_byte == UART_FLAG {
                // A flag closes the current record and simultaneously opens
                // the next one. Committing transfers the existing pool lease
                // to the callback without copying its decoded bytes.
                if self.in_frame && !self.escaped && !self.discard {
                    match self.marked {
                        Some(FrameKind::Packet) if self.len != 0 => {
                            if let Some(mut packet) = self.packet.take()
                                && packet.set_range(self.start..self.start + self.len).is_ok()
                            {
                                frame(PooledFrame::Packet(packet));
                            }
                        }
                        Some(FrameKind::Wake) if self.wake_payload_len == 0 => {
                            frame(PooledFrame::Wake);
                        }
                        Some(FrameKind::Log) if !self.other.is_empty() => {
                            frame(PooledFrame::Log(core::mem::take(&mut self.other)));
                        }
                        _ => {}
                    }
                }
                self.in_frame = true;
                self.escaped = false;
                self.discard = false;
                self.marked = None;
                self.wake_payload_len = 0;
                self.packet = None;
                self.start = 0;
                self.len = 0;
                self.packet_limit = 0;
                self.other.clear();
                continue;
            }
            if !self.in_frame || self.discard {
                continue;
            }
            // PPP escaping is removed before inspecting the first byte, so an
            // escaped 0xf7 still selects the packet path.
            let byte = if self.escaped {
                self.escaped = false;
                wire_byte ^ UART_ESCAPE_XOR
            } else if wire_byte == UART_ESCAPE {
                self.escaped = true;
                continue;
            } else {
                wire_byte
            };
            if self.marked.is_none() {
                let kind = if byte == PACKET_MARKER {
                    FrameKind::Packet
                } else if byte == WAKE_MARKER {
                    FrameKind::Wake
                } else {
                    FrameKind::Log
                };
                self.marked = Some(kind);
                if kind == FrameKind::Packet {
                    // The marker is only a UART envelope byte. Reserve the
                    // pool slot now, then decode every following byte directly
                    // into its payload area; no complete-frame scratch buffer or
                    // copy is needed at the UART ownership boundary.
                    match self.pool.alloc_with_headroom(payload_offset) {
                        Ok(mut packet) => {
                            let capacity = packet
                                .slot_slice_mut()
                                .map(|s| s.len().saturating_sub(payload_offset))
                                .unwrap_or(0);
                            self.packet_limit = capacity.min(DEFAULT_MAX_PAYLOAD);
                            self.start = payload_offset;
                            self.packet = Some(packet);
                        }
                        Err(_) => {
                            frame(PooledFrame::PoolUnavailable);
                            self.discard = true;
                        }
                    }
                } else if kind == FrameKind::Log {
                    self.other.push(byte);
                }
                continue;
            }
            if self.marked == Some(FrameKind::Packet) {
                // Dropping an uncommitted packet returns its slot to the pool.
                // Keep discarding until a flag resynchronizes the decoder.
                if self.len >= self.packet_limit {
                    self.discard = true;
                    self.packet = None;
                    continue;
                }
                if let Some(packet) = self.packet.as_mut()
                    && let Ok(slot) = packet.slot_slice_mut()
                {
                    slot[self.start + self.len] = byte;
                    self.len += 1;
                } else {
                    self.discard = true;
                    self.packet = None;
                }
            } else if self.marked == Some(FrameKind::Wake) {
                self.wake_payload_len += 1;
                if self.wake_payload_len > 0 {
                    self.discard = true;
                }
            } else if self.other.len() < DEFAULT_RECORD_MAX {
                self.other.push(byte);
            } else {
                // Sideband has no pool lease, but still has a fixed record-size
                // limit to prevent an unterminated record growing indefinitely.
                self.discard = true;
                self.other.clear();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::encode_payload;

    static POOL: mesh_api::pool::StaticPacketPool<1, 128> =
        mesh_api::pool::StaticPacketPool::with_geometry(0, 128);

    #[test]
    fn exact_wake_marker_is_not_admitted_as_quic() {
        let wire = encode_payload(&[WAKE_MARKER], 8).unwrap();
        let mut decoder = PooledDecoder::new(&POOL);
        let mut wakes = 0;
        let mut packets = 0;
        decoder.push(&wire, 0, |frame| match frame {
            PooledFrame::Wake => wakes += 1,
            PooledFrame::Packet(_) => packets += 1,
            _ => {}
        });
        assert_eq!((wakes, packets), (1, 0));
    }

    #[test]
    fn wake_marker_with_payload_is_rejected() {
        let wire = encode_payload(&[WAKE_MARKER, 1], 8).unwrap();
        let mut decoder = PooledDecoder::new(&POOL);
        let mut wakes = 0;
        decoder.push(&wire, 0, |frame| {
            if matches!(frame, PooledFrame::Wake) {
                wakes += 1;
            }
        });
        assert_eq!(wakes, 0);
    }
}
