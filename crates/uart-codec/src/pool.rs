//! Pool-backed PPP decoding shared by host and firmware UART adapters.

use alloc::vec::Vec;
use quic_lite::{OwnedPacket, PacketPool, PacketWriter};

use crate::{
    PACKET_MARKER, WAKE_MARKER,
    codec::{DEFAULT_RECORD_MAX, UART_ESCAPE, UART_ESCAPE_XOR, UART_FLAG},
};

pub enum PooledFrame<B> {
    /// A complete marked record backed by the shared QUIC packet pool.
    Packet(OwnedPacket<B>),
    /// One exact, non-QUIC wake request record.
    Wake,
    /// Unmarked UART sideband. It is diagnostic/log data, never a packet for
    /// QUIC or an application-control handler.
    Log(Vec<u8>),
    /// A marker was decoded, but no shared-pool slot was available. The rest
    /// of that record is discarded so it cannot be mistaken for sideband.
    PoolUnavailable,
}

/// Incremental PPP decoder which writes marked packets directly into the
/// shared quic-lite packet pool. Unmarked records are retained separately for
/// boot/crash or application-specific sideband handling.
pub struct PooledDecoder<P: PacketPool + 'static> {
    pool: &'static P,
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
    /// bytes are written here directly and the writer is committed at EOF.
    writer: Option<P::Writer>,
    /// Number of initialized packet payload bytes in `writer`.
    len: usize,
    /// Smaller of the writer's payload capacity and the QUIC packet limit.
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

impl<P: PacketPool + 'static> PooledDecoder<P> {
    pub fn new(pool: &'static P) -> Self {
        Self {
            pool,
            in_frame: false,
            escaped: false,
            discard: false,
            marked: None,
            wake_payload_len: 0,
            writer: None,
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
        self.writer = None;
        self.len = 0;
        self.packet_limit = 0;
        self.other.clear();
    }

    pub fn push(
        &mut self,
        bytes: &[u8],
        payload_offset: usize,
        mut frame: impl FnMut(PooledFrame<P::Buffer>),
    ) {
        for &wire_byte in bytes {
            if wire_byte == UART_FLAG {
                // A flag closes the current record and simultaneously opens
                // the next one. Committing transfers the existing pool lease
                // to the callback without copying its decoded bytes.
                if self.in_frame && !self.escaped && !self.discard {
                    match self.marked {
                        Some(FrameKind::Packet) if self.len != 0 => {
                            if let Some(writer) = self.writer.take()
                                && let Some(packet) = writer.commit(self.len)
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
                self.writer = None;
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
                // Classification happens once, on the first decoded byte. It
                // chooses either a pool lease or the sideband Vec for the
                // entire record.
                let kind = if byte == PACKET_MARKER {
                    FrameKind::Packet
                } else if byte == WAKE_MARKER {
                    FrameKind::Wake
                } else {
                    FrameKind::Log
                };
                self.marked = Some(kind);
                if kind == FrameKind::Packet {
                    // The marker is only a UART envelope byte. Reserve the QUIC
                    // pool slot now, then decode every following byte directly
                    // into its payload area; no complete-frame scratch buffer or
                    // copy is needed at the UART/QUIC ownership boundary.
                    match self.pool.acquire_writer(payload_offset, 0) {
                        Some(mut writer) => {
                            self.packet_limit = writer
                                .payload_mut()
                                .len()
                                .min(quic_lite::DEFAULT_MAX_PACKET_SIZE);
                            self.writer = Some(writer);
                        }
                        None => {
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
                // Dropping an uncommitted writer returns its slot to the pool.
                // Keep discarding until a flag resynchronizes the decoder.
                if self.len >= self.packet_limit {
                    self.discard = true;
                    self.writer = None;
                    continue;
                }
                // `packet_limit` was derived from this writer's payload slice.
                self.writer
                    .as_mut()
                    .expect("marked frame owns a writer")
                    .payload_mut()[self.len] = byte;
                self.len += 1;
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
