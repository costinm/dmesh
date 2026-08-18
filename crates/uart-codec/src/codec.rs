//! `no_std` PPP/HDLC framing for ESP32 UART records.

use alloc::vec::Vec;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    EmptyPayload,
    PayloadTooLarge,
}

impl core::fmt::Display for Error {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::EmptyPayload => formatter.write_str("UART payload is empty"),
            Self::PayloadTooLarge => formatter.write_str("UART payload is too large"),
        }
    }
}

pub type Result<T> = core::result::Result<T, Error>;

pub const UART_FLAG: u8 = 0x7e;
pub const UART_ESCAPE: u8 = 0x7d;
pub const UART_ESCAPE_XOR: u8 = 0x20;
pub const DEFAULT_RECORD_MAX: usize = 4_000;

/// Incremental PPP/HDLC encoder.
///
/// This intentionally borrows the payload.  A transport adapter can therefore
/// retain one packet-pool lease and produce the wire form as the physical
/// driver accepts bytes; it never needs a second, worst-case escaped frame.
pub struct Encoder<'a> {
    payload: &'a [u8],
    prefix: Option<u8>,
    offset: usize,
    state: EncodeState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EncodeState {
    OpeningFlag,
    Payload,
    Escape(u8),
    ClosingFlag,
    Done,
}

impl<'a> Encoder<'a> {
    pub fn new(payload: &'a [u8], max: usize) -> Result<Self> {
        if payload.is_empty() || payload.len() > max {
            return Err(if payload.is_empty() {
                Error::EmptyPayload
            } else {
                Error::PayloadTooLarge
            });
        }
        Ok(Self {
            payload,
            prefix: None,
            offset: 0,
            state: EncodeState::OpeningFlag,
        })
    }

    /// Frame a one-byte L2 marker followed by a borrowed packet without
    /// constructing a marker-plus-packet temporary buffer.
    pub fn new_prefixed(prefix: u8, payload: &'a [u8], max: usize) -> Result<Self> {
        if payload.len().saturating_add(1) > max {
            return Err(Error::PayloadTooLarge);
        }
        Ok(Self {
            payload,
            prefix: Some(prefix),
            offset: 0,
            state: EncodeState::OpeningFlag,
        })
    }

    /// Write as much of the frame as fits in `out`, returning the byte count.
    /// Calling this with short buffers is equivalent to writing the complete
    /// PPP frame at once.
    pub fn write(&mut self, out: &mut [u8]) -> usize {
        let mut used = 0;
        while used < out.len() && self.state != EncodeState::Done {
            out[used] = match self.state {
                EncodeState::OpeningFlag => {
                    self.state = EncodeState::Payload;
                    UART_FLAG
                }
                EncodeState::Payload => {
                    let byte = if let Some(prefix) = self.prefix.take() {
                        prefix
                    } else {
                        if self.offset == self.payload.len() {
                            self.state = EncodeState::ClosingFlag;
                            continue;
                        }
                        let byte = self.payload[self.offset];
                        self.offset += 1;
                        byte
                    };
                    if matches!(byte, UART_FLAG | UART_ESCAPE) {
                        self.state = EncodeState::Escape(byte ^ UART_ESCAPE_XOR);
                        UART_ESCAPE
                    } else {
                        byte
                    }
                }
                EncodeState::Escape(byte) => {
                    self.state = EncodeState::Payload;
                    byte
                }
                EncodeState::ClosingFlag => {
                    self.state = EncodeState::Done;
                    UART_FLAG
                }
                EncodeState::Done => break,
            };
            used += 1;
        }
        used
    }

    pub fn is_finished(&self) -> bool {
        self.state == EncodeState::Done
    }
}

/// Encode one raw firmware payload with delimiters and byte escaping.
pub fn encode_payload(payload: &[u8], max: usize) -> Result<Vec<u8>> {
    if payload.is_empty() || payload.len() > max {
        return Err(if payload.is_empty() {
            Error::EmptyPayload
        } else {
            Error::PayloadTooLarge
        });
    }
    let mut wire = Vec::with_capacity(payload.len() * 2 + 2);
    wire.push(UART_FLAG);
    for byte in payload {
        if matches!(*byte, UART_FLAG | UART_ESCAPE) {
            wire.push(UART_ESCAPE);
            wire.push(*byte ^ UART_ESCAPE_XOR);
        } else {
            wire.push(*byte);
        }
    }
    wire.push(UART_FLAG);
    Ok(wire)
}

pub struct Decoder {
    in_frame: bool,
    escaped: bool,
    discard: bool,
    payload: Vec<u8>,
    frame_activity: bool,
    frame_error: bool,
    max_payload: usize,
}

impl Decoder {
    /// Construct a decoder with a maximum decoded payload size.
    pub fn with_max(max_payload: usize) -> Self {
        Self {
            payload: Vec::with_capacity(max_payload.min(DEFAULT_RECORD_MAX)),
            max_payload,
            ..Self::default()
        }
    }

    /// Reset the decoder after a transport-level error or input flush.
    pub fn reset(&mut self) {
        self.in_frame = false;
        self.escaped = false;
        self.discard = false;
        self.payload.clear();
    }

    /// Consume fragmented bytes and return completed raw firmware payloads.
    pub fn push(&mut self, bytes: &[u8]) -> Result<Vec<Vec<u8>>> {
        let mut records = Vec::new();
        for byte in bytes {
            if *byte == UART_FLAG {
                if !self.in_frame {
                    self.in_frame = true;
                    self.escaped = false;
                    self.discard = false;
                    self.payload.clear();
                    continue;
                }
                let had_payload = !self.payload.is_empty();
                if !self.escaped && !self.discard && had_payload {
                    records.push(core::mem::take(&mut self.payload));
                }
                if self.escaped || self.discard {
                    self.frame_error = true;
                }
                if had_payload {
                    self.frame_activity = true;
                }
                self.escaped = false;
                self.discard = false;
                self.payload.clear();
                continue;
            }
            if !self.in_frame || self.discard {
                continue;
            }
            if self.escaped {
                self.payload.push(*byte ^ UART_ESCAPE_XOR);
                self.escaped = false;
            } else if *byte == UART_ESCAPE {
                self.escaped = true;
            } else {
                self.payload.push(*byte);
            }
            if self.payload.len() > self.max_payload {
                self.payload.clear();
                self.escaped = false;
                self.discard = true;
                self.frame_error = true;
            }
        }
        Ok(records)
    }

    /// Return and clear whether a non-empty physical frame was observed.
    pub fn take_frame_activity(&mut self) -> bool {
        core::mem::take(&mut self.frame_activity)
    }

    /// Return and clear whether malformed input was observed.
    pub fn take_frame_error(&mut self) -> bool {
        core::mem::take(&mut self.frame_error)
    }
}

impl Default for Decoder {
    fn default() -> Self {
        Self {
            in_frame: false,
            escaped: false,
            discard: false,
            payload: Vec::with_capacity(DEFAULT_RECORD_MAX),
            frame_activity: false,
            frame_error: false,
            max_payload: DEFAULT_RECORD_MAX,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn round_trip_escapes_delimiters() {
        let payload = [0x01, UART_FLAG, UART_ESCAPE, 0x02];
        let wire = encode_payload(&payload, 4000).unwrap();
        let mut decoder = Decoder::default();
        assert_eq!(decoder.push(&wire).unwrap(), vec![payload]);
    }

    #[test]
    fn bounded_decoder_reports_errors_and_resynchronizes() {
        let mut decoder = Decoder::with_max(2);
        let input = [UART_FLAG, 1, 2, 3, UART_FLAG, UART_FLAG, 9, UART_FLAG];
        assert_eq!(decoder.push(&input).unwrap(), vec![vec![9]]);
        assert!(decoder.take_frame_error());
        assert!(!decoder.take_frame_error());
    }

    #[test]
    fn incremental_encoder_matches_whole_frame_for_short_writes() {
        let payload = [1, UART_FLAG, 2, UART_ESCAPE, 3];
        let expected = encode_payload(&payload, 16).unwrap();
        let mut encoder = Encoder::new(&payload, 16).unwrap();
        let mut actual = Vec::new();
        let mut short = [0u8; 1];
        while !encoder.is_finished() {
            let used = encoder.write(&mut short);
            actual.extend_from_slice(&short[..used]);
        }
        assert_eq!(actual, expected);
    }

    #[test]
    fn prefixed_encoder_never_needs_a_marker_plus_packet_copy() {
        let payload = [UART_ESCAPE, 3];
        let mut expected_payload = vec![0x55];
        expected_payload.extend_from_slice(&payload);
        let expected = encode_payload(&expected_payload, 8).unwrap();
        let mut encoder = Encoder::new_prefixed(0x55, &payload, 8).unwrap();
        let mut actual = Vec::new();
        let mut short = [0u8; 1];
        while !encoder.is_finished() {
            let used = encoder.write(&mut short);
            actual.extend_from_slice(&short[..used]);
        }
        assert_eq!(actual, expected);
    }
}
