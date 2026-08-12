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
}
