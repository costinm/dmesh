//! Minimal definite-length CBOR, shared by firmware and host implementations.
//!
//! This is the no-alloc, `Option`-based codec that DMesh firmware and
//! `dmesh-server` use for tagged envelopes and object manifests. It performs
//! no text decoding or UTF-8 validation. Method names follow `minicbor`
//! where the signatures agree, so a caller can move between this codec and
//! `minicbor` with minimal effort:
//!
//! - `Encoder`: `u64`, `i64`, `map`, `array`, `bytes`, `str`, `bool`;
//! - `Decoder`: `u64`, `i64`, `str`, `str_ref`, `bool`, `skip`;
//!
//! Names ending in `_value`/`_ref` or taking an output slice keep the
//! original DMesh forms for fixed-buffer, borrow-only callers.

/// Fixed-capacity CBOR writer over a caller-owned buffer. Every method
/// returns `None` when the remaining capacity is insufficient.
pub struct Encoder<'a> {
    out: &'a mut [u8],
    pos: usize,
}

impl<'a> Encoder<'a> {
    pub fn new(out: &'a mut [u8]) -> Self {
        Self { out, pos: 0 }
    }
    pub fn len(&self) -> usize {
        self.pos
    }
    fn put(&mut self, byte: u8) -> Option<()> {
        *self.out.get_mut(self.pos)? = byte;
        self.pos += 1;
        Some(())
    }
    fn raw(&mut self, bytes: &[u8]) -> Option<()> {
        let end = self.pos.checked_add(bytes.len())?;
        self.out.get_mut(self.pos..end)?.copy_from_slice(bytes);
        self.pos = end;
        Some(())
    }
    fn head(&mut self, major: u8, value: u64) -> Option<()> {
        if value < 24 {
            self.put((major << 5) | value as u8)
        } else if value <= u8::MAX as u64 {
            self.raw(&[(major << 5) | 24, value as u8])
        } else if value <= u32::MAX as u64 {
            self.put((major << 5) | 26)?;
            self.raw(&(value as u32).to_be_bytes())
        } else {
            self.put((major << 5) | 27)?;
            self.raw(&value.to_be_bytes())
        }
    }
    pub fn map(&mut self, count: u64) -> Option<()> {
        self.head(5, count)
    }
    pub fn array(&mut self, count: u64) -> Option<()> {
        self.head(4, count)
    }
    pub fn uint(&mut self, value: u64) -> Option<()> {
        self.head(0, value)
    }
    /// `minicbor`-style alias for [`Encoder::uint`].
    pub fn u64(&mut self, value: u64) -> Option<()> {
        self.uint(value)
    }
    /// Encode a CBOR integer without forcing diagnostics such as RSSI into an
    /// unsigned surrogate. Negative values use CBOR major type 1 (`-1 - n`).
    pub fn int(&mut self, value: i64) -> Option<()> {
        if value >= 0 {
            self.uint(value as u64)
        } else {
            self.head(1, (-1_i64 - value) as u64)
        }
    }
    /// `minicbor`-style alias for [`Encoder::int`].
    pub fn i64(&mut self, value: i64) -> Option<()> {
        self.int(value)
    }
    pub fn bytes_value(&mut self, value: &[u8]) -> Option<()> {
        self.head(2, value.len() as u64)?;
        self.raw(value)
    }
    /// `minicbor`-style alias for [`Encoder::bytes_value`].
    pub fn bytes(&mut self, value: &[u8]) -> Option<()> {
        self.bytes_value(value)
    }
    pub fn text_value(&mut self, value: &[u8]) -> Option<()> {
        self.head(3, value.len() as u64)?;
        self.raw(value)
    }
    /// `minicbor`-style alias for [`Encoder::text_value`]. The input is
    /// written verbatim; no UTF-8 validation is performed.
    pub fn str(&mut self, value: &[u8]) -> Option<()> {
        self.text_value(value)
    }
    pub fn boolean(&mut self, value: bool) -> Option<()> {
        self.put(if value { 0xf5 } else { 0xf4 })
    }
    /// `minicbor`-style alias for [`Encoder::boolean`].
    pub fn bool(&mut self, value: bool) -> Option<()> {
        self.boolean(value)
    }
    /// Append one already-validated, complete CBOR value. This is used by
    /// tagged-envelope adapters to preserve a bounded field/result value
    /// without decoding it into an allocation or a lossy JSON form.
    pub fn encoded_value(&mut self, value: &[u8]) -> Option<()> {
        let mut decoder = Decoder::new(value);
        decoder.skip()?;
        decoder.is_finished().then(|| self.raw(value))?
    }
}

/// Borrowing CBOR reader. Lengths stay `u64` so malformed oversized items
/// fail the bounded `take` instead of truncating silently.
pub struct Decoder<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Decoder<'a> {
    pub const fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }
    pub const fn position(&self) -> usize {
        self.pos
    }
    pub const fn is_finished(&self) -> bool {
        self.pos == self.data.len()
    }
    pub fn set_position(&mut self, pos: usize) {
        self.pos = pos;
    }
    pub fn head(&mut self) -> Option<(u8, u64)> {
        let first = *self.data.get(self.pos)?;
        self.pos += 1;
        let major = first >> 5;
        let ai = first & 31;
        let value = match ai {
            0..=23 => ai as u64,
            24 => self.take(1)?[0] as u64,
            25 => u16::from_be_bytes(self.take(2)?.try_into().ok()?) as u64,
            26 => u32::from_be_bytes(self.take(4)?.try_into().ok()?) as u64,
            27 => u64::from_be_bytes(self.take(8)?.try_into().ok()?),
            31 => u64::MAX,
            _ => return None,
        };
        Some((major, value))
    }
    pub fn consume_break(&mut self) -> bool {
        if self.data.get(self.pos) == Some(&0xff) {
            self.pos += 1;
            true
        } else {
            false
        }
    }
    pub fn take(&mut self, len: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(len)?;
        let bytes = self.data.get(self.pos..end)?;
        self.pos = end;
        Some(bytes)
    }
    pub fn uint(&mut self) -> Option<u64> {
        let (major, value) = self.head()?;
        (major == 0).then_some(value)
    }
    /// `minicbor`-style alias for [`Decoder::uint`].
    pub fn u64(&mut self) -> Option<u64> {
        self.uint()
    }
    pub fn int(&mut self) -> Option<i64> {
        let (major, value) = self.head()?;
        match major {
            0 => i64::try_from(value).ok(),
            1 => value
                .checked_add(1)
                .and_then(|value| i64::try_from(value).ok())
                .map(|value| -value),
            _ => None,
        }
    }
    /// `minicbor`-style alias for [`Decoder::int`].
    pub fn i64(&mut self) -> Option<i64> {
        self.int()
    }
    pub fn bytes_ref(&mut self) -> Option<&'a [u8]> {
        let (major, len) = self.head()?;
        (major == 2).then(|| self.take(len as usize)).flatten()
    }
    pub fn bytes(&mut self, dst: &mut [u8]) -> Option<usize> {
        let bytes = self.bytes_ref()?;
        if bytes.len() > dst.len() {
            return None;
        }
        dst[..bytes.len()].copy_from_slice(bytes);
        Some(bytes.len())
    }
    pub fn text(&mut self, dst: &mut [u8]) -> Option<usize> {
        let (major, len) = self.head()?;
        if major != 3 || len as usize > dst.len() {
            return None;
        }
        let bytes = self.take(len as usize)?;
        dst[..bytes.len()].copy_from_slice(bytes);
        Some(bytes.len())
    }
    /// `minicbor`-style alias for [`Decoder::text`].
    pub fn str(&mut self, dst: &mut [u8]) -> Option<usize> {
        self.text(dst)
    }
    pub fn text_ref(&mut self) -> Option<&'a [u8]> {
        let (major, len) = self.head()?;
        (major == 3).then(|| self.take(len as usize)).flatten()
    }
    /// `minicbor`-style alias for [`Decoder::text_ref`].
    pub fn str_ref(&mut self) -> Option<&'a [u8]> {
        self.text_ref()
    }
    /// Accept a compact binary identifier from canonical CBOR clients or its
    /// UTF-8 text spelling from schema/JSON adapters. Callers still receive
    /// borrowed bytes and apply their own identifier alphabet constraints.
    pub fn bytes_or_text_ref(&mut self) -> Option<&'a [u8]> {
        let saved = self.position();
        if let Some(value) = self.bytes_ref() {
            return Some(value);
        }
        self.set_position(saved);
        self.text_ref()
    }
    pub fn boolean(&mut self) -> Option<bool> {
        match *self.take(1)?.first()? {
            0xf4 => Some(false),
            0xf5 => Some(true),
            _ => None,
        }
    }
    /// `minicbor`-style alias for [`Decoder::boolean`].
    pub fn bool(&mut self) -> Option<bool> {
        self.boolean()
    }
    pub fn boolean_or_text(&mut self) -> Option<bool> {
        let saved = self.position();
        if let Some(value) = self.boolean() {
            return Some(value);
        }
        self.set_position(saved);
        let mut text = [0u8; 5];
        let len = self.text(&mut text)?;
        match &text[..len] {
            b"true" => Some(true),
            b"false" => Some(false),
            _ => None,
        }
    }
    pub fn uint_or_text(&mut self) -> Option<u64> {
        let saved = self.position();
        if let Some(value) = self.uint() {
            return Some(value);
        }
        self.set_position(saved);
        let mut text = [0u8; 20];
        let len = self.text(&mut text)?;
        let mut value = 0u64;
        for byte in &text[..len] {
            if !byte.is_ascii_digit() {
                return None;
            }
            value = value.checked_mul(10)?.checked_add((byte - b'0') as u64)?;
        }
        Some(value)
    }
    pub fn skip(&mut self) -> Option<()> {
        let (major, len) = self.head()?;
        match major {
            0 | 1 | 7 => Some(()),
            2 | 3 => {
                self.take(len as usize)?;
                Some(())
            }
            4 => {
                let mut index = 0;
                while (len == u64::MAX && !self.consume_break()) || (len != u64::MAX && index < len)
                {
                    index += 1;
                    self.skip()?;
                }
                Some(())
            }
            5 => {
                let mut index = 0;
                while (len == u64::MAX && !self.consume_break()) || (len != u64::MAX && index < len)
                {
                    index += 1;
                    self.skip()?;
                    self.skip()?;
                }
                Some(())
            }
            _ => None,
        }
    }
}

/// Alloc-based helpers for callers that build nested values in a `Vec`.
pub mod encode {
    use alloc::vec::Vec;

    pub fn uint(value: u64, out: &mut Vec<u8>) {
        if value < 24 {
            out.push(value as u8);
        } else if value <= u8::MAX as u64 {
            out.extend_from_slice(&[24, value as u8]);
        } else if value <= u32::MAX as u64 {
            out.push(0x1a);
            out.extend_from_slice(&(value as u32).to_be_bytes());
        } else {
            out.push(0x1b);
            out.extend_from_slice(&value.to_be_bytes());
        }
    }
    pub fn map(len: u64, out: &mut Vec<u8>) {
        head(5, len, out);
    }
    pub fn array(len: u64, out: &mut Vec<u8>) {
        head(4, len, out);
    }
    pub fn bytes(bytes: &[u8], out: &mut Vec<u8>) {
        head(2, bytes.len() as u64, out);
        out.extend_from_slice(bytes);
    }
    pub fn boolean(value: bool, out: &mut Vec<u8>) {
        out.push(if value { 0xf5 } else { 0xf4 });
    }
    fn head(major: u8, len: u64, out: &mut Vec<u8>) {
        if len < 24 {
            out.push((major << 5) | len as u8);
        } else if len <= u8::MAX as u64 {
            out.extend_from_slice(&[(major << 5) | 24, len as u8]);
        } else {
            out.push((major << 5) | 26);
            out.extend_from_slice(&(len as u32).to_be_bytes());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encoder_and_decoder_round_trip_minicbor_named_methods() {
        let mut buffer = [0u8; 32];
        let mut encoder = Encoder::new(&mut buffer);
        encoder.map(2).unwrap();
        encoder.u64(1).unwrap();
        encoder.i64(-5).unwrap();
        encoder.u64(2).unwrap();
        encoder.bytes(b"ab").unwrap();
        let used = encoder.len();
        assert_eq!(&buffer[..used], &[0xa2, 0x01, 0x24, 0x02, 0x42, b'a', b'b']);

        let mut decoder = Decoder::new(&buffer[..used]);
        assert_eq!(decoder.head(), Some((5, 2)));
        assert_eq!(decoder.u64(), Some(1));
        assert_eq!(decoder.i64(), Some(-5));
        assert_eq!(decoder.u64(), Some(2));
        let mut text = [0u8; 8];
        assert_eq!(decoder.bytes(&mut text), Some(2));
        assert_eq!(&text[..2], b"ab");
        assert!(decoder.is_finished());
    }

    #[test]
    fn str_aliases_write_and_borrow_without_validation() {
        let mut buffer = [0u8; 16];
        let mut encoder = Encoder::new(&mut buffer);
        encoder.str(b"hi\xff").unwrap();
        let used = encoder.len();
        assert_eq!(&buffer[..used], &[0x63, b'h', b'i', 0xff]);

        let mut decoder = Decoder::new(&buffer[..used]);
        assert_eq!(decoder.str_ref().unwrap(), b"hi\xff");
    }

    #[test]
    fn encoded_value_appends_only_complete_items() {
        let mut buffer = [0u8; 16];
        let mut encoder = Encoder::new(&mut buffer);
        encoder.map(1).unwrap();
        encoder.uint(1).unwrap();
        encoder.encoded_value(&[0x01]).unwrap();
        // A truncated nested item must be rejected rather than copied.
        assert_eq!(encoder.encoded_value(&[0x62, b'h']), None);
        let used = encoder.len();
        assert_eq!(&buffer[..used], &[0xa1, 0x01, 0x01]);

        let mut decoder = Decoder::new(&buffer[..used]);
        decoder.skip().unwrap();
        assert!(decoder.is_finished());
    }

    #[test]
    fn bool_and_or_text_forms_are_accepted() {
        let mut buffer = [0u8; 8];
        {
            let mut encoder = Encoder::new(&mut buffer);
            encoder.bool(true).unwrap();
        }
        let mut decoder = Decoder::new(&buffer[..1]);
        assert_eq!(decoder.boolean_or_text(), Some(true));

        // CBOR text `true` (0x64 "true"), as schema/JSON adapters send it.
        let mut decoder = Decoder::new(&[0x64, b't', b'r', b'u', b'e']);
        assert_eq!(decoder.boolean_or_text(), Some(true));
    }

    #[test]
    fn skip_walks_nested_maps_and_arrays() {
        let mut buffer = [0u8; 16];
        let mut encoder = Encoder::new(&mut buffer);
        encoder.map(1).unwrap();
        encoder.uint(1).unwrap();
        encoder.array(2).unwrap();
        encoder.uint(1).unwrap();
        encoder.str(b"x").unwrap();
        let used = encoder.len();

        let mut decoder = Decoder::new(&buffer[..used]);
        decoder.skip().unwrap();
        assert!(decoder.is_finished());
    }

    #[test]
    fn alloc_encode_helpers_match_fixed_buffer_output() {
        let mut dynamic = alloc::vec::Vec::new();
        encode::map(1, &mut dynamic);
        encode::uint(3, &mut dynamic);
        encode::bytes(b"xy", &mut dynamic);
        encode::boolean(false, &mut dynamic);

        let mut buffer = [0u8; 16];
        let used = {
            let mut encoder = Encoder::new(&mut buffer);
            encoder.map(1).unwrap();
            encoder.uint(3).unwrap();
            encoder.bytes(b"xy").unwrap();
            encoder.boolean(false).unwrap();
            encoder.len()
        };
        assert_eq!(dynamic, buffer[..used]);
    }
}
