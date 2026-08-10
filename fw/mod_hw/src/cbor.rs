#![allow(dead_code)]

/// Small CBOR subset used by the hardware module. Requests are arrays of
/// unsigned integers; events are arrays of unsigned integers. This avoids a
/// dependency on a general decoder in the tiny flat image.
pub struct Reader<'a> {
    input: &'a [u8],
    pos: usize,
    remaining: usize,
}

impl<'a> Reader<'a> {
    pub fn array(input: &'a [u8]) -> Option<Self> {
        let (major, value, used) = head(input)?;
        if major != 4 || value > 32 { return None; }
        Some(Self { input: &input[used..], pos: 0, remaining: value as usize })
    }

    pub fn next_u64(&mut self) -> Option<u64> {
        if self.remaining == 0 { return None; }
        let (major, value, used) = head(&self.input[self.pos..])?;
        if major != 0 { return None; }
        self.pos += used;
        self.remaining -= 1;
        Some(value)
    }

    pub fn done(&self) -> bool { self.remaining == 0 && self.pos == self.input.len() }
    pub fn remaining(&self) -> usize { self.remaining }
}

pub struct Encoder<'a> {
    out: &'a mut [u8],
    pos: usize,
    count: usize,
}

impl<'a> Encoder<'a> {
    pub fn array(out: &'a mut [u8], count: usize) -> Option<Self> {
        let mut encoder = Self { out, pos: 0, count: 0 };
        encoder.head(4, count as u64)?;
        Some(encoder)
    }

    pub fn u64(&mut self, value: u64) -> Option<()> {
        self.head(0, value)?;
        self.count += 1;
        Some(())
    }

    pub fn len(&self) -> usize { self.pos }

    fn head(&mut self, major: u8, value: u64) -> Option<()> {
        let (initial, extra) = if value < 24 {
            ((major << 5) | value as u8, 0)
        } else if value <= u8::MAX as u64 {
            ((major << 5) | 24, 1)
        } else if value <= u16::MAX as u64 {
            ((major << 5) | 25, 2)
        } else if value <= u32::MAX as u64 {
            ((major << 5) | 26, 4)
        } else {
            ((major << 5) | 27, 8)
        };
        if self.pos + 1 + extra > self.out.len() { return None; }
        self.out[self.pos] = initial;
        self.pos += 1;
        for index in 0..extra {
            self.out[self.pos + index] = (value >> (8 * (extra - index - 1))) as u8;
        }
        self.pos += extra;
        Some(())
    }
}

fn head(input: &[u8]) -> Option<(u8, u64, usize)> {
    let first = *input.first()?;
    let major = first >> 5;
    let additional = first & 0x1f;
    if additional < 24 { return Some((major, additional as u64, 1)); }
    let bytes = match additional { 24 => 1, 25 => 2, 26 => 4, 27 => 8, _ => return None };
    if input.len() < bytes + 1 { return None; }
    let mut value = 0u64;
    for byte in &input[1..=bytes] { value = (value << 8) | *byte as u64; }
    Some((major, value, bytes + 1))
}
