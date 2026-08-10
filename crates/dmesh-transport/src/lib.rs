#![no_std]

//! Bounded, bearer-neutral reliable streams.
//!
//! This crate deliberately knows nothing about UDP, radio security, files, or
//! flashing.  A bearer supplies datagram boundaries and peer identity; the
//! caller supplies storage and time.  The wire format is QUIC-inspired, but
//! plaintext and intentionally not QUIC wire compatible.

use core::cmp::{max, min};

pub const FLAG_FIXED: u8 = 0x40;
pub const FLAG_SPIN: u8 = 0x20;
pub const FLAG_RESERVED: u8 = 0x18;
pub const FLAG_KEY_PHASE: u8 = 0x04;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConnectionId(u64);

impl ConnectionId {
    pub const fn new(value: u64) -> Option<Self> {
        if value < (1u64 << 62) { Some(Self(value)) } else { None }
    }

    pub const fn value(self) -> u64 { self.0 }

    /// The first two bits of the first CID byte encode total length.
    pub const fn encoded_len(self) -> usize {
        if self.0 <= 0x3f { 1 }
        else if self.0 <= 0x3fff { 2 }
        else if self.0 <= 0x3fff_ffff { 4 }
        else { 8 }
    }

    pub fn encode(self, out: &mut [u8]) -> Result<usize, Error> {
        let n = self.encoded_len();
        if out.len() < n { return Err(Error::BufferTooSmall); }
        let tag = match n { 1 => 0, 2 => 1, 4 => 2, _ => 3 } << 6;
        for i in 0..n { out[i] = (self.0 >> (8 * (n - i - 1))) as u8; }
        out[0] = (out[0] & 0x3f) | tag;
        Ok(n)
    }

    pub fn decode(input: &[u8]) -> Result<(Self, usize), Error> {
        if input.is_empty() { return Err(Error::Truncated); }
        let n = match input[0] >> 6 { 0 => 1, 1 => 2, 2 => 4, _ => 8 };
        if input.len() < n { return Err(Error::Truncated); }
        let mut value = (input[0] & 0x3f) as u64;
        for &b in &input[1..n] { value = (value << 8) | b as u64; }
        Ok((Self(value), n))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    BufferTooSmall,
    Truncated,
    Invalid,
    InvalidVarint,
    FlowControl,
    StreamLimit,
}

pub fn put_varint(value: u64, out: &mut [u8]) -> Result<usize, Error> {
    let n = if value < (1 << 6) { 1 } else if value < (1 << 14) { 2 }
        else if value < (1 << 30) { 4 } else if value < (1 << 62) { 8 } else { return Err(Error::InvalidVarint) };
    if out.len() < n { return Err(Error::BufferTooSmall); }
    let tag = match n { 1 => 0, 2 => 1, 4 => 2, _ => 3 } << 6;
    for i in 0..n { out[i] = (value >> (8 * (n - i - 1))) as u8; }
    out[0] = (out[0] & 0x3f) | tag;
    Ok(n)
}

pub fn get_varint(input: &[u8]) -> Result<(u64, usize), Error> {
    if input.is_empty() { return Err(Error::Truncated); }
    let n = 1usize << (input[0] >> 6);
    if input.len() < n { return Err(Error::Truncated); }
    let mut value = (input[0] & 0x3f) as u64;
    for &b in &input[1..n] { value = (value << 8) | b as u64; }
    Ok((value, n))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShortHeader {
    pub flags: u8,
    pub dcid: ConnectionId,
    pub packet_number: u32,
    pub packet_number_len: u8,
}

impl ShortHeader {
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
        let pn_len = self.packet_number_len.clamp(1, 4) as usize;
        let cid_len = self.dcid.encoded_len();
        if out.len() < 1 + cid_len + pn_len { return Err(Error::BufferTooSmall); }
        out[0] = (self.flags & !(FLAG_RESERVED | FLAG_KEY_PHASE)) | FLAG_FIXED
            | ((pn_len as u8 - 1) & 3);
        let n = self.dcid.encode(&mut out[1..])?;
        for i in 0..pn_len { out[1 + n + i] = (self.packet_number >> (8 * (pn_len - i - 1))) as u8; }
        Ok(1 + n + pn_len)
    }

    pub fn decode(input: &[u8]) -> Result<(Self, usize), Error> {
        if input.is_empty() { return Err(Error::Truncated); }
        if input[0] & FLAG_FIXED == 0 || input[0] & FLAG_RESERVED != 0 || input[0] & FLAG_KEY_PHASE != 0 {
            return Err(Error::Invalid);
        }
        let pn_len = ((input[0] & 3) + 1) as usize;
        let (dcid, cid_len) = ConnectionId::decode(&input[1..])?;
        if input.len() < 1 + cid_len + pn_len { return Err(Error::Truncated); }
        let mut pn = 0u32;
        for &b in &input[1 + cid_len..1 + cid_len + pn_len] { pn = (pn << 8) | b as u32; }
        Ok((Self { flags: input[0], dcid, packet_number: pn, packet_number_len: pn_len as u8 }, 1 + cid_len + pn_len))
    }
}

pub const FRAME_PADDING: u64 = 0x00;
pub const FRAME_PING: u64 = 0x01;
pub const FRAME_ACK: u64 = 0x02;
pub const FRAME_STREAM_BASE: u64 = 0x08;
pub const FRAME_MAX_DATA: u64 = 0x10;
pub const FRAME_MAX_STREAM_DATA: u64 = 0x11;
pub const FRAME_MAX_STREAMS_BIDI: u64 = 0x12;
pub const FRAME_MAX_STREAMS_UNI: u64 = 0x13;
pub const FRAME_CONNECTION_CLOSE: u64 = 0x1c;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StreamFrame<'a> { pub id: u64, pub offset: u64, pub fin: bool, pub data: &'a [u8] }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Frame<'a> {
    Padding,
    Ping,
    Ack { largest: u32, delay: u64 },
    Stream(StreamFrame<'a>),
    MaxData(u64),
    MaxStreamData { id: u64, max: u64 },
    MaxStreamsBidi(u64),
    MaxStreamsUni(u64),
    Close { code: u64 },
}

impl<'a> Frame<'a> {
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
        let mut p = 0;
        let put = |v: u64, out: &mut [u8], p: &mut usize| -> Result<(), Error> { let n = put_varint(v, &mut out[*p..])?; *p += n; Ok(()) };
        match self {
            Frame::Padding => { if out.is_empty() { return Err(Error::BufferTooSmall); } out[0] = FRAME_PADDING as u8; Ok(1) }
            Frame::Ping => { if out.is_empty() { return Err(Error::BufferTooSmall); } out[0] = FRAME_PING as u8; Ok(1) }
            Frame::Ack { largest, delay } => {
                put(FRAME_ACK, out, &mut p)?; put(*largest as u64, out, &mut p)?; put(*delay, out, &mut p)?;
                put(0, out, &mut p)?; put(0, out, &mut p)?; Ok(p)
            }
            Frame::Stream(s) => {
                let typ = FRAME_STREAM_BASE | 0x04 | 0x02 | if s.fin { 1 } else { 0 };
                put(typ, out, &mut p)?; put(s.id, out, &mut p)?; put(s.offset, out, &mut p)?; put(s.data.len() as u64, out, &mut p)?;
                if out.len() < p + s.data.len() { return Err(Error::BufferTooSmall); }
                out[p..p + s.data.len()].copy_from_slice(s.data); Ok(p + s.data.len())
            }
            Frame::MaxData(v) => { put(FRAME_MAX_DATA, out, &mut p)?; put(*v, out, &mut p)?; Ok(p) }
            Frame::MaxStreamData { id, max } => { put(FRAME_MAX_STREAM_DATA, out, &mut p)?; put(*id, out, &mut p)?; put(*max, out, &mut p)?; Ok(p) }
            Frame::MaxStreamsBidi(v) => { put(FRAME_MAX_STREAMS_BIDI, out, &mut p)?; put(*v, out, &mut p)?; Ok(p) }
            Frame::MaxStreamsUni(v) => { put(FRAME_MAX_STREAMS_UNI, out, &mut p)?; put(*v, out, &mut p)?; Ok(p) }
            Frame::Close { code } => { put(FRAME_CONNECTION_CLOSE, out, &mut p)?; put(*code, out, &mut p)?; put(0, out, &mut p)?; Ok(p) }
        }
    }
}

pub fn decode_frame<'a>(input: &'a [u8]) -> Result<(Frame<'a>, usize), Error> {
    let (typ, mut p) = get_varint(input)?;
    match typ {
        FRAME_PADDING => Ok((Frame::Padding, p)),
        FRAME_PING => Ok((Frame::Ping, p)),
        FRAME_ACK => { let (largest, n) = get_varint(&input[p..])?; p += n; let (delay, n) = get_varint(&input[p..])?; p += n; let (ranges, n) = get_varint(&input[p..])?; p += n; let (_first, n) = get_varint(&input[p..])?; p += n; if ranges != 0 { return Err(Error::Invalid); } Ok((Frame::Ack { largest: largest as u32, delay }, p)) }
        FRAME_MAX_DATA => { let (v, n) = get_varint(&input[p..])?; Ok((Frame::MaxData(v), p + n)) }
        FRAME_MAX_STREAM_DATA => { let (id, n) = get_varint(&input[p..])?; p += n; let (max, n) = get_varint(&input[p..])?; Ok((Frame::MaxStreamData { id, max }, p + n)) }
        FRAME_MAX_STREAMS_BIDI => { let (v, n) = get_varint(&input[p..])?; Ok((Frame::MaxStreamsBidi(v), p + n)) }
        FRAME_MAX_STREAMS_UNI => { let (v, n) = get_varint(&input[p..])?; Ok((Frame::MaxStreamsUni(v), p + n)) }
        FRAME_CONNECTION_CLOSE => { let (code, n) = get_varint(&input[p..])?; p += n; let (len, n) = get_varint(&input[p..])?; p += n; if input.len() < p + len as usize { return Err(Error::Truncated); } Ok((Frame::Close { code }, p + len as usize)) }
        t if (FRAME_STREAM_BASE..=FRAME_STREAM_BASE + 7).contains(&t) => {
            let (id, n) = get_varint(&input[p..])?; p += n;
            let offset = if t & 4 != 0 { let (v, n) = get_varint(&input[p..])?; p += n; v } else { 0 };
            let len = if t & 2 != 0 { let (v, n) = get_varint(&input[p..])?; p += n; v as usize } else { input.len() - p };
            if input.len() < p + len { return Err(Error::Truncated); }
            Ok((Frame::Stream(StreamFrame { id, offset, fin: t & 1 != 0, data: &input[p..p + len] }), p + len))
        }
        _ => Err(Error::Invalid),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AckRange { pub start: u32, pub end: u32 }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AckRanges<const N: usize> { ranges: [AckRange; N], len: usize }

impl<const N: usize> AckRanges<N> {
    pub const fn new() -> Self { Self { ranges: [AckRange { start: 0, end: 0 }; N], len: 0 } }
    pub fn len(&self) -> usize { self.len }
    pub fn get(&self, i: usize) -> Option<AckRange> { if i < self.len { Some(self.ranges[i]) } else { None } }
    pub fn insert(&mut self, pn: u32) {
        for i in 0..self.len {
            let r = self.ranges[i];
            if pn >= r.start.saturating_sub(1) && pn <= r.end.saturating_add(1) {
                self.ranges[i].start = min(r.start, pn); self.ranges[i].end = max(r.end, pn);
                if i > 0 && self.ranges[i - 1].start <= self.ranges[i].end.saturating_add(1) {
                    self.ranges[i - 1].start = min(self.ranges[i - 1].start, self.ranges[i].start);
                    self.ranges[i - 1].end = max(self.ranges[i - 1].end, self.ranges[i].end);
                    for j in i..self.len - 1 { self.ranges[j] = self.ranges[j + 1]; }
                    self.len -= 1;
                } else if i + 1 < self.len && self.ranges[i].start <= self.ranges[i + 1].end.saturating_add(1) {
                    self.ranges[i].start = min(self.ranges[i].start, self.ranges[i + 1].start);
                    self.ranges[i].end = max(self.ranges[i].end, self.ranges[i + 1].end);
                    for j in i + 1..self.len - 1 { self.ranges[j] = self.ranges[j + 1]; }
                    self.len -= 1;
                }
                return;
            }
            if pn > r.end { if self.len < N { for j in (i..self.len).rev() { self.ranges[j + 1] = self.ranges[j]; } self.ranges[i] = AckRange { start: pn, end: pn }; self.len += 1; } return; }
        }
        if self.len < N { self.ranges[self.len] = AckRange { start: pn, end: pn }; self.len += 1; }
    }
    pub fn contains(&self, pn: u32) -> bool { (0..self.len).any(|i| pn >= self.ranges[i].start && pn <= self.ranges[i].end) }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FlowControl { pub max_data: u64, pub consumed: u64 }

impl FlowControl {
    pub const fn new(max_data: u64) -> Self { Self { max_data, consumed: 0 } }
    pub fn can_receive(&self, end: u64) -> bool { end <= self.max_data }
    pub fn consume(&mut self, n: u64) { self.consumed = self.consumed.saturating_add(n); }
    pub fn extend(&mut self, credit: u64) { self.max_data = max(self.max_data, self.consumed.saturating_add(credit)); }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StreamState { pub id: u64, pub max_data: u64, pub received: u64, pub consumed: u64, pub finished: bool }

impl StreamState {
    pub const fn new(id: u64, max_data: u64) -> Self { Self { id, max_data, received: 0, consumed: 0, finished: false } }
    pub fn accept(&mut self, offset: u64, len: usize, fin: bool) -> Result<(), Error> {
        let end = offset.checked_add(len as u64).ok_or(Error::FlowControl)?;
        if end > self.max_data { return Err(Error::FlowControl); }
        self.received = max(self.received, end); self.finished |= fin; Ok(())
    }
    pub fn consume(&mut self, n: u64) { self.consumed = min(self.received, self.consumed.saturating_add(n)); }
    pub fn extend(&mut self, credit: u64) { self.max_data = max(self.max_data, self.consumed.saturating_add(credit)); }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Role { Client, Server }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConnectionLimits {
    pub max_data: u64,
    pub max_stream_data: u64,
    pub max_streams_bidi: u64,
    pub max_streams_uni: u64,
}

impl Default for ConnectionLimits {
    fn default() -> Self { Self { max_data: 256 * 1024, max_stream_data: 64 * 1024, max_streams_bidi: 1, max_streams_uni: 2 } }
}

/// Bounded stream accounting. Packet scheduling and bearer I/O remain in the caller.
pub struct ConnectionState<const N: usize> {
    pub role: Role,
    pub connection: FlowControl,
    pub limits: ConnectionLimits,
    pub received_data: u64,
    streams: [Option<StreamState>; N],
}

impl<const N: usize> ConnectionState<N> {
    pub fn new(role: Role, limits: ConnectionLimits) -> Self {
        Self { role, connection: FlowControl::new(limits.max_data), limits, received_data: 0, streams: [None; N] }
    }

    fn stream_kind(id: u64) -> (bool, bool) { (id & 1 != 0, id & 2 != 0) }

    fn stream_count(&self, uni: bool, local: bool) -> u64 {
        self.streams.iter().flatten().filter(|s| {
            let (server, is_uni) = Self::stream_kind(s.id);
            is_uni == uni && (server == matches!(self.role, Role::Server)) == local
        }).count() as u64
    }

    pub fn open(&mut self, id: u64) -> Result<&mut StreamState, Error> {
        let (server, uni) = Self::stream_kind(id);
        let local = server == matches!(self.role, Role::Server);
        if !local { return Err(Error::Invalid); }
        let limit = if uni { self.limits.max_streams_uni } else { self.limits.max_streams_bidi };
        if self.stream_count(uni, local) >= limit { return Err(Error::StreamLimit); }
        self.insert_stream(id)
    }

    pub fn accept(&mut self, id: u64, offset: u64, len: usize, fin: bool) -> Result<&mut StreamState, Error> {
        let slot = if let Some(i) = self.find(id) { i } else {
            let (server, uni) = Self::stream_kind(id);
            let local = server == matches!(self.role, Role::Server);
            if local { return Err(Error::Invalid); }
            let limit = if uni { self.limits.max_streams_uni } else { self.limits.max_streams_bidi };
            if self.stream_count(uni, local) >= limit { return Err(Error::StreamLimit); }
            self.insert_stream(id)?;
            self.find(id).ok_or(Error::Invalid)?
        };
        let end = offset.checked_add(len as u64).ok_or(Error::FlowControl)?;
        let previous = self.streams[slot].as_ref().ok_or(Error::Invalid)?.received;
        let delta = end.saturating_sub(previous);
        if !self.connection.can_receive(self.received_data.saturating_add(delta)) { return Err(Error::FlowControl); }
        self.received_data = self.received_data.saturating_add(delta);
        self.streams[slot].as_mut().ok_or(Error::Invalid)?.accept(offset, len, fin)?;
        Ok(self.streams[slot].as_mut().unwrap())
    }

    pub fn consume(&mut self, id: u64, n: u64) -> Result<(), Error> {
        let i = self.find(id).ok_or(Error::Invalid)?;
        self.streams[i].as_mut().ok_or(Error::Invalid)?.consume(n); self.connection.consume(n); Ok(())
    }

    fn find(&self, id: u64) -> Option<usize> { self.streams.iter().position(|s| s.map(|v| v.id) == Some(id)) }
    fn insert_stream(&mut self, id: u64) -> Result<&mut StreamState, Error> {
        let i = self.streams.iter().position(Option::is_none).ok_or(Error::StreamLimit)?;
        self.streams[i] = Some(StreamState::new(id, self.limits.max_stream_data)); Ok(self.streams[i].as_mut().unwrap())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_id_lengths_round_trip() {
        for value in [0, 0x3f, 0x40, 0x3fff, 0x4000, 0x3fff_ffff, 0x4000_0000, (1u64 << 62) - 1] {
            let id = ConnectionId::new(value).unwrap(); let mut b = [0; 8]; let n = id.encode(&mut b).unwrap();
            assert_eq!(n, id.encoded_len()); assert_eq!(ConnectionId::decode(&b[..n]).unwrap(), (id, n));
        }
    }

    #[test]
    fn varints_use_two_length_bits() {
        for value in [0, 63, 64, 16383, 16384, (1 << 30) - 1, 1 << 30] {
            let mut b = [0; 8]; let n = put_varint(value, &mut b).unwrap(); assert_eq!(get_varint(&b[..n]).unwrap(), (value, n));
        }
    }

    #[test]
    fn ack_ranges_merge_and_deduplicate() {
        let mut a = AckRanges::<4>::new(); for p in [4, 2, 3, 9, 8, 3] { a.insert(p); }
        assert_eq!(a.get(0), Some(AckRange { start: 8, end: 9 })); assert_eq!(a.get(1), Some(AckRange { start: 2, end: 4 })); assert!(a.contains(3));
    }

    #[test]
    fn short_header_round_trip_uses_variable_cid() {
        for value in [1, 0x1234, 0x1234_5678, 0x1234_5678_9abc_def0] {
            let mut b = [0u8; 32];
            let h = ShortHeader { flags: FLAG_FIXED, dcid: ConnectionId::new(value).unwrap(), packet_number: 0xabcdef, packet_number_len: 3 };
            let n = h.encode(&mut b).unwrap();
            let (decoded, used) = ShortHeader::decode(&b[..n]).unwrap();
            assert_eq!(used, n); assert_eq!(decoded.dcid, h.dcid); assert_eq!(decoded.packet_number, h.packet_number); assert_eq!(decoded.packet_number_len, h.packet_number_len);
        }
    }

    #[test]
    fn stream_and_flow_frames_round_trip() {
        let data = [1, 2, 3, 4];
        for frame in [
            Frame::Stream(StreamFrame { id: 7, offset: 4096, fin: true, data: &data }),
            Frame::MaxData(1000),
            Frame::MaxStreamData { id: 7, max: 2000 },
            Frame::MaxStreamsUni(2),
        ] {
            let mut b = [0u8; 64]; let n = frame.encode(&mut b).unwrap();
            assert_eq!(decode_frame(&b[..n]).unwrap(), (frame, n));
        }
    }

    #[test]
    fn connection_and_stream_credit_are_bounded() {
        let limits = ConnectionLimits { max_data: 8, max_stream_data: 8, max_streams_bidi: 1, max_streams_uni: 1 };
        let mut c = ConnectionState::<2>::new(Role::Server, limits);
        assert!(c.accept(0, 0, 5, false).is_ok());
        assert_eq!(c.accept(0, 5, 4, false), Err(Error::FlowControl));
        assert!(c.consume(0, 5).is_ok());
    }
}
