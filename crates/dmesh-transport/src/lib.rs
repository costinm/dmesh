#![no_std]

//! Bounded, bearer-neutral reliable streams.
//!
//! This crate deliberately knows nothing about UDP, radio security, files, or
//! flashing.  A bearer supplies datagram boundaries and peer identity; the
//! caller supplies storage and time.  The wire format is QUIC-inspired, but
//! plaintext and intentionally not QUIC wire compatible.

#[cfg(test)]
extern crate std;

use core::cmp::{max, min};

pub const FLAG_FIXED: u8 = 0x40;
pub const FLAG_SPIN: u8 = 0x20;
pub const FLAG_RESERVED: u8 = 0x18;
pub const FLAG_KEY_PHASE: u8 = 0x04;

/// Shared benchmark stream envelope used by the host and ESP32 test paths.
/// It is intentionally separate from the production object-store protocol so
/// an iperf-like run can vary bearer parameters without changing semantics.
pub const BENCH_MAGIC: [u8; 4] = *b"DMTB";
pub const BENCH_CONNECTION_ID: u64 = 0x1234;
pub const BENCH_STREAM_ID: u64 = 0;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConnectionId(u64);

impl ConnectionId {
    pub const fn new(value: u64) -> Option<Self> {
        if value < (1u64 << 62) {
            Some(Self(value))
        } else {
            None
        }
    }

    pub const fn value(self) -> u64 {
        self.0
    }

    /// The first two bits of the first CID byte encode total length.
    pub const fn encoded_len(self) -> usize {
        if self.0 <= 0x3f {
            1
        } else if self.0 <= 0x3fff {
            2
        } else if self.0 <= 0x3fff_ffff {
            4
        } else {
            8
        }
    }

    pub fn encode(self, out: &mut [u8]) -> Result<usize, Error> {
        let n = self.encoded_len();
        if out.len() < n {
            return Err(Error::BufferTooSmall);
        }
        let tag = match n {
            1 => 0,
            2 => 1,
            4 => 2,
            _ => 3,
        } << 6;
        for i in 0..n {
            out[i] = (self.0 >> (8 * (n - i - 1))) as u8;
        }
        out[0] = (out[0] & 0x3f) | tag;
        Ok(n)
    }

    pub fn decode(input: &[u8]) -> Result<(Self, usize), Error> {
        if input.is_empty() {
            return Err(Error::Truncated);
        }
        let n = match input[0] >> 6 {
            0 => 1,
            1 => 2,
            2 => 4,
            _ => 8,
        };
        if input.len() < n {
            return Err(Error::Truncated);
        }
        let mut value = (input[0] & 0x3f) as u64;
        for &b in &input[1..n] {
            value = (value << 8) | b as u64;
        }
        Ok((Self(value), n))
    }
}

/// Compact bearer envelope used by radio adapters around transport packets.
/// It is deliberately transport-owned: object stores provide stream bytes and
/// do not need to know how a NAN/action bearer identifies a peer.
pub const ENVELOPE_MAGIC: u32 = 0x4452_5332;
pub const ENVELOPE_VERSION: u8 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeerKey {
    pub wifi_mac: [u8; 6],
    pub dcid: ConnectionId,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnvelopeError { BufferTooSmall, Truncated, BadMagic, Invalid }

pub fn encode_envelope(key: PeerKey, kind: u8, payload: &[u8], out: &mut [u8]) -> Result<usize, EnvelopeError> {
    let mut cid = [0u8; 8];
    let cid_len = key.dcid.encode(&mut cid).map_err(|_| EnvelopeError::Invalid)?;
    let need = 4 + 1 + 1 + 6 + 1 + cid_len + payload.len();
    if out.len() < need { return Err(EnvelopeError::BufferTooSmall); }
    out[0..4].copy_from_slice(&ENVELOPE_MAGIC.to_be_bytes());
    out[4] = ENVELOPE_VERSION;
    out[5] = kind;
    out[6..12].copy_from_slice(&key.wifi_mac);
    out[12] = cid_len as u8;
    out[13..13 + cid_len].copy_from_slice(&cid[..cid_len]);
    out[13 + cid_len..need].copy_from_slice(payload);
    Ok(need)
}

pub fn decode_envelope(input: &[u8]) -> Result<(PeerKey, u8, &[u8]), EnvelopeError> {
    if input.len() < 14 || u32::from_be_bytes(input[0..4].try_into().map_err(|_| EnvelopeError::Truncated)?) != ENVELOPE_MAGIC || input[4] != ENVELOPE_VERSION {
        return Err(EnvelopeError::BadMagic);
    }
    let cid_len = input[12] as usize;
    if !matches!(cid_len, 1 | 2 | 4 | 8) || input.len() < 13 + cid_len { return Err(EnvelopeError::Truncated); }
    let (dcid, _) = ConnectionId::decode(&input[13..]).map_err(|_| EnvelopeError::Invalid)?;
    let mut wifi_mac = [0u8; 6];
    wifi_mac.copy_from_slice(&input[6..12]);
    Ok((PeerKey { wifi_mac, dcid }, input[5], &input[13 + cid_len..]))
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
    let n = if value < (1 << 6) {
        1
    } else if value < (1 << 14) {
        2
    } else if value < (1 << 30) {
        4
    } else if value < (1 << 62) {
        8
    } else {
        return Err(Error::InvalidVarint);
    };
    if out.len() < n {
        return Err(Error::BufferTooSmall);
    }
    let tag = match n {
        1 => 0,
        2 => 1,
        4 => 2,
        _ => 3,
    } << 6;
    for i in 0..n {
        out[i] = (value >> (8 * (n - i - 1))) as u8;
    }
    out[0] = (out[0] & 0x3f) | tag;
    Ok(n)
}

pub fn get_varint(input: &[u8]) -> Result<(u64, usize), Error> {
    if input.is_empty() {
        return Err(Error::Truncated);
    }
    let n = 1usize << (input[0] >> 6);
    if input.len() < n {
        return Err(Error::Truncated);
    }
    let mut value = (input[0] & 0x3f) as u64;
    for &b in &input[1..n] {
        value = (value << 8) | b as u64;
    }
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
        if out.len() < 1 + cid_len + pn_len {
            return Err(Error::BufferTooSmall);
        }
        out[0] = (self.flags & !(FLAG_RESERVED | FLAG_KEY_PHASE))
            | FLAG_FIXED
            | ((pn_len as u8 - 1) & 3);
        let n = self.dcid.encode(&mut out[1..])?;
        for i in 0..pn_len {
            out[1 + n + i] = (self.packet_number >> (8 * (pn_len - i - 1))) as u8;
        }
        Ok(1 + n + pn_len)
    }

    pub fn decode(input: &[u8]) -> Result<(Self, usize), Error> {
        if input.is_empty() {
            return Err(Error::Truncated);
        }
        if input[0] & FLAG_FIXED == 0
            || input[0] & FLAG_RESERVED != 0
            || input[0] & FLAG_KEY_PHASE != 0
        {
            return Err(Error::Invalid);
        }
        let pn_len = ((input[0] & 3) + 1) as usize;
        let (dcid, cid_len) = ConnectionId::decode(&input[1..])?;
        if input.len() < 1 + cid_len + pn_len {
            return Err(Error::Truncated);
        }
        let mut pn = 0u32;
        for &b in &input[1 + cid_len..1 + cid_len + pn_len] {
            pn = (pn << 8) | b as u32;
        }
        Ok((
            Self {
                flags: input[0],
                dcid,
                packet_number: pn,
                packet_number_len: pn_len as u8,
            },
            1 + cid_len + pn_len,
        ))
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
pub struct StreamFrame<'a> {
    pub id: u64,
    pub offset: u64,
    pub fin: bool,
    pub data: &'a [u8],
}

/// Encode one bounded benchmark datagram (magic, short header, stream frame).
pub fn encode_bench_stream(
    packet_number: u32,
    offset: u64,
    fin: bool,
    data: &[u8],
    out: &mut [u8],
) -> Result<usize, Error> {
    if out.len() < BENCH_MAGIC.len() {
        return Err(Error::BufferTooSmall);
    }
    out[..BENCH_MAGIC.len()].copy_from_slice(&BENCH_MAGIC);
    let header = ShortHeader {
        flags: FLAG_FIXED,
        dcid: ConnectionId::new(BENCH_CONNECTION_ID).ok_or(Error::Invalid)?,
        packet_number,
        packet_number_len: 2,
    };
    let header_len = header.encode(&mut out[BENCH_MAGIC.len()..])?;
    let frame = Frame::Stream(StreamFrame {
        id: BENCH_STREAM_ID,
        offset,
        fin,
        data,
    });
    let frame_len = frame.encode(&mut out[BENCH_MAGIC.len() + header_len..])?;
    Ok(BENCH_MAGIC.len() + header_len + frame_len)
}

/// Decode and validate one benchmark datagram, returning the stream frame and
/// the number of consumed bytes (excluding any optional monitor trailer).
pub fn decode_bench_stream(input: &[u8]) -> Result<(ShortHeader, StreamFrame<'_>, usize), Error> {
    if input.len() < BENCH_MAGIC.len() || input[..BENCH_MAGIC.len()] != BENCH_MAGIC {
        return Err(Error::Invalid);
    }
    let (header, header_len) = ShortHeader::decode(&input[BENCH_MAGIC.len()..])?;
    if header.dcid.value() != BENCH_CONNECTION_ID {
        return Err(Error::Invalid);
    }
    let (frame, frame_len) = decode_frame(&input[BENCH_MAGIC.len() + header_len..])?;
    let Frame::Stream(stream) = frame else {
        return Err(Error::Invalid);
    };
    if stream.id != BENCH_STREAM_ID {
        return Err(Error::Invalid);
    }
    Ok((header, stream, BENCH_MAGIC.len() + header_len + frame_len))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Frame<'a> {
    Padding,
    Ping,
    Ack {
        largest: u32,
        delay: u64,
    },
    /// QUIC ACK encoding with one largest range and zero or more additional
    /// descending ranges.  The range set is bounded for embedded callers.
    AckRanges {
        largest: u32,
        delay: u64,
        ranges: AckRangeSet,
    },
    Stream(StreamFrame<'a>),
    MaxData(u64),
    MaxStreamData {
        id: u64,
        max: u64,
    },
    MaxStreamsBidi(u64),
    MaxStreamsUni(u64),
    Close {
        code: u64,
    },
}

impl<'a> Frame<'a> {
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
        let mut p = 0;
        let put = |v: u64, out: &mut [u8], p: &mut usize| -> Result<(), Error> {
            let n = put_varint(v, &mut out[*p..])?;
            *p += n;
            Ok(())
        };
        match self {
            Frame::Padding => {
                if out.is_empty() {
                    return Err(Error::BufferTooSmall);
                }
                out[0] = FRAME_PADDING as u8;
                Ok(1)
            }
            Frame::Ping => {
                if out.is_empty() {
                    return Err(Error::BufferTooSmall);
                }
                out[0] = FRAME_PING as u8;
                Ok(1)
            }
            Frame::Ack { largest, delay } => {
                put(FRAME_ACK, out, &mut p)?;
                put(*largest as u64, out, &mut p)?;
                put(*delay, out, &mut p)?;
                put(0, out, &mut p)?;
                put(0, out, &mut p)?;
                Ok(p)
            }
            Frame::AckRanges {
                largest,
                delay,
                ranges,
            } => {
                if ranges.len() == 0 || ranges.get(0).map(|range| range.end) != Some(*largest) {
                    return Err(Error::Invalid);
                }
                put(FRAME_ACK, out, &mut p)?;
                put(*largest as u64, out, &mut p)?;
                put(*delay, out, &mut p)?;
                put((ranges.len() - 1) as u64, out, &mut p)?;
                let first = ranges.get(0).ok_or(Error::Invalid)?;
                put(u64::from(first.end - first.start), out, &mut p)?;
                for i in 1..ranges.len() {
                    let previous = ranges.get(i - 1).ok_or(Error::Invalid)?;
                    let current = ranges.get(i).ok_or(Error::Invalid)?;
                    let gap = u64::from(previous.start)
                        .checked_sub(u64::from(current.end) + 2)
                        .ok_or(Error::Invalid)?;
                    put(gap, out, &mut p)?;
                    put(u64::from(current.end - current.start), out, &mut p)?;
                }
                Ok(p)
            }
            Frame::Stream(s) => {
                let typ = FRAME_STREAM_BASE | 0x04 | 0x02 | if s.fin { 1 } else { 0 };
                put(typ, out, &mut p)?;
                put(s.id, out, &mut p)?;
                put(s.offset, out, &mut p)?;
                put(s.data.len() as u64, out, &mut p)?;
                if out.len() < p + s.data.len() {
                    return Err(Error::BufferTooSmall);
                }
                out[p..p + s.data.len()].copy_from_slice(s.data);
                Ok(p + s.data.len())
            }
            Frame::MaxData(v) => {
                put(FRAME_MAX_DATA, out, &mut p)?;
                put(*v, out, &mut p)?;
                Ok(p)
            }
            Frame::MaxStreamData { id, max } => {
                put(FRAME_MAX_STREAM_DATA, out, &mut p)?;
                put(*id, out, &mut p)?;
                put(*max, out, &mut p)?;
                Ok(p)
            }
            Frame::MaxStreamsBidi(v) => {
                put(FRAME_MAX_STREAMS_BIDI, out, &mut p)?;
                put(*v, out, &mut p)?;
                Ok(p)
            }
            Frame::MaxStreamsUni(v) => {
                put(FRAME_MAX_STREAMS_UNI, out, &mut p)?;
                put(*v, out, &mut p)?;
                Ok(p)
            }
            Frame::Close { code } => {
                put(FRAME_CONNECTION_CLOSE, out, &mut p)?;
                put(*code, out, &mut p)?;
                put(0, out, &mut p)?;
                Ok(p)
            }
        }
    }
}

pub fn decode_frame<'a>(input: &'a [u8]) -> Result<(Frame<'a>, usize), Error> {
    let (typ, mut p) = get_varint(input)?;
    match typ {
        FRAME_PADDING => Ok((Frame::Padding, p)),
        FRAME_PING => Ok((Frame::Ping, p)),
        FRAME_ACK => {
            let (largest, n) = get_varint(&input[p..])?;
            p += n;
            let (delay, n) = get_varint(&input[p..])?;
            p += n;
            let (range_count, n) = get_varint(&input[p..])?;
            p += n;
            let (first_range, n) = get_varint(&input[p..])?;
            p += n;
            if largest > u64::from(u32::MAX) || first_range > largest {
                return Err(Error::Invalid);
            }
            if range_count == 0 {
                return Ok((
                    Frame::Ack {
                        largest: largest as u32,
                        delay,
                    },
                    p,
                ));
            }
            if range_count as usize >= ACK_RANGE_CAPACITY {
                return Err(Error::Invalid);
            }
            let mut ranges = AckRangeSet::new();
            ranges.insert_range(AckRange {
                start: (largest - first_range) as u32,
                end: largest as u32,
            });
            let mut previous_start = largest - first_range;
            for _ in 0..range_count {
                let (gap, n) = get_varint(&input[p..])?;
                p += n;
                let (range, n) = get_varint(&input[p..])?;
                p += n;
                let current_end = previous_start.checked_sub(gap + 2).ok_or(Error::Invalid)?;
                let current_start = current_end.checked_sub(range).ok_or(Error::Invalid)?;
                if current_end > u64::from(u32::MAX) || current_start > u64::from(u32::MAX) {
                    return Err(Error::Invalid);
                }
                ranges.insert_range(AckRange {
                    start: current_start as u32,
                    end: current_end as u32,
                });
                previous_start = current_start;
            }
            Ok((
                Frame::AckRanges {
                    largest: largest as u32,
                    delay,
                    ranges,
                },
                p,
            ))
        }
        FRAME_MAX_DATA => {
            let (v, n) = get_varint(&input[p..])?;
            Ok((Frame::MaxData(v), p + n))
        }
        FRAME_MAX_STREAM_DATA => {
            let (id, n) = get_varint(&input[p..])?;
            p += n;
            let (max, n) = get_varint(&input[p..])?;
            Ok((Frame::MaxStreamData { id, max }, p + n))
        }
        FRAME_MAX_STREAMS_BIDI => {
            let (v, n) = get_varint(&input[p..])?;
            Ok((Frame::MaxStreamsBidi(v), p + n))
        }
        FRAME_MAX_STREAMS_UNI => {
            let (v, n) = get_varint(&input[p..])?;
            Ok((Frame::MaxStreamsUni(v), p + n))
        }
        FRAME_CONNECTION_CLOSE => {
            let (code, n) = get_varint(&input[p..])?;
            p += n;
            let (len, n) = get_varint(&input[p..])?;
            p += n;
            if input.len() < p + len as usize {
                return Err(Error::Truncated);
            }
            Ok((Frame::Close { code }, p + len as usize))
        }
        t if (FRAME_STREAM_BASE..=FRAME_STREAM_BASE + 7).contains(&t) => {
            let (id, n) = get_varint(&input[p..])?;
            p += n;
            let offset = if t & 4 != 0 {
                let (v, n) = get_varint(&input[p..])?;
                p += n;
                v
            } else {
                0
            };
            let len = if t & 2 != 0 {
                let (v, n) = get_varint(&input[p..])?;
                p += n;
                v as usize
            } else {
                input.len() - p
            };
            if input.len() < p + len {
                return Err(Error::Truncated);
            }
            Ok((
                Frame::Stream(StreamFrame {
                    id,
                    offset,
                    fin: t & 1 != 0,
                    data: &input[p..p + len],
                }),
                p + len,
            ))
        }
        _ => Err(Error::Invalid),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AckRange {
    pub start: u32,
    pub end: u32,
}

pub const ACK_RANGE_CAPACITY: usize = 8;
pub type AckRangeSet = AckRanges<ACK_RANGE_CAPACITY>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AckRanges<const N: usize> {
    ranges: [AckRange; N],
    len: usize,
}

impl<const N: usize> AckRanges<N> {
    pub const fn new() -> Self {
        Self {
            ranges: [AckRange { start: 0, end: 0 }; N],
            len: 0,
        }
    }
    pub fn len(&self) -> usize {
        self.len
    }
    pub fn get(&self, i: usize) -> Option<AckRange> {
        if i < self.len {
            Some(self.ranges[i])
        } else {
            None
        }
    }
    pub fn insert(&mut self, pn: u32) {
        self.insert_range(AckRange { start: pn, end: pn });
    }
    pub fn insert_range(&mut self, mut new: AckRange) {
        if new.start > new.end {
            return;
        }
        let mut i = 0;
        while i < self.len {
            let current = self.ranges[i];
            if u64::from(new.start) > u64::from(current.end) + 1 {
                if self.len < N {
                    for j in (i..self.len).rev() {
                        self.ranges[j + 1] = self.ranges[j];
                    }
                    self.ranges[i] = new;
                    self.len += 1;
                }
                return;
            }
            if u64::from(new.end) + 1 < u64::from(current.start) {
                i += 1;
                continue;
            }
            new.start = min(new.start, current.start);
            new.end = max(new.end, current.end);
            for j in i..self.len - 1 {
                self.ranges[j] = self.ranges[j + 1];
            }
            self.len -= 1;
        }
        if self.len < N {
            let mut at = self.len;
            while at > 0 && self.ranges[at - 1].end < new.end {
                self.ranges[at] = self.ranges[at - 1];
                at -= 1;
            }
            self.ranges[at] = new;
            self.len += 1;
        }
    }
    pub fn contains(&self, pn: u32) -> bool {
        (0..self.len).any(|i| pn >= self.ranges[i].start && pn <= self.ranges[i].end)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FlowControl {
    pub max_data: u64,
    pub consumed: u64,
}

impl FlowControl {
    pub const fn new(max_data: u64) -> Self {
        Self {
            max_data,
            consumed: 0,
        }
    }
    pub fn can_receive(&self, end: u64) -> bool {
        end <= self.max_data
    }
    pub fn consume(&mut self, n: u64) {
        self.consumed = self.consumed.saturating_add(n);
    }
    pub fn extend(&mut self, credit: u64) {
        self.max_data = max(self.max_data, self.consumed.saturating_add(credit));
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SendStreamCredit {
    pub id: u64,
    pub max_data: u64,
    pub sent: u64,
}

/// Peer-advertised connection and stream credit for a sender.  Retransmits do
/// not reserve credit again; only new stream-offset bytes advance `sent`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SendFlowControl<const N: usize> {
    pub max_data: u64,
    pub sent_data: u64,
    streams: [Option<SendStreamCredit>; N],
}

impl<const N: usize> SendFlowControl<N> {
    pub const fn new(max_data: u64, max_stream_data: u64) -> Self {
        let _ = max_stream_data;
        Self {
            max_data,
            sent_data: 0,
            streams: [None; N],
        }
    }

    pub fn open_stream(&mut self, id: u64, max_data: u64) -> Result<(), Error> {
        if self
            .streams
            .iter()
            .any(|stream| stream.map(|value| value.id) == Some(id))
        {
            return Ok(());
        }
        let slot = self
            .streams
            .iter()
            .position(Option::is_none)
            .ok_or(Error::StreamLimit)?;
        self.streams[slot] = Some(SendStreamCredit {
            id,
            max_data,
            sent: 0,
        });
        Ok(())
    }

    pub fn stream(&self, id: u64) -> Option<SendStreamCredit> {
        self.streams
            .iter()
            .flatten()
            .find(|stream| stream.id == id)
            .copied()
    }

    pub fn can_send(&self, id: u64, offset: u64, len: usize) -> bool {
        let Some(stream) = self.stream(id) else {
            return false;
        };
        let end = offset.saturating_add(len as u64);
        let new_bytes = end.saturating_sub(stream.sent);
        end <= stream.max_data && self.sent_data.saturating_add(new_bytes) <= self.max_data
    }

    pub fn reserve(&mut self, id: u64, offset: u64, len: usize) -> Result<(), Error> {
        if !self.can_send(id, offset, len) {
            return Err(Error::FlowControl);
        }
        let stream = self
            .streams
            .iter_mut()
            .flatten()
            .find(|stream| stream.id == id)
            .ok_or(Error::Invalid)?;
        let end = offset.saturating_add(len as u64);
        let new_bytes = end.saturating_sub(stream.sent);
        stream.sent = max(stream.sent, end);
        self.sent_data = self.sent_data.saturating_add(new_bytes);
        Ok(())
    }

    pub fn extend_connection(&mut self, max_data: u64) {
        self.max_data = max(self.max_data, max_data);
    }

    pub fn extend_stream(&mut self, id: u64, max_data: u64) -> Result<(), Error> {
        let stream = self
            .streams
            .iter_mut()
            .flatten()
            .find(|stream| stream.id == id)
            .ok_or(Error::Invalid)?;
        stream.max_data = max(stream.max_data, max_data);
        Ok(())
    }

    pub fn stream_credit(&self, id: u64) -> Option<u64> {
        self.stream(id).map(|stream| stream.max_data)
    }
}

/// RFC 9002 NewReno congestion state for one path.
///
/// This is intentionally bearer-neutral: the caller supplies packet sizes,
/// ACKs, and loss events.  Flow credit and congestion credit are separate;
/// both must allow a sender to transmit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CongestionController {
    pub max_datagram_size: u64,
    pub congestion_window: u64,
    pub slow_start_threshold: u64,
    pub bytes_in_flight: u64,
}

impl CongestionController {
    pub fn new(max_datagram_size: u64) -> Self {
        let mds = max_datagram_size.max(1);
        let initial_window = (10 * mds).min((2 * mds).max(14_720));
        Self {
            max_datagram_size: mds,
            congestion_window: initial_window,
            slow_start_threshold: u64::MAX,
            bytes_in_flight: 0,
        }
    }

    pub fn can_send(&self, bytes: u64) -> bool {
        self.bytes_in_flight.saturating_add(bytes) <= self.congestion_window
    }

    pub fn on_packet_sent(&mut self, bytes: u64) -> bool {
        if !self.can_send(bytes) {
            return false;
        }
        self.bytes_in_flight = self.bytes_in_flight.saturating_add(bytes);
        true
    }

    pub fn on_ack(&mut self, acked_bytes: u64) {
        let acked = min(acked_bytes, self.bytes_in_flight);
        self.bytes_in_flight -= acked;
        if acked == 0 {
            return;
        }
        if self.congestion_window < self.slow_start_threshold {
            self.congestion_window = self.congestion_window.saturating_add(acked);
        } else {
            let increase = (self.max_datagram_size.saturating_mul(acked)
                / self.congestion_window.max(1))
            .max(1);
            self.congestion_window = self.congestion_window.saturating_add(increase);
        }
    }

    pub fn on_loss(&mut self, lost_bytes: u64) {
        if lost_bytes == 0 {
            return;
        }
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(lost_bytes);
        let reduced = self.congestion_window / 2;
        self.slow_start_threshold = reduced.max(2 * self.max_datagram_size);
        self.congestion_window = self.slow_start_threshold;
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StreamState {
    pub id: u64,
    pub max_data: u64,
    pub received: u64,
    pub consumed: u64,
    pub finished: bool,
}

impl StreamState {
    pub const fn new(id: u64, max_data: u64) -> Self {
        Self {
            id,
            max_data,
            received: 0,
            consumed: 0,
            finished: false,
        }
    }
    pub fn accept(&mut self, offset: u64, len: usize, fin: bool) -> Result<(), Error> {
        let end = offset.checked_add(len as u64).ok_or(Error::FlowControl)?;
        if end > self.max_data {
            return Err(Error::FlowControl);
        }
        self.received = max(self.received, end);
        self.finished |= fin;
        Ok(())
    }
    pub fn consume(&mut self, n: u64) {
        self.consumed = min(self.received, self.consumed.saturating_add(n));
    }
    pub fn extend(&mut self, credit: u64) {
        self.max_data = max(self.max_data, self.consumed.saturating_add(credit));
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Role {
    Client,
    Server,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConnectionLimits {
    pub max_data: u64,
    pub max_stream_data: u64,
    pub max_streams_bidi: u64,
    pub max_streams_uni: u64,
}

pub const INITIAL_MAX_DATA: u64 = 256 * 1024;
pub const INITIAL_MAX_STREAM_DATA: u64 = 64 * 1024;

impl Default for ConnectionLimits {
    fn default() -> Self {
        Self {
            max_data: INITIAL_MAX_DATA,
            max_stream_data: INITIAL_MAX_STREAM_DATA,
            max_streams_bidi: 1,
            max_streams_uni: 2,
        }
    }
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
        Self {
            role,
            connection: FlowControl::new(limits.max_data),
            limits,
            received_data: 0,
            streams: [None; N],
        }
    }

    fn stream_kind(id: u64) -> (bool, bool) {
        (id & 1 != 0, id & 2 != 0)
    }

    fn stream_count(&self, uni: bool, local: bool) -> u64 {
        self.streams
            .iter()
            .flatten()
            .filter(|s| {
                let (server, is_uni) = Self::stream_kind(s.id);
                is_uni == uni && (server == matches!(self.role, Role::Server)) == local
            })
            .count() as u64
    }

    pub fn open(&mut self, id: u64) -> Result<&mut StreamState, Error> {
        let (server, uni) = Self::stream_kind(id);
        let local = server == matches!(self.role, Role::Server);
        if !local {
            return Err(Error::Invalid);
        }
        let limit = if uni {
            self.limits.max_streams_uni
        } else {
            self.limits.max_streams_bidi
        };
        if self.stream_count(uni, local) >= limit {
            return Err(Error::StreamLimit);
        }
        self.insert_stream(id)
    }

    pub fn accept(
        &mut self,
        id: u64,
        offset: u64,
        len: usize,
        fin: bool,
    ) -> Result<&mut StreamState, Error> {
        let slot = if let Some(i) = self.find(id) {
            i
        } else {
            let (server, uni) = Self::stream_kind(id);
            let local = server == matches!(self.role, Role::Server);
            if local {
                return Err(Error::Invalid);
            }
            let limit = if uni {
                self.limits.max_streams_uni
            } else {
                self.limits.max_streams_bidi
            };
            if self.stream_count(uni, local) >= limit {
                return Err(Error::StreamLimit);
            }
            self.insert_stream(id)?;
            self.find(id).ok_or(Error::Invalid)?
        };
        let end = offset.checked_add(len as u64).ok_or(Error::FlowControl)?;
        let previous = self.streams[slot].as_ref().ok_or(Error::Invalid)?.received;
        let delta = end.saturating_sub(previous);
        if !self
            .connection
            .can_receive(self.received_data.saturating_add(delta))
        {
            return Err(Error::FlowControl);
        }
        // Validate and update the stream before mutating connection-wide
        // accounting.  A rejected stream frame must not consume connection
        // credit or make a later valid frame fail spuriously.
        self.streams[slot]
            .as_mut()
            .ok_or(Error::Invalid)?
            .accept(offset, len, fin)?;
        self.received_data = self.received_data.saturating_add(delta);
        Ok(self.streams[slot].as_mut().unwrap())
    }

    pub fn consume(&mut self, id: u64, n: u64) -> Result<(), Error> {
        let i = self.find(id).ok_or(Error::Invalid)?;
        self.streams[i].as_mut().ok_or(Error::Invalid)?.consume(n);
        self.connection.consume(n);
        Ok(())
    }

    pub fn stream_max_data(&self, id: u64) -> Option<u64> {
        self.find(id)
            .and_then(|i| self.streams[i].map(|stream| stream.max_data))
    }

    pub fn extend_connection_credit(&mut self, credit: u64) {
        self.connection
            .extend(self.received_data.saturating_add(credit));
    }

    pub fn extend_stream_credit(&mut self, id: u64, credit: u64) -> Result<(), Error> {
        let i = self.find(id).ok_or(Error::Invalid)?;
        let consumed = self.streams[i].ok_or(Error::Invalid)?.consumed;
        self.streams[i]
            .as_mut()
            .ok_or(Error::Invalid)?
            .extend(consumed.saturating_add(credit));
        Ok(())
    }

    fn find(&self, id: u64) -> Option<usize> {
        self.streams
            .iter()
            .position(|s| s.map(|v| v.id) == Some(id))
    }
    fn insert_stream(&mut self, id: u64) -> Result<&mut StreamState, Error> {
        let i = self
            .streams
            .iter()
            .position(Option::is_none)
            .ok_or(Error::StreamLimit)?;
        self.streams[i] = Some(StreamState::new(id, self.limits.max_stream_data));
        Ok(self.streams[i].as_mut().unwrap())
    }
}

/// Bearer-neutral endpoint state shared by host and embedded users.
///
/// The bearer owns sockets, timers, and packet storage.  This type owns the
/// protocol state that must not diverge between implementations: packet
/// acknowledgement ranges, receive credit, peer-advertised send credit, and
/// congestion control.
pub struct EndpointState<const N: usize> {
    pub send: SendFlowControl<N>,
    pub receive: ConnectionState<N>,
    pub congestion: CongestionController,
    pub received_packets: AckRangeSet,
    pub next_packet_number: u32,
}

impl<const N: usize> EndpointState<N> {
    pub fn new(role: Role, limits: ConnectionLimits, max_datagram_size: u64) -> Self {
        Self {
            send: SendFlowControl::new(limits.max_data, limits.max_stream_data),
            receive: ConnectionState::new(role, limits),
            congestion: CongestionController::new(max_datagram_size),
            received_packets: AckRangeSet::new(),
            next_packet_number: 0,
        }
    }

    pub fn observe_packet(&mut self, packet_number: u32) { self.received_packets.insert(packet_number); }

    pub fn largest_received(&self) -> Option<u32> {
        self.received_packets.get(0).map(|range| range.end)
    }

    pub fn open_send_stream(&mut self, id: u64, max_data: u64) -> Result<(), Error> {
        self.send.open_stream(id, max_data)
    }

    pub fn reserve_send(&mut self, id: u64, offset: u64, len: usize) -> Result<(), Error> {
        self.send.reserve(id, offset, len)
    }

    pub fn packet_sent(&mut self, bytes: u64) -> bool { self.congestion.on_packet_sent(bytes) }

    pub fn acked(&mut self, bytes: u64) { self.congestion.on_ack(bytes); }

    pub fn lost(&mut self, bytes: u64) { self.congestion.on_loss(bytes); }

    /// Encode one stream packet using the endpoint's shared packet-number,
    /// flow-credit, and congestion state. The caller owns packet storage and
    /// retains the returned packet number for loss/ACK bookkeeping.
    pub fn encode_stream_packet(
        &mut self,
        dcid: ConnectionId,
        stream_id: u64,
        offset: u64,
        fin: bool,
        data: &[u8],
        out: &mut [u8],
    ) -> Result<(usize, u32), Error> {
        let header = ShortHeader {
            flags: FLAG_FIXED,
            dcid,
            packet_number: self.next_packet_number,
            // Keep the full packet number on this bounded protocol.  It avoids
            // a 16-bit wrap during large object transfers and removes packet
            // number reconstruction from the embedded bearers.
            packet_number_len: 4,
        };
        let mut p = header.encode(out)?;
        p += Frame::Stream(StreamFrame { id: stream_id, offset, fin, data }).encode(&mut out[p..])?;
        if !self.congestion.can_send(p as u64) { return Err(Error::Invalid); }
        self.send.reserve(stream_id, offset, data.len())?;
        if !self.congestion.on_packet_sent(p as u64) { return Err(Error::Invalid); }
        let packet_number = self.next_packet_number;
        self.next_packet_number = self.next_packet_number.wrapping_add(1);
        Ok((p, packet_number))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::vec;
    use std::vec::Vec;

    #[test]
    fn connection_id_lengths_round_trip() {
        for value in [
            0,
            0x3f,
            0x40,
            0x3fff,
            0x4000,
            0x3fff_ffff,
            0x4000_0000,
            (1u64 << 62) - 1,
        ] {
            let id = ConnectionId::new(value).unwrap();
            let mut b = [0; 8];
            let n = id.encode(&mut b).unwrap();
            assert_eq!(n, id.encoded_len());
            assert_eq!(ConnectionId::decode(&b[..n]).unwrap(), (id, n));
        }
    }

    #[test]
    fn varints_use_two_length_bits() {
        for value in [0, 63, 64, 16383, 16384, (1 << 30) - 1, 1 << 30] {
            let mut b = [0; 8];
            let n = put_varint(value, &mut b).unwrap();
            assert_eq!(get_varint(&b[..n]).unwrap(), (value, n));
        }
    }

    #[test]
    fn ack_ranges_merge_and_deduplicate() {
        let mut a = AckRanges::<4>::new();
        for p in [4, 2, 3, 9, 8, 3] {
            a.insert(p);
        }
        assert_eq!(a.get(0), Some(AckRange { start: 8, end: 9 }));
        assert_eq!(a.get(1), Some(AckRange { start: 2, end: 4 }));
        assert!(a.contains(3));
    }

    #[test]
    fn quic_ack_ranges_round_trip_with_gap() {
        let mut ranges = AckRangeSet::new();
        for packet_number in [10, 9, 7, 6, 2] {
            ranges.insert(packet_number);
        }
        let frame = Frame::AckRanges {
            largest: 10,
            delay: 3,
            ranges,
        };
        let mut encoded = [0u8; 64];
        let used = frame.encode(&mut encoded).unwrap();
        let (decoded, decoded_used) = decode_frame(&encoded[..used]).unwrap();
        assert_eq!(decoded_used, used);
        assert_eq!(decoded, frame);
    }

    #[test]
    fn short_header_round_trip_uses_variable_cid() {
        for value in [1, 0x1234, 0x1234_5678, 0x1234_5678_9abc_def0] {
            let mut b = [0u8; 32];
            let h = ShortHeader {
                flags: FLAG_FIXED,
                dcid: ConnectionId::new(value).unwrap(),
                packet_number: 0xabcdef,
                packet_number_len: 3,
            };
            let n = h.encode(&mut b).unwrap();
            let (decoded, used) = ShortHeader::decode(&b[..n]).unwrap();
            assert_eq!(used, n);
            assert_eq!(decoded.dcid, h.dcid);
            assert_eq!(decoded.packet_number, h.packet_number);
            assert_eq!(decoded.packet_number_len, h.packet_number_len);
        }
    }

    #[test]
    fn stream_and_flow_frames_round_trip() {
        let data = [1, 2, 3, 4];
        for frame in [
            Frame::Stream(StreamFrame {
                id: 7,
                offset: 4096,
                fin: true,
                data: &data,
            }),
            Frame::MaxData(1000),
            Frame::MaxStreamData { id: 7, max: 2000 },
            Frame::MaxStreamsUni(2),
        ] {
            let mut b = [0u8; 64];
            let n = frame.encode(&mut b).unwrap();
            assert_eq!(decode_frame(&b[..n]).unwrap(), (frame, n));
        }
    }

    #[test]
    fn connection_and_stream_credit_are_bounded() {
        let limits = ConnectionLimits {
            max_data: 8,
            max_stream_data: 8,
            max_streams_bidi: 1,
            max_streams_uni: 1,
        };
        let mut c = ConnectionState::<2>::new(Role::Server, limits);
        assert!(c.accept(0, 0, 5, false).is_ok());
        assert_eq!(c.accept(0, 5, 4, false), Err(Error::FlowControl));
        assert!(c.consume(0, 5).is_ok());
    }

    #[test]
    fn connection_and_stream_windows_are_independent_and_extendable() {
        let limits = ConnectionLimits {
            max_data: 16,
            max_stream_data: 8,
            max_streams_bidi: 2,
            max_streams_uni: 0,
        };
        let mut c = ConnectionState::<2>::new(Role::Server, limits);
        assert!(c.accept(0, 0, 8, false).is_ok());
        assert_eq!(c.accept(0, 8, 1, false), Err(Error::FlowControl));
        assert!(c.consume(0, 8).is_ok());
        c.streams[0].as_mut().unwrap().extend(8);
        assert!(c.accept(0, 8, 8, false).is_ok());
        assert_eq!(c.accept(0, 16, 1, false), Err(Error::FlowControl));
        assert!(c.consume(0, 8).is_ok());
        c.streams[0].as_mut().unwrap().extend(1);
        c.connection.extend(16);
        assert!(c.accept(0, 16, 1, false).is_ok());
    }

    #[test]
    fn sender_flow_credit_blocks_and_extension_allows_progress() {
        let mut flow = SendFlowControl::<2>::new(16, 8);
        flow.open_stream(7, 8).unwrap();
        assert!(flow.reserve(7, 0, 8).is_ok());
        assert_eq!(flow.reserve(7, 8, 1), Err(Error::FlowControl));
        flow.extend_stream(7, 16).unwrap();
        assert!(flow.reserve(7, 8, 8).is_ok());
        assert_eq!(flow.reserve(7, 16, 1), Err(Error::FlowControl));
        flow.extend_stream(7, 32).unwrap();
        flow.extend_connection(32);
        assert!(flow.reserve(7, 16, 1).is_ok());
    }

    #[test]
    fn endpoint_state_shares_ack_credit_and_newreno_state() {
        let mut endpoint = EndpointState::<2>::new(
            Role::Client,
            ConnectionLimits::default(),
            1200,
        );
        endpoint.open_send_stream(3, INITIAL_MAX_STREAM_DATA).unwrap();
        endpoint.observe_packet(4);
        endpoint.observe_packet(2);
        assert_eq!(endpoint.largest_received(), Some(4));
        assert!(endpoint.receive.accept(1, 0, 4, false).is_ok());
        endpoint.receive.consume(1, 4).unwrap();
        endpoint.receive.extend_connection_credit(INITIAL_MAX_DATA);
        endpoint.receive.extend_stream_credit(1, INITIAL_MAX_STREAM_DATA).unwrap();
        assert!(endpoint.reserve_send(3, 0, 8).is_ok());
        assert!(endpoint.packet_sent(1200));
        endpoint.acked(1200);
        assert_eq!(endpoint.congestion.bytes_in_flight, 0);
    }

    #[test]
    fn concurrent_streams_share_connection_but_keep_credit_independent() {
        let limits = ConnectionLimits {
            max_data: 16,
            max_stream_data: 8,
            max_streams_bidi: 1,
            max_streams_uni: 2,
        };
        let mut sender = EndpointState::<2>::new(Role::Server, limits, 64);
        let mut receiver = EndpointState::<2>::new(Role::Client, limits, 64);
        sender.open_send_stream(3, 8).unwrap();
        sender.open_send_stream(7, 8).unwrap();

        let mut packet_lengths = [0u64; 2];
        for (index, (stream_id, offset)) in [(3, 0), (7, 0)].into_iter().enumerate() {
            let mut packet = [0u8; 128];
            let (used, _) = sender
                .encode_stream_packet(
                    ConnectionId::new(1).unwrap(),
                    stream_id,
                    offset,
                    false,
                    b"abcd",
                    &mut packet,
                )
                .unwrap();
            packet_lengths[index] = used as u64;
            let (header, header_len) = ShortHeader::decode(&packet[..used]).unwrap();
            let (Frame::Stream(stream), _) = decode_frame(&packet[header_len..used]).unwrap() else {
                panic!("expected stream frame");
            };
            receiver.receive.accept(stream.id, stream.offset, stream.data.len(), stream.fin).unwrap();
            receiver.observe_packet(header.packet_number);
            receiver.receive.consume(stream.id, stream.data.len() as u64).unwrap();
        }
        assert_eq!(sender.congestion.bytes_in_flight, packet_lengths[0] + packet_lengths[1]);
        assert_eq!(sender.send.stream_credit(3), Some(8));
        assert_eq!(sender.send.stream_credit(7), Some(8));
        sender.acked(packet_lengths[0]);
        sender.acked(packet_lengths[1]);
        sender.send.extend_stream(3, 16).unwrap();
        assert!(sender.reserve_send(3, 4, 4).is_ok());
        assert_eq!(sender.send.stream(7).unwrap().sent, 4);
    }

    #[test]
    fn bearer_envelope_round_trips_without_object_store_dependency() {
        let key = PeerKey { wifi_mac: [1, 2, 3, 4, 5, 6], dcid: ConnectionId::new(0x1234).unwrap() };
        let mut out = [0u8; 64];
        let used = encode_envelope(key, 9, b"payload", &mut out).unwrap();
        let (decoded, kind, payload) = decode_envelope(&out[..used]).unwrap();
        assert_eq!(decoded, key);
        assert_eq!(kind, 9);
        assert_eq!(payload, b"payload");
    }

    #[test]
    fn newreno_congestion_window_uses_rfc_initial_and_loss_rules() {
        let mut c = CongestionController::new(1200);
        assert_eq!(c.congestion_window, 12_000);
        for _ in 0..10 {
            assert!(c.on_packet_sent(1200));
        }
        assert!(!c.on_packet_sent(1200));
        c.on_ack(1200);
        assert_eq!(c.congestion_window, 13_200);
        assert_eq!(c.bytes_in_flight, 10_800);
        c.on_loss(1200);
        assert_eq!(c.congestion_window, 6_600);
        assert_eq!(c.slow_start_threshold, 6_600);
        assert_eq!(c.bytes_in_flight, 9_600);
        c.on_loss(0);
        assert_eq!(c.congestion_window, 6_600);
    }

    struct DelayedPacketLink {
        now: u64,
        delay: u64,
        drop_once: Option<u32>,
        dropped: bool,
        queue: VecDeque<(u64, u32)>,
    }

    impl DelayedPacketLink {
        fn send(&mut self, packet_number: u32) {
            if self.drop_once == Some(packet_number) && !self.dropped {
                self.dropped = true;
                return;
            }
            self.queue.push_back((self.now + self.delay, packet_number));
        }

        fn advance(&mut self, elapsed: u64) -> Vec<u32> {
            self.now += elapsed;
            let mut delivered = Vec::new();
            while self.queue.front().is_some_and(|(at, _)| *at <= self.now) {
                delivered.push(self.queue.pop_front().unwrap().1);
            }
            delivered
        }
    }

    #[test]
    fn delayed_loss_link_exercises_selective_ack_and_newreno() {
        let mut link = DelayedPacketLink {
            now: 0,
            delay: 10,
            drop_once: Some(2),
            dropped: false,
            queue: VecDeque::new(),
        };
        let mut congestion = CongestionController::new(1200);
        for packet_number in 0..5 {
            assert!(congestion.on_packet_sent(1200));
            link.send(packet_number);
        }
        let delivered = link.advance(10);
        assert_eq!(delivered, vec![0, 1, 3, 4]);
        let mut received = AckRangeSet::new();
        for packet_number in delivered {
            received.insert(packet_number);
        }
        assert_eq!(received.get(0), Some(AckRange { start: 3, end: 4 }));
        assert_eq!(received.get(1), Some(AckRange { start: 0, end: 1 }));
        congestion.on_loss(1200);
        link.send(2);
        let retransmitted = link.advance(10);
        assert_eq!(retransmitted, vec![2]);
        received.insert(2);
        assert_eq!(received.get(0), Some(AckRange { start: 0, end: 4 }));
        congestion.on_ack(4 * 1200);
        assert_eq!(congestion.bytes_in_flight, 0);
    }

    /// Memory-only end-to-end stream stress.  This deliberately bypasses
    /// files and sockets: both endpoints use the same packet encoder,
    /// receiver flow accounting, ACK ranges, and NewReno state that bearers
    /// use in production.
    #[test]
    #[ignore = "64 MiB memory stream benchmark; run scripts/build.sh transport-loopback"]
    fn memory_stream_stress() {
        use std::collections::{BTreeMap, VecDeque};
        use std::time::Instant;

        let total = std::env::var("DMESH_STREAM_BYTES")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(64 * 1024 * 1024);
        let mtu = 1200usize;
        let dcid = ConnectionId::new(1).unwrap();
        let mut sender = EndpointState::<2>::new(
            Role::Server,
            ConnectionLimits::default(),
            mtu as u64,
        );
        let mut receiver = EndpointState::<2>::new(
            Role::Client,
            ConnectionLimits::default(),
            mtu as u64,
        );
        sender.open_send_stream(3, INITIAL_MAX_STREAM_DATA).unwrap();

        struct Flight {
            packet_number: u32,
            offset: u64,
            data: Vec<u8>,
            packet: Vec<u8>,
            packet_len: u64,
            acked: bool,
            lost: bool,
        }

        let mut flights = VecDeque::<Flight>::new();
        let mut segments = BTreeMap::<u64, usize>::new();
        let mut next_offset = 0u64;
        let mut contiguous = 0u64;
        let mut packet_count = 0u64;
        let mut retransmits = 0u64;
        let mut dropped = false;
        let started = Instant::now();

        while contiguous < total {
            let mut sent_this_round = 0u32;
            while next_offset < total && sender.congestion.can_send(mtu as u64) {
                let len = (total - next_offset).min((mtu - 32) as u64) as usize;
                let data = vec![0xa5; len];
                let mut packet = vec![0u8; mtu];
                let (used, packet_number) = match sender.encode_stream_packet(
                    dcid, 3, next_offset, next_offset + len as u64 == total,
                    &data, &mut packet,
                ) {
                    Ok(value) => value,
                    Err(_) => break,
                };
                packet.truncate(used);
                flights.push_back(Flight {
                    packet_number,
                    offset: next_offset,
                    data,
                    packet: packet.clone(),
                    packet_len: used as u64,
                    acked: false,
                    lost: false,
                });
                next_offset += len as u64;
                packet_count += 1;
                sent_this_round += 1;
            }

            // Deliver the current flight batch, dropping one packet once to
            // force a selective ACK gap and retransmission.
            let mut received = AckRangeSet::new();
            for flight in flights.iter().filter(|flight| !flight.lost) {
                if flight.packet_number == 3 && !dropped {
                    dropped = true;
                    continue;
                }
                let (header, header_len) = ShortHeader::decode(&flight.packet).unwrap();
                let (Frame::Stream(stream), _) = decode_frame(&flight.packet[header_len..]).unwrap() else {
                    panic!("memory stream packet was not a stream frame");
                };
                assert_eq!(stream.id, 3);
                receiver
                    .receive
                    .accept(stream.id, stream.offset, stream.data.len(), stream.fin)
                    .unwrap();
                receiver.observe_packet(header.packet_number);
                received.insert(header.packet_number);
                segments.entry(stream.offset).or_insert(stream.data.len());
            }

            while let Some(len) = segments.remove(&contiguous) {
                contiguous += len as u64;
                receiver.receive.consume(3, len as u64).unwrap();
            }
            receiver.receive.extend_connection_credit(INITIAL_MAX_DATA);
            receiver.receive.extend_stream_credit(3, INITIAL_MAX_STREAM_DATA).unwrap();
            sender.send.extend_connection(receiver.receive.connection.consumed + INITIAL_MAX_DATA);
            sender.send.extend_stream(3, receiver.receive.stream_max_data(3).unwrap()).unwrap();

            for flight in flights.iter_mut().filter(|flight| !flight.acked) {
                if received.contains(flight.packet_number) {
                    flight.acked = true;
                    sender.acked(flight.packet_len);
                }
            }
            let has_later_ack = flights.iter().any(|flight| flight.acked);
            let mut resend = Vec::new();
            for flight in flights.iter_mut().filter(|flight| !flight.acked && !flight.lost) {
                if has_later_ack {
                    flight.lost = true;
                    sender.lost(flight.packet_len);
                    resend.push((flight.offset, flight.data.clone()));
                }
            }
            let had_resend = !resend.is_empty();
            for (offset, data) in resend {
                let mut packet = vec![0u8; mtu];
                let (used, packet_number) = sender
                    .encode_stream_packet(dcid, 3, offset, offset + data.len() as u64 == total, &data, &mut packet)
                    .unwrap();
                packet.truncate(used);
                flights.push_back(Flight { packet_number, offset, data, packet, packet_len: used as u64, acked: false, lost: false });
                packet_count += 1;
                retransmits += 1;
            }
            flights.retain(|flight| !flight.acked && !flight.lost);
            assert!(sent_this_round != 0 || had_resend || contiguous == total);
        }

        let elapsed_ms = started.elapsed().as_millis().max(1);
        let bitrate_kbps = (total as u128 * 8_000 / elapsed_ms) as u64 / 1000;
        std::println!(
            "memory_stream bytes={} packets={} retransmits={} dropped_packet={} elapsed_ms={} bitrate_kbps={} cwnd={} consumed={}",
            total, packet_count, retransmits, dropped, elapsed_ms, bitrate_kbps,
            sender.congestion.congestion_window, contiguous,
        );
        assert_eq!(contiguous, total);
        assert!(retransmits > 0);
    }

    /// Apple-to-apple synthetic baseline for the same byte volume and
    /// application chunk size, using a real localhost TCP socket. No files,
    /// manifests, or object-store framing are involved.
    #[tokio::test]
    #[ignore = "64 MiB synthetic localhost TCP benchmark; run scripts/build.sh transport-compare"]
    async fn tcp_memory_stream_64m_baseline() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::{TcpListener, TcpStream};

        let total = std::env::var("DMESH_STREAM_BYTES")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(64 * 1024 * 1024);
        let chunk_size = 1200 - 32;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buffer = vec![0u8; 64 * 1024];
            let mut received = 0usize;
            while received < total {
                let n = stream.read(&mut buffer).await.unwrap();
                assert!(n != 0, "TCP peer closed before synthetic stream completed");
                received += n;
            }
            received
        });

        let mut stream = TcpStream::connect(address).await.unwrap();
        stream.set_nodelay(true).unwrap();
        let chunk = vec![0xa5u8; chunk_size];
        let started = std::time::Instant::now();
        let mut sent = 0usize;
        while sent < total {
            let len = (total - sent).min(chunk.len());
            stream.write_all(&chunk[..len]).await.unwrap();
            sent += len;
        }
        stream.shutdown().await.unwrap();
        assert_eq!(server.await.unwrap(), total);
        let elapsed_ms = started.elapsed().as_millis().max(1);
        let bitrate_kbps = (total as u128 * 8_000 / elapsed_ms) as u64 / 1000;
        std::println!(
            "tcp_memory_stream bytes={} chunk_bytes={} elapsed_ms={} bitrate_kbps={} tcp_nodelay=true",
            total, chunk_size, elapsed_ms, bitrate_kbps,
        );
    }
}
