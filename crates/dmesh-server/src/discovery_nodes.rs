//! `discovery.nodes`: a correlated response header followed by a CBOR sequence
//! of original announcement records and unsigned receiver metadata, then FIN.
use crate::{
    cbor::{Decoder, Encoder},
    tagged,
};

pub const END: &[u8] = &[0xa1, 0, 0];
pub const MAX_DURATION_MS: u32 = 300_000;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Options {
    pub duration_ms: u32,
    pub retained: bool,
    pub active: bool,
}
impl Default for Options {
    fn default() -> Self {
        Self {
            duration_ms: 5000,
            retained: true,
            active: true,
        }
    }
}
impl Options {
    pub fn decode(fields: Option<&[u8]>) -> Option<Self> {
        let mut options = Self::default();
        let Some(fields) = fields else {
            return Some(options);
        };
        let mut d = Decoder::new(fields);
        let (major, count) = d.head()?;
        if major != 5 {
            return None;
        }
        let mut seen = 0u8;
        for _ in 0..count {
            let key = d.uint()?;
            if (1..=3).contains(&key) {
                let bit = 1 << key;
                if seen & bit != 0 {
                    return None;
                }
                seen |= bit;
            }
            match key {
                1 => {
                    options.duration_ms = u32::try_from(d.uint()?).ok()?;
                    if options.duration_ms > MAX_DURATION_MS {
                        return None;
                    }
                }
                2 => options.retained = d.boolean()?,
                3 => options.active = d.boolean()?,
                _ => d.skip()?,
            }
        }
        d.is_finished().then_some(options)
    }
}
pub fn header(id: u64, out: &mut [u8]) -> Option<usize> {
    tagged::encode_numeric_response(6, 9, id, &[0xa1, 1, 1], out)
}
pub fn is_header(record: tagged::Record<'_>) -> bool {
    record.component == Some(tagged::Name::Tag(6))
        && record.method == Some(tagged::Name::Tag(9))
        && record.result == Some(&[0xa1, 1, 1][..])
        && record.error.is_none()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Origin {
    Direct = 0,
    Crawled = 1,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Observation<'a> {
    pub record: &'a [u8],
    pub peer: Option<[u8; 6]>,
    pub rssi_dbm: Option<i16>,
    pub channel: Option<u8>,
    /// Receiver-local monotonic microseconds; never compared across observers.
    pub received_us: Option<u64>,
    pub bearer: &'a str,
    /// Host UTC epoch milliseconds. Omitted by devices without a wall clock.
    pub last_seen_ms: Option<u64>,
    pub age_ms: Option<u64>,
    pub origin: Origin,
    pub retained: bool,
    /// Original observer identity hint for crawled observations.
    pub via: Option<&'a [u8]>,
}
impl<'a> Observation<'a> {
    pub fn new(record: &'a [u8], bearer: &'a str) -> Self {
        Self {
            record,
            bearer,
            peer: None,
            rssi_dbm: None,
            channel: None,
            received_us: None,
            last_seen_ms: None,
            age_ms: None,
            origin: Origin::Direct,
            retained: false,
            via: None,
        }
    }
    /// Encodes into the caller's packet/output storage, without allocation.
    pub fn encode(&self, out: &mut [u8]) -> Option<usize> {
        if self.record.is_empty()
            || self.bearer.is_empty()
            || self.via.is_some_and(|v| v.len() != 8)
        {
            return None;
        }
        let mut e = Encoder::new(out);
        let count = 5
            + usize::from(self.peer.is_some())
            + usize::from(self.rssi_dbm.is_some())
            + usize::from(self.channel.is_some())
            + usize::from(self.received_us.is_some())
            + usize::from(self.last_seen_ms.is_some())
            + usize::from(self.age_ms.is_some())
            + usize::from(self.via.is_some());
        e.map(count as u64)?;
        e.uint(0)?;
        e.uint(1)?;
        if let Some(peer) = self.peer {
            e.uint(1)?;
            e.bytes_value(&peer)?;
        }
        if let Some(rssi) = self.rssi_dbm {
            e.uint(2)?;
            e.int(rssi as i64)?;
        }
        if let Some(channel) = self.channel {
            e.uint(3)?;
            e.uint(channel as u64)?;
        }
        if let Some(time) = self.received_us {
            e.uint(4)?;
            e.uint(time)?;
        }
        e.uint(6)?;
        e.bytes_value(self.record)?;
        if let Some(time) = self.last_seen_ms {
            e.uint(7)?;
            e.uint(time)?;
        }
        e.uint(8)?;
        e.uint(self.origin as u64)?;
        e.uint(9)?;
        e.text_value(self.bearer.as_bytes())?;
        e.uint(10)?;
        e.boolean(self.retained)?;
        if let Some(via) = self.via {
            e.uint(11)?;
            e.bytes_value(via)?;
        }
        if let Some(age) = self.age_ms {
            e.uint(12)?;
            e.uint(age)?;
        }
        Some(e.len())
    }
    /// Decode one sequence item; fields are optional/order-independent.
    pub fn decode(data: &'a [u8]) -> Option<Self> {
        let mut d = Decoder::new(data);
        let (major, count) = d.head()?;
        if major != 5 {
            return None;
        }
        let mut row = Self::new(&[], "");
        let mut kind = None;
        let mut seen = 0u16;
        for _ in 0..count {
            let key = d.uint()?;
            if key <= 12 {
                let bit = 1 << key;
                if seen & bit != 0 {
                    return None;
                }
                seen |= bit;
            }
            match key {
                0 => kind = Some(d.uint()?),
                1 => row.peer = Some(d.bytes_ref()?.try_into().ok()?),
                2 => row.rssi_dbm = Some(i16::try_from(d.int()?).ok()?),
                3 => row.channel = Some(u8::try_from(d.uint()?).ok()?),
                4 => row.received_us = Some(d.uint()?),
                6 => row.record = d.bytes_ref()?,
                7 => row.last_seen_ms = Some(d.uint()?),
                8 => {
                    row.origin = match d.uint()? {
                        0 => Origin::Direct,
                        1 => Origin::Crawled,
                        _ => return None,
                    }
                }
                9 => row.bearer = core::str::from_utf8(d.text_ref()?).ok()?,
                10 => row.retained = d.boolean()?,
                11 => {
                    let via = d.bytes_ref()?;
                    if via.len() != 8 {
                        return None;
                    }
                    row.via = Some(via);
                }
                12 => row.age_ms = Some(d.uint()?),
                _ => d.skip()?,
            }
        }
        (d.is_finished() && kind == Some(1) && !row.record.is_empty() && !row.bearer.is_empty())
            .then_some(row)
    }
}
