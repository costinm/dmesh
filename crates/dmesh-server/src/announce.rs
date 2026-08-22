//! Small, bearer-neutral device presence records.
//!
//! An announce is a direct tagged-CBOR record, so exactly the same bytes can
//! travel in UART, a NAN Service Info field, a NOW action, or an IPv6 UDP
//! datagram. ESP records intentionally carry no key material. Host/Android
//! records may additionally carry a public key and a signature, allowing an
//! observer to distinguish an unsigned device presence hint from a signed
//! host identity without changing the bearer or envelope.

use crate::{
    cbor::{Decoder, Encoder},
    tagged::{Name, Record, decode},
};

/// Tagged component reserved for one-way presence records.
pub const ANNOUNCE_COMPONENT: u64 = 6;
pub const ANNOUNCE_BOOT: u64 = 1;
pub const ANNOUNCE_DISCOVERY: u64 = 2;
/// Local request/response for bounded observation caches, not a broadcast.
pub const ANNOUNCE_OBSERVED: u64 = 3;
/// Local request/response for bounded DMesh NAN Follow-up receipts.
pub const ANNOUNCE_FOLLOWUPS_OBSERVED: u64 = 4;

const FIELD_DEVICE_ID: u64 = 1;
const FIELD_UPTIME_SECS: u64 = 2;
const FIELD_TRANSPORT_MODE: u64 = 3;
const FIELD_COUNTERS: u64 = 4;
/// Optional DER SubjectPublicKeyInfo. Hosts currently use P-256; the tagged
/// field leaves the key algorithm to the public-key encoding itself.
pub const FIELD_PUBLIC_KEY: u64 = 5;
/// Optional fixed-width raw signature over [`signing_bytes`].
pub const FIELD_SIGNATURE: u64 = 6;
const MAX_DEVICE_ID: usize = 16;
pub const MAX_PUBLIC_KEY: usize = 128;
pub const SIGNATURE_LEN: usize = 64;

/// Bounded presence information common to every radio bearer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Announce {
    pub kind: u64,
    pub device_id: [u8; MAX_DEVICE_ID],
    pub device_id_len: u8,
    pub uptime_secs: u32,
    /// `0` unassociated/NAN+NOW, `1` associated STA, `2` UART-only.
    pub transport_mode: u8,
    /// A compact implementation-defined golden-counter summary.
    pub counters: u32,
    /// Optional public-key identity for hosts/Android. ESP leaves this empty.
    pub public_key: [u8; MAX_PUBLIC_KEY],
    pub public_key_len: u8,
    /// Optional raw signature over the same tagged record with field 6
    /// omitted. `signature_len == 0` is the explicitly unsigned device form.
    pub signature: [u8; SIGNATURE_LEN],
    pub signature_len: u8,
}

/// Typed entry in a local announce-observation cache.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObservedAnnounce<'a> {
    pub device_id: &'a [u8],
    pub source_mac: [u8; 6],
    pub source_ip: &'a [u8],
    pub uptime_secs: u32,
    pub transport_mode: u8,
    pub counters: u32,
    pub kind: u8,
    pub last_seen_ms: u32,
}

/// Small fixed diagnostic view of a received directed NAN Follow-up. Payload
/// bytes remain in the local bounded cache; the response carries a hash/size
/// so ten receipts fit in the common 1100-byte transport MTU.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObservedFollowup {
    pub source: [u8; 6],
    pub target: [u8; 6],
    pub msg_type: u8,
    pub seq: u16,
    pub payload_len: u16,
    pub payload_hash: u32,
    pub last_seen_ms: u32,
}

impl Announce {
    pub const fn boot(
        device_id: [u8; MAX_DEVICE_ID],
        device_id_len: u8,
        transport_mode: u8,
    ) -> Self {
        Self {
            kind: ANNOUNCE_BOOT,
            device_id,
            device_id_len,
            uptime_secs: 0,
            transport_mode,
            counters: 0,
            public_key: [0; MAX_PUBLIC_KEY],
            public_key_len: 0,
            signature: [0; SIGNATURE_LEN],
            signature_len: 0,
        }
    }

    pub const fn discovery(
        device_id: [u8; MAX_DEVICE_ID],
        device_id_len: u8,
        uptime_secs: u32,
        transport_mode: u8,
        counters: u32,
    ) -> Self {
        Self {
            kind: ANNOUNCE_DISCOVERY,
            device_id,
            device_id_len,
            uptime_secs,
            transport_mode,
            counters,
            public_key: [0; MAX_PUBLIC_KEY],
            public_key_len: 0,
            signature: [0; SIGNATURE_LEN],
            signature_len: 0,
        }
    }

    pub fn device_id(&self) -> &[u8] {
        &self.device_id[..usize::from(self.device_id_len).min(MAX_DEVICE_ID)]
    }

    pub fn public_key(&self) -> &[u8] {
        &self.public_key[..usize::from(self.public_key_len).min(MAX_PUBLIC_KEY)]
    }

    pub fn signature(&self) -> &[u8] {
        &self.signature[..usize::from(self.signature_len).min(SIGNATURE_LEN)]
    }

    pub fn has_identity(&self) -> bool {
        !self.public_key().is_empty() && !self.signature().is_empty()
    }

    /// Attach a host/Android public key before calculating its signature.
    pub fn set_public_key(&mut self, public_key: &[u8]) -> bool {
        if public_key.is_empty() || public_key.len() > MAX_PUBLIC_KEY {
            return false;
        }
        self.public_key.fill(0);
        self.public_key[..public_key.len()].copy_from_slice(public_key);
        self.public_key_len = public_key.len() as u8;
        true
    }

    pub fn set_signature(&mut self, signature: &[u8]) -> bool {
        if signature.len() != SIGNATURE_LEN {
            return false;
        }
        self.signature.copy_from_slice(signature);
        self.signature_len = SIGNATURE_LEN as u8;
        true
    }
}

/// Encode one announce into the common direct-record envelope.
pub fn encode(announce: Announce, out: &mut [u8]) -> Option<usize> {
    encode_inner(announce, true, out)
}

/// Canonical bytes signed by an identified announce. They include the public
/// key but omit the signature field itself.
pub fn signing_bytes(announce: Announce, out: &mut [u8]) -> Option<usize> {
    if announce.public_key_len == 0 {
        None
    } else {
        encode_inner(announce, false, out)
    }
}

fn encode_inner(announce: Announce, include_signature: bool, out: &mut [u8]) -> Option<usize> {
    let id = announce.device_id();
    if id.is_empty() {
        return None;
    }
    let has_key = !announce.public_key().is_empty();
    let supplied_signature = !announce.signature().is_empty();
    // Canonical signing bytes deliberately omit field 6 even after a
    // signature has been attached. Only the full wire form requires key and
    // signature to appear together; otherwise verification of a decoded
    // signed announce can never reconstruct the signed bytes.
    if (include_signature && supplied_signature != has_key)
        || (!include_signature && supplied_signature && !has_key)
    {
        return None;
    }
    let has_signature = include_signature && supplied_signature;
    let mut e = Encoder::new(out);
    e.map(3)?;
    e.uint(1)?;
    e.uint(ANNOUNCE_COMPONENT)?;
    e.uint(2)?;
    e.uint(announce.kind)?;
    e.uint(5)?;
    e.map(4 + u64::from(has_key) + u64::from(has_signature))?;
    e.uint(FIELD_DEVICE_ID)?;
    e.bytes_value(id)?;
    e.uint(FIELD_UPTIME_SECS)?;
    e.uint(u64::from(announce.uptime_secs))?;
    e.uint(FIELD_TRANSPORT_MODE)?;
    e.uint(u64::from(announce.transport_mode))?;
    e.uint(FIELD_COUNTERS)?;
    e.uint(u64::from(announce.counters))?;
    if has_key {
        e.uint(FIELD_PUBLIC_KEY)?;
        e.bytes_value(announce.public_key())?;
    }
    if has_signature {
        e.uint(FIELD_SIGNATURE)?;
        e.bytes_value(announce.signature())?;
    }
    Some(e.len())
}

/// Decode a local announce. Directed records are not presence broadcasts.
pub fn decode_announce(packet: &[u8]) -> Option<Announce> {
    let record = decode(packet)?;
    (record.to.is_none())
        .then(|| decode_record(record))
        .flatten()
}

/// True only for the canonical empty observation-list request.
pub fn is_observed_request(packet: &[u8]) -> bool {
    is_empty_observation_request(packet, ANNOUNCE_OBSERVED)
}

/// True only for the canonical empty Follow-up receipt-list request.
pub fn is_followups_observed_request(packet: &[u8]) -> bool {
    is_empty_observation_request(packet, ANNOUNCE_FOLLOWUPS_OBSERVED)
}

fn is_empty_observation_request(packet: &[u8], method: u64) -> bool {
    let Some(record) = decode(packet) else {
        return false;
    };
    if record.to.is_some()
        || record.component != Some(Name::Tag(ANNOUNCE_COMPONENT))
        || record.method != Some(Name::Tag(method))
    {
        return false;
    }
    let Some(fields) = record.fields else {
        return false;
    };
    let mut fields = Decoder::new(fields);
    matches!(fields.head(), Some((5, 0))) && fields.is_finished()
}

/// Encode the empty, bearer-neutral observation-list request.
pub fn encode_observed_request(out: &mut [u8]) -> Option<usize> {
    encode_empty_observation_request(ANNOUNCE_OBSERVED, out)
}

/// Encode the empty, bearer-neutral Follow-up receipt request.
pub fn encode_followups_observed_request(out: &mut [u8]) -> Option<usize> {
    encode_empty_observation_request(ANNOUNCE_FOLLOWUPS_OBSERVED, out)
}

fn encode_empty_observation_request(method: u64, out: &mut [u8]) -> Option<usize> {
    let mut e = Encoder::new(out);
    e.map(3)?;
    e.uint(1)?;
    e.uint(ANNOUNCE_COMPONENT)?;
    e.uint(2)?;
    e.uint(method)?;
    e.uint(5)?;
    e.map(0)?;
    Some(e.len())
}

/// Encode typed cache entries without allocating a per-bearer response.
pub fn encode_observed_response(entries: &[ObservedAnnounce<'_>], out: &mut [u8]) -> Option<usize> {
    let mut e = Encoder::new(out);
    e.map(3)?;
    e.uint(1)?;
    e.uint(ANNOUNCE_COMPONENT)?;
    e.uint(2)?;
    e.uint(ANNOUNCE_OBSERVED)?;
    e.uint(5)?;
    e.map(1)?;
    e.uint(1)?;
    e.array(entries.len() as u64)?;
    for entry in entries {
        e.map(8)?;
        e.uint(1)?;
        e.bytes_value(entry.device_id)?;
        e.uint(2)?;
        e.bytes_value(&entry.source_mac)?;
        e.uint(3)?;
        e.bytes_value(entry.source_ip)?;
        e.uint(4)?;
        e.uint(u64::from(entry.uptime_secs))?;
        e.uint(5)?;
        e.uint(u64::from(entry.transport_mode))?;
        e.uint(6)?;
        e.uint(u64::from(entry.counters))?;
        e.uint(7)?;
        e.uint(u64::from(entry.kind))?;
        e.uint(8)?;
        e.uint(u64::from(entry.last_seen_ms))?;
    }
    Some(e.len())
}

/// Encode bounded Follow-up receipt metadata without exposing Wi-Fi buffers
/// or overflowing the common control MTU.
pub fn encode_followups_observed_response(
    entries: &[ObservedFollowup],
    out: &mut [u8],
) -> Option<usize> {
    let mut e = Encoder::new(out);
    e.map(3)?;
    e.uint(1)?;
    e.uint(ANNOUNCE_COMPONENT)?;
    e.uint(2)?;
    e.uint(ANNOUNCE_FOLLOWUPS_OBSERVED)?;
    e.uint(5)?;
    e.map(1)?;
    e.uint(1)?;
    e.array(entries.len() as u64)?;
    for entry in entries {
        e.map(7)?;
        e.uint(1)?;
        e.bytes_value(&entry.source)?;
        e.uint(2)?;
        e.bytes_value(&entry.target)?;
        e.uint(3)?;
        e.uint(u64::from(entry.msg_type))?;
        e.uint(4)?;
        e.uint(u64::from(entry.seq))?;
        e.uint(5)?;
        e.uint(u64::from(entry.payload_len))?;
        e.uint(6)?;
        e.uint(u64::from(entry.payload_hash))?;
        e.uint(7)?;
        e.uint(u64::from(entry.last_seen_ms))?;
    }
    Some(e.len())
}

pub fn decode_record(record: Record<'_>) -> Option<Announce> {
    if record.component != Some(Name::Tag(ANNOUNCE_COMPONENT)) {
        return None;
    }
    let kind = match record.method? {
        Name::Tag(value @ (ANNOUNCE_BOOT | ANNOUNCE_DISCOVERY)) => value,
        _ => return None,
    };
    let mut d = Decoder::new(record.fields?);
    let (major, count) = d.head()?;
    if major != 5 || count == u64::MAX {
        return None;
    }
    let mut announce = Announce {
        kind,
        device_id: [0; MAX_DEVICE_ID],
        device_id_len: 0,
        uptime_secs: 0,
        transport_mode: 0,
        counters: 0,
        public_key: [0; MAX_PUBLIC_KEY],
        public_key_len: 0,
        signature: [0; SIGNATURE_LEN],
        signature_len: 0,
    };
    for _ in 0..count {
        match d.uint()? {
            FIELD_DEVICE_ID => {
                let id = d.bytes_ref()?;
                if id.is_empty() || id.len() > MAX_DEVICE_ID {
                    return None;
                }
                announce.device_id[..id.len()].copy_from_slice(id);
                announce.device_id_len = id.len() as u8;
            }
            FIELD_UPTIME_SECS => announce.uptime_secs = u32::try_from(d.uint()?).ok()?,
            FIELD_TRANSPORT_MODE => announce.transport_mode = u8::try_from(d.uint()?).ok()?,
            FIELD_COUNTERS => announce.counters = u32::try_from(d.uint()?).ok()?,
            FIELD_PUBLIC_KEY => {
                let key = d.bytes_ref()?;
                if key.is_empty() || key.len() > MAX_PUBLIC_KEY || !announce.public_key().is_empty()
                {
                    return None;
                }
                announce.public_key[..key.len()].copy_from_slice(key);
                announce.public_key_len = key.len() as u8;
            }
            FIELD_SIGNATURE => {
                let signature = d.bytes_ref()?;
                if signature.len() != SIGNATURE_LEN || !announce.signature().is_empty() {
                    return None;
                }
                announce.signature.copy_from_slice(signature);
                announce.signature_len = SIGNATURE_LEN as u8;
            }
            _ => d.skip()?,
        }
    }
    (announce.device_id_len != 0
        && (announce.public_key_len == 0) == (announce.signature_len == 0)
        && d.is_finished())
    .then_some(announce)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn announce_round_trips_as_one_direct_record() {
        let mut id = [0; MAX_DEVICE_ID];
        id[..6].copy_from_slice(b"e6-c6!");
        let announce = Announce::discovery(id, 6, 900, 1, 17);
        let mut wire = [0; 96];
        let used = encode(announce, &mut wire).unwrap();
        assert_eq!(decode_announce(&wire[..used]), Some(announce));
    }

    #[test]
    fn observed_request_is_separate_from_broadcast_presence() {
        let mut request = [0; 32];
        let used = encode_observed_request(&mut request).unwrap();
        assert!(is_observed_request(&request[..used]));
        assert!(decode_announce(&request[..used]).is_none());

        let entries = [ObservedAnnounce {
            device_id: b"e6-c6!",
            source_mac: [1, 2, 3, 4, 5, 6],
            source_ip: &[0; 16],
            uptime_secs: 20,
            transport_mode: 0,
            counters: 17,
            kind: ANNOUNCE_BOOT as u8,
            last_seen_ms: 500,
        }];
        let mut response = [0; 192];
        assert!(encode_observed_response(&entries, &mut response).is_some());
    }

    #[test]
    fn followup_observation_request_and_ten_entries_fit_control_mtu() {
        let mut request = [0; 32];
        let used = encode_followups_observed_request(&mut request).unwrap();
        assert!(is_followups_observed_request(&request[..used]));
        assert!(decode_announce(&request[..used]).is_none());

        let entry = ObservedFollowup {
            source: [1, 2, 3, 4, 5, 6],
            target: [6, 5, 4, 3, 2, 1],
            msg_type: 7,
            seq: 21,
            payload_len: 231,
            payload_hash: 0x1234_5678,
            last_seen_ms: 1_000,
        };
        let entries = [entry; 10];
        let mut response = [0; 1_100];
        assert!(encode_followups_observed_response(&entries, &mut response).is_some());
    }

    #[test]
    fn maximum_signed_host_announce_fits_host_scratch() {
        let mut id = [0; MAX_DEVICE_ID];
        id[..6].copy_from_slice(b"host01");
        let mut announce = Announce::discovery(id, 6, 1, 0, 0);
        assert!(announce.set_public_key(&[0x5a; MAX_PUBLIC_KEY]));
        assert!(announce.set_signature(&[0xa5; SIGNATURE_LEN]));
        let mut signing = [0; 384];
        assert!(signing_bytes(announce, &mut signing).is_some());
        let mut encoded = [0; 384];
        assert!(encode(announce, &mut encoded).is_some());
    }
}
