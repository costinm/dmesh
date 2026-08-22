//! Bounded borrowed form of the common tagged-CBOR envelope.
//!
//! Keys 9 (`to`) and 10 (`data`) are routing metadata and opaque bytes.  They
//! stay borrowed from the ingress packet so a relay need not copy a blob just
//! to decide whether it executes or forwards the request.

use crate::cbor::{Decoder, Encoder};

/// A component, method, or mesh destination identifier.
///
/// `Bytes` is intentionally borrowed.  Device destinations are commonly a
/// six-byte MAC, an EUI-64, or another binary node id; forcing those through
/// a text or JSON representation would allocate and copy before the routing
/// decision has even been made.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Name<'a> {
    Tag(u64),
    Text(&'a [u8]),
    Bytes(&'a [u8]),
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Record<'a> {
    pub component: Option<Name<'a>>,
    pub method: Option<Name<'a>>,
    /// Correlation identifier. Direct records use the same request/response
    /// rule as streams; a bearer is free to drop a response, but it must not
    /// invent a second response envelope.
    pub id: Option<u64>,
    /// Encoded positional parameter array, retained for a typed handler to
    /// decode without an intermediate allocation.
    pub params: Option<&'a [u8]>,
    /// Encoded named-field map, retained for the same reason.  The bounded
    /// no-std handler owns field decoding; the envelope only identifies it.
    pub fields: Option<&'a [u8]>,
    /// Encoded successful result value. Responses retain a borrow just like
    /// request fields so direct UART/radio and QUIC callers use one envelope
    /// without copying a bounded snapshot through a text status wrapper.
    pub result: Option<&'a [u8]>,
    /// Encoded error value, normally text. It is deliberately opaque here:
    /// component schemas decide the typed error representation.
    pub error: Option<&'a [u8]>,
    pub to: Option<Name<'a>>,
    pub data: Option<&'a [u8]>,
}

fn name<'a>(decoder: &mut Decoder<'a>) -> Option<Name<'a>> {
    let at = decoder.position();
    if let Some(tag) = decoder.uint() {
        return Some(Name::Tag(tag));
    }
    decoder.set_position(at);
    if let Some(text) = decoder.text_ref() {
        return Some(Name::Text(text));
    }
    decoder.set_position(at);
    decoder.bytes_ref().map(Name::Bytes)
}

pub fn decode(packet: &[u8]) -> Option<Record<'_>> {
    let mut d = Decoder::new(packet);
    let (major, count) = d.head()?;
    if major != 5 || count == u64::MAX {
        return None;
    }
    let mut record = Record::default();
    for _ in 0..count {
        match d.uint()? {
            1 => record.component = Some(name(&mut d)?),
            2 => record.method = Some(name(&mut d)?),
            3 => record.id = Some(d.uint()?),
            4 => {
                let start = d.position();
                d.skip()?;
                record.params = Some(&packet[start..d.position()]);
            }
            5 => {
                let start = d.position();
                d.skip()?;
                record.fields = Some(&packet[start..d.position()]);
            }
            6 => {
                let start = d.position();
                d.skip()?;
                record.result = Some(&packet[start..d.position()]);
            }
            7 => {
                let start = d.position();
                d.skip()?;
                record.error = Some(&packet[start..d.position()]);
            }
            9 => record.to = Some(name(&mut d)?),
            10 => record.data = Some(d.bytes_ref()?),
            _ => d.skip()?,
        }
    }
    (d.is_finished() && record.method.is_some()).then_some(record)
}

/// Read only the optional destination from a top-level envelope map.
///
/// This intentionally also accepts a legacy direct-record map: adapters use
/// it as a guard before passing that map to an older, narrower decoder.  A
/// directed legacy record must be rejected or forwarded, never accidentally
/// executed locally merely because the old decoder skips unknown root keys.
pub fn destination(packet: &[u8]) -> Result<Option<Name<'_>>, ()> {
    let mut d = Decoder::new(packet);
    let (major, count) = d.head().ok_or(())?;
    if major != 5 || count == u64::MAX {
        return Err(());
    }
    let mut to = None;
    for _ in 0..count {
        match d.uint().ok_or(())? {
            9 => to = Some(name(&mut d).ok_or(())?),
            _ => d.skip().ok_or(())?,
        }
    }
    d.is_finished().then_some(to).ok_or(())
}

/// Encode a correlated successful response in the common tagged envelope.
///
/// The caller supplies one complete, already bounded CBOR result value. This
/// preserves snapshots and setting values without an intermediate text/JSON
/// conversion. Requests with textual or binary component/method names need a
/// component-specific encoder; the common firmware control components use
/// numeric identities and therefore use this compact form.
pub fn encode_numeric_response(
    component: u64,
    method: u64,
    id: u64,
    result: &[u8],
    out: &mut [u8],
) -> Option<usize> {
    let mut encoder = Encoder::new(out);
    encoder.map(4)?;
    encoder.uint(1)?;
    encoder.uint(component)?;
    encoder.uint(2)?;
    encoder.uint(method)?;
    encoder.uint(3)?;
    encoder.uint(id)?;
    encoder.uint(6)?;
    encoder.encoded_value(result)?;
    Some(encoder.len())
}

#[cfg(test)]
mod tests {
    use super::{Name, decode, destination, encode_numeric_response};
    #[test]
    fn destination_and_binary_payload_stay_borrowed() {
        let wire = [
            0xa4, 1, 4, 2, 8, 9, 0x62, b'e', b'7', 10, 0x43, 0, 0xff, 0x7e,
        ];
        let record = decode(&wire).unwrap();
        assert_eq!(record.method, Some(Name::Tag(8)));
        assert_eq!(record.to, Some(Name::Text(b"e7")));
        assert_eq!(record.data, Some(&wire[11..14]));
    }

    #[test]
    fn binary_destination_stays_borrowed_too() {
        let wire = [0xa3, 1, 4, 2, 8, 9, 0x46, 2, 0, 0, 0, 0, 7];
        let record = decode(&wire).unwrap();
        assert_eq!(record.to, Some(Name::Bytes(&wire[7..13])));
    }

    #[test]
    fn result_and_error_stay_borrowed() {
        // {1: 4, 2: 73, 6: {20: 1}, 7: "ignored"}
        let wire = [
            0xa4, 1, 4, 2, 24, 73, 6, 0xa1, 20, 1, 7, 0x67, b'i', b'g', b'n', b'o', b'r', b'e',
            b'd',
        ];
        let record = decode(&wire).unwrap();
        assert_eq!(record.result, Some(&wire[7..10]));
        assert_eq!(record.error, Some(&wire[11..19]));
    }

    #[test]
    fn numeric_response_preserves_id_and_encoded_result() {
        let mut wire = [0; 32];
        let used = encode_numeric_response(1, 2, 9, &[0xa0], &mut wire).unwrap();
        let record = decode(&wire[..used]).unwrap();
        assert_eq!(record.component, Some(Name::Tag(1)));
        assert_eq!(record.method, Some(Name::Tag(2)));
        assert_eq!(record.id, Some(9));
        assert_eq!(record.result, Some(&[0xa0][..]));
    }

    #[test]
    fn destination_probe_covers_legacy_direct_records() {
        // Key 0/6 are the pre-tagged Recovery command shape.  The probe must
        // still find key 9 before a legacy decoder gets a chance to skip it.
        let wire = [0xa3, 0, 0x18, 0x44, 6, 0xa0, 9, 0x62, b'e', b'7'];
        assert_eq!(destination(&wire), Ok(Some(Name::Text(b"e7"))));
    }
}
