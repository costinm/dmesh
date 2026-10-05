//! REST-style requests in the tagged-CBOR envelope: component 2002 (`mesh::http_ids`), the verb as
//! the method, the path as `params`, the headers as `fields`, the body as the stream body.
//!
//! This is the generic form `POST /flash` uses; the wire rules are in ssh-mesh
//! `mesh-api/PROTOCOLS.md` ("HTTP component"). There is no router layer: the registry dispatches on
//! the list `[component, method, path...]` and the longest registered prefix wins (see
//! `Registry::register_stream_at`).

extern crate alloc;
use crate::cbor::{Decoder, Encoder};

pub const COMPONENT: u64 = 2002;

/// Verbs, numbered as the CoAP request codes.
pub mod verb {
    pub const GET: u64 = 1;
    pub const POST: u64 = 2;
    pub const PUT: u64 = 3;
    pub const DELETE: u64 = 4;
    pub const FETCH: u64 = 5;
    pub const PATCH: u64 = 6;
}

/// A header: its number and its text name are the same header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Header {
    pub number: u64,
    pub name: &'static str,
}

/// Reserved headers (keys 0..=63).
pub const STATUS: Header = Header { number: 0, name: "status" };
pub const CONTENT_LENGTH: Header = Header { number: 1, name: "content-length" };
pub const CONTENT_TYPE: Header = Header { number: 2, name: "content-type" };
/// First header key a resource may define.
pub const APPLICATION_BASE: u64 = 64;

/// A header key as it appears on the wire.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Key<'a> {
    Number(u64),
    Text(&'a [u8]),
}

impl Key<'_> {
    pub fn is(&self, header: Header) -> bool {
        match *self {
            Key::Number(number) => number == header.number,
            Key::Text(text) => text == header.name.as_bytes(),
        }
    }
}

/// Walk a header map. `each` is called with every key and a decoder positioned at its value, and
/// must consume exactly that value (returning `None` rejects the request, for an unknown header,
/// a malformed value or a duplicate). Returns `None` for anything but a definite map of entries.
pub fn for_each_header<'a>(
    fields: &'a [u8],
    mut each: impl FnMut(Key<'a>, &mut Decoder<'a>) -> Option<()>,
) -> Option<()> {
    let mut decoder = Decoder::new(fields);
    let (major, count) = decoder.head()?;
    if major != 5 {
        return None;
    }
    for _ in 0..count {
        let at = decoder.position();
        let key = match decoder.uint() {
            Some(number) => Key::Number(number),
            None => {
                decoder.set_position(at);
                Key::Text(decoder.text_ref()?)
            }
        };
        each(key, &mut decoder)?;
    }
    decoder.is_finished().then_some(())
}

/// One element of a dispatch key: a number or a text string. The registry key is the list
/// `[component, method, path...]`: for `POST /flash` that is `[http, post, FLASH]`, for a static
/// file server `[http, get, "service.namespace.example.com", "path1"]` registered as a prefix.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Seg {
    Num(u64),
    Text(&'static str),
}

/// The number of path segments in an encoded `params` array (`None` when it is not an array).
pub fn path_len(params: &[u8]) -> Option<usize> {
    let mut decoder = Decoder::new(params);
    match decoder.head()? {
        (4, count) => usize::try_from(count).ok(),
        _ => None,
    }
}

/// Whether the encoded `params` path starts with `prefix` (every element equal as a number or as
/// text). An empty prefix matches any path, including no `params` at all.
pub fn path_starts_with(params: Option<&[u8]>, prefix: &[Seg]) -> bool {
    if prefix.is_empty() {
        return true;
    }
    let Some(params) = params else {
        return false;
    };
    let mut decoder = Decoder::new(params);
    let Some((4, count)) = decoder.head() else {
        return false;
    };
    if count < prefix.len() as u64 {
        return false;
    }
    for segment in prefix {
        let matched = match *segment {
            Seg::Num(expected) => decoder.uint() == Some(expected),
            Seg::Text(expected) => decoder.text_ref() == Some(expected.as_bytes()),
        };
        if !matched {
            return false;
        }
    }
    true
}

/// Encode a request: `{1: 2002, 2: verb, 3: id, 4: path, 5: headers}`. `path` and `headers` are
/// already encoded CBOR (an array and a map).
pub fn encode_request(verb: u64, id: u64, path: &[u8], headers: &[u8], out: &mut [u8]) -> Option<usize> {
    let mut encoder = Encoder::new(out);
    encoder.map(5)?;
    encoder.uint(1)?;
    encoder.uint(COMPONENT)?;
    encoder.uint(2)?;
    encoder.uint(verb)?;
    encoder.uint(3)?;
    encoder.uint(id)?;
    encoder.uint(4)?;
    encoder.encoded_value(path)?;
    encoder.uint(5)?;
    encoder.encoded_value(headers)?;
    Some(encoder.len())
}

/// Encode a terminal response header: `{1: 2002, 2: verb, 3: id, 5: {0: status}, 6|7: ...}`. A
/// status below 400 carries `message` as the result text, otherwise as the error text.
pub fn encode_response(verb: u64, id: u64, status: u16, message: &[u8], out: &mut [u8]) -> Option<usize> {
    let mut encoder = Encoder::new(out);
    encoder.map(5)?;
    encoder.uint(1)?;
    encoder.uint(COMPONENT)?;
    encoder.uint(2)?;
    encoder.uint(verb)?;
    encoder.uint(3)?;
    encoder.uint(id)?;
    encoder.uint(5)?;
    encoder.map(1)?;
    encoder.uint(STATUS.number)?;
    encoder.uint(u64::from(status))?;
    encoder.uint(if status < 400 { 6 } else { 7 })?;
    encoder.text_value(message)?;
    Some(encoder.len())
}

/// The status of a response header, if it carries one.
pub fn response_status(record: &crate::tagged::Record<'_>) -> Option<u16> {
    let mut status = None;
    for_each_header(record.fields?, |key, decoder| {
        if key.is(STATUS) {
            status = Some(u16::try_from(decoder.uint()?).ok()?);
            Some(())
        } else {
            decoder.skip()
        }
    })?;
    status
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path(segments: &[&dyn Fn(&mut Encoder<'_>)]) -> Vec<u8> {
        let mut out = [0u8; 64];
        let mut encoder = Encoder::new(&mut out);
        encoder.array(segments.len() as u64).unwrap();
        for segment in segments {
            segment(&mut encoder);
        }
        let used = encoder.len();
        out[..used].to_vec()
    }

    #[test]
    fn a_dispatch_prefix_matches_numbers_and_text_in_order() {
        let flash = path(&[&|e| e.uint(10).unwrap()]);
        assert!(path_starts_with(Some(&flash), &[Seg::Num(10)]));
        assert!(!path_starts_with(Some(&flash), &[Seg::Num(11)]));
        assert!(!path_starts_with(Some(&flash), &[Seg::Text("flash")]));
        assert!(!path_starts_with(Some(&flash), &[Seg::Num(10), Seg::Num(1)]));
        assert!(path_starts_with(Some(&flash), &[]));
        assert!(path_starts_with(None, &[]));
        assert!(!path_starts_with(None, &[Seg::Num(10)]));
        assert_eq!(path_len(&flash), Some(1));

        let file = path(&[
            &|e| e.text_value(b"service.namespace.example.com").unwrap(),
            &|e| e.text_value(b"path1").unwrap(),
            &|e| e.uint(7).unwrap(),
        ]);
        assert!(path_starts_with(Some(&file), &[Seg::Text("service.namespace.example.com")]));
        assert!(path_starts_with(
            Some(&file),
            &[Seg::Text("service.namespace.example.com"), Seg::Text("path1")]
        ));
        assert!(!path_starts_with(Some(&file), &[Seg::Text("other"), Seg::Text("path1")]));
        assert!(!path_starts_with(Some(&file), &[Seg::Num(1)]));
        assert_eq!(path_len(&file), Some(3));
    }

    #[test]
    fn headers_accept_number_or_text_keys_and_reject_what_the_caller_refuses() {
        // {1: 7, "x": 2}
        let mut out = [0u8; 32];
        let mut encoder = Encoder::new(&mut out);
        encoder.map(2).unwrap();
        encoder.uint(1).unwrap();
        encoder.uint(7).unwrap();
        encoder.text_value(b"content-length").unwrap();
        encoder.uint(9).unwrap();
        let used = encoder.len();
        let mut seen = Vec::new();
        for_each_header(&out[..used], |key, decoder| {
            assert!(key.is(CONTENT_LENGTH));
            seen.push(decoder.uint()?);
            Some(())
        })
        .unwrap();
        assert_eq!(seen, [7, 9]);
        assert!(for_each_header(&out[..used], |_, _| None).is_none());
        assert!(for_each_header(&out[..used - 1], |_, d| d.skip()).is_none());
    }

    #[test]
    fn a_response_carries_the_status_in_its_headers_and_the_message_as_result_or_error() {
        let mut out = [0u8; 64];
        let used = encode_response(verb::POST, 5, 200, b"done", &mut out).unwrap();
        let record = crate::tagged::decode(&out[..used]).unwrap();
        assert_eq!(response_status(&record), Some(200));
        assert!(record.result.is_some() && record.error.is_none());
        let used = encode_response(verb::POST, 5, 503, b"busy", &mut out).unwrap();
        let record = crate::tagged::decode(&out[..used]).unwrap();
        assert_eq!(response_status(&record), Some(503));
        assert!(record.error.is_some() && record.result.is_none());
    }
}
