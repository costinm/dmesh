//! Minimal CBOR used by the object request and manifest protocol.
//!
//! The implementation lives in the portable `mesh-api` crate (no-alloc,
//! `Option`-based, minicbor-compatible method names) so firmware and host
//! share one codec. This module is the in-crate re-export; new DMesh code
//! may also reference `mesh_api::cbor` directly.
pub use mesh_api::cbor::*;

/// Borrowed scalar values for small structured events. No text formatting or
/// allocation is needed to construct the numeric-tagged map.
#[derive(Clone, Copy)]
pub enum FieldValue<'a> {
    Unsigned(u64),
    Signed(i64),
    Bool(bool),
    Text(&'a str),
    Null,
}

/// Encode ordered, unique numeric fields into a caller-provided buffer.
/// Invalid tags or insufficient space fail explicitly instead of truncating.
pub fn encode_fields(out: &mut [u8], fields: &[(u64, FieldValue<'_>)]) -> Option<usize> {
    let mut encoder = Encoder::new(out);
    encode_fields_into(&mut encoder, fields)?;
    Some(encoder.len())
}

/// Append an ordered field map without an intermediate stack buffer.
pub fn encode_fields_into(encoder: &mut Encoder<'_>, fields: &[(u64, FieldValue<'_>)]) -> Option<()> {
    if fields.windows(2).any(|pair| pair[0].0 >= pair[1].0) {
        return None;
    }
    encoder.map(fields.len() as u64)?;
    for (tag, value) in fields {
        encoder.uint(*tag)?;
        match value {
            FieldValue::Unsigned(value) => encoder.uint(*value)?,
            FieldValue::Signed(value) => encoder.int(*value)?,
            FieldValue::Bool(value) => encoder.bool(*value)?,
            FieldValue::Text(value) => encoder.text_value(value.as_bytes())?,
            FieldValue::Null => encoder.encoded_value(&[0xf6])?,
        }
    }
    Some(())
}

#[cfg(test)]
mod event_fields_tests {
    use super::*;
    #[test]
    fn typed_fields_preserve_values_without_formatting() {
        let mut out = [0; 64];
        let size = encode_fields(&mut out, &[(1, FieldValue::Text("example")), (2, FieldValue::Unsigned(3)), (3, FieldValue::Bool(true))]).unwrap();
        let mut decoder = Decoder::new(&out[..size]);
        assert_eq!(decoder.head(), Some((5, 3)));
        assert_eq!(decoder.uint(), Some(1));
        assert_eq!(decoder.text_ref(), Some(&b"example"[..]));
        assert_eq!(decoder.uint(), Some(2));
        assert_eq!(decoder.uint(), Some(3));
        assert_eq!(decoder.uint(), Some(3));
        assert_eq!(decoder.boolean(), Some(true));
        assert!(decoder.is_finished());
    }
    #[test]
    fn overflow_and_duplicate_tags_fail_instead_of_truncating() {
        assert!(encode_fields(&mut [0; 2], &[(1, FieldValue::Text("example"))]).is_none());
        assert!(encode_fields(&mut [0; 64], &[(1, FieldValue::Unsigned(1)), (1, FieldValue::Unsigned(2))]).is_none());
    }
}

/// Encode one host-side JSON value as the CBOR result payload of a numeric
/// tagged response. Object keys become text keys, so a constrained peer reads
/// the same field vocabulary the catalog documents. The compact firmware
/// responses stay hand-encoded; this helper only serves host services whose
/// results already exist as JSON.
#[cfg(feature = "std")]
pub fn encode_json_value(value: &serde_json::Value, out: &mut [u8]) -> Option<usize> {
    fn encode(encoder: &mut Encoder, value: &serde_json::Value) -> Option<()> {
        match value {
            serde_json::Value::Null => encoder.encoded_value(&[0xf6]),
            serde_json::Value::Bool(value) => encoder.bool(*value),
            serde_json::Value::Number(number) => {
                if let Some(value) = number.as_u64() {
                    encoder.uint(value)
                } else {
                    encoder.int(number.as_i64()?)
                }
            }
            serde_json::Value::String(value) => encoder.text_value(value.as_bytes()),
            serde_json::Value::Array(items) => {
                encoder.array(items.len() as u64)?;
                for item in items {
                    encode(encoder, item)?;
                }
                Some(())
            }
            serde_json::Value::Object(fields) => {
                encoder.map(fields.len() as u64)?;
                for (key, item) in fields {
                    encoder.text_value(key.as_bytes())?;
                    encode(encoder, item)?;
                }
                Some(())
            }
        }
    }

    let mut encoder = Encoder::new(out);
    encode(&mut encoder, value)?;
    Some(encoder.len())
}
