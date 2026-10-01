//! Minimal CBOR used by the object request and manifest protocol.
//!
//! The implementation lives in the portable `mesh-api` crate (no-alloc,
//! `Option`-based, minicbor-compatible method names) so firmware and host
//! share one codec. This module is the in-crate re-export; new DMesh code
//! may also reference `mesh_api::cbor` directly.
pub use mesh_api::cbor::*;

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
