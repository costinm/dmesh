//! Private device provisioning record carried only by a verified companion bearer.
//! A public NAN invitation opens a short window but never carries credentials.

use crate::{
    cbor::{Decoder, Encoder},
    tagged::{self, Name, Record},
};

pub const COMPONENT: u64 = 210;
pub const INSTALL: u64 = 1;
pub const UNPAIR: u64 = 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Install<'a> {
    pub name: &'a str,
    pub root_public_key: &'a [u8],
    pub secret: &'a [u8],
}

pub fn encode_install(id: u64, install: Install<'_>, out: &mut [u8]) -> Option<usize> {
    if !valid_install(install) {
        return None;
    }
    let mut e = Encoder::new(out);
    e.map(4)?;
    e.uint(1)?;
    e.uint(COMPONENT)?;
    e.uint(2)?;
    e.uint(INSTALL)?;
    e.uint(3)?;
    e.uint(id)?;
    e.uint(5)?;
    e.map(3)?;
    e.uint(1)?;
    e.text_value(install.name.as_bytes())?;
    e.uint(2)?;
    e.bytes_value(install.root_public_key)?;
    e.uint(3)?;
    e.bytes_value(install.secret)?;
    Some(e.len())
}

pub fn decode_install(record: Record<'_>) -> Option<Install<'_>> {
    if record.component != Some(Name::Tag(COMPONENT))
        || record.method != Some(Name::Tag(INSTALL))
        || record.id.is_none()
        || record.to.is_some()
        || record.params.is_some()
        || record.data.is_some()
        || record.result.is_some()
        || record.error.is_some()
    {
        return None;
    }
    let mut d = Decoder::new(record.fields?);
    let (major, count) = d.head()?;
    if major != 5 || count != 3 {
        return None;
    }
    let (mut name, mut root, mut secret) = (None, None, None);
    for _ in 0..count {
        match d.uint()? {
            1 if name.is_none() => name = Some(core::str::from_utf8(d.text_ref()?).ok()?),
            2 if root.is_none() => root = Some(d.bytes_ref()?),
            3 if secret.is_none() => secret = Some(d.bytes_ref()?),
            _ => return None,
        }
    }
    if !d.is_finished() {
        return None;
    }
    let install = Install {
        name: name?,
        root_public_key: root?,
        secret: secret?,
    };
    valid_install(install).then_some(install)
}

fn valid_install(value: Install<'_>) -> bool {
    !value.name.is_empty()
        && value.name.len() <= crate::announce::MAX_DEVICE_NAME
        && !value.name.as_bytes().contains(&0)
        && value.root_public_key.len() == 33
        && matches!(value.root_public_key[0], 2 | 3)
        && value.secret.len() == 32
}

pub fn encode_unpair(id: u64, out: &mut [u8]) -> Option<usize> {
    tagged::encode_numeric_empty_request(COMPONENT, UNPAIR, id, out)
}

pub fn is_unpair(record: Record<'_>) -> bool {
    record.component == Some(Name::Tag(COMPONENT))
        && record.method == Some(Name::Tag(UNPAIR))
        && record.id.is_some()
        && record.fields.is_none()
        && record.params.is_none()
        && record.data.is_none()
        && record.result.is_none()
        && record.error.is_none()
        && record.to.is_none()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn install_round_trip_preserves_binary_credentials_and_rejects_bad_keys() {
        let root = [2; 33];
        let secret = [7; 32];
        let install = Install {
            name: "sensor",
            root_public_key: &root,
            secret: &secret,
        };
        let mut wire = [0; 160];
        let len = encode_install(7, install, &mut wire).unwrap();
        assert_eq!(
            decode_install(tagged::decode(&wire[..len]).unwrap()),
            Some(install)
        );
        let bad = Install {
            root_public_key: &[4; 33],
            ..install
        };
        assert!(encode_install(7, bad, &mut wire).is_none());
    }
}
