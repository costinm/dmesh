//! Bearer-neutral direct-command dispatch.
//!
//! A complete raw record may arrive through UART PPP, raw UDP6, or an action
//! bearer. This module decodes it once and invokes a registered handler; it
//! deliberately owns no socket, radio, response queue, or persistent profile.

use crate::tagged::{Name, Record, decode as decode_tagged};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RawDispatchError {
    Decode,
    Rejected,
}

/// Routing result determined before a platform handler sees a record. A
/// forwarding adapter can retain `packet` and its borrowed `data` payload;
/// local firmware must not execute a request addressed to another device.
///
/// `Forward` is deliberately only a classification here.  The mesh relay owns
/// the next-hop selection and packet lifetime; the schema crate must not grow
/// a hidden forwarding queue or copy a large `data` field into one.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TaggedRoute<'a> {
    Local(Record<'a>),
    Forward(Record<'a>),
}

pub fn route_tagged<'a, F>(
    packet: &'a [u8],
    is_local: F,
) -> Result<TaggedRoute<'a>, RawDispatchError>
where
    F: FnOnce(Name<'a>) -> bool,
{
    let record = decode_tagged(packet).ok_or(RawDispatchError::Decode)?;
    Ok(match record.to {
        Some(destination) if !is_local(destination) => TaggedRoute::Forward(record),
        _ => TaggedRoute::Local(record),
    })
}

#[cfg(test)]
mod tests {
    use super::{TaggedRoute, route_tagged};
    use crate::tagged::Name;

    #[test]
    fn destination_is_routed_before_local_handler_dispatch() {
        let wire = [0xa3, 1, 4, 2, 8, 9, 0x62, b'e', b'7'];
        assert!(matches!(
            route_tagged(&wire, |_| false),
            Ok(TaggedRoute::Forward(_))
        ));
        assert!(matches!(
            route_tagged(&wire, |to| to == Name::Text(b"e7")),
            Ok(TaggedRoute::Local(_))
        ));
    }
}
