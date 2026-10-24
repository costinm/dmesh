//! Public access to the packet header encoders, for interoperability tests of other implementations (the C classifier of esp-xip-modules).
//!
//! These are thin wrappers over the crate-private encoders: the layouts are the ones the nodes use, nothing is duplicated.

use crate::{
    ConnectionId, Error, ShortHeader, DMESH_LONG_HEADER_VERSION, LONG_PACKET_INITIAL, LONG_PACKET_PATH_OPEN,
    LONG_PACKET_PATH_OPEN_ACK,
};

/// Version of the DMesh long headers (Initial, PathOpen, PathOpenAck).
pub const LONG_HEADER_VERSION: u32 = DMESH_LONG_HEADER_VERSION;
/// Long packet type: Initial.
pub const TYPE_INITIAL: u8 = LONG_PACKET_INITIAL;
/// Long packet type: PathOpen.
pub const TYPE_PATH_OPEN: u8 = LONG_PACKET_PATH_OPEN;
/// Long packet type: PathOpenAck.
pub const TYPE_PATH_OPEN_ACK: u8 = LONG_PACKET_PATH_OPEN_ACK;

fn cid(value: Option<u64>) -> Result<Option<ConnectionId>, Error> {
    value.map(|v| ConnectionId::new(v).ok_or(Error::Invalid)).transpose()
}

/// A connection ID as it appears on the wire (1, 2, 4 or 8 bytes, the class in the first byte). Returns its length.
pub fn encode_connection_id(value: u64, out: &mut [u8]) -> Result<usize, Error> {
    ConnectionId::new(value).ok_or(Error::Invalid)?.encode(out)
}

/// A long-header packet of `packet_type` (see the `TYPE_*` constants) with the DCID and SCID values (None: an empty CID), the packet number
/// truncated to `packet_number_len` (1..=4) bytes and `payload`. Returns the packet length.
pub fn encode_long_packet(
    packet_type: u8,
    dcid: Option<u64>,
    scid: Option<u64>,
    packet_number: u32,
    packet_number_len: u8,
    payload: &[u8],
    out: &mut [u8],
) -> Result<usize, Error> {
    crate::encode_long_packet(packet_type, cid(dcid)?, cid(scid)?, packet_number, packet_number_len, payload, out)
}

/// A short-header packet: flags (fixed bit), the DCID, the packet number truncated to `packet_number_len` bytes, then `payload` (opaque).
pub fn encode_short_packet(dcid: u64, packet_number: u32, packet_number_len: u8, payload: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    let header = ShortHeader { flags: 0, dcid: ConnectionId::new(dcid).ok_or(Error::Invalid)?, packet_number, packet_number_len };
    let n = header.encode(out)?;
    let end = n.checked_add(payload.len()).ok_or(Error::BufferTooSmall)?;
    out.get_mut(n..end).ok_or(Error::BufferTooSmall)?.copy_from_slice(payload);
    Ok(end)
}

/// The relay's rewrite of the destination connection ID of `input` (a short or long packet) into `out`; returns the length. This is what a
/// relay does to a packet before sending it to the next hop.
pub fn rewrite_dcid(input: &[u8], outbound_dcid: u64, out: &mut [u8]) -> Result<usize, Error> {
    crate::rewrite_dcid(input, ConnectionId::new(outbound_dcid).ok_or(Error::Invalid)?, out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrappers_produce_the_documented_layouts() {
        let mut out = [0u8; 64];
        let n = encode_long_packet(TYPE_INITIAL, Some(0x2a), Some(0x1234), 7, 1, &[0xaa, 0xbb], &mut out).unwrap();
        assert_eq!(&out[..n], &[0xc0, 0x44, 0x4d, 0x00, 0x01, 0x01, 0x2a, 0x02, 0x92, 0x34, 0x00, 0x03, 0x07, 0xaa, 0xbb]);
        let n = encode_short_packet(0x12345, 9, 2, &[0xde, 0xad], &mut out).unwrap();
        assert_eq!(&out[..n], &[0x41, 0xa0, 0x01, 0x23, 0x45, 0x00, 0x09, 0xde, 0xad]);
        let mut rewritten = [0u8; 64];
        let m = rewrite_dcid(&out[..n], 0x2a, &mut rewritten).unwrap();
        assert_eq!(&rewritten[..m], &[0x41, 0x2a, 0x00, 0x09, 0xde, 0xad]);
    }
}
