#![no_std]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(unreachable_pub)]

//! Bearer-neutral QUIC(-lite) packet transport.
//!
//! [`QuicNode`] owns the client/server association and DCID namespace for one
//! logical node. See [`bearer`] for the physical packet I/O contract.

extern crate alloc;
use alloc::vec::Vec;

#[cfg(all(feature = "std", not(test)))]
extern crate std;

pub mod bearer;
pub mod bearer_framed;
pub mod callback;
mod connection;
mod mux;
mod node;
pub mod nostd;
mod peer_table;

#[cfg(feature = "tokio")]
pub mod bearer_udp;
pub mod heap_packet_pool;
pub mod packet_pool;
pub mod probe;

mod relay;
#[cfg(feature = "tokio")]
pub mod tokio;

pub use bearer::{
    AddBearerError, BearerContext, BearerId, BearerInfo, BearerName, BearerRegistryError,
    EgressSubmission, OwnedPacket, PacketBearer, PacketBuildError, PacketCompletionToken,
    PacketEgress, PacketMeta, PacketPool, PacketSendOutcome, PacketSubmitError, PacketWriter,
    PeerL2Address,
};
pub use node::{
    AssociationEvent, AssociationLimits, DEFAULT_PACKET_POOL_SLOT_SIZE, NodeLimits,
    PACKET_PREFIX_RESERVE, PACKET_SUFFIX_RESERVE, QuicAssociation, QuicNode, QuicNodeEgressError,
    QuicNodeError, QuicStream, ReceivedStreamChunk,
};

#[cfg(any(feature = "std", test))]
pub mod fake;

#[cfg(test)]
extern crate std;

use core::cmp::{max, min};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

pub(crate) const FLAG_FIXED: u8 = 0x40;
pub(crate) const FLAG_RESERVED: u8 = 0x18;
pub(crate) const FLAG_KEY_PHASE: u8 = 0x04;

/// QUIC requires a stateless-reset token to be indistinguishable from random
/// bytes to an off-path observer.  The issuer derives it from a secret that
/// survives association-table eviction (and, in production, process/device
/// restart) plus the CID it issued to the peer.
///
/// This is deliberately a quic-lite primitive: bearers neither construct a
/// reset packet nor inspect its token.  They only write the opaque packet
/// selected by an association owner.
pub(crate) const STATELESS_RESET_TOKEN_LEN: usize = 16;
const STATELESS_RESET_MIN_PACKET_LEN: usize = 21;

// PSP-inspired key-schedule boundary: every protocol purpose gets a stable,
// versioned label below the device/control-plane root.  Stateless reset is the
// first consumer because it needs restart recovery before packet encryption is
// deployed.  Future authenticated receive/traffic keys must add their own
// labels here rather than deriving from the reset key or reusing reset tokens.
// This is deliberately only a DMesh key-separation model; it is not a claim
// of PSP message or wire-format compatibility.
const DEVICE_SECRET_RESET_KEY_LABEL: &[u8] = b"dmesh/quic-lite/reset-key/v1";
const STATELESS_RESET_TOKEN_LABEL: &[u8] = b"dmesh/quic-lite/stateless-reset/v1";
const STATELESS_RESET_PREFIX_LABEL: &[u8] = b"dmesh/quic-lite/stateless-reset/prefix/v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Device-derived key used by [`QuicNode`] to authenticate stateless resets.
///
/// This type is public because an application owns device secrets and must
/// supply the derived key when it constructs a node. Bearers never receive or
/// inspect it; all reset-token generation remains inside QUIC-lite.
pub struct StatelessResetKey([u8; 32]);

impl StatelessResetKey {
    /// Derive the reset-key branch from the provisioned device/control-plane
    /// secret. This is the narrow PSP-style schedule boundary for DMesh:
    /// reset and future receive-encryption keys intentionally use separate
    /// labels, so exposing a reset token never reuses traffic-key material.
    /// The root itself remains in NVS or the platform's private equivalent and
    /// never enters a packet or settings response. This reserves compatible
    /// key-separation semantics; it does not claim PSP wire compatibility.
    pub fn from_device_secret(secret: &[u8]) -> Result<Self, Error> {
        if secret.len() < 16 {
            return Err(Error::Invalid);
        }
        let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("HMAC accepts secret bytes");
        mac.update(DEVICE_SECRET_RESET_KEY_LABEL);
        let digest = mac.finalize().into_bytes();
        let mut key = [0u8; 32];
        key.copy_from_slice(&digest);
        Ok(Self(key))
    }

    /// Derive the reset token advertised for one locally-issued receive CID.
    /// A host/service supplies stable key material; a random boot-only key
    /// would not let a restarted endpoint reset associations from before the
    /// restart and therefore does not satisfy the recovery contract.
    pub(crate) fn token_for(self, cid: ConnectionId) -> StatelessResetToken {
        let mut cid_bytes = [0u8; 8];
        let cid_len = cid
            .encode(&mut cid_bytes)
            .expect("CID buffer is fixed-size");
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.0).expect("HMAC accepts 32-byte key");
        mac.update(STATELESS_RESET_TOKEN_LABEL);
        mac.update(&cid_bytes[..cid_len]);
        let digest = mac.finalize().into_bytes();
        let mut token = [0u8; STATELESS_RESET_TOKEN_LEN];
        token.copy_from_slice(&digest[..STATELESS_RESET_TOKEN_LEN]);
        StatelessResetToken(token)
    }

    /// Form an RFC 9000-style opaque stateless reset for an unknown
    /// short-header CID.  The triggering packet length is retained to avoid
    /// becoming a packet-size oracle.  The HMAC-generated prefix is opaque;
    /// the final bytes are the receiver-recognized token.
    pub(crate) fn encode_for_unknown_packet(
        self,
        triggering_packet: &[u8],
        out: &mut [u8],
    ) -> Result<Option<usize>, Error> {
        let (header, _) = ShortHeader::decode(triggering_packet)?;
        self.encode_for_unknown_cid(triggering_packet, header.dcid, out)
    }

    /// Internal reset formatter after QUIC-lite has decoded the unknown
    /// destination. Bearers must use [`Self::encode_for_unknown_packet`] so
    /// they never inspect a QUIC header merely to obtain a CID.
    fn encode_for_unknown_cid(
        self,
        triggering_packet: &[u8],
        unknown_dcid: ConnectionId,
        out: &mut [u8],
    ) -> Result<Option<usize>, Error> {
        if triggering_packet.len() < STATELESS_RESET_MIN_PACKET_LEN
            || triggering_packet
                .first()
                .is_none_or(|first| first & 0x80 != 0)
        {
            return Ok(None);
        }
        let used = triggering_packet.len().min(out.len());
        if used < STATELESS_RESET_MIN_PACKET_LEN {
            return Err(Error::BufferTooSmall);
        }
        let token = self.token_for(unknown_dcid);
        let mut cid_bytes = [0u8; 8];
        let cid_len = unknown_dcid.encode(&mut cid_bytes)?;
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.0).expect("HMAC accepts 32-byte key");
        mac.update(STATELESS_RESET_PREFIX_LABEL);
        mac.update(&cid_bytes[..cid_len]);
        mac.update(&(used as u64).to_be_bytes());
        let digest = mac.finalize().into_bytes();
        for (index, byte) in out[..used - STATELESS_RESET_TOKEN_LEN]
            .iter_mut()
            .enumerate()
        {
            *byte = digest[index % digest.len()] ^ (index as u8).wrapping_mul(0x9d);
        }
        // This implementation has no packet protection yet.  Make the
        // opaque reset fail the local pre-protection header parser so a
        // shared listener can offer it to candidate associations by ingress
        // path; quic-lite then performs the token comparison.  Full QUIC
        // packet protection naturally supplies this indistinguishability.
        out[0] &= 0x3f;
        out[used - STATELESS_RESET_TOKEN_LEN..used].copy_from_slice(&token.0);
        Ok(Some(used))
    }
}

/// Opaque state retained by an association after the peer issued its CID.
/// It is intentionally not serializable and has no public byte accessor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct StatelessResetToken([u8; STATELESS_RESET_TOKEN_LEN]);

impl StatelessResetToken {
    /// Recognize a reset only after normal association parsing has failed.
    /// A valid packet can end in the same bytes by chance, so calling this
    /// before normal packet authentication/parsing would be unsafe.
    pub(crate) fn matches_packet(self, input: &[u8]) -> bool {
        if input.len() < STATELESS_RESET_MIN_PACKET_LEN {
            return false;
        }
        let suffix = &input[input.len() - STATELESS_RESET_TOKEN_LEN..];
        let mut different = 0u8;
        for (received, expected) in suffix.iter().zip(self.0.iter()) {
            different |= received ^ expected;
        }
        different == 0
    }
}

pub(crate) const CONTROL_STREAM_ID: u64 = 0;
pub(crate) const FIRST_CLIENT_BIDI_STREAM_ID: u64 = 4;
pub(crate) const FIRST_SERVER_BIDI_STREAM_ID: u64 = 1;
/// Default bearer payload bound shared by UART, UDP, and the current extended
/// ESP-NOW/vendor-action frame. Keep every current bearer at 1,100 bytes:
/// this fits the proven firmware action ingress without relying on L2
/// fragmentation or per-bearer MTU negotiation.
pub const DEFAULT_MAX_PACKET_SIZE: usize = 1100;
/// Conservative one-packet application payload after short-header and
/// stream-frame overhead. Commands using this bound never rely on L2
/// fragmentation, even when CID/varint widths grow.
pub const DEFAULT_MAX_STREAM_PAYLOAD: usize = DEFAULT_MAX_PACKET_SIZE - 64;
/// Maximum simultaneously live stream records for one association. Storage
/// grows with active streams and is released when both halves complete; this
/// constant is an admission limit, not an eagerly allocated slot array.
pub(crate) const DEFAULT_STREAM_STATE_LIMIT: usize = 32;
/// Initial per-direction peer stream credit. Closed streams advance this limit
/// through MAX_STREAMS, so it limits concurrency rather than association
/// lifetime.
pub(crate) const DEFAULT_MAX_BIDI_STREAMS: u64 = 16;
#[cfg(test)]
const DEFAULT_MAX_IN_FLIGHT_PACKETS: u16 = 32;
/// Generic diagnostic ceiling for explicitly requested packet flights.
pub(crate) const MAX_DIAGNOSTIC_IN_FLIGHT_PACKETS: u16 = 64;
/// Default callback/reassembly allowance for a full diagnostic flight while
/// an earlier packet is repaired. Applications may inject a smaller value.
pub(crate) const DEFAULT_REORDER_CAPACITY_BYTES: usize =
    MAX_DIAGNOSTIC_IN_FLIGHT_PACKETS as usize * DEFAULT_MAX_PACKET_SIZE;
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct ConnectionId(u64);

impl ConnectionId {
    pub(crate) const MAX_VALUE: u64 = (1u64 << 61) - 1;

    pub(crate) const fn new(value: u64) -> Option<Self> {
        if value <= Self::MAX_VALUE {
            Some(Self(value))
        } else {
            None
        }
    }

    pub(crate) const fn value(self) -> u64 {
        self.0
    }

    /// CID byte 0 has a dedicated length class: `0` is a one-byte CID;
    /// `100`, `101`, and `110` select 2, 4, and 8 bytes respectively.
    /// `111` is reserved and rejected by the decoder.
    pub(crate) const fn encoded_len(self) -> usize {
        if self.0 <= 0x7f {
            1
        } else if self.0 <= 0x1fff {
            2
        } else if self.0 <= 0x1fff_ffff {
            4
        } else {
            8
        }
    }

    pub(crate) fn encode(self, out: &mut [u8]) -> Result<usize, Error> {
        let n = self.encoded_len();
        if out.len() < n {
            return Err(Error::BufferTooSmall);
        }
        let tag = match n {
            1 => 0,
            2 => 0b100,
            4 => 0b101,
            _ => 0b110,
        } << 5;
        for i in 0..n {
            out[i] = (self.0 >> (8 * (n - i - 1))) as u8;
        }
        out[0] = (out[0] & if n == 1 { 0x7f } else { 0x1f }) | tag;
        Ok(n)
    }

    pub(crate) fn decode(input: &[u8]) -> Result<(Self, usize), Error> {
        if input.is_empty() {
            return Err(Error::Truncated);
        }
        let (n, value_mask) = if input[0] & 0x80 == 0 {
            (1, 0x7f)
        } else {
            match (input[0] >> 5) & 0x03 {
                0 => (2, 0x1f),
                1 => (4, 0x1f),
                2 => (8, 0x1f),
                _ => return Err(Error::Invalid),
            }
        };
        if input.len() < n {
            return Err(Error::Truncated);
        }
        let mut value = (input[0] & value_mask) as u64;
        for &b in &input[1..n] {
            value = (value << 8) | b as u64;
        }
        let cid = Self(value);
        if cid.encoded_len() != n {
            return Err(Error::Invalid);
        }
        Ok((cid, n))
    }

    /// Build a relay-local CID from the node-local label and 1-based distance
    /// from the source. Labels 0 and 1 are reserved for bootstrap and control
    /// allocation respectively.
    pub(crate) const fn relay_local(label: u64, position: u8) -> Option<Self> {
        if label < 2 || position == 0 {
            return None;
        }
        if position <= 4 && label <= 0x1f {
            return Self::new((label << 2) | (position - 1) as u64);
        }
        if position <= 16 && label <= ((1u64 << 57) - 1) {
            return Self::new((label << 4) | (position - 1) as u64);
        }
        None
    }

    /// Return the node-local label and 1-based source distance encoded by a
    /// non-zero relay-local CID. Callers enforce whether an endpoint CID is
    /// being used as a relay label for a particular direction.
    pub(crate) const fn relay_parts(self) -> Option<(u64, u8)> {
        if self.0 == 0 {
            return None;
        }
        let hop_bits = if self.encoded_len() == 1 { 2 } else { 4 };
        let hop_mask = (1u64 << hop_bits) - 1;
        Some((
            self.0 >> hop_bits,
            ((self.0 & hop_mask) as u8).saturating_add(1),
        ))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Protocol errors which an application may need to distinguish from bearer
/// I/O failures.
///
/// The enum is public because stream and association operations preserve these
/// causes. Packet parsing itself remains private to the node.
pub enum Error {
    /// The caller-provided output region cannot hold the encoded value.
    BufferTooSmall,
    /// A received packet ended before a complete encoded value was available.
    Truncated,
    /// A value is structurally complete but invalid for the current state.
    Invalid,
    /// Sending is temporarily blocked by congestion or peer packet capacity.
    Blocked,
    /// A QUIC variable-length integer has an invalid representation.
    InvalidVarint,
    /// Sending would exceed peer-advertised connection or stream credit.
    FlowControl,
    /// Opening a stream would exceed the peer-advertised stream count.
    StreamLimit,
    /// The packet-number space cannot represent another packet.
    PacketNumberExhausted,
    /// The packet names a connection other than the selected association.
    WrongConnectionId,
    /// An opaque inbound packet matched the reset token issued by the peer
    /// for this association.  The association is no longer usable; its
    /// manager must create a fresh one before sending another stream.
    PeerRestarted,
    /// The association handshake does not match the expected state or values.
    BootstrapInvalid,
    /// Retained unacknowledged packet history has reached its configured limit.
    HistoryFull,
    /// A retained packet cannot be represented by the retransmission storage.
    RetransmissionTooLarge,
}

/// Embedded callers use this enum directly. Host association managers can
/// preserve the exact variant through an error chain; in particular,
/// `PeerRestarted` is a token-verified state change rather than an ambiguous
/// timeout, so it must not be reduced to a bearer-specific string.
impl core::fmt::Display for Error {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "{self:?}")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

/// Version assigned to the DMesh long-header extension. It deliberately does
/// not claim QUIC version 1: the header layout and CID roles follow RFC 9000,
/// while Initial protection and transport-parameter negotiation are not yet
/// implemented.
pub(crate) const DMESH_LONG_HEADER_VERSION: u32 = 0x444d_0001;
pub(crate) const LONG_PACKET_INITIAL: u8 = 0;

/// Parsed subset of the RFC 9000 long header used before a connection has an
/// established short-header destination CID.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LongHeader {
    packet_type: u8,
    version: u32,
    dcid: Option<ConnectionId>,
    scid: Option<ConnectionId>,
    packet_number: u32,
    packet_number_len: u8,
}

fn encode_long_packet(
    packet_type: u8,
    dcid: Option<ConnectionId>,
    scid: Option<ConnectionId>,
    packet_number: u32,
    packet_number_len: u8,
    payload: &[u8],
    out: &mut [u8],
) -> Result<usize, Error> {
    if packet_type > 3 || !matches!(packet_number_len, 1..=4) || payload.is_empty() {
        return Err(Error::Invalid);
    }
    let mut at = 0usize;
    let need = 1 + 4 + 1 + dcid.map_or(0, ConnectionId::encoded_len) + 1
        + scid.map_or(0, ConnectionId::encoded_len)
        + usize::from(packet_type == LONG_PACKET_INITIAL) // zero-length Initial token
        + 8 // maximum varint length for packet length
        + usize::from(packet_number_len)
        + payload.len();
    if out.len() < need {
        return Err(Error::BufferTooSmall);
    }
    out[at] = 0xc0 | (packet_type << 4) | (packet_number_len - 1);
    at += 1;
    out[at..at + 4].copy_from_slice(&DMESH_LONG_HEADER_VERSION.to_be_bytes());
    at += 4;
    for cid in [dcid, scid] {
        let len = cid.map_or(0, ConnectionId::encoded_len);
        out[at] = len as u8;
        at += 1;
        if let Some(cid) = cid {
            cid.encode(&mut out[at..at + len])?;
            at += len;
        }
    }
    if packet_type == LONG_PACKET_INITIAL {
        // Preserve the standard Initial token-length position. Retry/token
        // validation is not implemented yet, so the token is empty.
        out[at] = 0;
        at += 1;
    }
    let body_len = u64::from(packet_number_len) + payload.len() as u64;
    let length_len = put_varint(body_len, &mut out[at..])?;
    at += length_len;
    let pn = packet_number.to_be_bytes();
    out[at..at + usize::from(packet_number_len)]
        .copy_from_slice(&pn[4 - usize::from(packet_number_len)..]);
    at += usize::from(packet_number_len);
    out[at..at + payload.len()].copy_from_slice(payload);
    Ok(at + payload.len())
}

fn decode_long_packet(input: &[u8]) -> Result<(LongHeader, usize, usize), Error> {
    if input.len() < 9 || input[0] & 0xc0 != 0xc0 {
        return Err(Error::Invalid);
    }
    let version = u32::from_be_bytes(input[1..5].try_into().map_err(|_| Error::Truncated)?);
    if version != DMESH_LONG_HEADER_VERSION {
        return Err(Error::Invalid);
    }
    let packet_type = (input[0] >> 4) & 0x03;
    let packet_number_len = (input[0] & 0x03) + 1;
    let mut at = 5usize;
    let mut cids = [None, None];
    for slot in &mut cids {
        let len = *input.get(at).ok_or(Error::Truncated)? as usize;
        at += 1;
        if len != 0 {
            if !matches!(len, 1 | 2 | 4 | 8) || input.len() < at + len {
                return Err(Error::Invalid);
            }
            let (cid, used) = ConnectionId::decode(&input[at..at + len])?;
            if used != len {
                return Err(Error::Invalid);
            }
            *slot = Some(cid);
            at += len;
        }
    }
    if packet_type == LONG_PACKET_INITIAL {
        let (token_len, used) = get_varint(input.get(at..).ok_or(Error::Truncated)?)?;
        at += used;
        let token_len = usize::try_from(token_len).map_err(|_| Error::Invalid)?;
        at = at.checked_add(token_len).ok_or(Error::Invalid)?;
        if input.len() < at {
            return Err(Error::Truncated);
        }
    }
    let (body_len, used) = get_varint(&input[at..])?;
    at += used;
    let body_len = usize::try_from(body_len).map_err(|_| Error::Invalid)?;
    if body_len < usize::from(packet_number_len) || input.len() != at + body_len {
        return Err(Error::Invalid);
    }
    let mut pn = [0u8; 4];
    let pn_len = usize::from(packet_number_len);
    pn[4 - pn_len..].copy_from_slice(&input[at..at + pn_len]);
    at += pn_len;
    Ok((
        LongHeader {
            packet_type,
            version,
            dcid: cids[0],
            scid: cids[1],
            packet_number: u32::from_be_bytes(pn),
            packet_number_len,
        },
        at,
        body_len - pn_len,
    ))
}

/// Decode only the destination needed by endpoint/relay routing. Long-header
/// packets with an empty destination are represented by the reserved local
/// zero value internally; zero is never serialized as their DCID.
/// Internal relay routing decode. Shared listeners use
/// [`crate::classify_server_packet`] instead; exposing this would let a
/// bearer grow its own header-peeking path.
pub(crate) fn decode_routing_prefix(input: &[u8]) -> Result<ShortHeaderPrefix, Error> {
    if input.first().is_some_and(|flags| flags & 0x80 != 0) {
        let (header, header_len, _) = decode_long_packet(input)?;
        Ok(ShortHeaderPrefix {
            flags: input[0],
            dcid: header
                .dcid
                .unwrap_or(ConnectionId::new(0).ok_or(Error::Invalid)?),
            truncated_packet_number: header.packet_number,
            packet_number_len: header.packet_number_len,
            header_len,
        })
    } else {
        ShortHeader::decode_prefix(input)
    }
}

/// Rewrite only the DCID of an opaque short-header packet into separate
/// caller-owned storage.  Flags, truncated packet-number bytes, and all body
/// bytes are copied exactly.  The caller checks its selected bearer's MTU
/// before enqueueing `used` bytes.
pub(crate) fn rewrite_dcid(
    input: &[u8],
    outbound_dcid: ConnectionId,
    out: &mut [u8],
) -> Result<usize, Error> {
    if outbound_dcid.value() == 0 {
        return Err(Error::Invalid);
    }
    rewrite_destination(input, Some(outbound_dcid), out)
}

/// Rewrite a routing destination without representing an empty long-header
/// destination as a synthetic `ConnectionId(0)`. The bootstrap-only form is
/// private to QUIC-lite relay dispatch; all public established-route callers
/// use [`rewrite_dcid`].
fn rewrite_destination(
    input: &[u8],
    outbound_dcid: Option<ConnectionId>,
    out: &mut [u8],
) -> Result<usize, Error> {
    if input.first().is_some_and(|flags| flags & 0x80 != 0) {
        let (header, payload_at, payload_len) = decode_long_packet(input)?;
        return encode_long_packet(
            header.packet_type,
            outbound_dcid,
            header.scid,
            header.packet_number,
            header.packet_number_len,
            &input[payload_at..payload_at + payload_len],
            out,
        );
    }
    let outbound_dcid = outbound_dcid.ok_or(Error::Invalid)?;
    let prefix = ShortHeader::decode_prefix(input)?;
    let inbound_len = prefix.dcid.encoded_len();
    let outbound_len = outbound_dcid.encoded_len();
    let used = input
        .len()
        .checked_sub(inbound_len)
        .and_then(|len| len.checked_add(outbound_len))
        .ok_or(Error::Invalid)?;
    if out.len() < used {
        return Err(Error::BufferTooSmall);
    }
    out[0] = input[0];
    outbound_dcid.encode(&mut out[1..])?;
    let input_tail = 1 + inbound_len;
    let output_tail = 1 + outbound_len;
    out[output_tail..used].copy_from_slice(&input[input_tail..]);
    Ok(used)
}

pub(crate) fn rewrite_bootstrap_destination(input: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    rewrite_destination(input, None, out)
}

/// Rewrite the only bootstrap header field a relay is allowed to interpret.
///
/// A normal relay is deliberately opaque and should use [`rewrite_dcid`].
/// Relay-open is the one exception: the first OPEN names the CID to which the
/// server will send OPEN_ACK.  In a three-party path that address must be the
/// relay's *return alias*, not the client's private receive CID. The relay
/// therefore substitutes `relay_receive_cid` in the Initial SCID while changing
/// the DCID to `outbound_dcid` (normally empty at the final service).
/// Its independently installed reverse rule later rewrites that alias back to
/// the client CID before UDP delivery.  No later QUIC-lite packet is decoded
/// or changed by this helper.
pub(crate) fn rewrite_relay_open(
    input: &[u8],
    outbound_dcid: Option<ConnectionId>,
    relay_receive_cid: ConnectionId,
    out: &mut [u8],
) -> Result<usize, Error> {
    if relay_receive_cid.value() == 0 {
        return Err(Error::BootstrapInvalid);
    }
    // First remove the adjacent forwarding DCID and validate the resulting
    // Initial before changing its source CID. The setup body contains only
    // transport limits; relays never rewrite application/control payload.
    let mut direct = [0u8; DEFAULT_MAX_PACKET_SIZE];
    let direct_len = rewrite_bootstrap_destination(input, &mut direct)?;
    decode_bootstrap_open_packet_with_limits(&direct[..direct_len])?;
    let (header, payload_at, payload_len) = decode_long_packet(&direct[..direct_len])?;
    encode_long_packet(
        LONG_PACKET_INITIAL,
        outbound_dcid,
        Some(relay_receive_cid),
        header.packet_number,
        header.packet_number_len,
        &direct[payload_at..payload_at + payload_len],
        out,
    )
}

/// Result metadata for a bearer packet after transport processing. The
/// bearer may use this for diagnostics, but it never needs to inspect ACKs,
/// packet numbers, or other transport frames.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg(test)]
pub(crate) struct TransportReceiveInfo {
    pub stream: bool,
    pub duplicate: bool,
}

/// Application outcome for a committed stream callback.
///
/// `Deferred` means the application retained the bytes in bounded storage but
/// has not released flow credit yet. It deliberately leaves ACK timing to the
/// negotiated transport policy. `Reack` is only for an already-delivered
/// retransmitted range or another reordering exception that needs an
/// immediate acknowledgement of its fresh packet number.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg(test)]
pub(crate) enum CommittedStreamDisposition {
    Consumed(usize),
    Deferred,
    Reack,
}

/// Transport-owned diagnostics. Bearers may report this snapshot without
/// inspecting ACK frames, packet numbers, or other transport mechanics.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct TransportStats {
    pub received_packets: u64,
    pub stream_packets: u64,
    pub control_packets: u64,
    pub duplicate_packets: u64,
    pub out_of_order_packets: u64,
    pub inferred_missing_packets: u64,
    pub sent_packets: u64,
    /// Application STREAM packets emitted by this endpoint, including
    /// replacement transmissions. This is transport accounting: bearers do
    /// not need to parse packets to report it.
    pub sent_stream_packets: u64,
    /// ACK, flow-control, ACK_FREQUENCY, or close packets emitted by this
    /// endpoint. Comparing this with the peer's received control count makes
    /// packet-number gaps diagnosable without packet-path logging.
    pub sent_control_packets: u64,
    pub retransmitted_packets: u64,
    /// Stream packets declared lost from an ACK packet-number gap.
    pub loss_packet_threshold_packets: u64,
    /// Stream packets declared lost only because their send age exceeded
    /// the negotiated RTT/ACK-delay threshold.
    pub loss_time_threshold_packets: u64,
    /// ACK-driven loss batches. NewReno reduces cwnd at most once for each
    /// recovery epoch, but this counts every observed loss episode.
    pub loss_events: u64,
    /// Retransmissions selected because loss detection had already marked
    /// the stream range lost.
    pub loss_retransmitted_packets: u64,
    /// Retransmissions selected only by the PTO timer.
    pub pto_retransmitted_packets: u64,
    pub ack_frequency_received: u64,
    pub ack_frequency_sent: u64,
    pub ack_packets: u64,
    pub ack_immediate_packets: u64,
    pub ack_threshold_packets: u64,
    pub ack_timer_packets: u64,
    pub receive_interpacket_samples: u64,
    pub receive_interpacket_total: u64,
    pub receive_interpacket_min: u64,
    pub receive_interpacket_max: u64,
}

/// Stream lifecycle counts for one endpoint direction.
///
/// `total` is the number of stream IDs opened since this association was
/// created. `active` excludes a locally-sent or peer-received FIN. These are
/// association facts: a UART, UDP, or NOW adapter must never infer them from
/// frame bytes.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[cfg(test)]
pub(crate) struct StreamDirectionStats {
    pub active: u64,
    pub total: u64,
}

/// Stream lifecycle counts for both directions of one QUIC association.
///
/// A peer may open normal bidirectional streams at any time. “Locally
/// initiated” and “peer initiated” describe stream-ID ownership, not the
/// bearer that happened to carry the packet.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[cfg(test)]
pub(crate) struct ConnectionStreamStats {
    pub locally_initiated: StreamDirectionStats,
    pub peer_initiated: StreamDirectionStats,
}

/// Version-0 connection bootstrap carried as complete data on stream 0.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct BootstrapOpen {
    pub client_receive_cid: ConnectionId,
    /// Receiver credit the peer must honour before the first MAX_* frame.
    pub max_data: u64,
    pub max_stream_data: u64,
    /// Maximum outstanding STREAM packets this receiver can absorb. Zero
    /// means no packet-count bound for compatibility with older peers.
    pub max_in_flight_packets: u16,
    /// Token for the client's receive CID. This gives the server the same
    /// restart detection that OPEN_ACK already gives the client.
    pub stateless_reset_token: Option<StatelessResetToken>,
    /// Optional receiver profile requested for the peer.  This is an
    /// admission-time diagnostic/control request, not a promise: the peer
    /// clamps it to its compiled hard memory ceiling and returns the actual
    /// profile in OPEN_ACK.
    pub requested_peer_limits: Option<ReceiveWindowRequest>,
}

/// Host-selected upper bounds for the peer's initial receive credit.
///
/// A small device never trusts these as capacity claims.  They only let a
/// host deliberately exercise a lower point within the device's fixed
/// allocation envelope; the OPEN_ACK is authoritative.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ReceiveWindowRequest {
    pub max_data: u64,
    pub max_stream_data: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct BootstrapOpenAck {
    pub server_receive_cid: ConnectionId,
    /// Receiver credit the peer must honour before the first MAX_* frame.
    pub max_data: u64,
    pub max_stream_data: u64,
    /// See [`BootstrapOpen::max_in_flight_packets`].
    pub max_in_flight_packets: u16,
    /// Token that proves an opaque packet is the peer's stateless-reset
    /// signal for this association. Version-0 peers omit it; recovery then
    /// falls back to the bounded PTO/idle transition.
    pub stateless_reset_token: Option<StatelessResetToken>,
}

#[cfg(test)]
impl BootstrapOpen {
    pub(crate) const VERSION: u64 = 0;
    pub(crate) fn encode(self, out: &mut [u8]) -> Result<usize, Error> {
        if self.client_receive_cid.value() == 0 || self.stateless_reset_token.is_some() {
            return Err(Error::BootstrapInvalid);
        }
        if out.len() < 3 {
            return Err(Error::BufferTooSmall);
        }
        out[0] = 0;
        let mut p = 1;
        p += put_varint(Self::VERSION, &mut out[p..])?;
        p += self.client_receive_cid.encode(&mut out[p..])?;
        let mut parameters = [0u8; 32];
        let mut parameters_len = 0;
        parameters_len += put_varint(self.max_data, &mut parameters[parameters_len..])?;
        parameters_len += put_varint(self.max_stream_data, &mut parameters[parameters_len..])?;
        parameters_len += put_varint(
            self.max_in_flight_packets as u64,
            &mut parameters[parameters_len..],
        )?;
        p += put_varint(parameters_len as u64, &mut out[p..])?;
        if out.len() < p + parameters_len {
            return Err(Error::BufferTooSmall);
        }
        out[p..p + parameters_len].copy_from_slice(&parameters[..parameters_len]);
        p += parameters_len;
        Ok(p)
    }
    pub(crate) fn decode(input: &[u8]) -> Result<Self, Error> {
        if input.first().copied() != Some(0) {
            return Err(Error::BootstrapInvalid);
        }
        let (version, n) = get_varint(&input[1..])?;
        if version != Self::VERSION {
            return Err(Error::BootstrapInvalid);
        }
        let (cid, n_cid) = ConnectionId::decode(&input[1 + n..])?;
        if cid.value() == 0 {
            return Err(Error::BootstrapInvalid);
        }
        let (length, n_len) = get_varint(&input[1 + n + n_cid..])?;
        let parameters = &input[1 + n + n_cid + n_len..];
        if parameters.len() != length as usize {
            return Err(Error::BootstrapInvalid);
        }
        let (max_data, n_data) = get_varint(parameters)?;
        let (max_stream_data, n_stream) = get_varint(&parameters[n_data..])?;
        let max_in_flight_packets = if n_data + n_stream == parameters.len() {
            0
        } else {
            let (packets, n_packets) = get_varint(&parameters[n_data + n_stream..])?;
            if n_data + n_stream + n_packets != parameters.len() || packets > u16::MAX as u64 {
                return Err(Error::BootstrapInvalid);
            }
            packets as u16
        };
        if max_data == 0 || max_stream_data == 0 {
            return Err(Error::BootstrapInvalid);
        }
        Ok(Self {
            client_receive_cid: cid,
            max_data,
            max_stream_data,
            max_in_flight_packets,
            stateless_reset_token: None,
            requested_peer_limits: None,
        })
    }
}

#[cfg(test)]
impl BootstrapOpenAck {
    pub(crate) const VERSION: u64 = 0;
    pub(crate) fn encode(self, out: &mut [u8]) -> Result<usize, Error> {
        if self.server_receive_cid.value() == 0 || self.stateless_reset_token.is_some() {
            return Err(Error::BootstrapInvalid);
        }
        if out.len() < 3 {
            return Err(Error::BufferTooSmall);
        }
        out[0] = 1;
        let mut p = 1;
        p += put_varint(Self::VERSION, &mut out[p..])?;
        p += self.server_receive_cid.encode(&mut out[p..])?;
        let mut parameters = [0u8; 32];
        let mut parameters_len = 0;
        parameters_len += put_varint(self.max_data, &mut parameters[parameters_len..])?;
        parameters_len += put_varint(self.max_stream_data, &mut parameters[parameters_len..])?;
        parameters_len += put_varint(
            self.max_in_flight_packets as u64,
            &mut parameters[parameters_len..],
        )?;
        p += put_varint(parameters_len as u64, &mut out[p..])?;
        if out.len() < p + parameters_len {
            return Err(Error::BufferTooSmall);
        }
        out[p..p + parameters_len].copy_from_slice(&parameters[..parameters_len]);
        p += parameters_len;
        Ok(p)
    }
    pub(crate) fn decode(input: &[u8]) -> Result<Self, Error> {
        if input.first().copied() != Some(1) {
            return Err(Error::BootstrapInvalid);
        }
        let (version, n) = get_varint(&input[1..])?;
        if version != Self::VERSION {
            return Err(Error::BootstrapInvalid);
        }
        let (cid, n_cid) = ConnectionId::decode(&input[1 + n..])?;
        if cid.value() == 0 {
            return Err(Error::BootstrapInvalid);
        }
        let (length, n_len) = get_varint(&input[1 + n + n_cid..])?;
        let parameters = &input[1 + n + n_cid + n_len..];
        if parameters.len() != length as usize {
            return Err(Error::BootstrapInvalid);
        }
        let (max_data, n_data) = get_varint(parameters)?;
        let (max_stream_data, n_stream) = get_varint(&parameters[n_data..])?;
        let max_in_flight_packets = if n_data + n_stream == parameters.len() {
            0
        } else {
            let (packets, n_packets) = get_varint(&parameters[n_data + n_stream..])?;
            if n_data + n_stream + n_packets != parameters.len() || packets > u16::MAX as u64 {
                return Err(Error::BootstrapInvalid);
            }
            packets as u16
        };
        if max_data == 0 || max_stream_data == 0 {
            return Err(Error::BootstrapInvalid);
        }
        Ok(Self {
            server_receive_cid: cid,
            max_data,
            max_stream_data,
            max_in_flight_packets,
            stateless_reset_token: None,
        })
    }
}

fn encode_bootstrap_profile(
    kind: u8,
    limits: ConnectionLimits,
    max_in_flight_packets: u16,
    stateless_reset_token: Option<StatelessResetToken>,
    requested_peer_limits: Option<ReceiveWindowRequest>,
    out: &mut [u8],
) -> Result<usize, Error> {
    if out.len() < 3 || kind > 1 {
        return Err(Error::BufferTooSmall);
    }
    out[0] = kind;
    let mut at = 1;
    let version = match (
        stateless_reset_token.is_some(),
        requested_peer_limits.is_some(),
    ) {
        (false, false) => 0,
        (true, false) => 1,
        (false, true) => 2,
        (true, true) => 3,
    };
    at += put_varint(version, &mut out[at..])?;
    let mut parameters = [0u8; 64];
    let mut used = 0;
    used += put_varint(limits.max_data, &mut parameters[used..])?;
    used += put_varint(limits.max_stream_data, &mut parameters[used..])?;
    used += put_varint(u64::from(max_in_flight_packets), &mut parameters[used..])?;
    if let Some(token) = stateless_reset_token {
        parameters[used..used + STATELESS_RESET_TOKEN_LEN].copy_from_slice(&token.0);
        used += STATELESS_RESET_TOKEN_LEN;
    }
    if let Some(request) = requested_peer_limits {
        if request.max_data == 0 || request.max_stream_data == 0 {
            return Err(Error::BootstrapInvalid);
        }
        used += put_varint(request.max_data, &mut parameters[used..])?;
        used += put_varint(request.max_stream_data, &mut parameters[used..])?;
    }
    at += put_varint(used as u64, &mut out[at..])?;
    if out.len() < at + used {
        return Err(Error::BufferTooSmall);
    }
    out[at..at + used].copy_from_slice(&parameters[..used]);
    Ok(at + used)
}

fn decode_bootstrap_profile(
    input: &[u8],
    expected_kind: u8,
) -> Result<
    (
        ConnectionLimits,
        u16,
        Option<StatelessResetToken>,
        Option<ReceiveWindowRequest>,
    ),
    Error,
> {
    if input.first().copied() != Some(expected_kind) {
        return Err(Error::BootstrapInvalid);
    }
    let (version, version_len) = get_varint(&input[1..])?;
    if version > 3 {
        return Err(Error::BootstrapInvalid);
    }
    let (length, length_len) = get_varint(&input[1 + version_len..])?;
    let parameters = &input[1 + version_len + length_len..];
    if parameters.len() != length as usize {
        return Err(Error::BootstrapInvalid);
    }
    let (max_data, data_len) = get_varint(parameters)?;
    let (max_stream_data, stream_len) = get_varint(&parameters[data_len..])?;
    let (packets, packets_len) = get_varint(&parameters[data_len + stream_len..])?;
    let values_len = data_len + stream_len + packets_len;
    let (reset_token, requested_peer_limits) = match version {
        0 if values_len == parameters.len() => (None, None),
        1 if values_len + STATELESS_RESET_TOKEN_LEN == parameters.len() => {
            let mut token = [0u8; STATELESS_RESET_TOKEN_LEN];
            token.copy_from_slice(&parameters[values_len..]);
            (Some(StatelessResetToken(token)), None)
        }
        2 | 3 if expected_kind == 0 => {
            let (token, request) = if version == 3 {
                if parameters.len() < values_len + STATELESS_RESET_TOKEN_LEN {
                    return Err(Error::BootstrapInvalid);
                }
                let mut token = [0u8; STATELESS_RESET_TOKEN_LEN];
                token.copy_from_slice(
                    &parameters[values_len..values_len + STATELESS_RESET_TOKEN_LEN],
                );
                (
                    Some(StatelessResetToken(token)),
                    &parameters[values_len + STATELESS_RESET_TOKEN_LEN..],
                )
            } else {
                (None, &parameters[values_len..])
            };
            let (max_data, data_len) = get_varint(request)?;
            let (max_stream_data, stream_len) = get_varint(&request[data_len..])?;
            if data_len + stream_len != request.len() || max_data == 0 || max_stream_data == 0 {
                return Err(Error::BootstrapInvalid);
            }
            (
                token,
                Some(ReceiveWindowRequest {
                    max_data,
                    max_stream_data,
                }),
            )
        }
        _ => return Err(Error::BootstrapInvalid),
    };
    if values_len > parameters.len()
        || max_data == 0
        || max_stream_data == 0
        || packets > u16::MAX as u64
    {
        return Err(Error::BootstrapInvalid);
    }
    Ok((
        ConnectionLimits {
            max_data,
            max_stream_data,
            ..ConnectionLimits::default()
        },
        packets as u16,
        reset_token,
        requested_peer_limits,
    ))
}

/// Encode a complete stream-0 OPEN in a custom-version QUIC Initial header.
#[cfg(test)]
pub(crate) fn encode_bootstrap_open_packet(
    client_cid: ConnectionId,
    packet_number: u32,
    out: &mut [u8],
) -> Result<usize, Error> {
    encode_bootstrap_open_packet_with_limits(
        client_cid,
        packet_number,
        ConnectionLimits::default(),
        out,
    )
}

/// Encode OPEN with the receiver credit that applies from the first stream
/// packet. Bootstrap is the only point at which a peer may learn a smaller
/// initial window; later MAX_* frames can only increase it.
#[cfg(test)]
pub(crate) fn encode_bootstrap_open_packet_with_limits(
    client_cid: ConnectionId,
    packet_number: u32,
    limits: ConnectionLimits,
    out: &mut [u8],
) -> Result<usize, Error> {
    encode_bootstrap_open_packet_with_profile(client_cid, packet_number, limits, 0, out)
}

/// Encode OPEN with the complete initial receiver profile.  `0` means the
/// peer should use its normal packet budget; a non-zero value is useful for a
/// bounded diagnostic path and remains bearer-neutral.
#[cfg(test)]
pub(crate) fn encode_bootstrap_open_packet_with_profile(
    client_cid: ConnectionId,
    packet_number: u32,
    limits: ConnectionLimits,
    max_in_flight_packets: u16,
    out: &mut [u8],
) -> Result<usize, Error> {
    encode_bootstrap_open_packet_with_profile_and_peer_receive_request(
        client_cid,
        packet_number,
        limits,
        max_in_flight_packets,
        None,
        out,
    )
}

/// Encode OPEN with an optional request to lower the peer's receiver profile.
/// The request is bounded and clamped by the peer; it never changes the
/// opener's advertised receive credit.
#[cfg(test)]
pub(crate) fn encode_bootstrap_open_packet_with_profile_and_peer_receive_request(
    client_cid: ConnectionId,
    packet_number: u32,
    limits: ConnectionLimits,
    max_in_flight_packets: u16,
    requested_peer_limits: Option<ReceiveWindowRequest>,
    out: &mut [u8],
) -> Result<usize, Error> {
    encode_bootstrap_open_packet_with_profile_reset_token_and_peer_receive_request(
        client_cid,
        packet_number,
        limits,
        max_in_flight_packets,
        None,
        requested_peer_limits,
        out,
    )
}

pub(crate) fn encode_bootstrap_open_packet_with_profile_reset_token_and_peer_receive_request(
    client_cid: ConnectionId,
    packet_number: u32,
    limits: ConnectionLimits,
    max_in_flight_packets: u16,
    stateless_reset_token: Option<StatelessResetToken>,
    requested_peer_limits: Option<ReceiveWindowRequest>,
    out: &mut [u8],
) -> Result<usize, Error> {
    if client_cid.value() == 0 {
        return Err(Error::BootstrapInvalid);
    }
    let mut body = [0u8; 48];
    let body_len = encode_bootstrap_profile(
        0,
        limits,
        max_in_flight_packets,
        stateless_reset_token,
        requested_peer_limits,
        &mut body,
    )?;
    let mut frame = [0u8; 64];
    let frame_len = Frame::Stream(StreamFrame {
        id: CONTROL_STREAM_ID,
        offset: 0,
        fin: true,
        data: &body[..body_len],
    })
    .encode(&mut frame)?;
    encode_long_packet(
        LONG_PACKET_INITIAL,
        None,
        Some(client_cid),
        packet_number,
        1,
        &frame[..frame_len],
        out,
    )
}

/// Decode a complete custom-version Initial OPEN packet.
#[cfg(test)]
pub(crate) fn decode_bootstrap_open_packet(
    input: &[u8],
) -> Result<(ShortHeader, ConnectionId), Error> {
    let (header, open) = decode_bootstrap_open_packet_with_limits(input)?;
    Ok((header, open.client_receive_cid))
}

/// Decode OPEN including the peer's initial receive credit.
pub(crate) fn decode_bootstrap_open_packet_with_limits(
    input: &[u8],
) -> Result<(ShortHeader, BootstrapOpen), Error> {
    let (long, header_len, _) = decode_long_packet(input)?;
    if long.packet_type != LONG_PACKET_INITIAL || long.dcid.is_some() {
        return Err(Error::BootstrapInvalid);
    }
    let source_cid = long.scid.ok_or(Error::BootstrapInvalid)?;
    let (frame, used) = decode_frame(&input[header_len..])?;
    if header_len + used != input.len() {
        return Err(Error::BootstrapInvalid);
    }
    let Frame::Stream(stream) = frame else {
        return Err(Error::BootstrapInvalid);
    };
    if stream.id != CONTROL_STREAM_ID || stream.offset != 0 || !stream.fin {
        return Err(Error::BootstrapInvalid);
    }
    let (limits, max_in_flight_packets, reset_token, requested_peer_limits) =
        decode_bootstrap_profile(stream.data, 0)?;
    let open = BootstrapOpen {
        client_receive_cid: source_cid,
        max_data: limits.max_data,
        max_stream_data: limits.max_stream_data,
        max_in_flight_packets,
        stateless_reset_token: reset_token,
        requested_peer_limits,
    };
    Ok((
        ShortHeader {
            flags: FLAG_FIXED,
            dcid: ConnectionId::new(0).ok_or(Error::BootstrapInvalid)?,
            packet_number: long.packet_number,
            packet_number_len: long.packet_number_len,
        },
        open,
    ))
}

/// Encode OPEN_ACK in a custom-version Initial header. The standard DCID and
/// SCID fields carry the client and server receive CIDs respectively.
#[cfg(test)]
pub(crate) fn encode_bootstrap_open_ack_packet(
    client_cid: ConnectionId,
    server_cid: ConnectionId,
    packet_number: u32,
    out: &mut [u8],
) -> Result<usize, Error> {
    encode_bootstrap_open_ack_packet_with_limits(
        client_cid,
        server_cid,
        packet_number,
        ConnectionLimits::default(),
        out,
    )
}

/// Encode OPEN_ACK with the server's initial receive credit.
#[cfg(test)]
pub(crate) fn encode_bootstrap_open_ack_packet_with_limits(
    client_cid: ConnectionId,
    server_cid: ConnectionId,
    packet_number: u32,
    limits: ConnectionLimits,
    out: &mut [u8],
) -> Result<usize, Error> {
    encode_bootstrap_open_ack_packet_with_limits_and_reset_token(
        client_cid,
        server_cid,
        packet_number,
        limits,
        None,
        out,
    )
}

/// Encode OPEN_ACK while advertising the server CID's stateless-reset token.
/// Callers that retain a persistent [`StatelessResetKey`] derive this token
/// once per allocated server CID.  A client receiving it can recover a server
/// restart without waiting for a PTO timeout.
#[cfg(test)]
pub(crate) fn encode_bootstrap_open_ack_packet_with_limits_and_reset_token(
    client_cid: ConnectionId,
    server_cid: ConnectionId,
    packet_number: u32,
    limits: ConnectionLimits,
    stateless_reset_token: Option<StatelessResetToken>,
    out: &mut [u8],
) -> Result<usize, Error> {
    encode_bootstrap_open_ack_packet_with_profile_and_reset_token(
        client_cid,
        server_cid,
        packet_number,
        limits,
        0,
        stateless_reset_token,
        out,
    )
}

/// Encode OPEN_ACK with the complete receiver profile.
///
/// `max_in_flight_packets` is the receiver's bounded packet-ingress budget.
/// Keeping it in the connection bootstrap lets every bearer use the same
/// backpressure contract; zero retains compatibility with peers that did not
/// advertise a packet-count bound.
pub(crate) fn encode_bootstrap_open_ack_packet_with_profile_and_reset_token(
    client_cid: ConnectionId,
    server_cid: ConnectionId,
    packet_number: u32,
    limits: ConnectionLimits,
    max_in_flight_packets: u16,
    stateless_reset_token: Option<StatelessResetToken>,
    out: &mut [u8],
) -> Result<usize, Error> {
    if client_cid.value() == 0 || server_cid.value() == 0 || client_cid == server_cid {
        return Err(Error::BootstrapInvalid);
    }
    let mut body = [0u8; 64];
    let body_len = encode_bootstrap_profile(
        1,
        limits,
        max_in_flight_packets,
        stateless_reset_token,
        None,
        &mut body,
    )?;
    let mut frame = [0u8; 64];
    let frame_len = Frame::Stream(StreamFrame {
        id: CONTROL_STREAM_ID,
        offset: 0,
        fin: true,
        data: &body[..body_len],
    })
    .encode(&mut frame)?;
    encode_long_packet(
        LONG_PACKET_INITIAL,
        Some(client_cid),
        Some(server_cid),
        packet_number,
        1,
        &frame[..frame_len],
        out,
    )
}

/// Decode a complete custom-version Initial OPEN_ACK.
#[cfg(test)]
pub(crate) fn decode_bootstrap_open_ack_packet(
    input: &[u8],
    expected_client_cid: ConnectionId,
) -> Result<(ShortHeader, ConnectionId), Error> {
    let (header, ack) = decode_bootstrap_open_ack_packet_with_limits(input, expected_client_cid)?;
    Ok((header, ack.server_receive_cid))
}

/// Decode OPEN_ACK including the peer's initial receive credit.
pub(crate) fn decode_bootstrap_open_ack_packet_with_limits(
    input: &[u8],
    expected_client_cid: ConnectionId,
) -> Result<(ShortHeader, BootstrapOpenAck), Error> {
    let (long, header_len, _) = decode_long_packet(input)?;
    if long.packet_type != LONG_PACKET_INITIAL || long.dcid != Some(expected_client_cid) {
        return Err(Error::WrongConnectionId);
    }
    let (frame, used) = decode_frame(&input[header_len..])?;
    if header_len + used != input.len() {
        return Err(Error::BootstrapInvalid);
    }
    let Frame::Stream(stream) = frame else {
        return Err(Error::BootstrapInvalid);
    };
    if stream.id != CONTROL_STREAM_ID || stream.offset != 0 || !stream.fin {
        return Err(Error::BootstrapInvalid);
    }
    let server_cid = long.scid.ok_or(Error::BootstrapInvalid)?;
    if server_cid == expected_client_cid {
        return Err(Error::BootstrapInvalid);
    }
    let (limits, max_in_flight_packets, stateless_reset_token, requested_peer_limits) =
        decode_bootstrap_profile(stream.data, 1)?;
    if requested_peer_limits.is_some() {
        return Err(Error::BootstrapInvalid);
    }
    let ack = BootstrapOpenAck {
        server_receive_cid: server_cid,
        max_data: limits.max_data,
        max_stream_data: limits.max_stream_data,
        max_in_flight_packets,
        stateless_reset_token,
    };
    Ok((
        ShortHeader {
            flags: FLAG_FIXED,
            dcid: expected_client_cid,
            packet_number: long.packet_number,
            packet_number_len: long.packet_number_len,
        },
        ack,
    ))
}

pub(crate) fn put_varint(value: u64, out: &mut [u8]) -> Result<usize, Error> {
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

pub(crate) fn get_varint(input: &[u8]) -> Result<(u64, usize), Error> {
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
pub(crate) struct ShortHeader {
    pub flags: u8,
    pub dcid: ConnectionId,
    pub packet_number: u32,
    pub packet_number_len: u8,
}

/// The header prefix decoded before a connection is selected. The packet
/// number is intentionally only the truncated wire value until the bearer
/// supplies that connection's expected next packet number.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ShortHeaderPrefix {
    pub flags: u8,
    pub dcid: ConnectionId,
    pub truncated_packet_number: u32,
    pub packet_number_len: u8,
    pub header_len: usize,
}

impl ShortHeaderPrefix {
    /// Reconstruct the packet number nearest to `expected`, following the
    /// QUIC packet-number window rule. Version 0 uses a u32 full number and
    /// closes before it wraps.
    pub(crate) fn reconstruct(self, expected: u32) -> Result<ShortHeader, Error> {
        let pn_len = self.packet_number_len as usize;
        let window = 1u64 << (pn_len * 8);
        let half_window = window / 2;
        let truncated = u64::from(self.truncated_packet_number);
        let expected = u64::from(expected);
        let epoch = expected & !(window - 1);
        let mut candidate = epoch | truncated;
        if candidate + half_window <= expected && candidate + window <= u64::from(u32::MAX) {
            candidate += window;
        } else if candidate > expected + half_window {
            if candidate < window {
                return Err(Error::PacketNumberExhausted);
            }
            candidate -= window;
        }
        if candidate > u64::from(u32::MAX) {
            return Err(Error::PacketNumberExhausted);
        }
        Ok(ShortHeader {
            flags: self.flags,
            dcid: self.dcid,
            packet_number: candidate as u32,
            packet_number_len: self.packet_number_len,
        })
    }
}

impl ShortHeader {
    pub(crate) fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
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

    pub(crate) fn decode_prefix(input: &[u8]) -> Result<ShortHeaderPrefix, Error> {
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
        Ok(ShortHeaderPrefix {
            flags: input[0],
            dcid,
            truncated_packet_number: pn,
            packet_number_len: pn_len as u8,
            header_len: 1 + cid_len + pn_len,
        })
    }

    /// Decode with a connection-specific expected packet number.
    pub(crate) fn decode_with_expected(
        input: &[u8],
        expected: u32,
    ) -> Result<(Self, usize), Error> {
        let prefix = Self::decode_prefix(input)?;
        Ok((prefix.reconstruct(expected)?, prefix.header_len))
    }

    /// Decode the truncated value without reconstruction. This is retained
    /// only for wire/codec inspection; connection receive paths must use
    /// `decode_with_expected`.
    pub(crate) fn decode(input: &[u8]) -> Result<(Self, usize), Error> {
        let prefix = Self::decode_prefix(input)?;
        Ok((
            Self {
                flags: prefix.flags,
                dcid: prefix.dcid,
                packet_number: prefix.truncated_packet_number,
                packet_number_len: prefix.packet_number_len,
            },
            prefix.header_len,
        ))
    }
}

/// Select the shortest packet-number encoding whose reconstruction window is
/// unambiguous relative to the largest packet acknowledged by the peer.
pub(crate) fn packet_number_len(next: u32, largest_acked: Option<u32>) -> u8 {
    let baseline = largest_acked.unwrap_or(0);
    let distance = next.saturating_sub(baseline) as u64;
    let needed = distance.saturating_mul(2).max(1);
    if needed < (1 << 8) {
        1
    } else if needed < (1 << 16) {
        2
    } else if needed < (1 << 24) {
        3
    } else {
        4
    }
}

pub(crate) const FRAME_PADDING: u64 = 0x00;
pub(crate) const FRAME_PING: u64 = 0x01;
pub(crate) const FRAME_ACK: u64 = 0x02;
pub(crate) const FRAME_STREAM_BASE: u64 = 0x08;
pub(crate) const FRAME_MAX_DATA: u64 = 0x10;
pub(crate) const FRAME_MAX_STREAM_DATA: u64 = 0x11;
pub(crate) const FRAME_MAX_STREAMS_BIDI: u64 = 0x12;
pub(crate) const FRAME_MAX_STREAMS_UNI: u64 = 0x13;
pub(crate) const FRAME_CONNECTION_CLOSE: u64 = 0x1c;
/// QUIC ACK_FREQUENCY extension frame type. RFC 9000 defines the default
/// every-other-packet ACK behavior; this extension carries a later policy
/// update on the established connection.
pub(crate) const FRAME_ACK_FREQUENCY: u64 = 0xaf;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct StreamFrame<'a> {
    pub id: u64,
    pub offset: u64,
    pub fin: bool,
    pub data: &'a [u8],
}

/// Result of handing one bearer packet to the transport.  Bearers should
/// forward every packet here and only consume stream bytes; ACK and flow
/// control frames never escape to object or flash code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TransportFrame<'a> {
    Stream {
        header: ShortHeader,
        frame: StreamFrame<'a>,
    },
    Control,
}

/// All application stream frames admitted from one complete QUIC packet.
///
/// A packet can legitimately carry a transport ACK together with one or more
/// independent STREAM frames.  Returning only the first frame is sufficient
/// for a one-shot client but loses correlation for a shared association with
/// several in-flight streams.  This fixed-size view keeps the packet parser
/// and stream admission in QUIC-lite while letting a connection owner route
/// every accepted frame to its pending request.  Bearer adapters never decode
/// this structure themselves.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TransportFrames<'a> {
    pub header: ShortHeader,
    streams: [Option<StreamFrame<'a>>; 8],
    stream_count: usize,
    pub duplicate: bool,
}

impl<'a> TransportFrames<'a> {
    /// Ordered STREAM frames from this packet. Empty for a control-only or
    /// duplicate packet.
    pub(crate) fn streams(&self) -> impl Iterator<Item = StreamFrame<'a>> + '_ {
        self.streams[..self.stream_count].iter().flatten().copied()
    }

    #[cfg(test)]
    pub(crate) const fn has_streams(&self) -> bool {
        self.stream_count != 0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Frame<'a> {
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
    AckFrequency {
        sequence: u64,
        /// Maximum packets received without an ACK. A value of one means
        /// ACK every second ack-eliciting packet.
        packet_threshold: u64,
        /// Requested maximum ACK delay in microseconds.
        max_ack_delay_us: u64,
        /// Non-zero packet-number reordering which triggers an immediate ACK.
        reordering_threshold: u64,
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
    pub(crate) fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
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
            Frame::AckFrequency {
                sequence,
                packet_threshold,
                max_ack_delay_us,
                reordering_threshold,
            } => {
                put(FRAME_ACK_FREQUENCY, out, &mut p)?;
                put(*sequence, out, &mut p)?;
                put(*packet_threshold, out, &mut p)?;
                put(*max_ack_delay_us, out, &mut p)?;
                put(*reordering_threshold, out, &mut p)?;
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

pub(crate) fn decode_frame<'a>(input: &'a [u8]) -> Result<(Frame<'a>, usize), Error> {
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
            if range_count == 0 && first_range == 0 {
                return Ok((
                    Frame::Ack {
                        largest: largest as u32,
                        delay,
                    },
                    p,
                ));
            }
            if range_count >= ACK_RANGE_CAPACITY as u64 {
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
        FRAME_ACK_FREQUENCY => {
            let (sequence, n) = get_varint(&input[p..])?;
            p += n;
            let (packet_threshold, n) = get_varint(&input[p..])?;
            p += n;
            let (max_ack_delay_us, n) = get_varint(&input[p..])?;
            p += n;
            let (reordering_threshold, n) = get_varint(&input[p..])?;
            p += n;
            Ok((
                Frame::AckFrequency {
                    sequence,
                    packet_threshold,
                    max_ack_delay_us,
                    reordering_threshold,
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
            let len = usize::try_from(len).map_err(|_| Error::Invalid)?;
            let end = p.checked_add(len).ok_or(Error::Invalid)?;
            if input.len() < end {
                return Err(Error::Truncated);
            }
            Ok((Frame::Close { code }, end))
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
                usize::try_from(v).map_err(|_| Error::Invalid)?
            } else {
                input.len() - p
            };
            let end = p.checked_add(len).ok_or(Error::Invalid)?;
            if input.len() < end {
                return Err(Error::Truncated);
            }
            Ok((
                Frame::Stream(StreamFrame {
                    id,
                    offset,
                    fin: t & 1 != 0,
                    data: &input[p..end],
                }),
                end,
            ))
        }
        _ => Err(Error::Invalid),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AckRange {
    pub start: u32,
    pub end: u32,
}

pub(crate) const ACK_RANGE_CAPACITY: usize = 8;
/// Bound exponential PTO growth so a retained stream range is retried at
/// least once per eight base PTOs. Embedded and host associations use the
/// same cap; this is transport liveness policy, not bearer tuning.
const MAX_PTO_BACKOFF_EXPONENT: u8 = 3;
pub(crate) type AckRangeSet = AckRanges<ACK_RANGE_CAPACITY>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AckRanges<const N: usize> {
    ranges: [AckRange; N],
    len: usize,
}

impl<const N: usize> AckRanges<N> {
    pub(crate) const fn new() -> Self {
        Self {
            ranges: [AckRange { start: 0, end: 0 }; N],
            len: 0,
        }
    }
    pub(crate) fn len(&self) -> usize {
        self.len
    }
    pub(crate) fn get(&self, i: usize) -> Option<AckRange> {
        if i < self.len {
            Some(self.ranges[i])
        } else {
            None
        }
    }
    pub(crate) fn insert(&mut self, pn: u32) {
        self.insert_range(AckRange { start: pn, end: pn });
    }
    pub(crate) fn insert_range(&mut self, mut new: AckRange) {
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
                } else if i < N {
                    // The ACK wire budget is bounded, but it must always
                    // describe the newest packet numbers. Dropping this new
                    // high range would make a peer retransmit it forever;
                    // discard the oldest (lowest) range instead.
                    for j in (i..N - 1).rev() {
                        self.ranges[j + 1] = self.ranges[j];
                    }
                    self.ranges[i] = new;
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
    pub(crate) fn contains(&self, pn: u32) -> bool {
        (0..self.len).any(|i| pn >= self.ranges[i].start && pn <= self.ranges[i].end)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FlowControl {
    pub max_data: u64,
    pub consumed: u64,
}

impl FlowControl {
    pub(crate) const fn new(max_data: u64) -> Self {
        Self {
            max_data,
            consumed: 0,
        }
    }
    pub(crate) fn can_receive(&self, end: u64) -> bool {
        end <= self.max_data
    }
    pub(crate) fn consume(&mut self, n: u64) {
        self.consumed = self.consumed.saturating_add(n);
    }
    pub(crate) fn extend(&mut self, credit: u64) {
        self.max_data = max(self.max_data, self.consumed.saturating_add(credit));
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SendStreamCredit {
    pub id: u64,
    pub max_data: u64,
    pub sent: u64,
    finished: bool,
}

/// Peer-advertised connection and stream credit for a sender.  Retransmits do
/// not reserve credit again; only new stream-offset bytes advance `sent`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SendFlowControl {
    pub max_data: u64,
    initial_stream_max_data: u64,
    pub sent_data: u64,
    streams: Vec<SendStreamCredit>,
}

impl SendFlowControl {
    pub(crate) fn new(max_data: u64, max_stream_data: u64) -> Self {
        Self {
            max_data,
            initial_stream_max_data: max_stream_data,
            sent_data: 0,
            streams: Vec::new(),
        }
    }

    pub(crate) fn open_stream(&mut self, id: u64, max_data: u64) -> Result<(), Error> {
        if self.streams.iter().any(|stream| stream.id == id) {
            return Ok(());
        }
        self.streams
            .try_reserve(1)
            .map_err(|_| Error::StreamLimit)?;
        self.streams.push(SendStreamCredit {
            id,
            max_data: min(max_data, self.initial_stream_max_data),
            sent: 0,
            finished: false,
        });
        Ok(())
    }

    /// Apply bootstrap credit before any stream is opened.  Once application
    /// bytes exist, credit may only advance through peer MAX_* frames.
    pub(crate) fn set_initial_limits(
        &mut self,
        max_data: u64,
        max_stream_data: u64,
    ) -> Result<(), Error> {
        if max_data == 0 || max_stream_data == 0 || self.sent_data != 0 || !self.streams.is_empty()
        {
            return Err(Error::FlowControl);
        }
        self.max_data = max_data;
        self.initial_stream_max_data = max_stream_data;
        Ok(())
    }

    pub(crate) fn stream(&self, id: u64) -> Option<SendStreamCredit> {
        self.streams.iter().find(|stream| stream.id == id).copied()
    }

    pub(crate) fn can_send(&self, id: u64, offset: u64, len: usize) -> bool {
        let Some(stream) = self.stream(id) else {
            return false;
        };
        let end = offset.saturating_add(len as u64);
        let new_bytes = end.saturating_sub(stream.sent);
        end <= stream.max_data && self.sent_data.saturating_add(new_bytes) <= self.max_data
    }

    #[cfg(test)]
    fn available_at(&self, id: u64, offset: u64) -> Result<usize, Error> {
        let stream = self.stream(id).ok_or(Error::Invalid)?;
        let maximum_end = min(
            stream.max_data,
            stream
                .sent
                .saturating_add(self.max_data.saturating_sub(self.sent_data)),
        );
        Ok(usize::try_from(maximum_end.saturating_sub(offset)).unwrap_or(usize::MAX))
    }

    pub(crate) fn reserve(&mut self, id: u64, offset: u64, len: usize) -> Result<(), Error> {
        if !self.can_send(id, offset, len) {
            return Err(Error::FlowControl);
        }
        let stream = self
            .streams
            .iter_mut()
            .find(|stream| stream.id == id)
            .ok_or(Error::Invalid)?;
        let end = offset.saturating_add(len as u64);
        let new_bytes = end.saturating_sub(stream.sent);
        stream.sent = max(stream.sent, end);
        // Preserve existing tolerant send semantics while exposing lifecycle
        // diagnostics: a newly appended range after an earlier FIN makes the
        // send half active again. Exact retransmissions do not call reserve.
        if new_bytes != 0 {
            stream.finished = false;
        }
        self.sent_data = self.sent_data.saturating_add(new_bytes);
        Ok(())
    }

    pub(crate) fn extend_connection(&mut self, max_data: u64) {
        self.max_data = max(self.max_data, max_data);
    }

    pub(crate) fn extend_stream(&mut self, id: u64, max_data: u64) -> Result<(), Error> {
        let stream = self
            .streams
            .iter_mut()
            .find(|stream| stream.id == id)
            .ok_or(Error::Invalid)?;
        stream.max_data = max(stream.max_data, max_data);
        Ok(())
    }

    /// Record the final locally-sent stream frame after it has entered the
    /// endpoint retransmission ledger. Retransmission uses that ledger and
    /// therefore does not re-open a stream in this accounting.
    pub(crate) fn finish_stream(&mut self, id: u64) -> Result<(), Error> {
        let stream = self
            .streams
            .iter_mut()
            .find(|stream| stream.id == id)
            .ok_or(Error::Invalid)?;
        stream.finished = true;
        Ok(())
    }

    fn is_finished(&self, id: u64) -> bool {
        self.stream(id).is_some_and(|stream| stream.finished)
    }

    fn remove_stream(&mut self, id: u64) -> bool {
        let Some(index) = self.streams.iter().position(|stream| stream.id == id) else {
            return false;
        };
        self.streams.remove(index);
        true
    }

    #[cfg(test)]
    fn stream_stats(&self, role: Role) -> ConnectionStreamStats {
        let mut result = ConnectionStreamStats::default();
        for stream in &self.streams {
            let server_initiated = stream.id & 1 != 0;
            let local = server_initiated == matches!(role, Role::Server);
            let direction = if local {
                &mut result.locally_initiated
            } else {
                &mut result.peer_initiated
            };
            direction.total = direction.total.saturating_add(1);
            if !stream.finished {
                direction.active = direction.active.saturating_add(1);
            }
        }
        result
    }

    #[cfg(test)]
    pub(crate) fn stream_credit(&self, id: u64) -> Option<u64> {
        self.stream(id).map(|stream| stream.max_data)
    }

    /// Number of new ordered bytes which fit both the connection and stream
    /// limits at `offset`. This is application-facing stream capacity, not a
    /// packet, ACK, or retransmission API.
    pub(crate) fn available(&self, id: u64, offset: u64) -> Option<u64> {
        let stream = self.stream(id)?;
        let connection_end = stream
            .sent
            .saturating_add(self.max_data.saturating_sub(self.sent_data));
        Some(min(stream.max_data, connection_end).saturating_sub(offset))
    }
}

/// RFC 9002 NewReno congestion state for one path.
///
/// This is intentionally bearer-neutral: the caller supplies packet sizes,
/// ACKs, and loss events.  Flow credit and congestion credit are separate;
/// both must allow a sender to transmit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CongestionController {
    pub max_packet_size: u64,
    pub congestion_window: u64,
    pub slow_start_threshold: u64,
    pub bytes_in_flight: u64,
    /// Largest packet number sent when the current NewReno recovery epoch
    /// began. Losses from that older flight still leave bytes in flight, but
    /// must not halve the congestion window again.
    recovery_start_packet: Option<u32>,
}

/// Bounded RFC-9002-shaped RTT estimator. The endpoint starts with a
/// conservative 500 ms PTO and adapts only from newly acknowledged packets;
/// bearers provide the clock through `set_time`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RttEstimator {
    latest_rtt: Option<u64>,
    smoothed_rtt: Option<u64>,
    rttvar: u64,
    min_rtt: Option<u64>,
}

impl Default for RttEstimator {
    fn default() -> Self {
        Self {
            latest_rtt: None,
            smoothed_rtt: None,
            rttvar: 0,
            min_rtt: None,
        }
    }
}

impl RttEstimator {
    const INITIAL_PTO: u64 = 500_000;
    const GRANULARITY: u64 = 1_000;

    pub(crate) fn update(&mut self, sample: u64) {
        self.latest_rtt = Some(sample);
        self.min_rtt = Some(self.min_rtt.map_or(sample, |value| value.min(sample)));
        match self.smoothed_rtt {
            None => {
                self.smoothed_rtt = Some(sample);
                self.rttvar = sample / 2;
            }
            Some(smoothed) => {
                let variation = smoothed.abs_diff(sample);
                self.rttvar = (self.rttvar.saturating_mul(3).saturating_add(variation)) / 4;
                self.smoothed_rtt = Some(smoothed.saturating_mul(7).saturating_add(sample) / 8);
            }
        }
    }

    pub(crate) const fn latest(&self) -> Option<u64> {
        self.latest_rtt
    }

    pub(crate) const fn smoothed(&self) -> Option<u64> {
        self.smoothed_rtt
    }

    #[cfg(test)]
    pub(crate) const fn variance(&self) -> u64 {
        self.rttvar
    }

    pub(crate) const fn minimum(&self) -> Option<u64> {
        self.min_rtt
    }

    pub(crate) fn pto(&self) -> u64 {
        let Some(smoothed) = self.smoothed_rtt else {
            return Self::INITIAL_PTO;
        };
        smoothed
            .saturating_add((self.rttvar.saturating_mul(4)).max(Self::GRANULARITY))
            .max(Self::GRANULARITY)
    }
}

impl CongestionController {
    pub(crate) fn new(max_packet_size: u64) -> Self {
        let mds = max_packet_size.max(1);
        let initial_window = (10 * mds).min((2 * mds).max(14_720));
        Self {
            max_packet_size: mds,
            congestion_window: initial_window,
            slow_start_threshold: u64::MAX,
            bytes_in_flight: 0,
            recovery_start_packet: None,
        }
    }

    pub(crate) fn can_send(&self, bytes: u64) -> bool {
        self.bytes_in_flight.saturating_add(bytes) <= self.congestion_window
    }

    pub(crate) fn on_packet_sent(&mut self, bytes: u64) -> bool {
        if !self.can_send(bytes) {
            return false;
        }
        self.bytes_in_flight = self.bytes_in_flight.saturating_add(bytes);
        true
    }

    /// Account for one bounded loss/PTO probe.  A retransmission replaces
    /// information already declared lost, so it must remain possible even
    /// when the reduced congestion window is temporarily below data still in
    /// flight.  The caller's retained-packet bound limits the probe rate.
    pub(crate) fn on_retransmission_sent(&mut self, bytes: u64) {
        self.bytes_in_flight = self.bytes_in_flight.saturating_add(bytes);
    }

    pub(crate) fn on_ack(&mut self, acked_bytes: u64) {
        let acked = min(acked_bytes, self.bytes_in_flight);
        self.bytes_in_flight -= acked;
        if acked == 0 {
            return;
        }
        if self.congestion_window < self.slow_start_threshold {
            self.congestion_window = self.congestion_window.saturating_add(acked);
        } else {
            let increase =
                (self.max_packet_size.saturating_mul(acked) / self.congestion_window.max(1)).max(1);
            self.congestion_window = self.congestion_window.saturating_add(increase);
        }
    }

    /// Replace an outstanding transmission without declaring congestion.
    pub(crate) fn remove_in_flight(&mut self, bytes: u64) {
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(bytes);
    }

    #[cfg(test)]
    pub(crate) fn on_loss(&mut self, lost_bytes: u64) {
        if lost_bytes == 0 {
            return;
        }
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(lost_bytes);
        let reduced = self.congestion_window / 2;
        self.slow_start_threshold = reduced.max(2 * self.max_packet_size);
        self.congestion_window = self.slow_start_threshold;
    }

    /// Account a transport-declared packet loss using RFC 9002's NewReno
    /// recovery epoch.  Every loss releases its in-flight bytes.  The
    /// multiplicative decrease is applied once, when the first lost packet
    /// sent after the previous recovery boundary is declared lost.
    pub(crate) fn on_packet_lost(
        &mut self,
        lost_bytes: u64,
        lost_packet_number: u32,
        largest_sent_packet: u32,
    ) {
        if lost_bytes == 0 {
            return;
        }
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(lost_bytes);
        if self
            .recovery_start_packet
            .is_some_and(|start| lost_packet_number <= start)
        {
            return;
        }
        let reduced = self.congestion_window / 2;
        self.slow_start_threshold = reduced.max(2 * self.max_packet_size);
        self.congestion_window = self.slow_start_threshold;
        self.recovery_start_packet = Some(largest_sent_packet);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct StreamState {
    pub id: u64,
    pub max_data: u64,
    pub received: u64,
    pub consumed: u64,
    pub finished: bool,
}

impl StreamState {
    pub(crate) const fn new(id: u64, max_data: u64) -> Self {
        Self {
            id,
            max_data,
            received: 0,
            consumed: 0,
            finished: false,
        }
    }
    pub(crate) fn accept(&mut self, offset: u64, len: usize, fin: bool) -> Result<(), Error> {
        let end = offset.checked_add(len as u64).ok_or(Error::FlowControl)?;
        if end > self.max_data {
            return Err(Error::FlowControl);
        }
        self.received = max(self.received, end);
        self.finished |= fin;
        Ok(())
    }
    pub(crate) fn consume(&mut self, n: u64) {
        self.consumed = min(self.received, self.consumed.saturating_add(n));
    }
    pub(crate) fn extend(&mut self, credit: u64) {
        self.max_data = max(self.max_data, self.consumed.saturating_add(credit));
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Role {
    Client,
    Server,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Receive credit advertised when creating an association.
///
/// This is public because hosts and memory-constrained devices choose different
/// initial limits. QUIC-lite clamps negotiated values to the storage configured
/// in the node; bearers must not alter these limits.
pub struct ConnectionLimits {
    /// Total bytes the peer may send across all streams before more credit.
    pub max_data: u64,
    /// Bytes the peer may send on one stream before more credit.
    pub max_stream_data: u64,
    /// Number of peer-initiated bidirectional streams initially permitted.
    pub max_streams_bidi: u64,
    /// Number of peer-initiated unidirectional streams initially permitted.
    pub max_streams_uni: u64,
}

pub(crate) const INITIAL_MAX_DATA: u64 = 256 * 1024;
pub(crate) const INITIAL_MAX_STREAM_DATA: u64 = INITIAL_MAX_DATA / 4;

impl ConnectionLimits {
    /// Apply a peer's requested lower receive profile without ever relaxing
    /// this endpoint's configured memory policy.
    pub(crate) const fn clamped_to_request(self, request: Option<ReceiveWindowRequest>) -> Self {
        match request {
            Some(request) => Self {
                max_data: if request.max_data < self.max_data {
                    request.max_data
                } else {
                    self.max_data
                },
                max_stream_data: if request.max_stream_data < self.max_stream_data {
                    request.max_stream_data
                } else {
                    self.max_stream_data
                },
                ..self
            },
            None => self,
        }
    }
    /// Construct a bounded receiver profile.  The connection total and each
    /// stream's share are independent: a small device can admit four useful
    /// concurrent 1 KiB streams without ever retaining more than 4 KiB of
    /// QUIC stream payload.  Applications may request a smaller working
    /// window, but cannot raise either ceiling after association.
    pub const fn with_receive_profile(
        max_data: u64,
        max_stream_data: u64,
        max_streams_bidi: u64,
    ) -> Self {
        Self {
            max_data,
            max_stream_data,
            max_streams_bidi,
            max_streams_uni: 4,
        }
    }

    /// Construct ordinary connection and per-stream receive credit from one
    /// application-selected byte window. Each stream receives one quarter of
    /// the connection credit, with a floor of one packet (or the complete
    /// connection window when it is smaller). This keeps one idle stream from
    /// consuming all ordinary connection credit.
    pub const fn with_receive_window(window_bytes: u64) -> Self {
        let packet_floor = if window_bytes < DEFAULT_MAX_PACKET_SIZE as u64 {
            window_bytes
        } else {
            DEFAULT_MAX_PACKET_SIZE as u64
        };
        let quarter = window_bytes / 4;
        let stream_window = if quarter > packet_floor {
            quarter
        } else {
            packet_floor
        };
        Self::with_receive_profile(window_bytes, stream_window, DEFAULT_MAX_BIDI_STREAMS)
    }
}

impl Default for ConnectionLimits {
    fn default() -> Self {
        Self {
            max_data: INITIAL_MAX_DATA,
            max_stream_data: INITIAL_MAX_STREAM_DATA,
            max_streams_bidi: DEFAULT_MAX_BIDI_STREAMS,
            max_streams_uni: 4,
        }
    }
}

/// Bounded stream accounting. Packet scheduling and bearer I/O remain in the caller.
#[derive(Clone)]
pub(crate) struct ConnectionState {
    pub role: Role,
    pub connection: FlowControl,
    pub limits: ConnectionLimits,
    pub received_data: u64,
    streams: Vec<StreamState>,
    /// Inclusive stream-ID ranges already retired. IDs in one range have the
    /// same low two direction/type bits and advance in steps of four.
    retired_streams: Vec<(u64, u64)>,
}

impl ConnectionState {
    pub(crate) fn new(role: Role, limits: ConnectionLimits) -> Self {
        Self {
            role,
            connection: FlowControl::new(limits.max_data),
            limits,
            received_data: 0,
            streams: Vec::new(),
            retired_streams: Vec::new(),
        }
    }

    fn stream_kind(id: u64) -> (bool, bool) {
        (id & 1 != 0, id & 2 != 0)
    }

    fn stream_ordinal(id: u64) -> u64 {
        if id >= FIRST_CLIENT_BIDI_STREAM_ID && id & 3 == 0 {
            (id - FIRST_CLIENT_BIDI_STREAM_ID) / 4
        } else {
            id / 4
        }
    }

    pub(crate) fn open(&mut self, id: u64) -> Result<&mut StreamState, Error> {
        let (server, uni) = Self::stream_kind(id);
        let local = server == matches!(self.role, Role::Server);
        if !local {
            return Err(Error::Invalid);
        }
        let _ = uni;
        if let Some(index) = self.find(id) {
            return Ok(&mut self.streams[index]);
        }
        self.insert_stream(id)
    }

    pub(crate) fn accept(
        &mut self,
        id: u64,
        offset: u64,
        len: usize,
        fin: bool,
    ) -> Result<&mut StreamState, Error> {
        let end = offset.checked_add(len as u64).ok_or(Error::FlowControl)?;
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
            if Self::stream_ordinal(id) >= limit {
                return Err(Error::StreamLimit);
            }
            // Check connection credit before inserting the new stream.  A
            // rejected first fragment must not consume a stream slot or leave
            // a phantom stream that changes later stream-limit decisions.
            if !self
                .connection
                .can_receive(self.received_data.saturating_add(end))
            {
                return Err(Error::FlowControl);
            }
            self.insert_stream(id)?;
            self.find(id).ok_or(Error::Invalid)?
        };
        let previous = self.streams[slot].received;
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
        self.streams[slot].accept(offset, len, fin)?;
        self.received_data = self.received_data.saturating_add(delta);
        Ok(&mut self.streams[slot])
    }

    fn is_retired(&self, id: u64) -> bool {
        self.retired_streams
            .iter()
            .any(|(first, last)| id >= *first && id <= *last && (id - first) % 4 == 0)
    }

    fn retire_stream(&mut self, id: u64) -> bool {
        let Some(index) = self.find(id) else {
            return false;
        };
        self.streams.remove(index);
        let class = id & 3;
        let mut first = id;
        let mut last = id;
        let mut at = 0;
        while at < self.retired_streams.len() {
            let (range_first, range_last) = self.retired_streams[at];
            if range_first & 3 == class
                && range_last.saturating_add(4) >= first
                && last.saturating_add(4) >= range_first
            {
                first = first.min(range_first);
                last = last.max(range_last);
                self.retired_streams.remove(at);
            } else {
                at += 1;
            }
        }
        self.retired_streams.push((first, last));
        self.retired_streams.sort_unstable_by_key(|range| range.0);
        true
    }

    pub(crate) fn consume(&mut self, id: u64, n: u64) -> Result<(), Error> {
        let i = self.find(id).ok_or(Error::Invalid)?;
        self.streams[i].consume(n);
        self.connection.consume(n);
        Ok(())
    }

    fn is_complete(&self, id: u64) -> bool {
        self.find(id).is_some_and(|index| {
            let stream = self.streams[index];
            stream.finished && stream.consumed == stream.received
        })
    }

    fn is_complete_or_retired(&self, id: u64) -> bool {
        self.is_retired(id) || self.is_complete(id)
    }

    fn remove_stream(&mut self, id: u64) -> bool {
        let Some(index) = self.find(id) else {
            return false;
        };
        self.streams.remove(index);
        true
    }

    fn is_peer_initiated(&self, id: u64) -> bool {
        let (server, _) = Self::stream_kind(id);
        server != matches!(self.role, Role::Server)
    }

    pub(crate) fn stream_max_data(&self, id: u64) -> Option<u64> {
        self.find(id).map(|i| self.streams[i].max_data)
    }

    pub(crate) fn extend_connection_credit(&mut self, credit: u64) {
        self.connection.extend(credit);
    }

    pub(crate) fn extend_stream_credit(&mut self, id: u64, credit: u64) -> Result<(), Error> {
        let i = self.find(id).ok_or(Error::Invalid)?;
        self.streams[i].extend(credit);
        Ok(())
    }

    /// Reserve one peer-initiated stream after an authenticated application
    /// command has named it. This does not accept bytes or create any local
    /// send capability; it only permits a later MAX_STREAM_DATA update before
    /// the first peer fragment arrives.
    #[cfg(test)]
    pub(crate) fn prepare_remote_stream(&mut self, id: u64) -> Result<(), Error> {
        if self.find(id).is_some() {
            return Ok(());
        }
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
        if Self::stream_ordinal(id) >= limit {
            return Err(Error::StreamLimit);
        }
        self.insert_stream(id)?;
        Ok(())
    }

    fn prepare_local_bidi_receive(&mut self, id: u64) -> Result<(), Error> {
        if self.find(id).is_some() {
            return Ok(());
        }
        let (server, uni) = Self::stream_kind(id);
        let local = server == matches!(self.role, Role::Server);
        if !local || uni {
            return Err(Error::Invalid);
        }
        self.insert_stream(id)?;
        Ok(())
    }

    fn find(&self, id: u64) -> Option<usize> {
        self.streams.iter().position(|stream| stream.id == id)
    }
    fn insert_stream(&mut self, id: u64) -> Result<&mut StreamState, Error> {
        self.streams
            .try_reserve(1)
            .map_err(|_| Error::StreamLimit)?;
        self.streams
            .push(StreamState::new(id, self.limits.max_stream_data));
        Ok(self.streams.last_mut().unwrap())
    }

    #[cfg(test)]
    fn stream_stats(&self) -> ConnectionStreamStats {
        let mut result = ConnectionStreamStats::default();
        for stream in &self.streams {
            let (server_initiated, _) = Self::stream_kind(stream.id);
            let local = server_initiated == matches!(self.role, Role::Server);
            let direction = if local {
                &mut result.locally_initiated
            } else {
                &mut result.peer_initiated
            };
            direction.total = direction.total.saturating_add(1);
            if !stream.finished {
                direction.active = direction.active.saturating_add(1);
            }
        }
        result
    }
}

/// Bearer-neutral endpoint state shared by host and embedded users.
///
/// The bearer owns sockets, timers, and packet storage.  This type owns the
/// protocol state that must not diverge between implementations: packet
/// acknowledgement ranges, receive credit, peer-advertised send credit, and
/// congestion control.
#[derive(Clone)]
pub(crate) struct EndpointState<const P: usize = DEFAULT_MAX_PACKET_SIZE> {
    pub send: SendFlowControl,
    pub receive: ConnectionState,
    pub congestion: CongestionController,
    pub received_packets: AckRangeSet,
    /// Most recent ACK range set received from the peer. This is diagnostic
    /// state only; congestion accounting still walks the retained ledger.
    peer_ack_ranges: AckRangeSet,
    pub next_packet_number: u32,
    pub largest_acked_by_peer: Option<u32>,
    sent_packets: Vec<Option<SentPacket<P>>>,
    local_cid: Option<ConnectionId>,
    peer_cid: Option<ConnectionId>,
    control_pending: bool,
    ack_pending: bool,
    ack_packets: u8,
    ack_frequency: u8,
    ack_reordering_threshold: u32,
    largest_ack_frequency_sequence: Option<u64>,
    pending_ack_frequency: Option<(u64, u64, u64, u64)>,
    last_ack_time: u64,
    largest_received_at: u64,
    max_ack_delay_us: u64,
    peer_max_ack_delay_us: u64,
    peer_max_in_flight_packets: usize,
    peer_max_streams_bidi: u64,
    peer_max_streams_uni: u64,
    // Several streams may be consumed before delayed ACK emission. Keep a
    // deduplicated list so one stream's MAX_STREAM_DATA cannot erase
    // another's credit update. Its enforced limit matches active stream state
    // `N`, while storage is allocated only for IDs actually awaiting credit.
    pending_stream_ids: Vec<u64>,
    /// Latest flow-credit control packet. MAX_* frames are reliable
    /// connection state, not a best-effort UDP hint: retain their intent
    /// until the peer ACKs the packet that carried it.
    credit_pending: bool,
    credit_packet_number: Option<u32>,
    // Consumption may advance the absolute MAX_* limits while the previous
    // publication is still in flight.  Retain one packet until it is ACKed;
    // this bit requests exactly one replacement carrying the newest limits.
    credit_dirty: bool,
    credit_retry_backoff: u8,
    max_streams_bidi_pending: bool,
    send_clock: u64,
    rtt: RttEstimator,
    /// Endpoint-owned PTO scheduling. A bearer may poll in a tight loop when
    /// its send window is full; without this gate it would retransmit every
    /// overdue packet as a separate "probe" in the same PTO episode.
    last_pto_probe_at: Option<u64>,
    pto_backoff: u8,
    close_code: Option<u64>,
    history_limit: usize,
    receive_growth_limits: ConnectionLimits,
    retired_peer_bidi: u64,
    stats: TransportStats,
    highest_received_packet: Option<u32>,
    last_receive_time: Option<u64>,
}

/// Directional connection identifiers. `local_receive` is the CID this
/// endpoint accepts on inbound packets; `peer_receive` is the CID placed in
/// every outbound packet. New associations normally negotiate distinct IDs.
/// The values may be equal for the original QUIC-lite bootstrap protocol,
/// where the first valid short-header response established a symmetric CID.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ConnectionIds {
    pub local_receive: ConnectionId,
    pub peer_receive: ConnectionId,
}

impl ConnectionIds {
    pub(crate) fn new(
        local_receive: ConnectionId,
        peer_receive: ConnectionId,
    ) -> Result<Self, Error> {
        if local_receive.value() == 0 || peer_receive.value() == 0 {
            return Err(Error::WrongConnectionId);
        }
        Ok(Self {
            local_receive,
            peer_receive,
        })
    }
}

#[derive(Clone, Copy)]
struct SentPacket<const P: usize> {
    packet_number: u32,
    // A retransmission has a fresh packet number, but an ACK for any prior
    // transmission still proves that this logical stream range was delivered.
    // Keep a bounded no_std ledger so a delayed ACK retires the range instead
    // of needlessly retransmitting it again.
    prior_packet_numbers: [u32; 16],
    prior_packet_count: u8,
    bytes: u64,
    stream_id: u64,
    offset: u64,
    fin: bool,
    payload_len: usize,
    payload: [u8; P],
    sent_at: u64,
    lost: bool,
}

impl<const P: usize> SentPacket<P> {
    fn acknowledged_by(&self, acknowledged: &AckRangeSet) -> bool {
        acknowledged.contains(self.packet_number)
            || self.prior_packet_numbers[..self.prior_packet_count as usize]
                .iter()
                .any(|packet_number| acknowledged.contains(*packet_number))
    }

    fn add_prior_packet_number(&mut self, packet_number: u32) {
        let count = self.prior_packet_count as usize;
        if count < self.prior_packet_numbers.len() {
            self.prior_packet_numbers[count] = packet_number;
            self.prior_packet_count += 1;
        } else {
            self.prior_packet_numbers.rotate_left(1);
            let last = self.prior_packet_numbers.len() - 1;
            self.prior_packet_numbers[last] = packet_number;
        }
    }

    /// Packet number of the first transmission of this logical stream range.
    /// Retransmissions use a fresh wire packet number, but congestion recovery
    /// must not treat repeatedly lost copies of one range as new congestion
    /// events. ACK matching keeps the full bounded lineage separately.
    fn logical_packet_number(&self) -> u32 {
        self.prior_packet_numbers[..self.prior_packet_count as usize]
            .iter()
            .copied()
            .fold(self.packet_number, min)
    }
}

impl<const P: usize> EndpointState<P> {
    /// Initialize an endpoint in its final allocation. Firmware uses this for
    /// a boxed connection so the admission-sized retransmission ledger is
    /// never copied through an ingress task stack frame.
    pub(crate) unsafe fn init_in_place(
        out: *mut Self,
        role: Role,
        limits: ConnectionLimits,
        max_packet_size: u64,
        history_capacity: usize,
    ) {
        assert!(history_capacity > 0);
        unsafe {
            core::ptr::addr_of_mut!((*out).send).write(SendFlowControl::new(
                limits.max_data,
                limits.max_stream_data,
            ));
            core::ptr::addr_of_mut!((*out).receive).write(ConnectionState::new(role, limits));
            core::ptr::addr_of_mut!((*out).congestion)
                .write(CongestionController::new(max_packet_size));
            core::ptr::addr_of_mut!((*out).received_packets).write(AckRangeSet::new());
            core::ptr::addr_of_mut!((*out).peer_ack_ranges).write(AckRangeSet::new());
            core::ptr::addr_of_mut!((*out).next_packet_number).write(0);
            core::ptr::addr_of_mut!((*out).largest_acked_by_peer).write(None);
            core::ptr::addr_of_mut!((*out).sent_packets).write(alloc::vec![None; history_capacity]);
            core::ptr::addr_of_mut!((*out).local_cid).write(None);
            core::ptr::addr_of_mut!((*out).peer_cid).write(None);
            core::ptr::addr_of_mut!((*out).control_pending).write(false);
            core::ptr::addr_of_mut!((*out).ack_pending).write(false);
            core::ptr::addr_of_mut!((*out).ack_packets).write(0);
            core::ptr::addr_of_mut!((*out).ack_frequency).write(2);
            core::ptr::addr_of_mut!((*out).ack_reordering_threshold).write(1);
            core::ptr::addr_of_mut!((*out).largest_ack_frequency_sequence).write(None);
            core::ptr::addr_of_mut!((*out).pending_ack_frequency).write(None);
            core::ptr::addr_of_mut!((*out).last_ack_time).write(0);
            core::ptr::addr_of_mut!((*out).largest_received_at).write(0);
            core::ptr::addr_of_mut!((*out).max_ack_delay_us).write(25_000);
            core::ptr::addr_of_mut!((*out).peer_max_ack_delay_us).write(25_000);
            core::ptr::addr_of_mut!((*out).peer_max_in_flight_packets).write(usize::MAX);
            core::ptr::addr_of_mut!((*out).peer_max_streams_bidi).write(limits.max_streams_bidi);
            core::ptr::addr_of_mut!((*out).peer_max_streams_uni).write(limits.max_streams_uni);
            core::ptr::addr_of_mut!((*out).pending_stream_ids).write(Vec::new());
            core::ptr::addr_of_mut!((*out).credit_pending).write(false);
            core::ptr::addr_of_mut!((*out).credit_packet_number).write(None);
            core::ptr::addr_of_mut!((*out).credit_dirty).write(false);
            core::ptr::addr_of_mut!((*out).credit_retry_backoff).write(0);
            core::ptr::addr_of_mut!((*out).max_streams_bidi_pending).write(false);
            core::ptr::addr_of_mut!((*out).send_clock).write(0);
            core::ptr::addr_of_mut!((*out).rtt).write(RttEstimator::default());
            core::ptr::addr_of_mut!((*out).last_pto_probe_at).write(None);
            core::ptr::addr_of_mut!((*out).pto_backoff).write(0);
            core::ptr::addr_of_mut!((*out).close_code).write(None);
            core::ptr::addr_of_mut!((*out).history_limit).write(history_capacity);
            core::ptr::addr_of_mut!((*out).receive_growth_limits).write(limits);
            core::ptr::addr_of_mut!((*out).retired_peer_bidi).write(0);
            core::ptr::addr_of_mut!((*out).stats).write(TransportStats::default());
            core::ptr::addr_of_mut!((*out).highest_received_packet).write(None);
            core::ptr::addr_of_mut!((*out).last_receive_time).write(None);
        }
    }
    pub(crate) fn new(role: Role, limits: ConnectionLimits, max_packet_size: u64) -> Self {
        Self::new_with_history_capacity(role, limits, max_packet_size, 8)
    }

    pub(crate) fn new_established(
        role: Role,
        limits: ConnectionLimits,
        max_packet_size: u64,
        ids: ConnectionIds,
    ) -> Self {
        let mut endpoint = Self::new(role, limits, max_packet_size);
        endpoint.local_cid = Some(ids.local_receive);
        endpoint.peer_cid = Some(ids.peer_receive);
        endpoint
    }

    /// Construct an endpoint with a selected retransmission ledger size.
    ///
    /// Host and embedded builds allocate only the requested number of slots
    /// in the same heap-backed vector. The runtime resource policy supplies
    /// the limit; it is not part of the endpoint's concrete type.
    pub(crate) fn new_with_history_capacity(
        role: Role,
        limits: ConnectionLimits,
        max_packet_size: u64,
        history_capacity: usize,
    ) -> Self {
        assert!(history_capacity > 0);
        Self {
            send: SendFlowControl::new(limits.max_data, limits.max_stream_data),
            receive: ConnectionState::new(role, limits),
            congestion: CongestionController::new(max_packet_size),
            received_packets: AckRangeSet::new(),
            peer_ack_ranges: AckRangeSet::new(),
            next_packet_number: 0,
            largest_acked_by_peer: None,
            sent_packets: alloc::vec![None; history_capacity],
            local_cid: None,
            peer_cid: None,
            control_pending: false,
            ack_pending: false,
            ack_packets: 0,
            ack_frequency: 2,
            ack_reordering_threshold: 1,
            largest_ack_frequency_sequence: None,
            pending_ack_frequency: None,
            last_ack_time: 0,
            largest_received_at: 0,
            max_ack_delay_us: 25_000,
            peer_max_ack_delay_us: 25_000,
            peer_max_in_flight_packets: usize::MAX,
            peer_max_streams_bidi: limits.max_streams_bidi,
            peer_max_streams_uni: limits.max_streams_uni,
            pending_stream_ids: Vec::new(),
            credit_pending: false,
            credit_packet_number: None,
            credit_dirty: false,
            credit_retry_backoff: 0,
            max_streams_bidi_pending: false,
            send_clock: 0,
            rtt: RttEstimator::default(),
            last_pto_probe_at: None,
            pto_backoff: 0,
            close_code: None,
            history_limit: history_capacity,
            receive_growth_limits: limits,
            retired_peer_bidi: 0,
            stats: TransportStats::default(),
            highest_received_packet: None,
            last_receive_time: None,
        }
    }

    pub(crate) fn observe_packet(&mut self, packet_number: u32) {
        if !self.received_packets.contains(packet_number) {
            let previous_highest = self.highest_received_packet;
            if let Some(highest) = self.highest_received_packet {
                let next = highest.saturating_add(1);
                if packet_number < next {
                    self.stats.out_of_order_packets += 1;
                } else if packet_number > next {
                    self.stats.inferred_missing_packets += u64::from(packet_number - next);
                }
            }
            self.highest_received_packet = Some(
                self.highest_received_packet
                    .map_or(packet_number, |highest| highest.max(packet_number)),
            );
            if previous_highest.map_or(true, |highest| packet_number > highest) {
                self.largest_received_at = self.send_clock;
            }
            if let Some(previous) = self.last_receive_time {
                let delta = self.send_clock.saturating_sub(previous);
                self.stats.receive_interpacket_samples += 1;
                self.stats.receive_interpacket_total += delta;
                if self.stats.receive_interpacket_samples == 1 {
                    self.stats.receive_interpacket_min = delta;
                } else {
                    self.stats.receive_interpacket_min =
                        self.stats.receive_interpacket_min.min(delta);
                }
                self.stats.receive_interpacket_max = self.stats.receive_interpacket_max.max(delta);
            }
            self.last_receive_time = Some(self.send_clock);
        }
        self.received_packets.insert(packet_number);
    }

    pub(crate) fn expected_packet_number(&self) -> u32 {
        self.largest_received()
            .and_then(|value| value.checked_add(1))
            .unwrap_or(0)
    }

    pub(crate) fn next_packet_number_len(&self) -> u8 {
        packet_number_len(self.next_packet_number, self.largest_acked_by_peer)
    }

    pub(crate) fn largest_received(&self) -> Option<u32> {
        self.received_packets.get(0).map(|range| range.end)
    }

    pub(crate) fn open_send_stream(&mut self, id: u64, max_data: u64) -> Result<(), Error> {
        let server_initiated = id & 1 != 0;
        let unidirectional = id & 2 != 0;
        let locally_initiated = server_initiated == matches!(self.receive.role, Role::Server);
        if locally_initiated {
            let maximum = if unidirectional {
                self.peer_max_streams_uni
            } else {
                self.peer_max_streams_bidi
            };
            if ConnectionState::stream_ordinal(id) >= maximum {
                return Err(Error::StreamLimit);
            }
        }
        self.send.open_stream(id, max_data)?;
        if locally_initiated && !unidirectional {
            if let Err(error) = self.receive.open(id) {
                self.send.remove_stream(id);
                return Err(error);
            }
        }
        Ok(())
    }

    /// Install peer-advertised bootstrap credit before creating application
    /// streams. This prevents a default host window from overrunning a
    /// smaller embedded receiver before its first MAX_* update.
    pub(crate) fn set_initial_peer_credit(
        &mut self,
        max_data: u64,
        max_stream_data: u64,
    ) -> Result<(), Error> {
        self.set_initial_peer_budget(max_data, max_stream_data, 0)
    }

    /// Install bootstrap byte credit and an optional peer packet-flight
    /// budget. A non-zero budget is receiver-advertised backpressure, not a
    /// bearer pacing policy: ACKed packets immediately free another slot.
    pub(crate) fn set_initial_peer_budget(
        &mut self,
        max_data: u64,
        max_stream_data: u64,
        max_in_flight_packets: u16,
    ) -> Result<(), Error> {
        self.send.set_initial_limits(max_data, max_stream_data)?;
        self.peer_max_in_flight_packets = if max_in_flight_packets == 0 {
            usize::MAX
        } else {
            max_in_flight_packets as usize
        };
        Ok(())
    }

    /// Receiver-advertised bound on retained outbound STREAM packets.
    pub(crate) fn peer_max_in_flight_packets(&self) -> usize {
        self.peer_max_in_flight_packets
    }

    /// Current peer-advertised byte limits for a locally initiated stream.
    /// This is bounded transport telemetry for stalled-sender diagnosis.
    #[cfg(test)]
    pub(crate) fn peer_send_credit(&self, stream_id: u64) -> Option<(u64, u64)> {
        Some((self.send.max_data, self.send.stream_credit(stream_id)?))
    }

    /// Remaining peer-advertised byte capacity for one ordered stream source.
    pub(crate) fn available_stream_send_bytes(&self, stream_id: u64, offset: u64) -> Option<u64> {
        self.send.available(stream_id, offset)
    }

    /// Receiver-side consumption and current limits for bounded stream-sink
    /// diagnostics. This exposes no packet payload or bearer state.
    pub(crate) fn receive_credit_state(&self, stream_id: u64) -> Option<(u64, u64, u64)> {
        let index = self.receive.find(stream_id)?;
        let stream = self.receive.streams[index];
        Some((
            self.receive.connection.consumed,
            stream.consumed,
            stream.max_data,
        ))
    }

    /// Largest packet number the peer has acknowledged on this association.
    /// This is aggregate transport telemetry used to diagnose a stalled
    /// sender; callers must not infer application delivery from it.
    pub(crate) fn largest_acked_by_peer(&self) -> Option<u32> {
        self.largest_acked_by_peer
    }

    pub(crate) fn install_connection_ids(
        &mut self,
        local: ConnectionId,
        peer: ConnectionId,
    ) -> Result<(), Error> {
        let _ = ConnectionIds::new(local, peer)?;
        self.local_cid = Some(local);
        self.peer_cid = Some(peer);
        Ok(())
    }

    /// Continue the sender packet-number space after packets emitted by a
    /// bearer-owned bootstrap exchange.  The value may only move forward;
    /// retransmissions and later established packets therefore cannot reuse a
    /// bootstrap packet number.
    pub(crate) fn continue_packet_numbers_from(&mut self, next: u32) -> Result<(), Error> {
        if next < self.next_packet_number {
            return Err(Error::Invalid);
        }
        self.next_packet_number = next;
        Ok(())
    }

    pub(crate) fn local_connection_id(&self) -> Option<ConnectionId> {
        self.local_cid
    }
    pub(crate) fn peer_connection_id(&self) -> Option<ConnectionId> {
        self.peer_cid
    }
    /// Maximum number of retained packets currently enabled for this side.
    /// Host and firmware allocate the same heap-backed vector at association
    /// admission. The limit is runtime policy, not part of the endpoint type.
    pub(crate) const fn history_capacity(&self) -> usize {
        self.history_limit
    }

    /// Number of retransmission slots currently backed by heap storage.
    /// This is exposed for memory-budget diagnostics and regression tests;
    /// protocol decisions continue to use [`Self::history_capacity`].
    pub(crate) fn allocated_history_packets(&self) -> usize {
        self.sent_packets.len()
    }

    /// Resize the active ledger for a controlled diagnostic. Normal host and
    /// firmware associations select this at admission from the shared memory
    /// policy. A resize may never evict packets still needed for retransmission.
    pub(crate) fn set_history_capacity(&mut self, limit: usize) -> Result<(), Error> {
        if limit == 0 {
            return Err(Error::HistoryFull);
        }
        if limit > self.sent_packets.len() {
            self.sent_packets
                .try_reserve(limit - self.sent_packets.len())
                .map_err(|_| Error::HistoryFull)?;
            self.sent_packets.resize(limit, None);
        } else if limit < self.sent_packets.len()
            && self.sent_packets.iter().skip(limit).all(Option::is_none)
        {
            self.sent_packets.truncate(limit);
            self.sent_packets.shrink_to_fit();
        }
        self.history_limit = limit;
        Ok(())
    }

    /// Change the live receive-credit growth policy. Credit already sent on
    /// the wire is never revoked. Lower ceilings simply withhold later
    /// MAX_DATA, MAX_STREAM_DATA, and MAX_STREAMS increases.
    pub(crate) fn set_receive_growth_limits(
        &mut self,
        limits: ConnectionLimits,
    ) -> Result<(), Error> {
        if limits.max_data == 0 || limits.max_stream_data == 0 {
            return Err(Error::Invalid);
        }
        self.receive_growth_limits = limits;
        self.receive.extend_connection_credit(limits.max_data);
        for stream in &mut self.receive.streams {
            stream.max_data = max(
                stream.max_data,
                stream.consumed.saturating_add(limits.max_stream_data),
            );
        }
        let target = self
            .retired_peer_bidi
            .saturating_add(limits.max_streams_bidi);
        if target > self.receive.limits.max_streams_bidi {
            self.receive.limits.max_streams_bidi = target;
            self.max_streams_bidi_pending = true;
        }
        self.credit_pending = true;
        self.control_pending = true;
        Ok(())
    }
    pub(crate) fn history_len(&self) -> usize {
        self.sent_packets
            .iter()
            .filter(|slot| slot.is_some())
            .count()
    }

    /// Number of slots physically allocated by this endpoint. This changes
    /// with dynamic ledger growth/shrink on both host and no-std firmware.
    pub(crate) fn history_storage_slots(&self) -> usize {
        self.sent_packets.len()
    }

    pub(crate) fn history_storage_bytes(&self) -> usize {
        self.history_storage_slots() * core::mem::size_of::<SentPacket<P>>()
    }
    pub(crate) fn received_packet_count(&self) -> usize {
        self.received_packets.len()
    }
    pub(crate) fn has_received_packet(&self, packet_number: u32) -> bool {
        self.received_packets.contains(packet_number)
    }
    pub(crate) fn bytes_in_flight(&self) -> u64 {
        self.congestion.bytes_in_flight
    }

    pub(crate) const fn retransmission_payload_capacity(&self) -> usize {
        P
    }

    /// Number of retransmittable stream payload bytes currently retained.
    /// This is intentionally exposed for diagnostics and bounded-memory
    /// assertions; packet metadata is accounted separately by the profile.
    pub(crate) fn retained_payload_bytes(&self) -> usize {
        self.sent_packets
            .iter()
            .flatten()
            .map(|packet| packet.payload_len)
            .sum()
    }

    /// Maximum payload bytes that this endpoint can retain in its ledger.
    pub(crate) const fn retransmission_capacity_bytes(&self) -> usize {
        self.history_limit.saturating_mul(P)
    }

    /// Advance the transport clock in milliseconds.
    ///
    /// Every host and embedded adapter must convert its platform monotonic
    /// source at this boundary. ACK delay, credit retry, RTT/PTO samples, and
    /// [`Self::next_bearer_deadline`] all use this same unit.
    pub(crate) fn set_time(&mut self, now: u64) {
        self.send_clock = now;
    }

    /// Select how many newly received stream packets may be coalesced before
    /// an ACK/window packet is emitted. The transport still owns the ACK
    /// contents and scheduling; the bearer/profile selects this policy.
    pub(crate) fn set_ack_frequency(&mut self, packets: u8) {
        self.ack_frequency = packets.clamp(1, ACK_RANGE_CAPACITY as u8);
    }

    /// Install the out-of-band association ACK policy. Version 0 has no
    /// authenticated ACK_FREQUENCY frame, so both peers must receive these
    /// values from the association/bootstrap owner before data is sent.
    pub(crate) fn set_ack_policy(&mut self, packets: u8, max_ack_delay_us: u64) {
        self.set_ack_frequency(packets);
        self.max_ack_delay_us = max_ack_delay_us;
        self.peer_max_ack_delay_us = max_ack_delay_us;
    }

    /// Active local ACK policy after any peer ACK_FREQUENCY update.
    ///
    /// This exposes policy, rather than making a bearer infer it from the
    /// number of ACK_FREQUENCY frames observed in a diagnostics interval.
    pub(crate) const fn ack_frequency(&self) -> u8 {
        self.ack_frequency
    }

    /// Active local maximum delayed-ACK timer in microseconds.
    pub(crate) const fn max_ack_delay_us(&self) -> u64 {
        self.max_ack_delay_us
    }

    /// Return the next transport-owned wake deadline for a sparse bearer.
    ///
    /// The bearer supplies microseconds in the same monotonic domain as
    /// [`Self::set_time`], then blocks until this instant instead of running a
    /// housekeeping tick.  The result covers a pending delayed ACK and the
    /// earliest retained packet's PTO.  It deliberately exposes only a
    /// deadline, never a packet: the normal owner must still call
    /// [`Self::poll_transmit`] or [`Self::retransmit_due`] after the timer
    /// fires, preserving one packet/ledger owner across UART, UDP6, and NOW.
    pub(crate) fn next_bearer_deadline(&self) -> Option<u64> {
        let pto = self.pto_timeout();
        let immediate_control = self.control_pending
            || self.pending_ack_frequency.is_some()
            || (self.ack_pending && self.ack_packets >= self.ack_frequency);
        let ack_deadline = if immediate_control {
            Some(self.send_clock)
        } else {
            self.ack_pending.then_some(
                self.largest_received_at
                    .saturating_add(self.max_ack_delay_us),
            )
        };
        // MAX_DATA/MAX_STREAM_DATA packets are deliberately not retained in
        // the stream retransmission ledger: they carry the latest absolute
        // limits and are safe to regenerate. An event-driven bearer still
        // needs a wake after a submitted update may have been lost. Polling
        // socket loops used to hide this missing edge, while the ESP worker
        // slept forever with its peer flow-control blocked.
        // Consumption can be reported after this receive turn already emitted
        // its ordinary ACK.  In that case there is no credit packet number
        // yet, but the newly released MAX_* state still needs a wake of its
        // own: a flow-blocked peer has no further packet with which to wake
        // us.  Keep the same bounded delayed-control cadence for both the
        // first publication and a later unacknowledged publication.
        let credit_deadline =
            self.credit_pending
                .then_some(self.last_ack_time.saturating_add(
                    if self.credit_packet_number.is_some() {
                        // A MAX_* update is reliable connection state. Once it has
                        // been sent, retry it on the normal adaptive loss clock, not
                        // a fixed control tick: otherwise an unreachable peer is
                        // sent the identical ACK/MAX packet twenty times per second.
                        self.pto_timeout().saturating_mul(
                            1u64 << self.credit_retry_backoff.min(MAX_PTO_BACKOFF_EXPONENT),
                        )
                    } else {
                        self.max_ack_delay_us
                    },
                ));
        let earliest_sent = self
            .sent_packets
            .iter()
            .flatten()
            .filter(|packet| !packet.lost)
            .map(|packet| packet.sent_at)
            .min();
        let pto_deadline = earliest_sent.map(|sent_at| {
            let interval =
                pto.saturating_mul(1u64 << self.pto_backoff.min(MAX_PTO_BACKOFF_EXPONENT));
            self.last_pto_probe_at
                .map(|last| last.saturating_add(interval))
                .unwrap_or_else(|| sent_at.saturating_add(interval))
        });
        ack_deadline
            .into_iter()
            .chain(credit_deadline)
            .chain(pto_deadline)
            .min()
    }

    /// Request the peer's ACK policy using the QUIC ACK_FREQUENCY extension.
    /// `packet_threshold=1` is RFC 9000's every-other-ack-eliciting-packet
    /// default; delay is carried in microseconds by the extension.
    pub(crate) fn request_ack_frequency(
        &mut self,
        sequence: u64,
        packet_threshold: u64,
        max_ack_delay_us: u64,
        reordering_threshold: u64,
    ) -> Result<(), Error> {
        if packet_threshold >= ACK_RANGE_CAPACITY as u64
            || max_ack_delay_us > 16_383_000
            || reordering_threshold > u64::from(u32::MAX)
        {
            return Err(Error::Invalid);
        }
        self.pending_ack_frequency = Some((
            sequence,
            packet_threshold,
            max_ack_delay_us,
            reordering_threshold,
        ));
        Ok(())
    }

    fn apply_ack_frequency(
        &mut self,
        sequence: u64,
        packet_threshold: u64,
        max_ack_delay_us: u64,
        reordering_threshold: u64,
    ) -> Result<(), Error> {
        if self
            .largest_ack_frequency_sequence
            .is_some_and(|previous| sequence <= previous)
        {
            return Ok(());
        }
        if packet_threshold >= ACK_RANGE_CAPACITY as u64
            || max_ack_delay_us > 16_383_000
            || reordering_threshold > u64::from(u32::MAX)
        {
            return Err(Error::Invalid);
        }
        self.ack_frequency = (packet_threshold as u8).saturating_add(1);
        self.max_ack_delay_us = max_ack_delay_us;
        self.ack_reordering_threshold = reordering_threshold as u32;
        self.largest_ack_frequency_sequence = Some(sequence);
        self.stats.ack_frequency_received = self.stats.ack_frequency_received.saturating_add(1);
        Ok(())
    }

    /// Return transport diagnostics for the current measurement interval.
    pub(crate) const fn stats(&self) -> TransportStats {
        self.stats
    }

    /// Start a fresh diagnostics interval without disturbing protocol state.
    pub(crate) fn reset_stats(&mut self) {
        self.stats = TransportStats::default();
        self.highest_received_packet = None;
        self.last_receive_time = None;
    }

    pub(crate) const fn latest_rtt(&self) -> Option<u64> {
        self.rtt.latest()
    }

    pub(crate) const fn smoothed_rtt(&self) -> Option<u64> {
        self.rtt.smoothed()
    }

    #[cfg(test)]
    pub(crate) const fn rtt_variance(&self) -> u64 {
        self.rtt.variance()
    }

    pub(crate) const fn min_rtt(&self) -> Option<u64> {
        self.rtt.minimum()
    }

    pub(crate) fn pto_timeout(&self) -> u64 {
        self.rtt.pto().saturating_add(self.peer_max_ack_delay_us)
    }

    pub(crate) const fn is_closed(&self) -> bool {
        self.close_code.is_some()
    }

    pub(crate) const fn close_code(&self) -> Option<u64> {
        self.close_code
    }

    /// Snapshot stream ownership/lifecycle without exposing a transport
    /// packet or bearer address. This is the source for connection-status
    /// handlers on firmware, Linux, and Android.
    #[cfg(test)]
    pub(crate) fn stream_stats(&self) -> ConnectionStreamStats {
        let mut result = self.send.stream_stats(self.receive.role);
        let received = self.receive.stream_stats();
        result.locally_initiated.total = result
            .locally_initiated
            .total
            .saturating_add(received.locally_initiated.total);
        result.locally_initiated.active = result
            .locally_initiated
            .active
            .saturating_add(received.locally_initiated.active);
        result.peer_initiated.total = result
            .peer_initiated
            .total
            .saturating_add(received.peer_initiated.total);
        result.peer_initiated.active = result
            .peer_initiated
            .active
            .saturating_add(received.peer_initiated.active);
        result
    }

    pub(crate) fn close(&mut self, code: u64) {
        self.close_code = Some(code);
    }

    /// Encode a connection-close packet. The caller sends it through its
    /// bearer and then stops scheduling application data on this endpoint.
    pub(crate) fn poll_close(&mut self, out: &mut [u8]) -> Result<Option<usize>, Error> {
        let Some(code) = self.close_code else {
            return Ok(None);
        };
        let dcid = self.peer_cid.ok_or(Error::WrongConnectionId)?;
        let mut used = ShortHeader {
            flags: FLAG_FIXED,
            dcid,
            packet_number: self.next_packet_number,
            packet_number_len: self.next_packet_number_len(),
        }
        .encode(out)?;
        used += Frame::Close { code }.encode(&mut out[used..])?;
        self.next_packet_number = self
            .next_packet_number
            .checked_add(1)
            .ok_or(Error::PacketNumberExhausted)?;
        Ok(Some(used))
    }

    pub(crate) fn reserve_send(&mut self, id: u64, offset: u64, len: usize) -> Result<(), Error> {
        self.send.reserve(id, offset, len)
    }

    pub(crate) fn packet_sent(&mut self, bytes: u64) -> bool {
        self.congestion.on_packet_sent(bytes)
    }

    pub(crate) fn acked(&mut self, bytes: u64) {
        self.congestion.on_ack(bytes);
    }

    #[cfg(test)]
    pub(crate) fn lost(&mut self, bytes: u64) {
        self.congestion.on_loss(bytes);
    }

    /// Decode and account one received stream packet. This is the transport
    /// bearer boundary: callers provide packet bytes, while stream IDs,
    /// offsets, packet ACK state, and receive credit remain transport-owned.
    pub(crate) fn receive_stream_packet<'a>(
        &mut self,
        input: &'a [u8],
    ) -> Result<(ShortHeader, StreamFrame<'a>), Error> {
        let (header, header_len) =
            ShortHeader::decode_with_expected(input, self.expected_packet_number())?;
        let local = self.local_cid.ok_or(Error::WrongConnectionId)?;
        if header.dcid != local {
            return Err(Error::WrongConnectionId);
        }
        let (frame, _) = decode_frame(&input[header_len..])?;
        let Frame::Stream(stream) = frame else {
            return Err(Error::Invalid);
        };
        self.receive
            .accept(stream.id, stream.offset, stream.data.len(), stream.fin)?;
        self.observe_packet(header.packet_number);
        Ok((header, stream))
    }

    /// Process every QUIC frame carried by one packet.
    ///
    /// This is an endpoint operation, not the bearer receive entry point and
    /// not a batch of bearer packets. The connection owner calls it after
    /// routing and admission.
    pub(crate) fn receive_packet_batch<'a>(
        &mut self,
        input: &'a [u8],
    ) -> Result<TransportFrames<'a>, Error> {
        if self.is_closed() {
            return Err(Error::Invalid);
        }
        let expected_packet_number = self.expected_packet_number();
        let (header, header_len) =
            ShortHeader::decode_with_expected(input, expected_packet_number)?;
        // Packet numbers are allowed to arrive out of order within the
        // sender's bounded retransmission window.  A lower-than-expected
        // number is not necessarily a duplicate: it may be a delayed packet
        // filling a selective-ACK gap.  Only a number already present in the
        // receive ACK ranges is a duplicate.
        let duplicate = self.received_packets.contains(header.packet_number);
        let local = self.local_cid.ok_or(Error::WrongConnectionId)?;
        if header.dcid != local {
            return Err(Error::WrongConnectionId);
        }
        // Decode the complete frame list before mutating endpoint state. This
        // keeps a malformed trailing frame from partially applying an ACK or
        // stream credit update. ACK/control frames may accompany multiple
        // application streams in one packet.
        let mut offset = header_len;
        if offset == input.len() {
            return Err(Error::Truncated);
        }
        let mut streams = [None; 8];
        let mut stream_count = 0usize;
        let mut has_ack = false;
        let mut ack_eliciting = false;
        let mut ack_frequency = None;
        let mut close_code = None;
        while offset < input.len() {
            let (frame, used) = decode_frame(&input[offset..])?;
            if used == 0 {
                return Err(Error::Invalid);
            }
            match frame {
                Frame::Ack { .. } | Frame::AckRanges { .. } => has_ack = true,
                Frame::Ping | Frame::MaxData(_) | Frame::MaxStreamData { .. } => {
                    ack_eliciting = true
                }
                Frame::AckFrequency {
                    sequence,
                    packet_threshold,
                    max_ack_delay_us,
                    reordering_threshold,
                } => {
                    ack_eliciting = true;
                    if ack_frequency.is_some() {
                        return Err(Error::Invalid);
                    }
                    ack_frequency = Some((
                        sequence,
                        packet_threshold,
                        max_ack_delay_us,
                        reordering_threshold,
                    ));
                }
                Frame::Stream(value) => {
                    ack_eliciting = true;
                    if stream_count >= streams.len() {
                        return Err(Error::Invalid);
                    }
                    streams[stream_count] = Some(value);
                    stream_count += 1;
                }
                Frame::Close { code } => {
                    if close_code.is_some() {
                        return Err(Error::Invalid);
                    }
                    close_code = Some(code);
                }
                _ => {}
            }
            offset += used;
        }
        if offset != input.len() {
            return Err(Error::Invalid);
        }
        if close_code.is_some() && stream_count != 0 {
            return Err(Error::Invalid);
        }
        if has_ack {
            self.receive_ack_packet(input)?;
        } else {
            // MAX_DATA/MAX_STREAM_DATA are independently meaningful control
            // frames. A receiver that releases storage after its ACK turn may
            // emit a credit-only packet while the sender is flow blocked.
            // Requiring an ACK in the same packet silently discarded that
            // only liveness edge.
            self.receive_flow_control_packet(input)?;
        }
        if let Some((sequence, packet_threshold, max_ack_delay_us, reordering_threshold)) =
            ack_frequency
        {
            self.apply_ack_frequency(
                sequence,
                packet_threshold,
                max_ack_delay_us,
                reordering_threshold,
            )?;
        }
        if let Some(code) = close_code {
            self.close_code = Some(code);
            self.control_pending = true;
            self.ack_pending = true;
            ack_eliciting = true;
        }
        self.stats.received_packets += 1;
        if duplicate {
            // A lost ACK causes the peer to retransmit the same packet
            // number. Re-ack it without delivering its stream bytes again.
            self.control_pending = true;
            self.ack_pending = true;
            self.stats.duplicate_packets += 1;
            self.stats.control_packets += 1;
            return Ok(TransportFrames {
                header,
                streams: [None; 8],
                stream_count: 0,
                duplicate: true,
            });
        }
        let Some(_) = streams[0] else {
            // ACK/control packets still consume receive packet numbers.
            // PING, ACK_FREQUENCY, and CLOSE are ack-eliciting. Pure ACK and
            // flow-control packets are only acknowledged when otherwise due.
            self.observe_packet(header.packet_number);
            self.stats.control_packets += 1;
            if ack_eliciting {
                self.ack_pending = true;
                self.ack_packets = self.ack_packets.saturating_add(1);
            }
            return Ok(TransportFrames {
                header,
                streams,
                stream_count: 0,
                duplicate: false,
            });
        };
        for stream in &mut streams[..stream_count] {
            if stream.is_some_and(|stream| self.receive.is_retired(stream.id)) {
                // A retransmission may use a fresh packet number after the
                // original ACK was lost. Preserve ACK/control processing for
                // this packet, but never recreate or redeliver the stream.
                *stream = None;
            }
        }
        for stream in streams[..stream_count].iter().flatten() {
            self.receive
                .accept(stream.id, stream.offset, stream.data.len(), stream.fin)?;
        }
        // A FIN may arrive after every byte was already consumed (for example
        // the separate empty FIN written by `finish_stream`). Delivery does
        // not report zero consumed bytes, so this is the only event on which
        // such a stream becomes complete and can release its slot.
        for stream in streams[..stream_count].iter().flatten() {
            if stream.fin {
                self.try_retire_stream(stream.id);
            }
        }
        // Selective ACK gaps are loss signals. Do not wait for the normal
        // coalescing threshold when a packet creates or fills a gap.
        if self.ack_reordering_threshold != 0 {
            if let Some(highest) = self.highest_received_packet {
                let reordering = if header.packet_number > highest {
                    header
                        .packet_number
                        .saturating_sub(highest.saturating_add(1))
                } else {
                    highest
                        .saturating_sub(header.packet_number)
                        .saturating_add(1)
                };
                if reordering >= self.ack_reordering_threshold {
                    self.control_pending = true;
                }
            }
        }
        self.observe_packet(header.packet_number);
        self.ack_pending = true;
        self.ack_packets = self.ack_packets.saturating_add(1);
        self.stats.stream_packets += 1;
        Ok(TransportFrames {
            header,
            streams,
            stream_count,
            duplicate: false,
        })
    }

    /// Compatibility view for a one-stream-at-a-time consumer. New shared
    /// association owners should use [`Self::receive_packet_batch`] so a
    /// coalesced response cannot strand another in-flight request.
    pub(crate) fn receive_packet<'a>(
        &mut self,
        input: &'a [u8],
    ) -> Result<TransportFrame<'a>, Error> {
        let packet = self.receive_packet_batch(input)?;
        if let Some(frame) = packet.streams().next() {
            Ok(TransportFrame::Stream {
                header: packet.header,
                frame,
            })
        } else {
            Ok(TransportFrame::Control)
        }
    }

    /// Process one bearer packet and emit any transport responses through a
    /// callback. Application code supplies only a stream callback and the
    /// bearer send callback; ACKs, duplicate handling, flow credit, and
    /// response scheduling remain entirely inside transport.
    #[cfg(test)]
    pub(crate) fn receive_with_callbacks<S, O>(
        &mut self,
        input: &[u8],
        out: &mut [u8],
        mut emit: O,
        mut on_stream: S,
    ) -> Result<TransportReceiveInfo, Error>
    where
        S: FnMut(StreamFrame<'_>) -> Result<usize, Error>,
        O: FnMut(&[u8]),
    {
        // Stream delivery can apply bounded application backpressure. Do not
        // let a rejection consume packet numbers, ACK ranges, or flow credit.
        // `sent_packets` is heap-backed on every target, so this deep clone
        // has identical transactional semantics on host and firmware without
        // materialising the packet ledger on the ESP task stack.
        let checkpoint = self.clone();
        let packet = self.receive_packet_batch(input)?;
        let duplicate = packet.duplicate;
        let mut stream = false;
        for frame in packet.streams() {
            stream = true;
            let consumed = match on_stream(frame) {
                Ok(consumed) => consumed,
                Err(error) => {
                    *self = checkpoint;
                    return Err(error);
                }
            };
            if consumed != 0 {
                self.stream_consumed_deferred(frame.id, consumed)?;
            } else {
                // A committed callback returns zero for an already delivered
                // retransmitted range or for bounded out-of-order delivery.
                // Both are reordering exceptions: promptly re-ACK the fresh
                // packet number so the sender does not wait for another PTO.
                self.control_pending = true;
            }
        }
        if let Some(used) = self.poll_transmit(out)? {
            emit(&out[..used]);
        }
        Ok(TransportReceiveInfo { stream, duplicate })
    }

    /// Receive one packet on an embedded hot path whose stream callback is
    /// terminal on failure.
    ///
    /// Unlike [`Self::receive_with_callbacks`], this does not checkpoint the
    /// whole endpoint before invoking `on_stream`.  That rollback guarantee
    /// is necessary for retryable application backpressure, but copying the
    /// complete retransmission ledger for every ordinary in-order packet is
    /// prohibitively expensive on an ESP.  A callback error here commits the
    /// transport packet; callers must close or otherwise terminate that
    /// application stream instead of asking the peer to retry it.
    /// Receive one packet and commit its stream callback, deferring any
    /// ACK/control output until the bearer explicitly calls
    /// [`Self::poll_transmit`].
    ///
    /// A packet bearer may drain several already-queued packets before it
    /// returns to its transmit side.  Keeping this operation receive-only
    /// lets that bearer coalesce their ACK and flow-credit updates into one
    /// control packet without exposing transport details to the consumer.
    #[cfg(test)]
    pub(crate) fn receive_with_committed_callbacks_deferred<S>(
        &mut self,
        input: &[u8],
        mut on_stream: S,
    ) -> Result<TransportReceiveInfo, Error>
    where
        S: FnMut(StreamFrame<'_>) -> Result<usize, Error>,
    {
        self.receive_with_committed_callback_dispositions(input, |frame| {
            on_stream(frame).map(|consumed| {
                if consumed == 0 {
                    CommittedStreamDisposition::Reack
                } else {
                    CommittedStreamDisposition::Consumed(consumed)
                }
            })
        })
    }

    /// Receive a committed callback with an explicit durable-credit outcome.
    ///
    /// This is the asynchronous-sink form of
    /// [`Self::receive_with_committed_callbacks_deferred`]. It keeps delayed
    /// application credit distinct from an immediate re-ACK request, so a
    /// receiver does not accidentally defeat its negotiated ACK frequency.
    #[cfg(test)]
    pub(crate) fn receive_with_committed_callback_dispositions<S>(
        &mut self,
        input: &[u8],
        mut on_stream: S,
    ) -> Result<TransportReceiveInfo, Error>
    where
        S: FnMut(StreamFrame<'_>) -> Result<CommittedStreamDisposition, Error>,
    {
        let packet = self.receive_packet_batch(input)?;
        let duplicate = packet.duplicate;
        let mut stream = false;
        for frame in packet.streams() {
            stream = true;
            match on_stream(frame)? {
                CommittedStreamDisposition::Consumed(consumed) => {
                    if consumed != 0 {
                        self.stream_consumed_deferred(frame.id, consumed)?;
                    }
                }
                CommittedStreamDisposition::Deferred => {}
                CommittedStreamDisposition::Reack => {
                    self.control_pending = true;
                }
            }
        }
        Ok(TransportReceiveInfo { stream, duplicate })
    }

    /// Receive one packet on an embedded hot path whose stream callback is
    /// terminal on failure, then emit any due ACK/control packet.
    #[cfg(test)]
    pub(crate) fn receive_with_committed_callbacks<S, O>(
        &mut self,
        input: &[u8],
        out: &mut [u8],
        mut emit: O,
        on_stream: S,
    ) -> Result<TransportReceiveInfo, Error>
    where
        S: FnMut(StreamFrame<'_>) -> Result<usize, Error>,
        O: FnMut(&[u8]),
    {
        let info = self.receive_with_committed_callbacks_deferred(input, on_stream)?;
        if let Some(used) = self.poll_transmit(out)? {
            emit(&out[..used]);
        }
        Ok(info)
    }
}

impl<const P: usize> EndpointState<P> {
    /// Validate all frame boundaries without applying state. Adapters that
    /// need to inspect a packet before dispatch can use this inexpensive
    /// transaction check.
    pub(crate) fn validate_packet(input: &[u8]) -> Result<(), Error> {
        let (_, mut offset) =
            ShortHeader::decode_prefix(input).map(|prefix| (prefix, prefix.header_len))?;
        if offset == input.len() {
            return Err(Error::Truncated);
        }
        while offset < input.len() {
            let (_, used) = decode_frame(&input[offset..])?;
            if used == 0 {
                return Err(Error::Invalid);
            }
            offset += used;
        }
        (offset == input.len()).then_some(()).ok_or(Error::Invalid)
    }

    /// Report bytes delivered to the application. This is the only receive
    /// accounting call a stream consumer makes; transport decides when the
    /// resulting ACK/window update is emitted by `poll_transmit`.
    pub(crate) fn stream_consumed(&mut self, stream_id: u64, bytes: usize) -> Result<(), Error> {
        self.stream_consumed_inner(stream_id, bytes, true)
    }

    /// Notify transport that its bearer receive wait elapsed. A pending
    /// delayed ACK must be reconsidered when the peer has reached the
    /// advertised flow-credit edge and therefore has no further data to send.
    /// The bearer never decides ACK policy: after updating time, it calls
    /// `poll_transmit`, which emits only when the negotiated threshold or
    /// delayed-ACK deadline is actually due.  Forcing `control_pending` here
    /// turns each short socket timeout into an immediate ACK and throttles
    /// otherwise continuous Wi-Fi traffic.
    pub(crate) fn on_bearer_timeout(&mut self) {}

    /// Report application bytes made durable while leaving control-packet
    /// scheduling to the bearer’s next [`Self::poll_transmit`] call.
    ///
    /// This is for bounded asynchronous sinks: they may accept stream bytes
    /// into private storage, emit an ACK for the received burst, and only
    /// return flow credit after that storage is released. The caller never
    /// constructs or interprets an ACK.
    pub(crate) fn stream_consumed_deferred(
        &mut self,
        stream_id: u64,
        bytes: usize,
    ) -> Result<(), Error> {
        self.stream_consumed_inner(stream_id, bytes, false)
    }

    /// Record durable consumption but deliberately withhold any MAX_* credit
    /// extension. A device-wide RAM admission controller calls
    /// [`Self::grant_receive_window`] later, once node-owned packet/relay memory
    /// is available. ACK state remains live so a sender can distinguish
    /// delivery from additional receive capacity.
    pub(crate) fn stream_consumed_without_credit(
        &mut self,
        stream_id: u64,
        bytes: usize,
    ) -> Result<(), Error> {
        self.receive.consume(stream_id, bytes as u64)?;
        self.ack_pending = true;
        Ok(())
    }

    /// Whether ordered receive delivery for this stream has completed.
    ///
    /// Full stream retirement may wait for the local sending half and its
    /// retransmission history. Delivery adapters use this earlier receive-side
    /// state to suppress late retransmissions without maintaining another list
    /// of completed stream IDs.
    pub(crate) fn stream_delivery_complete(&self, stream_id: u64) -> bool {
        self.receive.is_complete_or_retired(stream_id)
    }

    /// Promptly acknowledge a fresh packet number whose stream range was
    /// already delivered or is waiting behind an ordering gap. All stream
    /// adapters use this same edge so a retransmission cannot be held until
    /// an unrelated packet reaches the negotiated ACK threshold.
    pub(crate) fn request_stream_reack(&mut self) {
        self.control_pending = true;
        self.ack_pending = true;
    }

    /// Advertise an admitted effective receive window. `window_bytes` is a
    /// sliding-window size, not an unconditional increment; FlowControl only
    /// advances the absolute MAX_* values as consumed bytes make room. A
    /// smaller value therefore withholds replenishment and never revokes an
    /// already advertised peer credit.
    pub(crate) fn grant_receive_window(
        &mut self,
        stream_id: u64,
        window_bytes: u64,
    ) -> Result<(), Error> {
        // The endpoint's device/application profile is the authoritative
        // receive-memory ceiling. A handler may report a larger private
        // buffer (for example a manifest or file cache), but it must never
        // turn that allocation into extra QUIC credit.
        let connection_window = window_bytes.min(self.receive_growth_limits.max_data);
        let stream_window = window_bytes.min(self.receive_growth_limits.max_stream_data);
        self.receive.extend_connection_credit(connection_window);
        self.receive
            .extend_stream_credit(stream_id, stream_window)?;
        self.control_pending = true;
        self.queue_stream_credit(stream_id)?;
        Ok(())
    }

    /// Prepare an authenticated peer-initiated application stream so its
    /// receiver can publish an initial sliding window before first payload.
    #[cfg(test)]
    pub(crate) fn prepare_receive_stream(&mut self, stream_id: u64) -> Result<(), Error> {
        self.receive.prepare_remote_stream(stream_id)
    }

    pub(crate) fn prepare_local_bidi_receive(&mut self, stream_id: u64) -> Result<(), Error> {
        self.receive.prepare_local_bidi_receive(stream_id)
    }

    fn queue_stream_credit(&mut self, stream_id: u64) -> Result<(), Error> {
        // A MAX_* packet may be in flight while the application consumes more
        // ordered bytes.  Keep that one reliable publication intact and mark
        // the latest absolute limit dirty.  Clearing its marker here made an
        // event-driven receiver re-send MAX_* at every delayed-ACK tick until
        // the peer replied, creating a control backlog at ordinary Wi-Fi RTT.
        // Its ACK releases exactly one replacement carrying the newest value.
        self.credit_dirty |= self.credit_packet_number.is_some();
        self.credit_pending = true;
        if self
            .pending_stream_ids
            .iter()
            .any(|pending| *pending == stream_id)
        {
            return Ok(());
        }
        self.pending_stream_ids
            .try_reserve(1)
            .map_err(|_| Error::StreamLimit)?;
        self.pending_stream_ids.push(stream_id);
        Ok(())
    }

    fn stream_consumed_inner(
        &mut self,
        stream_id: u64,
        bytes: usize,
        force_control: bool,
    ) -> Result<(), Error> {
        self.receive.consume(stream_id, bytes as u64)?;
        // Keep the advertised sliding window equal to the connection's
        // negotiated receive budget. Recovery deliberately uses a smaller
        // budget than the generic host default so it can retain a reordered
        // sender burst. Never silently grow it to INITIAL_MAX_* here.
        self.receive
            .extend_connection_credit(self.receive_growth_limits.max_data);
        self.receive
            .extend_stream_credit(stream_id, self.receive_growth_limits.max_stream_data)?;
        if force_control {
            self.control_pending = true;
        }
        self.ack_pending = true;
        self.queue_stream_credit(stream_id)?;
        self.try_retire_stream(stream_id);
        Ok(())
    }

    fn try_retire_stream(&mut self, stream_id: u64) {
        if !self.send.is_finished(stream_id)
            || !self.receive.is_complete(stream_id)
            || self
                .sent_packets
                .iter()
                .flatten()
                .any(|packet| packet.stream_id == stream_id)
        {
            return;
        }
        let peer_initiated = self.receive.is_peer_initiated(stream_id);
        self.send.remove_stream(stream_id);
        self.receive.retire_stream(stream_id);
        self.pending_stream_ids
            .retain(|pending| *pending != stream_id);
        if peer_initiated && stream_id & 2 == 0 {
            self.retired_peer_bidi = self.retired_peer_bidi.saturating_add(1);
            let target = self
                .retired_peer_bidi
                .saturating_add(self.receive_growth_limits.max_streams_bidi);
            if target > self.receive.limits.max_streams_bidi {
                self.receive.limits.max_streams_bidi = target;
                self.max_streams_bidi_pending = true;
            }
            // An earlier credit packet may still be in flight. Its ACK must
            // not clear this newer MAX_STREAMS value before it is sent.
            self.credit_dirty |= self.credit_packet_number.is_some();
            self.credit_pending = true;
            self.control_pending = true;
        }
    }

    /// Let the transport decide whether an ACK/window packet is due. The
    /// bearer only sends the returned packet and never inspects its frames.
    pub(crate) fn poll_transmit(&mut self, out: &mut [u8]) -> Result<Option<usize>, Error> {
        let ack_threshold_due = self.ack_pending && self.ack_packets >= self.ack_frequency;
        let ack_timer_due = self.ack_pending
            && self.send_clock.saturating_sub(self.largest_received_at) >= self.max_ack_delay_us;
        let delayed_ack_due = ack_threshold_due || ack_timer_due;
        // Retry a lost MAX_* control packet on the endpoint's adaptive PTO.
        // This is intentionally independent of the bearer: a sender may be
        // flow-blocked and have no stream packet left to provoke another ACK.
        let credit_retry_due = self.credit_pending
            && self.send_clock.saturating_sub(self.last_ack_time)
                >= if self.credit_packet_number.is_some() {
                    self.pto_timeout().saturating_mul(
                        1u64 << self.credit_retry_backoff.min(MAX_PTO_BACKOFF_EXPONENT),
                    )
                } else {
                    self.max_ack_delay_us
                };
        let send_ack = self.control_pending || delayed_ack_due || credit_retry_due;
        let ack_frequency = self.pending_ack_frequency;
        if !send_ack && ack_frequency.is_none() {
            return Ok(None);
        }
        let dcid = self.peer_cid.ok_or(Error::WrongConnectionId)?;
        let mut p = ShortHeader {
            flags: FLAG_FIXED,
            dcid,
            packet_number: self.next_packet_number,
            packet_number_len: self.next_packet_number_len(),
        }
        .encode(out)?;
        if send_ack {
            let immediate_ack = self.control_pending;
            let largest = self.largest_received().ok_or(Error::Invalid)?;
            p += Frame::AckRanges {
                largest,
                delay: self
                    .send_clock
                    .saturating_sub(self.largest_received_at)
                    .min(self.max_ack_delay_us),
                ranges: self.received_packets,
            }
            .encode(&mut out[p..])?;
            // ACK-only packets must remain non-ack-eliciting.  In
            // particular, continuously restating the current MAX_* values
            // turns an ordinary ACK into a peer ACK/control packet, causing
            // an ACK-of-ACK loop on a quiet UDP association.  A stream
            // consumer queues these frames only when it actually publishes
            // new receive capacity through `stream_consumed` or
            // `grant_receive_window`.
            if self.credit_pending {
                p += Frame::MaxData(self.receive.connection.max_data).encode(&mut out[p..])?;
                if self.max_streams_bidi_pending {
                    p += Frame::MaxStreamsBidi(self.receive.limits.max_streams_bidi)
                        .encode(&mut out[p..])?;
                }
                for &stream_id in &self.pending_stream_ids {
                    let max = self
                        .receive
                        .stream_max_data(stream_id)
                        .unwrap_or(self.receive.limits.max_stream_data);
                    p += Frame::MaxStreamData { id: stream_id, max }.encode(&mut out[p..])?;
                }
            }
            self.control_pending = false;
            self.ack_pending = false;
            self.ack_packets = 0;
            self.last_ack_time = self.send_clock;
            let retrying_credit = self.credit_pending && self.credit_packet_number.is_some();
            if self.credit_pending {
                self.credit_packet_number = Some(self.next_packet_number);
                self.credit_dirty = false;
                if retrying_credit {
                    self.credit_retry_backoff = self
                        .credit_retry_backoff
                        .saturating_add(1)
                        .min(MAX_PTO_BACKOFF_EXPONENT);
                }
            }
            self.stats.ack_packets += 1;
            if immediate_ack {
                self.stats.ack_immediate_packets += 1;
            } else if ack_threshold_due {
                self.stats.ack_threshold_packets += 1;
            } else if ack_timer_due {
                self.stats.ack_timer_packets += 1;
            }
        }
        if let Some((sequence, packet_threshold, max_ack_delay_us, reordering_threshold)) =
            ack_frequency
        {
            p += Frame::AckFrequency {
                sequence,
                packet_threshold,
                max_ack_delay_us,
                reordering_threshold,
            }
            .encode(&mut out[p..])?;
            self.pending_ack_frequency = None;
            self.stats.ack_frequency_sent = self.stats.ack_frequency_sent.saturating_add(1);
        }
        self.stats.sent_packets += 1;
        self.stats.sent_control_packets += 1;
        self.next_packet_number = self
            .next_packet_number
            .checked_add(1)
            .ok_or(Error::PacketNumberExhausted)?;
        Ok(Some(p))
    }

    /// Consume a peer ACK/flow-control packet for a bearer that sends one
    /// packet at a time. The bearer supplies the acknowledged packet bytes;
    /// packet history and flow-credit updates remain transport-owned.
    fn receive_ack_packet(&mut self, input: &[u8]) -> Result<(), Error> {
        let (_, header_len) = ShortHeader::decode(input)?;
        let mut offset = header_len;
        let mut acknowledged = AckRangeSet::new();
        let mut reported_ack_delay = 0u64;
        while offset < input.len() {
            let (frame, used) = decode_frame(&input[offset..])?;
            if used == 0 {
                return Err(Error::Invalid);
            }
            match frame {
                Frame::Ack { largest, delay } => {
                    acknowledged.insert(largest);
                    reported_ack_delay = delay;
                }
                Frame::AckRanges { ranges, delay, .. } => {
                    reported_ack_delay = delay;
                    for i in 0..ranges.len() {
                        if let Some(range) = ranges.get(i) {
                            acknowledged.insert_range(range);
                        }
                    }
                }
                Frame::MaxData(max) => self.send.extend_connection(max),
                // Credit for a retired stream can arrive late (reordered or
                // retried control packet). It is obsolete, not an error:
                // rejecting it would also discard the ACK in this packet.
                Frame::MaxStreamData { id, .. } if self.receive.is_retired(id) => {}
                Frame::MaxStreamData { id, max } => self.send.extend_stream(id, max)?,
                Frame::MaxStreamsBidi(max) => {
                    self.peer_max_streams_bidi = self.peer_max_streams_bidi.max(max)
                }
                Frame::MaxStreamsUni(max) => {
                    self.peer_max_streams_uni = self.peer_max_streams_uni.max(max)
                }
                _ => {}
            }
            offset += used;
        }
        if acknowledged.len() == 0 {
            return Err(Error::Invalid);
        }
        self.peer_ack_ranges = acknowledged;
        if self
            .credit_packet_number
            .is_some_and(|packet_number| acknowledged.contains(packet_number))
        {
            self.credit_packet_number = None;
            self.credit_retry_backoff = 0;
            if self.credit_dirty {
                // Preserve the deduplicated stream set and publish the
                // latest consumed offsets on the next transport turn.
                self.credit_pending = true;
                self.control_pending = true;
            } else {
                self.credit_pending = false;
                self.pending_stream_ids.clear();
                self.max_streams_bidi_pending = false;
            }
        }
        self.largest_acked_by_peer = acknowledged.get(0).map(|range| range.end);
        let largest_acked = acknowledged.get(0).map(|range| range.end);
        let mut rtt_sample = None;
        let mut acknowledged_fins = Vec::new();
        let mut newly_acked = false;
        for slot in &mut self.sent_packets {
            if let Some(sent) = *slot {
                if sent.acknowledged_by(&acknowledged) {
                    if sent.fin && !acknowledged_fins.contains(&sent.stream_id) {
                        acknowledged_fins.push(sent.stream_id);
                    }
                    if largest_acked.is_some_and(|packet| sent.packet_number == packet) {
                        rtt_sample = Some(self.send_clock.saturating_sub(sent.sent_at));
                    }
                    self.congestion.on_ack(sent.bytes);
                    *slot = None;
                    newly_acked = true;
                }
            }
        }
        for stream_id in acknowledged_fins {
            self.try_retire_stream(stream_id);
        }
        if newly_acked {
            // Any forward acknowledgement ends the PTO episode. The next
            // genuine timeout starts from the base PTO again.
            self.last_pto_probe_at = None;
            self.pto_backoff = 0;
        }
        if let Some(sample) = rtt_sample {
            let ack_delay = reported_ack_delay.min(self.peer_max_ack_delay_us);
            // Never reduce a sample below the observed minimum RTT; this is
            // QUIC's safeguard against an implausible or stale ACK delay.
            let adjusted = match self.rtt.minimum() {
                Some(minimum) if sample > minimum.saturating_add(ack_delay) => {
                    sample.saturating_sub(ack_delay)
                }
                _ => sample,
            };
            self.rtt.update(adjusted);
        }
        // Packet-threshold loss is defined over packet numbers, not logical
        // stream ranges. A retransmission has its own fresh packet number, so
        // acknowledging it is valid forward progress and makes sufficiently
        // older outstanding packets eligible for immediate repair. The
        // logical packet number retained in SentPacket separately prevents a
        // retransmitted range from repeatedly reducing congestion state.
        self.detect_ack_losses(largest_acked);
        Ok(())
    }

    fn receive_flow_control_packet(&mut self, input: &[u8]) -> Result<(), Error> {
        let (_, header_len) = ShortHeader::decode(input)?;
        let mut offset = header_len;
        while offset < input.len() {
            let (frame, used) = decode_frame(&input[offset..])?;
            if used == 0 {
                return Err(Error::Invalid);
            }
            match frame {
                Frame::MaxData(max) => self.send.extend_connection(max),
                // Credit for a retired stream can arrive late (reordered or
                // retried control packet). It is obsolete, not an error:
                // rejecting it would also discard the ACK in this packet.
                Frame::MaxStreamData { id, .. } if self.receive.is_retired(id) => {}
                Frame::MaxStreamData { id, max } => self.send.extend_stream(id, max)?,
                Frame::MaxStreamsBidi(max) => {
                    self.peer_max_streams_bidi = self.peer_max_streams_bidi.max(max)
                }
                Frame::MaxStreamsUni(max) => {
                    self.peer_max_streams_uni = self.peer_max_streams_uni.max(max)
                }
                _ => {}
            }
            offset += used;
        }
        Ok(())
    }

    /// Encode one stream packet using the endpoint's shared packet-number,
    /// flow-credit, and congestion state. The caller owns packet storage and
    /// retains the returned packet number for loss/ACK bookkeeping.
    pub(crate) fn encode_stream_packet(
        &mut self,
        dcid: ConnectionId,
        stream_id: u64,
        offset: u64,
        fin: bool,
        data: &[u8],
        out: &mut [u8],
    ) -> Result<(usize, u32), Error> {
        if let Some(peer) = self.peer_cid {
            if dcid != peer {
                return Err(Error::WrongConnectionId);
            }
        }
        if data.len() > P {
            return Err(Error::RetransmissionTooLarge);
        }
        if self.history_len() >= self.peer_max_in_flight_packets {
            // Receiver-advertised packet budget. This is intentionally
            // independent of byte cwnd: small packets must not translate
            // a 14 KiB window into a radio burst the peer cannot queue.
            return Err(Error::Blocked);
        }
        let header = ShortHeader {
            flags: FLAG_FIXED,
            dcid,
            packet_number: self.next_packet_number,
            packet_number_len: self.next_packet_number_len(),
        };
        let mut p = header.encode(out)?;
        p += Frame::Stream(StreamFrame {
            id: stream_id,
            offset,
            fin,
            data,
        })
        .encode(&mut out[p..])?;
        if !self
            .sent_packets
            .iter()
            .take(self.history_limit)
            .any(|slot| slot.is_none())
        {
            return Err(Error::HistoryFull);
        }
        if self.retained_payload_bytes().saturating_add(data.len())
            > self.retransmission_capacity_bytes()
        {
            return Err(Error::HistoryFull);
        }
        if !self.congestion.can_send(p as u64) {
            return Err(Error::Blocked);
        }
        self.send.reserve(stream_id, offset, data.len())?;
        if !self.congestion.on_packet_sent(p as u64) {
            return Err(Error::Blocked);
        }
        let packet_number = self.next_packet_number;
        self.next_packet_number = self
            .next_packet_number
            .checked_add(1)
            .ok_or(Error::PacketNumberExhausted)?;
        let slot = self
            .sent_packets
            .iter_mut()
            .take(self.history_limit)
            .find(|slot| slot.is_none())
            .ok_or(Error::HistoryFull)?;
        *slot = Some(SentPacket {
            packet_number,
            prior_packet_numbers: [0; 16],
            prior_packet_count: 0,
            bytes: p as u64,
            stream_id,
            offset,
            fin,
            payload_len: data.len(),
            payload: {
                let mut payload = [0u8; P];
                payload[..data.len()].copy_from_slice(data);
                payload
            },
            sent_at: self.send_clock,
            lost: false,
        });
        if fin {
            self.send.finish_stream(stream_id)?;
        }
        self.stats.sent_packets += 1;
        self.stats.sent_stream_packets += 1;
        Ok((p, packet_number))
    }

    /// Encode a small ack-eliciting probe on an established connection.
    /// Probes carry no application bytes or stream credit; multipath adapters
    /// use them to refresh a bearer measurement after temporary loss. Their
    /// packet number still belongs to the one shared connection sequence.
    pub(crate) fn encode_probe_packet(
        &mut self,
        dcid: ConnectionId,
        out: &mut [u8],
    ) -> Result<(usize, u32), Error> {
        if self.peer_cid.is_some_and(|peer| peer != dcid) {
            return Err(Error::WrongConnectionId);
        }
        let packet_number = self.next_packet_number;
        let header = ShortHeader {
            flags: FLAG_FIXED,
            dcid,
            packet_number,
            packet_number_len: packet_number_len(packet_number, self.largest_received()),
        };
        let header_len = header.encode(out)?;
        let frame_len = Frame::Ping.encode(&mut out[header_len..])?;
        self.next_packet_number = self
            .next_packet_number
            .checked_add(1)
            .ok_or(Error::PacketNumberExhausted)?;
        Ok((header_len + frame_len, packet_number))
    }

    /// Encode the largest fresh prefix that currently fits peer flow credit.
    /// This is the sender-side analogue of ordered partial consumption: a
    /// stream producer supplies ordinary bytes, while QUIC-lite chooses the
    /// packet boundary and retains all credit/packet accounting.
    #[cfg(test)]
    pub(crate) fn encode_stream_packet_fitting(
        &mut self,
        dcid: ConnectionId,
        stream_id: u64,
        offset: u64,
        fin: bool,
        data: &[u8],
        out: &mut [u8],
    ) -> Result<(usize, u32, usize), Error> {
        let length = data.len().min(self.send.available_at(stream_id, offset)?);
        if length == 0 {
            return Err(Error::FlowControl);
        }
        let (used, packet_number) = self.encode_stream_packet(
            dcid,
            stream_id,
            offset,
            fin && length == data.len(),
            &data[..length],
            out,
        )?;
        Ok((used, packet_number, length))
    }

    /// Re-encode one outstanding stream frame with a fresh packet number.
    ///
    /// Packet numbers are never reused within a connection. A retransmission
    /// carries the same stream range, which the receive stream reassembler
    /// deduplicates, but it is a new transport packet and must receive a new
    /// number.
    pub(crate) fn retransmit_stream_packet(
        &mut self,
        packet_number: u32,
        out: &mut [u8],
    ) -> Result<Option<(usize, u32)>, Error> {
        let Some(index) = self.sent_packets.iter().position(|slot| {
            slot.map(|packet| packet.packet_number == packet_number)
                .unwrap_or(false)
        }) else {
            return Ok(None);
        };
        let peer_cid = self.peer_cid.ok_or(Error::WrongConnectionId)?;
        let sent = self.sent_packets[index].take().ok_or(Error::Invalid)?;
        let previous_congestion = self.congestion;
        // Loss detection already removed marked packets from bytes in flight
        // and entered NewReno recovery. A PTO is a probe, not a declaration
        // of congestion. Retransmission therefore only accounts the new copy.
        if !sent.lost {
            self.congestion.remove_in_flight(sent.bytes);
        }
        let payload = &sent.payload[..sent.payload_len];
        let packet_number = self.next_packet_number;
        let header = ShortHeader {
            flags: FLAG_FIXED,
            dcid: peer_cid,
            packet_number,
            packet_number_len: self.next_packet_number_len(),
        };
        let mut used = match header.encode(out) {
            Ok(used) => used,
            Err(error) => {
                self.congestion = previous_congestion;
                self.sent_packets[index] = Some(sent);
                return Err(error);
            }
        };
        used = match Frame::Stream(StreamFrame {
            id: sent.stream_id,
            offset: sent.offset,
            fin: sent.fin,
            data: payload,
        })
        .encode(&mut out[used..])
        {
            Ok(used_frame) => used + used_frame,
            Err(error) => {
                self.congestion = previous_congestion;
                self.sent_packets[index] = Some(sent);
                return Err(error);
            }
        };
        self.congestion.on_retransmission_sent(used as u64);
        self.next_packet_number = self
            .next_packet_number
            .checked_add(1)
            .ok_or(Error::PacketNumberExhausted)?;
        let mut replacement = SentPacket {
            packet_number,
            bytes: used as u64,
            sent_at: self.send_clock,
            ..sent
        };
        replacement.add_prior_packet_number(sent.packet_number);
        replacement.lost = false;
        self.sent_packets[index] = Some(replacement);
        self.stats.sent_packets += 1;
        self.stats.sent_stream_packets += 1;
        self.stats.retransmitted_packets += 1;
        Ok(Some((used, packet_number)))
    }

    pub(crate) fn retransmit_due(
        &mut self,
        now: u64,
        pto: u64,
        out: &mut [u8],
    ) -> Result<Option<(usize, u32)>, Error> {
        if let Some(retransmission) = self.retransmit_marked_loss(out)? {
            return Ok(Some(retransmission));
        }
        self.retransmit_pto_probe(now, pto, out)
    }

    /// Retransmit one packet already declared lost by selective ACK or time
    /// threshold detection. Bearers may call this repeatedly (with their own
    /// bounded burst cap) before scheduling fresh stream bytes.
    pub(crate) fn retransmit_marked_loss(
        &mut self,
        out: &mut [u8],
    ) -> Result<Option<(usize, u32)>, Error> {
        let candidate = self
            .sent_packets
            .iter()
            .flatten()
            .filter(|packet| packet.lost)
            .min_by_key(|packet| packet.sent_at)
            .map(|packet| packet.packet_number);
        match candidate {
            Some(packet_number) => {
                let retransmission = self.retransmit_stream_packet(packet_number, out)?;
                if retransmission.is_some() {
                    self.stats.loss_retransmitted_packets =
                        self.stats.loss_retransmitted_packets.saturating_add(1);
                }
                Ok(retransmission)
            }
            None => Ok(None),
        }
    }

    /// Send at most one PTO probe when no packet has already been declared
    /// lost. Multiple PTO probes in one scheduler pass amplify a timeout into
    /// a burst; declared loss repair is handled by `retransmit_marked_loss`.
    pub(crate) fn retransmit_pto_probe(
        &mut self,
        now: u64,
        pto: u64,
        out: &mut [u8],
    ) -> Result<Option<(usize, u32)>, Error> {
        let multiplier = 1u64 << self.pto_backoff.min(MAX_PTO_BACKOFF_EXPONENT);
        let probe_interval = pto.saturating_mul(multiplier);
        if self
            .last_pto_probe_at
            .is_some_and(|last| now.saturating_sub(last) < probe_interval)
        {
            return Ok(None);
        }
        let candidate = self
            .sent_packets
            .iter()
            .flatten()
            .filter(|packet| !packet.lost && now.saturating_sub(packet.sent_at) >= pto)
            .min_by_key(|packet| packet.sent_at)
            .map(|packet| packet.packet_number);
        match candidate {
            Some(packet_number) => {
                let retransmission = self.retransmit_stream_packet(packet_number, out)?;
                if retransmission.is_some() {
                    self.stats.pto_retransmitted_packets =
                        self.stats.pto_retransmitted_packets.saturating_add(1);
                    self.last_pto_probe_at = Some(now);
                    self.pto_backoff = self
                        .pto_backoff
                        .saturating_add(1)
                        .min(MAX_PTO_BACKOFF_EXPONENT);
                }
                Ok(retransmission)
            }
            None => Ok(None),
        }
    }

    /// Mark packets inferred lost from selective ACK gaps before waiting for
    /// PTO. The bearer simply polls normal transport output for the resulting
    /// fresh-number retransmission.
    fn detect_ack_losses(&mut self, largest_acked: Option<u32>) {
        const PACKET_THRESHOLD: u32 = 3;
        let Some(largest_acked) = largest_acked else {
            return;
        };
        let base_rtt = self
            .rtt
            .latest()
            .or(self.rtt.smoothed())
            .unwrap_or(25_000)
            .max(1);
        // RFC 9002's 9/8 time threshold, rounded up in the microsecond clock.
        // `base_rtt` is ACK-delay compensated, while an outstanding sibling
        // packet may still be waiting for the peer's negotiated delayed ACK.
        // Include that association parameter here: otherwise a normal
        // delayed ACK makes a same-burst packet appear lost and collapses the
        // congestion window into stop-and-wait pacing.
        let time_threshold =
            base_rtt.saturating_mul(9).saturating_add(7) / 8 + self.peer_max_ack_delay_us;
        let mut lost_bytes = 0u64;
        let mut largest_lost: Option<u32> = None;
        for slot in &mut self.sent_packets {
            let Some(packet) = slot.as_mut() else {
                continue;
            };
            if packet.lost || packet.packet_number > largest_acked {
                continue;
            }
            let packet_threshold_lost =
                packet.packet_number.saturating_add(PACKET_THRESHOLD) <= largest_acked;
            let time_threshold_lost =
                self.send_clock.saturating_sub(packet.sent_at) >= time_threshold;
            if packet_threshold_lost || time_threshold_lost {
                if packet_threshold_lost {
                    self.stats.loss_packet_threshold_packets =
                        self.stats.loss_packet_threshold_packets.saturating_add(1);
                } else {
                    self.stats.loss_time_threshold_packets =
                        self.stats.loss_time_threshold_packets.saturating_add(1);
                }
                packet.lost = true;
                lost_bytes = lost_bytes.saturating_add(packet.bytes);
                largest_lost = Some(
                    largest_lost
                        .map(|current| current.max(packet.logical_packet_number()))
                        .unwrap_or_else(|| packet.logical_packet_number()),
                );
            }
        }
        if let Some(largest_lost) = largest_lost {
            self.stats.loss_events = self.stats.loss_events.saturating_add(1);
            self.congestion.on_packet_lost(
                lost_bytes,
                largest_lost,
                self.next_packet_number.saturating_sub(1),
            );
        }
    }

    /// Remove a packet that loss detection has conclusively declared lost.
    /// This is separate from retransmission so a bearer can account a packet
    /// as lost even when its replacement is queued by a different scheduler.
    pub(crate) fn mark_lost(&mut self, packet_number: u32) -> bool {
        let Some(index) = self.sent_packets.iter().position(|slot| {
            slot.map(|packet| packet.packet_number == packet_number)
                .unwrap_or(false)
        }) else {
            return false;
        };
        let Some(packet) = self.sent_packets[index].take() else {
            return false;
        };
        self.congestion.on_packet_lost(
            packet.bytes,
            // This public loss entry point is also used by bearers that
            // retire a retained packet without immediately encoding its
            // replacement.  Preserve the logical stream range's first
            // packet number here just as retransmit_stream_packet and
            // selective-ACK loss detection do: a fresh-number retry lost in
            // the same recovery epoch must not halve cwnd a second time.
            packet.logical_packet_number(),
            self.next_packet_number.saturating_sub(1),
        );
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::VecDeque;
    use std::vec;
    use std::vec::Vec;

    #[test]
    fn deterministic_parser_fuzz_smoke_never_panics_or_mutates_on_rejection() {
        let mut state = EndpointState::<128>::new(Role::Server, ConnectionLimits::default(), 1200);
        let local = ConnectionId::new(0x1234).unwrap();
        let peer = ConnectionId::new(0x5678).unwrap();
        state.install_connection_ids(local, peer).unwrap();
        let mut seed = 0x8f31_2a77_u64;
        for iteration in 0..20_000u32 {
            // Deterministic xorshift input makes failures reproducible without
            // bringing a property-testing dependency into the no_std crate.
            seed ^= seed << 7;
            seed ^= seed >> 9;
            seed ^= seed << 8;
            let length = ((seed as usize) % 96).max(1);
            let mut bytes = vec![0u8; length];
            for (index, byte) in bytes.iter_mut().enumerate() {
                *byte = seed
                    .rotate_left((index % 63) as u32)
                    .wrapping_add(iteration as u64) as u8;
            }
            let before = (
                state.next_packet_number,
                state.received_packet_count(),
                state.history_len(),
                state.bytes_in_flight(),
                state.local_connection_id(),
                state.peer_connection_id(),
            );
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _ = ShortHeader::decode(&bytes);
                let _ = decode_frame(&bytes);
                let _ = EndpointState::<128>::validate_packet(&bytes);
                state.receive_packet(&bytes)
            }));
            assert!(result.is_ok(), "parser panicked at seed={seed:#x}");
            if let Ok(Err(_)) = result {
                let after = (
                    state.next_packet_number,
                    state.received_packet_count(),
                    state.history_len(),
                    state.bytes_in_flight(),
                    state.local_connection_id(),
                    state.peer_connection_id(),
                );
                assert_eq!(
                    before, after,
                    "rejected packet mutated state at seed={seed:#x}"
                );
            }
        }
    }

    #[test]
    fn deterministic_valid_headers_reencode_canonically() {
        for packet_number in [0, 1, 0x7f, 0x4000, u32::MAX] {
            for cid_value in [1, 0x3f, 0x40, 0x4000, 0x1234_5678] {
                let header = ShortHeader {
                    flags: FLAG_FIXED,
                    dcid: ConnectionId::new(cid_value).unwrap(),
                    packet_number,
                    packet_number_len: 4,
                };
                let mut encoded = [0u8; 64];
                let used = header.encode(&mut encoded).unwrap();
                let (decoded, decoded_used) = ShortHeader::decode(&encoded[..used]).unwrap();
                assert_eq!(decoded_used, used);
                let mut canonical = [0u8; 64];
                assert_eq!(decoded.encode(&mut canonical).unwrap(), used);
                assert_eq!(&canonical[..used], &encoded[..used]);
            }
        }
    }

    #[test]
    fn connection_id_lengths_round_trip() {
        for value in [
            0,
            0x7f,
            0x80,
            0x1fff,
            0x2000,
            0x1fff_ffff,
            0x2000_0000,
            (1u64 << 61) - 1,
        ] {
            let id = ConnectionId::new(value).unwrap();
            let mut b = [0; 8];
            let n = id.encode(&mut b).unwrap();
            assert_eq!(n, id.encoded_len());
            assert_eq!(ConnectionId::decode(&b[..n]).unwrap(), (id, n));
        }
        assert!(ConnectionId::new(1u64 << 61).is_none());
    }

    #[test]
    fn connection_id_uses_structured_length_classes() {
        let cases = [
            (0x7f, &[0x7f][..]),
            (0x80, &[0x80, 0x80][..]),
            (0x1fff, &[0x9f, 0xff][..]),
            (0x2000, &[0xa0, 0x00, 0x20, 0x00][..]),
            (0x1fff_ffff, &[0xbf, 0xff, 0xff, 0xff][..]),
            (
                0x2000_0000,
                &[0xc0, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00][..],
            ),
        ];
        for (value, expected) in cases {
            let mut encoded = [0u8; 8];
            let used = ConnectionId::new(value)
                .unwrap()
                .encode(&mut encoded)
                .unwrap();
            assert_eq!(&encoded[..used], expected);
        }
    }

    #[test]
    fn connection_id_rejects_reserved_and_noncanonical_classes() {
        assert_eq!(
            ConnectionId::decode(&[0xe0, 0, 0, 0, 0, 0, 0, 0]),
            Err(Error::Invalid)
        );
        assert_eq!(ConnectionId::decode(&[0x80, 0x01]), Err(Error::Invalid));
        assert_eq!(
            ConnectionId::decode(&[0xa0, 0, 0, 0x7f]),
            Err(Error::Invalid)
        );
        assert_eq!(
            ConnectionId::decode(&[0xc0, 0, 0, 0, 0, 0, 0, 0x80]),
            Err(Error::Invalid)
        );
    }

    #[test]
    fn relay_local_cids_encode_class_dependent_hop_positions() {
        let nearby = ConnectionId::relay_local(2, 1).unwrap();
        assert_eq!(nearby.value(), 8);
        assert_eq!(nearby.encoded_len(), 1);
        assert_eq!(nearby.relay_parts(), Some((2, 1)));

        let nearby_last = ConnectionId::relay_local(31, 4).unwrap();
        assert_eq!(nearby_last.value(), 0x7f);
        assert_eq!(nearby_last.encoded_len(), 1);
        assert_eq!(nearby_last.relay_parts(), Some((31, 4)));

        let long = ConnectionId::relay_local(32, 1).unwrap();
        assert_eq!(long.value(), 0x200);
        assert_eq!(long.encoded_len(), 2);
        assert_eq!(long.relay_parts(), Some((32, 1)));

        let long_last = ConnectionId::relay_local(511, 16).unwrap();
        assert_eq!(long_last.value(), 0x1fff);
        assert_eq!(long_last.encoded_len(), 2);
        assert_eq!(long_last.relay_parts(), Some((511, 16)));

        assert!(ConnectionId::relay_local(1, 1).is_none());
        assert!(ConnectionId::relay_local(2, 0).is_none());
        assert!(ConnectionId::relay_local(2, 17).is_none());
        assert_eq!(ConnectionId::new(0).unwrap().relay_parts(), None);
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
    fn oversized_frame_lengths_and_ack_range_counts_are_rejected_without_panicking() {
        fn append(value: u64, packet: &mut [u8], used: &mut usize) {
            *used += put_varint(value, &mut packet[*used..]).unwrap();
        }

        let huge = (1_u64 << 62) - 1;
        let mut packet = [0_u8; 40];
        let mut used = 0;
        append(FRAME_CONNECTION_CLOSE, &mut packet, &mut used);
        append(0, &mut packet, &mut used);
        append(huge, &mut packet, &mut used);
        assert!(matches!(
            decode_frame(&packet[..used]),
            Err(Error::Invalid | Error::Truncated)
        ));

        used = 0;
        append(FRAME_STREAM_BASE | 0x02, &mut packet, &mut used);
        append(0, &mut packet, &mut used);
        append(huge, &mut packet, &mut used);
        assert!(matches!(
            decode_frame(&packet[..used]),
            Err(Error::Invalid | Error::Truncated)
        ));

        used = 0;
        append(FRAME_ACK, &mut packet, &mut used);
        append(0, &mut packet, &mut used);
        append(0, &mut packet, &mut used);
        append(huge, &mut packet, &mut used);
        append(0, &mut packet, &mut used);
        assert_eq!(decode_frame(&packet[..used]), Err(Error::Invalid));
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
    fn bounded_ack_ranges_keep_newest_packet_ranges() {
        let mut ranges = AckRanges::<2>::new();
        ranges.insert(10);
        ranges.insert(8);
        assert!(ranges.contains(10));
        assert!(ranges.contains(8));

        // Loss/reordering can create more holes than fit into one ACK. The
        // peer must still learn about the newest received packet rather than
        // retransmitting it forever because the oldest range consumed the
        // fixed wire budget.
        ranges.insert(12);
        assert!(ranges.contains(12));
        assert!(ranges.contains(10));
        assert!(!ranges.contains(8));
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
    fn quic_ack_range_with_contiguous_packets_preserves_first_range() {
        let mut ranges = AckRangeSet::new();
        for packet_number in [10, 9, 8] {
            ranges.insert(packet_number);
        }
        let frame = Frame::AckRanges {
            largest: 10,
            delay: 0,
            ranges,
        };
        let mut encoded = [0u8; 64];
        let used = frame.encode(&mut encoded).unwrap();
        let (decoded, _) = decode_frame(&encoded[..used]).unwrap();
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
    fn credit_only_packet_advances_a_flow_blocked_sender() {
        let client_cid = ConnectionId::new(0x701).unwrap();
        let server_cid = ConnectionId::new(0x702).unwrap();
        let mut client = EndpointState::<256>::new(Role::Client, ConnectionLimits::default(), 256);
        client
            .install_connection_ids(client_cid, server_cid)
            .unwrap();
        client.set_initial_peer_credit(100, 100).unwrap();
        client.open_send_stream(8, 100).unwrap();

        let mut packet = [0u8; 128];
        let header = ShortHeader {
            flags: FLAG_FIXED,
            dcid: client_cid,
            packet_number: 1,
            packet_number_len: 1,
        };
        let mut used = header.encode(&mut packet).unwrap();
        used += Frame::MaxData(500).encode(&mut packet[used..]).unwrap();
        used += Frame::MaxStreamData { id: 8, max: 400 }
            .encode(&mut packet[used..])
            .unwrap();
        client.receive_packet_batch(&packet[..used]).unwrap();
        assert_eq!(client.peer_send_credit(8), Some((500, 400)));
    }

    #[test]
    fn connection_and_stream_credit_are_bounded() {
        let limits = ConnectionLimits {
            max_data: 8,
            max_stream_data: 8,
            max_streams_bidi: 1,
            max_streams_uni: 1,
        };
        let mut c = ConnectionState::new(Role::Server, limits);
        assert!(c.accept(0, 0, 5, false).is_ok());
        assert_eq!(c.accept(0, 5, 4, false), Err(Error::FlowControl));
        assert!(c.consume(0, 5).is_ok());
    }

    #[test]
    fn consumed_stream_keeps_the_negotiated_receive_budget() {
        const RECEIVE_WINDOW: u64 = 32 * 1024;
        let limits = ConnectionLimits {
            max_data: RECEIVE_WINDOW,
            max_stream_data: RECEIVE_WINDOW,
            max_streams_bidi: 1,
            max_streams_uni: 1,
        };
        let mut endpoint =
            EndpointState::<DEFAULT_MAX_PACKET_SIZE>::new(Role::Client, limits, 1400);
        endpoint.receive.accept(3, 0, 1200, false).unwrap();
        endpoint.stream_consumed(3, 1200).unwrap();
        assert_eq!(endpoint.receive.connection.max_data, 1200 + RECEIVE_WINDOW);
        assert_eq!(
            endpoint.receive.stream_max_data(3),
            Some(1200 + RECEIVE_WINDOW)
        );
    }

    #[test]
    fn handler_grant_cannot_exceed_the_device_receive_window() {
        let limits = ConnectionLimits::with_receive_window(1024);
        let mut endpoint =
            EndpointState::<DEFAULT_MAX_PACKET_SIZE>::new(Role::Client, limits, 1200);
        endpoint.receive.accept(3, 0, 512, false).unwrap();
        endpoint.stream_consumed_without_credit(3, 512).unwrap();

        // A manifest/file handler may have a much larger private buffer, but
        // it cannot turn that into more live QUIC receive memory.
        endpoint.grant_receive_window(3, 64 * 1024).unwrap();
        assert_eq!(endpoint.receive.connection.max_data, 512 + 1024);
        assert_eq!(endpoint.receive.stream_max_data(3), Some(512 + 1024));
    }

    #[test]
    fn receiver_profile_bounds_four_mtu_streams_and_the_connection_total() {
        let limits = ConnectionLimits::with_receive_profile(4 * 1200, 1200, 4);
        assert_eq!(limits.max_data, 4 * 1200);
        assert_eq!(limits.max_stream_data, 1200);
        assert_eq!(limits.max_streams_bidi, 4);

        let mut endpoint =
            EndpointState::<DEFAULT_MAX_PACKET_SIZE>::new(Role::Server, limits, 1200);
        for stream in [4, 8, 12, 16] {
            endpoint.receive.accept(stream, 0, 1200, false).unwrap();
        }
        assert_eq!(
            endpoint.receive.accept(20, 0, 1, false),
            Err(Error::StreamLimit)
        );
    }

    #[test]
    fn open_peer_receive_request_round_trips_and_cannot_raise_a_hard_cap() {
        let client = ConnectionId::new(0x731).unwrap();
        let local = ConnectionLimits::with_receive_profile(48_000, 12_000, 4);
        let request = ReceiveWindowRequest {
            max_data: 1_200,
            max_stream_data: 900,
        };
        let mut packet = [0u8; 256];
        let used = encode_bootstrap_open_packet_with_profile_and_peer_receive_request(
            client,
            0,
            ConnectionLimits::default(),
            0,
            Some(request),
            &mut packet,
        )
        .unwrap();
        let (_, open) = decode_bootstrap_open_packet_with_limits(&packet[..used]).unwrap();
        assert_eq!(open.requested_peer_limits, Some(request));
        assert_eq!(
            local
                .clamped_to_request(open.requested_peer_limits)
                .max_data,
            1_200
        );
        assert_eq!(
            local
                .clamped_to_request(open.requested_peer_limits)
                .max_stream_data,
            900
        );

        let larger = ReceiveWindowRequest {
            max_data: u64::MAX,
            max_stream_data: u64::MAX,
        };
        assert_eq!(local.clamped_to_request(Some(larger)), local);
    }

    #[test]
    fn sparse_bearer_retries_a_lost_receive_credit_update_at_its_deadline() {
        let client_cid = ConnectionId::new(0x721).unwrap();
        let server_cid = ConnectionId::new(0x722).unwrap();
        let limits = ConnectionLimits {
            max_data: 64,
            max_stream_data: 64,
            ..ConnectionLimits::default()
        };
        let mut sender = EndpointState::<128>::new_established(
            Role::Client,
            limits,
            1200,
            ConnectionIds::new(client_cid, server_cid).unwrap(),
        );
        let mut receiver = EndpointState::<128>::new_established(
            Role::Server,
            limits,
            1200,
            ConnectionIds::new(server_cid, client_cid).unwrap(),
        );
        sender.open_send_stream(4, 64).unwrap();
        let mut packet = [0u8; 256];
        let (used, _) = sender
            .encode_stream_packet(server_cid, 4, 0, false, &[0x5a; 64], &mut packet)
            .unwrap();
        receiver.set_time(1);
        assert!(matches!(
            receiver.receive_packet(&packet[..used]),
            Ok(TransportFrame::Stream { .. })
        ));
        receiver.stream_consumed(4, 64).unwrap();

        // The first ACK+MAX packet is submitted but lost below QUIC. No peer
        // packet arrives to wake the receiver again.
        let first_credit = receiver.poll_transmit(&mut packet).unwrap().unwrap();
        assert!(first_credit > 0);
        assert_eq!(receiver.next_bearer_deadline(), Some(525_001));
        receiver.set_time(525_000);
        assert!(receiver.poll_transmit(&mut packet).unwrap().is_none());
        receiver.set_time(525_001);
        let retry = receiver.poll_transmit(&mut packet).unwrap().unwrap();
        let (_, header) = ShortHeader::decode(&packet[..retry]).unwrap();
        let mut offset = header;
        let mut saw_max_stream_data = false;
        while offset < retry {
            let (frame, frame_len) = decode_frame(&packet[offset..retry]).unwrap();
            saw_max_stream_data |= matches!(frame, Frame::MaxStreamData { id: 4, max: 128 });
            offset += frame_len;
        }
        assert!(saw_max_stream_data);
        // A peer that vanished after the first lost MAX update must not make
        // the receiver keep a fixed-rate control loop alive.
        assert_eq!(receiver.next_bearer_deadline(), Some(1_575_001));
    }

    #[test]
    fn bootstrap_credit_constrains_sender_before_first_window_update() {
        const RECEIVE_WINDOW: u64 = 32 * 1024;
        let recovery = ConnectionLimits {
            max_data: RECEIVE_WINDOW,
            max_stream_data: RECEIVE_WINDOW,
            ..ConnectionLimits::default()
        };
        let open = BootstrapOpen {
            client_receive_cid: ConnectionId::new(7).unwrap(),
            max_data: recovery.max_data,
            max_stream_data: recovery.max_stream_data,
            max_in_flight_packets: DEFAULT_MAX_IN_FLIGHT_PACKETS,
            stateless_reset_token: None,
            requested_peer_limits: None,
        };
        let mut encoded = [0u8; 32];
        let used = open.encode(&mut encoded).unwrap();
        let advertised = BootstrapOpen::decode(&encoded[..used]).unwrap();

        let mut host = EndpointState::<DEFAULT_MAX_PACKET_SIZE>::new(
            Role::Server,
            ConnectionLimits::default(),
            1400,
        );
        host.set_initial_peer_budget(
            advertised.max_data,
            advertised.max_stream_data,
            advertised.max_in_flight_packets,
        )
        .unwrap();
        host.open_send_stream(FIRST_SERVER_BIDI_STREAM_ID, INITIAL_MAX_STREAM_DATA)
            .unwrap();
        host.reserve_send(FIRST_SERVER_BIDI_STREAM_ID, 0, RECEIVE_WINDOW as usize)
            .unwrap();
        assert_eq!(
            host.reserve_send(FIRST_SERVER_BIDI_STREAM_ID, RECEIVE_WINDOW, 1,),
            Err(Error::FlowControl)
        );
    }

    #[test]
    fn delayed_bootstrap_ack_advances_the_receive_packet_frontier() {
        // OPEN retries and OPEN_ACK retries have independent packet-number
        // spaces. A client must retain the server's acknowledged packet
        // number before it accepts the first established stream packet.
        let client = ConnectionId::new(0x711).unwrap();
        let server = ConnectionId::new(0x712).unwrap();
        let limits = ConnectionLimits {
            max_data: 64 * 1200,
            max_stream_data: 64 * 1200,
            ..ConnectionLimits::default()
        };
        let mut open_ack = [0u8; 128];
        let open_ack_len =
            encode_bootstrap_open_ack_packet_with_limits(client, server, 98, limits, &mut open_ack)
                .unwrap();
        let (header, acknowledged) =
            decode_bootstrap_open_ack_packet_with_limits(&open_ack[..open_ack_len], client)
                .unwrap();

        let mut receiver =
            EndpointState::<DEFAULT_MAX_PACKET_SIZE>::new(Role::Client, limits, 1400);
        receiver
            .set_initial_peer_budget(
                acknowledged.max_data,
                acknowledged.max_stream_data,
                acknowledged.max_in_flight_packets,
            )
            .unwrap();
        receiver.observe_packet(header.packet_number);
        receiver.install_connection_ids(client, server).unwrap();

        let mut stream_packet = [0u8; 128];
        let stream_header = ShortHeader {
            flags: FLAG_FIXED,
            dcid: client,
            packet_number: 99,
            packet_number_len: 1,
        }
        .encode(&mut stream_packet)
        .unwrap();
        let stream_len = Frame::Stream(StreamFrame {
            id: FIRST_SERVER_BIDI_STREAM_ID,
            offset: 0,
            fin: false,
            data: b"ok",
        })
        .encode(&mut stream_packet[stream_header..])
        .unwrap();
        receiver
            .receive_packet(&stream_packet[..stream_header + stream_len])
            .unwrap();
        assert_eq!(receiver.stats().inferred_missing_packets, 0);
    }

    #[test]
    fn bootstrap_profile_preserves_explicit_packet_budget() {
        let client = ConnectionId::new(0x713).unwrap();
        let limits = ConnectionLimits {
            max_data: 48_000,
            max_stream_data: 24_000,
            ..ConnectionLimits::default()
        };
        let mut packet = [0u8; 128];
        let used =
            encode_bootstrap_open_packet_with_profile(client, 7, limits, 24, &mut packet).unwrap();
        let (header, open) = decode_bootstrap_open_packet_with_limits(&packet[..used]).unwrap();
        assert_eq!(header.packet_number, 7);
        assert_eq!(open.client_receive_cid, client);
        assert_eq!(open.max_data, 48_000);
        assert_eq!(open.max_stream_data, 24_000);
        assert_eq!(open.max_in_flight_packets, 24);
    }

    #[test]
    fn bootstrap_packet_budget_limits_small_packet_burst() {
        let local = ConnectionId::new(0x701).unwrap();
        let peer = ConnectionId::new(0x702).unwrap();
        let mut sender = EndpointState::<64>::new_with_history_capacity(
            Role::Server,
            ConnectionLimits::default(),
            1400,
            DEFAULT_MAX_IN_FLIGHT_PACKETS as usize,
        );
        sender.install_connection_ids(local, peer).unwrap();
        sender
            .set_initial_peer_budget(
                INITIAL_MAX_DATA,
                INITIAL_MAX_STREAM_DATA,
                DEFAULT_MAX_IN_FLIGHT_PACKETS,
            )
            .unwrap();
        sender
            .open_send_stream(FIRST_SERVER_BIDI_STREAM_ID, INITIAL_MAX_STREAM_DATA)
            .unwrap();
        sender.congestion.congestion_window = u64::from(DEFAULT_MAX_IN_FLIGHT_PACKETS) * 1400;
        let mut packet = [0u8; 128];
        for offset in 0..u64::from(DEFAULT_MAX_IN_FLIGHT_PACKETS) {
            sender
                .encode_stream_packet(
                    peer,
                    FIRST_SERVER_BIDI_STREAM_ID,
                    offset,
                    false,
                    b"x",
                    &mut packet,
                )
                .unwrap();
        }
        assert_eq!(
            sender.encode_stream_packet(
                peer,
                FIRST_SERVER_BIDI_STREAM_ID,
                u64::from(DEFAULT_MAX_IN_FLIGHT_PACKETS),
                true,
                b"x",
                &mut packet,
            ),
            Err(Error::Blocked)
        );
    }

    #[test]
    fn rejected_first_fragment_does_not_consume_stream_slot() {
        let limits = ConnectionLimits {
            max_data: 4,
            max_stream_data: 8,
            max_streams_bidi: 1,
            max_streams_uni: 0,
        };
        let mut c = ConnectionState::new(Role::Server, limits);
        assert_eq!(c.accept(4, 0, 5, true), Err(Error::FlowControl));
        // The only bidirectional stream slot is still available after the
        // rejected fragment; a later in-window stream can open normally.
        assert!(c.accept(4, 0, 4, true).is_ok());
    }

    #[test]
    fn connection_and_stream_windows_are_independent_and_extendable() {
        let limits = ConnectionLimits {
            max_data: 16,
            max_stream_data: 8,
            max_streams_bidi: 2,
            max_streams_uni: 0,
        };
        let mut c = ConnectionState::new(Role::Server, limits);
        assert!(c.accept(0, 0, 8, false).is_ok());
        assert_eq!(c.accept(0, 8, 1, false), Err(Error::FlowControl));
        assert!(c.consume(0, 8).is_ok());
        c.streams[0].extend(8);
        assert!(c.accept(0, 8, 8, false).is_ok());
        assert_eq!(c.accept(0, 16, 1, false), Err(Error::FlowControl));
        assert!(c.consume(0, 8).is_ok());
        c.streams[0].extend(1);
        c.connection.extend(16);
        assert!(c.accept(0, 16, 1, false).is_ok());
    }

    #[test]
    fn live_receive_limit_decrease_withholds_growth_without_revoking_credit() {
        let original = ConnectionLimits::with_receive_profile(64, 32, 4);
        let mut endpoint = EndpointState::<128>::new(Role::Server, original, 128);
        assert_eq!(endpoint.receive.connection.max_data, 64);
        assert_eq!(endpoint.receive.limits.max_streams_bidi, 4);

        endpoint
            .set_receive_growth_limits(ConnectionLimits::with_receive_profile(8, 4, 1))
            .unwrap();
        assert_eq!(endpoint.receive.connection.max_data, 64);
        assert_eq!(endpoint.receive.limits.max_streams_bidi, 4);

        endpoint
            .set_receive_growth_limits(ConnectionLimits::with_receive_profile(128, 64, 8))
            .unwrap();
        assert_eq!(endpoint.receive.connection.max_data, 128);
        assert_eq!(endpoint.receive.limits.max_streams_bidi, 8);
    }

    #[test]
    fn sender_flow_credit_blocks_and_extension_allows_progress() {
        let mut flow = SendFlowControl::new(16, 8);
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
        let mut endpoint = EndpointState::<DEFAULT_MAX_PACKET_SIZE>::new(
            Role::Client,
            ConnectionLimits::default(),
            1200,
        );
        endpoint
            .open_send_stream(3, INITIAL_MAX_STREAM_DATA)
            .unwrap();
        endpoint.observe_packet(4);
        endpoint.observe_packet(2);
        assert_eq!(endpoint.largest_received(), Some(4));
        assert!(endpoint.receive.accept(1, 0, 4, false).is_ok());
        endpoint.receive.consume(1, 4).unwrap();
        endpoint.receive.extend_connection_credit(INITIAL_MAX_DATA);
        endpoint
            .receive
            .extend_stream_credit(1, INITIAL_MAX_STREAM_DATA)
            .unwrap();
        assert!(endpoint.reserve_send(3, 0, 8).is_ok());
        assert!(endpoint.packet_sent(1200));
        endpoint.acked(1200);
        assert_eq!(endpoint.congestion.bytes_in_flight, 0);
    }

    #[test]
    fn bootstrap_stream_records_round_trip_and_reject_extensions() {
        let client = BootstrapOpen {
            client_receive_cid: ConnectionId::new(0x1234).unwrap(),
            max_data: 4096,
            max_stream_data: 2048,
            max_in_flight_packets: 8,
            stateless_reset_token: None,
            requested_peer_limits: None,
        };
        let mut encoded = [0u8; 32];
        let used = client.encode(&mut encoded).unwrap();
        assert_eq!(BootstrapOpen::decode(&encoded[..used]).unwrap(), client);
        let server = BootstrapOpenAck {
            server_receive_cid: ConnectionId::new(0x3fff).unwrap(),
            max_data: 4096,
            max_stream_data: 2048,
            max_in_flight_packets: 0,
            stateless_reset_token: None,
        };
        let used = server.encode(&mut encoded).unwrap();
        assert_eq!(BootstrapOpenAck::decode(&encoded[..used]).unwrap(), server);
        assert_eq!(
            BootstrapOpen::decode(&[0, 0, 0, 1]).unwrap_err(),
            Error::BootstrapInvalid
        );
        assert_eq!(
            BootstrapOpen::decode(&encoded[..used]).unwrap_err(),
            Error::BootstrapInvalid
        );
    }

    #[test]
    fn bootstrap_stream_records_have_byte_exact_golden_vectors() {
        let smallest = BootstrapOpen {
            client_receive_cid: ConnectionId::new(1).unwrap(),
            max_data: 64,
            max_stream_data: 64,
            max_in_flight_packets: 0,
            stateless_reset_token: None,
            requested_peer_limits: None,
        };
        let mut encoded = [0u8; 32];
        let used = smallest.encode(&mut encoded).unwrap();
        assert_eq!(
            &encoded[..used],
            &[0x00, 0x00, 0x01, 0x05, 0x40, 0x40, 0x40, 0x40, 0x00]
        );

        let largest = BootstrapOpen {
            client_receive_cid: ConnectionId::new(ConnectionId::MAX_VALUE).unwrap(),
            max_data: 64,
            max_stream_data: 64,
            max_in_flight_packets: 0,
            stateless_reset_token: None,
            requested_peer_limits: None,
        };
        let used = largest.encode(&mut encoded).unwrap();
        assert_eq!(
            &encoded[..used],
            &[
                0x00, 0x00, 0xdf, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x05, 0x40, 0x40, 0x40,
                0x40, 0x00
            ]
        );

        let smallest_ack = BootstrapOpenAck {
            server_receive_cid: ConnectionId::new(1).unwrap(),
            max_data: 64,
            max_stream_data: 64,
            max_in_flight_packets: 0,
            stateless_reset_token: None,
        };
        let used = smallest_ack.encode(&mut encoded).unwrap();
        assert_eq!(
            &encoded[..used],
            &[0x01, 0x00, 0x01, 0x05, 0x40, 0x40, 0x40, 0x40, 0x00]
        );

        let largest_ack = BootstrapOpenAck {
            server_receive_cid: ConnectionId::new(ConnectionId::MAX_VALUE).unwrap(),
            max_data: 64,
            max_stream_data: 64,
            max_in_flight_packets: 0,
            stateless_reset_token: None,
        };
        let used = largest_ack.encode(&mut encoded).unwrap();
        assert_eq!(
            &encoded[..used],
            &[
                0x01, 0x00, 0xdf, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x05, 0x40, 0x40, 0x40,
                0x40, 0x00
            ]
        );
    }

    #[test]
    fn directional_cids_are_validated_and_history_is_configurable() {
        let client_cid = ConnectionId::new(0x11).unwrap();
        let server_cid = ConnectionId::new(0x22).unwrap();
        let mut client = EndpointState::<DEFAULT_MAX_PACKET_SIZE>::new_with_history_capacity(
            Role::Client,
            ConnectionLimits::default(),
            1200,
            2,
        );
        let mut server = EndpointState::<DEFAULT_MAX_PACKET_SIZE>::new(
            Role::Server,
            ConnectionLimits::default(),
            1200,
        );
        client
            .install_connection_ids(client_cid, server_cid)
            .unwrap();
        server
            .install_connection_ids(server_cid, client_cid)
            .unwrap();
        assert_eq!(client.history_capacity(), 2);
        client.set_history_capacity(1).unwrap();
        assert_eq!(client.history_capacity(), 1);
        assert_eq!(
            client.retransmission_capacity_bytes(),
            DEFAULT_MAX_PACKET_SIZE
        );
        assert_eq!(client.set_history_capacity(0), Err(Error::HistoryFull));
        client.open_send_stream(4, INITIAL_MAX_STREAM_DATA).unwrap();
        let mut packet = [0u8; 256];
        let (used, pn) = client
            .encode_stream_packet(server_cid, 4, 0, true, b"x", &mut packet)
            .unwrap();
        assert_eq!(pn, 0);
        assert_eq!(
            client
                .encode_stream_packet(client_cid, 8, 0, true, b"wrong", &mut packet)
                .unwrap_err(),
            Error::WrongConnectionId
        );
        assert_eq!(
            client.set_history_capacity(0),
            Err(Error::HistoryFull),
            "an active retained packet cannot be evicted by reconfiguration"
        );
        client.set_history_capacity(2).unwrap();
        client.open_send_stream(8, INITIAL_MAX_STREAM_DATA).unwrap();
        let (_used_second, _second_pn) = client
            .encode_stream_packet(server_cid, 8, 0, true, b"y", &mut packet)
            .unwrap();
        // An ACK hole can leave a live packet in a higher slot. It must not
        // become unreachable when the active limit is lowered.
        client.sent_packets[0] = None;
        client.set_history_capacity(1).unwrap();
        assert_eq!(client.history_capacity(), 1);
        assert_eq!(client.allocated_history_packets(), 2);
        assert!(matches!(
            server.receive_packet(&packet[..used]).unwrap(),
            TransportFrame::Stream { .. }
        ));
        let wrong = ShortHeader {
            flags: FLAG_FIXED,
            dcid: client_cid,
            packet_number: 9,
            packet_number_len: 4,
        };
        let mut bad = [0u8; 256];
        let header_len = wrong.encode(&mut bad).unwrap();
        let frame_len = Frame::Ping.encode(&mut bad[header_len..]).unwrap();
        assert_eq!(
            server
                .receive_packet(&bad[..header_len + frame_len])
                .unwrap_err(),
            Error::WrongConnectionId
        );
    }

    #[test]
    fn combined_ack_and_stream_is_transactional() {
        let client_cid = ConnectionId::new(0x31).unwrap();
        let server_cid = ConnectionId::new(0x32).unwrap();
        let mut client = EndpointState::<DEFAULT_MAX_PACKET_SIZE>::new(
            Role::Client,
            ConnectionLimits::default(),
            1200,
        );
        let mut server = EndpointState::<DEFAULT_MAX_PACKET_SIZE>::new(
            Role::Server,
            ConnectionLimits::default(),
            1200,
        );
        client
            .install_connection_ids(client_cid, server_cid)
            .unwrap();
        server
            .install_connection_ids(server_cid, client_cid)
            .unwrap();
        client.open_send_stream(4, INITIAL_MAX_STREAM_DATA).unwrap();
        let mut request = [0u8; 256];
        let (request_len, _) = client
            .encode_stream_packet(server_cid, 4, 0, true, b"request", &mut request)
            .unwrap();
        assert!(matches!(
            server.receive_packet(&request[..request_len]).unwrap(),
            TransportFrame::Stream { .. }
        ));
        server.stream_consumed(4, 7).unwrap();
        let mut combined = [0u8; 256];
        let ack_len = server.poll_transmit(&mut combined).unwrap().unwrap();
        let stream_len = Frame::Stream(StreamFrame {
            id: 1,
            offset: 0,
            fin: true,
            data: b"response",
        })
        .encode(&mut combined[ack_len..])
        .unwrap();
        let second_stream_len = Frame::Stream(StreamFrame {
            id: 5,
            offset: 0,
            fin: true,
            data: b"second response",
        })
        .encode(&mut combined[ack_len + stream_len..])
        .unwrap();
        let total = ack_len + stream_len + second_stream_len;
        let packet = client.receive_packet_batch(&combined[..total]).unwrap();
        assert_eq!(
            packet.streams().map(|frame| frame.data).collect::<Vec<_>>(),
            vec![b"response".as_slice(), b"second response".as_slice()]
        );
        assert_eq!(client.history_len(), 0);
        assert!(
            EndpointState::<DEFAULT_MAX_PACKET_SIZE>::validate_packet(&combined[..total]).is_ok()
        );

        let mut malformed = combined[..total].to_vec();
        malformed.push(0xff);
        assert!(EndpointState::<DEFAULT_MAX_PACKET_SIZE>::validate_packet(&malformed).is_err());
    }

    #[test]
    fn packets_require_explicit_directional_cids() {
        let mut endpoint = EndpointState::<DEFAULT_MAX_PACKET_SIZE>::new(
            Role::Server,
            ConnectionLimits::default(),
            1200,
        );
        let cid = ConnectionId::new(0x44).unwrap();
        let header = ShortHeader {
            flags: FLAG_FIXED,
            dcid: cid,
            packet_number: 0,
            packet_number_len: 4,
        };
        let mut malformed = [0u8; 64];
        let header_len = header.encode(&mut malformed).unwrap();
        malformed[header_len] = FRAME_STREAM_BASE as u8 | 0x04 | 0x02 | 1;
        assert!(
            endpoint
                .receive_packet(&malformed[..header_len + 1])
                .is_err()
        );
        assert_eq!(endpoint.peer_connection_id(), None);

        let frame_len = Frame::Ping.encode(&mut malformed[header_len..]).unwrap();
        assert_eq!(
            endpoint
                .receive_packet(&malformed[..header_len + frame_len])
                .unwrap_err(),
            Error::WrongConnectionId
        );
    }

    #[test]
    fn history_capacity_applies_backpressure_without_mutating_window() {
        let cid = ConnectionId::new(9).unwrap();
        let mut endpoint = EndpointState::<DEFAULT_MAX_PACKET_SIZE>::new_with_history_capacity(
            Role::Client,
            ConnectionLimits::default(),
            1200,
            1,
        );
        endpoint
            .open_send_stream(4, INITIAL_MAX_STREAM_DATA)
            .unwrap();
        let mut packet = [0u8; 256];
        endpoint
            .encode_stream_packet(cid, 4, 0, false, b"a", &mut packet)
            .unwrap();
        let in_flight = endpoint.congestion.bytes_in_flight;
        assert_eq!(endpoint.history_len(), 1);
        assert_eq!(
            endpoint
                .encode_stream_packet(cid, 4, 1, true, b"b", &mut packet)
                .unwrap_err(),
            Error::HistoryFull
        );
        assert_eq!(endpoint.congestion.bytes_in_flight, in_flight);
        assert_eq!(endpoint.history_len(), 1);
    }

    #[test]
    fn host_ledger_allocates_and_grows_selected_capacity() {
        let mut endpoint = EndpointState::<128>::new_with_history_capacity(
            Role::Client,
            ConnectionLimits::default(),
            1200,
            4,
        );
        assert_eq!(endpoint.history_capacity(), 4);
        assert_eq!(endpoint.history_storage_slots(), 4);
        assert_eq!(endpoint.retransmission_capacity_bytes(), 4 * 128);
        endpoint.set_history_capacity(12).unwrap();
        assert_eq!(endpoint.history_capacity(), 12);
        assert_eq!(endpoint.history_storage_slots(), 12);
        assert_eq!(endpoint.retransmission_capacity_bytes(), 12 * 128);
        endpoint.set_history_capacity(6).unwrap();
        assert_eq!(endpoint.history_storage_slots(), 6);
    }

    #[test]
    fn history_limit_shrink_blocks_growth_without_evicting_live_entries() {
        let cid = ConnectionId::new(0x4711).unwrap();
        let peer = ConnectionId::new(0x4712).unwrap();
        let mut endpoint = EndpointState::<64>::new_with_history_capacity(
            Role::Client,
            ConnectionLimits::default(),
            1200,
            8,
        );
        endpoint.install_connection_ids(cid, peer).unwrap();
        endpoint
            .open_send_stream(4, INITIAL_MAX_STREAM_DATA)
            .unwrap();
        let mut packet = [0u8; 256];
        endpoint
            .encode_stream_packet(peer, 4, 0, false, b"one", &mut packet)
            .unwrap();
        endpoint
            .encode_stream_packet(peer, 4, 3, true, b"two", &mut packet)
            .unwrap();
        endpoint.set_history_capacity(1).unwrap();
        assert_eq!(endpoint.history_capacity(), 1);
        assert_eq!(endpoint.allocated_history_packets(), 8);
        assert_eq!(
            endpoint
                .encode_stream_packet(peer, 4, 6, false, b"three", &mut packet)
                .unwrap_err(),
            Error::HistoryFull
        );
    }

    #[test]
    fn dynamic_host_ledger_tiers_stay_bounded_under_faults() {
        for capacity in [4_usize, 16, 64, 256, 512] {
            let local = ConnectionId::new(0x5100 + capacity as u64).unwrap();
            let peer = ConnectionId::new(0x5200 + capacity as u64).unwrap();
            let limits = ConnectionLimits::default();
            let mut sender = EndpointState::<64>::new_with_history_capacity(
                Role::Client,
                limits,
                1200,
                capacity,
            );
            let mut receiver = EndpointState::<64>::new(Role::Server, limits, 1200);
            sender.install_connection_ids(local, peer).unwrap();
            receiver.install_connection_ids(peer, local).unwrap();
            sender.open_send_stream(4, INITIAL_MAX_STREAM_DATA).unwrap();
            sender.congestion.congestion_window = (capacity as u64) * 1200;
            sender.congestion.slow_start_threshold = sender.congestion.congestion_window;
            let mut link = crate::fake::FaultQueue::new(crate::fake::FaultConfig {
                latency_ticks: 5,
                drop_every: Some(3),
                duplicate: true,
                reorder: true,
                mtu: 1200,
            });
            let mut packet_numbers = Vec::with_capacity(capacity);
            let mut packet = [0_u8; 256];
            for index in 0..capacity {
                let data = [index as u8; 32];
                let (used, packet_number) = sender
                    .encode_stream_packet(
                        peer,
                        4,
                        (index * data.len()) as u64,
                        index + 1 == capacity,
                        &data,
                        &mut packet,
                    )
                    .unwrap();
                link.submit_at(index as u64, &packet[..used]).unwrap();
                packet_numbers.push(packet_number);
                assert_eq!(sender.history_storage_slots(), capacity);
                assert!(sender.history_len() <= capacity);
                assert!(sender.retained_payload_bytes() <= sender.retransmission_capacity_bytes());
            }
            for packet in link.poll_owned(capacity as u64 + 5) {
                if let Ok(TransportFrame::Stream { frame, .. }) =
                    receiver.receive_packet(packet.bytes())
                {
                    let _ = receiver.stream_consumed(frame.id, frame.data.len());
                }
            }
            for packet_number in packet_numbers {
                sender.mark_lost(packet_number);
            }
            assert_eq!(sender.retained_payload_bytes(), 0);
        }
    }

    #[test]
    fn retransmission_uses_bounded_payload_ledger_without_duplicate_credit() {
        let local = ConnectionId::new(51).unwrap();
        let peer = ConnectionId::new(52).unwrap();
        let mut sender = EndpointState::<64>::new(Role::Client, ConnectionLimits::default(), 1200);
        sender.install_connection_ids(local, peer).unwrap();
        sender.open_send_stream(4, INITIAL_MAX_STREAM_DATA).unwrap();
        let mut packet = [0u8; 256];
        let (_used, first_pn) = sender
            .encode_stream_packet(peer, 4, 0, true, b"reliable", &mut packet)
            .unwrap();
        let before = sender.send.sent_data;
        let (retransmitted, second_pn) = sender
            .retransmit_stream_packet(first_pn, &mut packet)
            .unwrap()
            .unwrap();
        assert_ne!(first_pn, second_pn);
        assert_eq!(sender.send.sent_data, before);
        let (_, header_len) = ShortHeader::decode(&packet[..retransmitted]).unwrap();
        assert_eq!(
            ShortHeader::decode(&packet[..retransmitted])
                .unwrap()
                .0
                .packet_number,
            second_pn
        );
        let (frame, _) = decode_frame(&packet[header_len..retransmitted]).unwrap();
        assert_eq!(
            frame,
            Frame::Stream(StreamFrame {
                id: 4,
                offset: 0,
                fin: true,
                data: b"reliable"
            })
        );
    }

    #[test]
    fn pto_retransmission_does_not_reduce_congestion_window() {
        let local = ConnectionId::new(0x551).unwrap();
        let peer = ConnectionId::new(0x552).unwrap();
        let mut sender = EndpointState::<128>::new_with_history_capacity(
            Role::Client,
            ConnectionLimits::default(),
            1200,
            32,
        );
        sender.install_connection_ids(local, peer).unwrap();
        sender.open_send_stream(4, INITIAL_MAX_STREAM_DATA).unwrap();
        let mut packet = [0u8; 256];
        let (_, original) = sender
            .encode_stream_packet(peer, 4, 0, true, b"one logical range", &mut packet)
            .unwrap();

        let (_, first_retry) = sender
            .retransmit_stream_packet(original, &mut packet)
            .unwrap()
            .unwrap();
        let after_first_loss = sender.congestion.congestion_window;
        let after_first_retry_flight = sender.congestion.bytes_in_flight;
        assert_eq!(after_first_loss, 12_000);

        // The first retry also disappears. It has a new packet number, but
        // it is still the same stream offset and payload. Losing it must not
        // turn a single logical loss episode into another cwnd reduction.
        let (_, second_retry) = sender
            .retransmit_stream_packet(first_retry, &mut packet)
            .unwrap()
            .unwrap();
        assert_ne!(first_retry, second_retry);
        assert_eq!(sender.congestion.congestion_window, after_first_loss);
        assert_eq!(sender.congestion.bytes_in_flight, after_first_retry_flight);
        assert_eq!(sender.stats().retransmitted_packets, 2);
    }

    #[test]
    fn retransmitting_a_detected_loss_subtracts_the_original_only_once() {
        let local = ConnectionId::new(0x571).unwrap();
        let peer = ConnectionId::new(0x572).unwrap();
        let mut sender = EndpointState::<128>::new(Role::Client, ConnectionLimits::default(), 1200);
        sender.install_connection_ids(local, peer).unwrap();
        sender.open_send_stream(4, INITIAL_MAX_STREAM_DATA).unwrap();
        let mut packet = [0_u8; 256];
        let mut first_packet = None;
        for offset in 0..4_u64 {
            let (_, packet_number) = sender
                .encode_stream_packet(peer, 4, offset, false, b"x", &mut packet)
                .unwrap();
            first_packet.get_or_insert(packet_number);
        }
        let first_packet = first_packet.unwrap();
        let first_bytes = sender
            .sent_packets
            .iter()
            .flatten()
            .find(|sent| sent.packet_number == first_packet)
            .unwrap()
            .bytes;
        let original_flight = sender.congestion.bytes_in_flight;

        sender.detect_ack_losses(Some(first_packet + 3));
        assert_eq!(
            sender.congestion.bytes_in_flight,
            original_flight - first_bytes
        );
        let flight_after_loss = sender.congestion.bytes_in_flight;
        let (replacement_bytes, _) = sender
            .retransmit_stream_packet(first_packet, &mut packet)
            .unwrap()
            .unwrap();
        assert_eq!(
            sender.congestion.bytes_in_flight,
            flight_after_loss + replacement_bytes as u64
        );
    }

    #[test]
    fn explicit_loss_of_retransmitted_range_keeps_recovery_epoch() {
        let local = ConnectionId::new(0x561).unwrap();
        let peer = ConnectionId::new(0x562).unwrap();
        let mut sender = EndpointState::<128>::new(Role::Client, ConnectionLimits::default(), 1200);
        sender.install_connection_ids(local, peer).unwrap();
        sender.open_send_stream(4, INITIAL_MAX_STREAM_DATA).unwrap();
        let mut packet = [0u8; 256];
        let (_, original) = sender
            .encode_stream_packet(peer, 4, 0, true, b"one logical range", &mut packet)
            .unwrap();
        let (_, retry) = sender
            .retransmit_stream_packet(original, &mut packet)
            .unwrap()
            .unwrap();
        let after_first_loss = sender.congestion.congestion_window;

        // A bearer which declares the retained retry lost must use the same
        // NewReno recovery boundary as the retransmission scheduler.
        assert!(sender.mark_lost(retry));
        assert!(sender.congestion.congestion_window < after_first_loss);
    }

    #[test]
    fn ack_for_original_packet_retires_retransmitted_stream_range() {
        let local = ConnectionId::new(53).unwrap();
        let peer = ConnectionId::new(54).unwrap();
        let mut sender = EndpointState::<128>::new(Role::Client, ConnectionLimits::default(), 1200);
        let mut receiver =
            EndpointState::<128>::new(Role::Server, ConnectionLimits::default(), 1200);
        sender.install_connection_ids(local, peer).unwrap();
        receiver.install_connection_ids(peer, local).unwrap();
        sender.open_send_stream(4, INITIAL_MAX_STREAM_DATA).unwrap();
        let mut packet = [0u8; 256];
        let (used, original_pn) = sender
            .encode_stream_packet(peer, 4, 0, true, b"logical delivery", &mut packet)
            .unwrap();
        receiver.receive_packet(&packet[..used]).unwrap();
        let (_, replacement_pn) = sender
            .retransmit_stream_packet(original_pn, &mut packet)
            .unwrap()
            .unwrap();
        assert_ne!(original_pn, replacement_pn);

        // The peer's delayed ACK covers the original transmission, not the
        // replacement. It must still retire the one logical stream range.
        receiver.set_time(25_000);
        let mut ack = [0u8; 256];
        let ack_len = receiver.poll_transmit(&mut ack).unwrap().unwrap();
        sender.receive_packet(&ack[..ack_len]).unwrap();
        assert_eq!(sender.history_len(), 0);
        assert_eq!(sender.latest_rtt(), None);
    }

    #[test]
    fn delayed_ack_emits_on_timer_tick_without_another_packet() {
        let local = ConnectionId::new(57).unwrap();
        let peer = ConnectionId::new(58).unwrap();
        let mut sender = EndpointState::<128>::new(Role::Client, ConnectionLimits::default(), 1200);
        let mut receiver =
            EndpointState::<128>::new(Role::Server, ConnectionLimits::default(), 1200);
        sender.install_connection_ids(local, peer).unwrap();
        receiver.install_connection_ids(peer, local).unwrap();
        receiver.set_ack_frequency(8);
        sender.open_send_stream(4, INITIAL_MAX_STREAM_DATA).unwrap();
        let mut packet = [0u8; 256];
        let (used, _) = sender
            .encode_stream_packet(peer, 4, 0, true, b"one packet", &mut packet)
            .unwrap();
        receiver.receive_packet(&packet[..used]).unwrap();
        let mut ack = [0u8; 256];
        assert!(receiver.poll_transmit(&mut ack).unwrap().is_none());
        receiver.set_time(25_000);
        assert!(receiver.poll_transmit(&mut ack).unwrap().is_some());
    }

    #[test]
    fn bearer_timeout_respects_delayed_ack_deadline() {
        let local = ConnectionId::new(61).unwrap();
        let peer = ConnectionId::new(62).unwrap();
        let mut sender = EndpointState::<128>::new(Role::Client, ConnectionLimits::default(), 1200);
        let mut receiver =
            EndpointState::<128>::new(Role::Server, ConnectionLimits::default(), 1200);
        sender.install_connection_ids(local, peer).unwrap();
        receiver.install_connection_ids(peer, local).unwrap();
        receiver.set_ack_frequency(4);
        sender.open_send_stream(4, INITIAL_MAX_STREAM_DATA).unwrap();
        let mut packet = [0u8; 256];
        let (used, _) = sender
            .encode_stream_packet(peer, 4, 0, false, b"final short burst", &mut packet)
            .unwrap();
        let TransportFrame::Stream { frame, .. } =
            receiver.receive_packet(&packet[..used]).unwrap()
        else {
            panic!("expected stream");
        };
        receiver
            .stream_consumed_deferred(frame.id, frame.data.len())
            .unwrap();
        let mut ack = [0u8; 256];
        assert!(receiver.poll_transmit(&mut ack).unwrap().is_none());
        receiver.set_time(24_000);
        receiver.on_bearer_timeout();
        assert!(receiver.poll_transmit(&mut ack).unwrap().is_none());
        receiver.set_time(25_000);
        receiver.on_bearer_timeout();
        assert!(receiver.poll_transmit(&mut ack).unwrap().is_some());
    }

    #[test]
    fn delayed_ack_budget_prevents_spurious_time_loss() {
        let local = ConnectionId::new(59).unwrap();
        let peer = ConnectionId::new(60).unwrap();
        let mut sender = EndpointState::<128>::new(Role::Client, ConnectionLimits::default(), 1200);
        sender.install_connection_ids(local, peer).unwrap();
        sender.set_ack_policy(8, 25_000);
        sender.open_send_stream(4, INITIAL_MAX_STREAM_DATA).unwrap();

        let mut packet = [0u8; 256];
        sender.set_time(35);
        let (_, first) = sender
            .encode_stream_packet(peer, 4, 0, false, b"first", &mut packet)
            .unwrap();
        sender.set_time(60);
        let (_, second) = sender
            .encode_stream_packet(peer, 4, 5, false, b"second", &mut packet)
            .unwrap();

        // The ACK for the later packet carries the peer's permitted 25 ms
        // delay. It does not prove the earlier packet was lost: on a busy
        // Wi-Fi receive path it can be merely reordered. Do not halve cwnd
        // before that delayed-ACK budget has elapsed.
        let mut ack = [0u8; 256];
        let mut used = ShortHeader {
            flags: FLAG_FIXED,
            dcid: local,
            packet_number: 0,
            packet_number_len: 1,
        }
        .encode(&mut ack)
        .unwrap();
        used += Frame::Ack {
            largest: second,
            delay: 25,
        }
        .encode(&mut ack[used..])
        .unwrap();
        sender.set_time(85);
        sender.receive_packet(&ack[..used]).unwrap();

        assert!(
            sender
                .sent_packets
                .iter()
                .flatten()
                .any(|packet| packet.packet_number == first && !packet.lost)
        );
    }

    #[test]
    fn recovery_ack_frequency_batches_eight_consumed_stream_packets() {
        let local = ConnectionId::new(59).unwrap();
        let peer = ConnectionId::new(60).unwrap();
        let mut sender = EndpointState::<128>::new(Role::Client, ConnectionLimits::default(), 1200);
        let mut receiver =
            EndpointState::<128>::new(Role::Server, ConnectionLimits::default(), 1200);
        sender.install_connection_ids(local, peer).unwrap();
        receiver.install_connection_ids(peer, local).unwrap();
        receiver.set_ack_frequency(8);
        sender.open_send_stream(4, INITIAL_MAX_STREAM_DATA).unwrap();
        let mut packet = [0u8; 128];
        let mut ack = [0u8; 128];
        for offset in 0..8 {
            let (used, _) = sender
                .encode_stream_packet(peer, 4, offset, false, b"x", &mut packet)
                .unwrap();
            receiver.receive_packet(&packet[..used]).unwrap();
            receiver.stream_consumed_deferred(4, 1).unwrap();
            assert_eq!(
                receiver.poll_transmit(&mut ack).unwrap().is_some(),
                offset == 7
            );
        }
        let stats = receiver.stats();
        assert_eq!(stats.ack_packets, 1);
        assert_eq!(stats.ack_threshold_packets, 1);
        assert_eq!(stats.ack_immediate_packets, 0);
        assert_eq!(stats.ack_timer_packets, 0);
    }

    #[test]
    fn delayed_ack_encodes_observed_wait_and_gap_is_immediate() {
        let local = ConnectionId::new(65).unwrap();
        let peer = ConnectionId::new(66).unwrap();
        let mut sender = EndpointState::<128>::new(Role::Client, ConnectionLimits::default(), 1200);
        let mut receiver =
            EndpointState::<128>::new(Role::Server, ConnectionLimits::default(), 1200);
        sender.install_connection_ids(local, peer).unwrap();
        receiver.install_connection_ids(peer, local).unwrap();
        receiver.set_ack_policy(8, 25_000);
        sender.open_send_stream(4, INITIAL_MAX_STREAM_DATA).unwrap();
        let mut packet = [0u8; 256];
        let (used, _) = sender
            .encode_stream_packet(peer, 4, 0, false, b"a", &mut packet)
            .unwrap();
        receiver.set_time(100);
        receiver.receive_packet(&packet[..used]).unwrap();
        receiver.set_time(117);
        receiver.stream_consumed(4, 1).unwrap();
        let mut ack = [0u8; 256];
        let ack_len = receiver.poll_transmit(&mut ack).unwrap().unwrap();
        let (_, header_len) = ShortHeader::decode(&ack[..ack_len]).unwrap();
        let (frame, _) = decode_frame(&ack[header_len..ack_len]).unwrap();
        assert!(matches!(
            frame,
            Frame::Ack { delay: 17, .. } | Frame::AckRanges { delay: 17, .. }
        ));

        // Packet 2 after packet 0 creates a selective-ACK gap and must not
        // wait for ACK frequency or max_ack_delay.
        sender
            .encode_stream_packet(peer, 4, 1, false, b"lost", &mut packet)
            .unwrap();
        let (used, _) = sender
            .encode_stream_packet(peer, 4, 2, false, b"b", &mut packet)
            .unwrap();
        receiver.receive_packet(&packet[..used]).unwrap();
        assert!(receiver.poll_transmit(&mut ack).unwrap().is_some());
    }

    #[test]
    fn committed_stream_retransmission_with_no_new_bytes_reacks_immediately() {
        let local = ConnectionId::new(67).unwrap();
        let peer = ConnectionId::new(68).unwrap();
        let mut sender = EndpointState::<128>::new(Role::Client, ConnectionLimits::default(), 1200);
        let mut receiver =
            EndpointState::<128>::new(Role::Server, ConnectionLimits::default(), 1200);
        sender.install_connection_ids(local, peer).unwrap();
        receiver.install_connection_ids(peer, local).unwrap();
        // A normal ACK is deliberately delayed, so this test proves the
        // special retransmission/reordering path rather than the threshold.
        receiver.set_ack_frequency(8);
        sender.open_send_stream(4, INITIAL_MAX_STREAM_DATA).unwrap();
        let mut packet = [0u8; 256];
        let (used, original) = sender
            .encode_stream_packet(peer, 4, 0, true, b"once", &mut packet)
            .unwrap();
        let mut output = [0u8; 256];
        let mut emitted = 0usize;
        let mut deliveries = 0usize;
        receiver
            .receive_with_committed_callbacks(
                &packet[..used],
                &mut output,
                |_| emitted += 1,
                |_| {
                    deliveries += 1;
                    Ok(4)
                },
            )
            .unwrap();
        assert_eq!(emitted, 0);

        let (retry_used, retry) = sender
            .retransmit_stream_packet(original, &mut packet)
            .unwrap()
            .unwrap();
        assert_ne!(retry, original);
        receiver
            .receive_with_committed_callbacks(
                &packet[..retry_used],
                &mut output,
                |_| emitted += 1,
                |_| {
                    deliveries += 1;
                    // CallbackStreams/Recovery returns zero for a stream
                    // range already delivered under its original packet ID.
                    Ok(0)
                },
            )
            .unwrap();
        assert_eq!(deliveries, 2);
        assert_eq!(
            emitted, 1,
            "fresh-number retransmission must be re-ACKed promptly"
        );
        assert_eq!(receiver.stats().ack_immediate_packets, 1);
    }

    #[test]
    fn committed_callbacks_deliver_every_coalesced_stream() {
        let local = ConnectionId::new(0x81).unwrap();
        let peer = ConnectionId::new(0x82).unwrap();
        let mut sender = EndpointState::<256>::new(Role::Client, ConnectionLimits::default(), 1200);
        let mut receiver =
            EndpointState::<256>::new(Role::Server, ConnectionLimits::default(), 1200);
        sender.install_connection_ids(local, peer).unwrap();
        receiver.install_connection_ids(peer, local).unwrap();
        sender.open_send_stream(4, INITIAL_MAX_STREAM_DATA).unwrap();
        sender.open_send_stream(8, INITIAL_MAX_STREAM_DATA).unwrap();

        let mut packet = [0u8; 256];
        let (first_used, _) = sender
            .encode_stream_packet(peer, 4, 0, true, b"first", &mut packet)
            .unwrap();
        let second_used = Frame::Stream(StreamFrame {
            id: 8,
            offset: 0,
            fin: true,
            data: b"second",
        })
        .encode(&mut packet[first_used..])
        .unwrap();
        let mut output = [0u8; 256];
        let mut received = Vec::new();
        let info = receiver
            .receive_with_committed_callbacks(
                &packet[..first_used + second_used],
                &mut output,
                |_| {},
                |frame| {
                    received.push((frame.id, frame.data.to_vec()));
                    Ok(frame.data.len())
                },
            )
            .unwrap();
        assert!(info.stream);
        assert_eq!(
            received,
            vec![(4, b"first".to_vec()), (8, b"second".to_vec())]
        );
    }

    #[test]
    fn committed_deferred_receive_coalesces_a_full_recovery_drain() {
        let local = ConnectionId::new(681).unwrap();
        let peer = ConnectionId::new(682).unwrap();
        let mut sender = EndpointState::<128>::new_with_history_capacity(
            Role::Client,
            ConnectionLimits::default(),
            1200,
            32,
        );
        let mut receiver =
            EndpointState::<128>::new(Role::Server, ConnectionLimits::default(), 1200);
        sender.install_connection_ids(local, peer).unwrap();
        receiver.install_connection_ids(peer, local).unwrap();
        receiver.set_ack_policy(8, 5_000);
        sender
            .set_initial_peer_budget(
                INITIAL_MAX_DATA,
                INITIAL_MAX_STREAM_DATA,
                DEFAULT_MAX_IN_FLIGHT_PACKETS,
            )
            .unwrap();
        sender.open_send_stream(4, INITIAL_MAX_STREAM_DATA).unwrap();
        // Model a steady-state flight after slow-start expands; this test
        // validates the receiver's complete drain, not cwnd growth.
        sender.congestion.congestion_window = 32 * 1200;

        let mut packet = [0u8; 256];
        // Match Recovery's `UDP_RECEIVE_DRAIN_LIMIT`. The device drains the
        // lwIP queue through the deferred callback path, then polls once;
        // polling per packet would hide an ACK-per-recvfrom regression.
        for offset in 0..32u64 {
            let (used, _) = sender
                .encode_stream_packet(peer, 4, offset, false, b"x", &mut packet)
                .unwrap();
            let info = receiver
                .receive_with_committed_callbacks_deferred(&packet[..used], |_| Ok(1))
                .unwrap();
            assert!(info.stream);
        }

        let mut output = [0u8; 256];
        assert!(receiver.poll_transmit(&mut output).unwrap().is_some());
        assert!(receiver.poll_transmit(&mut output).unwrap().is_none());
        assert_eq!(receiver.stats().ack_packets, 1);
        assert_eq!(receiver.stats().ack_threshold_packets, 1);
    }

    #[test]
    fn committed_deferred_credit_keeps_negotiated_ack_frequency() {
        let local = ConnectionId::new(683).unwrap();
        let peer = ConnectionId::new(684).unwrap();
        let mut sender = EndpointState::<128>::new(Role::Client, ConnectionLimits::default(), 1200);
        let mut receiver =
            EndpointState::<128>::new(Role::Server, ConnectionLimits::default(), 1200);
        sender.install_connection_ids(local, peer).unwrap();
        receiver.install_connection_ids(peer, local).unwrap();
        receiver.set_ack_policy(8, 5_000);
        sender.open_send_stream(4, INITIAL_MAX_STREAM_DATA).unwrap();
        let mut packet = [0u8; 256];
        let mut output = [0u8; 256];
        for offset in 0..8u64 {
            let (used, _) = sender
                .encode_stream_packet(peer, 4, offset, false, b"x", &mut packet)
                .unwrap();
            receiver
                .receive_with_committed_callback_dispositions(&packet[..used], |_| {
                    Ok(CommittedStreamDisposition::Deferred)
                })
                .unwrap();
            assert_eq!(
                receiver.poll_transmit(&mut output).unwrap().is_some(),
                offset == 7,
            );
        }
        assert_eq!(receiver.stats().ack_threshold_packets, 1);
        assert_eq!(receiver.stats().ack_immediate_packets, 0);
    }

    #[test]
    fn ack_frequency_frame_sets_every_other_packet_and_reordering_exception() {
        let local = ConnectionId::new(69).unwrap();
        let peer = ConnectionId::new(70).unwrap();
        let mut sender = EndpointState::<128>::new(Role::Client, ConnectionLimits::default(), 1200);
        let mut receiver =
            EndpointState::<128>::new(Role::Server, ConnectionLimits::default(), 1200);
        sender.install_connection_ids(local, peer).unwrap();
        receiver.install_connection_ids(peer, local).unwrap();
        sender.request_ack_frequency(7, 1, 25_000, 1).unwrap();
        let mut packet = [0u8; 256];
        let used = sender.poll_transmit(&mut packet).unwrap().unwrap();
        let (_, header_len) = ShortHeader::decode(&packet[..used]).unwrap();
        assert_eq!(
            decode_frame(&packet[header_len..used]).unwrap().0,
            Frame::AckFrequency {
                sequence: 7,
                packet_threshold: 1,
                max_ack_delay_us: 25_000,
                reordering_threshold: 1,
            }
        );
        assert_eq!(
            receiver.receive_packet(&packet[..used]).unwrap(),
            TransportFrame::Control
        );
        assert_eq!(sender.stats().sent_control_packets, 1);
        assert_eq!(sender.stats().sent_stream_packets, 0);
        assert_eq!(receiver.ack_frequency, 2);
        assert_eq!(receiver.max_ack_delay_us, 25_000);
        assert_eq!(receiver.ack_reordering_threshold, 1);
        assert_eq!(receiver.stats().ack_frequency_received, 1);

        // A second ack-eliciting ACK_FREQUENCY frame reaches the every-other
        // threshold and is acknowledged.
        sender.request_ack_frequency(8, 1, 25_000, 1).unwrap();
        let used = sender.poll_transmit(&mut packet).unwrap().unwrap();
        receiver.receive_packet(&packet[..used]).unwrap();
        assert!(receiver.poll_transmit(&mut packet).unwrap().is_some());
        assert_eq!(receiver.stats().ack_threshold_packets, 1);
        assert_eq!(sender.stats().sent_control_packets, 2);

        // Older association state cannot roll back a newer ACK policy.
        sender.request_ack_frequency(7, 7, 1_000, 0).unwrap();
        let used = sender.poll_transmit(&mut packet).unwrap().unwrap();
        receiver.receive_packet(&packet[..used]).unwrap();
        assert_eq!(receiver.ack_frequency, 2);
        assert_eq!(receiver.max_ack_delay_us, 25_000);
        assert_eq!(receiver.ack_reordering_threshold, 1);
    }

    #[test]
    fn declared_losses_can_be_drained_before_a_single_pto_probe() {
        let local = ConnectionId::new(71).unwrap();
        let peer = ConnectionId::new(72).unwrap();
        let mut sender = EndpointState::<128>::new(Role::Client, ConnectionLimits::default(), 1200);
        sender.install_connection_ids(local, peer).unwrap();
        sender.open_send_stream(4, INITIAL_MAX_STREAM_DATA).unwrap();
        let mut packet = [0u8; 256];
        for index in 0..4u64 {
            sender
                .encode_stream_packet(peer, 4, index, false, &[index as u8], &mut packet)
                .unwrap();
        }
        // Selective-ACK loss detection retains these ranges for fresh-number
        // repair; `mark_lost` is intentionally different and retires an
        // externally discarded packet.
        for packet in sender.sent_packets.iter_mut().flatten().skip(1) {
            packet.lost = true;
        }
        let mut repairs = 0;
        while sender
            .retransmit_marked_loss(&mut packet)
            .unwrap()
            .is_some()
        {
            repairs += 1;
        }
        assert_eq!(repairs, 3);
        assert!(
            sender
                .retransmit_pto_probe(0, 250, &mut packet)
                .unwrap()
                .is_none()
        );
        let stats = sender.stats();
        assert_eq!(stats.loss_retransmitted_packets, 3);
        assert_eq!(stats.pto_retransmitted_packets, 0);
    }

    #[test]
    fn pto_sends_one_probe_then_backs_off_until_ack_progress() {
        let local = ConnectionId::new(81).unwrap();
        let peer = ConnectionId::new(82).unwrap();
        let mut sender = EndpointState::<128>::new(Role::Client, ConnectionLimits::default(), 1200);
        sender.install_connection_ids(local, peer).unwrap();
        sender.open_send_stream(4, INITIAL_MAX_STREAM_DATA).unwrap();
        sender.set_time(0);
        let mut packet = [0u8; 256];
        for index in 0..4u64 {
            sender
                .encode_stream_packet(peer, 4, index, false, &[index as u8], &mut packet)
                .unwrap();
        }

        // All four packets are overdue together. This must still emit just
        // one PTO probe, rather than a tight-loop burst of four retries.
        assert!(
            sender
                .retransmit_pto_probe(250, 250, &mut packet)
                .unwrap()
                .is_some()
        );
        assert!(
            sender
                .retransmit_pto_probe(250, 250, &mut packet)
                .unwrap()
                .is_none()
        );
        assert!(
            sender
                .retransmit_pto_probe(499, 250, &mut packet)
                .unwrap()
                .is_none()
        );
        // PTO backoff doubles the next wait.
        assert!(
            sender
                .retransmit_pto_probe(750, 250, &mut packet)
                .unwrap()
                .is_some()
        );
        assert!(
            sender
                .retransmit_pto_probe(1_750, 250, &mut packet)
                .unwrap()
                .is_some()
        );
        assert!(
            sender
                .retransmit_pto_probe(3_750, 250, &mut packet)
                .unwrap()
                .is_some()
        );
        // The common cap remains eight base PTOs; a fifth loss does not grow
        // the next retry to sixteen PTOs and strand a bounded operation.
        assert!(
            sender
                .retransmit_pto_probe(5_749, 250, &mut packet)
                .unwrap()
                .is_none()
        );
        assert!(
            sender
                .retransmit_pto_probe(5_750, 250, &mut packet)
                .unwrap()
                .is_some()
        );
        assert_eq!(sender.stats().pto_retransmitted_packets, 5);
    }

    #[test]
    fn selective_ack_gap_retransmits_before_pto() {
        let local = ConnectionId::new(63).unwrap();
        let peer = ConnectionId::new(64).unwrap();
        let mut sender = EndpointState::<128>::new(Role::Client, ConnectionLimits::default(), 1200);
        let mut receiver =
            EndpointState::<128>::new(Role::Server, ConnectionLimits::default(), 1200);
        sender.install_connection_ids(local, peer).unwrap();
        receiver.install_connection_ids(peer, local).unwrap();
        sender.open_send_stream(4, INITIAL_MAX_STREAM_DATA).unwrap();
        sender.set_time(10);
        let mut packet = [0u8; 256];
        let mut delivered = [[0u8; 256]; 2];
        let mut delivered_len = [0usize; 2];
        for index in 0..5u64 {
            let (used, _) = sender
                .encode_stream_packet(peer, 4, index, false, &[index as u8], &mut packet)
                .unwrap();
            if index >= 3 {
                let slot = (index - 3) as usize;
                delivered[slot][..used].copy_from_slice(&packet[..used]);
                delivered_len[slot] = used;
            }
        }
        receiver
            .receive_packet(&delivered[0][..delivered_len[0]])
            .unwrap();
        receiver
            .receive_packet(&delivered[1][..delivered_len[1]])
            .unwrap();
        let mut ack = [0u8; 256];
        let ack_len = receiver.poll_transmit(&mut ack).unwrap().unwrap();
        sender.receive_packet(&ack[..ack_len]).unwrap();

        // No 250 ms PTO elapsed: packet-threshold loss makes the missing
        // early range eligible immediately.
        let (_, retransmitted_pn) = sender
            .retransmit_due(10, 250, &mut packet)
            .unwrap()
            .unwrap();
        assert!(retransmitted_pn >= 5);
        let stats = sender.stats();
        assert_eq!(stats.loss_packet_threshold_packets, 2);
        assert_eq!(stats.loss_time_threshold_packets, 0);
        assert_eq!(stats.loss_events, 1);
        assert_eq!(stats.loss_retransmitted_packets, 1);
        assert_eq!(stats.pto_retransmitted_packets, 0);
    }

    #[test]
    fn acked_retransmission_advances_packet_threshold_loss_frontier() {
        let local = ConnectionId::new(0x63).unwrap();
        let peer = ConnectionId::new(0x64).unwrap();
        let mut sender = EndpointState::<128>::new(Role::Client, ConnectionLimits::default(), 1200);
        let mut receiver =
            EndpointState::<128>::new(Role::Server, ConnectionLimits::default(), 1200);
        sender.install_connection_ids(local, peer).unwrap();
        receiver.install_connection_ids(peer, local).unwrap();
        receiver.set_ack_policy(1, 5_000);
        sender.open_send_stream(4, INITIAL_MAX_STREAM_DATA).unwrap();
        sender.set_time(10);
        let mut packet = [0u8; 256];
        let mut original = 0;
        for index in 0..4u64 {
            let (_, packet_number) = sender
                .encode_stream_packet(peer, 4, index, false, &[index as u8], &mut packet)
                .unwrap();
            if index == 0 {
                original = packet_number;
            }
        }

        // Only the replacement for packet zero reaches the peer. Its fresh
        // packet number is still the ordinary QUIC loss frontier: packet one
        // is now three behind it and must not wait for a PTO.
        let (retry_len, _) = sender
            .retransmit_stream_packet(original, &mut packet)
            .unwrap()
            .unwrap();
        receiver.receive_packet(&packet[..retry_len]).unwrap();
        let mut ack = [0u8; 256];
        let ack_len = receiver.poll_transmit(&mut ack).unwrap().unwrap();
        sender.receive_packet(&ack[..ack_len]).unwrap();

        let (_, repaired_packet_number) = sender
            .retransmit_due(10, 600, &mut packet)
            .unwrap()
            .expect("packet-threshold repair must precede PTO");
        assert!(repaired_packet_number > 4);
        assert_eq!(sender.stats().loss_retransmitted_packets, 1);
        assert_eq!(sender.stats().pto_retransmitted_packets, 0);
    }

    #[test]
    fn duplicate_packet_is_reacked_without_duplicate_stream_delivery() {
        let local = ConnectionId::new(59).unwrap();
        let peer = ConnectionId::new(60).unwrap();
        let mut sender = EndpointState::<64>::new(Role::Client, ConnectionLimits::default(), 1200);
        let mut receiver =
            EndpointState::<64>::new(Role::Server, ConnectionLimits::default(), 1200);
        sender.install_connection_ids(local, peer).unwrap();
        receiver.install_connection_ids(peer, local).unwrap();
        sender.open_send_stream(4, INITIAL_MAX_STREAM_DATA).unwrap();
        let mut packet = [0u8; 256];
        let (used, _) = sender
            .encode_stream_packet(peer, 4, 0, true, b"once", &mut packet)
            .unwrap();
        assert!(matches!(
            receiver.receive_packet(&packet[..used]).unwrap(),
            TransportFrame::Stream { .. }
        ));
        receiver.stream_consumed(4, 4).unwrap();
        let mut ack = [0u8; 256];
        assert!(receiver.poll_transmit(&mut ack).unwrap().is_some());
        assert_eq!(
            receiver.receive_packet(&packet[..used]).unwrap(),
            TransportFrame::Control
        );
        assert!(receiver.poll_transmit(&mut ack).unwrap().is_some());
    }

    #[test]
    fn selective_ack_accepts_a_delayed_packet_below_largest_received() {
        let local = ConnectionId::new(61).unwrap();
        let peer = ConnectionId::new(62).unwrap();
        let mut sender = EndpointState::<64>::new(Role::Client, ConnectionLimits::default(), 1200);
        let mut receiver =
            EndpointState::<64>::new(Role::Server, ConnectionLimits::default(), 1200);
        sender.install_connection_ids(local, peer).unwrap();
        receiver.install_connection_ids(peer, local).unwrap();
        sender.open_send_stream(4, INITIAL_MAX_STREAM_DATA).unwrap();
        let mut first = [0u8; 256];
        let mut second = [0u8; 256];
        let (first_len, first_number) = sender
            .encode_stream_packet(peer, 4, 0, false, b"first", &mut first)
            .unwrap();
        let (second_len, second_number) = sender
            .encode_stream_packet(peer, 4, 5, true, b"second", &mut second)
            .unwrap();
        assert_eq!(first_number + 1, second_number);
        assert!(matches!(
            receiver.receive_packet(&second[..second_len]).unwrap(),
            TransportFrame::Stream { .. }
        ));
        assert!(matches!(
            receiver.receive_packet(&first[..first_len]).unwrap(),
            TransportFrame::Stream { .. }
        ));
        assert!(receiver.has_received_packet(first_number));
        assert!(receiver.has_received_packet(second_number));
    }

    #[test]
    fn failed_retransmission_keeps_original_ledger_entry() {
        let local = ConnectionId::new(57).unwrap();
        let peer = ConnectionId::new(58).unwrap();
        let mut sender = EndpointState::<64>::new(Role::Client, ConnectionLimits::default(), 1200);
        sender.install_connection_ids(local, peer).unwrap();
        sender.open_send_stream(4, INITIAL_MAX_STREAM_DATA).unwrap();
        let mut packet = [0u8; 256];
        let (_, packet_number) = sender
            .encode_stream_packet(peer, 4, 0, true, b"retained", &mut packet)
            .unwrap();
        let before_flight = sender.bytes_in_flight();
        let before_payload = sender.retained_payload_bytes();
        let mut too_small = [0u8; 1];
        assert_eq!(
            sender
                .retransmit_stream_packet(packet_number, &mut too_small)
                .unwrap_err(),
            Error::BufferTooSmall
        );
        assert_eq!(sender.history_len(), 1);
        assert_eq!(sender.retained_payload_bytes(), before_payload);
        assert_eq!(sender.bytes_in_flight(), before_flight);
        let (used, replacement) = sender
            .retransmit_stream_packet(packet_number, &mut packet)
            .unwrap()
            .unwrap();
        assert!(used > 0);
        assert_ne!(replacement, packet_number);
    }

    #[test]
    fn connection_close_is_directional_and_terminal() {
        let local = ConnectionId::new(71).unwrap();
        let peer = ConnectionId::new(72).unwrap();
        let mut sender = EndpointState::<64>::new(Role::Client, ConnectionLimits::default(), 1200);
        let mut receiver =
            EndpointState::<64>::new(Role::Server, ConnectionLimits::default(), 1200);
        sender.install_connection_ids(local, peer).unwrap();
        receiver.install_connection_ids(peer, local).unwrap();
        sender.close(0x42);
        let mut packet = [0u8; 128];
        let used = sender.poll_close(&mut packet).unwrap().unwrap();
        let (header, _) = ShortHeader::decode(&packet[..used]).unwrap();
        assert_eq!(header.dcid, peer);
        assert_eq!(header.packet_number, 0);
        assert_eq!(
            receiver.receive_packet(&packet[..used]),
            Ok(TransportFrame::Control)
        );
        assert_eq!(receiver.close_code(), Some(0x42));
        assert!(receiver.is_closed());
        assert_eq!(
            receiver.receive_packet(&packet[..used]),
            Err(Error::Invalid)
        );
        assert_eq!(sender.poll_close(&mut packet).unwrap().unwrap(), used);
        assert_eq!(
            ShortHeader::decode(&packet[..used])
                .unwrap()
                .0
                .packet_number,
            1
        );
    }

    #[test]
    fn retransmission_payload_limit_is_explicit_for_embedded_profiles() {
        let cid = ConnectionId::new(53).unwrap();
        let peer = ConnectionId::new(54).unwrap();
        let mut sender = EndpointState::<4>::new(Role::Client, ConnectionLimits::default(), 1200);
        sender.install_connection_ids(cid, peer).unwrap();
        sender.open_send_stream(4, INITIAL_MAX_STREAM_DATA).unwrap();
        let mut packet = [0u8; 128];
        assert_eq!(
            sender
                .encode_stream_packet(peer, 4, 0, true, b"12345", &mut packet)
                .unwrap_err(),
            Error::RetransmissionTooLarge
        );
    }

    #[test]
    fn retransmission_due_uses_fake_clock_and_pto() {
        let cid = ConnectionId::new(54).unwrap();
        let peer = ConnectionId::new(55).unwrap();
        let mut sender = EndpointState::<32>::new(Role::Client, ConnectionLimits::default(), 1200);
        sender.install_connection_ids(cid, peer).unwrap();
        sender.open_send_stream(4, INITIAL_MAX_STREAM_DATA).unwrap();
        sender.set_time(100_000);
        let mut packet = [0u8; 128];
        let (_, pn) = sender
            .encode_stream_packet(peer, 4, 0, true, b"clock", &mut packet)
            .unwrap();
        sender.set_time(109_999);
        assert!(
            sender
                .retransmit_due(109_999, 10_000, &mut packet)
                .unwrap()
                .is_none()
        );
        let (_, retransmitted) = sender
            .retransmit_due(110_000, 10_000, &mut packet)
            .unwrap()
            .unwrap();
        assert_ne!(pn, retransmitted);
    }

    #[test]
    fn retransmission_probe_survives_reduced_congestion_window() {
        let cid = ConnectionId::new(0x71).unwrap();
        let peer = ConnectionId::new(0x72).unwrap();
        let mut sender = EndpointState::<32>::new(Role::Client, ConnectionLimits::default(), 1200);
        sender.install_connection_ids(cid, peer).unwrap();
        sender.open_send_stream(4, INITIAL_MAX_STREAM_DATA).unwrap();
        let mut packet = [0u8; 128];
        let (_, packet_number) = sender
            .encode_stream_packet(peer, 4, 0, true, b"probe", &mut packet)
            .unwrap();
        // Simulate loss recovery after cwnd was reduced below unrelated data
        // still in flight.  Rejecting the replacement here killed the live
        // UDP connection instead of performing its bounded PTO probe.
        sender.congestion.congestion_window = 1;
        sender.congestion.bytes_in_flight = 1;
        sender
            .sent_packets
            .iter_mut()
            .flatten()
            .find(|sent| sent.packet_number == packet_number)
            .unwrap()
            .lost = true;
        assert!(
            sender
                .retransmit_stream_packet(packet_number, &mut packet)
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn ack_clock_updates_rtt_and_adaptive_pto() {
        let local = ConnectionId::new(55).unwrap();
        let peer = ConnectionId::new(56).unwrap();
        let mut sender = EndpointState::<128>::new(Role::Client, ConnectionLimits::default(), 1200);
        let mut receiver =
            EndpointState::<128>::new(Role::Server, ConnectionLimits::default(), 1200);
        sender.install_connection_ids(local, peer).unwrap();
        receiver.install_connection_ids(peer, local).unwrap();
        sender.open_send_stream(4, INITIAL_MAX_STREAM_DATA).unwrap();
        sender.set_time(100_000);
        let mut packet = [0u8; 256];
        let (used, _) = sender
            .encode_stream_packet(peer, 4, 0, true, b"rtt", &mut packet)
            .unwrap();
        let TransportFrame::Stream { frame, .. } =
            receiver.receive_packet(&packet[..used]).unwrap()
        else {
            panic!("expected stream");
        };
        receiver
            .stream_consumed(frame.id, frame.data.len())
            .unwrap();
        receiver.set_time(150_000);
        let mut ack = [0u8; 256];
        let ack_len = receiver.poll_transmit(&mut ack).unwrap().unwrap();
        sender.set_time(150_000);
        sender.receive_packet(&ack[..ack_len]).unwrap();
        assert_eq!(sender.latest_rtt(), Some(50_000));
        assert_eq!(sender.smoothed_rtt(), Some(50_000));
        assert_eq!(sender.min_rtt(), Some(50_000));
        assert_eq!(sender.rtt_variance(), 25_000);
        assert_eq!(sender.pto_timeout(), 175_000);
    }

    #[test]
    fn fault_queue_exercises_retransmission_after_latency_and_loss() {
        let local = ConnectionId::new(61).unwrap();
        let peer = ConnectionId::new(62).unwrap();
        let mut sender = EndpointState::<128>::new(Role::Client, ConnectionLimits::default(), 1200);
        let mut receiver =
            EndpointState::<128>::new(Role::Server, ConnectionLimits::default(), 1200);
        sender.install_connection_ids(local, peer).unwrap();
        receiver.install_connection_ids(peer, local).unwrap();
        sender.open_send_stream(4, INITIAL_MAX_STREAM_DATA).unwrap();
        sender.open_send_stream(8, INITIAL_MAX_STREAM_DATA).unwrap();
        let mut link = crate::fake::FaultQueue::new(crate::fake::FaultConfig {
            latency_ticks: 4,
            drop_every: Some(2),
            duplicate: false,
            reorder: true,
            mtu: 1200,
        });
        let mut packet = [0u8; 256];
        let (first_len, _) = sender
            .encode_stream_packet(peer, 4, 0, true, b"one", &mut packet)
            .unwrap();
        link.submit_at(0, &packet[..first_len]).unwrap();
        let first = link.poll_owned(4);
        assert_eq!(first.len(), 1);
        receiver.receive_packet(first[0].bytes()).unwrap();
        let (second_len, second_pn) = sender
            .encode_stream_packet(peer, 8, 0, true, b"two", &mut packet)
            .unwrap();
        link.submit_at(4, &packet[..second_len]).unwrap();
        assert!(link.poll_owned(8).is_empty());
        let (retry_len, retry_pn) = sender
            .retransmit_stream_packet(second_pn, &mut packet)
            .unwrap()
            .unwrap();
        assert_ne!(retry_pn, second_pn);
        link.submit_at(8, &packet[..retry_len]).unwrap();
        let retry = link.poll_owned(12);
        assert_eq!(retry.len(), 1);
        assert!(matches!(
            receiver.receive_packet(retry[0].bytes()).unwrap(),
            TransportFrame::Stream { .. }
        ));
        assert_eq!(sender.send.sent_data, 6);
    }

    #[test]
    fn fault_queue_exercises_object_record_retransmission() {
        let local = ConnectionId::new(63).unwrap();
        let peer = ConnectionId::new(64).unwrap();
        let mut sender = EndpointState::<256>::new(Role::Client, ConnectionLimits::default(), 1200);
        let mut receiver =
            EndpointState::<256>::new(Role::Server, ConnectionLimits::default(), 1200);
        sender.install_connection_ids(local, peer).unwrap();
        receiver.install_connection_ids(peer, local).unwrap();
        sender.open_send_stream(4, INITIAL_MAX_STREAM_DATA).unwrap();
        let object_record = [1, 0, 0, 0, 3, 0xa1, 0x01, 0x02];
        let mut link = crate::fake::FaultQueue::new(crate::fake::FaultConfig {
            latency_ticks: 7,
            drop_every: Some(2),
            duplicate: false,
            reorder: true,
            mtu: 1200,
        });
        let mut packet = [0u8; 512];
        let (first_len, _) = sender
            .encode_stream_packet(peer, 4, 0, false, &object_record[..4], &mut packet)
            .unwrap();
        link.submit_at(0, &packet[..first_len]).unwrap();
        for packet in link.poll_owned(7) {
            receiver.receive_packet(packet.bytes()).unwrap();
        }
        let (second_len, second_pn) = sender
            .encode_stream_packet(peer, 4, 4, true, &object_record[4..], &mut packet)
            .unwrap();
        link.submit_at(7, &packet[..second_len]).unwrap();
        assert!(link.poll_owned(14).is_empty());
        let (retry_len, retry_pn) = sender
            .retransmit_stream_packet(second_pn, &mut packet)
            .unwrap()
            .unwrap();
        assert_ne!(retry_pn, second_pn);
        link.submit_at(14, &packet[..retry_len]).unwrap();
        let mut delivered = 0;
        for packet in link.poll_owned(21) {
            if let TransportFrame::Stream { frame, .. } =
                receiver.receive_packet(packet.bytes()).unwrap()
            {
                assert_eq!(frame.id, 4);
                delivered += frame.data.len();
            }
        }
        assert_eq!(delivered, object_record.len() - 4);
    }

    #[test]
    fn retransmission_profiles_stay_bounded_under_loss_and_latency() {
        fn profile<const H: usize>() {
            let local = ConnectionId::new(65 + H as u64).unwrap();
            let peer = ConnectionId::new(100 + H as u64).unwrap();
            let mut sender = EndpointState::<64>::new_with_history_capacity(
                Role::Client,
                ConnectionLimits::default(),
                1200,
                H,
            );
            let mut receiver =
                EndpointState::<64>::new(Role::Server, ConnectionLimits::default(), 1200);
            sender.congestion.congestion_window = (H as u64).saturating_mul(1200);
            sender.congestion.slow_start_threshold = sender.congestion.congestion_window;
            sender.install_connection_ids(local, peer).unwrap();
            receiver.install_connection_ids(peer, local).unwrap();
            sender.open_send_stream(4, INITIAL_MAX_STREAM_DATA).unwrap();
            let mut link = crate::fake::FaultQueue::new(crate::fake::FaultConfig {
                latency_ticks: 10,
                drop_every: Some(3),
                duplicate: true,
                reorder: true,
                mtu: 1200,
            });
            let mut now = 0u64;
            let mut offset = 0u64;
            for batch in 0..8 {
                // The profile test intentionally marks every unrecovered
                // packet lost at the end of a batch. Restore a generous
                // configured flight window for the next bounded-ledger
                // exercise so large capacities test retention rather than
                // NewReno collapse alone.
                sender.congestion.congestion_window = (H as u64).saturating_mul(1200);
                sender.congestion.slow_start_threshold = sender.congestion.congestion_window;
                let mut packet_numbers = Vec::new();
                for slot in 0..H {
                    let mut packet = [0u8; 256];
                    let data = [((batch * H + slot) & 0xff) as u8; 8];
                    let (_, packet_number) = sender
                        .encode_stream_packet(peer, 4, offset, false, &data, &mut packet)
                        .unwrap_or_else(|error| {
                            panic!(
                                "H={H} batch={batch} slot={slot} offset={offset} error={error:?}"
                            )
                        });
                    let used = ShortHeader::decode(&packet).unwrap().1;
                    let (_, frame_len) = decode_frame(&packet[used..]).unwrap();
                    link.submit_at(now, &packet[..used + frame_len]).unwrap();
                    packet_numbers.push(packet_number);
                    offset += data.len() as u64;
                    assert!(sender.history_len() <= H);
                    assert!(
                        sender.history_len() * sender.retransmission_payload_capacity() <= H * 64
                    );
                }
                assert_eq!(sender.history_len(), H);
                now += 10;
                for packet in link.poll_owned(now) {
                    if let TransportFrame::Stream { frame, .. } =
                        receiver.receive_packet(packet.bytes()).unwrap()
                    {
                        receiver
                            .stream_consumed(frame.id, frame.data.len())
                            .unwrap();
                        let mut ack = [0u8; 256];
                        if let Some(used) = receiver.poll_transmit(&mut ack).unwrap() {
                            sender.receive_packet(&ack[..used]).unwrap();
                        }
                    }
                }
                // A PTO retransmits any packet still retained after the
                // lossy delivery pass. Each retransmission replaces its old
                // ledger slot and is delivered after the same fake latency.
                let mut active_numbers = packet_numbers;
                for packet_number in &mut active_numbers {
                    let mut retry = [0u8; 256];
                    let retransmission = sender
                        .retransmit_stream_packet(*packet_number, &mut retry)
                        .unwrap_or_else(|error| {
                            assert_eq!(error, Error::Invalid);
                            None
                        });
                    if let Some((used, replacement)) = retransmission {
                        *packet_number = replacement;
                        now += 10;
                        if let TransportFrame::Stream { frame, .. } =
                            receiver.receive_packet(&retry[..used]).unwrap()
                        {
                            receiver
                                .stream_consumed(frame.id, frame.data.len())
                                .unwrap();
                            let mut ack = [0u8; 256];
                            if let Some(ack_len) = receiver.poll_transmit(&mut ack).unwrap() {
                                sender.receive_packet(&ack[..ack_len]).unwrap();
                            }
                        }
                    }
                    assert!(sender.history_len() <= H);
                }
                for packet_number in active_numbers {
                    sender.mark_lost(packet_number);
                }
                assert_eq!(sender.history_len(), 0, "H={H}");
                assert_eq!(sender.retained_payload_bytes(), 0, "H={H}");
            }
        }

        profile::<1>();
        profile::<2>();
        profile::<4>();
        profile::<16>();
        profile::<64>();
        profile::<512>();
    }

    #[test]
    fn runtime_retransmission_profiles_report_real_memory_bounds() {
        for selected in [4, 32, 512] {
            let endpoint = EndpointState::<DEFAULT_MAX_PACKET_SIZE>::new_with_history_capacity(
                Role::Client,
                ConnectionLimits::default(),
                DEFAULT_MAX_PACKET_SIZE as u64,
                selected,
            );
            assert_eq!(endpoint.history_storage_slots(), selected);
            assert_eq!(
                endpoint.retransmission_capacity_bytes(),
                selected * DEFAULT_MAX_PACKET_SIZE
            );
        }

        fn stress<const H: usize, const P: usize>() {
            let local = ConnectionId::new(0x900 + H as u64).unwrap();
            let peer = ConnectionId::new(0xa00 + H as u64).unwrap();
            let mut limits = ConnectionLimits::default();
            limits.max_data = 4 * 1024 * 1024;
            limits.max_stream_data = 2 * 1024 * 1024;
            let mut sender =
                EndpointState::<P>::new_with_history_capacity(Role::Client, limits, 1200, H);
            let mut receiver = EndpointState::<P>::new(Role::Server, limits, 1200);
            sender.install_connection_ids(local, peer).unwrap();
            receiver.install_connection_ids(peer, local).unwrap();
            sender.open_send_stream(4, limits.max_stream_data).unwrap();
            sender.congestion.congestion_window = (H as u64).saturating_mul(1500);
            sender.congestion.slow_start_threshold = sender.congestion.congestion_window;
            let mut link = crate::fake::FaultQueue::new(crate::fake::FaultConfig {
                latency_ticks: 25,
                drop_every: Some(3),
                duplicate: true,
                reorder: true,
                mtu: 1400,
            });
            let mut packet = [0u8; 1600];
            let mut packet_numbers = Vec::new();
            // Keep below the 1400-byte bearer MTU while filling the smaller
            // profile slots completely; the host profile therefore retains
            // 64 * 1200 bytes during this stress pass.
            let payload_len = P.min(1200);
            for index in 0..H {
                let data = vec![index as u8; payload_len];
                let (used, number) = sender
                    .encode_stream_packet(
                        peer,
                        4,
                        (index * payload_len) as u64,
                        false,
                        &data,
                        &mut packet,
                    )
                    .unwrap();
                link.submit_at(0, &packet[..used]).unwrap();
                packet_numbers.push(number);
                assert!(sender.retained_payload_bytes() <= sender.retransmission_capacity_bytes());
            }
            for packet in link.poll_owned(25) {
                if let TransportFrame::Stream { frame, .. } =
                    receiver.receive_packet(packet.bytes()).unwrap()
                {
                    receiver
                        .stream_consumed(frame.id, frame.data.len())
                        .unwrap();
                }
            }
            for number in packet_numbers {
                let mut retry = [0u8; 1600];
                sender.congestion.congestion_window = (H as u64).saturating_mul(1500);
                sender.congestion.slow_start_threshold = sender.congestion.congestion_window;
                match sender.retransmit_stream_packet(number, &mut retry) {
                    Ok(_) | Err(Error::Invalid) => {}
                    Err(error) => panic!("profile H={H} P={P} retransmission: {error:?}"),
                }
                assert!(sender.retained_payload_bytes() <= sender.retransmission_capacity_bytes());
            }
        }

        stress::<4, 256>();
        stress::<16, 512>();
        stress::<64, 1400>();
    }

    #[test]
    fn packet_numbers_increase_for_stream_and_control_output() {
        let cid = ConnectionId::new(7).unwrap();
        let sender_cid = ConnectionId::new(8).unwrap();
        let mut sender = EndpointState::<DEFAULT_MAX_PACKET_SIZE>::new_established(
            Role::Client,
            ConnectionLimits::default(),
            1200,
            ConnectionIds::new(sender_cid, cid).unwrap(),
        );
        sender.open_send_stream(4, INITIAL_MAX_STREAM_DATA).unwrap();
        let mut packet = [0u8; 256];
        let (_, first) = sender
            .encode_stream_packet(cid, 4, 0, true, b"x", &mut packet)
            .unwrap();
        assert_eq!(first, 0);
        let mut receiver = EndpointState::<DEFAULT_MAX_PACKET_SIZE>::new_established(
            Role::Server,
            ConnectionLimits::default(),
            1200,
            ConnectionIds::new(cid, sender_cid).unwrap(),
        );
        let used = sender
            .encode_stream_packet(cid, 4, 1, true, b"y", &mut packet)
            .unwrap()
            .0;
        assert_eq!(
            ShortHeader::decode(&packet[..used])
                .unwrap()
                .0
                .packet_number,
            1
        );
        receiver.receive_packet(&packet[..used]).unwrap();
        receiver.stream_consumed(4, 1).unwrap();
        let mut control = [0u8; 256];
        let control_len = receiver.poll_transmit(&mut control).unwrap().unwrap();
        assert_eq!(
            ShortHeader::decode(&control[..control_len])
                .unwrap()
                .0
                .packet_number,
            0
        );
    }

    #[test]
    fn established_probe_is_ack_eliciting_and_uses_shared_packet_numbers() {
        let client = ConnectionId::new(811).unwrap();
        let server = ConnectionId::new(812).unwrap();
        let mut sender = EndpointState::<DEFAULT_MAX_PACKET_SIZE>::new_established(
            Role::Client,
            ConnectionLimits::default(),
            1200,
            ConnectionIds::new(client, server).unwrap(),
        );
        let mut receiver = EndpointState::<DEFAULT_MAX_PACKET_SIZE>::new_established(
            Role::Server,
            ConnectionLimits::default(),
            1200,
            ConnectionIds::new(server, client).unwrap(),
        );
        receiver.set_ack_policy(1, 0);
        let mut probe = [0u8; 64];
        let (used, number) = sender.encode_probe_packet(server, &mut probe).unwrap();
        assert_eq!(number, 0);
        assert!(matches!(
            receiver.receive_packet(&probe[..used]),
            Ok(TransportFrame::Control)
        ));
        let mut ack = [0u8; 64];
        let ack_len = receiver.poll_transmit(&mut ack).unwrap().unwrap();
        assert!(sender.receive_packet(&ack[..ack_len]).is_ok());
        sender.open_send_stream(4, INITIAL_MAX_STREAM_DATA).unwrap();
        let (_, next) = sender
            .encode_stream_packet(server, 4, 0, true, b"x", &mut probe)
            .unwrap();
        assert_eq!(next, 1);
    }

    #[test]
    fn established_packet_numbers_continue_after_bootstrap() {
        let cid = ConnectionId::new(70).unwrap();
        let peer = ConnectionId::new(71).unwrap();
        let mut endpoint = EndpointState::<DEFAULT_MAX_PACKET_SIZE>::new(
            Role::Client,
            ConnectionLimits::default(),
            1200,
        );
        endpoint.install_connection_ids(cid, peer).unwrap();
        endpoint.continue_packet_numbers_from(3).unwrap();
        endpoint
            .open_send_stream(4, INITIAL_MAX_STREAM_DATA)
            .unwrap();
        let mut packet = [0u8; 256];
        let (used, packet_number) = endpoint
            .encode_stream_packet(peer, 4, 0, true, b"bootstrap-continuation", &mut packet)
            .unwrap();
        assert_eq!(packet_number, 3);
        assert_eq!(
            ShortHeader::decode(&packet[..used])
                .unwrap()
                .0
                .packet_number,
            3
        );
        assert_eq!(endpoint.next_packet_number, 4);
        assert_eq!(
            endpoint.continue_packet_numbers_from(2),
            Err(Error::Invalid)
        );
    }

    #[test]
    fn concurrent_streams_share_connection_but_keep_credit_independent() {
        let limits = ConnectionLimits {
            max_data: 16,
            max_stream_data: 8,
            max_streams_bidi: 1,
            max_streams_uni: 2,
        };
        let mut sender = EndpointState::<DEFAULT_MAX_PACKET_SIZE>::new(Role::Server, limits, 64);
        let mut receiver = EndpointState::<DEFAULT_MAX_PACKET_SIZE>::new(Role::Client, limits, 64);
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
            let (Frame::Stream(stream), _) = decode_frame(&packet[header_len..used]).unwrap()
            else {
                panic!("expected stream frame");
            };
            receiver
                .receive
                .accept(stream.id, stream.offset, stream.data.len(), stream.fin)
                .unwrap();
            receiver.observe_packet(header.packet_number);
            receiver
                .receive
                .consume(stream.id, stream.data.len() as u64)
                .unwrap();
        }
        assert_eq!(
            sender.congestion.bytes_in_flight,
            packet_lengths[0] + packet_lengths[1]
        );
        assert_eq!(sender.send.stream_credit(3), Some(8));
        assert_eq!(sender.send.stream_credit(7), Some(8));
        sender.acked(packet_lengths[0]);
        sender.acked(packet_lengths[1]);
        sender.send.extend_stream(3, 16).unwrap();
        assert!(sender.reserve_send(3, 4, 4).is_ok());
        assert_eq!(sender.send.stream(7).unwrap().sent, 4);
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

    #[test]
    fn newreno_reduces_once_for_one_lost_flight() {
        let mut c = CongestionController::new(1200);
        for _ in 0..10 {
            assert!(c.on_packet_sent(1200));
        }
        assert_eq!(c.congestion_window, 12_000);
        // Multiple gaps reported in later ACKs belong to the original
        // ten-packet flight. They all leave flight accounting, but only the
        // first starts recovery and cuts cwnd.
        c.on_packet_lost(1200, 1, 10);
        assert_eq!(c.congestion_window, 6_000);
        c.on_packet_lost(1200, 2, 10);
        c.on_packet_lost(1200, 7, 10);
        assert_eq!(c.congestion_window, 6_000);
        assert_eq!(c.bytes_in_flight, 8_400);

        // A loss sent after that boundary is a new congestion event.
        c.on_packet_lost(1200, 11, 14);
        assert_eq!(c.congestion_window, 3_000);
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
        // Use the same retained-packet capacity as the default host and ESP
        // endpoint. The former 1200-byte synthetic MTU exceeded this
        // endpoint's 1024-byte packet store, and the old loop silently
        // treated `RetransmissionTooLarge` as backpressure without ever
        // transferring a byte.
        let mtu = DEFAULT_MAX_PACKET_SIZE;
        let dcid = ConnectionId::new(1).unwrap();
        let mut sender = EndpointState::<DEFAULT_MAX_PACKET_SIZE>::new(
            Role::Server,
            ConnectionLimits::default(),
            mtu as u64,
        );
        let mut receiver = EndpointState::<DEFAULT_MAX_PACKET_SIZE>::new(
            Role::Client,
            ConnectionLimits::default(),
            mtu as u64,
        );
        sender
            .install_connection_ids(ConnectionId::new(2).unwrap(), dcid)
            .unwrap();
        sender.open_send_stream(3, INITIAL_MAX_STREAM_DATA).unwrap();

        struct Flight {
            packet_number: u32,
            offset: u64,
            packet: Vec<u8>,
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
        let mut receiver_packet_number = 0u32;
        let started = Instant::now();

        while contiguous < total {
            let mut sent_this_round = 0u32;
            while next_offset < total && sender.congestion.can_send(mtu as u64) {
                let len = (total - next_offset).min((mtu - 32) as u64) as usize;
                let data = vec![0xa5; len];
                let mut packet = vec![0u8; mtu];
                let (used, packet_number) = match sender.encode_stream_packet(
                    dcid,
                    3,
                    next_offset,
                    next_offset + len as u64 == total,
                    &data,
                    &mut packet,
                ) {
                    Ok(value) => value,
                    Err(Error::HistoryFull) => break,
                    Err(error) => panic!("memory stream send offset={next_offset}: {error:?}"),
                };
                packet.truncate(used);
                flights.push_back(Flight {
                    packet_number,
                    offset: next_offset,
                    packet: packet.clone(),
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
                let (_, header_len) = ShortHeader::decode(&flight.packet).unwrap();
                let (Frame::Stream(stream), _) =
                    decode_frame(&flight.packet[header_len..]).unwrap()
                else {
                    panic!("memory stream packet was not a stream frame");
                };
                assert_eq!(stream.id, 3);
                receiver
                    .receive
                    .accept(stream.id, stream.offset, stream.data.len(), stream.fin)
                    .unwrap();
                // The packet header contains a truncated packet number.
                // Production reconstructs it using connection state before
                // ACKing; this in-memory test already owns the authoritative
                // sent value, so never turn a wrap after 255 packets into a
                // bogus ACK range by using `ShortHeader::decode` directly.
                receiver.observe_packet(flight.packet_number);
                received.insert(flight.packet_number);
                segments.entry(stream.offset).or_insert(stream.data.len());
            }

            while let Some(len) = segments.remove(&contiguous) {
                contiguous += len as u64;
                receiver.receive.consume(3, len as u64).unwrap();
            }
            // A FIN closes the receive stream as soon as its final range is
            // consumed. There is no next byte to credit in that terminal
            // turn, so model the real handler boundary rather than trying to
            // extend a stream the endpoint has retired.
            if contiguous < total {
                receiver.receive.extend_connection_credit(INITIAL_MAX_DATA);
                receiver
                    .receive
                    .extend_stream_credit(3, INITIAL_MAX_STREAM_DATA)
                    .unwrap_or_else(|error| {
                        panic!(
                            "stream credit after contiguous={contiguous} total={total} max={:?}: {error:?}",
                            receiver.receive.stream_max_data(3)
                        )
                    });
                sender
                    .send
                    .extend_connection(receiver.receive.connection.consumed + INITIAL_MAX_DATA);
                sender
                    .send
                    .extend_stream(3, receiver.receive.stream_max_data(3).unwrap())
                    .unwrap();
            }

            if let Some(largest) = received.get(0).map(|range| range.end) {
                let mut ack = vec![0u8; mtu];
                let mut used = ShortHeader {
                    flags: FLAG_FIXED,
                    dcid,
                    packet_number: receiver_packet_number,
                    packet_number_len: 1,
                }
                .encode(&mut ack)
                .unwrap();
                used += Frame::AckRanges {
                    largest,
                    delay: 0,
                    ranges: received,
                }
                .encode(&mut ack[used..])
                .unwrap();
                receiver_packet_number = receiver_packet_number.saturating_add(1);
                sender.receive_ack_packet(&ack[..used]).unwrap();
            }
            for flight in flights.iter_mut().filter(|flight| !flight.acked) {
                if received.contains(flight.packet_number) {
                    flight.acked = true;
                }
            }
            let mut had_resend = false;
            loop {
                let mut packet = vec![0u8; mtu];
                let Some((used, packet_number)) =
                    sender.retransmit_marked_loss(&mut packet).unwrap()
                else {
                    break;
                };
                let (_, header_len) = ShortHeader::decode(&packet[..used]).unwrap();
                let (Frame::Stream(stream), _) = decode_frame(&packet[header_len..used]).unwrap()
                else {
                    panic!("memory stream retransmission was not a stream frame");
                };
                let offset = stream.offset;
                if let Some(original) = flights
                    .iter_mut()
                    .find(|flight| !flight.acked && flight.offset == offset)
                {
                    original.lost = true;
                }
                packet.truncate(used);
                flights.push_back(Flight {
                    packet_number,
                    offset,
                    packet,
                    acked: false,
                    lost: false,
                });
                packet_count += 1;
                retransmits += 1;
                had_resend = true;
            }
            flights.retain(|flight| !flight.acked && !flight.lost);
            assert!(
                sent_this_round != 0 || had_resend || contiguous == total,
                "memory stream stalled next_offset={next_offset} contiguous={contiguous} flights={} sender_credit={:?} receiver_credit={:?} cwnd={} history={}",
                flights.len(),
                sender.send.stream_credit(3),
                receiver.receive.stream_max_data(3),
                sender.congestion.congestion_window,
                sender.history_len(),
            );
        }

        let elapsed_ms = started.elapsed().as_millis().max(1);
        let bitrate_kbps = (total as u128 * 8_000 / elapsed_ms) as u64 / 1000;
        std::println!(
            "memory_stream bytes={} packets={} retransmits={} dropped_packet={} elapsed_ms={} bitrate_kbps={} cwnd={} consumed={}",
            total,
            packet_count,
            retransmits,
            dropped,
            elapsed_ms,
            bitrate_kbps,
            sender.congestion.congestion_window,
            contiguous,
        );
        assert_eq!(contiguous, total);
        assert!(retransmits > 0);
    }

    #[test]
    fn packet_number_length_uses_strict_half_window() {
        assert_eq!(packet_number_len(0, None), 1);
        assert_eq!(packet_number_len(127, Some(0)), 1);
        assert_eq!(packet_number_len(128, Some(0)), 2);
        assert_eq!(packet_number_len(32_767, Some(0)), 2);
        assert_eq!(packet_number_len(32_768, Some(0)), 3);
    }

    #[test]
    fn one_control_packet_returns_credit_for_each_consumed_stream() {
        let limits = ConnectionLimits {
            max_data: 32,
            max_stream_data: 16,
            max_streams_bidi: 2,
            max_streams_uni: 0,
        };
        let mut endpoint = EndpointState::<256>::new(Role::Client, limits, 256);
        endpoint
            .install_connection_ids(ConnectionId::new(7).unwrap(), ConnectionId::new(8).unwrap())
            .unwrap();
        endpoint.receive.accept(1, 0, 4, false).unwrap();
        endpoint.receive.accept(5, 0, 4, false).unwrap();
        endpoint.received_packets.insert(0);
        endpoint.stream_consumed(1, 4).unwrap();
        endpoint.stream_consumed(5, 4).unwrap();

        let mut packet = [0u8; 256];
        let used = endpoint.poll_transmit(&mut packet).unwrap().unwrap();
        let (_, mut offset) = ShortHeader::decode(&packet[..used]).unwrap();
        let mut credit_ids = [0u64; 2];
        let mut credits = 0usize;
        while offset < used {
            let (frame, frame_len) = decode_frame(&packet[offset..used]).unwrap();
            if let Frame::MaxStreamData { id, .. } = frame {
                credit_ids[credits] = id;
                credits += 1;
            }
            offset += frame_len;
        }
        assert_eq!(credits, 2);
        assert!(credit_ids.contains(&1));
        assert!(credit_ids.contains(&5));
    }

    #[test]
    fn deferred_consumption_batches_paired_connection_and_stream_credit() {
        let limits = ConnectionLimits {
            max_data: 64,
            max_stream_data: 64,
            max_streams_bidi: 1,
            max_streams_uni: 0,
        };
        let mut endpoint = EndpointState::<256>::new(Role::Server, limits, 256);
        endpoint
            .install_connection_ids(ConnectionId::new(7).unwrap(), ConnectionId::new(8).unwrap())
            .unwrap();
        endpoint.receive.accept(4, 0, 32, false).unwrap();
        endpoint.received_packets.insert(0);
        endpoint.highest_received_packet = Some(0);
        endpoint.largest_received_at = 1;
        endpoint.set_time(1);
        endpoint.stream_consumed_deferred(4, 32).unwrap();
        // Default delayed ACK policy is every second ack-eliciting packet or
        // 25 ms. This one-packet stream must publish both limits at the timer
        // deadline, without any application-specific wake or credit value.
        endpoint.set_time(26_000);
        let mut packet = [0u8; 256];
        let used = endpoint.poll_transmit(&mut packet).unwrap().unwrap();
        let (_, mut offset) = ShortHeader::decode(&packet[..used]).unwrap();
        let mut max_data = None;
        let mut max_stream_data = None;
        while offset < used {
            let (frame, frame_len) = decode_frame(&packet[offset..used]).unwrap();
            match frame {
                Frame::MaxData(max) => max_data = Some(max),
                Frame::MaxStreamData { id: 4, max } => max_stream_data = Some(max),
                _ => {}
            }
            offset += frame_len;
        }
        assert_eq!(max_data, Some(96));
        assert_eq!(max_stream_data, Some(96));
    }

    #[test]
    fn deferred_consumption_after_an_already_emitted_ack_gets_a_credit_deadline() {
        let limits = ConnectionLimits::with_receive_window(64);
        let mut endpoint = EndpointState::<256>::new(Role::Server, limits, 256);
        endpoint
            .install_connection_ids(ConnectionId::new(7).unwrap(), ConnectionId::new(8).unwrap())
            .unwrap();
        endpoint.receive.accept(4, 0, 32, false).unwrap();
        endpoint.received_packets.insert(0);
        endpoint.highest_received_packet = Some(0);
        endpoint.largest_received_at = 10;
        endpoint.set_time(10);

        // This models a receive turn that had already selected and encoded
        // its ACK before the application callback reports durable bytes.
        endpoint.control_pending = true;
        let mut packet = [0u8; 256];
        assert!(endpoint.poll_transmit(&mut packet).unwrap().is_some());
        assert_eq!(endpoint.next_bearer_deadline(), None);

        endpoint.stream_consumed_deferred(4, 32).unwrap();
        assert_eq!(endpoint.next_bearer_deadline(), Some(25_010));
        endpoint.set_time(25_009);
        assert!(endpoint.poll_transmit(&mut packet).unwrap().is_none());
        endpoint.set_time(25_010);
        let used = endpoint.poll_transmit(&mut packet).unwrap().unwrap();
        let (_, mut offset) = ShortHeader::decode(&packet[..used]).unwrap();
        let mut saw_credit = false;
        while offset < used {
            let (frame, frame_len) = decode_frame(&packet[offset..used]).unwrap();
            saw_credit |= matches!(frame, Frame::MaxData(_) | Frame::MaxStreamData { .. });
            offset += frame_len;
        }
        assert!(saw_credit);
    }

    #[test]
    fn unacknowledged_credit_retries_on_pto_not_delayed_ack_cadence() {
        let limits = ConnectionLimits::with_receive_window(64);
        let mut endpoint = EndpointState::<256>::new(Role::Server, limits, 256);
        endpoint
            .install_connection_ids(ConnectionId::new(7).unwrap(), ConnectionId::new(8).unwrap())
            .unwrap();
        endpoint.receive.accept(4, 0, 32, false).unwrap();
        endpoint.received_packets.insert(0);
        endpoint.highest_received_packet = Some(0);
        endpoint.largest_received_at = 10;
        endpoint.set_time(10);
        endpoint.stream_consumed_deferred(4, 32).unwrap();

        let mut packet = [0u8; 256];
        // The first MAX_* publication is delayed once with the ordinary ACK.
        endpoint.set_time(25_010);
        assert!(endpoint.poll_transmit(&mut packet).unwrap().is_some());
        assert!(endpoint.credit_packet_number.is_some());

        // An unreachable peer must not cause a new ACK+MAX packet at every
        // delayed-ACK wake. The next retry is transport-owned PTO (500 ms
        // before RTT samples), not the 25 ms ACK cadence seen in the capture.
        assert_eq!(endpoint.next_bearer_deadline(), Some(550_010));
        endpoint.set_time(60_000);
        assert!(endpoint.poll_transmit(&mut packet).unwrap().is_none());
        endpoint.set_time(550_009);
        assert!(endpoint.poll_transmit(&mut packet).unwrap().is_none());
        endpoint.set_time(550_010);
        assert!(endpoint.poll_transmit(&mut packet).unwrap().is_some());
        assert_eq!(endpoint.credit_retry_backoff, 1);
        assert_eq!(endpoint.next_bearer_deadline(), Some(1_600_010));
    }

    #[test]
    fn newer_consumption_is_not_cleared_by_an_older_credit_ack() {
        let limits = ConnectionLimits::with_receive_window(64);
        let mut endpoint = EndpointState::<256>::new(Role::Server, limits, 256);
        endpoint
            .install_connection_ids(ConnectionId::new(7).unwrap(), ConnectionId::new(8).unwrap())
            .unwrap();
        endpoint.receive.accept(4, 0, 32, false).unwrap();
        endpoint.received_packets.insert(0);
        endpoint.highest_received_packet = Some(0);
        endpoint.set_time(1);
        endpoint.stream_consumed(4, 32).unwrap();
        let mut packet = [0u8; 256];
        assert!(endpoint.poll_transmit(&mut packet).unwrap().is_some());
        assert!(endpoint.credit_packet_number.is_some());

        // More bytes arrive before the peer's ACK for that earlier MAX_*.
        // The new absolute credit must survive that late ACK.
        endpoint.receive.accept(4, 32, 16, false).unwrap();
        endpoint.stream_consumed_deferred(4, 16).unwrap();
        assert!(endpoint.credit_packet_number.is_some());
        assert!(endpoint.credit_pending);
        let credit_packet = endpoint.credit_packet_number.unwrap();
        let mut ack = [0u8; 256];
        let mut used = ShortHeader {
            flags: FLAG_FIXED,
            dcid: ConnectionId::new(7).unwrap(),
            packet_number: 1,
            packet_number_len: 1,
        }
        .encode(&mut ack)
        .unwrap();
        used += Frame::Ack {
            largest: credit_packet,
            delay: 0,
        }
        .encode(&mut ack[used..])
        .unwrap();
        endpoint.receive_packet(&ack[..used]).unwrap();
        assert!(endpoint.credit_pending);
        assert_eq!(endpoint.credit_packet_number, None);
        assert_eq!(endpoint.next_bearer_deadline(), Some(1));
        assert!(endpoint.poll_transmit(&mut packet).unwrap().is_some());
        assert!(endpoint.credit_packet_number.is_some());
    }

    #[test]
    fn packet_number_reconstruction_wraps_each_wire_width() {
        for (expected, number, len) in [
            (256u32, 256u32, 1u8),
            (65_536, 65_536, 2),
            (16_777_216, 16_777_216, 3),
        ] {
            let prefix = ShortHeaderPrefix {
                flags: FLAG_FIXED,
                dcid: ConnectionId::new(7).unwrap(),
                truncated_packet_number: number & ((1u32 << (len * 8)) - 1),
                packet_number_len: len,
                header_len: 0,
            };
            assert_eq!(prefix.reconstruct(expected).unwrap().packet_number, number);
        }
    }

    #[test]
    fn packet_number_outside_initial_window_is_rejected() {
        let prefix = ShortHeaderPrefix {
            flags: FLAG_FIXED,
            dcid: ConnectionId::new(7).unwrap(),
            truncated_packet_number: 255,
            packet_number_len: 1,
            header_len: 0,
        };
        assert_eq!(prefix.reconstruct(0), Err(Error::PacketNumberExhausted));
    }

    #[test]
    fn stateless_reset_is_opaque_and_recognized_only_by_its_issued_token() {
        let key = StatelessResetKey::from_device_secret(&[0x5a; 32]).unwrap();
        let stale = ConnectionId::new(0x1_2345).unwrap();
        let other = ConnectionId::new(0x1_2346).unwrap();
        let mut triggering = [0u8; 48];
        ShortHeader {
            flags: FLAG_FIXED,
            dcid: stale,
            packet_number: 7,
            packet_number_len: 1,
        }
        .encode(&mut triggering)
        .unwrap();
        let mut reset = [0u8; 48];
        let used = key
            .encode_for_unknown_cid(&triggering, stale, &mut reset)
            .unwrap()
            .unwrap();
        assert_eq!(used, triggering.len());
        assert!(key.token_for(stale).matches_packet(&reset[..used]));
        assert!(!key.token_for(other).matches_packet(&reset[..used]));
        assert_ne!(&reset[..used - STATELESS_RESET_TOKEN_LEN], &[0; 32]);
        assert!(
            key.encode_for_unknown_cid(&[0xc0; 48], stale, &mut reset)
                .unwrap()
                .is_none()
        );
        assert!(
            key.encode_for_unknown_cid(&triggering[..20], stale, &mut reset)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn established_dcid_rewrite_rejects_the_retired_zero_sentinel() {
        let mut packet = [0u8; 16];
        let used = ShortHeader {
            flags: FLAG_FIXED,
            dcid: ConnectionId::new(7).unwrap(),
            packet_number: 1,
            packet_number_len: 1,
        }
        .encode(&mut packet)
        .unwrap();
        let mut output = [0u8; 16];
        assert_eq!(
            rewrite_dcid(&packet[..used], ConnectionId::new(0).unwrap(), &mut output),
            Err(Error::Invalid)
        );
    }

    #[test]
    fn reset_key_is_a_labeled_derivation_of_the_device_secret() {
        let secret = [0x44; 32];
        let derived = StatelessResetKey::from_device_secret(&secret).unwrap();
        let different = StatelessResetKey::from_device_secret(&[0x45; 32]).unwrap();
        let cid = ConnectionId::new(0x111).unwrap();
        assert_ne!(derived.token_for(cid), different.token_for(cid));
        assert_eq!(
            derived.token_for(cid),
            StatelessResetKey::from_device_secret(&secret)
                .unwrap()
                .token_for(cid)
        );
        assert_eq!(
            StatelessResetKey::from_device_secret(&secret[..15]),
            Err(Error::Invalid)
        );
    }

    #[test]
    fn bootstrap_ack_carries_optional_peer_reset_token() {
        let key = StatelessResetKey::from_device_secret(&[0x91; 32]).unwrap();
        let client = ConnectionId::new(0x1234).unwrap();
        let server = ConnectionId::new(0x5678).unwrap();
        let token = key.token_for(server);
        let mut packet = [0u8; 128];
        let used = encode_bootstrap_open_ack_packet_with_limits_and_reset_token(
            client,
            server,
            0,
            ConnectionLimits::default(),
            Some(token),
            &mut packet,
        )
        .unwrap();
        let (_, ack) =
            decode_bootstrap_open_ack_packet_with_limits(&packet[..used], client).unwrap();
        assert_eq!(ack.server_receive_cid, server);
        assert_eq!(ack.stateless_reset_token, Some(token));
    }
}

#[cfg(test)]
mod stream_retirement_regressions {
    use super::*;

    /// Bug: a retired peer-initiated stream is re-opened by a late
    /// retransmission of its own data.
    ///
    /// `try_retire_stream` removes the stream from `ConnectionState` once the
    /// local send half is acknowledged and the receive half is consumed. It
    /// does not remember that the ID was used. If the ACK for the peer's
    /// request packet is lost, the peer's PTO retransmission (a fresh packet
    /// number, so not a duplicate) reaches `ConnectionState::accept`, which
    /// finds no stream, sees the ordinal below `max_streams_bidi`, and inserts
    /// a new `StreamState`. The application then receives offset 0 + FIN of
    /// the same request a second time. Retired peer stream IDs must be
    /// acknowledged and discarded, not reopened.
    #[test]
    fn late_retransmission_does_not_reopen_retired_peer_stream() {
        let client_cid = ConnectionId::new(0x11).unwrap();
        let server_cid = ConnectionId::new(0x22).unwrap();
        let mut client = EndpointState::<DEFAULT_MAX_PACKET_SIZE>::new(
            Role::Client,
            ConnectionLimits::default(),
            1200,
        );
        let mut server = EndpointState::<DEFAULT_MAX_PACKET_SIZE>::new(
            Role::Server,
            ConnectionLimits::default(),
            1200,
        );
        client
            .install_connection_ids(client_cid, server_cid)
            .unwrap();
        server
            .install_connection_ids(server_cid, client_cid)
            .unwrap();

        client.open_send_stream(4, INITIAL_MAX_STREAM_DATA).unwrap();
        let mut request = [0u8; 256];
        let (request_len, request_pn) = client
            .encode_stream_packet(server_cid, 4, 0, true, b"request", &mut request)
            .unwrap();
        let first = server
            .receive_packet_batch(&request[..request_len])
            .unwrap();
        assert_eq!(first.streams().count(), 1);
        server.stream_consumed(4, 7).unwrap();
        // The server's ACK for the request is lost on the air.
        let mut lost_ack = [0u8; 256];
        let _ = server.poll_transmit(&mut lost_ack).unwrap();

        server.open_send_stream(4, INITIAL_MAX_STREAM_DATA).unwrap();
        let mut response = [0u8; 256];
        let (response_len, _) = server
            .encode_stream_packet(client_cid, 4, 0, true, b"response", &mut response)
            .unwrap();
        client
            .receive_packet_batch(&response[..response_len])
            .unwrap();
        client.stream_consumed(4, 8).unwrap();
        let mut client_ack = [0u8; 256];
        let used = client.poll_transmit(&mut client_ack).unwrap().unwrap();
        server.receive_packet_batch(&client_ack[..used]).unwrap();
        assert_eq!(
            server.receive.stream_max_data(4),
            None,
            "precondition: the server retired stream 4"
        );

        // The client never saw an ACK for its request and retransmits it.
        let mut retransmission = [0u8; 256];
        let (retransmission_len, _) = client
            .retransmit_stream_packet(request_pn, &mut retransmission)
            .unwrap()
            .unwrap();
        let late = server
            .receive_packet_batch(&retransmission[..retransmission_len])
            .unwrap();
        assert_eq!(
            late.streams().count(),
            0,
            "a retired stream's data must not be delivered again"
        );
    }

    /// A reordered or retried control packet can carry MAX_STREAM_DATA for a
    /// stream the receiver has already retired. That credit is obsolete; the
    /// packet must still be accepted so the ACK it carries is not discarded.
    #[test]
    fn late_max_stream_data_for_retired_stream_keeps_packet() {
        let client_cid = ConnectionId::new(0x11).unwrap();
        let server_cid = ConnectionId::new(0x22).unwrap();
        let mut client = EndpointState::<DEFAULT_MAX_PACKET_SIZE>::new(
            Role::Client,
            ConnectionLimits::default(),
            1200,
        );
        let mut server = EndpointState::<DEFAULT_MAX_PACKET_SIZE>::new(
            Role::Server,
            ConnectionLimits::default(),
            1200,
        );
        client
            .install_connection_ids(client_cid, server_cid)
            .unwrap();
        server
            .install_connection_ids(server_cid, client_cid)
            .unwrap();
        client.open_send_stream(4, INITIAL_MAX_STREAM_DATA).unwrap();
        let mut request = [0u8; 256];
        let (request_len, _) = client
            .encode_stream_packet(server_cid, 4, 0, true, b"request", &mut request)
            .unwrap();
        server
            .receive_packet_batch(&request[..request_len])
            .unwrap();
        server.stream_consumed(4, 7).unwrap();
        server.open_send_stream(4, INITIAL_MAX_STREAM_DATA).unwrap();
        let mut response = [0u8; 256];
        let (response_len, _) = server
            .encode_stream_packet(client_cid, 4, 0, true, b"response", &mut response)
            .unwrap();
        client
            .receive_packet_batch(&response[..response_len])
            .unwrap();
        client.stream_consumed(4, 8).unwrap();
        let mut client_ack = [0u8; 256];
        let used = client.poll_transmit(&mut client_ack).unwrap().unwrap();
        server.receive_packet_batch(&client_ack[..used]).unwrap();
        assert!(
            server.receive.is_retired(4),
            "precondition: stream 4 retired"
        );

        let mut late = [0u8; 256];
        let mut used = ShortHeader {
            flags: FLAG_FIXED,
            dcid: server_cid,
            packet_number: 60,
            packet_number_len: 4,
        }
        .encode(&mut late)
        .unwrap();
        let mut ranges = AckRangeSet::new();
        ranges.insert_range(AckRange { start: 0, end: 1 });
        used += Frame::AckRanges {
            largest: 1,
            delay: 0,
            ranges,
        }
        .encode(&mut late[used..])
        .unwrap();
        used += Frame::MaxStreamData {
            id: 4,
            max: 1_000_000,
        }
        .encode(&mut late[used..])
        .unwrap();
        assert!(server.receive_packet_batch(&late[..used]).is_ok());
    }

    fn endpoint_pair() -> (EndpointState, EndpointState, ConnectionId, ConnectionId) {
        let client_cid = ConnectionId::new(0x11).unwrap();
        let server_cid = ConnectionId::new(0x22).unwrap();
        let mut client = EndpointState::<DEFAULT_MAX_PACKET_SIZE>::new(
            Role::Client,
            ConnectionLimits::default(),
            1200,
        );
        let mut server = EndpointState::<DEFAULT_MAX_PACKET_SIZE>::new(
            Role::Server,
            ConnectionLimits::default(),
            1200,
        );
        client
            .install_connection_ids(client_cid, server_cid)
            .unwrap();
        server
            .install_connection_ids(server_cid, client_cid)
            .unwrap();
        (client, server, client_cid, server_cid)
    }

    fn packet_frames(packet: &[u8]) -> std::vec::Vec<Frame<'_>> {
        let (_, mut offset) = ShortHeader::decode(packet).unwrap();
        let mut frames = std::vec::Vec::new();
        while offset < packet.len() {
            let (frame, used) = decode_frame(&packet[offset..]).unwrap();
            frames.push(frame);
            offset += used;
        }
        frames
    }

    /// Bug (fixed): a stream whose final event is an empty FIN never released
    /// its slot. `finish_stream` writes the FIN as a separate zero-length
    /// STREAM frame, and delivery does not report zero consumed bytes, so
    /// `try_retire_stream` ran only on consumption or on our FIN's ACK. When
    /// the peer's empty FIN arrived last, the stream stayed allocated; after
    /// enough exchanges `open_stream` failed with `StreamLimit` forever.
    #[test]
    fn empty_fin_after_consumption_retires_stream() {
        let (mut client, mut server, client_cid, server_cid) = endpoint_pair();
        client.open_send_stream(4, INITIAL_MAX_STREAM_DATA).unwrap();
        let mut packet = [0u8; 256];
        let (used, _) = client
            .encode_stream_packet(server_cid, 4, 0, false, b"abc", &mut packet)
            .unwrap();
        server.receive_packet_batch(&packet[..used]).unwrap();
        server.stream_consumed(4, 3).unwrap();

        server.open_send_stream(4, INITIAL_MAX_STREAM_DATA).unwrap();
        let (used, _) = server
            .encode_stream_packet(client_cid, 4, 0, true, b"ok", &mut packet)
            .unwrap();
        client.receive_packet_batch(&packet[..used]).unwrap();
        client.stream_consumed(4, 2).unwrap();
        let mut ack = [0u8; 256];
        let ack_len = client.poll_transmit(&mut ack).unwrap().unwrap();
        server.receive_packet_batch(&ack[..ack_len]).unwrap();
        assert!(
            !server.receive.is_retired(4),
            "request FIN not received yet"
        );

        let (used, _) = client
            .encode_stream_packet(server_cid, 4, 3, true, b"", &mut packet)
            .unwrap();
        server.receive_packet_batch(&packet[..used]).unwrap();
        assert!(
            server.receive.is_retired(4),
            "an empty FIN completing a consumed stream must release it"
        );
    }

    /// Bug (fixed): a MAX_STREAMS increase raised while an earlier credit
    /// packet was in flight could be lost. `try_retire_stream` set
    /// `credit_pending` but not `credit_dirty`; if the ACK for the older
    /// credit packet arrived before the next `poll_transmit`, it cleared
    /// `credit_pending` and `max_streams_bidi_pending`, and the new limit was
    /// never sent.
    #[test]
    fn max_streams_raised_while_credit_in_flight_is_sent() {
        let (mut client, mut server, client_cid, server_cid) = endpoint_pair();
        client.open_send_stream(4, INITIAL_MAX_STREAM_DATA).unwrap();
        let mut packet = [0u8; 256];
        let (used, _) = client
            .encode_stream_packet(server_cid, 4, 0, false, b"abc", &mut packet)
            .unwrap();
        server.receive_packet_batch(&packet[..used]).unwrap();
        server.stream_consumed(4, 3).unwrap();
        // Credit packet X is sent but delayed on the air.
        let mut credit = [0u8; 256];
        let credit_len = server.poll_transmit(&mut credit).unwrap().unwrap();

        server.open_send_stream(4, INITIAL_MAX_STREAM_DATA).unwrap();
        let (used, _) = server
            .encode_stream_packet(client_cid, 4, 0, true, b"ok", &mut packet)
            .unwrap();
        client.receive_packet_batch(&packet[..used]).unwrap();
        client.stream_consumed(4, 2).unwrap();
        let mut ack = [0u8; 256];
        let ack_len = client.poll_transmit(&mut ack).unwrap().unwrap();
        server.receive_packet_batch(&ack[..ack_len]).unwrap();

        // The request's FIN retires stream 4 and raises MAX_STREAMS while X
        // is still unacknowledged. No poll_transmit happens before X's ACK.
        let (used, _) = client
            .encode_stream_packet(server_cid, 4, 3, true, b"", &mut packet)
            .unwrap();
        server.receive_packet_batch(&packet[..used]).unwrap();
        assert!(server.receive.is_retired(4));

        client.receive_packet_batch(&credit[..credit_len]).unwrap();
        // Let the client's delayed-ACK timer expire.
        client.set_time(1_000_000);
        let ack_len = client.poll_transmit(&mut ack).unwrap().unwrap();
        server.receive_packet_batch(&ack[..ack_len]).unwrap();

        let used = server.poll_transmit(&mut packet).unwrap().unwrap();
        assert!(
            packet_frames(&packet[..used])
                .iter()
                .any(|frame| matches!(frame, Frame::MaxStreamsBidi(_))),
            "the raised MAX_STREAMS limit must still be published"
        );
    }
}
