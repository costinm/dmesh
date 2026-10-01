//! Capacity-limited DCID dispatch shared by endpoint and opaque-forwarding targets.
//!
//! Every serialized non-empty DCID occupies one entry in this registry, either
//! an endpoint owner or an opaque forwarding
//! rule.  A platform therefore performs one lookup before it chooses local
//! endpoint processing or next-hop egress; it must not maintain a competing
//! relay lookup table.

use alloc::vec::Vec;

#[cfg(test)]
use crate::connection::{ServerPacket, classify_server_packet};
use crate::{
    BearerId, ConnectionId, Error, PeerL2Address, ShortHeaderPrefix, decode_routing_prefix,
    rewrite_bootstrap_destination, rewrite_dcid,
};

/// Destination selected by an opaque relay rule.
///
/// `Bootstrap` means a QUIC long header with an empty destination CID. It is
/// explicit protocol state, not a numeric sentinel. Only the initial
/// OPEN is allowed to use it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ForwardDestination {
    Connection(ConnectionId),
    Bootstrap,
}

/// The adjacent egress selected by a relay rule. Both values are local to
/// the relay and are never read from a forwarded packet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ForwardNextHop {
    pub bearer: BearerId,
    pub peer_l2_address: PeerL2Address,
}

/// Opaque forwarding action selected by a non-zero local DCID.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ForwardRule<NextHop> {
    /// Platform-owned adjacent-peer or egress handle.
    pub next_hop: NextHop,
    /// Destination written before submitting the packet to `next_hop`.
    pub destination: ForwardDestination,
    /// Inactivity lease duration in microseconds.
    pub lease_duration_us: u64,
    /// Absolute expiry on the node's monotonic clock.
    pub lease_expires_at_us: u64,
    /// Shared lifecycle key for the two directions of one installed path.
    pub lease_group_id: u64,
    /// Maximum admitted packets for this direction. Zero means no quota for
    /// manually installed compatibility rules.
    pub packet_quota: u64,
    /// Packets admitted in the current quota window.
    pub forwarded_packets: u64,
    /// Admitted control packets, which may use the control reserve.
    pub forwarded_control_packets: u64,
    /// Start of the fixed quota window. Unlike the inactivity lease, this
    /// timestamp does not move when forwarding traffic renews that lease.
    pub quota_window_started_us: u64,
}

/// Admission result for one setup retry.
pub(crate) enum SetupTransactionLookup<'a> {
    /// First request for this previous-hop/transaction pair.
    New,
    /// Identical retry while downstream setup is still pending.
    PendingRetry,
    /// Matching transaction whose setup already expired or was cancelled.
    Expired,
    /// Identical retry after installation; replay these exact response bytes.
    Replay(&'a [u8]),
    /// Same transaction key was reused with different request bytes.
    Conflict,
    /// Configured pending, cache, request, or response storage is exhausted.
    Full,
    /// Transaction identifiers, retry deadlines, or reply sizes are invalid.
    Invalid,
}

struct SetupTransaction {
    previous_hop: ForwardNextHop,
    transaction_id: u64,
    request: Vec<u8>,
    reply: Vec<u8>,
    downstream_reply: Vec<u8>,
    downstream_hop: Option<ForwardNextHop>,
    relay_state: Option<SetupRelayState>,
    reply_ready: bool,
    expired: bool,
    pending_deadline_us: u64,
    cache_expiry_us: u64,
    reserved_reply_bytes: usize,
}

/// Fixed-policy transaction and reply cache for relay setup retries.
/// Admission reserves the reply capacity before a caller allocates CIDs or
/// installs rules, so successful installation always has room for its retry
/// response. The reply-entry cap counts pending reservations as well as
/// cached replies. Retries never extend the original pending deadline.
pub(crate) struct SetupTransactionTable {
    entries: Vec<SetupTransaction>,
    max_pending: usize,
    max_cached_replies: usize,
    max_request_bytes: usize,
    max_reply_bytes: usize,
    max_reserved_reply_bytes: usize,
    reserved_reply_bytes: usize,
    pending_count: usize,
    cached_count: usize,
    retention_us: u64,
}

impl SetupTransactionTable {
    pub(crate) fn new(
        max_pending: usize,
        max_cached_replies: usize,
        max_request_bytes: usize,
        max_reply_bytes: usize,
        max_reserved_reply_bytes: usize,
        retention_us: u64,
    ) -> Self {
        Self {
            entries: Vec::new(),
            max_pending,
            max_cached_replies,
            max_request_bytes,
            max_reply_bytes,
            max_reserved_reply_bytes,
            reserved_reply_bytes: 0,
            pending_count: 0,
            cached_count: 0,
            retention_us,
        }
    }

    pub(crate) fn begin<'a>(
        &'a mut self,
        previous_hop: ForwardNextHop,
        transaction_id: u64,
        request: &[u8],
        reply_capacity: usize,
        now_us: u64,
        pending_deadline_us: u64,
    ) -> SetupTransactionLookup<'a> {
        self.expire(now_us);
        if transaction_id == 0
            || request.is_empty()
            || request.len() > self.max_request_bytes
            || reply_capacity == 0
            || reply_capacity > self.max_reply_bytes
            || pending_deadline_us <= now_us
        {
            return SetupTransactionLookup::Invalid;
        }
        if let Some(index) = self.entries.iter().position(|entry| {
            entry.previous_hop == previous_hop && entry.transaction_id == transaction_id
        }) {
            let request_matches = self.entries[index].request == request;
            let reply_ready = self.entries[index].reply_ready;
            let expired = self.entries[index].expired;
            if !request_matches {
                return SetupTransactionLookup::Conflict;
            }
            if expired {
                return SetupTransactionLookup::Expired;
            }
            return if reply_ready {
                SetupTransactionLookup::Replay(&self.entries[index].reply)
            } else {
                SetupTransactionLookup::PendingRetry
            };
        }
        let Some(reserved_reply_bytes) = self.reserved_reply_bytes.checked_add(reply_capacity)
        else {
            return SetupTransactionLookup::Full;
        };
        if self.pending_count >= self.max_pending
            || self.entries.len() >= self.max_cached_replies
            || reserved_reply_bytes > self.max_reserved_reply_bytes
        {
            return SetupTransactionLookup::Full;
        }

        let mut owned_request = Vec::new();
        if owned_request.try_reserve_exact(request.len()).is_err() {
            return SetupTransactionLookup::Full;
        }
        let mut reply = Vec::new();
        if reply.try_reserve_exact(reply_capacity).is_err() || self.entries.try_reserve(1).is_err()
        {
            return SetupTransactionLookup::Full;
        }
        owned_request.extend_from_slice(request);
        self.entries.push(SetupTransaction {
            previous_hop,
            transaction_id,
            request: owned_request,
            reply,
            downstream_reply: Vec::new(),
            downstream_hop: None,
            relay_state: None,
            reply_ready: false,
            expired: false,
            pending_deadline_us,
            cache_expiry_us: 0,
            reserved_reply_bytes: reply_capacity,
        });
        self.pending_count += 1;
        self.reserved_reply_bytes = reserved_reply_bytes;
        SetupTransactionLookup::New
    }

    pub(crate) fn complete(
        &mut self,
        previous_hop: ForwardNextHop,
        transaction_id: u64,
        reply: &[u8],
        now_us: u64,
    ) -> Result<(), SetupTransactionError> {
        let Some(index) = self.entries.iter().position(|entry| {
            entry.previous_hop == previous_hop && entry.transaction_id == transaction_id
        }) else {
            return Err(SetupTransactionError::Missing);
        };
        if self.entries[index].expired || now_us >= self.entries[index].pending_deadline_us {
            return Err(SetupTransactionError::Expired);
        }
        if self.entries[index].reply_ready {
            return Err(SetupTransactionError::Missing);
        }
        if reply.is_empty() || reply.len() > self.entries[index].reserved_reply_bytes {
            return Err(SetupTransactionError::ReplyTooLarge);
        }
        let entry = &mut self.entries[index];
        entry.reply.extend_from_slice(reply);
        entry.reply_ready = true;
        entry.cache_expiry_us = now_us.saturating_add(self.retention_us);
        self.pending_count -= 1;
        self.cached_count += 1;
        Ok(())
    }

    pub(crate) fn set_downstream_hop(
        &mut self,
        previous_hop: ForwardNextHop,
        transaction_id: u64,
        downstream_hop: ForwardNextHop,
    ) -> Result<(), SetupTransactionError> {
        let entry = self
            .entries
            .iter_mut()
            .find(|entry| {
                entry.previous_hop == previous_hop && entry.transaction_id == transaction_id
            })
            .ok_or(SetupTransactionError::Missing)?;
        if entry.expired || entry.reply_ready {
            return Err(SetupTransactionError::Expired);
        }
        if entry
            .downstream_hop
            .is_some_and(|existing| existing != downstream_hop)
        {
            return Err(SetupTransactionError::Conflict);
        }
        entry.downstream_hop = Some(downstream_hop);
        Ok(())
    }

    pub(crate) fn downstream_hop(
        &self,
        previous_hop: ForwardNextHop,
        transaction_id: u64,
    ) -> Option<ForwardNextHop> {
        self.entries
            .iter()
            .find(|entry| {
                entry.previous_hop == previous_hop && entry.transaction_id == transaction_id
            })
            .and_then(|entry| entry.downstream_hop)
    }

    pub(crate) fn set_relay_state(
        &mut self,
        previous_hop: ForwardNextHop,
        transaction_id: u64,
        relay_state: SetupRelayState,
    ) -> Result<(), SetupTransactionError> {
        let entry = self
            .entries
            .iter_mut()
            .find(|entry| {
                entry.previous_hop == previous_hop && entry.transaction_id == transaction_id
            })
            .ok_or(SetupTransactionError::Missing)?;
        if entry.expired || entry.reply_ready {
            return Err(SetupTransactionError::Expired);
        }
        if entry
            .relay_state
            .is_some_and(|existing| existing != relay_state)
        {
            return Err(SetupTransactionError::Conflict);
        }
        entry.relay_state = Some(relay_state);
        Ok(())
    }

    pub(crate) fn relay_state(
        &self,
        previous_hop: ForwardNextHop,
        transaction_id: u64,
    ) -> Option<SetupRelayState> {
        self.entries
            .iter()
            .find(|entry| {
                entry.previous_hop == previous_hop && entry.transaction_id == transaction_id
            })
            .and_then(|entry| entry.relay_state)
    }

    pub(crate) fn validate_downstream_reply(
        &mut self,
        downstream_hop: ForwardNextHop,
        transaction_id: u64,
        circuit: SetupCircuitKey,
        reply: &[u8],
    ) -> Result<SetupDownstreamReply<'_>, SetupTransactionError> {
        let index = self
            .entries
            .iter()
            .position(|entry| {
                entry.downstream_hop == Some(downstream_hop)
                    && entry.transaction_id == transaction_id
            })
            .ok_or(SetupTransactionError::Missing)?;
        let entry = &mut self.entries[index];
        if entry.expired {
            return Err(SetupTransactionError::Expired);
        }
        let decoded =
            decode_setup_reply_packet(reply).map_err(|_| SetupTransactionError::Conflict)?;
        if decoded.transaction_id != transaction_id || decoded.circuit != circuit {
            return Err(SetupTransactionError::Conflict);
        }
        if !entry.downstream_reply.is_empty() {
            if entry.downstream_reply != reply {
                return Err(SetupTransactionError::Conflict);
            }
            if entry.reply_ready {
                return Ok(SetupDownstreamReply::Replay {
                    previous_hop: entry.previous_hop,
                    reply: &entry.reply,
                });
            }
        } else {
            if reply.is_empty() || reply.len() > self.max_reply_bytes {
                return Err(SetupTransactionError::ReplyTooLarge);
            }
            entry
                .downstream_reply
                .try_reserve_exact(reply.len())
                .map_err(|_| SetupTransactionError::ReplyTooLarge)?;
            entry.downstream_reply.extend_from_slice(reply);
        }
        let relay_state = entry.relay_state.ok_or(SetupTransactionError::Missing)?;
        Ok(SetupDownstreamReply::New {
            previous_hop: entry.previous_hop,
            relay_state,
        })
    }

    pub(crate) fn complete_from_downstream(
        &mut self,
        downstream_hop: ForwardNextHop,
        transaction_id: u64,
        reply: &[u8],
        now_us: u64,
    ) -> Result<ForwardNextHop, SetupTransactionError> {
        let previous_hop = self
            .entries
            .iter()
            .find(|entry| {
                entry.downstream_hop == Some(downstream_hop)
                    && entry.transaction_id == transaction_id
            })
            .map(|entry| entry.previous_hop)
            .ok_or(SetupTransactionError::Missing)?;
        self.complete(previous_hop, transaction_id, reply, now_us)?;
        Ok(previous_hop)
    }

    /// Cancel a matching provisional transaction and release its reservations.
    pub(crate) fn cancel(&mut self, previous_hop: ForwardNextHop, transaction_id: u64) -> bool {
        let Some(index) = self.entries.iter().position(|entry| {
            entry.previous_hop == previous_hop && entry.transaction_id == transaction_id
        }) else {
            return false;
        };
        self.mark_expired(index);
        true
    }

    pub(crate) fn expire(&mut self, now_us: u64) -> usize {
        let mut removed = 0usize;
        let mut index = 0;
        while index < self.entries.len() {
            let pending_expired = !self.entries[index].reply_ready
                && !self.entries[index].expired
                && self.entries[index].pending_deadline_us <= now_us;
            if pending_expired {
                self.mark_expired(index);
                removed += 1;
            }
            if (self.entries[index].reply_ready || self.entries[index].expired)
                && self.entries[index].cache_expiry_us <= now_us
            {
                self.remove(index);
                if !pending_expired {
                    removed += 1;
                }
            } else {
                index += 1;
            }
        }
        removed
    }

    pub(crate) fn pending_count(&self) -> usize {
        self.pending_count
    }

    pub(crate) fn cached_count(&self) -> usize {
        self.cached_count
    }

    pub(crate) fn next_deadline(&self) -> Option<u64> {
        self.entries
            .iter()
            .map(|entry| {
                if entry.reply_ready || entry.expired {
                    entry.cache_expiry_us
                } else {
                    entry.pending_deadline_us
                }
            })
            .min()
    }

    fn remove(&mut self, index: usize) {
        let entry = self.entries.remove(index);
        if entry.reply_ready {
            self.cached_count -= 1;
        } else if !entry.expired {
            self.pending_count -= 1;
        }
        self.reserved_reply_bytes = self
            .reserved_reply_bytes
            .saturating_sub(entry.reserved_reply_bytes);
    }

    fn mark_expired(&mut self, index: usize) {
        let entry = &mut self.entries[index];
        if entry.reply_ready || entry.expired {
            return;
        }
        entry.expired = true;
        entry.cache_expiry_us = entry.pending_deadline_us.saturating_add(self.retention_us);
        entry.reply = Vec::new();
        self.pending_count -= 1;
        self.reserved_reply_bytes = self
            .reserved_reply_bytes
            .saturating_sub(entry.reserved_reply_bytes);
        entry.reserved_reply_bytes = 0;
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SetupTransactionError {
    Missing,
    Expired,
    ReplyTooLarge,
    Conflict,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SetupRelayState {
    pub forward_cid: ConnectionId,
    pub reverse_cid: ConnectionId,
    pub reverse_target: ConnectionId,
    pub lease_duration_us: u64,
    pub packet_quota: u64,
}

pub(crate) enum SetupDownstreamReply<'a> {
    Replay {
        previous_hop: ForwardNextHop,
        reply: &'a [u8],
    },
    New {
        previous_hop: ForwardNextHop,
        relay_state: SetupRelayState,
    },
}

pub(crate) const SETUP_VERSION: u8 = 1;
const SETUP_REQUEST_VERSION: u8 = 2;
pub(crate) const MAX_SETUP_BLOCKS: usize = 8;
pub(crate) const MAX_SETUP_BLOCK_BYTES: usize = 256;
pub(crate) const MAX_SETUP_BODY_BYTES: usize = crate::DEFAULT_MAX_PACKET_SIZE - 64;
pub(crate) const DEFAULT_MAX_PENDING_SETUPS: usize = 4;
pub(crate) const DEFAULT_MAX_CACHED_SETUP_REPLIES: usize = 8;
pub(crate) const DEFAULT_SETUP_REPLY_BYTES: usize = 256;
pub(crate) const DEFAULT_SETUP_REPLY_STORAGE_BYTES: usize = 1_024;
pub(crate) const DEFAULT_SETUP_PENDING_TIMEOUT_US: u64 = 10_000_000;
pub(crate) const DEFAULT_SETUP_REPLY_RETENTION_US: u64 = 5_000_000;
pub(crate) const DEFAULT_SETUP_LEASE_US: u64 = 60_000_000;
pub(crate) const SETUP_BLOCK_RELAY: u8 = 1;
pub(crate) const SETUP_BLOCK_ENDPOINT: u8 = 2;
pub(crate) const MAX_SETUP_BOOTSTRAP_ACK_BYTES: usize = 128;
pub(crate) const MAX_SETUP_HOP_ADDRESS_BYTES: usize = 18;

/// Opaque egress address interpreted only by the relay named by the current
/// instruction block. The kind selects that relay's own bearer/address
/// namespace; it is not an opener-local `BearerId`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SetupHopInstruction {
    pub address_kind: u8,
    pub address_len: u8,
    pub address: [u8; MAX_SETUP_HOP_ADDRESS_BYTES],
    pub lease_us: u64,
    pub packet_quota: u64,
}

impl SetupHopInstruction {
    pub(crate) fn encode(self, output: &mut [u8]) -> Result<usize, Error> {
        let address_len = usize::from(self.address_len);
        if self.address_kind == 0
            || address_len == 0
            || address_len > MAX_SETUP_HOP_ADDRESS_BYTES
            || self.lease_us == 0
            || self.packet_quota == 0
        {
            return Err(Error::Invalid);
        }
        let mut pos = 0usize;
        put_setup_byte(output, &mut pos, self.address_kind)?;
        put_setup_byte(output, &mut pos, self.address_len)?;
        if output.len().saturating_sub(pos) < address_len {
            return Err(Error::BufferTooSmall);
        }
        output[pos..pos + address_len].copy_from_slice(&self.address[..address_len]);
        pos += address_len;
        pos += crate::put_varint(self.lease_us, &mut output[pos..])?;
        pos += crate::put_varint(self.packet_quota, &mut output[pos..])?;
        if pos > MAX_SETUP_BLOCK_BYTES {
            return Err(Error::Invalid);
        }
        Ok(pos)
    }

    pub(crate) fn decode(input: &[u8]) -> Result<Self, Error> {
        let mut pos = 0usize;
        let address_kind = take_setup_byte(input, &mut pos)?;
        let address_len = take_setup_byte(input, &mut pos)?;
        let address_len_usize = usize::from(address_len);
        if address_kind == 0
            || address_len_usize == 0
            || address_len_usize > MAX_SETUP_HOP_ADDRESS_BYTES
            || input.len().saturating_sub(pos) < address_len_usize
        {
            return Err(Error::Invalid);
        }
        let mut address = [0; MAX_SETUP_HOP_ADDRESS_BYTES];
        address[..address_len_usize].copy_from_slice(&input[pos..pos + address_len_usize]);
        pos += address_len_usize;
        let (lease_us, used) = crate::get_varint(&input[pos..])?;
        pos += used;
        let (packet_quota, used) = crate::get_varint(&input[pos..])?;
        pos += used;
        if lease_us == 0 || packet_quota == 0 || pos != input.len() {
            return Err(Error::Invalid);
        }
        Ok(Self {
            address_kind,
            address_len,
            address,
            lease_us,
            packet_quota,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SetupMode {
    Create,
    Join,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Routing contract carried by a relayed CREATE or JOIN.
pub enum RelayRouteMode {
    /// Each relay follows the explicit next-hop instruction in the request.
    Layered,
    /// The first gateway resolves the destination VIP through local policy.
    VipRouted,
    /// Relays extend the route incrementally under one circuit identity.
    Telescoping,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SetupCircuitKey {
    pub opener_role: crate::Role,
    pub sequence: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SetupBlock<'a> {
    pub kind: u8,
    pub version: u8,
    /// Zero selects the initial unencrypted setup profile.
    pub protection: u8,
    pub payload: &'a [u8],
}

/// Endpoint payload for joining a new circuit to an existing association.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SetupJoinEndpoint {
    pub join_cid: ConnectionId,
    pub opener_receive_cid: ConnectionId,
}

impl SetupJoinEndpoint {
    pub(crate) fn encode(self, output: &mut [u8]) -> Result<usize, Error> {
        if self.join_cid.value() == 0 || self.opener_receive_cid.value() == 0 {
            return Err(Error::Invalid);
        }
        let mut pos = self.join_cid.encode(output)?;
        pos += self.opener_receive_cid.encode(&mut output[pos..])?;
        Ok(pos)
    }

    pub(crate) fn decode(input: &[u8]) -> Result<Self, Error> {
        let (join_cid, first_used) = ConnectionId::decode(input)?;
        let (opener_receive_cid, second_used) = ConnectionId::decode(&input[first_used..])?;
        if join_cid.value() == 0
            || opener_receive_cid.value() == 0
            || first_used.saturating_add(second_used) != input.len()
        {
            return Err(Error::Invalid);
        }
        Ok(Self {
            join_cid,
            opener_receive_cid,
        })
    }
}

/// Version-2 endpoint payload for relayed association creation. The client
/// Initial remains opaque to relays; nearby return hints are read only by the
/// accepted endpoint and remain advisory.
pub(crate) struct SetupCreateEndpoint<'a> {
    pub initial_packet: &'a [u8],
    pub return_hints: crate::NearbyRelayHints,
}

impl SetupCreateEndpoint<'_> {
    pub(crate) fn encode(&self, output: &mut [u8]) -> Result<usize, Error> {
        if self.initial_packet.is_empty()
            || self.return_hints.len() > crate::MAX_NEARBY_RETURN_RELAYS
        {
            return Err(Error::Invalid);
        }
        let mut pos = crate::put_varint(self.initial_packet.len() as u64, output)?;
        if output.len().saturating_sub(pos) < self.initial_packet.len().saturating_add(1) {
            return Err(Error::BufferTooSmall);
        }
        output[pos..pos + self.initial_packet.len()].copy_from_slice(self.initial_packet);
        pos += self.initial_packet.len();
        output[pos] = self.return_hints.len() as u8;
        pos += 1;
        for hint in self.return_hints.iter() {
            if output.len().saturating_sub(pos) < hint.relay_id.len() {
                return Err(Error::BufferTooSmall);
            }
            output[pos..pos + hint.relay_id.len()].copy_from_slice(&hint.relay_id);
            pos += hint.relay_id.len();
            let instruction = SetupHopInstruction {
                address_kind: hint.hop.address_kind,
                address_len: hint.hop.address_len,
                address: hint.hop.address,
                lease_us: hint.hop.lease_us,
                packet_quota: hint.hop.packet_quota,
            };
            let mut encoded_hop = [0u8; MAX_SETUP_BLOCK_BYTES];
            let encoded_hop_len = instruction.encode(&mut encoded_hop)?;
            pos += crate::put_varint(encoded_hop_len as u64, &mut output[pos..])?;
            if output.len().saturating_sub(pos) < encoded_hop_len {
                return Err(Error::BufferTooSmall);
            }
            output[pos..pos + encoded_hop_len].copy_from_slice(&encoded_hop[..encoded_hop_len]);
            pos += encoded_hop_len;
        }
        if pos > MAX_SETUP_BLOCK_BYTES {
            return Err(Error::BufferTooSmall);
        }
        Ok(pos)
    }

    pub(crate) fn decode(
        payload: &[u8],
        block_version: u8,
    ) -> Result<(&[u8], crate::NearbyRelayHints), Error> {
        if block_version == 1 {
            return Ok((payload, crate::NearbyRelayHints::EMPTY));
        }
        if block_version != 2 {
            return Err(Error::Invalid);
        }
        let (initial_len, mut pos) = crate::get_varint(payload)?;
        let initial_len = usize::try_from(initial_len).map_err(|_| Error::Invalid)?;
        let initial_end = pos.checked_add(initial_len).ok_or(Error::Invalid)?;
        if initial_len == 0 || initial_end >= payload.len() {
            return Err(Error::Invalid);
        }
        let initial_packet = &payload[pos..initial_end];
        pos = initial_end;
        let hint_count = usize::from(take_setup_byte(payload, &mut pos)?);
        if hint_count > crate::MAX_NEARBY_RETURN_RELAYS {
            return Err(Error::Invalid);
        }
        let mut hints = [None; crate::MAX_NEARBY_RETURN_RELAYS];
        for entry in hints.iter_mut().take(hint_count) {
            let end = pos.checked_add(8).ok_or(Error::Invalid)?;
            let relay_id: [u8; 8] = payload
                .get(pos..end)
                .ok_or(Error::Truncated)?
                .try_into()
                .map_err(|_| Error::Invalid)?;
            pos = end;
            let (encoded_len, used) = crate::get_varint(&payload[pos..])?;
            pos = pos.checked_add(used).ok_or(Error::Invalid)?;
            let encoded_len = usize::try_from(encoded_len).map_err(|_| Error::Invalid)?;
            let encoded_end = pos.checked_add(encoded_len).ok_or(Error::Invalid)?;
            let encoded_hop = payload.get(pos..encoded_end).ok_or(Error::Truncated)?;
            let instruction = SetupHopInstruction::decode(encoded_hop)?;
            pos = encoded_end;
            let hop = crate::RelayHop {
                address_kind: instruction.address_kind,
                address_len: instruction.address_len,
                address: instruction.address,
                lease_us: instruction.lease_us,
                packet_quota: instruction.packet_quota,
            };
            *entry = Some(crate::NearbyRelayHint { relay_id, hop });
        }
        if pos != payload.len() {
            return Err(Error::Invalid);
        }
        let compacted = hints
            .into_iter()
            .take(hint_count)
            .flatten()
            .collect::<alloc::vec::Vec<_>>();
        let return_hints = crate::NearbyRelayHints::new(&compacted).ok_or(Error::Invalid)?;
        Ok((initial_packet, return_hints))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SetupRequest<'a> {
    pub transaction_id: u64,
    pub mode: SetupMode,
    pub route_mode: RelayRouteMode,
    pub circuit: SetupCircuitKey,
    pub destination_vip: Option<u64>,
    pub previous_reverse_cid: Option<ConnectionId>,
    pub blocks: &'a [SetupBlock<'a>],
}

impl SetupRequest<'_> {
    /// Encode a connectionless long-header PATH_OPEN sent to the first hop's
    /// physical address. The relay stack advances the versioned blocks as the
    /// packet moves toward its terminal endpoint.
    pub(crate) fn encode_packet(&self, output: &mut [u8]) -> Result<usize, Error> {
        let mut body = [0u8; MAX_SETUP_BODY_BYTES];
        let body_len = self.encode(&mut body)?;
        crate::encode_long_packet(
            crate::LONG_PACKET_PATH_OPEN,
            None,
            None,
            0,
            1,
            &body[..body_len],
            output,
        )
    }

    pub(crate) fn encode(&self, output: &mut [u8]) -> Result<usize, Error> {
        if self.transaction_id == 0
            || self.circuit.sequence == 0
            || self.blocks.is_empty()
            || self.blocks.len() > MAX_SETUP_BLOCKS
            || self.destination_vip == Some(0)
            || self
                .previous_reverse_cid
                .is_some_and(|cid| cid.value() == 0)
            || self.blocks.iter().any(|block| {
                block.kind == 0
                    || block.version == 0
                    || block.protection != 0
                    || block.payload.is_empty()
                    || block.payload.len() > MAX_SETUP_BLOCK_BYTES
            })
        {
            return Err(Error::Invalid);
        }
        let mut pos = 0usize;
        put_setup_byte(output, &mut pos, SETUP_REQUEST_VERSION)?;
        pos += crate::put_varint(self.transaction_id, &mut output[pos..])?;
        put_setup_byte(
            output,
            &mut pos,
            match self.mode {
                SetupMode::Create => 0,
                SetupMode::Join => 1,
            },
        )?;
        put_setup_byte(
            output,
            &mut pos,
            match self.route_mode {
                RelayRouteMode::Layered => 0,
                RelayRouteMode::VipRouted => 1,
                RelayRouteMode::Telescoping => 2,
            },
        )?;
        put_setup_byte(
            output,
            &mut pos,
            match self.circuit.opener_role {
                crate::Role::Client => 0,
                crate::Role::Server => 1,
            },
        )?;
        pos += crate::put_varint(self.circuit.sequence, &mut output[pos..])?;
        match self.destination_vip {
            Some(vip) => {
                put_setup_byte(output, &mut pos, 1)?;
                if output.len().saturating_sub(pos) < 8 {
                    return Err(Error::BufferTooSmall);
                }
                output[pos..pos + 8].copy_from_slice(&vip.to_be_bytes());
                pos += 8;
            }
            None => put_setup_byte(output, &mut pos, 0)?,
        }
        match self.previous_reverse_cid {
            Some(cid) => {
                put_setup_byte(output, &mut pos, 1)?;
                pos += cid.encode(&mut output[pos..])?;
            }
            None => put_setup_byte(output, &mut pos, 0)?,
        }
        pos += crate::put_varint(self.blocks.len() as u64, &mut output[pos..])?;
        for block in self.blocks {
            put_setup_byte(output, &mut pos, block.kind)?;
            put_setup_byte(output, &mut pos, block.version)?;
            put_setup_byte(output, &mut pos, block.protection)?;
            pos += crate::put_varint(block.payload.len() as u64, &mut output[pos..])?;
            if output.len().saturating_sub(pos) < block.payload.len() {
                return Err(Error::BufferTooSmall);
            }
            output[pos..pos + block.payload.len()].copy_from_slice(block.payload);
            pos += block.payload.len();
            if pos > MAX_SETUP_BODY_BYTES {
                return Err(Error::Invalid);
            }
        }
        Ok(pos)
    }

    pub(crate) fn decode(input: &[u8]) -> Result<SetupRequestView<'_>, Error> {
        if input.len() > MAX_SETUP_BODY_BYTES
            || !matches!(
                input.first().copied(),
                Some(SETUP_VERSION | SETUP_REQUEST_VERSION)
            )
        {
            return Err(Error::Invalid);
        }
        let version = input[0];
        let mut pos = 1usize;
        let (transaction_id, used) = crate::get_varint(&input[pos..])?;
        pos += used;
        let mode = match take_setup_byte(input, &mut pos)? {
            0 => SetupMode::Create,
            1 => SetupMode::Join,
            _ => return Err(Error::Invalid),
        };
        let route_mode = if version == SETUP_VERSION {
            RelayRouteMode::Layered
        } else {
            match take_setup_byte(input, &mut pos)? {
                0 => RelayRouteMode::Layered,
                1 => RelayRouteMode::VipRouted,
                2 => RelayRouteMode::Telescoping,
                _ => return Err(Error::Invalid),
            }
        };
        let opener_role = match take_setup_byte(input, &mut pos)? {
            0 => crate::Role::Client,
            1 => crate::Role::Server,
            _ => return Err(Error::Invalid),
        };
        let (sequence, used) = crate::get_varint(&input[pos..])?;
        pos += used;
        let destination_vip = match take_setup_byte(input, &mut pos)? {
            0 => None,
            1 => {
                if input.len().saturating_sub(pos) < 8 {
                    return Err(Error::Invalid);
                }
                let vip =
                    u64::from_be_bytes(input[pos..pos + 8].try_into().map_err(|_| Error::Invalid)?);
                pos += 8;
                if vip == 0 {
                    return Err(Error::Invalid);
                }
                Some(vip)
            }
            _ => return Err(Error::Invalid),
        };
        let previous_reverse_cid = match take_setup_byte(input, &mut pos)? {
            0 => None,
            1 => {
                let (cid, used) = ConnectionId::decode(&input[pos..])?;
                pos += used;
                if cid.value() == 0 {
                    return Err(Error::Invalid);
                }
                Some(cid)
            }
            _ => return Err(Error::Invalid),
        };
        let (block_count, used) = crate::get_varint(&input[pos..])?;
        pos += used;
        let block_count = usize::try_from(block_count).map_err(|_| Error::Invalid)?;
        if transaction_id == 0
            || sequence == 0
            || block_count == 0
            || block_count > MAX_SETUP_BLOCKS
        {
            return Err(Error::Invalid);
        }
        let blocks_offset = pos;
        for _ in 0..block_count {
            let kind = take_setup_byte(input, &mut pos)?;
            let version = take_setup_byte(input, &mut pos)?;
            let protection = take_setup_byte(input, &mut pos)?;
            let (len, used) = crate::get_varint(&input[pos..])?;
            pos += used;
            let len = usize::try_from(len).map_err(|_| Error::Invalid)?;
            if kind == 0
                || version == 0
                || protection != 0
                || len == 0
                || len > MAX_SETUP_BLOCK_BYTES
                || input.len().saturating_sub(pos) < len
            {
                return Err(Error::Invalid);
            }
            pos += len;
        }
        if pos != input.len() {
            return Err(Error::Invalid);
        }
        let blocks = SetupBlockBytes {
            bytes: &input[blocks_offset..],
            count: block_count,
        };
        Ok(SetupRequestView {
            version,
            transaction_id,
            mode,
            route_mode,
            circuit: SetupCircuitKey {
                opener_role,
                sequence,
            },
            destination_vip,
            previous_reverse_cid,
            blocks,
            raw: input,
        })
    }
}

/// Decode a connectionless PATH_OPEN packet. Routing is by its physical
/// ingress hop until the relay installs DCID forwarding rules.
pub(crate) fn decode_setup_request_packet(input: &[u8]) -> Result<SetupRequestView<'_>, Error> {
    let (header, body_at, body_len) = crate::decode_long_packet(input)?;
    if header.packet_type != crate::LONG_PACKET_PATH_OPEN
        || header.dcid.is_some()
        || header.scid.is_some()
    {
        return Err(Error::Invalid);
    }
    SetupRequest::decode(&input[body_at..body_at + body_len])
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SetupBlockBytes<'a> {
    bytes: &'a [u8],
    count: usize,
}

impl<'a> SetupBlockBytes<'a> {
    pub(crate) fn count(self) -> usize {
        self.count
    }

    pub(crate) fn get(self, index: usize) -> Option<Result<SetupBlock<'a>, Error>> {
        if index >= self.count {
            return None;
        }
        let mut pos = 0usize;
        for current in 0..=index {
            let kind = take_setup_byte(self.bytes, &mut pos).ok()?;
            let version = take_setup_byte(self.bytes, &mut pos).ok()?;
            let protection = take_setup_byte(self.bytes, &mut pos).ok()?;
            let (len, used) = crate::get_varint(&self.bytes[pos..]).ok()?;
            pos += used;
            let len = usize::try_from(len).ok()?;
            let end = pos.checked_add(len)?;
            let payload = self.bytes.get(pos..end)?;
            if current == index {
                return Some(Ok(SetupBlock {
                    kind,
                    version,
                    protection,
                    payload,
                }));
            }
            pos = end;
        }
        None
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SetupRequestView<'a> {
    version: u8,
    pub transaction_id: u64,
    pub mode: SetupMode,
    pub route_mode: RelayRouteMode,
    pub circuit: SetupCircuitKey,
    pub destination_vip: Option<u64>,
    pub previous_reverse_cid: Option<ConnectionId>,
    pub blocks: SetupBlockBytes<'a>,
    raw: &'a [u8],
}

impl<'a> SetupRequestView<'a> {
    pub(crate) fn request_body(self) -> &'a [u8] {
        self.raw
    }

    /// Decode this relay's leading instruction block. Unknown block versions,
    /// protection modes, and non-relay blocks fail closed at the current hop.
    pub(crate) fn current_hop_instruction(self) -> Result<SetupHopInstruction, Error> {
        let block = self.blocks.get(0).ok_or(Error::Invalid)??;
        if block.kind != SETUP_BLOCK_RELAY || block.version != 1 || block.protection != 0 {
            return Err(Error::Invalid);
        }
        SetupHopInstruction::decode(block.payload)
    }

    /// Re-encode this request after consuming the first relay instruction.
    /// All remaining versioned blocks are copied byte-for-byte, so a relay
    /// cannot accidentally reinterpret or mutate instructions for later hops.
    pub(crate) fn encode_after_first_block(self, output: &mut [u8]) -> Result<usize, Error> {
        self.encode_after_first_block_with_reverse_cid(self.previous_reverse_cid, output)
    }

    pub(crate) fn encode_after_first_block_with_reverse_cid(
        self,
        previous_reverse_cid: Option<ConnectionId>,
        output: &mut [u8],
    ) -> Result<usize, Error> {
        let consumed_blocks = usize::from(self.route_mode != RelayRouteMode::Telescoping);
        if self.blocks.count <= consumed_blocks {
            return Err(Error::Invalid);
        }
        let _ = self.current_hop_instruction()?;
        let mut block_pos = 0usize;
        for _ in 0..consumed_blocks {
            let _ = take_setup_byte(self.blocks.bytes, &mut block_pos)?;
            let _ = take_setup_byte(self.blocks.bytes, &mut block_pos)?;
            let _ = take_setup_byte(self.blocks.bytes, &mut block_pos)?;
            let (block_len, used) = crate::get_varint(&self.blocks.bytes[block_pos..])?;
            block_pos += used;
            let block_len = usize::try_from(block_len).map_err(|_| Error::Invalid)?;
            block_pos = block_pos
                .checked_add(block_len)
                .filter(|end| *end <= self.blocks.bytes.len())
                .ok_or(Error::Invalid)?;
        }

        let mut pos = 0usize;
        put_setup_byte(output, &mut pos, self.version)?;
        pos += crate::put_varint(self.transaction_id, &mut output[pos..])?;
        put_setup_byte(
            output,
            &mut pos,
            match self.mode {
                SetupMode::Create => 0,
                SetupMode::Join => 1,
            },
        )?;
        if self.version >= SETUP_REQUEST_VERSION {
            put_setup_byte(
                output,
                &mut pos,
                match self.route_mode {
                    RelayRouteMode::Layered => 0,
                    RelayRouteMode::VipRouted => 1,
                    RelayRouteMode::Telescoping => 2,
                },
            )?;
        }
        put_setup_byte(
            output,
            &mut pos,
            match self.circuit.opener_role {
                crate::Role::Client => 0,
                crate::Role::Server => 1,
            },
        )?;
        pos += crate::put_varint(self.circuit.sequence, &mut output[pos..])?;
        match self.destination_vip {
            Some(vip) => {
                put_setup_byte(output, &mut pos, 1)?;
                if output.len().saturating_sub(pos) < 8 {
                    return Err(Error::BufferTooSmall);
                }
                output[pos..pos + 8].copy_from_slice(&vip.to_be_bytes());
                pos += 8;
            }
            None => put_setup_byte(output, &mut pos, 0)?,
        }
        match previous_reverse_cid {
            Some(cid) => {
                put_setup_byte(output, &mut pos, 1)?;
                pos += cid.encode(&mut output[pos..])?;
            }
            None => put_setup_byte(output, &mut pos, 0)?,
        }
        pos += crate::put_varint(
            (self.blocks.count - consumed_blocks) as u64,
            &mut output[pos..],
        )?;
        let remaining = &self.blocks.bytes[block_pos..];
        if output.len().saturating_sub(pos) < remaining.len() {
            return Err(Error::BufferTooSmall);
        }
        output[pos..pos + remaining.len()].copy_from_slice(remaining);
        pos += remaining.len();
        if pos > MAX_SETUP_BODY_BYTES {
            return Err(Error::Invalid);
        }
        Ok(pos)
    }

    pub(crate) fn encode_packet_after_first_block_with_reverse_cid(
        self,
        previous_reverse_cid: Option<ConnectionId>,
        output: &mut [u8],
    ) -> Result<usize, Error> {
        let mut body = [0u8; MAX_SETUP_BODY_BYTES];
        let body_len =
            self.encode_after_first_block_with_reverse_cid(previous_reverse_cid, &mut body)?;
        crate::encode_long_packet(
            crate::LONG_PACKET_PATH_OPEN,
            None,
            None,
            0,
            1,
            &body[..body_len],
            output,
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SetupResult {
    Accepted {
        endpoint_cid: ConnectionId,
        lease_us: u64,
    },
    Rejected {
        code: u64,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SetupBootstrapAck {
    len: u8,
    bytes: [u8; MAX_SETUP_BOOTSTRAP_ACK_BYTES],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SetupRelayCids {
    len: u8,
    cids: [Option<ConnectionId>; MAX_SETUP_BLOCKS - 1],
}

impl SetupRelayCids {
    pub(crate) const fn empty() -> Self {
        Self {
            len: 0,
            cids: [None; MAX_SETUP_BLOCKS - 1],
        }
    }

    pub(crate) fn first(self) -> Option<ConnectionId> {
        self.cids.first().copied().flatten()
    }

    pub(crate) fn count(self) -> usize {
        usize::from(self.len)
    }

    pub(crate) fn get(self, index: usize) -> Option<ConnectionId> {
        self.cids
            .get(index)
            .copied()
            .flatten()
            .filter(|_| index < usize::from(self.len))
    }

    pub(crate) fn prepend(&mut self, cid: ConnectionId) -> Result<(), Error> {
        let len = usize::from(self.len);
        if cid.value() == 0 || len >= self.cids.len() {
            return Err(Error::Invalid);
        }
        for index in (0..len).rev() {
            self.cids[index + 1] = self.cids[index];
        }
        self.cids[0] = Some(cid);
        self.len += 1;
        Ok(())
    }

    fn encode(self, output: &mut [u8]) -> Result<usize, Error> {
        let mut pos = crate::put_varint(u64::from(self.len), output)?;
        for index in 0..usize::from(self.len) {
            let cid = self.cids[index].ok_or(Error::Invalid)?;
            pos += cid.encode(&mut output[pos..])?;
        }
        Ok(pos)
    }

    fn decode(input: &[u8], pos: &mut usize) -> Result<Self, Error> {
        let (len, used) = crate::get_varint(&input[*pos..])?;
        *pos += used;
        let len = usize::try_from(len).map_err(|_| Error::Invalid)?;
        if len > MAX_SETUP_BLOCKS - 1 {
            return Err(Error::Invalid);
        }
        let mut cids = Self::empty();
        for index in 0..len {
            let (cid, used) = ConnectionId::decode(&input[*pos..])?;
            *pos += used;
            if cid.value() == 0 {
                return Err(Error::Invalid);
            }
            cids.cids[index] = Some(cid);
        }
        cids.len = len as u8;
        Ok(cids)
    }
}

impl SetupBootstrapAck {
    pub(crate) fn from_slice(input: &[u8]) -> Result<Self, Error> {
        if input.is_empty() || input.len() > MAX_SETUP_BOOTSTRAP_ACK_BYTES {
            return Err(Error::Invalid);
        }
        let mut bytes = [0; MAX_SETUP_BOOTSTRAP_ACK_BYTES];
        bytes[..input.len()].copy_from_slice(input);
        Ok(Self {
            len: input.len() as u8,
            bytes,
        })
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SetupReply {
    pub transaction_id: u64,
    pub circuit: SetupCircuitKey,
    pub result: SetupResult,
    pub bootstrap_ack: Option<SetupBootstrapAck>,
    pub relay_cids: SetupRelayCids,
}

impl SetupReply {
    /// Encode a connectionless PATH_OPEN_ACK for the physical previous hop.
    pub(crate) fn encode_packet(self, output: &mut [u8]) -> Result<usize, Error> {
        let mut body = [0u8; DEFAULT_SETUP_REPLY_BYTES];
        let body_len = self.encode(&mut body)?;
        crate::encode_long_packet(
            crate::LONG_PACKET_PATH_OPEN_ACK,
            None,
            None,
            0,
            1,
            &body[..body_len],
            output,
        )
    }

    pub(crate) fn encode(self, output: &mut [u8]) -> Result<usize, Error> {
        if self.transaction_id == 0 || self.circuit.sequence == 0 {
            return Err(Error::Invalid);
        }
        let mut pos = 0usize;
        put_setup_byte(output, &mut pos, SETUP_VERSION)?;
        pos += crate::put_varint(self.transaction_id, &mut output[pos..])?;
        put_setup_byte(
            output,
            &mut pos,
            match self.circuit.opener_role {
                crate::Role::Client => 0,
                crate::Role::Server => 1,
            },
        )?;
        pos += crate::put_varint(self.circuit.sequence, &mut output[pos..])?;
        match self.result {
            SetupResult::Accepted {
                endpoint_cid,
                lease_us,
            } if endpoint_cid.value() != 0 && lease_us != 0 => {
                put_setup_byte(output, &mut pos, 0)?;
                pos += endpoint_cid.encode(&mut output[pos..])?;
                pos += crate::put_varint(lease_us, &mut output[pos..])?;
            }
            SetupResult::Rejected { code } => {
                if code == 0 {
                    return Err(Error::Invalid);
                }
                put_setup_byte(output, &mut pos, 1)?;
                pos += crate::put_varint(code, &mut output[pos..])?;
            }
            SetupResult::Accepted { .. } => return Err(Error::Invalid),
        }
        match (self.result, self.bootstrap_ack) {
            (SetupResult::Accepted { .. }, Some(ack)) => {
                put_setup_byte(output, &mut pos, 1)?;
                pos += crate::put_varint(ack.as_bytes().len() as u64, &mut output[pos..])?;
                if output.len().saturating_sub(pos) < ack.as_bytes().len() {
                    return Err(Error::BufferTooSmall);
                }
                output[pos..pos + ack.as_bytes().len()].copy_from_slice(ack.as_bytes());
                pos += ack.as_bytes().len();
            }
            (SetupResult::Accepted { .. }, None) | (SetupResult::Rejected { .. }, None) => {
                put_setup_byte(output, &mut pos, 0)?;
            }
            (SetupResult::Rejected { .. }, Some(_)) => return Err(Error::Invalid),
        }
        if matches!(self.result, SetupResult::Rejected { .. }) && self.relay_cids.len != 0 {
            return Err(Error::Invalid);
        }
        pos += self.relay_cids.encode(&mut output[pos..])?;
        if pos > MAX_SETUP_BODY_BYTES {
            return Err(Error::Invalid);
        }
        Ok(pos)
    }

    pub(crate) fn decode(input: &[u8]) -> Result<Self, Error> {
        if input.len() > MAX_SETUP_BODY_BYTES || input.first().copied() != Some(SETUP_VERSION) {
            return Err(Error::Invalid);
        }
        let mut pos = 1usize;
        let (transaction_id, used) = crate::get_varint(&input[pos..])?;
        pos += used;
        let opener_role = match take_setup_byte(input, &mut pos)? {
            0 => crate::Role::Client,
            1 => crate::Role::Server,
            _ => return Err(Error::Invalid),
        };
        let (sequence, used) = crate::get_varint(&input[pos..])?;
        pos += used;
        let result = match take_setup_byte(input, &mut pos)? {
            0 => {
                let (endpoint_cid, used) = ConnectionId::decode(&input[pos..])?;
                if endpoint_cid.value() == 0 {
                    return Err(Error::Invalid);
                }
                pos += used;
                let (lease_us, used) = crate::get_varint(&input[pos..])?;
                pos += used;
                if lease_us == 0 {
                    return Err(Error::Invalid);
                }
                SetupResult::Accepted {
                    endpoint_cid,
                    lease_us,
                }
            }
            1 => {
                let (code, used) = crate::get_varint(&input[pos..])?;
                pos += used;
                if code == 0 {
                    return Err(Error::Invalid);
                }
                SetupResult::Rejected { code }
            }
            _ => return Err(Error::Invalid),
        };
        let bootstrap_ack = match take_setup_byte(input, &mut pos)? {
            0 => None,
            1 => {
                let (len, used) = crate::get_varint(&input[pos..])?;
                pos += used;
                let len = usize::try_from(len).map_err(|_| Error::Invalid)?;
                let end = pos
                    .checked_add(len)
                    .filter(|end| *end <= input.len())
                    .ok_or(Error::Invalid)?;
                let ack = SetupBootstrapAck::from_slice(&input[pos..end])?;
                pos = end;
                Some(ack)
            }
            _ => return Err(Error::Invalid),
        };
        let relay_cids = SetupRelayCids::decode(input, &mut pos)?;
        if matches!(result, SetupResult::Rejected { .. }) && bootstrap_ack.is_some() {
            return Err(Error::Invalid);
        }
        if matches!(result, SetupResult::Rejected { .. }) && relay_cids.len != 0 {
            return Err(Error::Invalid);
        }
        if transaction_id == 0 || sequence == 0 || pos != input.len() {
            return Err(Error::Invalid);
        }
        Ok(Self {
            transaction_id,
            circuit: SetupCircuitKey {
                opener_role,
                sequence,
            },
            result,
            bootstrap_ack,
            relay_cids,
        })
    }
}

pub(crate) fn decode_setup_reply_packet(input: &[u8]) -> Result<SetupReply, Error> {
    let (header, body_at, body_len) = crate::decode_long_packet(input)?;
    if header.packet_type != crate::LONG_PACKET_PATH_OPEN_ACK
        || header.dcid.is_some()
        || header.scid.is_some()
    {
        return Err(Error::Invalid);
    }
    SetupReply::decode(&input[body_at..body_at + body_len])
}

fn put_setup_byte(output: &mut [u8], pos: &mut usize, value: u8) -> Result<(), Error> {
    let Some(byte) = output.get_mut(*pos) else {
        return Err(Error::BufferTooSmall);
    };
    *byte = value;
    *pos += 1;
    Ok(())
}

fn take_setup_byte(input: &[u8], pos: &mut usize) -> Result<u8, Error> {
    let Some(byte) = input.get(*pos).copied() else {
        return Err(Error::Invalid);
    };
    *pos += 1;
    Ok(byte)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum DcidTarget<Endpoint, NextHop> {
    Endpoint(Endpoint),
    Forward(ForwardRule<NextHop>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DcidRegistryError {
    InvalidConnectionId,
    Occupied,
    Full,
    Missing,
    WrongTarget,
    InvalidLeaseGroup,
}

/// Result of the first and only DCID lookup performed by an ingress adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DcidIngress<'a, Endpoint, NextHop> {
    Endpoint(ShortHeaderPrefix, &'a Endpoint),
    Forward(ShortHeaderPrefix, &'a ForwardRule<NextHop>),
}

pub(crate) enum RouterTarget<'a, Endpoint, NextHop> {
    Endpoint(&'a Endpoint),
    Forward(&'a ForwardRule<NextHop>),
    Missing,
}

/// Outcome of classifying one complete bearer packet.  Forwarding has
/// already copied the rewritten packet into caller-owned storage. Endpoint
/// outcomes retain borrowed input because they need no intermediate copy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DcidPacket<'a, Endpoint, NextHop> {
    Endpoint {
        /// DCID selected by this shared QUIC-lite router. Adapters may use it
        /// only to locate their association; packet headers remain private.
        received_dcid: ConnectionId,
        endpoint: &'a Endpoint,
    },
    Forward {
        /// CID from the received packet.  Relay adapters may use this only
        /// for relay-open bookkeeping and diagnostics; they must not parse
        /// the bearer frame a second time.
        received_dcid: ConnectionId,
        rule: &'a ForwardRule<NextHop>,
        used: usize,
    },
}

/// Failure while performing the single DCID classification required at a
/// bearer boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DcidPacketError {
    Header(Error),
    Registry(DcidRegistryError),
    Rewrite(Error),
}

/// Bearer-neutral result of routing one complete packet on a shared listener.
///
/// This is the narrow runtime boundary used by UDP, UART, BLE, and radio
/// bearers. It contains no peer L2 address: the caller keeps the ingress
/// `PacketMeta` and uses it only after the selected QUIC owner accepts the
/// packet.
pub(crate) enum PacketRoute<'a, Endpoint, NextHop> {
    Initial(crate::BootstrapOpen),
    PathOpen(SetupRequestView<'a>),
    PathOpenAck(SetupReply),
    Endpoint {
        destination: ConnectionId,
        endpoint: &'a Endpoint,
    },
    /// An opaque packet matched association-owned state, normally a peer's
    /// stateless-reset token. It intentionally has no parseable destination.
    OpaqueEndpoint {
        endpoint: &'a Endpoint,
    },
    Forward {
        received_dcid: ConnectionId,
        rule: &'a ForwardRule<NextHop>,
        used: usize,
    },
    /// Send `output[..used]` back through the bearer address on which the
    /// unknown short-header packet arrived.
    StatelessReset {
        used: usize,
    },
    Unknown {
        destination: ConnectionId,
    },
}

/// One DCID namespace for endpoint associations and relay forwarding rules.
///
/// The registry remains an implementation detail of the node owner. Bearers
/// submit complete bytes and never inspect a long/short header or use their
/// physical peer L2 address to select an association.
pub(crate) struct PacketRouter<Endpoint, NextHop> {
    registry: DcidRegistry<Endpoint, NextHop>,
    setup_transactions: SetupTransactionTable,
    #[cfg(feature = "stateless-reset")]
    _reset_key: Option<crate::StatelessResetKey>,
}

impl<Endpoint, NextHop> PacketRouter<Endpoint, NextHop> {
    pub(crate) fn new() -> Self {
        Self {
            registry: DcidRegistry::new(),
            setup_transactions: SetupTransactionTable::new(
                DEFAULT_MAX_PENDING_SETUPS,
                DEFAULT_MAX_CACHED_SETUP_REPLIES,
                MAX_SETUP_BODY_BYTES,
                DEFAULT_SETUP_REPLY_BYTES,
                DEFAULT_SETUP_REPLY_STORAGE_BYTES,
                DEFAULT_SETUP_REPLY_RETENTION_US,
            ),
            #[cfg(feature = "stateless-reset")]
            _reset_key: None,
        }
    }

    #[cfg(feature = "stateless-reset")]
    pub(crate) fn new_with_stateless_reset(reset_key: crate::StatelessResetKey) -> Self {
        Self {
            registry: DcidRegistry::new(),
            setup_transactions: SetupTransactionTable::new(
                DEFAULT_MAX_PENDING_SETUPS,
                DEFAULT_MAX_CACHED_SETUP_REPLIES,
                MAX_SETUP_BODY_BYTES,
                DEFAULT_SETUP_REPLY_BYTES,
                DEFAULT_SETUP_REPLY_STORAGE_BYTES,
                DEFAULT_SETUP_REPLY_RETENTION_US,
            ),
            _reset_key: Some(reset_key),
        }
    }

    pub(crate) fn set_max_entries(&mut self, max_entries: usize) {
        self.registry.set_max_entries(max_entries);
    }

    pub(crate) fn register_endpoint(
        &mut self,
        dcid: ConnectionId,
        endpoint: Endpoint,
    ) -> Result<(), DcidRegistryError> {
        self.registry.insert_endpoint(dcid, endpoint)
    }

    pub(crate) fn register_forward(
        &mut self,
        dcid: ConnectionId,
        rule: ForwardRule<NextHop>,
    ) -> Result<(), DcidRegistryError> {
        self.registry.install_forward(dcid, rule)
    }

    /// Install both directions as one registry operation.
    pub(crate) fn register_forward_pair(
        &mut self,
        first_cid: ConnectionId,
        first_rule: ForwardRule<NextHop>,
        second_cid: ConnectionId,
        second_rule: ForwardRule<NextHop>,
    ) -> Result<(), DcidRegistryError> {
        self.registry
            .install_forward_pair(first_cid, first_rule, second_cid, second_rule)
    }

    pub(crate) fn begin_setup_transaction<'a>(
        &'a mut self,
        previous_hop: ForwardNextHop,
        transaction_id: u64,
        request: &[u8],
        reply_capacity: usize,
        now_us: u64,
        pending_deadline_us: u64,
    ) -> SetupTransactionLookup<'a> {
        self.setup_transactions.begin(
            previous_hop,
            transaction_id,
            request,
            reply_capacity,
            now_us,
            pending_deadline_us,
        )
    }

    pub(crate) fn set_setup_downstream_hop(
        &mut self,
        previous_hop: ForwardNextHop,
        transaction_id: u64,
        downstream_hop: ForwardNextHop,
    ) -> Result<(), SetupTransactionError> {
        self.setup_transactions
            .set_downstream_hop(previous_hop, transaction_id, downstream_hop)
    }

    pub(crate) fn setup_downstream_hop(
        &self,
        previous_hop: ForwardNextHop,
        transaction_id: u64,
    ) -> Option<ForwardNextHop> {
        self.setup_transactions
            .downstream_hop(previous_hop, transaction_id)
    }

    pub(crate) fn set_setup_relay_state(
        &mut self,
        previous_hop: ForwardNextHop,
        transaction_id: u64,
        relay_state: SetupRelayState,
    ) -> Result<(), SetupTransactionError> {
        self.setup_transactions
            .set_relay_state(previous_hop, transaction_id, relay_state)
    }

    pub(crate) fn setup_relay_state(
        &self,
        previous_hop: ForwardNextHop,
        transaction_id: u64,
    ) -> Option<SetupRelayState> {
        self.setup_transactions
            .relay_state(previous_hop, transaction_id)
    }

    pub(crate) fn validate_setup_downstream_reply(
        &mut self,
        downstream_hop: ForwardNextHop,
        transaction_id: u64,
        circuit: SetupCircuitKey,
        reply: &[u8],
    ) -> Result<SetupDownstreamReply<'_>, SetupTransactionError> {
        self.setup_transactions.validate_downstream_reply(
            downstream_hop,
            transaction_id,
            circuit,
            reply,
        )
    }

    pub(crate) fn complete_setup_from_downstream(
        &mut self,
        downstream_hop: ForwardNextHop,
        transaction_id: u64,
        reply: &[u8],
        now_us: u64,
    ) -> Result<ForwardNextHop, SetupTransactionError> {
        self.setup_transactions.complete_from_downstream(
            downstream_hop,
            transaction_id,
            reply,
            now_us,
        )
    }

    pub(crate) fn complete_setup_transaction(
        &mut self,
        previous_hop: ForwardNextHop,
        transaction_id: u64,
        reply: &[u8],
        now_us: u64,
    ) -> Result<(), SetupTransactionError> {
        self.setup_transactions
            .complete(previous_hop, transaction_id, reply, now_us)
    }

    pub(crate) fn cancel_setup_transaction(
        &mut self,
        previous_hop: ForwardNextHop,
        transaction_id: u64,
    ) -> bool {
        self.setup_transactions.cancel(previous_hop, transaction_id)
    }

    pub(crate) fn expire_setup_transactions(&mut self, now_us: u64) -> usize {
        self.setup_transactions.expire(now_us)
    }

    pub(crate) fn next_setup_deadline(&self) -> Option<u64> {
        self.setup_transactions.next_deadline()
    }

    #[cfg(test)]
    pub(crate) fn setup_transaction_counts(&self) -> (usize, usize, usize) {
        (
            self.setup_transactions.pending_count(),
            self.setup_transactions.cached_count(),
            self.setup_transactions.reserved_reply_bytes,
        )
    }

    #[cfg(test)]
    pub(crate) fn route_count(&self) -> usize {
        self.registry.len()
    }

    pub(crate) fn contains(&self, dcid: ConnectionId) -> bool {
        self.registry.contains(dcid)
    }

    pub(crate) fn endpoint_for_cid(&self, dcid: ConnectionId) -> Option<&Endpoint> {
        let index = self.registry.find(dcid).ok()?;
        match &self.registry.entries[index].1 {
            DcidTarget::Endpoint(endpoint) => Some(endpoint),
            DcidTarget::Forward(_) => None,
        }
    }

    pub(crate) fn remove_endpoint(&mut self, dcid: ConnectionId, expected: &Endpoint) -> bool
    where
        Endpoint: PartialEq,
    {
        let Ok(index) = self.registry.find(dcid) else {
            return false;
        };
        if !matches!(&self.registry.entries[index].1, DcidTarget::Endpoint(endpoint) if endpoint == expected)
        {
            return false;
        }
        self.registry.entries.remove(index);
        true
    }

    pub(crate) fn remove_forward(&mut self, dcid: ConnectionId) -> bool {
        let Ok(index) = self.registry.find(dcid) else {
            return false;
        };
        if !matches!(self.registry.entries[index].1, DcidTarget::Forward(_)) {
            return false;
        }
        self.registry.entries.remove(index);
        true
    }

    pub(crate) fn remove_forward_pair(
        &mut self,
        first_cid: ConnectionId,
        second_cid: ConnectionId,
    ) -> bool {
        self.registry.remove_forward_pair(first_cid, second_cid)
    }

    pub(crate) fn consume_forward_quota(
        &mut self,
        dcid: ConnectionId,
        control_packet: bool,
        now_us: u64,
    ) -> bool {
        let Ok(index) = self.registry.find(dcid) else {
            return false;
        };
        let DcidTarget::Forward(rule) = &mut self.registry.entries[index].1 else {
            return false;
        };
        if rule.packet_quota == 0 {
            return true;
        }
        let window_us = rule.lease_duration_us.max(1);
        let elapsed_us = now_us.saturating_sub(rule.quota_window_started_us);
        if elapsed_us >= window_us {
            let elapsed_windows = elapsed_us / window_us;
            rule.quota_window_started_us = rule
                .quota_window_started_us
                .saturating_add(elapsed_windows.saturating_mul(window_us));
            rule.forwarded_packets = 0;
            rule.forwarded_control_packets = 0;
        }
        if rule.forwarded_packets >= rule.packet_quota {
            return false;
        }
        let control_reserve = (rule.packet_quota / 16).max(1);
        if !control_packet
            && rule.forwarded_packets >= rule.packet_quota.saturating_sub(control_reserve)
        {
            return false;
        }
        rule.forwarded_packets = rule.forwarded_packets.saturating_add(1);
        if control_packet {
            rule.forwarded_control_packets = rule.forwarded_control_packets.saturating_add(1);
        }
        true
    }

    pub(crate) fn target(
        &self,
        input: &[u8],
    ) -> Result<RouterTarget<'_, Endpoint, NextHop>, Error> {
        let prefix = decode_routing_prefix(input)?;
        match self.registry.ingress(prefix) {
            Ok(DcidIngress::Endpoint(_, endpoint)) => Ok(RouterTarget::Endpoint(endpoint)),
            Ok(DcidIngress::Forward(_, rule)) => Ok(RouterTarget::Forward(rule)),
            Err(DcidRegistryError::Missing) => Ok(RouterTarget::Missing),
            Err(_) => unreachable!("registry lookup reports only a missing key"),
        }
    }

    /// Expire an idle forward rule or renew its inactivity lease for traffic.
    /// Returns false when the CID was an expired forward rule.
    pub(crate) fn refresh_forward_lease(
        &mut self,
        input: &[u8],
        now_us: u64,
    ) -> Result<bool, Error> {
        if !self.forward_lease_active(input, now_us)? {
            return Ok(false);
        }
        let prefix = decode_routing_prefix(input)?;
        let Ok(index) = self.registry.find(prefix.dcid) else {
            return Ok(true);
        };
        let DcidTarget::Forward(rule) = &self.registry.entries[index].1 else {
            return Ok(true);
        };
        let group_id = rule.lease_group_id;
        let expires_at_us = now_us.saturating_add(rule.lease_duration_us);
        if group_id == 0 {
            if let DcidTarget::Forward(rule) = &mut self.registry.entries[index].1 {
                rule.lease_expires_at_us = expires_at_us;
            }
        } else {
            for (_, target) in &mut self.registry.entries {
                if let DcidTarget::Forward(rule) = target
                    && rule.lease_group_id == group_id
                {
                    rule.lease_expires_at_us = expires_at_us;
                }
            }
        }
        Ok(true)
    }

    /// Check lease validity without extending an active rule. Expired paired
    /// directions are removed together before the route is treated as unknown.
    pub(crate) fn forward_lease_active(
        &mut self,
        input: &[u8],
        now_us: u64,
    ) -> Result<bool, Error> {
        let prefix = decode_routing_prefix(input)?;
        let Ok(index) = self.registry.find(prefix.dcid) else {
            return Ok(true);
        };
        let DcidTarget::Forward(rule) = &self.registry.entries[index].1 else {
            return Ok(true);
        };
        if rule.lease_expires_at_us > now_us {
            return Ok(true);
        }
        let group_id = rule.lease_group_id;
        if group_id == 0 {
            self.registry.entries.remove(index);
        } else {
            self.registry.entries.retain(|(_, target)| {
                !matches!(target, DcidTarget::Forward(rule) if rule.lease_group_id == group_id)
            });
        }
        Ok(false)
    }

    pub(crate) fn next_forward_lease_deadline(&self) -> Option<u64> {
        self.registry.next_forward_lease_deadline()
    }

    pub(crate) fn expire_forward_leases(&mut self, now_us: u64) -> usize {
        self.registry.expire_forward_leases(now_us)
    }

    pub(crate) fn opaque_endpoint(
        &self,
        accepts: impl FnMut(&Endpoint) -> bool,
    ) -> Option<&Endpoint> {
        self.registry.endpoint_matching(accepts)
    }

    pub(crate) fn encode_stateless_reset(
        &self,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<Option<usize>, Error> {
        #[cfg(feature = "stateless-reset")]
        {
            match self._reset_key {
                Some(key) => key.encode_for_unknown_packet(input, output),
                None => Ok(None),
            }
        }
        #[cfg(not(feature = "stateless-reset"))]
        {
            let _ = (input, output);
            Ok(None)
        }
    }

    pub(crate) fn reset_token_for(
        &self,
        connection_id: ConnectionId,
    ) -> Option<crate::StatelessResetToken> {
        #[cfg(feature = "stateless-reset")]
        {
            self._reset_key.map(|key| key.token_for(connection_id))
        }
        #[cfg(not(feature = "stateless-reset"))]
        {
            let _ = connection_id;
            None
        }
    }

    pub(crate) fn path_probe_token_for(
        &self,
        connection_id: ConnectionId,
        packet_number: u32,
    ) -> Option<u64> {
        let _ = connection_id;
        // Path validation proves packet return-path reachability only. It is
        // not a cryptographic authenticator; authenticated path-control
        // traffic belongs to the deferred P8 security design.
        Some(u64::from(packet_number).max(1))
    }

    /// Route one packet. Malformed input is rejected after normal parsing;
    /// callers with outgoing client associations use
    /// [`Self::route_with_opaque`] so their private reset tokens are checked.
    #[cfg(test)]
    fn route<'a>(
        &'a self,
        input: &'a [u8],
        output: &mut [u8],
    ) -> Result<PacketRoute<'a, Endpoint, NextHop>, Error> {
        self.route_with_opaque(input, output, |_, _| false)
    }

    /// Route one packet and offer otherwise-unparseable bytes to endpoint
    /// state. The callback must check only association-owned opaque state; it
    /// must not parse another routing header or compare a bearer address.
    #[cfg(test)]
    fn route_with_opaque<'a>(
        &'a self,
        input: &'a [u8],
        output: &mut [u8],
        mut accepts_opaque: impl FnMut(&Endpoint, &[u8]) -> bool,
    ) -> Result<PacketRoute<'a, Endpoint, NextHop>, Error> {
        let classified = match classify_server_packet(input) {
            Ok(classified) => classified,
            Err(error) => {
                if let Some(endpoint) = self
                    .registry
                    .endpoint_matching(|endpoint| accepts_opaque(endpoint, input))
                {
                    return Ok(PacketRoute::OpaqueEndpoint { endpoint });
                }
                return Err(error);
            }
        };
        match classified {
            ServerPacket::Initial(open) => Ok(PacketRoute::Initial(open)),
            ServerPacket::PathOpen => {
                Ok(PacketRoute::PathOpen(decode_setup_request_packet(input)?))
            }
            ServerPacket::PathOpenAck => {
                Ok(PacketRoute::PathOpenAck(decode_setup_reply_packet(input)?))
            }
            _classified @ (ServerPacket::BootstrapAck { destination }
            | ServerPacket::Established { destination }) => {
                let prefix = decode_routing_prefix(input)?;
                match self.registry.ingress(prefix) {
                    Ok(DcidIngress::Endpoint(_, endpoint)) => Ok(PacketRoute::Endpoint {
                        destination,
                        endpoint,
                    }),
                    Ok(DcidIngress::Forward(_, rule)) => {
                        let used = match rule.destination {
                            ForwardDestination::Connection(dcid) => {
                                rewrite_dcid(input, dcid, output)
                            }
                            ForwardDestination::Bootstrap => {
                                rewrite_bootstrap_destination(input, output)
                            }
                        }?;
                        Ok(PacketRoute::Forward {
                            received_dcid: destination,
                            rule,
                            used,
                        })
                    }
                    Err(DcidRegistryError::Missing) => {
                        #[cfg(feature = "stateless-reset")]
                        let may_reset = matches!(_classified, ServerPacket::Established { .. });
                        #[cfg(feature = "stateless-reset")]
                        if may_reset && let Some(reset_key) = self._reset_key {
                            if let Some(used) =
                                reset_key.encode_for_unknown_packet(input, output)?
                            {
                                return Ok(PacketRoute::StatelessReset { used });
                            }
                        }
                        Ok(PacketRoute::Unknown { destination })
                    }
                    Err(_) => unreachable!("registry lookup reports only a missing key"),
                }
            }
        }
    }
}

/// Classify one complete QUIC-lite-shaped packet before any endpoint or
/// application dispatcher runs. A forwarding target rewrites only the DCID
/// into `output`; flags, packet number, and body are preserved byte-for-byte.
///
/// `output` is deliberately caller-owned because ESP Main must use its shared
/// packet pool and host/Android own their socket buffers. This function owns no
/// queues, clock, transport metadata, or next-hop policy.
pub(crate) fn dispatch_packet<'a, Endpoint, NextHop>(
    registry: &'a DcidRegistry<Endpoint, NextHop>,
    input: &'a [u8],
    output: &mut [u8],
) -> Result<DcidPacket<'a, Endpoint, NextHop>, DcidPacketError> {
    let prefix = decode_routing_prefix(input).map_err(DcidPacketError::Header)?;
    match registry
        .ingress(prefix)
        .map_err(DcidPacketError::Registry)?
    {
        DcidIngress::Endpoint(prefix, endpoint) => Ok(DcidPacket::Endpoint {
            received_dcid: prefix.dcid,
            endpoint,
        }),
        DcidIngress::Forward(_, rule) => {
            let used = match rule.destination {
                ForwardDestination::Connection(dcid) => rewrite_dcid(input, dcid, output),
                ForwardDestination::Bootstrap => rewrite_bootstrap_destination(input, output),
            }
            .map_err(DcidPacketError::Rewrite)?;
            Ok(DcidPacket::Forward {
                received_dcid: prefix.dcid,
                rule,
                used,
            })
        }
    }
}

/// Fixed-capacity registry for all non-zero local DCIDs.
#[derive(Clone)]
pub(crate) struct DcidRegistry<Endpoint, NextHop> {
    entries: Vec<(ConnectionId, DcidTarget<Endpoint, NextHop>)>,
    max_entries: usize,
}

impl<Endpoint, NextHop> Default for DcidRegistry<Endpoint, NextHop> {
    fn default() -> Self {
        Self::new()
    }
}

impl<Endpoint, NextHop> DcidRegistry<Endpoint, NextHop> {
    pub(crate) fn new() -> Self {
        Self {
            entries: Vec::new(),
            max_entries: usize::MAX,
        }
    }

    pub(crate) fn set_max_entries(&mut self, max_entries: usize) {
        self.max_entries = max_entries;
    }

    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    fn next_forward_lease_deadline(&self) -> Option<u64> {
        self.entries
            .iter()
            .filter_map(|(_, target)| match target {
                DcidTarget::Forward(rule) => Some(rule.lease_expires_at_us),
                DcidTarget::Endpoint(_) => None,
            })
            .min()
    }

    fn expire_forward_leases(&mut self, now_us: u64) -> usize {
        let previous_len = self.entries.len();
        self.entries.retain(|(_, target)| match target {
            DcidTarget::Forward(rule) => rule.lease_expires_at_us > now_us,
            DcidTarget::Endpoint(_) => true,
        });
        previous_len - self.entries.len()
    }

    /// Whether a non-zero local DCID is already owned by any endpoint or
    /// forwarding target. Reconciliation uses this to reject a replacement
    /// before removing the currently active rule.
    pub(crate) fn contains(&self, dcid: ConnectionId) -> bool {
        self.find(dcid).is_ok()
    }

    pub(crate) fn insert_endpoint(
        &mut self,
        dcid: ConnectionId,
        endpoint: Endpoint,
    ) -> Result<(), DcidRegistryError> {
        self.insert(dcid, DcidTarget::Endpoint(endpoint))
    }

    pub(crate) fn install_forward(
        &mut self,
        dcid: ConnectionId,
        rule: ForwardRule<NextHop>,
    ) -> Result<(), DcidRegistryError> {
        if rule.lease_group_id != 0 {
            return Err(DcidRegistryError::InvalidLeaseGroup);
        }
        self.insert(dcid, DcidTarget::Forward(rule))
    }

    /// Install both directions as one registry operation. The registry is
    /// unchanged if either CID conflicts, the pair is invalid, capacity is
    /// exhausted, or storage cannot reserve both entries.
    pub(crate) fn install_forward_pair(
        &mut self,
        first_cid: ConnectionId,
        first_rule: ForwardRule<NextHop>,
        second_cid: ConnectionId,
        second_rule: ForwardRule<NextHop>,
    ) -> Result<(), DcidRegistryError> {
        if first_cid.value() == 0 || second_cid.value() == 0 {
            return Err(DcidRegistryError::InvalidConnectionId);
        }
        if first_cid == second_cid
            || first_rule.lease_group_id == 0
            || first_rule.lease_group_id != second_rule.lease_group_id
            || first_rule.lease_duration_us != second_rule.lease_duration_us
            || first_rule.lease_expires_at_us != second_rule.lease_expires_at_us
            || first_rule.packet_quota != second_rule.packet_quota
            || first_rule.forwarded_packets != 0
            || second_rule.forwarded_packets != 0
            || first_rule.forwarded_control_packets != 0
            || second_rule.forwarded_control_packets != 0
        {
            return Err(DcidRegistryError::InvalidLeaseGroup);
        }
        if self.entries.iter().any(|(_, target)| {
            matches!(target, DcidTarget::Forward(rule) if rule.lease_group_id == first_rule.lease_group_id)
        }) {
            return Err(DcidRegistryError::Occupied);
        }
        if self.find(first_cid).is_ok() || self.find(second_cid).is_ok() {
            return Err(DcidRegistryError::Occupied);
        }
        if self.entries.len().saturating_add(2) > self.max_entries {
            return Err(DcidRegistryError::Full);
        }
        self.entries
            .try_reserve(2)
            .map_err(|_| DcidRegistryError::Full)?;

        let (low_cid, low_rule, high_cid, high_rule) = if first_cid < second_cid {
            (first_cid, first_rule, second_cid, second_rule)
        } else {
            (second_cid, second_rule, first_cid, first_rule)
        };
        let low_index = self.find(low_cid).unwrap_err();
        self.entries
            .insert(low_index, (low_cid, DcidTarget::Forward(low_rule)));
        let high_index = self.find(high_cid).unwrap_err();
        self.entries
            .insert(high_index, (high_cid, DcidTarget::Forward(high_rule)));
        Ok(())
    }

    fn remove_forward_pair(&mut self, first_cid: ConnectionId, second_cid: ConnectionId) -> bool {
        let (Ok(first_index), Ok(second_index)) = (self.find(first_cid), self.find(second_cid))
        else {
            return false;
        };
        let (DcidTarget::Forward(first), DcidTarget::Forward(second)) =
            (&self.entries[first_index].1, &self.entries[second_index].1)
        else {
            return false;
        };
        if first_cid == second_cid
            || first.lease_group_id == 0
            || first.lease_group_id != second.lease_group_id
        {
            return false;
        }
        let group = first.lease_group_id;
        self.entries.retain(|(_, target)| {
            !matches!(target, DcidTarget::Forward(rule) if rule.lease_group_id == group)
        });
        true
    }

    /// Install a forward rule once, or accept an exact duplicate as an
    /// idempotent control retry. Returns whether this call inserted a new
    /// entry. A different target for the same local DCID remains a conflict.
    pub(crate) fn install_forward_idempotent(
        &mut self,
        dcid: ConnectionId,
        rule: ForwardRule<NextHop>,
    ) -> Result<bool, DcidRegistryError>
    where
        NextHop: Eq,
    {
        if dcid.value() == 0 {
            return Err(DcidRegistryError::InvalidConnectionId);
        }
        if let Ok(index) = self.find(dcid) {
            let target = &self.entries[index].1;
            return match target {
                DcidTarget::Forward(existing) if *existing == rule => Ok(false),
                _ => Err(DcidRegistryError::Occupied),
            };
        }
        self.insert(dcid, DcidTarget::Forward(rule))?;
        Ok(true)
    }

    /// Replace only an existing forwarding target.  Endpoint ownership cannot
    /// be silently overwritten by relay setup.
    pub(crate) fn update_forward(
        &mut self,
        dcid: ConnectionId,
        rule: ForwardRule<NextHop>,
    ) -> Result<(), DcidRegistryError> {
        let Ok(index) = self.find(dcid) else {
            return Err(DcidRegistryError::Missing);
        };
        let target = &mut self.entries[index].1;
        if !matches!(target, DcidTarget::Forward(_)) {
            return Err(DcidRegistryError::WrongTarget);
        }
        *target = DcidTarget::Forward(rule);
        Ok(())
    }

    pub(crate) fn remove(&mut self, dcid: ConnectionId) -> Option<DcidTarget<Endpoint, NextHop>> {
        let index = self.find(dcid).ok()?;
        Some(self.entries.remove(index).1)
    }

    pub(crate) fn ingress(
        &self,
        prefix: ShortHeaderPrefix,
    ) -> Result<DcidIngress<'_, Endpoint, NextHop>, DcidRegistryError> {
        let index = self
            .find(prefix.dcid)
            .map_err(|_| DcidRegistryError::Missing)?;
        let target = &self.entries[index].1;
        Ok(match target {
            DcidTarget::Endpoint(endpoint) => DcidIngress::Endpoint(prefix, endpoint),
            DcidTarget::Forward(rule) => DcidIngress::Forward(prefix, rule),
        })
    }

    fn find(&self, dcid: ConnectionId) -> Result<usize, usize> {
        self.entries.binary_search_by_key(&dcid, |(key, _)| *key)
    }

    fn endpoint_matching(&self, mut predicate: impl FnMut(&Endpoint) -> bool) -> Option<&Endpoint> {
        self.entries.iter().find_map(|(_, target)| match target {
            DcidTarget::Endpoint(endpoint) if predicate(endpoint) => Some(endpoint),
            _ => None,
        })
    }

    fn insert(
        &mut self,
        dcid: ConnectionId,
        target: DcidTarget<Endpoint, NextHop>,
    ) -> Result<(), DcidRegistryError> {
        if dcid.value() == 0 {
            return Err(DcidRegistryError::InvalidConnectionId);
        }
        let index = match self.find(dcid) {
            Ok(_) => return Err(DcidRegistryError::Occupied),
            Err(index) => index,
        };
        if self.entries.len() >= self.max_entries {
            return Err(DcidRegistryError::Full);
        }
        self.entries
            .try_reserve(1)
            .map_err(|_| DcidRegistryError::Full)?;
        self.entries.insert(index, (dcid, target));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FLAG_FIXED, ShortHeader};

    #[test]
    fn create_endpoint_hints_round_trip_and_keep_legacy_payloads() {
        let return_hints = crate::NearbyRelayHints::new(&[
            crate::NearbyRelayHint {
                relay_id: [1; 8],
                hop: crate::RelayHop::new(2, &[3, 4], 60_000_000, 1024).unwrap(),
            },
            crate::NearbyRelayHint {
                relay_id: [5; 8],
                hop: crate::RelayHop::new(3, &[6], 30_000_000, 512).unwrap(),
            },
        ])
        .unwrap();
        let endpoint = SetupCreateEndpoint {
            initial_packet: &[0x91, 0x92, 0x93],
            return_hints,
        };
        let mut encoded = [0u8; MAX_SETUP_BLOCK_BYTES];
        let used = endpoint.encode(&mut encoded).unwrap();
        let (initial_packet, decoded_hints) =
            SetupCreateEndpoint::decode(&encoded[..used], 2).unwrap();
        assert_eq!(initial_packet, endpoint.initial_packet);
        assert_eq!(decoded_hints, return_hints);

        let (legacy_initial, legacy_hints) =
            SetupCreateEndpoint::decode(endpoint.initial_packet, 1).unwrap();
        assert_eq!(legacy_initial, endpoint.initial_packet);
        assert_eq!(legacy_hints, crate::NearbyRelayHints::EMPTY);
    }

    #[test]
    fn endpoint_and_forward_target_share_one_registry() {
        let endpoint = ConnectionId::new(4).unwrap();
        let relay = ConnectionId::new(0x234).unwrap();
        let mut registry = DcidRegistry::<u8, u16>::new();
        registry.set_max_entries(2);
        registry.insert_endpoint(endpoint, 7).unwrap();
        registry
            .install_forward(
                relay,
                ForwardRule {
                    next_hop: 9,
                    destination: ForwardDestination::Bootstrap,
                    lease_duration_us: 1_000,
                    lease_expires_at_us: 10_000,
                    lease_group_id: 0,
                    packet_quota: 0,
                    forwarded_packets: 0,
                    forwarded_control_packets: 0,
                    quota_window_started_us: 0,
                },
            )
            .unwrap();

        let mut endpoint_packet = [0; 16];
        let endpoint_len = ShortHeader {
            flags: FLAG_FIXED,
            dcid: endpoint,
            packet_number: 1,
            packet_number_len: 1,
        }
        .encode(&mut endpoint_packet)
        .unwrap();
        let endpoint_prefix = ShortHeader::decode_prefix(&endpoint_packet[..endpoint_len]).unwrap();
        assert!(matches!(
            registry.ingress(endpoint_prefix),
            Ok(DcidIngress::Endpoint(_, 7))
        ));

        let mut relay_packet = [0; 16];
        let relay_len = ShortHeader {
            flags: FLAG_FIXED,
            dcid: relay,
            packet_number: 2,
            packet_number_len: 1,
        }
        .encode(&mut relay_packet)
        .unwrap();
        let relay_prefix = ShortHeader::decode_prefix(&relay_packet[..relay_len]).unwrap();
        assert!(matches!(
            registry.ingress(relay_prefix),
            Ok(DcidIngress::Forward(_, ForwardRule { next_hop: 9, .. }))
        ));
    }

    #[test]
    fn directional_forward_rules_install_atomically_and_share_one_lease() {
        let first = ConnectionId::new(0x31).unwrap();
        let second = ConnectionId::new(0x32).unwrap();
        let mut router = PacketRouter::<(), u16>::new();
        router.set_max_entries(2);
        let make_rule = |next_hop, destination| ForwardRule {
            next_hop,
            destination: ForwardDestination::Connection(destination),
            lease_duration_us: 1_000,
            lease_expires_at_us: 100,
            lease_group_id: 42,
            packet_quota: 0,
            forwarded_packets: 0,
            forwarded_control_packets: 0,
            quota_window_started_us: 0,
        };
        router
            .register_forward_pair(
                first,
                make_rule(1, ConnectionId::new(0x41).unwrap()),
                second,
                make_rule(2, ConnectionId::new(0x42).unwrap()),
            )
            .unwrap();
        assert_eq!(router.registry.len(), 2);
        assert_eq!(router.next_forward_lease_deadline(), Some(100));

        let mut packet = [0u8; 16];
        let used = ShortHeader {
            flags: FLAG_FIXED,
            dcid: first,
            packet_number: 1,
            packet_number_len: 1,
        }
        .encode(&mut packet)
        .unwrap();
        assert!(router.refresh_forward_lease(&packet[..used], 99).unwrap());
        assert!(router.registry.entries.iter().all(|(_, target)| matches!(
            target,
            DcidTarget::Forward(rule) if rule.lease_expires_at_us == 1_099
        )));
        assert_eq!(router.next_forward_lease_deadline(), Some(1_099));
        assert_eq!(router.expire_forward_leases(1_098), 0);
        assert_eq!(router.expire_forward_leases(1_099), 2);
        assert_eq!(router.registry.len(), 0);
    }

    #[test]
    fn forward_packet_quota_reserves_control_capacity() {
        let mut router = PacketRouter::<(), u16>::new();
        router.set_max_entries(2);
        let first = ConnectionId::new(0x51).unwrap();
        let second = ConnectionId::new(0x52).unwrap();
        let make_rule = |next_hop, destination| ForwardRule {
            next_hop,
            destination: ForwardDestination::Connection(destination),
            lease_duration_us: 1_000,
            lease_expires_at_us: 1_000,
            lease_group_id: 91,
            packet_quota: 4,
            forwarded_packets: 0,
            forwarded_control_packets: 0,
            quota_window_started_us: 0,
        };
        router
            .register_forward_pair(
                first,
                make_rule(1, ConnectionId::new(0x61).unwrap()),
                second,
                make_rule(2, ConnectionId::new(0x62).unwrap()),
            )
            .unwrap();

        assert!(router.consume_forward_quota(first, false, 0));
        assert!(router.consume_forward_quota(first, false, 0));
        assert!(router.consume_forward_quota(first, false, 0));
        assert!(!router.consume_forward_quota(first, false, 0));
        assert!(router.consume_forward_quota(first, true, 0));
        assert!(!router.consume_forward_quota(first, true, 0));
        assert!(router.consume_forward_quota(second, false, 0));
        assert!(router.consume_forward_quota(first, false, 1_000));
    }

    #[test]
    fn failed_directional_forward_install_leaves_registry_unchanged() {
        let first = ConnectionId::new(0x31).unwrap();
        let second = ConnectionId::new(0x32).unwrap();
        let mut registry = DcidRegistry::<(), u16>::new();
        registry.set_max_entries(1);
        let rule = |next_hop, destination| ForwardRule {
            next_hop,
            destination: ForwardDestination::Connection(destination),
            lease_duration_us: 1_000,
            lease_expires_at_us: 2_000,
            lease_group_id: 7,
            packet_quota: 0,
            forwarded_packets: 0,
            forwarded_control_packets: 0,
            quota_window_started_us: 0,
        };
        assert_eq!(
            registry.install_forward_pair(
                first,
                rule(1, ConnectionId::new(0x41).unwrap()),
                second,
                rule(2, ConnectionId::new(0x42).unwrap()),
            ),
            Err(DcidRegistryError::Full)
        );
        assert_eq!(registry.len(), 0);

        registry.set_max_entries(3);
        registry.insert_endpoint(second, ()).unwrap();
        assert_eq!(
            registry.install_forward_pair(
                first,
                rule(1, ConnectionId::new(0x41).unwrap()),
                second,
                rule(2, ConnectionId::new(0x43).unwrap()),
            ),
            Err(DcidRegistryError::Occupied)
        );
        assert_eq!(registry.len(), 1);
        assert!(!registry.contains(first));
    }

    #[test]
    fn setup_transactions_deduplicate_replay_and_reject_conflicting_retries() {
        let source = ForwardNextHop {
            bearer: BearerId::new(1).unwrap(),
            peer_l2_address: PeerL2Address::new(9).unwrap(),
        };
        let mut table = SetupTransactionTable::new(2, 4, 32, 16, 32, 10);
        assert!(matches!(
            table.begin(source, 7, b"setup", 8, 0, 100),
            SetupTransactionLookup::New
        ));
        assert!(matches!(
            table.begin(source, 7, b"setup", 8, 50, 500),
            SetupTransactionLookup::PendingRetry
        ));
        assert_eq!(table.entries[0].pending_deadline_us, 100);
        assert!(matches!(
            table.begin(source, 7, b"different", 8, 50, 500),
            SetupTransactionLookup::Conflict
        ));
        table.complete(source, 7, b"reply", 99).unwrap();
        assert_eq!(table.pending_count(), 0);
        assert_eq!(table.cached_count(), 1);
        assert!(matches!(
            table.begin(source, 7, b"setup", 8, 108, 500),
            SetupTransactionLookup::Replay(b"reply")
        ));
        assert_eq!(table.expire(109), 1);
        assert_eq!(table.cached_count(), 0);
        assert_eq!(table.reserved_reply_bytes, 0);
    }

    #[test]
    fn setup_transaction_admission_reserves_reply_space_and_cancellation_releases_it() {
        let source = ForwardNextHop {
            bearer: BearerId::new(1).unwrap(),
            peer_l2_address: PeerL2Address::new(9).unwrap(),
        };
        let mut table = SetupTransactionTable::new(1, 2, 32, 16, 8, 10);
        assert!(matches!(
            table.begin(source, 1, b"setup", 9, 0, 100),
            SetupTransactionLookup::Full
        ));
        assert!(matches!(
            table.begin(source, 1, b"setup", 8, 0, 100),
            SetupTransactionLookup::New
        ));
        assert!(matches!(
            table.begin(source, 2, b"other", 1, 1, 100),
            SetupTransactionLookup::Full
        ));
        assert!(table.cancel(source, 1));
        assert_eq!(table.pending_count(), 0);
        assert_eq!(table.reserved_reply_bytes, 0);
        assert!(matches!(
            table.begin(source, 1, b"setup", 1, 1, 100),
            SetupTransactionLookup::Expired
        ));
        assert!(matches!(
            table.begin(source, 2, b"other", 1, 1, 100),
            SetupTransactionLookup::New
        ));
        assert_eq!(table.expire(100), 1);
        assert_eq!(table.pending_count(), 0);
    }

    #[test]
    fn idle_pending_setup_expiry_releases_reservation_and_retained_entry() {
        let source = ForwardNextHop {
            bearer: BearerId::new(1).unwrap(),
            peer_l2_address: PeerL2Address::new(9).unwrap(),
        };
        let mut table = SetupTransactionTable::new(1, 2, 32, 16, 32, 10);
        assert!(matches!(
            table.begin(source, 4, b"setup", 8, 0, 100),
            SetupTransactionLookup::New
        ));
        assert_eq!(table.pending_count(), 1);
        assert_eq!(table.reserved_reply_bytes, 8);
        assert_eq!(table.next_deadline(), Some(100));

        assert_eq!(table.expire(100), 1);
        assert_eq!(table.pending_count(), 0);
        assert_eq!(table.cached_count(), 0);
        assert_eq!(table.reserved_reply_bytes, 0);
        assert_eq!(table.next_deadline(), Some(110));
        assert!(matches!(
            table.begin(source, 4, b"setup", 8, 100, 200),
            SetupTransactionLookup::Expired
        ));

        assert_eq!(table.expire(110), 1);
        assert!(table.entries.is_empty());
        assert_eq!(table.next_deadline(), None);
        assert_eq!(table.reserved_reply_bytes, 0);
    }

    #[test]
    fn setup_request_codec_preserves_versioned_length_delimited_blocks() {
        let blocks = [
            SetupBlock {
                kind: 1,
                version: 1,
                protection: 0,
                payload: b"relay egress",
            },
            SetupBlock {
                kind: 2,
                version: 3,
                protection: 0,
                payload: b"endpoint join settings",
            },
        ];
        let request = SetupRequest {
            transaction_id: 17,
            mode: SetupMode::Join,
            route_mode: RelayRouteMode::Layered,
            circuit: SetupCircuitKey {
                opener_role: crate::Role::Server,
                sequence: 9,
            },
            destination_vip: Some(0x1020_3040_5060_7080),
            previous_reverse_cid: None,
            blocks: &blocks,
        };
        let mut encoded = [0u8; 256];
        let used = request.encode(&mut encoded).unwrap();
        let block_offset = {
            let decoded = SetupRequest::decode(&encoded[..used]).unwrap();
            assert_eq!(decoded.transaction_id, request.transaction_id);
            assert_eq!(decoded.mode, request.mode);
            assert_eq!(decoded.circuit, request.circuit);
            assert_eq!(decoded.destination_vip, request.destination_vip);
            assert_eq!(decoded.blocks.count(), 2);
            assert_eq!(decoded.blocks.get(0).unwrap().unwrap(), blocks[0]);
            assert_eq!(decoded.blocks.get(1).unwrap().unwrap(), blocks[1]);
            assert!(decoded.blocks.get(2).is_none());
            used - decoded.blocks.bytes.len()
        };

        assert_eq!(
            SetupRequest::decode(&encoded[..used - 1]),
            Err(Error::Invalid)
        );
        encoded[used] = 0;
        assert_eq!(
            SetupRequest::decode(&encoded[..used + 1]),
            Err(Error::Invalid)
        );

        encoded[block_offset + 2] = 1;
        assert_eq!(SetupRequest::decode(&encoded[..used]), Err(Error::Invalid));
    }

    #[test]
    fn setup_packets_use_distinct_connectionless_long_header_types() {
        let payload = [0x11, 0x22];
        let block = SetupBlock {
            kind: SETUP_BLOCK_ENDPOINT,
            version: 1,
            protection: 0,
            payload: &payload,
        };
        let request = SetupRequest {
            transaction_id: 11,
            mode: SetupMode::Create,
            route_mode: RelayRouteMode::Layered,
            circuit: SetupCircuitKey {
                opener_role: crate::Role::Client,
                sequence: 3,
            },
            destination_vip: Some(0x0102_0304_0506_0708),
            previous_reverse_cid: None,
            blocks: core::slice::from_ref(&block),
        };
        let mut packet = [0u8; crate::DEFAULT_MAX_PACKET_SIZE];
        let used = request.encode_packet(&mut packet).unwrap();
        let decoded = decode_setup_request_packet(&packet[..used]).unwrap();
        assert_eq!(decoded.transaction_id, request.transaction_id);
        assert_eq!(decoded.mode, request.mode);
        assert_eq!(decoded.circuit, request.circuit);
        assert_eq!(decoded.destination_vip, request.destination_vip);
        assert_eq!(decoded.blocks.get(0).unwrap().unwrap(), block);

        let reply = SetupReply {
            transaction_id: request.transaction_id,
            circuit: request.circuit,
            result: SetupResult::Rejected { code: 9 },
            bootstrap_ack: None,
            relay_cids: SetupRelayCids::empty(),
        };
        let used = reply.encode_packet(&mut packet).unwrap();
        assert_eq!(decode_setup_reply_packet(&packet[..used]), Ok(reply));
        assert_eq!(
            decode_setup_request_packet(&packet[..used]),
            Err(Error::Invalid)
        );
    }

    #[test]
    fn setup_request_codec_rejects_invalid_keys_and_excess_blocks() {
        let payload = [1u8];
        let block = SetupBlock {
            kind: 1,
            version: 1,
            protection: 0,
            payload: &payload,
        };
        let mut output = [0u8; 128];
        let mut request = SetupRequest {
            transaction_id: 0,
            mode: SetupMode::Create,
            route_mode: RelayRouteMode::Layered,
            circuit: SetupCircuitKey {
                opener_role: crate::Role::Client,
                sequence: 1,
            },
            destination_vip: None,
            previous_reverse_cid: None,
            blocks: core::slice::from_ref(&block),
        };
        assert_eq!(request.encode(&mut output), Err(Error::Invalid));
        request.transaction_id = 1;
        request.circuit.sequence = 0;
        assert_eq!(request.encode(&mut output), Err(Error::Invalid));

        request.circuit.sequence = 1;
        let too_many = [block; MAX_SETUP_BLOCKS + 1];
        request.blocks = &too_many;
        assert_eq!(request.encode(&mut output), Err(Error::Invalid));
    }

    #[test]
    fn setup_hop_instruction_round_trips_and_checks_egress_limits() {
        let instruction = SetupHopInstruction {
            address_kind: 3,
            address_len: 6,
            address: [1, 2, 3, 4, 5, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            lease_us: 30_000_000,
            packet_quota: 4096,
        };
        let mut encoded = [0u8; MAX_SETUP_BLOCK_BYTES];
        let used = instruction.encode(&mut encoded).unwrap();
        assert_eq!(
            SetupHopInstruction::decode(&encoded[..used]),
            Ok(instruction)
        );
        assert_eq!(
            SetupHopInstruction::decode(&encoded[..used - 1]),
            Err(Error::Truncated)
        );

        let invalid = SetupHopInstruction {
            address_kind: 0,
            ..instruction
        };
        assert_eq!(invalid.encode(&mut encoded), Err(Error::Invalid));
    }

    #[test]
    fn layered_setup_consumes_only_the_current_hop_block() {
        let instruction = SetupHopInstruction {
            address_kind: 3,
            address_len: 6,
            address: [1, 2, 3, 4, 5, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            lease_us: 30_000_000,
            packet_quota: 4096,
        };
        let mut relay_payload = [0u8; MAX_SETUP_BLOCK_BYTES];
        let relay_payload_len = instruction.encode(&mut relay_payload).unwrap();
        let endpoint_payload = [0xaa, 0xbb, 0xcc];
        let blocks = [
            SetupBlock {
                kind: SETUP_BLOCK_RELAY,
                version: 1,
                protection: 0,
                payload: &relay_payload[..relay_payload_len],
            },
            SetupBlock {
                kind: SETUP_BLOCK_ENDPOINT,
                version: 2,
                protection: 0,
                payload: &endpoint_payload,
            },
        ];
        let request = SetupRequest {
            transaction_id: 19,
            mode: SetupMode::Create,
            route_mode: RelayRouteMode::Layered,
            circuit: SetupCircuitKey {
                opener_role: crate::Role::Client,
                sequence: 7,
            },
            destination_vip: Some(0x0102_0304_0506_0708),
            previous_reverse_cid: None,
            blocks: &blocks,
        };
        let mut encoded = [0u8; 256];
        let used = request.encode(&mut encoded).unwrap();
        let decoded = SetupRequest::decode(&encoded[..used]).unwrap();
        assert_eq!(decoded.current_hop_instruction().unwrap().address_kind, 3);

        let mut forwarded = [0u8; 256];
        let forwarded_len = decoded.encode_after_first_block(&mut forwarded).unwrap();
        let forwarded = SetupRequest::decode(&forwarded[..forwarded_len]).unwrap();
        assert_eq!(forwarded.transaction_id, request.transaction_id);
        assert_eq!(forwarded.circuit, request.circuit);
        assert_eq!(forwarded.destination_vip, request.destination_vip);
        assert_eq!(forwarded.blocks.count(), 1);
        assert_eq!(forwarded.blocks.get(0).unwrap().unwrap(), blocks[1]);
        assert_eq!(forwarded.current_hop_instruction(), Err(Error::Invalid));
        assert_eq!(
            decoded.encode_after_first_block(&mut [0u8; 1]),
            Err(Error::BufferTooSmall)
        );
    }

    #[test]
    fn setup_reply_codec_echoes_transaction_key_and_result() {
        let accepted = SetupReply {
            transaction_id: 23,
            circuit: SetupCircuitKey {
                opener_role: crate::Role::Client,
                sequence: 5,
            },
            result: SetupResult::Accepted {
                endpoint_cid: ConnectionId::new(0x1234).unwrap(),
                lease_us: 30_000_000,
            },
            bootstrap_ack: None,
            relay_cids: SetupRelayCids::empty(),
        };
        let rejected = SetupReply {
            result: SetupResult::Rejected { code: 4 },
            ..accepted
        };
        let mut output = [0u8; 64];
        let used = accepted.encode(&mut output).unwrap();
        assert_eq!(SetupReply::decode(&output[..used]), Ok(accepted));
        let used = rejected.encode(&mut output).unwrap();
        assert_eq!(SetupReply::decode(&output[..used]), Ok(rejected));
        output[used] = 0;
        assert_eq!(SetupReply::decode(&output[..used + 1]), Err(Error::Invalid));
    }

    #[test]
    fn dispatches_endpoint_and_forward_once() {
        let endpoint = ConnectionId::new(4).unwrap();
        let relay = ConnectionId::new(0x234).unwrap();
        let mut registry = DcidRegistry::<u8, u16>::new();
        registry.set_max_entries(2);
        registry.insert_endpoint(endpoint, 7).unwrap();
        registry
            .install_forward(
                relay,
                ForwardRule {
                    next_hop: 9,
                    destination: ForwardDestination::Connection(ConnectionId::new(5).unwrap()),
                    lease_duration_us: 1_000,
                    lease_expires_at_us: 10_000,
                    lease_group_id: 0,
                    packet_quota: 0,
                    forwarded_packets: 0,
                    forwarded_control_packets: 0,
                    quota_window_started_us: 0,
                },
            )
            .unwrap();

        let mut output = [0; 32];

        let mut endpoint_packet = [0; 16];
        let endpoint_len = ShortHeader {
            flags: FLAG_FIXED,
            dcid: endpoint,
            packet_number: 1,
            packet_number_len: 1,
        }
        .encode(&mut endpoint_packet)
        .unwrap();
        assert!(matches!(
            dispatch_packet(&registry, &endpoint_packet[..endpoint_len], &mut output),
            Ok(DcidPacket::Endpoint { received_dcid, endpoint: 7 })
                if received_dcid == endpoint
        ));

        let mut relay_packet = [0; 16];
        let relay_len = ShortHeader {
            flags: FLAG_FIXED,
            dcid: relay,
            packet_number: 2,
            packet_number_len: 1,
        }
        .encode(&mut relay_packet)
        .unwrap();
        let used =
            match dispatch_packet(&registry, &relay_packet[..relay_len], &mut output).unwrap() {
                DcidPacket::Forward { rule, used, .. } => {
                    assert_eq!(rule.next_hop, 9);
                    used
                }
                _ => panic!("expected forward"),
            };
        let (rewritten, _) = ShortHeader::decode(&output[..used]).unwrap();
        assert_eq!(rewritten.dcid.value(), 5);
        assert_eq!(rewritten.packet_number, 2);
    }

    #[test]
    fn bootstrap_forwarding_uses_an_empty_long_header_destination() {
        let relay = ConnectionId::new(0x234).unwrap();
        let source = ConnectionId::new(11).unwrap();
        let mut registry = DcidRegistry::<(), u16>::new();
        registry.set_max_entries(1);
        registry
            .install_forward(
                relay,
                ForwardRule {
                    next_hop: 9,
                    destination: ForwardDestination::Bootstrap,
                    lease_duration_us: 1_000,
                    lease_expires_at_us: 10_000,
                    lease_group_id: 0,
                    packet_quota: 0,
                    forwarded_packets: 0,
                    forwarded_control_packets: 0,
                    quota_window_started_us: 0,
                },
            )
            .unwrap();
        let mut packet = [0; 64];
        let packet_len = crate::encode_long_packet(
            crate::LONG_PACKET_INITIAL,
            Some(relay),
            Some(source),
            1,
            4,
            &[0xa0],
            &mut packet,
        )
        .unwrap();
        let mut output = [0; 64];
        let DcidPacket::Forward { used, .. } =
            dispatch_packet(&registry, &packet[..packet_len], &mut output).unwrap()
        else {
            panic!("bootstrap packet must be forwarded")
        };
        let (header, _, _) = crate::decode_long_packet(&output[..used]).unwrap();
        assert_eq!(header.dcid, None);
        assert_eq!(header.scid, Some(source));
    }

    #[test]
    fn an_initial_with_an_empty_destination_is_not_a_registry_route() {
        let source = ConnectionId::new(11).unwrap();
        let registry = DcidRegistry::<(), u16>::new();
        let mut packet = [0; 64];
        let packet_len = crate::encode_long_packet(
            crate::LONG_PACKET_INITIAL,
            None,
            Some(source),
            1,
            4,
            &[0xa0],
            &mut packet,
        )
        .unwrap();
        let mut output = [0; 64];
        assert!(matches!(
            dispatch_packet(&registry, &packet[..packet_len], &mut output),
            Err(DcidPacketError::Registry(DcidRegistryError::Missing))
        ));
    }

    #[test]
    fn packet_router_owns_shared_listener_classification_and_dcid_dispatch() {
        let server_cid = ConnectionId::new(0x41).unwrap();
        let client_cid = ConnectionId::new(0x42).unwrap();
        let relay_cid = ConnectionId::new(0x234).unwrap();
        let mut router = PacketRouter::<u8, u16>::new();
        router.set_max_entries(3);
        router.register_endpoint(server_cid, 1).unwrap();
        router.register_endpoint(client_cid, 2).unwrap();
        router
            .register_forward(
                relay_cid,
                ForwardRule {
                    next_hop: 9,
                    destination: ForwardDestination::Connection(server_cid),
                    lease_duration_us: 1_000,
                    lease_expires_at_us: 10_000,
                    lease_group_id: 0,
                    packet_quota: 0,
                    forwarded_packets: 0,
                    forwarded_control_packets: 0,
                    quota_window_started_us: 0,
                },
            )
            .unwrap();
        let mut packet = [0u8; 128];
        let mut output = [0u8; 128];

        let source = ConnectionId::new(0x43).unwrap();
        let initial_len = crate::encode_bootstrap_open_packet(source, 0, &mut packet).unwrap();
        assert!(matches!(
            router.route(&packet[..initial_len], &mut output),
            Ok(PacketRoute::Initial(open)) if open.client_receive_cid == source
        ));

        let ack_len =
            crate::encode_bootstrap_open_ack_packet(client_cid, server_cid, 0, &mut packet)
                .unwrap();
        assert!(matches!(
            router.route(&packet[..ack_len], &mut output),
            Ok(PacketRoute::Endpoint { destination, endpoint: 2 })
                if destination == client_cid
        ));

        let established_len = ShortHeader {
            flags: FLAG_FIXED,
            dcid: server_cid,
            packet_number: 1,
            packet_number_len: 1,
        }
        .encode(&mut packet)
        .unwrap();
        assert!(matches!(
            router.route(&packet[..established_len], &mut output),
            Ok(PacketRoute::Endpoint { destination, endpoint: 1 })
                if destination == server_cid
        ));

        let relay_len = ShortHeader {
            flags: FLAG_FIXED,
            dcid: relay_cid,
            packet_number: 2,
            packet_number_len: 1,
        }
        .encode(&mut packet)
        .unwrap();
        let used = match router.route(&packet[..relay_len], &mut output).unwrap() {
            PacketRoute::Forward {
                received_dcid,
                rule,
                used,
            } => {
                assert_eq!(received_dcid, relay_cid);
                assert_eq!(rule.next_hop, 9);
                used
            }
            _ => panic!("relay CID must select its forwarding rule"),
        };
        assert_eq!(
            ShortHeader::decode(&output[..used]).unwrap().0.dcid,
            server_cid
        );
    }

    #[test]
    #[cfg(feature = "stateless-reset")]
    fn packet_router_generates_reset_only_for_unknown_short_dcid() {
        let reset_key = crate::StatelessResetKey::from_device_secret(&[0x71; 32]).unwrap();
        let router = PacketRouter::<u8, u16>::new_with_stateless_reset(reset_key);
        let unknown = ConnectionId::new(0x55).unwrap();
        let mut packet = [0x44u8; 48];
        let header_len = ShortHeader {
            flags: FLAG_FIXED,
            dcid: unknown,
            packet_number: 1,
            packet_number_len: 1,
        }
        .encode(&mut packet)
        .unwrap();
        packet[header_len..].fill(0x44);
        let mut output = [0u8; 64];
        let used = match router.route(&packet, &mut output).unwrap() {
            PacketRoute::StatelessReset { used } => used,
            _ => panic!("unknown established CID must produce a reset"),
        };
        assert_eq!(used, packet.len());
        assert!(reset_key.token_for(unknown).matches_packet(&output[..used]));

        let client = ConnectionId::new(0x56).unwrap();
        let server = ConnectionId::new(0x57).unwrap();
        let ack_len =
            crate::encode_bootstrap_open_ack_packet(client, server, 0, &mut packet).unwrap();
        assert!(matches!(
            router.route(&packet[..ack_len], &mut output),
            Ok(PacketRoute::Unknown { destination }) if destination == client
        ));
    }

    #[test]
    #[cfg(feature = "stateless-reset")]
    fn packet_router_offers_opaque_reset_to_association_state_without_an_address() {
        #[derive(Clone, Copy)]
        struct ClientState {
            token: crate::StatelessResetToken,
        }

        let peer_key = crate::StatelessResetKey::from_device_secret(&[0x81; 32]).unwrap();
        let client_cid = ConnectionId::new(0x61).unwrap();
        let old_server_cid = ConnectionId::new(0x62).unwrap();
        let mut router = PacketRouter::<ClientState, ()>::new();
        router
            .register_endpoint(
                client_cid,
                ClientState {
                    token: peer_key.token_for(old_server_cid),
                },
            )
            .unwrap();

        let mut stale = [0x22u8; 48];
        let header_len = ShortHeader {
            flags: FLAG_FIXED,
            dcid: old_server_cid,
            packet_number: 9,
            packet_number_len: 1,
        }
        .encode(&mut stale)
        .unwrap();
        stale[header_len..].fill(0x22);
        let mut reset = [0u8; 48];
        let reset_len = peer_key
            .encode_for_unknown_packet(&stale, &mut reset)
            .unwrap()
            .unwrap();
        let mut scratch = [0u8; 64];
        assert!(matches!(
            router.route_with_opaque(&reset[..reset_len], &mut scratch, |client, packet| {
                client.token.matches_packet(packet)
            }),
            Ok(PacketRoute::OpaqueEndpoint { endpoint })
                if endpoint.token.matches_packet(&reset[..reset_len])
        ));
    }

    #[test]
    fn packet_router_keeps_multiple_clients_servers_and_relays_in_one_namespace() {
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        enum Endpoint {
            Client(u8),
            Server(u8),
        }

        let clients = [0x101, 0x102].map(|value| ConnectionId::new(value).unwrap());
        let servers = [0x201, 0x202].map(|value| ConnectionId::new(value).unwrap());
        let relays = [
            ConnectionId::new(0x234).unwrap(),
            ConnectionId::new(0x235).unwrap(),
        ];
        let mut router = PacketRouter::<Endpoint, u8>::new();
        router.set_max_entries(6);
        for (index, cid) in clients.into_iter().enumerate() {
            router
                .register_endpoint(cid, Endpoint::Client(index as u8))
                .unwrap();
        }
        for (index, cid) in servers.into_iter().enumerate() {
            router
                .register_endpoint(cid, Endpoint::Server(index as u8))
                .unwrap();
        }
        for (index, cid) in relays.into_iter().enumerate() {
            router
                .register_forward(
                    cid,
                    ForwardRule {
                        next_hop: index as u8,
                        destination: ForwardDestination::Connection(servers[index]),
                        lease_duration_us: 1_000,
                        lease_expires_at_us: 10_000,
                        lease_group_id: 0,
                        packet_quota: 0,
                        forwarded_packets: 0,
                        forwarded_control_packets: 0,
                        quota_window_started_us: 0,
                    },
                )
                .unwrap();
        }
        assert_eq!(
            router.register_forward(
                clients[0],
                ForwardRule {
                    next_hop: 9,
                    destination: ForwardDestination::Bootstrap,
                    lease_duration_us: 1_000,
                    lease_expires_at_us: 10_000,
                    lease_group_id: 0,
                    packet_quota: 0,
                    forwarded_packets: 0,
                    forwarded_control_packets: 0,
                    quota_window_started_us: 0,
                },
            ),
            Err(DcidRegistryError::Occupied)
        );

        let mut packet = [0u8; 96];
        let mut output = [0u8; 96];
        for (index, client_cid) in clients.into_iter().enumerate() {
            let used = crate::encode_bootstrap_open_ack_packet(
                client_cid,
                servers[index],
                index as u32,
                &mut packet,
            )
            .unwrap();
            assert!(matches!(
                router.route(&packet[..used], &mut output),
                Ok(PacketRoute::Endpoint {
                    destination,
                    endpoint: Endpoint::Client(found),
                }) if destination == client_cid && *found == index as u8
            ));
        }
        for (index, server_cid) in servers.into_iter().enumerate() {
            let used = ShortHeader {
                flags: FLAG_FIXED,
                dcid: server_cid,
                packet_number: index as u32 + 1,
                packet_number_len: 1,
            }
            .encode(&mut packet)
            .unwrap();
            assert!(matches!(
                router.route(&packet[..used], &mut output),
                Ok(PacketRoute::Endpoint {
                    destination,
                    endpoint: Endpoint::Server(found),
                }) if destination == server_cid && *found == index as u8
            ));
        }
        for (index, relay_cid) in relays.into_iter().enumerate() {
            let used = ShortHeader {
                flags: FLAG_FIXED,
                dcid: relay_cid,
                packet_number: index as u32 + 3,
                packet_number_len: 1,
            }
            .encode(&mut packet)
            .unwrap();
            let rewritten = match router.route(&packet[..used], &mut output).unwrap() {
                PacketRoute::Forward { rule, used, .. } => {
                    assert_eq!(rule.next_hop, index as u8);
                    used
                }
                _ => panic!("relay did not share the root namespace"),
            };
            assert_eq!(
                ShortHeader::decode(&output[..rewritten]).unwrap().0.dcid,
                servers[index]
            );
        }

        assert!(router.remove_endpoint(servers[0], &Endpoint::Server(0)));
        assert!(!router.remove_endpoint(servers[0], &Endpoint::Server(0)));
        let used = ShortHeader {
            flags: FLAG_FIXED,
            dcid: servers[0],
            packet_number: 8,
            packet_number_len: 1,
        }
        .encode(&mut packet)
        .unwrap();
        assert!(matches!(
            router.route(&packet[..used], &mut output),
            Ok(PacketRoute::Unknown { destination }) if destination == servers[0]
        ));
        let used = ShortHeader {
            flags: FLAG_FIXED,
            dcid: servers[1],
            packet_number: 9,
            packet_number_len: 1,
        }
        .encode(&mut packet)
        .unwrap();
        assert!(matches!(
            router.route(&packet[..used], &mut output),
            Ok(PacketRoute::Endpoint {
                endpoint: Endpoint::Server(1),
                ..
            })
        ));
    }

    #[test]
    #[cfg(feature = "stateless-reset")]
    fn opaque_reset_selects_the_matching_client_among_multiple_endpoints() {
        #[derive(Clone, Copy)]
        struct Endpoint {
            id: u8,
            token: Option<crate::StatelessResetToken>,
        }

        let peer_key = crate::StatelessResetKey::from_device_secret(&[0x91; 32]).unwrap();
        let peer_cids = [0x301, 0x302].map(|value| ConnectionId::new(value).unwrap());
        let local_cids = [0x401, 0x402, 0x403].map(|value| ConnectionId::new(value).unwrap());
        let mut router = PacketRouter::<Endpoint, ()>::new();
        router
            .register_endpoint(
                local_cids[0],
                Endpoint {
                    id: 0,
                    token: Some(peer_key.token_for(peer_cids[0])),
                },
            )
            .unwrap();
        router
            .register_endpoint(
                local_cids[1],
                Endpoint {
                    id: 1,
                    token: Some(peer_key.token_for(peer_cids[1])),
                },
            )
            .unwrap();
        router
            .register_endpoint(local_cids[2], Endpoint { id: 2, token: None })
            .unwrap();

        let mut stale = [0x33u8; 48];
        let header_len = ShortHeader {
            flags: FLAG_FIXED,
            dcid: peer_cids[1],
            packet_number: 4,
            packet_number_len: 1,
        }
        .encode(&mut stale)
        .unwrap();
        stale[header_len..].fill(0x33);
        let mut reset = [0u8; 48];
        let reset_len = peer_key
            .encode_for_unknown_packet(&stale, &mut reset)
            .unwrap()
            .unwrap();
        let mut scratch = [0u8; 64];
        assert!(matches!(
            router.route_with_opaque(&reset[..reset_len], &mut scratch, |endpoint, packet| {
                endpoint.token.is_some_and(|token| token.matches_packet(packet))
            }),
            Ok(PacketRoute::OpaqueEndpoint { endpoint }) if endpoint.id == 1
        ));
        reset[reset_len - 1] ^= 1;
        assert!(
            router
                .route_with_opaque(&reset[..reset_len], &mut scratch, |endpoint, packet| {
                    endpoint
                        .token
                        .is_some_and(|token| token.matches_packet(packet))
                })
                .is_err()
        );
    }
}
