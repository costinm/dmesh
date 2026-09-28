//! Explicit allowlist for connectionless tagged messages.
//!
//! QUIC bootstrap uses the custom-version Initial long-header type and never
//! enters this module. All application operations not classified here
//! are normal QUIC stream handlers.

use crate::tagged::decode;

/// The application records currently permitted without a QUIC association.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirectMessageKind {
    /// Complete volatile bearer configuration, including all-off.
    TransportSet,
    /// Targeted wake admitted only while the device has no owner secret.
    PairWakeup,
}

/// Classify one tagged-CBOR payload against the shared direct allowlist.
pub fn classify(payload: &[u8]) -> Option<DirectMessageKind> {
    let record = decode(payload)?;
    match (record.component?, record.method?) {
        (
            crate::tagged::Name::Tag(crate::control::CONTROL_COMPONENT),
            crate::tagged::Name::Tag(crate::control::TRANSPORT_SET),
        ) => matches!(
            crate::control::decode_request(payload),
            Some(crate::control::Request::TransportSet { .. })
        )
        .then_some(DirectMessageKind::TransportSet),
        (
            crate::tagged::Name::Tag(crate::announce::ANNOUNCE_COMPONENT),
            crate::tagged::Name::Tag(crate::announce::ANNOUNCE_NAN_PAIR_WAKEUP),
        ) => crate::announce::decode_nan_pair_wakeup_request(record)
            .map(|_| DirectMessageKind::PairWakeup),
        _ => None,
    }
}

/// Fixed-capacity duplicate cache for a terminating direct handler.
pub struct TerminatingDirectDedup<const ENTRIES: usize, const RESPONSE_CAPACITY: usize> {
    entries: [Option<TerminatingDirectDedupEntry<RESPONSE_CAPACITY>>; ENTRIES],
    next: usize,
}

#[derive(Clone, Copy)]
struct TerminatingDirectDedupEntry<const RESPONSE_CAPACITY: usize> {
    id: Option<u64>,
    packet_number: u32,
    fingerprint: u32,
    response_len: usize,
    response: [u8; RESPONSE_CAPACITY],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TerminatingDirectDedupResult {
    New,
    Replay(usize),
    Conflict,
}

impl<const ENTRIES: usize, const RESPONSE_CAPACITY: usize>
    TerminatingDirectDedup<ENTRIES, RESPONSE_CAPACITY>
{
    pub const fn new() -> Self {
        Self {
            entries: [None; ENTRIES],
            next: 0,
        }
    }

    pub fn check(
        &self,
        packet_number: u32,
        payload: &[u8],
        output: &mut [u8],
    ) -> TerminatingDirectDedupResult {
        let id = decode(payload).and_then(|record| record.id);
        let fingerprint = direct_fingerprint(payload);
        for entry in self.entries.iter().flatten() {
            let same_key = match (id, entry.id) {
                (Some(id), Some(existing)) => id == existing,
                (None, None) => packet_number == entry.packet_number,
                _ => false,
            };
            if !same_key {
                continue;
            }
            if entry.fingerprint != fingerprint || entry.response_len > output.len() {
                return TerminatingDirectDedupResult::Conflict;
            }
            output[..entry.response_len].copy_from_slice(&entry.response[..entry.response_len]);
            return TerminatingDirectDedupResult::Replay(entry.response_len);
        }
        TerminatingDirectDedupResult::New
    }

    pub fn store(&mut self, packet_number: u32, payload: &[u8], response: &[u8]) -> bool {
        if ENTRIES == 0 || response.len() > RESPONSE_CAPACITY {
            return false;
        }
        let mut cached = [0; RESPONSE_CAPACITY];
        cached[..response.len()].copy_from_slice(response);
        self.entries[self.next] = Some(TerminatingDirectDedupEntry {
            id: decode(payload).and_then(|record| record.id),
            packet_number,
            fingerprint: direct_fingerprint(payload),
            response_len: response.len(),
            response: cached,
        });
        self.next = (self.next + 1) % ENTRIES;
        true
    }
}

impl<const ENTRIES: usize, const RESPONSE_CAPACITY: usize> Default
    for TerminatingDirectDedup<ENTRIES, RESPONSE_CAPACITY>
{
    fn default() -> Self {
        Self::new()
    }
}

fn direct_fingerprint(payload: &[u8]) -> u32 {
    payload.iter().fold(0x811c_9dc5, |hash, byte| {
        (hash ^ u32::from(*byte)).wrapping_mul(0x0100_0193)
    })
}
