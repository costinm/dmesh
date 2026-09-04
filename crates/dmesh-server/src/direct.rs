//! Explicit allowlist for connectionless tagged messages.
//!
//! QUIC bootstrap uses the custom-version Initial long-header type and never
//! enters this module. All application operations not classified here
//! are normal QUIC stream handlers.

use crate::tagged::decode;

/// The application records currently permitted without a QUIC association.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirectMessageKind {
    /// Unsolicited or correlated signed presence.
    Discovery,
    /// Directed request for a correlated signed discovery response.
    DiscoveryRequest,
    /// Complete volatile bearer configuration, including all-off.
    TransportSet,
}

/// Classify one tagged-CBOR payload against the shared direct allowlist.
pub fn classify(payload: &[u8]) -> Option<DirectMessageKind> {
    let record = decode(payload)?;
    match (record.component?, record.method?) {
        (
            crate::tagged::Name::Tag(crate::announce::ANNOUNCE_COMPONENT),
            crate::tagged::Name::Tag(crate::announce::ANNOUNCE_DISCOVERY),
        ) => {
            if crate::announce::discovery_request_id(payload).is_some() {
                Some(DirectMessageKind::DiscoveryRequest)
            } else {
                crate::announce::decode_announce(payload).map(|_| DirectMessageKind::Discovery)
            }
        }
        (
            crate::tagged::Name::Tag(crate::control::CONTROL_COMPONENT),
            crate::tagged::Name::Tag(crate::control::TRANSPORT_SET),
        ) => matches!(
            crate::control::decode_request(payload),
            Some(crate::control::Request::TransportSet { .. })
        )
        .then_some(DirectMessageKind::TransportSet),
        _ => None,
    }
}

/// Common connectionless application envelope used by discovery and the
/// narrowly allowed `transport.set` form.  It deliberately exposes only
/// payload-to-packet and packet-to-payload operations: QUIC-lite retains the
/// custom long-header representation, packet numbers, and response
/// correlation.  Bearer adapters must hand its completed packet to frame I/O
/// unchanged and must not inspect the result.
pub struct ConnectionlessMessage;

/// Result of giving a connectionless packet to the shared application
/// dispatcher. This intentionally describes payload completion only; the
/// enclosing QUIC long header stays private to `quic-lite`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectionlessDisposition {
    NotHandled,
    Handled,
    Response(usize),
}

impl ConnectionlessMessage {
    pub fn is_packet(packet: &[u8]) -> bool {
        quic_lite::is_direct_message_packet(packet)
    }

    pub fn encode(payload: &[u8], output: &mut [u8]) -> Option<usize> {
        quic_lite::encode_direct_message(payload, output).ok()
    }

    pub fn decode(packet: &[u8]) -> Option<&[u8]> {
        quic_lite::decode_direct_message_response(packet).ok()
    }

    /// Decode, dispatch, and correlate one bounded connectionless record.
    /// Callers receive only its application body and response scratch space;
    /// QUIC-lite writes the response long header itself.
    pub fn receive<F>(packet: &[u8], output: &mut [u8], handler: F) -> ConnectionlessDisposition
    where
        F: FnOnce(&[u8], &mut [u8]) -> ConnectionlessDisposition,
    {
        match quic_lite::handle_direct_message(packet, output, |payload, response| {
            match handler(payload, response) {
                ConnectionlessDisposition::NotHandled => {
                    quic_lite::DirectMessageDisposition::NotHandled
                }
                ConnectionlessDisposition::Handled => quic_lite::DirectMessageDisposition::Handled,
                ConnectionlessDisposition::Response(used) => {
                    quic_lite::DirectMessageDisposition::Response(used)
                }
            }
        }) {
            Ok(quic_lite::DirectMessageDisposition::NotHandled) => Self::not_handled(),
            Ok(quic_lite::DirectMessageDisposition::Handled) => Self::handled(),
            Ok(quic_lite::DirectMessageDisposition::Response(used)) => Self::response(used),
            Err(_) => Self::not_handled(),
        }
    }

    const fn not_handled() -> ConnectionlessDisposition {
        ConnectionlessDisposition::NotHandled
    }

    const fn handled() -> ConnectionlessDisposition {
        ConnectionlessDisposition::Handled
    }

    const fn response(used: usize) -> ConnectionlessDisposition {
        ConnectionlessDisposition::Response(used)
    }
}

/// Reusable terminating handler for the directed signed-discovery exception.
///
/// The caller supplies only the current, already-signed presence record.  The
/// shared direct plane owns request classification, correlation, and the
/// custom-version direct envelope so Linux and Android cannot grow subtly
/// different UDP responders.
#[cfg(feature = "udp")]
pub struct SignedDiscoveryResponder {
    current_announce: alloc::sync::Arc<dyn Fn() -> Option<crate::announce::Announce> + Send + Sync>,
}

#[cfg(feature = "udp")]
impl SignedDiscoveryResponder {
    pub fn new(
        current_announce: alloc::sync::Arc<
            dyn Fn() -> Option<crate::announce::Announce> + Send + Sync,
        >,
    ) -> Self {
        Self { current_announce }
    }

    fn response(&self, payload: &[u8]) -> Option<alloc::vec::Vec<u8>> {
        if classify(payload) != Some(DirectMessageKind::DiscoveryRequest) {
            return None;
        }
        let request_id = crate::announce::discovery_request_id(payload)?;
        let announce = (self.current_announce)()?;
        let mut record = [0u8; quic_lite::DEFAULT_MAX_DATAGRAM_SIZE];
        let used = crate::announce::encode_discovery_response(announce, request_id, &mut record)?;
        Some(record[..used].to_vec())
    }
}

#[cfg(feature = "udp")]
impl core::fmt::Debug for SignedDiscoveryResponder {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("SignedDiscoveryResponder")
    }
}

#[cfg(feature = "udp")]
impl crate::udp::TaggedStreamHandler for SignedDiscoveryResponder {
    fn handle<'a>(
        &'a self,
        _context: crate::udp::TaggedStreamContext,
        request: alloc::vec::Vec<u8>,
    ) -> core::pin::Pin<
        alloc::boxed::Box<
            dyn core::future::Future<Output = Option<alloc::vec::Vec<u8>>> + Send + 'a,
        >,
    > {
        alloc::boxed::Box::pin(async move { self.response(&request) })
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

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::sync::Arc;

    #[test]
    fn allowlist_accepts_only_discovery_and_transport_set() {
        let mut request = [0u8; 96];
        let used = crate::announce::encode_discovery_request(7, &mut request).unwrap();
        assert_eq!(
            classify(&request[..used]),
            Some(DirectMessageKind::DiscoveryRequest)
        );

        let used = crate::control::encode_request(
            crate::control::Request::TransportSet {
                kind: crate::control::TransportKind::Nan,
                config: crate::control::TransportConfig::default(),
            },
            Some(8),
            &mut request,
        )
        .unwrap();
        assert_eq!(
            classify(&request[..used]),
            Some(DirectMessageKind::TransportSet)
        );

        let used = crate::tagged::encode_numeric_empty_request(7, 1, 9, &mut request).unwrap();
        assert_eq!(classify(&request[..used]), None);
    }

    #[test]
    fn bare_tagged_cbor_is_not_a_connectionless_message() {
        let bare = [0xa1, 1, 1];
        let mut response = [0u8; 64];
        let mut invoked = false;
        assert_eq!(
            ConnectionlessMessage::receive(&bare, &mut response, |_, _| {
                invoked = true;
                ConnectionlessDisposition::Handled
            }),
            ConnectionlessDisposition::NotHandled
        );
        assert!(!invoked);
    }

    #[test]
    fn dedup_replays_id_and_rejects_conflicting_payload() {
        let request = [0xa3, 1, 1, 2, 4, 3, 0x18, 77];
        let mut cache = TerminatingDirectDedup::<2, 32>::new();
        let mut response = [0; 32];
        assert_eq!(
            cache.check(10, &request, &mut response),
            TerminatingDirectDedupResult::New
        );
        assert!(cache.store(10, &request, b"done"));
        assert_eq!(
            cache.check(11, &request, &mut response),
            TerminatingDirectDedupResult::Replay(4)
        );
        let conflicting = [0xa3, 1, 1, 2, 2, 3, 0x18, 77];
        assert_eq!(
            cache.check(12, &conflicting, &mut response),
            TerminatingDirectDedupResult::Conflict
        );
    }

    #[test]
    fn shared_signed_discovery_responder_correlates_only_discovery_requests() {
        let mut request = [0u8; 96];
        let request_used = crate::announce::encode_discovery_request(81, &mut request).unwrap();
        let responder = SignedDiscoveryResponder::new(Arc::new(|| {
            Some(crate::announce::Announce::discovery([7; 16], 16, 9))
        }));
        let payload = responder.response(&request[..request_used]).unwrap();
        assert_eq!(
            crate::tagged::decode(&payload).and_then(|record| record.id),
            Some(81)
        );
        assert!(crate::announce::decode_announce(&payload).is_some());
        let mut stream_only = [0u8; 32];
        let stream_only_used =
            crate::tagged::encode_numeric_empty_request(7, 1, 82, &mut stream_only).unwrap();
        assert_eq!(responder.response(&stream_only[..stream_only_used]), None);
    }
}
