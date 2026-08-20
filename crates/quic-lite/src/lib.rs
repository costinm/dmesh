#![no_std]

//! Bounded, bearer-neutral reliable streams.
//!
//! This crate deliberately knows nothing about UDP, radio security, files, or
//! flashing.  A bearer supplies datagram boundaries and peer identity; the
//! caller supplies storage and time.  The wire format follows QUIC's packet
//! and frame rules, with packet protection deliberately left to a future
//! bearer/security layer.

extern crate alloc;
use alloc::vec::Vec;
#[cfg(not(any(feature = "std", test)))]
use alloc::{
    alloc::{alloc, dealloc, Layout},
    boxed::Box,
};

#[cfg(all(feature = "std", not(test)))]
extern crate std;

pub mod bearer_probe;
pub mod callback;
pub mod iperf;
pub mod ledger;

pub mod mux;

pub mod framed_stream;
pub mod packet_pool;
pub mod path_bridge;
pub mod path_router;
pub mod ram_budget;
pub mod raw_udp6;
pub mod sta_selection;
pub mod uart;

pub use path_router::{
    ConnectionTable, ConnectionTableError, DcidRouter, DcidRouterError, PathCapacity, PathPolicy,
    PathState,
};

#[cfg(any(feature = "std", test))]
pub mod fake;

#[cfg(test)]
extern crate std;

use core::cmp::{max, min};

pub const FLAG_FIXED: u8 = 0x40;
pub const FLAG_SPIN: u8 = 0x20;
pub const FLAG_RESERVED: u8 = 0x18;
pub const FLAG_KEY_PHASE: u8 = 0x04;

/// Shared benchmark stream envelope used by the host and ESP32 test paths.
/// It is intentionally separate from the production object-store protocol so
/// an iperf-like run can vary bearer parameters without changing semantics.
pub const BENCH_MAGIC: [u8; 4] = *b"DMTB";
pub const BENCH_CONNECTION_ID: u64 = 0x1234;
pub const BENCH_STREAM_ID: u64 = 0;

/// Application stream service tags shared by all bearers.
pub const SERVICE_OBJECT: u8 = 1;
pub const SERVICE_ECHO: u8 = 2;
pub const SERVICE_STATUS: u8 = 3;
pub const SERVICE_STREAM: u8 = 4;
/// Enumerate every registered application stream handler.  The response is a
/// compact CBOR array of `[tag, name]` pairs. `STREAM` is retained as the
/// numeric wire tag while the handler name makes its purpose explicit to
/// interactive clients.
pub const SERVICE_HANDLERS: u8 = SERVICE_STREAM;
pub const SERVICE_IPERF: u8 = 5;
pub const SERVICE_METRICS: u8 = 6;
pub const SERVICE_EVENTS: u8 = 7;
/// Recovery command/log exchange. Payloads are compact CBOR records owned by
/// Recovery; transport only carries the stream and never interprets them.
pub const SERVICE_CONTROL: u8 = 8;
/// Subscribe to bounded diagnostic log records exposed by a server.  The
/// transport only carries this tag; log schemas and retention are server
/// policy.
pub const SERVICE_LOG_WATCH: u8 = 9;
/// Ask a device to fetch one signed object and install it through its local
/// flash sink. The device, not the command sender, opens the object GET.
pub const SERVICE_FLASH: u8 = 10;

/// A small CBOR selector used at the beginning of a stream command.  This is
/// intentionally not a CBOR dependency or a general decoder: transport only
/// recognizes one definite integer service tag and leaves the body opaque.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CborSelector {
    Tag(u64),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CborSelectorError {
    Truncated,
    Unsupported,
}

/// One application handler advertised by a QUIC-lite endpoint.
///
/// This deliberately describes dispatch only.  It contains neither a CBOR
/// schema nor a function pointer: the application owning a stream reads its
/// own payload after QUIC-lite has selected it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StreamHandler {
    pub tag: u8,
    pub name: &'static [u8],
}

/// Shared stream-handler registry for every QUIC-lite bearer.
///
/// The registry is in the transport crate so UART, UDP, ESP-NOW, and host
/// tests advertise the exact same tag/name surface.  It remains no_std and
/// only uses `alloc`; CBOR is limited to the small selector helper below.
#[derive(Clone, Debug)]
pub struct StreamRegistry {
    handlers: Vec<StreamHandler>,
}

impl Default for StreamRegistry {
    fn default() -> Self {
        let mut registry = Self {
            handlers: Vec::new(),
        };
        for handler in [
            StreamHandler {
                tag: SERVICE_OBJECT,
                name: b"object",
            },
            StreamHandler {
                tag: SERVICE_ECHO,
                name: b"echo",
            },
            StreamHandler {
                tag: SERVICE_STATUS,
                name: b"status",
            },
            StreamHandler {
                tag: SERVICE_HANDLERS,
                name: b"handlers",
            },
            StreamHandler {
                tag: SERVICE_IPERF,
                name: b"iperf",
            },
            StreamHandler {
                tag: SERVICE_METRICS,
                name: b"metrics",
            },
            StreamHandler {
                tag: SERVICE_EVENTS,
                name: b"events",
            },
            StreamHandler {
                tag: SERVICE_CONTROL,
                name: b"control",
            },
            StreamHandler {
                tag: SERVICE_LOG_WATCH,
                name: b"log-watch",
            },
        ] {
            // Registration mutates the advertised surface.  Do not place it
            // inside `debug_assert!`: release firmware would otherwise build
            // an empty registry and reject every valid stream service.  The
            // canonical static list is trusted in production; debug builds
            // still check it contains no duplicate tag or name.
            let _registered = registry.register(handler.tag, handler.name);
            debug_assert!(_registered);
        }
        registry
    }
}

impl StreamRegistry {
    /// Start with no advertised handlers. Bearer adapters use this when their
    /// available service surface is intentionally narrower than the common
    /// host/server baseline.
    pub fn empty() -> Self {
        Self {
            handlers: Vec::new(),
        }
    }

    /// Register one stable service tag and human-readable name.  A duplicate
    /// tag or name is rejected so discovery cannot advertise an ambiguous
    /// handler.
    pub fn register(&mut self, tag: u8, name: &'static [u8]) -> bool {
        if name.is_empty()
            || self
                .handlers
                .iter()
                .any(|handler| handler.tag == tag || handler.name == name)
        {
            return false;
        }
        self.handlers.push(StreamHandler { tag, name });
        true
    }

    pub fn handlers(&self) -> &[StreamHandler] {
        &self.handlers
    }

    pub fn contains(&self, tag: u8) -> bool {
        self.handlers.iter().any(|handler| handler.tag == tag)
    }

    /// Encode handler discovery as canonical compact CBOR:
    /// `[[tag, "name"], ...]`. This small self-contained encoder keeps
    /// QUIC-lite free of a CBOR crate and is not a handler payload schema.
    pub fn encode_handler_list(&self) -> Vec<u8> {
        let mut output = Vec::with_capacity(1 + self.handlers.len() * 12);
        encode_cbor_head(&mut output, 4, self.handlers.len() as u64);
        for handler in &self.handlers {
            encode_cbor_head(&mut output, 4, 2);
            encode_cbor_head(&mut output, 0, u64::from(handler.tag));
            encode_cbor_head(&mut output, 3, handler.name.len() as u64);
            output.extend_from_slice(handler.name);
        }
        output
    }

    /// Resolve a compact numeric service tag at the beginning of a stream
    /// body. Names are deliberately discovery-only metadata and never select
    /// a handler or command.
    pub fn resolve_tag<'a>(&self, input: &'a [u8]) -> Option<(u8, &'a [u8])> {
        let (selector, used) = decode_cbor_selector(input).ok()?;
        let CborSelector::Tag(tag) = selector;
        let handler = self
            .handlers
            .iter()
            .find(|handler| u64::from(handler.tag) == tag)?;
        Some((handler.tag, &input[used..]))
    }
}

fn encode_cbor_head(output: &mut Vec<u8>, major: u8, value: u64) {
    debug_assert!(major < 8);
    let prefix = major << 5;
    match value {
        0..=23 => output.push(prefix | value as u8),
        24..=255 => output.extend_from_slice(&[prefix | 24, value as u8]),
        256..=65_535 => {
            output.push(prefix | 25);
            output.extend_from_slice(&(value as u16).to_be_bytes());
        }
        65_536..=4_294_967_295 => {
            output.push(prefix | 26);
            output.extend_from_slice(&(value as u32).to_be_bytes());
        }
        _ => {
            output.push(prefix | 27);
            output.extend_from_slice(&value.to_be_bytes());
        }
    }
}

/// Decode a definite CBOR unsigned-integer service tag at `input[0]`.
/// Names are discovery metadata only and are rejected here. The returned
/// offset begins the handler-owned payload.
pub fn decode_cbor_selector(input: &[u8]) -> Result<(CborSelector, usize), CborSelectorError> {
    let Some(&head) = input.first() else {
        return Err(CborSelectorError::Truncated);
    };
    let major = head >> 5;
    let additional = head & 0x1f;
    let (value, header_len) = match additional {
        value @ 0..=23 => (u64::from(value), 1),
        24 => (*input.get(1).ok_or(CborSelectorError::Truncated)? as u64, 2),
        25 => {
            let bytes: [u8; 2] = input
                .get(1..3)
                .ok_or(CborSelectorError::Truncated)?
                .try_into()
                .map_err(|_| CborSelectorError::Truncated)?;
            (u64::from(u16::from_be_bytes(bytes)), 3)
        }
        26 => {
            let bytes: [u8; 4] = input
                .get(1..5)
                .ok_or(CborSelectorError::Truncated)?
                .try_into()
                .map_err(|_| CborSelectorError::Truncated)?;
            (u64::from(u32::from_be_bytes(bytes)), 5)
        }
        27 => {
            let bytes: [u8; 8] = input
                .get(1..9)
                .ok_or(CborSelectorError::Truncated)?
                .try_into()
                .map_err(|_| CborSelectorError::Truncated)?;
            (u64::from_be_bytes(bytes), 9)
        }
        _ => return Err(CborSelectorError::Unsupported),
    };
    if major == 0 {
        Ok((CborSelector::Tag(value), header_len))
    } else {
        Err(CborSelectorError::Unsupported)
    }
}
pub const CONTROL_STREAM_ID: u64 = 0;
pub const FIRST_CLIENT_BIDI_STREAM_ID: u64 = 4;
pub const FIRST_SERVER_BIDI_STREAM_ID: u64 = 1;
pub const FIRST_CLIENT_UNI_STREAM_ID: u64 = 2;
pub const FIRST_SERVER_UNI_STREAM_ID: u64 = 3;
/// Default bearer payload bound shared by UART, UDP, and the current extended
/// ESP-NOW/vendor-action frame. The action-frame adapter is presently capped
/// at 1200 bytes, so no bearer may silently use a larger transport packet.
pub const DEFAULT_MAX_DATAGRAM_SIZE: usize = 1200;
/// Conservative one-datagram application payload after short-header and
/// stream-frame overhead. Commands using this bound never rely on L2
/// fragmentation, even when CID/varint widths grow.
pub const DEFAULT_MAX_STREAM_PAYLOAD: usize = DEFAULT_MAX_DATAGRAM_SIZE - 64;
/// Fixed histogram shape for bearer inter-packet gaps.  Keeping this in the
/// transport lets every bearer report comparable pacing evidence without
/// coupling the measurements to sockets, Wi-Fi, or a server schema.
pub const INTERPACKET_GAP_BUCKETS: usize = 6;

/// Classify an elapsed bearer gap in microseconds.
pub const fn interpacket_gap_bucket(delta_us: u64) -> usize {
    match delta_us {
        0..=999 => 0,
        1_000..=4_999 => 1,
        5_000..=9_999 => 2,
        10_000..=24_999 => 3,
        25_000..=49_999 => 4,
        _ => 5,
    }
}

/// Return whether a wrapping millisecond clock is strictly before `deadline`.
///
/// Callers must keep individual intervals below half the `u32` range.  This
/// is suitable for short bearer retries and active-session leases and remains
/// host-testable independently of a firmware clock implementation.
pub const fn before_deadline_u32(now: u32, deadline: u32) -> bool {
    (now.wrapping_sub(deadline) as i32) < 0
}

/// Opaque egress timing for a datagram bearer.  The caller supplies a
/// monotonic microsecond clock; transport payload contents are not retained.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DatagramTiming {
    pub datagrams: u64,
    pub gaps: u64,
    pub total_gap_us: u64,
    pub max_gap_us: u64,
    pub gap_buckets: [u64; INTERPACKET_GAP_BUCKETS],
    last_sent_us: Option<u64>,
}

impl DatagramTiming {
    pub fn record_at(&mut self, now_us: u64) {
        if let Some(previous) = self.last_sent_us {
            let gap = now_us.saturating_sub(previous);
            self.gaps = self.gaps.saturating_add(1);
            self.total_gap_us = self.total_gap_us.saturating_add(gap);
            self.max_gap_us = self.max_gap_us.max(gap);
            let bucket = interpacket_gap_bucket(gap);
            self.gap_buckets[bucket] = self.gap_buckets[bucket].saturating_add(1);
        }
        self.last_sent_us = Some(now_us);
        self.datagrams = self.datagrams.saturating_add(1);
    }
}
/// Production Recovery's explicit maximum sender ledger. The host Wi-Fi
/// profile must retain at least the receiver-advertised packet budget.
pub const RECOVERY_MAX_HISTORY_PACKETS: usize = 64;
/// Production Recovery begins with a 32-packet sender budget. The same
/// bearer also supports the 64-packet diagnostic ceiling below, but the live
/// ESP32 Wi-Fi benchmark shows a 64-packet burst creates severe packet-number
/// holes before a pacing policy exists.
pub const RECOVERY_MAX_IN_FLIGHT_PACKETS: u16 = 32;
/// Largest explicit diagnostic receive window accepted by Recovery. At the
/// 1200-byte Wi-Fi payload profile, 64 packets are 76,800 bytes, below the
/// fixed 89,600-byte callback/reorder budget below.
pub const RECOVERY_MAX_DIAGNOSTIC_IN_FLIGHT_PACKETS: u16 = 64;
/// Callback/reassembly storage is deliberately larger than the send window:
/// it retains ordered bytes while an earlier Wi-Fi datagram is repaired.
pub const RECOVERY_REORDER_CAPACITY_BYTES: usize = 64 * DEFAULT_MAX_DATAGRAM_SIZE;
/// Recovery's application-owned flash pool.  It is deliberately smaller than
/// the packet reorder budget: the latter protects a gap in a 64-packet
/// diagnostic flight, while this credit limits object bytes to the fixed
/// reusable ESP flash slots.  ESP32-C6 has only internal RAM: 76 KiB of
/// application slots plus the manifest, lwIP queues, and Wi-Fi leaves no
/// allocation headroom and turns a valid manifest into an allocator abort.
/// This is eight complete 4 KiB blob records (4,096 payload + 17-byte record
/// header).  Packet history remains independently capped at 64; byte credit
/// is intentionally the tighter startup backpressure.
pub const RECOVERY_INITIAL_MAX_DATA: u64 = 8 * (4 * 1024 + 17);

/// Recovery's connection credit profile. Object transfer is constrained by
/// its flash-slot budget; a host/device transport benchmark instead uses the
/// requested packet window so it measures transport rather than storage.
pub fn recovery_connection_limits(
    transport_diagnostic: bool,
    requested_packets: u8,
) -> ConnectionLimits {
    let max_data = if transport_diagnostic {
        let packets = if requested_packets == 0 {
            RECOVERY_MAX_IN_FLIGHT_PACKETS
        } else {
            u16::from(requested_packets).min(RECOVERY_MAX_DIAGNOSTIC_IN_FLIGHT_PACKETS)
        };
        u64::from(packets) * 1200
    } else {
        RECOVERY_INITIAL_MAX_DATA
    };
    ConnectionLimits {
        max_data,
        max_stream_data: max_data,
        ..ConnectionLimits::default()
    }
}

/// Decide whether a bearer task should yield after an empty nonblocking poll.
/// The transport owns control emission; this only bounds CPU monopolization.
pub const fn bearer_poll_should_yield(
    emitted_control: bool,
    receive_wait_us: u64,
    consecutive_empty_spins: u64,
    since_full_yield_us: u64,
    spin_limit: u64,
    max_unyielded_us: u64,
) -> bool {
    !emitted_control
        && receive_wait_us < 1_000
        && consecutive_empty_spins >= spin_limit
        && since_full_yield_us >= max_unyielded_us
}

#[cfg(test)]
mod recovery_profile_tests {
    use super::*;

    #[test]
    fn recovery_profile_keeps_flash_and_diagnostic_credit_distinct() {
        let flash = recovery_connection_limits(false, 64);
        let default_diagnostic = recovery_connection_limits(true, 0);
        let diagnostic = recovery_connection_limits(true, 24);
        assert_eq!(flash.max_data, RECOVERY_INITIAL_MAX_DATA);
        assert_eq!(
            default_diagnostic.max_data,
            u64::from(RECOVERY_MAX_IN_FLIGHT_PACKETS) * 1200
        );
        assert_eq!(diagnostic.max_data, 24 * 1200);
    }

    #[test]
    fn bearer_poll_yield_is_bounded_and_control_aware() {
        assert!(!bearer_poll_should_yield(true, 0, 8, 100_000, 8, 100_000));
        assert!(!bearer_poll_should_yield(false, 0, 7, 100_000, 8, 100_000));
        assert!(bearer_poll_should_yield(false, 0, 8, 100_000, 8, 100_000));
    }

    #[test]
    fn bearer_timing_is_clock_supplied_and_bounded() {
        let mut timing = DatagramTiming::default();
        timing.record_at(1_000);
        timing.record_at(1_500);
        timing.record_at(11_500);
        assert_eq!(timing.datagrams, 3);
        assert_eq!(timing.gaps, 2);
        assert_eq!(timing.total_gap_us, 10_500);
        assert_eq!(timing.max_gap_us, 10_000);
        assert_eq!(timing.gap_buckets, [1, 0, 0, 1, 0, 0]);
    }

    #[test]
    fn stream_selector_accepts_compact_tag_only() {
        assert_eq!(
            decode_cbor_selector(&[8, 0xa0]),
            Ok((CborSelector::Tag(8), 1))
        );
        assert_eq!(
            decode_cbor_selector(&[0x69, b'l', b'o', b'g', b'-', b'w', b'a', b't', b'c', b'h']),
            Err(CborSelectorError::Unsupported)
        );
        assert_eq!(
            decode_cbor_selector(&[0xa1]),
            Err(CborSelectorError::Unsupported)
        );
        assert_eq!(
            decode_cbor_selector(&[0x78]),
            Err(CborSelectorError::Truncated)
        );
    }

    #[test]
    fn shared_handler_registry_advertises_tag_and_name_once() {
        let mut registry = StreamRegistry::default();
        assert!(registry.contains(SERVICE_HANDLERS));
        assert_eq!(
            registry.resolve_tag(&[SERVICE_HANDLERS, 1]),
            Some((SERVICE_HANDLERS, &[1][..]))
        );
        assert_eq!(
            registry.resolve_tag(&[0x68, b'h', b'a', b'n', b'd', b'l', b'e', b'r', b's']),
            None
        );
        assert_eq!(
            registry.encode_handler_list().get(..11),
            Some(&[0x89, 0x82, 1, 0x66, b'o', b'b', b'j', b'e', b'c', b't', 0x82][..])
        );
        assert!(!registry.register(SERVICE_HANDLERS, b"different-name"));
        assert!(!registry.register(42, b"handlers"));
        assert!(registry.register(42, b"custom"));
    }
}

/// Minimal synchronous bearer contract used by deterministic conformance
/// drivers. UDP, NAN, BLE, and device adapters own the actual I/O and peer
/// identity; they only need to preserve datagram boundaries and provide a
/// caller-supplied clock. The transport and stream handlers remain shared.
pub trait DatagramBearer {
    type Error;

    /// Queue one opaque datagram for transmission at `now`.
    fn send_datagram(&mut self, now: u64, payload: &[u8]) -> Result<(), Self::Error>;

    /// Return at most one received datagram, copying it into `out`.
    fn receive_datagram(&mut self, now: u64, out: &mut [u8]) -> Result<Option<usize>, Self::Error>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConnectionId(u64);

impl ConnectionId {
    pub const fn new(value: u64) -> Option<Self> {
        if value < (1u64 << 62) {
            Some(Self(value))
        } else {
            None
        }
    }

    pub const fn value(self) -> u64 {
        self.0
    }

    /// The first two bits of the first CID byte encode total length.
    pub const fn encoded_len(self) -> usize {
        if self.0 <= 0x3f {
            1
        } else if self.0 <= 0x3fff {
            2
        } else if self.0 <= 0x3fff_ffff {
            4
        } else {
            8
        }
    }

    pub fn encode(self, out: &mut [u8]) -> Result<usize, Error> {
        let n = self.encoded_len();
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
            out[i] = (self.0 >> (8 * (n - i - 1))) as u8;
        }
        out[0] = (out[0] & 0x3f) | tag;
        Ok(n)
    }

    pub fn decode(input: &[u8]) -> Result<(Self, usize), Error> {
        if input.is_empty() {
            return Err(Error::Truncated);
        }
        let n = match input[0] >> 6 {
            0 => 1,
            1 => 2,
            2 => 4,
            _ => 8,
        };
        if input.len() < n {
            return Err(Error::Truncated);
        }
        let mut value = (input[0] & 0x3f) as u64;
        for &b in &input[1..n] {
            value = (value << 8) | b as u64;
        }
        Ok((Self(value), n))
    }
}

/// Compact bearer envelope used by radio adapters around transport packets.
/// It is deliberately transport-owned: object stores provide stream bytes and
/// do not need to know how a NAN/action bearer identifies a peer.
pub const ENVELOPE_MAGIC: u32 = 0x4452_5332;
pub const ENVELOPE_VERSION: u8 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeerKey {
    pub wifi_mac: [u8; 6],
    pub dcid: ConnectionId,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnvelopeError {
    BufferTooSmall,
    Truncated,
    BadMagic,
    Invalid,
}

pub fn encode_envelope(
    key: PeerKey,
    kind: u8,
    payload: &[u8],
    out: &mut [u8],
) -> Result<usize, EnvelopeError> {
    let mut cid = [0u8; 8];
    let cid_len = key
        .dcid
        .encode(&mut cid)
        .map_err(|_| EnvelopeError::Invalid)?;
    let need = 4 + 1 + 1 + 6 + 1 + cid_len + payload.len();
    if out.len() < need {
        return Err(EnvelopeError::BufferTooSmall);
    }
    out[0..4].copy_from_slice(&ENVELOPE_MAGIC.to_be_bytes());
    out[4] = ENVELOPE_VERSION;
    out[5] = kind;
    out[6..12].copy_from_slice(&key.wifi_mac);
    out[12] = cid_len as u8;
    out[13..13 + cid_len].copy_from_slice(&cid[..cid_len]);
    out[13 + cid_len..need].copy_from_slice(payload);
    Ok(need)
}

pub fn decode_envelope(input: &[u8]) -> Result<(PeerKey, u8, &[u8]), EnvelopeError> {
    if input.len() < 14
        || u32::from_be_bytes(
            input[0..4]
                .try_into()
                .map_err(|_| EnvelopeError::Truncated)?,
        ) != ENVELOPE_MAGIC
        || input[4] != ENVELOPE_VERSION
    {
        return Err(EnvelopeError::BadMagic);
    }
    let cid_len = input[12] as usize;
    if !matches!(cid_len, 1 | 2 | 4 | 8) || input.len() < 13 + cid_len {
        return Err(EnvelopeError::Truncated);
    }
    let (dcid, _) = ConnectionId::decode(&input[13..]).map_err(|_| EnvelopeError::Invalid)?;
    let mut wifi_mac = [0u8; 6];
    wifi_mac.copy_from_slice(&input[6..12]);
    Ok((PeerKey { wifi_mac, dcid }, input[5], &input[13 + cid_len..]))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    BufferTooSmall,
    Truncated,
    Invalid,
    InvalidVarint,
    FlowControl,
    StreamLimit,
    PacketNumberExhausted,
    WrongConnectionId,
    BootstrapInvalid,
    HistoryFull,
    RetransmissionTooLarge,
}

/// Result metadata for a bearer datagram after transport processing. The
/// bearer may use this for diagnostics, but it never needs to inspect ACKs,
/// packet numbers, or other transport frames.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransportReceiveInfo {
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
pub enum CommittedStreamDisposition {
    Consumed(usize),
    Deferred,
    Reack,
}

/// Transport-owned diagnostics. Bearers may report this snapshot without
/// inspecting ACK frames, packet numbers, or other transport mechanics.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TransportStats {
    pub received_datagrams: u64,
    pub stream_datagrams: u64,
    pub control_datagrams: u64,
    pub duplicate_datagrams: u64,
    pub out_of_order_datagrams: u64,
    pub inferred_missing_packets: u64,
    pub sent_datagrams: u64,
    /// Application STREAM datagrams emitted by this endpoint, including
    /// replacement transmissions. This is transport accounting: bearers do
    /// not need to parse packets to report it.
    pub sent_stream_datagrams: u64,
    /// ACK, flow-control, ACK_FREQUENCY, or close datagrams emitted by this
    /// endpoint. Comparing this with the peer's received control count makes
    /// packet-number gaps diagnosable without packet-path logging.
    pub sent_control_datagrams: u64,
    pub retransmitted_datagrams: u64,
    /// Stream datagrams declared lost from an ACK packet-number gap.
    pub loss_packet_threshold_datagrams: u64,
    /// Stream datagrams declared lost only because their send age exceeded
    /// the negotiated RTT/ACK-delay threshold.
    pub loss_time_threshold_datagrams: u64,
    /// ACK-driven loss batches. NewReno reduces cwnd at most once for each
    /// recovery epoch, but this counts every observed loss episode.
    pub loss_events: u64,
    /// Retransmissions selected because loss detection had already marked
    /// the stream range lost.
    pub loss_retransmitted_datagrams: u64,
    /// Retransmissions selected only by the PTO timer.
    pub pto_retransmitted_datagrams: u64,
    pub ack_frequency_received: u64,
    pub ack_frequency_sent: u64,
    pub ack_datagrams: u64,
    pub ack_immediate_datagrams: u64,
    pub ack_threshold_datagrams: u64,
    pub ack_timer_datagrams: u64,
    pub receive_interpacket_samples: u64,
    pub receive_interpacket_total: u64,
    pub receive_interpacket_min: u64,
    pub receive_interpacket_max: u64,
}

/// Version-0 connection bootstrap carried as complete data on stream 0.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BootstrapOpen {
    pub client_receive_cid: ConnectionId,
    /// Receiver credit the peer must honour before the first MAX_* frame.
    pub max_data: u64,
    pub max_stream_data: u64,
    /// Maximum outstanding STREAM datagrams this receiver can absorb. Zero
    /// means no packet-count bound for compatibility with older peers.
    pub max_in_flight_packets: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BootstrapOpenAck {
    pub server_receive_cid: ConnectionId,
    /// Receiver credit the peer must honour before the first MAX_* frame.
    pub max_data: u64,
    pub max_stream_data: u64,
    /// See [`BootstrapOpen::max_in_flight_packets`].
    pub max_in_flight_packets: u16,
}

impl BootstrapOpen {
    pub const VERSION: u64 = 0;
    pub fn encode(self, out: &mut [u8]) -> Result<usize, Error> {
        if self.client_receive_cid.value() == 0 {
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
    pub fn decode(input: &[u8]) -> Result<Self, Error> {
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
        })
    }
}

impl BootstrapOpenAck {
    pub const VERSION: u64 = 0;
    pub fn encode(self, out: &mut [u8]) -> Result<usize, Error> {
        if self.server_receive_cid.value() == 0 {
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
    pub fn decode(input: &[u8]) -> Result<Self, Error> {
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
        })
    }
}

/// Shared no-std client-side version-0 bootstrap state machine. Bearers own
/// packet I/O and call these methods with their clock and output storage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootstrapClientState {
    Idle,
    Opening,
    Established,
    Failed,
}

pub struct BootstrapClient {
    local_cid: ConnectionId,
    peer_cid: Option<ConnectionId>,
    next_packet_number: u32,
    attempts: u8,
    max_attempts: u8,
    timeout: u64,
    deadline: u64,
    state: BootstrapClientState,
}

/// Shared no-std server-side bootstrap state. The server receive CID is
/// allocated by the bearer/application before construction; OPEN replay does
/// not allocate another CID.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootstrapServerState {
    Pending,
    Established,
}

pub struct BootstrapServer {
    local_cid: ConnectionId,
    peer_cid: Option<ConnectionId>,
    state: BootstrapServerState,
}

impl BootstrapServer {
    pub fn new(local_cid: ConnectionId) -> Result<Self, Error> {
        if local_cid.value() == 0 {
            return Err(Error::BootstrapInvalid);
        }
        Ok(Self {
            local_cid,
            peer_cid: None,
            state: BootstrapServerState::Pending,
        })
    }

    pub const fn state(&self) -> BootstrapServerState {
        self.state
    }

    pub const fn local_cid(&self) -> ConnectionId {
        self.local_cid
    }

    pub const fn peer_cid(&self) -> Option<ConnectionId> {
        self.peer_cid
    }

    /// Validate an OPEN and encode an ACK. A matching duplicate returns the
    /// same CID and a new caller-supplied packet number; a different client
    /// CID is a conflict and cannot steal the pending endpoint.
    pub fn accept_open(
        &mut self,
        input: &[u8],
        packet_number: u32,
        out: &mut [u8],
    ) -> Result<(ConnectionId, bool, usize), Error> {
        let (_, client_cid) = decode_bootstrap_open_packet(input)?;
        if client_cid == self.local_cid {
            return Err(Error::BootstrapInvalid);
        }
        let duplicate = if let Some(previous) = self.peer_cid {
            if previous != client_cid {
                return Err(Error::BootstrapInvalid);
            }
            true
        } else {
            self.peer_cid = Some(client_cid);
            false
        };
        let used =
            encode_bootstrap_open_ack_packet(client_cid, self.local_cid, packet_number, out)?;
        Ok((client_cid, duplicate, used))
    }

    pub fn confirm_established(&mut self, client_cid: ConnectionId) -> Result<(), Error> {
        if self.peer_cid != Some(client_cid) {
            return Err(Error::WrongConnectionId);
        }
        self.state = BootstrapServerState::Established;
        Ok(())
    }
}

impl BootstrapClient {
    pub fn new(local_cid: ConnectionId, timeout: u64, max_attempts: u8) -> Result<Self, Error> {
        if local_cid.value() == 0 || timeout == 0 || max_attempts == 0 {
            return Err(Error::BootstrapInvalid);
        }
        Ok(Self {
            local_cid,
            peer_cid: None,
            next_packet_number: 0,
            attempts: 0,
            max_attempts,
            timeout,
            deadline: 0,
            state: BootstrapClientState::Idle,
        })
    }

    pub const fn state(&self) -> BootstrapClientState {
        self.state
    }

    pub const fn local_cid(&self) -> ConnectionId {
        self.local_cid
    }

    pub const fn peer_cid(&self) -> Option<ConnectionId> {
        self.peer_cid
    }

    pub const fn attempts(&self) -> u8 {
        self.attempts
    }

    pub fn start_open(&mut self, now: u64, out: &mut [u8]) -> Result<usize, Error> {
        if !matches!(
            self.state,
            BootstrapClientState::Idle | BootstrapClientState::Failed
        ) {
            return Err(Error::BootstrapInvalid);
        }
        let packet_number = self.next_packet_number;
        let used = encode_bootstrap_open_packet(self.local_cid, packet_number, out)?;
        self.next_packet_number = self
            .next_packet_number
            .checked_add(1)
            .ok_or(Error::PacketNumberExhausted)?;
        self.attempts = 1;
        self.deadline = now.saturating_add(self.timeout);
        self.peer_cid = None;
        self.state = BootstrapClientState::Opening;
        Ok(used)
    }

    pub fn on_open_ack(&mut self, input: &[u8]) -> Result<ConnectionId, Error> {
        let (header, server_cid) = decode_bootstrap_open_ack_packet(input, self.local_cid)?;
        if !matches!(
            self.state,
            BootstrapClientState::Opening | BootstrapClientState::Established
        ) {
            return Err(Error::BootstrapInvalid);
        }
        if let Some(previous) = self.peer_cid {
            if previous != server_cid {
                return Err(Error::BootstrapInvalid);
            }
        }
        if header.dcid != self.local_cid {
            return Err(Error::WrongConnectionId);
        }
        if server_cid == self.local_cid {
            return Err(Error::BootstrapInvalid);
        }
        self.peer_cid = Some(server_cid);
        self.state = BootstrapClientState::Established;
        Ok(server_cid)
    }

    pub fn poll_timeout(&mut self, now: u64, out: &mut [u8]) -> Result<Option<usize>, Error> {
        if self.state != BootstrapClientState::Opening || now < self.deadline {
            return Ok(None);
        }
        if self.attempts >= self.max_attempts {
            self.state = BootstrapClientState::Failed;
            return Err(Error::BootstrapInvalid);
        }
        let packet_number = self.next_packet_number;
        let used = encode_bootstrap_open_packet(self.local_cid, packet_number, out)?;
        self.next_packet_number = self
            .next_packet_number
            .checked_add(1)
            .ok_or(Error::PacketNumberExhausted)?;
        self.attempts = self.attempts.saturating_add(1);
        let shift = u32::from(self.attempts.saturating_sub(1).min(6));
        self.deadline = now.saturating_add(self.timeout.saturating_mul(1u64 << shift));
        Ok(Some(used))
    }
}

/// Encode a complete stream-0/DCID-0 version-0 OPEN datagram.
pub fn encode_bootstrap_open_packet(
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
pub fn encode_bootstrap_open_packet_with_limits(
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
pub fn encode_bootstrap_open_packet_with_profile(
    client_cid: ConnectionId,
    packet_number: u32,
    limits: ConnectionLimits,
    max_in_flight_packets: u16,
    out: &mut [u8],
) -> Result<usize, Error> {
    let mut body = [0u8; 32];
    let body_len = BootstrapOpen {
        client_receive_cid: client_cid,
        max_data: limits.max_data,
        max_stream_data: limits.max_stream_data,
        max_in_flight_packets,
    }
    .encode(&mut body)?;
    let header_len = ShortHeader {
        flags: FLAG_FIXED,
        dcid: ConnectionId::new(0).ok_or(Error::BootstrapInvalid)?,
        packet_number,
        packet_number_len: 1,
    }
    .encode(out)?;
    let frame_len = Frame::Stream(StreamFrame {
        id: CONTROL_STREAM_ID,
        offset: 0,
        fin: true,
        data: &body[..body_len],
    })
    .encode(&mut out[header_len..])?;
    Ok(header_len + frame_len)
}

/// Decode a complete stream-0/DCID-0 version-0 OPEN datagram.
pub fn decode_bootstrap_open_packet(input: &[u8]) -> Result<(ShortHeader, ConnectionId), Error> {
    let (header, open) = decode_bootstrap_open_packet_with_limits(input)?;
    Ok((header, open.client_receive_cid))
}

/// Decode OPEN including the peer's initial receive credit.
pub fn decode_bootstrap_open_packet_with_limits(
    input: &[u8],
) -> Result<(ShortHeader, BootstrapOpen), Error> {
    let (header, header_len) = ShortHeader::decode_with_expected(input, 0)?;
    if header.dcid.value() != 0 {
        return Err(Error::BootstrapInvalid);
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
    Ok((header, BootstrapOpen::decode(stream.data)?))
}

/// Encode a complete stream-0 version-0 OPEN_ACK addressed to the client's
/// receive CID.
pub fn encode_bootstrap_open_ack_packet(
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
pub fn encode_bootstrap_open_ack_packet_with_limits(
    client_cid: ConnectionId,
    server_cid: ConnectionId,
    packet_number: u32,
    limits: ConnectionLimits,
    out: &mut [u8],
) -> Result<usize, Error> {
    if client_cid == server_cid {
        return Err(Error::BootstrapInvalid);
    }
    let mut body = [0u8; 32];
    let body_len = BootstrapOpenAck {
        server_receive_cid: server_cid,
        max_data: limits.max_data,
        max_stream_data: limits.max_stream_data,
        max_in_flight_packets: 0,
    }
    .encode(&mut body)?;
    let header_len = ShortHeader {
        flags: FLAG_FIXED,
        dcid: client_cid,
        packet_number,
        packet_number_len: 1,
    }
    .encode(out)?;
    let frame_len = Frame::Stream(StreamFrame {
        id: CONTROL_STREAM_ID,
        offset: 0,
        fin: true,
        data: &body[..body_len],
    })
    .encode(&mut out[header_len..])?;
    Ok(header_len + frame_len)
}

/// Decode a complete stream-0 version-0 OPEN_ACK.
pub fn decode_bootstrap_open_ack_packet(
    input: &[u8],
    expected_client_cid: ConnectionId,
) -> Result<(ShortHeader, ConnectionId), Error> {
    let (header, ack) = decode_bootstrap_open_ack_packet_with_limits(input, expected_client_cid)?;
    Ok((header, ack.server_receive_cid))
}

/// Decode OPEN_ACK including the peer's initial receive credit.
pub fn decode_bootstrap_open_ack_packet_with_limits(
    input: &[u8],
    expected_client_cid: ConnectionId,
) -> Result<(ShortHeader, BootstrapOpenAck), Error> {
    let (header, header_len) = ShortHeader::decode(input)?;
    if header.dcid != expected_client_cid {
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
    let ack = BootstrapOpenAck::decode(stream.data)?;
    let server_cid = ack.server_receive_cid;
    if server_cid == expected_client_cid {
        return Err(Error::BootstrapInvalid);
    }
    Ok((header, ack))
}

pub fn put_varint(value: u64, out: &mut [u8]) -> Result<usize, Error> {
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

pub fn get_varint(input: &[u8]) -> Result<(u64, usize), Error> {
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
pub struct ShortHeader {
    pub flags: u8,
    pub dcid: ConnectionId,
    pub packet_number: u32,
    pub packet_number_len: u8,
}

/// The header prefix decoded before a connection is selected. The packet
/// number is intentionally only the truncated wire value until the bearer
/// supplies that connection's expected next packet number.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShortHeaderPrefix {
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
    pub fn reconstruct(self, expected: u32) -> Result<ShortHeader, Error> {
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
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
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

    pub fn decode_prefix(input: &[u8]) -> Result<ShortHeaderPrefix, Error> {
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
    pub fn decode_with_expected(input: &[u8], expected: u32) -> Result<(Self, usize), Error> {
        let prefix = Self::decode_prefix(input)?;
        Ok((prefix.reconstruct(expected)?, prefix.header_len))
    }

    /// Decode the truncated value without reconstruction. This is retained
    /// only for wire/codec inspection; connection receive paths must use
    /// `decode_with_expected`.
    pub fn decode(input: &[u8]) -> Result<(Self, usize), Error> {
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
pub fn packet_number_len(next: u32, largest_acked: Option<u32>) -> u8 {
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

pub const FRAME_PADDING: u64 = 0x00;
pub const FRAME_PING: u64 = 0x01;
pub const FRAME_ACK: u64 = 0x02;
pub const FRAME_STREAM_BASE: u64 = 0x08;
pub const FRAME_MAX_DATA: u64 = 0x10;
pub const FRAME_MAX_STREAM_DATA: u64 = 0x11;
pub const FRAME_MAX_STREAMS_BIDI: u64 = 0x12;
pub const FRAME_MAX_STREAMS_UNI: u64 = 0x13;
pub const FRAME_CONNECTION_CLOSE: u64 = 0x1c;
/// QUIC ACK_FREQUENCY extension frame type. RFC 9000 defines the default
/// every-other-packet ACK behavior; this extension carries a later policy
/// update on the established connection.
pub const FRAME_ACK_FREQUENCY: u64 = 0xaf;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StreamFrame<'a> {
    pub id: u64,
    pub offset: u64,
    pub fin: bool,
    pub data: &'a [u8],
}

/// Result of handing one bearer datagram to the transport.  Bearers should
/// forward every datagram here and only consume stream bytes; ACK and flow
/// control frames never escape to object or flash code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportPacket<'a> {
    Stream {
        header: ShortHeader,
        frame: StreamFrame<'a>,
    },
    Control,
}

/// Encode one bounded benchmark datagram (magic, short header, stream frame).
pub fn encode_bench_stream(
    packet_number: u32,
    offset: u64,
    fin: bool,
    data: &[u8],
    out: &mut [u8],
) -> Result<usize, Error> {
    if out.len() < BENCH_MAGIC.len() {
        return Err(Error::BufferTooSmall);
    }
    out[..BENCH_MAGIC.len()].copy_from_slice(&BENCH_MAGIC);
    let header = ShortHeader {
        flags: FLAG_FIXED,
        dcid: ConnectionId::new(BENCH_CONNECTION_ID).ok_or(Error::Invalid)?,
        packet_number,
        packet_number_len: 2,
    };
    let header_len = header.encode(&mut out[BENCH_MAGIC.len()..])?;
    let frame = Frame::Stream(StreamFrame {
        id: BENCH_STREAM_ID,
        offset,
        fin,
        data,
    });
    let frame_len = frame.encode(&mut out[BENCH_MAGIC.len() + header_len..])?;
    Ok(BENCH_MAGIC.len() + header_len + frame_len)
}

/// Decode and validate one benchmark datagram, returning the stream frame and
/// the number of consumed bytes (excluding any optional monitor trailer).
pub fn decode_bench_stream(input: &[u8]) -> Result<(ShortHeader, StreamFrame<'_>, usize), Error> {
    if input.len() < BENCH_MAGIC.len() || input[..BENCH_MAGIC.len()] != BENCH_MAGIC {
        return Err(Error::Invalid);
    }
    let (header, header_len) = ShortHeader::decode(&input[BENCH_MAGIC.len()..])?;
    if header.dcid.value() != BENCH_CONNECTION_ID {
        return Err(Error::Invalid);
    }
    let (frame, frame_len) = decode_frame(&input[BENCH_MAGIC.len() + header_len..])?;
    let Frame::Stream(stream) = frame else {
        return Err(Error::Invalid);
    };
    if stream.id != BENCH_STREAM_ID {
        return Err(Error::Invalid);
    }
    Ok((header, stream, BENCH_MAGIC.len() + header_len + frame_len))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Frame<'a> {
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
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
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

pub fn decode_frame<'a>(input: &'a [u8]) -> Result<(Frame<'a>, usize), Error> {
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
            if range_count as usize >= ACK_RANGE_CAPACITY {
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
            if input.len() < p + len as usize {
                return Err(Error::Truncated);
            }
            Ok((Frame::Close { code }, p + len as usize))
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
                v as usize
            } else {
                input.len() - p
            };
            if input.len() < p + len {
                return Err(Error::Truncated);
            }
            Ok((
                Frame::Stream(StreamFrame {
                    id,
                    offset,
                    fin: t & 1 != 0,
                    data: &input[p..p + len],
                }),
                p + len,
            ))
        }
        _ => Err(Error::Invalid),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AckRange {
    pub start: u32,
    pub end: u32,
}

pub const ACK_RANGE_CAPACITY: usize = 8;
pub type AckRangeSet = AckRanges<ACK_RANGE_CAPACITY>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AckRanges<const N: usize> {
    ranges: [AckRange; N],
    len: usize,
}

impl<const N: usize> AckRanges<N> {
    pub const fn new() -> Self {
        Self {
            ranges: [AckRange { start: 0, end: 0 }; N],
            len: 0,
        }
    }
    pub fn len(&self) -> usize {
        self.len
    }
    pub fn get(&self, i: usize) -> Option<AckRange> {
        if i < self.len {
            Some(self.ranges[i])
        } else {
            None
        }
    }
    pub fn insert(&mut self, pn: u32) {
        self.insert_range(AckRange { start: pn, end: pn });
    }
    pub fn insert_range(&mut self, mut new: AckRange) {
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
    pub fn contains(&self, pn: u32) -> bool {
        (0..self.len).any(|i| pn >= self.ranges[i].start && pn <= self.ranges[i].end)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FlowControl {
    pub max_data: u64,
    pub consumed: u64,
}

impl FlowControl {
    pub const fn new(max_data: u64) -> Self {
        Self {
            max_data,
            consumed: 0,
        }
    }
    pub fn can_receive(&self, end: u64) -> bool {
        end <= self.max_data
    }
    pub fn consume(&mut self, n: u64) {
        self.consumed = self.consumed.saturating_add(n);
    }
    pub fn extend(&mut self, credit: u64) {
        self.max_data = max(self.max_data, self.consumed.saturating_add(credit));
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SendStreamCredit {
    pub id: u64,
    pub max_data: u64,
    pub sent: u64,
}

/// Peer-advertised connection and stream credit for a sender.  Retransmits do
/// not reserve credit again; only new stream-offset bytes advance `sent`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SendFlowControl<const N: usize> {
    pub max_data: u64,
    initial_stream_max_data: u64,
    pub sent_data: u64,
    streams: [Option<SendStreamCredit>; N],
}

impl<const N: usize> SendFlowControl<N> {
    pub const fn new(max_data: u64, max_stream_data: u64) -> Self {
        Self {
            max_data,
            initial_stream_max_data: max_stream_data,
            sent_data: 0,
            streams: [None; N],
        }
    }

    pub fn open_stream(&mut self, id: u64, max_data: u64) -> Result<(), Error> {
        if self
            .streams
            .iter()
            .any(|stream| stream.map(|value| value.id) == Some(id))
        {
            return Ok(());
        }
        let slot = self
            .streams
            .iter()
            .position(Option::is_none)
            .ok_or(Error::StreamLimit)?;
        self.streams[slot] = Some(SendStreamCredit {
            id,
            max_data: min(max_data, self.initial_stream_max_data),
            sent: 0,
        });
        Ok(())
    }

    /// Apply bootstrap credit before any stream is opened.  Once application
    /// bytes exist, credit may only advance through peer MAX_* frames.
    pub fn set_initial_limits(&mut self, max_data: u64, max_stream_data: u64) -> Result<(), Error> {
        if max_data == 0
            || max_stream_data == 0
            || self.sent_data != 0
            || self.streams.iter().any(Option::is_some)
        {
            return Err(Error::FlowControl);
        }
        self.max_data = max_data;
        self.initial_stream_max_data = max_stream_data;
        Ok(())
    }

    pub fn stream(&self, id: u64) -> Option<SendStreamCredit> {
        self.streams
            .iter()
            .flatten()
            .find(|stream| stream.id == id)
            .copied()
    }

    pub fn can_send(&self, id: u64, offset: u64, len: usize) -> bool {
        let Some(stream) = self.stream(id) else {
            return false;
        };
        let end = offset.saturating_add(len as u64);
        let new_bytes = end.saturating_sub(stream.sent);
        end <= stream.max_data && self.sent_data.saturating_add(new_bytes) <= self.max_data
    }

    pub fn reserve(&mut self, id: u64, offset: u64, len: usize) -> Result<(), Error> {
        if !self.can_send(id, offset, len) {
            return Err(Error::FlowControl);
        }
        let stream = self
            .streams
            .iter_mut()
            .flatten()
            .find(|stream| stream.id == id)
            .ok_or(Error::Invalid)?;
        let end = offset.saturating_add(len as u64);
        let new_bytes = end.saturating_sub(stream.sent);
        stream.sent = max(stream.sent, end);
        self.sent_data = self.sent_data.saturating_add(new_bytes);
        Ok(())
    }

    pub fn extend_connection(&mut self, max_data: u64) {
        self.max_data = max(self.max_data, max_data);
    }

    pub fn extend_stream(&mut self, id: u64, max_data: u64) -> Result<(), Error> {
        let stream = self
            .streams
            .iter_mut()
            .flatten()
            .find(|stream| stream.id == id)
            .ok_or(Error::Invalid)?;
        stream.max_data = max(stream.max_data, max_data);
        Ok(())
    }

    pub fn stream_credit(&self, id: u64) -> Option<u64> {
        self.stream(id).map(|stream| stream.max_data)
    }
}

/// RFC 9002 NewReno congestion state for one path.
///
/// This is intentionally bearer-neutral: the caller supplies packet sizes,
/// ACKs, and loss events.  Flow credit and congestion credit are separate;
/// both must allow a sender to transmit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CongestionController {
    pub max_datagram_size: u64,
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
pub struct RttEstimator {
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
    const INITIAL_PTO: u64 = 500;
    const GRANULARITY: u64 = 1;

    pub fn update(&mut self, sample: u64) {
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

    pub const fn latest(&self) -> Option<u64> {
        self.latest_rtt
    }

    pub const fn smoothed(&self) -> Option<u64> {
        self.smoothed_rtt
    }

    pub const fn variance(&self) -> u64 {
        self.rttvar
    }

    pub const fn minimum(&self) -> Option<u64> {
        self.min_rtt
    }

    pub fn pto(&self) -> u64 {
        let Some(smoothed) = self.smoothed_rtt else {
            return Self::INITIAL_PTO;
        };
        smoothed
            .saturating_add((self.rttvar.saturating_mul(4)).max(Self::GRANULARITY))
            .max(Self::GRANULARITY)
    }
}

impl CongestionController {
    pub fn new(max_datagram_size: u64) -> Self {
        let mds = max_datagram_size.max(1);
        let initial_window = (10 * mds).min((2 * mds).max(14_720));
        Self {
            max_datagram_size: mds,
            congestion_window: initial_window,
            slow_start_threshold: u64::MAX,
            bytes_in_flight: 0,
            recovery_start_packet: None,
        }
    }

    pub fn can_send(&self, bytes: u64) -> bool {
        self.bytes_in_flight.saturating_add(bytes) <= self.congestion_window
    }

    pub fn on_packet_sent(&mut self, bytes: u64) -> bool {
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
    pub fn on_retransmission_sent(&mut self, bytes: u64) {
        self.bytes_in_flight = self.bytes_in_flight.saturating_add(bytes);
    }

    pub fn on_ack(&mut self, acked_bytes: u64) {
        let acked = min(acked_bytes, self.bytes_in_flight);
        self.bytes_in_flight -= acked;
        if acked == 0 {
            return;
        }
        if self.congestion_window < self.slow_start_threshold {
            self.congestion_window = self.congestion_window.saturating_add(acked);
        } else {
            let increase = (self.max_datagram_size.saturating_mul(acked)
                / self.congestion_window.max(1))
            .max(1);
            self.congestion_window = self.congestion_window.saturating_add(increase);
        }
    }

    pub fn on_loss(&mut self, lost_bytes: u64) {
        if lost_bytes == 0 {
            return;
        }
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(lost_bytes);
        let reduced = self.congestion_window / 2;
        self.slow_start_threshold = reduced.max(2 * self.max_datagram_size);
        self.congestion_window = self.slow_start_threshold;
    }

    /// Account a transport-declared packet loss using RFC 9002's NewReno
    /// recovery epoch.  Every loss releases its in-flight bytes.  The
    /// multiplicative decrease is applied once, when the first lost packet
    /// sent after the previous recovery boundary is declared lost.
    pub fn on_packet_lost(
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
        self.slow_start_threshold = reduced.max(2 * self.max_datagram_size);
        self.congestion_window = self.slow_start_threshold;
        self.recovery_start_packet = Some(largest_sent_packet);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StreamState {
    pub id: u64,
    pub max_data: u64,
    pub received: u64,
    pub consumed: u64,
    pub finished: bool,
}

impl StreamState {
    pub const fn new(id: u64, max_data: u64) -> Self {
        Self {
            id,
            max_data,
            received: 0,
            consumed: 0,
            finished: false,
        }
    }
    pub fn accept(&mut self, offset: u64, len: usize, fin: bool) -> Result<(), Error> {
        let end = offset.checked_add(len as u64).ok_or(Error::FlowControl)?;
        if end > self.max_data {
            return Err(Error::FlowControl);
        }
        self.received = max(self.received, end);
        self.finished |= fin;
        Ok(())
    }
    pub fn consume(&mut self, n: u64) {
        self.consumed = min(self.received, self.consumed.saturating_add(n));
    }
    pub fn extend(&mut self, credit: u64) {
        self.max_data = max(self.max_data, self.consumed.saturating_add(credit));
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Role {
    Client,
    Server,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConnectionLimits {
    pub max_data: u64,
    pub max_stream_data: u64,
    pub max_streams_bidi: u64,
    pub max_streams_uni: u64,
}

pub const INITIAL_MAX_DATA: u64 = 256 * 1024;
// Keep the live Recovery window large enough to cover several flash blocks
// while remaining bounded for the device. The host regression deliberately
// exercises the smaller credit-extension boundary.
pub const INITIAL_MAX_STREAM_DATA: u64 = 256 * 1024;

impl Default for ConnectionLimits {
    fn default() -> Self {
        Self {
            max_data: INITIAL_MAX_DATA,
            max_stream_data: INITIAL_MAX_STREAM_DATA,
            max_streams_bidi: 8,
            max_streams_uni: 4,
        }
    }
}

/// Bounded stream accounting. Packet scheduling and bearer I/O remain in the caller.
#[derive(Clone)]
pub struct ConnectionState<const N: usize> {
    pub role: Role,
    pub connection: FlowControl,
    pub limits: ConnectionLimits,
    pub received_data: u64,
    streams: [Option<StreamState>; N],
}

impl<const N: usize> ConnectionState<N> {
    pub fn new(role: Role, limits: ConnectionLimits) -> Self {
        Self {
            role,
            connection: FlowControl::new(limits.max_data),
            limits,
            received_data: 0,
            streams: [None; N],
        }
    }

    fn stream_kind(id: u64) -> (bool, bool) {
        (id & 1 != 0, id & 2 != 0)
    }

    fn stream_count(&self, uni: bool, local: bool) -> u64 {
        self.streams
            .iter()
            .flatten()
            .filter(|s| {
                let (server, is_uni) = Self::stream_kind(s.id);
                is_uni == uni && (server == matches!(self.role, Role::Server)) == local
            })
            .count() as u64
    }

    pub fn open(&mut self, id: u64) -> Result<&mut StreamState, Error> {
        let (server, uni) = Self::stream_kind(id);
        let local = server == matches!(self.role, Role::Server);
        if !local {
            return Err(Error::Invalid);
        }
        let limit = if uni {
            self.limits.max_streams_uni
        } else {
            self.limits.max_streams_bidi
        };
        if self.stream_count(uni, local) >= limit {
            return Err(Error::StreamLimit);
        }
        self.insert_stream(id)
    }

    pub fn accept(
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
            if self.stream_count(uni, local) >= limit {
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
        let previous = self.streams[slot].as_ref().ok_or(Error::Invalid)?.received;
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
        self.streams[slot]
            .as_mut()
            .ok_or(Error::Invalid)?
            .accept(offset, len, fin)?;
        self.received_data = self.received_data.saturating_add(delta);
        Ok(self.streams[slot].as_mut().unwrap())
    }

    pub fn consume(&mut self, id: u64, n: u64) -> Result<(), Error> {
        let i = self.find(id).ok_or(Error::Invalid)?;
        self.streams[i].as_mut().ok_or(Error::Invalid)?.consume(n);
        self.connection.consume(n);
        Ok(())
    }

    pub fn stream_max_data(&self, id: u64) -> Option<u64> {
        self.find(id)
            .and_then(|i| self.streams[i].map(|stream| stream.max_data))
    }

    pub fn extend_connection_credit(&mut self, credit: u64) {
        self.connection.extend(credit);
    }

    pub fn extend_stream_credit(&mut self, id: u64, credit: u64) -> Result<(), Error> {
        let i = self.find(id).ok_or(Error::Invalid)?;
        self.streams[i]
            .as_mut()
            .ok_or(Error::Invalid)?
            .extend(credit);
        Ok(())
    }

    fn find(&self, id: u64) -> Option<usize> {
        self.streams
            .iter()
            .position(|s| s.map(|v| v.id) == Some(id))
    }
    fn insert_stream(&mut self, id: u64) -> Result<&mut StreamState, Error> {
        let i = self
            .streams
            .iter()
            .position(Option::is_none)
            .ok_or(Error::StreamLimit)?;
        self.streams[i] = Some(StreamState::new(id, self.limits.max_stream_data));
        Ok(self.streams[i].as_mut().unwrap())
    }
}

/// Bearer-neutral endpoint state shared by host and embedded users.
///
/// The bearer owns sockets, timers, and packet storage.  This type owns the
/// protocol state that must not diverge between implementations: packet
/// acknowledgement ranges, receive credit, peer-advertised send credit, and
/// congestion control.
#[derive(Clone)]
pub struct EndpointState<
    const N: usize,
    const H: usize = 16,
    const P: usize = DEFAULT_MAX_DATAGRAM_SIZE,
> {
    pub send: SendFlowControl<N>,
    pub receive: ConnectionState<N>,
    pub congestion: CongestionController,
    pub received_packets: AckRangeSet,
    /// Most recent ACK range set received from the peer. This is diagnostic
    /// state only; congestion accounting still walks the retained ledger.
    peer_ack_ranges: AckRangeSet,
    pub next_packet_number: u32,
    pub largest_acked_by_peer: Option<u32>,
    #[cfg(any(feature = "std", test))]
    sent_packets: Vec<Option<SentPacket<P>>>,
    #[cfg(not(any(feature = "std", test)))]
    sent_packets: [Option<SentPacket<P>>; H],
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
    max_ack_delay_ms: u64,
    peer_max_ack_delay_ms: u64,
    peer_max_in_flight_packets: usize,
    // Several streams may be consumed before delayed ACK emission. Keep a
    // bounded deduplicated set so one stream's MAX_STREAM_DATA cannot erase
    // another's credit update. The bound matches active stream state `N`.
    pending_stream_ids: [Option<u64>; N],
    send_clock: u64,
    rtt: RttEstimator,
    /// Endpoint-owned PTO scheduling. A bearer may poll in a tight loop when
    /// its send window is full; without this gate it would retransmit every
    /// overdue packet as a separate "probe" in the same PTO episode.
    last_pto_probe_at: Option<u64>,
    pto_backoff: u8,
    close_code: Option<u64>,
    history_limit: usize,
    stats: TransportStats,
    highest_received_packet: Option<u32>,
    last_receive_time: Option<u64>,
}

/// Named memory profiles used by the current products. They are type-level
/// choices so the compiler sizes the ledger and retained payload arrays for
/// each side; no endpoint silently allocates the largest profile.
pub type RecoveryEndpoint<const N: usize = 2> = EndpointState<N, 4, 256>;
/// ESP32/NAN keeps only four 512-byte payload slots per connection.  This is
/// intentionally smaller than the host profile; the adapter must not silently
/// instantiate the host-sized retransmission ledger.
pub type Esp32Endpoint<const N: usize = 8> = EndpointState<N, 4, 512>;
/// Host endpoints may use a larger heap-backed ledger; the active capacity is
/// selected per connection, so this ceiling is not allocated unless chosen.
pub type HostEndpoint<const N: usize = 8> = EndpointState<N, 512, DEFAULT_MAX_DATAGRAM_SIZE>;

/// Directional connection identifiers. `local_receive` is the CID this
/// endpoint accepts on inbound packets; `peer_receive` is the CID placed in
/// every outbound packet. They are deliberately separate so a received DCID
/// can never be mistaken for the sender's CID.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConnectionIds {
    pub local_receive: ConnectionId,
    pub peer_receive: ConnectionId,
}

impl ConnectionIds {
    pub fn new(local_receive: ConnectionId, peer_receive: ConnectionId) -> Result<Self, Error> {
        if local_receive.value() == 0 || peer_receive.value() == 0 || local_receive == peer_receive
        {
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

impl<const N: usize, const H: usize, const P: usize> EndpointState<N, H, P> {
    /// Initialize an endpoint in its final allocation. Firmware uses this for
    /// a boxed connection so the fixed retransmission ledger is never copied
    /// through an ingress task stack frame.
    pub unsafe fn init_in_place(
        out: *mut Self,
        role: Role,
        limits: ConnectionLimits,
        max_datagram_size: u64,
        history_capacity: usize,
    ) {
        assert!(history_capacity > 0 && history_capacity <= H);
        unsafe {
            core::ptr::addr_of_mut!((*out).send).write(SendFlowControl::new(
                limits.max_data,
                limits.max_stream_data,
            ));
            core::ptr::addr_of_mut!((*out).receive).write(ConnectionState::new(role, limits));
            core::ptr::addr_of_mut!((*out).congestion)
                .write(CongestionController::new(max_datagram_size));
            core::ptr::addr_of_mut!((*out).received_packets).write(AckRangeSet::new());
            core::ptr::addr_of_mut!((*out).peer_ack_ranges).write(AckRangeSet::new());
            core::ptr::addr_of_mut!((*out).next_packet_number).write(0);
            core::ptr::addr_of_mut!((*out).largest_acked_by_peer).write(None);
            #[cfg(any(feature = "std", test))]
            core::ptr::addr_of_mut!((*out).sent_packets).write(alloc::vec![None; history_capacity]);
            #[cfg(not(any(feature = "std", test)))]
            core::ptr::addr_of_mut!((*out).sent_packets).write([None; H]);
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
            core::ptr::addr_of_mut!((*out).max_ack_delay_ms).write(25);
            core::ptr::addr_of_mut!((*out).peer_max_ack_delay_ms).write(25);
            core::ptr::addr_of_mut!((*out).peer_max_in_flight_packets).write(usize::MAX);
            core::ptr::addr_of_mut!((*out).pending_stream_ids).write([None; N]);
            core::ptr::addr_of_mut!((*out).send_clock).write(0);
            core::ptr::addr_of_mut!((*out).rtt).write(RttEstimator::default());
            core::ptr::addr_of_mut!((*out).last_pto_probe_at).write(None);
            core::ptr::addr_of_mut!((*out).pto_backoff).write(0);
            core::ptr::addr_of_mut!((*out).close_code).write(None);
            core::ptr::addr_of_mut!((*out).history_limit).write(history_capacity);
            core::ptr::addr_of_mut!((*out).stats).write(TransportStats::default());
            core::ptr::addr_of_mut!((*out).highest_received_packet).write(None);
            core::ptr::addr_of_mut!((*out).last_receive_time).write(None);
        }
    }
    pub fn new(role: Role, limits: ConnectionLimits, max_datagram_size: u64) -> Self {
        Self::new_with_history_capacity(role, limits, max_datagram_size, H)
    }

    pub fn new_established(
        role: Role,
        limits: ConnectionLimits,
        max_datagram_size: u64,
        ids: ConnectionIds,
    ) -> Self {
        let mut endpoint = Self::new(role, limits, max_datagram_size);
        endpoint.local_cid = Some(ids.local_receive);
        endpoint.peer_cid = Some(ids.peer_receive);
        endpoint
    }

    /// Construct an endpoint with a selected retransmission ledger size.
    ///
    /// Host/std builds allocate only the requested number of slots. Embedded
    /// builds retain their fixed `H`-slot array and use the request as the
    /// active limit, so this API has identical semantics without introducing
    /// heap allocation into the no-std path.
    pub fn new_with_history_capacity(
        role: Role,
        limits: ConnectionLimits,
        max_datagram_size: u64,
        history_capacity: usize,
    ) -> Self {
        assert!(history_capacity > 0 && history_capacity <= H);
        Self {
            send: SendFlowControl::new(limits.max_data, limits.max_stream_data),
            receive: ConnectionState::new(role, limits),
            congestion: CongestionController::new(max_datagram_size),
            received_packets: AckRangeSet::new(),
            peer_ack_ranges: AckRangeSet::new(),
            next_packet_number: 0,
            largest_acked_by_peer: None,
            #[cfg(any(feature = "std", test))]
            sent_packets: alloc::vec![None; history_capacity],
            #[cfg(not(any(feature = "std", test)))]
            sent_packets: [None; H],
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
            max_ack_delay_ms: 25,
            peer_max_ack_delay_ms: 25,
            peer_max_in_flight_packets: usize::MAX,
            pending_stream_ids: [None; N],
            send_clock: 0,
            rtt: RttEstimator::default(),
            last_pto_probe_at: None,
            pto_backoff: 0,
            close_code: None,
            history_limit: history_capacity,
            stats: TransportStats::default(),
            highest_received_packet: None,
            last_receive_time: None,
        }
    }

    pub fn observe_packet(&mut self, packet_number: u32) {
        if !self.received_packets.contains(packet_number) {
            let previous_highest = self.highest_received_packet;
            if let Some(highest) = self.highest_received_packet {
                let next = highest.saturating_add(1);
                if packet_number < next {
                    self.stats.out_of_order_datagrams += 1;
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

    pub fn expected_packet_number(&self) -> u32 {
        self.largest_received()
            .and_then(|value| value.checked_add(1))
            .unwrap_or(0)
    }

    pub fn next_packet_number_len(&self) -> u8 {
        packet_number_len(self.next_packet_number, self.largest_acked_by_peer)
    }

    pub fn largest_received(&self) -> Option<u32> {
        self.received_packets.get(0).map(|range| range.end)
    }

    pub fn open_send_stream(&mut self, id: u64, max_data: u64) -> Result<(), Error> {
        self.send.open_stream(id, max_data)
    }

    /// Install peer-advertised bootstrap credit before creating application
    /// streams. This prevents a default host window from overrunning a
    /// smaller embedded receiver before its first MAX_* update.
    pub fn set_initial_peer_credit(
        &mut self,
        max_data: u64,
        max_stream_data: u64,
    ) -> Result<(), Error> {
        self.set_initial_peer_budget(max_data, max_stream_data, 0)
    }

    /// Install bootstrap byte credit and an optional peer packet-flight
    /// budget. A non-zero budget is receiver-advertised backpressure, not a
    /// bearer pacing policy: ACKed packets immediately free another slot.
    pub fn set_initial_peer_budget(
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
    pub fn peer_max_in_flight_packets(&self) -> usize {
        self.peer_max_in_flight_packets
    }

    /// Largest packet number the peer has acknowledged on this association.
    /// This is aggregate transport telemetry used to diagnose a stalled
    /// sender; callers must not infer application delivery from it.
    pub fn largest_acked_by_peer(&self) -> Option<u32> {
        self.largest_acked_by_peer
    }

    pub fn install_connection_ids(
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
    pub fn continue_packet_numbers_from(&mut self, next: u32) -> Result<(), Error> {
        if next < self.next_packet_number {
            return Err(Error::Invalid);
        }
        self.next_packet_number = next;
        Ok(())
    }

    pub fn local_connection_id(&self) -> Option<ConnectionId> {
        self.local_cid
    }
    pub fn peer_connection_id(&self) -> Option<ConnectionId> {
        self.peer_cid
    }
    /// Maximum number of retained packets currently enabled for this side.
    /// Host/std builds allocate this many slots; no-std builds retain their
    /// fixed type-level backing array and use this as the active limit.
    pub const fn history_capacity(&self) -> usize {
        self.history_limit
    }

    /// Reduce or restore the active ledger limit for this endpoint. A limit
    /// may never exceed the statically allocated profile and cannot evict
    /// packets that are still needed for retransmission.
    pub fn set_history_capacity(&mut self, limit: usize) -> Result<(), Error> {
        if limit == 0
            || limit > H
            || self.history_len() > limit
            || self
                .sent_packets
                .iter()
                .skip(limit)
                .any(|slot| slot.is_some())
        {
            return Err(Error::HistoryFull);
        }
        #[cfg(any(feature = "std", test))]
        {
            if limit > self.sent_packets.len() {
                self.sent_packets.resize(limit, None);
            } else if limit < self.sent_packets.len() {
                self.sent_packets.truncate(limit);
                self.sent_packets.shrink_to_fit();
            }
        }
        self.history_limit = limit;
        Ok(())
    }
    pub fn history_len(&self) -> usize {
        self.sent_packets
            .iter()
            .filter(|slot| slot.is_some())
            .count()
    }

    /// Number of slots physically allocated by this endpoint. On host/std
    /// this changes with dynamic ledger growth/shrink; on no-std it is the
    /// compile-time array size.
    pub fn history_storage_slots(&self) -> usize {
        self.sent_packets.len()
    }

    pub fn history_storage_bytes(&self) -> usize {
        self.history_storage_slots() * core::mem::size_of::<SentPacket<P>>()
    }
    pub fn received_packet_count(&self) -> usize {
        self.received_packets.len()
    }
    pub fn has_received_packet(&self, packet_number: u32) -> bool {
        self.received_packets.contains(packet_number)
    }
    pub fn bytes_in_flight(&self) -> u64 {
        self.congestion.bytes_in_flight
    }

    /// Copy the receive ACK ranges for bearer diagnostics.  The ranges are
    /// newest-first and bounded by the same fixed wire budget used by
    /// `Frame::AckRanges`; callers cannot observe or mutate endpoint storage.
    pub fn ack_ranges_snapshot(&self) -> [Option<AckRange>; ACK_RANGE_CAPACITY] {
        core::array::from_fn(|index| self.received_packets.get(index))
    }

    /// Copy the newest ACK range set received from the peer. This is separate
    /// from `ack_ranges_snapshot`, which reports packets received locally.
    pub fn peer_ack_ranges_snapshot(&self) -> [Option<AckRange>; ACK_RANGE_CAPACITY] {
        core::array::from_fn(|index| self.peer_ack_ranges.get(index))
    }

    /// Copy the currently retained wire packet numbers for diagnostics.  A
    /// retransmission replaces its slot with a fresh packet number, so this
    /// exposes exactly what the congestion ledger still considers in flight.
    /// The returned array is fixed-size to remain available on no-std targets;
    /// `count` is the number of populated entries.
    pub fn outstanding_packet_numbers(&self) -> ([Option<u32>; H], usize) {
        let mut numbers = [None; H];
        let mut count = 0;
        for (index, slot) in self.sent_packets.iter().take(H).enumerate() {
            if let Some(packet) = slot {
                numbers[index] = Some(packet.packet_number);
                count += 1;
            }
        }
        (numbers, count)
    }

    pub const fn retransmission_payload_capacity(&self) -> usize {
        P
    }

    /// Number of retransmittable stream payload bytes currently retained.
    /// This is intentionally exposed for diagnostics and bounded-memory
    /// assertions; packet metadata is accounted separately by the profile.
    pub fn retained_payload_bytes(&self) -> usize {
        self.sent_packets
            .iter()
            .flatten()
            .map(|packet| packet.payload_len)
            .sum()
    }

    /// Maximum payload bytes that this endpoint can retain in its ledger.
    pub const fn retransmission_capacity_bytes(&self) -> usize {
        self.history_limit.saturating_mul(P)
    }

    pub fn set_time(&mut self, now: u64) {
        self.send_clock = now;
    }

    /// Select how many newly received stream packets may be coalesced before
    /// an ACK/window datagram is emitted. The transport still owns the ACK
    /// contents and scheduling; the bearer/profile selects this policy.
    pub fn set_ack_frequency(&mut self, packets: u8) {
        self.ack_frequency = packets.clamp(1, ACK_RANGE_CAPACITY as u8);
    }

    /// Install the out-of-band association ACK policy. Version 0 has no
    /// authenticated ACK_FREQUENCY frame, so both peers must receive these
    /// values from the association/bootstrap owner before data is sent.
    pub fn set_ack_policy(&mut self, packets: u8, max_ack_delay_ms: u64) {
        self.set_ack_frequency(packets);
        self.max_ack_delay_ms = max_ack_delay_ms;
        self.peer_max_ack_delay_ms = max_ack_delay_ms;
    }

    /// Active local ACK policy after any peer ACK_FREQUENCY update.
    ///
    /// This exposes policy, rather than making a bearer infer it from the
    /// number of ACK_FREQUENCY frames observed in a diagnostics interval.
    pub const fn ack_frequency(&self) -> u8 {
        self.ack_frequency
    }

    /// Active local maximum delayed-ACK timer in milliseconds.
    pub const fn max_ack_delay_ms(&self) -> u64 {
        self.max_ack_delay_ms
    }

    /// Request the peer's ACK policy using the QUIC ACK_FREQUENCY extension.
    /// `packet_threshold=1` is RFC 9000's every-other-ack-eliciting-packet
    /// default; delay is carried in microseconds by the extension.
    pub fn request_ack_frequency(
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
        self.max_ack_delay_ms = max_ack_delay_us.saturating_add(999) / 1_000;
        self.ack_reordering_threshold = reordering_threshold as u32;
        self.largest_ack_frequency_sequence = Some(sequence);
        self.stats.ack_frequency_received = self.stats.ack_frequency_received.saturating_add(1);
        Ok(())
    }

    /// Return transport diagnostics for the current measurement interval.
    pub const fn stats(&self) -> TransportStats {
        self.stats
    }

    /// Start a fresh diagnostics interval without disturbing protocol state.
    pub fn reset_stats(&mut self) {
        self.stats = TransportStats::default();
        self.highest_received_packet = None;
        self.last_receive_time = None;
    }

    pub const fn latest_rtt(&self) -> Option<u64> {
        self.rtt.latest()
    }

    pub const fn smoothed_rtt(&self) -> Option<u64> {
        self.rtt.smoothed()
    }

    pub const fn rtt_variance(&self) -> u64 {
        self.rtt.variance()
    }

    pub const fn min_rtt(&self) -> Option<u64> {
        self.rtt.minimum()
    }

    pub fn pto_timeout(&self) -> u64 {
        self.rtt.pto()
    }

    pub const fn is_closed(&self) -> bool {
        self.close_code.is_some()
    }

    pub const fn close_code(&self) -> Option<u64> {
        self.close_code
    }

    pub fn close(&mut self, code: u64) {
        self.close_code = Some(code);
    }

    /// Encode a connection-close packet. The caller sends it through its
    /// bearer and then stops scheduling application data on this endpoint.
    pub fn poll_close(&mut self, out: &mut [u8]) -> Result<Option<usize>, Error> {
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

    pub fn reserve_send(&mut self, id: u64, offset: u64, len: usize) -> Result<(), Error> {
        self.send.reserve(id, offset, len)
    }

    pub fn packet_sent(&mut self, bytes: u64) -> bool {
        self.congestion.on_packet_sent(bytes)
    }

    pub fn acked(&mut self, bytes: u64) {
        self.congestion.on_ack(bytes);
    }

    pub fn lost(&mut self, bytes: u64) {
        self.congestion.on_loss(bytes);
    }

    /// Decode and account one received stream datagram. This is the transport
    /// bearer boundary: callers provide datagram bytes, while stream IDs,
    /// offsets, packet ACK state, and receive credit remain transport-owned.
    pub fn receive_stream_packet<'a>(
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

    /// Hand one complete bearer datagram to the transport. ACKs and flow
    /// control are consumed here; only application STREAM frames are returned
    /// to the bearer adapter.
    pub fn receive_datagram<'a>(&mut self, input: &'a [u8]) -> Result<TransportPacket<'a>, Error> {
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
        // stream credit update. Version 0 exposes at most one application
        // stream frame per datagram; ACK/control frames may accompany it.
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
                Frame::Ping => ack_eliciting = true,
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
        self.stats.received_datagrams += 1;
        if duplicate {
            // A lost ACK causes the peer to retransmit the same packet
            // number. Re-ack it without delivering its stream bytes again.
            self.control_pending = true;
            self.ack_pending = true;
            self.stats.duplicate_datagrams += 1;
            self.stats.control_datagrams += 1;
            return Ok(TransportPacket::Control);
        }
        let Some(stream) = streams[0] else {
            // ACK/control packets still consume receive packet numbers.
            // PING, ACK_FREQUENCY, and CLOSE are ack-eliciting. Pure ACK and
            // flow-control packets are only acknowledged when otherwise due.
            self.observe_packet(header.packet_number);
            self.stats.control_datagrams += 1;
            if ack_eliciting {
                self.ack_pending = true;
                self.ack_packets = self.ack_packets.saturating_add(1);
            }
            return Ok(TransportPacket::Control);
        };
        for stream in streams[..stream_count].iter().flatten() {
            self.receive
                .accept(stream.id, stream.offset, stream.data.len(), stream.fin)?;
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
        self.queue_stream_credit(stream.id);
        self.stats.stream_datagrams += 1;
        Ok(TransportPacket::Stream {
            header,
            frame: stream,
        })
    }

    /// Process one bearer datagram and emit any transport responses through a
    /// callback. Application code supplies only a stream callback and the
    /// bearer send callback; ACKs, duplicate handling, flow credit, and
    /// response scheduling remain entirely inside transport.
    pub fn receive_with_callbacks<S, O>(
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
        let (header, _) = ShortHeader::decode_with_expected(input, self.expected_packet_number())?;
        let duplicate = self.has_received_packet(header.packet_number);
        // Stream delivery can apply bounded application backpressure. Do not
        // let a rejection consume packet numbers, ACK ranges, or flow credit.
        // The embedded endpoint contains a fixed packet ledger larger than
        // Recovery's main stack, so copy its checkpoint directly into heap
        // storage instead of materialising `self.clone()` on that stack.
        #[cfg(any(feature = "std", test))]
        let checkpoint = self.clone();
        #[cfg(not(any(feature = "std", test)))]
        let checkpoint = {
            let layout = Layout::new::<Self>();
            let raw = unsafe { alloc(layout) as *mut Self };
            if raw.is_null() {
                return Err(Error::Invalid);
            }
            unsafe {
                core::ptr::copy_nonoverlapping(self, raw, 1);
                Box::from_raw(raw)
            }
        };
        let packet = self.receive_datagram(input)?;
        let mut stream = false;
        if let TransportPacket::Stream { frame, .. } = packet {
            stream = true;
            let consumed = match on_stream(frame) {
                Ok(consumed) => consumed,
                Err(error) => {
                    #[cfg(any(feature = "std", test))]
                    {
                        *self = checkpoint;
                    }
                    #[cfg(not(any(feature = "std", test)))]
                    unsafe {
                        core::ptr::copy_nonoverlapping(checkpoint.as_ref(), self, 1);
                        let raw = Box::into_raw(checkpoint);
                        dealloc(raw.cast(), Layout::new::<Self>());
                    }
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

    /// Receive one datagram on an embedded hot path whose stream callback is
    /// terminal on failure.
    ///
    /// Unlike [`Self::receive_with_callbacks`], this does not checkpoint the
    /// whole endpoint before invoking `on_stream`.  That rollback guarantee
    /// is necessary for retryable application backpressure, but copying the
    /// complete retransmission ledger for every ordinary in-order packet is
    /// prohibitively expensive on an ESP.  A callback error here commits the
    /// transport packet; callers must close or otherwise terminate that
    /// application stream instead of asking the peer to retry it.
    /// Receive one datagram and commit its stream callback, deferring any
    /// ACK/control output until the bearer explicitly calls
    /// [`Self::poll_transmit`].
    ///
    /// A datagram bearer may drain several already-queued packets before it
    /// returns to its transmit side.  Keeping this operation receive-only
    /// lets that bearer coalesce their ACK and flow-credit updates into one
    /// control datagram without exposing transport details to the consumer.
    pub fn receive_with_committed_callbacks_deferred<S>(
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
    pub fn receive_with_committed_callback_dispositions<S>(
        &mut self,
        input: &[u8],
        mut on_stream: S,
    ) -> Result<TransportReceiveInfo, Error>
    where
        S: FnMut(StreamFrame<'_>) -> Result<CommittedStreamDisposition, Error>,
    {
        let (header, _) = ShortHeader::decode_with_expected(input, self.expected_packet_number())?;
        let duplicate = self.has_received_packet(header.packet_number);
        let packet = self.receive_datagram(input)?;
        let mut stream = false;
        if let TransportPacket::Stream { frame, .. } = packet {
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

    /// Receive one datagram on an embedded hot path whose stream callback is
    /// terminal on failure, then emit any due ACK/control packet.
    pub fn receive_with_committed_callbacks<S, O>(
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

impl<const N: usize, const H: usize, const P: usize> EndpointState<N, H, P> {
    /// Validate all frame boundaries without applying state. Adapters that
    /// need to inspect a datagram before dispatch can use this inexpensive
    /// transaction check.
    pub fn validate_datagram(input: &[u8]) -> Result<(), Error> {
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
    pub fn stream_consumed(&mut self, stream_id: u64, bytes: usize) -> Result<(), Error> {
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
    pub fn on_bearer_timeout(&mut self) {}

    /// Report application bytes made durable while leaving control-packet
    /// scheduling to the bearer’s next [`Self::poll_transmit`] call.
    ///
    /// This is for bounded asynchronous sinks: they may accept stream bytes
    /// into private storage, emit an ACK for the received burst, and only
    /// return flow credit after that storage is released. The caller never
    /// constructs or interprets an ACK.
    pub fn stream_consumed_deferred(&mut self, stream_id: u64, bytes: usize) -> Result<(), Error> {
        self.stream_consumed_inner(stream_id, bytes, false)
    }

    /// Record durable consumption but deliberately withhold any MAX_* credit
    /// extension. A device-wide RAM admission controller calls
    /// [`Self::grant_receive_window`] later, once shared packet/relay memory
    /// is available. ACK state remains live so a sender can distinguish
    /// delivery from additional receive capacity.
    pub fn stream_consumed_without_credit(
        &mut self,
        stream_id: u64,
        bytes: usize,
    ) -> Result<(), Error> {
        self.receive.consume(stream_id, bytes as u64)?;
        self.ack_pending = true;
        Ok(())
    }

    /// Advertise an admitted effective receive window. `window_bytes` is a
    /// sliding-window size, not an unconditional increment; FlowControl only
    /// advances the absolute MAX_* values as consumed bytes make room. A
    /// smaller value therefore withholds replenishment and never revokes an
    /// already advertised peer credit.
    pub fn grant_receive_window(&mut self, stream_id: u64, window_bytes: u64) -> Result<(), Error> {
        self.receive.extend_connection_credit(window_bytes);
        self.receive.extend_stream_credit(stream_id, window_bytes)?;
        self.control_pending = true;
        self.queue_stream_credit(stream_id);
        Ok(())
    }

    fn queue_stream_credit(&mut self, stream_id: u64) {
        if self
            .pending_stream_ids
            .iter()
            .any(|pending| *pending == Some(stream_id))
        {
            return;
        }
        // A pending credit belongs only to an accepted stream, and accepted
        // streams are bounded by this endpoint's `N` slots. Therefore a free
        // pending slot must exist unless a caller has violated endpoint
        // ownership; retaining existing credits is safer than overwriting one.
        if let Some(slot) = self
            .pending_stream_ids
            .iter_mut()
            .find(|pending| pending.is_none())
        {
            *slot = Some(stream_id);
        }
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
            .extend_connection_credit(self.receive.limits.max_data);
        self.receive
            .extend_stream_credit(stream_id, self.receive.limits.max_stream_data)?;
        if force_control {
            self.control_pending = true;
        }
        self.ack_pending = true;
        self.queue_stream_credit(stream_id);
        Ok(())
    }

    /// Let the transport decide whether an ACK/window packet is due. The
    /// bearer only sends the returned datagram and never inspects its frames.
    pub fn poll_transmit(&mut self, out: &mut [u8]) -> Result<Option<usize>, Error> {
        let ack_threshold_due = self.ack_pending && self.ack_packets >= self.ack_frequency;
        let ack_timer_due = self.ack_pending
            && self.send_clock.saturating_sub(self.largest_received_at) >= self.max_ack_delay_ms;
        let delayed_ack_due = ack_threshold_due || ack_timer_due;
        let send_ack = self.control_pending || delayed_ack_due;
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
                    .min(self.max_ack_delay_ms),
                ranges: self.received_packets,
            }
            .encode(&mut out[p..])?;
            p += Frame::MaxData(self.receive.connection.max_data).encode(&mut out[p..])?;
            for stream_id in self.pending_stream_ids.iter_mut().filter_map(Option::take) {
                let max = self
                    .receive
                    .stream_max_data(stream_id)
                    .unwrap_or(self.receive.limits.max_stream_data);
                p += Frame::MaxStreamData { id: stream_id, max }.encode(&mut out[p..])?;
            }
            self.control_pending = false;
            self.ack_pending = false;
            self.ack_packets = 0;
            self.last_ack_time = self.send_clock;
            self.stats.ack_datagrams += 1;
            if immediate_ack {
                self.stats.ack_immediate_datagrams += 1;
            } else if ack_threshold_due {
                self.stats.ack_threshold_datagrams += 1;
            } else if ack_timer_due {
                self.stats.ack_timer_datagrams += 1;
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
        self.stats.sent_datagrams += 1;
        self.stats.sent_control_datagrams += 1;
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
                Frame::MaxStreamData { id, max } => self.send.extend_stream(id, max)?,
                _ => {}
            }
            offset += used;
        }
        if acknowledged.len() == 0 {
            return Err(Error::Invalid);
        }
        self.peer_ack_ranges = acknowledged;
        self.largest_acked_by_peer = acknowledged.get(0).map(|range| range.end);
        let largest_acked = acknowledged.get(0).map(|range| range.end);
        // A fresh wire packet number can carry a retransmission of an older
        // stream range. ACKing that packet proves only that old logical range
        // was delivered: it must not make every intervening, newly-sent wire
        // packet look lost. Keep a separate packet-threshold frontier made
        // solely from acknowledged first transmissions. Time/PTO recovery
        // remains available if no new logical range was acknowledged.
        let mut largest_acked_fresh_packet = None;
        let mut rtt_sample = None;
        let mut newly_acked = false;
        for slot in &mut self.sent_packets {
            if let Some(sent) = *slot {
                if sent.acknowledged_by(&acknowledged) {
                    if sent.prior_packet_count == 0 {
                        largest_acked_fresh_packet = Some(
                            largest_acked_fresh_packet
                                .map(|current: u32| current.max(sent.packet_number))
                                .unwrap_or(sent.packet_number),
                        );
                    }
                    if largest_acked.is_some_and(|packet| {
                        sent.packet_number == packet
                            || sent.prior_packet_numbers[..sent.prior_packet_count as usize]
                                .contains(&packet)
                    }) {
                        rtt_sample = Some(self.send_clock.saturating_sub(sent.sent_at));
                    }
                    self.congestion.on_ack(sent.bytes);
                    *slot = None;
                    newly_acked = true;
                }
            }
        }
        if newly_acked {
            // Any forward acknowledgement ends the PTO episode. The next
            // genuine timeout starts from the base PTO again.
            self.last_pto_probe_at = None;
            self.pto_backoff = 0;
        }
        if let Some(sample) = rtt_sample {
            let ack_delay = reported_ack_delay.min(self.peer_max_ack_delay_ms);
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
        self.detect_ack_losses(largest_acked_fresh_packet);
        Ok(())
    }

    /// Encode one stream packet using the endpoint's shared packet-number,
    /// flow-credit, and congestion state. The caller owns packet storage and
    /// retains the returned packet number for loss/ACK bookkeeping.
    pub fn encode_stream_packet(
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
            // independent of byte cwnd: small datagrams must not translate
            // a 14 KiB window into a radio burst the peer cannot queue.
            return Err(Error::Invalid);
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
            return Err(Error::Invalid);
        }
        self.send.reserve(stream_id, offset, data.len())?;
        if !self.congestion.on_packet_sent(p as u64) {
            return Err(Error::Invalid);
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
        self.stats.sent_datagrams += 1;
        self.stats.sent_stream_datagrams += 1;
        Ok((p, packet_number))
    }

    /// Encode a small ack-eliciting probe on an established connection.
    /// Probes carry no application bytes or stream credit; multipath adapters
    /// use them to refresh a bearer measurement after temporary loss. Their
    /// packet number still belongs to the one shared connection sequence.
    pub fn encode_probe_packet(
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

    /// Re-encode one outstanding stream frame with a fresh packet number.
    ///
    /// Packet numbers are never reused within a connection. A retransmission
    /// carries the same stream range, which the receive stream reassembler
    /// deduplicates, but it is a new transport packet and must receive a new
    /// number.
    pub fn retransmit_stream_packet(
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
        // Each lost *transmission* must leave bytes-in-flight. Use the first
        // packet number for the NewReno epoch, however, so retransmitting one
        // stream range under fresh packet numbers cannot halve cwnd again.
        self.congestion.on_packet_lost(
            sent.bytes,
            sent.logical_packet_number(),
            self.next_packet_number.saturating_sub(1),
        );
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
        self.stats.sent_datagrams += 1;
        self.stats.sent_stream_datagrams += 1;
        self.stats.retransmitted_datagrams += 1;
        Ok(Some((used, packet_number)))
    }

    pub fn retransmit_due(
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
    pub fn retransmit_marked_loss(
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
                    self.stats.loss_retransmitted_datagrams =
                        self.stats.loss_retransmitted_datagrams.saturating_add(1);
                }
                Ok(retransmission)
            }
            None => Ok(None),
        }
    }

    /// Send at most one PTO probe when no packet has already been declared
    /// lost. Multiple PTO probes in one scheduler pass amplify a timeout into
    /// a burst; declared loss repair is handled by `retransmit_marked_loss`.
    pub fn retransmit_pto_probe(
        &mut self,
        now: u64,
        pto: u64,
        out: &mut [u8],
    ) -> Result<Option<(usize, u32)>, Error> {
        let multiplier = 1u64 << self.pto_backoff.min(5);
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
                    self.stats.pto_retransmitted_datagrams =
                        self.stats.pto_retransmitted_datagrams.saturating_add(1);
                    self.last_pto_probe_at = Some(now);
                    self.pto_backoff = self.pto_backoff.saturating_add(1).min(5);
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
            .unwrap_or(25)
            .max(1);
        // RFC 9002's 9/8 time threshold, rounded up in millisecond clocks.
        // `base_rtt` is ACK-delay compensated, while an outstanding sibling
        // packet may still be waiting for the peer's negotiated delayed ACK.
        // Include that association parameter here: otherwise a normal
        // delayed ACK makes a same-burst packet appear lost and collapses the
        // congestion window into stop-and-wait pacing.
        let time_threshold =
            base_rtt.saturating_mul(9).saturating_add(7) / 8 + self.peer_max_ack_delay_ms;
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
                    self.stats.loss_packet_threshold_datagrams =
                        self.stats.loss_packet_threshold_datagrams.saturating_add(1);
                } else {
                    self.stats.loss_time_threshold_datagrams =
                        self.stats.loss_time_threshold_datagrams.saturating_add(1);
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
    pub fn mark_lost(&mut self, packet_number: u32) -> bool {
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

    #[test]
    fn before_deadline_handles_normal_and_wrapping_u32_clocks() {
        assert!(before_deadline_u32(100, 101));
        assert!(!before_deadline_u32(101, 101));
        assert!(!before_deadline_u32(102, 101));
        assert!(before_deadline_u32(u32::MAX - 2, 3));
        assert!(!before_deadline_u32(3, u32::MAX - 2));
    }
    use std::collections::VecDeque;
    use std::vec;
    use std::vec::Vec;

    #[test]
    fn deterministic_parser_fuzz_smoke_never_panics_or_mutates_on_rejection() {
        let mut state =
            EndpointState::<8, 4, 128>::new(Role::Server, ConnectionLimits::default(), 1200);
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
                let _ = EndpointState::<8, 4, 128>::validate_datagram(&bytes);
                state.receive_datagram(&bytes)
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
                    "rejected datagram mutated state at seed={seed:#x}"
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
            0x3f,
            0x40,
            0x3fff,
            0x4000,
            0x3fff_ffff,
            0x4000_0000,
            (1u64 << 62) - 1,
        ] {
            let id = ConnectionId::new(value).unwrap();
            let mut b = [0; 8];
            let n = id.encode(&mut b).unwrap();
            assert_eq!(n, id.encoded_len());
            assert_eq!(ConnectionId::decode(&b[..n]).unwrap(), (id, n));
        }
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
    fn connection_and_stream_credit_are_bounded() {
        let limits = ConnectionLimits {
            max_data: 8,
            max_stream_data: 8,
            max_streams_bidi: 1,
            max_streams_uni: 1,
        };
        let mut c = ConnectionState::<2>::new(Role::Server, limits);
        assert!(c.accept(0, 0, 5, false).is_ok());
        assert_eq!(c.accept(0, 5, 4, false), Err(Error::FlowControl));
        assert!(c.consume(0, 5).is_ok());
    }

    #[test]
    fn consumed_stream_keeps_the_negotiated_receive_budget() {
        let limits = ConnectionLimits {
            max_data: RECOVERY_INITIAL_MAX_DATA,
            max_stream_data: RECOVERY_INITIAL_MAX_DATA,
            max_streams_bidi: 1,
            max_streams_uni: 1,
        };
        let mut endpoint = EndpointState::<2>::new(Role::Client, limits, 1400);
        endpoint.receive.accept(3, 0, 1200, false).unwrap();
        endpoint.stream_consumed(3, 1200).unwrap();
        assert_eq!(
            endpoint.receive.connection.max_data,
            1200 + RECOVERY_INITIAL_MAX_DATA
        );
        assert_eq!(
            endpoint.receive.stream_max_data(3),
            Some(1200 + RECOVERY_INITIAL_MAX_DATA)
        );
    }

    #[test]
    fn bootstrap_credit_constrains_sender_before_first_window_update() {
        let recovery = ConnectionLimits {
            max_data: RECOVERY_INITIAL_MAX_DATA,
            max_stream_data: RECOVERY_INITIAL_MAX_DATA,
            ..ConnectionLimits::default()
        };
        let open = BootstrapOpen {
            client_receive_cid: ConnectionId::new(7).unwrap(),
            max_data: recovery.max_data,
            max_stream_data: recovery.max_stream_data,
            max_in_flight_packets: RECOVERY_MAX_IN_FLIGHT_PACKETS,
        };
        let mut encoded = [0u8; 32];
        let used = open.encode(&mut encoded).unwrap();
        let advertised = BootstrapOpen::decode(&encoded[..used]).unwrap();

        let mut host = EndpointState::<2>::new(Role::Server, ConnectionLimits::default(), 1400);
        host.set_initial_peer_budget(
            advertised.max_data,
            advertised.max_stream_data,
            advertised.max_in_flight_packets,
        )
        .unwrap();
        host.open_send_stream(FIRST_SERVER_BIDI_STREAM_ID, INITIAL_MAX_STREAM_DATA)
            .unwrap();
        host.reserve_send(
            FIRST_SERVER_BIDI_STREAM_ID,
            0,
            RECOVERY_INITIAL_MAX_DATA as usize,
        )
        .unwrap();
        assert_eq!(
            host.reserve_send(FIRST_SERVER_BIDI_STREAM_ID, RECOVERY_INITIAL_MAX_DATA, 1,),
            Err(Error::FlowControl)
        );
    }

    #[test]
    fn delayed_bootstrap_ack_advances_the_receive_packet_frontier() {
        // OPEN retries and OPEN_ACK retries have independent packet-number
        // spaces. A client must retain the server's acknowledged packet
        // number before it accepts the first established stream datagram.
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

        let mut receiver = EndpointState::<2>::new(Role::Client, limits, 1400);
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
            .receive_datagram(&stream_packet[..stream_header + stream_len])
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
    fn bootstrap_packet_budget_limits_small_datagram_burst() {
        let local = ConnectionId::new(0x701).unwrap();
        let peer = ConnectionId::new(0x702).unwrap();
        let mut sender =
            EndpointState::<2, 64, 64>::new(Role::Server, ConnectionLimits::default(), 1400);
        sender.install_connection_ids(local, peer).unwrap();
        sender
            .set_initial_peer_budget(
                INITIAL_MAX_DATA,
                INITIAL_MAX_STREAM_DATA,
                RECOVERY_MAX_IN_FLIGHT_PACKETS,
            )
            .unwrap();
        sender
            .open_send_stream(FIRST_SERVER_BIDI_STREAM_ID, INITIAL_MAX_STREAM_DATA)
            .unwrap();
        sender.congestion.congestion_window = u64::from(RECOVERY_MAX_IN_FLIGHT_PACKETS) * 1400;
        let mut packet = [0u8; 128];
        for offset in 0..u64::from(RECOVERY_MAX_IN_FLIGHT_PACKETS) {
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
                u64::from(RECOVERY_MAX_IN_FLIGHT_PACKETS),
                true,
                b"x",
                &mut packet,
            ),
            Err(Error::Invalid)
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
        let mut c = ConnectionState::<1>::new(Role::Server, limits);
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
        let mut c = ConnectionState::<2>::new(Role::Server, limits);
        assert!(c.accept(0, 0, 8, false).is_ok());
        assert_eq!(c.accept(0, 8, 1, false), Err(Error::FlowControl));
        assert!(c.consume(0, 8).is_ok());
        c.streams[0].as_mut().unwrap().extend(8);
        assert!(c.accept(0, 8, 8, false).is_ok());
        assert_eq!(c.accept(0, 16, 1, false), Err(Error::FlowControl));
        assert!(c.consume(0, 8).is_ok());
        c.streams[0].as_mut().unwrap().extend(1);
        c.connection.extend(16);
        assert!(c.accept(0, 16, 1, false).is_ok());
    }

    #[test]
    fn sender_flow_credit_blocks_and_extension_allows_progress() {
        let mut flow = SendFlowControl::<2>::new(16, 8);
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
        let mut endpoint = EndpointState::<2>::new(Role::Client, ConnectionLimits::default(), 1200);
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
        };
        let mut encoded = [0u8; 32];
        let used = client.encode(&mut encoded).unwrap();
        assert_eq!(BootstrapOpen::decode(&encoded[..used]).unwrap(), client);
        let server = BootstrapOpenAck {
            server_receive_cid: ConnectionId::new(0x3fff).unwrap(),
            max_data: 4096,
            max_stream_data: 2048,
            max_in_flight_packets: 0,
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
        };
        let mut encoded = [0u8; 32];
        let used = smallest.encode(&mut encoded).unwrap();
        assert_eq!(
            &encoded[..used],
            &[0x00, 0x00, 0x01, 0x05, 0x40, 0x40, 0x40, 0x40, 0x00]
        );

        let largest = BootstrapOpen {
            client_receive_cid: ConnectionId::new((1u64 << 62) - 1).unwrap(),
            max_data: 64,
            max_stream_data: 64,
            max_in_flight_packets: 0,
        };
        let used = largest.encode(&mut encoded).unwrap();
        assert_eq!(
            &encoded[..used],
            &[
                0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x05, 0x40, 0x40, 0x40,
                0x40, 0x00
            ]
        );

        let smallest_ack = BootstrapOpenAck {
            server_receive_cid: ConnectionId::new(1).unwrap(),
            max_data: 64,
            max_stream_data: 64,
            max_in_flight_packets: 0,
        };
        let used = smallest_ack.encode(&mut encoded).unwrap();
        assert_eq!(
            &encoded[..used],
            &[0x01, 0x00, 0x01, 0x05, 0x40, 0x40, 0x40, 0x40, 0x00]
        );

        let largest_ack = BootstrapOpenAck {
            server_receive_cid: ConnectionId::new((1u64 << 62) - 1).unwrap(),
            max_data: 64,
            max_stream_data: 64,
            max_in_flight_packets: 0,
        };
        let used = largest_ack.encode(&mut encoded).unwrap();
        assert_eq!(
            &encoded[..used],
            &[
                0x01, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x05, 0x40, 0x40, 0x40,
                0x40, 0x00
            ]
        );
    }

    #[test]
    fn shared_bootstrap_client_retries_with_new_packet_numbers_and_establishes() {
        let client_cid = ConnectionId::new(0x44).unwrap();
        let server_cid = ConnectionId::new(0x55).unwrap();
        let mut client = BootstrapClient::new(client_cid, 10, 3).unwrap();
        let mut open = [0u8; 128];
        let used = client.start_open(0, &mut open).unwrap();
        assert_eq!(client.state(), BootstrapClientState::Opening);
        assert_eq!(
            ShortHeader::decode(&open[..used]).unwrap().0.packet_number,
            0
        );

        let retry = client.poll_timeout(9, &mut open).unwrap();
        assert!(retry.is_none());
        let retry = client.poll_timeout(10, &mut open).unwrap().unwrap();
        assert_eq!(
            ShortHeader::decode(&open[..retry]).unwrap().0.packet_number,
            1
        );
        assert_eq!(client.attempts(), 2);

        let mut ack = [0u8; 128];
        let ack_len =
            encode_bootstrap_open_ack_packet(client_cid, server_cid, 0, &mut ack).unwrap();
        assert_eq!(client.on_open_ack(&ack[..ack_len]).unwrap(), server_cid);
        assert_eq!(client.state(), BootstrapClientState::Established);
        // A duplicate ACK is harmless; a different server CID is not.
        assert_eq!(client.on_open_ack(&ack[..ack_len]).unwrap(), server_cid);
        let other = ConnectionId::new(0x56).unwrap();
        let other_len = encode_bootstrap_open_ack_packet(client_cid, other, 1, &mut ack).unwrap();
        assert_eq!(
            client.on_open_ack(&ack[..other_len]),
            Err(Error::BootstrapInvalid)
        );

        let original_open_len = encode_bootstrap_open_packet(client_cid, 3, &mut open).unwrap();
        let mut collision_server = BootstrapServer::new(client_cid).unwrap();
        assert_eq!(
            collision_server.accept_open(&open[..original_open_len], 0, &mut ack),
            Err(Error::BootstrapInvalid)
        );
        assert_eq!(
            encode_bootstrap_open_ack_packet(client_cid, client_cid, 0, &mut ack),
            Err(Error::BootstrapInvalid)
        );
    }

    #[test]
    fn shared_bootstrap_client_fails_after_bounded_attempts() {
        let mut client = BootstrapClient::new(ConnectionId::new(0x66).unwrap(), 2, 2).unwrap();
        let mut packet = [0u8; 128];
        client.start_open(0, &mut packet).unwrap();
        assert!(client.poll_timeout(2, &mut packet).unwrap().is_some());
        assert_eq!(
            client.poll_timeout(6, &mut packet),
            Err(Error::BootstrapInvalid)
        );
        assert_eq!(client.state(), BootstrapClientState::Failed);
    }

    #[test]
    fn shared_bootstrap_server_replays_duplicate_and_rejects_conflict() {
        let client_cid = ConnectionId::new(0x77).unwrap();
        let server_cid = ConnectionId::new(0x88).unwrap();
        let mut client = BootstrapClient::new(client_cid, 10, 2).unwrap();
        let mut open = [0u8; 128];
        let open_len = client.start_open(0, &mut open).unwrap();
        let mut server = BootstrapServer::new(server_cid).unwrap();
        let mut ack = [0u8; 128];
        let (peer, duplicate, ack_len) =
            server.accept_open(&open[..open_len], 0, &mut ack).unwrap();
        assert_eq!(peer, client_cid);
        assert!(!duplicate);
        assert_eq!(server.state(), BootstrapServerState::Pending);
        let (_, duplicate, replay_len) =
            server.accept_open(&open[..open_len], 1, &mut ack).unwrap();
        assert!(duplicate);
        assert_ne!(ack_len, 0);
        assert_ne!(replay_len, 0);
        server.confirm_established(client_cid).unwrap();
        assert_eq!(server.state(), BootstrapServerState::Established);

        let other = ConnectionId::new(0x99).unwrap();
        let mut conflicting_client = BootstrapClient::new(other, 10, 2).unwrap();
        let conflicting_len = conflicting_client.start_open(0, &mut open).unwrap();
        assert_eq!(
            server.accept_open(&open[..conflicting_len], 2, &mut ack),
            Err(Error::BootstrapInvalid)
        );
    }

    #[test]
    fn directional_cids_are_validated_and_history_is_configurable() {
        let client_cid = ConnectionId::new(0x11).unwrap();
        let server_cid = ConnectionId::new(0x22).unwrap();
        let mut client =
            EndpointState::<4, 2>::new(Role::Client, ConnectionLimits::default(), 1200);
        let mut server =
            EndpointState::<4, 2>::new(Role::Server, ConnectionLimits::default(), 1200);
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
            DEFAULT_MAX_DATAGRAM_SIZE
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
        assert_eq!(client.set_history_capacity(1), Err(Error::HistoryFull));
        assert!(matches!(
            server.receive_datagram(&packet[..used]).unwrap(),
            TransportPacket::Stream { .. }
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
                .receive_datagram(&bad[..header_len + frame_len])
                .unwrap_err(),
            Error::WrongConnectionId
        );
    }

    #[test]
    fn combined_ack_and_stream_is_transactional() {
        let client_cid = ConnectionId::new(0x31).unwrap();
        let server_cid = ConnectionId::new(0x32).unwrap();
        let mut client =
            EndpointState::<4, 4>::new(Role::Client, ConnectionLimits::default(), 1200);
        let mut server =
            EndpointState::<4, 4>::new(Role::Server, ConnectionLimits::default(), 1200);
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
            server.receive_datagram(&request[..request_len]).unwrap(),
            TransportPacket::Stream { .. }
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
        let total = ack_len + stream_len;
        let packet = client.receive_datagram(&combined[..total]).unwrap();
        let TransportPacket::Stream { frame, .. } = packet else {
            panic!("combined packet lost stream frame");
        };
        assert_eq!(frame.data, b"response");
        assert_eq!(client.history_len(), 0);
        assert!(EndpointState::<4, 4>::validate_datagram(&combined[..total]).is_ok());

        let mut malformed = combined[..total].to_vec();
        malformed.push(0xff);
        assert!(EndpointState::<4, 4>::validate_datagram(&malformed).is_err());
    }

    #[test]
    fn packets_require_explicit_directional_cids() {
        let mut endpoint =
            EndpointState::<2, 2>::new(Role::Server, ConnectionLimits::default(), 1200);
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
        assert!(endpoint
            .receive_datagram(&malformed[..header_len + 1])
            .is_err());
        assert_eq!(endpoint.peer_connection_id(), None);

        let frame_len = Frame::Ping.encode(&mut malformed[header_len..]).unwrap();
        assert_eq!(
            endpoint
                .receive_datagram(&malformed[..header_len + frame_len])
                .unwrap_err(),
            Error::WrongConnectionId
        );
    }

    #[test]
    fn history_capacity_applies_backpressure_without_mutating_window() {
        let cid = ConnectionId::new(9).unwrap();
        let mut endpoint =
            EndpointState::<4, 1>::new(Role::Client, ConnectionLimits::default(), 1200);
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
        let mut endpoint = EndpointState::<4, 16, 128>::new_with_history_capacity(
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
    fn host_ledger_cannot_shrink_below_live_entries() {
        let cid = ConnectionId::new(0x4711).unwrap();
        let peer = ConnectionId::new(0x4712).unwrap();
        let mut endpoint = EndpointState::<4, 16, 64>::new_with_history_capacity(
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
        assert_eq!(endpoint.set_history_capacity(1), Err(Error::HistoryFull));
        assert_eq!(endpoint.history_capacity(), 8);
    }

    #[test]
    fn dynamic_host_ledger_tiers_stay_bounded_under_faults() {
        for capacity in [4_usize, 16, 64, 256, 512] {
            let local = ConnectionId::new(0x5100 + capacity as u64).unwrap();
            let peer = ConnectionId::new(0x5200 + capacity as u64).unwrap();
            let limits = ConnectionLimits::default();
            let mut sender = EndpointState::<512, 512, 64>::new_with_history_capacity(
                Role::Client,
                limits,
                1200,
                capacity,
            );
            let mut receiver = EndpointState::<512, 8, 64>::new(Role::Server, limits, 1200);
            sender.install_connection_ids(local, peer).unwrap();
            receiver.install_connection_ids(peer, local).unwrap();
            sender.open_send_stream(4, INITIAL_MAX_STREAM_DATA).unwrap();
            sender.congestion.congestion_window = (capacity as u64) * 1200;
            sender.congestion.slow_start_threshold = sender.congestion.congestion_window;
            let mut link = crate::fake::FakeDatagramLink::new(crate::fake::FaultConfig {
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
                link.send(index as u64, &packet[..used]);
                packet_numbers.push(packet_number);
                assert_eq!(sender.history_storage_slots(), capacity);
                assert!(sender.history_len() <= capacity);
                assert!(sender.retained_payload_bytes() <= sender.retransmission_capacity_bytes());
            }
            for datagram in link.poll(capacity as u64 + 5) {
                if let Ok(TransportPacket::Stream { frame, .. }) =
                    receiver.receive_datagram(&datagram)
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
        let mut sender =
            EndpointState::<4, 2, 64>::new(Role::Client, ConnectionLimits::default(), 1200);
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
    fn retransmitted_logical_range_does_not_repeat_congestion_reduction() {
        let local = ConnectionId::new(0x551).unwrap();
        let peer = ConnectionId::new(0x552).unwrap();
        let mut sender =
            EndpointState::<4, 4, 128>::new(Role::Client, ConnectionLimits::default(), 1200);
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
        assert_eq!(after_first_loss, 6_000);

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
        assert_eq!(sender.stats().retransmitted_datagrams, 2);
    }

    #[test]
    fn explicit_loss_of_retransmitted_range_keeps_recovery_epoch() {
        let local = ConnectionId::new(0x561).unwrap();
        let peer = ConnectionId::new(0x562).unwrap();
        let mut sender =
            EndpointState::<4, 4, 128>::new(Role::Client, ConnectionLimits::default(), 1200);
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
        assert_eq!(sender.congestion.congestion_window, after_first_loss);
    }

    #[test]
    fn ack_for_original_packet_retires_retransmitted_stream_range() {
        let local = ConnectionId::new(53).unwrap();
        let peer = ConnectionId::new(54).unwrap();
        let mut sender =
            EndpointState::<4, 4, 128>::new(Role::Client, ConnectionLimits::default(), 1200);
        let mut receiver =
            EndpointState::<4, 4, 128>::new(Role::Server, ConnectionLimits::default(), 1200);
        sender.install_connection_ids(local, peer).unwrap();
        receiver.install_connection_ids(peer, local).unwrap();
        sender.open_send_stream(4, INITIAL_MAX_STREAM_DATA).unwrap();
        let mut packet = [0u8; 256];
        let (used, original_pn) = sender
            .encode_stream_packet(peer, 4, 0, true, b"logical delivery", &mut packet)
            .unwrap();
        receiver.receive_datagram(&packet[..used]).unwrap();
        let (_, replacement_pn) = sender
            .retransmit_stream_packet(original_pn, &mut packet)
            .unwrap()
            .unwrap();
        assert_ne!(original_pn, replacement_pn);

        // The peer's delayed ACK covers the original transmission, not the
        // replacement. It must still retire the one logical stream range.
        receiver.set_time(25);
        let mut ack = [0u8; 256];
        let ack_len = receiver.poll_transmit(&mut ack).unwrap().unwrap();
        sender.receive_datagram(&ack[..ack_len]).unwrap();
        assert_eq!(sender.history_len(), 0);
    }

    #[test]
    fn delayed_ack_emits_on_timer_tick_without_another_datagram() {
        let local = ConnectionId::new(57).unwrap();
        let peer = ConnectionId::new(58).unwrap();
        let mut sender =
            EndpointState::<4, 4, 128>::new(Role::Client, ConnectionLimits::default(), 1200);
        let mut receiver =
            EndpointState::<4, 4, 128>::new(Role::Server, ConnectionLimits::default(), 1200);
        sender.install_connection_ids(local, peer).unwrap();
        receiver.install_connection_ids(peer, local).unwrap();
        receiver.set_ack_frequency(8);
        sender.open_send_stream(4, INITIAL_MAX_STREAM_DATA).unwrap();
        let mut packet = [0u8; 256];
        let (used, _) = sender
            .encode_stream_packet(peer, 4, 0, true, b"one packet", &mut packet)
            .unwrap();
        receiver.receive_datagram(&packet[..used]).unwrap();
        let mut ack = [0u8; 256];
        assert!(receiver.poll_transmit(&mut ack).unwrap().is_none());
        receiver.set_time(25);
        assert!(receiver.poll_transmit(&mut ack).unwrap().is_some());
    }

    #[test]
    fn bearer_timeout_respects_delayed_ack_deadline() {
        let local = ConnectionId::new(61).unwrap();
        let peer = ConnectionId::new(62).unwrap();
        let mut sender =
            EndpointState::<4, 4, 128>::new(Role::Client, ConnectionLimits::default(), 1200);
        let mut receiver =
            EndpointState::<4, 4, 128>::new(Role::Server, ConnectionLimits::default(), 1200);
        sender.install_connection_ids(local, peer).unwrap();
        receiver.install_connection_ids(peer, local).unwrap();
        receiver.set_ack_frequency(4);
        sender.open_send_stream(4, INITIAL_MAX_STREAM_DATA).unwrap();
        let mut packet = [0u8; 256];
        let (used, _) = sender
            .encode_stream_packet(peer, 4, 0, false, b"final short burst", &mut packet)
            .unwrap();
        let TransportPacket::Stream { frame, .. } =
            receiver.receive_datagram(&packet[..used]).unwrap()
        else {
            panic!("expected stream");
        };
        receiver
            .stream_consumed_deferred(frame.id, frame.data.len())
            .unwrap();
        let mut ack = [0u8; 256];
        assert!(receiver.poll_transmit(&mut ack).unwrap().is_none());
        receiver.set_time(24);
        receiver.on_bearer_timeout();
        assert!(receiver.poll_transmit(&mut ack).unwrap().is_none());
        receiver.set_time(25);
        receiver.on_bearer_timeout();
        assert!(receiver.poll_transmit(&mut ack).unwrap().is_some());
    }

    #[test]
    fn delayed_ack_budget_prevents_spurious_time_loss() {
        let local = ConnectionId::new(59).unwrap();
        let peer = ConnectionId::new(60).unwrap();
        let mut sender =
            EndpointState::<4, 4, 128>::new(Role::Client, ConnectionLimits::default(), 1200);
        sender.install_connection_ids(local, peer).unwrap();
        sender.set_ack_policy(8, 25);
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
        sender.receive_datagram(&ack[..used]).unwrap();

        assert!(sender
            .sent_packets
            .iter()
            .flatten()
            .any(|packet| packet.packet_number == first && !packet.lost));
    }

    #[test]
    fn recovery_ack_frequency_batches_eight_consumed_stream_packets() {
        let local = ConnectionId::new(59).unwrap();
        let peer = ConnectionId::new(60).unwrap();
        let mut sender =
            EndpointState::<4, 8, 128>::new(Role::Client, ConnectionLimits::default(), 1200);
        let mut receiver =
            EndpointState::<4, 8, 128>::new(Role::Server, ConnectionLimits::default(), 1200);
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
            receiver.receive_datagram(&packet[..used]).unwrap();
            receiver.stream_consumed_deferred(4, 1).unwrap();
            assert_eq!(
                receiver.poll_transmit(&mut ack).unwrap().is_some(),
                offset == 7
            );
        }
        let stats = receiver.stats();
        assert_eq!(stats.ack_datagrams, 1);
        assert_eq!(stats.ack_threshold_datagrams, 1);
        assert_eq!(stats.ack_immediate_datagrams, 0);
        assert_eq!(stats.ack_timer_datagrams, 0);
    }

    #[test]
    fn delayed_ack_encodes_observed_wait_and_gap_is_immediate() {
        let local = ConnectionId::new(65).unwrap();
        let peer = ConnectionId::new(66).unwrap();
        let mut sender =
            EndpointState::<4, 8, 128>::new(Role::Client, ConnectionLimits::default(), 1200);
        let mut receiver =
            EndpointState::<4, 8, 128>::new(Role::Server, ConnectionLimits::default(), 1200);
        sender.install_connection_ids(local, peer).unwrap();
        receiver.install_connection_ids(peer, local).unwrap();
        receiver.set_ack_policy(8, 25);
        sender.open_send_stream(4, INITIAL_MAX_STREAM_DATA).unwrap();
        let mut packet = [0u8; 256];
        let (used, _) = sender
            .encode_stream_packet(peer, 4, 0, false, b"a", &mut packet)
            .unwrap();
        receiver.set_time(100);
        receiver.receive_datagram(&packet[..used]).unwrap();
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
        receiver.receive_datagram(&packet[..used]).unwrap();
        assert!(receiver.poll_transmit(&mut ack).unwrap().is_some());
    }

    #[test]
    fn committed_stream_retransmission_with_no_new_bytes_reacks_immediately() {
        let local = ConnectionId::new(67).unwrap();
        let peer = ConnectionId::new(68).unwrap();
        let mut sender =
            EndpointState::<4, 8, 128>::new(Role::Client, ConnectionLimits::default(), 1200);
        let mut receiver =
            EndpointState::<4, 8, 128>::new(Role::Server, ConnectionLimits::default(), 1200);
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
        assert_eq!(receiver.stats().ack_immediate_datagrams, 1);
    }

    #[test]
    fn committed_deferred_receive_coalesces_a_full_recovery_drain() {
        let local = ConnectionId::new(681).unwrap();
        let peer = ConnectionId::new(682).unwrap();
        let mut sender =
            EndpointState::<4, 64, 128>::new(Role::Client, ConnectionLimits::default(), 1200);
        let mut receiver =
            EndpointState::<4, 16, 128>::new(Role::Server, ConnectionLimits::default(), 1200);
        sender.install_connection_ids(local, peer).unwrap();
        receiver.install_connection_ids(peer, local).unwrap();
        receiver.set_ack_policy(8, 5);
        sender
            .set_initial_peer_budget(
                INITIAL_MAX_DATA,
                INITIAL_MAX_STREAM_DATA,
                RECOVERY_MAX_IN_FLIGHT_PACKETS,
            )
            .unwrap();
        sender.open_send_stream(4, INITIAL_MAX_STREAM_DATA).unwrap();
        // Model a steady-state flight after slow-start expands; this test
        // validates the receiver's complete drain, not cwnd growth.
        sender.congestion.congestion_window = 32 * 1200;

        let mut packet = [0u8; 256];
        // Match Recovery's `UDP_RECEIVE_DRAIN_LIMIT`. The device drains the
        // lwIP queue through the deferred callback path, then polls once;
        // polling per datagram would hide an ACK-per-recvfrom regression.
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
        assert_eq!(receiver.stats().ack_datagrams, 1);
        assert_eq!(receiver.stats().ack_threshold_datagrams, 1);
    }

    #[test]
    fn committed_deferred_credit_keeps_negotiated_ack_frequency() {
        let local = ConnectionId::new(683).unwrap();
        let peer = ConnectionId::new(684).unwrap();
        let mut sender =
            EndpointState::<4, 16, 128>::new(Role::Client, ConnectionLimits::default(), 1200);
        let mut receiver =
            EndpointState::<4, 16, 128>::new(Role::Server, ConnectionLimits::default(), 1200);
        sender.install_connection_ids(local, peer).unwrap();
        receiver.install_connection_ids(peer, local).unwrap();
        receiver.set_ack_policy(8, 5);
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
        assert_eq!(receiver.stats().ack_threshold_datagrams, 1);
        assert_eq!(receiver.stats().ack_immediate_datagrams, 0);
    }

    #[test]
    fn ack_frequency_frame_sets_every_other_packet_and_reordering_exception() {
        let local = ConnectionId::new(69).unwrap();
        let peer = ConnectionId::new(70).unwrap();
        let mut sender =
            EndpointState::<4, 8, 128>::new(Role::Client, ConnectionLimits::default(), 1200);
        let mut receiver =
            EndpointState::<4, 8, 128>::new(Role::Server, ConnectionLimits::default(), 1200);
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
            receiver.receive_datagram(&packet[..used]).unwrap(),
            TransportPacket::Control
        );
        assert_eq!(sender.stats().sent_control_datagrams, 1);
        assert_eq!(sender.stats().sent_stream_datagrams, 0);
        assert_eq!(receiver.ack_frequency, 2);
        assert_eq!(receiver.max_ack_delay_ms, 25);
        assert_eq!(receiver.ack_reordering_threshold, 1);
        assert_eq!(receiver.stats().ack_frequency_received, 1);

        // A second ack-eliciting ACK_FREQUENCY frame reaches the every-other
        // threshold and is acknowledged.
        sender.request_ack_frequency(8, 1, 25_000, 1).unwrap();
        let used = sender.poll_transmit(&mut packet).unwrap().unwrap();
        receiver.receive_datagram(&packet[..used]).unwrap();
        assert!(receiver.poll_transmit(&mut packet).unwrap().is_some());
        assert_eq!(receiver.stats().ack_threshold_datagrams, 1);
        assert_eq!(sender.stats().sent_control_datagrams, 2);

        // Older association state cannot roll back a newer ACK policy.
        sender.request_ack_frequency(7, 7, 1_000, 0).unwrap();
        let used = sender.poll_transmit(&mut packet).unwrap().unwrap();
        receiver.receive_datagram(&packet[..used]).unwrap();
        assert_eq!(receiver.ack_frequency, 2);
        assert_eq!(receiver.max_ack_delay_ms, 25);
        assert_eq!(receiver.ack_reordering_threshold, 1);
    }

    #[test]
    fn declared_losses_can_be_drained_before_a_single_pto_probe() {
        let local = ConnectionId::new(71).unwrap();
        let peer = ConnectionId::new(72).unwrap();
        let mut sender =
            EndpointState::<4, 8, 128>::new(Role::Client, ConnectionLimits::default(), 1200);
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
        assert!(sender
            .retransmit_pto_probe(0, 250, &mut packet)
            .unwrap()
            .is_none());
        let stats = sender.stats();
        assert_eq!(stats.loss_retransmitted_datagrams, 3);
        assert_eq!(stats.pto_retransmitted_datagrams, 0);
    }

    #[test]
    fn pto_sends_one_probe_then_backs_off_until_ack_progress() {
        let local = ConnectionId::new(81).unwrap();
        let peer = ConnectionId::new(82).unwrap();
        let mut sender =
            EndpointState::<4, 8, 128>::new(Role::Client, ConnectionLimits::default(), 1200);
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
        assert!(sender
            .retransmit_pto_probe(250, 250, &mut packet)
            .unwrap()
            .is_some());
        assert!(sender
            .retransmit_pto_probe(250, 250, &mut packet)
            .unwrap()
            .is_none());
        assert!(sender
            .retransmit_pto_probe(499, 250, &mut packet)
            .unwrap()
            .is_none());
        // PTO backoff doubles the next wait.
        assert!(sender
            .retransmit_pto_probe(750, 250, &mut packet)
            .unwrap()
            .is_some());
        assert_eq!(sender.stats().pto_retransmitted_datagrams, 2);
    }

    #[test]
    fn selective_ack_gap_retransmits_before_pto() {
        let local = ConnectionId::new(63).unwrap();
        let peer = ConnectionId::new(64).unwrap();
        let mut sender =
            EndpointState::<4, 8, 128>::new(Role::Client, ConnectionLimits::default(), 1200);
        let mut receiver =
            EndpointState::<4, 8, 128>::new(Role::Server, ConnectionLimits::default(), 1200);
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
            .receive_datagram(&delivered[0][..delivered_len[0]])
            .unwrap();
        receiver
            .receive_datagram(&delivered[1][..delivered_len[1]])
            .unwrap();
        let mut ack = [0u8; 256];
        let ack_len = receiver.poll_transmit(&mut ack).unwrap().unwrap();
        sender.receive_datagram(&ack[..ack_len]).unwrap();

        // No 250 ms PTO elapsed: packet-threshold loss makes the missing
        // early range eligible immediately.
        let (_, retransmitted_pn) = sender
            .retransmit_due(10, 250, &mut packet)
            .unwrap()
            .unwrap();
        assert!(retransmitted_pn >= 5);
        let stats = sender.stats();
        assert_eq!(stats.loss_packet_threshold_datagrams, 2);
        assert_eq!(stats.loss_time_threshold_datagrams, 0);
        assert_eq!(stats.loss_events, 1);
        assert_eq!(stats.loss_retransmitted_datagrams, 1);
        assert_eq!(stats.pto_retransmitted_datagrams, 0);
    }

    #[test]
    fn duplicate_packet_is_reacked_without_duplicate_stream_delivery() {
        let local = ConnectionId::new(59).unwrap();
        let peer = ConnectionId::new(60).unwrap();
        let mut sender =
            EndpointState::<4, 4, 64>::new(Role::Client, ConnectionLimits::default(), 1200);
        let mut receiver =
            EndpointState::<4, 4, 64>::new(Role::Server, ConnectionLimits::default(), 1200);
        sender.install_connection_ids(local, peer).unwrap();
        receiver.install_connection_ids(peer, local).unwrap();
        sender.open_send_stream(4, INITIAL_MAX_STREAM_DATA).unwrap();
        let mut packet = [0u8; 256];
        let (used, _) = sender
            .encode_stream_packet(peer, 4, 0, true, b"once", &mut packet)
            .unwrap();
        assert!(matches!(
            receiver.receive_datagram(&packet[..used]).unwrap(),
            TransportPacket::Stream { .. }
        ));
        receiver.stream_consumed(4, 4).unwrap();
        let mut ack = [0u8; 256];
        assert!(receiver.poll_transmit(&mut ack).unwrap().is_some());
        assert_eq!(
            receiver.receive_datagram(&packet[..used]).unwrap(),
            TransportPacket::Control
        );
        assert!(receiver.poll_transmit(&mut ack).unwrap().is_some());
    }

    #[test]
    fn selective_ack_accepts_a_delayed_packet_below_largest_received() {
        let local = ConnectionId::new(61).unwrap();
        let peer = ConnectionId::new(62).unwrap();
        let mut sender =
            EndpointState::<4, 4, 64>::new(Role::Client, ConnectionLimits::default(), 1200);
        let mut receiver =
            EndpointState::<4, 4, 64>::new(Role::Server, ConnectionLimits::default(), 1200);
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
            receiver.receive_datagram(&second[..second_len]).unwrap(),
            TransportPacket::Stream { .. }
        ));
        assert!(matches!(
            receiver.receive_datagram(&first[..first_len]).unwrap(),
            TransportPacket::Stream { .. }
        ));
        assert!(receiver.has_received_packet(first_number));
        assert!(receiver.has_received_packet(second_number));
    }

    #[test]
    fn failed_retransmission_keeps_original_ledger_entry() {
        let local = ConnectionId::new(57).unwrap();
        let peer = ConnectionId::new(58).unwrap();
        let mut sender =
            EndpointState::<4, 4, 64>::new(Role::Client, ConnectionLimits::default(), 1200);
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
        let mut sender =
            EndpointState::<4, 4, 64>::new(Role::Client, ConnectionLimits::default(), 1200);
        let mut receiver =
            EndpointState::<4, 4, 64>::new(Role::Server, ConnectionLimits::default(), 1200);
        sender.install_connection_ids(local, peer).unwrap();
        receiver.install_connection_ids(peer, local).unwrap();
        sender.close(0x42);
        let mut packet = [0u8; 128];
        let used = sender.poll_close(&mut packet).unwrap().unwrap();
        let (header, _) = ShortHeader::decode(&packet[..used]).unwrap();
        assert_eq!(header.dcid, peer);
        assert_eq!(header.packet_number, 0);
        assert_eq!(
            receiver.receive_datagram(&packet[..used]),
            Ok(TransportPacket::Control)
        );
        assert_eq!(receiver.close_code(), Some(0x42));
        assert!(receiver.is_closed());
        assert_eq!(
            receiver.receive_datagram(&packet[..used]),
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
        let mut sender =
            EndpointState::<2, 2, 4>::new(Role::Client, ConnectionLimits::default(), 1200);
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
        let mut sender =
            EndpointState::<2, 2, 32>::new(Role::Client, ConnectionLimits::default(), 1200);
        sender.install_connection_ids(cid, peer).unwrap();
        sender.open_send_stream(4, INITIAL_MAX_STREAM_DATA).unwrap();
        sender.set_time(100);
        let mut packet = [0u8; 128];
        let (_, pn) = sender
            .encode_stream_packet(peer, 4, 0, true, b"clock", &mut packet)
            .unwrap();
        sender.set_time(109);
        assert!(sender
            .retransmit_due(109, 10, &mut packet)
            .unwrap()
            .is_none());
        let (_, retransmitted) = sender
            .retransmit_due(110, 10, &mut packet)
            .unwrap()
            .unwrap();
        assert_ne!(pn, retransmitted);
    }

    #[test]
    fn retransmission_probe_survives_reduced_congestion_window() {
        let cid = ConnectionId::new(0x71).unwrap();
        let peer = ConnectionId::new(0x72).unwrap();
        let mut sender =
            EndpointState::<2, 2, 32>::new(Role::Client, ConnectionLimits::default(), 1200);
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
        assert!(sender
            .retransmit_stream_packet(packet_number, &mut packet)
            .unwrap()
            .is_some());
    }

    #[test]
    fn ack_clock_updates_rtt_and_adaptive_pto() {
        let local = ConnectionId::new(55).unwrap();
        let peer = ConnectionId::new(56).unwrap();
        let mut sender =
            EndpointState::<4, 4, 128>::new(Role::Client, ConnectionLimits::default(), 1200);
        let mut receiver =
            EndpointState::<4, 4, 128>::new(Role::Server, ConnectionLimits::default(), 1200);
        sender.install_connection_ids(local, peer).unwrap();
        receiver.install_connection_ids(peer, local).unwrap();
        sender.open_send_stream(4, INITIAL_MAX_STREAM_DATA).unwrap();
        sender.set_time(100);
        let mut packet = [0u8; 256];
        let (used, _) = sender
            .encode_stream_packet(peer, 4, 0, true, b"rtt", &mut packet)
            .unwrap();
        let TransportPacket::Stream { frame, .. } =
            receiver.receive_datagram(&packet[..used]).unwrap()
        else {
            panic!("expected stream");
        };
        receiver
            .stream_consumed(frame.id, frame.data.len())
            .unwrap();
        receiver.set_time(150);
        let mut ack = [0u8; 256];
        let ack_len = receiver.poll_transmit(&mut ack).unwrap().unwrap();
        sender.set_time(150);
        sender.receive_datagram(&ack[..ack_len]).unwrap();
        assert_eq!(sender.latest_rtt(), Some(50));
        assert_eq!(sender.smoothed_rtt(), Some(50));
        assert_eq!(sender.min_rtt(), Some(50));
        assert_eq!(sender.rtt_variance(), 25);
        assert_eq!(sender.pto_timeout(), 150);
    }

    #[test]
    fn fake_fault_link_retransmits_after_latency_and_loss() {
        let local = ConnectionId::new(61).unwrap();
        let peer = ConnectionId::new(62).unwrap();
        let mut sender =
            EndpointState::<4, 4, 128>::new(Role::Client, ConnectionLimits::default(), 1200);
        let mut receiver =
            EndpointState::<4, 8, 128>::new(Role::Server, ConnectionLimits::default(), 1200);
        sender.install_connection_ids(local, peer).unwrap();
        receiver.install_connection_ids(peer, local).unwrap();
        sender.open_send_stream(4, INITIAL_MAX_STREAM_DATA).unwrap();
        sender.open_send_stream(8, INITIAL_MAX_STREAM_DATA).unwrap();
        let mut link = crate::fake::FakeDatagramLink::new(crate::fake::FaultConfig {
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
        link.send(0, &packet[..first_len]);
        let first = link.poll(4);
        assert_eq!(first.len(), 1);
        receiver.receive_datagram(&first[0]).unwrap();
        let (second_len, second_pn) = sender
            .encode_stream_packet(peer, 8, 0, true, b"two", &mut packet)
            .unwrap();
        link.send(4, &packet[..second_len]);
        assert!(link.poll(8).is_empty());
        let (retry_len, retry_pn) = sender
            .retransmit_stream_packet(second_pn, &mut packet)
            .unwrap()
            .unwrap();
        assert_ne!(retry_pn, second_pn);
        link.send(8, &packet[..retry_len]);
        let retry = link.poll(12);
        assert_eq!(retry.len(), 1);
        assert!(matches!(
            receiver.receive_datagram(&retry[0]).unwrap(),
            TransportPacket::Stream { .. }
        ));
        assert_eq!(sender.send.sent_data, 6);
    }

    #[test]
    fn fake_fault_link_retransmits_object_record_stream_bytes() {
        let local = ConnectionId::new(63).unwrap();
        let peer = ConnectionId::new(64).unwrap();
        let mut sender =
            EndpointState::<4, 4, 256>::new(Role::Client, ConnectionLimits::default(), 1200);
        let mut receiver =
            EndpointState::<4, 8, 256>::new(Role::Server, ConnectionLimits::default(), 1200);
        sender.install_connection_ids(local, peer).unwrap();
        receiver.install_connection_ids(peer, local).unwrap();
        sender.open_send_stream(4, INITIAL_MAX_STREAM_DATA).unwrap();
        let object_record = [SERVICE_OBJECT, 0, 0, 0, 3, 0xa1, 0x01, 0x02];
        let mut link = crate::fake::FakeDatagramLink::new(crate::fake::FaultConfig {
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
        link.send(0, &packet[..first_len]);
        for datagram in link.poll(7) {
            receiver.receive_datagram(&datagram).unwrap();
        }
        let (second_len, second_pn) = sender
            .encode_stream_packet(peer, 4, 4, true, &object_record[4..], &mut packet)
            .unwrap();
        link.send(7, &packet[..second_len]);
        assert!(link.poll(14).is_empty());
        let (retry_len, retry_pn) = sender
            .retransmit_stream_packet(second_pn, &mut packet)
            .unwrap()
            .unwrap();
        assert_ne!(retry_pn, second_pn);
        link.send(14, &packet[..retry_len]);
        let mut delivered = 0;
        for datagram in link.poll(21) {
            if let TransportPacket::Stream { frame, .. } =
                receiver.receive_datagram(&datagram).unwrap()
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
            let mut sender =
                EndpointState::<512, H, 64>::new(Role::Client, ConnectionLimits::default(), 1200);
            let mut receiver =
                EndpointState::<512, 8, 64>::new(Role::Server, ConnectionLimits::default(), 1200);
            sender.congestion.congestion_window = (H as u64).saturating_mul(1200);
            sender.congestion.slow_start_threshold = sender.congestion.congestion_window;
            sender.install_connection_ids(local, peer).unwrap();
            receiver.install_connection_ids(peer, local).unwrap();
            sender.open_send_stream(4, INITIAL_MAX_STREAM_DATA).unwrap();
            let mut link = crate::fake::FakeDatagramLink::new(crate::fake::FaultConfig {
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
                    link.send(now, &packet[..used + frame_len]);
                    packet_numbers.push(packet_number);
                    offset += data.len() as u64;
                    assert!(sender.history_len() <= H);
                    assert!(
                        sender.history_len() * sender.retransmission_payload_capacity() <= H * 64
                    );
                }
                assert_eq!(sender.history_len(), H);
                now += 10;
                for datagram in link.poll(now) {
                    if let TransportPacket::Stream { frame, .. } =
                        receiver.receive_datagram(&datagram).unwrap()
                    {
                        receiver
                            .stream_consumed(frame.id, frame.data.len())
                            .unwrap();
                        let mut ack = [0u8; 256];
                        if let Some(used) = receiver.poll_transmit(&mut ack).unwrap() {
                            sender.receive_datagram(&ack[..used]).unwrap();
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
                        if let TransportPacket::Stream { frame, .. } =
                            receiver.receive_datagram(&retry[..used]).unwrap()
                        {
                            receiver
                                .stream_consumed(frame.id, frame.data.len())
                                .unwrap();
                            let mut ack = [0u8; 256];
                            if let Some(ack_len) = receiver.poll_transmit(&mut ack).unwrap() {
                                sender.receive_datagram(&ack[..ack_len]).unwrap();
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
    fn product_retransmission_profiles_report_real_memory_bounds() {
        use core::mem::size_of;

        // Host/std ledgers are heap-backed, so their struct size is constant;
        // verify the selected runtime capacities instead of comparing the
        // Vec container size with embedded array profiles.
        assert!(size_of::<RecoveryEndpoint<2>>() > 0);
        assert!(size_of::<Esp32Endpoint<8>>() > 0);
        assert_eq!(
            RecoveryEndpoint::<2>::new(Role::Client, ConnectionLimits::default(), 1200)
                .retransmission_capacity_bytes(),
            4 * 256
        );
        assert_eq!(
            Esp32Endpoint::<8>::new(Role::Client, ConnectionLimits::default(), 1200)
                .retransmission_capacity_bytes(),
            4 * 512
        );
        assert_eq!(
            HostEndpoint::<8>::new(Role::Client, ConnectionLimits::default(), 1200)
                .retransmission_capacity_bytes(),
            512 * DEFAULT_MAX_DATAGRAM_SIZE
        );

        fn stress<const H: usize, const P: usize>() {
            let local = ConnectionId::new(0x900 + H as u64).unwrap();
            let peer = ConnectionId::new(0xa00 + H as u64).unwrap();
            let mut limits = ConnectionLimits::default();
            limits.max_data = 4 * 1024 * 1024;
            limits.max_stream_data = 2 * 1024 * 1024;
            let mut sender = EndpointState::<512, H, P>::new(Role::Client, limits, 1200);
            let mut receiver = EndpointState::<512, 8, P>::new(Role::Server, limits, 1200);
            sender.install_connection_ids(local, peer).unwrap();
            receiver.install_connection_ids(peer, local).unwrap();
            sender.open_send_stream(4, limits.max_stream_data).unwrap();
            sender.congestion.congestion_window = (H as u64).saturating_mul(1500);
            sender.congestion.slow_start_threshold = sender.congestion.congestion_window;
            let mut link = crate::fake::FakeDatagramLink::new(crate::fake::FaultConfig {
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
                link.send(0, &packet[..used]);
                packet_numbers.push(number);
                assert!(sender.retained_payload_bytes() <= sender.retransmission_capacity_bytes());
            }
            for datagram in link.poll(25) {
                if let TransportPacket::Stream { frame, .. } =
                    receiver.receive_datagram(&datagram).unwrap()
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
        let mut sender = EndpointState::<4, 4>::new_established(
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
        let mut receiver = EndpointState::<4, 4>::new_established(
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
        receiver.receive_datagram(&packet[..used]).unwrap();
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
        let mut sender = EndpointState::<4, 4>::new_established(
            Role::Client,
            ConnectionLimits::default(),
            1200,
            ConnectionIds::new(client, server).unwrap(),
        );
        let mut receiver = EndpointState::<4, 4>::new_established(
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
            receiver.receive_datagram(&probe[..used]),
            Ok(TransportPacket::Control)
        ));
        let mut ack = [0u8; 64];
        let ack_len = receiver.poll_transmit(&mut ack).unwrap().unwrap();
        assert!(sender.receive_datagram(&ack[..ack_len]).is_ok());
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
        let mut endpoint =
            EndpointState::<4, 4>::new(Role::Client, ConnectionLimits::default(), 1200);
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
        let mut sender = EndpointState::<2>::new(Role::Server, limits, 64);
        let mut receiver = EndpointState::<2>::new(Role::Client, limits, 64);
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
    fn bearer_envelope_round_trips_without_object_store_dependency() {
        let key = PeerKey {
            wifi_mac: [1, 2, 3, 4, 5, 6],
            dcid: ConnectionId::new(0x1234).unwrap(),
        };
        let mut out = [0u8; 64];
        let used = encode_envelope(key, 9, b"payload", &mut out).unwrap();
        let (decoded, kind, payload) = decode_envelope(&out[..used]).unwrap();
        assert_eq!(decoded, key);
        assert_eq!(kind, 9);
        assert_eq!(payload, b"payload");
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
        let mtu = 1200usize;
        let dcid = ConnectionId::new(1).unwrap();
        let mut sender =
            EndpointState::<2>::new(Role::Server, ConnectionLimits::default(), mtu as u64);
        let mut receiver =
            EndpointState::<2>::new(Role::Client, ConnectionLimits::default(), mtu as u64);
        sender.open_send_stream(3, INITIAL_MAX_STREAM_DATA).unwrap();

        struct Flight {
            packet_number: u32,
            offset: u64,
            data: Vec<u8>,
            packet: Vec<u8>,
            packet_len: u64,
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
                    Err(_) => break,
                };
                packet.truncate(used);
                flights.push_back(Flight {
                    packet_number,
                    offset: next_offset,
                    data,
                    packet: packet.clone(),
                    packet_len: used as u64,
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
                let (header, header_len) = ShortHeader::decode(&flight.packet).unwrap();
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
                receiver.observe_packet(header.packet_number);
                received.insert(header.packet_number);
                segments.entry(stream.offset).or_insert(stream.data.len());
            }

            while let Some(len) = segments.remove(&contiguous) {
                contiguous += len as u64;
                receiver.receive.consume(3, len as u64).unwrap();
            }
            receiver.receive.extend_connection_credit(INITIAL_MAX_DATA);
            receiver
                .receive
                .extend_stream_credit(3, INITIAL_MAX_STREAM_DATA)
                .unwrap();
            sender
                .send
                .extend_connection(receiver.receive.connection.consumed + INITIAL_MAX_DATA);
            sender
                .send
                .extend_stream(3, receiver.receive.stream_max_data(3).unwrap())
                .unwrap();

            for flight in flights.iter_mut().filter(|flight| !flight.acked) {
                if received.contains(flight.packet_number) {
                    flight.acked = true;
                    sender.acked(flight.packet_len);
                }
            }
            let has_later_ack = flights.iter().any(|flight| flight.acked);
            let mut resend = Vec::new();
            for flight in flights
                .iter_mut()
                .filter(|flight| !flight.acked && !flight.lost)
            {
                if has_later_ack {
                    flight.lost = true;
                    sender.lost(flight.packet_len);
                    resend.push((flight.offset, flight.data.clone()));
                }
            }
            let had_resend = !resend.is_empty();
            for (offset, data) in resend {
                let mut packet = vec![0u8; mtu];
                let (used, packet_number) = sender
                    .encode_stream_packet(
                        dcid,
                        3,
                        offset,
                        offset + data.len() as u64 == total,
                        &data,
                        &mut packet,
                    )
                    .unwrap();
                packet.truncate(used);
                flights.push_back(Flight {
                    packet_number,
                    offset,
                    data,
                    packet,
                    packet_len: used as u64,
                    acked: false,
                    lost: false,
                });
                packet_count += 1;
                retransmits += 1;
            }
            flights.retain(|flight| !flight.acked && !flight.lost);
            assert!(sent_this_round != 0 || had_resend || contiguous == total);
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
        let mut endpoint = EndpointState::<2, 4, 256>::new(Role::Client, limits, 256);
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
}
