//! The contract between packet bearers and QUIC-lite.
//!
//! A bearer moves opaque QUIC packets over UART, BLE, UDP, or another link. It
//! parses and removes its own link, network, transport, and framing envelope,
//! but does not inspect or classify the QUIC packet inside that envelope.
//! QUIC-lite owns packet protection because its keys are associated with the
//! connection ID.
//!
//! # Receive
//!
//! Send and receive use the packet pool owned by [`QuicNode`](crate::QuicNode).
//! QUIC-lite gives a receiver
//! a writable region and an offset at which to start reading. The offset leaves
//! the common outbound-prefix reserve before the eventual QUIC packet even for
//! a bearer, such as native ESP-NOW, whose received envelope has no prefix.
//!
//! A bearer reads one complete frame, parses its entire envelope, and validates
//! its lengths. The envelope is not assumed to be fixed: an Ethernet receiver,
//! for example, selects the network protocol from the EtherType and accounts for
//! the actual IPv4 header length, IPv6 extension headers, and UDP header. It then
//! constructs an [`OwnedPacket`] whose range is exactly the QUIC packet within
//! the pool slot. That range is the receive offset delivered to QUIC; link and
//! radio metadata must not be included in it.
//!
//! The resulting range must retain at least the common outbound-prefix reserve
//! before its start. Bytes before the range cease to be received-frame data and
//! are reusable headroom. A relay can therefore keep the same pool lease,
//! rewrite those bytes with a different bearer's envelope, and send the packet
//! without allocating or moving the QUIC bytes. The pool layout and receive
//! start offset must cover the largest accepted variable envelope. A frame that
//! cannot preserve the required headroom and tailroom is dropped; it is not
//! copied into a larger bearer-owned buffer.
//!
//! The bearer transfers the packet, an opaque [`PeerL2Address`], and monotonic
//! receive time through [`BearerContext::enqueue_packet`]. This transfers
//! ownership to the fixed-capacity QUIC ingress queue without waiting. A full queue
//! drops the packet; transport loss recovery handles retransmission. ESP
//! receive callbacks and host read tasks use the same entry point. QUIC retains
//! the registered [`BearerId`] and [`PeerL2Address`] as one return address only
//! after accepting the packet; equal address values on different bearers remain
//! distinct.
//!
//! # Packet storage and memory ownership
//!
//! [`QuicNode`](crate::QuicNode) owns the packet pool used by receive, send,
//! forwarding, retransmission, and send completion. A bearer must not own a
//! separate packet pool, allocate replacement packet buffers, or add a private
//! packet queue. This rule applies to host bearers as well as embedded bearers.
//! Hidden storage would prevent QUIC-lite from measuring packet memory pressure
//! and applying one memory limit to the whole node.
//!
//! Receive code borrows a [`PacketWriter`] from the node-owned pool, fills the
//! provided storage, commits it, and transfers the resulting [`OwnedPacket`] to
//! [`BearerContext::enqueue_packet`]. If no writer is available, the bearer drops the incoming
//! packet immediately. It must not allocate a fallback buffer or wait for pool
//! space; QUIC loss recovery handles the dropped packet.
//!
//! The pool's configured limit and current use are QUIC state, not bearer or
//! application state. QUIC-lite uses them when advertising and adjusting
//! connection and stream receive windows, so peer-visible flow control tracks
//! the memory actually available for packets. Capacity policy may differ by
//! device and may grow or shrink at runtime. Bearers therefore must handle
//! [`PacketPool::acquire_writer`] returning `None` without assuming a fixed
//! capacity or exposing the concrete pool to their users.
//!
//! # Registry
//!
//! One QUIC owner has one private bearer registry containing interfaces such as
//! `wlan0`, `eth0`, `uart0`, and `ble0`. A [`BearerId`] identifies the interface;
//! a [`PeerL2Address`] identifies an endpoint reached through it. Each
//! registration holds its description, security and buffer requirements,
//! nominal and measured rates, common counters, current reported state, and
//! send callback.
//!
//! The registry is descriptive and observational. It does not decide routing,
//! enforce readiness, or buffer packets. QUIC uses its state to choose a bearer;
//! the send callback remains authoritative and returns `WouldBlock` if physical
//! capacity changed after selection.
//!
//! # Send
//!
//! QUIC selects a ready peer L2 address and transfers one [`OwnedPacket`] to its
//! registered [`PacketEgress::submit`] callback. Its range initially covers
//! only the protected QUIC packet. After accepting ownership, the bearer may
//! prepend its envelope in the retained headroom and use the retained tailroom.
//! A packet stays owned by the bearer until send completion. The bearer consumes
//! its [`EgressSubmission`] to report completion, returning the exact packet
//! lease through [`PacketCompletionToken::complete`]. A busy bearer returns
//! the unchanged submission immediately so another sender can be selected.
//! `send_ready` is reserved for capacity returning after a zero-byte
//! `WouldBlock`; it is not completion. A byte-stream bearer may retain one
//! partially written packet, but it must not queue later packets. Once it
//! consumes any byte, the submission must never be returned or moved to another
//! bearer.

use alloc::{boxed::Box, sync::Arc};
use core::{fmt, ops::Range};

/// Exclusive construction access to one slot owned by a QUIC node's packet pool.
///
/// QUIC serializers write directly into `payload_mut` and commit exactly the
/// initialized packet bytes. Dropping an uncommitted writer returns its slot
/// to the pool. The resulting buffer lease remains owned by the same pool as
/// it moves through ingress, connection processing, egress, and completion.
pub trait PacketWriter: Sized {
    /// Pool-owned lease produced after a successful commit.
    type Buffer: AsRef<[u8]>;

    /// Writable packet region after the requested bearer headroom.
    fn payload_mut(&mut self) -> &mut [u8];

    /// Commit exactly `len` initialized bytes into a packet lease.
    fn commit(self, len: usize) -> Option<OwnedPacket<Self::Buffer>>;
}

/// Node-owned source of packet leases shared by every ingress and egress bearer.
///
/// A pool is owned for the node's lifetime, not by a bearer and not as a bearer
/// queue. Bearer implementations receive access to it from QUIC-lite; they must
/// not construct another pool or allocate fallback packet storage. Its current
/// capacity may differ between devices and may change while the device is
/// running; the associated writer and buffer types define how storage is
/// retained across a resize. `reserved` atomically leaves slots available for
/// replies or other higher-priority output.
pub trait PacketPool {
    /// Lease retained from construction through physical send completion.
    type Buffer: AsRef<[u8]>;
    /// Exclusive writer used to initialize one lease without an extra copy.
    type Writer: PacketWriter<Buffer = Self::Buffer>;

    /// Acquire a slot with `headroom`, leaving `reserved` slots available.
    fn acquire_writer(&'static self, headroom: usize, reserved: usize) -> Option<Self::Writer>;

    /// Currently active slots, which need not equal a compile-time maximum.
    fn capacity(&self) -> usize;

    /// Slots currently free for ingress or egress acquisition.
    fn available(&self) -> usize;

    /// Acquire a slot, serialize one QUIC packet directly into it, and return
    /// the pool-owned packet. No intermediate packet array is created.
    fn build_packet<E>(
        &'static self,
        headroom: usize,
        reserved: usize,
        serialize: impl FnOnce(&mut [u8]) -> Result<usize, E>,
    ) -> Result<OwnedPacket<Self::Buffer>, PacketBuildError<E>> {
        let mut writer = self
            .acquire_writer(headroom, reserved)
            .ok_or(PacketBuildError::Unavailable)?;
        let len = serialize(writer.payload_mut()).map_err(PacketBuildError::Serialize)?;
        writer.commit(len).ok_or(PacketBuildError::InvalidLength)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Failure while constructing a packet directly in a node-owned lease.
///
/// This is public so pool implementations can use the common construction
/// helper without exposing their concrete writer representation.
pub enum PacketBuildError<E> {
    /// No slot satisfying the requested reserve is free.
    Unavailable,
    /// The QUIC serializer returned its own error.
    Serialize(E),
    /// The reported serialized length cannot be committed.
    InvalidLength,
}

/// Stable handle for one registered bearer, such as `wlan0`, `uart0`, or
/// `ble0`, during the lifetime of a QUIC owner.
///
/// A bearer can carry many [`PeerL2Address`] values. The bearer ID selects the
/// interface and its send callback; the peer L2 address selects the endpoint to
/// which that callback sends a particular packet.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct BearerId(u16);

impl BearerId {
    /// Construct a nonzero bearer handle; zero is reserved as invalid.
    pub const fn new(value: u16) -> Option<Self> {
        if value == 0 { None } else { Some(Self(value)) }
    }

    /// Return the compact numeric handle stored in packet metadata.
    pub const fn value(self) -> u16 {
        self.0
    }
}

/// Short, allocation-free interface name used in status and configuration.
///
/// This is the logical interface name (`wlan0`, `eth0`, `uart0`), not a peer
/// identity, device path, or circuit path.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BearerName {
    bytes: [u8; 16],
    len: u8,
}

impl BearerName {
    /// Construct a short allocation-free name, rejecting invalid lengths.
    pub fn new(name: &str) -> Option<Self> {
        if name.is_empty() || name.len() > 16 || !name.is_ascii() {
            return None;
        }
        let mut bytes = [0; 16];
        bytes[..name.len()].copy_from_slice(name.as_bytes());
        Some(Self {
            bytes,
            len: name.len() as u8,
        })
    }

    /// Borrow the configured UTF-8 name.
    pub fn as_str(&self) -> &str {
        // Construction accepts ASCII only.
        core::str::from_utf8(&self.bytes[..self.len as usize]).expect("ASCII bearer name")
    }
}

impl fmt::Debug for BearerName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("BearerName")
            .field(&self.as_str())
            .finish()
    }
}

/// Bearer capabilities, policy, and current configured properties.
///
/// Packet encryption policy and link encryption are separate. For example,
/// Wi-Fi may set `requires_packet_encryption` even when WPA protects one hop;
/// BLE may report `secure_link` for an encrypted CoC peer and UART may report
/// it for a physically trusted connection even though UART is not encrypted.
/// Policy may then omit QUIC packet encryption on that path. Authentication
/// and encryption decisions remain in QUIC-lite; the driver never encrypts a
/// QUIC packet itself.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BearerInfo {
    /// Stable name used for registration and diagnostics.
    pub name: BearerName,
    /// Largest QUIC packet this bearer can carry, excluding its envelope.
    pub max_packet_size: usize,
    /// Largest envelope this bearer may prepend without moving QUIC bytes.
    pub prefix_required: usize,
    /// Largest trailer this bearer may append after the protected packet.
    pub suffix_required: usize,
    /// Require QUIC-lite packet encryption on this bearer.
    pub requires_packet_encryption: bool,
    /// Every peer path exposed by this bearer is trusted against interception
    /// or injection, through encryption or physical protection. A bearer with
    /// mixed per-peer security must leave this false until encryption policy
    /// can consume authenticated per-path metadata.
    pub secure_link: bool,
    /// Configured or negotiated physical rate. Zero means unknown or variable.
    pub nominal_bitrate_bps: u64,
    /// Local hardware address when the bearer has one.
    pub local_mac: Option<[u8; 6]>,
}

/// QUIC-owned per-bearer counters.
///
/// Bearer implementations report events to this registry instead of maintaining parallel
/// UART, BLE, Wi-Fi, and UDP counter sets. Connection loss, retransmission,
/// congestion, and flow-control counters remain connection state and are not
/// duplicated here.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct BearerStats {
    pub received_packets: u64,
    pub received_bytes: u64,
    pub ingress_drops: u64,
    pub submitted_packets: u64,
    pub submitted_bytes: u64,
    pub completed_packets: u64,
    pub completed_bytes: u64,
    pub send_would_block: u64,
    pub send_failures: u64,
}

/// Changing state for one registered bearer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct BearerState {
    /// Disabled bearers are not eligible for new sends or receives.
    pub enabled: bool,
    /// The driver's last report says it can atomically accept a packet now.
    pub ready: bool,
    /// Packets accepted by the callback and not yet reported complete.
    pub in_flight_packets: usize,
    /// Smoothed completion rate measured by the registry. Zero means unknown.
    pub measured_bitrate_bps: u64,
}

impl BearerState {
    pub(crate) const fn new() -> Self {
        Self {
            enabled: false,
            ready: false,
            in_flight_packets: 0,
            measured_bitrate_bps: 0,
        }
    }
}

/// Opaque handle for a directly reachable peer endpoint, scoped to one bearer.
///
/// This is neither a circuit path nor a peer identity. The bearer owns its
/// mapping to a UDP socket peer, radio peer, UART endpoint, or similar state.
/// "L2" means the immediate bearer hop; the value need not encode a MAC address
/// and has meaning only together with the [`BearerId`] that allocated it.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct PeerL2Address(u64);

impl PeerL2Address {
    /// Construct a nonzero bearer-local peer handle.
    pub const fn new(value: u64) -> Option<Self> {
        if value == 0 { None } else { Some(Self(value)) }
    }

    /// Return the bearer-local numeric peer handle.
    pub const fn value(self) -> u64 {
        self.0
    }
}

/// Metadata supplied with one received opaque QUIC packet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PacketMeta {
    /// Registered bearer on which this packet arrived.
    pub bearer: BearerId,
    /// Bearer-assigned peer endpoint handle.
    pub peer_l2_address: PeerL2Address,
    /// Monotonic receive time in microseconds.
    pub received_at_us: u64,
}

/// An owned received QUIC packet waiting for processing.
#[derive(Debug)]
pub(crate) struct ReceivedPacket<B> {
    pub meta: PacketMeta,
    pub packet: OwnedPacket<B>,
}

/// Queue one received packet for its QUIC owner.
pub(crate) trait PacketIngress<B: AsRef<[u8]>> {
    /// Transfer the packet to the bounded QUIC ingress queue without waiting.
    ///
    /// This method must not allocate, inspect packet bytes, or run QUIC. A full
    /// queue drops the packet and releases its buffer.
    fn enqueue_packet(&self, meta: PacketMeta, packet: OwnedPacket<B>);
}

/// Nonblocking receive destination supplied to an attached bearer.
///
/// This deliberately exposes only enqueueing. A bearer cannot invoke QUIC
/// parsing directly, borrow node state, or create a competing receive loop.
pub(crate) trait PacketIngressQueue<B>: Send + Sync {
    fn enqueue_packet(&self, meta: PacketMeta, packet: OwnedPacket<B>);
}

/// Resources assigned by a [`QuicNode`](crate::QuicNode) to one bearer.
///
/// The bearer uses the node-owned pool for receive storage and transfers every
/// completed inbound packet to `ingress`. It retains this context for its
/// lifetime; it must not create another pool or ingress queue.
pub struct BearerContext<P: PacketPool + 'static> {
    bearer: BearerId,
    pool: &'static P,
    ingress: Arc<dyn PacketIngressQueue<P::Buffer>>,
    events: Arc<dyn PacketEgressEvents<P::Buffer>>,
}

impl<P: PacketPool + 'static> Clone for BearerContext<P> {
    fn clone(&self) -> Self {
        Self {
            bearer: self.bearer,
            pool: self.pool,
            ingress: self.ingress.clone(),
            events: self.events.clone(),
        }
    }
}

impl<P: PacketPool + 'static> BearerContext<P> {
    pub(crate) fn new(
        bearer: BearerId,
        pool: &'static P,
        ingress: Arc<dyn PacketIngressQueue<P::Buffer>>,
        events: Arc<dyn PacketEgressEvents<P::Buffer>>,
    ) -> Self {
        Self {
            bearer,
            pool,
            ingress,
            events,
        }
    }

    /// Handle assigned to this bearer by the node.
    pub const fn bearer(&self) -> BearerId {
        self.bearer
    }

    /// Borrow the node-owned pool for receive packet acquisition.
    pub const fn pool(&self) -> &'static P {
        self.pool
    }

    /// Transfer a complete received packet into the node ingress queue.
    ///
    /// The packet must originate from [`Self::pool`]. A full fixed-capacity
    /// ingress queue drops it and releases the lease without blocking.
    pub fn enqueue_packet(&self, meta: PacketMeta, packet: OwnedPacket<P::Buffer>) {
        debug_assert_eq!(meta.bearer, self.bearer);
        self.ingress.enqueue_packet(meta, packet);
    }

    /// Report that a bearer which previously returned `WouldBlock` can accept
    /// another packet. Physical send completion uses `EgressSubmission`.
    pub fn send_ready(&self) {
        self.events.send_ready(self.bearer);
    }
}

impl<P: PacketPool + 'static> PacketIngress<P::Buffer> for BearerContext<P> {
    fn enqueue_packet(&self, meta: PacketMeta, packet: OwnedPacket<P::Buffer>) {
        BearerContext::enqueue_packet(self, meta, packet);
    }
}

/// Completion callback from a registered sender to QUIC.
pub(crate) trait PacketEgressEvents<B>: Send + Sync {
    /// Return an accepted packet lease and report physical send completion.
    ///
    /// Implementations normally enqueue this event for the QUIC owner. They
    /// must not call a mutably borrowed registry reentrantly from `submit`.
    fn send_completed(&self, completion: PacketSendCompletion<B>);

    /// Report capacity after a zero-byte `WouldBlock` result.
    fn send_ready(&self, bearer: BearerId);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Terminal physical-send result paired with a returned packet lease.
///
/// Bearers report this publicly because completion may happen asynchronously;
/// QUIC-lite, not the bearer, interprets it as path state.
pub enum PacketSendOutcome {
    /// The complete packet reached the physical transport.
    Sent,
    /// The transport failed after accepting ownership.
    Failed,
}

/// Ownership-bearing physical-send completion delivered to the QUIC owner.
pub(crate) struct PacketSendCompletion<B> {
    pub bearer: BearerId,
    pub packet: OwnedPacket<B>,
    pub outcome: PacketSendOutcome,
    pub elapsed_us: u64,
}

/// Single-use completion callback paired with one submitted packet.
///
/// This is public so asynchronous bearer implementations can return the exact
/// lease. Its private fields prevent callers from fabricating completions.
pub struct PacketCompletionToken<B> {
    bearer: BearerId,
    events: Arc<dyn PacketEgressEvents<B>>,
}

impl<B> fmt::Debug for PacketCompletionToken<B> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PacketCompletionToken")
            .field("bearer", &self.bearer)
            .finish_non_exhaustive()
    }
}

impl<B> PacketCompletionToken<B> {
    /// Return the exact packet lease after the physical send finishes.
    pub fn complete(self, packet: OwnedPacket<B>, outcome: PacketSendOutcome, elapsed_us: u64) {
        self.events.send_completed(PacketSendCompletion {
            bearer: self.bearer,
            packet,
            outcome,
            elapsed_us,
        });
    }
}

/// One packet plus the callback that must return its lease on completion.
pub struct EgressSubmission<B> {
    packet: OwnedPacket<B>,
    completion: PacketCompletionToken<B>,
}

impl<B: AsRef<[u8]>> fmt::Debug for EgressSubmission<B> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EgressSubmission")
            .field("bearer", &self.completion.bearer)
            .field("bytes", &self.packet.bytes().len())
            .finish()
    }
}

impl<B: AsRef<[u8]>> EgressSubmission<B> {
    pub(crate) fn new(
        bearer: BearerId,
        packet: OwnedPacket<B>,
        events: Arc<dyn PacketEgressEvents<B>>,
    ) -> Self {
        Self {
            packet,
            completion: PacketCompletionToken { bearer, events },
        }
    }

    /// Borrow the complete opaque packet presented to the bearer.
    pub fn packet(&self) -> &OwnedPacket<B> {
        &self.packet
    }

    /// Complete a synchronous physical send and return the lease to the node.
    pub fn complete(self, outcome: PacketSendOutcome, elapsed_us: u64) {
        self.completion.complete(self.packet, outcome, elapsed_us);
    }

    /// Split an accepted submission for asynchronous writing.
    ///
    /// The bearer must later return this same packet through the token.
    pub fn into_parts(self) -> (OwnedPacket<B>, PacketCompletionToken<B>) {
        (self.packet, self.completion)
    }
}

/// One complete QUIC packet and ownership of its backing buffer.
///
/// `B::as_ref()` must expose the entire pool slot, including unused prefix and
/// suffix space. A lease type whose `AsRef` exposes only its current active
/// bytes must be adapted before it is used here; otherwise the range and relay
/// capacity would be lost at the ingress boundary.
///
/// `range` identifies only the QUIC bytes. It deliberately does not identify
/// the whole received Ethernet, Wi-Fi, ESP-NOW, BLE, or UART frame. Bytes before
/// the range are available as outbound framing headroom and bytes after it are
/// available as authentication or framing tailroom. This lets a relay retain
/// the lease and replace one bearer envelope with another without moving the
/// QUIC packet.
///
/// The QUIC owner defines the required common headroom. A receiving bearer must
/// arrange its read offset and parse result so [`Self::prefix_capacity`] is at
/// least that requirement, including when its native callback supplies only a
/// payload body. Variable headers change the range start; they do not change
/// which bytes are exposed by [`Self::bytes`].
#[derive(Debug)]
pub struct OwnedPacket<B> {
    buffer: B,
    range: Range<usize>,
}

impl<B: AsRef<[u8]>> OwnedPacket<B> {
    /// Wrap a pool slot and select the exact QUIC packet within it.
    ///
    /// Receiving bearers obtain this range by parsing their complete envelope.
    /// `range.start` is also the headroom available if this lease is relayed.
    pub fn new(buffer: B, range: Range<usize>) -> Result<Self, B> {
        if range.start <= range.end && range.end <= buffer.as_ref().len() {
            Ok(Self { buffer, range })
        } else {
            Err(buffer)
        }
    }

    /// Treat the entire backing buffer as a QUIC packet.
    ///
    /// This has no prefix or suffix capacity. Production pooled receive paths
    /// that may be relayed should use [`Self::new`] with the pool-defined QUIC
    /// offset instead.
    pub(crate) fn from_buffer(buffer: B) -> Self {
        let len = buffer.as_ref().len();
        Self {
            buffer,
            range: 0..len,
        }
    }

    /// Borrow the complete opaque packet bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.buffer.as_ref()[self.range.clone()]
    }

    /// Location of the QUIC packet in the backing buffer.
    pub fn packet_range(&self) -> Range<usize> {
        self.range.clone()
    }

    /// Bytes available before the QUIC packet for an outbound bearer envelope.
    pub fn prefix_capacity(&self) -> usize {
        self.range.start
    }

    /// Bytes available after the QUIC packet for authentication or framing.
    pub fn suffix_capacity(&self) -> usize {
        self.buffer.as_ref().len() - self.range.end
    }

    /// Split the packet into its complete pool slot and exact QUIC range.
    ///
    /// A bearer calls this only after it has accepted ownership. It may then
    /// replace bytes outside the range with its envelope and adjust the range
    /// to the submitted frame. A bearer that may return `WouldBlock` must keep
    /// the `OwnedPacket` intact instead.
    pub fn into_parts(self) -> (B, Range<usize>) {
        (self.buffer, self.range)
    }

    /// Return the complete backing buffer, discarding the QUIC range metadata.
    pub fn into_buffer(self) -> B {
        self.buffer
    }
}

impl<B: AsRef<[u8]>> AsRef<[u8]> for OwnedPacket<B> {
    fn as_ref(&self) -> &[u8] {
        self.bytes()
    }
}

/// A bearer temporarily rejected a packet without taking ownership of it.
///
/// Terminal physical failures happen only after ownership transfers and are
/// reported through [`PacketSendOutcome::Failed`], which returns the lease by
/// the same completion path as a successful send.
#[derive(Debug)]
pub enum PacketSubmitError<B: AsRef<[u8]>> {
    /// The sender is temporarily full and consumed no bytes.
    WouldBlock(EgressSubmission<B>),
}

pub(crate) struct CompletionQueue<B> {
    completions: spin::Mutex<alloc::collections::VecDeque<PacketSendCompletion<B>>>,
    ready: spin::Mutex<alloc::collections::VecDeque<BearerId>>,
    #[cfg(feature = "tokio")]
    changed: ::tokio::sync::Notify,
    #[cfg(feature = "tokio")]
    poll_waker: spin::Mutex<Option<core::task::Waker>>,
}

impl<B> CompletionQueue<B> {
    pub(crate) fn new(capacity: usize) -> Self {
        assert!(capacity != 0, "completion queue capacity must be nonzero");
        Self {
            completions: spin::Mutex::new(alloc::collections::VecDeque::with_capacity(capacity)),
            ready: spin::Mutex::new(alloc::collections::VecDeque::with_capacity(capacity)),
            #[cfg(feature = "tokio")]
            changed: ::tokio::sync::Notify::new(),
            #[cfg(feature = "tokio")]
            poll_waker: spin::Mutex::new(None),
        }
    }

    pub(crate) fn pop_completion(&self) -> Option<PacketSendCompletion<B>> {
        self.completions.lock().pop_front()
    }

    pub(crate) fn pop_ready(&self) -> Option<BearerId> {
        self.ready.lock().pop_front()
    }

    #[cfg(feature = "tokio")]
    pub(crate) async fn changed(&self) {
        self.changed.notified().await;
    }

    #[cfg(feature = "tokio")]
    pub(crate) fn register_waker(&self, waker: &core::task::Waker) {
        *self.poll_waker.lock() = Some(waker.clone());
    }

    #[cfg(feature = "tokio")]
    fn wake_poller(&self) {
        if let Some(waker) = self.poll_waker.lock().take() {
            waker.wake();
        }
    }
}

impl<B: Send> PacketEgressEvents<B> for CompletionQueue<B> {
    fn send_completed(&self, completion: PacketSendCompletion<B>) {
        let mut queue = self.completions.lock();
        assert!(
            queue.len() < queue.capacity(),
            "completion queue invariant violated"
        );
        queue.push_back(completion);
        #[cfg(feature = "tokio")]
        self.changed.notify_one();
        #[cfg(feature = "tokio")]
        self.wake_poller();
    }

    fn send_ready(&self, bearer: BearerId) {
        let mut queue = self.ready.lock();
        assert!(
            queue.len() < queue.capacity(),
            "ready queue invariant violated"
        );
        queue.push_back(bearer);
        #[cfg(feature = "tokio")]
        self.changed.notify_one();
        #[cfg(feature = "tokio")]
        self.wake_poller();
    }
}

/// Callback used to transfer one complete packet to a bearer.
///
/// `Ok(())` transfers ownership to the bearer. It must retain a partially
/// written submission until the complete packet is written or the link fails
/// terminally. It must never return a partially written submission. Completion
/// consumes the submission and delivers its lease through the embedded callback.
/// `WouldBlock` is valid only before any byte is consumed and returns the
/// unchanged submission. Every other result, including a terminal physical
/// error discovered immediately, accepts ownership and reports completion.
pub trait PacketEgress<B: AsRef<[u8]>> {
    /// Try to transfer one whole packet without blocking the node.
    fn submit(
        &mut self,
        peer_l2_address: PeerL2Address,
        submission: EgressSubmission<B>,
    ) -> Result<(), PacketSubmitError<B>>;
}

/// Complete physical packet bearer owned by one QUIC node.
///
/// `PacketEgress` is the synchronous, nonblocking send half. `attach` installs
/// the receive half and its readiness notification path exactly once. Tokio
/// implementations normally spawn or wake their socket/serial read task from
/// `attach`; RTOS implementations retain the context for their task or ISR
/// handoff. Both directions use the node-owned pool in the supplied context.
pub trait PacketBearer<P>: PacketEgress<P::Buffer>
where
    P: PacketPool + 'static,
{
    /// Error produced while installing the receive/readiness path.
    type AttachError;

    /// Describe packet sizing, framing reserve, and physical link properties.
    fn info(&self) -> BearerInfo;

    /// Attach this bearer exactly once to the owning node context.
    fn attach(&mut self, context: BearerContext<P>) -> Result<(), Self::AttachError>;
}

impl<B, F> PacketEgress<B> for F
where
    B: AsRef<[u8]>,
    F: FnMut(PeerL2Address, EgressSubmission<B>) -> Result<(), PacketSubmitError<B>>,
{
    fn submit(
        &mut self,
        peer_l2_address: PeerL2Address,
        submission: EgressSubmission<B>,
    ) -> Result<(), PacketSubmitError<B>> {
        self(peer_l2_address, submission)
    }
}

/// One bearer registered with the QUIC owner.
///
/// This is the single owner of reported bearer readiness, physical-rate
/// measurement, and bearer counters. It records callback results but does not
/// impose scheduling policy or reject a submission itself. QUIC selects among
/// bearers using the reported state; the callback remains authoritative and
/// returns `WouldBlock` without changing a packet when it cannot accept it.
pub(crate) struct RegisteredBearer<B: AsRef<[u8]>> {
    id: BearerId,
    info: BearerInfo,
    state: BearerState,
    stats: BearerStats,
    egress: Box<dyn PacketEgress<B>>,
    events: Arc<dyn PacketEgressEvents<B>>,
    pending: Option<(PeerL2Address, EgressSubmission<B>)>,
}

impl<B: AsRef<[u8]>> RegisteredBearer<B> {
    pub(crate) const fn id(&self) -> BearerId {
        self.id
    }

    pub(crate) const fn info(&self) -> BearerInfo {
        self.info
    }

    pub(crate) const fn state(&self) -> BearerState {
        self.state
    }

    pub(crate) const fn stats(&self) -> BearerStats {
        self.stats
    }

    /// Reported eligibility for the scheduler. This is an observation, not an
    /// admission check performed by the registry.
    pub(crate) const fn is_ready(&self) -> bool {
        self.state.enabled && self.state.ready
    }

    pub(crate) fn can_submit(&self) -> bool {
        self.is_ready() && self.pending.is_none()
    }

    /// Enable or disable this bearer without disturbing the QUIC owner.
    ///
    /// The scheduler excludes a disabled bearer from new work. The registry
    /// remains observational: direct calls to [`Self::submit`] still reach the
    /// callback, and already accepted packets complete normally.
    pub(crate) fn set_enabled(&mut self, enabled: bool) {
        self.state.enabled = enabled;
    }

    /// Report an edge from a previously busy driver indicating that one packet
    /// can now be accepted. This does not complete accepted packets.
    pub(crate) fn send_ready(&mut self) {
        self.state.ready = true;
    }

    /// Submit one packet without making the application drive `WouldBlock`.
    ///
    /// A bearer can retain a partially written packet itself. When it has not
    /// consumed any bytes and returns `WouldBlock`, the node retains exactly
    /// that unchanged submission here and retries it on the next readiness
    /// edge. There is deliberately no bearer-private packet queue.
    pub(crate) fn submit_or_retain(
        &mut self,
        peer_l2_address: PeerL2Address,
        packet: OwnedPacket<B>,
    ) {
        assert!(
            self.pending.is_none(),
            "node submitted past a blocked bearer"
        );
        match self.submit(peer_l2_address, packet) {
            Ok(()) => {}
            Err(PacketSubmitError::WouldBlock(submission)) => {
                self.pending = Some((peer_l2_address, submission));
            }
        }
    }

    pub(crate) fn retry_pending(&mut self) {
        let Some((peer_l2_address, submission)) = self.pending.take() else {
            self.send_ready();
            return;
        };
        self.send_ready();
        match self.retry(peer_l2_address, submission) {
            Ok(()) => {}
            Err(PacketSubmitError::WouldBlock(submission)) => {
                self.pending = Some((peer_l2_address, submission));
            }
        }
    }

    /// Update a configured or negotiated physical rate, such as UART baud.
    pub(crate) fn set_nominal_bitrate_bps(&mut self, bitrate_bps: u64) {
        self.info.nominal_bitrate_bps = bitrate_bps;
    }

    /// Record one parsed packet before handing it to `PacketIngress`.
    ///
    /// Queue-pressure drops are reported separately. The registry records what
    /// the bearer reports and does not decide whether an ingress is admitted.
    pub(crate) fn record_received(&mut self, bytes: usize) {
        self.stats.received_packets = self.stats.received_packets.saturating_add(1);
        self.stats.received_bytes = self.stats.received_bytes.saturating_add(bytes as u64);
    }

    /// Record a malformed frame, unavailable pool slot, or full ingress queue.
    pub(crate) fn record_ingress_drop(&mut self) {
        self.stats.ingress_drops = self.stats.ingress_drops.saturating_add(1);
    }

    /// Submit one complete packet through this bearer.
    ///
    /// The registry delegates every call to the callback. `Ok` transfers
    /// ownership and records the callback as no longer ready. `WouldBlock`
    /// returns the unchanged packet and waits for a later [`Self::send_ready`]
    /// edge. The scheduler normally calls this only when
    /// [`Self::is_ready`] is true, but the callback must remain correct if that
    /// observation races physical capacity.
    pub(crate) fn submit(
        &mut self,
        peer_l2_address: PeerL2Address,
        packet: OwnedPacket<B>,
    ) -> Result<(), PacketSubmitError<B>> {
        let submission = EgressSubmission {
            packet,
            completion: PacketCompletionToken {
                bearer: self.id,
                events: self.events.clone(),
            },
        };
        self.retry(peer_l2_address, submission)
    }

    /// Retry the exact unchanged submission returned by `WouldBlock`.
    /// This preserves its completion token and never allocates a second lease.
    pub(crate) fn retry(
        &mut self,
        peer_l2_address: PeerL2Address,
        submission: EgressSubmission<B>,
    ) -> Result<(), PacketSubmitError<B>> {
        assert_eq!(submission.completion.bearer, self.id);
        let bytes = submission.packet().bytes().len();
        match self.egress.submit(peer_l2_address, submission) {
            Ok(()) => {
                self.state.ready = false;
                self.state.in_flight_packets = self.state.in_flight_packets.saturating_add(1);
                self.stats.submitted_packets = self.stats.submitted_packets.saturating_add(1);
                self.stats.submitted_bytes =
                    self.stats.submitted_bytes.saturating_add(bytes as u64);
                Ok(())
            }
            Err(PacketSubmitError::WouldBlock(packet)) => {
                self.state.ready = false;
                self.stats.send_would_block = self.stats.send_would_block.saturating_add(1);
                Err(PacketSubmitError::WouldBlock(packet))
            }
        }
    }

    /// Record completion and make the bearer ready again.
    ///
    /// `elapsed_us` measures physical submission time when the bearer can
    /// provide it. Successful samples update a smoothed bit rate. A later peer
    /// ACK is QUIC connection state and must not be reported here.
    fn record_completion(&mut self, success: bool, bytes: usize, elapsed_us: u64) {
        self.state.in_flight_packets = self.state.in_flight_packets.saturating_sub(1);
        self.state.ready = self.state.enabled;
        if success {
            self.stats.completed_packets = self.stats.completed_packets.saturating_add(1);
            self.stats.completed_bytes = self.stats.completed_bytes.saturating_add(bytes as u64);
            if elapsed_us != 0 {
                let sample = (bytes as u64)
                    .saturating_mul(8_000_000)
                    .saturating_div(elapsed_us)
                    .max(1);
                self.state.measured_bitrate_bps = if self.state.measured_bitrate_bps == 0 {
                    sample
                } else {
                    self.state
                        .measured_bitrate_bps
                        .saturating_mul(3)
                        .saturating_add(sample)
                        / 4
                };
            }
        } else {
            self.stats.send_failures = self.stats.send_failures.saturating_add(1);
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Failure to reserve a unique slot for a bearer added to a node.
///
/// This is public only because [`QuicNode::add_bearer`](crate::QuicNode::add_bearer)
/// reports registration separately from bearer-specific attachment failure.
pub enum BearerRegistryError {
    /// All node bearer slots are occupied.
    Full,
    /// Another registered bearer already uses the requested name.
    DuplicateName,
    /// This node has exhausted its lifetime supply of non-reused bearer IDs.
    /// Recreate the node before attaching another bearer.
    IdExhausted,
}

#[derive(Debug, Eq, PartialEq)]
/// Error returned while adding a [`PacketBearer`] to a node.
///
/// The generic attachment error is preserved so a platform can report its
/// socket, task, or device setup failure without exposing node internals.
pub enum AddBearerError<E> {
    /// The node could not reserve a registry entry.
    Registry(BearerRegistryError),
    /// The bearer cannot carry the node's configured common packet size.
    PacketTooSmall {
        /// Payload size declared by the bearer.
        actual: usize,
        /// Minimum payload size required by the node.
        required: usize,
    },
    /// Registration succeeded but the bearer rejected its context.
    Attach(E),
}

/// Fixed-capacity registry of every bearer owned by one QUIC runtime.
///
/// The registry is analogous to an operating system's interface table. It
/// owns registrations and their callbacks; associations retain only opaque
/// `BearerId` and `PeerL2Address` handles. Runtime status and exported metrics
/// are read from this table rather than assembled independently by each
/// bearer. Existing `PathState` and bearer statistics should converge here as
/// bearers migrate; they must not remain a second source of readiness or rate.
pub(crate) struct BearerRegistry<B: AsRef<[u8]>, const BEARERS: usize> {
    entries: [Option<RegisteredBearer<B>>; BEARERS],
    next_id: u16,
}

impl<B: AsRef<[u8]>, const BEARERS: usize> BearerRegistry<B, BEARERS> {
    pub(crate) fn reserve_id(&mut self, name: BearerName) -> Result<BearerId, BearerRegistryError> {
        if self
            .entries
            .iter()
            .flatten()
            .any(|entry| entry.info.name == name)
        {
            return Err(BearerRegistryError::DuplicateName);
        }
        if !self.entries.iter().any(Option::is_none) {
            return Err(BearerRegistryError::Full);
        }
        let id = BearerId::new(self.next_id).ok_or(BearerRegistryError::IdExhausted)?;
        self.next_id = self
            .next_id
            .checked_add(1)
            .ok_or(BearerRegistryError::IdExhausted)?;
        Ok(id)
    }

    pub(crate) fn new() -> Self {
        assert!(BEARERS <= u16::MAX as usize);
        Self {
            entries: core::array::from_fn(|_| None),
            next_id: 1,
        }
    }

    pub(crate) fn register<T>(
        &mut self,
        id: BearerId,
        info: BearerInfo,
        egress: T,
        events: Arc<dyn PacketEgressEvents<B>>,
    ) -> Result<BearerId, BearerRegistryError>
    where
        T: PacketEgress<B> + 'static,
    {
        if self
            .entries
            .iter()
            .flatten()
            .any(|entry| entry.info.name == info.name)
        {
            return Err(BearerRegistryError::DuplicateName);
        }
        let Some(slot) = self.entries.iter().position(Option::is_none) else {
            return Err(BearerRegistryError::Full);
        };
        self.entries[slot] = Some(RegisteredBearer {
            id,
            info,
            state: BearerState::new(),
            stats: BearerStats::default(),
            egress: Box::new(egress),
            events,
            pending: None,
        });
        Ok(id)
    }

    pub(crate) fn get(&self, id: BearerId) -> Option<&RegisteredBearer<B>> {
        self.entries.iter().flatten().find(|entry| entry.id == id)
    }

    pub(crate) fn get_mut(&mut self, id: BearerId) -> Option<&mut RegisteredBearer<B>> {
        self.entries
            .iter_mut()
            .flatten()
            .find(|entry| entry.id == id)
    }

    pub(crate) fn remove(&mut self, id: BearerId) -> bool {
        let Some(slot) = self
            .entries
            .iter()
            .position(|entry| entry.as_ref().is_some_and(|entry| entry.id == id))
        else {
            return false;
        };
        // Dropping the registration also returns any submission retained after
        // WouldBlock. Accepted submissions remain owned by the bearer until its
        // completion token returns their packet leases.
        self.entries[slot] = None;
        true
    }

    /// Apply one ownership-bearing completion queued by a bearer.
    /// Dropping this event after accounting returns its packet lease.
    pub(crate) fn send_completed(&mut self, completion: PacketSendCompletion<B>) -> bool {
        let bytes = completion.packet.bytes().len();
        let Some(bearer) = self.get_mut(completion.bearer) else {
            return false;
        };
        bearer.record_completion(
            completion.outcome == PacketSendOutcome::Sent,
            bytes,
            completion.elapsed_us,
        );
        true
    }

    pub(crate) fn by_name(&self, name: BearerName) -> Option<&RegisteredBearer<B>> {
        self.entries
            .iter()
            .flatten()
            .find(|entry| entry.info.name == name)
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = &RegisteredBearer<B>> {
        self.entries.iter().flatten()
    }
}

impl<B: AsRef<[u8]>, const BEARERS: usize> Default for BearerRegistry<B, BEARERS> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "tokio")]
pub(crate) mod tokio {
    //! Tokio bounded handoff for socket and asynchronous read-loop bearers.
    //!
    //! Create one channel per QUIC owner and clone its sender for every bearer.
    //! QUIC retains the root sender for the lifetime of the owner. Disabling a
    //! transport does not close the queue. The queue owns shared counters; do
    //! not create a queue or counters per bearer.

    use super::{PacketIngress, ReceivedPacket};

    /// Cloneable nonblocking producer for driver callbacks and read loops.
    pub(crate) struct PacketSender<B> {
        sender: ::tokio::sync::mpsc::Sender<ReceivedPacket<B>>,
    }

    impl<B> Clone for PacketSender<B> {
        fn clone(&self) -> Self {
            Self {
                sender: self.sender.clone(),
            }
        }
    }

    /// Single consumer owned by the QUIC task.
    pub(crate) struct PacketReceiver<B> {
        receiver: ::tokio::sync::mpsc::Receiver<ReceivedPacket<B>>,
    }

    /// Create the one shared ingress queue for a QUIC owner.
    pub(crate) fn channel<B>(capacity: usize) -> (PacketSender<B>, PacketReceiver<B>) {
        assert!(capacity != 0, "packet queue capacity must be nonzero");
        let (sender, receiver) = ::tokio::sync::mpsc::channel(capacity);
        (PacketSender { sender }, PacketReceiver { receiver })
    }

    impl<B> PacketSender<B> {
        /// Transfer a packet to the shared QUIC ingress queue without waiting.
        pub(crate) fn enqueue_packet(
            &self,
            meta: super::PacketMeta,
            packet: super::OwnedPacket<B>,
        ) {
            let packet = ReceivedPacket { meta, packet };
            match self.sender.try_send(packet) {
                Ok(()) => {}
                Err(::tokio::sync::mpsc::error::TrySendError::Full(packet)) => {
                    drop(packet);
                }
                Err(::tokio::sync::mpsc::error::TrySendError::Closed(packet)) => {
                    drop(packet);
                    // The node may have been dropped after an abrupt peer or
                    // application shutdown while an independently owned
                    // bearer task still observes a final packet. Returning
                    // the lease is sufficient; a dead node has no ingress
                    // state left to drive.
                }
            }
        }
    }

    impl<B: AsRef<[u8]>> PacketIngress<B> for PacketSender<B> {
        fn enqueue_packet(&self, meta: super::PacketMeta, packet: super::OwnedPacket<B>) {
            PacketSender::enqueue_packet(self, meta, packet);
        }
    }

    impl<B: AsRef<[u8]> + Send + 'static> super::PacketIngressQueue<B> for PacketSender<B> {
        fn enqueue_packet(&self, meta: super::PacketMeta, packet: super::OwnedPacket<B>) {
            PacketSender::enqueue_packet(self, meta, packet);
        }
    }

    impl<B: AsRef<[u8]>> PacketReceiver<B> {
        pub(crate) fn poll_receive(
            &mut self,
            context: &mut core::task::Context<'_>,
        ) -> core::task::Poll<ReceivedPacket<B>> {
            self.receiver
                .poll_recv(context)
                .map(|packet| packet.expect("QUIC ingress queue lifetime invariant violated"))
        }

        pub(crate) async fn receive(&mut self) -> ReceivedPacket<B> {
            self.receiver
                .recv()
                .await
                .expect("QUIC ingress queue lifetime invariant violated")
        }

        pub(crate) fn try_receive(&mut self) -> Option<ReceivedPacket<B>> {
            self.receiver.try_recv().ok()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::rc::Rc;
    use core::cell::Cell;

    #[test]
    fn rejected_submit_returns_the_same_owned_buffer() {
        let peer_l2_address = PeerL2Address::new(1).unwrap();
        let packet = OwnedPacket::new([1, 2, 3, 4], 1..3).unwrap();
        let events = Arc::new(CompletionQueue::new(1));
        let submission = EgressSubmission::new(BearerId::new(1).unwrap(), packet, events);
        let mut submit = |_peer_l2_address, submission| {
            Err::<(), _>(PacketSubmitError::<[u8; 4]>::WouldBlock(submission))
        };
        let PacketSubmitError::WouldBlock(submission) =
            submit.submit(peer_l2_address, submission).unwrap_err();
        let (packet, _) = submission.into_parts();
        assert_eq!(packet.bytes(), &[2, 3]);
        assert_eq!(packet.into_buffer(), [1, 2, 3, 4]);
    }

    #[test]
    fn registry_describes_observes_and_delegates_without_admission_policy() {
        let calls = Rc::new(Cell::new(0));
        let egress_calls = calls.clone();
        let egress = move |_peer_l2_address, submission: EgressSubmission<[u8; 8]>| {
            egress_calls.set(egress_calls.get() + 1);
            assert_eq!(submission.packet().bytes(), &[3, 4]);
            submission.complete(PacketSendOutcome::Sent, 10);
            Ok::<(), PacketSubmitError<[u8; 8]>>(())
        };
        let completions = Arc::new(CompletionQueue::new(2));
        let mut registry = BearerRegistry::<[u8; 8], 2>::new();
        let id = registry
            .reserve_id(BearerName::new("wlan0").unwrap())
            .unwrap();
        let id = registry
            .register(
                id,
                BearerInfo {
                    name: BearerName::new("wlan0").unwrap(),
                    max_packet_size: 1100,
                    prefix_required: 80,
                    suffix_required: 24,
                    requires_packet_encryption: true,
                    secure_link: false,
                    nominal_bitrate_bps: 54_000_000,
                    local_mac: Some([1, 2, 3, 4, 5, 6]),
                },
                egress,
                completions.clone(),
            )
            .unwrap();

        let bearer = registry.get_mut(id).unwrap();
        assert!(!bearer.is_ready());
        // The registry records readiness for selection but does not reject a
        // direct call. The callback is still the capacity authority.
        bearer
            .submit(
                PeerL2Address::new(7).unwrap(),
                OwnedPacket::new([0, 1, 2, 3, 4, 5, 6, 7], 3..5).unwrap(),
            )
            .unwrap();
        assert_eq!(calls.get(), 1);
        assert_eq!(bearer.state().in_flight_packets, 1);
        bearer.record_received(20);
        let completion = completions.pop_completion().unwrap();
        assert!(registry.send_completed(completion));
        let bearer = registry.get_mut(id).unwrap();
        assert_eq!(bearer.state().measured_bitrate_bps, 1_600_000);
        assert_eq!(
            bearer.stats(),
            BearerStats {
                received_packets: 1,
                received_bytes: 20,
                submitted_packets: 1,
                submitted_bytes: 2,
                completed_packets: 1,
                completed_bytes: 2,
                ..BearerStats::default()
            }
        );
        assert_eq!(
            registry
                .by_name(BearerName::new("wlan0").unwrap())
                .unwrap()
                .id(),
            id
        );
    }

    #[cfg(feature = "tokio")]
    #[test]
    fn tokio_handoff_is_bounded_and_drops_on_pressure() {
        let bearer = BearerId::new(1).unwrap();
        let peer_l2_address = PeerL2Address::new(1).unwrap();
        let meta = PacketMeta {
            bearer,
            peer_l2_address,
            received_at_us: 7,
        };
        let (sender, mut receiver) = tokio::channel(1);
        sender.enqueue_packet(meta, OwnedPacket::from_buffer([1, 2]));
        sender.enqueue_packet(meta, OwnedPacket::from_buffer([3, 4]));
        assert_eq!(receiver.try_receive().unwrap().packet.bytes(), &[1, 2]);
    }
}
