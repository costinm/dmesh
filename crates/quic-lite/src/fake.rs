//! In-memory packet bearer for public `QuicNode` tests.
//!
//! It uses the same attach, ingress, submission, and completion contracts as
//! physical bearers and does not expose a second connection or stream driver.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::vec::Vec;

use crate::bearer::OwnedPacket;
use crate::bearer::{
    BearerContext, BearerInfo, BearerName, EgressSubmission, PacketBearer, PacketEgress,
    PacketPool, PacketSendOutcome, PacketSubmitError, PacketWriter, PeerL2Address,
};

/// Complete in-memory bearer for public `QuicNode` API tests.
pub struct FakePacketBearer<P: PacketPool + 'static> {
    info: BearerInfo,
    sent: Arc<Mutex<Vec<Vec<u8>>>>,
    attached: bool,
    pair: Option<(Arc<Mutex<FakePair<P>>>, usize)>,
    simulated: Option<(Arc<Mutex<SimulatedPair<P>>>, usize)>,
    pool: core::marker::PhantomData<fn() -> P>,
}

struct FakePair<P: PacketPool + 'static> {
    contexts: [Option<BearerContext<P>>; 2],
}

/// Deterministic properties of one direction in the virtual packet network.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FakeLinkProfile {
    /// Fixed propagation delay added once to each delivered packet.
    pub latency_us: u64,
    /// Maximum seeded uniform delay added to each delivered packet.
    pub jitter_us: u64,
    /// Probability of dropping a transmitted packet, in parts per million.
    pub loss_per_million: u32,
    /// First accepted packet ordinal in a deterministic loss burst; zero disables it.
    pub loss_burst_start_packet: u64,
    /// Number of consecutive accepted packets dropped by the deterministic burst.
    pub loss_burst_packets: u64,
    /// Physical bit rate. Zero leaves serialization delay disabled.
    pub bitrate_bps: u64,
    /// Largest packet delivered by this link; larger packets are dropped.
    pub mtu_bytes: usize,
    /// Packet size reported to QUIC. It may exceed `mtu_bytes` to model a
    /// stale path-MTU estimate; values below the node's packet size are raised
    /// by bearer admission just as they are for a physical registration.
    pub advertised_max_packet_size: usize,
    /// Maximum packet count waiting for virtual delivery; zero means unlimited.
    pub queue_packets: usize,
    /// Return `WouldBlock` on every Nth submit attempt; zero disables it.
    pub would_block_every: u64,
    /// Virtual time until a blocked bearer reports send readiness again.
    pub readiness_delay_us: u64,
    /// Additional delay before an accepted send completes; serialization is
    /// also included in the completion time.
    pub completion_delay_us: u64,
    /// Complete every Nth accepted send with a definite failure; zero disables it.
    pub fail_every: u64,
    /// Complete every Nth accepted send as ambiguous; zero disables it.
    pub indeterminate_every: u64,
    /// Whether an ambiguous send is delivered to the remote endpoint.
    pub deliver_indeterminate: bool,
    /// Reverse packets that become ready in the same clock advance.
    pub reorder_ready_batch: bool,
    /// Initial seed for this direction's deterministic xorshift stream.
    pub seed: u64,
}

impl Default for FakeLinkProfile {
    fn default() -> Self {
        Self {
            latency_us: 0,
            jitter_us: 0,
            loss_per_million: 0,
            loss_burst_start_packet: 0,
            loss_burst_packets: 0,
            bitrate_bps: 0,
            mtu_bytes: usize::MAX,
            advertised_max_packet_size: crate::DEFAULT_MAX_PACKET_SIZE,
            queue_packets: 0,
            would_block_every: 0,
            readiness_delay_us: 1,
            completion_delay_us: 0,
            fail_every: 0,
            indeterminate_every: 0,
            deliver_indeterminate: true,
            reorder_ready_batch: false,
            seed: 1,
        }
    }
}

/// Independent packet-link profiles for the two directions of a fake pair.
#[derive(Clone, Debug, Default)]
pub struct FakeNetworkConfig {
    /// Packets sent by the first bearer toward the second.
    pub first_to_second: FakeLinkProfile,
    /// Packets sent by the second bearer toward the first.
    pub second_to_first: FakeLinkProfile,
    /// Optional physical bottleneck shared by this direction across network
    /// pairs. When present, its rate controls serialization for this path.
    pub first_to_second_shared_link: Option<FakeSharedLink>,
    /// Optional physical bottleneck shared by this direction across network
    /// pairs. The two directions need separate handles for a half-duplex link.
    pub second_to_first_shared_link: Option<FakeSharedLink>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
/// Aggregate serialization counters for a shared physical bottleneck.
pub struct FakeSharedLinkStats {
    /// Number of packets reserved on the link.
    pub packets: u64,
    /// Total bytes reserved on the link.
    pub bytes: u64,
    /// Virtual time when the last reserved packet finishes serialization.
    pub busy_until_us: u64,
}

#[derive(Debug, Default)]
struct SharedLinkState {
    stats: FakeSharedLinkStats,
}

/// A serialization bottleneck that can be shared by separate fake bearer pairs.
///
/// Clone a handle into each pair's matching direction to model independent
/// circuits competing for one physical link. Delivery delay, loss, MTU and
/// completion policy remain properties of each directed path profile.
#[derive(Clone, Debug)]
pub struct FakeSharedLink {
    bitrate_bps: u64,
    state: Arc<Mutex<SharedLinkState>>,
}

impl FakeSharedLink {
    /// Create a shared bottleneck with a fixed physical bit rate.
    ///
    /// # Panics
    /// Panics when `bitrate_bps` is zero; omit the shared link for an
    /// unconstrained bottleneck.
    pub fn new(bitrate_bps: u64) -> Self {
        assert!(bitrate_bps != 0, "shared fake link rate must be non-zero");
        Self {
            bitrate_bps,
            state: Arc::new(Mutex::new(SharedLinkState::default())),
        }
    }

    /// Snapshot aggregate submissions serialized through this link.
    pub fn stats(&self) -> FakeSharedLinkStats {
        self.state.lock().unwrap().stats
    }

    fn serialize(&self, now_us: u64, packet_bytes: usize) -> u64 {
        let mut state = self.state.lock().unwrap();
        let serialization_us = (packet_bytes as u64)
            .saturating_mul(8_000_000)
            .saturating_add(self.bitrate_bps - 1)
            / self.bitrate_bps;
        let finish_at_us = now_us
            .max(state.stats.busy_until_us)
            .saturating_add(serialization_us);
        state.stats.packets = state.stats.packets.saturating_add(1);
        state.stats.bytes = state.stats.bytes.saturating_add(packet_bytes as u64);
        state.stats.busy_until_us = finish_at_us;
        finish_at_us
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
/// Counters accumulated by a virtual network while it advances.
pub struct FakeNetworkStats {
    /// Packets enqueued into the peer's node-owned ingress queue.
    pub delivered_packets: u64,
    /// Packets dropped by deterministic loss policy.
    pub loss_drops: u64,
    /// Packets dropped because they exceed the configured MTU.
    pub mtu_drops: u64,
    /// Packets dropped because the configured virtual queue was full.
    pub queue_drops: u64,
    /// Accepted egress submissions completed to their owning node.
    pub completions: u64,
    /// Egress submissions accepted by the fake bearer.
    pub accepted_submissions: u64,
    /// Accepted sends completed with a definite failure.
    pub failed_completions: u64,
    /// Accepted sends completed with an ambiguous outcome.
    pub indeterminate_completions: u64,
    /// `WouldBlock` results returned before ownership transfer.
    pub would_block: u64,
    /// Largest number of accepted sends on this pair in one virtual instant.
    pub max_same_time_submission_burst_packets: u64,
    /// Largest total wire bytes accepted on this pair in one virtual instant.
    pub max_same_time_submission_burst_bytes: u64,
    /// Largest per-direction accepted-send burst in packets.
    pub max_same_time_submission_burst_packets_by_direction: [u64; 2],
    /// Largest per-direction accepted-send burst in bytes.
    pub max_same_time_submission_burst_bytes_by_direction: [u64; 2],
}

struct SimulatedPacket {
    ready_at_us: u64,
    ordinal: u64,
    bytes: Vec<u8>,
}

struct PendingCompletion<B> {
    side: usize,
    complete_at_us: u64,
    elapsed_us: u64,
    outcome: PacketSendOutcome,
    packet: OwnedPacket<B>,
    token: crate::bearer::PacketCompletionToken<B>,
}

struct SimulatedDirection {
    profile: FakeLinkProfile,
    shared_link: Option<FakeSharedLink>,
    packets: VecDeque<SimulatedPacket>,
    attempts: u64,
    accepted: u64,
    random_state: u64,
    last_serialized_at_us: u64,
    blocked_until_us: Option<u64>,
    last_submission_at_us: Option<u64>,
    same_time_submission_packets: u64,
    same_time_submission_bytes: u64,
}

impl SimulatedDirection {
    fn new(profile: FakeLinkProfile, shared_link: Option<FakeSharedLink>) -> Self {
        Self {
            profile,
            shared_link,
            packets: VecDeque::new(),
            attempts: 0,
            accepted: 0,
            random_state: if profile.seed == 0 { 1 } else { profile.seed },
            last_serialized_at_us: 0,
            blocked_until_us: None,
            last_submission_at_us: None,
            same_time_submission_packets: 0,
            same_time_submission_bytes: 0,
        }
    }

    fn random(&mut self) -> u64 {
        let mut value = self.random_state;
        value ^= value << 13;
        value ^= value >> 7;
        value ^= value << 17;
        self.random_state = value;
        value
    }
}

struct SimulatedPair<P: PacketPool + 'static> {
    contexts: [Option<BearerContext<P>>; 2],
    directions: [SimulatedDirection; 2],
    completions: Vec<PendingCompletion<P::Buffer>>,
    now_us: u64,
    stats: FakeNetworkStats,
}

/// Controller for a [`FakePacketBearer`] pair using explicit virtual time.
///
/// Calls to [`advance_to`](Self::advance_to) deliver due packets through the
/// peer's attached [`BearerContext`] and release due send completions. No
/// sleeps, threads, sockets, or wall-clock timers are used.
pub struct FakeNetwork<P: PacketPool + 'static> {
    pair: Arc<Mutex<SimulatedPair<P>>>,
}

impl<P: PacketPool + 'static> FakeNetwork<P> {
    /// Current virtual time in microseconds.
    pub fn now_us(&self) -> u64 {
        self.pair.lock().unwrap().now_us
    }

    /// Snapshot cumulative delivery, drop, submission and completion counters.
    pub fn stats(&self) -> FakeNetworkStats {
        self.pair.lock().unwrap().stats
    }

    /// Replace the first-to-second link profile at the current virtual time.
    /// Tests can restore a path after exercising a transient outage, then
    /// validate circuit resumption over the same bearer pair.
    pub fn set_first_to_second_profile(&mut self, profile: FakeLinkProfile) {
        self.pair.lock().unwrap().directions[0].profile = profile;
    }

    /// Replace the second-to-first link profile at the current virtual time.
    pub fn set_second_to_first_profile(&mut self, profile: FakeLinkProfile) {
        self.pair.lock().unwrap().directions[1].profile = profile;
    }

    /// Advance monotonic time and dispatch all due network and completion events.
    pub fn advance_to(&mut self, now_us: u64) -> FakeNetworkStats {
        let (deliveries, completions, ready) = {
            let mut pair = self.pair.lock().unwrap();
            assert!(now_us >= pair.now_us, "fake clock cannot move backwards");
            pair.now_us = now_us;
            let SimulatedPair {
                contexts,
                directions,
                completions: pending_completions,
                ..
            } = &mut *pair;

            let mut deliveries = Vec::new();
            for side in 0..2 {
                let direction = &mut directions[side];
                let mut ready_packets = Vec::new();
                let mut pending_packets = VecDeque::new();
                while let Some(packet) = direction.packets.pop_front() {
                    if packet.ready_at_us <= now_us {
                        ready_packets.push(packet);
                    } else {
                        pending_packets.push_back(packet);
                    }
                }
                direction.packets = pending_packets;
                if direction.profile.reorder_ready_batch {
                    ready_packets.sort_by_key(|packet| core::cmp::Reverse(packet.ordinal));
                } else {
                    ready_packets.sort_by_key(|packet| (packet.ready_at_us, packet.ordinal));
                }
                if let Some(target) = contexts[1 - side].clone() {
                    deliveries.extend(
                        ready_packets
                            .into_iter()
                            .map(|packet| (target.clone(), packet)),
                    );
                }
            }

            let mut ready = Vec::new();
            let mut completions = Vec::new();
            let mut pending = Vec::new();
            for completion in pending_completions.drain(..) {
                if completion.complete_at_us <= now_us {
                    if let Some(context) = contexts[completion.side].clone() {
                        ready.push(context);
                    }
                    completions.push(completion);
                } else {
                    pending.push(completion);
                }
            }
            *pending_completions = pending;

            for side in 0..2 {
                if directions[side]
                    .blocked_until_us
                    .is_some_and(|deadline| deadline <= now_us)
                {
                    directions[side].blocked_until_us = None;
                    if let Some(context) = contexts[side].clone() {
                        ready.push(context);
                    }
                }
            }
            (deliveries, completions, ready)
        };

        for (target, packet) in deliveries {
            if let Some(mut writer) = target
                .pool()
                .acquire_writer(crate::PACKET_PREFIX_RESERVE, 0)
                && let Some(output) = writer.payload_mut().get_mut(..packet.bytes.len())
            {
                output.copy_from_slice(&packet.bytes);
                if let Some(received) = writer.commit(packet.bytes.len()) {
                    target.enqueue_packet(
                        crate::PacketMeta {
                            bearer: target.bearer(),
                            peer_l2_address: PeerL2Address::new(1).unwrap(),
                            received_at_us: packet.ready_at_us,
                        },
                        received,
                    );
                    let mut pair = self.pair.lock().unwrap();
                    pair.stats.delivered_packets = pair.stats.delivered_packets.saturating_add(1);
                } else {
                    let mut pair = self.pair.lock().unwrap();
                    pair.stats.queue_drops = pair.stats.queue_drops.saturating_add(1);
                }
            } else {
                let mut pair = self.pair.lock().unwrap();
                pair.stats.queue_drops = pair.stats.queue_drops.saturating_add(1);
            }
        }
        for completion in completions {
            let outcome = completion.outcome;
            completion
                .token
                .complete(completion.packet, outcome, completion.elapsed_us);
            let mut pair = self.pair.lock().unwrap();
            pair.stats.completions = pair.stats.completions.saturating_add(1);
            match outcome {
                PacketSendOutcome::Sent => {}
                PacketSendOutcome::Failed => {
                    pair.stats.failed_completions = pair.stats.failed_completions.saturating_add(1);
                }
                PacketSendOutcome::Indeterminate => {
                    pair.stats.indeterminate_completions =
                        pair.stats.indeterminate_completions.saturating_add(1);
                }
            }
        }
        for context in ready {
            context.send_ready();
        }
        self.pair.lock().unwrap().stats
    }
}

impl<P: PacketPool + 'static> FakePacketBearer<P> {
    /// Create an unattached in-memory bearer with the supplied registration name.
    ///
    /// This is public only for external conformance and stress tests; production
    /// applications should register a physical bearer implementation.
    pub fn new(name: BearerName) -> Self {
        Self {
            info: BearerInfo {
                name,
                max_packet_size: crate::DEFAULT_MAX_PACKET_SIZE,
                prefix_required: 0,
                suffix_required: 0,
                requires_packet_encryption: false,
                secure_link: true,
                nominal_bitrate_bps: 0,
                local_mac: None,
            },
            sent: Arc::new(Mutex::new(Vec::new())),
            attached: false,
            pair: None,
            simulated: None,
            pool: core::marker::PhantomData,
        }
    }

    /// Create two complete packet bearers connected back-to-back.
    pub fn pair(first: BearerName, second: BearerName) -> (Self, Self) {
        let pair = Arc::new(Mutex::new(FakePair {
            contexts: [None, None],
        }));
        let mut first = Self::new(first);
        first.pair = Some((pair.clone(), 0));
        let mut second = Self::new(second);
        second.pair = Some((pair, 1));
        (first, second)
    }

    /// Create paired bearers controlled by a deterministic virtual-time link.
    pub fn pair_with_network(
        first: BearerName,
        second: BearerName,
        config: FakeNetworkConfig,
    ) -> (Self, Self, FakeNetwork<P>) {
        let pair = Arc::new(Mutex::new(SimulatedPair {
            contexts: [None, None],
            directions: [
                SimulatedDirection::new(config.first_to_second, config.first_to_second_shared_link),
                SimulatedDirection::new(config.second_to_first, config.second_to_first_shared_link),
            ],
            completions: Vec::new(),
            now_us: 0,
            stats: FakeNetworkStats::default(),
        }));
        let mut first_bearer = Self::new(first);
        first_bearer.simulated = Some((pair.clone(), 0));
        let mut second_bearer = Self::new(second);
        second_bearer.simulated = Some((pair.clone(), 1));
        (first_bearer, second_bearer, FakeNetwork { pair })
    }

    /// Captured opaque QUIC packets, for tests which only inspect submission.
    pub fn sent_packets(&self) -> Arc<Mutex<Vec<Vec<u8>>>> {
        self.sent.clone()
    }
}

impl<P> PacketEgress<P::Buffer> for FakePacketBearer<P>
where
    P: PacketPool + 'static,
{
    fn submit(
        &mut self,
        _peer_l2_address: PeerL2Address,
        submission: EgressSubmission<P::Buffer>,
    ) -> Result<(), PacketSubmitError<P::Buffer>> {
        debug_assert!(self.attached);
        self.sent
            .lock()
            .unwrap()
            .push(submission.packet().bytes().to_vec());
        if let Some((pair, side)) = &self.simulated {
            let mut pair = pair.lock().unwrap();
            let now_us = pair.now_us;
            let blocked = {
                let direction = &mut pair.directions[*side];
                if direction
                    .blocked_until_us
                    .is_some_and(|deadline| deadline > now_us)
                {
                    true
                } else {
                    direction.attempts = direction.attempts.saturating_add(1);
                    let block_period = direction.profile.would_block_every;
                    let queue_full = direction.profile.queue_packets != 0
                        && direction.packets.len() >= direction.profile.queue_packets;
                    let blocked =
                        queue_full || (block_period != 0 && direction.attempts % block_period == 0);
                    if blocked {
                        let delay = direction.profile.readiness_delay_us.max(1);
                        direction.blocked_until_us = Some(now_us.saturating_add(delay));
                    }
                    blocked
                }
            };
            if blocked {
                pair.stats.would_block = pair.stats.would_block.saturating_add(1);
                return Err(PacketSubmitError::WouldBlock(submission));
            }

            let (completion, mtu_drop, loss_drop, burst_packets, burst_bytes) = {
                let direction = &mut pair.directions[*side];
                let profile = direction.profile;
                let bytes = submission.packet().bytes().to_vec();
                let packet_bytes = bytes.len() as u64;
                if direction.last_submission_at_us == Some(now_us) {
                    direction.same_time_submission_packets =
                        direction.same_time_submission_packets.saturating_add(1);
                    direction.same_time_submission_bytes = direction
                        .same_time_submission_bytes
                        .saturating_add(packet_bytes);
                } else {
                    direction.last_submission_at_us = Some(now_us);
                    direction.same_time_submission_packets = 1;
                    direction.same_time_submission_bytes = packet_bytes;
                }
                let burst_packets = direction.same_time_submission_packets;
                let burst_bytes = direction.same_time_submission_bytes;
                let ordinal = direction.attempts;
                direction.accepted = direction.accepted.saturating_add(1);
                let accepted = direction.accepted;
                let random_loss = direction.random() % 1_000_000
                    < u64::from(profile.loss_per_million.min(1_000_000));
                let burst_start = profile.loss_burst_start_packet.max(1);
                let burst_loss = profile.loss_burst_packets != 0
                    && accepted >= burst_start
                    && accepted < burst_start.saturating_add(profile.loss_burst_packets);
                let jitter = if profile.jitter_us == 0 {
                    0
                } else {
                    direction.random() % profile.jitter_us.saturating_add(1)
                };
                let serialized_at_us = if let Some(shared_link) = &direction.shared_link {
                    shared_link.serialize(now_us, bytes.len())
                } else {
                    let serialization_us = if profile.bitrate_bps == 0 {
                        0
                    } else {
                        (bytes.len() as u64)
                            .saturating_mul(8_000_000)
                            .saturating_add(profile.bitrate_bps - 1)
                            / profile.bitrate_bps
                    };
                    let serialized_at_us = now_us
                        .max(direction.last_serialized_at_us)
                        .saturating_add(serialization_us);
                    direction.last_serialized_at_us = serialized_at_us;
                    serialized_at_us
                };
                let complete_at_us = serialized_at_us.saturating_add(profile.completion_delay_us);

                let outcome = if profile.fail_every != 0 && accepted % profile.fail_every == 0 {
                    PacketSendOutcome::Failed
                } else if profile.indeterminate_every != 0
                    && accepted % profile.indeterminate_every == 0
                {
                    PacketSendOutcome::Indeterminate
                } else {
                    PacketSendOutcome::Sent
                };
                let oversized = bytes.len() > profile.mtu_bytes;
                let deliver = !oversized
                    && !random_loss
                    && !burst_loss
                    && outcome != PacketSendOutcome::Failed
                    && (outcome != PacketSendOutcome::Indeterminate
                        || profile.deliver_indeterminate);
                if deliver {
                    direction.packets.push_back(SimulatedPacket {
                        ready_at_us: serialized_at_us
                            .saturating_add(profile.latency_us)
                            .saturating_add(jitter),
                        ordinal,
                        bytes,
                    });
                }
                let (packet, token) = submission.into_parts();
                (
                    PendingCompletion {
                        side: *side,
                        complete_at_us,
                        elapsed_us: complete_at_us.saturating_sub(now_us),
                        outcome,
                        packet,
                        token,
                    },
                    oversized,
                    (random_loss || burst_loss) && !oversized,
                    burst_packets,
                    burst_bytes,
                )
            };
            pair.stats.max_same_time_submission_burst_packets = pair
                .stats
                .max_same_time_submission_burst_packets
                .max(burst_packets);
            pair.stats.max_same_time_submission_burst_bytes = pair
                .stats
                .max_same_time_submission_burst_bytes
                .max(burst_bytes);
            pair.stats
                .max_same_time_submission_burst_packets_by_direction[*side] = pair
                .stats
                .max_same_time_submission_burst_packets_by_direction[*side]
                .max(burst_packets);
            pair.stats.max_same_time_submission_burst_bytes_by_direction[*side] =
                pair.stats.max_same_time_submission_burst_bytes_by_direction[*side]
                    .max(burst_bytes);
            if mtu_drop {
                pair.stats.mtu_drops = pair.stats.mtu_drops.saturating_add(1);
            } else if loss_drop {
                pair.stats.loss_drops = pair.stats.loss_drops.saturating_add(1);
            }
            pair.completions.push(completion);
            pair.stats.accepted_submissions = pair.stats.accepted_submissions.saturating_add(1);
            return Ok(());
        }
        if let Some((pair, side)) = &self.pair {
            let target = pair.lock().unwrap().contexts[1 - *side].clone();
            if let Some(target) = target
                && let Some(mut writer) = target
                    .pool()
                    .acquire_writer(crate::PACKET_PREFIX_RESERVE, 0)
            {
                let bytes = submission.packet().bytes();
                if let Some(output) = writer.payload_mut().get_mut(..bytes.len()) {
                    output.copy_from_slice(bytes);
                    if let Some(packet) = writer.commit(bytes.len()) {
                        target.enqueue_packet(
                            crate::PacketMeta {
                                bearer: target.bearer(),
                                peer_l2_address: PeerL2Address::new(1).unwrap(),
                                received_at_us: 0,
                            },
                            packet,
                        );
                    }
                }
            }
        }
        submission.complete(PacketSendOutcome::Sent, 0);
        Ok(())
    }
}

impl<P> PacketBearer<P> for FakePacketBearer<P>
where
    P: PacketPool + 'static,
{
    type AttachError = core::convert::Infallible;

    fn info(&self) -> BearerInfo {
        if let Some((pair, side)) = &self.simulated {
            let pair = pair.lock().unwrap();
            let profile = pair.directions[*side].profile;
            return BearerInfo {
                name: self.info.name,
                max_packet_size: profile.advertised_max_packet_size,
                prefix_required: 0,
                suffix_required: 0,
                requires_packet_encryption: false,
                secure_link: true,
                nominal_bitrate_bps: profile.bitrate_bps,
                local_mac: None,
            };
        }
        self.info
    }

    fn attach(&mut self, context: BearerContext<P>) -> Result<(), Self::AttachError> {
        if let Some((pair, side)) = &self.pair {
            pair.lock().unwrap().contexts[*side] = Some(context);
        } else if let Some((pair, side)) = &self.simulated {
            pair.lock().unwrap().contexts[*side] = Some(context);
        }
        self.attached = true;
        Ok(())
    }
}

/// Byte-level fault policy used only by transport-state unit tests.
#[cfg(test)]
#[derive(Clone, Copy, Debug)]
pub(crate) struct FaultConfig {
    pub latency_ticks: u64,
    pub drop_every: Option<u64>,
    pub duplicate: bool,
    pub reorder: bool,
    pub mtu: usize,
}

#[cfg(test)]
impl Default for FaultConfig {
    fn default() -> Self {
        Self {
            latency_ticks: 0,
            drop_every: None,
            duplicate: false,
            reorder: false,
            mtu: usize::MAX,
        }
    }
}

#[cfg(test)]
#[derive(Debug)]
struct FaultPacket {
    ready_at: u64,
    ordinal: u64,
    bytes: Vec<u8>,
}

/// Private byte queue for testing transport loss and timers. This is not a
/// bearer and cannot attach to or drive a `QuicNode`.
#[cfg(test)]
#[derive(Debug)]
pub(crate) struct FaultQueue {
    config: FaultConfig,
    profile: FaultProfile,
    queue: VecDeque<FaultPacket>,
    sent: u64,
    random_state: u64,
    last_ready_at: u64,
}

#[cfg(test)]
/// Additional deterministic link behavior. Rates use bytes per virtual tick;
/// jitter is a uniformly selected integer in `0..=jitter_ticks`. Loss uses a
/// seeded xorshift generator and is expressed in parts per million.
#[cfg(test)]
#[derive(Clone, Copy, Debug)]
pub(crate) struct FaultProfile {
    pub seed: u64,
    pub loss_per_million: u32,
    pub jitter_ticks: u64,
    pub rate_bytes_per_tick: u64,
    pub queue_packets: usize,
}

#[cfg(test)]
impl Default for FaultProfile {
    fn default() -> Self {
        Self {
            seed: 1,
            loss_per_million: 0,
            jitter_ticks: 0,
            rate_bytes_per_tick: 0,
            queue_packets: usize::MAX,
        }
    }
}

#[cfg(test)]
impl FaultQueue {
    pub(crate) fn new(config: FaultConfig) -> Self {
        Self::with_profile(config, FaultProfile::default())
    }

    pub(crate) fn with_profile(config: FaultConfig, profile: FaultProfile) -> Self {
        let random_state = if profile.seed == 0 { 1 } else { profile.seed };
        Self {
            config,
            profile,
            queue: VecDeque::new(),
            sent: 0,
            random_state,
            last_ready_at: 0,
        }
    }

    fn random(&mut self) -> u64 {
        let mut value = self.random_state;
        value ^= value << 13;
        value ^= value >> 7;
        value ^= value << 17;
        self.random_state = value;
        value
    }

    pub(crate) fn submit_at(&mut self, now: u64, payload: &[u8]) -> Result<(), crate::Error> {
        self.sent = self.sent.saturating_add(1);
        if self
            .config
            .drop_every
            .is_some_and(|n| n != 0 && self.sent % n == 0)
            || self.random() % 1_000_000 < u64::from(self.profile.loss_per_million.min(1_000_000))
            || payload.len() > self.config.mtu
            || self.queue.len() >= self.profile.queue_packets
        {
            return Ok(());
        }
        let bytes = payload.to_vec();
        let jitter = if self.profile.jitter_ticks == 0 {
            0
        } else {
            self.random() % self.profile.jitter_ticks.saturating_add(1)
        };
        let serialization = if self.profile.rate_bytes_per_tick == 0 {
            0
        } else {
            (payload.len() as u64).saturating_add(self.profile.rate_bytes_per_tick - 1)
                / self.profile.rate_bytes_per_tick
        };
        // Propagation delay applies once per packet. Serialization consumes
        // the shared direction's queue and determines when the next packet
        // may start; adding propagation delay to `last_ready_at` would
        // incorrectly serialize the link at one packet per RTT.
        let serialized_at = now.max(self.last_ready_at).saturating_add(serialization);
        let ready_at = serialized_at
            .saturating_add(self.config.latency_ticks)
            .saturating_add(jitter);
        self.last_ready_at = serialized_at;
        let packet = FaultPacket {
            ready_at,
            ordinal: self.sent,
            bytes,
        };
        self.queue.push_back(packet);
        if self.config.duplicate {
            let packet = self.queue.back().expect("packet was just queued");
            self.queue.push_back(FaultPacket {
                ready_at: packet.ready_at,
                ordinal: packet.ordinal,
                bytes: packet.bytes.clone(),
            });
        }
        Ok(())
    }

    pub(crate) fn poll_owned(&mut self, now: u64) -> Vec<OwnedPacket<Vec<u8>>> {
        let mut ready = Vec::new();
        let mut pending = VecDeque::new();
        while let Some(packet) = self.queue.pop_front() {
            if packet.ready_at <= now {
                ready.push(packet);
            } else {
                pending.push_back(packet);
            }
        }
        self.queue = pending;
        if self.config.reorder {
            ready.sort_by_key(|packet| core::cmp::Reverse(packet.ordinal));
        }
        ready
            .into_iter()
            .map(|packet| OwnedPacket::from_buffer(packet.bytes))
            .collect()
    }
}

#[cfg(test)]
mod fault_profile_tests {
    use super::*;

    fn configured() -> FaultConfig {
        FaultConfig {
            latency_ticks: 3,
            drop_every: None,
            duplicate: false,
            reorder: false,
            mtu: 8,
        }
    }

    #[test]
    fn seeded_profile_repeats_loss_jitter_rate_and_mtu_decisions() {
        let profile = FaultProfile {
            seed: 0xfeed_beef,
            loss_per_million: 350_000,
            jitter_ticks: 5,
            rate_bytes_per_tick: 2,
            queue_packets: 16,
        };
        let mut first = FaultQueue::with_profile(configured(), profile);
        let mut second = FaultQueue::with_profile(configured(), profile);
        for i in 0..12 {
            first.submit_at(i, b"12345678").unwrap();
            second.submit_at(i, b"12345678").unwrap();
        }
        let first: Vec<_> = first
            .poll_owned(10_000)
            .into_iter()
            .map(|packet| packet.bytes().to_vec())
            .collect();
        let second: Vec<_> = second
            .poll_owned(10_000)
            .into_iter()
            .map(|packet| packet.bytes().to_vec())
            .collect();
        assert_eq!(first, second);
        assert!(first.len() < 12, "seeded loss should drop packets");

        let mut mtu = FaultQueue::with_profile(configured(), FaultProfile::default());
        mtu.submit_at(0, b"123456789").unwrap();
        assert!(mtu.poll_owned(u64::MAX).is_empty());
    }

    #[test]
    fn rate_and_jitter_delay_packet_delivery() {
        let mut link = FaultQueue::with_profile(
            configured(),
            FaultProfile {
                seed: 7,
                jitter_ticks: 4,
                rate_bytes_per_tick: 2,
                ..FaultProfile::default()
            },
        );
        link.submit_at(0, b"12345678").unwrap();
        assert!(link.poll_owned(6).is_empty());
        assert_eq!(link.poll_owned(100).len(), 1);
    }

    #[test]
    fn propagation_latency_is_not_reapplied_to_queued_packets() {
        let mut link = FaultQueue::with_profile(
            FaultConfig {
                latency_ticks: 3,
                drop_every: None,
                duplicate: false,
                reorder: false,
                mtu: 16,
            },
            FaultProfile {
                rate_bytes_per_tick: 2,
                ..FaultProfile::default()
            },
        );
        link.submit_at(0, b"1234").unwrap();
        link.submit_at(0, b"5678").unwrap();
        assert!(link.poll_owned(4).is_empty());
        assert_eq!(link.poll_owned(5).len(), 1);
        assert_eq!(link.poll_owned(7).len(), 1);
    }
}

#[cfg(test)]
mod virtual_network_tests {
    use super::*;
    use crate::bearer::PacketIngressQueue;
    use crate::node::{InitialAdmission, NodeIngress};
    use crate::{ConnectionLimits, QuicNode, packet_pool::PacketPool};

    type Pool = PacketPool<16, { crate::DEFAULT_PACKET_POOL_SLOT_SIZE }>;
    type Buffer = <Pool as crate::bearer::PacketPool>::Buffer;
    type Node = QuicNode<Pool>;
    type IngressPacket<B> = (crate::PacketMeta, OwnedPacket<B>);

    struct Inbox<B>(Mutex<VecDeque<IngressPacket<B>>>);

    impl<B> Default for Inbox<B> {
        fn default() -> Self {
            Self(Mutex::new(VecDeque::new()))
        }
    }

    impl<B: AsRef<[u8]> + Send> PacketIngressQueue<B> for Inbox<B> {
        fn enqueue_packet(&self, meta: crate::PacketMeta, packet: OwnedPacket<B>) {
            self.0.lock().unwrap().push_back((meta, packet));
        }
    }

    static FIRST_POOL: Pool = Pool::new();
    static SECOND_POOL: Pool = Pool::new();
    static BACKPRESSURE_POOL: Pool = Pool::new();
    static BACKPRESSURE_PEER_POOL: Pool = Pool::new();

    #[test]
    fn virtual_time_pair_drives_the_registered_bearer_contract() {
        let config = FakeNetworkConfig {
            first_to_second: FakeLinkProfile {
                latency_us: 20_000,
                jitter_us: 500,
                bitrate_bps: 1_000_000,
                completion_delay_us: 5_000,
                seed: 0x1234,
                ..FakeLinkProfile::default()
            },
            second_to_first: FakeLinkProfile {
                latency_us: 30_000,
                jitter_us: 1_000,
                bitrate_bps: 2_000_000,
                completion_delay_us: 5_000,
                seed: 0x5678,
                ..FakeLinkProfile::default()
            },
            ..FakeNetworkConfig::default()
        };
        let (first_bearer, second_bearer, mut network) =
            FakePacketBearer::<Pool>::pair_with_network(
                BearerName::new("virtual-first").unwrap(),
                BearerName::new("virtual-second").unwrap(),
                config,
            );
        let first_inbox = Arc::new(Inbox::<Buffer>::default());
        let second_inbox = Arc::new(Inbox::<Buffer>::default());
        let mut first = Node::new(&FIRST_POOL);
        let mut second = Node::new(&SECOND_POOL);
        let first_bearer = first
            .register_bearer_with_ingress(first_bearer, first_inbox.clone())
            .unwrap();
        second
            .register_bearer_with_ingress(second_bearer, second_inbox.clone())
            .unwrap();

        let address = crate::PacketMeta {
            bearer: first_bearer,
            peer_l2_address: PeerL2Address::new(1).unwrap(),
            received_at_us: 0,
        };
        let association = first.associate(address, 0).unwrap();
        assert!(second_inbox.0.lock().unwrap().is_empty());

        let completion = network.advance_to(6_000);
        assert_eq!(completion.completions, 1);
        first.drain_bearer_events();
        assert!(second_inbox.0.lock().unwrap().is_empty());

        let delivered = network.advance_to(25_000);
        assert_eq!(delivered.delivered_packets, 1);
        let (meta, packet) = second_inbox.0.lock().unwrap().pop_front().unwrap();
        assert!(meta.received_at_us >= 20_000);
        let accepted = second
            .receive_packet(
                meta,
                packet,
                |_| {
                    Some(InitialAdmission {
                        local_limits: ConnectionLimits::default(),
                    })
                },
                |_, _, _, _, bytes| Ok(bytes.len()),
            )
            .unwrap();
        let response = match accepted {
            NodeIngress::Initial { response, .. } => response,
            _ => panic!("the virtual pair must deliver the Initial through ingress"),
        };
        second.submit_unassociated_packet(response).unwrap();

        network.advance_to(60_000);
        let (meta, packet) = first_inbox.0.lock().unwrap().pop_front().unwrap();
        assert!(meta.received_at_us >= 30_000);
        first
            .receive_packet(meta, packet, |_| None, |_, _, _, _, bytes| Ok(bytes.len()))
            .unwrap();
        assert!(first.association_is_established(association));
        let stats = network.advance_to(70_000);
        assert_eq!(stats.completions, 2);
        assert_eq!(stats.delivered_packets, 2);
    }

    #[test]
    fn queued_packet_rate_adds_serialization_without_repeating_propagation() {
        static RATE_CLIENT_POOL: Pool = Pool::new();
        static RATE_SERVER_POOL: Pool = Pool::new();
        let profile = FakeLinkProfile {
            latency_us: 100_000,
            bitrate_bps: 8_000_000,
            ..FakeLinkProfile::default()
        };
        let (first_bearer, second_bearer, mut network) =
            FakePacketBearer::<Pool>::pair_with_network(
                BearerName::new("rate-first").unwrap(),
                BearerName::new("rate-second").unwrap(),
                FakeNetworkConfig {
                    first_to_second: profile,
                    second_to_first: FakeLinkProfile::default(),
                    ..FakeNetworkConfig::default()
                },
            );
        let capture = first_bearer.sent_packets();
        let first_inbox = Arc::new(Inbox::<Buffer>::default());
        let second_inbox = Arc::new(Inbox::<Buffer>::default());
        let mut first = Node::new(&RATE_CLIENT_POOL);
        let mut second = Node::new(&RATE_SERVER_POOL);
        let first_bearer = first
            .register_bearer_with_ingress(first_bearer, first_inbox)
            .unwrap();
        second
            .register_bearer_with_ingress(second_bearer, second_inbox.clone())
            .unwrap();
        let address = crate::PacketMeta {
            bearer: first_bearer,
            peer_l2_address: PeerL2Address::new(1).unwrap(),
            received_at_us: 0,
        };

        let first_association = first.associate(address, 0).unwrap();
        let first_packet_len = capture.lock().unwrap()[0].len();
        network.advance_to(first_packet_len as u64);
        first.drain_bearer_events();
        let second_association = first.associate(address, first_packet_len as u64).unwrap();
        assert_ne!(first_association, second_association);
        let second_packet_len = capture.lock().unwrap()[1].len();

        network.advance_to(100_000 + first_packet_len as u64 + second_packet_len as u64);
        let first_meta = second_inbox.0.lock().unwrap().pop_front().unwrap().0;
        let second_meta = second_inbox.0.lock().unwrap().pop_front().unwrap().0;
        assert_eq!(
            second_meta.received_at_us - first_meta.received_at_us,
            second_packet_len as u64,
            "the shared direction serializes wire bytes but adds propagation once"
        );
    }

    #[test]
    fn would_block_readiness_retries_the_same_packet_through_the_node() {
        let (first_bearer, second_bearer, mut network) =
            FakePacketBearer::<Pool>::pair_with_network(
                BearerName::new("bp-first").unwrap(),
                BearerName::new("bp-second").unwrap(),
                FakeNetworkConfig {
                    first_to_second: FakeLinkProfile {
                        would_block_every: 2,
                        readiness_delay_us: 10,
                        ..FakeLinkProfile::default()
                    },
                    second_to_first: FakeLinkProfile::default(),
                    ..FakeNetworkConfig::default()
                },
            );
        let attempts = first_bearer.sent_packets();
        let first_inbox = Arc::new(Inbox::<Buffer>::default());
        let second_inbox = Arc::new(Inbox::<Buffer>::default());
        let mut first = Node::new(&BACKPRESSURE_POOL);
        let mut second = Node::new(&BACKPRESSURE_PEER_POOL);
        let bearer = first
            .register_bearer_with_ingress(first_bearer, first_inbox)
            .unwrap();
        second
            .register_bearer_with_ingress(second_bearer, second_inbox)
            .unwrap();
        let address = crate::PacketMeta {
            bearer,
            peer_l2_address: PeerL2Address::new(1).unwrap(),
            received_at_us: 0,
        };

        first.associate(address, 0).unwrap();
        network.advance_to(0);
        first.drain_bearer_events();
        first.associate(address, 1).unwrap();
        let rejected_bytes = attempts.lock().unwrap()[1].clone();
        assert_eq!(network.advance_to(10).would_block, 1);
        assert_eq!(attempts.lock().unwrap().len(), 2);

        first.drain_bearer_events();
        let retried = attempts.lock().unwrap();
        assert_eq!(retried.len(), 3);
        assert_eq!(retried[2], rejected_bytes);
        drop(retried);

        let stats = network.advance_to(10);
        assert_eq!(stats.accepted_submissions, 2);
        assert_eq!(stats.would_block, 1);
        assert_eq!(stats.delivered_packets, 2);
    }

    #[test]
    fn loss_mtu_and_send_outcomes_are_visible_through_bearer_ingress() {
        static FAILURE_CLIENT_POOL: Pool = Pool::new();
        static FAILURE_SERVER_POOL: Pool = Pool::new();
        let cases = [
            (
                "loss-a",
                "loss-b",
                FakeLinkProfile {
                    loss_per_million: 1_000_000,
                    ..FakeLinkProfile::default()
                },
            ),
            (
                "mtu-a",
                "mtu-b",
                FakeLinkProfile {
                    mtu_bytes: 1,
                    ..FakeLinkProfile::default()
                },
            ),
            (
                "fail-a",
                "fail-b",
                FakeLinkProfile {
                    fail_every: 1,
                    ..FakeLinkProfile::default()
                },
            ),
            (
                "maybe-a",
                "maybe-b",
                FakeLinkProfile {
                    indeterminate_every: 1,
                    deliver_indeterminate: true,
                    ..FakeLinkProfile::default()
                },
            ),
        ];
        let first_inbox = Arc::new(Inbox::<Buffer>::default());
        let second_inbox = Arc::new(Inbox::<Buffer>::default());
        let mut first = Node::new(&FAILURE_CLIENT_POOL);
        let mut second = Node::new(&FAILURE_SERVER_POOL);
        let mut paths = Vec::new();
        for (first_name, second_name, profile) in cases {
            let (first_bearer, second_bearer, network) =
                FakePacketBearer::<Pool>::pair_with_network(
                    BearerName::new(first_name).unwrap(),
                    BearerName::new(second_name).unwrap(),
                    FakeNetworkConfig {
                        first_to_second: profile,
                        second_to_first: FakeLinkProfile::default(),
                        ..FakeNetworkConfig::default()
                    },
                );
            let capture = first_bearer.sent_packets();
            let bearer = first
                .register_bearer_with_ingress(first_bearer, first_inbox.clone())
                .unwrap();
            second
                .register_bearer_with_ingress(second_bearer, second_inbox.clone())
                .unwrap();
            paths.push((bearer, network, capture));
        }

        for (bearer, _, _) in &paths {
            first
                .associate(
                    crate::PacketMeta {
                        bearer: *bearer,
                        peer_l2_address: PeerL2Address::new(1).unwrap(),
                        received_at_us: 0,
                    },
                    0,
                )
                .unwrap();
        }
        for (_, network, _) in &mut paths {
            network.advance_to(10);
        }

        assert_eq!(second_inbox.0.lock().unwrap().len(), 1);
        let stats = paths
            .iter_mut()
            .map(|(_, network, _)| network.advance_to(10))
            .collect::<Vec<_>>();
        assert_eq!(stats[0].loss_drops, 1);
        assert_eq!(stats[0].delivered_packets, 0);
        assert_eq!(stats[1].mtu_drops, 1);
        assert_eq!(stats[1].delivered_packets, 0);
        assert_eq!(stats[2].failed_completions, 1);
        assert_eq!(stats[2].delivered_packets, 0);
        assert_eq!(stats[3].indeterminate_completions, 1);
        assert_eq!(stats[3].delivered_packets, 1);
    }

    #[test]
    fn seeded_random_loss_repeats_through_registered_bearers() {
        static SEEDED_ONE_POOL: Pool = Pool::new();
        static SEEDED_TWO_POOL: Pool = Pool::new();
        static PEER_ONE_POOL: Pool = Pool::new();
        static PEER_TWO_POOL: Pool = Pool::new();

        fn delivery_pattern(
            client_pool: &'static Pool,
            peer_pool: &'static Pool,
            client_name: &'static str,
            peer_name: &'static str,
        ) -> Vec<bool> {
            let profile = FakeLinkProfile {
                loss_per_million: 500_000,
                seed: 0x8d31_5a27,
                ..FakeLinkProfile::default()
            };
            let (client_bearer, peer_bearer, mut network) =
                FakePacketBearer::<Pool>::pair_with_network(
                    BearerName::new(client_name).unwrap(),
                    BearerName::new(peer_name).unwrap(),
                    FakeNetworkConfig {
                        first_to_second: profile,
                        ..FakeNetworkConfig::default()
                    },
                );
            let client_ingress = Arc::new(Inbox::<Buffer>::default());
            let peer_ingress = Arc::new(Inbox::<Buffer>::default());
            let mut client = Node::new(client_pool);
            let mut peer = Node::new(peer_pool);
            let bearer = client
                .register_bearer_with_ingress(client_bearer, client_ingress)
                .unwrap();
            peer.register_bearer_with_ingress(peer_bearer, peer_ingress)
                .unwrap();

            let mut pattern = Vec::new();
            for ordinal in 0..16 {
                client
                    .associate(
                        crate::PacketMeta {
                            bearer,
                            peer_l2_address: PeerL2Address::new(1).unwrap(),
                            received_at_us: ordinal,
                        },
                        ordinal,
                    )
                    .unwrap();
                let before = network.stats().delivered_packets;
                let stats = network.advance_to(ordinal);
                pattern.push(stats.delivered_packets != before);
            }
            assert_eq!(network.stats().accepted_submissions, 16);
            pattern
        }

        let first = delivery_pattern(
            &SEEDED_ONE_POOL,
            &PEER_ONE_POOL,
            "seeded-one-c",
            "seeded-one-p",
        );
        let repeated = delivery_pattern(
            &SEEDED_TWO_POOL,
            &PEER_TWO_POOL,
            "seeded-two-c",
            "seeded-two-p",
        );
        assert_eq!(first, repeated, "the same seed must repeat loss decisions");
        assert!(first.iter().any(|delivered| *delivered));
        assert!(first.iter().any(|delivered| !*delivered));
    }

    #[test]
    fn ready_batch_reordering_reaches_peer_in_reverse_submission_order() {
        static REORDER_CLIENT_POOL: Pool = Pool::new();
        static REORDER_SERVER_POOL: Pool = Pool::new();
        let (first_bearer, second_bearer, mut network) =
            FakePacketBearer::<Pool>::pair_with_network(
                BearerName::new("reorder-a").unwrap(),
                BearerName::new("reorder-b").unwrap(),
                FakeNetworkConfig {
                    first_to_second: FakeLinkProfile {
                        latency_us: 100,
                        reorder_ready_batch: true,
                        ..FakeLinkProfile::default()
                    },
                    second_to_first: FakeLinkProfile::default(),
                    ..FakeNetworkConfig::default()
                },
            );
        let capture = first_bearer.sent_packets();
        let first_inbox = Arc::new(Inbox::<Buffer>::default());
        let second_inbox = Arc::new(Inbox::<Buffer>::default());
        let mut first = Node::new(&REORDER_CLIENT_POOL);
        let mut second = Node::new(&REORDER_SERVER_POOL);
        let bearer = first
            .register_bearer_with_ingress(first_bearer, first_inbox)
            .unwrap();
        second
            .register_bearer_with_ingress(second_bearer, second_inbox.clone())
            .unwrap();
        let address = crate::PacketMeta {
            bearer,
            peer_l2_address: PeerL2Address::new(1).unwrap(),
            received_at_us: 0,
        };
        first.associate(address, 0).unwrap();
        network.advance_to(0);
        first.drain_bearer_events();
        first.associate(address, 0).unwrap();
        let sent = capture.lock().unwrap().clone();
        assert_eq!(sent.len(), 2);

        let stats = network.advance_to(100);
        assert_eq!(stats.delivered_packets, 2);
        let received = second_inbox.0.lock().unwrap();
        assert_eq!(received[0].1.bytes(), sent[1]);
        assert_eq!(received[1].1.bytes(), sent[0]);
    }

    #[test]
    fn separate_bearer_pairs_share_one_physical_serialization_bottleneck() {
        static CLIENT_ONE_POOL: Pool = Pool::new();
        static PEER_ONE_POOL: Pool = Pool::new();
        static CLIENT_TWO_POOL: Pool = Pool::new();
        static PEER_TWO_POOL: Pool = Pool::new();
        let shared_link = FakeSharedLink::new(8_000_000);
        let path_profile = FakeLinkProfile::default();
        let (client_one_bearer, peer_one_bearer, mut path_one) =
            FakePacketBearer::<Pool>::pair_with_network(
                BearerName::new("share-one-c").unwrap(),
                BearerName::new("share-one-p").unwrap(),
                FakeNetworkConfig {
                    first_to_second: path_profile,
                    first_to_second_shared_link: Some(shared_link.clone()),
                    ..FakeNetworkConfig::default()
                },
            );
        let (client_two_bearer, peer_two_bearer, mut path_two) =
            FakePacketBearer::<Pool>::pair_with_network(
                BearerName::new("share-two-c").unwrap(),
                BearerName::new("share-two-p").unwrap(),
                FakeNetworkConfig {
                    first_to_second: path_profile,
                    first_to_second_shared_link: Some(shared_link.clone()),
                    ..FakeNetworkConfig::default()
                },
            );
        let packet_one = client_one_bearer.sent_packets();
        let packet_two = client_two_bearer.sent_packets();
        let client_one_inbox = Arc::new(Inbox::<Buffer>::default());
        let peer_one_inbox = Arc::new(Inbox::<Buffer>::default());
        let client_two_inbox = Arc::new(Inbox::<Buffer>::default());
        let peer_two_inbox = Arc::new(Inbox::<Buffer>::default());
        let mut client_one = Node::new(&CLIENT_ONE_POOL);
        let mut peer_one = Node::new(&PEER_ONE_POOL);
        let mut client_two = Node::new(&CLIENT_TWO_POOL);
        let mut peer_two = Node::new(&PEER_TWO_POOL);
        let bearer_one = client_one
            .register_bearer_with_ingress(client_one_bearer, client_one_inbox)
            .unwrap();
        peer_one
            .register_bearer_with_ingress(peer_one_bearer, peer_one_inbox.clone())
            .unwrap();
        let bearer_two = client_two
            .register_bearer_with_ingress(client_two_bearer, client_two_inbox)
            .unwrap();
        peer_two
            .register_bearer_with_ingress(peer_two_bearer, peer_two_inbox.clone())
            .unwrap();
        let address_one = crate::PacketMeta {
            bearer: bearer_one,
            peer_l2_address: PeerL2Address::new(1).unwrap(),
            received_at_us: 0,
        };
        let address_two = crate::PacketMeta {
            bearer: bearer_two,
            peer_l2_address: PeerL2Address::new(1).unwrap(),
            received_at_us: 0,
        };
        client_one.associate(address_one, 0).unwrap();
        client_two.associate(address_two, 0).unwrap();
        let first_len = packet_one.lock().unwrap()[0].len();
        let second_len = packet_two.lock().unwrap()[0].len();
        assert_eq!(shared_link.stats().packets, 2);
        assert_eq!(shared_link.stats().bytes, (first_len + second_len) as u64);
        assert_eq!(
            shared_link.stats().busy_until_us,
            (first_len + second_len) as u64,
            "8 Mbps serializes each wire byte once across both bearer pairs"
        );

        path_one.advance_to(first_len as u64 - 1);
        assert!(peer_one_inbox.0.lock().unwrap().is_empty());
        assert!(peer_two_inbox.0.lock().unwrap().is_empty());
        path_one.advance_to(first_len as u64);
        assert_eq!(peer_one_inbox.0.lock().unwrap().len(), 1);
        path_two.advance_to((first_len + second_len) as u64 - 1);
        assert!(peer_two_inbox.0.lock().unwrap().is_empty());
        path_two.advance_to((first_len + second_len) as u64);
        assert_eq!(peer_two_inbox.0.lock().unwrap().len(), 1);
    }
}
