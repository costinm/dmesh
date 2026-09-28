//! In-memory packet bearer for public `QuicNode` tests.
//!
//! It uses the same attach, ingress, submission, and completion contracts as
//! physical bearers and does not expose a second connection or stream driver.

#[cfg(test)]
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::vec::Vec;

#[cfg(test)]
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
    pool: core::marker::PhantomData<fn() -> P>,
}

struct FakePair<P: PacketPool + 'static> {
    contexts: [Option<BearerContext<P>>; 2],
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
        self.info
    }

    fn attach(&mut self, context: BearerContext<P>) -> Result<(), Self::AttachError> {
        if let Some((pair, side)) = &self.pair {
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
    queue: VecDeque<FaultPacket>,
    sent: u64,
}

#[cfg(test)]
impl FaultQueue {
    pub(crate) fn new(config: FaultConfig) -> Self {
        Self {
            config,
            queue: VecDeque::new(),
            sent: 0,
        }
    }

    pub(crate) fn submit_at(&mut self, now: u64, payload: &[u8]) -> Result<(), crate::Error> {
        self.sent = self.sent.saturating_add(1);
        if self
            .config
            .drop_every
            .is_some_and(|n| n != 0 && self.sent % n == 0)
        {
            return Ok(());
        }
        let mut bytes = payload.to_vec();
        bytes.truncate(self.config.mtu);
        let packet = FaultPacket {
            ready_at: now.saturating_add(self.config.latency_ticks),
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
