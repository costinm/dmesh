//! Immediate node driving for platforms without an async executor.
//!
//! Bearer registration, packet storage, readiness, completion, and physical
//! submission are common [`crate::QuicNode`] behavior. This module only turns
//! one synchronously received bearer packet into node progress and retains the
//! resulting application association/stream events.

use alloc::{boxed::Box, collections::VecDeque, sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicUsize, Ordering};
use spin::Mutex;

use crate::node::{
    ApplicationStreamSource, InitialAdmission, NodeIngress, QuicNodePacketRejection,
};
use crate::{
    AddBearerError, ConnectionLimits, OwnedPacket, PacketBearer, PacketMeta, PacketPool,
    QuicAssociation, QuicNode, QuicNodeEgressError, ReceivedStreamChunk,
};

struct IngressQueue<B> {
    packets: Mutex<VecDeque<crate::bearer::ReceivedPacket<B>>>,
    capacity: usize,
    enqueue_drops: AtomicUsize,
}

impl<B> IngressQueue<B> {
    fn new(capacity: usize) -> Self {
        Self {
            packets: Mutex::new(VecDeque::with_capacity(capacity)),
            capacity,
            enqueue_drops: AtomicUsize::new(0),
        }
    }

    fn pop(&self) -> Option<crate::bearer::ReceivedPacket<B>> {
        self.packets.lock().pop_front()
    }

    fn take_enqueue_drops(&self) -> usize {
        self.enqueue_drops.swap(0, Ordering::AcqRel)
    }
}

impl<B: AsRef<[u8]> + Send> crate::bearer::PacketIngressQueue<B> for IngressQueue<B> {
    fn enqueue_packet(&self, meta: PacketMeta, packet: OwnedPacket<B>) {
        // A physical receive callback can preempt the node owner while it
        // briefly holds this queue lock. Spinning in that callback would
        // deadlock a single-core target, so contention is treated like a
        // dropped UDP/UART datagram and left to QUIC retransmission.
        let Some(mut packets) = self.packets.try_lock() else {
            self.enqueue_drops.fetch_add(1, Ordering::Relaxed);
            drop(packet);
            return;
        };
        if packets.len() == self.capacity {
            self.enqueue_drops.fetch_add(1, Ordering::Relaxed);
            drop(packet);
        } else {
            packets.push_back(crate::bearer::ReceivedPacket { meta, packet });
        }
    }
}

/// Synchronous application adapter around one common QUIC node.
///
/// This type contains no bearer registry, packet pool, ingress queue, or
/// physical submission callback. Those remain owned by `QuicNode` and the
/// common bearer interface.
pub struct NoStdRuntime<
    P: PacketPool + 'static,
    const PACKET: usize = { crate::DEFAULT_MAX_PACKET_SIZE },
> {
    node: QuicNode<P, PACKET>,
    limits: ConnectionLimits,
    ingress: Arc<IngressQueue<P::Buffer>>,
    accepted: VecDeque<QuicAssociation>,
    streams: VecDeque<ReceivedStreamChunk>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bearer::PacketIngressQueue;
    use crate::fake::{FakeLinkProfile, FakeNetworkConfig, FakePacketBearer, FakeSharedLink};
    use crate::packet_pool::PacketPool as FixedPool;
    use crate::{
        BearerContext, BearerInfo, BearerName, CircuitInfo, EgressSubmission, PacketBearer,
        PacketEgress, PacketSendOutcome, PacketSubmitError, PeerL2Address,
    };
    use core::sync::atomic::{AtomicBool, Ordering};
    use std::eprintln;
    use std::sync::{Arc, Mutex};

    type Pool = FixedPool<4, { crate::DEFAULT_PACKET_POOL_SLOT_SIZE }>;
    static POOL: Pool = Pool::new();
    type BaselinePool = FixedPool<16, { crate::DEFAULT_PACKET_POOL_SLOT_SIZE }>;
    static BASELINE_CLIENT_POOL: BaselinePool = BaselinePool::new();
    static BASELINE_SERVER_POOL: BaselinePool = BaselinePool::new();
    static TIMER_CLIENT_POOL: BaselinePool = BaselinePool::new();
    static TIMER_SERVER_POOL: BaselinePool = BaselinePool::new();
    type MultipathPool = FixedPool<32, { crate::DEFAULT_PACKET_POOL_SLOT_SIZE }>;
    static MULTIPATH_CLIENT_POOL: MultipathPool = MultipathPool::new();
    static MULTIPATH_SERVER_POOL: MultipathPool = MultipathPool::new();
    type PtoPool = FixedPool<32, { crate::DEFAULT_PACKET_POOL_SLOT_SIZE }>;
    static PTO_CLIENT_POOL: PtoPool = PtoPool::new();
    static PTO_SERVER_POOL: PtoPool = PtoPool::new();
    type FairnessPool =
        crate::heap_packet_pool::HeapPacketPool<128, { crate::DEFAULT_PACKET_POOL_SLOT_SIZE }>;
    static FAIR_TARGET_POOL: FairnessPool = FairnessPool::new();
    static FAIR_COMPETITOR_POOL: FairnessPool = FairnessPool::new();
    static FAIR_TARGET_SERVER_POOL: FairnessPool = FairnessPool::new();
    static FAIR_COMPETITOR_SERVER_POOL: FairnessPool = FairnessPool::new();

    struct Probe {
        context: Arc<Mutex<Option<BearerContext<Pool>>>>,
        forwarded: Option<Arc<Mutex<Vec<(PeerL2Address, Vec<u8>)>>>>,
    }

    impl PacketEgress<<Pool as PacketPool>::Buffer> for Probe {
        fn submit(
            &mut self,
            peer: PeerL2Address,
            submission: EgressSubmission<<Pool as PacketPool>::Buffer>,
        ) -> Result<(), PacketSubmitError<<Pool as PacketPool>::Buffer>> {
            if let Some(forwarded) = &self.forwarded {
                forwarded
                    .lock()
                    .unwrap()
                    .push((peer, submission.packet().bytes().to_vec()));
            }
            submission.complete(PacketSendOutcome::Sent, 0);
            Ok(())
        }
    }

    impl PacketBearer<Pool> for Probe {
        type AttachError = core::convert::Infallible;

        fn info(&self) -> BearerInfo {
            BearerInfo {
                name: BearerName::new("uart0").unwrap(),
                max_packet_size: crate::DEFAULT_MAX_PACKET_SIZE,
                prefix_required: crate::PACKET_PREFIX_RESERVE,
                suffix_required: 0,
                requires_packet_encryption: false,
                secure_link: false,
                nominal_bitrate_bps: 115_200,
                local_mac: None,
            }
        }

        fn attach(&mut self, context: BearerContext<Pool>) -> Result<(), Self::AttachError> {
            *self.context.lock().unwrap() = Some(context);
            Ok(())
        }
    }

    struct ToggleBlocker {
        context: Arc<Mutex<Option<BearerContext<Pool>>>>,
        blocked: Arc<AtomicBool>,
    }

    impl PacketEgress<<Pool as PacketPool>::Buffer> for ToggleBlocker {
        fn submit(
            &mut self,
            _peer: PeerL2Address,
            submission: EgressSubmission<<Pool as PacketPool>::Buffer>,
        ) -> Result<(), PacketSubmitError<<Pool as PacketPool>::Buffer>> {
            if self.blocked.load(Ordering::Acquire) {
                return Err(PacketSubmitError::WouldBlock(submission));
            }
            submission.complete(PacketSendOutcome::Sent, 0);
            Ok(())
        }
    }

    impl PacketBearer<Pool> for ToggleBlocker {
        type AttachError = core::convert::Infallible;

        fn info(&self) -> BearerInfo {
            BearerInfo {
                name: BearerName::new("blocked").unwrap(),
                max_packet_size: crate::DEFAULT_MAX_PACKET_SIZE,
                prefix_required: crate::PACKET_PREFIX_RESERVE,
                suffix_required: 0,
                requires_packet_encryption: false,
                secure_link: false,
                nominal_bitrate_bps: 115_200,
                local_mac: None,
            }
        }

        fn attach(&mut self, context: BearerContext<Pool>) -> Result<(), Self::AttachError> {
            *self.context.lock().unwrap() = Some(context);
            Ok(())
        }
    }

    #[test]
    fn immediate_driver_uses_registered_bearer_pool_without_ingress_queue() {
        let retained = Arc::new(Mutex::new(None));
        let node = QuicNode::<Pool>::new(&POOL);
        let mut driver = NoStdRuntime::new(node, ConnectionLimits::default());
        let bearer = driver
            .add_bearer(Probe {
                context: retained.clone(),
                forwarded: None,
            })
            .unwrap();
        let context = retained.lock().unwrap().clone().unwrap();
        let mut writer =
            PacketPool::acquire_writer(context.pool(), crate::PACKET_PREFIX_RESERVE, 0).unwrap();
        writer.payload_mut()[0] = 0;
        let packet = crate::PacketWriter::commit(writer, 1).unwrap();
        context.enqueue_packet(
            PacketMeta {
                bearer,
                peer_l2_address: PeerL2Address::new(1).unwrap(),
                received_at_us: 1,
            },
            packet,
        );
        assert!(driver.progress().unwrap());
        assert!(driver.next_association().is_none());
        assert!(driver.next_stream_chunk().is_none());
    }

    #[test]
    fn ingress_callback_drops_on_lock_contention_instead_of_spinning() {
        let queue = IngressQueue::new(1);
        let mut writer =
            PacketPool::acquire_writer(&POOL, crate::PACKET_PREFIX_RESERVE, 0).unwrap();
        writer.payload_mut()[0] = 0;
        let packet = crate::PacketWriter::commit(writer, 1).unwrap();
        let guard = queue.packets.lock();

        crate::bearer::PacketIngressQueue::enqueue_packet(
            &queue,
            PacketMeta {
                bearer: crate::BearerId::new(1).unwrap(),
                peer_l2_address: PeerL2Address::new(1).unwrap(),
                received_at_us: 1,
            },
            packet,
        );

        assert_eq!(queue.take_enqueue_drops(), 1);
        drop(guard);
        assert!(queue.pop().is_none());
    }

    #[test]
    fn blocked_egress_pauses_ingress_until_bearer_readiness() {
        let context = Arc::new(Mutex::new(None));
        let blocked = Arc::new(AtomicBool::new(true));
        let node = QuicNode::<Pool>::new(&POOL);
        let mut driver = NoStdRuntime::new(node, ConnectionLimits::default());
        let bearer = driver
            .add_bearer(ToggleBlocker {
                context: context.clone(),
                blocked: blocked.clone(),
            })
            .unwrap();
        let peer = PeerL2Address::new(1).unwrap();

        let mut writer =
            PacketPool::acquire_writer(&POOL, crate::PACKET_PREFIX_RESERVE, 0).unwrap();
        writer.payload_mut()[0] = 1;
        let packet = crate::PacketWriter::commit(writer, 1).unwrap();
        driver
            .node
            .submit_egress(bearer, peer, packet)
            .expect("first blocked send is retained by the bearer registry");

        // A second egress must be rejected without panicking or disturbing
        // the first exact lease retained for retry.
        let mut writer =
            PacketPool::acquire_writer(&POOL, crate::PACKET_PREFIX_RESERVE, 0).unwrap();
        writer.payload_mut()[0] = 2;
        let second_packet = crate::PacketWriter::commit(writer, 1).unwrap();
        assert!(matches!(
            driver.node.submit_egress(bearer, peer, second_packet),
            Err(QuicNodeEgressError::BearerBusy)
        ));

        let mut writer =
            PacketPool::acquire_writer(&POOL, crate::PACKET_PREFIX_RESERVE, 0).unwrap();
        writer.payload_mut()[0] = 0;
        let packet = crate::PacketWriter::commit(writer, 1).unwrap();
        driver.ingress.enqueue_packet(
            PacketMeta {
                bearer,
                peer_l2_address: peer,
                received_at_us: 1,
            },
            packet,
        );

        assert!(!driver.progress().unwrap());
        assert_eq!(driver.ingress.packets.lock().len(), 1);

        blocked.store(false, Ordering::Release);
        context.lock().unwrap().as_ref().unwrap().send_ready();
        // Retry is accepted and completes synchronously; consume that queued
        // completion before allowing the retained ingress packet to proceed.
        assert!(
            !driver
                .progress_with_stream(|_, _, _, bytes| Ok(bytes.len()))
                .unwrap()
        );
        assert!(
            driver
                .progress_with_stream(|_, _, _, bytes| Ok(bytes.len()))
                .unwrap()
        );
        assert!(driver.ingress.packets.lock().is_empty());
    }

    #[test]
    fn immediate_driver_starts_client_association_without_exposing_role_state() {
        let retained = Arc::new(Mutex::new(None));
        let node = QuicNode::<Pool>::new(&POOL);
        let mut driver = NoStdRuntime::new(node, ConnectionLimits::default());
        let bearer = driver
            .add_bearer(Probe {
                context: retained,
                forwarded: None,
            })
            .unwrap();
        let address = PacketMeta {
            bearer,
            peer_l2_address: PeerL2Address::new(9).unwrap(),
            received_at_us: 10,
        };
        let association = driver.associate(address, 10).unwrap();

        assert!(!driver.association_is_established(association));
        assert!(driver.open_stream(association).is_err());
        assert!(driver.next_association().is_none());
    }

    #[test]
    fn boxed_runtime_initializes_in_final_storage() {
        let mut runtime =
            NoStdRuntime::<Pool>::try_new_boxed(&POOL, ConnectionLimits::default()).unwrap();
        let retained = Arc::new(Mutex::new(None));
        assert!(
            runtime
                .add_bearer(Probe {
                    context: retained.clone(),
                    forwarded: None,
                })
                .is_ok()
        );
        assert!(retained.lock().unwrap().is_some());
    }

    #[test]
    fn virtual_single_path_stream_baseline_reports_delivery_rtt_and_peak_leases() {
        run_virtual_single_path_stream_baseline(false);
    }

    #[test]
    fn virtual_single_path_stream_survives_burst_loss_and_blocked_submissions() {
        run_virtual_single_path_stream_baseline(true);
    }

    fn run_virtual_single_path_stream_baseline(burst_loss: bool) {
        let profile = FakeLinkProfile {
            latency_us: 3_000,
            bitrate_bps: 4_000_000,
            completion_delay_us: 500,
            // Exercise the same temporary no-capacity edge reported by a
            // packet-at-a-time physical bearer, including the server's
            // application-consumption/flow-control path.
            would_block_every: 7,
            readiness_delay_us: 1_000,
            seed: 0x51a9,
            ..FakeLinkProfile::default()
        };
        let (client_bearer, server_bearer, mut network) =
            FakePacketBearer::<BaselinePool>::pair_with_network(
                BearerName::new("baseline-c").unwrap(),
                BearerName::new("baseline-s").unwrap(),
                FakeNetworkConfig {
                    first_to_second: profile,
                    second_to_first: FakeLinkProfile {
                        loss_burst_start_packet: if burst_loss { 10 } else { 0 },
                        loss_burst_packets: if burst_loss { 3 } else { 0 },
                        would_block_every: 7,
                        readiness_delay_us: 1_000,
                        ..profile
                    },
                    ..FakeNetworkConfig::default()
                },
            );
        let mut client: NoStdRuntime<BaselinePool> = NoStdRuntime::new(
            QuicNode::<BaselinePool>::new(&BASELINE_CLIENT_POOL),
            ConnectionLimits::default(),
        );
        let mut server: NoStdRuntime<BaselinePool> = NoStdRuntime::new(
            QuicNode::<BaselinePool>::new(&BASELINE_SERVER_POOL),
            ConnectionLimits::default(),
        );
        let client_bearer = client.add_bearer(client_bearer).unwrap();
        server.add_bearer(server_bearer).unwrap();
        let association = client
            .associate(
                PacketMeta {
                    bearer: client_bearer,
                    peer_l2_address: PeerL2Address::new(1).unwrap(),
                    received_at_us: 0,
                },
                0,
            )
            .unwrap();

        let payload = (0..8192)
            .map(|index| (index % 251) as u8)
            .collect::<Vec<_>>();
        let mut received = Vec::with_capacity(payload.len());
        let mut received_fin = false;
        let mut received_at_us = None;
        let mut stream = None;
        let mut sent = 0usize;
        let mut fin_sent = false;
        let mut transfer_started_at_us = None;
        let mut peak_client_leases = 0usize;
        let mut peak_server_leases = 0usize;
        let mut now_us = 0u64;
        let mut completed_at_us = None;

        for _ in 0..20_000 {
            network.advance_to(now_us);
            client.advance_time(now_us).unwrap();
            server.advance_time(now_us).unwrap();
            client.progress_all().unwrap();
            server
                .progress_all_with_stream(|_, offset, fin, bytes| {
                    if offset != received.len() as u64 {
                        return Err(crate::Error::Invalid);
                    }
                    received.extend_from_slice(bytes);
                    received_fin |= fin;
                    if fin {
                        received_at_us = Some(now_us);
                    }
                    Ok(bytes.len())
                })
                .unwrap();

            if client.association_is_established(association) && stream.is_none() {
                stream = Some(client.open_stream(association).unwrap());
            }
            if let Some(stream) = stream.as_mut() {
                if sent < payload.len() {
                    match client.write_stream(stream, &payload[sent..]) {
                        Ok(count) => {
                            if count != 0 {
                                transfer_started_at_us.get_or_insert(now_us);
                                sent += count;
                            }
                        }
                        Err(error) if error.is_retryable() => {}
                        Err(error) => panic!("baseline stream write failed: {error:?}"),
                    }
                } else if !fin_sent {
                    match client.finish_stream(stream) {
                        Ok(()) => fin_sent = true,
                        Err(error) if error.is_retryable() => {}
                        Err(error) => panic!("baseline FIN failed: {error:?}"),
                    }
                }
            }

            peak_client_leases = peak_client_leases.max(
                client
                    .node
                    .packet_capacity()
                    .saturating_sub(client.node.available_packets()),
            );
            peak_server_leases = peak_server_leases.max(
                server
                    .node
                    .packet_capacity()
                    .saturating_sub(server.node.available_packets()),
            );

            let mut circuits = [CircuitInfo::default(); 1];
            client.circuits(association, &mut circuits);
            let fully_drained = circuits[0].bytes_in_flight == 0
                && network.stats().accepted_submissions == network.stats().completions;
            if received_fin && fully_drained {
                completed_at_us = received_at_us;
                break;
            }
            now_us = now_us.saturating_add(1_000);
        }

        assert_eq!(sent, payload.len());
        assert!(fin_sent, "sender must submit FIN");
        assert!(received_fin, "peer must receive FIN before the deadline");
        assert_eq!(received, payload);
        let transfer_started_at_us = transfer_started_at_us.unwrap();
        let completed_at_us = completed_at_us.unwrap();
        let elapsed_us = completed_at_us.saturating_sub(transfer_started_at_us);
        let goodput_bps = (received.len() as u64)
            .saturating_mul(8_000_000)
            .checked_div(elapsed_us.max(1))
            .unwrap();
        let mut circuits = [CircuitInfo::default(); 1];
        assert_eq!(client.circuits(association, &mut circuits), 1);
        let stats = network.stats();
        if burst_loss {
            assert_eq!(stats.loss_drops, 3);
            assert!(circuits[0].retransmitted_packets > 0);
        } else {
            assert_eq!(circuits[0].packets_lost, 0);
            assert_eq!(circuits[0].spurious_losses, 0);
            assert_eq!(circuits[0].retransmitted_packets, 0);
            assert_eq!(circuits[0].packets_duplicated, 0);
        }
        assert!(circuits[0].srtt_us > 0, "handshake should establish RTT");
        assert_eq!(stats.accepted_submissions, stats.completions);
        assert_eq!(stats.failed_completions, 0);
        assert!(peak_client_leases > 0 && peak_server_leases > 0);

        eprintln!(
            "P0 baseline burst_loss={} seed=0x51a9 rtt_us={} unique_delivered_bytes={} fin=true elapsed_us={} goodput_bps={} packets_lost={} retransmissions={} spurious_losses={} duplicate_packets={} peak_client_leases={} peak_server_leases={} delivered_packets={} accepted={} completed={}",
            burst_loss,
            circuits[0].srtt_us,
            received.len(),
            elapsed_us,
            goodput_bps,
            circuits[0].packets_lost,
            circuits[0].retransmitted_packets,
            circuits[0].spurious_losses,
            circuits[0].packets_duplicated,
            peak_client_leases,
            peak_server_leases,
            stats.delivered_packets,
            stats.accepted_submissions,
            stats.completions,
        );
    }

    #[test]
    fn virtual_loss_baseline_retries_initial_at_the_transport_deadline() {
        let (client_bearer, server_bearer, mut network) =
            FakePacketBearer::<BaselinePool>::pair_with_network(
                BearerName::new("timer-client").unwrap(),
                BearerName::new("timer-server").unwrap(),
                FakeNetworkConfig {
                    first_to_second: FakeLinkProfile {
                        loss_per_million: 1_000_000,
                        seed: 0x7a31,
                        ..FakeLinkProfile::default()
                    },
                    ..FakeNetworkConfig::default()
                },
            );
        let captured = client_bearer.sent_packets();
        let mut client: NoStdRuntime<BaselinePool> = NoStdRuntime::new(
            QuicNode::<BaselinePool>::new(&TIMER_CLIENT_POOL),
            ConnectionLimits::default(),
        );
        let mut server: NoStdRuntime<BaselinePool> = NoStdRuntime::new(
            QuicNode::<BaselinePool>::new(&TIMER_SERVER_POOL),
            ConnectionLimits::default(),
        );
        let bearer = client.add_bearer(client_bearer).unwrap();
        server.add_bearer(server_bearer).unwrap();
        let association = client
            .associate(
                PacketMeta {
                    bearer,
                    peer_l2_address: PeerL2Address::new(1).unwrap(),
                    received_at_us: 0,
                },
                0,
            )
            .unwrap();
        assert!(!client.association_is_established(association));
        assert_eq!(captured.lock().unwrap().len(), 1);

        network.advance_to(0);
        client.progress_all().unwrap();
        let retry_at_us = client.next_deadline().expect("Initial retry deadline");
        assert!(retry_at_us > 1);
        network.advance_to(retry_at_us - 1);
        client.advance_time(retry_at_us - 1).unwrap();
        assert_eq!(captured.lock().unwrap().len(), 1);

        network.advance_to(retry_at_us);
        client.advance_time(retry_at_us).unwrap();
        assert_eq!(captured.lock().unwrap().len(), 2);
        network.advance_to(retry_at_us);
        client.progress_all().unwrap();
        assert_eq!(network.stats().loss_drops, 2);
        assert_eq!(network.stats().accepted_submissions, 2);
        assert_eq!(network.stats().completions, 2);
        assert!(!client.association_is_established(association));
    }

    #[test]
    fn direct_20ms_and_60ms_circuits_deliver_without_skew_loss_and_recover_burst_loss() {
        run_direct_two_path_stream(false, false, false, false, false, false, false, false, 0);
        run_direct_two_path_stream(true, false, false, false, false, false, false, false, 0);
        run_direct_two_path_stream(false, true, false, false, false, false, false, false, 0);
        run_direct_two_path_stream(false, false, true, false, false, false, false, false, 0);
        run_direct_two_path_stream(false, false, false, false, true, false, false, false, 0);
        run_direct_two_path_stream(false, false, false, false, false, true, false, false, 0);
        run_direct_two_path_stream(false, false, false, true, false, false, false, false, 0);
    }

    #[test]
    fn p5_full_size_only_mtu_path_is_rejected_by_delivery_measurements() {
        run_direct_two_path_stream(false, false, false, false, false, false, true, false, 0);
    }

    #[test]
    fn p5_seeded_rate_rtt_loss_matrix_delivers_with_bearer_repair() {
        run_direct_two_path_stream(false, false, false, false, false, false, false, false, 1);
        run_direct_two_path_stream(false, false, false, false, false, false, false, false, 2);
    }

    #[test]
    fn p5_prioritized_control_uses_a_proactive_copy_after_primary_path_loss() {
        run_direct_two_path_stream(false, false, false, false, false, false, false, true, 0);
    }

    #[test]
    fn p5_pto_repair_uses_only_one_packet_of_destination_window_allowance() {
        type Runtime = NoStdRuntime<PtoPool>;
        let fast_profile = FakeLinkProfile {
            latency_us: 10_000,
            bitrate_bps: 20_000_000,
            seed: 0x5050,
            ..FakeLinkProfile::default()
        };
        let slow_profile = FakeLinkProfile {
            latency_us: 30_000,
            bitrate_bps: 20_000_000,
            seed: 0x6060,
            ..FakeLinkProfile::default()
        };
        let (client_fast, server_fast, mut fast_network) =
            FakePacketBearer::<PtoPool>::pair_with_network(
                BearerName::new("pto-fast-c").unwrap(),
                BearerName::new("pto-fast-s").unwrap(),
                FakeNetworkConfig {
                    first_to_second: fast_profile,
                    second_to_first: fast_profile,
                    ..FakeNetworkConfig::default()
                },
            );
        let (client_slow, server_slow, mut slow_network) =
            FakePacketBearer::<PtoPool>::pair_with_network(
                BearerName::new("pto-slow-c").unwrap(),
                BearerName::new("pto-slow-s").unwrap(),
                FakeNetworkConfig {
                    first_to_second: slow_profile,
                    second_to_first: slow_profile,
                    ..FakeNetworkConfig::default()
                },
            );
        let mut client = Runtime::new(
            QuicNode::<PtoPool>::new(&PTO_CLIENT_POOL),
            ConnectionLimits::default(),
        );
        let mut server = Runtime::new(
            QuicNode::<PtoPool>::new(&PTO_SERVER_POOL),
            ConnectionLimits::default(),
        );
        let client_fast = client.add_bearer(client_fast).unwrap();
        let client_slow = client.add_bearer(client_slow).unwrap();
        server.add_bearer(server_fast).unwrap();
        server.add_bearer(server_slow).unwrap();
        let association = client
            .associate(
                PacketMeta {
                    bearer: client_fast,
                    peer_l2_address: PeerL2Address::new(1).unwrap(),
                    received_at_us: 0,
                },
                0,
            )
            .unwrap();
        let mut now_us = 0u64;
        let mut circuits = [CircuitInfo::default(); 2];
        let mut ready = false;
        let mut received = Vec::new();
        let mut received_fin = false;
        let mut slow_circuit_created = false;
        for _ in 0..2_000 {
            fast_network.advance_to(now_us);
            slow_network.advance_to(now_us);
            client.advance_time(now_us).unwrap();
            server.advance_time(now_us).unwrap();
            client.progress_all().unwrap();
            server.progress_all().unwrap();
            while let Some(chunk) = server.next_stream_chunk() {
                assert_eq!(chunk.offset, received.len() as u64);
                received.extend_from_slice(&chunk.bytes);
                received_fin |= chunk.fin;
            }
            while server.next_association().is_some() {}
            if client.association_is_established(association) && !slow_circuit_created {
                client
                    .add_direct_circuit(
                        association,
                        crate::CircuitNextHop {
                            bearer: client_slow,
                            peer_l2_address: PeerL2Address::new(1).unwrap(),
                        },
                        now_us,
                    )
                    .unwrap();
                slow_circuit_created = true;
            }
            let count = client.circuits(association, &mut circuits);
            if count == 2
                && circuits[..2]
                    .iter()
                    .all(|circuit| circuit.status == crate::CircuitStatus::Active)
                && circuits[..2]
                    .iter()
                    .all(|circuit| circuit.bytes_in_flight == 0)
            {
                ready = true;
                break;
            }
            now_us += 1_000;
        }
        assert!(
            ready,
            "both direct bearer paths must validate and drain: now={now_us} circuits={circuits:?} fast={:?} slow={:?}",
            fast_network.stats(),
            slow_network.stats()
        );
        assert!(client.node.set_path_window_for_test(association, 1, 1));
        let pto_timeout_us = client
            .node
            .path_pto_timeout_for_test(association, 0)
            .unwrap();
        let mut stream = client.open_stream(association).unwrap();
        let payload = b"PTO destination window";
        assert_eq!(
            client.write_stream_and_finish(&mut stream, payload),
            Ok(payload.len())
        );
        let primary_reverse_loss = FakeLinkProfile {
            loss_burst_start_packet: 1,
            loss_burst_packets: u64::MAX,
            ..fast_profile
        };
        fast_network.set_second_to_first_profile(primary_reverse_loss);

        let mut pto_retransmissions = 0u64;
        let mut peak_pto_flight = 0u32;
        let mut peak_pto_window_excess = 0u32;
        for _ in 0..2_000 {
            fast_network.advance_to(now_us);
            slow_network.advance_to(now_us);
            client.advance_time(now_us).unwrap();
            server.advance_time(now_us).unwrap();
            client.progress_all().unwrap();
            server.progress_all().unwrap();
            while let Some(chunk) = server.next_stream_chunk() {
                assert_eq!(chunk.offset, received.len() as u64);
                received.extend_from_slice(&chunk.bytes);
                received_fin |= chunk.fin;
            }
            pto_retransmissions = client
                .node
                .pto_retransmissions_for_test(association)
                .unwrap();
            if pto_retransmissions != 0 {
                client.circuits(association, &mut circuits);
                peak_pto_flight = peak_pto_flight.max(circuits[1].bytes_in_flight);
                peak_pto_window_excess = peak_pto_window_excess.max(
                    circuits[1]
                        .bytes_in_flight
                        .saturating_sub(circuits[1].cwnd_bytes),
                );
            }
            if pto_retransmissions != 0
                && received_fin
                && circuits[1].bytes_in_flight == 0
                && slow_network.stats().accepted_submissions == slow_network.stats().completions
            {
                break;
            }
            now_us += 1_000;
        }
        assert_eq!(received, payload);
        assert!(received_fin);
        assert!(
            pto_retransmissions > 0,
            "the lost primary ACK must trigger PTO repair"
        );
        assert!(
            peak_pto_flight > 1,
            "PTO repair must exceed the one-byte destination window"
        );
        assert!(
            peak_pto_window_excess <= crate::DEFAULT_MAX_PACKET_SIZE as u32,
            "PTO repair exceeded the explicit single-packet allowance: {peak_pto_window_excess}"
        );
        assert!(slow_network.stats().delivered_packets > 0);
        assert_eq!(
            fast_network.stats().accepted_submissions,
            fast_network.stats().completions
        );
        assert_eq!(
            slow_network.stats().accepted_submissions,
            slow_network.stats().completions
        );
        eprintln!(
            "P5 PTO destination_window=1 pto_retransmissions={pto_retransmissions} destination_peak_flight={peak_pto_flight} destination_peak_excess={peak_pto_window_excess} packet_allowance={} pto_us={pto_timeout_us} delivered_bytes={} fin=true",
            crate::DEFAULT_MAX_PACKET_SIZE,
            received.len(),
        );
    }

    #[test]
    fn p5_two_circuit_association_shares_bottleneck_with_competing_single_circuit() {
        let single_circuit_ratio = run_p5_shared_bottleneck_reference(false);
        let multipath_ratio = run_p5_shared_bottleneck_reference(true);
        eprintln!(
            "P5 shared_bottleneck_comparison single_circuit_ratio_q16={single_circuit_ratio} two_circuit_ratio_q16={multipath_ratio}"
        );
    }

    #[test]
    fn p7_shared_link_stream_respects_configured_per_path_pacing_burst() {
        type Pool = FixedPool<32, { crate::DEFAULT_PACKET_POOL_SLOT_SIZE }>;
        type Runtime = NoStdRuntime<Pool>;
        static CLIENT_POOL: Pool = Pool::new();
        static SERVER_POOL: Pool = Pool::new();

        let forward_link = FakeSharedLink::new(4_000_000);
        let reverse_link = FakeSharedLink::new(4_000_000);
        let profile = FakeLinkProfile {
            latency_us: 8_000,
            bitrate_bps: 100_000_000,
            completion_delay_us: 100,
            ..FakeLinkProfile::default()
        };
        let make_pair = |first, second| {
            FakePacketBearer::<Pool>::pair_with_network(
                BearerName::new(first).unwrap(),
                BearerName::new(second).unwrap(),
                FakeNetworkConfig {
                    first_to_second: profile,
                    second_to_first: profile,
                    first_to_second_shared_link: Some(forward_link.clone()),
                    second_to_first_shared_link: Some(reverse_link.clone()),
                },
            )
        };
        let (client_fast, server_fast, mut fast_network) =
            make_pair("p7-fast-client", "p7-fast-server");
        let (client_slow, server_slow, mut slow_network) =
            make_pair("p7-slow-client", "p7-slow-server");
        let pacing = crate::PacingConfig {
            enabled: true,
            max_burst_packets: 1,
            max_burst_bytes: crate::DEFAULT_MAX_PACKET_SIZE as u32,
        };
        let mut limits = crate::AssociationLimits::host();
        limits.pacing = pacing;
        let mut client = Runtime::new(
            QuicNode::<Pool>::new(&CLIENT_POOL),
            ConnectionLimits::default(),
        );
        let mut server = Runtime::new(
            QuicNode::<Pool>::new(&SERVER_POOL),
            ConnectionLimits::default(),
        );
        client.set_default_association_limits(limits).unwrap();
        server.set_default_association_limits(limits).unwrap();
        let client_fast = client.add_bearer(client_fast).unwrap();
        let client_slow = client.add_bearer(client_slow).unwrap();
        server.add_bearer(server_fast).unwrap();
        server.add_bearer(server_slow).unwrap();
        let association = client
            .associate(
                PacketMeta {
                    bearer: client_fast,
                    peer_l2_address: PeerL2Address::new(1).unwrap(),
                    received_at_us: 0,
                },
                0,
            )
            .unwrap();

        let payload = (0..32_768)
            .map(|index| (index % 239) as u8)
            .collect::<Vec<_>>();
        let mut received = Vec::with_capacity(payload.len());
        let mut received_fin = false;
        let mut stream = None;
        let mut second_circuit = None;
        let mut sent = 0usize;
        let mut fin_sent = false;
        let mut now_us = 0u64;
        for _ in 0..20_000 {
            fast_network.advance_to(now_us);
            slow_network.advance_to(now_us);
            client.advance_time(now_us).unwrap();
            server.advance_time(now_us).unwrap();
            client.progress_all().unwrap();
            server
                .progress_all_with_stream(|_, offset, fin, bytes| {
                    if offset != received.len() as u64 {
                        return Err(crate::Error::Invalid);
                    }
                    received.extend_from_slice(bytes);
                    received_fin |= fin;
                    Ok(bytes.len())
                })
                .unwrap();

            if client.association_is_established(association) && second_circuit.is_none() {
                second_circuit = Some(
                    client
                        .add_direct_circuit(
                            association,
                            crate::CircuitNextHop {
                                bearer: client_slow,
                                peer_l2_address: PeerL2Address::new(1).unwrap(),
                            },
                            now_us,
                        )
                        .unwrap(),
                );
            }
            let mut circuits = [CircuitInfo::default(); 2];
            let count = client.circuits(association, &mut circuits);
            if count == 2
                && circuits
                    .iter()
                    .all(|circuit| circuit.status == crate::CircuitStatus::Active)
                && stream.is_none()
            {
                stream = Some(client.open_stream(association).unwrap());
            }
            if let Some(stream) = stream.as_mut() {
                if sent < payload.len() {
                    match client.write_stream(stream, &payload[sent..]) {
                        Ok(count) => sent += count,
                        Err(error) if error.is_retryable() => {}
                        Err(error) => panic!("paced stream write failed: {error:?}"),
                    }
                } else if !fin_sent {
                    match client.finish_stream(stream) {
                        Ok(()) => fin_sent = true,
                        Err(error) if error.is_retryable() => {}
                        Err(error) => panic!("paced FIN failed: {error:?}"),
                    }
                }
            }

            // Offer the node several scheduler turns without advancing virtual
            // time. This makes a configured burst cap observable rather than
            // relying on the harness's 1 ms outer-loop cadence.
            for _ in 0..8 {
                client.progress_all().unwrap();
            }

            let fast_stats = fast_network.stats();
            let slow_stats = slow_network.stats();
            if received_fin
                && fast_stats.accepted_submissions == fast_stats.completions
                && slow_stats.accepted_submissions == slow_stats.completions
            {
                break;
            }
            now_us = now_us.saturating_add(1_000);
        }

        assert_eq!(sent, payload.len());
        assert!(fin_sent);
        assert!(received_fin);
        assert_eq!(received, payload);
        let fast_stats = fast_network.stats();
        let slow_stats = slow_network.stats();
        for (name, stats) in [("fast", fast_stats), ("slow", slow_stats)] {
            for direction in 0..2 {
                assert!(
                    stats.max_same_time_submission_burst_packets_by_direction[direction]
                        <= u64::from(pacing.max_burst_packets),
                    "{name} direction {direction} exceeded packet cap: {stats:?}"
                );
                assert!(
                    stats.max_same_time_submission_burst_bytes_by_direction[direction]
                        <= u64::from(pacing.max_burst_bytes),
                    "{name} direction {direction} exceeded byte cap: {stats:?}"
                );
            }
        }
        assert!(forward_link.stats().packets > 0);
        assert_eq!(fast_stats.queue_drops + slow_stats.queue_drops, 0);
        eprintln!(
            "P7 shared_link pacing_burst_packets={} pacing_burst_bytes={} fast_max_packets={:?} fast_max_bytes={:?} slow_max_packets={:?} slow_max_bytes={:?} shared_bytes={} delivered_bytes={} fin=true",
            pacing.max_burst_packets,
            pacing.max_burst_bytes,
            fast_stats.max_same_time_submission_burst_packets_by_direction,
            fast_stats.max_same_time_submission_burst_bytes_by_direction,
            slow_stats.max_same_time_submission_burst_packets_by_direction,
            slow_stats.max_same_time_submission_burst_bytes_by_direction,
            forward_link.stats().bytes,
            received.len(),
        );
    }

    fn run_p5_shared_bottleneck_reference(target_two_circuits: bool) -> u128 {
        type Runtime = NoStdRuntime<FairnessPool>;

        FAIR_TARGET_POOL.resize(128).unwrap();
        FAIR_COMPETITOR_POOL.resize(128).unwrap();
        FAIR_TARGET_SERVER_POOL.resize(128).unwrap();
        FAIR_COMPETITOR_SERVER_POOL.resize(128).unwrap();

        let forward_link = FakeSharedLink::new(4_000_000);
        let reverse_link = FakeSharedLink::new(4_000_000);
        let profile = FakeLinkProfile {
            latency_us: 10_000,
            bitrate_bps: 100_000_000,
            completion_delay_us: 100,
            seed: 0x5045,
            ..FakeLinkProfile::default()
        };
        let make_pair = |client_name, server_name, seed, latency_us| {
            FakePacketBearer::<FairnessPool>::pair_with_network(
                BearerName::new(client_name).unwrap(),
                BearerName::new(server_name).unwrap(),
                FakeNetworkConfig {
                    first_to_second: FakeLinkProfile {
                        seed,
                        latency_us,
                        ..profile
                    },
                    second_to_first: FakeLinkProfile {
                        seed: seed ^ 0x55aa,
                        latency_us,
                        ..profile
                    },
                    first_to_second_shared_link: Some(forward_link.clone()),
                    second_to_first_shared_link: Some(reverse_link.clone()),
                },
            )
        };
        let (target_first, server_first, mut network_first) =
            make_pair("fair-target-a", "fair-server-a", 0x1111, 10_000);
        let (target_second, server_second, mut network_second) =
            make_pair("fair-target-b", "fair-server-b", 0x2222, 10_000);
        let (competitor_bearer, server_competitor, mut network_competitor) =
            make_pair("fair-competitor", "fair-server-c", 0x3333, 10_000);

        let mut target = Runtime::new(
            QuicNode::<FairnessPool>::new(&FAIR_TARGET_POOL),
            ConnectionLimits::default(),
        );
        let mut competitor = Runtime::new(
            QuicNode::<FairnessPool>::new(&FAIR_COMPETITOR_POOL),
            ConnectionLimits::default(),
        );
        let mut target_server = Runtime::new(
            QuicNode::<FairnessPool>::new(&FAIR_TARGET_SERVER_POOL),
            ConnectionLimits::default(),
        );
        let mut competitor_server = Runtime::new(
            QuicNode::<FairnessPool>::new(&FAIR_COMPETITOR_SERVER_POOL),
            ConnectionLimits::default(),
        );
        let target_first = target.add_bearer(target_first).unwrap();
        let target_second = target.add_bearer(target_second).unwrap();
        let competitor_bearer = competitor.add_bearer(competitor_bearer).unwrap();
        target_server.add_bearer(server_first).unwrap();
        target_server.add_bearer(server_second).unwrap();
        competitor_server.add_bearer(server_competitor).unwrap();

        let target_association = target
            .associate(
                PacketMeta {
                    bearer: target_first,
                    peer_l2_address: PeerL2Address::new(1).unwrap(),
                    received_at_us: 0,
                },
                0,
            )
            .unwrap();
        let competitor_association = competitor
            .associate(
                PacketMeta {
                    bearer: competitor_bearer,
                    peer_l2_address: PeerL2Address::new(1).unwrap(),
                    received_at_us: 0,
                },
                0,
            )
            .unwrap();

        const PAYLOAD_LEN: usize = 128 * 1024;
        let payloads = [[0x6d; PAYLOAD_LEN], [0xa7; PAYLOAD_LEN]];
        let mut received = [
            Vec::with_capacity(PAYLOAD_LEN),
            Vec::with_capacity(PAYLOAD_LEN),
        ];
        let mut received_fin = [false; 2];
        let mut accepted_associations = 0usize;
        let mut target_circuit = None;
        let mut target_stream = None;
        let mut competitor_stream = None;
        let mut offsets = [0usize; 2];
        let mut fin_sent = [false; 2];
        let mut start_at_us = None;
        let mut finish_at_us = [None; 2];
        let mut now_us = 0u64;

        for _ in 0..20_000 {
            network_first.advance_to(now_us);
            network_second.advance_to(now_us);
            network_competitor.advance_to(now_us);
            target.advance_time(now_us).unwrap();
            competitor.advance_time(now_us).unwrap();
            target_server.advance_time(now_us).unwrap();
            competitor_server.advance_time(now_us).unwrap();
            target.progress_all().unwrap();
            competitor.progress_all().unwrap();
            target_server
                .progress_all_with_stream(|_, offset, fin, bytes| {
                    if offset != received[0].len() as u64 {
                        return Err(crate::Error::Invalid);
                    }
                    received[0].extend_from_slice(bytes);
                    received_fin[0] |= fin;
                    if fin {
                        finish_at_us[0] = Some(now_us);
                    }
                    Ok(bytes.len())
                })
                .unwrap();
            competitor_server
                .progress_all_with_stream(|_, offset, fin, bytes| {
                    if offset != received[1].len() as u64 {
                        return Err(crate::Error::Invalid);
                    }
                    received[1].extend_from_slice(bytes);
                    received_fin[1] |= fin;
                    if fin {
                        finish_at_us[1] = Some(now_us);
                    }
                    Ok(bytes.len())
                })
                .unwrap();

            while target_server.next_association().is_some() {
                accepted_associations += 1;
            }
            while competitor_server.next_association().is_some() {
                accepted_associations += 1;
            }

            if target.association_is_established(target_association) && target_circuit.is_none() {
                if target_two_circuits {
                    target_circuit = Some(
                        target
                            .add_direct_circuit(
                                target_association,
                                crate::CircuitNextHop {
                                    bearer: target_second,
                                    peer_l2_address: PeerL2Address::new(1).unwrap(),
                                },
                                now_us,
                            )
                            .unwrap(),
                    );
                } else {
                    let mut primary = [CircuitInfo::default(); 1];
                    assert_eq!(target.circuits(target_association, &mut primary), 1);
                    target_circuit = Some(primary[0].id);
                }
            }

            let mut circuits = [CircuitInfo::default(); 2];
            let target_circuits = target.circuits(target_association, &mut circuits);
            let expected_target_circuits = if target_two_circuits { 2 } else { 1 };
            if target_circuits == expected_target_circuits
                && circuits[..target_circuits]
                    .iter()
                    .all(|circuit| circuit.status == crate::CircuitStatus::Active)
                && competitor.association_is_established(competitor_association)
                && target_stream.is_none()
            {
                let target_open = target.open_stream(target_association).unwrap();
                let competitor_open = competitor.open_stream(competitor_association).unwrap();
                target_stream = Some(target_open);
                competitor_stream = Some(competitor_open);
                start_at_us = Some(now_us);
            }

            if let Some(stream) = target_stream.as_mut() {
                if offsets[0] < PAYLOAD_LEN {
                    match target.write_stream(stream, &payloads[0][offsets[0]..]) {
                        Ok(count) => offsets[0] += count,
                        Err(error) if error.is_retryable() => {}
                        Err(error) => panic!("target stream write failed: {error:?}"),
                    }
                } else if !fin_sent[0] {
                    fin_sent[0] = target.finish_stream(stream).is_ok();
                }
            }
            if let Some(stream) = competitor_stream.as_mut() {
                if offsets[1] < PAYLOAD_LEN {
                    match competitor.write_stream(stream, &payloads[1][offsets[1]..]) {
                        Ok(count) => offsets[1] += count,
                        Err(error) if error.is_retryable() => {}
                        Err(error) => panic!("competitor stream write failed: {error:?}"),
                    }
                } else if !fin_sent[1] {
                    fin_sent[1] = competitor.finish_stream(stream).is_ok();
                }
            }

            if received_fin.iter().all(|fin| *fin)
                && [
                    network_first.stats(),
                    network_second.stats(),
                    network_competitor.stats(),
                ]
                .iter()
                .all(|stats| stats.accepted_submissions == stats.completions)
            {
                break;
            }
            now_us = now_us.saturating_add(1_000);
        }

        assert!(received[0].as_slice() == payloads[0]);
        assert!(received[1].as_slice() == payloads[1]);
        assert!(received_fin.into_iter().all(|fin| fin));
        assert_eq!(accepted_associations, 2);
        assert!(fin_sent.into_iter().all(|fin| fin));
        assert_eq!(offsets, [PAYLOAD_LEN; 2]);
        let started_at = start_at_us.expect("both associations became ready");
        let target_elapsed_us = finish_at_us[0].unwrap() - started_at;
        let competitor_elapsed_us = finish_at_us[1].unwrap() - started_at;
        let target_goodput = (PAYLOAD_LEN as u128 * 8_000_000) / u128::from(target_elapsed_us);
        let competitor_goodput =
            (PAYLOAD_LEN as u128 * 8_000_000) / u128::from(competitor_elapsed_us);
        let fairness_ratio_q16 = (target_goodput << 16) / competitor_goodput.max(1);
        let mut final_target_circuits = [CircuitInfo::default(); 2];
        let final_target_count = target.circuits(target_association, &mut final_target_circuits);
        eprintln!(
            "P5 shared_bottleneck raw target_circuit_count={} target_goodput_bps={target_goodput} competitor_goodput_bps={competitor_goodput} target_elapsed_us={target_elapsed_us} competitor_elapsed_us={competitor_elapsed_us} target_circuits={:?}",
            final_target_count,
            &final_target_circuits[..final_target_count],
        );
        assert!(target_goodput > 0 && competitor_goodput > 0);
        if !target_two_circuits {
            let lower = u128::from(crate::PathEstimatorConfig::Q16_ONE) * 80 / 100;
            let upper = u128::from(crate::PathEstimatorConfig::Q16_ONE) * 120 / 100;
            assert!(
                (lower..=upper).contains(&fairness_ratio_q16),
                "one-circuit reference flows exceeded the deterministic 20% tolerance: ratio_q16={fairness_ratio_q16}"
            );
        }
        assert!(forward_link.stats().bytes > 2 * PAYLOAD_LEN as u64);
        eprintln!(
            "P5 shared_bottleneck target_circuits={final_target_count} competing_circuits=1 shared_rate_bps=4000000 target_goodput_bps={target_goodput} competitor_goodput_bps={competitor_goodput} ratio_q16={fairness_ratio_q16} target_elapsed_us={target_elapsed_us} competitor_elapsed_us={competitor_elapsed_us} delivered_bytes_per_flow={PAYLOAD_LEN} fin=true shared_bytes={} shared_packets={}",
            forward_link.stats().bytes,
            forward_link.stats().packets,
        );
        fairness_ratio_q16
    }

    #[test]
    fn relayed_two_chain_stream_uses_three_no_std_relays_and_survives_path_loss() {
        type RelayPool = FixedPool<32, { crate::DEFAULT_PACKET_POOL_SLOT_SIZE }>;
        type Runtime = NoStdRuntime<RelayPool>;
        type Network = crate::fake::FakeNetwork<RelayPool>;
        static CLIENT_POOL: RelayPool = RelayPool::new();
        static SERVER_POOL: RelayPool = RelayPool::new();
        static RELAY1_POOL: RelayPool = RelayPool::new();
        static RELAY2_POOL: RelayPool = RelayPool::new();
        static RELAY3_POOL: RelayPool = RelayPool::new();

        let relay_limits = ConnectionLimits::default();
        let destination_vip = 0x0102_0304_0506_0708;
        let make_runtime =
            |pool: &'static RelayPool,
             routes: Option<Arc<Mutex<Vec<(u8, u8, crate::CircuitNextHop)>>>>| {
                let mut node = QuicNode::<RelayPool>::new(pool);
                if let Some(routes) = routes {
                    let layered_routes = routes.clone();
                    node.set_path_open_resolver(move |kind, address| {
                        let key = address.first().copied()?;
                        layered_routes.lock().unwrap().iter().find_map(
                            |(route_kind, route_key, next_hop)| {
                                (*route_kind == kind && *route_key == key).then_some(*next_hop)
                            },
                        )
                    });
                    node.set_vip_path_open_resolver(move |kind, address, vip| {
                        if vip != destination_vip {
                            return None;
                        }
                        let key = address.first().copied()?;
                        routes.lock().unwrap().iter().find_map(
                            |(route_kind, route_key, next_hop)| {
                                (*route_kind == kind && *route_key == key).then_some(*next_hop)
                            },
                        )
                    });
                }
                Runtime::new(node, relay_limits)
            };

        let routes1 = Arc::new(Mutex::new(Vec::new()));
        let routes2 = Arc::new(Mutex::new(Vec::new()));
        let routes3 = Arc::new(Mutex::new(Vec::new()));
        let mut client = make_runtime(&CLIENT_POOL, None);
        let mut relay1 = make_runtime(&RELAY1_POOL, Some(routes1.clone()));
        let mut relay2 = make_runtime(&RELAY2_POOL, Some(routes2.clone()));
        let mut relay3 = make_runtime(&RELAY3_POOL, Some(routes3.clone()));
        let mut server = make_runtime(&SERVER_POOL, None);
        server.node.set_local_vip(destination_vip).unwrap();

        let mut networks = Vec::<Network>::new();
        let mut client_ends = Vec::new();
        let mut peer_ends = Vec::new();
        let first_names = [
            ("a-r1", "r1-a"),
            ("r1-r2", "r2-r1"),
            ("r2-r3", "r3-r2"),
            ("r3-b", "b-r3"),
            ("a-r1b", "r1-ab"),
            ("r1-r2b", "r2-r1b"),
            ("r2-r3b", "r3-r2b"),
            ("r3-bb", "b-r3b"),
        ];
        for (index, (first_name, second_name)) in first_names.into_iter().enumerate() {
            let one_way_us = if index < 4 { 8_000 } else { 20_000 };
            let profile = FakeLinkProfile {
                latency_us: one_way_us,
                bitrate_bps: 20_000_000,
                completion_delay_us: 250,
                seed: 0x1000 + index as u64,
                ..FakeLinkProfile::default()
            };
            let reverse_profile = if index == 3 {
                FakeLinkProfile {
                    loss_burst_start_packet: 1,
                    loss_burst_packets: 1,
                    seed: 0xface,
                    ..profile
                }
            } else {
                profile
            };
            let (first, second, network) = FakePacketBearer::<RelayPool>::pair_with_network(
                BearerName::new(first_name).unwrap(),
                BearerName::new(second_name).unwrap(),
                FakeNetworkConfig {
                    first_to_second: profile,
                    second_to_first: reverse_profile,
                    ..FakeNetworkConfig::default()
                },
            );
            client_ends.push(Some(first));
            peer_ends.push(Some(second));
            networks.push(network);
        }

        let client_path1 = client.add_bearer(client_ends[0].take().unwrap()).unwrap();
        let client_path2 = client.add_bearer(client_ends[4].take().unwrap()).unwrap();
        let relay1_in1 = relay1.add_bearer(peer_ends[0].take().unwrap()).unwrap();
        let relay1_out1 = relay1.add_bearer(client_ends[1].take().unwrap()).unwrap();
        let relay1_in2 = relay1.add_bearer(peer_ends[4].take().unwrap()).unwrap();
        let relay1_out2 = relay1.add_bearer(client_ends[5].take().unwrap()).unwrap();
        let relay2_in1 = relay2.add_bearer(peer_ends[1].take().unwrap()).unwrap();
        let relay2_out1 = relay2.add_bearer(client_ends[2].take().unwrap()).unwrap();
        let relay2_in2 = relay2.add_bearer(peer_ends[5].take().unwrap()).unwrap();
        let relay2_out2 = relay2.add_bearer(client_ends[6].take().unwrap()).unwrap();
        let relay3_in1 = relay3.add_bearer(peer_ends[2].take().unwrap()).unwrap();
        let relay3_out1 = relay3.add_bearer(client_ends[3].take().unwrap()).unwrap();
        let relay3_in2 = relay3.add_bearer(peer_ends[6].take().unwrap()).unwrap();
        let relay3_out2 = relay3.add_bearer(client_ends[7].take().unwrap()).unwrap();
        let server_path1 = server.add_bearer(peer_ends[3].take().unwrap()).unwrap();
        let server_path2 = server.add_bearer(peer_ends[7].take().unwrap()).unwrap();

        let peer = PeerL2Address::new(1).unwrap();
        routes1.lock().unwrap().extend([
            (
                2,
                2,
                crate::CircuitNextHop {
                    bearer: relay1_out1,
                    peer_l2_address: peer,
                },
            ),
            (
                2,
                5,
                crate::CircuitNextHop {
                    bearer: relay1_out2,
                    peer_l2_address: peer,
                },
            ),
            (
                2,
                10,
                crate::CircuitNextHop {
                    bearer: relay1_in1,
                    peer_l2_address: peer,
                },
            ),
            (
                2,
                11,
                crate::CircuitNextHop {
                    bearer: relay1_out2,
                    peer_l2_address: peer,
                },
            ),
        ]);
        routes2.lock().unwrap().extend([
            (
                2,
                3,
                crate::CircuitNextHop {
                    bearer: relay2_out1,
                    peer_l2_address: peer,
                },
            ),
            (
                2,
                6,
                crate::CircuitNextHop {
                    bearer: relay2_out2,
                    peer_l2_address: peer,
                },
            ),
            (
                2,
                9,
                crate::CircuitNextHop {
                    bearer: relay2_in1,
                    peer_l2_address: peer,
                },
            ),
            (
                2,
                11,
                crate::CircuitNextHop {
                    bearer: relay2_out2,
                    peer_l2_address: peer,
                },
            ),
        ]);
        routes3.lock().unwrap().extend([
            (
                3,
                4,
                crate::CircuitNextHop {
                    bearer: relay3_out1,
                    peer_l2_address: peer,
                },
            ),
            (
                3,
                7,
                crate::CircuitNextHop {
                    bearer: relay3_out2,
                    peer_l2_address: peer,
                },
            ),
            (
                3,
                8,
                crate::CircuitNextHop {
                    bearer: relay3_in1,
                    peer_l2_address: peer,
                },
            ),
            (
                2,
                11,
                crate::CircuitNextHop {
                    bearer: relay3_out2,
                    peer_l2_address: peer,
                },
            ),
        ]);
        assert_ne!(relay1_in1, relay1_in2);
        assert_ne!(relay2_in1, relay2_in2);
        assert_ne!(relay3_in1, relay3_in2);

        let metadata = |bearer| PacketMeta {
            bearer,
            peer_l2_address: peer,
            received_at_us: 0,
        };
        let advance = |runtime: &mut Runtime, now_us| match runtime.advance_time(now_us) {
            Ok(_) => {}
            Err(error) if error.is_retryable() => {}
            Err(error) => panic!("no-std relay timer failed: {error:?}"),
        };
        let progress = |runtime: &mut Runtime| match runtime.progress_all() {
            Ok(count) => count,
            Err(error) if error.is_retryable() => 0,
            Err(error) => panic!("no-std relay ingress failed: {error:?}"),
        };
        let hops1 = [
            crate::RelayHop::new(2, &[2], 60_000_000, 4096).unwrap(),
            crate::RelayHop::new(2, &[3], 60_000_000, 4096).unwrap(),
            crate::RelayHop::new(3, &[4], 60_000_000, 4096).unwrap(),
        ];
        let client_return_hints = crate::NearbyRelayHints::new(&[
            crate::NearbyRelayHint {
                relay_id: [0x18; 8],
                hop: crate::RelayHop::new(3, &[8], 60_000_000, 4096).unwrap(),
            },
            crate::NearbyRelayHint {
                relay_id: [0x19; 8],
                hop: crate::RelayHop::new(2, &[9], 60_000_000, 4096).unwrap(),
            },
            crate::NearbyRelayHint {
                relay_id: [0x1a; 8],
                hop: crate::RelayHop::new(2, &[10], 60_000_000, 4096).unwrap(),
            },
        ])
        .unwrap();
        let association = client
            .node
            .associate_relayed_with_return_hints(
                metadata(client_path1),
                Some(0x0102_0304_0506_0708),
                &hops1,
                client_return_hints,
                0,
            )
            .unwrap();

        let mut server_association = None;
        let mut server_return_hints = None;
        let mut now_us = 0u64;
        for _ in 0..30_000 {
            for network in &mut networks {
                network.advance_to(now_us);
            }
            advance(&mut client, now_us);
            advance(&mut relay1, now_us);
            advance(&mut relay2, now_us);
            advance(&mut relay3, now_us);
            advance(&mut server, now_us);
            for _ in 0..8 {
                let progressed = progress(&mut client)
                    + progress(&mut relay1)
                    + progress(&mut relay2)
                    + progress(&mut relay3)
                    + progress(&mut server);
                if progressed == 0 {
                    break;
                }
            }
            server_association = server_association.or_else(|| server.next_association());
            while let Some(event) = server.next_event() {
                if let crate::AssociationEvent::PeerReturnPathHints {
                    association: hinted_association,
                    hints,
                } = event
                {
                    assert_eq!(server_association, Some(hinted_association));
                    server_return_hints = Some(hints);
                }
            }
            if client.association_is_established(association) && server_association.is_some() {
                break;
            }
            now_us = now_us.saturating_add(1_000);
        }
        assert!(client.association_is_established(association));
        assert!(server_association.is_some());
        assert!(server_return_hints.is_some());
        assert_eq!(server.node.association_count(), 1);
        assert_eq!(networks[3].stats().loss_drops, 1, "first reply was lost");

        let client_second_circuit = client
            .join_relayed_path_with_route_mode(
                association,
                metadata(client_path2),
                &[crate::RelayHop::new(2, &[11], 60_000_000, 4096).unwrap()],
                crate::RelayRouteMode::Telescoping,
                Some(destination_vip),
                now_us,
            )
            .unwrap();
        let server_association = server_association.unwrap();
        let server_hints = server_return_hints.unwrap();
        let hops_from_server = server_hints.iter().map(|hint| hint.hop).collect::<Vec<_>>();
        assert_eq!(hops_from_server.len(), 3);
        let server_second_circuit = server
            .join_relayed_path(
                server_association,
                metadata(server_path1),
                &hops_from_server,
                now_us,
            )
            .unwrap();
        let mut paths = [CircuitInfo::default(); 3];
        let mut client_join_active = false;
        let mut server_join_active = false;
        for _ in 0..30_000 {
            for network in &mut networks {
                network.advance_to(now_us);
            }
            advance(&mut client, now_us);
            advance(&mut relay1, now_us);
            advance(&mut relay2, now_us);
            advance(&mut relay3, now_us);
            advance(&mut server, now_us);
            for _ in 0..8 {
                let progressed = progress(&mut client)
                    + progress(&mut relay1)
                    + progress(&mut relay2)
                    + progress(&mut relay3)
                    + progress(&mut server);
                if progressed == 0 {
                    break;
                }
            }
            let client_count = client.circuits(association, &mut paths);
            client_join_active = client_count == 3
                && paths[..3].iter().any(|path| {
                    path.id == client_second_circuit && path.status == crate::CircuitStatus::Active
                });
            let server_count = server.circuits(server_association, &mut paths);
            server_join_active = server_count == 3
                && paths[..3].iter().any(|path| {
                    path.id == server_second_circuit && path.status == crate::CircuitStatus::Active
                });
            if client_join_active && server_join_active {
                break;
            }
            now_us = now_us.saturating_add(1_000);
        }
        assert!(
            client_join_active,
            "the client-built relay chain must validate"
        );
        assert!(
            server_join_active,
            "the server-built return chain must validate"
        );
        assert_eq!(
            server.node.association_count(),
            1,
            "simultaneous JOINs reuse the association"
        );
        let payload = (0usize..32_768)
            .map(|index| (index.wrapping_mul(31) % 251) as u8)
            .collect::<Vec<_>>();
        networks[0].set_first_to_second_profile(FakeLinkProfile {
            loss_per_million: 1_000_000,
            seed: 0xdead,
            ..FakeLinkProfile::default()
        });
        let mut stream = client.open_stream(association).unwrap();
        let mut sent = 0usize;
        let mut fin_sent = false;
        let mut received = Vec::with_capacity(payload.len());
        let mut received_fin = false;
        let mut complete_at_us = None;
        let mut failed_fast_paths_suspended = false;
        let mut client_paths = [CircuitInfo::default(); 3];
        for _ in 0..40_000 {
            for network in &mut networks {
                network.advance_to(now_us);
            }
            advance(&mut client, now_us);
            advance(&mut relay1, now_us);
            advance(&mut relay2, now_us);
            advance(&mut relay3, now_us);
            advance(&mut server, now_us);
            for _ in 0..8 {
                let mut progressed = progress(&mut client)
                    + progress(&mut relay1)
                    + progress(&mut relay2)
                    + progress(&mut relay3);
                progressed += match server.progress_all_with_stream(|_, offset, fin, bytes| {
                    if offset != received.len() as u64 {
                        return Err(crate::Error::Invalid);
                    }
                    received.extend_from_slice(bytes);
                    received_fin |= fin;
                    Ok(bytes.len())
                }) {
                    Ok(count) => count,
                    Err(error) if error.is_retryable() => 0,
                    Err(error) => panic!("no-std server ingress failed: {error:?}"),
                };
                if progressed == 0 {
                    break;
                }
            }
            if sent < payload.len() {
                match client.write_stream(&mut stream, &payload[sent..]) {
                    Ok(count) => sent += count,
                    Err(error) if error.is_retryable() => {}
                    Err(error) => panic!("relayed stream write failed: {error:?}"),
                }
            } else if !fin_sent {
                match client.finish_stream(&mut stream) {
                    Ok(()) => fin_sent = true,
                    Err(error) if error.is_retryable() => {}
                    Err(error) => panic!("relayed stream FIN failed: {error:?}"),
                }
            }
            client.circuits(association, &mut client_paths);
            if received_fin && !failed_fast_paths_suspended {
                for failed_path in client_paths
                    .iter()
                    .filter(|path| {
                        path.first_hop.bearer == client_path1 && path.bytes_in_flight != 0
                    })
                    .map(|path| path.id)
                    .collect::<Vec<_>>()
                {
                    client.suspend_circuit(failed_path).unwrap();
                }
                failed_fast_paths_suspended = true;
                client.circuits(association, &mut client_paths);
            }
            if received_fin
                && client_paths.iter().all(|path| path.bytes_in_flight == 0)
                && networks.iter().all(|network| {
                    network.stats().accepted_submissions == network.stats().completions
                })
            {
                complete_at_us = Some(now_us);
                break;
            }
            now_us = now_us.saturating_add(1_000);
        }

        assert_eq!(sent, payload.len());
        assert!(fin_sent && received_fin);
        assert!(
            networks[0].stats().loss_drops > 0,
            "fast path injected loss"
        );
        assert!(
            client_paths
                .iter()
                .any(|path| { path.first_hop.bearer == client_path2 && path.packets_sent > 0 }),
            "the surviving relayed circuit must carry repair traffic"
        );
        assert_eq!(received, payload);
        assert!(complete_at_us.is_some());
        assert_eq!(server.node.association_count(), 1);
        assert!(
            networks
                .iter()
                .any(|network| network.stats().delivered_packets > 0)
        );
        eprintln!(
            "P4 relayed_two_chain delivered_bytes={} fin=true elapsed_us={} relay_count=3 chains=2 server_associations={} return_hints={} server_return_built_from_peer_hints=true accepted={} completed={}",
            received.len(),
            complete_at_us.unwrap(),
            server.node.association_count(),
            server_hints.len(),
            networks
                .iter()
                .map(|network| network.stats().accepted_submissions)
                .sum::<u64>(),
            networks
                .iter()
                .map(|network| network.stats().completions)
                .sum::<u64>(),
        );
        let _ = server_path1;
        let _ = server_path2;
    }

    #[test]
    fn packet_number_wire_width_boundaries_complete_through_public_bearer() {
        for (packet_number, expected_len) in [
            (127, 1),
            (128, 2),
            (32_767, 2),
            (32_768, 3),
            (8_388_607, 3),
            (8_388_608, 4),
        ] {
            run_packet_number_wire_width_boundary(packet_number, expected_len);
        }
    }

    fn run_packet_number_wire_width_boundary(packet_number: u32, expected_len: u8) {
        static BOUNDARY_CLIENT_POOL: BaselinePool = BaselinePool::new();
        static BOUNDARY_SERVER_POOL: BaselinePool = BaselinePool::new();
        let (client_bearer, server_bearer, mut network) =
            FakePacketBearer::<BaselinePool>::pair_with_network(
                BearerName::new("pn-boundary-c").unwrap(),
                BearerName::new("pn-boundary-s").unwrap(),
                FakeNetworkConfig {
                    first_to_second: FakeLinkProfile {
                        latency_us: 1_000,
                        completion_delay_us: 100,
                        ..FakeLinkProfile::default()
                    },
                    second_to_first: FakeLinkProfile {
                        latency_us: 1_000,
                        completion_delay_us: 100,
                        ..FakeLinkProfile::default()
                    },
                    ..FakeNetworkConfig::default()
                },
            );
        let capture = client_bearer.sent_packets();
        let mut client: NoStdRuntime<BaselinePool> = NoStdRuntime::new(
            QuicNode::<BaselinePool>::new(&BOUNDARY_CLIENT_POOL),
            ConnectionLimits::default(),
        );
        let mut server: NoStdRuntime<BaselinePool> = NoStdRuntime::new(
            QuicNode::<BaselinePool>::new(&BOUNDARY_SERVER_POOL),
            ConnectionLimits::default(),
        );
        let client_bearer = client.add_bearer(client_bearer).unwrap();
        server.add_bearer(server_bearer).unwrap();
        let association = client
            .associate(
                PacketMeta {
                    bearer: client_bearer,
                    peer_l2_address: PeerL2Address::new(1).unwrap(),
                    received_at_us: 0,
                },
                0,
            )
            .unwrap();

        let payload = (0..512)
            .map(|index| (index % 251) as u8)
            .collect::<Vec<_>>();
        let mut received = Vec::new();
        let mut received_fin = false;
        let mut server_association = None;
        let mut stream = None;
        let mut sent = 0usize;
        let mut fin_sent = false;
        let mut seeded = false;
        let mut now_us = 0u64;

        for _ in 0..2_000 {
            network.advance_to(now_us);
            client.advance_time(now_us).unwrap();
            server.advance_time(now_us).unwrap();
            client.progress_all().unwrap();
            server
                .progress_all_with_stream(|_, offset, fin, bytes| {
                    if offset != received.len() as u64 {
                        return Err(crate::Error::Invalid);
                    }
                    received.extend_from_slice(bytes);
                    received_fin |= fin;
                    Ok(bytes.len())
                })
                .unwrap();
            if server_association.is_none() {
                server_association = server.next_association();
            }

            if !seeded && client.association_is_established(association) {
                let server_association = server_association.expect("server association accepted");
                assert!(client.node.seed_packet_number_state_for_test(
                    association,
                    Some(packet_number),
                    Some(0),
                    None,
                ));
                assert!(server.node.seed_packet_number_state_for_test(
                    server_association,
                    None,
                    None,
                    Some(packet_number),
                ));
                stream = Some(client.open_stream(association).unwrap());
                seeded = true;
            }

            if let Some(stream) = stream.as_mut() {
                if sent < payload.len() {
                    match client.write_stream(stream, &payload[sent..]) {
                        Ok(count) => sent += count,
                        Err(error) if error.is_retryable() => {}
                        Err(error) => {
                            panic!("packet-number boundary stream write failed: {error:?}")
                        }
                    }
                } else if !fin_sent {
                    match client.finish_stream(stream) {
                        Ok(()) => fin_sent = true,
                        Err(error) if error.is_retryable() => {}
                        Err(error) => panic!("packet-number boundary FIN failed: {error:?}"),
                    }
                }
            }

            let mut circuits = [CircuitInfo::default(); 1];
            client.circuits(association, &mut circuits);
            if received_fin
                && circuits[0].bytes_in_flight == 0
                && network.stats().accepted_submissions == network.stats().completions
            {
                break;
            }
            now_us = now_us.saturating_add(1_000);
        }

        assert!(seeded);
        assert_eq!(sent, payload.len());
        assert!(fin_sent && received_fin);
        assert_eq!(received, payload);
        let stream_packet = capture
            .lock()
            .unwrap()
            .iter()
            .find_map(|packet| {
                let prefix = crate::ShortHeader::decode_prefix(packet).ok()?;
                if prefix.flags & 0x80 != 0 {
                    return None;
                }
                let mut offset = prefix.header_len;
                let mut contains_stream = false;
                while offset < packet.len() {
                    let (frame, used) = crate::decode_frame(&packet[offset..]).ok()?;
                    contains_stream |= matches!(frame, crate::Frame::Stream(_));
                    offset += used;
                }
                contains_stream.then_some(prefix)
            })
            .expect("stream packet should traverse the fake packet bearer");
        assert_eq!(stream_packet.packet_number_len, expected_len);
        assert_eq!(
            stream_packet
                .reconstruct(packet_number)
                .unwrap()
                .packet_number,
            packet_number
        );
        assert_eq!(
            network.stats().accepted_submissions,
            network.stats().completions
        );
        eprintln!(
            "P3 packet_number_boundary packet_number={packet_number} wire_bytes={} delivered_bytes={} fin=true",
            expected_len,
            received.len()
        );
    }

    fn run_direct_two_path_stream(
        burst_loss: bool,
        forward_burst: bool,
        forward_outage: bool,
        delayed_completion: bool,
        ack_fragmentation: bool,
        reverse_outage: bool,
        p5_mtu_rate: bool,
        p5_priority_control: bool,
        p5_seeded_case: u8,
    ) {
        let p5_seeded_loss = p5_seeded_case != 0;
        let fast_profile = FakeLinkProfile {
            latency_us: if !p5_seeded_loss {
                10_000
            } else if p5_seeded_case == 2 {
                12_000
            } else {
                8_000
            },
            jitter_us: if ack_fragmentation { 20_000 } else { 0 },
            loss_per_million: match p5_seeded_case {
                1 => 100_000,
                2 => 200_000,
                _ => 0,
            },
            bitrate_bps: if p5_mtu_rate {
                2_000_000
            } else if p5_seeded_case == 2 {
                8_000_000
            } else if p5_seeded_loss {
                4_000_000
            } else {
                20_000_000
            },
            mtu_bytes: if p5_mtu_rate { 1_000 } else { usize::MAX },
            completion_delay_us: if delayed_completion {
                5_000
            } else if ack_fragmentation {
                0
            } else {
                500
            },
            reorder_ready_batch: false,
            loss_burst_start_packet: if forward_burst || forward_outage {
                15
            } else {
                0
            },
            loss_burst_packets: if forward_outage {
                u64::MAX
            } else if forward_burst {
                3
            } else {
                0
            },
            seed: match p5_seeded_case {
                1 => 0x5eed_2010,
                2 => 0x5eed_2020,
                _ => 0x2010,
            },
            ..FakeLinkProfile::default()
        };
        let fast_reverse_profile = FakeLinkProfile {
            latency_us: if !p5_seeded_loss {
                10_000
            } else if p5_seeded_case == 2 {
                12_000
            } else {
                8_000
            },
            jitter_us: 0,
            bitrate_bps: if p5_mtu_rate {
                8_000_000
            } else if p5_seeded_case == 2 {
                8_000_000
            } else if p5_seeded_loss {
                4_000_000
            } else {
                20_000_000
            },
            completion_delay_us: if delayed_completion {
                5_000
            } else if ack_fragmentation {
                0
            } else {
                500
            },
            loss_burst_start_packet: if reverse_outage {
                15
            } else if burst_loss {
                10
            } else {
                0
            },
            loss_burst_packets: if reverse_outage {
                u64::MAX
            } else if burst_loss {
                3
            } else {
                0
            },
            seed: match p5_seeded_case {
                1 => 0x5eed_1020,
                2 => 0x5eed_2021,
                _ => 0x1020,
            },
            ..FakeLinkProfile::default()
        };
        let slow_profile = FakeLinkProfile {
            latency_us: if ack_fragmentation {
                300_000
            } else if p5_seeded_case == 2 {
                36_000
            } else if p5_seeded_loss {
                24_000
            } else {
                30_000
            },
            bitrate_bps: if p5_mtu_rate {
                8_000_000
            } else if p5_seeded_case == 2 {
                4_000_000
            } else if p5_seeded_loss {
                2_000_000
            } else {
                20_000_000
            },
            completion_delay_us: if delayed_completion {
                5_000
            } else if ack_fragmentation {
                0
            } else {
                500
            },
            reorder_ready_batch: false,
            seed: match p5_seeded_case {
                1 => 0x5eed_6030,
                2 => 0x5eed_2030,
                _ => 0x6030,
            },
            ..FakeLinkProfile::default()
        };
        let slow_reverse_profile = FakeLinkProfile {
            latency_us: if p5_seeded_case == 2 {
                36_000
            } else if p5_seeded_loss {
                24_000
            } else {
                30_000
            },
            bitrate_bps: if p5_mtu_rate {
                8_000_000
            } else if p5_seeded_case == 2 {
                4_000_000
            } else if p5_seeded_loss {
                2_000_000
            } else {
                20_000_000
            },
            completion_delay_us: if delayed_completion {
                5_000
            } else if ack_fragmentation {
                0
            } else {
                500
            },
            reorder_ready_batch: false,
            seed: match p5_seeded_case {
                1 => 0x5eed_3060,
                2 => 0x5eed_2031,
                _ => 0x3060,
            },
            ..FakeLinkProfile::default()
        };
        let (client_fast, server_fast, mut fast_network) =
            FakePacketBearer::<MultipathPool>::pair_with_network(
                BearerName::new("path-fast-c").unwrap(),
                BearerName::new("path-fast-s").unwrap(),
                FakeNetworkConfig {
                    first_to_second: fast_profile,
                    second_to_first: fast_reverse_profile,
                    ..FakeNetworkConfig::default()
                },
            );
        let fast_ack_capture = server_fast.sent_packets();
        let client_fast_capture = client_fast.sent_packets();
        let (client_slow, server_slow, mut slow_network) =
            FakePacketBearer::<MultipathPool>::pair_with_network(
                BearerName::new("path-slow-c").unwrap(),
                BearerName::new("path-slow-s").unwrap(),
                FakeNetworkConfig {
                    first_to_second: slow_profile,
                    second_to_first: slow_reverse_profile,
                    ..FakeNetworkConfig::default()
                },
            );
        let slow_ack_capture = server_slow.sent_packets();
        let client_slow_capture = client_slow.sent_packets();
        let mut client: NoStdRuntime<MultipathPool> = NoStdRuntime::new(
            QuicNode::<MultipathPool>::new(&MULTIPATH_CLIENT_POOL),
            ConnectionLimits::default(),
        );
        let mut server: NoStdRuntime<MultipathPool> = NoStdRuntime::new(
            QuicNode::<MultipathPool>::new(&MULTIPATH_SERVER_POOL),
            ConnectionLimits::default(),
        );
        let mut association_limits = crate::AssociationLimits::host();
        association_limits.pacing = crate::PacingConfig {
            enabled: false,
            max_burst_packets: 256,
            max_burst_bytes: (256 * crate::DEFAULT_MAX_PACKET_SIZE) as u32,
        };
        association_limits.path_probe_interval_us = if ack_fragmentation {
            20_000_000
        } else {
            5_000_000
        };
        client
            .set_default_association_limits(association_limits)
            .unwrap();
        server
            .set_default_association_limits(association_limits)
            .unwrap();
        let client_fast = client.add_bearer(client_fast).unwrap();
        let client_slow = client.add_bearer(client_slow).unwrap();
        server.add_bearer(server_fast).unwrap();
        server.add_bearer(server_slow).unwrap();
        let association = client
            .associate(
                PacketMeta {
                    bearer: client_fast,
                    peer_l2_address: PeerL2Address::new(1).unwrap(),
                    received_at_us: 0,
                },
                0,
            )
            .unwrap();

        let payload_length = 32_768;
        let payload = (0usize..payload_length)
            .map(|index| (index.wrapping_mul(29) % 251) as u8)
            .collect::<Vec<_>>();
        let mut received = Vec::with_capacity(payload.len());
        let mut received_fin = false;
        let mut stream = None;
        let mut server_association = None;
        let mut sent = 0usize;
        let mut fin_sent = false;
        let mut slow_circuit = None;
        let mut now_us = 0u64;
        let mut completion_time_us = None;
        let mut loss_injected_at_us = None;
        let mut loss_detected_at_us = None;
        let mut fast_pto_timeout_us = None;
        let mut fast_suspended = false;
        let mut ack_eviction = None;
        let mut peak_client_leases = 0usize;
        let mut peak_server_leases = 0usize;
        let mut peak_flight_window_excess = 0u32;
        let mut prior_retransmissions = [0u64; 2];
        let mut prior_flight = [0u32; 2];
        let mut prior_cwnd = [0u32; 2];
        let mut have_prior_circuit_sample = false;
        let mut repair_window_checks = 0u32;
        let mut estimator_step_at_us = None;
        let mut sent_at_estimator_step = [0u64; 2];

        for _ in 0..10_000 {
            fast_network.advance_to(now_us);
            slow_network.advance_to(now_us);
            client.advance_time(now_us).unwrap();
            server.advance_time(now_us).unwrap();
            client.progress_all().unwrap();
            server
                .progress_all_with_stream(|_, offset, fin, bytes| {
                    if offset != received.len() as u64 {
                        return Err(crate::Error::Invalid);
                    }
                    received.extend_from_slice(bytes);
                    received_fin |= fin;
                    Ok(bytes.len())
                })
                .unwrap();
            if server_association.is_none() {
                server_association = server.next_association();
            }

            if client.association_is_established(association) && slow_circuit.is_none() {
                slow_circuit = Some(
                    client
                        .add_direct_circuit(
                            association,
                            crate::CircuitNextHop {
                                bearer: client_slow,
                                peer_l2_address: PeerL2Address::new(1).unwrap(),
                            },
                            now_us,
                        )
                        .unwrap(),
                );
            }

            let mut circuits = [CircuitInfo::default(); 2];
            let circuit_count = client.circuits(association, &mut circuits);
            if fast_pto_timeout_us.is_none() && circuits[0].srtt_us != 0 {
                fast_pto_timeout_us = client.node.path_pto_timeout_for_test(association, 0);
            }
            if ack_fragmentation
                && ack_eviction.is_none()
                && circuit_count == 2
                && circuits[..2]
                    .iter()
                    .all(|circuit| circuit.status == crate::CircuitStatus::Active)
                && circuits[..2].iter().all(|circuit| circuit.srtt_us > 0)
            {
                let (
                    max_ranges,
                    retained_ranges,
                    dropped_ranges,
                    stress_end_us,
                    ack_peak_client_leases,
                    ack_peak_server_leases,
                ) = run_ack_range_eviction_through_bearer(
                    &mut client,
                    &mut server,
                    association,
                    server_association.expect("server accepted the association"),
                    &fast_ack_capture,
                    &mut fast_network,
                    &mut slow_network,
                    now_us,
                );
                ack_eviction = Some((max_ranges, retained_ranges, dropped_ranges));
                now_us = stress_end_us;
                peak_client_leases = peak_client_leases.max(ack_peak_client_leases);
                peak_server_leases = peak_server_leases.max(ack_peak_server_leases);
            }
            if circuit_count == 2
                && circuits[..2]
                    .iter()
                    .all(|circuit| circuit.status == crate::CircuitStatus::Active)
                && stream.is_none()
            {
                stream = Some(client.open_stream(association).unwrap());
            }
            if let Some(stream) = stream.as_mut() {
                if sent < payload.len() {
                    match client.write_stream(stream, &payload[sent..]) {
                        Ok(count) => sent += count,
                        Err(error) if error.is_retryable() => {}
                        Err(error) => panic!(
                            "multipath stream write failed: {error:?} at {now_us}us, circuits={:?}",
                            &circuits[..circuit_count]
                        ),
                    }
                } else if !fin_sent {
                    match client.finish_stream(stream) {
                        Ok(()) => fin_sent = true,
                        Err(error) if error.is_retryable() => {}
                        Err(error) => panic!("multipath FIN failed: {error:?}"),
                    }
                }
            }

            if (forward_burst || forward_outage || reverse_outage || p5_seeded_loss)
                && fast_network.stats().loss_drops != 0
            {
                loss_injected_at_us.get_or_insert(now_us);
            }
            if p5_mtu_rate && fast_network.stats().mtu_drops != 0 {
                loss_injected_at_us.get_or_insert(now_us);
            }
            if forward_outage && !fast_suspended {
                if let (Some(injected_at), Some(pto_timeout)) =
                    (loss_injected_at_us, fast_pto_timeout_us)
                    && now_us >= injected_at.saturating_add(pto_timeout)
                {
                    client.node.suspend_circuit(circuits[0].id).unwrap();
                    fast_network.set_first_to_second_profile(FakeLinkProfile {
                        loss_burst_start_packet: 0,
                        loss_burst_packets: 0,
                        ..fast_profile
                    });
                    fast_suspended = true;
                    loss_detected_at_us = Some(now_us);
                }
            }

            peak_client_leases = peak_client_leases.max(
                client
                    .node
                    .packet_capacity()
                    .saturating_sub(client.node.available_packets()),
            );
            peak_server_leases = peak_server_leases.max(
                server
                    .node
                    .packet_capacity()
                    .saturating_sub(server.node.available_packets()),
            );
            client.circuits(association, &mut circuits);
            if estimator_step_at_us.is_none()
                && circuits[..circuit_count]
                    .iter()
                    .any(|circuit| circuit.estimator_step_events != 0)
            {
                estimator_step_at_us = Some(now_us);
                for path_id in 0..circuit_count {
                    sent_at_estimator_step[path_id] = circuits[path_id].packets_sent;
                }
            }
            if (forward_burst || forward_outage || reverse_outage || p5_mtu_rate || p5_seeded_loss)
                && have_prior_circuit_sample
            {
                for path_id in 1..circuit_count {
                    if circuits[path_id].retransmitted_packets > prior_retransmissions[path_id]
                        && prior_cwnd[path_id] != 0
                    {
                        assert!(
                            prior_flight[path_id] < prior_cwnd[path_id],
                            "alternate-path repair was accepted without destination window room: path={path_id} prior_flight={} prior_cwnd={} circuit={:?}",
                            prior_flight[path_id],
                            prior_cwnd[path_id],
                            circuits[path_id]
                        );
                        assert!(
                            circuits[path_id].bytes_in_flight <= circuits[path_id].cwnd_bytes,
                            "accepted alternate-path repair exceeded its destination congestion window: path={path_id} circuit={:?}",
                            circuits[path_id]
                        );
                        repair_window_checks = repair_window_checks.saturating_add(1);
                    }
                }
            }
            for path_id in 0..circuit_count {
                prior_retransmissions[path_id] = circuits[path_id].retransmitted_packets;
                prior_flight[path_id] = circuits[path_id].bytes_in_flight;
                prior_cwnd[path_id] = circuits[path_id].cwnd_bytes;
            }
            have_prior_circuit_sample = true;
            for circuit in &circuits[..circuit_count] {
                let excess = circuit.bytes_in_flight.saturating_sub(circuit.cwnd_bytes);
                peak_flight_window_excess = peak_flight_window_excess.max(excess);
            }
            if (forward_burst
                && circuits[..circuit_count]
                    .iter()
                    .any(|circuit| circuit.packets_lost > 0))
                || (p5_mtu_rate && circuits[0].packets_lost > 0)
                || (p5_seeded_loss && circuits[0].packets_lost > 0)
                || (reverse_outage && circuits[1].retransmitted_packets > 0)
                || (forward_outage && fast_suspended)
            {
                loss_detected_at_us.get_or_insert(now_us);
            }
            let flight_empty = circuits[..circuit_count]
                .iter()
                .all(|circuit| circuit.bytes_in_flight == 0);
            let submissions_complete = [fast_network.stats(), slow_network.stats()]
                .iter()
                .all(|stats| stats.accepted_submissions == stats.completions);
            if received_fin
                && (forward_outage || p5_mtu_rate || flight_empty)
                && submissions_complete
                && circuits[..circuit_count]
                    .iter()
                    .all(|circuit| circuit.srtt_us > 0)
            {
                completion_time_us = Some(now_us);
                break;
            }
            now_us = now_us.saturating_add(1_000);
        }

        assert_eq!(sent, payload.len());
        assert!(fin_sent);
        if !received_fin {
            let mut debug_circuits = [CircuitInfo::default(); 2];
            let debug_count = client.circuits(association, &mut debug_circuits);
            eprintln!(
                "forward_burst={forward_burst} burst_loss={burst_loss} forward_outage={forward_outage} reverse_outage={reverse_outage} delayed_completion={delayed_completion} ack_fragmentation={ack_fragmentation} p5_mtu_rate={p5_mtu_rate} p5_priority_control={p5_priority_control} p5_seeded_case={p5_seeded_case} now={now_us} delivered={} circuits={:?} fast={:?} slow={:?}",
                received.len(),
                &debug_circuits[..debug_count],
                fast_network.stats(),
                slow_network.stats()
            );
        }
        assert!(
            received_fin,
            "stream and FIN must arrive over the two circuits"
        );
        assert_eq!(received, payload);
        let mut fast_resumption_us = 0u64;
        let mut resume_started_at_us = 0u64;
        if forward_outage {
            assert!(
                fast_suspended,
                "the PTO deadline must suspend the failed circuit"
            );
            let mut before_resume = [CircuitInfo::default(); 2];
            assert_eq!(client.circuits(association, &mut before_resume), 2);
            if before_resume[0].status != crate::CircuitStatus::Suspended {
                // A delayed pre-outage validation response may complete after
                // suspension. Reapply the explicit failure state before the
                // repaired-link resumption check.
                client.node.suspend_circuit(before_resume[0].id).unwrap();
            }
            fast_network.set_first_to_second_profile(FakeLinkProfile {
                loss_burst_start_packet: 0,
                loss_burst_packets: 0,
                ..fast_profile
            });
            resume_started_at_us = now_us;
            client
                .node
                .resume_circuit(before_resume[0].id, before_resume[0].first_hop, now_us)
                .unwrap();
            let mut resumed = false;
            for _ in 0..500 {
                fast_network.advance_to(now_us);
                slow_network.advance_to(now_us);
                client.advance_time(now_us).unwrap();
                server.advance_time(now_us).unwrap();
                client.progress_all().unwrap();
                server.progress_all().unwrap();
                peak_client_leases = peak_client_leases.max(
                    client
                        .node
                        .packet_capacity()
                        .saturating_sub(client.node.available_packets()),
                );
                peak_server_leases = peak_server_leases.max(
                    server
                        .node
                        .packet_capacity()
                        .saturating_sub(server.node.available_packets()),
                );
                let mut after_resume = [CircuitInfo::default(); 2];
                client.circuits(association, &mut after_resume);
                if after_resume[0].status == crate::CircuitStatus::Active {
                    resumed = true;
                    fast_resumption_us = now_us;
                    break;
                }
                now_us = now_us.saturating_add(1_000);
            }
            assert!(
                resumed,
                "the repaired fast circuit must validate before reuse"
            );
            let resume_delay_us = fast_resumption_us.saturating_sub(resume_started_at_us);
            let validation_budget_us =
                u64::from(before_resume[0].srtt_us).saturating_mul(2) + 25_000;
            assert!(
                resume_delay_us <= validation_budget_us,
                "path validation took {resume_delay_us}us; bound is {validation_budget_us}us"
            );
            for _ in 0..16 {
                let fast_stats = fast_network.stats();
                let slow_stats = slow_network.stats();
                if fast_stats.accepted_submissions == fast_stats.completions
                    && slow_stats.accepted_submissions == slow_stats.completions
                {
                    break;
                }
                now_us = now_us.saturating_add(1_000);
                fast_network.advance_to(now_us);
                slow_network.advance_to(now_us);
                client.advance_time(now_us).unwrap();
                server.advance_time(now_us).unwrap();
                client.progress_all().unwrap();
                server.progress_all().unwrap();
                fast_network.advance_to(now_us);
                slow_network.advance_to(now_us);
            }
            assert_eq!(
                fast_network.stats().accepted_submissions,
                fast_network.stats().completions
            );
            assert_eq!(
                slow_network.stats().accepted_submissions,
                slow_network.stats().completions
            );
        }
        if (ack_fragmentation || p5_mtu_rate) && completion_time_us.is_none() {
            let mut debug_circuits = [CircuitInfo::default(); 2];
            let debug_count = client.circuits(association, &mut debug_circuits);
            eprintln!(
                "stress drain timeout mtu_rate={p5_mtu_rate} now={now_us} delivered={} circuits={:?} fast={:?} slow={:?}",
                received.len(),
                &debug_circuits[..debug_count],
                fast_network.stats(),
                slow_network.stats()
            );
        }
        assert!(completion_time_us.is_some());
        assert!(server_association.is_some());
        let mut circuits = [CircuitInfo::default(); 2];
        assert_eq!(client.circuits(association, &mut circuits), 2);
        if ack_fragmentation {
            let (max_ack_ranges, retained_ranges, dropped_ranges) = ack_eviction.unwrap();
            eprintln!(
                "P3 ack_fragmentation max_ack_ranges={max_ack_ranges} retained_ranges={retained_ranges} dropped_ranges={dropped_ranges} capacity={}",
                crate::ACK_RANGE_CAPACITY
            );
            // Sampling a received ACK may miss the instantaneous full set
            // when a fresh control/PTO packet coalesces gaps before emission.
            assert!(max_ack_ranges <= crate::ACK_RANGE_CAPACITY);
            // A later PTO/control packet may fill a gap and merge retained
            // ranges after capacity was reached. Eviction, not a permanently
            // full final ACK set, is the property this stress case requires.
            assert!(retained_ranges <= crate::ACK_RANGE_CAPACITY);
            assert!(dropped_ranges > 0, "the receive ACK set must evict ranges");
        }
        if p5_mtu_rate {
            assert!(
                fast_network.stats().mtu_drops > 0,
                "full-size-only fast path must drop stream packets"
            );
            assert!(
                circuits[0].packets_lost > 0,
                "dropped fast-path packets must feed delivery measurements"
            );
            assert!(
                circuits[1].retransmitted_packets > 0,
                "lost bytes must be repaired on the usable slow path"
            );
            assert!(
                circuits[0].estimator_step_events > 0,
                "repeated MTU loss must trigger conservative path scoring"
            );
            let stepped_at = estimator_step_at_us.expect("MTU delivery step is measured");
            let convergence_us = completion_time_us.unwrap().saturating_sub(stepped_at);
            let estimator_horizon_us =
                crate::PathEstimatorConfig::default_config().step_conservative_duration_us;
            assert!(
                convergence_us <= estimator_horizon_us,
                "delivery did not converge within the configured estimator horizon: {convergence_us}us > {estimator_horizon_us}us"
            );
            assert!(
                circuits[1]
                    .packets_sent
                    .saturating_sub(sent_at_estimator_step[1])
                    > circuits[0]
                        .packets_sent
                        .saturating_sub(sent_at_estimator_step[0]),
                "measured path cost did not move subsequent stream submissions toward the alternate"
            );
        }
        if p5_seeded_loss {
            assert!(
                fast_network.stats().loss_drops > 0,
                "seeded fast path must drop packets; stats={:?}",
                fast_network.stats()
            );
            assert!(
                circuits[0].packets_lost > 0,
                "seeded drops must feed path loss measurements"
            );
            assert!(
                circuits[1].retransmitted_packets > 0,
                "seeded losses must recover over the alternate"
            );
        }
        if burst_loss || forward_burst || forward_outage || reverse_outage {
            if forward_outage || reverse_outage {
                assert!(fast_network.stats().loss_drops > 3);
            } else {
                assert_eq!(fast_network.stats().loss_drops, 3);
            }
        } else if !ack_fragmentation && !p5_mtu_rate && !p5_seeded_loss {
            assert!(circuits.iter().all(|circuit| circuit.packets_lost == 0));
        }
        if !ack_fragmentation {
            assert!(circuits.iter().all(|circuit| circuit.spurious_losses == 0));
        }
        assert!(circuits.iter().all(|circuit| circuit.packets_sent > 0));
        if forward_burst || forward_outage || reverse_outage || p5_seeded_loss {
            if forward_burst {
                assert!(circuits[0].packets_lost > 0);
            }
            assert!(
                circuits[1].retransmitted_packets > 0,
                "lost application data must be repaired on the alternate circuit"
            );
            if forward_burst || forward_outage || reverse_outage || p5_seeded_loss {
                let recovery_delay_us = completion_time_us
                    .unwrap()
                    .saturating_sub(loss_detected_at_us.unwrap());
                let receiver_scheduling_budget_us = if p5_seeded_loss { 35_000 } else { 25_000 };
                let surviving_delivery_budget_us =
                    u64::from(circuits[1].srtt_us) + receiver_scheduling_budget_us;
                assert!(
                    recovery_delay_us <= surviving_delivery_budget_us,
                    "alternate-path delivery took {recovery_delay_us}us; bound is {surviving_delivery_budget_us}us"
                );
                let detection_delay_us = loss_detected_at_us
                    .unwrap()
                    .saturating_sub(loss_injected_at_us.unwrap());
                let pto_budget_us = fast_pto_timeout_us.expect("fast path PTO sample");
                assert!(
                    detection_delay_us <= pto_budget_us.saturating_add(1_000),
                    "loss detection took {detection_delay_us}us; configured PTO is {pto_budget_us}us"
                );
            }
        }
        let (fast_rtt_range, slow_rtt_range) = if ack_fragmentation {
            (15_000..=6_000_000, 50_000..=1_000_000)
        } else if p5_seeded_case == 2 {
            (15_000..=35_000, 60_000..=90_000)
        } else if delayed_completion {
            (15_000..=80_000, 50_000..=120_000)
        } else {
            (15_000..=25_000, 50_000..=70_000)
        };
        assert!(
            fast_rtt_range.contains(&circuits[0].srtt_us),
            "fast path RTT was {} us",
            circuits[0].srtt_us
        );
        assert!(
            slow_rtt_range.contains(&circuits[1].srtt_us),
            "slow path RTT was {} us",
            circuits[1].srtt_us
        );
        assert!(peak_client_leases > 0 && peak_server_leases > 0);
        assert!(peak_client_leases <= client.node.packet_capacity());
        assert!(peak_server_leases <= server.node.packet_capacity());
        if delayed_completion {
            assert!(peak_client_leases >= 3 && peak_server_leases >= 3);
        }
        for stats in [fast_network.stats(), slow_network.stats()] {
            assert!(
                stats.max_same_time_submission_burst_packets_by_direction[0] <= 256,
                "client exceeded the configured test-path burst: {stats:?}"
            );
            assert!(
                stats.max_same_time_submission_burst_bytes_by_direction[0]
                    <= (256 * crate::DEFAULT_MAX_PACKET_SIZE) as u64,
                "client exceeded the configured byte burst: {stats:?}"
            );
        }

        if p5_priority_control {
            fast_network.set_first_to_second_profile(FakeLinkProfile {
                loss_burst_start_packet: 1,
                loss_burst_packets: u64::MAX,
                ..fast_profile
            });
            let control_payload = b"priority control";
            let mut control_stream = client.open_stream(association).unwrap();
            control_stream.set_priority(true);
            let control_stream_id = control_stream.id();
            assert_eq!(
                client.write_stream(&mut control_stream, control_payload),
                Ok(control_payload.len())
            );
            let control_started_at_us = now_us;
            let mut control_received = Vec::new();
            let mut control_fin = false;
            let mut control_fin_sent = false;
            let mut control_received_at_us = None;
            for _ in 0..500 {
                fast_network.advance_to(now_us);
                slow_network.advance_to(now_us);
                client.advance_time(now_us).unwrap();
                server.advance_time(now_us).unwrap();
                client.progress_all().unwrap();
                server.progress_all().unwrap();
                while let Some(chunk) = server.next_stream_chunk() {
                    if chunk.stream.id() != control_stream_id {
                        continue;
                    }
                    assert_eq!(chunk.offset, control_received.len() as u64);
                    control_received.extend_from_slice(&chunk.bytes);
                    control_fin |= chunk.fin;
                    if chunk.fin {
                        control_received_at_us = Some(now_us);
                    }
                }
                if !control_fin_sent {
                    match client.finish_stream(&mut control_stream) {
                        Ok(()) => control_fin_sent = true,
                        Err(error) if error.is_retryable() => {}
                        Err(error) => panic!("priority control FIN failed: {error:?}"),
                    }
                }
                if control_fin
                    && [fast_network.stats(), slow_network.stats()]
                        .iter()
                        .all(|stats| stats.accepted_submissions == stats.completions)
                {
                    break;
                }
                now_us = now_us.saturating_add(1_000);
            }
            assert_eq!(control_received, control_payload);
            assert!(control_fin && control_fin_sent);
            assert!(fast_network.stats().loss_drops > 0);
            let mut after_control = [CircuitInfo::default(); 2];
            assert_eq!(client.circuits(association, &mut after_control), 2);
            assert!(after_control[1].packets_duplicated > 0);
            let control_elapsed_us = control_received_at_us.unwrap() - control_started_at_us;
            let delivery_budget_us = u64::from(after_control[1].srtt_us) + 25_000;
            assert!(
                control_elapsed_us <= delivery_budget_us,
                "duplicated priority control took {control_elapsed_us}us; surviving delivery and scheduling budget is {delivery_budget_us}us"
            );
            eprintln!(
                "P5 priority_control bytes={} fin=true primary_loss=true duplicated_packets={} duplicate_bytes={} elapsed_us={} surviving_rtt_us={} budget_us={delivery_budget_us}",
                control_received.len(),
                after_control[1].packets_duplicated,
                after_control[1].duplicate_bytes_prepared,
                control_elapsed_us,
                after_control[1].srtt_us,
            );
        }

        eprintln!(
            "virtual multipath baseline mtu_rate_case={} seeded_loss_case={} reverse_burst_loss={} forward_burst_loss={} forward_outage={} reverse_outage={} delayed_completion={} ack_fragmentation={} fast_rtt_us={} slow_rtt_us={} delivered_bytes={} fin=true completion_us={} recovery_after_loss_us={} loss_detection_us={} fast_pto_us={} fast_resume_us={} fast_sent={} slow_sent={} fast_retransmissions={} slow_retransmissions={} fast_lost={} slow_lost={} mtu_drops={} estimator_step_at_us={} estimator_convergence_us={} repair_window_checks={} peak_flight_above_cwnd={} peak_client_leases={} peak_server_leases={}",
            p5_mtu_rate,
            p5_seeded_case,
            burst_loss,
            forward_burst,
            forward_outage,
            reverse_outage,
            delayed_completion,
            ack_fragmentation,
            circuits[0].srtt_us,
            circuits[1].srtt_us,
            received.len(),
            completion_time_us.unwrap(),
            loss_detected_at_us
                .map(|detected| completion_time_us.unwrap().saturating_sub(detected))
                .unwrap_or(0),
            loss_injected_at_us
                .zip(loss_detected_at_us)
                .map(|(injected, detected)| detected.saturating_sub(injected))
                .unwrap_or(0),
            fast_pto_timeout_us.unwrap_or(0),
            fast_resumption_us,
            circuits[0].packets_sent,
            circuits[1].packets_sent,
            circuits[0].retransmitted_packets,
            circuits[1].retransmitted_packets,
            circuits[0].packets_lost,
            circuits[1].packets_lost,
            fast_network.stats().mtu_drops,
            estimator_step_at_us.unwrap_or(0),
            estimator_step_at_us
                .map(|step_at| completion_time_us.unwrap().saturating_sub(step_at))
                .unwrap_or(0),
            repair_window_checks,
            peak_flight_window_excess,
            peak_client_leases,
            peak_server_leases,
        );
    }

    fn run_ack_range_eviction_through_bearer(
        client: &mut NoStdRuntime<MultipathPool>,
        server: &mut NoStdRuntime<MultipathPool>,
        association: QuicAssociation,
        server_association: QuicAssociation,
        server_fast_capture: &Arc<Mutex<Vec<Vec<u8>>>>,
        fast_network: &mut crate::fake::FakeNetwork<MultipathPool>,
        slow_network: &mut crate::fake::FakeNetwork<MultipathPool>,
        now_us: u64,
    ) -> (usize, usize, u64, u64, usize, usize) {
        let mut saved_limits = client.node.association_limits(association).unwrap();
        let restore_limits = saved_limits;
        saved_limits.pacing = crate::PacingConfig {
            enabled: false,
            max_burst_packets: 256,
            max_burst_bytes: (256 * crate::DEFAULT_MAX_PACKET_SIZE) as u32,
        };
        client
            .node
            .set_association_limits(association, saved_limits)
            .unwrap();
        assert!(
            server
                .node
                .configure_ack_range_stress_for_test(server_association)
        );

        // Send real ledger-accounted PINGs in packet-number order, alternating
        // between the slow circuit and the fast circuit. Virtual time lets the
        // fast numbers arrive first while slow-path numbers remain in flight.
        let mut stress_at = now_us;
        let mut peak_client_leases = client
            .node
            .packet_capacity()
            .saturating_sub(client.node.available_packets());
        let mut peak_server_leases = server
            .node
            .packet_capacity()
            .saturating_sub(server.node.available_packets());
        for _ in 0..5 {
            for _ in 0..8 {
                client
                    .node
                    .submit_ping_on_path_for_test(association, 1)
                    .unwrap();
                client
                    .node
                    .submit_ping_on_path_for_test(association, 0)
                    .unwrap();
            }
            stress_at = stress_at.saturating_add(40_000);
            fast_network.advance_to(stress_at);
            slow_network.advance_to(stress_at);
            client.advance_time(stress_at).unwrap();
            server.advance_time(stress_at).unwrap();
            server.progress_all().unwrap();
            fast_network.advance_to(stress_at);
            client.progress_all().unwrap();
            peak_client_leases = peak_client_leases.max(
                client
                    .node
                    .packet_capacity()
                    .saturating_sub(client.node.available_packets()),
            );
            peak_server_leases = peak_server_leases.max(
                server
                    .node
                    .packet_capacity()
                    .saturating_sub(server.node.available_packets()),
            );
        }

        let max_ack_ranges = max_ack_range_count(server_fast_capture);
        let retained_ranges = server
            .node
            .received_ack_ranges_for_test(server_association)
            .unwrap()
            .len();
        let mut receive_circuits = [CircuitInfo::default(); 2];
        let receive_circuit_count = server
            .node
            .circuits(server_association, &mut receive_circuits);
        let dropped_ranges = receive_circuits[..receive_circuit_count]
            .iter()
            .map(|circuit| circuit.ack_ranges_dropped)
            .sum();
        assert!(
            server
                .node
                .restore_ack_policy_after_range_stress_for_test(server_association)
        );
        client
            .node
            .set_association_limits(association, restore_limits)
            .unwrap();

        // Drain the delayed direction in 8-packet batches. The main P3 stream
        // starts after this point and must complete with the retained ACK set.
        for _ in 0..32 {
            stress_at = stress_at.saturating_add(10_000);
            fast_network.advance_to(stress_at);
            slow_network.advance_to(stress_at);
            client.advance_time(stress_at).unwrap();
            server.advance_time(stress_at).unwrap();
            server.progress_all().unwrap();
            fast_network.advance_to(stress_at);
            slow_network.advance_to(stress_at);
            client.progress_all().unwrap();
            peak_client_leases = peak_client_leases.max(
                client
                    .node
                    .packet_capacity()
                    .saturating_sub(client.node.available_packets()),
            );
            peak_server_leases = peak_server_leases.max(
                server
                    .node
                    .packet_capacity()
                    .saturating_sub(server.node.available_packets()),
            );
        }
        for _ in 0..32 {
            let fast_stats = fast_network.stats();
            let slow_stats = slow_network.stats();
            if fast_stats.accepted_submissions == fast_stats.completions
                && slow_stats.accepted_submissions == slow_stats.completions
            {
                break;
            }
            stress_at = stress_at.saturating_add(10_000);
            fast_network.advance_to(stress_at);
            slow_network.advance_to(stress_at);
            client.advance_time(stress_at).unwrap();
            server.advance_time(stress_at).unwrap();
            client.progress_all().unwrap();
            server.progress_all().unwrap();
            fast_network.advance_to(stress_at);
            slow_network.advance_to(stress_at);
        }
        assert_eq!(fast_network.stats().queue_drops, 0);
        assert_eq!(slow_network.stats().queue_drops, 0);
        assert_eq!(
            fast_network.stats().accepted_submissions,
            fast_network.stats().completions
        );
        assert_eq!(
            slow_network.stats().accepted_submissions,
            slow_network.stats().completions
        );
        (
            max_ack_ranges,
            retained_ranges,
            dropped_ranges,
            stress_at,
            peak_client_leases,
            peak_server_leases,
        )
    }

    fn max_ack_range_count(capture: &Arc<Mutex<Vec<Vec<u8>>>>) -> usize {
        let packets = capture.lock().unwrap();
        let mut maximum = 0;
        for packet in packets.iter() {
            let Ok((_, mut offset)) = crate::ShortHeader::decode(packet) else {
                continue;
            };
            while offset < packet.len() {
                let Ok((frame, length)) = crate::decode_frame(&packet[offset..]) else {
                    break;
                };
                if let crate::Frame::AckRanges { ranges, .. } = frame {
                    maximum = maximum.max(ranges.len());
                }
                offset += length;
            }
        }
        maximum
    }
}

impl<P, const PACKET: usize> NoStdRuntime<P, PACKET>
where
    P: PacketPool + 'static,
    P::Buffer: Send,
{
    /// Return and clear the number of ingress packets dropped because the
    /// bounded queue was full or briefly locked by the node owner.
    pub fn take_ingress_drops(&self) -> usize {
        self.ingress.take_enqueue_drops()
    }

    /// Current node-wide admission limits.
    pub fn limits(&self) -> crate::NodeLimits {
        self.node.limits()
    }

    /// Read-only transport counters and send state for one live association.
    pub fn association_telemetry(
        &self,
        association: QuicAssociation,
    ) -> Option<crate::AssociationTelemetry> {
        self.node.association_telemetry(association)
    }

    /// The bearer an association's first path runs over (see
    /// [`QuicNode::association_bearer_name`]).
    pub fn association_bearer_name(&self, id: QuicAssociation) -> Option<crate::BearerName> {
        self.node.association_bearer_name(id)
    }

    /// Aggregate QUIC counters over currently live associations.
    pub fn telemetry(&self) -> crate::NodeTelemetry {
        self.node.telemetry()
    }

    /// Current defaults inherited by associations admitted after this call.
    pub fn default_association_limits(&self) -> crate::AssociationLimits {
        self.node.default_association_limits()
    }

    /// Replace node-wide runtime admission limits.
    pub fn set_limits(&mut self, limits: crate::NodeLimits) -> Result<(), crate::QuicNodeError> {
        self.node.set_limits(limits)
    }

    /// Select limits for associations admitted after this call.
    pub fn set_default_association_limits(
        &mut self,
        limits: crate::AssociationLimits,
    ) -> Result<(), crate::QuicNodeError> {
        self.limits = limits.connection;
        self.node.set_default_association_limits(limits)
    }

    /// Change one live association's growth policy.
    pub fn set_association_limits(
        &mut self,
        association: crate::QuicAssociation,
        limits: crate::AssociationLimits,
    ) -> Result<(), crate::QuicNodeEgressError> {
        self.node.set_association_limits(association, limits)
    }

    /// Bind fixed server admission limits to a node registered with its
    /// physical bearers.
    pub fn new(node: QuicNode<P, PACKET>, limits: ConnectionLimits) -> Self {
        let ingress = Arc::new(IngressQueue::new(node.packet_capacity().max(1)));
        Self {
            node,
            limits,
            ingress,
            accepted: VecDeque::new(),
            streams: VecDeque::new(),
        }
    }

    /// Allocate and initialize the complete no-std runtime in its final heap
    /// location.
    ///
    /// This is exported for RTOS integrations whose packet task stack cannot
    /// hold the complete node state even temporarily. It exposes
    /// no transport internals: callers receive the same opaque runtime as
    /// [`Self::new`], with allocation failure reported before initialization.
    pub fn try_new_boxed(pool: &'static P, limits: ConnectionLimits) -> Result<Box<Self>, ()> {
        let mut allocation = Vec::<core::mem::MaybeUninit<Self>>::new();
        allocation.try_reserve_exact(1).map_err(|_| ())?;
        allocation.push(core::mem::MaybeUninit::uninit());
        let mut allocation = allocation.into_boxed_slice();
        unsafe {
            let runtime = allocation[0].as_mut_ptr();
            let node_storage = &mut *core::ptr::addr_of_mut!((*runtime).node)
                .cast::<core::mem::MaybeUninit<QuicNode<P, PACKET>>>();
            let capacity = QuicNode::new_in_place(node_storage, pool)
                .packet_capacity()
                .max(1);
            core::ptr::addr_of_mut!((*runtime).limits).write(limits);
            core::ptr::addr_of_mut!((*runtime).ingress)
                .write(Arc::new(IngressQueue::new(capacity)));
            core::ptr::addr_of_mut!((*runtime).accepted).write(VecDeque::new());
            core::ptr::addr_of_mut!((*runtime).streams).write(VecDeque::new());
            let raw = Box::into_raw(allocation) as *mut core::mem::MaybeUninit<Self>;
            Ok(Box::from_raw(raw.cast::<Self>()))
        }
    }

    /// Add one physical packet bearer to this no-executor node.
    ///
    /// The bearer receives the node-owned pool and a fixed-capacity ingress
    /// queue. Interrupts or RTOS tasks enqueue complete packets through their
    /// retained [`crate::BearerContext`]; application code never injects
    /// packets into QUIC directly.
    pub fn add_bearer<T>(
        &mut self,
        bearer: T,
    ) -> Result<crate::BearerId, AddBearerError<T::AttachError>>
    where
        T: PacketBearer<P> + 'static,
    {
        self.node
            .register_bearer_with_ingress(bearer, self.ingress.clone())
    }

    /// Remove a physical bearer and forget association routes learned through it.
    ///
    /// The association and stream state remain owned by this runtime. They may
    /// continue through another address already learned on another bearer.
    pub fn remove_bearer(&mut self, bearer: crate::BearerId) -> bool {
        self.node.remove_bearer(bearer)
    }

    /// Start a client association through a registered bearer.
    ///
    /// The returned opaque handle names the client side of this association.
    /// Server associations admitted by [`Self::progress`] use the same
    /// handle type; `QuicNode` retains the role and applies the corresponding
    /// stream-number and packet rules internally.
    pub fn associate(
        &mut self,
        address: PacketMeta,
        now_us: u64,
    ) -> Result<QuicAssociation, QuicNodeEgressError> {
        self.node.associate(address, now_us)
    }

    /// Start a client association through a layered relay circuit.
    ///
    /// The supplied hops are resolved by the relays along the route. The
    /// returned handle names the client association while setup retries and
    /// reply processing continue through the same bearer-driven runtime.
    pub fn associate_relayed(
        &mut self,
        address: PacketMeta,
        destination_vip: Option<u64>,
        hops: &[crate::RelayHop],
        now_us: u64,
    ) -> Result<QuicAssociation, QuicNodeEgressError>
    where
        P::Buffer: Send,
    {
        self.node
            .associate_relayed(address, destination_vip, hops, now_us)
    }

    /// Start a layered relay circuit and attach nearby return-path hints for
    /// the peer accepted at the far endpoint.
    pub fn associate_relayed_with_return_hints(
        &mut self,
        address: PacketMeta,
        destination_vip: Option<u64>,
        hops: &[crate::RelayHop],
        return_hints: crate::NearbyRelayHints,
        now_us: u64,
    ) -> Result<QuicAssociation, QuicNodeEgressError>
    where
        P::Buffer: Send,
    {
        self.node.associate_relayed_with_return_hints(
            address,
            destination_vip,
            hops,
            return_hints,
            now_us,
        )
    }

    /// Start a relayed association using an explicit setup routing mode.
    pub fn associate_relayed_with_route_mode(
        &mut self,
        address: PacketMeta,
        destination_vip: Option<u64>,
        hops: &[crate::RelayHop],
        return_hints: crate::NearbyRelayHints,
        route_mode: crate::RelayRouteMode,
        now_us: u64,
    ) -> Result<QuicAssociation, QuicNodeEgressError>
    where
        P::Buffer: Send,
    {
        self.node.associate_relayed_with_route_mode(
            address,
            destination_vip,
            hops,
            return_hints,
            route_mode,
            now_us,
        )
    }

    /// Add a layered relay circuit to an established client association.
    ///
    /// Setup and join replies travel through registered bearers; path data is
    /// scheduled only after the end-to-end path validation succeeds.
    pub fn join_relayed_path(
        &mut self,
        association: QuicAssociation,
        address: PacketMeta,
        hops: &[crate::RelayHop],
        now_us: u64,
    ) -> Result<crate::CircuitId, QuicNodeEgressError>
    where
        P::Buffer: Send,
    {
        self.node
            .join_relayed_path(association, address, hops, now_us)
    }

    /// Add a relayed path using an explicit setup routing mode and VIP.
    pub fn join_relayed_path_with_route_mode(
        &mut self,
        association: QuicAssociation,
        address: PacketMeta,
        hops: &[crate::RelayHop],
        route_mode: crate::RelayRouteMode,
        destination_vip: Option<u64>,
        now_us: u64,
    ) -> Result<crate::CircuitId, QuicNodeEgressError>
    where
        P::Buffer: Send,
    {
        self.node.join_relayed_path_with_route_mode(
            association,
            address,
            hops,
            route_mode,
            destination_vip,
            now_us,
        )
    }

    /// Add a directly reachable circuit to an established association.
    pub fn add_direct_circuit(
        &mut self,
        association: QuicAssociation,
        next_hop: crate::CircuitNextHop,
        now_us: u64,
    ) -> Result<crate::CircuitId, QuicNodeEgressError> {
        self.node.add_direct_circuit(association, next_hop, now_us)
    }

    /// Retry a circuit whose join has not yet been validated.
    pub fn retry_direct_circuit(
        &mut self,
        circuit: crate::CircuitId,
    ) -> Result<(), QuicNodeEgressError> {
        self.node.retry_direct_circuit(circuit)
    }

    /// Mark a direct circuit unavailable after a neighbour-down notification.
    pub fn suspend_circuit(
        &mut self,
        circuit: crate::CircuitId,
    ) -> Result<(), QuicNodeEgressError> {
        self.node.suspend_circuit(circuit)
    }

    /// Probe a previously suspended circuit through a newly available next hop.
    pub fn resume_circuit(
        &mut self,
        circuit: crate::CircuitId,
        next_hop: crate::CircuitNextHop,
        now_us: u64,
    ) -> Result<(), QuicNodeEgressError> {
        self.node.resume_circuit(circuit, next_hop, now_us)
    }

    /// Close a circuit after PATH_STATUS abandon has been acknowledged.
    /// The first call queues the status and returns `CircuitBusy`; retry after
    /// the peer's ACK arrives.
    pub fn close_circuit(&mut self, circuit: crate::CircuitId) -> Result<(), QuicNodeEgressError> {
        self.node.close_circuit(circuit)
    }

    /// Fill `out` with circuit telemetry and return the total circuit count.
    pub fn circuits(&self, association: QuicAssociation, out: &mut [crate::CircuitInfo]) -> usize {
        self.node.circuits(association, out)
    }

    /// Open a locally initiated bidirectional stream on an association.
    pub fn open_stream(
        &mut self,
        association: QuicAssociation,
    ) -> Result<crate::QuicStream, QuicNodeEgressError> {
        self.node.open_stream(association)
    }

    /// Submit the next ordered bytes on an outbound or related stream.
    ///
    /// Temporary pool, flow-control, congestion, or bearer pressure leaves
    /// the stream position unchanged so the caller can retry the same bytes.
    pub fn write_stream(
        &mut self,
        stream: &mut crate::QuicStream,
        bytes: &[u8],
    ) -> Result<usize, QuicNodeEgressError> {
        self.node.write_stream(stream, bytes)
    }

    /// Write the final application bytes, carrying FIN on the packet that
    /// accepts the complete remaining slice.
    pub fn write_stream_and_finish(
        &mut self,
        stream: &mut crate::QuicStream,
        bytes: &[u8],
    ) -> Result<usize, QuicNodeEgressError> {
        self.node.write_stream_and_finish(stream, bytes)
    }

    /// Close the stream's sending half after all accepted bytes.
    pub fn finish_stream(
        &mut self,
        stream: &mut crate::QuicStream,
    ) -> Result<(), QuicNodeEgressError> {
        self.node.finish_stream(stream)
    }

    /// Peer-advertised byte credit at the stream's current ordered position.
    pub fn stream_send_window(
        &self,
        stream: &crate::QuicStream,
    ) -> Result<u64, QuicNodeEgressError> {
        self.node.stream_send_window(stream)
    }

    /// Whether the association has completed client establishment or is an
    /// admitted server association. Role remains node-private.
    pub fn association_is_established(&self, association: QuicAssociation) -> bool {
        self.node.association_is_established(association)
    }

    /// Process at most one queued bearer event.
    ///
    /// An RTOS task calls this after its bearer wake notification. Returning
    /// `true` means one packet was consumed; returning `false` means ingress
    /// was empty or is paused until a retained egress packet can be retried.
    /// The method does not wait or poll in a loop.
    pub fn progress(&mut self) -> Result<bool, QuicNodeEgressError> {
        self.node.drain_bearer_events();
        if !self.node.can_progress_ingress() {
            return Ok(false);
        }
        let Some(received) = self.ingress.pop() else {
            return Ok(false);
        };
        self.process_packet::<fn(crate::QuicStream, u64, bool, &[u8]) -> Result<usize, crate::Error>>(
            received.meta,
            received.packet,
            None,
        )?;
        Ok(true)
    }

    /// Drain all packets currently queued by bearer callbacks.
    ///
    /// Callback wakeups may coalesce when several datagrams arrive before the
    /// owner task runs. Owners that receive one wake per burst should use this
    /// method (or repeat [`Self::progress`]) so every queued packet is handled
    /// before sleeping again.
    pub fn progress_all(&mut self) -> Result<usize, QuicNodeEgressError> {
        let mut processed = 0usize;
        while self.progress()? {
            processed = processed.saturating_add(1);
        }
        Ok(processed)
    }

    /// Process one bearer event while delivering associated stream bytes
    /// directly from the receive packet.
    ///
    /// Returning `n` accepts exactly the first `n` bytes. QUIC-lite retains an
    /// unread suffix under its ordered-delivery limit and does not grant
    /// receive credit for it. A zero-length chunk (a bare FIN) cannot be
    /// refused: returning 0 for it accepts the end of the stream. In-order
    /// chunks therefore require no per-chunk
    pub fn progress_with_stream<F>(&mut self, mut on_stream: F) -> Result<bool, QuicNodeEgressError>
    where
        F: FnMut(crate::QuicStream, u64, bool, &[u8]) -> Result<usize, crate::Error>,
    {
        self.node.drain_bearer_events();
        // Control generated by a consumed application chunk may have been
        // deferred while a bearer retained its previous packet. Retry it on
        // this owner turn after readiness/completion has been processed.
        if self.node.retry_one_pending_control()? {
            return Ok(true);
        }
        // Processing another packet can itself generate an ACK or flow-control
        // packet. Leave ingress queued until any previously blocked egress is
        // retried, rather than submitting past the bearer-owned retained slot.
        if !self.node.can_progress_ingress() {
            return Ok(false);
        }
        let Some(received) = self.ingress.pop() else {
            return Ok(false);
        };
        self.process_packet(received.meta, received.packet, Some(&mut on_stream))?;
        Ok(true)
    }

    /// Drain every currently queued packet while delivering stream bytes to
    /// one application callback. This is the burst-safe form of
    /// [`Self::progress_with_stream`] for event-coalescing bearers.
    pub fn progress_all_with_stream<F>(
        &mut self,
        mut on_stream: F,
    ) -> Result<usize, QuicNodeEgressError>
    where
        F: FnMut(crate::QuicStream, u64, bool, &[u8]) -> Result<usize, crate::Error>,
    {
        let mut processed = 0usize;
        while self.progress_with_stream(&mut on_stream)? {
            processed = processed.saturating_add(1);
        }
        Ok(processed)
    }

    /// Advance transport timers and retain any terminal association event.
    pub fn advance_time(&mut self, now_us: u64) -> Result<bool, QuicNodeEgressError> {
        self.node.advance_clock(now_us);
        match self.node.timer_expired(now_us)? {
            Some(crate::node::NodeTimer::Egress(packet)) => {
                self.node.submit_node_packet(packet)?;
                Ok(true)
            }
            Some(crate::node::NodeTimer::BootstrapTimedOut { .. }) => Ok(true),
            Some(crate::node::NodeTimer::IdleTimedOut { .. }) => Ok(true),
            Some(crate::node::NodeTimer::CircuitSetupTimedOut { .. }) => Ok(true),
            None => Ok(false),
        }
    }

    /// Earliest transport retry, loss, or idle deadline for the platform timer.
    pub fn next_deadline(&self) -> Option<u64> {
        self.node.next_deadline()
    }

    fn process_packet<F>(
        &mut self,
        meta: PacketMeta,
        packet: OwnedPacket<P::Buffer>,
        mut on_stream: Option<&mut F>,
    ) -> Result<(), QuicNodeEgressError>
    where
        F: FnMut(crate::QuicStream, u64, bool, &[u8]) -> Result<usize, crate::Error>,
    {
        self.node.drain_bearer_events();
        let limits = self.limits;
        let node_limits = self.node.limits();
        let stream_queue_limit = node_limits
            .max_associations
            .saturating_mul(self.node.default_association_limits().max_pending_streams)
            .max(1);
        let streams = &mut self.streams;
        let ingress = self
            .node
            .receive_packet(
                meta,
                packet,
                |_| {
                    Some(InitialAdmission {
                        local_limits: limits,
                    })
                },
                |source, stream, offset, fin, bytes| {
                    let ApplicationStreamSource::Association(association) = source;
                    if let Some(handler) = on_stream.as_deref_mut() {
                        return handler(
                            crate::QuicStream::incoming(association, stream),
                            offset,
                            fin,
                            bytes,
                        );
                    }
                    // A zero-length FIN cannot be refused (it has no bytes
                    // to retain), so it is queued even at capacity.
                    if !bytes.is_empty()
                        && (streams.len() >= stream_queue_limit || streams.try_reserve(1).is_err())
                    {
                        return Ok(0);
                    }
                    streams.push_back(ReceivedStreamChunk {
                        stream: crate::QuicStream::incoming(association, stream),
                        offset,
                        fin,
                        bytes: bytes.to_vec(),
                    });
                    Ok(bytes.len())
                },
            )
            .map_err(|rejected| match rejected.reason {
                QuicNodePacketRejection::Egress(error) => error,
                QuicNodePacketRejection::Packet(error)
                | QuicNodePacketRejection::Application(error) => {
                    QuicNodeEgressError::Transport(error)
                }
                QuicNodePacketRejection::PeerClosed(_) => {
                    QuicNodeEgressError::Transport(crate::Error::PeerRestarted)
                }
            })?;

        match ingress {
            NodeIngress::Initial {
                association,
                response,
            } => {
                if self.accepted.len() < node_limits.max_associations
                    && self.accepted.try_reserve(1).is_ok()
                {
                    self.accepted.push_back(association);
                }
                self.node.submit_egress(
                    response.bearer,
                    response.peer_l2_address,
                    response.packet,
                )?;
            }
            NodeIngress::SetupReply { response } => self.node.submit_egress(
                response.bearer,
                response.peer_l2_address,
                response.packet,
            )?,
            NodeIngress::SetupAccepted {
                association,
                return_hints: _,
                response,
            } => {
                if self.accepted.len() < node_limits.max_associations
                    && self.accepted.try_reserve(1).is_ok()
                {
                    self.accepted.push_back(association);
                }
                self.node.submit_egress(
                    response.bearer,
                    response.peer_l2_address,
                    response.packet,
                )?;
            }
            NodeIngress::PathControl { response, .. } => {
                self.node.submit_node_packet(response)?;
            }
            NodeIngress::Association { association, .. } => {
                self.node
                    .submit_or_defer_control(association.association())?;
            }
            NodeIngress::StatelessReset { response } => self.node.submit_egress(
                response.bearer,
                response.peer_l2_address,
                response.packet,
            )?,
            NodeIngress::PeerReset { .. } | NodeIngress::PeerClosed { .. } => {}
            NodeIngress::Forward { next_hop, packet } => {
                self.node
                    .submit_egress(next_hop.bearer, next_hop.peer_l2_address, packet)?
            }
            NodeIngress::InitialDeclined { .. }
            | NodeIngress::Unknown { .. }
            | NodeIngress::NonQuic { .. } => {}
        }
        Ok(())
    }

    /// Take the next newly accepted association.
    pub fn next_association(&mut self) -> Option<QuicAssociation> {
        self.accepted.pop_front()
    }

    /// Take the next ordered application stream chunk.
    pub fn next_stream_chunk(&mut self) -> Option<ReceivedStreamChunk> {
        let chunk = self.streams.pop_front()?;
        if let Some(association) = chunk.stream.association() {
            let stream_queue_limit = self
                .node
                .limits()
                .max_associations
                .saturating_mul(self.node.default_association_limits().max_pending_streams)
                .max(1);
            let streams = &mut self.streams;
            let resumed = self.node.resume_stream_delivery(
                association,
                chunk.stream.id(),
                &mut |source, stream, offset, fin, bytes| {
                    let ApplicationStreamSource::Association(association) = source;
                    // A zero-length FIN cannot be refused (it has no bytes to
                    // retain), so it is queued even at capacity.
                    if !bytes.is_empty()
                        && (streams.len() >= stream_queue_limit || streams.try_reserve(1).is_err())
                    {
                        return Ok(0);
                    }
                    streams.push_back(ReceivedStreamChunk {
                        stream: crate::QuicStream::incoming(association, stream),
                        offset,
                        fin,
                        bytes: bytes.to_vec(),
                    });
                    Ok(bytes.len())
                },
            );
            debug_assert!(
                resumed.is_ok(),
                "retained stream resume failed: {resumed:?}"
            );
            if resumed.is_ok_and(|bytes| bytes != 0) {
                let _ = self.node.submit_or_defer_control(association);
            }
        }
        Some(chunk)
    }

    /// Take the next terminal association lifecycle event.
    pub fn next_event(&mut self) -> Option<crate::AssociationEvent> {
        self.node.next_association_event()
    }
}
