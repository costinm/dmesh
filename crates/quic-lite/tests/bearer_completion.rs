#![cfg(feature = "tokio")]
#![deny(deprecated)]

use std::sync::{Arc, Mutex};

use quic_lite::tokio::TokioNodeDriver;
use quic_lite::{
    BearerContext, BearerInfo, BearerName, CircuitNextHop, EgressSubmission, OwnedPacket,
    PacketBearer, PacketCompletionToken, PacketEgress, PacketMeta, PacketPool as PacketPoolTrait,
    PacketSendOutcome, PacketSubmitError, PacketWriter, PeerL2Address, QuicNode,
    QuicNodeEgressError, fake::FakePacketBearer, packet_pool::PacketPool,
};
use tokio::io::AsyncWriteExt;

type Pool = PacketPool<4, { quic_lite::DEFAULT_PACKET_POOL_SLOT_SIZE }>;
type Buffer = <Pool as PacketPoolTrait>::Buffer;
type SubmissionParts = (OwnedPacket<Buffer>, PacketCompletionToken<Buffer>);

static POOL: Pool = Pool::new();

type PairPool = PacketPool<16, { quic_lite::DEFAULT_PACKET_POOL_SLOT_SIZE }>;
type PairBuffer = <PairPool as PacketPoolTrait>::Buffer;
type PairNode = QuicNode<PairPool>;
type HeldSubmission = (OwnedPacket<PairBuffer>, PacketCompletionToken<PairBuffer>);

static DELAYED_CLIENT_POOL: PairPool = PairPool::new();
static DELAYED_SERVER_POOL: PairPool = PairPool::new();

#[derive(Default)]
struct DelayedPairState {
    contexts: [Option<BearerContext<PairPool>>; 2],
    completions: Vec<HeldSubmission>,
    submitted: [usize; 2],
    received: [usize; 2],
}

impl DelayedPairState {
    fn pending(&self) -> usize {
        self.completions.len()
    }

    fn complete_all(&mut self) {
        for (packet, completion) in self.completions.drain(..) {
            completion.complete(packet, PacketSendOutcome::Sent, 1_000);
        }
    }
}

struct DelayedPairBearer {
    state: Arc<Mutex<DelayedPairState>>,
    side: usize,
}

impl DelayedPairBearer {
    fn pair() -> (Self, Self, Arc<Mutex<DelayedPairState>>) {
        let state = Arc::new(Mutex::new(DelayedPairState::default()));
        (
            Self {
                state: state.clone(),
                side: 0,
            },
            Self {
                state: state.clone(),
                side: 1,
            },
            state,
        )
    }
}

impl PacketEgress<PairBuffer> for DelayedPairBearer {
    fn submit(
        &mut self,
        _peer: PeerL2Address,
        submission: EgressSubmission<PairBuffer>,
    ) -> Result<(), PacketSubmitError<PairBuffer>> {
        let (packet, completion) = submission.into_parts();
        let mut state = self.state.lock().unwrap();
        state.submitted[self.side] += 1;
        let peer = state.contexts[1 - self.side]
            .as_ref()
            .expect("both delayed pair bearers are attached")
            .clone();
        let bytes = packet.bytes().to_vec();
        if let Some(mut writer) = peer
            .pool()
            .acquire_writer(quic_lite::PACKET_PREFIX_RESERVE, 0)
        {
            if let Some(output) = writer.payload_mut().get_mut(..bytes.len()) {
                output.copy_from_slice(&bytes);
                if let Some(received) = writer.commit(bytes.len()) {
                    state.received[1 - self.side] += 1;
                    peer.enqueue_packet(
                        PacketMeta {
                            bearer: peer.bearer(),
                            peer_l2_address: PeerL2Address::new(1).unwrap(),
                            received_at_us: 0,
                        },
                        received,
                    );
                }
            }
        }
        state.completions.push((packet, completion));
        state.contexts[self.side]
            .as_ref()
            .expect("local delayed bearer is attached")
            .send_ready();
        Ok(())
    }
}

impl PacketBearer<PairPool> for DelayedPairBearer {
    type AttachError = core::convert::Infallible;

    fn info(&self) -> BearerInfo {
        BearerInfo {
            name: BearerName::new(if self.side == 0 {
                "delayed-client"
            } else {
                "delayed-server"
            })
            .unwrap(),
            max_packet_size: quic_lite::DEFAULT_MAX_PACKET_SIZE,
            prefix_required: quic_lite::PACKET_PREFIX_RESERVE,
            suffix_required: quic_lite::PACKET_SUFFIX_RESERVE,
            requires_packet_encryption: false,
            secure_link: true,
            nominal_bitrate_bps: 1_000_000,
            local_mac: None,
        }
    }

    fn attach(&mut self, context: BearerContext<PairPool>) -> Result<(), Self::AttachError> {
        self.state.lock().unwrap().contexts[self.side] = Some(context);
        Ok(())
    }
}

#[derive(Default)]
struct SendState {
    calls: usize,
    first_bytes: Vec<u8>,
    accepted: Option<SubmissionParts>,
}

struct DeferredBearer {
    context: Arc<Mutex<Option<BearerContext<Pool>>>>,
    state: Arc<Mutex<SendState>>,
}

impl PacketEgress<Buffer> for DeferredBearer {
    fn submit(
        &mut self,
        _peer: PeerL2Address,
        submission: EgressSubmission<Buffer>,
    ) -> Result<(), PacketSubmitError<Buffer>> {
        let mut state = self.state.lock().unwrap();
        state.calls += 1;
        if state.calls == 1 {
            state.first_bytes = submission.packet().bytes().to_vec();
            return Err(PacketSubmitError::WouldBlock(submission));
        }

        assert!(state.accepted.is_none());
        state.accepted = Some(submission.into_parts());
        Ok(())
    }
}

impl PacketBearer<Pool> for DeferredBearer {
    type AttachError = core::convert::Infallible;

    fn info(&self) -> BearerInfo {
        BearerInfo {
            name: BearerName::new("deferred").unwrap(),
            max_packet_size: quic_lite::DEFAULT_MAX_PACKET_SIZE,
            prefix_required: quic_lite::PACKET_PREFIX_RESERVE,
            suffix_required: quic_lite::PACKET_SUFFIX_RESERVE,
            requires_packet_encryption: false,
            secure_link: true,
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
fn would_block_retries_the_same_lease_and_completion_restores_node_capacity() {
    let context = Arc::new(Mutex::new(None));
    let state = Arc::new(Mutex::new(SendState::default()));
    let mut node = QuicNode::<Pool>::new(&POOL);
    let bearer = node
        .add_bearer(DeferredBearer {
            context: context.clone(),
            state: state.clone(),
        })
        .unwrap();
    let address = PacketMeta {
        bearer,
        peer_l2_address: PeerL2Address::new(1).unwrap(),
        received_at_us: 0,
    };

    assert_eq!(node.available_packets(), 4);
    node.associate(address, 0).unwrap();
    assert_eq!(node.available_packets(), 3);
    assert_eq!(state.lock().unwrap().calls, 1);

    context.lock().unwrap().as_ref().unwrap().send_ready();
    assert_eq!(
        node.associate(address, 1),
        Err(QuicNodeEgressError::BearerBusy)
    );

    let (packet, completion) = state.lock().unwrap().accepted.take().unwrap();
    assert_eq!(state.lock().unwrap().calls, 2);
    assert_eq!(packet.bytes(), state.lock().unwrap().first_bytes);
    completion.complete(packet, PacketSendOutcome::Sent, 25);

    // Completion is an event: the lease returns when the node next advances.
    assert_eq!(node.available_packets(), 3);
    node.associate(address, 2).unwrap();
    assert_eq!(node.available_packets(), 3);

    let (packet, completion) = state.lock().unwrap().accepted.take().unwrap();
    completion.complete(packet, PacketSendOutcome::Failed, 30);

    // A terminal physical failure still returns the lease and restores bearer
    // readiness. It does not masquerade as a peer ACK.
    node.associate(address, 3).unwrap();
    assert_eq!(state.lock().unwrap().calls, 4);
}

#[tokio::test]
async fn direct_circuit_delayed_completion_preserves_stream_delivery_and_pool_leases() {
    let (client_base, server_base) = FakePacketBearer::<PairPool>::pair(
        BearerName::new("comp-base-c").unwrap(),
        BearerName::new("comp-base-s").unwrap(),
    );
    let (client_direct, server_direct, delayed) = DelayedPairBearer::pair();
    let mut client_node = PairNode::new(&DELAYED_CLIENT_POOL);
    let mut server_node = PairNode::new(&DELAYED_SERVER_POOL);
    let client_base = client_node.add_bearer(client_base).unwrap();
    let client_direct = client_node.add_bearer(client_direct).unwrap();
    server_node.add_bearer(server_base).unwrap();
    server_node.add_bearer(server_direct).unwrap();
    let (client, client_driver) =
        TokioNodeDriver::new(client_node, quic_lite::ConnectionLimits::default());
    let (server, server_driver) =
        TokioNodeDriver::new(server_node, quic_lite::ConnectionLimits::default());

    let scenario = async move {
        let association = client
            .associate(
                PacketMeta {
                    bearer: client_base,
                    peer_l2_address: PeerL2Address::new(1).unwrap(),
                    received_at_us: 0,
                },
                0,
            )
            .await
            .unwrap();
        association.wait_established().await.unwrap();
        let direct = association
            .add_direct_circuit(
                CircuitNextHop {
                    bearer: client_direct,
                    peer_l2_address: PeerL2Address::new(1).unwrap(),
                },
                1,
            )
            .await
            .unwrap();
        let circuits = tokio::time::timeout(std::time::Duration::from_secs(1), async {
            loop {
                let circuits = association.circuits().await.unwrap();
                if circuits.iter().any(|circuit| {
                    circuit.id == direct && circuit.status == quic_lite::CircuitStatus::Active
                }) {
                    break circuits;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("direct path validation completes");
        assert!(delayed.lock().unwrap().pending() > 0);

        // Force the stream onto the direct circuit. The base path suspension
        // affects client-to-server sends only; the peer can still reply there.
        association.suspend_circuit(circuits[0].id).await.unwrap();
        let mut outgoing = association.open_stream().await.unwrap();
        let sender = async {
            outgoing
                .write_all(b"accepted before completion")
                .await
                .unwrap();
            outgoing.shutdown().await.unwrap();
        };
        let receiver = async {
            let mut incoming = server.accept_stream().await.expect("stream arrives");
            let mut bytes = Vec::new();
            tokio::io::AsyncReadExt::read_to_end(&mut incoming, &mut bytes)
                .await
                .unwrap();
            bytes
        };
        let transfer = tokio::time::timeout(std::time::Duration::from_secs(1), async {
            tokio::join!(sender, receiver)
        })
        .await;
        let circuits_after_transfer = association.circuits().await.unwrap();
        assert!(
            transfer.is_ok(),
            "stream delivery does not wait for completion; circuits={circuits_after_transfer:?}; delayed state={:?}",
            {
                let state = delayed.lock().unwrap();
                (state.submitted, state.received, state.pending())
            }
        );
        let ((), received) = transfer.unwrap();
        assert_eq!(received, b"accepted before completion");
        assert!(delayed.lock().unwrap().pending() > 0);
        assert!(DELAYED_CLIENT_POOL.available() < DELAYED_CLIENT_POOL.capacity());

        delayed.lock().unwrap().complete_all();
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while DELAYED_CLIENT_POOL.available() < DELAYED_CLIENT_POOL.capacity()
                || DELAYED_SERVER_POOL.available() < DELAYED_SERVER_POOL.capacity()
            {
                let _ = association.circuits().await;
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("completion returns every held packet lease to its node pool");
        assert_eq!(
            DELAYED_CLIENT_POOL.available(),
            DELAYED_CLIENT_POOL.capacity()
        );
        assert_eq!(
            DELAYED_SERVER_POOL.available(),
            DELAYED_SERVER_POOL.capacity()
        );
    };

    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        tokio::select! {
            result = client_driver.run() => panic!("client driver stopped: {result:?}"),
            result = server_driver.run() => panic!("server driver stopped: {result:?}"),
            () = scenario => {}
        }
    })
    .await
    .unwrap();
}
