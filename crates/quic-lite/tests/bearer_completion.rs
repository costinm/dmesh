#![cfg(feature = "tokio")]
#![deny(deprecated)]

use std::sync::{Arc, Mutex};

use quic_lite::{
    BearerContext, BearerInfo, BearerName, EgressSubmission, OwnedPacket, PacketBearer,
    PacketCompletionToken, PacketEgress, PacketMeta, PacketPool as PacketPoolTrait,
    PacketSendOutcome, PacketSubmitError, PeerL2Address, QuicNode, QuicNodeEgressError,
    packet_pool::PacketPool,
};

type Pool = PacketPool<4, { quic_lite::DEFAULT_PACKET_POOL_SLOT_SIZE }>;
type Buffer = <Pool as PacketPoolTrait>::Buffer;
type SubmissionParts = (OwnedPacket<Buffer>, PacketCompletionToken<Buffer>);

static POOL: Pool = Pool::new();

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
    let mut node = QuicNode::<(), 4, 4, Pool>::new(None, &POOL);
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
