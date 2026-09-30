//! Host ESP-NOW action-frame adapter for `quic-lite`.
//!
//! NOW synchronization and discovery remain raw radio operations. Every other
//! ESP-NOW payload is an opaque QUIC packet; the ESP-NOW envelope itself is
//! the bearer framing, so no UART marker is added.

use std::sync::{Arc, Mutex};

use quic_lite::bearer::{
    BearerContext, BearerInfo, BearerName, EgressSubmission, PacketBearer, PacketEgress,
    PacketMeta, PacketPool, PacketSendOutcome, PacketSubmitError, PacketWriter, PeerL2Address,
};

/// Type-erased receive side retained by the raw NAN monitor.
pub trait EspNowIngress: Send + Sync {
    /// Decode directly into the registered QUIC packet pool, then let the
    /// radio owner consume connectionless records in place. Return `true`
    /// only when the borrowed payload is an opaque packet for QUIC ingress.
    fn receive_action_frame(
        &self,
        frame: &[u8],
        received_at_us: u64,
        admit: &mut dyn FnMut([u8; 6], &[u8]) -> bool,
    );
}

struct Shared<P: PacketPool + 'static> {
    context: Mutex<Option<BearerContext<P>>>,
}

impl<P> EspNowIngress for Shared<P>
where
    P: PacketPool + Sync + 'static,
    P::Buffer: Send,
{
    fn receive_action_frame(
        &self,
        frame: &[u8],
        received_at_us: u64,
        admit: &mut dyn FnMut([u8; 6], &[u8]) -> bool,
    ) {
        let context = self
            .context
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let Some(context) = context else { return };
        let Some(mut writer) = context
            .pool()
            .acquire_writer(quic_lite::PACKET_PREFIX_RESERVE, 0)
        else {
            return;
        };
        let Some((peer, len)) =
            dmesh_rawnan::espnow::parse_action_frame_into(frame, writer.payload_mut())
        else {
            return;
        };
        if !admit(peer, &writer.payload_mut()[..len]) {
            return;
        }
        let Some(packet) = writer.commit(len) else {
            return;
        };
        context.enqueue_packet(
            PacketMeta {
                bearer: context.bearer(),
                peer_l2_address: peer_address(peer),
                received_at_us,
            },
            packet,
        );
    }
}

/// ESP-NOW action-frame bearer. The radio monitor owns frame parsing and calls
/// the returned [`EspNowIngress`]; this adapter owns no packet queue or pool.
pub struct EspNowBearer<P: PacketPool + 'static> {
    iface: String,
    shared: Arc<Shared<P>>,
}

impl<P: PacketPool + 'static> EspNowBearer<P> {
    pub fn new(iface: impl Into<String>) -> (Self, Arc<dyn EspNowIngress>)
    where
        P: Sync,
        P::Buffer: Send,
    {
        let shared = Arc::new(Shared {
            context: Mutex::new(None),
        });
        (
            Self {
                iface: iface.into(),
                shared: shared.clone(),
            },
            shared,
        )
    }
}

impl<P> PacketEgress<P::Buffer> for EspNowBearer<P>
where
    P: PacketPool + 'static,
{
    fn submit(
        &mut self,
        peer: PeerL2Address,
        submission: EgressSubmission<P::Buffer>,
    ) -> Result<(), PacketSubmitError<P::Buffer>> {
        let result = crate::radio::send_raw_action_datagram(
            &self.iface,
            address_peer(peer),
            submission.packet().bytes(),
            1,
        );
        submission.complete(
            if result.is_ok() {
                PacketSendOutcome::Sent
            } else {
                PacketSendOutcome::Failed
            },
            0,
        );
        Ok(())
    }
}

impl<P> PacketBearer<P> for EspNowBearer<P>
where
    P: PacketPool + Sync + 'static,
    P::Buffer: Send + 'static,
{
    type AttachError = core::convert::Infallible;

    fn info(&self) -> BearerInfo {
        BearerInfo {
            name: BearerName::new("espnow").unwrap(),
            max_packet_size: quic_lite::DEFAULT_MAX_PACKET_SIZE,
            prefix_required: 0,
            suffix_required: 0,
            requires_packet_encryption: true,
            secure_link: false,
            nominal_bitrate_bps: 1_000_000,
            local_mac: None,
        }
    }

    fn attach(&mut self, context: BearerContext<P>) -> Result<(), Self::AttachError> {
        *self
            .shared
            .context
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(context);
        Ok(())
    }
}

/// Stable bearer-local address derived from the immediate peer MAC.
pub fn peer_address(peer: [u8; 6]) -> PeerL2Address {
    let value = peer
        .into_iter()
        .fold(0_u64, |value, octet| (value << 8) | u64::from(octet));
    PeerL2Address::new(value.max(1)).unwrap()
}

fn address_peer(address: PeerL2Address) -> [u8; 6] {
    let bytes = address.value().to_be_bytes();
    bytes[2..].try_into().unwrap()
}

#[cfg(test)]
mod tests {
    use super::{EspNowBearer, EspNowIngress, address_peer, peer_address};
    use quic_lite::bearer::PacketBearer;

    type TestPool =
        quic_lite::packet_pool::PacketPool<4, { quic_lite::DEFAULT_PACKET_POOL_SLOT_SIZE }>;
    static POOL: TestPool = TestPool::new();

    #[test]
    fn peer_handle_round_trips_full_mac_and_is_nonzero() {
        for peer in [[0x02, 0x11, 0x22, 0x33, 0x44, 0x55], [0xff; 6]] {
            let handle = peer_address(peer);
            assert_ne!(handle.value(), 0);
            assert_eq!(address_peer(handle), peer);
        }
    }

    #[test]
    fn action_payload_is_parsed_in_the_node_pool_and_can_be_consumed_in_place() {
        let source = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];
        let control = [0xa3, 1, 6, 2, 1, 3, 1];
        let quic = [0x40, 0x01, 0x02, 0x03];
        let frame =
            dmesh_rawnan::espnow::build_action_frame([0xff; 6], source, [0xff; 6], &control)
                .unwrap();
        let (bearer, ingress) = EspNowBearer::<TestPool>::new("not-opened-by-receive-test");
        let mut node: quic_lite::QuicNode<TestPool> = quic_lite::QuicNode::new(None, &POOL);
        node.add_bearer(bearer).unwrap();

        let available_before_control = POOL.available();
        let mut observed = false;
        ingress.receive_action_frame(&frame, 17, &mut |peer, payload| {
            assert_eq!(peer, source);
            assert_eq!(payload, control);
            observed = true;
            false // A control frame is handled here, not enqueued into QUIC.
        });
        assert!(observed);
        assert_eq!(POOL.available(), available_before_control);

        let quic_frame =
            dmesh_rawnan::espnow::build_action_frame([0xff; 6], source, [0xff; 6], &quic).unwrap();
        let available_before_quic = POOL.available();
        ingress.receive_action_frame(&quic_frame, 18, &mut |peer, payload| {
            assert_eq!(peer, source);
            assert_eq!(payload, quic);
            true
        });
        // Accepted opaque QUIC owns a pool lease in the node ingress queue;
        // non-QUIC control above was handled in place and released its lease.
        assert_eq!(POOL.available(), available_before_quic - 1);
    }
}
