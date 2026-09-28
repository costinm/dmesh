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
    /// Deliver one complete opaque QUIC packet received from `peer`.
    fn receive(&self, peer: [u8; 6], packet: &[u8], received_at_us: u64);
}

struct Shared<P: PacketPool + 'static> {
    context: Mutex<Option<BearerContext<P>>>,
}

impl<P> EspNowIngress for Shared<P>
where
    P: PacketPool + Sync + 'static,
    P::Buffer: Send,
{
    fn receive(&self, peer: [u8; 6], packet: &[u8], received_at_us: u64) {
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
        if packet.len()
            > writer
                .payload_mut()
                .len()
                .saturating_sub(quic_lite::PACKET_SUFFIX_RESERVE)
        {
            return;
        }
        writer.payload_mut()[..packet.len()].copy_from_slice(packet);
        let Some(packet) = writer.commit(packet.len()) else {
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
