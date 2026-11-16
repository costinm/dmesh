//! Host ESP-NOW action-frame adapter over [`mesh_api::link::PacketLink`].
//!
//! NOW synchronization and discovery remain raw radio operations. Every other
//! ESP-NOW payload is an opaque packet; the ESP-NOW envelope itself is
//! the link framing, so no UART marker is added.

use std::string::String;
use std::sync::{Arc, Mutex};

use mesh_api::link::{
    LinkInfo, LinkIngress, LinkMeta, LinkName, LinkTxOutcome, PacketLink, PeerL2Address,
};
use mesh_api::pool::{DEFAULT_MAX_PAYLOAD, PacketPool, PoolPacket};

/// Type-erased receive side retained by the raw NAN monitor.
pub trait EspNowIngress: Send + Sync {
    /// Decode the action frame, let the radio owner consume connectionless
    /// records in place, and enqueue admitted opaque packets into the attached
    /// packet pool.
    fn receive_action_frame(
        &self,
        frame: &[u8],
        received_at_us: u64,
        admit: &mut dyn FnMut([u8; 6], &[u8]) -> bool,
    );
}

struct Attached<P: PacketPool> {
    pool: P,
    ingress: Arc<dyn LinkIngress<P::Packet>>,
}

struct Shared<P: PacketPool + 'static> {
    attached: Mutex<Option<Attached<P>>>,
}

impl<P> EspNowIngress for Shared<P>
where
    P: PacketPool + Send + Sync + 'static,
    P::Packet: Send + 'static,
{
    fn receive_action_frame(
        &self,
        frame: &[u8],
        received_at_us: u64,
        admit: &mut dyn FnMut([u8; 6], &[u8]) -> bool,
    ) {
        let mut buf = [0u8; DEFAULT_MAX_PAYLOAD];
        let Some((peer, len)) = crate::espnow::parse_action_frame_into(frame, &mut buf) else {
            return;
        };
        if !admit(peer, &buf[..len]) {
            return;
        }
        let guard = self
            .attached
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(attached) = guard.as_ref() else {
            return;
        };
        let Ok(mut packet) = attached.pool.alloc() else {
            return;
        };
        if packet.append(&buf[..len]).is_err() {
            return;
        }
        attached.ingress.on_packet(
            LinkMeta {
                peer: peer_address(peer),
                received_at_us,
                rssi_dbm: None,
            },
            packet,
        );
    }
}

/// ESP-NOW action-frame link adapter. The radio monitor owns frame parsing and calls
/// the returned [`EspNowIngress`]; this adapter owns no packet queue or pool.
pub struct EspNowBearer<P: PacketPool + 'static> {
    transmitter: super::frames::RawActionTransmitter,
    shared: Arc<Shared<P>>,
    info: LinkInfo,
}

impl<P: PacketPool + 'static> EspNowBearer<P> {
    pub fn new(iface: impl Into<String>) -> (Self, Arc<dyn EspNowIngress>)
    where
        P: Send + Sync,
        P::Packet: Send,
    {
        let shared = Arc::new(Shared {
            attached: Mutex::new(None),
        });
        (
            Self {
                transmitter: super::frames::RawActionTransmitter::new(iface.into()),
                shared: shared.clone(),
                info: LinkInfo {
                    name: LinkName::new("espnow").unwrap(),
                    max_packet_size: DEFAULT_MAX_PAYLOAD,
                    prefix_required: 0,
                    suffix_required: 0,
                    requires_packet_encryption: true,
                    secure_link: false,
                    nominal_bitrate_bps: 6_000_000,
                    local_mac: None,
                },
            },
            shared,
        )
    }

    /// Attach a packet pool and ingress sink for received opaque packets.
    pub fn attach(&mut self, pool: P, ingress: Arc<dyn LinkIngress<P::Packet>>) {
        *self
            .shared
            .attached
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Attached { pool, ingress });
    }
}

impl<P> PacketLink<P::Packet> for EspNowBearer<P>
where
    P: PacketPool + 'static,
{
    fn info(&self) -> &LinkInfo {
        &self.info
    }

    fn send_packet(
        &mut self,
        peer: PeerL2Address,
        packet: P::Packet,
    ) -> Result<LinkTxOutcome, P::Packet> {
        match self
            .transmitter
            .send(address_peer(peer), packet.bytes(), 6)
        {
            Ok(()) => Ok(LinkTxOutcome::Sent),
            Err(super::frames::RawActionSubmitError::WouldBlock) => Err(packet),
            Err(super::frames::RawActionSubmitError::Failed(error)) => {
                tracing::warn!(peer = ?address_peer(peer), %error, "lmesh_espnow_submit_failed");
                Ok(LinkTxOutcome::Failed)
            }
        }
    }
}

/// Stable link-local address derived from the immediate peer MAC.
pub fn peer_address(peer: [u8; 6]) -> PeerL2Address {
    let value = peer
        .into_iter()
        .fold(0_u64, |value, octet| (value << 8) | u64::from(octet));
    PeerL2Address::new(value.max(1)).unwrap()
}

fn address_peer(address: PeerL2Address) -> [u8; 6] {
    let bytes = address.get().to_be_bytes();
    bytes[2..].try_into().unwrap()
}

#[cfg(test)]
mod tests {
    use super::{EspNowBearer, address_peer, peer_address};
    use mesh_api::link::{LinkIngress, LinkMeta};
    use mesh_api::pool::{DEFAULT_SLOT_SIZE, PacketPool as _, StaticPacketLease, StaticPacketPool};
    use std::sync::{Arc, Mutex};
    use std::vec::Vec;

    type StaticPool = StaticPacketPool<4, DEFAULT_SLOT_SIZE>;
    type TestPool = &'static StaticPool;
    static POOL: StaticPool = StaticPacketPool::new();

    struct HoldIngress(Mutex<Vec<(LinkMeta, StaticPacketLease<'static, 4, DEFAULT_SLOT_SIZE>)>>);
    impl LinkIngress<StaticPacketLease<'static, 4, DEFAULT_SLOT_SIZE>> for HoldIngress {
        fn on_packet(
            &self,
            meta: LinkMeta,
            packet: StaticPacketLease<'static, 4, DEFAULT_SLOT_SIZE>,
        ) {
            self.0.lock().unwrap().push((meta, packet));
        }
    }

    #[test]
    fn peer_handle_round_trips_full_mac_and_is_nonzero() {
        for peer in [[0x02, 0x11, 0x22, 0x33, 0x44, 0x55], [0xff; 6]] {
            let handle = peer_address(peer);
            assert_ne!(handle.get(), 0);
            assert_eq!(address_peer(handle), peer);
        }
    }

    #[test]
    fn action_payload_is_parsed_in_the_node_pool_and_can_be_consumed_in_place() {
        let source = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];
        let control = [0xa3, 1, 6, 2, 1, 3, 1];
        let quic = [0x40, 0x01, 0x02, 0x03];
        let frame =
            crate::espnow::build_action_frame([0xff; 6], source, [0xff; 6], &control).unwrap();
        let (mut bearer, ingress) = EspNowBearer::<TestPool>::new("not-opened-by-receive-test");
        let hold = Arc::new(HoldIngress(Mutex::new(Vec::new())));
        bearer.attach(&POOL, hold.clone());

        let available_before_control = (&POOL).available();
        let mut observed = false;
        ingress.receive_action_frame(&frame, 17, &mut |peer, payload| {
            assert_eq!(peer, source);
            assert_eq!(payload, control);
            observed = true;
            false // A control frame is handled here, not enqueued.
        });
        assert!(observed);
        assert_eq!((&POOL).available(), available_before_control);

        let quic_frame =
            crate::espnow::build_action_frame([0xff; 6], source, [0xff; 6], &quic).unwrap();
        let available_before_quic = (&POOL).available();
        ingress.receive_action_frame(&quic_frame, 18, &mut |peer, payload| {
            assert_eq!(peer, source);
            assert_eq!(payload, quic);
            true
        });
        // Accepted opaque packet owns a pool lease in the ingress sink;
        // non-QUIC control above was handled in place and did not allocate.
        assert_eq!((&POOL).available(), available_before_quic - 1);
        assert_eq!(hold.0.lock().unwrap().len(), 1);
    }
}
