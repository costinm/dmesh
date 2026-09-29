//! Bounded DCID dispatch shared by endpoint and opaque-forwarding targets.
//!
//! Every serialized non-empty DCID occupies one entry in this registry, either
//! an endpoint owner or an opaque forwarding
//! rule.  A platform therefore performs one lookup before it chooses local
//! endpoint processing or next-hop egress; it must not maintain a competing
//! relay lookup table.

use alloc::vec::Vec;

#[cfg(test)]
use crate::connection::{ServerPacket, classify_server_packet};
use crate::{
    ConnectionId, Error, ShortHeaderPrefix, decode_routing_prefix, rewrite_bootstrap_destination,
    rewrite_dcid,
};

/// Destination selected by an opaque relay rule.
///
/// `Bootstrap` means a QUIC long header with an empty destination CID. It is
/// explicit protocol state, not a numeric sentinel. Only the initial
/// OPEN is allowed to use it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ForwardDestination {
    Connection(ConnectionId),
    Bootstrap,
}

/// Opaque forwarding action selected by a non-zero local DCID.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ForwardRule<NextHop> {
    /// Platform-owned adjacent-peer or egress handle.
    pub next_hop: NextHop,
    /// Destination written before submitting the packet to `next_hop`.
    pub destination: ForwardDestination,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum DcidTarget<Endpoint, NextHop> {
    Endpoint(Endpoint),
    Forward(ForwardRule<NextHop>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DcidRegistryError {
    InvalidConnectionId,
    Occupied,
    Full,
    Missing,
    WrongTarget,
}

/// Result of the first and only DCID lookup performed by an ingress adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DcidIngress<'a, Endpoint, NextHop> {
    Endpoint(ShortHeaderPrefix, &'a Endpoint),
    Forward(ShortHeaderPrefix, &'a ForwardRule<NextHop>),
}

pub(crate) enum RouterTarget<'a, Endpoint, NextHop> {
    Endpoint(&'a Endpoint),
    Forward(&'a ForwardRule<NextHop>),
    Missing,
}

/// Outcome of classifying one complete bearer packet.  Forwarding has
/// already copied the rewritten packet into caller-owned storage. Endpoint
/// outcomes retain borrowed input because they need no intermediate copy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DcidPacket<'a, Endpoint, NextHop> {
    Endpoint {
        /// DCID selected by this shared QUIC-lite router. Adapters may use it
        /// only to locate their association; packet headers remain private.
        received_dcid: ConnectionId,
        endpoint: &'a Endpoint,
    },
    Forward {
        /// CID from the received packet.  Relay adapters may use this only
        /// for relay-open bookkeeping and diagnostics; they must not parse
        /// the bearer frame a second time.
        received_dcid: ConnectionId,
        rule: &'a ForwardRule<NextHop>,
        used: usize,
    },
}

/// Failure while performing the single DCID classification required at a
/// bearer boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DcidPacketError {
    Header(Error),
    Registry(DcidRegistryError),
    Rewrite(Error),
}

/// Bearer-neutral result of routing one complete packet on a shared listener.
///
/// This is the narrow runtime boundary used by UDP, UART, BLE, and radio
/// bearers. It contains no peer L2 address: the caller keeps the ingress
/// `PacketMeta` and uses it only after the selected QUIC owner accepts the
/// packet.
pub(crate) enum PacketRoute<'a, Endpoint, NextHop> {
    Initial(crate::BootstrapOpen),
    Endpoint {
        destination: ConnectionId,
        endpoint: &'a Endpoint,
    },
    /// An opaque packet matched association-owned state, normally a peer's
    /// stateless-reset token. It intentionally has no parseable destination.
    OpaqueEndpoint {
        endpoint: &'a Endpoint,
    },
    Forward {
        received_dcid: ConnectionId,
        rule: &'a ForwardRule<NextHop>,
        used: usize,
    },
    /// Send `output[..used]` back through the bearer address on which the
    /// unknown short-header packet arrived.
    StatelessReset {
        used: usize,
    },
    Unknown {
        destination: ConnectionId,
    },
}

/// One DCID namespace for endpoint associations and relay forwarding rules.
///
/// The registry remains an implementation detail of the node owner. Bearers
/// submit complete bytes and never inspect a long/short header or use their
/// physical peer L2 address to select an association.
pub(crate) struct PacketRouter<Endpoint, NextHop> {
    registry: DcidRegistry<Endpoint, NextHop>,
    _reset_key: Option<crate::StatelessResetKey>,
}

impl<Endpoint, NextHop> PacketRouter<Endpoint, NextHop> {
    pub(crate) fn new(reset_key: Option<crate::StatelessResetKey>) -> Self {
        Self {
            registry: DcidRegistry::new(),
            _reset_key: reset_key,
        }
    }

    pub(crate) fn set_max_entries(&mut self, max_entries: usize) {
        self.registry.set_max_entries(max_entries);
    }

    pub(crate) fn register_endpoint(
        &mut self,
        dcid: ConnectionId,
        endpoint: Endpoint,
    ) -> Result<(), DcidRegistryError> {
        self.registry.insert_endpoint(dcid, endpoint)
    }

    pub(crate) fn register_forward(
        &mut self,
        dcid: ConnectionId,
        rule: ForwardRule<NextHop>,
    ) -> Result<(), DcidRegistryError> {
        self.registry.install_forward(dcid, rule)
    }

    pub(crate) fn contains(&self, dcid: ConnectionId) -> bool {
        self.registry.contains(dcid)
    }

    pub(crate) fn remove_endpoint(&mut self, dcid: ConnectionId, expected: &Endpoint) -> bool
    where
        Endpoint: PartialEq,
    {
        let Ok(index) = self.registry.find(dcid) else {
            return false;
        };
        if !matches!(&self.registry.entries[index].1, DcidTarget::Endpoint(endpoint) if endpoint == expected)
        {
            return false;
        }
        self.registry.entries.remove(index);
        true
    }

    pub(crate) fn remove_forward(&mut self, dcid: ConnectionId) -> bool {
        let Ok(index) = self.registry.find(dcid) else {
            return false;
        };
        if !matches!(self.registry.entries[index].1, DcidTarget::Forward(_)) {
            return false;
        }
        self.registry.entries.remove(index);
        true
    }

    pub(crate) fn target(
        &self,
        input: &[u8],
    ) -> Result<RouterTarget<'_, Endpoint, NextHop>, Error> {
        let prefix = decode_routing_prefix(input)?;
        match self.registry.ingress(prefix) {
            Ok(DcidIngress::Endpoint(_, endpoint)) => Ok(RouterTarget::Endpoint(endpoint)),
            Ok(DcidIngress::Forward(_, rule)) => Ok(RouterTarget::Forward(rule)),
            Err(DcidRegistryError::Missing) => Ok(RouterTarget::Missing),
            Err(_) => unreachable!("registry lookup reports only a missing key"),
        }
    }

    pub(crate) fn opaque_endpoint(
        &self,
        accepts: impl FnMut(&Endpoint) -> bool,
    ) -> Option<&Endpoint> {
        self.registry.endpoint_matching(accepts)
    }

    pub(crate) fn encode_stateless_reset(
        &self,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<Option<usize>, Error> {
        match self._reset_key {
            Some(key) => key.encode_for_unknown_packet(input, output),
            None => Ok(None),
        }
    }

    pub(crate) fn reset_token_for(
        &self,
        connection_id: ConnectionId,
    ) -> Option<crate::StatelessResetToken> {
        self._reset_key.map(|key| key.token_for(connection_id))
    }

    /// Route one packet. Malformed input is rejected after normal parsing;
    /// callers with outgoing client associations use
    /// [`Self::route_with_opaque`] so their private reset tokens are checked.
    #[cfg(test)]
    fn route<'a>(
        &'a self,
        input: &'a [u8],
        output: &mut [u8],
    ) -> Result<PacketRoute<'a, Endpoint, NextHop>, Error> {
        self.route_with_opaque(input, output, |_, _| false)
    }

    /// Route one packet and offer otherwise-unparseable bytes to endpoint
    /// state. The callback must check only association-owned opaque state; it
    /// must not parse another routing header or compare a bearer address.
    #[cfg(test)]
    fn route_with_opaque<'a>(
        &'a self,
        input: &'a [u8],
        output: &mut [u8],
        mut accepts_opaque: impl FnMut(&Endpoint, &[u8]) -> bool,
    ) -> Result<PacketRoute<'a, Endpoint, NextHop>, Error> {
        let classified = match classify_server_packet(input) {
            Ok(classified) => classified,
            Err(error) => {
                if let Some(endpoint) = self
                    .registry
                    .endpoint_matching(|endpoint| accepts_opaque(endpoint, input))
                {
                    return Ok(PacketRoute::OpaqueEndpoint { endpoint });
                }
                return Err(error);
            }
        };
        match classified {
            ServerPacket::Initial(open) => Ok(PacketRoute::Initial(open)),
            classified @ (ServerPacket::BootstrapAck { destination }
            | ServerPacket::Established { destination }) => {
                let may_reset = matches!(classified, ServerPacket::Established { .. });
                let prefix = decode_routing_prefix(input)?;
                match self.registry.ingress(prefix) {
                    Ok(DcidIngress::Endpoint(_, endpoint)) => Ok(PacketRoute::Endpoint {
                        destination,
                        endpoint,
                    }),
                    Ok(DcidIngress::Forward(_, rule)) => {
                        let used = match rule.destination {
                            ForwardDestination::Connection(dcid) => {
                                rewrite_dcid(input, dcid, output)
                            }
                            ForwardDestination::Bootstrap => {
                                rewrite_bootstrap_destination(input, output)
                            }
                        }?;
                        Ok(PacketRoute::Forward {
                            received_dcid: destination,
                            rule,
                            used,
                        })
                    }
                    Err(DcidRegistryError::Missing) => {
                        if may_reset && let Some(reset_key) = self._reset_key {
                            if let Some(used) =
                                reset_key.encode_for_unknown_packet(input, output)?
                            {
                                return Ok(PacketRoute::StatelessReset { used });
                            }
                        }
                        Ok(PacketRoute::Unknown { destination })
                    }
                    Err(_) => unreachable!("registry lookup reports only a missing key"),
                }
            }
        }
    }
}

/// Classify one complete QUIC-lite-shaped packet before any endpoint or
/// application dispatcher runs. A forwarding target rewrites only the DCID
/// into `output`; flags, packet number, and body are preserved byte-for-byte.
///
/// `output` is deliberately caller-owned because ESP Main must use its shared
/// packet pool and host/Android own their socket buffers. This function owns no
/// queues, clock, transport metadata, or next-hop policy.
pub(crate) fn dispatch_packet<'a, Endpoint, NextHop>(
    registry: &'a DcidRegistry<Endpoint, NextHop>,
    input: &'a [u8],
    output: &mut [u8],
) -> Result<DcidPacket<'a, Endpoint, NextHop>, DcidPacketError> {
    let prefix = decode_routing_prefix(input).map_err(DcidPacketError::Header)?;
    match registry
        .ingress(prefix)
        .map_err(DcidPacketError::Registry)?
    {
        DcidIngress::Endpoint(prefix, endpoint) => Ok(DcidPacket::Endpoint {
            received_dcid: prefix.dcid,
            endpoint,
        }),
        DcidIngress::Forward(_, rule) => {
            let used = match rule.destination {
                ForwardDestination::Connection(dcid) => rewrite_dcid(input, dcid, output),
                ForwardDestination::Bootstrap => rewrite_bootstrap_destination(input, output),
            }
            .map_err(DcidPacketError::Rewrite)?;
            Ok(DcidPacket::Forward {
                received_dcid: prefix.dcid,
                rule,
                used,
            })
        }
    }
}

/// Fixed-capacity registry for all non-zero local DCIDs.
#[derive(Clone)]
pub(crate) struct DcidRegistry<Endpoint, NextHop> {
    entries: Vec<(ConnectionId, DcidTarget<Endpoint, NextHop>)>,
    max_entries: usize,
}

impl<Endpoint, NextHop> Default for DcidRegistry<Endpoint, NextHop> {
    fn default() -> Self {
        Self::new()
    }
}

impl<Endpoint, NextHop> DcidRegistry<Endpoint, NextHop> {
    pub(crate) fn new() -> Self {
        Self {
            entries: Vec::new(),
            max_entries: usize::MAX,
        }
    }

    pub(crate) fn set_max_entries(&mut self, max_entries: usize) {
        self.max_entries = max_entries;
    }

    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether a non-zero local DCID is already owned by any endpoint or
    /// forwarding target. Reconciliation uses this to reject a replacement
    /// before removing the currently active rule.
    pub(crate) fn contains(&self, dcid: ConnectionId) -> bool {
        self.find(dcid).is_ok()
    }

    pub(crate) fn insert_endpoint(
        &mut self,
        dcid: ConnectionId,
        endpoint: Endpoint,
    ) -> Result<(), DcidRegistryError> {
        self.insert(dcid, DcidTarget::Endpoint(endpoint))
    }

    pub(crate) fn install_forward(
        &mut self,
        dcid: ConnectionId,
        rule: ForwardRule<NextHop>,
    ) -> Result<(), DcidRegistryError> {
        self.insert(dcid, DcidTarget::Forward(rule))
    }

    /// Install a forward rule once, or accept an exact duplicate as an
    /// idempotent control retry. Returns whether this call inserted a new
    /// entry. A different target for the same local DCID remains a conflict.
    pub(crate) fn install_forward_idempotent(
        &mut self,
        dcid: ConnectionId,
        rule: ForwardRule<NextHop>,
    ) -> Result<bool, DcidRegistryError>
    where
        NextHop: Eq,
    {
        if dcid.value() == 0 {
            return Err(DcidRegistryError::InvalidConnectionId);
        }
        if let Ok(index) = self.find(dcid) {
            let target = &self.entries[index].1;
            return match target {
                DcidTarget::Forward(existing) if *existing == rule => Ok(false),
                _ => Err(DcidRegistryError::Occupied),
            };
        }
        self.insert(dcid, DcidTarget::Forward(rule))?;
        Ok(true)
    }

    /// Replace only an existing forwarding target.  Endpoint ownership cannot
    /// be silently overwritten by relay setup.
    pub(crate) fn update_forward(
        &mut self,
        dcid: ConnectionId,
        rule: ForwardRule<NextHop>,
    ) -> Result<(), DcidRegistryError> {
        let Ok(index) = self.find(dcid) else {
            return Err(DcidRegistryError::Missing);
        };
        let target = &mut self.entries[index].1;
        if !matches!(target, DcidTarget::Forward(_)) {
            return Err(DcidRegistryError::WrongTarget);
        }
        *target = DcidTarget::Forward(rule);
        Ok(())
    }

    pub(crate) fn remove(&mut self, dcid: ConnectionId) -> Option<DcidTarget<Endpoint, NextHop>> {
        let index = self.find(dcid).ok()?;
        Some(self.entries.remove(index).1)
    }

    pub(crate) fn ingress(
        &self,
        prefix: ShortHeaderPrefix,
    ) -> Result<DcidIngress<'_, Endpoint, NextHop>, DcidRegistryError> {
        let index = self
            .find(prefix.dcid)
            .map_err(|_| DcidRegistryError::Missing)?;
        let target = &self.entries[index].1;
        Ok(match target {
            DcidTarget::Endpoint(endpoint) => DcidIngress::Endpoint(prefix, endpoint),
            DcidTarget::Forward(rule) => DcidIngress::Forward(prefix, rule),
        })
    }

    fn find(&self, dcid: ConnectionId) -> Result<usize, usize> {
        self.entries.binary_search_by_key(&dcid, |(key, _)| *key)
    }

    fn endpoint_matching(&self, mut predicate: impl FnMut(&Endpoint) -> bool) -> Option<&Endpoint> {
        self.entries.iter().find_map(|(_, target)| match target {
            DcidTarget::Endpoint(endpoint) if predicate(endpoint) => Some(endpoint),
            _ => None,
        })
    }

    fn insert(
        &mut self,
        dcid: ConnectionId,
        target: DcidTarget<Endpoint, NextHop>,
    ) -> Result<(), DcidRegistryError> {
        if dcid.value() == 0 {
            return Err(DcidRegistryError::InvalidConnectionId);
        }
        let index = match self.find(dcid) {
            Ok(_) => return Err(DcidRegistryError::Occupied),
            Err(index) => index,
        };
        if self.entries.len() >= self.max_entries {
            return Err(DcidRegistryError::Full);
        }
        self.entries
            .try_reserve(1)
            .map_err(|_| DcidRegistryError::Full)?;
        self.entries.insert(index, (dcid, target));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FLAG_FIXED, ShortHeader};

    #[test]
    fn endpoint_and_forward_target_share_one_registry() {
        let endpoint = ConnectionId::new(4).unwrap();
        let relay = ConnectionId::relay_local(2, 1).unwrap();
        let mut registry = DcidRegistry::<u8, u16>::new();
        registry.set_max_entries(2);
        registry.insert_endpoint(endpoint, 7).unwrap();
        registry
            .install_forward(
                relay,
                ForwardRule {
                    next_hop: 9,
                    destination: ForwardDestination::Bootstrap,
                },
            )
            .unwrap();

        let mut endpoint_packet = [0; 16];
        let endpoint_len = ShortHeader {
            flags: FLAG_FIXED,
            dcid: endpoint,
            packet_number: 1,
            packet_number_len: 1,
        }
        .encode(&mut endpoint_packet)
        .unwrap();
        let endpoint_prefix = ShortHeader::decode_prefix(&endpoint_packet[..endpoint_len]).unwrap();
        assert!(matches!(
            registry.ingress(endpoint_prefix),
            Ok(DcidIngress::Endpoint(_, 7))
        ));

        let mut relay_packet = [0; 16];
        let relay_len = ShortHeader {
            flags: FLAG_FIXED,
            dcid: relay,
            packet_number: 2,
            packet_number_len: 1,
        }
        .encode(&mut relay_packet)
        .unwrap();
        let relay_prefix = ShortHeader::decode_prefix(&relay_packet[..relay_len]).unwrap();
        assert!(matches!(
            registry.ingress(relay_prefix),
            Ok(DcidIngress::Forward(_, ForwardRule { next_hop: 9, .. }))
        ));
    }

    #[test]
    fn dispatches_endpoint_and_forward_once() {
        let endpoint = ConnectionId::new(4).unwrap();
        let relay = ConnectionId::relay_local(2, 1).unwrap();
        let mut registry = DcidRegistry::<u8, u16>::new();
        registry.set_max_entries(2);
        registry.insert_endpoint(endpoint, 7).unwrap();
        registry
            .install_forward(
                relay,
                ForwardRule {
                    next_hop: 9,
                    destination: ForwardDestination::Connection(ConnectionId::new(5).unwrap()),
                },
            )
            .unwrap();

        let mut output = [0; 32];

        let mut endpoint_packet = [0; 16];
        let endpoint_len = ShortHeader {
            flags: FLAG_FIXED,
            dcid: endpoint,
            packet_number: 1,
            packet_number_len: 1,
        }
        .encode(&mut endpoint_packet)
        .unwrap();
        assert!(matches!(
            dispatch_packet(&registry, &endpoint_packet[..endpoint_len], &mut output),
            Ok(DcidPacket::Endpoint { received_dcid, endpoint: 7 })
                if received_dcid == endpoint
        ));

        let mut relay_packet = [0; 16];
        let relay_len = ShortHeader {
            flags: FLAG_FIXED,
            dcid: relay,
            packet_number: 2,
            packet_number_len: 1,
        }
        .encode(&mut relay_packet)
        .unwrap();
        let used =
            match dispatch_packet(&registry, &relay_packet[..relay_len], &mut output).unwrap() {
                DcidPacket::Forward { rule, used, .. } => {
                    assert_eq!(rule.next_hop, 9);
                    used
                }
                _ => panic!("expected forward"),
            };
        let (rewritten, _) = ShortHeader::decode(&output[..used]).unwrap();
        assert_eq!(rewritten.dcid.value(), 5);
        assert_eq!(rewritten.packet_number, 2);
    }

    #[test]
    fn bootstrap_forwarding_uses_an_empty_long_header_destination() {
        let relay = ConnectionId::relay_local(2, 1).unwrap();
        let source = ConnectionId::new(11).unwrap();
        let mut registry = DcidRegistry::<(), u16>::new();
        registry.set_max_entries(1);
        registry
            .install_forward(
                relay,
                ForwardRule {
                    next_hop: 9,
                    destination: ForwardDestination::Bootstrap,
                },
            )
            .unwrap();
        let mut packet = [0; 64];
        let packet_len = crate::encode_long_packet(
            crate::LONG_PACKET_INITIAL,
            Some(relay),
            Some(source),
            1,
            4,
            &[0xa0],
            &mut packet,
        )
        .unwrap();
        let mut output = [0; 64];
        let DcidPacket::Forward { used, .. } =
            dispatch_packet(&registry, &packet[..packet_len], &mut output).unwrap()
        else {
            panic!("bootstrap packet must be forwarded")
        };
        let (header, _, _) = crate::decode_long_packet(&output[..used]).unwrap();
        assert_eq!(header.dcid, None);
        assert_eq!(header.scid, Some(source));
    }

    #[test]
    fn an_initial_with_an_empty_destination_is_not_a_registry_route() {
        let source = ConnectionId::new(11).unwrap();
        let registry = DcidRegistry::<(), u16>::new();
        let mut packet = [0; 64];
        let packet_len = crate::encode_long_packet(
            crate::LONG_PACKET_INITIAL,
            None,
            Some(source),
            1,
            4,
            &[0xa0],
            &mut packet,
        )
        .unwrap();
        let mut output = [0; 64];
        assert!(matches!(
            dispatch_packet(&registry, &packet[..packet_len], &mut output),
            Err(DcidPacketError::Registry(DcidRegistryError::Missing))
        ));
    }

    #[test]
    fn packet_router_owns_shared_listener_classification_and_dcid_dispatch() {
        let server_cid = ConnectionId::new(0x41).unwrap();
        let client_cid = ConnectionId::new(0x42).unwrap();
        let relay_cid = ConnectionId::relay_local(2, 1).unwrap();
        let mut router = PacketRouter::<u8, u16>::new(None);
        router.set_max_entries(3);
        router.register_endpoint(server_cid, 1).unwrap();
        router.register_endpoint(client_cid, 2).unwrap();
        router
            .register_forward(
                relay_cid,
                ForwardRule {
                    next_hop: 9,
                    destination: ForwardDestination::Connection(server_cid),
                },
            )
            .unwrap();
        let mut packet = [0u8; 128];
        let mut output = [0u8; 128];

        let source = ConnectionId::new(0x43).unwrap();
        let initial_len = crate::encode_bootstrap_open_packet(source, 0, &mut packet).unwrap();
        assert!(matches!(
            router.route(&packet[..initial_len], &mut output),
            Ok(PacketRoute::Initial(open)) if open.client_receive_cid == source
        ));

        let ack_len =
            crate::encode_bootstrap_open_ack_packet(client_cid, server_cid, 0, &mut packet)
                .unwrap();
        assert!(matches!(
            router.route(&packet[..ack_len], &mut output),
            Ok(PacketRoute::Endpoint { destination, endpoint: 2 })
                if destination == client_cid
        ));

        let established_len = ShortHeader {
            flags: FLAG_FIXED,
            dcid: server_cid,
            packet_number: 1,
            packet_number_len: 1,
        }
        .encode(&mut packet)
        .unwrap();
        assert!(matches!(
            router.route(&packet[..established_len], &mut output),
            Ok(PacketRoute::Endpoint { destination, endpoint: 1 })
                if destination == server_cid
        ));

        let relay_len = ShortHeader {
            flags: FLAG_FIXED,
            dcid: relay_cid,
            packet_number: 2,
            packet_number_len: 1,
        }
        .encode(&mut packet)
        .unwrap();
        let used = match router.route(&packet[..relay_len], &mut output).unwrap() {
            PacketRoute::Forward {
                received_dcid,
                rule,
                used,
            } => {
                assert_eq!(received_dcid, relay_cid);
                assert_eq!(rule.next_hop, 9);
                used
            }
            _ => panic!("relay CID must select its forwarding rule"),
        };
        assert_eq!(
            ShortHeader::decode(&output[..used]).unwrap().0.dcid,
            server_cid
        );
    }

    #[test]
    fn packet_router_generates_reset_only_for_unknown_short_dcid() {
        let reset_key = crate::StatelessResetKey::from_device_secret(&[0x71; 32]).unwrap();
        let router = PacketRouter::<u8, u16>::new(Some(reset_key));
        let unknown = ConnectionId::new(0x55).unwrap();
        let mut packet = [0x44u8; 48];
        let header_len = ShortHeader {
            flags: FLAG_FIXED,
            dcid: unknown,
            packet_number: 1,
            packet_number_len: 1,
        }
        .encode(&mut packet)
        .unwrap();
        packet[header_len..].fill(0x44);
        let mut output = [0u8; 64];
        let used = match router.route(&packet, &mut output).unwrap() {
            PacketRoute::StatelessReset { used } => used,
            _ => panic!("unknown established CID must produce a reset"),
        };
        assert_eq!(used, packet.len());
        assert!(reset_key.token_for(unknown).matches_packet(&output[..used]));

        let client = ConnectionId::new(0x56).unwrap();
        let server = ConnectionId::new(0x57).unwrap();
        let ack_len =
            crate::encode_bootstrap_open_ack_packet(client, server, 0, &mut packet).unwrap();
        assert!(matches!(
            router.route(&packet[..ack_len], &mut output),
            Ok(PacketRoute::Unknown { destination }) if destination == client
        ));
    }

    #[test]
    fn packet_router_offers_opaque_reset_to_association_state_without_an_address() {
        #[derive(Clone, Copy)]
        struct ClientState {
            token: crate::StatelessResetToken,
        }

        let peer_key = crate::StatelessResetKey::from_device_secret(&[0x81; 32]).unwrap();
        let client_cid = ConnectionId::new(0x61).unwrap();
        let old_server_cid = ConnectionId::new(0x62).unwrap();
        let mut router = PacketRouter::<ClientState, ()>::new(None);
        router
            .register_endpoint(
                client_cid,
                ClientState {
                    token: peer_key.token_for(old_server_cid),
                },
            )
            .unwrap();

        let mut stale = [0x22u8; 48];
        let header_len = ShortHeader {
            flags: FLAG_FIXED,
            dcid: old_server_cid,
            packet_number: 9,
            packet_number_len: 1,
        }
        .encode(&mut stale)
        .unwrap();
        stale[header_len..].fill(0x22);
        let mut reset = [0u8; 48];
        let reset_len = peer_key
            .encode_for_unknown_packet(&stale, &mut reset)
            .unwrap()
            .unwrap();
        let mut scratch = [0u8; 64];
        assert!(matches!(
            router.route_with_opaque(&reset[..reset_len], &mut scratch, |client, packet| {
                client.token.matches_packet(packet)
            }),
            Ok(PacketRoute::OpaqueEndpoint { endpoint })
                if endpoint.token.matches_packet(&reset[..reset_len])
        ));
    }

    #[test]
    fn packet_router_keeps_multiple_clients_servers_and_relays_in_one_namespace() {
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        enum Endpoint {
            Client(u8),
            Server(u8),
        }

        let clients = [0x101, 0x102].map(|value| ConnectionId::new(value).unwrap());
        let servers = [0x201, 0x202].map(|value| ConnectionId::new(value).unwrap());
        let relays = [
            ConnectionId::relay_local(2, 1).unwrap(),
            ConnectionId::relay_local(2, 2).unwrap(),
        ];
        let mut router = PacketRouter::<Endpoint, u8>::new(None);
        router.set_max_entries(6);
        for (index, cid) in clients.into_iter().enumerate() {
            router
                .register_endpoint(cid, Endpoint::Client(index as u8))
                .unwrap();
        }
        for (index, cid) in servers.into_iter().enumerate() {
            router
                .register_endpoint(cid, Endpoint::Server(index as u8))
                .unwrap();
        }
        for (index, cid) in relays.into_iter().enumerate() {
            router
                .register_forward(
                    cid,
                    ForwardRule {
                        next_hop: index as u8,
                        destination: ForwardDestination::Connection(servers[index]),
                    },
                )
                .unwrap();
        }
        assert_eq!(
            router.register_forward(
                clients[0],
                ForwardRule {
                    next_hop: 9,
                    destination: ForwardDestination::Bootstrap,
                },
            ),
            Err(DcidRegistryError::Occupied)
        );

        let mut packet = [0u8; 96];
        let mut output = [0u8; 96];
        for (index, client_cid) in clients.into_iter().enumerate() {
            let used = crate::encode_bootstrap_open_ack_packet(
                client_cid,
                servers[index],
                index as u32,
                &mut packet,
            )
            .unwrap();
            assert!(matches!(
                router.route(&packet[..used], &mut output),
                Ok(PacketRoute::Endpoint {
                    destination,
                    endpoint: Endpoint::Client(found),
                }) if destination == client_cid && *found == index as u8
            ));
        }
        for (index, server_cid) in servers.into_iter().enumerate() {
            let used = ShortHeader {
                flags: FLAG_FIXED,
                dcid: server_cid,
                packet_number: index as u32 + 1,
                packet_number_len: 1,
            }
            .encode(&mut packet)
            .unwrap();
            assert!(matches!(
                router.route(&packet[..used], &mut output),
                Ok(PacketRoute::Endpoint {
                    destination,
                    endpoint: Endpoint::Server(found),
                }) if destination == server_cid && *found == index as u8
            ));
        }
        for (index, relay_cid) in relays.into_iter().enumerate() {
            let used = ShortHeader {
                flags: FLAG_FIXED,
                dcid: relay_cid,
                packet_number: index as u32 + 3,
                packet_number_len: 1,
            }
            .encode(&mut packet)
            .unwrap();
            let rewritten = match router.route(&packet[..used], &mut output).unwrap() {
                PacketRoute::Forward { rule, used, .. } => {
                    assert_eq!(rule.next_hop, index as u8);
                    used
                }
                _ => panic!("relay did not share the root namespace"),
            };
            assert_eq!(
                ShortHeader::decode(&output[..rewritten]).unwrap().0.dcid,
                servers[index]
            );
        }

        assert!(router.remove_endpoint(servers[0], &Endpoint::Server(0)));
        assert!(!router.remove_endpoint(servers[0], &Endpoint::Server(0)));
        let used = ShortHeader {
            flags: FLAG_FIXED,
            dcid: servers[0],
            packet_number: 8,
            packet_number_len: 1,
        }
        .encode(&mut packet)
        .unwrap();
        assert!(matches!(
            router.route(&packet[..used], &mut output),
            Ok(PacketRoute::Unknown { destination }) if destination == servers[0]
        ));
        let used = ShortHeader {
            flags: FLAG_FIXED,
            dcid: servers[1],
            packet_number: 9,
            packet_number_len: 1,
        }
        .encode(&mut packet)
        .unwrap();
        assert!(matches!(
            router.route(&packet[..used], &mut output),
            Ok(PacketRoute::Endpoint {
                endpoint: Endpoint::Server(1),
                ..
            })
        ));
    }

    #[test]
    fn opaque_reset_selects_the_matching_client_among_multiple_endpoints() {
        #[derive(Clone, Copy)]
        struct Endpoint {
            id: u8,
            token: Option<crate::StatelessResetToken>,
        }

        let peer_key = crate::StatelessResetKey::from_device_secret(&[0x91; 32]).unwrap();
        let peer_cids = [0x301, 0x302].map(|value| ConnectionId::new(value).unwrap());
        let local_cids = [0x401, 0x402, 0x403].map(|value| ConnectionId::new(value).unwrap());
        let mut router = PacketRouter::<Endpoint, ()>::new(None);
        router
            .register_endpoint(
                local_cids[0],
                Endpoint {
                    id: 0,
                    token: Some(peer_key.token_for(peer_cids[0])),
                },
            )
            .unwrap();
        router
            .register_endpoint(
                local_cids[1],
                Endpoint {
                    id: 1,
                    token: Some(peer_key.token_for(peer_cids[1])),
                },
            )
            .unwrap();
        router
            .register_endpoint(local_cids[2], Endpoint { id: 2, token: None })
            .unwrap();

        let mut stale = [0x33u8; 48];
        let header_len = ShortHeader {
            flags: FLAG_FIXED,
            dcid: peer_cids[1],
            packet_number: 4,
            packet_number_len: 1,
        }
        .encode(&mut stale)
        .unwrap();
        stale[header_len..].fill(0x33);
        let mut reset = [0u8; 48];
        let reset_len = peer_key
            .encode_for_unknown_packet(&stale, &mut reset)
            .unwrap()
            .unwrap();
        let mut scratch = [0u8; 64];
        assert!(matches!(
            router.route_with_opaque(&reset[..reset_len], &mut scratch, |endpoint, packet| {
                endpoint.token.is_some_and(|token| token.matches_packet(packet))
            }),
            Ok(PacketRoute::OpaqueEndpoint { endpoint }) if endpoint.id == 1
        ));
        reset[reset_len - 1] ^= 1;
        assert!(
            router
                .route_with_opaque(&reset[..reset_len], &mut scratch, |endpoint, packet| {
                    endpoint
                        .token
                        .is_some_and(|token| token.matches_packet(packet))
                })
                .is_err()
        );
    }
}
