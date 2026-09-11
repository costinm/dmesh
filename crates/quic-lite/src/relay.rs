//! Bounded DCID dispatch shared by endpoint and opaque-forwarding targets.
//!
//! Every serialized non-empty DCID occupies one entry in this registry, either
//! an endpoint owner or an opaque forwarding
//! rule.  A platform therefore performs one lookup before it chooses local
//! endpoint processing or next-hop egress; it must not maintain a competing
//! relay lookup table.

use crate::{
    ConnectionId, Error, ShortHeaderPrefix, decode_direct_packet, decode_routing_prefix,
    rewrite_bootstrap_destination, rewrite_dcid,
};

/// Destination selected by an opaque relay rule.
///
/// `Bootstrap` means a QUIC long header with an empty destination CID. It is
/// explicit protocol state, not a numeric sentinel. Only the initial
/// OPEN is allowed to use it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ForwardDestination {
    Connection(ConnectionId),
    Bootstrap,
}

/// Opaque forwarding action selected by a non-zero local DCID.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ForwardRule<NextHop> {
    /// Platform-owned adjacent-peer or egress handle.
    pub next_hop: NextHop,
    /// Destination written before submitting the packet to `next_hop`.
    pub destination: ForwardDestination,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DcidTarget<Endpoint, NextHop> {
    Endpoint(Endpoint),
    Forward(ForwardRule<NextHop>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DcidRegistryError {
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

/// Outcome of classifying one complete bearer datagram.  Forwarding has
/// already copied the rewritten packet into caller-owned storage.  Direct and
/// endpoint outcomes retain borrowed input because neither path needs an
/// intermediate packet copy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DcidDatagram<'a, Endpoint, NextHop> {
    Direct {
        payload: &'a [u8],
    },
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
pub enum DcidDatagramError {
    Header(Error),
    Registry(DcidRegistryError),
    Rewrite(Error),
}

/// Classify one complete QUIC-lite-shaped datagram before any endpoint or
/// application dispatcher runs. A forwarding target rewrites only the DCID
/// into `output`; flags, packet number, and body are preserved byte-for-byte.
///
/// `output` is deliberately caller-owned because ESP Main must use its shared
/// packet pool and host/Android own their socket buffers. This function owns no
/// queues, clock, transport metadata, or next-hop policy.
pub fn dispatch_datagram<'a, Endpoint, NextHop, const ENTRIES: usize>(
    registry: &'a DcidRegistry<Endpoint, NextHop, ENTRIES>,
    input: &'a [u8],
    output: &mut [u8],
) -> Result<DcidDatagram<'a, Endpoint, NextHop>, DcidDatagramError> {
    // Direct traffic is its own custom-version long-header form.  Classify it
    // before DCID routing so neither this registry nor a bearer treats an
    // empty Initial destination as a synthetic numeric CID.
    if crate::DirectMessageEndpoint::is_packet(input) {
        let (_, payload) = decode_direct_packet(input).map_err(DcidDatagramError::Header)?;
        return Ok(DcidDatagram::Direct { payload });
    }
    let prefix = decode_routing_prefix(input).map_err(DcidDatagramError::Header)?;
    match registry
        .ingress(prefix)
        .map_err(DcidDatagramError::Registry)?
    {
        DcidIngress::Endpoint(prefix, endpoint) => Ok(DcidDatagram::Endpoint {
            received_dcid: prefix.dcid,
            endpoint,
        }),
        DcidIngress::Forward(_, rule) => {
            let used = match rule.destination {
                ForwardDestination::Connection(dcid) => rewrite_dcid(input, dcid, output),
                ForwardDestination::Bootstrap => rewrite_bootstrap_destination(input, output),
            }
            .map_err(DcidDatagramError::Rewrite)?;
            Ok(DcidDatagram::Forward {
                received_dcid: prefix.dcid,
                rule,
                used,
            })
        }
    }
}

/// Fixed-capacity registry for all non-zero local DCIDs.
#[derive(Clone)]
pub struct DcidRegistry<Endpoint, NextHop, const ENTRIES: usize> {
    entries: [Option<(ConnectionId, DcidTarget<Endpoint, NextHop>)>; ENTRIES],
}

impl<Endpoint, NextHop, const ENTRIES: usize> Default for DcidRegistry<Endpoint, NextHop, ENTRIES> {
    fn default() -> Self {
        Self::new()
    }
}

impl<Endpoint, NextHop, const ENTRIES: usize> DcidRegistry<Endpoint, NextHop, ENTRIES> {
    pub fn new() -> Self {
        Self {
            entries: core::array::from_fn(|_| None),
        }
    }

    pub fn len(&self) -> usize {
        self.entries.iter().filter(|entry| entry.is_some()).count()
    }

    /// Whether a non-zero local DCID is already owned by any endpoint or
    /// forwarding target. Reconciliation uses this to reject a replacement
    /// before removing the currently active rule.
    pub fn contains(&self, dcid: ConnectionId) -> bool {
        self.entries.iter().flatten().any(|(key, _)| *key == dcid)
    }

    pub fn insert_endpoint(
        &mut self,
        dcid: ConnectionId,
        endpoint: Endpoint,
    ) -> Result<(), DcidRegistryError> {
        self.insert(dcid, DcidTarget::Endpoint(endpoint))
    }

    pub fn install_forward(
        &mut self,
        dcid: ConnectionId,
        rule: ForwardRule<NextHop>,
    ) -> Result<(), DcidRegistryError> {
        self.insert(dcid, DcidTarget::Forward(rule))
    }

    /// Install a forward rule once, or accept an exact duplicate as an
    /// idempotent control retry. Returns whether this call inserted a new
    /// entry. A different target for the same local DCID remains a conflict.
    pub fn install_forward_idempotent(
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
        if let Some((_, target)) = self
            .entries
            .iter()
            .filter_map(Option::as_ref)
            .find(|(key, _)| *key == dcid)
        {
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
    pub fn update_forward(
        &mut self,
        dcid: ConnectionId,
        rule: ForwardRule<NextHop>,
    ) -> Result<(), DcidRegistryError> {
        let Some(entry) = self
            .entries
            .iter_mut()
            .find(|entry| entry.as_ref().is_some_and(|(key, _)| *key == dcid))
        else {
            return Err(DcidRegistryError::Missing);
        };
        let Some((_, target)) = entry.as_mut() else {
            return Err(DcidRegistryError::Missing);
        };
        if !matches!(target, DcidTarget::Forward(_)) {
            return Err(DcidRegistryError::WrongTarget);
        }
        *target = DcidTarget::Forward(rule);
        Ok(())
    }

    pub fn remove(&mut self, dcid: ConnectionId) -> Option<DcidTarget<Endpoint, NextHop>> {
        let entry = self
            .entries
            .iter_mut()
            .find(|entry| entry.as_ref().is_some_and(|(key, _)| *key == dcid))?;
        entry.take().map(|(_, target)| target)
    }

    pub(crate) fn ingress(
        &self,
        prefix: ShortHeaderPrefix,
    ) -> Result<DcidIngress<'_, Endpoint, NextHop>, DcidRegistryError> {
        let (_, target) = self
            .entries
            .iter()
            .filter_map(Option::as_ref)
            .find(|(key, _)| *key == prefix.dcid)
            .ok_or(DcidRegistryError::Missing)?;
        Ok(match target {
            DcidTarget::Endpoint(endpoint) => DcidIngress::Endpoint(prefix, endpoint),
            DcidTarget::Forward(rule) => DcidIngress::Forward(prefix, rule),
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
        if self
            .entries
            .iter()
            .any(|entry| entry.as_ref().is_some_and(|(key, _)| *key == dcid))
        {
            return Err(DcidRegistryError::Occupied);
        }
        let entry = self
            .entries
            .iter_mut()
            .find(|entry| entry.is_none())
            .ok_or(DcidRegistryError::Full)?;
        *entry = Some((dcid, target));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FLAG_FIXED, ShortHeader, encode_direct_packet};

    #[test]
    fn endpoint_and_forward_target_share_one_registry() {
        let endpoint = ConnectionId::new(4).unwrap();
        let relay = ConnectionId::relay_local(2, 1).unwrap();
        let mut registry = DcidRegistry::<u8, u16, 2>::new();
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
    fn dispatches_direct_endpoint_and_forward_once() {
        let endpoint = ConnectionId::new(4).unwrap();
        let relay = ConnectionId::relay_local(2, 1).unwrap();
        let mut registry = DcidRegistry::<u8, u16, 2>::new();
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

        let mut direct = [0; 32];
        let direct_len = encode_direct_packet(3, &[0xa0], &mut direct).unwrap();
        let mut output = [0; 32];
        assert!(matches!(
            dispatch_datagram(&registry, &direct[..direct_len], &mut output),
            Ok(DcidDatagram::Direct { payload }) if payload == [0xa0]
        ));

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
            dispatch_datagram(&registry, &endpoint_packet[..endpoint_len], &mut output),
            Ok(DcidDatagram::Endpoint { received_dcid, endpoint: 7 })
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
            match dispatch_datagram(&registry, &relay_packet[..relay_len], &mut output).unwrap() {
                DcidDatagram::Forward { rule, used, .. } => {
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
        let mut registry = DcidRegistry::<(), u16, 1>::new();
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
        let DcidDatagram::Forward { used, .. } =
            dispatch_datagram(&registry, &packet[..packet_len], &mut output).unwrap()
        else {
            panic!("bootstrap packet must be forwarded")
        };
        let (header, _, _) = crate::decode_long_packet(&output[..used]).unwrap();
        assert_eq!(header.dcid, None);
        assert_eq!(header.scid, Some(source));
    }

    #[test]
    fn an_initial_with_an_empty_destination_is_not_direct_traffic() {
        let source = ConnectionId::new(11).unwrap();
        let registry = DcidRegistry::<(), u16, 1>::new();
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
            dispatch_datagram(&registry, &packet[..packet_len], &mut output),
            Err(DcidDatagramError::Registry(DcidRegistryError::Missing))
        ));
    }
}
