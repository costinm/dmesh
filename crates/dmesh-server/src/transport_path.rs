//! Common packet-path metadata and egress policy for bearer adapters.
//!
//! This is deliberately below services and above platform framing. UART PPP,
//! ESP-NOW action frames, raw UDP6, FSK, and LoRa each decode into the same
//! path facts. A connection may prefer its ingress path for a reply, but the
//! preference is not ownership: a later multipath scheduler may select any
//! eligible live bearer without changing the service or QUIC-lite packet.

/// Stable platform-neutral bearer identifier.
///
/// Values are intentionally open rather than an exhaustive enum: a product
/// can assign FSK, LoRa, BLE, or a test bearer without teaching every shared
/// service about that adapter. The predefined values are the current ESP
/// links and must remain stable because they identify an existing raw
/// association's reply preference.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd)]
#[repr(transparent)]
pub struct TransportId(pub u8);

impl TransportId {
    pub const UDP6: Self = Self(1);
    pub const NOW: Self = Self(2);
    pub const UART: Self = Self(3);
    pub const NAN: Self = Self(4);
    pub const FSK: Self = Self(5);
    pub const LORA: Self = Self(6);
    pub const BLE: Self = Self(7);

    /// Bit used by [`TransportMask`]. IDs outside the bounded multipath set
    /// retain their ingress metadata but cannot be selected until a platform
    /// registers an explicit scheduler mapping for them.
    pub const fn mask_bit(self) -> u32 {
        if self.0 == 0 || self.0 > 32 {
            0
        } else {
            1_u32 << (self.0 - 1)
        }
    }
}

/// Bounded set of bearers eligible for one egress frame.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(transparent)]
pub struct TransportMask(pub u32);

impl TransportMask {
    pub const NONE: Self = Self(0);

    pub const fn only(transport: TransportId) -> Self {
        Self(transport.mask_bit())
    }

    pub const fn contains(self, transport: TransportId) -> bool {
        self.0 & transport.mask_bit() != 0
    }

    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

/// Packet provenance retained after an adapter has released its native frame.
///
/// `peer` is the adapter's stable local-link identity when known. It is not a
/// routing destination: multipath forwarding may select a different link or
/// next hop. `link_hint` is platform-owned (for example ESP STA/AP) and is
/// opaque to portable services.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PacketPath {
    pub ingress: TransportId,
    pub peer: [u8; 6],
    pub link_hint: u8,
}

/// Exact bounded mapping between a platform address and QUIC-lite's opaque
/// path handle.
///
/// Small adapters cannot squeeze a complete UDP6 address, port, interface and
/// MAC into `PathId` without collisions. They use this table to allocate a
/// handle and retain the complete return address outside QUIC. Host socket
/// code naturally retains the same tuple in its connection task; tests use
/// this table to exercise the bounded firmware ownership rule.
pub struct PathBindingTable<K, const N: usize> {
    entries: [Option<(quic_lite::PathId, K)>; N],
    next: u64,
}

impl<K: Copy + Eq, const N: usize> PathBindingTable<K, N> {
    pub const fn new(first_path_value: u64) -> Self {
        Self {
            entries: [None; N],
            next: first_path_value,
        }
    }

    /// Return the stable handle for an exact address, allocating one empty
    /// slot when first observed. A full table applies bounded backpressure;
    /// it never aliases or evicts another live return address.
    pub fn bind(&mut self, key: K) -> Option<quic_lite::PathId> {
        if let Some((path, _)) = self
            .entries
            .iter()
            .flatten()
            .find(|(_, known)| *known == key)
        {
            return Some(*path);
        }
        let slot = self.entries.iter().position(Option::is_none)?;
        let path = loop {
            let candidate = quic_lite::PathId::new(self.next)?;
            self.next = self.next.checked_add(1)?;
            if !self
                .entries
                .iter()
                .flatten()
                .any(|(known, _)| *known == candidate)
            {
                break candidate;
            }
        };
        self.entries[slot] = Some((path, key));
        Some(path)
    }

    pub fn get(&self, path: quic_lite::PathId) -> Option<K> {
        self.entries
            .iter()
            .flatten()
            .find_map(|(known, key)| (*known == path).then_some(*key))
    }

    pub fn remove(&mut self, path: quic_lite::PathId) -> bool {
        let Some(entry) = self
            .entries
            .iter_mut()
            .find(|entry| entry.is_some_and(|(known, _)| known == path))
        else {
            return false;
        };
        *entry = None;
        true
    }

    /// Reclaim one platform binding only after its connection owner confirms
    /// the opaque path is no longer live.
    pub fn reclaim_one(&mut self, reclaimable: impl Fn(quic_lite::PathId) -> bool) -> bool {
        let Some(entry) = self
            .entries
            .iter_mut()
            .find(|entry| entry.as_ref().is_some_and(|(path, _)| reclaimable(*path)))
        else {
            return false;
        };
        *entry = None;
        true
    }
}

/// Policy supplied with a queued outbound frame.
///
/// Initially replies use `preferred` only, preserving today's same-bearer
/// behavior. A router can instead set a wider `eligible` mask and let the
/// shared scheduler prefer a lower-loss/live bearer or duplicate control
/// frames. The frame itself remains connection-owned, never copied into one
/// queue per bearer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EgressPolicy {
    pub preferred: TransportId,
    pub eligible: TransportMask,
}

impl EgressPolicy {
    pub const fn reply(path: PacketPath) -> Self {
        Self {
            preferred: path.ingress,
            eligible: TransportMask::only(path.ingress),
        }
    }

    /// Pick the preferred bearer when it is live; otherwise choose the first
    /// live eligible bearer. Availability is supplied by the platform owner,
    /// so this portable policy never probes or wakes a radio.
    pub const fn select(self, available: TransportMask) -> Option<TransportId> {
        if self.eligible.contains(self.preferred) && available.contains(self.preferred) {
            return Some(self.preferred);
        }
        let eligible = self.eligible.0 & available.0;
        if eligible == 0 {
            return None;
        }
        Some(TransportId(eligible.trailing_zeros() as u8 + 1))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reply_stays_on_ingress_until_policy_expands_it() {
        let path = PacketPath {
            ingress: TransportId::NOW,
            peer: [1; 6],
            link_hint: 0,
        };
        let policy = EgressPolicy::reply(path);
        let available =
            TransportMask::only(TransportId::NOW).union(TransportMask::only(TransportId::UART));
        assert_eq!(policy.select(available), Some(TransportId::NOW));
    }

    #[test]
    fn multipath_policy_falls_back_without_losing_preference() {
        let policy = EgressPolicy {
            preferred: TransportId::NOW,
            eligible: TransportMask::only(TransportId::NOW)
                .union(TransportMask::only(TransportId::UDP6))
                .union(TransportMask::only(TransportId::UART)),
        };
        assert_eq!(
            policy.select(TransportMask::only(TransportId::UDP6)),
            Some(TransportId::UDP6)
        );
    }

    #[test]
    fn exact_path_bindings_do_not_alias_two_udp_ports_on_one_peer() {
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        struct UdpPeer {
            ip: [u8; 16],
            port: u16,
            mac: [u8; 6],
        }
        let first = UdpPeer {
            ip: [1; 16],
            port: 3337,
            mac: [2; 6],
        };
        let second = UdpPeer {
            port: 49152,
            ..first
        };
        let mut bindings = PathBindingTable::<UdpPeer, 2>::new(0x1_0000_0000_0001);
        let first_path = bindings.bind(first).unwrap();
        let second_path = bindings.bind(second).unwrap();
        assert_ne!(first_path, second_path);
        assert_eq!(bindings.bind(first), Some(first_path));
        assert_eq!(bindings.get(first_path), Some(first));
        assert_eq!(bindings.get(second_path), Some(second));
        assert!(bindings.remove(first_path));
        assert_eq!(bindings.get(first_path), None);
    }

    #[test]
    fn full_path_table_reclaims_only_connection_confirmed_inactive_binding() {
        let mut bindings = PathBindingTable::<u16, 2>::new(10);
        let live = bindings.bind(3337).unwrap();
        let stale = bindings.bind(49152).unwrap();
        assert_eq!(bindings.bind(49153), None);
        assert!(!bindings.reclaim_one(|_| false));
        assert_eq!(bindings.get(live), Some(3337));
        assert_eq!(bindings.get(stale), Some(49152));

        assert!(bindings.reclaim_one(|path| path == stale));
        let replacement = bindings.bind(49153).unwrap();
        assert_ne!(replacement, live);
        assert_ne!(replacement, stale);
        assert_eq!(bindings.get(live), Some(3337));
        assert_eq!(bindings.get(replacement), Some(49153));
    }
}
