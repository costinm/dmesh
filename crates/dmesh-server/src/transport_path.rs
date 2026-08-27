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
        let available = TransportMask::only(TransportId::NOW)
            .union(TransportMask::only(TransportId::UART));
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
}
