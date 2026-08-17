//! Host-testable state for two opaque datagram bearers.
//!
//! This is deliberately not firmware or service code. A host harness may use
//! it while a connection bootstraps on an existing bearer and then moves its
//! established QUIC-lite packets over either selected path. Serial I/O,
//! socket ownership, commands, logs, and endpoint identities stay outside.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PathBridgeAction<'a> {
    /// Send a device-originated datagram to the existing host peer.
    ToBackend(&'a [u8]),
    /// Deliver the one bootstrap reply through the original bearer.
    ToBootstrapPath(&'a [u8]),
    /// Send an established backend datagram over the selected secondary path.
    ToSecondaryPath(&'a [u8]),
    /// Empty, malformed, or oversized PPP data is ignored.
    Drop,
}

/// Stateless-payload, bounded bridge policy for a connection which has an
/// existing bootstrap bearer and a secondary bearer. It does not parse QUIC
/// headers: endpoint/DCID validation remains in the one shared connection.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PathBridge {
    bootstrap_reply_pending: bool,
}

impl PathBridge {
    /// A bootstrap-bearer packet establishes where the first backend reply
    /// must go. Later connection traffic is selected by the transport policy.
    pub fn on_bootstrap_path<'a>(&mut self, packet: &'a [u8]) -> PathBridgeAction<'a> {
        if packet.is_empty() || packet.len() > crate::DEFAULT_MAX_DATAGRAM_SIZE {
            return PathBridgeAction::Drop;
        }
        self.bootstrap_reply_pending = true;
        PathBridgeAction::ToBackend(packet)
    }

    /// A complete datagram received from the secondary path. The bridge does
    /// not interpret its payload or path-specific framing.
    pub fn on_secondary_path<'a>(&self, packet: &'a [u8]) -> PathBridgeAction<'a> {
        if packet.is_empty() || packet.len() > crate::DEFAULT_MAX_DATAGRAM_SIZE {
            PathBridgeAction::Drop
        } else {
            PathBridgeAction::ToBackend(packet)
        }
    }

    /// Preserve the existing association for exactly its bootstrap reply.
    /// Subsequent endpoint output uses the secondary path; no service semantics
    /// or firmware-specific policy is embedded in this choice.
    pub fn on_backend_datagram<'a>(&mut self, packet: &'a [u8]) -> PathBridgeAction<'a> {
        self.on_backend_datagram_on_path(packet, true)
    }

    /// Choose the bearer for established backend output. The first response
    /// always returns on the bootstrap bearer; after that a host multipath
    /// adapter may keep one path full and spill excess datagrams to another without
    /// interpreting transport or service bytes.
    pub fn on_backend_datagram_on_path<'a>(
        &mut self,
        packet: &'a [u8],
        secondary: bool,
    ) -> PathBridgeAction<'a> {
        if packet.is_empty() || packet.len() > crate::DEFAULT_MAX_DATAGRAM_SIZE {
            return PathBridgeAction::Drop;
        }
        if self.bootstrap_reply_pending {
            self.bootstrap_reply_pending = false;
            PathBridgeAction::ToBootstrapPath(packet)
        } else if secondary {
            PathBridgeAction::ToSecondaryPath(packet)
        } else {
            PathBridgeAction::ToBootstrapPath(packet)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn preserves_one_bootstrap_reply_then_uses_secondary_path() {
        let mut bridge = PathBridge::default();
        assert_eq!(
            bridge.on_bootstrap_path(&[0x40, 1]),
            PathBridgeAction::ToBackend(&[0x40, 1])
        );
        assert_eq!(
            bridge.on_backend_datagram(&[0x40, 2]),
            PathBridgeAction::ToBootstrapPath(&[0x40, 2])
        );
        assert_eq!(
            bridge.on_backend_datagram(&[0x40, 3]),
            PathBridgeAction::ToSecondaryPath(&[0x40, 3])
        );
    }

    #[test]
    fn established_packets_may_spill_to_the_bootstrap_path() {
        let mut bridge = PathBridge::default();
        assert!(matches!(
            bridge.on_bootstrap_path(&[0x40, 1]),
            PathBridgeAction::ToBackend(_)
        ));
        assert!(matches!(
            bridge.on_backend_datagram(&[0x40, 2]),
            PathBridgeAction::ToBootstrapPath(_)
        ));
        assert!(matches!(
            bridge.on_backend_datagram_on_path(&[0x40, 3], false),
            PathBridgeAction::ToBootstrapPath(_)
        ));
    }
}
