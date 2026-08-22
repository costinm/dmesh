//! Bearer-neutral QUIC-lite connection policy.
//!
//! A connection can be carried by UART, UDP6, ESP-NOW, LoRa, or a host-only
//! test bearer.  Consequently this module owns no radio lifecycle, socket,
//! peer address, or task state.  Those belong to physical transport adapters.
//!
//! Stream opening, RPC, forwarding, and service selection are connection
//! operations built on this policy.  They must not be represented as a
//! `transport.start` request: starting a bearer merely makes paths available.

/// Partial policy applied when a QUIC-lite association is created.
///
/// Omitted fields preserve the connection manager's existing/default values.
/// Bounds are enforced by the schema adapter before this value reaches a
/// connection manager, allowing this type to remain CBOR-free and reusable by
/// host tests.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ConnectionPolicy {
    pub ack_frequency: Option<u8>,
    pub ack_delay_ms: Option<u8>,
    pub tx_burst_packets: Option<u8>,
    pub path_policy: Option<u8>,
    pub timeout_ms: Option<u32>,
}

/// Bearer-neutral connection manager boundary.
///
/// Implementations own connection IDs, peer identity, stream allocation, RPC,
/// and forwarding. A physical transport only submits/receives datagrams for
/// the connection manager and never owns these queues or policies.
pub trait ConnectionManager {
    type Error;

    fn configure_connection(&mut self, policy: ConnectionPolicy) -> Result<(), Self::Error>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_has_no_bearer_identity() {
        let policy = ConnectionPolicy {
            ack_frequency: Some(8),
            tx_burst_packets: Some(16),
            ..ConnectionPolicy::default()
        };
        assert_eq!(policy.ack_frequency, Some(8));
        assert_eq!(policy.tx_burst_packets, Some(16));
    }
}
