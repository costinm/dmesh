//! Tagged-CBOR entry point for bearer-neutral QUIC-lite connection policy.
//!
//! This is intentionally a different component from [`crate::control`].
//! `transport.start` creates or enables a physical path; it neither creates a
//! QUIC-lite connection nor allocates a stream.  A connection manager owns
//! association IDs, streams, RPC, forwards, flow control, and memory grants.
//! It may attach the resulting connection to one or more already-started
//! bearers.

use crate::{
    cbor::{Decoder, Encoder},
    tagged::{Name, Record, decode},
};
pub use quic_lite::{connection::ConnectionManager, connection::ConnectionPolicy};

/// Component for QUIC-lite connection/stream/RPC/forwarding primitives.
/// Component 2 is already assigned to direct iperf; keep connection lifecycle
/// distinct instead of extending a benchmark component.
pub const CONNECTION_COMPONENT: u64 = 3;
pub const CONNECTION_CONFIGURE: u64 = 1;

const FIELD_ACK_FREQUENCY: u64 = 2;
const FIELD_ACK_DELAY_MS: u64 = 3;
const FIELD_TX_BURST_PACKETS: u64 = 4;
const FIELD_PATH_POLICY: u64 = 11;
const FIELD_TIMEOUT_MS: u64 = 12;

/// Currently the only bounded direct connection operation. Stream open, RPC,
/// and forward requests will be added here as their transport-independent
/// managers are introduced; they are not radio operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Request {
    Configure(ConnectionPolicy),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DispatchError<E> {
    MalformedOrDirected,
    Handler(E),
}

pub fn dispatch<H: ConnectionManager>(
    packet: &[u8],
    handler: &mut H,
) -> Result<(), DispatchError<H::Error>> {
    let request = decode_request(packet).ok_or(DispatchError::MalformedOrDirected)?;
    dispatch_request(request, handler).map_err(DispatchError::Handler)
}

pub fn dispatch_request<H: ConnectionManager>(
    request: Request,
    handler: &mut H,
) -> Result<(), H::Error> {
    match request {
        Request::Configure(policy) => handler.configure_connection(policy),
    }
}

/// Decode a local connection request. Directed messages remain the
/// responsibility of the mesh route adapter, before either local component is
/// called.
pub fn decode_request(packet: &[u8]) -> Option<Request> {
    let record = decode(packet)?;
    if record.to.is_some() {
        return None;
    }
    decode_record(record)
}

pub fn decode_record(record: Record<'_>) -> Option<Request> {
    if record.component != Some(Name::Tag(CONNECTION_COMPONENT))
        || record.method != Some(Name::Tag(CONNECTION_CONFIGURE))
    {
        return None;
    }
    Some(Request::Configure(decode_policy(record.fields?)?))
}

fn decode_policy(encoded: &[u8]) -> Option<ConnectionPolicy> {
    let mut d = Decoder::new(encoded);
    let (major, count) = d.head()?;
    if major != 5 || count == u64::MAX {
        return None;
    }
    let mut policy = ConnectionPolicy::default();
    for _ in 0..count {
        match d.uint()? {
            FIELD_ACK_FREQUENCY => {
                policy.ack_frequency =
                    Some(d.uint()?.clamp(1, quic_lite::ACK_RANGE_CAPACITY as u64) as u8)
            }
            FIELD_ACK_DELAY_MS => policy.ack_delay_ms = Some(d.uint()?.clamp(1, 25) as u8),
            FIELD_TX_BURST_PACKETS => policy.tx_burst_packets = Some(d.uint()?.min(32) as u8),
            FIELD_PATH_POLICY => policy.path_policy = Some(d.uint()?.min(4) as u8),
            FIELD_TIMEOUT_MS => policy.timeout_ms = Some(d.uint()?.clamp(1_000, 300_000) as u32),
            _ => d.skip()?,
        }
    }
    d.is_finished().then_some(policy)
}

/// Fixed-buffer encoder used by CLI, direct records, and host tests.
pub fn encode_configure(
    policy: ConnectionPolicy,
    id: Option<u64>,
    out: &mut [u8],
) -> Option<usize> {
    let count = [
        policy.ack_frequency.is_some(),
        policy.ack_delay_ms.is_some(),
        policy.tx_burst_packets.is_some(),
        policy.path_policy.is_some(),
        policy.timeout_ms.is_some(),
    ]
    .into_iter()
    .filter(|present| *present)
    .count() as u64;
    let mut e = Encoder::new(out);
    e.map(if id.is_some() { 4 } else { 3 })?;
    e.uint(1)?;
    e.uint(CONNECTION_COMPONENT)?;
    e.uint(2)?;
    e.uint(CONNECTION_CONFIGURE)?;
    if let Some(id) = id {
        e.uint(3)?;
        e.uint(id)?;
    }
    e.uint(5)?;
    e.map(count)?;
    for (field, value) in [
        (FIELD_ACK_FREQUENCY, policy.ack_frequency),
        (FIELD_ACK_DELAY_MS, policy.ack_delay_ms),
        (FIELD_TX_BURST_PACKETS, policy.tx_burst_packets),
        (FIELD_PATH_POLICY, policy.path_policy),
    ] {
        if let Some(value) = value {
            e.uint(field)?;
            e.uint(value as u64)?;
        }
    }
    if let Some(value) = policy.timeout_ms {
        e.uint(FIELD_TIMEOUT_MS)?;
        e.uint(value as u64)?;
    }
    Some(e.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Manager(Option<ConnectionPolicy>);

    impl ConnectionManager for Manager {
        type Error = ();
        fn configure_connection(&mut self, policy: ConnectionPolicy) -> Result<(), Self::Error> {
            self.0 = Some(policy);
            Ok(())
        }
    }

    #[test]
    fn connection_policy_has_its_own_component_and_owner() {
        let policy = ConnectionPolicy {
            ack_frequency: Some(8),
            path_policy: Some(3),
            ..ConnectionPolicy::default()
        };
        let mut wire = [0; 64];
        let used = encode_configure(policy, Some(9), &mut wire).unwrap();
        assert_eq!(
            decode_request(&wire[..used]),
            Some(Request::Configure(policy))
        );
        let mut manager = Manager::default();
        dispatch(&wire[..used], &mut manager).unwrap();
        assert_eq!(manager.0, Some(policy));
    }

    #[test]
    fn directed_connection_request_is_not_applied_locally() {
        let wire = [
            0xa4,
            1,
            CONNECTION_COMPONENT as u8,
            2,
            1,
            5,
            0xa0,
            9,
            0x62,
            b'e',
            b'7',
        ];
        assert_eq!(decode_request(&wire), None);
    }
}
