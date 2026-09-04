//! UART PPP-information-field framing for opaque QUIC-lite packets.
//!
//! Serial I/O remains in host and ESP bearer adapters. This module recognizes
//! only the UART transport marker; it does not decode QUIC headers, direct
//! envelopes, CBOR, or service records.

use quic_lite::DEFAULT_MAX_DATAGRAM_SIZE;

/// Non-ASCII marker preceding one complete QUIC-lite datagram in PPP.
pub const UART_TRANSPORT_MARKER: u8 = 0xf7;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UartIngress<'a> {
    Transport(&'a [u8]),
    /// An unmarked PPP information field. New senders use this only for a
    /// complete private direct long-header packet. The shared connectionless
    /// endpoint, not the UART adapter, decides whether it is admissible.
    Unmarked(&'a [u8]),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UartIngressError {
    Empty,
    Oversize,
}

/// Prefix a complete transport datagram for one PPP information field.
pub fn encode_uart_datagram(packet: &[u8], out: &mut [u8]) -> Option<usize> {
    if packet.is_empty() || packet.len() > DEFAULT_MAX_DATAGRAM_SIZE || out.len() < packet.len() + 1
    {
        return None;
    }
    out[0] = UART_TRANSPORT_MARKER;
    out[1..packet.len() + 1].copy_from_slice(packet);
    Some(packet.len() + 1)
}

/// Classify one PPP payload. Empty frames are invalid, not heartbeats.
///
/// Direct records carry the custom-version QUIC-lite long header, so control
/// has the same framing over UART and UDP. The unmarked branch deliberately
/// preserves its completed bytes: bare CBOR is not a compatibility command
/// path and is rejected by the shared direct endpoint.
pub fn classify_uart_payload(payload: &[u8]) -> Result<UartIngress<'_>, UartIngressError> {
    let Some((&first, rest)) = payload.split_first() else {
        return Err(UartIngressError::Empty);
    };
    if first == UART_TRANSPORT_MARKER {
        if rest.is_empty() {
            return Err(UartIngressError::Empty);
        }
        if rest.len() > DEFAULT_MAX_DATAGRAM_SIZE {
            return Err(UartIngressError::Oversize);
        }
        Ok(UartIngress::Transport(rest))
    } else if payload.len() > DEFAULT_MAX_DATAGRAM_SIZE {
        Err(UartIngressError::Oversize)
    } else {
        Ok(UartIngress::Unmarked(payload))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn marker_is_unambiguous_and_empty_is_invalid() {
        assert_eq!(
            classify_uart_payload(&[UART_TRANSPORT_MARKER, 0x40]),
            Ok(UartIngress::Transport(&[0x40]))
        );
        assert_eq!(
            classify_uart_payload(&[0xa1, 1]),
            Ok(UartIngress::Unmarked(&[0xa1, 1]))
        );
        assert_eq!(classify_uart_payload(&[]), Err(UartIngressError::Empty));
    }

    #[test]
    fn direct_packet_remains_opaque_for_the_shared_handler() {
        let mut packet = [0u8; 32];
        let used = crate::direct::ConnectionlessMessage::encode(&[0xa1, 1], &mut packet).unwrap();
        assert_eq!(
            classify_uart_payload(&packet[..used]),
            Ok(UartIngress::Unmarked(&packet[..used]))
        );
    }
    #[test]
    fn egress_uses_the_shared_mtu_and_marker() {
        let mut out = [0u8; DEFAULT_MAX_DATAGRAM_SIZE + 1];
        let used = encode_uart_datagram(&[0x40, 1], &mut out).unwrap();
        assert_eq!(&out[..used], &[UART_TRANSPORT_MARKER, 0x40, 1]);
    }
}
