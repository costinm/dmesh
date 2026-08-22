//! UART PPP-information-field framing for direct records and QUIC-lite datagrams.
//!
//! Serial I/O remains in host and ESP bearer adapters; this only distinguishes
//! their direct records from complete transport datagrams.

use quic_lite::DEFAULT_MAX_DATAGRAM_SIZE;

/// Non-ASCII marker preceding one complete QUIC-lite datagram in PPP.
pub const UART_TRANSPORT_MARKER: u8 = 0xf7;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UartIngress<'a> {
    Transport(&'a [u8]),
    DirectRecord(&'a [u8]),
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
        Ok(UartIngress::DirectRecord(payload))
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
            Ok(UartIngress::DirectRecord(&[0xa1, 1]))
        );
        assert_eq!(classify_uart_payload(&[]), Err(UartIngressError::Empty));
    }
    #[test]
    fn egress_uses_the_shared_mtu_and_marker() {
        let mut out = [0u8; DEFAULT_MAX_DATAGRAM_SIZE + 1];
        let used = encode_uart_datagram(&[0x40, 1], &mut out).unwrap();
        assert_eq!(&out[..used], &[UART_TRANSPORT_MARKER, 0x40, 1]);
    }
}
