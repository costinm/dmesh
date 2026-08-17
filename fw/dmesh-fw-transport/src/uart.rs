// IMPORTANT: This crate is for firmware/platform-only glue. If code can be
// host-tested or reused without ESP/FreeRTOS ownership, it probably belongs
// in `quic-lite` (QUIC-lite transport mechanics) or `dmesh-server` (shared
// service/protocol behavior), not here.

//! PPP UART L2 marker and payload classification shared by firmware adapters.

pub use quic_lite::uart::{
    UartIngress as PppIngress, UartIngressError as PppIngressError, UART_TRANSPORT_MARKER,
};

pub use quic_lite::uart::encode_uart_datagram as encode_uart_transport_payload;

/// Empty PPP payloads are invalid; they are not link heartbeats.
pub use quic_lite::uart::classify_uart_payload as classify_ppp_payload;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TRANSPORT_MTU;

    #[test]
    fn marker_is_unambiguous_and_empty_is_invalid() {
        assert_eq!(
            classify_ppp_payload(&[UART_TRANSPORT_MARKER, 0x40]),
            Ok(PppIngress::Transport(&[0x40]))
        );
        assert_eq!(
            classify_ppp_payload(&[0xa1, 1]),
            Ok(PppIngress::DirectRecord(&[0xa1, 1]))
        );
        assert_eq!(classify_ppp_payload(&[]), Err(PppIngressError::Empty));
    }

    #[test]
    fn egress_uses_marker() {
        let mut out = [0u8; TRANSPORT_MTU + 1];
        let used = encode_uart_transport_payload(&[0x40, 1], &mut out).unwrap();
        assert_eq!(&out[..used], &[UART_TRANSPORT_MARKER, 0x40, 1]);
    }
}
