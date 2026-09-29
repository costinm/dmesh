#![no_std]

//! Runtime-neutral UART framing shared by host forwarding and ESP32 firmware.

extern crate alloc;
#[cfg(feature = "host")]
extern crate std;

/// Low-level codec API. It is public only so the Wi-Fi backend can reuse the
/// implementation; it is not part of the service command API.
#[doc(hidden)]
pub mod codec;
pub mod pool;

/// Marker for one complete QUIC-lite packet inside a decoded PPP record.
/// Every QUIC-lite packet type uses this envelope; packet classification stays
/// in QUIC-lite.
pub const PACKET_MARKER: u8 = 0xf7;
/// Sideband control record that asks a sleepy Main device to remain awake for
/// its configured debug grace period. It is not a QUIC packet.
pub const WAKE_MARKER: u8 = 0xf8;

#[deprecated(note = "UART carries opaque QUIC packets; use PACKET_MARKER")]
pub const DATAGRAM_MARKER: u8 = PACKET_MARKER;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PacketFrameError {
    Empty,
    NotPacket,
    PayloadTooLarge,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DatagramFrameError {
    Empty,
    NotDatagram,
    PayloadTooLarge,
}

/// Remove the UART bearer envelope without inspecting the QUIC-lite packet.
pub fn decode_packet(payload: &[u8]) -> Result<&[u8], PacketFrameError> {
    let Some((&marker, packet)) = payload.split_first() else {
        return Err(PacketFrameError::Empty);
    };
    if marker != PACKET_MARKER {
        return Err(PacketFrameError::NotPacket);
    }
    if packet.is_empty() {
        return Err(PacketFrameError::Empty);
    }
    if packet.len() > quic_lite::DEFAULT_MAX_PACKET_SIZE {
        return Err(PacketFrameError::PayloadTooLarge);
    }
    Ok(packet)
}

/// Construct a streaming PPP encoder for one opaque QUIC-lite packet.
pub fn encode_packet(packet: &[u8]) -> codec::Result<codec::Encoder<'_>> {
    if packet.is_empty() {
        return Err(codec::Error::EmptyPayload);
    }
    codec::Encoder::new_prefixed(
        PACKET_MARKER,
        packet,
        quic_lite::DEFAULT_MAX_PACKET_SIZE + 1,
    )
}

/// Construct the single-record UART wake request.
pub fn encode_wake() -> codec::Result<codec::Encoder<'static>> {
    codec::Encoder::new(&[WAKE_MARKER], 1)
}

#[deprecated(note = "UART carries opaque QUIC packets; use decode_packet")]
pub fn decode_datagram(payload: &[u8]) -> Result<&[u8], DatagramFrameError> {
    decode_packet(payload).map_err(|error| match error {
        PacketFrameError::Empty => DatagramFrameError::Empty,
        PacketFrameError::NotPacket => DatagramFrameError::NotDatagram,
        PacketFrameError::PayloadTooLarge => DatagramFrameError::PayloadTooLarge,
    })
}

#[deprecated(note = "UART carries opaque QUIC packets; use encode_packet")]
pub fn encode_datagram(packet: &[u8]) -> codec::Result<codec::Encoder<'_>> {
    encode_packet(packet)
}

/// Linux UART device and asynchronous I/O. Firmware builds retain the
/// runtime-neutral codec, marker envelope, and pool-backed decoder above.
#[cfg(all(feature = "host", target_os = "linux"))]
pub mod host;

#[cfg(test)]
mod datagram_tests {
    use super::*;

    #[test]
    fn one_marker_wraps_every_opaque_quic_packet() {
        let mut encoder = encode_packet(&[0xc0, 1, 2]).unwrap();
        let mut wire = [0u8; 16];
        let used = encoder.write(&mut wire);
        assert!(encoder.is_finished());
        let mut decoder = codec::Decoder::with_max(16);
        let records = decoder.push(&wire[..used]).unwrap();
        assert_eq!(decode_packet(&records[0]), Ok(&[0xc0, 1, 2][..]));
        assert_eq!(decode_packet(&[1, 2]), Err(PacketFrameError::NotPacket));
    }

    #[test]
    fn wake_record_is_a_single_non_quic_sideband_marker() {
        let mut encoder = encode_wake().unwrap();
        let mut wire = [0u8; 8];
        let used = encoder.write(&mut wire);
        assert!(encoder.is_finished());
        let mut decoder = codec::Decoder::with_max(8);
        let records = decoder.push(&wire[..used]).unwrap();
        assert_eq!(records, alloc::vec![alloc::vec![WAKE_MARKER]]);
        assert_eq!(decode_packet(&records[0]), Err(PacketFrameError::NotPacket));
    }
}
