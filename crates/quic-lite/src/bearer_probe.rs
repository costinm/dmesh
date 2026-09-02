//! Tiny bearer-health probe used only to localize UDP delivery failures.
//!
//! This is deliberately not a command, stream, or authentication mechanism.
//! The probe is a DCID-zero QUIC-lite direct record. It is not a raw-UDP
//! exception: a test can distinguish socket ingress/egress from endpoint
//! bootstrap while exercising the same short-header classifier.

pub const UDP_BEARER_PROBE_REQUEST: [u8; 4] = *b"DMUP";
pub const UDP_BEARER_PROBE_RESPONSE: [u8; 4] = *b"DMUR";
pub const UDP_BEARER_PROBE_PAYLOAD_LEN: usize = 12;

pub fn encode_udp_bearer_probe(packet_number: u32, nonce: u64, out: &mut [u8]) -> Option<usize> {
    let mut payload = [0u8; UDP_BEARER_PROBE_PAYLOAD_LEN];
    payload[..4].copy_from_slice(&UDP_BEARER_PROBE_REQUEST);
    payload[4..].copy_from_slice(&nonce.to_be_bytes());
    crate::encode_direct_packet(packet_number, &payload, out).ok()
}

pub fn udp_bearer_probe_response(packet: &[u8], out: &mut [u8]) -> Option<usize> {
    let (header, payload) = crate::decode_direct_packet(packet).ok()?;
    if payload.len() != UDP_BEARER_PROBE_PAYLOAD_LEN || payload[..4] != UDP_BEARER_PROBE_REQUEST {
        return None;
    }
    let mut response = [0u8; UDP_BEARER_PROBE_PAYLOAD_LEN];
    response[..4].copy_from_slice(&UDP_BEARER_PROBE_RESPONSE);
    response[4..].copy_from_slice(&payload[4..]);
    crate::encode_direct_packet(header.packet_number.wrapping_add(1), &response, out).ok()
}

pub fn decode_udp_bearer_probe_response(packet: &[u8], nonce: u64) -> bool {
    crate::decode_direct_packet(packet).is_ok_and(|(_, payload)| {
        payload.len() == UDP_BEARER_PROBE_PAYLOAD_LEN
            && payload[..4] == UDP_BEARER_PROBE_RESPONSE
            && payload[4..] == nonce.to_be_bytes()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn echoes_only_the_exact_probe() {
        let mut request = [0u8; 32];
        let used = encode_udp_bearer_probe(7, 0x1234, &mut request).unwrap();
        let mut response = [0u8; 32];
        let response_used = udp_bearer_probe_response(&request[..used], &mut response).unwrap();
        assert!(decode_udp_bearer_probe_response(
            &response[..response_used],
            0x1234
        ));
        assert!(udp_bearer_probe_response(b"DMUP", &mut response).is_none());
    }
}
