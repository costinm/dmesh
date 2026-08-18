//! Tiny bearer-health probe used only to localize UDP delivery failures.
//!
//! This is deliberately not a command, stream, or authentication mechanism.
//! A UDP adapter may answer this fixed nonce echo before QUIC-lite parsing so
//! a test can distinguish socket ingress/egress from DCID and handler work.

pub const UDP_BEARER_PROBE_REQUEST: [u8; 4] = *b"DMUP";
pub const UDP_BEARER_PROBE_RESPONSE: [u8; 4] = *b"DMUR";
pub const UDP_BEARER_PROBE_LEN: usize = 12;

pub fn encode_udp_bearer_probe(nonce: u64) -> [u8; UDP_BEARER_PROBE_LEN] {
    let mut packet = [0u8; UDP_BEARER_PROBE_LEN];
    packet[..4].copy_from_slice(&UDP_BEARER_PROBE_REQUEST);
    packet[4..].copy_from_slice(&nonce.to_be_bytes());
    packet
}

pub fn udp_bearer_probe_response(packet: &[u8]) -> Option<[u8; UDP_BEARER_PROBE_LEN]> {
    if packet.len() != UDP_BEARER_PROBE_LEN || packet[..4] != UDP_BEARER_PROBE_REQUEST {
        return None;
    }
    let mut response = [0u8; UDP_BEARER_PROBE_LEN];
    response[..4].copy_from_slice(&UDP_BEARER_PROBE_RESPONSE);
    response[4..].copy_from_slice(&packet[4..]);
    Some(response)
}

pub fn decode_udp_bearer_probe_response(packet: &[u8], nonce: u64) -> bool {
    packet.len() == UDP_BEARER_PROBE_LEN
        && packet[..4] == UDP_BEARER_PROBE_RESPONSE
        && packet[4..] == nonce.to_be_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn echoes_only_the_exact_probe() {
        let request = encode_udp_bearer_probe(0x1234);
        let response = udp_bearer_probe_response(&request).unwrap();
        assert!(decode_udp_bearer_probe_response(&response, 0x1234));
        assert!(udp_bearer_probe_response(b"DMUP").is_none());
        assert!(udp_bearer_probe_response(&[0; UDP_BEARER_PROBE_LEN]).is_none());
    }
}
