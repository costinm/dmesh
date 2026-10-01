//! no-std AES-128-GCM packet-protection experiment behind the optional
//! `packet-protection` feature. This is not yet the P8 security design.
//!
//! This module deliberately does not choose packet fields or parse headers.
//! Callers must supply the canonical end-to-end associated data after relay
//! CID restoration. Relays forward ciphertext and its tag without changing
//! either.

use aes_gcm::{Aes128Gcm, KeyInit, Nonce, Tag, aead::AeadInPlace};
use alloc::sync::Arc;
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

use crate::{ConnectionId, Error};

pub(crate) const TRAFFIC_KEY_LEN: usize = 16;
pub(crate) const TRAFFIC_IV_LEN: usize = 12;
pub(crate) const AEAD_TAG_LEN: usize = 16;
pub(crate) const ASSOCIATION_RANDOM_LEN: usize = 32;

/// Serialize the associated-data header with the destination's endpoint CID.
/// Relays may rewrite only the wire DCID; the receiver restores the matching
/// endpoint CID from its local path state before calling this function.
pub(crate) fn canonical_short_header_aad(
    mut header: crate::ShortHeader,
    endpoint_dcid: ConnectionId,
    output: &mut [u8],
) -> Result<usize, Error> {
    if endpoint_dcid.value() == 0 {
        return Err(Error::Invalid);
    }
    header.dcid = endpoint_dcid;
    header.encode(output)
}

/// One directional packet key and its nonce base.
pub(crate) struct DirectionKey {
    key: [u8; TRAFFIC_KEY_LEN],
    iv: [u8; TRAFFIC_IV_LEN],
}

impl DirectionKey {
    fn new(material: &[u8; TRAFFIC_KEY_LEN + TRAFFIC_IV_LEN]) -> Self {
        let mut key = [0; TRAFFIC_KEY_LEN];
        key.copy_from_slice(&material[..TRAFFIC_KEY_LEN]);
        let mut iv = [0; TRAFFIC_IV_LEN];
        iv.copy_from_slice(&material[TRAFFIC_KEY_LEN..]);
        Self { key, iv }
    }

    /// A 96-bit nonce formed by XORing the packet number into the
    /// low 32 bits of the direction-specific IV. Packet numbers are never
    /// reset when paths are added, so retransmissions and multipath copies
    /// receive distinct nonces under this direction key.
    pub(crate) fn nonce(&self, packet_number: u32) -> [u8; TRAFFIC_IV_LEN] {
        let mut nonce = self.iv;
        let number = packet_number.to_be_bytes();
        for (destination, source) in nonce[TRAFFIC_IV_LEN - number.len()..]
            .iter_mut()
            .zip(number)
        {
            *destination ^= source;
        }
        nonce
    }

    /// Encrypt one packet body in place and return its detached Poly1305 tag.
    /// The caller appends the tag after reserving [`AEAD_TAG_LEN`] bytes.
    pub(crate) fn seal(
        &self,
        packet_number: u32,
        associated_data: &[u8],
        body: &mut [u8],
    ) -> Result<[u8; AEAD_TAG_LEN], Error> {
        let cipher = Aes128Gcm::new_from_slice(&self.key).map_err(|_| Error::Invalid)?;
        let nonce = self.nonce(packet_number);
        let tag = cipher
            .encrypt_in_place_detached(Nonce::from_slice(&nonce), associated_data, body)
            .map_err(|_| Error::Invalid)?;
        let mut output = [0; AEAD_TAG_LEN];
        output.copy_from_slice(&tag);
        Ok(output)
    }

    /// Authenticate and decrypt one packet body in place.
    pub(crate) fn open(
        &self,
        packet_number: u32,
        associated_data: &[u8],
        body: &mut [u8],
        tag: &[u8; AEAD_TAG_LEN],
    ) -> Result<(), Error> {
        let cipher = Aes128Gcm::new_from_slice(&self.key).map_err(|_| Error::Invalid)?;
        let nonce = self.nonce(packet_number);
        cipher
            .decrypt_in_place_detached(
                Nonce::from_slice(&nonce),
                associated_data,
                body,
                Tag::from_slice(tag),
            )
            .map_err(|_| Error::Invalid)
    }
}

impl Drop for DirectionKey {
    fn drop(&mut self) {
        self.key.zeroize();
        self.iv.zeroize();
    }
}

/// Direction-separated secrets derived from a provisioned 256-bit PSK and
/// fresh per-association random values supplied by the platform RNG.
pub(crate) struct TrafficKeys {
    pub(crate) client_to_server: DirectionKey,
    pub(crate) server_to_client: DirectionKey,
}

/// Endpoint-local key ordering. The send and receive keys are distinct and
/// their direction is selected from the authenticated association role.
#[derive(Clone)]
pub(crate) struct EndpointProtection {
    pub(crate) send: Arc<DirectionKey>,
    pub(crate) receive: Arc<DirectionKey>,
}

impl TrafficKeys {
    pub(crate) fn for_role(self, role: crate::Role) -> EndpointProtection {
        match role {
            crate::Role::Client => EndpointProtection {
                send: Arc::new(self.client_to_server),
                receive: Arc::new(self.server_to_client),
            },
            crate::Role::Server => EndpointProtection {
                send: Arc::new(self.server_to_client),
                receive: Arc::new(self.client_to_server),
            },
        }
    }
}

/// Derive initial traffic keys using HKDF-SHA256. `client_random` and
/// `server_random` must be independently generated for each association by a
/// cryptographically secure platform RNG; connection IDs are transcript
/// context and are not treated as entropy.
pub(crate) fn derive_traffic_keys(
    psk: &[u8; 32],
    client_random: &[u8; ASSOCIATION_RANDOM_LEN],
    server_random: &[u8; ASSOCIATION_RANDOM_LEN],
    client_cid: ConnectionId,
    server_cid: ConnectionId,
) -> Result<TrafficKeys, Error> {
    if client_cid.value() == 0 || server_cid.value() == 0 || client_cid == server_cid {
        return Err(Error::Invalid);
    }

    let mut salt = [0; ASSOCIATION_RANDOM_LEN * 2];
    salt[..ASSOCIATION_RANDOM_LEN].copy_from_slice(client_random);
    salt[ASSOCIATION_RANDOM_LEN..].copy_from_slice(server_random);
    let schedule = Hkdf::<Sha256>::new(Some(&salt), psk);
    let mut client_to_server = [0; TRAFFIC_KEY_LEN + TRAFFIC_IV_LEN];
    let mut server_to_client = [0; TRAFFIC_KEY_LEN + TRAFFIC_IV_LEN];
    let mut info = [0; 64];
    let label = b"dmesh/quic-lite/traffic/v1/";
    info[..label.len()].copy_from_slice(label);
    info[label.len()..label.len() + 8].copy_from_slice(&client_cid.value().to_be_bytes());
    info[label.len() + 8..label.len() + 16].copy_from_slice(&server_cid.value().to_be_bytes());
    let context_len = label.len() + 16;

    info[context_len..context_len + 4].copy_from_slice(b"c2s\0");
    schedule
        .expand(&info[..context_len + 4], &mut client_to_server)
        .map_err(|_| Error::Invalid)?;
    info[context_len..context_len + 4].copy_from_slice(b"s2c\0");
    schedule
        .expand(&info[..context_len + 4], &mut server_to_client)
        .map_err(|_| Error::Invalid)?;
    salt.zeroize();
    info.zeroize();
    let traffic_keys = TrafficKeys {
        client_to_server: DirectionKey::new(&client_to_server),
        server_to_client: DirectionKey::new(&server_to_client),
    };
    client_to_server.zeroize();
    server_to_client.zeroize();
    Ok(traffic_keys)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn from_hex(input: &str) -> alloc::vec::Vec<u8> {
        input
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let digit = |value: u8| match value {
                    b'0'..=b'9' => value - b'0',
                    b'a'..=b'f' => value - b'a' + 10,
                    _ => panic!("invalid test vector hex"),
                };
                digit(pair[0]) * 16 + digit(pair[1])
            })
            .collect()
    }

    #[test]
    fn nist_aes128_gcm_vector_and_tamper_rejection() {
        let key = [0; 16];
        let nonce = [0; 12];
        let cipher = Aes128Gcm::new_from_slice(&key).unwrap();
        let mut body = [0; 16];
        let tag = cipher
            .encrypt_in_place_detached(Nonce::from_slice(&nonce), &[], &mut body)
            .unwrap();
        assert_eq!(
            body,
            from_hex("0388dace60b6a392f328c2b971b2fe78").as_slice()
        );
        assert_eq!(tag.as_slice(), from_hex("ab6e47d42cec13bdf53a67b21257bddf"));
        let mut tampered = body;
        tampered[0] ^= 1;
        assert!(
            cipher
                .decrypt_in_place_detached(Nonce::from_slice(&nonce), &[], &mut tampered, &tag,)
                .is_err()
        );
    }

    #[test]
    fn association_derivation_separates_directions_and_packet_nonces() {
        let client_cid = ConnectionId::new(0x1020).unwrap();
        let server_cid = ConnectionId::new(0x3040).unwrap();
        let keys =
            derive_traffic_keys(&[0x5a; 32], &[1; 32], &[2; 32], client_cid, server_cid).unwrap();
        assert_ne!(keys.client_to_server.key, keys.server_to_client.key);
        assert_ne!(keys.client_to_server.iv, keys.server_to_client.iv);
        assert_ne!(
            keys.client_to_server.nonce(7),
            keys.client_to_server.nonce(8)
        );
        assert_ne!(
            keys.client_to_server.nonce(7),
            keys.server_to_client.nonce(7)
        );
        let changed =
            derive_traffic_keys(&[0x5a; 32], &[1; 32], &[3; 32], client_cid, server_cid).unwrap();
        assert_ne!(
            keys.client_to_server.nonce(7),
            changed.client_to_server.nonce(7)
        );
    }

    #[test]
    fn authenticated_body_rejects_header_and_ciphertext_changes() {
        let keys = derive_traffic_keys(
            &[0x42; 32],
            &[0x11; 32],
            &[0x22; 32],
            ConnectionId::new(10).unwrap(),
            ConnectionId::new(20).unwrap(),
        )
        .unwrap();
        let aad = b"canonical dmesh endpoint header";
        let mut body = b"STREAM frame and payload".to_vec();
        let tag = keys.client_to_server.seal(9, aad, &mut body).unwrap();
        let mut opened = body.clone();
        keys.client_to_server
            .open(9, aad, &mut opened, &tag)
            .unwrap();
        assert_eq!(opened, b"STREAM frame and payload");

        let mut altered_header_body = body.clone();
        assert_eq!(
            keys.client_to_server.open(
                9,
                b"altered endpoint header",
                &mut altered_header_body,
                &tag
            ),
            Err(Error::Invalid)
        );
        let mut altered_body = body;
        altered_body[0] ^= 1;
        assert_eq!(
            keys.client_to_server.open(9, aad, &mut altered_body, &tag),
            Err(Error::Invalid)
        );
    }

    #[test]
    fn canonical_header_is_stable_across_wire_cid_rewrites() {
        let endpoint_cid = ConnectionId::new(0x1234).unwrap();
        let mut canonical_aad = [0; 32];
        let mut rewritten_aad = [0; 32];
        let header = |dcid| crate::ShortHeader {
            flags: crate::FLAG_FIXED,
            dcid,
            packet_number: 0x0102_0304,
            packet_number_len: 4,
        };
        let canonical_len =
            canonical_short_header_aad(header(endpoint_cid), endpoint_cid, &mut canonical_aad)
                .unwrap();
        let rewritten_len = canonical_short_header_aad(
            header(ConnectionId::new(0x55).unwrap()),
            endpoint_cid,
            &mut rewritten_aad,
        )
        .unwrap();
        assert_eq!(canonical_len, rewritten_len);
        assert_eq!(
            &canonical_aad[..canonical_len],
            &rewritten_aad[..rewritten_len]
        );
    }
}
