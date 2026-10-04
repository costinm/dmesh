//! Who we are on the wire: the stable device id and the signature on our announce.

use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use dmesh_server::announce::{self, Announce};
use p256::SecretKey;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use p256::elliptic_curve::Generate;
use p256::elliptic_curve::sec1::ToSec1Point;
use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey};
use sha2::{Digest, Sha256};

#[derive(Debug)]
pub enum IdentityError {
    /// The announce does not fit with the key and signature added.
    TooLarge,
    Key(String),
    Io(std::io::Error),
}

impl std::fmt::Display for IdentityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooLarge => f.write_str("announce with its identity exceeds the wire bound"),
            Self::Key(message) => write!(f, "identity key: {message}"),
            Self::Io(error) => write!(f, "identity key file: {error}"),
        }
    }
}

impl std::error::Error for IdentityError {}

/// The local identity. A receiver accepts an unsigned announce only from a
/// peer that carries no public key, so a platform that cannot sign (Android
/// today, from a hash of its SSH key) uses [`UnsignedIdentity`].
pub trait Identity: Send + Sync {
    /// The 16-byte stable device id: a prefix of SHA-256 of the public key.
    fn device_id(&self) -> [u8; 16];

    /// Add the public key and signature to `announce`. The default adds nothing.
    fn sign(&self, _announce: &mut Announce) -> Result<(), IdentityError> {
        Ok(())
    }
}

/// A device id without a key: announces carry no signature.
#[derive(Clone, Copy, Debug)]
pub struct UnsignedIdentity {
    id: [u8; 16],
}

impl UnsignedIdentity {
    /// The id is the first 16 bytes of SHA-256 of `seed` (a stable local
    /// string such as the node's SSH public key).
    pub fn from_seed(seed: &[u8]) -> Self {
        let digest = Sha256::digest(seed);
        let mut id = [0u8; 16];
        id.copy_from_slice(&digest[..16]);
        Self { id }
    }
}

impl Identity for UnsignedIdentity {
    fn device_id(&self) -> [u8; 16] {
        self.id
    }
}

/// A P-256 key: announces carry the compressed public key and an ECDSA
/// signature, and the device id is derived from the key.
pub struct P256Identity {
    signing: SigningKey,
    public: Vec<u8>,
    id: [u8; 16],
}

impl P256Identity {
    pub fn from_secret(secret: SecretKey) -> Self {
        let public = secret.public_key().to_sec1_point(true).as_bytes().to_vec();
        let digest = Sha256::digest(&public);
        let mut id = [0u8; 16];
        id.copy_from_slice(&digest[..16]);
        Self {
            signing: SigningKey::from(secret),
            public,
            id,
        }
    }

    pub fn generate() -> Self {
        Self::from_secret(SecretKey::generate())
    }

    /// Read a PKCS#8 PEM key from `path`, or generate one and write it there
    /// (mode 0600, parent directories created).
    pub fn load_or_generate(path: &Path) -> Result<Self, IdentityError> {
        if let Ok(pem) = fs::read_to_string(path) {
            if !pem.is_empty() {
                if let Ok(secret) = SecretKey::from_pkcs8_pem(&pem) {
                    return Ok(Self::from_secret(secret));
                }
            }
        }
        let secret = SecretKey::generate();
        let pem = secret
            .to_pkcs8_pem(Default::default())
            .map_err(|error| IdentityError::Key(error.to_string()))?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(IdentityError::Io)?;
        }
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(path)
            .map_err(IdentityError::Io)?;
        file.write_all(pem.as_bytes()).map_err(IdentityError::Io)?;
        Ok(Self::from_secret(secret))
    }

    /// The compressed SEC1 public key carried in announces.
    pub fn public_key(&self) -> &[u8] {
        &self.public
    }
}

impl Identity for P256Identity {
    fn device_id(&self) -> [u8; 16] {
        self.id
    }

    fn sign(&self, announce: &mut Announce) -> Result<(), IdentityError> {
        if !announce.set_public_key(&self.public) {
            return Err(IdentityError::TooLarge);
        }
        // The signature covers the canonical fields including the key. A
        // signed host record is larger than the ESP/NAN unsigned wire, so the
        // scratch buffer is too.
        let mut bytes = [0u8; 384];
        let used = announce::signing_bytes(*announce, &mut bytes).ok_or(IdentityError::TooLarge)?;
        let signature: Signature = self.signing.sign(&bytes[..used]);
        if !announce.set_signature(signature.to_bytes().as_ref()) {
            return Err(IdentityError::TooLarge);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_generated_key_signs_an_announce_that_verifies() {
        let identity = P256Identity::generate();
        let mut announce = Announce::discovery(identity.device_id(), 16, 5);
        identity.sign(&mut announce).unwrap();
        assert!(announce.has_identity());
        assert!(announce::verify_identity(announce));
        // Changing a signed field breaks the signature.
        announce.uptime_secs += 1;
        assert!(!announce::verify_identity(announce));
    }

    #[test]
    fn the_key_file_is_created_private_and_reloaded() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("nested").join("key.pem");
        let first = P256Identity::load_or_generate(&path).unwrap();
        assert_eq!(
            std::os::unix::fs::PermissionsExt::mode(&fs::metadata(&path).unwrap().permissions())
                & 0o777,
            0o600
        );
        let second = P256Identity::load_or_generate(&path).unwrap();
        assert_eq!(first.device_id(), second.device_id());
        assert_eq!(first.public_key(), second.public_key());
    }

    #[test]
    fn an_unsigned_identity_has_a_stable_id_and_no_signature() {
        let identity = UnsignedIdentity::from_seed(b"ssh-ed25519 AAAA");
        assert_eq!(identity.device_id(), UnsignedIdentity::from_seed(b"ssh-ed25519 AAAA").device_id());
        let mut announce = Announce::discovery(identity.device_id(), 16, 1);
        identity.sign(&mut announce).unwrap();
        assert!(!announce.has_identity());
    }
}
