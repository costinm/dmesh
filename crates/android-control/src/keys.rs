//! ADB key material: RSA-2048 `adbkey` (PKCS#8 PEM), the Android-native `.pub`
//! encoding, the self-signed x509 cert used for TLS client auth, and a small
//! paired-device (known-hosts) store.
//!
//! File layout (matches host `adb` conventions):
//! - `adbkey`      — PKCS#8 `PRIVATE KEY` PEM, mode 0600.
//! - `adbkey.pub`  — `<base64(android RSA_PUBLIC_KEY)> <name>\n`.
//! - `adbkey.crt`  — self-signed x509 certificate PEM (CN = name).
//!
//! The `.pub` payload is Android's *native* binary RSA public key
//! (`system/core/libcrypto_utils/android_pubkey.cpp`), NOT PKCS#1 DER:
//!
//! ```text
//! uint32 LE modulus_size_words   (64)
//! uint32 LE n0inv                (-N^-1 mod 2^32)
//! byte[256]  modulus             (little-endian, zero-padded)
//! byte[256]  rr                  (2^(2*rsa_bits) mod N, LE, zero-padded)
//! uint32 LE exponent             (65537)
//! ```
//! Fields are zero-padded to 256 bytes exactly as AOSP's `BN_bn2binpad` does
//! (`adb_client`'s copy omits the pad; we do not repeat that bug).

use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use base64::Engine;
use num_bigint::{BigUint, ModInverse};
use num_traits::{One, ToPrimitive};
use pkcs8::{DecodePrivateKey, EncodePrivateKey, LineEnding};
use rcgen::{CertificateParams, DnType, KeyPair, PKCS_RSA_SHA256};
use rsa::{
    traits::PublicKeyParts,
    Pkcs1v15Sign, RsaPrivateKey,
};
use sha1::Sha1;

/// Default adbkey name embedded in `adbkey.pub`.
pub const KEY_NAME: &str = "android-control";

const ANDROID_PUBKEY_MODULUS_SIZE_WORDS: u32 = 64;
const MODULUS_BYTES: usize = 256;
const RR_BYTES: usize = 256;

pub struct AdbKeys {
    pub name: String,
    /// PKCS#8 DER private key (what rustls and rcgen consume).
    pub pkcs8_der: Vec<u8>,
    /// Native ADB `.pub` body: base64(android RSA_PUBLIC_KEY).
    pub pub_pem: String,
    /// Full `adbkey.pub` line: `<pub_pem> <name>\n`.
    pub pub_text: String,
    /// Self-signed certificate, PEM.
    pub cert_pem: String,
    /// Self-signed certificate, DER.
    pub cert_der: Vec<u8>,
    private: Arc<RsaPrivateKey>,
}

impl AdbKeys {
    /// Load keys from `dir` or generate + persist them if absent.
    pub fn load_or_create(dir: &Path) -> Result<Arc<Self>> {
        Self::load_or_create_with(dir, KEY_NAME)
    }

    pub fn load_or_create_with(dir: &Path, name: &str) -> Result<Arc<Self>> {
        fs::create_dir_all(dir)
            .with_context(|| format!("create key dir {}", dir.display()))?;
        let key_path = dir.join("adbkey");
        let pub_path = dir.join("adbkey.pub");
        let crt_path = dir.join("adbkey.crt");

        if key_path.exists() {
            let pem = fs::read_to_string(&key_path)
                .with_context(|| format!("read {}", key_path.display()))?;
            // Reuse the name recorded in an existing adbkey.pub, if any.
            let name = fs::read_to_string(&pub_path)
                .ok()
                .and_then(|s| pub_text_to_bytes(s.trim_end()).ok().map(|(_, n)| n))
                .filter(|n| !n.is_empty())
                .unwrap_or_else(|| name.to_string());
            return Self::from_files(&pem, &crt_path, &name);
        }

        let (pem, pub_text, cert_pem) = Self::generate(name)?;
        write_mode_600(&key_path, pem.as_bytes())?;
        fs::write(&pub_path, pub_text.as_bytes())
            .with_context(|| format!("write {}", pub_path.display()))?;
        fs::write(&crt_path, cert_pem.as_bytes())
            .with_context(|| format!("write {}", crt_path.display()))?;
        Self::from_files(&pem, &crt_path, name)
    }

    fn from_files(pem: &str, crt_path: &Path, name: &str) -> Result<Arc<Self>> {
        let private =
            RsaPrivateKey::from_pkcs8_pem(pem).context("parse adbkey PKCS#8 PEM")?;
        let pub_pem = android_pubkey_b64(&private)?;

        let cert_pem = if crt_path.exists() {
            fs::read_to_string(crt_path)
                .with_context(|| format!("read {}", crt_path.display()))?
        } else {
            let c = cert_pem_from_key(&private, name)?;
            fs::write(crt_path, c.as_bytes())
                .with_context(|| format!("write {}", crt_path.display()))?;
            c
        };
        let cert_der = der_from_pem_cert(&cert_pem)?;
        let pub_text = format!("{pub_pem} {name}\n");

        Ok(Arc::new(Self {
            name: name.to_string(),
            pkcs8_der: private.to_pkcs8_der()?.as_bytes().to_vec(),
            pub_pem,
            pub_text,
            cert_pem,
            cert_der,
            private: Arc::new(private),
        }))
    }

    fn generate(name: &str) -> Result<(String, String, String)> {
        use rand::rngs::OsRng;
        let private =
            RsaPrivateKey::new(&mut OsRng, 2048).context("generate RSA-2048 adbkey")?;
        let pem = (*private
            .to_pkcs8_pem(LineEnding::LF)
            .context("encode adbkey PEM")?)
        .clone();
        let pub_pem = android_pubkey_b64(&private)?;
        let pub_text = format!("{pub_pem} {name}\n");
        let cert_pem = cert_pem_from_key(&private, name)?;
        Ok((pem, pub_text, cert_pem))
    }

    /// RSA-SHA1 (PKCS#1 v1.5) signature of an ADB auth token, as sent in
    /// `A_AUTH arg0=2`.
    pub fn sign_token(&self, token: &[u8]) -> Result<Vec<u8>> {
        self.private
            .sign(Pkcs1v15Sign::new::<Sha1>(), token)
            .context("sign auth token")
    }

    /// rustls client-auth (cert, key) for TLS connections.
    pub fn rustls_client_auth(
        &self,
    ) -> (
        rustls_pki_types::CertificateDer<'static>,
        rustls_pki_types::PrivatePkcs8KeyDer<'static>,
    ) {
        (
            rustls_pki_types::CertificateDer::from(self.cert_der.clone()),
            rustls_pki_types::PrivatePkcs8KeyDer::from(self.pkcs8_der.clone()),
        )
    }

    /// Public key components (n big-endian bytes, e).
    pub fn public_components(&self) -> (Vec<u8>, u32) {
        (
            self.private.n().to_bytes_be(),
            self.private.e().to_u32().expect("rsa exponent fits u32"),
        )
    }
}

/// base64 of the Android-native `RSA_PUBLIC_KEY` binary layout.
pub fn android_pubkey_b64(private: &RsaPrivateKey) -> Result<String> {
    let (n, e) = rsa_public_components(private);
    Ok(base64::engine::general_purpose::STANDARD.encode(android_pubkey_bytes(
        &n, e,
    )))
}

fn rsa_public_components(private: &RsaPrivateKey) -> (Vec<u8>, u32) {
    (
        private.n().to_bytes_be(),
        private.e().to_u32().expect("rsa exponent fits u32"),
    )
}

/// Android-native `RSA_PUBLIC_KEY` binary encoding (see module docs).
pub fn android_pubkey_bytes(n_be: &[u8], e: u32) -> Vec<u8> {
    let n = BigUint::from_bytes_be(n_be);
    let r32 = BigUint::from(1u64 << 32);
    let r = BigUint::one() << (MODULUS_BYTES * 8); // 2^2048
    let rr = r.modpow(&r, &n);
    let rem = &n % &r32;
    let n0inv_inv = rem
        .mod_inverse(&r32)
        .and_then(|v| v.to_biguint())
        .expect("N is odd, inverse exists");
    let n0inv = &r32 - &n0inv_inv; // -N^-1 mod 2^32

    let mut out = Vec::with_capacity(4 + 4 + MODULUS_BYTES + RR_BYTES + 4);
    out.extend_from_slice(&ANDROID_PUBKEY_MODULUS_SIZE_WORDS.to_le_bytes());
    out.extend_from_slice(&n0inv.to_u32().unwrap().to_le_bytes());
    out.extend(pad_le(&n.to_bytes_le(), MODULUS_BYTES));
    out.extend(pad_le(&rr.to_bytes_le(), RR_BYTES));
    out.extend_from_slice(&e.to_le_bytes());
    out
}

fn pad_le(bytes: &[u8], len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    let n = bytes.len().min(len);
    out[..n].copy_from_slice(&bytes[..n]);
    out
}

fn cert_pem_from_key(private: &RsaPrivateKey, name: &str) -> Result<String> {
    use rustls_pki_types::PrivatePkcs8KeyDer;
    let pkcs8 = private.to_pkcs8_der()?;
    let key_der = PrivatePkcs8KeyDer::from(pkcs8.as_bytes().to_vec());
    let key_pair =
        KeyPair::from_pkcs8_der_and_sign_algo(&key_der, &PKCS_RSA_SHA256)
            .context("rcgen key import")?;
    let mut params = CertificateParams::default();
    params.distinguished_name.push(DnType::CommonName, name);
    let cert = params.self_signed(&key_pair).context("self-sign cert")?;
    Ok(cert.pem())
}

fn der_from_pem_cert(pem: &str) -> Result<Vec<u8>> {
    let mut reader = std::io::Cursor::new(pem.as_bytes());
    let certs: Vec<_> = rustls_pemfile::certs(&mut reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("parse cert PEM")?;
    certs
        .into_iter()
        .next()
        .map(|c| c.to_vec())
        .ok_or_else(|| anyhow!("no certificate in PEM"))
}

fn write_mode_600(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut f =
        fs::File::create(path).with_context(|| format!("write {}", path.display()))?;
    f.write_all(bytes).context("write adbkey")?;
    drop(f);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .with_context(|| format!("chmod {}", path.display()))?;
    }
    Ok(())
}

/// Parse a native ADB `.pub` line (`<base64> <name>`) into the binary layout.
pub fn pub_text_to_bytes(pub_text: &str) -> Result<(Vec<u8>, String)> {
    let line = pub_text
        .lines()
        .find(|l| !l.trim().is_empty())
        .context("empty pub text")?;
    let (b64, name) =
        line.split_once(' ').ok_or_else(|| anyhow!("malformed adb pub line"))?;
    let der = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .context("decode pub base64")?;
    Ok((der, name.trim().to_string()))
}

/// Decode a native ADB `.pub` binary blob (as received from a device in
/// `A_AUTH arg0=3` or pairing PeerInfo) into `(n big-endian bytes, e)`.
pub fn native_pub_components(bytes: &[u8]) -> Result<(Vec<u8>, u32)> {
    if bytes.len() < 8 {
        return Err(anyhow!("pub blob too short"));
    }
    let words = u32::from_le_bytes(bytes[0..4].try_into().unwrap()) as usize;
    let mod_len = words * 4;
    let mod_off = 8;
    let rr_off = mod_off + mod_len;
    let exp_off = rr_off + RR_BYTES;
    if bytes.len() < exp_off + 4 {
        return Err(anyhow!("pub blob too short for exponent"));
    }
    let n_le = BigUint::from_bytes_le(&bytes[mod_off..rr_off]);
    let e = u32::from_le_bytes(bytes[exp_off..exp_off + 4].try_into().unwrap());
    Ok((n_le.to_bytes_be(), e))
}

/// Default host key directory: `~/.android`.
pub fn default_key_dir() -> PathBuf {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/"));
    home.join(".android")
}

/// Paired-device store. One line per device:
/// `<guid>\t<host>\t<port>\t<pub-pem or ->\n`
#[derive(Default)]
pub struct KnownHosts {
    path: PathBuf,
    entries: Vec<KnownHost>,
}

#[derive(Clone, Debug)]
pub struct KnownHost {
    pub guid: String,
    pub host: Option<String>,
    pub port: Option<u16>,
    pub pub_pem: Option<String>,
}

impl KnownHosts {
    pub fn load(dir: &Path) -> Result<Self> {
        let path = dir.join("adb_known_hosts");
        let mut entries = Vec::new();
        if path.exists() {
            let mut f = fs::File::open(&path)
                .with_context(|| format!("read {}", path.display()))?;
            let mut s = String::new();
            f.read_to_string(&mut s).with_context(|| path.display().to_string())?;
            for line in s.lines() {
                let line = line.trim_end();
                if line.is_empty() {
                    continue;
                }
                let mut it = line.split('\t');
                let guid = it.next().unwrap_or_default().to_string();
                let host = it.next().filter(|h| !h.is_empty()).map(String::from);
                let port = it.next().and_then(|p| p.parse().ok());
                let pub_pem = it.next().filter(|p| *p != "-").map(String::from);
                entries.push(KnownHost { guid, host, port, pub_pem });
            }
        }
        Ok(Self { path, entries })
    }

    pub fn upsert(&mut self, h: KnownHost) -> Result<()> {
        self.entries.retain(|e| e.guid != h.guid);
        self.entries.push(h);
        self.save()
    }

    pub fn remove(&mut self, guid: &str) -> Result<()> {
        self.entries.retain(|e| e.guid != guid);
        self.save()
    }

    pub fn get(&self, guid: &str) -> Option<&KnownHost> {
        self.entries.iter().find(|e| e.guid == guid)
    }

    pub fn entries(&self) -> &[KnownHost] {
        &self.entries
    }

    fn save(&self) -> Result<()> {
        let mut s = String::new();
        for e in &self.entries {
            s.push_str(&e.guid);
            s.push('\t');
            s.push_str(e.host.as_deref().unwrap_or(""));
            s.push('\t');
            s.push_str(&e.port.map(|p| p.to_string()).unwrap_or_default());
            s.push('\t');
            s.push_str(e.pub_pem.as_deref().unwrap_or("-"));
            s.push('\n');
        }
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("create {}", parent.display()))?;
        }
        fs::write(&self.path, s).with_context(|| format!("write {}", self.path.display()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::RsaPublicKey;

    #[test]
    fn generate_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let keys = AdbKeys::load_or_create(dir.path()).unwrap();
        assert_eq!(keys.pub_text, format!("{} {}\n", keys.pub_pem, keys.name));
        let pem_file = fs::read_to_string(dir.path().join("adbkey")).unwrap();
        assert!(pem_file.starts_with("-----BEGIN PRIVATE KEY-----"));
        assert!(!keys.pkcs8_der.is_empty());
        assert!(keys.cert_pem.contains("BEGIN CERTIFICATE"));

        // reload from disk: same material.
        let keys2 = AdbKeys::load_or_create(dir.path()).unwrap();
        assert_eq!(keys2.pub_pem, keys.pub_pem);
        assert_eq!(keys2.cert_der, keys.cert_der);
        assert_eq!(keys2.pkcs8_der, keys.pkcs8_der);
    }

    #[test]
    fn sign_token_verifies() {
        let dir = tempfile::tempdir().unwrap();
        let keys = AdbKeys::load_or_create(dir.path()).unwrap();
        let token = [7u8; 20];
        let sig = keys.sign_token(&token).unwrap();
        assert_eq!(sig.len(), 256);
        let pubk = RsaPublicKey::new(
            keys.private.n().clone(),
            keys.private.e().clone(),
        )
        .unwrap();
        pubk.verify(Pkcs1v15Sign::new::<Sha1>(), &token, &sig).unwrap();
    }

    #[test]
    fn native_pub_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let keys = AdbKeys::load_or_create(dir.path()).unwrap();
        let (bytes, name) = pub_text_to_bytes(&keys.pub_text).unwrap();
        assert_eq!(name, keys.name);
        // layout: 4 + 4 + 256 + 256 + 4 = 524 bytes
        assert_eq!(bytes.len(), 524);
        let (n_be, e) = native_pub_components(&bytes).unwrap();
        assert_eq!(n_be, keys.private.n().to_bytes_be());
        assert_eq!(e, keys.private.e().to_u32().unwrap());
        // n0inv sanity: (N mod 2^32) * n0inv ≡ -1 (mod 2^32)
        let n0inv = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
        let rem = *n_be.last().unwrap() as u32
            | ((*n_be.get(n_be.len() - 2).unwrap_or(&0)) as u32) << 8
            | ((*n_be.get(n_be.len() - 3).unwrap_or(&0)) as u32) << 16
            | ((*n_be.get(n_be.len() - 4).unwrap_or(&0)) as u32) << 24;
        assert_eq!(rem.wrapping_mul(n0inv).wrapping_add(1), 0);
    }

    #[test]
    fn known_hosts_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let mut kh = KnownHosts::load(dir.path()).unwrap();
        kh.upsert(KnownHost {
            guid: "abc".into(),
            host: Some("10.0.0.1".into()),
            port: Some(4357),
            pub_pem: Some("PEMDATA".into()),
        })
        .unwrap();
        let mut kh2 = KnownHosts::load(dir.path()).unwrap();
        let h = kh2.get("abc").unwrap();
        assert_eq!(h.host.as_deref(), Some("10.0.0.1"));
        assert_eq!(h.port, Some(4357));
        assert_eq!(h.pub_pem.as_deref(), Some("PEMDATA"));
        kh2.remove("abc").unwrap();
        assert!(KnownHosts::load(dir.path()).unwrap().entries().is_empty());
    }

    #[test]
    fn default_key_dir_is_under_home() {
        let d = default_key_dir();
        assert!(d.ends_with(".android"));
    }
}
