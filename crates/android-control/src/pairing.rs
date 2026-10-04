//! Android 11+ wireless ADB pairing handshake (client + server).
//!
//! Wire layout (AOSP `pairing_connection.cpp`, `pairing_auth.cpp`,
//! `aes_128_gcm.cpp`, `tls_connection.cpp`):
//!
//! 1. TCP, then TLS 1.2/1.3. Both sides present certs and **verify nothing**
//!    (`SetCertVerifyCallback([] { return 1; })`).
//! 2. `TLS_export_keying_material(label="adb-label\0", context=empty, 64)`.
//!    (AOSP passes `sizeof("adb-label")` = 10, NUL included.)
//! 3. SPAKE2 (BoringSSL curve25519 variant) with password =
//!    `<pairing code bytes> + <64 exported bytes>`.
//! 4. `PairingPacketHeader { version=1, type, payload_len: u32 BE }` + payload:
//!    - `type=0` SPAKE2_MSG: 32-byte point, plaintext in TLS;
//!    - `type=1` PEER_INFO: AES-128-GCM(`PeerInfo{type, data[8191]}`) + 16 tag.
//!    (Packet types per AOSP `proto/pairing.proto`; distinct from the PeerInfo
//!    `type` byte inside the encrypted payload.)
//!      GCM key = HKDF-SHA256(ikm=64B SPAKE2 key, salt=empty,
//!      info="adb pairing_auth aes-128-gcm key"); nonce = u64 LE counter ++ 4
//!      zero bytes; PeerInfo is encrypted once (counter 0 → all-zero nonce).
//! 5. PeerInfo types: `0` = ADB_RSA_PUB_KEY (our `adbkey.pub` line),
//!    `1` = ADB_DEVICE_GUID (device guid, NUL-terminated).
//!
//! Both roles send their SPAKE2 msg before reading, and send their PeerInfo
//! before reading (AOSP `DoExchangeMsgs`/`DoExchangePeerInfo`), so either
//! ordering of read-then-send still makes progress.

use std::io::{Read, Write};
use std::net::{IpAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use aes_gcm::aead::Aead;
use aes_gcm::{Aes128Gcm, Key, KeyInit, Nonce};
use anyhow::{anyhow, bail, Context, Result};
use hkdf::Hkdf;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::SideData;
use sha2::Sha256;

use crate::keys::AdbKeys;
use crate::spake2::Spake2;

const HEADER_VERSION: u8 = 1;
pub const PACKET_TYPE_SPAKE2_MSG: u8 = 0;
pub const PACKET_TYPE_PEER_INFO: u8 = 1;

pub const PEER_INFO_TYPE_ADB_RSA_PUB_KEY: u8 = 0;
pub const PEER_INFO_TYPE_ADB_DEVICE_GUID: u8 = 1;

const PEER_INFO_SIZE: usize = 8192;
const MAX_PAYLOAD: usize = PEER_INFO_SIZE + 16; // one GCM block + tag

/// Result of a successful pairing (client role).
#[derive(Debug, Clone)]
pub struct PairResult {
    /// Device GUID / serial the device now trusts our key for.
    pub guid: String,
}

/// Result of a successful pairing (server role).
#[derive(Debug, Clone)]
pub struct PairServerResult {
    /// The client's native `adbkey.pub` line (base64 + name).
    pub client_pub: String,
}

#[derive(Debug)]
struct NoCertVerifier;

impl rustls::client::danger::ServerCertVerifier for NoCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        use rustls::SignatureScheme::*;
        vec![
            RSA_PKCS1_SHA1,
            ECDSA_SHA1_Legacy,
            RSA_PKCS1_SHA256,
            ECDSA_NISTP256_SHA256,
            RSA_PKCS1_SHA384,
            ECDSA_NISTP384_SHA384,
            RSA_PKCS1_SHA512,
            ECDSA_NISTP521_SHA512,
            RSA_PSS_SHA256,
            RSA_PSS_SHA384,
            RSA_PSS_SHA512,
            ED25519,
        ]
    }
}

fn client_tls_config(keys: &AdbKeys) -> Result<Arc<rustls::ClientConfig>> {
    let (cert, pk8) = keys.rustls_client_auth();
    let config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoCertVerifier))
        .with_client_auth_cert(vec![cert], pk8.into())
        .context("build pairing client TLS config")?;
    Ok(Arc::new(config))
}

fn server_tls_config(keys: &AdbKeys) -> Result<Arc<rustls::ServerConfig>> {
    let (cert, pk8) = keys.rustls_client_auth();
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], pk8.into())
        .context("build pairing server TLS config")?;
    Ok(Arc::new(config))
}

/// Install the process-level rustls crypto provider (ring) exactly once.
///
/// Must run before any rustls TLS use, including the external `adb_client`
/// crate's `A_STLS` handshake in `adb::AdbDevice::connect`, which does not
/// install a provider itself and would otherwise panic on auto-detection.
pub(crate) fn ensure_provider() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::CryptoProvider::install_default(
            rustls::crypto::ring::default_provider(),
        );
    });
}

fn server_name_for(host: &str) -> Result<ServerName<'static>> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(ServerName::IpAddress(ip.into()));
    }
    ServerName::try_from(host.to_string()).context("server name from host")
}

/// AES-128-GCM counter cipher per AOSP `aes_128_gcm.cpp`.
struct PairCipher {
    gcm: Aes128Gcm,
    enc_seq: u64,
    dec_seq: u64,
}

impl PairCipher {
    fn new(key_material: &[u8; 64]) -> Self {
        let hk = Hkdf::<Sha256>::new(None, key_material);
        let mut okm = [0u8; 16];
        hk.expand(b"adb pairing_auth aes-128-gcm key", &mut okm)
            .expect("16 bytes is a valid HKDF output length");
        let gcm = Aes128Gcm::new(Key::<Aes128Gcm>::from_slice(&okm));
        Self { gcm, enc_seq: 0, dec_seq: 0 }
    }

    fn nonce(seq: u64) -> [u8; 12] {
        let mut n = [0u8; 12];
        n[..8].copy_from_slice(&seq.to_le_bytes());
        n
    }

    fn encrypt(&mut self, data: &[u8]) -> Vec<u8> {
        let out = self
            .gcm
            .encrypt(Nonce::from_slice(&Self::nonce(self.enc_seq)), data)
            .expect("aes-gcm encrypt");
        self.enc_seq += 1;
        out
    }

    fn decrypt(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let out = self
            .gcm
            .decrypt(Nonce::from_slice(&Self::nonce(self.dec_seq)), data)
            .map_err(|e| {
                anyhow!(
                    "aes-gcm decrypt (tag mismatch — SPAKE2 key differs): {e}"
                )
            })?;
        self.dec_seq += 1;
        Ok(out)
    }
}

fn write_packet(w: &mut impl Write, ty: u8, payload: &[u8]) -> Result<()> {
    if payload.is_empty() || payload.len() > MAX_PAYLOAD {
        bail!("pairing payload size out of range: {}", payload.len());
    }
    let mut hdr = [0u8; 6];
    hdr[0] = HEADER_VERSION;
    hdr[1] = ty;
    hdr[2..6].copy_from_slice(&(payload.len() as u32).to_be_bytes());
    w.write_all(&hdr)?;
    w.write_all(payload)?;
    w.flush()?;
    Ok(())
}

fn read_packet(r: &mut impl Read) -> Result<(u8, Vec<u8>)> {
    let mut hdr = [0u8; 6];
    r.read_exact(&mut hdr).context("read pairing header")?;
    if hdr[0] != HEADER_VERSION {
        bail!("pairing header version mismatch: {}", hdr[0]);
    }
    let len = u32::from_be_bytes(hdr[2..6].try_into().unwrap()) as usize;
    if len == 0 || len > MAX_PAYLOAD {
        bail!("pairing payload size out of range: {len}");
    }
    let mut payload = vec![0u8; len];
    r.read_exact(&mut payload).context("read pairing payload")?;
    Ok((hdr[1], payload))
}

fn make_peer_info(ty: u8, data: &[u8]) -> [u8; PEER_INFO_SIZE] {
    let mut pi = [0u8; PEER_INFO_SIZE];
    pi[0] = ty;
    let n = data.len().min(PEER_INFO_SIZE - 1);
    pi[1..1 + n].copy_from_slice(&data[..n]);
    pi
}

fn peer_info_string(pi: &[u8]) -> String {
    let end = pi[1..]
        .iter()
        .position(|&b| b == 0)
        .map(|p| p + 1)
        .unwrap_or(pi.len() - 1);
    String::from_utf8_lossy(&pi[1..end]).into_owned()
}

/// Drive the TLS handshake to completion. TLS 1.3 clients may send the first
/// app-data record in the same burst as `Finished`, so any decrypted bytes
/// returned while still handshaking are preserved in `leftover` (they belong
/// to the pairing stream, not the handshake).
fn tls_handshake_done<C, T, S>(
    tls: &mut rustls::StreamOwned<C, T>,
    leftover: &mut Vec<u8>,
) -> Result<()>
where
    C: std::ops::DerefMut + std::ops::Deref<Target = rustls::ConnectionCommon<S>>,
    T: Read + Write,
    S: SideData,
{
    loop {
        if !tls.conn.is_handshaking() {
            return Ok(());
        }
        let mut buf = [0u8; 4096];
        match tls.read(&mut buf) {
            Ok(0) => bail!("TLS: peer closed during handshake"),
            Ok(n) => {
                leftover.extend_from_slice(&buf[..n]);
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(e) => return Err(e.into()),
        }
        tls.flush()?;
    }
}

/// Reads from the TLS stream, serving handshake-time leftovers first.
struct TlsRead<'a, C, T: Read + Write> {
    tls: &'a mut rustls::StreamOwned<C, T>,
    leftover: &'a mut Vec<u8>,
}

impl<C, T, S> Read for TlsRead<'_, C, T>
where
    C: std::ops::DerefMut + std::ops::Deref<Target = rustls::ConnectionCommon<S>>,
    T: Read + Write,
    S: SideData,
{
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.leftover.is_empty() {
            return self.tls.read(buf);
        }
        let n = buf.len().min(self.leftover.len());
        buf[..n].copy_from_slice(&self.leftover[..n]);
        self.leftover.drain(..n);
        Ok(n)
    }
}

fn export_ekme<C, T, S>(tls: &mut rustls::StreamOwned<C, T>) -> Result<Vec<u8>>
where
    C: std::ops::DerefMut + std::ops::Deref<Target = rustls::ConnectionCommon<S>>,
    T: Read + Write,
    S: SideData,
{
    // AOSP: SSL_export_keying_material(ssl, out, 64, "adb-label", 10 /* incl. NUL */,
    // nullptr, 0, false)
    let label = b"adb-label\0";
    tls.conn
        .export_keying_material(vec![0u8; 64], label, None)
        .with_context(|| "export_keying_material")
}

/// Run the pairing **client** against a device pairing port.
/// `code` is the 6- or 8-digit pairing code shown on the device dialog.
pub fn pair_client(
    host: &str,
    port: u16,
    code: &str,
    keys: &AdbKeys,
) -> Result<PairResult> {
    ensure_provider();
    let stream = TcpStream::connect((host, port))
        .with_context(|| format!("tcp connect to {host}:{port}"))?;
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    stream.set_write_timeout(Some(Duration::from_secs(30)))?;

    let config = client_tls_config(keys)?;
    let conn = rustls::ClientConnection::new(config, server_name_for(host)?)?;
    let mut tls = rustls::StreamOwned::new(conn, stream);
    let mut leftover = Vec::new();
    tls_handshake_done(&mut tls, &mut leftover)?;

    let dbg = std::env::var("ADBCTL_DEBUG").is_ok();
    let hx = |v: &[u8]| -> String { v.iter().map(|b| format!("{b:02x}")).collect() };
    if dbg {
        eprintln!("DBG tls version: {:?}", tls.conn.protocol_version());
    }
    let ekme = export_ekme(&mut tls)?;
    if dbg {
        eprintln!("DBG ekme: {}", hx(&ekme));
    }
    let mut password = code.as_bytes().to_vec();
    password.extend_from_slice(&ekme);
    if dbg {
        eprintln!("DBG code: {:?} password len: {}", code, password.len());
    }

    let mut spake2 = Spake2::new_client(&password);
    if dbg {
        eprintln!("DBG my spake2 msg: {}", hx(spake2.my_msg()));
        eprintln!("DBG my spake2 priv: {}", hx(&spake2.private_for_debug()));
    }

    write_packet(&mut tls, PACKET_TYPE_SPAKE2_MSG, spake2.my_msg())?;
    let (ty, payload) = read_packet(&mut TlsRead { tls: &mut tls, leftover: &mut leftover })?;
    if ty != PACKET_TYPE_SPAKE2_MSG || payload.len() != 32 {
        bail!("expected SPAKE2_MSG, got type={ty} len={}", payload.len());
    }
    if dbg {
        eprintln!("DBG their spake2 msg: {}", hx(&payload));
    }
    let spake2_key = spake2
        .process_msg(payload.as_slice().try_into().unwrap())
        .context("spake2 process")?;
    if dbg {
        eprintln!("DBG spake2 key: {}", hx(&spake2_key));
    }

    let mut cipher = PairCipher::new(&spake2_key);
    let pi = make_peer_info(PEER_INFO_TYPE_ADB_RSA_PUB_KEY, keys.pub_text.as_bytes());
    write_packet(&mut tls, PACKET_TYPE_PEER_INFO, &cipher.encrypt(&pi))?;

    let (ty, payload) = read_packet(&mut TlsRead { tls: &mut tls, leftover: &mut leftover })?;
    if ty != PACKET_TYPE_PEER_INFO {
        bail!("expected PEER_INFO, got type={ty}");
    }
    let their_pi = cipher.decrypt(&payload).context("decrypt peer info")?;
    if their_pi.len() != PEER_INFO_SIZE {
        bail!("peer info size {} != {PEER_INFO_SIZE}", their_pi.len());
    }
    match their_pi[0] {
        PEER_INFO_TYPE_ADB_DEVICE_GUID => Ok(PairResult { guid: peer_info_string(&their_pi) }),
        t => bail!("unexpected peer info type {t}"),
    }
}

/// Run the pairing **server** (device role) on `listener`; handles exactly
/// one connection. Used for loopback tests and future device-side use.
/// `code` is the pairing code the "device" shows; `our_guid` is the guid we
/// return to the client.
pub fn pair_server_once(
    listener: &TcpListener,
    code: &str,
    keys: &AdbKeys,
    our_guid: &str,
) -> Result<PairServerResult> {
    ensure_provider();
    let (stream, _addr) = listener.accept().context("accept pairing connection")?;
    stream
        .set_read_timeout(Some(Duration::from_secs(60)))
        .and_then(|_| stream.set_write_timeout(Some(Duration::from_secs(60))))
        .context("set timeouts")?;

    let config = server_tls_config(keys)?;
    let conn = rustls::ServerConnection::new(config)?;
    let mut tls = rustls::StreamOwned::new(conn, stream);
    let mut leftover = Vec::new();
    tls_handshake_done(&mut tls, &mut leftover)?;

    let ekme = export_ekme(&mut tls)?;
    let mut password = code.as_bytes().to_vec();
    password.extend_from_slice(&ekme);

    let mut spake2 = Spake2::new_server(&password);

    write_packet(&mut tls, PACKET_TYPE_SPAKE2_MSG, spake2.my_msg())?;
    let (ty, payload) = read_packet(&mut TlsRead { tls: &mut tls, leftover: &mut leftover })?;
    if ty != PACKET_TYPE_SPAKE2_MSG || payload.len() != 32 {
        bail!("expected SPAKE2_MSG, got type={ty} len={}", payload.len());
    }
    let spake2_key = spake2
        .process_msg(payload.as_slice().try_into().unwrap())
        .context("spake2 process")?;

    let mut cipher = PairCipher::new(&spake2_key);
    let pi = make_peer_info(PEER_INFO_TYPE_ADB_DEVICE_GUID, our_guid.as_bytes());
    write_packet(&mut tls, PACKET_TYPE_PEER_INFO, &cipher.encrypt(&pi))?;

    let (ty, payload) = read_packet(&mut TlsRead { tls: &mut tls, leftover: &mut leftover })?;
    if ty != PACKET_TYPE_PEER_INFO {
        bail!("expected PEER_INFO, got type={ty}");
    }
    let their_pi = cipher.decrypt(&payload).context("decrypt peer info")?;
    if their_pi.len() != PEER_INFO_SIZE {
        bail!("peer info size {} != {PEER_INFO_SIZE}", their_pi.len());
    }
    match their_pi[0] {
        PEER_INFO_TYPE_ADB_RSA_PUB_KEY => Ok(PairServerResult {
            client_pub: peer_info_string(&their_pi),
        }),
        t => bail!("unexpected peer info type {t}"),
    }
}

/// Listen on `host:port`, accept one pairing connection, and resolve.
pub fn pair_server_listen(
    host: &str,
    port: u16,
    code: &str,
    keys: &AdbKeys,
    our_guid: &str,
) -> Result<PairServerResult> {
    let listener =
        TcpListener::bind((host, port)).with_context(|| format!("bind {host}:{port}"))?;
    pair_server_once(&listener, code, keys, our_guid)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Loopback pairing: in-process server thread + client over real TCP/TLS.
    #[test]
    fn loopback_pairing() {
        let dir = tempfile::tempdir().unwrap();
        let keys = Arc::new(AdbKeys::load_or_create(dir.path()).unwrap());
        let code = "12345678";
        let guid = "test-guid-0001";

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        let server_keys = Arc::clone(&keys);
        let code_s = code.to_string();
        let guid_s = guid.to_string();
        let server = std::thread::spawn(move || {
            pair_server_once(&listener, &code_s, &server_keys, &guid_s)
        });

        let client = pair_client("127.0.0.1", port, code, &keys)
            .expect("client pairing succeeds");
        let server_res = server.join().expect("server thread").expect("server pairing succeeds");

        assert_eq!(client.guid, guid);
        // The server must have received the client's exact adbkey.pub line.
        assert_eq!(server_res.client_pub, keys.pub_text);
    }

    #[test]
    fn loopback_pairing_wrong_code_fails() {
        let dir = tempfile::tempdir().unwrap();
        let keys = Arc::new(AdbKeys::load_or_create(dir.path()).unwrap());

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        let server_keys = Arc::clone(&keys);
        let server = std::thread::spawn(move || {
            pair_server_once(&listener, "87654321", &server_keys, "g")
        });

        // Different code → different SPAKE2 key → GCM tag mismatch.
        let res = pair_client("127.0.0.1", port, "11112222", &keys);
        assert!(res.is_err(), "pairing must fail on wrong code: {res:?}");
        let _ = server.join();
    }

    #[test]
    fn cipher_roundtrip() {
        let km: [u8; 64] = [3u8; 64];
        let mut a = PairCipher::new(&km);
        let mut b = PairCipher::new(&km);
        let pt = vec![9u8; 100];
        let ct = a.encrypt(&pt);
        assert_eq!(ct.len(), 116); // 100 + 16 tag
        assert_eq!(b.decrypt(&ct).unwrap(), pt);
        let mut c = PairCipher::new(&[4u8; 64]); // wrong key
        assert!(c.decrypt(&ct).is_err()); // tag mismatch
    }
}
