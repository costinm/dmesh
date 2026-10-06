//! The host side of `companion.pair` / `companion.unpair`, independent of the
//! bearer: given an established association with a device, verify its signed
//! identity, install fresh credentials with `provision.install`, and save the
//! device record.
//!
//! Bearers carry no credentials and make no security claim; the device decides
//! whether a request is accepted (a wired UART/USB host may replace a secret, a
//! radio bearer may not). The secret is never logged or returned.

use std::net::Ipv6Addr;

use quic_lite::tokio::TokioAssociation;

use crate::announce::{self, Announce};
use crate::device_record::{DeviceRecord, DeviceStore};
use crate::{provision, tagged};

/// What to pair.
pub struct Pairing<'a> {
    /// The signed device identity the caller expects on this association. When
    /// absent, whatever device answers is paired under its own signed identity.
    pub vip6: Option<Ipv6Addr>,
    /// Name to store on the device; the device's own name when absent.
    pub name: Option<&'a str>,
    /// Compressed P-256 control-plane root to install (33 bytes).
    pub root_public_key: [u8; 33],
    /// Where the device's record is saved.
    pub store: &'a DeviceStore,
    /// Bearer kind and adapter-local id, kept as an endpoint of the record.
    pub endpoint: (&'a str, &'a str),
}

/// A completed pairing, without the secret.
#[derive(Clone, Debug)]
pub struct Paired {
    pub vip6: Ipv6Addr,
    pub name: String,
}

/// Verify the device, install fresh credentials, and save the owned record,
/// replacing an earlier one: the device already decided that this bearer may
/// set the secret.
pub async fn pair(
    association: &TokioAssociation,
    request: &Pairing<'_>,
) -> Result<Paired, String> {
    pair_on(association, request).await
}

// Private test seam: lifecycle simulations exercise the real CBOR exchanges
// without a physical bearer or changing the public client/QUIC API.
trait PairExchange: Sync {
    fn exchange(&self, request: &[u8]) -> impl core::future::Future<Output = Result<Vec<u8>, String>> + Send;
}

impl PairExchange for TokioAssociation {
    async fn exchange(&self, request: &[u8]) -> Result<Vec<u8>, String> {
        exchange(self, request).await
    }
}

async fn pair_on(
    transport: &impl PairExchange,
    request: &Pairing<'_>,
) -> Result<Paired, String> {
    let announce = discover(transport).await?;
    let identity = signed_identity(&announce)?;
    if let Some(expected) = request.vip6
        && identity.vip6 != expected
    {
        return Err(format!(
            "device is {}, not the expected {expected}",
            identity.vip6
        ));
    }
    let device = pairing_record(&announce, identity.vip6, request)?;
    let name = device.name.as_deref().ok_or("device has no name")?;
    let id = fresh_id();
    let mut wire = [0u8; 192];
    let used = provision::encode_install(
        id,
        provision::Install {
            name,
            root_public_key: &request.root_public_key,
            secret: &device.secret,
        },
        &mut wire,
    )
    .ok_or("name, root key, or secret is not valid for provision.install")?;
    let response = transport.exchange(&wire[..used]).await?;
    let record = tagged::decode(&response).ok_or("invalid provision.install response")?;
    if record.id != Some(id) {
        return Err("provision.install response id mismatch".to_owned());
    }
    if record.error.is_some() || record.result != Some(&[0xf5][..]) {
        return Err(
            "device refused provision.install (over BLE a device that already has a secret \
             refuses; a radio bearer also needs the device's pairing window open)"
                .to_owned(),
        );
    }
    // The device committed. If the local commit fails, retain the old record and
    // report the divergence; physical USB takeover/reset remains the repair path.
    request.store.save_paired(&device).map_err(|error| {
        format!(
            "device accepted the credentials but the device record was not saved ({error}); pair it again over a wired link"
        )
    })?;
    Ok(Paired {
        vip6: identity.vip6,
        name: name.to_owned(),
    })
}

/// Reset the device to unpaired (it forgets the secret, the control-plane root
/// and its BLE bonds; the device only allows this over a wired link), then clear
/// credentials/companion membership while keeping discovery/configuration.
pub async fn unpair(association: &TokioAssociation, store: &DeviceStore) -> Result<Ipv6Addr, String> {
    unpair_on(association, store).await
}

async fn unpair_on(transport: &impl PairExchange, store: &DeviceStore) -> Result<Ipv6Addr, String> {
    let announce = discover(transport).await?;
    let identity = signed_identity(&announce)?;
    let id = fresh_id();
    let mut wire = [0u8; 64];
    let used = provision::encode_unpair(id, &mut wire).ok_or("encode provision.unpair")?;
    let response = transport.exchange(&wire[..used]).await?;
    let record = tagged::decode(&response).ok_or("invalid provision.unpair response")?;
    if record.id != Some(id) || record.error.is_some() || record.result != Some(&[0xf5][..]) {
        return Err(
            "device refused provision.unpair (only a wired link may reset a device)".to_owned(),
        );
    }
    let vip6 = identity.vip6.to_string();
    store.clear_pairing(&vip6).map_err(|error| {
        format!("device reset succeeded but local credentials could not be cleared ({error})")
    })?;
    Ok(identity.vip6)
}

struct Identity {
    vip6: Ipv6Addr,
}

/// Prepare a replacement without mutating the store before device acceptance.
/// Reuse the existing secret for the same root; explicit root replacement may
/// rotate it. Persisted operator settings and other attachment hints survive.
fn pairing_record(
    announce: &Announce,
    vip6: Ipv6Addr,
    request: &Pairing<'_>,
) -> Result<DeviceRecord, String> {
    let mut device = request.store.load(&vip6.to_string())?.unwrap_or_default();
    if !device.public_key.is_empty() && device.public_key != announce.public_key() {
        return Err("stored device key does not match signed identity".to_owned());
    }
    let name = request.name
        .or(device.name.as_deref())
        .or_else(|| announce.device_name())
        .filter(|name| !name.is_empty())
        .ok_or("device has no name; supply one with name=")?
        .to_owned();
    if device.secret.len() != 32 || device.root_public_key != request.root_public_key {
        device.secret = random_secret()?.to_vec();
    }
    device.device_id = hex(announce.device_id());
    device.name = Some(name);
    device.public_key = announce.public_key().to_vec();
    device.root_public_key = request.root_public_key.to_vec();
    device.vip6 = Some(vip6.to_string());
    device.companion = true;
    device.endpoints.insert(request.endpoint.0.to_owned(), request.endpoint.1.to_owned());
    Ok(device)
}

/// The device's announce must be signed and self-consistent: pairing a device
/// that cannot prove its key would store a secret under an unproven identity.
fn signed_identity(announce: &Announce) -> Result<Identity, String> {
    if !announce.has_identity() || !announce::verify_identity(*announce) {
        return Err("device did not present a valid signed identity".to_owned());
    }
    if announce.public_key().len() != 33 {
        return Err("device public key is not a compressed P-256 key".to_owned());
    }
    let vip6 = announce::virtual_ip6(announce.public_key())
        .ok_or("device identity has no virtual address")?;
    Ok(Identity {
        vip6: Ipv6Addr::from(vip6),
    })
}

async fn discover(transport: &impl PairExchange) -> Result<Announce, String> {
    let id = fresh_id();
    let mut wire = [0u8; 64];
    let used = announce::encode_discovery_request(id, &mut wire).ok_or("encode discovery")?;
    let response = transport.exchange(&wire[..used]).await?;
    let record = tagged::decode(&response).ok_or("invalid discovery response")?;
    if record.id != Some(id) {
        return Err("discovery response id mismatch".to_owned());
    }
    announce::decode_record(record).ok_or_else(|| "invalid discovery response".to_owned())
}

async fn exchange(association: &TokioAssociation, request: &[u8]) -> Result<Vec<u8>, String> {
    let mut stream = association
        .open_stream()
        .await
        .map_err(|error| format!("open stream: {error:?}"))?;
    crate::stream_client::exchange(&mut stream, &[request])
        .await
        .map_err(|error| format!("stream exchange: {error}"))
}

fn random_secret() -> Result<[u8; 32], String> {
    let mut secret = [0u8; 32];
    let mut filled = 0;
    while filled < secret.len() {
        let count = unsafe {
            libc::getrandom(secret[filled..].as_mut_ptr().cast(), secret.len() - filled, 0)
        };
        if count < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(format!("generate secret: {error}"));
        }
        filled += count as usize;
    }
    Ok(secret)
}

fn fresh_id() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(1)
        | 1
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // This simulator processes exactly the signed discovery and provision CBOR
    // records used by production. No sockets, serial ports or radios are opened.
    struct Device {
        announce: Announce,
        installs: Mutex<Vec<Vec<u8>>>,
        accept: bool,
        lose_reply: bool,
    }

    impl PairExchange for Device {
        async fn exchange(&self, request: &[u8]) -> Result<Vec<u8>, String> {
            let record = tagged::decode(request).ok_or("bad simulated request")?;
            let id = record.id.ok_or("missing request id")?;
            let mut output = [0; 1024];
            let used = if let Some(install) = provision::decode_install(record) {
                if self.accept {
                    self.installs.lock().unwrap().push(install.secret.to_vec());
                }
                if self.lose_reply {
                    return Err("simulated lost install reply".into());
                }
                tagged::encode_numeric_response(provision::COMPONENT, provision::INSTALL,
                    id, if self.accept { &[0xf5] } else { &[0xf4] }, &mut output)
            } else if provision::is_unpair(record) {
                if self.accept {
                    self.installs.lock().unwrap().clear();
                }
                if self.lose_reply {
                    return Err("simulated lost reset reply".into());
                }
                tagged::encode_numeric_response(provision::COMPONENT, provision::UNPAIR,
                    id, if self.accept { &[0xf5] } else { &[0xf4] }, &mut output)
            } else {
                announce::encode_discovery_response(self.announce, id, &mut output)
            }.ok_or("simulated response overflow")?;
            Ok(output[..used].to_vec())
        }
    }

    fn device() -> Device {
        use p256::ecdsa::{Signature, SigningKey, signature::Signer};
        use p256::elliptic_curve::sec1::ToSec1Point;
        use sha2::{Digest, Sha256};
        let key = SigningKey::from(p256::SecretKey::from_slice(&[1; 32]).unwrap());
        let public = key.verifying_key().to_sec1_point(true);
        let digest = Sha256::digest(public.as_bytes());
        let mut id = [0; 16];
        id.copy_from_slice(&digest[..16]);
        let mut announce = Announce::discovery(id, 16, 0);
        assert!(announce.set_device_name("sim-node"));
        assert!(announce.set_public_key(public.as_bytes()));
        let mut bytes = [0; 1024];
        let used = announce::signing_bytes(announce, &mut bytes).unwrap();
        let signature: Signature = key.sign(&bytes[..used]);
        assert!(announce.set_signature(&signature.to_bytes()));
        assert!(announce::verify_identity(announce));
        Device { announce, installs: Mutex::new(Vec::new()), accept: true, lose_reply: false }
    }

    fn request<'a>(store: &'a DeviceStore) -> Pairing<'a> {
        Pairing { vip6: None, name: None, root_public_key: [2; 33],
            store, endpoint: ("simulated", "attachment") }
    }

    #[tokio::test]
    async fn simulator_repeat_pair_preserves_credentials_and_operator_configuration() {
        let directory = tempfile::tempdir().unwrap();
        let store = DeviceStore::new(directory.path());
        let device = device();
        let paired = pair_on(&device, &request(&store)).await.unwrap();
        let mut existing = store.load(&paired.vip6.to_string()).unwrap().unwrap();
        let secret = existing.secret.clone();
        existing.domain = Some("operator.example".into());
        existing.sleepy = true;
        existing.endpoints.insert("other".into(), "configured-address".into());
        store.put(&existing).unwrap();
        pair_on(&device, &request(&store)).await.unwrap();
        let saved = store.load(&paired.vip6.to_string()).unwrap().unwrap();
        assert!(saved.companion);
        assert_eq!(saved.secret, secret);
        assert_eq!(saved.domain, existing.domain);
        assert!(saved.sleepy);
        assert_eq!(saved.endpoints, existing.endpoints);
        assert_eq!(device.installs.lock().unwrap().as_slice(), [secret.clone(), secret]);
    }

    #[tokio::test]
    async fn simulator_refused_or_lost_reply_preserves_the_previous_record() {
        for lose_reply in [false, true] {
            let directory = tempfile::tempdir().unwrap();
            let store = DeviceStore::new(directory.path());
            let mut device = device();
            let paired = pair_on(&device, &request(&store)).await.unwrap();
            let old = store.load(&paired.vip6.to_string()).unwrap().unwrap();
            device.accept = lose_reply;
            device.lose_reply = lose_reply;
            assert!(pair_on(&device, &request(&store)).await.is_err());
            let saved = store.load(&paired.vip6.to_string()).unwrap().unwrap();
            assert_eq!(saved.secret, old.secret);
            assert!(saved.companion);
            assert!(unpair_on(&device, &store).await.is_err());
            assert_eq!(store.load(&paired.vip6.to_string()).unwrap().unwrap().secret, old.secret);
        }
    }

    #[tokio::test]
    async fn simulator_reset_keeps_discovery_record_and_repeated_reset_converges() {
        let directory = tempfile::tempdir().unwrap();
        let store = DeviceStore::new(directory.path());
        let device = device();
        let paired = pair_on(&device, &request(&store)).await.unwrap();
        for _ in 0..2 {
            assert_eq!(unpair_on(&device, &store).await.unwrap(), paired.vip6);
            let saved = store.load(&paired.vip6.to_string()).unwrap().unwrap();
            assert!(!saved.companion);
            assert!(saved.secret.is_empty() && saved.root_public_key.is_empty());
            assert_eq!(saved.public_key, device.announce.public_key());
            assert_eq!(saved.trust.as_deref(), Some("first-seen"));
        }
    }

    #[tokio::test]
    async fn simulator_wrong_identity_is_refused_before_installation() {
        let directory = tempfile::tempdir().unwrap();
        let store = DeviceStore::new(directory.path());
        let device = device();
        let mut request = request(&store);
        request.vip6 = Some("fc00::1234".parse().unwrap());
        assert!(pair_on(&device, &request).await.unwrap_err().contains("not the expected"));
        assert!(device.installs.lock().unwrap().is_empty());
        assert!(store.list().unwrap().is_empty());
    }

    #[test]
    fn secrets_are_random_and_full_length() {
        let (a, b) = (random_secret().unwrap(), random_secret().unwrap());
        assert_ne!(a, b);
        assert!(a.iter().any(|byte| *byte != 0));
    }

    #[test]
    fn an_unsigned_device_cannot_be_paired() {
        let unsigned = Announce::discovery([1; 16], 16, 0);
        assert!(signed_identity(&unsigned).is_err());
    }
}
