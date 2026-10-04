//! The host side of `companion.pair` / `companion.unpair`, independent of the
//! bearer: given an established association with a device, verify its signed
//! identity, install fresh credentials with `provision.install`, and save the
//! private owned-device record.
//!
//! Bearers carry no credentials and make no security claim; the device decides
//! whether a request is accepted (a wired UART/USB host may replace a secret, a
//! radio bearer may not). The secret is never logged or returned.

use std::net::Ipv6Addr;
use std::path::Path;

use quic_lite::tokio::TokioAssociation;

use crate::announce::{self, Announce};
use crate::discovery::{OwnedDevice, PairedDevices};
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
    /// Private directory for the owned-device record.
    pub directory: &'a Path,
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
    let secret = random_secret()?;
    let announce = discover(association).await?;
    let identity = signed_identity(&announce)?;
    if let Some(expected) = request.vip6
        && identity.vip6 != expected
    {
        return Err(format!(
            "device is {}, not the expected {expected}",
            identity.vip6
        ));
    }
    let name = request
        .name
        .or_else(|| announce.device_name())
        .filter(|name| !name.is_empty())
        .ok_or("device has no name; supply one with name=")?
        .to_owned();
    let id = fresh_id();
    let mut wire = [0u8; 192];
    let used = provision::encode_install(
        id,
        provision::Install {
            name: &name,
            root_public_key: &request.root_public_key,
            secret: &secret,
        },
        &mut wire,
    )
    .ok_or("name, root key, or secret is not valid for provision.install")?;
    let response = exchange(association, &wire[..used]).await?;
    let record = tagged::decode(&response).ok_or("invalid provision.install response")?;
    if record.id != Some(id) {
        return Err("provision.install response id mismatch".to_owned());
    }
    if record.result != Some(&[0xf5][..]) {
        return Err(
            "device refused provision.install (over BLE a device that already has a secret \
             refuses; a radio bearer also needs the device's pairing window open)"
                .to_owned(),
        );
    }
    let vip6 = identity.vip6.to_string();
    let device = OwnedDevice {
        device_id: hex(announce.device_id()),
        name: Some(name.clone()),
        mac: None,
        public_key: announce.public_key().to_vec(),
        root_public_key: request.root_public_key.to_vec(),
        vip6: Some(vip6.clone()),
        endpoints: [(request.endpoint.0.to_owned(), request.endpoint.1.to_owned())].into(),
        secret: secret.to_vec(),
    };
    // The device has committed. A failed save leaves it paired with no host
    // record; say so, because only a wired pair or unpair recovers it.
    if PairedDevices::load(request.directory, &vip6)?.is_some() {
        PairedDevices::remove(request.directory, &vip6)?;
    }
    PairedDevices::save(request.directory, &device).map_err(|error| {
        format!(
            "device accepted the credentials but the owned record was not saved ({error}); pair it again over a wired link"
        )
    })?;
    Ok(Paired {
        vip6: identity.vip6,
        name,
    })
}

/// Reset the device to unpaired (it forgets the secret, the control-plane root
/// and its BLE bonds; the device only allows this over a wired link) and remove
/// the owned record when one exists.
pub async fn unpair(association: &TokioAssociation, directory: &Path) -> Result<Ipv6Addr, String> {
    let announce = discover(association).await?;
    let identity = signed_identity(&announce)?;
    let id = fresh_id();
    let mut wire = [0u8; 64];
    let used = provision::encode_unpair(id, &mut wire).ok_or("encode provision.unpair")?;
    let response = exchange(association, &wire[..used]).await?;
    let record = tagged::decode(&response).ok_or("invalid provision.unpair response")?;
    if record.id != Some(id) || record.error.is_some() || record.result != Some(&[0xf5][..]) {
        return Err(
            "device refused provision.unpair (only a wired link may reset a device)".to_owned(),
        );
    }
    let vip6 = identity.vip6.to_string();
    if PairedDevices::load(directory, &vip6)?.is_some() {
        PairedDevices::remove(directory, &vip6)?;
    }
    Ok(identity.vip6)
}

struct Identity {
    vip6: Ipv6Addr,
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

async fn discover(association: &TokioAssociation) -> Result<Announce, String> {
    let id = fresh_id();
    let mut wire = [0u8; 64];
    let used = announce::encode_discovery_request(id, &mut wire).ok_or("encode discovery")?;
    let response = exchange(association, &wire[..used]).await?;
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
