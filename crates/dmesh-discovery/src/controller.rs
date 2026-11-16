//! Node control ownership ("who can control this node"): enrolling a node over
//! an attachment link, installing the controller's trusted public key and a
//! generated (or admin-overridden) file-backed secret, and persisting the node
//! record in [`DeviceStore`].
//!
//! Which physical or local bearer reaches the node (a serial port, a BLE L2CAP
//! channel, Android's Bluetooth stack, or another point-to-point link) belongs
//! to the platform adapter via [`ControllerLink`]. Everything else lives here
//! once: validating requests, choosing the trusted controller public key,
//! exchanging signed discovery + `provision.install` / `provision.unpair` over
//! a `quic-mux` multiplexer ([`pair_mux`] / [`unpair_mux`]), and atomically
//! committing the file-backed [`DeviceRecord`]. Secrets remain private to the
//! file store and never appear in discovery views, logs, or responses.

use std::collections::BTreeMap;
use std::net::Ipv6Addr;
use std::sync::Arc;

use async_trait::async_trait;
use mesh_api::envelope as tagged;

use crate::announce::{self, Announce};
use crate::device_record::{DeviceRecord, DeviceStore};
use crate::provision;

/// Wire gateway component name (`companion` = 209).
pub const SERVICE_NAME: &str = "companion";

/// Parameters passed to [`Controllers::pair`].
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct PairInput {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vip6: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub baud: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub psm: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_public_key_b64: Option<String>,
}

/// Parameters passed to [`Controllers::unpair`].
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct UnpairInput {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
}

/// Validated parameters handed to a [`ControllerLink`] to enroll one node.
pub struct PairRequest<'a> {
    /// Link-local identifier (for example serial path or BLE address).
    pub id: &'a str,
    /// Signed identity the node must prove; any valid signed identity when absent.
    pub vip6: Option<Ipv6Addr>,
    /// Optional UART line rate.
    pub baud: Option<u32>,
    /// Optional BLE L2CAP PSM.
    pub psm: Option<u16>,
    /// Optional node name to persist on the target and in its record.
    pub name: Option<&'a str>,
    /// Compressed P-256 controller root public key to install (`None` when
    /// neither this controller nor the request supplied one).
    pub root_public_key: Option<[u8; 33]>,
    /// File-backed node record store.
    pub store: &'a DeviceStore,
}

/// Platform bearer adapter that attaches a node link and runs control enrollment
/// or ownership reset. One implementation per `kind` (`uart`, `ble`, ...).
#[async_trait]
pub trait ControllerLink: Send + Sync {
    async fn pair(&self, request: PairRequest<'_>) -> Result<(), String>;
    /// Confirm target reset and clear local credentials/ownership in `store`.
    /// Disconnecting alone must return an error, not successful unpair.
    async fn unpair(&self, id: &str, store: &DeviceStore) -> Result<(), String>;
}

/// Compatibility alias for [`ControllerLink`].
pub use ControllerLink as CompanionLink;

/// Coordinator for enrolling and resetting controlled nodes across registered
/// [`ControllerLink`] kinds.
pub struct Controllers {
    links: BTreeMap<&'static str, Arc<dyn ControllerLink>>,
    /// Default compressed P-256 controller root public key installed unless a
    /// request overrides `root_public_key_b64` (empty when unset).
    own_key: Vec<u8>,
    store: DeviceStore,
    /// Serialize state-changing enrollment operations so concurrent pair/unpair
    /// calls cannot race target NVS and local file commits.
    operation: tokio::sync::Mutex<()>,
}

/// Compatibility alias for [`Controllers`].
pub type Companions = Controllers;

impl Controllers {
    pub fn new(own_key: &[u8], store: DeviceStore) -> Self {
        Self {
            links: BTreeMap::new(),
            own_key: own_key.to_vec(),
            store,
            operation: tokio::sync::Mutex::new(()),
        }
    }

    /// Register the link adapter that serves `kind` (for example `uart`, `ble`).
    pub fn with_link(mut self, kind: &'static str, link: Arc<dyn ControllerLink>) -> Self {
        self.links.insert(kind, link);
        self
    }

    fn link(&self, kind: Option<&str>) -> Result<&Arc<dyn ControllerLink>, String> {
        match kind {
            Some(kind) => self
                .links
                .get(kind)
                .ok_or_else(|| format!("unsupported controller link kind: {kind}")),
            None => Err("pair/unpair request needs kind".to_owned()),
        }
    }

    pub async fn pair_input(&self, request: &PairInput) -> Result<(), String> {
        let _operation = self.operation.lock().await;
        let link = self.link(request.kind.as_deref())?;
        let root_public_key = root_key(request.root_public_key_b64.as_deref(), &self.own_key)?;
        let id = request.id.as_deref().ok_or("pair request needs id")?;
        let vip6 = request
            .vip6
            .as_deref()
            .map(|text| text.parse().map_err(|_| "vip6 is not an IPv6 address".to_owned()))
            .transpose()?;
        link.pair(PairRequest {
            id,
            vip6,
            baud: request.baud,
            psm: request.psm,
            name: request.name.as_deref(),
            root_public_key,
            store: &self.store,
        })
        .await
    }

    pub async fn unpair_input(&self, request: &UnpairInput) -> Result<(), String> {
        let _operation = self.operation.lock().await;
        let link = self.link(request.kind.as_deref())?;
        let id = request.id.as_deref().ok_or("unpair request needs id")?;
        link.unpair(id, &self.store).await
    }
}

/// Parameters for enrolling a node over an already-established multiplexer.
pub struct Pairing<'a> {
    /// Expected signed VIP6 of the node (`None` accepts whichever signed node answers).
    pub vip6: Option<Ipv6Addr>,
    /// Name to persist on the node (`None` keeps the node's existing name).
    pub name: Option<&'a str>,
    /// Compressed P-256 trusted controller public key to install (33 bytes).
    pub root_public_key: [u8; 33],
    /// File-backed node record store.
    pub store: &'a DeviceStore,
    /// `(kind, adapter_id)` recorded in `endpoints` on the saved [`DeviceRecord`].
    pub endpoint: (&'a str, &'a str),
}

/// Completed enrollment summary (never carries secret bytes).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Paired {
    pub vip6: Ipv6Addr,
    pub name: String,
}

/// Enroll a node over a [`quic_mux::TokioMux`] multiplexer: verify signed
/// discovery, install trusted root key + secret via `provision.install`, and
/// save the private [`DeviceRecord`] file.
pub async fn pair_mux(
    mux: &quic_mux::TokioMux,
    request: &Pairing<'_>,
) -> Result<Paired, String> {
    pair_on(mux, request).await
}

/// Reset a node to unpaired over a [`quic_mux::TokioMux`] multiplexer and clear
/// its local credentials/ownership in `store` once confirmed.
pub async fn unpair_mux(
    mux: &quic_mux::TokioMux,
    store: &DeviceStore,
) -> Result<Ipv6Addr, String> {
    unpair_on(mux, store).await
}

trait PairExchange: Sync {
    fn exchange(
        &self,
        request: &[u8],
    ) -> impl core::future::Future<Output = Result<Vec<u8>, String>> + Send;
}

impl PairExchange for quic_mux::TokioMux {
    async fn exchange(&self, request: &[u8]) -> Result<Vec<u8>, String> {
        let mut stream = self
            .open_bidi()
            .await
            .map_err(|error| format!("open stream: {error}"))?;
        quic_tools::stream_client::exchange(&mut stream, &[request])
            .await
            .map_err(|error| format!("stream exchange: {error}"))
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

async fn unpair_on(
    transport: &impl PairExchange,
    store: &DeviceStore,
) -> Result<Ipv6Addr, String> {
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

struct SignedNodeIdentity {
    vip6: Ipv6Addr,
}

/// Prepare a replacement without mutating the store before target acceptance.
/// If an admin already placed a 32-byte secret in the file for the same root, or
/// a previous enrollment saved one, reuse it; otherwise auto-generate a fresh
/// 32-byte secret.
fn pairing_record(
    announce: &Announce,
    vip6: Ipv6Addr,
    request: &Pairing<'_>,
) -> Result<DeviceRecord, String> {
    let mut device = request.store.load(&vip6.to_string())?.unwrap_or_default();
    if !device.public_key.is_empty() && device.public_key != announce.public_key() {
        return Err("stored device key does not match signed identity".to_owned());
    }
    let name = request
        .name
        .or(device.name.as_deref())
        .or_else(|| announce.device_name())
        .filter(|name| !name.is_empty())
        .ok_or("device has no name; supply one with name=")?
        .to_owned();
    let keep_existing_secret = device.secret.len() == 32
        && (device.root_public_key.is_empty() || device.root_public_key == request.root_public_key);
    if !keep_existing_secret {
        device.secret = random_secret()?.to_vec();
    }
    device.device_id = hex(announce.device_id());
    device.name = Some(name);
    device.public_key = announce.public_key().to_vec();
    device.root_public_key = request.root_public_key.to_vec();
    device.vip6 = Some(vip6.to_string());
    device.companion = true;
    device
        .endpoints
        .insert(request.endpoint.0.to_owned(), request.endpoint.1.to_owned());
    Ok(device)
}

fn signed_identity(announce: &Announce) -> Result<SignedNodeIdentity, String> {
    if !announce.has_identity() || !announce::verify_identity(*announce) {
        return Err("device did not present a valid signed identity".to_owned());
    }
    if announce.public_key().len() != 33 {
        return Err("device public key is not a compressed P-256 key".to_owned());
    }
    let vip6 = announce::virtual_ip6(announce.public_key())
        .ok_or("device identity has no virtual address")?;
    Ok(SignedNodeIdentity {
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

/// Resolve the trusted controller public key to install: an explicit
/// `root_public_key_b64`, else this controller's own key, else `None`.
pub fn root_key(explicit_b64: Option<&str>, own: &[u8]) -> Result<Option<[u8; 33]>, String> {
    let bytes = match explicit_b64 {
        Some(text) => base64_decode(text).ok_or("root_public_key_b64 is not base64")?,
        None if own.is_empty() => return Ok(None),
        None => own.to_vec(),
    };
    let key: [u8; 33] = bytes
        .try_into()
        .map_err(|_| "control-plane root must be a 33-byte compressed P-256 key".to_owned())?;
    if !matches!(key[0], 2 | 3) {
        return Err("control-plane root must be a compressed P-256 key".to_owned());
    }
    Ok(Some(key))
}

fn base64_decode(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() * 3 / 4);
    let (mut bits, mut count) = (0u32, 0u32);
    for byte in text.trim_end_matches('=').bytes() {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            _ => return None,
        };
        bits = bits << 6 | u32::from(value);
        count += 6;
        if count >= 8 {
            count -= 8;
            out.push((bits >> count) as u8);
            bits &= (1 << count) - 1;
        }
    }
    Some(out)
}

fn random_secret() -> Result<[u8; 32], String> {
    let mut secret = [0u8; 32];
    let mut filled = 0;
    while filled < secret.len() {
        let count = unsafe {
            libc::getrandom(
                secret[filled..].as_mut_ptr().cast(),
                secret.len() - filled,
                0,
            )
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

    #[derive(Default)]
    struct Recorder {
        pairs: Mutex<Vec<(String, Option<Ipv6Addr>, Option<u32>, [u8; 33])>>,
        unpairs: Mutex<Vec<String>>,
    }

    #[async_trait]
    impl ControllerLink for Recorder {
        async fn pair(&self, request: PairRequest<'_>) -> Result<(), String> {
            self.pairs.lock().unwrap().push((
                request.id.to_owned(),
                request.vip6,
                request.baud,
                request.root_public_key.unwrap(),
            ));
            Ok(())
        }
        async fn unpair(&self, id: &str, _: &DeviceStore) -> Result<(), String> {
            self.unpairs.lock().unwrap().push(id.to_owned());
            Ok(())
        }
    }

    fn controllers(link: &Arc<Recorder>) -> Controllers {
        Controllers::new(
            &[3u8; 33],
            DeviceStore::new(std::env::temp_dir().join("dmesh-controller-test")),
        )
        .with_link("uart", link.clone())
    }

    fn block<T>(future: impl std::future::Future<Output = T>) -> T {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(future)
    }

    #[test]
    fn base64_accepts_standard_and_url_alphabets_with_or_without_padding() {
        assert_eq!(base64_decode("aGVsbG8=").unwrap(), b"hello");
        assert_eq!(base64_decode("aGVsbG8").unwrap(), b"hello");
        assert_eq!(base64_decode("-_8").unwrap(), base64_decode("+/8=").unwrap());
        assert!(base64_decode("a b").is_none());
    }

    #[test]
    fn the_root_defaults_to_the_controller_key_and_must_be_a_compressed_p256_key() {
        let own = [3u8; 33];
        assert_eq!(root_key(None, &own).unwrap(), Some(own));
        assert_eq!(root_key(None, &[]).unwrap(), None);
        assert!(root_key(None, &[3u8; 32]).is_err());
        assert!(root_key(None, &[4u8; 33]).is_err());
        assert_eq!(
            root_key(Some("AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIC"), &own).unwrap(),
            Some([2u8; 33])
        );
    }

    #[test]
    fn a_pair_request_reaches_the_link_of_its_kind_with_the_defaults_filled_in() {
        let link = Arc::new(Recorder::default());
        let ctl = controllers(&link);
        block(ctl.pair_input(&PairInput {
            kind: Some("uart".into()),
            id: Some("/dev/ttyUSB0".into()),
            baud: Some(115200),
            vip6: Some("fc00::1".into()),
            ..Default::default()
        }))
        .unwrap();
        let pairs = link.pairs.lock().unwrap();
        assert_eq!(
            pairs[0],
            (
                "/dev/ttyUSB0".to_owned(),
                Some("fc00::1".parse().unwrap()),
                Some(115200),
                [3u8; 33]
            )
        );
        block(ctl.unpair_input(&UnpairInput {
            kind: Some("uart".into()),
            id: Some("p".into()),
        }))
        .unwrap();
        assert_eq!(link.unpairs.lock().unwrap().as_slice(), ["p"]);
    }

    #[test]
    fn a_missing_or_unknown_kind_and_a_missing_id_are_refused_before_any_link_is_used() {
        let link = Arc::new(Recorder::default());
        let ctl = controllers(&link);
        let error = |request: PairInput| block(ctl.pair_input(&request)).unwrap_err();
        assert!(error(PairInput::default()).contains("needs kind"));
        assert!(error(PairInput {
            kind: Some("lora".into()),
            ..Default::default()
        })
        .contains("unsupported"));
        assert!(error(PairInput {
            kind: Some("uart".into()),
            ..Default::default()
        })
        .contains("needs id"));
        assert!(error(PairInput {
            kind: Some("uart".into()),
            id: Some("x".into()),
            vip6: Some("nope".into()),
            ..Default::default()
        })
        .contains("vip6"));
        assert!(link.pairs.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn concurrent_pair_and_unpair_are_serialized_by_the_shared_handler() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        #[derive(Default)]
        struct Simulator {
            active: AtomicUsize,
            peak: AtomicUsize,
            calls: AtomicUsize,
        }
        impl Simulator {
            async fn operation(&self) {
                let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
                self.peak.fetch_max(active, Ordering::SeqCst);
                tokio::task::yield_now().await;
                self.calls.fetch_add(1, Ordering::SeqCst);
                self.active.fetch_sub(1, Ordering::SeqCst);
            }
        }
        #[async_trait]
        impl ControllerLink for Simulator {
            async fn pair(&self, _: PairRequest<'_>) -> Result<(), String> {
                self.operation().await;
                Ok(())
            }
            async fn unpair(&self, _: &str, _: &DeviceStore) -> Result<(), String> {
                self.operation().await;
                Ok(())
            }
        }
        let directory = tempfile::tempdir().unwrap();
        let simulator = Arc::new(Simulator::default());
        let ctl = Controllers::new(&[2; 33], DeviceStore::new(directory.path()))
            .with_link("sim", simulator.clone());
        let pair = PairInput {
            kind: Some("sim".into()),
            id: Some("attachment".into()),
            ..Default::default()
        };
        let unpair = UnpairInput {
            kind: Some("sim".into()),
            id: Some("attachment".into()),
        };
        let (a, b, c) = tokio::join!(
            ctl.pair_input(&pair),
            ctl.unpair_input(&unpair),
            ctl.pair_input(&pair)
        );
        a.unwrap();
        b.unwrap();
        c.unwrap();
        assert_eq!(simulator.calls.load(Ordering::SeqCst), 3);
        assert_eq!(simulator.peak.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_link_reset_failure_is_not_reported_as_success() {
        struct RefusingLink;
        #[async_trait]
        impl ControllerLink for RefusingLink {
            async fn pair(&self, _: PairRequest<'_>) -> Result<(), String> {
                Ok(())
            }
            async fn unpair(&self, _: &str, _: &DeviceStore) -> Result<(), String> {
                Err("device reset not confirmed".into())
            }
        }
        let directory = tempfile::tempdir().unwrap();
        let ctl = Controllers::new(&[], DeviceStore::new(directory.path()))
            .with_link("sim", Arc::new(RefusingLink));
        let error = ctl
            .unpair_input(&UnpairInput {
                kind: Some("sim".into()),
                id: Some("attachment".into()),
            })
            .await
            .unwrap_err();
        assert_eq!(error, "device reset not confirmed");
    }

    struct SimDevice {
        announce: Announce,
        installs: Mutex<Vec<Vec<u8>>>,
        accept: bool,
        lose_reply: bool,
    }

    impl PairExchange for SimDevice {
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
                tagged::encode_numeric_response(
                    provision::COMPONENT,
                    provision::INSTALL,
                    id,
                    if self.accept { &[0xf5] } else { &[0xf4] },
                    &mut output,
                )
            } else if provision::is_unpair(record) {
                if self.accept {
                    self.installs.lock().unwrap().clear();
                }
                if self.lose_reply {
                    return Err("simulated lost reset reply".into());
                }
                tagged::encode_numeric_response(
                    provision::COMPONENT,
                    provision::UNPAIR,
                    id,
                    if self.accept { &[0xf5] } else { &[0xf4] },
                    &mut output,
                )
            } else {
                announce::encode_discovery_response(self.announce, id, &mut output)
            }
            .ok_or("simulated response overflow")?;
            Ok(output[..used].to_vec())
        }
    }

    fn sim_device() -> SimDevice {
        use p256::ecdsa::{Signature, SigningKey, signature::Signer};
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
        SimDevice {
            announce,
            installs: Mutex::new(Vec::new()),
            accept: true,
            lose_reply: false,
        }
    }

    fn sim_request<'a>(store: &'a DeviceStore) -> Pairing<'a> {
        Pairing {
            vip6: None,
            name: None,
            root_public_key: [2; 33],
            store,
            endpoint: ("simulated", "attachment"),
        }
    }

    #[tokio::test]
    async fn simulator_repeat_pair_preserves_credentials_and_operator_configuration() {
        let directory = tempfile::tempdir().unwrap();
        let store = DeviceStore::new(directory.path());
        let device = sim_device();
        let paired = pair_on(&device, &sim_request(&store)).await.unwrap();
        let mut existing = store.load(&paired.vip6.to_string()).unwrap().unwrap();
        let secret = existing.secret.clone();
        existing.domain = Some("operator.example".into());
        existing.sleepy = true;
        existing
            .endpoints
            .insert("other".into(), "configured-address".into());
        store.put(&existing).unwrap();
        pair_on(&device, &sim_request(&store)).await.unwrap();
        let saved = store.load(&paired.vip6.to_string()).unwrap().unwrap();
        assert!(saved.companion);
        assert_eq!(saved.secret, secret);
        assert_eq!(saved.domain, existing.domain);
        assert!(saved.sleepy);
        assert_eq!(saved.endpoints, existing.endpoints);
        assert_eq!(
            device.installs.lock().unwrap().as_slice(),
            [secret.clone(), secret]
        );
    }

    #[tokio::test]
    async fn admin_preseeded_secret_in_file_is_installed_without_overwriting() {
        let directory = tempfile::tempdir().unwrap();
        let store = DeviceStore::new(directory.path());
        let device = sim_device();
        let vip6 = Ipv6Addr::from(announce::virtual_ip6(device.announce.public_key()).unwrap());
        let admin_secret = vec![0x42u8; 32];
        store
            .put(&DeviceRecord {
                vip6: Some(vip6.to_string()),
                secret: admin_secret.clone(),
                ..Default::default()
            })
            .unwrap();
        let paired = pair_on(&device, &sim_request(&store)).await.unwrap();
        let saved = store.load(&paired.vip6.to_string()).unwrap().unwrap();
        assert_eq!(saved.secret, admin_secret);
        assert_eq!(device.installs.lock().unwrap().as_slice(), [admin_secret]);
    }

    #[tokio::test]
    async fn simulator_refused_or_lost_reply_preserves_the_previous_record() {
        for lose_reply in [false, true] {
            let directory = tempfile::tempdir().unwrap();
            let store = DeviceStore::new(directory.path());
            let mut device = sim_device();
            let paired = pair_on(&device, &sim_request(&store)).await.unwrap();
            let old = store.load(&paired.vip6.to_string()).unwrap().unwrap();
            device.accept = lose_reply;
            device.lose_reply = lose_reply;
            assert!(pair_on(&device, &sim_request(&store)).await.is_err());
            let saved = store.load(&paired.vip6.to_string()).unwrap().unwrap();
            assert_eq!(saved.secret, old.secret);
            assert!(saved.companion);
            assert!(unpair_on(&device, &store).await.is_err());
            assert_eq!(
                store.load(&paired.vip6.to_string()).unwrap().unwrap().secret,
                old.secret
            );
        }
    }

    #[tokio::test]
    async fn simulator_reset_keeps_discovery_record_and_repeated_reset_converges() {
        let directory = tempfile::tempdir().unwrap();
        let store = DeviceStore::new(directory.path());
        let device = sim_device();
        let paired = pair_on(&device, &sim_request(&store)).await.unwrap();
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
        let device = sim_device();
        let mut request = sim_request(&store);
        request.vip6 = Some("fc00::1234".parse().unwrap());
        assert!(pair_on(&device, &request)
            .await
            .unwrap_err()
            .contains("not the expected"));
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
