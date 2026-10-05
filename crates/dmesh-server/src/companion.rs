//! `companion.pair` and `companion.unpair`: the platform-independent part.
//!
//! Which bearer reaches a companion (a serial port, a BLE L2CAP channel, Android's Bluetooth stack)
//! is the platform's: it implements [`CompanionLink`]. Everything else is here once, for every
//! platform: validating the request, choosing the control-plane root to install, saving the device
//! record, and registering the two methods. Linux registers [`Companions`] with its UART and BLE
//! links; Android registers the same with its own BLE link.

use std::collections::BTreeMap;
use std::net::Ipv6Addr;
use std::sync::Arc;

use async_trait::async_trait;

use crate::device_record::DeviceStore;
use crate::platform_api::{
    CompanionPairRequest, CompanionPairResponse, CompanionUnpairRequest, CompanionUnpairResponse,
};
use crate::registry::{CallContext, Handler, LocalOnly, Registry, methods};
use crate::registry_bridge::TypedHandler;

/// Gateway name of the companion methods.
pub const SERVICE_NAME: &str = "companion";

/// The methods this service implements, with their numbers and names.
pub fn methods() -> Vec<crate::registry::Method> {
    crate::registry_bridge::methods_from_tools(&tools_json())
}

pub fn tools_json() -> serde_json::Value {
    crate::platform_catalog::tools_for("companion.")
}

/// What a link needs to pair one device.
pub struct PairRequest<'a> {
    /// The link-local identifier: the serial path or the BLE address.
    pub id: &'a str,
    /// The signed identity the device must prove; any when absent.
    pub vip6: Option<Ipv6Addr>,
    /// UART line rate.
    pub baud: Option<u32>,
    /// BLE L2CAP PSM.
    pub psm: Option<u16>,
    /// Name to store on the device.
    pub name: Option<&'a str>,
    /// The compressed P-256 control-plane root to install; `None` when this controller has no key
    /// and the request named none.
    pub root_public_key: Option<[u8; 33]>,
    /// Where the device's record is saved.
    pub store: &'a DeviceStore,
}

/// A way to reach companions: attach the link, run the exchange on one association, detach the link
/// again on failure. One per `kind`.
#[async_trait]
pub trait CompanionLink: Send + Sync {
    async fn pair(&self, request: PairRequest<'_>) -> Result<(), String>;
    /// Reset the device to unpaired and drop its record, or release the link.
    async fn unpair(&self, id: &str, store: &DeviceStore) -> Result<(), String>;
}

/// The companion handlers of one node.
pub struct Companions {
    links: BTreeMap<&'static str, Arc<dyn CompanionLink>>,
    /// This controller's own control-plane public key (empty when it has none): the root installed
    /// unless a request names one.
    own_key: Vec<u8>,
    store: DeviceStore,
}

impl Companions {
    pub fn new(own_key: &[u8], store: DeviceStore) -> Self {
        Self { links: BTreeMap::new(), own_key: own_key.to_vec(), store }
    }

    /// Add the link that serves `kind` (`uart`, `ble`).
    pub fn with_link(mut self, kind: &'static str, link: Arc<dyn CompanionLink>) -> Self {
        self.links.insert(kind, link);
        self
    }

    fn link(&self, kind: Option<&str>) -> Result<&Arc<dyn CompanionLink>, String> {
        match kind {
            Some(kind) => self.links.get(kind).ok_or_else(|| format!("unsupported companion kind: {kind}")),
            None => Err("companion request needs kind".to_owned()),
        }
    }

    pub async fn pair(&self, request: &CompanionPairRequest) -> Result<CompanionPairResponse, String> {
        let link = self.link(request.kind.as_deref())?;
        let root_public_key = root_key(request, &self.own_key)?;
        let id = request.id.as_deref().ok_or("companion.pair needs id")?;
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
        .await?;
        Ok(CompanionPairResponse::default())
    }

    pub async fn unpair(&self, request: &CompanionUnpairRequest) -> Result<CompanionUnpairResponse, String> {
        let link = self.link(request.kind.as_deref())?;
        let id = request.id.as_deref().ok_or("companion.unpair needs id")?;
        link.unpair(id, &self.store).await?;
        Ok(CompanionUnpairResponse::default())
    }

    /// Register `companion.pair` and `companion.unpair` in `registry`.
    pub fn register(self: Arc<Self>, registry: &Registry) {
        self.install(registry, false);
    }

    /// Like [`Self::register`], but only the device's own control surface may call them.
    pub fn register_local_only(self: Arc<Self>, registry: &Registry) {
        self.install(registry, true);
    }

    fn install(self: Arc<Self>, registry: &Registry, local_only: bool) {
        fn put(registry: &Registry, method: crate::registry::Method, handler: impl Handler, local_only: bool) -> bool {
            if local_only {
                registry.register(method, LocalOnly(handler))
            } else {
                registry.register(method, handler)
            }
        }
        let pair = self.clone();
        // A restart in the same process registers the same methods again; the first stays.
        put(
            registry,
            methods::COMPANION_PAIR,
            TypedHandler::new(move |request: CompanionPairRequest, _: CallContext| {
                let companions = pair.clone();
                async move { companions.pair(&request).await }
            }),
            local_only,
        );
        put(
            registry,
            methods::COMPANION_UNPAIR,
            TypedHandler::new(move |request: CompanionUnpairRequest, _: CallContext| {
                let companions = self.clone();
                async move { companions.unpair(&request).await }
            }),
            local_only,
        );
    }
}

/// The control-plane root to install: an explicit `root_public_key_b64`, else this controller's own
/// key, else none.
fn root_key(request: &CompanionPairRequest, own: &[u8]) -> Result<Option<[u8; 33]>, String> {
    let bytes = match request.root_public_key_b64.as_deref() {
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

/// Standard or URL-safe base64, padded or not.
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
    impl CompanionLink for Recorder {
        async fn pair(&self, request: PairRequest<'_>) -> Result<(), String> {
            self.pairs.lock().unwrap().push((request.id.to_owned(), request.vip6, request.baud, request.root_public_key.unwrap()));
            Ok(())
        }
        async fn unpair(&self, id: &str, _: &DeviceStore) -> Result<(), String> {
            self.unpairs.lock().unwrap().push(id.to_owned());
            Ok(())
        }
    }

    fn companions(link: &Arc<Recorder>) -> Companions {
        Companions::new(&[3u8; 33], DeviceStore::new(std::env::temp_dir().join("dmesh-companion-test")))
            .with_link("uart", link.clone())
    }

    fn block<T>(future: impl std::future::Future<Output = T>) -> T {
        tokio::runtime::Builder::new_current_thread().build().unwrap().block_on(future)
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
        assert_eq!(root_key(&CompanionPairRequest::default(), &own).unwrap(), Some(own));
        assert_eq!(root_key(&CompanionPairRequest::default(), &[]).unwrap(), None);
        assert!(root_key(&CompanionPairRequest::default(), &[3u8; 32]).is_err());
        assert!(root_key(&CompanionPairRequest::default(), &[4u8; 33]).is_err());
        let explicit = CompanionPairRequest {
            root_public_key_b64: Some("AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIC".to_owned()),
            ..Default::default()
        };
        assert_eq!(root_key(&explicit, &own).unwrap(), Some([2u8; 33]));
    }

    #[test]
    fn a_pair_request_reaches_the_link_of_its_kind_with_the_defaults_filled_in() {
        let link = Arc::new(Recorder::default());
        let companions = companions(&link);
        block(companions.pair(&CompanionPairRequest {
            kind: Some("uart".into()),
            id: Some("/dev/ttyUSB0".into()),
            baud: Some(115200),
            vip6: Some("fc00::1".into()),
            ..Default::default()
        }))
        .unwrap();
        let pairs = link.pairs.lock().unwrap();
        assert_eq!(pairs[0], ("/dev/ttyUSB0".to_owned(), Some("fc00::1".parse().unwrap()), Some(115200), [3u8; 33]));
        block(companions.unpair(&CompanionUnpairRequest { kind: Some("uart".into()), id: Some("p".into()) })).unwrap();
        assert_eq!(link.unpairs.lock().unwrap().as_slice(), ["p"]);
    }

    #[test]
    fn a_missing_or_unknown_kind_and_a_missing_id_are_refused_before_any_link_is_used() {
        let link = Arc::new(Recorder::default());
        let companions = companions(&link);
        let error = |request: CompanionPairRequest| block(companions.pair(&request)).unwrap_err();
        assert!(error(CompanionPairRequest::default()).contains("needs kind"));
        assert!(error(CompanionPairRequest { kind: Some("lora".into()), ..Default::default() }).contains("unsupported"));
        assert!(error(CompanionPairRequest { kind: Some("uart".into()), ..Default::default() }).contains("needs id"));
        assert!(error(CompanionPairRequest { kind: Some("uart".into()), id: Some("x".into()), vip6: Some("nope".into()), ..Default::default() }).contains("vip6"));
        assert!(link.pairs.lock().unwrap().is_empty());
    }
}
