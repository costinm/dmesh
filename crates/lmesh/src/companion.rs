//! Linux `companion.pair` / `companion.unpair`, dispatched by `kind`.
//!
//! `ble` is implemented by `lmesh-ble-hci` and `uart` by `uart-codec`; any
//! other kind is refused. Both attach their bearer to the running node.

use std::path::PathBuf;
use std::sync::Arc;

use dmesh_server::platform_api::{
    CompanionPairRequest, CompanionPairResponse, CompanionUnpairRequest, CompanionUnpairResponse,
};
use dmesh_server::registry::{CallContext, Registry, methods};
use dmesh_server::registry_bridge::TypedHandler;
use lmesh_ble_hci::BleCompanion;
use uart_codec::host_pair::{Pairing, UartCompanion};

fn unsupported(kind: Option<&str>) -> String {
    match kind {
        Some("ble" | "uart") => unreachable!("dispatched"),
        Some(kind) => format!("unsupported companion kind: {kind}"),
        None => "companion request needs kind".to_owned(),
    }
}

/// Directory of private owned-device records.
fn paired_directory() -> PathBuf {
    std::env::var_os("DMESH_PAIRED_DEVICES_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/home/system/etc/lmesh/paired"))
}

/// The control-plane root to install: an explicit `root_public_key_b64`, else
/// this controller's own key.
fn root_key(request: &CompanionPairRequest, own: &[u8]) -> Result<[u8; 33], String> {
    let bytes = match request.root_public_key_b64.as_deref() {
        Some(text) => base64_decode(text).ok_or("root_public_key_b64 is not base64")?,
        None => own.to_vec(),
    };
    let key: [u8; 33] = bytes
        .try_into()
        .map_err(|_| "control-plane root must be a 33-byte compressed P-256 key".to_owned())?;
    if !matches!(key[0], 2 | 3) {
        return Err("control-plane root must be a compressed P-256 key".to_owned());
    }
    Ok(key)
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

/// `id` and the optional expected `vip6` of a pairing request.
fn target(request: &CompanionPairRequest) -> Result<(&str, Option<std::net::Ipv6Addr>), String> {
    let id = request.id.as_deref().ok_or("companion.pair needs id")?;
    let vip6 = request
        .vip6
        .as_deref()
        .map(|text| text.parse().map_err(|_| "vip6 is not an IPv6 address".to_owned()))
        .transpose()?;
    Ok((id, vip6))
}

const POOL_SLOTS: usize = crate::HOST_POOL_SLOTS;
const POOL_SLOT_SIZE: usize = quic_lite::DEFAULT_PACKET_POOL_SLOT_SIZE;
type Ble = BleCompanion<POOL_SLOTS, POOL_SLOT_SIZE>;
type Uart = UartCompanion<POOL_SLOTS, POOL_SLOT_SIZE>;

/// Register both methods against the running node; `own_key` is the default
/// control-plane root a pairing installs. Both bearers attach to `node` as
/// ordinary bearers and pair over an ordinary association. `startup_uart` is a
/// serial port the daemon already attached, which a pairing then reuses.
pub fn register(
    registry: &Registry,
    node: &quic_lite::tokio::TokioNode,
    own_key: &[u8],
    startup_uart: Option<(String, quic_lite::BearerId)>,
) {
    let own_key: Arc<[u8]> = own_key.into();
    let uart: Arc<Uart> = Arc::new(UartCompanion::new(node.clone()));
    if let Some((path, bearer)) = startup_uart {
        uart.adopt(&path, bearer);
    }
    let ble: Arc<Ble> = Arc::new(BleCompanion::new(node.clone()));
    let (pair_uart, pair_ble) = (uart.clone(), ble.clone());
    assert!(
        registry.register(
            methods::COMPANION_PAIR,
            TypedHandler::new(move |request: CompanionPairRequest, _: CallContext| {
                let (uart, ble, own_key) = (pair_uart.clone(), pair_ble.clone(), own_key.clone());
                async move {
                    let root_public_key = root_key(&request, &own_key)?;
                    let directory = paired_directory();
                    match request.kind.as_deref() {
                        Some("ble") => ble.pair(&request, root_public_key, &directory).await,
                        Some("uart") => {
                            let (path, vip6) = target(&request)?;
                            uart.pair(Pairing {
                                path,
                                baud: request.baud,
                                vip6,
                                name: request.name.as_deref(),
                                root_public_key,
                                directory: &directory,
                            })
                            .await
                            .map(|_| CompanionPairResponse::default())
                        }
                        kind => Err(unsupported(kind)),
                    }
                }
            }),
        ),
        "companion.pair registered twice"
    );
    assert!(
        registry.register(
            methods::COMPANION_UNPAIR,
            TypedHandler::new(move |request: CompanionUnpairRequest, _: CallContext| {
                let (uart, ble) = (uart.clone(), ble.clone());
                async move {
                    match request.kind.as_deref() {
                        Some("ble") => ble.unpair(&request).await,
                        Some("uart") => {
                            let path = request
                                .id
                                .as_deref()
                                .ok_or("companion.unpair kind=uart needs id (the serial path)")?;
                            uart.unpair(path, None, &paired_directory())
                                .await
                                .map(|_| CompanionUnpairResponse::default())
                        }
                        kind => Err(unsupported(kind)),
                    }
                }
            }),
        ),
        "companion.unpair registered twice"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(root_key(&CompanionPairRequest::default(), &own).unwrap(), own);
        assert!(root_key(&CompanionPairRequest::default(), &[3u8; 32]).is_err());
        assert!(root_key(&CompanionPairRequest::default(), &[4u8; 33]).is_err());
        let explicit = CompanionPairRequest {
            root_public_key_b64: Some("AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIC".to_owned()),
            ..Default::default()
        };
        assert_eq!(root_key(&explicit, &own).unwrap(), [2u8; 33]);
    }

    #[test]
    fn kinds_other_than_ble_and_uart_are_refused() {
        assert!(unsupported(Some("wifi")).contains("unsupported"));
        assert!(unsupported(Some("lora")).contains("unsupported"));
        assert!(unsupported(None).contains("needs kind"));
    }
}
