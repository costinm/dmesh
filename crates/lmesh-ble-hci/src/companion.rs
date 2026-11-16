//! `companion.pair` and `companion.unpair` for `kind=ble`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use dmesh_discovery::controller::{self, ControllerLink, PairRequest};
use dmesh_discovery::device_record::DeviceStore;
use quic_link::{
    AssocConfig, ConnectionId, LinkId, LinkProfile, PeerL2Address, TokioAssocDriver,
};
use quic_mux::{TokioMux, TokioMuxConfig};

use crate::CocBearer;
use crate::coc::{COC_PACKET_MAX, CocChannel};

/// Whole-operation limit after the CoC is connected.
const TIMEOUT: Duration = Duration::from_secs(20);

struct ConnectedBle {
    _mux: TokioMux,
    driver_task: tokio::task::JoinHandle<()>,
    channel: Arc<CocChannel>,
}

impl Drop for ConnectedBle {
    fn drop(&mut self) {
        self.driver_task.abort();
        self.channel.shutdown();
    }
}

/// Linux implementation of the BLE half of the common companion handlers.
///
/// The CoC is driven by `quic-link` (`TokioAssocDriver`) + `quic-mux` (`TokioMux`),
/// and pairing exchanges control records over a mux stream. The link is encrypted
/// (`CocBearer::connect` requires it) and the device refuses a BLE pairing when it
/// already has a secret.
#[derive(Default)]
pub struct BleCompanion {
    connected: Mutex<HashMap<String, ConnectedBle>>,
}

impl BleCompanion {
    pub fn new() -> Self {
        Self::default()
    }

    /// Connect a CoC, drive it with `quic-link`/`quic-mux`, and install fresh credentials.
    async fn pair_device(&self, request: PairRequest<'_>) -> Result<(), String> {
        let address = request.id;
        let key = address.to_ascii_uppercase();
        if self.lock().contains_key(&key) {
            return Err(format!("{address} is already connected"));
        }
        // Connecting is a blocking kernel call that waits for the link.
        let (connect_address, psm) = (address.to_owned(), request.psm);
        let mut bearer = tokio::task::spawn_blocking(move || CocBearer::connect(&connect_address, psm))
            .await
            .map_err(|error| format!("connect task failed: {error}"))?
            .map_err(|error| format!("{error:#}"))?;
        let channel = bearer.channel();

        let peer_cid = ConnectionId::new(1).unwrap();
        let mut driver = TokioAssocDriver::new(AssocConfig::default(), 64);
        let profile = LinkProfile::udp_datagram(1, COC_PACKET_MAX, peer_cid);
        let _ = driver.add_link_with(
            LinkId(1),
            PeerL2Address::new(1).ok_or("peer address")?,
            profile,
            |pool, ingress| {
                bearer.attach(pool, ingress);
                Ok::<_, std::convert::Infallible>(bearer)
            },
        );
        let (tx, rx, driver_task) = driver.spawn();
        let (mux, _acceptor) = TokioMux::spawn(true, TokioMuxConfig::default());
        mux.add_packet_link(tx, rx, COC_PACKET_MAX, 10);

        let outcome = tokio::time::timeout(
            TIMEOUT,
            controller::pair_mux(
                &mux,
                &controller::Pairing {
                    vip6: request.vip6,
                    name: request.name,
                    root_public_key: request
                        .root_public_key
                        .ok_or("this controller has no control-plane root key; name one in root_public_key_b64")?,
                    store: request.store,
                    endpoint: ("ble", address),
                },
            ),
        )
        .await
        .unwrap_or_else(|_| Err(format!("BLE pairing with {address} timed out after {TIMEOUT:?}")));

        match outcome {
            Ok(_) => {
                self.lock().insert(
                    key,
                    ConnectedBle {
                        _mux: mux,
                        driver_task,
                        channel,
                    },
                );
                Ok(())
            }
            Err(error) => {
                drop(mux);
                driver_task.abort();
                channel.shutdown();
                Err(error)
            }
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, ConnectedBle>> {
        self.connected
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

#[async_trait::async_trait]
impl ControllerLink for BleCompanion {
    async fn pair(&self, request: PairRequest<'_>) -> Result<(), String> {
        self.pair_device(request).await
    }

    async fn unpair(&self, id: &str, _store: &DeviceStore) -> Result<(), String> {
        // Firmware permits ownership reset only over a physical wired link.
        // Do not disconnect or erase the record and claim device-side success.
        Err(format!("cannot reset {id} over BLE; use USB/UART to unpair the device"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn companion() -> BleCompanion {
        BleCompanion::new()
    }

    fn local<F: std::future::Future>(future: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(tokio::task::LocalSet::new().run_until(future))
    }

    fn pair_request<'a>(id: &'a str, psm: Option<u16>, store: &'a DeviceStore) -> PairRequest<'a> {
        PairRequest {
            id,
            vip6: None,
            baud: None,
            psm,
            name: None,
            root_public_key: Some([2; 33]),
            store,
        }
    }

    #[test]
    fn a_psm_outside_the_dynamic_range_is_rejected_before_any_radio_use() {
        local(async {
            let store = DeviceStore::new("/nonexistent");
            let error = companion()
                .pair_device(pair_request("AA:BB:CC:DD:EE:FF", Some(0x0001), &store))
                .await
                .unwrap_err();
            assert!(error.contains("PSM"), "{error}");
        });
    }

    #[test]
    fn ble_unpair_does_not_claim_device_reset() {
        local(async {
            let error = companion()
                .unpair("AA:BB:CC:DD:EE:FF", &DeviceStore::new("/nonexistent"))
                .await
                .unwrap_err();
            assert!(error.contains("use USB/UART"));
        });
    }
}
