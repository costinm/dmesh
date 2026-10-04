//! `companion.pair` and `companion.unpair` for `kind=ble`.

use std::collections::HashMap;
use std::marker::PhantomData;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use dmesh_server::companion_pair;
use dmesh_server::platform_api::{
    CompanionPairRequest, CompanionPairResponse, CompanionUnpairRequest, CompanionUnpairResponse,
};
use quic_lite::packet_pool::PacketPool;
use quic_lite::tokio::TokioNode;
use quic_lite::{BearerId, PacketMeta, PeerL2Address};

use crate::CocBearer;
use crate::coc::CocChannel;

/// Whole-operation limit after the CoC is connected.
const TIMEOUT: Duration = Duration::from_secs(20);

/// Linux implementation of the BLE half of the common companion handlers.
///
/// The CoC is attached to the caller's running QUIC node as an ordinary
/// bearer, and pairing is an ordinary association with the device. The link is
/// encrypted (`CocBearer::connect` requires it) and the device refuses a BLE
/// pairing when it already has a secret. The caller dispatches by `kind`: requests whose kind is `ble` go
/// to [`Self::pair`] and [`Self::unpair`], any other kind to its own bearer.
/// `SLOTS` and `MTU` are the node's packet pool.
pub struct BleCompanion<const SLOTS: usize, const MTU: usize> {
    node: TokioNode,
    connected: Mutex<HashMap<String, (BearerId, Arc<CocChannel>)>>,
    _pool: PhantomData<fn() -> PacketPool<SLOTS, MTU>>,
}

impl<const SLOTS: usize, const MTU: usize> BleCompanion<SLOTS, MTU> {
    pub fn new(node: TokioNode) -> Self {
        Self {
            node,
            connected: Mutex::new(HashMap::new()),
            _pool: PhantomData,
        }
    }

    /// `companion.pair`: connect a CoC, attach it to the node, and install
    /// fresh credentials. The bearer stays attached after a successful pair;
    /// a failed one is detached again.
    pub async fn pair(
        &self,
        request: &CompanionPairRequest,
        root_public_key: [u8; 33],
        directory: &Path,
    ) -> Result<CompanionPairResponse, String> {
        let address = request
            .id
            .as_deref()
            .ok_or("companion.pair kind=ble needs id (the BLE address)")?;
        let vip6 = request
            .vip6
            .as_deref()
            .map(|text| text.parse().map_err(|_| "vip6 is not an IPv6 address".to_owned()))
            .transpose()?;
        let key = address.to_ascii_uppercase();
        if self.lock().contains_key(&key) {
            return Err(format!("{address} is already connected"));
        }
        // Connecting is a blocking kernel call that waits for the link.
        let (connect_address, psm) = (address.to_owned(), request.psm);
        let bearer = tokio::task::spawn_blocking(move || CocBearer::connect(&connect_address, psm))
            .await
            .map_err(|error| format!("connect task failed: {error}"))?
            .map_err(|error| format!("{error:#}"))?;
        let channel = bearer.channel();
        let id = self
            .node
            .add_bearer::<PacketPool<SLOTS, MTU>, { quic_lite::DEFAULT_MAX_PACKET_SIZE }, _>(bearer)
            .await?;
        let outcome = tokio::time::timeout(TIMEOUT, async {
            let association = self
                .node
                .associate(
                    PacketMeta {
                        bearer: id,
                        peer_l2_address: PeerL2Address::new(1).ok_or("peer address")?,
                        received_at_us: 0,
                    },
                    0,
                )
                .await
                .map_err(|error| format!("start association: {error:?}"))?;
            association
                .wait_established()
                .await
                .map_err(|error| format!("establish association: {error:?}"))?;
            let paired = companion_pair::pair(
                &association,
                &companion_pair::Pairing {
                    vip6,
                    name: request.name.as_deref(),
                    root_public_key,
                    directory,
                    endpoint: ("ble", address),
                },
            )
            .await;
            let _ = association.finish().await;
            paired
        })
        .await
        .unwrap_or_else(|_| Err(format!("BLE pairing with {address} timed out after {TIMEOUT:?}")));
        match outcome {
            Ok(_) => {
                self.lock().insert(key, (id, channel));
                Ok(CompanionPairResponse::default())
            }
            Err(error) => {
                self.node.remove_bearer(id).await;
                channel.shutdown();
                Err(error)
            }
        }
    }

    /// `companion.unpair`: release the CoC. Resetting the device and removing
    /// the BlueZ bond are not implemented.
    pub async fn unpair(
        &self,
        request: &CompanionUnpairRequest,
    ) -> Result<CompanionUnpairResponse, String> {
        let address = request
            .id
            .as_deref()
            .ok_or("companion.unpair kind=ble needs id (the BLE address)")?;
        let (id, channel) = self
            .lock()
            .remove(&address.to_ascii_uppercase())
            .ok_or_else(|| format!("{address} is not connected"))?;
        self.node.remove_bearer(id).await;
        channel.shutdown();
        Ok(CompanionUnpairResponse::default())
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, (BearerId, Arc<CocChannel>)>> {
        self.connected
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quic_lite::{QuicNode, tokio::TokioNodeDriver};

    const SLOTS: usize = 4;
    const MTU: usize = quic_lite::DEFAULT_PACKET_POOL_SLOT_SIZE;
    type Pool = PacketPool<SLOTS, MTU>;
    static POOL: Pool = Pool::new();

    fn companion() -> BleCompanion<SLOTS, MTU> {
        let (handle, driver) = TokioNodeDriver::new(
            QuicNode::<Pool>::new(&POOL),
            quic_lite::AssociationLimits::host().connection,
        );
        tokio::task::spawn_local(async move {
            let _ = driver.run().await;
        });
        BleCompanion::new(handle)
    }

    fn local<F: std::future::Future>(future: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(tokio::task::LocalSet::new().run_until(future))
    }

    #[test]
    fn pair_needs_the_address() {
        local(async {
            let companion = companion();
            let directory = Path::new("/nonexistent");
            let error = |request: CompanionPairRequest| {
                let companion = &companion;
                async move { companion.pair(&request, [2; 33], directory).await.unwrap_err() }
            };
            assert!(error(CompanionPairRequest::default()).await.contains("id"));
        });
    }

    #[test]
    fn a_psm_outside_the_dynamic_range_is_rejected_before_any_radio_use() {
        local(async {
            let request = CompanionPairRequest {
                id: Some("AA:BB:CC:DD:EE:FF".to_owned()),
                psm: Some(0x0001),
                ..Default::default()
            };
            let error = companion()
                .pair(&request, [2; 33], Path::new("/nonexistent"))
                .await
                .unwrap_err();
            assert!(error.contains("PSM"), "{error}");
        });
    }

    #[test]
    fn unpair_of_an_unknown_address_is_an_error() {
        local(async {
            let request = CompanionUnpairRequest {
                id: Some("AA:BB:CC:DD:EE:FF".to_owned()),
                ..Default::default()
            };
            assert!(companion().unpair(&request).await.unwrap_err().contains("not connected"));
        });
    }
}
