//! Linux companion links, wired into [`dmesh_discovery::controller::Controllers`].
//!
//! All enrollment logic, root-key choice, `provision` wire exchange, and record saving live in
//! [`dmesh_discovery::controller`]. What is Linux's is how a companion is reached: a serial port
//! (`uart-codec`) and a BLE L2CAP channel (`lmesh-ble-hci`), each attached to the running node as
//! an ordinary bearer.

use std::sync::Arc;

use dmesh_discovery::controller::{Controllers, PairInput, UnpairInput};
use dmesh_discovery::device_record::DeviceStore;
use lmesh_ble_hci::BleCompanion;
use lmesh_wifi::rpc_router::{
    CallContext, CompanionPairRequest, CompanionPairResponse, CompanionUnpairRequest,
    CompanionUnpairResponse, LocalOnly, Registry, TypedHandler, methods,
};
use uart_codec::host_pair::UartCompanion;

/// The device records of this node (lmesh's `DMESH_PAIRED_DEVICES_DIR`, by default).
pub(crate) fn device_store() -> DeviceStore {
    DeviceStore::from_env(Some(std::path::Path::new("/home/system/etc/lmesh/paired")))
}

/// Register the controller enrollment methods (`companion.pair` / `companion.unpair`) as
/// local-only control methods; `own_key` is the control-plane root key installed by default.
pub fn register(registry: &Registry, own_key: &[u8]) {
    let uart = Arc::new(UartCompanion::new());
    let ble = Arc::new(BleCompanion::new());
    let controllers = Arc::new(
        Controllers::new(own_key, device_store())
            .with_link("uart", uart)
            .with_link("ble", ble),
    );

    let pair = controllers.clone();
    assert!(
        registry.register(
            methods::COMPANION_PAIR,
            LocalOnly(TypedHandler::new(
                move |request: CompanionPairRequest, _: CallContext| {
                    let controllers = pair.clone();
                    async move {
                        controllers
                            .pair_input(&PairInput {
                                kind: request.kind,
                                id: request.id,
                                vip6: request.vip6,
                                baud: request.baud,
                                psm: request.psm,
                                name: request.name,
                                root_public_key_b64: request.root_public_key_b64,
                            })
                            .await
                            .map(|()| CompanionPairResponse)
                    }
                },
            )),
        ),
        "companion.pair registered twice"
    );

    assert!(
        registry.register(
            methods::COMPANION_UNPAIR,
            LocalOnly(TypedHandler::new(
                move |request: CompanionUnpairRequest, _: CallContext| {
                    let controllers = controllers.clone();
                    async move {
                        controllers
                            .unpair_input(&UnpairInput {
                                kind: request.kind,
                                id: request.id,
                            })
                            .await
                            .map(|()| CompanionUnpairResponse)
                    }
                },
            )),
        ),
        "companion.unpair registered twice"
    );
}
