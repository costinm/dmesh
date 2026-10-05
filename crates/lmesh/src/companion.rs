//! Linux companion links, wired into the shared companion handlers.
//!
//! The request handling, root-key choice, record saving and registration of `companion.pair` and
//! `companion.unpair` are `dmesh_server::companion`. What is Linux's is how a companion is
//! reached: a serial port (`uart-codec`) and a BLE L2CAP channel (`lmesh-ble-hci`), each attached to
//! the running node as an ordinary bearer.

use std::sync::Arc;

use dmesh_server::companion::Companions;
use dmesh_server::device_record::DeviceStore;
use dmesh_server::registry::Registry;
use lmesh_ble_hci::BleCompanion;
use uart_codec::host_pair::UartCompanion;

const POOL_SLOTS: usize = crate::HOST_POOL_SLOTS;
const POOL_SLOT_SIZE: usize = quic_lite::DEFAULT_PACKET_POOL_SLOT_SIZE;

/// The device records of this node (lmesh's `DMESH_PAIRED_DEVICES_DIR`, by default).
pub(crate) fn device_store() -> DeviceStore {
    DeviceStore::from_env(Some(std::path::Path::new("/home/system/etc/lmesh/paired")))
}

/// Register the companion methods; `own_key` is the control-plane root a pairing installs by default.
/// `startup_uart` is a serial port the daemon already attached, which a pairing then reuses.
pub fn register(
    registry: &Registry,
    node: &quic_lite::tokio::TokioNode,
    own_key: &[u8],
    startup_uart: Option<(String, quic_lite::BearerId)>,
) {
    let uart: Arc<UartCompanion<POOL_SLOTS, POOL_SLOT_SIZE>> = Arc::new(UartCompanion::new(node.clone()));
    if let Some((path, bearer)) = startup_uart {
        uart.adopt(&path, bearer);
    }
    let ble: Arc<BleCompanion<POOL_SLOTS, POOL_SLOT_SIZE>> = Arc::new(BleCompanion::new(node.clone()));
    Arc::new(
        Companions::new(own_key, device_store())
            .with_link("uart", uart)
            .with_link("ble", ble),
    )
    .register(registry);
}
