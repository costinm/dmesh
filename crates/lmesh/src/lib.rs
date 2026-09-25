//! BLE-enabled launcher facade over the shared Linux mesh core.
//!
//! Discovery, routing, object transport, and all Wi-Fi/NAN/P2P behavior are
//! implemented by the internal radio crate; this crate retains BLE additions.

pub use lmesh_wifi::mesh_core::api;
pub use lmesh_wifi::mesh_core::*;

/// Linux BLE is an adapter dependency; this crate only exposes it to the
/// integration layer and does not implement the transport.
pub use lmesh_ble_hci as ble;
