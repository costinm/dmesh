//! BLE-enabled launcher facade over the shared Linux mesh core.
//!
//! Discovery, routing, object transport, and all Wi-Fi/NAN/P2P behavior are
//! implemented by `lmesh-wifi`; this crate retains BLE-only additions.

pub use lmesh_wifi::mesh_core::api;
pub use lmesh_wifi::mesh_core::*;

/// The only permanent lmesh-specific extension: optional Linux BLE HCI.
pub mod ble;
