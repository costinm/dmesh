//! Compatibility re-export for ESP persistence adapters.
//!
//! The profile definition and CBOR application are host-testable and live in
//! `dmesh-server::firmware_profile`; this module intentionally owns none.
pub use dmesh_server::firmware_profile::TransportProfile;
