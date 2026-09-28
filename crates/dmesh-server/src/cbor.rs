//! Minimal CBOR used by the object request and manifest protocol.
//!
//! The implementation lives in the portable `mesh-api` crate (no-alloc,
//! `Option`-based, minicbor-compatible method names) so firmware and host
//! share one codec. This module is the in-crate re-export; new DMesh code
//! may also reference `mesh_api::cbor` directly.
pub use mesh_api::cbor::*;
