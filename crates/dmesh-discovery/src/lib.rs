//! Local discovery for DMesh.
//!
//! Every platform learns about nearby nodes from the same signed CBOR
//! `announce` record (`dmesh_server::announce`), whatever carried it: UDP6/UDP4
//! multicast, NAN Service Info or Follow-up, ESP-NOW, BLE. This crate holds
//! what is common to all of them:
//!
//! - [`Identity`]: the stable device id and the signature on our announce
//!   ([`P256Identity`] on hosts);
//! - [`Inventory`]: the typed set of discovered [`Device`]s with per-bearer
//!   observations, expiry, and endpoint resolution;
//! - [`Engine`]: sans-IO. It builds our announce, answers directed discovery
//!   requests, validates and records what arrives, and never touches a socket
//!   or a radio;
//! - [`endpoint`]: parsing of explicit UDP endpoints and resolving a node
//!   (`mesh://VIP`, device id, name) to the UDP address to use;
//! - with the `tokio` feature, [`udp::UdpDiscovery`]: the multicast sockets,
//!   the receive loop, solicitation (`discovery.active`) and directed
//!   discovery. This is the one UDP discovery that `lmesh` and Android share.
//!
//! A bearer that is not UDP (the monitor interface, Android's NAN
//! callbacks, firmware) feeds [`Engine::on_datagram`] and sends what the engine
//! gives it; it does not reimplement the protocol.

pub mod endpoint;
mod engine;
mod identity;
pub mod interfaces;
mod inventory;
pub mod nodes;
pub mod persist;
#[cfg(feature = "tokio")]
pub mod udp;

pub use engine::{BEARER_UDP, Carrier, Engine, LocalFacts, NoFacts, Received};
pub use identity::{Identity, IdentityError, P256Identity, UnsignedIdentity};
pub use inventory::{Device, Inventory, NoRoute, NodeKey};
