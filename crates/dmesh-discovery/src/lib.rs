#![cfg_attr(not(feature = "std"), no_std)]

//! Local discovery for DMesh.
//!
//! Every platform learns about nearby nodes from the same signed CBOR
//! `announce` record ([`announce`]), whatever carried it: UDP6/UDP4
//! multicast, NAN Service Info or Follow-up, ESP-NOW, BLE. This crate holds
//! what is common to all of them:
//!
//! - [`announce`], [`discovery`], [`discovery_nodes`], [`local_networks`],
//!   [`net`], and [`wake`]: `#![no_std]` codecs, observation facts, and NAN
//!   wake planning shared across firmware, Android, and Linux;
//! - with the `std` feature (enabled by default):
//!   - [`device_record`]: persisted `DeviceRecord` and `DeviceStore` TOML files;
//!   - [`Identity`]: the stable device id and the signature on our announce
//!     ([`P256Identity`] on hosts);
//!   - [`Inventory`]: the typed set of discovered [`Device`]s with per-bearer
//!     observations, expiry, and endpoint resolution;
//!   - [`Engine`]: sans-IO. It builds our announce, answers directed discovery
//!     requests, validates and records what arrives, and never touches a socket
//!     or a radio;
//!   - [`endpoint`]: parsing of explicit UDP endpoints and resolving a node
//!     (`mesh://VIP`, device id, name) to the UDP address to use;
//! - with the `tokio` feature, [`udp::UdpDiscovery`]: the multicast sockets,
//!   the receive loop, solicitation (`discovery.active`) and directed
//!   discovery. This is the one UDP discovery that `lmesh` and Android share.
//!
//! A bearer that is not UDP (the monitor interface, Android's NAN
//! callbacks, firmware) feeds [`Engine::on_datagram`] and sends what the engine
//! gives it; it does not reimplement the protocol.

extern crate alloc;

/// Compact boot and periodic presence records shared by UART, UDP, NOW, and
/// NAN Service Discovery.
pub mod announce;
/// Explicit connectionless application-message allowlist and replay support.
pub mod connectionless;
/// Tagged-CBOR control handlers shared by direct records and streams.
pub mod control;
/// Shared receiver-side facts exposed by every platform's discovered-device
/// list. Radio callbacks and retention remain adapter-owned.
pub mod discovery;
pub mod discovery_nodes;
/// Shared, bearer- and ESP-independent Recovery/Main bootstrap profile.
pub mod firmware_profile;
/// Common CBOR contract for platform-observed local interfaces and addresses.
pub mod local_networks;
/// Small no-std network-address helpers used by bearer adapters.
pub mod net;
/// Private node control provisioning wire records (`210.1` `install`, `210.2` `unpair`).
pub mod provision;
/// The DMesh transport profile, its codec and store, and the mapping to the module ABI's `wifi` component.
pub mod transport_profile;
/// Cross-platform selection of NAN observers for waking a sleepy peer.
pub mod wake;

#[cfg(feature = "tokio")]
pub mod controller;
#[cfg(feature = "tokio")]
pub use controller as companion;
#[cfg(feature = "std")]
pub mod device_record;
#[cfg(feature = "std")]
pub mod endpoint;
#[cfg(feature = "std")]
mod engine;
#[cfg(feature = "std")]
mod identity;
#[cfg(feature = "std")]
pub mod interfaces;
#[cfg(feature = "std")]
mod inventory;
#[cfg(feature = "std")]
pub mod nodes;
#[cfg(feature = "std")]
pub mod persist;
#[cfg(feature = "tokio")]
pub mod udp;

pub const DEFAULT_EVENT_PORT: u16 = 3336;

/// Physical RAM reported by `/proc/meminfo` (`MemTotal:`) on Linux and Android.
#[cfg(feature = "std")]
pub fn host_total_ram_bytes() -> Option<u64> {
    let info = std::fs::read_to_string("/proc/meminfo").ok()?;
    info.lines().find_map(|line| {
        let mut words = line.split_whitespace();
        (words.next()? == "MemTotal:").then_some(())?;
        let kib = words.next()?.parse::<u64>().ok()?;
        (words.next()? == "kB").then_some(())?;
        kib.checked_mul(1024)
    })
}

/// Resident set size of the current process (`VmRSS:`) from `/proc/self/status`
/// on Linux and Android.
#[cfg(feature = "std")]
pub fn process_rss_bytes() -> Result<u64, std::string::String> {
    let status = std::fs::read_to_string("/proc/self/status")
        .map_err(|error| alloc::string::ToString::to_string(&error))?;
    status
        .lines()
        .find_map(|line| line.strip_prefix("VmRSS:"))
        .and_then(|rest| rest.trim().strip_suffix("kB"))
        .and_then(|kilobytes| kilobytes.trim().parse::<u64>().ok())
        .map(|kilobytes| kilobytes.saturating_mul(1024))
        .ok_or_else(|| alloc::string::String::from("no VmRSS in /proc/self/status"))
}

#[cfg(feature = "std")]
pub use engine::{BEARER_UDP, Carrier, Engine, LocalFacts, NoFacts, Received};
#[cfg(feature = "std")]
pub use identity::{Identity, IdentityError, P256Identity, UnsignedIdentity};
#[cfg(feature = "std")]
pub use inventory::{Device, ESP_UDP_PORT, Inventory, NoRoute, NodeKey};
