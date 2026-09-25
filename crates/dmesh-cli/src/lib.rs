//! Direct, bearer-neutral device-session client.
//!
//! `dmesh-cli` is the host-facing shell and library for QUIC-lite sessions
//! over a selected UART, UDP endpoint, or named device profile.  It owns no
//! managed UART forwarding. Physical UART ownership and diagnostics live in
//! `uart`; there is no standalone forwarding service or control socket.

pub mod client;
mod device;
mod flash;
mod http;
pub mod prober;
mod schema;
pub mod uart;

pub use client::{run_dmesh_cli, run_dmesh_cli_args};
pub use uart::{DeviceSession, DeviceSessionEvent};
