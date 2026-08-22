//! Direct, bearer-neutral device-session client.
//!
//! `dmesh-cli` is the host-facing shell and library for QUIC-lite sessions
//! over a selected UART, UDP endpoint, or named device profile.  It owns no
//! managed UART forwarding. The direct UART L2 implementation lives here and
//! has no standalone forwarding service or control socket.

pub mod client;
mod device;
mod l2;
mod schema;

pub use client::{
    ClientPathPolicy, DeviceSession, DeviceSessionEvent, run_dmesh_cli, run_dmesh_cli_args,
};
