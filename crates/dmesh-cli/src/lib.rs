//! Direct, bearer-neutral device-session client.
//!
//! `dmesh-cli` is the host-facing shell and library for QUIC-lite sessions
//! over a selected UART, UDP endpoint, or named device profile.  It owns no
//! managed UART forwarding; `lmesh-uart` remains the reusable UART L2 library.
//! The implementation is temporarily supplied by that L2 crate while the
//! transport/session code is moved out in follow-up cleanup.

pub mod client {
    pub use lmesh_uart::client::{ClientPathPolicy, run_dmesh_cli, run_dmesh_cli_args};
}

pub use client::{run_dmesh_cli, run_dmesh_cli_args};
