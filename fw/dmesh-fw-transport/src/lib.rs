#![no_std]
// IMPORTANT: This is the shared no-std ESP firmware layer. If code can be
// host-tested or reused without ESP/FreeRTOS ownership, it belongs in
// `quic-lite` (transport mechanics) or `dmesh-server` (service behavior),
// not here.

//! Portable firmware-side transport policy.
//!
//! The portable surface deliberately contains no bearer API, CBOR service, or
//! server dependency. ESP-only adapters feed complete L2 datagrams into a
//! shared `quic_lite` node; service handlers live above that node. Recovery
//! and Main can therefore use the same ingress rules without inheriting each
//! other's binary surface.

extern crate alloc;

pub mod nvs;
pub mod profile;

// These modules are the shared ESP-IDF runtime.  They are feature-gated so
// profile/schema/queue tests remain ordinary host tests.  Recovery and Main
// both enable this feature; neither depends on the other firmware binary.
pub mod commands;
pub mod crypto_esp;
pub mod flash;
pub mod recovery_runtime;
pub mod state;
pub mod task_esp;
pub mod uart_esp;
// One device-wide pool is also the UART packet handoff. It is available in a
// UART-only Recovery/Main build so a later Wi-Fi bearer does not create a
// second packet budget.
pub mod shared_ingress_esp;
pub mod wifi_esp;
pub mod wifi_espnow_esp;
pub mod wifi_nan_dw_capture_esp;
pub mod wifi_nonpromisc_probe_esp;
pub mod wifi_radio_lab_esp;
pub mod wifi_raw_udp6_esp;

/// The one packet payload limit used by every bearer. A bearer that cannot
/// carry this must reject it at bring-up; it must not fragment at this layer.
pub const TRANSPORT_MTU: usize = quic_lite::DEFAULT_MAX_DATAGRAM_SIZE;
/// Static maximum for a raw bearer connection.  Both Recovery and Main use
/// this same storage ceiling; the negotiated/request-scoped burst may lower
/// active use, but no image gets a silently different transport profile.
pub const RAW_SERVICE_HISTORY_CAPACITY: usize = 8;
pub type RawService =
    dmesh_server::raw_transport::RawService<RAW_SERVICE_HISTORY_CAPACITY, { TRANSPORT_MTU }>;

pub use dmesh_server::firmware_profile::{apply_recovery_packet, ApplyResult};
pub use profile::TransportProfile;
