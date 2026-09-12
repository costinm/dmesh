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

pub mod profile;
/// Main desired-profile publication. This is separate from the Main applied
/// radio state so bearer ingress cannot mutate a live driver epoch directly.
pub mod profile_store;

// These modules are the shared ESP-IDF runtime.  The crate is built only by
// firmware targets; portable profile/schema/queue tests stay in dmesh-server
// and quic-lite. Main and Recovery select concrete entry points, not Cargo
// product-role features.
pub mod commands;
/// Shared transport engine used by the Main and Recovery policy wrappers.
pub mod core_runtime;
pub mod crypto_esp;
pub mod flash;
/// Main-specific policy entry point. The implementation is intentionally
/// separate from the shared engine so Main can evolve without making the
/// frozen Recovery lane link or execute its policy.
pub mod main_runtime;
/// ESP-IDF PM adapter used only by Main's explicit power policy transitions.
pub mod power_esp;
/// Recovery-specific policy entry point. This remains a thin compatibility
/// shell until Recovery is reduced to open-STA UDP6 flashing.
pub mod recovery_runtime;
/// Main-only bounded DCID forwarding state. Recovery intentionally does not
/// register this handler or accept transit rules.
pub mod relay_main;
pub mod state;
mod stream_handlers;
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
pub mod wifi_radio_control_esp;
pub mod wifi_radio_inject_esp;
pub mod wifi_raw_udp6_esp;

/// The one packet payload limit used by every bearer. A bearer that cannot
/// carry this must reject it at bring-up; it must not fragment at this layer.
pub const TRANSPORT_MTU: usize = quic_lite::DEFAULT_MAX_DATAGRAM_SIZE;
/// Static maximum for one retained association's outstanding packet ledger.
/// The negotiated/request-scoped burst may lower active use, but no image
/// gets a silently different transport profile. Finished sequential streams
/// release this ledger through normal bidirectional ACK traffic.
pub const CONNECTION_HISTORY_CAPACITY: usize = 8;
/// Maximum simultaneously live peer associations in Main.  Each entry owns
/// its own bounded QUIC stream ledger; this is deliberately a firmware memory
/// budget, not a bearer limit. UART, UDP6 and NOW all feed the same table.
/// Concurrent peer budget. One slot costs 312 bytes inline on the host ABI;
/// an admitted peer additionally allocates a 3.8 KiB stream ledger. Twelve
/// peers therefore bound connection state near 50 KiB while leaving embedded
/// heap headroom. When full, zero-stream peers are reclaimed oldest-first;
/// there is deliberately no firmware wall-clock expiry by default.
pub const MAX_QUIC_ASSOCIATIONS: usize = 12;
pub type ConnectionServer =
    dmesh_server::transport::ConnectionServer<CONNECTION_HISTORY_CAPACITY, { TRANSPORT_MTU }>;

pub use profile::TransportProfile;
