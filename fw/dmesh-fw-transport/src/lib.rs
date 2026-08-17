#![no_std]
// IMPORTANT: This is the shared no-std ESP firmware layer. If code can be
// host-tested or reused without ESP/FreeRTOS ownership, it belongs in
// `quic-lite` (transport mechanics) or `dmesh-server` (service behavior),
// not here.

//! Portable firmware-side transport policy.
//!
//! This crate deliberately contains no ESP-IDF, socket, CBOR, server, or
//! FreeRTOS dependency. Platform adapters feed complete L2 datagrams into a
//! shared `quic_lite` node; service handlers live above that node. Recovery
//! and Main can therefore use the same ingress rules without inheriting each
//! other's binary surface.

extern crate alloc;

pub mod command;
pub mod profile;
pub mod queue;
pub mod settings;
pub mod uart;

// These modules are the shared ESP-IDF runtime.  They are feature-gated so
// profile/schema/queue tests remain ordinary host tests.  Recovery and Main
// both enable this feature; neither depends on the other firmware binary.
#[cfg(feature = "esp-idf")]
pub mod command_esp;
#[cfg(feature = "esp-idf")]
pub mod commands;
#[cfg(feature = "esp-idf")]
pub mod crypto_esp;
#[cfg(feature = "esp-idf")]
pub mod esp_nvs;
#[cfg(feature = "esp-idf")]
pub mod flash;
#[cfg(feature = "esp-idf")]
pub mod recovery_runtime;
#[cfg(feature = "esp-idf")]
pub mod state;
#[cfg(feature = "esp-idf")]
pub mod uart_esp;
#[cfg(feature = "esp-idf")]
pub mod wifi_esp;

/// The one packet payload limit used by every bearer. A bearer that cannot
/// carry this must reject it at bring-up; it must not fragment at this layer.
pub const TRANSPORT_MTU: usize = quic_lite::DEFAULT_MAX_DATAGRAM_SIZE;

pub use command::{apply_recovery_packet, ApplyResult};
pub use profile::TransportProfile;
pub use queue::{queue_disposition, QueueDisposition};
pub use settings::{load_profile, persist_profile, TransportSettings, NVS_NAMESPACE};
pub use uart::{
    classify_ppp_payload, encode_uart_transport_payload, PppIngress, PppIngressError,
    UART_TRANSPORT_MARKER,
};
