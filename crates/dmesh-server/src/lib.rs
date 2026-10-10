#![cfg_attr(not(feature = "std"), no_std)]

//! Transport-neutral device services: the tagged-CBOR registry and discovery records. It contains no sockets, UDP, QUIC packet handling,
//! retransmission, or radio code; bearer adapters own socket or radio I/O.

extern crate alloc;

/// Compact boot and periodic presence records shared by UART, UDP, NOW, and
/// NAN Service Discovery.
pub mod announce;
pub mod cbor;
/// Independent-tick validation for platform clock rollback repair.
pub mod clock_guard;
/// Explicit connectionless application-message allowlist and replay support.
pub mod connectionless;
/// Tagged-CBOR control handlers shared by direct records and streams.
pub mod control;
/// Shared receiver-side facts exposed by every platform's discovered-device
/// list. Radio callbacks and retention remain adapter-owned.
pub mod discovery;
#[cfg(feature = "std")]
pub mod device_record;
#[cfg(feature = "std")]
pub mod radio_history;
#[cfg(feature = "std")]
pub mod companion;
/// Shared, bearer- and ESP-independent Recovery/Main bootstrap profile.
pub mod firmware_profile;
/// Common CBOR contract for platform-observed local interfaces and addresses.
/// Adapters report available fields; common routing/discovery consumes it.
pub mod local_networks;
/// Portable state, event, effect, and redacted diagnostic contract for the
/// Main firmware runtime. ESP adapters enqueue these events but do not own the
/// state machine.
pub mod main_runtime_state;
/// Small no-std network-address helpers used by bearer adapters. This module
/// has no socket runtime or ESP-IDF dependency.
pub mod net;
/// Discovery-driven circuit selection and device-local relay reputation.
pub mod path_builder;
/// `log.watch`: one record type and retained history for logs, events and
/// telemetry snapshots.
pub mod log_watch;
/// Common, bearer-independent platform power and memory observation contract.
/// Android, Linux, and ESP adapters report facts; server policy consumes this
/// state without depending on framework callback types.
pub mod power;
/// Privileged host/Android A-to-B probe request and result contract.
pub mod probe;
mod probe_service;
mod probe_stream;
pub mod provision;
/// Bearer-neutral raw-command decoding and handler dispatch. Firmware and
/// hosts supply handlers; neither UART nor Wi-Fi participates in this layer.
pub mod raw_dispatch;
/// CBOR-decoded, socket-free raw 802.11 hardware request schema.
pub mod raw_wifi;
/// The one registration and dispatch path for tagged-CBOR handlers, shared by
/// Linux, Android, and firmware.
pub mod registry;
/// REST-style requests (component 2002): verb, path, headers, body, and the per-verb router.
pub mod http;
/// Handler streams: the header scanner, handler traits and server stream
/// state machine shared by every ingress.
pub mod stream;
/// Bridges between the registry and ssh-mesh `TaggedRecordHandler`s.
#[cfg(feature = "mesh-session")]
pub mod registry_bridge;
/// Predefined common stream services and schemas.  This is deliberately
/// above `quic-lite`: transport provides ordered streams, while this module
/// owns service tags, CBOR/object operations, diagnostics, and log watching.
pub mod services;
/// Bearer-neutral storage behavior for the `settings.*` control component.
pub mod settings;
/// Host-testable STA discovery and association policy.
pub mod sta_selection;
/// Application dispatch over accepted QUIC-lite byte streams.
///
/// This is the replacement boundary for the legacy packet-oriented server:
/// quic-lite owns nodes, associations, packet routing, and bearers, while
/// dmesh-server handlers accept ordinary asynchronous streams.
#[cfg(feature = "std")]
pub mod stream_service;
/// Transport-neutral asynchronous client exchanges.
#[cfg(feature = "std")]
pub mod stream_client;
/// Bounded borrowed tagged-CBOR envelope shared with host mesh control.
pub mod tagged;
/// Portable local discovery status and transport-owned metric views.
pub mod telemetry;
pub mod packet_pool_policy;
/// Common ingress provenance and policy-driven egress selection shared by
/// QUIC-lite, discovery/control adapters, and future relay paths.
pub mod transport_path;
pub mod transport_state;
/// Cross-platform selection of NAN observers for waking a sleepy peer.
pub mod wake;

/// Service adapters used by Linux and Android host integrations.
#[cfg(feature = "std")]
pub mod ble_service;
#[cfg(feature = "std")]
pub mod companion_pair;
/// Typed request/response structs for every `portable` and `android` method,
/// generated from `API.md` (serde plus `mesh::tagged::TaggedFields`).
#[cfg(feature = "std")]
pub mod platform_api;
/// Catalog of the Android platform methods generated from `API.md`.
#[cfg(feature = "std")]
pub mod platform_catalog;
#[cfg(feature = "std")]
pub mod transport_service;
#[cfg(feature = "std")]
pub mod usb_service;
#[cfg(feature = "std")]
pub mod wifi_service;
