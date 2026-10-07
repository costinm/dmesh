#![cfg_attr(not(feature = "std"), no_std)]

//! Transport-neutral device services: the tagged-CBOR registry, discovery records, and the
//! `object.flash` image push. It contains no sockets, UDP, QUIC packet handling,
//! retransmission, or radio code; bearer adapters own socket or radio I/O.

extern crate alloc;

/// Compact boot and periodic presence records shared by UART, UDP, NOW, and
/// NAN Service Discovery.
pub mod announce;
pub mod cbor;
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

#[cfg(feature = "std")]
mod host {
    use anyhow::{Result, bail};
    use std::path::{Path, PathBuf};

    pub use crate::object_transfer::{ObjectId, REQUEST_MAX};

    #[derive(Debug, Clone)]
    pub struct ServerConfig {
        pub artifact_root: PathBuf,
        pub archive_root: Option<PathBuf>,
    }

    impl Default for ServerConfig {
        fn default() -> Self {
            Self {
                artifact_root: PathBuf::from("target/flash"),
                archive_root: None,
            }
        }
    }

    fn target_file(root: &Path, request: ObjectId<'_>) -> Result<PathBuf> {
        let chip = match request.cpu {
            9 => "esp32s3",
            13 => "esp32c6",
            _ => "esp32",
        };
        let file = match request.target {
            6 => root.join(chip).join("main-app.bin"),
            3 => root.join(chip).join("recovery.bin"),
            // Target 2 is the bounded pre-partition-table Stage2 boot region,
            // not the partition table itself. Partition-layout changes remain
            // a provisioning operation because one object stream cannot
            // atomically replace both boot code and the table it interprets.
            2 => root.join(chip).join("stage2.bin"),
            7 => {
                let name = request
                    .name
                    .ok_or_else(|| anyhow::anyhow!("object name missing"))?;
                if !name
                    .iter()
                    .all(|b| b.is_ascii_alphanumeric() || *b == b'_' || *b == b'-')
                {
                    bail!("invalid object name");
                }
                let name = String::from_utf8_lossy(name);
                let module_root = root.join("modules").join(chip);
                let path = module_root.join(format!("mod_{name}.dmod"));
                if path.is_file() {
                    path
                } else {
                    module_root.join(format!("{name}.dmod"))
                }
            }
            _ => bail!("unsupported target"),
        };
        if file.is_file() {
            Ok(file)
        } else {
            bail!("artifact not found: {}", file.display())
        }
    }

    #[derive(Clone)]
    pub struct ObjectServer {
        pub config: ServerConfig,
    }

    impl ObjectServer {
        pub fn new(config: ServerConfig) -> Self {
            Self { config }
        }

        /// The catalog file for an object: the artifact of its CPU family and target.
        pub fn object_path(&self, request: ObjectId<'_>) -> Result<PathBuf> {
            target_file(&self.config.artifact_root, request)
        }

        /// Read an object's bytes: the request body of `POST /flash`. Its length is the `len`
        /// header the sender declares.
        pub fn read_object(&self, request: ObjectId<'_>) -> Result<(Vec<u8>, PathBuf)> {
            let source = self.object_path(request)?;
            let image = Self::read_file(&source)?;
            Ok((image, source))
        }

        /// Read an explicitly selected file with the same checks as a catalog artifact.
        pub fn read_file(source: &Path) -> Result<Vec<u8>> {
            if !source.is_file() {
                bail!("artifact not found: {}", source.display());
            }
            let image = std::fs::read(source)?;
            if image.is_empty() || image.len() > u32::MAX as usize {
                bail!("object size out of range: {}", source.display());
            }
            Ok(image)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use tempfile::tempdir;

        #[test]
        fn a_catalog_object_is_the_exact_file_selected_by_cpu_and_target() {
            let directory = tempdir().unwrap();
            let artifact_root = directory.path().join("flash");
            let artifact = artifact_root.join("esp32c6/main-app.bin");
            std::fs::create_dir_all(artifact.parent().unwrap()).unwrap();
            let bytes: Vec<u8> = (0..5000).map(|value| (value % 251) as u8).collect();
            std::fs::write(&artifact, &bytes).unwrap();

            let server = ObjectServer::new(ServerConfig { artifact_root, ..ServerConfig::default() });
            let (body, path) = server
                .read_object(ObjectId { name: None, cpu: 13, target: 6 })
                .unwrap();
            assert_eq!(body, bytes);
            assert_eq!(path, artifact);
            assert!(ObjectServer::read_file(&directory.path().join("missing")).is_err());
        }

        #[test]
        fn object_catalog_keeps_stage2_and_modules_cpu_qualified() {
            let directory = tempdir().unwrap();
            let root = directory.path();
            let stage = root.join("esp32c6/stage2.bin");
            let module = root.join("modules/esp32c6/mod_lora.dmod");
            std::fs::create_dir_all(stage.parent().unwrap()).unwrap();
            std::fs::create_dir_all(module.parent().unwrap()).unwrap();
            std::fs::write(&stage, b"stage").unwrap();
            std::fs::write(&module, b"module").unwrap();

            assert_eq!(
                target_file(
                    root,
                    ObjectId {
                        name: None,
                        cpu: 13,
                        target: 2,
                    },
                )
                .unwrap(),
                stage
            );
            assert_eq!(
                target_file(
                    root,
                    ObjectId {
                        name: Some(b"lora"),
                        cpu: 13,
                        target: 7,
                    },
                )
                .unwrap(),
                module
            );
        }
    }
}

#[cfg(feature = "std")]
pub use host::*;

/// `object.flash` (`POST /flash`): request headers, the image body, and the sink writer. Flash
/// supplies only its durable partition sink; QUIC-lite and generic transport do not depend on this
/// module.
pub mod object_transfer {
    include!("object_transfer.rs");
}

#[cfg(not(feature = "std"))]
pub use object_transfer::*;
