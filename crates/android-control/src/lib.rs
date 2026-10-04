//! android-control: ADB control-plane logic for DMesh.
//!
//! Holds all ADB protocol logic in Rust:
//! - `keys` — RSA-2048 `adbkey` load/generate, native `.pub` encoding, x509
//!   self-signed cert, paired-device (known-hosts) store.
//! - `spake2` — BoringSSL curve25519 SPAKE2 (the ADB wireless-pairing variant).
//! - `pairing` — Android 11+ wireless pairing handshake (TLS + SPAKE2 +
//!   AES-128-GCM PeerInfo), client and server roles.
//! - `adb` — device connection layer built on `adb_client` (connect/shell/exec).
//! - `discovery` — host mDNS browse for `_adb-tls-pairing._tcp` /
//!   `_adb-tls-connect._tcp`.
//! - `jni` (feature `jni-wrapper`) — thin message-oriented JNI surface for the
//!   `app-control` Android adapter.

pub mod adb;
pub mod discovery;
pub mod keys;
pub mod pairing;
pub mod spake2;

#[cfg(feature = "jni-wrapper")]
pub mod jni;
