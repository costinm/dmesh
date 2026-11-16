//! Creates a mesh environment, allowing execution of on-demand services.
//!
//! The `dmesh` crate provides a unified interface to the ssh-mesh ecosystem.
//! Language-specific wrappers are feature-gated:
//!
//! - `jni-wrapper` — JNI bindings for Java/Android (`mesh_jni` module)
//!
//! The Python wrapper lives in the upstream ssh-mesh checkout.

// Re-export reusable upstream crates.
pub use mesh_tun;
pub use ssh_mesh;

pub mod android_api;
pub mod bearer;
pub mod ble_service;
pub mod mesh_common;
pub mod power;
pub mod radio_history;
pub mod transport_service;
pub mod usb_service;
pub mod wifi_service;

#[cfg(feature = "jni-wrapper")]
mod android_nan_protocol;

#[cfg(feature = "jni-wrapper")]
pub mod mesh_jni;
