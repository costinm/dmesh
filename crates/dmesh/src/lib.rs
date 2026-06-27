//! Creates a mesh environment, allowing execution of on-demand services.
//!
//! The `dmesh` crate provides a unified interface to the ssh-mesh ecosystem.
//! Language-specific wrappers are feature-gated:
//!
//! - `jni-wrapper` — JNI bindings for Java/Android (`mesh_jni` module)
//!
//! The Python wrapper lives in the upstream ssh-mesh checkout.

// Re-export workspace crates
pub use lmesh;
pub use mesh_tun;
pub use pmond;
pub use ssh_mesh;

pub mod mesh_common;

#[cfg(feature = "jni-wrapper")]
pub mod mesh_jni;
