//! Compatibility export for the protocol-neutral QUIC-lite probe workload.
//!
//! The CBOR request and DMesh service policy remain in this crate. Ordered
//! stream generation and validation belong to QUIC-lite so examples, fake
//! links, host services, and firmware all exercise the same public contract.

pub use quic_lite::probe::{ProbeReceiver, ProbeRun, ProbeSender};
