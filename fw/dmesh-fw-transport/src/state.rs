// IMPORTANT: This is shared no-std ESP firmware code. It contains only the
// firmware task wake primitive; no host-testable transport semantics live
// here.
//! Direct-record dispatcher state, separate from the physical UART bearer.

use core::sync::atomic::{AtomicU32, Ordering};

static DIRECT_RECORD_GENERATION: AtomicU32 = AtomicU32::new(0);

/// An opaque direct record entered the bounded dispatcher queue.
pub(crate) fn direct_record_queued() {
    DIRECT_RECORD_GENERATION.fetch_add(1, Ordering::Release);
}

/// A direct record was accepted by the narrow exception dispatcher. This is
/// deliberately separate from transport ingress and wakes a worker waiting
/// for a subsequent run.
/// Account for a common direct control record accepted by either Recovery or
/// Main.  The wake/generation primitive is firmware-only, but it cannot be
/// Recovery-private because both images dispatch the identical CBOR records.
pub fn direct_record_accepted() {
    direct_record_queued();
}

pub fn direct_record_generation() -> u32 {
    DIRECT_RECORD_GENERATION.load(Ordering::Acquire)
}

pub fn direct_record_generation_changed(observed: u32) -> bool {
    observed != direct_record_generation()
}

#[cfg(test)]
pub(crate) fn direct_record_generation_changed_from(observed: u32, current: u32) -> bool {
    observed != current
}
