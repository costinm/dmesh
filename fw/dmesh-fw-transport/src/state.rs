// IMPORTANT: This is shared no-std ESP firmware code. It contains only the
// firmware task wake primitive; no host-testable transport semantics live
// here.
//! Command-owner state, separate from the physical UART bearer.

use core::sync::atomic::{AtomicU32, Ordering};

static COMMAND_GENERATION: AtomicU32 = AtomicU32::new(0);

/// An opaque direct record entered the bounded dispatcher queue.
pub(crate) fn command_queued() {
    COMMAND_GENERATION.fetch_add(1, Ordering::Release);
}

/// A direct command decoded successfully. This is deliberately separate from
/// transport ingress and wakes a worker waiting for a subsequent run.
pub(crate) fn command_accepted() {
    command_queued();
}

pub fn command_generation() -> u32 {
    COMMAND_GENERATION.load(Ordering::Acquire)
}

pub fn command_generation_changed(observed: u32) -> bool {
    observed != command_generation()
}

#[cfg(test)]
pub(crate) fn command_generation_changed_from(observed: u32, current: u32) -> bool {
    observed != current
}
