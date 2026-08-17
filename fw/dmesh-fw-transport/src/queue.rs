// IMPORTANT: This crate is for firmware/platform-only glue. If code can be
// host-tested or reused without ESP/FreeRTOS ownership, it probably belongs
// in `quic-lite` (QUIC-lite transport mechanics) or `dmesh-server` (shared
// service/protocol behavior), not here.

//! Bounded service-to-bearer queue outcomes.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QueueDisposition {
    Queued,
    Drop,
    Timeout,
}

/// Logs/events may drop when a path is full; command work must time out
/// instead of blocking a FreeRTOS bearer task on stream credit.
pub const fn queue_disposition(has_capacity: bool, lossy: bool) -> QueueDisposition {
    if has_capacity {
        QueueDisposition::Queued
    } else if lossy {
        QueueDisposition::Drop
    } else {
        QueueDisposition::Timeout
    }
}
