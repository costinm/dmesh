//! Small retained Main log history for the QUIC `log-watch` diagnostic.
//!
//! Physical UART remains the primary crash/debug path. This separate ring
//! lets a connected controller retrieve recent ESP-IDF log lines without
//! coupling log production to a bearer or adding another queue.

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

pub const CAPACITY: usize = 32;
pub const LINE_BYTES: usize = 160;

struct History {
    next: u64,
    lengths: [u16; CAPACITY],
    lines: [[u8; LINE_BYTES]; CAPACITY],
}

struct SharedHistory {
    locked: AtomicBool,
    value: core::cell::UnsafeCell<History>,
}

unsafe impl Sync for SharedHistory {}

static HISTORY: SharedHistory = SharedHistory {
    locked: AtomicBool::new(false),
    value: core::cell::UnsafeCell::new(History {
        next: 0,
        lengths: [0; CAPACITY],
        lines: [[0; LINE_BYTES]; CAPACITY],
    }),
};
static DROPPED: AtomicU32 = AtomicU32::new(0);

struct Guard;
impl Drop for Guard {
    fn drop(&mut self) {
        HISTORY.locked.store(false, Ordering::Release);
    }
}

fn lock() -> Guard {
    while HISTORY.locked.swap(true, Ordering::Acquire) {
        core::hint::spin_loop();
    }
    Guard
}

/// Retain one already-formatted ASCII line. Oversized input is truncated;
/// non-ASCII or empty input is rejected and counted.
pub fn push(line: &[u8]) {
    if line.is_empty() || !line.is_ascii() {
        DROPPED.fetch_add(1, Ordering::Relaxed);
        return;
    }
    let _guard = lock();
    // SAFETY: the spin lock serializes all access to the history.
    let history = unsafe { &mut *HISTORY.value.get() };
    let sequence = history.next.saturating_add(1);
    let slot = (sequence as usize - 1) % CAPACITY;
    let length = line.len().min(LINE_BYTES);
    history.lines[slot].fill(0);
    history.lines[slot][..length].copy_from_slice(&line[..length]);
    history.lengths[slot] = length as u16;
    history.next = sequence;
}

/// Copy up to `limit` lines newer than `since` into caller-owned storage.
pub fn read(since: u64, limit: usize) -> (u64, alloc::vec::Vec<(u64, alloc::vec::Vec<u8>)>) {
    let _guard = lock();
    // SAFETY: the spin lock serializes all access to the history.
    let history = unsafe { &*HISTORY.value.get() };
    let first = history
        .next
        .saturating_sub(CAPACITY as u64)
        .saturating_add(1);
    let start = since.saturating_add(1).max(first);
    let end = history.next;
    let mut records = alloc::vec::Vec::new();
    let take_end = end.min(start.saturating_add(limit.saturating_sub(1) as u64));
    if limit != 0 && start <= take_end {
        if records
            .try_reserve((take_end - start + 1) as usize)
            .is_err()
        {
            return (end, records);
        }
        for sequence in start..=take_end {
            let slot = (sequence as usize - 1) % CAPACITY;
            let length = usize::from(history.lengths[slot]).min(LINE_BYTES);
            let mut line = alloc::vec::Vec::new();
            if line.try_reserve(length).is_err() {
                break;
            }
            line.extend_from_slice(&history.lines[slot][..length]);
            records.push((sequence, line));
        }
    }
    (end, records)
}

pub fn dropped() -> u32 {
    DROPPED.load(Ordering::Relaxed)
}
