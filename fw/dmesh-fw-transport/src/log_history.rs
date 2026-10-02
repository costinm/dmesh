//! Retained Main log history for `log.watch`.
//!
//! Physical UART remains the primary crash/debug path. This separate ring lets
//! a connected controller retrieve recent ESP-IDF log lines without coupling
//! log production to a bearer or adding another queue. ESP-IDF's
//! `I (123) tag: text` lines are split into level, source and text so a
//! watcher can filter them.
//!
//! The producer is the C log hook, which can run in any task, so `push` takes a
//! short spin lock and never allocates: slots are fixed-size. Records are built
//! (and allocated) only on the read side, by the `log.watch` handler.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use dmesh_server::log_watch::{self, LogRecord, LogSource};

/// Records kept; older ones are replaced.
pub const CAPACITY: usize = 32;
const TEXT_BYTES: usize = 160;
const SOURCE_BYTES: usize = 16;

#[derive(Clone, Copy)]
struct Slot {
    seq: u64,
    time_ms: u64,
    level: u8,
    source_len: u8,
    text_len: u8,
    source: [u8; SOURCE_BYTES],
    text: [u8; TEXT_BYTES],
}

const EMPTY: Slot = Slot {
    seq: 0,
    time_ms: 0,
    level: 0,
    source_len: 0,
    text_len: 0,
    source: [0; SOURCE_BYTES],
    text: [0; TEXT_BYTES],
};

struct History {
    next: u64,
    slots: [Slot; CAPACITY],
}

struct Shared {
    locked: AtomicBool,
    value: UnsafeCell<History>,
}

unsafe impl Sync for Shared {}

static HISTORY: Shared = Shared {
    locked: AtomicBool::new(false),
    value: UnsafeCell::new(History {
        next: 0,
        slots: [EMPTY; CAPACITY],
    }),
};
static DROPPED: AtomicU32 = AtomicU32::new(0);

fn with<R>(f: impl FnOnce(&mut History) -> R) -> R {
    while HISTORY.locked.swap(true, Ordering::Acquire) {
        core::hint::spin_loop();
    }
    // SAFETY: the spin lock serializes all access to the history.
    let result = f(unsafe { &mut *HISTORY.value.get() });
    HISTORY.locked.store(false, Ordering::Release);
    result
}

fn uptime_ms() -> u64 {
    (unsafe { esp_idf_sys::esp_timer_get_time() }.max(0) as u64) / 1_000
}

/// Copy `line` into `out` without ANSI color escapes (`ESC [ ... m`), which
/// ESP-IDF adds with colored logs. Returns the plain text; no allocation.
fn strip_escapes<'a>(line: &str, out: &'a mut [u8; 256]) -> &'a str {
    let mut used = 0;
    let mut in_escape = false;
    for &byte in line.as_bytes() {
        if in_escape {
            in_escape = byte != b'm';
        } else if byte == 0x1b {
            in_escape = true;
        } else if used < out.len() {
            out[used] = byte;
            used += 1;
        }
    }
    // The input is ASCII (checked by the caller), so any prefix is valid UTF-8.
    core::str::from_utf8(&out[..used]).unwrap_or("")
}

fn copy_prefix(dst: &mut [u8], src: &str) -> u8 {
    let mut end = src.len().min(dst.len());
    while !src.is_char_boundary(end) {
        end -= 1;
    }
    dst[..end].copy_from_slice(&src.as_bytes()[..end]);
    end as u8
}

/// Retain one already-formatted ASCII line. Oversized text is truncated;
/// non-ASCII or empty input is rejected and counted.
pub fn push(line: &[u8]) {
    let Ok(line) = core::str::from_utf8(line) else {
        DROPPED.fetch_add(1, Ordering::Relaxed);
        return;
    };
    let line = line.trim_end_matches(['\r', '\n']);
    if line.is_empty() || !line.is_ascii() {
        DROPPED.fetch_add(1, Ordering::Relaxed);
        return;
    }
    let mut scratch = [0u8; 256];
    let plain = strip_escapes(line, &mut scratch);
    let (level, source, text) = log_watch::parse_esp_idf_line(plain);
    let time_ms = uptime_ms();
    let mut slot = EMPTY;
    slot.level = level;
    slot.time_ms = time_ms;
    slot.source_len = copy_prefix(&mut slot.source, source);
    slot.text_len = copy_prefix(&mut slot.text, text);
    with(|history| {
        history.next += 1;
        slot.seq = history.next;
        history.slots[(slot.seq as usize - 1) % CAPACITY] = slot;
    });
}

pub fn dropped() -> u32 {
    DROPPED.load(Ordering::Relaxed)
}

/// The history as a `log.watch` source.
pub struct Source;

impl LogSource for Source {
    fn now_ms(&self) -> u64 {
        uptime_ms()
    }

    fn read(&self, since: u64, visit: &mut dyn FnMut(&LogRecord) -> bool) -> u64 {
        let (end, first) = with(|history| {
            (
                history.next,
                history.next.saturating_sub(CAPACITY as u64).saturating_add(1),
            )
        });
        let start = since.saturating_add(1).max(first);
        let dropped = first.saturating_sub(since.saturating_add(1)).min(end);
        for seq in start..=end {
            // One slot per lock hold; it may be replaced meanwhile.
            let slot = with(|history| history.slots[(seq as usize - 1) % CAPACITY]);
            if slot.seq != seq {
                continue;
            }
            let record = LogRecord {
                seq,
                time_ms: slot.time_ms,
                level: slot.level,
                source: alloc::string::String::from_utf8_lossy(
                    &slot.source[..usize::from(slot.source_len)],
                )
                .into_owned(),
                kind: None,
                text: alloc::string::String::from_utf8_lossy(&slot.text[..usize::from(slot.text_len)])
                    .into_owned(),
                fields: None,
            };
            if !visit(&record) {
                break;
            }
        }
        dropped
    }
}
