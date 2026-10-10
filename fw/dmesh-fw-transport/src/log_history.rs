//! Main's retained structured log history.
//!
//! Log records are CBOR-encoded directly into packets acquired from the
//! node-owned dynamic QUIC pool. Six pool leases form the circular history;
//! each lease holds as many self-delimiting CBOR records as fit. The ESP-IDF
//! log hook and structured event producers allocate no private history buffer.
//!
//! The pool leases remain immutable to readers until released. The current
//! tail is appended only while this history is its unique owner. A full tail
//! rotates the oldest lease back into the shared pool before acquiring its
//! replacement.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use dmesh_server::log_watch::{self, LogRecord, LogSource};
use quic_lite::{OwnedPacket, PacketBuffer, PacketWriter};

const HISTORY_PACKETS: usize = 6;
type Packet = crate::quic_node_esp::FirmwarePacket;

struct Slot {
    packet: Option<Packet>,
    first_seq: u64,
    last_seq: u64,
}

impl Slot {
    const fn empty() -> Self {
        Self {
            packet: None,
            first_seq: 0,
            last_seq: 0,
        }
    }
}

struct History {
    next_seq: u64,
    head: usize,
    count: usize,
    slots: [Slot; HISTORY_PACKETS],
}

struct Shared {
    locked: AtomicBool,
    value: UnsafeCell<History>,
}

unsafe impl Sync for Shared {}

static HISTORY: Shared = Shared {
    locked: AtomicBool::new(false),
    value: UnsafeCell::new(History {
        next_seq: 0,
        head: 0,
        count: 0,
        slots: [const { Slot::empty() }; HISTORY_PACKETS],
    }),
};
static DROPPED: AtomicU32 = AtomicU32::new(0);

fn with<R>(f: impl FnOnce(&mut History) -> R) -> Option<R> {
    // Wi-Fi logs may preempt the lower-priority history reader/producer.
    // Never wait for an owner which cannot run until this callback returns.
    HISTORY.locked.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed).ok()?;
    struct Unlock<'a>(&'a AtomicBool);
    impl Drop for Unlock<'_> {
        fn drop(&mut self) { self.0.store(false, Ordering::Release); }
    }
    let _unlock = Unlock(&HISTORY.locked);
    // SAFETY: the atomic lock serializes all history access.
    let result = f(unsafe { &mut *HISTORY.value.get() });
    Some(result)
}

fn uptime_ms() -> u64 {
    (unsafe { esp_idf_sys::esp_timer_get_time() }.max(0) as u64) / 1_000
}

/// Strip ESP-IDF ANSI color sequences into a bounded stack scratch area. The
/// log hook currently receives the already formatted line, so its arguments
/// cannot reliably be recovered as typed values; explicit event producers use
/// `push_event` and retain typed CBOR fields instead.
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
    // ESP-IDF's formatted log line is ASCII in the supported configurations.
    core::str::from_utf8(&out[..used]).unwrap_or("")
}

fn encode_line(
    out: &mut [u8],
    seq: u64,
    time_ms: u64,
    level: u8,
    source: &str,
    text: &str,
) -> Option<usize> {
    let mut e = dmesh_server::cbor::Encoder::new(out);
    e.map(5)?;
    e.uint(1)?;
    e.uint(seq)?;
    e.uint(2)?;
    e.uint(time_ms)?;
    e.uint(3)?;
    e.uint(u64::from(level))?;
    e.uint(4)?;
    e.text_value(source.as_bytes())?;
    e.uint(6)?;
    e.text_value(text.as_bytes())?;
    Some(e.len())
}

/// Append an encoded record directly into the shared packet history. `encode`
/// is retried against a fresh pool lease if the current packet has no room;
/// failed or oversized records advance sequence and are reflected as dropped.
/// Lock contention rejects admission immediately and increments `dropped()`;
/// no sequence is assigned until a producer owns the history.
fn append_record(mut encode: impl FnMut(&mut [u8], u64) -> Option<usize>) -> bool {
    with(|history| {
        history.next_seq = history.next_seq.saturating_add(1);
        let seq = history.next_seq;

        if history.count != 0 {
            let tail = (history.head + history.count - 1) % HISTORY_PACKETS;
            let slot = &mut history.slots[tail];
            if let Some(packet) = slot.packet.take() {
                let (mut buffer, range) = packet.into_parts();
                let used = if let Some(storage) = buffer.as_mut_unique() {
                    encode(&mut storage[range.end..], seq)
                } else {
                    None
                };
                if let Some(used) = used {
                    match OwnedPacket::new(buffer, range.start..range.end + used) {
                        Ok(packet) => {
                            slot.packet = Some(packet);
                            slot.last_seq = seq;
                            return true;
                        }
                        Err(buffer) => {
                            slot.packet = OwnedPacket::new(buffer, range.clone()).ok();
                        }
                    }
                } else {
                    // `range` excludes any partially written bytes, so restore
                    // is safe even when the encoder found too little capacity.
                    slot.packet = OwnedPacket::new(buffer, range.clone()).ok();
                }
            }
        }

        if history.count == HISTORY_PACKETS {
            history.slots[history.head] = Slot::empty();
            history.head = (history.head + 1) % HISTORY_PACKETS;
            history.count -= 1;
        }

        let Some(mut writer) = crate::quic_node_esp::acquire_log_writer() else {
            DROPPED.fetch_add(1, Ordering::Relaxed);
            return false;
        };
        let Some(used) = encode(writer.payload_mut(), seq) else {
            DROPPED.fetch_add(1, Ordering::Relaxed);
            return false;
        };
        let Some(packet) = writer.commit(used) else {
            DROPPED.fetch_add(1, Ordering::Relaxed);
            return false;
        };
        let index = (history.head + history.count) % HISTORY_PACKETS;
        history.slots[index] = Slot {
            packet: Some(packet),
            first_seq: seq,
            last_seq: seq,
        };
        history.count += 1;
        true
    }).unwrap_or_else(|| {
        DROPPED.fetch_add(1, Ordering::Relaxed);
        false
    })
}

/// Retain one ESP-IDF formatted log line. It is represented as a CBOR
/// `LogRecord`; only the `text` field is textual, with its timestamp encoded
/// as an integer. The formatted printf arguments are unavailable at this hook.
pub fn push(line: &[u8]) -> bool {
    let Ok(line) = core::str::from_utf8(line) else {
        DROPPED.fetch_add(1, Ordering::Relaxed);
        return false;
    };
    let line = line.trim_end_matches(['\r', '\n']);
    if line.is_empty() {
        DROPPED.fetch_add(1, Ordering::Relaxed);
        return false;
    }
    let mut scratch = [0u8; 256];
    let plain = strip_escapes(line, &mut scratch);
    let (level, source, text) = log_watch::parse_esp_idf_line(plain);
    let time_ms = uptime_ms();
    append_record(|out, seq| encode_line(out, seq, time_ms, level, source, text))
}

/// Retain a structured event without converting typed fields to text.
pub fn push_event(
    level: u8,
    source: &str,
    kind: &str,
    fields: &[(u64, dmesh_server::cbor::FieldValue<'_>)],
) -> bool {
    let time_ms = uptime_ms();
    append_record(|out, seq| {
        log_watch::encode_event_into(out, seq, time_ms, level, source, kind, fields)
    })
}

pub fn dropped() -> u32 {
    DROPPED.load(Ordering::Relaxed)
}

/// The shared-pool packet history as a `log.watch` source. Readers share one
/// immutable pool lease at a time, then decode and visit outside the producer
/// lock; they do not copy a complete retained packet into a stack scratch
/// array.
pub struct Source;

fn owned_run(
    packet: &Packet,
    start: usize,
    end: usize,
) -> Option<OwnedPacket<quic_lite::ErasedPacketBuffer>> {
    let (buffer, range) = packet.clone_shared().into_parts();
    let range = range.start.checked_add(start)?..range.start.checked_add(end)?;
    OwnedPacket::new(buffer, range).ok()?.try_erase().ok()
}

impl Source {
    fn visit_encoded(
        &self,
        since: u64,
        visit: &mut dyn FnMut(log_watch::LogRecordView<'_>, &[u8]) -> bool,
    ) -> u64 {
        let Some((count, next, oldest, snapshot)) = with(|history| {
            let oldest = if history.count == 0 {
                history.next_seq.saturating_add(1)
            } else {
                history.slots[history.head].first_seq
            };
            let mut snapshot = [(usize::MAX, 0, 0); HISTORY_PACKETS];
            for offset in 0..history.count {
                let index = (history.head + offset) % HISTORY_PACKETS;
                let slot = &history.slots[index];
                snapshot[offset] = (index, slot.first_seq, slot.last_seq);
            }
            (history.count, history.next_seq, oldest, snapshot)
        }) else { return 0 };
        let dropped = oldest
            .saturating_sub(since.saturating_add(1))
            .min(next.saturating_sub(since));
        for &(index, first_seq, last_seq) in snapshot.iter().take(count) {
            let packet = with(|history| {
                let slot = &history.slots[index];
                if slot.first_seq != first_seq || slot.last_seq != last_seq {
                    return None;
                }
                slot.packet.as_ref().map(OwnedPacket::clone_shared)
            });
            // Contention is not a gap: retry from the same cursor next turn.
            let Some(packet) = packet else { return dropped };
            let Some(packet) = packet else { continue };
            let bytes = packet.bytes();
            let mut cursor = 0;
            while cursor < bytes.len() {
                let Some((record, used)) = log_watch::LogRecordView::decode(&bytes[cursor..])
                else {
                    break;
                };
                let encoded = &bytes[cursor..cursor + used];
                cursor += used;
                if record.seq > since && !visit(record, encoded) {
                    return dropped;
                }
            }
        }
        dropped
    }
}

impl LogSource for Source {
    fn now_ms(&self) -> u64 {
        uptime_ms()
    }

    fn read(&self, since: u64, visit: &mut dyn FnMut(&LogRecord) -> bool) -> u64 {
        self.read_encoded(since, &mut |record, _encoded| visit(record))
    }

    fn read_encoded(&self, since: u64, visit: &mut dyn FnMut(&LogRecord, &[u8]) -> bool) -> u64 {
        self.visit_encoded(since, &mut |_view, encoded| {
            let Some((record, _)) = LogRecord::decode(encoded) else {
                return true;
            };
            visit(&record, encoded)
        })
    }

    fn read_encoded_views(
        &self,
        since: u64,
        visit: &mut dyn FnMut(log_watch::LogRecordView<'_>, &[u8]) -> bool,
    ) -> u64 {
        self.visit_encoded(since, visit)
    }

    fn read_encoded_runs(
        &self,
        since: u64,
        matches: &mut dyn FnMut(log_watch::LogRecordView<'_>) -> bool,
        visit: &mut dyn FnMut(
            u64,
            &[u8],
            Option<OwnedPacket<quic_lite::ErasedPacketBuffer>>,
        ) -> bool,
    ) {
        let Some((count, next, oldest, snapshot)) = with(|history| {
            let oldest = if history.count == 0 {
                history.next_seq.saturating_add(1)
            } else {
                history.slots[history.head].first_seq
            };
            let mut snapshot = [(usize::MAX, 0, 0); HISTORY_PACKETS];
            for offset in 0..history.count {
                let index = (history.head + offset) % HISTORY_PACKETS;
                let slot = &history.slots[index];
                snapshot[offset] = (index, slot.first_seq, slot.last_seq);
            }
            (history.count, history.next_seq, oldest, snapshot)
        }) else {
            let _ = visit(since, &[], None);
            return;
        };
        let _dropped = oldest
            .saturating_sub(since.saturating_add(1))
            .min(next.saturating_sub(since));
        let mut through = since;
        let mut stopped = false;
        for &(index, first_seq, last_seq) in snapshot.iter().take(count) {
            let packet = with(|history| {
                let slot = &history.slots[index];
                if slot.first_seq != first_seq || slot.last_seq != last_seq {
                    return None;
                }
                slot.packet.as_ref().map(OwnedPacket::clone_shared)
            });
            let Some(packet) = packet else {
                let _ = visit(through, &[], None);
                return;
            };
            let Some(packet) = packet else { continue };
            let bytes = packet.bytes();
            let mut offset = 0;
            let mut run_start = None;
            let mut run_end = 0;
            let mut run_through = through;
            let mut run_last_seq = through;
            while offset < bytes.len() {
                let Some((record, used)) = log_watch::LogRecordView::decode(&bytes[offset..])
                else {
                    break;
                };
                let start = offset;
                offset += used;
                if record.seq <= since {
                    continue;
                }
                if matches(record) {
                    if run_start.is_none() {
                        run_start = Some(start);
                        run_through = through;
                    }
                    run_end = offset;
                    run_last_seq = record.seq;
                    continue;
                }
                if let Some(start) = run_start.take() {
                    let owned = owned_run(&packet, start, run_end);
                    if !visit(run_through, &bytes[start..run_end], owned) {
                        stopped = true;
                        break;
                    }
                    through = run_last_seq;
                }
                through = through.max(record.seq);
            }
            if stopped {
                break;
            }
            if let Some(start) = run_start {
                let owned = owned_run(&packet, start, run_end);
                if !visit(run_through, &bytes[start..run_end], owned) {
                    stopped = true;
                    break;
                }
                through = run_last_seq;
            }
        }
        if !stopped {
            let _ = visit(through, &[], None);
        }
    }

    fn advance_stream_cursor(&self, through_seq: u64) {
        let _ = with(|history| {
            while history.count != 0 && history.slots[history.head].last_seq <= through_seq {
                history.slots[history.head] = Slot::empty();
                history.head = (history.head + 1) % HISTORY_PACKETS;
                history.count -= 1;
            }
        });
    }
}
